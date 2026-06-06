#!/usr/bin/env python3
"""Mantishack local scan server.

Runs a small web server on your machine (default http://127.0.0.1:8080) that:

  * serves a single-page scan UI (`app.html`) with live loading screens, and
  * exposes a tiny async scan API the UI drives.

A visitor pastes a link, a NEW scan session starts (its own scan_id + output
dir), the Mantishack engine runs in a background thread, real progress streams
into the loading screen, and the parsed report appears when done.

Protocol
--------
    POST /scan        {"url": "...", "type": "web"}            -> {"scan_id"}
    POST /scan        {"repo": "https://github.com/u/r"}       -> {"scan_id"}
    GET  /scan/<id>   -> {status, current_step, progress, findings, target, error}
    GET  /            -> the scan UI (app.html)
    GET  /health      -> {ok, engine, python}

Run it
------
    cd ~/Downloads/mantishack
    python3 server.py
    # open http://127.0.0.1:8080

Env overrides
-------------
    MANTISHACK_SERVER_HOST   bind host    (default 127.0.0.1 — local only)
    MANTISHACK_SERVER_PORT   bind port    (default 8080)
    MANTISHACK_PYTHON        engine python (default: ./.venv/bin/python if present)
    MANTISHACK_SCAN_TIMEOUT  per-scan cap, seconds (default 900)

Safety
------
  * Binds to localhost only by default. When bound to a non-loopback
    address (e.g. ``MANTISHACK_SERVER_HOST=0.0.0.0``) the scan API
    REQUIRES a bearer token — printed at startup, or pinned via
    ``MANTISHACK_SERVER_TOKEN`` — so a LAN visitor cannot drive
    arbitrary clone+scan+LLM spend.
  * On a loopback bind, a Host-header allowlist defeats DNS-rebinding
    (a malicious page that rebinds its domain to 127.0.0.1 still sends
    its own Host header, which is rejected).
  * Web-scan targets pass an SSRF guard: the host is resolved and any
    address that is loopback / link-local / private / reserved / the
    cloud-metadata endpoint (169.254.169.254) is refused.
  * Repo scans go through the engine's hardened ``clone_repository`` —
    github/gitlab allowlist, sandboxed git, egress proxy, ``--no-tags``,
    per-repo-config RCE mitigations (CVE-2024-32002 family) — instead of
    a bare ``git clone``.
  * The job store is bounded (TTL + hard cap) so a scripted POST loop
    cannot grow memory without limit. Per-IP rate limiting on the scan
    API. All subprocess calls use list args (no shell).
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ENGINE_DIR = Path(__file__).resolve().parent
HOST = os.environ.get("MANTISHACK_SERVER_HOST", "127.0.0.1")
PORT = int(os.environ.get("MANTISHACK_SERVER_PORT", "8080"))
SCAN_TIMEOUT = int(os.environ.get("MANTISHACK_SCAN_TIMEOUT", "900"))
MAX_BODY_BYTES = 64 * 1024
MAX_ACTIVE_JOBS = 4

# Job-store bounds — a scripted POST loop must not grow memory forever.
MAX_JOBS = 256          # hard cap on retained job records
JOB_TTL = 3600          # seconds to keep a finished job before reaping

# Per-client rate limit on the scan API.
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX = 12     # max POST /scan per window per client IP


def _is_loopback_bind(host: str) -> bool:
    if host in ("localhost",):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


# When the server is reachable off-box (non-loopback bind) the scan API
# is unauthenticated-by-default's worst case: any LAN visitor could drive
# arbitrary clone+scan+LLM spend. Require a bearer token in that mode —
# operator-pinned via MANTISHACK_SERVER_TOKEN, else a random one printed
# at startup. A loopback bind keeps the token empty (no token needed) and
# leans on the Host-header allowlist below to defeat DNS-rebinding.
_BIND_IS_LOCAL = _is_loopback_bind(HOST)
_AUTH_TOKEN = os.environ.get("MANTISHACK_SERVER_TOKEN", "").strip()
if not _BIND_IS_LOCAL and not _AUTH_TOKEN:
    _AUTH_TOKEN = secrets.token_urlsafe(32)

# Host headers accepted on a loopback bind (anti-DNS-rebinding). A page
# that rebinds its hostname to 127.0.0.1 still sends its own Host header,
# which is absent here and so rejected.
_ALLOWED_HOSTS = {
    f"127.0.0.1:{PORT}", f"localhost:{PORT}", f"[::1]:{PORT}",
    "127.0.0.1", "localhost",
}

# Hostnames refused outright for web scans regardless of DNS resolution
# (defence in depth on top of the resolved-IP check below).
_BLOCKED_HOSTNAMES = {"localhost", "metadata", "metadata.google.internal"}


def _engine_python() -> str:
    """Pick the interpreter that runs the engine (needs requests/bs4)."""
    env = os.environ.get("MANTISHACK_PYTHON")
    if env and Path(env).exists():
        return env
    venv = ENGINE_DIR / ".venv" / "bin" / "python"
    if venv.exists():
        return str(venv)
    return sys.executable


ENGINE_PY = _engine_python()

# --------------------------------------------------------------------------- #
# Job store
# --------------------------------------------------------------------------- #
_JOBS: dict[str, dict] = {}
_JOBS_LOCK = threading.Lock()
_ACTIVE = threading.Semaphore(MAX_ACTIVE_JOBS)

# Per-IP sliding-window counters for the scan-API rate limit.
_RATE: dict[str, list[float]] = {}
_RATE_LOCK = threading.Lock()


def _now() -> float:
    return time.time()


def _rate_ok(client: str) -> bool:
    """True if ``client`` may make another POST /scan in this window."""
    now = _now()
    cutoff = now - RATE_LIMIT_WINDOW
    with _RATE_LOCK:
        hits = [t for t in _RATE.get(client, ()) if t > cutoff]
        if len(hits) >= RATE_LIMIT_MAX:
            _RATE[client] = hits
            return False
        hits.append(now)
        _RATE[client] = hits
        # Opportunistic GC of idle clients so this map can't grow forever.
        if len(_RATE) > 4096:
            for k in [k for k, v in _RATE.items() if not any(t > cutoff for t in v)]:
                _RATE.pop(k, None)
        return True


def _reap_jobs() -> None:
    """Evict finished jobs past their TTL and enforce the hard cap.

    Called before each new job so a scripted POST loop cannot grow the
    job store without bound. Caller must NOT hold ``_JOBS_LOCK``.
    """
    now = _now()
    with _JOBS_LOCK:
        for sid in list(_JOBS):
            fin = _JOBS[sid].get("finished")
            if fin and (now - fin) > JOB_TTL:
                del _JOBS[sid]
        if len(_JOBS) > MAX_JOBS:
            # Evict oldest by start time down to the cap.
            doomed = sorted(_JOBS, key=lambda s: _JOBS[s].get("started", 0))
            for sid in doomed[: len(_JOBS) - MAX_JOBS]:
                del _JOBS[sid]


def _new_job(target: str, kind: str) -> str:
    _reap_jobs()
    scan_id = "scan_" + uuid.uuid4().hex[:12]
    with _JOBS_LOCK:
        _JOBS[scan_id] = {
            "scan_id": scan_id,
            "type": kind,
            "target": target,
            "status": "queued",
            "current_step": "Queued…",
            "progress": 5,
            "findings": [],
            "error": None,
            "started": _now(),
            "finished": None,
        }
    return scan_id


def _update(scan_id: str, **fields) -> None:
    with _JOBS_LOCK:
        job = _JOBS.get(scan_id)
        if job:
            job.update(fields)


def _get(scan_id: str) -> dict | None:
    with _JOBS_LOCK:
        job = _JOBS.get(scan_id)
        return dict(job) if job else None


# --------------------------------------------------------------------------- #
# Finding normalisation
# --------------------------------------------------------------------------- #
_SEV_MAP = {
    "critical": "critical", "high": "high", "error": "high",
    "medium": "medium", "moderate": "medium", "warning": "medium", "warn": "medium",
    "low": "low", "info": "low", "informational": "low", "note": "low", "none": "low",
}


def _norm_sev(raw) -> str:
    return _SEV_MAP.get(str(raw or "").strip().lower(), "low")


def _normalize_findings(raw: list) -> list[dict]:
    out = []
    for f in raw:
        if not isinstance(f, dict):
            continue
        out.append({
            "severity": _norm_sev(
                f.get("severity") or f.get("severity_assessment") or f.get("level")),
            "title": f.get("title") or f.get("vuln_type") or f.get("rule_id")
            or f.get("check_id") or "Finding",
            "file_path": f.get("file_path") or f.get("file") or "",
            "url": f.get("url") or f.get("target") or "",
            "line": f.get("line") or f.get("start_line"),
            "description": f.get("description") or f.get("message")
            or f.get("reasoning") or "",
        })
    return out


def _safe_env() -> dict:
    try:
        from core.config import MantishackConfig
        return MantishackConfig.get_safe_env(include_python_user_base=True)
    except Exception:
        env = dict(os.environ)
        for k in ("LD_PRELOAD", "LD_LIBRARY_PATH"):
            env.pop(k, None)
        return env


def _parse_sarif(path: Path) -> list[dict]:
    findings = []
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (ValueError, OSError):
        return findings
    for run in data.get("runs") or []:
        for res in run.get("results") or []:
            locs = res.get("locations") or [{}]
            first = locs[0] if isinstance(locs, list) and locs and isinstance(locs[0], dict) else {}
            phys = first.get("physicalLocation", {})
            findings.append({
                "rule_id": res.get("ruleId", "unknown"),
                "severity": _norm_sev(res.get("level", "warning")),
                "message": (res.get("message") or {}).get("text", ""),
                "file_path": phys.get("artifactLocation", {}).get("uri", ""),
                "line": phys.get("region", {}).get("startLine"),
            })
    return findings


# --------------------------------------------------------------------------- #
# Target validation (SSRF guard + repo allowlist)
# --------------------------------------------------------------------------- #
def _ip_is_blocked(ip_str: str) -> bool:
    """True if ``ip_str`` is an address a scan must never reach."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # unparseable → refuse, fail closed
    return bool(
        ip.is_loopback or ip.is_link_local or ip.is_private
        or ip.is_multicast or ip.is_reserved or ip.is_unspecified
        or not ip.is_global
    )


def _validate_scan_target_url(raw: str) -> tuple[str | None, str | None]:
    """Return ``(safe_url, None)`` or ``(None, error)`` for a web-scan URL.

    Rejects non-http(s) schemes, embedded credentials, and — the SSRF
    guard — any host that is, or resolves to, a loopback / link-local /
    private / reserved address or the cloud-metadata endpoint
    (169.254.169.254). DNS is resolved here and EVERY returned address
    is checked, so a hostname pointing at an internal IP is refused.

    Note: this is an entry-point check. The crawler subprocess re-resolves
    at fetch time, so a TOCTOU/DNS-rebind window remains — this closes the
    common, scriptable SSRF cases (metadata/localhost/RFC1918 targets).
    """
    full = raw if "//" in raw else "https://" + raw
    try:
        parsed = urlparse(full)
    except ValueError:
        return None, "could not parse url"
    if parsed.scheme not in ("http", "https"):
        return None, "url must be http(s)://host"
    if parsed.username or parsed.password:
        return None, "url must not contain credentials"
    host = parsed.hostname
    if not host:
        return None, "url must include a host"
    if host.lower() in _BLOCKED_HOSTNAMES:
        return None, "refusing to scan a local/metadata host"

    # Collect candidate IPs: a literal address, or every DNS answer.
    try:
        candidates = [str(ipaddress.ip_address(host))]
    except ValueError:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        try:
            infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        except socket.gaierror:
            return None, f"could not resolve host: {host}"
        candidates = [info[4][0] for info in infos]
    if not candidates:
        return None, f"could not resolve host: {host}"
    for ip_str in candidates:
        if _ip_is_blocked(ip_str):
            return None, (
                "host resolves to a private/loopback/link-local address "
                "(SSRF blocked)"
            )
    return full, None


def _repo_url_allowed(repo: str) -> bool:
    """True if ``repo`` passes the engine's github/gitlab clone allowlist.

    Fails closed: any import or validation error → not allowed.
    """
    try:
        from core.git.validate import validate_repo_url
        return bool(validate_repo_url(repo))
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# Engine streaming
# --------------------------------------------------------------------------- #
_STEP_HINTS = [
    (re.compile(r"crawl|discover", re.I), "Crawling target & mapping attack surface…", 35),
    (re.compile(r"semgrep|static", re.I), "Running static analysis…", 45),
    (re.compile(r"codeql", re.I), "Running CodeQL dataflow analysis…", 55),
    (re.compile(r"fuzz|param|inject|xss|sqli|probe|check", re.I), "Probing for vulnerabilities…", 68),
    (re.compile(r"analy", re.I), "Analysing responses…", 82),
    (re.compile(r"report|writing|complete|saved", re.I), "Generating report…", 92),
]


def _stream_engine(cmd: list[str], scan_id: str) -> int:
    proc = subprocess.Popen(
        cmd, cwd=str(ENGINE_DIR), env=_safe_env(),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    deadline = _now() + SCAN_TIMEOUT
    try:
        for line in proc.stdout:  # type: ignore[union-attr]
            line = line.rstrip()
            if not line:
                continue
            for rx, step, pct in _STEP_HINTS:
                if rx.search(line):
                    cur = _get(scan_id) or {}
                    _update(scan_id, current_step=step,
                            progress=max(cur.get("progress", 0), pct))
                    break
            if _now() > deadline:
                proc.kill()
                _update(scan_id, current_step="Scan timed out — terminating…")
                break
    finally:
        rc = proc.wait()
    return rc


def _newest_run(prefix: str, since: float) -> Path | None:
    out = ENGINE_DIR / "out"
    if not out.is_dir():
        return None
    best, best_m = None, since - 5
    for d in out.iterdir():
        if not d.is_dir() or not d.name.startswith(prefix):
            continue
        try:
            m = d.stat().st_mtime
        except OSError:
            continue
        if m > best_m:
            best, best_m = d, m
    return best


def _run_web_scan(scan_id: str, url: str) -> None:
    _update(scan_id, status="running", current_step="Initializing scan engine…", progress=15)
    started = _now()
    rc = _stream_engine([ENGINE_PY, "mantishack.py", "web", "--url", url], scan_id)
    if rc != 0:
        _update(scan_id, status="failed", error=f"engine exited {rc}", finished=_now())
        return
    findings = []
    d = _newest_run("web_", started)
    if d:
        rep = d / "web_scan_report.json"
        if rep.is_file():
            try:
                data = json.loads(rep.read_text(encoding="utf-8-sig"))
                findings = _normalize_findings(data.get("findings") or [])
            except (ValueError, OSError):
                pass
    _update(scan_id, status="completed", current_step="Scan complete",
            progress=100, findings=findings, finished=_now())


def _run_repo_scan(scan_id: str, repo: str) -> None:
    # Defence in depth: do_POST already gated on _repo_url_allowed, but a
    # worker must never clone a URL the allowlist would reject.
    if not _repo_url_allowed(repo):
        _update(scan_id, status="failed",
                error=("repo URL not allowed — only https github.com / gitlab.com "
                       "repositories are accepted (e.g. https://github.com/user/repo)"),
                finished=_now())
        return
    _update(scan_id, status="running", current_step="Cloning repository…", progress=15)
    tmp = Path(tempfile.mkdtemp(prefix="mantishack_repo_"))
    clone_dir = tmp / "repo"
    started = _now()
    try:
        # Route through the engine's hardened clone instead of a bare
        # ``git clone``: sandboxed git, egress proxy pinned to the forge
        # hosts, --no-tags, and per-repo-config RCE mitigations
        # (CVE-2024-32002 family). Raises on any failure (including the
        # fail-closed "sandbox unavailable" path).
        try:
            from core.git.clone import clone_repository
            clone_repository(repo, clone_dir)
        except Exception as exc:  # noqa: BLE001 - surface as a failed scan
            _update(scan_id, status="failed",
                    error="git clone failed: " + str(exc)[-300:], finished=_now())
            return
        _update(scan_id, current_step="Running static analysis (Semgrep)…", progress=45)
        rc = _stream_engine([ENGINE_PY, "mantishack.py", "scan", "--repo", str(clone_dir)], scan_id)
        if rc != 0:
            _update(scan_id, status="failed", error=f"scan engine exited {rc}", finished=_now())
            return
        findings = []
        d = _newest_run("scan_", started)
        if d:
            for sarif in list(d.glob("*.sarif")) + list((d / "codeql").glob("*.sarif")):
                findings.extend(_parse_sarif(sarif))
            for sgj in d.glob("semgrep_*.json"):
                try:
                    sg = json.loads(sgj.read_text(encoding="utf-8-sig"))
                    for r in sg.get("results") or []:
                        findings.append({
                            "rule_id": r.get("check_id", "semgrep"),
                            "severity": _norm_sev((r.get("extra") or {}).get("severity")),
                            "message": (r.get("extra") or {}).get("message", ""),
                            "file_path": r.get("path", ""),
                            "line": (r.get("start") or {}).get("line"),
                        })
                except (ValueError, OSError):
                    continue
        _update(scan_id, status="completed", current_step="Scan complete",
                progress=100, findings=_normalize_findings(findings), finished=_now())
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _worker(scan_id: str, kind: str, target: str) -> None:
    if not _ACTIVE.acquire(timeout=SCAN_TIMEOUT):
        _update(scan_id, status="failed", error="server busy, try again", finished=_now())
        return
    try:
        (_run_web_scan if kind == "web" else _run_repo_scan)(scan_id, target)
    except Exception as exc:  # noqa: BLE001 - never crash the worker thread
        _update(scan_id, status="failed", error=f"{type(exc).__name__}: {exc}", finished=_now())
    finally:
        _ACTIVE.release()


# --------------------------------------------------------------------------- #
# HTTP handler
# --------------------------------------------------------------------------- #
class Handler(BaseHTTPRequestHandler):
    server_version = "MantishackScan/1.0"

    def _security_headers(self, csp: str = "default-src 'none'") -> None:
        self.send_header("Content-Security-Policy", csp)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")

    def _json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._security_headers()
        self.end_headers()
        self.wfile.write(body)

    def _client_ip(self) -> str:
        return self.client_address[0] if self.client_address else "?"

    def _host_ok(self) -> bool:
        """Anti-DNS-rebinding gate (loopback binds only).

        A page that rebinds its hostname to 127.0.0.1 still sends its own
        Host header, which is absent from the allowlist and so rejected.
        For non-loopback binds the legitimate Host varies (LAN IP /
        hostname), so the bearer token is the control there instead.
        """
        if not _BIND_IS_LOCAL:
            return True
        return (self.headers.get("Host") or "").lower() in _ALLOWED_HOSTS

    def _auth_ok(self) -> bool:
        if not _AUTH_TOKEN:
            return True
        hdr = self.headers.get("Authorization", "")
        if not hdr.startswith("Bearer "):
            return False
        return secrets.compare_digest(hdr[len("Bearer "):].strip(), _AUTH_TOKEN)

    def log_message(self, fmt, *args):
        sys.stderr.write("[server] %s\n" % (fmt % args))

    def do_POST(self):
        if self.path.rstrip("/") != "/scan":
            self._json(404, {"error": "not found"})
            return
        if not self._host_ok():
            self._json(403, {"error": "host not allowed"})
            return
        if not self._auth_ok():
            self._json(401, {"error": "authentication required "
                                      "(Authorization: Bearer <token>)"})
            return
        if not _rate_ok(self._client_ip()):
            self._json(429, {"error": "rate limit exceeded — slow down"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY_BYTES:
            self._json(400, {"error": "invalid body length"})
            return
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self._json(400, {"error": "invalid JSON"})
            return
        if not isinstance(payload, dict):
            self._json(400, {"error": "body must be a JSON object"})
            return

        kind = (payload.get("type") or "").lower()
        url = (payload.get("url") or "").strip()
        repo = (payload.get("repo") or "").strip()

        if repo or kind == "repo":
            target = repo or url
            if not target:
                self._json(400, {"error": "missing repo URL"})
                return
            # Validate BEFORE creating a job so rejected input cannot grow
            # the store and never reaches the clone worker.
            if not _repo_url_allowed(target):
                self._json(400, {"error": "repo URL must be a https "
                                          "github.com / gitlab.com repository"})
                return
            scan_id = _new_job(target, "repo")
            threading.Thread(target=_worker, args=(scan_id, "repo", target), daemon=True).start()
            self._json(200, {"scan_id": scan_id, "status": "queued"})
            return

        if not url:
            self._json(400, {"error": "missing url"})
            return
        # SSRF guard: resolve + reject loopback/link-local/private/metadata
        # before a job exists or the crawler runs.
        safe, err = _validate_scan_target_url(url)
        if err:
            self._json(400, {"error": err})
            return
        scan_id = _new_job(safe, "web")
        threading.Thread(target=_worker, args=(scan_id, "web", safe), daemon=True).start()
        self._json(200, {"scan_id": scan_id, "status": "queued"})

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path.startswith("/scan/"):
            if not self._host_ok():
                self._json(403, {"error": "host not allowed"})
                return
            job = _get(path[len("/scan/"):].strip("/"))
            if not job:
                self._json(404, {"error": "unknown scan_id", "status": "failed"})
                return
            self._json(200, job)
            return
        if path == "/health":
            self._json(200, {"ok": True, "engine": str(ENGINE_DIR), "python": ENGINE_PY})
            return
        self._serve_static(path)

    def _serve_static(self, path: str) -> None:
        # Tight allowlist: the SPA itself + an optional assets/ dir for images.
        # The repo is NOT a web root — never serve arbitrary source files.
        rel = path.lstrip("/") or "app.html"
        if rel in ("", "app.html", "index.html"):
            candidate = ENGINE_DIR / "app.html"
        elif rel.startswith("assets/"):
            candidate = (ENGINE_DIR / rel).resolve()
            assets_root = (ENGINE_DIR / "assets").resolve()
            try:
                candidate.relative_to(assets_root)
            except ValueError:
                self._json(403, {"error": "forbidden"})
                return
            if candidate.suffix.lower() not in _CTYPES:
                self._json(403, {"error": "forbidden"})
                return
        else:
            self._json(404, {"error": "not found"})
            return
        if not candidate.is_file():
            self._json(404, {"error": "not found"})
            return
        try:
            data = candidate.read_bytes()
        except OSError:
            self._json(500, {"error": "read error"})
            return
        self.send_response(200)
        self.send_header("Content-Type", _ctype(candidate))
        self.send_header("Content-Length", str(len(data)))
        if candidate.suffix.lower() in (".html", ".htm"):
            # app.html ships inline <script>/<style> and fetches the scan
            # API same-origin. 'unsafe-inline' is required for those, but
            # connect-src 'self' still blocks exfiltration to an external
            # origin if a finding ever smuggled markup past the renderer,
            # and frame-ancestors 'none' blocks clickjacking.
            self._security_headers(
                "default-src 'none'; script-src 'unsafe-inline'; "
                "style-src 'unsafe-inline'; img-src 'self' data:; "
                "connect-src 'self'; base-uri 'none'; form-action 'none'; "
                "frame-ancestors 'none'")
        else:
            self._security_headers()
        self.end_headers()
        self.wfile.write(data)


_CTYPES = {
    ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8", ".json": "application/json",
    ".svg": "image/svg+xml", ".png": "image/png", ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg", ".ico": "image/x-icon", ".webp": "image/webp",
}


def _ctype(p: Path) -> str:
    return _CTYPES.get(p.suffix.lower(), "application/octet-stream")


def main() -> int:
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print("🦂 Mantishack scan server")
    print(f"   engine : {ENGINE_DIR}")
    print(f"   python : {ENGINE_PY}")
    print(f"   open   : http://{HOST}:{PORT}")
    print("   api    : POST /scan · GET /scan/<id> · GET /health")
    if not _BIND_IS_LOCAL:
        print()
        print("   ⚠️  bound to a non-loopback address — reachable off this host.")
        print(f"   token  : {_AUTH_TOKEN}")
        print("            send as  Authorization: Bearer <token>  on POST /scan")
        print("            (pin your own with MANTISHACK_SERVER_TOKEN=…)")
        print()
    elif _AUTH_TOKEN:
        print(f"   token  : {_AUTH_TOKEN}  (Authorization: Bearer <token>)")
    print("   (Ctrl-C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down…")
        httpd.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
