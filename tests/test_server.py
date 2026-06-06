"""Tests for the local scan server (``server.py``).

Covers the security-relevant surface the server adds:

  * the SSRF guard on web-scan target URLs (``_validate_scan_target_url``),
  * the github/gitlab repo allowlist (``_repo_url_allowed``),
  * finding normalisation / SARIF parsing,
  * the bounded job store (TTL + hard cap) and the per-IP rate limiter,
  * the HTTP gate chain end-to-end (body cap, JSON validation, Host-header
    allowlist, validate-before-job) via a live ``ThreadingHTTPServer``.

All tests are network-free: the SSRF cases use literal IPs (no DNS), the
repo allowlist is pure regex, and the live-server tests monkeypatch the
worker so no clone/crawl ever runs.

Run with:  ``pytest tests/test_server.py``
(The root CI invocation is ``pytest core packages`` and does not collect
this top-level ``tests/`` dir — wire it in when ``server.py`` lands on the
branch CI runs against.)
"""
from __future__ import annotations

import http.client
import json
import sys
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

# ``import server`` must work regardless of pytest's import mode: the
# scan server lives at the repo root, which isn't on the path under
# ``--import-mode=importlib``.
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import server as srv  # noqa: E402


# --------------------------------------------------------------------------- #
# SSRF guard
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("url", [
    "http://169.254.169.254/latest/meta-data/",   # cloud metadata (link-local)
    "http://127.0.0.1:8080/",                      # loopback
    "http://[::1]/",                               # IPv6 loopback
    "http://10.1.2.3/",                            # RFC1918
    "http://172.16.0.1/",                          # RFC1918
    "http://192.168.0.5/",                         # RFC1918
    "http://0.0.0.0/",                             # unspecified
    "localhost",                                   # hostname blocklist
    "metadata.google.internal",                    # GCP metadata name
])
def test_ssrf_blocks_internal_targets(url):
    safe, err = srv._validate_scan_target_url(url)
    assert safe is None
    assert err  # a non-empty reason


def test_ssrf_allows_public_literal_ip():
    safe, err = srv._validate_scan_target_url("http://8.8.8.8/")
    assert err is None
    assert safe == "http://8.8.8.8/"


def test_ssrf_defaults_scheme_to_https():
    safe, err = srv._validate_scan_target_url("8.8.8.8")
    assert err is None
    assert safe == "https://8.8.8.8"


@pytest.mark.parametrize("url,reason_contains", [
    ("ftp://8.8.8.8/", "http(s)"),
    ("file:///etc/passwd", "http(s)"),
    ("http://user:pass@8.8.8.8/", "credentials"),
    ("http:///path-only", "host"),
])
def test_ssrf_rejects_bad_shape(url, reason_contains):
    safe, err = srv._validate_scan_target_url(url)
    assert safe is None
    assert reason_contains in err


def test_ip_is_blocked():
    assert srv._ip_is_blocked("127.0.0.1")
    assert srv._ip_is_blocked("169.254.169.254")
    assert srv._ip_is_blocked("10.0.0.1")
    assert srv._ip_is_blocked("not-an-ip")     # unparseable → fail closed
    assert not srv._ip_is_blocked("8.8.8.8")
    assert not srv._ip_is_blocked("1.1.1.1")


# --------------------------------------------------------------------------- #
# Repo allowlist
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("repo,allowed", [
    ("https://github.com/user/repo", True),
    ("https://gitlab.com/group/proj", True),
    ("https://github.com/user/repo/", True),
    ("https://evil.com/user/repo", False),
    ("http://github.com/user/repo", False),          # http rejected
    ("file:///etc/passwd", False),
    ("git@github.com:user/repo.git", True),
    ("https://github.com/user/repo/../../etc", False),
    ("https://github.com/-flag/repo", False),        # leading-dash owner
    ("ssh://github.com/user/repo", False),
])
def test_repo_allowlist(repo, allowed):
    assert srv._repo_url_allowed(repo) is allowed


# --------------------------------------------------------------------------- #
# Finding normalisation + SARIF parsing
# --------------------------------------------------------------------------- #
def test_norm_sev_maps_synonyms():
    assert srv._norm_sev("ERROR") == "high"
    assert srv._norm_sev("warning") == "medium"
    assert srv._norm_sev("note") == "low"
    assert srv._norm_sev("CRITICAL") == "critical"
    assert srv._norm_sev(None) == "low"
    assert srv._norm_sev("nonsense") == "low"


def test_normalize_findings_key_fallbacks():
    raw = [
        {"severity_assessment": "high", "vuln_type": "SQLi",
         "file": "a.py", "start_line": 12, "reasoning": "tainted"},
        {"level": "warning", "rule_id": "R1", "message": "m"},
        "not-a-dict",  # skipped
    ]
    out = srv._normalize_findings(raw)
    assert len(out) == 2
    assert out[0]["severity"] == "high"
    assert out[0]["title"] == "SQLi"
    assert out[0]["file_path"] == "a.py"
    assert out[0]["line"] == 12
    assert out[1]["severity"] == "medium"
    assert out[1]["title"] == "R1"


def test_parse_sarif(tmp_path):
    sarif = {
        "runs": [{
            "results": [{
                "ruleId": "py/sql-injection",
                "level": "error",
                "message": {"text": "tainted query"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "app/db.py"},
                    "region": {"startLine": 42},
                }}],
            }],
        }],
    }
    p = tmp_path / "out.sarif"
    p.write_text(json.dumps(sarif), encoding="utf-8")
    findings = srv._parse_sarif(p)
    assert len(findings) == 1
    f = findings[0]
    assert f["rule_id"] == "py/sql-injection"
    assert f["severity"] == "high"
    assert f["file_path"] == "app/db.py"
    assert f["line"] == 42


def test_parse_sarif_bad_file(tmp_path):
    p = tmp_path / "broken.sarif"
    p.write_text("{not json", encoding="utf-8")
    assert srv._parse_sarif(p) == []


# --------------------------------------------------------------------------- #
# Bounded job store + rate limiter
# --------------------------------------------------------------------------- #
def test_reap_jobs_ttl(monkeypatch):
    monkeypatch.setattr(srv, "_JOBS", {})
    now = srv._now()
    srv._JOBS["old"] = {"started": now - 10_000, "finished": now - 9_000}
    srv._JOBS["fresh"] = {"started": now, "finished": None}
    srv._reap_jobs()
    assert "old" not in srv._JOBS      # finished + past TTL → reaped
    assert "fresh" in srv._JOBS        # unfinished → kept


def test_reap_jobs_hard_cap(monkeypatch):
    monkeypatch.setattr(srv, "_JOBS", {})
    monkeypatch.setattr(srv, "MAX_JOBS", 5)
    now = srv._now()
    for i in range(20):
        srv._JOBS[f"j{i}"] = {"started": now + i, "finished": None}
    srv._reap_jobs()
    assert len(srv._JOBS) <= 5
    # The newest (highest start time) survive.
    assert "j19" in srv._JOBS
    assert "j0" not in srv._JOBS


def test_rate_limit(monkeypatch):
    monkeypatch.setattr(srv, "_RATE", {})
    monkeypatch.setattr(srv, "RATE_LIMIT_MAX", 3)
    monkeypatch.setattr(srv, "RATE_LIMIT_WINDOW", 60)
    assert srv._rate_ok("1.2.3.4")
    assert srv._rate_ok("1.2.3.4")
    assert srv._rate_ok("1.2.3.4")
    assert not srv._rate_ok("1.2.3.4")     # 4th in window → blocked
    assert srv._rate_ok("5.6.7.8")         # a different client is unaffected


# --------------------------------------------------------------------------- #
# Live HTTP gate chain
# --------------------------------------------------------------------------- #
@pytest.fixture
def live_server(monkeypatch):
    """A running server on an ephemeral loopback port with the worker
    stubbed out (no clone/crawl) and the Host allowlist widened to the
    test port. Yields ``(port, worker_calls)``."""
    calls = []
    monkeypatch.setattr(
        srv, "_worker",
        lambda scan_id, kind, target: calls.append((scan_id, kind, target)))
    monkeypatch.setattr(srv, "_RATE", {})
    monkeypatch.setattr(srv, "_JOBS", {})

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), srv.Handler)
    port = httpd.server_address[1]
    monkeypatch.setattr(
        srv, "_ALLOWED_HOSTS",
        set(srv._ALLOWED_HOSTS) | {f"127.0.0.1:{port}", f"localhost:{port}"})
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        yield port, calls
    finally:
        httpd.shutdown()
        httpd.server_close()


def _post(port, body, *, host=None, raw_body=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    payload = raw_body if raw_body is not None else json.dumps(body).encode()
    if host is None:
        conn.request("POST", "/scan", body=payload,
                     headers={"Content-Type": "application/json"})
    else:
        # Manual request so we can forge a Host header.
        conn.putrequest("POST", "/scan", skip_host=True, skip_accept_encoding=True)
        conn.putheader("Host", host)
        conn.putheader("Content-Type", "application/json")
        conn.putheader("Content-Length", str(len(payload)))
        conn.endheaders()
        conn.send(payload)
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp.status, data


def _get(port, path):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", path)
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp.status, data


def test_post_valid_repo_queued(live_server):
    port, calls = live_server
    status, data = _post(port, {"repo": "https://github.com/octocat/Hello-World"})
    assert status == 200
    body = json.loads(data)
    assert body["scan_id"].startswith("scan_")
    assert body["status"] == "queued"
    # The worker was dispatched (stubbed) for a repo scan.
    for _ in range(50):
        if calls:
            break
        time.sleep(0.01)
    assert calls and calls[0][1] == "repo"


def test_post_rejects_non_allowlisted_repo(live_server):
    port, _ = live_server
    status, data = _post(port, {"repo": "https://evil.example.com/a/b"})
    assert status == 400
    assert b"github.com" in data


def test_post_rejects_ssrf_url(live_server):
    port, _ = live_server
    status, data = _post(port, {"url": "http://169.254.169.254/"})
    assert status == 400
    assert b"SSRF" in data or b"private" in data


def test_post_rejects_oversize_body(live_server):
    port, _ = live_server
    big = b'{"url":"' + b"a" * (srv.MAX_BODY_BYTES + 1) + b'"}'
    status, data = _post(port, None, raw_body=big)
    assert status == 400
    assert b"body length" in data


def test_post_rejects_invalid_json(live_server):
    port, _ = live_server
    status, data = _post(port, None, raw_body=b"{not valid json")
    assert status == 400
    assert b"invalid JSON" in data


def test_post_rejects_missing_target(live_server):
    port, _ = live_server
    status, data = _post(port, {})
    assert status == 400


def test_post_rejects_bad_host_header(live_server):
    """Anti-DNS-rebinding: a forged Host not in the allowlist is refused
    on a loopback bind."""
    port, _ = live_server
    status, data = _post(port, {"url": "http://8.8.8.8/"}, host="evil.attacker.test")
    assert status == 403
    assert b"host not allowed" in data


def test_health_ok(live_server):
    port, _ = live_server
    status, data = _get(port, "/health")
    assert status == 200
    assert json.loads(data)["ok"] is True


def test_unknown_scan_id(live_server):
    port, _ = live_server
    status, data = _get(port, "/scan/scan_does_not_exist")
    assert status == 404


def test_security_headers_on_health(live_server):
    port, _ = live_server
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", "/health")
    resp = conn.getresponse()
    resp.read()
    assert resp.getheader("X-Content-Type-Options") == "nosniff"
    assert resp.getheader("X-Frame-Options") == "DENY"
    assert "default-src" in (resp.getheader("Content-Security-Policy") or "")
    conn.close()
