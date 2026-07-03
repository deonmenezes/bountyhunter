#!/usr/bin/env node
"use strict";

/*
 * Mantis local scan server.
 *
 * Turns this laptop into the scan backend for mantishack.com: real internet
 * requests (forwarded through a cloudflared tunnel) trigger the Mantis web
 * scanner here, in a subprocess or a Docker container.
 *
 * Guardrails ON by default (loosen each with one env var):
 *   - SCAN_TOKEN     shared token; requests must send it. OPEN=1 disables.
 *   - ALLOWED_HOSTS  comma list of allowed target host suffixes. '*' = any.
 *   - MAX_CONCURRENT=1, MAX_QUEUE, RUN_TIMEOUT_MS, RATE_PER_MIN.
 *   - Private / loopback / cloud-metadata IPs are always blocked (anti-SSRF).
 *
 * Zero npm dependencies — Node built-ins only.
 */

const http = require("http");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawn } = require("child_process");

// ── Config ────────────────────────────────────────────────────────────────
const PORT = parseInt(process.env.PORT || "8787", 10);
const OPEN = /^(1|true|yes|on)$/i.test(process.env.OPEN || "");
const SCAN_TOKEN = process.env.SCAN_TOKEN || (OPEN ? "" : crypto.randomBytes(12).toString("hex"));
const ALLOWED_HOSTS = (process.env.ALLOWED_HOSTS || "mantishack.com,virelity.com")
  .split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
const ALLOW_ANY_HOST = ALLOWED_HOSTS.includes("*");
const HARNESS_DIR = process.env.HARNESS_DIR || path.join(os.homedir(), "Projects", "mantishack");
const USE_DOCKER = /^(1|true|yes|on)$/i.test(process.env.USE_DOCKER || "");
const DOCKER_IMAGE = process.env.DOCKER_IMAGE || "mantis-web:local";
const MAX_CONCURRENT = parseInt(process.env.MAX_CONCURRENT || "1", 10);
const MAX_QUEUE = parseInt(process.env.MAX_QUEUE || "5", 10);
const RUN_TIMEOUT_MS = parseInt(process.env.RUN_TIMEOUT_MS || String(10 * 60 * 1000), 10);
const RATE_PER_MIN = parseInt(process.env.RATE_PER_MIN || "6", 10);
const OUT_ROOT = process.env.OUT_ROOT || path.join(os.tmpdir(), "mantis-scans");
const CORS_ORIGIN = process.env.CORS_ORIGIN || "https://mantishack.com";
const UNSAFE_ENV_KEYS = new Set([
  "SCAN_TOKEN", "TERMINAL", "EDITOR", "VISUAL", "BROWSER", "PAGER",
]);

fs.mkdirSync(OUT_ROOT, { recursive: true });

// ── State ─────────────────────────────────────────────────────────────────
const jobs = new Map();      // id -> job
const queue = [];            // ids waiting
let running = 0;
const rate = new Map();      // ip -> [timestamps]

// ── Helpers ───────────────────────────────────────────────────────────────
function send(res, code, body) {
  const data = Buffer.from(JSON.stringify(body));
  res.writeHead(code, {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": CORS_ORIGIN,
    "Access-Control-Allow-Headers": "Content-Type, X-Scan-Token",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Content-Length": data.length,
  });
  res.end(data);
}

function clientIp(req) {
  // Only trust X-Forwarded-For from loopback (i.e. from a local reverse
  // proxy such as cloudflared).  Direct external connections must use
  // the socket address so clients cannot spoof their IP to bypass the
  // rate limiter.
  const peer = req.socket.remoteAddress || "";
  const isLoopback = peer === "127.0.0.1" || peer === "::1" || peer === "::ffff:127.0.0.1";
  if (isLoopback) {
    const xff = req.headers["x-forwarded-for"];
    if (typeof xff === "string" && xff.length) return xff.split(",")[0].trim();
  }
  return peer || "unknown";
}

function rateOk(ip) {
  const now = Date.now();
  const win = (rate.get(ip) || []).filter((t) => now - t < 60_000);
  if (win.length >= RATE_PER_MIN) { rate.set(ip, win); return false; }
  win.push(now);
  rate.set(ip, win);
  return true;
}

function isBlockedHost(host) {
  const h = host.toLowerCase();
  if (h === "localhost" || h.endsWith(".localhost")) return true;
  // IPv4 literal checks for private / loopback / link-local / metadata
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const [a, b] = [parseInt(m[1], 10), parseInt(m[2], 10)];
    if (a === 127 || a === 10 || a === 0) return true;
    if (a === 192 && b === 168) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 169 && b === 254) return true; // link-local + 169.254.169.254 metadata
    if (a >= 224) return true;               // multicast / reserved
  }
  if (h === "::1" || h.startsWith("fe80:") || h.startsWith("fc") || h.startsWith("fd")) return true;
  return false;
}

function validateTarget(raw) {
  let u;
  try { u = new URL(raw); } catch { return { ok: false, why: "not a valid URL" }; }
  if (!/^https?:$/.test(u.protocol)) return { ok: false, why: "only http/https targets" };
  const host = u.hostname;
  if (isBlockedHost(host)) return { ok: false, why: "internal/private targets are blocked" };
  if (!ALLOW_ANY_HOST) {
    const allowed = ALLOWED_HOSTS.some((d) => host === d || host.endsWith("." + d));
    if (!allowed) {
      return { ok: false, why: `host not in allowlist (${ALLOWED_HOSTS.join(", ")}). Set ALLOWED_HOSTS to widen.` };
    }
  }
  return { ok: true, url: u.toString(), host };
}

// ── Runner ────────────────────────────────────────────────────────────────
function buildCommand(target, outDir) {
  if (USE_DOCKER) {
    return {
      cmd: "docker",
      args: ["run", "--rm", "--pull", "never",
        "-v", `${outDir}:/out`,
        DOCKER_IMAGE, "web", "--url", target, "--out", "/out"],
      cwd: process.cwd(),
    };
  }
  const py = path.join(HARNESS_DIR, ".venv", "bin", "python");
  const bin = fs.existsSync(py) ? py : "python3";
  return {
    cmd: bin,
    args: ["mantishack.py", "web", "--url", target, "--out", outDir],
    cwd: HARNESS_DIR,
  };
}

function startJob(job) {
  running++;
  job.status = "running";
  job.startedAt = Date.now();
  const outDir = path.join(OUT_ROOT, job.id);
  fs.mkdirSync(outDir, { recursive: true });
  job.outDir = outDir;

  const { cmd, args, cwd } = buildCommand(job.target, outDir);
  job.command = `${cmd} ${args.join(" ")}`;
  let tail = "";
  let settled = false;
  // Filter environment: strip SCAN_TOKEN and shell-evaluating keys
  // (mirrors the framework's get_safe_env() policy).
  const childEnv = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (!UNSAFE_ENV_KEYS.has(k)) childEnv[k] = v;
  }
  const child = spawn(cmd, args, { cwd, env: childEnv });
  job.pid = child.pid;

  const onData = (d) => { tail = (tail + d.toString()).slice(-8000); job.logTail = tail; };
  child.stdout.on("data", onData);
  child.stderr.on("data", onData);

  const killer = setTimeout(() => {
    job.timedOut = true;
    try { child.kill("SIGKILL"); } catch {}
  }, RUN_TIMEOUT_MS);

  child.on("error", (err) => {
    if (settled) return;
    settled = true;
    clearTimeout(killer);
    job.status = "error";
    job.error = err.message;
    job.finishedAt = Date.now();
    finish(job);
  });

  child.on("close", (code) => {
    if (settled) return;
    settled = true;
    clearTimeout(killer);
    job.exitCode = code;
    job.finishedAt = Date.now();
    let artifacts = [];
    try { artifacts = fs.readdirSync(outDir); } catch {}
    job.artifacts = artifacts;
    job.status = job.timedOut ? "timeout" : code === 0 ? "done" : "error";
    finish(job);
  });
}

function finish(job) {
  running--;
  pump();
}

function pump() {
  while (running < MAX_CONCURRENT && queue.length) {
    const id = queue.shift();
    const job = jobs.get(id);
    if (job && job.status === "queued") startJob(job);
  }
}

// ── HTTP ──────────────────────────────────────────────────────────────────
const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);

  if (req.method === "OPTIONS") return send(res, 204, {});

  if (req.method === "GET" && url.pathname === "/api/health") {
    return send(res, 200, {
      ok: true, running, queued: queue.length, maxConcurrent: MAX_CONCURRENT,
    });
  }

  // GET /api/scan/:id — require token so log output isn't world-readable.
  const statusMatch = url.pathname.match(/^\/api\/scan\/([A-Za-z0-9_-]+)$/);
  if (req.method === "GET" && statusMatch) {
    const token = req.headers["x-scan-token"] || url.searchParams.get("token") || "";
    if (!OPEN && token !== SCAN_TOKEN) return send(res, 401, { error: "missing/invalid token" });
    const job = jobs.get(statusMatch[1]);
    if (!job) return send(res, 404, { error: "no such job" });
    return send(res, 200, publicJob(job));
  }

  if (req.method === "POST" && url.pathname === "/api/scan") {
    const ip = clientIp(req);
    if (!rateOk(ip)) return send(res, 429, { error: "rate limited, slow down" });

    let raw = "";
    req.on("data", (c) => { raw += c; if (raw.length > 8192) req.destroy(); });
    req.on("end", () => {
      let body = {};
      try { body = JSON.parse(raw || "{}"); } catch { return send(res, 400, { error: "bad JSON" }); }

      const token = req.headers["x-scan-token"] || body.token || "";
      if (!OPEN && token !== SCAN_TOKEN) return send(res, 401, { error: "missing/invalid token" });

      const v = validateTarget(String(body.target || ""));
      if (!v.ok) return send(res, 400, { error: v.why });

      if (queue.length >= MAX_QUEUE) return send(res, 503, { error: "queue full, try later" });

      const id = crypto.randomBytes(6).toString("hex");
      const job = { id, target: v.url, host: v.host, status: "queued", createdAt: Date.now(), ip };
      jobs.set(id, job);
      queue.push(id);
      pump();
      return send(res, 202, { id, status: job.status, poll: `/api/scan/${id}` });
    });
    return;
  }

  return send(res, 404, { error: "not found" });
});

function publicJob(job) {
  return {
    id: job.id, target: job.target, status: job.status,
    createdAt: job.createdAt, startedAt: job.startedAt, finishedAt: job.finishedAt,
    exitCode: job.exitCode, timedOut: !!job.timedOut, artifacts: job.artifacts || [],
    logTail: job.logTail || "", error: job.error,
  };
}

server.listen(PORT, "127.0.0.1", () => {
  console.log(`\n  Mantis scan server → http://127.0.0.1:${PORT}`);
  console.log(`  mode          : ${USE_DOCKER ? `docker (${DOCKER_IMAGE})` : "subprocess (.venv)"}`);
  console.log(`  harness dir   : ${HARNESS_DIR}`);
  console.log(`  allowed hosts : ${ALLOW_ANY_HOST ? "* (ANY — open relay!)" : ALLOWED_HOSTS.join(", ")}`);
  console.log(`  auth          : ${OPEN ? "OPEN (no token!)" : `token required`}`);
  if (!OPEN) {
    const redacted = SCAN_TOKEN.slice(0, 4) + "…" + SCAN_TOKEN.slice(-4);
    console.log(`  SCAN_TOKEN    : ${redacted}  (full value in SCAN_TOKEN env var or pass --show-token)`);
    if (process.argv.includes("--show-token")) console.log(`  SCAN_TOKEN    : ${SCAN_TOKEN}`);
  }
  console.log(`  limits        : ${MAX_CONCURRENT} concurrent · queue ${MAX_QUEUE} · ${RATE_PER_MIN}/min/ip · ${Math.round(RUN_TIMEOUT_MS/60000)}m timeout\n`);
});
