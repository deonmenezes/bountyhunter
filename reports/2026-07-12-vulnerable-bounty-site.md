# Scan log — vulnerable-bounty-site.vercel.app

**Run date:** 2026-07-12
**Target:** `https://vulnerable-bounty-site.vercel.app` (owner-authorized discovery-only target)
**Scope:** discovery only — no active exploitation, no destructive requests

## Result: scan did not run — network egress blocked

This session's outbound network goes through a policy-enforcing egress proxy
(`/root/.ccr/`). Every attempt to reach the target host was rejected by the
proxy itself, before any request reached the target:

- `curl` (direct HTTPS CONNECT): `curl: (56) CONNECT tunnel failed, response 403`
- `WebFetch` tool: `HTTP 403 Forbidden` (surfaced from the proxy, not the target)
- Proxy status endpoint (`GET /__agentproxy/status`) confirms the rejection is
  a policy denial, not a target-side response:

  ```json
  {
    "kind": "connect_rejected",
    "detail": "gateway answered 403 to CONNECT (policy denial or upstream failure)",
    "host": "vulnerable-bounty-site.vercel.app:443"
  }
  ```

Per this session's own operating instructions (`/root/.ccr/README.md`), a
403/407 from the proxy means the destination host is not on this session's
egress allowlist, and the correct action is to report the blocked host rather
than retry or route around it. No requests were sent to the target; no
findings were produced this run.

## What's needed to unblock future runs

The environment (or the specific session/routine environment) needs
`vulnerable-bounty-site.vercel.app` added to its outbound network allowlist.
Once that's in place, this routine can run the intended discovery pass
(headers/security-misconfig check, exposed-file probe, cookie-flag check,
lightweight reflected-input check, etc.) using the repo's `http_audit` /
`mantis_findings` tooling to capture and redact evidence.

## Detection-improvement work this run

Unrelated to the scan, this run also proposed a small detection-coverage
improvement: XXE (CWE-611) sink coverage for `source_sink_scan`
(`.codex/mcp-servers/program-analysis/source_sink_rules.js`). See
[#125](https://github.com/deonmenezes/mantishack/pull/125).
