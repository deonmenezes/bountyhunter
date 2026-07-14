# Scan log — vulnerable-bounty-site.vercel.app

Authorized discovery-only target for the recurring "maintenance + testing"
routine (fires every 4h). This file tracks scan attempts/findings over time
so each run can diff against the last one instead of starting cold.

Target: `https://vulnerable-bounty-site.vercel.app`
Scope: discovery-only (no active exploitation, no destructive requests).

---

## 2026-07-13T00:08Z — blocked at the network layer, no scan performed

Every outbound HTTPS request from this session's environment — to the
target *and* to unrelated control domains (`example.com`, `vercel.app`,
`nextjs.org`) — was rejected at the egress proxy with `connect_rejected`,
`gateway answered 403 to CONNECT (policy denial or upstream failure)`.

This is not the target site responding 403; the TLS CONNECT tunnel itself
never completed. The environment's outbound network policy currently allows
only the proxy's static allowlist (anthropic.com, package registries,
git hosts, RFC1918 ranges, etc.) and blocks general internet egress
entirely, so the target domain was unreachable regardless of authorization.

No requests reached `vulnerable-bounty-site.vercel.app`; no findings to
report this run.

**Action needed (outside this session's control):** the environment's
network egress policy needs to allow outbound HTTPS to
`vulnerable-bounty-site.vercel.app` (or a broader "internet" policy) before
this routine can actually perform the authorized scan. See
`https://code.claude.com/docs/en/claude-code-on-the-web` for how environment
network policies are configured.

## 2026-07-13T04:05Z — still blocked at the network layer, no scan performed

Re-checked this run: `curl -sS -m 15 https://vulnerable-bounty-site.vercel.app`
fails with `curl: (56) CONNECT tunnel failed, response 403` before any TLS
handshake with the target occurs. `$HTTPS_PROXY/__agentproxy/status` confirms
the same `connect_rejected` denial recorded above, timestamped this run:

```json
{
  "kind": "connect_rejected",
  "detail": "gateway answered 403 to CONNECT (policy denial or upstream failure)",
  "host": "vulnerable-bounty-site.vercel.app:443"
}
```

No change from the prior run — the egress allowlist still does not include
this target, so the repository's own scanning tools (`http_audit`,
`source_sink_scan`, etc.) were never given a live target to reach. No
findings to report; nothing to compare against a previous scan since no scan
has yet reached the target. Once the environment's network policy allows
outbound HTTPS to this host, the next run should be able to perform an
actual discovery pass (recon → `http_audit` evidence capture → candidate
findings via the mantis-pipeline stages) instead of only recording the
block.

## 2026-07-14T04:08Z — still blocked at the network layer, no scan performed

Third consecutive run with the same result. Re-verified with both `curl` and
the `WebFetch` tool (which routes independently of this session's raw
`HTTPS_PROXY`) to rule out a tool-specific issue rather than an
environment-wide policy:

- `curl -sS -m 15 https://vulnerable-bounty-site.vercel.app` →
  `curl: (56) CONNECT tunnel failed, response 403`
- `curl -sS -m 15 https://example.com` (unrelated control domain) → same
  `CONNECT tunnel failed, response 403`
- `WebFetch` against the target → `The server returned HTTP 403 Forbidden`
  (rejected before reaching the origin; same shape as the proxy denial, not
  a target-side response)
- `$HTTPS_PROXY/__agentproxy/status` → `recentRelayFailures` shows two fresh
  `connect_rejected` entries for `vulnerable-bounty-site.vercel.app:443`
  timestamped this run (`2026-07-14T04:05:03Z`, `2026-07-14T04:08:04Z`), plus
  matching denials for `example.com:443`

Same conclusion as the last two runs: this is a categorical "no general
internet egress" policy on the environment, not anything specific to the
target or to how the request is made. No request has ever reached
`vulnerable-bounty-site.vercel.app` across three runs now, so there is
still nothing to diff and no findings to report.

**Action needed (unchanged, outside this session's control):** add
`vulnerable-bounty-site.vercel.app` (or general internet egress) to this
environment's outbound network policy. Until that happens, every future
firing of this routine will keep producing the same "blocked, no scan"
result — worth fixing the policy once rather than re-discovering this every
4 hours.
