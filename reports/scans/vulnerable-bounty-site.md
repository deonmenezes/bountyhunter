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
