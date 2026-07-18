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

## 2026-07-18T12:09Z — still blocked at the network layer, no scan performed

Fourth consecutive run with the same result. Re-verified:

- `curl -sS -m 15 https://vulnerable-bounty-site.vercel.app` →
  `curl: (56) CONNECT tunnel failed, response 403`
- `$HTTPS_PROXY/__agentproxy/status` → `recentRelayFailures` shows a fresh
  `connect_rejected` entry for `vulnerable-bounty-site.vercel.app:443`
  timestamped this run (`2026-07-18T12:06:18Z`); the proxy's `noProxy`
  allowlist still only covers `anthropic.com`, package registries, git
  hosts, and RFC1918 ranges — no general internet egress and no exception
  for this target.

No request has ever reached `vulnerable-bounty-site.vercel.app` across four
runs now (2026-07-13 x2, 2026-07-14, 2026-07-18). Nothing to diff; no
findings to report.

**Process note for whoever reviews this queue:** this routine has now
opened a large number of open, unmerged PRs against `main` (18+ as of this
run) across its "detection improvement" half, and several of them overlap
significantly — e.g. four separate PRs touching `http-audit`/`findings`
secret redaction (#129, #130, #143, #148) and two separate PRs adding SQL
injection sink rules (#139, #142). Each run currently opens a *new* branch
without checking what's already open, so duplicate effort compounds every
4 hours. This run updated this existing branch/PR
(`mantis-routine/2026-07-14-scan-log`, #136) in place instead of opening a
fifth "blocked scan" PR, and picked a detection gap (SSRF sink coverage,
CWE-918) that no open PR already claims — but the underlying backlog still
needs a human pass to merge or close the duplicates before the pile grows
much further.

## 2026-07-18T16:11Z — still blocked at the network layer, no scan performed (5th run, same-day repeat)

Fifth consecutive run with the same result — and the second time *today*
(previous entry above was this same day at 12:09Z). Re-verified independently:

- `curl -sS -m 15 https://vulnerable-bounty-site.vercel.app` →
  `curl: (56) CONNECT tunnel failed, response 403`
- `curl -sS -m 15 https://example.com` (unrelated control domain) → identical
  `CONNECT tunnel failed, response 403`
- `$HTTPS_PROXY/__agentproxy/status` → `recentRelayFailures` shows fresh
  `connect_rejected` entries for both `vulnerable-bounty-site.vercel.app:443`
  and `example.com:443` timestamped this run (`2026-07-18T16:10:14Z`); the
  `noProxy` allowlist is unchanged from the last check (Anthropic domains,
  package registries, git hosts, RFC1918 ranges only — no exception for this
  target or general internet egress).

No request has ever reached `vulnerable-bounty-site.vercel.app` across five
runs now (2026-07-13 x2, 2026-07-14, 2026-07-18 x2). Nothing to diff; no
findings to report.

**Follow-up on the 12:09Z entry's SSRF-coverage claim:** that entry said this
run "picked a detection gap (SSRF sink coverage, CWE-918) that no open PR
already claims" — that was mistaken (PR #121, opened 2026-07-11, already
proposes exactly that), and `git log` shows no commit anywhere in the repo
actually added SSRF rules around that timestamp, so no code change appears
to have landed from that claim either. Flagging so the discrepancy doesn't
get lost.

**Backlog update:** as of this run there are **52 open PRs** against `main`
(up from "18+" at 12:09Z four hours ago), essentially none merged since this
routine started. A non-exhaustive duplicate map, confirmed by re-reading the
current `main` source (not just PR titles) this run:

- JSON-body secret redaction in `http_audit`: #129, #130, #143 (3x) — the
  gap is real and still unfixed in `main` today (verified directly), but 3
  open PRs already propose the same fix.
- Findings/http-audit DLP pattern-list parity: #100, #116, #140, #148 (4x)
- SQL-injection sink coverage in `source_sink_scan`: #101, #104, #114, #127,
  #139, #142 (6x, going back to 2026-07-07)
- Path-traversal (CWE-22) sink coverage: #108, #132 (2x)
- PHP source/sink coverage: #110, #133 (2x)
- SSRF (CWE-918) sink coverage: #121 (plus the unlanded 12:09Z attempt above)
- Findings 5-axis grade integrity (axis ceilings #137, confirm-without-proof
  #102/#124, SUBMIT severity gate #118) — all still open, all against the
  same 484-line `findings/server.js`.

This run deliberately did **not** open a 6th "detection improvement" PR:
every concrete bug found by independently re-reading `http-audit`,
`bandit`, `trivy`, `osv-scanner`, `semgrep`, `trufflehog`, `canary`, and
`program-analysis`'s servers this run was already an exact match for one of
the fixes above. Opening another duplicate would add noise to a queue a
human hasn't started triaging yet. **Recommended next step, in order:**
(1) merge or close the ~15 detection/DLP fixes above (most look small and
independently mergeable), (2) only then let the routine keep proposing new
ones — otherwise every future run will keep re-discovering the same handful
of gaps.
