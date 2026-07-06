---
name: semgrep-triage
description: Run semgrep via the mantis_semgrep MCP server and triage results into the candidate/confirmed/rejected lifecycle
---

Use the `semgrep_scan` tool (mantis_semgrep MCP server) for the **Detect** stage of the Mantis pipeline: high-recall SAST over a file or directory.

- Default `config` to `"auto"`. Prefer a narrower ruleset (e.g. `"p/owasp-top-ten"`, `"p/secrets"`) when you already know the vulnerability class you're hunting.
- Every result is a `candidate`, not a finding. Do not report severity from semgrep's own `ERROR`/`WARNING`/`INFO` labels as final severity -- those describe rule confidence, not demonstrated impact.
- For each candidate: trace the exact source-to-sink path in the surrounding code before deciding it's worth validating further. If the sink is unreachable from attacker-controlled input (auth-gated, admin-only, framework-sanitized), reject it and cite the specific roadblock -- never "seems safe."
- Reachable candidates move to attacker-simulation validation (see `program-analysis` skill for the reachability tools) before you claim a confirmed finding.
- If `semgrep` reports `available: false`, tell the user it isn't installed rather than silently skipping SAST coverage.
