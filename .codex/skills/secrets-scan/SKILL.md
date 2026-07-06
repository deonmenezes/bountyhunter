---
name: secrets-scan
description: Run trufflehog via the mantis_trufflehog MCP server and handle secret findings without ever exposing the raw secret
---

Use `trufflehog_scan({ path, only_verified })` (mantis_trufflehog MCP server) for the **Detect** stage's secrets coverage.

- The server already redacts every secret value before it reaches you (`redacted_secret` is a masked preview, never the full value). Never try to reconstruct, print, or echo the full secret elsewhere -- e.g. don't re-read the source line containing it and paste it into a report just because the tool redacted its own output.
- `verified: true` means trufflehog live-checked the credential against its provider and it's currently active -- treat this as a near-`confirmed` finding with severity driven by what the credential can access. `verified: false` is a `candidate` (pattern-matched but not live-checked, could be a dead/rotated key or a false-positive-looking test fixture).
- Remediation for any verified secret is always: rotate/revoke the credential at the provider, then remove it from source (and consider it compromised in git history even after removal -- flag that separately, since simply deleting the line does not purge history).
- Set `only_verified: true` when you specifically want to cut noise from test fixtures and example keys; leave it off for full recall during an initial sweep.
