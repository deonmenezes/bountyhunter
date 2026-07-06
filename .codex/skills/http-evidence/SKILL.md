---
name: http-evidence
description: Turn a captured HTTP request/response into a bounded, redacted evidence pack with a stable request-ref using the mantis_http_audit MCP server, instead of pasting raw traffic into a finding
---

Use `http_audit` (mantis_http_audit MCP server) whenever you have a captured HTTP exchange that proves a web finding, before attaching it as evidence. It converts raw request/response text into a bounded, redacted evidence pack and a stable `request_ref`/`response_ref` hash.

Why go through it instead of pasting the raw exchange into the finding:

- It strips secret-bearing headers (`Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, CSRF tokens, ...) and inline secrets (AWS keys, GitHub/Slack tokens, JWTs, private keys, `user:pass@` in URLs). Raw secrets must never land in a finding, artifact, report, or prompt (PRD section 9/11).
- It bounds the body: full bodies are hashed and previewed (first 512 bytes), never stored whole.
- The `request_ref` is a stable hash of the exchange, so the same request always maps to the same id -- use it to cross-reference and dedup evidence across findings.

Workflow: capture the request (and response) text -> call `http_audit({ request, response })` -> attach the returned `request_ref`/`response_ref` and the redacted pack to the finding via `mantis_findings` `finding_update` `evidence`. The tool makes NO network call itself; you pass in traffic you already captured under authorized, scoped testing.

Do not defeat the redaction by separately pasting the raw header/body you just redacted into the finding or report. If you need to prove a specific secret was exposed, reference it by its redaction label and location, and follow the `secrets-scan` skill's remediation guidance (rotate/revoke, then remove from source and history).
