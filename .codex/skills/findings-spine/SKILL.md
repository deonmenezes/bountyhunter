---
name: findings-spine
description: Record and advance every vulnerability finding through the tool-owned mantis_findings service instead of tracking findings in prose
---

The `mantis_findings` MCP server owns finding state (PRD section 9, FR-9.*). Findings live in an append-only event log at `.codex/findings/events.jsonl`, not in your message history -- so a run is reconstructable and nothing is silently dropped. Never track confirmed/rejected findings only in prose; write them through this service so ids, lifecycle, severity, evidence, and grade are authoritative.

Lifecycle (PRD section 5): `candidate -> confirmed | rejected -> exploited -> fixed -> verified`. `rejected` is terminal. Detect is generous, Validate is ruthless.

When to call each tool:

- **`finding_create`**: the moment Detect/Recon surfaces a plausible weakness, register it as a `candidate`. Do NOT self-censor false positives at this stage -- high recall is the point; killing false positives is Validate's job. Pass `vuln_class`, a one-sentence `claim`, and `location`. You get back a stable `id` -- use it in every later step.
- **`finding_update` to `confirmed`**: only after attacker-simulation. The service refuses to confirm without reachability evidence -- pass `reachability_note` (how attacker-controlled input provably reaches the sink) or attach `evidence` first. "No proof -> no confirm."
- **`finding_update` to `rejected`**: requires `rejected_reason` naming the SPECIFIC roadblock (auth gate, sanitizer/parameterization at the sink, provably-unreachable path, self-only harm, framework auto-protection). The service rejects "seems safe" by requiring the field -- but you must still make the reason specific and true.
- **`finding_update` with `grade`**: pass the 5 axes (impact 0-30, proof 0-25, severity_accuracy 0-15, chain 0-15, report_quality 0-15). The service computes the total and the SUBMIT (>=40) / HOLD (20-39) / SKIP (<20) disposition for you.
- **`finding_update` with `evidence` / `poc` / `patch`**: append bounded evidence refs, a PoC descriptor (gated exploit stage only), or a patch descriptor as the finding advances.
- **`finding_list`**: before you write a report, list findings to get the authoritative queue and a by-status / by-severity summary. Report from this, not from memory.

Evidence discipline (PRD section 9 / 11): the service refuses payloads that look like they contain a raw secret, token, key, or JWT. Store a redacted reference or a hash, never the raw credential -- in findings, evidence, or your report. Keep evidence bounded: file:line refs, hashes, redacted samples, not full response bodies.

Severity = demonstrated outcome, never bug-class. A `candidate` from a scanner is not a severity; only a confirmed, reachable, attacker-simulated finding gets a real severity driven by what the exploit actually achieves.
