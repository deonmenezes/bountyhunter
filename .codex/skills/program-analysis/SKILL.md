---
name: program-analysis
description: Use ast_grep_scan, source_sink_scan, and smt_check_reachability (mantis_program_analysis MCP server) to move a candidate toward a proven-reachable finding
---

The `mantis_program_analysis` MCP server is the program-analysis substrate (PRD FR-3.1/3.2/3.3): it doesn't find vulnerabilities by itself, it gives you the primitives to prove or disprove reachability for candidates surfaced elsewhere (semgrep, CodeQL, manual reading).

Three tools, three different jobs:

- **`source_sink_scan`**: fast, dependency-free regex proxy for attacker-controlled-input sources (`req.query`, `request.args`, `os.Args`, ...) and dangerous sinks (`eval`, `exec`, `innerHTML`, `pickle.loads`, ...) across JS/TS, Python, Go, and Java. This is a **recall** tool, not proof -- it will surface sources and sinks in the same file or project without knowing if they're actually connected. Use it to cheaply widen your candidate list early in Recon/Detect, then manually trace whether a specific source really flows to a specific sink.
- **`ast_grep_scan`**: precise structural search when you need to find every call site of a specific pattern (e.g. `exec($CMD, $CB)`) with real AST semantics instead of regex guessing. Use this to enumerate all call sites of a sink once you've picked a vulnerability class to chase, or to confirm a source-sink pair you suspect from `source_sink_scan` actually appears in the same statement/scope.
- **`smt_check_reachability`**: once you've traced a concrete path from source to sink and can express the path condition (e.g. "sink fires when `cmd` is attacker-controlled and no allowlist check occurred on that branch") as SMT-LIB2 constraints, hand it to z3. `sat` means an attacker-controlled assignment exists that reaches the sink -- move the candidate to Validate. `unsat` means the path is provably unreachable under those constraints -- reject it and cite the unsat result as the roadblock. `unknown` proves nothing either way; don't treat it as a pass.

None of these three tools replace attacker-simulation validation -- they narrow candidates and prove/disprove reachability so validation time is spent on things that can actually matter.
