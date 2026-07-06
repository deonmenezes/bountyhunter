---
name: codeql-audit
description: Build a CodeQL database and run dataflow-backed query-suite analysis via the mantis_codeql MCP server
---

Use `codeql_create_database` then `codeql_analyze` (mantis_codeql MCP server) when you need dataflow-aware SAST beyond what regex/pattern tools (semgrep, ast-grep) can prove -- CodeQL's query suites trace actual source-to-sink data flow through the codebase.

Workflow:
1. `codeql_create_database({ source_root, language, database_path })` once per target/language. This is slow (can take minutes on large repos); don't repeat it unless the source changed.
2. `codeql_analyze({ database_path, query_suite })`. Default `query_suite` is `"security-extended"`; use `"security-and-quality"` only if the user wants broader quality findings too.
3. Treat every SARIF result as a `candidate` with a dataflow-backed path, which is stronger recall evidence than a plain grep match -- but it is still not a confirmed finding. CodeQL's own dataflow models can miss framework-specific sanitization; verify the path manually before validating.
4. If `codeql` reports `available: false`, fall back to `semgrep_scan` and `program-analysis`'s `source_sink_scan`/`ast_grep_scan` for recall, and tell the user CodeQL-grade dataflow coverage wasn't available for this run.
