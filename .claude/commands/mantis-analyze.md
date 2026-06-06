---
description: Analyze existing SARIF findings with LLM
---

# /mantis-analyze - MANTISHACK LLM Analysis

Analyzes existing SARIF files with LLM (for findings from previous scans).

Execute: `python3 mantishack.py analyze --repo <path> --sarif <sarif-file>`

Use when you already have SARIF findings and want LLM analysis.

## Multi-model support

The same `--model`, `--consensus`, `--judge`, and `--aggregate` flags from `/mantis-agentic`
work here. When any role flag is provided, `/mantis-analyze` preps findings
then dispatches them through the parallel orchestrator:

```
# Analyze with a specific model
python3 mantishack.py analyze --repo /path --sarif findings.sarif --model gemini-2.5-pro

# Add consensus + judge
python3 mantishack.py analyze --repo /path --sarif findings.sarif \
  --model gemini-2.5-pro --consensus claude-opus-4-6 --judge gpt-5.4

# Multi-model analysis + final aggregation
python3 mantishack.py analyze --repo /path --sarif findings.sarif \
  --model claude-opus-4-6 --model gpt-5.4 --aggregate claude-sonnet-4-6
```

Without role flags, `/mantis-analyze` runs the sequential single-model path as before.

---
