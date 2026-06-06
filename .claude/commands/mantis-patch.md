---
description: Generate secure patches for vulnerabilities (beta)
---

# /mantis-patch - Generate Secure Patches (beta)

Generate secure patches to fix vulnerabilities.

**Requires:** SARIF file from previous /mantis-scan

**What it does:**
- Analyzes findings with LLM
- Generates secure patch code
- Saves to out/*/patches/
- Does NOT generate exploits (use /mantis-exploit for that)

**Run:** `python3 mantishack.py agentic --repo <path> --no-exploits --max-findings <N>`

**Example:**
```bash
/mantis-scan test/                    # First, find vulnerabilities
/mantis-patch                         # Then, generate fixes for findings
```

**Note:** Review patches before applying to production code.

---
