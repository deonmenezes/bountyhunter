# Contributing to Mantishack

Thanks for looking at this. A few things to know before you start.

---

## Upstream first

Mantishack is a fork of [RAPTOR](https://github.com/gadievron/raptor) by Gadi Evron,
Daniel Cuthbert, Thomas Dullien, Michael Bargury, and John Cartwright. The agentic
workflow, Semgrep/CodeQL pipeline, multi-stage validation methodology, and persona
library all live upstream. If your change improves any of that core machinery,
**open the PR upstream at [gadievron/raptor](https://github.com/gadievron/raptor/pulls)
first**. Improvements that land upstream benefit everyone and will be pulled into this
fork on the next sync.

Changes that belong here (not upstream):

- The `/mantis-*` slash-command vocabulary and CLAUDE.md routing
- The auth + logging audit lane (`engine/semgrep/rules/auth/`,
  `engine/semgrep/rules/logging/`, `conftest.py` auth_audit fixtures)
- The local scan server (`server.py`)
- Mantishack-specific CI, packaging, and the mascot

If you're not sure which repo a change belongs to, open an issue here first and ask.

---

## Dev setup

```bash
git clone https://github.com/deonmenezes/mantishack.git
cd mantishack
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

Check that your local tooling is healthy:

```bash
mantishack doctor
```

This verifies Semgrep, CodeQL CLI, and optional dependencies (rr, z3-solver, etc.)
and tells you what's missing without requiring them all to be present.

Run tests:

```bash
pytest
```

`pytest.ini` sets `importmode = importlib` — you don't need to install the package to
run the suite, and conftest fixtures load automatically.

Lint:

```bash
ruff check .
ruff format --check .
```

The CI runs both. Fix lint before pushing.

---

## Testing expectations

- Add tests for new behaviour. Security-sensitive changes (auth audit rules, the scan
  server, the disclosure helper) need tests — the risk profile is higher and the
  surface is smaller, so there is no excuse not to test it.
- Don't break existing tests. If you need to change a test, explain why in the PR.
- The `@pytest.mark.auth_audit` marker triggers the `assert_audit_log_emitted`
  fixture — if you're touching auth-related code, mark the relevant tests.

---

## Dependency policy

Dependencies in `requirements.txt` are exact-pinned (`==`) with an inline comment
explaining the CVE or rationale for the pin. Follow this convention:

```
cryptography==42.0.8  # CVE-2024-26130 fixed in 42.0.4; pinned to latest patch
```

Dependency bumps should be their own dedicated PR with a clear reason — don't bundle
them into feature work. Review the new version's changelog for anything security-relevant.

---

## Commit and PR etiquette

- Small, focused PRs. One logical change per PR.
- Describe the security impact in the PR description, even if the answer is "none".
- If your change touches exploit generation, PoC code, or the auth audit lane, say so
  explicitly in the description.
- Run `ruff` and `pytest` before opening the PR. The CI will catch failures, but it's
  faster to fix them locally.

---

## Dangerous operations

CLAUDE.md says it clearly: safe operations (install, scan, read, generate) — do it.
Dangerous operations (apply patches, delete, push) — ask first. The same convention
applies to contributor PRs: if your change does something irreversible or has
significant blast radius, describe the risk and how to roll it back.
