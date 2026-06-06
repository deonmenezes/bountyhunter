# Security Policy

Mantishack is a security research tool. It scans for vulnerabilities in _other_ software.
It also has its own attack surface — the scan server, the engine, the disclosure helper —
and this policy covers that.

---

## Supported versions

This project is in beta. The `main` branch is the only supported line.
There are no stable release tags with independent security support.

---

## Reporting a vulnerability in Mantishack itself

**Primary channel:** GitHub Private Vulnerability Reporting — go to the
[Security tab](https://github.com/deonmenezes/mantishack/security) and click
**"Report a vulnerability"**. This keeps the report private until coordinated disclosure
is ready.

> **Maintainer note:** If the button above is missing, enable Private Vulnerability
> Reporting under *Settings → Code security → Private vulnerability reporting*.

**If PVR is disabled:** Open a minimal public issue with the title
"Security: request for private contact" and no technical detail. The maintainer will
follow up with a private channel.

Please do not post technical vulnerability details in public issues or pull requests.

---

## Scope

**In scope — vulnerabilities in the Mantishack framework itself:**

- `mantishack.py` and the Python execution layer (`packages/`, `core/`, `engine/`)
- The local scan server (`server.py`)
- The auth + logging audit rules and pytest fixtures
- The CI and release workflows (`.github/workflows/`)
- The coordinated-disclosure email helper (`/mantis-fullsend` and related code)
- Dependency issues in `requirements.txt` / `requirements-dev.txt` that affect
  Mantishack's own security posture (e.g. a transitive dependency with an RCE)

**Out of scope — not bugs in Mantishack:**

- Vulnerabilities that Mantishack *finds* in scan targets. Those belong to the
  respective upstream projects — report them there.
- False positives or false negatives in scan results.
- Intentional dangerous capabilities (exploit generation, PoC code, fuzzing) that
  are expected behaviour of a security research tool.
- Vulnerabilities in CodeQL, Semgrep, or other third-party tools that Mantishack
  invokes as subprocesses.

---

## What to include in a report

- Affected component and version/commit
- Steps to reproduce
- Impact: what can an attacker do, and from what position?
- Whether you have a proof-of-concept (a draft patch is very welcome but not required)

---

## Coordinated disclosure

Please give the maintainer reasonable time to confirm and fix the issue before
publishing details. Two weeks is the minimum; four weeks is preferred. If the timeline
needs to change for any reason, say so in the report and we will figure it out together.

Mantishack ships `/mantis-fullsend`, a coordinated-disclosure helper that generates
structured disclosure drafts. We practice what we preach — the same responsible
timeline applies here.

---

## Authorised use reminder

Mantishack is intended for authorised security testing only. Using it against systems
you do not own or have explicit permission to test is not covered by this policy and
may be illegal. Vulnerabilities arising from out-of-scope use are not in scope here.
