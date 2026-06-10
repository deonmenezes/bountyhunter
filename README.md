<div align="center">

<img src="docs/assets/mascot/hero.png" alt="Mantishack — offensive-security mascot" width="640" />

# Mantishack

`stalk · wait · strike · hold`
**Ethically hack and discover vulnerabilities in any software with the power of AI.**

[mantishack.com](https://mantishack.com) ·
Upstream: [github.com/gadievron/raptor](https://github.com/gadievron/raptor)

</div>

---

## What is Mantishack?

Mantishack is an autonomous security research framework built on top of Claude Code (but not tied to it — you can plug in your own analysis layer too). It chains together static analysis, binary analysis, LLM-powered vulnerability validation, exploit generation, and patch writing into a single workflow you can run against a codebase or binary.

It is not polished software. The upstream is held together with enthusiasm and duct tape, and it works well enough that the upstream maintainers can't stop using it. This fork is the same — usable in the field, rough in the corners. Open issues upstream at [gadievron/raptor](https://github.com/gadievron/raptor/issues).

---

## Quick start

### Option 1: Install manually

```bash
# Clone the repo
git clone https://github.com/deonmenezes/mantishack.git
cd mantishack

# Install Python dependencies
pip install -r requirements.txt

# Install Claude Code (required)
npm install -g @anthropic-ai/claude-code

# Install Semgrep (required for scanning)
pip install semgrep

# Open Mantishack
claude
```

### Option 2: Devcontainer (recommended)

Everything pre-installed. Open in VS Code with **Dev Containers: Open Folder in Container**, or build manually:

```bash
docker build -f .devcontainer/Dockerfile -t mantishack:latest .
docker run --privileged -it mantishack:latest
```

The `--privileged` flag is required for the `rr` deterministic debugger. The image is large (around 6 GB). It starts from the Microsoft Python 3.12 devcontainer and adds static analysis, fuzzing, and browser automation tooling.

Once inside, just say "hi" to get started, or jump straight to a command.

### Check your setup

Not sure what's installed? Run the built-in diagnostic. It needs no LLM and reports which external tools (Semgrep, CodeQL, AFL++, …) are present and which features degrade without them:

```bash
python3 mantishack.py doctor
```

If `/mantis-scan` or `/mantis-agentic` says it is unavailable, this is the first thing to run — it tells you exactly what is missing.

---

## What Mantishack can do

| Command | What it does | Status |
|---------|--------------|--------|
| `/mantis-agentic` | Full autonomous workflow: scan, **auth+logging audit**, validate, exploit, patch | Stable |
| `/mantis-scan` | Static analysis with Semgrep and CodeQL | Stable |
| `/mantis-auth-audit` | **Automatic JWT + cookie + audit-log security check** | Stable (fork addition) |
| `/mantis-understand` | Map attack surface, trace data flows, hunt vulnerability variants | Stable |
| `/mantis-validate` | Multi-stage exploitability validation pipeline (Stages 0–F) | Stable |
| `/mantis-codeql` | CodeQL-only deep analysis with SMT dataflow pre-screening | Stable |
| `/mantis-exploit` | Generate proof-of-concept exploit code | Beta |
| `/mantis-patch` | Generate secure patches for confirmed vulnerabilities | Beta |
| `/mantis-fuzz` | Binary fuzzing with AFL++ and crash analysis | Stable |
| `/mantis-crash-analysis` | Autonomous root-cause analysis for C/C++ crashes | Stable |
| `/mantis-oss-forensics` | Evidence-backed forensic investigation for GitHub repositories | Stable |
| `/mantis-project` | Named workspaces to organise runs and track findings over time | Stable |
| `/mantis-sca` | Software composition analysis | Stable |
| `/mantis-cve-diff` | Compare scanner runs across known CVE fixes | Stable |
| `/mantis-web` | Web application scanning | Alpha/stub |

---

## How the pipeline works

Start by creating a project so all your runs land in one place:

```
/mantis-project create myapp --target /path/to/code   # create a project first
/mantis-project use myapp                             # set it as active
/mantis-understand --map                              # map the attack surface
/mantis-agentic                                       # scan, audit, validate, exploit, patch
/mantis-project findings                              # review everything in one place
```

`/mantis-understand` builds a context map of entry points, trust boundaries, and sinks before a line of scanning happens. `/mantis-agentic` then runs Semgrep and CodeQL, **executes the auth + logging audit lane automatically**, deduplicates findings, and dispatches each one for validation using the exploitation-validator methodology:

- Stage A: is the pattern actually a vulnerability, or is the tool pattern-matching noise?
- Stage B: what does an attacker need to reach it, and what gets in the way?
- Stage C: does the code path actually exist? can it be reached from outside?
- Stage D: final call — is this test code, does it need unrealistic preconditions, is the model hedging?

Findings that clear validation get exploit PoCs and patches generated. A cross-finding analysis runs at the end to find shared root causes and attack chains.

`/mantis-validate` runs this same pipeline as a standalone step if you already have findings from a previous scan.

---

## Authentication + logging audit (fork addition)

Mantishack automatically runs an **auth + logging audit** on every `/mantis-agentic` invocation. The same checks are also exposed as a standalone `/mantis-auth-audit` slash command for faster, more-targeted runs.

The lane uses Semgrep rules tagged `mantis_capability: auth-audit` plus pytest fixtures that assert audit-log coverage at runtime. What it looks for:

**JWT** — `engine/semgrep/rules/auth/jwt-misuse.yaml`
- `alg=none` accepted (token forgery)
- Hardcoded HMAC secret (brute-force key recovery)
- Missing `exp` claim (token never expires)
- No audience / issuer pinning (cross-tenant token acceptance)

**Cookies** — `engine/semgrep/rules/auth/cookie-security.yaml`
- Missing `HttpOnly` (XSS-exfiltrable)
- Missing `Secure` (plaintext-HTTP exposure)
- Missing `SameSite` (CSRF)
- Session id passed in URL query parameter (referer / log leak)

**Logging** — `engine/semgrep/rules/logging/missing-auth-audit.yaml`
- Auth-failure branch with no log line
- Privileged action (delete / role-change / `is_admin = True`) with no audit log
- Raw JWT / bearer / `session_id` written to logs (credential leak)

**Pytest harness** — `conftest.py`
- `@pytest.mark.auth_audit` marker + `assert_audit_log_emitted` fixture: tests that exercise auth-sensitive code paths fail the run if (a) no INFO/WARN log was emitted, or (b) any log record contains a raw JWT / session id / bearer token.

Usage example for the pytest hook:

```python
import pytest

@pytest.mark.auth_audit
def test_login_logs_failure(client, assert_audit_log_emitted):
    client.post("/login", data={"u": "alice", "p": "wrong"})
    # fixture teardown asserts an audit log was emitted and no credential leaked
```

Run the standalone audit:

```bash
python3 mantishack.py scan --repo /path/to/code --policy-groups auth,logging
```

---

## Z3 SMT integration

Mantishack inherits RAPTOR's two-layer Z3 integration (`pip install z3-solver`). It is optional. Everything works without it, but the results are better with it.

**Dataflow pre-screening (CodeQL)** — When CodeQL produces a path result, the path constraints are checked for satisfiability before any LLM call is made. Paths that are provably unreachable get dropped immediately. For paths that are reachable, Z3 produces concrete candidate inputs that go into the analysis prompt.

**One-gadget constraint analysis (binary feasibility)** — During binary exploit feasibility assessment, Z3 checks whether a one-gadget's register and memory constraints are satisfiable against the concrete crash state. Gadgets are ranked by actual reachability rather than heuristics.

Z3 is pre-installed in the devcontainer. For manual installs: `pip install z3-solver`.

---

## Running offline and in air-gapped pipelines

Semgrep scanning works fully offline. All registry packs that would normally be fetched from semgrep.dev at scan time are shipped in the repo under `engine/semgrep/rules/registry-cache/`. The scanner resolves pack IDs to local files before invoking semgrep, so no network call happens.

Cached packs: `p/security-audit`, `p/owasp-top-ten`, `p/secrets`, `p/command-injection`, `p/jwt`, `p/default`, `p/xss`.

CodeQL needs network access only during initial setup to download the CLI and query packs. Once installed it runs offline.

---

## Using a different LLM

Mantishack has two separate model layers, inherited from RAPTOR:

The **orchestration layer** is always Claude Code. The CLAUDE.md, skills, and commands all run as Claude Code instructions. To change which Claude model orchestrates Mantishack, use Claude Code's `--model` flag or the `/model` command inside a session.

The **analysis dispatch layer** is the LLM that analyses individual vulnerability findings. This is separate from the orchestration layer and can be any supported provider. Configure it in `~/.config/mantishack/models.json`:

```json
{
  "models": [
    {
      "provider": "anthropic",
      "model": "claude-opus-4-6",
      "api_key": "sk-ant-...",
      "role": "analysis"
    },
    {
      "provider": "openai",
      "model": "gpt-5.4",
      "api_key": "sk-...",
      "role": "analysis"
    },
    {
      "provider": "anthropic",
      "model": "claude-sonnet-4-6",
      "api_key": "sk-ant-...",
      "role": "aggregate"
    }
  ]
}
```

Or skip the config file and set environment variables:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
export OPENAI_API_KEY=sk-...
export GEMINI_API_KEY=...
export MISTRAL_API_KEY=...
export OLLAMA_HOST=http://localhost:11434
```

Budget control:

```bash
export MANTISHACK_MAX_COST=5.00   # cap analysis spend at $5 per run
```

---

## Architecture

Mantishack is two layers.

The **Python execution layer** (`mantishack.py`, `packages/`, `core/`, `engine/`) handles the heavy lifting: running Semgrep and CodeQL, managing subprocesses, parsing SARIF, deduplicating findings, dispatching LLM API calls, tracking costs, writing output files. It does not make decisions. It executes.

The **Claude Code decision layer** (`.claude/`, `tiers/`, `CLAUDE.md`) makes the calls: which findings to prioritise, how to interpret results, what the attack scenario is, whether the exploit is realistic. Implemented as Claude Code skills, commands, and agents that load progressively.

```
CLAUDE.md              always loaded — bootstrap, routing, security rules
.claude/commands/      slash commands (/mantis-agentic, /mantis-scan, …)
.claude/skills/        methodology detail, loaded on demand
tiers/                 adversarial thinking, recovery, expert personas
.claude/agents/        specialist sub-agents (offsec, crash analysis, forensics)
```

The split means you can run the Python layer from a CI pipeline (`python3 mantishack.py scan --repo ...`) and get structured SARIF output without Claude Code, or run it interactively with the full agentic workflow.

---

## Built on top of RAPTOR

**Mantishack is a fork of [RAPTOR](https://github.com/gadievron/raptor)** — the Recursive Autonomous Penetration Testing and Observation Robot by Gadi Evron, Daniel Cuthbert, Thomas Dullien (Halvar Flake), Michael Bargury, and John Cartwright. The agentic workflow, the Semgrep + CodeQL pipeline, the multi-stage validation methodology, the persona library, and the offline registry packs all come from RAPTOR. Mantishack carries that work forward, rebrands the user-facing surface to the `/mantis-*` slash-command vocabulary, adds an automatic auth + logging audit lane (JWT, cookies, audit-log coverage), and ships under MIT with two coexisting copyrights.

> **Upstream licence:** MIT © 2025-2026 Gadi Evron, Daniel Cuthbert, Thomas Dullien (Halvar Flake), Michael Bargury, John Cartwright — see [`LICENSE`](./LICENSE).
> **Fork-modification licence:** MIT © 2026 Deon Menezes — see [`LICENSE-MANTISHACK`](./LICENSE-MANTISHACK).
> Combined attribution and modification log in [`NOTICE`](./NOTICE).

If you came here looking for the canonical project, please visit [github.com/gadievron/raptor](https://github.com/gadievron/raptor) — that is where upstream development happens. If you want to make the framework better, open a PR upstream.

---

## Licence

MIT, dual-copyright:

- **Upstream RAPTOR code** — Copyright (c) 2025-2026 Gadi Evron, Daniel Cuthbert, Thomas Dullien (Halvar Flake), Michael Bargury, John Cartwright. See [`LICENSE`](./LICENSE).
- **Fork modifications** (mantishack branding, `/mantis-*` rename, auth + logging audit rules, pytest fixtures, README/NOTICE) — Copyright (c) 2026 Deon Menezes. See [`LICENSE-MANTISHACK`](./LICENSE-MANTISHACK).

Both files are MIT; the fork-modification licence sits alongside the upstream RAPTOR licence and does not supersede it. See [`NOTICE`](./NOTICE) for combined attribution and the fork-modification log. Review the licences for all dependencies before commercial use — **CodeQL in particular does not permit commercial use**.

**Upstream:** https://github.com/gadievron/raptor — please file framework-level issues and PRs upstream.

**Mantishack fork issues:** https://github.com/deonmenezes/mantishack/issues

---

## Project history

Earlier mantishack versions ran as an independent Rust daemon + MCP agent stack and **drew from many open-source projects**. That architecture has been retired and removed from this repository; the codebase you see here is a full rebrand of [RAPTOR](https://github.com/gadievron/raptor) (MIT). The acknowledgements below are historical — none of these projects ship as code in this tree today (RAPTOR has its own dependency set listed in [`requirements.txt`](./requirements.txt)) — but they shaped what mantishack used to be and we credit them here in good faith.

**Primary derivation:**
- [vmihalis/hacker-bob](https://github.com/vmihalis/hacker-bob) (Apache-2.0) — agent prompts, role prompts, slash commands, capability playbook conventions, chain-attempt outcome enum, severity-ladder rules, and `bob-hunt` workflow shape were derived from Hacker Bob.

**AI models and LLM ecosystem:**
- [Nous Research — Hermes](https://huggingface.co/NousResearch) (Hermes 2/3 family, various licences)
- [Anthropic Claude](https://www.anthropic.com/) (host LLM via API + Claude Code)
- [OpenAI Codex CLI](https://github.com/openai/codex) (Apache-2.0)
- [OpenCode](https://opencode.ai/)
- [Model Context Protocol (MCP)](https://github.com/modelcontextprotocol) spec + [rmcp](https://github.com/modelcontextprotocol/rust-sdk) Rust SDK (MIT)

**Operating systems & runtimes:**
- [Linux kernel](https://kernel.org/) (GPL-2.0)
- [GNU userland / glibc / musl](https://www.gnu.org/)
- [Rust toolchain](https://www.rust-lang.org/) (Apache-2.0 / MIT)
- [Node.js](https://nodejs.org/), [Bun](https://bun.sh/), [Deno](https://deno.com/) (MIT)
- [Docker](https://www.docker.com/) / [OCI](https://opencontainers.org/) (Apache-2.0)
- [Homebrew](https://brew.sh/) (BSD-2-Clause)

**Cryptography & integrity:**
- [BLAKE3](https://github.com/BLAKE3-team/BLAKE3), [ed25519-dalek](https://github.com/dalek-cryptography/ed25519-dalek), [ring](https://github.com/briansmith/ring), [rustls](https://github.com/rustls/rustls), [zeroize](https://github.com/RustCrypto/utils/tree/master/zeroize)

**Rust async ecosystem & core libraries:**
- [Tokio](https://tokio.rs/), [Tower](https://github.com/tower-rs/tower), [Hyper](https://hyper.rs/), [reqwest](https://github.com/seanmonstar/reqwest), [Serde](https://serde.rs/) + [serde_json](https://github.com/serde-rs/json) / [serde_yaml_ng](https://github.com/acatton/serde-yaml-ng) / [toml](https://github.com/toml-rs/toml), [Tonic](https://github.com/hyperium/tonic) + [Prost](https://github.com/tokio-rs/prost), [anyhow](https://github.com/dtolnay/anyhow), [thiserror](https://github.com/dtolnay/thiserror), [tracing](https://github.com/tokio-rs/tracing), [clap](https://github.com/clap-rs/clap), [schemars](https://github.com/GREsau/schemars)

**Storage:**
- [RocksDB](https://rocksdb.org/) + [rust-rocksdb](https://github.com/rust-rocksdb/rust-rocksdb)
- [Supabase](https://supabase.com/) (landing page auth + Postgres)

**Offensive-security tooling invoked / integrated:**
- ProjectDiscovery: [subfinder](https://github.com/projectdiscovery/subfinder), [httpx](https://github.com/projectdiscovery/httpx), [katana](https://github.com/projectdiscovery/katana), [nuclei](https://github.com/projectdiscovery/nuclei) + [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates), [chaos](https://github.com/projectdiscovery/chaos-client), [dnsx](https://github.com/projectdiscovery/dnsx), [interactsh](https://github.com/projectdiscovery/interactsh), [notify](https://github.com/projectdiscovery/notify)
- [OWASP Amass](https://github.com/owasp-amass/amass) (Apache-2.0)
- [ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool) (GPL-3.0, subprocess-only)
- [OJ/gobuster](https://github.com/OJ/gobuster) (Apache-2.0)
- [Patchright](https://github.com/Kaliiiiiiiiii-Vinyzu/patchright) (headless browser automation)
- [Bearer](https://github.com/Bearer/bearer) (Elastic-2.0)
- [Trivy](https://github.com/aquasecurity/trivy) (Apache-2.0)
- [trufflehog](https://github.com/trufflesecurity/trufflehog) (AGPL-3.0)
- [hashcat](https://hashcat.net/) (MIT)
- [Hydra](https://github.com/vanhauser-thc/thc-hydra) (AGPL-3.0)

**Standards, taxonomies, reporting formats:**
- [CVSS v3.1 / v4](https://www.first.org/cvss/) (FIRST.org)
- [CWE](https://cwe.mitre.org/) (MITRE)
- [SARIF v2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/) (OASIS)
- [OpenVEX](https://github.com/openvex/spec)
- [HackerOne report schema](https://api.hackerone.com/)
- [Bugcrowd VRT](https://bugcrowd.com/vulnerability-rating-taxonomy)
- [OWASP Top 10](https://owasp.org/Top10/)

**Web stack (legacy landing page + dashboard):**
- [Vite](https://vitejs.dev/), [React](https://react.dev/), [TypeScript](https://www.typescriptlang.org/), [Tailwind CSS](https://tailwindcss.com/), [shadcn/ui](https://ui.shadcn.com/), [Radix UI](https://www.radix-ui.com/), [lucide-react](https://lucide.dev/), [Supabase JS SDK](https://github.com/supabase/supabase-js)

**Distribution & CI:**
- [GitHub Actions](https://github.com/features/actions), [GitHub CLI](https://github.com/cli/cli), [cargo-chef](https://github.com/LukeMathWalker/cargo-chef), [cargo-deny](https://github.com/EmbarkStudios/cargo-deny), [rustup](https://rustup.rs/)

If we drew from a project that isn't credited here, please open an issue — we want this list to reflect reality.
