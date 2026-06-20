# Mantishack

An autonomous security research framework (fork of [RAPTOR](https://github.com/gadievron/raptor)) that chains together static analysis, binary analysis, LLM-powered vulnerability validation, exploit generation, and patch writing into a single agentic workflow. Run against a codebase or binary to discover and validate vulnerabilities end-to-end.

## Tech Stack

- **Language:** Python 3 (core framework)
- **Static analysis engines:** Semgrep, CodeQL, Coccinelle
- **LLM integration:** Anthropic Claude Code (required), plus optional OpenAI-compatible providers
- **Key libraries:** `requests`, `pydantic`, `typer`, `urllib3` (pinned; see `requirements.txt`)
- **Test framework:** pytest
- **CLI entry points:** `mantishack.py`, `mantishack_agentic.py`, `mantishack_codeql.py`, `mantishack_fuzzing.py`

## Setup

```bash
# Clone and install
git clone https://github.com/deonmenezes/mantishack.git
cd mantishack

pip install -r requirements.txt

# Install Claude Code (required)
npm install -g @anthropic-ai/claude-code
```

Dev dependencies (pytest, linting):
```bash
pip install -r requirements-dev.txt
```

## Build / Run / Test

```bash
# Run the main agentic workflow
python mantishack.py <target>

# Agentic (full autonomous) mode
python mantishack_agentic.py <target>

# CodeQL-specific scan
python mantishack_codeql.py <target>

# Fuzzing workflow
python mantishack_fuzzing.py <target>

# Run tests
pytest
```

Scripts in `bin/` and `libexec/` require one of `CLAUDECODE`, `_MANTISHACK_TRUSTED`, or `MANTISHACK_DIR` to be set in the environment (trust-marker check). The test suite sets these automatically via `conftest.py`.

## Project Structure

```
mantishack.py             Main CLI entry point
mantishack_agentic.py     Full autonomous agentic workflow
mantishack_codeql.py      CodeQL-focused scan workflow
mantishack_fuzzing.py     Fuzzing workflow
core/                     Core framework modules
  annotations/            Result annotation system
  ast/                    AST analysis utilities
  binary/                 Binary analysis
  llm/                    LLM integration (Anthropic + OpenAI-compatible)
  orchestration/          Agent orchestration and pipeline
  reporting/              Output formatting / SARIF
  security/               Security-specific utilities
  (many more sub-modules)
engine/
  semgrep/                Semgrep rule integration
  codeql/                 CodeQL query integration
  coccinelle/             Coccinelle semantic patch integration
plugins/
  coverage/               Coverage analysis plugin
bin/                      Executable scripts
libexec/                  Internal helper scripts (trust-gated)
tiers/                    Tier definitions for scan depth
packages/                 Packaged rule sets
test/                     pytest test suite
requirements.txt          Pinned runtime dependencies
requirements-dev.txt      Pinned dev/test dependencies
CLAUDE.md                 Claude Code project instructions
```

## Architecture & Key Files

- The framework is pipeline-based: static analysis (Semgrep/CodeQL/Coccinelle) → LLM validation → exploit generation → patch writing → reporting.
- `core/orchestration/` controls the multi-stage pipeline and agent coordination.
- `core/llm/` abstracts LLM calls; supports both Anthropic (Claude) and OpenAI-compatible providers.
- `core/reporting/` outputs findings in SARIF format and human-readable reports.
- Trust-marker system: `libexec/` scripts refuse to run without `CLAUDECODE`, `_MANTISHACK_TRUSTED`, or `MANTISHACK_DIR` set — prevents accidental execution outside the framework.
- Upstream: [github.com/gadievron/raptor](https://github.com/gadievron/raptor). This fork adds `/mantis-*` slash-command vocabulary and auth/logging audit lane.

## Conventions & Notes for Agents

- **Dependency pins are intentional** (`requirements.txt` uses exact versions). Upgrade via dedicated PRs only — do not loosen pins.
- `libexec/` scripts are trust-gated; tests set the trust marker via `conftest.py`. If adding a new `libexec/` script, follow the existing trust-marker pattern.
- Do not modify `LICENSE` or `NOTICE` — dual copyright (upstream RAPTOR MIT + fork MIT) must be preserved.
- The `CLAUDE.md` in this repo contains additional Claude Code-specific instructions — read it before making agentic changes.
- Claude Code is a **required** runtime dependency, not optional.
- Upstream PRs for framework improvements should go to [gadievron/raptor](https://github.com/gadievron/raptor/issues), not this fork.
