<div align="center">

<img src="docs/assets/mascot/hero.png" alt="Mantishack - offensive-security mascot" width="640" />

# Mantishack

`stalk - wait - strike - hold`
**Ethically hack and discover vulnerabilities in any software with the power of AI.**

[mantishack.com](https://mantishack.com)

</div>

---

## What is Mantishack?

Mantishack is Mantis AI: an autonomous vulnerability-discovery agent built on top of [OpenAI's Codex CLI](https://github.com/openai/codex) (Rust, Apache-2.0), rebranded and wired end-to-end as an offensive-AppSec harness. It runs a staged detect-then-validate pipeline over a codebase - recon, detect, reachability, attacker-simulation validation, chaining, gated exploitation, fixing, and reporting - with every finding owned by a tool, not tracked in prose.

The core bet is the same one this project has always made: **detection is commodity, validation precision is the product.** What survives attacker-simulation is real; everything else gets rejected with a cited roadblock.

It is not polished software. It is a working harness with real gaps (see "Project history" and `MANTIS.md` for what's wired vs. what still needs external binaries or a running target), usable in the field, rough in the corners.

---

## Quick start

### Build from source

```bash
# Clone the repo
git clone https://github.com/deonmenezes/mantishack.git
cd mantishack

# Build the CLI (Rust toolchain required, see codex-rs/rust-toolchain.toml)
cd codex-rs
cargo build --release -p codex-cli

# Run it from the repo root so the project-scoped .codex/config.toml resolves
cd ..
./codex-rs/target/release/codex
```

### Install the capability-catalog binaries

The MCP tool servers under `.codex/mcp-servers/` are pure Node.js and need no install of their own, but the scanners they wrap degrade to `available: false` until you install the underlying binaries:

```bash
pip install semgrep bandit
brew install trufflehog trivy z3 ast-grep    # or your platform's equivalent
go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest
# CodeQL CLI: https://github.com/github/codeql-cli-binaries
```

Nothing is fabricated when a binary is missing - each server reports plainly that the tool isn't installed rather than inventing findings.

---

## What's wired

| Layer                          | Where                                                                         | What it does                                                                                                                                                                                                                                                                       |
| ------------------------------ | ----------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Capability servers (MCP)**   | `.codex/mcp-servers/`                                                         | `semgrep_scan`, `codeql_create_database`/`codeql_analyze`, `osv_scan`, `trufflehog_scan`, `bandit_scan`, `trivy_scan` - SAST/SCA/secrets, all report-until-installed.                                                                                                              |
| **Program-analysis substrate** | `.codex/mcp-servers/program-analysis/`                                        | `source_sink_scan` (heuristic, works now), `ast_grep_scan` (structural search), `smt_check_reachability` (z3-backed path-condition satisfiability).                                                                                                                                |
| **Findings spine**             | `.codex/mcp-servers/findings/`                                                | Tool-owned finding state: `finding_create/update/get/list`. Enforces "no proof -> no confirm" and "reject cites a roadblock" in code, not prose. Works now, zero deps.                                                                                                             |
| **Evidence**                   | `.codex/mcp-servers/http-audit/`                                              | Turns a captured HTTP exchange into a bounded, redacted evidence pack with a stable request-ref hash. Works now, zero deps.                                                                                                                                                        |
| **Injection defense**          | `.codex/mcp-servers/canary/`                                                  | Decoy tools that alert if called - a tripwire for prompt injection or hallucinated tool use. Works now, zero deps.                                                                                                                                                                 |
| **Agent catalog**              | `.codex/agents/*.toml`                                                        | The full pipeline as `spawn_agent` roles: `recon`, `context-enrich`, `detector`, `reachability`, `validator`, `verifier-balanced`/`brutalist`/`final`, `chain-builder`, `exploiter` (gated), `fixer`, `reporter`, `orchestrator`.                                                  |
| **Knowledge**                  | `.codex/skills/*/SKILL.md`                                                    | Playbooks tying each tool/agent into the findings lifecycle: `mantis-pipeline` (master playbook), `semgrep-triage`, `codeql-audit`, `osv-dependency-scan`, `secrets-scan`, `detection-breadth`, `program-analysis`, `findings-spine`, `http-evidence`, `canary-tripwire-response`. |
| **Identity**                   | `codex-rs/core/*_prompt.md`, `codex-rs/protocol/`, `codex-rs/models-manager/` | The agent's system prompts, rebranded to Mantis AI's authorized-vulnerability-discovery mission and safety contract.                                                                                                                                                               |
| **TUI**                        | `codex-rs/tui/`                                                               | Mantis mascot ASCII boot animation (with a blink) and a green accent theme.                                                                                                                                                                                                        |

See `MANTIS.md` for the full map, the "how to extend" recipes, and the prioritized roadmap of what's next (recon/DAST toolchain, injection confirmers, OOB, fuzzing, CVE intel - each a report-until-installed MCP server on the existing pattern).

---

## How the pipeline works

Findings move through one lifecycle, owned by the findings service, never hand-edited in prose:

```
candidate -> confirmed | rejected -> exploited -> fixed -> verified
```

- **Detect is generous.** SAST/SCA/secrets scanners plus LLM reasoning surface `candidate`s at high recall. Do not self-censor false positives here - that's Validate's job.
- **Validate is ruthless.** Attacker-simulation reasons as an attacker with attacker-only capabilities: is the pattern real or noise, what does an attacker need to reach it, does the path actually exist, can it be reached from outside. A candidate only becomes `confirmed` with reachability evidence attached - the findings service refuses the transition otherwise. A `rejected` candidate must cite the specific roadblock (auth gate, sanitizer at the sink, provably-unreachable path, self-only harm) - "seems safe" isn't accepted.
- **Chain, exploit, fix, verify** follow only for confirmed findings, with exploitation double-gated and off by default.

Establish scope and authorization first. Work only on targets you own or are explicitly authorized to test. If authorization for active/exploit testing is unclear, restrict the run to read-only static analysis until scope is established.

---

## Z3 SMT integration

The program-analysis MCP server wraps z3 for reachability (`smt_check_reachability`): construct the path condition for a candidate source-to-sink flow as an SMT-LIB2 script, hand it to the tool, and get back `sat` (an attacker-controlled assignment reaches the sink - proceed to Validate), `unsat` (provably unreachable - reject, citing the unsat result as the roadblock), or `unknown` (proves nothing either way). It degrades to `available: false` if `z3` isn't installed, same as every other scanner server.

---

## Using a different model

Mantis AI inherits Codex CLI's provider-agnostic model routing - configure providers, API keys, and per-model settings the same way you would for upstream Codex CLI (see `codex-rs/config.md` and `codex-rs/model-provider/`). There's no separate "orchestration vs. analysis" split: one model runs the harness loop, calling the MCP tools and (when multi-agent mode is enabled) spawning the role agents in `.codex/agents/`.

---

## Architecture

The invariant that governs everything (also documented in `MANTIS.md`):

- **Tool = code** - an MCP server handler that _does_ something. Wired in `.codex/config.toml [mcp_servers.*]`, implemented under `.codex/mcp-servers/<name>/server.js`.
- **Agent = prompt** - a system prompt + model tier + tool/permission policy. A TOML role file under `.codex/agents/<name>.toml`, auto-discovered and offered as a `spawn_agent` agent type.
- **Skill = knowledge** - reference text the model reads. `.codex/skills/<name>/SKILL.md`.

The harness (Codex CLI, Rust - `codex-rs/`) runs the loop; it does zero security by itself. All actual security logic lives in the capability layer, the agent prompts, and the skills.

```
codex-rs/                the Codex CLI harness (sessions, sandboxing, TUI, MCP client)
.codex/config.toml        project-scoped MCP server registration
.codex/mcp-servers/       capability layer (the tools)
.codex/agents/            role catalog (the agents)
.codex/skills/            playbooks (the knowledge)
.codex/MANTIS.md          map of what's wired + how to extend it
```

---

## Licence

Apache-2.0, dual-copyright:

- **Upstream framework code** (OpenAI Codex CLI) - see [`LICENSE`](./LICENSE) for the full copyright notice.
- **Mantishack/Mantis AI modifications** (identity rebrand, capability layer, agent/skill catalog, TUI mascot + theme, README/NOTICE) - Copyright (c) 2026 Deon Menezes. See [`LICENSE-MANTISHACK`](./LICENSE-MANTISHACK).

Both files' terms sit alongside each other; neither supersedes the other. See [`NOTICE`](./NOTICE) for combined attribution. Review the licences for all invoked components before commercial use - **CodeQL in particular does not permit commercial use**.

**Mantishack issues:** https://github.com/deonmenezes/mantishack/issues

---

## Project history

Earlier mantishack versions ran as an independent Rust daemon + MCP agent stack and drew from many open-source projects; that architecture was retired. The codebase that followed was a full rebrand of an upstream MIT framework, [RAPTOR](https://github.com/gadievron/raptor) by Gadi Evron, Daniel Cuthbert, Thomas Dullien (Halvar Flake), Michael Bargury, and John Cartwright - built on Claude Code, adding an auth + logging audit lane, `/mantis-*` slash commands, and the mascot/branding you still see above.

That RAPTOR-derived codebase has now also been retired and replaced with the architecture described in this README: OpenAI's Codex CLI (Rust, Apache-2.0) as the harness, rebranded to Mantis AI, with the capability/agent/skill layers described above under "What's wired". None of RAPTOR's code ships in this tree today - see [`LICENSE`](./LICENSE), [`LICENSE-MANTISHACK`](./LICENSE-MANTISHACK), and [`NOTICE`](./NOTICE) for the current licensing, and [`CITATION.cff`](./CITATION.cff) for RAPTOR's original citation, preserved for the historical record. We credit RAPTOR's authors here in good faith for the work that shaped what mantishack used to be.

---

## Acknowledgements

**Current architecture:**

- [OpenAI Codex CLI](https://github.com/openai/codex) (Apache-2.0) - the harness this project is built on and rebranded from.
- [Ratatui](https://github.com/ratatui/ratatui) (MIT) - terminal UI, via Codex CLI.
- [Model Context Protocol (MCP)](https://github.com/modelcontextprotocol) - the tool-server protocol the capability layer speaks.
- [Semgrep](https://semgrep.dev/), [CodeQL](https://codeql.github.com/), [osv-scanner](https://github.com/google/osv-scanner), [trufflehog](https://github.com/trufflesecurity/trufflehog), [bandit](https://bandit.readthedocs.io/), [Trivy](https://github.com/aquasecurity/trivy), [ast-grep](https://ast-grep.github.io/), [Z3](https://github.com/Z3Prover/z3) - the scanners and solvers the capability layer wraps.

**Historical (retired RAPTOR-era stack):** the previous version of this README credited a much longer list of tools and ecosystems (ProjectDiscovery's recon suite, jwt_tool, gobuster, Patchright, Bearer, Trivy, trufflehog, hashcat, Hydra, the Rust async/crypto ecosystem, a Vite/React/Supabase dashboard, and more) that shaped the RAPTOR-derived codebase this repository used to ship. None of that code is present today; the full historical acknowledgement list is preserved in this repository's git history for the record.

If we drew from a project that isn't credited here, please open an issue - we want this list to reflect reality.
