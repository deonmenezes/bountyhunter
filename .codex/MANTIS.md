# Mantis harness upgrade map

How the Codex fork is wired into the Mantis AI capability stack, and the best
way to extend it further. Grounded in `Mantis-AI-PRD.md` (v2.0). This is the
canonical map of the `.codex/` layer; keep it in sync when you add capability.

The invariant that governs everything (PRD Appendix D):

- **Tool = code** — an MCP server handler that *does* something. Wired in `.codex/config.toml [mcp_servers.*]`, implemented under `.codex/mcp-servers/<name>/server.js`.
- **Agent = prompt** — a system prompt + model tier + tool/permission policy. A TOML role file under `.codex/agents/<name>.toml`, auto-discovered and offered as a `spawn_agent` `agent_type`.
- **Skill = knowledge** — reference text the model reads. `.codex/skills/<name>/SKILL.md`.

The harness runs the loop; it does **zero** security by itself. Detect is
generous (high recall); Validate is ruthless (kill false positives with cited
roadblocks). "What survives attacker-simulation is real."

---

## What is wired now

### Capability layer — MCP servers (`.codex/config.toml`)

| Server | Tool(s) | PRD stage | Status in this env |
|---|---|---|---|
| `mantis_semgrep` | `semgrep_scan` | Detect / SAST ★ | report-until-`semgrep` installed |
| `mantis_codeql` | `codeql_create_database`, `codeql_analyze` | Detect / dataflow SAST ★ | report-until-`codeql` installed |
| `mantis_osv_scanner` | `osv_scan` | Detect / SCA ★ | report-until-`osv-scanner` installed |
| `mantis_trufflehog` | `trufflehog_scan` | Detect / secrets ★ | report-until-`trufflehog` installed |
| `mantis_bandit` | `bandit_scan` | Detect / Python SAST | report-until-`bandit` installed |
| `mantis_trivy` | `trivy_scan` | Detect / SCA+IaC+secrets | report-until-`trivy` installed |
| `mantis_program_analysis` | `source_sink_scan`, `ast_grep_scan`, `smt_check_reachability` | Substrate / reachability ★ | `ast-grep` present; `z3` report-until-installed |
| `mantis_http_audit` | `http_audit` | Validate/DAST evidence | **works now (pure Node)** |
| `mantis_findings` | `finding_create/update/get/list` | Findings spine ★ | **works now (pure Node)** |
| `mantis_canary` | decoy tripwire tools | Prompt-injection defense ★ | **works now (pure Node)** |

Every scanner server degrades gracefully: if its binary is absent it returns
`available: false` and says so, instead of fabricating findings
(`.codex/mcp-servers/lib/run_tool.js`). Install the binaries to light them up;
no wiring changes needed.

### Agent catalog — role files (`.codex/agents/*.toml`)

The full PRD Appendix B pipeline, each with a system prompt, a model tier
(`model_reasoning_effort`), and a permission posture (`:read-only` for every
analysis role; the `fixer` inherits write; the `exploiter` is kept read-only as
a safety backstop and is off by default):

`recon` · `context-enrich` · `detector` · `reachability` · `validator` ·
`verifier-balanced` · `verifier-brutalist` · `verifier-final` · `chain-builder`
· `exploiter` (gated) · `fixer` · `reporter` · `orchestrator` (lead).

### Knowledge layer — skills (`.codex/skills/*/SKILL.md`)

`mantis-pipeline` (master playbook) · `findings-spine` · `semgrep-triage` ·
`codeql-audit` · `osv-dependency-scan` · `secrets-scan` · `detection-breadth`
(bandit+trivy) · `program-analysis` · `http-evidence` · `canary-tripwire-response`.

### The findings spine

`.codex/mcp-servers/findings/server.js` owns finding state as an append-only
event log at `.codex/findings/events.jsonl` (gitignored). It enforces the PRD
invariants in code, not prose: legal lifecycle transitions only
(`candidate -> confirmed | rejected -> exploited -> fixed -> verified`), no
`confirmed` without reachability evidence, no `rejected` without a cited
roadblock, 5-axis grading -> SUBMIT/HOLD/SKIP, and refusal of any payload that
looks like it carries a raw secret.

---

## How to extend (copy-paste recipes)

### Add a tool (MCP server)

1. `mkdir .codex/mcp-servers/<name>` and write `server.js` following
   `.codex/mcp-servers/semgrep/server.js`: `require('../lib/mcp_stdio.js')` +
   `require('../lib/run_tool.js')`, one handler per tool, return `available:
   false` via `notFoundMessage(...)` when the binary is missing. Normalize every
   result to a `candidate`, never a severity.
2. Register it in `.codex/config.toml`:
   ```toml
   [mcp_servers.mantis_<name>]
   command = "node"
   args = [".codex/mcp-servers/<name>/server.js"]
   startup_timeout_sec = 10
   tool_timeout_sec = 300
   default_tools_approval_mode = "auto"
   ```
3. Add a `.codex/skills/<name>/SKILL.md` telling agents when to reach for it and
   how its output maps into the findings lifecycle.

### Add an agent (role)

Create `.codex/agents/<name>.toml` (auto-discovered from the project config
layer; `name` and `developer_instructions` are required):

```toml
name = "<name>"
description = "One line shown in spawn_agent guidance."
model_reasoning_effort = "high"     # tier: high=strong stages, medium=mid, low=cheap
default_permissions = ":read-only"  # omit for a role that must write (e.g. fixer)
developer_instructions = '''
The system prompt: role, method, tool routing, output, safety.
'''
```

It appears as a `spawn_agent` `agent_type` automatically. Requires multi-agent
mode enabled in the session (see caveats). Prefer TOML role files over compiling
built-ins into `codex-rs/core/src/agent/role.rs` unless the agent must ship in
the binary. Note: `codex-rs/core/templates/agents/orchestrator.md` is dead code
— editing it defines nothing.

### Add knowledge (skill)

`.codex/skills/<name>/SKILL.md` with frontmatter (`name`, `description`) and a
tight body. Skills are surfaced to the model by the harness; keep each one about
one job and cross-link with the pipeline.

---

## The best way to go further — prioritized roadmap

Ordered by value given the PRD phase gates and this environment. P0/P1 detection
+ the validation agents + the findings spine are done; the gaps below are mostly
P2/P3 and need a running target and external tooling.

**Now (highest leverage, low risk):**
1. Install the P0 binaries (`semgrep`, `osv-scanner`, `trufflehog`, `codeql`,
   `z3`, `bandit`) so the wired detectors actually run. No code changes.
2. Enable multi-agent spawning so the 13 roles are usable as subagents; until
   then run the pipeline stages sequentially in one context (the `mantis-pipeline`
   skill covers both modes).
3. Per-stage model routing (PRD FR-14.1): pin a specific strong model on
   `detector`/`reachability`/`validator`/verifiers and a cheaper model on
   `recon`/`context-enrich`/`reporter` by adding `model = "..."` to those role
   files, once the target model ids are confirmed valid in this fork.

**P2 (needs a running app + external binaries) — add as MCP servers + skills:**
4. Recon/DAST toolchain: `httpx`, `subfinder`, `naabu`, `nmap`, `katana`,
   `wafw00f`, `nuclei`, `wapiti`, `ZAP`, `ffuf`/`dirsearch`/`arjun`. Each is a
   report-until-installed server on the existing pattern; they only run when
   scope is `active`/`exploit` against an authorized target.
5. Injection confirmers: `sqlmap` + per-class HTTP confirm tools (idor/xss/cors)
   that build on `http_audit` for evidence.
6. OOB/blind: `interactsh-client`; Auth: `jwt_tool` + auth-profiles; Browser:
   headless chromium for DOM/client-side XSS.

**P3 (deep verticals):**
7. Fuzzing/binary/crash: AFL++/libFuzzer/atheris, gdb crash-analyzer, Frida.
8. CVE intel + OSS forensics: `cve-diff`, `cvemap`, git/wayback provenance
   (git is present — a pure-ish server is feasible sooner).
9. Web3 vertical (Foundry/Halmos/Anchor) — gated on the PRD's D-Web3 go/no-go.

**Cross-cutting infra the PRD calls for but the `.codex/` layer can't fully own:**
per-stage LLM gateway with budget/DLP/reliability-scorecard (FR-14.4), the
control/data-plane split, per-run container/microVM isolation beyond the Codex
OS-sandbox, and the private adversarial benchmark. These live above the harness
and are tracked as child artifacts of the PRD, not in `.codex/`.

## Caveats

- **Multi-agent mode**: the `spawn_agent` tool (and therefore the role files) is
  gated by `MultiAgentVersion` (Disabled/V1/V2), resolved from feature flags in
  `codex-rs/core/src/config/mod.rs`. Defining roles is forward-compatible and
  harmless when spawning is off; they light up when it is enabled.
- **Per-agent MCP tool subsets**: role files intentionally do NOT override
  `mcp_servers`, so every agent inherits the full project toolset and no security
  tool is accidentally hidden. Hard per-tool allowlists per role (e.g. detector
  can't reach an exploit tool) are a follow-up once merge-vs-replace semantics of
  a role-layer `mcp_servers` table are confirmed; today the `:read-only` posture
  plus prompt-level tool routing is the enforced restriction.
- **Run from the repo root** so the relative `args` paths in `config.toml`
  resolve (see the header comment in `.codex/config.toml`).
