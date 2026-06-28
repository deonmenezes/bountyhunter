# PHASES — execution plan with Claude Code context operations

Each phase below is a batch of package ports. The **context operation** rules are
what keep a 438K-LOC migration tractable in Claude Code: every port runs in its own
fresh window seeing only what it needs. Run the driver, not your memory.

> Generated assignment lives in `PHASES.lock.json` (`migrate.py plan`). Counts below
> are from the current inventory and will shift as `review` packages get dispositioned.

---

## The context operation (applies to every port task)

A port is **one Claude Code invocation** fed **one generated bundle**:

```
python3 rust-migration/orchestrator/migrate.py port <package> --exec
```

That command:
1. **Marks** the package `in_progress` in `migration-state.json`.
2. **Generates** `phases/phaseN/<pkg>.task.md` — a bundle containing ONLY:
   - the package's in-scope `.py` files (the sole files the task may rewrite),
   - already-ported Rust deps (reuse, never reimplement),
   - the Python test suite that is the parity oracle,
   - the strict faithful-rewrite contract (no features, no API changes).
3. **Dispatches** it to a fresh `claude -p` process — **no shared context** with any
   other port, so context never grows across the 58-package migration.
4. **Verifies** via `verify.py` (cargo test + Python oracle under the Rust backend).
5. Leaves the package `verified` on success, `in_progress` on failure.

**Hard context rules for the executing agent (encoded in every bundle):**
- Read/modify **only** the listed files. Need another file? Stop and report — don't pull it in.
- The operation is a **rewrite**: identical behavior, identical public signatures.
- Do not touch any other package. Do not "improve" anything.
- Don't mark done until the parity harness is green.

---

## Phase 0 — Foundation  *(done)*

**Context:** orchestrator + build config only; no Python source in scope.

- [x] Inventory + classifier + topo-order (`inventory.py` → `migration-manifest.json`).
- [x] Durable state ledger (`state.py` → `migration-state.json`).
- [x] Context-bundle generator (`context.py`).
- [x] Parity gate (`verify.py`).
- [x] Driver with per-phase commits (`migrate.py`).
- [x] Cargo workspace + shared PyO3 dependency + release profile.
- [x] First port proves the loop: `packages.cvss` → `mantishack_cvss` (parity green).

**Gate:** `cargo test` green on the seed crate; `migrate.py plan` produces a phase lock.
**Commit:** `rust-migration phase 0: foundation + orchestrator`.

## Phase 1 — Pure-compute leaves  *(6 pkgs · ~2,039 LOC)*

Zero-internal-dependency `rust-port` packages — the safest first batch.
e.g. `core.sentinels`, `core.url_patterns`, `packages.cvss`, `core.schema_constants`,
`core.function_taxonomy`, `packages.sca.versions`.

**Context per task:** the single package's files + golden vectors. No deps.
**Gate:** each package `verified`. **Commit:** `rust-migration phase 1: pure-compute leaves`.

## Phase 2 — Static-analysis core  *(5 pkgs · ~16,281 LOC)*

`rust-port` packages with shallow deps (depth 1–2) — the CPU-bound win that
motivated the migration: AST, dataflow, call-graph/reachability inventory.

**Context per task:** the package + its Phase-1 Rust deps (signatures only).
**Gate:** parity + a perf note (≥10× target, non-gating).
**Commit:** `rust-migration phase 2: static-analysis core`.

## Phase 3 — Data/format layer  *(19 pkgs · ~56,187 LOC)*

Deeper `rust-port` packages (depth 3+): sarif, tar/zip/oci, json, git, http, url, cve/nvd/osv.

**Context per task:** the package + already-ported deps.
**Gate:** parity. **Commit:** `rust-migration phase 3: data/format layer`.

## Phase 4 — External-tool glue  *(28 pkgs · ~81,377 LOC)*

`rust-glue` packages: codeql, semgrep, fuzzing, coccinelle, smt_solver, binary_analysis,
recon. **Port the subprocess/parse glue to Rust; the external binaries stay.**

**Context per task:** the package + the external tool's I/O contract (sample output).
**Gate:** parity against recorded tool fixtures. **Commit:** `rust-migration phase 4: external-tool glue`.

## Phase 5 — Wiring / cutover  *(17 keep-python pkgs at the seam)*

`keep-python` packages stay Python but flip their imports to the Rust shims. Run the
**full** Mantishack test suite with `MANTISHACK_USE_RUST=1` as the final parity gate,
then make Rust the default backend.

**Context per task:** only the import-seam files of each keep-python package.
**Gate:** full suite green under Rust backend. **Commit:** `rust-migration phase 5: wiring/cutover`.

## Phase 6 — Cleanup  *(manual)*

Delete superseded pure-Python implementations now shadowed by verified crates;
`review` packages get dispositioned and folded into the right phase. Final
`cargo clippy`, workspace-wide test, and a coverage report against the 58 targets.

---

## Daily operator loop

```bash
python3 rust-migration/orchestrator/migrate.py status        # where are we
python3 rust-migration/orchestrator/migrate.py next          # next ready package
python3 rust-migration/orchestrator/migrate.py port <pkg> --exec   # rewrite + verify one
python3 rust-migration/orchestrator/migrate.py run 1 --exec   # whole phase
python3 rust-migration/orchestrator/migrate.py commit 1 --exec     # tidy phase commit
```

Re-running is safe: verified packages are skipped, and dependency order is enforced
so a package never ports before the crates it calls exist.
