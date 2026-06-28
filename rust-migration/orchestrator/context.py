"""Per-package context-bundle generator — the 'clean context operations'.

The migration's core risk is context pollution: a 528K-LOC repo cannot be held
in one Claude Code window, and a port task that sees the whole tree will drift.
This module manufactures, for ONE package, a self-contained task bundle that
contains EXACTLY what's needed to rewrite that package to Rust and nothing else:

    * the Python source files to rewrite (the only files in scope),
    * the already-ported Rust deps it may call (signatures only),
    * the Python tests that are the parity oracle,
    * a strict, faithful-rewrite instruction block,
    * the exact target crate path and binding contract.

A bundle is a single markdown file under rust-migration/phases/phaseN/<pkg>.task.md.
Feed it to a fresh `claude -p < bundle` or a subagent. When the task finishes,
the orchestrator advances state and the bundle is never needed again — no
cross-task memory, no growing context.

THE OPERATION IS A REWRITE, NOT A REDESIGN. The generated instructions forbid
behavior changes: same inputs -> same outputs, byte-for-byte where the Python
tests assert it. Rust is an implementation detail swap, not a product change.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
MANIFEST_PATH = REPO / "rust-migration" / "migration-manifest.json"
PHASES_DIR = REPO / "rust-migration" / "phases"


def _crate_name(pkg: str) -> str:
    # core.inventory -> mantishack_core_inventory ; packages.cvss -> mantishack_cvss
    leaf = pkg.replace("packages.", "").replace("core.", "core_").replace(".", "_")
    return f"mantishack_{leaf}".replace("__", "_")


def _py_files_for(pkg: str, manifest: dict) -> list[str]:
    """All non-test .py files whose owning package is exactly `pkg`."""
    base = pkg.replace(".", os.sep)
    out = []
    pkg_dir = REPO / base
    if pkg_dir.is_dir():
        for p in sorted(pkg_dir.glob("*.py")):
            if p.name != "__init__.py" or p.stat().st_size > 0:
                out.append(str(p.relative_to(REPO)))
    return out


def build_bundle(pkg: str, manifest: dict, state, phase: int) -> Path:
    info = manifest["packages"][pkg]
    crate = _crate_name(pkg)
    py_files = _py_files_for(pkg, manifest)

    # Resolve already-ported dependencies (signature-only references).
    dep_lines = []
    for d in info["depends_on"]:
        ds = state.packages.get(d)
        if ds and ds.crate:
            dep_lines.append(f"- `{d}` → already a Rust crate `{ds.crate}`; call it, don't reimplement.")
        elif ds and ds.disposition == "keep-python":
            dep_lines.append(f"- `{d}` → stays Python; your crate must not depend on it (invert if needed).")
    deps_block = "\n".join(dep_lines) if dep_lines else "- (none — this is a leaf package)"

    files_block = "\n".join(f"  - `{f}`" for f in py_files) or "  - (package has no direct .py modules)"

    # Locate the Python tests that will serve as the parity oracle.
    test_dir = REPO / pkg.replace(".", os.sep) / "tests"
    oracle = (f"`{test_dir.relative_to(REPO)}` — run these against BOTH implementations."
              if test_dir.is_dir() else
              "No co-located tests. Write golden-vector parity tests from the Python behavior.")

    crate_path = f"rust-migration/crates/{crate}"

    bundle = f"""# PORT TASK — `{pkg}` → Rust crate `{crate}`

> Phase {phase} · disposition **{info['disposition']}** · {info['loc']:,} LOC · {info['n_files']} files
> Classifier reason: {info['reason']}

## OPERATION: faithful rewrite to Rust (NOT a redesign)

You are rewriting ONE Python package into an equivalent Rust crate. This is a
behavior-preserving port. Hard rules:

1. **Same behavior.** Identical inputs must produce identical outputs, including
   edge cases, error types, and rounding. The Python package's tests are the
   contract — they must pass against your Rust implementation via the binding.
2. **No new features, no "improvements", no API changes.** If the Python code
   has a quirk that tests rely on (e.g. CVSS `\\Z` anchor rejecting trailing
   newlines, duplicate-key rejection), reproduce the quirk exactly.
3. **Scope is ONLY the files listed below.** Do not read or modify anything else
   in the repo. Do not touch other packages. If you think you need another file,
   stop and report it — do not pull it into context.
4. **PyO3 binding with identical signatures.** Expose the same public functions
   so Python callers switch by changing one import line, nothing else.
5. **Idiomatic, safe Rust.** No `unsafe` unless a listed file genuinely requires
   it. Prefer `Result<T, E>` mapping the Python exceptions to error variants.

## FILES IN SCOPE (the only files you may rewrite)
{files_block}

## DEPENDENCIES (already resolved — reuse, do not reimplement)
{deps_block}

## TARGET
- Crate dir: `{crate_path}/`
- `Cargo.toml` with `[lib] crate-type = ["cdylib", "rlib"]`, `pyo3` dependency.
- `src/lib.rs` (+ submodules mirroring the Python modules 1:1).
- `#[pymodule]` named `{crate}` exporting every public symbol the Python had.

## PARITY ORACLE
{oracle}

## DEFINITION OF DONE
- [ ] `cargo build -p {crate}` succeeds with no warnings.
- [ ] `cargo test -p {crate}` (native Rust unit tests mirroring Python cases) green.
- [ ] `maturin develop -m {crate_path}/Cargo.toml` builds the Python extension.
- [ ] Parity harness passes: `python3 rust-migration/orchestrator/verify.py {pkg}`.
- [ ] You changed NOTHING outside `{crate_path}/`.

When done, report: crate path, # public symbols exported, parity pass count.
Do NOT mark the task done until the parity harness is green.
"""
    phase_dir = PHASES_DIR / f"phase{phase}"
    phase_dir.mkdir(parents=True, exist_ok=True)
    out = phase_dir / f"{pkg.replace('.', '__')}.task.md"
    out.write_text(bundle, encoding="utf-8")
    return out


def main(argv: list[str]) -> int:
    manifest = json.loads(MANIFEST_PATH.read_text())
    from state import MigrationState
    state = MigrationState()
    if len(argv) < 2:
        print("usage: context.py <package> [phase]")
        return 2
    pkg = argv[1]
    phase = int(argv[2]) if len(argv) > 2 else state.packages[pkg].phase
    out = build_bundle(pkg, manifest, state, phase if phase >= 0 else 1)
    print(f"Wrote context bundle: {out.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main(sys.argv))
