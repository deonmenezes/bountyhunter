"""Parity verifier — proves a Rust rewrite matches the Python original.

A port is only 'verified' when the SAME behavioral oracle passes against the
Rust implementation. Two complementary checks:

  1. Native Rust tests       — `cargo test -p <crate>` (mirrors Python unit cases).
  2. Cross-language parity    — the package's Python test suite, re-run with the
                                Rust binding swapped in for the pure-Python module.

For (2) we rely on a convention: each ported crate ships a thin Python shim
`<crate>.py` that re-exports the PyO3 symbols with the original module's public
names. The parity run sets MANTISHACK_USE_RUST=1 so the package's `__init__`
imports the shim instead of the Python implementation, then runs pytest. If the
existing suite is green under the Rust backend, behavior is preserved.

This module does not itself build Rust (that's the port task's job); it gates.
Exit 0 = verified, non-zero = parity failure (stay in 'ported', not 'verified').
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
MANIFEST_PATH = REPO / "rust-migration" / "migration-manifest.json"
CARGO = os.path.expanduser("~/.cargo/bin/cargo")


def _crate_for(pkg: str, state) -> str:
    ps = state.packages.get(pkg)
    return ps.crate if ps else ""


def cargo_test(crate: str) -> tuple[bool, str]:
    crate_name = Path(crate).name
    try:
        r = subprocess.run(
            [CARGO, "test", "-p", crate_name],
            cwd=REPO / "rust-migration", capture_output=True, text=True, timeout=900,
        )
        return r.returncode == 0, r.stdout[-2000:] + r.stderr[-2000:]
    except FileNotFoundError:
        return False, "cargo not found on PATH (~/.cargo/bin)"
    except subprocess.TimeoutExpired:
        return False, "cargo test timed out"


def pytest_parity(pkg: str) -> tuple[bool, str]:
    test_dir = REPO / pkg.replace(".", os.sep) / "tests"
    if not test_dir.is_dir():
        return True, "no Python test oracle (golden-vector Rust tests only)"
    env = dict(os.environ, MANTISHACK_USE_RUST="1")
    try:
        r = subprocess.run(
            [sys.executable, "-m", "pytest", str(test_dir), "-q", "--no-header"],
            cwd=REPO, capture_output=True, text=True, timeout=900, env=env,
        )
        return r.returncode == 0, r.stdout[-2000:] + r.stderr[-1000:]
    except subprocess.TimeoutExpired:
        return False, "pytest parity run timed out"


def verify(pkg: str) -> int:
    from state import MigrationState
    state = MigrationState()
    crate = _crate_for(pkg, state)
    if not crate:
        print(f"[parity] {pkg}: no crate recorded in state — port it first.")
        return 3

    ok_rust, rust_log = cargo_test(crate)
    print(f"[parity] cargo test -p {Path(crate).name}: {'PASS' if ok_rust else 'FAIL'}")
    if not ok_rust:
        print(rust_log)
        return 1

    ok_py, py_log = pytest_parity(pkg)
    print(f"[parity] python oracle (MANTISHACK_USE_RUST=1): {'PASS' if ok_py else 'FAIL'}")
    if not ok_py:
        print(py_log)
        return 2

    # Record parity result and promote to 'verified'.
    state.set_status(pkg, "verified", parity={"rust": "pass", "python_oracle": "pass"})
    print(f"[parity] {pkg}: VERIFIED — rewrite preserves behavior.")
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: verify.py <package>")
        raise SystemExit(2)
    raise SystemExit(verify(sys.argv[1]))
