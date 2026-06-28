"""migrate.py — the driver that runs the entire Python→Rust rewrite.

This is the single entrypoint a human (or a CI loop) calls. It does NOT itself
write Rust — it orchestrates: assigns packages to phases, manufactures the
clean per-package context bundle, dispatches the faithful-rewrite task to a
fresh Claude Code process, verifies parity, and commits each phase atomically.

Subcommands:
    plan                     compute phase assignment, write rust-migration/PHASES.lock.json
    status                   show migration progress
    bundle  <phase>          generate context bundles for every package in a phase
    next                     print the next ready-to-port package (deps satisfied)
    port    <package>        run ONE package end to end: bundle → dispatch → verify
    run     <phase> [--exec] dispatch every ready package in the phase (dry-run unless --exec)
    commit  <phase>          git add the phase's crates + state, commit with a clean message

Design guarantees:
  * Context isolation — each port is a separate `claude -p` invocation fed only
    its bundle; no shared conversation, no context growth across packages.
  * Behavior preservation — a package is only committed after verify.py is green.
  * Atomic phase commits — one tidy commit per phase, message lists what moved.
  * Idempotent — re-running skips already-verified packages.

Dispatch is OFF by default (prints the command). Pass --exec to actually invoke
Claude Code. This keeps the driver safe to run for planning without burning tokens
or mutating the tree.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
MANIFEST_PATH = REPO / "rust-migration" / "migration-manifest.json"
PHASES_LOCK = REPO / "rust-migration" / "PHASES.lock.json"

sys.path.insert(0, str(HERE))
from state import MigrationState, DONE_STATES  # noqa: E402
import context as ctx                            # noqa: E402


# --- phase assignment -------------------------------------------------------

def _dep_depth(manifest: dict) -> dict[str, int]:
    """Longest internal-dependency chain length per package (memoised DFS)."""
    pkgs = manifest["packages"]
    depth: dict[str, int] = {}
    visiting: set[str] = set()

    def d(name: str) -> int:
        if name in depth:
            return depth[name]
        if name in visiting or name not in pkgs:
            return 0  # cycle / external — treat as leaf
        visiting.add(name)
        deps = pkgs[name]["depends_on"]
        depth[name] = (1 + max((d(x) for x in deps), default=-1)) if deps else 0
        visiting.discard(name)
        return depth[name]

    for k in pkgs:
        d(k)
    return depth


def assign_phases(manifest: dict) -> dict[str, int]:
    """Map each in-scope package to a semantic phase number.

    1  pure-compute leaves          (rust-port, depth 0)
    2  static-analysis / mid core   (rust-port, depth 1-2)
    3  deep data/format layer       (rust-port, depth 3+)
    4  external-tool glue           (rust-glue, any depth)
    5  wiring / cutover boundary     (keep-python — flips imports to Rust)
    -1 review (blocked) / skip-test  (not auto-phased)
    """
    depth = _dep_depth(manifest)
    phase: dict[str, int] = {}
    for name, p in manifest["packages"].items():
        disp = p["disposition"]
        if disp == "rust-port":
            dd = depth.get(name, 0)
            phase[name] = 1 if dd == 0 else (2 if dd <= 2 else 3)
        elif disp == "rust-glue":
            phase[name] = 4
        elif disp == "keep-python":
            phase[name] = 5
        else:  # review / skip-test
            phase[name] = -1
    return phase


def cmd_plan(_args) -> int:
    manifest = json.loads(MANIFEST_PATH.read_text())
    phase = assign_phases(manifest)
    state = MigrationState()
    # persist phase onto state
    for name, ph in phase.items():
        if name in state.packages:
            state.packages[name].phase = ph
    state.save()

    buckets: dict[int, list[str]] = defaultdict(list)
    order = manifest["port_order"]
    rank = {p: i for i, p in enumerate(order)}
    for name, ph in phase.items():
        buckets[ph].append(name)
    for ph in buckets:
        buckets[ph].sort(key=lambda n: rank.get(n, 1 << 30))

    PHASES_LOCK.write_text(json.dumps({str(k): v for k, v in sorted(buckets.items())}, indent=2))

    names = {1: "pure-compute leaves", 2: "static-analysis core", 3: "data/format layer",
             4: "external-tool glue", 5: "wiring / cutover", -1: "review / skip (manual)"}
    print("Phase plan (written to PHASES.lock.json):\n")
    for ph in sorted(buckets):
        loc = sum(manifest["packages"][n]["loc"] for n in buckets[ph])
        print(f"  Phase {ph:>2} · {names.get(ph,'?'):<24} {len(buckets[ph]):>3} pkgs · {loc:>7,} LOC")
    return 0


def cmd_status(_args) -> int:
    st = MigrationState()
    prog = st.progress()
    print(f"Progress: {prog['done']}/{prog['total']} packages resolved\n")
    for status, n in sorted(prog["by_status"].items()):
        print(f"  {status:<12} {n}")
    return 0


def _ready_in_phase(phase: int, manifest: dict, state: MigrationState) -> list[str]:
    lock = json.loads(PHASES_LOCK.read_text()) if PHASES_LOCK.exists() else {}
    members = lock.get(str(phase), [])
    ready = []
    for name in members:
        ps = state.packages.get(name)
        if not ps or ps.status in DONE_STATES or ps.status == "verified":
            continue
        if state.deps_satisfied(name, manifest):
            ready.append(name)
    return ready


def cmd_next(_args) -> int:
    manifest = json.loads(MANIFEST_PATH.read_text())
    state = MigrationState()
    for ph in (1, 2, 3, 4, 5):
        ready = _ready_in_phase(ph, manifest, state)
        if ready:
            print(f"Phase {ph} — next ready: {ready[0]}")
            print(f"  remaining ready in phase: {ready}")
            return 0
    print("Nothing ready — either all done or blocked on review packages.")
    return 0


def cmd_bundle(args) -> int:
    manifest = json.loads(MANIFEST_PATH.read_text())
    state = MigrationState()
    lock = json.loads(PHASES_LOCK.read_text())
    members = lock.get(str(args.phase), [])
    for name in members:
        if state.packages[name].disposition in {"rust-port", "rust-glue"}:
            out = ctx.build_bundle(name, manifest, state, args.phase)
            print(f"  bundle: {out.relative_to(REPO)}")
    return 0


def _dispatch(bundle: Path, execute: bool) -> bool:
    """Run a single faithful-rewrite task in a fresh Claude Code process."""
    prompt = bundle.read_text()
    cmd = ["claude", "-p", prompt, "--permission-mode", "acceptEdits"]
    if not execute:
        print(f"    [dry-run] would dispatch: claude -p < {bundle.name}")
        return False
    print(f"    dispatching port task: {bundle.name}")
    r = subprocess.run(cmd, cwd=REPO)
    return r.returncode == 0


def cmd_port(args) -> int:
    manifest = json.loads(MANIFEST_PATH.read_text())
    state = MigrationState()
    name = args.package
    ps = state.packages[name]
    if ps.status in DONE_STATES:
        print(f"{name}: already {ps.status} — skipping.")
        return 0
    phase = ps.phase if ps.phase > 0 else 1
    crate = ctx._crate_name(name)
    state.set_status(name, "in_progress", crate=f"rust-migration/crates/{crate}", phase=phase)
    bundle = ctx.build_bundle(name, manifest, state, phase)
    print(f"{name}: bundle -> {bundle.relative_to(REPO)}")
    ok = _dispatch(bundle, args.exec)
    if not ok and args.exec:
        print(f"{name}: dispatch failed — left in_progress.")
        return 1
    if args.exec:
        rc = subprocess.run([sys.executable, str(HERE / "verify.py"), name], cwd=REPO).returncode
        return rc
    return 0


def cmd_run(args) -> int:
    manifest = json.loads(MANIFEST_PATH.read_text())
    state = MigrationState()
    ready = _ready_in_phase(args.phase, manifest, state)
    if not ready:
        print(f"Phase {args.phase}: nothing ready.")
        return 0
    print(f"Phase {args.phase}: {len(ready)} package(s) ready: {ready}")
    for name in ready:
        a = argparse.Namespace(package=name, exec=args.exec)
        cmd_port(a)
    return 0


def cmd_commit(args) -> int:
    """One tidy commit per phase: the new crates + advanced state."""
    lock = json.loads(PHASES_LOCK.read_text())
    members = lock.get(str(args.phase), [])
    state = MigrationState()
    done = [n for n in members if state.packages[n].status in {"verified", "wired"}]
    if not done:
        print(f"Phase {args.phase}: no verified packages to commit.")
        return 0

    names = {1: "pure-compute leaves", 2: "static-analysis core", 3: "data/format layer",
             4: "external-tool glue", 5: "wiring/cutover"}
    crates = [state.packages[n].crate for n in done if state.packages[n].crate]
    paths = crates + [
        "rust-migration/migration-state.json",
        "rust-migration/Cargo.toml",
    ]
    subprocess.run(["git", "add", *paths], cwd=REPO)
    body = "\n".join(f"- {n} → {state.packages[n].crate}" for n in done)
    msg = (f"rust-migration phase {args.phase}: {names.get(args.phase, 'port')}\n\n"
           f"Faithful Python→Rust rewrite of {len(done)} package(s), parity-verified.\n\n"
           f"{body}\n\n"
           "Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>")
    if args.exec:
        subprocess.run(["git", "commit", "-m", msg], cwd=REPO)
    else:
        print("[dry-run] commit message:\n")
        print(msg)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(prog="migrate", description="Mantishack Python→Rust migration driver")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("plan").set_defaults(fn=cmd_plan)
    sub.add_parser("status").set_defaults(fn=cmd_status)
    sub.add_parser("next").set_defaults(fn=cmd_next)
    b = sub.add_parser("bundle"); b.add_argument("phase", type=int); b.set_defaults(fn=cmd_bundle)
    p = sub.add_parser("port"); p.add_argument("package"); p.add_argument("--exec", action="store_true"); p.set_defaults(fn=cmd_port)
    r = sub.add_parser("run"); r.add_argument("phase", type=int); r.add_argument("--exec", action="store_true"); r.set_defaults(fn=cmd_run)
    c = sub.add_parser("commit"); c.add_argument("phase", type=int); c.add_argument("--exec", action="store_true"); c.set_defaults(fn=cmd_commit)
    args = ap.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
