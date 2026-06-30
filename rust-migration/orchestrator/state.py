"""Migration state — the durable ledger of what has been rewritten.

State lives on disk (migration-state.json), NOT in any Claude Code conversation.
This is deliberate: each port task runs in a fresh, scoped context and reads/writes
only this ledger. No phase depends on another phase's conversation memory.

Status lifecycle per package:
    pending      -> not started
    in_progress  -> a port task is active
    ported       -> Rust crate written, compiles
    verified     -> parity tests pass against the Python oracle
    wired        -> Python now imports the Rust binding (cutover done)
    skipped      -> keep-python / skip-test (never ported)
    blocked      -> needs human decision (review) or a failed gate

Only `verified` and beyond count as "done" for progress accounting.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict, fields
from functools import lru_cache
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
STATE_PATH = REPO / "rust-migration" / "migration-state.json"
MANIFEST_PATH = REPO / "rust-migration" / "migration-manifest.json"

DONE_STATES = {"verified", "wired", "skipped"}
ACTIVE_STATES = {"in_progress", "ported"}


@dataclass
class PackageState:
    name: str
    disposition: str
    status: str = "pending"
    crate: str = ""             # rust-migration/crates/<crate> once created
    phase: int = -1
    notes: str = ""
    parity: dict = field(default_factory=dict)  # {"py_tests": n, "passed": n}


@lru_cache(maxsize=1)
def _manifest_dispositions() -> dict[str, str]:
    """`{package: disposition}` from the manifest, for backfilling state rows
    that were hand-edited without the required identity fields."""
    if not MANIFEST_PATH.exists():
        return {}
    man = json.loads(MANIFEST_PATH.read_text())
    return {name: p.get("disposition", "review") for name, p in man["packages"].items()}


def _coerce_package(key: str, raw: dict) -> "PackageState":
    """Build a PackageState from a possibly-partial on-disk row.

    Partial-port rows (e.g. core.cve, packages.sca) are hand-annotated with
    rich free-text `status`/`parity` and may omit the identity fields. Backfill
    `name` from the dict key and `disposition` from the manifest, and drop any
    keys the dataclass doesn't know about, so a malformed row never crashes the
    whole ledger load (R8: idempotent & resumable)."""
    known = {f.name for f in fields(PackageState)}
    data = {k: v for k, v in raw.items() if k in known}
    data.setdefault("name", key)
    if "disposition" not in data:
        data["disposition"] = _manifest_dispositions().get(key, "review")
    return PackageState(**data)


class MigrationState:
    def __init__(self) -> None:
        self.packages: dict[str, PackageState] = {}
        self.load()

    # --- persistence --------------------------------------------------------
    def load(self) -> None:
        if STATE_PATH.exists():
            raw = json.loads(STATE_PATH.read_text())
            self.packages = {
                k: _coerce_package(k, v) for k, v in raw.get("packages", {}).items()
            }
        else:
            self._seed_from_manifest()

    def save(self) -> None:
        STATE_PATH.write_text(json.dumps(
            {"packages": {k: asdict(v) for k, v in self.packages.items()}},
            indent=2,
        ))

    def _seed_from_manifest(self) -> None:
        if not MANIFEST_PATH.exists():
            raise SystemExit("Run inventory.py first — migration-manifest.json missing.")
        man = json.loads(MANIFEST_PATH.read_text())
        for name, p in man["packages"].items():
            disp = p["disposition"]
            # keep-python and skip-test start life already 'skipped' (not ported).
            status = "skipped" if disp in {"keep-python", "skip-test"} else "pending"
            self.packages[name] = PackageState(name=name, disposition=disp, status=status)
        self.save()

    # --- queries ------------------------------------------------------------
    def get(self, name: str) -> PackageState:
        return self.packages[name]

    def set_status(self, name: str, status: str, **fields) -> None:
        p = self.packages[name]
        p.status = status
        for k, v in fields.items():
            setattr(p, k, v)
        self.save()

    def deps_satisfied(self, name: str, manifest: dict) -> bool:
        """A package is ready to port only when every internal dep is done."""
        for d in manifest["packages"][name]["depends_on"]:
            if d in self.packages and self.packages[d].status not in DONE_STATES:
                return False
        return True

    def progress(self) -> dict:
        tot = len(self.packages)
        by_status: dict[str, int] = {}
        for p in self.packages.values():
            by_status[p.status] = by_status.get(p.status, 0) + 1
        done = sum(by_status.get(s, 0) for s in DONE_STATES)
        return {"total": tot, "done": done, "by_status": by_status}


if __name__ == "__main__":
    st = MigrationState()
    prog = st.progress()
    print(f"Migration state: {prog['done']}/{prog['total']} packages resolved")
    for status, n in sorted(prog["by_status"].items()):
        print(f"  {status:<12} {n}")
