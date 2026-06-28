"""Inventory + classify + order the Mantishack Python codebase for Rust migration.

This is the analytical core of the migration orchestrator. It:

  1. Walks the real Python source tree (skipping vendored/.venv/out/test caches).
  2. Parses every module with `ast` to extract its imports (cheap, accurate,
     no execution of untrusted code).
  3. Builds an internal module dependency graph (who-imports-whom).
  4. Classifies each *package* into a migration disposition:
        - rust-port      pure compute, good Rust fit, port to a crate
        - rust-glue      wraps an external binary; port the orchestration glue,
                         keep shelling out to the binary
        - keep-python    LLM/agentic/SDK-bound; stays Python, calls INTO Rust
        - review         ambiguous; a human decides
  5. Emits a topological port order (leaves first) so a module is only ported
     after everything it depends on already has a Rust (or stable-Python) home.

Output: migration-manifest.json — the single source of truth every other
orchestrator component reads. Nothing here mutates source; it only measures.

Run:  python3 rust-migration/orchestrator/inventory.py
"""
from __future__ import annotations

import ast
import json
import os
import sys
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path

# Repo root = two levels up from this file (rust-migration/orchestrator/inventory.py).
REPO = Path(__file__).resolve().parents[2]

# Directories that are NOT first-party source — never inventoried.
SKIP_DIRS = {
    ".git", ".venv", "venv", "node_modules", "out", "__pycache__",
    "codeql_dbs", ".omc", "rust-migration", "docs", ".devcontainer",
    "build", "dist", ".pytest_cache", ".mypy_cache",
}

# Top-level source roots we care about. Everything else at repo root is config.
SOURCE_ROOTS = ["core", "packages", "engine", "libexec", "tiers", "bin"]

# --- classification signal tables -------------------------------------------

# Import prefixes that force keep-python: the mature AI / orchestration stack
# that has no equivalent worth rebuilding in Rust.
KEEP_PYTHON_IMPORTS = {
    "anthropic", "openai", "litellm", "google.generativeai", "cohere",
    "ollama", "transformers", "torch", "langchain", "llama_index",
    "claude_code", "mcp",
}
KEEP_PYTHON_NAMES = {  # package path fragments
    "llm", "orchestration", "autonomous", "sage", "agentic",
    "strategy_eval", "reporting", "progress", "status", "startup",
}

# Names / imports that mark a module as glue around an external binary:
# the binary stays; only the subprocess+parse logic moves to Rust.
GLUE_NAMES = {
    "codeql", "semgrep", "fuzzing", "coccinelle", "smt_solver",
    "binary_analysis", "recon",
}
# Distinctive whole-token tool names that, when they appear as an argv[0]-style
# string constant, indicate the module shells out. Short/ambiguous tokens
# (z3, nm, rr) are deliberately excluded — they cause substring false positives.
GLUE_TOOL_TOKENS = {
    "codeql", "semgrep", "afl-fuzz", "spatch", "coccinelle",
    "objdump", "readelf",
}

# Names that are strong rust-port candidates: pure computation / data structures.
RUST_PORT_NAMES = {
    "cvss", "hash", "url_patterns", "schema_constants", "json", "sarif",
    "ast", "dataflow", "inventory", "function_taxonomy", "witness",
    "verified_outcome", "sentinels", "cve", "nvd", "osv", "sca", "cvss",
    "http", "url", "git", "config", "tuning",
}


@dataclass
class ModuleInfo:
    path: str                      # repo-relative .py path
    package: str                   # owning top-level package (e.g. "core.inventory")
    loc: int                       # non-blank lines of code
    imports_internal: list[str] = field(default_factory=list)
    imports_external: list[str] = field(default_factory=list)
    subprocess_tokens: list[str] = field(default_factory=list)


@dataclass
class PackageInfo:
    name: str                      # dotted package, e.g. "core.inventory"
    loc: int
    n_files: int
    disposition: str               # rust-port | rust-glue | keep-python | review
    reason: str
    depends_on: list[str] = field(default_factory=list)   # other internal packages
    external_imports: list[str] = field(default_factory=list)


def _iter_py_files() -> list[Path]:
    files: list[Path] = []
    for root in SOURCE_ROOTS:
        base = REPO / root
        if not base.exists():
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                if fn.endswith(".py"):
                    files.append(Path(dirpath) / fn)
    return files


def _package_of(rel: Path) -> str:
    """Owning package = directory path with dots, e.g. core/inventory/x.py -> core.inventory."""
    parts = rel.parts
    if len(parts) <= 1:
        return parts[0] if parts else "<root>"
    return ".".join(parts[:-1])


def _nonblank_loc(src: str) -> int:
    return sum(1 for ln in src.splitlines() if ln.strip())


def _analyze_module(path: Path) -> ModuleInfo | None:
    rel = path.relative_to(REPO)
    try:
        src = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(src, filename=str(rel))
    except (SyntaxError, ValueError):
        return None

    internal: set[str] = set()
    external: set[str] = set()
    tokens: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                (internal if top in {"core", "packages", "engine"} else external).add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level and node.level > 0:
                internal.add("." * node.level + (node.module or ""))
            elif node.module:
                top = node.module.split(".")[0]
                (internal if top in {"core", "packages", "engine"} else external).add(node.module)
        # subprocess-token scan: a string constant that IS an external tool name
        # (argv[0] style) or starts with it followed by a space/flag. Whole-token
        # only — avoids matching tool names buried inside unrelated prose.
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            v = node.value.strip().lower()
            head = v.split()[0] if v.split() else ""
            head = head.rsplit("/", 1)[-1]  # basename of a path-like argv[0]
            if head in GLUE_TOOL_TOKENS:
                tokens.add(head)

    return ModuleInfo(
        path=str(rel),
        package=_package_of(rel),
        loc=_nonblank_loc(src),
        imports_internal=sorted(internal),
        imports_external=sorted(external),
        subprocess_tokens=sorted(tokens),
    )


def _classify(pkg: str, loc: int, ext_imports: set[str], tokens: set[str]) -> tuple[str, str]:
    leaf = pkg.split(".")[-1]
    name_parts = set(pkg.split("."))

    # 0. test/fixture packages are out of migration scope — Rust crates get
    #    their own native #[test] modules; Python tests become the parity oracle.
    if name_parts & {"tests", "test", "fixtures", "fixture", "testdata", "__pycache__"}:
        return "skip-test", "test/fixture package — not migrated; used as parity oracle"

    # 1. keep-python wins if it touches the AI/orchestration stack.
    hit = sorted(e for e in ext_imports if e.split(".")[0] in KEEP_PYTHON_IMPORTS)
    if hit:
        return "keep-python", f"imports AI/orchestration SDK: {', '.join(hit[:3])}"
    if name_parts & KEEP_PYTHON_NAMES:
        return "keep-python", f"orchestration/LLM package name ({leaf})"

    # 2. rust-glue if it drives an external binary.
    if tokens:
        return "rust-glue", f"wraps external tool(s): {', '.join(sorted(tokens)[:3])}"
    if name_parts & GLUE_NAMES:
        return "rust-glue", f"external-tool package name ({leaf})"

    # 3. rust-port for known pure-compute packages.
    if name_parts & RUST_PORT_NAMES:
        return "rust-port", f"pure-compute package ({leaf}); strong Rust fit"

    # 4. otherwise: small + no heavy external deps -> rust-port candidate; else review.
    heavy = {"requests", "aiohttp", "flask", "fastapi", "django", "boto3",
             "sqlalchemy", "pandas", "numpy", "scipy"}
    if ext_imports & heavy:
        return "review", f"depends on heavy runtime lib: {', '.join(sorted(ext_imports & heavy)[:2])}"
    return "review", "no decisive signal — human dispositions this package"


def build_manifest() -> dict:
    modules = [m for p in _iter_py_files() if (m := _analyze_module(p))]

    # Aggregate into packages.
    pkg_loc: dict[str, int] = defaultdict(int)
    pkg_files: dict[str, int] = defaultdict(int)
    pkg_ext: dict[str, set[str]] = defaultdict(set)
    pkg_tokens: dict[str, set[str]] = defaultdict(set)
    pkg_internal: dict[str, set[str]] = defaultdict(set)

    for m in modules:
        pkg_loc[m.package] += m.loc
        pkg_files[m.package] += 1
        pkg_ext[m.package].update(m.imports_external)
        pkg_tokens[m.package].update(m.subprocess_tokens)
        for imp in m.imports_internal:
            if imp.startswith("."):
                continue  # relative import = same package, ignore for cross-pkg graph
            # map dotted module import to its owning package (drop trailing symbol)
            pkg_internal[m.package].add(imp)

    packages: dict[str, PackageInfo] = {}
    for pkg in sorted(pkg_loc):
        # Resolve internal imports to known packages (prefix match, longest first).
        deps: set[str] = set()
        known = set(pkg_loc)
        for imp in pkg_internal[pkg]:
            cand = [k for k in known if imp == k or imp.startswith(k + ".")]
            for c in sorted(cand, key=len, reverse=True):
                if c != pkg:
                    deps.add(c)
                    break
        disp, reason = _classify(pkg, pkg_loc[pkg], pkg_ext[pkg], pkg_tokens[pkg])
        packages[pkg] = PackageInfo(
            name=pkg, loc=pkg_loc[pkg], n_files=pkg_files[pkg],
            disposition=disp, reason=reason,
            depends_on=sorted(deps), external_imports=sorted(pkg_ext[pkg])[:25],
        )

    order = _topo_order(packages)

    summary: dict[str, int] = defaultdict(int)
    loc_by_disp: dict[str, int] = defaultdict(int)
    for p in packages.values():
        summary[p.disposition] += 1
        loc_by_disp[p.disposition] += p.loc

    # Port order excludes test/fixture packages — they are never migrated.
    order = [k for k in order if packages[k].disposition != "skip-test"]

    return {
        "repo": str(REPO),
        "totals": {
            "modules": len(modules),
            "packages": len(packages),
            "loc": sum(pkg_loc.values()),
        },
        "summary_by_disposition": dict(summary),
        "loc_by_disposition": dict(loc_by_disp),
        "port_order": order,
        "packages": {k: asdict(v) for k, v in packages.items()},
    }


def _topo_order(packages: dict[str, PackageInfo]) -> list[str]:
    """Kahn topological sort over internal package deps; leaves (no deps) first.

    Cycles are broken deterministically by emitting the lowest-LOC member first
    (small modules are easier to port to break a cycle). Order only includes
    packages whose disposition involves Rust work, but every package is ranked.
    """
    indeg: dict[str, int] = {k: 0 for k in packages}
    radj: dict[str, list[str]] = defaultdict(list)
    for k, p in packages.items():
        for d in p.depends_on:
            if d in packages:
                indeg[k] += 1
                radj[d].append(k)

    import heapq
    # priority = (indegree-ready, loc) -> smaller first
    ready = [(packages[k].loc, k) for k in packages if indeg[k] == 0]
    heapq.heapify(ready)
    order: list[str] = []
    seen: set[str] = set()
    remaining = dict(indeg)

    while ready:
        _, k = heapq.heappop(ready)
        if k in seen:
            continue
        seen.add(k)
        order.append(k)
        for nxt in radj[k]:
            remaining[nxt] -= 1
            if remaining[nxt] <= 0 and nxt not in seen:
                heapq.heappush(ready, (packages[nxt].loc, nxt))

    # Any leftovers (cycles): append by ascending LOC.
    for k in sorted(set(packages) - seen, key=lambda x: packages[x].loc):
        order.append(k)
    return order


def main() -> int:
    manifest = build_manifest()
    out = REPO / "rust-migration" / "migration-manifest.json"
    out.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    t = manifest["totals"]
    print(f"Inventoried {t['modules']} modules / {t['packages']} packages / {t['loc']:,} LOC")
    print("\nDisposition (packages | LOC):")
    for disp in ("rust-port", "rust-glue", "keep-python", "review", "skip-test"):
        n = manifest["summary_by_disposition"].get(disp, 0)
        loc = manifest["loc_by_disposition"].get(disp, 0)
        print(f"  {disp:<12} {n:>4} pkgs | {loc:>8,} LOC")
    print(f"\nManifest written: {out.relative_to(REPO)}")
    print(f"First 12 in port order: {manifest['port_order'][:12]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
