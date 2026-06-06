---
description: Add, list, edit, or remove per-function annotations attached to source files
---

# /mantis-annotate

Per-function prose annotations stored as markdown mirroring the source tree.
Annotations capture audit-style notes on individual functions: a manual
"reviewed clean", a hypothesis-then-validate finding, a CWE label, or any
free-form prose.

Operator-driven adds default to ``metadata.source=human``, so subsequent
LLM passes (`/mantis-agentic`, `/mantis-understand` post-processor) that pass
``overwrite=respect-manual`` will not silently clobber operator notes.

## Usage

```
/mantis-annotate add <file> <function> [options]
/mantis-annotate ls [options]
/mantis-annotate show <file> <function> [options]
/mantis-annotate edit <file> <function> [options]
/mantis-annotate rm <file> <function> [options]
/mantis-annotate stale [options]
```

## Subcommands

| Subcommand | What it does |
|---|---|
| `add <file> <function>` | Write or update an annotation |
| `ls` | List annotations (filterable by file/status/source) |
| `show <file> <function>` | Render one annotation |
| `edit <file> <function>` | Open the source file's annotation .md in `$EDITOR` |
| `rm <file> <function>` | Remove an annotation; cleans up empty .md files |
| `stale` | List annotations whose stored source-line hash no longer matches |

## Add options

| Option | Purpose |
|---|---|
| `--status VALUE` | `clean` / `suspicious` / `finding` / `error` |
| `--cwe CWE-XX` | CWE identifier |
| `-m, --body TEXT` | Annotation prose |
| `--body-file PATH` | Read body from file (`-` for stdin) |
| `--lines N-M` | Source line range; computes `metadata.hash` for staleness |
| `--target REPO_ROOT` | Where to find source for hash (default: cwd) |
| `--meta KEY=VALUE` | Extra metadata (repeatable) |
| `--source VALUE` | Defaults to `human`; set `llm` only for scripted adds |
| `--overwrite MODE` | `all` (default) or `respect-manual` |

## ls options

| Option | Purpose |
|---|---|
| `--file PATH` | Show only annotations for one source file |
| `--status VALUE` | Filter by `metadata.status` |
| `--source VALUE` | Filter by `metadata.source` |
| `--cwe CWE-XX` | Filter by `metadata.cwe` (exact match) |
| `--rule-id PATTERN` | Filter by `metadata.rule_id` substring (e.g. `py/`) |
| `--grep TEXT` | Case-insensitive substring search across body + metadata |
| `--since 7d` | Annotation file mtime within window (`Nd`/`Nh`/`Nm`/`Ns`/`Nw`) |

## stale options

| Option | Purpose |
|---|---|
| `--target REPO_ROOT` | Source-tree root for hash recomputation (default: cwd) |

## Common option

`--base PATH` — annotation base directory. Defaults to the active project's
`<output_dir>/annotations`. Required if no project is active.

## Examples

```
# Manual clean review
/mantis-annotate add src/auth.py check_password \
    --status clean -m "Reviewed: constant-time compare, no taint"

# Manual finding with CWE + staleness hash
/mantis-annotate add src/exec.py run_cmd \
    --status finding --cwe CWE-78 \
    --lines 42-58 --target ~/repos/myproj \
    -m "Confirmed shell injection via subprocess(shell=True)"

# Quick listing
/mantis-annotate ls
/mantis-annotate ls --status finding
/mantis-annotate ls --source human

# Inspect one record
/mantis-annotate show src/auth.py check_password

# Edit (opens .md in $EDITOR)
/mantis-annotate edit src/auth.py check_password

# Remove a record
/mantis-annotate rm src/auth.py old_function

# Find stale annotations after source edits
/mantis-annotate stale --target ~/repos/myproj
```

## Execution

Run via the Bash tool:

```bash
libexec/mantishack-annotate <subcommand> [args]
```

For `add` calls invoked through this slash command, the operator's intent
is implicit — keep the default `--source human`. Do **not** pass
`--source llm` from `/mantis-annotate` unless the operator explicitly asks for
scripted, non-human-attributable behaviour.

## Output

Output the result verbatim in a fenced code block. Do not summarise — the
operator wants exact paths, exact metadata values, and exact bodies.

## Base-dir resolution

The CLI resolves the annotation base in this order:

1. Explicit `--base PATH` argument
2. Active project's `<output_dir>/annotations`
3. Exit 2 with a hint to set `--base` or activate a project

So when a project is active (`/mantis-project use foo`), `/mantis-annotate ls` "just
works" without arguments.

## Conventions

- **`metadata.source=human`** marks a manual entry. LLM-driven callers
  (e.g. `/mantis-agentic`'s annotation emitter) pass `overwrite=respect-manual`
  so they will skip rather than overwrite a human-source record.
- **`metadata.hash`**: a short sha256 prefix of the function's source
  lines, captured at add time when `--lines N-M --target REPO_ROOT` is
  provided. Used by `/mantis-annotate stale` to detect annotations whose source
  has drifted.
- **Function names**: top-level functions use bare names (`process`);
  class methods use dotted form (`MyClass.process`).
- **Path traversal**: `../etc/passwd` is rejected before any filesystem
  access, regardless of `--base` value.
