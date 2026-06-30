"""Shared helpers for ``libexec/`` dispatch scripts.

Centralises boilerplate that was previously duplicated across many
libexec scripts — directory/file validation, context-map loading, and
SMT-verb result output.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Callable, Optional


# ---------------------------------------------------------------------------
# Context-map enrichment helpers
# ---------------------------------------------------------------------------

def load_context_map_for_enrichment(
    understand_dir_arg: str,
    *,
    script_name: str,
) -> tuple[Path, dict, Optional[str]] | None:
    """Validate inputs and load context-map.json + checklist for enrichment.

    Performs the directory-exists / file-exists / JSON-object / checklist
    target_path checks that every ``mantishack-enrich-context-map-*``
    script needs.

    Returns ``(context_map_path, context_map, target_path)`` on success.
    On validation failure prints a diagnostic to stderr and returns
    ``None``; the caller should ``return 0`` or ``return 1`` as appropriate.

    ``target_path`` may be ``None`` if the checklist is missing or lacks
    the key — callers that require it should handle the ``None`` case.
    """
    from core.json import load_json  # deferred: sys.path may not be set at import time

    understand_dir = Path(understand_dir_arg).resolve()
    if not understand_dir.is_dir():
        print(
            f"{script_name}: {understand_dir} is not a directory",
            file=sys.stderr,
        )
        return None

    context_map_path = understand_dir / "context-map.json"
    if not context_map_path.exists():
        print(
            f"{script_name}: {context_map_path} does not exist",
            file=sys.stderr,
        )
        return None

    context_map = load_json(context_map_path)
    if not isinstance(context_map, dict):
        print(
            f"{script_name}: {context_map_path} is not a JSON object",
            file=sys.stderr,
        )
        return None

    checklist = load_json(understand_dir / "checklist.json") or {}
    target_path = (
        checklist.get("target_path") if isinstance(checklist, dict) else None
    )

    return context_map_path, context_map, target_path


# ---------------------------------------------------------------------------
# SMT verb helpers
# ---------------------------------------------------------------------------

def run_smt_verb(
    verb_fn: Callable[..., dict],
    verb_kwargs: dict[str, Any],
    *,
    script_name: str,
) -> int:
    """Call an SMT verb function, print JSON result, handle errors.

    Shared exit-code / output convention for all ``mantishack-smt-check-*``
    scripts:

    * On success: ``json.dump(result, stdout)`` and return ``0``.
    * On ``TypeError`` / ``ValueError``: print diagnostic to stderr and
      return ``2``.
    """
    try:
        result = verb_fn(**verb_kwargs)
    except (TypeError, ValueError) as e:
        print(f"{script_name}: {e}", file=sys.stderr)
        return 2

    json.dump(result, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0
