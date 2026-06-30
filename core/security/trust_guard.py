"""Shared trust-marker guard for libexec dispatch scripts.

Every ``libexec/`` script must refuse to run unless one of the
recognised trust environment variables is set (``CLAUDECODE`` or
``_MANTISHACK_TRUSTED``).  Previously this check was copy-pasted as
an ~8-line inline block in each script.  This module centralises the
logic so every script calls one function instead.

The guard deliberately avoids importing heavyweight framework modules
— it runs at script top-level before ``sys.path`` is configured, so
only stdlib is available.

Usage (at the top of a libexec script, after ``import sys``)::

    from core.security.trust_guard import require_trusted_caller
    require_trusted_caller()
"""

import os
import sys


def require_trusted_caller(
    *,
    run_hint: str = "Run via 'bin/mantishack' instead.",
    exit_code: int = 2,
) -> None:
    """Exit immediately if the process is not running in a trusted context.

    Trusted means one of ``CLAUDECODE`` or ``_MANTISHACK_TRUSTED`` is
    set in the environment.  ``MANTISHACK_DIR`` alone is intentionally
    NOT sufficient (see ``packages/sca/tests/test_mantishack_sca_run.py``
    for the rationale).

    Parameters
    ----------
    run_hint:
        Instruction printed on the second line when the check fails
        (e.g. ``"Run 'bin/mantishack-sca <args>' instead."``).
    exit_code:
        Status code to exit with on failure (default ``2``).
    """
    if os.environ.get("CLAUDECODE") or os.environ.get("_MANTISHACK_TRUSTED"):
        return
    script_name = sys.argv[0] if sys.argv else "<unknown>"
    sys.stderr.write(
        f"{script_name}: internal dispatch script.\n"
        f"  {run_hint}\n"
        "  Tests / power users: set _MANTISHACK_TRUSTED=1 to bypass.\n"
    )
    sys.exit(exit_code)
