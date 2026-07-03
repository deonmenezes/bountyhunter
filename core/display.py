"""Shared display / formatting helpers for MANTISHACK CLI output.

Centralises the ``"=" * 70`` phase-header pattern that was previously
duplicated across dozens of files (mantishack_agentic.py,
mantishack_codeql.py, mantishack_fuzzing.py, packages/web/scanner.py,
packages/llm_analysis/agent.py, packages/fuzzing/afl_runner.py, …).
"""

from __future__ import annotations

import logging
from typing import Optional

SECTION_WIDTH = 70


def print_phase_header(title: str, *, width: int = SECTION_WIDTH) -> None:
    """Print a visual section header to stdout.

    ::

        ======================================================================
        PHASE 1: SCANNING
        ======================================================================
    """
    sep = "=" * width
    print(f"\n{sep}")
    print(title)
    print(sep)


def log_phase_header(
    title: str,
    *,
    logger: Optional[logging.Logger] = None,
    width: int = SECTION_WIDTH,
) -> None:
    """Emit a visual section header via ``logger.info``.

    Falls back to the root logger when *logger* is ``None``.
    """
    if logger is None:
        logger = logging.getLogger()
    sep = "=" * width
    logger.info(sep)
    logger.info(title)
    logger.info(sep)
