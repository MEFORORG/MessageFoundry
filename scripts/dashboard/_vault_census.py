#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Run the vault's own ledger census in a child process, and print it as JSON on stdout.

WHY A CHILD PROCESS. The census code is the vault's ``scripts/docs/ledger_weekly_report.py`` and
its sibling ``backlog_status_check.py``, read from vault ``origin/main``, which merges with no
approval. ``collect_metrics.py`` therefore never imports it into the process that holds the ``gh``
session. It runs this driver with ``python -I`` and an allowlisted environment that carries no
token and no ``GIT_*`` variable, and reads back only the JSON below. That environment is the
allowlist ``collect_metrics.py``'s docstring describes; it withholds variables and nothing more,
and it is no sandbox. The child runs with the full power of
the same user: it can read and write any file that user can, a ``gh`` credential file among them,
and so alter the engine files run after it. ``collect_metrics.py``'s docstring states the trust
this takes.

Two modes, both reading an archive root the parent extracted:

``globs ROOT``
    ``{"ledger_file_globs": [...]}``: the checker's ``LEDGER_FILE_GLOBS``, so the parent knows
    which ledger files to archive.
``census ROOT THROUGH``
    The census, with every date after ``THROUGH`` counted under ``after-through`` (the census
    buckets by ISO week alone, so the final week would otherwise run past ``THROUGH``), plus the
    vault vocabulary the parent checks its keys against.
"""

from __future__ import annotations

import datetime as dt
import importlib
import json
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from types import ModuleType
from typing import Any

AFTER_THROUGH = "after-through"


def _import(root: Path, name: str) -> ModuleType:
    # The vault modules import each other by bare name, so their directory goes on the path.
    sys.path.insert(0, str(root / "scripts" / "docs"))
    return importlib.import_module(name)


def clipped_census(report: Any, sources: Any, through: dt.date) -> tuple[Any, int]:
    """``report.census(sources)`` with dates after ``through`` under :data:`AFTER_THROUGH`.

    ``Census.count`` resolves the module-level ``iso_week`` at call time, so it is wrapped for the
    one call. Returns the census and how often the wrapper ran; a census that dated rows without
    calling it has stopped dating through it, and the caller refuses that.
    """
    original: Callable[[str | None], str | None] | None = getattr(report, "iso_week", None)
    if not callable(original):
        raise ValueError("the vault census has no iso_week to clip at --through")
    calls = 0

    def clipped(date: str | None) -> str | None:
        nonlocal calls
        calls += 1
        week = original(date)
        if week is not None and date is not None and dt.date.fromisoformat(date) > through:
            return AFTER_THROUGH
        return week

    report.iso_week = clipped
    try:
        census = report.census(sources)
    finally:
        report.iso_week = original
    return census, calls


def census_json(report: Any, root: Path, through: dt.date) -> dict[str, Any]:
    paths = [root / p for p in report.DEFAULT_SOURCES]
    sources = report.read_sources(paths, root, explicit=True)
    census, calls = clipped_census(report, sources, through)
    return {
        "rows": int(census.rows),
        "per_source": [[str(label), int(n)] for label, n in census.per_source],
        "weeks": {str(w): {str(k): int(v) for k, v in c.items()} for w, c in census.weeks.items()},
        "undated": {str(k): int(v) for k, v in census.undated.items()},
        "open_by_verdict": {str(k): int(v) for k, v in census.open_by_verdict.items()},
        "active_verdicts": [str(v) for v in report.ACTIVE_VERDICTS],
        "deferred_verdict": str(report.DEFERRED_VERDICT),
        "activity": [str(c) for c in report.ACTIVITY],
        "min_total_items": int(report.MIN_TOTAL_ITEMS),
        "structural_errors": [
            str(e) for e in report.default_corpus_errors(root, census.per_source)
        ],
        "clip_calls": calls,
    }


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) == 2 and args[0] == "globs":
        checker = _import(Path(args[1]), "backlog_status_check")
        out: dict[str, Any] = {"ledger_file_globs": [str(g) for g in checker.LEDGER_FILE_GLOBS]}
    elif len(args) == 3 and args[0] == "census":
        root = Path(args[1])
        report = _import(root, "ledger_weekly_report")
        out = census_json(report, root, dt.date.fromisoformat(args[2]))
    else:
        print("usage: _vault_census.py globs ROOT | census ROOT YYYY-MM-DD", file=sys.stderr)
        return 2
    sys.stdout.write(json.dumps(out))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
