#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Run the vault's own ledger census in a child process, and print it as JSON on stdout.

WHY A CHILD PROCESS. The census code is the vault's ``scripts/docs/ledger_weekly_report.py`` and
its sibling ``backlog_status_check.py``, read from vault ``origin/main``, which merges with no
approval. ``collect_metrics.py`` therefore never imports it into the process that holds the ``gh``
session. It runs this driver with ``python -I`` and an allowlisted environment that carries no
token and no ``GIT_*`` variable, and reads back the JSON below; on a non-zero exit the tail of
its stderr goes into the error text, which the snapshot keeps. That environment is the
allowlist ``collect_metrics.py``'s docstring describes; it withholds variables and nothing more,
and it is no sandbox. The child runs with the full power of the same user: it can read and write any file that user can, a ``gh`` credential file among them,
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
import re
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


#: A row's priority, as its section marker line writes it: ``**Cluster:** X. **Priority:** P3.``
_PRIORITY = re.compile(r"\*\*Priority:\*\*\s*(P[0-9]+)\b")
#: A banner-block score, ``Value **6/10**``: a copy of the vault ``backlog_status_check._SCORE``,
#: so the FIRST banner-block line it matches is the line ``parse_items`` takes its score from.
_SCORE = re.compile(r"[Vv]alue\s*\**\s*(?P<value>\d+)\s*/\s*10", re.I)
#: The tier a scoring pass writes in that line's lead-in, before the score:
#: ``**Re-scored 2026-11-25 -> P2.** Value **6/10**``. Some rows write the arrow as U+2192.
_TIER = re.compile(r"(?:->|\u2192)\s*(P[0-9]+|DEMAND-GATE)\.")
#: The priority bucket of a row whose first score line carries no tier, and whose section marker
#: names no priority. Most are filing estimates; a tierless score with a Cluster priority is not here.
ESTIMATE = "scored, no tier"
#: The priority bucket of a row with no tier, no section-marker priority and no score.
UNSCORED = "unscored"


def row_status(checker: Any, item: Any, lines: Sequence[str]) -> str | None:
    """One status per row, the buckets disjoint: an open row is ``partial`` when its banner block
    holds a PARTIAL line, else ``in progress`` under an in-progress banner, else ``open``; a closed
    row is ``closed``, ``declined`` or ``superseded`` by its newest closed banner, as the weekly
    census reads it. ``None`` for a row with no status banner, which the census counts nowhere."""
    closing = {
        checker.SHIPPED_BANNER: "closed",
        checker.DECLINED_BANNER: "declined",
        checker.RETIRED_BANNER: "superseded",
    }
    if not item.is_open:
        newest = next((b for _, b in item.banner_lines if b in closing), None)
        return None if newest is None else closing[newest]
    block = lines[item.line : item.body_line - 1]
    if any(checker.PARTIAL_LINE.match(line) for line in block):
        return "partial"
    newest = next((b for _, b in item.banner_lines), None)
    return "in progress" if newest == checker.IN_PROGRESS_BANNER else "open"


def row_priority(item: Any, lines: Sequence[str]) -> str:
    """The row's priority bucket, read only from its OWN lines, never from one its prose quotes.

    First, the tier in the lead-in of the FIRST banner-block line holding a ``Value **N/10**``
    score, the line a scoring pass writes (it never rewrites the Cluster line); else the priority
    on the row's section marker line; else :data:`ESTIMATE` when that score line carries no tier;
    else :data:`UNSCORED`. A tier after the score is prose on that line, not the row's tier."""
    block = lines[item.line : item.body_line - 1]
    found = next(((ln, s) for ln in block if (s := _SCORE.search(ln)) is not None), None)
    if found is not None:
        line, score = found
        # The tier nearest the score is the one written with it; an earlier one on the same
        # line belongs to an older banner sharing it.
        tiers = list(_TIER.finditer(line, 0, score.start()))
        if tiers:
            return tiers[-1][1]
    for n in item.section_lines[:1]:
        m = _PRIORITY.search(lines[n - 1])
        if m:
            return m[1]
    return UNSCORED if found is None else ESTIMATE


def priority_census(checker: Any, sources: Sequence[tuple[str, str]]) -> dict[str, dict[str, int]]:
    """Rows per priority per status, over the same sources the weekly census reads."""
    out: dict[str, dict[str, int]] = {}
    for _label, text in sources:
        lines = text.splitlines()
        for item in checker.parse_items(text):
            status = row_status(checker, item, lines)
            if status is None:
                continue
            bucket = out.setdefault(row_priority(item, lines), {})
            bucket[status] = bucket.get(status, 0) + 1
    return out


def census_json(report: Any, root: Path, through: dt.date) -> dict[str, Any]:
    paths = [root / p for p in report.DEFAULT_SOURCES]
    sources = report.read_sources(paths, root, explicit=True)
    census, calls = clipped_census(report, sources, through)
    checker = _import(root, "backlog_status_check")
    return {
        "by_priority": priority_census(checker, sources),
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
