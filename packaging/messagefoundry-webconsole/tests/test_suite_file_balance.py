# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""No single web console test file may hold too large a share of the suite (BACKLOG #2509).

ci.yml runs this suite under ``--dist loadfile``, which puts a whole file on one worker. So the step
can never finish faster than its largest file. ``test_webui.py`` held 342 of the 879 test functions
the suite had before #2509 split it and added this guard, and it set the step's wall time.

THE PROXY IS THE TEST-FUNCTION COUNT, NOT WALL TIME. Wall time varies by runner and by load, so a
guard on it would be flaky. The count is static: it reads the source and needs no run. A parametrized
test counts once, because its cases share a body and usually a cost.

WHY 10 PERCENT. A count share is not a time share. On one local run on 2026-10-17, junit times summed
per file, ``test_ui_mfa_gate.py`` held 5.0 percent of the functions and 12.4 percent of the time, the
widest ratio in the suite at about 2.5x. At that ratio a file at 10 percent of the functions could
hold a quarter of the time. That is one worker's whole even share at the four workers the ci.yml matrix
gave the step on that date. Past it, the file alone sets the wall time again.

A count cannot see a file that is small in functions but slow. The step-margin gate in ci.yml reads
the step's time, and that gate is what catches it.

When this fails, split the named file by page or subject. Do not raise the bound to make it pass.
"""

from __future__ import annotations

import ast
from pathlib import Path

_TESTS = Path(__file__).resolve().parent
_MAX_SHARE = 0.10

#: Floors well under what the suite held when this landed (881 functions in 58 files). They catch a
#: walk gone blind, such as a moved directory or a changed glob, which would otherwise pass vacuously.
_MIN_FUNCTIONS = 500
_MIN_FILES = 20


def _count_tests(source: str) -> int:
    """Count the test functions in one module, methods on a test class included."""
    return sum(
        1
        for node in ast.walk(ast.parse(source))
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test_")
    )


def _oversized(counts: dict[str, int], max_share: float) -> list[str]:
    total = sum(counts.values())
    return [
        f"{name}: {n} of {total} test functions ({n / total:.1%}, bound {max_share:.0%})"
        for name, n in sorted(counts.items(), key=lambda kv: -kv[1])
        if n / total > max_share
    ]


def _suite_counts() -> dict[str, int]:
    return {
        p.name: _count_tests(p.read_text(encoding="utf-8"))
        for p in sorted(_TESTS.glob("test_*.py"))
    }


def test_no_web_console_test_file_holds_too_large_a_share() -> None:
    counts = _suite_counts()
    total = sum(counts.values())
    assert len(counts) >= _MIN_FILES and total >= _MIN_FUNCTIONS, (
        f"the walk saw {len(counts)} files and {total} test functions under {_TESTS}; "
        "it has gone blind, so a pass would mean nothing"
    )
    over = _oversized(counts, _MAX_SHARE)
    assert not over, (
        "under --dist loadfile one file runs on one worker, so these files set the step's wall "
        "time; split each by page or subject (BACKLOG #2509):\n  " + "\n  ".join(over)
    )


def test_the_guard_flags_an_oversized_file() -> None:
    # Positive control: the guard must fire on the shape it exists for, one file of 342 functions
    # beside many small ones, as the suite stood before #2509 split test_webui.py.
    before = {"test_webui.py": 342} | {f"test_small_{i}.py": 11 for i in range(49)}
    assert _oversized(before, _MAX_SHARE) == [
        "test_webui.py: 342 of 881 test functions (38.8%, bound 10%)"
    ]
    assert _count_tests("def test_a(): ...\nclass TestB:\n    async def test_c(self): ...\n") == 2
