# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""No single web console test file may hold too large a share of the suite (BACKLOG #2509).

ci.yml runs this suite under ``--dist loadfile``, which puts a whole file on one worker. So the step
can never finish faster than its largest file. Before #2509 split it, ``test_webui.py`` held 370 of
the suite's 1061 collected tests at engine ``064700f2d``, and it set the step's wall time.

THE PROXY IS THE COLLECTED-TEST COUNT, NOT WALL TIME. Wall time varies by runner and by load, so a
guard on it would be flaky. The count comes from ``pytest --collect-only``, which runs no test body
and gives the same answer on every machine. It counts each parametrized case, because each case runs
the whole body. A plain function count misses that: one file of 3 functions collects 23 tests.

WHY 8 PERCENT. A count share is not a time share. Two local runs on 2026-10-17, junit times summed
per file, put the widest time-to-count ratio among files holding 2 percent or more of the tests at
about 2.6x (``test_webui_account.py``: 2.4 percent of the tests, 6.0 percent of the time). Allow 3x
for drift, and 8 percent of the tests could still be 24 percent of the time. That is just under one
worker's even share at the four workers the ci.yml matrix gave the step on that date. Past it, one
file could set the wall time again.

A count cannot see a file that is small in tests but slow. The step-margin gate in ci.yml reads the
step's time, and that gate is what catches it.

When this fails, split the named file by page or subject. Do not raise the bound to make it pass.
"""

from __future__ import annotations

import subprocess
import sys
from collections import Counter
from pathlib import Path

_TESTS = Path(__file__).resolve().parent
_MAX_SHARE = 0.08

#: Floors well under what the suite held when this landed (1064 tests in 58 files). They catch a
#: collection gone blind, such as a moved directory or a failed import, which would pass vacuously.
_MIN_TESTS = 700
_MIN_FILES = 20


def _per_file(nodeids: list[str]) -> Counter[str]:
    """Count collected test ids by the file they live in."""
    return Counter(nodeid.split("::", 1)[0] for nodeid in nodeids)


def _oversized(counts: Counter[str], max_share: float) -> list[str]:
    total = sum(counts.values())
    return [
        f"{name}: {n} of {total} collected tests ({n / total:.1%}, bound {max_share:.0%})"
        for name, n in counts.most_common()
        if n / total > max_share
    ]


def _collect() -> list[str]:
    # A child process, so this run's own selection (-k, a single file) cannot narrow what is counted.
    # -p no:xdist keeps the child from spawning workers; collection imports modules and runs nothing.
    out = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:xdist"]
        + ["-p", "no:cacheprovider", str(_TESTS)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
        timeout=180,
    )
    assert out.returncode == 0, f"collection failed ({out.returncode}):\n{out.stdout[-2000:]}"
    # Test ids start in column 0; the warnings summary that may follow is indented.
    return [line for line in out.stdout.splitlines() if "::" in line and not line[:1].isspace()]


def test_no_web_console_test_file_holds_too_large_a_share() -> None:
    counts = _per_file(_collect())
    total = sum(counts.values())
    assert len(counts) >= _MIN_FILES and total >= _MIN_TESTS, (
        f"collection saw {len(counts)} files and {total} tests under {_TESTS}; "
        "it has gone blind, so a pass would mean nothing"
    )
    over = _oversized(counts, _MAX_SHARE)
    assert not over, (
        "under --dist loadfile one file runs on one worker, so these files set the step's wall "
        "time; split each by page or subject (BACKLOG #2509):\n  " + "\n  ".join(over)
    )


def test_the_guard_flags_an_oversized_file() -> None:
    # Positive control: the guard must fire on the shape it exists for, one file of 370 tests beside
    # many small ones, as the suite stood before #2509 split test_webui.py.
    ids = [f"tests/test_webui.py::test_{i}" for i in range(370)]
    ids += [f"tests/test_small_{i}.py::test_{j}[case]" for i in range(48) for j in range(14)]
    assert _oversized(_per_file(ids), _MAX_SHARE) == [
        "tests/test_webui.py: 370 of 1042 collected tests (35.5%, bound 8%)"
    ]
