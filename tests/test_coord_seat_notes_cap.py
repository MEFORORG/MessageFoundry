# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``seat.ps1 -Declare -Notes`` caps the COLLAPSED notes at 2000 characters (BACKLOG #5764).

The cap took ``Substring(0, Min(2000, $Notes.Length))`` of the whitespace-collapsed string, so a
value under 2000 characters with a run of whitespace asked for more characters than the collapsed
string held, the Substring threw, and the declaration was not written.
"""

from __future__ import annotations

from pathlib import Path

from tests.test_coord_seat_prompt import pytestmark, record, repo, seat

__all__ = ["pytestmark", "repo"]  # the skip mark and the fixture, re-exported for collection


def _declare(repo: Path, notes: str) -> dict:
    proc = seat(
        repo, "-Declare", "-Seat", "builder9", "-Goal", "g", "-SessionId", "s1", "-Notes", notes
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return record(repo)


def test_short_notes_with_a_whitespace_run_are_collapsed_and_written(repo: Path) -> None:
    assert _declare(repo, "a    b\t\tc")["notes"] == "a b c"


def test_long_notes_are_capped_at_2000_after_collapsing(repo: Path) -> None:
    # 3001 characters collapse to 2001 ("a " * 1000 + "b"), so the cap still bites, at 2000.
    notes = "a  " * 1000 + "b"
    got = _declare(repo, notes)["notes"]
    assert len(got) == 2000
    assert got == ("a " * 1000)[:2000]
