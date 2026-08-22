# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The roster must answer "who holds this worktree", which it cannot do at one row per record.

MEASURED 2026-08-22 against the live seats directory: ``fleet.ps1 -Text`` rendered **279 rows for
46 boxes** over 73 worktrees. One box, ``messagefoundry-096b5d29``, occupied **104 of them** -- one
row saying ``builder1 CLOSED``, one saying ``maintenance``, and about a hundred reading
``NOT-DECLARED``. The receipt printed ``NO STOP CONDITIONS`` while doing it, because nothing was
failing. Every row was a valid record.

**The classification was never the problem.** ``SUPERSEDED`` has been computed correctly since it
was written -- 102 of that box's 104 records carried it. It simply was not used to fold anything,
so the roster showed a worktree's entire history every time somebody asked who was in it.

TWO DEFECTS FOUND WHILE FIXING THAT, both the same shape as the bug this whole evening was about:
an instrument whose resolution or subject does not match the question it is asked.

1. **The supersede test compared a DISPLAY value.** ``Get-AgeHours`` rounds to one decimal, which
   is a 6-minute bucket, and the comparison used it. Two records inside one bucket tied, no strict
   ``-lt`` could order them, and both survived. Measured in that same box: ``21:17:32Z`` and
   ``21:16:52Z``, forty seconds apart, both rounding to ``0.1``, both rendered. Ordering now runs
   on the exact age; display still rounds.

2. **Folding on the STATE LABEL missed the records that most needed folding.** The state switch
   tests lifecycle first, so a ``CLOSED`` record is never *labelled* ``SUPERSEDED`` even when a
   newer record exists. Four boxes rendered two rows each for that reason -- and every one of the
   four was an orphan a seat had *just closed on purpose* to tidy the roster. Folding keys on the
   superseded fact now; the labels are untouched, because "somebody closed this" and "a newer
   episode exists" are different things a reader wants.

FOLDED, NEVER DROPPED. A superseded record is evidence. A seat is deliberately holding a ``nosid``
record tonight because it evidences a defect, and a roster that silently discarded superseded rows
would erase exactly that class of proof. The count is always printed, ``-History`` always brings
them back, and ``-Json`` never filtered at all.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
COORD = ROOT / "scripts" / "coord"
TIMEOUT = 120

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="seat.ps1 and fleet.ps1 need pwsh on Windows",
)


def git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=TIMEOUT, check=True
    )
    return proc.stdout


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A throwaway checkout carrying its OWN copies of the scripts under test.

    Both scripts anchor on where they LIVE, so copying them in is what keeps a stray record out of
    the real registry.
    """
    r = tmp_path / "repo"
    (r / "scripts" / "coord").mkdir(parents=True)
    subprocess.run(["git", "init", "-q", "-b", "main", str(r)], check=True, capture_output=True)
    git(r, "config", "user.email", "t@example.invalid")
    git(r, "config", "user.name", "t")
    for name in ("seat.ps1", "fleet.ps1", "mail-key.ps1", "session-registry.ps1"):
        shutil.copy2(COORD / name, r / "scripts" / "coord" / name)
    (r / "f.txt").write_text("x", encoding="utf-8")
    git(r, "add", "-A")
    git(r, "commit", "-qm", "base")
    return r


def seat(repo: Path, *args: str, session: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["CLAUDE_CODE_SESSION_ID"] = session
    return subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(repo / "scripts" / "coord" / "seat.ps1"),
            *args,
        ],
        cwd=str(repo),
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
        env=env,
    )


def fleet(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(repo / "scripts" / "coord" / "fleet.ps1"),
            *args,
        ],
        cwd=str(repo),
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )
    return proc.stdout


def roster_rows(text: str) -> list[str]:
    """The rendered table only -- everything below the BOX header, receipt and footers excluded."""
    lines = text.splitlines()
    start = next((i for i, ln in enumerate(lines) if ln.startswith("BOX ")), None)
    if start is None:
        return []
    out = []
    for ln in lines[start + 1 :]:
        if not ln.strip():
            break
        out.append(ln)
    return out


def three_episodes(repo: Path) -> None:
    """Three sessions in ONE worktree, which is the ordinary life of a long-lived box.

    Consecutive runs land seconds apart, well inside the 6-minute bucket the old comparison
    rounded to -- so this fixture also reproduces defect 1 above without having to fake a clock.
    """
    seat(repo, "-Declare", "-Seat", "first", "-Goal", "g1", session="sess-1")
    seat(repo, "-Declare", "-Seat", "second", "-Goal", "g2", session="sess-2")
    seat(repo, "-Declare", "-Seat", "third", "-Goal", "g3", session="sess-3")


class TestOneRowPerWorktree:
    def test_three_episodes_in_one_box_render_one_row(self, repo: Path) -> None:
        """The defect, stated directly: 104 records in one worktree produced 104 roster lines."""
        three_episodes(repo)
        assert len(roster_rows(fleet(repo, "-Text"))) == 1

    def test_the_row_kept_is_the_newest_episode(self, repo: Path) -> None:
        """Folding to the WRONG survivor would be worse than not folding.

        A reader would get one confident line naming a seat that finished hours ago.
        """
        three_episodes(repo)
        rows = roster_rows(fleet(repo, "-Text"))
        assert "third" in rows[0], rows

    def test_records_seconds_apart_do_not_both_survive(self, repo: Path) -> None:
        """The precision regression, named so it cannot be optimised away.

        Ordering on the ROUNDED age let two records in one 6-minute bucket tie, and a tie means
        neither supersedes the other, so both rendered.
        """
        seat(repo, "-Declare", "-Seat", "a", "-Goal", "g", session="sess-a")
        seat(repo, "-Declare", "-Seat", "b", "-Goal", "g", session="sess-b")
        assert len(roster_rows(fleet(repo, "-Text"))) == 1


class TestTheFoldIsVisibleAndReversible:
    def test_history_restores_every_record(self, repo: Path) -> None:
        three_episodes(repo)
        assert len(roster_rows(fleet(repo, "-Text", "-History"))) == 3

    def test_all_also_restores_them(self, repo: Path) -> None:
        """-All reads as "show me everything" and would be a trap if it did not include these."""
        three_episodes(repo)
        assert len(roster_rows(fleet(repo, "-Text", "-All"))) == 3

    def test_the_fold_is_counted_rather_than_silent(self, repo: Path) -> None:
        """A missing row a reader cannot account for is worse than a long roster."""
        three_episodes(repo)
        out = fleet(repo, "-Text")
        assert "2 row(s) folded as SUPERSEDED" in out
        assert "-History" in out

    def test_nothing_is_reported_folded_when_nothing_was(self, repo: Path) -> None:
        """The negative control. A footer that always prints reports nothing."""
        seat(repo, "-Declare", "-Seat", "only", "-Goal", "g", session="sess-only")
        assert "folded as SUPERSEDED" not in fleet(repo, "-Text")

    def test_json_still_emits_every_row(self, repo: Path) -> None:
        """A machine consumer must not inherit a fold chosen to fit a human's screen."""
        three_episodes(repo)
        payload = json.loads(fleet(repo, "-Json"))
        assert len(payload["rows"]) == 3


class TestClosedRecords:
    def test_a_closed_record_with_a_newer_sibling_is_folded(self, repo: Path) -> None:
        """The case that kept four boxes at two rows, every one a just-tidied orphan.

        A CLOSED record is never LABELLED superseded -- lifecycle wins the state switch -- so a
        fold keyed on the label leaves exactly the rows a remediating seat tried to retire.
        """
        # Session keys sort in WRITE order on purpose. asOf is stamped to the second, so two runs
        # can land in one second and tie; the tie is broken on the file name, and naming these out
        # of order would make the test assert the tiebreak rather than the fold. Measured: it
        # passed alone and failed under load before the names were ordered.
        seat(repo, "-Declare", "-Seat", "old", "-Goal", "g", session="sess-a-old")
        seat(repo, "-Close", session="sess-a-old")
        seat(repo, "-Declare", "-Seat", "new", "-Goal", "g", session="sess-b-new")
        rows = roster_rows(fleet(repo, "-Text"))
        assert len(rows) == 1
        assert "new" in rows[0], rows

    def test_a_closed_record_with_no_newer_sibling_still_shows(self, repo: Path) -> None:
        """THE CONTROL, and it could not be run against the live directory.

        Every CLOSED record on disk that evening happened to be a superseded orphan, so the live
        check was vacuous -- it proved only that no such row existed to hide. A seat that closed
        cleanly and left nothing after it must still appear, or the roster would drop the one
        record that says the worktree was handed back deliberately.
        """
        seat(repo, "-Declare", "-Seat", "only", "-Goal", "g", session="sess-only")
        seat(repo, "-Close", session="sess-only")
        rows = roster_rows(fleet(repo, "-Text"))
        assert len(rows) == 1
        assert "CLOSED" in rows[0], rows


class TestTheRosterSurfacesTheWritersCurrency:
    """Recording the fact in seat.ps1 surfaces nothing until the roster shows it."""

    def test_an_out_of_date_writer_is_marked_on_its_row(self, repo: Path) -> None:
        head = git(repo, "rev-parse", "HEAD").strip()
        target = repo / "scripts" / "coord" / "seat.ps1"
        target.write_text(
            target.read_text(encoding="utf-8") + "\n# newer, on origin/main only\n",
            encoding="utf-8",
        )
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "newer seat.ps1")
        git(repo, "update-ref", "refs/remotes/origin/main", git(repo, "rev-parse", "HEAD").strip())
        git(repo, "reset", "-q", "--hard", head)
        seat(repo, "-Declare", "-Seat", "s", "-Goal", "g", session="sess-old-script")
        assert "[SCRIPT-OUT-OF-DATE]" in fleet(repo, "-Text")

    def test_a_current_writer_is_not_marked(self, repo: Path) -> None:
        """The negative control. A mark that always prints is not a signal."""
        git(repo, "update-ref", "refs/remotes/origin/main", git(repo, "rev-parse", "HEAD").strip())
        seat(repo, "-Declare", "-Seat", "s", "-Goal", "g", session="sess-current")
        assert "[SCRIPT-OUT-OF-DATE]" not in fleet(repo, "-Text")

    def test_it_is_not_confused_with_the_record_age_marker(self, repo: Path) -> None:
        """WRITER-STALE means the RECORD is old; this means the SCRIPT is. Different objects."""
        text = (COORD / "fleet.ps1").read_text(encoding="utf-8")
        assert "[WRITER-STALE]" in text and "[SCRIPT-OUT-OF-DATE]" in text
