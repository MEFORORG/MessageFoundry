# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""A seat must be able to tell that the script it is coordinating with is out of date.

WHY THIS EXISTS. Measured 2026-08-22 across the live seats directory: 19 records were keyed to the
literal ``nosid`` rather than to a session. Every one carried a ``goal``, so each looked like a
declaration and belonged to nobody.

Every one of the 19 was written by a worktree running a ``seat.ps1`` that predated the fix for
exactly that defect. Each record carries the ``tip`` it was written at, and grepped at that tip all
19 have **zero** occurrences of the environment fallback, against **four** on ``origin/main``.
Eighteen of the 19 also recorded ``dirty.count == 0``, which is what joins the committed blob to
the file that actually ran. Not one was a logic error.

**The code was correct and was not reaching the seats running it**, and nothing anywhere reported
that. Three sessions spent an evening inventing a second cause before someone graded the tree at
the record's timestamp instead of at the moment they looked.

WHAT NO OTHER TEST CAN COVER, AND WHY THIS MODULE EXISTS SEPARATELY. ``test_coord_seat_session_key``
already runs the banner invocation directly -- ``-Declare`` with no ``-SessionId`` and the
environment set -- with a negative control beside it. It was green throughout, and correctly so.
Staleness is invisible to it by construction: a test of ``seat.ps1`` always runs the checkout's own
copy, so no assertion about behaviour can distinguish a current writer from an ancient one. The
property has to be tested against a *declared* reference, which is what the sandboxes below build.

THE PROPERTY: the script reports its own currency, and never acts on it. A coordination script that
refused to write because it was out of date would convert a reporting gap into an outage, and the
seat that most needs its record written is the one whose checkout nobody has touched. Every test
that asserts a warning also asserts the record was written anyway.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SEAT = ROOT / "scripts" / "coord" / "seat.ps1"
MAILKEY = ROOT / "scripts" / "coord" / "mail-key.ps1"
TIMEOUT = 90

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="seat.ps1 needs pwsh on Windows",
)


def git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=True,
    )
    return proc.stdout


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A throwaway checkout carrying its OWN copy of the script under test.

    seat.ps1 anchors on where it LIVES, so copying it in is what keeps a stray record out of the
    real registry -- and it is also what lets these tests hold the running file and the declared
    reference apart, which is the whole subject here.
    """
    r = tmp_path / "repo"
    (r / "scripts" / "coord").mkdir(parents=True)
    subprocess.run(["git", "init", "-q", "-b", "main", str(r)], check=True, capture_output=True)
    git(r, "config", "user.email", "t@example.invalid")
    git(r, "config", "user.name", "t")
    shutil.copy2(SEAT, r / "scripts" / "coord" / "seat.ps1")
    shutil.copy2(MAILKEY, r / "scripts" / "coord" / "mail-key.ps1")
    (r / "f.txt").write_text("x", encoding="utf-8")
    git(r, "add", "-A")
    git(r, "commit", "-qm", "base")
    return r


def set_origin_main(repo: Path, sha: str) -> None:
    """Point refs/remotes/origin/main at a commit, with no remote and no network.

    seat.ps1 reads whatever origin/main this checkout already knows and never fetches, so a plain
    ref write is the same input it would see in the field.
    """
    git(repo, "update-ref", "refs/remotes/origin/main", sha)


def make_origin_main_differ(repo: Path) -> str:
    """Give origin/main a DIFFERENT seat.ps1 than the working tree, and return to the old one.

    Leaves the working tree and HEAD on the original script, so the running file equals HEAD's blob
    and differs from origin/main's -- which is exactly a worktree that has not pulled.
    """
    head_before = git(repo, "rev-parse", "HEAD").strip()
    seat = repo / "scripts" / "coord" / "seat.ps1"
    original = seat.read_text(encoding="utf-8")
    seat.write_text(original + "\n# a later change, on origin/main only\n", encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "newer seat.ps1")
    newer = git(repo, "rev-parse", "HEAD").strip()
    set_origin_main(repo, newer)
    # Put HEAD and the working tree back on the older script.
    git(repo, "reset", "-q", "--hard", head_before)
    return newer


def seat(
    cwd: Path, *args: str, session_env: str | None = "sess-abc"
) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env.pop("CLAUDE_CODE_SESSION_ID", None)
    if session_env is not None:
        env["CLAUDE_CODE_SESSION_ID"] = session_env
    return subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(cwd / "scripts" / "coord" / "seat.ps1"),
            *args,
        ],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
        env=env,
    )


def records(repo: Path) -> dict[str, dict[str, object]]:
    common = git(repo, "rev-parse", "--path-format=absolute", "--git-common-dir").strip()
    found = sorted(Path(common).joinpath("mefor-coord", "seats").rglob("*.json"))
    return {p.stem: json.loads(p.read_text(encoding="utf-8")) for p in found}


def currency(repo: Path) -> dict[str, object]:
    rec = records(repo)["sess-abc"]
    ws = rec["writerScript"]
    assert isinstance(ws, dict)
    return ws


class TestTheFourStates:
    def test_a_script_matching_origin_main_reports_current(self, repo: Path) -> None:
        """The baseline. Without it, every other assertion here is consistent with a stuck field."""
        set_origin_main(repo, git(repo, "rev-parse", "HEAD").strip())
        seat(repo, "-Declare", "-Seat", "s", "-Goal", "g")
        assert currency(repo)["state"] == "current"

    def test_an_older_script_reports_out_of_date(self, repo: Path) -> None:
        """The defect, stated directly: this is the shape all 19 nosid records were written in."""
        make_origin_main_differ(repo)
        seat(repo, "-Declare", "-Seat", "s", "-Goal", "g")
        assert currency(repo)["state"] == "out-of-date"

    def test_a_working_tree_edit_reports_modified_not_out_of_date(self, repo: Path) -> None:
        """Somebody editing seat.ps1 and somebody who never pulled want OPPOSITE responses.

        Collapsing them would tell a maintainer mid-edit to go and pull, every single write.
        """
        set_origin_main(repo, git(repo, "rev-parse", "HEAD").strip())
        target = repo / "scripts" / "coord" / "seat.ps1"
        target.write_text(target.read_text(encoding="utf-8") + "\n# local edit\n", encoding="utf-8")
        seat(repo, "-Declare", "-Seat", "s", "-Goal", "g")
        assert currency(repo)["state"] == "modified"

    def test_no_origin_main_reports_unknown_rather_than_current(self, repo: Path) -> None:
        """The honesty control, and it is the one that matters most.

        A sandbox or a fresh clone has no origin/main. Defaulting that to 'current' would
        manufacture agreement with a reference that is not there -- a false clean bill, which is
        the dangerous direction. Reporting 'unknown' says only what is known.
        """
        seat(repo, "-Declare", "-Seat", "s", "-Goal", "g")
        ws = currency(repo)
        assert ws["state"] == "unknown"
        assert ws["reason"]


class TestItReportsAndNeverRefuses:
    """The scope the owner set: surface it, do not gate on it."""

    def test_an_out_of_date_writer_still_writes_the_record(self, repo: Path) -> None:
        make_origin_main_differ(repo)
        seat(repo, "-Declare", "-Seat", "lander", "-Goal", "g")
        rec = records(repo)["sess-abc"]
        assert rec["seat"] == "lander"
        assert rec["goal"] == "g"

    def test_an_out_of_date_writer_still_exits_zero(self, repo: Path) -> None:
        """Rule 2 of this script: nothing may take a seat's Stop hook down with it."""
        make_origin_main_differ(repo)
        assert seat(repo, "-Declare", "-Seat", "s", "-Goal", "g").returncode == 0

    def test_the_cli_is_warned_in_words_a_reader_can_grep(self, repo: Path) -> None:
        make_origin_main_differ(repo)
        out = seat(repo, "-Declare", "-Seat", "s", "-Goal", "g").stdout
        assert "OUT-OF-DATE" in out
        assert "REPORTED, not enforced" in out

    def test_a_current_writer_is_not_warned(self, repo: Path) -> None:
        """The negative control for the message. A warning that always fires reports nothing."""
        set_origin_main(repo, git(repo, "rev-parse", "HEAD").strip())
        out = seat(repo, "-Declare", "-Seat", "s", "-Goal", "g").stdout
        assert "OUT-OF-DATE" not in out

    def test_the_hook_path_stays_silent(self, repo: Path) -> None:
        """-Record runs every turn and must never narrate into a session's context.

        The field is still recorded; only the narration is suppressed. That split is the point --
        the seat least likely to declare is the one whose checkout nobody has touched, so measuring
        only on the CLI path would leave the worst cases unmeasured.
        """
        make_origin_main_differ(repo)
        out = seat(repo, "-Record", "-SessionId", "sess-abc").stdout
        assert "OUT-OF-DATE" not in out
        assert currency(repo)["state"] == "out-of-date"


class TestTheVerdictCarriesItsReferencePoint:
    def test_it_records_the_ref_the_comparison_was_taken_against(self, repo: Path) -> None:
        """No verdict here is a fact without the ref beside it.

        This whole episode was built out of measurements published without the instant they were
        taken at. origin/main is never fetched by this script, so it may itself be old, and a bare
        'out-of-date' would hide that. The sha lets a reader grade the grader.
        """
        newer = make_origin_main_differ(repo)
        seat(repo, "-Declare", "-Seat", "s", "-Goal", "g")
        ws = currency(repo)
        assert ws["comparedTo"] == "origin/main"
        assert ws["comparedToSha"] == newer
        assert ws["runningSha"] != ws["mainSha"]

    def test_the_running_sha_is_the_file_that_actually_ran(self, repo: Path) -> None:
        """Not HEAD's blob -- the bytes on disk. A dirty worktree runs the file, not the commit."""
        set_origin_main(repo, git(repo, "rev-parse", "HEAD").strip())
        target = repo / "scripts" / "coord" / "seat.ps1"
        target.write_text(target.read_text(encoding="utf-8") + "\n# local edit\n", encoding="utf-8")
        seat(repo, "-Declare", "-Seat", "s", "-Goal", "g")
        on_disk = git(repo, "hash-object", str(target)).strip()
        assert currency(repo)["runningSha"] == on_disk


class TestABranchThatIsAheadIsNotCalledBehind:
    """The check got this wrong about ITSELF, on its own first run.

    This worktree was 8 commits AHEAD of origin/main, carrying the very change being described,
    and the check reported OUT-OF-DATE and told it to run ``merge --ff-only origin/main`` -- not a
    remedy for a branch that is ahead. With the stale population measured at zero the same evening,
    a false OUT-OF-DATE was the only thing this check had left to say to anyone.
    """

    def test_a_branch_containing_main_reports_ahead(self, repo: Path) -> None:
        set_origin_main(repo, git(repo, "rev-parse", "HEAD").strip())
        target = repo / "scripts" / "coord" / "seat.ps1"
        target.write_text(
            target.read_text(encoding="utf-8") + "\n# my own work\n", encoding="utf-8"
        )
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "my own change to seat.ps1")
        seat(repo, "-Declare", "-Seat", "s", "-Goal", "g")
        assert currency(repo)["state"] == "ahead"

    def test_ahead_is_not_warned_about(self, repo: Path) -> None:
        """Silent alongside 'current'. A warning on the ordinary case teaches readers to skip it."""
        set_origin_main(repo, git(repo, "rev-parse", "HEAD").strip())
        target = repo / "scripts" / "coord" / "seat.ps1"
        target.write_text(
            target.read_text(encoding="utf-8") + "\n# my own work\n", encoding="utf-8"
        )
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "my own change to seat.ps1")
        out = seat(repo, "-Declare", "-Seat", "s", "-Goal", "g").stdout
        assert "OUT-OF-DATE" not in out
        assert "merge --ff-only" not in out

    def test_a_branch_NOT_containing_main_still_reports_out_of_date(self, repo: Path) -> None:
        """THE CONTROL. Without it, 'ahead' could swallow the real defect the check exists for."""
        make_origin_main_differ(repo)
        seat(repo, "-Declare", "-Seat", "s", "-Goal", "g")
        assert currency(repo)["state"] == "out-of-date"
