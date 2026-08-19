# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""``seat.ps1 -Prompt`` records that a seat was ASKED for a goal, and never invents one.

seat.ps1 has carried ``-Declare -Seat -Goal`` since it was written, and the mechanical half of the
episode record has always worked -- a Stop hook fires ``-Record`` and every episode carries writes,
touchedPaths, dirty, unpushed and tip. The declared half did not. Measured across the live seats
directory on 2026-08-18: **22 records, 1 with a goal, 1 with a seat, 22 reading lifecycle:open**.

So the fleet could answer "is this seat alive and writing" and could not answer "what is it trying
to do", which is the question a person actually asks. The schema was never the problem; nothing fed
it.

``-Prompt`` is the hook path. It cannot write a goal -- a goal is intent, and a machine that invents
one produces a record that looks declared and says nothing. What it does is make the silence
legible, because "no goal" previously covered two states with opposite fixes:

    never asked     -> the fleet has no declaration habit; fix the setup
    asked, ignored  -> this seat chose not to; fix the seat

The property under test throughout is that a DERIVED label can never be read as a DECLARED one. A
measurement and a statement of intent are different facts, and the moment one can wear the other's
clothes the record stops being evidence.
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
HOOK = ROOT / "scripts" / "hooks" / "seat-declare-prompt.ps1"
TIMEOUT = 90

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="seat.ps1 needs pwsh on Windows",
)


def git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=TIMEOUT, check=True
    )
    return proc.stdout


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A throwaway checkout carrying its OWN copy of the script under test.

    seat.ps1 anchors on where it LIVES, not on the cwd, so copying it in is what makes the sandbox
    structural rather than ambient -- the same lesson test_coord_claim_refresh.py records after two
    stray claims landed in the real registry.
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


def seat(cwd: Path, *args: str) -> subprocess.CompletedProcess[str]:
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
    )


def record(repo: Path) -> dict:
    common = git(repo, "rev-parse", "--path-format=absolute", "--git-common-dir").strip()
    found = sorted(Path(common).joinpath("mefor-coord", "seats").rglob("*.json"))
    assert found, "no episode record was written"
    return json.loads(found[-1].read_text(encoding="utf-8"))


class TestPromptRecordsTheQuestion:
    def test_prompt_stamps_when_no_goal_exists(self, repo: Path) -> None:
        seat(repo, "-Prompt", "-SessionId", "s1")
        assert record(repo)["goalPromptedAt"], "asking must leave a trace or it cannot be audited"

    def test_prompt_never_invents_a_goal(self, repo: Path) -> None:
        """The whole point. A goal a machine wrote is not a declaration of anything."""
        seat(repo, "-Prompt", "-SessionId", "s1")
        assert record(repo)["goal"] is None

    def test_prompt_is_silent(self, repo: Path) -> None:
        """It is a hook path like -Record; the session's context is not its to narrate."""
        proc = seat(repo, "-Prompt", "-SessionId", "s1")
        assert "wrote " not in proc.stdout

    def test_a_second_prompt_after_a_goal_does_not_restamp(self, repo: Path) -> None:
        """Once the question is answered, re-stamping turns a silence into noise."""
        seat(repo, "-Prompt", "-SessionId", "s1")
        first = record(repo)["goalPromptedAt"]
        seat(repo, "-Declare", "-Seat", "builder9", "-Goal", "a real goal", "-SessionId", "s1")
        seat(repo, "-Prompt", "-SessionId", "s1")
        assert record(repo)["goalPromptedAt"] == first


class TestDerivedIsNeverDeclared:
    """A measurement must not be readable as a statement of intent."""

    def test_a_derived_seat_is_marked_derived(self, repo: Path) -> None:
        seat(repo, "-Prompt", "-DerivedSeat", "tracker-board-f5", "-SessionId", "s1")
        rec = record(repo)
        assert rec["seat"] == "tracker-board-f5"
        assert rec["seatSource"] == "derived:caller"

    def test_a_derived_seat_leaves_declaredAt_null(self, repo: Path) -> None:
        """declaredAt answers 'did somebody SAY what this is for'. Deriving is not saying."""
        seat(repo, "-Prompt", "-DerivedSeat", "tracker-board-f5", "-SessionId", "s1")
        assert record(repo)["declaredAt"] is None

    def test_declaring_overwrites_a_derived_label(self, repo: Path) -> None:
        seat(repo, "-Prompt", "-DerivedSeat", "guessed", "-SessionId", "s1")
        seat(repo, "-Declare", "-Seat", "builder9", "-Goal", "g", "-SessionId", "s1")
        rec = record(repo)
        assert rec["seat"] == "builder9"
        assert rec["seatSource"] == "declared"
        assert rec["declaredAt"]

    def test_a_derived_label_never_overwrites_a_declaration(self, repo: Path) -> None:
        """The regression that would matter: a hook quietly relabelling a seat somebody named."""
        seat(repo, "-Declare", "-Seat", "builder9", "-Goal", "g", "-SessionId", "s1")
        seat(repo, "-Prompt", "-DerivedSeat", "SHOULD-NOT-WIN", "-SessionId", "s1")
        rec = record(repo)
        assert rec["seat"] == "builder9"
        assert rec["seatSource"] == "declared"
        assert rec["goal"] == "g"


class TestExistingPathsAreUnchanged:
    """-Prompt is additive. The two paths the fleet already depends on must not move."""

    def test_record_still_writes_a_record_and_says_nothing(self, repo: Path) -> None:
        proc = seat(repo, "-Record", "-SessionId", "s1")
        assert proc.returncode == 0
        assert record(repo)["lifecycle"] == "open"
        assert "wrote " not in proc.stdout

    def test_record_does_not_stamp_the_prompt_field(self, repo: Path) -> None:
        """Only asking counts as asking. A Stop hook is not a question."""
        seat(repo, "-Record", "-SessionId", "s1")
        assert record(repo).get("goalPromptedAt") is None

    def test_declare_still_sets_everything_it_did_before(self, repo: Path) -> None:
        seat(
            repo,
            "-Declare",
            "-Seat",
            "builder9",
            "-Goal",
            "g",
            "-Done",
            "d",
            "-OutOfScope",
            "o",
            "-SessionId",
            "s1",
        )
        rec = record(repo)
        assert (rec["seat"], rec["goal"], rec["done"], rec["outOfScope"]) == (
            "builder9",
            "g",
            "d",
            "o",
        )


class TestTheHookCannotBreakATurn:
    """It runs at SessionStart in every worktree of a repo with a live fleet in it."""

    def test_the_hook_exits_zero_with_no_payload(self, repo: Path) -> None:
        proc = subprocess.run(
            ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(HOOK)],
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            check=False,
            input="",
        )
        assert proc.returncode == 0

    def test_the_hook_exits_zero_on_malformed_payload(self, repo: Path) -> None:
        proc = subprocess.run(
            ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(HOOK)],
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            check=False,
            input="{not json at all",
        )
        assert proc.returncode == 0

    def test_the_hook_says_what_to_run(self, repo: Path) -> None:
        """A prompt nobody can act on is decoration."""
        proc = subprocess.run(
            ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(HOOK)],
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            check=False,
            input="",
        )
        assert "-Declare" in proc.stdout
        assert "-Goal" in proc.stdout
