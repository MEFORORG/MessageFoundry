# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Two staleness signals that are really one, and the third that is not.

Readers across this repo treat ``seats/.writer-alive/<box>.txt`` and the seat record's ``asOf`` as
independent corroboration. They are one signal read twice: ``seat.ps1`` writes both inside a single
``-Record``, the heartbeat at its rule 3 touch and ``asOf`` in the record body.

Measured 2026-08-22 across every box on disk: **the two agree to the second in 42 of 42.**

That is not a curiosity. ``seat.ps1``'s own rule 3 records why the heartbeat exists at all -- hooks
are disabled silently by ``disableAllHooks``, by org policy and by workspace trust, and all three
produce exactly the observable of a quiet, healthy fleet. When the writer is not running, both
signals go stale together and a sweep reading them concludes the seat is dead while somebody is
still typing in it.

So ``box-activity.ps1`` adds a signal ``seat.ps1`` does not write: the newest transcript under
``<config-root>/projects/<slug>/``, which Claude Code writes every turn. Measured the same day,
``messagefoundry-096b5d29`` had a transcript 31.50h old against a ``.writer-alive`` 0.14h old -- the
two disagreeing by 31.4 hours, on a real box, on the day this was written.

**Every veto test here is a PAIR.** Asserting only that a fresh transcript vetoes would pass against
a function that always vetoes, which is the safest possible wrong answer and the one that would make
the whole mechanism useless without failing anything. The second half of each pair back-dates the
signal and asserts the veto lifts.
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
LIB = ("box-activity.ps1", "session-registry.ps1", "occupancy.ps1", "mail-key.ps1")
TIMEOUT = 120

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="box-activity.ps1 needs pwsh on Windows",
)


@pytest.fixture
def sandbox(tmp_path: Path) -> Path:
    """Scripts, a seats dir, a config root and a git worktree -- none of them the real ones.

    test_coord_seat_prompt.py records why this matters: two stray claims once landed in the live
    registry because a test ran against the live tree.
    """
    box = tmp_path / "scripts" / "coord"
    box.mkdir(parents=True)
    for name in LIB:
        shutil.copy2(COORD / name, box / name)
    (tmp_path / "seats" / ".writer-alive").mkdir(parents=True)
    wt = tmp_path / "wt"
    wt.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(wt)], check=True, capture_output=True)
    return tmp_path


def activity(sandbox: Path, **over: object) -> dict:
    """Call Get-BoxActivity and read back its object as JSON."""
    args = {
        "BoxKey": "demo-box-0000",
        "WorktreePath": str(sandbox / "wt"),
        "SeatsDir": str(sandbox / "seats"),
        "ConfigRoot": str(sandbox / "root"),
        "RepoHint": str(sandbox / "wt"),
    }
    args.update({k: str(v) for k, v in over.items()})
    ps = (
        f". '{sandbox / 'scripts' / 'coord' / 'box-activity.ps1'}'; "
        + "Get-BoxActivity "
        + " ".join(f"-{k} '{v}'" for k, v in args.items())
        + " | ConvertTo-Json -Depth 5"
    )
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", ps],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )
    assert proc.returncode == 0, f"rc={proc.returncode}\n{proc.stdout}\n{proc.stderr}"
    return json.loads(proc.stdout)


def write_heartbeat(sandbox: Path, age_hours: float, box: str = "demo-box-0000") -> None:
    f = sandbox / "seats" / ".writer-alive" / f"{box}.txt"
    f.write_text("stamp", encoding="utf-8")
    _back_date(f, age_hours)


def write_transcript(sandbox: Path, age_hours: float) -> None:
    slug = str(sandbox / "wt")
    for ch in ":\\/.":
        slug = slug.replace(ch, "-")
    d = sandbox / "root" / "projects" / slug
    d.mkdir(parents=True, exist_ok=True)
    f = d / "turn.jsonl"
    f.write_text('{"t":1}\n', encoding="utf-8")
    _back_date(f, age_hours)


def _back_date(path: Path, age_hours: float) -> None:
    import time

    when = time.time() - age_hours * 3600
    os.utime(path, (when, when))


class TestTheIndependentSignalWins:
    def test_a_fresh_transcript_vetoes_a_stale_writer_alive(self, sandbox: Path) -> None:
        """The hooks-disabled case. Reproduces the 31.4-hour disagreement measured on a live box."""
        write_heartbeat(sandbox, age_hours=48)
        write_transcript(sandbox, age_hours=0.02)
        a = activity(sandbox)
        assert a["Veto"] is True, a
        assert a["TranscriptAgeH"] < 1
        assert a["WriterAliveAgeH"] > 24
        assert any("transcript" in w for w in a["Why"]), a["Why"]

    def test_and_it_does_not_veto_once_the_transcript_is_stale_too(self, sandbox: Path) -> None:
        """THE OTHER HALF OF THE PAIR.

        Without this, the test above passes against a function that returns True unconditionally --
        the safest wrong answer, and the one that would silently make the mechanism useless.
        """
        write_heartbeat(sandbox, age_hours=48)
        write_transcript(sandbox, age_hours=48)
        a = activity(sandbox)
        assert a["Veto"] is False, a
        assert a["Why"] == [], a["Why"]

    def test_a_fresh_heartbeat_still_vetoes_on_its_own(self, sandbox: Path) -> None:
        """Adding a signal must not remove one. The heartbeat is weaker, not discarded."""
        write_heartbeat(sandbox, age_hours=0.1)
        write_transcript(sandbox, age_hours=48)
        assert activity(sandbox)["Veto"] is True


class TestTheSignalCountIsHonest:
    def test_writer_alive_is_counted_once_not_twice_with_seat_asof(self, sandbox: Path) -> None:
        """42 of 42 boxes had `.writer-alive` and seat `asOf` equal to the second.

        The function returns no `asOf` accessor at all, so a caller cannot inflate the count by
        reading one clock twice. Heartbeat plus worktree is two, and that is the whole of it.
        """
        write_heartbeat(sandbox, age_hours=48)
        a = activity(sandbox)
        assert a["Signals"] == 2, a  # heartbeat + worktree; no transcript written
        assert "AsOf" not in a and "SeatAsOf" not in a

    def test_missing_everything_reports_unevaluable_not_dead(self, sandbox: Path) -> None:
        """`Signals` below two must not read as permission. An unevaluated fence is not a passed one."""
        a = activity(sandbox, WorktreePath=str(sandbox / "nope"), RepoHint=str(sandbox / "nope"))
        assert a["Signals"] < 2, a
        assert a["Evaluable"] is False, a
        assert a["Veto"] is False, "no veto and not evaluable are DIFFERENT answers"

    def test_a_present_worktree_is_a_signal_and_a_veto_is_not_implied_by_it(
        self, sandbox: Path
    ) -> None:
        """Existing is evidence the box is real, not evidence anyone is in it."""
        write_heartbeat(sandbox, age_hours=48)
        write_transcript(sandbox, age_hours=48)
        a = activity(sandbox)
        assert a["WorktreeExists"] is True
        assert a["Signals"] == 3
        assert a["Veto"] is False


class TestTheTranscriptSlug:
    @pytest.mark.parametrize(
        ("path", "expected"),
        [
            (
                r"D:\proj\App\.claude\worktrees\demo-1234",
                "D--proj-App--claude-worktrees-demo-1234",
            ),
            (r"D:\proj\App", "D--proj-App"),
            (r"D:\a.b\c", "D--a-b-c"),
            ("", ""),
        ],
    )
    def test_slug_matches_the_directory_claude_code_actually_writes(
        self, sandbox: Path, path: str, expected: str
    ) -> None:
        """Shape verified against the real tree; the rows here are neutral paths on purpose.

        A real home path carries the OS account name, which the forbidden-content gate blocks, and
        it blocked exactly these rows on the first commit attempt. The first row is the live shape
        with the drive and user segments swapped out.

        The doubled separators look like a bug and are not. `D:` and `\\` both map, giving `D--`;
        `\\.claude` is a separator followed by a dot, giving `--claude`.
        """
        ps = (
            f". '{sandbox / 'scripts' / 'coord' / 'box-activity.ps1'}'; "
            f"ConvertTo-TranscriptSlug -Path '{path}'"
        )
        proc = subprocess.run(
            ["pwsh", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout.strip() == expected


class TestTheLibraryHasNoSideEffects:
    def test_dot_sourcing_does_not_change_the_callers_strict_mode(self, sandbox: Path) -> None:
        """A dot-sourced file sets StrictMode in its CALLER, and none of its siblings do.

        Caught by breaking a caller: an early draft set `Set-StrictMode -Version Latest`, and the
        harness that loaded it started failing on `$LASTEXITCODE` being unset. A library whose
        synopsis says "defines functions, does nothing" must not re-strictify every script that
        loads it.
        """
        ps = (
            f". '{sandbox / 'scripts' / 'coord' / 'box-activity.ps1'}'; "
            "if ($null -eq (Get-Variable -Name nope-not-set -EA SilentlyContinue)) { 'lenient' }"
        )
        proc = subprocess.run(
            ["pwsh", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr
        assert "lenient" in proc.stdout
