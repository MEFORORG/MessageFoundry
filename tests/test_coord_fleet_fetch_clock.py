# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""``fleet.ps1`` must report when the repository last FETCHED, not when ``origin/main`` last MOVED.

BACKLOG #1374, and it has two halves that fail in opposite directions.

**The field was named for one question and answered another.** ``originMainAgeMinutes`` stat()ed the
ref file ``refs/remotes/origin/main`` -- whose mtime moves when the ref MOVES. A fetch that finds
nothing new leaves that file untouched, so a fleet that fetched seconds ago over a quiet ``main``
reported however long ``main`` had been quiet and fired the stop that prints DO NOT TREAT THE ROSTER
BELOW AS COMPLETE. Measured read-only in the engine checkout on 2026-09-03, with no fetch issued:

    refs/remotes/origin/main mtime   21:25:40.160 UTC     shipped field: 53 minutes
    newest FETCH_HEAD mtime          22:18:35     UTC     real clock:     0 minutes

Seven minutes from a stop condition about a fetch made seconds earlier.

**The second half is worse: on the packed-refs path the value was null and the stop was guarded on
non-null, so it never fired -- and an absent warning renders identically to a healthy one.** The
blind case and the clean case were indistinguishable on screen. ``.git/packed-refs`` in that checkout
already carries a stale ``refs/remotes/origin/main``, so the loose ref was the only thing keeping the
field readable at all.

**FETCH_HEAD is PER-WORKTREE**, which is why the fix scans rather than reading one path. Measured the
same day: 262 worktree gitdirs, 101 carrying a ``FETCH_HEAD`` and 162 carrying none -- the session
that made this change among the latter. Remote-tracking refs are shared, so any worktree's fetch
refreshes the ref every seat reads, and the newest across the common dir and all worktree gitdirs is
the repository's fetch clock.

The three arms below have to be read together, because each alone is satisfiable by a broken tool:

* a fresh fetch over a quiet ``main`` must NOT stop  -- the false alarm,
* an unmeasurable clock MUST stop                    -- the blind instrument,
* a genuinely stale fetch MUST still stop            -- the alarm not traded away.

Every arm was mutation-checked against a scratch copy carrying the pre-fix logic, and all three go
red there. A test that passes against both the fixed and the broken tool measures nothing.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
COORD = ROOT / "scripts" / "coord"
TIMEOUT = 120

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="fleet.ps1 needs pwsh on Windows",
)


def git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=TIMEOUT, check=True
    )
    return proc.stdout


def set_mtime(path: Path, minutes_ago: float) -> None:
    when = (datetime.now(UTC) - timedelta(minutes=minutes_ago)).timestamp()
    os.utime(path, (when, when))


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A throwaway checkout carrying its OWN copies of the scripts under test.

    Never the shared object store: ``fleet.ps1`` resolves the git common dir from where it is RUN,
    and the primary checkout's git state is shared by every worktree on the box. Nothing here fetches
    -- both clocks are written by hand, which is the only way to drive them independently.
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


def common_dir(repo: Path) -> Path:
    return Path(git(repo, "rev-parse", "--path-format=absolute", "--git-common-dir").strip())


def write_lf(path: Path, text: str) -> None:
    """LF, explicitly. ``write_text`` translates to CRLF on Windows and git's packed-refs parser
    rejects the result -- which cost one red arm here before anyone looked at the bytes."""
    path.write_text(text, encoding="utf-8", newline="\n")


def write_loose_ref(repo: Path, minutes_ago: float) -> Path:
    """Put ``origin/main`` on the LOOSE path, dated. The clock the shipped code used to read."""
    sha = git(repo, "rev-parse", "HEAD").strip()
    ref = common_dir(repo) / "refs" / "remotes" / "origin" / "main"
    ref.parent.mkdir(parents=True, exist_ok=True)
    write_lf(ref, sha + "\n")
    set_mtime(ref, minutes_ago)
    return ref


def pack_the_ref(repo: Path) -> Path:
    """Move ``origin/main`` onto the PACKED path, leaving no loose file to stat.

    Packed by GIT ITSELF rather than by writing the file, so the fixture is the state a ``git gc``
    actually leaves rather than this test's idea of it -- and so a change to the packed-refs format
    cannot leave the arm passing against a file git no longer reads.
    """
    common = common_dir(repo)
    git(repo, "pack-refs", "--all")
    loose = common / "refs" / "remotes" / "origin" / "main"
    assert not loose.exists(), (
        "pack-refs left the loose ref behind; the fixture is not in the state"
    )
    packed = common / "packed-refs"
    assert "refs/remotes/origin/main" in packed.read_text(encoding="utf-8"), packed
    return packed


def write_fetch_clock(
    repo: Path, minutes_ago: float, *, worktree_gitdir: str | None = None
) -> Path:
    """Write a ``FETCH_HEAD``, dated -- in the common dir, or in a named worktree gitdir."""
    sha = git(repo, "rev-parse", "HEAD").strip()
    base = common_dir(repo)
    if worktree_gitdir is not None:
        base = base / "worktrees" / worktree_gitdir
        base.mkdir(parents=True, exist_ok=True)
    fh = base / "FETCH_HEAD"
    write_lf(fh, f"{sha}\t\tbranch 'main' of example\n")
    set_mtime(fh, minutes_ago)
    return fh


def clear_fetch_clocks(repo: Path) -> int:
    """Remove every ``FETCH_HEAD``. Returns how many were removed, so a no-op cannot pass silently."""
    common = common_dir(repo)
    removed = 0
    for fh in [common / "FETCH_HEAD", *common.glob("worktrees/*/FETCH_HEAD")]:
        if fh.exists():
            fh.unlink()
            removed += 1
    return removed


def fleet_json(repo: Path) -> dict[str, Any]:
    proc = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(repo / "scripts" / "coord" / "fleet.ps1"),
            "-Json",
        ],
        cwd=str(repo),
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )
    # Exit 2 means fenceAvailable=false, which is expected in a sandbox with no config root.
    assert proc.returncode in (0, 2), f"rc={proc.returncode} stderr={proc.stderr}"
    parsed: dict[str, Any] = json.loads(proc.stdout)
    return parsed


def fleet_text(repo: Path) -> str:
    proc = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(repo / "scripts" / "coord" / "fleet.ps1"),
        ],
        cwd=str(repo),
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )
    assert proc.returncode in (0, 2), f"rc={proc.returncode} stderr={proc.stderr}"
    return proc.stdout


def age_stops(receipt: dict[str, Any]) -> list[str]:
    return [s for s in receipt["stopConditions"] if "originMainAgeMinutes" in s]


class TestTheFieldReadsTheFetchClockNotTheRefMtime:
    def test_a_fresh_fetch_over_a_quiet_main_raises_no_stop(self, repo: Path) -> None:
        """ARM ONE -- the false alarm. The half the item was filed for.

        The ref has not moved in three hours and the fetch was a minute ago. Both are ordinary: a
        quiet ``main`` is the normal state of a repository nobody has landed to this afternoon.
        Reading the ref mtime here fires a stop that tells every seat the roster is incomplete.
        """
        write_loose_ref(repo, minutes_ago=180)
        write_fetch_clock(repo, minutes_ago=1)

        receipt = fleet_json(repo)["receipt"]
        assert receipt["originMainAgeMinutes"] is not None, receipt
        assert receipt["originMainAgeMinutes"] <= 2, (
            "the age must track the FETCH, not the 180-minute-old ref: "
            f"{receipt['originMainAgeMinutes']}"
        )
        assert receipt["originMainFetchClock"].endswith("FETCH_HEAD"), receipt
        assert age_stops(receipt) == [], age_stops(receipt)

    def test_an_unmeasurable_clock_fires_the_stop(self, repo: Path) -> None:
        """ARM TWO -- the blind instrument, and the worse half.

        No ``FETCH_HEAD`` anywhere and ``origin/main`` on the packed path, so neither the shipped
        clock nor the fixed one has a file to stat. The shipped code left the value null, the stop
        was guarded on non-null, and the render was byte-identical to a healthy fleet.
        """
        write_loose_ref(repo, minutes_ago=1)
        pack_the_ref(repo)
        write_fetch_clock(repo, minutes_ago=1)
        assert clear_fetch_clocks(repo) == 1, "the fixture must actually remove a clock"
        assert not (common_dir(repo) / "refs" / "remotes" / "origin" / "main").exists()
        # The ref still RESOLVES -- it is packed, not gone. This is a readable repo with an
        # unreadable clock, not a broken one.
        assert (
            git(repo, "rev-parse", "origin/main").strip() == git(repo, "rev-parse", "HEAD").strip()
        )

        receipt = fleet_json(repo)["receipt"]
        assert receipt["originMainAgeMinutes"] is None, receipt
        assert receipt["originMainFetchClock"].startswith("UNKNOWN"), receipt
        stops = age_stops(receipt)
        assert len(stops) == 1, stops
        assert "UNKNOWN" in stops[0] and "CANNOT BE MEASURED" in stops[0], stops[0]

        # ...AND IT MUST REACH THE SCREEN. A stop in the JSON that renders as an empty column is the
        # same defect one layer down.
        text = fleet_text(repo)
        assert "STOP CONDITIONS FIRED" in text, text
        assert "NO STOP CONDITIONS" not in text, text
        assert "originMainAgeMinutes       UNKNOWN" in text, (
            "a null must print the word, not an empty column"
        )

    def test_a_genuinely_stale_fetch_still_fires_the_stop(self, repo: Path) -> None:
        """ARM THREE -- the alarm that must not be traded away for the fix to arm one.

        The inverse fixture: the ref moved a minute ago (someone pulled into it by hand, or an
        earlier fetch landed a commit) while the last fetch was three hours back. Reading the ref
        mtime here reports a healthy fleet and MISSES the stale ref -- the direction the original
        comment on this block calls the dangerous one, since a reverted change reads as landed.
        """
        write_loose_ref(repo, minutes_ago=1)
        write_fetch_clock(repo, minutes_ago=180)

        receipt = fleet_json(repo)["receipt"]
        assert receipt["originMainAgeMinutes"] is not None
        assert receipt["originMainAgeMinutes"] >= 179, receipt["originMainAgeMinutes"]
        stops = age_stops(receipt)
        assert len(stops) == 1, stops
        assert "has not been fetched recently" in stops[0], stops[0]
        assert "UNKNOWN" not in stops[0], "a measurable stale clock is not an unmeasurable one"

    def test_the_clock_is_the_newest_across_every_worktree_gitdir(self, repo: Path) -> None:
        """FETCH_HEAD is per-worktree, so one worktree's fetch refreshes the ref all seats read.

        Measured on the engine checkout 2026-09-03: 262 worktree gitdirs, 101 carrying a FETCH_HEAD,
        and the session that wrote this test among the 161 that do not. Reading only this worktree's
        path -- what ``git rev-parse --git-path FETCH_HEAD`` returns -- would report UNKNOWN for the
        majority of callers, converting the fixed stop into a new false alarm.
        """
        write_loose_ref(repo, minutes_ago=180)
        write_fetch_clock(repo, minutes_ago=400)  # the common dir is the STALE one
        write_fetch_clock(repo, minutes_ago=2, worktree_gitdir="agent-fresh")
        write_fetch_clock(repo, minutes_ago=900, worktree_gitdir="agent-ancient")

        receipt = fleet_json(repo)["receipt"]
        assert receipt["originMainAgeMinutes"] <= 3, (
            f"the newest clock wins: {receipt['originMainAgeMinutes']}"
        )
        assert "agent-fresh" in receipt["originMainFetchClock"], receipt["originMainFetchClock"]
        assert age_stops(receipt) == [], age_stops(receipt)

    def test_the_receipt_names_the_file_it_read(self, repo: Path) -> None:
        """POSITIVE CONTROL on the evidence, not just the verdict.

        A stop condition is a claim about a measurement, and a reader who cannot see WHICH file was
        stat()ed cannot tell a fetch clock from a ref mtime -- which is exactly how the shipped bug
        survived. The path is printed beside the number so the next reader can check it in one look.
        """
        fh = write_fetch_clock(repo, minutes_ago=5)
        write_loose_ref(repo, minutes_ago=5)

        receipt = fleet_json(repo)["receipt"]
        assert receipt["originMainFetchClock"] == str(fh), receipt["originMainFetchClock"]
        assert "refs" not in Path(receipt["originMainFetchClock"]).name, (
            "the clock must be FETCH_HEAD, never a ref file"
        )
        text = fleet_text(repo)
        assert "originMainFetchClock" in text, text
