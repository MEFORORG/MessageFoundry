# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""``fleet.ps1`` must time the FETCH, and must never go quiet when it cannot time anything.

``fleet.ps1`` computes every landed verdict against the cached ``origin/main``, so the receipt has
to say how old that ref is. It reported ``originMainAgeMinutes`` and stat'ed the ref file
``refs/remotes/origin/main``, whose mtime moves when the REF MOVES rather than when a fetch
happened. Two clocks, two failures (BACKLOG #1374).

**THE WRONG CLOCK.** Measured on this repo 2026-08-28: ``.git/FETCH_HEAD`` at ``18:02:16.769``
against the loose ref at ``18:01:24.059`` -- a fetch landed 52 seconds AFTER the ref last moved and
left the ref untouched. So a fleet that fetched seconds ago, against a quiet ``main``, fired the
stop and printed DO NOT TREAT THE ROSTER BELOW AS COMPLETE about a fetch that was fresh.

**THE UNMEASURABLE CASE RENDERED HEALTHY, AND THAT IS THE WORSE HALF.** With the ref packed there is
no loose file to stat, the value stayed null, and the guard read ``-ne $null -and -gt 60`` -- so the
one state where the instrument knows nothing was the one state it said nothing about. An absent
warning renders identically to a healthy one.

**THAT STATE IS THE DEFAULT, NOT AN EDGE.** Measured from an empty sandbox 2026-09-03 and pinned by
``test_a_fresh_clone_has_no_loose_ref_and_no_fetch_clock`` below: ``git clone`` packs
``refs/remotes/origin/main`` and writes NO ``FETCH_HEAD``. A brand-new checkout was blind, silently.

**AND THE CLOCK IS PER-WORKTREE WHILE THE REF IS SHARED.** Measured 2026-09-03: a fetch inside a
linked worktree writes ``<git-dir>/FETCH_HEAD`` and leaves ``<common>/FETCH_HEAD`` untouched, while
``refs/remotes/origin/main`` is common to the clone. Every seat here works in a linked worktree, so
a common-dir-only read reports the PRIMARY's last fetch. Live in the engine checkout the same day,
three clocks disagreeing at once: loose ref 34 minutes, ``<common>/FETCH_HEAD`` 17 minutes, newest
worktree ``FETCH_HEAD`` 3 minutes.

THE POSITIVE CONTROL RUNS FIRST. Every other arm here asserts a stop condition or a null, and a
suite that only ever asserts failure states would pass against a script hard-coded to fire.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
COORD = ROOT / "scripts" / "coord"
TIMEOUT = 180

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="fleet.ps1 needs pwsh on Windows",
)


def git(cwd: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(cwd), *args], capture_output=True, text=True, timeout=TIMEOUT, check=True
    )
    return proc.stdout.strip()


def backdate(path: Path, minutes: float) -> None:
    """Move one file's mtime into the past. The only way to age a clock inside a test."""
    when = time.time() - minutes * 60
    os.utime(path, (when, when))


def common_dir(clone: Path) -> Path:
    return Path(git(clone, "rev-parse", "--path-format=absolute", "--git-common-dir"))


def fetch_heads(clone: Path) -> list[Path]:
    """Every FETCH_HEAD this clone owns: the common dir's, plus one per linked worktree.

    Deliberately a second, independent implementation of the sweep fleet.ps1 does, so an error in
    the SCRIPT cannot hide behind the same error in the test. The premise the two share -- that
    these are the directories that count -- is pinned instead by
    ``test_a_fetch_from_a_linked_worktree_is_the_clock_that_counts``, which makes real git put a
    real clock in a real linked worktree.
    """
    common = common_dir(clone)
    found = [common / "FETCH_HEAD"]
    found += sorted((common / "worktrees").glob("*/FETCH_HEAD"))
    return [p for p in found if p.exists()]


@pytest.fixture(scope="session")
def upstream(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A remote to clone from, so the clone under test has a real ``origin/main``.

    SESSION-SCOPED because no arm mutates it -- they clone it and fetch from it, and every mutation
    in this file lands in the per-test ``clone``. `git` costs roughly 280 ms per process on Windows,
    so a function-scoped fixture spent five spawns per test on a repo nobody writes to.
    """
    up = tmp_path_factory.mktemp("up")
    subprocess.run(["git", "init", "-q", "-b", "main", str(up)], check=True, capture_output=True)
    git(up, "config", "user.email", "t@example.invalid")
    git(up, "config", "user.name", "t")
    (up / "a.txt").write_text("a", encoding="utf-8")
    git(up, "add", "a.txt")
    git(up, "commit", "-qm", "base")
    return up


@pytest.fixture
def clone(tmp_path: Path, upstream: Path) -> Path:
    """A throwaway CLONE carrying its OWN copy of the script under test.

    A clone rather than a bare ``git init``, because the packed-refs state this item is about is
    something ``git clone`` produces and ``git init`` cannot. fleet.ps1 anchors on where it LIVES,
    so copying it in is what keeps this sandbox out of the real registry.
    """
    c = tmp_path / "clone"
    subprocess.run(
        ["git", "clone", "-q", str(upstream), str(c)],
        check=True,
        capture_output=True,
        timeout=TIMEOUT,
    )
    git(c, "config", "user.email", "t@example.invalid")
    git(c, "config", "user.name", "t")
    (c / "scripts" / "coord").mkdir(parents=True)
    for name in ("fleet.ps1", "mail-key.ps1", "session-registry.ps1"):
        shutil.copy2(COORD / name, c / "scripts" / "coord" / name)
    return c


def fleet(clone: Path, render: str) -> str:
    proc = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(clone / "scripts" / "coord" / "fleet.ps1"),
            render,
        ],
        cwd=str(clone),
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )
    # Exit 2 means fenceAvailable=false, which is expected wherever no config root is present.
    assert proc.returncode in (0, 2), f"rc={proc.returncode} stderr={proc.stderr}"
    return proc.stdout


def fleet_json(clone: Path) -> dict:
    return json.loads(fleet(clone, "-Json"))


def fleet_text(clone: Path) -> str:
    return fleet(clone, "-Text")


def fetch_stops(receipt: dict) -> list[str]:
    """Only this rung's stops. Other rungs fire in a sandbox and are not what these arms measure."""
    return [s for s in receipt["stopConditions"] if "lastFetch" in s]


class TestTheClockIsTheFetchAndNotTheRef:
    def test_a_fresh_fetch_reports_a_small_age_and_raises_no_stop(self, clone: Path) -> None:
        """POSITIVE CONTROL, AND IT RUNS FIRST.

        If a measurable, recent fetch cannot produce a clean receipt in this sandbox, then every
        assertion below is satisfied by a script that fires unconditionally.
        """
        git(clone, "fetch", "origin")
        receipt = fleet_json(clone)["receipt"]
        assert receipt["lastFetchAgeMinutes"] is not None, receipt
        assert receipt["lastFetchAgeMinutes"] < 60
        assert receipt["lastFetchClock"].endswith("FETCH_HEAD"), receipt["lastFetchClock"]
        assert fetch_stops(receipt) == []

    def test_a_stale_ref_beside_a_fresh_fetch_raises_no_stop(self, clone: Path) -> None:
        """THE WRONG-CLOCK ARM. The ref has not moved for a day; the fetch was seconds ago.

        This is the 52-second reading at its real magnitude. The predecessor stat'ed the ref file
        and would report a day of staleness here, firing DO NOT TREAT THE ROSTER BELOW AS COMPLETE
        about a fetch that is fresh.
        """
        git(clone, "fetch", "origin")
        # A loose ref, backdated a day. It is written directly because `git update-ref` to the value
        # the ref ALREADY has is a no-op and leaves the pack alone -- measured here, and the arm
        # failed on exactly that until the write became explicit. A single sha line is the shape git
        # writes, and the rev-parse below is the check that the ref still resolves through it.
        sha = git(clone, "rev-parse", "origin/main")
        loose = common_dir(clone) / "refs" / "remotes" / "origin" / "main"
        loose.parent.mkdir(parents=True, exist_ok=True)
        loose.write_text(sha + "\n", encoding="utf-8")
        assert git(clone, "rev-parse", "origin/main") == sha
        backdate(loose, minutes=24 * 60)

        receipt = fleet_json(clone)["receipt"]
        assert receipt["lastFetchAgeMinutes"] < 60, "the FETCH is fresh, whatever the ref says"
        assert fetch_stops(receipt) == [], "a fresh fetch must not be reported as a stale ref"

    def test_a_fetch_older_than_an_hour_still_fires_the_stop(self, clone: Path) -> None:
        """The stop must survive the clock swap. A gate that never fires reports nothing."""
        git(clone, "fetch", "origin")
        for head in fetch_heads(clone):
            backdate(head, minutes=180)

        receipt = fleet_json(clone)["receipt"]
        assert receipt["lastFetchAgeMinutes"] >= 170, receipt["lastFetchAgeMinutes"]
        stops = fetch_stops(receipt)
        assert len(stops) == 1, stops
        assert "lastFetchAgeMinutes=" in stops[0]
        assert "stale origin/main" in stops[0], stops[0]


class TestBlindMustNotRenderAsHealthy:
    def test_a_fresh_clone_has_no_loose_ref_and_no_fetch_clock(self, clone: Path) -> None:
        """THE CONSTRUCTED ROW, asserted as a precondition before anything is judged on it.

        A checkout with a loose ref cannot exercise the null case at all, so the case is BUILT here
        rather than hoped for. This also pins the measurement the fix rests on: the packed-refs
        state is what `git clone` hands you, not an exotic configuration someone opted into.
        """
        common = common_dir(clone)
        assert not (common / "refs" / "remotes" / "origin" / "main").exists(), (
            "a fresh clone must have NO loose remote ref -- nothing here would be measuring the "
            "packed-refs path otherwise"
        )
        packed = (common / "packed-refs").read_text(encoding="utf-8")
        assert "refs/remotes/origin/main" in packed, packed
        assert git(clone, "rev-parse", "origin/main"), "and the ref still resolves through the pack"
        assert fetch_heads(clone) == [], "and `git clone` writes no fetch clock at all"

    def test_no_fetch_clock_anywhere_fires_the_stop_rather_than_going_quiet(
        self, clone: Path
    ) -> None:
        """THE HALF THAT RENDERED HEALTHY. Null is now loud, and it is loud in the receipt too."""
        for head in fetch_heads(clone):
            head.unlink()  # defensive: the arm is "no clock exists", not "this git wrote none"
        assert fetch_heads(clone) == []

        receipt = fleet_json(clone)["receipt"]
        assert receipt["lastFetchAgeMinutes"] is None, receipt["lastFetchAgeMinutes"]
        stops = fetch_stops(receipt)
        assert len(stops) == 1, stops
        assert "UNMEASURABLE" in stops[0], stops[0]
        # The neighbouring receipt field must not be blank either. A null age printed as an empty
        # column is the same silence in a different place.
        assert receipt["lastFetchClock"], "the clock field must never render empty"
        assert "UNMEASURABLE" in receipt["lastFetchClock"], receipt["lastFetchClock"]

    def test_the_text_render_refuses_to_call_a_blind_roster_complete(self, clone: Path) -> None:
        """The reader of this output is the person least equipped to notice a missing warning.

        ``-Text`` is what a seat actually reads, so the blind case is asserted where they read it.

        THIS ARM ASSERTED THE WRONG FEATURE FIRST AND SURVIVED A MUTATION IT SHOULD HAVE CAUGHT.
        ``STOP CONDITIONS FIRED`` and a bare ``UNMEASURABLE`` are both satisfied without this rung:
        an empty sandbox already fires ``recordsExamined=0``, and ``lastFetchClock`` prints the word
        in the receipt block whatever the guard does. Re-put the null guard back and the arm stayed
        green. It now reads the STOP BLOCK ITSELF and looks for this rung's own line.
        """
        for head in fetch_heads(clone):
            head.unlink()
        out = fleet_text(clone)
        assert "NO STOP CONDITIONS" not in out, out[:2000]
        marker = "STOP CONDITIONS FIRED"
        assert marker in out, out[:2000]
        block = out.split(marker, 1)[1].split("\n\n", 1)[0]
        assert "lastFetchAgeMinutes=UNMEASURABLE" in block, block

    def test_a_null_receipt_field_prints_a_sentinel_instead_of_whitespace(
        self, clone: Path
    ) -> None:
        """The generic backstop, on the field that exposed the need for it.

        PowerShell's ``-f`` formats ``$null`` as the empty string, so any receipt field this
        instrument could not measure printed as a blank column and read exactly like a quiet healthy
        one. ``originMainSha`` is null in any checkout with no ``origin`` remote, and was rendering
        that way -- the same failure as the fetch clock, one field along.

        The remote is REMOVED here rather than hoped absent, because a clone always has one.
        """
        git(clone, "remote", "remove", "origin")
        out = fleet_text(clone)
        # `.strip()` is the point: a blank value strips down to the key alone, so `endswith` is what
        # tells a rendered sentinel apart from an empty column.
        lines = {
            ln.split()[0]: ln.strip()
            for ln in out.splitlines()
            if ln.startswith("  ") and ln.strip()
        }
        assert lines["originMainSha"].endswith("(null)"), lines["originMainSha"]
        assert lines["lastFetchAgeMinutes"].endswith("(null)"), lines["lastFetchAgeMinutes"]


class TestTheWholeCloneIsRead:
    def test_a_fetch_from_a_linked_worktree_is_the_clock_that_counts(self, clone: Path) -> None:
        """FETCH_HEAD is per-worktree; the remote-tracking ref is shared.

        Every seat here works in a linked worktree, so a common-dir-only read answers "when did the
        PRIMARY last fetch" while the receipt's label asks "how fresh is origin/main". Any
        worktree's fetch refreshes the shared ref, so the newest clock in the clone is the answer.
        """
        git(clone, "fetch", "origin")
        common = common_dir(clone)
        wt = clone.parent / "wt"
        git(clone, "worktree", "add", "-q", "-b", "side", str(wt))
        git(wt, "fetch", "origin")

        wt_head = Path(git(wt, "rev-parse", "--path-format=absolute", "--git-dir")) / "FETCH_HEAD"
        assert wt_head.exists(), "the arm needs the per-worktree clock it is about"
        # The primary's clock is a day old. Only the worktree's is fresh.
        backdate(common / "FETCH_HEAD", minutes=24 * 60)

        receipt = fleet_json(clone)["receipt"]
        assert receipt["lastFetchAgeMinutes"] < 60, receipt["lastFetchAgeMinutes"]
        assert "worktrees" in receipt["lastFetchClock"], receipt["lastFetchClock"]
        assert fetch_stops(receipt) == []


class TestTheFieldNamesTheClockItReads:
    def test_the_misnamed_predecessor_key_is_gone(self, clone: Path) -> None:
        """A key that claims fetch recency and times a ref file must not survive the fix.

        Checked before renaming rather than after: nothing outside ``docs/BACKLOG.md`` reads this
        key by name, in this repo or in the vault's ``origin/main``, with ``fleet.ps1`` itself as
        the positive control that the search could see. So it was renamed, not doubled -- a
        consumer pinned to the old key now finds no key, which is the honest failure.
        """
        git(clone, "fetch", "origin")
        receipt = fleet_json(clone)["receipt"]
        assert "originMainAgeMinutes" not in receipt, sorted(receipt)
        assert "lastFetchAgeMinutes" in receipt, sorted(receipt)
        assert "lastFetchClock" in receipt, sorted(receipt)
        # The sha is a different question and stays.
        assert receipt["originMainSha"], receipt
