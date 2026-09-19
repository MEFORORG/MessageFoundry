# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The occupancy fence must be able to report UNAVAILABLE, or its green light proves nothing.

``scripts/coord/occupancy.ps1`` returns ``Available`` beside its rows precisely so that "the fence
ran and nobody is here" stops looking like "the fence could not look". Its own header states the
rule: an unplaceable record makes the whole fence unavailable, because such a record could name ANY
worktree and therefore clears none of them.

**The header promised it and the matcher dropped one shape on the floor.** A record whose cwd matched
no registered worktree left the loop on a bare ``continue`` and reached no counter, so a session
sitting in a checkout git no longer lists -- which is exactly what the incident in
``prune-merged.ps1``'s header produced, a worktree deregistered with somebody still working in it --
was INVISIBLE rather than UNPLACEABLE. ``RecordsUnplaceable`` could not rise past the two shapes the
matcher did count, and no third shape could ever make ``Available`` false.

That is a control that cannot fail, so it measured nothing, and the two reapers gated on it inherited
the same hole.

**Every test here is one half of a pair.** Asserting only that a planted record makes the fence
unavailable would pass against a matcher that refuses unconditionally, which is the safest possible
wrong answer and would quietly disarm every caller. So each direction is asserted:

* a planted record whose worktree is gone MUST make the fence unavailable;
* the clean case, and a session belonging to some OTHER repository on the same host, MUST leave it
  available. Over-flagging costs the fence in the other direction: most records on this machine
  belong to other repos, and faulting them would leave the fence permanently refusing.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from tests._dead_pid import never_live_pid

ROOT = Path(__file__).resolve().parents[1]
COORD = ROOT / "scripts" / "coord"
LIB = ("occupancy.ps1", "session-registry.ps1")
TIMEOUT = 120

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="occupancy.ps1 needs pwsh on Windows (Get-Process / Process.StartTime)",
)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True)


class Fixture:
    """A throwaway repo, a throwaway config root, and a COPY of the scripts under test.

    Never the live tree: ``test_coord_seat_prompt.py`` records two stray claims that landed in the
    real registry because a test ran against it.
    """

    def __init__(self, tmp_path: Path) -> None:
        self.tmp = tmp_path
        self.box = tmp_path / "scripts" / "coord"
        self.box.mkdir(parents=True)
        for name in LIB:
            shutil.copy2(COORD / name, self.box / name)

        self.repo = tmp_path / "repo"
        self.repo.mkdir()
        _git(self.repo, "init", "-q", "-b", "main")
        _git(self.repo, "config", "user.email", "t@example.invalid")
        _git(self.repo, "config", "user.name", "t")
        (self.repo / "f.txt").write_text("x", encoding="utf-8")
        _git(self.repo, "add", "f.txt")
        _git(self.repo, "commit", "-qm", "init")

        self.root = tmp_path / "root"
        (self.root / "sessions").mkdir(parents=True)

    def sibling(self, name: str) -> Path:
        """The path ``scripts/worktree/new.ps1`` gives a sibling worktree: ``<primary>-<name>``."""
        return self.repo.parent / f"{self.repo.name}-{name}"

    def write_session(self, *, cwd: Path | str, session_id: str, pid: int | None = None) -> Path:
        """A registry record. The pid is dead by construction: faults are counted before the
        liveness fence runs, so no test here needs a live process."""
        procid = never_live_pid() if pid is None else pid
        rec = {
            "pid": procid,
            "sessionId": session_id,
            "cwd": str(cwd),
            "startedAt": 1767225600000,
            "version": "2.1.219",
            "peerProtocol": 1,
            "kind": "interactive",
            "entrypoint": "claude-desktop",
            "name": session_id[:8],
            "nameSource": "derived",
        }
        f = self.root / "sessions" / f"{session_id}.json"
        f.write_text(json.dumps(rec), encoding="utf-8")
        return f

    def occupancy(self) -> dict[str, Any]:
        ps = (
            f". '{self.box / 'occupancy.ps1'}'; "
            f"Get-WorktreeOccupancy -Repo '{self.repo}' -ConfigRoot '{self.root}' "
            "| ConvertTo-Json -Depth 6"
        )
        proc = subprocess.run(
            ["pwsh", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            check=False,
        )
        assert proc.returncode == 0, f"rc={proc.returncode}\n{proc.stdout}\n{proc.stderr}"
        parsed: dict[str, Any] = json.loads(proc.stdout)
        return parsed


@pytest.fixture
def fx(tmp_path: Path) -> Fixture:
    return Fixture(tmp_path)


def test_the_clean_case_reads_available(fx: Fixture) -> None:
    """The positive control. Without this, every assertion below passes against a fence that has
    simply been wired shut, and a fence that always refuses is as useless as one that never can."""
    fx.write_session(cwd=fx.repo, session_id="aaaaaaaa-1111")
    occ = fx.occupancy()

    assert occ["Available"] is True, occ["Detail"]
    assert occ["RecordsUnplaceable"] == 0
    assert occ["RecordsExamined"] == 1
    assert occ["Detail"] == ""


def test_a_session_whose_worktree_is_gone_is_unplaceable_not_invisible(fx: Fixture) -> None:
    """The defect. ``EnterWorktree`` relocates a live session into
    ``<checkout>/.claude/worktrees/<slug>``; ``prune-merged.ps1``'s header records a run that
    deregistered a worktree with somebody still working in it and failed to delete the directory.

    After that, the session's recorded cwd names a checkout ``git worktree list`` does not carry. The
    matcher fell out of the loop on a bare ``continue``, so the record reached no counter at all: the
    fence reported one fewer record than existed and still called itself Available.
    """
    relocated = fx.sibling("relocated") / ".claude" / "worktrees" / "inner"
    planted = fx.write_session(cwd=relocated, session_id="bbbbbbbb-2222")
    assert not relocated.exists(), "the point of the test is a cwd that is no longer on disk"

    occ = fx.occupancy()

    assert occ["RecordsUnplaceable"] >= 1, (
        "a record naming a checkout of this repo that git no longer lists reached no counter, so "
        f"the receipt under-reports what exists: {occ}"
    )
    assert occ["Available"] is False, (
        f"the fence cleared every worktree while a session it could not place existed: {occ}"
    )
    assert str(planted) in " ".join(occ["UnplaceableFiles"]), (
        f"the operator is told the fence refused but not which file to go and look at: {occ}"
    )
    # It must not be attributed to a worktree either. An unplaceable record clears none of them and
    # belongs to none of them; inventing an owner would be worse than the silence it replaces.
    assert occ["Sessions"] == []


def test_a_deregistered_checkout_still_on_disk_is_unplaceable(fx: Fixture) -> None:
    """The same defect with the directory left behind, which is the state the incident actually
    produced: ``git worktree remove --force`` deregistered the tree and then failed to delete it.

    The directory and its ``.git`` pointer still name this repository's worktree admin area, so the
    evidence that it belongs to this repo is on disk -- and git does not list it.
    """
    orphan = fx.sibling("orphan")
    _git(fx.repo, "worktree", "add", "-q", "-b", "orphan-branch", str(orphan))
    admin = fx.repo / ".git" / "worktrees" / orphan.name
    assert admin.is_dir(), f"git did not register the worktree where expected: {admin}"
    shutil.rmtree(admin)  # deregistered; the checkout and its .git file stay put

    listed = subprocess.run(
        ["git", "-C", str(fx.repo), "worktree", "list", "--porcelain"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert orphan.name not in listed, (
        f"git still lists it, so this is not the state under test:\n{listed}"
    )

    fx.write_session(cwd=orphan, session_id="cccccccc-3333")
    occ = fx.occupancy()

    assert occ["RecordsUnplaceable"] >= 1, occ
    assert occ["Available"] is False, occ


def test_another_repositorys_session_does_not_make_this_fence_unavailable(fx: Fixture) -> None:
    """The other direction, and the one that decides whether the fault is worth having.

    Most records on this host belong to other repositories. Faulting them would leave the fence
    permanently refusing, which disarms it exactly as thoroughly as never refusing at all -- a caller
    that always reads UNAVAILABLE stops reading it.

    Three shapes that are NOT this repo's business, planted together:

    * a session in a different git repository;
    * a session in a plain directory that merely shares the ``<primary>-`` name prefix. This is the
      sibling-prefix trap ``test_coord_presence.py`` already pins for attribution, and the fault must
      not reintroduce it by another route;
    * a session at a path that does not exist and is nowhere near this repo's naming.
    """
    other = fx.tmp / "other-repo"
    other.mkdir()
    _git(other, "init", "-q", "-b", "main")

    lookalike = fx.sibling("sweep")  # a plain directory, not a checkout of anything
    lookalike.mkdir()

    fx.write_session(cwd=fx.repo, session_id="dddddddd-4444")
    fx.write_session(cwd=other, session_id="eeeeeeee-5555")
    fx.write_session(cwd=lookalike, session_id="ffffffff-6666")
    fx.write_session(cwd=fx.tmp / "somewhere-else", session_id="99999999-7777")

    occ = fx.occupancy()

    assert occ["RecordsUnplaceable"] == 0, (
        "a record belonging to another repository was counted as this fence's fault, so the fence "
        f"now refuses whenever anyone works anywhere else on this host: {occ['UnplaceableFiles']}"
    )
    assert occ["Available"] is True, occ["Detail"]
    assert occ["RecordsExamined"] == 4
