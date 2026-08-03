# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The BLOCKING paths must know whether the holder still exists (BACKLOG #345 Half B).

``-List`` learned holder-liveness first, and that was the wrong half to fix on its own: ``-List`` is
where you *browse*, ``-Take`` and ``-Release`` are where you are *stopped*. Both blocking paths
printed the same "held by another worktree" block whether the holder had been deleted, had died, or
was committing that minute -- and ``-Release`` went further, printing "If that session is gone,
re-run with -Force" on a holder it had never looked at.

That is an instruction to guess, issued at exactly the moment an operator is deciding whether to take
someone else's key, and the cheapest way past the gate was also the one that causes the duplicate
build the gate exists to prevent. The 2026-07-24 incident in ``claim.ps1``'s own header is what that
costs: three sessions fixed the same advisory, two PRs were closed as duplicates, and the one that
merged had not tested what the others found.

**The asymmetry is the whole design.** A vanished worktree is a *fact* and the one state safe to act
on unasked. Everything else -- present, undatable, unprobeable -- must read as "coordinate first",
never as "probably fine". A session can be alive and simply not committing, so silence is not
evidence of death. Every test below therefore pairs a positive case with the negative one that would
pass if the probe simply always said "gone".
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CLAIM = ROOT / "scripts" / "coord" / "claim.ps1"
TIMEOUT = 60

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="claim.ps1 needs pwsh on Windows",
)


def git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=TIMEOUT, check=True
    )
    return proc.stdout


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    r.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(r)], check=True, capture_output=True)
    git(r, "config", "user.email", "t@example.invalid")
    git(r, "config", "user.name", "t")
    (r / "f.txt").write_text("x", encoding="utf-8")
    git(r, "add", "-A")
    git(r, "commit", "-qm", "base")
    return r


def claim(cwd: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(CLAIM), *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )


def peer_holding(repo: Path, tmp_path: Path, key: str, note: str = "the peer's work") -> Path:
    """A second worktree that holds ``key``. Returned so a test can delete it."""
    peer = tmp_path / "peer-wt"
    git(repo, "worktree", "add", "-q", "-b", "peer-branch", str(peer))
    assert claim(peer, "-Take", key, "-Note", note).returncode == 0
    return peer


def orphan(repo: Path, peer: Path) -> None:
    """Delete the holder's directory, leaving its claim behind -- the orphan #345 is about.

    ``git worktree remove`` would also deregister it; the claim file lives beside the SHARED object
    store either way, which is precisely why it outlives its worktree.
    """
    shutil.rmtree(peer)


# --------------------------------------------------------------------------------------------------
# -Take: the path a blocked session actually hits
# --------------------------------------------------------------------------------------------------


def test_take_blocked_by_a_VANISHED_holder_says_so(repo: Path, tmp_path: Path) -> None:
    peer = peer_holding(repo, tmp_path, "k")
    orphan(repo, peer)

    proc = claim(repo, "-Take", "k", "-Note", "mine now")

    assert proc.returncode == 1, "the key is still held; blocking is correct"
    assert "HOLDER GONE" in proc.stdout
    # Naming the exact command is the point: an operator told only "it is gone" still has to guess how
    # to proceed, and the guess people reach for is editing the registry by hand.
    assert "-Release k -Force" in proc.stdout
    assert "BLOCKED" in proc.stdout


def test_take_blocked_by_a_LIVING_holder_does_not_offer_force(repo: Path, tmp_path: Path) -> None:
    """The load-bearing negative. A probe hardwired to 'gone' passes every test above and fails this.

    Before this change the output was identical in both cases and ended with a bare `-Force` recipe --
    so the fastest way past the gate was to take a live session's key.
    """
    peer_holding(repo, tmp_path, "k")  # still on disk

    proc = claim(repo, "-Take", "k", "-Note", "mine now")

    assert proc.returncode == 1
    assert "HOLDER IS STILL THERE" in proc.stdout
    assert "HOLDER GONE" not in proc.stdout
    # The property is "no runnable RECIPE", not "the token -Force never appears". The live-holder text
    # deliberately says "do NOT -Force it", so a bare token search fails on the prohibition itself --
    # which is the assertion telling you it is measuring the wrong thing, not the code.
    assert "-Release k -Force" not in proc.stdout, (
        "a live holder must not be handed a copy-pasteable -Force command"
    )
    assert "quiet is not dead" in proc.stdout


def test_take_reports_the_holders_note_either_way(repo: Path, tmp_path: Path) -> None:
    """The note is what tells a blocked session whether to wait or pick other work."""
    peer_holding(repo, tmp_path, "k", note="rebuilding the codec")
    assert "rebuilding the codec" in claim(repo, "-Take", "k").stdout


# --------------------------------------------------------------------------------------------------
# -Release: it used to RECOMMEND -Force without looking
# --------------------------------------------------------------------------------------------------


def test_release_of_a_VANISHED_holders_claim_recommends_force(repo: Path, tmp_path: Path) -> None:
    peer = peer_holding(repo, tmp_path, "k")
    orphan(repo, peer)

    proc = claim(repo, "-Release", "k")

    assert proc.returncode == 1, "still refuses without -Force; it reports, it does not act"
    assert "HOLDER GONE" in proc.stdout
    assert "-Release k -Force" in proc.stdout
    # And the refusal must not have silently released it.
    assert claim(repo, "-Take", "k", "-Note", "x").returncode == 1


def test_release_of_a_LIVING_holders_claim_warns_instead_of_advising_force(
    repo: Path, tmp_path: Path
) -> None:
    """The exact string this replaces was 'If that session is gone, re-run with -Force.'

    Printed unconditionally, on a holder never probed. This asserts the advice inverted for the live
    case rather than merely gaining a new line beside it.
    """
    peer_holding(repo, tmp_path, "k")

    proc = claim(repo, "-Release", "k")

    assert proc.returncode == 1
    assert "HOLDER IS STILL THERE" in proc.stdout
    assert "If that session is gone, re-run with -Force." not in proc.stdout, (
        "the unconditional recommendation must be gone, not supplemented"
    )
    assert "Ask that session first" in proc.stdout


def test_force_still_works_on_a_live_holder(repo: Path, tmp_path: Path) -> None:
    """This reports; it must not have become an enforcement.

    Refusing to -Force a live claim would strand every key whose holder is merely unreachable -- the
    orphan problem again, one level up. The operator keeps the override; they just stop being told to
    use it blind.
    """
    peer_holding(repo, tmp_path, "k")
    assert claim(repo, "-Release", "k", "-Force").returncode == 0
    assert claim(repo, "-Take", "k", "-Note", "now free").returncode == 0


def test_releasing_your_OWN_claim_never_probes_liveness(repo: Path) -> None:
    """The holder is this worktree; there is nothing to warn about and no reason to slow it down."""
    assert claim(repo, "-Take", "k", "-Note", "mine").returncode == 0
    proc = claim(repo, "-Release", "k")
    assert proc.returncode == 0
    assert "HOLDER" not in proc.stdout


# --------------------------------------------------------------------------------------------------
# -List keeps its behaviour: the refactor shares one rule, it does not change what -List reports
# --------------------------------------------------------------------------------------------------


def test_list_still_flags_a_vanished_holder(repo: Path, tmp_path: Path) -> None:
    peer = peer_holding(repo, tmp_path, "k")
    orphan(repo, peer)
    out = claim(repo, "-List").stdout
    assert "HOLDER GONE" in out
    assert "release with -Force" in out


def test_list_still_reports_a_living_holders_quiet_hours(repo: Path, tmp_path: Path) -> None:
    """Anti-regression for the shared helper: 'present' must still carry its commit age."""
    peer_holding(repo, tmp_path, "k")
    out = claim(repo, "-List").stdout
    assert "holder last committed" in out
    assert "HOLDER GONE" not in out
