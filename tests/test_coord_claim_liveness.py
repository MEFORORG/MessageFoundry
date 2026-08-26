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

import json
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
    (r / "scripts" / "coord").mkdir(parents=True)
    subprocess.run(["git", "init", "-q", "-b", "main", str(r)], check=True, capture_output=True)
    git(r, "config", "user.email", "t@example.invalid")
    git(r, "config", "user.name", "t")
    # Staged and committed for the reason written out in test_coord_claim_refresh.py's fixture:
    # claim.ps1 anchors on its own location now (BACKLOG #1060), so the copy IS the sandbox, and a
    # linked worktree of this fixture carries its own -- which is what `peer_holding` relies on.
    shutil.copy2(CLAIM, r / "scripts" / "coord" / "claim.ps1")
    (r / "f.txt").write_text("x", encoding="utf-8")
    git(r, "add", "-A")
    git(r, "commit", "-qm", "base")
    return r


def claim(cwd: Path, *args: str) -> subprocess.CompletedProcess[str]:
    """Run the checkout's OWN copy -- it scopes itself to where it LIVES, not to the cwd."""
    return subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(cwd / "scripts" / "coord" / "claim.ps1"),
            *args,
        ],
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
    """Anti-regression for the shared helper: 'present' must still carry its commit age.

    The wording moved with BACKLOG #1348 -- "holder last committed Nh ago" became "LIVE SESSION in
    the holder, last committed Nh ago" -- because the old phrase was true of a directory nobody was
    in. The commit age is still there; only the claim about WHO is there is new.
    """
    peer_holding(repo, tmp_path, "k")
    out = claim(repo, "-List").stdout
    assert "last committed" in out
    assert "HOLDER GONE" not in out


# --------------------------------------------------------------------------------------------------
# THE THIRD STATE: a holder that is a DIRECTORY rather than a SESSION (BACKLOG #1348)
# --------------------------------------------------------------------------------------------------

# `present` used to mean "the path exists". It never asked whether a session was IN it, so a
# worktree that outlived its session rendered identically to a lane actively building. Measured on
# the live board when this landed: 35 holders gone, 8 with a live session, and 23 that were a
# directory with nobody in it -- and all 31 of the last two groups had been rendering the same way.
#
# THE STATE REPORTS. IT DOES NOT PERMIT. Every test below pins BOTH halves, because a fix that
# turned the new state into a licence to release would be worse than the defect: occupancy.ps1's own
# rule is that it "may only ever VETO an action; a DEAD/STALE/absent verdict must never by itself
# authorise one", since a session working in a path by ABSOLUTE PATH from another cwd is invisible
# to a cwd-keyed probe.


@pytest.fixture
def repo_with_occupancy(repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The sandbox, plus the occupancy probe claim.ps1 consults, plus a config root it can read.

    The base `repo` fixture deliberately copies ONLY claim.ps1, which is what makes the probe
    unavailable there -- and that is a real configuration, not an artifact: a checkout carrying a
    partial scripts/coord/ behaves exactly that way. Both are worth testing, so they get separate
    fixtures rather than one that hides the difference.

    *** THE PLANTED CONFIG ROOT IS WHY THIS PASSES ON CI, and its absence is why the first version
    of these tests did not. *** `Get-WorktreeOccupancy` reports Available=FALSE unless it finds at
    least one READABLE SESSION RECORD -- not merely a config root, an actual record. Measured:

        no config root at all          Available=False  "no Claude config root ... was found"
        a config root, empty sessions  Available=False  "not one readable session record in them"
        a config root + one record     Available=True   Sessions=0

    A CI runner has no Claude session registry, so the probe was unavailable there and the code fell
    back to its unknown-occupancy state -- while these tests asserted the DIRECTORY-ONLY state, which
    is reachable only through an available probe. They passed on a developer box and failed on
    windows-2025, which is the worst shape a test can have: green exactly where nobody is watching.

    The record carries a DEAD pid, so it makes the probe available while placing NO occupant
    anywhere. Occupancy is decided by whether the pid is running (session-registry.ps1), and 999999
    is not a live process on any runner. The cwd points outside the sandbox for the same reason.
    """
    src = CLAIM.parent
    for name in ("occupancy.ps1", "session-registry.ps1"):
        shutil.copy2(src / name, repo / "scripts" / "coord" / name)

    home = tmp_path / "fakehome"
    sessions = home / ".claude" / "sessions"
    sessions.mkdir(parents=True)
    (sessions / "999999.json").write_text(
        json.dumps(
            {
                "cwd": str(tmp_path / "somewhere-else"),
                "pid": 999999,
                "sessionId": "planted-dead-session",
                "startedAt": "2026-01-01T00:00:00Z",
                "procStart": "2026-01-01T00:00:00Z",
                "kind": "desktop",
                "entrypoint": "test",
                "name": "planted",
                "nameSource": "test",
                "peerProtocol": "none",
            }
        ),
        encoding="utf-8",
    )
    # Both, because the roots are resolved from the user profile and the two differ across shells.
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("HOME", str(home))
    return repo


def test_a_holder_with_no_live_session_is_distinguishable_from_one_with_a_session(
    repo_with_occupancy: Path, tmp_path: Path
) -> None:
    """The whole point of #1348: the two must not render identically.

    Nothing is running in the sandbox's peer worktree, so the probe places zero sessions in it.
    """
    peer_holding(repo_with_occupancy, tmp_path, "k")
    out = claim(repo_with_occupancy, "-List").stdout
    assert "DIRECTORY ONLY" in out, out
    assert "no live session in it" in out
    # and it must not claim someone is there
    assert "LIVE SESSION in the holder" not in out


def test_the_third_state_still_refuses_a_take(repo_with_occupancy: Path, tmp_path: Path) -> None:
    """Distinguishable is not releasable. The refusal is unchanged."""
    peer_holding(repo_with_occupancy, tmp_path, "k")
    proc = claim(repo_with_occupancy, "-Take", "k", "-Note", "mine now")
    assert proc.returncode != 0, "an unoccupied holder must still block a take"
    assert "A DIRECTORY, NOT A SESSION" in proc.stdout
    assert "still not yours to -force" in proc.stdout.lower()


def test_the_third_state_does_not_recommend_force_on_a_release(
    repo_with_occupancy: Path, tmp_path: Path
) -> None:
    """`-Force` is recommended for exactly one state, and this is not it.

    The negative control is the vanished-holder case above, which DOES recommend it -- so this
    assertion is about the state, not about the word being absent everywhere.
    """
    peer_holding(repo_with_occupancy, tmp_path, "k")
    proc = claim(repo_with_occupancy, "-Release", "k")
    assert proc.returncode != 0
    assert "A DIRECTORY, NOT A SESSION" in proc.stdout
    assert "Safe to take over" not in proc.stdout


def test_a_vanished_holder_still_outranks_the_third_state(
    repo_with_occupancy: Path, tmp_path: Path
) -> None:
    """Positive control for the probe being live at all.

    With occupancy available, a DELETED worktree must still read GONE and still recommend -Force.
    If this ever reported the third state instead, the new branch would be swallowing the one
    verdict that is safe to act on unasked.
    """
    peer = peer_holding(repo_with_occupancy, tmp_path, "k")
    orphan(repo_with_occupancy, peer)
    out = claim(repo_with_occupancy, "-List").stdout
    assert "HOLDER GONE" in out
    assert "DIRECTORY ONLY" not in out


def test_without_the_probe_it_falls_back_to_REFUSING_not_to_the_new_state(
    repo: Path, tmp_path: Path
) -> None:
    """THE POLARITY RULE, and it is the one that must never regress.

    The base fixture has no occupancy.ps1, so the probe cannot load. A missing answer must cost a
    REFUSAL, never a licence: recognition may only ever suppress. If an unloadable probe ever
    produced "DIRECTORY ONLY", every checkout with a partial scripts/coord/ would start reporting
    live lanes as abandoned -- the same false record, arrived at from the other side.
    """
    peer_holding(repo, tmp_path, "k")
    out = claim(repo, "-List").stdout
    assert "DIRECTORY ONLY" not in out, "an unavailable probe must not produce the new state"
    assert "last committed" in out
    proc = claim(repo, "-Take", "k", "-Note", "mine now")
    assert proc.returncode != 0, "the take must still be refused when the probe cannot load"


def test_an_unavailable_probe_never_claims_a_live_session(repo: Path, tmp_path: Path) -> None:
    """THE REGRESSION TEST FOR THE BUG THAT REACHED CI. One state cannot mean two things.

    The first version of BACKLOG #1348 returned `present` BOTH when the probe looked and found an
    occupant AND when the probe could not look at all -- then labelled `present` "LIVE SESSION in
    the holder". On any machine with no Claude session registry, which is every CI runner, the
    fallback fired and the tool ASSERTED A LIVE SESSION IT HAD NEVER OBSERVED.

    That is not a cosmetic wording defect. The whole point of the item is telling a DIRECTORY apart
    from a PERSON, and a state that reports "person" when it means "I could not look" is the same
    conflation the item exists to remove, reintroduced in the deny text.

    The base `repo` fixture copies only claim.ps1, so occupancy.ps1 cannot be dot-sourced and the
    probe is genuinely unavailable -- the same condition as a runner, reached a different way.
    """
    peer_holding(repo, tmp_path, "k")
    out = claim(repo, "-List").stdout
    assert "LIVE SESSION in the holder" not in out, (
        "the tool claimed a live session while the occupancy probe could not run. It cannot know "
        f"that, and saying it is what shipped to CI.\n{out}"
    )
    assert "OCCUPANCY UNKNOWN" in out, (
        "an unavailable probe must SAY it could not look, not fall silent into a state that reads "
        f"as a measurement.\n{out}"
    )
    # And it must still refuse -- naming the unknown is not a licence.
    proc = claim(repo, "-Take", "k", "-Note", "mine now")
    assert proc.returncode != 0
    assert "quiet is not dead" in proc.stdout, (
        "the unknown-occupancy branch dropped the safety guidance the occupied branch carries. "
        "Only the liveness CLAIM should differ between them; the advice must not."
    )
