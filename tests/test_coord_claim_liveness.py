# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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
import time
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


# --------------------------------------------------------------------------------------------------
# BACKLOG #1466: merged-work EVIDENCE for a directory-only holder, and never authority
# --------------------------------------------------------------------------------------------------
#
# The directory-only state has no remedy on this host, so the tool now reports the one fact a reader
# can ground a decision on: whether the holder's work already landed on origin/main. Every test pins
# the second half too -- the refusal is unchanged -- because evidence that quietly became a licence is
# the automatic release this item declined.


@pytest.fixture
def evidence_repo(repo_with_occupancy: Path, tmp_path: Path) -> Path:
    """The occupancy sandbox plus a bare ``origin`` with ``main`` pushed and fetched.

    main's tip is dated in the PAST, so a fresh peer branch's head predates its claim by construction
    rather than by luck -- ``%ct`` has whole seconds, and a same-second commit would read as "after".
    """
    r = repo_with_occupancy
    (r / "old.txt").write_text("old", encoding="utf-8")
    git(r, "add", "-A")
    past = "2026-01-01T00:00:00Z"
    env = {**os.environ, "GIT_COMMITTER_DATE": past, "GIT_AUTHOR_DATE": past}
    subprocess.run(
        ["git", "-C", str(r), "commit", "-qm", "old"], check=True, capture_output=True, env=env
    )
    origin = tmp_path / "origin.git"
    subprocess.run(["git", "init", "-q", "--bare", str(origin)], check=True, capture_output=True)
    git(r, "remote", "add", "origin", str(origin))
    publish_main(r)
    return r


def commit_later(repo: Path, message: str) -> None:
    """Commit everything, dated two minutes AHEAD so it is strictly after any claim just taken.

    The verdict compares whole seconds and counts a tie as BEFORE, so a real-time commit made in the
    claim's own second would read as "nothing built". Dating it forward makes the order the test's.
    """
    later = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 120))
    env = {**os.environ, "GIT_COMMITTER_DATE": later, "GIT_AUTHOR_DATE": later}
    git(repo, "add", "-A")
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-qm", message], check=True, capture_output=True, env=env
    )


def peer_commits(peer: Path) -> None:
    (peer / "work.txt").write_text("the peer's work", encoding="utf-8")
    commit_later(peer, "work")


def publish_main(r: Path) -> None:
    git(r, "push", "-q", "origin", "main")
    git(r, "fetch", "-q", "origin")


def evidence_lines(out: str) -> list[str]:
    return [ln.strip() for ln in out.splitlines() if ln.strip().startswith("evidence:")]


def assert_still_refused(r: Path, key: str = "k") -> str:
    """The half every evidence test pins: the release is still refused and the claim still exists."""
    proc = claim(r, "-Release", key)
    assert proc.returncode == 1, proc.stdout
    assert "Released claim" not in proc.stdout
    assert "Safe to take over" not in proc.stdout
    assert "not authority to release" in proc.stdout
    common = Path(git(r, "rev-parse", "--path-format=absolute", "--git-common-dir").strip())
    assert (common / "mefor-coord" / "claims" / f"{key}.json").exists()
    return proc.stdout


def test_evidence_says_ON_MAIN_when_the_branch_merged_and_still_refuses(
    evidence_repo: Path, tmp_path: Path
) -> None:
    peer = peer_holding(evidence_repo, tmp_path, "k")
    peer_commits(peer)
    git(evidence_repo, "merge", "-q", "--no-ff", "peer-branch", "-m", "merge peer")
    publish_main(evidence_repo)

    out = claim(evidence_repo, "-List").stdout
    assert "DIRECTORY ONLY" in out, out
    assert any(ln.startswith("evidence: ON MAIN --") for ln in evidence_lines(out)), out
    assert "FOR THE OWNER, NOT AUTHORITY TO RELEASE" in out

    refused = assert_still_refused(evidence_repo)
    assert "EVIDENCE FOR THE OWNER" in refused
    assert "evidence: ON MAIN --" in refused


def test_evidence_sees_a_SQUASH_merge_that_ancestry_cannot(
    evidence_repo: Path, tmp_path: Path
) -> None:
    """Pull requests here are squash-merged, so the landed branch is NOT an ancestor of main."""
    peer = peer_holding(evidence_repo, tmp_path, "k")
    peer_commits(peer)
    git(evidence_repo, "merge", "-q", "--squash", "peer-branch")
    git(evidence_repo, "commit", "-qm", "squashed")
    publish_main(evidence_repo)

    ev = evidence_lines(claim(evidence_repo, "-List").stdout)
    assert any(ln.startswith("evidence: CONTENT ON MAIN --") for ln in ev), ev
    assert not any(ln.startswith("evidence: NOT ON MAIN") for ln in ev), ev
    assert_still_refused(evidence_repo)


def test_evidence_says_NOT_ON_MAIN_for_unmerged_work_and_names_the_missing_branch(
    evidence_repo: Path, tmp_path: Path
) -> None:
    """The negative control for both tests above: a probe hardwired to "landed" fails here."""
    peer = peer_holding(evidence_repo, tmp_path, "k")
    peer_commits(peer)

    ev = evidence_lines(claim(evidence_repo, "-List").stdout)
    assert any(ln.startswith("evidence: NOT ON MAIN --") for ln in ev), ev
    assert not any(
        ln.startswith(("evidence: ON MAIN", "evidence: CONTENT ON MAIN")) for ln in ev
    ), ev
    assert (
        "evidence: branch peer-branch on origin: NO per this clone's tracking refs (last fetch)"
        in ev
    )

    # Pushed and fetched, the same branch reads as present -- the pair makes "NO" attributable.
    git(peer, "push", "-q", "origin", "peer-branch")
    git(evidence_repo, "fetch", "-q", "origin")
    ev = evidence_lines(claim(evidence_repo, "-List").stdout)
    on = "evidence: branch peer-branch on origin: yes per this clone's tracking ref"
    assert any(ln.startswith(on) for ln in ev), ev


def test_a_fresh_branch_is_NOTHING_BUILT_not_landed(evidence_repo: Path, tmp_path: Path) -> None:
    """A branch with nothing on it IS an ancestor of main, trivially. That must not read as landed."""
    peer_holding(evidence_repo, tmp_path, "k")
    ev = evidence_lines(claim(evidence_repo, "-List").stdout)
    assert any(ln.startswith("evidence: NOTHING BUILT --") for ln in ev), ev
    assert not any(ln.startswith("evidence: ON MAIN") for ln in ev), ev


def test_the_refusal_reports_uncommitted_changes(evidence_repo: Path, tmp_path: Path) -> None:
    peer = peer_holding(evidence_repo, tmp_path, "k")
    peer_commits(peer)
    git(evidence_repo, "merge", "-q", "--no-ff", "peer-branch", "-m", "merge peer")
    publish_main(evidence_repo)
    (peer / "f.txt").write_text("edited after the merge", encoding="utf-8")

    refused = assert_still_refused(evidence_repo)
    assert "evidence: ON MAIN --" in refused
    assert "1 uncommitted change(s) to tracked files" in refused


def test_no_origin_main_is_UNKNOWN_not_a_verdict(repo_with_occupancy: Path, tmp_path: Path) -> None:
    peer = peer_holding(repo_with_occupancy, tmp_path, "k")
    peer_commits(peer)
    ev = evidence_lines(claim(repo_with_occupancy, "-List").stdout)
    assert ev, "the directory-only holder must still get an evidence line"
    assert all(ln.startswith("evidence: UNKNOWN --") for ln in ev), ev
    assert "no origin/main" in ev[0]


def test_online_lookups_answer_when_they_can_and_say_UNKNOWN_when_they_cannot(
    evidence_repo: Path, tmp_path: Path
) -> None:
    """-Online asks origin directly. A reachable origin answers; an unreachable one is "unknown".

    `gh` never has an answer here: the fake profile is signed out and origin is not on GitHub. That is
    the offline path this pins -- a failed lookup prints UNKNOWN rather than "none" or a guess.
    """
    peer = peer_holding(evidence_repo, tmp_path, "k")
    peer_commits(peer)
    git(peer, "push", "-q", "origin", "peer-branch")

    out = claim(evidence_repo, "-List", "-Online").stdout
    ev = evidence_lines(out)
    assert "evidence: branch peer-branch on origin: yes (git ls-remote, just now)" in ev, out
    assert "evidence: pull request: UNKNOWN -- origin is not a GitHub repository" in ev, out
    assert "Pass -Online" not in out

    git(evidence_repo, "remote", "set-url", "origin", str(tmp_path / "no-such-origin.git"))
    ev = evidence_lines(claim(evidence_repo, "-List", "-Online").stdout)
    assert any(ln.startswith("evidence: branch peer-branch on origin: UNKNOWN") for ln in ev), ev
    assert any(ln.startswith("evidence: pull request: UNKNOWN") for ln in ev), ev
    # The offline verdict does not depend on the network, so it survives the dead origin.
    assert any(ln.startswith("evidence: NOT ON MAIN --") for ln in ev), ev


def test_evidence_is_only_for_the_directory_only_state(evidence_repo: Path, tmp_path: Path) -> None:
    """Scope: a GONE holder already has its answer, and gets no evidence block."""
    peer = peer_holding(evidence_repo, tmp_path, "k")
    orphan(evidence_repo, peer)
    out = claim(evidence_repo, "-List").stdout
    assert "HOLDER GONE" in out
    assert "evidence:" not in out
    assert "NOT AUTHORITY TO RELEASE" not in out


def test_two_claims_from_one_holder_each_get_their_own_evidence(
    evidence_repo: Path, tmp_path: Path
) -> None:
    """Evidence is keyed per CLAIM: one worktree often holds several, and keying by path doubled them."""
    peer = peer_holding(evidence_repo, tmp_path, "k")
    assert claim(peer, "-Take", "k2", "-Note", "second").returncode == 0
    peer_commits(peer)

    ev = evidence_lines(claim(evidence_repo, "-List").stdout)
    verdicts = [ln for ln in ev if ln.startswith("evidence: NOT ON MAIN --")]
    assert len(verdicts) == 2, ev


def test_a_conflicting_branch_is_UNCLEAR_not_a_verdict(evidence_repo: Path, tmp_path: Path) -> None:
    """Work that landed and was later edited on main conflicts exactly like work that never landed."""
    peer = peer_holding(evidence_repo, tmp_path, "k")
    (peer / "f.txt").write_text("the peer's line", encoding="utf-8")
    commit_later(peer, "peer edit")
    (evidence_repo / "f.txt").write_text("main's line", encoding="utf-8")
    git(evidence_repo, "commit", "-qam", "main edit")
    publish_main(evidence_repo)

    ev = evidence_lines(claim(evidence_repo, "-List").stdout)
    assert any(ln.startswith("evidence: UNCLEAR --") for ln in ev), ev
    assert not any("ON MAIN --" in ln for ln in ev), ev


def test_a_branch_that_only_PULLED_main_is_not_called_landed(
    evidence_repo: Path, tmp_path: Path
) -> None:
    """Fast-forwarding to someone else's newer commit looks exactly like a merge to ancestry.

    So no verdict may say "landed". It reports the fact -- nothing main lacks, and the head moved -- and
    says in the line itself that a merged branch and one that pulled main look the same.
    """
    peer = peer_holding(evidence_repo, tmp_path, "k")
    (evidence_repo / "someone-else.txt").write_text("not the peer's", encoding="utf-8")
    commit_later(evidence_repo, "someone else's work")
    publish_main(evidence_repo)
    git(peer, "merge", "-q", "--ff-only", "origin/main")

    out = claim(evidence_repo, "-List").stdout
    ev = evidence_lines(out)
    assert any(ln.startswith("evidence: ON MAIN --") and "pulled main" in ln for ln in ev), ev
    assert "LANDED" not in out, out


def test_a_REUSED_branch_whose_old_work_landed_is_NOTHING_BUILT(
    evidence_repo: Path, tmp_path: Path
) -> None:
    """A branch squash-merged BEFORE the claim carries nothing main lacks, and nothing new either."""
    r = evidence_repo
    git(r, "checkout", "-q", "-b", "old-work")
    (r / "old-work.txt").write_text("done long ago", encoding="utf-8")
    git(r, "add", "-A")
    past = "2026-01-02T00:00:00Z"
    env = {**os.environ, "GIT_COMMITTER_DATE": past, "GIT_AUTHOR_DATE": past}
    subprocess.run(
        ["git", "-C", str(r), "commit", "-qm", "old work"], check=True, capture_output=True, env=env
    )
    git(r, "checkout", "-q", "main")
    git(r, "merge", "-q", "--squash", "old-work")
    git(r, "commit", "-qm", "squashed old work")
    publish_main(r)
    peer = tmp_path / "reuse-wt"
    git(r, "worktree", "add", "-q", str(peer), "old-work")
    assert claim(peer, "-Take", "k", "-Note", "new work on an old branch").returncode == 0

    ev = evidence_lines(claim(r, "-List").stdout)
    assert any(ln.startswith("evidence: NOTHING BUILT --") for ln in ev), ev
    assert not any(ln.startswith("evidence: CONTENT ON MAIN") for ln in ev), ev


def test_merging_main_INTO_the_branch_is_NOTHING_BUILT_not_a_squash(
    evidence_repo: Path, tmp_path: Path
) -> None:
    """A merge commit of main is one commit ahead with nothing of its own. It is not a squash shape."""
    peer = peer_holding(evidence_repo, tmp_path, "k")
    (evidence_repo / "someone-else.txt").write_text("not the peer's", encoding="utf-8")
    commit_later(evidence_repo, "someone else's work")
    publish_main(evidence_repo)
    later = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 180))
    env = {**os.environ, "GIT_COMMITTER_DATE": later, "GIT_AUTHOR_DATE": later}
    subprocess.run(
        ["git", "-C", str(peer), "merge", "-q", "--no-ff", "origin/main", "-m", "pull main"],
        check=True,
        capture_output=True,
        env=env,
    )

    ev = evidence_lines(claim(evidence_repo, "-List").stdout)
    assert any(ln.startswith("evidence: NOTHING BUILT --") and "all merges" in ln for ln in ev), ev
    assert not any(ln.startswith("evidence: CONTENT ON MAIN") for ln in ev), ev
