# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The durability hook must write a ref that can be read after the branch is gone (BACKLOG #1349).

``scripts/hooks/durability_push.sh`` is the highest-volume writer of rescue refs in this project --
it fires on every commit in every armed checkout -- and it used to force-push a bare ref recording
nothing. Measured 2026-09-03 in the live checkout: ``rescue.ps1 -Check`` examined 1671 refs and
returned UNVERIFIABLE for all 1671, because a bare ref can only be graded against a branch that
still exists, and a rescue ref is read once, in the moment the original is already gone.

**DURABILITY OUTRANKS PROVENANCE, AND THE TESTS ARE ORDERED THAT WAY.** This is a POST-COMMIT hook
whose first contract is that it never fails a commit. Provenance is an improvement layered on top of
a guarantee that must not move, so the degradation arms below are not edge cases -- they are the
acceptance. Each one drives a real failure and requires the commit to stand and the push to happen
anyway.

**THE PUSH IS BACKGROUNDED, SO THE REMOTE IS POLLED RATHER THAN READ ONCE.** The hook detaches the
push so the commit returns immediately, which is the property that keeps it from being disabled by
the first person it inconveniences. A single read straight after ``git commit`` is therefore a race,
and asserting on elapsed time would be a load measurement rather than a behaviour one.

**THE TAG OBJECT IS NOT THE COMMIT.** ``git rev-parse`` on an annotated tag returns the TAG OBJECT.
``diff``, ``merge-base`` and ``rev-list`` all dereference silently, so ancestry looks right while a
published sha does not resolve -- which happened once and was corrected. The commit assertions here
go through ``%(*objectname)`` or ``^{commit}`` for that reason.

**NO LOCAL REF IS CREATED, AND THAT IS ASSERTED.** A local annotated tag reachable from a branch tip
would be swept up by ``git push --follow-tags`` to whatever remote a hand reaches for, and the
default one in this project is PUBLIC. A provenance mechanism that opens the publication path the
hook exists to avoid would be a worse defect than the one it fixes.

The fixtures build throwaway repositories under ``tmp_path`` and never touch the real
``.git/hooks``: the suite runs under ``pytest-xdist``, so four workers would race any shared state.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HOOK = ROOT / "scripts" / "hooks" / "durability_push.sh"
RESCUE = ROOT / "scripts" / "coord" / "rescue.ps1"
TIMEOUT = 180
#: The push is detached, so the remote is polled. Generous because the box this runs on is routinely
#: saturated; a short budget would turn load into a red test.
PUSH_WAIT = 90.0

pytestmark = pytest.mark.skipif(
    shutil.which("sh") is None, reason="durability_push.sh is a /bin/sh hook and needs sh on PATH"
)


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=TIMEOUT, check=True
    ).stdout.strip()


@pytest.fixture
def armed(tmp_path: Path) -> tuple[Path, Path]:
    """A checkout with the hook installed and armed, plus the bare remote it pushes to.

    The repository directory is named ``r`` on purpose: the hook derives the ``<repo>`` path segment
    from the git COMMON DIR's parent, so the ref it writes is ``refs/tags/rescue/auto/r/<branch>``.
    That segment is load-bearing -- two repositories pushing to one remote collided on
    ``refs/tags/rescue/auto/main`` before it existed -- so the tests spell the full refname out.
    """
    bare = tmp_path / "priv.git"
    subprocess.run(
        ["git", "init", "-q", "--bare", "-b", "main", str(bare)], check=True, capture_output=True
    )
    repo = tmp_path / "r"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True, capture_output=True)
    git(repo, "config", "user.email", "t@example.invalid")
    git(repo, "config", "user.name", "t")
    hook = repo / ".git" / "hooks" / "post-commit"
    shutil.copy2(HOOK, hook)
    hook.chmod(0o755)
    git(repo, "remote", "add", "priv", str(bare))
    git(repo, "config", "mefor.durabilityRemote", "priv")
    return repo, bare


def commit(repo: Path, text: str) -> str:
    (repo / "a.txt").write_text(text, encoding="utf-8")
    subprocess.run(
        ["git", "-C", str(repo), "add", "-A"], check=True, capture_output=True, timeout=TIMEOUT
    )
    proc = subprocess.run(
        ["git", "-C", str(repo), "commit", "-qm", text.strip()],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
    )
    assert proc.returncode == 0, "THE HOOK FAILED A COMMIT\n" + proc.stdout + proc.stderr
    return git(repo, "rev-parse", "HEAD")


def wait_for_ref(bare: Path, ref: str) -> bool:
    deadline = time.monotonic() + PUSH_WAIT
    while time.monotonic() < deadline:
        got = subprocess.run(
            ["git", "-C", str(bare), "rev-parse", "--verify", "--quiet", ref],
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
        )
        if got.returncode == 0 and got.stdout.strip():
            return True
        time.sleep(0.25)
    return False


def tag_body(bare: Path, ref: str) -> str:
    return git(bare, "for-each-ref", "--format=%(contents)", ref)


def test_the_pushed_ref_carries_the_provenance_the_audit_reads(armed: tuple[Path, Path]) -> None:
    """THE POSITIVE CONTROL, and every degradation arm below is meaningless without it.

    The message shape is not this file's invention: it is the same ``mefor-rescue-v1`` block
    ``rescue.ps1 -Anchor`` writes and ``-Check`` parses, so a hook-written ref and an operator-written
    one grade identically.
    """
    repo, bare = armed
    sha = commit(repo, "one\n")
    ref = "refs/tags/rescue/auto/r/main"

    assert wait_for_ref(bare, ref), "the durability push never landed"
    assert git(bare, "for-each-ref", "--format=%(objecttype)", ref) == "tag", (
        "a bare ref again -- nothing can be read back from it"
    )
    body = tag_body(bare, ref)
    assert "mefor-rescue-v1" in body
    assert f"commit: {sha}" in body
    assert "branch: main" in body
    assert "was-tip: True" in body
    assert "writer: durability_push.sh" in body


def test_the_ref_reports_its_COMMIT_and_not_the_tag_object(armed: tuple[Path, Path]) -> None:
    """The trap the item flags by name, pinned where the sha is actually published.

    ``rev-parse`` on this ref returns the TAG OBJECT. Ancestry and diffstat dereference silently, so
    a wrong sha survives every check a reader is likely to run and only fails when someone pastes it
    into a log. One such sha was published and corrected while #1349 was being written.
    """
    repo, bare = armed
    sha = commit(repo, "one\n")
    ref = "refs/tags/rescue/auto/r/main"
    assert wait_for_ref(bare, ref)

    tag_object = git(bare, "rev-parse", ref)
    assert tag_object != sha, "fixture is not annotated -- this test would prove nothing"
    assert git(bare, "rev-parse", f"{ref}^{{commit}}") == sha
    assert git(bare, "for-each-ref", "--format=%(*objectname)", ref) == sha
    # The recorded sha must be the COMMIT too, or -Check compares a tag object against a branch tip
    # and reports ALTERED about a ref that is perfectly sound.
    assert f"commit: {sha}" in tag_body(bare, ref)


def test_no_LOCAL_ref_is_created_so_provenance_cannot_leak_to_a_public_remote(
    armed: tuple[Path, Path],
) -> None:
    """The failure mode the design avoids, asserted rather than asserted-in-a-comment.

    Building the tag object with ``hash-object`` and pushing it BY ID leaves nothing locally for
    ``git push --follow-tags`` or ``git push --tags`` to carry to ``origin``. Writing the same
    annotated tag under ``refs/tags/`` first would have been simpler and would have made the
    durability hook a publication channel, which is the one thing it must never become.
    """
    repo, bare = armed
    commit(repo, "one\n")
    assert wait_for_ref(bare, "refs/tags/rescue/auto/r/main")

    local = git(repo, "for-each-ref", "--format=%(refname)", "refs/tags")
    assert local == "", f"the hook left a local tag behind: {local}"


def test_a_DETACHED_capture_omits_was_tip_rather_than_guessing(armed: tuple[Path, Path]) -> None:
    """A missing answer and a negative answer must not collapse into one.

    With no branch there is no tip to have been, so both ``True`` and ``False`` would be claims about
    a branch that does not exist. Leaving the line out is what makes ``-Check`` say SELF-DESCRIBING:
    intact, and whether it held a tip cannot be told. That is the true statement here.
    """
    repo, bare = armed
    commit(repo, "one\n")
    git(repo, "checkout", "-q", "--detach")
    sha = commit(repo, "two\n")
    short = git(repo, "rev-parse", "--short", "HEAD")
    ref = f"refs/tags/rescue/auto/r/detached/{short}"

    assert wait_for_ref(bare, ref), "a detached HEAD is the state most likely to lose work"
    body = tag_body(bare, ref)
    assert "was-tip:" not in body, "guessed an answer about a branch that does not exist"
    assert "branch: (detached)" in body
    assert f"commit: {sha}" in body


def test_a_BROKEN_IDENTITY_degrades_to_a_bare_push_and_the_hook_still_exits_0(
    armed: tuple[Path, Path],
) -> None:
    """THE DEGRADATION ARM. A post-commit hook must never fail a commit, whatever else goes wrong.

    ``git hash-object`` fsck-validates the tag object and refuses a malformed tagger line, and
    ``git var GIT_COMMITTER_IDENT`` fails outright on an empty name -- measured, not assumed:
    ``fatal: empty ident name (for <t@e.com>) not allowed``, exit 128. That is the whole class of new
    failure this change introduced, driven here through its most reachable trigger.

    The requirement is not that provenance survives. It is that DURABILITY does: the ref still lands,
    the exit status is still 0, and the operator is told once rather than left to discover a silent
    downgrade. The hook is invoked directly because the sabotage would otherwise break the commit
    itself, and the question is about the hook.

    THE HOOK IS DISARMED WHILE THE FIXTURE COMMIT IS MADE, and that is not tidiness. Leaving it armed
    would fire a healthy backgrounded push for the same ref, racing the sabotaged one -- and whichever
    landed second would decide the assertion. A test whose verdict depends on which of two pushes wins
    reports scheduling, not behaviour.
    """
    repo, bare = armed
    git(repo, "config", "--unset", "mefor.durabilityRemote")
    git(repo, "checkout", "-q", "-b", "sabotaged")
    sha = commit(repo, "two\n")
    git(repo, "config", "mefor.durabilityRemote", "priv")
    assert git(bare, "for-each-ref", "--format=%(refname)") == "", "the fixture commit pushed"

    env = dict(os.environ, GIT_COMMITTER_NAME="")
    proc = subprocess.run(
        ["sh", str(repo / ".git" / "hooks" / "post-commit")],
        cwd=str(repo),
        env=env,
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
    )

    assert proc.returncode == 0, "a post-commit hook that exits non-zero is a broken commit"
    assert "WARNING" in proc.stderr, "a silent downgrade is how a control stops protecting anything"
    assert "DURABILITY IS UNAFFECTED" in proc.stderr

    ref = "refs/tags/rescue/auto/r/sabotaged"
    assert wait_for_ref(bare, ref), "provenance failed and took durability down with it"
    assert git(bare, "for-each-ref", "--format=%(objecttype)", ref) == "commit"
    assert git(bare, "rev-parse", ref) == sha


def test_an_UNREACHABLE_remote_does_not_fail_the_commit(armed: tuple[Path, Path]) -> None:
    """The ordinary field failure: the nominated remote is gone, offline, or misspelled.

    Nothing here can report that, and it deliberately does not try -- the reporting job belongs to
    ``unbacked_check.ps1``, which measures the true state rather than trusting this hook ran. What
    must hold is that the commit is unaffected.
    """
    repo, bare = armed
    commit(repo, "one\n")
    git(repo, "remote", "set-url", "priv", str(bare.parent / "not-a-repo.git"))

    commit(repo, "two\n")  # asserts returncode 0 internally
    assert git(repo, "rev-list", "--count", "HEAD") == "2"


def test_an_UNARMED_hook_pushes_nothing_and_the_commit_stands(armed: tuple[Path, Path]) -> None:
    """Fail-safe by absence. A fresh clone, a CI checkout or a contributor's fork must push nowhere.

    This is the negative control for the whole file: without it, a hook that pushed unconditionally
    would satisfy every other test here.
    """
    repo, bare = armed
    git(repo, "config", "--unset", "mefor.durabilityRemote")
    commit(repo, "one\n")

    assert git(bare, "for-each-ref", "--format=%(refname)") == "", "pushed without being armed"


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="pwsh (PowerShell 7) not on PATH")
def test_a_hook_written_ref_is_still_readable_AFTER_the_branch_is_deleted(
    armed: tuple[Path, Path], tmp_path: Path
) -> None:
    """THE PAYOFF, and the only state that matters: the branch is gone and the ref still speaks.

    This is the population #1349 is about -- a rescue ref is consulted once, after the original is
    already gone, and 436 of one measured namespace's 730 refs name a branch that no longer exists.
    Before this change the hook's refs came back UNVERIFIABLE there, which is the honest verdict for
    a ref recording nothing and a useless one for somebody deciding what to recover.

    The audit is run in a CONSUMER of the remote rather than in the writing repository, because that
    is the real shape: the refs arrive under ``refs/remotes/<remote>/rescuetags/*`` through the fetch
    refspec, which is the namespace the audit was widened to read in the same change.
    """
    repo, bare = armed
    git(repo, "checkout", "-q", "-b", "doomed")
    sha = commit(repo, "work that outlives its branch\n")
    assert wait_for_ref(bare, "refs/tags/rescue/auto/r/doomed")

    consumer = tmp_path / "consumer"
    subprocess.run(
        ["git", "init", "-q", "-b", "main", str(consumer)], check=True, capture_output=True
    )
    (consumer / "scripts" / "coord").mkdir(parents=True)
    shutil.copy2(RESCUE, consumer / "scripts" / "coord" / "rescue.ps1")
    git(consumer, "remote", "add", "priv", str(bare))
    git(
        consumer,
        "config",
        "--add",
        "remote.priv.fetch",
        "+refs/tags/rescue/*:refs/remotes/priv/rescuetags/*",
    )
    git(consumer, "fetch", "-q", "priv")
    # The branch never existed here, which is exactly the state a rescue ref is read in.
    assert git(consumer, "for-each-ref", "--format=%(refname)", "refs/heads") == ""

    proc = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(consumer / "scripts" / "coord" / "rescue.ps1"),
            "-Check",
        ],
        cwd=str(consumer),
        capture_output=True,
        text=True,
        timeout=TIMEOUT * 2,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
    assert "HELD-THE-TIP" in proc.stdout, proc.stdout
    assert "UNVERIFIABLE" not in proc.stdout, proc.stdout
    # And the recorded sha is the COMMIT, so a reader who acts on it reaches the work.
    assert sha in git(
        consumer, "for-each-ref", "--format=%(contents)", "refs/remotes/priv/rescuetags"
    )
