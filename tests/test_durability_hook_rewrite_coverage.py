# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A rewrite must not silently drop what the rescue tag used to cover.

``scripts/hooks/durability_push.sh`` writes ONE ref per branch and force-moves it on every commit.
That is correct while history only grows: the old value is an ancestor of the new one, so the move
costs nothing. After a rebase, an amend or a reset it is not an ancestor, and the force-move made
the discarded commits reachable from no ref on the remote at all.

**THE FAILURE MODE IS SILENCE, WHICH IS WHY THIS IS TESTED RATHER THAN NOTED.** The tag still
exists, the push still succeeds, and nothing anywhere reports that the ref stopped covering the
commits it used to. A durability control that quietly narrows is worse than one that is absent,
because the absent one is not trusted.

Measured 2026-09-20 against the pre-fix hook, in a throwaway repository: two commits on a branch, a
rebase onto a moved ``main``, then one more commit, and both pre-rebase commits were reachable from
NO ref in the bare remote. The same query asked of the new tip named the moving tag, so the scan
that returned "no coverage" was not a broken scan. That pairing is reproduced here as
``test_an_ordinary_commit_creates_NO_orphan_ref``: without it, a hook that wrote an orphan ref on
every single commit would satisfy every positive test in this file.

**A NEGATIVE ASSERTION HERE IS A RACE UNLESS IT WAITS FOR SOMETHING FIRST.** The push is detached,
so "the orphan ref is absent" is trivially true the instant after ``git commit`` returns. Every
absence assertion below therefore waits for the MOVING tag to reach its new commit first, and only
then asks about the orphan -- the push that would have written one has demonstrably finished.

**AND THE REMOTE TAG IS NOT THE HOOK'S LAST WRITE.** The local ``$LAST`` ref lands after it. So a
test that reads ``$LAST`` next, or commits again on the same branch and so makes the hook read it,
waits on ``wait_for_landed`` instead, which waits for both.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
#: Overridable, as in the sibling suites, so this file can be run against a MODIFIED copy of the
#: current hook -- for example one with a delay before its ``update-ref``:
#:     MEFOR_DURABILITY_HOOK=/tmp/delayed.sh pytest <this file>
#: NOT a red-first control against a hook older than ``$LAST``: every ``wait_for_landed`` then fails
#: in setup, the negative control included, before any test reaches the defect it exists for.
HOOK = Path(
    os.environ.get("MEFOR_DURABILITY_HOOK") or (ROOT / "scripts" / "hooks" / "durability_push.sh")
)
TIMEOUT = 180
#: The push is detached, so the remote is polled. Generous for the same reason the sibling file
#: states: a short budget on a saturated box measures load, not behaviour.
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
    """A checkout with the hook armed, plus the bare remote it pushes to.

    ``core.longpaths`` is set on the bare remote deliberately. An orphan ref carries a twelve-character
    sha as an extra path segment, so it is the longest name this hook writes, and a loose ref is a
    file: on Windows the combination hit MAX_PATH while this test was being developed and the push
    failed with ``unable to write file ... Filename too long``, which reads as a hook fault.

    The repository directory is named ``r`` to match the sibling suite, because the hook derives the
    ``<repo>`` path segment from the git common dir's parent and the refnames are spelled out below.
    """
    bare = tmp_path / "priv.git"
    subprocess.run(
        ["git", "init", "-q", "--bare", "-b", "main", str(bare)], check=True, capture_output=True
    )
    git(bare, "config", "core.longpaths", "true")
    repo = tmp_path / "r"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True, capture_output=True)
    git(repo, "config", "user.email", "t@example.invalid")
    git(repo, "config", "user.name", "t")
    git(repo, "config", "core.longpaths", "true")
    git(repo, "config", "commit.gpgsign", "false")
    hook = repo / ".git" / "hooks" / "post-commit"
    shutil.copy2(HOOK, hook)
    hook.chmod(0o755)
    git(repo, "remote", "add", "priv", str(bare))
    git(repo, "config", "mefor.durabilityRemote", "priv")
    return repo, bare


def commit(repo: Path, name: str, text: str) -> str:
    (repo / name).write_text(text, encoding="utf-8")
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


def peel(bare: Path, ref: str) -> str:
    """The COMMIT a ref names, empty if it does not resolve.

    Through ``^{commit}`` because these refs are annotated tags and ``rev-parse`` on one returns the
    TAG OBJECT -- the trap the sibling suite pins by name.
    """
    got = subprocess.run(
        ["git", "-C", str(bare), "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
    )
    return got.stdout.strip() if got.returncode == 0 else ""


def wait_for_commit(bare: Path, ref: str, sha: str) -> bool:
    """Poll until ``ref`` names ``sha``. The detached push is why this is a poll and not a read."""
    deadline = time.monotonic() + PUSH_WAIT
    while time.monotonic() < deadline:
        if peel(bare, ref) == sha:
            return True
        time.sleep(0.25)
    return False


def wait_for_landed(repo: Path, bare: Path, tag: str, sha: str) -> bool:
    """Poll until BOTH the remote ``tag`` and the local ``$LAST`` name ``sha``.

    **THE REMOTE TAG ALONE DOES NOT MEAN THE HOOK HAS FINISHED.** The hook writes ``$LAST`` only
    after the moving push succeeds, so for a moment the bare remote names ``sha`` and the local ref
    does not. Anything that reads ``$LAST`` in that window reads the old value: an assertion here,
    or the hook itself on the NEXT commit, which decides from ``$LAST`` whether it is a rewrite.
    CI showed it as an assertion whose message printed the expected list -- the ref was absent at
    the comparison and present by the time the message was built. Measured 2026-09-22 with a
    ``sleep`` before the hook's ``update-ref``: at 80ms, 8 of 15 runs failed, 6 in exactly that
    shape.

    ``$LAST`` is derived from ``tag`` the way the hook derives it.
    """
    last = "refs/mefor/durability/" + tag.removeprefix("refs/tags/rescue/auto/")
    deadline = time.monotonic() + PUSH_WAIT
    while time.monotonic() < deadline:
        if peel(bare, tag) == sha and peel(repo, last) == sha:
            return True
        time.sleep(0.25)
    return False


def refs(bare: Path, prefix: str = "") -> list[str]:
    args = ["for-each-ref", "--format=%(refname)"]
    if prefix:
        args.append(prefix)
    out = git(bare, *args)
    return [line for line in out.splitlines() if line.strip()]


def covers(bare: Path, ref: str, sha: str) -> bool:
    """Is ``sha`` reachable from ``ref``? THE EXIT CODE, not the output -- there is none."""
    return (
        subprocess.run(
            ["git", "-C", str(bare), "merge-base", "--is-ancestor", sha, ref],
            capture_output=True,
            timeout=TIMEOUT,
        ).returncode
        == 0
    )


MOVING = "refs/tags/rescue/auto/r/feature"
ORPHANS = "refs/tags/rescue/orphan"


def _feature_with_two_commits(repo: Path, bare: Path) -> tuple[str, str]:
    """A branch whose tip is captured on the remote, ready to be rewritten. Returns (tip, first)."""
    commit(repo, "base.txt", "base\n")
    git(repo, "checkout", "-q", "-b", "feature")
    first = commit(repo, "a.txt", "one\n")
    # Landed before the next commit, so the two detached pushes cannot finish out of order and put
    # the remote tag or ``$LAST`` back on ``first`` after the wait below has seen both on ``tip``.
    assert wait_for_landed(repo, bare, MOVING, first), "the first capture never landed"
    tip = commit(repo, "b.txt", "two\n")
    assert wait_for_landed(repo, bare, MOVING, tip), "the pre-rewrite capture never landed"
    return tip, first


def test_a_REBASE_no_longer_orphans_the_tip_the_tag_used_to_cover(
    armed: tuple[Path, Path],
) -> None:
    """THE DEFECT, driven through the sequence that produced it.

    The loss needs two steps, and the second is the one that is easy to miss: the rebase alone is
    harmless, because nothing re-pushes the tag and the remote still holds the old tip. It is the
    NEXT commit on the rewritten branch that force-moves the tag off it.
    """
    repo, bare = armed
    discarded_tip, discarded_first = _feature_with_two_commits(repo, bare)

    git(repo, "checkout", "-q", "main")
    commit(repo, "base.txt", "base\nmain advances\n")
    git(repo, "checkout", "-q", "feature")
    git(repo, "rebase", "main")
    new_tip = commit(repo, "c.txt", "three\n")

    assert wait_for_commit(bare, MOVING, new_tip), "the moving tag never reached the new tip"
    assert not covers(bare, MOVING, discarded_tip), (
        "fixture is not a rewrite -- the moving tag still covers the old tip, so this proves nothing"
    )

    orphans = refs(bare, ORPHANS)
    assert len(orphans) == 1, f"expected exactly one orphan ref, got {orphans}"
    assert orphans[0] == f"{ORPHANS}/r/feature/{discarded_tip[:12]}", orphans[0]
    assert peel(bare, orphans[0]) == discarded_tip
    # Both discarded commits, not merely the tip: the ref is only worth writing if it carries the
    # history behind it.
    assert covers(bare, orphans[0], discarded_first)


def test_an_AMEND_preserves_the_commit_it_replaced(armed: tuple[Path, Path]) -> None:
    """The other everyday rewrite, and far more frequent than a rebase.

    An amend builds a sibling of the commit it replaces, so the old one is not an ancestor of the
    new one and the moving tag steps off it exactly as a rebase makes it do.
    """
    repo, bare = armed
    commit(repo, "base.txt", "base\n")
    git(repo, "checkout", "-q", "-b", "feature")
    replaced = commit(repo, "a.txt", "one\n")
    assert wait_for_landed(repo, bare, MOVING, replaced), (
        "the pre-amend capture never reached both the remote tag and $LAST"
    )

    (repo / "a.txt").write_text("one, corrected\n", encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "--amend", "-m", "one, corrected")
    amended = git(repo, "rev-parse", "HEAD")
    assert amended != replaced

    assert wait_for_commit(bare, MOVING, amended)
    orphan = f"{ORPHANS}/r/feature/{replaced[:12]}"
    assert peel(bare, orphan) == replaced, (
        f"the amended-away commit was dropped; refs: {refs(bare)}"
    )


def test_an_ORDINARY_commit_creates_NO_orphan_ref(armed: tuple[Path, Path]) -> None:
    """THE NEGATIVE CONTROL FOR THIS WHOLE FILE, and without it the positives are worthless.

    A hook that wrote an orphan ref on every commit would satisfy every other test here while
    turning a bounded namespace into one ref per commit. The preserve step must fire on a rewrite
    and on nothing else.

    The absence is asked only AFTER the moving tag has reached the new commit, so the push that
    would have written an orphan has finished. Asked any earlier it is a race that always passes.
    """
    repo, bare = armed
    _tip, _first = _feature_with_two_commits(repo, bare)
    third = commit(repo, "c.txt", "three\n")

    assert wait_for_commit(bare, MOVING, third)
    assert refs(bare, ORPHANS) == [], "an orphan ref was written for a plain fast-forward commit"


def test_the_FIRST_commit_on_a_branch_creates_no_orphan(armed: tuple[Path, Path]) -> None:
    """The arm where there is nothing to compare against, which must not read as a rewrite.

    ``git merge-base --is-ancestor`` exits 128, not 1, when a name does not resolve -- measured on
    git 2.55.0.windows.5. Collapsing 128 into "not an ancestor" would make every branch's first
    commit try to preserve a ref that does not exist.
    """
    repo, bare = armed
    first = commit(repo, "base.txt", "base\n")

    assert wait_for_commit(bare, "refs/tags/rescue/auto/r/main", first)
    assert refs(bare, ORPHANS) == []


def test_the_orphan_ref_is_SELF_DESCRIBING_and_names_what_displaced_it(
    armed: tuple[Path, Path],
) -> None:
    """A ref that records nothing can only be graded against a branch that still exists.

    That is the population the provenance item was about, and an orphan ref is squarely in it: it is
    read once, after the work is already unreachable from every branch. It carries the same
    ``mefor-rescue-v1`` block ``rescue.ps1 -Check`` parses, plus the one fact that decides a
    recovery -- which commit displaced this one.

    **NO was-tip LINE, AND THAT IS ASSERTED.** ``was-tip`` answers "was this the branch tip when
    captured", and this ref is captured precisely because it no longer is. ``False`` is literally
    true and renders as SHORT-AT-CAPTURE, "a partial snapshot", which is the opposite of what a
    reader should conclude about the only remaining copy of discarded work. ``True`` would be a
    straight falsehood. Omitting it gives SELF-DESCRIBING, the neutral verdict.
    """
    repo, bare = armed
    replaced = commit(repo, "base.txt", "base\n")
    git(repo, "checkout", "-q", "-b", "feature")
    replaced = commit(repo, "a.txt", "one\n")
    assert wait_for_landed(repo, bare, MOVING, replaced), (
        "the pre-amend capture never reached both the remote tag and $LAST"
    )
    (repo / "a.txt").write_text("one, corrected\n", encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "--amend", "-m", "one, corrected")
    amended = git(repo, "rev-parse", "HEAD")
    assert wait_for_commit(bare, MOVING, amended)

    orphan = f"{ORPHANS}/r/feature/{replaced[:12]}"
    assert git(bare, "for-each-ref", "--format=%(objecttype)", orphan) == "tag", (
        "a bare ref again -- nothing can be read back from it once the branch is gone"
    )
    body = git(bare, "for-each-ref", "--format=%(contents)", orphan)
    assert "mefor-rescue-v1" in body
    assert f"commit: {replaced}" in body
    assert "branch: feature" in body
    assert f"orphaned-by: {amended}" in body
    assert "writer: durability_push.sh" in body
    assert "was-tip:" not in body


def test_the_bookkeeping_ref_is_outside_refs_tags_so_a_tag_sweep_cannot_publish_it(
    armed: tuple[Path, Path], tmp_path: Path
) -> None:
    """The hazard the whole hook is built around, re-checked against the ref this change adds.

    Knowing which commit was last pushed needs state, and that state is a LOCAL ref -- by being a
    ref it also keeps the discarded object reachable, which is what makes the rescue possible at
    all. A ref under ``refs/tags/`` would be swept to whatever remote a hand reaches for by
    ``git push --tags`` or ``--follow-tags``, and the default one in this project is PUBLIC.

    ``refs/mefor/`` is outside both sweeps. It is also outside ``push_guard.py``'s
    ``PUSHABLE_NAMESPACES``, so the one flag that does offer every ref, ``--mirror``, is refused
    there by a second mechanism.
    """
    repo, bare = armed
    sha = commit(repo, "base.txt", "base\n")
    assert wait_for_landed(repo, bare, "refs/tags/rescue/auto/r/main", sha), (
        "the remote tag and the local bookkeeping ref never both reached the commit"
    )

    # Read ONCE, so the message shows the value that was compared and not a later one.
    mefor = refs(repo, "refs/mefor")
    assert mefor == ["refs/mefor/durability/r/main"], mefor
    assert refs(repo, "refs/tags") == [], "a local tag would be swept to a public remote"

    elsewhere = tmp_path / "elsewhere.git"
    subprocess.run(
        ["git", "init", "-q", "--bare", "-b", "main", str(elsewhere)],
        check=True,
        capture_output=True,
    )
    git(repo, "remote", "add", "elsewhere", str(elsewhere))
    git(repo, "push", "-q", "--follow-tags", "elsewhere", "main")
    git(repo, "push", "-q", "--tags", "elsewhere")

    landed = refs(elsewhere)
    # The control: the push must actually have reached the remote, or the absence below is the
    # absence of a push rather than the absence of a leak.
    assert "refs/heads/main" in landed, landed
    assert [r for r in landed if "mefor" in r or "rescue" in r] == [], landed
