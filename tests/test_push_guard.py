"""Tests for the push guard (scripts/hooks/push_guard.py).

Since the MEFORORG cutover this repository IS the published artifact -- a push to ``main`` is
publication, immediately, with no publish step left to catch anything. Server-side branch protection
requires a PR and a set of required status checks; the count is deliberately not repeated here,
because it rots (``.github/required-contexts.txt`` is the checked-in claim, and this file is one of
the claim files ``tests/test_required_contexts.py`` scans for exactly that). Those checks gate
MERGING a pull request, not the push these tests exercise.

``enforce_admins`` was ON from 2026-07-28 but is OFF again as of 2026-07-29 -- the documented escape
hatch in the hook's own HISTORY note -- so for an admin protection does not apply to a direct push at
all, and this hook is the ONLY thing refusing it, exactly as when it was first written. An earlier
revision of this docstring called it "defence-in-depth"; that rested on the same false premise the
hook's own deny message carried, that the server would refuse the push anyway. It covers
``cla-signatures`` either way, which branch protection does not. The realistic trigger is unchanged:
one click on VS Code's Sync button while the current branch happens to be ``main``.

THREE GUARDS, THREE QUESTIONS, and the sections below follow that split. PROTECTED asks WHERE a push
lands. Guard A (``PUSHABLE_NAMESPACES``) asks WHICH REFS it offers -- the ``--mirror`` shape. Guard B
(``PRIVATE_TREES``) asks WHAT THOSE REFS CARRY. Each section pairs a refusal with the ordinary push it
must still permit, because a guard that refuses everything passes every refusal test there is.

Every test feeds the script the EXACT stdin contract git uses for a pre-push hook --
``<local ref> <local sha> <remote ref> <remote sha>``, one line per ref -- so what is asserted is the
interface git will actually invoke, not a convenience wrapper. The Guard B tests go further and build
a REAL throwaway repository with real commits, because that guard's answer comes from ``git ls-tree``
against a real object: fed a synthetic sha it returns "clean" for every ref alike, and a suite written
that way would be green whether or not the guard worked.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
_GUARD = _REPO / "scripts" / "hooks" / "push_guard.py"
_INSTALLER = _REPO / "scripts" / "coord" / "install-git-hooks.ps1"

_SHA = "a" * 40
_ZERO = "0" * 40


def _run(
    refs: str,
    env_extra: dict[str, str] | None = None,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    env = None
    if env_extra:
        env = {**os.environ, **env_extra}
    return subprocess.run(
        [sys.executable, str(_GUARD)],
        input=refs,
        capture_output=True,
        text=True,
        env=env,
        cwd=str(cwd) if cwd else None,
        check=False,
    )


# --------------------------------------------------------------------------------------------------
# PROTECTED -- where the push lands.
# --------------------------------------------------------------------------------------------------


def test_a_direct_push_to_main_is_refused() -> None:
    r = _run(f"refs/heads/x {_SHA} refs/heads/main {_ZERO}\n")
    assert r.returncode == 1, r.stderr
    assert "REFUSED" in r.stderr


def test_deleting_main_is_refused() -> None:
    """A deletion has an all-zero LOCAL sha. Deleting main is worse than pushing to it."""
    r = _run(f"refs/heads/x {_ZERO} refs/heads/main {_SHA}\n")
    assert r.returncode == 1, r.stderr
    assert "DELETE" in r.stderr


def test_the_cla_signature_branch_is_protected() -> None:
    """Written by the CLA Assistant action, never by a human — and every PR wedges if it is damaged."""
    r = _run(f"refs/heads/x {_SHA} refs/heads/cla-signatures {_ZERO}\n")
    assert r.returncode == 1, r.stderr


def test_an_ordinary_branch_push_is_allowed() -> None:
    """The control. Without this, a guard that refused EVERYTHING would look identical to a working one."""
    r = _run(f"refs/heads/x {_SHA} refs/heads/feature-y {_ZERO}\n")
    assert r.returncode == 0, r.stderr
    assert r.stderr.strip() == ""


def test_a_mixed_push_is_refused_because_one_ref_is_protected() -> None:
    """git sends one line per ref, so a multi-ref push is one hook run: one protected ref must sink it.

    ``git push --all`` produces this shape -- and only this shape. It sends every ref under
    ``refs/heads/``, NOT every ref: ``git bundle create --all`` and ``git rev-list --all`` mean every
    ref, ``git push --all`` does not, and ``git push --mirror`` is the flag that does. An earlier
    revision of this docstring asserted the opposite ("`git push --all` sends every ref at once"),
    which is the precise belief that makes ``--all`` and ``--mirror`` look interchangeable -- and
    ``--mirror`` is the one that offers remote-tracking refs. Guard A exists for that flag, and
    ``test_an_all_shaped_push_of_ordinary_branches_is_permitted`` pins the difference from the other
    side.
    """
    r = _run(
        f"refs/heads/a {_SHA} refs/heads/feature-y {_ZERO}\n"
        f"refs/heads/b {_SHA} refs/heads/main {_ZERO}\n"
    )
    assert r.returncode == 1, r.stderr


def test_the_escape_hatch_works_and_says_so() -> None:
    """Deliberately NOT --no-verify: a distinct variable is greppable in shell history, and cannot be
    reached by the muscle memory that skips every other hook at once."""
    r = _run(
        f"refs/heads/x {_SHA} refs/heads/main {_ZERO}\n",
        {"MEFOR_ALLOW_DIRECT_PUSH": "1"},
    )
    assert r.returncode == 0, r.stderr
    assert "ALLOWED" in r.stderr


def test_malformed_stdin_does_not_crash_the_push() -> None:
    """git sends nothing at all for some invocations. Fail OPEN on garbage rather than wedging pushes —
    the guard exists to stop an accident, and crashing on unexpected input would BE one."""
    r = _run("not four fields\n\n")
    assert r.returncode == 0, r.stderr


# --------------------------------------------------------------------------------------------------
# GUARD A -- which refs the push offers. `git push --mirror` offers every ref under refs/, including
# remote-tracking namespaces an ordinary push never names.
# --------------------------------------------------------------------------------------------------


def test_a_remote_tracking_ref_is_refused() -> None:
    """The ``--mirror`` shape, minus the coincidence that used to catch it.

    Nothing here touches ``refs/heads/main``: this is the mirror line for a remote-tracking ref alone.
    Before Guard A it would have returned 0 on its own, and a real mirror push was refused only
    because it ALSO offered local main as a forced update -- a property of one branch's state, not a
    rule. Assert on the namespace being named in the output, not merely on the exit code, so a refusal
    that happened for some unrelated reason cannot pass as this one.
    """
    r = _run(f"refs/remotes/vault/main {_SHA} refs/remotes/vault/main {_ZERO}\n")
    assert r.returncode == 1, r.stderr
    assert "refs/remotes/vault/main" in r.stderr
    assert "non-branch/tag ref" in r.stderr


@pytest.mark.parametrize(
    "remote_ref",
    [
        "refs/remotes/origin/main",
        "refs/notes/commits",
        "refs/replace/1234567890123456789012345678901234567890",
        "refs/stash",
        "refs/keep-around/abc",
    ],
)
def test_every_non_branch_non_tag_namespace_is_refused(remote_ref: str) -> None:
    """An ALLOWLIST, so an unfamiliar namespace is refused without anyone having enumerated it."""
    r = _run(f"refs/heads/x {_SHA} {remote_ref} {_ZERO}\n")
    assert r.returncode == 1, r.stderr


def test_a_tag_push_is_permitted() -> None:
    """The other half of the allowlist, and a real workflow: release.yml fires on a tag push."""
    r = _run(f"refs/tags/v9.9.9 {_SHA} refs/tags/v9.9.9 {_ZERO}\n")
    assert r.returncode == 0, r.stderr
    assert r.stderr.strip() == ""


def test_an_all_shaped_push_of_ordinary_branches_is_permitted() -> None:
    """Guard A must NOT fire on ``git push --all``, and saying so is the honest half of the guard.

    ``--all`` sends every ref under ``refs/heads/`` and nothing else, so every line it produces is
    inside the allowlist. Guard A is a check on ``--mirror``, and claiming it covers ``--all`` would
    be a compensating-control claim resting on a false premise. What still catches an ``--all`` push
    is PROTECTED (main is in the set) and Guard B (the tip trees) -- see the mixed-push test above.
    """
    r = _run(
        f"refs/heads/a {_SHA} refs/heads/feature-a {_ZERO}\n"
        f"refs/heads/b {_SHA} refs/heads/feature-b {_ZERO}\n"
    )
    assert r.returncode == 0, r.stderr
    assert r.stderr.strip() == ""


# --------------------------------------------------------------------------------------------------
# GUARD B -- what the pushed refs carry. Against a REAL repository: this guard's answer comes from
# `git ls-tree` on a real object, and a synthetic sha makes every ref read as clean.
# --------------------------------------------------------------------------------------------------


def _git(repo: Path, *args: str) -> str:
    out = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=True,
    )
    return out.stdout.strip()


@pytest.fixture(scope="module")
def tree_repo(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, str, str]:
    """A throwaway repo with two commits: (clean tip, tip carrying docs/security).

    The private file is added with ``-f`` against a ``.gitignore`` that carries the real
    ``/docs/security/`` rule, because that is the exact condition Guard B exists for and the one the
    ignore rule cannot address: an ignore rule governs UNTRACKED paths only, so a ref whose history
    already tracks those files carries them past it without complaint. Reproducing that faithfully is
    what stops this fixture proving something easier than the real case.

    ``core.hooksPath`` is pointed at an empty directory: it is set at REPO scope in this checkout, so
    a fresh temp repo does not inherit it -- but relying on that is relying on a config that could
    move to global scope on any box, and a fixture that runs this repo's real commit-msg/pre-commit
    hooks against throwaway commits would fail for reasons that have nothing to do with the guard.
    """
    repo = tmp_path_factory.mktemp("push_guard_tree")
    nohooks = tmp_path_factory.mktemp("push_guard_nohooks")
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "core.hooksPath", str(nohooks))
    _git(repo, "config", "user.email", "test@example.invalid")
    _git(repo, "config", "user.name", "push guard test")
    _git(repo, "config", "commit.gpgsign", "false")

    (repo / ".gitignore").write_text("/docs/security/\n", encoding="utf-8")
    (repo / "README.md").write_text("ordinary work\n", encoding="utf-8")
    _git(repo, "add", ".gitignore", "README.md")
    _git(repo, "commit", "-m", "clean tip")
    clean = _git(repo, "rev-parse", "HEAD")

    private = repo / "docs" / "security"
    private.mkdir(parents=True)
    (private / "NOTES.md").write_text("maintainer-internal working document\n", encoding="utf-8")
    _git(repo, "add", "-f", "docs/security/NOTES.md")
    _git(repo, "commit", "-m", "tip carrying a private tree")
    dirty = _git(repo, "rev-parse", "HEAD")

    assert clean != dirty
    return repo, clean, dirty


def test_the_fixture_really_tracks_the_private_tree(tree_repo: tuple[Path, str, str]) -> None:
    """Guard the fixture before asserting anything with it.

    If ``add -f`` had not beaten the ignore rule, the "dirty" tip would be clean and the refusal test
    below would go green for the wrong reason -- the false-GREEN shape a content gate is most exposed
    to. Assert the setup from git's own view of both tips, in both directions.
    """
    repo, clean, dirty = tree_repo
    assert _git(repo, "ls-tree", "-r", "--name-only", dirty, "--", "docs/security"), (
        "the fixture's 'dirty' commit does not actually track docs/security -- every Guard B "
        "assertion below would then pass vacuously"
    )
    assert _git(repo, "ls-tree", "-r", "--name-only", clean, "--", "docs/security") == "", (
        "the fixture's 'clean' commit already carries docs/security -- the permit case is not a "
        "control"
    )


def test_a_ref_whose_tip_tree_carries_private_docs_is_refused(
    tree_repo: tuple[Path, str, str],
) -> None:
    """The highest-likelihood path, and the only guard that sees it.

    An ordinary-looking branch, an ordinary-looking namespace, no protected ref anywhere: PROTECTED
    and Guard A both pass this line. What it carries is the whole objection.
    """
    repo, _clean, dirty = tree_repo
    r = _run(f"refs/heads/wip {dirty} refs/heads/wip {_ZERO}\n", cwd=repo)
    assert r.returncode == 1, r.stderr
    assert "docs/security/NOTES.md" in r.stderr, r.stderr
    assert "tip tree" in r.stderr


def test_a_ref_whose_tip_tree_is_clean_is_permitted(tree_repo: tuple[Path, str, str]) -> None:
    """The control that makes the refusal above mean something: same repo, same ref name, clean tip."""
    repo, clean, _dirty = tree_repo
    r = _run(f"refs/heads/wip {clean} refs/heads/wip {_ZERO}\n", cwd=repo)
    assert r.returncode == 0, r.stderr
    assert r.stderr.strip() == ""


def test_a_tag_pointing_at_a_private_tree_is_refused(tree_repo: tuple[Path, str, str]) -> None:
    """The allowlist admits refs/tags/, so Guard A does not look at a tag. Guard B must."""
    repo, _clean, dirty = tree_repo
    r = _run(f"refs/tags/v9.9.9 {dirty} refs/tags/v9.9.9 {_ZERO}\n", cwd=repo)
    assert r.returncode == 1, r.stderr
    assert "docs/security/NOTES.md" in r.stderr


def test_deleting_an_unprotected_ref_is_still_permitted(tree_repo: tuple[Path, str, str]) -> None:
    """A deletion has no local tip to read, and removing a ref publishes nothing. Guard B skips it
    rather than trying to ls-tree the all-zero sha, which would refuse (or error on) every delete."""
    repo, _clean, _dirty = tree_repo
    r = _run(f"refs/heads/gone {_ZERO} refs/heads/gone {_SHA}\n", cwd=repo)
    assert r.returncode == 0, r.stderr
    assert r.stderr.strip() == ""


def test_a_tip_tree_the_guard_cannot_read_is_treated_as_clean(
    tree_repo: tuple[Path, str, str],
) -> None:
    """FAIL-OPEN, pinned deliberately so the gap is a decision and not a discovery.

    An object git cannot resolve reads as clean. git only ever hands a pre-push hook local objects, so
    this is not a real push path -- it is the path the other tests in this file reach with ``_SHA``,
    and pinning it here is what keeps THOSE tests honest: they permit because the guard could not
    look, not because it looked and approved.
    """
    repo, _clean, _dirty = tree_repo
    r = _run(f"refs/heads/wip {_SHA} refs/heads/wip {_ZERO}\n", cwd=repo)
    assert r.returncode == 0, r.stderr
    assert r.stderr.strip() == ""


def test_guard_b_reads_the_tip_only_and_the_message_says_so(
    tree_repo: tuple[Path, str, str],
) -> None:
    """The documented limit, asserted rather than described.

    A branch that added the files and then removed them has a clean TIP and a dirty HISTORY, and this
    guard permits it. That is not a defect to fix here -- one ``ls-tree`` per ref is the whole cost
    model -- but it is exactly the claim someone would otherwise over-read from a green run, so the
    permit is pinned AND the deny message is required to state the limit where an operator reads it.
    """
    repo, _clean, dirty = tree_repo
    _git(repo, "rm", "-r", "--quiet", "--cached", "docs/security")
    _git(repo, "commit", "-m", "remove the private tree again")
    removed = _git(repo, "rev-parse", "HEAD")
    assert _git(repo, "ls-tree", "-r", "--name-only", removed, "--", "docs/security") == ""

    r = _run(f"refs/heads/wip {removed} refs/heads/wip {_ZERO}\n", cwd=repo)
    assert r.returncode == 0, (
        f"the tip is clean, so Guard B permits -- its history is not read: {r.stderr}"
    )

    # ...and the refusal text must not let anyone read a tip check as a history check.
    denied = _run(f"refs/heads/wip {dirty} refs/heads/wip {_ZERO}\n", cwd=repo)
    assert denied.returncode == 1
    assert "TIP TREE ONLY" in denied.stderr, (
        "the deny message no longer states that this is a tip check, which is the one place an "
        "operator is reading at the moment it matters"
    )


def test_the_escape_hatch_disables_the_content_guard_too(
    tree_repo: tuple[Path, str, str],
) -> None:
    """Bypass surface, pinned as fact rather than left to be discovered.

    ``MEFOR_ALLOW_DIRECT_PUSH`` is named for the protected-branch case and returns before every guard,
    so it switches off the content check as well. That is a guardrail's honest posture -- the hook's
    own docstring calls it one -- but it must be an asserted property, not an assumption: if the
    variable is ever narrowed to the protected-branch check alone, this test is what says so.
    """
    repo, _clean, dirty = tree_repo
    r = _run(
        f"refs/heads/wip {dirty} refs/heads/wip {_ZERO}\n",
        {"MEFOR_ALLOW_DIRECT_PUSH": "1"},
        cwd=repo,
    )
    assert r.returncode == 0, r.stderr
    assert "ALLOWED" in r.stderr


# --------------------------------------------------------------------------------------------------
# WIRING. The tests above prove the logic. None of them notices if nothing ever installs the hook —
# the same gap that let the ledger gate sit silently un-invoked (see test_ledger_check.py).
# --------------------------------------------------------------------------------------------------


def test_the_installer_wires_the_push_guard() -> None:
    src = _INSTALLER.read_text(encoding="utf-8")
    assert "push_guard.py" in src, "installer never copies the guard into .git/hooks"
    assert "WriteAllText($prePush" in src, "installer never writes the pre-push hook"
    # It must refuse to clobber someone else's pre-push hook, and remove its own on -Uninstall.
    assert "Refusing to overwrite it" in src
    assert "Remove-Item -LiteralPath $prePush" in src, "-Uninstall must remove the push guard"


def test_the_shim_fails_CLOSED_when_python_is_absent() -> None:
    """This test previously pinned the OPPOSITE, and the reversal is the point of this branch.

    It read: "NOT a change request -- a pinned statement of the widest bypass in the whole mechanism",
    and it was right about the bypass. The installed ``.git/hooks/pre-push`` exited 0 when neither
    ``python`` nor ``python3`` resolved, so every guard in push_guard.py was off and the only evidence
    was one line on stderr in the middle of git's own push output. That is BACKLOG #1034, and pinning
    it is what made it a decision rather than a discovery -- this test did its job and is now
    collecting on it.

    Naming the bypass kept "the push guard ran and permitted this" distinguishable from "the push
    guard did not run". Failing closed removes the need to distinguish them: the second state no
    longer permits anything.

    Asserted here as a STRING property of the generator, which is all this module can see. The real
    coverage is in tests/test_installed_coord_hooks.py, which parses the here-string, reads the
    interpreter-resolution branch specifically, and EXECUTES the shim body under sh with an empty PATH
    to check the exit code git would actually act on -- a text scan proves the source says exit 1, not
    that the branch is reached.
    """
    src = _INSTALLER.read_text(encoding="utf-8")
    assert "THE PUSH GUARD IS OFF for this push" not in src, (
        "the fail-open notice is back in the generated shim -- BACKLOG #1034 has regressed"
    )
    assert "the push guard cannot run" in src, "the shim no longer explains why it is refusing"
    assert "REFUSING this push" in src, "the shim does not refuse when it cannot run"
    # The way forward has to be named, or a fail-closed gate gets "fixed" by deleting it.
    assert "--no-verify" in src
