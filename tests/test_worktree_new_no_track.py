# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""A new worktree's branch must not inherit the BASE as its upstream (BACKLOG #1087).

THE DEFECT. ``new.ps1`` created the branch with ``git worktree add <path> -b <Branch> <Base>`` and
``-Base`` defaults to ``origin/main``. Git's ``branch.autoSetupMerge`` then set the new branch's
upstream to the remote-tracking **base**, so ``@{u}`` resolved to ``origin/main`` rather than to the
branch's own remote ref. The visible symptom is trivial; the consequence is not. **``@{u}..HEAD``
reports a branch's own commits as "unpushed" forever, including immediately after a successful
push** -- and that number is part of how a session decides whether a worktree is safe to remove. A
session read 2 and 1 unpushed commits on two branches that were byte-identical to their remotes.

WHAT IS ASSERTED, AND WHY IT IS NOT "IS THE UPSTREAM UNSET". Asserting the mechanism passes
trivially and would also pass on a branch nobody ever pushed. The case that distinguishes is a
branch whose tip **equals its pushed remote ref**: on such a branch every instrument keyed on
``@{u}`` must either answer "nothing outstanding" or fail loudly. Answering "1 commit" is the defect.
So the fixture pushes to a real bare origin first, and the assertion is on the reading.

THE CONTROL IS THE PRE-FIX COMMAND ITSELF, run in the same test against the same fixture. It is
written out literally rather than derived by stripping a flag off the current command, so it keeps
reproducing the class no matter which of the two sanctioned fixes ``new.ps1`` carries later
(``--no-track`` at creation, or setting the upstream to the branch's own remote after first push).

NOT AN ACCEPTABLE FIX, and there is a guard for it below: ``git config push.default upstream``. With
the upstream pointing at ``origin/main`` that makes a bare ``git push`` write the feature branch onto
``main``, and push to ``main`` is not blocked server-side on this repo. ``push.default`` being UNSET
-- so git uses ``simple``, which refuses when the upstream's name differs from the branch's -- is
load-bearing.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
_NEW_PS1 = _REPO / "scripts" / "worktree" / "new.ps1"
_SCRIPTS = _REPO / "scripts"

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="new.ps1 is a PowerShell script and these tests run git the way it does on Windows",
)

#: The creation call under test: the arm that cuts a NEW branch off the base. The other arm
#: (``worktree add <path> <Branch>``, reusing an existing branch) sets no upstream and is not it.
_ADD_NEW_BRANCH = re.compile(r"^\s*&\s*(?P<cmd>git\s+.*\bworktree\s+add\b.*-b\s+\$Branch\b.*?)\s*$")


def _code_lines(path: Path) -> list[str]:
    """Non-comment lines. The rationale comments quote the command under test, so scanning raw text
    would let an explanation satisfy the assertion."""
    return [
        ln for ln in path.read_text(encoding="utf-8").splitlines() if not ln.strip().startswith("#")
    ]


def _add_command() -> str:
    matches = [m.group("cmd") for ln in _code_lines(_NEW_PS1) if (m := _ADD_NEW_BRANCH.match(ln))]
    assert len(matches) == 1, (
        f"expected exactly one `worktree add ... -b $Branch` call in {_NEW_PS1.name}, found "
        f"{len(matches)}: {matches}. If creation was restructured, re-point this guard rather than "
        "letting it pass on an empty set."
    )
    return matches[0]


def _render(cmd: str, *, repo_root: Path, worktree: Path, branch: str, base: str) -> list[str]:
    text = cmd
    for token, value in (
        ("$WorktreePath", str(worktree)),
        ("$RepoRoot", str(repo_root)),
        ("$Branch", branch),
        ("$Base", base),
    ):
        text = text.replace(token, value)
    assert "$" not in text, f"unsubstituted variable in the rendered command: {text}"
    return [t.strip('"') for t in shlex.split(text, posix=False)]


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    )
    return proc.stdout


def _git_raw(repo: Path, *args: str) -> tuple[int, str]:
    """Exit code plus combined output -- a non-zero exit here is the answer, not a failure."""
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=False
    )
    return proc.returncode, (proc.stdout + proc.stderr).strip()


class Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.primary = root / "r"
        self.origin = root / "o.git"

    def push_a_commit(self, wt: Path, branch: str) -> None:
        """Commit and PUSH -- the state in which the @{u} reading is taken."""
        (wt / f"{branch}.txt").write_text("work", encoding="utf-8")
        _git(wt, "add", "--", f"{branch}.txt")
        _git(wt, "commit", "-qm", f"work on {branch}")
        _git(wt, "push", "-q", "origin", branch)
        _git(wt, "fetch", "-q", "origin")

    def is_fully_pushed(self, wt: Path, branch: str) -> bool:
        return (
            _git(wt, "rev-parse", "HEAD").strip()
            == _git(wt, "rev-parse", f"refs/remotes/origin/{branch}").strip()
        )


@pytest.fixture
def fx(tmp_path: Path) -> Fixture:
    f = Fixture(tmp_path)
    subprocess.run(["git", "init", "-q", "--bare", str(f.origin)], check=True, capture_output=True)
    # Windows path budget: a bare repo's incoming-objects temp dir is deep, and these run under a
    # pytest tmp path that is already long.
    _git(f.origin, "config", "core.longpaths", "true")
    f.primary.mkdir(parents=True)
    _git(f.primary, "init", "-q", "-b", "main")
    _git(f.primary, "config", "user.email", "t@example.invalid")
    _git(f.primary, "config", "user.name", "t")
    _git(f.primary, "config", "core.longpaths", "true")
    # Pin the setting the defect depends on, so the control reproduces regardless of the developer's
    # global config. `true` is git's own default: set an upstream when branching off a
    # remote-tracking ref, which is exactly the shape new.ps1 uses.
    _git(f.primary, "config", "branch.autoSetupMerge", "true")
    _git(f.primary, "remote", "add", "origin", str(f.origin))
    (f.primary / "seed.txt").write_text("seed", encoding="utf-8")
    _git(f.primary, "add", "--", "seed.txt")
    _git(f.primary, "commit", "-qm", "seed")
    _git(f.primary, "push", "-q", "origin", "main")
    _git(f.primary, "fetch", "-q", "origin")
    return f


def _upstream_reading(wt: Path, branch: str) -> tuple[int, str, str]:
    """What an instrument keyed on ``@{u}`` sees: (exit, upstream-or-error, unpushed-count)."""
    up_exit, up = _git_raw(wt, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}")
    count_exit, count = _git_raw(wt, "rev-list", "--count", "@{u}..HEAD")
    return (up_exit or count_exit), up, count


def test_the_creation_command_is_extractable_and_carries_a_tracking_decision() -> None:
    """Non-vacuity, and a record of which sanctioned fix is in force."""
    cmd = _add_command()

    assert "worktree" in cmd and "add" in cmd
    assert "--no-track" in cmd, (
        f"the worktree creation command does not pass --no-track:\n  {cmd}\n"
        "Without it git's branch.autoSetupMerge sets the new branch's upstream to the BASE "
        "(origin/main), and @{u}..HEAD then reports a fully-pushed branch's own commits as unpushed. "
        "The other sanctioned fix is setting the upstream to the branch's own remote after the first "
        "push; if that is what landed, this assertion is the thing to re-point -- the behavioural "
        "test below is the one that must keep passing."
    )


def test_a_fully_pushed_worktree_branch_reports_nothing_outstanding(fx: Fixture) -> None:
    """The reading, taken on a branch whose tip equals its pushed remote ref.

    The pre-fix command runs first, in the same fixture, and must reproduce the false reading --
    otherwise a green below would be evidence of nothing.
    """
    # --- control: the command new.ps1 used to run, written out literally ------------------------
    bad_wt = fx.root / "bad"
    subprocess.run(
        ["git", "-C", str(fx.primary), "worktree", "add", str(bad_wt), "-b", "bad", "origin/main"],
        check=True,
        capture_output=True,
        text=True,
    )
    fx.push_a_commit(bad_wt, "bad")
    assert fx.is_fully_pushed(bad_wt, "bad")
    bad_exit, bad_up, bad_count = _upstream_reading(bad_wt, "bad")

    assert bad_exit == 0 and bad_up == "origin/main", (
        f"the control did not reproduce the defect (upstream={bad_up!r}, exit={bad_exit}); the "
        "assertions below would then prove nothing. Check branch.autoSetupMerge in the fixture."
    )
    assert bad_count == "1", (
        f"expected the control to report a FALSE unpushed commit, got {bad_count!r}"
    )

    # --- subject: whatever new.ps1 runs today ----------------------------------------------------
    good_wt = fx.root / "good"
    subprocess.run(
        _render(
            _add_command(),
            repo_root=fx.primary,
            worktree=good_wt,
            branch="good",
            base="origin/main",
        ),
        check=True,
        capture_output=True,
        text=True,
    )
    fx.push_a_commit(good_wt, "good")
    assert fx.is_fully_pushed(good_wt, "good")
    good_exit, good_up, good_count = _upstream_reading(good_wt, "good")

    # Two end states are acceptable and both are correct failure directions: no upstream at all
    # (@{u} unresolvable, which fails LOUDLY), or the branch's OWN remote ref with nothing
    # outstanding. Answering "origin/main" and a non-zero count is the defect.
    if good_exit == 0:
        assert good_up == "origin/good", (
            f"a fully-pushed worktree branch resolves @{{u}} to {good_up!r}. Only the branch's own "
            "remote ref answers the question an instrument keyed on @{u} is asking."
        )
        assert good_count == "0", (
            f"@{{u}}..HEAD reports {good_count} unpushed commit(s) on a branch whose tip equals "
            "origin/good -- the false positive BACKLOG #1087 is about."
        )
    else:
        assert "no upstream" in good_up.lower() or "no upstream" in good_count.lower(), (
            f"@{{u}} failed for an unexpected reason: {good_up!r} / {good_count!r}"
        )

    # --- and the state ordinary use reaches: `git push -u` ---------------------------------------
    # Without an inherited upstream the first push is `push -u`, which sets @{u} to the branch's OWN
    # remote ref. That is the end state every later reading is taken in, so it is asserted here
    # rather than left to be inferred. Under the control's configuration this is unreachable: with
    # @{u} = origin/main a bare push refuses and git's own remediation text reads
    # `git push origin HEAD:main`, so nothing ever corrects the upstream.
    _git(good_wt, "push", "-u", "-q", "origin", "good")
    settled_exit, settled_up, settled_count = _upstream_reading(good_wt, "good")

    assert settled_exit == 0
    assert settled_up == "origin/good"
    assert settled_count == "0"


def test_no_script_relaxes_push_default(fx: Fixture) -> None:
    """``push.default`` unset is what stops a bare push writing a feature branch onto main.

    Scanned: every ``.ps1`` under ``scripts/``. The count is printed in the failure message so a
    future reader can tell an empty scan from a clean one.
    """
    scanned = sorted(_SCRIPTS.rglob("*.ps1"))
    assert len(scanned) > 20, (
        f"only {len(scanned)} PowerShell scripts found under {_SCRIPTS} -- the scan is not reaching "
        "the tree it is meant to cover, so a pass here would mean nothing."
    )
    # EXECUTABLE lines only. Written first as a raw text scan, which fired on new.ps1's own comment
    # WARNING against push.default -- proof the string match works, and proof that a raw scan forbids
    # documenting the hazard. A commented-out `git config push.default` sets nothing.
    offenders = [
        f"{p.relative_to(_REPO)}:{i}: {ln.strip()}"
        for p in scanned
        for i, ln in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1)
        if "push.default" in ln and not ln.strip().startswith("#")
    ]
    assert not offenders, (
        f"a script configures push.default (scanned {len(scanned)} .ps1 files under scripts/):\n  "
        + "\n  ".join(offenders)
        + "\npush.default=upstream is strictly WORSE than the upstream defect it appears to fix: "
        "with the upstream pointing at origin/main a bare `git push` writes the feature branch onto "
        "main, and push to main is not blocked server-side here. Leave it unset so git uses "
        "`simple`, which refuses when the upstream's name differs from the branch's."
    )
