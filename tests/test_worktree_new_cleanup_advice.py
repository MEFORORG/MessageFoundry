# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""``new.ps1``'s cleanup advice must be runnable as written (BACKLOG #1078).

THE DEFECT. ``new.ps1`` anchors on ``$PSScriptRoot``, so run from a linked worktree it creates the
new tree beside **itself** -- e.g. under ``.claude/worktrees/`` -- and then printed *"When done (run
from the MAIN checkout): scripts\\worktree\\remove.ps1 -Name <name>"*. ``remove.ps1`` anchors on its
own location too, so the main checkout's copy derives ``<main-parent>/<main-leaf>-<name>``, which
does not exist, and it throws ``No such worktree``. The anchoring is correct (BACKLOG #1060); the
sentence was wrong.

THE INSTRUMENT. A text assertion that the advice "mentions $RepoRoot" would pass on advice that is
still unrunnable, so the commands are **extracted from the script and executed** against a synthetic
repo. ``test_the_advice_that_used_to_be_printed_still_throws_today`` carries the live positive
control in the same test as the fix: the old ``main checkout`` form is run against the very fixture
the new form then cleans up successfully, so a green here is evidence that the assertion can see the
class rather than evidence that nothing was checked.

THE EXTRACTION CONTRACT, which ``new.ps1`` states on its side too: inside ``Show-NextSteps`` an
advice line whose text begins ``"  #   "`` (hash, then THREE spaces) is a command meant to be run
verbatim; ``"  # "`` (hash, one space) is prose. Keeping the two shapes distinct is what lets a test
run the advice instead of merely reading it.
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
_REMOVE_PS1 = _REPO / "scripts" / "worktree" / "remove.ps1"

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="new.ps1/remove.ps1 are PowerShell scripts driven through pwsh on Windows",
)

#: An advice line carrying a COMMAND (see the extraction contract above).
_ADVICE_COMMAND = re.compile(r'^\s*Write-Host\s+"  #   (?P<cmd>.*)"\s*$')

#: The stale claim the item is about, as a LITERAL tripwire across both scripts. Deliberately blunt:
#: it cannot tell an instruction from a retraction quoting one, so a note recording that the claim was
#: removed must PARAPHRASE it rather than quote it. That is the cheaper half of the trade -- a smarter
#: pattern would have to decide which sentences are imperative, and would be the thing to get wrong.
_STALE_CLAIM = re.compile(r"run from the MAIN checkout", re.IGNORECASE)


def _advice_commands() -> list[str]:
    """The raw (still ``$``-templated) command lines new.ps1 prints as cleanup advice."""
    return [
        m.group("cmd")
        for m in (
            _ADVICE_COMMAND.match(ln) for ln in _NEW_PS1.read_text(encoding="utf-8").splitlines()
        )
        if m
    ]


def _render(cmd: str, *, repo_root: Path, worktree: Path, name: str) -> list[str]:
    """Turn one printed advice line into an argv, exactly as a reader copying it would.

    Longest token first so no substitution eats a prefix of another.
    """
    text = cmd.replace('`"', '"')
    for token, value in (
        ("$WorktreePath", str(worktree)),
        ("$RepoRoot", str(repo_root)),
        ("$Name", name),
    ):
        text = text.replace(token, value)
    assert "$" not in text, f"advice line still carries an unsubstituted variable: {text}"
    return [t.strip('"') for t in shlex.split(text, posix=False)]


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    )
    return proc.stdout


def _registered(primary: Path) -> set[str]:
    out = _git(primary, "worktree", "list", "--porcelain")
    return {
        ln.split(" ", 1)[1].replace("\\", "/").rstrip("/")
        for ln in out.splitlines()
        if ln.startswith("worktree ")
    }


class Fixture:
    """A synthetic repo that carries a real copy of ``remove.ps1`` at the tracked path.

    Committing the script means every checkout of the fixture -- primary and linked -- has it where
    ``$RepoRoot\\scripts\\worktree\\remove.ps1`` resolves, which is the whole point of the advice
    naming a root.
    """

    def __init__(self, root: Path) -> None:
        self.root = root
        self.primary = root / "wt" / "repo"

    def worktree(self, path: Path, branch: str) -> Path:
        _git(self.primary, "worktree", "add", "-q", "-b", branch, str(path))
        # The untracked entry every real worktree carries. `git worktree remove` refuses on it
        # without --force, so advice that omits --force would fail here -- which is the point.
        (path / ".venv").mkdir()
        (path / ".venv" / "marker.txt").write_text("untracked", encoding="utf-8")
        return path


@pytest.fixture
def fx(tmp_path: Path) -> Fixture:
    f = Fixture(tmp_path)
    tracked = f.primary / "scripts" / "worktree"
    tracked.mkdir(parents=True)
    shutil.copyfile(_REMOVE_PS1, tracked / "remove.ps1")
    _git(f.primary, "init", "-q", "-b", "main")
    _git(f.primary, "config", "user.email", "t@example.invalid")
    _git(f.primary, "config", "user.name", "t")
    _git(f.primary, "add", "--", "scripts/worktree/remove.ps1")
    _git(f.primary, "commit", "-qm", "seed")
    _git(
        f.primary,
        "update-ref",
        "refs/remotes/origin/main",
        _git(f.primary, "rev-parse", "HEAD").strip(),
    )
    return f


def _run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, capture_output=True, text=True, timeout=180, check=False)


def test_the_advice_is_a_non_empty_set_of_commands_naming_the_checkout(fx: Fixture) -> None:
    """Non-vacuity first: an empty extraction would make every execution test below pass silently."""
    commands = _advice_commands()

    assert commands, (
        f"{_NEW_PS1.name} prints no cleanup command in the extractable form. If Show-NextSteps was "
        "restructured, re-point this guard rather than letting it pass on an empty set."
    )
    rootless = [c for c in commands if "$RepoRoot" not in c]
    assert not rootless, (
        "a cleanup command does not name the checkout the worktree belongs to:\n  "
        + "\n  ".join(rootless)
        + "\nA root-less command resolves against the reader's cwd, which is the BACKLOG #1078 defect: "
        "the main checkout's remove.ps1 looks for a sibling that does not exist and throws."
    )
    # Both scripts carried the claim, and remove.ps1's own header is the one a reader hits after
    # following the advice. Fixing one site and leaving the other is how a corrected fact comes back.
    stale = [
        f"{p.name}: {ln.strip()}"
        for p in (_NEW_PS1, _REMOVE_PS1)
        for ln in p.read_text(encoding="utf-8").splitlines()
        if _STALE_CLAIM.search(ln)
    ]
    assert not stale, (
        'a worktree script still asserts "run from the MAIN checkout":\n  '
        + "\n  ".join(stale)
        + "\nThat is false whenever new.ps1 itself ran from a linked worktree."
    )


def test_every_printed_cleanup_command_actually_removes_the_worktree(fx: Fixture) -> None:
    """Follow the advice as written, once per printed command, and require the worktree to be gone."""
    commands = _advice_commands()
    assert commands

    for i, cmd in enumerate(commands):
        wt = fx.worktree(fx.primary.parent / f"repo-adv{i}", f"adv{i}")
        assert str(wt).replace("\\", "/") in _registered(fx.primary)

        proc = _run(_render(cmd, repo_root=fx.primary, worktree=wt, name=f"adv{i}"))

        assert proc.returncode == 0, f"advice failed: {cmd}\n{proc.stdout}\n{proc.stderr}"
        assert not wt.exists(), f"advice ran but left the worktree behind: {cmd}"
        assert str(wt).replace("\\", "/") not in _registered(fx.primary), (
            f"advice ran but the worktree is still registered: {cmd}"
        )


def test_the_advice_that_used_to_be_printed_still_throws_today(fx: Fixture) -> None:
    """The live positive control, in the shape that produced the item.

    ``inner`` stands in for a linked worktree new.ps1 was run from; ``inner-feature`` is the tree it
    would then create beside itself. The retired advice -- the MAIN checkout's own relative
    ``remove.ps1 -Name feature`` -- is run against that tree and must still fail, and the advice
    printed today must then clean it up. One test, both directions.
    """
    inner = fx.primary / ".claude" / "worktrees" / "inner"
    _git(fx.primary, "worktree", "add", "-q", "-b", "inner", str(inner))
    target = fx.worktree(inner.parent / "inner-feature", "feature")

    retired = _run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(fx.primary / "scripts" / "worktree" / "remove.ps1"),
            "-Name",
            "feature",
        ]
    )

    assert retired.returncode != 0, (
        "the retired advice succeeded, so this control proves nothing -- re-derive it before trusting "
        "the assertions above"
    )
    assert "No such worktree" in retired.stderr
    assert str(fx.primary.parent / "repo-feature") in retired.stderr
    assert target.exists()

    for cmd in _advice_commands():
        if not target.exists():
            break
        proc = _run(_render(cmd, repo_root=inner, worktree=target, name="feature"))
        assert proc.returncode == 0, f"advice failed: {cmd}\n{proc.stdout}\n{proc.stderr}"

    assert not target.exists()
    assert str(target).replace("\\", "/") not in _registered(fx.primary)
