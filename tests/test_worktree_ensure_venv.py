# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``ensure-venv.ps1`` is the route a HARNESS-created worktree has to a locked environment.

WHY IT EXISTS. Two things create worktrees here and only one of them installed anything.
``scripts/worktree/new.ps1`` builds siblings (``<repo>-<name>``) and bootstraps a venv; Claude Code's
own ``--worktree``, the desktop app and ``isolation: worktree`` subagents build nested worktrees under
``<primary>/.claude/worktrees/`` and install nothing. Measured 2026-09-16 on the author's machine:
**21 of 22** siblings carried a usable ``.venv`` against **47 of 86** nested ones.

WHY THAT MATTERS BEYOND CONVENIENCE. Without a venv ``pytest`` does not run slowly against the wrong
interpreter -- it **dies at import**, so the worker cannot run the checks its brief requires and the
first real signal arrives in CI after its process is gone. It also had a second-order cost: a session
that wanted a working environment took a SIBLING and then tried to relocate into it, which from a
subagent is refused outright and from a session asks the owner. Closing the venv gap is what makes the
prompt-free entry point usable. Both behaviours are recorded once, in docs/WORKTREES.md section "Start
the session in the worktree".

WHAT IS ASSERTED HERE, AND WHAT IS NOT. The refusal and no-op paths are DRIVEN as a subprocess -- they
are fast and touch nothing. The install path is not executed: it creates a venv and downloads the
world, which is minutes of I/O per run. Its two invariants (extras parity with ``ci.yml``, and
``--constraint constraints.lock``) are held by the two tests that already owned them and now read this
file instead of ``new.ps1``.

One test here is deliberately about ``new.ps1`` rather than this script: that it still CALLS this one.
Without it the extraction could be silently undone -- the two text gates would keep passing while
``new.ps1`` installed nothing at all.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
_SCRIPT = _REPO / "scripts" / "worktree" / "ensure-venv.ps1"
_NEW_PS1 = _REPO / "scripts" / "worktree" / "new.ps1"

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="ensure-venv.ps1 is a PowerShell script driven through pwsh on Windows",
)


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(_SCRIPT), *args],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(cwd), *args], capture_output=True, text=True, check=True)


def _fake_checkout(tmp_path: Path, *, pyproject: bool) -> Path:
    """A git repo that is structurally a checkout, with no Python in it."""
    root = tmp_path / "checkout"
    root.mkdir()
    _git(root, "init", "-q")
    if pyproject:
        (root / "pyproject.toml").write_text("[project]\nname = 'fake'\n", encoding="utf-8")
    return root


def test_it_refuses_a_path_that_is_not_a_git_checkout(tmp_path: Path) -> None:
    """A mistyped -Path must fail loudly rather than build a stray .venv where it landed."""
    plain = tmp_path / "not-a-repo"
    plain.mkdir()
    proc = _run("-Path", str(plain))
    assert proc.returncode != 0, proc.stdout
    assert "Not a git checkout" in proc.stderr + proc.stdout


def test_it_refuses_a_checkout_that_is_not_this_project(tmp_path: Path) -> None:
    """Without this, a wrong -Path installs an unrelated package tree into a venv and the failure
    surfaces much later as an import error nobody connects back to here."""
    root = _fake_checkout(tmp_path, pyproject=False)
    proc = _run("-Path", str(root))
    assert proc.returncode != 0, proc.stdout
    assert "not a messagefoundry checkout" in (proc.stderr + proc.stdout).lower()


def test_it_is_a_no_op_when_a_usable_interpreter_is_already_present(tmp_path: Path) -> None:
    """IDEMPOTENCE IS THE POINT. A session cannot know whether its worktree already has an
    environment, so this must be safe to run unconditionally at the start of one.

    The assertion is that it returns success WITHOUT installing: no network, no pip. A fake
    ``python.exe`` stands in for a real venv precisely so that a regression here -- one that reached
    the install path anyway -- would try to run that fake and fail, rather than quietly spending
    minutes rebuilding a real environment."""
    root = _fake_checkout(tmp_path, pyproject=True)
    venv_py = root / ".venv" / "Scripts" / "python.exe"
    venv_py.parent.mkdir(parents=True)
    venv_py.write_text("", encoding="utf-8")

    proc = _run("-Path", str(root))

    assert proc.returncode == 0, proc.stderr
    assert "already present" in proc.stdout
    assert "Creating virtualenv" not in proc.stdout, (
        "reached the install path despite a usable interpreter being present"
    )


def test_it_resolves_a_subdirectory_to_the_checkout_root(tmp_path: Path) -> None:
    """Run from a subdirectory it must find the checkout root, not create a stray .venv there.

    Asserted through the no-op path so the test stays free of an install: the venv it reports as
    already present is the ROOT's, which is only reachable if the resolution worked."""
    root = _fake_checkout(tmp_path, pyproject=True)
    venv_py = root / ".venv" / "Scripts" / "python.exe"
    venv_py.parent.mkdir(parents=True)
    venv_py.write_text("", encoding="utf-8")
    sub = root / "messagefoundry" / "store"
    sub.mkdir(parents=True)

    proc = _run("-Path", str(sub))

    assert proc.returncode == 0, proc.stderr
    assert "already present" in proc.stdout


def test_new_ps1_still_delegates_the_bootstrap_to_this_script() -> None:
    """THE EXTRACTION MUST NOT BE SILENTLY UNDONE.

    The extras-parity and constraint tests now read ``ensure-venv.ps1``. If ``new.ps1`` stopped
    calling it, both would keep passing while ``new.ps1`` installed nothing -- a worktree with no
    environment and two green gates saying otherwise."""
    text = _NEW_PS1.read_text(encoding="utf-8")
    call_lines = [
        ln for ln in text.splitlines() if not ln.strip().startswith("#") and "ensure-venv.ps1" in ln
    ]
    assert call_lines, (
        "new.ps1 no longer calls ensure-venv.ps1. The venv bootstrap moved there and two text gates "
        "(extras parity, constraints.lock) read it there -- if new.ps1 stopped calling it, a new "
        "worktree would come up with no environment and both gates would still be green."
    )
