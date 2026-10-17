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

WHAT IS ASSERTED HERE, AND WHAT IS NOT. The refusal, no-op and import-check paths are DRIVEN as a
subprocess, against a real venv that has NO PIP. The install is never completed: it downloads the
world, which is minutes of I/O per run. A test that reaches the install line instead proves it did so
by pip's absence ("No module named pip"), so a venv fixture that gained pip would turn those tests into
real installs. Its two invariants (extras parity with ``ci.yml``, and
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
import sys
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


@pytest.fixture(scope="session")
def _template_venv(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """One REAL venv with no pip, built once per session; each test gets its own copy of it.

    Building one takes seconds. A Windows venv's launcher finds the ``pyvenv.cfg`` beside it, so a
    copied tree is a working venv of its own, and no test can change another's."""
    venv = tmp_path_factory.mktemp("template") / ".venv"
    subprocess.run(
        [sys.executable, "-m", "venv", "--without-pip", str(venv)],
        capture_output=True,
        text=True,
        check=True,
        timeout=180,
    )
    return venv


def _venv_checkout(tmp_path: Path, template: Path) -> tuple[Path, Path]:
    """A fake checkout holding both import packages, and a REAL venv with no pip in it.

    The venv is real because the script asks its interpreter where the packages import from. It has
    no pip on purpose: a regression that reached the install path fails at once with "No module
    named pip", rather than quietly spending minutes rebuilding an environment. A ``.pth`` file
    stands in for the engine's editable install, which adds the checkout root to ``sys.path``.
    """
    root = _fake_checkout(tmp_path, pyproject=True)
    for name in ("messagefoundry", "messagefoundry_webconsole"):
        (root / name).mkdir()
        (root / name / "__init__.py").write_text(f"# {name} source\n", encoding="utf-8")
    venv = root / ".venv"
    shutil.copytree(template, venv, symlinks=True)
    site = venv / "Lib" / "site-packages"
    (site / "_editable_impl_messagefoundry.pth").write_text(f"{root}\n", encoding="utf-8")
    return root, site


def _plant_copy(site: Path, root: Path, name: str, *, stale: bool, same_size: bool = False) -> None:
    """A non-editable copy of ``name`` in site-packages, which sits ahead of the ``.pth`` root.

    With ``same_size`` the stale copy differs by one byte at an unchanged size, so only the
    byte-for-byte comparison can tell it from the source."""
    (site / name).mkdir()
    body = (root / name / "__init__.py").read_text(encoding="utf-8")
    if stale:
        body = body.replace("source", "sourcE") if same_size else body + "# an older build\n"
    (site / name / "__init__.py").write_text(body, encoding="utf-8")


def test_it_is_a_no_op_when_both_packages_import_from_the_checkout(
    tmp_path: Path, _template_venv: Path
) -> None:
    """IDEMPOTENCE IS THE POINT. A session cannot know whether its worktree already has an
    environment, so this must be safe to run unconditionally at the start of one."""
    root, _site = _venv_checkout(tmp_path, _template_venv)

    proc = _run("-Path", str(root))

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "both packages import from this checkout, nothing to do" in proc.stdout
    assert f"messagefoundry OK source {root / 'messagefoundry'}" in proc.stdout
    assert "Creating virtualenv" not in proc.stdout
    assert "reinstalling" not in proc.stdout


def test_a_web_console_copy_that_matches_the_source_is_accepted(
    tmp_path: Path, _template_venv: Path
) -> None:
    """Every install of the web console is a copy (hatch force-include), so a current one passes."""
    root, site = _venv_checkout(tmp_path, _template_venv)
    _plant_copy(site, root, "messagefoundry_webconsole", stale=False)

    proc = _run("-Path", str(root))

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "messagefoundry_webconsole OK copy-matching-source" in proc.stdout
    assert "nothing to do" in proc.stdout


def test_a_tool_cache_in_the_source_does_not_make_a_current_copy_stale(
    tmp_path: Path, _template_venv: Path
) -> None:
    """A cache a tool writes into the source never reaches the copy. Counting it would fail a fresh
    copy, and the reinstall after it, on every run."""
    root, site = _venv_checkout(tmp_path, _template_venv)
    name = "messagefoundry_webconsole"
    _plant_copy(site, root, name, stale=False)
    (root / name / ".mypy_cache").mkdir()
    (root / name / ".mypy_cache" / "cache.json").write_text("{}", encoding="utf-8")

    proc = _run("-Path", str(root))

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert f"{name} OK copy-matching-source" in proc.stdout


def test_sqlserver_takes_the_install_even_when_both_packages_are_current(
    tmp_path: Path, _template_venv: Path
) -> None:
    """-Sqlserver asks for an extra the import check cannot see, so it must not read as a no-op."""
    root, _site = _venv_checkout(tmp_path, _template_venv)

    proc = _run("-Path", str(root), "-Sqlserver")

    assert proc.returncode != 0, proc.stdout
    assert "nothing to do" not in proc.stdout
    assert "for -Sqlserver" in proc.stdout
    assert "No module named pip" in proc.stdout + proc.stderr


@pytest.mark.parametrize("name", ["messagefoundry_webconsole", "messagefoundry"])
def test_a_stale_copy_shadowing_the_checkout_is_reinstalled(
    tmp_path: Path, _template_venv: Path, name: str
) -> None:
    """BACKLOG #2857. The old script returned once python.exe existed, so a stale copy in
    site-packages went on shadowing the source, and a test read the result as a code defect.

    The reinstall is asserted by its attempt. This venv has no pip, so the install line fails, and
    that failure shows the script left the no-op path, after naming the package that sent it."""
    root, site = _venv_checkout(tmp_path, _template_venv)
    _plant_copy(site, root, name, stale=True)

    proc = _run("-Path", str(root))

    assert proc.returncode != 0, proc.stdout
    assert "nothing to do" not in proc.stdout
    assert "imports a package from outside this checkout; reinstalling" in proc.stdout
    assert f"{name} BAD it imports from {site / name}" in proc.stdout
    assert "No module named pip" in proc.stdout + proc.stderr


def test_a_same_size_stale_web_console_copy_is_reinstalled(
    tmp_path: Path, _template_venv: Path
) -> None:
    """Names and sizes match, so only the byte comparison can catch this copy as stale."""
    root, site = _venv_checkout(tmp_path, _template_venv)
    name = "messagefoundry_webconsole"
    _plant_copy(site, root, name, stale=True, same_size=True)

    proc = _run("-Path", str(root))

    assert proc.returncode != 0, proc.stdout
    assert f"{name} BAD it imports from {site / name}" in proc.stdout
    assert "No module named pip" in proc.stdout + proc.stderr


def test_it_resolves_a_subdirectory_to_the_checkout_root(
    tmp_path: Path, _template_venv: Path
) -> None:
    """Run from a subdirectory it must find the checkout root, not create a stray .venv there.

    Asserted through the no-op path so the test stays free of an install: the venv it reports as
    already present is the ROOT's, which is only reachable if the resolution worked."""
    root, _site = _venv_checkout(tmp_path, _template_venv)
    sub = root / "messagefoundry" / "store"
    sub.mkdir(parents=True)

    proc = _run("-Path", str(sub))

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "nothing to do" in proc.stdout
    assert not (sub / ".venv").exists()


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
