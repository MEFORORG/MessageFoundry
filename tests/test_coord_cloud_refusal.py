# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The coordination scripts refuse in a Claude Code cloud session instead of writing where nobody reads.

A cloud VM is its own clone, so ``git rev-parse --git-common-dir`` resolves to that clone's ``.git``
and ``<git-common-dir>/mefor-coord`` is a valid directory that no other session ever reads. Before the
guard, ``seat.ps1``, ``mail.ps1``, ``alloc.ps1`` and ``claim.ps1`` would all have "succeeded" into it:
a declaration nobody sees, mail nobody drains, an ADR number the fleet never learns about.

Each refusal is paired with a control that runs the same call without ``CLAUDE_CODE_REMOTE`` and
must take the normal path, because a refusal test alone also passes against a script that refuses
every call. tests/conftest.py drops the variable from the suite's own environment, so the controls
stay meaningful when the suite itself runs in a cloud VM.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
COORD = ROOT / "scripts" / "coord"
HOOKS = ROOT / "scripts" / "hooks"
TIMEOUT = 120
REFUSAL_EXIT = 3
REFUSAL_TAIL = (
    ": refused in a Claude Code cloud session (CLAUDE_CODE_REMOTE=true). This VM's .git/mefor-coord"
    " reaches no other session, so nothing was read or recorded."
)
SEAT_DECLARE = ("-Declare", "-Seat", "builder", "-Goal", "cloud refusal test")

needs_pwsh = pytest.mark.skipif(shutil.which("pwsh") is None, reason="the scripts run under pwsh")
# The normal paths of these scripts are exercised on Windows by their own suites; the controls here
# follow the same platform gate. The refusals fire before anything platform-specific.
needs_windows = pytest.mark.skipif(
    os.name != "nt", reason="the scripts' normal paths run on Windows"
)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=TIMEOUT, check=True
    )


@pytest.fixture(scope="module")
def _template(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """One clone carrying its OWN copy of scripts/coord and scripts/hooks, built once per module."""
    r = tmp_path_factory.mktemp("template") / "repo"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@example.invalid")
    _git(r, "config", "user.name", "t")
    # No background maintenance: the commit below can detach one that holds
    # .git/objects/maintenance.lock while a test copies the tree, and the copy then fails on a lock
    # that vanished mid-walk. Measured on the ubuntu tooling leg, PR 2434.
    _git(r, "config", "maintenance.auto", "false")
    _git(r, "config", "gc.auto", "0")
    shutil.copytree(COORD, r / "scripts" / "coord")
    shutil.copytree(HOOKS, r / "scripts" / "hooks")
    (r / "f.txt").write_text("x", encoding="utf-8")
    _git(r, "add", "f.txt")
    _git(r, "commit", "-qm", "base")
    return r


@pytest.fixture
def repo(tmp_path: Path, _template: Path) -> Path:
    """A private copy of the template per test. These scripts anchor on where they live, not on the
    cwd, so the copy is what keeps every write out of the real registry and out of a sibling test."""
    r = tmp_path / "repo"
    shutil.copytree(_template, r, symlinks=True, ignore=shutil.ignore_patterns("*.lock"))
    return r


def _coord_dir(repo: Path) -> Path:
    return repo / ".git" / "mefor-coord"


def _run(repo: Path, script: str, *args: str, cloud: bool) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    if cloud:
        env["CLAUDE_CODE_REMOTE"] = "true"
    return subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(repo / "scripts" / script), *args],
        cwd=str(repo),
        env=env,
        input="",
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )


@needs_pwsh
@pytest.mark.parametrize(
    ("label", "script", "args"),
    [
        pytest.param("seat.ps1", "coord/seat.ps1", SEAT_DECLARE, id="seat-declare"),
        pytest.param("seat.ps1", "coord/seat.ps1", ("-Close",), id="seat-close"),
        pytest.param("mail.ps1", "coord/mail.ps1", ("-Status",), id="mail-status"),
        pytest.param("alloc.ps1", "coord/alloc.ps1", ("-List",), id="alloc-list"),
        pytest.param("claim.ps1", "coord/claim.ps1", ("-List",), id="claim-list"),
    ],
)
def test_each_coordination_script_refuses_in_a_cloud_session(
    repo: Path, label: str, script: str, args: tuple[str, ...]
) -> None:
    proc = _run(repo, script, *args, cloud=True)
    assert proc.returncode == REFUSAL_EXIT, (proc.stdout, proc.stderr)
    assert proc.stderr.strip() == label + REFUSAL_TAIL, proc.stderr
    assert proc.stdout == "", proc.stdout
    assert not _coord_dir(repo).exists(), "a refused call still created the coordination directory"


@needs_pwsh
def test_mail_send_refuses_before_writing_to_an_explicit_mail_root(
    repo: Path, tmp_path: Path
) -> None:
    """-MailRoot bypasses the git lookup, so this proves the refusal comes before the write itself."""
    root = tmp_path / "mail"
    args = ("-Send", "-To", str(repo), "-Body", "x", "-MailRoot", str(root))
    proc = _run(repo, "coord/mail.ps1", *args, cloud=True)
    assert proc.returncode == REFUSAL_EXIT, (proc.stdout, proc.stderr)
    assert not root.exists()


@needs_pwsh
@needs_windows
def test_seat_record_is_not_refused_in_the_cloud(repo: Path) -> None:
    """-Record is a Stop-hook path that must exit 0 on every route, so it is exempt."""
    proc = _run(repo, "coord/seat.ps1", "-Record", cloud=True)
    assert "refused in a Claude Code cloud session" not in proc.stdout + proc.stderr
    assert proc.returncode == 0, (proc.stdout, proc.stderr)


@needs_pwsh
@needs_windows
@pytest.mark.parametrize(
    ("script", "args"),
    [
        pytest.param("coord/mail.ps1", ("-Status",), id="mail-status"),
        pytest.param("coord/alloc.ps1", ("-List",), id="alloc-list"),
        pytest.param("coord/claim.ps1", ("-List",), id="claim-list"),
    ],
)
def test_each_coordination_script_takes_its_normal_path_outside_the_cloud(
    repo: Path, script: str, args: tuple[str, ...]
) -> None:
    proc = _run(repo, script, *args, cloud=False)
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    assert "refused in a Claude Code cloud session" not in proc.stdout + proc.stderr


@needs_pwsh
@needs_windows
def test_seat_declare_outside_the_cloud_writes_its_record(repo: Path) -> None:
    """The control for the declaration: the record the refusal withholds is really written here."""
    proc = _run(repo, "coord/seat.ps1", *SEAT_DECLARE, cloud=False)
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    assert "refused in a Claude Code cloud session" not in proc.stdout + proc.stderr
    records = list((_coord_dir(repo) / "seats").rglob("*.json"))
    assert records, "seat.ps1 -Declare wrote no record outside the cloud"


@needs_pwsh
def test_the_declare_prompt_hook_prints_one_cloud_line_and_exits_zero(repo: Path) -> None:
    proc = _run(repo, "hooks/seat-declare-prompt.ps1", cloud=True)
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    assert len(lines) == 1, proc.stdout
    assert "cloud Builder with no seat registry" in lines[0]
    assert "seat.ps1 -Declare -Seat" not in proc.stdout
    assert not _coord_dir(repo).exists(), "the cloud hook stamped a seat record nobody reads"


@needs_pwsh
@needs_windows
def test_the_declare_prompt_hook_prints_the_prompt_outside_the_cloud(repo: Path) -> None:
    proc = _run(repo, "hooks/seat-declare-prompt.ps1", cloud=False)
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    assert "seat.ps1 -Declare -Seat" in proc.stdout
    assert "cloud Builder" not in proc.stdout


@pytest.mark.parametrize("name", ["seat", "mail", "alloc", "claim"])
def test_each_script_carries_the_one_refusal_line(name: str) -> None:
    """The guard is inlined: alloc.ps1 and claim.ps1 dot-source no helper the other two share. This
    holds the four copies to one line without pwsh, so it also runs where the refusal tests skip."""
    text = (COORD / f"{name}.ps1").read_text(encoding="utf-8")
    line = f"[Console]::Error.WriteLine('{name}.ps1{REFUSAL_TAIL}')".replace("VM's", "VM''s")
    guard = f"    {line}\n    exit {REFUSAL_EXIT}\n"
    assert text.count(guard) == 1, f"{name}.ps1 lost or changed its cloud refusal line"
