# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The cloud-only SessionStart hook: wired once, gated on CLAUDE_CODE_REMOTE, and inert locally.

The hook installs pwsh and Python 3.14 in a Claude Code cloud VM. The property that matters most
is the one nobody would notice breaking: on a LOCAL session it must do nothing at all. It is wired
in the tracked settings file, so every session on every account runs its command, and a broken
gate would run apt-get on a developer box. So the gate is tested as wired, with a control proving
the same command DOES run the script once the variable is set.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_SETTINGS = _ROOT / ".claude" / "settings.json"
_SCRIPT = _ROOT / "scripts" / "hooks" / "cloud-setup.sh"
_BASH = shutil.which("bash")

needs_bash = pytest.mark.skipif(_BASH is None, reason="bash is not on PATH")


def _cloud_handlers() -> list[dict[str, Any]]:
    settings = json.loads(_SETTINGS.read_text(encoding="utf-8"))
    return [
        handler
        for group in settings["hooks"]["SessionStart"]
        for handler in group.get("hooks", [])
        if "cloud-setup.sh" in handler.get("command", "")
    ]


def _run(
    command: list[str], env_extra: dict[str, str], cwd: Path
) -> subprocess.CompletedProcess[str]:
    env = {k: v for k, v in os.environ.items() if k != "CLAUDE_CODE_REMOTE"}
    env.update(env_extra)
    return subprocess.run(
        command, cwd=cwd, env=env, capture_output=True, text=True, timeout=60, check=False
    )


def test_the_hook_is_wired_exactly_once_in_shell_form_with_its_gate() -> None:
    handlers = _cloud_handlers()
    assert len(handlers) == 1, (
        f"expected one SessionStart handler for cloud-setup.sh, got {handlers}"
    )
    handler = handlers[0]
    # Exec form would need `bash` on PATH, and on the Windows dev box it is not: the hook would then
    # fail to start in EVERY local session. `shell: bash` is resolved by Claude Code itself.
    assert handler.get("shell") == "bash"
    assert "args" not in handler
    assert handler["command"].startswith('[ "${CLAUDE_CODE_REMOTE:-}" = true ] || exit 0;')
    # Installs on a fresh VM take tens of seconds. A stated budget keeps a slow mirror from being
    # mistaken for a hang; the script's header has the measured times.
    assert handler.get("timeout", 0) >= 120


def _planted_project(tmp_path: Path) -> Path:
    """A project dir whose cloud-setup.sh only reports that it ran."""
    hooks = tmp_path / "scripts" / "hooks"
    hooks.mkdir(parents=True)
    (hooks / "cloud-setup.sh").write_text("echo PLANTED-RAN\n", encoding="utf-8")
    return tmp_path


@needs_bash
@pytest.mark.parametrize(("remote", "runs"), [(None, False), ("false", False), ("true", True)])
def test_the_wired_command_runs_the_script_only_in_the_cloud(
    tmp_path: Path, remote: str | None, runs: bool
) -> None:
    assert _BASH is not None
    project = _planted_project(tmp_path)
    env = {"CLAUDE_PROJECT_DIR": project.as_posix()}
    if remote is not None:
        env["CLAUDE_CODE_REMOTE"] = remote
    result = _run([_BASH, "-c", _cloud_handlers()[0]["command"]], env, project)
    assert result.returncode == 0, result.stderr
    # The "true" row is the control: without it, a command that never ran anything would pass the
    # two local rows.
    assert ("PLANTED-RAN" in result.stdout) is runs, result.stdout


@needs_bash
def test_the_script_is_a_silent_no_op_outside_the_cloud(tmp_path: Path) -> None:
    assert _BASH is not None
    result = _run([_BASH, str(_SCRIPT)], {"CLAUDE_PROJECT_DIR": tmp_path.as_posix()}, tmp_path)
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""


@needs_bash
def test_the_script_refuses_loudly_without_a_checkout_and_installs_nothing(tmp_path: Path) -> None:
    assert _BASH is not None
    result = _run(
        [_BASH, str(_SCRIPT)],
        {"CLAUDE_CODE_REMOTE": "true", "CLAUDE_PROJECT_DIR": tmp_path.as_posix()},
        tmp_path,
    )
    assert result.returncode == 0, result.stderr
    assert "NOT RUN: no checkout found" in result.stdout
    assert "guard" in result.stdout


def _stub_tools(tmp_path: Path, gh_output: str | None) -> Path:
    """`pwsh`, `uv` and `gh` stand-ins, so the cloud path runs with no install and no network."""
    stubs = tmp_path / "stubs"
    stubs.mkdir()
    gh_body = f"printf '%s\\n' '{gh_output}'" if gh_output is not None else "exit 1"
    bodies = {
        "pwsh": "exit 0",
        "uv": '[ "$1 $2" = "python find" ] && echo /stub/python3.14; exit 0',
        "gh": gh_body,
    }
    for name, body in bodies.items():
        f = stubs / name
        f.write_text(f"#!/usr/bin/env bash\n{body}\n", encoding="utf-8", newline="\n")
        f.chmod(0o755)
    return stubs


def _checkout(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "pyproject.toml").write_text("", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    return repo


def _local_git_config(repo: Path, key: str) -> str | None:
    out = subprocess.run(
        ["git", "-C", str(repo), "config", "--local", "--get", key],
        capture_output=True,
        text=True,
        check=False,
    )
    return out.stdout.strip() if out.returncode == 0 else None


@needs_bash
def test_the_identity_is_the_pushing_accounts_own_noreply(tmp_path: Path) -> None:
    assert _BASH is not None
    repo = _checkout(tmp_path)
    stubs = _stub_tools(tmp_path, "12345\tjdoe\tJane Doe")
    env = {
        "CLAUDE_CODE_REMOTE": "true",
        "CLAUDE_PROJECT_DIR": repo.as_posix(),
        "PATH": str(stubs) + os.pathsep + os.environ.get("PATH", ""),
    }
    result = _run([_BASH, str(_SCRIPT)], env, repo)
    assert result.returncode == 0, result.stderr
    assert _local_git_config(repo, "user.name") == "Jane Doe", result.stdout
    assert _local_git_config(repo, "user.email") == "12345+jdoe@users.noreply.github.com"
    # The printed venv command must be runnable as-is: the script and parameter that exist today.
    assert "ensure-venv.ps1 -Python '/stub/python3.14'" in result.stdout
    assert (_ROOT / "scripts" / "worktree" / "ensure-venv.ps1").is_file()


@needs_bash
def test_no_venv_instruction_once_the_venv_exists(tmp_path: Path) -> None:
    """SessionStart also fires on resume and compact; a built venv must not be rebuilt on advice."""
    assert _BASH is not None
    repo = _checkout(tmp_path)
    venv_py = repo / ".venv" / "bin" / "python"
    venv_py.parent.mkdir(parents=True)
    venv_py.write_bytes(b"#!/bin/sh\n")
    venv_py.chmod(0o755)
    stubs = _stub_tools(tmp_path, "12345\tjdoe\tJane Doe")
    env = {
        "CLAUDE_CODE_REMOTE": "true",
        "CLAUDE_PROJECT_DIR": repo.as_posix(),
        "PATH": str(stubs) + os.pathsep + os.environ.get("PATH", ""),
    }
    result = _run([_BASH, str(_SCRIPT)], env, repo)
    assert result.returncode == 0, result.stderr
    assert "no venv yet" not in result.stdout
    # Control: the same run reached the end, so the absence above is the gate, not an early exit.
    assert "[cloud-setup] cloud session." in result.stdout


@needs_bash
def test_a_failed_account_lookup_sets_no_identity_and_says_so(tmp_path: Path) -> None:
    assert _BASH is not None
    repo = _checkout(tmp_path)
    stubs = _stub_tools(tmp_path, None)
    env = {
        "CLAUDE_CODE_REMOTE": "true",
        "CLAUDE_PROJECT_DIR": repo.as_posix(),
        "PATH": str(stubs) + os.pathsep + os.environ.get("PATH", ""),
    }
    result = _run([_BASH, str(_SCRIPT)], env, repo)
    assert result.returncode == 0, result.stderr
    assert "gh api user failed" in result.stdout
    assert _local_git_config(repo, "user.email") is None
