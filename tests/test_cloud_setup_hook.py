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
import re
import subprocess
from pathlib import Path
from typing import Any

import pytest

from tests._bash_resolver import probe_env, require_bash

_ROOT = Path(__file__).resolve().parents[1]
_SETTINGS = _ROOT / ".claude" / "settings.json"
_SCRIPT = _ROOT / "scripts" / "hooks" / "cloud-setup.sh"


@pytest.fixture(scope="module")
def bash(tmp_path_factory: pytest.TempPathFactory) -> Path:
    # Not `shutil.which`: on Windows it can answer with the WSL launcher, or with Git's bin/bash.exe
    # wrapper, which puts mingw64/bin (it ships curl.exe) ahead of a stub directory. See
    # _bash_resolver.
    return Path(require_bash(tmp_path_factory.mktemp("resolve-bash")))


def _cloud_handlers() -> list[dict[str, Any]]:
    settings = json.loads(_SETTINGS.read_text(encoding="utf-8"))
    return [
        handler
        for group in settings["hooks"]["SessionStart"]
        for handler in group.get("hooks", [])
        if "cloud-setup.sh" in handler.get("command", "")
    ]


def _run(
    bash: Path, args: list[str], env_extra: dict[str, str], cwd: Path
) -> subprocess.CompletedProcess[str]:
    # The script must set DEBIAN_FRONTEND and LC_ALL itself, so an inherited value cannot stand in.
    unset = ("CLAUDE_CODE_REMOTE", "DEBIAN_FRONTEND", "LC_ALL")
    env = {k: v for k, v in os.environ.items() if k not in unset}
    env.update(env_extra)
    return subprocess.run(
        [str(bash), *args],
        cwd=cwd,
        env=probe_env(bash, env),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
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


@pytest.mark.parametrize(("remote", "runs"), [(None, False), ("false", False), ("true", True)])
def test_the_wired_command_runs_the_script_only_in_the_cloud(
    bash: Path, tmp_path: Path, remote: str | None, runs: bool
) -> None:
    project = _planted_project(tmp_path)
    env = {"CLAUDE_PROJECT_DIR": project.as_posix()}
    if remote is not None:
        env["CLAUDE_CODE_REMOTE"] = remote
    result = _run(bash, ["-c", _cloud_handlers()[0]["command"]], env, project)
    assert result.returncode == 0, result.stderr
    # The "true" row is the control: without it, a command that never ran anything would pass the
    # two local rows.
    assert ("PLANTED-RAN" in result.stdout) is runs, result.stdout


def test_the_script_is_a_silent_no_op_outside_the_cloud(bash: Path, tmp_path: Path) -> None:
    result = _run(bash, [str(_SCRIPT)], {"CLAUDE_PROJECT_DIR": tmp_path.as_posix()}, tmp_path)
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""


def test_the_script_refuses_loudly_without_a_checkout_and_installs_nothing(
    bash: Path, tmp_path: Path
) -> None:
    result = _run(
        bash,
        [str(_SCRIPT)],
        {"CLAUDE_CODE_REMOTE": "true", "CLAUDE_PROJECT_DIR": tmp_path.as_posix()},
        tmp_path,
    )
    assert result.returncode == 0, result.stderr
    assert "NOT RUN: no checkout found" in result.stdout
    assert "guard" in result.stdout


def _write_stubs(tmp_path: Path, bodies: dict[str, str]) -> dict[str, str]:
    """Bash stand-ins, one executable per name in ``bodies``; returns the PATH that finds them."""
    stubs = tmp_path / "stubs"
    stubs.mkdir()
    for name, body in bodies.items():
        f = stubs / name
        f.write_text(f"#!/usr/bin/env bash\n{body}\n", encoding="utf-8", newline="\n")
        f.chmod(0o755)
    return {"PATH": str(stubs) + os.pathsep + os.environ.get("PATH", "")}


def _stub_tools(tmp_path: Path, gh_output: str | None) -> dict[str, str]:
    """`pwsh`, `uv` and `gh` stand-ins, so the cloud path runs with no install and no network."""
    gh_body = f"printf '%s\\n' '{gh_output}'" if gh_output is not None else "exit 1"
    return _write_stubs(
        tmp_path,
        {
            "pwsh": "exit 0",
            "uv": '[ "$1 $2" = "python find" ] && echo /stub/python3.14; exit 0',
            "gh": gh_body,
        },
    )


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


def test_the_identity_is_the_pushing_accounts_own_noreply(bash: Path, tmp_path: Path) -> None:
    repo = _checkout(tmp_path)
    env = {
        "CLAUDE_CODE_REMOTE": "true",
        "CLAUDE_PROJECT_DIR": repo.as_posix(),
        **_stub_tools(tmp_path, "12345\tjdoe\tJane Doe"),
    }
    result = _run(bash, [str(_SCRIPT)], env, repo)
    assert result.returncode == 0, result.stderr
    assert _local_git_config(repo, "user.name") == "Jane Doe", result.stdout
    assert _local_git_config(repo, "user.email") == "12345+jdoe@users.noreply.github.com"
    # The printed venv command must be runnable as-is: the script and parameter that exist today.
    assert "ensure-venv.ps1 -Python '/stub/python3.14'" in result.stdout
    assert (_ROOT / "scripts" / "worktree" / "ensure-venv.ps1").is_file()


def test_no_venv_instruction_once_the_venv_exists(bash: Path, tmp_path: Path) -> None:
    """SessionStart also fires on resume and compact; a built venv must not be rebuilt on advice."""
    repo = _checkout(tmp_path)
    venv_py = repo / ".venv" / "bin" / "python"
    venv_py.parent.mkdir(parents=True)
    venv_py.write_bytes(b"#!/bin/sh\n")
    venv_py.chmod(0o755)
    env = {
        "CLAUDE_CODE_REMOTE": "true",
        "CLAUDE_PROJECT_DIR": repo.as_posix(),
        **_stub_tools(tmp_path, "12345\tjdoe\tJane Doe"),
    }
    result = _run(bash, [str(_SCRIPT)], env, repo)
    assert result.returncode == 0, result.stderr
    assert "no venv yet" not in result.stdout
    # Control: the same run reached the end, so the absence above is the gate, not an early exit.
    assert "[cloud-setup] cloud session." in result.stdout


def test_a_failed_account_lookup_sets_no_identity_and_says_so(bash: Path, tmp_path: Path) -> None:
    repo = _checkout(tmp_path)
    env = {
        "CLAUDE_CODE_REMOTE": "true",
        "CLAUDE_PROJECT_DIR": repo.as_posix(),
        **_stub_tools(tmp_path, None),
    }
    result = _run(bash, [str(_SCRIPT)], env, repo)
    assert result.returncode == 0, result.stderr
    assert "gh api user failed" in result.stdout
    assert _local_git_config(repo, "user.email") is None


def _code_lines() -> list[str]:
    text = _SCRIPT.read_text(encoding="utf-8")
    return [line for line in text.splitlines() if not line.lstrip().startswith("#")]


def test_apt_get_runs_only_through_the_lock_waiting_wrapper_and_dpkg_i_is_gone() -> None:
    """At VM boot another process can hold the dpkg lock; a call that does not wait loses to it."""
    code = _code_lines()
    apt_lines = [line for line in code if re.search(r"\bapt-get\b", line)]
    # One apt-get line, the wrapper, so a new literal apt-get call cannot skip its wait. A call
    # spelled some other way is the behavioral tests' to catch, not this scan's.
    assert len(apt_lines) == 1, apt_lines
    assert "DPkg::Lock::Timeout=" in apt_lines[0]
    assert "DEBIAN_FRONTEND=noninteractive" in apt_lines[0]
    # dpkg itself cannot wait for its lock, which is what lost on 2026-10-21.
    assert not [line for line in code if re.search(r"\bdpkg\s+(-i|--install)\b", line)]


def test_the_lock_budget_fits_inside_the_hook_timeout() -> None:
    """A hook that reaches its timeout loses its output, PWSH INSTALL FAILED included."""
    budget = [m for line in _code_lines() if (m := re.fullmatch(r"lock_wait=(\d+)", line))]
    assert len(budget) == 1
    # Headroom for the downloads and installs themselves; the script's header has measured times.
    assert int(budget[0].group(1)) + 120 <= _cloud_handlers()[0]["timeout"]


def _install_pwsh_definitions() -> str:
    """The script's text from the lock budget through install_pwsh, so the function runs alone."""
    text = _SCRIPT.read_text(encoding="utf-8")
    start, end = text.index("\nlock_wait="), text.index("\npwsh_new=0")
    return text[start:end]


# apt's wording for a held lock: the lists lock is what `update` takes, the dpkg frontend lock is
# what `install` takes and what a bare `dpkg -i` lost on 2026-10-21.
_LISTS_LOCKED = "Could not get lock /var/lib/apt/lists/lock. It is held by process 280 (apt-get)"
_DPKG_LOCKED = "Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 280 (apt-get)"


def _run_install_pwsh(
    bash: Path, tmp_path: Path, *, fail_verb: str, fail_times: int, message: str, lock_wait: int
) -> tuple[subprocess.CompletedProcess[str], list[tuple[str, int, str]]]:
    """Run install_pwsh against stub curl and apt-get; return the run and each apt-get call.

    The apt-get stub fails its first ``fail_times`` calls whose verb is ``fail_verb``, printing
    ``message`` the way apt does.
    """
    path = _write_stubs(
        tmp_path,
        {
            "curl": 'while [ $# -gt 0 ]; do [ "$1" = -o ] && : >"$2"; shift; done',
            # $1 $2 are `-o DPkg::Lock::Timeout=N`, so $3 is the verb.
            "apt-get": (
                'printf "%s,%s|%s\\n" "$DEBIAN_FRONTEND" "$LC_ALL" "$*" >>"$APT_LOG"\n'
                '[ "$3" = "$FAIL_VERB" ] || exit 0\n'
                'n=$(cat "$FAIL_COUNT" 2>/dev/null || echo 0); echo $((n + 1)) >"$FAIL_COUNT"\n'
                '[ "$n" -ge "$FAIL_TIMES" ] && exit 0\n'
                'echo "E: $FAIL_MSG" >&2; exit 100'
            ),
        },
    )
    log = tmp_path / "apt.log"
    # The script's own mktemp files land here, so the test can see they were cleaned up.
    tmp = tmp_path / "tmp"
    tmp.mkdir()
    env = {
        "TMPDIR": tmp.as_posix(),
        "APT_LOG": log.as_posix(),
        "FAIL_COUNT": (tmp_path / "fails").as_posix(),
        "FAIL_VERB": fail_verb,
        "FAIL_TIMES": str(fail_times),
        "FAIL_MSG": message,
        **path,
    }
    # A sleep that only advances bash's clock: the deadline arithmetic is the same, with no real
    # wait, so the budget runs out on the retries' own sleeps rather than on how fast the box is.
    program = (
        "sleep() { SECONDS=$((SECONDS + $1)); }\n"
        f"{_install_pwsh_definitions()}\nlock_wait={lock_wait}\ninstall_pwsh; echo rc=$?\n"
    )
    result = _run(bash, ["-c", program], env, tmp_path)
    assert log.exists(), ("apt-get stub never ran", result.stdout, result.stderr)
    assert not list(tmp.iterdir()), list(tmp.iterdir())
    calls = []
    for line in log.read_text(encoding="utf-8").splitlines():
        frontend, args = line.split("|", 1)
        m = re.fullmatch(r"-o DPkg::Lock::Timeout=(\d+) (.*)", args)
        assert m is not None, f"apt-get called without a lock timeout first: {args!r}"
        calls.append((frontend, int(m.group(1)), m.group(2)))
    return result, calls


def test_install_pwsh_shares_one_budget_and_retries_a_locked_update(
    bash: Path, tmp_path: Path
) -> None:
    budget = 120
    result, calls = _run_install_pwsh(
        bash, tmp_path, fail_verb="update", fail_times=1, message=_LISTS_LOCKED, lock_wait=budget
    )
    assert "rc=0" in result.stdout, (result.stdout, result.stderr)
    verbs = [args.split()[0] for _, _, args in calls]
    assert verbs == ["install", "update", "update", "install"], calls
    deb = calls[0][2].split()[-1]
    # apt-get treats an argument as a local file only when it holds a slash.
    assert "/" in deb and deb.endswith(".deb"), deb
    assert calls[-1][2].split()[-1] == "powershell"
    # _run removes both from the env, so these values are the script's own. LC_ALL=C is what keeps
    # the lock message in the English the retry matches.
    assert all(frontend == "noninteractive,C" for frontend, _, _ in calls), calls
    # One shared budget: the retry's 2 s sleep is charged to every later call, so a fresh budget per
    # call (which could add up past the hook timeout) fails here.
    waits = [wait for _, wait, _ in calls]
    assert waits == sorted(waits, reverse=True) and waits[0] <= budget, waits
    assert waits[-1] <= budget - 2, waits


def test_a_lock_that_never_frees_fails_inside_the_budget(bash: Path, tmp_path: Path) -> None:
    result, calls = _run_install_pwsh(
        bash, tmp_path, fail_verb="install", fail_times=1000, message=_DPKG_LOCKED, lock_wait=10
    )
    # Non-zero, so the caller prints PWSH INSTALL FAILED rather than hanging or claiming success.
    assert "rc=" in result.stdout and "rc=0" not in result.stdout, (result.stdout, result.stderr)
    assert all(args.endswith(".deb") for _, _, args in calls), calls
    # Control: the locked install really was retried, so the failure is the deadline, not a first
    # refusal. The upper bound is the deadline itself: one try per 2 s sleep, plus the first.
    assert 3 <= len(calls) <= 10 // 2 + 1, calls


def test_a_failure_that_is_not_a_held_lock_is_not_retried(bash: Path, tmp_path: Path) -> None:
    """A lasting error, such as a refused source, must not burn the whole budget at session start."""
    result, calls = _run_install_pwsh(
        bash,
        tmp_path,
        fail_verb="update",
        fail_times=1000,
        message="Failed to fetch https://packages.microsoft.com/  403  Forbidden",
        lock_wait=120,
    )
    assert "rc=" in result.stdout and "rc=0" not in result.stdout, (result.stdout, result.stderr)
    assert [args.split()[0] for _, _, args in calls] == ["install", "update"], calls
