# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The cloud-only SessionStart hook: wired once, gated on CLAUDE_CODE_REMOTE, and inert locally.

The hook installs pwsh and Python 3.14 in a Claude Code cloud VM, and the git hooks a local clone
has. The property that matters most is the one nobody would notice breaking: on a LOCAL session it
must do nothing at all. It is wired in the tracked settings file, so every session on every account
runs its command, and a broken gate would run apt-get on a developer box, or write over the shared
.git/hooks every local worktree commits through. So the gate is tested as wired, with a control
proving the same command DOES run the script once the variable is set.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
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
    # The leak-gate settings decide whether pre-commit can run, so only a test may set them. A
    # GIT_* variable from the caller would point git, and the real hook installer, at another repo.
    unset = (
        "CLAUDE_CODE_REMOTE",
        "DEBIAN_FRONTEND",
        "LC_ALL",
        "MEFOR_FORBIDDEN_TOKENS",
        "MEFOR_MIN_DETECTORS",
        "MEFOR_REQUIRE_TOKENS",
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_COMMON_DIR",
    )
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


def _write_stub(path: Path, body: str) -> None:
    path.write_text(f"#!/usr/bin/env bash\n{body}\n", encoding="utf-8", newline="\n")
    path.chmod(0o755)


def _write_stubs(tmp_path: Path, bodies: dict[str, str]) -> dict[str, str]:
    """Bash stand-ins, one executable per name in ``bodies``; returns the PATH that finds them."""
    stubs = tmp_path / "stubs"
    stubs.mkdir()
    for name, body in bodies.items():
        _write_stub(stubs / name, body)
    return {"PATH": str(stubs) + os.pathsep + os.environ.get("PATH", "")}


# `python` stand-ins. The script asks `python` two questions: does it run 3.14 (`-c ...`), and can
# the leak gate run (scan_forbidden.py, exit 2 when it has no full token source).
PY_READY = "exit 0"
PY_NO_TOKENS = (
    '[ "$1" = scripts/security/scan_forbidden.py ] && { echo "scanner: no token source"; exit 2; }'
    "\nexit 0"
)
PY_OLD = "exit 1"
PY_REAL = f'exec "{Path(sys.executable).as_posix()}" "$@"'


def _stub_tools(
    tmp_path: Path,
    gh_output: str | None = "12345\tjdoe\tJane Doe",
    *,
    pwsh_rc: int | None = 0,
    uv_tool_rc: int = 0,
    install_hooks_rc: int = 0,
    install_rc: int = 0,
    python: str = PY_READY,
    py_found: bool = True,
) -> dict[str, str]:
    """`pwsh`, `uv`, `gh`, `python` and `pre-commit` stand-ins, so the cloud path runs with no
    install and no network. `pwsh`, `uv` and `pre-commit` append their argv to the file _calls reads.

    ``pwsh_rc=None`` leaves `pwsh` unstubbed, so the real one runs.
    """
    # An old `python` and a 3.14 to link would make the script link one into the real
    # /usr/local/bin, which a root runner lets it do.
    assert not (python == PY_OLD and py_found), "pair PY_OLD with py_found=False"
    log = 'printf "%s\\n" "$(basename "$0") $*" >>"$STUB_LOG"'
    uv_bin = tmp_path / "uv-bin"
    uv_bin.mkdir()
    _write_stub(
        uv_bin / "pre-commit",
        f'{log}\ncase "$1" in\n  install-hooks) exit {install_hooks_rc} ;;\n'
        f"  install) exit {install_rc} ;;\nesac\nexit 0",
    )
    find = "echo /stub/python3.14" if py_found else ":"
    bodies = {
        "uv": (
            f"{log}\n"
            'case "$1 $2" in\n'
            f'  "python find") {find} ;;\n'
            f'  "tool install") exit {uv_tool_rc} ;;\n'
            f'  "tool dir") echo "{uv_bin.as_posix()}" ;;\n'
            "esac\nexit 0"
        ),
        "gh": f"printf '%s\\n' '{gh_output}'" if gh_output is not None else "exit 1",
        "python": python,
    }
    if pwsh_rc is not None:
        bodies["pwsh"] = (
            f'{log}\n[ {pwsh_rc} = 0 ] || echo "installer: refused" >&2\nexit {pwsh_rc}'
        )
    return {**_write_stubs(tmp_path, bodies), "STUB_LOG": (tmp_path / "calls.log").as_posix()}


def _calls(tmp_path: Path) -> list[str]:
    """Each stubbed call, as `<tool> <args>`, in the order the script made them."""
    log = tmp_path / "calls.log"
    return log.read_text(encoding="utf-8").splitlines() if log.exists() else []


_INSTALLER_CALL = "pwsh -NoProfile -NonInteractive -File scripts/coord/install-git-hooks.ps1"
_ARM = "--arm-pre-commit"
_ARM_HINT = "Before your first commit, run: bash scripts/hooks/cloud-setup.sh --arm-pre-commit ("


def _git_isolation(tmp_path: Path) -> dict[str, str]:
    """No global or system git config, so a caller's hooks directory or init template cannot steer
    `git init` or the real installer out of the sandbox."""
    empty = tmp_path / "empty.gitconfig"
    empty.touch()
    return {"GIT_CONFIG_GLOBAL": str(empty), "GIT_CONFIG_NOSYSTEM": "1"}


def _checkout(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "pyproject.toml").write_text("", encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(_git_isolation(tmp_path))
    subprocess.run(["git", "init", "-q", str(repo)], check=True, env=env)
    return repo


def _local_git_config(repo: Path, key: str) -> str | None:
    out = subprocess.run(
        ["git", "-C", str(repo), "config", "--local", "--get", key],
        capture_output=True,
        text=True,
        check=False,
    )
    return out.stdout.strip() if out.returncode == 0 else None


def _cloud_env(
    repo: Path, tmp_path: Path, *, remote: str | None = "true", **stubs: Any
) -> dict[str, str]:
    """A session's environment over stub tools; ``remote=None`` leaves CLAUDE_CODE_REMOTE unset."""
    env = {
        "CLAUDE_PROJECT_DIR": repo.as_posix(),
        **_git_isolation(tmp_path),
        **_stub_tools(tmp_path, **stubs),
    }
    if remote is not None:
        env["CLAUDE_CODE_REMOTE"] = remote
    return env


def test_the_identity_is_the_pushing_accounts_own_noreply(bash: Path, tmp_path: Path) -> None:
    repo = _checkout(tmp_path)
    result = _run(bash, [str(_SCRIPT)], _cloud_env(repo, tmp_path), repo)
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
    result = _run(bash, [str(_SCRIPT)], _cloud_env(repo, tmp_path), repo)
    assert result.returncode == 0, result.stderr
    assert "no venv yet" not in result.stdout
    # Control: the same run reached the end, so the absence above is the gate, not an early exit.
    assert "[cloud-setup] cloud session." in result.stdout


def test_a_failed_account_lookup_sets_no_identity_and_says_so(bash: Path, tmp_path: Path) -> None:
    repo = _checkout(tmp_path)
    result = _run(bash, [str(_SCRIPT)], _cloud_env(repo, tmp_path, gh_output=None), repo)
    assert result.returncode == 0, result.stderr
    assert "gh api user failed" in result.stdout
    assert _local_git_config(repo, "user.email") is None


def _installed_hooks(repo: Path) -> list[str]:
    """What is in .git/hooks beyond git's own samples (a git with no templates makes no dir)."""
    hooks = repo / ".git" / "hooks"
    return (
        sorted(p.name for p in hooks.iterdir() if p.suffix != ".sample") if hooks.is_dir() else []
    )


def _off_line(stdout: str, what: str) -> str:
    """The one line saying `what` is NOT INSTALLED."""
    off = [ln for ln in stdout.splitlines() if f"{what} NOT INSTALLED" in ln]
    assert len(off) == 1, stdout
    return off[0]


@pytest.mark.parametrize("args", [[], [_ARM]], ids=["session-start", "arm"])
@pytest.mark.parametrize("remote", [None, "false"])
def test_outside_the_cloud_nothing_is_installed(
    bash: Path, tmp_path: Path, remote: str | None, args: list[str]
) -> None:
    """.git/hooks is shared by every local worktree of a clone, so a local run must write nothing.
    The controls are the cloud runs below, which do install. Asked to arm, it says it did not."""
    repo = _checkout(tmp_path)
    result = _run(bash, [str(_SCRIPT), *args], _cloud_env(repo, tmp_path, remote=remote), repo)
    assert result.returncode == (1 if args else 0), result.stderr
    assert ("nothing was armed" in result.stderr) is bool(args), result.stderr
    assert result.stdout == ""
    assert _calls(tmp_path) == []
    assert _installed_hooks(repo) == []


def test_a_session_start_installs_the_git_hooks_and_says_how_to_arm_pre_commit(
    bash: Path, tmp_path: Path
) -> None:
    repo = _checkout(tmp_path)
    result = _run(bash, [str(_SCRIPT)], _cloud_env(repo, tmp_path), repo)
    assert result.returncode == 0, result.stderr
    calls = _calls(tmp_path)
    assert _INSTALLER_CALL in calls, calls
    # Arming builds hook environments, which can outrun the hook's timeout, so it is not done here.
    assert not [c for c in calls if c.startswith(("uv tool", "pre-commit"))], calls
    assert "GIT HOOKS NOT INSTALLED" not in result.stdout, result.stdout
    off = _off_line(result.stdout, "PRE-COMMIT HOOKS")
    assert "the ledger gate and the leak gate among them" in off
    assert _ARM_HINT in off
    # The arming step outlasts the Bash tool's default timeout, so the hint says how to give it room.
    assert "10-minute timeout, or in the background" in off


def test_an_unknown_argument_is_refused_rather_than_run_as_a_session_start(
    bash: Path, tmp_path: Path
) -> None:
    """A typo of --arm-pre-commit must not rerun the whole session start and exit 0."""
    repo = _checkout(tmp_path)
    result = _run(bash, [str(_SCRIPT), "--arm"], _cloud_env(repo, tmp_path), repo)
    assert result.returncode == 2, result.stderr
    assert "usage: cloud-setup.sh [--arm-pre-commit]" in result.stderr
    assert _calls(tmp_path) == []


def test_a_session_start_installs_the_git_hooks_once_per_clone(bash: Path, tmp_path: Path) -> None:
    """The installer copies the gates from the branch it runs on. A resume or compact runs this
    script again, by when the branch may carry the Builder's own edit to a gate."""
    repo = _checkout(tmp_path)
    (repo / ".git" / "hooks").mkdir(exist_ok=True)
    (repo / ".git" / "hooks" / "commit-msg").write_text(
        "#!/bin/sh\n# MessageFoundry claim gate -- INSTALLED COPY.\n", encoding="utf-8"
    )
    result = _run(bash, [str(_SCRIPT)], _cloud_env(repo, tmp_path), repo)
    assert result.returncode == 0, result.stderr
    assert _INSTALLER_CALL not in _calls(tmp_path)
    assert "GIT HOOKS NOT INSTALLED" not in result.stdout
    # Control: the same run reached the end, so the absence above is the check, not an early exit.
    assert "[cloud-setup] cloud session." in result.stdout


def test_a_session_start_says_nothing_once_pre_commit_is_armed(bash: Path, tmp_path: Path) -> None:
    """A resumed VM keeps .git/hooks, so the advice to arm would only be noise there."""
    repo = _checkout(tmp_path)
    (repo / ".git" / "hooks").mkdir(exist_ok=True)
    (repo / ".git" / "hooks" / "pre-commit").write_text(
        "#!/usr/bin/env bash\n# File generated by pre-commit: https://pre-commit.com\n",
        encoding="utf-8",
    )
    result = _run(bash, [str(_SCRIPT)], _cloud_env(repo, tmp_path), repo)
    assert result.returncode == 0, result.stderr
    assert "PRE-COMMIT" not in result.stdout, result.stdout
    # Control: the same run reached the end, so the silence above is the check, not an early exit.
    assert "[cloud-setup] cloud session." in result.stdout


@pytest.mark.parametrize("args", [[], [_ARM]], ids=["session-start", "arm"])
@pytest.mark.parametrize(
    ("python", "py_found", "reason"),
    [
        pytest.param(PY_NO_TOKENS, True, "the leak gate's scanner refuses to run", id="no-tokens"),
        pytest.param(PY_OLD, False, "python does not run Python 3.14", id="no-python-3.14"),
    ],
)
def test_pre_commit_is_not_offered_where_its_hooks_cannot_run(
    bash: Path, tmp_path: Path, python: str, py_found: bool, reason: str, args: list[str]
) -> None:
    """A shim whose hooks cannot start refuses every commit, so neither run moves toward one, and
    one line says why. Neither row links a `python`: one has 3.14, the other finds none to link."""
    repo = _checkout(tmp_path)
    env = _cloud_env(repo, tmp_path, python=python, py_found=py_found)
    result = _run(bash, [str(_SCRIPT), *args], env, repo)
    assert result.returncode == (1 if args else 0), result.stderr
    off = _off_line(result.stdout, "PRE-COMMIT HOOKS")
    assert reason in off
    assert _ARM_HINT not in off
    assert not [c for c in _calls(tmp_path) if c.startswith(("uv tool", "pre-commit"))]
    if python == PY_NO_TOKENS:
        # The scanner's own words come first, so the line's "as its output above says" holds.
        assert "[cloud-setup]   scanner: no token source" in result.stdout
        assert off.endswith("set MEFOR_FORBIDDEN_TOKENS on the cloud environment.")


@pytest.mark.parametrize("tokens", [False, True])
def test_the_scanner_itself_decides_whether_the_leak_gate_can_run(
    bash: Path, tmp_path: Path, tokens: bool
) -> None:
    """The real scan_forbidden.py, so the script's question is the hook's own. The synthetic example
    fills every section the floor reads, so it stands in for the private list here."""
    repo = _checkout(tmp_path)
    security = repo / "scripts" / "security"
    security.mkdir(parents=True)
    # Only these: the worktree may hold the real, git-ignored token list beside them.
    for name in ("scan_forbidden.py", "scan-allowlist.txt", "scan-tokens.local.txt.example"):
        shutil.copy2(_ROOT / "scripts" / "security" / name, security / name)
    env = _cloud_env(repo, tmp_path, python=PY_REAL)
    if tokens:
        env["MEFOR_FORBIDDEN_TOKENS"] = (security / "scan-tokens.local.txt.example").as_posix()
    result = _run(bash, [str(_SCRIPT)], env, repo)
    assert result.returncode == 0, result.stderr
    off = _off_line(result.stdout, "PRE-COMMIT HOOKS")
    assert (_ARM_HINT in off) is tokens, off
    # The example passes the floor and matches nothing real, so a pass on it must say so.
    assert ("blind to every real customer token" in result.stdout) is tokens, result.stdout


def test_arming_installs_pre_commit_builds_every_environment_then_the_shim(
    bash: Path, tmp_path: Path
) -> None:
    repo = _checkout(tmp_path)
    result = _run(bash, [str(_SCRIPT), _ARM], _cloud_env(repo, tmp_path), repo)
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert _calls(tmp_path) == [
        "uv tool install pre-commit==4.7.0",
        "uv tool dir --bin",
        "pre-commit install-hooks",
        "pre-commit install",
    ]
    assert result.stdout.endswith(
        "[cloud-setup] pre-commit hooks installed: the hooks in .pre-commit-config.yaml now run"
        " on each commit.\n"
    )


@pytest.mark.parametrize(
    ("stubs", "reason", "last_call"),
    [
        pytest.param(
            {"uv_tool_rc": 1},
            "uv tool install pre-commit==4.7.0 failed",
            "uv tool install pre-commit==4.7.0",
            id="uv-tool",
        ),
        # The shim must not go in: a hook that cannot start would refuse every commit.
        pytest.param(
            {"install_hooks_rc": 1},
            "a hook environment did not build",
            "pre-commit install-hooks",
            id="install-hooks",
        ),
        pytest.param(
            {"install_rc": 1}, "pre-commit install failed", "pre-commit install", id="install"
        ),
    ],
)
def test_a_failed_arming_step_is_reported_and_stops_there(
    bash: Path, tmp_path: Path, stubs: dict[str, Any], reason: str, last_call: str
) -> None:
    repo = _checkout(tmp_path)
    result = _run(bash, [str(_SCRIPT), _ARM], _cloud_env(repo, tmp_path, **stubs), repo)
    assert result.returncode == 1, result.stderr
    assert f": {reason}" in _off_line(result.stdout, "PRE-COMMIT HOOKS")
    assert _calls(tmp_path)[-1] == last_call
    assert "pre-commit hooks installed" not in result.stdout


def test_a_failed_hook_installer_is_reported_and_the_rest_still_runs(
    bash: Path, tmp_path: Path
) -> None:
    repo = _checkout(tmp_path)
    result = _run(bash, [str(_SCRIPT)], _cloud_env(repo, tmp_path, pwsh_rc=1), repo)
    assert result.returncode == 0, result.stderr
    assert _off_line(result.stdout, "GIT HOOKS") == (
        "[cloud-setup] GIT HOOKS NOT INSTALLED: scripts/coord/install-git-hooks.ps1 failed, so the"
        " claim gate (commit-msg) and the push guard (pre-push) are OFF. Fix what its output above"
        " names, then run: pwsh -NoProfile -File scripts/coord/install-git-hooks.ps1"
    )
    # The failing step's own output is shown, not swallowed.
    assert "[cloud-setup]   installer: refused" in result.stdout
    assert "[cloud-setup] cloud session." in result.stdout


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="runs the real installer under pwsh")
def test_the_real_installer_writes_its_hooks_in_a_cloud_session(bash: Path, tmp_path: Path) -> None:
    """install-git-hooks.ps1 carries no cloud refusal, and this is the run that shows it: the real
    script, under CLAUDE_CODE_REMOTE=true, into a clone carrying its own copy of the scripts."""
    repo = _checkout(tmp_path)
    for sub in ("coord", "hooks"):
        shutil.copytree(_ROOT / "scripts" / sub, repo / "scripts" / sub)
    result = _run(bash, [str(_SCRIPT)], _cloud_env(repo, tmp_path, pwsh_rc=None), repo)
    assert result.returncode == 0, result.stderr
    assert "GIT HOOKS NOT INSTALLED" not in result.stdout, result.stdout
    hooks = repo / ".git" / "hooks"
    markers = {
        "commit-msg": "MessageFoundry claim gate",
        "pre-push": "MessageFoundry push guard",
        "post-commit": "MessageFoundry durability hook",
        "post-merge": "MessageFoundry durability hook",
    }
    for name, marker in markers.items():
        assert marker in (hooks / name).read_text(encoding="utf-8"), name
    payloads = ["claim_check.py", "coord_root.py", "push_guard.py"]
    # Also the positive control for _installed_hooks, which the outside-the-cloud rows read as [].
    assert _installed_hooks(repo) == sorted([*markers, *payloads])
    # Inert: nothing names a remote for the durability hook to push to.
    assert _local_git_config(repo, "mefor.durabilityRemote") is None


def _python_definitions() -> str:
    """`say`, `python_ok` and the script's python block, so ensure_python runs alone."""
    text = _SCRIPT.read_text(encoding="utf-8")
    one_liners = [ln for ln in text.splitlines() if ln.startswith(("say()", "python_ok()"))]
    start, end = text.index("\npython_dir="), text.index('\nensure_python "$py"')
    return "\n".join([*one_liners, text[start:end]])


@pytest.mark.parametrize(
    ("python_is_new", "has_target", "target_works", "dangling", "linked"),
    [
        pytest.param(True, True, True, False, False, id="already-3.14"),
        pytest.param(False, True, True, False, True, id="links-3.14"),
        pytest.param(False, False, True, False, False, id="no-interpreter"),
        pytest.param(False, True, False, False, False, id="link-does-not-help"),
        pytest.param(False, True, True, True, True, id="replaces-a-dangling-link"),
    ],
)
def test_ensure_python_links_a_3_14_python_only_where_one_is_missing(
    bash: Path,
    tmp_path: Path,
    python_is_new: bool,
    has_target: bool,
    target_works: bool,
    dangling: bool,
    linked: bool,
) -> None:
    """The git hooks run `python`, which a stock Ubuntu image may not have."""
    link_dir = tmp_path / "local-bin"
    link_dir.mkdir()
    if dangling:
        try:
            (link_dir / "python").symlink_to(tmp_path / "gone" / "python3.14")
        except OSError:
            pytest.skip("this box cannot make a symlink")
    # The `python` already on PATH: 3.14 or not, which its exit code stands for.
    stubs = _write_stubs(tmp_path, {"python": PY_READY if python_is_new else PY_OLD})
    py = tmp_path / "python3.14"
    _write_stub(py, PY_READY if target_works else PY_OLD)
    program = (
        f"{_python_definitions()}\npython_dir='{link_dir.as_posix()}'\n"
        f"ensure_python '{py.as_posix() if has_target else ''}'; echo rc=$?\n"
    )
    env = {"PATH": str(link_dir) + os.pathsep + stubs["PATH"]}
    result = _run(bash, ["-c", program], env, tmp_path)
    rc = 0 if python_is_new or linked else 1
    assert f"rc={rc}" in result.stdout, (result.stdout, result.stderr)
    assert (link_dir / "python").exists() is linked, list(link_dir.iterdir())
    assert ("[cloud-setup] linked " in result.stdout) is linked, result.stdout
    # A link that could not help is reported; a missing interpreter was reported where it failed.
    not_linked = has_target and rc == 1
    assert ("[cloud-setup] PYTHON NOT LINKED:" in result.stdout) is not_linked, result.stdout


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
