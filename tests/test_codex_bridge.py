# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Exercise the bridge with disposable sources, never the live fleet registry."""

from __future__ import annotations

import importlib.util
import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def bridge():
    spec = importlib.util.spec_from_file_location("codex_bridge", ROOT / "scripts/codex/bridge.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def settings(root, handlers, event="PreToolUse"):
    (root / ".claude").mkdir(exist_ok=True)
    (root / ".claude/settings.json").write_text(
        json.dumps({"hooks": {event: [{"matcher": "Bash", "hooks": handlers}]}}),
        encoding="utf-8",
    )


def handler(text):
    return {"type": "command", "command": sys.executable, "args": ["-c", f"print({text!r})"]}


def test_reads_current_source_each_time_and_preserves_denial(bridge, tmp_path):
    payload = {"session_id": "test", "hook_event_name": "PreToolUse", "tool_name": "Bash"}
    settings(tmp_path, [])
    assert bridge.dispatch(tmp_path, payload) == {}
    denial = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": "source says no",
        }
    }
    settings(tmp_path, [handler(json.dumps(denial))])
    assert bridge.dispatch(tmp_path, payload) == denial


def test_deny_wins_over_later_allow(bridge, tmp_path):
    def decision(value):
        return handler(
            json.dumps(
                {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": value,
                        "permissionDecisionReason": value,
                    }
                }
            )
        )

    settings(tmp_path, [decision("deny"), decision("allow")])
    result = bridge.dispatch(
        tmp_path, {"session_id": "x", "hook_event_name": "PreToolUse", "tool_name": "Bash"}
    )
    assert result["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_child_environment_does_not_impersonate_claude(bridge, tmp_path, monkeypatch):
    monkeypatch.setenv("CLAUDE_CODE_SESSION_ID", "claude-real")
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", "claude-account")
    env = bridge.child_environment(tmp_path, "codex-real")
    assert env["KORUS_AGENT"] == "codex"
    assert env["KORUS_SESSION_ID"] == "codex-real"
    assert env["KORUS_STATE_REL"].startswith(".codex/sessions/")
    assert "CLAUDE_CODE_SESSION_ID" not in env
    assert "CLAUDE_CONFIG_DIR" not in env
    assert os.environ["CLAUDE_CODE_SESSION_ID"] == "claude-real"


def test_missing_session_is_error(bridge, tmp_path):
    with pytest.raises(ValueError, match="session"):
        bridge.child_environment(tmp_path, "")


def test_new_unsupported_hook_is_reported(bridge, tmp_path):
    settings(tmp_path, [{"type": "prompt", "prompt": "review"}])
    with pytest.raises(ValueError, match="prompt"):
        bridge.dispatch(
            tmp_path, {"session_id": "x", "hook_event_name": "PreToolUse", "tool_name": "Bash"}
        )


def test_hook_timeout_is_reported(bridge, tmp_path):
    settings(
        tmp_path,
        [
            {
                "type": "command",
                "command": sys.executable,
                "args": ["-c", "import time; time.sleep(5)"],
                "timeout": 0.1,
            }
        ],
    )
    with pytest.raises(subprocess.TimeoutExpired):
        bridge.dispatch(
            tmp_path, {"session_id": "x", "hook_event_name": "PreToolUse", "tool_name": "Bash"}
        )


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="requires PowerShell")
def test_real_guard_runs_from_current_claude_settings(bridge, tmp_path):
    script = ROOT / "scripts/hooks/block-api-burn.ps1"
    settings(
        tmp_path,
        [{"type": "command", "command": "pwsh", "args": ["-NoProfile", "-File", str(script)]}],
    )
    tool_input = {"command": "gh run watch 123"}
    payload = {
        "session_id": "x",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": tool_input,
    }
    result = bridge.dispatch(tmp_path, payload)
    assert result["hookSpecificOutput"]["permissionDecision"] == "deny"
    tool_input["command"] = "gh run view 123"
    assert bridge.dispatch(tmp_path, payload) == {}


def test_skill_pointer_reads_source_and_refresh_keeps_unrelated_skills(bridge, tmp_path):
    source = tmp_path / ".claude/skills/example/SKILL.md"
    source.parent.mkdir(parents=True)
    source.write_text("---\nname: example\ndescription: Old metadata\n---\nOld procedure\n")
    other = tmp_path / ".agents/skills/other/SKILL.md"
    other.parent.mkdir(parents=True)
    other.write_text("Keep this unrelated skill")
    bridge.sync_skills(tmp_path)
    target = tmp_path / ".agents/skills/example/SKILL.md"
    assert "Old procedure" not in target.read_text()
    # .claude/ is gitignored, so a committed link into it dangles in every other clone.
    assert "source-skill example`" in target.read_text()
    assert ".claude/skills" not in target.read_text()
    source.write_text("---\nname: example\ndescription: New metadata\n---\nNew procedure\n")
    bridge.sync_skills(tmp_path)
    assert "New metadata" in target.read_text()
    assert "New procedure" not in target.read_text()
    assert other.read_text() == "Keep this unrelated skill"


def test_user_skill_discovery_and_repo_precedence(bridge, tmp_path):
    user_skills = tmp_path / "claude-user/skills"
    for name in ("seat", "standup"):
        source = user_skills / name / "SKILL.md"
        source.parent.mkdir(parents=True)
        source.write_text(f"---\nname: {name}\ndescription: User {name}\n---\nUser procedure\n")
    local = tmp_path / ".claude/skills/standup/SKILL.md"
    local.parent.mkdir(parents=True)
    local.write_text("---\nname: standup\ndescription: Repo standup\n---\nRepo procedure\n")
    bridge.sync_skills(tmp_path, user_skills=user_skills)
    seat = (tmp_path / ".agents/skills/seat/SKILL.md").read_text()
    assert "source-skill seat" in seat
    assert "User procedure" not in seat
    assert "Repo standup" in (tmp_path / ".agents/skills/standup/SKILL.md").read_text()
    assert (
        bridge.source_skill(tmp_path, "seat", user_skills=user_skills)
        == user_skills / "seat/SKILL.md"
    )


def test_repo_only_refresh_reports_a_pointer_no_invocation_can_resolve(
    bridge, tmp_path, monkeypatch
):
    """Every pointer shares one text form, so the resolver, not the text, decides what is missing."""
    user_skills = tmp_path / "claude-user/skills"
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(user_skills.parent))
    for directory, name in ((user_skills, "seat"), (tmp_path / ".claude/skills", "example")):
        source = directory / name / "SKILL.md"
        source.parent.mkdir(parents=True)
        source.write_text(f"---\nname: {name}\ndescription: {name}\n---\nProcedure\n")
    bridge.sync_skills(tmp_path, user_skills=user_skills)
    (tmp_path / ".claude/skills/example/SKILL.md").unlink()
    (tmp_path / ".claude/skills/kept/SKILL.md").parent.mkdir()
    (tmp_path / ".claude/skills/kept/SKILL.md").write_text("---\nname: kept\n---\nProcedure\n")
    missing = [m for m in bridge.sync_skills(tmp_path) if m.startswith("MISSING SOURCE")]
    assert missing == [
        f"MISSING SOURCE: {Path('.agents/skills/example/SKILL.md')}; remove or rename this pointer"
    ]


@pytest.fixture
def dual_repo(tmp_path):
    if shutil.which("pwsh") is None or os.name != "nt":
        pytest.skip("the existing seat writer requires Windows PowerShell")
    root = tmp_path / "repo with spaces"
    root.mkdir()
    for relative in (
        "scripts/coord/seat.ps1",
        "scripts/coord/mail-key.ps1",
        "scripts/coord/coord-root.ps1",
        "scripts/hooks/role-card-inject.ps1",
        "scripts/hooks/precompact-reprime.ps1",
    ):
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, target)
    roster = root / "docs/roles"
    roster.mkdir(parents=True)
    (roster / "seats.json").write_text(
        json.dumps({"live": ["special", "manager"], "aliases": {}, "retired": {}, "elsewhere": {}})
    )
    (roster / "special.card.md").write_text("CODEX ROLE CARD")
    (roster / "manager.card.md").write_text("CLAUDE ROLE CARD")
    for args in (
        ("init", "-q"),
        ("config", "user.name", "Test"),
        ("config", "user.email", "test@example.invalid"),
        ("add", "."),
        ("commit", "-qm", "fixture"),
    ):
        subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)
    return root


def ps(root, relative, *args, env, payload=None):
    return subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(root / relative), *args],
        cwd=root,
        env=env,
        input=json.dumps(payload) if payload else "",
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=True,
        timeout=30,
    ).stdout


def test_both_agents_keep_their_own_markers_records_and_goals(bridge, dual_repo):
    root = dual_repo
    claude = os.environ.copy()
    for key in ("KORUS_AGENT", "KORUS_SESSION_ID", "KORUS_STATE_REL", "KORUS_SEAT"):
        claude.pop(key, None)
    claude["CLAUDE_CODE_SESSION_ID"] = "same-id"
    codex = bridge.child_environment(root, "same-id")
    for env, seat_name, goal in (
        (claude, "manager", "CLAUDE GOAL"),
        (codex, "special", "CODEX GOAL"),
    ):
        ps(root, "scripts/coord/seat.ps1", "-Declare", "-Seat", seat_name, "-Goal", goal, env=env)
    assert (root / ".claude/seat.local.txt").read_text() == "manager"
    assert (root / codex["KORUS_STATE_REL"] / "seat.local.txt").read_text() == "special"
    records = {
        p.stem: json.loads(p.read_text(encoding="utf-8-sig"))
        for p in (root / ".git/mefor-coord/seats").glob("*/*.json")
    }
    assert "codex-same-id" not in records, "Codex must not appear as a dead Claude process"
    codex_records = {
        p.stem: json.loads(p.read_text(encoding="utf-8-sig"))
        for p in (root / ".git/mefor-coord/codex-seats").glob("*/*.json")
    }
    assert records["same-id"]["goal"] == "CLAUDE GOAL"
    assert codex_records["codex-same-id"]["goal"] == "CODEX GOAL"
    assert codex_records["codex-same-id"]["configRootLabel"] == "codex"
    for env, expected, absent in ((claude, "CLAUDE", "CODEX"), (codex, "CODEX", "CLAUDE")):
        card = ps(root, "scripts/hooks/role-card-inject.ps1", "-WorktreeRoot", str(root), env=env)
        assert f"{expected} ROLE CARD" in card
        assert f"{absent} ROLE CARD" not in card
        recovered = ps(
            root,
            "scripts/hooks/precompact-reprime.ps1",
            env=env,
            payload={"hook_event_name": "SessionStart", "source": "compact"},
        )
        assert f"{expected} GOAL" in recovered
        assert f"{absent} GOAL" not in recovered


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="requires PowerShell")
def test_registered_command_runs_from_a_subdirectory(tmp_path):
    """Run the exact TOML command using a disposable launcher (no live startup writes)."""
    import tomllib

    root = tmp_path / "repo with spaces"
    scripts = root / "scripts/codex"
    scripts.mkdir(parents=True)
    (scripts / "invoke.ps1").write_text("[Console]::Out.Write([Console]::In.ReadToEnd())\n")
    subprocess.run(["git", "init", "-q", str(root)], check=True, capture_output=True)
    config = tomllib.loads((ROOT / ".codex/config.toml").read_text())
    assert set(config["hooks"]) == {
        "SessionStart",
        "SessionEnd",
        "PreToolUse",
        "PostToolUse",
        "PermissionRequest",
        "UserPromptSubmit",
        "PreCompact",
        "PostCompact",
        "Stop",
        "SubagentStart",
        "SubagentStop",
    }
    command = config["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    completed = subprocess.run(
        ["pwsh", "-NoProfile", "-Command", command],
        cwd=scripts,
        input='{"probe":true}',
        text=True,
        capture_output=True,
        check=True,
        timeout=20,
    )
    assert json.loads(completed.stdout) == {"probe": True}


# --- The registered line, end to end: a hook's exit 2 reaches Codex as 2 where the outer shell
# keeps it, and every fault path is at least as strict as main's exit code (non-zero, as on main).

_DENY = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny"}}
_PAYLOAD = {"session_id": "x", "hook_event_name": "PreToolUse", "tool_name": "Bash"}


def _py(source, **extra):
    return {"type": "command", "command": sys.executable, "args": ["-c", source], **extra}


def _outer_shells():
    shells = ["pwsh"]
    if os.name == "nt":
        shells.append("cmd")
    if shutil.which("sh"):
        shells.append("sh")
    return shells


def _outer_argv(shell, command):
    # cmd takes the line verbatim, as a string: Python's argv quoting escapes quotes in a way cmd
    # does not read.
    if shell == "cmd":
        return f"cmd /d /c {command}"
    if shell == "pwsh":
        return ["pwsh", "-NoProfile", "-Command", command]
    if shell == "none":
        return shlex.split(command)
    return [shutil.which("sh"), "-c", command]


def _link_python(root):
    """Give the copied launcher a .venv that reaches this test's own interpreter."""
    if os.name == "nt":
        if not (Path(sys.prefix) / "Scripts/python.exe").is_file():
            pytest.skip("needs a virtualenv to junction on Windows")
        link = ["cmd", "/c", "mklink", "/J", str(root / ".venv"), sys.prefix]
        subprocess.run(link, check=True, capture_output=True)
    else:
        (root / ".venv/bin").mkdir(parents=True)
        (root / ".venv/bin/python").symlink_to(sys.executable)


def _make_repo(tmp_path, settings_text, venv=True):
    root = tmp_path / "repo"
    scripts = root / "scripts/codex"
    scripts.mkdir(parents=True)
    for name in ("invoke.ps1", "bridge.py"):
        shutil.copy2(ROOT / "scripts/codex" / name, scripts / name)
    (root / ".claude").mkdir()
    (root / ".claude/settings.json").write_text(settings_text, encoding="utf-8")
    if venv:
        _link_python(root)
    subprocess.run(["git", "init", "-q", str(root)], check=True, capture_output=True)
    return root


def _launch(argv, cwd, payload=_PAYLOAD, env=None):
    stdin = payload if isinstance(payload, str) else json.dumps(payload)
    return subprocess.run(
        argv,
        cwd=cwd,
        input=stdin,
        text=True,
        capture_output=True,
        check=False,
        timeout=60,
        env=env,
    )


def _run_registered(tmp_path, shell, settings_text, payload=_PAYLOAD, venv=True):
    import tomllib

    root = _make_repo(tmp_path, settings_text, venv)
    config = tomllib.loads((ROOT / ".codex/config.toml").read_text())
    command = config["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    return _launch(_outer_argv(shell, command), root / "scripts/codex", payload)


def _hooks(*handlers):
    return json.dumps({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": list(handlers)}]}})


_FAULTS = {
    "hook-exits-1": (_hooks(_py("import sys; sys.exit(1)")), _PAYLOAD, True),
    "hook-timeout": (_hooks(_py("import time; time.sleep(5)", timeout=0.5)), _PAYLOAD, True),
    "unsupported-hook": (_hooks({"type": "prompt", "prompt": "review"}), _PAYLOAD, True),
    "non-object-json": (_hooks(_py("print('[1]')")), _PAYLOAD, True),
    "null-json": (_hooks(_py("print('null')")), _PAYLOAD, True),
    "hooks-null": (
        json.dumps({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": None}]}}),
        _PAYLOAD,
        True,
    ),
    "unparseable-settings": ("{not json", _PAYLOAD, True),
    "missing-session-id": (_hooks(_py("print('{}')")), {**_PAYLOAD, "session_id": ""}, True),
    "unparseable-payload": (_hooks(_py("print('{}')")), "not json", True),
    "no-venv": (_hooks(_py("print('{}')")), _PAYLOAD, False),
}


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="requires PowerShell")
@pytest.mark.parametrize("shell", _outer_shells())
@pytest.mark.parametrize("fault", list(_FAULTS))
def test_every_fault_path_is_at_least_as_strict_as_mains_exit_code(tmp_path, shell, fault):
    """On origin/main each of these exits non-zero through the registered line, never 0."""
    settings_text, payload, venv = _FAULTS[fault]
    completed = _run_registered(tmp_path, shell, settings_text, payload, venv)
    assert completed.returncode != 0, (completed.stdout, completed.stderr)


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="requires PowerShell")
@pytest.mark.parametrize("shell", _outer_shells())
def test_a_hooks_exit_2_reaches_codex_where_the_outer_shell_keeps_it(tmp_path, shell):
    completed = _run_registered(tmp_path, shell, _hooks(_py("import sys; sys.exit(2)")))
    # pwsh -Command reports a last native program's or script's exit 2 as 1; cmd and sh pass it on.
    assert completed.returncode == (1 if shell == "pwsh" else 2), completed.stderr


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="requires PowerShell")
@pytest.mark.parametrize("shell", _outer_shells())
def test_a_deny_and_a_clean_run_exit_0(tmp_path, shell):
    deny = _run_registered(tmp_path / "deny", shell, _hooks(_py(f"print({json.dumps(_DENY)!r})")))
    assert deny.returncode == 0, deny.stderr
    assert json.loads(deny.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
    clean = _run_registered(tmp_path / "clean", shell, _hooks(_py("print('{}')")))
    assert clean.returncode == 0, clean.stderr


# --- The block exit flag. invoke.ps1 passes `--block-exit 10` only for `hook` as its first
# argument, the condition its 10-to-2 mapping uses; without the flag a hook's exit 2 exits 2, as on
# main. The flag is argv, so neither a child nor an inherited environment carries it.

_EXIT_2 = _hooks(_py("import sys; sys.exit(2)"))
# A variable an ancestor could set; the block exit must not depend on the environment.
_OLD_SENTINEL = {"MEFOR_CODEX_BLOCK_SENTINEL": "1"}
_needs_pwsh = pytest.mark.skipif(shutil.which("pwsh") is None, reason="requires PowerShell")


def _env(**extra):
    env = {k: v for k, v in os.environ.items() if k not in _OLD_SENTINEL}
    env.update(extra)
    return env


def _direct(root, *args, payload=_PAYLOAD, **extra):
    bridge_py = root / "scripts/codex/bridge.py"
    return _launch([sys.executable, str(bridge_py), *args], root, payload, _env(**extra))


def _invoke_file(root, *args, payload=_PAYLOAD, **extra):
    invoke = root / "scripts/codex/invoke.ps1"
    argv = ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(invoke), *args]
    return _launch(argv, root, payload, _env(**extra))


def _assert_blocked(completed, code):
    """Assert the exit code and the bridge's block line, which a silent blocking hook produces."""
    assert completed.returncode == code, completed.stderr
    assert "Claude hook blocked this event" in completed.stderr


@_needs_pwsh
def test_the_registered_line_gives_2_for_a_hooks_exit_2(tmp_path):
    _assert_blocked(_run_registered(tmp_path, "none", _EXIT_2), 2)


def test_a_direct_bridge_hook_gives_2_for_a_hooks_exit_2(tmp_path):
    root = _make_repo(tmp_path, _EXIT_2, venv=False)
    _assert_blocked(_direct(root, "hook"), 2)
    _assert_blocked(_direct(root, "hook", "--block-exit", "10"), 10)


def test_the_retired_sentinel_variable_does_not_change_the_block_exit(tmp_path):
    root = _make_repo(tmp_path, _EXIT_2, venv=False)
    _assert_blocked(_direct(root, "hook", **_OLD_SENTINEL), 2)


@_needs_pwsh
def test_invoke_ignores_an_inherited_environment(tmp_path):
    root = _make_repo(tmp_path, _EXIT_2)
    _assert_blocked(_invoke_file(root, "--session-id", "x", "hook", **_OLD_SENTINEL), 2)


_ARGV_CHILD = "import json, sys\nprint(json.dumps(sys.argv[1:]))\n"


@_needs_pwsh
def test_invoke_adds_no_flag_to_a_run_childs_argv(tmp_path):
    root = _make_repo(tmp_path, _hooks())
    (root / "scripts/argv.py").write_text(_ARGV_CHILD, encoding="utf-8")
    completed = _invoke_file(root, "run", "scripts/argv.py", "--b", "1", CODEX_THREAD_ID="x")
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == ["--b", "1"]


@pytest.mark.parametrize("flags", [["--block", "1", "--block-exit", "0"], ["--block-exit", "10"]])
def test_a_run_childs_block_exit_flags_pass_through_as_on_main(tmp_path, flags):
    root = _make_repo(tmp_path, _hooks(), venv=False)
    (root / "scripts/argv.py").write_text(_ARGV_CHILD, encoding="utf-8")
    completed = _direct(root, "--session-id", "x", "run", "scripts/argv.py", *flags)
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == flags


def test_only_the_launchers_block_exit_is_honoured(tmp_path):
    root = _make_repo(tmp_path, _EXIT_2, venv=False)
    _assert_blocked(_direct(root, "hook", "--block-exit", "0"), 2)


@_needs_pwsh
def test_invoke_forwards_a_single_argument_whole(tmp_path):
    root = _make_repo(tmp_path, _hooks())
    completed = _invoke_file(root, "state-dir", CODEX_THREAD_ID="x")
    assert completed.returncode == 0, completed.stderr
    assert ".codex" in completed.stdout


@_needs_pwsh
def test_invoke_with_a_flag_before_hook_gives_2(tmp_path):
    root = _make_repo(tmp_path, _EXIT_2)
    _assert_blocked(_invoke_file(root, "--session-id", "x", "hook"), 2)


@_needs_pwsh
def test_a_run_child_exiting_10_is_not_remapped(tmp_path):
    root = _make_repo(tmp_path, _hooks())
    (root / "scripts/exit10.py").write_text("import sys\nsys.exit(10)\n", encoding="utf-8")
    assert _invoke_file(root, "--session-id", "x", "run", "scripts/exit10.py").returncode == 10
    run_first = _invoke_file(root, "run", "scripts/exit10.py", CODEX_THREAD_ID="x")
    assert run_first.returncode == 10, run_first.stderr
    direct = _direct(root, "--session-id", "x", "run", "scripts/exit10.py")
    assert direct.returncode == 10, direct.stderr


# The exit code each fault gave on origin/main, through each launch path. "registered" runs the
# .codex/config.toml line with no outer shell; its pwsh -Command reports the script's exit 2 as 1.
# With no .venv, invoke.ps1 throws before the bridge runs, which exits 1.
_MAIN_FAULT_EXIT = {"registered": 1, "direct": 2, "invoke": 2}


@pytest.mark.parametrize("path", list(_MAIN_FAULT_EXIT))
@pytest.mark.parametrize("fault", list(_FAULTS))
def test_every_fault_path_exits_as_on_main(tmp_path, path, fault):
    settings_text, payload, venv = _FAULTS[fault]
    if path != "direct" and shutil.which("pwsh") is None:
        pytest.skip("requires PowerShell")
    if path == "registered":
        completed = _run_registered(tmp_path, "none", settings_text, payload, venv)
    elif not venv and path == "direct":
        pytest.skip("the direct path never reads a .venv")
    else:
        root = _make_repo(tmp_path, settings_text, venv and path != "direct")
        if path == "direct":
            completed = _direct(root, "hook", "--block-exit", "10", payload=payload)
        else:
            completed = _invoke_file(root, "hook", payload=payload)
    expected = 1 if not venv else _MAIN_FAULT_EXIT[path]
    assert completed.returncode == expected, (completed.stdout, completed.stderr)
