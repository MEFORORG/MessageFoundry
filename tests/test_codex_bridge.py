# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Exercise the bridge with disposable sources, never the live fleet registry."""

from __future__ import annotations

import importlib.util
import io
import json
import os
import re
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


def settings(root, handlers, event="PreToolUse", matcher="Bash"):
    (root / ".claude").mkdir(exist_ok=True)
    (root / ".claude/settings.json").write_text(
        json.dumps({"hooks": {event: [{"matcher": matcher, "hooks": handlers}]}}),
        encoding="utf-8",
    )


def python(source, **extra):
    return {"type": "command", "command": sys.executable, "args": ["-c", source], **extra}


def handler(text):
    return python(f"print({text!r})")


def exits(code, stdout=""):
    return python(
        f"print({stdout!r}); import sys; sys.stderr.write('hook says {code}'); sys.exit({code})"
    )


DENIAL = {
    "hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": "later hook ran",
    }
}
BASH_CALL = {"session_id": "x", "hook_event_name": "PreToolUse", "tool_name": "Bash"}


def assert_denied_with_notice(result, notice):
    """The later hook's denial survived, and the failure reached the JSON Codex reads."""
    assert result["hookSpecificOutput"] == DENIAL["hookSpecificOutput"]
    assert notice in result["systemMessage"]
    assert "(not blocking)" in result["systemMessage"]


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
    payload = {"session_id": "x", "hook_event_name": "PreToolUse", "tool_name": "Bash"}
    settings(tmp_path, [{"type": "prompt", "prompt": "review"}])
    # In an advisory group it is reported and the group skipped.
    assert "prompt" in bridge.dispatch(tmp_path, payload)["systemMessage"]
    # A hook that set onFailure to block has failed, so it blocks.
    settings(tmp_path, [{"type": "prompt", "prompt": "review", "onFailure": "block"}])
    with pytest.raises(bridge.HookBlocked, match="prompt"):
        bridge.dispatch(tmp_path, payload)


def test_hook_timeout_is_reported_without_blocking_later_hooks(bridge, tmp_path, capsys):
    """Claude Code treats a timed-out hook as a non-blocking error, and so must the bridge."""
    slow = python("import time; time.sleep(5)", timeout=0.1, statusMessage="the slow hook")
    settings(tmp_path, [slow, handler(json.dumps(DENIAL))])
    notice = "timed out after 0.1 seconds: the slow hook (not blocking)"
    assert_denied_with_notice(bridge.dispatch(tmp_path, BASH_CALL), notice)
    assert notice in capsys.readouterr().err


@pytest.mark.parametrize("code", [1, 3, 127])
def test_non_blocking_exit_is_reported_and_later_hooks_still_run(bridge, tmp_path, capsys, code):
    """Only exit 2 blocks. Another non-zero exit must neither block nor stop the hooks after it."""
    # The failing hook's stdout is not read, so its "continue": false must not reach the result.
    settings(tmp_path, [exits(code, stdout='{"continue": false}'), handler(json.dumps(DENIAL))])
    assert_denied_with_notice(bridge.dispatch(tmp_path, BASH_CALL), f"exited {code}: ")
    err = capsys.readouterr().err
    # The hook's own stderr ends its line, so the bridge's report starts a fresh one.
    assert f"hook says {code}\nCodex bridge: hook exited {code}: " in err


def test_unstartable_hook_is_reported_without_blocking(bridge, tmp_path):
    missing = {"type": "command", "command": str(tmp_path / "no-such-hook.exe"), "args": []}
    settings(tmp_path, [missing, handler(json.dumps(DENIAL))])
    assert_denied_with_notice(bridge.dispatch(tmp_path, BASH_CALL), "could not start")


@pytest.mark.parametrize(
    "failing",
    [exits(1), python("import time; time.sleep(5)", timeout=0.1)],
    ids=["exit-1", "timeout"],
)
def test_on_failure_block_turns_a_non_blocking_failure_into_a_block(bridge, tmp_path, failing):
    settings(tmp_path, [{**failing, "onFailure": "block"}, handler(json.dumps(DENIAL))])
    with pytest.raises(bridge.HookBlocked, match="onFailure is block"):
        bridge.dispatch(tmp_path, BASH_CALL)


def test_exit_2_blocks_and_stops_the_remaining_hooks(bridge, tmp_path, capsys):
    marker = tmp_path / "later-hook-ran"
    settings(tmp_path, [exits(2), python(f"open({str(marker)!r}, 'w').close()")])
    with pytest.raises(bridge.HookBlocked, match="hook says 2"):
        bridge.dispatch(tmp_path, BASH_CALL)
    assert not marker.exists()
    # The reason travels once, in the HookBlocked run_hook prints, not also as raw stderr.
    assert "hook says 2" not in capsys.readouterr().err


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="requires PowerShell")
@pytest.mark.parametrize(
    ("command", "outcome"),
    [
        # pwsh -Command reports a native program's exit 2 as 1, which would fail open.
        ("& '{py}' -c 'import sys; sys.exit(2)'", "block"),
        # A stale exit 2 from an earlier statement must not block a hook that went on to succeed.
        ("& '{py}' -c 'import sys; sys.exit(2)'; Write-Output '{{}}'", "allow"),
        # A failed cmdlet as the last statement stays -Command's own non-blocking 1.
        ("Get-Item -LiteralPath 'no-such-item-b4'", "notice"),
    ],
    ids=["native-exit-2", "stale-exit-2", "failed-cmdlet"],
)
def test_a_powershell_hook_keeps_exit_2_and_only_exit_2(bridge, tmp_path, command, outcome):
    hook = {"type": "command", "shell": "powershell", "command": command.format(py=sys.executable)}
    settings(tmp_path, [hook])
    if outcome == "block":
        with pytest.raises(bridge.HookBlocked):
            bridge.dispatch(tmp_path, BASH_CALL)
        return
    result = bridge.dispatch(tmp_path, BASH_CALL)
    assert ("exited 1:" in result.get("systemMessage", "")) == (outcome == "notice"), result


def test_project_dir_is_substituted_in_every_form(bridge, tmp_path):
    structured = {"type": "command", "command": "${CLAUDE_PROJECT_DIR}/guard", "args": ["a"]}
    assert bridge.hook_argv(tmp_path, structured) == [f"{tmp_path}/guard", "a"]
    shell = {"type": "command", "shell": "powershell", "command": "'${CLAUDE_PROJECT_DIR}_x'"}
    # Braced, so a following name character cannot join the variable name.
    assert "'${env:CLAUDE_PROJECT_DIR}_x'" in bridge.hook_argv(tmp_path, shell)[-1]


def test_each_event_matches_its_own_discriminator_field(bridge, tmp_path):
    settings(tmp_path, [handler(json.dumps(DENIAL))], event="SubagentStart", matcher="^worker$")
    payload = {"session_id": "x", "hook_event_name": "SubagentStart", "agent_type": "worker"}
    # A null, or another event's field, must not stand in for SubagentStart's agent_type.
    for other in (None, "", "startup"):
        assert bridge.dispatch(tmp_path, {**payload, "source": other}) == DENIAL


def test_a_matcher_on_an_event_without_one_is_ignored(bridge, tmp_path):
    """Claude Code ignores a matcher on UserPromptSubmit, so the bridge must still run the group."""
    settings(tmp_path, [handler("remember the brief")], event="UserPromptSubmit", matcher=".+")
    result = bridge.dispatch(tmp_path, {"session_id": "x", "hook_event_name": "UserPromptSubmit"})
    assert result["hookSpecificOutput"]["additionalContext"] == "remember the brief"


@pytest.mark.parametrize("stdout", ["remember the brief", "3", "true", '["a list"]'])
def test_plain_or_non_object_prompt_hook_output_becomes_context(bridge, tmp_path, stdout):
    settings(tmp_path, [handler(stdout)], event="UserPromptSubmit", matcher="")
    result = bridge.dispatch(tmp_path, {"session_id": "x", "hook_event_name": "UserPromptSubmit"})
    assert result["hookSpecificOutput"]["additionalContext"] == stdout


def test_non_object_json_on_a_tool_event_is_not_a_block(bridge, tmp_path, capsys):
    settings(tmp_path, [handler("3")])
    assert bridge.dispatch(tmp_path, BASH_CALL) == {}
    assert "3" in capsys.readouterr().err


def test_a_command_only_hook_defaults_to_bash_then_powershell(bridge, tmp_path, monkeypatch):
    """Claude Code's default shell is bash, or PowerShell on Windows when Git Bash is missing."""
    hook = {"type": "command", "command": "echo hi"}
    monkeypatch.setattr(bridge, "git_bash", lambda: "git/bin/bash.exe")
    assert Path(bridge.hook_argv(tmp_path, hook)[0]).stem == "bash"
    if os.name == "nt":
        monkeypatch.setattr(bridge, "git_bash", lambda: None)
        assert bridge.hook_argv(tmp_path, hook)[0] == "pwsh"
        with pytest.raises(FileNotFoundError):
            bridge.hook_argv(tmp_path, {**hook, "shell": "bash"})


# Values a tracked matcher is tried against, per event's discriminator. A new matcher that selects
# none of them fails the test below and names itself, rather than going undispatched.
_TOOL_NAMES = ("Bash", "PowerShell", "Agent", "Task", "Workflow", "EnterWorktree", "Edit", "Write")
_FIELD_VALUES = ("startup", "resume", "clear", "compact", "manual", "auto", "logout", "other")


def _tracked_settings():
    return json.loads((ROOT / ".claude/settings.json").read_text(encoding="utf-8-sig"))


def test_every_hook_in_the_tracked_settings_dispatches_to_a_runnable_argv(
    bridge, tmp_path, monkeypatch
):
    """Read the tracked .claude/settings.json, not a synthetic one, and dispatch each group.

    The subprocess is recorded, not run: the tracked hooks write the live seat registry.
    """
    tracked = _tracked_settings()
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude/settings.json").write_text(json.dumps(tracked), encoding="utf-8")
    calls: list[list[str]] = []

    def record(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(bridge.subprocess, "run", record)
    monkeypatch.setattr(bridge, "git_bash", lambda: "git/bin/bash.exe")
    assert tracked["hooks"], "the tracked settings wire no hooks; this test proves nothing"
    for event, groups in tracked["hooks"].items():
        assert event in bridge.EVENTS, f"{event} has no Codex adapter"
        for group in groups:
            payload = {"session_id": "x", "hook_event_name": event}
            matcher = group.get("matcher", "")
            if matcher not in ("", "*"):
                if event in bridge.TOOL_EVENTS:
                    field, values = "tool_name", _TOOL_NAMES
                else:
                    field, values = bridge.MATCHER_FIELDS.get(event, "ignored"), _FIELD_VALUES
                names = [value for value in values if re.search(matcher, value)]
                assert names, f"no value in the test's lists selects {event} matcher {matcher!r}"
                payload[field] = names[0]
            calls.clear()
            bridge.dispatch(tmp_path, payload)
            for hook in group["hooks"]:
                argv = bridge.hook_argv(tmp_path, hook)
                assert argv in calls, (event, hook["command"], calls)
                if "args" in hook:
                    assert argv[0] == hook["command"]
                    assert not any("${CLAUDE_PROJECT_DIR}" in arg for arg in argv), argv
                else:
                    assert hook.get("shell") in (None, "bash", "powershell"), hook
                    if hook.get("shell", "bash") == "bash":
                        assert Path(argv[0]).stem == "bash"
                        assert argv[1:] == ["-c", hook["command"]]


def test_tracked_command_only_hooks_run_cleanly_through_their_shell(bridge, tmp_path, capsys):
    """Run each tracked command-only hook for real. The bridge strips CLAUDE_*, so the cloud-only
    gate exits 0 before its script runs. On Windows the wrong shell, pwsh, cannot parse it and
    exits 1; on POSIX sh would exit 0 too, so the argv test above is the control there."""
    hooks = [
        hook
        for groups in _tracked_settings()["hooks"].values()
        for group in groups
        for hook in group["hooks"]
        if "args" not in hook
    ]
    if not hooks:
        pytest.skip("the tracked settings carry no command-only hook")
    if os.name == "nt" and bridge.git_bash() is None:
        pytest.skip("Git Bash is not installed")
    for hook in hooks:
        settings(tmp_path, [hook], event="SessionStart", matcher="")
        bridge.dispatch(tmp_path, {"session_id": "x", "hook_event_name": "SessionStart"})
        assert "not blocking" not in capsys.readouterr().err, hook["command"]


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
    # Like the real launcher in hook mode, it ends the process with its decision.
    (scripts / "invoke.ps1").write_text(
        "[Console]::Out.Write([Console]::In.ReadToEnd()); [Environment]::Exit(0)\n"
    )
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


# --- Who decides a block: only a hook. A bridge fault or a launcher with no decision never blocks.

UNSUPPORTED = {"type": "prompt", "prompt": "review"}
DENY_GROUP = {"matcher": "^(Bash|PowerShell)$", "hooks": [handler(json.dumps(DENIAL))]}


def write_settings(root, hooks):
    (root / ".claude").mkdir(exist_ok=True)
    (root / ".claude/settings.json").write_text(json.dumps({"hooks": hooks}), encoding="utf-8")


def run(bridge, root, payload, event=""):
    text = payload if isinstance(payload, str) else json.dumps(payload)
    return bridge.run_hook(root, text, event)


def reported(capsys, text="Codex bridge fault"):
    """The fault reached stderr and the systemMessage Codex reads; returns the printed result."""
    captured = capsys.readouterr()
    assert text in captured.err
    result = json.loads(captured.out.splitlines()[-1])
    assert text in result["systemMessage"]
    assert "(not blocking)" in result["systemMessage"]
    return result


@pytest.mark.parametrize("tool", ["Bash", "PowerShell", "Agent", "EnterWorktree", "Read"])
def test_a_fault_under_the_tracked_settings_is_reported_and_never_blocks(
    bridge, tmp_path, capsys, tool
):
    """A missing session id would have blocked the guarded shell call; nothing blocks now."""
    tracked = _tracked_settings()
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude/settings.json").write_text(json.dumps(tracked), encoding="utf-8")
    payload = {"hook_event_name": "PreToolUse", "tool_name": tool}  # no session_id: a fault
    assert run(bridge, tmp_path, payload, "PreToolUse") == 0
    reported(capsys)


@pytest.mark.parametrize(
    "event", ["PreToolUse", "PermissionRequest", "Stop", "SubagentStop", "SessionStart"]
)
def test_a_fault_on_any_event_is_reported_and_never_blocks(bridge, tmp_path, capsys, event):
    write_settings(tmp_path, {event: [DENY_GROUP], "disableAllHooks": True})
    assert run(bridge, tmp_path, {"hook_event_name": event, "tool_name": "Bash"}, event) == 0
    reported(capsys)


@pytest.mark.parametrize("event", ["PreToolUse", "Stop"])
def test_settings_that_cannot_be_parsed_are_reported_and_never_block(
    bridge, tmp_path, capsys, event
):
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude/settings.json").write_text("{ not json", encoding="utf-8")
    payload = {"session_id": "x", "hook_event_name": event, "tool_name": "Bash"}
    assert run(bridge, tmp_path, payload, event) == 0
    reported(capsys)


@pytest.mark.parametrize("text", ["{ not json", '["a list"]', ""])
@pytest.mark.parametrize("event", ["PreToolUse", "Stop", ""])
def test_a_payload_that_cannot_be_parsed_is_reported_and_never_blocks(
    bridge, tmp_path, capsys, event, text
):
    write_settings(tmp_path, {"PreToolUse": [DENY_GROUP]})
    assert run(bridge, tmp_path, text, event) == 0
    reported(capsys)


def test_a_deliberate_block_and_a_clean_run_exit_2_and_0(bridge, tmp_path, capsys):
    settings(tmp_path, [exits(2)])
    assert run(bridge, tmp_path, BASH_CALL) == 2
    settings(tmp_path, [handler(json.dumps(DENIAL))])
    assert run(bridge, tmp_path, BASH_CALL) == 0
    assert json.loads(capsys.readouterr().out.splitlines()[-1]) == DENIAL


@pytest.mark.parametrize(
    ("event", "decision", "kept"),
    [
        ("PreToolUse", DENIAL, ("hookSpecificOutput", DENIAL["hookSpecificOutput"])),
        ("Stop", {"decision": "block", "reason": "not yet"}, ("decision", "block")),
    ],
    ids=["deny", "stop-block"],
)
def test_a_decision_gathered_before_a_fault_still_stands(
    bridge, tmp_path, capsys, monkeypatch, event, decision, kept
):
    first = {"matcher": "", "hooks": [handler(json.dumps(decision))]}
    write_settings(tmp_path, {event: [first, {"matcher": "", "hooks": [handler("{}")]}]})
    real_run_group = bridge.run_group
    calls = []

    def fault_on_second(*args):
        calls.append(args)
        if len(calls) == 2:
            raise RuntimeError("a fault after a decision")
        real_run_group(*args)

    monkeypatch.setattr(bridge, "run_group", fault_on_second)
    payload = {"session_id": "x", "hook_event_name": event, "tool_name": "Bash"}
    assert run(bridge, tmp_path, payload, event) == 0
    result = reported(capsys, "a fault after a decision")
    assert result[kept[0]] == kept[1]


# --- The launcher and the registered commands: no decision is a non-blocking 1 on every event.

_STUB_BRIDGE = "import os, sys\nsys.exit(int(os.environ['STUB_BRIDGE_EXIT']))\n"


def _outer_shells():
    shells = ["pwsh"]
    if os.name == "nt":
        shells.append("cmd")
    if shutil.which("sh"):
        shells.append("sh")
    return shells


def _outer_argv(shell, command):
    # cmd takes the line verbatim, as a string: Python's argv quoting escapes quotes in a way
    # cmd does not read.
    if shell == "cmd":
        return f"cmd /d /c {command}"
    return ["pwsh", "-NoProfile", "-Command", command] if shell == "pwsh" else ["sh", "-c", command]


def _link_python(root):
    """Give the copied invoke.ps1 a .venv that reaches this test's own interpreter."""
    if os.name == "nt":
        if not (Path(sys.prefix) / "Scripts/python.exe").is_file():
            pytest.skip("needs a virtualenv to junction on Windows")
        link = ["cmd", "/c", "mklink", "/J", str(root / ".venv"), sys.prefix]
        subprocess.run(link, check=True, capture_output=True)
    else:
        (root / ".venv/bin").mkdir(parents=True)
        (root / ".venv/bin/python").symlink_to(sys.executable)


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="requires PowerShell")
@pytest.mark.parametrize("shell", _outer_shells())
@pytest.mark.parametrize(
    ("event", "setup", "expected"),
    [
        ("PreToolUse", "0", 0),
        ("PreToolUse", "10", 2),
        # A launcher that cannot run the bridge would lock Codex out of the fix if it blocked.
        ("PreToolUse", "2", 1),
        ("PreToolUse", "1", 1),
        ("PreToolUse", "no-venv", 1),
        ("PreToolUse", "no-repo", 1),
        ("Stop", "0", 0),
        ("Stop", "10", 2),
        # Python's "can't open file", argparse and a crash exit 2: no decision, never a block.
        ("Stop", "2", 1),
        ("Stop", "1", 1),
        ("Stop", "no-venv", 1),
        ("Stop", "no-repo", 1),
    ],
)
def test_a_registered_command_passes_a_decision_and_maps_no_decision(
    tmp_path, shell, event, setup, expected
):
    """No decision (a crash, a missing .venv, no repo) is a non-blocking 1 on every event, never 0
    and never 2. The real invoke.ps1 runs a stub bridge."""
    import tomllib

    assert bridge_block_exit() == 10, "invoke.ps1 hardcodes the bridge's BLOCK_EXIT"

    root = tmp_path / "repo"
    scripts = root / "scripts/codex"
    scripts.mkdir(parents=True)
    shutil.copy2(ROOT / "scripts/codex/invoke.ps1", scripts / "invoke.ps1")
    (scripts / "bridge.py").write_text(_STUB_BRIDGE)
    if setup != "no-venv":
        _link_python(root)
    if setup != "no-repo":
        subprocess.run(["git", "init", "-q", str(root)], check=True, capture_output=True)
    hooks = tomllib.loads((ROOT / ".codex/config.toml").read_text())["hooks"][event][0]["hooks"]
    env = {**os.environ, "STUB_BRIDGE_EXIT": setup if setup.isdigit() else "0"}
    if setup == "no-repo":
        env["GIT_CEILING_DIRECTORIES"] = str(tmp_path)
    completed = subprocess.run(
        _outer_argv(shell, hooks[0]["command"]),
        cwd=scripts,
        env=env,
        input="{}",
        text=True,
        capture_output=True,
        check=False,
        timeout=60,
    )
    assert completed.returncode == expected, (shell, completed.stdout, completed.stderr)
    if expected == 1 and setup != "no-repo":  # invoke.ps1 ran and reported it.
        assert "no decision, not blocking" in json.loads(completed.stdout)["systemMessage"]


def bridge_block_exit():
    spec = importlib.util.spec_from_file_location(
        "codex_bridge_c", ROOT / "scripts/codex/bridge.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.BLOCK_EXIT


def _main(bridge, monkeypatch, root, argv, stdin_bytes=b"", encoding="cp1252"):
    """Run bridge.main() as Codex would, with a text stdin that does not decode as UTF-8."""
    monkeypatch.setattr(bridge, "ROOT", root)
    monkeypatch.setattr(sys, "argv", ["bridge.py", *argv])
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(stdin_bytes), encoding=encoding))
    return bridge.main()


def test_hook_mode_reads_the_payload_as_utf8_bytes(bridge, tmp_path, monkeypatch, capsys):
    echo = "import json, sys; p = json.load(sys.stdin); print(json.dumps({'reason': p['tool_input']['command']}))"
    settings(tmp_path, [python(echo)])
    payload = {**BASH_CALL, "tool_input": {"command": "cat \u2190 \u3053"}}
    code = _main(
        bridge,
        monkeypatch,
        tmp_path,
        ["hook", "--event", "PreToolUse"],
        json.dumps(payload, ensure_ascii=False).encode("utf-8"),
    )
    assert code == 0
    assert json.loads(capsys.readouterr().out)["reason"] == "cat \u2190 \u3053"


def test_hook_mode_exits_the_block_code_only_for_a_decision(bridge, tmp_path, monkeypatch):
    settings(tmp_path, [exits(2)])
    argv = ["hook", "--event", "PreToolUse"]
    assert _main(bridge, monkeypatch, tmp_path, argv, json.dumps(BASH_CALL).encode()) == 10
    settings(tmp_path, [handler("{}")])
    assert _main(bridge, monkeypatch, tmp_path, argv, json.dumps(BASH_CALL).encode()) == 0
    # A usage error exits 2 through argparse, which the launcher reads as no decision.
    with pytest.raises(SystemExit) as stopped:
        _main(bridge, monkeypatch, tmp_path, ["hook", "--evnt", "Stop"], b"{}")
    assert stopped.value.code == 2


def test_run_mode_leaves_a_target_scripts_own_event_flag(bridge, monkeypatch):
    calls: list[list[str]] = []

    def call(argv, **kwargs):
        calls.append(argv)
        return 0

    monkeypatch.setattr(bridge.subprocess, "call", call)
    argv = ["run", "scripts/codex/bridge.py", "--event", "push", "--even", "x", "--limit", "3"]
    assert _main(bridge, monkeypatch, ROOT, [*argv, "--session-id", "s"]) == 0
    assert calls[0][-6:] == ["--event", "push", "--even", "x", "--limit", "3"]


@pytest.mark.parametrize(
    ("registered", "named"),
    [("PreToolUse", "Stop"), ("PreToolUse", None), ("Stop", "PreToolUse"), ("PreToolUze", None)],
    ids=["pre-named-stop", "pre-unnamed", "stop-named-pre", "unknown-registration"],
)
def test_a_payload_naming_another_event_is_a_reported_fault(
    bridge, tmp_path, capsys, registered, named
):
    write_settings(tmp_path, {"PreToolUse": [DENY_GROUP], "Stop": [{"hooks": [exits(2)]}]})
    payload = {"session_id": "x", "tool_name": "Bash"}
    if named:
        payload["hook_event_name"] = named
    if registered == "PreToolUze":
        payload["hook_event_name"] = "PreToolUze"
    assert run(bridge, tmp_path, payload, registered) == 0
    reported(capsys, "registered as")


def test_an_event_name_in_another_case_still_runs_the_hooks(bridge, tmp_path, capsys):
    write_settings(tmp_path, {"PreToolUse": [DENY_GROUP]})
    payload = {**BASH_CALL, "hook_event_name": "pretooluse"}
    assert run(bridge, tmp_path, payload, "PRETOOLUSE") == 0
    assert json.loads(capsys.readouterr().out) == DENIAL


@pytest.mark.parametrize(
    "defect",
    [{"matcher": "^(Task|Agent|Workflow$|spawn_task"}, {"hooks": [UNSUPPORTED]}],
    ids=["bad-matcher", "unsupported-hook"],
)
def test_a_defective_group_is_skipped_and_later_groups_still_run(bridge, tmp_path, capsys, defect):
    defective = {"matcher": ".*", "hooks": [handler("{}")], **defect}
    write_settings(tmp_path, {"PreToolUse": [defective, DENY_GROUP]})
    assert run(bridge, tmp_path, BASH_CALL, "PreToolUse") == 0
    result = reported(capsys, "skipped a hook group with a defect")
    assert result["hookSpecificOutput"] == DENIAL["hookSpecificOutput"]


@pytest.mark.parametrize(
    "defect",
    [{"matcher": "(["}, {"hooks": [{**UNSUPPORTED, "onFailure": "block"}]}],
    ids=["bad-matcher", "unsupported-hook"],
)
def test_a_defective_group_whose_hook_sets_on_failure_block_blocks(bridge, tmp_path, defect):
    group = {"matcher": ".*", "hooks": [{**handler("{}"), "onFailure": "block"}], **defect}
    # PreToolUse, because Stop ignores a matcher and would never read the bad one.
    write_settings(tmp_path, {"PreToolUse": [group]})
    assert run(bridge, tmp_path, BASH_CALL, "PreToolUse") == 2
