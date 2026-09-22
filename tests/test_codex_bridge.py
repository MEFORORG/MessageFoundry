# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Exercise the bridge with disposable sources, never the live fleet registry."""

from __future__ import annotations

import importlib.util
import json
import os
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
    payload = {
        "session_id": "x",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "gh run watch 123"},
    }
    result = bridge.dispatch(tmp_path, payload)
    assert result["hookSpecificOutput"]["permissionDecision"] == "deny"
    payload["tool_input"]["command"] = "gh run view 123"
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
