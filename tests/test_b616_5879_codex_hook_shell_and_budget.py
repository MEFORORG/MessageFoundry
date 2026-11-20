# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The Codex bridge honours a hook's `shell`, fits every hook into Codex's outer timeout, and keeps
earlier SessionStart context when one SessionStart hook fails. Disposable sources only."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_SESSION_START = {"session_id": "x", "hook_event_name": "SessionStart", "source": "startup"}
_PRE_TOOL = {"session_id": "x", "hook_event_name": "PreToolUse", "tool_name": "Bash"}


@pytest.fixture
def bridge():
    spec = importlib.util.spec_from_file_location("codex_bridge", ROOT / "scripts/codex/bridge.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _settings(root: Path, event: str, handlers: list[dict]) -> None:
    (root / ".claude").mkdir(exist_ok=True)
    (root / ".claude/settings.json").write_text(
        json.dumps({"hooks": {event: [{"hooks": handlers}]}}), encoding="utf-8"
    )


def _py(source: str, **extra: object) -> dict:
    return {"type": "command", "command": sys.executable, "args": ["-c", source], **extra}


def _context(text: str) -> dict:
    out = {"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": text}}
    return _py(f"print({json.dumps(out)!r})")


def _has_bash(bridge) -> bool:
    try:
        bridge.find_bash()
    except FileNotFoundError:
        return False
    return True


def test_a_bash_shell_hook_runs_under_bash(bridge, tmp_path):
    if not _has_bash(bridge):
        pytest.skip("requires bash")
    out = json.dumps({"hookSpecificOutput": {"additionalContext": "from bash"}})
    # [[ ]] is bash-only: neither pwsh -Command nor POSIX sh parses it.
    hook = {
        "type": "command",
        "shell": "bash",
        "command": f"[[ -n \"${{CLAUDE_PROJECT_DIR:-}}\" ]] && echo '{out}'",
    }
    _settings(tmp_path, "SessionStart", [hook])
    result = bridge.dispatch(tmp_path, _SESSION_START)
    assert "from bash" in result["hookSpecificOutput"]["additionalContext"]
    assert "systemMessage" not in result


def test_an_unknown_shell_is_refused(bridge, tmp_path):
    _settings(tmp_path, "PreToolUse", [{"type": "command", "shell": "fish", "command": "true"}])
    with pytest.raises(ValueError, match="shell"):
        bridge.dispatch(tmp_path, _PRE_TOOL)


@pytest.mark.parametrize(
    "failing",
    [_py("import sys; sys.exit(1)"), _py("import time; time.sleep(5)", timeout=0.5)],
    ids=["exit-1", "timeout"],
)
def test_a_failing_session_start_hook_keeps_earlier_context(bridge, tmp_path, failing):
    _settings(tmp_path, "SessionStart", [_context("earlier"), failing, _context("later")])
    result = bridge.dispatch(tmp_path, _SESSION_START)
    context = result["hookSpecificOutput"]["additionalContext"]
    assert "Read CLAUDE.md now" in context
    assert "earlier" in context
    assert "later" in context
    assert "SessionStart hook" in result["systemMessage"]


def test_a_missing_bash_does_not_drop_session_start_context(bridge, tmp_path, monkeypatch):
    def no_bash() -> str:
        raise FileNotFoundError("bash not found for a shell: bash hook")

    monkeypatch.setattr(bridge, "find_bash", no_bash)
    hook = {"type": "command", "shell": "bash", "command": "exit 0"}
    _settings(tmp_path, "SessionStart", [_context("earlier"), hook])
    result = bridge.dispatch(tmp_path, _SESSION_START)
    assert "earlier" in result["hookSpecificOutput"]["additionalContext"]
    assert "bash not found" in result["systemMessage"]


def test_other_events_still_raise(bridge, tmp_path):
    """The failure propagates; docs/CODEX.md states what the registered line returns.

    How Codex handles that exit is assumed there, not measured.
    """
    _settings(tmp_path, "PreToolUse", [_py("import sys; sys.exit(1)")])
    with pytest.raises(subprocess.CalledProcessError):
        bridge.dispatch(tmp_path, _PRE_TOOL)


def _cap(root: Path, event: str, seconds: int) -> None:
    (root / ".codex").mkdir(exist_ok=True)
    (root / ".codex/config.toml").write_text(
        f'[[hooks.{event}]]\n[[hooks.{event}.hooks]]\ntype = "command"\n'
        f'command = "pwsh scripts/codex/invoke.ps1 hook"\ntimeout = {seconds}\n'
        # Another hook's shorter timeout is not the bridge's budget.
        f'[[hooks.{event}]]\n[[hooks.{event}.hooks]]\ntype = "command"\n'
        'command = "lint"\ntimeout = 1\n',
        encoding="utf-8",
    )


def test_a_hook_timeout_above_the_outer_cap_is_clamped(bridge, tmp_path):
    # A cap of margin + 1 leaves at most half of it, far below the hook's own 300.
    _cap(tmp_path, "PreToolUse", int(bridge.OUTER_TIMEOUT_MARGIN) + 1)
    _settings(tmp_path, "PreToolUse", [_py("import time; time.sleep(40)", timeout=300)])
    started = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        bridge.dispatch(tmp_path, _PRE_TOOL)
    assert time.monotonic() - started < 20


def test_hooks_share_one_budget(bridge, tmp_path):
    _cap(tmp_path, "SessionStart", int(bridge.OUTER_TIMEOUT_MARGIN) + 6)
    slow = _py("import time; time.sleep(30)", timeout=300)
    _settings(tmp_path, "SessionStart", [_context("first"), slow, slow])
    started = time.monotonic()
    result = bridge.dispatch(tmp_path, _SESSION_START)
    assert time.monotonic() - started < 20
    assert "first" in result["hookSpecificOutput"]["additionalContext"]
    assert result["systemMessage"].count("SessionStart hook") == 2


def test_a_timeout_kills_a_grandchild_holding_the_pipes(bridge, tmp_path):
    # The hook starts a child that inherits its stdout and outlives it; subprocess.run alone would
    # wait for that child after killing the hook, on Windows; elsewhere the drain is bounded.
    spawn = (
        "import subprocess, sys, time; "
        "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(40)']); time.sleep(40)"
    )
    _settings(tmp_path, "PreToolUse", [_py(spawn, timeout=2)])
    started = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        bridge.dispatch(tmp_path, _PRE_TOOL)
    assert time.monotonic() - started < 25


def test_session_start_exit_2_and_a_bad_shell_do_not_drop_context(bridge, tmp_path):
    blocked = _py("import sys; sys.exit(2)")
    bad_shell = {"type": "command", "shell": "fish", "command": "true"}
    _settings(tmp_path, "SessionStart", [_context("earlier"), blocked, bad_shell])
    result = bridge.dispatch(tmp_path, _SESSION_START)
    assert "earlier" in result["hookSpecificOutput"]["additionalContext"]
    assert result["systemMessage"].count("SessionStart hook") == 2


def test_session_start_non_object_json_does_not_drop_context(bridge, tmp_path):
    _settings(tmp_path, "SessionStart", [_context("earlier"), _py("print('[1]')")])
    result = bridge.dispatch(tmp_path, _SESSION_START)
    assert "earlier" in result["hookSpecificOutput"]["additionalContext"]
    assert "not an object" in result["systemMessage"]


def test_a_wrongly_shaped_codex_config_falls_back_to_the_default(bridge, tmp_path):
    (tmp_path / ".codex").mkdir()
    (tmp_path / ".codex/config.toml").write_text("hooks = []\n", encoding="utf-8")
    assert bridge.outer_timeout(tmp_path, "PreToolUse") == bridge.DEFAULT_OUTER_TIMEOUT


def test_a_null_timeout_runs_within_the_budget(bridge, tmp_path):
    _settings(tmp_path, "SessionStart", [{**_context("ran"), "timeout": None}])
    result = bridge.dispatch(tmp_path, _SESSION_START)
    assert "ran" in result["hookSpecificOutput"]["additionalContext"]


def test_an_unparseable_codex_config_falls_back_to_the_default(bridge, tmp_path):
    (tmp_path / ".codex").mkdir()
    (tmp_path / ".codex/config.toml").write_text("[not toml", encoding="utf-8")
    assert bridge.outer_timeout(tmp_path, "PreToolUse") == bridge.DEFAULT_OUTER_TIMEOUT


def test_a_cap_at_or_below_the_margin_still_runs_hooks(bridge, tmp_path):
    _cap(tmp_path, "SessionStart", int(bridge.OUTER_TIMEOUT_MARGIN))
    _settings(tmp_path, "SessionStart", [_context("ran")])
    result = bridge.dispatch(tmp_path, _SESSION_START)
    assert "ran" in result["hookSpecificOutput"]["additionalContext"]
    assert "systemMessage" not in result


def test_the_live_sources_fit_the_bridge(bridge):
    assert bridge.outer_timeout(ROOT, "SessionStart") == 90
    config = json.loads((ROOT / ".claude/settings.json").read_text(encoding="utf-8-sig"))
    shells = {
        hook.get("shell")
        for groups in config["hooks"].values()
        for group in groups
        for hook in group["hooks"]
        if "args" not in hook
    }
    assert shells <= {None, "bash", "powershell"}


@pytest.mark.skipif(os.name != "nt", reason="WSL's launcher exists only on Windows")
def test_the_wsl_launcher_is_never_taken_for_git_bash(bridge, monkeypatch):
    monkeypatch.delenv("CLAUDE_CODE_GIT_BASH_PATH", raising=False)
    wsl = r"C:\Windows\System32\bash.exe"
    monkeypatch.setattr(bridge.shutil, "which", lambda name: wsl if name == "bash" else None)
    with pytest.raises(FileNotFoundError):
        bridge.find_bash()
