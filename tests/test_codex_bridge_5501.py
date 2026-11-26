# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Codex bridge tests that pass against origin/main's bridge, kept apart from test_codex_bridge.py.

BACKLOG #5501: the tracked-settings tests dispatch over the repository's own .claude/settings.json
rather than a synthetic one, with the hook process stubbed. For each tracked group, probed with a
Claude Code tool name or event the test picks, they check that the bridge runs the hooks of the
groups the test's own matcher reading selects, each with the argv the test expects, a command-only
hook with no args included. On PreToolUse a stubbed exit 1 raises CalledProcessError and a stubbed
exit 2 raises HookBlocked, so the two stay distinct as exceptions. This file does not show they
stay distinct at the process exit code, and does not cover SessionStart, which handles both apart.

The exit-2 test uses synthetic settings and real hook processes: on PreToolUse an exit 2 ends the
event before a later hook runs. It came from the withdrawn BACKLOG #5496 section of this branch.
"""

from __future__ import annotations

import importlib.util
import json
import re
import shutil
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
_PAYLOAD = {"session_id": "x", "hook_event_name": "PreToolUse", "tool_name": "Bash"}


@pytest.fixture
def bridge() -> ModuleType:
    spec = importlib.util.spec_from_file_location("codex_bridge", ROOT / "scripts/codex/bridge.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _py(source: str) -> dict[str, object]:
    return {"type": "command", "command": sys.executable, "args": ["-c", source]}


def _marker(path: Path) -> dict[str, object]:
    return _py(f"open({str(path)!r}, 'w').close()")


def _settings(root: Path, handlers: list[dict[str, object]]) -> None:
    (root / ".claude").mkdir(exist_ok=True)
    (root / ".claude/settings.json").write_text(
        json.dumps({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": handlers}]}}),
        encoding="utf-8",
    )


def test_a_hooks_exit_2_still_ends_the_event_at_once(bridge: ModuleType, tmp_path: Path) -> None:
    """As on main: an exit 2 raises HookBlocked before the event's later hooks run."""
    ran = tmp_path / "later-hook-ran"
    _settings(tmp_path, [_py("import sys; sys.exit(2)"), _marker(ran)])
    with pytest.raises(bridge.HookBlocked):
        bridge.dispatch(tmp_path, dict(_PAYLOAD))
    assert not ran.exists()


def test_the_marker_hook_is_live_after_a_clean_hook(bridge: ModuleType, tmp_path: Path) -> None:
    """Positive control for the test above: the same marker runs when the first hook exits 0."""
    ran = tmp_path / "later-hook-ran"
    _settings(tmp_path, [_py("import sys; sys.exit(0)"), _marker(ran)])
    bridge.dispatch(tmp_path, dict(_PAYLOAD))
    assert ran.exists()


_TRACKED: dict[str, Any] = json.loads(
    (ROOT / ".claude/settings.json").read_text(encoding="utf-8-sig")
)
_PROBE_TOOLS = ("Bash", "PowerShell", "Agent", "Task", "Workflow", "EnterWorktree", "Edit", "Write")
_BASH = "stub-git-bash"


def _tracked_repo(tmp_path: Path) -> Path:
    (tmp_path / ".claude").mkdir()
    shutil.copy2(ROOT / ".claude/settings.json", tmp_path / ".claude/settings.json")
    return tmp_path


def _expected_argv(root: Path, hook: dict[str, Any]) -> list[str]:
    """What Claude Code runs for a hook, written from its hook schema rather than from hook_argv."""
    if "args" in hook:
        return [
            hook["command"],
            *(a.replace("${CLAUDE_PROJECT_DIR}", str(root)) for a in hook["args"]),
        ]
    assert hook.get("shell") == "bash", f"add the expected argv for shell {hook.get('shell')!r}"
    return [_BASH, "-c", hook["command"]]


_TOOL_EVENTS = ("PreToolUse", "PostToolUse", "PermissionRequest")


def _accepts(matcher: str, tool: str) -> bool:
    return matcher in ("", "*") or re.search(matcher, tool) is not None


def _tracked_payloads() -> Iterator[tuple[str, dict[str, Any], dict[str, str]]]:
    """One payload per tracked group, with a tool name its matcher accepts."""
    for event, groups in _TRACKED["hooks"].items():
        for group in groups:
            payload = {"session_id": "x", "hook_event_name": event}
            matcher = group.get("matcher", "")
            if event in _TOOL_EVENTS:
                tools = [t for t in _PROBE_TOOLS if _accepts(matcher, t)]
                assert tools, f"no probe tool name matches {event} matcher {matcher!r}"
                payload["tool_name"] = tools[0]
            else:
                assert matcher in ("", "*"), (
                    f"give the {event} probe a field matcher {matcher!r} reads"
                )
            yield event, group, payload


def _matched_argvs(root: Path, event: str, payload: dict[str, str]) -> list[list[str]]:
    """The argv of every hook in every group of the event that the probe's tool name matches."""
    return [
        _expected_argv(root, hook)
        for group in _TRACKED["hooks"][event]
        if event not in _TOOL_EVENTS or _accepts(group.get("matcher", ""), payload["tool_name"])
        for hook in group["hooks"]
    ]


def _stub_hooks(
    bridge: ModuleType, monkeypatch: pytest.MonkeyPatch, returncode: int = 0
) -> list[list[str]]:
    calls: list[list[str]] = []

    def run_hook(
        argv: list[str], payload: object, root: object, env: object, timeout: object
    ) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        return subprocess.CompletedProcess(argv, returncode, "", "")

    monkeypatch.setattr(bridge, "run_hook", run_hook)
    monkeypatch.setattr(bridge, "find_bash", lambda: _BASH)
    return calls


def test_the_tracked_settings_has_a_command_only_hook_with_no_args() -> None:
    """The case the synthetic settings in test_codex_bridge.py never write; it stays covered."""
    hooks = [h for groups in _TRACKED["hooks"].values() for g in groups for h in g["hooks"]]
    assert any("args" not in hook for hook in hooks)


def test_every_tracked_hook_is_dispatched_with_its_claude_argv(
    bridge: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _tracked_repo(tmp_path)
    calls = _stub_hooks(bridge, monkeypatch)
    for event, group, payload in _tracked_payloads():
        calls.clear()
        bridge.dispatch(root, payload)
        for hook in group["hooks"]:
            assert _expected_argv(root, hook) in calls, (payload, hook)
        # Exactly the selected groups' hooks, once each: a bridge that runs a group the test's
        # matcher reading does not select fails here.
        assert sorted(calls) == sorted(_matched_argvs(root, event, payload)), payload


@pytest.mark.parametrize(
    ("returncode", "expected"), [(1, subprocess.CalledProcessError), (2, None)], ids=["1", "2"]
)
def test_a_tracked_guards_exit_1_is_not_its_exit_2(
    bridge: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    returncode: int,
    expected: type[BaseException] | None,
) -> None:
    root = _tracked_repo(tmp_path)
    _stub_hooks(bridge, monkeypatch, returncode)
    with pytest.raises(expected or bridge.HookBlocked) as caught:
        bridge.dispatch(root, dict(_PAYLOAD))
    assert isinstance(caught.value, bridge.HookBlocked) == (returncode == 2)
