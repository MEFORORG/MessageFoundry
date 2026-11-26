# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Pin fault-order shapes to a failing exit through the registered Codex hook line.

Each case runs, for one event, a hook that prints a decision, a hook that exits 1, and in some cases
a hook that prints an allow. On the bridge these tests were written against, the hook that exits 1
stops the event: the bridge emits nothing, the registered line exits 1, and the earlier decision is
dropped too (docs/CODEX.md states that gap). These tests pin only that the event fails and that no
allow reaches stdout. They do not show that a deny survives a fault; it does not.

A withdrawn change for BACKLOG #5496 (engine commit 6a8c02a9b2a, never merged) ran the later hooks
and exited 0 on each case here, the first two emitting the allow. To re-run the negative control,
put that commit's scripts/codex/bridge.py in place: every case below fails with 0 == 1.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
# The bridge strips these for its own git calls; an inherited one would point git at another repo.
_GIT_VARIABLES = ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE")

pytestmark = pytest.mark.skipif(shutil.which("pwsh") is None, reason="requires PowerShell")


def _env() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if k not in _GIT_VARIABLES}


def _py(source: str) -> dict[str, object]:
    return {"type": "command", "command": sys.executable, "args": ["-c", source]}


def _prints(event: str, **fields: object) -> dict[str, object]:
    return _py(f"print({json.dumps({'hookSpecificOutput': {'hookEventName': event, **fields}})!r})")


def _link_python(root: Path) -> None:
    if os.name == "nt":
        if not (Path(sys.prefix) / "Scripts/python.exe").is_file():
            pytest.skip("needs a virtualenv to junction on Windows")
        link = ["cmd", "/c", "mklink", "/J", str(root / ".venv"), sys.prefix]
        subprocess.run(link, check=True, capture_output=True)
    else:
        (root / ".venv/bin").mkdir(parents=True)
        (root / ".venv/bin/python").symlink_to(sys.executable)


def _registered_command(event: str) -> str:
    text = (ROOT / ".codex/config.toml").read_text(encoding="utf-8-sig")
    groups = tomllib.loads(text)["hooks"][event]
    commands = [
        h["command"]
        for g in groups
        for h in g["hooks"]
        if "scripts/codex/invoke.ps1" in h["command"]
    ]
    assert len(commands) == 1, commands
    return commands[0]


def _run_registered(tmp_path: Path, event: str, handlers: list[dict[str, object]]):
    root = tmp_path / "repo"
    scripts = root / "scripts/codex"
    scripts.mkdir(parents=True)
    for name in ("invoke.ps1", "bridge.py"):
        shutil.copy2(ROOT / "scripts/codex" / name, scripts / name)
    (root / ".codex").mkdir()
    shutil.copy2(ROOT / ".codex/config.toml", root / ".codex/config.toml")
    (root / ".claude").mkdir()
    settings = {"hooks": {event: [{"matcher": "Bash", "hooks": handlers}]}}
    (root / ".claude/settings.json").write_text(json.dumps(settings), encoding="utf-8")
    _link_python(root)
    subprocess.run(["git", "init", "-q", str(root)], check=True, capture_output=True, env=_env())
    payload = {"session_id": "x", "hook_event_name": event, "tool_name": "Bash"}
    return subprocess.run(
        shlex.split(_registered_command(event)),
        cwd=scripts,
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=False,
        timeout=60,
        env=_env(),
    )


def _allowed(stdout: str) -> bool:
    if not stdout.strip():
        return False
    specific: dict[str, Any] = json.loads(stdout).get("hookSpecificOutput", {})
    decision = specific.get("decision")
    behavior = decision.get("behavior") if isinstance(decision, dict) else None
    return "allow" in (specific.get("permissionDecision"), behavior)


_EXIT_1 = _py("import sys; sys.exit(1)")
_PR, _PRE, _POST = "PermissionRequest", "PreToolUse", "PostToolUse"

# (event, handlers before the fault, handlers after it). The deny in each sits in a field the
# event does not read, except where noted, so it is not a protection the fault removes.
_CASES = {
    # A permissionDecision deny, then after the fault a decision allow.
    "permission-request": (
        _PR,
        [_prints(_PR, permissionDecision="deny")],
        [_prints(_PR, decision={"behavior": "allow"})],
    ),
    # A decision.behavior deny, then after the fault a permissionDecision allow.
    "pre-tool-use": (
        _PRE,
        [_prints(_PRE, decision={"behavior": "deny"})],
        [_prints(_PRE, permissionDecision="allow")],
    ),
    # The same masking with no allow at all: a field the event ignores hid the fault.
    "post-tool-use": (_POST, [_prints(_POST, permissionDecision="deny")], []),
    # An ask (a field PreToolUse does read) followed by a fault.
    "pre-tool-use-ask": (_PRE, [_prints(_PRE, permissionDecision="ask")], []),
}


@pytest.mark.parametrize("case", list(_CASES))
def test_a_failed_hook_fails_the_event_and_lets_no_allow_out(tmp_path, case):
    event, before, after = _CASES[case]
    completed = _run_registered(tmp_path, event, [*before, _EXIT_1, *after])
    assert completed.returncode == 1, (completed.stdout, completed.stderr)
    # The bridge's own fault line: proves the exit-1 hook ended the run, not a launcher failure.
    assert "returned non-zero exit status 1" in completed.stderr, completed.stderr
    assert not _allowed(completed.stdout), completed.stdout


def test_the_fixture_is_live_without_the_fault(tmp_path):
    """Positive control: the same handlers minus the exit-1 hook run clean and emit the allow."""
    event, before, after = _CASES["pre-tool-use"]
    completed = _run_registered(tmp_path, event, [*before, *after])
    assert completed.returncode == 0, completed.stderr
    assert _allowed(completed.stdout), completed.stdout
