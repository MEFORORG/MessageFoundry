# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Pin two fault-order shapes to a failing exit through the registered Codex hook line.

A hook that exits 1 between a deny and a later allow must fail the event, not let the allow out.
On origin/main the bridge stops at the failed hook and the registered line exits 1. A withdrawn
bridge change ran the later hooks and exited 0 with the allow; these tests stop a future change
reopening either shape silently.
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

import pytest

ROOT = Path(__file__).resolve().parents[1]

pytestmark = pytest.mark.skipif(shutil.which("pwsh") is None, reason="requires PowerShell")


def _py(source: str) -> dict[str, object]:
    return {"type": "command", "command": sys.executable, "args": ["-c", source]}


def _prints(obj: dict[str, object]) -> dict[str, object]:
    return _py(f"print({json.dumps(obj)!r})")


def _link_python(root: Path) -> None:
    if os.name == "nt":
        if not (Path(sys.prefix) / "Scripts/python.exe").is_file():
            pytest.skip("needs a virtualenv to junction on Windows")
        link = ["cmd", "/c", "mklink", "/J", str(root / ".venv"), sys.prefix]
        subprocess.run(link, check=True, capture_output=True)
    else:
        (root / ".venv/bin").mkdir(parents=True)
        (root / ".venv/bin/python").symlink_to(sys.executable)


def _run_registered(tmp_path: Path, event: str, handlers: list[dict[str, object]]):
    root = tmp_path / "repo"
    scripts = root / "scripts/codex"
    scripts.mkdir(parents=True)
    for name in ("invoke.ps1", "bridge.py"):
        shutil.copy2(ROOT / "scripts/codex" / name, scripts / name)
    (root / ".claude").mkdir()
    settings = {"hooks": {event: [{"matcher": "Bash", "hooks": handlers}]}}
    (root / ".claude/settings.json").write_text(json.dumps(settings), encoding="utf-8")
    _link_python(root)
    subprocess.run(["git", "init", "-q", str(root)], check=True, capture_output=True)
    config = tomllib.loads((ROOT / ".codex/config.toml").read_text())
    command = config["hooks"][event][0]["hooks"][0]["command"]
    payload = {"session_id": "x", "hook_event_name": event, "tool_name": "Bash"}
    return subprocess.run(
        shlex.split(command),
        cwd=scripts,
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=False,
        timeout=60,
    )


_EXIT_1 = _py("import sys; sys.exit(1)")

_CASES = {
    # A permissionDecision deny, a hook that exits 1, then a decision allow.
    "permission-request": (
        "PermissionRequest",
        [
            _prints(
                {
                    "hookSpecificOutput": {
                        "hookEventName": "PermissionRequest",
                        "permissionDecision": "deny",
                    }
                }
            ),
            _EXIT_1,
            _prints(
                {
                    "hookSpecificOutput": {
                        "hookEventName": "PermissionRequest",
                        "decision": {"behavior": "allow"},
                    }
                }
            ),
        ],
    ),
    # A decision.behavior deny (a field PreToolUse ignores), a hook that exits 1, then a
    # permissionDecision allow.
    "pre-tool-use": (
        "PreToolUse",
        [
            _prints(
                {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "decision": {"behavior": "deny"},
                    }
                }
            ),
            _EXIT_1,
            _prints(
                {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "allow",
                    }
                }
            ),
        ],
    ),
}


@pytest.mark.parametrize("case", list(_CASES))
def test_a_failed_hook_between_a_deny_and_an_allow_exits_1(tmp_path, case):
    event, handlers = _CASES[case]
    completed = _run_registered(tmp_path, event, handlers)
    assert completed.returncode == 1, (completed.stdout, completed.stderr)
    assert "allow" not in completed.stdout, completed.stdout
