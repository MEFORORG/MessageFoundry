# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""scripts/coord/afk-kill.ps1: the AFK-autonomy kill switch reads fail-safe (ADR 0211).

Only a read that returns exactly ``off`` is OFF. The tests drive the real script against a fake gh
(tests/_fake_gh.py); the real repository variable is never read or set here.
"""

from __future__ import annotations

import json
import shutil
import time
from pathlib import Path

import pytest

from tests._fake_gh import COORD, ROOT, Sandbox, make_sandbox

KILL = COORD / "afk-kill.ps1"

pytestmark = pytest.mark.skipif(shutil.which("pwsh") is None, reason="pwsh not on PATH")


@pytest.fixture
def sb(tmp_path: Path) -> Sandbox:
    return make_sandbox(tmp_path)


def _status(sb: Sandbox, *args: str) -> tuple[str, str]:
    proc = sb.run(KILL, "-Status", *args)
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    return proc.stdout.strip(), proc.stderr


@pytest.mark.parametrize("value", ["off", "OFF", " off "])
def test_off_reads_off(sb: Sandbox, value: str) -> None:
    sb.set_state(variables={"MEFOR_AFK_KILL": value})
    assert _status(sb)[0] == "OFF"
    call = sb.calls[0]
    assert call[:2] == ["api", "repos/MEFORORG/MessageFoundry/actions/variables/MEFOR_AFK_KILL"]


@pytest.mark.parametrize("value", ["on", "ON", "", "of", "false", "0"])
def test_any_value_but_off_reads_on(sb: Sandbox, value: str) -> None:
    sb.set_state(variables={"MEFOR_AFK_KILL": value})
    assert _status(sb)[0] == "ON"


def test_a_missing_variable_reads_on(sb: Sandbox) -> None:
    out, err = _status(sb)
    assert out == "ON"
    assert "unreadable" in err and "404" in err


def test_a_failed_read_reads_on(sb: Sandbox) -> None:
    sb.set_state(fail=True, variables={"MEFOR_AFK_KILL": "off"})
    assert _status(sb)[0] == "ON"


def test_no_gh_on_path_reads_on(sb: Sandbox, tmp_path: Path) -> None:
    sb.set_state(variables={"MEFOR_AFK_KILL": "off"})
    pwsh = shutil.which("pwsh")
    assert pwsh
    beside = Path(pwsh).parent
    if any((beside / name).exists() for name in ("gh", "gh.exe")):
        pytest.skip("a real gh sits beside pwsh, so no PATH holding pwsh can lack gh")
    proc = sb.run(KILL, "-Status", PATH=str(beside))
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "ON"


def test_a_hung_read_reads_on_inside_its_timeout(sb: Sandbox) -> None:
    sb.set_state(hang=6, variables={"MEFOR_AFK_KILL": "off"})
    start = time.monotonic()
    out, err = _status(sb, "-TimeoutSeconds", "1")
    assert out == "ON"
    assert "did not finish" in err
    assert time.monotonic() - start < 6


def test_the_banner_is_loud_when_on_and_silent_when_off(sb: Sandbox) -> None:
    sb.set_state(variables={"MEFOR_AFK_KILL": "on"})
    on = sb.run(KILL, "-Banner")
    assert on.returncode == 0, on.stderr
    hook = json.loads(on.stdout)
    assert "AFK KILL SWITCH IS ON" in hook["systemMessage"]
    assert hook["hookSpecificOutput"]["hookEventName"] == "SessionStart"
    assert "ask-mode" in hook["hookSpecificOutput"]["additionalContext"]
    sb.set_state(variables={"MEFOR_AFK_KILL": "off"})
    off = sb.run(KILL, "-Banner")
    assert off.returncode == 0 and off.stdout == "", (off.stdout, off.stderr)


def test_the_banner_runs_at_every_session_start() -> None:
    settings = json.loads((ROOT / ".claude" / "settings.json").read_text(encoding="utf-8"))
    handlers = [
        h
        for group in settings["hooks"]["SessionStart"]
        for h in group["hooks"]
        if any(str(a).endswith("scripts/coord/afk-kill.ps1") for a in h.get("args", []))
    ]
    assert len(handlers) == 1, handlers
    assert handlers[0]["args"][-1] == "-Banner"
    assert "matcher" not in settings["hooks"]["SessionStart"][0], "every source, not only startup"
