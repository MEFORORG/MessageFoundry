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


# While the switch reads OFF, -Banner tells every session but a Special seat to load the driver
# and empower skills (owner approval 2026-10-22). The seat comes from the worktree the hook input's
# cwd names, so each run below hands the script a SessionStart payload.
CLOUD_NAMES = ("anthropic-skills:driver", "anthropic-skills:empower")


def _seat_banner(sb: Sandbox, switch: str, seat: str | None, cwd: Path | None = None) -> str:
    """-Banner's stdout with the switch at ``switch``, in a worktree whose marker holds ``seat``."""
    sb.set_state(variables={"MEFOR_AFK_KILL": switch})
    roles = sb.repo / "docs" / "roles"
    roles.mkdir(parents=True, exist_ok=True)
    shutil.copy(ROOT / "docs" / "roles" / "seats.json", roles / "seats.json")
    if seat is not None:
        marker = sb.repo / ".claude" / "seat.local.txt"
        marker.parent.mkdir(exist_ok=True)
        marker.write_text(seat, encoding="utf-8")
    payload = json.dumps({"hook_event_name": "SessionStart", "cwd": str(cwd or sb.repo)})
    proc = sb.run(KILL, "-Banner", stdin=payload, KORUS_SEAT="", KORUS_AGENT="")
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


def _instruction(stdout: str) -> str:
    """The skill instruction -Banner printed, or '' when it printed none."""
    if not stdout.strip():
        return ""
    context: str = json.loads(stdout)["hookSpecificOutput"]["additionalContext"]
    return context if "`driver`" in context else ""


def test_a_switch_that_reads_on_gives_the_banner_and_no_skill_instruction(sb: Sandbox) -> None:
    hook = json.loads(_seat_banner(sb, "on", "builder"))
    assert hook["hookSpecificOutput"]["additionalContext"].startswith("AFK KILL SWITCH IS ON")
    assert "driver" not in json.dumps(hook) and "empower" not in json.dumps(hook)


@pytest.mark.parametrize("seat", ["special", " Special\n", "special1", "adhoc"])
def test_a_special_seat_gets_no_skill_instruction(sb: Sandbox, seat: str) -> None:
    assert _seat_banner(sb, "off", seat) == ""


@pytest.mark.parametrize("seat", ["builder", "manager", "builder-2", "", None])
def test_every_other_seat_gets_the_skill_instruction(sb: Sandbox, seat: str | None) -> None:
    out = _seat_banner(sb, "off", seat)
    hook = json.loads(out)
    assert "systemMessage" not in hook
    assert hook["hookSpecificOutput"]["hookEventName"] == "SessionStart"
    text = _instruction(out)
    assert text.index("`driver`") < text.index("`empower`")
    assert "Skill tool" in text


def test_the_instruction_names_the_cloud_skill_names(sb: Sandbox) -> None:
    text = _instruction(_seat_banner(sb, "off", "builder"))
    assert "CLAUDE_CODE_REMOTE=true" in text
    assert all(name in text for name in CLOUD_NAMES), text


def test_korus_seat_names_the_seat_when_the_marker_does_not(sb: Sandbox) -> None:
    sb.set_state(variables={"MEFOR_AFK_KILL": "off"})
    payload = json.dumps({"cwd": str(sb.repo)})
    proc = sb.run(KILL, "-Banner", stdin=payload, KORUS_SEAT="special", KORUS_AGENT="")
    assert proc.returncode == 0 and proc.stdout == "", (proc.stdout, proc.stderr)


def test_the_seat_comes_from_the_payload_cwd_not_the_process_cwd(sb: Sandbox) -> None:
    # Under the desktop app the hook runs in the primary checkout; the payload names the worktree.
    worktree = sb.repo / "wt"
    (worktree / ".claude").mkdir(parents=True)
    (worktree / ".git").write_text("gitdir: elsewhere\n", encoding="utf-8")
    (worktree / ".claude" / "seat.local.txt").write_text("special", encoding="utf-8")
    (worktree / "src").mkdir()
    assert _seat_banner(sb, "off", "builder", cwd=worktree / "src") == ""


@pytest.mark.parametrize("stdin", ["", "not json", "{}", "MISSING"])
def test_an_unusable_payload_gives_no_skill_instruction(sb: Sandbox, stdin: str) -> None:
    sb.set_state(variables={"MEFOR_AFK_KILL": "off"})
    if stdin == "MISSING":
        stdin = json.dumps({"cwd": str(sb.repo / "no-such-dir")})
    proc = sb.run(KILL, "-Banner", stdin=stdin, KORUS_SEAT="", KORUS_AGENT="")
    assert proc.returncode == 0 and proc.stdout == "", (proc.stdout, proc.stderr)


def test_a_seat_file_read_fault_gives_no_instruction_and_keeps_the_banner(sb: Sandbox) -> None:
    on_before = _seat_banner(sb, "on", None)
    # A directory where the marker belongs: it exists, and reading it as a file throws.
    (sb.repo / ".claude" / "seat.local.txt").mkdir(parents=True)
    assert _seat_banner(sb, "off", None) == ""
    assert _seat_banner(sb, "on", None) == on_before
