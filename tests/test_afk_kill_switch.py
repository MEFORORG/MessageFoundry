# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""scripts/coord/afk-kill.ps1: the AFK-autonomy kill switch reads fail-safe (ADR 0211).

Only a read that returns exactly ``off`` is OFF. The tests drive the real script against a fake gh
(tests/_fake_gh.py); the real repository variable is never read or set here.
"""

from __future__ import annotations

import json
import shutil
import subprocess
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


def test_the_banner_is_loud_when_on_and_silent_when_off_with_no_hook_input(sb: Sandbox) -> None:
    # With no hook input there is no worktree to name a seat, so OFF prints nothing. With one, OFF
    # prints the skill instruction; the tests below cover that.
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


# While the switch reads OFF, -Banner may print the skill instruction ADR 0211 describes. The seat
# comes from the worktree the hook input names, so each run below hands the script a payload.
CLOUD_NAMES = ("anthropic-skills:driver", "anthropic-skills:empower")


def _mark(root: Path, seat: str) -> None:
    marker = root / ".claude" / "seat.local.txt"
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(seat, encoding="utf-8")


def _linked_worktree(sb: Sandbox, name: str = "wt") -> Path:
    """A linked worktree of the sandbox repository, as git lays one out: _hookinput.ps1 reads it."""
    gitdir = sb.repo / ".git" / "worktrees" / name
    gitdir.mkdir(parents=True)
    (gitdir / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (gitdir / "commondir").write_text("../..\n", encoding="utf-8")
    root = sb.repo.parent / name
    root.mkdir()
    (root / ".git").write_text(f"gitdir: {gitdir}\n", encoding="utf-8")
    return root


def _seat_run(
    sb: Sandbox,
    switch: str,
    seat: str | None,
    cwd: Path | None = None,
    source: str = "startup",
    **env: str,
) -> subprocess.CompletedProcess[str]:
    """-Banner with the switch at ``switch``, in a worktree whose marker holds ``seat``."""
    sb.set_state(variables={"MEFOR_AFK_KILL": switch})
    roles = sb.repo / "docs" / "roles"
    roles.mkdir(parents=True, exist_ok=True)
    shutil.copy(ROOT / "docs" / "roles" / "seats.json", roles / "seats.json")
    if seat is not None:
        _mark(sb.repo, seat)
    payload = {"hook_event_name": "SessionStart", "source": source, "cwd": str(cwd or sb.repo)}
    proc = sb.run(
        KILL, "-Banner", stdin=json.dumps(payload), **{"KORUS_SEAT": "", "KORUS_AGENT": "", **env}
    )
    assert proc.returncode == 0, proc.stderr
    return proc


def _seat_banner(
    sb: Sandbox, switch: str, seat: str | None, cwd: Path | None = None, **env: str
) -> str:
    return _seat_run(sb, switch, seat, cwd, **env).stdout


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
    # stderr too: a fault also prints no instruction, but says so there.
    proc = _seat_run(sb, "off", seat)
    assert (proc.stdout, proc.stderr) == ("", "")


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


def test_the_instruction_tells_a_late_special_to_skip_it(sb: Sandbox) -> None:
    # A Special seat declares late, so an undeclared one is told here.
    text = _instruction(_seat_banner(sb, "off", None))
    assert "A Special seat skips this" in text


RESTART_SOURCES = ("compact", "clear")
OTHER_SOURCES = ("startup", "resume", "fork", "", "Startup")
FULL_TEXT_SKIP = (
    "Skip a skill only if its full text is in your context now; a summary saying it was loaded "
    "does not count."
)


def _source_text(sb: Sandbox, source: str) -> str:
    text = _instruction(_seat_run(sb, "off", "builder", source=source).stdout)
    assert text, source
    return text


def _without_the_special_sentence(text: str) -> str:
    special = "A Special seat skips this"
    assert special in text, text
    return text[: text.index(special)]


@pytest.mark.parametrize("source", [*RESTART_SOURCES, " Compact "])
def test_a_compact_or_clear_is_told_to_load_both_again_with_no_skip_clause(
    sb: Sandbox, source: str
) -> None:
    text = _source_text(sb, source)
    assert "so load both again" in text
    # Any skip wording at all, bar the Special seat's, would let a session that reads a summary
    # saying it holds both skills keep going without them.
    assert "skip" not in _without_the_special_sentence(text).lower(), text


@pytest.mark.parametrize("source", OTHER_SOURCES)
def test_any_other_source_skips_a_skill_only_on_its_full_text(sb: Sandbox, source: str) -> None:
    text = _source_text(sb, source)
    assert FULL_TEXT_SKIP in text
    assert "again" not in text, text


def test_the_text_differs_by_source_only_in_the_reload_sentence(sb: Sandbox) -> None:
    texts = {source: _source_text(sb, source) for source in (*RESTART_SOURCES, *OTHER_SOURCES)}
    assert len({texts[s] for s in RESTART_SOURCES}) == 1, texts
    assert len({texts[s] for s in OTHER_SOURCES}) == 1, texts

    def outside(text: str, sentence: str) -> str:
        return text[: text.index(sentence)] + text[text.index("An owner instruction") :]

    restart, other = texts["compact"], texts["startup"]
    assert restart != other
    assert outside(restart, "This session restarted") == outside(other, FULL_TEXT_SKIP)


def test_an_owner_instruction_in_the_conversation_outranks_the_hook(sb: Sandbox) -> None:
    for source in ("compact", "resume"):
        text = _source_text(sb, source)
        assert "An owner instruction in this conversation to stop using either skill" in text


def test_korus_seat_names_the_seat_when_the_marker_does_not(sb: Sandbox) -> None:
    proc = _seat_run(sb, "off", None, KORUS_SEAT="special")
    assert (proc.stdout, proc.stderr) == ("", "")


def test_the_marker_outranks_korus_seat(sb: Sandbox) -> None:
    assert _instruction(_seat_banner(sb, "off", "builder", KORUS_SEAT="special"))


def test_a_codex_session_gets_no_skill_instruction(sb: Sandbox) -> None:
    assert _seat_banner(sb, "off", "builder", KORUS_AGENT="codex") == ""


def test_the_seat_comes_from_the_payload_worktree_not_the_process_cwd(sb: Sandbox) -> None:
    # Under the desktop app the hook runs in the primary checkout; the payload names the worktree.
    # The linked worktree holds no roster, so its seat is read against the script's own.
    wt = _linked_worktree(sb)
    _mark(wt, "builder")
    (wt / "src").mkdir()
    assert _instruction(_seat_banner(sb, "off", "special", cwd=wt / "src"))


@pytest.mark.parametrize("source", ["clear", "compact"])
def test_a_clear_or_compact_answers_for_the_worktree_its_cwd_names(
    sb: Sandbox, source: str
) -> None:
    # As role-card-inject.ps1 does, so the two hooks name one seat. A /clear mints a session id no
    # pin knows, and a pin-based read would refuse this desktop-app worktree after every /clear.
    wt = _linked_worktree(sb)
    _mark(wt, "builder")
    assert _instruction(_seat_run(sb, "off", "special", cwd=wt, source=source).stdout)
    _mark(wt, "special")
    proc = _seat_run(sb, "off", "builder", cwd=wt, source=source)
    assert (proc.stdout, proc.stderr) == ("", "")


def test_a_cwd_inside_no_checkout_gives_no_instruction_and_says_so(sb: Sandbox) -> None:
    outside = sb.repo.parent / "no-checkout"
    outside.mkdir()
    proc = _seat_run(sb, "off", "builder", cwd=outside)
    assert proc.stdout == "" and "inside no checkout" in proc.stderr, proc.stderr


@pytest.mark.parametrize("stdin", ["", "not json", "{}", "MISSING"])
def test_an_unusable_payload_gives_no_skill_instruction(sb: Sandbox, stdin: str) -> None:
    sb.set_state(variables={"MEFOR_AFK_KILL": "off"})
    if stdin == "MISSING":
        stdin = json.dumps({"cwd": str(sb.repo / "no-such-dir")})
    proc = sb.run(KILL, "-Banner", stdin=stdin, KORUS_SEAT="", KORUS_AGENT="")
    assert proc.returncode == 0 and proc.stdout == "", (proc.stdout, proc.stderr)


def test_a_roster_with_no_alias_map_gives_no_instruction_and_says_so(sb: Sandbox) -> None:
    roles = sb.repo / "docs" / "roles"
    roles.mkdir(parents=True)
    (roles / "seats.json").write_text(json.dumps({"live": ["builder"]}), encoding="utf-8")
    _mark(sb.repo, "builder")
    sb.set_state(variables={"MEFOR_AFK_KILL": "off"})
    payload = json.dumps({"hook_event_name": "SessionStart", "cwd": str(sb.repo)})
    proc = sb.run(KILL, "-Banner", stdin=payload, KORUS_SEAT="", KORUS_AGENT="")
    assert proc.stdout == "" and "no skill instruction" in proc.stderr, proc.stderr


def test_a_seat_file_read_fault_gives_no_instruction_and_keeps_the_banner(sb: Sandbox) -> None:
    on_before = _seat_banner(sb, "on", None)
    # A directory where the marker belongs: it exists, and reading it as a file throws.
    (sb.repo / ".claude" / "seat.local.txt").mkdir(parents=True)
    off = _seat_run(sb, "off", None)
    assert off.stdout == "" and "no skill instruction" in off.stderr, off.stderr
    assert _seat_banner(sb, "on", None) == on_before
