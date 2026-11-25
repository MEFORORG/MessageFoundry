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
import sys
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


def _linked_worktree(sb: Sandbox, name: str = "wt", repo: Path | None = None) -> Path:
    """A linked worktree of ``repo`` (the sandbox's by default), as git lays one out."""
    gitdir = (repo or sb.repo) / ".git" / "worktrees" / name
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


def _foreign_repo(sb: Sandbox, seat: str) -> Path:
    """A checkout of another repository, with a roster that maps no alias to Special."""
    foreign = sb.repo.parent / "foreign"
    foreign.mkdir()
    subprocess.run(["git", "init", "-q", str(foreign)], check=True, capture_output=True, timeout=60)
    roles = foreign / "docs" / "roles"
    roles.mkdir(parents=True)
    (roles / "seats.json").write_text(json.dumps({"aliases": {}}), encoding="utf-8")
    _mark(foreign, seat)
    (foreign / "src").mkdir()
    return foreign


NOT_OURS = "not shown to be a checkout of this repository"


def _undeclared(proc: subprocess.CompletedProcess[str]) -> None:
    """The instruction, its Special-skips sentence and the not-ours note were printed.

    Every instruction carries that sentence, so this alone does not prove the seat was undeclared.
    Where a caller sets this repository's own marker to Special and the cwd is elsewhere, reading
    that marker instead would print nothing. A non-Special cwd marker, read as the seat, would print
    the same instruction, so only the not-ours note shows that it did not name the seat.
    """
    text = _instruction(proc.stdout)
    assert "A Special seat skips this" in text, (proc.stdout, proc.stderr)
    assert NOT_OURS in proc.stderr, proc.stderr


def test_a_foreign_marker_does_not_decide_the_seat(sb: Sandbox) -> None:
    # BACKLOG #7559. A cwd in another repository's checkout must not let that checkout's marker, or
    # its roster missing the Special alias, name the seat: a non-Special one reads as undeclared.
    foreign = _foreign_repo(sb, "builder")
    _undeclared(_seat_run(sb, "off", "special", cwd=foreign / "src"))


@pytest.mark.parametrize("marker", ["", "\ufeff", "  \n"])
def test_a_blank_foreign_marker_falls_through_to_korus_seat_not_to_a_fault(
    sb: Sandbox, marker: str
) -> None:
    # KORUS_SEAT is Special, so only a fall-through to it prints nothing; returning undeclared on
    # the blank marker would print the instruction, and a fault would say so on stderr.
    foreign = _foreign_repo(sb, "builder")
    _mark(foreign, marker)
    proc = _seat_run(sb, "off", "builder", cwd=foreign / "src", KORUS_SEAT="special")
    assert proc.stdout == "" and NOT_OURS in proc.stderr, (proc.stdout, proc.stderr)
    assert VETO not in proc.stderr and "no skill instruction" not in proc.stderr, proc.stderr


@pytest.mark.parametrize("seat", ["special", "adhoc"])
def test_a_foreign_cwd_reads_korus_seat_against_our_roster(sb: Sandbox, seat: str) -> None:
    # The foreign roster maps no alias, so only this script's roster can make 'adhoc' Special.
    foreign = _foreign_repo(sb, "builder")
    proc = _seat_run(sb, "off", None, cwd=foreign / "src", KORUS_SEAT=seat)
    assert proc.stdout == "" and NOT_OURS in proc.stderr, (proc.stdout, proc.stderr)
    assert "no skill instruction" not in proc.stderr, proc.stderr  # read as Special, not a fault
    assert VETO not in proc.stderr, proc.stderr  # KORUS_SEAT silenced it, not the marker


def test_a_foreign_cwd_with_a_non_special_korus_seat_gets_the_instruction(sb: Sandbox) -> None:
    # The negative control for the test above.
    foreign = _foreign_repo(sb, "builder")
    _undeclared(_seat_run(sb, "off", None, cwd=foreign / "src", KORUS_SEAT="builder"))


def test_a_linked_worktree_of_another_repository_reads_as_undeclared(sb: Sandbox) -> None:
    wt = _linked_worktree(sb, "fwt", repo=_foreign_repo(sb, "special"))
    _mark(wt, "builder")
    _undeclared(_seat_run(sb, "off", "special", cwd=wt))


VETO = "its seat marker names a Special seat, so no instruction"


def _veto(proc: subprocess.CompletedProcess[str]) -> None:
    """No instruction, no fault, and the not-ours branch's veto is what silenced it."""
    assert proc.stdout == "", (proc.stdout, proc.stderr)
    assert VETO in proc.stderr and "no skill instruction" not in proc.stderr, proc.stderr


def _orphan_worktree(sb: Sandbox) -> Path:
    """A worktree whose git dir is gone, so its common dir cannot be read."""
    wt = sb.repo.parent / "orphan"
    wt.mkdir()
    (wt / ".git").write_text(
        f"gitdir: {sb.repo / '.git' / 'worktrees' / 'gone'}\n", encoding="utf-8"
    )
    return wt


# A marker outside this repository cannot NAME the seat, but one naming Special, or an alias of it
# in this script's roster, still VETOES the instruction, as it did before the repository check.
# Each case leaves this repository's own marker on a non-Special seat, so only the cwd's marker
# can silence the hook; the foreign roster maps no alias, so only ours can make 'adhoc' Special.
@pytest.mark.parametrize("marker", ["special", " Special\n", "adhoc", "special-1", "specials"])
def test_a_foreign_special_marker_vetoes_the_instruction(sb: Sandbox, marker: str) -> None:
    foreign = _foreign_repo(sb, marker)
    _veto(_seat_run(sb, "off", "builder", cwd=foreign / "src"))


def test_an_alias_only_the_foreign_roster_maps_still_vetoes(sb: Sandbox) -> None:
    # This script's roster does not know 'special9', so only the cwd's roster can make it Special.
    foreign = _foreign_repo(sb, "special9")
    roster = foreign / "docs" / "roles" / "seats.json"
    roster.write_text(json.dumps({"aliases": {"special9": "special"}}), encoding="utf-8")
    _veto(_seat_run(sb, "off", "builder", cwd=foreign / "src"))


def test_a_foreign_cwd_reads_korus_seat_against_the_cwd_roster_too(sb: Sandbox) -> None:
    # With no marker, KORUS_SEAT is the label read. This script's roster does not know 'special9',
    # so only the cwd's roster can make it Special, as it does for the marker above.
    foreign = _foreign_repo(sb, "builder")
    (foreign / ".claude" / "seat.local.txt").unlink()
    roster = foreign / "docs" / "roles" / "seats.json"
    roster.write_text(json.dumps({"aliases": {"special9": "special"}}), encoding="utf-8")
    proc = _seat_run(sb, "off", "builder", cwd=foreign / "src", KORUS_SEAT="special9")
    assert proc.stdout == "" and NOT_OURS in proc.stderr, (proc.stdout, proc.stderr)
    assert "no skill instruction" not in proc.stderr, proc.stderr  # read as Special, not a fault
    assert VETO not in proc.stderr, proc.stderr  # KORUS_SEAT silenced it, not the marker
    # The control: the same setup with a non-Special KORUS_SEAT prints the instruction.
    _undeclared(_seat_run(sb, "off", "builder", cwd=foreign / "src", KORUS_SEAT="builder"))


@pytest.mark.parametrize("label", ["marker", "korus_seat"])
def test_an_unreadable_foreign_roster_gives_no_instruction(sb: Sandbox, label: str) -> None:
    # A Special alias only that roster maps would be lost if the fault were skipped, so it throws
    # and prints no instruction, as a fault reading this script's roster or the marker does. The
    # label it would be read for is the cwd's marker or, with no marker, KORUS_SEAT. Every label
    # here is non-Special, so only the fault can silence the hook.
    foreign = _foreign_repo(sb, "builder")
    env = {}
    if label == "korus_seat":
        (foreign / ".claude" / "seat.local.txt").unlink()
        env["KORUS_SEAT"] = "builder"
    roster = foreign / "docs" / "roles" / "seats.json"
    roster.write_text("not json", encoding="utf-8")
    proc = _seat_run(sb, "off", "builder", cwd=foreign / "src", **env)
    assert proc.stdout == "", (proc.stdout, proc.stderr)
    assert VETO not in proc.stderr, proc.stderr
    # The fault names the roster it could not read: the JSON error alone names no file.
    fault = [line for line in proc.stderr.splitlines() if "no skill instruction" in line]
    assert len(fault) == 1, proc.stderr
    assert "foreign" in fault[0] and "seats.json" in fault[0], fault[0]
    # The control: the same setup with a readable roster prints the instruction, so the roster's
    # content is what silenced it above.
    roster.write_text(json.dumps({"aliases": {}}), encoding="utf-8")
    _undeclared(_seat_run(sb, "off", "builder", cwd=foreign / "src", **env))


def test_a_foreign_special_marker_outranks_korus_seat(sb: Sandbox) -> None:
    # As the cwd's marker outranks KORUS_SEAT within this repository.
    foreign = _foreign_repo(sb, "special")
    _veto(_seat_run(sb, "off", "builder", cwd=foreign / "src", KORUS_SEAT="builder"))


def test_a_foreign_linked_worktree_special_marker_vetoes_the_instruction(sb: Sandbox) -> None:
    wt = _linked_worktree(sb, "fwt", repo=_foreign_repo(sb, "builder"))
    _mark(wt, "special")
    _veto(_seat_run(sb, "off", "builder", cwd=wt))


def test_a_worktree_whose_git_dir_is_gone_reads_as_undeclared(sb: Sandbox) -> None:
    # Its common dir cannot be read, so it cannot be shown to be this repository's.
    wt = _orphan_worktree(sb)
    _mark(wt, "builder")
    _undeclared(_seat_run(sb, "off", "special", cwd=wt))


@pytest.mark.parametrize("marker", ["special", "adhoc"])
def test_a_special_marker_where_the_git_dir_is_gone_vetoes_the_instruction(
    sb: Sandbox, marker: str
) -> None:
    # Its common dir cannot be read, so the marker cannot name the seat, but it can still veto.
    wt = _orphan_worktree(sb)
    _mark(wt, marker)
    _veto(_seat_run(sb, "off", "builder", cwd=wt))


def _dir_link(link: Path, target: Path) -> None:
    if sys.platform == "win32":
        subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(target)],
            check=True,
            capture_output=True,
            timeout=60,
        )
    else:
        link.symlink_to(target, target_is_directory=True)


def test_a_worktree_of_this_repository_spelled_through_a_link_names_its_seat(
    sb: Sandbox,
) -> None:
    # The positive control for the repository check: the script runs through a link to the repo,
    # while the worktree's gitdir line names the real path, as git writes it. Its Special marker
    # holds only if the worktree is recognised as ours; read as undeclared it would print.
    wt = _linked_worktree(sb)
    _mark(wt, "special")
    link = sb.repo.parent / "linked-repo"
    _dir_link(link, sb.repo)
    sb.set_state(variables={"MEFOR_AFK_KILL": "off"})
    roles = sb.repo / "docs" / "roles"
    roles.mkdir(parents=True, exist_ok=True)
    shutil.copy(ROOT / "docs" / "roles" / "seats.json", roles / "seats.json")
    payload = {"hook_event_name": "SessionStart", "source": "compact", "cwd": str(wt)}
    argv = sb.argv(KILL, "-Banner")
    argv[argv.index("-File") + 1] = str(link / KILL.relative_to(ROOT))
    proc = subprocess.run(
        argv,
        cwd=str(link),
        env=sb.env(KORUS_SEAT="", KORUS_AGENT=""),
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert (proc.stdout, proc.stderr) == ("", "")


def test_an_unreadable_own_checkout_reads_as_undeclared(sb: Sandbox) -> None:
    # The script's own common dir cannot be read, so no cwd can be shown to be this repository's.
    (sb.repo / ".git" / "HEAD").unlink()
    _undeclared(_seat_run(sb, "off", "builder"))


def test_a_special_marker_in_an_unreadable_own_checkout_vetoes_the_instruction(
    sb: Sandbox,
) -> None:
    (sb.repo / ".git" / "HEAD").unlink()
    _veto(_seat_run(sb, "off", "special"))


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
