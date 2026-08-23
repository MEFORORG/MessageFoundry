# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The seat-clock alarm must fire on a dead chain and stay quiet on a healthy one (#1269).

Every test is one half of a PAIR, because the item's whole thesis is that the OBVIOUS
implementation reads healthy at the moment it should fire. A suite of must-fire arms alone would be
satisfied by the freshness-only version this build exists to replace.

``test_it_fires_when_the_watched_worktree_is_absent_from_a_FRESH_state_file`` is the discriminating
one: it is green for the broken implementation and red for a correct one, so it is the only arm that
separates them. Every other arm guards a fault that would make a HEALTHY clock report as broken --
and a false-positive watchdog is not a safe failure mode, it is a slow-acting off switch.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = _ROOT / "scripts" / "coord" / "seat_clock_alarm.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("seat_clock_alarm", _SCRIPT)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


alarm = _load()

WATCHED = r"C:\work\lane-a"
NOW = 1_787_000_000.0
FRESH = int(NOW) - 60
STALE_TICK = int(NOW) - (60 * 60)


def _state(**extra: int) -> dict[str, int]:
    base = {r"c:\work\other-lane": FRESH}
    base.update(extra)
    return base


# --------------------------------------------------------------------------------------------
# THE DISCRIMINATING PAIR
# --------------------------------------------------------------------------------------------


def test_it_fires_when_the_watched_worktree_is_absent_from_a_FRESH_state_file() -> None:
    """MUST FIRE, AND THIS IS THE ONLY ARM THAT SEPARATES THE TWO IMPLEMENTATIONS.

    Other seats keep the heartbeat fresh, so a freshness-only alarm is GREEN here -- at exactly the
    moment the watched seat has stopped being woken. Measured precedent: ticks 59m58s apart while the
    file stayed under two minutes old for the whole hour."""
    v = alarm.evaluate(WATCHED, "lane-a", _state(), "other-lane=SENT:abc", NOW)
    assert v.alarm is True
    assert v.code == "ABSENT"
    assert "no entry" in v.detail


def test_it_is_silent_when_the_watched_worktree_is_present_and_recent() -> None:
    """MUST NOT FIRE -- the twin. Without it, an alarm that fired unconditionally would pass above."""
    v = alarm.evaluate(
        WATCHED, "lane-a", _state(**{r"c:\work\lane-a": FRESH}), "lane-a=SENT:abc", NOW
    )
    assert v.alarm is False
    assert v.code == "OK"


# --------------------------------------------------------------------------------------------
# THE FIRST-MATCH TRAP -- measured on the live file, three seats twice each
# --------------------------------------------------------------------------------------------


def test_a_seat_named_TWICE_reads_as_SENT_not_as_the_first_token() -> None:
    """MUST NOT FIRE, AND THIS IS A LIVE SHAPE RATHER THAN A HYPOTHETICAL.

    Measured 2026-08-23: the real one-liner carried steward, lander and dispatcher TWICE EACH --
    once STALE(no-live-session), once SENT:<id>. Taking the first match reads STALE for all three
    while the clock ticks normally, which is the same first-match trap that cost four seats a wrong
    answer that morning."""
    line = "lane-a=STALE(no-live-session)  other=SENT:zzz  lane-a=SENT:20260823T184037416-texbqx"
    assert alarm.suppression_for(line, "lane-a") is None, "a send anywhere in the line must win"


def test_a_seat_named_only_as_STALE_is_read_as_suppressed() -> None:
    """MUST NOT FIRE AS A DEATH -- the twin of the arm above, differing only by the SENT token.

    Without this pair, 'a send wins' could be implemented as 'never suppress' and both would pass."""
    line = "lane-a=STALE(no-live-session)  other=SENT:zzz"
    assert alarm.suppression_for(line, "lane-a") == "STALE(no-live-session)"


# --------------------------------------------------------------------------------------------
# SUPPRESSION -- a deliberate gap is not a dead chain
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "status",
    [
        "THROTTLED(last-send-120s-ago,floor-360s)",
        "COLD(3-ticks,2-peer-mail,0-unreadable,oldest=20m,needs-send_message)",
        "BACKLOG(4-pending,oldest=30m,suppressed)",
        "STALE(no-live-session)",
    ],
)
def test_a_long_gap_under_a_suppression_token_does_not_alarm(status: str) -> None:
    """MUST NOT FIRE. An 88-minute gap once read as 'chain broken' and was deliberate suppression on
    a seat taking continuous turns. All four tokens are read from the emitter, not from the item --
    STALE and the (roster-blind) suffix postdate the item's list."""
    v = alarm.evaluate(
        WATCHED,
        "lane-a",
        _state(**{r"c:\work\lane-a": STALE_TICK}),
        f"lane-a={status}",
        NOW,
    )
    assert v.alarm is False
    assert v.code == "SUPPRESSED"


def test_the_same_long_gap_with_NO_suppression_token_does_alarm() -> None:
    """MUST FIRE -- the twin. Otherwise 'honour suppression' could be implemented as 'never alarm on
    age' and every suppression arm above would still pass."""
    v = alarm.evaluate(
        WATCHED,
        "lane-a",
        _state(**{r"c:\work\lane-a": STALE_TICK}),
        "lane-a=SENT:abc",
        NOW,
    )
    assert v.alarm is True
    assert v.code == "DEAD"


# --------------------------------------------------------------------------------------------
# THROTTLE-AGE CONSISTENCY -- one comparison that rejects the decoy and catches corruption
# --------------------------------------------------------------------------------------------


def test_a_throttle_record_that_contradicts_itself_does_NOT_silence_the_alarm() -> None:
    """MUST FIRE. The known decoy claims THROTTLED with floor-360s while its own stated age is
    ~36000s -- a hundred-fold contradiction, since throttling means suppressed because a send was too
    RECENT. Honouring it is how an alarm goes quiet over a ten-hour-old file and reports nothing
    wrong, because from its point of view nothing IS wrong."""
    line = "lane-a=THROTTLED(last-send-35997s-ago,floor-360s)"
    assert alarm.throttle_is_credible("THROTTLED(last-send-35997s-ago,floor-360s)") is False
    v = alarm.evaluate(WATCHED, "lane-a", _state(**{r"c:\work\lane-a": STALE_TICK}), line, NOW)
    assert v.alarm is True and v.code == "DEAD"


def test_a_CREDIBLE_throttle_record_is_still_honoured() -> None:
    """MUST NOT FIRE -- the twin. A sanity check that rejected every throttle would turn ordinary
    suppression into a permanent alarm, which is the false-positive direction that gets it ignored."""
    assert alarm.throttle_is_credible("THROTTLED(last-send-120s-ago,floor-360s)") is True


def test_a_throttle_claiming_a_send_in_the_FUTURE_is_rejected() -> None:
    """MUST FIRE. The decoy's literal text is `last-send--35997s-ago` -- a NEGATIVE age, i.e. a send
    ten hours from now. Both readings of that string are self-contradictory and either must trip."""
    assert alarm.throttle_is_credible("THROTTLED(last-send--35997s-ago,floor-360s)") is False


# --------------------------------------------------------------------------------------------
# DEDUPE BY TICK IDENTITY, and the over-firing bound
# --------------------------------------------------------------------------------------------


def test_an_UNCHANGED_stamp_is_the_same_tick_not_a_zero_length_interval() -> None:
    """MUST NOT FIRE, AND THIS IS THE MEASURED FAULT. A raw scan produced ten 0.0-minute intervals
    and flagged over-firing ten times; 22 records were about 12 ticks differing in milliseconds.
    Identity is the stamp VALUE -- seeing it twice is one tick observed twice."""
    v = alarm.evaluate(
        WATCHED,
        "lane-a",
        _state(**{r"c:\work\lane-a": FRESH}),
        "lane-a=SENT:abc",
        NOW,
        previous_tick=FRESH,
    )
    assert v.alarm is False, "the same stamp seen twice is not a zero-second interval"
    assert v.code == "OK"


def test_two_GENUINELY_close_ticks_do_alarm_as_over_firing() -> None:
    """MUST FIRE -- the twin of the dedupe arm. Over-firing is the EXPENSIVE fault: every tick wakes a
    seat and spends a turn, so a runaway clock burns the budget the alarm exists to protect. Six
    manual runs once cost ~9 points of a shared pool in nine minutes."""
    v = alarm.evaluate(
        WATCHED,
        "lane-a",
        _state(**{r"c:\work\lane-a": FRESH}),
        "lane-a=SENT:abc",
        NOW,
        previous_tick=FRESH - 30,
    )
    assert v.alarm is True
    assert v.code == "OVERFIRING"


# --------------------------------------------------------------------------------------------
# PATH DISCIPLINE AND THE MISSING-INSTRUMENT REFUSAL
# --------------------------------------------------------------------------------------------


def test_the_watched_path_matches_regardless_of_case_and_separator() -> None:
    """Windows path casing has already killed this clock once -- seats.json carried one directory
    under two casings and the tick script died on the parse. The state file's own keys are
    lowercased, so the lookup must normalise both sides."""
    state = {r"c:\work\lane-a": FRESH}
    v = alarm.evaluate("C:/Work/Lane-A", "lane-a", state, "lane-a=SENT:abc", NOW)
    assert v.code == "OK", "a case- or separator-differing path must still find its entry"


def test_a_missing_instrument_returns_2_rather_than_reporting_OK(
    tmp_path: Path,
) -> None:
    """A MISSING INSTRUMENT IS NOT A CLEAN RESULT. Returning 0 here would be the same false green the
    alarm exists to catch, one level up -- and it is how a glob that lands nowhere reports health."""
    rc = alarm.main(
        [
            "--worktree",
            WATCHED,
            "--seat",
            "lane-a",
            "--state",
            str(tmp_path / "nope.json"),
            "--last",
            str(tmp_path / "nope.last"),
        ]
    )
    assert rc == 2, "absent instruments must be distinguishable from a healthy clock"


def test_the_cli_reports_its_denominator(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A state file holding 3 worktrees and one holding 60 must not print the same reassuring line."""
    state = tmp_path / "s.json"
    state.write_text(json.dumps({r"c:\work\lane-a": FRESH, r"c:\work\b": FRESH}), encoding="utf-8")
    last = tmp_path / "s.last"
    last.write_text("2026-01-01T00:00:00Z\tlane-a=SENT:abc", encoding="utf-8")
    alarm.main(
        [
            "--worktree",
            WATCHED,
            "--seat",
            "lane-a",
            "--state",
            str(state),
            "--last",
            str(last),
        ]
    )
    assert "2 worktrees in state" in capsys.readouterr().out


# ---------------------------------------------------------------------------------------------
# A BROKEN INSTRUMENT IS NOT AN ALARM CONDITION.
#
# The first cut reported DEAD/ABSENT when it could not READ the state file -- a false positive that
# fires for EVERY watched seat at once, so the first false alarm is also the loudest. That is the
# worst possible introduction for a tool whose only value is being believed, and the module docstring
# already names the consequence: a false-positive watchdog is a slow-acting off switch.
#
# exit 2 CANNOT MEASURE already existed for the MISSING file. These arms are its second application.
# ---------------------------------------------------------------------------------------------


def _files(tmp_path: Path, state_text: str) -> tuple[Path, Path]:
    s = tmp_path / "state.json"
    s.write_text(state_text, encoding="utf-8")
    last = tmp_path / "state.last"
    last.write_text("2026-01-01T00:00:00Z\tlane-a=SENT:abc", encoding="utf-8")
    return s, last


def _rc(tmp_path: Path, state_text: str) -> int:
    s, last = _files(tmp_path, state_text)
    return alarm.main(
        [
            "--worktree",
            WATCHED,
            "--seat",
            "lane-a",
            "--state",
            str(s),
            "--last",
            str(last),
        ]
    )


def test_a_CORRUPT_state_file_cannot_measure_rather_than_alarming(
    tmp_path: Path,
) -> None:
    """MUST NOT ALARM. This is an OBSERVED event here, not a hypothetical: the item records that a
    Windows path-casing collision killed this clock once already by dying on a JSON parse."""
    assert _rc(tmp_path, '{"c:\\work\\lane-a": 178700') == 2


def test_a_state_SCHEMA_this_reader_does_not_know_cannot_measure(
    tmp_path: Path,
) -> None:
    """MUST NOT ALARM. Every record skipped is a signal the schema changed, never an empty registry.

    Before this, the reader dropped them silently and the alarm reported ABSENT for every seat --
    confidently, on data it had never understood. The Liaison's form of the same rule: when every
    field you asked for comes back empty, you are querying a schema you did not read."""
    assert _rc(tmp_path, '{"c:\\work\\lane-a": {"last": 1787000000}}') == 2


def test_a_GENUINELY_EMPTY_registry_still_alarms(tmp_path: Path) -> None:
    """MUST ALARM -- THE TWIN, and the arm that stops the fix swallowing the real case.

    An empty object is not an unreadable one. No records means the watched seat really has no tick,
    which is the discriminating condition this whole tool exists for. A schema check that treated
    {} as unreadable would silence the alarm exactly when it should fire."""
    assert _rc(tmp_path, "{}") == 1


def test_a_MISSING_state_file_still_cannot_measure(tmp_path: Path) -> None:
    """REGRESSION. The original exit-2 arm must survive the new ones."""
    rc = alarm.main(
        [
            "--worktree",
            WATCHED,
            "--seat",
            "lane-a",
            "--state",
            str(tmp_path / "absent.json"),
            "--last",
            str(tmp_path / "absent.last"),
        ]
    )
    assert rc == 2
