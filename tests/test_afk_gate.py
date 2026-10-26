# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""scripts/coord/decision.ps1 -Gate: the Class B gate (docs/AUTONOMY-PLAN.md R4 and 4.5-4.7).

Each test drives the real script from a sandbox (tests/_fake_gh.py). The vault is seeded directly
with comments in decision.ps1's format, dated relative to the wall clock because the gate reads the
trailing hours before now. The cost rung reads a stand-in usage reader the test writes, never the
host account's own usage files.

A calibrated seat with nothing else against it answers NO-REVIEW, and each REVIEW or HALT test
starts from that seat, so a REVIEW proves the one condition the test adds closed the path.
"""

from __future__ import annotations

import itertools
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from tests._fake_gh import (
    COORD,
    ROOT,
    Sandbox,
    make_sandbox,
    no_host_usage,
    seed_vault,
    write_fake_usage,
)

DECISION = COORD / "decision.ps1"
DIGEST = COORD / "digest.ps1"
NO_REVIEW, REVIEW, HALT = 10, 11, 12

pytestmark = pytest.mark.skipif(shutil.which("pwsh") is None, reason="pwsh not on PATH")

_SEQ = itertools.count(1)


def ago(**delta: float) -> datetime:
    # Read per call, not at import: the gate reads the wall clock, and a long suite would
    # otherwise age every record by however long it ran before this test.
    return datetime.now(UTC) - timedelta(**delta)


def rec(kind: str = "decision", at: datetime | None = None, **fields: Any) -> dict[str, Any]:
    """A record whose id carries ``at`` (default an hour ago), as decision.ps1 would mint it."""
    when = at or ago(hours=1)
    n = next(_SEQ)
    base: dict[str, Any] = {
        "v": 1,
        "id": f"d{when.strftime('%Y%m%dT%H%M%S')}{when.microsecond // 1000:03d}-{n:06x}",
        "ts": when.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "kind": kind,
        "item": "",
        "seat": "manager",
        "session": "s1",
        "class": "B",
        "predicates": [],
        "recommendation": "r",
        "alternatives": ["the other way"],
        "undo": "",
        "confidence": None,
        "reviewed": "no",
        "reviewedBy": "",
        "outcome": "pending",
        "ref": "",
        "rating": "",
        "note": "",
        "buildsOn": [],
        "gate": "",
    }
    base.update(fields)
    return base


def calibrated(seat: str) -> list[dict[str, Any]]:
    """60 Class B decisions by ``seat``, 20 days old, each rated agree: calibrated, all on one day
    so the gate reads one more issue for them, and outside the 14-day reversal window."""
    decided = [rec(at=ago(days=20, minutes=i), seat=seat, item="calib") for i in range(60)]
    rated = [
        rec("rating", at=ago(days=20, minutes=-1 - i), seat="owner", ref=d["id"], rating="agree")
        for i, d in enumerate(decided)
    ]
    return decided + rated


def reversal(decision: dict[str, Any], at: datetime, by: str = "lander") -> dict[str, Any]:
    return rec("outcome", at=at, seat=by, ref=decision["id"], outcome="reversed", note="PR 9")


def usage(pct: float | None = 40.0, **five: Any) -> dict[str, Any]:
    """usage.ps1 -Json's shape for a fresh 5-hour reading, with no burn rate unless given one."""
    window = {
        "label": "session (5h)",
        "used_percentage": pct,
        "reading_age_min": 1.0,
        "minutes_to_reset": 120,
        "rate_pct_per_hr": None,
        "minutes_to_empty": None,
        "state": "OK",
        "reason": "",
    }
    window.update(five)
    return {"state": window["state"], "exit_code": 0, "five_hour": window, "seven_day": {}}


@pytest.fixture
def sb(tmp_path: Path) -> Sandbox:
    s = make_sandbox(tmp_path)
    s.set_state(variables={"MEFOR_AFK_KILL": "off"})
    write_fake_usage(tmp_path / "usage.ps1", usage())
    return s


def _usage_path(sb: Sandbox) -> Path:
    return sb.state_path.parent / "usage.ps1"


def _thresholds(sb: Sandbox) -> Path:
    return sb.state_path.parent / "thresholds.json"


def gate(
    sb: Sandbox, *args: str, item: str = "4242", seat: str | None = "manager", **extra: str
) -> tuple[int, dict[str, Any]]:
    seat_args = ("-Seat", seat) if seat is not None else ()
    proc = sb.run(
        DECISION, *no_host_usage(sb, ("-Gate", "-Item", item, *seat_args, "-Json", *args)), **extra
    )
    assert proc.stdout.strip(), (proc.stdout, proc.stderr)
    doc: dict[str, Any] = json.loads(proc.stdout)
    assert doc["exit"] == proc.returncode, doc
    return proc.returncode, doc


def why(doc: dict[str, Any]) -> str:
    return "\n".join(doc["reasons"])


# --- the positive control, and the default answer ---------------------------------------------


def test_a_calibrated_seat_with_nothing_against_it_may_act_without_review(sb: Sandbox) -> None:
    seed_vault(sb, calibrated("manager"))
    code, doc = gate(sb)
    assert (code, doc["result"]) == (NO_REVIEW, "NO-REVIEW"), why(doc)


def test_an_uncalibrated_seat_takes_the_review_path(sb: Sandbox) -> None:
    """Nothing is calibrated today, so this is every seat's answer until 60 blind samples exist."""
    code, doc = gate(sb)
    assert (code, doc["result"]) == (REVIEW, "REVIEW")
    assert "not calibrated (review path, 0/60 samples" in why(doc)


def test_the_plain_answer_is_one_word_with_the_reasons_on_stderr(sb: Sandbox) -> None:
    proc = sb.run(DECISION, *no_host_usage(sb, ("-Gate", "-Item", "1", "-Seat", "manager")))
    assert proc.returncode == REVIEW
    assert proc.stdout.strip() == "REVIEW"
    assert "decision.ps1: gate: calibration:" in proc.stderr


def test_a_kill_switch_that_is_not_off_reviews_without_reading_the_log(sb: Sandbox) -> None:
    seed_vault(sb, calibrated("manager"))
    sb.set_state(variables={"MEFOR_AFK_KILL": "on"}, calls=[])
    code, doc = gate(sb)
    assert code == REVIEW and "kill switch reads 'ON'" in why(doc)
    assert not [c for c in sb.calls if any("/issues" in a for a in c)], "the log was read"


# --- fails closed ---------------------------------------------------------------------------


def test_a_log_that_cannot_be_read_reviews(sb: Sandbox) -> None:
    seed_vault(sb, calibrated("manager"))
    sb.set_state(fail_match="/comments")
    code, doc = gate(sb)
    assert code == REVIEW and "not fully read" in why(doc)


@pytest.mark.parametrize(
    "answer",
    [pytest.param("not json at all", id="garbage"), pytest.param("", id="nothing")],
)
def test_a_usage_reading_that_cannot_be_parsed_reviews(sb: Sandbox, answer: str) -> None:
    seed_vault(sb, calibrated("manager"))
    write_fake_usage(_usage_path(sb), answer, code=1)
    code, doc = gate(sb)
    assert code == REVIEW and "cost rung UNKNOWN" in why(doc)


def test_a_missing_usage_reader_reviews(sb: Sandbox) -> None:
    seed_vault(sb, calibrated("manager"))
    _usage_path(sb).unlink()
    code, doc = gate(sb)
    assert code == REVIEW and "does not exist" in why(doc)


def test_a_session_with_no_seat_reviews(sb: Sandbox) -> None:
    """No -Seat, and the sandbox's seat registry holds nothing for the session."""
    code, doc = gate(sb, seat=None)
    assert code == REVIEW and "no seat was given" in why(doc)


def test_gate_needs_an_item_and_refuses_a_malformed_builds_on(sb: Sandbox) -> None:
    proc = sb.run(DECISION, "-Gate", "-Seat", "manager")
    assert proc.returncode == 2 and "-Gate needs -Item" in proc.stderr
    proc = sb.run(DECISION, "-Gate", "-Item", "1", "-BuildsOn", "not-an-id")
    assert proc.returncode == 2 and "is not a decision id" in proc.stderr


# --- the cost rung (plan 4.7) ----------------------------------------------------------------


def test_the_level_backstop_halts_before_anything_is_read(sb: Sandbox) -> None:
    """With no burn rate, the 5-hour level at the start-nothing rung (80, STEWARD.md section 3)."""
    seed_vault(sb, calibrated("manager"))
    write_fake_usage(_usage_path(sb), usage(80.0))
    sb.set_state(calls=[])
    code, doc = gate(sb)
    assert (code, doc["result"]) == (HALT, "HALT"), why(doc)
    assert sb.calls == [], "a HALT read the network"


def test_below_the_level_with_no_rate_does_not_halt(sb: Sandbox) -> None:
    seed_vault(sb, calibrated("manager"))
    write_fake_usage(_usage_path(sb), usage(79.9))
    assert gate(sb)[0] == NO_REVIEW


def test_a_projected_cutoff_inside_twenty_minutes_halts(sb: Sandbox) -> None:
    seed_vault(sb, calibrated("manager"))
    write_fake_usage(
        _usage_path(sb),
        usage(50.0, rate_pct_per_hr=200.0, minutes_to_empty=15, minutes_to_reset=90),
    )
    code, doc = gate(sb)
    assert code == HALT and "run out in about 15 min" in why(doc)


def test_the_rate_governs_over_a_high_level(sb: Sandbox) -> None:
    """STEWARD.md 9.6a: a window that resets before it runs out does not stop new work."""
    seed_vault(sb, calibrated("manager"))
    write_fake_usage(
        _usage_path(sb),
        usage(90.0, state="WARN", rate_pct_per_hr=2.0, minutes_to_empty=300, minutes_to_reset=30),
    )
    code, doc = gate(sb)
    assert code == NO_REVIEW, why(doc)


def test_a_window_at_the_ceiling_halts_whatever_the_rate(sb: Sandbox) -> None:
    """A flat rate at 100 percent leaves usage.ps1 no minutes_to_empty; it is no room, not room."""
    seed_vault(sb, calibrated("manager"))
    write_fake_usage(
        _usage_path(sb),
        usage(100.0, state="CRITICAL", rate_pct_per_hr=0.0, minutes_to_empty=None),
    )
    code, doc = gate(sb)
    assert code == HALT and "At the ceiling" in why(doc)


def test_a_critical_reading_below_the_rung_is_unknown(sb: Sandbox) -> None:
    """usage.ps1 skips its statusLine trust check at CRITICAL overall, here from the weekly window."""
    seed_vault(sb, calibrated("manager"))
    doc = usage(40.0)
    doc.update(state="CRITICAL", statusline_state="WIRED_ELSEWHERE")
    write_fake_usage(_usage_path(sb), doc, code=11)
    code, out = gate(sb)
    assert code == REVIEW and "may be another root's" in why(out)


def test_an_unknown_cost_reading_reviews_rather_than_halts(sb: Sandbox) -> None:
    seed_vault(sb, calibrated("manager"))
    write_fake_usage(_usage_path(sb), {"state": "UNKNOWN", "reason": "no statusLine"}, code=20)
    code, doc = gate(sb)
    assert code == REVIEW and "not to a halt" in why(doc)


def test_a_reading_usage_calls_unknown_overall_is_unknown_here(sb: Sandbox) -> None:
    """usage.ps1's overall UNKNOWN also carries its refusal of a statusLine wired elsewhere."""
    seed_vault(sb, calibrated("manager"))
    doc = usage(40.0)
    doc.update(state="UNKNOWN", statusline_state="WIRED_ELSEWHERE")
    write_fake_usage(_usage_path(sb), doc, code=20)
    code, out = gate(sb)
    assert code == REVIEW and "WIRED_ELSEWHERE" in why(out)


def test_a_hit_stands_when_usage_reads_unknown_overall(sb: Sandbox) -> None:
    """An OK 5-hour window past the level backstop, under usage.ps1's refusal of a statusLine
    wired elsewhere: downgrading that hit to UNKNOWN would let a session at the rung act."""
    seed_vault(sb, calibrated("manager"))
    doc = usage(82.0)
    doc.update(state="UNKNOWN", statusline_state="WIRED_ELSEWHERE")
    write_fake_usage(_usage_path(sb), doc, code=20)
    code, out = gate(sb)
    assert code == HALT and "the level is the backstop" in why(out), why(out)


@pytest.mark.parametrize("seat", ["lander", "land"])
def test_the_lander_is_exempt_from_the_halt(sb: Sandbox, seat: str) -> None:
    """The roster's aliases count too; the sandbox gets the real roster, as a checkout has it."""
    roster = sb.repo / "docs" / "roles"
    roster.mkdir(parents=True)
    shutil.copy2(ROOT / "docs" / "roles" / "seats.json", roster / "seats.json")
    seed_vault(sb, calibrated(seat))
    write_fake_usage(_usage_path(sb), usage(99.0, state="CRITICAL"))
    code, doc = gate(sb, seat=seat)
    assert code == NO_REVIEW, why(doc)
    assert "Lander is exempt" in why(doc)


def test_the_thresholds_file_moves_the_rung(sb: Sandbox) -> None:
    seed_vault(sb, calibrated("manager"))
    write_fake_usage(_usage_path(sb), usage(75.0))
    _thresholds(sb).write_text(json.dumps({"levels": {"weekly": [90, 94, 97]}}), encoding="utf-8")
    assert gate(sb)[0] == NO_REVIEW, "a weekly-only file moved the 5-hour rung"
    _thresholds(sb).write_text(json.dumps({"levels": {"5-hour": [70, 80, 90]}}), encoding="utf-8")
    code, doc = gate(sb)
    assert code == HALT and str(_thresholds(sb)) in why(doc)


@pytest.mark.parametrize(
    "body",
    [
        pytest.param("{not json", id="unreadable"),
        pytest.param(json.dumps({"levels": {"5-hour": [80, 86]}}), id="two-numbers"),
        pytest.param(json.dumps({"levels": {"5h": [80, 86, 92]}}), id="unknown-window"),
    ],
)
def test_a_malformed_thresholds_file_reviews(sb: Sandbox, body: str) -> None:
    seed_vault(sb, calibrated("manager"))
    _thresholds(sb).write_text(body, encoding="utf-8")
    code, doc = gate(sb)
    assert code == REVIEW and "rung levels could not be read" in why(doc)


@pytest.mark.parametrize(("pct", "expected"), [(99, HALT), (50, REVIEW)])
def test_the_real_usage_reader_feeds_the_rung(
    sb: Sandbox, tmp_path: Path, pct: int, expected: int
) -> None:
    """The real reader and collector, so the gate reads usage.ps1's real shape. The fixture root
    wires no statusLine, so usage.ps1 calls a 50 percent reading UNKNOWN overall, while 99 is
    CRITICAL, which outranks that refusal."""
    root = tmp_path / "config-root"
    root.mkdir()
    # The pin alone names the root: usage.ps1 reads the home directory only when it is unset.
    env = {"CLAUDE_CONFIG_DIR": str(root)}
    payload = {
        "session_id": "fixture",
        "rate_limits": {
            "five_hour": {"used_percentage": pct, "resets_at": int(ago().timestamp()) + 4800},
            "seven_day": {"used_percentage": 10, "resets_at": int(ago().timestamp()) + 200000},
        },
    }
    collect = sb.run(
        COORD / "usage-collect.ps1",
        "-StateDir",
        str(root / "mefor-usage"),
        stdin=json.dumps(payload),
        **env,
    )
    assert collect.returncode == 0, collect.stderr
    seed_vault(sb, calibrated("manager"))
    real = sb.repo / "scripts" / "coord" / "usage.ps1"
    code, doc = gate(sb, "-UsageScript", str(real), item="1", **env)
    assert code == expected, why(doc)


# --- the reversal budget (plan 4.5) and the item rule ----------------------------------------


def test_two_reversals_of_a_seats_decisions_close_that_seat_only(sb: Sandbox) -> None:
    """Charged to the seat of the DECISION, not to the lander that logged the outcome."""
    mine = [rec(at=ago(days=20), seat="manager", item=f"x{i}") for i in range(2)]
    seed_vault(sb, calibrated("manager") + calibrated("builder") + calibrated("lander") + mine)
    seed_vault(sb, [reversal(mine[0], ago(hours=3)), reversal(mine[1], ago(hours=2))])
    code, doc = gate(sb)
    assert code == REVIEW and "two reversals of manager's decisions" in why(doc)
    assert gate(sb, seat="builder")[0] == NO_REVIEW
    assert gate(sb, seat="lander")[0] == NO_REVIEW, "the outcome's own seat was charged"


def test_a_reversal_logged_twice_counts_once(sb: Sandbox) -> None:
    mine = rec(at=ago(days=20), seat="manager", item="x")
    seed_vault(sb, [*calibrated("manager"), mine])
    seed_vault(sb, [reversal(mine, ago(hours=3)), reversal(mine, ago(hours=2), by="watchdog")])
    code, doc = gate(sb)
    assert code == NO_REVIEW, why(doc)


def test_a_future_dated_reversal_counts_as_now(sb: Sandbox) -> None:
    """A clock running ahead wrote the second id; dropping it would leave the budget open."""
    mine = [rec(at=ago(days=20), seat="manager", item=f"x{i}") for i in range(2)]
    seed_vault(sb, calibrated("manager") + mine)
    seed_vault(sb, [reversal(mine[0], ago(hours=3)), reversal(mine[1], ago(hours=-2))])
    code, doc = gate(sb)
    assert code == REVIEW and "two reversals of manager's decisions" in why(doc), why(doc)


def test_three_reversals_fleet_wide_close_every_seat(sb: Sandbox) -> None:
    others = [rec(at=ago(days=20), seat=s, item="x") for s in ("a", "b", "c")]
    seed_vault(sb, calibrated("manager") + others)
    seed_vault(sb, [reversal(d, ago(hours=5 - i)) for i, d in enumerate(others)])
    code, doc = gate(sb)
    assert code == REVIEW and "three reversals fleet-wide" in why(doc)


def test_the_budget_closes_for_24_hours_from_the_reversal_that_breached_it(sb: Sandbox) -> None:
    """Three inside 20 hours, the third 20 hours ago: closed although only one is in the last 24."""
    others = [rec(at=ago(days=20), seat=s, item="x") for s in ("a", "b", "c")]
    seed_vault(sb, calibrated("manager") + others)
    times = [ago(hours=40), ago(hours=38), ago(hours=20)]
    seed_vault(sb, [reversal(d, t) for d, t in zip(others, times, strict=True)])
    assert gate(sb)[0] == REVIEW


def test_a_breach_older_than_24_hours_has_reopened(sb: Sandbox) -> None:
    mine = [rec(at=ago(days=20), seat="manager", item=f"x{i}") for i in range(2)]
    seed_vault(sb, calibrated("manager") + mine)
    seed_vault(sb, [reversal(mine[0], ago(hours=30)), reversal(mine[1], ago(hours=26))])
    code, doc = gate(sb)
    assert code == NO_REVIEW, why(doc)


def test_a_reversal_corrected_by_a_later_outcome_is_not_one(sb: Sandbox) -> None:
    mine = [rec(at=ago(days=20), seat="manager", item=f"x{i}") for i in range(2)]
    seed_vault(sb, calibrated("manager") + mine)
    seed_vault(sb, [reversal(mine[0], ago(hours=3)), reversal(mine[1], ago(hours=2))])
    fixed = rec("outcome", at=ago(hours=1), seat="lander", ref=mine[0]["id"], outcome="kept")
    seed_vault(sb, [fixed])
    code, doc = gate(sb)
    assert code == NO_REVIEW, why(doc)


def test_an_earlier_reversal_on_the_same_item_reviews(sb: Sandbox) -> None:
    """Any seat's decision on the item, reversed days ago, outside the 24-hour budget."""
    theirs = rec(at=ago(days=6), seat="builder", item="4242")
    seed_vault(sb, [*calibrated("manager"), theirs, reversal(theirs, ago(days=5))])
    code, doc = gate(sb)
    assert code == REVIEW and f"decision {theirs['id']} on item 4242 was reversed" in why(doc)


def test_a_reversal_of_a_decision_the_log_does_not_hold_reviews(sb: Sandbox) -> None:
    ghost = rec(at=ago(days=3), seat="builder", item="")
    seed_vault(sb, [*calibrated("manager"), reversal(ghost, ago(days=2))])
    code, doc = gate(sb)
    assert code == REVIEW and "the log does not hold and names no item" in why(doc)


# --- the chain limit (plan 4.6) --------------------------------------------------------------


@pytest.mark.parametrize(("count", "expected"), [(2, NO_REVIEW), (3, REVIEW)])
def test_the_item_floor_counts_unsampled_class_b_in_24_hours(
    sb: Sandbox, count: int, expected: int
) -> None:
    """No -BuildsOn at all: the floor alone catches a chain nobody declared."""
    recent = [rec(at=ago(hours=1 + i), seat="builder", item="4242") for i in range(count)]
    stale = rec(at=ago(hours=30), seat="builder", item="4242")
    class_c = rec(at=ago(hours=2), seat="builder", item="4242", **{"class": "C"})
    seed_vault(sb, [*calibrated("manager"), *recent, stale, class_c])
    code, doc = gate(sb)
    assert code == expected, why(doc)


def test_a_future_dated_decision_counts_toward_the_floor(sb: Sandbox) -> None:
    """Two in the last hours and one a skewed clock dated just past tomorrow's 00:00 UTC, so it
    sits in tomorrow's issue, which the gate must read as well: depth three."""
    recent = [rec(at=ago(hours=1 + i), seat="builder", item="4242") for i in range(2)]
    midnight = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    ahead = rec(at=midnight + timedelta(days=1, seconds=30), seat="builder", item="4242")
    seed_vault(sb, [*calibrated("manager"), *recent, ahead])
    code, doc = gate(sb)
    assert code == REVIEW and "chain: depth 3" in why(doc), why(doc)


def test_a_halted_decision_does_not_count_toward_the_floor(sb: Sandbox) -> None:
    """The gate answered HALT for it, so it was deferred, not acted on."""
    recent = [rec(at=ago(hours=1 + i), seat="builder", item="4242") for i in range(2)]
    halted = rec(at=ago(minutes=30), seat="builder", item="4242", gate="HALT")
    seed_vault(sb, [*calibrated("manager"), *recent, halted])
    assert gate(sb)[0] == NO_REVIEW


def test_a_rated_decision_does_not_count_toward_the_floor(sb: Sandbox) -> None:
    recent = [rec(at=ago(hours=1 + i), seat="builder", item="4242") for i in range(3)]
    rating = rec("rating", at=ago(minutes=5), seat="owner", ref=recent[0]["id"], rating="agree")
    seed_vault(sb, [*calibrated("manager"), *recent, rating])
    assert gate(sb)[0] == NO_REVIEW


@pytest.mark.parametrize(("rate_one", "expected"), [(False, REVIEW), (True, NO_REVIEW)])
def test_builds_on_walks_the_unsampled_ancestors_on_the_item(
    sb: Sandbox, rate_one: bool, expected: int
) -> None:
    """Three linked decisions two days old, outside the floor's 24 hours, via one other item."""
    a = rec(at=ago(days=2, hours=3), seat="builder", item="4242")
    b = rec(at=ago(days=2, hours=2), seat="builder", item="4242", buildsOn=[a["id"]])
    detour = rec(
        at=ago(days=2, hours=1, minutes=30), seat="builder", item="other", buildsOn=[b["id"]]
    )
    c = rec(at=ago(days=2, hours=1), seat="builder", item="4242", buildsOn=[detour["id"]])
    records = [*calibrated("manager"), a, b, detour, c]
    if rate_one:
        records.append(rec("rating", at=ago(days=1), seat="owner", ref=a["id"], rating="agree"))
    seed_vault(sb, records)
    code, doc = gate(sb, "-BuildsOn", c["id"])
    assert code == expected, why(doc)


def test_a_builds_on_day_outside_the_window_does_not_widen_calibration(sb: Sandbox) -> None:
    """Calibration reads the 60-day window alone, as the digest does, whatever else is read."""
    old = [rec(at=ago(days=80, minutes=i), seat="manager", item="calib") for i in range(60)]
    rated = [
        rec("rating", at=ago(days=80, minutes=-1 - i), seat="owner", ref=d["id"], rating="agree")
        for i, d in enumerate(old)
    ]
    seed_vault(sb, old + rated)
    code, doc = gate(sb, "-BuildsOn", old[0]["id"])
    assert code == REVIEW and "review path, 0/60 samples" in why(doc)


def test_builds_on_a_decision_the_log_does_not_hold_reviews(sb: Sandbox) -> None:
    seed_vault(sb, calibrated("manager"))
    ghost = rec(at=ago(days=1))["id"]
    code, doc = gate(sb, "-BuildsOn", ghost)
    assert code == REVIEW and f"builds on {ghost}" in why(doc)


# --- -Log enforces it ------------------------------------------------------------------------

LOG_B = ("-Log", "-Item", "4242", "-Seat", "manager", "-Recommendation", "go")


def _log(sb: Sandbox, *args: str, klass: str = "B") -> subprocess.CompletedProcess[str]:
    return sb.run(DECISION, *no_host_usage(sb, (*LOG_B, "-Class", klass, *args)))


def _logged(sb: Sandbox) -> list[dict[str, Any]]:
    proc = sb.run(DECISION, "-List", "-Json", "-Item", "4242", "-Days", "2")
    assert proc.returncode == 0, proc.stderr
    rows: list[dict[str, Any]] = json.loads(proc.stdout) if proc.stdout.strip() else []
    return rows


def test_an_unreviewed_class_b_record_is_logged_and_exits_with_the_gate(sb: Sandbox) -> None:
    proc = _log(sb)
    assert proc.returncode == REVIEW, (proc.stdout, proc.stderr)
    lines = proc.stdout.split("\n")
    assert lines[0].startswith("LOGGED ") and lines[0].endswith(" posted")
    assert lines[1] == "GATE REVIEW"
    assert "decision.ps1: gate: calibration:" in proc.stderr
    (row,) = _logged(sb)
    assert row["gate"] == "REVIEW" and row["posted"] is True


def test_logging_a_halted_decision_exits_halt(sb: Sandbox) -> None:
    write_fake_usage(_usage_path(sb), usage(95.0, state="WARN"))
    proc = _log(sb)
    assert proc.returncode == HALT, (proc.stdout, proc.stderr)
    assert [r["gate"] for r in _logged(sb)] == ["HALT"]


def test_a_no_review_record_logs_as_before(sb: Sandbox) -> None:
    seed_vault(sb, calibrated("manager"))
    first = rec(at=ago(minutes=30), item="4242")
    seed_vault(sb, [first])
    proc = _log(sb, "-BuildsOn", first["id"])
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    assert proc.stdout.split("\n")[1] == "GATE NO-REVIEW"
    mine = [r for r in _logged(sb) if r["id"] != first["id"]]
    assert [(r["gate"], r["buildsOn"]) for r in mine] == [("NO-REVIEW", [first["id"]])]


def test_no_post_gates_with_no_network_and_never_answers_no_review(sb: Sandbox) -> None:
    seed_vault(sb, calibrated("manager"))
    sb.set_state(calls=[])
    proc = _log(sb, "-NoPost")
    assert proc.returncode == REVIEW, (proc.stdout, proc.stderr)
    assert "-NoPost reads no network" in proc.stderr
    assert sb.calls == [] and len(sb.spool()) == 1


@pytest.mark.parametrize(
    ("klass", "args"),
    [
        pytest.param("B", ("-Reviewed", "yes", "-ReviewedBy", "a reviewer"), id="reviewed"),
        pytest.param("C", (), id="class-c"),
    ],
)
def test_a_reviewed_or_other_class_record_is_not_gated(
    sb: Sandbox, klass: str, args: tuple[str, ...]
) -> None:
    write_fake_usage(_usage_path(sb), usage(99.0, state="CRITICAL"))
    proc = _log(sb, *args, klass=klass)
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    assert "GATE" not in proc.stdout
    assert [r["gate"] for r in _logged(sb)] == [""]


def _spooled(sb: Sandbox) -> list[dict[str, Any]]:
    return [json.loads(p.read_text(encoding="utf-8")) for p in sb.spool() if p.suffix == ".json"]


def test_the_logged_record_does_not_count_against_its_own_chain_floor(sb: Sandbox) -> None:
    """It is spooled before the gate runs; read back, it would be the third unsampled decision."""
    seed_vault(sb, calibrated("manager"))
    seed_vault(sb, [rec(at=ago(hours=1 + i), seat="builder", item="4242") for i in range(2)])
    proc = _log(sb)
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    assert proc.stdout.split("\n")[1] == "GATE NO-REVIEW"


def test_a_gate_that_crashes_leaves_the_record_spooled(sb: Sandbox) -> None:
    """The usage reader kills decision.ps1 mid-gate; the record was spooled before the gate ran."""
    _usage_path(sb).write_text(
        "$p = (Get-Process -Id $PID).Parent\nStop-Process -Id $p.Id -Force\n$p.WaitForExit()\n",
        encoding="utf-8",
    )
    proc = _log(sb)
    assert proc.returncode not in (0, 4, NO_REVIEW, REVIEW, HALT), (proc.stdout, proc.stderr)
    assert "LOGGED" not in proc.stdout
    (row,) = _spooled(sb)
    assert (row["kind"], row["item"], row["gate"]) == ("decision", "4242", "PENDING")


def test_a_gate_that_hangs_leaves_the_record_spooled(sb: Sandbox, tmp_path: Path) -> None:
    """The usage reader never answers. While the gate waits on it, the record is already spooled,
    and a flusher leaves it there rather than post its PENDING gate for good."""
    started, stop = tmp_path / "usage-started", tmp_path / "usage-stop"
    # The reader blocks until the test releases it, and the gate is told to wait far longer than
    # the test takes, so no check races the default 30-second wait however slow the runner. The
    # reader's own cap only stops an orphan if the test process dies.
    _usage_path(sb).write_text(
        f"Set-Content -LiteralPath '{started}' -Value started\n"
        "$until = (Get-Date).AddSeconds(1800)\n"
        f"while (-not (Test-Path -LiteralPath '{stop}') -and (Get-Date) -lt $until) "
        "{ Start-Sleep -Milliseconds 200 }\n",
        encoding="utf-8",
    )
    proc = subprocess.Popen(
        sb.argv(
            DECISION, *no_host_usage(sb, (*LOG_B, "-Class", "B", "-UsageTimeoutSeconds", "300"))
        ),
        cwd=str(sb.repo),
        env=sb.env(),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 60
        while not started.exists() and time.monotonic() < deadline:
            time.sleep(0.2)
        assert started.exists(), "the stand-in usage reader never started"
        assert proc.poll() is None, "decision.ps1 finished; the gate did not hang"
        (row,) = _spooled(sb)
        assert (row["kind"], row["item"], row["gate"]) == ("decision", "4242", "PENDING")
        flush = sb.run(DECISION, "-Flush")
        # Held, and said so: a flush that posts nothing must not read as one with nothing to post.
        assert "FLUSHED posted=0 failed=0 held=1 skipped=0" in flush.stdout, (
            flush.stdout,
            flush.stderr,
        )
        assert flush.returncode == 0, flush.stderr
        assert [r["id"] for r in _spooled(sb)] == [row["id"]]
        assert proc.poll() is None, "the gate stopped waiting while the test was still checking"
    finally:
        stop.write_text("stop", encoding="utf-8")
        proc.kill()
        proc.wait(timeout=30)


def _halt_after(sb: Sandbox, action: str) -> None:
    """A usage reader that runs ``action`` on the spooled record ``$f`` while the gate waits on
    it, then reads HALT."""
    write_fake_usage(
        _usage_path(sb),
        usage(95.0, state="WARN"),
        prelude=(
            f"$f = Get-ChildItem -LiteralPath '{sb.spool_dir}' -Filter '*.json' "
            f"| Select-Object -First 1\n{action}\n"
        ),
    )


def test_a_record_claimed_before_the_gate_answers_stays_pending(sb: Sandbox) -> None:
    """A flusher claims the record while the gate runs: the answer cannot be written into it, so
    it keeps gate PENDING, which counts toward the floor, and -Log says so."""
    _halt_after(sb, "Rename-Item -LiteralPath $f.FullName -NewName ($f.Name + '.99999.posting')")
    proc = _log(sb)
    assert proc.returncode == HALT, (proc.stdout, proc.stderr)
    assert "could not be rewritten" in proc.stderr and "says gate PENDING" in proc.stderr
    (claim,) = sb.spool()
    assert claim.name.endswith(".json.99999.posting"), sb.spool()
    assert json.loads(claim.read_text(encoding="utf-8"))["gate"] == "PENDING"


def test_a_gate_answer_that_cannot_be_written_down_is_still_reported(sb: Sandbox) -> None:
    """The rewrite's part file cannot be written (a directory holds its name, as a full disk or
    an AV lock would refuse it). The gate has answered, so -Log reports HALT rather than throw,
    and the record keeps gate PENDING."""
    _halt_after(
        sb,
        "$owner = (Get-Process -Id $PID).Parent.Id\n"
        "$null = New-Item -ItemType Directory -Path ($f.FullName + '.' + $owner + '.tmp')",
    )
    proc = _log(sb)
    assert proc.returncode == HALT, (proc.stdout, proc.stderr)
    lines = proc.stdout.split("\n")
    assert lines[0].startswith("LOGGED ") and lines[1] == "GATE HALT", proc.stdout
    assert "its new copy could not be written" in proc.stderr, proc.stderr
    assert "says gate PENDING" in proc.stderr
    (row,) = _spooled(sb)
    assert row["gate"] == "PENDING"


def _spool_write(sb: Sandbox, record: dict[str, Any]) -> Path:
    """A record spooled as decision.ps1 spools it, <id>.json."""
    sb.spool_dir.mkdir(parents=True, exist_ok=True)
    path = sb.spool_dir / f"{record['id']}.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    return path


def test_a_record_a_flusher_posts_during_the_read_still_counts(sb: Sandbox) -> None:
    """Three unsampled Class B decisions on the item are spooled. A concurrent flusher posts the
    third once the gate has listed the vault's issues, then deletes its spool file. Its day had no
    issue at the listing, so the vault read misses it; the spool, read first, still holds it."""
    seed_vault(sb, calibrated("manager"))
    recent = [rec(at=ago(hours=1 + i), seat="builder", item="4242") for i in range(3)]
    paths = [_spool_write(sb, r) for r in recent]
    sb.set_state(
        after_match={"match": "labels=decision-log", "record": recent[2], "remove": str(paths[2])}
    )
    code, doc = gate(sb)
    assert "after_match" not in sb.state, "the stand-in flusher never ran"
    assert not paths[2].exists()
    assert code == REVIEW and "chain: depth 3" in why(doc), why(doc)


def test_an_unreadable_spool_file_fails_the_gate_closed(sb: Sandbox) -> None:
    """It may hold a record the gate must count, so the read is incomplete, as a failed vault
    read is, rather than a quiet drop."""
    seed_vault(sb, calibrated("manager"))
    _spool_write(sb, rec(at=ago(minutes=5), item="4242")).write_text("{not json", encoding="utf-8")
    code, doc = gate(sb)
    assert code == REVIEW and "not fully read" in why(doc), why(doc)
    assert "unreadable spool file" in why(doc)
    listed = sb.run(DECISION, "-List", "-Json", "-Days", "2")
    assert listed.returncode == 4 and "INCOMPLETE" in listed.stderr, listed.stderr


def test_a_pending_record_whose_post_failed_is_not_held_again(sb: Sandbox) -> None:
    """Its gate died 15 minutes ago, so a flush takes it; the post fails, and the claim goes back
    with the claim's fresh write time. The hold reads the id's age, not that stamp, so the next
    flush posts it rather than hold it for another ten minutes."""
    old = rec(at=ago(minutes=15), item="4242", gate="PENDING")
    path = _spool_write(sb, old)
    aged = ago(minutes=15).timestamp()
    os.utime(path, (aged, aged))
    sb.set_state(fail_post=True)
    first = sb.run(DECISION, "-Flush")
    assert "FLUSHED posted=0 failed=1 held=0" in first.stdout, (first.stdout, first.stderr)
    assert path.exists(), "a failed post left the spool"
    sb.set_state(fail_post=False)
    second = sb.run(DECISION, "-Flush")
    assert "FLUSHED posted=1 failed=0 held=0" in second.stdout, (second.stdout, second.stderr)


def test_the_hold_takes_a_fresh_unreadable_file_and_not_a_far_future_one(sb: Sandbox) -> None:
    """A fresh file that cannot be read may be a PENDING record a moment from its answer, so it
    is held. One whose id a clock a day fast minted is not held for a day."""
    _spool_write(sb, rec(at=ago(minutes=1), item="4242")).write_text("{", encoding="utf-8")
    _spool_write(sb, rec(at=ago(hours=-24), item="4242", gate="PENDING"))
    flush = sb.run(DECISION, "-Flush")
    assert "FLUSHED posted=1 failed=0 held=1 skipped=0" in flush.stdout, (
        flush.stdout,
        flush.stderr,
    )


def test_a_spool_file_that_cannot_be_claimed_is_reported(sb: Sandbox) -> None:
    """On Windows another process holds it open; elsewhere the spool refuses the rename. Either
    way it stays spooled, and -Flush names it and exits 4 rather than print a clean nothing."""
    path = _spool_write(sb, rec(at=ago(minutes=30), item="4242"))
    if sys.platform == "win32":
        # Python opens without delete sharing, so the claim's rename meets a sharing violation.
        with path.open("rb"):
            flush = sb.run(DECISION, "-Flush")
    else:
        if os.geteuid() == 0:
            pytest.skip("root renames in a read-only directory; nothing is shown")
        path.parent.chmod(0o555)
        try:
            flush = sb.run(DECISION, "-Flush")
        finally:
            path.parent.chmod(0o755)
    assert flush.returncode == 4, (flush.stdout, flush.stderr)
    assert "FLUSHED posted=0 failed=0 held=0 skipped=1" in flush.stdout, flush.stdout
    assert f"{path.name}: could not be claimed to post" in flush.stderr, flush.stderr
    assert path.exists()


def test_ids_and_days_are_gregorian_under_a_thai_culture() -> None:
    """A Buddhist-era id would read 543 years ahead, past every window the gate counts."""
    script = (
        "[cultureinfo]::CurrentCulture = 'th-TH'; "
        f". '{COORD / '_decisionlog.ps1'}'; "
        "New-DecisionId; Get-DecisionDayRange '2026-10-26' 2; Resolve-DecisionDay ''; "
        "(Get-Date).ToString('yyyy')"
    )
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    minted, *days, today, control = proc.stdout.split()
    if int(control) < 2500:
        pytest.skip("th-TH did not take on this host (invariant globalization?); nothing is shown")
    at = datetime.strptime(minted[1:16], "%Y%m%dT%H%M%S").replace(tzinfo=UTC)
    assert abs(at - datetime.now(UTC)) < timedelta(hours=1), minted
    assert days == ["2026-10-26", "2026-10-25"]
    assert today[:4] == minted[1:5], today


# --- the digest carries the gate's state and the attic ---------------------------------------


def _git(repo: Path, *args: str, stdin: str = "") -> str:
    # The attic snapshot's commit date is its age in the digest; 3 days 2 hours, plus a margin.
    stamp = f"{int(ago(days=3, hours=2, minutes=5).timestamp())} +0000"
    env = {
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.invalid",
        "GIT_AUTHOR_DATE": stamp,
        "GIT_COMMITTER_DATE": stamp,
    }
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        input=stdin,
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
        env={**os.environ, **env},
    )
    return proc.stdout.strip()


def test_the_digest_shows_the_gate_state_and_lists_the_attic_without_pruning(
    sb: Sandbox,
) -> None:
    mine = [rec(at=ago(days=20), seat="manager", item=f"x{i}") for i in range(2)]
    chain = [rec(at=ago(hours=1 + i), seat="builder", item="77") for i in range(3)]
    seed_vault(sb, mine + chain)
    seed_vault(sb, [reversal(mine[0], ago(hours=3)), reversal(mine[1], ago(hours=2))])
    tree = _git(sb.repo, "mktree")
    commit = _git(sb.repo, "commit-tree", tree, "-m", "attic snapshot")
    _git(sb.repo, "update-ref", "refs/attic/2026-10-20-old-tree", commit)
    proc = sb.run(DIGEST, *no_host_usage(sb, ("-Sample", "0")))
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    out = proc.stdout
    gate_part = out[out.index("## Gate state") : out.index("## The attic")]
    assert "fleet-wide: 2 of 3 in the trailing 24 hours; open" in gate_part
    assert "| manager | 2 of 2 in the trailing 24 hours; CLOSED" in gate_part
    assert "| builder | 0 of 2 in the trailing 24 hours; open | no |" in gate_part
    assert "Cost rung, read now on the account this digest ran on: **OK**" in gate_part
    assert "- item 77: 3 unsampled Class B decisions" in gate_part
    attic = out[out.index("## The attic") :]
    assert "`refs/attic/2026-10-20-old-tree`, 3 days 2 hours old" in attic
    assert _git(sb.repo, "for-each-ref", "refs/attic") != "", "the digest pruned the attic"
