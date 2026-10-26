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

NOW = datetime.now(UTC)
_SEQ = itertools.count(1)


def ago(**delta: float) -> datetime:
    return NOW - timedelta(**delta)


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
            "five_hour": {"used_percentage": pct, "resets_at": int(NOW.timestamp()) + 4800},
            "seven_day": {"used_percentage": 10, "resets_at": int(NOW.timestamp()) + 200000},
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


# --- the digest carries the gate's state and the attic ---------------------------------------


def _git(repo: Path, *args: str, stdin: str = "") -> str:
    # The attic snapshot's commit date is its age in the digest; 3 days 2 hours, plus a margin.
    stamp = f"{int((NOW - timedelta(days=3, hours=2, minutes=5)).timestamp())} +0000"
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
