# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""scripts/coord/digest.ps1: the owner's daily digest, blind sample and calibration (ADR 0211).

The fake vault (tests/_fake_gh.py) is seeded directly with comments in decision.ps1's format, so
a test can hold sixty rated decisions without sixty script launches; the end-to-end test logs
through decision.ps1 itself, which holds the two formats to one.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import pytest

from tests._fake_gh import (
    COORD,
    GUARDED_TIMEOUT_S,
    Sandbox,
    id_day,
    make_sandbox,
    no_host_usage,
    seed_vault,
    utc_day_now,
    utc_day_with_room,
    with_default,
    write_fake_usage,
)

DIGEST = COORD / "digest.ps1"
DECISION = COORD / "decision.ps1"
# A fixed day, which digest() passes as -Day unless a test names its own, so the seeded records
# and the digested day never read the wall clock: a run that crosses UTC midnight would otherwise
# seed one day and have digest.ps1 default to the next. A record decision.ps1 mints itself, a
# -Rate rating included, is still dated by the wall clock, and lands in that day's issue; a test
# that digests one names its day from utc_day_with_room().
TODAY_DATE = date(2026, 6, 15)
TODAY = TODAY_DATE.isoformat()


def days_before(n: int) -> str:
    return (TODAY_DATE - timedelta(days=n)).isoformat()


pytestmark = pytest.mark.skipif(shutil.which("pwsh") is None, reason="pwsh not on PATH")


@pytest.fixture
def sb(tmp_path: Path) -> Sandbox:
    s = make_sandbox(tmp_path)
    s.set_state(variables={"MEFOR_AFK_KILL": "off"})
    # The cost rung reads this, never the host account's own usage files.
    write_fake_usage(tmp_path / "usage.ps1", {"state": "UNKNOWN", "reason": "test"}, code=20)
    return s


_SEQ = [0]


def rec(kind: str = "decision", day: str = TODAY, **fields: Any) -> dict[str, Any]:
    _SEQ[0] += 1
    n = _SEQ[0]
    base: dict[str, Any] = {
        "v": 1,
        "id": f"d{day.replace('-', '')}T1200{n % 100000:05d}-{n % 0xFFFFFF:06x}",
        "ts": f"{day}T12:00:00.{n:07d}Z",
        "kind": kind,
        "item": "",
        "seat": "manager",
        "session": "s1",
        "class": "B",
        "predicates": [],
        "recommendation": "",
        "alternatives": ["the other way"],
        "undo": "",
        "confidence": None,
        "reviewed": "no",
        "reviewedBy": "",
        "outcome": "pending",
        "ref": "",
        "rating": "",
        "note": "",
    }
    base.update(fields)
    return base


def digest(sb: Sandbox, *args: str, code: int = 0) -> str:
    proc = sb.run(DIGEST, *no_host_usage(sb, with_default(args, "-Day", TODAY)))
    assert proc.returncode == code, (proc.stdout, proc.stderr)
    return proc.stdout


def blind_order(r: dict[str, Any]) -> list[str]:
    opts = list(dict.fromkeys([r["recommendation"], *r["alternatives"]]))

    def key(o: str) -> str:
        return hashlib.sha256(f"{r['id']}|{o}".encode()).hexdigest().upper()

    return sorted(opts, key=key)


def ratings(sb: Sandbox) -> list[dict[str, Any]]:
    out = []
    for issue in sb.issues():
        for c in issue["comments"]:
            body = c["body"]
            r = json.loads(body[body.index("```json") + 7 : body.rindex("```")])
            if r["kind"] == "rating":
                out.append(r)
    return out


def test_the_digest_has_every_section_and_is_written_privately(sb: Sandbox) -> None:
    seed_vault(
        sb,
        [
            rec(item="1", **{"class": "A"}),
            rec(item="2", recommendation="do b"),
            rec(item="3", **{"class": "C"}, recommendation="sign it?", alternatives=["wait"]),
            rec(item="4", **{"class": "D"}, recommendation="pwsh -File x.ps1 -Fix"),
            rec("tripwire", note="Bash command carried: git reset --hard", **{"class": "C"}),
        ],
    )
    out = digest(sb, "-Sample", "0")
    for heading in (
        "## Decisions by class",
        "## Your blind sample",
        "## Reversals and tripwire hits",
        "## Class C questions for you, bundled",
        "## Spend",
        "## Collisions",
        "## Class D commands",
        "## Calibration, per seat and class",
    ):
        assert heading in out, heading
    assert "Kill switch: **OFF**" in out
    assert "| B | 1 |" in out and "| C | 1 |" in out and "| D | 1 |" in out
    assert "recommends **sign it?**" in out and "alternatives: wait" in out
    assert "`pwsh -File x.ps1 -Fix`" in out
    assert "git reset --hard" in out
    assert "Designed, not built." in out
    written = sb.coord / "digests" / f"{TODAY}.md"
    assert written.is_file() and f"WROTE {written}" in out


def test_the_blind_sample_hides_the_recommendation(sb: Sandbox) -> None:
    sampled = rec(
        item="9",
        recommendation="merge the two rows",
        alternatives=["keep them apart", "file a third row"],
        confidence=90,
        undo="split them again",
        predicates=[{"name": "live", "evidence": "read the ledger"}],
    )
    seed_vault(sb, [sampled])
    out = digest(sb, "-Sample", "1")
    section = out[out.index("## Your blind sample") : out.index("## Reversals")]
    shown = [ln.split(". ", 1)[1] for ln in section.splitlines() if ln[:2] in {"1.", "2.", "3."}]
    assert shown == blind_order(sampled)
    assert (
        "Recommended" not in out and "split them again" not in out and "confidence" not in section
    )
    assert "checked live: read the ledger" in section
    listing = out[out.index("## Decisions by class") : out.index("## Your blind sample")]
    assert "merge the two rows" not in listing and "(in your blind sample below)" in listing


def _drawn(sb: Sandbox) -> list[str]:
    drawn: list[str] = json.loads(
        (sb.coord / "digests" / f"{TODAY}.sample.json").read_text("utf-8")
    )
    return drawn


def test_a_saved_draw_is_kept_and_topped_up_never_redrawn(sb: Sandbox) -> None:
    seed_vault(sb, [rec(item=str(i), recommendation=f"r{i}") for i in range(8)])
    first = digest(sb, "-Sample", "3")
    picked = _drawn(sb)
    assert len(picked) == 3 and first.count("### `d") == 3
    assert digest(sb, "-Sample", "3").count("### `d") == 3 and _drawn(sb) == picked
    again = digest(sb)
    assert _drawn(sb)[:3] == picked and len(_drawn(sb)) == 5
    assert again.count("### `d") == 5


def test_an_early_empty_draw_does_not_freeze_the_days_sample(sb: Sandbox) -> None:
    """A digest run before any Class B decision is logged must not leave the day unsampled."""
    digest(sb)
    assert _drawn(sb) == []
    seed_vault(sb, [rec(item=str(i), recommendation=f"r{i}") for i in range(4)])
    assert digest(sb).count("### `d") == 4


def test_the_default_draw_is_five_or_ten_percent(sb: Sandbox) -> None:
    seed_vault(sb, [rec(item=str(i), recommendation=f"r{i}") for i in range(60)])
    assert digest(sb).count("### `d") == 6


@pytest.mark.parametrize("pick_recommended", [True, False])
def test_rate_by_option_number_compares_with_the_hidden_recommendation(
    sb: Sandbox, pick_recommended: bool
) -> None:
    r = rec(item="5", recommendation="yes", alternatives=["no", "later"])
    seed_vault(sb, [r])
    order = blind_order(r)
    n = order.index("yes") + 1 if pick_recommended else order.index("no") + 1
    digest(sb)
    proc = sb.run(DIGEST, "-Rate", r["id"], str(n))
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    (rating,) = ratings(sb)
    assert rating["ref"] == r["id"] and rating["seat"] == "owner"
    assert rating["rating"] == ("agree" if pick_recommended else "disagree")
    assert f"picked option {n}" in rating["note"]


@pytest.mark.timeout(GUARDED_TIMEOUT_S)
def test_rate_takes_agree_or_disagree_and_drops_a_rated_decision_from_the_pool(
    sb: Sandbox,
) -> None:
    # decision.ps1 dates the rating by the wall clock, and a digest reads no rating after its day,
    # so this test's day is the real one, with room left in it for every run below.
    day = utc_day_with_room()
    r = rec(day=day, item="5", recommendation="yes", alternatives=["no"])
    seed_vault(sb, [r])
    digest(sb, "-Day", day)
    assert sb.run(DIGEST, "-Rate", r["id"], "disagree").returncode == 0
    assert [x["rating"] for x in ratings(sb)] == ["disagree"]
    assert "No unrated Class B decision today." in digest(sb, "-Day", day, "-Sample", "5")


@pytest.mark.parametrize(
    ("make", "verdict", "code"),
    [
        pytest.param(lambda: rec(**{"class": "C"}, recommendation="x"), "agree", 2, id="class-c"),
        pytest.param(lambda: rec(recommendation="x"), "maybe", 2, id="bad-verdict"),
        pytest.param(lambda: rec(recommendation="x"), "7", 2, id="no-such-option"),
    ],
)
def test_rate_refuses_what_it_cannot_record(
    sb: Sandbox, make: Any, verdict: str, code: int
) -> None:
    r = make()
    seed_vault(sb, [r])
    digest(sb)
    proc = sb.run(DIGEST, "-Rate", r["id"], verdict)
    assert proc.returncode == code, (proc.stdout, proc.stderr)
    assert ratings(sb) == []


def test_rate_refuses_a_decision_that_was_not_drawn_blind(sb: Sandbox) -> None:
    """Its recommendation was in the day's list, so a rating of it is not blind."""
    drawn, seen = rec(recommendation="a"), rec(recommendation="b")
    seed_vault(sb, [drawn])
    digest(sb, "-Sample", "1")
    seed_vault(sb, [seen])
    digest(sb, "-Sample", "1")
    proc = sb.run(DIGEST, "-Rate", seen["id"], "agree")
    assert proc.returncode == 2 and "was not in the" in proc.stderr
    assert ratings(sb) == []


def test_rate_refuses_an_id_that_is_not_in_the_log(sb: Sandbox) -> None:
    proc = sb.run(DIGEST, "-Rate", f"d{TODAY.replace('-', '')}T120000000-abcdef", "agree")
    assert proc.returncode == 2 and "is not in the log" in proc.stderr


def _calibration_row(out: str, seat: str, klass: str) -> list[str]:
    for ln in out.splitlines():
        cells = [c.strip() for c in ln.strip("|").split("|")]
        if cells[:2] == [seat, klass]:
            return cells
    raise AssertionError(f"no calibration row for {seat}/{klass}:\n{out}")


def _rated(count: int, disagree_first: int) -> list[dict[str, Any]]:
    """`count` Class B decisions over the last 20 days, each rated, the oldest ratings disagreeing."""
    decided = [rec(day=days_before(20 - i % 20), recommendation="r") for i in range(count)]
    rated = [
        rec(
            "rating",
            seat="owner",
            ref=d["id"],
            rating="disagree" if i < disagree_first else "agree",
        )
        for i, d in enumerate(decided)
    ]
    return decided + rated


@pytest.mark.parametrize(
    ("disagree", "status"),
    [(3, "calibrated"), (4, "BREACH: review path, 0/60 fresh samples")],
)
def test_sixty_rated_samples_calibrate_at_three_disagreements_or_fewer(
    sb: Sandbox, disagree: int, status: str
) -> None:
    seed_vault(sb, _rated(60, disagree))
    cells = _calibration_row(digest(sb, "-Sample", "0"), "manager", "B")
    assert cells[2:5] == ["60", str(disagree), status]


@pytest.mark.parametrize(
    ("count", "status"),
    [(61, "BREACH: review path, 1/60 fresh samples"), (120, "calibrated")],
)
def test_after_a_breach_sixty_fresh_samples_must_pass(sb: Sandbox, count: int, status: str) -> None:
    """One agreement that pushes the fourth disagreement out of the window is not 60 fresh."""
    seed_vault(sb, _rated(count, 4))
    cells = _calibration_row(digest(sb, "-Sample", "0", "-Window", "60"), "manager", "B")
    assert cells[4] == status


def test_under_sixty_samples_stay_on_the_review_path(sb: Sandbox) -> None:
    decided = [rec(recommendation="r") for _ in range(10)]
    seed_vault(
        sb, decided + [rec("rating", seat="owner", ref=d["id"], rating="agree") for d in decided]
    )
    cells = _calibration_row(digest(sb, "-Sample", "0"), "manager", "B")
    assert cells[4] == "review path, 10/60 samples"


def test_the_fourteen_day_reversal_rate_breaches_above_five_percent(sb: Sandbox) -> None:
    old = days_before(30)
    recent = [rec(seat="lander", recommendation="r") for _ in range(10)]
    stale = [rec(day=old, seat="lander", recommendation="r") for _ in range(10)]
    reversed_ = [
        rec("outcome", seat="lander", ref=d["id"], outcome="reversed", note="reverted in PR 9")
        for d in (recent[0], stale[0], stale[1])
    ]
    seed_vault(sb, recent + stale + reversed_)
    out = digest(sb, "-Sample", "0")
    cells = _calibration_row(out, "lander", "B")
    assert cells[5:8] == ["10", "1", "10.0% BREACH"]
    assert f"reversal of `{recent[0]['id']}`" in out


def test_two_sessions_on_one_item_is_a_collision(sb: Sandbox) -> None:
    seed_vault(
        sb,
        [
            rec(item="42", session="s1", recommendation="a"),
            rec(item="42", session="s2", seat="builder", recommendation="b"),
            rec(item="43", session="s1", recommendation="c"),
        ],
    )
    out = digest(sb, "-Sample", "0")
    section = out[out.index("## Collisions") : out.index("## Class D")]
    assert "item 42" in section and "item 43" not in section


def test_a_decision_with_one_option_is_never_drawn(sb: Sandbox) -> None:
    """Its only option would be the recommendation, so a rating of it could not be blind."""
    seed_vault(
        sb, [rec(recommendation="go", alternatives=[]), rec(recommendation="x", alternatives=["x"])]
    )
    assert "No unrated Class B decision today." in digest(sb)


def test_a_reversal_of_an_earlier_days_unrated_sample_stays_hidden(sb: Sandbox) -> None:
    yesterday = days_before(1)
    drawn = rec(day=yesterday, recommendation="a")
    seed_vault(sb, [drawn])
    digest(sb, "-Day", yesterday)
    seed_vault(
        sb, [rec("outcome", seat="lander", ref=drawn["id"], outcome="reversed", note="PR 9")]
    )
    out = digest(sb)
    assert "shown once you rate it" in out and drawn["id"] not in out


def test_with_no_day_the_digest_is_for_the_utc_day_it_runs(sb: Sandbox) -> None:
    """Read either side of the run, so a run that crosses UTC midnight still passes."""
    before = utc_day_now()
    proc = sb.run(DIGEST, *no_host_usage(sb, ("-Sample", "0")))
    after = utc_day_now()
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    (day,) = [d for d in {before, after} if f"# AFK-autonomy digest, {d} (UTC)" in proc.stdout]
    assert (sb.coord / "digests" / f"{day}.md").is_file()


def test_an_impossible_day_is_refused(sb: Sandbox) -> None:
    proc = sb.run(DIGEST, "-Day", "2026-02-30")
    assert proc.returncode == 2 and "real date" in proc.stderr


def test_an_unread_vault_marks_the_digest_incomplete(sb: Sandbox) -> None:
    seed_vault(sb, [rec(recommendation="r")])
    sb.set_state(fail=True)
    out = digest(sb, code=4)
    assert "INCOMPLETE" in out and "Kill switch: **ON**" in out


@pytest.mark.timeout(GUARDED_TIMEOUT_S)
def test_end_to_end_a_logged_decision_is_sampled_and_rated(sb: Sandbox) -> None:
    """The owner's flow: log now, run the digest with no -Day, rate what it drew."""
    day = utc_day_with_room()
    args = ("-Log", "-Item", "7", "-Class", "B", "-Seat", "manager", "-Recommendation", "go")
    logged = sb.run(DECISION, *no_host_usage(sb, (*args, "-Alternative", "stop")))
    # Unreviewed and uncalibrated: the gate answers REVIEW (11), and the record is still logged.
    assert logged.returncode == 11, logged.stderr
    did = logged.stdout.split()[1]
    assert id_day(did) == day, "the id is not dated on the UTC day it was logged"
    proc = sb.run(DIGEST, *no_host_usage(sb, ("-Sample", "1")))
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    assert f"### `{did}`" in proc.stdout
    assert sb.run(DIGEST, "-Rate", did, "agree").returncode == 0
    assert [r["ref"] for r in ratings(sb)] == [did]
