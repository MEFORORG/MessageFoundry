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
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from tests._fake_gh import COORD, VAULT, Sandbox, make_sandbox

DIGEST = COORD / "digest.ps1"
DECISION = COORD / "decision.ps1"
MARKER = "<!-- mefor-decision v1 -->"
TODAY = datetime.now(UTC).strftime("%Y-%m-%d")

pytestmark = pytest.mark.skipif(shutil.which("pwsh") is None, reason="pwsh not on PATH")


@pytest.fixture
def sb(tmp_path: Path) -> Sandbox:
    s = make_sandbox(tmp_path)
    s.set_state(variables={"MEFOR_AFK_KILL": "off"})
    return s


_SEQ = [0]


def rec(kind: str = "decision", day: str = TODAY, **fields: Any) -> dict[str, Any]:
    _SEQ[0] += 1
    n = _SEQ[0]
    base: dict[str, Any] = {
        "v": 1,
        "id": f"d{day.replace('-', '')}T1200{n % 100000:05d}-{n % 0xFFFFFF:06x}",
        "ts": f"{day}T12:00:00.{n % 1000:03d}Z",
        "kind": kind,
        "item": "",
        "seat": "manager",
        "session": "s1",
        "class": "B",
        "predicates": [],
        "recommendation": "",
        "alternatives": [],
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


def seed(sb: Sandbox, records: list[dict[str, Any]]) -> None:
    state = sb.state
    store = state.setdefault("repos", {}).setdefault(VAULT, {"issues": [], "labels": []})
    for r in records:
        day = f"{r['id'][1:5]}-{r['id'][5:7]}-{r['id'][7:9]}"
        title = f"decision-log {day}"
        issue = next((i for i in store["issues"] if i["title"] == title), None)
        if issue is None:
            issue = {
                "number": len(store["issues"]) + 1,
                "title": title,
                "labels": ["decision-log"],
                "comments": [],
            }
            store["issues"].append(issue)
        body = f"{MARKER}\nheader\n\n```json\n{json.dumps(r, indent=2)}\n```"
        issue["comments"].append({"id": len(issue["comments"]) + 1, "body": body})
    sb.state_path.write_text(json.dumps(state), encoding="utf-8")


def digest(sb: Sandbox, *args: str, code: int = 0) -> str:
    proc = sb.run(DIGEST, *args)
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
    seed(
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
    seed(sb, [sampled])
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


def test_a_saved_draw_is_reused_and_sample_n_draws_afresh(sb: Sandbox) -> None:
    seed(sb, [rec(item=str(i), recommendation=f"r{i}") for i in range(8)])
    first = digest(sb, "-Sample", "3")
    picked = json.loads((sb.coord / "digests" / f"{TODAY}.sample.json").read_text("utf-8"))
    assert len(picked) == 3
    again = digest(sb)
    assert json.loads((sb.coord / "digests" / f"{TODAY}.sample.json").read_text("utf-8")) == picked
    assert first.count("### `d") == again.count("### `d") == 3


def test_the_default_draw_is_five_or_ten_percent(sb: Sandbox) -> None:
    seed(sb, [rec(item=str(i), recommendation=f"r{i}") for i in range(60)])
    assert digest(sb).count("### `d") == 6


@pytest.mark.parametrize("pick_recommended", [True, False])
def test_rate_by_option_number_compares_with_the_hidden_recommendation(
    sb: Sandbox, pick_recommended: bool
) -> None:
    r = rec(item="5", recommendation="yes", alternatives=["no", "later"])
    seed(sb, [r])
    order = blind_order(r)
    n = order.index("yes") + 1 if pick_recommended else order.index("no") + 1
    proc = sb.run(DIGEST, "-Rate", r["id"], str(n))
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    (rating,) = ratings(sb)
    assert rating["ref"] == r["id"] and rating["seat"] == "owner"
    assert rating["rating"] == ("agree" if pick_recommended else "disagree")
    assert f"picked option {n}" in rating["note"]


def test_rate_takes_agree_or_disagree_and_drops_a_rated_decision_from_the_pool(
    sb: Sandbox,
) -> None:
    r = rec(item="5", recommendation="yes", alternatives=["no"])
    seed(sb, [r])
    assert sb.run(DIGEST, "-Rate", r["id"], "disagree").returncode == 0
    assert [x["rating"] for x in ratings(sb)] == ["disagree"]
    assert "No unrated Class B decision today." in digest(sb, "-Sample", "5")


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
    seed(sb, [r])
    proc = sb.run(DIGEST, "-Rate", r["id"], verdict)
    assert proc.returncode == code, (proc.stdout, proc.stderr)
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


@pytest.mark.parametrize(("disagree", "status"), [(3, "calibrated"), (4, "BREACH: review path")])
def test_sixty_rated_samples_calibrate_at_three_disagreements_or_fewer(
    sb: Sandbox, disagree: int, status: str
) -> None:
    day = datetime.now(UTC) - timedelta(days=20)
    decided = [
        rec(day=(day + timedelta(days=i % 20)).strftime("%Y-%m-%d"), recommendation="r")
        for i in range(60)
    ]
    rated = [
        rec("rating", seat="owner", ref=d["id"], rating="disagree" if i < disagree else "agree")
        for i, d in enumerate(decided)
    ]
    seed(sb, decided + rated)
    cells = _calibration_row(digest(sb, "-Sample", "0"), "manager", "B")
    assert cells[2:5] == ["60", str(disagree), status]


def test_under_sixty_samples_stay_on_the_review_path(sb: Sandbox) -> None:
    decided = [rec(recommendation="r") for _ in range(10)]
    seed(sb, decided + [rec("rating", seat="owner", ref=d["id"], rating="agree") for d in decided])
    cells = _calibration_row(digest(sb, "-Sample", "0"), "manager", "B")
    assert cells[4] == "review path, 10/60 samples"


def test_the_fourteen_day_reversal_rate_breaches_above_five_percent(sb: Sandbox) -> None:
    old = (datetime.now(UTC) - timedelta(days=30)).strftime("%Y-%m-%d")
    recent = [rec(seat="lander", recommendation="r") for _ in range(10)]
    stale = [rec(day=old, seat="lander", recommendation="r") for _ in range(10)]
    reversed_ = [
        rec("outcome", seat="lander", ref=d["id"], outcome="reversed", note="reverted in PR 9")
        for d in (recent[0], stale[0], stale[1])
    ]
    seed(sb, recent + stale + reversed_)
    out = digest(sb, "-Sample", "0")
    cells = _calibration_row(out, "lander", "B")
    assert cells[5:8] == ["10", "1", "10.0% BREACH"]
    assert f"reversal of `{recent[0]['id']}`" in out


def test_two_sessions_on_one_item_is_a_collision(sb: Sandbox) -> None:
    seed(
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


def test_an_unread_vault_marks_the_digest_incomplete(sb: Sandbox) -> None:
    seed(sb, [rec(recommendation="r")])
    sb.set_state(fail=True)
    out = digest(sb, code=4)
    assert "INCOMPLETE" in out and "Kill switch: **ON**" in out


def test_end_to_end_a_logged_decision_is_sampled_and_rated(sb: Sandbox) -> None:
    args = ("-Log", "-Item", "7", "-Class", "B", "-Seat", "manager", "-Recommendation", "go")
    logged = sb.run(DECISION, *args, "-Alternative", "stop")
    assert logged.returncode == 0, logged.stderr
    did = logged.stdout.split()[1]
    out = digest(sb, "-Sample", "1")
    assert f"### `{did}`" in out
    assert sb.run(DIGEST, "-Rate", did, "agree").returncode == 0
    assert [r["ref"] for r in ratings(sb)] == [did]
