# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""scripts/coord/decision.ps1: the AFK-autonomy decision log (ADR 0211).

Each test drives the real script against a fake gh (tests/_fake_gh.py) from a sandbox git
repository, so the vault it writes is a JSON file and the spool is the sandbox's own.
"""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from tests._fake_gh import COORD, Sandbox, make_sandbox

DECISION = COORD / "decision.ps1"

pytestmark = pytest.mark.skipif(shutil.which("pwsh") is None, reason="pwsh not on PATH")

B_DECISION = (
    "-Log",
    "-Item",
    "3905",
    "-Class",
    "B",
    "-Seat",
    "manager",
    "-Recommendation",
    "split the fix into two PRs",
    "-Alternative",
    "one PR",
    "-Predicate",
    "live-state=gh pr view 2460 read at 17:02Z\nclaims=claim.ps1 -List shows no other holder",
    "-Undo",
    "close the second PR",
    "-Confidence",
    "80",
)


@pytest.fixture
def sb(tmp_path: Path) -> Sandbox:
    return make_sandbox(tmp_path)


def _comments(sb: Sandbox) -> list[str]:
    return [c["body"] for i in sb.issues() for c in i["comments"]]


def _logged_id(stdout: str) -> str:
    line = next(ln for ln in stdout.splitlines() if ln.startswith("LOGGED "))
    return line.split()[1]


def _list(sb: Sandbox, *args: str) -> list[dict[str, Any]]:
    proc = sb.run(DECISION, "-List", "-Json", *args)
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    rows: list[dict[str, Any]] = json.loads(proc.stdout) if proc.stdout.strip() else []
    return rows


def test_log_posts_one_comment_to_the_days_issue_with_the_full_schema(sb: Sandbox) -> None:
    proc = sb.run(DECISION, *B_DECISION)
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    assert proc.stdout.strip().endswith("posted")
    issues = sb.issues()
    day = datetime.now(UTC).strftime("%Y-%m-%d")
    assert [i["title"] for i in issues] == [f"decision-log {day}"]
    assert issues[0]["labels"] == ["decision-log"]
    (body,) = _comments(sb)
    assert body.startswith("<!-- mefor-decision v1 -->")
    rec = _list(sb)[0]
    assert rec["id"] == _logged_id(proc.stdout)
    assert rec["class"] == "B" and rec["item"] == "3905" and rec["seat"] == "manager"
    assert rec["predicates"] == [
        {"name": "live-state", "evidence": "gh pr view 2460 read at 17:02Z"},
        {"name": "claims", "evidence": "claim.ps1 -List shows no other holder"},
    ]
    assert rec["alternatives"] == ["one PR"]
    assert rec["undo"] == "close the second PR" and rec["confidence"] == 80
    assert rec["reviewed"] == "no" and rec["outcome"] == "pending"
    assert rec["session"] == "sess-test-0001" and rec["posted"] is True
    assert sb.spool() == [], "a posted record stayed in the spool"


def test_a_second_record_reuses_the_days_issue_from_the_local_cache(sb: Sandbox) -> None:
    assert sb.run(DECISION, *B_DECISION).returncode == 0
    before = len(sb.calls)
    assert sb.run(DECISION, *B_DECISION).returncode == 0
    assert len(sb.issues()) == 1
    assert len(_comments(sb)) == 2
    # One request per record once the day's issue number is cached: the post itself.
    methods = [c[2] if c[1] == "-X" else "GET" for c in sb.calls[before:]]
    assert methods == ["POST"], sb.calls[before:]


def test_a_cached_issue_that_is_gone_is_listed_again_on_the_next_flush(sb: Sandbox) -> None:
    assert sb.run(DECISION, *B_DECISION).returncode == 0
    cache = sb.coord / "decisions" / "issues.json"
    day = datetime.now(UTC).strftime("%Y-%m-%d")
    cache.write_text(json.dumps({f"MEFORORG/MessageFoundry-vault|{day}": 99}), encoding="utf-8")
    assert sb.run(DECISION, *B_DECISION).returncode == 4
    assert sb.run(DECISION, "-Flush").returncode == 0
    assert len(_comments(sb)) == 2


def test_days_older_than_a_full_listing_reaches_are_incomplete(sb: Sandbox) -> None:
    state = sb.state
    issues = [
        {"number": n + 1, "title": f"decision-log 2026-{1 + n // 28:02d}-{1 + n % 28:02d}"}
        for n in range(100)
    ]
    for i in issues:
        i.update(labels=["decision-log"], comments=[])
    state.setdefault("repos", {})["MEFORORG/MessageFoundry-vault"] = {
        "issues": issues,
        "labels": ["decision-log"],
    }
    sb.state_path.write_text(json.dumps(state), encoding="utf-8")
    proc = sb.run(DECISION, "-List", "-Day", "2025-12-31")
    assert proc.returncode == 4 and "reaches back only to 2026-01-01" in proc.stderr


def test_no_post_spools_with_no_network_call_and_flush_posts_it(sb: Sandbox) -> None:
    proc = sb.run(DECISION, *B_DECISION, "-NoPost")
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip().endswith("spooled")
    assert sb.calls == [], "-NoPost called gh"
    assert len(sb.spool()) == 1
    flushed = sb.run(DECISION, "-Flush")
    assert flushed.returncode == 0, flushed.stderr
    assert "posted=1 failed=0" in flushed.stdout
    assert len(_comments(sb)) == 1 and sb.spool() == []


def test_a_failed_post_keeps_the_record_spooled_and_says_so(sb: Sandbox) -> None:
    sb.set_state(fail=True)
    proc = sb.run(DECISION, *B_DECISION)
    assert proc.returncode == 4, (proc.stdout, proc.stderr)
    assert proc.stdout.strip().endswith("spooled")
    assert "NOT POSTED, still spooled" in proc.stderr
    assert len(sb.spool()) == 1
    sb.set_state(fail=False)
    assert sb.run(DECISION, "-Flush").returncode == 0
    assert len(_comments(sb)) == 1


def test_list_merges_the_spool_marks_it_and_filters_by_seat_and_item(sb: Sandbox) -> None:
    assert sb.run(DECISION, *B_DECISION).returncode == 0
    other = ("-Log", "-Item", "77", "-Class", "C", "-Seat", "lander", "-Recommendation", "ask")
    assert sb.run(DECISION, *other, "-NoPost").returncode == 0
    rows = _list(sb)
    assert sorted(r["item"] for r in rows) == ["3905", "77"]
    assert {r["item"]: r["posted"] for r in rows} == {"3905": True, "77": False}
    assert [r["item"] for r in _list(sb, "-Seat", "lander")] == ["77"]
    assert [r["item"] for r in _list(sb, "-Item", "3905")] == ["3905"]
    assert _list(sb, "-Day", "2001-01-01") == []


def test_a_record_posted_twice_lists_once(sb: Sandbox) -> None:
    """A lost response re-posts a record; the reader drops the duplicate by id."""
    assert sb.run(DECISION, *B_DECISION).returncode == 0
    state = sb.state
    issue = state["repos"]["MEFORORG/MessageFoundry-vault"]["issues"][0]
    issue["comments"].append(dict(issue["comments"][0], id=2))
    sb.state_path.write_text(json.dumps(state), encoding="utf-8")
    assert len(_list(sb)) == 1


def test_list_says_incomplete_when_the_vault_cannot_be_read(sb: Sandbox) -> None:
    assert sb.run(DECISION, *B_DECISION, "-NoPost").returncode == 0
    sb.set_state(fail=True)
    proc = sb.run(DECISION, "-List")
    assert proc.returncode == 4, (proc.stdout, proc.stderr)
    assert "INCOMPLETE" in proc.stderr
    assert "[spooled, not posted]" in proc.stdout


def test_the_seat_defaults_to_the_sessions_declared_seat(sb: Sandbox) -> None:
    box = sb.coord / "seats" / "box1"
    box.mkdir(parents=True)
    (box / "sess-test-0001.json").write_text(json.dumps({"seat": "builder"}), encoding="utf-8")
    args = ("-Log", "-Item", "1", "-Class", "B", "-Recommendation", "x", "-NoPost")
    assert sb.run(DECISION, *args).returncode == 0
    assert _list(sb)[0]["seat"] == "builder"


def test_the_seat_file_is_found_by_seat_ps1s_session_key(sb: Sandbox) -> None:
    """seat.ps1 names the file by a sanitised key, so an id holding `:` is found under `-`."""
    box = sb.coord / "seats" / "box1"
    box.mkdir(parents=True)
    (box / "local-a.b-c.json").write_text(json.dumps({"seat": "lander"}), encoding="utf-8")
    args = ("-Log", "-Item", "1", "-Class", "B", "-Recommendation", "x", "-NoPost")
    assert sb.run(DECISION, *args, CLAUDE_CODE_SESSION_ID="local:a.b-c").returncode == 0
    assert _list(sb)[0]["seat"] == "lander"


@pytest.mark.parametrize(
    ("args", "needs"),
    [
        pytest.param(("-Log", "-Class", "B", "-Seat", "m"), "Item, Recommendation", id="decision"),
        pytest.param(("-Log", "-Kind", "rating", "-Ref", "x1"), "", id="bad-ref"),
        pytest.param(("-Log", "-Kind", "outcome"), "Outcome, Ref", id="outcome"),
        pytest.param(("-Log", "-Kind", "tripwire"), "Note", id="tripwire"),
        pytest.param((*B_DECISION, "-Reviewed", "yes"), "", id="reviewed-without-reviewer"),
        pytest.param(
            ("-Log", "-Item", "1", "-Class", "B", "-Seat", "m", "-Recommendation", "x")
            + ("-Predicate", "live=ok\nno-equals"),
            "",
            id="bad-predicate",
        ),
        pytest.param(("-Log", "-List"), "", id="two-modes"),
    ],
)
def test_an_incomplete_record_is_refused_before_anything_is_written(
    sb: Sandbox, args: tuple[str, ...], needs: str
) -> None:
    proc = sb.run(DECISION, *args)
    assert proc.returncode == 2, (proc.stdout, proc.stderr)
    assert needs in proc.stderr
    assert sb.spool() == [] and sb.calls == []


def test_an_outcome_record_refers_to_a_decision(sb: Sandbox) -> None:
    did = _logged_id(sb.run(DECISION, *B_DECISION).stdout)
    args = ("-Log", "-Kind", "outcome", "-Ref", did, "-Outcome", "reversed", "-Seat", "manager")
    assert sb.run(DECISION, *args).returncode == 0
    outcome = next(r for r in _list(sb) if r["kind"] == "outcome")
    assert outcome["ref"] == did and outcome["outcome"] == "reversed"
