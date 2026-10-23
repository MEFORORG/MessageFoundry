# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""scripts/coord/decision.ps1: the AFK-autonomy decision log (ADR 0211).

Each test drives the real script against a fake gh (tests/_fake_gh.py) from a sandbox git
repository, so the vault it writes is a JSON file and the spool is the sandbox's own.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from tests._fake_gh import (
    COORD,
    GUARDED_TIMEOUT_S,
    Sandbox,
    id_day,
    make_sandbox,
    utc_day_now,
    utc_day_with_room,
    with_default,
)

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
    # Two days ending the listing's own, unless a test names its window: a record a test logged
    # just before UTC midnight is still in the window when the listing runs just after it.
    proc = sb.run(DECISION, "-List", "-Json", *with_default(args, "-Days", "2"))
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    rows: list[dict[str, Any]] = json.loads(proc.stdout) if proc.stdout.strip() else []
    return rows


def test_log_posts_one_comment_to_the_days_issue_with_the_full_schema(sb: Sandbox) -> None:
    before = utc_day_now()
    proc = sb.run(DECISION, *B_DECISION)
    after = utc_day_now()
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    assert proc.stdout.strip().endswith("posted")
    issues = sb.issues()
    did = _logged_id(proc.stdout)
    assert id_day(did) in {before, after}, "the id is not dated on the UTC day it was logged"
    assert [i["title"] for i in issues] == [f"decision-log {id_day(did)}"]
    assert issues[0]["labels"] == ["decision-log"]
    (body,) = _comments(sb)
    assert body.startswith("<!-- mefor-decision v1 -->")
    rec = _list(sb)[0]
    assert rec["id"] == did
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


@pytest.mark.timeout(GUARDED_TIMEOUT_S)
def test_a_second_record_reuses_the_days_issue_from_the_local_cache(sb: Sandbox) -> None:
    utc_day_with_room()  # both records must land on one day's issue
    assert sb.run(DECISION, *B_DECISION).returncode == 0
    before = len(sb.calls)
    assert sb.run(DECISION, *B_DECISION).returncode == 0
    assert len(sb.issues()) == 1
    assert len(_comments(sb)) == 2
    # One request per record once the day's issue number is cached: the post itself.
    methods = [c[2] if c[1] == "-X" else "GET" for c in sb.calls[before:]]
    assert methods == ["POST"], sb.calls[before:]


@pytest.mark.timeout(GUARDED_TIMEOUT_S)
def test_a_cached_issue_that_is_gone_is_listed_again_on_the_next_flush(sb: Sandbox) -> None:
    day = utc_day_with_room()  # the second record must land on the day the cache names
    assert sb.run(DECISION, *B_DECISION).returncode == 0
    cache = sb.coord / "decisions" / "issues.json"
    cache.write_text(json.dumps({f"MEFORORG/MessageFoundry-vault|{day}": 99}), encoding="utf-8")
    assert sb.run(DECISION, *B_DECISION).returncode == 4
    assert sb.run(DECISION, "-Flush").returncode == 0
    assert len(_comments(sb)) == 2


def test_the_whole_issue_listing_is_read_not_only_its_first_page(sb: Sandbox) -> None:
    """A day behind 100 newer issues is still found: the listing is paginated."""
    assert sb.run(DECISION, *B_DECISION).returncode == 0
    state = sb.state
    store = state["repos"]["MEFORORG/MessageFoundry-vault"]
    for n in range(150):
        store["issues"].append(
            {
                "number": n + 2,
                "title": f"decision-log 2027-{1 + n // 28:02d}-{1 + n % 28:02d}",
                "labels": ["decision-log"],
                "comments": [],
            }
        )
    sb.state_path.write_text(json.dumps(state), encoding="utf-8")
    assert len(_list(sb)) == 1
    listing = next(c for c in sb.calls[::-1] if any("/issues?" in a for a in c))
    assert "--paginate" in listing and "--slurp" in listing


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


@pytest.mark.timeout(GUARDED_TIMEOUT_S)
def test_list_says_incomplete_when_the_vault_cannot_be_read(sb: Sandbox) -> None:
    # The one listing with the default window, today only, so the record must be logged today.
    utc_day_with_room()
    assert sb.run(DECISION, *B_DECISION, "-NoPost").returncode == 0
    sb.set_state(fail=True)
    proc = sb.run(DECISION, "-List")
    assert proc.returncode == 4, (proc.stdout, proc.stderr)
    assert "INCOMPLETE" in proc.stderr
    assert "[spooled, not posted]" in proc.stdout


LOG_NO_SEAT = ("-Log", "-Item", "1", "-Class", "B", "-Recommendation", "x", "-NoPost")
SID = "sess-test-0001"


def _box_keys(sb: Sandbox) -> tuple[str, str]:
    """This sandbox worktree's (host-keyed, legacy path-only) seat box keys, from mail-key.ps1."""
    script = (
        ". ./scripts/coord/mail-key.ps1; . ./scripts/coord/coord-root.ps1; "
        "$wt = (Resolve-Path -LiteralPath (git rev-parse --show-toplevel)).Path; "
        "ConvertTo-BoxKey -Path $wt; ConvertTo-LegacyBoxKey -Path $wt"
    )
    out = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", script],
        cwd=str(sb.repo),
        capture_output=True,
        text=True,
        timeout=GUARDED_TIMEOUT_S,
        check=True,
    ).stdout.split()
    assert len(out) == 2, out
    return out[0], out[1]


def _seat_file(seats: Path, box: str, rec: dict[str, Any] | str, sid: str = SID) -> None:
    (seats / box).mkdir(parents=True, exist_ok=True)
    body = rec if isinstance(rec, str) else json.dumps(rec)
    (seats / box / f"{sid}.json").write_text(body, encoding="utf-8")


def _logged_seat(sb: Sandbox, **extra: str) -> str:
    proc = sb.run(DECISION, *LOG_NO_SEAT, **extra)
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    return str(_list(sb)[0]["seat"])


def test_the_seat_defaults_to_the_sessions_declared_seat(sb: Sandbox) -> None:
    hosted, _ = _box_keys(sb)
    _seat_file(sb.coord / "seats", hosted, {"seat": "builder"})
    assert _logged_seat(sb) == "builder"


def test_the_newer_of_the_two_boxes_names_the_seat(sb: Sandbox) -> None:
    """A session that declared before the host joined the box key keeps a record under the
    path-only key (docs/COORD-SHARED-ROOT.md, step 4). Whichever of this worktree's two records
    was written last names the seat, as seat.ps1 picks its prior.

    Both directions run in ONE sandbox, so the two box names and their listing order are the same
    for both. A lookup that takes whichever box it meets first returns the same box twice and
    fails one direction, whatever order the file system lists them in."""
    hosted, legacy = _box_keys(sb)
    seats = sb.coord / "seats"
    old = {"asOf": "2026-10-20T08:00:00Z", "writes": 9, "seatSource": "declared"}
    new = {"asOf": "2026-10-22T08:00:00Z", "writes": 2, "seatSource": "declared"}
    got: dict[str, str] = {}
    for item, newer in (("101", "hosted"), ("102", "legacy")):
        _seat_file(seats, hosted, {**(new if newer == "hosted" else old), "seat": "hosted-seat"})
        _seat_file(seats, legacy, {**(new if newer == "legacy" else old), "seat": "legacy-seat"})
        args = ("-Log", "-Item", item, "-Class", "B", "-Recommendation", "x", "-NoPost")
        proc = sb.run(DECISION, *args)
        assert proc.returncode == 0, (proc.stdout, proc.stderr)
        got[newer] = next(str(r["seat"]) for r in _list(sb) if str(r["item"]) == item)
    assert got == {"hosted": "hosted-seat", "legacy": "legacy-seat"}


def test_a_declared_seat_beats_a_newer_derived_one(sb: Sandbox) -> None:
    """seat.ps1's rule: declared wins, and a derived seat fills only a vacuum."""
    hosted, legacy = _box_keys(sb)
    seats = sb.coord / "seats"
    old = {"seat": "builder", "seatSource": "declared", "asOf": "2026-10-20T08:00:00Z"}
    new = {"seat": "manager", "seatSource": "derived:caller", "asOf": "2026-10-22T08:00:00Z"}
    _seat_file(seats, legacy, old)
    _seat_file(seats, hosted, new)
    assert _logged_seat(sb) == "builder"


def test_only_this_worktrees_boxes_on_this_host_are_read(sb: Sandbox) -> None:
    """A legacy record stamped by another PC, and the same session id in another worktree's box,
    are not this seat, however new they are."""
    hosted, legacy = _box_keys(sb)
    seats = sb.coord / "seats"
    newest = "2026-10-23T08:00:00Z"
    _seat_file(seats, hosted, {"seat": "manager", "asOf": "2026-10-20T08:00:00Z"})
    _seat_file(seats, legacy, {"seat": "other-pc", "host": "OTHER-PC", "asOf": newest})
    _seat_file(seats, "aaa-elsewhere-0000", {"seat": "elsewhere", "asOf": newest})
    _seat_file(seats, "zzz-elsewhere-ffff", {"seat": "elsewhere", "asOf": newest})
    assert _logged_seat(sb) == "manager"


def test_a_bad_sort_key_does_not_drop_the_seat(sb: Sandbox) -> None:
    hosted, _ = _box_keys(sb)
    _seat_file(sb.coord / "seats", hosted, {"seat": "lander", "asOf": "not a date", "writes": "x"})
    assert _logged_seat(sb) == "lander"


def test_an_unreadable_box_beside_a_readable_one_still_names_the_seat(sb: Sandbox) -> None:
    hosted, legacy = _box_keys(sb)
    seats = sb.coord / "seats"
    _seat_file(seats, hosted, "{not json")
    _seat_file(seats, legacy, {"seat": "builder", "asOf": "2026-10-20T08:00:00Z"})
    assert _logged_seat(sb) == "builder"


def test_an_offsetless_asof_is_read_as_utc(sb: Sandbox) -> None:
    """An asOf with no offset is UTC, never local time. Read as local, 08:00 on a PC behind UTC
    would outrank 09:00Z. This proves nothing on a PC at UTC or ahead of it."""
    hosted, legacy = _box_keys(sb)
    seats = sb.coord / "seats"
    _seat_file(seats, hosted, {"seat": "naive", "asOf": "2026-10-22T08:00:00"})
    _seat_file(seats, legacy, {"seat": "zulu", "asOf": "2026-10-22T09:00:00Z"})
    assert _logged_seat(sb) == "zulu"


@pytest.mark.skipif(os.name != "nt", reason="the shared-root probe is exercised on Windows")
def test_the_seat_is_read_from_the_shared_root_seat_ps1_writes(sb: Sandbox, tmp_path: Path) -> None:
    """seats/ is a shared kind: seat.ps1 writes it on the resolved shared root, so the lookup reads
    it there too, and a stale copy on the local root is not the seat."""
    hosted, _ = _box_keys(sb)
    shared = tmp_path / "shared-root"
    shared.mkdir()
    _seat_file(shared / "seats", hosted, {"seat": "manager", "asOf": "2026-10-20T08:00:00Z"})
    _seat_file(sb.coord / "seats", hosted, {"seat": "stale-local", "asOf": "2026-10-22T08:00:00Z"})
    proc = sb.run(DECISION, *LOG_NO_SEAT, MEFOR_COORD_ROOT=str(shared))
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    assert _list(sb)[0]["seat"] == "manager"


def test_the_seat_file_is_found_by_seat_ps1s_session_key(sb: Sandbox) -> None:
    """seat.ps1 names the file by a sanitised key, so an id holding `:` is found under `-`."""
    hosted, _ = _box_keys(sb)
    _seat_file(sb.coord / "seats", hosted, {"seat": "lander"}, sid="local-a.b-c")
    assert _logged_seat(sb, CLAUDE_CODE_SESSION_ID="local:a.b-c") == "lander"


def test_an_empty_record_skips_only_itself(sb: Sandbox) -> None:
    """`{}` parses to an object with no properties. Under StrictMode it once threw outside the
    per-record guard, so the valid record in the other box lost its seat too. Both directions run,
    so whichever box is read first holds the empty record once."""
    hosted, legacy = _box_keys(sb)
    seats = sb.coord / "seats"
    got: dict[str, str] = {}
    for item, empty in (("201", hosted), ("202", legacy)):
        valid = legacy if empty == hosted else hosted
        _seat_file(seats, empty, "{}")
        _seat_file(seats, valid, {"seat": f"valid-{item}", "asOf": "2026-10-20T08:00:00Z"})
        args = ("-Log", "-Item", item, "-Class", "B", "-Recommendation", "x", "-NoPost")
        proc = sb.run(DECISION, *args)
        assert proc.returncode == 0, (proc.stdout, proc.stderr)
        got[item] = next(str(r["seat"]) for r in _list(sb) if str(r["item"]) == item)
    assert got == {"201": "valid-201", "202": "valid-202"}


def test_an_unreadable_record_names_no_seat_rather_than_the_older_one(sb: Sandbox) -> None:
    """A record that exists but cannot be READ might be the newer one, so the older box's record
    is not the seat. A directory where the file should be is an unreadable record on every OS."""
    hosted, legacy = _box_keys(sb)
    seats = sb.coord / "seats"
    (seats / hosted / f"{SID}.json").mkdir(parents=True)
    _seat_file(seats, legacy, {"seat": "older", "asOf": "2026-10-20T08:00:00Z"})
    proc = sb.run(DECISION, "-Log", "-Kind", "tripwire", "-Note", "x", "-NoPost")
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    assert _list(sb)[0]["seat"] == ""


def test_a_host_keyed_record_naming_another_host_is_skipped(sb: Sandbox) -> None:
    """The host-keyed box is judged by its `host` too, as lane.ps1 refuses a record at its own key
    that names another machine: a copied or hand-made file is not this seat, however new."""
    hosted, legacy = _box_keys(sb)
    seats = sb.coord / "seats"
    _seat_file(
        seats, hosted, {"seat": "other-pc", "host": "OTHER-PC", "asOf": "2026-10-23T08:00:00Z"}
    )
    _seat_file(seats, legacy, {"seat": "manager", "asOf": "2026-10-20T08:00:00Z"})
    assert _logged_seat(sb) == "manager"


# TEST-NET-1 (RFC 5737): no host answers there, so a probe of it times out or fails.
UNREACHABLE_ROOT = r"\\192.0.2.1\coord"


def test_no_post_never_probes_or_reads_a_network_root(sb: Sandbox) -> None:
    """-NoPost is the tripwire hook's path, and its header promises no network. The probe writes
    coord-root-down.json when the root does not answer, so that file is the instrument. The
    control, a -Log without -NoPost, shows the instrument sees a probe."""
    down = sb.coord / "coord-root-down.json"
    tripwire = ("-Log", "-Kind", "tripwire", "-Note", "x")
    proc = sb.run(DECISION, *tripwire, "-NoPost", MEFOR_COORD_ROOT=UNREACHABLE_ROOT)
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    assert not down.exists(), "-NoPost probed the shared root"
    assert _list(sb)[0]["seat"] == ""
    control = sb.run(DECISION, *tripwire, MEFOR_COORD_ROOT=UNREACHABLE_ROOT)
    assert control.returncode == 0, (control.stdout, control.stderr)
    assert down.exists(), "the control did not probe, so the instrument proves nothing"


def test_the_sandbox_does_not_pass_the_coord_root_or_agent_through(
    sb: Sandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A real MEFOR_COORD_ROOT would send a seat test to a real share, and KORUS_AGENT=codex would
    flip it to the Codex box."""
    monkeypatch.setenv("MEFOR_COORD_ROOT", UNREACHABLE_ROOT)
    monkeypatch.setenv("KORUS_AGENT", "codex")
    env = sb.env()
    assert "MEFOR_COORD_ROOT" not in env and "KORUS_AGENT" not in env
    assert sb.env(KORUS_AGENT="codex")["KORUS_AGENT"] == "codex", "an explicit value is kept"


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
