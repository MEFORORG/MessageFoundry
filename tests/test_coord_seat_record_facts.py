# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""What a `seat.ps1` record says about its tree, its episode and its roster verdict.

Three defects, one per group below, each of which left a valid-looking record that was wrong:

- BACKLOG #5874: the first dirty path lost a character when its status line began with a space.
- BACKLOG #5875: a claim or allocation was attributed to the wrong episode, or to none.
- BACKLOG #5876: a plain record pass erased the roster verdict a declaration had written.

Every run uses a throwaway repository, and `MEFOR_COORD_ROOT` is removed from the child's
environment, so nothing here can touch a live coordination root.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
COORD = ROOT / "scripts" / "coord"
SEATS = ROOT / "docs" / "roles" / "seats.json"
TIMEOUT = 120

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="seat.ps1 needs pwsh on Windows",
)


def git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=TIMEOUT, check=True
    )
    return proc.stdout


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    (r / "scripts" / "coord").mkdir(parents=True)
    (r / "docs" / "roles").mkdir(parents=True)
    subprocess.run(["git", "init", "-q", "-b", "main", str(r)], check=True, capture_output=True)
    git(r, "config", "user.email", "t@example.invalid")
    git(r, "config", "user.name", "t")
    for name in ("seat.ps1", "mail-key.ps1", "coord-root.ps1"):
        shutil.copy2(COORD / name, r / "scripts" / "coord" / name)
    shutil.copy2(SEATS, r / "docs" / "roles" / "seats.json")
    # Ignored so the copied tooling never shows up in the dirty-path assertions below.
    (r / ".gitignore").write_text("scripts/\ndocs/\n", encoding="utf-8")
    for name in ("alpha.txt", "beta.txt", "gamma.txt"):
        (r / name).write_text("x\n", encoding="utf-8")
    git(r, "add", "-A")
    git(r, "commit", "-qm", "base")
    return r


def seat_script(repo: Path) -> Path:
    return repo / "scripts" / "coord" / "seat.ps1"


def seat(
    repo: Path, *args: str, session: str | None = "record-facts-probe"
) -> subprocess.CompletedProcess[str]:
    """`session=None` writes the shared `nosid` record successive occupants of a tree can share."""
    return run_pwsh(repo, ["-File", str(seat_script(repo)), *args], session)


def run_pwsh(
    repo: Path, pwsh_args: list[str], session: str | None = "record-facts-probe"
) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env.pop("CLAUDE_CODE_SESSION_ID", None)
    if session is not None:
        env["CLAUDE_CODE_SESSION_ID"] = session
    env.pop("MEFOR_COORD_ROOT", None)
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", *pwsh_args],
        cwd=str(repo),
        input="",
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
        env=env,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return proc


def declare(repo: Path, label: str = "builder") -> dict[str, Any]:
    seat(repo, "-Declare", "-Seat", label, "-Goal", "record facts probe")
    return read_record(repo)


def plain_record(repo: Path) -> subprocess.CompletedProcess[str]:
    return seat(repo, "-Record")


def coord_dir(repo: Path) -> Path:
    common = git(repo, "rev-parse", "--path-format=absolute", "--git-common-dir").strip()
    return Path(common) / "mefor-coord"


def record_path(repo: Path) -> Path:
    found = sorted((coord_dir(repo) / "seats").rglob("*.json"))
    assert len(found) == 1, f"expected exactly one record, got {[p.name for p in found]}"
    return found[0]


def read_record(repo: Path) -> dict[str, Any]:
    rec: dict[str, Any] = json.loads(record_path(repo).read_text(encoding="utf-8"))
    return rec


def episode_start(rec: dict[str, Any]) -> datetime:
    return datetime.fromisoformat(str(rec["lifecycleAt"]))


def put_json(path: Path, body: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(body), encoding="utf-8")


# --- BACKLOG #5874 ------------------------------------------------------------------------------


def test_a_first_status_line_beginning_with_a_space_keeps_its_whole_path(repo: Path) -> None:
    (repo / "alpha.txt").write_text("changed\n", encoding="utf-8")
    assert declare(repo)["dirty"]["paths"] == ["alpha.txt"]


def test_a_rename_records_the_new_path_and_counts_once(repo: Path) -> None:
    git(repo, "mv", "beta.txt", "renamed.txt")
    dirty = declare(repo)["dirty"]
    assert dirty["paths"] == ["renamed.txt"]
    assert dirty["count"] == 1
    assert dirty["trackedCount"] == 1


def test_a_path_git_would_quote_is_recorded_as_its_real_name(repo: Path) -> None:
    """A space and a non-ASCII letter: plain porcelain quotes one and octal-escapes the other."""
    name = "café notes.txt"
    (repo / name).write_text("new\n", encoding="utf-8")
    dirty = declare(repo)["dirty"]
    assert dirty["untracked"] == [name]
    assert dirty["untrackedCount"] == 1


def test_tracked_and_untracked_stay_separated(repo: Path) -> None:
    (repo / "alpha.txt").write_text("changed\n", encoding="utf-8")
    (repo / "new.txt").write_text("new\n", encoding="utf-8")
    dirty = declare(repo)["dirty"]
    assert sorted(dirty["paths"]) == ["alpha.txt", "new.txt"]
    assert dirty["untracked"] == ["new.txt"]
    assert dirty["trackedCount"] == 1


def test_a_clean_tree_records_no_dirty_paths(repo: Path) -> None:
    dirty = declare(repo)["dirty"]
    assert dirty["count"] == 0
    assert dirty["paths"] == []


def test_a_failed_status_read_is_not_recorded_as_clean(repo: Path) -> None:
    clean = declare(repo)
    assert clean["dirty"]["statusKnown"] is True  # control: the same field, on a readable tree
    assert clean["stashCovers"] == "nothing-clean"
    (repo / ".git" / "index").write_bytes(b"this is not a git index")
    plain_record(repo)
    after = read_record(repo)
    assert after["writes"] == clean["writes"] + 1
    assert after["dirty"]["statusKnown"] is False
    assert after["dirty"]["count"] is None
    assert after["dirty"]["trackedCount"] is None
    assert after["dirty"]["untrackedCount"] is None
    assert after["dirty"]["paths"] == []
    assert after["dirty"]["untracked"] == []
    assert after["stashCovers"] == "unknown"


# --- BACKLOG #5875 ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("minutes", "expected"), [(20, "this-episode"), (-20, "worktree-inherited")]
)
def test_an_allocation_is_attributed_by_instant_after_a_prior_read(
    repo: Path, minutes: int, expected: str
) -> None:
    """The second pass reads the episode start back through the prior record."""
    rec = declare(repo)
    stamp = episode_start(rec) + timedelta(minutes=minutes)
    # The form alloc.ps1 writes: round-trip with a numeric offset.
    offset = stamp.astimezone(timezone(timedelta(hours=-6))).isoformat()
    put_json(
        coord_dir(repo) / "alloc" / "adr" / "9001.json",
        {"worktree": rec["worktree"], "claimed": offset},
    )
    plain_record(repo)
    allocations = read_record(repo)["allocations"]
    assert [a["attribution"] for a in allocations] == [expected]


@pytest.mark.parametrize(
    ("minutes", "expected"), [(20, "this-episode"), (-20, "worktree-inherited")]
)
def test_a_claim_reads_the_field_claim_ps1_writes(repo: Path, minutes: int, expected: str) -> None:
    rec = declare(repo)
    stamp = episode_start(rec) + timedelta(minutes=minutes)
    put_json(
        coord_dir(repo) / "claims" / "9002.json",
        {"worktree": rec["worktree"], "claimed": stamp.astimezone(UTC).isoformat()},
    )
    plain_record(repo)
    claims = read_record(repo)["claims"]
    assert [c["attribution"] for c in claims] == [expected]
    recorded = datetime.fromisoformat(str(claims[0]["claimedAt"]))
    assert recorded == stamp


@pytest.mark.parametrize("stamp", ["2026-11-22T10:00:00", "11-22-2026"])
def test_a_stamp_with_no_zone_is_unknown_rather_than_guessed(repo: Path, stamp: str) -> None:
    """The second shape ends in `-2026`, which a loose offset pattern reads as a zone."""
    rec = declare(repo)
    put_json(
        coord_dir(repo) / "alloc" / "adr" / "9003.json",
        {"worktree": rec["worktree"], "claimed": stamp},
    )
    plain_record(repo)
    assert [a["attribution"] for a in read_record(repo)["allocations"]] == ["unknown"]


def test_closing_keeps_the_episodes_own_claims_attributed_to_it(repo: Path) -> None:
    rec = declare(repo)
    stamp = episode_start(rec)
    put_json(
        coord_dir(repo) / "claims" / "9004.json",
        {"worktree": rec["worktree"], "claimed": stamp.isoformat()},
    )
    # Past the one-second stamp resolution, so the close time is later than the claim.
    subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Seconds 2"],
        check=True,
        timeout=TIMEOUT,
    )
    seat(repo, "-Close", "-Handback")
    closed = read_record(repo)
    assert closed["lifecycleAt"] != rec["lifecycleAt"]
    assert [c["attribution"] for c in closed["claims"]] == ["this-episode"]
    plain_record(repo)
    assert [c["attribution"] for c in read_record(repo)["claims"]] == ["this-episode"]


def test_a_claim_this_episode_re_took_is_this_episodes(repo: Path) -> None:
    rec = declare(repo)
    start = episode_start(rec)
    put_json(
        coord_dir(repo) / "claims" / "9005.json",
        {
            "worktree": rec["worktree"],
            "claimed": (start - timedelta(days=2)).isoformat(),
            "refreshed": (start + timedelta(minutes=5)).isoformat(),
        },
    )
    plain_record(repo)
    assert [c["attribution"] for c in read_record(repo)["claims"]] == ["this-episode"]


def rewrite_record(repo: Path, *drop: str, **fields: Any) -> None:
    """Set `fields` on the record and remove the keys named in `drop`."""
    rec = read_record(repo)
    rec.update(fields)
    for key in drop:
        rec.pop(key, None)
    put_json(record_path(repo), rec)


@pytest.mark.parametrize(
    "body", ["", "{}", "null", "[]", "42", '"text"', "not json", '[{"worktree": "WT"}]']
)
@pytest.mark.parametrize("kind", ["claims", "alloc"])
def test_one_bad_registry_file_costs_only_that_entry(repo: Path, kind: str, body: str) -> None:
    rec = declare(repo)
    stamp = (episode_start(rec) + timedelta(minutes=5)).isoformat()
    folder = coord_dir(repo) / "claims" if kind == "claims" else coord_dir(repo) / "alloc" / "adr"
    folder.mkdir(parents=True, exist_ok=True)
    wt = str(rec["worktree"]).replace("\\", "/")
    (folder / "8000.json").write_text(body.replace("WT", wt), encoding="utf-8")
    put_json(folder / "9100.json", {"worktree": rec["worktree"], "claimed": stamp})
    plain_record(repo)
    after = read_record(repo)
    assert after["writes"] == rec["writes"] + 1, "the record was not rewritten"
    if kind == "claims":
        assert [c["key"] for c in after["claims"]] == ["9100"]
    else:
        assert [a["number"] for a in after["allocations"]] == ["9100"]


def test_the_episode_start_is_written_in_the_invariant_calendar(repo: Path) -> None:
    """th-TH is day-first and defaults to the Buddhist calendar, 543 years ahead."""
    script = str(seat_script(repo)).replace("'", "''")
    command = (
        "[cultureinfo]::CurrentCulture = [cultureinfo]::GetCultureInfo('th-TH'); "
        f"& '{script}' -Declare -Seat builder -Goal 'culture probe'; exit $LASTEXITCODE"
    )
    run_pwsh(repo, ["-Command", command])
    rec = read_record(repo)
    for field in ("asOf", "lifecycleAt", "episodeStart"):
        written = datetime.fromisoformat(str(rec[field]))
        assert abs(written - datetime.now(UTC)) < timedelta(days=1), f"{field}: {rec[field]}"


def test_a_successor_on_a_shared_nosid_record_is_a_new_episode(repo: Path) -> None:
    seat(repo, "-Declare", "-Seat", "builder", "-Goal", "first occupant", session=None)
    rec = read_record(repo)
    start = episode_start(rec)
    seat(repo, "-Close", "-Handback", session=None)
    rewrite_record(repo, lifecycleAt=(start + timedelta(hours=1)).isoformat())
    for key, minutes in (("9201", 10), ("9202", 120)):
        put_json(
            coord_dir(repo) / "claims" / f"{key}.json",
            {
                "worktree": rec["worktree"],
                "claimed": (start + timedelta(minutes=minutes)).isoformat(),
            },
        )
    seat(repo, "-Record", session=None)
    by_key = {c["key"]: c["attribution"] for c in read_record(repo)["claims"]}
    assert by_key == {"9201": "worktree-inherited", "9202": "this-episode"}


def test_a_named_session_keeps_its_episode_across_its_own_close(repo: Path) -> None:
    """The control for the case above: only the shared record has successive occupants."""
    rec = declare(repo)
    start = episode_start(rec)
    seat(repo, "-Close", "-Handback")
    rewrite_record(repo, lifecycleAt=(start + timedelta(hours=1)).isoformat())
    put_json(
        coord_dir(repo) / "claims" / "9203.json",
        {"worktree": rec["worktree"], "claimed": (start + timedelta(minutes=10)).isoformat()},
    )
    plain_record(repo)
    assert [c["attribution"] for c in read_record(repo)["claims"]] == ["this-episode"]


@pytest.mark.parametrize("state", ["closed", "handed"])
def test_a_close_stamp_is_never_pinned_as_the_episode_start(repo: Path, state: str) -> None:
    """An older writer drops `episodeStart`; on a closed record `lifecycleAt` is the close."""
    rec = declare(repo)
    start = episode_start(rec)
    rewrite_record(
        repo,
        "episodeStart",
        lifecycle=state,
        lifecycleAt=(start + timedelta(hours=1)).isoformat(),
    )
    put_json(
        coord_dir(repo) / "claims" / "9204.json",
        {"worktree": rec["worktree"], "claimed": (start + timedelta(minutes=10)).isoformat()},
    )
    plain_record(repo)
    after = read_record(repo)
    assert after["episodeStart"] is None
    assert [c["attribution"] for c in after["claims"]] == ["unknown"]


def test_an_open_record_with_no_episode_start_still_falls_back(repo: Path) -> None:
    rec = declare(repo)
    rewrite_record(repo, "episodeStart")
    plain_record(repo)
    after = read_record(repo)
    assert datetime.fromisoformat(str(after["episodeStart"])) == episode_start(rec)


@pytest.mark.parametrize(
    "shape",
    [
        {"refreshed": None, "claimed": "GOOD"},
        {"refreshed": "not a stamp", "claimed": "GOOD"},
        {"refreshed": "2026-11-22T10:00:00", "claimed": "GOOD"},
        {"claimed": None, "claimedAt": "GOOD"},
        {"claimed": "not a stamp", "at": "GOOD"},
        {"refreshed": None, "claimed": None, "created": "GOOD"},
    ],
)
@pytest.mark.parametrize(("minutes", "expected"), [(5, "this-episode"), (-5, "worktree-inherited")])
def test_a_claim_falls_through_to_the_next_usable_stamp(
    repo: Path, shape: dict[str, Any], minutes: int, expected: str
) -> None:
    rec = declare(repo)
    good = (episode_start(rec) + timedelta(minutes=minutes)).isoformat()
    body = {k: (good if v == "GOOD" else v) for k, v in shape.items()}
    put_json(coord_dir(repo) / "claims" / "9301.json", {"worktree": rec["worktree"], **body})
    plain_record(repo)
    claims = read_record(repo)["claims"]
    assert [c["attribution"] for c in claims] == [expected]
    assert datetime.fromisoformat(str(claims[0]["claimedAt"])) == datetime.fromisoformat(good)


@pytest.mark.parametrize(
    "shape",
    [{"claimed": None, "allocatedAt": "GOOD"}, {"claimed": "not a stamp", "at": "GOOD"}],
)
def test_an_allocation_falls_through_to_the_next_usable_stamp(
    repo: Path, shape: dict[str, Any]
) -> None:
    rec = declare(repo)
    good = (episode_start(rec) + timedelta(minutes=5)).isoformat()
    body = {k: (good if v == "GOOD" else v) for k, v in shape.items()}
    put_json(coord_dir(repo) / "alloc" / "adr" / "9302.json", {"worktree": rec["worktree"], **body})
    plain_record(repo)
    assert [a["attribution"] for a in read_record(repo)["allocations"]] == ["this-episode"]


# --- BACKLOG #5876 ------------------------------------------------------------------------------


def test_a_plain_pass_keeps_the_declared_roster_resolution(repo: Path) -> None:
    declared = declare(repo, "mgr")
    assert (declared["seatCanonical"], declared["seatRosterVerdict"]) == ("manager", "alias")
    proc = plain_record(repo)
    after = read_record(repo)
    assert (after["seatCanonical"], after["seatRosterVerdict"]) == ("manager", "alias")
    assert proc.stderr.strip() == ""


def test_a_plain_pass_does_not_reprint_a_retired_objection(repo: Path) -> None:
    """The verdict is carried, not re-resolved, so a hook path stays quiet."""
    declared = declare(repo, "console")
    assert declared["seatRosterVerdict"] == "retired"
    proc = plain_record(repo)
    assert read_record(repo)["seatRosterVerdict"] == "retired"
    assert proc.stderr.strip() == ""


def test_a_new_declaration_replaces_the_carried_verdict(repo: Path) -> None:
    declare(repo, "console")
    plain_record(repo)
    after = declare(repo, "manager")
    assert (after["seatCanonical"], after["seatRosterVerdict"]) == ("manager", "live")


def test_a_never_declared_record_still_reads_none(repo: Path) -> None:
    plain_record(repo)
    rec = read_record(repo)
    assert rec["seatCanonical"] is None
    assert rec["seatRosterVerdict"] == "none"


# --- A declaration reopens an ended record --------------------------------------------------------


@pytest.mark.parametrize("handback", [False, True])
@pytest.mark.parametrize("session", ["record-facts-probe", None])
def test_a_declaration_after_a_close_reopens_the_record(
    repo: Path, handback: bool, session: str | None
) -> None:
    """A resumed session declares again; announce-session.ps1 hides any record not `open`."""
    seat(repo, "-Declare", "-Seat", "builder", "-Goal", "first episode", session=session)
    start = episode_start(read_record(repo))
    seat(repo, "-Close", *(["-Handback"] if handback else []), session=session)
    close_at = start + timedelta(hours=1)
    rewrite_record(repo, lifecycleAt=close_at.isoformat())
    ended = read_record(repo)
    assert ended["lifecycle"] == ("handed" if handback else "closed")
    for key, minutes in (("9401", 10), ("9402", 120)):
        put_json(
            coord_dir(repo) / "claims" / f"{key}.json",
            {
                "worktree": ended["worktree"],
                "claimed": (start + timedelta(minutes=minutes)).isoformat(),
            },
        )
    seat(repo, "-Declare", "-Seat", "builder", "-Goal", "resumed", session=session)
    after = read_record(repo)
    assert after["lifecycle"] == "open"
    assert datetime.fromisoformat(str(after["lifecycleAt"])) > start
    by_key = {c["key"]: c["attribution"] for c in after["claims"]}
    if session is None:
        # A shared record's close is the boundary: before it is the last occupant's.
        assert datetime.fromisoformat(str(after["episodeStart"])) == close_at
        assert by_key == {"9401": "worktree-inherited", "9402": "this-episode"}
    else:
        # A named session keeps its episode, and so its own pre-close claims, across the close.
        assert datetime.fromisoformat(str(after["episodeStart"])) == start
        assert by_key == {"9401": "this-episode", "9402": "this-episode"}
    # A later hook pass carries the reopened state forward.
    seat(repo, "-Record", session=session)
    carried = read_record(repo)
    assert (carried["lifecycle"], carried["episodeStart"]) == ("open", after["episodeStart"])


def test_a_plain_pass_on_a_closed_record_leaves_it_closed(repo: Path) -> None:
    """The Stop hook fires on a closing session's last turn; that pass must not reopen it."""
    declare(repo)
    seat(repo, "-Close")
    closed = read_record(repo)
    plain_record(repo)
    after = read_record(repo)
    assert (after["lifecycle"], after["lifecycleAt"]) == ("closed", closed["lifecycleAt"])


@pytest.mark.parametrize("session", ["record-facts-probe", None])
def test_a_reopen_with_no_usable_start_or_close_stamp(repo: Path, session: str | None) -> None:
    seat(repo, "-Declare", "-Seat", "builder", "-Goal", "first", session=session)
    seat(repo, "-Close", session=session)
    rewrite_record(repo, "episodeStart", lifecycleAt="not a stamp")
    seat(repo, "-Declare", "-Seat", "builder", "-Goal", "resumed", session=session)
    after = read_record(repo)
    assert after["lifecycle"] == "open"
    if session is None:
        assert after["episodeStart"] == after["lifecycleAt"]
    else:
        # A named session's own pre-close claims stay unknown, never inherited.
        assert after["episodeStart"] is None


@pytest.mark.parametrize("handback", [False, True])
def test_a_pointer_only_declaration_does_not_reopen(repo: Path, handback: bool) -> None:
    """A handed seat fixing a pointer has not resumed; its successor respawns from HANDED."""
    declare(repo)
    seat(repo, "-Close", *(["-Handback"] if handback else []))
    ended = read_record(repo)
    seat(repo, "-Declare", "-Notes", "pointer fix only")
    after = read_record(repo)
    assert (after["lifecycle"], after["lifecycleAt"]) == (ended["lifecycle"], ended["lifecycleAt"])


def test_a_reopened_unknown_start_stays_unknown_across_later_passes(repo: Path) -> None:
    """The reopen stamp is not when the episode began, so a hook pass must not adopt it."""
    rec = declare(repo)
    start = episode_start(rec)
    seat(repo, "-Close")
    # An older writer's ended record: no start field at all.
    rewrite_record(repo, "episodeStart", lifecycleAt=(start + timedelta(hours=1)).isoformat())
    put_json(
        coord_dir(repo) / "claims" / "9501.json",
        {"worktree": rec["worktree"], "claimed": (start + timedelta(minutes=10)).isoformat()},
    )
    seat(repo, "-Declare", "-Seat", "builder", "-Goal", "resumed")
    plain_record(repo)
    after = read_record(repo)
    assert after["lifecycle"] == "open"
    assert after["episodeStart"] is None
    assert [c["attribution"] for c in after["claims"]] == ["unknown"]
