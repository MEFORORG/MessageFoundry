# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Seats, mail and handoffs follow the SHARED coordination root; local state stays put.

docs/COORD-SHARED-ROOT.md is the design. These tests point MEFOR_COORD_ROOT at a temp directory and
check four things:

1. the shared kinds this group owns (seats, mail, handoffs) land under the shared root, and the
   local kinds (announce, overlap-cache) do not move;
2. a writer refuses when the shared root does not answer, and a reading hook skips without blocking;
3. every seat record carries ``host``, and a record from another host is never judged by probing a
   path on this disk, while a record with no host still is;
4. ``mail.ps1 -To`` accepts a seat id from the shared registry, for a seat on another PC.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
COORD = ROOT / "scripts" / "coord"
HOOKS = ROOT / "scripts" / "hooks"
TIMEOUT = 90

# TEST-NET-1 (RFC 5737): never routed, so a connect to it can only time out.
DEAD_UNC = r"\\192.0.2.1\nothing\mefor-coord"
OTHER_HOST = "OTHER-PC"
SEAT_ID = "autonomy-plan-62022e2c"

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="the coordination scripts need pwsh on Windows",
)


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=TIMEOUT, check=True
    )
    return proc.stdout.strip()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    r.mkdir()
    for args in (
        ["init", "-q", "-b", "main"],
        ["config", "user.email", "t@example.invalid"],
        ["config", "user.name", "t"],
    ):
        _git(r, *args)
    (r / "f.txt").write_text("x", encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-qm", "base")
    return r


@pytest.fixture
def shared(tmp_path: Path) -> Path:
    s = tmp_path / "shared" / "mefor-coord"
    s.mkdir(parents=True)
    return s


def _local(repo: Path) -> Path:
    return (
        Path(_git(repo, "rev-parse", "--path-format=absolute", "--git-common-dir")) / "mefor-coord"
    )


def _env(root: str | Path | None, **extra: str) -> dict[str, str]:
    env = dict(os.environ)
    env.pop("MEFOR_COORD_ROOT", None)
    env.pop("CLAUDE_CODE_SESSION_ID", None)
    if root is not None:
        env["MEFOR_COORD_ROOT"] = str(root)
    env.update(extra)
    return env


def _ps(
    script: Path, cwd: Path, *args: str, env: dict[str, str], stdin: str | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(script), *args],
        cwd=str(cwd),
        input=stdin if stdin is not None else "",
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
        env=env,
    )


def _plant_record(seats: Path, box: str, rec: dict[str, Any]) -> Path:
    d = seats / box
    d.mkdir(parents=True, exist_ok=True)
    f = d / f"{rec['sessionKey']}.json"
    f.write_text(json.dumps(rec), encoding="utf-8")
    return f


def _record(
    *, box: str, session: str, worktree: str, host: str | None, handoff: str | None = None
) -> dict[str, Any]:
    rec: dict[str, Any] = {
        "schema": 1,
        "asOf": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "lifecycle": "open",
        "boxKey": box,
        "worktree": worktree,
        "sessionId": f"{session}-0000-0000-0000-000000000000",
        "sessionKey": session,
        "seat": "manager",
        "branch": "claude/x",
        "claims": [],
        "allocations": [],
        "handoff": None,
    }
    if host is not None:
        rec["host"] = host
    if handoff is not None:
        rec["handoff"] = {"path": handoff, "bytes": 10, "sha256": None, "pointedAt": rec["asOf"]}
    return rec


# --------------------------------------------------------------------------------------- seats


def test_a_declared_seat_lands_on_the_shared_root_and_carries_its_host(
    repo: Path, shared: Path
) -> None:
    proc = _ps(
        COORD / "seat.ps1",
        repo,
        "-Declare",
        "-Seat",
        "builder",
        "-Goal",
        "g",
        env=_env(shared, CLAUDE_CODE_SESSION_ID="sess-shared"),
    )
    assert proc.returncode == 0, proc.stderr
    recs = list((shared / "seats").rglob("sess-shared.json"))
    assert len(recs) == 1, f"no record under the shared root: {proc.stdout} {proc.stderr}"
    rec = json.loads(recs[0].read_text(encoding="utf-8"))
    assert rec["host"].lower() == os.environ.get("COMPUTERNAME", "").lower()
    # The heartbeat follows the registry, and the local root holds no seat at all.
    assert any((shared / "seats" / ".writer-alive").iterdir())
    assert not (_local(repo) / "seats").exists()


def test_with_nothing_configured_the_record_stays_local(repo: Path) -> None:
    proc = _ps(
        COORD / "seat.ps1",
        repo,
        "-Declare",
        "-Seat",
        "builder",
        "-Goal",
        "g",
        env=_env(None, CLAUDE_CODE_SESSION_ID="sess-local"),
    )
    assert proc.returncode == 0, proc.stderr
    recs = list((_local(repo) / "seats").rglob("sess-local.json"))
    assert len(recs) == 1
    assert json.loads(recs[0].read_text(encoding="utf-8"))["host"]


def test_declare_refuses_when_the_shared_root_does_not_answer(repo: Path) -> None:
    proc = _ps(
        COORD / "seat.ps1",
        repo,
        "-Declare",
        "-Seat",
        "builder",
        "-Goal",
        "g",
        env=_env(DEAD_UNC, CLAUDE_CODE_SESSION_ID="sess-dead"),
    )
    assert proc.returncode == 1
    assert "REFUSED" in proc.stderr and "unreachable" in proc.stderr
    # No fallback: the local root gets no record either.
    assert not list((_local(repo) / "seats").rglob("*.json"))


def test_the_record_hook_exits_zero_and_writes_nothing_when_the_root_is_down(repo: Path) -> None:
    proc = _ps(
        COORD / "seat.ps1",
        repo,
        "-Record",
        env=_env(DEAD_UNC, CLAUDE_CODE_SESSION_ID="sess-dead"),
    )
    assert proc.returncode == 0
    assert "did not resolve" in proc.stderr
    assert not list((_local(repo) / "seats").rglob("*.json"))


def test_clear_handoff_refuses_a_record_from_another_host(repo: Path, shared: Path) -> None:
    missing = str(repo / "gone" / "HANDOFF.md")
    _plant_record(
        shared / "seats",
        SEAT_ID,
        _record(
            box=SEAT_ID,
            session="sess-other",
            worktree=r"D:\t\autonomy-plan",
            host=OTHER_HOST,
            handoff=missing,
        ),
    )
    proc = _ps(
        COORD / "seat.ps1",
        repo,
        "-ClearHandoff",
        "-Box",
        SEAT_ID,
        "-SessionId",
        "sess-other",
        env=_env(shared),
    )
    assert proc.returncode == 1
    assert OTHER_HOST in proc.stderr and "not checkable here" in proc.stderr


# --------------------------------------------------------------------------------------- fleet


def _fleet(repo: Path, shared: Path) -> dict[str, Any]:
    proc = _ps(COORD / "fleet.ps1", repo, "-Json", env=_env(shared))
    # Exit 2 means fenceAvailable=false, which a sandbox may legitimately read.
    assert proc.returncode in (0, 2), proc.stderr
    out: dict[str, Any] = json.loads(proc.stdout)
    return out


def test_fleet_never_judges_another_hosts_record_but_still_judges_a_legacy_one(
    repo: Path, shared: Path
) -> None:
    missing = str(repo / "nowhere" / "H.md")
    seats = shared / "seats"
    _plant_record(
        seats,
        "remote-aaaaaaaa",
        _record(
            box="remote-aaaaaaaa",
            session="sess-r",
            worktree=r"D:\t\remote",
            host=OTHER_HOST,
            handoff=missing,
        ),
    )
    _plant_record(
        seats,
        "legacy-bbbbbbbb",
        _record(
            box="legacy-bbbbbbbb",
            session="sess-l",
            worktree=str(repo / "absent"),
            host=None,
            handoff=missing,
        ),
    )
    j = _fleet(repo, shared)
    rows = {r["Box"]: r for r in j["rows"]}
    remote, legacy = rows["remote-aaaaaaaa"], rows["legacy-bbbbbbbb"]

    assert remote["State"] == f"ON {OTHER_HOST}"
    assert remote["Fence"] == "NOT-CHECKABLE-HERE"
    assert remote["HandoffState"] == "not-checkable-here"
    # The legacy record is this PC's and is judged as before: not running, and its pointer dangles.
    assert legacy["State"] in ("INTERRUPTED", "UNKNOWN-NO-FENCE", "ORPHANED-STALE")
    assert legacy["HandoffState"] == "dangling"

    receipt = j["receipt"]
    assert receipt["seatsDir"].lower() == str(seats).lower()
    assert receipt["recordsOtherHost"] == 1
    assert receipt["handoffPointersOtherHost"] == 1
    # Only the legacy pointer counts as broken; the remote one would be a false stop.
    assert receipt["handoffPointersDangling"] == 1


def test_fleet_refuses_rather_than_reading_the_local_copy_when_the_root_is_down(
    repo: Path,
) -> None:
    proc = _ps(COORD / "fleet.ps1", repo, "-Json", env=_env(DEAD_UNC))
    assert proc.returncode == 2
    assert "did not resolve" in proc.stderr


# ---------------------------------------------------------------------------------------- mail


def _send(repo: Path, root: str | Path, to: str) -> subprocess.CompletedProcess[str]:
    return _ps(
        COORD / "mail.ps1", repo, "-Send", "-To", to, "-Body", "hello", "-Json", env=_env(root)
    )


def test_a_path_send_lands_on_the_shared_root(repo: Path, shared: Path) -> None:
    proc = _send(repo, shared, str(repo))
    assert proc.returncode == 0, proc.stderr
    assert list((shared / "mail" / "box").rglob("inbox/*.json"))
    assert not (_local(repo) / "mail").exists()


def test_a_seat_id_on_another_host_is_a_mailbox(repo: Path, shared: Path) -> None:
    _plant_record(
        shared / "seats",
        SEAT_ID,
        _record(box=SEAT_ID, session="sess-o", worktree=r"D:\t\autonomy-plan", host=OTHER_HOST),
    )
    proc = _send(repo, shared, SEAT_ID)
    assert proc.returncode == 0, proc.stderr
    msgs = list((shared / "mail" / "box" / SEAT_ID / "inbox").glob("*.json"))
    assert len(msgs) == 1
    msg = json.loads(msgs[0].read_text(encoding="ascii"))
    assert msg["to"]["cwd"] == r"D:\t\autonomy-plan"
    row = json.loads(proc.stdout)[0]
    assert row["Key"] == SEAT_ID and OTHER_HOST in row["To"]


def test_the_seat_id_box_is_the_one_the_recipients_drain_reads() -> None:
    """The seat id is a box key only because seat.ps1 and the drain key on ONE function."""
    script = f". '{COORD / 'mail-key.ps1'}'; ConvertTo-BoxKey -Path 'D:\\t\\autonomy-plan'"
    key = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=True,
    ).stdout.strip()
    assert key.startswith("autonomy-plan-") and len(key) == len("autonomy-plan-") + 8


@pytest.mark.parametrize("to", ["nobody-deadbeef", "autonomy-plan", "Autonomy-Plan-62022E2C"])
def test_an_unknown_or_misshapen_seat_id_is_refused_and_mints_no_box(
    repo: Path, shared: Path, to: str
) -> None:
    _plant_record(
        shared / "seats",
        SEAT_ID,
        _record(box=SEAT_ID, session="sess-o", worktree=r"D:\t\autonomy-plan", host=OTHER_HOST),
    )
    proc = _send(repo, shared, to)
    assert proc.returncode != 0
    assert "not a seat id" in proc.stderr
    assert not (shared / "mail" / "box").exists()


def test_a_seat_directory_with_no_readable_record_is_not_a_seat(repo: Path, shared: Path) -> None:
    (shared / "seats" / SEAT_ID).mkdir(parents=True)
    (shared / "seats" / SEAT_ID / "torn.json").write_text("{not json", encoding="utf-8")
    proc = _send(repo, shared, SEAT_ID)
    assert proc.returncode != 0
    assert not (shared / "mail" / "box").exists()


def test_a_send_refuses_when_the_shared_root_does_not_answer(repo: Path) -> None:
    proc = _send(repo, DEAD_UNC, str(repo))
    assert proc.returncode != 0
    assert "REFUSED" in proc.stderr
    assert not (_local(repo) / "mail").exists()


def _drain(repo: Path, root: str | Path, event: str) -> subprocess.CompletedProcess[str]:
    payload = {
        "hook_event_name": event,
        "cwd": str(repo),
        "session_id": "11111111-2222-3333-4444-555555555555",
    }
    return _ps(HOOKS / "mail-drain.ps1", repo, env=_env(root), stdin=json.dumps(payload))


def test_the_drain_reads_the_shared_box(repo: Path, shared: Path) -> None:
    assert _send(repo, shared, str(repo)).returncode == 0
    proc = _drain(repo, shared, "SessionStart")
    assert proc.returncode == 0, proc.stderr
    assert "hello" in proc.stdout


def test_the_drain_skips_without_blocking_when_the_root_is_down(repo: Path) -> None:
    started = time.monotonic()
    start = _drain(repo, DEAD_UNC, "SessionStart")
    assert start.returncode == 0
    ctx = json.loads(start.stdout)["hookSpecificOutput"]["additionalContext"]
    assert "SHARED ROOT UNAVAILABLE" in ctx and "NOTHING WAS READ" in ctx
    # At Stop it must not inject, because output there re-wakes the model.
    stop = _drain(repo, DEAD_UNC, "Stop")
    assert stop.returncode == 0 and not stop.stdout.strip()
    assert "SHARED ROOT UNAVAILABLE" in stop.stderr
    # One bounded probe, then the cached DOWN verdict: well inside any hook timeout.
    assert time.monotonic() - started < 30


# ------------------------------------------------------------------------------------ handoffs


def test_handoff_write_and_where_use_the_shared_root(repo: Path, shared: Path) -> None:
    draft = repo / "draft.md"
    draft.write_text("# handoff\n", encoding="utf-8")
    w = _ps(
        COORD / "handoff.ps1",
        repo,
        "-Write",
        "X-2026-10-21.md",
        "-From",
        str(draft),
        env=_env(shared),
    )
    assert w.returncode == 0, w.stdout + w.stderr
    assert (shared / "handoffs" / "X-2026-10-21.md").is_file()
    where = _ps(COORD / "handoff.ps1", repo, "-Where", env=_env(shared))
    assert where.returncode == 0
    assert where.stdout.strip().lower().startswith(str(shared / "handoffs").lower())
    assert not (_local(repo) / "handoffs").exists()


def test_handoff_write_refuses_when_the_root_is_down(repo: Path) -> None:
    draft = repo / "draft.md"
    draft.write_text("# handoff\n", encoding="utf-8")
    w = _ps(COORD / "handoff.ps1", repo, "-Write", "X.md", "-From", str(draft), env=_env(DEAD_UNC))
    assert w.returncode == 2
    assert "did not resolve" in w.stdout
    assert not (_local(repo) / "handoffs").exists()


# ----------------------------------------------------------------------- precompact and local kinds


def _reprime(repo: Path, root: str | Path) -> str:
    payload = {"hook_event_name": "SessionStart", "source": "compact", "cwd": str(repo)}
    proc = _ps(HOOKS / "precompact-reprime.ps1", repo, env=_env(root), stdin=json.dumps(payload))
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


def test_precompact_restores_from_the_shared_root_and_ignores_another_hosts_record(
    repo: Path, shared: Path
) -> None:
    top = _git(repo, "rev-parse", "--path-format=absolute", "--show-toplevel")
    other = _record(box="b-11111111", session="sess-x", worktree=top, host=OTHER_HOST)
    other["goal"] = "GOAL FROM THE OTHER PC"
    _plant_record(shared / "seats", "b-11111111", other)
    assert "GOAL FROM THE OTHER PC" not in _reprime(repo, shared)

    mine = _record(box="b-22222222", session="sess-y", worktree=top, host=None)
    mine["goal"] = "GOAL FROM THIS PC"
    mine["branch"] = "main"
    _plant_record(shared / "seats", "b-22222222", mine)
    assert "GOAL FROM THIS PC" in _reprime(repo, shared)


def test_precompact_says_why_when_the_root_is_down(repo: Path) -> None:
    out = _reprime(repo, DEAD_UNC)
    assert "not restored" in out and "BRANCH:" in out


def test_the_overlap_cache_stays_local_under_a_shared_root(
    repo: Path, shared: Path, tmp_path: Path
) -> None:
    proc = _ps(
        COORD / "overlap.ps1",
        repo,
        "-Repo",
        str(repo),
        "-ConfigRoot",
        str(tmp_path / "no-such-config"),
        "-TasksDir",
        str(tmp_path / "no-such-tasks"),
        "-Json",
        env=_env(shared),
    )
    assert proc.returncode == 0, proc.stderr
    assert (_local(repo) / "overlap-cache").is_dir()
    assert not (shared / "overlap-cache").exists()


# ----------------------------------------------------------------------------------- wiki prompt


def test_the_wiki_prompt_names_the_shared_root_and_keeps_its_own_state_local(
    tmp_path: Path, shared: Path
) -> None:
    from tests.test_wiki_write_prompt_hook import MIN_TOOLS, Env, blocked, tools

    (tmp_path / "wiki").mkdir()
    wiki = Env(tmp_path / "wiki")
    wiki.append(tools(MIN_TOOLS))
    reason = blocked(wiki.run(env={"MEFOR_COORD_ROOT": str(shared)}))["reason"]
    assert f'-StateRoot "{str(shared).replace(chr(92), "/")}"' in reason
    # wiki-prompt/ is a LOCAL kind: the cooldown state stays in this clone.
    assert wiki.state_path.is_file()
    assert not (shared / "wiki-prompt").exists()


# ------------------------------------------------- another host's claims and allocations at this path
#
# On a shared root a claim or allocation names a worktree path on the machine that wrote it. Two PCs
# can hold trees at the same path string, so a reader matching by path alone would credit this tree
# with the other PC's records. Each reader below must skip an OTHER-PC record and keep a no-host one.


def _plant_claim(shared: Path, key: str, worktree: str, host: str | None) -> None:
    d = shared / "claims"
    d.mkdir(parents=True, exist_ok=True)
    rec: dict[str, Any] = {"key": key, "worktree": worktree, "claimedAt": "2026-10-21T00:00:00Z"}
    if host is not None:
        rec["host"] = host
    (d / f"{key}.json").write_text(json.dumps(rec), encoding="utf-8")


def _plant_alloc(shared: Path, number: str, worktree: str, host: str | None) -> None:
    d = shared / "alloc" / "adr"
    d.mkdir(parents=True, exist_ok=True)
    rec: dict[str, Any] = {
        "number": number,
        "kind": "adr",
        "title": f"title {number}",
        "worktree": worktree,
        "claimed": "2026-10-21T00:00:00Z",
    }
    if host is not None:
        rec["host"] = host
    (d / f"{number}.json").write_text(json.dumps(rec), encoding="utf-8")


def test_the_seat_record_counts_only_this_machines_claims_and_allocations(
    repo: Path, shared: Path
) -> None:
    top = _git(repo, "rev-parse", "--path-format=absolute", "--show-toplevel")
    _plant_claim(shared, "k-other", top, OTHER_HOST)
    _plant_claim(shared, "k-mine", top, None)
    _plant_alloc(shared, "0007", top, OTHER_HOST)
    _plant_alloc(shared, "0008", top, None)
    proc = _ps(
        COORD / "seat.ps1",
        repo,
        "-Declare",
        "-Seat",
        "builder",
        "-Goal",
        "g",
        env=_env(shared, CLAUDE_CODE_SESSION_ID="sess-hosts"),
    )
    assert proc.returncode == 0, proc.stderr
    recs = list((shared / "seats").rglob("sess-hosts.json"))
    assert len(recs) == 1, proc.stdout + proc.stderr
    rec = json.loads(recs[0].read_text(encoding="utf-8"))
    assert [c["key"] for c in rec["claims"]] == ["k-mine"], rec["claims"]
    assert [a["number"] for a in rec["allocations"]] == ["0008"], rec["allocations"]


def test_precompact_lists_only_this_machines_ledger_numbers(repo: Path, shared: Path) -> None:
    top = _git(repo, "rev-parse", "--path-format=absolute", "--show-toplevel")
    _plant_alloc(shared, "0007", top, OTHER_HOST)
    _plant_alloc(shared, "0008", top, None)
    out = _reprime(repo, shared)
    assert "#0008 (adr) title 0008" in out, out
    assert "#0007" not in out, out


# ------------------------------------------------------------------------------------- lane level


def _lane_level(repo: Path, root: str | Path | None) -> str:
    proc = _ps(
        HOOKS / "lane-level.ps1",
        repo,
        env=_env(root),
        stdin=json.dumps({"hook_event_name": "Stop"}),
    )
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout.strip()
    return str(json.loads(out)["hookSpecificOutput"]["additionalContext"]) if out else ""


@pytest.fixture
def dispatcher_repo(tmp_path: Path) -> Path:
    # lane-level.ps1 reads the seat registry only for a dispatcher, which it tells by the leaf name.
    r = tmp_path / "dispatcher-lane"
    r.mkdir()
    for args in (
        ["init", "-q", "-b", "main"],
        ["config", "user.email", "t@example.invalid"],
        ["config", "user.name", "t"],
    ):
        _git(r, *args)
    _git(r, "commit", "-q", "--allow-empty", "-m", "base")
    return r


def test_lane_level_reads_seats_from_the_shared_root(dispatcher_repo: Path, shared: Path) -> None:
    for i in range(6):
        box = f"b-{i:08d}"
        _plant_record(
            shared / "seats", box, _record(box=box, session=f"s{i}", worktree="C:/x", host=None)
        )
    # Control: with nothing configured the hook reads the local root, which holds no seats.
    assert "seats\\ is absent" in _lane_level(dispatcher_repo, None)
    text = _lane_level(dispatcher_repo, shared)
    assert "INSTRUMENT ERROR" not in text, text
    assert "coverage: 0 lanes discovered" in text, text
    assert not (_local(dispatcher_repo) / "seats").exists()


def test_lane_level_skips_with_a_note_when_the_root_is_down(dispatcher_repo: Path) -> None:
    text = _lane_level(dispatcher_repo, DEAD_UNC)
    assert text.startswith("[lane] SKIPPED: the coordination root did not resolve"), text
