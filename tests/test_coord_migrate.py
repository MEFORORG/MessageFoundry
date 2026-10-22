# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The shared-root migration tools: ``scripts/coord/coord-migrate.ps1`` and ``coord-race.ps1``.

Every case runs against temp directories. Neither tool is ever pointed at a real coordination
directory or a share here; running them for real is the owner's call (docs/COORD-SHARED-ROOT.md).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from tests._no_prompt import run_holding_stdin_open

ROOT = Path(__file__).resolve().parents[1]
MIGRATE = ROOT / "scripts" / "coord" / "coord-migrate.ps1"
RACE = ROOT / "scripts" / "coord" / "coord-race.ps1"
TIMEOUT = 120
STAMP = "SRCPC"
REFUSAL = "refused in a Claude Code cloud session"

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="the coordination scripts run under pwsh on Windows",
)


def _env(*, cloud: bool = False) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k != "CLAUDE_CODE_REMOTE"}
    if cloud:
        env["CLAUDE_CODE_REMOTE"] = "true"
    return env


def _pwsh(
    script: Path, *args: str, cwd: Path, cloud: bool = False
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(script), *args],
        cwd=str(cwd),
        env=_env(cloud=cloud),
        input="",
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _source(tmp_path: Path) -> Path:
    """A small coordination directory with every class of file the tool must sort."""
    src = tmp_path / "src"
    _write(src / "seats" / "a-1.json", '{"seat": "builder", "at": "2026-10-21T10:00:00Z"}')
    _write(src / "seats" / "b-2.json", '{"seat": "manager", "host": "srcpc"}')
    _write(src / "claims" / "1234.json", '{"holder": "x"}')
    _write(src / "claims" / ".history", '{"released": "1"}\n')
    _write(src / "alloc" / "adr" / "0211.json", '{"title": "t"}')
    _write(src / "alloc" / "backlog" / "1770.json", '{"title": "old"}')
    _write(src / "alloc" / "backlog" / "1000000.json", '{"tombstone": true, "worktree": ""}')
    _write(src / "mail" / "inbox" / "m1.json", "{}")
    _write(src / "mail" / "tmp" / "half.json", '{"x"')
    _write(src / "wiki" / "inbox" / "e1.json", '{"id": "e1"}')
    _write(src / "handoffs" / "box" / "state.json", '{"next": "x"}')
    _write(src / "owner-log" / "OWNER-ITEMS.md", "| row |\n")
    # Never copied: retired, backup, cache and local trees.
    _write(src / "_retired-2026-08-22" / "seats" / "old.json", "{}")
    _write(src / "seats" / "backups" / "s.json", "{}")
    _write(src / "seats" / "a-1.json.BACKUP-20261001", "{}")
    _write(src / "handoffs" / "x.cache" / "c.json", "{}")
    _write(src / "overlap-cache" / "k.json", "{}")
    _write(src / "announce" / "r.json", "{}")
    return src


def _dst(tmp_path: Path, name: str = "dst") -> Path:
    """Migration step 1 creates the target; the tool refuses one that does not exist."""
    d = tmp_path / name
    d.mkdir()
    return d


def _migrate(
    src: Path, dst: Path, *extra: str, host: str | None = STAMP
) -> tuple[subprocess.CompletedProcess[str], Any]:
    stamp = ("-SourceHost", host) if host else ()
    proc = _pwsh(
        MIGRATE, "-Source", str(src), "-Target", str(dst), *stamp, "-Json", *extra, cwd=src.parent
    )
    return proc, json.loads(proc.stdout) if proc.stdout.strip() else None


def _kind(summary: Any, kind: str) -> dict[str, int]:
    row: dict[str, int] = next(r for r in summary["kinds"] if r["kind"] == kind)
    return row


def _read(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def test_dry_run_writes_nothing(tmp_path: Path) -> None:
    src = _source(tmp_path)
    dst = _dst(tmp_path)
    proc, summary = _migrate(src, dst)
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    assert summary["mode"] == "dry-run"
    assert list(dst.iterdir()) == []
    assert _kind(summary, "seats")["copy"] == 2


def test_a_missing_target_is_refused(tmp_path: Path) -> None:
    """A dry run against nothing would report no collisions, which reads as clean."""
    src = _source(tmp_path)
    proc, _ = _migrate(src, tmp_path / "typo")
    assert proc.returncode == 2, (proc.stdout, proc.stderr)
    assert not (tmp_path / "typo").exists()


def test_relative_paths_resolve_against_the_working_directory(tmp_path: Path) -> None:
    _source(tmp_path)
    dst = _dst(tmp_path)
    args = ("-Source", "src", "-Target", "dst", "-SourceHost", STAMP, "-Apply")
    proc = _pwsh(MIGRATE, *args, cwd=tmp_path)
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    assert (dst / "seats" / "a-1.json").is_file()


def test_apply_copies_and_stamps_only_an_absent_host(tmp_path: Path) -> None:
    src = _source(tmp_path)
    dst = _dst(tmp_path)
    proc, summary = _migrate(src, dst, "-Apply")
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    assert _read(dst / "seats" / "a-1.json") == {
        "host": STAMP,
        "seat": "builder",
        "at": "2026-10-21T10:00:00Z",
    }
    # The date string survives as written: the stamp is a text insert, not a re-serialisation.
    assert '"at": "2026-10-21T10:00:00Z"' in (dst / "seats" / "a-1.json").read_text(
        encoding="utf-8"
    )
    # A present host is kept, never overwritten by the stamp.
    assert _read(dst / "seats" / "b-2.json")["host"] == "srcpc"
    assert _read(dst / "mail" / "inbox" / "m1.json") == {"host": STAMP}
    # Wiki events and handoffs are copied byte for byte: korus compile compares an event with its
    # landed copy, and a seat record pins its handoff's size and sha256.
    for rel in ("wiki/inbox/e1.json", "handoffs/box/state.json"):
        assert (dst / rel).read_bytes() == (src / rel).read_bytes(), rel
    assert (dst / "claims" / ".history").read_text(encoding="utf-8") == '{"released": "1"}\n'
    assert (dst / "owner-log" / "OWNER-ITEMS.md").is_file()
    seats = _kind(summary, "seats")
    assert (seats["copy"], seats["stamped"], seats["hostKept"]) == (2, 1, 1)
    # The source's last-write time travels with the copy, because seat liveness reads it.
    assert (dst / "claims" / "1234.json").stat().st_mtime == pytest.approx(
        (src / "claims" / "1234.json").stat().st_mtime, abs=1
    )
    assert not list(dst.rglob("*.tmp"))
    # A second run finds every file PRESENT, so it is a clean no-op.
    proc2, again = _migrate(src, dst, "-Apply")
    assert proc2.returncode == 0, (proc2.stdout, proc2.stderr)
    assert sum(r["copy"] for r in again["kinds"]) == 0
    assert _kind(again, "seats")["present"] == 2


@pytest.mark.parametrize(
    ("body", "reason"),
    [
        pytest.param('{"holder": "x", "host": null}', "null or blank", id="null-host"),
        pytest.param('{"holder": "x", "host": "  "}', "null or blank", id="blank-host"),
        pytest.param('{"holder": "x", "Host": "PC"}', "another case", id="cased-host"),
        pytest.param('{"holder": "x",}', "readable", id="unreadable"),
    ],
)
def test_a_record_that_cannot_be_stamped_safely_is_not_clean(
    tmp_path: Path, body: str, reason: str
) -> None:
    """Each of these would read as "this machine" on every PC, so it is held back, and said so."""
    src = tmp_path / "src"
    _write(src / "claims" / "9.json", body)
    dst = _dst(tmp_path)
    proc, summary = _migrate(src, dst, "-Apply")
    assert proc.returncode == 3, (proc.stdout, proc.stderr)
    [entry] = summary["unstamped"]
    assert entry["path"] == "claims/9.json" and reason in entry["reason"]
    assert not (dst / "claims" / "9.json").exists()


def test_a_foreign_host_without_source_host_is_not_clean(tmp_path: Path) -> None:
    """Without -SourceHost the stamp is this machine; a source naming another host is suspect."""
    src = _source(tmp_path)
    _write(src / "claims" / "77.json", '{"holder": "y", "host": "OTHERPC"}')
    dst = _dst(tmp_path)
    # -Apply writes nothing at all: a wrong stamp on the share could never be repaired.
    proc, summary = _migrate(src, dst, "-Apply", host=None)
    assert proc.returncode == 3, (proc.stdout, proc.stderr)
    assert "OTHERPC" in summary["foreignHosts"] and summary["held"] is True
    assert list(dst.iterdir()) == []
    # A mistyped -SourceHost is caught the same way.
    proc2, typo = _migrate(src, dst, host="OTHERPC1")
    assert proc2.returncode == 3, (proc2.stdout, proc2.stderr)
    assert sorted(typo["foreignHosts"]) == ["OTHERPC", "srcpc"]


def test_retired_backup_cache_temp_and_local_trees_are_skipped(tmp_path: Path) -> None:
    src = _source(tmp_path)
    dst = _dst(tmp_path)
    proc, summary = _migrate(src, dst, "-Apply")
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    for gone in (
        "_retired-2026-08-22",
        "overlap-cache",
        "announce",
        "seats/backups",
        "seats/a-1.json.BACKUP-20261001",
        "handoffs/x.cache",
        "mail/tmp",
    ):
        assert not (dst / gone).exists(), gone
    reasons = {s["path"]: s["reason"] for s in summary["skipped"]}
    assert reasons["seats/backups"] == "backup"
    assert reasons["mail/tmp"] == "temp file"
    assert reasons["handoffs/x.cache"] == "cache"


def test_retired_backlog_has_its_own_heading_and_is_not_copied(tmp_path: Path) -> None:
    src = _source(tmp_path)
    dst = _dst(tmp_path)
    proc, summary = _migrate(src, dst, "-Apply")
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    assert summary["retiredBacklog"] == {"records": 2, "tombstones": 1, "included": False}
    assert not (dst / "alloc" / "backlog").exists()
    assert (dst / "alloc" / "adr" / "0211.json").is_file()
    d2 = _dst(tmp_path, "d2")
    text = _pwsh(MIGRATE, "-Source", str(src), "-Target", str(d2), cwd=tmp_path)
    assert "RETIRED BACKLOG ALLOCATIONS (alloc/backlog): 2 record(s), 1 tombstone(s)" in text.stdout
    d3 = _dst(tmp_path, "d3")
    proc3, _ = _migrate(src, d3, "-Apply", "-IncludeRetiredBacklog")
    assert proc3.returncode == 0, (proc3.stdout, proc3.stderr)
    assert (d3 / "alloc" / "backlog" / "1000000.json").is_file()


def test_conflict_and_adr_collision_are_reported_and_never_overwritten(tmp_path: Path) -> None:
    src = _source(tmp_path)
    dst = _dst(tmp_path)
    _write(dst / "claims" / "1234.json", '{"holder": "someone else", "host": "OTHERPC"}')
    _write(dst / "alloc" / "adr" / "0211.json", '{"title": "another ADR", "host": "OTHERPC"}')
    # Ledgers both PCs hold are NOT MERGED, and do not count as conflicts.
    _write(dst / "claims" / ".history", '{"released": "2"}\n')
    _write(dst / "owner-log" / "OWNER-ITEMS.md", "| other row |\n")
    before = {p: p.read_bytes() for p in dst.rglob("*") if p.is_file()}
    proc, summary = _migrate(src, dst, "-Apply")
    assert proc.returncode == 3, (proc.stdout, proc.stderr)
    assert summary["conflicts"] == ["claims/1234.json"]
    assert summary["collisions"] == ["alloc/adr/0211.json"]
    assert sorted(summary["notMerged"]) == ["claims/.history", "owner-log/OWNER-ITEMS.md"]
    assert {p: p.read_bytes() for p in before} == before
    # Everything else still copied.
    assert (dst / "seats" / "a-1.json").is_file()
    text = _pwsh(MIGRATE, "-Source", str(src), "-Target", str(dst), cwd=tmp_path)
    assert text.returncode == 3
    assert "COLLISIONS" in text.stdout and "alloc/adr/0211.json" in text.stdout
    assert "CONFLICTS" in text.stdout and "claims/1234.json" in text.stdout
    assert "NOT MERGED" in text.stdout


def test_nested_roots_are_refused(tmp_path: Path) -> None:
    src = _source(tmp_path)
    proc = _pwsh(MIGRATE, "-Source", str(src), "-Target", str(src / "seats"), cwd=tmp_path)
    assert proc.returncode == 2, (proc.stdout, proc.stderr)


@pytest.mark.parametrize("script", [MIGRATE, RACE], ids=["migrate", "race"])
def test_a_bare_call_refuses_rather_than_prompting(tmp_path: Path, script: Path) -> None:
    code, err = run_holding_stdin_open(
        ["pwsh", "-NoProfile", "-File", str(script)], cwd=tmp_path, env=_env()
    )
    assert code == 2, err
    assert "needs -" in err


def _soon(seconds: float) -> str:
    return (datetime.now(UTC) + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def test_the_cloud_refusal_comes_before_any_write(tmp_path: Path) -> None:
    """Arguments that would copy, and would race, outside the cloud: so a refusal moved below the
    work would be caught. The controls are the apply and race tests above and below."""
    src = _source(tmp_path)
    dst = _dst(tmp_path)
    proc = _pwsh(
        MIGRATE, "-Source", str(src), "-Target", str(dst), "-Apply", cwd=tmp_path, cloud=True
    )
    assert proc.returncode == 3 and REFUSAL in proc.stderr, (proc.stdout, proc.stderr)
    assert list(dst.iterdir()) == []
    race = _dst(tmp_path, "race")
    args = ("-Dir", str(race), "-Tag", "A", "-StartAtUtc", _soon(1), "-Slots", "3")
    proc2 = _pwsh(RACE, *args, cwd=tmp_path, cloud=True)
    assert proc2.returncode == 3 and REFUSAL in proc2.stderr, (proc2.stdout, proc2.stderr)
    assert list(race.iterdir()) == []


T0 = "2026-10-21T10:00:00.000Z"


def _result(
    d: Path,
    tag: str,
    won: list[int],
    slots: int,
    start: str = T0,
    end: str = "2026-10-21T10:00:02.000Z",
    errors: int = 0,
) -> None:
    body = {
        "tag": tag,
        "host": tag,
        "slots": slots,
        "gapMs": 20,
        "won": won,
        "errors": [{"slot": 1, "error": "denied"}] * errors,
        "startAtUtc": T0,
        "startedAtUtc": start,
        "finishedAtUtc": end,
    }
    (d / f"result-{tag}.json").write_text(json.dumps(body), encoding="utf-8")


def _compare(d: Path) -> tuple[subprocess.CompletedProcess[str], Any]:
    proc = _pwsh(RACE, "-Compare", "-Dir", str(d), "-Json", cwd=d)
    return proc, json.loads(proc.stdout) if proc.stdout.strip() else None


def test_compare_flags_a_planted_double_winner_and_an_empty_slot(tmp_path: Path) -> None:
    d = _dst(tmp_path, "race")
    for n, tag in ((1, "A"), (2, "B"), (3, "A")):
        (d / f"slot-{n}").write_text(tag, encoding="utf-8")
    # Slot 1 claimed by both; slot 4 by nobody; slot 3 claimed by B but holding A.
    _result(d, "A", [1], 4)
    _result(d, "B", [1, 2, 3], 4)
    proc, summary = _compare(d)
    assert proc.returncode == 3, (proc.stdout, proc.stderr)
    assert [x["slot"] for x in summary["doubleWinners"]] == [1]
    assert summary["emptySlots"] == [4]
    assert [x["slot"] for x in summary["mismatches"]] == [3]


def test_compare_gives_no_verdict_on_a_run_that_was_not_a_race(tmp_path: Path) -> None:
    """Clean slots, but B started after A finished and won nothing: that proves nothing."""
    d = _dst(tmp_path, "race")
    for n in (1, 2):
        (d / f"slot-{n}").write_text("A", encoding="utf-8")
    _result(d, "A", [1, 2], 2, "2026-10-21T10:00:00.000Z", "2026-10-21T10:00:01.000Z")
    _result(d, "B", [], 2, "2026-10-21T10:00:05.000Z", "2026-10-21T10:00:06.000Z")
    proc, summary = _compare(d)
    assert proc.returncode == 2, (proc.stdout, proc.stderr)
    text = " ".join(summary["invalid"])
    assert "won no slot" in text and "do not overlap" in text and "ms late" in text


def test_compare_gives_no_verdict_when_an_error_explains_an_empty_slot(tmp_path: Path) -> None:
    """Access denied on a slot leaves it empty; that is not a failure of exclusive create."""
    d = _dst(tmp_path, "race")
    (d / "slot-1").write_text("A", encoding="utf-8")
    _result(d, "A", [1], 2)
    _result(d, "B", [], 2, errors=1)
    proc, summary = _compare(d)
    assert proc.returncode == 2, (proc.stdout, proc.stderr)
    assert summary["emptySlots"] == [2]


def test_compare_needs_two_results(tmp_path: Path) -> None:
    d = _dst(tmp_path, "race")
    _result(d, "A", [1], 1)
    proc = _pwsh(RACE, "-Compare", "-Dir", str(d), cwd=d)
    assert proc.returncode == 2, (proc.stdout, proc.stderr)


def test_a_start_time_in_the_past_is_refused(tmp_path: Path) -> None:
    d = _dst(tmp_path, "race")
    proc = _pwsh(RACE, "-Dir", str(d), "-Tag", "A", "-StartAtUtc", _soon(-60), cwd=d)
    assert proc.returncode == 2, (proc.stdout, proc.stderr)
    assert list(d.iterdir()) == []


def test_two_real_processes_race_clean(tmp_path: Path) -> None:
    d = _dst(tmp_path, "race")
    start = _soon(8)
    procs = [
        subprocess.Popen(
            [
                "pwsh",
                "-NoProfile",
                "-NonInteractive",
                "-File",
                str(RACE),
                "-Dir",
                str(d),
                "-Tag",
                tag,
                "-StartAtUtc",
                start,
                "-Slots",
                "50",
            ],
            cwd=str(d),
            env=_env(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for tag in ("P1", "P2")
    ]
    for p in procs:
        out, err = p.communicate(timeout=TIMEOUT)
        assert p.returncode == 0, (out, err)
    proc, summary = _compare(d)
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    assert summary["doubleWinners"] == [] and summary["emptySlots"] == []
    assert summary["invalid"] == []
    assert sum(s["won"] for s in summary["sides"]) == 50
    # A rerun in the same directory is refused: a stale slot would read as a loss for both sides.
    again = _pwsh(RACE, "-Dir", str(d), "-Tag", "P3", "-StartAtUtc", _soon(30), cwd=d)
    assert again.returncode == 2, (again.stdout, again.stderr)
    assert "slot file" in again.stderr
