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

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="the coordination scripts run under pwsh on Windows",
)


def _env() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if k != "CLAUDE_CODE_REMOTE"}


def _pwsh(script: Path, *args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(script), *args],
        cwd=str(cwd),
        env=_env(),
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
    _write(src / "seats" / "b-2.json", '{"seat": "manager", "host": "OTHERPC"}')
    _write(src / "claims" / "1234.json", '{"holder": "x"}')
    _write(src / "claims" / ".history" / "log.txt", "line\n")
    _write(src / "alloc" / "adr" / "0211.json", '{"title": "t"}')
    _write(src / "alloc" / "backlog" / "1770.json", '{"title": "old"}')
    _write(src / "alloc" / "backlog" / "1000000.json", '{"tombstone": true, "worktree": ""}')
    _write(src / "mail" / "inbox" / "m1.json", "{}")
    _write(src / "mail" / "tmp" / "half.json", '{"x"')
    _write(src / "owner-log" / "OWNER-ITEMS.md", "| row |\n")
    # Never copied: retired, backup, cache and local trees.
    _write(src / "_retired-2026-08-22" / "seats" / "old.json", "{}")
    _write(src / "seats" / "backups" / "s.json", "{}")
    _write(src / "seats" / "a-1.json.BACKUP-20261001", "{}")
    _write(src / "handoffs" / "x.cache" / "c.json", "{}")
    _write(src / "overlap-cache" / "k.json", "{}")
    _write(src / "announce" / "r.json", "{}")
    return src


def _migrate(src: Path, dst: Path, *extra: str) -> tuple[subprocess.CompletedProcess[str], Any]:
    proc = _pwsh(
        MIGRATE,
        "-Source",
        str(src),
        "-Target",
        str(dst),
        "-SourceHost",
        STAMP,
        "-Json",
        *extra,
        cwd=src.parent,
    )
    return proc, json.loads(proc.stdout) if proc.stdout.strip() else None


def _kind(summary: Any, kind: str) -> dict[str, int]:
    row: dict[str, int] = next(r for r in summary["kinds"] if r["kind"] == kind)
    return row


def test_dry_run_writes_nothing(tmp_path: Path) -> None:
    src = _source(tmp_path)
    dst = tmp_path / "dst"
    proc, summary = _migrate(src, dst)
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    assert summary["mode"] == "dry-run"
    assert not dst.exists()
    assert _kind(summary, "seats")["copy"] == 2


def test_apply_copies_and_stamps_only_an_absent_host(tmp_path: Path) -> None:
    src = _source(tmp_path)
    dst = tmp_path / "dst"
    proc, summary = _migrate(src, dst, "-Apply")
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    a = json.loads((dst / "seats" / "a-1.json").read_text(encoding="utf-8"))
    assert a == {"host": STAMP, "seat": "builder", "at": "2026-10-21T10:00:00Z"}
    # The date string survives as written: the stamp is a text insert, not a re-serialisation.
    assert '"at": "2026-10-21T10:00:00Z"' in (dst / "seats" / "a-1.json").read_text(
        encoding="utf-8"
    )
    # A present host is kept, never overwritten by the stamp.
    b = json.loads((dst / "seats" / "b-2.json").read_text(encoding="utf-8"))
    assert b["host"] == "OTHERPC"
    assert json.loads((dst / "mail" / "inbox" / "m1.json").read_text(encoding="utf-8")) == {
        "host": STAMP
    }
    assert (dst / "claims" / ".history" / "log.txt").read_text(encoding="utf-8") == "line\n"
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


def test_retired_backup_cache_temp_and_local_trees_are_skipped(tmp_path: Path) -> None:
    src = _source(tmp_path)
    dst = tmp_path / "dst"
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
    dst = tmp_path / "dst"
    proc, summary = _migrate(src, dst, "-Apply")
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    assert summary["retiredBacklog"] == {"records": 2, "tombstones": 1, "included": False}
    assert not (dst / "alloc" / "backlog").exists()
    assert (dst / "alloc" / "adr" / "0211.json").is_file()
    text = _pwsh(MIGRATE, "-Source", str(src), "-Target", str(tmp_path / "d2"), cwd=tmp_path)
    assert "RETIRED BACKLOG ALLOCATIONS (alloc/backlog): 2 record(s), 1 tombstone(s)" in text.stdout
    proc3, _ = _migrate(src, tmp_path / "d3", "-Apply", "-IncludeRetiredBacklog")
    assert proc3.returncode == 0, (proc3.stdout, proc3.stderr)
    assert (tmp_path / "d3" / "alloc" / "backlog" / "1000000.json").is_file()


def test_conflict_and_adr_collision_are_reported_and_never_overwritten(tmp_path: Path) -> None:
    src = _source(tmp_path)
    dst = tmp_path / "dst"
    _write(dst / "claims" / "1234.json", '{"holder": "someone else", "host": "OTHERPC"}')
    _write(dst / "alloc" / "adr" / "0211.json", '{"title": "another ADR", "host": "OTHERPC"}')
    before = {p: p.read_bytes() for p in dst.rglob("*.json")}
    proc, summary = _migrate(src, dst, "-Apply")
    assert proc.returncode == 3, (proc.stdout, proc.stderr)
    assert summary["conflicts"] == ["claims/1234.json"]
    assert summary["collisions"] == ["alloc/adr/0211.json"]
    assert {p: p.read_bytes() for p in before} == before
    # Everything else still copied.
    assert (dst / "seats" / "a-1.json").is_file()
    text = _pwsh(MIGRATE, "-Source", str(src), "-Target", str(dst), cwd=tmp_path)
    assert text.returncode == 3
    assert "COLLISIONS" in text.stdout and "alloc/adr/0211.json" in text.stdout
    assert "CONFLICTS" in text.stdout and "claims/1234.json" in text.stdout


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


def _result(d: Path, tag: str, won: list[int], slots: int) -> None:
    body = {"tag": tag, "host": tag, "slots": slots, "won": won, "errors": [], "startedAtUtc": ""}
    (d / f"result-{tag}.json").write_text(json.dumps(body), encoding="utf-8")


def _compare(d: Path) -> tuple[subprocess.CompletedProcess[str], Any]:
    proc = _pwsh(RACE, "-Compare", "-Dir", str(d), "-Json", cwd=d)
    return proc, json.loads(proc.stdout) if proc.stdout.strip() else None


def test_compare_flags_a_planted_double_winner_and_an_empty_slot(tmp_path: Path) -> None:
    d = tmp_path / "race"
    d.mkdir()
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


def test_compare_needs_two_results(tmp_path: Path) -> None:
    d = tmp_path / "race"
    d.mkdir()
    _result(d, "A", [1], 1)
    proc = _pwsh(RACE, "-Compare", "-Dir", str(d), cwd=d)
    assert proc.returncode == 2, (proc.stdout, proc.stderr)


def test_two_real_processes_race_clean(tmp_path: Path) -> None:
    d = tmp_path / "race"
    d.mkdir()
    start = (datetime.now(UTC) + timedelta(seconds=8)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
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
    assert sum(s["won"] for s in summary["sides"]) == 50
    # A rerun in the same directory is refused: a stale slot would read as a loss for both sides.
    again = _pwsh(RACE, "-Dir", str(d), "-Tag", "P3", "-StartAtUtc", start, cwd=d)
    assert again.returncode == 2, (again.stdout, again.stderr)
