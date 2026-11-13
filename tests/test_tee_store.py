# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Unit tests for the tee relay's SQLite log (tee/store.py)."""

from __future__ import annotations

import asyncio
import logging
import os
import pickle
import sqlite3
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

import tee.controlchars as tee_controlchars
import tee.store as tee_store
from tee.__main__ import main as tee_main
from tee.store import PurgeIncompleteError, RelayStore

BUMP = tee_store._BUMP_GENERATION  # noqa: SLF001 - a peer stands in for another purge


async def _open(tmp_path: Path) -> RelayStore:
    return await RelayStore.open(str(tmp_path / "tee.db"))


async def test_record_and_query_naks(tmp_path: Path) -> None:
    store = await _open(tmp_path)
    try:
        await store.record_leg(
            direction="epic_to_corepoint",
            leg="corepoint",
            control_id="C1",
            message_type="ADT^A01",
            size_bytes=100,
            outcome="accepted",
            ack_code="AA",
            detail=None,
        )
        await store.record_leg(
            direction="epic_to_corepoint",
            leg="corepoint",
            control_id="C2",
            message_type="ADT^A01",
            size_bytes=120,
            outcome="nak",
            ack_code="AE",
            detail="busy",
        )
        await store.record_leg(
            direction="epic_to_corepoint",
            leg="mefor",
            control_id="C3",
            message_type="ORU^R01",
            size_bytes=90,
            outcome="transport_error",
            ack_code=None,
            detail="connect refused",
        )
        naks = await store.recent_naks()
        # The accepted row is excluded; the NAK and the transport error are returned, newest first.
        assert [n.control_id for n in naks] == ["C3", "C2"]
        assert naks[0].outcome == "transport_error"
        assert naks[1].ack_code == "AE"
    finally:
        await store.close()


async def test_detail_is_bounded_and_scrubbed(tmp_path: Path) -> None:
    store = await _open(tmp_path)
    try:
        await store.record_leg(
            direction="epic_to_corepoint",
            leg="corepoint",
            control_id="C1",
            message_type=None,
            size_bytes=1,
            outcome="nak",
            ack_code="AR",
            detail="x" * 5000 + "\x00\x07ctrl",
        )
        naks = await store.recent_naks()
        assert naks[0].detail is not None
        assert len(naks[0].detail) <= 500
        assert "\x00" not in naks[0].detail
    finally:
        await store.close()


async def test_capture_bodies(tmp_path: Path) -> None:
    store = await _open(tmp_path)
    try:
        await store.record_capture(direction="epic_to_corepoint", control_id="C9", raw=b"MSH|...")
        cur = await store._db.execute("SELECT raw FROM relay_capture")  # noqa: SLF001 — test introspection
        row = await cur.fetchone()
        assert row is not None and bytes(row["raw"]) == b"MSH|..."
    finally:
        await store.close()


async def test_captures_reader(tmp_path: Path) -> None:
    # The #14 parity reader: returns raw bodies + control_id, oldest-first, filterable by direction /
    # time window — what the compare tool pulls for Corepoint's output.
    store = await _open(tmp_path)
    try:
        await store.record_capture(direction="epic_to_corepoint", control_id="IN1", raw=b"MSH|in")
        await store.record_capture(direction="corepoint_copy", control_id="OUT1", raw=b"MSH|out1")
        await store.record_capture(direction="corepoint_copy", control_id="OUT2", raw=b"MSH|out2")
        # All captures: raw bytes + control_id preserved for correlation, oldest-first.
        allc = await store.captures()
        assert [(c.direction, c.control_id, c.raw) for c in allc] == [
            ("epic_to_corepoint", "IN1", b"MSH|in"),
            ("corepoint_copy", "OUT1", b"MSH|out1"),
            ("corepoint_copy", "OUT2", b"MSH|out2"),
        ]
        # Filter to Corepoint's output (the parity baseline) + most-recent-N.
        assert [c.control_id for c in await store.captures(direction="corepoint_copy")] == [
            "OUT1",
            "OUT2",
        ]
        assert [c.control_id for c in await store.captures(limit=1)] == ["OUT2"]
        # Time-window filter (since/before), seeded with a controlled timestamp.
        await store._db.execute(  # noqa: SLF001 — seed with a controlled timestamp
            "INSERT INTO relay_capture (at, direction, control_id, raw) VALUES (?,?,?,?)",
            (1000.0, "corepoint_copy", "OLD", b"MSH|old"),
        )
        await store._db.commit()  # noqa: SLF001
        assert [c.control_id for c in await store.captures(since=500.0, before=2000.0)] == ["OLD"]
    finally:
        await store.close()


async def _record(store: RelayStore, **overrides: object) -> None:
    base: dict[str, object] = {
        "direction": "epic_to_corepoint",
        "leg": "corepoint",
        "control_id": "C",
        "message_type": "ADT^A01",
        "size_bytes": 10,
        "outcome": "accepted",
        "ack_code": "AA",
        "detail": None,
    }
    base.update(overrides)
    await store.record_leg(**base)  # type: ignore[arg-type]


_COUNT_SQL = {
    "relay_log": "SELECT COUNT(*) AS n FROM relay_log",
    "relay_capture": "SELECT COUNT(*) AS n FROM relay_capture",
}


async def _count(store: RelayStore, table: str) -> int:
    cur = await store._db.execute(_COUNT_SQL[table])  # noqa: SLF001 — test introspection
    row = await cur.fetchone()
    assert row is not None
    return int(row["n"])


async def test_purge_all(tmp_path: Path) -> None:
    store = await _open(tmp_path)
    try:
        await _record(store, outcome="nak", ack_code="AE")
        await store.record_capture(direction="epic_to_corepoint", control_id="C", raw=b"MSH|x")
        assert await store.purge() == (1, 1)  # (log rows, capture rows) deleted
        assert await _count(store, "relay_log") == 0
        assert await _count(store, "relay_capture") == 0
    finally:
        await store.close()


async def test_purge_captures_only_keeps_log(tmp_path: Path) -> None:
    store = await _open(tmp_path)
    try:
        await _record(store)
        await store.record_capture(direction="epic_to_corepoint", control_id="C", raw=b"MSH|x")
        assert await store.purge(captures_only=True) == (0, 1)
        assert await _count(store, "relay_log") == 1  # NAK/leg log kept
        assert await _count(store, "relay_capture") == 0  # only the PHI bodies dropped
    finally:
        await store.close()


async def test_purge_by_age(tmp_path: Path) -> None:
    store = await _open(tmp_path)
    try:
        for at in (1000.0, 9000.0):
            await store._db.execute(  # noqa: SLF001 — seed rows with controlled timestamps
                "INSERT INTO relay_log (at,direction,leg,size_bytes,outcome) VALUES (?,?,?,?,?)",
                (at, "epic_to_corepoint", "corepoint", 10, "accepted"),
            )
        await store._db.commit()  # noqa: SLF001
        assert await store.purge(before=5000.0) == (1, 0)  # only the old row goes
        cur = await store._db.execute("SELECT at FROM relay_log")  # noqa: SLF001
        assert [r["at"] for r in await cur.fetchall()] == [9000.0]
    finally:
        await store.close()


async def test_export_summary_and_rows_no_bodies(tmp_path: Path) -> None:
    store = await _open(tmp_path)
    try:
        await _record(store, control_id="C1", outcome="accepted", ack_code="AA")
        await _record(store, leg="mefor", control_id="C1", outcome="nak", ack_code="AE", detail="x")
        data = await store.export()
        summary = data["summary"]
        assert summary["total_legs"] == 2
        assert summary["naks"] == 1
        assert summary["distinct_control_ids"] == 1
        assert summary["by_leg"] == {"corepoint": 1, "mefor": 1}
        assert summary["by_ack_code"] == {"AA": 1, "AE": 1}
        rows = data["rows"]
        assert len(rows) == 2
        assert all("at_iso" in r for r in rows)
        assert all("raw" not in r for r in rows)  # metadata only — never a message body
    finally:
        await store.close()


async def test_export_naks_only_and_limit(tmp_path: Path) -> None:
    store = await _open(tmp_path)
    try:
        await _record(store, control_id="C1", outcome="accepted", ack_code="AA")
        await _record(store, control_id="C2", outcome="nak", ack_code="AE")
        await _record(store, control_id="C3", outcome="transport_error", ack_code=None)
        naks = await store.export(naks_only=True)
        assert [r["control_id"] for r in naks["rows"]] == ["C2", "C3"]
        assert naks["summary"]["total_legs"] == 3  # summary covers ALL rows, not just the naks
        limited = await store.export(limit=1)
        assert [r["control_id"] for r in limited["rows"]] == ["C3"]  # the most recent
    finally:
        await store.close()


# --- BACKLOG #5637: WAL-sibling permissions and purged-body residue -----------------------------
#
# A synthetic capture body with a marker that cannot occur by chance in SQLite's own page headers or
# schema text, so its bytes on disk prove a purged body survived. No PHI: the HL7 is invented.
_MARKER = b"ZZPURGEMARKER5637QX"
_MARKER_BODY = b"MSH|^~\\&|TEE|TEST|||20260101000000||ADT^A01|C5637|P|2.5.1\rPID|1||" + _MARKER


def _on_disk(path: Path) -> bytes:
    """The DB file plus its -wal sibling, as raw bytes (an absent -wal reads as empty)."""
    wal = Path(f"{path}-wal")
    return path.read_bytes() + (wal.read_bytes() if wal.exists() else b"")


async def test_purge_leaves_no_body_bytes_in_wal_or_db(tmp_path: Path) -> None:
    # A second connection held open is the realistic case: with only one connection, closing it
    # checkpoints and deletes the -wal, which would hide residue that a live peer keeps on disk.
    db_path = tmp_path / "tee.db"
    store = await RelayStore.open(str(db_path))
    peer: sqlite3.Connection | None = None
    try:
        peer = sqlite3.connect(db_path)
        peer.execute("SELECT COUNT(*) FROM relay_log").fetchall()  # attach to the WAL, no txn held
        await store.record_capture(direction="corepoint_copy", control_id="C5637", raw=_MARKER_BODY)
        assert _MARKER in _on_disk(db_path)  # positive control: the instrument sees the body
        assert await store.purge(captures_only=True) == (0, 1)
        assert _MARKER not in _on_disk(db_path)
        # The -wal holds at most the scrub record's own frame now, never a purged page.
        assert Path(f"{db_path}-wal").stat().st_size < 3 * 4096
    finally:
        if peer is not None:
            peer.close()
        await store.close()


@pytest.fixture
def fast_checkpoint_poll(monkeypatch: pytest.MonkeyPatch) -> None:
    """Two checkpoint tries with no sleep, so a pinned WAL fails in milliseconds rather than ~5 s."""
    monkeypatch.setattr(tee_store, "_CHECKPOINT_ATTEMPTS", 2)
    monkeypatch.setattr(tee_store, "_CHECKPOINT_POLL_SECONDS", 0.0)


@pytest.mark.usefixtures("fast_checkpoint_poll")
async def test_purge_refuses_to_report_clean_when_checkpoint_is_busy(tmp_path: Path) -> None:
    # A peer holding a read transaction pins the WAL, so a TRUNCATE checkpoint cannot finish. Purge
    # must say so rather than return counts that read as a clean purge.
    db_path = tmp_path / "tee.db"
    store = await RelayStore.open(str(db_path))
    peer: sqlite3.Connection | None = None
    try:
        await store.record_capture(direction="corepoint_copy", control_id="C5637", raw=_MARKER_BODY)
        peer = sqlite3.connect(db_path, isolation_level=None)
        peer.execute("BEGIN")
        peer.execute("SELECT COUNT(*) FROM relay_capture").fetchall()  # holds the read snapshot
        with pytest.raises(PurgeIncompleteError) as excinfo:
            await store.purge(captures_only=True)
        assert (excinfo.value.log_rows, excinfo.value.capture_rows) == (0, 1)
        assert _MARKER in _on_disk(db_path)  # the residue the error reports is really there
        peer.execute("COMMIT")
        # Once the reader lets go, the scrub-only recovery step finishes and removes the residue.
        await store.scrub()
        assert _MARKER not in _on_disk(db_path)
    finally:
        if peer is not None:
            peer.close()
        await store.close()


def test_purge_incomplete_error_round_trips_through_pickle() -> None:
    err = pickle.loads(pickle.dumps(PurgeIncompleteError(2, 3, "busy")))
    assert (err.log_rows, err.capture_rows, err.reason) == (2, 3, "busy")
    assert str(err) == str(PurgeIncompleteError(2, 3, "busy"))


@pytest.mark.usefixtures("fast_checkpoint_poll")
def test_purge_cli_reports_a_busy_checkpoint_as_an_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Sync test: tee's main() runs its own event loop.
    db_path = tmp_path / "tee.db"

    async def seed() -> None:
        store = await RelayStore.open(str(db_path))
        try:
            await store.record_capture(direction="corepoint_copy", control_id="C", raw=_MARKER_BODY)
        finally:
            await store.close()

    asyncio.run(seed())
    peer = sqlite3.connect(db_path, isolation_level=None)
    try:
        peer.execute("BEGIN")
        peer.execute("SELECT COUNT(*) FROM relay_capture").fetchall()
        rc = tee_main(["purge", "--db", str(db_path), "--captures-only", "-y"])
    finally:
        peer.close()
    assert rc == 1
    captured = capsys.readouterr()
    assert "error: deleted 0 log row(s) and 1 capture row(s)" in captured.err
    assert "purged " not in captured.out


async def test_secure_delete_is_fast(tmp_path: Path) -> None:
    store = await _open(tmp_path)
    try:
        async with store._db.execute("PRAGMA secure_delete") as cur:  # noqa: SLF001
            row = await cur.fetchone()
        assert row is not None and int(row[0]) == 2  # 2 is FAST
    finally:
        await store.close()


async def test_first_checkpoint_alone_scrubs_a_body_already_in_the_main_file(
    tmp_path: Path,
) -> None:
    # Pins secure_delete's share of the scrub, with no VACUUM: for a simple delete like this one,
    # delete plus commit plus the first TRUNCATE checkpoint leaves no purged bytes. It is not the
    # whole scrub; a rebalance can leave stale cell copies only VACUUM removes (see _scrub). The
    # body is checkpointed into the main file first, as a long-running relay's auto-checkpoint
    # would, so the residue under test is in the DB file, not the -wal.
    db_path = tmp_path / "tee.db"
    store = await RelayStore.open(str(db_path))
    try:
        await store.record_capture(direction="corepoint_copy", control_id="C5637", raw=_MARKER_BODY)
        assert await store._checkpoint_truncate()  # noqa: SLF001
        assert _MARKER in db_path.read_bytes()  # positive control: the body is in the main file
        await store._db.execute("DELETE FROM relay_capture WHERE 1")  # noqa: SLF001
        await store._db.commit()  # noqa: SLF001
        assert await store._checkpoint_truncate()  # noqa: SLF001
        assert _MARKER not in _on_disk(db_path)
    finally:
        await store.close()


def _spy_execute(
    store: RelayStore, monkeypatch: pytest.MonkeyPatch, fail_on: str, error: BaseException
) -> list[str]:
    """Make the store connection raise ``error`` on the SQL ``fail_on``; return the SQL it ran."""
    real_execute = store._db.execute  # noqa: SLF001
    ran: list[str] = []

    def execute(sql: str, *args: Any) -> Any:
        ran.append(sql)
        if sql == fail_on:
            raise error
        return real_execute(sql, *args)

    monkeypatch.setattr(store._db, "execute", execute)  # noqa: SLF001
    return ran


@pytest.mark.parametrize(
    "error", [sqlite3.OperationalError("disk I/O error"), MemoryError()], ids=["sqlite", "nomem"]
)
async def test_a_failed_vacuum_raises_after_still_running_the_checkpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: BaseException
) -> None:
    # VACUUM is part of the scrub (stale cell copies), so its failure is not a clean purge. CPython
    # raises MemoryError, not an sqlite3.Error, for SQLITE_NOMEM, so both must map.
    store = await _open(tmp_path)
    try:
        await store.record_capture(direction="corepoint_copy", control_id="C", raw=_MARKER_BODY)
        ran = _spy_execute(store, monkeypatch, "VACUUM", error)
        with pytest.raises(PurgeIncompleteError) as excinfo:
            await store.purge(captures_only=True)
        assert (excinfo.value.log_rows, excinfo.value.capture_rows) == (0, 1)
        assert excinfo.value.reason.startswith(f"VACUUM failed: {type(error).__name__}")
        after_vacuum = ran[ran.index("VACUUM") + 1 :]
        assert any("wal_checkpoint" in sql for sql in after_vacuum)  # it truncates spilled frames
    finally:
        await store.close()


async def test_an_sqlite_error_from_the_checkpoint_becomes_purge_incomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = await _open(tmp_path)
    try:
        await store.record_capture(direction="corepoint_copy", control_id="C", raw=_MARKER_BODY)
        _spy_execute(
            store,
            monkeypatch,
            "PRAGMA wal_checkpoint(TRUNCATE)",
            sqlite3.OperationalError("disk I/O error"),
        )
        with pytest.raises(PurgeIncompleteError) as excinfo:
            await store.purge(captures_only=True)
        assert excinfo.value.capture_rows == 1
        assert excinfo.value.reason == "the WAL checkpoint failed: OperationalError: disk I/O error"
        assert isinstance(excinfo.value.__cause__, sqlite3.OperationalError)
    finally:
        await store.close()


async def test_a_busy_checkpoint_after_vacuum_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # After VACUUM the old pages, stale cells included, stay in the main file until this checkpoint.
    store = await _open(tmp_path)
    try:
        await store.record_capture(direction="corepoint_copy", control_id="C", raw=_MARKER_BODY)
        results = iter([True, False])

        async def checkpoint() -> bool:
            return next(results)

        monkeypatch.setattr(store, "_checkpoint_truncate", checkpoint)
        with pytest.raises(PurgeIncompleteError) as excinfo:
            await store.purge(captures_only=True)
        assert excinfo.value.reason == "the WAL checkpoint after VACUUM stayed busy"
    finally:
        await store.close()


async def _set_journal_mode(store: RelayStore, mode: str) -> str:
    # Read the result and close the cursor: an unread PRAGMA statement left open makes SQLite refuse
    # the next journal-mode change silently, returning the old mode.
    async with store._db.execute(f"PRAGMA journal_mode={mode}") as cur:  # noqa: SLF001
        row = await cur.fetchone()
    assert row is not None
    return str(row[0])


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits; the Windows DACL half is open")
async def test_wal_siblings_recreated_after_open_inherit_owner_only_mode(tmp_path: Path) -> None:
    # Reviewed not-a-bug check for the POSIX half of #5637: SQLite creates -wal and -shm with the
    # main DB file's mode (unix VFS findCreateFileMode), so siblings re-created long after open's
    # chmod are 0600 even under a permissive umask. Switching the journal mode away and back removes
    # both siblings, and the next write re-creates them after _secure_file has already run.
    db_path = tmp_path / "tee.db"
    wal, shm = Path(f"{db_path}-wal"), Path(f"{db_path}-shm")
    old_umask = os.umask(0)
    try:
        store = await RelayStore.open(str(db_path))
        try:
            assert await _set_journal_mode(store, "DELETE") == "delete"
            assert not wal.exists() and not shm.exists()
            assert await _set_journal_mode(store, "WAL") == "wal"
            await store.record_capture(direction="corepoint_copy", control_id="C", raw=b"MSH|x")
            for sibling in (db_path, wal, shm):
                assert sibling.exists(), sibling
                assert stat.S_IMODE(sibling.stat().st_mode) == 0o600, sibling
        finally:
            await store.close()
    finally:
        os.umask(old_umask)


def _count_checkpoints(store: RelayStore, monkeypatch: pytest.MonkeyPatch) -> list[bool]:
    """Record each _checkpoint_truncate result, so a test can see whether the scrub ran at all."""
    real = store._checkpoint_truncate  # noqa: SLF001
    results: list[bool] = []

    async def counted() -> bool:
        results.append(await real())
        return results[-1]

    monkeypatch.setattr(store, "_checkpoint_truncate", counted)
    return results


@pytest.mark.usefixtures("fast_checkpoint_poll")
@pytest.mark.parametrize("seed_old_log_row", [False, True], ids=["zero-delete", "log-rows-only"])
async def test_only_a_purge_that_deleted_no_row_skips_the_scrub(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, seed_old_log_row: bool
) -> None:
    # A sweep that deleted no row must not VACUUM or contend with a reader. One that deleted only
    # log rows still scrubs, because a log row's detail keeps partner ACK text. The control: with
    # the same reader pinning the WAL, scrub() fails, so a purge that ran the scrub raises.
    db_path = tmp_path / "tee.db"
    store = await RelayStore.open(str(db_path))
    peer: sqlite3.Connection | None = None
    try:
        await store.record_capture(direction="corepoint_copy", control_id="C", raw=b"MSH|keep")
        if seed_old_log_row:
            await store._db.execute(  # noqa: SLF001
                "INSERT INTO relay_log (at,direction,leg,size_bytes,outcome) VALUES (?,?,?,?,?)",
                (1000.0, "epic_to_corepoint", "corepoint", 10, "accepted"),
            )
            await store._db.commit()  # noqa: SLF001
        await store.scrub()  # pays the one scrub a new DB owes, so nothing is owed now
        peer = sqlite3.connect(db_path, isolation_level=None)
        peer.execute("BEGIN")
        peer.execute("SELECT COUNT(*) FROM relay_capture").fetchall()  # pins the WAL
        checkpoints = _count_checkpoints(store, monkeypatch)
        if seed_old_log_row:
            with pytest.raises(PurgeIncompleteError) as excinfo:
                await store.purge(before=5000.0)
            assert (excinfo.value.log_rows, excinfo.value.capture_rows) == (1, 0)
            assert checkpoints and checkpoints[-1] is False  # the scrub ran and went busy
            return
        assert await store.purge(before=5000.0) == (0, 0)
        assert checkpoints == []  # the scrub never ran
        with pytest.raises(PurgeIncompleteError):  # control: the reader really pins the WAL
            await store.scrub()
        assert checkpoints and checkpoints[-1] is False  # it ran and went busy
    finally:
        if peer is not None:
            peer.close()
        await store.close()


async def test_a_vacuum_failure_is_kept_when_the_checkpoint_after_it_also_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = await _open(tmp_path)
    try:
        await store.record_capture(direction="corepoint_copy", control_id="C", raw=_MARKER_BODY)
        real_execute = store._db.execute  # noqa: SLF001
        seen = {"vacuum": False}

        def execute(sql: str, *args: Any) -> Any:
            if sql == "VACUUM":
                seen["vacuum"] = True
                raise sqlite3.OperationalError("database or disk is full")
            if seen["vacuum"] and "wal_checkpoint" in sql:
                raise sqlite3.OperationalError("disk I/O error")
            return real_execute(sql, *args)

        monkeypatch.setattr(store._db, "execute", execute)  # noqa: SLF001
        with pytest.raises(PurgeIncompleteError) as excinfo:
            await store.purge(captures_only=True)
        assert excinfo.value.reason == (
            "VACUUM failed: OperationalError: database or disk is full;"
            " then the WAL checkpoint after VACUUM failed: OperationalError: disk I/O error"
        )
        assert str(excinfo.value.__cause__) == "database or disk is full"
    finally:
        await store.close()


def test_scrub_only_cli_deletes_nothing_and_reports_a_busy_scrub(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tee_store, "_CHECKPOINT_ATTEMPTS", 2)
    monkeypatch.setattr(tee_store, "_CHECKPOINT_POLL_SECONDS", 0.0)
    db_path = tmp_path / "tee.db"

    async def seed() -> None:
        store = await RelayStore.open(str(db_path))
        try:
            await store.record_capture(direction="corepoint_copy", control_id="C", raw=b"MSH|keep")
        finally:
            await store.close()

    asyncio.run(seed())
    assert tee_main(["purge", "--db", str(db_path), "--scrub-only"]) == 0  # no -y needed
    assert f"scrubbed {db_path}" in capsys.readouterr().out
    peer = sqlite3.connect(db_path, isolation_level=None)
    try:
        peer.execute("BEGIN")
        assert peer.execute("SELECT COUNT(*) FROM relay_capture").fetchone() == (1,)  # kept
        assert tee_main(["purge", "--db", str(db_path), "--scrub-only"]) == 1
    finally:
        peer.close()
    assert "error: deleted 0 log row(s) and 0 capture row(s)" in capsys.readouterr().err
    assert tee_main(["purge", "--db", str(db_path), "--scrub-only", "--captures-only"]) == 2
    missing = tmp_path / "typo.db"
    assert tee_main(["purge", "--db", str(missing), "--scrub-only"]) == 2
    assert not missing.exists()  # refused, not created and reported as scrubbed
    assert "--db <the same DB> --scrub-only" in str(PurgeIncompleteError(0, 1, "busy"))


async def test_each_truncate_checkpoint_is_preceded_by_a_passive_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # PASSIVE copies the bulk of the WAL without the writer lock, so the TRUNCATE that follows holds
    # it only for what is left: a shorter stall for the live relay's writes.
    store = await _open(tmp_path)
    try:
        await store.record_capture(direction="corepoint_copy", control_id="C", raw=_MARKER_BODY)
        ran = _spy_execute(store, monkeypatch, fail_on="", error=RuntimeError())
        await store.purge(captures_only=True)
        checkpoints = [sql for sql in ran if "wal_checkpoint" in sql]
        assert (
            checkpoints
            == [
                "PRAGMA wal_checkpoint(PASSIVE)",
                "PRAGMA wal_checkpoint(TRUNCATE)",
            ]
            * 2  # before VACUUM and after it
        )
    finally:
        await store.close()


@pytest.mark.usefixtures("fast_checkpoint_poll")
async def test_rerun_finishes_a_busy_scrub_while_the_reader_still_holds_the_wal(
    tmp_path: Path,
) -> None:
    # The natural retry deletes nothing, but the residue the failed scrub left must still be
    # scrubbed, not reported as a clean purge. Here the peer stays open, so the -wal survives.
    db_path = tmp_path / "tee.db"
    store = await RelayStore.open(str(db_path))
    peer: sqlite3.Connection | None = None
    try:
        await store.record_capture(direction="corepoint_copy", control_id="C5637", raw=_MARKER_BODY)
        peer = sqlite3.connect(db_path, isolation_level=None)
        peer.execute("BEGIN")
        peer.execute("SELECT COUNT(*) FROM relay_capture").fetchall()  # pins the WAL
        with pytest.raises(PurgeIncompleteError):
            await store.purge(captures_only=True)
        peer.execute("COMMIT")
        assert _MARKER in _on_disk(db_path)  # positive control: residue before the retry
        assert await store.purge(captures_only=True) == (0, 0)
        assert _MARKER not in _on_disk(db_path)
    finally:
        if peer is not None:
            peer.close()
        await store.close()


async def test_a_large_delete_does_not_write_a_zeroed_frame_per_freed_page(tmp_path: Path) -> None:
    # With secure_delete=ON the delete itself wrote about as many WAL bytes as it freed, so a purge
    # to free space on a full volume failed before it committed. FAST leaves freed pages alone.
    db_path = tmp_path / "tee.db"
    store = await RelayStore.open(str(db_path))
    try:
        big = b"MSH|^~\\&|TEE|TEST\r" + b"Z" * (4 * 1024 * 1024)
        await store.record_capture(direction="corepoint_copy", control_id="C", raw=big)
        assert await store._checkpoint_truncate()  # noqa: SLF001
        await store._db.execute("DELETE FROM relay_capture WHERE 1")  # noqa: SLF001
        await store._db.commit()  # noqa: SLF001
        assert Path(f"{db_path}-wal").stat().st_size < 1024 * 1024
    finally:
        await store.close()


async def test_vacuum_runs_with_temp_store_file_then_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = await _open(tmp_path)
    try:
        await store.record_capture(direction="corepoint_copy", control_id="C", raw=_MARKER_BODY)
        ran = _spy_execute(store, monkeypatch, fail_on="", error=RuntimeError())
        await store.purge(captures_only=True)
        i = ran.index("VACUUM")
        assert ran[i - 1] == "PRAGMA temp_store=FILE"
        assert ran[i + 1] == "PRAGMA temp_store=DEFAULT"
    finally:
        await store.close()


def _owed(db_path: Path) -> bool:
    """Whether the scrub-pending record says a scrub is owed, read by a separate connection."""
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute("SELECT generation > scrubbed_through FROM scrub_state").fetchone()
        return row is None or bool(row[0])  # no record yet reads as one scrub owed, as in the store
    finally:
        conn.close()


@pytest.mark.usefixtures("fast_checkpoint_poll")
async def test_rerun_finishes_a_busy_scrub_after_the_reader_closed_and_removed_the_wal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The reviewer's reproduction: the reader that made the scrub busy closes last, which
    # checkpoints and deletes the -wal, so no residue hint is left. The flag still is.
    db_path = tmp_path / "tee.db"
    store = await RelayStore.open(str(db_path))
    peer = sqlite3.connect(db_path, isolation_level=None)
    try:
        await store.record_capture(direction="corepoint_copy", control_id="C5637", raw=_MARKER_BODY)
        peer.execute("BEGIN")
        peer.execute("SELECT COUNT(*) FROM relay_capture").fetchall()
        with pytest.raises(PurgeIncompleteError):
            await store.purge(captures_only=True)
        await store.close()
        peer.execute("COMMIT")
    finally:
        peer.close()
    assert not Path(f"{db_path}-wal").exists()  # the last close removed it: no hint left
    assert _owed(db_path)  # the record survived
    store = await RelayStore.open(str(db_path))
    try:
        ran = _spy_execute(store, monkeypatch, fail_on="", error=RuntimeError())
        assert await store.purge(captures_only=True) == (0, 0)
        assert "VACUUM" in ran
    finally:
        await store.close()
    assert not _owed(db_path)  # recorded as scrubbed once the scrub finished


async def test_rerun_finishes_a_scrub_whose_vacuum_failed_after_a_small_delete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "tee.db"
    store = await RelayStore.open(str(db_path))
    try:
        await store._db.execute(  # noqa: SLF001 - two log rows sharing one leaf page
            "INSERT INTO relay_log (at,direction,leg,size_bytes,outcome) VALUES"
            " (1000.0,'d','corepoint',1,'accepted'), (9000.0,'d','corepoint',1,'accepted')"
        )
        await store._db.commit()  # noqa: SLF001
        _spy_execute(
            store, monkeypatch, "VACUUM", sqlite3.OperationalError("database or disk is full")
        )
        with pytest.raises(PurgeIncompleteError):
            await store.purge(before=5000.0)  # deletes one row and frees no whole page
        monkeypatch.undo()
        ran = _spy_execute(store, monkeypatch, fail_on="", error=RuntimeError())
        assert await store.purge(before=5000.0) == (0, 0)
        assert "VACUUM" in ran
    finally:
        await store.close()
    assert not _owed(db_path)


async def test_a_purge_that_ran_alongside_a_scrub_keeps_its_scrub_pending_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Purge A's scrub is under way when purge B's delete lands (B's increment, made here by a second
    # connection just before A's VACUUM). A's finished scrub must not erase B's record.
    db_path = tmp_path / "tee.db"
    store = await RelayStore.open(str(db_path))
    peer = sqlite3.connect(db_path, isolation_level=None)
    try:
        await store.record_capture(direction="corepoint_copy", control_id="C", raw=_MARKER_BODY)
        real_execute = store._db.execute  # noqa: SLF001

        def execute(sql: str, *args: Any) -> Any:
            if sql == "VACUUM":
                peer.execute(BUMP)  # purge B's delete lands
            return real_execute(sql, *args)

        monkeypatch.setattr(store._db, "execute", execute)  # noqa: SLF001
        assert await store.purge(captures_only=True) == (0, 1)
        monkeypatch.undo()
    finally:
        peer.close()
        await store.close()
    assert _owed(db_path)  # B's record survives A's clear


@pytest.mark.usefixtures("fast_checkpoint_poll")
@pytest.mark.parametrize("owed", [True, False], ids=["owed", "not-owed"])
async def test_a_failed_scrub_only_leaves_the_record_as_it_was(tmp_path: Path, owed: bool) -> None:
    # An owed scrub stays owed when --scrub-only fails; one that was not owed creates no new
    # obligation by failing, so later sweeps are not stuck owing a scrub nothing needed.
    db_path = tmp_path / "tee.db"
    store = await RelayStore.open(str(db_path))
    peer: sqlite3.Connection | None = None
    try:
        await store.record_capture(direction="corepoint_copy", control_id="C", raw=b"MSH|keep")
        if not owed:
            await store.scrub()
        assert _owed(db_path) is owed
        peer = sqlite3.connect(db_path, isolation_level=None)
        peer.execute("BEGIN")
        peer.execute("SELECT COUNT(*) FROM relay_capture").fetchall()  # pins the WAL
        await store.record_capture(direction="corepoint_copy", control_id="C", raw=b"MSH|more")
        with pytest.raises(PurgeIncompleteError):
            await store.scrub()
        peer.execute("END")
    finally:
        if peer is not None:
            peer.close()
        await store.close()
    assert _owed(db_path) is owed


async def test_a_failed_scrub_record_logs_and_does_not_report_a_failed_purge(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    store = await _open(tmp_path)
    try:
        await store.record_capture(direction="corepoint_copy", control_id="C", raw=_MARKER_BODY)
        _spy_execute(
            store,
            monkeypatch,
            tee_store._RECORD_SCRUBBED,
            sqlite3.OperationalError("disk I/O error"),
        )  # noqa: SLF001
        with caplog.at_level(logging.WARNING, logger="tee.store"):
            assert await store.purge(captures_only=True) == (0, 1)
        assert "the scrub finished but recording it failed" in caplog.text
        monkeypatch.undo()
    finally:
        await store.close()
    assert _owed(tmp_path / "tee.db")  # the next purge scrubs again


async def test_a_stale_scrub_does_not_erase_a_later_purges_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The reviewer's three-purge interleaving. A deletes (generation 1) and its scrub starts from 1.
    # During A's VACUUM, B deletes and scrubs to completion (generation 2, scrubbed through 2), then
    # C deletes (generation 3). A then records its own scrub; C must still be owed.
    db_path = tmp_path / "tee.db"
    store = await RelayStore.open(str(db_path))
    peer = sqlite3.connect(db_path, isolation_level=None)
    try:
        await store.record_capture(direction="corepoint_copy", control_id="C", raw=_MARKER_BODY)
        real_execute = store._db.execute  # noqa: SLF001

        def execute(sql: str, *args: Any) -> Any:
            if sql == "VACUUM":
                peer.execute(BUMP)  # B's delete
                peer.execute("UPDATE scrub_state SET scrubbed_through = generation")  # B's scrub
                peer.execute(BUMP)  # C's delete
            return real_execute(sql, *args)

        monkeypatch.setattr(store._db, "execute", execute)  # noqa: SLF001
        assert await store.purge(captures_only=True) == (0, 1)
        monkeypatch.undo()
    finally:
        peer.close()
        await store.close()
    assert _owed(db_path)  # C's record survives A's stale clear


async def test_a_failure_after_the_delete_rolls_it_back_with_its_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The delete and its scrub-pending record are one transaction: if the record cannot be written,
    # the delete must not become durable through a later commit on the same store.
    db_path = tmp_path / "tee.db"
    store = await RelayStore.open(str(db_path))
    try:
        await store.record_capture(direction="corepoint_copy", control_id="C", raw=_MARKER_BODY)
        real_execute = store._db.execute  # noqa: SLF001

        def execute(sql: str, *args: Any) -> Any:
            if sql == BUMP:
                raise sqlite3.OperationalError("disk I/O error")
            return real_execute(sql, *args)

        monkeypatch.setattr(store._db, "execute", execute)  # noqa: SLF001
        with pytest.raises(sqlite3.OperationalError):
            await store.purge(captures_only=True)
        monkeypatch.undo()
        await _record(store)  # a later write on the same store commits
        assert await _count(store, "relay_capture") == 1  # the delete did not land
    finally:
        await store.close()


@pytest.mark.usefixtures("fast_checkpoint_poll")
async def test_a_sweep_that_deletes_nothing_and_owes_nothing_skips_beside_a_busy_reader(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The record alone decides: a non-empty -wal from relay writes is no reason to scrub.
    db_path = tmp_path / "tee.db"
    store = await RelayStore.open(str(db_path))
    peer: sqlite3.Connection | None = None
    try:
        await store.scrub()  # nothing owed from here
        await store.record_capture(direction="corepoint_copy", control_id="C", raw=b"MSH|keep")
        assert Path(f"{db_path}-wal").stat().st_size > 0  # relay writes left the -wal non-empty
        peer = sqlite3.connect(db_path, isolation_level=None)
        peer.execute("BEGIN")
        peer.execute("SELECT COUNT(*) FROM relay_capture").fetchall()  # pins the WAL
        checkpoints = _count_checkpoints(store, monkeypatch)
        assert await store.purge(before=0.0) == (0, 0)
        assert checkpoints == []
        peer.execute("END")
    finally:
        if peer is not None:
            peer.close()
        await store.close()


async def test_open_and_a_read_succeed_while_another_connection_holds_the_writer_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "tee.db"
    store = await RelayStore.open(str(db_path))
    await store.close()
    monkeypatch.setattr(tee_store, "_BUSY_TIMEOUT_MS", 200)  # fail fast if open needs the lock
    writer = sqlite3.connect(db_path, isolation_level=None)
    try:
        writer.execute("BEGIN IMMEDIATE")  # holds the writer lock, as a long purge would
        store = await RelayStore.open(str(db_path))
        try:
            assert await store.recent_naks() == []
        finally:
            await store.close()
    finally:
        writer.execute("ROLLBACK")
        writer.close()


async def test_a_failed_commit_rolls_the_delete_back_with_its_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = await _open(tmp_path)
    try:
        await store.record_capture(direction="corepoint_copy", control_id="C", raw=_MARKER_BODY)
        real_commit = store._db.commit  # noqa: SLF001
        calls = {"n": 0}

        async def commit() -> None:
            calls["n"] += 1
            if calls["n"] == 1:
                raise sqlite3.OperationalError("disk I/O error")
            await real_commit()

        monkeypatch.setattr(store._db, "commit", commit)  # noqa: SLF001
        with pytest.raises(sqlite3.OperationalError):
            await store.purge(captures_only=True)
        monkeypatch.undo()
        await _record(store)  # a later write on the same store commits
        assert await _count(store, "relay_capture") == 1  # the delete did not land
    finally:
        await store.close()


async def test_a_db_without_the_record_owes_one_scrub(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "tee.db"
    store = await RelayStore.open(str(db_path))
    await store.close()
    legacy = sqlite3.connect(db_path)
    legacy.execute("DROP TABLE scrub_state")  # a DB from before the record existed
    legacy.close()
    store = await RelayStore.open(str(db_path))
    try:
        ran = _spy_execute(store, monkeypatch, fail_on="", error=RuntimeError())
        assert await store.purge(before=0.0) == (0, 0)
        assert "VACUUM" in ran  # the one owed scrub
        ran.clear()
        assert await store.purge(before=0.0) == (0, 0)
        assert "VACUUM" not in ran  # owed once only
    finally:
        await store.close()


async def test_detail_escapes_c0_del_c1_and_bidi_controls_and_keeps_tab(tmp_path: Path) -> None:
    store = await _open(tmp_path)
    try:
        await _record(
            store, outcome="nak", ack_code="AE", detail="a\x00\x1b[31m\x7f\u0080\u202e\tb"
        )
        naks = await store.recent_naks()
        detail = naks[0].detail
        assert detail is not None
        assert detail.isascii()
        assert "\t" in detail  # tab is kept
        assert not any(ord(ch) < 0x20 and ch != "\t" for ch in detail)
        assert "\\u0080" in detail and "\\u202e" in detail  # stored as backslash escapes
    finally:
        await store.close()


def test_naks_output_survives_a_strict_cp1252_stdout(tmp_path: Path) -> None:
    # A partner's UTF-8 smart quote, decoded as latin-1 by the ACK reader, arrives as U+0080 and
    # U+0099. Unescaped, `tee naks > file` on a cp1252 console encoding raised UnicodeEncodeError.
    db_path = tmp_path / "tee.db"

    async def seed() -> None:
        store = await RelayStore.open(str(db_path))
        try:
            await _record(store, outcome="nak", ack_code="AE", detail="don\u00e2\u0080\u0099t")
        finally:
            await store.close()

    asyncio.run(seed())
    env = {**os.environ, "PYTHONIOENCODING": "cp1252:strict", "PYTHONUTF8": "0"}
    result = subprocess.run(
        [sys.executable, "-m", "tee", "naks", "--db", str(db_path)],
        capture_output=True,
        env=env,
        cwd=Path(__file__).resolve().parents[1],
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
    assert b"\\u0080\\u0099" in result.stdout  # the escaped detail reached the output


def test_naks_escapes_a_control_id_and_type_from_partner_bytes(tmp_path: Path) -> None:
    # MSH-10 and MSH-9 come from latin-1-decoded partner bytes too. Printed raw, a C1 code point in
    # either broke a strict cp1252 stdout, and an ESC sequence could drive the terminal.
    db_path = tmp_path / "tee.db"

    async def seed() -> None:
        store = await RelayStore.open(str(db_path))
        try:
            await _record(
                store,
                outcome="nak",
                ack_code="AE",
                control_id="C\u0080\u0099",
                message_type="ADT\x1b[31m",
            )
        finally:
            await store.close()

    asyncio.run(seed())
    env = {**os.environ, "PYTHONIOENCODING": "cp1252:strict", "PYTHONUTF8": "0"}
    result = subprocess.run(
        [sys.executable, "-m", "tee", "naks", "--db", str(db_path)],
        capture_output=True,
        env=env,
        cwd=Path(__file__).resolve().parents[1],
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
    assert b"\x1b" not in result.stdout
    assert b"control_id=C\\u0080\\u0099" in result.stdout


async def test_export_escapes_identifiers_but_the_store_keeps_them(tmp_path: Path) -> None:
    store = await _open(tmp_path)
    try:
        await _record(store, control_id="C\u0080", message_type="ADT\x1b[31m")
        row = (await store.export())["rows"][0]
        assert row["control_id"] == "C\\u0080"
        assert row["message_type"] == "ADT\\u001b[31m"
        cur = await store._db.execute("SELECT control_id FROM relay_log")  # noqa: SLF001
        stored = await cur.fetchone()
        assert stored is not None and stored["control_id"] == "C\u0080"  # kept for correlation
    finally:
        await store.close()


@pytest.mark.parametrize(
    "detail",
    ["\u0080" * 600, "a" * 499 + "\x00tail", "b" * 497 + "\U0001f600" * 3],
    ids=["all-c1", "control-at-the-cut", "astral-at-the-cut"],
)
async def test_detail_is_at_most_500_characters_after_escaping_and_never_cuts_an_escape(
    tmp_path: Path, detail: str
) -> None:
    store = await _open(tmp_path)
    try:
        await _record(store, outcome="nak", ack_code="AE", detail=detail)
        stored = (await store.recent_naks())[0].detail
        assert stored is not None
        assert len(stored) <= 500
        expected = "".join(tee_controlchars.scrub_control_chars(ch) for ch in detail)
        assert expected.startswith(stored)  # a prefix of whole escapes
        assert tee_controlchars.scrub_control_chars(stored) == stored  # no half escape left over
        # It ends where a whole escape of the original ends.
        ends, used = {0}, 0
        for ch in detail:
            used += len(tee_controlchars.scrub_control_chars(ch))
            ends.add(used)
        assert len(stored) in ends
    finally:
        await store.close()
