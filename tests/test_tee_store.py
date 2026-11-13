# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Unit tests for the tee relay's SQLite log (tee/store.py)."""

from __future__ import annotations

import os
import sqlite3
import stat
from pathlib import Path

import pytest

from tee.store import PurgeIncompleteError, RelayStore


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
    peer = sqlite3.connect(db_path)
    try:
        peer.execute("SELECT COUNT(*) FROM relay_log").fetchall()  # attach to the WAL, no txn held
        await store.record_capture(direction="corepoint_copy", control_id="C5637", raw=_MARKER_BODY)
        assert _MARKER in _on_disk(db_path)  # positive control: the instrument sees the body
        assert await store.purge(captures_only=True) == (0, 1)
        assert _MARKER not in _on_disk(db_path)
        assert Path(f"{db_path}-wal").stat().st_size == 0  # TRUNCATE checkpoint emptied the WAL
    finally:
        peer.close()
        await store.close()


async def test_purge_refuses_to_report_clean_when_checkpoint_is_busy(tmp_path: Path) -> None:
    # A peer holding a read transaction pins the WAL, so a TRUNCATE checkpoint cannot finish. Purge
    # must say so rather than return counts that read as a clean purge.
    db_path = tmp_path / "tee.db"
    store = await RelayStore.open(str(db_path))
    await store._db.execute("PRAGMA busy_timeout=0")  # noqa: SLF001 - keep the busy wait short
    await store.record_capture(direction="corepoint_copy", control_id="C5637", raw=_MARKER_BODY)
    peer = sqlite3.connect(db_path, isolation_level=None)
    try:
        peer.execute("BEGIN")
        peer.execute("SELECT COUNT(*) FROM relay_capture").fetchall()  # holds the read snapshot
        with pytest.raises(PurgeIncompleteError) as excinfo:
            await store.purge(captures_only=True)
        assert (excinfo.value.log_rows, excinfo.value.capture_rows) == (0, 1)
        peer.execute("COMMIT")
        # Once the reader lets go, a re-run completes and scrubs the residue.
        assert await store.purge(captures_only=True) == (0, 0)
        assert _MARKER not in _on_disk(db_path)
    finally:
        peer.close()
        await store.close()


async def test_secure_delete_is_on(tmp_path: Path) -> None:
    store = await _open(tmp_path)
    try:
        cur = await store._db.execute("PRAGMA secure_delete")  # noqa: SLF001 - test introspection
        row = await cur.fetchone()
        assert row is not None and int(row[0]) == 1
    finally:
        await store.close()


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits; the Windows DACL half is open")
async def test_wal_siblings_recreated_after_open_inherit_owner_only_mode(tmp_path: Path) -> None:
    # Reviewed not-a-bug check for the POSIX half of #5637: SQLite creates -wal and -shm with the
    # main DB file's mode (unix VFS findCreateFileMode), so siblings re-created long after open's
    # chmod are 0600 even under a permissive umask. Switching the journal mode away and back removes
    # both siblings, and the next write re-creates them after _secure_file has already run.
    db_path = tmp_path / "tee.db"
    old_umask = os.umask(0)
    try:
        store = await RelayStore.open(str(db_path))
        try:
            await store._db.execute("PRAGMA journal_mode=DELETE")  # noqa: SLF001
            assert not Path(f"{db_path}-wal").exists()
            await store._db.execute("PRAGMA journal_mode=WAL")  # noqa: SLF001
            await store.record_capture(direction="corepoint_copy", control_id="C", raw=b"MSH|x")
            for sibling in (db_path, Path(f"{db_path}-wal"), Path(f"{db_path}-shm")):
                assert sibling.exists(), sibling
                assert stat.S_IMODE(sibling.stat().st_mode) == 0o600, sibling
        finally:
            await store.close()
    finally:
        os.umask(old_umask)
