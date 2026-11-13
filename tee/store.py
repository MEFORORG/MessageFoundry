# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""SQLite log for the tee relay — its only store (the NAK log + an optional body capture).

Deliberately tiny: one row per forwarding **leg** (``corepoint`` / ``mefor``) recording the outcome
and the ACK code, so every NAK is durably captured and greppable (backlog #14's "log every NAK"). It
is an **audit/log**, not a durable retry queue — the relay is fail-closed, not store-and-forward.

PHI posture: the log stores message **identifiers** (MSH-10 control id, MSH-9 type) and **metadata**
(size, outcome, ACK code) — never message bodies. Its ``detail`` column, though, can carry at least
the partner's MSA-3 ACK text or a transport error string, and either can name a patient, so **every**
tee DB holds PHI at rest, capture on or off, and must live on a protected volume (the file is
``chmod 0600`` best-effort on open). The optional body capture (``--capture-bodies``) adds raw HL7
in a separate table and is **off by default**.
"""

from __future__ import annotations

import asyncio
import os
import sqlite3
import time
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import aiosqlite

__all__ = ["RelayStore", "NakRow", "CaptureRow", "PurgeIncompleteError"]

# Bound the stored detail (an MSA-3 reason or an error string) so a hostile/huge field can't bloat the
# log, and scrub control characters that could corrupt a terminal when an operator reads it back.
_MAX_DETAIL = 500

_SCHEMA = """
CREATE TABLE IF NOT EXISTS relay_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    at           REAL    NOT NULL,           -- epoch seconds
    direction    TEXT    NOT NULL,           -- 'epic_to_corepoint' | 'corepoint_copy'
    leg          TEXT    NOT NULL,           -- 'corepoint' | 'mefor'
    control_id   TEXT,                       -- MSH-10 (identifier, not PHI)
    message_type TEXT,                       -- MSH-9  (identifier, not PHI)
    size_bytes   INTEGER NOT NULL,
    outcome      TEXT    NOT NULL,           -- 'accepted' | 'nak' | 'transport_error'
    ack_code     TEXT,                       -- AA/AE/AR/CA/CE/CR or NULL
    detail       TEXT                        -- sanitized MSA-3 / error string (bounded); never a body
);
CREATE INDEX IF NOT EXISTS ix_relay_at  ON relay_log(at);
CREATE INDEX IF NOT EXISTS ix_relay_ack ON relay_log(ack_code);

CREATE TABLE IF NOT EXISTS relay_capture (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    at         REAL NOT NULL,
    direction  TEXT NOT NULL,
    control_id TEXT,
    raw        BLOB NOT NULL                 -- full message; ONLY written when --capture-bodies is on
);
CREATE INDEX IF NOT EXISTS ix_capture_at ON relay_capture(at);
"""

# An ACK code that means the partner rejected the message (vs AA/CA accepted). Used to flag NAK rows.
_NAK_CODES = ("AE", "AR", "CE", "CR")

# A TRUNCATE checkpoint takes the writer lock, copies the WAL back and waits for readers while
# holding it, so a long busy wait would stall the live relay's writes for as long. Purge instead
# polls with no busy wait, which releases the lock between tries, for about the store's usual 5 s
# busy_timeout in all, and runs a PASSIVE checkpoint first, which copies the bulk of the WAL
# without blocking writers. VACUUM itself still holds the writer lock for its whole rebuild, as it
# always has, so a purge that scrubs a large DB can still stall a live relay's writes past its 5 s.
_BUSY_TIMEOUT_MS = 5000
_CHECKPOINT_POLL_SECONDS = 0.1
_CHECKPOINT_ATTEMPTS = 50


class PurgeIncompleteError(RuntimeError):
    """The scrub after a purge's delete (or a ``scrub()`` run alone) did not finish, so purged
    bodies may still sit in the main DB file or its -wal file. ``reason`` names the step. Any
    counts are rows the run already deleted and committed; a ``scrub()`` run deletes none."""

    def __init__(self, log_rows: int, capture_rows: int, reason: str) -> None:
        self.log_rows = log_rows
        self.capture_rows = capture_rows
        self.reason = reason
        super().__init__(
            f"deleted {log_rows} log row(s) and {capture_rows} capture row(s), but the scrub did"
            f" not finish ({reason}), so purged bytes may remain in the DB file or its -wal file."
            " Run `python -m tee purge --db <the same DB> --scrub-only` once the cause is gone;"
            " docs/TEE-RELAY.md, Purge, says more."
        )

    def __reduce__(self) -> tuple[type[PurgeIncompleteError], tuple[int, int, str]]:
        # BaseException would rebuild from the message alone, which this __init__ does not take.
        return (type(self), (self.log_rows, self.capture_rows, self.reason))


def _describe(exc: BaseException) -> str:
    """An exception as ``Type: message``, or the bare type when it has no message (MemoryError)."""
    text = str(exc)
    return f"{type(exc).__name__}: {text}" if text else type(exc).__name__


@dataclass(frozen=True)
class NakRow:
    """A single logged NAK (or transport error), for the ``naks`` CLI readout."""

    at: float
    direction: str
    leg: str
    control_id: str | None
    message_type: str | None
    outcome: str
    ack_code: str | None
    detail: str | None


@dataclass(frozen=True)
class CaptureRow:
    """One captured full message **body** (PHI), for the #14 parity-comparison reader. Returned only by
    the explicit :meth:`RelayStore.captures` read — never by the body-free :meth:`RelayStore.export`."""

    at: float
    direction: str
    control_id: str | None
    raw: bytes


def _clean_detail(detail: str | None) -> str | None:
    """Scrub control characters and bound the length of a logged detail string."""
    if detail is None:
        return None
    cleaned = "".join(ch if ch >= " " or ch == "\t" else " " for ch in detail)
    return cleaned[:_MAX_DETAIL]


def _iso(at: float) -> str:
    """An epoch-seconds timestamp as a UTC ISO-8601 string (for human/AI-readable export)."""
    return datetime.fromtimestamp(at, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _is_nak(row: aiosqlite.Row) -> bool:
    """Whether a relay_log row is a NAK or transport error (the interesting rows for review)."""
    return row["outcome"] == "transport_error" or row["ack_code"] in _NAK_CODES


def _row_to_dict(row: aiosqlite.Row) -> dict[str, Any]:
    """One relay_log row as a plain JSON-able dict. Never a message body, but ``detail`` is
    emitted verbatim and can carry at least the partner's MSA-3 ACK text or a transport error string,
    and either can name a patient."""
    return {
        "at": row["at"],
        "at_iso": _iso(row["at"]),
        "direction": row["direction"],
        "leg": row["leg"],
        "control_id": row["control_id"],
        "message_type": row["message_type"],
        "size_bytes": row["size_bytes"],
        "outcome": row["outcome"],
        "ack_code": row["ack_code"],
        "detail": row["detail"],
    }


def _summarize(rows: list[aiosqlite.Row]) -> dict[str, Any]:
    """Aggregate counts over relay_log rows — the at-a-glance overview for a reviewer / AI."""
    by_leg: Counter[str] = Counter()
    by_outcome: Counter[str] = Counter()
    by_ack: Counter[str] = Counter()
    control_ids: set[str] = set()
    naks = 0
    ats: list[float] = []
    for row in rows:
        by_leg[row["leg"]] += 1
        by_outcome[row["outcome"]] += 1
        if row["ack_code"]:
            by_ack[row["ack_code"]] += 1
        if _is_nak(row):
            naks += 1
        if row["control_id"]:
            control_ids.add(row["control_id"])
        ats.append(row["at"])
    return {
        "total_legs": len(rows),
        "naks": naks,
        "distinct_control_ids": len(control_ids),
        "by_leg": dict(by_leg),
        "by_outcome": dict(by_outcome),
        "by_ack_code": dict(by_ack),
        "first_at": _iso(min(ats)) if ats else None,
        "last_at": _iso(max(ats)) if ats else None,
    }


def _precreate_secure(path: str) -> None:
    """Create the DB file with owner-only permissions *before* SQLite opens it, closing the brief
    window where SQLite would otherwise create it world-readable (POSIX umask). No-op if it exists."""
    if os.path.exists(path):
        return
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
    except OSError:
        # Race / permission / Windows quirks are non-fatal; _secure_file still chmods after open.
        pass


def _secure_file(path: str) -> None:
    """Best-effort owner-only permissions on the DB file **and its WAL/SHM siblings** (which WAL mode
    creates and which can hold message data when body capture is on).

    On POSIX a sibling SQLite re-creates later, after this one-time chmod, takes the main file's
    mode whatever the umask (the unix VFS copies it), so it is 0600 whenever the main file is,
    which holds only when _precreate_secure's 0600 create or this best-effort chmod succeeds;
    neither reports a failure. test_wal_siblings_recreated_after_open_inherit_owner_only_mode
    pins the inheritance. On Windows chmod sets only
    the read-only bit, so none of the three files is restricted to the owner here; that half is
    open (BACKLOG #5637) and the protected-volume advice below is the only control there today."""
    for sibling in (path, path + "-wal", path + "-shm"):
        try:  # noqa: SIM105 - suppress() would drop the rationale recorded in the handler below
            os.chmod(sibling, 0o600)
        except OSError:
            # Non-fatal: on some filesystems / Windows ACLs chmod is a partial no-op. Deployments that
            # enable body capture should place the DB on a protected volume regardless.
            pass


class RelayStore:
    """Async SQLite-backed relay log. Writes are serialized under a lock (single-writer SQLite)."""

    def __init__(self, db: aiosqlite.Connection, path: str) -> None:
        self._db = db
        self._path = path
        self._lock = asyncio.Lock()
        self._closed = False

    @classmethod
    async def open(cls, path: str) -> RelayStore:
        if path != ":memory:":
            _precreate_secure(
                path
            )  # create 0600 before SQLite opens it (closes the readable window)
        db = await aiosqlite.connect(path)
        db.row_factory = aiosqlite.Row
        await db.execute("PRAGMA journal_mode=WAL")
        await db.execute("PRAGMA synchronous=NORMAL")
        await db.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MS}")
        # Zero freed content instead of only unlinking it, so a deleted capture body leaves no
        # readable bytes in a free page. Per-connection, so set on the store's one connection.
        async with db.execute("PRAGMA secure_delete=ON"):
            pass
        await db.executescript(_SCHEMA)
        await db.commit()
        if path != ":memory:":
            _secure_file(path)
        return cls(db, path)

    async def record_leg(
        self,
        *,
        direction: str,
        leg: str,
        control_id: str | None,
        message_type: str | None,
        size_bytes: int,
        outcome: str,
        ack_code: str | None,
        detail: str | None,
    ) -> None:
        """Record the outcome of one forwarding leg (one row per attempt)."""
        async with self._lock:
            await self._db.execute(
                "INSERT INTO relay_log"
                " (at, direction, leg, control_id, message_type, size_bytes, outcome, ack_code, detail)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    time.time(),
                    direction,
                    leg,
                    control_id,
                    message_type,
                    size_bytes,
                    outcome,
                    ack_code,
                    _clean_detail(detail),
                ),
            )
            await self._db.commit()

    async def record_capture(self, *, direction: str, control_id: str | None, raw: bytes) -> None:
        """Persist a full message body (only called when body capture is enabled)."""
        async with self._lock:
            await self._db.execute(
                "INSERT INTO relay_capture (at, direction, control_id, raw) VALUES (?,?,?,?)",
                (time.time(), direction, control_id, raw),
            )
            await self._db.commit()

    async def captures(
        self,
        *,
        direction: str | None = None,
        since: float | None = None,
        before: float | None = None,
        limit: int | None = None,
    ) -> list[CaptureRow]:
        """Captured full message **bodies** (PHI) for the #14 parity comparison — typically the
        Corepoint-output rows (``direction='corepoint_copy'``) the compare tool diffs against MEFOR's
        transform output, carrying the MSH-10 control id for correlation.

        Unlike :meth:`export` (deliberately body-free), this returns raw bodies and is therefore
        **test-data-only**: never log it or redirect it to CI. ``direction``/``since``/``before`` narrow
        the window; ``limit`` caps to the most recent N. Ordered oldest-first. Filtering follows
        :meth:`export` — code-controlled clause literals with bound parameters, so the SQL stays safe.
        """
        clauses: list[str] = []
        params: list[Any] = []
        if direction is not None:
            clauses.append("direction = ?")
            params.append(direction)
        if since is not None:
            clauses.append("at >= ?")
            params.append(since)
        if before is not None:
            clauses.append("at < ?")
            params.append(before)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        async with self._lock:
            cur = await self._db.execute(
                "SELECT at, direction, control_id, raw FROM relay_capture"
                f"{where} ORDER BY at ASC, id ASC",
                tuple(params),
            )
            rows = list(await cur.fetchall())
        selected = rows[-limit:] if limit else rows
        return [
            CaptureRow(
                at=row["at"],
                direction=row["direction"],
                control_id=row["control_id"],
                raw=bytes(row["raw"]),
            )
            for row in selected
        ]

    async def recent_naks(self, limit: int = 50) -> list[NakRow]:
        """Return the most recent NAK / transport-error rows, newest first."""
        placeholders = ",".join("?" for _ in _NAK_CODES)
        async with self._lock:
            cur = await self._db.execute(
                "SELECT at, direction, leg, control_id, message_type, outcome, ack_code, detail"
                f" FROM relay_log WHERE outcome='transport_error' OR ack_code IN ({placeholders})"
                " ORDER BY at DESC LIMIT ?",
                (*_NAK_CODES, limit),
            )
            rows = await cur.fetchall()
        return [
            NakRow(
                at=row["at"],
                direction=row["direction"],
                leg=row["leg"],
                control_id=row["control_id"],
                message_type=row["message_type"],
                outcome=row["outcome"],
                ack_code=row["ack_code"],
                detail=row["detail"],
            )
            for row in rows
        ]

    async def _checkpoint_truncate(self) -> bool:
        """Copy every WAL frame into the main file and truncate the -wal to zero bytes.

        The result row is ``(busy, log, checkpointed)``; only ``busy == 0`` means the WAL was fully
        copied back and truncated. Polls with busy_timeout at 0 (see ``_CHECKPOINT_ATTEMPTS``)."""
        await self._pragma("busy_timeout=0")
        try:
            await self._pragma("wal_checkpoint(PASSIVE)")  # the bulk copy, without the writer lock
            for attempt in range(_CHECKPOINT_ATTEMPTS):
                async with self._db.execute("PRAGMA wal_checkpoint(TRUNCATE)") as cur:
                    row = await cur.fetchone()
                if row is not None and int(row[0]) == 0:
                    return True
                if attempt + 1 < _CHECKPOINT_ATTEMPTS:
                    await asyncio.sleep(_CHECKPOINT_POLL_SECONDS)
            return False
        finally:
            await self._pragma(f"busy_timeout={_BUSY_TIMEOUT_MS}")

    async def _scrub(self, log_rows: int, capture_rows: int) -> None:
        """TRUNCATE checkpoint, VACUUM, TRUNCATE checkpoint; raise if any of them does not finish.

        The first checkpoint writes the pages secure_delete zeroed back into the main file and
        empties the -wal. VACUUM is part of the scrub too: B-tree rebalancing can leave stale
        copies of a deleted cell in a page's unused space, which only its rebuild removes, and only
        once the second checkpoint writes the rebuilt pages over the old ones. That checkpoint runs
        even after a failed VACUUM, to truncate the frames the VACUUM spilled into the -wal.

        At least these raise :class:`PurgeIncompleteError`, with ``log_rows`` and
        ``capture_rows`` as the caller's deleted counts: a checkpoint that stays busy, and a
        ``sqlite3.Error`` or ``MemoryError`` (CPython's SQLITE_NOMEM) from VACUUM, a checkpoint or a
        PRAGMA. Anything else, such as a cancellation, propagates as raised.

        This is a file-level scrub. A TRUNCATE frees the -wal's blocks and VACUUM's checkpoint
        shrinks the DB file without overwriting either, so the bytes can stay in freed filesystem
        blocks, and nothing here reaches a copy or backup taken before the purge."""
        # temp_store stays at its default, so VACUUM may build its rebuilt copy in a temp file in
        # SQLite's temp directory, which may sit off the DB's volume. In memory, a large capture DB
        # would fail every purge with out of memory. docs/TEE-RELAY.md, Purge, says how an operator
        # points that directory at a protected volume.
        try:
            scrubbed = await self._checkpoint_truncate()
        except (sqlite3.Error, MemoryError) as exc:
            raise PurgeIncompleteError(
                log_rows, capture_rows, f"the WAL checkpoint failed: {_describe(exc)}"
            ) from exc
        if not scrubbed:
            raise PurgeIncompleteError(log_rows, capture_rows, "the WAL checkpoint stayed busy")
        failures: list[str] = []
        cause: BaseException | None = None
        try:
            async with self._db.execute("VACUUM"):
                pass
        except (sqlite3.Error, MemoryError) as exc:
            failures.append(f"VACUUM failed: {_describe(exc)}")
            cause = exc
        try:  # runs even after a failed VACUUM, to truncate the frames it spilled
            if not await self._checkpoint_truncate():
                failures.append("the WAL checkpoint after VACUUM stayed busy")
        except (sqlite3.Error, MemoryError) as exc:
            failures.append(f"the WAL checkpoint after VACUUM failed: {_describe(exc)}")
            cause = cause or exc
        if failures:
            raise PurgeIncompleteError(log_rows, capture_rows, "; then ".join(failures)) from cause

    async def scrub(self) -> None:
        """Run the scrub alone, deleting nothing: the recovery step after a purge whose scrub did
        not finish. Raises :class:`PurgeIncompleteError` (with zero counts) as :meth:`_scrub` says."""
        async with self._lock:
            await self._scrub(0, 0)

    async def _pragma(self, setting: str) -> None:
        # Close the cursor: aiosqlite keeps an unclosed one's statement in progress, which makes a
        # later VACUUM fail ("SQL statements in progress") or a journal-mode change silently refuse.
        async with self._db.execute(f"PRAGMA {setting}"):
            pass

    async def purge(
        self, *, before: float | None = None, captures_only: bool = False
    ) -> tuple[int, int]:
        """Delete logged rows + captured bodies, then scrub deleted bodies from the DB and -wal files.

        ``before=None`` purges **everything**; ``before=<epoch>`` purges only rows older than it.
        ``captures_only`` leaves the relay_log (the NAK/leg audit) intact and drops only the captured
        message bodies (the PHI-bearing table). Returns ``(relay_log rows, relay_capture rows)`` deleted.

        In WAL mode a delete writes new pages to the -wal file and leaves the old frames, body
        bytes included, on disk until a checkpoint, so once the delete commits, a run that deleted
        any row runs :meth:`_scrub`, which raises :class:`PurgeIncompleteError` with the deleted
        counts if the scrub does not finish. Returning the counts then would read as a clean purge
        that did not happen. relay_log rows count too: their ``detail`` keeps the partner's MSA-3
        text, which can name a patient. A run that deleted no row skips the scrub, since it freed
        nothing to scrub, and a routine sweep should not rewrite the DB or contend with a reader
        for nothing. :meth:`scrub` runs the scrub alone, to recover.
        """
        async with self._lock:
            # NB: a bare `DELETE FROM t` (no WHERE) hits SQLite's truncate optimization, which makes
            # rowcount inaccurate (0). `WHERE 1` deletes row-by-row so the returned count is real.
            if before is None:
                cap = await self._db.execute("DELETE FROM relay_capture WHERE 1")
                log = (
                    None
                    if captures_only
                    else await self._db.execute("DELETE FROM relay_log WHERE 1")
                )
            else:
                cap = await self._db.execute("DELETE FROM relay_capture WHERE at < ?", (before,))
                log = (
                    None
                    if captures_only
                    else await self._db.execute("DELETE FROM relay_log WHERE at < ?", (before,))
                )
            cap_n = cap.rowcount
            log_n = 0 if log is None else log.rowcount
            await self._db.commit()
            if log_n or cap_n:
                await self._scrub(log_n, cap_n)
        return (log_n, cap_n)

    async def export(
        self,
        *,
        since: float | None = None,
        before: float | None = None,
        naks_only: bool = False,
        limit: int | None = None,
    ) -> dict[str, Any]:
        """A **body-free, structured** snapshot of the relay LOG for review / AI analysis.

        Returns ``{"summary": {...}, "rows": [...]}`` — never the captured message **bodies** (only the
        leg metadata: outcomes, ACK codes, control ids, types, sizes, details). It is **not**
        PHI-safe: ``detail`` is emitted verbatim (control characters scrubbed, 500 characters at
        most) and can carry at least the partner's MSA-3 ACK text or a transport error string,
        and either can name a patient, so treat an export as PHI. The summary
        aggregates the whole time window; ``rows`` is optionally narrowed to NAKs and the most-recent
        ``limit``. Filtering is done in Python (the log is small), so the SQL stays static."""
        async with self._lock:
            cur = await self._db.execute(
                "SELECT at, direction, leg, control_id, message_type, size_bytes, outcome, ack_code,"
                " detail FROM relay_log ORDER BY at ASC"
            )
            all_rows = list(await cur.fetchall())
        window = [
            row
            for row in all_rows
            if (since is None or row["at"] >= since) and (before is None or row["at"] < before)
        ]
        selected = [row for row in window if _is_nak(row)] if naks_only else window
        if limit:
            selected = selected[-limit:]  # the most recent N
        return {"summary": _summarize(window), "rows": [_row_to_dict(row) for row in selected]}

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        await self._db.close()
