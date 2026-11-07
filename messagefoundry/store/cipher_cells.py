# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Each store's cipher-covered cells, declared as data (BACKLOG #1719, ASVS 11.3.3).

``MessageStore._CIPHER_COLUMNS`` lists the cipher-covered cells whose AAD binds to the row ``id``. The
rest bind to a composite or natural key, so each has its own migration and rotation pass inside the
store, and until this module no caller outside it could read them back. This module names those cells
and the columns each writer binds into ``cell_aad``, in the order it binds them, and joins both kinds
into :data:`SQLITE_CIPHER_CELLS`. :data:`POSTGRES_CIPHER_CELLS` and :data:`SQLSERVER_CIPHER_CELLS`
are the same cells as each server store seals them, paged by primary key. The full restore-verify
reads every sealed value in them back through the cipher, so a ciphertext whose tag no longer
authenticates fails the verify instead of surfacing at first use. It also reads the non-blank values
with no marker, so a text value whose marker itself is damaged fails it on a surface the keyed store
has sealed.

:func:`read_cipher_cells` is the one walk over a SQLite store's cells, and
:func:`read_server_cipher_cells` its twin for a server store. The restore-verify stops at its first
failure; :func:`audit_cipher_cells`, behind ``messagefoundry cipher-audit``, reads a LIVE store with
it to the end and also counts, in a keyed store, the non-blank text values that carry no marker,
which is where a damaged marker lands.

It is READ-ONLY: nothing here writes a cell, and the store's own passes do not consume it. Driving
every pass from one declaration is BACKLOG #1169's scope, not this one's. Until then two guards keep
this list honest. ``tests/test_store_cipher_sweep_parity.py`` fails when ``store.py`` gains a composite
cipher cell this module does not name, and ``tests/test_cipher_cells_readback.py`` does the same for
``postgres.py`` and ``sqlserver.py`` against their inventories. ``tests/test_cipher_cells_readback.py``
also writes each cell through the real store writer, proves the AAD here opens it, and proves a
flipped byte fails it.
"""

from __future__ import annotations

import asyncio
import sqlite3
from collections.abc import AsyncGenerator, Callable, Generator, Iterable, Mapping, Sequence
from contextlib import aclosing
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Literal, Protocol

from messagefoundry.redaction import safe_exc
from messagefoundry.store.cell_tag import is_row_tagged, row_tag_aad, row_tag_columns
from messagefoundry.store.crypto import MARKER_PREFIX, Cipher, CipherError, cell_aad
from messagefoundry.store.queue_tag import QUEUE_TAG_COLUMNS, QueueTagError, queue_row_aad
from messagefoundry.store.store import MessageStore, _sqlite_readonly_uri

__all__ = [
    "COMPOSITE_CIPHER_CELLS",
    "DEFAULT_CHUNK_ROWS",
    "POSITION",
    "POSTGRES_CIPHER_CELLS",
    "SQLITE_CIPHER_CELLS",
    "SQLSERVER_CIPHER_CELLS",
    "CellReading",
    "CellTally",
    "CipherAudit",
    "CipherCell",
    "CipherCellSource",
    "CipherWalkInterrupted",
    "audit_cipher_cells",
    "audit_server_cipher_cells",
    "cell_present",
    "connect_readonly",
    "keyed_store_mismatch",
    "read_cipher_cells",
    "read_server_cipher_cells",
    "server_cell_present",
    "server_keyed_store_mismatch",
    "server_walk_tables",
    "store_tables",
    "with_first_failure",
]


@dataclass(frozen=True, slots=True)
class CipherCell:
    """One cipher-covered cell: its table, its column, and the columns its AAD binds, in bind order.

    ``locator`` is the columns a failure message may name to point an operator at the row: a
    synthetic id, or a key made only of ids, names and counters. Otherwise it is the snapshot's own
    ``rowid``, which a VACUUM may have renumbered, so it locates the row in the snapshot and not
    necessarily in the live store. A key column is never a locator when it can itself be PHI: a
    ``state`` or ``reference`` key is whatever the transform chose, and ``shared_body.hash`` and
    ``attachment_chunk.attachment_id`` are digests of the plaintext.

    ``builder`` is for a cell whose AAD is not ``cell_aad(table, column, *key)``: it takes the
    ``aad_columns`` values in order and returns the AAD (the queue payload's routing tag).

    ``check`` is for a cell whose reader refuses a value that opened: it takes the opened value and
    the ``aad_columns`` values, and raises :class:`CipherError` where that reader would (the queue
    payload's sealed ``shared_body`` reference against its ``body_ref`` column).

    ``order`` is the columns a server-store walk pages by, the table's primary key (a server table
    has no ``rowid``); the SQLite walk pages by ``rowid`` and does not read it. On a server cell
    the ``"position"`` locator stands where SQLite's ``rowid`` does: the value's 1-based place
    among the cell's non-NULL values in ``order``, which a later write may shift.

    ``chunk_cap`` bounds a server walk's chunk for a cell whose rows are large, since a server
    driver fetches a whole chunk at once where SQLite reads it one row at a time."""

    table: str
    column: str
    aad_columns: tuple[str, ...]
    locator: tuple[str, ...] = ("rowid",)
    builder: Callable[..., bytes] | None = None
    check: Callable[..., None] | None = None
    order: tuple[str, ...] = ("rowid",)
    chunk_cap: int | None = None

    def aad(self, *key: object) -> bytes:
        """The AAD the writer bound for this cell, given the ``aad_columns`` values in order."""
        if self.builder is not None:
            return self.builder(*key)
        return cell_aad(self.table, self.column, *key)

    def locate(self, *values: object) -> str:
        """The row's ``locator`` values as ``column=value`` pairs, for a PHI-free failure message.

        A value is read from the store, and a planted row is one thing a cipher read hunts for, so
        each is cut to :data:`_LOCATOR_LIMIT` characters and a control character is escaped: a
        locator cannot forge a line of the report or carry a long value out whole."""
        return " ".join(f"{c}={_shown(v)}" for c, v in zip(self.locator, values, strict=True))


#: The most characters of one locator value a report quotes. Synthetic ids are far shorter.
_LOCATOR_LIMIT = 64


def _shown(value: object) -> str:
    text = str(value)
    if len(text) > _LOCATOR_LIMIT:
        text = text[:_LOCATOR_LIMIT] + "..."
    return text if text.isprintable() else text.encode("unicode_escape").decode("ascii")


_RESPONSE_KEY = ("message_id", "destination_name", "response_seq")


def _queue_payload_aad(*values: object) -> bytes:
    """The queue payload's routing tag from the :data:`QUEUE_TAG_COLUMNS` values (BACKLOG #2593)."""
    return queue_row_aad(dict(zip(QUEUE_TAG_COLUMNS, values, strict=True)))


def _queue_payload_check(opened: str, *values: object) -> None:
    """What ``open_queue_cell`` refuses in a payload that opened: a store-once row whose sealed
    ``shared_body`` key differs from its ``body_ref`` column. ``body_ref`` is not in the tag, so the
    tag alone cannot catch a row pointed at another body."""
    body_ref = dict(zip(QUEUE_TAG_COLUMNS, values, strict=True))["body_ref"]
    if body_ref is not None and opened != body_ref:
        raise QueueTagError("integrity: the queue row's sealed reference differs from its body_ref")


def _id_keyed_cell(table: str, column: str) -> CipherCell:
    """An id-keyed cell. A message cell binds its channel and a preset's criteria its owner as well
    (BACKLOG #2593), so those take their tag's columns and builder."""
    if not is_row_tagged(table, column):
        return CipherCell(table, column, ("id",), locator=("id",))
    columns = row_tag_columns(table, column)

    def build(*values: object) -> bytes:
        return row_tag_aad(table, column, dict(zip(columns, values, strict=True)))

    return CipherCell(table, column, columns, locator=("id",), builder=build)


#: Every literal ``cell_aad`` cell in ``store.py`` that ``_CIPHER_COLUMNS`` does not carry. The AAD columns
#: are copied from each cell's writer, and the round-trip test proves they match it.
COMPOSITE_CIPHER_CELLS: tuple[CipherCell, ...] = (
    # A message id, a connection name and a counter: nothing in this key is PHI, so it is the locator.
    CipherCell("response", "body", _RESPONSE_KEY, locator=_RESPONSE_KEY),
    CipherCell("response", "detail", _RESPONSE_KEY, locator=_RESPONSE_KEY),
    CipherCell("response", "resp_headers", _RESPONSE_KEY, locator=_RESPONSE_KEY),
    CipherCell("state", "value", ("namespace", "key")),
    CipherCell("reference", "value", ("name", "version", "key")),
    CipherCell("shared_body", "body", ("hash",)),
    CipherCell("attachment_chunk", "ciphertext", ("attachment_id", "seq")),
    # The queue payload binds the row's routing fields, not its id alone (BACKLOG #2593).
    CipherCell(
        "queue",
        "payload",
        QUEUE_TAG_COLUMNS,
        locator=("id",),
        builder=_queue_payload_aad,
        check=_queue_payload_check,
    ),
    # These three have an AUTOINCREMENT id the encrypting INSERT cannot know, so their AAD binds the
    # natural columns the writer has in hand instead. alert_instance binds only its de-dup grain, which
    # its resolved and open rows can share, so a reason moved between those rows still opens.
    CipherCell("message_events", "detail", ("message_id", "ts", "event"), locator=("id",)),
    CipherCell("connection_event", "reason", ("connection", "ts", "kind"), locator=("id",)),
    CipherCell("alert_instance", "reason", ("event_type", "connection"), locator=("id",)),
)

#: Every cipher-covered cell of the SQLite store: the id-keyed ones from the store's own tuple, then
#: the composite ones above.
SQLITE_CIPHER_CELLS: tuple[CipherCell, ...] = (
    *(_id_keyed_cell(t, c) for t, c in MessageStore._CIPHER_COLUMNS),
    *COMPOSITE_CIPHER_CELLS,
)

#: The pseudo-locator of a server cell whose key can itself be PHI; see :class:`CipherCell`.
POSITION = "position"

#: Rows a server walk reads per chunk of ``attachment_chunk``: each row is one 1 MiB slice, so the
#: usual chunk would hold hundreds of MiB at once. The store's own seal pass batches it the same.
_ATTACHMENT_CHUNK_ROWS = 16

#: The id-keyed cells both server stores seal. Neither server module keeps one tuple of them that
#: this could import (SQL Server spells its list inline in ``_encrypt_existing_rows``), so they are
#: declared here and pinned to each module's ``cell_aad`` calls by a test.
_SERVER_ID_KEYED: tuple[tuple[str, str], ...] = (
    ("messages", "raw"),
    ("messages", "error"),
    ("queue", "last_error"),
    ("messages", "summary"),
    ("messages", "metadata"),
    ("users", "totp_secret"),
    ("search_presets", "criteria"),
)

#: The server stores' composite cells: SQLite's, with each table's primary key to page by, and a
#: ``position`` locator wherever SQLite falls back to ``rowid``.
_SERVER_ORDER: dict[str, tuple[str, ...]] = {
    "response": _RESPONSE_KEY,
    "state": ("namespace", "key"),
    "reference": ("name", "version", "key"),
    "shared_body": ("hash",),
    "attachment_chunk": ("attachment_id", "seq"),
}


def _server_cell(cell: CipherCell) -> CipherCell:
    """``cell`` as a server walk reads it: paged by its table's primary key, and located by
    ``position`` where SQLite's ``rowid`` stood."""
    locator = (POSITION,) if cell.locator == ("rowid",) else cell.locator
    cap = _ATTACHMENT_CHUNK_ROWS if cell.table == "attachment_chunk" else None
    return replace(
        cell, locator=locator, order=_SERVER_ORDER.get(cell.table, ("id",)), chunk_cap=cap
    )


def _server_cells() -> tuple[CipherCell, ...]:
    return tuple(
        _server_cell(c)
        for c in (*(_id_keyed_cell(t, c) for t, c in _SERVER_ID_KEYED), *COMPOSITE_CIPHER_CELLS)
    )


#: Every cipher-covered cell of the PostgreSQL store. ``tests/test_cipher_cells_readback.py`` pins
#: it to every ``cell_aad`` cell in ``postgres.py``, so a new ciphered column there reds until it is
#: listed here.
POSTGRES_CIPHER_CELLS: tuple[CipherCell, ...] = _server_cells()

#: Every cipher-covered cell of the SQL Server store, pinned to ``sqlserver.py`` the same way.
SQLSERVER_CIPHER_CELLS: tuple[CipherCell, ...] = _server_cells()

#: Rows one statement of :func:`read_cipher_cells` reads. Each chunk is its own short read
#: transaction, so a walk of a live store never holds one snapshot open across a whole table.
DEFAULT_CHUNK_ROWS = 500

#: What :func:`read_cipher_cells` found at one value; see :class:`CellReading`.
ReadingKind = Literal["opened", "failed", "blob", "keyless", "unmarked", "legacy"]


class CipherWalkInterrupted(RuntimeError):
    """The store's schema changed part way through a walk, so its ``rowid`` chunks no longer line
    up: a VACUUM, which the retention runner schedules, may renumber the rowids of a table with no
    INTEGER PRIMARY KEY, and a later chunk would then skip rows or read some twice. Raised rather
    than finishing on a subset that would read as a clean store."""


@dataclass(frozen=True, slots=True)
class CellReading:
    """What :func:`read_cipher_cells` found at one value of one cell.

    ``kind`` is ``"opened"`` when the value decrypted and authenticated, ``"failed"`` when it did
    not or its reader would refuse it (``error`` says why), ``"blob"`` for a BLOB, which is a
    failure under any cipher and never a key question (see :func:`_sealed_test`), and
    ``"keyless"`` when it is sealed text and the cipher holds no key, so nothing could have opened
    it. Two kinds are reported only when the
    walk is asked for unmarked values: ``"unmarked"``, a non-blank text value with no marker on a
    surface the store has sealed, which it refuses at read, and ``"legacy"``, the same on a surface
    no keyed open has sealed yet, which the next keyed open seals. ``values`` are the cell's
    ``locator`` values: never a plaintext, and never a key column that can itself be PHI."""

    cell: CipherCell
    kind: ReadingKind
    values: tuple[object, ...]
    error: CipherError | None = None
    #: A failed value whose marker names a key the cipher's keyring does not hold. Still a
    #: failure: a damaged key id reads the same way, and corruption must not be talked down.
    foreign_key: bool = False

    @property
    def where(self) -> str:
        """The row's locator, as ``column=value`` pairs."""
        return self.cell.locate(*self.values)

    def failure(self, *, source: str = "store") -> str:
        """The PHI-free line a failed, BLOB or keyless value is reported with: table, column and
        locator, and for a failure the redacted cipher error, never the value. ``source`` names
        what was read in the keyless line: the live store, or a restore-verify's snapshot."""
        name = f"{self.cell.table}.{self.cell.column}"
        if self.kind == "keyless":
            return (
                f"{name} is encrypted at rest but the store settings resolved no key "
                f"to open it (keyless open of an encrypted {source})"
            )
        if self.kind == "blob":
            return (
                f"{name} {self.where} holds a BLOB where the store writes only text: a planted or "
                "damaged row, which no key makes readable"
            )
        reason = safe_exc(self.error) if self.error is not None else self.kind
        if self.foreign_key:
            reason += (
                "; its marker names a key these settings do not hold, so a shell without the "
                "service's key, or a damaged key id, reads this way"
            )
        return f"{name} {self.where} did not decrypt: {reason}"


def store_tables(conn: sqlite3.Connection) -> set[str]:
    """The tables the store at ``conn`` has."""
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def cell_present(conn: sqlite3.Connection, spec: CipherCell, tables: set[str]) -> bool:
    """Whether the store has ``spec``'s table and every column the walk selects for it. An older
    store may predate a cell; its values cannot be read, and a report must not call it empty."""
    if spec.table not in tables:
        return False
    names = {r[1] for r in conn.execute(f"PRAGMA table_info({spec.table})")}  # declared constant
    return names.issuperset({spec.column, *spec.aad_columns, *spec.locator} - {"rowid"})


def _surface_sealed(conn: sqlite3.Connection, spec: CipherCell, tables: set[str]) -> bool:
    """Whether the store has sealed ``spec``'s surface, by the rule its at-open sweep applies
    (BACKLOG #3383): a ``keyed_surface`` row for it, or at least one marked value in it. On a
    sealed surface the store refuses an unmarked value at read; on an unsealed one the next keyed
    open seals it as legacy plaintext."""
    if (
        "keyed_surface" in tables
        and conn.execute(
            "SELECT 1 FROM keyed_surface WHERE surface_table = ? AND surface_column = ?",
            (spec.table, spec.column),
        ).fetchone()
    ):
        return True
    # The store's own test, LIKE as `_surface_holds_ciphertext` spells it, not `_sealed_test`: this
    # answers what the store will do, so it must read the surface the way the store reads it.
    marked = conn.execute(
        f"SELECT 1 FROM {spec.table} WHERE {spec.column} LIKE ? LIMIT 1",  # declared constants
        (f"{MARKER_PREFIX}%",),
    ).fetchone()
    return marked is not None


def _sealed_test(column: str) -> tuple[str, tuple[object, ...]]:
    """The SQL test that calls a value of ``column`` sealed, and the parameters it takes, which
    travel together so a caller cannot bind one without the other.

    A text value is sealed when it starts with the marker in any ASCII case, as ``LIKE 'mfenc:%'``
    reads it on a default build. LIKE itself is not used, because what it does depends at least on
    the build and the connection: ``SQLITE_LIKE_DOESNT_MATCH_BLOBS`` (Ubuntu's SQLite has it, the
    Windows one does not) makes it skip every BLOB, and ``SQLITE_CASE_SENSITIVE_LIKE`` or ``PRAGMA
    case_sensitive_like`` makes it skip ``MFENC:``. A value it skipped would never be read at all.

    Every BLOB is called sealed, by its type, ``x''`` included, and the walk reports it as a
    ``"blob"`` reading under any cipher, without a decrypt: it fails closed on a BLOB on every
    build. At least the store's own writer, ``_enc``, binds text, so a BLOB is a planted or damaged
    row, and the walk fails it for that, whatever the store's reader would do with it. That varies:
    under a key the reader cannot open one; with no key it hands one back as bytes, which some
    readers take (a JSON-shaped ``state`` BLOB loads) and others refuse. No key is the remedy, so
    a BLOB is never reported as a key mismatch."""
    sql = f"(typeof({column}) = 'blob' OR lower(substr({column}, 1, ?)) = ?)"
    return sql, (len(MARKER_PREFIX), MARKER_PREFIX.lower())


def _schema_version(conn: sqlite3.Connection) -> int:
    return int(conn.execute("PRAGMA schema_version").fetchone()[0])


def read_cipher_cells(
    conn: sqlite3.Connection,
    cipher: Cipher,
    *,
    cells: Iterable[CipherCell] = SQLITE_CIPHER_CELLS,
    chunk_rows: int = DEFAULT_CHUNK_ROWS,
    unmarked: bool = False,
) -> Generator[CellReading]:
    """Read every sealed value in ``cells`` back through ``cipher``, yielding one reading per value.

    Each value is opened with the AAD its writer bound (ASVS 11.3.3), so a ciphertext moved between
    cells fails its tag here as it would at a live read, and then put through the cell's ``check``.
    A cell :func:`cell_present` says the store lacks is skipped: an older store predates it.

    Which values are sealed is :func:`_sealed_test`'s; :func:`_open` says which of them fail
    without a decrypt.

    The rows of each cell are read in ``rowid`` order, ``chunk_rows`` at a time. Each chunk is one
    statement, read one row at a time and opened as it is read, and its readings are yielded only
    once the statement is closed. So no read transaction stays open while the caller works, a
    writer on a live store waits on at most one chunk's decrypts, and memory holds one stored value
    at a time. The schema version is read after every chunk; a change raises
    :class:`CipherWalkInterrupted`. A decrypt that failed because the key service did
    (:func:`_is_outage`) ends the walk after its reading is yielded.

    ``unmarked`` also yields every non-blank text value with no marker, in a keyed store only, as
    ``"unmarked"`` or ``"legacy"`` by whether the store has sealed that surface (see
    :class:`CellReading`). A walk selecting by the marker alone never reads such a value, which is
    where a damaged or stripped marker, or a planted row, lands. NULL and the text ``''`` are never
    reported: every purge path writes ``''``. In a keyless store every text value is plaintext, so
    none is.

    The cipher decides keylessness, never a value: a decrypted value may itself begin with the
    marker. Under ``vault_transit`` every decrypt is one Transit request."""
    if chunk_rows < 1:
        raise ValueError(f"chunk_rows must be at least 1, not {chunk_rows}")
    keyless = not cipher.encrypts
    unmarked = unmarked and not keyless
    version = _schema_version(conn)
    tables = store_tables(conn)
    for spec in cells:
        if not cell_present(conn, spec, tables):
            continue
        table, column = spec.table, spec.column
        unsealed_kind: ReadingKind = "unmarked"
        if unmarked and not _surface_sealed(conn, spec, tables):
            unsealed_kind = "legacy"
        # Table, column and key names are declared constants; only values are parameters. The
        # sealed test is selected, not applied to the value in Python, so a value is judged by the
        # same test that selects it. Selecting by it, every row is sealed, so the column is `1`.
        sealed_sql, sealed_params = _sealed_test(column)
        if unmarked:
            flag, chosen = sealed_sql, f"{column} IS NOT NULL AND {column} != ''"
            params = sealed_params
        else:
            flag, chosen, params = "1", sealed_sql, sealed_params
        picked = ", ".join(("rowid", flag, *spec.locator, *spec.aad_columns, column))
        first = f"SELECT {picked} FROM {table} WHERE {chosen} ORDER BY rowid LIMIT ?"
        after = f"SELECT {picked} FROM {table} WHERE {chosen} AND rowid > ? ORDER BY rowid LIMIT ?"
        width = len(spec.locator)
        last: int | None = None
        while True:
            readings: list[CellReading] = []
            count = 0
            outage = False
            bound = (chunk_rows,) if last is None else (last, chunk_rows)
            cursor = conn.execute(first if last is None else after, params + bound)
            for rowid, sealed, *row in cursor:
                count, last = count + 1, int(rowid)
                where, key, stored = tuple(row[:width]), row[width:-1], row[-1]
                if not sealed:
                    readings.append(CellReading(spec, unsealed_kind, where))
                elif not isinstance(stored, str):
                    # Only a BLOB is sealed and not text; see `_sealed_test` for why it fails.
                    readings.append(CellReading(spec, "blob", where))
                elif keyless:
                    # The sealed test ignores case; the marker does not. A keyless store's plaintext
                    # that only resembles it is not a sealed cell.
                    if cipher.is_encrypted(stored):
                        readings.append(CellReading(spec, "keyless", where))
                else:
                    reading = _open(spec, cipher, stored, key, where)
                    readings.append(reading)
                    if reading.error is not None and _is_outage(reading.error):
                        # One timeout is the evidence; every later value would wait out its own and
                        # then read as damaged. Stop, and let the caller say which it was.
                        outage = True
                        break
            cursor.close()  # ends the chunk's read transaction even when the loop broke early
            if _schema_version(conn) != version:
                raise CipherWalkInterrupted(
                    f"the store's schema changed while {table}.{column} was read (a VACUUM or a "
                    "migration), so its rowid chunks no longer line up"
                )
            yield from readings
            if outage:
                return
            if count < chunk_rows:
                break


def _is_outage(error: CipherError) -> bool:
    """Whether a failed decrypt was the key service failing rather than the value. The Transit
    cipher raises :class:`CipherError` for both, from the client's own error: an ``OSError`` for
    an unreachable Vault (a ``requests`` connection error or timeout is one), and an ``hvac``
    error for a reply. Vault answers a value it cannot authenticate with HTTP 400, which ``hvac``
    raises as ``InvalidRequest``; any other ``hvac`` error (a sealed Vault, a token refused, a
    5xx) is the service. At least those shapes; a cause of any other kind counts as the value's."""
    cause = error.__cause__
    if isinstance(cause, OSError):
        return True
    return (
        cause is not None
        and type(cause).__module__.split(".")[0] == "hvac"
        and type(cause).__name__ != "InvalidRequest"
    )


def _open(
    spec: CipherCell,
    cipher: Cipher,
    stored: str,
    key: list[object],
    where: tuple[object, ...],
) -> CellReading:
    """Open one text value :func:`_sealed_test` called sealed, under a key, and run its cell's
    check; the plaintext goes no further. A marker in another case fails here without a decrypt:
    the cipher would otherwise hand it to its unmarked-value rule and, under
    ``allow_unmarked_ciphertext``, return it with no tag checked."""
    if not stored.startswith(MARKER_PREFIX):
        return CellReading(
            spec,
            "failed",
            where,
            CipherError(f"the value's at-rest marker is not spelled {MARKER_PREFIX!r}"),
        )
    try:
        opened = cipher.decrypt(stored, aad=spec.aad(*key))
        if spec.check is not None:
            spec.check(opened, *key)
    except CipherError as exc:
        holds = getattr(cipher, "holds_key_for", None)
        foreign = callable(holds) and not holds(stored)
        return CellReading(spec, "failed", where, exc, foreign_key=foreign)
    return CellReading(spec, "opened", where)


@dataclass(slots=True)
class CellTally:
    """One cell's counts from :func:`audit_cipher_cells`, and the first finding of each kind as a
    PHI-free line. ``present`` is False for a cell the store lacks, which was not read at all."""

    table: str
    column: str
    present: bool = True
    opened: int = 0
    failed: int = 0
    #: BLOBs, apart from ``failed``: a data fault, not a key or ciphertext one.
    blob: int = 0
    unmarked: int = 0
    legacy: int = 0
    first_failure: str | None = None
    first_unmarked: str | None = None

    @property
    def name(self) -> str:
        return f"{self.table}.{self.column}"


@dataclass(slots=True)
class CipherAudit:
    """The result of :func:`audit_cipher_cells`: one tally per cell asked for, in declaration
    order, and the keyless finding when the walk stopped on one."""

    tallies: list[CellTally] = field(default_factory=list)
    key_mismatch: str | None = None

    @property
    def opened(self) -> int:
        return sum(t.opened for t in self.tallies)

    @property
    def failed(self) -> int:
        return sum(t.failed for t in self.tallies)

    @property
    def blob(self) -> int:
        return sum(t.blob for t in self.tallies)

    @property
    def unmarked(self) -> int:
        return sum(t.unmarked for t in self.tallies)

    @property
    def legacy(self) -> int:
        return sum(t.legacy for t in self.tallies)

    @property
    def absent(self) -> list[str]:
        return [t.name for t in self.tallies if not t.present]


def with_first_failure(mismatch: str, first: str | None) -> str:
    """A key-mismatch line that keeps a failure the walk met before it: the mismatch decides the
    verdict, and the failure, which no key will clear, must not wait for a second run to show."""
    return mismatch if first is None else f"{mismatch}; also found before it: {first}"


def _keyed_mismatch_line(table: object, column: object, source: str) -> str:
    # Read from the store, so bounded and escaped like a locator: a planted row cannot forge a line.
    return (
        f"{_shown(table)}.{_shown(column)} is recorded as keyed in this {source}, but the "
        f"store settings resolved no key to read it (keyless open of a keyed {source})"
    )


def keyed_store_mismatch(
    conn: sqlite3.Connection, cipher: Cipher, tables: set[str], *, source: str = "store"
) -> str | None:
    """The key-mismatch line for a store a keyed open has recorded (its ``keyed_surface`` rows),
    read under a keyless cipher; ``None`` otherwise. Checked before any value is read, by both the
    restore-verify and ``cipher-audit``, so they agree on such a store whatever its rows hold:
    every sealed value may be purged to ``''``, or only BLOBs left, and a walk alone would then
    find no key question."""
    if cipher.encrypts or "keyed_surface" not in tables:
        return None
    keyed = conn.execute(
        "SELECT surface_table, surface_column FROM keyed_surface ORDER BY 1, 2 LIMIT 1"
    ).fetchone()
    return None if keyed is None else _keyed_mismatch_line(keyed[0], keyed[1], source)


class _Tallier:
    """Folds readings into a :class:`CipherAudit`, for :func:`audit_cipher_cells` and
    :func:`audit_server_cipher_cells` alike, so the backends' verdicts cannot drift apart."""

    def __init__(self, audit: CipherAudit) -> None:
        self._audit = audit
        self._tally = {(t.table, t.column): t for t in audit.tallies}
        self._first: str | None = None

    def add(self, reading: CellReading) -> bool:
        """Count ``reading``; True when the walk must stop. A keyless reading stops it, recorded as
        the key mismatch, since every later one would say the same. A decrypt the key service
        failed (:func:`_is_outage`) is raised: every later value would wait out its own timeout and
        then read as damaged, which an outage is not."""
        found = self._tally[(reading.cell.table, reading.cell.column)]
        if reading.kind == "keyless":
            self._audit.key_mismatch = with_first_failure(reading.failure(), self._first)
            return True
        if reading.kind == "opened":
            found.opened += 1
        elif reading.kind in ("failed", "blob"):
            if reading.error is not None and _is_outage(reading.error):
                raise reading.error
            if reading.kind == "blob":
                found.blob += 1
            else:
                found.failed += 1
            if found.first_failure is None:
                found.first_failure = reading.failure()
            self._first = self._first or found.first_failure
        elif reading.kind == "legacy":
            found.legacy += 1
        else:
            found.unmarked += 1
            if found.first_unmarked is None:
                found.first_unmarked = f"{found.name} {reading.where} carries no at-rest marker"
        return False


def audit_cipher_cells(
    conn: sqlite3.Connection,
    cipher: Cipher,
    *,
    cells: Iterable[CipherCell] = SQLITE_CIPHER_CELLS,
    chunk_rows: int = DEFAULT_CHUNK_ROWS,
) -> CipherAudit:
    """Walk every value in ``cells`` to the end and tally it, unlike the restore-verify, which
    stops at its first failure. Counts unmarked values in a keyed store.

    The verdict precedence is :func:`keyed_store_mismatch`'s, then a keyless reading's, then a
    failure's, so it does not depend on which value the walk meets first. What stops the walk is
    :meth:`_Tallier.add`'s to say."""
    wanted = tuple(cells)
    tables = store_tables(conn)
    audit = CipherAudit(
        [CellTally(c.table, c.column, present=cell_present(conn, c, tables)) for c in wanted]
    )
    audit.key_mismatch = keyed_store_mismatch(conn, cipher, tables)
    if audit.key_mismatch is not None:
        return audit
    tallier = _Tallier(audit)
    for reading in read_cipher_cells(
        conn, cipher, cells=wanted, chunk_rows=chunk_rows, unmarked=True
    ):
        if tallier.add(reading):
            break
    return audit


# --- the server stores (PostgreSQL, SQL Server) ------------------------------


class CipherCellSource(Protocol):
    """What a server store offers :func:`read_server_cipher_cells`: four reads, each one statement,
    implemented by ``PostgresStore`` and ``SqlServerStore`` in their own dialects. None writes."""

    async def cipher_walk_columns(self, tables: Sequence[str]) -> dict[str, frozenset[str]]: ...

    async def cipher_walk_keyed_surface(self) -> tuple[str, str] | None: ...

    async def cipher_walk_surface_sealed(self, table: str, column: str, *, keyed: bool) -> bool: ...

    async def cipher_walk_chunk(
        self,
        table: str,
        column: str,
        select: Sequence[str],
        order: Sequence[str],
        after: Sequence[Any] | None,
        limit: int,
        *,
        sealed_only: bool,
    ) -> list[tuple[Any, ...]]: ...


def server_cell_present(spec: CipherCell, columns: Mapping[str, frozenset[str]]) -> bool:
    """:func:`cell_present` for a server store, from :meth:`CipherCellSource.cipher_walk_columns`."""
    have = columns.get(spec.table)
    needed = {spec.column, *spec.aad_columns, *spec.order, *spec.locator} - {POSITION}
    return have is not None and have.issuperset(needed)


def server_walk_tables(cells: Iterable[CipherCell]) -> tuple[str, ...]:
    """The tables a server walk of ``cells`` asks the columns of: theirs and ``keyed_surface``."""
    return tuple(dict.fromkeys((*(c.table for c in cells), "keyed_surface")))


def _server_select(spec: CipherCell) -> tuple[str, ...]:
    """The columns a server chunk selects before the value: the paging key first, then the
    locator and the AAD columns, each once."""
    named = (*spec.order, *(c for c in spec.locator if c != POSITION), *spec.aad_columns)
    return tuple(dict.fromkeys(named))


def _is_sealed_text(stored: str) -> bool:
    """:func:`_sealed_test` for one text value: the marker in any ASCII case."""
    head = stored[: len(MARKER_PREFIX)]
    return head.isascii() and head.lower() == MARKER_PREFIX.lower()


def _read_server_chunk(
    spec: CipherCell,
    cipher: Cipher,
    rows: list[tuple[Any, ...]],
    position: int,
    *,
    unmarked: bool,
    unsealed_kind: ReadingKind,
) -> tuple[list[CellReading], int, bool]:
    """Classify one chunk's rows as :func:`read_cipher_cells` classifies a SQLite row. Returns the
    readings, the position of the last row read, and whether a key-service outage stopped it. Run
    in a worker thread: under ``vault_transit`` every decrypt is a Transit request."""
    index = {c: i for i, c in enumerate(_server_select(spec))}
    keyless = not cipher.encrypts
    readings: list[CellReading] = []
    for row in rows:
        position += 1
        stored = row[-1]
        where = tuple(position if c == POSITION else row[index[c]] for c in spec.locator)
        if not isinstance(stored, str):
            # Every server cipher column is text, so a driver handing back anything else is a
            # damaged row, failed as SQLite fails a BLOB.
            readings.append(CellReading(spec, "blob", where))
            continue
        if stored == "":
            continue  # every purge path writes '' (see read_cipher_cells)
        if not _is_sealed_text(stored):
            if unmarked:
                readings.append(CellReading(spec, unsealed_kind, where))
            continue
        if keyless:
            # The sealed test ignores case; the marker does not (see read_cipher_cells).
            if cipher.is_encrypted(stored):
                readings.append(CellReading(spec, "keyless", where))
            continue
        key = [row[index[c]] for c in spec.aad_columns]
        reading = _open(spec, cipher, stored, key, where)
        readings.append(reading)
        if reading.error is not None and _is_outage(reading.error):
            return readings, position, True
    return readings, position, False


async def read_server_cipher_cells(
    source: CipherCellSource,
    cipher: Cipher,
    *,
    cells: Iterable[CipherCell],
    chunk_rows: int = DEFAULT_CHUNK_ROWS,
    unmarked: bool = False,
    columns: Mapping[str, frozenset[str]] | None = None,
) -> AsyncGenerator[CellReading]:
    """:func:`read_cipher_cells` for a PostgreSQL or SQL Server store: the same readings, by the
    same rules, so ``cipher-audit`` reads every backend alike.

    A server table has no ``rowid``, so each cell is paged by its ``order`` key, ``chunk_rows`` at
    a time (``chunk_cap`` lowers it), and each chunk is one SELECT that ends before the next. A row
    added behind the walk's key while it runs is not read. Nothing renumbers a key, so there is no
    schema-version check. The marker test runs here rather than in SQL, because neither server's
    ``LIKE`` reads case as SQLite's does; ``sealed_only`` only narrows what a chunk fetches. The
    decrypts run off the event loop. ``columns`` is :meth:`CipherCellSource.cipher_walk_columns`
    for :func:`server_walk_tables`, when the caller already holds it."""
    if chunk_rows < 1:
        raise ValueError(f"chunk_rows must be at least 1, not {chunk_rows}")
    wanted = tuple(cells)
    unmarked = unmarked and cipher.encrypts
    if columns is None:
        columns = await source.cipher_walk_columns(server_walk_tables(wanted))
    keyed_table = "keyed_surface" in columns
    for spec in wanted:
        if not server_cell_present(spec, columns):
            continue
        unsealed_kind: ReadingKind = "unmarked"
        if unmarked and not await source.cipher_walk_surface_sealed(
            spec.table, spec.column, keyed=keyed_table
        ):
            unsealed_kind = "legacy"
        limit = chunk_rows if spec.chunk_cap is None else min(chunk_rows, spec.chunk_cap)
        after: tuple[Any, ...] | None = None
        position = 0
        while True:
            rows = await source.cipher_walk_chunk(
                spec.table,
                spec.column,
                _server_select(spec),
                spec.order,
                after,
                limit,
                sealed_only=not unmarked,
            )
            if not rows:
                break
            after = tuple(rows[-1][: len(spec.order)])
            readings, position, outage = await asyncio.to_thread(
                _read_server_chunk,
                spec,
                cipher,
                rows,
                position,
                unmarked=unmarked,
                unsealed_kind=unsealed_kind,
            )
            for reading in readings:
                yield reading
            if outage:
                return
            if len(rows) < limit:
                break


async def server_keyed_store_mismatch(
    source: CipherCellSource, cipher: Cipher, columns: Mapping[str, frozenset[str]]
) -> str | None:
    """:func:`keyed_store_mismatch` for a server store, ``columns`` naming the tables it holds."""
    if cipher.encrypts or "keyed_surface" not in columns:
        return None
    keyed = await source.cipher_walk_keyed_surface()
    return None if keyed is None else _keyed_mismatch_line(keyed[0], keyed[1], "store")


async def audit_server_cipher_cells(
    source: CipherCellSource,
    cipher: Cipher,
    *,
    cells: Iterable[CipherCell],
    chunk_rows: int = DEFAULT_CHUNK_ROWS,
    columns: Mapping[str, frozenset[str]] | None = None,
) -> CipherAudit:
    """:func:`audit_cipher_cells` for a PostgreSQL or SQL Server store, through
    :func:`read_server_cipher_cells`, with the same precedence and the same stops."""
    wanted = tuple(cells)
    if columns is None:
        columns = await source.cipher_walk_columns(server_walk_tables(wanted))
    audit = CipherAudit(
        [CellTally(c.table, c.column, present=server_cell_present(c, columns)) for c in wanted]
    )
    audit.key_mismatch = await server_keyed_store_mismatch(source, cipher, columns)
    if audit.key_mismatch is not None:
        return audit
    tallier = _Tallier(audit)
    walk = read_server_cipher_cells(
        source, cipher, cells=wanted, chunk_rows=chunk_rows, unmarked=True, columns=columns
    )
    async with aclosing(walk):
        async for reading in walk:
            if tallier.add(reading):
                break
    return audit


def connect_readonly(path: str | Path, *, busy_timeout: float) -> sqlite3.Connection:
    """A read-only connection to the SQLite store at ``path``, for a walk of a LIVE store or a
    check of a DR snapshot.

    ``mode=ro`` through the store's own URI builder, so a path holding a space, ``#``, ``?`` or
    ``%``, or a UNC path, opens the file it names, and a missing file is refused rather than
    created. ``isolation_level=None`` leaves each statement its own read transaction, which is what
    keeps :func:`read_cipher_cells`' chunks short. ``busy_timeout`` is in seconds."""
    return sqlite3.connect(
        _sqlite_readonly_uri(str(Path(path).resolve())),
        uri=True,
        timeout=busy_timeout,
        isolation_level=None,
    )
