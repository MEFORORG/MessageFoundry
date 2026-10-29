# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The SQLite store's cipher-covered cells, declared as data (BACKLOG #1719, ASVS 11.3.3).

``MessageStore._CIPHER_COLUMNS`` lists the cipher-covered cells whose AAD binds to the row ``id``. The
rest bind to a composite or natural key, so each has its own migration and rotation pass inside the
store, and until this module no caller outside it could read them back. This module names those cells
and the columns each writer binds into ``cell_aad``, in the order it binds them, and joins both kinds
into :data:`SQLITE_CIPHER_CELLS`. The full restore-verify reads every sealed value in them back
through the cipher, so a ciphertext whose tag no longer authenticates fails the verify instead of
surfacing at first use. It selects values by their marker, so a value whose marker itself is damaged
is not reached by that pass.

:func:`read_cipher_cells` is the one walk over those cells. The restore-verify stops at its first
failure; :func:`audit_cipher_cells`, behind ``messagefoundry cipher-audit``, reads a LIVE store with
it to the end and also counts, in a keyed store, the non-blank values that carry no marker at all,
which is where a damaged marker lands.

It is READ-ONLY: nothing here writes a cell, and the store's own passes do not consume it. Driving
every pass from one declaration is BACKLOG #1169's scope, not this one's. Until then two guards keep
this list honest. ``tests/test_store_cipher_sweep_parity.py`` fails when ``store.py`` gains a composite
cipher cell this module does not name. ``tests/test_cipher_cells_readback.py`` writes each cell through
the real store writer, proves the AAD here opens it, and proves a flipped byte fails it.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Generator, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from messagefoundry.redaction import safe_exc
from messagefoundry.store.cell_tag import is_row_tagged, row_tag_aad, row_tag_columns
from messagefoundry.store.crypto import MARKER_PREFIX, Cipher, CipherError, cell_aad
from messagefoundry.store.queue_tag import QUEUE_TAG_COLUMNS, QueueTagError, queue_row_aad
from messagefoundry.store.store import MessageStore, _sqlite_readonly_uri

__all__ = [
    "COMPOSITE_CIPHER_CELLS",
    "DEFAULT_CHUNK_ROWS",
    "SQLITE_CIPHER_CELLS",
    "CellReading",
    "CellTally",
    "CipherAudit",
    "CipherCell",
    "CipherWalkInterrupted",
    "audit_cipher_cells",
    "cell_present",
    "connect_readonly",
    "read_cipher_cells",
    "store_tables",
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
    payload's sealed ``shared_body`` reference against its ``body_ref`` column)."""

    table: str
    column: str
    aad_columns: tuple[str, ...]
    locator: tuple[str, ...] = ("rowid",)
    builder: Callable[..., bytes] | None = None
    check: Callable[..., None] | None = None

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

#: Rows one statement of :func:`read_cipher_cells` reads. Each chunk is its own short read
#: transaction, so a walk of a live store never holds one snapshot open across a whole table.
DEFAULT_CHUNK_ROWS = 500

#: What :func:`read_cipher_cells` found at one value; see :class:`CellReading`.
ReadingKind = Literal["opened", "failed", "keyless", "unmarked", "legacy"]


class CipherWalkInterrupted(RuntimeError):
    """The store's schema changed part way through a walk, so its ``rowid`` chunks no longer line
    up: a VACUUM, which the retention runner schedules, may renumber the rowids of a table with no
    INTEGER PRIMARY KEY, and a later chunk would then skip rows or read some twice. Raised rather
    than finishing on a subset that would read as a clean store."""


@dataclass(frozen=True, slots=True)
class CellReading:
    """What :func:`read_cipher_cells` found at one value of one cell.

    ``kind`` is ``"opened"`` when the value decrypted and authenticated, ``"failed"`` when it did
    not or its reader would refuse it (``error`` says why), and ``"keyless"`` when it is sealed and
    the cipher holds no key, so nothing could have opened it. Two kinds are reported only when the
    walk is asked for unmarked values: ``"unmarked"``, a non-blank value with no marker on a surface
    the store has sealed, which it refuses at read, and ``"legacy"``, the same on a surface no keyed
    open has sealed yet, which the next keyed open seals. ``values`` are the cell's ``locator``
    values: never a plaintext, and never a key column that can itself be PHI."""

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
        """The PHI-free line a failed or keyless value is reported with: table, column and locator,
        and for a failure the redacted cipher error, never the value. ``source`` names what was
        read in the keyless line: the live store, or a restore-verify's snapshot."""
        name = f"{self.cell.table}.{self.cell.column}"
        if self.kind == "keyless":
            return (
                f"{name} is encrypted at rest but the store settings resolved no key "
                f"to open it (keyless open of an encrypted {source})"
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
    marked = conn.execute(
        f"SELECT 1 FROM {spec.table} WHERE {_sealed_sql(spec.column)} LIMIT 1",  # declared constants
        (f"{MARKER_PREFIX}%",),
    ).fetchone()
    return marked is not None


def _sealed_sql(column: str) -> str:
    """The SQL test that calls a value of ``column`` sealed, with one ``?`` for the marker pattern.

    ``LIKE 'mfenc:%'`` alone is not the same test on every platform. A SQLite built with
    ``SQLITE_LIKE_DOESNT_MATCH_BLOBS``, as Ubuntu's is, never matches a BLOB, while the Windows
    build matches one by its bytes. So a BLOB is called sealed by its type, on every build: no
    writer stores one in a cipher-covered column, and :func:`_open` fails it without a decrypt.
    That fails closed, where a BLOB the test skipped would never be read at all."""
    return f"(typeof({column}) = 'blob' OR {column} LIKE ?)"


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

    A value is sealed when it is a BLOB or SQLite's ``LIKE 'mfenc:%'`` matches it (see
    :func:`_sealed_sql`): the LIKE is the test the restore-verify has always selected with, and it
    ignores case, but whether it matches a BLOB depends on how SQLite was built, so a BLOB is
    judged by its type instead. A sealed value that is a BLOB, or whose marker is in another case,
    fails without a decrypt (see :func:`_open`).

    The rows of each cell are read in ``rowid`` order, ``chunk_rows`` at a time. Each chunk is one
    statement, read one row at a time and opened as it is read, and its readings are yielded only
    once the statement is closed. So no read transaction stays open while the caller works, a
    writer on a live store waits on at most one chunk's decrypts, and memory holds one stored value
    at a time. The schema version is read after every chunk; a change raises
    :class:`CipherWalkInterrupted`. A decrypt that failed because the key service did
    (:func:`_is_outage`) ends the walk after its reading is yielded.

    ``unmarked`` also yields every non-blank value with no marker, in a keyed store only, as
    ``"unmarked"`` or ``"legacy"`` by whether the store has sealed that surface (see
    :class:`CellReading`). A walk selecting by the marker alone never reads such a value, which is
    where a damaged or stripped marker, or a planted row, lands. NULL and ``''`` are never reported:
    every purge path writes ``''``. In a keyless store every value is plaintext, so none is.

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
        # same test that selects it.
        sealed_sql = _sealed_sql(column)
        picked = ", ".join(("rowid", sealed_sql, *spec.locator, *spec.aad_columns, column))
        chosen = f"{column} IS NOT NULL AND {column} != ''" if unmarked else sealed_sql
        marker: tuple[object, ...] = (f"{MARKER_PREFIX}%",)
        params = marker if unmarked else marker * 2
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
                elif keyless:
                    # LIKE ignores case; the marker does not. A keyless store's plaintext that only
                    # resembles it is not a sealed cell.
                    text = _as_text(stored)
                    if text is not None and cipher.is_encrypted(text):
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


def _as_text(stored: object) -> str | None:
    """A stored value as the text the store's reader would see: a ``str`` as it is, a UTF-8 BLOB
    decoded, anything else ``None``."""
    if isinstance(stored, str):
        return stored
    if isinstance(stored, bytes):
        try:
            return stored.decode("utf-8")
        except UnicodeDecodeError:
            return None
    return None


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
    stored: object,
    key: list[object],
    where: tuple[object, ...],
) -> CellReading:
    """Open one value the marker test called sealed, and run its cell's check; the plaintext goes
    no further. A value the store's reader could not take as a sealed cell fails here without a
    decrypt: a BLOB, or a marker in another case, which the cipher would otherwise hand to its
    unmarked-value rule and, under ``allow_unmarked_ciphertext``, return with no tag checked."""
    if not isinstance(stored, str):
        return CellReading(
            spec, "failed", where, CipherError("the sealed value is stored as a BLOB, not text")
        )
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
    def unmarked(self) -> int:
        return sum(t.unmarked for t in self.tallies)

    @property
    def legacy(self) -> int:
        return sum(t.legacy for t in self.tallies)

    @property
    def absent(self) -> list[str]:
        return [t.name for t in self.tallies if not t.present]


def audit_cipher_cells(
    conn: sqlite3.Connection,
    cipher: Cipher,
    *,
    cells: Iterable[CipherCell] = SQLITE_CIPHER_CELLS,
    chunk_rows: int = DEFAULT_CHUNK_ROWS,
) -> CipherAudit:
    """Walk every value in ``cells`` to the end and tally it, unlike the restore-verify, which
    stops at its first failure. Counts unmarked values in a keyed store.

    Two things stop the walk. A sealed value under a keyless cipher is recorded as the key
    mismatch, since every other sealed value would say the same. A decrypt that failed because the
    key service was unreachable (:func:`_is_outage`) is raised: every later value would wait out
    its own timeout and then read as damaged, which an outage is not."""
    wanted = tuple(cells)
    tables = store_tables(conn)
    audit = CipherAudit(
        [CellTally(c.table, c.column, present=cell_present(conn, c, tables)) for c in wanted]
    )
    if not cipher.encrypts and "keyed_surface" in tables:
        # A store a keyed open has recorded, read with no key. It may hold no sealed value just
        # now (purged to ''), and then the walk below would find nothing to object to.
        keyed = conn.execute(
            "SELECT surface_table, surface_column FROM keyed_surface ORDER BY 1, 2 LIMIT 1"
        ).fetchone()
        if keyed is not None:
            audit.key_mismatch = (
                f"{keyed[0]}.{keyed[1]} is recorded as keyed in this store, but the store "
                "settings resolved no key to read it (keyless open of a keyed store)"
            )
            return audit
    tally = {(t.table, t.column): t for t in audit.tallies}
    for reading in read_cipher_cells(
        conn, cipher, cells=wanted, chunk_rows=chunk_rows, unmarked=True
    ):
        found = tally[(reading.cell.table, reading.cell.column)]
        if reading.kind == "keyless":
            audit.key_mismatch = reading.failure()
            break
        if reading.kind == "opened":
            found.opened += 1
        elif reading.kind == "failed":
            if reading.error is not None and _is_outage(reading.error):
                raise reading.error
            found.failed += 1
            if found.first_failure is None:
                found.first_failure = reading.failure()
        elif reading.kind == "legacy":
            found.legacy += 1
        else:
            found.unmarked += 1
            if found.first_unmarked is None:
                found.first_unmarked = f"{found.name} {reading.where} carries no at-rest marker"
    return audit


def connect_readonly(path: str | Path, *, busy_timeout: float) -> sqlite3.Connection:
    """A read-only connection to the SQLite store at ``path``, for a walk of a LIVE store.

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
