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
from messagefoundry.store.queue_tag import QUEUE_TAG_COLUMNS, queue_row_aad
from messagefoundry.store.store import MessageStore, _sqlite_readonly_uri

__all__ = [
    "COMPOSITE_CIPHER_CELLS",
    "DEFAULT_CHUNK_ROWS",
    "SQLITE_CIPHER_CELLS",
    "CellReading",
    "CellTally",
    "CipherAudit",
    "CipherCell",
    "audit_cipher_cells",
    "connect_readonly",
    "read_cipher_cells",
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
    ``aad_columns`` values in order and returns the AAD (the queue payload's routing tag)."""

    table: str
    column: str
    aad_columns: tuple[str, ...]
    locator: tuple[str, ...] = ("rowid",)
    builder: Callable[..., bytes] | None = None

    def aad(self, *key: object) -> bytes:
        """The AAD the writer bound for this cell, given the ``aad_columns`` values in order."""
        if self.builder is not None:
            return self.builder(*key)
        return cell_aad(self.table, self.column, *key)

    def locate(self, *values: object) -> str:
        """The row's ``locator`` values as ``column=value`` pairs, for a PHI-free failure message."""
        return " ".join(f"{c}={v}" for c, v in zip(self.locator, values, strict=True))


_RESPONSE_KEY = ("message_id", "destination_name", "response_seq")


def _queue_payload_aad(*values: object) -> bytes:
    """The queue payload's routing tag from the :data:`QUEUE_TAG_COLUMNS` values (BACKLOG #2593)."""
    return queue_row_aad(dict(zip(QUEUE_TAG_COLUMNS, values, strict=True)))


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
    CipherCell("queue", "payload", QUEUE_TAG_COLUMNS, locator=("id",), builder=_queue_payload_aad),
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
ReadingKind = Literal["opened", "failed", "keyless", "unmarked"]


@dataclass(frozen=True, slots=True)
class CellReading:
    """What :func:`read_cipher_cells` found at one value of one cell.

    ``kind`` is ``"opened"`` when the value decrypted and authenticated, ``"failed"`` when it did
    not (``error`` says why), ``"keyless"`` when it is sealed and the cipher holds no key, so nothing
    could have opened it, and ``"unmarked"`` for a non-blank value with no marker, reported only when
    the walk is asked for them. ``values`` are the cell's ``locator`` values: never a plaintext, and
    never a key column that can itself be PHI."""

    cell: CipherCell
    kind: ReadingKind
    values: tuple[object, ...]
    error: CipherError | None = None

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
        return f"{name} {self.where} did not decrypt: {reason}"


def _looks_sealed(value: str) -> bool:
    """SQLite's ``LIKE 'mfenc:%'``, which the restore-verify selects with: an ASCII prefix match
    that ignores case. A value spelled ``MFENC:`` is read as sealed and refused by the cipher there,
    so the walk treats it the same way whichever mode selected it."""
    head = value[: len(MARKER_PREFIX)]
    return head.isascii() and head.lower() == MARKER_PREFIX


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
    cells fails its tag here as it would at a live read. A table the store does not have, or that
    lacks a column the cell names, is skipped: an older store predates it.

    The rows of each cell are read in ``rowid`` order, ``chunk_rows`` at a time, each chunk by one
    statement read to the end before anything is yielded. So no read transaction stays open while
    the caller works, and a writer on a live store waits on at most one chunk.

    ``unmarked`` also yields every non-blank value with no marker, in a keyed store only: there a
    keyed writer seals every value, so such a value is a damaged or stripped marker or a planted row,
    and selecting by the marker alone would never read it. NULL and ``''`` are never reported: every
    purge path writes ``''``. In a keyless store every value is plaintext, so nothing is reported.

    The cipher decides keylessness, never a value: a decrypted value may itself begin with the
    marker. Under ``vault_transit`` every decrypt is one Transit request."""
    if chunk_rows < 1:
        raise ValueError(f"chunk_rows must be at least 1, not {chunk_rows}")
    keyless = not cipher.encrypts
    unmarked = unmarked and not keyless
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    for spec in cells:
        table, column = spec.table, spec.column
        if table not in tables:
            continue
        names = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}  # declared constant
        if not names.issuperset({column, *spec.aad_columns, *spec.locator} - {"rowid"}):
            continue
        # Table, column and key names are declared constants; only values are parameters.
        picked = ", ".join(("rowid", *spec.locator, *spec.aad_columns, column))
        chosen: str
        params: tuple[object, ...]
        if unmarked:
            chosen, params = f"{column} IS NOT NULL AND {column} != ''", ()
        else:
            chosen, params = f"{column} LIKE ?", (f"{MARKER_PREFIX}%",)
        first = f"SELECT {picked} FROM {table} WHERE {chosen} ORDER BY rowid LIMIT ?"
        after = f"SELECT {picked} FROM {table} WHERE rowid > ? AND {chosen} ORDER BY rowid LIMIT ?"
        width = len(spec.locator)
        last: int | None = None
        while True:
            if last is None:
                rows = conn.execute(first, (*params, chunk_rows)).fetchall()
            else:
                rows = conn.execute(after, (last, *params, chunk_rows)).fetchall()
            for _rowid, *row in rows:
                where, key, stored = tuple(row[:width]), row[width:-1], str(row[-1])
                if not _looks_sealed(stored):
                    yield CellReading(spec, "unmarked", where)
                    continue
                if keyless:
                    # LIKE ignores case; the marker does not. A keyless store's plaintext that only
                    # resembles it is not a sealed cell.
                    if cipher.is_encrypted(stored):
                        yield CellReading(spec, "keyless", where)
                    continue
                try:
                    cipher.decrypt(stored, aad=spec.aad(*key))
                except CipherError as exc:
                    yield CellReading(spec, "failed", where, exc)
                    continue
                yield CellReading(spec, "opened", where)
            if len(rows) < chunk_rows:
                break
            last = int(rows[-1][0])


@dataclass(slots=True)
class CellTally:
    """One cell's counts from :func:`audit_cipher_cells`, and the first finding of each kind as a
    PHI-free line."""

    table: str
    column: str
    opened: int = 0
    failed: int = 0
    unmarked: int = 0
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


def audit_cipher_cells(
    conn: sqlite3.Connection,
    cipher: Cipher,
    *,
    cells: Iterable[CipherCell] = SQLITE_CIPHER_CELLS,
    chunk_rows: int = DEFAULT_CHUNK_ROWS,
) -> CipherAudit:
    """Walk every value in ``cells`` to the end and tally it, unlike the restore-verify, which
    stops at its first failure. Counts unmarked values in a keyed store. A sealed value under a
    keyless cipher stops the walk: every other sealed value would say the same."""
    wanted = tuple(cells)
    audit = CipherAudit([CellTally(c.table, c.column) for c in wanted])
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
            found.failed += 1
            if found.first_failure is None:
                found.first_failure = reading.failure()
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
