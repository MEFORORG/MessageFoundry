# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The SQLite store's cipher-covered cells, declared as data (BACKLOG #1719, ASVS 11.3.3).

``MessageStore._CIPHER_COLUMNS`` lists the cipher-covered cells whose AAD binds to the row ``id``. The
rest bind to a composite or natural key, so each has its own migration and rotation pass inside the
store, and until this module no caller outside it could read them back. This module names those cells
and the columns each writer binds into ``cell_aad``, in the order it binds them, and joins both kinds
into :data:`SQLITE_CIPHER_CELLS`. The full restore-verify reads every one back through the cipher, so a
corrupted value fails the verify instead of surfacing at first use.

It is READ-ONLY: nothing here writes a cell, and the store's own passes do not consume it. Driving
every pass from one declaration is BACKLOG #1169's scope, not this one's. Until then two guards keep
this list honest. ``tests/test_store_cipher_sweep_parity.py`` fails when ``store.py`` gains a composite
cipher cell this module does not name. ``tests/test_cipher_cells_readback.py`` writes each cell through
the real store writer, proves the AAD here opens it, and proves a flipped byte fails it.
"""

from __future__ import annotations

from dataclasses import dataclass

from messagefoundry.store.crypto import cell_aad
from messagefoundry.store.store import MessageStore

__all__ = ["COMPOSITE_CIPHER_CELLS", "SQLITE_CIPHER_CELLS", "CipherCell"]


@dataclass(frozen=True, slots=True)
class CipherCell:
    """One cipher-covered cell: its table, its column, and the columns its AAD binds, in bind order.

    ``locator`` is the column a failure message may name to point an operator at the row: a synthetic
    id where the table has one. Otherwise it is the snapshot's own ``rowid``, which a VACUUM may have
    renumbered, so it locates the row in the snapshot and not necessarily in the live store. A key
    column is never the locator when it can itself be PHI: a ``state`` or ``reference`` key is
    whatever the transform chose, and ``shared_body.hash`` and ``attachment_chunk.attachment_id``
    are digests of the plaintext."""

    table: str
    column: str
    aad_columns: tuple[str, ...]
    locator: str = "rowid"

    def aad(self, *key: object) -> bytes:
        """The AAD the writer bound for this cell, given the ``aad_columns`` values in order."""
        return cell_aad(self.table, self.column, *key)


_RESPONSE_KEY = ("message_id", "destination_name", "response_seq")

#: Every cipher-covered cell in ``store.py`` that ``_CIPHER_COLUMNS`` does not carry. The AAD columns
#: are copied from each cell's writer, and the round-trip test proves they match it.
COMPOSITE_CIPHER_CELLS: tuple[CipherCell, ...] = (
    CipherCell("response", "body", _RESPONSE_KEY, locator="message_id"),
    CipherCell("response", "detail", _RESPONSE_KEY, locator="message_id"),
    CipherCell("response", "resp_headers", _RESPONSE_KEY, locator="message_id"),
    CipherCell("state", "value", ("namespace", "key")),
    CipherCell("reference", "value", ("name", "version", "key")),
    CipherCell("shared_body", "body", ("hash",)),
    CipherCell("attachment_chunk", "ciphertext", ("attachment_id", "seq")),
    # These three have an AUTOINCREMENT id the encrypting INSERT cannot know, so their AAD binds the
    # natural columns the writer has in hand instead. alert_instance binds only its de-dup grain, which
    # its resolved and open rows can share, so a reason moved between those rows still opens.
    CipherCell("message_events", "detail", ("message_id", "ts", "event"), locator="id"),
    CipherCell("connection_event", "reason", ("connection", "ts", "kind"), locator="id"),
    CipherCell("alert_instance", "reason", ("event_type", "connection"), locator="id"),
)

#: Every cipher-covered cell of the SQLite store: the id-keyed ones from the store's own tuple, then
#: the composite ones above.
SQLITE_CIPHER_CELLS: tuple[CipherCell, ...] = (
    *(CipherCell(t, c, ("id",), locator="id") for t, c in MessageStore._CIPHER_COLUMNS),
    *COMPOSITE_CIPHER_CELLS,
)
