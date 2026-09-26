# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The SQLite store's composite-key cipher cells, declared as data (BACKLOG #1719, ASVS 11.3.3).

``MessageStore._CIPHER_COLUMNS`` lists the cipher-covered cells whose AAD binds to the row ``id``. The
rest bind to a composite or natural key, so each has its own migration and rotation pass inside the
store, and until this module no caller outside it could read them back. This module names those cells
and the columns each writer binds into ``cell_aad``, in the order it binds them. The full
restore-verify reads every one back through the cipher, so a corrupted value fails the verify instead
of surfacing at first use.

It is READ-ONLY: nothing here writes a cell, and the store's own passes do not consume it. Driving
every pass from one declaration is BACKLOG #1169's scope, not this one's. Until then two guards keep
this list honest. ``tests/test_store_cipher_sweep_parity.py`` fails when ``store.py`` gains a composite
cipher cell this tuple does not name. ``tests/test_cipher_cells_readback.py`` writes each cell through
the real store writer, proves the AAD here opens it, and proves a flipped byte fails it.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from messagefoundry.store.crypto import cell_aad

__all__ = ["COMPOSITE_CIPHER_CELLS", "CipherCell"]


@dataclass(frozen=True, slots=True)
class CipherCell:
    """One cipher-covered cell: its table, its column, and the columns its AAD binds, in bind order."""

    table: str
    column: str
    aad_columns: tuple[str, ...]

    def aad(self, row: Mapping[str, object]) -> bytes:
        """The AAD the writer bound for this cell in ``row``, which must carry every ``aad_columns``."""
        return cell_aad(self.table, self.column, *(row[c] for c in self.aad_columns))


_RESPONSE_KEY = ("message_id", "destination_name", "response_seq")

#: Every cipher-covered cell in ``store.py`` that ``_CIPHER_COLUMNS`` does not carry. The AAD columns
#: are copied from each cell's writer, and the round-trip test proves they match it.
COMPOSITE_CIPHER_CELLS: tuple[CipherCell, ...] = (
    CipherCell("response", "body", _RESPONSE_KEY),
    CipherCell("response", "detail", _RESPONSE_KEY),
    CipherCell("response", "resp_headers", _RESPONSE_KEY),
    CipherCell("state", "value", ("namespace", "key")),
    CipherCell("reference", "value", ("name", "version", "key")),
    CipherCell("shared_body", "body", ("hash",)),
    CipherCell("attachment_chunk", "ciphertext", ("attachment_id", "seq")),
    # These three have an AUTOINCREMENT id the encrypting INSERT cannot know, so their AAD binds the
    # natural columns the writer has in hand instead.
    CipherCell("message_events", "detail", ("message_id", "ts", "event")),
    CipherCell("connection_event", "reason", ("connection", "ts", "kind")),
    CipherCell("alert_instance", "reason", ("event_type", "connection")),
)
