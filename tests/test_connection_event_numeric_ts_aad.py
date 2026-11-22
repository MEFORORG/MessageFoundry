# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A connection event's sealed reason opens whatever numeric spelling its timestamp was written in.

BACKLOG #5962 fixed this in ``store/crypto.py``'s ``_aad_component``: the column hands back a float,
so an ``int`` or ``-0.0`` written into it must bind the same AAD. This runs that shared code through
the SQLite store only. It does not exercise SQL Server, the backend BACKLOG #5690 names.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.store import MessageStore


@pytest.mark.parametrize("ts", [1000, 0, -0.0, 1000.0, 1000.5])
async def test_a_sealed_reason_opens_on_read(tmp_path: Path, ts: float) -> None:
    # write_v2: the cell-bound writer open_store builds by default. The v1 writer binds no AAD, so
    # this test would pass on it whatever the AAD's spelling.
    cipher = make_cipher(generate_key(), write_v2=True)
    store = await MessageStore.open(tmp_path / "ev.db", cipher=cipher)
    try:
        await store.record_connection_event(
            connection="IB_SYNTH",
            transport="mllp",
            direction="inbound",
            kind="established",
            reason="synthetic reason",
            now=ts,
        )
        cur = await store._db.execute("SELECT reason FROM connection_event")
        row = await cur.fetchone()
        assert row is not None
        assert row["reason"].startswith("mfenc:v4:")  # cell-bound, so the read below proves the AAD
        events = await store.list_connection_events(allowed_channels=None)
        assert [e.reason for e in events] == ["synthetic reason"]
    finally:
        await store.close()
