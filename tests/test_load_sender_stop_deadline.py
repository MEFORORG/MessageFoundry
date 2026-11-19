# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``PersistentConnection.stop`` has a hard deadline (BACKLOG #5951).

A graceful stop drains what is queued, then waits its grace for ACKs. Against a peer that accepts
and never reads, the drain never finishes, and ``stop`` used to await the connection task with no
bound, so a load run's shutdown hung for good. Past the grace plus ``_STOP_HARD_MARGIN_S`` the
socket is now aborted and the task cancelled.
"""

from __future__ import annotations

import asyncio
import time

import pytest

import harness.load.sender as sender
from harness.load.corpus import Outgoing
from harness.load.correlator import Correlator
from harness.load.metrics import Counters, Histogram, LiveMetrics

_MSG = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01^ADT_A01|X1|P|2.5.1\r" + "OBX|" + "A" * 65536 + "\r"


async def test_stop_returns_against_a_peer_that_never_reads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sender, "_STOP_HARD_MARGIN_S", 0.5)
    held: list[asyncio.StreamWriter] = []
    accepted = asyncio.Event()

    async def peer(_reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        held.append(writer)  # hold the socket open and read nothing, so the sender's drain stalls
        accepted.set()

    server = await asyncio.start_server(peer, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    metrics = LiveMetrics(Counters(), Histogram(), Histogram())
    conn = sender.PersistentConnection(
        "127.0.0.1", port, Correlator(1000, metrics), metrics, queue_max=1000
    )
    try:
        conn.start()
        await asyncio.wait_for(accepted.wait(), timeout=5.0)
        for seq in range(1, 501):  # about 32 MB: far past what the socket buffers take unread
            assert conn.submit_nowait(Outgoing(seq, "ADT", f"X{seq}", _MSG))
        await asyncio.sleep(0.5)  # let the writer fill the buffers and block in drain
        started = time.monotonic()
        await asyncio.wait_for(conn.stop(0.1), timeout=10.0)
        assert time.monotonic() - started < 5.0
        assert conn._task is not None and conn._task.done()
        assert not conn.up
    finally:
        for writer in held:
            writer.transport.abort()
        server.close()
        await server.wait_closed()
