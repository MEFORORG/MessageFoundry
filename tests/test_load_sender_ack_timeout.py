# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A load target's ``ack_timeout_s`` reaches its connections (BACKLOG #5952).

The profile parsed and validated ``ack_timeout_s`` per target, but ``ConnectionPool`` never passed
it on, and the read loop waited on the socket with no deadline. A target that took a message and
never answered held its in-flight sends, and a closed-loop slot, for the whole run. Now the
connection is closed once the oldest send has waited that long, its sends are counted as timeouts,
and it reconnects.
"""

from __future__ import annotations

import asyncio

import pytest

import harness.load.sender as sender
from harness.load.corpus import Outgoing
from harness.load.correlator import Correlator
from harness.load.metrics import Counters, Histogram, LiveMetrics
from harness.load.profile import Target

_MSG = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01^ADT_A01|X1|P|2.5.1\r"


async def _silent_peer() -> tuple[asyncio.Server, int, list[asyncio.StreamWriter]]:
    """Reads everything, answers nothing, and holds each socket open."""
    held: list[asyncio.StreamWriter] = []

    async def peer(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        held.append(writer)
        while await reader.read(65536):
            pass

    server = await asyncio.start_server(peer, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1], held


async def test_a_silent_target_times_out_and_reconnects() -> None:
    server, port, held = await _silent_peer()
    metrics = LiveMetrics(Counters(), Histogram(), Histogram())
    target = Target(name="t", host="127.0.0.1", port=port, ack_timeout_s=0.3)
    pool = sender.ConnectionPool(target, 1, Correlator(100, metrics), metrics)
    conn = pool._conns[0]
    released = asyncio.Event()
    try:
        pool.start()
        assert pool.submit_nowait(Outgoing(1, "ADT", "X1", _MSG), released.set)
        await asyncio.wait_for(released.wait(), timeout=5.0)  # the slot comes back
        assert metrics.counters.timeouts == 1
        assert metrics.counters.acked == 0
        assert conn.drops == 0  # this side closed it; the peer dropped nothing
        for _ in range(100):
            if conn.generation >= 2:
                break
            await asyncio.sleep(0.05)
        assert conn.generation >= 2, "the connection did not reconnect"
    finally:
        await pool.stop(0.05)
        for writer in held:
            writer.transport.abort()
        server.close()
        await server.wait_closed()


async def test_no_timeout_is_passed_when_no_ack_is_expected() -> None:
    metrics = LiveMetrics(Counters(), Histogram(), Histogram())
    target = Target(name="t", expect_ack=False, ack_timeout_s=0.3)
    pool = sender.ConnectionPool(target, 1, Correlator(10, metrics), metrics)
    assert pool._conns[0]._ack_timeout_ns is None


@pytest.mark.parametrize("bad", [0.0, -1.0, float("nan")])
def test_a_non_positive_ack_timeout_is_refused(bad: float) -> None:
    metrics = LiveMetrics(Counters(), Histogram(), Histogram())
    with pytest.raises(ValueError, match="ack_timeout"):
        sender.PersistentConnection(
            "127.0.0.1", 1, Correlator(10, metrics), metrics, ack_timeout=bad
        )
