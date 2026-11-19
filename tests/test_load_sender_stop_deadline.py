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


async def test_a_slow_peer_still_taking_the_queue_is_not_cut_off(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The deadline counts from the last progress, not from stop(): a healthy peer that takes a long
    queue slowly gets every queued send, however long past grace plus the margin that runs."""
    monkeypatch.setattr(sender, "_STOP_HARD_MARGIN_S", 0.5)
    count = 200  # about 13 MB, read at about 6 MB/s: a couple of seconds, past 0.1 + 0.5

    async def slow(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        while await reader.read(131072):
            await asyncio.sleep(0.02)
        writer.close()

    server = await asyncio.start_server(slow, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    metrics = LiveMetrics(Counters(), Histogram(), Histogram())
    conn = sender.PersistentConnection(
        "127.0.0.1", port, Correlator(1000, metrics), metrics, expect_ack=False, queue_max=1000
    )
    try:
        conn.start()
        for seq in range(1, count + 1):
            assert conn.submit_nowait(Outgoing(seq, "ADT", f"X{seq}", _MSG))
        for _ in range(100):  # a stop before the first connect sends nothing, as on main
            if conn.up:
                break
            await asyncio.sleep(0.02)
        with caplog.at_level("WARNING", logger=sender.__name__):
            await asyncio.wait_for(conn.stop(0.1), timeout=60.0)
        assert metrics.counters.sent == count
        assert "aborting" not in caplog.text
        assert "unwritten" not in caplog.text
    finally:
        server.close()
        await server.wait_closed()


async def test_a_cancelled_stop_still_takes_the_connection_down(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``asyncio.wait`` does not pass a cancellation on to the task it waits for, so stop() does:
    a caller that cancels stop() (a timeout around it, say) leaves no connection writing behind it,
    and every queued job's closed-loop slot is released."""
    monkeypatch.setattr(sender, "_STOP_HARD_MARGIN_S", 30.0)
    held: list[asyncio.StreamWriter] = []
    accepted = asyncio.Event()

    async def deaf(_reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        held.append(writer)
        accepted.set()

    server = await asyncio.start_server(deaf, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    metrics = LiveMetrics(Counters(), Histogram(), Histogram())
    conn = sender.PersistentConnection(
        "127.0.0.1", port, Correlator(1000, metrics), metrics, queue_max=1000
    )
    released: list[int] = []
    count = 500
    try:
        conn.start()
        await asyncio.wait_for(accepted.wait(), timeout=5.0)
        for seq in range(1, count + 1):
            assert conn.submit_nowait(
                Outgoing(seq, "ADT", f"X{seq}", _MSG), lambda: released.append(1)
            )
        await asyncio.sleep(0.5)  # the writer blocks in drain with most of the queue unwritten
        stopping = asyncio.create_task(conn.stop(0.1))
        await asyncio.sleep(0.3)
        stopping.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(stopping, timeout=10.0)
        assert conn._task is not None and conn._task.done()
        assert conn.queued == 0
        assert len(released) == count, "a queued or in-flight job kept its slot"
    finally:
        for writer in held:
            writer.transport.abort()
        server.close()
        await server.wait_closed()


async def test_a_grace_longer_than_the_margin_is_not_cut_short(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """After a long drain, the ACK grace still runs in full. The window used to drop to the bare
    margin once the queue had moved, so a grace longer than the margin was cut short.

    Buffer premise: the peer's slow read must be drain progress the sender can see, so both socket
    buffers are sized small here. The grace starts when the writer finishes, which is when the
    kernel has taken the bytes, not when the peer has read them. Default buffers on Linux can hold
    megabytes, so the peer is still reading when the grace starts and its late ACKs miss it.
    """
    import socket

    from messagefoundry.mllpcodec import frame

    monkeypatch.setattr(sender, "_STOP_HARD_MARGIN_S", 0.3)
    count = 200  # read slowly: a drain of a couple of seconds, past grace plus the margin
    ack = frame("MSH|^~\\&|B|A|C|D|20260101||ACK|A1|P|2.5.1\rMSA|AA|X1\r")
    peer_rcvbuf = 64 * 1024  # the kernel may double it; still a few messages, not megabytes
    sender_sndbuf = 64 * 1024

    async def slow_then_late_acks(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        seen = 0
        while seen < count:
            chunk = await reader.read(131072)
            if not chunk:
                return
            seen += chunk.count(b"\x1c")
            await asyncio.sleep(0.02)
        await asyncio.sleep(0.6)  # longer than the margin, shorter than the grace
        writer.write(ack * count)
        await writer.drain()
        await reader.read()

    server = await asyncio.start_server(slow_then_late_acks, "127.0.0.1", 0)
    # Set on the listener, before any connection, so the accepted socket inherits it.
    server.sockets[0].setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, peer_rcvbuf)
    port = server.sockets[0].getsockname()[1]
    metrics = LiveMetrics(Counters(), Histogram(), Histogram())
    conn = sender.PersistentConnection(
        "127.0.0.1", port, Correlator(1000, metrics), metrics, queue_max=1000
    )
    try:
        conn.start()
        for _ in range(100):
            if conn.up:
                break
            await asyncio.sleep(0.02)
        assert conn.up and conn._writer is not None
        # Sized before anything is queued, so no write reaches a larger default buffer.
        conn._writer.get_extra_info("socket").setsockopt(
            socket.SOL_SOCKET, socket.SO_SNDBUF, sender_sndbuf
        )
        for seq in range(1, count + 1):
            assert conn.submit_nowait(Outgoing(seq, "ADT", f"X{seq}", _MSG))
        await asyncio.wait_for(conn.stop(1.0), timeout=60.0)
        assert metrics.counters.sent == count
        assert metrics.counters.acked == count
        assert metrics.counters.timeouts == 0
    finally:
        server.close()
        await server.wait_closed()
