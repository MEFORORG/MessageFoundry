# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""P2a — MLLP connection-event emit-points + the runner's off-hot-path drain to the store (#46).

The transport tests inject a capturing sink straight onto the source and drive real client sockets,
asserting the lifecycle (established/closed) + the pre-ingress failure kinds fire with the right
metadata. The runner test proves the injected sink → bounded queue → drain task → store path lands
``connection_event`` rows end-to-end.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.config.wiring import ConnectionSpec, InboundConnection, Registry
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStore
from messagefoundry.transports.mllp import SB, MLLPSource, build_ack, frame
from messagefoundry.transports.tcp import TcpSource

ADT = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"


class _Capture:
    def __init__(self) -> None:
        self.events: list[tuple[str, str | None, str | None]] = []

    async def __call__(self, kind: str, peer_host: str | None, reason: str | None) -> None:
        self.events.append((kind, peer_host, reason))

    def kinds(self) -> list[str]:
        return [k for k, _, _ in self.events]


async def _wait_for(predicate, timeout: float = 2.0) -> bool:  # type: ignore[no-untyped-def]
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.01)
    return False


def _mllp(**extra: object) -> MLLPSource:
    return MLLPSource(
        Source(type=ConnectorType.MLLP, settings={"host": "127.0.0.1", "port": 0, **extra})
    )


async def _ack_handler(raw: bytes) -> str:
    return build_ack(raw, code="AA")


async def test_emits_established_then_closed() -> None:
    cap = _Capture()
    source = _mllp()
    source.on_connection_event = cap
    await source.start(_ack_handler)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
        writer.write(frame(ADT))
        await writer.drain()
        await asyncio.wait_for(reader.read(100), 2.0)  # got the ACK → message handled
        assert await _wait_for(lambda: "established" in cap.kinds())
        writer.close()
        await writer.wait_closed()
    finally:
        await source.stop()
    assert cap.kinds()[0] == "established"
    assert "closed" in cap.kinds()
    closed = next((p, r) for k, p, r in cap.events if k == "closed")
    assert closed == ("127.0.0.1", "eof")  # peer host captured; clean-EOF reason


async def test_no_sink_is_a_noop() -> None:
    # Capture off (the default): the listener path is byte-identical — no sink, no crash.
    source = _mllp()
    assert source.on_connection_event is None
    await source.start(_ack_handler)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
        writer.write(frame(ADT))
        await writer.drain()
        assert await asyncio.wait_for(reader.read(100), 2.0)  # ACK still returned
        writer.close()
    finally:
        await source.stop()


async def test_emits_peer_not_allowlisted() -> None:
    cap = _Capture()
    source = _mllp(source_ip_allowlist=["10.0.0.0/8"])  # 127.0.0.1 not allowed
    source.on_connection_event = cap
    await source.start(_ack_handler)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
        assert await asyncio.wait_for(reader.read(), 2.0) == b""  # refused → EOF
        writer.close()
    finally:
        await source.stop()
    assert "peer_not_allowlisted" in cap.kinds()
    assert "established" not in cap.kinds() and "closed" not in cap.kinds()


async def test_emits_at_capacity() -> None:
    cap = _Capture()
    source = _mllp(max_connections=1)
    source.on_connection_event = cap
    await source.start(_ack_handler)
    try:
        _r1, w1 = await asyncio.open_connection("127.0.0.1", source.sockport)
        assert await _wait_for(lambda: source._active == 1)  # first client established
        r2, w2 = await asyncio.open_connection("127.0.0.1", source.sockport)
        assert await asyncio.wait_for(r2.read(), 2.0) == b""  # second refused → EOF
        assert await _wait_for(lambda: "at_capacity" in cap.kinds())
        w1.close()
        w2.close()
    finally:
        await source.stop()


async def test_emits_frame_oversize() -> None:
    cap = _Capture()
    source = _mllp(max_frame_bytes=64)
    source.on_connection_event = cap
    await source.start(_ack_handler)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
        writer.write(bytes([SB]) + b"A" * 200)  # open frame past the cap
        await writer.drain()
        assert await asyncio.wait_for(reader.read(), 2.0) == b""  # dropped → EOF
        assert await _wait_for(lambda: "frame_oversize" in cap.kinds())
        writer.close()
    finally:
        await source.stop()
    # the connection was accepted (established) then failed — no redundant clean 'closed'
    assert "established" in cap.kinds() and "closed" not in cap.kinds()


async def test_idle_timeout_close_reason() -> None:
    cap = _Capture()
    source = _mllp(receive_timeout=0.1)
    source.on_connection_event = cap
    await source.start(_ack_handler)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
        assert await asyncio.wait_for(reader.read(), 2.0) == b""  # idle close
        writer.close()
    finally:
        await source.stop()
    assert await _wait_for(lambda: "closed" in cap.kinds())
    closed_reason = next(r for k, _, r in cap.events if k == "closed")
    assert closed_reason == "idle_timeout"


async def test_tcp_emits_established_then_closed() -> None:
    cap = _Capture()
    source = TcpSource(
        Source(
            type=ConnectorType.TCP, settings={"host": "127.0.0.1", "port": 0, "framing": "vt_fs"}
        )
    )
    source.on_connection_event = cap

    async def handler(raw: bytes) -> None:
        return None

    await source.start(handler)
    try:
        _reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
        assert await _wait_for(lambda: "established" in cap.kinds())
        writer.close()
        await writer.wait_closed()
    finally:
        await source.stop()
    assert cap.kinds()[0] == "established"
    assert "closed" in cap.kinds()


async def test_runner_writes_connection_events_to_store(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "ce_runner.db")
    try:
        reg = Registry()
        reg.add_inbound(
            InboundConnection(
                "IB_T_ADT",
                ConnectionSpec(ConnectorType.MLLP, {"host": "127.0.0.1", "port": 0}),
                router="r",
            )
        )
        reg.add_router("r", lambda m: [])
        runner = RegistryRunner(reg, store)
        await runner.start()
        try:
            port = runner._sources["IB_T_ADT"].sockport  # type: ignore[attr-defined]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(frame(ADT))
            await writer.drain()
            await asyncio.wait_for(reader.read(100), 2.0)
            writer.close()
            await writer.wait_closed()
        finally:
            await runner.stop()  # stops the source (closed emitted) then flushes the drain queue
        events = await store.list_connection_events(connection="IB_T_ADT")
        kinds = {e.kind for e in events}
        assert "established" in kinds and "closed" in kinds
        assert all(e.direction == "inbound" and e.transport == "mllp" for e in events)
    finally:
        await store.close()
