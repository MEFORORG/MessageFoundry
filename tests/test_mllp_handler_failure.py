# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1619: the MLLP listener answers a handler fault with a NAK, not a silent drop.

The runner lets a store exception at the ingress commit propagate (BACKLOG #1608 pins that). Before
this fix the exception reached the listener's last-resort catch, which dropped the connection with no
reply and recorded the event as ``framing_error``. A store outage is not a framing fault, and a
dropped socket gives the sender no protocol signal to back off on.

Every test here but one fails on the pre-fix listener: the NAK arms read EOF instead of a reply,
and the no-reply arms record ``framing_error`` instead of ``handler_error``. The exception is
``test_a_codec_fault_in_the_listener_still_drops_as_framing_error``, which pins the other side: a
codec fault in the listener itself still reaches the last-resort arm, which still drops.

Synthetic HL7 only, never real PHI.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Callable
from pathlib import Path
from typing import Any, NoReturn

import pytest

from messagefoundry.config.models import AckMode, ConnectorType, ContentType, Source
from messagefoundry.config.wiring import ConnectionSpec, InboundConnection, Registry
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStore
from messagefoundry.transports import mllp as mllp_mod
from messagefoundry.transports.mllp import CR, EB, MLLPSource, build_ack, frame

_ADT = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"
_ADT2 = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG2|P|2.5.1\rPID|1||101^^^H^MR||ROE^RICH\r"
# The fault's text carries a segment, the way a driver error quoting a bound parameter would.
_FAULT_TEXT = "database is locked binding PID|1||100^^^H^MR||DOE^JANE"


class _Capture:
    def __init__(self) -> None:
        self.events: list[tuple[str, str | None, str | None]] = []

    async def __call__(self, kind: str, peer_host: str | None, reason: str | None) -> None:
        self.events.append((kind, peer_host, reason))

    def kinds(self) -> list[str]:
        return [k for k, _, _ in self.events]


def _mllp(ack_mode: AckMode = AckMode.ORIGINAL, **settings: object) -> MLLPSource:
    return MLLPSource(
        Source(
            type=ConnectorType.MLLP,
            settings={"host": "127.0.0.1", "port": 0, **settings},
            ack_mode=ack_mode,
        )
    )


async def _read_reply(reader: asyncio.StreamReader, timeout: float = 3.0) -> bytes:
    """One framed reply (through its trailing CR), or ``b""`` if the listener closed the socket instead."""
    with contextlib.suppress(ConnectionResetError, asyncio.IncompleteReadError):
        return await asyncio.wait_for(reader.readuntil(bytes([EB, CR])), timeout)
    return b""


async def _read_eof(reader: asyncio.StreamReader, timeout: float = 3.0) -> bytes:
    with contextlib.suppress(ConnectionResetError):
        return await asyncio.wait_for(reader.read(), timeout)
    return b""


async def _wait_for(predicate: Callable[[], bool], timeout: float = 3.0) -> bool:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.01)
    return False


class _FaultFirst:
    """Raise a store-shaped fault on the first message, then ACK (or return nothing) normally."""

    def __init__(self, *, reply: bool = True) -> None:
        self.calls = 0
        self.reply = reply

    async def __call__(self, raw: bytes) -> str | None:
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError(_FAULT_TEXT)
        return build_ack(raw, code="AA") if self.reply else None


async def _boom(raw: bytes) -> str | None:
    raise RuntimeError(_FAULT_TEXT)


async def test_a_store_outage_is_answered_with_ae_then_the_connection_closes() -> None:
    cap = _Capture()
    source = _mllp()
    source.on_connection_event = cap
    handler = _FaultFirst()
    await source.start(handler)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
        writer.write(frame(_ADT))
        await writer.drain()
        nak = await _read_reply(reader)
        # AE: this engine's "not accepted, try again" (its own MLLP destination retries AE).
        assert b"MSA|AE|MSG1|" in nak, nak
        assert mllp_mod._HANDLER_FAILURE_NAK_TEXT.encode() in nak
        assert b"locked" not in nak  # the fault's text never reaches the sender
        assert await _read_eof(reader) == b""  # then the connection closes
        writer.close()
        await writer.wait_closed()
        # The listener survived: the resend on a fresh connection is ACKed.
        reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
        writer.write(frame(_ADT2))
        await writer.drain()
        assert b"MSA|AA|MSG2" in await _read_reply(reader)
        writer.close()
        await writer.wait_closed()
    finally:
        await asyncio.wait_for(source.stop(), timeout=5.0)
    assert handler.calls == 2
    kinds = cap.kinds()
    assert "handler_error" in kinds and "framing_error" not in kinds, kinds
    # handler_error names why the first connection closed, so it carries no `closed` of its own.
    assert kinds[:2] == ["established", "handler_error"], kinds
    reason = next(r for k, _, r in cap.events if k == "handler_error")
    assert reason is not None and "RuntimeError" in reason
    assert "JANE" not in reason  # safe_exc redacts the segment out of the recorded reason


async def test_enhanced_mode_answers_ce() -> None:
    source = _mllp(AckMode.ENHANCED)
    await source.start(_boom)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
        writer.write(frame(_ADT))
        await writer.drain()
        assert b"MSA|CE|MSG1|" in await _read_reply(reader)
        writer.close()
        await writer.wait_closed()
    finally:
        await asyncio.wait_for(source.stop(), timeout=5.0)


async def test_a_frame_pipelined_behind_a_fault_is_left_for_the_sender_to_resend() -> None:
    # One write carrying two frames. The second is not handled: the sender got no reply for it, so
    # it resends it after the first, and the order the sender chose holds.
    source = _mllp()
    handler = _FaultFirst()
    await source.start(handler)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
        writer.write(frame(_ADT) + frame(_ADT2))
        await writer.drain()
        assert b"MSA|AE|MSG1|" in await _read_reply(reader)
        assert await _read_eof(reader) == b""
        writer.close()
        await writer.wait_closed()
    finally:
        await asyncio.wait_for(source.stop(), timeout=5.0)
    assert handler.calls == 1


async def test_an_ackless_inbound_keeps_the_socket_and_handles_what_follows() -> None:
    # AckMode.NONE: the sender expects no reply and never resends. Dropping the socket would also
    # discard the frames already sent behind the faulted one, so the listener keeps it.
    cap = _Capture()
    source = _mllp(AckMode.NONE)
    source.on_connection_event = cap
    handler = _FaultFirst(reply=False)
    await source.start(handler)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
        writer.write(frame(_ADT) + frame(_ADT2))
        await writer.drain()
        assert await _wait_for(lambda: handler.calls == 2), handler.calls
        writer.close()
        await writer.wait_closed()
        assert await _read_eof(reader) == b""  # nothing was ever sent back
    finally:
        await asyncio.wait_for(source.stop(), timeout=5.0)
    kinds = cap.kinds()
    assert "handler_error" in kinds and "framing_error" not in kinds, kinds


async def test_a_non_hl7_inbound_gets_no_hl7_reply() -> None:
    # The runner injects the content type; it never answers a non-HL7 body in HL7, so neither
    # does the listener, even for a body that happens to start with MSH.
    cap = _Capture()
    source = _mllp()
    source.on_connection_event = cap
    source.content_type = ContentType.TEXT
    handler = _FaultFirst(reply=False)
    await source.start(handler)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
        writer.write(frame(_ADT) + frame(_ADT2))
        await writer.drain()
        assert await _wait_for(lambda: handler.calls == 2), handler.calls
        writer.close()
        await writer.wait_closed()
        assert await _read_eof(reader) == b""
    finally:
        await asyncio.wait_for(source.stop(), timeout=5.0)
    assert "handler_error" in cap.kinds() and "framing_error" not in cap.kinds(), cap.kinds()


async def test_an_unreadable_header_is_answered_with_the_defaults() -> None:
    # An HL7 inbound owes a reply even for a body with no MSH: the runner would NAK it AR after
    # recording ERROR, and if that write faults the sender must still hear something.
    source = _mllp()
    await source.start(_boom)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
        writer.write(frame("not an HL7 message"))
        await writer.drain()
        assert b"MSA|AE||" in await _read_reply(reader)
        writer.close()
        await writer.wait_closed()
    finally:
        await asyncio.wait_for(source.stop(), timeout=5.0)


async def test_a_header_that_faults_the_ack_builder_falls_back_to_defaults(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The fault may come from reading the very message being answered (BACKLOG #1594's shape), so a
    # build_ack that faults on the parsed header must not cost the sender its NAK.
    real = mllp_mod.build_ack

    def faulting(inbound: Any, **kwargs: Any) -> str:
        if isinstance(inbound, mllp_mod.Peek):
            raise IndexError("string index out of range")
        return real(inbound, **kwargs)

    monkeypatch.setattr(mllp_mod, "build_ack", faulting)
    source = _mllp()
    await source.start(_boom)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
        writer.write(frame(_ADT))
        await writer.drain()
        # Header defaults: no control id to echo, but still a NAK.
        assert b"MSA|AE||" in await _read_reply(reader)
        writer.close()
        await writer.wait_closed()
    finally:
        await asyncio.wait_for(source.stop(), timeout=5.0)


async def test_an_owed_reply_that_cannot_be_built_closes_the_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The last fallback: a reply is owed and not even the default header can be framed. The
    # connection closes, and handler_error still names the cause.
    def never(*args: Any, **kwargs: Any) -> str:
        raise ValueError("cannot build")

    monkeypatch.setattr(mllp_mod, "build_ack", never)
    cap = _Capture()
    source = _mllp()
    source.on_connection_event = cap
    await source.start(_boom)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
        writer.write(frame(_ADT))
        await writer.drain()
        assert await _read_eof(reader) == b""
        writer.close()
        await writer.wait_closed()
    finally:
        await asyncio.wait_for(source.stop(), timeout=5.0)
    kinds = cap.kinds()
    assert kinds == ["established", "handler_error"], kinds


async def test_a_codec_fault_in_the_listener_still_drops_as_framing_error() -> None:
    # The last-resort arm (ASVS 16.5.4) still covers the listener's own path: a reply the
    # listener's encoding cannot carry is not a handler fault, and it still drops the connection.
    cap = _Capture()
    source = _mllp(encoding="ascii")
    source.on_connection_event = cap

    async def unencodable(raw: bytes) -> str:
        return build_ack(raw, code="AA", text="café")

    await source.start(unencodable)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
        writer.write(frame(_ADT))
        await writer.drain()
        assert await _read_eof(reader) == b""
        writer.close()
        await writer.wait_closed()
    finally:
        await asyncio.wait_for(source.stop(), timeout=5.0)
    kinds = cap.kinds()
    assert "framing_error" in kinds and "handler_error" not in kinds, kinds


async def _raise_locked(*args: Any, **kwargs: Any) -> NoReturn:
    raise RuntimeError("database is locked")


async def test_end_to_end_an_ingress_commit_failure_reaches_the_sender_as_ae(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = await MessageStore.open(tmp_path / "ingress_outage.db")
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
            monkeypatch.setattr(store, "enqueue_ingress", _raise_locked)
            port = runner._sources["IB_T_ADT"].sockport  # type: ignore[attr-defined]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(frame(_ADT))
            await writer.drain()
            nak = await _read_reply(reader)
            assert b"MSA|AE|MSG1|" in nak, nak
            assert b"MSA|AA" not in nak  # never an acceptance over a store that took nothing
            writer.close()
            await writer.wait_closed()
        finally:
            await asyncio.wait_for(runner.stop(), timeout=5.0)
        assert await store.count_messages() == 0
        kinds = {e.kind for e in await store.list_connection_events(connection="IB_T_ADT")}
        assert "handler_error" in kinds and "framing_error" not in kinds, kinds
    finally:
        await store.close()
