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

BACKLOG #5022, step 2: on an inbound that owes no reply, the faulted frame is now held and retried
through ``transports.base.hold_and_retry`` until it is recorded or the listener stops, as on the
raw-TCP and X12 listeners. The shipped code recorded ``handler_error`` and read on, dropping the
frame. A refused sender (BACKLOG #4907) is not held; its test pins that it still is not.

Synthetic HL7 only, never real PHI.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, NoReturn

import pytest

import messagefoundry.transports.base as base_mod
from messagefoundry.config.models import AckMode, ConnectorType, ContentType, Source
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import ConnectionSpec, InboundConnection, Registry
from messagefoundry.parsing.peek import Peek
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStore
from messagefoundry.transports import mllp as mllp_mod
from messagefoundry.transports.mllp import CR, EB, MLLPSource, build_ack, frame
from tests.test_x12_connection_events import Event, _Peer, _sink

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


class _Recording:
    """Raise a store-shaped fault on the first ``failures`` calls, then record each frame it is
    handed and return no reply, as a no-reply inbound's handler does."""

    def __init__(self, failures: int = 1) -> None:
        self.failures = failures
        self.calls = 0
        self.recorded: list[bytes] = []

    async def __call__(self, raw: bytes) -> str | None:
        self.calls += 1
        if self.calls <= self.failures:
            raise RuntimeError(_FAULT_TEXT)
        self.recorded.append(raw)
        return None


async def test_an_ackless_inbound_keeps_the_socket_and_holds_the_frame() -> None:
    # AckMode.NONE: the sender expects no reply and never resends. Dropping the socket would also
    # discard the frames already sent behind the faulted one, so the listener keeps it, and it
    # holds the faulted frame until a retry records it (BACKLOG #5022), over a real socket.
    cap = _Capture()
    source = _mllp(AckMode.NONE)
    source.on_connection_event = cap
    handler = _Recording()
    await source.start(handler)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
        writer.write(frame(_ADT) + frame(_ADT2))
        await writer.drain()
        assert await _wait_for(lambda: handler.calls == 3), handler.calls
        writer.close()
        await writer.wait_closed()
        assert await _read_eof(reader) == b""  # nothing was ever sent back
    finally:
        await asyncio.wait_for(source.stop(), timeout=5.0)
    assert handler.recorded == [_ADT.encode(), _ADT2.encode()]
    kinds = cap.kinds()
    # A fault the first retry clears is no handler_error: hold_and_retry reports only one that
    # outlasts HANDLER_FAULT_REPORT_AFTER attempts.
    assert "handler_error" not in kinds and "framing_error" not in kinds, kinds


async def test_a_non_hl7_inbound_gets_no_hl7_reply() -> None:
    # The runner injects the content type; it never answers a non-HL7 body in HL7, so neither
    # does the listener, even for a body that happens to start with MSH. It holds the frame instead.
    cap = _Capture()
    source = _mllp()
    source.on_connection_event = cap
    source.content_type = ContentType.TEXT
    handler = _Recording()
    await source.start(handler)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
        writer.write(frame(_ADT) + frame(_ADT2))
        await writer.drain()
        assert await _wait_for(lambda: handler.calls == 3), handler.calls
        writer.close()
        await writer.wait_closed()
        assert await _read_eof(reader) == b""
    finally:
        await asyncio.wait_for(source.stop(), timeout=5.0)
    assert handler.recorded == [_ADT.encode(), _ADT2.encode()]
    assert "framing_error" not in cap.kinds(), cap.kinds()


# --- BACKLOG #5022, step 2: the no-reply arm holds the frame, as the raw-TCP and X12 listeners do.
#
# In the shipped code the MLLP listener recorded `handler_error` on a no-reply inbound's handler
# fault and read on, so the faulted frame was dropped: the sender never resends, and the frame in
# hand was its only copy. These drive `_on_client` with fakes, as tests/test_tcp_x12_handler_failure.py
# does, with the retry pauses zeroed so a test stays inside the 2 s bound; nothing binds a port.

REPORT_AFTER = base_mod.HANDLER_FAULT_REPORT_AFTER


class _ThenEof:
    """Hands over one chunk, then hangs up."""

    def __init__(self, data: bytes) -> None:
        self._data = data

    async def read(self, _n: int) -> bytes:
        chunk, self._data = self._data, b""
        return chunk


@pytest.fixture
def no_retry_pauses(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(base_mod, "HANDLER_RETRY_DELAYS", (0.0,))


def _no_reply() -> MLLPSource:
    return _mllp(AckMode.NONE)


async def _drive(source: MLLPSource, reader: object, writer: _Peer, handler: object) -> list[Event]:
    events: list[Event] = []
    source.on_connection_event = _sink(events)  # type: ignore[assignment]
    source._handler = handler  # type: ignore[assignment]
    await asyncio.wait_for(source._on_client(reader, writer), timeout=2.0)  # type: ignore[arg-type]
    return events


def _kinds_of(events: list[Event]) -> list[str]:
    return [kind for kind, _, _ in events]


@pytest.mark.usefixtures("no_retry_pauses")
async def test_no_reply_a_fault_once_is_held_and_the_frames_behind_it_keep_their_order(
    caplog: pytest.LogCaptureFixture,
) -> None:
    handler = _Recording()
    writer = _Peer()
    with caplog.at_level(logging.WARNING):
        events = await _drive(_no_reply(), _ThenEof(frame(_ADT) + frame(_ADT2)), writer, handler)
    assert handler.recorded == [_ADT.encode(), _ADT2.encode()], "held, retried, then the next"
    assert handler.calls == 3
    assert _kinds_of(events) == ["established", "closed"], "a fault a retry clears is no event"
    assert not writer.written, "a no-reply inbound sends nothing"
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert any("retrying in" in r.getMessage() for r in caplog.records)


@pytest.mark.usefixtures("no_retry_pauses")
async def test_no_reply_a_long_fault_is_reported_once_and_the_frame_held_until_recorded(
    caplog: pytest.LogCaptureFixture,
) -> None:
    failures = REPORT_AFTER + 2
    handler = _Recording(failures)
    with caplog.at_level(logging.WARNING):
        events = await _drive(_no_reply(), _ThenEof(frame(_ADT) + frame(_ADT2)), _Peer(), handler)
    assert handler.recorded == [_ADT.encode(), _ADT2.encode()]
    assert _kinds_of(events) == ["established", "handler_error", "closed"]
    reason = events[1][2]
    assert reason is not None and "RuntimeError" in reason and "JANE" not in reason
    errors = [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == 1 and errors[0].startswith("MLLP message")
    assert "held and retried" in errors[0]


@pytest.mark.usefixtures("no_retry_pauses")
async def test_no_reply_a_stop_during_the_hold_gets_one_last_attempt_then_names_the_loss(
    caplog: pytest.LogCaptureFixture,
) -> None:
    source = _no_reply()
    seen: list[bytes] = []

    async def explode_then_stop(raw: bytes) -> None:
        seen.append(raw)
        if len(seen) == 2:
            source._stopping = True
        raise RuntimeError(_FAULT_TEXT)

    writer = _Peer()
    with caplog.at_level(logging.WARNING):
        events = await _drive(
            source, _ThenEof(frame(_ADT) + frame(_ADT2)), writer, explode_then_stop
        )
    # The stop lands during attempt 2, which fails, so attempt 3 is the last one, and the frame
    # behind it in the read is never handled.
    assert seen == [_ADT.encode()] * 3
    assert _kinds_of(events) == ["established", "handler_error"], (
        "reported, and a failed connection must not also emit `closed`"
    )
    assert writer.closed and not writer.written
    last = [r for r in caplog.records if "one last attempt" in r.getMessage()]
    assert len(last) == 1
    errors = [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == 1
    assert "nor is any frame behind it" in errors[0] and "listener is stopping" in errors[0]
    assert "JANE" not in errors[0]


@pytest.mark.usefixtures("no_retry_pauses")
async def test_no_reply_a_stop_whose_last_attempt_succeeds_loses_nothing(
    caplog: pytest.LogCaptureFixture,
) -> None:
    source = _no_reply()
    seen: list[bytes] = []

    async def stop_then_recover(raw: bytes) -> None:
        seen.append(raw)
        if len(seen) == 1:
            source._stopping = True
            raise RuntimeError(_FAULT_TEXT)

    with caplog.at_level(logging.WARNING):
        events = await _drive(source, _ThenEof(frame(_ADT)), _Peer(), stop_then_recover)
    assert seen == [_ADT.encode()] * 2
    assert _kinds_of(events) == ["established", "closed"]
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]


@pytest.mark.usefixtures("no_retry_pauses")
async def test_no_reply_a_retry_runs_outside_the_first_faults_except_clause() -> None:
    # A hold can last hours. Run inside the listener's `except` arm, it would keep the first fault,
    # its traceback and the message locals that traceback references, alive the whole time.
    handling: list[object] = []

    async def fail_then_look(raw: bytes) -> None:
        if not handling:
            handling.append(None)
            raise RuntimeError(_FAULT_TEXT)
        handling.append(sys.exc_info()[1])

    events = await _drive(_no_reply(), _ThenEof(frame(_ADT)), _Peer(), fail_then_look)
    assert handling == [None, None], "no exception is being handled while the retry runs"
    assert _kinds_of(events) == ["established", "closed"]


@pytest.mark.usefixtures("no_retry_pauses")
async def test_no_reply_a_retry_still_takes_an_in_flight_slot() -> None:
    # Each attempt runs through _handle_bounded, so the listener's in-flight bound still applies
    # to a retry, and the slot is given back between attempts rather than held across the pause.
    source = _no_reply()
    slots = asyncio.Semaphore(1)
    source._inflight = slots
    held: list[bool] = []

    async def fail_then_record(raw: bytes) -> None:
        held.append(slots.locked())
        if len(held) == 1:
            raise RuntimeError(_FAULT_TEXT)

    events = await _drive(source, _ThenEof(frame(_ADT)), _Peer(), fail_then_record)
    assert held == [True, True], "both attempts ran inside a slot"
    assert not slots.locked(), "and the slot was released after the last"
    assert _kinds_of(events) == ["established", "closed"]


async def test_a_refused_sender_on_a_no_reply_inbound_is_not_held(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # BACKLOG #4907: a sender outside tls_client_subjects is refused, and its connection closes
    # after the read. A hold would keep that refused peer's socket open for a whole store outage,
    # so its faulted frame gets one attempt, handler_error and the close, as before. The lost ERROR
    # row is the gap docs/CONNECTIONS.md names for that case.
    source = _no_reply()
    calls: list[bytes] = []

    async def refuse(raw: bytes) -> None:
        calls.append(raw)
        raise RuntimeError(_FAULT_TEXT)

    async def admit_refused(_writer: object, _peer_host: object) -> tuple[object, bool]:
        return refuse, True

    monkeypatch.setattr(source, "_admit_sender", admit_refused)
    writer = _Peer()
    with caplog.at_level(logging.WARNING):
        events = await _drive(source, _ThenEof(frame(_ADT) + frame(_ADT2)), writer, refuse)
    assert calls == [_ADT.encode(), _ADT2.encode()], "one attempt each, no retry"
    assert _kinds_of(events) == ["handler_error", "handler_error"]
    assert writer.closed and not writer.written
    assert not any("retrying in" in r.getMessage() for r in caplog.records)


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
        if isinstance(inbound, Peek):
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
        runner = RegistryRunner(reg, store, egress=EgressSettings(deny_by_default=False))
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
        assert await store.count_messages(allowed_channels=None) == 0
        kinds = {
            e.kind
            for e in await store.list_connection_events(
                connection="IB_T_ADT", allowed_channels=None
            )
        }
        assert "handler_error" in kinds and "framing_error" not in kinds, kinds
    finally:
        await store.close()
