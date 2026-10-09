# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""One admission path for the four asyncio listeners (vault BACKLOG #2606).

The MLLP listener carried a per-host connection cap, a frame deadline and a throttled refusal log.
The raw-TCP and X12 listeners carried none of the three, and every listener wrote one WARNING per
allowlist refusal. These tests drive each listener over a real loopback socket and read only what a
peer or an operator could see: the connection events, the bytes on the socket and the log lines. So
they hold whichever way the admission code is arranged inside the listener.

Each refusal test carries its own control: the same drive with the bound switched off, or the same
listener admitting a peer that is within its budget. A refusal that a broken harness produced would
read as a working cap without one.

Vault BACKLOG #2847 moved the MLLP listener onto the same frame clock, so MLLP joins most of the
frame-deadline tests here, and it put the MLLP stop()'s per-host reset in a ``finally``.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Awaitable, Callable
from types import SimpleNamespace
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.framing import MLLP_CODEC, STX_ETX_CODEC, FrameCodec
from messagefoundry.parsing.x12.interchange import X12FrameReader
from messagefoundry.transports import admission
from messagefoundry.transports.admission import FrameClock, ListenerAdmission, RefusalLog
from messagefoundry.transports.base import SourceConnector
from messagefoundry.transports.http_listener import HttpSource
from messagefoundry.transports.mllp import (
    DEFAULT_MAX_CONNECTIONS_PER_HOST,
    DEFAULT_MAX_FRAME_SECONDS,
    MLLPSource,
    build_ack,
)
from messagefoundry.transports.tcp import TcpSource
from messagefoundry.transports.x12 import X12Source
from tests.test_x12_transport import _interchange

#: A synthetic, PHI-free ADT^A01. Only its framing matters here.
HL7 = (
    "MSH|^~\\&|SND|FAC|RCV|FAC|20260101000000||ADT^A01|MSG0001|P|2.5\r"
    "PID|1||12345^^^MRN||DOE^JANE\r"
)
EDI = _interchange()

#: TEST-NET-1 (RFC 5737). Loopback is never in it, so every local peer is refused.
NOT_LOOPBACK = ["192.0.2.0/24"]


class _Events:
    def __init__(self) -> None:
        self.events: list[tuple[str, str | None, str | None]] = []

    async def __call__(self, kind: str, peer_host: str | None, reason: str | None) -> None:
        self.events.append((kind, peer_host, reason))

    def count(self, kind: str) -> int:
        return sum(1 for k, _, _ in self.events if k == kind)

    def reasons(self, kind: str) -> list[str | None]:
        return [r for k, _, r in self.events if k == kind]


async def _until(predicate: Callable[[], bool], timeout: float = 3.0) -> bool:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.01)
    return predicate()


def _build(kind: str, **settings: Any) -> SourceConnector:
    base: dict[str, Any] = {"host": "127.0.0.1", "port": 0, **settings}
    if kind == "mllp":
        return MLLPSource(Source(type=ConnectorType.MLLP, settings=base))
    if kind == "tcp":
        return TcpSource(Source(type=ConnectorType.TCP, settings={"framing": "stx_etx", **base}))
    if kind == "x12":
        return X12Source(Source(type=ConnectorType.X12, settings=base))
    if kind == "http":
        return HttpSource(Source(type=ConnectorType.HTTP, settings=base))
    raise AssertionError(kind)


async def _reply_handler(raw: bytes) -> str | None:
    return "OK"


async def _ack_handler(raw: bytes) -> str:
    return build_ack(raw, code="AA")


async def _run(
    source: SourceConnector,
    body: Callable[[int], Awaitable[None]],
    handler: Callable[[bytes], Awaitable[str | None]] = _reply_handler,
) -> None:
    await source.start(handler)
    try:
        await body(source.sockport)  # type: ignore[attr-defined]
    finally:
        await asyncio.wait_for(source.stop(), timeout=10.0)


async def _close(writer: asyncio.StreamWriter) -> None:
    writer.close()
    with contextlib.suppress(OSError):
        await writer.wait_closed()


async def _refused(reader: asyncio.StreamReader) -> bool:
    """Whether the listener closed this connection without serving it."""
    try:
        data = await asyncio.wait_for(reader.read(), 3.0)
    except TimeoutError:  # an OSError subclass, so it must be caught first: the socket stayed open
        return False
    except OSError:  # a reset: refused before the close was clean
        return True
    # An HTTP listener writes a short status before it closes; the others write nothing.
    return data == b"" or data.startswith(b"HTTP/1.1 503") or data.startswith(b"HTTP/1.1 403")


# --- The per-host cap ------------------------------------------------------------------------------


@pytest.mark.parametrize("kind", ["tcp", "x12"])
async def test_the_per_host_cap_refuses_a_third_connection_from_one_address(kind: str) -> None:
    """The global cap is OFF, so only a per-host term can refuse the third connection."""
    events = _Events()
    source = _build(kind, max_connections=0, max_connections_per_host=2)
    source.on_connection_event = events

    async def body(port: int) -> None:
        held = [await asyncio.open_connection("127.0.0.1", port) for _ in range(2)]
        assert await _until(lambda: events.count("established") == 2)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        assert await _refused(reader), "a third connection from one address was served"
        assert await _until(lambda: events.count("at_capacity") == 1)
        assert events.reasons("at_capacity") == ["max_connections_per_host"]
        # CONTROL: the budget comes back when one of that host's own connections ends.
        await _close(held[0][1])
        assert await _until(lambda: events.count("closed") == 1)
        _r, again = await asyncio.open_connection("127.0.0.1", port)
        assert await _until(lambda: events.count("established") == 3)
        for w in (held[1][1], writer, again):
            await _close(w)

    await _run(source, body)


@pytest.mark.parametrize("kind", ["tcp", "x12"])
async def test_the_per_host_cap_ships_on_for_raw_tcp_and_x12(kind: str) -> None:
    assert _build(kind).max_connections_per_host == DEFAULT_MAX_CONNECTIONS_PER_HOST  # type: ignore[attr-defined]
    # CONTROL: None and 0 switch it off, as on MLLP.
    assert _build(kind, max_connections_per_host=0).max_connections_per_host is None  # type: ignore[attr-defined]
    with pytest.raises(ValueError, match="max_connections_per_host"):
        _build(kind, max_connections_per_host=-1)


def test_the_per_host_cap_ships_off_for_the_http_listener() -> None:
    # One request per connection behind a reverse proxy would make 32 the listener's whole capacity.
    assert _build("http").max_connections_per_host is None  # type: ignore[attr-defined]
    assert _build("http", max_connections_per_host=4).max_connections_per_host == 4  # type: ignore[attr-defined]


async def test_the_http_listener_applies_a_per_host_cap_an_operator_sets() -> None:
    events = _Events()
    source = _build("http", max_connections=0, max_connections_per_host=1)
    source.on_connection_event = events

    async def body(port: int) -> None:
        _r1, holder = await asyncio.open_connection("127.0.0.1", port)
        assert await _until(lambda: events.count("established") == 1)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        assert await _refused(reader)
        assert await _until(lambda: events.count("at_capacity") == 1)
        assert events.reasons("at_capacity") == ["max_connections_per_host"]
        await _close(writer)
        await _close(holder)

    await _run(source, body)


# --- The frame deadline ----------------------------------------------------------------------------


def _frame_start(kind: str) -> tuple[bytes, bytes]:
    """The bytes that open a frame, and a byte to trickle inside it."""
    if kind == "mllp":
        return b"\x0b", b"A"
    if kind == "tcp":
        return b"\x02", b"A"
    return EDI.encode("ascii")[:120], b"*"


def _whole_frame(kind: str, payload: str = "PAYLOAD") -> bytes:
    """One complete frame for ``kind``. X12 always sends the synthetic interchange."""
    if kind == "mllp":
        return MLLP_CODEC.frame(payload)
    if kind == "tcp":
        return STX_ETX_CODEC.frame(payload)
    return EDI.encode("ascii")


async def _trickle(port: int, kind: str, seconds: float) -> bool:
    """Open a frame, then send one byte every 0.1 s for up to ``seconds``. True if the listener
    closed the connection first. The peer is never idle, so only a frame deadline can close it."""
    start, drip = _frame_start(kind)
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    closed = asyncio.ensure_future(reader.read())
    try:
        writer.write(start)
        await writer.drain()
        loop = asyncio.get_running_loop()
        deadline = loop.time() + seconds
        while loop.time() < deadline:
            if closed.done():
                return True
            try:
                writer.write(drip)
                await writer.drain()
            except (ConnectionResetError, OSError):
                return True
            await asyncio.sleep(0.1)
        return closed.done()
    finally:
        closed.cancel()
        with contextlib.suppress(BaseException):
            await closed
        await _close(writer)


@pytest.mark.parametrize("kind", ["mllp", "tcp", "x12"])
async def test_the_frame_deadline_closes_a_peer_trickling_inside_a_frame(kind: str) -> None:
    events = _Events()
    source = _build(kind, max_frame_seconds=0.5, receive_timeout=5.0)
    source.on_connection_event = events

    async def body(port: int) -> None:
        assert await _trickle(port, kind, 4.0), "a peer trickling inside a frame was never closed"
        assert await _until(lambda: events.count("closed") == 1)
        assert events.reasons("closed") == ["frame_deadline"]

    await _run(source, body)


@pytest.mark.parametrize("kind", ["mllp", "tcp", "x12"])
async def test_the_frame_deadline_also_closes_a_peer_trickling_outside_any_frame(kind: str) -> None:
    """Bytes the decoder discards outside a frame reset the idle bound too, so the deadline must
    start on them as well, or such a peer would hold its slot for as long as it kept sending.

    On MLLP this is vault BACKLOG #2847: its clock used to start only on a start byte."""
    events = _Events()
    source = _build(kind, max_frame_seconds=0.5, receive_timeout=5.0)
    source.on_connection_event = events

    async def body(port: int) -> None:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        closed = asyncio.ensure_future(reader.read())
        try:
            for _ in range(40):  # 4 s of one non-frame byte every 0.1 s
                if closed.done():
                    break
                with contextlib.suppress(OSError):
                    writer.write(b"Z")
                    await writer.drain()
                await asyncio.sleep(0.1)
            assert closed.done(), "a peer trickling bytes outside any frame was never closed"
        finally:
            closed.cancel()
            with contextlib.suppress(BaseException):
                await closed
            await _close(writer)
        assert await _until(lambda: events.count("closed") == 1)
        assert events.reasons("closed") == ["frame_deadline"]

    await _run(source, body)


def test_a_late_stop_does_not_wipe_a_restarted_listeners_counts() -> None:
    gate = ListenerAdmission(
        transport="TCP", max_connections=None, max_connections_per_host=2, source_ip_allowlist=None
    )
    gate.stopping = False  # restarted
    gate.admit("192.0.2.7")
    gate.reset()  # the previous run's stop() finishing late
    assert gate.per_host == {"192.0.2.7": 1}
    # CONTROL: while stopping, reset clears.
    gate.stopping = True
    gate.reset()
    assert gate.per_host == {}


@pytest.mark.parametrize("kind", ["mllp", "tcp", "x12"])
async def test_with_the_frame_deadline_off_the_trickling_peer_stays(kind: str) -> None:
    """CONTROL for the test above: the same drive, with only the deadline switched off."""
    source = _build(kind, max_frame_seconds=0, receive_timeout=5.0)

    async def body(port: int) -> None:
        assert not await _trickle(port, kind, 1.5)

    await _run(source, body)


@pytest.mark.parametrize("kind", ["tcp", "x12"])
def test_the_frame_deadline_ships_on_and_refuses_a_negative(kind: str) -> None:
    assert _build(kind).max_frame_seconds == DEFAULT_MAX_FRAME_SECONDS  # type: ignore[attr-defined]
    assert _build(kind, max_frame_seconds=None).max_frame_seconds is None  # type: ignore[attr-defined]
    with pytest.raises(ValueError, match="max_frame_seconds"):
        _build(kind, max_frame_seconds=-1)


@pytest.mark.parametrize("kind", ["tcp", "x12"])
async def test_a_pipelined_sender_is_not_cut_off_by_the_frame_deadline(kind: str) -> None:
    """The clock restarts for each frame, so a feed that runs longer than the deadline in total,
    one complete frame at a time, is never dropped.

    The sender and the listener share one event loop, and the deadline is many gaps long, so only
    a loop stall longer than ``deadline - gap`` can cut the feed. These are the margins of the
    MLLP twin in tests/test_connection_event_emit.py. Sleeps only run long, so the whole feed
    always outlasts the deadline, and a clock that never restarted would cut it.
    """
    events = _Events()
    received: list[bytes] = []
    deadline, gap, writes = 1.0, 0.03, 60
    assert writes * gap > deadline  # the feed must outlast the deadline in total

    async def handler(raw: bytes) -> str | None:
        received.append(raw)
        return None

    source = _build(kind, max_frame_seconds=deadline, receive_timeout=5.0)
    source.on_connection_event = events
    frame = _whole_frame(kind)

    async def body(port: int) -> None:
        _reader, writer = await asyncio.open_connection("127.0.0.1", port)
        # Each write ends half way through the next frame, so a frame is always open between reads.
        half = len(frame) // 2
        # A drop surfaces as a short count below, which names the defect, not as a reset here.
        with contextlib.suppress(OSError):
            writer.write(frame[:half])
            for _ in range(writes):
                writer.write(frame[half:] + frame[:half])
                await writer.drain()
                await asyncio.sleep(gap)
            writer.write(frame[half:])
            await writer.drain()
        assert await _until(lambda: len(received) == writes + 1), (
            f"{len(received)} of {writes + 1} frames arrived: the frame clock ran across frames"
        )
        await _close(writer)

    await _run(source, body, handler)
    assert "frame_deadline" not in events.reasons("closed")


def test_the_frame_clock_restarts_on_each_completed_frame(monkeypatch: pytest.MonkeyPatch) -> None:
    """The per-frame restart on a fake clock, so no runner's speed can move it. It holds for every
    listener that uses FrameClock; the socket test above shows the listeners do."""
    now = 100.0
    monkeypatch.setattr(admission, "time", SimpleNamespace(monotonic=lambda: now))
    clock = FrameClock(transport="TCP", max_frame_seconds=1.0, receive_timeout=None)
    clock.after_read(in_frame=True, decoded=0, trailer_only=False)
    assert clock.opened_at == 100.0  # the first frame's first bytes start the clock
    now = 100.8
    clock.after_read(in_frame=True, decoded=1, trailer_only=False)
    assert clock.opened_at == 100.8  # a frame completed and the next one opened: a fresh budget
    now = 101.5
    clock.after_read(in_frame=True, decoded=0, trailer_only=False)
    assert clock.opened_at == 100.8  # still the same frame: its clock keeps running
    clock.after_read(in_frame=False, decoded=1, trailer_only=False)
    assert clock.opened_at is None  # the frame completed and none is open: no clock


@pytest.mark.parametrize("kind", ["mllp", "tcp", "x12"])
async def test_whole_frames_with_quiet_gaps_longer_than_the_deadline_are_not_cut_off(
    kind: str,
) -> None:
    """CONTROL for the any-byte clock: a completed frame STOPS the clock, so a peer that sends whole
    frames at a normal pace, quiet for longer than the deadline between them, is never dropped. A
    clock that kept running after a completed frame would cut this feed at the first gap."""
    events = _Events()
    received: list[bytes] = []

    async def handler(raw: bytes) -> str | None:
        received.append(raw)
        return None

    source = _build(kind, max_frame_seconds=0.3, receive_timeout=5.0)
    source.on_connection_event = events

    async def body(port: int) -> None:
        _reader, writer = await asyncio.open_connection("127.0.0.1", port)
        for _ in range(3):
            writer.write(_whole_frame(kind))
            await writer.drain()
            await asyncio.sleep(0.5)  # quiet, for longer than max_frame_seconds
        assert await _until(lambda: len(received) == 3)
        assert events.count("closed") == 0, events.events
        await _close(writer)

    await _run(source, body, handler)
    assert "frame_deadline" not in events.reasons("closed")


@pytest.mark.parametrize(
    ("kind", "after", "cut"),
    [
        ("mllp", b"\r", False),
        (
            "mllp",
            b"\n",
            False,
        ),  # after a trailer that arrived with the FS: CR LF split as FS CR | LF
        ("tcp", b"\r", False),
        ("mllp", b"Z", True),  # CONTROL: any other byte after a completed frame starts the clock
        ("mllp", b"\r\n\r", True),  # CONTROL: line ends past the two-byte allowance are noise
    ],
)
async def test_line_end_bytes_ending_a_frame_do_not_start_the_frame_deadline(
    kind: str, after: bytes, cut: bool
) -> None:
    """Up to two line-end bytes after a frame's end byte belong to that frame. When they reach the
    listener in a read of their own (a TCP segment or a 4096-byte read boundary after the FS), they
    must start nothing, or a healthy peer that then goes quiet is cut as `frame_deadline` (vault
    BACKLOG #2847 review). The raw-TCP case runs the MLLP codec through `framing="mllp"`."""
    events = _Events()
    received: list[bytes] = []

    async def handler(raw: bytes) -> str | None:
        received.append(raw)
        return None

    framing = {"framing": "mllp"} if kind == "tcp" else {}
    source = _build(kind, max_frame_seconds=0.3, receive_timeout=5.0, **framing)
    source.on_connection_event = events
    whole = _whole_frame("mllp")
    # The `\n` row sends the CR with the frame, so the LF is the second line-end byte.
    first = whole if after == b"\n" else whole[:-1]

    async def body(port: int) -> None:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        closed = asyncio.ensure_future(reader.read())
        try:
            writer.write(first)
            await writer.drain()
            assert await _until(lambda: len(received) == 1)
            writer.write(after)
            await writer.drain()
            await asyncio.wait({closed}, timeout=0.9)  # quiet, for three times max_frame_seconds
        finally:
            closed.cancel()
            with contextlib.suppress(BaseException):
                await closed
            await _close(writer)

    await _run(source, body, handler)
    assert ("frame_deadline" in events.reasons("closed")) is cut, events.events


def test_the_decoder_marks_only_a_frames_own_line_ends_as_trailer_only() -> None:
    decoder = MLLP_CODEC.decoder()
    whole = MLLP_CODEC.frame("PAYLOAD")
    assert list(decoder.feed(whole[:-1])) == [b"PAYLOAD"]
    assert not decoder.trailer_only
    assert list(decoder.feed(b"\r")) == []
    assert decoder.trailer_only, "the CR ending the frame"
    assert list(decoder.feed(b"\n")) == []
    assert decoder.trailer_only, "the LF of a CR LF ending"
    # CONTROL: a third line-end byte is past the allowance, so it is noise like any other byte.
    assert list(decoder.feed(b"\r")) == []
    assert not decoder.trailer_only
    # CONTROL: a byte that is not a line end ends the allowance for what follows it too.
    assert list(decoder.feed(whole[:-1])) == [b"PAYLOAD"]
    assert list(decoder.feed(b"Z")) == []
    assert not decoder.trailer_only
    assert list(decoder.feed(b"\r")) == []
    assert not decoder.trailer_only
    # A whole frame with its CR leaves one byte of allowance, for an LF.
    assert list(decoder.feed(whole)) == [b"PAYLOAD"]
    assert list(decoder.feed(b"\n")) == []
    assert decoder.trailer_only
    # Decided when feed() is called, before its generator runs, so it never describes a past read.
    assert list(decoder.feed(whole)) == [b"PAYLOAD"]
    decoder.feed(b"Z")  # not iterated
    assert not decoder.trailer_only
    # STX/ETX framing takes the same line-end allowance.
    plain = STX_ETX_CODEC.decoder()
    assert list(plain.feed(STX_ETX_CODEC.frame("P"))) == [b"P"]
    assert list(plain.feed(b"\r\n")) == []
    assert plain.trailer_only
    # A configured trailer that is not a line end is part of the allowance too.
    eot = FrameCodec(start=0x02, end=0x03, trailer=0x04).decoder()
    assert list(eot.feed(b"\x02P\x03")) == [b"P"]
    assert list(eot.feed(b"\x04")) == []
    assert eot.trailer_only
    # CONTROL: the same byte on a codec without that trailer is noise.
    assert list(plain.feed(STX_ETX_CODEC.frame("P"))) == [b"P"]
    assert list(plain.feed(b"\x04")) == []
    assert not plain.trailer_only


def test_the_x12_reader_reports_an_open_interchange() -> None:
    reader = X12FrameReader()
    assert not reader.in_frame
    data = EDI.encode("ascii")
    assert list(reader.feed(b"noise ")) == []
    assert not reader.in_frame, "noise before an ISA opens nothing"
    assert list(reader.feed(data[:50])) == []
    assert reader.in_frame
    assert len(list(reader.feed(data[50:]))) == 1
    assert not reader.in_frame


# --- The allowlist refusal log ---------------------------------------------------------------------


def _allowlist_lines(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.levelno >= logging.WARNING and "source_ip_allowlist" in r.getMessage()
    ]


@pytest.mark.parametrize("kind", ["mllp", "tcp", "x12", "http"])
async def test_repeated_allowlist_refusals_log_one_warning(
    kind: str, caplog: pytest.LogCaptureFixture
) -> None:
    events = _Events()
    source = _build(kind, source_ip_allowlist=NOT_LOOPBACK)
    source.on_connection_event = events

    async def body(port: int) -> None:
        for _ in range(5):
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            # CONTROL, inside the loop: every one of the five really was refused.
            assert await _refused(reader)
            await _close(writer)
        # The event still records every refusal, for anyone counting them.
        assert await _until(lambda: events.count("peer_not_allowlisted") == 5)

    with caplog.at_level(logging.WARNING):
        await _run(source, body, _ack_handler if kind == "mllp" else _reply_handler)
    lines = _allowlist_lines(caplog)
    assert len(lines) == 1, lines
    assert (
        "5 refused" not in lines[0]
    )  # the first line carries the count at the time it was written
    assert "127.0.0.1" in lines[0]


def test_the_refusal_log_is_per_address_and_capped_across_addresses() -> None:
    log = RefusalLog(window_seconds=60.0, max_per_window=3)
    assert log.note("192.0.2.1") == 1
    assert log.note("192.0.2.1") is None, "a second refusal inside the window is not logged"
    assert log.note("192.0.2.2") == 3
    assert log.note("192.0.2.3") == 4
    assert log.note("192.0.2.4") is None, "the window's ceiling across addresses holds"
    assert log.refusals == 5, "every refusal is counted, logged or not"
    assert len(log.logged) == 3


def test_the_refusal_log_logs_an_address_again_after_its_window() -> None:
    log = RefusalLog(window_seconds=60.0, max_per_window=3)
    assert log.note("192.0.2.1") == 1
    log.logged["192.0.2.1"] -= 61.0  # age the line past the window, in place of sleeping
    assert log.note("192.0.2.1") == 2
    assert list(log.logged) == ["192.0.2.1"]


def test_the_refusal_log_defaults_match_the_dicom_server() -> None:
    from messagefoundry.transports import dicom

    assert dicom._REFUSAL_LOG_WINDOW_SECONDS == admission.REFUSAL_LOG_WINDOW_SECONDS
    assert dicom._REFUSAL_LOG_MAX_PER_WINDOW == admission.REFUSAL_LOG_MAX_PER_WINDOW


# --- Stopping, and the slot accounting -------------------------------------------------------------


def test_admission_refuses_while_stopping_and_releases_what_it_admits() -> None:
    gate = ListenerAdmission(
        transport="TCP", max_connections=2, max_connections_per_host=1, source_ip_allowlist=None
    )

    class _W:
        def get_extra_info(self, name: str, default: object = None) -> object:
            return ("192.0.2.7", 4000) if name == "peername" else default

    w: Any = _W()
    assert gate.check(w, "192.0.2.7") is None
    gate.admit("192.0.2.7")
    refusal = gate.check(w, "192.0.2.7")
    assert refusal is not None and refusal.reason == "max_connections_per_host"
    gate.release("192.0.2.7")
    assert gate.active == 0 and gate.per_host == {}
    assert gate.host_capacity_warned == set()
    gate.stopping = True
    refusal = gate.check(w, "192.0.2.8")
    assert refusal is not None and refusal.kind is None, "a stop refusal emits no event"


@pytest.mark.parametrize("kind", ["tcp", "x12", "http"])
async def test_a_connection_reaching_a_stopping_listener_is_refused_unread(kind: str) -> None:
    events = _Events()
    calls: list[bytes] = []

    async def handler(raw: bytes) -> str | None:
        calls.append(raw)
        return None

    source = _build(kind)
    source.on_connection_event = events

    async def body(port: int) -> None:
        source._admission.stopping = True  # type: ignore[attr-defined]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        with contextlib.suppress(OSError):
            writer.write(b"\x02x\x03")
            await writer.drain()
        assert await _refused(reader)
        await _close(writer)
        source._admission.stopping = False  # type: ignore[attr-defined]

    await _run(source, body, handler)
    assert events.count("established") == 0
    assert calls == []


@pytest.mark.parametrize("how", ["cancelled", "raises"])
@pytest.mark.parametrize("kind", ["mllp", "tcp", "x12"])
async def test_a_stop_cut_short_in_its_wait_still_clears_the_per_host_count(
    kind: str, how: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """stop()'s per-host reset runs in a ``finally``; vault BACKLOG #2847 added it on MLLP, and the
    other two already had it. A client held inside its handler keeps stop() in its grace wait; the
    wait is then cancelled, or raises. Without the ``finally`` the count survives, and a restarted
    listener would refuse that address early."""
    entered = asyncio.Event()
    release = asyncio.Event()

    async def handler(raw: bytes) -> str:
        entered.set()
        await release.wait()
        return build_ack(raw, code="AA")

    source = _build(kind)
    await source.start(handler)
    gate = source._admission  # type: ignore[attr-defined]
    client_tasks = source._client_tasks  # type: ignore[attr-defined]
    writer: asyncio.StreamWriter | None = None
    try:
        _reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)  # type: ignore[attr-defined]
        writer.write(_whole_frame(kind, HL7))
        await writer.drain()
        await asyncio.wait_for(entered.wait(), 3.0)
        # CONTROL: the count the stop must clear is really there before it runs.
        assert gate.per_host == {"127.0.0.1": 1}
        if how == "cancelled":
            stopping = asyncio.ensure_future(source.stop())
            await asyncio.sleep(0.1)  # inside the 5 s client-task grace wait
            assert not stopping.done(), "stop() did not wait on the held client"
            stopping.cancel()
            with pytest.raises(asyncio.CancelledError):
                await stopping
        else:
            real_wait = asyncio.wait

            async def failing_wait(fs: Any, *args: Any, **kwargs: Any) -> Any:
                # Fail only the listener's own client-task wait; any other task on the shared loop
                # that calls asyncio.wait meanwhile gets the real one.
                fs = list(fs)
                if any(task in client_tasks for task in fs):
                    raise RuntimeError("synthetic failure in stop()'s client-task wait")
                return await real_wait(fs, *args, **kwargs)

            with monkeypatch.context() as patch:
                patch.setattr(asyncio, "wait", failing_wait)
                with pytest.raises(RuntimeError, match="synthetic failure"):
                    await source.stop()
        assert gate.per_host == {}, "a stop() cut short left a stale per-host count behind"
    finally:
        release.set()
        if writer is not None:
            await _close(writer)
        await asyncio.wait_for(source.stop(), timeout=10.0)


# --- A normal frame still flows, and is answered, with every new bound at its default -------------


async def test_mllp_still_acks_a_normal_frame() -> None:
    source = _build("mllp")

    async def body(port: int) -> None:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(_whole_frame("mllp", HL7))
        await writer.drain()
        ack = await asyncio.wait_for(reader.readuntil(b"\x1c\r"), 5.0)
        assert b"MSA|AA|MSG0001" in ack
        await _close(writer)

    await _run(source, body, _ack_handler)


@pytest.mark.parametrize("kind", ["tcp", "x12"])
async def test_raw_tcp_and_x12_still_hand_over_a_normal_frame_and_reply(kind: str) -> None:
    received: list[bytes] = []

    async def handler(raw: bytes) -> str | None:
        received.append(raw)
        return "OK"

    source = _build(kind)
    frame = _whole_frame(kind, HL7)

    async def body(port: int) -> None:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(frame)
        await writer.drain()
        reply = await asyncio.wait_for(reader.read(64), 5.0)
        assert b"OK" in reply
        await _close(writer)

    await _run(source, body, handler)
    assert len(received) == 1
