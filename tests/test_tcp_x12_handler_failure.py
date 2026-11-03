# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A fault in the inbound handler on the raw-TCP and X12 listeners (BACKLOG #5022).

Both listeners caught a handler fault in their last-resort arm, recorded ``framing_error`` and
dropped the connection. The decoder had read the frame cleanly, so the event blamed the wrong
layer. A sender that waits for no reply never resends, so the drop lost that frame and every frame
already sent behind it, with nothing naming the loss.

Now the event is ``handler_error`` (``transports.base.recover_handler_fault``). When the inbound
owes a reply the listener closes, so the sender resends. When it owes none the handler is retried
in place on the frame in hand, and if it still faults the listener logs the loss of that one frame
and keeps reading the frames behind it.

Each test runs on both listeners through the same fakes. The listener is driven by calling
``_on_client`` with fakes, as ``tests/test_x12_connection_events.py`` does; nothing binds a port.
Synthetic payloads only.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

import pytest

import messagefoundry.transports.base as base_mod
from messagefoundry.config.models import AckMode, ContentType
from messagefoundry.redaction import safe_exc
from messagefoundry.transports.tcp import TcpSource
from messagefoundry.transports.x12 import X12Source
from tests.test_x12_connection_events import EDI, _drive, _kinds, _Peer, _tcp, _x12

#: A frame the raw-TCP decoder reads cleanly; the X12 one is the ISA/IEA interchange ``EDI``.
TCP_FRAME = b"\x02synthetic raw tcp body\x03"

Build = Callable[[], X12Source | TcpSource]
LISTENERS: list[tuple[str, Build, bytes, bytes]] = [
    ("X12", _x12, EDI, EDI),
    ("TCP", _tcp, TCP_FRAME, b"synthetic raw tcp body"),
]


class _ThenEof:
    """Hands over one chunk, then hangs up."""

    def __init__(self, data: bytes) -> None:
        self._data = data

    async def read(self, _n: int) -> bytes:
        chunk, self._data = self._data, b""
        return chunk


@pytest.fixture(autouse=True)
def _no_retry_pauses(monkeypatch: pytest.MonkeyPatch) -> None:
    # The same number of attempts, without the real pauses, so a test stays inside _drive's bound.
    monkeypatch.setattr(base_mod, "HANDLER_RETRY_DELAYS", (0.0, 0.0, 0.0))


def _attempts() -> int:
    return len(base_mod.HANDLER_RETRY_DELAYS) + 1


def _no_reply(build: Build) -> X12Source | TcpSource:
    """A listener whose inbound owes its sender no reply: a non-HL7 content type, as the runner
    injects for an X12 or raw-X12 feed."""
    source = build()
    source.content_type = ContentType.X12
    return source


def _replying(build: Build) -> X12Source | TcpSource:
    """A listener whose inbound answers each frame in HL7."""
    source = build()
    source.content_type = ContentType.HL7V2
    return source


@pytest.mark.parametrize(("transport", "build", "wire", "body"), LISTENERS)
async def test_no_reply_a_handler_that_keeps_faulting_is_retried_then_recorded_and_kept(
    caplog: pytest.LogCaptureFixture, transport: str, build: Build, wire: bytes, body: bytes
) -> None:
    seen: list[bytes] = []
    fault = RuntimeError("synthetic store outage")

    async def explode(raw: bytes) -> None:
        seen.append(raw)
        raise fault

    with caplog.at_level(logging.WARNING):
        events = await _drive(_no_reply(build), _ThenEof(wire), _Peer(), handler=explode)

    assert _kinds(events) == ["established", "handler_error", "closed"], (
        "a handler fault is not a framing fault, and the connection is kept, so it ends on the "
        "sender's own EOF"
    )
    assert events[1][2] == safe_exc(fault)  # the scrubbed reason, as every other kind carries
    assert seen == [body] * _attempts(), "every attempt was on the one frame in hand"
    errors = [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == 1 and errors[0].startswith(f"{transport} message")
    assert "may not be recorded" in errors[0] and "keeping the connection" in errors[0]
    retries = [r for r in caplog.records if r.levelno == logging.WARNING and "attempt" in r.msg]
    assert len(retries) == _attempts() - 1


@pytest.mark.parametrize(("transport", "build", "wire", "body"), LISTENERS)
async def test_no_reply_the_frames_behind_a_lost_one_are_still_handled(
    transport: str, build: Build, wire: bytes, body: bytes
) -> None:
    # Two frames in one read; the first faults every time. Closing would have lost the second too,
    # since this sender never resends; it is handled, after the first's retries.
    seen: list[bytes] = []

    async def first_fails(raw: bytes) -> None:
        seen.append(raw)
        if len(seen) <= _attempts():
            raise RuntimeError("synthetic store outage")

    events = await _drive(_no_reply(build), _ThenEof(wire + wire), _Peer(), handler=first_fails)
    assert _kinds(events) == ["established", "handler_error", "closed"]
    assert len(seen) == _attempts() + 1, "the second frame reached the handler once"


@pytest.mark.parametrize(("transport", "build", "wire", "body"), LISTENERS)
async def test_no_reply_a_transient_handler_fault_is_recovered_with_nothing_lost(
    transport: str, build: Build, wire: bytes, body: bytes
) -> None:
    calls: list[bytes] = []

    async def flaky(raw: bytes) -> None:
        calls.append(raw)
        if len(calls) < 3:
            raise RuntimeError("synthetic store blip")

    events = await _drive(_no_reply(build), _ThenEof(wire), _Peer(), handler=flaky)
    assert calls == [body] * 3, "the third attempt commits the frame"
    assert _kinds(events) == ["established", "closed"], "a recovered frame records no fault"


@pytest.mark.parametrize(("transport", "build", "wire", "body"), LISTENERS)
async def test_no_reply_the_retries_stop_once_the_listener_is_stopping(
    caplog: pytest.LogCaptureFixture, transport: str, build: Build, wire: bytes, body: bytes
) -> None:
    # stop() cancels a client task past its shutdown grace, which would skip the handler_error
    # record. The retries end as soon as stop() begins, so the fault is still recorded.
    source = _no_reply(build)
    seen: list[bytes] = []

    async def explode_then_stop(raw: bytes) -> None:
        seen.append(raw)
        source._admission.stopping = True
        raise RuntimeError("synthetic store outage")

    with caplog.at_level(logging.ERROR):
        events = await _drive(source, _ThenEof(wire), _Peer(), handler=explode_then_stop)
    assert seen == [body], "no retry once stopping"
    assert "handler_error" in _kinds(events)
    assert any("after 1 attempt(s)" in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize(("transport", "build", "wire", "body"), LISTENERS)
async def test_a_reply_owed_fault_is_not_retried_and_closes_for_the_sender_to_resend(
    caplog: pytest.LogCaptureFixture, transport: str, build: Build, wire: bytes, body: bytes
) -> None:
    # A sender that waits for a reply resends on a close; a retry would hold it past its own reply
    # timeout and race its resend. Both frames in the read stay unhandled, so the resend keeps order.
    seen: list[bytes] = []

    async def explode(raw: bytes) -> None:
        seen.append(raw)
        raise RuntimeError("synthetic store outage")

    writer = _Peer()
    with caplog.at_level(logging.ERROR):
        events = await _drive(_replying(build), _ThenEof(wire + wire), writer, handler=explode)
    assert _kinds(events) == ["established", "handler_error"], (
        "the failed connection must not also emit `closed`"
    )
    assert seen == [body], "one attempt, and nothing behind it was handled"
    assert writer.closed and not writer.written  # closed, and nothing acknowledged
    assert any("closing the connection for the sender" in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize(("transport", "build", "wire", "body"), LISTENERS)
async def test_acks_off_on_an_hl7_inbound_owes_no_reply(
    transport: str, build: Build, wire: bytes, body: bytes
) -> None:
    # The runner answers an HL7 inbound only with acknowledgements on; with them off the sender
    # waits for nothing, so the frame is retried and the connection kept.
    source = _replying(build)
    source.ack_mode = AckMode.NONE
    seen: list[bytes] = []

    async def explode(raw: bytes) -> None:
        seen.append(raw)
        raise RuntimeError("synthetic store outage")

    events = await _drive(source, _ThenEof(wire), _Peer(), handler=explode)
    assert len(seen) == _attempts()
    assert _kinds(events) == ["established", "handler_error", "closed"]


@pytest.mark.parametrize(("transport", "build", "wire", "body"), LISTENERS)
async def test_an_os_error_in_the_handler_is_a_handler_error_not_a_peer_reset(
    transport: str, build: Build, wire: bytes, body: bytes
) -> None:
    # A store write can fail with an OSError. Before, it escaped to the listener's outer OSError
    # arm and read as the peer resetting the connection.
    async def disk_error(raw: bytes) -> None:
        raise OSError(5, "synthetic I/O error")

    events = await _drive(_replying(build), _ThenEof(wire), _Peer(), handler=disk_error)
    assert _kinds(events) == ["established", "handler_error"]


def test_a_direct_build_is_read_as_owing_a_reply() -> None:
    # The conservative default, as MLLP's: with no injected content type the sender may be waiting.
    assert base_mod.owes_hl7_reply(AckMode.ORIGINAL, None)
    assert not base_mod.owes_hl7_reply(AckMode.ORIGINAL, ContentType.X12)
    assert not base_mod.owes_hl7_reply(AckMode.NONE, ContentType.HL7V2)
