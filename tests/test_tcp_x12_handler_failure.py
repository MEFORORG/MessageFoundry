# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A fault in the inbound handler on the raw-TCP and X12 listeners (BACKLOG #5022).

In the shipped code both listeners caught a handler fault in their last-resort arm, recorded
``framing_error`` and dropped the connection. The decoder had read the frame cleanly, so the event
would have blamed the wrong layer. A sender that waits for no reply never resends, so the drop would
have lost that frame and every frame already sent behind it, with nothing naming the loss.

Now the event is ``handler_error``. When the inbound owes a reply the listener closes at once, so the
sender resends. When it owes none, ``transports.base.hold_and_retry`` holds the frame and retries
until it is recorded or the listener stops, so the sender is stalled rather than losing frames.

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
REPORT_AFTER = base_mod.HANDLER_FAULT_REPORT_AFTER


class _ThenEof:
    """Hands over one chunk, then hangs up."""

    def __init__(self, data: bytes) -> None:
        self._data = data

    async def read(self, _n: int) -> bytes:
        chunk, self._data = self._data, b""
        return chunk


@pytest.fixture(autouse=True)
def _no_retry_pauses(monkeypatch: pytest.MonkeyPatch) -> None:
    # The same schedule, without the real pauses, so a test stays inside _drive's bound.
    monkeypatch.setattr(base_mod, "HANDLER_RETRY_DELAYS", (0.0,))


def _no_reply(build: Build) -> X12Source | TcpSource:
    """A listener whose inbound owes its sender no reply: a non-HL7 content type, as the runner
    injects for an X12 feed."""
    source = build()
    source.content_type = ContentType.X12
    return source


def _replying(build: Build) -> X12Source | TcpSource:
    """A listener whose inbound answers each frame in HL7."""
    source = build()
    source.content_type = ContentType.HL7V2
    return source


def _failing_for(attempts: int, seen: list[bytes]) -> Callable[[bytes], object]:
    async def handler(raw: bytes) -> None:
        seen.append(raw)
        if len(seen) <= attempts:
            raise RuntimeError("synthetic store outage")

    return handler


@pytest.mark.parametrize(("transport", "build", "wire", "body"), LISTENERS)
async def test_no_reply_a_blip_the_first_retries_recover_records_no_fault(
    caplog: pytest.LogCaptureFixture, transport: str, build: Build, wire: bytes, body: bytes
) -> None:
    seen: list[bytes] = []
    handler = _failing_for(REPORT_AFTER - 1, seen)
    with caplog.at_level(logging.WARNING):
        events = await _drive(_no_reply(build), _ThenEof(wire), _Peer(), handler=handler)
    assert seen == [body] * REPORT_AFTER, "the last attempt records the frame"
    assert _kinds(events) == ["established", "closed"], "a recovered blip records no fault"
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]


@pytest.mark.parametrize(("transport", "build", "wire", "body"), LISTENERS)
async def test_no_reply_a_long_fault_is_reported_once_and_the_frame_held_until_recorded(
    caplog: pytest.LogCaptureFixture, transport: str, build: Build, wire: bytes, body: bytes
) -> None:
    # Past the report threshold the frame is still held, and both frames in the read are recorded
    # in order once the fault clears: nothing behind the failed frame is taken and dropped.
    seen: list[bytes] = []
    failures = REPORT_AFTER + 3
    handler = _failing_for(failures, seen)
    with caplog.at_level(logging.WARNING):
        events = await _drive(_no_reply(build), _ThenEof(wire + wire), _Peer(), handler=handler)
    assert seen == [body] * (failures + 2), "the first frame until recorded, then the second once"
    assert _kinds(events) == ["established", "handler_error", "closed"], (
        "reported once, and the connection kept, so it ends on the sender's own EOF"
    )
    assert events[1][2] == safe_exc(RuntimeError("synthetic store outage"))
    errors = [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == 1 and errors[0].startswith(f"{transport} message")
    assert "held and retried" in errors[0]
    assert any("was recorded on attempt" in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize(("transport", "build", "wire", "body"), LISTENERS)
async def test_no_reply_a_stop_ends_the_hold_and_names_the_loss(
    caplog: pytest.LogCaptureFixture, transport: str, build: Build, wire: bytes, body: bytes
) -> None:
    # stop() cancels a client task past its shutdown grace, which would skip the record. The hold
    # sees the stop first, so the loss is still logged and recorded, and the connection closes.
    source = _no_reply(build)
    seen: list[bytes] = []

    async def explode_then_stop(raw: bytes) -> None:
        seen.append(raw)
        if len(seen) == 2:
            source._admission.stopping = True
        raise RuntimeError("synthetic store outage")

    writer = _Peer()
    with caplog.at_level(logging.ERROR):
        events = await _drive(source, _ThenEof(wire), writer, handler=explode_then_stop)
    assert seen == [body] * 2, "no attempt once stopping"
    assert _kinds(events) == ["established", "handler_error"], (
        "reported before the threshold, and a failed connection must not also emit `closed`"
    )
    assert writer.closed and not writer.written
    assert any("is not recorded" in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize(("transport", "build", "wire", "body"), LISTENERS)
async def test_a_reply_owed_fault_is_not_retried_and_closes_for_the_sender_to_resend(
    caplog: pytest.LogCaptureFixture, transport: str, build: Build, wire: bytes, body: bytes
) -> None:
    # A sender that waits for a reply resends on a close; a retry would hold it past its own reply
    # timeout and race its resend. Both frames in the read stay unhandled, so the resend keeps order.
    seen: list[bytes] = []
    writer = _Peer()
    with caplog.at_level(logging.ERROR):
        events = await _drive(
            _replying(build), _ThenEof(wire + wire), writer, handler=_failing_for(99, seen)
        )
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
    # waits for nothing, so the frame is held and retried.
    source = _replying(build)
    source.ack_mode = AckMode.NONE
    seen: list[bytes] = []
    events = await _drive(source, _ThenEof(wire), _Peer(), handler=_failing_for(2, seen))
    assert seen == [body] * 3
    assert _kinds(events) == ["established", "closed"]


@pytest.mark.parametrize(("transport", "build", "wire", "body"), LISTENERS)
async def test_an_os_error_in_the_handler_is_a_handler_error_not_a_peer_reset(
    transport: str, build: Build, wire: bytes, body: bytes
) -> None:
    # A store write can fail with an OSError. In the shipped code it would have escaped to the
    # listener's outer OSError arm and read as the peer resetting the connection.
    async def disk_error(raw: bytes) -> None:
        raise OSError(5, "synthetic I/O error")

    events = await _drive(_replying(build), _ThenEof(wire), _Peer(), handler=disk_error)
    assert _kinds(events) == ["established", "handler_error"]


def test_a_direct_build_is_read_as_owing_a_reply() -> None:
    # The conservative default, as MLLP's: with no injected content type the sender may be waiting.
    assert base_mod.owes_hl7_reply(AckMode.ORIGINAL, None)
    assert not base_mod.owes_hl7_reply(AckMode.ORIGINAL, ContentType.X12)
    assert not base_mod.owes_hl7_reply(AckMode.NONE, ContentType.HL7V2)


def test_the_retry_schedule_backs_off_to_a_bounded_pause(monkeypatch: pytest.MonkeyPatch) -> None:
    # A long outage costs the store one attempt per connection per final pause, not a tight loop.
    monkeypatch.undo()  # the shipped schedule, not the autouse fixture's
    delays = base_mod.HANDLER_RETRY_DELAYS
    assert all(later >= earlier > 0 for earlier, later in zip(delays, delays[1:], strict=False))
    assert delays[-1] <= 60
