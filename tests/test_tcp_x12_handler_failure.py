# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A fault in the inbound handler on the raw-TCP and X12 listeners (BACKLOG #5022).

Both listeners caught a handler fault in their last-resort arm, recorded ``framing_error`` and
dropped the connection. The decoder had read the frame cleanly, so the event blamed the wrong
layer, and a sender that waits for no reply never resends, so the frame was lost with nothing
saying so. Now the handler is retried in place on the frame in hand; if it still faults the
listener records ``handler_error``, logs at ERROR that the frame may not be recorded, and closes.

Each test runs on both listeners through the same fakes, so a pass on one side is checked against
the other. The listener is driven by calling ``_on_client`` with fakes, as
``tests/test_x12_connection_events.py`` does; nothing binds a port. Synthetic payloads only.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

import pytest

import messagefoundry.transports.base as base_mod
import messagefoundry.transports.tcp as tcp_mod
import messagefoundry.transports.x12 as x12_mod
from messagefoundry.redaction import safe_exc
from messagefoundry.transports.tcp import TcpSource
from messagefoundry.transports.x12 import X12Source
from tests.test_x12_connection_events import EDI, _drive, _kinds, _Peer, _tcp, _x12

#: A frame the raw-TCP decoder reads cleanly; the X12 one is the ISA/IEA interchange ``EDI``.
TCP_FRAME = b"\x02synthetic raw tcp body\x03"

Listener = tuple[str, Callable[[], X12Source | TcpSource], bytes, bytes]
LISTENERS: list[Listener] = [
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


@pytest.mark.parametrize(("transport", "build", "wire", "body"), LISTENERS)
async def test_a_handler_that_keeps_faulting_is_retried_then_recorded_as_handler_error(
    caplog: pytest.LogCaptureFixture,
    transport: str,
    build: Callable[[], X12Source | TcpSource],
    wire: bytes,
    body: bytes,
) -> None:
    seen: list[bytes] = []
    fault = RuntimeError("synthetic store outage")

    async def explode(raw: bytes) -> None:
        seen.append(raw)
        raise fault

    writer = _Peer()
    with caplog.at_level(logging.WARNING):
        events = await _drive(build(), _ThenEof(wire), writer, handler=explode)

    assert _kinds(events) == ["established", "handler_error"], (
        "a handler fault is not a framing fault, and the failed connection must not also emit "
        "`closed`"
    )
    assert events[1][2] == safe_exc(fault)  # the scrubbed reason, as every other kind carries
    assert seen == [body] * _attempts(), "every attempt was on the one frame in hand"
    assert writer.closed and not writer.written  # closed, and nothing acknowledged
    errors = [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == 1 and f"{transport} message" in errors[0]
    assert "may not be recorded" in errors[0] and "closing the connection" in errors[0]
    retries = [r for r in caplog.records if r.levelno == logging.WARNING and "attempt" in r.msg]
    assert len(retries) == _attempts() - 1


@pytest.mark.parametrize(("transport", "build", "wire", "body"), LISTENERS)
async def test_a_transient_handler_fault_is_recovered_with_nothing_lost(
    transport: str, build: Callable[[], X12Source | TcpSource], wire: bytes, body: bytes
) -> None:
    calls: list[bytes] = []

    async def flaky(raw: bytes) -> None:
        calls.append(raw)
        if len(calls) < 3:
            raise RuntimeError("synthetic store blip")

    events = await _drive(build(), _ThenEof(wire), _Peer(), handler=flaky)
    assert calls == [body] * 3, "the third attempt commits the frame"
    assert _kinds(events) == ["established", "closed"], (
        "a recovered frame leaves the connection to end the ordinary way, on the sender's EOF"
    )


@pytest.mark.parametrize(("transport", "build", "wire", "body"), LISTENERS)
async def test_nothing_behind_a_failed_frame_is_handled(
    transport: str, build: Callable[[], X12Source | TcpSource], wire: bytes, body: bytes
) -> None:
    # Two frames in one read. The connection closes on the first, so the second is never handed to
    # the handler ahead of it: order holds, and the ERROR line names that loss.
    seen: list[bytes] = []

    async def explode(raw: bytes) -> None:
        seen.append(raw)
        raise RuntimeError("synthetic store outage")

    events = await _drive(build(), _ThenEof(wire + wire), _Peer(), handler=explode)
    assert _kinds(events) == ["established", "handler_error"]
    assert len(seen) == _attempts()


@pytest.mark.parametrize(("transport", "build", "wire", "body"), LISTENERS)
async def test_an_os_error_in_the_handler_is_a_handler_error_not_a_peer_reset(
    transport: str, build: Callable[[], X12Source | TcpSource], wire: bytes, body: bytes
) -> None:
    # A store write can fail with an OSError. Before, it escaped to the listener's outer OSError
    # arm and read as the peer resetting the connection.
    async def disk_error(raw: bytes) -> None:
        raise OSError(5, "synthetic I/O error")

    events = await _drive(build(), _ThenEof(wire), _Peer(), handler=disk_error)
    assert _kinds(events) == ["established", "handler_error"]


def test_the_retry_pauses_are_bounded_inside_the_shutdown_grace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # stop() gives a client task each listener's _CLIENT_SHUTDOWN_GRACE before it cancels it; the
    # shipped pauses must leave room for the handler attempts themselves inside that grace.
    monkeypatch.undo()
    delays = base_mod.HANDLER_RETRY_DELAYS
    assert all(delay > 0 for delay in delays)
    for module in (tcp_mod, x12_mod):
        assert sum(delays) < module._CLIENT_SHUTDOWN_GRACE / 2, module.__name__
