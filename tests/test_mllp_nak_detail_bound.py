# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A negative acknowledgment's MSA-3 is bounded at READ time (BACKLOG #1576).

``receive_max_bytes`` caps the ACK FRAME, not a field inside it, so a remote peer could answer a
delivery with an MSA-3 running to the 16 MiB default cap. That text went into ``NegativeAckError``
whole, and every consumer of it -- the dead-letter row's ``last_error`` via ``safe_exc``, the alert,
the log line -- redacts before it truncates. Redaction is a linear scan and it runs on the asyncio
event loop, so an unbounded field here was an unbounded stall there: measured 0.29 s to 0.78 s per
negative acknowledgment at the cap depending on the shape of the text, against an independent
0.53-0.94 s measurement on another box.

**Not fixed by slicing.** A cut at an arbitrary offset strands a fragment under the redactor's
thresholds -- one delimiter where ``_HL7_FIELD_RUN`` needs two -- and the surname walks into the log.
``clamp_untrusted`` cuts at whitespace instead; ``redaction._CUT_CHARS`` carries the per-pattern
argument for what that covers, and ``tests/test_redaction.py`` holds the measurement.

The peers here are real loopback ``asyncio.start_server`` receivers and the deliveries are real
``MLLPDestination.send`` calls, so these arms exercise the shipped path rather than ``_check_ack``
in isolation. Every fixture is synthetic HL7.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.redaction import safe_exc
from messagefoundry.transports.base import DeliveryError, NegativeAckError
from messagefoundry.transports.mllp import (
    _MAX_NAK_DETAIL_CHARS,
    MLLPDecoder,
    MLLPDestination,
    build_ack,
    frame,
)

#: Synthetic identifiers the hostile MSA-3 is built from. None is real PHI; all of them are shaped so
#: ``redact`` would catch them in text short enough to reach it, which is what makes their ABSENCE
#: from a bounded error message meaningful rather than accidental.
_IDENTIFIERS = ("Z9998887", "DOE^JANE^Q", "19800101", "DOE JANE")

#: How much MSA-3 the hostile peer returns. Well under the 16 MiB frame cap so the test stays quick,
#: and far enough over the bound to prove the bound: unbounded, this shape measured about 70 ms of
#: event-loop time per acknowledgment, which is already a stall.
_HOSTILE_DETAIL_CHARS = 4 * 1024 * 1024

#: The budget the render path must stay inside: deliberately generous against the ~70 ms the unbounded
#: path costs on this fixture, so a stall fails the arm and a loaded runner does not. It equals the
#: budgets in ``tests/test_redaction.py`` and ``tests/test_logging.py`` because all three were derived
#: the same way; nothing couples them, and re-deriving one does not move the others.
_RENDER_BUDGET_SECONDS = 0.05


def _msg(control_id: str) -> str:
    return (
        f"MSH|^~\\&|SNDAPP|SNDFAC|RCVAPP|RCVFAC|20260101||ADT^A01|{control_id}|P|2.5.1\r"
        "PID|1||100||SMITH^ROBERT\r"
    )


def _hostile_detail() -> str:
    """An MSA-3 the peer sizes: identifier-bearing HL7 repeated past the bound.

    Repeated segments rather than one solid run on purpose. A solid run has no whitespace anywhere, so
    the clamp drops it whole and every absence arm below would pass vacuously. This shape gives the
    clamp real boundaries to cut at and still must not leak."""
    unit = "PID|1||Z9998887^^^H^MR||DOE^JANE^Q||19800101|F patient DOE JANE rejected "
    return (unit * (_HOSTILE_DETAIL_CHARS // len(unit) + 1))[:_HOSTILE_DETAIL_CHARS]


def _hostile_control_id() -> str:
    """The same hostile field, shaped for **MSA-2**, which means it may hold no ``|``.

    **A field separator inside a field ENDS it, and that is how the MSA-2 arm went vacuous.** Built
    from :func:`_hostile_detail`, the reply read ``MSA|AA|PID|1||Z999...``, so ``MSA-2`` parsed to the
    three characters ``PID``: the bound never ran, the length assertion passed on a 3-character field,
    and the identifier assertions passed because no identifier was ever in the field being asserted
    about. The separator is dropped rather than escaped so the identifiers stay in the shape ``redact``
    would catch, which is what makes their absence meaningful.

    Everything else that makes the fixture hostile is kept: the same identifiers as
    :data:`_IDENTIFIERS`, whitespace so the clamp has real boundaries to cut at rather than dropping
    the field whole, and the same size."""
    unit = "PID^1^^Z9998887^^^H^MR^^DOE^JANE^Q^^19800101^F patient DOE JANE rejected "
    assert "|" not in unit, "a field separator would end MSA-2 and make every arm below vacuous"
    return (unit * (_HOSTILE_DETAIL_CHARS // len(unit) + 1))[:_HOSTILE_DETAIL_CHARS]


def _dest(port: int, **overrides: object) -> MLLPDestination:
    settings: dict[str, object] = {
        "host": "127.0.0.1",
        "port": port,
        "timeout_seconds": 20,
        "connect_timeout": 5,
    }
    settings.update(overrides)
    return MLLPDestination(Destination(name="out", type=ConnectorType.MLLP, settings=settings))


def _ack_with_control_id(msa1: str, control_id: str) -> str:
    """An acknowledgment whose **MSA-2** is ``control_id``.

    Hand-built rather than ``build_ack(..., control_id=...)``, because that parameter sets the ACK's
    own MSH-10; MSA-2 always echoes the inbound control id, so the helper cannot produce the
    mis-correlated reply this arm needs."""
    return (
        "MSH|^~\\&|RCVAPP|RCVFAC|SNDAPP|SNDFAC|20260101||ACK^A01|A1|P|2.5.1\r"
        f"MSA|{msa1}|{control_id}\r"
    )


class _NakPeer:
    """A loopback receiver that answers every message with a scripted acknowledgment.

    Defaults to an ``AR`` rejection carrying ``detail`` in MSA-3. ``raw_ack`` replaces the whole reply
    instead, which is what the MSA-2 arm needs (see :func:`_ack_with_control_id`)."""

    def __init__(self, detail: str, *, raw_ack: str | None = None) -> None:
        self.detail = detail
        self.raw_ack = raw_ack
        self.received: list[bytes] = []
        self._server: asyncio.Server | None = None
        self._writers: list[asyncio.StreamWriter] = []

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._on_client, "127.0.0.1", 0)

    @property
    def port(self) -> int:
        assert self._server is not None
        return int(self._server.sockets[0].getsockname()[1])

    async def _on_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._writers.append(writer)
        decoder = MLLPDecoder()
        try:
            while True:
                chunk = await reader.read(65536)
                if not chunk:
                    return
                for message in decoder.feed(chunk):
                    self.received.append(message)
                    ack = self.raw_ack or build_ack(message, code="AR", text=self.detail)
                    writer.write(frame(ack))
                    await writer.drain()
        except (OSError, ConnectionError):
            pass  # client went away

    async def stop(self) -> None:
        assert self._server is not None
        self._server.close()
        for writer in self._writers:
            writer.close()
        self._writers.clear()
        try:  # noqa: SIM105
            await asyncio.wait_for(self._server.wait_closed(), 2.0)
        except (TimeoutError, OSError):
            pass


async def _nak_from(detail: str) -> NegativeAckError:
    """Deliver one synthetic message to a peer that NAKs it with ``detail``, and return the raise."""
    peer = _NakPeer(detail)
    await peer.start()
    dest = _dest(peer.port)
    try:
        with pytest.raises(NegativeAckError) as raised:
            await dest.send(_msg("M1"))
        assert len(peer.received) == 1, "the frame must have reached the peer"
        return raised.value
    finally:
        await dest.aclose()
        await peer.stop()


async def test_a_hostile_nak_detail_is_bounded_at_read_time() -> None:
    """AC-1: the peer's field never reaches the exception message whole."""
    exc = await _nak_from(_hostile_detail())
    assert len(str(exc)) < _MAX_NAK_DETAIL_CHARS + 200, (
        f"the NegativeAckError message is {len(str(exc))} characters; MSA-3 reached it unbounded"
    )


async def test_no_identifier_escapes_a_hostile_nak_detail() -> None:
    """AC-2: and what DOES reach a stored ``last_error`` carries no identifier.

    ``safe_exc`` is what the delivery worker writes into a dead-letter row
    (``wiring_runner``: ``dead_letter_batch(ids, safe_exc(exc))``), so it is the right rendering to
    assert against rather than a hand-built one."""
    rendered = safe_exc(await _nak_from(_hostile_detail()))
    for identifier in _IDENTIFIERS:
        assert identifier not in rendered, f"{identifier!r} survived into {rendered!r}"


async def test_a_hostile_nak_does_not_buy_the_event_loop() -> None:
    """AC-3, the row's responsiveness arm: delivering and rendering a 4 MiB rejection stays inside a
    budget the unbounded path could not.

    The heartbeat is the direct reading -- a task ticking every millisecond alongside the delivery --
    and the render timing is the indirect one. Both are here because they fail differently: a stall
    inside ``_check_ack`` shows up in the heartbeat, and one inside the redaction ``safe_exc`` runs
    shows up in the elapsed time."""
    ticks = 0
    stop = asyncio.Event()

    async def heartbeat() -> None:
        nonlocal ticks
        while not stop.is_set():
            ticks += 1
            await asyncio.sleep(0.001)

    beat = asyncio.create_task(heartbeat())
    try:
        exc = await _nak_from(_hostile_detail())
        start = time.perf_counter()
        rendered = safe_exc(exc)
        elapsed = time.perf_counter() - start
    finally:
        stop.set()
        await beat

    assert elapsed < _RENDER_BUDGET_SECONDS, (
        f"rendering the rejection cost {elapsed:.4f}s of the event loop against a "
        f"{_RENDER_BUDGET_SECONDS}s budget"
    )
    assert ticks > 5, f"the loop ticked only {ticks} times while a 4 MiB rejection was handled"
    assert rendered.startswith("NegativeAckError: ")


async def test_control_an_ordinary_nak_reason_still_arrives_intact() -> None:
    """THE CONTROL, and the arm a careless run drops. Every assertion above is about something being
    ABSENT, and a bound that threw MSA-3 away entirely would satisfy all of them. An operator reads
    this field to find out why a partner refused a message, so a real reason has to survive."""
    exc = await _nak_from("unknown receiving facility RCVFAC")
    assert "unknown receiving facility RCVFAC" in str(exc)
    assert "negative ACK (MSA-1=AR)" in str(exc)
    assert "[redaction bound:" not in str(exc)
    assert exc.permanent is True  # AR is a reject, so it dead-letters rather than retrying


async def test_a_hostile_ack_control_id_is_bounded_too() -> None:
    """MSA-2 is peer-chosen and frame-cap sized exactly like MSA-3, and ``_check_ack`` interpolates it
    into a ``DeliveryError`` on the very same path.

    **This is the sibling the first cut of the fix missed**, and it is the failure mode a call-site
    bound has: bounding one field and leaving the one twenty lines above it. Both go through
    ``_bounded_ack_field`` now, so they cannot drift apart again.

    The fixture is :func:`_hostile_control_id` and not :func:`_hostile_detail` for the reason that
    function carries: a ``|`` in the payload ends MSA-2, and this arm asserted nothing for as long as
    it used one."""
    hostile = _hostile_control_id()
    peer = _NakPeer("", raw_ack=_ack_with_control_id("AA", hostile))
    await peer.start()
    dest = _dest(peer.port, verify_ack_control_id=True)
    try:
        with pytest.raises(DeliveryError) as raised:
            await dest.send(_msg("M1"))
    finally:
        await dest.aclose()
        await peer.stop()

    message = str(raised.value)
    assert "ACK control-id mismatch" in message
    # THE NON-VACUITY CONTROL. Every assertion below is satisfied by a field that never arrived, and
    # a field separator in the fixture is exactly how it fails to: MSA-2 would parse to `PID` and the
    # bound would never run. Assert the peer really sent a frame-cap-sized MSA-2 before asserting
    # what the bound did to it.
    assert len(peer.received) == 1, "the frame must have reached the peer"
    sent_msa2 = (peer.raw_ack or "").split("\r")[1].split("|")[2]
    assert sent_msa2 == hostile, (
        f"the reply's MSA-2 is {len(sent_msa2)} characters, not the {len(hostile)} sent: a field "
        f"separator in the fixture ended the field early and the bound never ran"
    )
    assert len(hostile) > _MAX_NAK_DETAIL_CHARS * 100, (
        f"the hostile control id is only {len(hostile)} characters, which the bound would not have "
        f"had to cut -- this arm no longer measures a bound"
    )
    assert len(message) < _MAX_NAK_DETAIL_CHARS + 300, (
        f"the mismatch message is {len(message)} characters; MSA-2 reached it unbounded"
    )
    for identifier in _IDENTIFIERS:
        assert identifier not in safe_exc(raised.value)


async def test_control_a_correlated_ack_still_succeeds() -> None:
    """THE CONTROL for the arm above. Bounding MSA-2 must not break the correlation it feeds: an
    ordinary ACK whose MSA-2 echoes the sent MSH-10 has to keep passing, or the bound would have
    turned every verified delivery into a mismatch."""
    peer = _NakPeer("", raw_ack=_ack_with_control_id("AA", "M1"))  # MSA-2 echoes the sent MSH-10
    await peer.start()
    dest = _dest(peer.port, verify_ack_control_id=True)
    try:
        assert await dest.send(_msg("M1")) is None  # delivered, no raise
    finally:
        await dest.aclose()
        await peer.stop()


async def test_control_an_ordinary_nak_reason_is_still_redacted() -> None:
    """The other half of the control: bounding the field must not have displaced the redaction that
    was already there. A short reason quoting a patient is still scrubbed on the way to the store."""
    exc = await _nak_from("rejected PID|1||Z9998887^^^H^MR||DOE^JANE^Q")
    rendered = safe_exc(exc)
    for identifier in ("Z9998887", "DOE", "JANE"):
        assert identifier not in rendered
    assert "[redacted]" in rendered  # scrubbed, not silently dropped
