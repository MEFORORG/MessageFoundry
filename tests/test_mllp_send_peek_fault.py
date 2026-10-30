# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A faulting MSH-10 read at the MLLP send site skips ACK correlation instead of escaping send()
(BACKLOG #1623).

With ``verify_ack_control_id`` on, ``MLLPDestination.send`` reads the outgoing MSH-10 once to
correlate it with the reply's MSA-2. That read caught ``HL7PeekError`` only, so a payload that parsed
but faulted the field READ escaped ``send()`` outside the ``DeliveryError`` contract the delivery
worker relies on. A blank segment was the fault that found it, and BACKLOG #1594 widened the catch to
``PEEK_READ_FAULTS``.

**Why the fault is injected rather than sent.** #1594 also drops a blank segment at the parse, so a
blank-segment payload now reads MSH-10 cleanly and never reaches the widened catch; a literal
blank-segment test would pass with the catch deleted. The first test pins that premise for this file
(``tests/test_blank_segment_ingress.py`` covers more blank-segment shapes). The rest inject the fault
at ``Peek.field`` for the path ``MSH-10`` only. ``Peek.control_id`` reads through ``Peek.field``, so
either spelling of the send site's read meets the fault, while the ACK side's ``MSA-*`` reads stay
intact and the reply still parses and classifies normally.

The peer is a real loopback receiver from ``test_mllp_nak_detail_bound`` and the deliveries are real
``send()`` calls. Every fixture is synthetic HL7. Deliberately ASCII-only: pytest echoes a failing
body to a cp1252 console on Windows.
"""

from __future__ import annotations

import logging

import pytest

from messagefoundry.parsing.peek import PEEK_READ_FAULTS, HL7PeekError, Peek
from messagefoundry.transports.base import DeliveryError, DeliveryResponse
from tests.test_mllp_nak_detail_bound import _ack_with_control_id, _dest, _msg, _NakPeer

_LOGGER = "messagefoundry.transports.mllp"
_SKIPPED = "ACK correlation skipped"

#: The control id the sent message carries, and a different one the peer echoes in MSA-2.
_SENT_ID = "CTL1623"
_OTHER_ID = "NOTMINE1623"

#: The injected faults. ``LookupError`` itself pins the whole family: a catch narrowed to its
#: subclasses (``IndexError``, ``KeyError``) would not catch it. ``IndexError`` is kept beside it as
#: the shape the blank segment actually raised. A meta-test below checks every family is covered.
_FAULTS = (IndexError, LookupError, TypeError, ValueError)

#: Text carried by the injected fault. The send-site warning must name the fault's TYPE only, so this
#: marker appearing anywhere in the captured log is a leak of the fault's text.
_FAULT_TEXT = "injected-fault-text-1623"


def _inject_msh10_fault(monkeypatch: pytest.MonkeyPatch, fault: type[Exception]) -> list[int]:
    """Make every ``Peek.field("MSH-10")`` read raise ``fault``; every other path reads normally.

    Returns a one-slot counter of the faulted reads, so an arm can prove the fault fired inside
    ``send()``. The patch is class-wide, but the peer sends ``raw_ack`` and never peeks, so only the
    send site's read counts."""
    calls = [0]
    real_field = Peek.field

    def _field(self: Peek, path: str) -> str | None:
        if path == "MSH-10":
            calls[0] += 1
            raise fault(_FAULT_TEXT)
        return real_field(self, path)

    monkeypatch.setattr(Peek, "field", _field)
    return calls


@pytest.fixture(params=_FAULTS, ids=lambda exc: exc.__name__)
def faulting_msh10(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> tuple[type[Exception], list[int]]:
    """Each fault in :data:`_FAULTS` in turn, injected at the MSH-10 read."""
    fault: type[Exception] = request.param
    return fault, _inject_msh10_fault(monkeypatch, fault)


async def _send_against_mismatched_ack() -> tuple[_NakPeer, DeliveryResponse | None]:
    """Deliver ``_msg(_SENT_ID)`` to a peer that accepts it with ``MSA-2`` = ``_OTHER_ID``.

    Correlation on, so the reply is a mismatch unless the send site skipped correlation."""
    peer = _NakPeer("", raw_ack=_ack_with_control_id("AA", _OTHER_ID))
    await peer.start()
    try:
        # Short timeouts: the peer answers at once, so a regression that waits on a reply fails fast.
        dest = _dest(peer.port, verify_ack_control_id=True, timeout_seconds=5, connect_timeout=2)
        try:
            result = await dest.send(_msg(_SENT_ID))
        finally:
            await dest.aclose()
    finally:
        await peer.stop()
    return peer, result


def _skip_warnings(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.name == _LOGGER and _SKIPPED in r.getMessage()]


def test_a_blank_segment_no_longer_reaches_the_catch() -> None:
    """BACKLOG #1594: the blank line is dropped at the parse, so MSH-10 reads cleanly. This is why
    the arms below inject the fault: a blank-segment payload would never exercise the catch."""
    blank = _msg(_SENT_ID).replace("\rPID", "\r\rPID", 1)
    assert "\r\r" in blank
    assert Peek.parse(blank).control_id == _SENT_ID


def test_the_injected_types_cover_every_family_the_catch_names() -> None:
    """Both directions: each injected type is one the catch promises to handle, and each family
    ``PEEK_READ_FAULTS`` names has an injected type, so a new family cannot go untested silently."""
    for fault in _FAULTS:
        assert issubclass(fault, PEEK_READ_FAULTS)
    for family in PEEK_READ_FAULTS:
        assert any(issubclass(fault, family) for fault in _FAULTS), family


def test_the_injection_is_scoped_to_msh10(
    faulting_msh10: tuple[type[Exception], list[int]],
) -> None:
    """The injection faults MSH-10 through both spellings of the read, and leaves every other path
    readable, which is what keeps the ACK side's MSA reads working in the arms below."""
    fault, calls = faulting_msh10
    peek = Peek.parse(_msg(_SENT_ID))
    with pytest.raises(fault):
        _ = peek.control_id
    with pytest.raises(fault):
        peek.field("MSH-10")
    assert calls == [2]
    assert peek.field("MSH-9") == "ADT^A01"


async def test_control_a_mismatched_msa2_raises_without_the_fault(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Control: with the MSH-10 read healthy, the same mismatched reply is refused, and nothing says
    correlation was skipped. So acceptance in the faulted arm below is the effect of skipping
    correlation, not of a peer that matches."""
    with (
        caplog.at_level(logging.WARNING, logger=_LOGGER),
        pytest.raises(DeliveryError, match="ACK control-id mismatch"),
    ):
        await _send_against_mismatched_ack()
    assert _skip_warnings(caplog) == []


async def test_a_faulting_msh10_read_skips_correlation_and_delivers(
    faulting_msh10: tuple[type[Exception], list[int]],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Mutation: delete the ``except PEEK_READ_FAULTS`` arm around the send site's MSH-10 read. Red:
    the injected fault escapes ``send()``.

    With the catch in place, ``send()`` does not raise, the mismatched MSA-2 is accepted (correlation
    was skipped), and one WARNING names the fault's type and never its text."""
    fault, calls = faulting_msh10
    with caplog.at_level(logging.WARNING, logger=_LOGGER):
        peer, result = await _send_against_mismatched_ack()

    assert result is None  # accepted, and this destination does not capture the reply
    assert len(peer.received) == 1, "the frame must have reached the peer"
    # The fault fired inside send(), once, at the read the catch guards.
    assert calls == [1]

    records = [r for r in caplog.records if r.name == _LOGGER and r.levelno >= logging.WARNING]
    assert len(records) == 1, [r.getMessage() for r in records]
    record = records[0]
    text = record.getMessage()
    assert record.levelno == logging.WARNING
    assert _SKIPPED in text
    assert fault.__name__ in text
    # The text must not reach the log by any route: the message, a traceback, or a stack dump.
    assert record.exc_info is None and record.stack_info is None
    assert _FAULT_TEXT not in caplog.text


async def test_an_unparseable_msh10_skips_correlation_quietly(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The ``HL7PeekError`` arm is the documented quiet skip for a payload with no readable MSH-10.
    ``HL7PeekError`` is a ``ValueError``, so merging the two arms would still pass the faulted arm
    above while logging a WARNING on every such send; this arm pins the silence."""
    calls = _inject_msh10_fault(monkeypatch, HL7PeekError)
    with caplog.at_level(logging.WARNING, logger=_LOGGER):
        peer, result = await _send_against_mismatched_ack()

    assert result is None
    assert len(peer.received) == 1
    assert calls == [1]
    assert _skip_warnings(caplog) == []
