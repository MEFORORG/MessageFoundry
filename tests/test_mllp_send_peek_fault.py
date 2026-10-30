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
blank-segment test would pass with the catch deleted. The first test pins that. The rest inject the
fault at ``Peek.control_id``, which is the send site's read and nothing else's: the ACK side reads
``MSA-1`` and ``MSA-2`` through ``Peek.field``, so the reply still parses and classifies normally.

The peer is a real loopback receiver from ``test_mllp_nak_detail_bound`` and the deliveries are real
``send()`` calls. Every fixture is synthetic HL7. Deliberately ASCII-only: pytest echoes a failing
body to a cp1252 console on Windows.
"""

from __future__ import annotations

import logging

import pytest

from messagefoundry.parsing.peek import PEEK_READ_FAULTS, Peek
from messagefoundry.transports.base import DeliveryError, DeliveryResponse
from tests.test_mllp_nak_detail_bound import _ack_with_control_id, _dest, _msg, _NakPeer

_LOGGER = "messagefoundry.transports.mllp"

#: The control id the sent message carries, and a different one the peer echoes in MSA-2.
_SENT_ID = "CTL1623"
_OTHER_ID = "NOTMINE1623"

#: One concrete type from each family ``PEEK_READ_FAULTS`` names, so the arms go red for any of the
#: three the catch in ``mllp.py`` stops covering.
_FAULTS = (IndexError, TypeError, ValueError)

#: Text carried by the injected fault. The send-site warning must name the fault's TYPE only, so this
#: marker appearing in a log record is a leak of the fault's text.
_FAULT_TEXT = "injected-fault-text-1623"


@pytest.fixture(params=_FAULTS, ids=lambda exc: exc.__name__)
def faulting_control_id(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> tuple[type[Exception], list[int]]:
    """Make every ``Peek.control_id`` read raise, as a parser fault past the tolerant contract would.

    Returns the fault type and a one-slot counter of how many times the read ran, so an arm can prove
    the fault fired inside ``send()`` rather than somewhere the catch never sees."""
    fault: type[Exception] = request.param
    calls = [0]

    def _raise(self: Peek) -> str | None:
        calls[0] += 1
        raise fault(_FAULT_TEXT)

    # Class-wide, so the in-process peer would fault too if it built its reply with ``build_ack``
    # (which reads ``control_id``). It sends ``raw_ack`` instead, and ``calls == [1]`` below says so.
    monkeypatch.setattr(Peek, "control_id", property(_raise))
    return fault, calls


async def _send_against_mismatched_ack() -> tuple[_NakPeer, DeliveryResponse | None]:
    """Deliver ``_msg(_SENT_ID)`` to a peer that accepts it with ``MSA-2`` = ``_OTHER_ID``.

    Correlation on, so the reply is a mismatch unless the send site skipped correlation."""
    peer = _NakPeer("", raw_ack=_ack_with_control_id("AA", _OTHER_ID))
    await peer.start()
    # Short timeouts: the peer answers at once, so a regression that waits on a reply fails fast.
    dest = _dest(peer.port, verify_ack_control_id=True, timeout_seconds=5, connect_timeout=2)
    try:
        result = await dest.send(_msg(_SENT_ID))
    finally:
        await dest.aclose()
        await peer.stop()
    return peer, result


def test_a_blank_segment_no_longer_reaches_the_catch() -> None:
    """BACKLOG #1594: the blank line is dropped at the parse, so MSH-10 reads cleanly. This is why
    the arms below inject the fault: a blank-segment payload would never exercise the catch."""
    blank = _msg(_SENT_ID).replace("\rPID", "\r\rPID", 1)
    assert "\r\r" in blank
    assert Peek.parse(blank).control_id == _SENT_ID


def test_the_injected_types_are_the_ones_the_catch_names() -> None:
    """Each injected type falls inside ``PEEK_READ_FAULTS``; a fault outside it would be a test of
    behaviour the catch never promised."""
    for fault in _FAULTS:
        assert issubclass(fault, PEEK_READ_FAULTS)


def test_the_injected_fault_really_faults_the_control_id_read(
    faulting_control_id: tuple[type[Exception], list[int]],
) -> None:
    """Positive control on the injection: without it the arms below could pass on a read that
    succeeds, and prove nothing. ``Peek.field`` stays intact, which the ACK side relies on."""
    fault, calls = faulting_control_id
    peek = Peek.parse(_msg(_SENT_ID))
    with pytest.raises(fault):
        _ = peek.control_id
    assert calls == [1]
    assert peek.field("MSH-10") == _SENT_ID


async def test_control_a_mismatched_msa2_raises_without_the_fault() -> None:
    """Control: with the MSH-10 read healthy, the same mismatched reply is refused. So acceptance in
    the faulted arm below is the effect of skipping correlation, not of a peer that matches."""
    with pytest.raises(DeliveryError, match="ACK control-id mismatch"):
        await _send_against_mismatched_ack()


async def test_a_faulting_msh10_read_skips_correlation_and_delivers(
    faulting_control_id: tuple[type[Exception], list[int]],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Mutation: delete the ``except PEEK_READ_FAULTS`` arm around the send site's MSH-10 read. Red:
    the injected fault escapes ``send()``.

    With the catch in place, ``send()`` does not raise, the mismatched MSA-2 is accepted (correlation
    was skipped), and one WARNING names the fault's type and never its text."""
    fault, calls = faulting_control_id
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
    assert "ACK correlation skipped" in text
    assert fault.__name__ in text
    assert _FAULT_TEXT not in text
