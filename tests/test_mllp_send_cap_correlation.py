# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A body over a ``Peek.parse`` cap still has its ACK correlated at the MLLP send site (BACKLOG
#4905).

With ``verify_ack_control_id`` on, ``MLLPDestination.send`` reads the outgoing MSH-10 to correlate
it with the reply's MSA-2. It parsed the WHOLE body to do that, so a body over a ``Peek.parse`` cap
(16 MiB, 10,000 segments, the counted-escape scan) raised ``HL7PeekError`` into the quiet arm, and
correlation switched off with no log line although MSH-10 sat readable in the header. The read now
parses the MSH segment alone.

The arms: each cap refuses the whole body (the premise, pinned so a raised cap cannot make this file
vacuous) while the header read returns MSH-10; a real send of a 10,001-segment body to a peer that
echoes the wrong MSA-2 is refused as a mismatch, with a control that echoes the right one; a header
that leads with MSH and still cannot be read logs by type name; and a payload that is not HL7 stays
quiet. Every fixture is synthetic HL7. Deliberately ASCII-only.
"""

from __future__ import annotations

import logging

import pytest

from messagefoundry.parsing._builtin_hl7 import MAX_COUNTED_ESCAPE_OPENERS
from messagefoundry.parsing.peek import (
    DEFAULT_MAX_MESSAGE_BYTES,
    DEFAULT_MAX_SEGMENTS,
    HL7MessageTooLarge,
    HL7PeekError,
    Peek,
)
from messagefoundry.transports.base import DeliveryError, DeliveryResponse
from messagefoundry.transports.mllp import _outgoing_control_id
from tests.test_mllp_nak_detail_bound import _ack_with_control_id, _dest, _NakPeer

_LOGGER = "messagefoundry.transports.mllp"
_SKIPPED = "ACK correlation skipped"

_SENT_ID = "CTL4905"
_OTHER_ID = "NOTMINE4905"

_HEADER = f"MSH|^~\\&|SNDAPP|SNDFAC|RCVAPP|RCVFAC|20260101||ORU^R01|{_SENT_ID}|P|2.5.1\r"


def _over_segments() -> str:
    return _HEADER + "OBX|1|ST|X||v\r" * DEFAULT_MAX_SEGMENTS


def _over_size() -> str:
    return _HEADER + "OBX|1|ST|X||" + "A" * DEFAULT_MAX_MESSAGE_BYTES + "\r"


def _over_escapes() -> str:
    # ``\.in5\`` is the counted rich-text escape the scan walks; one past its ceiling.
    return _HEADER + "OBX|1|FT|X||" + "\\.in5\\" * (MAX_COUNTED_ESCAPE_OPENERS + 1) + "\r"


_CAPPED = {
    "segments": (_over_segments, HL7PeekError),
    "size": (_over_size, HL7MessageTooLarge),
    "escapes": (_over_escapes, HL7PeekError),
}


@pytest.mark.parametrize("cap", sorted(_CAPPED))
def test_a_capped_body_is_refused_whole_but_its_msh10_reads(cap: str) -> None:
    """Premise and fix in one arm: the whole-body parse refuses (what the send site used to run),
    and the header read the send site runs now returns MSH-10."""
    build, refusal = _CAPPED[cap]
    body = build()
    with pytest.raises(refusal):
        Peek.parse(body)
    assert _outgoing_control_id(body) == _SENT_ID


@pytest.mark.parametrize(
    "payload",
    [
        _HEADER + "PID|1\r",
        _HEADER.replace("\r", "\n") + "PID|1\n",
        _HEADER.replace("\r", "\r\n") + "PID|1\r\n",
        "\r\n " + _HEADER + "PID|1\r",
        _HEADER.rstrip("\r"),
    ],
    ids=["cr", "lf", "crlf", "leading-whitespace", "header-only"],
)
def test_the_header_read_agrees_with_the_whole_body_read(payload: str) -> None:
    """Under every cap, slicing at the first line break reads the same MSH-10 the whole-body parse
    reads, whatever the line endings or leading whitespace."""
    assert _outgoing_control_id(payload) == Peek.parse(payload).control_id == _SENT_ID


async def _send(payload: str, echoed: str) -> tuple[_NakPeer, DeliveryResponse | None]:
    """Deliver ``payload`` to a peer that accepts it with MSA-2 = ``echoed``, correlation on."""
    peer = _NakPeer("", raw_ack=_ack_with_control_id("AA", echoed))
    await peer.start()
    try:
        dest = _dest(peer.port, verify_ack_control_id=True, timeout_seconds=10, connect_timeout=2)
        try:
            result = await dest.send(payload)
        finally:
            await dest.aclose()
    finally:
        await peer.stop()
    return peer, result


def _skip_warnings(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.name == _LOGGER and _SKIPPED in r.getMessage()]


async def test_a_capped_body_with_a_wrong_msa2_is_refused(caplog: pytest.LogCaptureFixture) -> None:
    """Mutation: send-site read back to ``Peek.parse(payload).control_id``. Red: the segment cap
    refuses the parse, correlation switches off quietly, and the wrong MSA-2 is accepted."""
    with (
        caplog.at_level(logging.WARNING, logger=_LOGGER),
        pytest.raises(DeliveryError, match="ACK control-id mismatch"),
    ):
        await _send(_over_segments(), _OTHER_ID)
    assert _skip_warnings(caplog) == []


async def test_control_a_capped_body_with_its_own_msa2_is_accepted() -> None:
    """Control: the same body, with the peer echoing the sent MSA-2, delivers. So the refusal above
    is the correlation check, not the body or the peer."""
    peer, result = await _send(_over_segments(), _SENT_ID)
    assert result is None
    assert len(peer.received) == 1


async def test_an_msh_led_header_that_cannot_be_read_logs_by_type(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A payload that leads with MSH but whose header is refused switches off a delivery check, so it
    says so, naming the refusal's type and never its text. Correlation is skipped, so the wrong MSA-2
    is accepted."""
    payload = "MSH\rPID|1\r"
    with pytest.raises(HL7PeekError):
        Peek.parse(payload)
    with caplog.at_level(logging.WARNING, logger=_LOGGER):
        peer, result = await _send(payload, _OTHER_ID)
    assert result is None
    assert len(peer.received) == 1
    records = _skip_warnings(caplog)
    assert len(records) == 1, [r.getMessage() for r in records]
    text = records[0].getMessage()
    assert "HL7PeekError" in text
    assert "too short" not in text  # the refusal's text stays out of the log
    assert records[0].exc_info is None


async def test_a_payload_that_is_not_hl7_skips_correlation_quietly(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A non-HL7 payload has no MSH-10 at all; skipping correlation there is the documented quiet
    case, so it logs nothing."""
    with caplog.at_level(logging.WARNING, logger=_LOGGER):
        peer, result = await _send("NOT-HL7 payload\r", _OTHER_ID)
    assert result is None
    assert len(peer.received) == 1
    assert _skip_warnings(caplog) == []
