# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The harness X12 sink never echoes an ISA13 that is not nine digits into its TA1 (ASVS 1.1.2).

ISA13 is read by fixed offset, so a received one can hold the element and segment separators. The
sink's TA1 is written with fixed separators, so echoing ``1*0*0*R~Z`` into TA101 gave a reply the
engine's own codec reads as TA1-04 ``R``: a sink configured to ACCEPT made the engine's X12
destination dead-letter the delivery as a permanent reject. The sink now answers nothing for such
an interchange, as it already did for one with no readable ISA13, and ``ta1()`` refuses the value.

Each case pairs with a clean control on the same path, so a pass is not a check that cannot fail.
Synthetic data only: the interchange is the harness's own synthetic 837 envelope.
"""

from __future__ import annotations

import asyncio

import pytest

from harness.drivers._x12_interchange import (
    fresh_control_number,
    interchange,
    is_control_number,
    ta1,
)
from harness.drivers.x12 import X12Driver
from harness.sinks.x12 import X12Sink, isa13_of
from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.parsing.x12 import X12FrameReader, X12Message
from messagefoundry.transports.base import DeliveryError, NegativeAckError
from messagefoundry.transports.x12 import X12Destination

#: Nine characters, so it sits exactly in ISA13's fixed slot, and it holds the element separator
#: and the segment terminator: echoed into a TA1 it adds TA1-02..04 = 0, 0, R and a stray segment.
_HOSTILE_ISA13 = "1*0*0*R~Z"


def _interchange_with_isa13(isa13: str) -> bytes:
    """The harness's synthetic interchange with ISA13 set to ``isa13``. Built from a clean interchange
    through the ISA's field list, because ``isa()`` refuses a control number that is not nine digits.
    IEA02 keeps the clean value: a terminator in it would end the frame early, and the sink answers
    a TA1 whether or not the envelope ties out."""
    assert len(isa13) == 9
    clean = interchange("000000001").decode("ascii")
    head, rest = clean[:106], clean[106:]
    fields = head[:-1].split("*")
    fields[13] = isa13
    rebuilt = "*".join(fields) + "~"
    assert len(rebuilt) == 106
    return (rebuilt + rest).encode("ascii")


def test_the_hostile_interchange_frames_and_peeks_its_isa13_by_offset() -> None:
    # Preconditions: the hostile value reaches the sink's echo, so the tests below exercise it.
    wire = _interchange_with_isa13(_HOSTILE_ISA13)
    assert list(X12FrameReader().feed(wire)) == [wire]
    assert isa13_of(wire) == _HOSTILE_ISA13
    assert not is_control_number(_HOSTILE_ISA13)
    assert is_control_number("000000001")
    assert not is_control_number("00000000١")  # a non-ASCII digit is not an X12 digit


def test_ta1_refuses_an_acknowledged_value_that_is_not_nine_digits() -> None:
    with pytest.raises(ValueError, match="TA101 must be nine digits"):
        ta1(_HOSTILE_ISA13, "A", control="000000999")
    # Control: a nine-digit value is acknowledged, and parses back as it was written.
    reply = X12Message.parse(ta1("000000123", "A", control="000000999"))
    assert (reply.get("TA1-01"), reply.get("TA1-04")) == ("000000123", "A")


def test_an_accepting_sink_does_not_answer_a_hostile_isa13() -> None:
    wire = _interchange_with_isa13(_HOSTILE_ISA13)
    with X12Sink(ta1="A") as sink:
        (out,) = X12Driver("127.0.0.1", sink.port, timeout=5.0).inject([wire])
        records = sink.wait_for(bool, 5.0)
    assert out.error == ""
    assert out.reply is None  # before the fix: a TA1 whose TA1-04 parsed as "R"
    assert [r.payload for r in records] == [wire]  # still recorded, as everything received is
    assert records[0].meta["isa13"] == _HOSTILE_ISA13


def _dest(port: int) -> X12Destination:
    settings: dict[str, object] = {
        "host": "127.0.0.1",
        "port": port,
        "timeout_seconds": 1,
        "ta1_required": True,
    }
    return X12Destination(Destination(name="out", type=ConnectorType.X12, settings=settings))


def test_the_engine_destination_is_not_told_reject_by_an_accepting_sink() -> None:
    """End to end: the engine's own X12 destination delivers to the harness sink set to accept.
    Before the fix the echoed ISA13 turned the TA1 into TA1-04 R, a permanent NegativeAckError
    (dead-letter). Now the sink stays silent, which a ta1_required destination treats as a
    retryable DeliveryError -- never as the partner's permanent reject."""

    async def deliver(wire: bytes) -> None:
        with X12Sink(ta1="A") as sink:
            await _dest(sink.port).send(wire.decode("ascii"))

    with pytest.raises(DeliveryError) as caught:
        asyncio.run(deliver(_interchange_with_isa13(_HOSTILE_ISA13)))
    assert not isinstance(caught.value, NegativeAckError)
    # Clean control on the same path: a nine-digit ISA13 is acknowledged and accepted.
    asyncio.run(deliver(interchange(fresh_control_number())))
