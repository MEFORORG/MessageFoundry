# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A blank-segment payload names its file by the fallback instead of faulting (BACKLOG #1623).

``render_filename`` caught ``HL7PeekError`` around ``Peek.parse`` only. A payload with a blank
segment PARSES, and then the field read raises ``IndexError`` by design (the peek keeps python-hl7's
behaviour there). That escaped ``FileDestination.send()`` as a bare ``IndexError``, outside the
``DeliveryError`` contract the delivery worker relies on, so the fallback name was never used.

Deliberately ASCII-only: pytest echoes a failing body to a cp1252 console on Windows.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.parsing.peek import Peek
from messagefoundry.transports.file import FileDestination, render_filename

# A blank segment between MSH and PID: the "\r\r" is the whole defect.
_BLANK_SEGMENT = (
    "MSH|^~\\&|SND|FAC|RCV|FAC|20260101120000||ADT^A01|CTL1623|P|2.5.1\r\rPID|1||12345\r"
)


def test_the_payload_really_faults_a_field_read() -> None:
    """Positive control on the fixture: without it the tests below could pass on a payload the peek
    reads cleanly, and prove nothing."""
    peek = Peek.parse(_BLANK_SEGMENT)
    with pytest.raises(IndexError):
        peek.field("MSH-10")


def test_render_filename_falls_back_when_the_field_read_faults() -> None:
    """Mutation: remove the ``except (IndexError, ValueError)`` around the field read. Red:
    ``IndexError`` escapes."""
    assert render_filename("{MSH-10}.hl7", _BLANK_SEGMENT, fallback="message.hl7") == (
        "message.hl7.hl7"
    )


async def test_send_delivers_under_the_fallback_name(tmp_path: Path) -> None:
    """End to end through ``send()``: the message is delivered, not faulted."""
    destination = FileDestination(
        Destination(
            name="archive",
            type=ConnectorType.FILE,
            settings={"directory": str(tmp_path), "filename": "{MSH-10}.hl7"},
        )
    )

    await destination.send(_BLANK_SEGMENT)

    assert [p.name for p in tmp_path.iterdir()] == ["message.hl7.hl7"]
    assert (tmp_path / "message.hl7.hl7").read_bytes() == _BLANK_SEGMENT.encode("utf-8")
