# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A faulting field read names the file by the fallback instead of escaping send() (BACKLOG #1623).

``render_filename`` caught ``HL7PeekError`` around ``Peek.parse`` only. A payload that parsed could
still fault the field READ, and that escaped ``FileDestination.send()`` outside the ``DeliveryError``
contract the delivery worker relies on. A blank segment was the fault that found it.

BACKLOG #1594 then fixed the blank segment at the parse, so that payload no longer faults: it names
its file by MSH-10, which the first test pins. The #1623 fallback stays for any other parser fault,
so the rest inject one at ``Peek.field``, and a positive control proves the injection really fires.

Deliberately ASCII-only: pytest echoes a failing body to a cp1252 console on Windows.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.parsing.peek import Peek
from messagefoundry.transports.file import FileDestination, render_filename

# A blank segment between MSH and PID: the "\r\r" used to fault every field read.
_BLANK_SEGMENT = (
    "MSH|^~\\&|SND|FAC|RCV|FAC|20260101120000||ADT^A01|CTL1623|P|2.5.1\r\rPID|1||12345\r"
)

#: One concrete type from each family ``PEEK_READ_FAULTS`` names. The fallback tests below go red for
#: any of them the catch in ``file.py`` stops covering, which is what pins the catch to all three.
_FAULTS = (IndexError, TypeError, ValueError)


@pytest.fixture(params=_FAULTS, ids=lambda exc: exc.__name__)
def faulting_read(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> type[Exception]:
    """Make every ``Peek.field`` read raise, as a parser fault past the tolerant contract would."""
    fault: type[Exception] = request.param

    def _raise(self: Peek, path: str) -> str | None:
        raise fault(f"injected fault reading {path}")

    monkeypatch.setattr(Peek, "field", _raise)
    return fault


def _destination(tmp_path: Path) -> FileDestination:
    return FileDestination(
        Destination(
            name="archive",
            type=ConnectorType.FILE,
            settings={"directory": str(tmp_path), "filename": "{MSH-10}.hl7"},
        )
    )


def test_a_blank_segment_names_its_file_by_msh10() -> None:
    """BACKLOG #1594: the blank line is dropped at the parse, so MSH-10 reads and names the file."""
    assert Peek.parse(_BLANK_SEGMENT).field("MSH-10") == "CTL1623"
    assert render_filename("{MSH-10}.hl7", _BLANK_SEGMENT, fallback="message.hl7") == "CTL1623.hl7"


def test_the_injected_fault_really_faults_a_field_read(faulting_read: type[Exception]) -> None:
    """Positive control on the injection: without it the tests below could pass on a read that
    succeeds, and prove nothing. The same payload reads cleanly in the test above."""
    peek = Peek.parse(_BLANK_SEGMENT)
    with pytest.raises(faulting_read):
        peek.field("MSH-10")


def test_render_filename_falls_back_when_the_field_read_faults(
    faulting_read: type[Exception], caplog: pytest.LogCaptureFixture
) -> None:
    """Mutation: remove the ``except PEEK_READ_FAULTS`` around the field read. Red: the injected
    fault escapes. The fallback is logged by fault type and placeholder, never by the fault's text."""
    with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.file"):
        assert render_filename("{MSH-10}.hl7", _BLANK_SEGMENT, fallback="message.hl7") == (
            "message.hl7.hl7"
        )
    [record] = [r for r in caplog.records if r.name == "messagefoundry.transports.file"]
    assert record.levelno == logging.WARNING
    assert faulting_read.__name__ in record.getMessage() and "MSH-10" in record.getMessage()
    assert "injected" not in record.getMessage()


async def test_send_delivers_under_the_fallback_name(
    tmp_path: Path, faulting_read: type[Exception]
) -> None:
    """End to end through ``send()``: the message is delivered, not faulted."""
    await _destination(tmp_path).send(_BLANK_SEGMENT)

    assert [p.name for p in tmp_path.iterdir()] == ["message.hl7.hl7"]
    assert (tmp_path / "message.hl7.hl7").read_bytes() == _BLANK_SEGMENT.encode("utf-8")
