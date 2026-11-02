# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The FILE source records each quarantine as a connection event (BACKLOG #1621).

Its four quarantine arms (oversize, gunzip failure, content mismatch, scanner rejection) moved the
drop to ``.error`` and logged a WARNING, and wrote nothing to the store, although the runner injects
the connection-event sink on every source and the MLLP over-cap arm has always used it. An operator
watching the console saw nothing when a partner's drop was quarantined. Each arm now emits one event
whose reason carries no exact copy of the file name. A scanner quoting it in another form is kept:
``_QUOTED_FORMS`` pins that limit, which ``docs/PHI.md`` section 7 row 7 states.

Deliberately ASCII-only: pytest echoes a failing body to a cp1252 console on Windows.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.redaction import safe_name
from messagefoundry.transports.file import FileSource, ScanRejected, set_scan_hook

# A partner-chosen name built from an MRN: an exact copy of it must not reach the reason.
_NAME = "MRN123456789_ADT.hl7"
_HL7 = b"MSH|^~\\&|SND|FAC|RCV|FAC|20260101120000||ADT^A01|CTL1621|P|2.5.1\rPID|1||12345\r"

# (form id, the file's name, how the scanner's message quotes it, the reason keeps that text)
_QUOTED_FORMS: list[tuple[str, str, str, bool]] = [
    ("exact", _NAME, _NAME, False),  # the control: this arm really does scrub
    ("lower_case", _NAME, _NAME.lower(), True),
    ("upper_case", _NAME, _NAME.upper(), True),
    ("no_extension", _NAME, _NAME.removesuffix(".hl7"), True),
    ("percent_encoded", "DOE JOHN.hl7", "DOE%20JOHN.hl7", True),
    ("decomposed_unicode", "JOS\u00c9_ADT.hl7", "JOSE\u0301_ADT.hl7", True),
    ("escaped_unicode", "JOS\u00c9_ADT.hl7", "JOS\\xc9_ADT.hl7", True),
]


class _Sink:
    def __init__(self) -> None:
        self.events: list[tuple[str, str | None, str | None]] = []

    async def __call__(self, kind: str, peer_host: str | None, reason: str | None) -> None:
        self.events.append((kind, peer_host, reason))


@pytest.fixture
def _no_scan_hook() -> Iterator[None]:
    yield
    set_scan_hook(None)


def _reject(_raw: bytes, _source: str) -> None:
    raise ScanRejected(f"EICAR test signature in {_NAME}")


async def _settle(source: FileSource) -> None:
    """Take the settle poll (BACKLOG #1811). A file's first sighting only records its stat and reaches
    no quarantine arm, so the scan after this one is the one these tests measure."""
    await source._scan_once()


# (kind, extra settings, file bytes, install the rejecting scan hook)
_ARMS: list[tuple[str, dict[str, Any], bytes, bool]] = [
    ("file_oversize", {"max_file_bytes": 10}, _HL7, False),
    ("file_decompress_failed", {"decompress": "gzip"}, b"this is not a gzip stream", False),
    ("file_content_mismatch", {}, b"%PDF-1.7 not an HL7 message", False),
    ("file_scan_rejected", {}, _HL7, True),
]


@pytest.mark.parametrize(
    ("kind", "settings", "body", "scan_rejects"), _ARMS, ids=[a[0] for a in _ARMS]
)
@pytest.mark.usefixtures("_no_scan_hook")
async def test_each_quarantine_arm_records_one_event_without_the_file_name(
    tmp_path: Path, kind: str, settings: dict[str, Any], body: bytes, scan_rejects: bool
) -> None:
    """Mutation: drop the ``_emit_event`` call from any one arm. Red: that arm records nothing."""
    inbox = tmp_path / "in"
    inbox.mkdir()
    (inbox / _NAME).write_bytes(body)
    source = FileSource(
        Source(type=ConnectorType.FILE, settings={"directory": str(inbox), **settings})
    )
    sink = _Sink()
    source.on_connection_event = sink
    handed_off: list[bytes] = []

    async def handler(raw: bytes) -> str | None:
        handed_off.append(raw)
        return None

    source._handler = handler
    source._prepare_subdirs()
    if scan_rejects:
        set_scan_hook(_reject)

    await _settle(source)
    assert sink.events == [], "the settle poll quarantines nothing"
    await source._scan_once()

    assert handed_off == [], "a quarantined drop must never reach the pipeline"
    assert (inbox / ".error" / _NAME).exists(), "the drop is preserved in .error"
    assert [(k, peer) for k, peer, _reason in sink.events] == [(kind, None)]
    reason = sink.events[0][2]
    assert reason, "the event carries a reason"
    assert "MRN123456789" not in reason, f"the file name leaked into the reason: {reason!r}"


@pytest.mark.parametrize(
    ("name", "quoted", "kept"), [f[1:] for f in _QUOTED_FORMS], ids=[f[0] for f in _QUOTED_FORMS]
)
@pytest.mark.usefixtures("_no_scan_hook")
async def test_the_scan_reject_reason_scrubs_only_an_exact_copy_of_the_name(
    tmp_path: Path, name: str, quoted: str, kept: bool
) -> None:
    """Pins the limit ``docs/PHI.md`` section 7 row 7 states. A stronger scrub turns this red, and
    that row must then change with it.

    Mutation: make the replacement in ``safe_exc`` ignore case. Red: the two case rows."""
    inbox = tmp_path / "in"
    inbox.mkdir()
    (inbox / name).write_bytes(_HL7)
    source = FileSource(Source(type=ConnectorType.FILE, settings={"directory": str(inbox)}))
    sink = _Sink()
    source.on_connection_event = sink

    async def handler(_raw: bytes) -> str | None:
        return None

    def reject(_raw: bytes, _source: str) -> None:
        raise ScanRejected(f"EICAR test signature in {quoted}")

    source._handler = handler
    source._prepare_subdirs()
    set_scan_hook(reject)
    await _settle(source)
    await source._scan_once()

    assert [k for k, _peer, _reason in sink.events] == ["file_scan_rejected"]
    reason = sink.events[0][2]
    assert reason is not None
    assert (quoted in reason) is kept, f"unexpected reason: {ascii(reason)}"
    if not kept:
        assert safe_name(name) in reason, f"unexpected reason: {ascii(reason)}"


async def test_a_failing_sink_never_stops_the_quarantine(tmp_path: Path) -> None:
    """The event is a pure observer: a sink that raises is logged and the scan carries on.

    Mutation: let the sink's exception propagate. Red: ``_scan_once`` raises."""
    inbox = tmp_path / "in"
    inbox.mkdir()
    (inbox / _NAME).write_bytes(_HL7)
    source = FileSource(
        Source(type=ConnectorType.FILE, settings={"directory": str(inbox), "max_file_bytes": 10})
    )

    async def broken_sink(_kind: str, _peer: str | None, _reason: str | None) -> None:
        raise RuntimeError("event store unavailable")

    async def handler(_raw: bytes) -> str | None:
        return None

    source.on_connection_event = broken_sink
    source._handler = handler
    source._prepare_subdirs()

    await _settle(source)
    await source._scan_once()

    assert (inbox / ".error" / _NAME).exists()


async def test_a_quarantine_whose_move_failed_records_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A drop that could not be moved (a read-only share, a locked file) is still in place and is
    examined again next scan. Recording it as quarantined would be false, and would write one row
    per poll for as long as it stays.

    Mutation: emit regardless of the move's result. Red: an event is recorded."""
    inbox = tmp_path / "in"
    inbox.mkdir()
    (inbox / _NAME).write_bytes(_HL7)
    source = FileSource(
        Source(type=ConnectorType.FILE, settings={"directory": str(inbox), "max_file_bytes": 10})
    )
    sink = _Sink()
    source.on_connection_event = sink

    async def handler(_raw: bytes) -> str | None:
        return None

    source._handler = handler
    moves: list[Path] = []

    def failed_move(path: Path, _dest: Path, *_rest: object) -> bool:
        moves.append(path)
        return False

    monkeypatch.setattr(FileSource, "_move", staticmethod(failed_move))

    await _settle(source)
    await source._scan_once()

    assert moves == [inbox / _NAME], "the oversize arm really tried the move (not a vacuous pass)"
    assert sink.events == []
    assert (inbox / _NAME).exists()
