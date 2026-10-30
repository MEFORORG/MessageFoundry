# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The REMOTEFILE source records each quarantine as a connection event (BACKLOG #1621).

Packet 9 finding P9-11, the remote half of the row whose FILE half PR 1583 built. The SFTP/FTP/FTPS
poll source's four quarantine arms (over the listed size, over the retrieved size, a content-vs-type
mismatch, a scanner rejection) moved the file to ``error_subdir`` and logged a WARNING, and wrote
nothing to the store. Each arm now emits the FILE source's matching kind, with a reason that never
carries the file name. The refused-unsafe-name arm deliberately records nothing: it moves nothing.

Deliberately ASCII-only: pytest echoes a failing body to a cp1252 console on Windows.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from messagefoundry.transports.file import set_scan_hook
from messagefoundry.transports.remotefile import _RemoteError
from tests.test_file_source_quarantine_events import _HL7, _NAME, _reject, _Sink
from tests.test_remotefile_transport import _FakeClient, _RecordingHandler, _settle, _src

_PATH = f"/in/{_NAME}"


@pytest.fixture
def _no_scan_hook() -> Iterator[None]:
    yield
    set_scan_hook(None)


# (arm id, kind, file bytes, listed size or None, max_file_bytes, rejecting hook, reason holds)
_ARMS: list[tuple[str, str, bytes, int | None, int, bool, str]] = [
    ("listed_oversize", "file_oversize", _HL7, None, 10, False, "listed at"),
    # The share lists 4 bytes and delivers the whole body: the listing gate passes, the read refuses.
    # The reason says which gate refused, so an operator can tell a lying listing apart.
    ("retrieved_oversize", "file_oversize", _HL7, 4, 10, False, "delivered more than"),
    (
        "content_mismatch",
        "file_content_mismatch",
        b"%PDF-1.7 not an HL7 message",
        None,
        0,
        False,
        "content type hl7v2",
    ),
    ("scan_rejected", "file_scan_rejected", _HL7, None, 0, True, "EICAR"),
]


@pytest.mark.parametrize(
    ("kind", "body", "listed", "cap", "scan_rejects", "says"),
    [a[1:] for a in _ARMS],
    ids=[a[0] for a in _ARMS],
)
@pytest.mark.usefixtures("_no_scan_hook")
async def test_each_quarantine_arm_records_one_event_without_the_file_name(
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
    body: bytes,
    listed: int | None,
    cap: int,
    scan_rejects: bool,
    says: str,
) -> None:
    """Mutation: drop the ``_emit_event`` call from any one arm. Red: that arm records nothing."""
    client = _FakeClient(files={_PATH: body}, sizes={} if listed is None else {_PATH: listed})
    src = _src(monkeypatch, client, max_file_bytes=cap)
    sink = _Sink()
    src.on_connection_event = sink
    handler = _RecordingHandler()
    src._handler = handler
    if scan_rejects:
        set_scan_hook(_reject)

    await _settle(src)
    assert sink.events == [], "the settle poll quarantines nothing"
    await src._poll_once()

    assert handler.bodies == [], "a quarantined drop must never reach the pipeline"
    assert f"/in/.error/{_NAME}" in client.files, "the drop is preserved in error_subdir"
    assert [(k, peer) for k, peer, _reason in sink.events] == [(kind, None)]
    reason = sink.events[0][2]
    assert reason is not None and says in reason, f"unexpected reason: {reason!r}"
    assert "MRN123456789" not in reason, f"the file name leaked into the reason: {reason!r}"


async def test_a_failing_sink_never_stops_the_quarantine(monkeypatch: pytest.MonkeyPatch) -> None:
    """The event is a pure observer: a sink that raises is logged and the poll carries on.

    Mutation: let the sink's exception propagate. Red: ``_poll_once`` raises."""
    client = _FakeClient(files={_PATH: _HL7})
    src = _src(monkeypatch, client, max_file_bytes=10)

    async def broken_sink(_kind: str, _peer: str | None, _reason: str | None) -> None:
        raise RuntimeError("event store unavailable")

    src.on_connection_event = broken_sink
    src._handler = _RecordingHandler()
    await _settle(src)
    await src._poll_once()

    assert f"/in/.error/{_NAME}" in client.files


@pytest.mark.parametrize(
    ("body", "listed", "cap", "scan_rejects"),
    [a[2:6] for a in _ARMS],
    ids=[a[0] for a in _ARMS],
)
@pytest.mark.usefixtures("_no_scan_hook")
async def test_a_quarantine_whose_move_failed_records_nothing(
    monkeypatch: pytest.MonkeyPatch,
    body: bytes,
    listed: int | None,
    cap: int,
    scan_rejects: bool,
) -> None:
    """A file the server would not rename (locked, error dir unwritable) is still in the poll
    directory and is examined again next poll. Recording it as quarantined would be false, and would
    write one row per poll for as long as it stays.

    Mutation: emit regardless of the move's result in any one arm. Red: an event is recorded."""
    client = _FakeClient(
        files={_PATH: body},
        sizes={} if listed is None else {_PATH: listed},
        rename_exc=_RemoteError("permission denied", permanent=False),
    )
    src = _src(monkeypatch, client, max_file_bytes=cap)
    sink = _Sink()
    src.on_connection_event = sink
    src._handler = _RecordingHandler()
    if scan_rejects:
        set_scan_hook(_reject)
    await _settle(src)
    await src._poll_once()

    assert ("rename", f"{_PATH}->/in/.error/{_NAME}") in client.ops, "the move was really tried"
    assert sink.events == []
    assert _PATH in client.files


async def test_a_refused_unsafe_name_records_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    """The unsafe-name arm leaves the entry in place, so it is refused again every poll; an event
    there would be one store row per poll interval. It deliberately records none.

    Mutation: emit an event from that arm. Red: an event is recorded."""
    client = _FakeClient()
    monkeypatch.setattr(
        client,
        "list_dir",
        lambda _remote_dir: [("../escape.hl7", len(_HL7))],
    )
    src = _src(monkeypatch, client, max_file_bytes=10)
    sink = _Sink()
    src.on_connection_event = sink
    src._handler = _RecordingHandler()
    await _settle(src)
    await src._poll_once()

    assert not any(op == "retrieve" for op, _ in client.ops), "the name was refused, not read"
    assert sink.events == []
