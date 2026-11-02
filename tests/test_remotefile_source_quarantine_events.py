# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The REMOTEFILE source records each quarantine as a connection event (BACKLOG #1621).

Packet 9 finding P9-11, the remote half of the row whose FILE half PR 1583 built. The SFTP/FTP/FTPS
poll source's four quarantine arms (over the listed size, over the retrieved size, a content-vs-type
mismatch, a scanner rejection) moved the file to ``error_subdir`` and logged a WARNING, and wrote
nothing to the store. Each arm now emits the FILE source's matching kind, with a reason that carries
no exact copy of the file name. A scanner quoting it in another form is kept, the limit
``docs/PHI.md`` section 7 row 7 states. The refused-unsafe-name arm deliberately records nothing: it
moves nothing.

Deliberately ASCII-only: pytest echoes a failing body to a cp1252 console on Windows.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from messagefoundry.redaction import safe_name
from messagefoundry.transports.file import ScanRejected, set_scan_hook
from messagefoundry.transports.remotefile import _RemoteError
from tests.test_file_source_quarantine_events import _HL7, _NAME, _QUOTED_FORMS, _reject, _Sink
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


@pytest.mark.parametrize(
    ("name", "quoted", "kept"), [f[1:] for f in _QUOTED_FORMS], ids=[f[0] for f in _QUOTED_FORMS]
)
@pytest.mark.usefixtures("_no_scan_hook")
async def test_the_scan_reject_reason_scrubs_only_an_exact_copy_of_the_name(
    monkeypatch: pytest.MonkeyPatch, name: str, quoted: str, kept: bool
) -> None:
    """Pins the limit ``docs/PHI.md`` section 7 row 7 states. A stronger scrub turns this red, and
    that row must then change with it.

    Mutation: make the replacement in ``safe_exc`` ignore case. Red: the two case rows."""
    client = _FakeClient(files={f"/in/{name}": _HL7})
    src = _src(monkeypatch, client)
    sink = _Sink()
    src.on_connection_event = sink
    src._handler = _RecordingHandler()

    def reject(_raw: bytes, _source: str) -> None:
        raise ScanRejected(f"EICAR test signature in {quoted}")

    set_scan_hook(reject)
    await _settle(src)
    await src._poll_once()

    assert [k for k, _peer, _reason in sink.events] == ["file_scan_rejected"]
    reason = sink.events[0][2]
    assert reason is not None
    assert (quoted in reason) is kept, f"unexpected reason: {ascii(reason)}"
    if not kept:
        assert safe_name(name) in reason, f"unexpected reason: {ascii(reason)}"


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


@pytest.mark.parametrize("error_subdir", ["", "."])
async def test_an_error_subdir_naming_the_poll_directory_records_nothing(
    monkeypatch: pytest.MonkeyPatch, error_subdir: str
) -> None:
    """An ``error_subdir`` that resolves to the poll directory turns the quarantine move into a
    rename onto itself, which a server reports as success. The file never leaves, so recording it
    would write one row each time it settles again.

    Mutation: drop the same-path check in ``_move``. Red: events are recorded."""
    client = _FakeClient(files={_PATH: _HL7})
    src = _src(monkeypatch, client, max_file_bytes=10, error_subdir=error_subdir)
    sink = _Sink()
    src.on_connection_event = sink
    src._handler = _RecordingHandler()
    for _ in range(4):
        await src._poll_once()

    assert sink.events == []
    assert _PATH in client.files
