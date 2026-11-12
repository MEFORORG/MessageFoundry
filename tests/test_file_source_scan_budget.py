# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A FILE source charges its per-tick budget only for a reject it actually archived (BACKLOG #5717).

``_scan_once`` used to count every quarantine arm against ``poll_max_files`` whether or not the move
to ``.error`` succeeded. A reject the move left in place (a locked file, an unwritable ``.error``, a
read-only share under ``after_read = "leave"``) is examined again on the next scan, so one that sorts
early would spend the budget on every scan and the healthy drops behind it would never be ingested.

Deliberately ASCII-only: pytest echoes a failing body to a cp1252 console on Windows.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.transports.file import FileSource

_HL7 = b"MSH|^~\\&|SND|FAC|RCV|FAC|20260101120000||ADT^A01|CTL5717|P|2.5.1\rPID|1||12345\r"
# Sorts before the healthy drop under the default name order, and is no HL7 message: the
# content-type arm rejects it.
_REJECT = "a_reject.hl7"
_HEALTHY = "b_healthy.hl7"


class _Sink:
    def __init__(self) -> None:
        self.kinds: list[str] = []

    async def __call__(self, kind: str, _peer_host: str | None, _reason: str | None) -> None:
        self.kinds.append(kind)


def _source(inbox: Path, handed_off: list[bytes], **settings: Any) -> tuple[FileSource, _Sink]:
    source = FileSource(
        Source(
            type=ConnectorType.FILE,
            settings={"directory": str(inbox), "poll_max_files": 1, **settings},
        )
    )
    sink = _Sink()
    source.on_connection_event = sink

    async def handler(raw: bytes) -> str | None:
        handed_off.append(raw)
        return None

    source._handler = handler
    source._prepare_subdirs()
    return source, sink


def _drops(tmp_path: Path) -> Path:
    inbox = tmp_path / "in"
    inbox.mkdir()
    (inbox / _REJECT).write_bytes(b"%PDF-1.7 not an HL7 message")
    (inbox / _HEALTHY).write_bytes(_HL7)
    return inbox


async def test_a_reject_whose_move_failed_does_not_spend_the_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Mutation: charge the quarantine arm whatever the move returned (the old ``disposed += 1``
    outside the ``if``). Red: the scan stops at the reject and the healthy drop is never handed off."""
    inbox = _drops(tmp_path)
    handed_off: list[bytes] = []
    source, sink = _source(inbox, handed_off)
    real_move = FileSource._move
    refused: list[str] = []

    def move(self: FileSource, path: Path, dest_dir: Path, *rest: Any, **kw: Any) -> bool:
        if dest_dir == self.error_dir:
            refused.append(path.name)
            return False  # as _move reports an archive it could not make
        return real_move(self, path, dest_dir, *rest, **kw)

    monkeypatch.setattr(FileSource, "_move", move)

    await source._scan_once()  # the settle poll (BACKLOG #1811)
    await source._scan_once()

    assert refused == [_REJECT], "the content arm really tried the move (not a vacuous pass)"
    assert handed_off == [_HL7], "the healthy drop behind the stuck reject was ingested this scan"
    assert (inbox / ".processed" / _HEALTHY).exists()
    assert (inbox / _REJECT).exists(), "the unmoved reject is left in place, not dropped"
    assert sink.kinds == [], "a reject that was not archived records no quarantine event"


async def test_an_archived_reject_still_spends_the_budget(tmp_path: Path) -> None:
    """The control: a reject that did leave for ``.error`` is finished with, so it charges, and the
    healthy drop waits for the next scan. Mutation: never charge a quarantine. Red: both go in one."""
    inbox = _drops(tmp_path)
    handed_off: list[bytes] = []
    source, sink = _source(inbox, handed_off)

    await source._scan_once()  # the settle poll (BACKLOG #1811)
    await source._scan_once()

    assert (inbox / ".error" / _REJECT).exists()
    assert sink.kinds == ["file_content_mismatch"]
    assert handed_off == [], "the budget of one was spent on the archived reject"

    await source._scan_once()
    assert handed_off == [_HL7], "the deferred healthy drop arrives on the next scan"
