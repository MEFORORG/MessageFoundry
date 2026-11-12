# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A FILE source charges its per-tick budget only for a reject that left the drop directory
(BACKLOG #5717).

``_scan_once`` used to count every quarantine arm against ``poll_max_files`` whether or not the move
to ``.error`` succeeded. A reject the move left in place (a locked file, an unwritable ``.error``, a
read-only share under ``after_read = "leave"``) is examined again on the next scan, so one that sorts
early would spend the budget on every scan and the healthy drops behind it would never be ingested.

Deliberately ASCII-only: pytest echoes a failing body to a cp1252 console on Windows.
"""

from __future__ import annotations

import gzip
import shutil
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.transports.file import FileSource, ScanRejected, set_scan_hook

_HL7 = b"MSH|^~\\&|SND|FAC|RCV|FAC|20260101120000||ADT^A01|CTL5717|P|2.5.1\rPID|1||12345\r"
_REJECT_MARK = b"REJECT5717"
# Sorts before the healthy drop under the default name order.
_REJECT = "a_reject.hl7"
_HEALTHY = "b_healthy.hl7"


def _scan_rejects_marked(raw: bytes, _source: str) -> None:
    if _REJECT_MARK in raw:
        raise ScanRejected("test signature")


# (kind, extra settings, reject bytes, healthy bytes, install the scan hook)
_ARMS: list[tuple[str, dict[str, Any], bytes, bytes, bool]] = [
    ("file_oversize", {"max_file_bytes": 100}, _HL7 + b"X" * 100, _HL7, False),
    (
        "file_decompress_failed",
        {"decompress": "gzip"},
        b"this is not a gzip stream",
        gzip.compress(_HL7),
        False,
    ),
    ("file_content_mismatch", {}, b"%PDF-1.7 not an HL7 message", _HL7, False),
    ("file_scan_rejected", {}, _HL7 + _REJECT_MARK, _HL7, True),
]


class _Sink:
    def __init__(self) -> None:
        self.kinds: list[str] = []

    async def __call__(self, kind: str, _peer_host: str | None, _reason: str | None) -> None:
        self.kinds.append(kind)


@pytest.fixture
def _no_scan_hook() -> Iterator[None]:
    yield
    set_scan_hook(None)


def _setup(
    tmp_path: Path, settings: dict[str, Any], reject: bytes, healthy: bytes, scan_hook: bool
) -> tuple[Path, FileSource, _Sink, list[bytes]]:
    inbox = tmp_path / "in"
    inbox.mkdir()
    (inbox / _REJECT).write_bytes(reject)
    (inbox / _HEALTHY).write_bytes(healthy)
    source = FileSource(
        Source(
            type=ConnectorType.FILE,
            settings={"directory": str(inbox), "poll_max_files": 1, **settings},
        )
    )
    sink = _Sink()
    source.on_connection_event = sink
    handed_off: list[bytes] = []

    async def handler(raw: bytes) -> str | None:
        handed_off.append(raw)
        return None

    source._handler = handler
    source._prepare_subdirs()
    if scan_hook:
        set_scan_hook(_scan_rejects_marked)
    return inbox, source, sink, handed_off


@pytest.mark.parametrize(
    ("kind", "settings", "reject", "healthy", "scan_hook"), _ARMS, ids=[a[0] for a in _ARMS]
)
@pytest.mark.usefixtures("_no_scan_hook")
async def test_a_reject_whose_move_failed_does_not_spend_the_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
    settings: dict[str, Any],
    reject: bytes,
    healthy: bytes,
    scan_hook: bool,
) -> None:
    """Mutation: charge any one quarantine arm whatever the move returned (the old ``disposed += 1``
    outside the ``if``). Red: that arm's scan stops at the reject and the healthy drop waits."""
    inbox, source, sink, handed_off = _setup(tmp_path, settings, reject, healthy, scan_hook)
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

    assert refused == [_REJECT], f"the {kind} arm really tried the move (not a vacuous pass)"
    assert handed_off == [_HL7], "the healthy drop behind the stuck reject was ingested this scan"
    assert (inbox / _REJECT).exists(), "the unmoved reject is left in place, not dropped"
    assert sink.kinds == [], "a reject that was not archived records no quarantine event"


async def test_a_reject_archived_but_not_removed_does_not_spend_the_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``_move`` also answers True when it archived a copy and could not remove the original, which
    stays in the drop directory. Mutation: charge on ``_move``'s answer alone. Red: the healthy drop
    waits."""
    inbox, source, sink, handed_off = _setup(
        tmp_path, {}, b"%PDF-1.7 not an HL7 message", _HL7, False
    )
    real_move = FileSource._move

    def move(self: FileSource, path: Path, dest_dir: Path, *rest: Any, **kw: Any) -> bool:
        if dest_dir == self.error_dir:
            shutil.copyfile(path, dest_dir / path.name)
            return True  # archived, but the original stayed
        return real_move(self, path, dest_dir, *rest, **kw)

    monkeypatch.setattr(FileSource, "_move", move)

    await source._scan_once()  # the settle poll (BACKLOG #1811)
    await source._scan_once()

    assert (inbox / ".error" / _REJECT).exists()
    assert (inbox / _REJECT).exists()
    assert sink.kinds == ["file_content_mismatch"], "the copy in .error is a real quarantine"
    assert handed_off == [_HL7], "the healthy drop behind the unremoved reject was ingested"


async def test_an_archived_reject_still_spends_the_budget(tmp_path: Path) -> None:
    """The control: a reject that did leave for ``.error`` is finished with, so it charges, and the
    healthy drop waits for the next scan. Mutation: never charge a quarantine. Red: both go in one."""
    inbox, source, sink, handed_off = _setup(
        tmp_path, {}, b"%PDF-1.7 not an HL7 message", _HL7, False
    )

    await source._scan_once()  # the settle poll (BACKLOG #1811)
    await source._scan_once()

    assert (inbox / ".error" / _REJECT).exists()
    assert not (inbox / _REJECT).exists()
    assert sink.kinds == ["file_content_mismatch"]
    assert handed_off == [], "the budget of one was spent on the archived reject"

    await source._scan_once()
    assert handed_off == [_HL7], "the deferred healthy drop arrives on the next scan"
