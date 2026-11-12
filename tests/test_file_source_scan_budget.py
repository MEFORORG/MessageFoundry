# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A FILE source charges its per-tick budget only for a reject of which a copy reached ``.error``
(BACKLOG #5717).

``_scan_once`` used to count every quarantine arm against ``poll_max_files`` whether or not the move
to ``.error`` succeeded. A reject the move left in place (a locked file, an unwritable ``.error``, a
read-only share under ``after_read = "leave"``) is examined again on a later scan, so rejects that
sort early would spend the budget on each scan that examines them and hold back the healthy drops.

Such a reject, and at least the other arms that read a file and leave it in place, charge a second
budget of the same size instead, which bounds those reads and pre-ingest scans per tick
(``_at_ceiling``).

Deliberately ASCII-only: pytest echoes a failing body to a cp1252 console on Windows.
"""

from __future__ import annotations

import gzip
import logging
import shutil
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.transports import file as file_mod
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
    tmp_path: Path,
    settings: dict[str, Any],
    reject: bytes,
    healthy: bytes,
    scan_hook: bool,
    *,
    cap: int = 1,
    rejects: int = 1,
    healthies: int = 1,
) -> tuple[Path, FileSource, _Sink, list[bytes]]:
    """The first reject is named ``_REJECT`` and the first healthy drop ``_HEALTHY``; the rest follow
    each in name order, so every reject sorts ahead of every healthy drop."""
    inbox = tmp_path / "in"
    inbox.mkdir()
    for n in range(rejects):
        (inbox / (_REJECT if n == 0 else f"a_reject{n}.hl7")).write_bytes(reject)
    for n in range(healthies):
        (inbox / (_HEALTHY if n == 0 else f"b_healthy{n}.hl7")).write_bytes(healthy)
    source = FileSource(
        Source(
            type=ConnectorType.FILE,
            settings={"directory": str(inbox), "poll_max_files": cap, **settings},
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


def _refuse_error_moves(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Make every move to ``.error`` archive nothing, as a locked file or an unwritable ``.error``
    would; return the names refused, in order."""
    real_move = FileSource._move
    refused: list[str] = []

    def move(self: FileSource, path: Path, dest_dir: Path, *rest: Any, **kw: Any) -> bool:
        if dest_dir == self.error_dir:
            refused.append(path.name)
            return False  # as _move reports an archive it could not make
        return real_move(self, path, dest_dir, *rest, **kw)

    monkeypatch.setattr(FileSource, "_move", move)
    return refused


def _record_reads(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record the name of every file a scan reads (each call into the confined read)."""
    real_read = file_mod._read_confined
    reads: list[str] = []

    def read(path: Path, *rest: Any, **kw: Any) -> Any:
        reads.append(path.name)
        return real_read(path, *rest, **kw)

    monkeypatch.setattr(file_mod, "_read_confined", read)
    return reads


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
    """A budget of two, one stuck reject and two healthy drops behind it: both healthy drops go in one
    scan. Mutation: charge any one quarantine arm whatever the move returned (the old
    ``disposed += 1`` outside the ``if``). Red: that arm's scan stops after one healthy drop."""
    inbox, source, sink, handed_off = _setup(
        tmp_path, settings, reject, healthy, scan_hook, cap=2, healthies=2
    )
    refused = _refuse_error_moves(monkeypatch)

    await source._scan_once()  # the settle poll (BACKLOG #1811)
    await source._scan_once()

    assert refused == [_REJECT], f"the {kind} arm really tried the move (not a vacuous pass)"
    assert handed_off == [_HL7, _HL7], "both healthy drops behind the stuck reject went this scan"
    assert (inbox / _REJECT).exists(), "the unmoved reject is left in place, not dropped"
    assert sink.kinds == [], "a reject that was not archived records no quarantine event"


@pytest.mark.parametrize(
    ("kind", "settings", "reject", "healthy", "scan_hook"), _ARMS, ids=[a[0] for a in _ARMS]
)
@pytest.mark.usefixtures("_no_scan_hook")
async def test_rejects_left_in_place_are_read_at_most_the_ceiling_per_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    kind: str,
    settings: dict[str, Any],
    reject: bytes,
    healthy: bytes,
    scan_hook: bool,
) -> None:
    """Five stuck rejects ahead of a healthy drop, against a budget of two: one scan reads two of the
    rejects, scans them where the arm scans, and stops. The healthy drop waits for a later scan, which
    is the cost of the bound, and is still in place.

    Mutation: leave an unarchived reject uncharged on the second budget (drop its
    ``retried += 1``). Red: the scan reads all five rejects and hands off the healthy drop."""
    inbox, source, _sink, handed_off = _setup(
        tmp_path, settings, reject, healthy, scan_hook, cap=2, rejects=5
    )
    refused = _refuse_error_moves(monkeypatch)
    scanned: list[str] = []
    if scan_hook:

        def hook(raw: bytes, name: str) -> None:
            scanned.append(name)
            _scan_rejects_marked(raw, name)

        set_scan_hook(hook)

    await source._scan_once()  # the settle poll (BACKLOG #1811)
    reads = _record_reads(monkeypatch)
    with caplog.at_level(logging.INFO, logger="messagefoundry.transports.file"):
        await source._scan_once()

    stuck = [_REJECT, "a_reject1.hl7"]
    assert reads == stuck, f"the {kind} scan read only the ceiling of stuck rejects"
    assert refused == stuck
    if scan_hook:
        assert scanned == stuck, "the pre-ingest scan ran only on the ceiling of stuck rejects"
    assert handed_off == []
    assert "read and left in place" in caplog.text
    assert (inbox / _HEALTHY).exists(), "the healthy drop is deferred, not dropped"


@pytest.mark.parametrize("arm", ["scan_hook_error", "handler_error", "changed_during_read"])
@pytest.mark.usefixtures("_no_scan_hook")
async def test_other_files_left_in_place_after_a_read_are_bounded_too(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, arm: str
) -> None:
    """A malfunctioning scan hook, a failing handler and a file that changed during its read (#116)
    each leave a file in place after reading it, and charge the second budget: four such files
    against a budget of two, one scan, two reads, stopped on the second budget.

    Mutations: drop the ``retried += 1`` on that arm (red: the scan reads all four), or charge
    ``disposed`` there instead (red: the stop is not logged as files read and left in place)."""
    _inbox, source, _sink, _handed = _setup(
        tmp_path, {}, _HL7, _HL7, False, cap=2, rejects=4, healthies=0
    )
    if arm == "scan_hook_error":

        def hook(_raw: bytes, _name: str) -> None:
            raise RuntimeError("scanner unreachable")

        set_scan_hook(hook)
    elif arm == "handler_error":

        async def handler(_raw: bytes) -> str | None:
            raise OSError("store unavailable")

        source._handler = handler

    await source._scan_once()  # the settle poll (BACKLOG #1811)
    reads = _record_reads(monkeypatch)
    if arm == "changed_during_read":
        counted_read = file_mod._read_confined

        def short_read(path: Path, *rest: Any, **kw: Any) -> Any:
            raw, file_id = counted_read(path, *rest, **kw)
            return raw[:-1], file_id  # fewer bytes than the stat: a partner still writing

        monkeypatch.setattr(file_mod, "_read_confined", short_read)
    with caplog.at_level(logging.INFO, logger="messagefoundry.transports.file"):
        await source._scan_once()

    assert len(reads) == 2, f"the {arm} scan read only the ceiling of files it left in place"
    assert "reached poll_max_files (2) this scan in files read and left in place" in caplog.text


async def test_a_reject_archived_but_not_removed_still_spends_the_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``_move`` also answers True when it archived a copy and could not remove the original, which
    stays in the drop directory. It still charges: otherwise every later scan would write another copy
    into ``.error`` with nothing bounding how many a tick writes. Mutation: charge only once the file
    is gone. Red: the healthy drop goes in the same scan."""
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
    assert handed_off == [], "the budget of one was spent on the archived copy"


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
