# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The FILE source's remaining raw log sites are scrubbed (BACKLOG #1625).

The eight name-logging sites and the handler-failure arm were fixed under BACKLOG #1748, which
added ``safe_name`` and the ``file_name`` argument to ``safe_exc``. Three sites were left: the claim
cleanup, which logged a placeholder's full path and the raw ``OSError`` (on the archive move that
path carries the partner's own file name); the directory-listing failure, which logged the raw
``OSError`` (under ``recursive`` its path can be a partner-created subdirectory); and the poll
loop's last-resort arm, which logged a full traceback at ERROR where MLLP's scrubs.

Deliberately ASCII-only: pytest echoes a failing body to a cp1252 console on Windows.
"""

from __future__ import annotations

import asyncio
import errno
import logging
import os
import shutil
from pathlib import Path
from typing import BinaryIO

import pytest

from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.transports import file as file_mod
from messagefoundry.transports.file import FileSource, _claim_unique

_MRN = "MRN123456789"
_LOGGER = "messagefoundry.transports.file"


def _no_hard_links(*_a: object, **_k: object) -> None:
    raise OSError("hard links unsupported on this filesystem")


def test_a_failed_claim_cleanup_logs_no_partner_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The archive move claims ``processed/<partner name>``. When the publish over the placeholder
    fails and the placeholder cannot be removed either, the WARNING names neither the file nor the
    path the ``OSError`` carries.

    Mutation: log ``path`` and ``exc`` raw in ``_discard``. Red: the MRN is in the log."""
    source = tmp_path / "in" / f"{_MRN}_ADT.hl7"
    source.parent.mkdir()
    source.write_bytes(b"PAYLOAD")
    processed = tmp_path / "processed"
    processed.mkdir()

    def replace_fails(*_a: object, **_k: object) -> None:
        raise OSError(errno.EIO, "I/O error")

    def unlink_denied(self: Path, **_k: object) -> None:
        raise PermissionError(errno.EACCES, "another process has the file open", str(self))

    monkeypatch.setattr(os, "link", _no_hard_links)
    monkeypatch.setattr(os, "replace", replace_fails)
    monkeypatch.setattr(Path, "unlink", unlink_denied)
    monkeypatch.setattr(file_mod, "_RENAME_REFUSES_OVERWRITE", False)

    with caplog.at_level(logging.WARNING, logger=_LOGGER), pytest.raises(OSError, match="I/O"):
        _claim_unique(source, processed / source.name)

    cleanup = [r.getMessage() for r in caplog.records if "failed claim" in r.getMessage()]
    assert cleanup, "the cleanup failure must still be logged"
    assert not any(_MRN in line for line in cleanup), cleanup


async def test_a_listing_failure_logs_no_partner_subdirectory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Mutation: log the raw ``OSError`` in ``_candidates``. Red: the subdirectory name is logged."""
    inbox = tmp_path / "in"
    inbox.mkdir()
    source = FileSource(
        Source(type=ConnectorType.FILE, settings={"directory": str(inbox), "recursive": True})
    )
    denied = str(inbox / f"{_MRN}_drops")

    def rglob_denied(self: Path, _pattern: str) -> list[Path]:
        raise PermissionError(errno.EACCES, "Permission denied", denied)

    monkeypatch.setattr(Path, "rglob", rglob_denied)

    with caplog.at_level(logging.WARNING, logger=_LOGGER):
        assert source._candidates() == []

    lines = [r.getMessage() for r in caplog.records if "could not list" in r.getMessage()]
    assert lines and "Permission denied" in lines[0], lines
    assert _MRN not in lines[0], lines


async def test_a_scan_failure_logs_no_traceback_at_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The poll loop's last-resort arm logs a scrubbed one-liner at ERROR, as MLLP's does; the
    traceback goes to DEBUG only.

    Mutation: restore ``logger.exception``. Red: the ERROR record carries ``exc_info``."""
    inbox = tmp_path / "in"
    inbox.mkdir()
    source = FileSource(
        Source(type=ConnectorType.FILE, settings={"directory": str(inbox), "poll_seconds": 0.05})
    )
    failed = asyncio.Event()

    async def scan_fails() -> None:
        failed.set()
        raise RuntimeError("scan blew up")

    monkeypatch.setattr(source, "_scan_once", scan_fails)

    async def handler(_raw: bytes) -> str | None:
        return None

    with caplog.at_level(logging.WARNING, logger=_LOGGER):
        await source.start(handler)
        await asyncio.wait_for(failed.wait(), 5)
        await source.stop()

    errors = [r for r in caplog.records if "scan failed" in r.getMessage()]
    assert errors, "the scan failure must still be logged"
    assert all(r.exc_info is None for r in errors), "a traceback was logged at ERROR"
    assert "RuntimeError" in errors[0].getMessage()
    assert "file.py:" in errors[0].getMessage(), "the raising site is not named"


def test_a_failed_archive_claim_on_a_bumped_name_logs_no_partner_name(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Partners resend names, so the archive claim often lands on ``name-1.ext``. ``safe_exc``
    swaps only the exact basename, so an ``OSError`` carrying the bumped name used to be logged in
    the clear.

    Mutation: log the claim failure with ``safe_exc(exc, file_name=path.name)``. Red: the bumped
    name, MRN included, is in the log."""
    inbox = tmp_path / "in"
    inbox.mkdir()
    dropped = inbox / f"{_MRN}_ADT.hl7"
    dropped.write_bytes(b"PAYLOAD")
    bumped = str(tmp_path / "processed" / f"{_MRN}_ADT-1.hl7")

    def claim_fails(_tmp: Path, _target: Path) -> Path:
        raise PermissionError(errno.EACCES, "Permission denied", "tmpab12.part", None, bumped)

    monkeypatch.setattr(file_mod, "_claim_unique", claim_fails)

    with caplog.at_level(logging.WARNING, logger=_LOGGER):
        assert FileSource._move(dropped, tmp_path / "processed") is False

    lines = [r.getMessage() for r in caplog.records if "could not move" in r.getMessage()]
    assert lines and "Permission denied" in lines[0], lines
    assert _MRN not in lines[0], lines


def test_a_staged_copy_that_vanished_is_reported_not_taken_as_removed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """On Windows a dropped UNC share surfaces as FileNotFoundError, and the full copy is still there
    when the share returns. Cleanup must say so rather than treat it as already gone.

    Mutation: ``unlink(missing_ok=True)`` in ``_discard``. Red: no warning."""
    source = tmp_path / "src.bin"
    source.write_bytes(b"PAYLOAD")
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    def die_mid_copy(_src: object, dst: BinaryIO, *_a: object, **_k: object) -> None:
        dst.write(b"TRUNC")
        raise OSError(errno.ENOSPC, "No space left on device")

    def share_gone(self: Path, **_k: object) -> None:
        raise FileNotFoundError(errno.ENOENT, "The network path was not found", str(self))

    monkeypatch.setattr(os, "link", _no_hard_links)
    monkeypatch.setattr(shutil, "copyfileobj", die_mid_copy)
    monkeypatch.setattr(Path, "unlink", share_gone)

    with caplog.at_level(logging.WARNING, logger=_LOGGER), pytest.raises(OSError, match="space"):
        _claim_unique(source, out_dir / "out.hl7")

    assert any("failed claim" in r.getMessage() for r in caplog.records)
