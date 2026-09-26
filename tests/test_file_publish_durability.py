# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The FILE destination makes a delivered file durable before it publishes it (BACKLOG #1618).

The delivery worker marks an outbox row delivered, durably, the moment ``send()`` returns. The
file's bytes used to be written, closed and renamed with no flush, so they could still be in the
page cache at that moment: a power loss then would leave an empty file at the final name with the
store saying delivered, and nothing would ever re-deliver it. These tests pin the flush on every
publish path, and on POSIX the directory flush that makes the new NAME durable as well.

Deliberately ASCII-only: pytest echoes a failing body to a cp1252 console on Windows.
"""

from __future__ import annotations

import errno
import logging
import os
import stat
from pathlib import Path

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.transports import file as file_mod
from messagefoundry.transports.base import DeliveryError
from messagefoundry.transports.file import FileDestination, _claim_unique

_PAYLOAD = "MSH|^~\\&|SND|FAC|RCV|FAC|20260101120000||ADT^A01|CTL1618|P|2.5.1\rPID|1||12345\r"


def _destination(directory: Path, **settings: object) -> FileDestination:
    return FileDestination(
        Destination(
            name="archive",
            type=ConnectorType.FILE,
            settings={"directory": str(directory), "filename": "out.hl7", **settings},
        )
    )


def _is_dir_fd(fd: int) -> bool:
    return stat.S_ISDIR(os.fstat(fd).st_mode)


@pytest.mark.parametrize("overwrite", [False, True], ids=["claim", "replace"])
async def test_the_file_is_flushed_before_its_final_name_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, overwrite: bool
) -> None:
    """Both publish paths: the claim (``os.link``) and the ``overwrite=True`` replace.

    The spy records, for every FILE fsync, whether the final name already existed. A flush that
    lands only after the publish would leave the same window open, so it must not count.

    Mutation: drop the ``handle.flush(); os.fsync(...)`` pair in ``_write``. Red: no file fsync
    happens at all (measured on the pre-fix code: zero calls on both paths)."""
    final = tmp_path / "out.hl7"
    before_publish: list[bool] = []
    real_fsync = os.fsync

    def spy(fd: int) -> None:
        if not _is_dir_fd(fd):
            before_publish.append(not final.exists())
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", spy)

    await _destination(tmp_path, overwrite=overwrite).send(_PAYLOAD)

    assert final.read_bytes() == _PAYLOAD.encode("utf-8")
    assert before_publish, "the delivered file was never fsync'd"
    assert before_publish[0], "the first file fsync ran after the final name was already published"


def test_the_copy_fallback_flushes_the_copy_it_publishes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Where hard links are unavailable, ``_claim_unique`` publishes a COPY. The flush given to the
    delivery temp does not cover a new file, so the copy needs its own.

    Mutation: drop the flush in ``_claim_unique``'s copy arm. Red: zero fsync calls."""

    def _no_hard_links(*_a: object, **_k: object) -> None:
        raise OSError("hard links unsupported on this filesystem")

    calls: list[int] = []
    real_fsync = os.fsync

    def spy(fd: int) -> None:
        if not _is_dir_fd(fd):
            calls.append(fd)
        real_fsync(fd)

    monkeypatch.setattr(os, "link", _no_hard_links)
    monkeypatch.setattr(os, "fsync", spy)
    source = tmp_path / "src.part"
    source.write_bytes(b"PAYLOAD")

    claimed = _claim_unique(source, tmp_path / "out.hl7")

    assert claimed.read_bytes() == b"PAYLOAD"
    assert calls, "the copied file was published without an fsync"


@pytest.mark.skipif(os.name != "posix", reason="a directory fsync exists only on POSIX")
async def test_the_directory_is_flushed_after_the_publish_on_posix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """POSIX makes a new directory entry durable only once the directory itself is fsync'd.

    Mutation: drop ``self._fsync_directory()`` from ``_write``. Red: no directory fsync."""
    final = tmp_path / "out.hl7"
    dir_flushes_after_publish: list[bool] = []
    real_fsync = os.fsync

    def spy(fd: int) -> None:
        if _is_dir_fd(fd):
            dir_flushes_after_publish.append(final.exists())
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", spy)

    await _destination(tmp_path).send(_PAYLOAD)

    assert dir_flushes_after_publish == [True]


@pytest.mark.skipif(os.name != "posix", reason="a directory fsync exists only on POSIX")
async def test_a_refused_directory_flush_is_logged_once_and_never_fails_the_delivery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Some network filesystems refuse a directory fsync. The file is published by then, so raising
    would make the worker retry and publish a duplicate. It is logged once per destination instead.

    Mutation: let the ``OSError`` propagate. Red: ``send`` raises and the second delivery never runs."""
    real_fsync = os.fsync

    def refuse_dirs(fd: int) -> None:
        if _is_dir_fd(fd):
            raise OSError(22, "Invalid argument")
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", refuse_dirs)
    destination = _destination(tmp_path)

    with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.file"):
        await destination.send(_PAYLOAD)
        await destination.send(_PAYLOAD)

    assert sorted(p.name for p in tmp_path.iterdir()) == ["out-1.hl7", "out.hl7"]
    warnings = [r for r in caplog.records if "could not be fsync'd" in r.getMessage()]
    assert len(warnings) == 1


@pytest.mark.skipif(os.name != "posix", reason="a directory fsync exists only on POSIX")
async def test_a_transient_directory_flush_failure_is_retried_on_the_next_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Only an UNSUPPORTED directory fsync is remembered. A transient one (EIO) must not switch the
    flush off for the life of the process.

    Mutation: latch on any OSError. Red: the second publish logs no second warning."""
    real_fsync = os.fsync

    def eio_on_dirs(fd: int) -> None:
        if _is_dir_fd(fd):
            raise OSError(5, "Input/output error")
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", eio_on_dirs)
    destination = _destination(tmp_path)

    with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.file"):
        await destination.send(_PAYLOAD)
        await destination.send(_PAYLOAD)

    warnings = [r for r in caplog.records if "could not be fsync'd" in r.getMessage()]
    assert len(warnings) == 2


async def test_a_filesystem_without_fsync_still_delivers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Some FUSE, WebDAV and network mounts answer fsync with EINVAL or ENOTSUP. Deliveries worked
    there before the flush existed, so an unsupported flush is logged once, not raised: raising
    would fail the lane forever.

    Mutation: let every fsync OSError propagate. Red: ``send`` raises ``DeliveryError``."""
    monkeypatch.setattr(file_mod, "_fsync_unsupported_dirs", set())

    def unsupported(_fd: int) -> None:
        raise OSError(errno.EINVAL, "Invalid argument")

    monkeypatch.setattr(os, "fsync", unsupported)
    destination = _destination(tmp_path)

    with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.file"):
        await destination.send(_PAYLOAD)
        await destination.send(_PAYLOAD)

    assert sorted(p.name for p in tmp_path.iterdir()) == ["out-1.hl7", "out.hl7"]
    notes = [r for r in caplog.records if "does not support fsync" in r.getMessage()]
    assert len(notes) == 1


async def test_a_failed_flush_still_fails_the_delivery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """EIO means the bytes are not known to be on disk, so the delivery fails and is retried, and
    nothing is published.

    Mutation: treat every fsync OSError as unsupported. Red: the file is published."""

    def eio(_fd: int) -> None:
        raise OSError(errno.EIO, "Input/output error")

    monkeypatch.setattr(os, "fsync", eio)

    with pytest.raises(DeliveryError):
        await _destination(tmp_path).send(_PAYLOAD)

    assert list(tmp_path.iterdir()) == []
