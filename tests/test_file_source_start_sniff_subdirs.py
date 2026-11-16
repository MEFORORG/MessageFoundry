# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""FileSource start, content sniff, archive subdirectories and leave ledger order.

* BACKLOG #5683: no blocking filesystem work on the event loop at build or start.
* BACKLOG #5684: a UTF-16 or UTF-32 drop is sniffed through its configured encoding.
* BACKLOG #5682: an archive subdirectory naming the watch directory, or one above it, is refused, and
  an unnormalised one is normalised.
* BACKLOG #5685: leave mode writes the durable ledger before the in-memory seen cache.

Synthetic HL7 only. Deliberately ASCII-only: pytest echoes a failing body to a cp1252 console.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, ContentType, Source
from messagefoundry.transports.file import FileSource

_HL7 = "MSH|^~\\&|SND|FAC|RCV|FAC|20260101120000||ADT^A01|CTL5684|P|2.5.1\rPID|1||12345\r"


def _source(directory: Path, **settings: Any) -> FileSource:
    return FileSource(
        Source(type=ConnectorType.FILE, settings={"directory": str(directory), **settings})
    )


class _Recorder:
    def __init__(self) -> None:
        self.bodies: list[bytes] = []

    async def __call__(self, raw: bytes) -> str | None:
        self.bodies.append(raw)
        return None


# --- BACKLOG #5683 -----------------------------------------------------------------------------


def test_constructor_does_not_resolve_the_watch_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Red on the unfixed code: the constructor called ``Path.resolve`` on the event loop."""
    calls: list[Path] = []
    real_resolve = Path.resolve

    def spy(self: Path, strict: bool = False) -> Path:
        calls.append(self)
        return real_resolve(self, strict=strict)

    monkeypatch.setattr(Path, "resolve", spy)
    src = _source(tmp_path)
    assert calls == [], "the constructor must not touch the filesystem"
    # The confinement root still resolves, on first use.
    assert src._root_real == real_resolve(tmp_path)
    assert len(calls) == 1
    assert src._root_real == real_resolve(tmp_path)
    assert len(calls) == 1, "resolved once, then cached"


async def test_start_prepares_subdirs_off_the_event_loop(tmp_path: Path) -> None:
    """Red on the unfixed code: with no credential, start ran ``_prepare_subdirs`` inline."""
    src = _source(tmp_path)
    loop_thread = threading.get_ident()
    seen: list[int] = []
    real_prepare = src._prepare_subdirs

    def spy() -> None:
        seen.append(threading.get_ident())
        real_prepare()

    src._prepare_subdirs = spy  # type: ignore[method-assign]
    await src.start(_Recorder())
    try:
        assert len(seen) == 1
        assert seen[0] != loop_thread, "the subdirs must be prepared off the event loop"
        assert (tmp_path / ".processed").is_dir()
        assert (tmp_path / ".error").is_dir()
    finally:
        await src.stop()


# --- BACKLOG #5684 -----------------------------------------------------------------------------


async def _scan_twice(src: FileSource) -> None:
    await src._scan_once()  # the settle poll (BACKLOG #1811)
    await src._scan_once()


@pytest.mark.parametrize("encoding", ["utf-16", "utf-16-le", "utf-32", "utf-8-sig", "utf-8"])
async def test_a_utf16_or_utf32_hl7_drop_is_not_quarantined(tmp_path: Path, encoding: str) -> None:
    """Red on the unfixed code for utf-16, utf-16-le and utf-32: the raw bytes lead with a BOM or
    NULs, so the raw sniff quarantined the drop. utf-8 and utf-8-sig are the controls."""
    (tmp_path / "a.hl7").write_bytes(_HL7.encode(encoding))
    src = _source(tmp_path, encoding=encoding)
    rec = _Recorder()
    src._handler = rec
    src._prepare_subdirs()
    await _scan_twice(src)
    assert not (tmp_path / ".error" / "a.hl7").exists(), "a legitimate drop was quarantined"
    assert len(rec.bodies) == 1


@pytest.mark.parametrize("encoding", ["utf-16", "utf-32"])
async def test_a_utf16_json_drop_is_not_quarantined(tmp_path: Path, encoding: str) -> None:
    (tmp_path / "a.json").write_bytes('  {"k": 1}'.encode(encoding))
    src = _source(tmp_path, encoding=encoding)
    src.content_type = ContentType.JSON
    rec = _Recorder()
    src._handler = rec
    src._prepare_subdirs()
    await _scan_twice(src)
    assert not (tmp_path / ".error" / "a.json").exists()
    assert len(rec.bodies) == 1


async def test_a_mismatched_utf16_drop_is_still_quarantined(tmp_path: Path) -> None:
    """The control: decoding the head does not admit content that contradicts the declared type."""
    (tmp_path / "a.hl7").write_bytes("%PDF-1.7 not an HL7 message".encode("utf-16"))
    src = _source(tmp_path, encoding="utf-16")
    rec = _Recorder()
    src._handler = rec
    src._prepare_subdirs()
    await _scan_twice(src)
    assert (tmp_path / ".error" / "a.hl7").exists()
    assert rec.bodies == []


async def test_a_utf16_drop_on_a_utf8_inbound_is_still_quarantined(tmp_path: Path) -> None:
    """The head is decoded with the CONFIGURED encoding, not guessed from the bytes."""
    (tmp_path / "a.hl7").write_bytes(_HL7.encode("utf-16"))
    src = _source(tmp_path)
    rec = _Recorder()
    src._handler = rec
    src._prepare_subdirs()
    await _scan_twice(src)
    assert (tmp_path / ".error" / "a.hl7").exists()
    assert rec.bodies == []


# --- BACKLOG #5682 -----------------------------------------------------------------------------


@pytest.mark.parametrize("knob", ["processed_subdir", "error_subdir"])
@pytest.mark.parametrize("value", ["", "   ", ".", "./", "..", "a/..", "a/../..", "../.."])
def test_an_archive_subdir_at_or_above_the_watch_directory_is_refused(
    tmp_path: Path, knob: str, value: str
) -> None:
    """Red on the unfixed code: each was accepted, and every drop would then be skipped."""
    with pytest.raises(ValueError, match=knob):
        _source(tmp_path / "in", **{knob: value})


@pytest.mark.parametrize("knob", ["processed_subdir", "error_subdir"])
def test_an_absolute_archive_subdir_at_or_above_the_watch_directory_is_refused(
    tmp_path: Path, knob: str
) -> None:
    inbox = tmp_path / "in"
    for value in (str(inbox), str(tmp_path), str(inbox / "x" / "..")):
        with pytest.raises(ValueError, match=knob):
            _source(inbox, **{knob: value})


def test_a_non_string_archive_subdir_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="processed_subdir"):
        _source(tmp_path, processed_subdir=3)


def test_an_unnormalised_archive_subdir_is_normalised(tmp_path: Path) -> None:
    inbox = tmp_path / "in"
    src = _source(inbox, processed_subdir="./done/../arch", error_subdir="err/")
    assert src.processed_dir == inbox / "arch"
    assert src.error_dir == inbox / "err"
    # An absolute path inside the watch tree is spelled from the watch directory, as listings are.
    src = _source(inbox, processed_subdir=str(inbox / "x" / ".." / "arch"))
    assert src.processed_dir == inbox / "arch"
    # Outside the watch tree, absolute or relative, stays allowed.
    outside = tmp_path / "archive"
    assert _source(inbox, processed_subdir=str(outside)).processed_dir == outside
    assert _source(inbox, processed_subdir="../archive").processed_dir == inbox / ".." / "archive"


async def test_files_moved_to_an_unnormalised_subdir_are_not_ingested_again(
    tmp_path: Path,
) -> None:
    """Red on the unfixed code: under a recursive scan, ``x/../arch`` never compared equal to a listed
    parent, so each archived file was listed and handed off again."""
    (tmp_path / "a.hl7").write_bytes(_HL7.encode())
    src = _source(tmp_path, recursive=True, processed_subdir="x/../arch")
    rec = _Recorder()
    src._handler = rec
    src._prepare_subdirs()
    for _ in range(4):
        await src._scan_once()
    assert (tmp_path / "arch" / "a.hl7").exists()
    assert len(rec.bodies) == 1, "an archived file was ingested again"


def test_guarded_dirs_follows_the_normalised_error_dir(tmp_path: Path) -> None:
    config = Source(
        type=ConnectorType.FILE,
        settings={"directory": str(tmp_path), "error_subdir": "./err/"},
    )
    assert FileSource.guarded_dirs(config) == (tmp_path, tmp_path / "err")


# --- BACKLOG #5685 (local source) ----------------------------------------------------------------


class _FailingLedger:
    def __init__(self) -> None:
        self.keys: set[str] = set()
        self.fail = True

    async def is_processed(self, file_key: str) -> bool:
        return file_key in self.keys

    async def mark_processed(self, file_key: str) -> None:
        if self.fail:
            raise OSError("synthetic ledger write failure")
        self.keys.add(file_key)

    async def prune(self) -> None:
        return None


async def test_a_failed_leave_ledger_write_leaves_no_cached_key(tmp_path: Path) -> None:
    """Red on the unfixed code: the key was cached before the write, so it stayed cached."""
    src = _source(tmp_path, after_read="leave")
    ledger = _FailingLedger()
    src.processed_ledger = ledger
    with pytest.raises(OSError):
        await src._leave_record("fk1:" + "0" * 64)
    assert "fk1:" + "0" * 64 not in src._processed_seen
    ledger.fail = False
    await src._leave_record("fk1:" + "0" * 64)
    assert ledger.keys == {"fk1:" + "0" * 64}
    assert "fk1:" + "0" * 64 in src._processed_seen
