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

import os
import sys
import threading
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, ContentType, Source
from messagefoundry.transports.base import SourceStartupError
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


async def test_a_bomless_drop_on_a_utf16_inbound_never_aborts_the_scan(tmp_path: Path) -> None:
    """An incremental utf-16 decoder raises on a stream with no BOM. The sniff must not: a plain
    ASCII PDF on a utf-16 inbound is quarantined, and the scan goes on to the next file."""
    (tmp_path / "a.hl7").write_bytes(b"%PDF-1.7 not an HL7 message")
    (tmp_path / "b.hl7").write_bytes(_HL7.encode("utf-16"))
    src = _source(tmp_path, encoding="utf-16")
    rec = _Recorder()
    src._handler = rec
    src._prepare_subdirs()
    await _scan_twice(src)
    assert (tmp_path / ".error" / "a.hl7").exists()
    assert len(rec.bodies) == 1


def test_the_decoded_sniff_reads_a_bounded_head(monkeypatch: pytest.MonkeyPatch) -> None:
    """It runs on the event loop, so however much leading whitespace a drop carries, it decodes at
    most _SNIFF_DECODE_MAX bytes; MSH past that bound is not found."""
    from messagefoundry.transports import file as file_mod

    monkeypatch.setattr(file_mod, "_SNIFF_DECODE_MAX", 64)
    near = (" " * 10 + "MSH|").encode("utf-16-le")
    far = (" " * 100 + "MSH|").encode("utf-16-le")
    assert file_mod._content_matches_encoded(ContentType.HL7V2, near, "utf-16-le")
    assert not file_mod._content_matches_encoded(ContentType.HL7V2, far, "utf-16-le")


def test_the_decoded_sniff_gives_utf16_the_utf8_verdict() -> None:
    """The decoded head is spelled as UTF-8 again, so the sniff strips the same leading noise from
    it as from a UTF-8 file: a form feed before MSH is refused on both encodings."""
    from messagefoundry.transports import file as file_mod

    text = "\x0c" + _HL7
    assert not file_mod._content_matches_encoded(ContentType.HL7V2, text.encode("utf-8"), "utf-8")
    assert not file_mod._content_matches_encoded(ContentType.HL7V2, text.encode("utf-16"), "utf-16")


def test_a_lone_surrogate_in_the_decoded_head_never_raises() -> None:
    """utf-7 decodes ``+2AA-`` to a lone surrogate, which a strict UTF-8 encode refuses; the sniff
    must answer no match rather than raise out of the scan."""
    from messagefoundry.transports import file as file_mod

    assert not file_mod._content_matches_encoded(ContentType.HL7V2, b"+2AA-MSH|", "utf-7")


async def test_an_ascii_encoding_admits_only_what_the_raw_sniff_admits(tmp_path: Path) -> None:
    """A form feed before MSH fails the raw HL7 sniff. The decoded head would strip it, so on a
    utf-8 inbound the decoded sniff must not run and the drop stays quarantined as before."""
    (tmp_path / "a.hl7").write_bytes(b"\x0c" + _HL7.encode())
    src = _source(tmp_path)
    rec = _Recorder()
    src._handler = rec
    src._prepare_subdirs()
    await _scan_twice(src)
    assert (tmp_path / ".error" / "a.hl7").exists()
    assert rec.bodies == []


# --- BACKLOG #5682 -----------------------------------------------------------------------------


@pytest.mark.parametrize("knob", ["processed_subdir", "error_subdir"])
@pytest.mark.parametrize(
    "value", ["", "   ", ".", "./", "..", "a/..", "a/../..", "../..", "../in", "x/../../in"]
)
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


def test_a_pathlike_archive_subdir_is_accepted_and_checked(tmp_path: Path) -> None:
    """Red on c0df8be6c2: a ``pathlib.Path`` setting was refused; on main it was joined. Its
    ``os.fspath`` now takes the same checks as a string."""
    inbox = tmp_path / "in"
    src = _source(inbox, processed_subdir=Path("done"), error_subdir=Path("err/../bad"))
    assert src.processed_dir == inbox / "done"
    assert src.error_dir == inbox / "bad"
    for value in (Path(".."), inbox):
        with pytest.raises(ValueError, match="processed_subdir"):
            _source(inbox, processed_subdir=value)


def test_a_pathlike_that_names_no_path_is_refused_as_a_setting(tmp_path: Path) -> None:
    """``os.fspath`` raises TypeError for an ``__fspath__`` that returns neither str nor bytes; the
    build reports it as the setting refusal, not as a TypeError."""

    class NotAPath:
        def __fspath__(self) -> Any:
            return 3

    with pytest.raises(ValueError, match="processed_subdir"):
        _source(tmp_path / "in", processed_subdir=NotAPath())


def test_an_unnormalised_archive_subdir_is_normalised(tmp_path: Path) -> None:
    inbox = tmp_path / "in"
    src = _source(inbox, processed_subdir="./done/../arch", error_subdir="err/")
    assert src.processed_dir == inbox / "arch"
    assert src.error_dir == inbox / "err"
    # An absolute path inside the watch tree is spelled from the watch directory, as listings are.
    src = _source(inbox, processed_subdir=str(inbox / "x" / ".." / "arch"))
    assert src.processed_dir == inbox / "arch"
    # A relative value that climbs out and back in is spelled from the watch directory too.
    assert _source(inbox, processed_subdir="../in/arch").processed_dir == inbox / "arch"
    # Outside the watch tree, absolute or relative, stays allowed, normalised.
    outside = tmp_path / "archive"
    assert _source(inbox, processed_subdir=str(outside)).processed_dir == outside
    assert _source(inbox, processed_subdir="../archive").processed_dir == outside


@pytest.mark.skipif(sys.platform != "win32", reason="Windows path forms")
@pytest.mark.parametrize(
    "value", ["\\", "/", "\\Users", "C:", "Z:", "Z:arch", "arch.", "arch ", "a./b"]
)
def test_windows_root_drive_and_trailing_dot_values_are_refused(tmp_path: Path, value: str) -> None:
    """A root-relative or drive-relative value is not absolute on Windows and names the drive root,
    an ancestor or the watch directory; a trailing dot or space is stripped by Win32 at creation, so
    the listed parent never matches. Each is refused."""
    inbox = tmp_path / "in"
    if value == "\\Users" and Path(f"{tmp_path.drive}\\Users") not in inbox.parents:
        pytest.skip("the temp directory is not under \\Users here")
    with pytest.raises(ValueError, match="processed_subdir"):
        _source(inbox, processed_subdir=value)


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
        self.pruned = 0

    async def is_processed(self, file_key: str) -> bool:
        return file_key in self.keys

    async def mark_processed(self, file_key: str) -> None:
        if self.fail:
            raise OSError("synthetic ledger write failure")
        self.keys.add(file_key)

    async def prune(self) -> None:
        self.pruned += 1


async def test_a_persistently_failing_leave_ledger_hands_each_file_over_once(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Red on 896db80ea9: the key was cached only after a successful write and the failure escaped,
    so every scan aborted at the first file and handed it over again, and the second file was never
    reached. Now the failure is logged, the key cached, and the scan goes on (BACKLOG #5685)."""
    (tmp_path / "a.hl7").write_bytes(_HL7.encode())
    (tmp_path / "b.hl7").write_bytes(_HL7.replace("CTL5684", "CTL5685").encode())
    src = _source(tmp_path, after_read="leave")
    ledger = _FailingLedger()
    src.processed_ledger = ledger
    rec = _Recorder()
    src._handler = rec
    src._prepare_subdirs()
    for _ in range(4):
        await src._scan_once()
    assert len(rec.bodies) == 2, "each drop handed over exactly once in this process"
    assert ledger.keys == set()
    assert ledger.pruned == 0, "a failed write is not counted as recorded, so it draws no prune"
    assert "processed-ledger write failed (OSError)" in caplog.text
    assert "CTL568" not in caplog.text, "no body in the log"


async def test_a_refused_ledger_key_hands_each_file_over_once(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Red on c0df8be6c2: a key that passes the ledger's read check but that its write refuses
    (``FileKeyError``) escaped before the key was cached, so the first file was handed over again on
    every scan and the second was never reached. On main the key was cached first; now the refusal
    is logged by type, the key cached, and the scan goes on."""
    from messagefoundry.transports.base import FileKeyError

    (tmp_path / "a.hl7").write_bytes(_HL7.encode())
    (tmp_path / "b.hl7").write_bytes(_HL7.replace("CTL5684", "CTL5685").encode())
    src = _source(tmp_path, after_read="leave")

    class _Ledger(_FailingLedger):
        async def mark_processed(self, file_key: str) -> None:
            raise FileKeyError("synthetic")

    src.processed_ledger = _Ledger()
    rec = _Recorder()
    src._handler = rec
    src._prepare_subdirs()
    for _ in range(4):
        await src._scan_once()
    assert len(rec.bodies) == 2, "each drop handed over exactly once in this process"
    assert "processed-ledger write failed (FileKeyError)" in caplog.text
    assert "CTL568" not in caplog.text, "no body in the log"


async def test_a_successful_leave_ledger_write_comes_before_the_cache(tmp_path: Path) -> None:
    src = _source(tmp_path, after_read="leave")
    seen_when_written: list[bool] = []

    class _Ledger(_FailingLedger):
        async def mark_processed(self, file_key: str) -> None:
            seen_when_written.append(file_key in src._processed_seen)
            self.keys.add(file_key)

    src.processed_ledger = _Ledger()
    await src._leave_record("fk1:" + "0" * 64)
    assert seen_when_written == [False]
    assert "fk1:" + "0" * 64 in src._processed_seen


# --- BACKLOG #5682: the identity limb ------------------------------------------------------------


def _link_dir(target: Path, link: Path) -> None:
    """A directory link at ``link``: a junction on Windows, which needs no privilege, else a symlink."""
    if sys.platform == "win32":
        import _winapi

        _winapi.CreateJunction(str(target), str(link))
    else:
        os.symlink(target, link, target_is_directory=True)


@pytest.mark.parametrize(
    ("after_read", "knob"),
    [
        ("move", "processed_subdir"),
        ("move", "error_subdir"),
        ("delete", "error_subdir"),
        ("leave", "error_subdir"),
    ],
)
@pytest.mark.parametrize("below", ["", "done"], ids=["the-watch-dir", "inside-it"])
def test_an_archive_subdir_reaching_the_watch_tree_through_a_link_is_refused_at_start(
    tmp_path: Path, knob: str, below: str, after_read: str
) -> None:
    """Red on the unfixed code: a value spelled outside the watch directory that reaches it, or a
    directory inside it, through a link or a junction passed, and archived files would be listed
    and ingested again on every poll. Refused before it is created, so nothing is made inside the
    watch tree."""
    inbox = tmp_path / "in"
    inbox.mkdir()
    alias = tmp_path / "alias"
    _link_dir(inbox, alias)
    value = str(alias / below) if below else str(alias)
    src = _source(inbox, after_read=after_read, **{knob: value})
    with pytest.raises(SourceStartupError, match=knob) as caught:
        src._prepare_subdirs()
    assert "alias" not in str(caught.value)
    assert not (inbox / "done").exists()


@pytest.mark.parametrize("after_read", ["leave", "delete"])
def test_a_processed_subdir_through_a_link_is_not_judged_where_nothing_is_archived(
    tmp_path: Path, after_read: str
) -> None:
    # Only the move mode writes processed_dir, so in the others it is not judged.
    inbox = tmp_path / "in"
    inbox.mkdir()
    alias = tmp_path / "alias"
    _link_dir(inbox, alias)
    src = _source(inbox, after_read=after_read, processed_subdir=str(alias / "done"))
    src._prepare_subdirs()


def test_a_watch_directory_with_no_file_identity_skips_the_check_and_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """An inode of 0 on every directory (some SMB servers) would make every archive directory on
    the volume match, so the check does not run, and a WARNING says it did not."""
    from messagefoundry.transports import file as file_module

    inbox = tmp_path / "in"
    inbox.mkdir()
    archive = tmp_path / "archive"
    archive.mkdir()
    real_stat = os.stat

    def no_identity(path: Any, *args: Any, **kwargs: Any) -> Any:
        st = real_stat(path, *args, **kwargs)
        return os.stat_result((st.st_mode, 0, *tuple(st)[2:]))

    monkeypatch.setattr(os, "stat", no_identity)
    with caplog.at_level("WARNING", logger="messagefoundry.transports.file"):
        assert not file_module._inside_watch_tree_by_identity(archive, inbox)
    assert "reports no file identity" in caplog.text


def test_an_archive_path_with_no_readable_part_skips_the_check_and_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Red before: on Windows an unreachable UNC share reports ENOENT for every part of the path,
    its root included, so nothing was compared and the check returned False with no word. It now
    logs a WARNING naming the path's class, and not the archive path's text."""
    from messagefoundry.transports import file as file_module

    inbox = tmp_path / "in"
    inbox.mkdir()
    archive = tmp_path / "unreachable-share" / "archive"
    real_stat = os.stat

    def unreachable(path: Any, *args: Any, **kwargs: Any) -> Any:
        if os.fspath(path) == os.fspath(inbox):
            return real_stat(path, *args, **kwargs)
        raise FileNotFoundError(2, "The network path was not found")

    monkeypatch.setattr(os, "stat", unreachable)
    with caplog.at_level("WARNING", logger="messagefoundry.transports.file"):
        assert not file_module._inside_watch_tree_by_identity(archive, inbox, "error_subdir")
    path_class = "drive" if sys.platform == "win32" else "local"
    assert f"the error_subdir identity check gave no verdict: no part of its {path_class} path" in (
        caplog.text
    )
    assert "unreachable-share" not in caplog.text


def test_a_share_fault_reported_as_enoent_is_logged_not_read_as_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """ERROR_BAD_NETPATH (53) maps to FileNotFoundError, as at a DFS link whose target server is
    down while the namespace root reads. It is a share fault, so it is logged, not skipped as a
    directory still to be created."""
    from messagefoundry.transports import file as file_module

    inbox = tmp_path / "in"
    inbox.mkdir()
    link = tmp_path / "dfs-link"
    archive = link / "archive"
    real_stat = os.stat

    def bad_netpath(path: Any, *args: Any, **kwargs: Any) -> Any:
        if os.fspath(path) in (os.fspath(archive), os.fspath(link)):
            exc = FileNotFoundError(2, "The network path was not found")
            exc.winerror = 53  # type: ignore[attr-defined]
            raise exc
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(os, "stat", bad_netpath)
    monkeypatch.setattr(os.path, "realpath", lambda p, *a, **k: os.fspath(p))
    with caplog.at_level("WARNING", logger="messagefoundry.transports.file"):
        assert not file_module._inside_watch_tree_by_identity(archive, inbox)
    assert caplog.text.count("could not be read for the identity check") == 2


def test_an_archive_path_with_no_file_identity_is_no_verdict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # An archive volume that reports inode 0 everywhere gives nothing to compare.
    from messagefoundry.transports import file as file_module

    inbox = tmp_path / "in"
    inbox.mkdir()
    archive = tmp_path / "archive"
    real_stat = os.stat

    def archive_side_no_identity(path: Any, *args: Any, **kwargs: Any) -> Any:
        st = real_stat(path, *args, **kwargs)
        if os.fspath(path) == os.fspath(inbox):
            return st
        return os.stat_result((st.st_mode, 0, *tuple(st)[2:]))

    monkeypatch.setattr(os, "stat", archive_side_no_identity)
    with caplog.at_level("WARNING", logger="messagefoundry.transports.file"):
        assert not file_module._inside_watch_tree_by_identity(archive, inbox)
    assert "gave no verdict" in caplog.text


def test_an_archive_path_whose_parent_exists_logs_no_skip(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # The control: a not-yet-created archive directory under an existing parent is compared.
    from messagefoundry.transports import file as file_module

    inbox = tmp_path / "in"
    inbox.mkdir()
    with caplog.at_level("WARNING", logger="messagefoundry.transports.file"):
        assert not file_module._inside_watch_tree_by_identity(tmp_path / "new" / "archive", inbox)
    assert "did not run" not in caplog.text
    assert "no verdict" not in caplog.text
    assert "could not be read" not in caplog.text


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        (PureWindowsPath(r"\\server\share\archive"), "UNC"),
        (PureWindowsPath("//server/share/archive"), "UNC"),
        (PureWindowsPath(r"\\?\UNC\server\share\archive"), "UNC"),
        (PureWindowsPath(r"\\?\D:\archive"), "device"),
        (PureWindowsPath(r"\\.\D:\archive"), "device"),
        (PureWindowsPath(r"D:\archive"), "drive"),
        (PurePosixPath("/srv/archive"), "local"),
    ],
)
def test_the_path_class_names_no_path_text(path: Any, expected: str) -> None:
    from messagefoundry.transports import file as file_module

    assert file_module._path_class(path) == expected


def test_an_archive_subdir_outside_the_watch_tree_through_a_link_still_starts(
    tmp_path: Path,
) -> None:
    # The control: a link to a directory outside the watch tree is the operator's to use.
    inbox = tmp_path / "in"
    inbox.mkdir()
    archive = tmp_path / "archive"
    archive.mkdir()
    alias = tmp_path / "alias"
    _link_dir(archive, alias)
    src = _source(inbox, processed_subdir=str(alias), error_subdir=str(tmp_path / "err"))
    src._prepare_subdirs()
