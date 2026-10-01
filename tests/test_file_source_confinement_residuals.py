# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The FILE source acts only on the file it read, and only into the archive directory it opened (#2535).

BACKLOG #2507 made the read and the move check the handle. Its review left a set of gaps, and a review
of the archive directories added one more:

- a file renamed over the name after the read was archived or deleted unread (the pin compared no
  identity with the read);
- on Windows a directory or a last name swapped for a link after the pin's check was followed by the
  move and the delete, which acted by name, and so was a link at the last name by the copy fallback;
- on Windows the listing and the read opened a link at the last name to look at it, which reaches
  whatever it names (a pipe here, standing in for a UNC path's server);
- on POSIX the copy fallback opened the name without ``O_NONBLOCK``, so a FIFO swapped in held a worker
  thread;
- ``.processed`` and ``.error`` were checked only at start, so one swapped for a link later had the
  next archive written through it.

Every swap happens at the exact point the old code trusted, through a hook, so each test is
deterministic. Symbolic links need a privilege on Windows; the tests that make one skip where the
process cannot, and run on every Linux runner. All HL7 is synthetic.
"""

from __future__ import annotations

import asyncio
import contextlib
import errno
import os
import sys
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.transports import file as file_mod
from messagefoundry.transports.file import FileSource

_DROP = rb"MSH|^~\&|LAB|FAC|EHR|FAC|20260930||ADT^A01|CTRL1|P|2.5" + b"\rPID|1||SYN01\r"
#: The same length as the drop, so no size compare can tell them apart.
_TWIN = _DROP.replace(b"SYN01", b"SYN02")
_SECRET = _DROP.replace(b"SYN01", b"SEC99")


class _Recorder:
    def __init__(self, on_first: Callable[[], None] | None = None) -> None:
        self.got: list[bytes] = []
        self._on_first = on_first

    async def __call__(self, raw: bytes) -> str | None:
        self.got.append(raw)
        if len(self.got) == 1 and self._on_first is not None:
            self._on_first()
        return None


def _source(inbox: Path, **over: object) -> FileSource:
    settings: dict[str, object] = {"directory": str(inbox), "pattern": "*.hl7"}
    settings.update(over)
    src = FileSource(Source(type=ConnectorType.FILE, settings=settings))
    src._prepare_subdirs()
    return src


def _require_symlinks(tmp_path: Path) -> None:
    probe = tmp_path / "symlink-probe"
    try:
        probe.symlink_to(tmp_path)
    except (OSError, NotImplementedError):
        pytest.skip("this process cannot create a symbolic link here")
    probe.unlink()


def _same_stat(model: Path, path: Path) -> None:
    """Give ``path`` ``model``'s modification time, so the #116 size-and-mtime compare passes."""
    st = model.stat()
    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns))


def _holds(directory: Path, body: bytes) -> list[str]:
    """Entries under ``directory`` that are links, or that read back as ``body``."""
    found: list[str] = []
    for entry in directory.rglob("*"):
        if entry.is_symlink() or entry.is_junction():
            found.append(f"{entry.name} (a link)")
        elif entry.is_file() and entry.read_bytes() == body:
            found.append(entry.name)
    return found


def _after_pin(monkeypatch: pytest.MonkeyPatch, swap: Callable[[], None]) -> list[str]:
    """Run ``swap`` once, just after the move's or delete's check has passed. Returns a list that
    records whether the swap was refused by the filesystem (NTFS refuses to rename a directory with
    a file open below it, which the new Windows pin holds)."""
    real = file_mod._pin_confined
    refused: list[str] = []
    done: list[bool] = []

    def pinned(*args: Any, **kwargs: Any) -> Any:
        pin = real(*args, **kwargs)
        if not done:
            done.append(True)
            try:
                swap()
            except OSError as exc:
                refused.append(type(exc).__name__)
        return pin

    monkeypatch.setattr(file_mod, "_pin_confined", pinned)
    return refused


async def _read_and_hand_off(src: FileSource) -> None:
    await src._scan_once()  # the settle poll (BACKLOG #1811)
    await src._scan_once()  # read, hand off, then move or delete


# === a file renamed over the name after the read ===================================================


@pytest.mark.parametrize("after_read", ["move", "delete"])
async def test_a_file_renamed_over_the_name_after_the_read_is_left_for_the_next_scan(
    tmp_path: Path, after_read: str, caplog: pytest.LogCaptureFixture
) -> None:
    """A partner resends under the same name, by write-then-rename, while the first copy is in the
    hand-off. Size and mtime match, so the #116 compare cannot tell.

    Red on origin/main: the resent file is archived (``move``) or deleted (``delete``) without ever
    being read, so its message is lost."""
    inbox = tmp_path / "in"
    inbox.mkdir()
    drop = inbox / "drop.hl7"
    drop.write_bytes(_DROP)
    staged = tmp_path / "resend.part"

    def resend() -> None:
        staged.write_bytes(_TWIN)
        _same_stat(drop, staged)
        os.replace(staged, drop)

    src = _source(inbox, after_read=after_read)
    handler = _Recorder(on_first=resend)
    src._handler = handler
    with caplog.at_level("WARNING", logger="messagefoundry.transports.file"):
        await _read_and_hand_off(src)
    assert handler.got == [_DROP]
    assert drop.read_bytes() == _TWIN, "the resent file was archived or deleted unread"
    assert "replaced after it was read" in caplog.text
    assert drop.name not in caplog.text
    await _read_and_hand_off(src)
    assert handler.got == [_DROP, _TWIN], "the resent file was not read on the next scan"


# === a link swapped in after the pin ===============================================================


def _layout(tmp_path: Path, kind: str) -> tuple[Path, Path, Path, Callable[[], None]]:
    """The drop, the watch root, the outside file, and a swap that puts a link where the drop (or its
    subdirectory) was."""
    inbox = tmp_path / "in"
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    parked = tmp_path / "parked"
    parked.mkdir()
    if kind == "file":
        inbox.mkdir()
        drop = inbox / "drop.hl7"
        drop.write_bytes(_DROP)
        outside = outside_dir / "secret.hl7"
        outside.write_bytes(_SECRET)

        def swap() -> None:
            drop.rename(parked / drop.name)
            drop.symlink_to(outside)

        return drop, inbox, outside, swap
    sub = inbox / "sub"
    sub.mkdir(parents=True)
    drop = sub / "drop.hl7"
    drop.write_bytes(_DROP)
    outside = outside_dir / drop.name
    outside.write_bytes(_SECRET)

    def swap_dir() -> None:
        sub.rename(parked / sub.name)
        sub.symlink_to(outside_dir, target_is_directory=True)

    return drop, inbox, outside, swap_dir


@pytest.mark.parametrize(
    ("kind", "after_read"),
    [("file", "move"), ("dir", "move"), ("dir", "delete")],
)
async def test_a_link_swapped_in_after_the_pin_is_neither_archived_nor_deleted_through(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str, after_read: str
) -> None:
    """The swap lands after the move's check and before its act.

    Red on origin/main on Windows: the act resolved the name again, so ``move`` archived the outside
    file and ``delete`` through the swapped directory deleted it. On POSIX the ``file`` case is red
    too: the claim hard-linked the link itself into ``.processed``."""
    _require_symlinks(tmp_path)
    drop, inbox, outside, swap = _layout(tmp_path, kind)
    src = _source(inbox, recursive=kind == "dir", after_read=after_read)
    src._handler = _Recorder()
    await src._scan_once()
    _after_pin(monkeypatch, swap)
    await src._scan_once()
    assert outside.is_file(), "the outside file was moved or deleted through the link"
    assert outside.read_bytes() == _SECRET
    for sub in (".processed", ".error"):
        assert _holds(inbox / sub, _SECRET) == [], f"the outside file or a link reached {sub}"


async def test_the_copy_fallback_copies_the_checked_file_and_not_a_link_swapped_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Where the archive cannot link or rename (another volume, no hard links), the move copies.

    Red on origin/main on Windows: the copy opened the name again, without ``O_NOFOLLOW`` (Windows has
    none), so a link swapped in after the check put the outside file in ``.processed``."""
    _require_symlinks(tmp_path)
    drop, inbox, outside, swap = _layout(tmp_path, "file")

    def no_links(*_a: object, **_k: object) -> None:
        raise OSError(errno.EXDEV, "Invalid cross-device link")

    def other_volume(*_a: object, **_k: object) -> None:
        raise OSError(None, "The system cannot move the file to a different disk drive", None, 17)

    monkeypatch.setattr(os, "link", no_links)
    monkeypatch.setattr(file_mod, "_rename_by_handle", other_volume, raising=False)
    src = _source(inbox)
    src._handler = _Recorder()
    await src._scan_once()
    _after_pin(monkeypatch, swap)
    await src._scan_once()
    assert outside.read_bytes() == _SECRET
    assert _holds(inbox / ".processed", _SECRET) == [], "the outside file was copied in"


@pytest.mark.parametrize("arm", ["cross-filesystem", "no-hard-links"])
async def test_the_copy_fallback_still_archives_the_drop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arm: str
) -> None:
    """The copy path, now relative to the archive directory's descriptor on POSIX, still archives.

    ``cross-filesystem``: only the first link fails, so the staged copy is published by a link.
    ``no-hard-links``: every link fails, so it is published over an ``O_EXCL`` placeholder."""
    inbox = tmp_path / "in"
    inbox.mkdir()
    drop = inbox / "drop.hl7"
    drop.write_bytes(_DROP)
    real_link = os.link
    calls: list[int] = []

    def link(src: Any, dst: Any, **kw: Any) -> None:
        calls.append(1)
        if arm == "no-hard-links" or len(calls) == 1:
            raise OSError(errno.EXDEV, "Invalid cross-device link")
        real_link(src, dst, **kw)

    def other_volume(*_a: object, **_k: object) -> None:
        raise OSError(None, "The system cannot move the file to a different disk drive", None, 17)

    monkeypatch.setattr(os, "link", link)
    monkeypatch.setattr(file_mod, "_rename_by_handle", other_volume, raising=False)
    src = _source(inbox)
    handler = _Recorder()
    src._handler = handler
    await _read_and_hand_off(src)
    assert handler.got == [_DROP]
    assert not drop.exists(), "the original was not removed after the copy"
    archived = sorted(p.name for p in (inbox / ".processed").iterdir())
    assert archived == ["drop.hl7"], archived
    assert (inbox / ".processed" / "drop.hl7").read_bytes() == _DROP


@pytest.mark.skipif(sys.platform == "win32", reason="no FIFOs on Windows")
async def test_a_fifo_swapped_in_before_the_copy_fallback_is_refused_without_blocking(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On Linux the copy is the usual path for a partner's file: ``fs.protected_hardlinks`` refuses to
    link a file the engine does not own. The copy opens the name ``O_NONBLOCK`` and checks it.

    Red on origin/main: the copy's open waits for a FIFO writer, so the scan times out."""
    inbox = tmp_path / "in"
    inbox.mkdir()
    drop = inbox / "drop.hl7"
    drop.write_bytes(_DROP)

    def no_links(*_a: object, **_k: object) -> None:
        raise OSError(errno.EPERM, "Operation not permitted")

    def swap() -> None:
        drop.unlink()
        if sys.platform != "win32":  # narrows mypy; the test is skipped there
            os.mkfifo(drop)

    monkeypatch.setattr(os, "link", no_links)
    src = _source(inbox)
    handler = _Recorder()
    src._handler = handler
    await src._scan_once()
    _after_pin(monkeypatch, swap)
    try:
        await asyncio.wait_for(src._scan_once(), timeout=10)
    finally:
        # A blocked reader on the old code would hold its thread forever; a writer releases it.
        if sys.platform != "win32":  # narrows mypy; the test is skipped there
            with contextlib.suppress(OSError):
                os.close(os.open(drop, os.O_WRONLY | os.O_NONBLOCK))
    assert handler.got == [_DROP]
    assert list((inbox / ".processed").iterdir()) == []


# === the listing and the read do not reach what a link names (Windows) =============================


@pytest.mark.skipif(sys.platform != "win32", reason="named pipes are a Windows path here")
async def test_a_link_to_a_pipe_is_refused_without_connecting_to_it(tmp_path: Path) -> None:
    """A link in the drop directory to a named pipe stands in for one to a UNC path: opening through
    it reaches whatever it names (an SMB server, which then gets the service account's NTLM exchange;
    a pipe server, which can impersonate the client). The listing and the read open the link itself.

    Red on origin/main: the listing's ``is_file()`` follows the link and connects to the pipe."""
    _require_symlinks(tmp_path)
    if sys.platform != "win32":  # narrows mypy; the test is skipped there
        return
    import _winapi

    inbox = tmp_path / "in"
    inbox.mkdir()
    link = inbox / "drop.hl7"
    name = "\\\\.\\pipe\\mefor-2535-" + uuid.uuid4().hex
    # Made before the server exists: os.symlink probes its target to choose a file or directory link.
    link.symlink_to(name)
    handle = _winapi.CreateNamedPipe(
        name,
        _winapi.PIPE_ACCESS_DUPLEX | _winapi.FILE_FLAG_OVERLAPPED,
        _winapi.PIPE_TYPE_MESSAGE | _winapi.PIPE_READMODE_MESSAGE | _winapi.PIPE_WAIT,
        1,
        4096,
        4096,
        0,
        _winapi.NULL,
    )
    pending = _winapi.ConnectNamedPipe(handle, overlapped=True)
    try:
        src = _source(inbox)
        handler = _Recorder()
        src._handler = handler
        for _ in range(3):  # the listing, the settle poll, the read
            await src._scan_once()
        connected = _winapi.WaitForSingleObject(pending.event, 0) == _winapi.WAIT_OBJECT_0
        assert not connected, "the engine connected to the pipe the link names"
        assert handler.got == []
        assert os.path.lexists(link)
    finally:
        with contextlib.suppress(OSError):
            pending.cancel()
        _winapi.CloseHandle(handle)


# === the archive directory swapped for a link after start ==========================================


def _junction(link: Path, target: Path) -> None:
    if sys.platform != "win32":
        pytest.skip("junctions are Windows only")
    import _winapi

    _winapi.CreateJunction(str(target), str(link))


@pytest.mark.parametrize("dest", [".processed", ".error"])
@pytest.mark.parametrize("link_kind", ["symlink", "junction"])
async def test_an_archive_directory_swapped_for_a_link_is_refused_and_nothing_is_written_through(
    tmp_path: Path, dest: str, link_kind: str, caplog: pytest.LogCaptureFixture
) -> None:
    """Whoever writes the drop directory can rename ``.processed`` or ``.error`` after start and put a
    link in its place. A junction needs no privilege on Windows.

    Red on origin/main: the archive lands in the directory the link names."""
    if link_kind == "symlink":
        _require_symlinks(tmp_path)
    inbox = tmp_path / "in"
    inbox.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    drop = inbox / "drop.hl7"
    # A non-HL7 body takes the quarantine arm into .error; an HL7 one is archived into .processed.
    drop.write_bytes(_DROP if dest == ".processed" else b"%PDF-" + b"x" * 40)
    src = _source(inbox)
    handler = _Recorder()
    src._handler = handler
    (inbox / dest).rename(tmp_path / "parked")
    if link_kind == "symlink":
        (inbox / dest).symlink_to(elsewhere, target_is_directory=True)
    else:
        _junction(inbox / dest, elsewhere)
    with caplog.at_level("WARNING", logger="messagefoundry.transports.file"):
        await _read_and_hand_off(src)
    assert list(elsewhere.iterdir()) == [], "the archive was written through the link"
    assert drop.exists(), "the drop is left in place when its archive directory is refused"
    assert "could not move" in caplog.text
    assert drop.name not in caplog.text


# === Windows: a reparse point that names no path is read through its filter ========================


@pytest.mark.skipif(sys.platform != "win32", reason="reparse tags are a Windows path")
def test_a_non_link_reparse_point_is_reopened_and_must_stay_the_same_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A deduplicated, cloud or tiered file carries a reparse tag that names no path. Opened as itself
    it would serve the filter's stub, so it is opened again, and must still be the same file.

    Mutations: drop the reopen (the identity compare is then never reached, and the swapped file is
    returned); drop the identity compare (the swapped file's bytes come back)."""
    inbox = tmp_path / "in"
    inbox.mkdir()
    drop = inbox / "drop.hl7"
    drop.write_bytes(_DROP)
    real_tag = file_mod._attribute_tag
    dedup_tag = 0x80000013  # IO_REPARSE_TAG_DEDUP: no name-surrogate bit

    def tagged(handle: int) -> tuple[int, int]:
        attributes, tag = real_tag(handle)
        return attributes | 0x400, dedup_tag  # FILE_ATTRIBUTE_REPARSE_POINT

    monkeypatch.setattr(file_mod, "_attribute_tag", tagged)
    raw, _file_id = file_mod._read_confined(drop, inbox, inbox.resolve(), None)
    assert raw == _DROP

    real_create = file_mod._win_create

    def swap_before_reopen(path: Path, access: int, share: int, flags: int) -> int:
        if flags == 0 and path.name == drop.name:  # the reopen
            drop.rename(tmp_path / "parked.hl7")
            drop.write_bytes(_TWIN)
        return real_create(path, access, share, flags)

    monkeypatch.setattr(file_mod, "_win_create", swap_before_reopen)
    with pytest.raises(file_mod._Replaced):
        file_mod._read_confined(drop, inbox, inbox.resolve(), None)
