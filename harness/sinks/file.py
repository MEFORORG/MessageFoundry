# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""File sink: record each file an engine File outbound writes into a directory, and where.

Files present when the sink starts are ignored while they stay unchanged, so a long-lived output
directory cannot satisfy a scenario with an earlier run's output; a file written again in place,
whether present at start or already recorded, is recorded again. "Unchanged" is the ``lstat``
identity, file type, size and modification time, and a file that changes while it is read is
recorded once it settles, not twice. The scan enters only what ``lstat`` reads as a plain
directory, never a link or a junction (a folder swapped for a link during the scan is an open race,
see :meth:`FileSink._entries`), and records each file's path relative to it
(``meta["relpath"]``) and whether its resolved path, symlinks followed, stays inside it
(``meta["inside"]``). A link that cannot be resolved strictly (a loop, a dangling link, a race) is
recorded as not inside, never as inside. A file written OUTSIDE the directory is by construction not
seen here; a scenario that tests for an escape must look where it would land, and a link the sink
records unread carries no control id, so a scenario must check ``meta["symlink"]`` itself.

Reading is bounded the way the GUI's folder watcher is, through the same reader
(:func:`harness.bounded_file.read_capped`): regular files only, a symlink as the last path
component not followed, each capped at the engine's per-message cap, checked again on the open
handle, and an over-cap file (or one that grows past the cap while read) recorded with an empty
payload and a ``refused`` reason rather than read. Only a plain directory is skipped: a symlink (``meta["symlink"]``), FIFO or device is recorded
unread with the :data:`~harness.bounded_file.NOT_REGULAR` reason, so a link out of the directory
reads as an escape, not as nothing. A listed name that :func:`_unsafe_listed_name` refuses is
never joined onto its folder: it is recorded once, unread, with the :data:`UNSAFE_NAME` reason, its
folder's relative path (``meta["folder"]``) and no ``path`` or ``relpath``.
"""

from __future__ import annotations

import ntpath
import os
import stat
from pathlib import Path

from harness.bounded_file import NOT_REGULAR, read_capped
from harness.endpoints import Endpoints
from harness.sinks import Record, Sink
from messagefoundry.parsing.peek import DEFAULT_MAX_MESSAGE_BYTES

KIND = "file"

#: The engine's File destination writes a ``mkstemp`` temp with one of these suffixes and then
#: renames it; a scan that lands mid-write must not record the temp as a delivery.
_ENGINE_TEMP_SUFFIXES = frozenset({".part", ".probe"})

#: What the sink remembers of a path it has seen: its identity, file type, size and modification
#: time. A change to any of them is taken as a new write; permission bits are left out, so a chmod
#: is not. A same-size rewrite within one mtime tick, on the same inode, is not seen.
_Signature = tuple[int, int, int, int, int]

#: The reparse-tag bit Windows sets on a tag that names another path: a symlink, and a junction,
#: which ``S_ISLNK`` does not report. ``transports/file.py`` defines the same bit; a client may not
#: import it from there.
_NAME_SURROGATE = 0x20000000

#: Whether the Windows name rules apply. A module flag, so a test can exercise either set anywhere.
_WINDOWS = os.name == "nt"

#: The ``refused`` reason for a listed name :func:`_unsafe_listed_name` refuses.
UNSAFE_NAME = "unsafe name"


def _signature(st: os.stat_result) -> _Signature:
    return (st.st_dev, st.st_ino, stat.S_IFMT(st.st_mode), st.st_size, st.st_mtime_ns)


def _is_link(st: os.stat_result) -> bool:
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_reparse_tag", 0) & _NAME_SURROGATE)


def _unsafe_listed_name(name: str) -> bool:
    """Whether a name read back from a listing must not be joined onto its folder.

    On every platform: an empty name, ``.``, ``..``, or one holding a path separator or a NUL. On
    Windows also: one holding a colon, which pathlib reads as a drive (``C:`` joins to the folder's
    own drive, ``D:x`` to another drive) or which names an alternate data stream, and one
    :func:`ntpath.isreserved` reports, which covers at least a trailing dot or space (Windows strips
    it, so ``...`` reads as the folder itself) and a device name such as ``nul`` or ``NUL.txt``."""
    if name in ("", ".", ".."):
        return True
    separators = {"/", "\\"} if _WINDOWS else {os.sep, os.altsep or os.sep}
    if "\0" in name or any(sep in name for sep in separators):
        return True
    return _WINDOWS and (":" in name or ntpath.isreserved(name))


class FileSink(Sink):
    kind = KIND

    def __init__(self, directory: str | Path, *, pattern: str = "*") -> None:
        super().__init__()
        self.directory = Path(directory)
        self.pattern = pattern
        self._seen: dict[Path, _Signature] = {}
        #: Listed names refused unjoined, as ``(folder, name)``: each is recorded once.
        self._seen_unsafe: set[tuple[Path, str]] = set()
        #: The most one file may hold and still be read: the engine's per-message cap.
        self.max_file_bytes = DEFAULT_MAX_MESSAGE_BYTES

    def start(self) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        found, unsafe = self._entries()
        self._seen = {path: _signature(st) for path, st in found}
        self._seen_unsafe = set(unsafe)

    def _entries(self) -> tuple[list[tuple[Path, os.stat_result]], list[tuple[Path, str]]]:
        """``(path, lstat)`` for each candidate under the directory, sorted by path, and
        ``(folder, name)`` for each listed name :func:`_unsafe_listed_name` refused before the join.

        Each listed name is checked before it is joined onto its folder. The walk enters only entries that ``lstat`` reads as plain directories. A link, a junction
        included, is a candidate whatever its name and is not entered. A folder swapped for a link
        after that ``lstat`` is not refused: at least from its listing until each file under it is
        read in :meth:`records`, paths under it go through the link, so a file outside the
        directory can be read and recorded. That is an open race. A path gone before its ``lstat``,
        or a folder gone before it is listed, is left out: nothing is there to record or to
        ignore."""
        found: list[tuple[Path, os.stat_result]] = []
        unsafe: list[tuple[Path, str]] = []
        pending = [self.directory]
        while pending:
            folder = pending.pop()
            try:
                with os.scandir(folder) as listing:
                    names = [entry.name for entry in listing]
            except OSError:
                continue
            for name in names:
                if _unsafe_listed_name(name):
                    unsafe.append((folder, name))
                    continue
                path = folder / name
                try:
                    st = path.lstat()
                except OSError:
                    continue
                link = _is_link(st)
                if stat.S_ISDIR(st.st_mode) and not link:
                    pending.append(path)
                elif link or (
                    path.relative_to(self.directory).match(self.pattern)
                    and not name.startswith(".")
                    and path.suffix not in _ENGINE_TEMP_SUFFIXES
                ):
                    # A link is never an engine temp, so no name or pattern keeps one out.
                    found.append((path, st))
        return sorted(found, key=lambda item: item[0]), sorted(unsafe)

    def _inside(self, path: Path, link: bool, root: Path) -> bool:
        """Whether ``path`` resolves inside ``root``; False where that cannot be shown. A link is
        resolved strictly, so a loop or a dangling link is not inside. A file is judged by its folder,
        which the walk reached through what ``lstat`` read as plain directories, so a file that
        vanishes after its read is not mistaken for an escape. A folder swapped for a link and back
        during the scan defeats this check: the open race in :meth:`_entries`."""
        try:
            if link:
                return path.resolve(strict=True).is_relative_to(root)
            return (path.parent.resolve(strict=True) / path.name).is_relative_to(root)
        except OSError:
            return False

    def records(self) -> list[Record]:
        root = self.directory.resolve()
        found, unsafe = self._entries()
        for folder, name in unsafe:
            if (folder, name) in self._seen_unsafe:
                continue  # no lstat to tell a rewrite from the same entry, so recorded once
            self._seen_unsafe.add((folder, name))
            meta = {
                "name": name,
                "folder": folder.relative_to(self.directory).as_posix(),
                "inside": "false",
                "refused": UNSAFE_NAME,
            }
            self._add(Record(b"", meta))
        for path, st in found:
            signature = _signature(st)
            if self._seen.get(path) == signature:
                continue
            link = _is_link(st)
            if link:
                data, refused = b"", NOT_REGULAR  # never read through a link
            else:
                try:
                    # O_NOFOLLOW on the open, where the OS has it, catches a link swapped in now
                    # as the file itself, not as a folder above it.
                    data, refused = read_capped(path, self.max_file_bytes, follow_symlinks=False)
                except OSError:
                    continue  # vanished or locked mid-write: the next scan retries it
            inside = self._inside(path, link, root)
            try:
                settled = _signature(path.lstat()) == signature
            except FileNotFoundError:
                settled = True  # gone after a whole read: what was read is the delivery
            except OSError:
                settled = False
            if not settled:
                continue  # changed while read: the next scan records what it settled to, once
            self._seen[path] = signature
            meta = {
                "path": str(path),
                "name": path.name,
                "relpath": path.relative_to(self.directory).as_posix(),
                "inside": str(inside).lower(),
            }
            if link:
                meta["symlink"] = "true"
            if refused:
                meta["refused"] = refused
            self._add(Record(data, meta))
        return super().records()


def build(endpoints: Endpoints, key: str) -> Sink:
    return FileSink(endpoints.value(key))
