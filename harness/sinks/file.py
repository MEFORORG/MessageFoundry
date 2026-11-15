# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""File sink: record each file an engine File outbound writes into a directory, and where.

Files present when the sink starts are ignored while they stay unchanged, so a long-lived output
directory cannot satisfy a scenario with an earlier run's output; a file written again in place,
whether present at start or already recorded, is recorded again. "Unchanged" is the ``lstat``
identity, size and modification time. The scan walks the whole tree under the directory and
records each file's path relative to it (``meta["relpath"]``) and whether its resolved path,
symlinks followed, stays inside it (``meta["inside"]``). A path that cannot be resolved strictly (a
link loop, a dangling link, a mid-scan race) is recorded as not inside, never as inside. A file
written OUTSIDE the directory is by construction not seen here; a scenario that tests for an escape
must look where it would land.

Reading is bounded the way the GUI's folder watcher is, through the same reader
(:func:`harness.bounded_file.read_capped`): regular files only, symlinks not followed, each capped
at the engine's per-message cap, checked again on the open handle, and an over-cap file (or one that
grows past the cap while read) recorded with an empty payload and a ``refused`` reason rather than
read. Only a plain directory is skipped: a symlink (``meta["symlink"]``), FIFO or device is recorded
unread with the :data:`~harness.bounded_file.NOT_REGULAR` reason, so a link out of the directory
reads as an escape, not as nothing.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Iterator
from pathlib import Path

from harness.bounded_file import NOT_REGULAR, read_capped
from harness.endpoints import Endpoints
from harness.sinks import Record, Sink
from messagefoundry.parsing.peek import DEFAULT_MAX_MESSAGE_BYTES

KIND = "file"

#: The engine's File destination writes a ``mkstemp`` temp with one of these suffixes and then
#: renames it; a scan that lands mid-write must not record the temp as a delivery.
_ENGINE_TEMP_SUFFIXES = frozenset({".part", ".probe"})

#: What the sink remembers of a path it has seen: a change to any of these is a new write.
_Signature = tuple[int, int, int, int, int]


#: The reparse-tag bit Windows sets on a tag that names another path: a symlink, and a junction,
#: which ``S_ISLNK`` does not report. ``transports/file.py`` defines the same bit; a client may not
#: import it from there.
_NAME_SURROGATE = 0x20000000


def _signature(st: os.stat_result) -> _Signature:
    return (st.st_dev, st.st_ino, st.st_mode, st.st_size, st.st_mtime_ns)


def _is_link(st: os.stat_result) -> bool:
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_reparse_tag", 0) & _NAME_SURROGATE)


class FileSink(Sink):
    kind = KIND

    def __init__(self, directory: str | Path, *, pattern: str = "*") -> None:
        super().__init__()
        self.directory = Path(directory)
        self.pattern = pattern
        self._seen: dict[Path, _Signature] = {}
        #: The most one file may hold and still be read: the engine's per-message cap.
        self.max_file_bytes = DEFAULT_MAX_MESSAGE_BYTES

    def start(self) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        self._seen = {path: _signature(st) for path, st, _ in self._entries()}

    def _entries(self) -> Iterator[tuple[Path, os.stat_result, bool]]:
        """``(path, lstat, is a link)`` for each candidate but a plain directory, which the walk
        descends into; a link to a directory, a junction included, is not skipped. A path gone
        before its ``lstat`` is left out: nothing is there to record or to ignore."""
        for path in sorted(self.directory.rglob(self.pattern)):
            if path.name.startswith(".") or path.suffix in _ENGINE_TEMP_SUFFIXES:
                continue
            try:
                st = path.lstat()
            except OSError:
                continue
            link = _is_link(st)
            if link or not stat.S_ISDIR(st.st_mode):
                yield path, st, link

    def records(self) -> list[Record]:
        root = self.directory.resolve()
        for path, st, link in self._entries():
            signature = _signature(st)
            if self._seen.get(path) == signature:
                continue
            if link:
                data, refused = b"", NOT_REGULAR  # never read through a link
            else:
                try:
                    # O_NOFOLLOW on the open, where the OS has it, catches a link swapped in now.
                    data, refused = read_capped(path, self.max_file_bytes, follow_symlinks=False)
                except OSError:
                    continue  # vanished or locked mid-write: the next scan retries it
            try:
                inside = path.resolve(strict=True).is_relative_to(root)
            except (OSError, RuntimeError):
                inside = False  # a link loop, a dangling link, a race: not shown to stay inside
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
