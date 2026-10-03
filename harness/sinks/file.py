# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""File sink: record each file an engine File outbound writes into a directory, and where.

Files present when the sink starts are ignored, so a long-lived output directory cannot satisfy a
scenario with an earlier run's output. The scan walks the whole tree under the directory and
records each file's path relative to it (``meta["relpath"]``) and whether its resolved path,
symlinks followed, stays inside it (``meta["inside"]``). A file written OUTSIDE the directory is by
construction not seen here; a scenario that tests for an escape must look where it would land.

Reading is bounded the way the GUI's folder watcher is, through the same reader
(:func:`harness.bounded_file.read_capped`): regular files only, symlinks not followed, each capped
at the engine's per-message cap, checked again on the open handle, and an over-cap file (or one that
grows past the cap while read) recorded with an empty payload and a ``refused`` reason rather than
read.
"""

from __future__ import annotations

from pathlib import Path

from harness.bounded_file import NOT_REGULAR, read_capped
from harness.endpoints import Endpoints
from harness.sinks import Record, Sink
from messagefoundry.parsing.peek import DEFAULT_MAX_MESSAGE_BYTES

KIND = "file"

#: The engine's File destination writes a ``mkstemp`` temp with one of these suffixes and then
#: renames it; a scan that lands mid-write must not record the temp as a delivery.
_ENGINE_TEMP_SUFFIXES = frozenset({".part", ".probe"})


class FileSink(Sink):
    kind = KIND

    def __init__(self, directory: str | Path, *, pattern: str = "*") -> None:
        super().__init__()
        self.directory = Path(directory)
        self.pattern = pattern
        self._seen: set[Path] = set()
        #: The most one file may hold and still be read: the engine's per-message cap.
        self.max_file_bytes = DEFAULT_MAX_MESSAGE_BYTES

    def start(self) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        self._seen = set(self._candidates())

    def _candidates(self) -> list[Path]:
        return sorted(
            p
            for p in self.directory.rglob(self.pattern)
            if not p.name.startswith(".") and p.suffix not in _ENGINE_TEMP_SUFFIXES
        )

    def records(self) -> list[Record]:
        root = self.directory.resolve()
        for path in self._candidates():
            if path in self._seen:
                continue
            try:
                # Symlinks are not followed: lstat first, O_NOFOLLOW on the open where the OS has it.
                data, refused = read_capped(path, self.max_file_bytes, follow_symlinks=False)
            except OSError:
                continue  # vanished or locked mid-write: the next scan retries it
            if refused == NOT_REGULAR:
                continue
            self._seen.add(path)
            resolved = path.resolve()
            meta = {
                "path": str(path),
                "name": path.name,
                "relpath": path.relative_to(self.directory).as_posix(),
                "inside": str(resolved.is_relative_to(root)).lower(),
            }
            if refused:
                meta["refused"] = refused
            self._add(Record(data, meta))
        return super().records()


def build(endpoints: Endpoints, key: str) -> Sink:
    return FileSink(endpoints.value(key))
