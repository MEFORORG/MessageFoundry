# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The bounded on-disk spool behind the off-box log forwarder (BACKLOG #1966, ADR 0200).

Before this, a record the forwarder could not send was gone: dropped for a full hand-off queue,
discarded at shutdown, or lost to a down collector one send at a time. The spool keeps those records
on disk, in order, and sends them when the collector answers again, including after a restart.

**What goes in.** Only what the forwarder's hand-off queue already holds, and that is text the PHI,
credential and control-character filters have ALREADY processed on the caller's thread
(``logging_setup._ForwardQueueHandler`` argues why the chain sits there). Nothing in this module
formats, filters or reads a raw record. A spool fed before that chain would hold records
unredacted; this one cannot be, because it only ever sees the queue's side of the hand-off.

**File format (version 1).** A directory of segment files named ``spool-<12-digit sequence>.jsonl``.
Each line is one UTF-8 JSON object, ``{"v": 1, "level": "<levelname>", "line": "<rendered text>"}``,
ending in ``\\n``. JSON escaping keeps one entry on one physical line whatever the rendered text holds.
``level`` is kept because the syslog priority is derived from it when the entry is finally sent.

**Rotation and bound.** Appends go to the newest segment until it reaches ``segment_bytes``; the next
append opens a new one. The whole directory is capped at ``max_bytes`` on disk. An append that would
cross the cap is DROPPED and counted, newest first, which keeps the oldest evidence -- the same
choice the in-memory queue makes, for the same reason. A segment is deleted as soon as every entry in
it has been sent, so a drained spool holds no files.

**Replay order.** Strictly first in, first out: segments in sequence order, lines in file order. While
anything is spooled, the forwarder appends new records to the spool rather than sending them live,
so nothing overtakes older evidence.

**Crash safety.** Each append is flushed to the operating system, so a process crash loses nothing
already appended. A power loss can lose a tail the OS had not yet written.

**Delivery is best effort, not at least once.** After a TCP or TLS collector resets, the first send
on the dead connection can succeed into the local kernel buffer, so that entry is marked sent and
lost. The read position is kept in memory, so after a restart the oldest segment is replayed from its
start: a collector can see up to one segment (one eighth of the cap, 12.5 MB at the default 100 MB)
twice. Over UDP no send failure is detectable at all. ADR 0200 states the same limits. A torn or unreadable line (a crash mid-write) is skipped
and counted, never guessed at. After a restart, appends always start a NEW segment, so they never
extend a file whose tail may be torn.

**One process per directory.** The spool takes a non-blocking OS lock on ``spool.lock``. A second
process pointed at the same directory fails to open it and runs without a spool, rather than
interleaving appends or deleting segments the first one has not sent.

**PHI at rest.** The same class as the application log files: redacted but best-effort, so PL-1, and
plaintext (no app-level cipher). The directory is created owner-only where the platform honours a
mode; on Windows it inherits its parent's ACL, like ``[logging].log_dir``. The bound is size, and a
delivered entry is deleted with its segment. ``docs/PHI.md`` section 2 carries the row.

**Threading.** A :class:`LogSpool` belongs to ONE thread, the forwarder's listener thread. It has no
lock of its own, by design: a second writer is exactly what the directory lock exists to refuse.
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import IO

#: The on-disk format version written into every entry. A reader skips an entry of any other version
#: (counted as unreadable) rather than guessing at its shape.
SPOOL_FORMAT_VERSION = 1

_SEGMENT_PREFIX = "spool-"
_SEGMENT_SUFFIX = ".jsonl"
_LOCK_NAME = "spool.lock"


class SpoolUnavailable(OSError):
    """The spool directory could not be opened for this process (unwritable, or locked by another)."""


@dataclass(frozen=True, slots=True)
class SpoolEntry:
    """One spooled record: its level name and the rendered, already-filtered line."""

    level: str
    line: str

    def encode(self) -> bytes:
        payload = {"v": SPOOL_FORMAT_VERSION, "level": self.level, "line": self.line}
        # ensure_ascii (the default): a lone surrogate in a record is written as its escape instead
        # of raising UnicodeEncodeError on the listener thread, which would end that thread.
        return (json.dumps(payload) + "\n").encode("ascii")

    @staticmethod
    def decode(raw: bytes) -> SpoolEntry | None:
        """The entry ``raw`` holds, or ``None`` if it is torn, malformed or another version."""
        try:
            obj = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return None
        if not isinstance(obj, dict) or obj.get("v") != SPOOL_FORMAT_VERSION:
            return None
        level, line = obj.get("level"), obj.get("line")
        if not isinstance(level, str) or not isinstance(line, str):
            return None
        return SpoolEntry(level=level, line=line)


def _segment_seq(path: Path) -> int | None:
    name = path.name
    if not (name.startswith(_SEGMENT_PREFIX) and name.endswith(_SEGMENT_SUFFIX)):
        return None
    digits = name[len(_SEGMENT_PREFIX) : -len(_SEGMENT_SUFFIX)]
    # Only the canonical 12 ASCII digits this module writes: `spool-1.jsonl` would parse as seq 1
    # while _path(1) names a different file, and str.isdigit() accepts non-ASCII digits.
    return int(digits) if len(digits) == 12 and digits.isascii() and digits.isdigit() else None


def _try_lock(fd: int) -> bool:
    """Take a non-blocking exclusive lock on ``fd``; ``False`` if another process holds it."""
    if sys.platform == "win32":
        import msvcrt

        try:
            os.lseek(fd, 0, os.SEEK_SET)  # msvcrt locks from the current position
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        except OSError:
            return False
        return True
    import fcntl

    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return False
    return True


def _unlock(fd: int) -> None:
    if sys.platform == "win32":
        import msvcrt

        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        return
    import fcntl

    fcntl.flock(fd, fcntl.LOCK_UN)


class LogSpool:
    """A bounded, ordered, on-disk queue of rendered log lines. See the module docstring."""

    def __init__(self, directory: str | Path, *, max_bytes: int, segment_bytes: int | None = None):
        if max_bytes <= 0:
            raise ValueError("a log spool needs max_bytes > 0")
        self.directory = Path(directory)
        self.max_bytes = max_bytes
        self.segment_bytes = segment_bytes if segment_bytes else max(1, max_bytes // 8)
        #: Entries refused because the spool was full, or because the disk refused the write.
        self.dropped = 0
        #: Torn, malformed or other-version lines skipped on replay.
        self.unreadable = 0
        self._lock_fd: int | None = None
        #: Segment sequence numbers on disk, oldest first. The last one is the write segment once an
        #: append has opened it.
        self._segments: list[int] = []
        self._sizes: dict[int, int] = {}
        self._writer: IO[bytes] | None = None
        self._write_seq: int | None = None
        self._reader: IO[bytes] | None = None
        self._read_seq: int | None = None
        self._peeked: SpoolEntry | None = None
        self._peeked_end = 0
        #: The highest segment number ever seen or issued. Never reused: a segment whose unlink
        #: failed stays on disk, and reusing its number would collide with it on O_EXCL for good.
        self._last_seq = 0

    # --- lifecycle ------------------------------------------------------------------------------

    def open(self) -> None:
        """Create the directory, take its lock, and index any segments a previous process left.

        Raises :class:`SpoolUnavailable` when the directory cannot be used by this process."""
        try:
            self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = os.open(self.directory / _LOCK_NAME, os.O_RDWR | os.O_CREAT, 0o600)
        except OSError as exc:
            raise SpoolUnavailable(
                f"log spool directory {self.directory} is not usable: {exc}"
            ) from exc
        if not _try_lock(fd):
            os.close(fd)
            raise SpoolUnavailable(
                f"log spool directory {self.directory} is in use by another process"
            )
        self._lock_fd = fd
        try:
            for path in self.directory.iterdir():
                seq = _segment_seq(path)
                if seq is not None:
                    self._segments.append(seq)
                    self._sizes[seq] = path.stat().st_size
        except OSError as exc:
            # Unreadable leftovers make the spool unusable, not the process: the caller runs
            # spool-less. A bare OSError here would reach serve's [logging].file refusal instead.
            self.close()
            self._segments.clear()
            self._sizes.clear()
            raise SpoolUnavailable(
                f"log spool directory {self.directory} is not readable: {exc}"
            ) from exc
        self._segments.sort()
        self._last_seq = self._segments[-1] if self._segments else 0

    def close(self) -> None:
        """Close the files and release the lock. Spooled entries stay on disk for the next start."""
        for handle in (self._writer, self._reader):
            if handle is not None:
                with contextlib.suppress(OSError):
                    handle.close()
        self._writer = self._reader = None
        self._write_seq = self._read_seq = None
        self._peeked = None
        if self._lock_fd is not None:
            with contextlib.suppress(OSError):
                _unlock(self._lock_fd)
            with contextlib.suppress(OSError):
                os.close(self._lock_fd)
            self._lock_fd = None

    # --- state ----------------------------------------------------------------------------------

    @property
    def bytes_used(self) -> int:
        """Bytes the segments occupy on disk, delivered-but-not-yet-deleted lines included."""
        return sum(self._sizes.values())

    @property
    def pending(self) -> bool:
        """Whether anything is waiting to be sent."""
        return self.peek() is not None

    def _path(self, seq: int) -> Path:
        return self.directory / f"{_SEGMENT_PREFIX}{seq:012d}{_SEGMENT_SUFFIX}"

    # --- write side -----------------------------------------------------------------------------

    def append(self, entry: SpoolEntry) -> bool:
        """Append ``entry`` at the tail. ``False`` (and counted in :attr:`dropped`) when it would
        cross :attr:`max_bytes` or the disk refuses the write."""
        data = entry.encode()
        if self.bytes_used + len(data) > self.max_bytes:
            self.dropped += 1
            return False
        try:
            writer = self._writer_for(len(data))
            writer.write(data)
            writer.flush()
        except OSError:
            self.dropped += 1
            self._close_writer()
            return False
        assert self._write_seq is not None
        self._sizes[self._write_seq] += len(data)
        return True

    def _writer_for(self, size: int) -> IO[bytes]:
        seq = self._write_seq
        if (
            self._writer is not None
            and seq is not None
            and self._sizes[seq] + size > self.segment_bytes
            and self._sizes[seq] > 0
        ):
            self._close_writer()
        if self._writer is None:
            seq = self._last_seq = self._last_seq + 1
            fd = os.open(self._path(seq), os.O_WRONLY | os.O_CREAT | os.O_EXCL | _BINARY, 0o600)
            self._writer = os.fdopen(fd, "ab")
            self._write_seq = seq
            self._segments.append(seq)
            self._sizes[seq] = 0
        return self._writer

    def _close_writer(self) -> None:
        if self._writer is not None:
            with contextlib.suppress(OSError):
                self._writer.close()
        self._writer = None
        self._write_seq = None

    # --- read side ------------------------------------------------------------------------------

    def peek(self) -> SpoolEntry | None:
        """The oldest undelivered entry, or ``None`` when the spool is drained. Idempotent until
        :meth:`advance`."""
        while self._peeked is None:
            if not self._segments:
                return None
            seq = self._segments[0]
            if self._reader is None or self._read_seq != seq:
                try:
                    self._open_reader(seq)
                except OSError:
                    # A segment removed or locked from outside. Skipping it is the only move that
                    # keeps the listener thread alive; an exception here would end it for good.
                    self.unreadable += 1
                    if seq == self._write_seq:
                        self._close_writer()
                    self._retire(seq)
                    continue
            assert self._reader is not None
            start = self._reader.tell()
            raw = self._reader.readline()
            if raw.endswith(b"\n"):
                entry = SpoolEntry.decode(raw[:-1])
                if entry is None:
                    self.unreadable += 1
                    continue
                self._peeked, self._peeked_end = entry, self._reader.tell()
                break
            if seq == self._write_seq:
                # The live write segment, read up to what has been written: nothing more yet. Seek
                # back so a partial read of a line still being written is re-read whole next time.
                self._reader.seek(start)
                return None
            if raw:
                self.unreadable += 1  # a torn final line in a closed segment
            self._retire(seq)
        return self._peeked

    def advance(self) -> None:
        """Mark the entry :meth:`peek` returned as delivered."""
        if self._peeked is None:
            return
        self._peeked = None
        seq = self._read_seq
        if seq is not None and seq != self._write_seq and self._peeked_end >= self._sizes[seq]:
            self._retire(seq)
        elif seq is not None and seq == self._write_seq and self._peeked_end >= self._sizes[seq]:
            # Drained up to the live tail: retire it too, so an empty spool holds no files. The
            # next append opens a fresh segment.
            self._close_writer()
            self._retire(seq)

    def _open_reader(self, seq: int) -> None:
        if self._reader is not None:
            with contextlib.suppress(OSError):
                self._reader.close()
        self._reader = open(self._path(seq), "rb")  # noqa: SIM115 - held across calls on purpose
        self._read_seq = seq

    def _retire(self, seq: int) -> None:
        if self._reader is not None and self._read_seq == seq:
            with contextlib.suppress(OSError):
                self._reader.close()
            self._reader = None
            self._read_seq = None
        with contextlib.suppress(OSError):
            self._path(seq).unlink()
        self._segments.remove(seq)
        self._sizes.pop(seq, None)


#: ``O_BINARY`` on Windows (no newline translation), zero elsewhere.
_BINARY: int = getattr(os, "O_BINARY", 0)
