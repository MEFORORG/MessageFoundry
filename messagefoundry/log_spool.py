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
Text is written as itself, in UTF-8, so its cost against the cap is its real size. The one exception
is an entry holding a lone surrogate, which has no UTF-8 form and is written with ASCII escapes.

**Rotation and bound.** Appends go to the newest segment until it reaches ``segment_bytes``; the next
append opens a new one. The whole directory is capped at ``max_bytes`` on disk. An append that would
cross the cap is DROPPED and counted, newest first, which keeps the oldest evidence -- the same
choice the in-memory queue makes, for the same reason. A segment is deleted as soon as every entry in
it has been sent, so a drained spool holds no files. A sent segment whose delete FAILED is out of
the replay order but still on disk, so it stays counted against the cap until :meth:`LogSpool.reclaim`
or :meth:`LogSpool.close` deletes it. One that is still there at the next start is replayed whole,
because nothing on disk marks it as sent. A write the disk refused is dropped and counted; the empty
segment it would have started is removed, so a full disk does not fill the directory with empty files.

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
        # Real UTF-8, so a non-ASCII character costs its own bytes against the cap and not a
        # six-byte escape each (BACKLOG #2279). JSON still escapes every control character, so one
        # entry stays on one physical line, and no UTF-8 sequence contains the newline byte.
        try:
            return (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")
        except UnicodeEncodeError:
            # A lone surrogate has no UTF-8 form. Write that one entry escaped, as before, instead
            # of raising on the listener thread, which would end that thread. decode() reads both.
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


def count_segments(directory: str | Path) -> int:
    """How many spool segment files ``directory`` holds. ``0`` if it does not exist.

    Reads names only, takes no lock and changes nothing, so it is safe on a directory another
    process is spooling into. A directory that exists but cannot be listed raises ``OSError``:
    "cannot tell" must not read as "nothing there"."""
    try:
        return sum(1 for path in Path(directory).iterdir() if _segment_seq(path) is not None)
    except (FileNotFoundError, NotADirectoryError):
        return 0


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
        #: Torn, malformed or other-version lines skipped on replay, and segments found gone.
        self.unreadable = 0
        #: Reads that failed for a reason other than a missing file. The files are kept.
        self.read_errors = 0
        #: Whether the LAST read failed that way. :attr:`read_errors` never goes down, so it cannot
        #: say whether a fault is still standing; this can.
        self.read_faulted = False
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
        #: The highest segment number on disk or issued. Never reused while its file may exist: a
        #: segment whose unlink failed stays on disk, and reusing its number would collide with it
        #: on O_EXCL for good. Only an empty write segment that WAS deleted hands its number back.
        self._last_seq = 0
        #: Sent segments whose file would not delete (BACKLOG #2279). Out of the replay order, but
        #: still on disk, so their bytes stay in :attr:`_sizes` and count against the cap.
        self._undeleted: list[int] = []
        #: The directories :meth:`open` made itself, leaf first, and whether it made the lock file.
        #: :meth:`discard_unused` removes only what this object created.
        self._created_dirs: list[Path] = []
        self._created_lock = False

    # --- lifecycle ------------------------------------------------------------------------------

    def open(self) -> None:
        """Create the directory, take its lock, and index any segments a previous process left.

        Raises :class:`SpoolUnavailable` when the directory cannot be used by this process."""
        lock_path = self.directory / _LOCK_NAME
        try:
            missing, node = [], self.directory
            while not node.exists() and node != node.parent:
                missing.append(node)
                node = node.parent
            self._created_lock = not lock_path.exists()
            self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            self._created_dirs = missing
            fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        except OSError as exc:
            self._remove_created_dirs()  # no lock file was made, so they are empty, or stay
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
        if self._lock_fd is not None:
            # Last try at files an earlier delete left: one that stays is replayed whole by the
            # next start, which cannot tell a sent segment from a waiting one.
            self.reclaim()
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

    def discard_unused(self) -> None:
        """Close, and remove the lock file and directory this :meth:`open` created, if the spool
        holds nothing (BACKLOG #2279).

        For a caller that opened the spool and then found it has no forwarder to put behind it.
        Without this, a start that failed left an empty directory and a ``spool.lock`` behind for
        a spool that never ran. Nothing that was there before is removed: not a directory that
        already existed, not a lock file an earlier run left, and never a directory holding a
        segment, which is undelivered evidence. Does nothing on a spool that does not hold the
        lock: the files may then be another process's."""
        if self._lock_fd is None:
            return
        empty = not self._sizes
        lock_path = self.directory / _LOCK_NAME
        if empty and self._created_lock and sys.platform != "win32":
            # POSIX: unlink while the lock is still held, so no other process can lock a file
            # that is about to vanish. Windows cannot delete an open file; it goes after close().
            with contextlib.suppress(OSError):
                lock_path.unlink()
        self.close()
        if not empty:
            return
        if self._created_lock and sys.platform == "win32":
            with contextlib.suppress(OSError):  # held open by another process: theirs now, keep it
                lock_path.unlink()
        self._remove_created_dirs()

    def _remove_created_dirs(self) -> None:
        """Remove the directories :meth:`open` created, leaf first, stopping at the first that is
        not empty (``rmdir`` refuses one)."""
        for directory in self._created_dirs:
            try:
                directory.rmdir()
            except OSError:
                break
        self._created_dirs = []

    # --- state ----------------------------------------------------------------------------------

    @property
    def bytes_used(self) -> int:
        """Bytes the segments occupy on disk, delivered-but-not-yet-deleted lines included."""
        return sum(self._sizes.values())

    @property
    def undeleted_segments(self) -> int:
        """Sent segments still on disk because their delete failed. Their bytes count in
        :attr:`bytes_used` until :meth:`reclaim` or :meth:`close` manages to delete them."""
        return len(self._undeleted)

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
            self._abandon_write()
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
            seq = self._last_seq + 1
            try:
                fd = os.open(self._path(seq), os.O_WRONLY | os.O_CREAT | os.O_EXCL | _BINARY, 0o600)
            except FileExistsError:
                self._last_seq = seq  # a leftover holds this number: step past it, or stick here
                raise
            # Taken only once the file exists, so a create the disk refused costs no number.
            self._last_seq = seq
            self._writer = os.fdopen(fd, "ab")
            self._write_seq = seq
            self._segments.append(seq)
            self._sizes[seq] = 0
        return self._writer

    def _abandon_write(self) -> None:
        """Close the write segment after a failed write, and leave no empty file behind.

        The writer is closed, not kept: a failed write may have put part of a line on disk, and an
        append after it would join two entries into one unreadable line. So the next append opens
        a new segment. While a disk stays full that used to leave one EMPTY file, and burn one
        sequence number, for every record (BACKLOG #2279). An empty segment is deleted here and
        its number handed back; one that holds bytes is kept and its real size counted."""
        seq = self._write_seq
        self._close_writer()
        if seq is None:
            return  # the create itself failed: there is no file
        try:
            on_disk = self._path(seq).stat().st_size
        except OSError:
            return
        if on_disk:
            self._sizes[seq] = on_disk
            return
        self._retire(seq)
        if seq not in self._undeleted:
            # The write segment is always the newest number, and its file is gone, so handing the
            # number back cannot collide with anything on disk.
            self._last_seq = seq - 1

    def _close_writer(self) -> None:
        if self._writer is not None:
            with contextlib.suppress(OSError):
                self._writer.close()
        self._writer = None
        self._write_seq = None

    # --- read side ------------------------------------------------------------------------------

    def peek(self) -> SpoolEntry | None:
        """The oldest undelivered entry, or ``None`` when the spool is drained OR cannot be read just
        now. Idempotent until :meth:`advance`.

        A read error never escapes: ``QueueListener`` catches only ``queue.Empty``, so an exception
        here would end the listener thread for good. Only a segment that is GONE is retired; any
        other ``OSError`` (out of descriptors, a sharing violation) keeps every file and returns
        ``None``, so the caller tries again later instead of deleting undelivered records."""
        try:
            entry = self._peek()
            self.read_faulted = False
            return entry
        except FileNotFoundError:
            self.unreadable += 1
            seq = self._segments[0] if self._segments else None
            if seq is not None:
                if seq == self._write_seq:
                    self._close_writer()
                self._retire(seq)
            return None
        except OSError:
            self.read_errors += 1
            self.read_faulted = True
            self._close_reader()
            return None

    def _close_reader(self) -> None:
        if self._reader is not None:
            with contextlib.suppress(OSError):
                self._reader.close()
        self._reader = None
        self._read_seq = None

    def _peek(self) -> SpoolEntry | None:
        while self._peeked is None:
            if not self._segments:
                return None
            seq = self._segments[0]
            if self._reader is None or self._read_seq != seq:
                self._open_reader(seq)  # an OSError here is peek()'s to classify
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
        self._segments.remove(seq)
        if self._unlink(seq):
            self._sizes.pop(seq, None)
        else:
            # Still on disk, so still counted. Dropping its size here would let the directory
            # grow past the cap by one segment for every delete that failed (BACKLOG #2279).
            self._undeleted.append(seq)

    def _unlink(self, seq: int) -> bool:
        """Delete segment ``seq``'s file. Whether it is gone afterwards."""
        try:
            self._path(seq).unlink(missing_ok=True)
        except OSError:
            return False
        return True

    def reclaim(self) -> None:
        """Try again to delete the sent segments whose delete failed, and stop counting those now
        gone. One ``unlink`` per leftover, so the caller decides how often: nothing in this class
        calls it per record."""
        freed = [seq for seq in self._undeleted if self._unlink(seq)]
        for seq in freed:
            self._undeleted.remove(seq)
            self._sizes.pop(seq, None)


#: ``O_BINARY`` on Windows (no newline translation), zero elsewhere.
_BINARY: int = getattr(os, "O_BINARY", 0)
