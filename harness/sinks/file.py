# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""File sink: record each file an engine File outbound writes into a directory, and where.

Files present when the sink starts are ignored while they stay unchanged, so a long-lived output
directory cannot satisfy a scenario with an earlier run's output; a file written again in place,
whether present at start or already recorded, is recorded again. "Unchanged" is the ``lstat``
identity, file type, size and modification time, and a file that changes while it is read is
recorded once it settles, not twice. The scan enters only what ``lstat`` reads as a plain
directory, never a link or a junction, except in the Windows folder-swap race this module names
as open, and records each file's path relative to it
(``meta["relpath"]``) and whether it stays inside it (``meta["inside"]``): for a link, whether its
resolved path, symlinks followed, does; for a file the walk reached through held folder handles,
true, since each folder on the way was opened relative to its parent; for a file the by-path walk
read, whether its folder's resolved path does. A link that cannot be resolved strictly (a loop, a
dangling link, a race) is recorded as not inside, never as inside. A file written OUTSIDE the directory is not looked for
here; a scenario that tests for an escape must look where it would land, and a link the sink
records unread carries no control id, so a scenario must check ``meta["symlink"]`` itself.

**The walk, and the race it closes where the OS allows.** The sink directory itself must be a plain
directory, not a link or a junction: :meth:`FileSink.start` refuses one.
`FileSink.start` refuses a root it cannot read. A scan that finds it swapped for another
directory, a link or a non-directory records the :data:`ROOT_CHANGED` refusal once and scans
nothing; one that cannot open or list it for another reason (missing for now, permissions, no free
handle) logs it once and is retried on the next scan. Where the OS lets a directory be opened and listed by handle (``dir_fd``, at least Linux
and macOS), the walk holds each folder open: a sub-folder is opened by name relative to its parent's
handle with ``O_NOFOLLOW`` and checked to be the one its ``lstat`` saw, and each file is opened
the same way, so a folder or file swapped for a link during the scan is not followed. Windows has
no ``dir_fd``: there each folder is listed by path, so a folder swapped for a link or junction
between its ``lstat`` and its listing is still listed and its files read. That is an open race on
Windows. On every platform a file's open handle must be the file its ``lstat`` saw (identity, type,
size and modification time), checked again after the read, so a file swapped for a link, or
replaced, between the ``lstat`` and the open is not read under the old signature. A link found at
the open and still at the path (refused by ``O_NOFOLLOW``, or on Windows followed by the open) is
recorded as a link, unread; anything else is logged and left for the next scan. One scan stops at
:attr:`FileSink.max_depth` folders deep, recording the :data:`WALK_BOUND` refusal once per sink,
and enters each folder at most once (where the volume reports file ids), so a walk that escaped
through a sub-folder cannot descend without end. The number of names a scan lists is not
bounded: a large output directory starts and is polled whole.

Reading is bounded the way the GUI's folder watcher is, through the same reader
(:func:`harness.bounded_file.read_fd_capped`): regular files only, nothing read through a
symbolic link or junction on platforms with ``dir_fd``, each
capped at the engine's per-message cap, checked on the open handle, and an over-cap file recorded with an empty payload and a ``refused`` reason rather
than read. Only a plain directory is skipped: a symlink (``meta["symlink"]``), FIFO or device is
recorded unread with the :data:`~harness.bounded_file.NOT_REGULAR` reason, so a link out of the
directory reads as an escape, not as nothing. A listed name that :func:`_unsafe_listed_name` refuses
is never joined onto its folder: it is recorded once, unread, with the :data:`UNSAFE_NAME` reason,
its folder's relative path (``meta["folder"]``) and no ``path`` or ``relpath``. A folder that cannot
be listed, an entry that cannot be ``lstat``-ed and a file that cannot be opened are logged at
WARNING, once per entry and kind of fault for the sink's life, and retried on the next scan; an
entry gone before its ``lstat`` is skipped unlogged. The log names no listed entry, since a File outbound can render a
name from HL7 fields: only the kind of fault and the OS error number.
"""

from __future__ import annotations

import errno
import functools
import logging
import ntpath
import os
import stat
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from harness.bounded_file import LINK_ERRNOS, NOT_REGULAR, over_cap, read_fd_capped
from harness.endpoints import Endpoints
from harness.sinks import Record, Sink
from messagefoundry.parsing.peek import DEFAULT_MAX_MESSAGE_BYTES

KIND = "file"

_log = logging.getLogger(__name__)

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

#: Whether the walk holds each folder open and opens what is under it relative to that handle. A
#: module flag, so a test can exercise the by-path walk where the OS has ``dir_fd`` too.
_DIR_FD = (
    {os.open, os.stat} <= os.supports_dir_fd
    and os.scandir in os.supports_fd
    and hasattr(os, "O_DIRECTORY")
    and hasattr(os, "O_NOFOLLOW")
)

_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
#: A folder: never through a link as its last component.
_DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | _NOFOLLOW | _CLOEXEC
#: A file: non-blocking so a FIFO swapped in after the ``lstat`` cannot hang the open.
_FILE_FLAGS = (
    os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0) | _NOFOLLOW | _CLOEXEC
)

#: The ``refused`` reason for a listed name :func:`_unsafe_listed_name` refuses.
UNSAFE_NAME = "unsafe name"
#: The ``refused`` reason for a scan that found the sink directory is no longer what it started on.
ROOT_CHANGED = "the sink directory is not the plain directory the sink started on; not scanned"
#: The ``refused`` reason for a scan that stopped at :attr:`FileSink.max_depth`.
WALK_BOUND = "the scan reached its depth bound; the rest was not scanned"

#: Opens a listed file for reading, relative to its held folder or by its path.
_Opener = Callable[[], int]
#: ``lstat``-s a listed entry again, the same way.
_Restat = Callable[[], os.stat_result]
#: Called with each candidate's path, its ``lstat``, and how to open it and ``lstat`` it again,
#: while its folder is held.
_Visit = Callable[[Path, os.stat_result, _Opener, _Restat], None]


def _signature(st: os.stat_result) -> _Signature:
    return (st.st_dev, st.st_ino, stat.S_IFMT(st.st_mode), st.st_size, st.st_mtime_ns)


def _is_link(st: os.stat_result) -> bool:
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_reparse_tag", 0) & _NAME_SURROGATE)


def _unsafe_listed_name(name: str) -> bool:
    """Whether a name read back from a listing must not be joined onto its folder.

    On every platform: an empty name, ``.``, ``..``, or one holding a path separator or a NUL. On
    Windows also: one holding a colon, which pathlib reads as a drive, so the join no longer names
    the listed entry (``C:`` or ``D:x`` joins to the folder or to a path on that drive, depending on
    which drive the folder is on) or which names an alternate data stream; and one
    :func:`ntpath.isreserved` reports. That covers at least a trailing dot or space (Windows strips
    it, so ``...`` reads as the folder itself) and ``nul``, which names the NUL device. It also
    refuses ``NUL.txt`` because ``ntpath.isreserved`` reports it, and it over-refuses at least
    ``COM1.hl7``, ``con.txt`` and ``aux.hl7``, which modern Windows treats as ordinary files: they
    are recorded refused and unread, the fail-closed side."""
    if name in ("", ".", ".."):
        return True
    separators = {"/", "\\"} if _WINDOWS else {os.sep, os.altsep or os.sep}
    if "\0" in name or any(sep in name for sep in separators):
        return True
    return _WINDOWS and (":" in name or ntpath.isreserved(name))


def _identity(st: os.stat_result) -> tuple[int, int] | None:
    """``(st_dev, st_ino)``, or None where the volume reports no file id (``st_ino`` 0), so two
    different entries cannot be taken for one."""
    return (st.st_dev, st.st_ino) if st.st_ino else None


def _why(exc: OSError) -> str:
    """An OS error for the log without its file name: a File outbound can render a name from HL7
    fields, so names stay out of the general log, as ``harness/file_transport.py`` keeps them."""
    return f"{type(exc).__name__}, errno {exc.errno}"


@dataclass
class _Scan:
    """One scan's running state: the names it refused, what bounds it, and what it has entered.
    ``failed`` is set when the directory itself could not be opened or listed, so the scan says
    nothing about what is there; ``error`` is why, where an OS error said. A folder or entry under
    it that could not be read is logged and skipped."""

    unsafe: list[tuple[Path, str]] = field(default_factory=list)
    entered: set[tuple[int, int]] = field(default_factory=set)
    bounded: bool = False
    failed: bool = False
    error: OSError | None = None


class FileSink(Sink):
    kind = KIND

    #: The deepest a scan descends below the sink directory.
    max_depth = 32

    def __init__(self, directory: str | Path, *, pattern: str = "*") -> None:
        super().__init__()
        self.directory = Path(directory)
        self.pattern = pattern
        self._seen: dict[Path, _Signature] = {}
        #: Listed names refused unjoined, as ``(folder, name)``: each is recorded once.
        self._seen_unsafe: set[tuple[Path, str]] = set()
        #: Scan-wide refusals (:data:`ROOT_CHANGED`, :data:`WALK_BOUND`) already recorded.
        self._reported: set[str] = set()
        #: What has been logged, so a fault that persists is logged once, not on every poll.
        self._warned: set[tuple[str, Path]] = set()
        #: The sink directory's ``(st_dev, st_ino)`` as :meth:`start` found it.
        self._root_id: tuple[int, int] | None = None
        #: Whether :meth:`start` has finished, and whether its first scan is running.
        self._started = False
        self._starting = False
        #: The most one file may hold and still be read: the engine's per-message cap.
        self.max_file_bytes = DEFAULT_MAX_MESSAGE_BYTES

    def start(self) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        st = self.directory.lstat()
        if _is_link(st) or not stat.S_ISDIR(st.st_mode):
            raise NotADirectoryError(
                f"file sink directory {self.directory} is a link, a junction or not a directory"
            )
        self._root_id = _identity(st)
        seen: dict[Path, _Signature] = {}
        self._starting = True
        try:
            scan = self._scan(
                lambda path, st, _open, _again: seen.__setitem__(path, _signature(st))
            )
        finally:
            self._starting = False
        if scan is None or scan.failed:
            # Without a whole first scan, files already there would later read as new deliveries.
            error = scan.error if scan is not None else None
            why = f" ({_why(error)})" if error is not None else ""
            raise NotADirectoryError(
                f"file sink directory {self.directory} could not be scanned{why}"
            ) from error
        self._started = True
        self._seen = seen
        self._seen_unsafe = set(scan.unsafe)
        if scan.bounded:
            self._report(WALK_BOUND)  # files past the bound were not taken as already there

    def _warn(self, kind: str, where: Path, message: str, *args: object) -> None:
        """Log ``message`` at WARNING once per ``(kind, where)``; ``where`` itself is not logged."""
        if (kind, where) in self._warned:
            return
        self._warned.add((kind, where))
        _log.warning(message, *args)

    def _matches(self, path: Path) -> bool:
        """Whether ``path`` matches :attr:`pattern`, relative to the directory. Right-anchored, so
        ``*`` matches a file at any depth, as it always has; or matched whole, so ``**/*.hl7``
        matches a top-level file too (``**`` is zero or more folders there)."""
        relative = path.relative_to(self.directory)
        return relative.match(self.pattern) or relative.full_match(self.pattern)

    def _file_name(self, path: Path, name: str) -> bool:
        """Whether a file of this name is a candidate: on the pattern, not a dot-file, and not one
        of the engine's temps."""
        return (
            self._matches(path)
            and not name.startswith(".")
            and path.suffix not in _ENGINE_TEMP_SUFFIXES
        )

    def _scan(self, visit: _Visit) -> _Scan | None:
        """Walk the directory, calling ``visit`` for each candidate while its folder is held, and
        return the scan's state; or None, with nothing visited, when something is at the path and
        it is not the plain directory :meth:`start` found. A directory that cannot be opened or
        listed for another reason (missing for now, permissions, no free handle) is a failed
        scan, retried next time, not a replaced one. Each listed name is checked before it is joined onto its folder. A link, a
        junction included, is a candidate whatever its name and is not entered. A path gone
        before its ``lstat``, or a folder gone before it is listed, is left out: nothing is there
        to record or to ignore."""
        scan = _Scan()
        if _DIR_FD:
            try:
                root_fd = os.open(self.directory, _DIR_FLAGS)
            except OSError as exc:
                if exc.errno in LINK_ERRNOS or isinstance(exc, NotADirectoryError):
                    # A link or a non-directory, if something is at the path: present, and not
                    # the directory start() took. Otherwise an ancestor is missing or not a
                    # folder, and the next poll tries again.
                    try:
                        self.directory.lstat()
                    except OSError:
                        return self._root_unreadable(scan, exc)
                    return self._root_gone(exc)
                return self._root_unreadable(scan, exc)  # missing now, or unreadable: retried
            try:
                st = os.fstat(root_fd)
                if not self._root_is(st):
                    return self._root_gone(None)
                if (identity := _identity(st)) is not None:
                    scan.entered.add(identity)
                if not self._walk(root_fd, self.directory, 0, visit, scan):
                    scan.failed = True
            except OSError as exc:
                return self._root_unreadable(scan, exc)
            finally:
                os.close(root_fd)
            return scan
        try:
            st = self.directory.lstat()
        except OSError as exc:
            return self._root_unreadable(scan, exc)  # missing now, or unreadable: retried
        if _is_link(st) or not stat.S_ISDIR(st.st_mode) or not self._root_is(st):
            return self._root_gone(None)
        if (identity := _identity(st)) is not None:
            scan.entered.add(identity)
        if not self._walk(self.directory, self.directory, 0, visit, scan):
            scan.failed = True
        return scan

    def _root_gone(self, exc: OSError | None) -> _Scan | None:
        """Log, once, that the path is a link, a non-directory or another directory now; None, the
        scan's answer for that."""
        reason = f" ({_why(exc)})" if exc is not None else ""
        self._warn(
            "root",
            self.directory,
            "file sink: %s is no longer the plain directory it started on%s",
            self.directory,
            reason,
        )
        return None

    def _root_unreadable(self, scan: _Scan, exc: OSError) -> _Scan:
        """A failed scan, logged once as retried. At :meth:`start` it is raised with ``exc``
        rather than retried, so it is not logged there."""
        if not self._starting:
            self._warn(
                "root-read",
                self.directory,
                "file sink: cannot read %s, retried next scan (%s)",
                self.directory,
                _why(exc),
            )
        scan.failed = True
        scan.error = exc
        return scan

    def _root_is(self, st: os.stat_result) -> bool:
        """Whether ``st`` is the directory :meth:`start` found (or, unstarted, take it as that).
        Where the volume reports no file id now, that cannot be told, and it is taken as the same.
        A file id where :meth:`start` found none is not the directory it found."""
        identity = _identity(st)
        if self._root_id is None:
            if self._started:
                return identity is None
            self._root_id = identity
        return identity is None or identity == self._root_id

    def _walk(self, held: int | Path, folder: Path, depth: int, visit: _Visit, scan: _Scan) -> bool:
        """List ``folder``, held as a directory handle where the OS has ``dir_fd`` and by its path
        otherwise, and visit or enter each entry under it. False when ``folder`` itself could not
        be listed."""
        try:
            with os.scandir(held) as listing:
                names = [entry.name for entry in listing]
        except OSError as exc:
            if depth == 0:
                # The directory itself, gone included: a failed scan, so start() does not take an
                # empty first scan for a whole one.
                self._root_unreadable(scan, exc)
                return False
            if isinstance(exc, FileNotFoundError):
                return True  # a sub-folder gone: nothing there to record or to ignore
            self._warn(
                "list", folder, "file sink: cannot list a folder, retried next scan (%s)", _why(exc)
            )
            return False
        for name in sorted(names):
            if _unsafe_listed_name(name):
                scan.unsafe.append((folder, name))
                continue
            path = folder / name
            try:
                if isinstance(held, int):
                    st = os.stat(name, dir_fd=held, follow_symlinks=False)
                else:
                    st = path.lstat()
            except FileNotFoundError:
                continue
            except OSError as exc:
                self._warn(
                    "lstat",
                    path,
                    "file sink: cannot lstat an entry, retried next scan (%s)",
                    _why(exc),
                )
                continue
            link = _is_link(st)
            if stat.S_ISDIR(st.st_mode) and not link:
                identity = _identity(st)
                if depth + 1 > self.max_depth:
                    scan.bounded = True
                elif identity is None or identity not in scan.entered:
                    if identity is not None:
                        scan.entered.add(identity)
                    self._enter(held, name, path, st, depth, visit, scan)
            elif link or self._file_name(path, name):
                # A link is never an engine temp, so no name or pattern keeps one out.
                again: _Restat
                if isinstance(held, int):
                    opener = functools.partial(os.open, name, _FILE_FLAGS, dir_fd=held)
                    again = functools.partial(os.stat, name, dir_fd=held, follow_symlinks=False)
                else:
                    opener = functools.partial(os.open, path, _FILE_FLAGS)
                    again = path.lstat
                visit(path, st, opener, again)
        return True

    def _enter(
        self,
        held: int | Path,
        name: str,
        path: Path,
        st: os.stat_result,
        depth: int,
        visit: _Visit,
        scan: _Scan,
    ) -> None:
        """Walk the sub-folder ``name``. Under a held handle it is opened relative to that handle,
        never through a link, and entered only if it is the folder its ``lstat`` saw. A folder that
        cannot be entered or listed is logged once and skipped."""
        if not isinstance(held, int):
            self._walk(path, path, depth + 1, visit, scan)
            return
        try:
            child = os.open(name, _DIR_FLAGS, dir_fd=held)
        except FileNotFoundError:
            return
        except OSError as exc:
            if exc.errno in LINK_ERRNOS or exc.errno == errno.ENOTDIR:
                said = "file sink: not entering a folder that is no longer a plain folder (%s)"
                self._warn("enter-link", path, said, _why(exc))
            else:
                said = "file sink: cannot open a folder, retried next scan (%s)"
                self._warn("enter-open", path, said, _why(exc))
            return
        try:
            if _identity(os.fstat(child)) != _identity(st):
                said = "file sink: not entering a folder replaced after its lstat"
                self._warn("enter-swap", path, said)
                return
            self._walk(child, path, depth + 1, visit, scan)
        except OSError as exc:
            said = "file sink: cannot read a folder, retried next scan (%s)"
            self._warn("enter-read", path, said, _why(exc))
        finally:
            os.close(child)

    def _read(
        self, path: Path, opener: _Opener, again: _Restat, signature: _Signature
    ) -> tuple[bytes, str, _Signature | None] | None:
        """``(data, refused, None)`` for the file its ``lstat`` saw, or None to retry on the next
        scan: the open failed, or the open handle is not that file (replaced, or written to) before
        or during the read. Judged on the handle, so a file replaced at its path right after the
        read is still recorded as what was read. A link found at the open and still at the path,
        refused by ``O_NOFOLLOW`` or followed by the open (Windows), is ``(b"", NOT_REGULAR, <the
        link's signature>)``: nothing is read through it, and it is recorded as a link."""
        try:
            fd = opener()
        except FileNotFoundError:
            return None
        except OSError as exc:
            if exc.errno in LINK_ERRNOS:  # O_NOFOLLOW refused a link swapped in after the lstat
                return self._not_the_file(path, again)
            self._warn(
                "open", path, "file sink: cannot open a file, retried next scan (%s)", _why(exc)
            )
            return None
        try:
            if _signature(os.fstat(fd)) != signature:
                return self._not_the_file(path, again)
            data, refused = read_fd_capped(fd, self.max_file_bytes)
            if _signature(os.fstat(fd)) != signature:
                return None  # changed while read: the next scan records what it settled to, once
        except OSError as exc:
            self._warn(
                "read", path, "file sink: cannot read a file, retried next scan (%s)", _why(exc)
            )
            return None
        finally:
            os.close(fd)
        return data, refused, None

    def _not_the_file(
        self, path: Path, again: _Restat
    ) -> tuple[bytes, str, _Signature | None] | None:
        """The open did not reach the file the ``lstat`` saw. Where the entry is a link now, read
        again the way the walk read it (through its held folder, where it holds one), that is
        recorded as a link, unread, under the link's own signature. Otherwise (replaced, or a link
        swapped in and back again) it is logged and the next scan ``lstat``-s what is there now,
        so a file restored at the path is still read."""
        try:
            now = again()
        except FileNotFoundError:
            return None
        except OSError as exc:
            self._warn(
                "relstat",
                path,
                "file sink: cannot lstat a file again, retried next scan (%s)",
                _why(exc),
            )
            return None
        if _is_link(now):
            return b"", NOT_REGULAR, _signature(now)
        self._warn(
            "swap",
            path,
            "file sink: a file was replaced or swapped between its lstat and its open; not read, "
            "retried next scan",
        )
        return None

    def _inside(self, path: Path, link: bool, root: Path, by_handle: bool) -> bool:
        """Whether ``path`` resolves inside ``root``; False where that cannot be shown. A link is
        resolved strictly, so a loop or a dangling link is not inside. A file the walk reached
        through held folder handles (``by_handle``, given only where the root's file id showed it
        is the directory :meth:`start` found) is inside: each folder on the way was opened
        relative to its parent, never through a link. A file the by-path walk read is judged by its folder, which the walk reached
        through what ``lstat`` read as plain directories, so a file that vanishes after its read
        is not mistaken for an escape. Where the walk lists by path (Windows), a folder swapped for
        a link and back during the scan defeats this check: the open race in the module
        docstring."""
        if by_handle and not link:
            return True
        try:
            if link:
                return path.resolve(strict=True).is_relative_to(root)
            return (path.parent.resolve(strict=True) / path.name).is_relative_to(root)
        except OSError:
            return False

    def _report(self, reason: str) -> None:
        """Record a scan-wide refusal, once."""
        if reason in self._reported:
            return
        self._reported.add(reason)
        meta = {"name": self.directory.name, "folder": ".", "inside": "false", "refused": reason}
        self._add(Record(b"", meta))

    def records(self) -> list[Record]:
        root = self.directory.resolve()
        #: What this scan found, kept apart until the walk returns: a path's signature is
        #: remembered only together with its record, so a scan that ends early loses neither.
        found: list[tuple[Path, _Signature, Record]] = []

        # Read once, as _scan reads _DIR_FD, so each record is judged by the walk that found it.
        # Without the root's file id the handle walk cannot show its root is the directory start()
        # found (an ancestor may have been swapped for a link), so files are judged by path then.
        by_handle = _DIR_FD and self._root_id is not None

        def visit(path: Path, st: os.stat_result, opener: _Opener, again: _Restat) -> None:
            signature = _signature(st)
            if self._seen.get(path) == signature:
                return
            link = _is_link(st)
            if link or not stat.S_ISREG(st.st_mode):
                data, refused = b"", NOT_REGULAR  # never opened: not through a link, not a FIFO
            elif st.st_size > self.max_file_bytes:
                # Refused from the lstat size, never opened, as read_capped refuses it.
                data, refused = b"", over_cap(st.st_size, self.max_file_bytes)
            else:
                read = self._read(path, opener, again, signature)
                if read is None:
                    return
                data, refused, link_signature = read
                if link_signature is not None:  # a link found at the open: remember it as one
                    link, signature = True, link_signature
            inside = self._inside(path, link, root, by_handle)
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
            found.append((path, signature, Record(data, meta)))

        scan = self._scan(visit)
        if scan is None:
            self._report(ROOT_CHANGED)
            return super().records()
        for folder, name in sorted(scan.unsafe):
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
        for path, signature, record in sorted(found, key=lambda item: item[0]):
            self._seen[path] = signature
            self._add(record)
        if scan.bounded:
            self._warn("bound", self.directory, "file sink: a scan of %s reached its bound", root)
            self._report(WALK_BOUND)
        return super().records()


def build(endpoints: Endpoints, key: str) -> Sink:
    return FileSink(endpoints.value(key))
