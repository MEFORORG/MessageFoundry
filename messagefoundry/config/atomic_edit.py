# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The one write path the four config editors share: validate a candidate, then replace the live file.

``alerts_edit``, ``security_edit``, ``codeset_edit`` and ``connections_edit`` each rewrite one file an
operator also edits by hand. Each used to carry its own copy of the write: three of the four wrote a
fixed ``<name>.tmp`` at the process umask, all four put the unvalidated text at the live path for the
length of the validation and rolled it back afterwards, and the rollback skipped the owner-only
restriction (vault BACKLOG #2782). One copy here replaces the four.

:func:`replace_validated` writes the new bytes to a CANDIDATE that carries the live file's own name,
inside a private directory created beside it (unique, and on POSIX owner-only from creation: mode
0700 for the directory and 0600 for the file; same filesystem, so the final ``os.replace`` is atomic).
On Windows those modes are ignored and the candidate carries the directory's inherited access list
until ``store._secure_file`` restricts the replaced file, the same window the old ``mkstemp`` writer
had; the directory's own access list is the control there (``docs/SERVICE.md``). The caller's ``validate`` runs against that candidate. Only a candidate
that validates replaces the live file, so a refused edit never touches the live file at all: its bytes
and its permission bits stay exactly as they were, and there is no rollback write to get wrong.

The candidate keeps the live file's NAME because the loaders read meaning from it: a code set's name is
its file stem and its format is its suffix, and ``connections.toml`` is found by name. ``companions``
copies sibling files the loader reads beside the candidate, such as a code set's policy sidecar.

:func:`edit_lock` is the cross-process half. The engine serialises its own writers with an
``asyncio.Lock``, which the ``connection`` CLI in another process cannot see, so a CLI edit and a
console edit could each read the same original and the second replace would drop the first. The lock
is an OS lock on one hidden file per DIRECTORY, ``.mefor-edit.lock`` beside the edited file, held from
the read through the replace. One per directory rather than one per file, so a code-set rename or
remove covers both of its names with one lock and a renamed table leaves no lock file behind. It never
runs on an event loop: the engine's one caller already moves the whole write to a worker thread.

:func:`read_text` and :func:`encode_text` keep a file's line endings: the editors parse and dump with
``\n``, and a file written wholly in ``\r\n`` is written back that way rather than reflowed.
"""

from __future__ import annotations

import contextlib
import errno
import logging
import os
import shutil
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path

__all__ = [
    "DEFAULT_LOCK_TIMEOUT_S",
    "LOCK_FILE_NAME",
    "edit_lock",
    "encode_text",
    "lock_path_for",
    "read_text",
    "replace_validated",
]

_log = logging.getLogger(__name__)

#: How long an edit waits for another editor to finish before it gives up. An edit holds the lock for
#: one parse, one validation and one rename, so a wait this long means a stuck holder, not a busy one.
DEFAULT_LOCK_TIMEOUT_S = 30.0

#: The lock file, one per directory holding an edited file.
LOCK_FILE_NAME = ".mefor-edit.lock"

#: The poll interval while another editor holds the lock.
_LOCK_POLL_S = 0.05

#: ``errno`` values meaning the file system cannot lock at all (an NFS mount with no lock daemon, some
#: FUSE and SMB mounts), as opposed to a lock someone else holds. The same set ``dr_backup`` reads.
_LOCK_UNSUPPORTED = frozenset({errno.ENOLCK, errno.EOPNOTSUPP, errno.ENOTSUP})

#: Text-mode translation would rewrite every ``\n`` as ``\r\n`` on Windows; the bytes go out verbatim.
_O_BINARY = getattr(os, "O_BINARY", 0)

# Lock files this THREAD already holds, so a caller that takes the lock around a wider read (the
# engine's list-then-upsert) can call a writer that takes it again. A second ``flock`` on a new handle
# in the same process would wait on the first one forever.
_held = threading.local()


def lock_path_for(path: Path) -> Path:
    """The lock file guarding edits to ``path``, and to every other file in its directory."""
    return path.with_name(LOCK_FILE_NAME)


def read_text(path: Path) -> tuple[str, bool]:
    """``path`` as UTF-8 text with ``\n`` line endings, and whether EVERY line ended ``\r\n``.

    A file with mixed endings reads as ``\n``, the editors' own form, rather than being
    reflowed to ``\r\n`` on the strength of one line."""
    raw = path.read_bytes()
    crlf = raw.count(b"\r\n")
    return raw.decode("utf-8").replace("\r\n", "\n"), crlf > 0 and crlf == raw.count(b"\n")


def encode_text(text: str, crlf: bool) -> bytes:
    """``text`` (``\n`` endings) as the UTF-8 bytes to write, with ``\r\n`` endings when ``crlf``."""
    return (text.replace("\n", "\r\n") if crlf else text).encode("utf-8")


@contextlib.contextmanager
def edit_lock(
    path: Path,
    *,
    busy_error: Callable[[str], Exception] = TimeoutError,
    timeout: float = DEFAULT_LOCK_TIMEOUT_S,
) -> Iterator[None]:
    """Hold the cross-process edit lock for ``path`` for the body of the ``with``.

    Blocking: call it from a worker thread, never from a coroutine. Re-entrant within one thread. When
    another process or thread still holds it after ``timeout`` seconds, raises ``busy_error(message)``,
    which each editor sets to its own refusal type so its callers catch one exception as before. A file
    system that cannot lock is logged and the edit proceeds unlocked, since the lock guards against a
    lost update, not against a reader of the file."""
    lock_path = lock_path_for(path)
    key = os.path.normcase(str(lock_path.resolve()))
    held: set[str] = _held.__dict__.setdefault("paths", set())
    if key in held:
        yield
        return
    # Read-only and readable by all: the file holds no data, a lock needs only an open handle,
    # and an editor running as another account (an operator's CLI beside the service) must
    # still be able to open a lock file the other one created.
    fd = os.open(lock_path, os.O_RDONLY | os.O_CREAT | _O_BINARY, 0o644)
    try:
        locked = _acquire(fd, lock_path, path, busy_error, timeout)
        held.add(key)
        try:
            yield
        finally:
            held.discard(key)
            if locked:
                _release(fd)
    finally:
        # Closing the handle also drops the lock. The lock FILE stays: unlinking it while another
        # editor waits on its open handle would let a third editor lock a new file beside it.
        with contextlib.suppress(OSError):
            os.close(fd)


def replace_validated(
    path: Path,
    data: bytes,
    validate: Callable[[Path], None],
    *,
    companions: Iterable[Path] = (),
) -> None:
    """Replace ``path`` with ``data`` only if ``validate`` accepts a candidate holding ``data``.

    The candidate is ``<private dir>/<path.name>``, the private directory a unique one created beside
    ``path``. Each existing file in ``companions`` is copied beside the candidate first. ``validate``
    receives the candidate path and raises to refuse; the refusal propagates unchanged and the live
    file is left byte-for-byte and mode-for-mode as it was. On success the candidate is renamed over
    ``path`` and re-restricted to its owner. The private directory is removed either way."""
    private = Path(tempfile.mkdtemp(dir=path.parent, prefix=f".{path.name}.", suffix=".edit"))
    try:
        candidate = private / path.name
        fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_BINARY, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            # On disk before the rename, so a crash just after it cannot leave an empty live file.
            handle.flush()
            os.fsync(handle.fileno())
        for companion in companions:
            if companion.is_file():
                shutil.copyfile(companion, private / companion.name)
        validate(candidate)
        os.replace(candidate, path)
    finally:
        _remove_private_dir(private)
    _fsync_dir(path.parent)
    _secure_file(path)


def _acquire(
    fd: int,
    lock_path: Path,
    path: Path,
    busy_error: Callable[[str], Exception],
    timeout: float,
) -> bool:
    """Take the lock on ``fd``, polling until ``timeout``. ``False`` when the file system cannot lock."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            if _try_lock(fd):
                return True
        except OSError as exc:
            if exc.errno not in _LOCK_UNSUPPORTED:
                raise
            _log.warning(
                "%s: the file system cannot lock %s (%s); editing without the cross-process lock",
                path,
                lock_path,
                exc,
            )
            return False
        if time.monotonic() >= deadline:
            raise busy_error(
                f"another edit of {path} is still in progress after {timeout:g}s "
                f"(it holds {lock_path}); try again once it finishes"
            )
        time.sleep(_LOCK_POLL_S)


def _try_lock(fd: int) -> bool:
    """One non-blocking attempt at an exclusive lock. ``False`` when another handle holds it.

    ``flock`` on POSIX, not ``lockf``: a ``lockf`` lock belongs to the process, so two threads of one
    process would not exclude each other. ``msvcrt.locking`` on Windows is per handle already."""
    if sys.platform == "win32":
        import msvcrt

        os.lseek(fd, 0, os.SEEK_SET)
        try:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        except OSError as exc:
            # A held range refuses with EACCES or EDEADLOCK, the CRT's two contention codes (the same
            # reading as `pipeline/dr_backup.py` and `api/tls.py`). Anything else is a real fault.
            if exc.errno not in (errno.EACCES, errno.EDEADLOCK):
                raise
            return False
        return True
    import fcntl

    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return False
    return True


def _release(fd: int) -> None:
    """Drop the lock on ``fd``. A failure is harmless: closing the handle drops it anyway."""
    with contextlib.suppress(OSError):
        if sys.platform == "win32":
            import msvcrt

            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_UN)


def _fsync_dir(directory: Path) -> None:
    """Make the rename durable (POSIX). Windows has no directory handle to flush; NTFS journals it."""
    if sys.platform == "win32":
        return
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError as exc:
        _log.warning("could not open %s to flush the edit's rename: %s", directory, exc)
        return
    try:
        os.fsync(fd)
    except OSError as exc:
        _log.warning("could not flush the edit's rename in %s: %s", directory, exc)
    finally:
        os.close(fd)


def _remove_private_dir(private: Path) -> None:
    """Remove the candidate's private directory, logging rather than raising if it cannot be removed.

    A failure here must not mask the edit's own outcome: on success the live file is already replaced,
    and on a refusal the caller needs the validation error, not a cleanup error."""

    def _report(_func: object, target: str, exc: BaseException) -> None:
        _log.warning("could not remove the edit candidate %s: %s", target, exc)

    shutil.rmtree(private, onexc=_report)


def _secure_file(path: Path) -> None:
    # Owner-only permissions (defence in depth). Reuse the store's primitive, imported here rather than
    # at module top so the config layer does not pull the store package in at import time.
    from messagefoundry.store.store import _secure_file as _secure

    _secure(path)
