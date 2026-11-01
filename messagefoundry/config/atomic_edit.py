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

:func:`refused_as` turns a refusal from the file system into the editor's own refusal type, for at
least the lock, the read, the candidate, its companions and the replace, each of which leaves the
edited file as it was. Each editor names that type, so a root-owned or read-only config directory
reaches an operator as a refused edit and not as an unhandled ``OSError``. ``validate`` is not one of
those steps: what it raises is its own.
"""

from __future__ import annotations

import contextlib
import errno
import glob
import logging
import os
import re
import shutil
import stat
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path

from messagefoundry.config.key_file_access import _UNREACHABLE_WINERRORS
from messagefoundry.config.snapshot import is_missing_directory

__all__ = [
    "CANDIDATE_DIR_SUFFIX",
    "DEFAULT_LOCK_TIMEOUT_S",
    "LOCK_FILE_NAME",
    "edit_lock",
    "encode_text",
    "is_candidate_dir_name",
    "lock_path_for",
    "is_dir",
    "is_file",
    "read_text",
    "read_text_if_present",
    "refused_as",
    "replace_validated",
]

_log = logging.getLogger(__name__)

#: How long an edit waits for another editor to finish before it gives up. An edit holds the lock for
#: one parse, one validation and one rename, so a wait this long means a stuck holder, not a busy one.
DEFAULT_LOCK_TIMEOUT_S = 30.0

#: The lock file, one per directory holding an edited file.
LOCK_FILE_NAME = ".mefor-edit.lock"

#: The suffix of a candidate's private directory, ``.<name>.<random>.edit`` beside the edited
#: file. A reader that walks a config directory (the DR backup) skips these and the lock file.
CANDIDATE_DIR_SUFFIX = ".edit"

#: The exact name ``tempfile.mkdtemp`` gives a candidate directory: the file's name, then its
#: random part, eight characters with no dot, so an operator's own ``.x.edit`` directory and a
#: sibling file's candidates (``.<name>.bak.<random>.edit``) never match. A test pins this against
#: the real ``mkdtemp``, so a change in its naming fails loudly rather than leaking candidates.
#: A literal, so the static regex scanner and its ReDoS lint can read it; the trailing ``\.edit``
#: is ``CANDIDATE_DIR_SUFFIX``, which a test holds the two to.
_CANDIDATE_DIR_RE = re.compile(r"\.(?P<name>.+)\.[a-z0-9_]{8}\.edit")

#: A candidate directory older than this is a leftover from a killed editor, never a live edit:
#: a live one lasts one validation. Old enough to stay safe on a file system that cannot lock.
_STALE_CANDIDATE_S = 600.0

#: The poll interval while another editor holds the lock.
_LOCK_POLL_S = 0.05

#: ``errno`` values meaning the file system cannot lock at all (an NFS mount with no lock daemon, some
#: FUSE and SMB mounts), as opposed to a lock someone else holds. The same set ``dr_backup`` reads.
_LOCK_UNSUPPORTED = frozenset({errno.ENOLCK, errno.EOPNOTSUPP, errno.ENOTSUP})

#: ``errno`` values meaning the file system will not let this account read the file or write its
#: directory: a root-owned one, or a read-only mount. Only these become an editor's
#: ``refused_error`` at a read or a write; a full disk or a missing directory keeps its own
#: ``OSError``, so it is not reported as a permission. The stat gate has its own rule (:func:`is_file`).
_REFUSED = frozenset({errno.EACCES, errno.EPERM, errno.EROFS})

#: The ``step`` of a refused read, which :func:`_refusal` advises on differently: a read-only
#: directory refuses no read, so the write advice would send an operator to the wrong fix.
_READ_STEP = "read it"

#: The ``step`` of a stat that failed with no refusal in it: a broken link or a fault, which no
#: change of account cures.
_STAT_STEP = "stat it"

#: Windows also answers ``EACCES`` when another program holds the file open, and for most of these
#: steps nothing tells the two apart: ``open`` reports a sharing violation through the C runtime as
#: bare ``EACCES`` with no ``winerror``, and a replace over a held file reports the same
#: ``ERROR_ACCESS_DENIED`` as a true denial (both measured on Windows 11). So the wording on Windows
#: names both causes.
_WINDOWS = sys.platform == "win32"

#: Text-mode translation would rewrite every ``\n`` as ``\r\n`` on Windows; the bytes go out verbatim.
_O_BINARY = getattr(os, "O_BINARY", 0)

# Lock files this THREAD already holds, so a caller that takes the lock around a wider read (the
# engine's list-then-upsert) can call a writer that takes it again. A second ``flock`` on a new handle
# in the same process would wait on the first one forever.
_held = threading.local()


def lock_path_for(path: Path) -> Path:
    """The lock file guarding edits to ``path``, and to every other file in its directory."""
    return path.with_name(LOCK_FILE_NAME)


def is_candidate_dir_name(name: str, *, of: str | None = None) -> bool:
    """Whether ``name`` is a candidate's private directory, ``.<file>.<random>.edit``, and when
    ``of`` is given, a candidate of the file named ``of``."""
    match = _CANDIDATE_DIR_RE.fullmatch(name)
    return match is not None and (of is None or match.group("name") == of)


def read_text(path: Path, *, refused_error: Callable[[str], Exception]) -> tuple[str, bool]:
    """``path`` as UTF-8 text with ``\n`` line endings, and whether EVERY line ended ``\r\n``.

    A file with mixed endings reads as ``\n``, the editors' own form, rather than being
    reflowed to ``\r\n`` on the strength of one line. A refused read is raised as
    ``refused_error(message)``, as :func:`refused_as` says."""
    with refused_as(path, refused_error, _READ_STEP):
        raw = path.read_bytes()
    crlf = raw.count(b"\r\n")
    return raw.decode("utf-8").replace("\r\n", "\n"), crlf > 0 and crlf == raw.count(b"\n")


def read_text_if_present(
    path: Path, *, refused_error: Callable[[str], Exception]
) -> tuple[str | None, bool]:
    """:func:`read_text`, or ``(None, False)`` for a path that is no regular file, as for a file an
    edit is about to create."""
    if not is_file(path, refused_error=refused_error):
        return None, False
    return read_text(path, refused_error=refused_error)


def is_file(path: Path, *, refused_error: Callable[[str], Exception] | None) -> bool:
    """Whether ``path`` is a regular file, by the stat every config gate shares.

    Not ``Path.is_file``, which answers ``False`` for every stat that fails: a config file that is a
    link to an unmounted share, or into a directory this account cannot search, would read as absent,
    and an edit would start from an empty document and replace the link with it.

    ``False`` here means there is no file to lose: nothing at the path, or a name no file can have
    (:func:`~messagefoundry.config.snapshot.is_missing_directory`). So a bad path lists as empty, as
    ``Path.is_file`` answered. Every other failed stat is raised as ``refused_error(message)``, or as
    itself with no ``refused_error``: a link on the path that cannot be followed, a share Windows
    says it cannot reach, and any fault that does not say the file is gone. A link that ends at
    something other than a regular file answers ``False``. A share that reads as a plain missing
    path does too, because nothing tells the two apart (Windows answered error 3 for one)."""
    return _is_a(path, stat.S_ISREG, refused_error)


def is_dir(path: Path, *, refused_error: Callable[[str], Exception]) -> bool:
    """:func:`is_file`, for whether ``path`` is a directory."""
    return _is_a(path, stat.S_ISDIR, refused_error)


def _is_a(
    path: Path, kind: Callable[[int], bool], refused_error: Callable[[str], Exception] | None
) -> bool:
    try:
        return kind(path.stat().st_mode)
    except ValueError:  # an embedded NUL, which no path can hold
        return False
    except OSError as exc:
        if _nothing_there(path, exc):
            return False
        if refused_error is None:
            raise
        step = _READ_STEP if exc.errno in _REFUSED else _STAT_STEP
        raise refused_error(_refusal(path, exc, step)) from exc


def _nothing_there(path: Path, exc: OSError) -> bool:
    """Whether ``exc``, from a stat of ``path``, means no file is there to lose. The walk stops at
    the first entry that exists, so it costs a few calls, and only on a stat that failed."""
    if not is_missing_directory(exc) or getattr(exc, "winerror", None) in _UNREACHABLE_WINERRORS:
        return False
    for entry in (path, *path.parents):
        if os.path.exists(entry):
            return True
        if os.path.lexists(entry):  # a link or a Windows junction that cannot be followed
            return False
    return True


def encode_text(text: str, crlf: bool) -> bytes:
    """``text`` (``\n`` endings) as the UTF-8 bytes to write, with ``\r\n`` endings when ``crlf``."""
    return (text.replace("\n", "\r\n") if crlf else text).encode("utf-8")


@contextlib.contextmanager
def edit_lock(
    path: Path,
    *,
    busy_error: Callable[[str], Exception] = TimeoutError,
    timeout: float = DEFAULT_LOCK_TIMEOUT_S,
    refused_error: Callable[[str], Exception] | None = None,
) -> Iterator[None]:
    """Hold the cross-process edit lock for ``path`` for the body of the ``with``.

    Blocking: call it from a worker thread, never from a coroutine. Re-entrant within one thread. When
    another process or thread still holds it after ``timeout`` seconds, raises ``busy_error(message)``,
    which each editor sets to its own refusal type so its callers catch one exception as before. A file
    system that cannot lock is logged and the edit proceeds unlocked, since the lock guards against a
    lost update, not against a reader of the file. When the file system refuses to create the lock
    file (``EACCES``, ``EPERM`` or ``EROFS``: a root-owned or read-only directory), the ``OSError``
    propagates, or with ``refused_error`` set it is raised as ``refused_error(message)``."""
    lock_path = lock_path_for(path)
    key = os.path.normcase(str(lock_path.resolve()))
    held: set[str] = _held.__dict__.setdefault("paths", set())
    if key in held:
        yield
        return
    # Read-write off Windows, although nothing is written to it: an NFS client emulates flock with a
    # byte-range lock, and an exclusive one needs a writable handle or it fails EBADF (flock(2)), so
    # a read-only handle would fail every edit on NFS. Read-only on Windows, where msvcrt.locking
    # needs no more, and asking for write would be refused by a backup agent or scanner holding the
    # file with read sharing only. The cost, off Windows: a lock file this account cannot write, at
    # 0444 or at 0644 under another account, refuses the edit where a read-only open would have
    # locked it. The refusal names the lock file, and fixing its owner or mode cures it.
    # Owner-only, like the files it guards: every edit leaves the edited file 0600, so an account
    # that could not open a lock an editor created could not edit that file either, and root opens
    # a 0600 file regardless. Wider access gains nothing.
    # O_NOFOLLOW where the platform has it: a lock path planted as a link is refused, not followed.
    # O_NONBLOCK so a lock path planted as a FIFO cannot block the open before the timeout runs.
    flags = (os.O_RDONLY if _WINDOWS else os.O_RDWR) | os.O_CREAT | _O_BINARY
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        with refused_as(path, refused_error, f"create or open its edit lock {lock_path.name}"):
            fd = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        if exc.errno != errno.ELOOP:
            raise
        # In the editor's own refusal type, so its callers catch it as they catch a busy lock.
        raise busy_error(
            f"{lock_path} is a link; an edit of {path} will not lock through it -- remove it"
        ) from exc
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
    refused_error: Callable[[str], Exception] | None = None,
) -> None:
    """Replace ``path`` with ``data`` only if ``validate`` accepts a candidate holding ``data``.

    The candidate is ``<private dir>/<path.name>``, the private directory a unique one created beside
    ``path``. Each file in ``companions`` is copied beside the candidate first, and one whose stat
    fails stops the edit (:func:`is_file`), since a candidate without it would prove nothing. ``validate``
    receives the candidate path and raises to refuse; the refusal propagates unchanged and the live
    file is left byte-for-byte and mode-for-mode as it was. On success the candidate is renamed over
    ``path`` and re-restricted to its owner. The private directory is removed either way, and a
    stale one a killed editor of ``path`` left behind is removed first.

    On Windows the replace rides out a momentary hold on either file, such as a virus scanner reading
    the new candidate. With ``refused_error`` set, a refusal building the candidate or making the
    replace (``EACCES``, ``EPERM`` or ``EROFS``: a root-owned or read-only directory, or a hold that
    did not pass) is raised as ``refused_error(message)``. Those steps leave the live file as it
    was, since a rename that fails has not happened. What follows the replace, any other
    ``OSError`` past that companion stat, and whatever ``validate`` raises are never converted."""
    # Here, not at module top, so importing the config layer does not import the auth package.
    from messagefoundry.restricted_file import replace_generated

    _remove_stale_candidates(path)
    with refused_as(path, refused_error, "create its edit candidate"):
        private = Path(
            tempfile.mkdtemp(dir=path.parent, prefix=f".{path.name}.", suffix=CANDIDATE_DIR_SUFFIX)
        )
    try:
        candidate = private / path.name
        with refused_as(path, refused_error, "write its edit candidate"):
            fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_BINARY, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                # On disk before the rename, so a crash just after it cannot leave an empty file.
                handle.flush()
                os.fsync(handle.fileno())
        for companion in companions:
            # The stat gate: a companion read as absent would validate the candidate without it.
            if is_file(companion, refused_error=refused_error):
                with refused_as(path, refused_error, f"copy {companion.name} to validate it"):
                    shutil.copyfile(companion, private / companion.name)
        validate(candidate)
        with refused_as(path, refused_error, "replace it with the validated edit"):
            replace_generated(candidate, path)
    finally:
        _remove_private_dir(private)
    _fsync_dir(path.parent)
    _secure_file(path)


@contextlib.contextmanager
def refused_as(
    path: Path, refused_error: Callable[[str], Exception] | None, step: str
) -> Iterator[None]:
    """Raise a refusal (``_REFUSED``) from the body, which does ``step`` to ``path``, as
    ``refused_error(message)``; any other ``OSError``, or any at all when ``refused_error`` is
    ``None``, propagates unchanged. Only for a step that leaves ``path`` as it was when it fails,
    because the message says so."""
    try:
        yield
    except OSError as exc:
        if refused_error is None or exc.errno not in _REFUSED:
            raise
        raise refused_error(_refusal(path, exc, step)) from exc


def _refusal(path: Path, exc: OSError, step: str) -> str:
    """The message for an edit of ``path`` the file system refused, which left the file as it was.

    It names the file, the step that was refused and the cause, not the directory: it reaches an
    operator through the API, where an absolute host path adds nothing the file name does not. The
    full error, with the path, is logged. On Windows ``EACCES`` may only mean another program has
    the file open (``_WINDOWS``), so the cause a second attempt cures comes first."""
    _log.warning("this account could not %s, for %s: %s", step, path, exc)
    code = errno.errorcode.get(exc.errno, "") if exc.errno is not None else ""
    reason = (exc.strerror or type(exc).__name__) + (f" ({code})" if code else "")
    held = (
        "Another program may have the file open, such as an editor or a virus scanner, so try "
        "again once it closes it. If that is not it: "
        if _WINDOWS and exc.errno == errno.EACCES
        else ""
    )
    if step == _STAT_STEP:
        return (
            f"{path.name} could not be read: {reason}. It or a folder above it may be a link, or "
            "on a share, that cannot be reached, so it was not taken to be absent. Restore the "
            "share or the link's target, or remove the link"
        )
    if step == _READ_STEP:
        return (
            f"{path.name} could not be read: {reason}. {held}Another account owns the file or its "
            "directory; read it as that account, or give this account access to it"
        )
    return (
        f"{path.name} was not changed: the file system would not let this account {step}: "
        f"{reason}. {held}Its directory is read-only or another account owns it, as a root-owned or "
        "read-only config directory is, or another account owns the file named; change the file "
        "where this account can write it, or as the account that owns it"
    )


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


def _remove_stale_candidates(path: Path) -> None:
    """Remove candidate directories for ``path`` that a killed editor left behind.

    Each caller holds the edit lock, and only a directory older than ``_STALE_CANDIDATE_S`` is
    touched, so a live candidate is safe even where the file system could not lock. Best-effort:
    a directory that cannot be listed or removed is logged and the edit goes on."""
    cutoff = time.time() - _STALE_CANDIDATE_S
    try:
        entries = list(path.parent.glob(f".{glob.escape(path.name)}.*{CANDIDATE_DIR_SUFFIX}"))
    except OSError as exc:
        _log.warning("could not list %s for stale edit candidates: %s", path.parent, exc)
        return
    for entry in entries:
        if not is_candidate_dir_name(entry.name, of=path.name):
            continue
        try:
            st = entry.lstat()
        except OSError:
            continue
        if stat.S_ISDIR(st.st_mode) and st.st_mtime < cutoff:
            _remove_private_dir(entry)


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
