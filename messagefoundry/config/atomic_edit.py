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
On Windows those modes do not restrict the file, so the candidate is given a protected access list
granting the editing account, and the live file's owner when that is another account, before its
first byte is written. An own-account replaced file is then given the editing account's list
alone; a foreign-owned one gets the list the next paragraph describes. ``_restrict_to_editor``
writes that one whole list. When that write fails, ``store._secure_file``, which can grant only
the editing account, is the fallback for a file no other account owns. On Windows, a file another
account owns takes its kept icacls rewrite instead, which removes inherited entries and keeps the
explicit ones, the owner's entry among them where the candidate's write took. The
caller's ``validate`` runs against that candidate. Only a candidate that
validates replaces the live file, so a refused edit never touches the live file at all: its bytes
and its permission bits stay exactly as they were, and there is no rollback write to get wrong.

The replaced file keeps its OWNER (vault BACKLOG #5619). An edit restricts it to its owner, and an
edit run as another account, such as root or an elevated administrator editing a file the service
account owns, would otherwise have left it owned by and restricted to the editing account, so the
account that reads it could no longer. On POSIX, root gives the candidate the live file's owner and
group before the rename, and the mode is still 0600. On Windows, a live file another account owns
is restricted to that account at full control and the editing one at read only, rather than to
the editing account alone (``_owner_and_editor_list`` says why). The candidate grants the editor
full control until the rename, so no step of the edit depends on what the private directory
grants. The file's ownership is given back where Windows lets this account do that. That needs the
restore privilege enabled, which an elevated administrator holds but does not enable, and nothing
here enables it. Otherwise the file stays owned by the account that created the candidate: the
editing account, or on Windows Server Administrators. Where the editing account still owns it, it
keeps full control: read only would bind it to nothing, since an owner may rewrite a file's access
list, and would take only the right to delete the file that its next edit needs. A later edit by
an administrator then reads the file as its own and makes the owner-only rewrite, which drops the
owner's grant. Where the editor neither owns the file nor keeps full control, its later edit,
code-set rename or remove of that file replaces or deletes a file it may not delete, so it succeeds
only where the folder lets it delete files in it, as Administrators' full control of a folder does;
elsewhere it is refused and the file is left as it was. An edit by the file's own account, or by an
elevated administrator of a file Administrators owns, makes the owner-only rewrite: on Windows the one entry it leaves grants
the editing account, not SYSTEM, Administrators or another reader. That holds only when this
process's account can be read from its token and the list can be written. When the token cannot be
read, no list is written, the edit logs it, and the file keeps what its staging directory gave it.
When only the write fails, ``store._secure_file`` runs; its docstring states what it leaves,
including the entries it carries over and the cases where it runs the kept icacls rewrite, which
keeps every explicit entry. Where it fails too, the file keeps the candidate's or staging
directory's list, which can hold more entries.
A config file that is itself a link is refused rather than replaced: the rename would put a detached
regular file where the link was and leave its target unedited.

The candidate keeps the live file's NAME because the loaders read meaning from it: a code set's name is
its file stem and its format is its suffix, and ``connections.toml`` is found by name. ``companions``
copies sibling files the loader reads beside the candidate, such as a code set's policy sidecar.

:func:`edit_lock` keeps edits of one config directory apart. Each CLI run of an editor is its own
process, so two edits could each read the same original and the second replace would drop the
first. The lock
is an OS lock on one hidden file per DIRECTORY, ``.mefor-edit.lock`` beside the edited file, held from
the read through the replace. One per directory rather than one per file, so a code-set rename or
remove covers both of its names with one lock and a renamed table leaves no lock file behind. It
blocks, so it must not run on an event loop; the engine writes no config file and never takes it
there. The uploads store takes the same lock in the uploads root (``uploads._pair_lock``).

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
from dataclasses import dataclass
from pathlib import Path

from messagefoundry.config.key_file_access import _UNREACHABLE_WINERRORS
from messagefoundry.config.snapshot import is_missing_directory
from messagefoundry.controlchars import scrub_log_argument
from messagefoundry.file_lock import lock_exclusive as _try_lock
from messagefoundry.file_lock import unlock as _unlock

__all__ = [
    "CANDIDATE_DIR_SUFFIX",
    "DEFAULT_LOCK_TIMEOUT_S",
    "LOCK_FILE_NAME",
    "READ_STEP",
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

#: ``errno`` values from a chown meaning the owner's id has no mapping here: a user namespace or an
#: id-mapped mount (a container, a mount inside one).
_UNMAPPED_ID = frozenset({errno.EINVAL, errno.EOVERFLOW})

#: The ``step`` of a refused read, which :func:`_refusal` advises on differently: a read-only
#: directory refuses no read, so the write advice would send an operator to the wrong fix.
READ_STEP = "read it"

#: The ``step`` of a stat that failed with no refusal in it: a broken link or a fault, which no
#: change of account cures.
_STAT_STEP = "stat it"

#: Windows also answers ``EACCES`` when another program holds the file open, and for most of these
#: steps nothing tells the two apart: ``open`` reports a sharing violation through the C runtime as
#: bare ``EACCES`` with no ``winerror``, and a replace over a held file reports the same
#: ``ERROR_ACCESS_DENIED`` as a true denial (both measured on Windows 11). So the wording on Windows
#: names both causes.
_WINDOWS = sys.platform == "win32"

#: The bit of a reparse tag that marks a name surrogate: a symbolic link, a junction or another
#: link-like reparse point such as a WSL symlink. The value ``uploads._NAME_SURROGATE_TAG`` holds.
_NAME_SURROGATE_TAG = 0x20000000

#: Text-mode translation would rewrite every ``\n`` as ``\r\n`` on Windows; the bytes go out verbatim.
_O_BINARY = getattr(os, "O_BINARY", 0)

# Lock files this THREAD already holds, so a caller that takes the lock around a wider read
# can call a writer that takes it again. A second ``flock`` on a new handle
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
    with refused_as(path, refused_error, READ_STEP):
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
    """Whether ``path`` is a regular file, by the stat the four editors share.

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
        step = READ_STEP if exc.errno in _REFUSED else _STAT_STEP
        raise refused_error(_refusal(path, exc, step)) from exc


def _nothing_there(path: Path, exc: OSError) -> bool:
    """Whether ``exc``, from a stat of ``path``, means no file is there to lose. The walk stops at
    the first entry that exists, so it costs a few calls, and only on a stat that failed."""
    if not is_missing_directory(exc) or getattr(exc, "winerror", None) in _UNREACHABLE_WINERRORS:
        return False
    # Anything at the path itself is a file the stat could not answer for, however it got there: a
    # link or a Windows junction that cannot be followed, or a share that came back a moment later.
    if os.path.lexists(path):
        return False
    for folder in path.parents:
        if os.path.exists(folder):
            return True
        if os.path.lexists(folder):
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
    # locked it. The refusal names the lock file, though its advice speaks of owners, not modes.
    # Owner-only, like the files it guards: every edit leaves the edited file 0600, so an account
    # that could not open a lock an editor created could not edit that file either, and root opens
    # a 0600 file regardless. Wider access gains nothing. A root edit gives the file back to its
    # owner, so root hands a lock it holds to the folder's owner too (_give_root_lock_to_folder_owner).
    # O_NOFOLLOW where the platform has it: a lock path planted as a link is refused, not followed.
    # O_NONBLOCK so a lock path planted as a FIFO cannot block the open before the timeout runs.
    flags = (os.O_RDONLY if _WINDOWS else os.O_RDWR) | os.O_CREAT | _O_BINARY
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    if refused_error is not None:
        # For its refusal alone: a folder that is a broken link would fail the open as plain ENOENT.
        is_dir(path.parent, refused_error=refused_error)
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
    _give_root_lock_to_folder_owner(fd, path.parent)
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


def _give_root_lock_to_folder_owner(fd: int, folder: Path) -> None:
    """Hand a lock file root holds to the owner of its folder. Best-effort and POSIX only.

    A root edit gives the edited file back to its owner (:func:`replace_validated`), so a lock file
    left owned by root at 0600 would refuse every later edit by that owner, who could otherwise
    edit the file (vault BACKLOG #5619). The folder's owner stands for the file's: one lock guards
    every file in the folder."""
    if sys.platform == "win32" or os.geteuid() != 0:
        return
    try:
        lock = os.fstat(fd)
        owner = os.stat(folder)
        # Only a lock file that is nothing else: the folder's owner could have planted the lock name
        # as a hard link to a file root owns, and the chown would hand that file over.
        if not stat.S_ISREG(lock.st_mode) or lock.st_nlink != 1:
            return
        if lock.st_uid == 0 and owner.st_uid != 0:
            os.fchown(fd, owner.st_uid, owner.st_gid)
    except OSError as exc:
        _log.warning("could not give the edit lock in %s to its folder's owner: %s", folder, exc)


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
    ``path`` and re-restricted to its owner, which stays the live file's owner (vault BACKLOG #5619,
    as the module docstring says). A ``path`` that is itself a link is refused before anything is
    written, as ``refused_error(message)``, or with no ``refused_error`` as an ``OSError``
    (``ELOOP``). The private directory is removed either way, and a
    stale one a killed editor of ``path`` left behind is removed first.

    On Windows the replace rides out a momentary hold on either file, such as a virus scanner reading
    the new candidate. With ``refused_error`` set, a refusal building the candidate or making the
    replace (``EACCES``, ``EPERM`` or ``EROFS``: a root-owned or read-only directory, or a hold that
    did not pass), and any failure of root's chown of the candidate, is raised as
    ``refused_error(message)``. Those steps leave the live file as it
    was, since a rename that fails has not happened. What follows the replace, any other
    ``OSError`` past that companion stat, and whatever ``validate`` raises are never converted."""
    # Here, not at module top, so importing the config layer does not import the auth package.
    from messagefoundry.restricted_file import replace_generated

    _refuse_a_link(path, refused_error)
    live = _live_security(path)
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
                if sys.platform == "win32":
                    # Before the first byte, so the candidate never carries its directory's list.
                    # A failure is logged, and the replaced file is restricted again below.
                    _restrict_to_editor(candidate, owner=live.windows_owner, editor_writes=True)
                handle.write(data)
                # On disk before the rename, so a crash just after it cannot leave an empty file.
                handle.flush()
                os.fsync(handle.fileno())
                if live.posix_owner is not None and sys.platform != "win32":
                    # Through the handle, never by path: the folder's owner could swap the private
                    # directory before a chown by name. Before the rename, so a chown that fails
                    # leaves the live file as it was.
                    _give_candidate_the_owner(
                        handle.fileno(), live.posix_owner, path, refused_error
                    )
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
    if live.windows_owner is not None and _restrict_to_owner_and_editor(path, live.windows_owner):
        return
    # When the owner-and-editor list write fails, the fallback writes the same list again: the live
    # owner at full control, the editor at read only. A refused ownership hand-back whose list was
    # written never gets here.
    if sys.platform == "win32" and _restrict_to_editor(path, owner=live.windows_owner):
        return
    if sys.platform == "win32" and live.windows_owner is not None:
        # The bare store._secure_file writes a list granting the editing account alone, which would
        # take the owning account's entry the candidate gave the file (vault BACKLOG #5619). The
        # kept icacls rewrite removes inherited entries, such as the staging directory's, and keeps
        # every explicit one, the owner's among them where the candidate's write took.
        _secure_file(path, keep_explicit_entries=True)
        return
    _secure_file(path)


@dataclass(frozen=True)
class _LiveSecurity:
    """Whose the replaced file must stay. ``posix_owner`` is the live file's ``(uid, gid)`` when
    root is editing a file it does not own as root; ``windows_owner`` is the live file's owner SID
    when that is another account. Each is ``None`` when the owner-only restriction for the editing
    account is already right, as for a file the edit creates."""

    posix_owner: tuple[int, int] | None = None
    windows_owner: str | None = None


def _give_candidate_the_owner(
    fd: int,
    owner: tuple[int, int],
    path: Path,
    refused_error: Callable[[str], Exception] | None,
) -> None:
    """Give the candidate open on ``fd`` the live file's ``owner`` (POSIX, root only). Any failure
    is raised as ``refused_error(message)``, or unchanged with no ``refused_error``: it comes before
    the rename, so the live file is as it was whatever the cause. The message names the cause the
    ``errno`` points to, since none of them is a read-only or foreign-owned directory."""
    if sys.platform == "win32":  # pragma: no cover - the caller is POSIX only; for the type checker
        return
    try:
        os.fchown(fd, *owner)
    except OSError as exc:
        if refused_error is None:
            raise
        _log.warning(
            "this account could not give the edit candidate for %s its owner: %s",
            scrub_log_argument(str(path)),
            scrub_log_argument(str(exc)),
        )
        cause = (
            "That account's id may not exist on this mount or in this container"
            if exc.errno in _UNMAPPED_ID
            else "This account may not change a file's owner here, as a root that NFS squashes or "
            "a container without the chown capability cannot, or the file system does not keep "
            "owners"
        )
        raise refused_error(
            f"{path.name} was not changed: this account could not give the edited file back to "
            f"the account that owns it: {_reason(exc)}. {cause}; edit the file as the account that owns "
            "it"
        ) from exc


def _refuse_a_link(path: Path, refused_error: Callable[[str], Exception] | None) -> None:
    """Refuse an edit of ``path`` when ``path`` itself is a link: ``os.replace`` replaces the link,
    not its target, so the edit would land in a detached regular file and leave the target as it
    was (vault BACKLOG #5619). A folder above it that is a link is followed, as every reader does."""
    try:
        info = os.lstat(path)
    except OSError:
        return  # nothing there, or a stat the editors' own gates already answered for
    reparse = getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
    surrogate = reparse and getattr(info, "st_reparse_tag", 0) & _NAME_SURROGATE_TAG
    if not (stat.S_ISLNK(info.st_mode) or surrogate):
        return
    message = (
        f"{path.name} was not changed: it is a link, and an edit would replace the link with a "
        "copy rather than change the file it points to. Edit the file it points to, in its own "
        "folder, or replace the link with that file"
    )
    if refused_error is None:
        raise OSError(errno.ELOOP, message, str(path))
    raise refused_error(message)


def _live_security(path: Path) -> _LiveSecurity:
    """Whose the live file is, where the edit must keep it so; see :class:`_LiveSecurity`."""
    try:
        st = os.stat(path, follow_symlinks=False)
    except FileNotFoundError:
        return _LiveSecurity()  # a file the edit creates
    except OSError as exc:
        _log.warning(
            "could not read who owns %s; the edit restricts it to this account: %s", path, exc
        )
        return _LiveSecurity()
    if not stat.S_ISREG(st.st_mode):
        return _LiveSecurity()
    if sys.platform == "win32":
        return _LiveSecurity(windows_owner=_foreign_windows_owner(path))
    euid = os.geteuid()
    if euid == 0 and (st.st_uid, st.st_gid) != (euid, os.getegid()):
        return _LiveSecurity(posix_owner=(st.st_uid, st.st_gid))
    return _LiveSecurity()


def _canonical_sid(sid: str) -> str | None:
    """``sid`` as Windows renders it in ``S-1-...`` form, an SDDL alias such as ``LS`` or ``BA``
    included, or ``None`` when it does not convert. Windows only."""
    if sys.platform != "win32":  # pragma: no cover - guard for the type checker on POSIX
        return None
    import ctypes

    from messagefoundry.restricted_file import _render_sid, _sid_libraries

    advapi32, kernel32 = _sid_libraries()
    pointer = ctypes.c_void_p()
    if not advapi32.ConvertStringSidToSidW(sid, ctypes.byref(pointer)):
        return None
    try:
        return _render_sid(pointer)
    finally:
        kernel32.LocalFree(pointer)


def _owner_of(path: Path) -> str | None:
    """The SID that owns ``path``, in ``S-1-...`` form, or ``None`` when it cannot be read.
    Windows only."""
    from messagefoundry.store.store import _SDDL_OWNER, _read_dacl_sddl

    sddl = _read_dacl_sddl(path, owner=True)
    match = _SDDL_OWNER.search(sddl) if sddl is not None else None
    return _canonical_sid(match.group(1)) if match is not None else None


def _foreign_windows_owner(path: Path) -> str | None:
    """The SID of the account that owns ``path`` when that is not this process's account, else
    ``None``. ``None`` too when the owner, the token or the token's groups cannot be read, and for
    an owner many accounts hold, such as Users; the edit then makes the owner-only rewrite, which
    grants the editing account alone where the token can be read (the module docstring says what
    happens where it cannot).

    Administrators as the owner is this account's own when its token holds Administrators enabled:
    that is the default owner of an elevated administrator's files on Windows Server, and such a
    file is the administrator's own."""
    from messagefoundry.auth.anchor_path import ADMINISTRATORS_SID
    from messagefoundry.restricted_file import (
        RestrictedFileError,
        _is_broad_group,
        _is_package_sid,
        administrators_enabled,
    )
    from messagefoundry.store.store import _current_user_sid

    owner = _owner_of(path)
    editor = _current_user_sid()
    if owner is None or editor is None or owner == editor:
        return None
    # An owner many accounts hold is never granted the file: the owner-only rewrite drops it.
    if _is_broad_group(owner) or _is_package_sid(owner):
        return None
    if owner == ADMINISTRATORS_SID:
        try:
            if administrators_enabled():
                return None
        except RestrictedFileError as exc:
            _log.warning("could not read this process's groups for %s: %s", path, exc)
            return None
    return owner


def _owner_and_editor_list(owner: str | None, editor: str | None, *, editor_writes: bool) -> str:
    """A protected SDDL access list: ``owner`` at full control when given, then ``editor`` at full
    control when ``editor_writes`` or when there is no other owner, else at read only. ``None`` is
    left out, and an editor that is the owner keeps the owner's entry.

    Read only for the editor beside another owner, because the config loader refuses a file a
    non-owner, non-admin account can write (``wiring._evaluate_config_dacl``), and the owner must be
    able to load the file it was given back. It binds only an editor that does not end up owning the
    file, since an owner may rewrite a file's access list."""
    from messagefoundry.restricted_file import _FULL_ACCESS, _READ_ACCESS, _protected_sddl

    access: dict[str, int] = {}
    if owner is not None:
        access[owner] = _FULL_ACCESS
    if editor is not None:
        access.setdefault(editor, _FULL_ACCESS if editor_writes or owner is None else _READ_ACCESS)
    return _protected_sddl(access)


def _restrict_to_editor(
    path: Path, *, owner: str | None = None, editor_writes: bool = False
) -> bool:
    """Replace the access list of ``path`` with a protected one granting ``owner`` full control
    when one is given, and the editing account full control, or read only beside another owner
    unless ``editor_writes`` (:func:`_owner_and_editor_list`); ``False``, logged, when the token or
    the write failed. Windows only. The candidate takes ``editor_writes`` (the module docstring says
    why).

    The whole list in one write, never an ``icacls /inheritance:r`` rewrite. The private directory
    ``mkdtemp`` makes on Python 3.13+ grants SYSTEM, Administrators and OWNER RIGHTS, and an
    own-account edit whose replaced file went through that icacls rewrite, which
    ``store._secure_file`` made until it too wrote one whole list (it still makes it on the
    fallbacks its docstring names), was measured granting all four
    rather than its owner alone; that rewrite does not remove an entry a file carries explicitly.
    :func:`replace_validated` calls this on the candidate before its first
    byte, with the live file's owner when that is another account so it can still read the file
    once it is renamed into place, and again on an own-account replaced file."""
    from messagefoundry.store.store import _current_user_sid, _set_security_from_sddl

    editor = _current_user_sid()
    if editor is None:
        _log.warning(
            "could not read this process's account from its token to restrict %s",
            scrub_log_argument(str(path)),
        )
        return False
    sddl = _owner_and_editor_list(owner, editor, editor_writes=editor_writes)
    result = _set_security_from_sddl(path, sddl, protected=True)
    if result.failure is not None or result.dacl_status != 0:
        _log.warning(
            "could not restrict %s to this account: %s",
            scrub_log_argument(str(path)),
            result.failure or f"Win32 status {result.dacl_status}",
        )
        return False
    return True


def _restrict_to_owner_and_editor(path: Path, owner: str) -> bool:
    """Restrict ``path`` to the account that owned the live file and the editing account, and give
    the ownership back; ``False``, logged, when the access list could not be written. Windows only.

    The owner-only rewrite would grant the editing account alone, so an elevated administrator's
    edit of a file the service account owns would leave the service unable to read it (vault
    BACKLOG #5619). The editor keeps read only (:func:`_owner_and_editor_list` says why). Naming
    another account
    as the owner needs the restore privilege, which an elevated administrator holds but does not
    enable; when that is refused the access list alone is written and the refusal is logged, since
    the access list is what lets the owner read it."""
    from messagefoundry.store.store import _current_user_sid, _set_security_from_sddl

    editor = _current_user_sid()
    sddl = f"O:{owner}" + _owner_and_editor_list(owner, editor, editor_writes=False)
    result = _set_security_from_sddl(path, sddl, protected=True)
    if result.failure is not None:
        _log.warning("could not restrict %s to its owner after the edit: %s", path, result.failure)
        return False
    if result.owner_status not in (None, 0):
        _log.warning(
            "%s is restricted to its owner %s after the edit, but the ownership could not be "
            "given back (Win32 status %s); this account owns it now",
            path,
            owner,
            result.owner_status,
        )
    if result.owner_status != 0 and result.dacl_status != 0:
        _log.warning(
            "could not restrict %s to its owner after the edit (Win32 status %s)",
            path,
            result.dacl_status,
        )
        return False
    if result.owner_status != 0 and editor is not None and _owner_of(path) == editor:
        # The hand-back was refused and the editor still owns the file. Read only would bind it to
        # nothing, since an owner may rewrite the list, and the loader trusts the owner's own entry;
        # it would only take the DELETE a later edit by this editor needs. Where another account
        # owns it instead, such as Administrators on Windows Server, the editor stays at read only.
        kept = _set_security_from_sddl(
            path, _owner_and_editor_list(owner, editor, editor_writes=True), protected=True
        )
        if kept.failure is not None or kept.dacl_status != 0:
            _log.warning(
                "%s is left read only for this account, which owns it: %s",
                scrub_log_argument(str(path)),
                kept.failure or f"Win32 status {kept.dacl_status}",
            )
    return True


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

    It names the file, the step that was refused and the cause, not the directory: an absolute host
    path adds nothing the file name does not. The
    full error, with the path, is logged. On Windows ``EACCES`` may only mean another program has
    the file open (``_WINDOWS``), so the cause a second attempt cures comes first."""
    _log.warning(
        "this account could not %s, for %s: %s",
        step,
        scrub_log_argument(str(path)),  # a name from a directory listing, which nothing has checked
        scrub_log_argument(str(exc)),
    )
    reason = _reason(exc)
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
    if step == READ_STEP:
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


def _reason(exc: OSError) -> str:
    """The error's text and its ``errno`` name, as an operator message quotes them."""
    code = errno.errorcode.get(exc.errno, "") if exc.errno is not None else ""
    return (exc.strerror or type(exc).__name__) + (f" ({code})" if code else "")


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


def _release(fd: int) -> None:
    """Drop the lock on ``fd``. A failure is harmless: closing the handle drops it anyway."""
    with contextlib.suppress(OSError):
        _unlock(fd)


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


def _secure_file(path: Path, *, keep_explicit_entries: bool = False) -> None:
    # The store's primitive (defence in depth; its docstring says what each mode grants), imported
    # here rather than at module top so the config layer does not pull the store package in at
    # import time.
    from messagefoundry.store.store import _secure_file as _secure

    _secure(path, keep_explicit_entries=keep_explicit_entries)
