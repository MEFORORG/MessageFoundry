# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Offline uploaded-logs storage (BACKLOG #125/#126, ADR 0134).

An operator uploads a partner-supplied ``.hl7``/``.txt``/``.xml`` file to inspect it as a filterable,
searchable log **decoupled from any live connection** — never ingested into the store through a wired
inbound. Each upload is persisted on the **filesystem** (under ``[store].uploads_dir``), so it stays
connection-decoupled, and **AES-256-GCM-encrypted at rest** through the *same* ``store/crypto.py``
cipher the message store uses (identity/plaintext-on-disk only when no key is configured — the same
at-rest tier as the File-connector spill dirs, documented in ``docs/PHI.md`` §2).

This is a **leaf** module: it imports only the pure ``store.crypto`` cipher seam + the pure
``parsing.split``/``parsing.peek`` HL7 library, and ``config.atomic_edit``'s cross-process file lock
(:func:`_pair_lock`). It never imports the store instance, a transport, a
connection, ``api/``, or ``pipeline/`` — the offline viewer is not wired into the graph. The
cross-process quota ledger (ASVS 2.3.4) does not change that: the store handle arrives as a
constructor argument typed against the narrow :class:`UploadQuotaLedger` protocol declared HERE, so
no store module is imported. All disk + crypto + split work runs **off the event loop**
(``asyncio.to_thread``).

**PHI.** An uploaded file is real HL7 PHI at rest. Bodies are never logged at INFO+; every access is
gated + audited by the API layer. The on-disk **identity** is a random 32-hex ``file_id`` — the
operator-supplied filename is display metadata only and is **never** joined into a filesystem path
(the path-traversal guard, ADR 0134 #126 section).
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import contextvars
import errno
import functools
import hashlib
import io
import json
import logging
import os
import re
import secrets
import sys
import threading
import time
from collections.abc import Awaitable, Callable, Coroutine, Iterator
from concurrent.futures import Executor, ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from enum import Enum, auto
from pathlib import Path
from stat import FILE_ATTRIBUTE_REPARSE_POINT, S_ISDIR, S_ISLNK, S_ISREG
from typing import Any, BinaryIO, Literal, NamedTuple, Protocol, TypeGuard

from messagefoundry.config.atomic_edit import _REFUSED, LOCK_FILE_NAME, edit_lock, lock_path_for
from messagefoundry.controlchars import (
    has_lone_surrogate,
    scrub_log_argument,
    strip_control_chars,
)
from messagefoundry.parsing.peek import HL7PeekError, Peek
from messagefoundry.parsing.sniff import _looks_like_hl7, _sniff_head, nontext_upload_reason
from messagefoundry.parsing.split import split_batch
from messagefoundry.path_reach import is_absent, is_name_absent, is_unreachable
from messagefoundry.redaction import codec_safe_str, json_loads_or_refusal
from messagefoundry.store.content_search import SearchSpec, row_matches
from messagefoundry.store.crypto import (
    MARKER_PREFIX,
    AesGcmCipher,
    Cipher,
    CipherError,
    CipherUnavailableError,
    UnauthenticatedCipherError,
    cell_aad,
    gave_no_verdict,
)

_log = logging.getLogger(__name__)

# A file_id is exactly what ``secrets.token_hex(16)`` mints: 32 lowercase hex chars. The strict shape is
# the FIRST half of the path-traversal guard (ADR 0134): no ``.``, ``/``, ``\`` or NUL can pass, so a
# validated id can never escape the uploads root. ``\Z`` (not ``$``) so a trailing newline can't slip in.
_FILE_ID_RE = re.compile(r"^[0-9a-f]{32}\Z")
_BLOB_SUFFIX = ".blob"
_META_SUFFIX = ".meta"
_SECONDS_PER_DAY = 86_400

# Keep an operator-supplied filename to a safe, display-only form: strip any directory parts (it is NEVER
# a path here) and control characters, and bound the length. This value is shown back in the UI and
# audited; it is not used to locate anything on disk. The control-character set is controlchars' own
# (BACKLOG #1273): this file used to spell it as a private regex with the same 33 code points.
_MAX_FILENAME = 255

# The temp-file name one atomic write mints, and the ONLY temp shape the orphan sweep will unlink
# (BACKLOG #1678). Minting and matching sit together deliberately: the sweep DELETES what this
# matches, so a pattern drifting wider than the writer's own spelling would start removing an
# operator's stray files. Shape: a leading dot, the 32-hex file_id, the target's suffix, this write's
# own random tag, ``.tmp``.
_TMP_TOKEN_BYTES = 4
_ORPHAN_TMP_RE = re.compile(
    rf"^\.[0-9a-f]{{32}}(?:{re.escape(_BLOB_SUFFIX)}|{re.escape(_META_SUFFIX)})"
    rf"\.[0-9a-f]{{{_TMP_TOKEN_BYTES * 2}}}\.tmp\Z"
)

# How stale a leftover must look before the orphan sweep will remove it. A write in THIS process is
# protected by ``_inflight_names``, an exact identity test, and not by this floor. For a write in
# another process, at least a sibling engine shard's, this age test is the main protection this
# pass has, and ``max_bytes`` bounds that write's size, not how long it can stall:
# :meth:`UploadStore._sweep_orphans_sync` states what that leaves open. An hour matches the default
# prune cadence and sits far outside a healthy write.
_ORPHAN_MIN_AGE_SECONDS = 3600.0

# How long a cancelled save waits for each engine-shard ledger call, the reserve and the release, to
# finish (BACKLOG #2263). It is per call, so a save cancelled during a slow reserve can wait up to
# two bounds. A healthy statement takes well under a second. The bound exists so a stuck store
# cannot hold ``_quota_lock``, and the request's cancellation, indefinitely. Past it the call is
# logged and left running (UploadStore._leave_running). The save-time prune reuses the same bound for
# its audit rows after a cancelled upload (UploadStore._run_to_completion, BACKLOG #2261).
_LEDGER_CANCEL_WAIT_SECONDS = 5.0

# How long the removal of a cancelled save's landed pair keeps the next save in this process from
# scanning the disk (UploadStore._remove_cancelled_pair, vault BACKLOG #3740 item 4). A filesystem
# bound, apart from the ledger's, so tuning one does not move the other. A healthy unlink takes
# milliseconds.
_CANCELLED_REMOVAL_WAIT_SECONDS = 5.0
# How many of those removals run at once, on their own pool rather than the default executor, so
# unlinks that hang can hold at most this many threads, never the pool every ``asyncio.to_thread``
# in the engine shares. A removal past the cap queues on the pool and still runs.
_CANCELLED_REMOVAL_WORKERS = 2

# How long a pair removal, or a ``rotate-key`` re-seal's replace, waits for the uploads root's
# cross-process pair lock (:func:`_pair_lock`, BACKLOG #3181 item 5). Each holder keeps it only
# across its unlinks, or across one re-check and one rename, so a wait this long means a stalled
# file system. Then an engine removal goes on without the lock, and the re-seal skips the half, or
# at the pass's first check writes nothing.
# Under the 5 s bounds above, so a removal that waits it out still ends inside them.
_PAIR_LOCK_TIMEOUT_SECONDS = 2.0


@functools.cache
def _removal_executor() -> ThreadPoolExecutor:
    """The process's pool for cancelled-pair removals (``_CANCELLED_REMOVAL_WORKERS``), built on
    first use. It is never shut down: a queued removal must still run, and the interpreter joins
    its threads at exit as it does the default executor's."""
    return ThreadPoolExecutor(
        max_workers=_CANCELLED_REMOVAL_WORKERS, thread_name_prefix="mefor-upload-removal"
    )


@dataclass(slots=True)
class _PendingRemoval:
    """A cancelled save's removal that later saves still wait for, until ``deadline`` (loop
    time). ``flagged`` is set once an ERROR has named it as possibly stored."""

    file_id: str
    deadline: float
    flagged: bool = False


# How often a save that holds an engine-shard reservation touches the ledger row, so a slow save
# keeps its slot past ``store.base.UPLOAD_RESERVATION_STALE_AFTER`` (300 s) instead of having it
# reclaimed by a sibling engine shard's reserve (BACKLOG #2648). A third of that window, which
# leaves room for touches that are slow as well as one that fails. Written out rather than imported
# to keep this module a leaf; a test pins the ratio.
_RESERVATION_HEARTBEAT_SECONDS = 100.0
# How long a save keeps touching its row at most. A write that never finishes would otherwise pin
# the row, and any leaked slot in it, for as long as the process lives. Past this the heartbeat
# stops with a WARNING, and the reservation goes stale; no other activity keeps it fresh (vault
# BACKLOG #3180). A write is
# bounded by ``max_upload_bytes`` (512 MiB at most), so an hour is far past any healthy save.
_RESERVATION_HEARTBEAT_MAX_SECONDS = 3600.0
# How long the heartbeat waits for one touch before it goes on without it (BACKLOG #3256). A
# running heartbeat leaves the touch running and never cancels it, so a slow touch that lands still
# refreshes the reservation. One still running when the heartbeat ends is held as a straggler, so
# it is cancelled at ``_LEDGER_STRAGGLER_MAX_SECONDS`` or by the shutdown drain (vault BACKLOG
# #3180), which does not wait for it (#3740 item 14). Well under the interval, so the wait never
# delays the next beat by much.
_RESERVATION_TOUCH_WAIT_SECONDS = 10.0

# How long a ledger call a cancelled save left running may run before it is cancelled (vault
# BACKLOG #3180). Without a cap a stalled store held every such call, and every late release it
# spawned, for as long as the process lived. Cancelling one is safe because each reservation is its
# own row: a slot the call did take is reclaimed once it goes stale, whatever else the uploader does.
_LEDGER_STRAGGLER_MAX_SECONDS = 60.0

# How long :meth:`UploadStore.drain_stragglers` waits at shutdown for the calls and save-time sweeps
# a cancelled save left running, then how long it waits for the ones it cancels (vault BACKLOG
# #3180). These are upper limits. Both lifespans run the drain as one step of the API teardown,
# under its one shutdown budget (``api.app._SHUTDOWN_BUDGET_SECONDS``, BACKLOG #3191), through
# :meth:`UploadStore.drain_stragglers_within`, which fits both waits inside a share of that step's
# bound, so the drain's own waits end, and cancel what is left, before the teardown cuts the step.
_STRAGGLER_DRAIN_SECONDS = 2.0
_STRAGGLER_CANCEL_GRACE_SECONDS = 1.0

# How much of a refused plaintext sidecar the quota reads to find the uploader it bills (BACKLOG
# #2322). A sidecar the engine wrote is a few hundred bytes. Past this the owner counts as unknown.
_UNSEALABLE_OWNER_READ_LIMIT = 64 * 1024
# The largest a sidecar may be on disk (BACKLOG #5387 added item 1). A sidecar the engine writes
# is a few hundred bytes. The longest it can be is its text fields at their bounds
# (``_MAX_SIDECAR_TEXT``), every character an astral one that ``json.dumps`` escapes as twelve, then
# sealed, which base64 grows by a third: under 40 KiB. :meth:`UploadStore.save` refuses to write a
# longer one. The listing scan, which runs under ``_quota_lock``, the by-id reads, the startup
# count and ``rotate-key`` (:meth:`UploadStore._reseal_half`) read no more than this, plus one
# byte, so a planted file cannot exhaust memory there; a longer sidecar is refused as damaged.
# :meth:`UploadStore._unsealable_sync` reads by characters instead, up to
# ``_UNSEALABLE_OWNER_READ_LIMIT`` of them, at most about 256 KiB. A plaintext sidecar is held to
# the tighter ``_PLAIN_SIDECAR_LIMIT``, the longest whose sealed form still fits here, and
# ``rotate-key`` never writes a sidecar longer than this.
_SIDECAR_LIMIT = 128 * 1024
# The longest a PLAINTEXT sidecar may be, in UTF-8 bytes once unpadded (BACKLOG #5387 added item
# 1): the longest whose sealed form fits ``_SIDECAR_LIMIT``. Sealing adds a 12-byte nonce and a
# 16-byte tag, base64 grows that by a third, and the marker in front is under 256 characters
# (``_MARKER_READ_LIMIT``), so 32 bytes of slack covers the rest. A test pins that a plaintext this
# long seals within the cap. Far above any sidecar the store writes, so it refuses only a plant.
_PLAIN_SIDECAR_LIMIT = (_SIDECAR_LIMIT - 256) // 4 * 3 - 32
# The chunk size for checking that a body decodes as text. It bounds memory, not the work.
_BODY_CHECK_CHUNK = 1 << 20

# Every filename a write in THIS process is currently holding: an atomic write's temp from the moment
# it is created until its ``os.replace`` lands, and a save's blob from its own write until its sidecar
# lands. The orphan sweep skips these outright, so it never has to reason about timing for a race it
# can see. Writes run in ``asyncio.to_thread`` worker threads and a sweep runs in another, so the
# guard is a ``threading.Lock``, not an ``asyncio`` one.
#
# The key is the bare NAME, not a path: every file here is a direct child of one uploads root, names
# carry 32 hex bits of file_id (plus 8 more for a temp), and keying on the name sidesteps every
# resolved-vs-unresolved and Windows-case normalization question. Two stores over different roots
# cannot realistically collide, and if they did the effect is to SKIP a delete, which is the safe
# direction.
_inflight_lock = threading.Lock()
_inflight_names: set[str] = set()


@contextlib.contextmanager
def _inflight(name: str) -> Iterator[None]:
    """Hold ``name`` in the in-flight set for the duration of the block (see ``_inflight_names``)."""
    with _inflight_lock:
        _inflight_names.add(name)
    try:
        yield
    finally:
        with _inflight_lock:
            _inflight_names.discard(name)


def _is_inflight(name: str) -> bool:
    """Is a write in this process currently holding ``name``?"""
    with _inflight_lock:
        return name in _inflight_names


#: How long one upload's report is given once (BACKLOG #5552, #5553). Every listing, quota check and
#: prune meets the same sidecar, so without this each would raise the alert, or log the line, again.
_REPORT_INTERVAL_S = 3600.0
#: The most keys one memo remembers; the oldest recorded is forgotten first.
_REPORTED_MAX = 4096
#: How much of an upload id a tag-failure alert names, as ``store/cell_tag.py`` names a row.
_TAG_REF_LEN = 12
#: How much of a stored value the tag-failure checks read: more than any marker this build writes
#: (version, algorithm, key id and v4 salt), so a multi-MiB body is not copied to read its key id.
_TAG_MARKER_HEAD_CHARS = 256


class _OncePerInterval:
    """Which keys were reported within ``interval_s``, remembering at most ``max_keys``, on the
    ``clock`` given. Scans run on worker threads, so the read-modify-write holds a lock."""

    def __init__(
        self,
        interval_s: float = _REPORT_INTERVAL_S,
        max_keys: int = _REPORTED_MAX,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._interval_s = interval_s
        self._max_keys = max_keys
        self._clock = clock
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def first(self, key: str) -> bool:
        """Whether ``key`` has not been reported within the interval; records it."""
        now = self._clock()
        with self._lock:
            last = self._seen.get(key)
            if last is not None and now - last < self._interval_s:
                return False
            self._seen.pop(key, None)
            self._seen[key] = now
            while len(self._seen) > self._max_keys:
                self._seen.pop(next(iter(self._seen)))
        return True


#: The ``"<part> <upload id>"`` keys of the sidecar and body tag failures reported (BACKLOG #5553,
#: #5552 item 6 (a)), so one upload can hold two entries. One memo for the process, whichever
#: cipher instance reported.
_tag_reported = _OncePerInterval()

#: The parts of an upload whose tag failure is reported, as the alert names them.
_TaggedPart = Literal["sidecar", "body"]


def _not_a_plain_file(path: Path) -> str | None:
    """Why ``path`` must not be read, from its ``lstat``: it is a symbolic link or a Windows
    name-surrogate reparse point such as a junction (BACKLOG #5552), or it is not a regular file,
    such as a FIFO, whose open would block the reader for good. ``None`` when it is a regular file,
    or when it cannot be checked; the caller's own read then meets and names that fault."""
    try:
        info = path.lstat()
    except OSError:
        return None
    return _plain_refusal(info)


def _plain_refusal(info: os.stat_result) -> str | None:
    """Why the file an ``lstat`` result describes must not be read, as :func:`_not_a_plain_file`
    words it, or ``None`` when it is a regular file."""
    if _names_a_link(info):
        return "it is a link and was not followed"
    if not _is_regular(info):
        return "it is not a regular file"
    return None


def _known_absent(path: Path) -> bool:
    """Whether an ``lstat`` shows the name ``path`` is not there
    (:func:`~messagefoundry.path_reach.is_name_absent`, whose limits apply to a ``True``).
    ``False`` when something is there, and when the ``lstat`` fails for any other reason, such as
    a share that cannot be reached or, on Windows, a missing folder or drive above the name, which
    is logged (BACKLOG #5388)."""
    try:
        os.lstat(path)
    except OSError as exc:
        if is_name_absent(exc):
            return True
        _log.warning("uploaded-file part %s could not be checked: %s", path.name, exc)
    return False


def _sidecar_is_absent(sidecar: Path) -> bool:
    """Whether an ``lstat`` reports ``sidecar`` as not there, by
    :func:`~messagefoundry.path_reach.is_name_absent`, whose limits apply to a ``True``. ``False``
    when the ``lstat`` succeeds, in any form of file, since it follows no link. Any other failure
    raises ``OSError`` (BACKLOG #6575)."""
    try:
        os.lstat(sidecar)
    except FileNotFoundError as exc:
        if is_name_absent(exc):
            return True
        raise
    return False


def _root_fault(root: Path) -> str | None:
    """The reason the uploads root's own ``stat`` failed, or ``None`` when it answers. A failure
    is read as the root being lost, which an entry's own error cannot show: a dangling link can
    raise the codes a lost share does. An answer proves nothing about the entries under it: a POSIX
    mount that dropped leaves a mount point that still answers. Text and not the exception, whose
    traceback would hold the sweep's frame, and so its whole listing, until a cyclic collection."""
    try:
        root.stat()
    except OSError as exc:
        return exc.strerror or type(exc).__name__
    return None


def _names_a_link(info: os.stat_result) -> bool:
    """Whether an ``lstat`` result is a symbolic link or a name-surrogate reparse point."""
    reparse = getattr(info, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT
    return S_ISLNK(info.st_mode) or bool(
        reparse and getattr(info, "st_reparse_tag", 0) & _NAME_SURROGATE_TAG
    )


#: The reparse tags of Windows files that ``lstat`` reports as regular by ``st_mode`` but that an
#: open refuses with ``EINVAL``: at least an ``AF_UNIX`` socket (``IO_REPARSE_TAG_AF_UNIX``), the
#: FIFO, character and block device files WSL makes (``IO_REPARSE_TAG_LX_FIFO``, ``_LX_CHR``,
#: ``_LX_BLK``), and an app execution alias (``IO_REPARSE_TAG_APPEXECLINK``). Listed, not inferred
#: from the reparse attribute, since a cloud-files or dedup placeholder is a reparse point too and
#: is read as the file it is.
_UNOPENABLE_REPARSE_TAGS = frozenset({0x80000023, 0x80000024, 0x80000025, 0x80000026, 0x8000001B})


def _is_regular(info: os.stat_result) -> bool:
    """Whether an ``lstat`` result is a regular file, and not one of the Windows reparse points
    ``_UNOPENABLE_REPARSE_TAGS`` names, which only their tag tells apart (BACKLOG #5388 added
    item 3)."""
    return (
        S_ISREG(info.st_mode) and getattr(info, "st_reparse_tag", 0) not in _UNOPENABLE_REPARSE_TAGS
    )


#: How a sidecar or body is opened (BACKLOG #5387 added item 1). ``O_NOFOLLOW`` refuses a final
#: name that became a symbolic link after the ``lstat`` that checked it, and ``O_NONBLOCK`` keeps a
#: FIFO swapped in there from blocking the open, which the ``fstat`` after it then refuses. Windows
#: has neither flag, so there :func:`_open_plain` checks the name again once it is open.
_O_NOFOLLOW: int = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK: int = getattr(os, "O_NONBLOCK", 0)
# O_NOCTTY, as auth/trust_anchors.read_if_regular sets it, so a terminal swapped in after the
# lstat never becomes the engine's controlling terminal before the fstat refuses it.
_PLAIN_OPEN_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_BINARY", 0)
    | getattr(os, "O_NOCTTY", 0)
    | _O_NOFOLLOW
    | _O_NONBLOCK
)


class _NotPlainError(OSError):
    """A sidecar or body that is not the plain file its ``lstat`` showed when it was opened. An
    ``OSError``, so each reader treats it as it treats a file it could not read."""


class _RefusedBeforeOpen(_NotPlainError):
    """A :class:`_NotPlainError` raised by :func:`_open_plain`'s own ``lstat``, before any open:
    ``reason`` is :func:`_plain_refusal`'s. The listing scan reads it rather than making that
    ``lstat`` itself (BACKLOG #5552 item 8). ``reason`` defaults, and lives in the instance dict,
    so a copy or unpickle, which calls the class with ``args`` alone, rebuilds it."""

    def __init__(self, message: str, reason: str = "") -> None:
        super().__init__(message)
        self.reason = reason


def _open_plain(path: Path) -> tuple[BinaryIO, os.stat_result]:
    """The regular file ``path`` open for reading, without following a link, and its ``fstat``
    (BACKLOG #5387 added item 1). The caller closes it.

    The ``lstat`` before the open is the check :func:`_not_a_plain_file` makes. The ``fstat`` after
    it must show a regular file, so a FIFO swapped in between the two is refused rather than waited
    on. Where there is ``O_NOFOLLOW``, the open itself refuses a link swapped in after the
    ``lstat``.

    **Windows has no ``O_NOFOLLOW``, so there the open FOLLOWS a link swapped in after the
    ``lstat``, and opens whatever it names.** Only then is it refused: the name is checked again
    after the open, and must still be no link and name the file that was opened
    (``os.path.samestat``), so this function returns no handle to, and nothing is read from, the
    link's target. A regular file put in its place, as an atomic replace does, is read.

    An open the filesystem refuses is a :class:`_NotPlainError` too when a fresh ``lstat`` shows
    the name is now a link or not a regular file (BACKLOG #5388 added item 3), as at least a
    dangling link Windows followed, which answers ``FileNotFoundError``, a Windows folder, which
    answers ``PermissionError``, and a socket, which Windows answers with ``EINVAL``, are. Any other
    ``EINVAL``, as on a Windows reparse point ``_UNOPENABLE_REPARSE_TAGS`` does not list, is
    re-raised: the Windows CRT answers EINVAL for every Win32 error it does not map, so it may be a
    sound file whose filter is not running. A refused open whose name is gone by that ``lstat``
    raises ``FileNotFoundError``, whatever the open met, so the race answers the same on every
    platform; one whose share cannot be reached (``messagefoundry.path_reach``) raises :class:`_UnreachableError`, never ``FileNotFoundError``. Raises :class:`_NotPlainError`
    for a refusal, and any other ``OSError`` the filesystem gives, ``FileNotFoundError`` and
    ``PermissionError`` included. An error of the open itself carries the re-check's verdict for
    :func:`_refused_read`."""
    unreached: str | None = None
    try:
        before = path.lstat()
    except OSError as exc:
        # Whatever class it arrives as: a FileNotFoundError on Windows, and at least the ESTALE of
        # a stale NFS handle, which was re-raised and answered a server error (BACKLOG #5388).
        unreached = _unreachable_fault(exc)
        if unreached is None:
            raise
    if unreached is not None:
        raise _unreached(path, unreached)
    refused = _plain_refusal(before)
    if refused is not None:
        raise _RefusedBeforeOpen(f"{path.name} is not a plain file", refused)
    met: tuple[_Recheck, str] | None = None
    try:
        fd = os.open(path, _PLAIN_OPEN_FLAGS)
    except OSError as exc:
        # What the open meets when the name is swapped after the lstat varies by platform: at
        # least ENXIO or EOPNOTSUPP for a socket (EINVAL on Windows), a PermissionError for a
        # folder on Windows, and there a FileNotFoundError for a dangling link it followed. The
        # name is what decides, so every caller sees one refusal (BACKLOG #5388 added item 3).
        # A share that went away is classed first, before any errno, at least the EINVAL a
        # dropped Windows share answers, so it is a 503 rather than a re-raised error.
        seen: _Recheck = "unreachable" if is_unreachable(exc) else _recheck(path, exc)
        # A refusal is converted when the name is now not plain, is gone and the open met
        # something other than absence, or cannot be reached; anything else is re-raised.
        absent = is_absent(exc)
        # An open's FileNotFoundError is absence only when a fresh lstat agrees the name is gone:
        # Windows maps a dropped share to ENOENT with no winerror on an open, so a share that came
        # back for the lstat, or one the lstat could not check, would otherwise read as an upload
        # that is gone (BACKLOG #5388).
        if isinstance(exc, FileNotFoundError) and seen not in ("gone", "unplain"):
            seen = "unreachable"
        if seen not in ("unplain", "unreachable") and not (seen == "gone" and not absent):
            # The caller classes it; it reads this verdict rather than checking, and logging a
            # failed check, a second time.
            setattr(exc, _RECHECKED, seen)
            raise
        met = (seen, codec_safe_str(exc))
    if met is not None:
        # Raised after the handler, so the open's error is on no chain; its text names what the
        # open met, so the log says so. A part gone by the re-check is answered as an absent
        # one, so the race reads the same on every platform, whatever errno the open met.
        seen, text = met
        if seen == "gone":
            raise FileNotFoundError(
                errno.ENOENT, f"{path.name} went after it was checked: {text}", str(path)
            )
        if seen == "unreachable":
            raise _unreached(path, text)
        raise _NotPlainError(f"{path.name} changed after it was checked: {text}")
    # Each step after the open classes a share that went away as the open does, so no caller
    # re-raises it as a server error (BACKLOG #5388).
    try:
        # Before the fdopen, which answers a directory swapped in after the lstat with its own
        # IsADirectoryError, naming the descriptor rather than the path (BACKLOG #5388 added
        # item 3). POSIX opens a directory for reading, so this check is the one that refuses it.
        # S_ISREG, not _is_regular: a Windows socket never gets this far, since its open fails.
        after = os.fstat(fd)
        if not S_ISREG(after.st_mode):
            raise _NotPlainError(f"{path.name} changed after it was checked")
        handle = os.fdopen(fd, "rb")
    except BaseException as exc:
        os.close(fd)
        unreached = _unreachable_fault(exc)
        if unreached is None:
            raise
    if unreached is not None:
        raise _unreached(path, unreached)
    try:
        if not _O_NOFOLLOW:
            again = path.lstat()
            if _names_a_link(again) or not os.path.samestat(again, after):
                raise _NotPlainError(f"{path.name} changed after it was checked")
        if _O_NONBLOCK:
            # A regular file, so a blocking read is safe, and some filesystems would otherwise
            # answer a read with EAGAIN.
            os.set_blocking(handle.fileno(), True)
    except BaseException as exc:
        handle.close()
        unreached = _outage_fault(exc)
        if unreached is None:
            raise
    if unreached is not None:
        raise _unreached(path, unreached)
    return handle, after


def _read_plain_text(path: Path, limit: int | None = None) -> str:
    """The text of the regular file ``path``, opened by :func:`_open_plain`, with no more than
    ``limit`` bytes read when one is given (BACKLOG #5387 added item 1). Raises what that raises,
    :class:`_OversizedFileError` for a file over ``limit``, and ``UnicodeDecodeError`` for one
    that is not UTF-8. A read that meets the share going away raises :class:`_UnreachableError`,
    as the open does (BACKLOG #5388)."""
    handle, info = _open_plain(path)
    with handle:
        if limit is not None and info.st_size > limit:
            raise _OversizedFileError(limit)
        unreached: str | None = None
        try:
            if limit is None:
                data = handle.read()
            else:
                # Sized by the file, not the limit, so a small file costs a small buffer. A file
                # that grew since the fstat is read on, up to one byte past the limit, so it is
                # either read whole or refused, never cut short.
                data = handle.read(info.st_size + 1)
                if info.st_size < len(data) <= limit:
                    data += handle.read(limit + 1 - len(data))
        except OSError as exc:
            unreached = _read_fault(path, exc)
            if unreached is None:
                raise
        if unreached is not None:
            raise _unreached(path, unreached)
        if limit is not None and len(data) > limit:
            raise _OversizedFileError(limit)
    return data.decode("utf-8")


#: What a sidecar may carry around its value and still be read (BACKLOG #5387 added item 1): a
#: UTF-8 byte-order mark, which an editor may add, and the JSON whitespace one may append. The
#: store writes neither. Stripped, a sealed sidecar that gained them still reads as sealed, and is
#: never mistaken for a damaged one, which the prune ages on disk.
_SIDECAR_PAD = " \t\r\n"


def _too_long_to_seal(value: str) -> bool:
    """Whether unpadded sidecar text ``value`` is plaintext longer than
    :data:`_PLAIN_SIDECAR_LIMIT`, so no seal of it fits :data:`_SIDECAR_LIMIT` (BACKLOG #5387).
    The test the save, every reader through :func:`_read_sidecar` and ``rotate-key``'s
    :meth:`UploadStore._reseal_half` apply. :meth:`UploadStore._unsealable_sync`, the test of an
    upload as never sealable, does not call it, so where a caller asks that test after
    :func:`_read_sidecar` refused a sidecar as too long, as at least the prune's listing scan and
    the delete do, it can still class that upload as never sealable. The startup count does not
    ask it for such a sidecar."""
    return not value.startswith(MARKER_PREFIX) and len(value.encode("utf-8")) > _PLAIN_SIDECAR_LIMIT


def _read_sidecar(path: Path) -> str:
    """The text of sidecar ``path``, as :func:`_read_plain_text` reads it with
    :data:`_SIDECAR_LIMIT`. A plaintext one longer than :data:`_PLAIN_SIDECAR_LIMIT` once unpadded
    is refused as oversized too (BACKLOG #5387 added item 1): no store writes one, and no
    ``rotate-key`` could seal it within :data:`_SIDECAR_LIMIT`, so every reader agrees it is
    damaged rather than leave it refused under the key and never sealable. ``rotate-key`` skips
    it, since it may hold a value under a prior key (:meth:`UploadStore._refused_meta`)."""
    text = _read_plain_text(path, _SIDECAR_LIMIT)
    if _too_long_to_seal(_unpadded(text)):
        raise _OversizedFileError(_PLAIN_SIDECAR_LIMIT)
    return text


#: How a by-id read answers a refused ``OSError`` (:func:`_refused_read`).
_ReadRefusal = Literal["damaged", "denied"]


def _refused_read(exc: OSError) -> _ReadRefusal | None:
    """How a by-id read answers ``exc``, raised reading an upload's part (BACKLOG #5388 added items
    2 and 3). ``"damaged"`` for a part that is not a plain file: a :class:`_NotPlainError`, an
    ``ELOOP`` for a link ``O_NOFOLLOW`` would not follow, or a refusal whose path a fresh ``lstat``
    shows is a link or is not a regular file (:func:`_recheck`). Only when the error names no path
    does an errno in ``_NOT_A_FILE`` decide it, so neither a regular file the filesystem answers
    with ``ENXIO`` for some other reason, nor a part that is gone or cannot be checked again, is
    called damaged. ``"denied"`` for any other ``PermissionError``: at least a permission or an
    ACL the engine lacks, and on Windows a file another program holds open (a sharing violation).
    That is not damage, so it is never answered as a file an operator should delete. ``None`` for
    any other ``OSError``, such as too many open files or an I/O error, which may pass on a retry,
    so the caller re-raises it. An error :func:`_open_plain` already checked again carries that
    verdict, which is read rather than checked, and logged, a second time."""
    if isinstance(exc, _NotPlainError) or exc.errno == errno.ELOOP:
        return "damaged"
    seen = getattr(exc, _RECHECKED, None) or _recheck(exc.filename, exc)
    if seen == "unplain" or (seen == "unnamed" and exc.errno in _NOT_A_FILE):
        return "damaged"
    return "denied" if isinstance(exc, PermissionError) else None


#: What a fresh ``lstat`` shows of a part after an access to it was refused (:func:`_recheck`).
_Recheck = Literal["unplain", "plain", "gone", "unreachable", "unnamed", "unchecked"]

#: The attribute :func:`_open_plain` sets on an error it re-raises, holding its :func:`_recheck`.
_RECHECKED = "_mefor_upload_recheck"


class _UnreachableError(OSError):
    """A part whose share or directory could not be reached, so nothing is known about it
    (BACKLOG #5388 added item 3). Never a ``FileNotFoundError``, so no caller reads it as an upload
    that is gone; the by-id reads and the delete answer it as :class:`UploadStorageUnreachableError`."""


def _unreached(path: Path, fault: str) -> _UnreachableError:
    """The :class:`_UnreachableError` for part ``path``, whose access met ``fault``, already
    rendered. ENOENT, not the errno met, so no caller classes it by errno; its type says what it
    is."""
    return _UnreachableError(errno.ENOENT, f"{path.name} could not be reached: {fault}")


def _unreachable_fault(exc: BaseException) -> str | None:
    """``exc`` rendered when it is an ``OSError`` saying a part's share cannot be reached
    (:func:`~messagefoundry.path_reach.is_unreachable`), whatever its class, else ``None``
    (BACKLOG #5388). The one test each step of a part's read applies, so the caller raises
    :func:`_unreached` after its handler."""
    if isinstance(exc, OSError) and is_unreachable(exc):
        return codec_safe_str(exc)
    return None


def _outage_fault(exc: BaseException) -> str | None:
    """:func:`_unreachable_fault`, for a check of a name that was just there: a
    ``FileNotFoundError`` :func:`~messagefoundry.path_reach.is_name_absent` does not read as the
    name missing, such as a Windows missing folder (3) or drive (15) above it, is an outage too,
    so only a missing final name reads as gone (BACKLOG #5388)."""
    fault = _unreachable_fault(exc)
    if fault is None and isinstance(exc, FileNotFoundError) and not is_name_absent(exc):
        return codec_safe_str(exc)
    return fault


def _read_fault(path: Path, exc: OSError) -> str | None:
    """``exc`` rendered when the read of the open part ``path`` failed because its share could not
    be reached, else ``None`` (BACKLOG #5388). A read's error names no path, and on Windows it
    carries no ``winerror`` either, so :func:`_unreachable_fault` alone misses a dropped share
    there: the name is checked again (:func:`_recheck`). A ``FileNotFoundError`` is never absence,
    since the file was open; Windows maps a dropped share to ``ENOENT``. Any other verdict is set
    on ``exc`` as :func:`_open_plain` sets one, so :func:`_refused_read` reads it rather than
    checking a read's error, which names no path, as ``"unnamed"``."""
    fault = _unreachable_fault(exc)
    if fault is None and isinstance(exc, FileNotFoundError):
        fault = codec_safe_str(exc)
    if fault is not None:
        return fault
    seen = _recheck(path, exc)
    if seen == "unreachable":
        return codec_safe_str(exc)
    setattr(exc, _RECHECKED, seen)
    return None


def _recheck(name: object, cause: OSError) -> _Recheck:
    """What ``name`` is by a fresh ``lstat`` (BACKLOG #5388 added item 3), after ``cause`` refused
    an access to it: ``"unplain"`` for a link or a file that is not regular, ``"plain"`` for a
    regular file, ``"gone"`` for one that is not there, and
    ``"unreachable"`` when its share cannot be reached, as on a share that dropped.
    ``"unnamed"`` when ``name`` is no path (``None``, or a descriptor), and ``"unchecked"`` when
    the ``lstat`` fails for any other reason. A fault in reaching it is logged, never swallowed."""
    if not isinstance(name, str | bytes | os.PathLike):
        return "unnamed"
    again: Exception
    verdict: _Recheck = "unchecked"
    try:
        info = os.lstat(name)
    except FileNotFoundError as exc:
        if is_absent(exc):
            return "gone"
        again, verdict = exc, "unreachable"
    except OSError as exc:
        again = exc
        if is_unreachable(exc):
            verdict = "unreachable"
    except ValueError as exc:
        again = exc
    else:
        return "unplain" if _names_a_link(info) or not _is_regular(info) else "plain"
    _log.warning(
        "uploaded-file part could not be checked again after a refused access (%s): %s",
        codec_safe_str(cause),
        codec_safe_str(again),
    )
    return verdict


def _refused_unlink(
    exc: OSError, path: Path
) -> _ReadRefusal | Literal["gone", "unreachable"] | None:
    """How the delete answers ``exc``, raised unlinking the body ``path`` (BACKLOG #5388 added
    item 3). ``"gone"`` when the body is not there by a fresh ``lstat``, as when another
    remover took it, so this call removed nothing of it; ``"unreachable"`` when its share cannot be
    reached. ``"damaged"`` only when the body is now a directory, which no
    unlink removes: a FIFO, a socket or a device is unlinked as a file is, so its kind is not why
    an unlink failed. ``"denied"`` for any other ``PermissionError``, and ``None`` for any other
    ``OSError``, which the caller raises as it is. A body that cannot be checked again is a
    directory only by ``EISDIR``; that check's failure is logged, never swallowed."""
    if is_unreachable(exc):
        return "unreachable"
    try:
        folder = S_ISDIR(os.lstat(path).st_mode)
    except FileNotFoundError as again:
        return "gone" if is_absent(again) else "unreachable"
    except OSError as again:
        if is_unreachable(again):
            return "unreachable"
        _log.warning(
            "uploaded-file body could not be checked again after a refused unlink (%s): %s",
            codec_safe_str(exc),
            codec_safe_str(again),
        )
        folder = exc.errno == errno.EISDIR
    if folder:
        return "damaged"
    return "denied" if isinstance(exc, PermissionError) else None


#: Windows errors for a file another handle holds open without sharing delete access:
#: ``ERROR_SHARING_VIOLATION`` (32) and ``ERROR_LOCK_VIOLATION`` (33). Python opens a file with no
#: delete sharing, so the engine's own read of a body or sidecar meets a delete with one.
_IN_USE_WINERRORS = frozenset({32, 33})


def _in_use(exc: OSError) -> bool:
    """Whether ``exc`` is a Windows sharing or lock violation (:data:`_IN_USE_WINERRORS`)."""
    winerror = getattr(exc, "winerror", None)
    return isinstance(winerror, int) and winerror in _IN_USE_WINERRORS


#: How often, and after how long a first pause in seconds, doubled each time, the delete tries an
#: unlink another handle refused (BACKLOG #5388 added item 3). Brief, since the delete holds the pair
#: lock meanwhile; enough for a read the engine itself holds open to end.
_UNLINK_ATTEMPTS = 3
_UNLINK_PAUSE = 0.05


def _unlink_retrying(path: Path) -> bool:
    """Unlink ``path``, and whether this call removed it: ``False`` when nothing was there
    (:func:`~messagefoundry.path_reach.is_absent`). A share that cannot be reached raises
    :class:`_UnreachableError`, so it never reads as a removal or as absence. An unlink another
    handle refuses (:func:`_in_use`) is tried again, up to :data:`_UNLINK_ATTEMPTS` times in all.
    Any other error, and the last such refusal, is raised at once, so a lasting denial costs no
    pause under the pair lock. It sleeps, so it runs only on a worker thread."""
    pause = _UNLINK_PAUSE
    for attempt in range(1, _UNLINK_ATTEMPTS + 1):
        unreached: str | None = None
        try:
            path.unlink()
            return True
        except FileNotFoundError as exc:
            if is_absent(exc):
                return False
            unreached = codec_safe_str(exc)
        except OSError as exc:
            if is_unreachable(exc):
                unreached = codec_safe_str(exc)
            elif attempt == _UNLINK_ATTEMPTS or not _in_use(exc):
                raise
            _log.info(
                "uploaded-file part %s is in use, trying its unlink again: %s",
                path.name,
                codec_safe_str(exc),
            )
        if unreached is not None:
            # After the handler, so the error is on no chain. ENOENT, not the errno met, so no
            # caller classes it by errno; its type says what it is.
            raise _unreached(path, unreached)
        time.sleep(pause)
        pause *= 2
    return False  # unreachable: the last try returned or raised


def _unpadded(text: str) -> str:
    """``text`` without a leading byte-order mark or surrounding JSON whitespace."""
    return _lstrip_pad(text).rstrip(_SIDECAR_PAD)


def _lstrip_pad(text: str) -> str:
    """``text`` without a leading byte-order mark or JSON whitespace."""
    return text.lstrip(_SIDECAR_PAD).removeprefix("\ufeff").lstrip(_SIDECAR_PAD)


class UploadError(Exception):
    """Base class for uploaded-logs storage failures."""


class UploadPathError(UploadError):
    """A file_id is malformed or resolves outside the uploads root (path-traversal guard, ADR 0134).

    ``UploadStore._paths`` also raises it for a path that does not resolve to itself, such as a
    symbolic link inside the root (BACKLOG #5552)."""


class UploadTooLargeError(UploadError):
    """An upload exceeds ``[store].max_upload_bytes``."""


class UploadContentError(UploadError):
    """An upload's extension is not permitted, or its content contradicts its extension (ASVS 5.2.2).

    The uploaded-logs feature accepts only text diagnostic logs; a disallowed extension or a
    content/extension mismatch (a ``.hl7`` with no HL7 header, a non-``<`` body in a ``.xml``) is
    refused at the chokepoint before anything is written. The API maps it to HTTP 400 and a
    metadata-only ``upload.reject`` audit, and its subclass :class:`UploadNotTextError`, a body that
    is not plain text, to HTTP 415.

    ``str(exc)`` names the file, for the uploader's own 400 response. ``reason`` is the same text
    without the name, and is what the audit row records: the audit log is plaintext and kept, and an
    operator-chosen file name can carry a patient identifier (vault BACKLOG #2619)."""

    def __init__(self, display: str, reason: str) -> None:
        super().__init__(f"upload {display!r} {reason}")
        self.display = display
        self.reason = reason

    def __reduce__(self) -> tuple[type[UploadContentError], tuple[str, str]]:
        # The default rebuilds from ``self.args``, the one formatted message, which this signature
        # does not take; copy and pickle would raise TypeError.
        return (type(self), (self.display, self.reason))


class UploadNotTextError(UploadContentError):
    """An upload's body is not plain text (ASVS 14.2.8): it begins with a binary container's
    signature, holds a NUL byte, or has a control-dense 8 KiB window, as
    ``parsing.sniff.nontext_upload_reason`` judges it. ``reason`` is that function's
    text. The API answers it 415, where any other :class:`UploadContentError` is 400 (BACKLOG
    #5551)."""


class UploadFieldError(UploadContentError):
    """A value :meth:`UploadStore.save` would store in the sidecar is one the sidecar reader refuses
    (BACKLOG #5387): at least an account name or id longer than :data:`_MAX_SIDECAR_TEXT` allows, a
    field that holds a lone surrogate, an engine clock that reads earlier than
    :data:`_MIN_SIDECAR_STAMP` (2026-01-01T00:00:00Z) or later than 2^53 seconds
    (:func:`_stamp_in_range`), and sealed metadata longer than :data:`_SIDECAR_LIMIT`. The clock is
    the host's fault, not the uploader's, and is still answered 400. Refused before anything is
    written, so no upload is stored that
    its own owner could not see, and the quota would not bill. A subclass, so the API answers it
    as any other :class:`UploadContentError`: 400 and a metadata-only ``upload.reject`` audit.
    ``reason`` names the field and the defect, never the value."""


class UploadQuotaError(UploadError):
    """An upload would push the uploader over their file-count or aggregate-bytes quota (ASVS 5.2.4).

    The uploaded-logs feature caps how many files and how many aggregate bytes a single uploader may
    retain at once (``[store].max_upload_files_per_user`` / ``max_upload_total_bytes_per_user``, both
    defaults-ON). A would-be over-quota upload is refused at the chokepoint before anything is written;
    the API maps it to HTTP 409 and a metadata-only ``upload.reject_quota`` audit.

    The check and the write it authorises run as ONE critical section per process (ASVS 2.3.4), so
    concurrent uploads inside an engine cannot double-book the budget. The quota is scoped to the
    ``uploads_dir``, not to the process: :meth:`UploadStore._scan_metas_sync` re-reads the sidecars
    with no cache, so engine shards sharing one dir enforce ONE budget between them (measured
    2026-08-10). Shards pointed at separate dirs get separate budgets, by construction.

    The cross-PROCESS half is the ledger reservation (BACKLOG #1112). The per-process lock is an
    ``asyncio.Lock``, so N engine shards over one dir used to hold N of them and each could overshoot
    by one file while another scanned. :meth:`UploadStore._reserve_across_shards` now takes an atomic
    reservation on the ONE unified store every shard shares before the write and pays it back after,
    so a shard mid-upload is visible to its siblings.

    **The reservation alone did not make the decision exclusive, and this paragraph used to say it
    did (BACKLOG #1942).** The reserve checked headroom from a scan taken before it, so a sibling
    shard's file could land in between and two shards could each pass on stale headroom, while the
    later disk scan never read the ledger (BACKLOG #1941). Measured shape: cap 3, one file on disk,
    two shards, four files landed.

    What holds now is narrower and is an ordering argument, not a lock. **This is the one place it is
    written; the code and the store docstrings point here.** Each upload reserves, THEN reads the
    ledger's in-flight total (``Store.upload_quota_in_flight``), THEN scans the disk, and is refused
    unless the disk, the siblings' share of that total, and this file all fit. Take the last of any
    set of concurrent uploads to do its read. Every other one reserved before its own read, so before
    this one, and is now either still reserved, which the read counts, or released. A release happens
    only after that upload's file landed, so the later disk scan counts it, or after its write failed,
    and then there is no file to count. So the last reader counts every sibling. A file that has
    landed but is not yet released is counted twice, which can refuse an upload that would have fit.
    That errs toward refusing and clears when the sibling releases.

    Residuals, stated precisely. At least these three survive the ordering:

    * **No ledger bound.** ``UploadStore(store=None)`` — the genuinely store-less construction path
      (embedding / tests) — keeps only the per-process lock, so the pre-#1112 bound applies there: at
      most **N-1 files** over, one per shard mid-write, each bounded by ``max_upload_bytes``.
    * **A leaked reservation.** A process killed between reserve and release never pays back, and
      its slot narrows that uploader's budget until it goes stale. It errs toward refusing, not
      allowing. Each reservation is its own ledger row with its own clock, named by the save's
      ``file_id`` (vault BACKLOG #3180). So a leaked slot is reclaimed
      ``UPLOAD_RESERVATION_STALE_AFTER`` after its last touch however active the uploader stays,
      and a release pays back only its own slot. A cancelled ``save`` waits a bounded time for its
      reserve and release (BACKLOG #2263), and starts a release by id even for a reserve whose
      outcome it never learned. That release pays back a slot only if one is committed when it
      runs, and it can fail or be cancelled like any other. At least these still leak until the
      window passes: a release that fails; a release cancelled at its
      ``_LEDGER_STRAGGLER_MAX_SECONDS`` cap or by the shutdown drain; a reserve whose statement
      commits after the release by id ran; and a reserve the shutdown drain cancels, which starts
      no release. The module logs a WARNING when it gives up on a call, but it cannot see a
      statement that commits later, so that leak has no line of its own, only the earlier
      WARNING that the reserve was cancelled or failed. **On Postgres and SQL Server the stamp
      and the staleness test both read the database server's clock (BACKLOG #3256),** so an
      engine host's skew no longer moves either. A server clock that ran ahead and is stepped
      back still holds a slot it stamped meanwhile longer by the step, because that stamp was
      written ahead, and so does a failover to a replica whose clock lags the old primary's. A
      server clock stepped forward, or a failover to a replica whose clock runs ahead, makes every
      slot look older by the step, so it can reclaim a live slot early (the next bullet). So the
      database servers' own time sync now carries what each engine host's did. SQLite reads the engine host's clock, and only one host ever writes a SQLite
      store, because ``require_unified_store`` refuses SQLite for more than one engine shard.
    * **A reclaimed live reservation (BACKLOG #2648).** The store reclaims a reservation with no
      activity for ``UPLOAD_RESERVATION_STALE_AFTER``, and it cannot tell a dead holder from a slow
      one. A live save touches its own reservation every ``_RESERVATION_HEARTBEAT_SECONDS``
      (:meth:`UploadStore._start_heartbeat`), so a slow save keeps its slot. A live slot is still
      reclaimed in at least these cases: its holder lands no touch for the whole window while it is
      alive (a suspended process or VM, an event loop starved for minutes, or a store this engine
      shard cannot reach while a sibling can); its save outlives
      ``_RESERVATION_HEARTBEAT_MAX_SECONDS``; its touches stall on the store for the whole
      window; one touch never returns, since no second touch starts while one runs (BACKLOG
      #3256); or the database server's clock steps forward by a large part of the window, or a
      failover lands on a replica whose clock runs that far ahead. A sibling then counts neither
      that file nor its slot until the file lands. The holder's later release deletes only its
      own row, so the undercount ends with that save. That restores the N-1 bound above while it
      lasts, never worse than the pre-#1112 behaviour. Host clock skew is not one of these cases
      on the server backends (the bullet above says why).

    The ledger is checked and paid back around the write, not in the same transaction as it, because
    the body lives on the filesystem rather than in the store. The ordering above is what stands in
    for that transaction, and the residuals above are the known limits of the cross-process bound."""


class UploadUnreadableError(UploadError, CipherError):
    """The store cipher refused an uploaded file on a by-id read (BACKLOG #1169).

    On a keyed store that is usually a plaintext upload stored before the key was enabled, which a
    keyed store refuses until ``rotate-key`` seals it, where it can (owner ruling 2026-09-23, BACKLOG
    #2322). It can also be a file under a key that is no longer configured. It is a
    :class:`CipherError` too, so any caller that already catches the cipher's error still does. The
    API maps it to HTTP 423 without importing the cipher module. The message is the cipher's own,
    which names only the surface and the remedies it offers, or
    :data:`_REFUSED_NOT_UNSEALABLE` from :meth:`UploadStore.delete`, which names neither. A damaged
    file raises the subclass :class:`UploadDamagedError` (BACKLOG #5388), and a part the filesystem
    refused the engine, such as one whose permissions deny it, raises the subclass
    :class:`UploadAccessError` instead (BACKLOG #5388 added item 2). On a store that refuses
    plaintext, :meth:`UploadStore.delete` may instead remove a sidecar that is not UTF-8 or is
    oversized, when it is the never-sealable kind the scan classes too."""


class UploadUnavailableError(UploadError, CipherError):
    """The store cipher's key service gave no verdict on an uploaded file, so a later try may
    succeed (BACKLOG #3734). Raised for :class:`~messagefoundry.store.crypto.CipherUnavailableError`
    where :class:`UploadUnreadableError` would otherwise be, and from :meth:`UploadStore.save`. The
    file is neither refused nor changed, and nothing was removed. The API answers it 503 with
    ``Retry-After``. The message is the cipher's own, as :class:`UploadUnreadableError`'s is."""


#: The text of the refusal :meth:`UploadStore.delete` raises when its caller's read was refused
#: and the upload is not the never-sealable kind. It names no file and no cipher detail.
_REFUSED_NOT_UNSEALABLE = "the uploaded file's metadata is refused under the configured store key"


_DAMAGED = "the uploaded file's {part} is damaged or is not this upload's, so it was not read"

_STORAGE_UNREACHABLE = "the uploads directory could not be reached, so nothing was read or changed"

_STORAGE_UNCONFIRMED = (
    "the uploads directory could not be reached during the delete, so whether the file's content "
    "was removed could not be confirmed"
)

_STILL_SEALED = "the uploaded file's {part} is sealed under a store key this engine does not hold"

_ACCESS_REFUSED = (
    "the uploaded file's {part} could not be opened: the filesystem refused the engine"
)


def _refuse_still_sealed(text: str, part: str) -> None:
    """Raise a :class:`CipherError` when the cipher handed back text that is still sealed, as the
    keyless cipher does with a value it cannot open. Such a file is not damaged: the key it was
    sealed under recovers it. So it must take the cipher-declined path, which the prune never
    removes, rather than the damaged one, which the prune ages on disk (BACKLOG #5387, #5388). No
    sidecar JSON and no base64 body ever starts with the marker, so a sound file never trips it.
    A sidecar's padding is skipped, as its reader skips it; a body has none (BACKLOG #5387)."""
    if (_unpadded(text) if part == "sidecar" else text).startswith(MARKER_PREFIX):
        raise CipherError(_STILL_SEALED.format(part=part))


class UploadDamagedError(UploadUnreadableError):
    """The :class:`UploadUnreadableError` of a damaged file, which no key or ``rotate-key`` repairs
    (BACKLOG #5388): at least a file that is not UTF-8, a body that is not strict base64, a sidecar
    that is not this upload's metadata, and a part that is not a regular file. A subclass, so a
    caller that catches the refusal still does, and the API can answer it with its own text."""


class UploadAccessError(UploadUnreadableError):
    """The :class:`UploadUnreadableError` of a part the filesystem refused the engine (BACKLOG
    #5388 added item 2): a ``PermissionError``, which is at least a permission or an ACL the engine
    lacks, or on Windows a file another program holds open. The file is not known to be damaged,
    and fixing the cause makes it readable again, so the API answers it with its own text, which
    does not invite a delete. The listing scan skips such a sidecar and the prune never ages it.
    A delete answers a body another handle holds open with :class:`UploadDeleteIncompleteError`
    instead (BACKLOG #5388 added item 3)."""


def _refusal(file_id: str, part: str, defect: str, kind: _ReadRefusal) -> UploadUnreadableError:
    """The refusal a by-id read raises for a part read as ``kind`` (:func:`_refused_read`), logged
    as :func:`_damaged` logs one. ``defect`` is already rendered content-free, and the caller
    raises after its handler ends, so the error is not left on the refusal's ``__context__``."""
    if kind == "denied":
        _log.warning("uploaded-file %s %s: access refused on disk: %s", part, file_id, defect)
        return UploadAccessError(_ACCESS_REFUSED.format(part=part))
    return _damaged(file_id, part, defect)


def _unreachable(file_id: str, fault: str) -> UploadStorageUnreachableError:
    """Log that upload ``file_id`` could not be reached on disk, and return the refusal a by-id read
    or the delete raises for it (BACKLOG #5388 added item 3). ``fault`` is already rendered."""
    _log.warning("uploaded file %s could not be reached on disk: %s", file_id, fault)
    return UploadStorageUnreachableError(_STORAGE_UNREACHABLE)


def _damaged(file_id: str, part: str, defect: str) -> UploadDamagedError:
    """Log a damaged ``part`` of upload ``file_id`` and return the refusal a by-id read raises
    (BACKLOG #5388), so one damaged file answers a handled error rather than a server error.
    ``defect`` is already rendered content-free, and the caller raises after its handler ends, so
    the decode error, which holds the whole file, is not left on the refusal's ``__context__``."""
    _log.warning("uploaded-file %s %s: damaged, refused: %s", part, file_id, defect)
    return UploadDamagedError(_DAMAGED.format(part=part))


def _refuse_unplain(file_id: str, part: str, path: Path) -> None:
    """Raise the damaged refusal when ``path`` is not a plain file (:func:`_not_a_plain_file`),
    the test the listing scan meets through :func:`_open_plain`'s own ``lstat`` (BACKLOG #5552), so a by-id read does not open a directory,
    which answered a server error, or a FIFO, which blocked a worker thread for good, that is in
    place when it looks. It guards against what is on disk then, not against a writer racing it.
    The reads that follow open through :func:`_open_plain`, which refuses a file swapped in after
    its own ``lstat`` (BACKLOG #5387 added item 1). The delete only unlinks the body, so a FIFO
    swapped in there is unlinked, never opened. A path that is absent passes, and the caller's read
    answers it as missing."""
    refused = _not_a_plain_file(path)
    if refused is not None:
        raise _damaged(file_id, part, refused)


class UploadNotFoundError(UploadError):
    """No uploaded file exists for the given (well-formed) file_id."""


class UploadStorageUnreachableError(UploadUnavailableError):
    """The uploads directory, or the share it is on, could not be reached, so nothing was read,
    removed or changed, and a later try may succeed (BACKLOG #5388 added item 3). Raised where a
    ``FileNotFoundError`` would otherwise say a part is gone, so an outage never reads as a
    missing upload or a finished delete. A subclass of :class:`UploadUnavailableError`, so every
    route answers it 503 with ``Retry-After``, with its own text."""


class UploadDeleteUnconfirmedError(UploadStorageUnreachableError):
    """A delete whose body unlink failed while the share could not be reached, so whether the
    body was removed is not known: a network filesystem may apply a delete whose reply never
    arrives (BACKLOG #5388 added item 3). The sidecar was not touched. ``meta`` is the upload's
    metadata, so the route records the attempt with its outcome unknown, never as nothing
    removed."""

    def __init__(self, message: str, meta: UploadedFileMeta | None = None) -> None:
        # Only the text in args, as UploadDeleteIncompleteError keeps only its id: the metadata
        # holds the uploader's filename.
        super().__init__(message)
        self.meta = meta

    def __reduce__(self) -> tuple[type[UploadDeleteUnconfirmedError], tuple[object, ...]]:
        return (type(self), (self.args[0], self.meta))


@dataclass(frozen=True)
class UploadRemoval:
    """What one :meth:`UploadStore.delete` call removed (BACKLOG #5388 added item 3): the upload's
    metadata, and whether this call unlinked its body and its sidecar. A part already absent is
    not counted, so the route records only what the call did."""

    meta: UploadedFileMeta
    body_removed: bool
    sidecar_removed: bool
    #: Whether the sidecar was there when this call took the pair lock. One already gone, as
    #: after another remover, is neither removed nor kept, so the row says neither.
    sidecar_was_there: bool = True

    @property
    def removed_any(self) -> bool:
        return self.body_removed or self.sidecar_removed


class UploadDeleteIncompleteError(UploadError):
    """A delete :meth:`UploadStore.delete` could not finish, though it tried each unlink again
    briefly, and that a later try may finish (BACKLOG #5388 added item 3). ``removed`` says what
    this call did remove, when its sidecar could not go after it reached the unlinks: at least the
    body, or nothing, as on a retry whose sidecar still cannot go. The upload is then still on
    disk and still counted. ``None`` when another handle held the body open, as the engine's own
    read of it does on Windows (:func:`_in_use`), so nothing was removed."""

    def __init__(self, file_id: str, removed: UploadRemoval | None = None) -> None:
        # Only the id in args: the metadata holds the uploader's filename, which an orphaned
        # operation's log line would print through the error's repr.
        super().__init__(file_id)
        self.removed = removed

    def __reduce__(self) -> tuple[type[UploadDeleteIncompleteError], tuple[object, ...]]:
        return (type(self), (self.args[0], self.removed))


@dataclass(frozen=True)
class UploadedFileMeta:
    """Non-body metadata about one uploaded file (persisted encrypted in the ``.meta`` sidecar).

    ``filename`` is the operator-supplied name, sanitized for display; it is never a filesystem path.
    ``content_type`` is the format tag (``hl7v2``/``xml``/``text``), not an HTTP MIME type.

    TWO owner fields, and the split is deliberate. ``uploader_id`` is the account's **immutable**
    identifier (``Identity.user_id``, a ``uuid4`` hex minted once per account row) and is the ONLY
    value ownership and the per-uploader quota key on. ``uploader`` is the username, which is a
    **display label**: it is unique among live accounts but it is *reusable* — deleting an account
    frees the name, and recreating it mints a different ``user_id``. Keying either the ownership
    check or the budget on the name would hand a recycled account the departed operator's files.

    **The id is immutable per ROW, and on AD it is now per PERSON too (BACKLOG #1471).**
    ``_upsert_ad_user`` used to resolve by ``sAMAccountName`` and mint a new ``user_id`` only when no
    mirror row survived, so a directory-side recycle WITHOUT a MessageFoundry ``delete_user`` re-bound
    the EXISTING id to the new principal and this field followed it. It now resolves by the
    directory's immutable id (``users.directory_object_id``), and refuses a principal whose id
    disagrees with the row holding its username, so a recycled name gets a new ``user_id``. The
    remaining gap is a directory that returns no immutable identifier at all, where name resolution
    still applies."""

    file_id: str
    filename: str
    uploader: str
    uploader_id: str
    content_type: str
    size: int
    sha256: str
    uploaded_at: float
    message_count: int


@dataclass(frozen=True)
class _UnsealableUpload:
    """One kind of upload ``rotate-key`` cannot seal, which the retention prune and the quota still
    read (BACKLOG #2322).

    It is a plaintext sidecar that a keyed store refuses, over a body that is missing or is not
    text (:meth:`UploadStore._unsealable_sync` is the test). ``rotate-key`` leaves that sidecar
    unsealed, because sealing it would list an upload with no usable body and would seal a planted
    lone sidecar too. So it is refused on every read, for good. The listing and the by-id reads never
    serve it, and :meth:`UploadStore.delete` removes it.

    **Not every refused upload is one, so this class does not keep every refused upload inside
    retention** (BACKLOG #3240). At least a plaintext sidecar over a body that is oversized and not
    text, is not a regular file, or cannot be read for another cause is not. A blank sidecar, or one
    that is not UTF-8 within the part :meth:`UploadStore._unsealable_sync` reads, is not one either,
    but the prune ages it as damaged (:meth:`UploadStore._aged_on_disk_sync`), which reuses this record
    with a blank owner. ``docs/PHI.md`` §3 names the ones outside retention.

    At least these fields are not taken from the plaintext. ``file_id`` comes from the PATH, so a
    planted sidecar cannot name another upload. ``modified`` is the sidecar's mtime, which is the
    expiry clock. ``size`` is the body's size on disk, never the sidecar's claim, so it cannot be
    negative. ``uploader_id`` IS read from the plaintext, and is used here only to bill the quota. A
    plant can bill another uploader that way, which errs toward refusing an upload until the plant
    expires.
    """

    file_id: str
    uploader_id: str
    size: int
    modified: float

    def expired(self, cutoff: float, now: float) -> bool:
        # An mtime more than a day ahead is not a clock the engine set: a plant dated into the future
        # would otherwise never age out, and keep billing an uploader forever. The cost: a clock set
        # back more than a day, or a past ``now`` passed in, prunes these uploads early. Each one is
        # refused on every read for good, so early is the safe direction.
        return self.modified < cutoff or self.modified > now + _SECONDS_PER_DAY

    def as_meta(self) -> UploadedFileMeta:
        """The metadata an ``upload.prune`` or ``upload.delete`` audit row reports. The owner fields
        are blank: a permanent audit record must not name an owner the engine cannot verify."""
        return UploadedFileMeta(
            file_id=self.file_id,
            filename="",
            uploader="",
            uploader_id="",
            content_type="",
            size=self.size,
            sha256="",
            uploaded_at=self.modified,
            message_count=0,
        )


class _Observed(NamedTuple):
    """What one uploader holds on disk, from :meth:`UploadStore._observed_sync`.

    ``files`` and ``size`` are what the quota scan bills, the uploads ``rotate-key`` cannot seal
    (:class:`_UnsealableUpload`) included. An upload the scan neither reads nor classes is not in
    them.
    ``unsealable_files`` and ``unsealable_size`` count those again on their own, because the listing
    never shows them, and a 409 that bills them must say how much of the budget the uploader cannot
    see (BACKLOG #3183)."""

    files: int
    size: int
    unsealable_files: int
    unsealable_size: int


def _unsealable_note(observed: _Observed, *, by_bytes: bool = False) -> str:
    """The clause a quota refusal adds for the uploads it bills that the listing never shows, or
    ``""`` when they add nothing to the cap that fired: none at all, or, for the byte cap
    (``by_bytes``), none holding a byte (BACKLOG #3183). The engine-shard refusal names both caps
    and cannot tell which one its sibling tipped, so it passes the default and says the clause
    whenever any is billed.

    Counts only. Never a file id and never a file name: the name comes from a plaintext sidecar
    nobody can verify, and an operator-chosen name can carry a patient identifier. The refusal is
    also the ``upload.reject_quota`` audit reason, which is kept."""
    if not (observed.unsealable_size if by_bytes else observed.unsealable_files):
        return ""
    return (
        "; counted here are uploaded files that cannot be read under the configured store key and "
        f"are not listed: {observed.unsealable_files}, holding {observed.unsealable_size} bytes. "
        "The retention prune removes them once they expire"
    )


def sanitize_filename(name: str | None) -> str:
    """Reduce an operator-supplied filename to a safe, display-only string (basename, no control chars,
    bounded length). Never used to locate a file on disk — the ``file_id`` is the on-disk identity."""
    if not name:
        return "upload"
    # Strip directory parts on either separator (the value may come from a Windows or POSIX client).
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    # Cut, then strip again, so a cut that ends on a space leaves none and a second pass, as every
    # sidecar read makes (BACKLOG #5387), returns the same name.
    base = strip_control_chars(base).strip()[:_MAX_FILENAME].rstrip()
    return base or "upload"


class _MalformedSidecarError(ValueError):
    """A sidecar that reached the JSON parse but is not metadata this store would have written
    (BACKLOG #5387, #5388). Its message names only the defect, never a value from the sidecar."""


class _OversizedFileError(_MalformedSidecarError):
    """A sidecar larger than any the store writes, refused before it is read whole (BACKLOG #5387
    added item 1). It is its damage, as any other malformed sidecar's is."""

    def __init__(self, limit: int) -> None:
        super().__init__(f"it is larger than {limit} bytes")


#: The longest each text field of a sidecar may be. :meth:`UploadStore.save` writes a hex SHA-256
#: and a format tag, which are always within it, and the sanitized filename and an account's own
#: name and id, which it refuses up front when the reader would (:class:`UploadFieldError`), so no
#: write is one the reader refuses. A longer one is refused as malformed, so a plant cannot carry an
#: unbounded value into the permanent ``upload.prune`` audit row, a listing page or a log line.
_MAX_SIDECAR_TEXT = {
    "filename": _MAX_FILENAME,
    "uploader": 1024,
    "uploader_id": 1024,
    "content_type": 64,
    "sha256": 64,
}


def _sidecar_text_defect(key: str, value: str) -> str | None:
    """Why the text field ``key`` of a sidecar would be refused, or ``None``. The one rule, which
    the reader applies and :meth:`UploadStore.save` applies before it writes, so the two agree."""
    if len(value) > _MAX_SIDECAR_TEXT[key]:
        return f"field {key!r} is longer than {_MAX_SIDECAR_TEXT[key]} characters"
    # A JSON escape can carry a lone surrogate, which no response can serialize, so one such
    # sidecar would fail every listing page it falls on.
    if has_lone_surrogate(value):
        return f"field {key!r} holds a lone surrogate"
    return None


def _sidecar_text(d: dict[str, Any], key: str, default: str) -> str:
    value = d.get(key, default)
    if not isinstance(value, str):
        raise _MalformedSidecarError(f"field {key!r} is not a string")
    defect = _sidecar_text_defect(key, value)
    if defect is not None:
        raise _MalformedSidecarError(defect)
    return value


#: The largest count a sidecar may carry, far past any upload the engine accepts, and the largest
#: ``uploaded_at`` in seconds. It bounds the digits a plant can write into the audit detail. It
#: does not stop a plant billing an uploader out of quota: any count near it does that, because
#: ``size`` is not checked against the body on disk.
_MAX_SIDECAR_COUNT = 2**53

#: The earliest ``uploaded_at`` a sidecar may carry: 2026-01-01T00:00:00Z, before the first release
#: of this engine (0.1.0, 2026-06-18), so no sidecar the store wrote is older (BACKLOG #5387 added
#: item 1). A planted small stamp such as ``1`` would otherwise be read as decades old and its pair
#: deleted on the first prune pass, the same harm a zero or negative stamp did.
_MIN_SIDECAR_STAMP = 1_767_225_600


def _sidecar_count(d: dict[str, Any], key: str) -> int:
    value = d.get(key, 0)
    # bool is an int subclass, and no field here is ever written as one.
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value <= _MAX_SIDECAR_COUNT
    ):
        raise _MalformedSidecarError(f"field {key!r} is not a count in range")
    return value


def _stamp_in_range(value: object) -> TypeGuard[int | float]:
    """Whether ``value`` is an ``uploaded_at`` the sidecar reader accepts: a number no earlier than
    :data:`_MIN_SIDECAR_STAMP` and no larger than :data:`_MAX_SIDECAR_COUNT`. The one rule, which
    the reader applies and :meth:`UploadStore.save` applies to its clock before it writes, so the
    two agree.

    A missing stamp, and one before that floor, such as 0, a negative one or a small positive one,
    are refused rather than read as decades old: the prune would delete the body on its first
    pass, with no retention window (BACKLOG #5387). Refused, the pair is aged by its age on disk
    instead (:meth:`UploadStore._aged_on_disk_sync`). A planted stamp after the floor but older
    than the retention window is not refused, since no rule that reads no clock can tell it from
    a genuine old upload; planting one needs write access to the store, which can delete the body
    anyway."""
    # bool is an int subclass, and no stamp is ever written as one. An int compares with a float
    # exactly, so a huge one is refused here rather than overflowing; NaN fails both bounds, and
    # infinity the upper one.
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and _MIN_SIDECAR_STAMP <= value <= _MAX_SIDECAR_COUNT
    )


def _meta_from_json(raw: str, file_id: str) -> UploadedFileMeta:
    """The metadata a decrypted sidecar holds, checked rather than trusted (BACKLOG #5387).

    On a store that passes unmarked sidecars (keyless, ``vault_transit``, or
    ``allow_unmarked_ciphertext``) the JSON is not bound to its path, so a planted one could name
    another upload's ``file_id`` for the prune to delete, or carry a negative ``size`` that lifts a
    quota. So the ``file_id`` must be the path's own id, each count an integer from 0 to
    :data:`_MAX_SIDECAR_COUNT`, the timestamp present and a number from
    :data:`_MIN_SIDECAR_STAMP` to that bound (:func:`_stamp_in_range`), and every text field a
    string no longer than :data:`_MAX_SIDECAR_TEXT` allows with no lone surrogate, and the filename
    is sanitized as :meth:`UploadStore.save` sanitizes it. Anything else, including JSON that does
    not parse or nests past the parser's depth, raises :class:`_MalformedSidecarError` (BACKLOG
    #5388).

    **The check reads no clock.** A timestamp far ahead of the clock is not refused: after a host
    clock is stepped back, every genuine upload is dated ahead, and refusing them would hide each
    from its owner and from the quota. Such a timestamp is not trusted for retention either, since
    it would never age out; the prune ages that upload by its pair's age on disk instead
    (:meth:`UploadStore.prune_expired`).

    A refused sidecar is left out of the listing and the quota, and the prune ages it as
    :meth:`UploadStore._aged_on_disk_sync` says."""
    # Returns rather than raises, so the decode error, which holds the whole sidecar, is not left
    # on the refusal's __context__.
    d, hint = json_loads_or_refusal(_unpadded(raw))
    if hint is not None:
        raise _MalformedSidecarError("not valid JSON")
    if not isinstance(d, dict):
        raise _MalformedSidecarError("not a JSON object")
    if d.get("file_id") != file_id:
        raise _MalformedSidecarError("its file_id is not its own upload id")
    uploaded_at = d.get("uploaded_at")
    if not _stamp_in_range(uploaded_at):
        raise _MalformedSidecarError("field 'uploaded_at' is not a time in range")
    stamp = float(uploaded_at)
    return UploadedFileMeta(
        file_id=file_id,
        filename=sanitize_filename(_sidecar_text(d, "filename", "upload")),
        uploader=_sidecar_text(d, "uploader", ""),
        # Tolerant, like every other optional field — a sidecar without the key yields "", which
        # matches NOBODY at the ownership check (api/app.py ``_may_access_upload``) and buckets
        # into no operator's quota. That is the fail-closed end state, not a migration gap: there
        # is deliberately no fallback to ``uploader`` here, because a name fallback would
        # reintroduce exactly the recycled-username reachability this field exists to close.
        uploader_id=_sidecar_text(d, "uploader_id", ""),
        content_type=_sidecar_text(d, "content_type", "hl7v2"),
        size=_sidecar_count(d, "size"),
        sha256=_sidecar_text(d, "sha256", ""),
        uploaded_at=stamp,
        message_count=_sidecar_count(d, "message_count"),
    )


def content_type_for(filename: str) -> str:
    """Best-effort format tag from the filename extension (display + browse hint only)."""
    lower = filename.lower()
    if lower.endswith((".hl7", ".hl7v2")):
        return "hl7v2"
    if lower.endswith(".xml"):
        return "xml"
    return "text"


# The uploaded-logs feature scopes uploads to text diagnostic logs (ADR 0134); the extension allowlist
# mirrors content_type_for's mapping. Anything else is refused at the chokepoint (ASVS 5.2.2).
_ALLOWED_UPLOAD_EXTENSIONS = (".hl7", ".hl7v2", ".txt", ".xml")


def validate_upload_content(display: str, data: bytes) -> None:
    """Text-only check, extension allowlist and content-vs-extension sniff for an uploaded file.

    First, the whole body must be plain text (ASVS 14.2.8, ``parsing.sniff.nontext_upload_reason``):
    no binary container signature, no NUL byte anywhere, and no control-dense window. A failure
    raises :class:`UploadNotTextError`, which the route answers 415. It is checked here, at the
    chokepoint, and nowhere else, so every caller of :meth:`UploadStore.save` meets it (BACKLOG
    #5551).

    Then (ASVS 5.2.2) it raises :class:`UploadContentError` when the sanitized display filename's
    extension is not permitted, or when the content's leading bytes contradict the extension:

    * ``.hl7``/``.hl7v2`` → an MSH/FHS/BHS HL7 header sniff;
    * ``.xml`` → a leading ``<`` after any BOM/whitespace;
    * ``.txt`` → nothing more (``.txt`` has no magic signature, so content validation is necessarily
      weak — the same residual the plain-text connectors carry).

    Pure (no I/O), but linear in the body, so :meth:`UploadStore.save` runs it off the event loop.
    Reuses the shared ``parsing.sniff`` magic-byte helpers, so the upload chokepoint and the File
    connectors enforce the same sniff."""
    nontext = nontext_upload_reason(data)
    if nontext is not None:
        raise UploadNotTextError(display, nontext)
    if not display.lower().endswith(_ALLOWED_UPLOAD_EXTENSIONS):
        raise UploadContentError(
            display,
            f"has a disallowed extension; permitted: {', '.join(_ALLOWED_UPLOAD_EXTENSIONS)}",
        )
    ctype = content_type_for(display)
    if ctype == "hl7v2" and not _looks_like_hl7(data):
        raise UploadContentError(
            display, "is not HL7 (no MSH/FHS/BHS header) despite its extension"
        )
    if ctype == "xml" and not _sniff_head(data).startswith(b"<"):
        raise UploadContentError(display, "is not XML (no leading '<') despite its extension")


def _decode_text(data: bytes) -> str:
    """Decode uploaded bytes to text for splitting/peeking, tolerant of non-UTF-8 (replace, never raise —
    a diagnostic file may be mis-encoded; the browse view degrades gracefully)."""
    return data.decode("utf-8", errors="replace")


def split_uploaded(data: bytes) -> list[str]:
    """Split an uploaded file's bytes into individual HL7 messages (the File-source splitter)."""
    return split_batch(_decode_text(data))


@dataclass(frozen=True)
class BrowsedMessage:
    """One split message inside an uploaded file (metadata only — never the decrypted body)."""

    index: int
    message_type: str | None
    control_id: str | None
    size: int


@dataclass(frozen=True)
class BrowseResult:
    """A filtered/paginated page of an uploaded file's split messages."""

    messages: list[BrowsedMessage]
    total_messages: int
    scanned: int
    matched: int
    truncated: bool


def browse_messages(
    data: bytes,
    *,
    spec: SearchSpec | None,
    message_type: str | None,
    control_id: str | None,
    limit: int,
    offset: int,
) -> BrowseResult:
    """Split ``data`` into messages, apply the offline filters (metadata substring on
    ``message_type``/``control_id`` + an optional ADR 0046 content needle), and return one page.

    Pure + off-loop friendly (no I/O, no cipher). Peeking a message is tolerant — an unparseable body
    simply has ``None`` metadata and can't satisfy a metadata/content filter, never an error."""
    parts = split_uploaded(data)
    total = len(parts)
    mt_needle = (message_type or "").strip().casefold()
    cid_needle = (control_id or "").strip().casefold()
    matched: list[BrowsedMessage] = []
    for idx, raw in enumerate(parts):
        try:
            peek = Peek.parse(raw)
            mtype: str | None = peek.message_type
            cid: str | None = peek.control_id
        except HL7PeekError:
            mtype = cid = None
        if mt_needle and mt_needle not in (mtype or "").casefold():
            continue
        if cid_needle and cid_needle not in (cid or "").casefold():
            continue
        if spec is not None and not row_matches(spec, raw=raw, summary=None):
            continue
        matched.append(BrowsedMessage(index=idx, message_type=mtype, control_id=cid, size=len(raw)))
    page = matched[offset : offset + limit]
    return BrowseResult(
        messages=page,
        total_messages=total,
        scanned=total,
        matched=len(matched),
        truncated=offset + limit < len(matched),
    )


@dataclass(frozen=True)
class ResealResult:
    """What one :meth:`UploadStore.reseal_to_active` pass did.

    ``skipped`` is load-bearing, not decoration: an operator reads it to decide whether it is safe to
    drop the retired key. A file this pass could not read MAY still be sealed under the OLD key, and
    dropping that key would make it permanently unreadable, so a non-zero ``skipped`` means "fix the
    cause and run it again before you retire anything". ``rotate-key`` exits non-zero and writes no
    rotation stamp while it is non-zero (BACKLOG #3181). It includes a value no configured key opens,
    which the pass leaves as it was and moves past. A readable-sized body that is missing or is not
    text is not counted here when its sidecar is readable: no key reads that body and no re-run
    changes it (``unsealable``, ``body_lost``), and neither is anything that is not a file, such as
    a FIFO or a directory (``not_regular``). At least a body too large for an upload, a symlink and
    a sidecar every reader refuses before decrypting, as over the sidecar cap, not UTF-8 or
    plaintext too long to seal, are still skips, whatever that sidecar holds (BACKLOG #5387).

    The counts use different units. ``resealed`` counts VALUES: each body or sidecar it rewrites
    adds one. ``skipped`` counts UPLOADS: a pair adds at most one, whichever half failed (BACKLOG
    #2322)."""

    resealed: int = 0
    skipped: int = 0
    #: How many UPLOADS this pass cannot seal and left as they were: a PLAINTEXT sidecar over a body
    #: that is missing or is not text (BACKLOG #2322). Not counted in ``skipped``: neither half is
    #: under any key, so retiring one loses nothing, and no re-run changes them. They stay refused on
    #: every read where the store refuses plaintext. The prune removes them once they expire
    #: (:class:`_UnsealableUpload`).
    unsealable: int = 0
    #: How many UPLOADS had a plaintext half that this pass sealed (BACKLOG #1169). It counts files,
    #: not values, so it matches the count ``serve`` logs at startup (:meth:`UploadStore.warn_if_unsealed`).
    #: A keyed store refuses those uploads until this pass seals them. An upload also counted in
    #: ``skipped`` counts here too when one half was sealed, since a planted body under a sealed
    #: sidecar would otherwise be sealed without ever being counted (BACKLOG #3240). The cost is
    #: that an upload whose two plaintext halves are sealed in two runs counts in both, so after a
    #: skip the total across runs can exceed the startup count without a plant.
    sealed_plaintext: int = 0
    #: How many UPLOADS have a SEALED sidecar over a body that is missing or is not text (BACKLOG
    #: #3181). Not counted in ``skipped``: the body is under no key, and the sidecar is re-sealed like
    #: any other, so retiring the prior key loses nothing. The upload stays listed with a body that
    #: cannot be read until an operator deletes it or the retention prune removes it at expiry.
    body_lost: int = 0
    #: How many UPLOADS have a body or sidecar that is neither a regular file nor a symlink, such as
    #: a FIFO or a directory (BACKLOG #3737). It holds no value, so it is not a skip, and an operator
    #: removes it by hand. A symlink is not counted here: its target may be under the prior key, so
    #: it is a skip.
    not_regular: int = 0
    #: How many UPLOADS have a sidecar that provably holds nothing (BACKLOG #5387 added item 1):
    #: read in full within :data:`_SIDECAR_LIMIT`, it is empty, or only the byte-order mark and
    #: whitespace a reader skips. Every reader refuses it as damaged. No value under any key is in
    #: it, so retiring the prior key loses nothing of it, and no re-run changes it, so it is not a
    #: skip and does not keep ``rotate-key`` from completing. The sidecar is left as it is, and its
    #: body is still re-sealed as any other, and over a body the pass skips the upload counts in
    #: ``skipped`` instead. At least a sidecar every reader refuses before decrypting as over
    #: :data:`_SIDECAR_LIMIT`, not UTF-8 or plaintext too long to seal is a skip, never counted
    #: here, since the pass does not look inside it for a value under the prior key
    #: (:meth:`UploadStore._refused_meta`). A sidecar that is not a regular file is not counted
    #: here either (``not_regular``). ``rotate-key``'s output does not report this count; the log
    #: names each one.
    damaged: int = 0
    #: How many of the ``skipped`` UPLOADS were skipped because their sidecar is one every reader
    #: refuses before decrypting, as over :data:`_SIDECAR_LIMIT`, not UTF-8, or plaintext too long
    #: to seal (BACKLOG #5387). Each is also counted in ``skipped``. It could not be used, and it
    #: may hold a value under the prior key, so ``rotate-key`` says not to retire that key until
    #: it is fixed or deliberately removed, and never advises deleting it as a damaged file.
    refused_sidecars: int = 0
    #: True when the uploads root could not be listed, as when it is missing or is not a directory
    #: (BACKLOG #4940). ``rotate-key`` refuses such a root before it writes anything, so this is a
    #: backstop. A root that stays listable is not missing, so an empty mount point over a volume
    #: that is not mounted reads as no uploads; docs/PHI.md's ``rotate-key`` passage, under "It
    #: refuses only a path it cannot list", names at least the cases it leaves uncaught. Also True
    #: when a non-empty listing is followed by a root that is no directory, at the check right after
    #: the listing or at the pass's first pair-lock check. It is not a skip: ``rotate-key`` aborts
    #: on it before its audit roll.
    root_missing: bool = False

    @property
    def incomplete(self) -> bool:
        """True when an upload may still be under the prior key, so the run must not complete."""
        return bool(self.skipped) or self.root_missing


class _Half(Enum):
    """What one reseal pass did with one half (body or sidecar) of an upload. The pair's single count
    in :class:`ResealResult` is worked out from its two halves in one place."""

    CURRENT = auto()  # already under the active key; nothing was written
    RESEALED = auto()  # rewritten under the active key
    SEALED_PLAINTEXT = auto()  # the same, and it was plaintext
    LOST = auto()  # a body that is missing or is not text
    UNSEALABLE = auto()  # a plaintext sidecar over a lost body
    NOT_REGULAR = auto()  # no regular file or link, or a plaintext sidecar over one; left as is
    DAMAGED = auto()  # a blank sidecar, which holds nothing; left as is
    REFUSED = auto()  # a sidecar every reader refuses before decrypting; a skip, left as is
    SKIPPED = auto()  # it may still be under the prior key


#: The halves this pass rewrote, each one value in :attr:`ResealResult.resealed`.
_WRITTEN = frozenset({_Half.RESEALED, _Half.SEALED_PLAINTEXT})
#: More characters than any ``mfenc:`` marker has before its ciphertext.
_MARKER_READ_LIMIT = 256


@dataclass(frozen=True)
class PruneResult:
    """What one :meth:`UploadStore.prune_expired` pass did.

    ``pruned`` is the aged (blob, meta) pairs it deleted, carried whole because the caller writes one
    ``upload.prune`` audit row per file from that metadata. ``orphans_removed`` counts what the same
    pass swept as write leftovers (BACKLOG #1678). The sweep reads no metadata for one, so it is a
    count here and a WARNING in the log, not an audit row. A body goes on the file system's report
    that it has no sidecar, which does not prove that none landed
    (:meth:`UploadStore._sweep_orphans_sync`)."""

    pruned: list[UploadedFileMeta] = field(default_factory=list)
    orphans_removed: int = 0


class UploadQuotaLedger(Protocol):
    """What :class:`UploadStore` needs from the message store: an atomic, cross-process reservation
    of an uploader's in-flight upload budget (ASVS 2.3.4), and a read of it taken after reserving.

    Declared here as a structural protocol rather than importing ``store.base.Store``, so this module
    stays a leaf (see the module docstring). Every backend's ``Store`` satisfies it structurally —
    see :meth:`messagefoundry.store.base.Store.reserve_upload_quota` and
    :meth:`~messagefoundry.store.base.Store.upload_quota_in_flight` for the full contract.

    **A reservation is named by its caller (vault BACKLOG #3180).** ``reservation_id`` is the save's
    ``file_id``, so a release pays back that reservation and nothing else, and is safe after a
    reserve whose outcome is unknown. The heartbeat (BACKLOG #2648) touches that reservation only."""

    async def reserve_upload_quota(
        self,
        uploader_id: str,
        reservation_id: str,
        *,
        size_bytes: int,
        max_files: int,
        max_total_bytes: int,
    ) -> bool: ...

    async def release_upload_quota(self, *, uploader_id: str, reservation_id: str) -> None: ...

    async def touch_upload_quota(self, reservation_id: str) -> None: ...

    async def upload_quota_in_flight(self, uploader_id: str) -> tuple[int, int]: ...


class UploadStore:
    """Filesystem-backed, encrypted-at-rest store for operator-uploaded diagnostic files (ADR 0134).

    Constructed with the store's :class:`~messagefoundry.store.crypto.Cipher` so uploaded bodies ride the
    same DEK/keyring/rotation posture as the message store. ``max_bytes`` bounds a single upload (and thus
    the in-memory whole-file split at browse time).

    ``ledger`` is the message store, used ONLY for the cross-process half of the per-uploader quota
    (ASVS 2.3.4). ``None`` — the genuinely store-less construction path (embedding / tests) — leaves
    the quota enforced by the per-process lock alone, which is what shipped before and is a real
    degradation, not a second control: N engine shards over one ``uploads_dir`` would then each be
    able to overshoot the budget by one file."""

    def __init__(
        self,
        root: str | os.PathLike[str],
        cipher: Cipher,
        *,
        max_bytes: int,
        max_files_per_user: int = 100,
        max_total_bytes_per_user: int = 250 * 1024 * 1024,
        retention_days: int = 30,
        store: UploadQuotaLedger | None = None,
    ) -> None:
        self._root = Path(root)
        self._cipher = cipher
        self._max_bytes = int(max_bytes)
        # Per-uploader quotas + retention (ASVS 5.2.4). Defaults mirror the [store] settings floors so a
        # directly-constructed store (tests/embedding) still enforces the control — it cannot ship
        # disabled. `max(1, ...)` keeps the enforcement path safe even if a caller passes 0/negative.
        self._max_files_per_user = max(1, int(max_files_per_user))
        self._max_total_bytes_per_user = max(1, int(max_total_bytes_per_user))
        self._retention_days = max(1, int(retention_days))
        # ASVS 2.3.4: the quota check and the write that consumes it must be ONE critical section, or
        # concurrent uploads each read a stale count and double-book the budget. Serialising the whole
        # build-and-write (not just the check) is what makes it atomic — releasing between them is the
        # race. The throughput cost is acceptable here and nowhere near the data plane: this is the
        # operator diagnostic-upload surface. Each pass is one sidecar scan plus a write bounded by
        # max_bytes.
        #
        # This lock is an asyncio.Lock, so it is per-event-loop and therefore PER-PROCESS. Engine
        # sharding is the built, shipped, default scaling axis and nothing partitions uploads_dir per
        # shard, so N shards over one directory hold N independent copies of it. `_ledger` is the
        # cross-process half: one atomic row on the ONE unified store every shard already shares.
        self._quota_lock = asyncio.Lock()
        self._ledger = store
        # Ledger calls a cancelled save stopped waiting for (BACKLOG #2263), and save-time sweeps a
        # cancelled upload stopped waiting for (#2261), held until they finish: the loop holds a
        # Task only weakly. See _hold.
        self._stragglers: set[asyncio.Future[Any]] = set()
        # The tasks drain_stragglers cancelled and that have not ended yet. A reserve among them
        # spawns no late release (#3180): the store is about to close.
        self._drain_cancelled: set[asyncio.Future[Any]] = set()
        # Live saves' reservation heartbeats (BACKLOG #2648), held for the same reason. Each ends
        # once its save sets the stop Event. See _start_heartbeat.
        self._heartbeats: set[asyncio.Future[None]] = set()
        # Removals of cancelled saves' landed pairs that later saves still wait for before they
        # scan, until each ends, passes its bound or the shutdown drain names it (vault BACKLOG
        # #3740 item 4).
        self._pending_removals: dict[asyncio.Future[bool], _PendingRemoval] = {}
        # The heartbeat touches among the stragglers. A touch only refreshes its reservation's
        # clock, so the shutdown drain cancels one rather than waiting for it (vault BACKLOG #3740
        # item 14).
        self._touches: set[asyncio.Future[Any]] = set()
        # Body name -> ((mtime_ns, size), decodes as text). Checking a body means reading it whole,
        # and every save's quota scan asks, so a body that has not changed is not read twice.
        self._body_checks: dict[str, tuple[tuple[int, int], bool]] = {}
        # The running UploadRetentionRunner's wake, or None (BACKLOG #3184). See wake_retention.
        self._retention_wake: Callable[[], bool] | None = None
        # The scan's, the prune's and the orphan sweep's lines for what they left for an operator,
        # keyed by what each line is about, so a listing or a save does not repeat one inside
        # _REPORT_INTERVAL_S (BACKLOG #5552). The default retention pass is as far apart as that
        # interval, so a lasting fault can log on every scheduled pass, and a key pushed out past
        # _REPORTED_MAX logs again sooner.
        self._link_logged = _OncePerInterval()

    def wake_retention(self) -> bool:
        """Ask the running :class:`UploadRetentionRunner` over this store to sweep now, and return
        whether one is running (BACKLOG #3184).

        The upload route calls this after a save, in place of sweeping on the request path, so a
        large prune never adds to an upload's latency or meets its deadline. The runner's sweep is
        audited like any other. It returns at once: the sweep runs in the runner's own task, and a
        wake during a sweep starts one more sweep after it, never two at once. ``False`` means no
        runner is running, as in an app built with ``create_app`` alone, and the caller sweeps
        itself (:meth:`prune_on_save`). The cost: the sweep now finishes after the response, so an
        upload sent straight after it can still be billed for expired files not yet removed. That
        errs toward refusing, and clears once the sweep lands."""
        wake = self._retention_wake
        return wake is not None and wake()

    def bind_retention_wake(self, wake: Callable[[], bool]) -> None:
        """Make ``wake`` what :meth:`wake_retention` calls. It returns whether its runner's loop is
        still running, so a loop that ended without a stop sends the caller back to sweeping for
        itself. :meth:`UploadRetentionRunner.start` binds it. One runner per store: a second
        binding replaces the first."""
        self._retention_wake = wake

    def unbind_retention_wake(self, wake: Callable[[], bool]) -> None:
        """Undo :meth:`bind_retention_wake` for ``wake``, and leave any other binding alone."""
        if self._retention_wake == wake:
            self._retention_wake = None

    @property
    def max_bytes(self) -> int:
        return self._max_bytes

    @property
    def max_files_per_user(self) -> int:
        return self._max_files_per_user

    @property
    def max_total_bytes_per_user(self) -> int:
        return self._max_total_bytes_per_user

    @property
    def retention_days(self) -> int:
        return self._retention_days

    def _ensure_root(self) -> Path:
        """Create the uploads dir best-effort (owner-only where the OS honours it) and return its
        canonical path. Directory ACL hardening is operator-owned (docs/PHI.md §10)."""
        self._root.mkdir(mode=0o700, parents=True, exist_ok=True)
        return self._root.resolve()

    def _paths(self, file_id: str) -> tuple[Path, Path]:
        """Resolve the (blob, meta) paths for ``file_id`` with the ADR 0134 path-traversal guard:
        reject any id that is not the exact 32-hex shape, then resolve and assert each path is
        **itself**, directly under the canonical uploads root. Raises :class:`UploadPathError` on any
        mismatch — without touching the filesystem for a bad id.

        **What it refuses (BACKLOG #5552): a path that does not resolve to itself,** such as a
        symbolic link or a junction to another file, wherever that file is. Such a link to ANOTHER
        upload's file inside the root would otherwise let a delete, prune or discard under one id
        act on the other upload. **A hard link is not refused:** it is a second name for the same
        file and resolves to itself. Nor is a symbolic link that loops back to itself, which
        resolves to itself too; it reaches no other file, and its own read fails. A refused pair
        is left to an operator."""
        blob, meta = self._paths_unfollowed(file_id)
        if blob.resolve() != blob or meta.resolve() != meta:
            raise UploadPathError(
                f"upload id {file_id!r} names a link or resolves elsewhere; it is not followed"
            )
        return blob, meta

    def _paths_unfollowed(self, file_id: str) -> tuple[Path, Path]:
        """The (blob, meta) paths of ``file_id`` under the canonical root, the id guard applied and
        the final name not resolved, so the reseal sees a link as a link (BACKLOG #3737). Resolved, a
        link out of the root raised :class:`UploadPathError` here, and that failed every run."""
        if not _FILE_ID_RE.match(file_id):
            raise UploadPathError(f"malformed upload id: {file_id!r}")
        root = self._root.resolve()
        return root / f"{file_id}{_BLOB_SUFFIX}", root / f"{file_id}{_META_SUFFIX}"

    # --- crypto helpers (bytes ride the str cipher via base64, NUL-safe) --------------------------

    def _encrypt_blob(self, data: bytes, file_id: str) -> str:
        b64 = base64.b64encode(data).decode("ascii")
        return self._cipher.encrypt(b64, aad=cell_aad("uploaded_file", "body", file_id))

    @property
    def _passes_unmarked(self) -> bool:
        """True when this surface reads an unmarked file back as plaintext (BACKLOG #1169).

        **Owner ruling 2026-09-23: on a keyed store, an unmarked upload is REFUSED until an operator
        runs ``rotate-key``,** which reseals it where it can (BACKLOG #2322). So the refusal applies
        exactly where that command can reseal, which is an :class:`AesGcmCipher`. There the cipher's own policy decides, and
        ``[store].allow_unmarked_ciphertext`` restores the passthrough for this surface too.

        Every other cipher keeps the passthrough. The identity cipher has no key, so nothing is
        refused anyway. ``vault_transit`` is a named residual, and ``docs/PHI.md`` §3 is where it and
        its reason are stated."""
        return not isinstance(self._cipher, AesGcmCipher)

    @property
    def _refuses_plaintext(self) -> bool:
        """True when this surface refuses every plaintext sidecar, which is the only place an upload
        ``rotate-key`` cannot seal exists (:class:`_UnsealableUpload`). Under
        ``[store].allow_unmarked_ciphertext`` the listing scan reads those sidecars itself."""
        cipher = self._cipher
        return isinstance(cipher, AesGcmCipher) and not cipher.allow_unmarked

    def _decrypt_blob(self, stored: str, file_id: str) -> bytes:
        b64 = self._cipher.decrypt(
            stored,
            aad=cell_aad("uploaded_file", "body", file_id),
            allow_unmarked=self._passes_unmarked,
        )
        _refuse_still_sealed(b64, "body")
        # Strict, as the writer emits it, so a damaged body is refused rather than served with
        # its stray characters dropped. Encoded first, so a non-ASCII character raises a
        # UnicodeError and the only other refusal is binascii.Error, the two read_bytes catches.
        return base64.b64decode(b64.encode("ascii"), validate=True)

    def _encrypt_meta(self, meta: UploadedFileMeta) -> str:
        return self._cipher.encrypt(
            json.dumps(asdict(meta)), aad=cell_aad("uploaded_file", "meta", meta.file_id)
        )

    def _decrypt_meta(self, stored: str, file_id: str) -> UploadedFileMeta:
        # Unpadded first, so a sealed sidecar that gained a byte-order mark or whitespace reads as
        # sealed rather than as a damaged plaintext one (BACKLOG #5387 added item 1).
        raw = self._cipher.decrypt(
            _unpadded(stored),
            aad=cell_aad("uploaded_file", "meta", file_id),
            allow_unmarked=self._passes_unmarked,
        )
        _refuse_still_sealed(raw, "sidecar")
        return _meta_from_json(raw, file_id)

    def _iter_sidecars(self) -> Iterator[tuple[str, Path]]:
        """Every ``(file_id, sidecar path)`` pair in the uploads root, as :meth:`_walk_sidecars`
        yields them, which holds the definition of "a file of ours" for those two. The listing scan
        consumes this, and the re-seal pass consumes :meth:`_walk_sidecars` itself, so the id shape
        and the sidecar suffix cannot drift apart between them. The orphan sweep derives a sidecar
        name from a body name itself, from the same ``_FILE_ID_RE`` and ``_META_SUFFIX``. Anything else in the directory (an
        operator's stray file, a temp file, an id that fails the strict 32-hex shape) is not ours
        and is skipped without being opened. A root that is not a directory yields nothing here,
        since the first save creates it."""
        if self._root.is_dir():
            yield from self._walk_sidecars()

    def _walk_sidecars(self) -> Iterator[tuple[str, Path]]:
        """:meth:`_iter_sidecars` with no check on the root, so a root it cannot list raises
        ``OSError``. The re-seal pass walks this, because there no root is not zero uploads
        (BACKLOG #4940)."""
        for entry in self._root.iterdir():
            if not entry.name.endswith(_META_SUFFIX):
                continue
            fid = entry.name[: -len(_META_SUFFIX)]
            if _FILE_ID_RE.match(fid):
                yield fid, entry

    def _scan_metas_sync(
        self,
        held: list[_UnsealableUpload] | None = None,
        *,
        outage_raises: bool = False,
        damaged: list[_UnsealableUpload] | None = None,
    ) -> list[UploadedFileMeta]:
        """Walk the uploads root and decrypt every well-formed ``.meta`` sidecar (UNSORTED). A
        bad/foreign/undecryptable sidecar is skipped **with its cause named** (never a body in the
        log), so a rotated-away key can neither sink the listing nor silently drop a quota/retention
        pass. Pure filesystem read — the caller runs it off the event loop.

        **An outage is the exception (BACKLOG #3734).** A sidecar the key service gave no verdict
        on is logged with its upload id on a line of its own. With ``outage_raises`` it then raises
        :class:`UploadUnavailableError`, ending the scan, so a quota count is never taken with the
        sidecar left out; without it, it is skipped like the rest.

        **Each failure class is caught on its own and logged distinctly (BACKLOG #1169, CLAUDE.md
        §6).** One blanket ``except Exception`` used to fold all three into a single
        "skipping unreadable sidecar" line, which made three unrelated conditions indistinguishable
        in the log: a key that was rotated away, a sidecar whose bytes are damaged, and the cipher
        REFUSING a value. The third is the one that matters — it is the class a strict-ciphertext
        read would raise in, on exactly the surface where planting a file is easiest (a pair of
        plain files in a directory, no database write needed). A refusal folded into the same line
        as a routine post-rotation skip is a refusal nobody can see, so the strict read cannot
        honestly be built on top of this handler until the classes are separated. It now is built:
        on a keyed AES-GCM store an unmarked sidecar is refused (:attr:`_passes_unmarked`), lands in
        the cipher branch below, and is left out of the listing, the quota and the retention prune
        until ``rotate-key`` reseals it.

        **The quota and the prune deliberately do NOT read a refused sidecar either.** A plaintext
        sidecar is not bound to its path, so its JSON can name ANOTHER upload's ``file_id`` for the
        prune to delete, carry a negative ``size`` that lifts an uploader's byte quota, write
        attacker-chosen names into the ``upload.prune`` audit, or hold a number that overflows the
        coercion and fails every save. Trusting it to keep retention working would trade a bounded
        residual for all of that. The residual is named in ``docs/PHI.md`` §3: a refused upload is
        outside retention and the quota until ``rotate-key`` seals it, and ``serve`` logs the count
        at startup so the operator knows to run it. One kind ``rotate-key`` can never seal is
        brought back through ``held`` instead, without trusting its sidecar.

        **``damaged`` is for the prune only (BACKLOG #5387, #5388).** When it is a list, each
        sidecar that is not UTF-8, or that decrypted but is not this upload's metadata
        (:func:`_meta_from_json`), and that ``held`` did not take, is appended to it as
        :meth:`_aged_on_disk_sync` records it, which says how the prune ages it. A sidecar the cipher declined is never
        appended, because a key rotated away must not silently destroy data. At least that kind is
        still left out of the prune.

        **``held`` is for the quota and the prune only (BACKLOG #2322, #3184).** When it is a list
        and the cipher refuses plaintext, each refused sidecar that is an upload ``rotate-key``
        cannot seal is appended to it, from this same directory walk, so a quota check walks the
        directory once rather than twice. Nothing that lists or serves an upload passes it, so the
        strict read is not loosened. Only a sidecar the cipher refused, or one that is not UTF-8
        as a whole or is larger than :data:`_SIDECAR_LIMIT`, is classed; the last two cover a
        plaintext sidecar that is not UTF-8 only past the part :meth:`_unsealable_sync` reads, or
        that a plant grew past the cap (BACKLOG #5387 added item 1). A sidecar the cipher decrypted
        is sealed, and :meth:`_unsealable_sync` would decline it anyway. The class is keyed by the PATH id, never
        by the id in a sidecar's JSON.

        The cipher's own message is safe to log — every ``CipherError`` carries only key ids,
        marker versions and algorithm names, never a decrypted value. Each of those is cut from the
        stored text, so the cipher bounds what it echoes of one (BACKLOG #5553). The malformed-shape branch
        names only the field and the defect (:class:`_MalformedSidecarError`), or for any other
        ``ValueError`` only its TYPE, because such an error can echo a field's value back into the
        message.

        **A sidecar whose tag fails under a key the cipher holds is reported (BACKLOG #5553),**
        through the cipher's tag-failure hook, once per upload per hour, while a tag-failure hook
        is armed (:meth:`_report_tag_failure`). That is a value sealed under this store's key for
        some other place, such as another upload's sidecar moved under this id. A value under a key
        that is not configured is a key fault, not that, and is only logged.

        **A sidecar that is a link, or is not a regular file, is not read (BACKLOG #5552).** It is
        skipped, and its log line is rate-limited per upload: a followed link read a file outside
        the root, or another upload's sidecar, and a FIFO would block the scan, and the
        ``_quota_lock`` a save holds over it, for good. The check is the open's own ``lstat``
        (:class:`_RefusedBeforeOpen`); one swapped in between it and the open is refused at the
        open (:func:`_read_plain_text`) and logged as unreadable, and no read takes more than
        :data:`_SIDECAR_LIMIT` bytes, so a planted oversized sidecar cannot exhaust memory under
        that lock either; it is refused as malformed (BACKLOG #5387 added item 1)."""
        out: list[UploadedFileMeta] = []
        sink = held if self._refuses_plaintext else None
        bodies: set[str] = set()
        for fid, entry in self._iter_sidecars():
            if sink is not None:
                bodies.add(f"{fid}{_BLOB_SUFFIX}")
            classify = False
            broken = False
            stored = ""
            try:
                stored = _read_sidecar(entry)
                out.append(self._decrypt_meta(stored, fid))
            except _RefusedBeforeOpen as exc:
                # The open's own lstat refused it, so the scan makes none of its own under
                # _quota_lock (BACKLOG #5552 item 8).
                if self._link_logged.first(f"scan {fid} {exc.reason}"):
                    _log.warning(
                        "uploaded-file sidecar %s: %s, so it was not read", fid, exc.reason
                    )
                continue
            except CipherError as exc:
                if isinstance(exc, CipherUnavailableError):
                    # Its own line, so an outage never reads as the refusal logged below. Logged
                    # before the raise too, so the sidecar that stopped a count is named.
                    _log.warning("uploaded-file sidecar %s: key service unavailable: %s", fid, exc)
                    if outage_raises:
                        # A count with a sidecar it could not read is not a count (BACKLOG #3734).
                        raise UploadUnavailableError(str(exc)) from exc
                    continue
                # The cipher declined the value: a wrong/rotated-away key, a blob relocated into
                # another cell, or the refusal of an unmarked (legacy, planted or downgraded)
                # sidecar. Named on its own so these can be told apart from a damaged file.
                _log.warning("uploaded-file sidecar %s: cipher declined it: %s", fid, exc)
                # Unpadded, as the decrypt saw it, so a padded marker still reaches the check.
                self._report_tag_failure(fid, _unpadded(stored), exc)
                classify = True
            except (OSError, UnicodeDecodeError) as exc:
                # The bytes never reached the cipher — unreadable file, or not valid UTF-8.
                _log.warning(
                    "uploaded-file sidecar %s: unreadable on disk: %s", fid, codec_safe_str(exc)
                )
                # A decode error is classed too: a plaintext sidecar that is not UTF-8 only past
                # the part the class check reads is still one rotate-key can never seal. An
                # OSError is not, so a stalled read is not paid twice under _quota_lock.
                classify = broken = isinstance(exc, UnicodeDecodeError)
            except (ValueError, TypeError, KeyError) as exc:
                # Decrypted, but not metadata this store wrote, or not this upload's (BACKLOG
                # #5387). Left out of the listing and the quota; the prune ages it on disk only.
                # Never a value logged. A _MalformedSidecarError names only the defect; any other
                # error, which could echo a value, only its type.
                defect = (
                    codec_safe_str(exc)
                    if isinstance(exc, _MalformedSidecarError)
                    else type(exc).__name__
                )
                _log.warning("uploaded-file sidecar %s: malformed metadata: %s", fid, defect)
                # Only the store's own shape refusal is damage the prune may age. Any other error
                # here is not known to be one, so it is skipped, never pruned.
                broken = isinstance(exc, _MalformedSidecarError)
                # An oversized one is classed as a decode error is: the class check reads only a
                # bounded part of it.
                classify = isinstance(exc, _OversizedFileError)
            lost = None
            if classify and sink is not None:
                lost = self._unsealable_sync(fid, entry)
                if lost is not None:
                    sink.append(lost)
            if lost is None and broken and damaged is not None:
                record = self._aged_on_disk_sync(fid)
                if record is not None:
                    damaged.append(record)
        if sink is not None:
            # Forget the checks of uploads that are gone, so the cache cannot outgrow the directory.
            # A copy, because a scan on another worker thread may be writing to it.
            for name in self._body_checks.copy().keys() - bodies:
                self._body_checks.pop(name, None)
        return out

    def _report_tag_failure(
        self, fid: str, stored: str, exc: CipherError, part: _TaggedPart = "sidecar"
    ) -> None:
        """Raise the cipher's tag-failure alert for upload ``fid``'s ``part``, its sidecar or its
        body, when ``exc`` is that part's AEAD tag failing under a key the cipher holds, once per
        part per upload per :data:`_REPORT_INTERVAL_S` and only while its hook is armed (BACKLOG
        #5553; the body by :meth:`read_bytes`, BACKLOG #5552 item 6 (a)). The tests are ``store/cell_tag.py``'s
        ``_tag_failure_kind``, inlined because that module imports beyond this leaf's set: a verdict was given, a cipher that names
        its keys holds the one the marker names, and one that cannot (Vault Transit) declares that
        its refusal is the value's own tag. The reason names a prefix of the upload id, as
        ``cell_tag`` names a row: the id is random and carries no PHI. The WARNING the scan, or
        :meth:`read_bytes` for a body, logs beside it names the whole id."""
        cipher = self._cipher
        report = getattr(cipher, "report_tag_failure", None)
        # A report with no hook armed goes nowhere, so it must not use up the upload's slot: a hook
        # armed later in the interval would then never hear of it. A cipher with no such attribute,
        # such as one forwarding to an inner cipher, is taken as armed, as before. Checked first, as
        # the cheapest test.
        if not callable(report) or getattr(cipher, "_tag_failure_hook", True) is None:
            return
        if not isinstance(exc, UnauthenticatedCipherError) or gave_no_verdict(exc):
            return
        head = stored[:_TAG_MARKER_HEAD_CHARS]
        if not cipher.is_encrypted(head):
            return
        holds = getattr(cipher, "holds_key_for", None)
        held = holds(head) if callable(holds) else getattr(cipher, "names_no_keys", False) is True
        if not (held and _tag_reported.first(f"{part} {fid}")):
            return
        # The body under its own table name, so its alert has its own notifier subject and a
        # sidecar page inside the cooldown cannot hold it back (BACKLOG #5552 item 6 (a)).
        report(
            "uploaded_file" if part == "sidecar" else "uploaded_file_body",
            f"an uploaded-file {part} failed its integrity tag (upload {fid[:_TAG_REF_LEN]})",
        )

    def _unsealable_sync(self, fid: str, sidecar: Path) -> _UnsealableUpload | None:
        """``fid`` as an upload ``rotate-key`` cannot seal, or ``None`` when it is not one.

        It is one when its sidecar is plaintext and its body is missing or is not text. The body
        test is :meth:`_lost_body_size`, which the reseal also calls. Any other failure returns
        ``None``: a body unreadable for another cause, such as a permission, is one a re-run of
        ``rotate-key`` can seal once the cause is fixed, so it waits like any refused upload."""
        try:
            handle, info = _open_plain(sidecar)
            with io.TextIOWrapper(handle, encoding="utf-8") as text_handle:
                text = text_handle.read(_UNSEALABLE_OWNER_READ_LIMIT)
                whole = not text_handle.read(1)
            modified = info.st_mtime
        except (OSError, UnicodeDecodeError):
            return None  # the listing scan names this one
        # A byte-order mark or whitespace around a sealed sidecar does not make it plaintext
        # (BACKLOG #5387 added item 1), and one that is only those is blank. A part read that is
        # only those is not: what follows it is not one the store wrote either.
        text = _unpadded(text) if whole else _lstrip_pad(text)
        if (whole and not text) or text.startswith(MARKER_PREFIX):
            return None  # blank, or sealed: not plaintext
        try:
            # The prune unlinks through the same guard, so anything it refuses is never billed.
            blob, _ = self._paths(fid)
        except UploadPathError:
            return None
        size = self._lost_body_size(blob)
        if size is None:
            return None
        owner = ""
        if whole:
            # Only a string is taken, so nothing here can fail to coerce or carry a negative size.
            with contextlib.suppress(ValueError, RecursionError):
                d = json.loads(text)
                if isinstance(d, dict) and isinstance(d.get("uploader_id"), str):
                    owner = d["uploader_id"]
        return _UnsealableUpload(file_id=fid, uploader_id=owner, size=size, modified=modified)

    def _aged_on_disk_sync(self, fid: str) -> _UnsealableUpload | None:
        """Upload ``fid`` as the prune ages it by its pair on disk (BACKLOG #5387, #5388): one whose
        sidecar is refused as damaged, or a sound one whose ``uploaded_at`` the prune cannot trust
        (:meth:`prune_expired`). ``None`` when its pair cannot be checked; the next pass tries again.

        Nothing is taken from the sidecar. ``modified`` is the later of the sidecar's and the
        body's modification times, read without following a link, so a pair is due only once both
        halves are old on disk. Unlike the never-sealable kind, one dated ahead is not pruned: the
        prune compares it with the cutoff alone, so a pair written before a clock was stepped back
        waits for wall time. ``size`` is the body's size on disk, ``0`` when it is gone. The owner
        is blank, so the record bills nobody and the audit row names no owner. The record is the
        never-sealable kind's only in shape: it reaches the prune alone."""
        try:
            blob_path, sidecar = self._paths_unfollowed(fid)
            modified = sidecar.lstat().st_mtime
            try:
                body = blob_path.lstat()
            except FileNotFoundError as exc:
                # Only a body that is absent is size 0. One whose share cannot be reached raises
                # to the handler below, so the pair waits for the next pass (BACKLOG #5388).
                if not is_absent(exc):
                    raise
                size = 0
            else:
                modified = max(modified, body.st_mtime)
                size = body.st_size
        except OSError as exc:
            _log.warning("uploaded-file %s: could not age the pair on disk: %s", fid, exc)
            return None
        return _UnsealableUpload(file_id=fid, uploader_id="", size=size, modified=modified)

    @property
    def _stored_limit(self) -> int:
        """The largest file a body can be on disk: base64 of ``max_bytes``, plus a generous
        allowance for the cipher's marker and tag. A sidecar is held to ``_SIDECAR_LIMIT``
        instead."""
        return 2 * self._max_bytes + 4096

    def _body_unread(self, blob: Path, exc: OSError) -> None:
        """Log a body the check could not read, once per interval per body, since the quota scan
        meets the same one on every save and listing."""
        if self._link_logged.first(f"body {blob.name}"):
            _log.warning("uploaded file %s: could not check the body: %s", blob.name, exc)

    def _lost_body_size(self, blob: Path) -> int | None:
        """The bytes on disk of a body no key can read, or ``None`` when the body is readable text.

        ``0`` when it is missing, and its size when it does not decode as UTF-8. ``None`` also when
        it cannot be read for another cause. A decoded body is not checked again until its mtime or
        size changes (``_body_checks``).

        Only a regular file no larger than a body the engine could have written is read, because the
        quota scan runs this under ``_quota_lock``. A FIFO, a device or an oversized plant would
        otherwise stall every later upload. Any of those returns ``None`` and waits for an operator.
        The body is opened by :func:`_open_plain` (BACKLOG #5387 added item 1), so a link, a
        dangling one included, is never followed and returns ``None`` too, and a FIFO swapped in
        after the check is refused rather than waited on. A body whose ``lstat`` matches a cached
        check is not opened at all."""
        try:
            before = blob.lstat()
        except OSError as exc:
            # Only an absent body is a lost one. A share that cannot be reached raises a
            # FileNotFoundError too on Windows, and that body is not known to be lost (BACKLOG
            # #5388), so it waits as an unread one does.
            if is_absent(exc):
                return 0
            self._body_unread(blob, exc)
            return None
        if _names_a_link(before) or not _is_regular(before):
            _log.warning("uploaded file %s: not a regular file; it was not read", blob.name)
            return None
        if before.st_size > self._stored_limit:
            _log.warning("uploaded file %s: larger than an upload can be", blob.name)
            return None
        cached = self._body_checks.get(blob.name)
        if cached is not None and cached[0] == (before.st_mtime_ns, before.st_size):
            return None if cached[1] else before.st_size
        try:
            handle, stat = _open_plain(blob)
        except FileNotFoundError:
            return 0
        except _NotPlainError:
            _log.warning("uploaded file %s: not a regular file; it was not read", blob.name)
            return None
        except OSError as exc:
            self._body_unread(blob, exc)
            return None
        with handle:
            if stat.st_size > self._stored_limit:
                _log.warning("uploaded file %s: larger than an upload can be", blob.name)
                return None
            key = (stat.st_mtime_ns, stat.st_size)
            cached = self._body_checks.get(blob.name)
            if cached is not None and cached[0] == key:
                decodes = cached[1]
            else:
                try:
                    with io.TextIOWrapper(handle, encoding="utf-8") as text:
                        while text.read(_BODY_CHECK_CHUNK):
                            pass
                except UnicodeDecodeError:
                    decodes = False
                except OSError as exc:
                    _log.warning("uploaded file %s: could not check the body: %s", blob.name, exc)
                    return None
                else:
                    decodes = True
                self._body_checks[blob.name] = (key, decodes)
        return None if decodes else stat.st_size

    # --- public API (all disk/crypto/split work off the event loop) --------------------------------

    async def save(
        self,
        *,
        data: bytes,
        filename: str,
        uploader: str,
        uploader_id: str,
    ) -> UploadedFileMeta:
        """Persist an uploaded file (encrypted at rest) and return its metadata. Its format tag is
        derived from its extension; a caller cannot set one (BACKLOG #5551).

        ``uploader_id`` is the owning account's immutable ``Identity.user_id``; ``uploader`` is its
        username, kept for display and the audit rows only. Both are required — a file written with
        no ``uploader_id`` would be readable by nobody but a ``files:access_any`` holder while still
        billing to nobody's quota, so an empty one is a programming error and is refused here.

        Raises :class:`UploadTooLargeError` if it exceeds ``max_bytes``, :class:`UploadNotTextError`
        on a body that is not plain text (ASVS 14.2.8), :class:`UploadContentError` on a disallowed
        extension / content mismatch (ASVS 5.2.2), :class:`UploadQuotaError` when
        the uploader's file-count or aggregate-byte quota would be exceeded (ASVS 5.2.4), or
        :class:`UploadUnavailableError` when the cipher's key service gave no verdict, before anything
        is written (BACKLOG #3734), or :class:`UploadFieldError` when the filename, ``uploader`` or
        ``uploader_id`` is one the sidecar reader would refuse, before anything is written (BACKLOG
        #5387).

        **A cancellation that reaches ``save`` after the pair landed removes it (BACKLOG #2262).**
        The caller writes ``upload.create`` only once this returns. A kept pair would be stored with
        no creation row, while the client was told the upload failed and may well retry it. The
        cancellation can propagate before the removal ends; the next save in this process waits
        for it before it scans. A removal the filesystem refuses is logged at ERROR, and so is one
        still running after ``_CANCELLED_REMOVAL_WAIT_SECONDS``, which may not finish before the
        process stops (:meth:`_remove_cancelled_pair`). This covers ``save`` only. The
        API writes the row after this returns as an operation the request deadline cannot cancel,
        and a row that fails there removes the pair through :meth:`discard` (vault BACKLOG
        #3178)."""
        if not uploader_id:
            raise ValueError("uploader_id is required (an upload with no owner id is unreachable)")
        # Only the cheap size check runs on the loop; the sha256, the whole-file split, the cipher, and
        # the disk writes are ALL bounded by max_bytes (25 MiB default), so they run OFF the event loop
        # (a large upload must never stall the shared engine loop — ADR 0134 / CLAUDE.md §6).
        if len(data) > self._max_bytes:
            raise UploadTooLargeError(
                f"upload is {len(data)} bytes; the limit is {self._max_bytes}"
            )
        display = sanitize_filename(filename)
        # The reader's own rule, applied before anything is written, so no write is one it refuses
        # (BACKLOG #5387). content_type and sha256 are the store's own, always within it.
        for key, value in (
            ("filename", display),
            ("uploader", uploader),
            ("uploader_id", uploader_id),
        ):
            defect = _sidecar_text_defect(key, value)
            if defect is not None:
                raise UploadFieldError(display, f"was not stored: {defect}")
        # Text-only check, extension allowlist + content-vs-extension sniff at the chokepoint (ASVS
        # 14.2.8, 5.2.2). Both upload surfaces (POST /uploads and POST /ui/uploaded-logs/upload) reach
        # save(), so a non-text body, a disallowed extension or a content/extension mismatch is
        # refused here before any PHI is written. It reads the whole body (BACKLOG #5551), so it runs
        # off the loop like the rest.
        await asyncio.to_thread(validate_upload_content, display, data)
        # Always derived from the extension the check above judged, never a caller's label (#5551).
        ctype = content_type_for(display)
        file_id = secrets.token_hex(16)
        # Set by the write thread once the sidecar lands; read only after that thread has finished.
        landed = False

        def _build_and_write(in_flight: tuple[int, int]) -> UploadedFileMeta:
            nonlocal landed
            # Per-uploader quota (ASVS 5.2.4): scan the uploader's existing sidecars and refuse BEFORE
            # writing when this file would exceed their file-count or aggregate-byte cap. Runs in the same
            # off-loop thread as the write, and the caller holds _quota_lock across BOTH, so no second
            # upload in this process can read this count before the write consumes it (ASVS 2.3.4).
            # The scan is uncached, so shards sharing a dir enforce one budget rather than one each.
            # A sibling shard's upload that is reserved but not landed is counted by `in_flight`
            # instead, read after reserving and before this scan (see UploadQuotaError for why).
            disk = self._observed_sync(uploader_id)
            refusal = self._on_disk_refusal(uploader=uploader, observed=disk, size=len(data))
            if refusal is not None:
                raise refusal
            # The ledger total includes this upload's own reservation, which `size` already counts,
            # so only the siblings' share is added to the disk figures.
            with_siblings = disk._replace(
                files=disk.files + max(0, in_flight[0] - 1),
                size=disk.size + max(0, in_flight[1] - len(data)),
            )
            if (
                self._on_disk_refusal(uploader=uploader, observed=with_siblings, size=len(data))
                is not None
            ):
                raise self._shard_refusal(uploader=uploader, observed=disk)
            stamp = time.time()
            # The reader's own rule for the stamp, so a clock before _MIN_SIDECAR_STAMP writes no
            # sidecar the reader refuses (BACKLOG #5387). Refused, not clamped: a stamp clamped to
            # the floor would be read as old and pruned before its retention window ends.
            if not _stamp_in_range(stamp):
                raise UploadFieldError(
                    display, "was not stored: the engine clock is not a time in range"
                )
            meta = UploadedFileMeta(
                file_id=file_id,
                filename=display,
                uploader=uploader,
                uploader_id=uploader_id,
                content_type=ctype,
                size=len(data),
                sha256=hashlib.sha256(data).hexdigest(),
                uploaded_at=stamp,
                # Message count is derived once at save (bounded by max_bytes) so listing never re-splits.
                message_count=len(split_batch(_decode_text(data))),
            )
            root = self._ensure_root()
            blob_path, meta_path = self._paths(file_id)
            try:
                blob_ct = self._encrypt_blob(data, file_id)
                meta_ct = self._encrypt_meta(meta)
            except CipherUnavailableError as exc:
                raise UploadUnavailableError(str(exc)) from exc
            # The reader's own cap, so no write is one the reader refuses (BACKLOG #5387 added item
            # 1). The bounded fields keep a sealed sidecar far below it, so only a cipher that
            # grows a value past it would meet this.
            # An unsealed one is held to the plaintext bound every reader applies, so a store with
            # no key never writes a sidecar it then refuses as damaged.
            if len(meta_ct.encode("utf-8")) > _SIDECAR_LIMIT or _too_long_to_seal(meta_ct):
                raise UploadFieldError(
                    display, "was not stored: its metadata is larger than the store can read back"
                )
            # Atomic-ish write: tmp + os.replace so a reader never sees a half-written ciphertext.
            #
            # The two writes are ordered body-then-sidecar because the sidecar is the listing key, so
            # the pair is invisible until it is whole. The cost is a window where the body exists
            # alone, and a failure inside it used to leave that body behind permanently: no sweep
            # walks anything but `_iter_sidecars`, which yields `.meta` names only (BACKLOG #1678).
            # Remove it here rather than leave it for the orphan sweep, which cannot run for an hour.
            # `BaseException` so a cancellation cleans up too; the original failure is re-raised.
            with _inflight(blob_path.name):
                _atomic_write_text(root, blob_path, blob_ct)
                try:
                    _atomic_write_text(root, meta_path, meta_ct)
                except BaseException:
                    with contextlib.suppress(OSError):
                        blob_path.unlink(missing_ok=True)
                    raise
            landed = True
            return meta

        # One critical section per process: quota check + write. See _quota_lock in __init__.
        # Inside it, one cross-PROCESS reservation around the same window (ASVS 2.3.4), named by
        # this save's file_id (vault BACKLOG #3180). The order is load-bearing: reserve, THEN read
        # the ledger's in-flight total, THEN scan the disk inside _build_and_write.
        # UploadQuotaError carries the argument for why that order counts every sibling upload. The
        # reservation is released only once the file is on disk (or the write fails), which is what
        # the argument needs.
        #
        # The cancel handler sits outside the release, so it also catches a cancellation that lands
        # in the release await, after the write returned, and INSIDE the lock. It starts the
        # removal there, and the next save in this process waits for that removal before it scans,
        # so it does not scan the disk while a pair about to be removed is still on it (vault
        # BACKLOG #3180; that scan answered a spurious 409 at the quota edge), for a bounded time:
        # see _remove_cancelled_pair. A sibling engine shard's scan between
        # the release and the removal over-counts the pair, which can refuse it but never admits one
        # too many. The reserve and the release each get a bounded wait to finish before a
        # cancellation propagates, so a cancelled save normally pays its slot back (BACKLOG #2263).
        # The cases that still leak are listed once, in UploadQuotaError.
        async with self._quota_lock:
            try:
                await self._wait_for_pending_removals()
                reserved = await self._reserve_across_shards(
                    uploader_id=uploader_id, uploader=uploader, size=len(data), reservation=file_id
                )
                stop_heartbeat = asyncio.Event()
                try:
                    if reserved:
                        self._start_heartbeat(file_id, uploader_id, stop_heartbeat)
                    in_flight = (
                        await self._ledger.upload_quota_in_flight(uploader_id)
                        if self._ledger is not None
                        else (0, 0)
                    )
                    return await _to_thread_to_completion(_build_and_write, in_flight)
                finally:
                    stop_heartbeat.set()
                    if reserved:
                        await self._release_across_shards(
                            reservation=file_id, uploader_id=uploader_id
                        )
            except asyncio.CancelledError:
                if landed:
                    # Not discard(): this already holds _quota_lock. Nothing cancels the removal
                    # once started, and _remove_cancelled_pair logs how it ends. A failure to start
                    # it must not replace the cancellation, so it is logged and the cancel raised.
                    try:
                        await self._remove_cancelled_pair(file_id)
                    except RuntimeError:  # at least submit() after interpreter shutdown
                        _log.error(
                            "upload %s was cancelled after its file landed and has no "
                            "upload.create audit row; its removal could not be started, so the "
                            "file is still stored",
                            file_id,
                            exc_info=True,
                        )
                raise

    async def discard(self, file_id: str) -> bool:
        """Remove a stored pair whose ``upload.create`` row could not be written (vault BACKLOG
        #3178), the way a save cancelled after it landed is removed. It holds ``_quota_lock`` while
        it removes, as that save does, so no other save in this process scans the disk partway
        through the removal. The lock is free while the row is being written, so a save in that
        window still counts the pair. A refused removal is logged, never raised, and so is any other
        failure of the removal: only a cancellation of the caller itself propagates.

        It returns whether this removal took the pair away, so the caller writes an
        ``upload.delete`` row only for a removal that happened (vault BACKLOG #3740 item 2).
        ``False`` covers a refused or failed removal, a pair something else had already removed,
        and a removal whose outcome was not read.

        **The removal outlives a cancellation, the wait for the lock included.** It runs as its own
        task, held like the other stragglers. A cancelled caller waits up to
        ``_LEDGER_CANCEL_WAIT_SECONDS`` for it, then propagates while it goes on. If the removal is
        itself cancelled before it finishes, such as by the shutdown drain, an ERROR names the
        ``file_id``, so a stored file with no creation row is never left without a record. The
        wait is :meth:`_run_to_completion`'s (vault BACKLOG #3740 item 12), which also logs a
        removal still running at the bound."""
        try:
            return await self._run_to_completion(
                self._discard_under_lock(file_id),
                what=f"the removal of upload {file_id}",
                on_late=functools.partial(_log_discard_unfinished, file_id=file_id),
                held=True,
            )
        except asyncio.CancelledError:
            task = asyncio.current_task()
            if task is not None and task.cancelling():
                raise
            # The removal was cancelled, not this caller; _log_discard_unfinished named it.
        except Exception:  # noqa: BLE001, S110 — _log_discard_unfinished logged it by file_id
            pass
        return False

    async def _discard_under_lock(self, file_id: str) -> bool:
        async with self._quota_lock:
            # _to_thread_to_completion's body, kept here so a cancel still reads the thread's answer.
            loop = asyncio.get_running_loop()
            ctx = contextvars.copy_context()
            removal = loop.run_in_executor(None, ctx.run, self._discard_cancelled_sync, file_id)
            try:
                return await _wait_to_completion(removal)
            except asyncio.CancelledError:
                # With no bound this raises only once the thread has finished the removal, so it
                # is done; ending normally keeps _log_discard_unfinished from saying it is not, and
                # the answer still says whether the pair is gone (vault BACKLOG #3740 item 2).
                return removal.result()

    def _discard_cancelled_sync(self, file_id: str) -> bool:
        """Remove a pair whose save was cancelled after it landed (BACKLOG #2262; see :meth:`save`).

        Body first, then the sidecar, as :meth:`delete` and :meth:`prune_expired` do. The sidecar is
        the listing key, so it stays until the body is gone, and the orphan sweep never sees a body
        with no sidecar. A refused body unlink keeps the whole pair, listed and billed. A refused
        sidecar unlink leaves a listed sidecar with no body, which the retention prune clears. The
        log names the ``file_id`` only, because the filename can carry PHI. Returns whether this
        call removed the sidecar, the listing key, after the body: ``False`` when the sidecar was
        already gone. That keeps a second removal row off a pair an operator's delete had already
        finished, though not off one whose delete runs alongside this, since a delete does not
        take ``_quota_lock``."""
        blob_path, meta_path = self._paths(file_id)
        try:
            # Under the pair lock, so a rotate-key re-seal cannot put either back (BACKLOG #3181).
            with _pair_lock(meta_path):
                # An absent part is already gone; a share that cannot be reached raises
                # _UnreachableError to the handler below, so it is logged as not removed rather
                # than read as gone (BACKLOG #5388).
                _unlink_retrying(blob_path)
                if not _unlink_retrying(meta_path):
                    return False
        except OSError as exc:
            _log.error(
                "upload %s was cancelled after its file landed, or its upload.create row failed, "
                "and it was not fully removed; what remains may have no upload.create audit "
                "row: %s",
                file_id,
                exc,
            )
            return False
        return True

    async def _reserve_across_shards(
        self, *, uploader_id: str, uploader: str, size: int, reservation: str
    ) -> bool:
        """Take this upload's engine-shard reservation, named ``reservation``; return whether one is
        held.

        ``False`` means there is no ledger bound (the store-less construction path) — not that the
        reservation was refused. A refusal raises :class:`UploadQuotaError`, the same TYPE the
        in-process check raises, so the API's 409 + ``upload.reject_quota`` audit is unchanged; the
        message differs on purpose, so an operator can tell the two causes apart. A ledger error is
        NOT swallowed: the store being unreachable fails the upload closed. It may have committed
        before it raised, so the reservation is released by its id, and that release is awaited
        before the error propagates, for at most ``_LEDGER_CANCEL_WAIT_SECONDS`` (vault BACKLOG
        #3180).

        **This is not the quota decision (BACKLOG #1941).** ``save`` makes that after reserving, from
        a read of the ledger plus a fresh disk scan; :class:`UploadQuotaError` says why the order
        matters. The headroom handed to the ledger here is the cap minus a sidecar scan taken BEFORE
        the reserve, so it can be stale, and it serves only as a first filter. It lets the second of
        two same-moment uploads be refused at the ledger, rather than both reserving and each then
        refusing the other.

        That makes two sidecar scans per save, this one and the one in ``_build_and_write``, and the
        ordering argument needs both: this one is before the reserve and that one after the ledger
        read. Each is ONE walk of the directory (BACKLOG #3184) that reads and decrypts EVERY sidecar,
        for every uploader, then filters, and classes each refused one for an upload ``rotate-key``
        cannot seal (BACKLOG #2322). Both run under the per-process ``_quota_lock``. They run off the
        event loop, on the operator diagnostic surface rather than the data plane.

        An uploader already over budget on disk is refused here, with the on-disk wording, before the
        ledger is consulted. Otherwise a zero-headroom ledger would refuse first, and its message would
        blame uploads on another shard that do not exist."""
        if self._ledger is None:
            return False
        observed = await asyncio.to_thread(self._observed_sync, uploader_id)
        refusal = self._on_disk_refusal(uploader=uploader, observed=observed, size=size)
        if refusal is not None:
            raise refusal
        # A cancellation can arrive after the store committed the reserve but before the call
        # returned, so `save` never learns a slot is held and its release never runs (BACKLOG #2263).
        # Finish the call, then pay back by id whatever it took before the cancellation propagates.
        reserve = asyncio.ensure_future(
            self._ledger.reserve_upload_quota(
                uploader_id,
                reservation,
                size_bytes=size,
                max_files=self._max_files_per_user - observed.files,
                max_total_bytes=self._max_total_bytes_per_user - observed.size,
            )
        )
        try:
            ok = await _wait_to_completion(reserve, cancel_bound=_LEDGER_CANCEL_WAIT_SECONDS)
        except asyncio.CancelledError:
            if not reserve.done():
                self._leave_running(
                    reserve, what="reserve", uploader_id=uploader_id, reservation=reservation
                )
            elif self._reserve_may_hold_a_slot(reserve, uploader_id):
                await self._release_across_shards(reservation=reservation, uploader_id=uploader_id)
            raise
        except Exception:
            # Its outcome is unknown, and a release by id pays back exactly what it took, if
            # anything. Awaited, under _quota_lock, before the error propagates: a release that was
            # only started let an immediate retry in this process reserve while its own orphan row
            # was still counted, and be refused at the quota edge as "another engine shard". The
            # wait is bounded, so a stalled store cannot hold the lock and every queued save. The
            # release never raises a ledger error, so the reserve's error is what propagates.
            release = self._release_later(reservation, uploader_id)
            if release is not None:
                await asyncio.wait((release,), timeout=_LEDGER_CANCEL_WAIT_SECONDS)
            raise
        if not ok:
            raise self._shard_refusal(uploader=uploader, observed=observed)
        return True

    @staticmethod
    def _reserve_may_hold_a_slot(reserve: asyncio.Future[bool], uploader_id: str) -> bool:
        """Whether a finished reserve, abandoned by a cancelled save, may hold a slot to pay back.

        Only a refusal holds none. A reserve that was cancelled or raised may have committed, and
        the release is by its own id, so paying it back can never touch a sibling's slot (vault
        BACKLOG #3180). Either is logged, which also marks its error retrieved. The line says a
        release is started, not that the slot is paid back: a statement that commits after the
        release ran, or a release that fails, leaves the slot to go stale (vault BACKLOG #3740
        item 11)."""
        if reserve.cancelled():
            _log.warning(
                "the engine-shard upload reserve for %s was cancelled before it finished; a "
                "release by its id is started for a slot it may have taken",
                uploader_id,
            )
            return True
        exc = reserve.exception()
        if exc is not None:
            _log.warning(
                "the engine-shard upload reserve for %s failed while the upload was being "
                "cancelled; a release by its id is started for a slot it may have taken",
                uploader_id,
                exc_info=exc,
            )
            return True
        return reserve.result()

    def _start_heartbeat(self, reservation: str, uploader_id: str, stop: asyncio.Event) -> None:
        """Touch this save's reservation every ``_RESERVATION_HEARTBEAT_SECONDS`` until ``stop`` is
        set, so a slow save keeps its slot (BACKLOG #2648; :class:`UploadQuotaError` states the
        residual). The touch moves only this reservation's clock (vault BACKLOG #3180). A touch
        that lands after the save's release finds no row and changes nothing, so ``stop`` is a
        signal, never a wait. A failed touch is logged and the next one tried.

        **The wait for a touch is bounded, and a running heartbeat never cancels a touch (BACKLOG
        #3256).** The heartbeat waits ``_RESERVATION_TOUCH_WAIT_SECONDS`` for it, then goes on, so a
        touch stuck on the store no longer holds the heartbeat or its lifetime cap, and a ``stop``
        during the wait ends it at once. The stuck touch is left to land on its own, which still
        moves the reservation's clock when it does, and no second touch starts while it runs, so a
        stalled store never collects one abandoned statement per interval. One still running when
        the heartbeat ends is held like the other stragglers, and so is capped at
        ``_LEDGER_STRAGGLER_MAX_SECONDS`` and cancelled by the shutdown drain, which does not wait
        for it. A heartbeat that is itself cancelled, as by that drain, cancels its touch as it
        ends (vault BACKLOG #3740 item 14). The cost: a touch that never returns ends the
        refreshing for that save, which :class:`UploadQuotaError` lists."""
        ledger = self._ledger
        if ledger is None:
            return

        def _missed(touch: asyncio.Future[Any]) -> None:
            if not touch.cancelled() and touch.exception() is not None:
                _log.warning(
                    "could not refresh the engine-shard upload reservation for %s; it may be "
                    "reclaimed if the upload outlasts the staleness window",
                    uploader_id,
                    exc_info=touch.exception(),
                )

        async def _beat() -> None:
            deadline = time.monotonic() + _RESERVATION_HEARTBEAT_MAX_SECONDS
            touch: asyncio.Future[None] | None = None
            try:
                while not stop.is_set():
                    try:
                        await asyncio.wait_for(stop.wait(), _RESERVATION_HEARTBEAT_SECONDS)
                    except TimeoutError:
                        if time.monotonic() >= deadline:
                            _log.warning(
                                "an upload by %s is still writing after %gs; its engine-shard "
                                "reservation is no longer refreshed and may be reclaimed",
                                uploader_id,
                                _RESERVATION_HEARTBEAT_MAX_SECONDS,
                            )
                            return
                        if touch is not None and not touch.done():
                            continue  # the last touch is still running; it is not doubled
                        touch = asyncio.ensure_future(ledger.touch_upload_quota(reservation))
                        # On the touch itself, so a failure that lands after the wait is logged.
                        touch.add_done_callback(_missed)
                        stopped = asyncio.ensure_future(stop.wait())
                        try:
                            await asyncio.wait(
                                {touch, stopped},
                                timeout=_RESERVATION_TOUCH_WAIT_SECONDS,
                                return_when=asyncio.FIRST_COMPLETED,
                            )
                        finally:
                            stopped.cancel()
                        if not touch.done() and not stop.is_set():
                            _log.warning(
                                "an engine-shard upload reservation touch for %s did not finish "
                                "within %gs; it was left running, and the next waits for it",
                                uploader_id,
                                _RESERVATION_TOUCH_WAIT_SECONDS,
                            )
            finally:
                if touch is not None and not touch.done():
                    # Still referenced, and _missed still logs its outcome. Capped like every other
                    # straggler, so a stalled store does not collect one per save (vault BACKLOG
                    # #3180); a touch cancelled there moves no clock, which is all it would do.
                    self._touches.add(touch)
                    touch.add_done_callback(self._touches.discard)
                    self._hold(touch, cap=_LEDGER_STRAGGLER_MAX_SECONDS)
                    current = asyncio.current_task()
                    if current is not None and current.cancelling():
                        # The shutdown drain cancelled this heartbeat, so its touch goes now, not
                        # at the drain's next pass, and once only (vault BACKLOG #3740 item 14).
                        self._cancel_touches()

        task = asyncio.ensure_future(_beat())
        self._heartbeats.add(task)
        task.add_done_callback(self._heartbeats.discard)

    def _leave_running(
        self, fut: asyncio.Future[Any], *, what: str, uploader_id: str, reservation: str
    ) -> None:
        """Let a ledger call a cancelled save stopped waiting for finish on its own (BACKLOG #2263),
        for at most ``_LEDGER_STRAGGLER_MAX_SECONDS`` (vault BACKLOG #3180).

        A reserve that then may hold a slot is paid back by a fresh release, by its id."""
        _log.warning(
            "the engine-shard upload %s for %s did not finish within %gs of a cancellation; it "
            "was left running",
            what,
            uploader_id,
            _LEDGER_CANCEL_WAIT_SECONDS,
        )

        def _done(done: asyncio.Future[Any]) -> None:
            if what != "reserve":
                _log_release_cancelled(done, uploader_id)
            elif done in self._drain_cancelled:
                # The drain cancelled it because the store is about to close, so nothing new
                # starts against it; the slot is reclaimed once it goes stale. This line is its
                # one record, so a reserve error is marked retrieved here rather than logged.
                if not done.cancelled():
                    done.exception()
                _log.warning(
                    "shutdown: a slot the engine-shard upload reserve for %s may have taken is "
                    "not released; it is reclaimed once it goes stale",
                    uploader_id,
                )
            elif self._reserve_may_hold_a_slot(done, uploader_id):
                self._release_later(reservation, uploader_id)

        self._hold(fut, _done, cap=_LEDGER_STRAGGLER_MAX_SECONDS)

    def _release_later(self, reservation: str, uploader_id: str) -> asyncio.Future[None] | None:
        """Start a release of ``reservation``, held for at most ``_LEDGER_STRAGGLER_MAX_SECONDS``
        (vault BACKLOG #3180), and return it, or ``None`` with no ledger. The held task is the
        store call itself, so the cap or the shutdown drain cancels the call, not a wrapper that
        would absorb the cancellation. A caller may wait on it; nothing has to."""
        ledger = self._ledger
        if ledger is None:
            return None
        release = asyncio.ensure_future(_release_reservation(ledger, reservation, uploader_id))
        self._hold(
            release,
            functools.partial(_log_release_cancelled, uploader_id=uploader_id),
            cap=_LEDGER_STRAGGLER_MAX_SECONDS,
        )
        return release

    def _hold(
        self,
        fut: asyncio.Future[Any],
        on_done: Callable[[asyncio.Future[Any]], None] | None = None,
        *,
        cap: float | None = None,
    ) -> None:
        """Keep ``fut`` referenced in ``_stragglers`` until it finishes, then call ``on_done``.
        The loop holds a Task only weakly, so a task nobody awaits any more must be held here.
        ``cap`` cancels ``fut`` if it is still running that many seconds on (vault BACKLOG #3180),
        which keeps the set bounded while a store stalls."""
        self._stragglers.add(fut)
        timer = asyncio.get_running_loop().call_later(cap, fut.cancel) if cap is not None else None

        def _done(done: asyncio.Future[Any]) -> None:
            self._stragglers.discard(done)
            if timer is not None:
                timer.cancel()
            if on_done is not None:
                on_done(done)

        fut.add_done_callback(_done)

    async def _remove_cancelled_pair(self, file_id: str) -> None:
        """Start the removal of a cancelled save's landed pair, and wait for it until the next
        cancellation or ``_CANCELLED_REMOVAL_WAIT_SECONDS`` (vault BACKLOG #3740 item 4).

        ``save`` calls this holding ``_quota_lock``. The removal is registered in
        ``_pending_removals`` until it ends, its bound passes or the shutdown drain names it, and
        the next save in this process waits for it there before it scans
        (:meth:`_wait_for_pending_removals`), so it neither counts a pair about to go nor holds
        its sidecar open. That wait is the next save's, not this cancelled one's. A request
        deadline arrives through anyio scopes that cancel again on every loop pass, so a wait here
        that absorbed each cancellation spun the loop for the whole bound while every other upload
        queued on the lock. This wait ends at the first cancellation it meets instead. With no
        bound at all, one hung unlink held the lock for as long as the filesystem took.

        A thread cannot be stopped, so past the bound the removal goes on, and until it lands the
        pair is on disk and billed: a save that scans meanwhile, in this process or on a sibling
        engine shard, counts it. That can refuse an upload at the quota edge, but never admits one
        too many. At the bound, or at the end of the shutdown drain's wait if that comes first, an
        ERROR names the ``file_id`` as a stored file with no ``upload.create`` row, since the
        process may stop before the removal answers (vault BACKLOG #3178). A removal that then
        takes the pair away logs a WARNING withdrawing it, from its own thread. Any removal that
        fails or is refused logs an ERROR, at whatever time it ends.

        The removals run on :func:`_removal_executor`, never the default executor, so unlinks that
        hang hold at most ``_CANCELLED_REMOVAL_WORKERS`` threads, and the pool every
        ``asyncio.to_thread`` in the engine shares stays free. A removal past that cap queues and
        still runs: its Future is the executor's own, which nothing cancels, so it is not held as a
        straggler the shutdown drain would cancel. The cost: while that many unlinks hang, every
        later removal in the process waits behind them, its bound counted from when it was queued,
        so its pair stays stored and billed until they return, each named at ERROR at its bound.
        The cap is read once, when the pool is first built. Once a removal outlives its bound, a
        save that scans can hold the sidecar open while it unlinks; on Windows that refuses the
        unlink, which is logged, and the sidecar stays listed until the retention prune clears it.

        This covers the cancelled-save path only. :meth:`discard`'s removal, after a failed
        ``upload.create`` row, still waits on its unlink under the lock with no bound."""
        loop = asyncio.get_running_loop()
        entry = _PendingRemoval(file_id, loop.time() + _CANCELLED_REMOVAL_WAIT_SECONDS)
        # submit() can raise, at least after interpreter shutdown; save logs that and propagates
        # its cancellation.
        removal = _submit_to_thread(
            self._remove_and_report_sync, entry, executor=_removal_executor()
        )
        self._pending_removals[removal] = entry
        overdue = loop.call_at(
            entry.deadline,
            self._flag_removal,
            removal,
            f"its removal did not finish within {_CANCELLED_REMOVAL_WAIT_SECONDS:g}s and goes "
            "on without holding back other uploads",
        )

        def _ended(done: asyncio.Future[bool]) -> None:
            self._pending_removals.pop(done, None)
            overdue.cancel()
            if done.cancelled() or done.exception() is not None:
                _log_discard_unfinished(done, file_id)

        removal.add_done_callback(_ended)
        # Only for a caller already propagating a cancellation, as save's arm is: a repeat
        # cancellation ends the wait and is not passed on.
        with contextlib.suppress(asyncio.CancelledError):
            await asyncio.wait((removal,), timeout=_CANCELLED_REMOVAL_WAIT_SECONDS)

    def _flag_removal(self, removal: asyncio.Future[bool], why: str) -> None:
        """Name a cancelled-pair removal still running at ERROR, once, as a stored file with no
        ``upload.create`` row, and stop holding later saves for it. Called at its bound and by the
        shutdown drain, since the process may stop before the removal answers (vault BACKLOG #3178,
        #3740 item 4)."""
        entry = self._pending_removals.pop(removal, None)
        if entry is None or removal.done():
            return
        entry.flagged = True
        _log.error(
            "upload %s was cancelled after its file landed and has no upload.create audit row; "
            "%s, so the file may still be stored, and counts against its uploader's quota until "
            "it goes",
            entry.file_id,
            why,
        )

    async def _wait_for_pending_removals(self) -> None:
        """Wait, holding ``_quota_lock``, for the cancelled-pair removals still inside their bound
        before this save scans the disk (vault BACKLOG #3740 item 4). Every uploader's: the scan
        opens every sidecar, and on Windows an open sidecar refuses its unlink. A cancellation of
        this save propagates as usual: it has reserved nothing yet. The deadline is read here as
        well as by the bound's timer, so an entry whose timer never ran cannot hold a save."""
        loop = asyncio.get_running_loop()
        while pending := {
            removal: entry.deadline
            for removal, entry in self._pending_removals.items()
            if not removal.done() and entry.deadline > loop.time()
        }:
            await asyncio.wait(pending.keys(), timeout=min(pending.values()) - loop.time())

    def _remove_and_report_sync(self, entry: _PendingRemoval) -> bool:
        """In the removal's thread: :meth:`_discard_cancelled_sync`, then whether neither half of
        the pair is left. A removal an ERROR already named that takes the pair away withdraws it
        here, in the thread, since a loop callback would not run once the loop has closed, as it
        may have by then at shutdown. Reading ``entry.flagged`` from this thread races the loop
        setting it, so a removal that lands just as it is named may leave the ERROR standing."""
        self._discard_cancelled_sync(entry.file_id)
        # Not Path.exists, which answers False for any OSError, so a share that cannot be reached
        # would read as a pair removed and withdraw the ERROR (BACKLOG #5388).
        gone = all(_known_absent(path) for path in self._paths(entry.file_id))
        if gone and entry.flagged:
            _log.warning(
                "upload %s: its removal finished after it was named at ERROR, so the earlier "
                "ERROR that it may still be stored no longer applies",
                entry.file_id,
            )
        return gone

    def _running(self, left: set[asyncio.Future[Any]]) -> set[asyncio.Future[Any]]:
        """What of ``left`` and the stragglers held now has not ended, for the drain's grace."""
        return {t for t in left | self._stragglers if not t.done()}

    def _cancel_touches(self) -> None:
        """Cancel every heartbeat touch held as a straggler, once each, since a store's unwind of
        the cancelled statement may itself take a while (vault BACKLOG #3740 item 14)."""
        for touch in self._touches:
            if not (isinstance(touch, asyncio.Task) and touch.cancelling()):
                touch.cancel()

    async def drain_stragglers_within(
        self, budget: float, *, settle: Callable[[float], Awaitable[object]] | None = None
    ) -> None:
        """:meth:`drain_stragglers` with both of its waits fitted inside ``budget`` seconds, the
        form a shutdown step under one teardown budget calls (BACKLOG #3191). The budget is split
        between the wait and the grace for what it then cancels in the ratio of the drain's own
        defaults, and each is capped at its default (vault BACKLOG #3740 item 17).

        ``settle``, when given, is awaited first with the wait's share, and the drain's own wait
        gets what it leaves. It waits for work that may still start a straggler, so the drain does
        not return before that straggler is held (vault BACKLOG #3740 item 6)."""
        loop = asyncio.get_running_loop()
        ratio = _STRAGGLER_DRAIN_SECONDS / (
            _STRAGGLER_DRAIN_SECONDS + _STRAGGLER_CANCEL_GRACE_SECONDS
        )
        wait = max(0.0, min(_STRAGGLER_DRAIN_SECONDS, budget * ratio))
        grace = max(0.0, min(_STRAGGLER_CANCEL_GRACE_SECONDS, budget - wait))
        if settle is None:
            await self.drain_stragglers(wait, grace=grace)
            return
        self._cancel_touches()  # not left running through the settle
        began = loop.time()
        try:
            await settle(wait)
        except asyncio.CancelledError:
            # The step was cut: cancel what is left, and wait for none of it.
            await self.drain_stragglers(0.0, grace=0.0)
            raise
        except Exception:
            # A settle that fails still leaves the drain to run, since that is the step's point.
            await self.drain_stragglers(max(0.0, wait - (loop.time() - began)), grace=grace)
            raise
        await self.drain_stragglers(max(0.0, wait - (loop.time() - began)), grace=grace)

    async def drain_stragglers(
        self,
        timeout: float | None = None,
        *,
        grace: float | None = None,
    ) -> None:
        """Let what a cancelled save left running finish before the store closes (vault BACKLOG
        #3180): the ledger calls, the late releases they spawn, and the save-time sweeps. The
        lifespan calls it before ``engine.stop()``.

        It waits up to ``timeout``. A reserve that finishes inside that wait still starts its
        release, and the wait covers that release too. Then it cancels what is left, live saves'
        heartbeats included, and waits up to ``grace`` for those to end and for any release one of
        them started meanwhile; such a release still running at ``grace`` is cancelled. A reserve it cancelled
        spawns no release when it ends, however long past ``grace`` that is, so nothing new starts
        against a store about to close; a slot it may have taken goes stale. Only those reserves
        are refused, so a lifespan that runs again on this store releases normally. A sweep it
        cancels logs each file it removed with no row, as a shutdown cancel always has.

        ``None`` for either wait reads its module default, ``_STRAGGLER_DRAIN_SECONDS`` or
        ``_STRAGGLER_CANCEL_GRACE_SECONDS``, when the drain runs rather than when this method was
        defined (vault BACKLOG #3740 item 12).

        A heartbeat touch is not waited for, and each pass of either wait cancels every touch
        held then (vault BACKLOG #3740 item 14). A touch would only refresh this process's
        reservation, whose save does not outlive the shutdown, so landing late would only put off
        the moment a sibling engine shard may reclaim the slot."""
        if timeout is None:
            timeout = _STRAGGLER_DRAIN_SECONDS
        if grace is None:
            grace = _STRAGGLER_CANCEL_GRACE_SECONDS
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        # A cancelled save's removal still running is waited for here too, but it is not a
        # straggler: cancelling its job could keep it from running at all. Its bound's ERROR is a
        # loop timer the closing loop would drop, so one still running at the end of this wait
        # is named here instead (vault BACKLOG #3740 item 4).
        while (waited := (self._stragglers - self._touches) | set(self._pending_removals)) and (
            remaining := deadline - loop.time()
        ) > 0:
            self._cancel_touches()
            await asyncio.wait(waited, timeout=remaining)
        for removal in list(self._pending_removals):
            self._flag_removal(removal, "its removal was still running at shutdown")
        self._cancel_touches()
        left = set(self._stragglers) | set(self._heartbeats)
        if not left:
            return
        if calls := self._stragglers - self._touches:
            _log.warning(
                "shutdown: cancelling %d upload ledger call(s) or save-time sweep(s) still "
                "running after %gs",
                len(calls),
                timeout,
            )
        # Each discard is registered after the task's own callbacks, so a reserve's done callback
        # still finds it here and starts no release.
        # A task already done is not cancelled and keeps its own outcome: a reserve that finished
        # in the same pass as the wait's timeout still pays its slot back.
        # Not the touches, which _cancel_touches has cancelled once already: a second cancel
        # would cut short the store's unwind of the first.
        for task in left - self._touches:
            if task.cancel():
                self._drain_cancelled.add(task)
                task.add_done_callback(self._drain_cancelled.discard)
        # The grace covers what a callback starts meanwhile too: a release from a reserve that
        # finished before the cancel reached it. One still running at the bound is cancelled and
        # marked like the rest, so a reserve among them starts no release; the drain does not wait
        # for it to unwind, as it does not for anything still stuck in `left`.
        # The first wait runs even when everything in `left` is done: it is also the loop pass in
        # which a done task's own callbacks run and start that release. A touch is in no wait,
        # since a store can take a while to unwind a cancelled statement.
        deadline = loop.time() + grace
        if unwinding := left - self._touches:
            await asyncio.wait(unwinding, timeout=grace)
        else:
            await asyncio.sleep(0)
        while (pending := self._running(left) - self._touches) and (
            remaining := deadline - loop.time()
        ) > 0:
            self._cancel_touches()  # one a heartbeat that ended held meanwhile
            await asyncio.wait(pending, timeout=remaining)
        self._cancel_touches()
        stuck = self._running(left) - self._touches
        for task in stuck - left:
            if task.cancel():
                self._drain_cancelled.add(task)
                task.add_done_callback(self._drain_cancelled.discard)
        if stuck:
            _log.error(
                "shutdown: %d cancelled upload task(s) had not finished after %gs",
                len(stuck),
                grace,
            )
        if unwinding_touches := self._running(set()) & self._touches:
            # Not waited for, but named: on SQLite one still holds the writer lock as it unwinds.
            _log.warning(
                "shutdown: %d cancelled engine-shard reservation touch(es) still unwinding",
                len(unwinding_touches),
            )

    def _shard_refusal(self, *, uploader: str, observed: _Observed) -> UploadQuotaError:
        """The refusal when what is on disk fits but uploads in flight on other engine shards take
        the rest of the budget. Worded apart from :meth:`_on_disk_refusal` so an operator can tell
        the two causes apart."""
        return UploadQuotaError(
            f"uploader {uploader!r} has {observed.files} uploaded files holding "
            f"{observed.size} bytes, and another engine shard is mid-upload against the same "
            f"budget; the limits are {self._max_files_per_user} files / "
            f"{self._max_total_bytes_per_user} bytes{_unsealable_note(observed)}"
        )

    def _on_disk_refusal(
        self, *, uploader: str, observed: _Observed, size: int
    ) -> UploadQuotaError | None:
        """The per-uploader quota verdict against what is ALREADY on disk, or ``None`` if it fits.

        One string, two callers: the under-lock check inside ``save``'s build-and-write, and the
        engine-shard reservation's pre-check. The bucket key is the IMMUTABLE ``uploader_id`` (the
        caller filters on it, the same value the ownership check uses), so the budget and the
        ownership rule can never disagree about who a file belongs to and a recycled username is
        never billed for files it cannot read. The message names the human username, because an
        operator reading a 409 needs a name, not a uuid."""
        if observed.files + 1 > self._max_files_per_user:
            return UploadQuotaError(
                f"uploader {uploader!r} has {observed.files} uploaded files; the limit is "
                f"{self._max_files_per_user}{_unsealable_note(observed)}"
            )
        projected = observed.size + size
        if projected > self._max_total_bytes_per_user:
            return UploadQuotaError(
                f"uploader {uploader!r} would hold {projected} bytes; the limit is "
                f"{self._max_total_bytes_per_user}{_unsealable_note(observed, by_bytes=True)}"
            )
        return None

    async def _release_across_shards(self, *, reservation: str, uploader_id: str) -> None:
        """Pay the reservation back, by its id (vault BACKLOG #3180). Never raises a ledger error:
        the file is already written (or already failed) by the time this runs, so turning a ledger
        blip into a failed upload would be strictly worse.

        **A cancellation waits for the release to finish, then propagates (BACKLOG #2263).** A request
        deadline arrives through an anyio scope that cancels again at every await, so a plain await
        here was cut short whenever the deadline fired mid-upload, and the slot leaked. Once the
        caller is cancelled, the wait is bounded by ``_LEDGER_CANCEL_WAIT_SECONDS``, so a stuck store
        cannot hold ``_quota_lock`` and the cancellation indefinitely. That includes a cancellation
        an earlier wait already absorbed. A release still running at the bound is logged and left
        to finish on its own, for at most ``_LEDGER_STRAGGLER_MAX_SECONDS``.

        A reservation that is never released is reclaimed once it goes stale, whatever else its
        uploader does: only its own reserve and its own heartbeat move its clock.
        :class:`UploadQuotaError` states the residual."""
        ledger = self._ledger
        if ledger is None:
            return
        release = asyncio.ensure_future(_release_reservation(ledger, reservation, uploader_id))
        try:
            await _wait_to_completion(release, cancel_bound=_LEDGER_CANCEL_WAIT_SECONDS)
        except asyncio.CancelledError:
            if not release.done():
                self._leave_running(
                    release, what="release", uploader_id=uploader_id, reservation=reservation
                )
            raise

    def _observed_sync(self, uploader_id: str) -> _Observed:
        """What is already ON DISK for ``uploader_id`` — the fleet-visible half of the budget. Sync:
        the caller runs it off the event loop.

        An upload ``rotate-key`` cannot seal counts too, at its body's size on disk (BACKLOG #2322).
        Its owner is unverified, so this errs toward refusing; :class:`_UnsealableUpload` says why.
        Both kinds come from one walk of the directory (BACKLOG #3184). The never-sealable ones are
        also counted apart, for the refusal to name (BACKLOG #3183).

        A sidecar the key service gave no verdict on raises :class:`UploadUnavailableError` rather
        than being left out, so an outage cannot lower the count a quota is checked against
        (BACKLOG #3734)."""
        held: list[_UnsealableUpload] = []
        metas = self._scan_metas_sync(held, outage_raises=True)
        sizes = [m.size for m in metas if m.uploader_id == uploader_id]
        mine = [h.size for h in held if h.uploader_id == uploader_id]
        held_files, held_bytes = len(mine), sum(mine)
        return _Observed(len(sizes) + held_files, sum(sizes) + held_bytes, held_files, held_bytes)

    async def list_files(self) -> list[UploadedFileMeta]:
        """List all uploaded files (newest first). Undecryptable/foreign sidecars are skipped with a
        warning (never a body in the log), so a rotated-away key can't 500 the whole page.

        The sort is TOTAL — ``file_id`` breaks a timestamp tie — because ``GET /uploads`` pages off
        this order (BACKLOG #1152). ``uploaded_at`` alone is not a total order: files written in the
        same instant compare equal, and the underlying scan is a directory walk whose order is not
        guaranteed to repeat, so two requests could place a tied file on both pages or on neither.
        A stable tiebreak is what makes "page 2" mean the same thing twice."""

        def _scan() -> list[UploadedFileMeta]:
            out = self._scan_metas_sync()
            out.sort(key=lambda m: (m.uploaded_at, m.file_id), reverse=True)
            return out

        return await asyncio.to_thread(_scan)

    async def storage_reachable(self) -> bool:
        """Whether the uploads root itself can be reached now, so an outage met on one upload is
        that upload's own fault, such as a stale NFS handle, not the storage's (BACKLOG #5388 added
        item 3). The route reads it to answer a caller who may not see the upload as it answers an
        absent id (ASVS 8.2.2). ``False`` only when the root's ``lstat`` fails as unreachable
        (:func:`~messagefoundry.path_reach.is_unreachable`); a root that is missing is reachable
        storage holding nothing."""

        def _check() -> bool:
            try:
                os.lstat(self._root)
            except OSError as exc:
                return not is_unreachable(exc)
            return True

        return await asyncio.to_thread(_check)

    async def get_meta(self, file_id: str) -> UploadedFileMeta:
        """Return one file's metadata (path-traversal-guarded). Raises :class:`UploadNotFoundError`,
        and :class:`UploadUnreadableError` for a sidecar the cipher refuses, that is damaged
        (:class:`UploadDamagedError`) or that the filesystem refused the engine
        (:class:`UploadAccessError`)."""

        def _read() -> UploadedFileMeta:
            _, meta_path = self._paths(file_id)
            _refuse_unplain(file_id, "sidecar", meta_path)
            kind: _ReadRefusal = "damaged"
            unreached: str | None = None
            try:
                return self._decrypt_meta(_read_sidecar(meta_path), file_id)
            except _UnreachableError as exc:
                unreached = codec_safe_str(exc)
            except FileNotFoundError as exc:
                raise UploadNotFoundError(file_id) from exc
            except CipherUnavailableError as exc:
                raise UploadUnavailableError(str(exc)) from exc
            except CipherError as exc:
                raise UploadUnreadableError(str(exc)) from exc
            except OSError as exc:
                # Only when it is the file's own refusal, such as a permission the engine lacks,
                # which answered a server error (BACKLOG #5388 added item 2). Its own arm, so the
                # Unicode error below is rendered only through codec_safe_str.
                refused = _refused_read(exc)
                if refused is None:
                    raise
                kind = refused
                defect = codec_safe_str(exc)
            except (UnicodeDecodeError, _MalformedSidecarError) as exc:
                defect = codec_safe_str(exc)
            # Raised after the handler, so the error holding the file is on no chain.
            if unreached is not None:
                raise _unreachable(file_id, unreached)
            raise _refusal(file_id, "sidecar", defect, kind)

        return await asyncio.to_thread(_read)

    async def read_bytes(self, file_id: str) -> bytes:
        """Return the decrypted body bytes (path-traversal-guarded). Raises
        :class:`UploadNotFoundError`, and :class:`UploadUnreadableError` for a body the cipher
        refuses, that is damaged (:class:`UploadDamagedError`) or that the filesystem refused the
        engine (:class:`UploadAccessError`)."""

        def _read() -> bytes:
            blob_path, _ = self._paths(file_id)
            _refuse_unplain(file_id, "body", blob_path)
            kind: _ReadRefusal = "damaged"
            unreached: str | None = None
            stored = ""
            try:
                # No size cap: a sound body stored under a larger max_upload_bytes is still
                # served, as the reseal pass keeps it too.
                stored = _read_plain_text(blob_path)
                return self._decrypt_blob(stored, file_id)
            except _UnreachableError as exc:
                unreached = codec_safe_str(exc)
            except FileNotFoundError as exc:
                raise UploadNotFoundError(file_id) from exc
            except CipherUnavailableError as exc:
                stored = ""
                raise UploadUnavailableError(str(exc)) from exc
            except CipherError as exc:
                # Logged with the whole id, as the scan logs a sidecar's, and a body under a held
                # key whose tag fails is reported as a sidecar is (BACKLOG #5552 item 6 (a)). The
                # cipher's message carries no decrypted value.
                _log.warning("uploaded-file body %s: cipher declined it: %s", file_id, exc)
                self._report_tag_failure(file_id, stored, exc, part="body")
                # This frame's copy is let go; _decrypt_blob's frame on the cause's traceback
                # still holds the stored text, as it did before this report.
                stored = ""
                raise UploadUnreadableError(str(exc)) from exc
            except OSError as exc:
                # Refused on disk (BACKLOG #5388 added item 2). Its own arm, so the Unicode error
                # below is rendered only through codec_safe_str.
                refused = _refused_read(exc)
                if refused is None:
                    raise
                kind = refused
                defect = codec_safe_str(exc)
            except (UnicodeError, binascii.Error) as exc:
                # Not UTF-8, not ASCII, or not the strict base64 the body is stored as.
                defect = codec_safe_str(exc)
            # The refusal raised below holds this frame on its traceback, so the stored body is
            # let go first.
            stored = ""
            if unreached is not None:
                raise _unreachable(file_id, unreached)
            raise _refusal(file_id, "body", defect, kind)

        return await asyncio.to_thread(_read)

    async def delete(self, file_id: str, *, sidecar_refused: bool = False) -> UploadRemoval:
        """Delete an uploaded file, its body and then its sidecar. Returns what this call removed
        (:class:`UploadRemoval`), for the audit row, once the sidecar is gone; a part already
        absent is not counted as removed (BACKLOG #5388 added item 3). Path-traversal-guarded;
        raises :class:`UploadNotFoundError` if it does not exist, or if this call removed nothing
        because both parts were already gone. A share or uploads directory that cannot be reached
        raises :class:`UploadStorageUnreachableError`, never a missing file or a removal.

        An unlink another handle refuses, as a Windows sharing violation does, is tried again
        briefly. A body still held open by then raises :class:`UploadDeleteIncompleteError` with
        nothing removed, and a sidecar that cannot be removed raises it carrying what this call
        did remove, so the route records only that.

        An upload ``rotate-key`` cannot seal is deleted too, although its sidecar is refused
        (BACKLOG #2322). The metadata returned then carries only its id, its body's size on disk and
        its sidecar's mtime (:meth:`_UnsealableUpload.as_meta`). Any other refused upload still
        raises :class:`UploadUnreadableError`, and nothing is removed. A sidecar the cipher's key
        service gave no verdict on raises :class:`UploadUnavailableError`, and nothing is removed
        (BACKLOG #3734).

        ``sidecar_refused`` says the caller's own :meth:`get_meta` was just refused. The sidecar is
        then not decrypted again, so one delete raises one cipher WARNING and one alert, not two.
        It does not widen what is removed: of the uploads whose sidecar is refused, only the
        never-sealable kind is removed, whether the refusal was the caller's read or this call's own.
        The flag does not authorize anything either. The route decides who may pass it.

        A sidecar that is gone by the time it is classed answers :class:`UploadNotFoundError`, as an
        absent one does (BACKLOG #3240). It is checked again only after the class is refused."""

        def _delete() -> UploadRemoval:
            blob_path, meta_path = self._paths(file_id)
            # Before anything is read or classed. The sidecar is opened, so it must be a plain
            # file. The body is only unlinked, which a FIFO allows and a directory refuses.
            _refuse_unplain(file_id, "sidecar", meta_path)
            if blob_path.is_dir():
                raise _damaged(file_id, "body", "it is a directory")
            meta: UploadedFileMeta | None = None
            refusal = _REFUSED_NOT_UNSEALABLE
            defect: str | None = None
            kind: _ReadRefusal = "damaged"
            classed = False
            unreached: str | None = None
            if sidecar_refused:
                # The store checks the caller's claim: only a cipher that refuses plaintext can
                # hold the never-sealable kind.
                if not self._refuses_plaintext:
                    raise UploadUnreadableError(refusal)
            else:
                try:
                    meta = self._decrypt_meta(_read_sidecar(meta_path), file_id)
                except _UnreachableError as exc:
                    unreached = codec_safe_str(exc)
                except FileNotFoundError as exc:
                    raise UploadNotFoundError(file_id) from exc
                except CipherUnavailableError as exc:
                    # No verdict on the sidecar, so it is not classed and nothing is removed.
                    raise UploadUnavailableError(str(exc)) from exc
                except CipherError as exc:
                    refusal = str(exc)
                except OSError as exc:
                    # Only when it is the file's own refusal, such as a permission the engine
                    # lacks, which answered a server error (BACKLOG #5388 added item 2). It is
                    # never classed, and a permission refusal is not answered as damage. Its own
                    # arm, so the Unicode error below is rendered only through codec_safe_str.
                    refused = _refused_read(exc)
                    if refused is None:
                        raise
                    kind = refused
                    defect = codec_safe_str(exc)
                except (UnicodeDecodeError, _MalformedSidecarError) as exc:
                    defect = codec_safe_str(exc)
                    classed = isinstance(exc, UnicodeDecodeError | _OversizedFileError)
            if unreached is not None:
                raise _unreachable(file_id, unreached)
            # Refused, never trusted, and raised after the handler, so the error holding the file
            # is on no chain. Classed only where the scan classes it too: a sidecar that is not
            # UTF-8 or is oversized, on a cipher that refuses plaintext, may be the never-sealable
            # kind. That one is logged as a refusal below only if the class check refuses it too.
            if defect is not None and not (classed and self._refuses_plaintext):
                raise _refusal(file_id, "sidecar", defect, kind)
            if meta is None:
                held = self._unsealable_sync(file_id, meta_path)
                if held is None:
                    # _unsealable_sync declines a sidecar it cannot open, so tell an absent one,
                    # whether it was never there or went since the read, from a refused one.
                    # Only FileNotFoundError means absent. Any other OSError is answered as the
                    # read above answers it, never as a missing file (BACKLOG #5388 added item 2).
                    try:
                        meta_path.lstat()
                    except FileNotFoundError as exc:
                        if is_absent(exc):
                            raise UploadNotFoundError(file_id) from exc
                        unreached = codec_safe_str(exc)
                    except OSError as exc:
                        # A share that went away is unreachable, as the read above answers it,
                        # never a server error (BACKLOG #5388).
                        unreached = _unreachable_fault(exc)
                        if unreached is None:
                            refused = _refused_read(exc)
                            if refused is None:
                                raise
                            kind = refused
                            defect = codec_safe_str(exc)
                    if unreached is not None:
                        raise _unreachable(file_id, unreached)
                    if defect is not None:
                        raise _refusal(file_id, "sidecar", defect, kind)
                    raise UploadUnreadableError(refusal)
                meta = held.as_meta()
            # Remove the body first, then the sidecar (best-effort on the body — the sidecar is the
            # listing key, so once it is gone the file is invisible even if the blob lingers).
            # Under the pair lock, so a rotate-key re-seal cannot put either back (BACKLOG #3181).
            with _pair_lock(meta_path):
                return self._unlink_pair(file_id, blob_path, meta_path, meta)

        return await asyncio.to_thread(_delete)

    def _unlink_pair(
        self, file_id: str, blob_path: Path, meta_path: Path, meta: UploadedFileMeta
    ) -> UploadRemoval:
        """The delete's unlinks, under the pair lock (:meth:`delete`): the body first, then the
        sidecar, each counted only when this call removed it (BACKLOG #5388 added item 3)."""
        # A directory swapped in for the sidecar after its read is refused before the body goes,
        # since its unlink would fail with the body already removed. So is a sidecar that cannot be
        # checked: a permission is the access refusal, a share that cannot be reached is
        # unreachable, and any other failure is raised as it is.
        unchecked: str | None = None
        unreached: str | None = None
        sidecar_dir = False
        sidecar_there = True
        try:
            sidecar_dir = S_ISDIR(meta_path.lstat().st_mode)
        except FileNotFoundError as exc:
            if is_absent(exc):
                # Gone since its read, as another remover's work: there is nothing of it for this
                # call to remove or to keep, so the row records neither.
                sidecar_there = False
            else:
                unreached = codec_safe_str(exc)
        except PermissionError as exc:
            unchecked = codec_safe_str(exc)
        except OSError as exc:
            if not is_unreachable(exc):
                raise
            unreached = codec_safe_str(exc)
        if unreached is not None:
            raise _unreachable(file_id, unreached)
        if unchecked is not None:
            raise _refusal(file_id, "sidecar", unchecked, "denied")
        if sidecar_dir:
            raise _damaged(file_id, "sidecar", "it is a directory")
        body_removed = False
        body_refusal: tuple[str, _ReadRefusal] | None = None
        in_use: str | None = None
        try:
            body_removed = _unlink_retrying(blob_path)
        except _UnreachableError as exc:
            # The unlink met the share going away, so whether it took is not known.
            unreached = codec_safe_str(exc)
        except OSError as exc:
            # Nothing is removed yet. A Windows sharing violation that outlasted the tries is a
            # handle held open, at least the engine's own read, so it is answered as one a retry
            # may clear, never as access refused. Otherwise a directory is damage, any other
            # permission is denied, a body another remover took is not this call's removal, and
            # any other failure, such as a read-only volume, is raised as it is
            # (:func:`_refused_unlink`). The sidecar is kept, so the upload stays on disk.
            if _in_use(exc):
                in_use = codec_safe_str(exc)
            else:
                unlinked = _refused_unlink(exc, blob_path)
                if unlinked is None:
                    raise
                if unlinked == "unreachable":
                    unreached = codec_safe_str(exc)
                elif unlinked == "gone":
                    _log.warning(
                        "uploaded file %s: its body unlink failed and the body was gone after "
                        "it, so this delete did not remove it: %s",
                        file_id,
                        codec_safe_str(exc),
                    )
                else:
                    body_refusal = (codec_safe_str(exc), unlinked)
        # After the handler, as _refusal requires, so the error is on no chain. A body unlink that
        # met the share going away may have taken effect, so it is answered as unconfirmed, with
        # the metadata, and never as nothing removed.
        if unreached is not None:
            _log.warning(
                "uploaded file %s: its body unlink could not be confirmed, since the uploads "
                "storage could not be reached: %s",
                file_id,
                unreached,
            )
            raise UploadDeleteUnconfirmedError(_STORAGE_UNCONFIRMED, meta)
        if in_use is not None:
            _log.warning(
                "uploaded file %s: its body is in use, so nothing was deleted: %s", file_id, in_use
            )
            raise UploadDeleteIncompleteError(file_id, None)
        if body_refusal is not None:
            raise _refusal(file_id, "body", *body_refusal)
        kept: str | None = None
        sidecar_removed = False
        try:
            sidecar_removed = _unlink_retrying(meta_path)
        except _UnreachableError as exc:
            unreached = codec_safe_str(exc)
        except OSError as exc:
            kept = codec_safe_str(exc)
        removal = UploadRemoval(meta, body_removed, sidecar_removed, sidecar_there)
        if unreached is not None or kept is not None:
            # The sidecar is still there, or cannot be told to be gone, so this is no success: the
            # route records what this call removed, if anything, and answers that a retry finishes
            # it. A share that dropped here is answered as unfinished too, since the body may
            # already be gone.
            _log.warning(
                "uploaded file %s: its sidecar was not deleted%s; delete it again, or remove "
                "the sidecar: %s",
                file_id,
                " after its body was" if body_removed else "",
                unreached if unreached is not None else kept,
            )
            raise UploadDeleteIncompleteError(file_id, removal)
        if not removal.removed_any:
            # Both parts were already gone, as after a delete that raced this one: nothing for
            # this call to report, and no row is owed.
            raise UploadNotFoundError(file_id)
        return removal

    async def reseal_to_active(self) -> ResealResult:
        """Re-seal every uploaded ``(blob, meta)`` pair under the **active** key — the uploads half of
        ``messagefoundry rotate-key`` (BACKLOG #1169, ASVS 11.2.2/11.3.3).

        The store's :meth:`~messagefoundry.store.base.Store.reencrypt_to_active` has covered its
        cipher columns since WP-5; this surface had **no pass of any kind**, so an uploaded file was
        left behind by both transitions the store handles. A first key-enable left it plaintext on
        disk forever, and a key rotation left it under the retired key — which is a data-loss defect
        on its own, because the operator's next step is to drop that key and every upload written
        before the rotation then stops decrypting.

        **The two transitions are not closed the same way, and the difference is deliberate.** The
        store seals legacy plaintext AUTOMATICALLY, in ``_encrypt_existing_rows`` at every keyed open.
        This pass has one caller, ``rotate-key``, so it closes the rotation half automatically and
        the first-key-enable half only when an operator runs that command. **Owner ruling
        2026-09-23:** until then a keyed store REFUSES each plaintext upload on read (fail-closed, like
        ``[backup].allow_unencrypted``), and ``serve`` logs how many are waiting
        (:meth:`warn_if_unsealed`). The engine does not seal them at startup, because a
        whole-directory crypto sweep is unbounded boot-time work over a directory with no batching
        seam.

        Like the store's pass, it rewrites values that are plaintext **or** under a retired key and
        skips values already under the active key (so it is idempotent). **Unlike it, a value no
        configured key opens does not abort the pass (BACKLOG #3181).** It is left as it was and
        counted in ``skipped``, and the pass moves on, so one damaged upload cannot hold back every
        other one. Nothing is dropped, and a non-zero ``skipped`` fails ``rotate-key``, which names
        both causes: a prior key not supplied, or a damaged file. Also mirrors its **limitation**:
        a non-``AesGcmCipher`` (the identity cipher, or a ``vault_transit`` cipher whose DEK never
        enters the heap) rotates nothing and returns zeros, exactly as ``reencrypt_to_active`` does.

        Re-sealing happens at the **cipher** layer — ``encrypt(decrypt(stored))`` over the stored
        string — so a body's base64 envelope is never decoded and the plaintext bytes are never
        reassembled here. Files are processed one at a time and each is rewritten through the same
        atomic temp-and-replace the write path uses. Peak memory is a SMALL MULTIPLE of ``max_bytes``,
        not ``max_bytes`` itself: base64 and the AES-GCM round trip each hold their own copy, so a
        25 MiB upload transiently costs a few hundred MiB. A body already under the active key is
        detected from its first bytes and never read whole. A sidecar, at most
        :data:`_SIDECAR_LIMIT`, is read and decoded whole before it is taken as current, so one
        every reader refuses is never current (BACKLOG #5387).

        **This pass LAUNDERS an unmarked value, and that is the ruled trade, not an oversight.** It
        seals every plaintext file it can, legacy or planted, into a genuine AAD-bound ciphertext,
        after which nothing distinguishes it from a file the engine wrote itself. Unlike the store,
        this surface has no "already sealed" evidence to tell the two apart: new sealed uploads land
        beside legacy plaintext ones for as long as the operator has not run ``rotate-key``. So the
        control is the refusal BEFORE this pass, with its alert and the startup count, plus
        ``sealed_plaintext`` in the result, which the operator can check against that count.

        **It does not seal a plaintext sidecar over a body it did not seal (BACKLOG #2322).** Sealing
        it would list an upload with no usable body, and would seal a planted lone sidecar too. Where
        the body is missing or is not text, no re-run can change that, so the upload is counted in
        ``unsealable`` rather than ``skipped``, and the retention prune removes it at expiry. The
        exception is a sidecar every reader refuses before decrypting, as one past the plaintext
        seal bound: that upload is a skip, also counted in ``refused_sidecars``. The same
        body under a SEALED sidecar is counted in ``body_lost``, also not a skip, and its sidecar is
        re-sealed. **That is a judgment about the body as it is now (BACKLOG #3737):** a missing body
        that comes back under a key retired since then is unreadable, so the command's note tells
        the operator to keep the prior key while one may.

        **Only a regular file is opened (BACKLOG #3737),** no link is followed, and no file larger
        than an upload can be is read whole. See :meth:`_reseal_half`.

        **A root it cannot list sets ``root_missing`` (BACKLOG #4940),** never zero counts.

        Runs entirely off the event loop."""
        return await asyncio.to_thread(self._reseal_to_active_sync)

    def _reseal_to_active_sync(self) -> ResealResult:
        """The blocking half of :meth:`reseal_to_active` (disk + cipher). Caller runs it off-loop."""
        cipher = self._cipher
        if not isinstance(cipher, AesGcmCipher):
            return ResealResult()  # identity / transit cipher — nothing this process can rotate
        try:
            # Listed once, up front, so the one listing is the check: a root that goes away between
            # a separate check and the walk cannot read as zero uploads.
            pairs = list(self._walk_sidecars())
        except OSError as exc:
            _log.warning(
                "uploads root %s could not be listed (%s); no uploaded file was read",
                self._root,
                exc.strerror or type(exc).__name__,
            )
            return ResealResult(root_missing=True)
        if pairs and not os.path.isdir(self._root):
            # The root went after the listing: the BACKLOG #4940 outcome, not N lost bodies.
            _log.warning(
                "uploads root %s is gone after it was listed; no uploaded file was read", self._root
            )
            return ResealResult(root_missing=True)
        gate = _ResealLockCheck(self._root / LOCK_FILE_NAME)
        resealed = skipped = sealed_plaintext = unsealable = body_lost = not_regular = damaged = 0
        refused_sidecars = 0
        for fid, _sidecar in pairs:
            try:
                blob_path, meta_path = self._paths_unfollowed(fid)
            except UploadPathError:
                # Unreachable for an id that passed _FILE_ID_RE — the guard re-checks the same shape.
                # Kept anyway, because `prune_expired` guards its unlink the same way: a path guard
                # this pass skipped would be the one place a bad id reaches the filesystem.
                skipped += 1
                _log.warning("uploaded file %s: skipped, its id fails the path guard", fid)
                continue
            # The sidecar carries the AAD kind "meta"; the body carries "body" (see _encrypt_meta /
            # _encrypt_blob). Body FIRST, as save() writes it: the sidecar is the listing key, and a
            # keyed store refuses a plaintext value (BACKLOG #1169). Sealing the sidecar first would
            # let an interrupted pass list an upload whose body is still refused.
            body = self._reseal_half(cipher, fid, blob_path, "body", gate=gate)
            meta = self._reseal_half(
                cipher, fid, meta_path, "meta", over=(body, blob_path), gate=gate
            )
            if gate.root_gone():
                # The root went before the lock check, which runs before the pass's first write, so
                # nothing was written: the BACKLOG #4940 outcome, as above. _pair_lock logged it.
                return ResealResult(root_missing=True)
            resealed += (body in _WRITTEN) + (meta in _WRITTEN)
            # Once per pair, whichever half failed. A skipped pair counts in sealed_plaintext too
            # when it had a plaintext half sealed (BACKLOG #3240): its sidecar may be sealed
            # already, and then no later run sees any plaintext in it to count.
            sealed_plaintext += _Half.SEALED_PLAINTEXT in (body, meta)
            # One count per pair, the first that holds. UNSEALABLE comes first because a sidecar
            # reports it only over a body no key reads, so nothing of the pair waits on a re-run.
            if meta is _Half.UNSEALABLE:
                unsealable += 1
            elif _Half.SKIPPED in (body, meta) or meta is _Half.REFUSED:
                skipped += 1
                refused_sidecars += meta is _Half.REFUSED
            elif meta is _Half.DAMAGED:
                damaged += 1
            elif _Half.NOT_REGULAR in (body, meta):
                not_regular += 1
            elif body is _Half.LOST:
                body_lost += 1
        if resealed or skipped or unsealable or body_lost or not_regular or damaged:
            _log.info(
                "re-sealed %d uploaded-file value(s) under the active key, sealing %d plaintext "
                "upload(s) (%d upload(s) skipped, %d of them over a sidecar every reader refuses "
                "that may hold a value under a prior key, %d that cannot be sealed, %d whose body "
                "is lost, "
                "%d holding a file that is not regular, %d whose sidecar is blank and every reader "
                "refuses as damaged)",
                resealed,
                sealed_plaintext,
                skipped,
                refused_sidecars,
                unsealable,
                body_lost,
                not_regular,
                damaged,
            )
        return ResealResult(
            resealed=resealed,
            skipped=skipped,
            sealed_plaintext=sealed_plaintext,
            unsealable=unsealable,
            body_lost=body_lost,
            not_regular=not_regular,
            damaged=damaged,
            refused_sidecars=refused_sidecars,
        )

    @staticmethod
    def _damaged_meta(fid: str) -> _Half:
        """Log and answer a sidecar that provably holds nothing (BACKLOG #5387 added item 1): read
        in full within :data:`_SIDECAR_LIMIT`, it is empty, or only the byte-order mark and
        whitespace a reader skips. Every reader refuses it as damaged, and no value under any key
        is in it, so it is not a skip, which would fail every later run and hold the rotation
        record open for good. It is left as it is. This is the only sidecar the pass reports as
        damaged."""
        _log.warning(
            "uploaded file %s (meta): left as it is for good, it is blank; every read refuses it "
            "as damaged",
            fid,
        )
        return _Half.DAMAGED

    @staticmethod
    def _refused_meta(fid: str, cause: str) -> _Half:
        """Answer a sidecar every reader refuses before decrypting, as over :data:`_SIDECAR_LIMIT`,
        not UTF-8, or plaintext too long to seal (BACKLOG #5387). It is a skip, whatever it holds.
        Padding, a stray byte, a re-encoding or text around it may hide a whole value sealed under
        a PRIOR key, which a repair recovers with that key, and the pass neither decrypts it nor
        looks inside it for a marker to rule that out: a bounded read cannot see all of an oversized file, and a
        marker test is defeated by at least a cut at the read bound, stripped padding and UTF-16.
        So retiring the prior key is never reported safe while one is on disk. A sidecar that the
        readers decode is not one of these: a prior-key value behind a stray prefix that still
        decodes as UTF-8, such as a BOM-less UTF-16 re-save, reads as plaintext and is sealed,
        within the plaintext bound. ``cause`` names the refusal."""
        _log.warning(
            "uploaded file %s (meta): skipped, %s, so it could not be used and may hold a value "
            "under a prior key; do not retire that key until it is fixed or deliberately removed",
            fid,
            cause,
        )
        return _Half.REFUSED

    def _reseal_half(
        self,
        cipher: AesGcmCipher,
        fid: str,
        path: Path,
        kind: Literal["body", "meta"],
        *,
        over: tuple[_Half, Path] | None = None,
        gate: _ResealLockCheck,
    ) -> _Half:
        """Re-seal one half of upload ``fid`` and say what became of it. A sidecar passes ``over``,
        the body half's result and its path, because a plaintext sidecar is sealed only over a body
        that was. Re-binding the SAME cell AAD is what keeps a re-sealed value readable.

        ``lstat`` decides what is opened (BACKLOG #3737). A FIFO would block the open for good.
        Anything that is neither a regular file nor a symlink holds no value, so it is reported and
        left alone, and it is not a skip, like a missing body. A symlink is not followed, because that would re-seal or read a
        file this store does not own. It is a skip, because its target may be a real upload still
        under the prior key. That check guards against what is on disk when it looks, not against
        a writer racing it.

        **The write never re-creates a removed file (BACKLOG #3181 item 5).** ``rotate-key`` refuses
        a held store only on SQLite, so an engine on a server store can delete an upload while this
        runs, and a plain replace brought the sidecar back. The replace now happens under
        :func:`_pair_lock`, only while the path is still the file this ``lstat`` saw. ``gate`` is the
        pass's one pair-lock check, made at the first half that needs a write. When it failed (the
        lock was busy, refused or timed out, taking it failed, or the root was gone), each half that
        needs a write is a skip before it is decrypted. A write that finds the uploads root
        gone, or the lock not to be had, is a skip too."""
        try:
            info = path.lstat()
            if S_ISLNK(info.st_mode):
                _log.warning(
                    "uploaded file %s (%s): skipped, it is a symlink and was not followed",
                    fid,
                    kind,
                )
                return _Half.SKIPPED
            if not _is_regular(info):
                _log.warning("uploaded file %s (%s): not a file; left as it is", fid, kind)
                return _Half.NOT_REGULAR
            # For a body, read the MARKER first, not the file. The idempotency test is a prefix
            # compare, and a sealed 25 MiB upload is ~44 MiB on disk — reading it whole only to
            # skip it made a re-run cost a full pass over every already-current file. The store's
            # own passes push this filter into SQL (`WHERE col NOT LIKE ...`) for the same reason;
            # on a filesystem the equivalent is a bounded read. So an already-current body is
            # never size-checked: a lowered max_upload_bytes must not turn one into a skip. A
            # sidecar is size-checked first and decoded whole before it is taken as current
            # (BACKLOG #5387), since every reader refuses one over the cap or not UTF-8, whatever
            # its marker.
            #
            # Opened by _open_plain (BACKLOG #5387 added item 1), so a link or FIFO swapped in
            # after the lstat above is refused, a skip as an unreadable file is, and the marker,
            # the size and the text all come from the one file that was opened.
            active = cipher.active_marker_prefix.encode("ascii")
            handle, opened = _open_plain(path)
            with handle:
                limit = _SIDECAR_LIMIT if kind == "meta" else self._stored_limit
                # A sidecar over the cap is refused before the marker test, since every reader
                # refuses it whatever its marker. A body is not: a lowered max_upload_bytes must
                # not turn an already-current one into a skip.
                if kind == "meta" and opened.st_size > limit:
                    return self._refused_meta(fid, f"{opened.st_size} bytes is over the cap")
                head = handle.read(len(active))
                if head == active and kind == "body":
                    return _Half.CURRENT  # already under the active key in the active format
                size = opened.st_size
                if size <= limit:
                    # Sized by the fstat, as _read_plain_text is, so no read allocates the whole
                    # limit for a small file. One that grew since is read only to one byte past
                    # its limit, and refused below, never read whole (BACKLOG #3737).
                    # Never negative: a file that grew may have given a head longer than its fstat.
                    data = head + handle.read(max(size + 1 - len(head), 0))
                    if len(data) > size:
                        data += handle.read(limit + 1 - len(data))
                    size = len(data)
                if kind == "meta" and size > limit:
                    return self._refused_meta(fid, f"{size} bytes is over the cap")
                if size > limit:
                    # BACKLOG #3737: a read of the whole file could raise MemoryError, which no
                    # handler takes, so a planted one would abort the pass. A skip and not a loss:
                    # it may be a real body from before a lowered max_upload_bytes, still under the
                    # prior key.
                    _log.warning(
                        "uploaded file %s (%s): skipped, %d bytes is larger than an upload can be. "
                        "If it is a real upload, raise [store].max_upload_bytes for this run",
                        fid,
                        kind,
                        size,
                    )
                    return _Half.SKIPPED
                try:
                    stored = data.decode("utf-8")
                except UnicodeDecodeError:
                    if kind == "meta":
                        return self._refused_meta(fid, "it is not UTF-8")
                    raise
                if head == active:
                    # A sidecar is small, so it is decoded before this test: one that starts with
                    # the active marker and is not UTF-8 past it is refused by every reader, so it
                    # is a skip above, never current (BACKLOG #5387).
                    return _Half.CURRENT
                del data  # free the raw copy before the decrypt and the encrypt make two more
            if kind == "meta":
                # As the reader unpads it, so a sealed sidecar that gained a byte-order mark or
                # whitespace is re-sealed, never sealed a second time as plaintext (BACKLOG #5387
                # added item 1).
                stored = _unpadded(stored)
                if not stored:
                    return self._damaged_meta(fid)
            plaintext = bool(stored) and not stored.startswith(MARKER_PREFIX)
            if kind == "meta" and _too_long_to_seal(stored):
                # Checked before the body's outcome is weighed, because every reader refuses it
                # before decrypting (_read_sidecar), so it is a skip over any body, a lost one too.
                return self._refused_meta(fid, "it is plaintext too long to seal")
        except (OSError, UnicodeDecodeError) as exc:
            # Only an absent body is missing, and only when a fresh lstat says its final name is
            # gone (_known_absent): a share that cannot be reached raises a FileNotFoundError too
            # on Windows, with no winerror on a read, as does a missing folder or drive above the
            # name, and that body may still be under the OLD key, so it is a skip below, never a
            # lost one a re-run would not count (BACKLOG #5388).
            missing = (
                kind == "body"
                and isinstance(exc, OSError)
                and is_absent(exc)
                and _known_absent(path)
            )
            if kind == "body" and (missing or isinstance(exc, UnicodeDecodeError)):
                # BACKLOG #3181: the body is missing or is not text, so no key reads it and no
                # re-run changes that. It holds nothing under the OLD key, so it is not a skip;
                # counting one would fail every later run for good. The sidecar is still handled,
                # as the unsealable kind when it is plaintext.
                _log.warning(
                    "uploaded file %s (body): missing or not text; no key can read it", fid
                )
                return _Half.LOST
            # An unreadable file. Counted and named, never silent: this file may still be under
            # the OLD key and the operator must not retire it yet.
            _log.warning(
                "uploaded file %s (%s): skipped, unreadable: %s", fid, kind, codec_safe_str(exc)
            )
            return _Half.SKIPPED
        if plaintext and over is not None:
            body, blob = over
            # BACKLOG #2322: the body was not sealed, so a PLAINTEXT sidecar stays as it is. A keyed
            # store refuses it, so the upload is unlisted; sealing it would list an upload whose body
            # is unusable, and would seal a planted lone sidecar too. A sidecar under a retired key
            # is listed already, so it is still re-sealed: left behind, it would drop out of reach of
            # prune_expired once that key goes.
            if body is _Half.NOT_REGULAR:
                return _Half.NOT_REGULAR  # left as it is, for the same reason as its body
            # The body is missing or is not text: the one test the prune and the quota use too.
            # Asked of a CURRENT body, because that pass trusts a body whose first bytes are the
            # active marker without reading the rest. Every other body was read whole just now.
            if body is _Half.LOST or (
                body is _Half.CURRENT and self._lost_body_size(blob) is not None
            ):
                # No key reads either half and no re-run changes that, so it is not a skip. It
                # stays refused, and the prune removes it at expiry.
                _log.warning(
                    "uploaded file %s (meta): left unsealed for good, its body is missing or is "
                    "not text; retention removes it when it expires",
                    fid,
                )
                return _Half.UNSEALABLE
            if body is _Half.SKIPPED:
                _log.warning("uploaded file %s (meta): left unsealed, its body was not", fid)
                return _Half.SKIPPED
        blocked = gate.check()
        if blocked == "gone":
            # Not a skip: the pass ends as root_missing once this pair is done, and _pair_lock
            # logged the gone directory.
            return _Half.SKIPPED
        if blocked is not None:
            _log.warning(
                "uploaded file %s (%s): skipped, nothing is written: %s",
                fid,
                kind,
                _RESEAL_BLOCKED[blocked],
            )
            return _Half.SKIPPED
        try:
            sealed = _reencrypt_value(cipher, stored, cell_aad("uploaded_file", kind, fid))
        except _UnopenableValueError:
            # It could not be decrypted. Nothing is written, so the file is left exactly as it was,
            # and it is a skip, which fails the command and leaves the rotation record open (BACKLOG
            # #3181, #3737). One bad upload used to abort the whole pass, and the CLI then blamed a
            # missing prior key for what may be one damaged file. An encrypt-side refusal is not
            # caught here and still aborts. The cipher's own message is not logged: a malformed
            # marker's key id is cut from the stored text up to the next ':', so it can carry a
            # piece of a damaged or planted file. _unopened_cause names the cause without that.
            _log.warning(
                "uploaded file %s (%s): skipped, it could not be decrypted: %s",
                fid,
                kind,
                _unopened_cause(cipher, stored),
            )
            return _Half.SKIPPED
        del stored  # the write holds its own copy, so free this file-sized buffer before it
        if kind == "meta" and len(sealed.encode("utf-8")) > _SIDECAR_LIMIT:
            # A backstop (BACKLOG #5387 added item 1): a plaintext sidecar this would grow past the
            # cap was a skip above, as REFUSED, so this is a sealed one whose re-seal grew it. The
            # readers refuse a sidecar this long as damaged, so it is not written. It is still
            # under the prior key, so it is a skip: retiring that key would lose it.
            _log.warning(
                "uploaded file %s (meta): skipped, sealed it would be larger than a sidecar can be",
                fid,
            )
            return _Half.SKIPPED
        try:
            _atomic_write_text(self._root, path, sealed, seen=info)
        except _ChangedUnderReseal as changed:
            # BACKLOG #3181 item 5: a running engine removed or replaced it after the read. Nothing
            # is written, so a deleted pair stays deleted. A removed body is a lost one, as at the
            # read; anything else is a skip, as a sidecar gone at the read is. That is also what
            # an unmounted volume looks like, so it must never read as done.
            if changed.gone and kind == "body":
                _log.warning(
                    "uploaded file %s (body): removed while this pass ran; not re-created", fid
                )
                return _Half.LOST
            _log.warning(
                "uploaded file %s (%s): skipped, it was %s while this pass ran, so nothing was "
                "written over it or in its place; re-run to confirm",
                fid,
                kind,
                changed,
            )
            return _Half.SKIPPED
        except (_PairLockFailed, OSError) as exc:
            # The lock's failure is read as _pair_lock logged it, never classified again: a root
            # that came back in between would make the two disagree.
            if isinstance(exc, _PairLockFailed):
                gone = exc.kind == "gone"
                exc = exc.cause
            else:
                gone = _root_gone(exc, self._root)
            if gone:
                # The target's own absence is _ChangedUnderReseal. Its error would name the lock
                # file when the root went before the lock's open, so this half's warning does not
                # give it as the cause.
                _log.warning(
                    "uploaded file %s (%s): skipped, could not be written: the uploads directory "
                    "is gone",
                    fid,
                    kind,
                )
                return _Half.SKIPPED
            # The write failed and the temp-and-replace left the file as it was. A skip, like a read
            # failure, so one file that cannot be written does not stop the pass.
            _log.warning(
                "uploaded file %s (%s): skipped, could not be written: %s",
                fid,
                kind,
                codec_safe_str(exc),
            )
            return _Half.SKIPPED
        return _Half.SEALED_PLAINTEXT if plaintext else _Half.RESEALED

    async def warn_if_unsealed(self) -> int:
        """Log, once at ``serve`` startup, how many uploads a keyed store holds as plaintext.

        Owner ruling 2026-09-23 (BACKLOG #1169): each one is refused on read until an operator runs
        ``rotate-key``, and nothing else would tell the operator they exist, because a refused file
        simply drops out of the listing. So this logs the COUNT at WARNING with that instruction, and
        never names a file: the filename inside a sidecar can carry PHI, and the count is all the
        operator needs. Returns the count. Returns 0 without logging where the refusal does not apply
        (see :attr:`_passes_unmarked`).

        **An upload ``rotate-key`` cannot seal is counted apart, on a line of its own (BACKLOG
        #2322).** Telling the operator to run a command that can never seal it would be false, so
        that line says what does remove it. It is not in the returned count, which is the number
        ``rotate-key`` should report as sealed.

        The cost is one directory walk, a read of at most a marker's length from each body, and a
        read of each sidecar whole, up to :data:`_SIDECAR_LIMIT`, since its byte-order mark and
        whitespace are skipped as the reader skips them (BACKLOG #5387 added item 1). A sidecar
        every reader refuses as oversized, blank, not UTF-8 or plaintext too long to seal is never
        itself counted, nor counted as one ``rotate-key`` cannot seal, but its upload is counted by
        its body, which ``rotate-key`` seals under it (:meth:`_count_unsealed_sync`). Then, for each upload with a PLAINTEXT sidecar, or with a plaintext body under
        a sidecar that is not, a read of its whole body, to tell the two kinds apart, or to count
        only a body ``rotate-key`` can seal. That body read is new work
        at startup, bounded by the plaintext uploads still waiting for ``rotate-key``, and the first quota scan or prune after it does not repeat it
        (``_body_checks``). Runs off the event loop. **The body read is whole on purpose (BACKLOG
        #3183).** One byte that is not UTF-8, anywhere in it, makes an upload one ``rotate-key``
        cannot seal, so a prefix cannot decide it. Each read is bounded by the size an upload can
        be (:meth:`_lost_body_size`), and the result is cached. The cost is startup time, since
        ``serve`` awaits this before the API answers, and it lasts only while plaintext uploads
        wait for ``rotate-key``. Where the store refuses plaintext, the first save's quota scan
        would otherwise make the same reads under ``_quota_lock``."""
        cipher = self._cipher
        if not isinstance(cipher, AesGcmCipher):  # the same test as _passes_unmarked
            return 0
        try:
            count, unsealable = await asyncio.to_thread(self._count_unsealed_sync)
        except OSError as exc:
            # The directory itself could not be walked. A startup notice must never stop serve; the
            # listing scan will hit and name the same fault.
            _log.warning("uploaded-logs: could not count plaintext uploads at startup: %s", exc)
            return 0
        if count:
            what = (
                "served as plaintext, because [store].allow_unmarked_ciphertext is on"
                if cipher.allow_unmarked
                else "refused on every read"
            )
            _log.warning(
                "uploaded-logs: %d uploaded file(s) are stored as plaintext on this keyed store and "
                "are %s. Run 'messagefoundry rotate-key' with the engine stopped to seal them "
                "(BACKLOG #1169)",
                count,
                what,
            )
        if unsealable:
            _log.warning(
                "uploaded-logs: %d uploaded file(s) have a plaintext sidecar over a body that is "
                "missing or is not text. rotate-key cannot seal them. The retention prune removes "
                "them once they expire (BACKLOG #2322)",
                unsealable,
            )
        return count

    def _seals_whole(self, body: Path) -> bool:
        """Whether ``rotate-key`` would seal plaintext body ``body``: a regular file no larger than
        :attr:`_stored_limit` that decodes to its end (:meth:`_lost_body_size`)."""
        try:
            info = body.lstat()
        except OSError:
            return False
        if not _is_regular(info) or info.st_size > self._stored_limit:
            return False
        return self._lost_body_size(body) is None

    def _count_unsealed_sync(self) -> tuple[int, int]:
        """How many uploads have a non-blank half with no ``mfenc:`` marker, as two counts: those
        ``rotate-key`` can seal, and those it cannot (:meth:`_unsealable_sync`). Reads the first
        ``len(MARKER_PREFIX)`` characters of each body, and of each sidecar past its byte-order
        mark and whitespace, reading no more of a sidecar than :data:`_SIDECAR_LIMIT`. Each file is
        opened by :func:`_open_plain`, so a link is not followed and a FIFO does not block startup.
        A file that cannot be read is not counted here; the listing scan names it on its own. The
        sidecar is read first. One every reader refuses before decrypting, as oversized, blank,
        not UTF-8 or plaintext too long to seal, is never itself counted, since ``rotate-key``
        skips it or, when it is blank, leaves it as it is (``damaged``). Nor is its upload ever
        counted as one ``rotate-key`` cannot seal, since that pass reports none of these kinds as
        ``unsealable``. Its upload is still counted by its body, as under a sealed sidecar,
        because ``rotate-key`` seals a plaintext body under each of those kinds, so the count
        matches that pass's ``sealed_plaintext`` over every one of them (BACKLOG #5387). A
        plaintext body under a sidecar that is not plaintext is counted only when it is a regular
        file no larger than a body can be that decodes to its end (:meth:`_seals_whole`), as
        ``rotate-key`` seals only such a body. A body this scan cannot open for its head, such as
        one whose permission denies it, is not counted. One whose head it reads but whose whole read
        then fails for another cause is still counted, since :meth:`_lost_body_size` answers
        ``None`` for it, though that pass skips it."""
        count = unsealable = 0
        for fid, sidecar in self._iter_sidecars():
            try:
                body, meta = self._paths(fid)
            except UploadPathError:
                continue
            held: bool | None = None  # the class check's answer, once it has been asked
            for path in (meta, body):
                try:
                    if path is meta:
                        # The reader's padding is skipped, so a padded sealed sidecar is not
                        # counted as plaintext (BACKLOG #5387 added item 1).
                        head = _unpadded(_read_sidecar(path))
                        head = head[: len(MARKER_PREFIX)]
                    else:
                        handle, _ = _open_plain(path)
                        with io.TextIOWrapper(handle, encoding="utf-8") as text_handle:
                            head = text_handle.read(len(MARKER_PREFIX))
                except (_OversizedFileError, UnicodeDecodeError):
                    # rotate-key skips such a sidecar and leaves a blank one as it is, so neither
                    # is ever one it cannot seal (BACKLOG #5387). It still seals the body under
                    # each, so the body is counted as under a sealed sidecar, by _seals_whole.
                    if path is meta:
                        held = False
                    continue
                except (OSError, _MalformedSidecarError):
                    continue
                if path is meta and not head:
                    held = False  # blank: as above
                    continue
                if head and head != MARKER_PREFIX:
                    if held is None:
                        held = self._unsealable_sync(fid, sidecar) is not None
                    if held:
                        unsealable += 1
                    elif path is meta or self._seals_whole(path):
                        # A plaintext body is counted only when rotate-key would seal it: text to
                        # its end, and no larger than a body can be, since that pass counts one not
                        # text as lost and skips one too large.
                        count += 1
                    break  # count the upload once, whichever half is plaintext
        return count, unsealable

    async def prune_expired(
        self,
        *,
        now: float | None = None,
        retention_days: int | None = None,
        abort: threading.Event | None = None,
        tally: _SweepTally | None = None,
        audit: Callable[[UploadedFileMeta], Awaitable[None]] | None = None,
    ) -> PruneResult:
        """Age-based retention sweep (ASVS 5.2.4): delete every (blob, meta) pair whose ``uploaded_at`` is
        older than ``retention_days`` (default: the configured ``retention_days``), then sweep the write
        leftovers no other pass can reach. Returns a :class:`PruneResult` — the pruned metadata rows (for
        the ``upload.prune`` audit: ``file_id`` + ``uploader`` only, never content) plus the orphan count.

        Idempotent: a re-run finds the already-deleted pairs gone and returns an empty pass.
        Sidecars the cipher declines are skipped (never pruned — a rotated-away key must not silently
        destroy data). One exception is an upload ``rotate-key`` can never seal (BACKLOG #2322):
        it is pruned once its sidecar's mtime passes the cutoff, and is reported with blank owner
        fields (:class:`_UnsealableUpload`). Another is a sidecar refused as damaged, which the
        cipher did not decline (BACKLOG #5387, #5388), aged as :meth:`_aged_on_disk_sync` says, reported
        the same way and logged as such. A sound sidecar whose ``uploaded_at`` is more than a day
        ahead of ``now`` is aged the same way, by its pair's age on disk and never by an mtime
        ahead of the clock, since that stamp alone would never age out; it is reported with its own
        metadata and logged as such. Runs off the event loop; the periodic runner + the
        opportunistic save-time sweep both drive it. A save wakes the runner, and sweeps itself only
        where none is running (:meth:`wake_retention`).

        A pair is reported only when this pass removed its body, the PHI the audit row is about. A
        refused body unlink leaves the whole pair for the next pass; a refused sidecar unlink leaves
        a sidecar the next pass clears without a second report.

        ``abort`` stops the pass early without losing track of what it already deleted (BACKLOG #2065;
        :meth:`UploadRetentionRunner.stop` says why cancelling is not enough). The pass checks it before
        the scan and before each pair, then skips the orphan sweep and returns the pairs it did delete.
        A pair is never half-deleted by an abort.

        ``tally`` records, as the pass goes, each pair it removes and the pair it is removing. The
        retention runner uses it to name the files a timed-out stop loses (:class:`_SweepTally`).

        **``audit`` is called for each pair right after its removal, before the next pair is
        touched (BACKLOG #3184).** The pass used to delete every due pair, then sweep the orphans,
        and only then write the rows, so a stop that timed out mid-pass lost the row of every pair
        removed so far. Now a timed-out stop loses at most the pair in progress and its row. Each
        pair is removed in its own worker-thread call, so the rows are written on the event loop
        between them, and a cancellation stops the pass at the pair in progress. A failed ``audit``
        call is logged and the pass goes on, so one bad row never costs the others. ``tally``
        counts each call once it returns or raises."""
        days = self._retention_days if retention_days is None else max(1, int(retention_days))
        at = time.time() if now is None else now
        cutoff = at - days * _SECONDS_PER_DAY

        stop = abort if abort is not None else threading.Event()
        sweep = tally if tally is not None else _SweepTally()
        # The due uploads aged by their age on disk, with why, which the pass logs.
        by_disk: dict[str, str] = {}

        def _due() -> list[UploadedFileMeta]:
            # Checked before the scan too: the scan decrypts every sidecar, which is wasted on a stop.
            if stop.is_set():
                return []
            held: list[_UnsealableUpload] = []
            broken: list[_UnsealableUpload] = []
            metas = self._scan_metas_sync(held, damaged=broken)
            due: list[UploadedFileMeta] = []
            for meta in metas:
                if meta.uploaded_at <= at + _SECONDS_PER_DAY:
                    if meta.uploaded_at < cutoff:
                        due.append(meta)
                    continue
                # A stamp this far ahead is not one this clock wrote, so it alone would never age
                # out (BACKLOG #5387). It may be a genuine upload after a clock step-back, so it is
                # still listed and billed, and aged here by the pair's age on disk instead.
                on_disk = self._aged_on_disk_sync(meta.file_id)
                if on_disk is not None and on_disk.modified < cutoff:
                    due.append(meta)
                    by_disk[meta.file_id] = "whose uploaded_at is ahead of the clock"
            # An upload rotate-key cannot seal ages by its sidecar's mtime (BACKLOG #2322), and one
            # whose sidecar is damaged by its pair's mtimes (BACKLOG #5387, #5388).
            aged = [lost for lost in held if lost.expired(cutoff, at)]
            for lost in broken:
                # By the cutoff alone, never by an mtime ahead of the clock, so a pair written
                # before a clock was stepped back waits for wall time.
                if lost.modified < cutoff:
                    aged.append(lost)
                    by_disk[lost.file_id] = "whose sidecar was refused"
            return due + [lost.as_meta() for lost in aged]

        def _remove(meta: UploadedFileMeta) -> bool | None:
            """Remove one due pair; ``None`` when the pass was stopped before it."""
            if not sweep.begin(meta, stop):
                return None
            removed = False
            try:
                removed = self._prune_pair_sync(meta)
            finally:
                sweep.end(removed)
            # Logged once the pair is gone, a lone sidecar's included, which writes no audit row,
            # so the log is that removal's only record. It says why the stamp was not used.
            why = by_disk.get(meta.file_id)
            if why is not None and (
                removed or not os.path.lexists(self._paths_unfollowed(meta.file_id)[1])
            ):
                _log.warning(
                    "uploaded-logs prune took %s, %s, by its age on disk", meta.file_id, why
                )
            return removed

        def _orphans() -> int:
            # A failure here must not raise out of the pass: that would drop `pruned` (BACKLOG
            # #2261). ERROR, as the runner logged this before the catch moved here.
            try:
                return self._sweep_orphans_sync(now=at, abort=stop)
            except Exception:  # noqa: BLE001 — logged; a raise would drop the pass's result
                _log.exception("uploaded-logs orphan sweep failed; will retry next pass")
                return 0

        for meta in await asyncio.to_thread(_due):
            removed = await asyncio.to_thread(_remove, meta)
            if removed is None:
                break
            if removed and audit is not None:
                try:
                    await audit(meta)
                except Exception:  # noqa: BLE001 — logged; one bad row must not cost the rest
                    # ERROR: the file is gone and this was its only record, the level every other
                    # upload.prune audit gap logs at.
                    _log.exception(
                        "uploaded-logs prune audit failed for %s; it has no upload.prune audit row",
                        meta.file_id,
                    )
                sweep.audited += 1
        pruned = list(sweep.removed)
        if stop.is_set():
            return PruneResult(pruned=pruned)
        # The orphan sweep runs AFTER the deletions and their rows.
        return PruneResult(pruned=pruned, orphans_removed=await asyncio.to_thread(_orphans))

    def _prune_pair_sync(self, meta: UploadedFileMeta) -> bool:
        """Remove one aged pair for :meth:`prune_expired`; True when THIS call removed its body.

        Never raises: a raise would drop the pass's list, and with it the audit rows for every
        pair already deleted. ``_paths`` resolves the path, which can touch the filesystem, so an
        ``OSError`` there leaves the pair for the next pass like a refused unlink does."""
        # A sidecar whose id fails the path guard, or whose pair holds a link, is left alone (never
        # blindly unlinked) and named, so an operator can remove it (BACKLOG #5552). The id is cut
        # short: the scan's ids are the path's own (BACKLOG #5387), but a caller may pass any.
        try:
            blob_path, meta_path = self._paths(meta.file_id)
        except UploadPathError:
            if self._link_logged.first(f"prune {meta.file_id[:40]}"):
                _log.warning(
                    "uploaded-logs prune left %r for an operator: its id fails the path guard or "
                    "its pair holds a link",
                    meta.file_id[:40],
                )
            return False
        except OSError as exc:
            _log.warning("uploaded-logs prune left %s for the next pass: %s", meta.file_id, exc)
            return False
        # Under the pair lock, so a rotate-key re-seal cannot put either half back (BACKLOG
        # #3181 item 5).
        with _pair_lock(meta_path):
            # The BODY goes first, and a pair is reported exactly when THIS pass removed its body,
            # because the body is the PHI the audit row records the deletion of. Sidecar-first
            # reported a pair whose body unlink was refused and left the body on disk, and it
            # opened a window where a body with no sidecar is exactly what a concurrent pass's
            # orphan sweep takes. Body-first keeps the sidecar in place until the body is gone,
            # so the orphan sweep never sees a pair mid-prune. A body already gone was removed,
            # and reported, by an earlier or overlapping pass (the save-time sweep and the runner
            # can overlap), so only its leftover sidecar is cleared, with no second report.
            removed_before = False
            try:
                blob_path.unlink()
            except OSError as exc:
                # Only an absent body was removed before. One whose share cannot be reached raises
                # a FileNotFoundError too on Windows, and its sidecar is kept (BACKLOG #5388).
                if not is_absent(exc):
                    _log.warning(
                        "uploaded-logs prune left %s for the next pass: %s", meta.file_id, exc
                    )
                    return False
                removed_before = True
            if removed_before:
                try:
                    _unlink_retrying(meta_path)
                except OSError as exc:
                    # Logged, never swallowed; the next pass finds the body gone again.
                    _log.warning(
                        "uploaded-logs prune could not clear the leftover sidecar of %s; the next "
                        "pass will try again: %s",
                        meta.file_id,
                        exc,
                    )
                return False
            # A refused sidecar unlink leaves a sidecar with no body. The next pass finds the
            # body gone and clears the sidecar without reporting the pair again.
            try:
                # An absent sidecar is fine; one whose share cannot be reached is logged here
                # rather than read as gone (BACKLOG #5388).
                _unlink_retrying(meta_path)
            except OSError as exc:
                _log.warning(
                    "uploaded-logs prune removed the body of %s but not its sidecar; the next "
                    "pass will clear it: %s",
                    meta.file_id,
                    exc,
                )
            return True

    async def prune_on_save(
        self, audit: Callable[[UploadedFileMeta], Awaitable[None]]
    ) -> PruneResult:
        """The save-time sweep: an audited :meth:`prune_expired` that a cancelled caller cannot cut
        short (BACKLOG #2261). The upload route runs it only where no retention runner is running
        to wake instead (:meth:`wake_retention`, BACKLOG #3184).

        The request deadline cancels the upload route, and a cancel used to drop the result naming
        what the sweep's thread had deleted, so no ``upload.prune`` row was written for those files.
        The thread kept deleting with nobody left to audit it. This is the retention runner's
        treatment (#2065): a cancel sets the sweep's ``abort``, so it stops at its next file, and
        the rows for what it removed are still written. See :meth:`_run_to_completion` for the wait.

        A sweep that then fails, or that shutdown cancels, is logged as the retention runner's stop
        logs one, from a :class:`_SweepTally`: an ERROR naming each removed file with no row yet,
        or a WARNING when no row is lost (BACKLOG #2264)."""
        abort = threading.Event()
        tally = _SweepTally()

        def _late(task: asyncio.Future[Any]) -> None:
            if task.cancelled():
                why = "was cancelled before it finished"
            elif task.exception() is not None:
                why = "failed after its request was cancelled"
            else:
                return
            _log_unaudited(
                f"the save-time upload prune {why}",
                tally,
                exc=None if task.cancelled() else task.exception(),
            )

        return await self._run_to_completion(
            self.prune_expired(audit=audit, abort=abort, tally=tally),
            what="the save-time upload prune",
            on_cancel=lambda: tally.abort(abort),
            on_late=_late,
        )

    async def _run_to_completion[T](
        self,
        coro: Coroutine[Any, Any, T],
        *,
        what: str = "a task run to completion",
        on_cancel: Callable[[], None] | None = None,
        on_late: Callable[[asyncio.Future[Any]], None] | None = None,
        held: bool = False,
    ) -> T:
        """Run ``coro`` as its own task, so a cancellation of the caller does not cut it short.

        With ``held``, the task is held from the start rather than only once its caller is
        cancelled, so the shutdown drain waits for it, and cancels it, while its caller still
        waits, and ``on_late`` is given the finished task whatever its caller did (:meth:`discard`).

        The task is outside the caller's cancel scope, so the request deadline does not reach its
        awaits. A cancelled caller calls ``on_cancel`` first, then waits up to
        ``_LEDGER_CANCEL_WAIT_SECONDS`` for the task, then the cancellation propagates. A task
        still running at that bound is logged, naming it by ``what``, and held until it finishes.
        Once the caller is cancelled, ``on_late`` is given the finished task, since the
        cancellation is what propagates and nothing else reads its outcome; without one, a failure
        is logged at ERROR. Without a cancellation, the task's result or exception is the caller's.

        The task itself can be cancelled too, by a loop shutdown, while its caller is not. That
        surfaces here as the same ``CancelledError``, so ``on_cancel`` runs again on this path: a
        sweep's thread outlives its task, and must still be told to stop."""
        task = asyncio.create_task(coro)
        late = on_late or functools.partial(_log_late_failure, what=what)
        if held:
            self._hold(task, late)
        try:
            return await _wait_to_completion(
                task, cancel_bound=_LEDGER_CANCEL_WAIT_SECONDS, on_cancel=on_cancel
            )
        except asyncio.CancelledError:
            if on_cancel is not None:
                on_cancel()  # idempotent; covers a cancel of the task itself (see above)
            if not task.done():
                _log.warning(
                    "%s did not finish within %gs of its caller's cancellation; it was left running",
                    what,
                    _LEDGER_CANCEL_WAIT_SECONDS,
                )
            if not held:
                self._hold(task, late)
            raise

    def _sweep_orphans_sync(self, *, now: float, abort: threading.Event | None = None) -> int:
        """Remove the write leftovers no other pass can reach, and return how many went (BACKLOG #1678).

        Two shapes, which this pass reads as a write that started and never landed: a
        ``.<id>.<suffix>.<tag>.tmp`` whose ``os.replace`` never ran, and an ``<id>.blob`` whose
        sidecar was never written. Neither is reachable through :meth:`_walk_sidecars`, which
        yields ``.meta`` names only, so :meth:`list_files`, :meth:`prune_expired` and
        :meth:`reseal_to_active` all walk straight past them: a partial body would otherwise sit in
        the uploads root for the life of the directory, outside the retention window this module
        promises, and (under a configured key) as ciphertext ``rotate-key`` would never re-seal.

        **This pass UNLINKS, so it refuses any name that does not match one of its two shapes.** A
        name matching neither is treated as an operator's own file and is never touched, the same way
        :meth:`_iter_sidecars` skips it. A ``.blob`` whose sidecar exists but cannot be DECRYPTED is
        kept, because this pass checks that the sidecar's name exists without opening it — a
        rotated-away key can no more destroy data here than it can in the age pass.

        **A fault whose code does not mean a missing name keeps the body (BACKLOG #6575).** The root
        is listed once, whole, before anything is removed. A listing error
        :func:`~messagefoundry.path_reach.is_absent` reads as no root is an empty pass, and any
        other raises with nothing removed. A body the listing shows with no sidecar goes only once
        it is past the floor and :func:`_sidecar_is_absent`, asked right before the unlink, reports
        the sidecar not there.

        **That report is the file system's answer, not proof that no sidecar exists.**
        :func:`~messagefoundry.path_reach.is_name_absent` states its limits, at least a POSIX
        missing parent, a stale client cache and the unmeasured Access-Based Enumeration case. Any
        of them can send a body whose sidecar still exists to the unlink. The check narrows the
        race with a sidecar landing after the listing and does not close it: one can land between
        that check and the unlink. Neither that check nor the unlink holds :func:`_pair_lock`.

        **The floor reads an mtime, which proves less than "abandoned".** ``stat`` follows a link,
        so a new link to an old file is past the floor the moment it appears, as is a body restored
        with its mtime preserved. With no sidecar reported, that name is unlinked. The mtime is
        the stamp the file system recorded, and it is compared with this host's clock. Which clock
        stamped it can differ by file system and is not asserted here.

        A fault on one entry leaves that entry for the next pass. If the root then fails a ``stat``
        too, the pass stops and returns what it removed, logged at ERROR with the root's own error.
        :class:`_OncePerInterval` damps only a repeat inside its interval, and the default pass
        interval is as long, so a lasting fault can log on every scheduled pass.

        **A live write in THIS process is safe by IDENTITY, not by age.** ``_inflight_names`` holds
        every name a write in this process currently holds, and a held name is skipped outright, so
        the threshold never adjudicates a race this process can see. ``_ORPHAN_MIN_AGE_SECONDS`` is
        the floor for everything else. A file the registry cannot see can come from at least a
        process that DIED mid-write (an in-process failure, cancellation included, removes its own
        temp, though that unlink suppresses ``OSError`` and can leave one behind), a sibling engine shard sharing this ``uploads_dir``, or a restore.

        **A sibling shard's stalled write is a residual, in at least two forms.**
        ``_inflight_names`` does not reach another process, so the floor, and for a body the sidecar
        re-check, are what stand between this pass and a write stalled past it. On Windows an open
        handle can also block the unlink. The first form covers a ``save``'s temp and a stalled
        ``rotate-key`` re-seal's temp, which share the temp shape. Stalled before a temp's ``os.replace``, it can have that temp removed underneath
        it: the ``os.replace`` then raises. A ``save`` fails and the operator retries; a re-seal is not a
        save, it fails in ``_replace_if_unchanged`` and is handled as a skipped half. Nothing is
        published half-written either way. Stalled after its body landed and before its
        sidecar did, it can LOSE THE BODY: this pass sees a body past the floor with no sidecar and
        unlinks it, with no audit row, and the ``save`` then publishes the sidecar and reports
        success for an upload with no body. ``max_bytes``, 25 MiB by default, bounds a write's size
        and not how long it can stall, so an hour is a margin against this and not a bar to it.

        ``abort`` is :meth:`prune_expired`'s. It is checked before the listing and before each entry
        once the listing has been read, so a slow sweep over a large dir does not hold a stop past
        its bound while it removes files (BACKLOG #2264). It is not seen during the listing:
        ``Path.iterdir`` reads the whole directory before it returns on this Python, so a stop set
        meanwhile takes effect when that read ends. The pass's audit rows are already written when
        this runs (BACKLOG #3184). An aborted sweep returns what it removed so far; the next one
        resumes."""
        stop = abort if abort is not None else threading.Event()
        root = self._root
        if stop.is_set():
            return 0
        cutoff = now - _ORPHAN_MIN_AGE_SECONDS
        # The one listing, read whole before anything goes, so a failure at any point removes
        # nothing. An error is_absent reads as no root ends the pass at 0, and any other raises;
        # prune_expired logs that and keeps its result (BACKLOG #6575).
        try:
            entries = list(root.iterdir())
        except OSError as exc:
            if is_absent(exc):
                return 0  # read as no root yet, as a lost drive or parent also is
            raise
        # A sidecar is the listing key, so an id with one is reachable and this pass is not about it.
        names = {entry.name for entry in entries}
        removed = 0
        for entry in entries:
            if stop.is_set():
                break
            name = entry.name
            stem = name[: -len(_BLOB_SUFFIX)] if name.endswith(_BLOB_SUFFIX) else ""
            sidecar: Path | None = None
            if _ORPHAN_TMP_RE.match(name):
                kind = "temp file"
            elif _FILE_ID_RE.match(stem):
                sidecar_name = f"{stem}{_META_SUFFIX}"
                if sidecar_name in names:
                    continue
                sidecar = root / sidecar_name
                kind = "body with no sidecar"
            else:
                continue  # not one of ours — never touched
            if _is_inflight(name):
                continue  # a write in this process is holding it right now
            try:
                if entry.stat().st_mtime > cutoff:
                    continue  # inside the floor; being past it does not prove it abandoned
                # The listing is a snapshot and a share can return a short one with no error, so
                # ask again, last, before the unlink.
                if sidecar is not None and not _sidecar_is_absent(sidecar):
                    continue
                entry.unlink()
            except OSError as exc:
                if (root_fault := _root_fault(root)) is not None:
                    _log.log(
                        logging.ERROR
                        if self._link_logged.first("orphan sweep stopped")
                        else logging.DEBUG,
                        "uploaded-logs orphan sweep stopped at %s: the uploads root stopped "
                        "answering (%s); no further file was removed and the next pass retries",
                        name,
                        root_fault,
                    )
                    break
                # Already gone (a sibling shard's sweep), held open by another process, or not a file
                # at all. Never fatal — the next pass retries. The NAME is safe to log: a file_id and
                # a random tag, never a body. What is_name_absent does not read as gone is logged,
                # since a body whose sidecar cannot be checked is left for a later pass, which unlinks it
                # if the fault has cleared and the sidecar still reads as absent. A dangling
                # link can read as gone too, since the stat follows it: on POSIX with any part of
                # its target missing, and on Windows with only the target's last part missing.
                quiet = is_name_absent(exc) or not self._link_logged.first(f"orphan sweep {name}")
                _log.log(
                    logging.DEBUG if quiet else logging.WARNING,
                    "uploaded-logs orphan sweep left %s alone: %s",
                    name,
                    exc.strerror or type(exc).__name__,
                )
                continue
            removed += 1
            # ASCII only in the message itself: a stock Windows cp1252 console raises
            # UnicodeEncodeError on the em dashes this module's prose uses freely.
            # A temp is removed with no sidecar check, so only a body's text says one read as absent.
            _log.warning(
                "uploaded-logs orphan sweep removed %s %s: past the age floor%s",
                kind,
                name,
                "" if sidecar is None else ", and its sidecar read as absent",
            )
        return removed


# One prune sweep per hour is ample for a day-granularity retention window (a save wakes the runner
# for the between-ticks case, UploadStore.wake_retention), and it keeps the background wakeups
# negligible.
_DEFAULT_PRUNE_INTERVAL_SECONDS = 3600.0

# How long ``UploadRetentionRunner.stop`` waits for a sweep already in flight to finish and write its
# audit rows. The sweep stops at its next file once asked, so this bounds a hung filesystem call, a
# sidecar scan already under way, and the audit writes for what the sweep had deleted. The runner
# stops FIRST in the API lifespan's teardown, and engine.stop() still has to run after it. It is an
# upper limit: that teardown passes ``stop(timeout=...)`` a share of the step's bound in one shutdown
# budget (``_SHUTDOWN_BUDGET_SECONDS`` in ``api/app.py``, BACKLOG #3191), which is shorter.
#
# It shares NSSM's 15 s graceful-stop window (AppStopMethodConsole in
# scripts/service/install-service.ps1) with uvicorn's connection drain, which runs BEFORE the
# lifespan teardown. ``serve`` bounds that drain with ``timeout_graceful_shutdown``
# (``__main__._UVICORN_DRAIN_SECONDS``, BACKLOG #3256), so a request still open at Ctrl+C can no
# longer use up the window before this wait starts. Since the sweep writes each row as it goes
# (BACKLOG #3184), a stop that runs out loses at most the pair in progress.
_DEFAULT_STOP_TIMEOUT_SECONDS = 5.0


@dataclass
class _SweepTally:
    """How far one sweep got. Two readers: :meth:`UploadRetentionRunner.stop` when it times out,
    and :meth:`UploadStore.prune_on_save` when a sweep its request stopped waiting for is cancelled
    or fails. Both read it through :func:`_log_unaudited`.

    ``removed`` lists each pair the sweep's thread removed, in the order it is audited, and
    ``removing`` is the pair it is removing now. ``audited`` counts audit calls that returned or
    raised; a raised call is counted because :meth:`UploadStore.prune_expired` already logs it.
    So ``unaudited()`` names every removed file whose row has not been written. It also names the
    pair in progress, which may turn out not to be removed, and a row whose interrupted write may
    still land, so it can name more than are lost, never fewer.

    The abort check and the ``removing`` mark are one step under ``lock``, and so is the stop's
    ``abort.set()``. A thread that passed the check is therefore already visible to the stop.
    Each sweep, the runner's and the save-time one alike, gets its own tally, so a thread a
    timed-out stop left running never writes into the next sweep's."""

    lock: threading.Lock = field(default_factory=threading.Lock)
    removed: list[UploadedFileMeta] = field(default_factory=list)
    removing: UploadedFileMeta | None = None
    audited: int = 0

    def begin(self, meta: UploadedFileMeta, abort: threading.Event) -> bool:
        """In the sweep's thread: mark ``meta`` as being removed, unless ``abort`` is set."""
        with self.lock:
            if abort.is_set():
                return False
            self.removing = meta
            return True

    def end(self, removed: bool) -> None:
        """In the sweep's thread: the pair :meth:`begin` marked is settled."""
        with self.lock:
            if removed and self.removing is not None:
                self.removed.append(self.removing)
            self.removing = None

    def abort(self, abort: threading.Event) -> None:
        """Set ``abort`` so that no :meth:`begin` straddles it."""
        with self.lock:
            abort.set()

    def unaudited(self) -> list[str]:
        """The ``file_id`` of each removed, or being removed, file with no audit row yet."""
        with self.lock:
            ids = [m.file_id for m in self.removed[self.audited :]]
            if self.removing is not None:
                ids.append(self.removing.file_id)
            return ids


class UploadRetentionRunner:
    """Periodically prunes aged uploaded files (ASVS 5.2.4). Modelled on
    :class:`~messagefoundry.pipeline.cert_expiry.CertExpiryRunner`: an injected clock + an ``await``-able
    :meth:`run_once` make a single pass deterministically testable; the loop only governs cadence. An
    optional ``audit`` callback records one row per pruned file (``file_id`` + ``uploader``, never
    content) — injected so this leaf module never imports the store. Owned by the API lifespan where the
    :class:`UploadStore` is built (started after the engine, stopped in the shutdown ``finally``)."""

    def __init__(
        self,
        store: UploadStore,
        *,
        interval_seconds: float = _DEFAULT_PRUNE_INTERVAL_SECONDS,
        audit: Callable[[UploadedFileMeta], Awaitable[None]] | None = None,
        clock: Callable[[], float] = time.time,
        stop_timeout_seconds: float = _DEFAULT_STOP_TIMEOUT_SECONDS,
    ) -> None:
        self._store = store
        self._interval = float(interval_seconds)
        self._audit = audit
        self._clock = clock
        self._stop_timeout = float(stop_timeout_seconds)
        self._stop = asyncio.Event()
        # Set by stop() and by wake(): either ends the wait between sweeps (BACKLOG #3184).
        self._kick = asyncio.Event()
        # The sweep's worker thread reads this one; an asyncio.Event is not thread-safe.
        self._abort = threading.Event()
        self._task: asyncio.Task[None] | None = None
        self._tally = _SweepTally()  # the sweep in flight, or the last one

    def start(self) -> None:
        """Spawn the supervised prune loop (idempotent), and bind it as the store's
        :meth:`UploadStore.wake_retention`."""
        if self._task is not None:
            return
        # A fresh event, not a clear(), for the same reason as _abort below: a loop a stop() is
        # still waiting on holds the old one, and clearing it would keep that loop sweeping beside
        # the new one, each replacing the tally the other's stop() reads.
        self._stop = asyncio.Event()
        self._kick = asyncio.Event()
        # A fresh event, not a clear(): a sweep thread a timed-out stop() left running still holds
        # the old one, and clearing it would let that thread resume deleting with nobody to audit.
        self._abort = threading.Event()
        self._task = asyncio.create_task(self._run(self._stop, self._kick))
        self._store.bind_retention_wake(self.wake)
        _log.info(
            "uploaded-logs retention prune enabled: older than %d days, every %gs",
            self._store.retention_days,
            self._interval,
        )

    async def stop(self, timeout: float | None = None) -> None:
        """Signal the loop and await its exit, audit rows included (idempotent).

        **The loop is asked to stop, not cancelled (BACKLOG #2065).** A sweep deletes files in a
        worker thread, and cancelling the task that awaits it leaves the thread deleting while the
        result naming those files is dropped, so no ``upload.prune`` row is ever written for them.
        Instead the sweep is told to stop at its next file, and this waits for it to return and for
        its audit rows to land, up to ``stop_timeout_seconds``, or ``timeout`` when that is shorter.
        A caller with a shutdown budget of its own passes ``timeout``, so this wait ends, and cancels
        the sweep, before the caller cuts it.

        A sweep can outlast that bound: one stuck filesystem call, the sidecar scan or orphan sweep
        already under way, or one stuck audit write. The task is then cancelled. The sweep writes
        each pair's row before it touches the next pair (BACKLOG #3184), so at most the pair in
        progress has no row. When the sweep had started deleting a file it had not yet audited, that
        loss is logged as an ERROR, naming the file. A sweep that had no such file loses no row, so
        it is logged as a WARNING instead.

        This never raises into the caller's teardown. If the caller is itself cancelled while
        waiting, the sweep is cancelled the same way and this returns, as it did before #2065, so the
        API lifespan's later steps, ``engine.stop()`` among them, still run."""
        self._stop.set()
        self._kick.set()
        self._store.unbind_retention_wake(self.wake)  # an upload sweeps for itself again
        task = self._task
        self._task = None
        if task is None:
            return
        # Stop the sweep in flight, which holds THIS event, then give the runner a fresh one. Left
        # set, it made every later run_once() prune nothing, silently. The tally is kept in a local:
        # a start() during the wait below replaces self._tally with the next sweep's.
        tally = self._tally
        tally.abort(self._abort)
        self._abort = threading.Event()
        wait = self._stop_timeout if timeout is None else min(self._stop_timeout, timeout)
        try:
            # shield: a timeout must not cancel the task mid-audit; the branches below decide that.
            await asyncio.wait_for(asyncio.shield(task), wait)
            return
        except TimeoutError:
            why = f"did not finish within {wait:g}s of shutdown"
        except asyncio.CancelledError:
            why = "was still running when shutdown itself was cancelled"
        # Read before the cancel. Every id is logged, since these lines are the only record of them.
        if self._audit is None:
            _log.warning(
                "uploaded-logs retention sweep %s; cancelling it. The runner has no audit "
                "callback, so it owed no upload.prune row",
                why,
            )
        else:
            _log_unaudited(f"uploaded-logs retention sweep {why}; cancelling it", tally)
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    def wake(self) -> bool:
        """Start the next sweep now rather than at the end of the interval (BACKLOG #3184), and
        return whether the loop is running. A wake during a sweep starts one more sweep after it.
        ``False``, doing nothing, when the loop is not running, including one that ended without a
        :meth:`stop`."""
        task = self._task
        if task is None or task.done():
            return False
        self._kick.set()
        return True

    async def _run(self, stop: asyncio.Event, kick: asyncio.Event) -> None:
        # One isolated sweep per interval or wake; an error in a pass is logged and the loop
        # continues (a prune must never take the engine down). Cooperatively cancellable via
        # ``stop``, this loop's own, which stop() pairs with a kick so the wait ends at once.
        while not stop.is_set():
            # Cleared before the sweep, so a wake that lands during it is kept for the next one.
            kick.clear()
            try:
                # The loop's sweep alone owns self._tally, so a direct run_once() never hides it.
                self._tally = _SweepTally()
                await self._sweep(self._tally)
            except Exception:
                _log.exception("uploaded-logs retention prune failed; will retry next interval")
            try:  # noqa: SIM105 — a stop or a wake ends the wait; only the interval times out
                await asyncio.wait_for(kick.wait(), self._interval)
            except TimeoutError:
                pass

    async def run_once(self, now: float | None = None) -> PruneResult:
        """One audited :meth:`UploadStore.prune_expired` pass for ``now`` (default: the injected
        clock). The pass's orphan count rides back in the result; it is logged by the sweep and
        carries no metadata to audit (see :class:`PruneResult`)."""
        return await self._sweep(None, now)

    async def _sweep(self, tally: _SweepTally | None, now: float | None = None) -> PruneResult:
        return await self._store.prune_expired(
            audit=self._audit,
            now=self._clock() if now is None else now,
            abort=self._abort,
            tally=tally,
        )


class _UnopenableValueError(CipherError):
    """A stored upload value could not be decrypted. The reseal skips that file and goes on (BACKLOG
    #3181). Raised only from the DECRYPT half of :func:`_reencrypt_value`, so an encrypt-side refusal,
    such as the AES-GCM invocation ceiling, still stops the whole pass as a plain ``CipherError``."""


def _reencrypt_value(cipher: AesGcmCipher, stored: str, aad: bytes) -> str:
    """Decrypt (keyring — any configured key) then re-encrypt under the active key, rebinding the
    SAME cell AAD (ASVS 11.3.3).

    Deliberately named to match ``MessageStore._reencrypt_value`` and its Postgres and SQL Server
    twins, which are the identical computation for the database half. They are four spellings of one
    seam and folding them into ``store/crypto.py`` is worth doing — but those three are staticmethods
    on store classes this LEAF module may not import (see the module docstring), so the shared name
    is what keeps a grep for ``_reencrypt_value`` from missing this one. Pairing a decrypt and an
    encrypt with different AADs is the mistake the single-expression form exists to prevent."""
    # allow_unmarked=True: the one pass that reads a plaintext upload, because sealing it is the
    # whole point. Owner ruling 2026-09-23 (BACKLOG #1169): a keyed store refuses a plaintext
    # upload on every read path until `rotate-key` runs this pass.
    try:
        opened = cipher.decrypt(stored, aad=aad, allow_unmarked=True)
    except CipherError as exc:
        raise _UnopenableValueError(str(exc)) from exc
    return cipher.encrypt(opened, aad=aad)


def _unopened_cause(cipher: AesGcmCipher, stored: str) -> str:
    """Why no key opened ``stored``, for the log, telling a key to supply from a damaged file
    (BACKLOG #3737). It reads only the marker. :meth:`AesGcmCipher.named_key_id` passes only the
    shape of a whole key id, so a planted value of that shape does reach the log, and any other
    text does not. Only the head of ``stored`` is passed, because parsing a marker copies what follows it, and that
    can be a whole upload."""
    head = stored[:_MARKER_READ_LIMIT]
    key_id = cipher.named_key_id(head)
    if key_id is None:
        return (
            "its marker names no key id this cipher reads. A prior key not supplied may still "
            "open it, or it is damaged, planted or sealed by another cipher"
        )
    if cipher.holds_key_for(head):
        return f"key {key_id} is configured and did not open it, so it is damaged or was moved"
    return f"key {key_id} is not configured; supply it, unless the value is damaged"


async def _to_thread_to_completion[T, A](func: Callable[[A], T], arg: A) -> T:
    """``asyncio.to_thread``, except that a cancellation waits for the thread to finish first.

    A bare ``to_thread`` re-raises a cancellation at once while its thread keeps running. ``save``
    then pays its engine-shard reservation back and drops ``_quota_lock`` while the file is still
    being written, so a sibling can read the ledger and scan the disk and count neither. That breaks
    the premise :class:`UploadQuotaError`'s ordering argument rests on. The save's thread runs the
    quota's sidecar scan and then the write. The write is bounded by ``max_bytes``. The scan is
    bounded by the number of sidecars in the dir, which per-uploader quotas cap for each uploader
    but nothing caps overall. The wait is as long as both. Further cancellations while waiting are
    absorbed, and a ``CancelledError`` is raised once the thread is done.

    The wait is on the executor's own Future, never on a Task wrapping ``to_thread``. ``asyncio.run``
    cancels every pending TASK at shutdown, so a Task here would be cancelled out from under the
    wait and end it early. A plain Future is not in ``asyncio.all_tasks()``, and nothing else holds
    it, so only the thread finishing can complete it."""
    return await _wait_to_completion(_submit_to_thread(func, arg))


def _submit_to_thread[T, A](
    func: Callable[[A], T], arg: A, *, executor: Executor | None = None
) -> asyncio.Future[T]:
    """Start ``func(arg)`` on ``executor``, the default one when ``None``, as ``asyncio.to_thread``
    would, and return the executor's own Future rather than a Task
    (:func:`_to_thread_to_completion` says why)."""
    ctx = contextvars.copy_context()  # what to_thread passes to the thread, kept the same
    return asyncio.get_running_loop().run_in_executor(executor, ctx.run, func, arg)


def _log_late_failure(task: asyncio.Future[Any], *, what: str) -> None:
    """Log the failure of a :meth:`UploadStore._run_to_completion` task whose caller was cancelled
    and passed no ``on_late``, since nothing else will read it. A cancelled task (shutdown) is
    logged too, since it stopped short of what it was run to finish."""
    if task.cancelled():
        _log.error("%s was cancelled after its caller was cancelled", what)
    elif (exc := task.exception()) is not None:
        _log.error("%s failed after its caller was cancelled", what, exc_info=exc)


# How many file_ids one audit-gap line names. A first sweep after a long outage can remove
# thousands of pairs, and one line that long is handled badly by log shippers and NSSM's rotated
# stdout. Every id is still logged, over as many lines as it takes: those lines are their only record.
_UNAUDITED_IDS_PER_LINE = 50


def _log_unaudited(what: str, tally: _SweepTally, *, exc: BaseException | None = None) -> None:
    """Log what a sweep that stopped short of its audit rows lost, from its ``tally`` (BACKLOG
    #2264). An ERROR names each removed file with no row yet, :data:`_UNAUDITED_IDS_PER_LINE` to a
    line; a sweep that lost no row logs a WARNING. ``what`` says what happened to the sweep."""
    lost = tally.unaudited()
    if not lost:
        _log.warning(
            "%s. It had removed no aged pair it had not audited, so no upload.prune row is lost",
            what,
            exc_info=exc,
        )
        return
    for first in range(0, len(lost), _UNAUDITED_IDS_PER_LINE):
        chunk = lost[first : first + _UNAUDITED_IDS_PER_LINE]
        # An audit write the cancel interrupts may still land, so "may".
        _log.error(
            "%s. %d file(s) it removed, or was removing, may have no upload.prune audit row "
            "(%d to %d): %s",
            what,
            len(lost),
            first + 1,
            first + len(chunk),
            ", ".join(chunk),
            exc_info=exc if first == 0 else None,
        )


async def _release_reservation(
    ledger: UploadQuotaLedger, reservation: str, uploader_id: str
) -> None:
    """Release ``reservation`` on ``ledger``. The log sits inside the task, so a failure is reported
    in this module's words whether or not anyone still waits, and the task never ends in an error
    of its own; a release failure must not fail an upload that landed."""
    try:
        await ledger.release_upload_quota(uploader_id=uploader_id, reservation_id=reservation)
    except Exception:  # noqa: BLE001 — logged; the slot is reclaimed once it goes stale
        _log.warning(
            "could not release the engine-shard upload reservation for %s; it will be "
            "reclaimed when it goes stale",
            uploader_id,
            exc_info=True,
        )


def _log_discard_unfinished(done: asyncio.Future[Any], file_id: str) -> None:
    """Name a removal of an unrecorded pair that did not finish (vault BACKLOG #3178). The log
    names the ``file_id`` only, because the filename can carry PHI."""
    if done.cancelled():
        _log.error(
            "upload %s has no upload.create audit row and its removal was cancelled before it "
            "finished; the file may still be stored",
            file_id,
        )
    elif (exc := done.exception()) is not None:
        _log.error(
            "upload %s has no upload.create audit row and its removal failed; the file may "
            "still be stored",
            file_id,
            exc_info=exc,
        )


def _log_release_cancelled(done: asyncio.Future[Any], uploader_id: str) -> None:
    """Name a release that was cancelled before it finished; its slot then goes stale."""
    if done.cancelled():
        _log.warning(
            "the engine-shard upload release for %s was cancelled before it finished; its slot is "
            "reclaimed once it goes stale",
            uploader_id,
        )


async def _wait_to_completion[T](
    fut: asyncio.Future[T],
    *,
    cancel_bound: float | Callable[[], float] | None = None,
    on_cancel: Callable[[], None] | None = None,
) -> T:
    """Await ``fut``; on a cancellation, wait for it to finish, then raise ``CancelledError``.

    The shared body of :func:`_to_thread_to_completion` and the engine-shard ledger calls (BACKLOG
    #2263). Further cancellations while waiting are absorbed. A ledger call is a coroutine, so it
    runs as a Task, and ``asyncio.run``'s shutdown cancellation can still end it early. That
    leaves the reservation as a killed process would.

    The wait is ``asyncio.wait``, never ``asyncio.shield``. Once its caller is cancelled, shield
    reports a later failure of ``fut`` to the loop's exception handler at ERROR, so a failure the
    caller already logs is logged twice.

    ``cancel_bound`` limits the wait after a cancellation, in seconds; ``None`` waits as long as it
    takes, which the save's thread needs, since a thread cannot be stopped. A ledger call waits on
    the store, which may not be bounded at all. At the bound this raises with ``fut`` still
    running, and the caller decides what to do with it. Under an anyio scope, the scope cancels
    again on every loop pass, so the wait costs CPU, and the bound limits that too. A callable
    bound is read when the cancellation arrives, for a caller whose bound is the time some other
    wait has left (BACKLOG #3157); one at or below zero raises at once.

    **A caller already cancelled at entry gets the bound as well.** That is a ``finally`` running
    after an earlier wait absorbed the cancellation: the release after a cancelled write. Without
    this, a plain asyncio cancel used up by the write would leave the release unbounded. Such a
    caller gets the result when ``fut`` finishes in time, since a cancellation is already on its
    way out."""
    loop = asyncio.get_running_loop()
    task = asyncio.current_task()
    already = task is not None and task.cancelling() > 0
    cancelled = False

    def _deadline() -> float | None:
        if cancel_bound is None:
            return None
        return loop.time() + (cancel_bound() if callable(cancel_bound) else cancel_bound)

    deadline = _deadline() if already else None
    if already and on_cancel is not None:
        on_cancel()  # the caller is already on its way out, so ask the work to stop now
    while not fut.done():
        remaining = None if deadline is None else deadline - loop.time()
        if remaining is not None and remaining <= 0:
            raise asyncio.CancelledError
        try:
            await asyncio.wait((fut,), timeout=remaining)
        except asyncio.CancelledError:
            if not (cancelled or already):
                deadline = _deadline()
            if not (cancelled or already) and on_cancel is not None:
                on_cancel()  # once, at the first cancellation: a sweep's abort (BACKLOG #2261)
            cancelled = True
    if cancelled:
        if not fut.cancelled():
            fut.exception()  # mark it retrieved; the caller reads the outcome off `fut` itself
        raise asyncio.CancelledError
    return fut.result()


class _PairLockBusy(TimeoutError):
    """``edit_lock``'s ``busy_error`` for the pair lock: another holder kept it past the wait."""


type _PairLockFailure = Literal["busy", "gone", "timeout", "refused", "failed"]


def _not_a_file_errnos(platform: str) -> frozenset[int]:
    """What opening the lock path raises on ``platform`` when something planted there is not a
    regular file. ``EISDIR``: a directory. ``ENXIO``: a socket, on Linux. On macOS and the BSDs,
    ``EOPNOTSUPP`` is a socket and ``EFTYPE`` is a link that ``O_NOFOLLOW`` refused, as NetBSD
    reports one; ``EMLINK`` is such a link on FreeBSD and DragonFly. Never on Linux, where
    ``EOPNOTSUPP`` comes from a FUSE or 9p mount, not a planted file."""
    codes = {errno.EISDIR, errno.ENXIO}
    if platform.startswith(("darwin", "freebsd", "openbsd", "netbsd", "dragonfly")):
        codes.add(errno.EOPNOTSUPP)
        eftype = getattr(errno, "EFTYPE", None)
        if eftype is not None:
            codes.add(eftype)
    if platform.startswith(("freebsd", "dragonfly")):
        codes.add(errno.EMLINK)
    return frozenset(codes)


#: Like a planted link, a planted directory or socket is a refusal, so the engine logs it at ERROR
#: with the advice to remove it.
_NOT_A_FILE = _not_a_file_errnos(sys.platform)


def _root_gone(exc: OSError, root: Path) -> bool:
    """Whether ``exc`` is a ``FileNotFoundError`` or ``NotADirectoryError`` while the uploads root
    ``root`` is no directory, as when it is missing or was replaced by a file, and not one from
    under a root still there. ``os.path.isdir`` follows links, so a root that is a link to a
    missing target is gone too."""
    return isinstance(exc, FileNotFoundError | NotADirectoryError) and not os.path.isdir(root)


def _lock_name(path: Path) -> str:
    """The pair lock file for ``path``, as it is logged and as ``_unlocked_logged`` keys it."""
    return scrub_log_argument(str(lock_path_for(path)))


def _pair_lock_failure(exc: OSError, root: Path) -> _PairLockFailure:
    """Why :func:`_pair_lock` could not take the lock in the uploads root ``root``. ``busy``:
    another holder kept it past the wait. ``gone``: a ``FileNotFoundError`` or
    ``NotADirectoryError`` while the root is no directory (:func:`_root_gone`).
    ``timeout``: the OS timed out (``ETIMEDOUT``), as a network file system can. ``refused``:
    the file system refused this account (``atomic_edit._REFUSED``), such as a lock file another
    account owns; a ``_PairLockBusy`` with a cause is one too, as is what ``_NOT_A_FILE`` names,
    and a ``FileNotFoundError`` while ``root`` is there. ``failed``: any other error, such as
    ``EIO`` or ``ESTALE`` from a network file system."""
    if isinstance(exc, _PairLockBusy):
        return "refused" if exc.__cause__ is not None else "busy"
    if _root_gone(exc, root):
        return "gone"
    if isinstance(exc, FileNotFoundError):
        return "refused"
    if isinstance(exc, TimeoutError):
        return "timeout"
    if exc.errno in _REFUSED or exc.errno in _NOT_A_FILE:
        return "refused"
    return "failed"


class _PairLockFailed(Exception):
    """What :func:`_pair_lock` raises for the re-seal when it cannot take the lock: ``kind`` is the
    failure it classified and logged, and ``cause`` is the error. The caller reads ``kind`` rather
    than classifying ``cause`` again, since a root that went or came back in between would make the
    two disagree."""

    def __init__(self, kind: _PairLockFailure, cause: OSError) -> None:
        super().__init__(kind, cause)
        self.kind: _PairLockFailure = kind
        self.cause = cause


class _ResealLockCheck:
    """The re-seal pass's one pair-lock check in the uploads root, made at the first half that
    needs a write and remembered for the rest of the pass. Finding a lock it cannot take per half
    would decrypt and re-encrypt each upload first, then wait out the lock for each write, so once
    it fails every half that needs a write is a skip and nothing is written. A pass in which every
    half is already current takes no lock."""

    def __init__(self, lock: Path) -> None:
        self._lock = lock
        self._checked = False
        self.failure: _PairLockFailure | None = None

    def root_gone(self) -> bool:
        """Whether the check ran and found the uploads root gone."""
        return self.failure == "gone"

    def check(self) -> _PairLockFailure | None:
        """Take and release the lock the first time, and return why that failed, or None."""
        if not self._checked:
            # Marked checked only once the attempt ends in a lock taken or a _PairLockFailed. Any
            # other exception propagates and leaves it unchecked, so it never reads as success.
            try:
                with _pair_lock(self._lock, for_reseal=True):
                    pass
            except _PairLockFailed as failed:
                self.failure = failed.kind
            self._checked = True
        return self.failure


#: What a busy pair lock tells the ``rotate-key`` operator to do.
_RERUN_WHEN_FREE = "re-run rotate-key once whatever holds the lock releases it"

#: What a re-seal half skipped for a failed first pair-lock check logs as the cause.
_RESEAL_BLOCKED: dict[_PairLockFailure, str] = {
    "busy": f"the uploads pair lock was still held when the wait ran out; {_RERUN_WHEN_FREE}",
    "timeout": "the file system timed out taking the uploads pair lock",
    "refused": "the uploads pair lock could not be taken",
    "failed": "the file system failed taking the uploads pair lock",
    "gone": "the uploads directory was gone at the pair-lock check",
}


# The lock files whose refusal an engine removal has logged at ERROR since this process last took
# them, so a lock that stays refused is one ERROR, not one per pair on every prune pass. Taking the
# lock clears its entry, so a refusal that comes back gets its ERROR again.
_unlocked_logged: set[str] = set()
_unlocked_logged_lock = threading.Lock()


@contextlib.contextmanager
def _pair_lock(path: Path, *, for_reseal: bool = False) -> Iterator[None]:
    """The cross-process lock over the pairs in ``path``'s directory, the uploads root (BACKLOG
    #3181 item 5). Blocking, so call it off the event loop; re-entrant in one thread.

    The engine's removals of a pair (:meth:`UploadStore.delete`, the retention prune and a discard)
    hold it across their unlinks, and ``rotate-key``'s re-seal holds it across the check that the
    file it read is still there and the rename that replaces it (:func:`_replace_if_unchanged`). So
    while both hold it, a pair an engine removes while ``rotate-key`` runs is not re-created by the
    re-seal, on any store backend: the re-seal either replaces the file before the removal takes the
    lock, and the removal then takes the new file away, or finds it gone and writes nothing.
    ``rotate-key`` is a separate process, so ``_quota_lock`` cannot do this. At least these leave
    the re-seal's check and rename unguarded: a file system that cannot lock, where both sides go on
    unlocked with a WARNING (:func:`~messagefoundry.config.atomic_edit.edit_lock`), and an engine
    removal that could not take the lock, below. The orphan sweep and a save's own cleanup do not
    take it. Both aim at files the re-seal does not walk, a temp or a body with no sidecar, but the
    sweep's sidecar check and unlink run outside this lock, so it orders neither against a re-seal.
    A sidecar that check misses (:meth:`UploadStore._sweep_orphans_sync`) would have the sweep
    remove the body of a pair the re-seal walks, and a re-seal past its own check could then put
    that body back.

    **A lock the engine cannot take does not stop it removing uploads.** Retention and delete must
    not depend on a file anyone who can write the uploads directory can plant, so the removal goes
    on unlocked. A refusal is logged at ERROR, naming the lock file and the likely cause: a lock
    file another account created, as when ``rotate-key`` ran as root or as an administrator. While
    it lasts, each later refusal of that lock file is logged at DEBUG; once this process takes the
    lock again, the next refusal is an ERROR again. A lock whose directory is gone is not logged:
    there is nothing left to remove. A lock still held when the wait runs out is not a refusal: it
    is logged at WARNING each time, with ``edit_lock``'s own reason, and never uses up that ERROR.
    Nor is an OS timeout, which is logged at WARNING each time as a timeout, nor any other error
    that is not a refusal, which is logged at WARNING each time, naming the error
    (:func:`_pair_lock_failure`).
    **The re-seal fails closed (``for_reseal``):** a lock it cannot take is logged and raised as
    :class:`_PairLockFailed`, carrying the failure it was logged as. At the pass's first check that
    stops every write; at a half's write, that half is a skip."""
    with contextlib.ExitStack() as held:
        try:
            _refuse_a_planted_link(lock_path_for(path))
            held.enter_context(
                edit_lock(path, busy_error=_PairLockBusy, timeout=_PAIR_LOCK_TIMEOUT_SECONDS)
            )
        except OSError as exc:
            lock = _lock_name(path)
            failure = _pair_lock_failure(exc, lock_path_for(path).parent)
            consequence = (
                "rotate-key skips each file it would write under it"
                if for_reseal
                else "This removal goes on without it, so a rotate-key run meanwhile could "
                "re-create the removed upload"
            )
            if failure == "busy":
                _log.warning(
                    "uploaded-logs pair lock: %s. %s%s",
                    codec_safe_str(exc),
                    consequence,
                    f"; {_RERUN_WHEN_FREE}" if for_reseal else "",
                )
            elif failure in ("timeout", "failed"):
                _log.warning(
                    "uploaded-logs pair lock %s: the file system %s taking it (%s: %s). %s",
                    lock,
                    "timed out" if failure == "timeout" else "failed",
                    type(exc).__name__,
                    codec_safe_str(exc),
                    consequence,
                )
            elif failure == "gone":
                if for_reseal:
                    _log.warning(
                        "rotate-key could not open the uploads pair lock %s: its directory is gone",
                        lock,
                    )
            elif for_reseal:
                _log.error(
                    "rotate-key could not take the uploads pair lock %s (%s), so it writes no "
                    "uploaded file while it cannot. Run rotate-key as the account the engine runs "
                    "as. If another account owns the lock file, or it is not a regular file, "
                    "delete it while neither the engine nor rotate-key runs",
                    lock,
                    codec_safe_str(exc),
                )
            else:
                with _unlocked_logged_lock:
                    first = lock not in _unlocked_logged
                    _unlocked_logged.add(lock)
                _log.log(
                    logging.ERROR if first else logging.DEBUG,
                    "uploaded-logs pair lock %s could not be taken (%s), so uploads are removed "
                    "without it, and a rotate-key run meanwhile could re-create a removed upload. "
                    "If another account owns it, as when rotate-key ran as root or an "
                    "administrator, give it to the engine's service account; if it is not a "
                    "regular file, remove it. Until this process takes the lock again, later "
                    "refusals of it are logged at DEBUG",
                    lock,
                    codec_safe_str(exc),
                )
            if for_reseal:
                raise _PairLockFailed(failure, exc) from exc
        else:
            if _unlocked_logged:
                with _unlocked_logged_lock:
                    _unlocked_logged.discard(_lock_name(path))
        yield


#: The reparse-tag bit of a Windows reparse point that names another path, such as a symbolic
#: link or a junction (``IO_REPARSE_TAG_NAME_SURROGATE``), as ``pipeline/dr_backup.py`` tests it. A
#: cloud-files, dedup or tiering placeholder lacks it and names no other path.
_NAME_SURROGATE_TAG = 0x20000000


def _refuse_a_planted_link(lock: Path) -> None:
    """Refuse the pair lock file ``lock`` before ``edit_lock`` opens it when it is a symbolic link
    or a name-surrogate reparse point: raises :class:`_PairLockBusy` chained from an
    ``ELOOP``, the shape ``edit_lock`` gives a link its ``O_NOFOLLOW`` open refuses, so
    :func:`_pair_lock_failure` reads it as a refusal. Windows has no ``O_NOFOLLOW``, so there
    ``edit_lock`` follows a planted link and creates or locks its target. A link planted after this
    ``lstat`` and before that open is still followed there. A missing lock path is left to
    ``edit_lock``; any other ``lstat`` error is raised as it is."""
    try:
        info = lock.lstat()
    except FileNotFoundError:
        return  # edit_lock creates it, or fails and _pair_lock classifies and logs why
    # Any other lstat error propagates, so _pair_lock classifies and logs it as it would the open's,
    # and no open follows a path this could not check.
    if _names_a_link(info):
        loop = OSError(errno.ELOOP, os.strerror(errno.ELOOP), str(lock))
        raise _PairLockBusy(
            f"{lock} is a link; the uploads pair lock is not taken through it -- remove it"
        ) from loop


class _ChangedUnderReseal(Exception):
    """The file a re-seal read was removed (``gone``) or replaced before its write, so nothing was
    written (BACKLOG #3181 item 5)."""

    def __init__(self, *, gone: bool) -> None:
        super().__init__("removed" if gone else "replaced")
        self.gone = gone


def _same_file(a: os.stat_result, b: os.stat_result) -> bool:
    """Whether two ``lstat`` results are one unchanged file. The engine never writes a pair in place,
    only by temp-and-replace, so a rewrite gives a new file id, and the size and times catch most of
    what a file system that reports none would hide. The change time is a creation time on Windows,
    so a replacement's is new there; a false "changed" makes that half a skip."""
    return os.path.samestat(a, b) and (a.st_size, a.st_mtime_ns, a.st_ctime_ns) == (
        b.st_size,
        b.st_mtime_ns,
        b.st_ctime_ns,
    )


def _replace_if_unchanged(tmp: Path, path: Path, seen: os.stat_result) -> None:
    """``os.replace(tmp, path)`` only while ``path`` is still the file ``seen`` describes, under
    :func:`_pair_lock`. Raises :class:`_ChangedUnderReseal` and leaves ``path`` alone otherwise. A
    plain replace creates ``path`` when it is gone, which re-created a pair an engine deleted while
    ``rotate-key`` ran (BACKLOG #3181 item 5)."""
    with _pair_lock(path, for_reseal=True):
        unreached: str | None = None
        try:
            now = path.lstat()
        except OSError as exc:
            # Only a missing final name was removed. One whose share cannot be reached, whatever
            # class it arrives as, or a Windows missing folder or drive above it, raises
            # _UnreachableError, so the caller skips it, never counts a body as lost, and never
            # logs it as the uploads directory gone (BACKLOG #5388).
            if is_name_absent(exc):
                raise _ChangedUnderReseal(gone=True) from exc
            unreached = _outage_fault(exc)
            if unreached is None:
                raise
        if unreached is not None:
            raise _unreached(path, unreached)
        if not _same_file(now, seen):
            raise _ChangedUnderReseal(gone=False)
        os.replace(tmp, path)


def _atomic_write_text(
    root: Path, path: Path, text: str, *, seen: os.stat_result | None = None
) -> None:
    """Write ``text`` to ``path`` via a temp file + ``os.replace`` (atomic on the same dir), owner-only.

    With ``seen``, the replace is :func:`_replace_if_unchanged`'s: the temp is written first, outside
    the lock, and ``path`` is replaced only if it is still that file.

    **On any failure the temp is removed rather than left behind (BACKLOG #1678).** Without this, a
    write that raises — disk full is the realistic trigger and the blob is the large write — leaves a
    partial, PHI-bearing ciphertext in the uploads root that NO sweep can reach: ``list_files``,
    ``prune_expired`` and ``reseal_to_active`` all walk ``_walk_sidecars`` (the first two through
    ``_iter_sidecars``), which yields ``.meta`` names only. Catching ``BaseException`` is
    deliberate, as in ``config/atomic_edit.py``'s candidate cleanup: a cancellation must clean up
    too, and the original failure is re-raised untouched. The unlink's own errors are suppressed so
    a cleanup problem can never mask the real cause.

    The name is held in ``_inflight_names`` for the whole window, so a concurrent orphan sweep in this
    process skips it by identity instead of guessing from its age."""
    tmp = root / f".{path.name}.{secrets.token_hex(_TMP_TOKEN_BYTES)}.tmp"
    with _inflight(tmp.name):
        try:
            tmp.write_text(text, encoding="utf-8")
            with contextlib.suppress(OSError):
                os.chmod(
                    tmp, 0o600
                )  # best-effort (Windows / restricted FS) — directory ACL is the backstop
            if seen is None:
                os.replace(tmp, path)
            else:
                _replace_if_unchanged(tmp, path, seen)
        except BaseException:
            with contextlib.suppress(OSError):
                tmp.unlink(missing_ok=True)
            raise
