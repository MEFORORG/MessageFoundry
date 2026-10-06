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
``parsing.split``/``parsing.peek`` HL7 library. It never imports the store instance, a transport, a
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
import contextlib
import contextvars
import hashlib
import json
import logging
import os
import re
import secrets
import threading
import time
from collections.abc import Awaitable, Callable, Iterator
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol

from messagefoundry.controlchars import strip_control_chars
from messagefoundry.parsing.peek import HL7PeekError, Peek
from messagefoundry.parsing.sniff import _looks_like_hl7, _lstrip_bom_ws
from messagefoundry.parsing.split import split_batch
from messagefoundry.store.content_search import SearchSpec, row_matches
from messagefoundry.store.crypto import (
    MARKER_PREFIX,
    AesGcmCipher,
    Cipher,
    CipherError,
    cell_aad,
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

# How stale a leftover must look before the orphan sweep will remove it. This is a floor for a
# leftover from a process that DIED mid-write, NOT the mechanism that protects a live write — that is
# ``_inflight_names``, which is an exact identity test. An hour matches the default prune cadence and
# sits far outside any single write, which is bounded by ``max_bytes``.
_ORPHAN_MIN_AGE_SECONDS = 3600.0

# How long a cancelled save waits for each cross-shard ledger call, the reserve and the release, to
# finish (BACKLOG #2263). It is per call, so a save cancelled during a slow reserve can wait up to
# two bounds. A healthy statement takes well under a second. The bound exists so a stuck store
# cannot hold ``_quota_lock``, and the request's cancellation, indefinitely. Past it the call is
# logged and left running (UploadStore._leave_running).
_LEDGER_CANCEL_WAIT_SECONDS = 5.0

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


class UploadError(Exception):
    """Base class for uploaded-logs storage failures."""


class UploadPathError(UploadError):
    """A file_id is malformed or resolves outside the uploads root (path-traversal guard, ADR 0134)."""


class UploadTooLargeError(UploadError):
    """An upload exceeds ``[store].max_upload_bytes``."""


class UploadContentError(UploadError):
    """An upload's extension is not permitted, or its content contradicts its extension (ASVS 5.2.2).

    The uploaded-logs feature accepts only text diagnostic logs; a disallowed extension or a
    content/extension mismatch (PNG bytes in a ``.hl7``, a non-``<`` body in a ``.xml``, a NUL-bearing
    ``.txt``) is refused at the chokepoint before anything is written. The API maps it to HTTP 400 and a
    metadata-only ``upload.reject`` audit."""


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
    * **A leaked reservation.** A process killed between reserve and release never pays back, and its
      slot narrows that uploader's budget until the row goes idle for
      ``UPLOAD_RESERVATION_STALE_AFTER``. It errs toward refusing, not allowing. A cancelled
      ``save`` now waits a bounded time for its reserve and release to finish first (BACKLOG
      #2263), which closes the common case. At least these cancelled cases still leak: a reserve
      that raised after it may have committed, a release that fails, and a reserve or release Task
      that ``asyncio.run``'s shutdown cancels. A call still running at the bound is left to
      finish, and only leaks if it then lands in one of those cases. The module logs each at
      WARNING except a shutdown cancel of a call it was still waiting for.
      **IT DOES NOT SELF-HEAL UNCONDITIONALLY, and an earlier version of this line said it did.**
      The release statement sets ``since = <now>`` **unconditionally** (its own comment: "Never
      conditional: refusing a release would strand the reservation it is paying back"), so every
      *subsequent* release by the same uploader pushes the staleness clock forward. **It self-heals
      only while that uploader is otherwise IDLE.** A uploader who keeps uploading successfully can
      hold a leaked slot indefinitely, and the reserve path's own staleness reset never fires for it.
    * **A reclaimed live reservation.** If one uploader keeps reservations continuously outstanding
      for longer than that window, the staleness reset zeroes a row that was legitimately non-zero,
      which restores the N-1 bound above for that window. Never worse than the pre-#1112 behaviour.

    The ledger is checked and paid back around the write, not in the same transaction as it, because
    the body lives on the filesystem rather than in the store. The ordering above is what stands in
    for that transaction, and the residuals above are the known limits of the cross-process bound."""


class UploadUnreadableError(UploadError, CipherError):
    """The store cipher refused an uploaded file on a by-id read (BACKLOG #1169).

    On a keyed store that is usually a plaintext upload stored before the key was enabled, which a
    keyed store refuses until ``rotate-key`` seals it (owner ruling 2026-09-23). It can also be a file
    under a key that is no longer configured. It is a :class:`CipherError` too, so any caller that
    already catches the cipher's error still does. The API maps it to HTTP 423 without importing the
    cipher module. The message is the cipher's own, which names only the surface and the fix."""


class UploadNotFoundError(UploadError):
    """No uploaded file exists for the given (well-formed) file_id."""


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


def sanitize_filename(name: str | None) -> str:
    """Reduce an operator-supplied filename to a safe, display-only string (basename, no control chars,
    bounded length). Never used to locate a file on disk — the ``file_id`` is the on-disk identity."""
    if not name:
        return "upload"
    # Strip directory parts on either separator (the value may come from a Windows or POSIX client).
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    base = strip_control_chars(base).strip()
    if not base:
        return "upload"
    return base[:_MAX_FILENAME]


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
    """Extension-allowlist + content-vs-extension sniff for an uploaded file (ASVS 5.2.2). Raises
    :class:`UploadContentError` when the sanitized display filename's extension is not permitted, or when
    the content's leading bytes contradict the extension:

    * ``.hl7``/``.hl7v2`` → an MSH/FHS/BHS HL7 header sniff (rejects e.g. PNG bytes in a ``.hl7``);
    * ``.xml`` → a leading ``<`` after any BOM/whitespace;
    * ``.txt`` → NUL-free (``.txt`` has no magic signature, so content validation is necessarily weak —
      the same residual the plain-text connectors carry).

    Pure + off-loop friendly (no I/O). Reuses the shared ``parsing.sniff`` magic-byte helpers, so the
    upload chokepoint and the File connectors enforce the same sniff."""
    if not display.lower().endswith(_ALLOWED_UPLOAD_EXTENSIONS):
        raise UploadContentError(
            f"upload {display!r} has a disallowed extension; permitted: "
            f"{', '.join(_ALLOWED_UPLOAD_EXTENSIONS)}"
        )
    ctype = content_type_for(display)
    if ctype == "hl7v2":
        if not _looks_like_hl7(data):
            raise UploadContentError(
                f"upload {display!r} is not HL7 (no MSH/FHS/BHS header) despite its extension"
            )
    elif ctype == "xml":
        if not _lstrip_bom_ws(data).startswith(b"<"):
            raise UploadContentError(
                f"upload {display!r} is not XML (no leading '<') despite its extension"
            )
    elif b"\x00" in data:  # text (.txt) — no magic; NUL-free is the only structural check
        raise UploadContentError(
            f"upload {display!r} declares .txt but contains NUL bytes (not plain text)"
        )


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
    drop the retired key. A file this pass could not read is a file still sealed under the OLD key,
    and dropping that key makes it permanently unreadable — so a non-zero ``skipped`` means "run it
    again before you retire anything".

    The counts use different units. ``resealed`` counts VALUES: each body or sidecar it rewrites
    adds one. ``skipped`` counts UPLOADS: a pair adds at most one, whichever half failed (BACKLOG
    #2322). An unreadable body leaves its sidecar unread and unsealed, and that is still one upload."""

    resealed: int = 0
    skipped: int = 0
    #: How many UPLOADS had a plaintext half that this pass sealed (BACKLOG #1169). It counts files,
    #: not values, so it matches the count ``serve`` logs at startup (:meth:`UploadStore.warn_if_unsealed`).
    #: A keyed store refuses those uploads until this pass seals them, so this is how many it turned
    #: from refused into readable.
    sealed_plaintext: int = 0


@dataclass(frozen=True)
class PruneResult:
    """What one :meth:`UploadStore.prune_expired` pass did.

    ``pruned`` is the aged (blob, meta) pairs it deleted, carried whole because the caller writes one
    ``upload.prune`` audit row per file from that metadata. ``orphans_removed`` counts the write
    leftovers the same pass swept (BACKLOG #1678); those have no metadata by definition — a leftover
    is precisely a file whose sidecar never landed — so they are a count here and a WARNING in the
    log, not audit rows."""

    pruned: list[UploadedFileMeta] = field(default_factory=list)
    orphans_removed: int = 0


class UploadQuotaLedger(Protocol):
    """What :class:`UploadStore` needs from the message store: an atomic, cross-process reservation
    of an uploader's in-flight upload budget (ASVS 2.3.4), and a read of it taken after reserving.

    Declared here as a structural protocol rather than importing ``store.base.Store``, so this module
    stays a leaf (see the module docstring). Every backend's ``Store`` satisfies it structurally —
    see :meth:`messagefoundry.store.base.Store.reserve_upload_quota` and
    :meth:`~messagefoundry.store.base.Store.upload_quota_in_flight` for the full contract."""

    async def reserve_upload_quota(
        self,
        uploader_id: str,
        *,
        files: int,
        size_bytes: int,
        max_files: int = 0,
        max_total_bytes: int = 0,
    ) -> bool: ...

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
        # operator diagnostic-upload surface, and each pass is bounded by max_bytes.
        #
        # This lock is an asyncio.Lock, so it is per-event-loop and therefore PER-PROCESS. Engine
        # sharding is the built, shipped, default scaling axis and nothing partitions uploads_dir per
        # shard, so N shards over one directory hold N independent copies of it. `_ledger` is the
        # cross-process half: one atomic row on the ONE unified store every shard already shares.
        self._quota_lock = asyncio.Lock()
        self._ledger = store
        # Ledger calls a cancelled save stopped waiting for (BACKLOG #2263), held until they finish:
        # the loop holds a Task only weakly. See _leave_running.
        self._stragglers: set[asyncio.Future[Any]] = set()

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
        reject any id that is not the exact 32-hex shape, then resolve and assert both paths sit
        **directly under** the canonical uploads root. Raises :class:`UploadPathError` on any mismatch —
        without touching the filesystem for a bad id."""
        if not _FILE_ID_RE.match(file_id):
            raise UploadPathError(f"malformed upload id: {file_id!r}")
        root = self._root.resolve()
        blob = (root / f"{file_id}{_BLOB_SUFFIX}").resolve()
        meta = (root / f"{file_id}{_META_SUFFIX}").resolve()
        # Belt-and-suspenders: a validated 32-hex id cannot contain a separator, but verify the resolved
        # parent IS the root so no symlink/normalization trick lands the write elsewhere.
        if blob.parent != root or meta.parent != root:
            raise UploadPathError(f"upload id {file_id!r} resolves outside the uploads root")
        return blob, meta

    # --- crypto helpers (bytes ride the str cipher via base64, NUL-safe) --------------------------

    def _encrypt_blob(self, data: bytes, file_id: str) -> str:
        b64 = base64.b64encode(data).decode("ascii")
        return self._cipher.encrypt(b64, aad=cell_aad("uploaded_file", "body", file_id))

    @property
    def _passes_unmarked(self) -> bool:
        """True when this surface reads an unmarked file back as plaintext (BACKLOG #1169).

        **Owner ruling 2026-09-23: on a keyed store, an unmarked upload is REFUSED until an operator
        runs ``rotate-key``,** which reseals it. So the refusal applies exactly where that command can
        reseal, which is an :class:`AesGcmCipher`. There the cipher's own policy decides, and
        ``[store].allow_unmarked_ciphertext`` restores the passthrough for this surface too.

        Every other cipher keeps the passthrough. The identity cipher has no key, so nothing is
        refused anyway. ``vault_transit`` is a named residual, and ``docs/PHI.md`` §3 is where it and
        its reason are stated."""
        return not isinstance(self._cipher, AesGcmCipher)

    def _decrypt_blob(self, stored: str, file_id: str) -> bytes:
        b64 = self._cipher.decrypt(
            stored,
            aad=cell_aad("uploaded_file", "body", file_id),
            allow_unmarked=self._passes_unmarked,
        )
        return base64.b64decode(b64)

    def _encrypt_meta(self, meta: UploadedFileMeta) -> str:
        return self._cipher.encrypt(
            json.dumps(asdict(meta)), aad=cell_aad("uploaded_file", "meta", meta.file_id)
        )

    def _decrypt_meta(self, stored: str, file_id: str) -> UploadedFileMeta:
        raw = self._cipher.decrypt(
            stored,
            aad=cell_aad("uploaded_file", "meta", file_id),
            allow_unmarked=self._passes_unmarked,
        )
        d = json.loads(raw)
        return UploadedFileMeta(
            file_id=str(d["file_id"]),
            filename=str(d.get("filename", "upload")),
            uploader=str(d.get("uploader", "")),
            # Tolerant, like every other optional field — a sidecar without the key yields "", which
            # matches NOBODY at the ownership check (api/app.py ``_may_access_upload``) and buckets
            # into no operator's quota. That is the fail-closed end state, not a migration gap: there
            # is deliberately no fallback to ``uploader`` here, because a name fallback would
            # reintroduce exactly the recycled-username reachability this field exists to close.
            uploader_id=str(d.get("uploader_id", "")),
            content_type=str(d.get("content_type", "hl7v2")),
            size=int(d.get("size", 0)),
            sha256=str(d.get("sha256", "")),
            uploaded_at=float(d.get("uploaded_at", 0.0)),
            message_count=int(d.get("message_count", 0)),
        )

    def _iter_sidecars(self) -> Iterator[tuple[str, Path]]:
        """Every ``(file_id, sidecar path)`` pair in the uploads root — the ONE definition of "a file
        of ours". Both the listing scan and the re-seal pass consume it, so the id shape and the
        sidecar suffix cannot drift apart between them. Anything else in the directory (an operator's
        stray file, a temp file, an id that fails the strict 32-hex shape) is not ours and is skipped
        without being opened."""
        root = self._root
        if not root.is_dir():
            return
        for entry in root.iterdir():
            if not entry.name.endswith(_META_SUFFIX):
                continue
            fid = entry.name[: -len(_META_SUFFIX)]
            if _FILE_ID_RE.match(fid):
                yield fid, entry

    def _scan_metas_sync(self) -> list[UploadedFileMeta]:
        """Walk the uploads root and decrypt every well-formed ``.meta`` sidecar (UNSORTED). A
        bad/foreign/undecryptable sidecar is skipped **with its cause named** (never a body in the
        log), so a rotated-away key can neither sink the listing nor silently drop a quota/retention
        pass. Pure filesystem read — the caller runs it off the event loop.

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
        at startup so the operator knows to run it.

        The cipher's own message is safe to log — every ``CipherError`` carries only key ids,
        marker versions and algorithm names, never a decrypted value. The malformed-shape branch
        logs only the exception TYPE, because a ``ValueError`` from coercing a metadata field can
        echo that field's value back into the message."""
        out: list[UploadedFileMeta] = []
        for fid, entry in self._iter_sidecars():
            try:
                out.append(self._decrypt_meta(entry.read_text(encoding="utf-8"), fid))
            except CipherError as exc:
                # The cipher declined the value: a wrong/rotated-away key, a blob relocated into
                # another cell, or the refusal of an unmarked (legacy, planted or downgraded)
                # sidecar. Named on its own so these can be told apart from a damaged file.
                _log.warning("uploaded-file sidecar %s: cipher declined it: %s", fid, exc)
            except (OSError, UnicodeDecodeError) as exc:
                # The bytes never reached the cipher — unreadable file, or not valid UTF-8.
                _log.warning("uploaded-file sidecar %s: unreadable on disk: %s", fid, exc)
            except (ValueError, TypeError, KeyError) as exc:
                # Decrypted, but the JSON is malformed or a field will not coerce. Type only.
                _log.warning(
                    "uploaded-file sidecar %s: malformed metadata (%s)", fid, type(exc).__name__
                )
        return out

    # --- public API (all disk/crypto/split work off the event loop) --------------------------------

    async def save(
        self,
        *,
        data: bytes,
        filename: str,
        uploader: str,
        uploader_id: str,
        content_type: str | None = None,
    ) -> UploadedFileMeta:
        """Persist an uploaded file (encrypted at rest) and return its metadata.

        ``uploader_id`` is the owning account's immutable ``Identity.user_id``; ``uploader`` is its
        username, kept for display and the audit rows only. Both are required — a file written with
        no ``uploader_id`` would be readable by nobody but a ``files:access_any`` holder while still
        billing to nobody's quota, so an empty one is a programming error and is refused here.

        Raises :class:`UploadTooLargeError` if it exceeds ``max_bytes``, :class:`UploadContentError`
        on a disallowed extension / content mismatch (ASVS 5.2.2), or :class:`UploadQuotaError` when
        the uploader's file-count or aggregate-byte quota would be exceeded (ASVS 5.2.4).

        **A cancellation that reaches ``save`` after the pair landed removes it (BACKLOG #2262).**
        The caller writes ``upload.create`` only once this returns. A kept pair would be stored with
        no creation row, while the client was told the upload failed and may well retry it. A
        removal the filesystem refuses is logged at ERROR. This covers ``save`` only. A caller
        cancelled in its own audit write, after this returned, still keeps the file."""
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
        # Extension allowlist + content-vs-extension sniff at the chokepoint (ASVS 5.2.2). Both upload
        # surfaces (POST /uploads and POST /ui/uploaded-logs/upload) reach save(), so a disallowed
        # extension or a content/extension mismatch is refused here before any PHI is written.
        validate_upload_content(display, data)
        ctype = content_type or content_type_for(display)
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
            disk_files, disk_bytes = self._observed_sync(uploader_id)
            refusal = self._on_disk_refusal(
                uploader=uploader,
                observed_files=disk_files,
                observed_bytes=disk_bytes,
                size=len(data),
            )
            if refusal is not None:
                raise refusal
            # The ledger total includes this upload's own reservation, which `size` already counts,
            # so only the siblings' share is added to the disk figures.
            if (
                self._on_disk_refusal(
                    uploader=uploader,
                    observed_files=disk_files + max(0, in_flight[0] - 1),
                    observed_bytes=disk_bytes + max(0, in_flight[1] - len(data)),
                    size=len(data),
                )
                is not None
            ):
                raise self._shard_refusal(
                    uploader=uploader, observed_files=disk_files, observed_bytes=disk_bytes
                )
            meta = UploadedFileMeta(
                file_id=file_id,
                filename=display,
                uploader=uploader,
                uploader_id=uploader_id,
                content_type=ctype,
                size=len(data),
                sha256=hashlib.sha256(data).hexdigest(),
                uploaded_at=time.time(),
                # Message count is derived once at save (bounded by max_bytes) so listing never re-splits.
                message_count=len(split_batch(_decode_text(data))),
            )
            root = self._ensure_root()
            blob_path, meta_path = self._paths(file_id)
            blob_ct = self._encrypt_blob(data, file_id)
            meta_ct = self._encrypt_meta(meta)
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
        # Inside it, one cross-PROCESS reservation around the same window (ASVS 2.3.4). The order is
        # load-bearing: reserve, THEN read the ledger's in-flight total, THEN scan the disk inside
        # _build_and_write. UploadQuotaError carries the argument for why that order counts every
        # sibling upload. The reservation is released only once the file is on disk (or the write
        # fails), which is what the argument needs.
        #
        # The cancel handler sits OUTSIDE the lock so it also catches a cancellation that lands in
        # the release await, after the write returned. A disk scan between the release and the
        # removal over-counts the pair, which can refuse a sibling but never admits one too many.
        # The reserve and the release each get a bounded wait to finish before a cancellation
        # propagates, so a cancelled save normally pays its slot back (BACKLOG #2263). The cases
        # that still leak are listed once, in UploadQuotaError.
        try:
            async with self._quota_lock:
                reserved = await self._reserve_across_shards(
                    uploader_id=uploader_id, uploader=uploader, size=len(data)
                )
                try:
                    in_flight = (
                        await self._ledger.upload_quota_in_flight(uploader_id)
                        if self._ledger is not None
                        else (0, 0)
                    )
                    return await _to_thread_to_completion(_build_and_write, in_flight)
                finally:
                    if reserved:
                        await self._release_across_shards(uploader_id=uploader_id, size=len(data))
        except asyncio.CancelledError:
            if landed:
                # Cancel-resistant, like the write. A request deadline is delivered through anyio
                # task groups, which cancel again at every await, and a plain to_thread job that
                # is cancelled before a worker picks it up never runs at all. A cleanup failure
                # must not replace the cancellation, so it is logged and the cancel raised.
                try:
                    await _to_thread_to_completion(self._discard_cancelled_sync, file_id)
                except Exception:  # noqa: BLE001 — logged; the cancellation is what propagates
                    _log.error("could not remove cancelled upload %s", file_id, exc_info=True)
            raise

    def _discard_cancelled_sync(self, file_id: str) -> None:
        """Remove a pair whose save was cancelled after it landed (BACKLOG #2262; see :meth:`save`).

        Body first, then the sidecar, as :meth:`delete` and :meth:`prune_expired` do. The sidecar is
        the listing key, so it stays until the body is gone, and the orphan sweep never sees a body
        with no sidecar. A refused body unlink keeps the whole pair, listed and billed. A refused
        sidecar unlink leaves a listed sidecar with no body, which the retention prune clears. The
        log names the ``file_id`` only, because the filename can carry PHI."""
        blob_path, meta_path = self._paths(file_id)
        try:
            blob_path.unlink(missing_ok=True)
            meta_path.unlink(missing_ok=True)
        except OSError as exc:
            _log.error(
                "upload %s was cancelled after its file landed and was not fully removed; what "
                "remains has no upload.create audit row: %s",
                file_id,
                exc,
            )

    async def _reserve_across_shards(self, *, uploader_id: str, uploader: str, size: int) -> bool:
        """Take this uploader's cross-shard in-flight reservation; return whether one is held.

        ``False`` means there is no ledger bound (the store-less construction path) — not that the
        reservation was refused. A refusal raises :class:`UploadQuotaError`, the same TYPE the
        in-process check raises, so the API's 409 + ``upload.reject_quota`` audit is unchanged; the
        message differs on purpose, so an operator can tell the two causes apart. A ledger error is
        NOT swallowed: the store being unreachable fails the upload closed.

        **This is not the quota decision (BACKLOG #1941).** ``save`` makes that after reserving, from
        a read of the ledger plus a fresh disk scan; :class:`UploadQuotaError` says why the order
        matters. The headroom handed to the ledger here is the cap minus a sidecar scan taken BEFORE
        the reserve, so it can be stale, and it serves only as a first filter. It lets the second of
        two same-moment uploads be refused at the ledger, rather than both reserving and each then
        refusing the other.

        That makes two sidecar scans per save, this one and the one in ``_build_and_write``. Each
        reads and decrypts EVERY sidecar in the directory, for every uploader, then filters, and both
        run under the per-process ``_quota_lock``. They run off the event loop, on the operator
        diagnostic surface rather than the data plane.

        An uploader already over budget on disk is refused here, with the on-disk wording, before the
        ledger is consulted. Otherwise a zero-headroom ledger would refuse first, and its message would
        blame uploads on another shard that do not exist."""
        if self._ledger is None:
            return False
        observed_files, observed_bytes = await asyncio.to_thread(self._observed_sync, uploader_id)
        refusal = self._on_disk_refusal(
            uploader=uploader,
            observed_files=observed_files,
            observed_bytes=observed_bytes,
            size=size,
        )
        if refusal is not None:
            raise refusal
        # A cancellation can arrive after the store committed the reserve but before the call
        # returned, so `save` never learns a slot is held and its release never runs (BACKLOG #2263).
        # Finish the call, then pay back what it took before the cancellation propagates.
        reserve = asyncio.ensure_future(
            self._ledger.reserve_upload_quota(
                uploader_id,
                files=1,
                size_bytes=size,
                max_files=self._max_files_per_user - observed_files,
                max_total_bytes=self._max_total_bytes_per_user - observed_bytes,
            )
        )
        try:
            ok = await _wait_to_completion(reserve, cancel_bound=_LEDGER_CANCEL_WAIT_SECONDS)
        except asyncio.CancelledError:
            if not reserve.done():
                self._leave_running(reserve, what="reserve", uploader_id=uploader_id, size=size)
            elif self._reserve_took_a_slot(reserve, uploader_id):
                await self._release_across_shards(uploader_id=uploader_id, size=size)
            raise
        if not ok:
            raise self._shard_refusal(
                uploader=uploader, observed_files=observed_files, observed_bytes=observed_bytes
            )
        return True

    @staticmethod
    def _reserve_took_a_slot(reserve: asyncio.Future[bool], uploader_id: str) -> bool:
        """Whether a finished reserve, abandoned by a cancelled save, holds a slot to pay back.

        A reserve that raised is NOT paid back. Its outcome is unknown, and a release when nothing
        committed would subtract a sibling shard's live slot and let an upload past the cap."""
        if reserve.cancelled():
            _log.warning(
                "the cross-shard upload reserve for %s was cancelled before it finished; a slot "
                "it took is not paid back",
                uploader_id,
            )
            return False
        exc = reserve.exception()
        if exc is not None:
            _log.warning(
                "the cross-shard upload reserve for %s failed while the upload was being "
                "cancelled; a slot it took is not paid back",
                uploader_id,
                exc_info=exc,
            )
            return False
        return reserve.result()

    def _leave_running(
        self, fut: asyncio.Future[Any], *, what: str, uploader_id: str, size: int
    ) -> None:
        """Let a ledger call a cancelled save stopped waiting for finish on its own (BACKLOG #2263).

        A reserve that then turns out to hold a slot is paid back by a fresh release."""
        _log.warning(
            "the cross-shard upload %s for %s did not finish within %gs of a cancellation; it "
            "was left running",
            what,
            uploader_id,
            _LEDGER_CANCEL_WAIT_SECONDS,
        )
        self._stragglers.add(fut)

        def _done(done: asyncio.Future[Any]) -> None:
            self._stragglers.discard(done)
            if what == "reserve":
                if self._reserve_took_a_slot(done, uploader_id):
                    late = asyncio.ensure_future(
                        self._release_across_shards(uploader_id=uploader_id, size=size)
                    )
                    self._stragglers.add(late)
                    late.add_done_callback(self._stragglers.discard)
            elif done.cancelled():
                _log.warning(
                    "the cross-shard upload release for %s was cancelled before it finished; "
                    "its slot is not paid back",
                    uploader_id,
                )

        fut.add_done_callback(_done)

    def _shard_refusal(
        self, *, uploader: str, observed_files: int, observed_bytes: int
    ) -> UploadQuotaError:
        """The refusal when what is on disk fits but uploads in flight on other engine shards take
        the rest of the budget. Worded apart from :meth:`_on_disk_refusal` so an operator can tell
        the two causes apart."""
        return UploadQuotaError(
            f"uploader {uploader!r} has {observed_files} uploaded files holding "
            f"{observed_bytes} bytes, and another engine shard is mid-upload against the same "
            f"budget; the limits are {self._max_files_per_user} files / "
            f"{self._max_total_bytes_per_user} bytes"
        )

    def _on_disk_refusal(
        self, *, uploader: str, observed_files: int, observed_bytes: int, size: int
    ) -> UploadQuotaError | None:
        """The per-uploader quota verdict against what is ALREADY on disk, or ``None`` if it fits.

        One string, two callers: the under-lock check inside ``save``'s build-and-write, and the
        cross-shard reservation's pre-check. The bucket key is the IMMUTABLE ``uploader_id`` (the
        caller filters on it, the same value the ownership check uses), so the budget and the
        ownership rule can never disagree about who a file belongs to and a recycled username is
        never billed for files it cannot read. The message names the human username, because an
        operator reading a 409 needs a name, not a uuid."""
        if observed_files + 1 > self._max_files_per_user:
            return UploadQuotaError(
                f"uploader {uploader!r} has {observed_files} uploaded files; the limit is "
                f"{self._max_files_per_user}"
            )
        projected = observed_bytes + size
        if projected > self._max_total_bytes_per_user:
            return UploadQuotaError(
                f"uploader {uploader!r} would hold {projected} bytes; the limit is "
                f"{self._max_total_bytes_per_user}"
            )
        return None

    async def _release_across_shards(self, *, uploader_id: str, size: int) -> None:
        """Pay the reservation back. Never raises a ledger error: the file is already written (or
        already failed) by the time this runs, so turning a ledger blip into a failed upload would be
        strictly worse.

        **A cancellation waits for the release to finish, then propagates (BACKLOG #2263).** A request
        deadline arrives through an anyio scope that cancels again at every await, so a plain await
        here was cut short whenever the deadline fired mid-upload, and the slot leaked. Once the
        caller is cancelled, the wait is bounded by ``_LEDGER_CANCEL_WAIT_SECONDS``, so a stuck store
        cannot hold ``_quota_lock`` and the cancellation indefinitely. That includes a cancellation
        an earlier wait already absorbed. A release still running at the bound is logged and left
        to finish on its own, which pays the slot back if it succeeds.

        A reservation that is never released is reclaimed once the row goes stale — **but only while
        that uploader is otherwise IDLE.** This statement sets ``since = <now>`` unconditionally, so
        each later release by the same uploader restarts the staleness clock and a leaked slot can
        survive indefinitely under continued activity. See
        :meth:`messagefoundry.store.base.Store.reserve_upload_quota`."""
        ledger = self._ledger
        if ledger is None:
            return

        # The log sits inside the task, so a failure is reported in this module's words whether or
        # not the caller is being cancelled, and the task never ends in an error of its own.
        async def _release() -> None:
            try:
                await ledger.reserve_upload_quota(
                    uploader_id, files=-1, size_bytes=-size, max_files=0, max_total_bytes=0
                )
            except Exception:  # noqa: BLE001 — a release failure must not fail an upload that landed
                _log.warning(
                    "could not release the cross-shard upload reservation for %s; it will be "
                    "reclaimed when it goes stale",
                    uploader_id,
                    exc_info=True,
                )

        release = asyncio.ensure_future(_release())
        try:
            await _wait_to_completion(release, cancel_bound=_LEDGER_CANCEL_WAIT_SECONDS)
        except asyncio.CancelledError:
            if not release.done():
                self._leave_running(release, what="release", uploader_id=uploader_id, size=size)
            raise

    def _observed_sync(self, uploader_id: str) -> tuple[int, int]:
        """(file count, total bytes) already ON DISK for ``uploader_id`` — the fleet-visible half of
        the budget. Sync: the caller runs it off the event loop."""
        mine = [m for m in self._scan_metas_sync() if m.uploader_id == uploader_id]
        return len(mine), sum(m.size for m in mine)

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

    async def get_meta(self, file_id: str) -> UploadedFileMeta:
        """Return one file's metadata (path-traversal-guarded). Raises :class:`UploadNotFoundError`."""

        def _read() -> UploadedFileMeta:
            _, meta_path = self._paths(file_id)
            try:
                return self._decrypt_meta(meta_path.read_text(encoding="utf-8"), file_id)
            except FileNotFoundError as exc:
                raise UploadNotFoundError(file_id) from exc
            except CipherError as exc:
                raise UploadUnreadableError(str(exc)) from exc

        return await asyncio.to_thread(_read)

    async def read_bytes(self, file_id: str) -> bytes:
        """Return the decrypted body bytes (path-traversal-guarded). Raises
        :class:`UploadNotFoundError`."""

        def _read() -> bytes:
            blob_path, _ = self._paths(file_id)
            try:
                return self._decrypt_blob(blob_path.read_text(encoding="utf-8"), file_id)
            except FileNotFoundError as exc:
                raise UploadNotFoundError(file_id) from exc
            except CipherError as exc:
                raise UploadUnreadableError(str(exc)) from exc

        return await asyncio.to_thread(_read)

    async def delete(self, file_id: str) -> UploadedFileMeta:
        """Delete an uploaded file (both sidecars). Returns the deleted metadata for the audit row.
        Path-traversal-guarded; raises :class:`UploadNotFoundError` if it does not exist."""

        def _delete() -> UploadedFileMeta:
            blob_path, meta_path = self._paths(file_id)
            try:
                meta = self._decrypt_meta(meta_path.read_text(encoding="utf-8"), file_id)
            except FileNotFoundError as exc:
                raise UploadNotFoundError(file_id) from exc
            except CipherError as exc:
                raise UploadUnreadableError(str(exc)) from exc
            # Remove the body first, then the sidecar (best-effort on the body — the sidecar is the
            # listing key, so once it is gone the file is invisible even if the blob lingers).
            blob_path.unlink(missing_ok=True)
            meta_path.unlink(missing_ok=True)
            return meta

        return await asyncio.to_thread(_delete)

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

        Same contract as the store's pass: rewrites values that are plaintext **or** under a retired
        key, skips values already under the active key (so it is idempotent), and lets a
        :class:`CipherError` propagate rather than dropping data — a value no configured key opens
        means the prior key was not supplied, and the CLI says so. Also mirrors its **limitation**:
        a non-``AesGcmCipher`` (the identity cipher, or a ``vault_transit`` cipher whose DEK never
        enters the heap) rotates nothing and returns zeros, exactly as ``reencrypt_to_active`` does.

        Re-sealing happens at the **cipher** layer — ``encrypt(decrypt(stored))`` over the stored
        string — so a body's base64 envelope is never decoded and the plaintext bytes are never
        reassembled here. Files are processed one at a time and each is rewritten through the same
        atomic temp-and-replace the write path uses. Peak memory is a SMALL MULTIPLE of ``max_bytes``,
        not ``max_bytes`` itself: base64 and the AES-GCM round trip each hold their own copy, so a
        25 MiB upload transiently costs a few hundred MiB. A file already under the active key is
        detected from its first bytes and never read whole.

        **This pass LAUNDERS an unmarked value, and that is the ruled trade, not an oversight.** It
        seals every plaintext file it finds, legacy or planted, into a genuine AAD-bound ciphertext,
        after which nothing distinguishes it from a file the engine wrote itself. Unlike the store,
        this surface has no "already sealed" evidence to tell the two apart: new sealed uploads land
        beside legacy plaintext ones for as long as the operator has not run ``rotate-key``. So the
        control is the refusal BEFORE this pass, with its alert and the startup count, plus
        ``sealed_plaintext`` in the result, which the operator can check against that count.

        Runs entirely off the event loop."""
        return await asyncio.to_thread(self._reseal_to_active_sync)

    def _reseal_to_active_sync(self) -> ResealResult:
        """The blocking half of :meth:`reseal_to_active` (disk + cipher). Caller runs it off-loop."""
        cipher = self._cipher
        if not isinstance(cipher, AesGcmCipher):
            return ResealResult()  # identity / transit cipher — nothing this process can rotate
        root = self._root
        if not root.is_dir():
            return ResealResult()
        active = cipher.active_marker_prefix
        resealed = skipped = sealed_plaintext = 0
        for fid, _sidecar in self._iter_sidecars():
            try:
                blob_path, meta_path = self._paths(fid)
            except UploadPathError:
                # Unreachable for an id that passed _FILE_ID_RE — the guard re-checks the same shape.
                # Kept anyway, because `prune_expired` guards its unlink the same way: a path guard
                # this pass skipped would be the one place a bad id reaches the filesystem.
                skipped += 1
                _log.warning("uploaded file %s: skipped, its id fails the path guard", fid)
                continue
            had_plaintext = False
            # The sidecar carries the AAD kind "meta"; the body carries "body" (see _encrypt_meta /
            # _encrypt_blob). Re-binding the SAME cell AAD is what keeps a re-sealed value readable.
            # Body FIRST, as save() writes it: the sidecar is the listing key, and a keyed store
            # refuses a plaintext value (BACKLOG #1169). Sealing the sidecar first would let an
            # interrupted pass list an upload whose body is still refused.
            for path, kind in ((blob_path, "body"), (meta_path, "meta")):
                try:
                    # Read the MARKER first, not the file. The idempotency test is a prefix compare,
                    # and a sealed 25 MiB upload is ~44 MiB on disk — reading it whole only to skip
                    # it made a re-run cost a full pass over every already-current file. The store's
                    # own passes push this filter into SQL (`WHERE col NOT LIKE ...`) for the same
                    # reason; on a filesystem the equivalent is a bounded read.
                    with path.open(encoding="utf-8") as handle:
                        if handle.read(len(active)) == active:
                            continue  # already under the active key in the active format
                    stored = path.read_text(encoding="utf-8")
                    had_plaintext |= bool(stored) and not stored.startswith(MARKER_PREFIX)
                except (OSError, UnicodeDecodeError) as exc:
                    # A half-deleted pair or an unreadable file. Counted and named, never silent:
                    # this file is still under the OLD key and the operator must not retire it yet.
                    skipped += 1
                    _log.warning("uploaded file %s (%s): skipped, unreadable: %s", fid, kind, exc)
                    if kind == "body" and isinstance(exc, FileNotFoundError):
                        # A body that is GONE has nothing left to refuse, and no re-run brings it
                        # back. Sealing its sidecar keeps the pair decryptable after the old key
                        # goes, so `prune_expired` can still remove it at expiry.
                        continue
                    # A body that is present but unreadable ends the pair here, so its sidecar is
                    # not sealed over a body this pass never sealed (BACKLOG #2322). The sidecar is
                    # the last kind, so either way the pair counts once in `skipped`.
                    break
                aad = cell_aad("uploaded_file", kind, fid)
                # A CipherError here means a prior key was not supplied. It PROPAGATES, before any
                # write, so the operator is told to supply it rather than losing the file.
                _atomic_write_text(root, path, _reencrypt_value(cipher, stored, aad))
                # Drop the file-sized buffer before the next iteration allocates its own. Without
                # this the previous file's plaintext stays reachable from the frame while the next
                # one is read, roughly doubling peak memory for no reason.
                del stored
                resealed += 1
            sealed_plaintext += had_plaintext
        if resealed or skipped:
            _log.info(
                "re-sealed %d uploaded-file value(s) under the active key, sealing %d plaintext "
                "upload(s) (%d upload(s) skipped)",
                resealed,
                sealed_plaintext,
                skipped,
            )
        return ResealResult(resealed=resealed, skipped=skipped, sealed_plaintext=sealed_plaintext)

    async def warn_if_unsealed(self) -> int:
        """Log, once at ``serve`` startup, how many uploads a keyed store holds as plaintext.

        Owner ruling 2026-09-23 (BACKLOG #1169): each one is refused on read until an operator runs
        ``rotate-key``, and nothing else would tell the operator they exist, because a refused file
        simply drops out of the listing. So this logs the COUNT at WARNING with that instruction, and
        never names a file: the filename inside a sidecar can carry PHI, and the count is all the
        operator needs. Returns the count. Returns 0 without logging where the refusal does not apply
        (see :attr:`_passes_unmarked`).

        The cost is one directory walk and a read of at most a marker's length from each file. The
        hourly retention scan already decrypts every sidecar, so this adds nothing of a new order. Runs
        off the event loop."""
        cipher = self._cipher
        if not isinstance(cipher, AesGcmCipher):  # the same test as _passes_unmarked
            return 0
        try:
            count = await asyncio.to_thread(self._count_unsealed_sync)
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
        return count

    def _count_unsealed_sync(self) -> int:
        """How many uploads have a non-blank half with no ``mfenc:`` marker. Reads only the first
        ``len(MARKER_PREFIX)`` characters of each file. A file that cannot be read is not counted here;
        the listing scan names it on its own."""
        count = 0
        for fid, _sidecar in self._iter_sidecars():
            try:
                paths = self._paths(fid)
            except UploadPathError:
                continue
            for path in paths:
                try:
                    with path.open(encoding="utf-8") as handle:
                        head = handle.read(len(MARKER_PREFIX))
                except (OSError, UnicodeDecodeError):
                    continue
                if head and head != MARKER_PREFIX:
                    count += 1
                    break  # count the upload once, whichever half is plaintext
        return count

    async def prune_expired(
        self,
        *,
        now: float | None = None,
        retention_days: int | None = None,
        abort: threading.Event | None = None,
    ) -> PruneResult:
        """Age-based retention sweep (ASVS 5.2.4): delete every (blob, meta) pair whose ``uploaded_at`` is
        older than ``retention_days`` (default: the configured ``retention_days``), then sweep the write
        leftovers no other pass can reach. Returns a :class:`PruneResult` — the pruned metadata rows (for
        the ``upload.prune`` audit: ``file_id`` + ``uploader`` only, never content) plus the orphan count.

        Idempotent: a re-run finds the already-deleted pairs gone and returns an empty pass.
        Undecryptable/foreign sidecars are skipped (never pruned — a rotated-away key must not silently
        destroy data). Runs off the event loop; the periodic runner + the opportunistic save-time sweep
        both drive it.

        A pair is reported only when this pass removed its body, the PHI the audit row is about. A
        refused body unlink leaves the whole pair for the next pass; a refused sidecar unlink leaves
        a sidecar the next pass clears without a second report.

        ``abort`` stops the pass early without losing track of what it already deleted (BACKLOG #2065;
        :meth:`UploadRetentionRunner.stop` says why cancelling is not enough). The pass checks it before
        the scan and before each pair, then skips the orphan sweep and returns the pairs it did delete.
        A pair is never half-deleted by an abort."""
        days = self._retention_days if retention_days is None else max(1, int(retention_days))
        at = time.time() if now is None else now
        cutoff = at - days * _SECONDS_PER_DAY

        stop = abort if abort is not None else threading.Event()

        def _prune() -> PruneResult:
            pruned: list[UploadedFileMeta] = []
            # Checked before the scan too: the scan decrypts every sidecar, which is wasted on a stop.
            metas = [] if stop.is_set() else self._scan_metas_sync()
            for meta in metas:
                if meta.uploaded_at >= cutoff:
                    continue
                if stop.is_set():
                    break
                # A sidecar whose id somehow fails the path guard is left alone (never blindly unlinked).
                try:
                    blob_path, meta_path = self._paths(meta.file_id)
                except UploadPathError:
                    continue
                # A refused unlink must not raise out of the loop: that would drop `pruned`, and with
                # it the audit rows for every pair already deleted.
                #
                # The BODY goes first, and a pair is reported exactly when THIS pass removed its body,
                # because the body is the PHI the audit row records the deletion of. Sidecar-first
                # reported a pair whose body unlink was refused and left the body on disk, and it
                # opened a window where a body with no sidecar is exactly what a concurrent pass's
                # orphan sweep takes. Body-first keeps the sidecar in place until the body is gone,
                # so the orphan sweep never sees a pair mid-prune. A body already gone was removed,
                # and reported, by an earlier or overlapping pass (the save-time sweep and the runner
                # can overlap), so only its leftover sidecar is cleared, with no second report.
                try:
                    blob_path.unlink()
                except FileNotFoundError:
                    with contextlib.suppress(OSError):
                        meta_path.unlink(missing_ok=True)
                    continue
                except OSError as exc:
                    _log.warning(
                        "uploaded-logs prune left %s for the next pass: %s", meta.file_id, exc
                    )
                    continue
                pruned.append(meta)
                # A refused sidecar unlink leaves a sidecar with no body. The next pass finds the
                # body gone and clears the sidecar without reporting the pair again.
                try:
                    meta_path.unlink(missing_ok=True)
                except OSError as exc:
                    _log.warning(
                        "uploaded-logs prune removed the body of %s but not its sidecar; the next "
                        "pass will clear it: %s",
                        meta.file_id,
                        exc,
                    )
            if stop.is_set():
                return PruneResult(pruned=pruned)
            return PruneResult(pruned=pruned, orphans_removed=self._sweep_orphans_sync(now=at))

        return await asyncio.to_thread(_prune)

    def _sweep_orphans_sync(self, *, now: float) -> int:
        """Remove the write leftovers no other pass can reach, and return how many went (BACKLOG #1678).

        Two shapes, both meaning a write that started and never landed: a ``.<id>.<suffix>.<tag>.tmp``
        whose ``os.replace`` never ran, and an ``<id>.blob`` whose sidecar was never written. Neither is
        reachable through :meth:`_iter_sidecars`, which yields ``.meta`` names only, so
        :meth:`list_files`, :meth:`prune_expired` and :meth:`reseal_to_active` all walk straight past
        them: a partial body would otherwise sit in the uploads root for the life of the directory,
        outside the retention window this module promises, and (under a configured key) as ciphertext
        ``rotate-key`` would never re-seal.

        **This pass UNLINKS, so it refuses anything it cannot positively identify as ours.** A name
        matching neither exact shape is an operator's own file and is never touched, the same way
        :meth:`_iter_sidecars` skips it. A ``.blob`` whose sidecar exists but cannot be DECRYPTED is
        kept, because :meth:`_iter_sidecars` yields that sidecar without opening it — a rotated-away key
        can no more destroy data here than it can in the age pass.

        **A live write is safe by IDENTITY, not by age.** ``_inflight_names`` holds every name a write
        in this process currently holds, and a held name is skipped outright, so the threshold never
        adjudicates a race this process can see. ``_ORPHAN_MIN_AGE_SECONDS`` is the floor for everything
        else — a leftover the registry cannot see comes from a process that DIED mid-write (every
        in-process failure, cancellation included, now cleans up after itself), or from a sibling engine
        shard sharing this ``uploads_dir``.

        **That second case is the residual, stated precisely.** A sibling shard whose single write — one
        write, bounded by ``max_bytes`` — has been stalled for longer than the floor could have its temp
        removed underneath it. Its ``os.replace`` then raises and its ``save`` fails cleanly: nothing is
        published half-written, nothing is left behind, and the operator retries. An hour against a
        25 MiB default bound is far outside that window."""
        root = self._root
        if not root.is_dir():
            return 0
        cutoff = now - _ORPHAN_MIN_AGE_SECONDS
        # A sidecar is the listing key, so an id with one is reachable and this pass is not about it.
        reachable = {fid for fid, _ in self._iter_sidecars()}
        removed = 0
        for entry in root.iterdir():
            name = entry.name
            stem = name[: -len(_BLOB_SUFFIX)] if name.endswith(_BLOB_SUFFIX) else ""
            if _ORPHAN_TMP_RE.match(name):
                kind = "temp file"
            elif _FILE_ID_RE.match(stem):
                if stem in reachable:
                    continue
                kind = "body with no sidecar"
            else:
                continue  # not one of ours — never touched
            if _is_inflight(name):
                continue  # a write in this process is holding it right now
            try:
                if entry.stat().st_mtime > cutoff:
                    continue  # too young to be certain it is abandoned
                entry.unlink()
            except OSError as exc:
                # Already gone (a sibling shard's sweep), held open by another process, or not a file
                # at all. Never fatal — the next pass retries. The NAME is safe to log: a file_id and
                # a random tag, never a body.
                _log.debug("uploaded-logs orphan sweep left %s alone: %s", name, exc)
                continue
            removed += 1
            # ASCII only in the message itself: a stock Windows cp1252 console raises
            # UnicodeEncodeError on the em dashes this module's prose uses freely.
            _log.warning(
                "uploaded-logs: removed an abandoned %s (%s): a write started and never landed",
                kind,
                name,
            )
        return removed


# One prune sweep per hour is ample for a day-granularity retention window (the opportunistic save-time
# sweep covers the between-ticks case), and it keeps the background wakeups negligible.
_DEFAULT_PRUNE_INTERVAL_SECONDS = 3600.0

# How long ``UploadRetentionRunner.stop`` waits for a sweep already in flight to finish and write its
# audit rows. The sweep stops at its next file once asked, so this bounds a hung filesystem call, a
# sidecar scan already under way, and the audit writes for what the sweep had deleted. It sits well
# under NSSM's 15 s graceful-stop window (AppStopMethodConsole in scripts/service/install-service.ps1),
# because the runner stops FIRST in the API lifespan's teardown and engine.stop() still has to run.
_DEFAULT_STOP_TIMEOUT_SECONDS = 5.0


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
        # The sweep's worker thread reads this one; an asyncio.Event is not thread-safe.
        self._abort = threading.Event()
        self._task: asyncio.Task[None] | None = None

    def start(self) -> None:
        """Spawn the supervised prune loop (idempotent)."""
        if self._task is not None:
            return
        self._stop.clear()
        # A fresh event, not a clear(): a sweep thread a timed-out stop() left running still holds
        # the old one, and clearing it would let that thread resume deleting with nobody to audit.
        self._abort = threading.Event()
        self._task = asyncio.create_task(self._run())
        _log.info(
            "uploaded-logs retention prune enabled: older than %d days, every %gs",
            self._store.retention_days,
            self._interval,
        )

    async def stop(self) -> None:
        """Signal the loop and await its exit, audit rows included (idempotent).

        **The loop is asked to stop, not cancelled (BACKLOG #2065).** A sweep deletes files in a
        worker thread, and cancelling the task that awaits it leaves the thread deleting while the
        result naming those files is dropped, so no ``upload.prune`` row is ever written for them.
        Instead the sweep is told to stop at its next file, and this waits for it to return and for
        its audit rows to land, up to ``stop_timeout_seconds``.

        A sweep can outlast that bound: one stuck filesystem call, the sidecar scan or orphan sweep
        already under way, or the audit writes for a long list of deletions. The task is then
        cancelled and the loss is logged as an ERROR. The loss covers every file the sweep deleted
        and had not yet audited, not only what it deletes afterwards.

        This never raises into the caller's teardown. If the caller is itself cancelled while
        waiting, the sweep is cancelled the same way and this returns, as it did before #2065, so the
        API lifespan's later steps, ``engine.stop()`` among them, still run."""
        self._stop.set()
        task = self._task
        self._task = None
        if task is None:
            return
        # Stop the sweep in flight, which holds THIS event, then give the runner a fresh one. Left
        # set, it made every later run_once() prune nothing, silently.
        self._abort.set()
        self._abort = threading.Event()
        try:
            # shield: a timeout must not cancel the task mid-audit; the branches below decide that.
            await asyncio.wait_for(asyncio.shield(task), self._stop_timeout)
            return
        except TimeoutError:
            why = f"did not finish within {self._stop_timeout:g}s of shutdown"
        except asyncio.CancelledError:
            why = "was still running when shutdown itself was cancelled"
        _log.error(
            "uploaded-logs retention sweep %s; cancelling it. A file it deleted and had not yet "
            "audited, or deletes after this point, has no upload.prune audit row",
            why,
        )
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    async def _run(self) -> None:
        # One isolated sweep per interval; an error in a pass is logged and the loop continues (a prune
        # must never take the engine down). Cooperatively cancellable via _stop.
        while not self._stop.is_set():
            try:
                await self.run_once()
            except Exception:
                _log.exception("uploaded-logs retention prune failed; will retry next interval")
            await self._sleep(self._interval)

    async def _sleep(self, delay: float) -> None:
        try:  # noqa: SIM105 — wake immediately on stop so shutdown isn't held by the interval
            await asyncio.wait_for(self._stop.wait(), delay)
        except TimeoutError:
            pass

    async def run_once(self, now: float | None = None) -> PruneResult:
        """Run one prune sweep for ``now`` (default: the injected clock), auditing each pruned file. The
        audit callback (contractually) never raises, but be defensive — one bad audit call must not abort
        the remaining prunes. The pass's orphan count rides back in the result; it is logged by the sweep
        and carries no metadata to audit (see :class:`PruneResult`)."""
        result = await self._store.prune_expired(
            now=self._clock() if now is None else now, abort=self._abort
        )
        for meta in result.pruned:
            if self._audit is None:
                continue
            try:
                await self._audit(meta)
            except Exception:
                _log.warning("uploaded-logs prune audit failed for %s", meta.file_id, exc_info=True)
        return result


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
    return cipher.encrypt(cipher.decrypt(stored, aad=aad, allow_unmarked=True), aad=aad)


async def _to_thread_to_completion[T, A](func: Callable[[A], T], arg: A) -> T:
    """``asyncio.to_thread``, except that a cancellation waits for the thread to finish first.

    A bare ``to_thread`` re-raises a cancellation at once while its thread keeps running. ``save``
    then pays its cross-shard reservation back and drops ``_quota_lock`` while the file is still
    being written, so a sibling can read the ledger and scan the disk and count neither. That breaks
    the premise :class:`UploadQuotaError`'s ordering argument rests on. The write is bounded by
    ``max_bytes``, so the wait is too. Further cancellations while waiting are absorbed, and a
    ``CancelledError`` is raised once the thread is done.

    The wait is on the executor's own Future, never on a Task wrapping ``to_thread``. ``asyncio.run``
    cancels every pending TASK at shutdown, so a Task here would be cancelled out from under the
    wait and end it early. A plain Future is not in ``asyncio.all_tasks()``, and nothing else holds
    it, so only the thread finishing can complete it."""
    loop = asyncio.get_running_loop()
    ctx = contextvars.copy_context()  # what to_thread passes to the thread, kept the same
    return await _wait_to_completion(loop.run_in_executor(None, ctx.run, func, arg))


async def _wait_to_completion[T](fut: asyncio.Future[T], *, cancel_bound: float | None = None) -> T:
    """Await ``fut``; on a cancellation, wait for it to finish, then raise ``CancelledError``.

    The shared body of :func:`_to_thread_to_completion` and the cross-shard ledger calls (BACKLOG
    #2263). Further cancellations while waiting are absorbed. A ledger call is a coroutine, so it
    runs as a Task, and ``asyncio.run``'s shutdown cancellation can still end it early. That
    leaves the reservation as a killed process would.

    The wait is ``asyncio.wait``, never ``asyncio.shield``. Once its caller is cancelled, shield
    reports a later failure of ``fut`` to the loop's exception handler at ERROR, so a failure the
    caller already logs is logged twice.

    ``cancel_bound`` limits the wait after a cancellation, in seconds; ``None`` waits as long as it
    takes, which the bounded file write needs. A ledger call waits on the store, which may not be
    bounded at all. At the bound this raises with ``fut`` still running, and the caller decides
    what to do with it. Under an anyio scope, the scope cancels again on every loop pass, so the
    wait costs CPU, and the bound limits that too.

    **A caller already cancelled at entry gets the bound as well.** That is a ``finally`` running
    after an earlier wait absorbed the cancellation: the release after a cancelled write. Without
    this, a plain asyncio cancel used up by the write would leave the release unbounded. Such a
    caller gets the result when ``fut`` finishes in time, since a cancellation is already on its
    way out."""
    loop = asyncio.get_running_loop()
    task = asyncio.current_task()
    already = task is not None and task.cancelling() > 0
    cancelled = False
    deadline = None if not already or cancel_bound is None else loop.time() + cancel_bound
    while not fut.done():
        remaining = None if deadline is None else deadline - loop.time()
        if remaining is not None and remaining <= 0:
            raise asyncio.CancelledError
        try:
            await asyncio.wait((fut,), timeout=remaining)
        except asyncio.CancelledError:
            if not (cancelled or already) and cancel_bound is not None:
                deadline = loop.time() + cancel_bound
            cancelled = True
    if cancelled:
        if not fut.cancelled():
            fut.exception()  # mark it retrieved; the caller reads the outcome off `fut` itself
        raise asyncio.CancelledError
    return fut.result()


def _atomic_write_text(root: Path, path: Path, text: str) -> None:
    """Write ``text`` to ``path`` via a temp file + ``os.replace`` (atomic on the same dir), owner-only.

    **On any failure the temp is removed rather than left behind (BACKLOG #1678).** Without this, a
    write that raises — disk full is the realistic trigger and the blob is the large write — leaves a
    partial, PHI-bearing ciphertext in the uploads root that NO sweep can reach: ``list_files``,
    ``prune_expired`` and ``reseal_to_active`` all walk ``_iter_sidecars``, which yields ``.meta``
    names only. Catching ``BaseException`` is deliberate and matches ``config/connections_edit.py``'s
    twin: a cancellation must clean up too, and the original failure is re-raised untouched. The
    unlink's own errors are suppressed so a cleanup problem can never mask the real cause.

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
            os.replace(tmp, path)
        except BaseException:
            with contextlib.suppress(OSError):
                tmp.unlink(missing_ok=True)
            raise
