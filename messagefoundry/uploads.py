# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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
import hashlib
import json
import logging
import os
import re
import secrets
import time
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Protocol

from messagefoundry.parsing.peek import HL7PeekError, Peek
from messagefoundry.parsing.sniff import _looks_like_hl7, _lstrip_bom_ws
from messagefoundry.parsing.split import split_batch
from messagefoundry.store.content_search import SearchSpec, row_matches
from messagefoundry.store.crypto import Cipher, cell_aad

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
# audited; it is not used to locate anything on disk.
_FILENAME_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")
_MAX_FILENAME = 255


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
    so a shard mid-upload is visible to its siblings and the decision is exclusive across processes.

    Residual, stated precisely, and there are three:

    * **No ledger bound.** ``UploadStore(store=None)`` — the genuinely store-less construction path
      (embedding / tests) — keeps only the per-process lock, so the pre-#1112 bound applies there: at
      most **N-1 files** over, one per shard mid-write, each bounded by ``max_upload_bytes``.
    * **A leaked reservation.** A process killed between reserve and release never pays back, and its
      slot narrows that uploader's budget until the row goes idle for
      ``UPLOAD_RESERVATION_STALE_AFTER``. It errs toward refusing, not allowing, and it self-heals.
    * **A reclaimed live reservation.** If one uploader keeps reservations continuously outstanding
      for longer than that window, the staleness reset zeroes a row that was legitimately non-zero,
      which restores the N-1 bound above for that window. Never worse than the pre-#1112 behaviour.

    Still open, and out of scope here: the ledger is checked and paid back around the write, not in
    the same transaction as it, because the body lives on the filesystem rather than in the store."""


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

    **The id is immutable per ROW, which is not the same as per PERSON on AD.** ``_upsert_ad_user``
    resolves by ``sAMAccountName`` and mints a new ``user_id`` only when no mirror row survives, so a
    directory-side rename/recycle WITHOUT a MessageFoundry ``delete_user`` re-binds the EXISTING id
    to the new principal. A deploying site on AD would need the directory-immutable binding tracked
    as BACKLOG #1143 for that case; this field closes the local-account path and the AD path that
    goes through a delete."""

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
    base = _FILENAME_CTRL_RE.sub("", base).strip()
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


class UploadQuotaLedger(Protocol):
    """The ONE thing :class:`UploadStore` needs from the message store: an atomic, cross-process
    reservation of an uploader's in-flight upload budget (ASVS 2.3.4).

    Declared here as a structural protocol rather than importing ``store.base.Store``, so this module
    stays a leaf (see the module docstring). Every backend's ``Store`` satisfies it structurally —
    see :meth:`messagefoundry.store.base.Store.reserve_upload_quota` for the full contract."""

    async def reserve_upload_quota(
        self,
        uploader_id: str,
        *,
        files: int,
        size_bytes: int,
        max_files: int = 0,
        max_total_bytes: int = 0,
    ) -> bool: ...


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

    def _decrypt_blob(self, stored: str, file_id: str) -> bytes:
        b64 = self._cipher.decrypt(stored, aad=cell_aad("uploaded_file", "body", file_id))
        return base64.b64decode(b64)

    def _encrypt_meta(self, meta: UploadedFileMeta) -> str:
        return self._cipher.encrypt(
            json.dumps(asdict(meta)), aad=cell_aad("uploaded_file", "meta", meta.file_id)
        )

    def _decrypt_meta(self, stored: str, file_id: str) -> UploadedFileMeta:
        raw = self._cipher.decrypt(stored, aad=cell_aad("uploaded_file", "meta", file_id))
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

    def _scan_metas_sync(self) -> list[UploadedFileMeta]:
        """Walk the uploads root and decrypt every well-formed ``.meta`` sidecar (UNSORTED). A
        bad/foreign/undecryptable sidecar is skipped with a warning (never a body in the log), so a
        rotated-away key can neither sink the listing nor silently drop a quota/retention pass. Pure
        filesystem read — the caller runs it off the event loop."""
        root = self._root
        if not root.is_dir():
            return []
        out: list[UploadedFileMeta] = []
        for entry in root.iterdir():
            if not entry.name.endswith(_META_SUFFIX):
                continue
            fid = entry.name[: -len(_META_SUFFIX)]
            if not _FILE_ID_RE.match(fid):
                continue
            try:
                out.append(self._decrypt_meta(entry.read_text(encoding="utf-8"), fid))
            except Exception:  # noqa: BLE001 — a bad/foreign sidecar must not sink the scan
                _log.warning("skipping unreadable uploaded-file sidecar %s", fid)
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
        the uploader's file-count or aggregate-byte quota would be exceeded (ASVS 5.2.4)."""
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

        def _build_and_write() -> UploadedFileMeta:
            # Per-uploader quota (ASVS 5.2.4): scan the uploader's existing sidecars and refuse BEFORE
            # writing when this file would exceed their file-count or aggregate-byte cap. Runs in the same
            # off-loop thread as the write, and the caller holds _quota_lock across BOTH, so no second
            # upload in this process can read this count before the write consumes it (ASVS 2.3.4).
            # The scan is uncached, so shards sharing a dir enforce one budget rather than one each.
            # The residual the lock alone cannot cover — a sibling shard between ITS scan and ITS
            # write, invisible to this one — is covered by the ledger reservation the caller holds
            # around this whole call. See _reserve_across_shards and _on_disk_refusal.
            mine = [m for m in self._scan_metas_sync() if m.uploader_id == uploader_id]
            refusal = self._on_disk_refusal(
                uploader=uploader,
                observed_files=len(mine),
                observed_bytes=sum(m.size for m in mine),
                size=len(data),
            )
            if refusal is not None:
                raise refusal
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
            _atomic_write_text(root, blob_path, blob_ct)
            _atomic_write_text(root, meta_path, meta_ct)
            return meta

        # One critical section per process: quota check + write. See _quota_lock in __init__.
        # Inside it, one cross-PROCESS reservation around the same window (ASVS 2.3.4): the sidecar
        # scan below already sees every shard's files, so the only thing it CANNOT see is an upload
        # in flight on another shard — reserved but not yet landed. The reservation is what the other
        # shards see instead, and it is released the moment the file is on disk (or the write fails),
        # so a completed upload is counted by the scan and by nothing else.
        async with self._quota_lock:
            reserved = await self._reserve_across_shards(
                uploader_id=uploader_id, uploader=uploader, size=len(data)
            )
            try:
                return await asyncio.to_thread(_build_and_write)
            finally:
                if reserved:
                    await self._release_across_shards(uploader_id=uploader_id, size=len(data))

    async def _reserve_across_shards(self, *, uploader_id: str, uploader: str, size: int) -> bool:
        """Take this uploader's cross-shard in-flight reservation; return whether one is held.

        ``False`` means there is no ledger bound (the store-less construction path) — not that the
        reservation was refused. A refusal raises :class:`UploadQuotaError`, the same TYPE the
        in-process check raises, so the API's 409 + ``upload.reject_quota`` audit is unchanged; the
        message differs on purpose, so an operator can tell the two causes apart. A ledger error is
        NOT swallowed: the store being unreachable fails the upload closed.

        The headroom handed to the ledger is the cap minus what the (fleet-visible, uncached) sidecar
        scan observed, so the ledger only ever holds the in-flight remainder. That is a second scan
        per save — bounded by the uploader's own file count, off the event loop, and on the operator
        diagnostic surface rather than the data plane."""
        if self._ledger is None:
            return False
        observed_files, observed_bytes = await asyncio.to_thread(self._observed_sync, uploader_id)
        # Refuse an already-over-budget uploader HERE, with the on-disk wording, before consulting
        # the ledger. Otherwise the ledger (handed zero headroom) refuses first and its message
        # blames in-flight uploads on another shard that do not exist — a 409 that sends an operator
        # hunting a phantom. Same helper as the under-lock check, so the text is one string.
        refusal = self._on_disk_refusal(
            uploader=uploader,
            observed_files=observed_files,
            observed_bytes=observed_bytes,
            size=size,
        )
        if refusal is not None:
            raise refusal
        ok = await self._ledger.reserve_upload_quota(
            uploader_id,
            files=1,
            size_bytes=size,
            max_files=self._max_files_per_user - observed_files,
            max_total_bytes=self._max_total_bytes_per_user - observed_bytes,
        )
        if not ok:
            # Headroom was positive, so the only thing that can have consumed it is an upload in
            # flight on another shard. That is exactly the double-book this control exists to refuse.
            raise UploadQuotaError(
                f"uploader {uploader!r} has {observed_files} uploaded files holding "
                f"{observed_bytes} bytes, and another engine shard is mid-upload against the same "
                f"budget; the limits are {self._max_files_per_user} files / "
                f"{self._max_total_bytes_per_user} bytes"
            )
        return True

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
        """Pay the reservation back. Never raises: the file is already written (or already failed) by
        the time this runs, so turning a ledger blip into a failed upload would be strictly worse.
        A reservation that is never released is reclaimed once it goes stale — see
        :meth:`messagefoundry.store.base.Store.reserve_upload_quota`."""
        if self._ledger is None:
            return
        try:
            await self._ledger.reserve_upload_quota(
                uploader_id, files=-1, size_bytes=-size, max_files=0, max_total_bytes=0
            )
        except Exception:  # noqa: BLE001 — a release failure must not fail an upload that landed
            _log.warning(
                "could not release the cross-shard upload reservation for %s; it will be reclaimed "
                "when it goes stale",
                uploader_id,
                exc_info=True,
            )

    def _observed_sync(self, uploader_id: str) -> tuple[int, int]:
        """(file count, total bytes) already ON DISK for ``uploader_id`` — the fleet-visible half of
        the budget. Sync: the caller runs it off the event loop."""
        mine = [m for m in self._scan_metas_sync() if m.uploader_id == uploader_id]
        return len(mine), sum(m.size for m in mine)

    async def list_files(self) -> list[UploadedFileMeta]:
        """List all uploaded files (newest first). Undecryptable/foreign sidecars are skipped with a
        warning (never a body in the log), so a rotated-away key can't 500 the whole page."""

        def _scan() -> list[UploadedFileMeta]:
            out = self._scan_metas_sync()
            out.sort(key=lambda m: m.uploaded_at, reverse=True)
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
            # Remove the body first, then the sidecar (best-effort on the body — the sidecar is the
            # listing key, so once it is gone the file is invisible even if the blob lingers).
            blob_path.unlink(missing_ok=True)
            meta_path.unlink(missing_ok=True)
            return meta

        return await asyncio.to_thread(_delete)

    async def prune_expired(
        self, *, now: float | None = None, retention_days: int | None = None
    ) -> list[UploadedFileMeta]:
        """Age-based retention sweep (ASVS 5.2.4): delete every (blob, meta) pair whose ``uploaded_at`` is
        older than ``retention_days`` (default: the configured ``retention_days``) and return the pruned
        metadata rows (for the ``upload.prune`` audit — ``file_id`` + ``uploader`` only, never content).

        Idempotent: a re-run finds the already-deleted pairs gone and returns ``[]``. Undecryptable/foreign
        sidecars are skipped (never pruned — a rotated-away key must not silently destroy data). Runs off
        the event loop; the periodic runner + the opportunistic save-time sweep both drive it."""
        days = self._retention_days if retention_days is None else max(1, int(retention_days))
        cutoff = (time.time() if now is None else now) - days * _SECONDS_PER_DAY

        def _prune() -> list[UploadedFileMeta]:
            pruned: list[UploadedFileMeta] = []
            for meta in self._scan_metas_sync():
                if meta.uploaded_at >= cutoff:
                    continue
                # A sidecar whose id somehow fails the path guard is left alone (never blindly unlinked).
                try:
                    blob_path, meta_path = self._paths(meta.file_id)
                except UploadPathError:
                    continue
                blob_path.unlink(missing_ok=True)
                meta_path.unlink(missing_ok=True)
                pruned.append(meta)
            return pruned

        return await asyncio.to_thread(_prune)


# One prune sweep per hour is ample for a day-granularity retention window (the opportunistic save-time
# sweep covers the between-ticks case), and it keeps the background wakeups negligible.
_DEFAULT_PRUNE_INTERVAL_SECONDS = 3600.0


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
    ) -> None:
        self._store = store
        self._interval = float(interval_seconds)
        self._audit = audit
        self._clock = clock
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None

    def start(self) -> None:
        """Spawn the supervised prune loop (idempotent)."""
        if self._task is not None:
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._run())
        _log.info(
            "uploaded-logs retention prune enabled: older than %d days, every %gs",
            self._store.retention_days,
            self._interval,
        )

    async def stop(self) -> None:
        """Signal the loop and await its exit (idempotent)."""
        self._stop.set()
        task = self._task
        self._task = None
        if task is not None:
            task.cancel()
            try:  # noqa: SIM105
                await task
            except asyncio.CancelledError:
                pass

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

    async def run_once(self, now: float | None = None) -> list[UploadedFileMeta]:
        """Run one prune sweep for ``now`` (default: the injected clock), auditing each pruned file. The
        audit callback (contractually) never raises, but be defensive — one bad audit call must not abort
        the remaining prunes."""
        pruned = await self._store.prune_expired(now=self._clock() if now is None else now)
        for meta in pruned:
            if self._audit is None:
                continue
            try:
                await self._audit(meta)
            except Exception:
                _log.warning("uploaded-logs prune audit failed for %s", meta.file_id, exc_info=True)
        return pruned


def _atomic_write_text(root: Path, path: Path, text: str) -> None:
    """Write ``text`` to ``path`` via a temp file + ``os.replace`` (atomic on the same dir), owner-only."""
    tmp = root / f".{path.name}.{secrets.token_hex(4)}.tmp"
    tmp.write_text(text, encoding="utf-8")
    with contextlib.suppress(OSError):
        os.chmod(
            tmp, 0o600
        )  # best-effort (Windows / restricted FS) — directory ACL is the backstop
    os.replace(tmp, path)
