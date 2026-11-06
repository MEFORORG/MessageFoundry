# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Turnkey DR backup and restore: scheduled + on-demand config + SQLite-store backup, the
``restore-verify`` primitive, and the ``restore`` that puts an archive back (ADR 0049, #60).

:func:`run_restore` is the read half: it decrypts a ``.mfbak`` once, verifies the extracted
``store.db``, and places those exact bytes at a destination it refuses to overwrite (with an optional
config-bundle restore). ADR 0048's cold-seed activation is its consumer.

:class:`BackupRunner` is a sibling of the :class:`~messagefoundry.pipeline.retention.RetentionRunner`:
a **leader-gated, daily-clock** background singleton that, on its schedule (and on demand via the
``messagefoundry backup`` CLI), takes a **consistent SQLite snapshot** (read-only against the live
store — it never claims/mutates/resets/completes a staged-queue row), bundles a copy of the loaded
config dir, encrypts the whole thing to a single ``.mfbak`` AES-256-GCM archive **keyed by the existing
store DEK** (ADR 0019 KeyProvider), writes it to a configured **local/UNC** destination (no cloud
target), runs a **lightweight restore-verify** (open + ``integrity_check`` + row-count), **publishes
the canonical archive name by atomic rename** once every configured check has passed, applies keep-N
retention, and records **one PHI-free ``dr_backup`` audit row** per run. On failure it raises
``AlertSink.backup_failed`` and records a ``dr_backup`` ERROR row, leaving any prior good archive intact.

**Boundary (BACKLOG #52).** The store snapshot applies only to ``[store].backend = "sqlite"`` (the box
with no DBA). On postgres/sqlserver, ``store.snapshot_to`` raises :class:`DbaDelegatedError`; the runner
then backs up the **config bundle only** (or skips per ``[backup].config_only_on_server_db``).

**Invariants honored.** The snapshot is point-in-time + non-mutating (reliability + count-and-log
invariants intact); the archive is encrypted at rest (the config bundle can carry secrets, the snapshot
carries PHI); the destination is local/UNC (no new egress); the audit row + logs carry
counts/sizes/paths/fingerprints only — **never a message body or key bytes**.

Engine-side and dependency-light (stdlib + the store/crypto/alert seams), so it never pulls the API or
console into the engine. All blocking work (snapshot, tar, AEAD over a large file, disk I/O) runs OFF
the event loop via :func:`asyncio.to_thread`.
"""

from __future__ import annotations

import asyncio
import contextlib
import ctypes
import errno
import functools
import hmac
import io
import json
import logging
import os
import re
import shutil
import sqlite3
import stat
import sys
import tarfile
import tempfile
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, BinaryIO, cast

from messagefoundry.config import atomic_edit
from messagefoundry.config.settings import BackupSettings, StoreBackend, StoreSettings
from messagefoundry.config.tls_policy import HopPosture
from messagefoundry.controlchars import scrub_log_argument
from messagefoundry.last_resort import run_guarded
from messagefoundry.pipeline.alerts import AlertSink, LoggingAlertSink, utc_or_unknown
from messagefoundry.pipeline.cluster import ClusterCoordinator, NullCoordinator
from messagefoundry.redaction import json_loads_or_refusal, safe_exc, safe_text
from messagefoundry.restore_notice import RESTORE_NOTICE_POINTER, RESTORE_ROLLBACK_NOTICE
from messagefoundry.store import Store
from messagefoundry.store.backup_codec import (
    FORMAT_VERSION,
    BackupCodecError,
    BackupKeyMismatch,
    archive_key_id,
    decrypt_stream,
    encrypt_stream,
    key_fingerprint,
    read_header,
)
from messagefoundry.store.base import (
    DbaDelegatedError,
    StoreCipherConfigError,
    build_store_cipher,
    resolve_active_key,
    resolve_decrypt_keys,
)
from messagefoundry.store.cipher_cells import (
    CipherWalkInterrupted,
    connect_readonly,
    keyed_store_mismatch,
    read_cipher_cells,
    store_tables,
    with_first_failure,
)
from messagefoundry.store.crypto import (
    StoreKeylessError,
    _decode_key,
    store_data_key_id,
)
from messagefoundry.store.gcm_bound import bounded_cipher
from messagefoundry.store.schema_verify import SchemaMismatchError
from messagefoundry.transports.file import (
    _FLAG_BACKUP_SEMANTICS,
    _FLAG_OPEN_REPARSE_POINT,
    _NAME_SURROGATE,
    _SHARE_ALL,
    _WIN_UNSUPPORTED,
    _attribute_tag,
    _fd_for,
    _handle_final_path,
    _os_handle,
    _Replaced,
    _Unconfined,
    _win_create,
    _win_hold_dirs,
    _win_lstat,
    _win_open_file,
    _win_release,
)

__all__ = [
    "BackupRunner",
    "BackupResult",
    "RestoreResult",
    "VerifyResult",
    "BackupError",
    "RESTORE_NEEDS_A_DESTINATION",
    "run_restore",
    "run_restore_verify",
]

log = logging.getLogger(__name__)

#: Archive members inside the encrypted tar.
_STORE_MEMBER = "store.db"
_CONFIG_PREFIX = "config/"
_MANIFEST_MEMBER = "manifest.json"

#: Suffixes that hold an archive OUT of the keep-N candidate set (BACKLOG #1587).
#:
#: **The canonical name means this archive passed every check this instance was configured to run.**
#: So the bytes go to ``<canonical>.part`` and the canonical name is published by an atomic rename
#: afterwards: with ``verify_after_backup`` on, once the restore-verify passes; with it off,
#: write-completion is the bar and the rename follows the completed, fsynced write. An archive that
#: fails its verify is kept for diagnosis under ``<canonical>.failed``.
#:
#: Neither suffixed name can match :meth:`BackupRunner._prune_keep_n`'s pattern, which ends in the
#: archive extension — which is exactly why an archive that never earns the canonical name can never
#: spend a retention slot.
#:
#: **Both suffixes name a PHI-bearing file that NOTHING in the engine expires**, and that is the
#: price of the line above: a file keep-N cannot see is a file keep-N cannot prune. A ``.failed``
#: archive is left deliberately, for diagnosis. A ``.part`` is left by any abort between the write
#: and the rename — a dropped UNC share, a cancelled verify when the engine stops mid-backup, a
#: rename that fails — and on a box that restarts during its backup window those accumulate, one
#: full-size archive per incident. Clearing both is the operator's, and ``docs/PHI.md`` lists them
#: among the tiers with no retention rather than implying keep-N covers them.
#:
#: This is still strictly better than what it replaced: before BACKLOG #1587 those same aborts left
#: a TRUNCATED file wearing the canonical name, which keep-N then counted as a good backup.
#: The two archive extensions this runner writes: encrypted under the store DEK, or plaintext on
#: a box that set the audited ``[backup].allow_unencrypted`` escape. Named together because keep-N
#: retention has to span BOTH -- see :meth:`BackupRunner._prune_keep_n` (BACKLOG #1724).
#:
#: Orthogonal to the staging suffixes below: those come AFTER the extension, so a `.part` or
#: `.failed` file matches neither pattern. Widening to two extensions does not reopen #1587.
_ENCRYPTED_EXT = ".mfbak"
_PLAINTEXT_EXT = ".mfbak.plain"
_ARCHIVE_EXTS = (_ENCRYPTED_EXT, _PLAINTEXT_EXT)

_STAGING_SUFFIX = ".part"
_FAILED_SUFFIX = ".failed"

#: ASVS 5.2.3 restore-extract bound: refuse to stream a single tar member larger than this out of an
#: archive during restore-verify (defends the temp-dir extract against a forged archive that declares — or
#: streams — an absurd member size). Generous enough for a real single-box SQLite store snapshot; the
#: :func:`_extract_member` ``max_member_bytes`` parameter overrides it (tests pass a small cap).
_MAX_RESTORE_MEMBER_BYTES = 16 * 1024 * 1024 * 1024  # 16 GiB

#: The same ASVS 5.2.3 bound as :data:`_MAX_RESTORE_MEMBER_BYTES`, at the stage that consumes the temp
#: dir FIRST. Passed to ``decrypt_stream(..., max_plaintext_bytes=...)``; the codec takes it as a
#: parameter rather than declaring it, because the budget is the restore's and ``store/`` may not import
#: ``pipeline/`` (see ``store/backup_codec.py``'s module docstring).
#:
#: **POST-AUTHENTICATION on the ENCRYPTED path, and it must not be described as anything else.** Every
#: byte counted there has already passed its AES-GCM frame tag. The pre-authentication bounds are
#: ``MAX_HEADER_BYTES``, the declared ``chunk_size`` against ``MAX_CHUNK_SIZE``, and the per-frame
#: ``ctlen`` — all in the codec, all checked before the read they drive. That limb is a RESOURCE bound
#: against an archive sealed under a key the site legitimately holds: an oversized one, or one a
#: key-holder crafted. It defends nothing against an unauthenticated attacker, who cannot get a frame
#: past its tag to be counted at all.
#:
#: **The plaintext limb is the opposite and is the one that carries weight.** A no-key box restoring a
#: ``.mfbak.plain`` has no tag to fail on, so nothing authenticates the archive before it is staged and
#: this count is the ONLY thing standing between a forged file and the destination volume. Both limbs
#: of :func:`_restore_blocking` enforce it; the plaintext one did not, which is what made the sentence
#: below about "the first write" false where it mattered most.
#:
#: **Why the per-member cap does not already cover this.** :func:`_extract_member` bounds ``store.db``
#: so a lying header or stream cannot exhaust the extract temp dir — but it runs on ``archive.tar``,
#: which the decrypt has already written to that same temp dir in full. So the member cap is reached
#: only after the disk it protects is spent. This moves the bound to the first write — on the restore
#: path, both limbs of it. :func:`_verify_archive_blocking`'s own plaintext limb is still uncounted,
#: though since BACKLOG #1174 it too stages beside a SQLite store. Its copy is no larger than the
#: archive file it reads, and giving it this bound means adding an escape arm to that function's
#: ordered ``except`` block, which is a wider change than the one this constant documents.
#:
#: **Why twice the member cap, and why a multiple rather than a literal.** A conforming archive is one
#: ``store.db`` — admitted up to :data:`_MAX_RESTORE_MEMBER_BYTES`, above which the verify FAILs at the
#: member cap anyway — plus the config bundle, the manifest and tar framing. So the cumulative ceiling
#: cannot sit AT the member cap without refusing a store snapshot that is itself legal, and NOTHING
#: bounds the config bundle at the point this ceiling has to hold, so there is no exact second term to
#: add. Rather than fork a second number, the remainder gets the ceiling the store gets: one whole
#: extra maximal snapshot of headroom, which no real config dir (a few Python modules, a TOML, some
#: codesets) approaches. Written as a multiple so it TRACKS the member cap: a literal would silently
#: begin false-refusing legal archives the day that cap was raised.
#:
#: **:data:`_MAX_CONFIG_BYTES` is NOT that second term, and must not be read as one.** It is a
#: restore-EXTRACT bound: its only read is in :func:`_extract_config_members`, which runs solely when
#: ``--config-to`` was given and solely AFTER the decrypt this ceiling exists to bound. The build side
#: (:func:`_add_config_dir`) tars the config dir with no cap at all, and the verify path never extracts
#: config. So a `.mfbak` can legally carry a config bundle larger than ``_MAX_CONFIG_BYTES``; that is
#: caught on the way back out, not on the way in. Deriving this ceiling as ``member + config`` would
#: therefore bound the decrypt by a number the archive was never built against.
#:
#: A file-size cap (``max_plaintext_bytes = archive.stat().st_size``) looks like the exact bound and is
#: not one — it can never fire. Each frame carries 12 nonce + 4 length + 16 tag bytes around at most
#: ``chunk_size`` of plaintext, so a ``.mfbak`` is strictly LARGER than what it decrypts to. The format
#: cannot amplify, which is also why this is not a decompression-bomb defence.
_MAX_RESTORE_PLAINTEXT_BYTES = 2 * _MAX_RESTORE_MEMBER_BYTES

#: ASVS 5.2.3 manifest-read bound (BACKLOG #1570): refuse to read a ``manifest.json`` member larger
#: than this out of an archive. The store member is STREAMED to disk under its own cap; the manifest
#: is the one member parsed into memory (``json.loads`` holds the decoded object on top of the raw
#: bytes), so an unbounded read here is the only place a forged archive could balloon the verifying
#: process's memory. 1 MiB is many times the usual manifest this writer produces — a fixed field
#: set plus one row count per table in the snapshot's own schema (BACKLOG #1722; every table, not a
#: hand-picked sample — see :func:`_count_tables`). It is not a bound on what the writer can
#: produce: ``config_unreadable_files`` holds one relative path per file or folder the config
#: digest left out, uncapped (vault BACKLOG #3765). A list long enough to pass this cap writes an
#: archive this read refuses, so a verify reports FAIL and a restore refuses it.
#: ``config_skipped_files`` is capped at :data:`_MAX_SKIPPED_RECORDED` for that reason (vault
#: BACKLOG #5233).
_MAX_MANIFEST_BYTES = 1024 * 1024  # 1 MiB


#: The subject a ``cleanup`` alert carries (BACKLOG #1174, PR 1771 defect 5). A good run whose
#: staging could not be cleared is not a failed backup, so it must not share the failed-backup
#: subject: the notifier keys its realert throttle and the durable alert instance on type plus
#: subject, so a cleanup alert under ``dr_backup`` would silence a real failure for the cooldown,
#: or be silenced by one.
CLEANUP_ALERT_SUBJECT = "dr_backup:staging"


class BackupError(RuntimeError):
    """A backup run failed at a named phase (``snapshot``/``encrypt``/``write``/``verify``/
    ``destination``/``space``). The same alert also carries kind ``cleanup``, under
    :data:`CLEANUP_ALERT_SUBJECT`, for a good run whose staging could not be cleared (see
    :attr:`BackupResult.staging_leftover`). Carries the ``kind`` so the caller can pass it to ``AlertSink.backup_failed`` and
    record it in the ``dr_backup`` ERROR audit row — the message is the ``safe_exc``-scrubbed cause
    (PHI-free)."""

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind


@dataclass(frozen=True)
class VerifyResult:
    """The outcome of a restore-verify pass (lightweight or full). ``status`` is ``PASS`` / ``FAIL`` /
    ``KEY_MISMATCH``. PHI-free — counts + a reason only."""

    status: str
    integrity_ok: bool = False
    row_counts: dict[str, int] = field(default_factory=dict)
    manifest_counts: dict[str, int] = field(default_factory=dict)
    reason: str | None = None
    #: How many cipher-covered cells the FULL verify decrypted AND authenticated in the snapshot. A
    #: count, never a plaintext. ``0`` on a lightweight verify (it does not run the pass) and on an
    #: unencrypted store (there is nothing sealed to open) — so it distinguishes "read the PHI" from
    #: "opened the file", which is the whole difference a full verify is meant to prove.
    decrypted_cells: int = 0

    @property
    def ok(self) -> bool:
        return self.status == "PASS"


@dataclass(frozen=True)
class BackupResult:
    """What one backup run produced — returned for the CLI summary + the audit row + tests. PHI-free:
    paths, sizes, counts, and one-way fingerprints only (never a body or key bytes)."""

    archive_path: str
    archive_bytes: int
    snapshot_sha256: str
    config_only: bool
    snapshot_method: str
    key_id: str | None
    config_fingerprint: str | None
    row_counts: dict[str, int]
    verify: VerifyResult | None
    pruned: int
    encrypted: bool
    #: Set when the build's staging directory could not be shown free of plaintext after the archive
    #: was written (BACKLOG #1174): a PHI-free sentence naming it. The archive is good and published;
    #: the run alerts ``backup_failed`` with kind ``cleanup`` and records this in its audit row, and the
    #: next backup's sweep retries the directory.
    staging_leftover: str | None = None
    #: Whether the archive carries a config file under ``config/``, the dir this pass read, and,
    #: when it could not be read, the fault's class name (vault BACKLOG #3094), or
    #: :data:`CONFIG_WALK_ADDED_NOTHING` when the walk added no regular file (vault BACKLOG #5220).
    #: A full run with ``config_bundled`` false still succeeds: the store snapshot is worth keeping.
    config_bundled: bool = False
    config_dir: str | None = None
    config_bundle_error: str | None = None
    #: What ``config_fingerprint`` left out as unreadable (vault BACKLOG #3765): it covers the rest.
    #: :meth:`BackupRunner._inspect_config` says what reaches it on a bundled pass.
    config_unreadable_files: tuple[str, ...] = ()
    #: What the archive walk passed over (vault BACKLOG #5233), at most
    #: :data:`_MAX_SKIPPED_RECORDED` of them, and how many there were in all. What they mean for
    #: the archive is in the ``include_config`` row of ``docs/CONFIGURATION.md``.
    config_skipped_files: tuple[str, ...] = ()
    config_skipped_count: int = 0


#: The ``config_bundle_error`` a pass records when its config walk added no regular file, as for an
#: empty dir or one holding only links (vault BACKLOG #5220). Every other value there is an exception
#: class name, so this one is spelled so it cannot be read as one.
CONFIG_WALK_ADDED_NOTHING = "no-regular-file"

#: How many of the paths the archive walk passed over a pass records by name, and how many bytes
#: of the manifest's JSON they may take (vault BACKLOG #5233); the record also carries the total.
#: A config dir can hold any number of links, such as a linked package tree, and a list long
#: enough to pass :data:`_MAX_MANIFEST_BYTES` would make the whole archive, store snapshot
#: included, one that verify and restore refuse.
_MAX_SKIPPED_RECORDED = 1000
_MAX_SKIPPED_BYTES = 256 * 1024


def _capped_skips(skipped: tuple[str, ...]) -> tuple[str, ...]:
    """The leading ``skipped`` paths that fit both caps above, each measured as the manifest
    encodes it (``json.dumps`` escapes every non-ASCII character to six bytes)."""
    size = 0
    for i, rel in enumerate(skipped[:_MAX_SKIPPED_RECORDED]):
        size += len(json.dumps(rel)) + 2  # the separator ", "
        if size > _MAX_SKIPPED_BYTES:
            return skipped[:i]
    return skipped[:_MAX_SKIPPED_RECORDED]


@dataclass(frozen=True)
class _ConfigBundle:
    """What one pass found at its config dir; see :meth:`BackupRunner._inspect_config`."""

    path: Path | None
    bundled: bool
    fingerprint: str | None
    error: str | None
    #: The files and folders ``fingerprint`` left out, so a reader does not take it for the digest
    #: of the whole bundle (vault BACKLOG #3765).
    left_out: tuple[str, ...] = ()
    #: What the archive walk passed over, the first :data:`_MAX_SKIPPED_RECORDED` of them, and how
    #: many in all; set by :meth:`after_walk` (vault BACKLOG #5233).
    skipped: tuple[str, ...] = ()
    skipped_count: int = 0

    def after_walk(self, added: int, skipped: tuple[str, ...]) -> _ConfigBundle:
        """This bundle as the record states it once the walk has run, with what the walk passed
        over: a bundled pass whose walk added no regular file carries no config, so it is recorded
        as not bundled, with :data:`CONFIG_WALK_ADDED_NOTHING` as its error (vault BACKLOG
        #5220)."""
        walked = replace(self, skipped=_capped_skips(skipped), skipped_count=len(skipped))
        if self.bundled and added == 0:
            return replace(walked, bundled=False, error=CONFIG_WALK_ADDED_NOTHING)
        return walked

    def manifest_fields(self) -> dict[str, object]:
        """The fields the manifest and the ``dr_backup`` audit row both carry: a directory path, a
        digest, an exception class name, and relative paths from the operator's config dir. No
        message content, but a path carries whatever name the operator gave the file."""
        return {
            "config_fingerprint": self.fingerprint,
            "config_bundled": self.bundled,
            # Named on a fault too, so the record says which directory failed.
            "config_dir": str(self.path) if self.path is not None else None,
            "config_bundle_error": self.error,
            "config_unreadable_files": list(self.left_out),
            "config_skipped_files": list(self.skipped),
            "config_skipped_count": self.skipped_count,
        }


@dataclass(frozen=True)
class RestoreResult:
    """What one ``messagefoundry restore`` produced — the CLI summary + tests. PHI-free: paths, sizes,
    counts, and one-way fingerprints only (never a body or key bytes)."""

    archive_path: str
    #: ``None`` when only a CONFIG-ONLY archive's config bundle was restored (vault BACKLOG #5233);
    #: ``store_bytes`` is then 0 and ``row_counts`` empty.
    store_path: str | None
    store_bytes: int
    row_counts: dict[str, int]
    encrypted: bool
    key_id: str | None
    config_dir: str | None
    config_files: int
    #: BACKLOG #2614: the SHA-256 of the archive bytes this restore read, the archive's own
    #: ``created_utc`` as epoch seconds, and the newest audit row it held; each time ``None`` when
    #: the archive did not say. The restore writes them into the store's restore marker.
    archive_sha256: str
    archive_created_at: float | None = None
    last_audit_at: float | None = None
    #: How many open sessions the restore ended in the store it placed (BACKLOG #2614).
    sessions_revoked: int = 0


class _HashingReader:
    """A read-only view of ``raw`` that hashes every byte it hands out (BACKLOG #2614). The restore
    reads the archive through it, so the hash it records is of the bytes it decrypted, not of a
    second read that a replaced file could answer differently."""

    def __init__(self, raw: io.BufferedReader) -> None:
        import hashlib

        self._raw = raw
        self.digest = hashlib.sha256()

    def read(self, size: int = -1) -> bytes:
        data = self._raw.read(size)
        self.digest.update(data)
        return data


def _manifest_time(manifest: dict[str, object]) -> float | None:
    """The archive's ``created_utc`` as epoch seconds, or ``None`` when it is absent or not the
    ``YYYY-MM-DDTHH:MM:SSZ`` the backup writes (BACKLOG #2614)."""
    import calendar

    value = manifest.get("created_utc")
    if not isinstance(value, str):
        return None
    try:
        return float(calendar.timegm(time.strptime(value, "%Y-%m-%dT%H:%M:%SZ")))
    except ValueError:
        return None


class BackupRunner:
    """Engine-managed DR backup (ADR 0049). Construct with the store + ``[backup]`` settings + the store
    settings (for the key source) + the loaded config dir; call :meth:`start`/:meth:`stop` for the
    supervised daily loop, or :meth:`run_once` for a single deterministic pass (the CLI + tests).

    ``config_dir`` may be a callable, read once at the start of each pass. The engine passes its
    running config dir that way, so after an operator reload from another root the archive carries,
    and fingerprints, the directory the running graph came from (vault BACKLOG #3094)."""

    def __init__(
        self,
        store: Store,
        settings: BackupSettings,
        *,
        store_settings: object,
        config_dir: str | Path | Callable[[], str | Path | None] | None,
        engine_version: str = "",
        instance: str = "",
        alert_sink: AlertSink | None = None,
        clock: Callable[[], float] = time.time,
        coordinator: ClusterCoordinator | None = None,
        hop_posture: HopPosture | None = None,
    ) -> None:
        self._store = store
        self._settings = settings
        # The store settings carry the KeyProvider seam (ADR 0019) — the archive's KEY SOURCE. Typed
        # loosely to avoid importing StoreSettings here; resolve_active_key takes it.
        self._store_settings = store_settings
        # The instance posture, for the Vault hop a key resolve or a full verify can dial on every
        # pass (vault BACKLOG #2983). The engine and the `backup` command pass their own. `None`
        # counts as enforcing on that hop.
        self._hop_posture = hop_posture
        self._config_dir_source = config_dir
        self._engine_version = engine_version
        self._instance = instance
        self._alert_sink: AlertSink = alert_sink or LoggingAlertSink()
        self._clock = clock
        # Backup is a leader-only WRITE singleton: it reads PHI, writes audit rows, writes archives to a
        # SHARED destination, and prunes keep-N. Under active-passive HA only the leader backs up, or HA
        # nodes would race the destination dir + corrupt the keep-N prune. Default NullCoordinator (always
        # leader) keeps single-node byte-identical.
        self._coordinator: ClusterCoordinator = coordinator or NullCoordinator()
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        self._last_backup_day: str | None = None
        # ASVS 11.3.4: AES-GCM frame counts reported by the codec from the worker thread, drained and
        # charged to the key's persisted invocation bound after each run. Backup is a leader-only
        # singleton with one run in flight at a time, so a plain list is sufficient.
        #
        # Each entry carries the cipher_meta id of the key its frames were sealed under (ADR 0196
        # AC-6). A build cancelled on the loop keeps running on its worker thread and reports its
        # frames AFTER this run's charge has run; the next run then charges them under the id they
        # were sealed under, never under its own. The lock covers the append (worker thread) and the
        # drain (event loop), so a late report cannot land in a list that was just swapped out.
        self._frames: list[tuple[str, int]] = []
        self._frames_lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return self._settings.enabled

    # --- lifecycle -----------------------------------------------------------

    def start(self) -> None:
        """Spawn the supervised daily-clock loop (no-op when ``[backup].enabled`` is false, or when no
        schedule is set — on-demand-only deployments have nothing to loop)."""
        if self._task is not None:
            return
        if not self._settings.enabled or self._settings.schedule_time() is None:
            log.debug("DR backup loop not started (disabled or on-demand-only)")
            return
        self._preflight_destination()
        self._stop.clear()
        self._task = asyncio.create_task(self._run())
        log.info(
            "DR backup enabled: destination=%r schedule_at=%r retention_keep=%d snapshot_method=%r",
            self._settings.destination,
            self._settings.schedule_at,
            self._settings.retention_keep,
            self._settings.snapshot_method,
        )

    async def stop(self) -> None:
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
        # One pass per due day; an error in a pass is alerted + logged and the loop continues (a backup
        # hiccup must never take the engine down). Cooperatively cancellable via _stop.
        while not self._stop.is_set():
            try:
                if self._backup_due(self._clock()):
                    await self.run_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                # run_once already alerts + audits a failure; this catch is the last-resort guard so the
                # loop survives even an unexpected error path. No body is logged.
                log.exception("DR backup pass failed; will retry next interval")
            await self._sleep(60.0)  # check the daily clock once a minute

    async def _sleep(self, delay: float) -> None:
        try:  # noqa: SIM105
            await asyncio.wait_for(self._stop.wait(), delay)
        except TimeoutError:
            pass

    def _backup_due(self, now: float) -> bool:
        """True when the daily backup time is configured, the local clock has reached it, and we haven't
        already backed up today (at-most-once per local day; a late start that day still catches up)."""
        target = self._settings.schedule_time()
        if target is None:
            return False
        if not self._coordinator.is_leader():
            return False  # leader-gated: a follower never backs up the shared destination (AC-12)
        lt = time.localtime(now)
        reached = (lt.tm_hour, lt.tm_min) >= target
        return reached and self._last_backup_day != _day_key(now)

    # --- one pass ------------------------------------------------------------

    async def run_once(
        self, now: float | None = None, *, force_config_only: bool = False
    ) -> BackupResult | None:
        """One backup pass: snapshot → bundle → encrypt → write → verify → publish → prune → audit.

        ``publish`` is the atomic rename onto the canonical archive name. It sits AFTER the verify
        on purpose, and that ordering is what keeps a failed archive out of keep-N (BACKLOG #1587);
        the rule it follows is stated once, at :data:`_STAGING_SUFFIX`.

        Leader-gated (AC-12): a non-leader returns ``None`` without touching the store or the shared
        destination (so in a cluster exactly one node backs up). On success records a ``dr_backup`` audit
        row + returns the :class:`BackupResult`; on failure records a ``dr_backup`` ERROR row, raises
        ``AlertSink.backup_failed``, leaves any prior good archive intact, and re-raises
        :class:`BackupError`. ``force_config_only`` (the CLI ``--config-only`` flag) backs up the config
        bundle only even on a SQLite store (a server-DB store is always config-only per the boundary)."""
        if not self._coordinator.is_leader():
            return None
        now = self._clock() if now is None else now
        self._last_backup_day = _day_key(now)  # advance the daily cadence even if this pass fails
        try:
            result = await self._do_backup(now, force_config_only=force_config_only)
        except BackupError as exc:
            await self._record_failure(exc.kind, exc, now)
            raise
        except Exception as exc:  # any unexpected failure → a generic backup_failed (no body leaks)
            await self._record_failure("backup", exc, now)
            raise BackupError("backup", safe_exc(exc)) from exc
        await self._record_success(result, now)
        return result

    async def _do_backup(self, now: float, *, force_config_only: bool = False) -> BackupResult:
        s = self._settings
        # Decide config-only vs full per backend + setting (AC-7). SQLite → full store snapshot; a
        # server-DB store → config-only (or skip) because the DB backup is DBA-delegated (#52). The CLI
        # --config-only flag forces config-only even on SQLite.
        config_only = force_config_only or self._is_server_db()
        # Read once, so the space check, the archive's config/ members and its fingerprint all name
        # one directory even if a reload lands during the pass.
        config_dir = self._current_config_dir()
        if self._is_server_db() and not s.config_only_on_server_db:
            raise BackupError(
                "snapshot",
                f"store backend {self._backend_value()!r} is DBA-delegated (BACKLOG #52) and "
                "[backup].config_only_on_server_db=false — nothing to back up; the DB is the DBA's job",
            )
        if config_only and (config_dir is None or not s.include_config):
            # A config-only archive without its config holds nothing to restore, yet it would verify
            # and take a keep-N slot from an archive that does (vault BACKLOG #5220). Refused before
            # any I/O; a dir that cannot be listed, and a walk that adds no file, are refused below.
            why = (
                "no config dir is loaded"
                if config_dir is None
                else "[backup].include_config is false"
            )
            raise BackupError("snapshot", f"config-only backup: {why}; nothing to archive")

        dest_dir = Path(s.destination)
        self._ensure_destination(dest_dir)

        # The key SOURCE is the existing store DEK (ADR 0019). Resolve it the same way open_store does.
        key = self._resolve_key()
        if key is None and not s.allow_unencrypted:
            # Fail-closed: a no-key instance refuses to write a cleartext archive unless the explicit,
            # audited [backup].allow_unencrypted escape is set (parallel to [store].allow_unencrypted_phi).
            raise BackupError(
                "encrypt",
                "no store encryption key is configured; refusing to write an UNENCRYPTED .mfbak archive "
                "(configure a store encryption key, such as MEFOR_STORE_ENCRYPTION_KEY, or set "
                "[backup].allow_unencrypted=true to accept a cleartext archive, which can hold PHI)",
            )
        key_id = key_fingerprint(key) if key is not None else None
        # ADR 0196: seal the frames under the live store's data sub-key (the header records the salt,
        # so the DR site derives it from the DEK alone). The build charges them to THAT key's row (AC-6).
        # A store on the frozen v1 writer has no salt: the frames are then sealed under the DEK and
        # charged to the DEK's row, which is where that store's own values are counted too.
        salt = self._store_salt() if key is not None else None

        ext = _ENCRYPTED_EXT if key is not None else _PLAINTEXT_EXT
        stamp = _utc_stamp(now)
        inst = _safe_segment(self._instance) or "instance"
        archive_path = dest_dir / f"mefor-backup-{inst}-{stamp}{ext}"
        # The bytes are written HERE, not at the canonical name; see _STAGING_SUFFIX for the rule.
        staging_path = archive_path.with_name(archive_path.name + _STAGING_SUFFIX)
        for occupied in (archive_path, staging_path):
            # Extremely unlikely (1s granularity) — never clobber a prior archive, nor a staging
            # file some other pass is still writing.
            if occupied.exists():
                raise BackupError("write", f"archive already exists: {occupied}")

        # Build everything in one staging directory: the data dir on a SQLite store, `.mefor-staging`
        # under the destination otherwise (BACKLOG #1174; see `_open_staging`). The sweep removes what
        # a crashed or killed run left in the staging root. It goes by each directory's lock, never by
        # age, so a sibling engine shard's live run survives it, and only by this account's owner:
        # `.mefor-staging` inherits whatever the destination grants, so another account could plant a
        # directory there for the teardown to run on (BACKLOG #2420). It runs first, keyed on the
        # owner a new entry in the staging root gets, learned by `_probe_owner` from a probe it creates
        # and removes there, and reads through the descriptor it created, so a rename in the staging
        # root cannot choose it. Never the process's own owner as such: on a share whose
        # server sets the owner, a directory carrying that one may have been made by another
        # principal (BACKLOG #4988). The probe is a write, so on a volume it cannot be created on,
        # such as one a killed run filled, `_fallback_root_owner` keys the sweep on the process's
        # owner only when the staging root itself carries it, which a root this account made on such
        # a share does not. When neither answers, this sweep is off; the space check below probes once more when
        # the run is short, and this run's own directory's owner sweeps once it is open. A run whose
        # open fails still sweeps. Off the loop, like the rest.
        staging_root, secure = self._staging_root(dest_dir)
        process_owner = await asyncio.to_thread(_process_owner)
        probed = await asyncio.to_thread(_probe_owner, staging_root)
        root_owner = probed
        if root_owner is None:
            root_owner = await asyncio.to_thread(_fallback_root_owner, staging_root, process_owner)
        swept_by: list[object] = []
        if root_owner is not None:
            swept_by.append(root_owner)
            await asyncio.to_thread(_sweep_owned, staging_root, root_owner, own=None)
        # A standalone verify stages in the OS temp dir, so a killed cold-seed on this engine leaves
        # its decrypted copy there. Each backup sweeps it too, by the owner a new directory there
        # gets, as `_process_owner` reads it: a verify this account ran there made its directory
        # with that owner, whatever owner a share's server gives this run's staging directory. On
        # Windows that read is a probe in the OS temp dir, and when it answers None this sweep is
        # off for this run.
        await asyncio.to_thread(_sweep_os_temp, process_owner)
        # After those sweeps, which free what dead runs left when they ran, and before this run's
        # directory is opened or any of its bytes is staged. It is not before every write: the
        # owner probes, above and below on a short run, are written first. A run that cannot fit
        # fails here with kind `space`, naming the volume, not half-way through a multi-GB write.
        shortfall = await asyncio.to_thread(
            self._space_shortfall,
            staging_root,
            dest_dir,
            config_only=config_only,
            config_dir=config_dir,
        )
        if shortfall is not None and probed is None:
            # The early probe answered None, so the early sweep may have missed what this account's
            # killed run left, and it would refuse every later run until someone deleted it. Probe
            # once more and, only when that owner is not one a sweep above already went by, sweep by
            # it and check once more whatever the sweep counted: a leftover it emptied but could not
            # remove is not counted, yet frees the space. No run directory is open yet, so a refusal
            # still leaves no lock or marker. When this probe cannot be created either, the refusal
            # stands.
            again = await asyncio.to_thread(_probe_owner, staging_root)
            if again is not None and again not in swept_by:
                swept_by.append(again)
                await asyncio.to_thread(_sweep_owned, staging_root, again, own=None)
                shortfall = await asyncio.to_thread(
                    self._space_shortfall,
                    staging_root,
                    dest_dir,
                    config_only=config_only,
                    config_dir=config_dir,
                )
        if shortfall is not None:
            raise BackupError(
                "space", f"not enough free space to stage this backup: it {shortfall}"
            )
        loop = asyncio.get_running_loop()
        opening = loop.run_in_executor(
            None,
            functools.partial(_open_staging, staging_root, _BACKUP_STAGING_PREFIX, secure=secure),
        )
        try:
            work = await asyncio.shield(opening)
        except asyncio.CancelledError:
            # The open may still land after this cancel. Release it then, or its lock would stay held
            # and its directory would look live to every sweep for the life of the process.
            opening.add_done_callback(_release_when_opened)
            raise
        except StagingNotPrivateError as exc:
            # Its own text leads, whole: it names the directory and the fix, and holds no PHI.
            raise BackupError("write", str(exc)) from exc
        except OSError as exc:
            raise BackupError(
                "write",
                f"could not create a staging directory under {staging_root}: {safe_exc(exc)}",
            ) from exc

        # The CONSISTENT SNAPSHOT must run on the ENGINE event loop (store.snapshot_to takes the store
        # lock for its WAL checkpoint and drives aiosqlite, which is bound to this loop — it does its own
        # off-loop copy, off the store lock since BACKLOG #1937). The CPU/IO-heavy tar + AEAD then run
        # OFF the loop in a worker thread over the snapshot file (never blocking asyncio, never the whole
        # store in RAM).
        #
        # The staging directory holds plaintext, so it is released on every path. Once the worker has
        # claimed it, the WORKER releases it, after it has let go of the files: a build cancelled on the
        # loop keeps running on its thread, and tearing the directory down under it would leave what it
        # writes afterwards behind. The loop's own release covers only the paths the worker never ran.
        staging_leftover: str | None = None
        try:
            # Swept again by this run's own directory's owner only where no sweep above went by it,
            # such as where no staging-root probe above could be created. Read from the descriptor
            # of the lock file this run created there, never by path, so a rename in the staging
            # root cannot choose it.
            own_owner = await asyncio.to_thread(work.owner)
            if own_owner is None:
                log.warning(
                    "DR staging: cannot read the owner of %s, so %s is not swept",
                    work.path,
                    staging_root,
                )
            elif own_owner not in swept_by:
                await asyncio.to_thread(_sweep_owned, staging_root, own_owner, own=work.path)
            snap_path: Path | None = None
            if not config_only:
                snap_path = work.path / _STORE_MEMBER
                try:
                    await self._store.snapshot_to(snap_path, method=s.snapshot_method)
                except (
                    DbaDelegatedError
                ) as exc:  # defensive: config_only already handles the server DB
                    raise BackupError("snapshot", safe_exc(exc)) from exc
                except (OSError, ValueError, FileExistsError, sqlite3.Error) as exc:
                    # sqlite3.Error: since BACKLOG #1937 the copy opens its own read-only connection,
                    # and a failure there is a snapshot failure too, not a generic backup one.
                    raise BackupError("snapshot", safe_exc(exc)) from exc
                # The snapshot's real size is known now, and it is already on disk, so this asks only
                # for what is still to come: the tar beside it and the archive at the destination.
                # Inside the try, so a refusal here still releases the staging directory.
                shortfall = await asyncio.to_thread(
                    self._space_shortfall_after_snapshot,
                    snap_path,
                    work.path,
                    dest_dir,
                    config_dir=config_dir,
                )
                if shortfall is not None:
                    raise BackupError(
                        "space", f"not enough free space to finish this backup: it {shortfall}"
                    )
            # Read once, off the loop, and recorded in both the manifest and the audit row.
            bundle = await asyncio.to_thread(self._inspect_config, config_dir)
            if config_only and bundle.error is not None:
                # A config-only archive without its config holds nothing to restore, yet it would
                # verify and take a keep-N slot from an archive that does. It fails instead. A walk
                # that adds no file is refused in the build, which is where the walk runs.
                raise BackupError(
                    "snapshot",
                    f"config-only backup: the config dir {config_dir} could not be read "
                    f"({bundle.error}); nothing to archive",
                )
            try:
                (
                    snapshot_sha256,
                    row_counts,
                    archive_bytes,
                    # What the archive carries, as its manifest records it (vault BACKLOG #5220,
                    # #5233).
                    bundle,
                    staging_leftover,
                ) = await asyncio.to_thread(
                    self._build_in_staging,
                    work,
                    out_path=staging_path,
                    snap_path=snap_path,
                    key=key,
                    key_id=key_id,
                    salt=salt,
                    config_only=config_only,
                    now=now,
                    bundle=bundle,
                )
            except (OSError, BackupCodecError) as exc:
                kind = "write" if isinstance(exc, OSError) else "encrypt"
                raise BackupError(kind, safe_exc(exc)) from exc
            finally:
                # In a `finally` (ADR 0196 AC-6): a build that dies after sealing some frames has still
                # spent them under this run's key. Charged after the run only on success, they stayed
                # queued in `_frames` and were charged by the NEXT run that finished -- under its own
                # key, if the key had been rotated in between -- or never, for a one-shot backup.
                await self._charge_archive_invocations()
        except BaseException as exc:
            # Submitted to the executor at once and shielded: a second cancellation must not cancel
            # the release before it starts, which would leave the lock held and the directory
            # looking live to every sweep for the life of the process.
            release = loop.run_in_executor(
                None, functools.partial(work.release, unless_claimed=True)
            )
            leftover = await asyncio.shield(release)
            if leftover is None:
                raise
            if isinstance(exc, BackupError):
                # First, so the 200-character cut the failure record applies keeps the directory.
                raise BackupError(exc.kind, f"{leftover}; the run failed: {exc}") from exc
            exc.add_note(leftover)
            raise

        verify: VerifyResult | None = None
        try:
            verify = await self._verify_and_publish(
                staging_path,
                archive_path,
                key=key,
                staging_root=staging_root,
                secure=secure,
            )
        except BackupError as exc:
            if staging_leftover is None:
                raise
            # The staging teardown failed too; that must not ride only in the log. It leads, so the
            # 200-character cut the failure record applies keeps the directory.
            raise BackupError(exc.kind, f"{staging_leftover}; the run failed: {exc}") from exc

        # keep-N prune runs only after that rename, so the candidate set contains this archive and
        # every earlier archive that also passed — and nothing that failed (AC-6).
        pruned = self._prune_keep_n(dest_dir, inst, just_written=archive_path)

        return BackupResult(
            archive_path=str(archive_path),
            archive_bytes=archive_bytes,
            snapshot_sha256=snapshot_sha256,
            config_only=config_only,
            snapshot_method=s.snapshot_method,
            key_id=key_id,
            config_fingerprint=bundle.fingerprint,
            row_counts=row_counts,
            verify=verify,
            pruned=pruned,
            encrypted=key is not None,
            staging_leftover=staging_leftover,
            config_bundled=bundle.bundled,
            config_dir=str(bundle.path) if bundle.path is not None else None,
            config_bundle_error=bundle.error,
            config_unreadable_files=bundle.left_out,
            config_skipped_files=bundle.skipped,
            config_skipped_count=bundle.skipped_count,
        )

    async def _verify_and_publish(
        self,
        staging_path: Path,
        archive_path: Path,
        *,
        key: bytes | None,
        staging_root: Path,
        secure: bool,
    ) -> VerifyResult | None:
        """Restore-verify the written archive when configured, then publish it under its canonical
        name. Raises :class:`BackupError` when either fails."""
        s = self._settings
        verify: VerifyResult | None = None
        if s.verify_after_backup:
            # The just-written archive is sealed under the active key, so the active key is the only
            # candidate the post-write verify needs (the retired-key keyring matters only for the
            # standalone restore-verify of an OLDER archive — run_restore_verify, AC-5).
            try:
                verify = await asyncio.to_thread(
                    _verify_archive_blocking,
                    archive_path=str(staging_path),
                    keys=[key] if key is not None else [],
                    full=s.full_restore_verify,
                    allow_unencrypted=s.allow_unencrypted,
                    # The LIVE store settings, so a full verify opens the snapshot under this
                    # instance's real cipher/keyring/provider rather than a bare default (see
                    # _full_open_check).
                    store_settings=self._store_settings,
                    # The same staging root as the build, so the next backup's sweep covers both.
                    staging_root=staging_root,
                    secure=secure,
                    posture=self._hop_posture,
                )
            except StagingNotPrivateError as exc:
                # Not a verdict on the archive: it stays at its staging name, unpublished and not
                # quarantined, and the run fails naming both.
                # The archive's location leads, so the 200-character cut keeps it.
                raise BackupError(
                    "write",
                    f"archive written but not verified, left at {staging_path.name}: {exc}",
                ) from exc
            if not verify.ok:
                # A verify FAIL means the archive is unusable, so it never earns the canonical name
                # (AC-6). Skipping only THIS run's prune — what this path used to do — does not
                # achieve that: the bad archive kept the canonical name, so the NEXT run's prune
                # counted it as a retention slot and evicted an older GOOD copy instead
                # (BACKLOG #1587). Deferring the eviction one run is not preventing it.
                kept = self._keep_failed_archive(staging_path, archive_path)
                raise BackupError(
                    "verify",
                    f"restore-verify {verify.status}: "
                    f"{verify.reason or 'archive did not verify'} "
                    f"(kept for diagnosis as {kept.name}; it holds no retention slot, and nothing "
                    "in the engine expires it)",
                )

        # Only now does the archive earn the canonical name.
        self._publish_archive(staging_path, archive_path)
        return verify

    def _store_salt(self) -> bytes | None:
        """The live store's salt, whose data sub-key the archive frames are sealed under (ADR 0196), or
        ``None`` when its cipher has none (the frozen v1 writer, a keyless or ``vault_transit`` store)."""
        bound = bounded_cipher(self._store.cipher())
        return bound.store_salt if bound is not None else None

    def _record_frames(self, key_id: str, count: int) -> None:
        """The codec's ``on_frames`` for one run, called on the worker thread."""
        with self._frames_lock:
            self._frames.append((key_id, count))

    async def _charge_archive_invocations(self) -> None:
        """Charge this run's DR-frame AES-GCM invocations to the PERSISTED invocation bound of the key
        they were sealed under (ASVS 11.3.4; ADR 0196 AC-6) — a post-run aggregate add, since the
        frames are written on a worker thread that holds no store handle. Each queued entry is charged
        to its own key id: the store data sub-key's for a salted archive, the DEK's for an unsalted
        one -- including frames a cancelled earlier run reported late.

        Without this the bound under-counts by every backup run: ``backup_codec`` constructs its own
        ``AESGCM`` over the same key bytes and never reaches ``AesGcmCipher._count_invocation``, yet a 10 GB
        store at the 1 MiB default chunk is ~10k invocations per run under that same key. Best-effort —
        an accounting failure must never fail an otherwise-successful backup."""
        with self._frames_lock:
            pending, self._frames = self._frames, []
        per_key: dict[str, int] = {}
        for key_id, count in pending:
            per_key[key_id] = per_key.get(key_id, 0) + count
        unpaid = {key_id: frames for key_id, frames in per_key.items() if frames}
        try:
            for key_id, frames in list(unpaid.items()):
                try:
                    await self._store.add_cipher_invocations(key_id, frames)
                except Exception:  # noqa: BLE001 — advisory accounting; never fail a good backup
                    log.warning(
                        "DR backup: could not charge %d archive frame(s) to the AES-GCM invocation "
                        "bound; they stay queued for this runner's next run",
                        frames,
                        exc_info=True,
                    )
                    continue
                del unpaid[key_id]
        finally:
            # Put back what was not charged, on a failure or a cancellation mid-loop: dropped, the
            # key's persisted count would under-read by every frame, the one direction the bound must
            # not drift. A charge cancelled after it committed is charged twice, which errs high.
            if unpaid:
                with self._frames_lock:
                    self._frames.extend(unpaid.items())

    # --- publishing the canonical name ---------------------------------------

    def _publish_archive(self, staging_path: Path, archive_path: Path) -> None:
        """Publish a completed archive under its canonical name, by atomic rename.

        The rule that decides WHEN this may be called is stated once, at :data:`_STAGING_SUFFIX`.
        What this method adds: until the rename lands, nothing at the destination carries a name
        keep-N counts, so a crash mid-write leaves an excluded ``.part`` file rather than a
        truncated file wearing an archive's name."""
        try:
            os.replace(staging_path, archive_path)
        except OSError as exc:
            # Name the staging file. This arm strands an archive that PASSED every check under a
            # name keep-N cannot see, so an operator who is not told where it is has no way to find
            # a good backup that the run reported as failed.
            raise BackupError(
                "write",
                f"could not publish the completed archive as {archive_path.name}: "
                f"{safe_exc(exc)} (the verified archive is at {staging_path.name})",
            ) from exc

    def _keep_failed_archive(self, staging_path: Path, archive_path: Path) -> Path:
        """Move a verify-failed archive to its diagnostic name; return where it ended up.

        **Kept, never deleted** — the archive that would not verify is the evidence for why it would
        not. This is the half of the write-temp-then-publish pattern that deliberately diverges from
        :class:`~messagefoundry.transports.file.FileDestination`, which unlinks its temp in a
        ``finally``: a dropped delivery file is debris, a DR archive that failed its restore-verify
        is a diagnosis.

        The consequence, stated rather than quietly bounded: the name is outside the keep-N
        candidate set, so **nothing in the engine ever expires it**. A run of verify failures
        accumulates sealed archives at the destination until an operator clears them. Auto-deleting
        them on some second cap would defeat keeping them at all, and pruning them by keep-N is the
        defect this whole path exists to fix. ``docs/PHI.md`` carries the same caveat beside the
        keep-N claim, because these files are PHI-bearing (sealed under the store DEK, exactly like
        a good archive — the at-rest protection is unchanged; only the retention bound is)."""
        failed_path = archive_path.with_name(archive_path.name + _FAILED_SUFFIX)
        try:
            os.replace(staging_path, failed_path)
        except OSError:
            # The staging suffix is excluded from keep-N too, so a failed rename still leaves the
            # archive outside the candidate set — the diagnosis just has a less obvious filename.
            # Log it and return the real path; this must never displace the verify failure the
            # caller is about to raise.
            log.warning(
                "DR backup: could not rename the verify-failed archive to %s; it stays at %s",
                failed_path.name,
                staging_path.name,
                exc_info=True,
            )
            return staging_path
        return failed_path

    # --- archive build (worker thread; no event loop, no store await) --------

    def _build_in_staging(
        self,
        work: _Staging,
        *,
        out_path: Path,
        snap_path: Path | None,
        key: bytes | None,
        key_id: str | None,
        config_only: bool,
        now: float,
        bundle: _ConfigBundle,
        salt: bytes | None = None,
    ) -> tuple[str, dict[str, int], int, _ConfigBundle, str | None]:
        """Run :meth:`_build_archive_blocking` in ``work`` and release ``work`` on every exit, from this
        thread. Returns the build's four values, then the release's leftover sentence (``None`` when
        no file in the directory still holds plaintext). Releasing here, not on the loop, is what
        makes a cancelled build clean up after itself: it keeps running on this thread, and the
        directory goes only once it has let go of the files."""
        if not work.claim():
            raise OSError(f"the backup staging directory {work.path} was released before the build")
        try:
            built = self._build_archive_blocking(
                out_path=out_path,
                snap_path=snap_path,
                key=key,
                key_id=key_id,
                config_only=config_only,
                now=now,
                salt=salt,
                work_dir=work.path,
                secure=work.secure,
                bundle=bundle,
            )
        except BaseException as exc:
            leftover = work.release()
            if leftover is None:
                raise
            if isinstance(exc, BackupError):
                # A refusal the build raised itself (vault BACKLOG #5220): the leftover leads for the
                # same reason, and a note would not reach the audit row or the alert.
                raise BackupError(exc.kind, f"{leftover}; the build failed: {exc}") from exc
            if isinstance(exc, OSError | BackupCodecError):
                # Named in the error itself, first, so the audit row and the alert carry it; a note
                # would not survive the loop wrapping this into a BackupError.
                kind = "write" if isinstance(exc, OSError) else "encrypt"
                raise BackupError(kind, f"{leftover}; the build failed: {safe_exc(exc)}") from exc
            exc.add_note(leftover)
            raise
        return (*built, work.release())

    def _build_archive_blocking(
        self,
        *,
        out_path: Path,
        snap_path: Path | None,
        key: bytes | None,
        key_id: str | None,
        config_only: bool,
        now: float,
        work_dir: Path,
        secure: bool,
        bundle: _ConfigBundle,
        salt: bytes | None = None,
    ) -> tuple[str, dict[str, int], int, _ConfigBundle]:
        """tar(store.db + config/ + manifest.json) → stream-encrypt to ``out_path``. Runs entirely
        OFF the event loop (the consistent snapshot at ``snap_path`` was already taken on the loop by the
        caller). Returns ``(snapshot_sha256, row_counts, archive_bytes, walked)``, the last
        ``bundle`` as the manifest records it once the walk has run. The tar goes to a file in
        ``work_dir`` (not RAM) so a multi-GB store never sits in memory; the codec then streams it to the
        archive. That tar is plaintext, so with ``secure`` it is locked to its owner before its first
        byte, the way the restore path locks its own staged tar.

        ``out_path`` is the STAGING path, not the canonical archive name — the caller publishes that
        name by rename once the archive has passed every configured check (see :data:`_STAGING_SUFFIX`).
        The final ``fsync`` below is what makes that rename safe to treat as the publish point when
        ``verify_after_backup`` is off: the bytes are durable before the name appears."""
        snapshot_sha256 = ""
        row_counts: dict[str, int] = {}
        if snap_path is not None:
            snapshot_sha256 = _sha256_file(snap_path)
            row_counts = _count_tables(snap_path)

        # In the run's own staging directory, which the caller releases on every exit.
        tar_path = work_dir / "archive.tar"
        with open(tar_path, "wb") as tar_fh:
            _secure_staged(tar_path, secure)
            with tarfile.open(fileobj=tar_fh, mode="w") as tar:
                if snap_path is not None:
                    tar.add(snap_path, arcname=_STORE_MEMBER)
                added = 0
                skipped: tuple[str, ...] = ()
                if bundle.bundled and bundle.path is not None:
                    added, skipped = self._add_config_dir(tar, bundle.path)
                walked = bundle.after_walk(added, skipped)
                if config_only and added == 0:
                    # Before the archive is written, so nothing is published or pruned: an archive of
                    # a manifest alone would verify and take a keep-N slot (vault BACKLOG #5220).
                    # The verdict leads the message, ahead of the path. A staging leftover, when
                    # there is one, is put ahead of both by `_build_in_staging`.
                    raise BackupError(
                        "snapshot",
                        "config-only backup: the config walk added no regular file, so there is "
                        f"nothing to archive (config dir {bundle.path})",
                    )
                # Built after the walk, so `config_bundled` says whether a config file was added,
                # not whether the walk was asked to run (vault BACKLOG #5220), and
                # `config_skipped_files` names what the walk passed over (vault BACKLOG #5233).
                manifest = {
                    "format": "mfbak",
                    # The .mfbak archive format version — parity with the AAD-bound codec header
                    # (ADR 0049 "What's in the archive"). The header's value is authoritative for
                    # decode; this is the human-/tooling-readable copy inside the manifest.
                    "format_version": FORMAT_VERSION,
                    "engine_version": self._engine_version,
                    "instance": self._instance,
                    "created_utc": _utc_iso(now),
                    "snapshot_method": self._settings.snapshot_method,
                    "config_only": config_only,
                    "backend": self._backend_value(),
                    "key_id": key_id,  # one-way fingerprint, NEVER key bytes
                    **walked.manifest_fields(),
                    "snapshot_sha256": snapshot_sha256,
                    "row_counts": row_counts,
                }
                manifest_bytes = json.dumps(manifest, sort_keys=True).encode("utf-8")
                info = tarfile.TarInfo(_MANIFEST_MEMBER)
                info.size = len(manifest_bytes)
                info.mtime = int(now)
                tar.addfile(info, io.BytesIO(manifest_bytes))

        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(tar_path, "rb") as src, open(out_path, "wb") as dst:
            if key is not None:
                # ASVS 11.3.4: every DR frame is an AES-GCM invocation under the key it is sealed
                # under -- the store data sub-key for a salted archive, the DEK for an unsalted one
                # (ADR 0196 AC-6) -- so it spends that key's budget. The id is derived here from the
                # same (key, salt) the codec seals under, so the two cannot disagree. Record the
                # count (the worker thread holds no store) and charge it after the run.
                charge_id = store_data_key_id(key, salt) if salt else key_fingerprint(key)
                encrypt_stream(
                    src,
                    dst,
                    key,
                    on_frames=functools.partial(self._record_frames, charge_id),
                    salt=salt,
                )
            else:
                # No key + allow_unencrypted: write the plaintext tar verbatim. It can hold PHI: no
                # instance is synthetic since BACKLOG #1279 (ADR 0186).
                while True:
                    buf = src.read(1024 * 1024)
                    if not buf:
                        break
                    dst.write(buf)
            dst.flush()
            os.fsync(dst.fileno())
        archive_bytes = out_path.stat().st_size
        return snapshot_sha256, row_counts, archive_bytes, walked

    def _add_config_dir(self, tar: tarfile.TarFile, base: Path) -> tuple[int, tuple[str, ...]]:
        """Add the config dir ``base`` under ``config/`` — every regular file (incl. ``_*.py``,
        ``connections.toml``, ``codesets/``, fixtures). A link out of the bundle would smuggle an
        arbitrary host file into the archive, so the walk aims to add only regular files and does
        NOT follow at least: a symlinked file, a symlinked directory, and on Windows a junction or
        volume mount point below ``base`` (vault BACKLOG #5221), as :func:`_walk_unfollowed` reads
        them. A filesystem mounted below ``base`` on POSIX is not a link, and is walked. ``base``
        itself is the operator's configured directory and is walked whatever it is. At least each
        directory link the walk lists as a directory is named in one WARNING, since the loader and
        the config digest may read through it.

        Not covered, at least: the walk reads each entry, then lists or opens it by name, so a path
        swapped for a link in between is followed. The swaps that reach it include at least these.
        A directory swapped for a junction in that gap is descended, as :func:`_walk_unfollowed`
        says, and the files behind it are bundled. A parent folder swapped for a junction after the
        walk had already decided to descend into the folder lets ``tar.add`` open each name listed
        under the folder through the junction. A swapped file adds one member, since ``tar.add`` is
        not recursive. This walk does not close that race, and this docstring does not bound who
        can win it; closing it is separate work.

        A config editor's lock file and candidate directories are skipped (vault BACKLOG #2782): a
        candidate lives only for one validation, so one listed here may be gone by the add, and a
        killed editor's leftover is not config. So is the backup's own staging, which a data dir
        inside the config dir puts there (BACKLOG #1174): its plaintext snapshot and the tar being
        written must not ride in the bundle.

        Returns how many regular files it added, which a config-only pass needs (vault BACKLOG
        #5220), and what it passed over, so the archive records what it does not carry (vault
        BACKLOG #5233): sorted paths relative to ``base``, ``.`` for ``base`` itself, as
        :func:`~messagefoundry.config.fingerprint.describe_left_out` reads them. What that names,
        and what it does not, is stated once, in the ``include_config`` row of
        ``docs/CONFIGURATION.md``."""
        pruned: list[str] = []
        unlisted: list[str] = []
        found: list[Path] = []
        for dirpath, dirs, files in _walk_unfollowed(base, pruned, unlisted):
            # Pruned here, before the walk descends them, so a link inside one is not reported.
            dirs[:] = [
                d
                for d in dirs
                if not (atomic_edit.is_candidate_dir_name(d) or _is_staging_dir(Path(dirpath, d)))
            ]
            found.extend(Path(dirpath, name) for name in files)
        links = sorted(Path(p).relative_to(base).as_posix() for p in pruned)
        if links:
            log.warning(
                "DR backup: the config bundle of %s does not follow a directory link, so it leaves "
                "out: %s",
                base,
                scrub_log_argument(", ".join(links)),
            )
        # What is passed over as neither a link nor config: unlisted folders, then files below.
        passed_over = {Path(p).relative_to(base).as_posix() for p in unlisted}
        # The names this walk added as regular members, which a second hard link may name; their
        # count is the regular files it added.
        regular_names: set[str] = set()
        # Sorted whole, as the earlier `sorted(rglob)` was, so the member order is unchanged.
        for path in sorted(found):
            rel = path.relative_to(base)
            if _is_config_edit_artifact(rel):
                continue
            try:
                st = path.lstat()
                regular = stat.S_ISREG(st.st_mode) and not _stat_names_another_path(st)
            except FileNotFoundError:
                # Gone since the listing, such as an editor's save probe: no longer config.
                continue
            except OSError:
                regular = False
            if not regular:
                passed_over.add(rel.as_posix())
                continue
            before = len(tar.getmembers())
            tar.add(path, arcname=f"{_CONFIG_PREFIX}{rel.as_posix()}", recursive=False)
            # Counted from the member tar wrote, so a path swapped for a link or a folder after the
            # check above does not count as a file, nor one tar skipped, such as a socket.
            members = tar.getmembers()
            last = members[-1] if len(members) > before else None
            # A second name of a file this walk already added is carried too, so it is not passed
            # over: tar stores it as a link member naming that one, and a restore writes it as a
            # copy of that file's bytes (`_extract_config_members`) (vault BACKLOG #5233).
            if last is not None and last.isreg():
                regular_names.add(last.name)
            elif not (last is not None and last.islnk() and last.linkname in regular_names):
                passed_over.add(rel.as_posix())
        if passed_over:
            from messagefoundry.config.fingerprint import describe_left_out

            log.warning(
                "DR backup: the config bundle of %s leaves out %d path(s) it could not list or add "
                "as a regular file, first %d by name: %s",
                base,
                len(passed_over),
                min(len(passed_over), _MAX_SKIPPED_RECORDED),
                scrub_log_argument(describe_left_out(sorted(passed_over)[:_MAX_SKIPPED_RECORDED])),
            )
        return len(regular_names), tuple(sorted(passed_over | set(links)))

    # --- keep-N retention ----------------------------------------------------

    def _prune_keep_n(self, dest_dir: Path, inst: str, *, just_written: Path) -> int:
        """Delete this instance's archives beyond the newest ``retention_keep`` at the destination.
        ``0`` = keep all. Only archives this runner writes (same instance prefix + extension) are
        candidates, so an operator's unrelated files at the destination are never touched.

        The candidate set is the CANONICAL name and nothing else, which is what stops a bad archive
        spending a retention slot: the caller publishes that name only to an archive that passed
        every configured check (BACKLOG #1587).

        RETENTION SPANS BOTH EXTENSIONS, which is BACKLOG #1724. This pruned only the extension the
        CURRENT pass wrote, and the two anchored patterns are disjoint -- neither matches the
        other's files. So configuring a store key on a box that had been writing ``.mfbak.plain``
        left every existing plaintext archive outside keep-N forever, and removing a key stranded
        the ``.mfbak`` ones the same way. The window silently stopped applying to a whole generation
        of archives, in either direction, with nothing reporting it.

        ``just_written`` is that published archive, and it is EXCLUDED FROM THE CANDIDATES AND
        COUNTED rather than relied upon to sort newest. This docstring used to say it simply is the
        newest candidate; that holds only while stamps rise with the wall clock, and widening the
        set to both extensions makes the assumption carry more weight because an older-generation
        archive can now evict. A clock stepping backwards -- an NTP correction, a restored VM
        snapshot -- would otherwise let a pass delete the archive it had just published.

        The exclusion is COUNTED, not assumed. Reserving its retention slot unconditionally keeps
        ``keep - 1`` archives whenever the published file is not actually at the destination, and at
        ``retention_keep = 1`` that keeps ZERO while the pass reports success -- a data-loss defect,
        not an off-by-one in a report."""
        keep = self._settings.retention_keep
        if keep <= 0:
            return 0
        prefix = f"mefor-backup-{inst}-"
        # Two independent things keep a bad archive out of this set, and they are not equally
        # load-bearing:
        #
        # 1. The WRITE PATH. A staging or verify-failed archive carries a `.part` / `.failed`
        #    suffix AFTER the extension, so it cannot match a pattern that ends in `ext` — anchored
        #    or loose. This is the half that actually fixes BACKLOG #1587.
        # 2. The ANCHORING. Pinning the middle to the exact _utc_stamp shape (YYYYMMDDThhmmssZ)
        #    rather than a loose f"{prefix}*{ext}" additionally rejects a name carrying an extra
        #    token BEFORE the extension, which a `*` would span and count.
        #
        # The comment here used to justify (2) with a `mefor-backup-dev-<stamp>.corrupt.mfbak` file
        # "left behind" by the verify path. That attribution was wrong — no engine path has ever
        # written a `.corrupt.mfbak`, and before the fix above the verify path left its failure at
        # the CANONICAL name, which is the defect, not a name the anchoring could have caught. The
        # name itself is real, though: `tests/test_restore_verify.py`, `tests/test_dr_seeding.py`
        # and `tests/test_cli_backup_dispatch.py` each write one beside a live archive via
        # `with_suffix(".corrupt.mfbak")`. So (2) is not hypothetical margin — a loose glob would
        # count those fixtures — it is simply protecting against a different name than the comment
        # claimed.
        # One anchored pattern PER EXTENSION, never a single loose one. A loose `*` would cover both
        # extensions too and would undo (2) above.
        candidates = [
            p
            for archive_ext in _ARCHIVE_EXTS
            for p in dest_dir.glob(f"{prefix}????????T??????Z{archive_ext}")
            if p.is_file()
        ]
        # COUNT the exclusion, do not assume it -- see the docstring. The published archive can be
        # absent for ordinary reasons: antivirus quarantining a freshly written multi-GB opaque file
        # on a share, a cleanup script, or a second engine sharing the instance and destination,
        # which the default NullCoordinator does not prevent.
        reserved = sum(1 for p in candidates if p == just_written)
        archives = sorted(
            (p for p in candidates if p != just_written),
            # The stamp is fixed-width and precedes the extension, so a lexical sort over the
            # name is chronological across extensions too, not just within one.
            #
            # NORMCASE, and not decoration: `Path.glob` is case-INSENSITIVE on Windows, the
            # platform this ships on, so `...Z.MFBAK` enters the candidate set -- and a
            # case-SENSITIVE sort puts `M` (0x4D) before `m` (0x6D) and reads the newest
            # archive as the oldest. That deleted the newest archive and kept two older ones
            # at keep=3.
            key=lambda p: os.path.normcase(p.name),
            reverse=True,
        )
        # The first pass after an encryption change deletes a whole generation at once -- measured,
        # 18 archives in one run at keep=7 -- and the only record of that was a `pruned` integer
        # inside one audit row. One line naming the count and the extensions makes it greppable.
        doomed = archives[keep - reserved :]
        crossing = {p.suffixes[-1] for p in doomed} - {just_written.suffixes[-1]}
        if crossing:
            log.info(
                "DR backup: keep-N is pruning %d archive(s) written with a different extension "
                "(%s); expected on the first pass after a store key was configured or removed",
                len(doomed),
                ", ".join(sorted(crossing)),
            )
        pruned = 0
        for stale in doomed:
            try:
                stale.unlink()
                pruned += 1
            except OSError:
                log.warning("DR backup: could not prune stale archive %s", stale.name)
        return pruned

    # --- audit + alert -------------------------------------------------------

    async def _record_success(self, result: BackupResult, now: float) -> None:
        verify = result.verify
        detail = {
            "archive": Path(result.archive_path).name,  # filename, not contents
            "archive_bytes": result.archive_bytes,
            "snapshot_method": result.snapshot_method,
            "config_only": result.config_only,
            "encrypted": result.encrypted,
            "key_id": result.key_id,  # one-way fingerprint — never key bytes
            "config_fingerprint": result.config_fingerprint,
            "config_bundled": result.config_bundled,
            "config_dir": result.config_dir,
            "config_bundle_error": result.config_bundle_error,
            "config_unreadable_files": list(result.config_unreadable_files),
            "config_skipped_files": list(result.config_skipped_files),
            "config_skipped_count": result.config_skipped_count,
            "snapshot_sha256": result.snapshot_sha256,
            "row_counts": result.row_counts,
            "verify": verify.status if verify is not None else "skipped",
            "verify_integrity_ok": verify.integrity_ok if verify is not None else None,
            # A COUNT of cipher-covered cells the full verify opened — PHI-free, and the one field that
            # distinguishes "the snapshot opened" from "its PHI was readable".
            "verify_decrypted_cells": verify.decrypted_cells if verify is not None else None,
            "pruned": result.pruned,
        }
        if result.staging_leftover is not None:
            detail["staging_leftover"] = result.staging_leftover  # a path and file names, PHI-free
        await self._store.record_audit(
            "dr_backup", actor="system", detail=json.dumps(detail, sort_keys=True), now=now
        )
        if result.staging_leftover is not None:
            # The archive is good, so the run succeeds; the plaintext left in staging is what an
            # operator must still hear about, through the same alert a failed run raises.
            try:
                self._alert_sink.backup_failed(
                    CLEANUP_ALERT_SUBJECT, kind="cleanup", detail=result.staging_leftover
                )
            except Exception:
                log.warning("DR backup: backup_failed alert sink raised", exc_info=True)

    async def _record_failure(self, kind: str, exc: BaseException, now: float) -> None:
        reason = safe_exc(exc) if isinstance(exc, BaseException) else str(exc)
        detail = {"outcome": "error", "kind": kind, "error": reason}
        try:
            await self._store.record_audit(
                "dr_backup", actor="system", detail=json.dumps(detail, sort_keys=True), now=now
            )
        except Exception:
            # Recording the failure must itself never raise into the loop — the alert below is the
            # backstop signal. (A store that can't even write the audit row is already in deep trouble.)
            log.warning("DR backup: could not record the dr_backup ERROR audit row", exc_info=True)
        # The sink never raises (contract), but be defensive — an alert failure must not mask the backup
        # failure we're reporting.
        try:
            self._alert_sink.backup_failed("dr_backup", kind=kind, detail=reason)
        except Exception:
            log.warning("DR backup: backup_failed alert sink raised", exc_info=True)

    # --- helpers -------------------------------------------------------------

    def _resolve_key(self) -> bytes | None:
        """The 32-byte store DEK via the ADR 0019 KeyProvider seam, or ``None`` (identity cipher)."""
        key_b64 = resolve_active_key(self._store_settings, posture=self._hop_posture)  # type: ignore[arg-type]
        if not key_b64:
            return None
        return _decode_store_key(key_b64)

    def _current_config_dir(self) -> Path | None:
        """The config dir this pass backs up: the constructor's value, or what its callable names
        now."""
        source = self._config_dir_source
        current = source() if callable(source) else source
        return Path(current) if current is not None else None

    def _inspect_config(self, config_dir: Path | None) -> _ConfigBundle:
        """Whether this pass can bundle ``config_dir``, and its ADR 0041 D1 digest. Blocking; the
        caller runs it off the loop.

        A directory that is gone or cannot be listed is not bundled, and the archive records that
        with the fault's class name (vault BACKLOG #3094). The fold and the archive walk both list
        through calls that swallow that error (``glob``, ``os.walk``), so without this check the
        archive would carry an empty ``config/``, and an empty-bundle digest, under a clean
        success. A full pass still
        goes on, because the store snapshot is worth keeping; a config-only pass fails, in
        :meth:`_do_backup`. The digest itself catches what
        :meth:`Engine.fingerprint_bundle_blocking` catches, its rule's source of record, so a bundle
        a load tolerates cannot fail a backup, though the archive walk can: ``tar.add`` opens each
        file itself, so a file still locked there fails the run. What the digest left out as
        unreadable is recorded beside it, so the record does not read as the digest of the whole
        bundle (vault BACKLOG #3765), and logged at WARNING when the bundle is being archived. On a
        bundled pass that list reaches a record only for what the walk passes over, at least a
        folder it cannot list, and for a lock gone by the walk. What the walk itself passes over is
        recorded apart, by :meth:`_add_config_dir` (vault BACKLOG #5233), since this digest is
        taken before the walk runs and can read through a link. Each warning names the directory
        and an error class, a scrubbed reason or a relative file name, never config content. With
        ``include_config`` off nothing is bundled, so a listing fault is not one the operator needs
        to hear about, and none is recorded; the digest is still taken, so its left-out list is."""
        if config_dir is None:
            return _ConfigBundle(path=None, bundled=False, fingerprint=None, error=None)
        from messagefoundry.config.fingerprint import describe_left_out, snapshot_fingerprint
        from messagefoundry.config.snapshot import read_config_snapshot

        include = self._settings.include_config
        try:
            # Raises the real reason (gone, not a directory, access denied) where glob would not.
            with os.scandir(config_dir):
                pass
        except OSError as exc:
            error = type(exc).__name__
            if not include:
                return _ConfigBundle(path=config_dir, bundled=False, fingerprint=None, error=None)
            log.warning(
                "DR backup: config dir %s could not be read (%s); this archive carries no config "
                "and no config fingerprint",
                config_dir,
                error,
            )
            return _ConfigBundle(path=config_dir, bundled=False, fingerprint=None, error=error)
        fingerprint: str | None = None
        left_out: tuple[str, ...] = ()
        try:
            snapshot = read_config_snapshot(config_dir, strict=False)
            fingerprint = snapshot_fingerprint(snapshot)
            left_out = snapshot.unreadable
        except (OSError, ValueError) as exc:
            log.warning(
                "DR backup: config fingerprint failed for %s: %s", config_dir, safe_exc(exc)
            )
        if left_out and include:
            log.warning(
                "DR backup: the config fingerprint of %s left out what it could not read: %s",
                config_dir,
                scrub_log_argument(describe_left_out(left_out)),
            )
        return _ConfigBundle(
            path=config_dir,
            bundled=include,
            fingerprint=fingerprint,
            error=None,
            left_out=left_out,
        )

    def _is_server_db(self) -> bool:
        return self._backend_value() in (StoreBackend.POSTGRES.value, StoreBackend.SQLSERVER.value)

    def _staging_root(self, dest_dir: Path) -> tuple[Path, bool]:
        """Where this runner stages plaintext, and whether it secures the files; see
        :func:`_staging_root_for`."""
        path = getattr(self._store, "path", None)
        return _staging_root_for(
            server_db=self._is_server_db(),
            store_path=path if isinstance(path, str) else None,
            destination=dest_dir,
        )

    def _space_shortfall(
        self, staging_root: Path, dest_dir: Path, *, config_only: bool, config_dir: Path | None
    ) -> str | None:
        """Whether this run fits, as :func:`_space_shortfall` answers it. Runs off the loop.

        The peak, with ``S`` the store file and ``C`` the config bundle: the staging root holds the
        snapshot and the tar at once (``2S + C``), and so does the backup's own verify later (the
        decrypted tar and the extracted store); the destination holds the archive (``S + C``, the
        tar plus a small framing overhead). On one volume that is ``3S + 2C``.

        The WAL is left out on purpose. SQLite never shrinks it without a truncating checkpoint, so
        its file can stand at a high-water size far above what the snapshot will carry, and counting
        it would refuse runs that fit. :meth:`_space_shortfall_after_snapshot` checks again with the
        snapshot's real size once it exists."""
        store_bytes = 0
        path = getattr(self._store, "path", None)
        if not config_only and isinstance(path, str) and path != ":memory:":
            store_bytes = _file_size(Path(path))
        config_bytes = self._config_bytes(config_dir)
        return _space_shortfall(
            [
                (staging_root, 2 * store_bytes + config_bytes),
                (dest_dir, store_bytes + config_bytes),
            ]
        )

    def _space_shortfall_after_snapshot(
        self, snap_path: Path, staging: Path, dest_dir: Path, *, config_dir: Path | None
    ) -> str | None:
        """The second free-space check, once the snapshot is on disk. It asks only for what is still
        to be written: the tar in staging (``S' + C``) and the archive at the destination
        (``S' + C``), with ``S'`` the snapshot's real size. The backup's own verify later holds no
        more on the staging volume than the build did, because the build's staging is released
        first."""
        rest = _file_size(snap_path) + self._config_bytes(config_dir)
        return _space_shortfall([(staging, rest), (dest_dir, rest)])

    def _config_bytes(self, config_dir: Path | None) -> int:
        """The bytes of the config bundle the archive will carry, or 0 when it carries none."""
        if self._settings.include_config and config_dir is not None:
            return _tree_size(config_dir)
        return 0

    def _backend_value(self) -> str:
        backend = getattr(self._store, "backend", None)
        return getattr(backend, "value", str(backend)) if backend is not None else "sqlite"

    def _preflight_destination(self) -> None:
        """Startup advisory: warn (don't fail) when the destination is unwritable or low on free space,
        so an operator learns of an unreachable UNC share at boot, not silently at 02:00 (AC-10). Fires
        the existing ``storage_threshold`` alert on low space (reuses that sink method)."""
        dest = Path(self._settings.destination)
        try:
            dest.mkdir(parents=True, exist_ok=True)
            probe = dest / ".mefor-backup-write-probe"
            probe.write_bytes(b"")
            probe.unlink()
        except OSError as exc:
            log.warning(
                "DR backup destination %s is not writable at startup: %s "
                "(the scheduled backup will fail until this is fixed)",
                self._settings.destination,
                safe_exc(exc),
            )
            return
        try:
            usage = shutil.disk_usage(dest)
        except OSError:
            return
        # Advisory low-space signal: under ~1 GB free is worth surfacing (reuse storage_threshold).
        low = 1024 * 1024 * 1024
        if usage.free < low:
            try:
                self._alert_sink.storage_threshold(
                    str(dest), size_bytes=usage.used, limit_bytes=usage.total
                )
            except Exception:
                log.warning("DR backup: storage_threshold preflight alert raised", exc_info=True)

    def _ensure_destination(self, dest_dir: Path) -> None:
        try:
            dest_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise BackupError(
                "destination",
                f"backup destination {dest_dir} is unreachable/unwritable: {safe_exc(exc)}",
            ) from exc


# --- module-level verify (also the restore-verify CLI entry point) -----------


def _select_decrypt_key(keys: list[bytes], header_key_id: str) -> bytes | None:
    """From the decrypt-capable keyring (active + retired, ADR 0049 AC-5 "incl. retired keys"), pick the
    key whose ``key_id`` fingerprint matches the archive header, or ``None`` if none does. So a backup
    taken under a now-retired key still verifies after a routine key rotation (WP-5), instead of a false
    ``KEY_MISMATCH``.

    The walk visits EVERY key and compares each with ``hmac.compare_digest``, with no return on the
    first match, so the work done does not depend on where in the keyring the match sits (ASVS 11.2.4,
    BACKLOG #1167). The first matching key still wins, as it did."""
    # `surrogatepass`: the header is read before anything authenticates it, and a forged `key_id`
    # holding a lone surrogate must be a non-match, not a UnicodeEncodeError.
    target = header_key_id.encode("utf-8", "surrogatepass")
    match: bytes | None = None
    for key in keys:
        # The compare runs before the `match is None` test, so it runs for every key.
        if hmac.compare_digest(key_fingerprint(key).encode("ascii"), target) and match is None:
            match = key
    return match


def _as_store_settings(settings: object) -> StoreSettings | None:
    """Narrow the loosely-typed ``store_settings`` seam to the real model, or ``None``.

    The public entry points (:class:`BackupRunner`, :func:`run_restore_verify`) type it as ``object``,
    and that annotation is left alone so no caller has to change. The FULL verify needs the real model
    to reach the cipher/keyring/provider, and anything else must fail the verify rather than quietly
    fall back to defaults."""
    return settings if isinstance(settings, StoreSettings) else None


def _verify_archive_blocking(
    *,
    archive_path: str,
    keys: list[bytes],
    full: bool,
    staging_root: Path | None,
    secure: bool = False,
    allow_unencrypted: bool = False,
    store_settings: object | None = None,
    posture: HopPosture | None = None,
) -> VerifyResult:
    """Lightweight (or full) restore-verify of a ``.mfbak`` archive — runs OFF the event loop.

    ``staging_root`` is where the decrypted archive is staged (BACKLOG #1174). A backup's own verify
    passes its build's root, a SQLite store's data directory or ``.mefor-staging`` under the backup
    destination (see :func:`_staging_root_for`). A standalone verify passes ``None``: it stages in the
    OS temp dir, and first sweeps that dir of this account's own abandoned staging (see
    :func:`_standalone_staging_root` and the staging-location block above :class:`_Staging`).
    ``secure`` locks each staged file to its owner before its first byte,
    which every case passes.

    ``keys`` is the decrypt-capable keyring (active + retired, ADR 0049 AC-5 "incl. retired keys") — the
    archive is matched against the whole set so one taken under a now-retired key still verifies after a
    rotation; an empty list means "no key configured" (only valid for a plaintext archive).

    ASVS 5.2.3 (symmetric ``allow_unencrypted``): the write path refuses to *write* a plaintext archive
    when no key is configured unless ``[backup].allow_unencrypted`` is set; symmetrically, when a store key
    IS configured a **plaintext** archive is a downgrade signal (an attacker swapping the AEAD-sealed
    archive for an unauthenticated one) and is refused here as ``KEY_MISMATCH`` — unless ``allow_unencrypted``
    is set. That flag reads no synthetic or non-PHI condition (BACKLOG #1279, ADR 0186).

    ``store_settings`` is this instance's live :class:`StoreSettings`. It is what a ``full`` verify opens
    the snapshot with, so the snapshot is read under the real cipher, keyring and key provider; without
    it a ``full`` verify FAILs rather than opening keyless (see :func:`_full_open_check`).

    Steps (ADR 0049): (1) key-fingerprint precheck — a mismatch is a clean ``KEY_MISMATCH`` BEFORE any
    decrypt; (2) decrypt the archive; (3) extract + open ``store.db`` read-only, run
    ``PRAGMA integrity_check``; (4) compare per-table row counts to the manifest. ``full`` additionally
    re-opens the snapshot through the real ``open_store`` path (cipher + migrations) and decrypts +
    authenticates every cipher-covered cell in it — heavier. That leg returns its own
    ``KEY_MISMATCH`` when the settings resolve no key for a snapshot that holds sealed cells or is
    recorded as keyed (see :func:`_full_open_check`), so an archive that is fine and a key
    configuration that is not are not both reported as ``FAIL``.

    Steps 2 to 4 write the decrypted archive into a ``mefor-verify-*`` staging directory, locked for
    the run (see :func:`_open_staging`), which is discarded on every exit path by
    :func:`_discard_verify_staging`. When decrypted bytes survive that, the result says so: a ``PASS``
    becomes ``FAIL``, and any other verdict keeps its status and gains the directory in its reason. Its
    lock is released either way, so the next sweep of the same root removes what survived."""
    standalone = staging_root is None
    try:
        # (1) Pre-decryption key check (only meaningful for an encrypted archive). For a plaintext
        # archive (no codec header) there is no key to mismatch.
        match_key: bytes | None = None
        encrypted = _looks_encrypted(archive_path)
        if not encrypted and keys and not allow_unencrypted and Path(archive_path).is_file():
            # A store key is configured but the archive is plaintext — refuse (possible downgrade/tamper),
            # symmetric to the write-side fail-closed. allow_unencrypted opts any box back in.
            # is_file() gates this to a real plaintext archive (a MISSING file also has no MAGIC, but that
            # is a plain FAIL, not a downgrade).
            return VerifyResult(
                "KEY_MISMATCH",
                reason="archive is plaintext but a store key is configured; refusing to verify a "
                "plaintext archive (possible downgrade). Set [backup].allow_unencrypted to accept it.",
            )
        if encrypted:
            with open(archive_path, "rb") as fh:
                header_key_id = read_header(fh).key_id
            if not keys:
                return VerifyResult(
                    "KEY_MISMATCH",
                    reason="archive is encrypted but no store key is configured to decrypt it",
                )
            match_key = _select_decrypt_key(keys, header_key_id)
            if match_key is None:
                return VerifyResult(
                    "KEY_MISMATCH",
                    reason=f"no resolved key (active or retired) matches archive key_id={header_key_id}",
                )

        if staging_root is None:
            staging_root = _standalone_staging_root()
        work = _open_staging(staging_root, _VERIFY_STAGING_PREFIX, secure=secure)
    except StagingNotPrivateError as exc:
        if not standalone:
            # A backup's own verify: the volume is at fault, not the archive, so this must not reach
            # `_keep_failed_archive`, which would quarantine a good archive. The caller turns it into
            # a `write` failure and leaves the archive unpublished.
            raise
        return VerifyResult("FAIL", reason=f"not a fault in the archive: {exc}")
    except (BackupCodecError, OSError, tarfile.TarError) as exc:
        return _verify_failure(exc)

    # Everything from here writes decrypted plaintext into the staging directory, so its teardown is
    # explicit and not a `TemporaryDirectory`: that `__exit__` raised when one unlink was refused (on
    # Windows, a handle still open on the extracted store), which REPLACED the verdict or the error in
    # flight and left the directory, holding the decrypted store, permanently behind (BACKLOG #1721).
    # `release` never raises, so whatever the verify concluded is what reaches the caller, and an
    # exception escaping the verify is still the verify's own.
    try:
        if standalone:
            # After the key precheck, so a verify that was never going to stage pays for no scan, and
            # before the decrypt, so a dead run's plaintext is gone before this one needs the space.
            # Inside this block, so even a fault in the sweep still releases this run's directory.
            _sweep_abandoned_staging(staging_root, owner=work.owner(), own=work.path)
        # A standalone verify holds the decrypted tar and the extracted store at once, each about the
        # archive's size (BACKLOG #1174, PR 1771 defect 3). The backup's own verify is covered by the
        # backup's check, which counts this peak on its staging root.
        shortfall = (
            _space_shortfall([(work.path, 2 * _file_size(Path(archive_path)))])
            if standalone
            else None
        )
        try:
            if shortfall is not None:
                # The reason says it is the volume, not the archive, so this FAIL is not read as a
                # verdict on the archive.
                result = VerifyResult(
                    "FAIL",
                    reason=f"not enough free space to verify this archive (not a fault in it): "
                    f"it {shortfall}",
                )
            else:
                result = _verify_in_staging(
                    work.path,
                    archive_path=archive_path,
                    encrypted=encrypted,
                    match_key=match_key,
                    full=full,
                    store_settings=store_settings,
                    secure=secure,
                    posture=posture,
                )
        except (BackupCodecError, OSError, tarfile.TarError) as exc:
            result = _verify_failure(exc)
    except BaseException as exc:
        # Unexpected, an interrupt, or a fault while mapping an expected one. The teardown still
        # runs, and a directory it could not clear rides on the exception as a note rather than
        # living only in the log.
        leftover = work.release()
        if leftover is not None:
            exc.add_note(leftover)
        raise
    leftover = work.release()
    if leftover is None:
        return result
    # Decrypted bytes outlived the teardown. That is not a fact about the archive, but it is the one
    # outcome an operator must hear about, so a PASS does not stay a PASS.
    status = "FAIL" if result.status == "PASS" else result.status
    prefix = "the archive verified" if result.status == "PASS" else "the verify failed"
    detail = f" ({result.reason})" if result.reason else ""
    return replace(result, status=status, reason=f"{prefix}{detail}, but {leftover}")


def _verify_failure(exc: BaseException) -> VerifyResult:
    """The verdict for an exception the verify expects. ``BackupKeyMismatch`` subclasses
    ``BackupCodecError``, so it is tested first."""
    if isinstance(exc, BackupKeyMismatch):
        return VerifyResult("KEY_MISMATCH", reason=safe_exc(exc))
    if isinstance(exc, BackupCodecError):
        return VerifyResult("FAIL", reason=f"decrypt failed: {safe_exc(exc)}")
    # `json.JSONDecodeError` is not expected here: `_read_manifest_from_tar` reports a manifest that
    # will not parse as `TarError`, and nothing else in the verify parses JSON (`read_header` raises
    # `BackupCodecError` for its own). A name for a type that cannot arrive reads as a guard and
    # guards nothing.
    return VerifyResult("FAIL", reason=safe_exc(exc))


#: The pauses between attempts to remove a verify's staging directory (BACKLOG #1721). A refused unlink
#: is usually brief: on Windows a scanner or the indexer opens a file it has just seen written, and
#: closes it again. About two seconds in all, on a worker thread, and only when an attempt failed.
_STAGING_REMOVE_DELAYS: tuple[float, ...] = (0.05, 0.1, 0.25, 0.5, 1.0)


def _clear_readonly_and_retry(func: Callable[..., object], path: str, exc: BaseException) -> None:
    """``shutil.rmtree``'s ``onexc``: clear a read-only entry and retry its removal, which
    ``TemporaryDirectory`` did and a plain ``rmtree`` does not. Only an unlink or rmdir is retried,
    and never through a link; anything else re-raises, so ``rmtree`` fails rather than skipping a
    subtree it could not read. A sharing violation is also a ``PermissionError``: its retry raises
    again, and the caller's own schedule takes over."""
    if isinstance(exc, FileNotFoundError):
        return
    if (
        not isinstance(exc, PermissionError)
        or func not in (os.unlink, os.remove, os.rmdir)
        or os.path.islink(path)
    ):
        raise exc
    os.chmod(path, stat.S_IWRITE | stat.S_IREAD | (stat.S_IEXEC if os.path.isdir(path) else 0))
    func(path)


def _remove_tree(path: Path) -> bool:
    """Remove ``path`` and everything in it. ``True`` only when it is gone, including when it
    already was: a clean return from ``rmtree`` is checked rather than trusted."""
    try:
        shutil.rmtree(path, onexc=_clear_readonly_and_retry)
    except FileNotFoundError:
        pass
    except OSError:
        return False
    return not os.path.lexists(path)


def _fd_walk(
    top: Path, onerror: Callable[[OSError], object]
) -> Iterator[tuple[str, list[str], list[str], int]]:
    """``os.fwalk``'s shape, top down, for the POSIX fail-safe: each directory comes with a descriptor
    and every child is opened relative to its parent's with ``O_NOFOLLOW``. Unlike ``os.fwalk`` it
    reports every listing and open failure to ``onerror`` and walks on: a directory that will not list
    or open, or one swapped for a link after it was listed, is reported and is never the end of the
    walk. An entry whose ``is_dir`` raises is listed as a file, so if it is a directory it is never
    walked; the fail-safe's ``lstat`` of it then finds a directory and reports it (BACKLOG #4989)."""
    if sys.platform == "win32":  # pragma: no cover - guard for the type checker on Windows
        raise OSError("the descriptor walk runs only on POSIX")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    try:
        stack = [(os.fspath(top), os.open(top, flags))]
    except OSError as exc:
        onerror(exc)
        return
    try:
        while stack:
            path, fd = stack.pop()
            try:
                try:
                    entries = list(os.scandir(fd))
                except OSError as exc:
                    onerror(OSError(exc.errno, exc.strerror, path))
                    continue
                dirs: list[str] = []
                files: list[str] = []
                for entry in entries:
                    try:
                        is_dir = entry.is_dir(follow_symlinks=False)
                    except OSError:
                        is_dir = False
                    (dirs if is_dir else files).append(entry.name)
                yield path, dirs, files, fd
                for name in reversed(dirs):
                    child = os.path.join(path, name)
                    try:
                        stack.append((child, os.open(name, flags, dir_fd=fd)))
                    except OSError as exc:
                        onerror(OSError(exc.errno, exc.strerror, child))
            finally:
                os.close(fd)
    finally:
        for _path, fd in stack:
            os.close(fd)


#: The POSIX walk the truncate fail-safe uses, named here so a test can refuse a listing without
#: patching every caller's walk. Windows walks by held handle instead (:func:`_win_held_walk`).
_walk = _fd_walk


def _empty_files_in_place(staging: Path) -> list[str]:
    """Truncate every regular file under ``staging`` to zero bytes. Returns what could NOT be shown
    empty: a file that refused, or a directory that could not be listed.

    Walked with a walk that reports a listing error, and an ``lstat``, rather than ``Path.rglob`` and
    ``Path.is_file``, which on Python 3.14 swallow ``OSError``: a directory that cannot be listed would
    read as empty, and a file that cannot be stat'ed as absent, and both would be reported clean while
    still full.

    The sweep runs this on directories it did not make this run, so it truncates the object it
    checked, never a name it checked a moment earlier (BACKLOG #2420). Each file is opened without
    following a link, and the OPEN handle must be a regular file with one link before it is truncated:

    - POSIX: :func:`_fd_walk` hands over a descriptor per directory and opens each child directory with
      ``O_NOFOLLOW``; each file is opened with ``O_NOFOLLOW`` relative to its directory's descriptor.
    - Windows: :func:`_win_held_walk` holds each directory, and the ones above it, while it is checked,
      listed and emptied. Each file is opened as itself and checked (:func:`_open_unfollowed`), and
      its final path must lie under ``staging``'s.

    What this leaves open is listed once, in docs/PHI.md section 2's ``mefor-backup-*`` /
    ``mefor-verify-*`` staging row."""
    unproven: list[str] = []

    def _unlisted(exc: OSError) -> None:
        unproven.append(f"{Path(exc.filename or staging).name}/ (not listed)")

    def _report(reason: str | None) -> None:
        # The reason for something reached through a link carries no name, so it is said once.
        if reason is not None and not (reason == _OUTSIDE_REASON and reason in unproven):
            unproven.append(reason)

    walked = False
    if sys.platform == "win32":
        for dirpath, dirnames, filenames, inside in _win_held_walk(staging, unproven, _report):
            walked = True
            # Never descend through a link or a junction, which `os.walk` follows even with
            # `followlinks=False`.
            dirnames[:] = [d for d in dirnames if not _is_dir_link(os.path.join(dirpath, d))]
            for name in filenames:
                _report(_truncate_unfollowed(Path(dirpath) / name, None, inside))
    else:
        for dirpath, _dirnames, filenames, dirfd in _walk(staging, onerror=_unlisted):
            walked = True
            for name in filenames:
                _report(_truncate_unfollowed(Path(dirpath) / name, dirfd, None))
    if not walked and not unproven:
        # A walk that yields nothing at all and reports nothing still did not show the root empty.
        unproven.append(f"{staging.name}/ (not listed)")
    return unproven


#: What the fail-safe reports for something it reached through a link. Not named: it lives outside
#: the staging directory, wherever the link pointed, and its name may be anyone's.
_OUTSIDE_REASON = "an entry outside the directory (reached through a link, not truncated)"


class _HardLinked(OSError):
    """The opened file has a second link, so it is not truncated (see :func:`_vet_for_truncate`).
    Never carries a name."""


class _Outside(OSError):
    """Windows: the file opened as itself has a final path outside the staging directory, so it is
    not truncated and is reported as :data:`_OUTSIDE_REASON`. Never carries a name."""


def _truncate_unfollowed(entry: Path, dir_fd: int | None, inside: str | None) -> str | None:
    """Truncate ``entry`` if it is a regular file with one link, checked on the handle that truncates
    it. ``None`` when it was emptied or holds nothing to empty, else what to report.

    ``dir_fd`` is its directory's descriptor on POSIX; ``inside`` is the staging directory's final
    path on Windows, as :func:`_win_held_walk` yields it. The ``lstat`` first only skips a link or a
    hard link without opening it; the check that decides is the one on the open handle."""
    name = entry.name
    try:
        if dir_fd is not None:
            st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        elif sys.platform == "win32":
            # Not `os.lstat`, which opens a cloud, deduplicated or tiered file through its filter.
            st, tag = _win_lstat(entry)
            if tag & _NAME_SURROGATE:
                return None  # a link, skipped as below; `os.fstat` calls a file symlink regular
        else:
            st = os.lstat(entry)
    except FileNotFoundError:
        return None
    except OSError:
        return name
    # A directory here is one the walk took for a file because reading its type raised, so nothing
    # in it was walked or emptied: report it, or the teardown would call the tree clean and raise no
    # cleanup alert while it may still hold plaintext (BACKLOG #4989). A junction, which Windows
    # reports as a directory, never reaches here: it names another path, so the Windows screen above
    # skips it by its reparse tag, which `os.fstat` does not carry.
    if stat.S_ISDIR(st.st_mode):
        return f"{name}/ (not walked)"
    # A link is never followed: truncating through one would empty a file outside the directory, and
    # the link itself holds no plaintext.
    if not stat.S_ISREG(st.st_mode):
        return None
    # Nor is a HARD link truncated: it shares its bytes with a name outside this directory. No file
    # the engine stages has a second link, so one here was put there by someone else.
    if st.st_nlink > 1:
        return f"{name} (hard-linked, not truncated)"
    try:
        fd = _open_unfollowed(entry, dir_fd, inside)
    except FileNotFoundError:
        return None
    except OSError as exc:
        return _not_truncated(name, exc)
    try:
        # Checked on the handle that truncates: POSIX's only check, and on Windows the reopened
        # handle of a file a filter serves (the handle opened as itself was checked before that,
        # inside test included, and the reopen must be that same file).
        _vet_for_truncate(fd)
        os.ftruncate(fd, 0)
    except OSError as exc:
        return _not_truncated(name, exc)
    finally:
        os.close(fd)
    return None


def _not_truncated(name: str, exc: OSError) -> str:
    """What the fail-safe reports for the file ``name`` it did not truncate, by why."""
    if isinstance(exc, _Outside):
        return _OUTSIDE_REASON
    if isinstance(exc, _HardLinked):
        return f"{name} (hard-linked, not truncated)"
    if isinstance(exc, (_Unconfined, _Replaced)):
        # The name became a link or not a regular file, or the Windows reopen that lets a filter
        # serve the file reached another one. A swap, not something reached through a link.
        return f"{name} (changed while being emptied, not truncated)"
    return name


def _open_unfollowed(entry: Path, dir_fd: int | None, inside: str | None) -> int:
    """Open ``entry`` for writing without following a link at its last component, and return a
    descriptor. A test seam. ``dir_fd`` and ``inside`` are as :func:`_truncate_unfollowed` takes
    them.

    POSIX opens ``entry.name`` relative to ``dir_fd`` (``entry`` itself without one) with
    ``O_NOFOLLOW``, so a link there fails with ``ELOOP``. ``O_NONBLOCK`` too, so a FIFO swapped in
    after the check fails at once rather than holding the teardown's thread until a reader comes; it
    also makes an open that breaks a file lease fail rather than wait, and that file is reported.

    Windows opens ``entry`` through ``transports/file.py``'s :func:`_win_open_file`, the file
    connector's own open: as itself, refusing a link or junction there (``_Unconfined``), and
    refusing a reopen that reaches another file (``_Replaced``). Before a filter is let serve the
    file, the file opened as itself must have a final path under ``inside`` (``_Outside``) and pass
    :func:`_vet_for_truncate`, so a file reached outside the directory, through a directory turned
    into a junction in place, is never served by its filter (BACKLOG #4992).

    A name that is gone once the file was opened as itself, as when it is renamed away before the
    reopen, raises ``_Replaced``, not ``FileNotFoundError``: the caller reads that as nothing to
    empty, and the file still holds its bytes under another name."""
    if sys.platform == "win32":
        # GENERIC_READ | GENERIC_WRITE, what `open(..., "r+b")` asked for before.
        access = 0x80000000 | 0x40000000
        opened: list[bool] = []

        def vet(fd: int) -> None:
            opened.append(True)
            if inside is not None and not _win_final_path(_os_handle(fd)).startswith(inside):
                raise _Outside("outside the directory")
            _vet_for_truncate(fd)

        try:
            return _win_open_file(entry, access, vet=vet, fd_flags=os.O_RDWR)
        except FileNotFoundError as exc:
            if opened:
                raise _Replaced("gone after it was opened") from exc
            raise
    flags = os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC
    if dir_fd is None:
        return os.open(entry, flags)
    return os.open(entry.name, flags, dir_fd=dir_fd)


#: ``O_NOFOLLOW`` where the platform has it: the sweep's lock open and the teardown's re-mark refuse a
#: lock file or marker planted as a link. Windows has none, and follows one there.
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
#: ``O_NONBLOCK`` where the platform has it, for the teardown's re-mark (see :func:`_teardown_staging`).
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
#: The bit a Windows reparse tag carries when it names another path (a symbolic link, a junction),
#: read at least by :func:`_owner_of`, :func:`_names_another_path` and :func:`_stat_names_another_path`.
#: :func:`_truncate_unfollowed` reads the same bit as ``_NAME_SURROGATE``.
_WIN_NAME_SURROGATE = _NAME_SURROGATE

# The Windows half of the fail-safe opens, holds and checks through `transports/file.py`'s own
# helpers (`_win_hold_dirs`, `_win_open_file`, `_handle_final_path`), the ones the file connector
# confines its drops with, so one copy of that code serves both (BACKLOG #4992).


def _vet_for_truncate(fd: int) -> None:
    """Refuse, on the open file, what the fail-safe never truncates: something that is not a regular
    file, or a file with a second link.

    On Windows :func:`_win_open_file` calls this on the file opened as itself, before it lets a
    filter serve a reparse point that names no path, and the screen before that open is
    :func:`_win_lstat`, not ``os.lstat`` (BACKLOG #4992). What still reaches a filter first is
    listed in docs/PHI.md section 2's ``mefor-backup-*`` / ``mefor-verify-*`` staging row."""
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        raise _Unconfined("not a regular file")
    if st.st_nlink > 1:
        raise _HardLinked("a second link")


def _win_final_path(handle: int) -> str:
    """The final path of the object open on the OS ``handle``, every link and junction resolved, in
    ``os.path.normcase`` form. A test seam: the one call whose failure can mean the volume cannot
    report a final path at all."""
    return os.path.normcase(_handle_final_path(handle))


def _win_unlisted(
    unproven: list[str], where: Path, exc: OSError, *, final_path: bool = False
) -> None:
    """Report the directory ``where`` as not listed, by its own name, and log the error it met as
    itself (BACKLOG #4992).

    Only a failed final-path query (``final_path``) with ``ERROR_INVALID_FUNCTION``,
    ``ERROR_NOT_SUPPORTED`` or ``ERROR_INVALID_PARAMETER`` is read as a volume that cannot report a
    final path. The same codes from an open or an attribute query mean something else, and are logged
    as what they are."""
    unproven.append(f"{where.name}/ (not listed)")
    if final_path and getattr(exc, "winerror", None) in _WIN_UNSUPPORTED:
        # Some redirectors and file systems (VirtualBox shared folders, WebDAV, some RAM disks)
        # cannot name a handle's final path, so nothing here can be shown to lie inside the
        # directory. Truncating by path instead is what BACKLOG #2420 removed, so nothing is
        # emptied, and that is said, without any file's name.
        log.warning(
            "DR staging: the truncate fail-safe cannot run on the volume holding %s, which "
            "cannot report a file's final path, so no file in it was emptied",
            where,
        )
        return
    log.warning(
        "DR staging: the truncate fail-safe could not open or list %s, so no file in it was "
        "emptied: %s",
        where,
        safe_exc(exc),
    )


def _win_held_walk(
    staging: Path, unproven: list[str], report: Callable[[str | None], None]
) -> Iterator[tuple[str, list[str], list[str], str]]:
    """Windows: walk ``staging`` top down, as ``os.walk`` does, yielding ``(dirpath, dirnames,
    filenames, inside)`` for each directory, where ``inside`` is ``staging``'s final path with a
    trailing separator, for a prefix test. A caller that prunes ``dirnames`` in place prunes the walk.

    Each directory is HELD by :func:`_win_hold_dirs`, with every directory between it and
    ``staging``, and ``staging`` itself: opened as themselves, refused if one names another path, and
    shared for reading and writing but not for delete, so that, at least, none can be renamed or
    replaced by another directory or a junction. The hold does not stop a held directory that is
    empty being turned into a junction in place, which needs only write-attributes access; the
    backup staging row of docs/PHI.md section 2 names that residual. It is held before it is
    checked and listed, and until the caller has emptied its files and resumes the walk (BACKLOG
    #4992), the order :func:`_fd_walk` keeps with its descriptors.

    A directory that cannot be opened or listed is added to ``unproven`` by its own name, never
    ``staging``'s, and its error is logged as itself (:func:`_win_unlisted`). One that is a link, a
    junction or no directory, or whose final path lies outside ``staging``, is passed to ``report``
    as :data:`_OUTSIDE_REASON`, without a name. Neither is descended into."""
    held_root = _win_hold_root(staging, unproven)
    if held_root is None:
        return
    root, inside = held_root
    try:
        stack = [staging]
        while stack:
            where = stack.pop()
            held = _win_hold_below(staging, where, inside, unproven, report)
            if held is None:
                continue
            try:
                try:
                    with os.scandir(where) as listing:
                        entries = list(listing)
                except OSError as exc:
                    _win_unlisted(unproven, where, exc)
                    continue
                dirnames: list[str] = []
                filenames: list[str] = []
                for entry in entries:
                    # Not followed: a link to a directory is listed as a file, and its lstat skips it.
                    (dirnames if entry.is_dir(follow_symlinks=False) else filenames).append(
                        entry.name
                    )
                yield os.fspath(where), dirnames, filenames, inside
                stack.extend(where / name for name in reversed(dirnames))
            finally:
                _win_release(held)
    finally:
        _win_release(root)


def _win_hold_root(staging: Path, unproven: list[str]) -> tuple[list[int], str] | None:
    """Hold ``staging`` itself and return its handle with its final path, or ``None`` once what
    stopped it is reported. A link or a junction there is never walked."""
    try:
        root = _win_hold_dirs(staging.parent, (staging.name,))
    except _Unconfined:
        unproven.append(f"{staging.name}/ (not listed)")
        log.warning(
            "DR staging: the truncate fail-safe did not walk %s, which is a link, a junction or not "
            "a directory, so no file in it was emptied",
            staging,
        )
        return None
    except OSError as exc:
        _win_unlisted(unproven, staging, exc)
        return None
    try:
        return root, _win_final_path(root[0]).rstrip("\\") + "\\"
    except OSError as exc:
        _win_release(root)
        _win_unlisted(unproven, staging, exc, final_path=True)
        return None


def _win_hold_below(
    staging: Path,
    where: Path,
    inside: str,
    unproven: list[str],
    report: Callable[[str | None], None],
) -> list[int] | None:
    """Hold every directory from below ``staging`` down to ``where`` and return their handles, or
    ``None`` once what refused it is reported. ``staging`` itself is held by the caller."""
    try:
        held = _win_hold_dirs(staging, where.relative_to(staging).parts)
    except _Unconfined:
        report(_OUTSIDE_REASON)
        return None
    except OSError as exc:
        _win_unlisted(unproven, where, exc)
        return None
    if not held:  # `staging` itself, checked by _win_hold_root
        return held
    try:
        outside = not (_win_final_path(held[-1]).rstrip("\\") + "\\").startswith(inside)
    except OSError as exc:
        _win_release(held)
        _win_unlisted(unproven, where, exc, final_path=True)
        return None
    if outside:
        _win_release(held)
        report(_OUTSIDE_REASON)
        return None
    return held


def _discard_verify_staging(staging: Path) -> str | None:
    """Remove a DR staging directory -- a backup's snapshot and plaintext tar, or a verify's decrypted
    archive. Never raises.

    Returns ``None`` when no file there still holds plaintext, or a PHI-free sentence naming the
    directory when one might. When the first removal is refused it empties every file in place at
    once, then retries the removal on a short schedule. A file another process holds open cannot be
    unlinked on Windows, but it can usually still be truncated, because Python's own ``open`` and
    SQLite both share write access; a holder that denies write sharing, or has the file mapped,
    refuses that too. Emptying first keeps the plaintext's time on disk to the one failed attempt
    rather than the whole retry schedule.

    Truncation rather than an overwrite with zeros: on an SSD or a copy-on-write volume an overwrite
    lands on new blocks and proves nothing, so the promise that can be kept is that the FILE no
    longer holds the plaintext. The blocks it freed still do until reused, and only full-disk
    encryption on the staging volume covers them (docs/PHI.md section 10)."""
    unproven: list[str] = []
    try:
        if _remove_tree(staging):
            return None
        unproven = _empty_files_in_place(staging)
        for delay in _STAGING_REMOVE_DELAYS:
            time.sleep(delay)
            if _remove_tree(staging):
                return None
    except Exception as exc:  # never raise over the verdict or the error in flight
        log.error("DR staging directory %s could not be cleared: %s", staging, safe_exc(exc))
        return (
            f"the plaintext staging directory {staging} could not be cleared; "
            "delete it once nothing holds it open"
        )
    if unproven:
        log.error(
            "DR staging directory %s could not be removed, and %s in it could not be emptied; "
            "delete it once nothing holds it open",
            staging,
            ", ".join(unproven),
        )
        return (
            f"the plaintext staging directory {staging} could not be removed, and "
            f"{', '.join(unproven)} could not be emptied; delete it once nothing holds it open"
        )
    log.warning(
        "DR staging directory %s had every file emptied but could not be removed; no file in it "
        "holds plaintext, and it can be deleted once nothing holds it open",
        staging,
    )
    return None


# --- staging location, per-run lock, and the orphan sweep (BACKLOG #1174, #1721) ---------------------
#
# A backup stages a plaintext tar of the store snapshot, and a verify stages the decrypted archive.
# Both used to live under the OS temp dir. They now live where the engine's own controls reach:
#
# * A SQLite store stages in its own DATA DIRECTORY, beside the store, and applies the store's
#   best-effort `_secure_file` to each staged tar and extracted store before its first byte, the way
#   `mefor-restore-*` does. The snapshot file gets it from `snapshot_to` once its copy completes. What
#   `_secure_file` leaves inside a temp directory's own DACL is not always owner-only (ADR 0163).
# * A server-DB store has no data directory, so it stages in `.mefor-staging` under the backup
#   destination, secured the same way: an owner-only per-run directory and `_secure_file` on each
#   staged file. A share that will not keep the directory owner-only refuses the run (see
#   `_open_staging`) rather than staging plaintext it cannot protect.
# * A STANDALONE verify (`restore-verify`, the DR cold-seed activation) is neither. It stages in a
#   private `mkdtemp` directory under the OS temp dir: mode 0700 on POSIX, and on Windows the
#   protected DACL Python 3.13+ writes for that mode (SYSTEM, Administrators, OWNER RIGHTS), with
#   `_secure_file` on each staged file. So it does not stage in the archive's directory, which on a
#   DR box may be a read-only share with no engine ACL. Nor does it stage beside `[store].path`,
#   the current directory under the default relative path. The exception is when one of those IS
#   the OS temp dir. Each standalone verify, and each backup, sweeps the temp dir of the
#   directories this account owns, and only those, since the temp dir can be shared.
#
# Every staging directory holds a lock file, locked for the whole run. A crash or SIGKILL releases the
# lock with the process, and that is the ONLY proof of abandonment the sweep accepts. Age is not proof:
# a sibling engine shard sharing the destination can be mid-backup in a directory of any age.

#: The staging directory prefixes. The sweep looks for these and nothing else.
_BACKUP_STAGING_PREFIX = "mefor-backup-"
_VERIFY_STAGING_PREFIX = "mefor-verify-"
_SWEPT_PREFIXES = (_BACKUP_STAGING_PREFIX, _VERIFY_STAGING_PREFIX)
#: The probe :func:`_probe_owner` makes to learn the owner a new entry gets: an empty file. Never a
#: staging directory; a leaked one is empty, and the sweep removes it only while it is empty. The
#: sweep also removes an empty probe-named directory by ``rmdir`` alone.
_OWNER_PROBE_PREFIX = "mefor-owner-probe-"

#: The server-DB staging root, a dot-prefixed directory under the backup destination.
_SERVER_DB_STAGING_DIR = ".mefor-staging"

#: The per-run lock file inside each staging directory, and the empty marker a run creates only once
#: it holds that lock. The marker is a file of its own, not bytes in the lock file, because a teardown
#: that cannot remove the directory truncates every file in it: a marker written INTO the lock file
#: would be emptied with the rest, and the sweep could then never prove the directory abandoned.
_LOCK_NAME = ".lock"
_HELD_MARKER_NAME = ".lock-held"

#: ``errno`` values that mean the file system cannot lock at all (an NFS mount without a lock daemon,
#: some FUSE and SMB mounts), as opposed to a lock someone else holds.
_LOCK_UNSUPPORTED = frozenset({errno.ENOLCK, errno.EOPNOTSUPP, errno.ENOTSUP})


def _lock_exclusive(fd: int, *, wait: bool) -> bool:
    """Take an exclusive OS lock on ``fd``. ``True`` when held. With ``wait`` False, ``False`` means
    another handle holds it. The OS drops the lock when the process dies, which is what lets a crashed
    run's directory be told apart from a live one.

    ``flock`` on POSIX, not ``lockf``: a ``lockf`` lock belongs to the process, so a second handle in
    the same process would not conflict, and a live run could not be told apart from a dead one by an
    engine that shares its process. ``msvcrt.locking`` on Windows is per handle already."""
    if sys.platform == "win32":
        import msvcrt

        os.lseek(fd, 0, os.SEEK_SET)
        try:
            msvcrt.locking(fd, msvcrt.LK_LOCK if wait else msvcrt.LK_NBLCK, 1)
        except OSError as exc:
            # A held range refuses with EACCES, or EDEADLOCK, the CRT's other contention code (the
            # same reading as `api/tls.py`). Anything else is a real fault and propagates.
            if wait or exc.errno not in (errno.EACCES, errno.EDEADLOCK):
                raise
            return False
        return True
    import fcntl

    try:
        fcntl.flock(fd, fcntl.LOCK_EX if wait else fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        if wait:
            raise
        return False
    return True


def _unlock_and_close(fd: int) -> None:
    """Drop the lock and close the handle. Never raises."""
    # A failed unlock is harmless: closing the handle below drops the lock anyway.
    with contextlib.suppress(OSError):
        if sys.platform == "win32":
            import msvcrt

            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_UN)
    with contextlib.suppress(OSError):
        os.close(fd)


class _Staging:
    """One staging directory and the lock that proves it is live. Released exactly once.

    ``claim`` and ``release`` share one mutex so a worker thread and the event loop can hand the
    directory between them: a worker that has claimed it releases it itself, once it has let go of the
    files, and a release from the loop then does nothing and does not wait."""

    def __init__(self, path: Path, fd: int, *, secure: bool) -> None:
        self.path = path
        self.secure = secure
        self._fd = fd
        self._mutex = threading.Lock()
        self._released = False
        self._claimed = False

    def owner(self) -> object | None:
        """The owner of the lock file this run created in the directory, read from its descriptor
        (:func:`_owner_of_fd`), never by path. Called before the directory is released."""
        return _owner_of_fd(self._fd, self.path / _LOCK_NAME)

    def claim(self) -> bool:
        """Called by a worker before it touches the directory. ``False`` if it is already gone."""
        with self._mutex:
            if self._released:
                return False
            self._claimed = True
            return True

    def release(self, *, unless_claimed: bool = False) -> str | None:
        """Drop the lock and remove the directory. Never raises. Returns ``None`` when no file there
        still holds plaintext, or a PHI-free sentence naming the directory when one might (see
        :func:`_discard_verify_staging`). The lock is dropped first because Windows will not delete a
        file that is still open."""
        with self._mutex:
            if self._released or (unless_claimed and self._claimed):
                return None
            self._released = True
        _unlock_and_close(self._fd)
        return _teardown_staging(self.path)


def _teardown_staging(path: Path) -> str | None:
    """:func:`_discard_verify_staging`, then, if the directory survived, put its lock file and marker
    back so the next sweep can prove it abandoned. Never raises.

    A refused removal can take the lock file and marker with it, because ``rmtree`` removes entries in
    listing order and on NTFS the dot-names list first. Left like that, the directory would hold
    plaintext and no proof, and every later sweep would skip it. Nobody holds the lock now, so the
    files are all the proof needs."""
    leftover = _discard_verify_staging(path)
    if os.path.lexists(path):
        # `_O_NONBLOCK` too, as the fail-safe's own opens: a FIFO planted at either name would
        # otherwise hold this thread in the open until a reader came, which may be never.
        flags = os.O_WRONLY | os.O_CREAT | _O_NOFOLLOW | _O_NONBLOCK
        try:
            for name in (_LOCK_NAME, _HELD_MARKER_NAME):
                os.close(os.open(path / name, flags, 0o600))
        except OSError as exc:
            log.warning(
                "DR staging directory %s survived its teardown and could not be marked for the next "
                "sweep: %s",
                path,
                safe_exc(exc),
            )
    return leftover


def _release_when_opened(opening: asyncio.Future[_Staging]) -> None:
    """Done-callback for an open whose awaiter was cancelled: release what it opened, off the loop."""
    if opening.cancelled() or opening.exception() is not None:
        return
    work = opening.result()
    asyncio.get_running_loop().run_in_executor(None, work.release)


def _file_size(path: Path) -> int:
    """The size of ``path``, or 0 when it does not exist or cannot be read."""
    try:
        return os.stat(path).st_size
    except OSError:
        return 0


def _is_config_edit_artifact(rel: Path) -> bool:
    """Whether ``rel`` (relative to the config dir) is a config editor's lock file, or sits in one
    of its candidate directories (:mod:`messagefoundry.config.atomic_edit`)."""
    return rel.name == atomic_edit.LOCK_FILE_NAME or any(
        atomic_edit.is_candidate_dir_name(part) for part in rel.parts[:-1]
    )


def _walk_unfollowed(
    root: Path, pruned: list[str] | None = None, unlisted: list[str] | None = None
) -> Iterator[tuple[str, list[str], list[str]]]:
    """``os.walk(root)``, top-down, that does not descend a directory link below ``root``, as
    :func:`_is_dir_link` reads one: at least a symlinked directory and, on Windows, a junction or
    volume mount point, which ``os.walk`` descends even with ``followlinks=False`` (vault BACKLOG
    #5221). A directory whose ``lstat`` fails is not descended either. Each pruned directory's path
    is appended to ``pruned`` when one is given, and each folder ``os.walk`` could not list, ``root``
    included, to ``unlisted`` (vault BACKLOG #5233). A caller may prune the yielded directory list
    further, as with ``os.walk``. The read and the descent are by name, so a directory swapped for a
    link between them is descended."""

    def record_unlisted(exc: OSError) -> None:
        # os.walk names the folder it failed to list. With no name the folder is unknown, so root
        # is recorded: that overstates the loss rather than let it pass unrecorded.
        if unlisted is None:
            return
        name = os.fsdecode(exc.filename) if exc.filename is not None else str(root)
        # A subfolder gone since its parent was listed is no longer config; root gone is a loss.
        if isinstance(exc, FileNotFoundError) and name != str(root):
            return
        unlisted.append(name)

    for dirpath, dirs, files in os.walk(root, onerror=record_unlisted, followlinks=False):
        kept = []
        for d in dirs:
            full = os.path.join(dirpath, d)
            if not _is_dir_link(full, unreadable=True):
                kept.append(d)
            elif pruned is not None:
                pruned.append(full)
        dirs[:] = kept
        yield dirpath, dirs, files


def _is_dir_link(path: str, *, unreadable: bool = False) -> bool:
    """Whether ``path`` names another path: a symlink, or on Windows a name-surrogate reparse point,
    at least a junction or a volume mount point. Read by ``lstat``, never by a following ``stat``. A
    reparse point that names no other path, such as a cloud placeholder or a deduplicated file, is
    not one, so it is walked as what it holds; the same rule as :func:`_owner_of`. ``unreadable`` is
    the answer when the ``lstat`` fails: the config walk prunes such an entry, and the staging walk,
    which reports what it cannot list, lets ``os.walk`` try it as it did before."""
    try:
        st = os.lstat(path)
    except OSError:
        return unreadable
    return _stat_names_another_path(st)


def _stat_names_another_path(st: os.stat_result) -> bool:
    """Whether an ``lstat`` result is a link as :func:`_is_dir_link` reads one, for a file or a
    folder. On Windows a name-surrogate reparse point other than a symlink, such as a WSL link,
    reads as ``S_IFREG``, so the mode alone does not say."""
    reparse = getattr(st, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
    return stat.S_ISLNK(st.st_mode) or bool(
        reparse and getattr(st, "st_reparse_tag", 0) & _WIN_NAME_SURROGATE
    )


def _tree_size(root: Path) -> int:
    """The total size of the regular files under ``root``, on the walk ``_add_config_dir`` uses
    (:func:`_walk_unfollowed`), so a directory link it passes over is not counted. Unlike that
    walk it does not skip the backup's own staging or a config editor's lock file. 0 when ``root``
    cannot be walked."""
    total = 0
    for dirpath, dirs, files in _walk_unfollowed(root):
        # Candidate directories are pruned, as _add_config_dir skips their files.
        dirs[:] = [d for d in dirs if not atomic_edit.is_candidate_dir_name(d)]
        for name in files:
            try:
                st = os.lstat(os.path.join(dirpath, name))
            except OSError:
                continue
            if stat.S_ISREG(st.st_mode):
                total += st.st_size
    return total


def _nearest_existing(path: Path) -> Path:
    """``path``, or its nearest ancestor that exists: a staging root may not be created yet."""
    for candidate in (path, *path.parents):
        if candidate.exists():
            return candidate
    return path


def _mib(n: int) -> str:
    return f"{max(n, 0) / (1024 * 1024):,.0f} MiB"


def _space_shortfall(needs: list[tuple[Path, int]]) -> str | None:
    """A PHI-free sentence naming the first volume without room for what will be written there, or
    ``None`` when every volume has room (BACKLOG #1174, PR 1771 defect 3).

    ``needs`` pairs each directory with the bytes a run will hold there at its peak. Two directories
    on one volume add up, which is the case that matters most: a server-DB store stages under its
    own backup destination. A volume whose free space cannot be read is skipped, not failed: the
    check exists to fail early and clearly, and a run it cannot judge still fails at the write."""
    by_volume: dict[int, tuple[Path, int]] = {}
    for path, needed in needs:
        existing = _nearest_existing(path.absolute())
        try:
            volume = os.stat(existing).st_dev
        except OSError:
            continue
        where, total = by_volume.get(volume, (existing, 0))
        by_volume[volume] = (where, total + needed)
    for where, total in by_volume.values():
        try:
            free = shutil.disk_usage(where).free
        except OSError:
            continue
        if free < total:
            return (
                f"needs about {_mib(total)} free on the volume holding {where}, "
                f"and {_mib(free)} is free"
            )
    return None


class StagingNotPrivateError(OSError):
    """A secured staging directory did not come out owner-only, so nothing was staged in it."""


def _staging_is_private(path: Path) -> bool:
    """Whether a staging directory admits only its own account.

    POSIX: no group or other permission bits. Windows: a protected DACL whose allow entries name only
    SYSTEM, Administrators, OWNER RIGHTS or the directory's own owner, which is what ``mkdtemp``
    writes on Python 3.13+. A DACL that cannot be read or parsed is not private. Deny entries are
    ignored: they only narrow access.

    What it does not see, stated rather than implied: it trusts the owner the file system reports,
    so a share whose server sets the owner (a CIFS ``uid=`` mount, Samba ``force user``) can pass
    while admitting that principal; and on POSIX it reads mode bits only, so an inherited macOS or
    NFSv4 extended ACL, which applies whatever the mode says, is invisible to it. Linux POSIX ACLs
    are covered, because their mask follows the group bits of mode ``0700``."""
    if sys.platform != "win32":
        try:
            return stat.S_IMODE(os.stat(path).st_mode) & 0o077 == 0
        except OSError:
            return False
    from messagefoundry.store.store import _SDDL_DENY_TYPES, _parse_sddl_dacl, _read_dacl_sddl

    sddl = _read_dacl_sddl(path, owner=True)
    dacl = _parse_sddl_dacl(sddl) if sddl else None
    if dacl is None or not dacl.protected or not dacl.aces:
        return False
    allowed = {"S-1-5-18", "S-1-5-32-544", "OW", "S-1-3-4"}
    if dacl.owner:
        allowed.add(dacl.owner)
    return all(sid in allowed for kind, _f, _r, sid in dacl.aces if kind not in _SDDL_DENY_TYPES)


def _open_staging(root: Path, prefix: str, *, secure: bool) -> _Staging:
    """Create a staging directory under ``root`` and take its lock before anything is written there.

    The marker is created only AFTER the lock is held. A sweep that takes the lock and finds no marker
    cannot tell a crash in that instant from a run about to take its lock, so it leaves the directory
    alone. Nothing in such a directory holds plaintext yet.

    With ``secure``, the new directory must be owner-only (BACKLOG #1174). ``mkdtemp`` asks for that,
    but a share can ignore the request, for example an SMB or NFS mount whose modes or ACLs the
    server sets. Then this removes the directory and raises :class:`StagingNotPrivateError`: the run
    fails with a reason naming the directory, rather than staging plaintext the engine cannot
    protect. Falling back to a local directory was the other choice, and was not taken: the run's
    free-space check and its verify both name one staging root, and a second one would split them."""
    root.mkdir(parents=True, exist_ok=True)
    path = Path(tempfile.mkdtemp(prefix=prefix, dir=root))
    if secure and not _staging_is_private(path):
        # Empty, so a leftover holds no plaintext; but it has no lock file, so no sweep will take it.
        removed = _remove_tree(path)
        # Short first: the failure record and the alert keep only the first 200 characters.
        raise StagingNotPrivateError(
            f"staging dir {path} is not owner-only"
            + ("" if removed else " (empty, could not be removed; delete it)")
            + "; the engine stages no plaintext there. Use a volume that keeps a directory's mode "
            "or ACL: move the SQLite store's data directory, [backup].destination for a server-DB "
            "store, or TMP/TEMP/TMPDIR for a standalone restore-verify"
        )
    try:
        fd = os.open(
            path / _LOCK_NAME,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o600,
        )
    except OSError:
        _remove_tree(path)
        raise
    try:
        _lock_exclusive(fd, wait=True)
    except OSError as exc:
        if exc.errno not in _LOCK_UNSUPPORTED:
            _unlock_and_close(fd)
            _remove_tree(path)
            raise
        # No lock is possible here, so no marker either: the sweep can then never prove this
        # directory abandoned, and a crash leaves it for the operator. That is still safe, and it
        # keeps a backup working on a destination that cannot lock.
        log.warning(
            "DR staging root %s cannot be locked (%s); staging there without a lock, so a directory "
            "a crash leaves behind will not be swept",
            root,
            safe_exc(exc),
        )
        return _Staging(path, fd, secure=secure)
    try:
        os.close(os.open(path / _HELD_MARKER_NAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
    except OSError:
        _unlock_and_close(fd)
        _remove_tree(path)
        raise
    return _Staging(path, fd, secure=secure)


def _is_staging_dir(path: Path) -> bool:
    """Whether ``path`` is a directory this module stages in: ``.mefor-staging``, or a prefixed
    directory holding a lock file. The lock file is what keeps an operator's own directory that
    happens to share a prefix, such as ``codesets/mefor-verify-maps``, in the config bundle."""
    if path.name == _SERVER_DB_STAGING_DIR:
        return True
    return path.name.startswith(_SWEPT_PREFIXES) and os.path.lexists(path / _LOCK_NAME)


def _secure_staged(path: Path, secure: bool) -> None:
    """Apply the store's ``_secure_file`` to a just-created, still-empty staged file when ``secure``."""
    if secure:
        from messagefoundry.store.store import _secure_file

        _secure_file(path)


def _staging_root_for(
    *, server_db: bool, store_path: str | None, destination: Path
) -> tuple[Path, bool]:
    """Where to stage, and whether to lock the files with ``_secure_file``.

    A SQLite store on disk stages in its own data directory. Anything else stages in
    ``.mefor-staging`` under ``destination``: a server-DB store has no data directory, and an
    in-memory store has none either. Both are secured (BACKLOG #1174): each run's directory must be
    owner-only, which :func:`_open_staging` checks, and each staged file gets ``_secure_file``."""
    if not server_db and store_path and store_path != ":memory:":
        return Path(store_path).absolute().parent, True
    return destination.absolute() / _SERVER_DB_STAGING_DIR, True


def _standalone_staging_root() -> Path:
    """The OS temp dir, where a standalone verify stages, and which each backup also sweeps.

    Whatever ``tempfile.gettempdir`` answers. When no temp candidate is writable Python falls back to
    the current directory, and this does not second-guess that: telling the fallback apart from a
    temp dir that is also the current directory needs ``tempfile``'s private candidate list."""
    return Path(tempfile.gettempdir()).absolute()


def _sweep_os_temp(owner: object | None) -> int:
    """The backup's sweep of the OS temp dir, for what a killed standalone verify on this account
    left there, keyed on ``owner``, the process's own as :func:`_process_owner` reads it. Never
    raises: a temp dir that cannot be found, or an owner that could not be read, is a reason to skip,
    not to fail."""
    try:
        root = _standalone_staging_root()
    except OSError as exc:
        log.warning("DR staging: no OS temp dir to sweep: %s", safe_exc(exc))
        return 0
    if owner is None:
        log.warning("DR staging: cannot read this process's owner, so %s is not swept", root)
        return 0
    return _sweep_owned(root, owner, own=None)


def _process_owner() -> object | None:
    """The owner a directory this process creates gets, as :func:`_owner_of` reports it, read
    without creating one in the staging root. ``None`` when it cannot be read.

    POSIX: the effective uid, which is a new directory's ``st_uid``. Windows: the owner of a probe
    file made in the OS temp dir by :func:`_probe_owner`, since a local NTFS entry takes the token's
    default owner wherever it is made. On a share whose server sets the owner this answer differs
    from what a directory there gets, so the backup keys its OS-temp sweep on it, and sweeps its
    staging root by :func:`_probe_owner` of that root, or by this answer only as
    :func:`_fallback_root_owner` allows (BACKLOG #4988). On Windows this is ``None`` when the probe
    cannot be made; the backup then skips its OS-temp sweep."""
    if sys.platform != "win32":
        return os.geteuid()
    return _probe_owner(None)


@functools.cache
def _win_api() -> Any:
    """``kernel32`` with the prototypes the Windows owner probe uses (:func:`_win_create_owner_probe`,
    :func:`_win_sd_as_sddl`). The staging fail-safe's opens go through ``transports/file.py``'s own
    helpers instead (BACKLOG #4992)."""
    if sys.platform != "win32":  # pragma: no cover - guard for the type checker on POSIX
        raise OSError("the Windows file API runs only on Windows")
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.LocalFree.restype = ctypes.c_void_p
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    return kernel32


@functools.cache
def _win_security_api() -> Any:
    """``advapi32`` with the prototypes :func:`_win_owner_of_handle` uses."""
    if sys.platform != "win32":  # pragma: no cover - guard for the type checker on POSIX
        raise OSError("the Windows security API runs only on Windows")
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    pvoid_p = ctypes.POINTER(ctypes.c_void_p)
    advapi32.GetSecurityInfo.restype = wintypes.DWORD
    advapi32.GetSecurityInfo.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.DWORD,
        pvoid_p,
        pvoid_p,
        pvoid_p,
        pvoid_p,
        pvoid_p,
    ]
    advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = wintypes.BOOL
    advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPWSTR),
        ctypes.c_void_p,
    ]
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        pvoid_p,
        ctypes.c_void_p,
    ]
    return advapi32


def _win_sd_as_sddl(descriptor: Any, info: int) -> str | None:
    """The ``info`` parts of the security descriptor ``descriptor`` as SDDL, or ``None`` (logged)
    when it cannot be rendered."""
    if sys.platform != "win32":  # pragma: no cover - guard for the type checker on POSIX
        raise OSError("the Windows security API runs only on Windows")
    from ctypes import wintypes

    text = wintypes.LPWSTR()
    if not _win_security_api().ConvertSecurityDescriptorToStringSecurityDescriptorW(
        descriptor, 1, info, ctypes.byref(text), None
    ):
        log.warning(
            "DR staging: a security descriptor could not be rendered as SDDL: Win32 status %d",
            ctypes.get_last_error(),
        )
        return None
    try:
        return text.value
    finally:
        _win_api().LocalFree(ctypes.cast(text, ctypes.c_void_p))


def _win_handle_sddl(handle: int, info: int) -> str | None:
    """The ``info`` parts of the security descriptor of the object open as ``handle``, read with
    ``GetSecurityInfo`` on the handle, never by path, as SDDL. ``None`` (logged) when it cannot be
    read. The handle needs ``READ_CONTROL``."""
    if sys.platform != "win32":  # pragma: no cover - guard for the type checker on POSIX
        raise OSError("the Windows security API runs only on Windows")
    descriptor = ctypes.c_void_p()
    status = _win_security_api().GetSecurityInfo(
        handle,
        1,  # SE_FILE_OBJECT
        info,
        None,
        None,
        None,
        None,
        ctypes.byref(descriptor),
    )
    if status != 0:
        log.warning("DR staging: GetSecurityInfo could not read a handle: Win32 status %d", status)
        return None
    try:
        return _win_sd_as_sddl(descriptor, info)
    finally:
        _win_api().LocalFree(descriptor)


def _win_owner_of_handle(handle: int) -> object | None:
    """The owner SID of the object open as ``handle``, read with ``GetSecurityInfo`` on the handle,
    never by path, in the form :func:`_owner_of` reports (SDDL, aliases resolved), so the two compare.
    ``None`` when it cannot be read. The handle needs ``READ_CONTROL``."""
    return _owner_from_sddl(_win_handle_sddl(handle, 0x00000001))  # OWNER_SECURITY_INFORMATION


def _owner_from_sddl(sddl: str | None) -> object | None:
    """The owner SID an SDDL string names, aliases resolved, so :func:`_owner_of` and
    :func:`_owner_of_fd` answer in one form. ``None`` when it names none."""
    from messagefoundry.store.store import _SDDL_OWNER, _resolve_sid

    found = _SDDL_OWNER.search(sddl) if sddl else None
    return _resolve_sid(found.group(1)) if found else None


@contextlib.contextmanager
def _owner_probe(root: Path | None) -> Iterator[tuple[int, Path]]:
    """Create an empty ``mefor-owner-probe-*`` file under ``root`` (the OS temp dir when ``None``)
    with ``O_CREAT | O_EXCL``, yield its descriptor and path, and remove it on exit. A test seam.
    Raises ``OSError`` on entry when it cannot be created.

    POSIX: ``mkstemp``, removed on exit by name only when, at a check just before, its name still
    names the object it created: after a rename swap the name holds someone else's object, which is
    theirs to remove. A swap between that check and the unlink can still remove the swapped-in
    object. A removal that fails is logged and left for the next sweep. Windows:
    :func:`_win_create_owner_probe`, created with a protected access list and opened
    delete-on-close, so the file is deleted when its handle closes, wherever a rename has put it by
    then, and nothing is ever removed by its name."""
    if sys.platform == "win32":
        fd, probe = _win_create_owner_probe(Path(tempfile.gettempdir()) if root is None else root)
        try:
            yield fd, probe
        finally:
            os.close(fd)
        return
    fd, name = tempfile.mkstemp(prefix=_OWNER_PROBE_PREFIX, dir=root)
    try:
        yield fd, Path(name)
    finally:
        try:
            made, named = os.fstat(fd), os.lstat(name)
            if (made.st_dev, made.st_ino) == (named.st_dev, named.st_ino):
                os.unlink(name)
        except FileNotFoundError:
            pass  # a sibling's sweep, or a rename, already took the name
        except OSError as exc:
            log.warning("DR staging: could not remove owner probe %s: %s", name, safe_exc(exc))
        os.close(fd)


def _win_create_owner_probe(directory: Path) -> tuple[int, Path]:
    """Create the Windows owner probe under ``directory`` and return a descriptor owning its handle,
    and its path. Raises ``OSError`` when it cannot be created as asked.

    The probe carries, from the ``CreateFileW`` call that creates it, the protected access list
    :mod:`messagefoundry.restricted_file` writes on a key file: full control for SYSTEM,
    Administrators and the creating account, and nothing inherited from ``directory``. So no access
    entry inherited from the staging root gives another account ``WRITE_OWNER`` on it, and none can
    re-own it before its owner is read and choose the owner the sweep goes by (BACKLOG #4988). The
    list is read back from the handle before the probe is used, and a probe whose list is not
    protected, or is not exactly the list the create asked for, as on a server that does not
    apply the list a create asks for, is closed and refused. ``CREATE_NEW`` with
    ``FILE_FLAG_OPEN_REPARSE_POINT`` refuses a name already taken, by a file or by a link, and
    ``FILE_FLAG_DELETE_ON_CLOSE`` deletes the probe when the handle closes, wherever a rename has
    put it by then."""
    if sys.platform != "win32":  # pragma: no cover - guard for the type checker on POSIX
        raise OSError("the Windows owner probe runs only on Windows")
    import msvcrt
    from ctypes import wintypes

    from messagefoundry.config.wiring import _win32_config_source_probes
    from messagefoundry.restricted_file import _expected_access, _protected_sddl
    from messagefoundry.store.store import _parse_sddl_dacl

    self_sid = _win32_config_source_probes().self_sid
    if self_sid is None:
        raise OSError("this process's own account could not be read, so no probe was made")
    advapi32, kernel32 = _win_security_api(), _win_api()
    dacl_info = 0x00000004  # DACL_SECURITY_INFORMATION

    class _SecurityAttributes(ctypes.Structure):
        _fields_ = (
            ("nLength", wintypes.DWORD),
            ("lpSecurityDescriptor", ctypes.c_void_p),
            ("bInheritHandle", wintypes.BOOL),
        )

    descriptor = ctypes.c_void_p()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        _protected_sddl(_expected_access(self_sid, ())), 1, ctypes.byref(descriptor), None
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        # The list as Windows renders it, so the read-back below compares like with like.
        rendered = _win_sd_as_sddl(descriptor, dacl_info)
        asked = _parse_sddl_dacl(rendered) if rendered is not None else None
        if asked is None:
            raise OSError("the probe's access list could not be built")
        attributes = _SecurityAttributes(
            ctypes.sizeof(_SecurityAttributes), descriptor.value, False
        )
        for _attempt in range(100):
            probe = directory / f"{_OWNER_PROBE_PREFIX}{os.urandom(8).hex()}"
            handle = kernel32.CreateFileW(
                str(probe),
                0x00020000 | 0x00010000,  # READ_CONTROL, for the owner read; DELETE, for the close
                0x00000007,  # FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
                ctypes.byref(attributes),
                1,  # CREATE_NEW
                # FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_DELETE_ON_CLOSE
                0x00000100 | _FLAG_OPEN_REPARSE_POINT | 0x04000000,
                None,
            )
            if handle is not None and handle != ctypes.c_void_p(-1).value:
                break
            error = ctypes.get_last_error()
            if error not in (80, 183):  # ERROR_FILE_EXISTS, ERROR_ALREADY_EXISTS: another name
                raise ctypes.WinError(error)
        else:
            raise FileExistsError(f"no free owner probe name under {directory}")
    finally:
        kernel32.LocalFree(descriptor)
    try:
        sddl = _win_handle_sddl(handle, dacl_info)
        got = _parse_sddl_dacl(sddl) if sddl is not None else None
        if got is None or not got.protected or set(got.aces) != set(asked.aces):
            raise OSError(
                f"owner probe in {directory} does not carry the protected access list it was "
                "created with, so its owner is not read"
            )
        return msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY), probe
    except BaseException:
        kernel32.CloseHandle(handle)
        raise


def _probe_owner(root: Path | None) -> object | None:
    """The owner a new entry this process makes under ``root`` gets, as :func:`_owner_of` reports
    it, learned from a ``mefor-owner-probe-*`` file made there (:func:`_owner_probe`) and removed
    again. ``root`` ``None`` is the OS temp dir. ``None`` when the probe cannot be created or its
    owner read; nothing is created when ``root`` does not exist.

    The owner is read from the descriptor that created the probe (:func:`_owner_of_fd`): ``fstat`` on
    POSIX, ``GetSecurityInfo`` on its handle on Windows. It is never read by path, so an account that
    can rename entries in ``root`` cannot swap another object in at its name and choose the answer;
    nor can a sibling engine shard's sweep removing it first. An empty file needs no data block, so
    it can often be created on a volume full to the last block, though not on one out of inodes or
    MFT records (BACKLOG #4988).

    The probe holds no lock and no marker, so it is never a staging directory. One whose removal
    fails is left empty, and the next sweep of that root by its owner removes it
    (:func:`_sweep_owned`)."""
    owner: object | None = None
    try:
        with _owner_probe(root) as (fd, name):
            owner = _owner_of_fd(fd, name)
    except FileNotFoundError:
        pass  # no such root (or no temp dir): nothing to probe, and nothing to sweep there
    except OSError as exc:
        # The probe's creation, or its close once the owner was read, which keeps that owner.
        # `_owner_of_fd` itself never raises.
        log.warning(
            "DR staging: owner probe in %s failed: %s",
            "the OS temp dir" if root is None else root,
            safe_exc(exc),
        )
    return owner


def _owner_of_fd(fd: int, opened_as: Path) -> object | None:
    """The owner of the object open as ``fd``, read from the descriptor, never by path: ``fstat`` on
    POSIX, ``GetSecurityInfo`` on its handle on Windows, in the form :func:`_owner_of` reports.
    ``None`` when it cannot be read.

    ``opened_as`` is the path ``fd`` was opened at. It is never read here: it is the seam a test's
    stand-in for a share whose server sets the owner keys on, as it keys :func:`_owner_of` on a
    path."""
    del opened_as
    if sys.platform == "win32":
        import msvcrt

        try:
            return _win_owner_of_handle(msvcrt.get_osfhandle(fd))
        except OSError as exc:
            log.warning("DR staging: could not read an owner from a handle: %s", safe_exc(exc))
            return None
    try:
        return os.fstat(fd).st_uid
    except OSError as exc:
        log.warning("DR staging: could not read an owner from a descriptor: %s", safe_exc(exc))
        return None


def _open_for_owner(root: Path) -> int:
    """Open the directory ``root`` for :func:`_owner_of_fd` and return a descriptor. POSIX follows a
    link, as the sweep and the staging open do. Windows opens a link or junction as itself, with
    ``READ_CONTROL`` and ``FILE_READ_ATTRIBUTES``, so the caller can refuse it."""
    if sys.platform == "win32":
        # READ_CONTROL | FILE_READ_ATTRIBUTES, through `transports/file.py`'s own open; its
        # FILE_FLAG_BACKUP_SEMANTICS lets a directory open at all.
        return _fd_for(
            _win_create(
                root,
                0x00020000 | 0x00000080,
                _SHARE_ALL,
                _FLAG_OPEN_REPARSE_POINT | _FLAG_BACKUP_SEMANTICS,
            )
        )
    return os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)


def _names_another_path(fd: int) -> bool:
    """Whether the object open on ``fd`` is a Windows reparse point that names another path: a
    symbolic link or a junction opened as itself. Always ``False`` on POSIX, where the caller's open
    follows a link as the sweep does."""
    if sys.platform != "win32":
        return False
    attributes, tag = _attribute_tag(_os_handle(fd))
    return bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT and tag & _WIN_NAME_SURROGATE)


def _fallback_root_owner(root: Path, process: object | None) -> object | None:
    """The owner the backup's early staging-root sweep goes by when :func:`_probe_owner` of ``root``
    answers ``None``, such as on a volume a killed run filled: ``process``, the process's own owner
    as :func:`_process_owner` reads it, and only when ``root`` itself carries that owner. ``None``
    otherwise, and the early sweep is then off. A root that does not exist answers ``None`` with no
    log line, since there is nothing to sweep; any other refused probe is logged at WARNING.

    The gate is what keeps BACKLOG #4988 closed. On a share whose server sets the owner, what this
    account makes there, its staging root among it, carries the server's choice, so the gate fails
    and no directory carrying the process's own owner, which another principal may have made there,
    is swept by it. Where a new entry gets the process's owner, a root this account made carries it,
    so the sweep frees a killed run's leftover before the space check, as it did before the probe.
    The root is opened (:func:`_open_for_owner`) and its owner read from that descriptor; on Windows
    a link or junction root is refused, as :func:`_owner_of` refuses one. What the gate leaves open
    is listed once, in docs/PHI.md section 2's ``mefor-backup-*`` / ``mefor-verify-*`` staging row."""
    if not os.path.isdir(root):
        return None
    log.warning(
        "DR staging: could not learn the owner a new entry in %s gets from a probe there", root
    )
    if process is None:
        return None
    try:
        fd = _open_for_owner(root)
    except OSError as exc:
        log.warning(
            "DR staging: could not open staging root %s to read its owner: %s", root, safe_exc(exc)
        )
        return None
    try:
        if _names_another_path(fd):
            log.warning(
                "DR staging: staging root %s is a link or junction; its owner is not read", root
            )
            return None
        return process if _owner_of_fd(fd, root) == process else None
    except OSError as exc:
        log.warning(
            "DR staging: could not read the owner of staging root %s: %s", root, safe_exc(exc)
        )
        return None
    finally:
        os.close(fd)


def _owner_of(path: Path) -> object | None:
    """Who owns ``path``: a uid on POSIX, an owner SID on Windows. ``None`` when it cannot be read,
    and ``None`` for a link or a junction, whose owner is never reported: Windows would read through
    it to its target. A reparse point that names no other path, such as a cloud placeholder, is read
    as itself (BACKLOG #2420). Compared only with another ``_owner_of`` answer.

    On Windows an elevated process's default owner is Administrators, not its user, so every elevated
    account on the box, and SYSTEM, can share one owner here."""
    try:
        st = os.lstat(path)
    except OSError:
        return None
    reparse = getattr(st, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
    if stat.S_ISLNK(st.st_mode) or (
        reparse and getattr(st, "st_reparse_tag", 0) & _WIN_NAME_SURROGATE
    ):
        return None
    if sys.platform != "win32":
        return st.st_uid
    from messagefoundry.store.store import _read_dacl_sddl

    return _owner_from_sddl(_read_dacl_sddl(path, owner=True))


def _sweep_abandoned_staging(root: Path, *, owner: object | None, own: Path) -> int:
    """Remove the staging directories under ``root`` that a dead run left behind. Never raises.

    A directory is removed only when its lock file exists, its lock can be taken, and it holds the
    marker a run creates once it holds the lock. That set means the run that made it is
    gone: the OS dropped its lock with the process. Everything else is left alone -- a live run holds
    its lock, and a directory with no lock or no marker has not had plaintext written to it. Age is
    never consulted. Returns how many directories were removed.

    ``own`` names a directory this run just created, left alone, and only a directory with ``owner``
    is a candidate; nothing is swept when ``owner`` is ``None``, an owner that could not be read. It
    is required (BACKLOG #2420). A standalone verify passes, for the OS temp dir, which can be
    shared, :meth:`_Staging.owner` of its own directory: the owner of the lock file it created
    there, read from its descriptor, never by path, so a rename in ``root`` cannot choose it
    (BACKLOG #4988). A backup sweeps both the OS
    temp dir and its own staging root, whose `.mefor-staging` inherits what the destination grants,
    with :func:`_sweep_owned` by the same rule: the staging root keyed on the owner a probe there
    gets (:func:`_probe_owner`), or on the process's owner only as :func:`_fallback_root_owner`
    allows, and the OS temp dir on :func:`_process_owner`.
    Another account could plant a directory in either holding a lock file and a marker, and the
    teardown must never run on a tree it controls."""
    if owner is None:
        log.warning(
            "DR staging: this run's owner for %s could not be read, so %s is not swept", own, root
        )
        return 0
    return _sweep_owned(root, owner, own=own)


def _sweep_owned(root: Path, owner: object, *, own: Path | None) -> int:
    """:func:`_sweep_abandoned_staging` for a known ``owner``, as :func:`_owner_of` reports it,
    leaving ``own`` alone."""
    swept = 0
    try:
        entries = list(os.scandir(root))
    except FileNotFoundError:
        return 0
    except OSError as exc:
        log.warning("DR staging: could not list staging root %s: %s", root, safe_exc(exc))
        return 0
    for entry in entries:
        probe = entry.name.startswith(_OWNER_PROBE_PREFIX)
        if not probe and not entry.name.startswith(_SWEPT_PREFIXES):
            continue
        path = Path(entry.path)
        try:
            if probe and entry.is_file(follow_symlinks=False):
                # A probe file `_probe_owner` failed to remove. Only an empty one with this
                # owner goes, and `unlink` removes the name itself, never what a link names.
                st = entry.stat(follow_symlinks=False)
                if st.st_size == 0 and _owner_of(path) == owner:
                    try:
                        os.unlink(path)
                    except FileNotFoundError:
                        pass
                    except OSError as exc:
                        log.warning(
                            "DR staging: could not remove leaked owner probe %s: %s",
                            path,
                            safe_exc(exc),
                        )
                continue
            if not entry.is_dir(follow_symlinks=False) or os.path.isjunction(entry.path):
                continue
        except OSError:
            continue
        if path == own:
            continue  # this run's own directory, held live
        if probe:
            # A probe-named directory. `rmdir` alone, which refuses a directory that
            # holds anything and never follows a link, so nothing but an empty directory goes.
            if _owner_of(path) == owner:
                with contextlib.suppress(OSError):
                    os.rmdir(path)
            continue
        # No lock file is no proof either way. Checked before the owner, which on Windows costs a
        # security-descriptor read, so a temp dir full of other programs' leftovers stays cheap.
        if not os.path.lexists(path / _LOCK_NAME):
            continue
        if _owner_of(path) != owner:
            # Not this account's, or an owner that could not be read: another account's run, such as
            # an administrator's interactive one, or a plant. Said, not skipped silently.
            log.warning(
                "DR staging: staging directory %s has another owner, so the sweep leaves it", path
            )
            continue
        try:
            # `_O_NONBLOCK` as the re-mark has it: a FIFO planted at the lock must not hold the sweep.
            fd = os.open(
                path / _LOCK_NAME,
                os.O_RDWR | getattr(os, "O_BINARY", 0) | _O_NOFOLLOW | _O_NONBLOCK,
            )
        except FileNotFoundError:
            continue  # no lock file: no proof either way
        except OSError as exc:
            # A directory with this account's owner whose lock file this account still cannot open;
            # another owner's directory never reaches here, since the owner is checked first. Said,
            # not skipped silently.
            log.warning(
                "DR staging: cannot open the lock of staging directory %s, so the sweep leaves it: %s",
                path,
                safe_exc(exc),
            )
            continue
        try:
            if not _lock_exclusive(fd, wait=False):
                continue  # a live run holds it
            if not os.path.lexists(path / _HELD_MARKER_NAME):
                continue  # locked by nobody, but no marker: not proven abandoned
        except OSError as exc:
            log.warning(
                "DR staging: could not test the lock of staging directory %s: %s",
                path,
                safe_exc(exc),
            )
            continue
        finally:
            _unlock_and_close(fd)
        leftover = _teardown_staging(path)
        if leftover is not None:
            log.error("DR staging: an abandoned staging directory survived the sweep: %s", leftover)
        elif os.path.lexists(path):
            log.warning(
                "DR staging: emptied abandoned staging directory %s but could not remove it; the "
                "next sweep of this root retries it",
                path,
            )
        else:
            swept += 1
            log.info("DR staging: removed abandoned staging directory %s", path)
    return swept


def _verify_in_staging(
    staging: Path,
    *,
    archive_path: str,
    encrypted: bool,
    match_key: bytes | None,
    full: bool,
    store_settings: object | None,
    secure: bool = False,
    posture: HopPosture | None = None,
) -> VerifyResult:
    """Steps 2 to 4 of :func:`_verify_archive_blocking`, writing into ``staging``, which the caller
    creates and always discards. With ``secure``, each plaintext file is locked to its owner before its
    first byte."""
    tar_path = staging / "archive.tar"
    # (2) decrypt (or copy a plaintext archive) to the tar.
    with open(archive_path, "rb") as src, open(tar_path, "wb") as dst:
        _secure_staged(tar_path, secure)
        if encrypted:
            assert match_key is not None
            # Post-authentication resource bound on the temp dir (see the constant). An over-cap
            # archive raises BackupCodecError, which the caller's `_verify_failure` arm
            # already turns into a FAIL — no new failure arm, and the caller's staging
            # teardown discards the partial tar on the way out.
            decrypt_stream(src, dst, match_key, max_plaintext_bytes=_MAX_RESTORE_PLAINTEXT_BYTES)
        else:
            while True:
                buf = src.read(1024 * 1024)
                if not buf:
                    break
                dst.write(buf)
    manifest = _read_manifest_from_tar(tar_path)
    if manifest.get("config_only"):
        # A config-only archive (server-DB store) has no store.db to integrity-check; verifying
        # it means "the tar decrypts + carries the manifest + config", which steps 1-2 proved.
        return VerifyResult(
            "PASS",
            integrity_ok=True,
            reason="config-only archive (server-DB store, DBA-delegated DB)",
        )
    snap = _extract_member(tar_path, _STORE_MEMBER, staging, secure=secure)
    if snap is None:
        return VerifyResult("FAIL", reason="archive has no store.db member")

    # (3) integrity_check (the fuller PRAGMA integrity_check, off the hot path).
    integrity_ok, integrity_msg = _integrity_check(snap)
    row_counts = _count_tables(snap)
    manifest_counts, count_refusal = _compare_row_counts(manifest, row_counts)
    if not integrity_ok:
        return VerifyResult(
            "FAIL",
            integrity_ok=False,
            row_counts=row_counts,
            manifest_counts=manifest_counts,
            reason=f"integrity_check failed: {integrity_msg}",
        )
    # (4) row-count sanity vs the manifest (catches a torn/truncated snapshot, and a compare that
    # read nothing); :func:`_compare_row_counts` says why it is keyed off the manifest's tables.
    if count_refusal is not None:
        return VerifyResult(
            "FAIL",
            integrity_ok=True,
            row_counts=row_counts,
            manifest_counts=manifest_counts,
            reason=count_refusal,
        )
    decrypted_cells = 0
    if full:
        # The heavier end-to-end restore: open the snapshot through the real open_store path
        # (cipher + migrations) to prove it restores, decrypt + authenticate its PHI, then
        # discard it.
        full_status, full_msg, decrypted_cells = _full_open_check(
            snap,
            _as_store_settings(store_settings),
            engine_version=str(manifest.get("engine_version") or ""),
            posture=posture,
        )
        if full_status != "PASS":
            return VerifyResult(
                full_status,
                integrity_ok=True,
                row_counts=row_counts,
                manifest_counts=manifest_counts,
                # No status word in the prefix: the caller that turns this into a BackupError
                # already prints `verify.status`, and repeating it reads as two verdicts.
                reason=f"full restore-verify: {full_msg}",
            )
    return VerifyResult(
        "PASS",
        integrity_ok=True,
        row_counts=row_counts,
        manifest_counts=manifest_counts,
        decrypted_cells=decrypted_cells,
    )


def _decode_store_key(key_b64: str) -> bytes:
    """One base64 store key as the 32 bytes it names, by the rule ``open_store`` applies.

    A key that is not strict base64 of 32 bytes raises :class:`StoreCipherConfigError`, which the
    ``restore-verify`` and ``restore`` commands report as "could not start" and exit 2, and a backup
    run records as a failed backup (BACKLOG #4878). Its text is the decoder's fixed sentence. The
    decoder, ``_decode_key``, already raises its ``ValueError`` with no chain (BACKLOG #3471); this
    wrapper changes only the type, so the callers' ``StoreCipherConfigError`` handling reaches it,
    and raises outside the handler so the new error carries no chain either."""
    try:
        decoded = _decode_key(key_b64, "a store encryption key")
    except ValueError as exc:
        reason = str(exc)
    else:
        key = bytes(decoded)
        decoded[:] = bytes(len(decoded))  # best effort: the decoder's copy exists to be wiped
        return key
    raise StoreCipherConfigError(reason)


async def run_restore_verify(
    archive_path: str,
    *,
    store_settings: object,
    full: bool = False,
    allow_unencrypted: bool = False,
    posture: HopPosture | None = None,
) -> VerifyResult:
    """Verify an existing ``.mfbak`` archive WITHOUT activating it (ADR 0049 — 0049's owned primitive,
    which ADR 0048's cold-seed activation *calls*). Resolves the store's decrypt-capable keyring (active
    + retired, AC-5 "incl. retired keys"), runs the key-fingerprint precheck → decrypt → integrity_check
    → row-count compare, and returns a structured ``PASS``/``FAIL``/``KEY_MISMATCH``
    :class:`VerifyResult`. All heavy work runs off the event loop.

    ``allow_unencrypted`` (``[backup].allow_unencrypted``, default off) mirrors the write-side fail-closed:
    with it off, a plaintext archive is refused (``KEY_MISMATCH``) when a store key is configured (ASVS
    5.2.3 downgrade guard)."""
    # The decrypt-capable keyring, NOT just the active key: a backup taken under a key that has since
    # been retired (a routine WP-5 rotation) must still verify, or ADR 0048's cold-seed activation would
    # falsely refuse a perfectly recoverable archive (AC-5: compare to the resolved key, incl. retired).
    # `posture` is the caller's, for the Vault hop the key resolve and a full verify can dial
    # (vault BACKLOG #2983). The engine's DR activation passes its own; the `restore-verify`
    # command holds none, and `None` counts as enforcing on that hop.
    keys = [
        _decode_store_key(k)
        for k in resolve_decrypt_keys(
            store_settings,  # type: ignore[arg-type]
            posture=posture,
        )
    ]
    # `staging_root=None` is a standalone verify: a private directory under the OS temp dir, never
    # where the backup runner stages. See the staging-location block above `_Staging` (BACKLOG #1174).
    return await asyncio.to_thread(
        _verify_archive_blocking,
        archive_path=archive_path,
        keys=keys,
        full=full,
        staging_root=None,
        secure=True,
        allow_unencrypted=allow_unencrypted,
        # Threaded through so a full verify opens the snapshot under the SAME cipher/keyring/provider
        # the keyring above was resolved from, instead of a bare default (see _full_open_check).
        store_settings=store_settings,
        posture=posture,
    )


# --- small pure helpers (no store/loop) --------------------------------------


def _looks_encrypted(archive_path: str) -> bool:
    """Whether the file begins with the ``.mfbak`` magic (an encrypted/codec archive) vs a plaintext tar
    (the ``allow_unencrypted`` path). Cheap header sniff."""
    from messagefoundry.store.backup_codec import MAGIC

    try:
        with open(archive_path, "rb") as fh:
            return fh.read(len(MAGIC)) == MAGIC
    except OSError:
        return False


def _sha256_file(path: Path) -> str:
    import hashlib

    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


#: sqlite3's own default. Nothing else writes a snapshot these checks open, the backup's own or an
#: extracted one, so it never waits.
_SNAPSHOT_BUSY_TIMEOUT = 5.0


def _count_tables(db_path: Path) -> dict[str, int]:
    """Row counts for EVERY table in ``db_path``'s own schema, via a plain read-only sqlite3
    connection (no engine store). The table set is DERIVED from ``sqlite_master`` at count time
    rather than a hand-picked sample (BACKLOG #1722): the old fixed four-table list
    (``messages``/``queue``/``message_events``/``audit_log``) covered 4 of this schema's 30 tables —
    a truncated or absent table among the other 26 (at least the auth tables ``users``/``sessions``/
    ``roles``/``webauthn_credentials``) passed
    restore-verify PASS undetected, and the old list could not have named all of them: it predates
    several of those tables entirely, and the next one added to the schema would have been silently
    out of scope again. Called once against the just-taken snapshot when the manifest is written and
    once against the restored snapshot at verify time.

    Both calls read the identical file (the ``.mfbak`` codec is authenticated encryption, not a
    transform), so for a manifest and archive written by the SAME build of this function the two
    calls always return the same keys. They can still return DIFFERENT keys across a build boundary
    — a manifest written before this table set was widened (or before a later table existed at all)
    has fewer keys than a snapshot's schema really has — and that is expected, not tampering:
    ``run_restore_verify`` is a standalone check of an archive from any earlier point (AC-5), so an
    older, narrower manifest is an ordinary thing to verify. The compare in
    :func:`_compare_row_counts` is written to tolerate exactly that (keyed off the manifest's
    own keys, not dict equality) — this function only ever reports what IS in the schema, and does
    not itself guarantee cross-build equality.

    ``sqlite_%`` names are excluded: they are sqlite's own bookkeeping (e.g. ``sqlite_sequence`` for
    an ``AUTOINCREMENT`` column), not store data, and are not guaranteed to exist at all until some
    other operation (a first autoincrement insert, an ``ANALYZE``) creates them.

    Opened through :func:`connect_readonly`, so a ``#`` or ``?`` in the staging path cannot cut the
    URI and count an empty stand-in (BACKLOG #2186)."""
    conn = connect_readonly(db_path, busy_timeout=_SNAPSHOT_BUSY_TIMEOUT)
    try:
        names = sorted(
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\'"
            )
        )
        counts: dict[str, int] = {}
        for table in names:
            # table is a real identifier read back from this same file's own sqlite_master, but
            # quote + escape it anyway rather than trust that no engine table name will ever need
            # quoting (ASVS: parameterize/escape identifiers, don't rely on today's schema).
            quoted = table.replace('"', '""')
            (n,) = conn.execute(f'SELECT COUNT(*) FROM "{quoted}"').fetchone()
            counts[table] = int(n)
    finally:
        conn.close()
    return counts


def _integrity_check(db_path: Path) -> tuple[bool, str]:
    """``PRAGMA integrity_check`` on a snapshot, opened through :func:`connect_readonly`, so a ``#``
    or ``?`` in the staging path cannot cut the URI and check an empty stand-in (BACKLOG #2186)."""
    conn = connect_readonly(db_path, busy_timeout=_SNAPSHOT_BUSY_TIMEOUT)
    try:
        results = [str(r[0]) for r in conn.execute("PRAGMA integrity_check")]
    finally:
        conn.close()
    ok = results == ["ok"]
    return ok, "ok" if ok else "; ".join(results)[:500]


def _full_open_check(
    snap: Path,
    settings: StoreSettings | None,
    *,
    engine_version: str = "",
    posture: HopPosture | None = None,
) -> tuple[str, str, int]:
    """Decrypt + authenticate the snapshot's PHI as archived, then open it through the real
    ``open_store`` path.
    Returns ``(status, message, decrypted_cells)`` — the ``VerifyResult`` status this leg earned, so the
    caller can hand it straight on. Heavier; only run for ``full_restore_verify``.

    ``KEY_MISMATCH`` is reserved for the one cause the keyring is unambiguously to blame for: these
    settings resolve **no** key for a snapshot that needs one, because it holds sealed (``mfenc:``)
    cells or its ``keyed_surface`` rows record it as keyed, so nothing could have read it. An
    operator reading that fixes their key configuration; reading ``FAIL`` they would go looking for
    a bad archive. A BLOB found before the decision is named in the reason too, since no key will
    clear it (:func:`_decrypt_check`). A cell that will not decrypt under
    a keyring that DOES hold keys stays ``FAIL``, because :class:`CipherError` cannot tell a corrupted
    ciphertext from a key that was never supplied (see its own docstring) and corruption is the reading
    that must not be talked down.

    ``settings`` must be the LIVE store settings, with **only** the path (and the backend, below)
    substituted. A bare ``StoreSettings(path=...)`` resolves no key, so an ENCRYPTED snapshot opens under
    the identity cipher: the open succeeds, ``quick_check`` passes, and the verify reports PASS having
    proved nothing about whether a single PHI cell is readable. Substituting only the path is what keeps
    every field that governs HOW the bytes are read — ``cipher_provider``, ``key_provider``, the active +
    retired keyring, ``aad_bind`` — and it is why this is a ``model_copy`` rather than a rebuilt object:
    a field added to ``StoreSettings`` later rides along instead of being silently dropped.

    ``backend`` is the one other substitution. The extracted member is a SQLite file by construction
    (``Store.snapshot_to`` writes one, and the integrity/row-count steps above already read it with
    ``sqlite3``), so an instance that has since moved to a server DB must still verify its older SQLite
    archive against SQLite rather than dialling Postgres/SQL Server with a file path.

    ``engine_version`` is the manifest's, named in the refusal of a snapshot this build cannot open
    (BACKLOG #2101). The store's own remedy for that case, recreating the store, is wrong here: the
    archive is not damaged, and what restores it is the version that wrote it."""
    from messagefoundry.store.base import open_store

    if settings is None:
        # Fail-closed. The only thing available without the live settings is a keyless open, and a PASS
        # from one says nothing about an encrypted archive — which is the archive worth verifying.
        return "FAIL", "no live store settings were supplied for the full restore-verify", 0
    snap_settings = settings.model_copy(update={"path": str(snap), "backend": StoreBackend.SQLITE})
    # The cells are read FIRST, from the snapshot as the archive holds it (BACKLOG #1719). The open
    # below is a keyed open, and its at-open sweep seals what it reads as legacy plaintext: under
    # the opt-out, or on a surface no keyed open recorded, that includes a value whose marker is
    # damaged, which would then open cleanly and PASS. Read first, the walk judges that value as
    # it was archived, and the verdict matches `cipher-audit`'s on the same store.
    walked = _decrypt_check(snap, snap_settings, posture=posture)
    # ADR 0196 AC-8: the snapshot is a copy of the LIVE store and carries its salt. Opened as it is,
    # anything the open seals (the at-open sweep) would land under the live store's data sub-key and
    # be counted only in this throwaway copy's row. Dropping the salt makes the open mint a new one,
    # so whatever it seals is under a key nothing else uses. Every existing value names its own salt,
    # so the decrypt pass below is unaffected. The copy is discarded afterwards either way.
    import sqlite3

    from messagefoundry.store.store import forget_store_salt

    try:
        forget_store_salt(snap)
    except sqlite3.Error as exc:
        return "FAIL", safe_exc(exc), 0

    async def _open() -> tuple[bool, str]:
        # Bind the store BEFORE the try. An open that raises — a keyless or wrong-key open, an
        # unreachable key provider — must surface ITS OWN cause, not a NameError from a finally closing
        # a store that was never created. A handle left open here would also hold the extracted store
        # on Windows and send the staging teardown to its fail-safe (see _discard_verify_staging).
        # A throwaway snapshot copy, integrity-checked and deleted, so nothing it writes outlives
        # the check (BACKLOG #1916). A keyed open of a snapshot whose audit_log is EMPTY writes that
        # copy's genesis row, like any keyed open of an empty log, and tees it; a snapshot of a
        # store that holds a key already has one.
        # `posture` is the caller's, for the Vault hop the cipher build can dial; `None` counts
        # as enforcing there (vault BACKLOG #2983). The snapshot itself is always SQLite.
        store = await open_store(snap_settings, keyless_chain_refusal=None, posture=posture)
        try:
            return await store.integrity_check()
        finally:
            await store.close()

    # Verdict order: an incompatible snapshot first, since its cells may read wrongly only because
    # this build reads them differently, and the remedy is the version that wrote it; then the
    # walk's verdict, which read the archive before the open could change it; then the open's.
    try:
        ok, msg = run_guarded(_open())
    except SchemaMismatchError as exc:
        return "FAIL", _incompatible_snapshot(exc, engine_version), 0
    except StoreKeylessError as exc:
        # The store's own eager `state`/`reference` warm-ups fail closed on a keyless open of an
        # encrypted store. Same cause, same verdict — an absent keyring, not a bad archive. Its
        # text names the setting to fix, so it leads; a walk that found the same keeps its line.
        if walked[0] == "FAIL":
            return walked
        reason = safe_exc(exc) if walked[0] == "PASS" else f"{safe_exc(exc)}; {walked[1]}"
        return "KEY_MISMATCH", reason, 0
    except Exception as exc:  # a restore that won't even open is the thing we're trying to catch
        return walked if walked[0] != "PASS" else ("FAIL", safe_exc(exc), 0)
    if walked[0] != "PASS":
        return walked
    if not ok:
        return "FAIL", msg, 0
    return walked


#: Longer than safe_exc's default, so the remedy and at least the first differences survive.
_INCOMPATIBLE_REASON_LIMIT = 600


def _incompatible_snapshot(exc: SchemaMismatchError, engine_version: str) -> str:
    """The restore-verify refusal of a snapshot this build's schema cannot open (BACKLOG #2101).

    The store's own message tells an operator to move the store aside and recreate it, and for an
    encrypted store to change its key first. Neither applies to an archive, so this names the
    version to restore it with instead. The remedy leads and the differences follow, so a short
    display loses only the detail."""
    # The manifest is inside the authenticated archive, but it is still a string this build did not
    # write, so only a short, printable version label is quoted back.
    version = "".join(c for c in engine_version[:40] if c.isprintable())
    wrote = f"engine {version!r}" if version else "the engine version that wrote it"
    if exc.differences:
        tail = f"Differences: {'; '.join(exc.differences)}."
    else:
        tail = f"The schema step failed: {exc.cause or ''}."
    # Redacted and bounded like every other arm's reason (safe_exc there): the tail is driver text
    # and a difference list with no length of its own. The remedy leads, so a cut loses only detail.
    return safe_text(
        "the archive's store is from an incompatible version, so this build cannot open it: restore"
        f" it with {wrote}. The archive opened and passed its integrity and row-count checks; its"
        f" cells were not decrypted. {tail}",
        limit=_INCOMPATIBLE_REASON_LIMIT,
    )


def _sqlite_error_reason(exc: sqlite3.Error) -> str:
    """A SQLite error as a FAIL reason that quotes no row. Its decode error quotes the column's
    bytes (``... with text '...'``), which are a row's content and which ``safe_exc`` keeps, so
    that tail is cut, as ``cipher-audit``'s report cuts it."""
    text = re.sub(r" with text '.*\Z", " (its text is not shown)", str(exc), flags=re.DOTALL)
    return safe_text(f"{type(exc).__name__}: {text}")


def _decrypt_check(
    snap: Path, settings: StoreSettings, *, posture: HopPosture | None = None
) -> tuple[str, str, int]:
    """Decrypt AND authenticate every cipher-covered cell retained in the snapshot, under the store's own
    cipher. Returns ``(status, message, cells)`` — a COUNT and a PHI-free reason, never a plaintext.

    Opening the store proves the file is a readable SQLite database. It does not prove the PHI inside it
    is readable, and those are the two different claims a disaster-recovery check gets confused about: a
    bit-flipped AEAD cell passes ``PRAGMA quick_check`` and every row count, so without this pass a full
    verify would report PASS on an archive whose bodies no longer decrypt. Each value is opened with the
    same cell-bound AAD the store writes (ASVS 11.3.3), so a ciphertext moved between cells fails its tag
    here exactly as it would at a live read.

    The cell list is :data:`~messagefoundry.store.cipher_cells.SQLITE_CIPHER_CELLS`, the id-keyed and
    the composite-key cells alike (BACKLOG #1719). It is declared beside the store rather than here,
    and a parity test pins it to at least every literal ``cell_aad`` call in ``store.py``. A failure
    names the table, the column and the cell's ``locator``, never a key column that can itself be PHI.

    The walk is :func:`~messagefoundry.store.cipher_cells.read_cipher_cells`, which ``cipher-audit``
    shares, and so is its verdict precedence: a keyed snapshot read with no key
    (:func:`~messagefoundry.store.cipher_cells.keyed_store_mismatch`), then a sealed text value no
    key opened, then a failure. Under a key no keyless reading can come, so this pass stops at the
    first value that does not open. With no key it reads on past a BLOB, which fails under any
    cipher, so a sealed value later in the walk still decides KEY_MISMATCH, as ``cipher-audit``
    decides it, whichever row comes first. A full verify runs this pass before the store's own
    open (:func:`_full_open_check`), so the open cannot decide first or change a cell this reads.

    It also reads the non-blank values with no marker, as ``cipher-audit`` does: one on a surface
    the keyed store has sealed fails, unless ``allow_unmarked_ciphertext`` is set, because the
    store refuses it at read. Selecting by the marker alone never read such a value, which is where
    a damaged marker lands. One on a surface no keyed open recorded is legacy plaintext, and passes.
    """
    cipher = build_store_cipher(settings, posture=posture)
    cells = 0
    first_blob: str | None = None
    # The store's own read-only URI builder, not `f"file:{snap}"`: a path can hold `#` or `?`, and
    # an unquoted `#` cut the path short, so the old open read a different, empty file and passed.
    conn = connect_readonly(snap, busy_timeout=_SNAPSHOT_BUSY_TIMEOUT)
    try:
        mismatch = keyed_store_mismatch(conn, cipher, store_tables(conn), source="snapshot")
        if mismatch is not None:
            return "KEY_MISMATCH", mismatch, cells
        for reading in read_cipher_cells(conn, cipher, unmarked=True):
            if reading.kind == "unmarked":
                # A non-blank value with no marker on a surface the keyed store sealed: the store
                # refuses it at read, so it is a damaged or stripped marker or a planted row, as
                # `cipher-audit` reports it. Under the audited opt-out the store reads it as
                # plaintext, and so does this. Only a keyed walk yields one.
                if settings.allow_unmarked_ciphertext:
                    continue
                return (
                    "FAIL",
                    f"{reading.cell.table}.{reading.cell.column} {reading.where} carries no "
                    "at-rest marker on a surface this keyed store has sealed, so the store "
                    "refuses it at read: a damaged or stripped marker, or a planted row",
                    cells,
                )
            if reading.kind == "legacy":
                # Plaintext on a surface no keyed open recorded, which the next keyed open seals.
                continue
            if reading.kind == "keyless":
                # The #241 F2 keyless-open trap: the snapshot holds sealed text and these settings
                # resolved no key for it. Nothing could have opened it, so the keyring is
                # unambiguously the cause. Keylessness is the CIPHER's, never a plaintext's: a
                # decrypted value may itself begin with the marker. A BLOB never comes here.
                mismatch = with_first_failure(reading.failure(source="snapshot"), first_blob)
                return "KEY_MISMATCH", mismatch, cells
            elif reading.kind == "blob":
                # FAIL under any cipher, and never the keyring's: no key makes a BLOB readable.
                if cipher.encrypts:
                    return "FAIL", reading.failure(source="snapshot"), cells
                first_blob = first_blob or reading.failure(source="snapshot")
            elif reading.kind == "failed":
                # Only under a key: a keyless walk never decrypts. FAIL, not KEY_MISMATCH:
                # CipherError cannot separate a corrupted ciphertext from a key that was never
                # supplied, so the softer verdict on a bit-flipped PHI cell is the reading that
                # must not be talked down.
                return "FAIL", reading.failure(source="snapshot"), cells
            elif reading.kind == "opened":
                cells += 1
        if first_blob is not None:
            return "FAIL", first_blob, cells
    except sqlite3.Error as exc:
        return "FAIL", _sqlite_error_reason(exc), cells
    except CipherWalkInterrupted as exc:  # nothing else writes a snapshot, but never PASS a part
        return "FAIL", str(exc), cells
    finally:
        conn.close()
    return "PASS", "ok", cells


def _read_manifest_from_tar(tar_path: Path) -> dict[str, object]:
    # ASVS 5.2.3: pin the UNCOMPRESSED reader ("r:", not "r"). The writer only ever writes an
    # uncompressed tar, so auto-detecting/decompressing gzip/bz2/xz here is pure attack surface (a
    # decompression-bomb vector) — "r:" refuses a compressed archive with tarfile.ReadError.
    #
    # ASVS 5.2.3 bound (BACKLOG #1570). The manifest is the one member parsed INTO MEMORY rather
    # than streamed to disk (json.loads holds the decoded object on top of the raw bytes), so it
    # needs a cap of its own; _extract_member bounds the store member separately.
    #
    # Two checks, and they are NOT independent — said plainly so nobody re-derives a stronger claim
    # from the shape. In random-access mode ("r:") tarfile bounds the reader it hands back by the
    # member's declared `size`, so the read can never return more than that: reject an over-cap
    # `size` first and the length check below cannot fire. Each check bounds memory on its own (the
    # first refuses before reading; the second reads at most cap+1 whatever the header claims), and
    # keeping both means neither the header nor the read is the single point the bound rests on.
    # What it does NOT buy is a defence against "a lying stream" — for this reader there is no such
    # thing, because the header IS the stream bound.
    #
    # Scope, stated so it is not over-claimed: on the encrypted path this read is
    # POST-AUTHENTICATION. `decrypt_stream` has already verified every AES-GCM frame tag under the
    # store DEK, so reaching this line means the archive was sealed by a holder of the key. The cap
    # is defence in depth — against a locally damaged or tampered archive, and against the
    # `allow_unencrypted` plaintext path, which has no tag to check. It is NOT a pre-auth exposure.
    #
    # Every way the manifest can be unusable is reported as ONE type, `tarfile.TarError`, from here.
    # It used to raise `KeyError` for an absent member and let `json.loads` raise its own
    # `ValueError` (a `JSONDecodeError`, or a `UnicodeDecodeError` on bytes that are not UTF-8),
    # and only the restore call site translated those; `_verify_archive_blocking` caught neither,
    # so `messagefoundry restore-verify` on the identical forged archive -- the command the runbook
    # says to run FIRST -- raised a traceback where `restore` refused. Both callers already catch
    # `TarError` for this function's own cap refusals, so normalising here covers both at once.
    #
    # A manifest that reads back as something other than an object -- a directory wearing the
    # member's name (`extractfile` returns None), or valid JSON such as `[]` or `null` -- used to
    # fold to `{}`, which RESTORED with no manifest check at all while an absent manifest refused.
    # Those are the same state to an operator (no manifest to verify the store against), so they
    # refuse the same way.
    with tarfile.open(tar_path, "r:") as tar:
        try:
            info = tar.getmember(_MANIFEST_MEMBER)
        except KeyError as exc:
            raise tarfile.TarError(
                f"archive has no {_MANIFEST_MEMBER} member, so there is nothing to verify the store "
                "against"
            ) from exc
        if info.size > _MAX_MANIFEST_BYTES:
            raise tarfile.TarError(
                f"archive manifest exceeds the read cap ({_MAX_MANIFEST_BYTES} bytes)"
            )
        member = tar.extractfile(info)
        if member is None:
            raise tarfile.TarError(f"archive {_MANIFEST_MEMBER} member is not a regular file")
        data = member.read(_MAX_MANIFEST_BYTES + 1)
        if len(data) > _MAX_MANIFEST_BYTES:
            raise tarfile.TarError(
                f"archive manifest stream exceeds the read cap ({_MAX_MANIFEST_BYTES} bytes)"
            )
    # The helper covers both parse-side ValueErrors (not JSON, not UTF-8) and json's depth-limit
    # RecursionError, and returns a content-free hint so nothing chains the manifest (BACKLOG #2085).
    obj, refused = json_loads_or_refusal(data)
    if refused is not None:
        raise tarfile.TarError(f"archive {_MANIFEST_MEMBER} could not be parsed: {refused}")
    if not isinstance(obj, dict):
        raise tarfile.TarError(
            f"archive {_MANIFEST_MEMBER} is not a JSON object (got {type(obj).__name__})"
        )
    return obj


def _extract_member(
    tar_path: Path,
    name: str,
    dest_dir: Path,
    *,
    max_member_bytes: int = _MAX_RESTORE_MEMBER_BYTES,
    secure: bool = False,
) -> Path | None:
    """Extract a single archive member to ``dest_dir`` and return its path, or ``None`` when absent.

    ``secure`` hands the output file to the store's own best-effort ``_secure_file`` the moment it
    exists, BEFORE the first byte is streamed into it; what that leaves is not always owner-only on
    Windows (ADR 0163). The restore path passes it: its staging directory sits on the destination
    volume, and the file is the whole decrypted store. Securing it after the stream, the way
    :func:`_place_restored_store` secures the file it publishes, would leave a multi-GB write of PHI
    under the inherited ACL for as long as the write takes. The verify path passes it on each staging
    root it uses, ``.mefor-staging`` included (BACKLOG #1174).

    Path-traversal-safe by construction, NOT by an after-the-fact check: the member's *stored name* is
    never used as a filesystem path — we look the member up by name, then stream its CONTENT to a fixed
    output path (``dest_dir/extracted_store.db``). So a tampered tar whose member name is
    ``../../etc/passwd`` cannot escape ``dest_dir`` (the classic tar-extract CVE), because we never call
    ``tar.extract``/``extractall`` with the member's path. Keep it that way: if a future change extracts
    by the member's own name, add an explicit ``resolved.is_relative_to(dest_dir)`` guard first.

    ASVS 5.2.3 bound: the reader is pinned to the UNCOMPRESSED format (``"r:"``, never ``"r"`` — a
    compressed archive is refused rather than decompressed), the member's declared ``size`` is rejected
    *before* any streaming when it exceeds ``max_member_bytes``, and the bytes actually streamed are
    counted and enforced against the same cap — so neither a lying header nor a lying stream can exhaust
    the extract temp dir. An over-cap member raises :class:`tarfile.TarError` (surfaced by the caller as a
    restore-verify ``FAIL``)."""
    out = (dest_dir / "extracted_store.db").resolve()
    with tarfile.open(tar_path, "r:") as tar:
        try:
            member = tar.getmember(name)
        except KeyError:
            return None
        # A member of that name that is not a file is refused, not read as absent: absent, it sent
        # the config-only restore route and this one to each other (vault BACKLOG #5233), since
        # :func:`_tar_has_member` counts it as present. Nor is a link member followed, which would
        # read another member's bytes as this one's.
        if not member.isreg():
            raise tarfile.TarError(f"archive {name} member is not a regular file")
        if member.size > max_member_bytes:
            raise tarfile.TarError(
                f"archive member exceeds the restore extract cap ({max_member_bytes} bytes)"
            )
        src = tar.extractfile(member)
        if src is None:
            return None
        streamed = 0
        with open(out, "wb") as fh:
            # Reuse the store's own PHI-at-rest primitive, on the empty file, before any of the
            # member's bytes reach it.
            _secure_staged(out, secure)
            while True:
                buf = src.read(1024 * 1024)
                if not buf:
                    break
                streamed += len(buf)
                if streamed > max_member_bytes:
                    raise tarfile.TarError(
                        "archive member stream exceeds the restore extract cap "
                        f"({max_member_bytes} bytes)"
                    )
                fh.write(buf)
    return out


def _utc_stamp(now: float) -> str:
    """A filesystem-safe, lexically-sortable UTC timestamp for the archive filename (sort == chrono)."""
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(now))


def _utc_iso(now: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))


def _day_key(now: float) -> str:
    lt = time.localtime(now)
    return f"{lt.tm_year:04d}-{lt.tm_mon:02d}-{lt.tm_mday:02d}"


def _safe_segment(value: str) -> str:
    """Reduce a free-form instance name to a filename-safe segment (letters/digits/._-)."""
    return "".join(ch for ch in value if ch.isalnum() or ch in "._-")


# --- restore (the `messagefoundry restore` entry point) ----------------------
#
# The engine could WRITE a .mfbak archive and VERIFY one, and had no way to RESTORE one. A backup you
# cannot restore is not a backup, so the whole DR story rested on an operator hand-extracting the tar,
# which no shipped code or doc described. This section is that missing half; ADR 0048's cold-seed
# activation is the consumer (the DR box restores here, then activates onto the restored store).

#: A WAL-mode store is three files. Restoring `store.db` beside a leftover `store.db-wal` from a
#: DIFFERENT database would let SQLite replay that stale WAL over the restored pages, so the sidecars
#: are refused as destinations too, not just the main file.
_SIDECAR_SUFFIXES = ("-wal", "-shm")

#: ASVS 5.2.3 bounds on the restored CONFIG bundle, which the per-member cap alone cannot give: N
#: members each just under that cap would still fill the destination volume. A real config dir is a
#: handful of Python modules, a TOML and some codesets, so these are generous by orders of magnitude.
_MAX_CONFIG_BYTES = 1024 * 1024 * 1024  # 1 GiB across the whole bundle
_MAX_CONFIG_MEMBERS = 10_000

#: The one place the never-overwrite refusal is worded, so the operator who loses the create race reads
#: the same sentence as the one who was refused up front.
_OVERWRITE_REFUSAL = (
    "refusing to overwrite an existing path at {path} — restoring over a live store is unrecoverable; "
    "choose an empty --to path (or move the existing store aside first)"
)

#: The one place the RESTORE path words a codec-level archive failure, so the operator whose header will
#: not parse reads the same sentence as the one whose GCM tag failed. ``{reason}`` keeps the codec's own
#: scrubbed message rather than summarizing it: a failed AEAD tag cannot tell bad bytes from the wrong
#: key, and the codec is the only thing that says so.
#:
#: **Scope is restore only.** :func:`_verify_archive_blocking` words its own codec branch
#: (``decrypt failed: ...``), so ``restore-verify`` — the command an operator runs FIRST to triage —
#: does not carry the remediation sentence. Rendering both from here is the right end state, left to
#: whoever next edits the verify path.
_DECRYPT_REFUSAL = (
    "the archive did not verify: {reason}. Nothing was written to the destination. Confirm the .mfbak "
    "is intact (size and checksum against the source) and that the configured store key is the DEK the "
    "archive was sealed under"
)


def restored_accounts_notice(sessions_revoked: int) -> str:
    """The CLI summary's whole notice: what to re-apply (BACKLOG #5094), and what the restore
    already did. Worded from the count the restore's own revoke returned, so it never claims more
    than it ended."""
    return (
        f"{RESTORE_ROLLBACK_NOTICE} The restore ended {sessions_revoked} open session(s) in the "
        "store it placed, and the first engine start on this store ends every session again and "
        "records the restore."
    )


#: How far ahead of this host's clock an archive's date may be before it counts as undated: a
#: backup host whose clock leads by a little is ordinary, one a day ahead is not (BACKLOG #2614).
_ARCHIVE_CLOCK_SKEW_SECONDS = 3600.0


def _refuse_an_old_archive(
    *,
    archive_created_at: float | None,
    last_audit_at: float | None,
    max_age_seconds: float,
    now: float,
    config_only: bool = False,
) -> None:
    """Refuse an archive taken more than ``max_age_seconds`` before ``now``, or one that does not
    say when it was taken (BACKLOG #2614). A restore undoes every account change made after the
    archive, so the older it is the more an operator must re-apply, and the refusal names the
    time after which that is so. The caller words how to override it; the CLI's
    ``--allow-old-archive`` skips this check.

    ``config_only`` words the refusal for the config-only route (vault BACKLOG #5233), which places
    no store: there is no audit row to name and no account change to undo, and what an old bundle
    brings back is old config."""
    kind = "age"
    if archive_created_at is None:
        taken = "the archive does not say when it was taken"
        kind = "age_undated"
    elif archive_created_at > now + _ARCHIVE_CLOCK_SKEW_SECONDS:
        # A date in the future says the backup host's clock was wrong, so the age is not known.
        taken = (
            f"the archive says it was taken {utc_or_unknown(archive_created_at)}, after now, so "
            "its age is not known"
        )
        kind = "age_undated"
    else:
        age = now - archive_created_at
        if age <= max_age_seconds:
            return
        taken = (
            f"the archive was taken {utc_or_unknown(archive_created_at)}, "
            f"{age / 86400:.1f} days ago, past the {max_age_seconds / 86400:g}-day limit"
        )
    if config_only:
        raise BackupError(
            kind,
            f"Nothing was written: {taken}. Its config bundle brings back the connection settings, "
            "router and handler code and any secrets the config dir held when the archive was "
            "taken, so a config change made after that must be re-applied by hand.",
        )
    # Short, and pointing at the notice rather than carrying it (BACKLOG #5094): the refusal's
    # point is that nothing was written. The CLI adds how to override it.
    raise BackupError(
        kind,
        f"Nothing was written: {taken}. Its newest audit row is {utc_or_unknown(last_audit_at)}. "
        "A restore undoes what was changed after the archive was taken, and that must be "
        f"re-applied by hand. {RESTORE_NOTICE_POINTER}",
    )


def _codec_refusal(exc: BackupCodecError) -> BackupError:
    """Translate a ``.mfbak`` codec failure into the restore path's refusal — the single seam, so both
    the header read and the decrypt word it once and order the arms once.

    ``BackupKeyMismatch`` is a SUBCLASS of :class:`BackupCodecError`, so it must be separated here or it
    reads as a generic bad archive. :func:`_verify_archive_blocking` keeps that distinction in its own
    ordered arms and the two paths must not disagree about it. It is reachable despite the fingerprint
    precheck: ``archive_key_id`` reads the header, ``decrypt_stream`` re-reads it, and an archive
    replaced between those two reads authenticates against a key the precheck already approved. Telling
    that operator "the archive did not verify" would point at the bytes when the key is the subject."""
    if isinstance(exc, BackupKeyMismatch):
        return BackupError("verify", f"KEY_MISMATCH: {safe_exc(exc)}")
    return BackupError("verify", _DECRYPT_REFUSAL.format(reason=safe_exc(exc)))


async def run_restore(
    archive_path: str,
    *,
    dest_store_path: str | Path | None,
    store_settings: object,
    config_dest: str | Path | None = None,
    max_age_seconds: float | None = None,
) -> RestoreResult:
    """Restore a ``.mfbak`` archive's store member to ``dest_store_path`` (ADR 0049's missing half; the
    primitive ADR 0048's cold seed consumes).

    ``max_age_seconds`` refuses an archive taken longer ago than that, or one whose manifest does
    not say when, before anything is written (BACKLOG #2614). ``None`` checks no age: the
    ``restore`` CLI passes its limit unless the operator gave ``--allow-old-archive``.

    Resolves the store's decrypt-capable keyring exactly as :func:`run_restore_verify` does (active +
    retired, AC-5 "incl. retired keys"), then decrypts the archive ONCE and verifies the extracted
    ``store.db`` — ``integrity_check`` plus the manifest row-count compare, the same checks
    :func:`run_restore_verify` runs — before handing those exact bytes to the destination. All heavy work
    runs off the event loop.

    **It never overwrites** an existing destination (see :func:`_refuse_existing_destination`).

    ``config_dest`` additionally restores the archive's ``config/`` bundle into that directory. It is a
    **refusal**, not a no-op, when the archive carries no config member: an operator who asked for the
    config back and silently got an empty directory would believe the config was restored. The bundle is
    written AFTER the store, so a member aimed at the store's own path would overwrite it: that is
    refused before the store is extracted (see :func:`_refuse_colliding_config_members`), as is a
    ``config_dest`` sitting under ``dest_store_path`` (:func:`_refuse_config_dest_under_the_store`).

    ``dest_store_path=None`` with a ``config_dest`` restores ONLY the config bundle of a CONFIG-ONLY
    archive, which carries no store (vault BACKLOG #5233); an archive that carries one is refused
    there. See :func:`_restore_blocking`.

    **There is deliberately no ``allow_unencrypted`` here**, unlike :func:`run_restore_verify`. The
    downgrade guard stays at its strictest on the one path that writes bytes to disk. It carried such a
    parameter and nothing ever set it: the CLI documented in a comment that it withheld it on purpose,
    so the refusal's own remedy (*"set [backup].allow_unencrypted"*) named a setting this path does not
    read — a prescription an operator would have followed to no effect. The parameter is gone and the
    refusal now says the true thing: a plaintext archive restores only on a box with no store key."""
    keys = [
        _decode_store_key(k)
        for k in resolve_decrypt_keys(store_settings)  # type: ignore[arg-type]
    ]
    return await asyncio.to_thread(
        _restore_blocking,
        archive_path=archive_path,
        dest_store_path=Path(dest_store_path) if dest_store_path is not None else None,
        config_dest=Path(config_dest) if config_dest is not None else None,
        keys=keys,
        max_age_seconds=max_age_seconds,
    )


def _restore_blocking(
    *,
    archive_path: str,
    dest_store_path: Path | None,
    config_dest: Path | None,
    keys: list[bytes],
    max_age_seconds: float | None,
) -> RestoreResult:
    """The off-loop half of :func:`run_restore`: refuse -> decrypt -> extract -> verify -> place. Raises
    :class:`BackupError` with the failing ``kind`` (``archive``/``destination``/``verify``/``restore``,
    ``age`` for an archive past ``max_age_seconds`` and ``age_undated`` for one whose age is not
    known (BACKLOG #2614), and ``cleanup`` for the one
    failure that follows a whole restore -- see below).

    It runs the verify's checks itself rather than calling :func:`_verify_archive_blocking` first, for
    two reasons. A .mfbak archive is the size of the store, so a verify pass followed by a restore pass
    would decrypt and extract every byte TWICE on the one path where an operator is already waiting. And
    the verify owns its own temp dir, so the file it checked is deleted and a second, unchecked
    extraction is what would reach the destination — here the bytes checked are the bytes placed.

    **Nothing this function publishes survives its own failure.** Everything it writes to the
    destination is removed on any exception after the store is placed, so a failed restore leaves the
    destination as it found it and the operator can simply run the command again — rather than meeting
    the never-overwrite refusal on the retry and having to delete a PHI-bearing file by hand. The
    cleanup runs AFTER the staging directory is gone and removes only the paths this restore recorded
    writing (:func:`_discard_partial_restore`), so it cannot reach the staging directory or anything
    else that shares the destination's parent.

    **A restore that is whole is never rolled back, whatever happens after it.** The one thing that
    runs after the config bundle lands is the staging directory's own removal, and it can fail: on
    Windows an antivirus scanner or the indexer holding the just-written store open makes that
    ``rmtree`` raise ``PermissionError``. That is a leftover to report, not a restore to undo --
    undoing it would delete a placed, verified store to answer a directory that could not be
    deleted, and leave the operator with no store, no bundle, and the plaintext staging directory
    still on disk. It raises ``BackupError("cleanup", ...)`` naming the directory instead, with the
    store and bundle intact.

    **``dest_store_path`` is ``None`` only for a CONFIG-ONLY archive's bundle (vault BACKLOG #5233).**
    A server-DB store's archive carries no store, so ``--to`` has nothing to name, and the refusal that
    meets ``--to`` on such an archive used to offer ``--config-to``, an option of this same command that
    reached the same refusal first. With ``config_dest`` alone, the archive is decrypted under the
    same key, downgrade and size checks, its manifest is read, the age refusal applies, and then only
    its config bundle is extracted, under every check :func:`_extract_config_members` applies. An
    archive that carries a store is refused on this route, at its first tar member where the store
    leads it (:class:`_StoreMemberGuard`), and after the decrypt in any case, by the store member
    itself: its store is the restore. One whose manifest does not mark it config-only is refused
    there too. One whose manifest marks it config-only while it carries a store is refused as
    malformed on both routes once the manifest is read. Where its store leads the tar, the guard
    on the config-only route refuses it before the manifest is read and sends the operator to
    ``--to``, which then refuses it as malformed, so the two routes end in that refusal rather
    than sending the operator back and forth."""
    import sqlite3

    from messagefoundry.store.store import (
        _secure_file,
        forget_store_salt,
        newest_audit_time,
        write_restore_marker,
    )

    # Where the staging directory goes: beside the store, or on the config-only route beside the
    # bundle's directory, for the same reason (the decrypted archive stays on the destination volume).
    anchor = dest_store_path if dest_store_path is not None else config_dest
    if anchor is None:
        raise BackupError("destination", RESTORE_NEEDS_A_DESTINATION)
    if not Path(archive_path).is_file():
        raise BackupError("archive", f"no archive at {archive_path}")
    _refuse_existing_destination(dest_store_path, config_dest)

    # Key precheck BEFORE any decrypt, and the same ASVS 5.2.3 downgrade guard the verify applies: with a
    # store key configured, a PLAINTEXT archive is a downgrade signal (an attacker swapping the
    # AEAD-sealed archive for an unauthenticated one), not an archive to restore.
    encrypted = _looks_encrypted(archive_path)
    key_id: str | None = None
    match_key: bytes | None = None
    if encrypted:
        # The header read is already a codec operation: a .mfbak whose magic survived but whose version
        # or JSON header did not fails HERE, one step before the decrypt, and must refuse the same way.
        try:
            key_id = archive_key_id(archive_path)
        except BackupCodecError as exc:
            raise _codec_refusal(exc) from exc
        if not keys:
            raise BackupError(
                "verify", "archive is encrypted but no store key is configured to decrypt it"
            )
        match_key = _select_decrypt_key(keys, key_id)
        if match_key is None:
            raise BackupError(
                "verify",
                f"KEY_MISMATCH: no resolved key (active or retired) matches archive key_id={key_id}",
            )
    elif keys:
        raise BackupError(
            "verify",
            "KEY_MISMATCH: the archive is plaintext but a store key is configured; refusing to restore "
            "a plaintext archive (possible downgrade). This path has no opt-out: a plaintext archive "
            "restores only on a box with no store key configured.",
        )

    # The config-only route stages in the RESOLVED parent: an unresolved `.` (or `""`) is its own
    # parent, which would stage the decrypted archive inside the bundle's own directory.
    staging_parent = anchor.parent if dest_store_path is not None else anchor.resolve().parent
    if dest_store_path is None and staging_parent == anchor.resolve():
        raise BackupError(
            "destination",
            f"--config-to {anchor} is a filesystem root, so there is no directory beside it to stage "
            "the decrypted archive in; choose a directory below it",
        )
    # The directories this call creates, for its staging and for the bundle, read before the first
    # mkdir, so a restore that does not complete removes them again: a refusal that says nothing was
    # written must not leave a new --config-to, or a new ancestor of it or of --to, behind (vault
    # BACKLOG #5233). A directory that was already there is never in this list.
    made_dirs = _missing_dirs(staging_parent, config_dest)
    # The rollback's three facts, kept outside the staging block so the `finally` can read them after
    # it: whether the store was published (before that, every refusal already leaves nothing behind),
    # which config paths this restore created, and whether the restore itself completed. `finally`
    # rather than `except` for the rollback: nothing is caught on its account, so no failure mode is
    # missed -- a cancelled or interrupted restore rolls back too.
    #
    # `completed` flips on the LAST LINE INSIDE the staging block, not after the block closes, and
    # the difference is the regression this ordering exists to prevent. What runs between the two is
    # the staging directory's own teardown, and `TemporaryDirectory` raises when that fails. A flag
    # set after the block read the failed teardown as a failed restore and rolled back a store that
    # was placed, verified and published -- the one outcome worse than the leftover it was reporting.
    # So the teardown failure is its own arm below: reported, never rolled back.
    published = False
    completed = False
    config_written: list[Path] = []
    staging: Path | None = None
    try:
        # Inside the `try`, so a parent that cannot be made meets the `staging is None` refusal
        # below, and the `finally` removes what the mkdir made before it failed.
        staging_parent.mkdir(parents=True, exist_ok=True)
        # Stage on the DESTINATION volume, not the system temp dir: the extracted store is then placed
        # by a hard link rather than a second multi-GB copy, and the decrypted PHI never lands on a
        # shared temp volume that may be less protected than the store's own.
        #
        # "Less protected than the store's own" is a claim about the VOLUME, and it does not carry to
        # the files. `TemporaryDirectory` restricts the directory on POSIX, and on Windows under Python
        # 3.13+ writes its own protected DACL (SYSTEM, Administrators, OWNER RIGHTS -- measured on
        # 3.14.6) rather than inheriting the parent's. The files staged inside it are the whole
        # decrypted archive and, on the store route, the whole extracted store. Both can be full-body
        # PHI at rest (docs/PHI.md section 3), the archive on the config-only route too when a
        # store-carrying archive is decrypted whole before it is refused, and an archive can also
        # carry a config bundle that holds secrets. So each is handed to the store's own `_secure_file` the
        # moment it exists and before its first byte is written. Best-effort and non-fatal, per that
        # primitive's contract.
        # The file `_place_restored_store` PUBLISHES gets the store-trio rule instead (ADR 0183 Wave 0b).
        # archive.tar and extracted_store.db keep what `_secure_file` leaves, which is NOT owner-only when
        # a file carries the temp directory's entries explicitly (it removes inherited entries only;
        # measured on the hosted runners, CI run 36039014999). A hard-linked placement then shares the
        # published DACL. A follow-up recorded in ADR 0163.
        with tempfile.TemporaryDirectory(prefix="mefor-restore-", dir=staging_parent) as tmp:
            staging = Path(tmp)
            tar_path = staging / "archive.tar"
            with open(archive_path, "rb") as raw_src, open(tar_path, "wb") as tar_fh:
                src = _HashingReader(raw_src)
                _secure_file(tar_path)
                # On the config-only route a store-carrying archive is refused at its first tar
                # member, not after the whole store is decrypted beside --config-to only to be
                # refused after it; the checks after the decrypt stay the authority (vault BACKLOG
                # #5233).
                guard = _StoreMemberGuard(tar_fh) if dest_store_path is None else None
                dst: BinaryIO = cast(BinaryIO, guard) if guard is not None else tar_fh
                if match_key is not None:
                    # A failed GCM tag is the point of the AEAD framing, so it is an ORDINARY outcome
                    # here, not a bug: refuse the way the destination check does rather than escape as
                    # a codec exception. Narrowed to the codec's own type so an OSError stays an
                    # OSError.
                    #
                    # Capped for the same ASVS 5.2.3 reason as the verify path's call: this decrypt is
                    # the first thing to write into the staging dir, so an oversized archive is refused
                    # before `_extract_member`'s per-member cap is ever reached. The staging dir is on
                    # the DESTINATION volume here, which makes the bound matter more than it does on
                    # verify -- an unbounded decrypt would fill the very volume the restored store is
                    # about to land on. POST-AUTHENTICATION, like the verify site: see
                    # _MAX_RESTORE_PLAINTEXT_BYTES.
                    try:
                        decrypt_stream(
                            cast(BinaryIO, src),
                            dst,
                            match_key,
                            max_plaintext_bytes=_MAX_RESTORE_PLAINTEXT_BYTES,
                        )
                    except BackupCodecError as exc:
                        raise _codec_refusal(exc) from exc
                else:
                    # The plaintext (no-key box) branch carries the SAME bound, and did not: it was a
                    # bare `copyfileobj` while `_MAX_RESTORE_PLAINTEXT_BYTES` said of itself that it
                    # "moves the bound to the first write". It is the branch that needs the bound most,
                    # because it has no AEAD tag to fail on first -- a forged archive is simply copied.
                    # Counting the streamed bytes IS the enforcement (a file's size on disk is not a
                    # bound an attacker who supplies the file is subject to), so this cannot become
                    # `copyfileobj`.
                    streamed = 0
                    while True:
                        buf = src.read(1024 * 1024)
                        if not buf:
                            break
                        streamed += len(buf)
                        if streamed > _MAX_RESTORE_PLAINTEXT_BYTES:
                            raise BackupError(
                                "verify",
                                "the plaintext archive exceeds the restore staging cap "
                                f"({_MAX_RESTORE_PLAINTEXT_BYTES} bytes); refusing to fill the "
                                "destination volume",
                            )
                        dst.write(buf)
                if guard is not None:
                    guard.finish()

            # `_read_manifest_from_tar` reports every way the manifest can be unusable -- absent, a
            # directory, over the cap, not UTF-8, not JSON, not an object -- as `tarfile.TarError`
            # (see its comment), so one arm covers the set here and the verify path's existing
            # `TarError` arm covers it there. Unguarded, a forged archive left this path as a CLI
            # traceback from the last-resort excepthook instead of the refusal every other archive
            # fault here gets; translating at this site alone left `restore-verify` with the
            # traceback.
            try:
                manifest = _read_manifest_from_tar(tar_path)
            except (tarfile.TarError, OSError) as exc:
                raise BackupError(
                    "restore", f"archive manifest could not be read: {safe_exc(exc)}"
                ) from exc
            config_only = bool(manifest.get("config_only"))
            # The members themselves, then the manifest's word, on BOTH routes and by one check. A
            # manifest that says config-only over an archive that carries a store is malformed:
            # each route used to send the operator to the other, `--to` trusting the manifest and
            # `--config-to` the member (vault BACKLOG #5233). Neither restores it, store dropped or
            # bundle dropped. On the config-only route `_StoreMemberGuard` can still meet a store
            # that leads the tar before the manifest is read; it sends the operator to `--to`,
            # which then refuses here.
            # Read only where the answer is used: a store route that is not config-only finds a
            # missing or non-file store member in `_extract_member` anyway.
            carries_store = (config_only or dest_store_path is None) and _tar_has_member(
                tar_path, _STORE_MEMBER
            )
            if config_only and carries_store:
                raise BackupError("restore", _CONTRADICTORY_ARCHIVE_REFUSAL)
            if dest_store_path is None:
                if carries_store:
                    raise BackupError("destination", _CARRIES_A_STORE_REFUSAL)
                if not config_only:
                    # No store, and no word that there should be none: neither route restores it,
                    # so the refusal does not send the operator to --to.
                    raise BackupError(
                        "restore",
                        "the archive's manifest does not mark it CONFIG-ONLY, yet it carries no "
                        f"{_STORE_MEMBER}; refusing to restore it on either route",
                    )
                # The age refusal binds here too: an old bundle brings back old credentials and old
                # router and handler code, and --max-age-days / --allow-old-archive say what they
                # say on every route (BACKLOG #2614).
                archive_created_at = _manifest_time(manifest)
                if max_age_seconds is not None:
                    _refuse_an_old_archive(
                        archive_created_at=archive_created_at,
                        last_audit_at=None,
                        max_age_seconds=max_age_seconds,
                        now=time.time(),
                        config_only=True,
                    )
                # `published` before the first write, as the store route sets it once the store is
                # placed: from here a failure leaves files this restore made, and the `finally`
                # removes exactly the ones `config_written` records.
                published = True
                config_files = _restore_config_members(tar_path, anchor, written=config_written)
                result = RestoreResult(
                    archive_path=archive_path,
                    store_path=None,
                    store_bytes=0,
                    row_counts={},
                    encrypted=encrypted,
                    key_id=key_id,
                    config_dir=str(anchor),
                    config_files=config_files,
                    archive_sha256=src.digest.hexdigest(),
                    archive_created_at=archive_created_at,
                )
                # The restore is whole from here, as on the store route below.
                completed = True
                return result
            if config_only:
                raise BackupError(
                    "restore",
                    "this is a CONFIG-ONLY archive (a server-DB store's backup is DBA-delegated, "
                    "BACKLOG #52) — it carries no store to restore; restore the database from the "
                    "DBA's own backup, and restore the config bundle with this command's "
                    "--config-to <dir> and no --to",
                )
            # Before the store is extracted, let alone published: a config member aimed at the store's
            # own path is a destination refusal, and finding it here costs neither the extract nor a
            # restore that half-finished (BACKLOG #1717).
            if config_dest is not None:
                _refuse_colliding_config_members(tar_path, dest_store_path, config_dest)

            try:
                # The BOUNDED extractor: its declared-size and streamed-byte caps are what keep a
                # forged archive from exhausting the staging dir (ASVS 5.2.3). `secure` locks the
                # extracted store to its owner before the first byte lands (see the block comment
                # above the staging directory).
                snap = _extract_member(tar_path, _STORE_MEMBER, Path(tmp), secure=True)
            except tarfile.TarError as exc:
                raise BackupError("restore", safe_exc(exc)) from exc
            if snap is None:
                raise BackupError("restore", f"archive has no {_STORE_MEMBER} member to restore")

            row_counts = _verify_extracted_store(snap, manifest)
            # BACKLOG #2614: when the archive was taken, and its newest audit row, read from the
            # checked bytes. Both feed the age refusal, the restore marker and the summary.
            archive_created_at = _manifest_time(manifest)
            try:
                last_audit_at = newest_audit_time(snap)
            except sqlite3.Error as exc:
                raise BackupError("restore", safe_exc(exc)) from exc
            if max_age_seconds is not None:
                _refuse_an_old_archive(
                    archive_created_at=archive_created_at,
                    last_audit_at=last_audit_at,
                    max_age_seconds=max_age_seconds,
                    now=time.time(),
                )
            # ADR 0196 (C+): the restored store must not seal a single value under the archive's data
            # sub-key. That key's persisted count is the archive's, which may trail the key's real use
            # -- the primary kept sealing after the backup, and the ADR 0048 cold seed can run beside
            # it. Dropping the salt here, after the checks and before the store is placed, makes its
            # first open mint a new salt and so a new key. Old values name their own salt and still
            # open with the DEK alone, and nothing about the key the DR site must hold changes.
            try:
                dropped = forget_store_salt(snap)
            except sqlite3.Error as exc:
                raise BackupError("restore", safe_exc(exc)) from exc
            if dropped and "store_salt" in row_counts:
                # The counts were taken to check the archive; the summary reports the placed store.
                row_counts = {**row_counts, "store_salt": 0}
            # BACKLOG #2614: the archive's accounts, password hashes, roles, factors and sessions
            # come back as they were. Mark the store so its first engine start ends every session
            # and records the restore (`MessageStore.consume_restore_record`). Written after the
            # checks, like the salt drop, so the bytes checked are the archive's; the marker is
            # this restore's own row.
            archive_sha256 = src.digest.hexdigest()
            try:
                sessions_revoked = write_restore_marker(
                    snap,
                    archive_sha256=archive_sha256,
                    archive_created_at=archive_created_at,
                    last_audit_at=last_audit_at,
                    restored_at=time.time(),
                )
            except sqlite3.Error as exc:
                raise BackupError("restore", safe_exc(exc)) from exc
            row_counts = {**row_counts, "restore_marker": 1}
            # The exclusive create sits OUTSIDE the rollback on purpose: a lost create race raises
            # FileExistsError, and the file then at the destination belongs to the winner -- deleting
            # it would turn a refusal into the unrecoverable overwrite the refusal exists to prevent.
            # `published` flips only once the store at `dest_store_path` is one THIS call made.
            try:
                store_bytes = _place_restored_store(snap, dest_store_path)
            except FileExistsError as exc:
                raise BackupError(
                    "destination", _OVERWRITE_REFUSAL.format(path=dest_store_path)
                ) from exc
            except OSError as exc:
                raise BackupError("destination", safe_exc(exc)) from exc
            published = True

            # The config bundle is written AFTER the store, and every way it can fail used to leave
            # the store published anyway: a refused member name, a cap, a collision, an archive with
            # no config member at all. The operator then had a reported failure, a PHI-bearing store
            # at the destination, and a retry blocked by the never-overwrite refusal -- with a manual
            # delete the only way forward. `_place_restored_store` already guards its own half this
            # way; the `finally` below is the missing sibling, and `config_written` is what it reads.
            config_files = 0
            if config_dest is not None:
                config_files = _restore_config_members(
                    tar_path, config_dest, written=config_written
                )
            # The restore is whole from here. Nothing after this line may roll it back.
            completed = True
    except OSError as exc:
        if staging is None:
            # The staging directory itself could not be made (an unwritable parent, say), so
            # nothing was decrypted or written: a refusal line, not a traceback.
            raise BackupError("destination", _staging_refusal(staging_parent, anchor, exc)) from exc
        if not completed:
            # A refusal already leaving the block, found anywhere in the chain: an OSError raised
            # on its way out (the staging teardown, whose rmtree retry chains its own first
            # failure, or a close-time flush) would otherwise replace it with a traceback.
            refusal = _refusal_in_flight(exc)
            if refusal is None:
                # No refusal behind it: the OSError is the failure itself, such as a full volume
                # mid-decrypt. A refusal line rather than a traceback, on both routes; the
                # `finally` still rolls back what was published.
                raise BackupError("restore", f"the restore failed: {safe_exc(exc)}") from exc
            if not staging.exists():
                raise refusal from exc
            # The teardown failed, and the directory holds decrypted archive content.
            raise BackupError(
                refusal.kind,
                f"{str(refusal).rstrip('.')}. Separately, the restore's own staging directory "
                f"{staging}, beside the destination, could not be removed ({safe_exc(exc)}) and "
                "still holds decrypted archive content: delete it by hand once nothing holds it "
                "open",
            ) from refusal
        # Only the staging directory's teardown runs after `completed`, so an OSError here IS that
        # teardown failing (on Windows, a scanner or the indexer still holding the extracted store
        # open). The store and bundle are intact; what is left is the plaintext staging directory,
        # which its own remover just failed to delete. A BackupError, so the CLI prints a refusal
        # line rather than a traceback, and a kind of its own, so the line does not read as the
        # restore having failed. The `finally` below sees `completed` and leaves the restore alone.
        intact: list[str] = []
        if dest_store_path is not None:
            intact.append(f"the restored store at {dest_store_path}")
        if config_dest is not None:
            intact.append(f"the config bundle at {config_dest}")
        held = "archive and store" if dest_store_path is not None else "archive"
        raise BackupError(
            "cleanup",
            f"the restore completed, but its staging directory {staging} could not be removed: "
            f"{safe_exc(exc)}. Intact: {', and '.join(intact)}. The staging "
            f"directory still holds the decrypted {held}: delete it by hand once nothing "
            "holds it open. Do not re-run the restore; the destination is now in use.",
        ) from exc
    finally:
        if published and not completed:
            _discard_partial_restore(dest_store_path, config_written)
        if not completed:
            # After the staging directory's own teardown and the rollback, so each is empty again.
            _remove_made_dirs(made_dirs)

    return RestoreResult(
        archive_path=archive_path,
        store_path=str(dest_store_path) if dest_store_path is not None else None,
        store_bytes=store_bytes,
        row_counts=row_counts,
        encrypted=encrypted,
        key_id=key_id,
        config_dir=str(config_dest) if config_dest is not None else None,
        config_files=config_files,
        archive_sha256=archive_sha256,
        archive_created_at=archive_created_at,
        last_audit_at=last_audit_at,
        sessions_revoked=sessions_revoked,
    )


def _staging_refusal(parent: Path, anchor: Path, exc: OSError) -> str:
    """The refusal for a restore that could not make ``parent``, or its staging directory in it."""
    return (
        f"could not create {parent}, or the restore's staging directory in it ({safe_exc(exc)}). "
        f"The restore stages the decrypted archive there, beside {anchor}, so that directory must "
        "exist or be creatable, and be writable. Nothing was decrypted"
    )


def _refusal_in_flight(exc: BaseException) -> BackupError | None:
    """The first :class:`BackupError` in ``exc``'s ``__context__`` chain, or ``None``."""
    seen: set[int] = set()
    link = exc.__context__
    while link is not None and id(link) not in seen:
        if isinstance(link, BackupError):
            return link
        seen.add(id(link))
        link = link.__context__
    return None


def _missing_dirs(*paths: Path | None) -> list[Path]:
    """Each of ``paths`` that is not ``None``, and each of their ancestors, that does not exist yet,
    resolved and deepest first: what a ``mkdir(parents=True)`` of each is about to create."""
    missing: set[Path] = set()
    for path in paths:
        if path is None:
            continue
        probe = path.resolve()
        while probe != probe.parent and not probe.exists():
            missing.add(probe)
            probe = probe.parent
    return sorted(missing, key=lambda p: len(p.parts), reverse=True)


def _remove_made_dirs(dirs: list[Path]) -> None:
    """Remove the directories :func:`_missing_dirs` recorded, deepest first, each only while it is
    empty. Best-effort, like :func:`_discard_partial_restore`, because it runs while a failure is
    already propagating. A directory that holds something stays, and so do its ancestors, because
    ``rmdir`` refuses each of them in turn."""
    for path in dirs:
        # A path the mkdir never got to (an ancestor is a regular file, say) is not a directory,
        # and there is nothing of this restore's to remove or to report there.
        if not path.is_dir():
            continue
        try:
            path.rmdir()
        except FileNotFoundError:
            continue
        except OSError as exc:
            log.warning("left the directory %s this restore created: %s", path, safe_exc(exc))


class _StoreMemberGuard:
    """Writes the decrypted tar through to ``raw``, and refuses before any of it lands when its first
    member is the store (vault BACKLOG #5233). Used only on the config-only route, where a
    store-carrying archive is refused anyway: the backup writes the store first, so this catches it
    at the first frames instead of after a multi-GB decrypt. The member scan after the decrypt stays
    the authority, for an archive that puts its store anywhere else.

    It HOLDS every write until :data:`_GUARD_HEAD_BYTES` have arrived (or :meth:`finish` is called
    at the end of a shorter stream), then reads the first member from them with :mod:`tarfile`, not
    from the first 512-byte block, because ``tar.add`` can open with a PAX extended header that
    carries the member's real name (measured on Windows). Holding is what makes "before any of it
    lands" true whatever frame size the archive was sealed with. A head that does not parse is left
    to the checks after the decrypt.

    It offers :meth:`write` and :meth:`finish` and nothing else, so any other file method raises
    ``AttributeError``. It once forwarded the rest to the raw file, which would answer without the
    held bytes: ``writelines`` would land bytes past the check, and ``tell`` would report a position
    short of what was written. Nothing called them: the decrypt and the plaintext copy only write."""

    def __init__(self, raw: BinaryIO) -> None:
        self._raw = raw
        self._held: list[bytes] = []
        self._held_bytes = 0
        self._released = False

    def write(self, data: bytes) -> int:
        if self._released:
            return self._raw.write(data)
        self._held.append(bytes(data))
        self._held_bytes += len(data)
        if self._held_bytes >= _GUARD_HEAD_BYTES:
            self._release()
        return len(data)

    def finish(self) -> None:
        """Check and write what is still held: the end of a stream shorter than the head."""
        if not self._released:
            self._release()

    def _release(self) -> None:
        self._released = True
        head = b"".join(self._held)
        self._held = []
        if _first_member_name(head) == _STORE_MEMBER:
            raise BackupError("destination", _CARRIES_A_STORE_REFUSAL)
        self._raw.write(head)


def _first_member_name(head: bytes) -> str | None:
    """The name of the first member of the tar that ``head`` opens, or ``None`` if it does not parse."""
    try:
        with tarfile.open(fileobj=io.BytesIO(head), mode="r:") as tar:
            first = tar.next()
    except (tarfile.TarError, OSError, ValueError) as exc:
        # The type alone, never the message: these bytes are decrypted archive content, and a
        # parse error's message is not known never to quote them.
        log.debug(
            "the config-only restore could not read the decrypted tar's first member (%s); the "
            "checks after the decrypt decide whether it carries a store",
            type(exc).__name__,
        )
        return None
    return None if first is None else first.name


def _tar_has_member(tar_path: Path, name: str) -> bool:
    """Does the tar at ``tar_path`` carry a member of exactly ``name``, of any type? Looked up the
    way :func:`_extract_member` looks the store up, which refuses a member of that name that is not
    a regular file rather than read it as absent, so the two cannot disagree (vault BACKLOG
    #5233)."""
    try:
        with tarfile.open(tar_path, "r:") as tar:
            tar.getmember(name)
    except KeyError:
        return False
    except (tarfile.TarError, OSError) as exc:
        raise BackupError("restore", safe_exc(exc)) from exc
    return True


#: How much of the decrypted tar :class:`_StoreMemberGuard` reads its first member from: room for a
#: PAX extended header and the header after it, many times over.
_GUARD_HEAD_BYTES = 64 * 1024


#: A restore given neither destination (vault BACKLOG #5233). The CLI checks it before it loads
#: any settings; this primitive refuses it for every other caller.
RESTORE_NEEDS_A_DESTINATION = (
    "a restore needs --to <new store path>, or --config-to <dir> alone for a CONFIG-ONLY "
    "archive's config bundle"
)

#: The config-only route's refusal of an archive that carries a store (vault BACKLOG #5233).
_CARRIES_A_STORE_REFUSAL = (
    "this archive carries a store, so restoring it needs --to <new store path>; --config-to "
    "alone restores only a CONFIG-ONLY archive's config bundle"
)

#: Both routes' refusal of an archive whose manifest marks it config-only over a store member
#: (vault BACKLOG #5233). It names no other route, because each route would send it to the other.
_CONTRADICTORY_ARCHIVE_REFUSAL = (
    f"the archive is malformed: its manifest marks it CONFIG-ONLY, yet it carries a {_STORE_MEMBER} "
    "member; refusing to restore it on either route"
)


def _discard_partial_restore(dest_store_path: Path | None, written: list[Path]) -> None:
    """Remove what a failed :func:`_restore_blocking` published -- the store it placed, then every
    config member and directory it recorded creating, newest first -- so the destination is left as the
    restore found it and the retry is the same command again.

    Only the recorded paths are in scope, and that scope is the whole of the safety argument. An
    earlier draft emptied ``config_dest`` instead, on the reasoning that
    :func:`_refuse_existing_destination` had proved it empty or absent. But that check runs BEFORE the
    staging directory exists, and in the one-directory form (``--to D/store.db --config-to D``, which
    :func:`_refuse_colliding_config_members` defends by name) the staging directory sits INSIDE
    ``config_dest`` -- so "everything in here is ours" deleted the live staging directory out from under
    the restore that was still using it. A ledger of what was written has no such gap: it needs no
    precondition about the directory's contents, and a path nobody recorded is a path nobody deletes.

    The store is unlinked, never overwritten-and-truncated: :func:`_place_restored_store` creates it
    exclusively, so a file at that path when this runs is one the failed restore made. ``config_dest``
    itself is never in the ledger (see :func:`_extract_config_members`). A directory this restore
    created is removed only while empty; one that gained a stranger's file since is kept and logged.

    Best-effort by construction. It runs while an exception is already propagating, so a cleanup error
    must never replace the failure the operator needs to read -- it is logged and swallowed. A restore
    that could not clean up is a worse report, not a different outcome.

    ``dest_store_path`` is ``None`` on the config-only route, which places no store (vault BACKLOG
    #5233), so only the recorded config paths are removed."""
    if dest_store_path is not None:
        try:
            dest_store_path.unlink(missing_ok=True)
        except OSError as exc:
            log.warning(
                "could not remove the partially restored store at %s: %s", dest_store_path, exc
            )
    for path in reversed(written):
        try:
            if path.is_dir() and not path.is_symlink():
                path.rmdir()  # a directory this restore created, and only while it is empty
            else:
                path.unlink(missing_ok=True)
        except OSError as exc:
            log.warning("could not remove the partially restored config member %s: %s", path, exc)


def _compare_row_counts(
    manifest: dict[str, object], row_counts: dict[str, int]
) -> tuple[dict[str, int], str | None]:
    """The manifest's recorded counts, and the reason the snapshot's ``row_counts`` fail the compare
    against them (``None`` when they agree). The one compare both :func:`_verify_in_staging` (the
    archive verify) and :func:`_verify_extracted_store` (restore's pre-place check) run.

    Keyed off the MANIFEST's own tables, not dict equality (BACKLOG #1722 follow-up).
    :func:`_count_tables` derives its table set from the file it is given, so ``row_counts`` reflects
    the snapshot's own schema, which can legitimately be a superset of what an OLDER manifest
    recorded: one written before this table set was widened (or before a later table existed) has
    fewer keys than the archive really has tables. Verifying or restoring an archive taken by an
    earlier build is ordinary (AC-5), so dict equality would refuse every such archive on sight. A
    table the manifest tracked that the snapshot's schema lacks reads as 0, so a manifest count of 0
    for it still agrees and a nonzero one is real data loss. A table the snapshot has that the
    manifest never tracked is not compared at all.

    Because the compare walks the manifest's tables, it reads nothing when the manifest records none
    (``row_counts`` empty or missing), and nothing of the snapshot when the two share no table, the
    case of a snapshot whose schema holds no table at all: every manifest count then reads as 0. A PASS there would certify counts nobody compared, the shape BACKLOG #2186 produced
    when the backup and the verify both counted an empty stand-in, so at least those refuse (BACKLOG
    #5056). A full archive never legitimately has either: its manifest lists every table of its
    store, and even the oldest, four-table manifest names ``messages``. A config-only archive carries
    no snapshot and returns before this compare. A ``row_counts`` that is not a mapping, or a count
    that is not a non-negative integer, refuses too, rather than being coerced (``3.9`` read as
    ``3``) or raising out of the verify."""
    raw_counts = manifest.get("row_counts")
    manifest_counts: dict[str, int] = {}
    if raw_counts is not None and not isinstance(raw_counts, dict):
        return manifest_counts, (
            f"the manifest's row counts are a {type(raw_counts).__name__}, not a mapping of table "
            "to count, so they cannot be compared"
        )
    malformed: list[str] = []
    for table, count in (raw_counts or {}).items():
        # bool is an int subclass, and a float, a string or a null is not a row count.
        if isinstance(count, int) and not isinstance(count, bool) and count >= 0:
            manifest_counts[str(table)] = count
        else:
            malformed.append(str(table))
    if malformed:
        return manifest_counts, (
            f"the manifest's row counts for {sorted(malformed)} are not non-negative integers, so "
            "they cannot be compared"
        )
    if not manifest_counts:
        return manifest_counts, (
            "the manifest records no row counts, so the row-count compare would read nothing; a "
            "full archive's manifest lists every table of its store"
        )
    mismatches = sorted(
        table for table in manifest_counts if row_counts.get(table, 0) != manifest_counts[table]
    )
    if mismatches:
        return manifest_counts, (
            f"row-count mismatch on {mismatches} (a torn snapshot or a wrong manifest): "
            f"snapshot={row_counts} manifest={manifest_counts}"
        )
    # After the mismatch check, so a truncated snapshot against nonzero counts still reads as the
    # data loss it is; what reaches here is an all-zero manifest agreeing with tables it never saw.
    if not manifest_counts.keys() & row_counts.keys():
        return manifest_counts, (
            f"the manifest's {len(manifest_counts)} table(s) share none with the archive's store.db "
            f"({len(row_counts)} table(s)), so the row-count compare would read nothing"
        )
    return manifest_counts, None


def _verify_extracted_store(snap: Path, manifest: dict[str, object]) -> dict[str, int]:
    """``integrity_check`` + the manifest row-count compare (:func:`_compare_row_counts`) on the
    extracted ``store.db``, run on the exact file about to be placed. Same two checks (and the same
    helpers) as :func:`_verify_archive_blocking` steps 3-4; returns the counts for the restore
    summary."""
    integrity_ok, integrity_msg = _integrity_check(snap)
    if not integrity_ok:
        raise BackupError("verify", f"the archive's store failed integrity_check: {integrity_msg}")
    row_counts = _count_tables(snap)
    _manifest_counts, count_refusal = _compare_row_counts(manifest, row_counts)
    if count_refusal is not None:
        raise BackupError("verify", count_refusal)
    return row_counts


def _refuse_existing_destination(dest_store_path: Path | None, config_dest: Path | None) -> None:
    """Refuse every destination that already holds something, BEFORE any decrypt work. Restoring over a
    live store is unrecoverable and a CLI cannot ask for permission, so the answer is no and the message
    names the path the operator must move or choose differently.

    The last arm refuses a pair of destinations that are individually empty and still collide, because
    this restore writes BOTH of them: see :func:`_refuse_config_dest_under_the_store`. Its mirror image
    needs the archive's member list and so runs later, in :func:`_refuse_colliding_config_members`.

    ``dest_store_path`` is ``None`` on the config-only route (vault BACKLOG #5233): there is no store
    to place, so only the config destination is checked."""
    if dest_store_path is not None:
        for path in (
            dest_store_path,
            *(dest_store_path.with_name(dest_store_path.name + s) for s in _SIDECAR_SUFFIXES),
        ):
            if path.exists():
                raise BackupError("destination", _OVERWRITE_REFUSAL.format(path=path))
    if config_dest is not None:
        # is_file() BEFORE iterdir(): a --config-to that names an existing FILE is a typo to report, and
        # iterdir() on one raises NotADirectoryError, which escapes the CLI's BackupError handler as a
        # traceback.
        if config_dest.is_file():
            raise BackupError(
                "destination",
                f"--config-to names an existing file at {config_dest}, not a directory — choose an "
                "empty or absent directory for the config bundle",
            )
        if config_dest.is_dir() and any(config_dest.iterdir()):
            raise BackupError(
                "destination",
                f"refusing to restore the config bundle into the non-empty directory {config_dest} — "
                "choose an empty or absent --config-to path",
            )
        if dest_store_path is not None:
            _refuse_config_dest_under_the_store(dest_store_path, config_dest)


def _refuse_config_dest_under_the_store(dest_store_path: Path, config_dest: Path) -> None:
    """Refuse a ``--config-to`` directory at or under the ``--to`` store's own path.

    ``--to D --config-to D/cfg`` passes both emptiness checks, because both destinations really are
    absent when they are read. The restore then publishes the verified store as the regular file ``D``,
    and the config bundle's ``mkdir(parents=True)`` needs ``D`` to be a directory -- so it dies with an
    uncaught ``FileExistsError`` while a restored store already sits at ``D`` and the retry is blocked by
    the never-overwrite refusal.

    No legitimate invocation has this shape: a directory cannot live under a regular file. Refusing the
    pair up front costs nothing and there is no decrypt to waste. The other direction (a ``--config-to``
    that CONTAINS the store) is a real invocation and is checked per member instead, against the
    archive's own member list -- see :func:`_refuse_colliding_config_members`."""
    if not _is_within(dest_store_path, config_dest):
        return
    raise BackupError(
        "destination",
        f"refusing to restore the config bundle into {config_dest}, which sits under the restored "
        f"store's own path {dest_store_path} — the store is written first, as a file, so the bundle "
        "could not be created beneath it. Choose a --config-to directory outside the --to path",
    )


def _refuse_colliding_config_members(
    tar_path: Path, dest_store_path: Path, config_dest: Path
) -> None:
    """Refuse an archive whose config bundle would land ON a file this restore publishes.

    This is the control for the P1 (BACKLOG #1717). ``--to D/store.db --config-to D`` passes every
    emptiness check, because both destinations really are absent when they are read. The restore then
    publishes the verified store at ``D/store.db`` and extracts the config bundle over the top of it, so
    a ``config/store.db`` member -- which the backup writer happily includes, since
    :meth:`BackupRunner._add_config_dir` takes every regular file under the config dir -- replaces the
    database that just passed ``integrity_check`` and the row-count compare. The summary still reports
    the pre-overwrite counts, so the operator is told a store was restored that is no longer there.

    It asks the PRECISE question -- does a member's output path equal one this restore writes -- rather
    than the proxy "does ``--config-to`` contain ``--to``". The proxy would refuse
    ``--to /srv/dr/store.db --config-to /srv/dr``, which is the one-directory form the early-adopter
    drill documents and which is perfectly safe for an archive with no colliding member.

    Run before the store is extracted, so a refusal costs neither the extract nor a half-finished
    restore. Traversal names are compared like any other: a ``../store.db`` member resolving back onto
    the store is the same collision, and refusing it here beats refusing it after placement. The
    exclusive create in :func:`_extract_config_members` is the backstop under this, not the control."""
    published = {
        _norm_for_compare(p)
        for p in (
            dest_store_path,
            *(dest_store_path.with_name(dest_store_path.name + s) for s in _SIDECAR_SUFFIXES),
        )
    }
    seen: set[str] = set()
    try:
        with tarfile.open(tar_path, "r:") as tar:
            for member in tar.getmembers():
                if not _is_config_payload_member(member):
                    continue
                # A hard link the extractor will refuse is refused here, before the store is
                # extracted, verified and placed only to be rolled back (vault BACKLOG #5233).
                # The whole restore is refused, store included; the refusal says the store alone
                # restores, because this check runs only when --config-to was given.
                if member.islnk() and member.linkname not in seen:
                    raise BackupError(
                        "restore",
                        f"{_dangling_link_refusal(member)}. The store alone restores: run the "
                        "same command without --config-to",
                    )
                seen.add(member.name)
                out = config_dest / member.name[len(_CONFIG_PREFIX) :]
                if _norm_for_compare(out) not in published:
                    continue
                raise BackupError(
                    "destination",
                    f"the archive's config bundle carries a member that would be written to {out}, "
                    f"which is where this restore publishes the store ({dest_store_path}) — it would "
                    "overwrite the database this restore just verified, and the summary would still "
                    "report the verified row counts. Choose a --config-to directory that does not "
                    "contain the --to path",
                )
    except (OSError, ValueError, tarfile.TarError) as exc:
        # The same catch-all shape :func:`_verify_archive_blocking` uses. ValueError is in it because
        # this reads ATTACKER-SUPPLIED member names into ``Path``: a name the platform cannot parse
        # must be a refusal, not a traceback out of a check whose whole job is to refuse.
        raise BackupError("restore", safe_exc(exc)) from exc


def _dangling_link_refusal(member: tarfile.TarInfo) -> str:
    """The refusal for a hard-link config member that names no config file extracted before it."""
    return (
        f"archive carries a config member {member.name!r} that is a hard link to "
        f"{member.linkname!r}, which names no config member earlier in the archive; "
        "refusing to restore it rather than leave that name out"
    )


def _is_config_payload_member(member: tarfile.TarInfo) -> bool:
    """Is ``member`` one the restore writes into the config bundle: a ``config/`` member that is a
    regular file or a hard link (vault BACKLOG #5233)? One predicate, because the pre-extract
    collision check (:func:`_refuse_colliding_config_members`) must see every member the extractor
    (:func:`_extract_config_members`) writes."""
    return (member.isfile() or member.islnk()) and member.name.startswith(_CONFIG_PREFIX)


def _norm_for_compare(path: Path) -> Path:
    """``path`` resolved and lower-cased, for comparison against another destination path.

    Neither path need exist yet, so the comparison has to be lexical; ``resolve`` first, so ``..``, a
    relative spelling and a symlinked destination all reduce to one form.

    Case is folded UNCONDITIONALLY, not via :func:`os.path.normcase`, which is the identity function on
    POSIX and would therefore miss case-insensitive macOS and every case-insensitive mount. The cost is
    a false refusal where two paths differing only in case really are two files; that costs the operator
    a rename, where a missed collision costs the restored database. ``lower`` rather than ``casefold``
    because ``casefold`` maps ``ss`` onto the sharp s and would fuse two genuinely distinct paths."""
    return Path(str(path.resolve()).lower())


def _is_within(root: Path, path: Path) -> bool:
    """Is ``path`` at or under ``root``? Both reduced by :func:`_norm_for_compare` first."""
    return _norm_for_compare(path).is_relative_to(_norm_for_compare(root))


def _place_restored_store(src: Path, dest: Path) -> int:
    """Put the verified ``store.db`` at ``dest`` without ever overwriting, and return its size.

    A hard link first: ``src`` was staged on the destination's own volume, so this costs nothing where
    a multi-GB copy would, and ``os.link`` raises ``FileExistsError`` on a collision — closing the
    check-then-write race that a concurrent creator could otherwise slip through. Where links are
    unavailable (FAT, some SMB shares) the fallback is an EXCLUSIVE-create copy, which has the same
    never-overwrite property. Either way the restored file is a full copy of the PHI-bearing store, so
    it is locked down the way ``Store.snapshot_to`` locks its own output down."""
    # Reuse the store's own PHI-at-rest primitive rather than a second chmod/icacls path. It is the
    # store-trio rule, not bare _secure_file: restored into a hardened data directory, an owner-only
    # file would lock the service account out of the store it is about to open (ADR 0183 Wave 0b).
    from messagefoundry.store.store import _secure_store_file, _store_dir_grants

    size = src.stat().st_size
    try:
        os.link(src, dest)
    except FileExistsError:
        raise
    except OSError:
        # The exclusive create sits OUTSIDE the cleanup guard on purpose: a lost create race raises
        # FileExistsError here, and the file then at ``dest`` belongs to the winner — deleting it would
        # turn a refusal into the unrecoverable overwrite the refusal exists to prevent.
        out = open(dest, "xb")  # noqa: SIM115 — held open across the guard below
        placed = False
        try:
            with out, open(src, "rb") as fh:
                shutil.copyfileobj(fh, out, 1024 * 1024)
                out.flush()
                os.fsync(out.fileno())
            placed = True
        finally:
            # A copy that dies mid-stream (a full volume, a dropped share) would otherwise leave a
            # TRUNCATED store beside a reported failure: a valid-looking SQLite file an operator could
            # activate, and debris that then fails the retry's never-overwrite check. ``finally``, not
            # ``except``, so nothing is caught and no failure mode is missed. It runs after ``with out``
            # has closed the handle, which Windows requires before an unlink.
            if not placed:
                dest.unlink(missing_ok=True)
    _secure_store_file(dest, dir_grants=_store_dir_grants(dest.parent))
    return size


def _restore_config_members(
    tar_path: Path, config_dest: Path, *, written: list[Path] | None = None
) -> int:
    """:func:`_extract_config_members`, with an ``OSError``, ``ValueError`` or ``tarfile.TarError``
    it does not word itself made a refusal (vault BACKLOG #5233). At least these are covered: a
    ``PermissionError`` from a ``mkdir``, a full volume, and a member that ends early. Any other
    exception type still escapes as it did. Unguarded, each left the restore as a CLI
    traceback, on the config-only route and the store route alike. The caller's ``finally`` still
    rolls back what ``written`` records."""
    try:
        return _extract_config_members(tar_path, config_dest, written=written)
    except (OSError, ValueError, tarfile.TarError) as exc:
        raise BackupError(
            "restore", f"could not restore the config bundle into {config_dest}: {safe_exc(exc)}"
        ) from exc


def _extract_config_members(
    tar_path: Path, config_dest: Path, *, written: list[Path] | None = None
) -> int:
    """Extract the archive's ``config/`` members into ``config_dest`` and return how many files landed.

    ``written`` is the caller's ledger of what this call created -- every directory it made under
    ``config_dest`` and every file it opened, each appended BEFORE any bytes land in it and in creation
    order, so :func:`_discard_partial_restore` can walk it backwards. ``config_dest`` itself is never
    recorded: one the operator prepared may carry ACLs worth more than the tidiness of deleting it.
    An absent one that a failed restore created is removed while still empty, by
    :func:`_restore_blocking` from its own list of the directories it made (vault BACKLOG #5233). A
    file the exclusive create refused is not recorded either, because it is not this call's to
    remove.

    It cannot reuse :func:`_extract_member`, which streams ONE member to a single fixed output name;
    a config bundle is many files that must keep their relative layout. It carries the same ASVS 5.2.3
    bound (the uncompressed-pinned ``"r:"`` reader, the declared size rejected before streaming, the
    streamed bytes counted). Member names are gated by the shared ASVS 5.3.2 check
    (:func:`~messagefoundry.parsing.sniff.archive_member_name_reason`) rather than a second private one,
    so a traversal, a backslash separator, a drive-relative prefix or a control character is refused
    here exactly as it is on the inbound-archive path.

    The per-member cap is not enough on its own here — N members each just under it would still fill the
    disk — so the bundle also carries an AGGREGATE byte ceiling and a member-count ceiling.

    The restored bundle can carry secrets (``connections.toml``), so each file is locked to its owner.

    **A hard-link member is restored, never skipped (vault BACKLOG #5233).** ``tar.add`` stores the
    second name of a hard-linked file as a link member (``LNKTYPE``) naming the first, and this loop
    used to take regular members alone, so that name was silently missing from the restored bundle.
    It now lands as its own regular file, a copy of the bytes of the member it names, under every
    check a regular member gets: the name gate and the containment backstop on its OWN name, the size
    caps on the bytes it carries, and the exclusive create. The bytes are read only from a regular
    config member this call has ALREADY extracted, looked up by exact name, so the link cannot reach
    the store, the manifest, a later member, or anything outside the archive, and no OS link is made
    in the destination. A link member naming anything else is refused, naming both names. Any other
    member type (a directory, a symlink, a device) is still not extracted. A link carries no bytes of
    its own, so a few link headers can write a large member several times over: what bounds that is
    the bundle's aggregate byte and member-count caps below, which count every landed copy.

    An archive with no config member is a REFUSAL, not a quiet empty directory — see :func:`run_restore`.
    """
    from messagefoundry.parsing.sniff import archive_member_name_reason
    from messagefoundry.store.store import _secure_file

    config_dest.mkdir(parents=True, exist_ok=True)
    root = config_dest.resolve()
    landed = 0
    total = 0
    # Each config member extracted so far, by its exact name, mapped to the regular member whose
    # bytes it carries. A hard-link member reads its bytes from here and nowhere else.
    extracted: dict[str, tarfile.TarInfo] = {}
    with tarfile.open(tar_path, "r:") as tar:
        for member in tar.getmembers():
            if not _is_config_payload_member(member):
                continue
            if landed >= _MAX_CONFIG_MEMBERS:
                raise BackupError(
                    "restore",
                    f"config bundle exceeds the restore member-count cap ({_MAX_CONFIG_MEMBERS})",
                )
            rel = member.name[len(_CONFIG_PREFIX) :]
            reason = archive_member_name_reason(rel)
            if reason is not None:
                raise BackupError(
                    "restore", f"archive carries an unsafe config member name ({reason})"
                )
            out = (root / rel).resolve()
            if not out.is_relative_to(root):  # backstop: the name gate is the primary control
                raise BackupError(
                    "restore",
                    "archive carries a config member that resolves outside the destination; "
                    "refusing to extract it",
                )
            data = member
            if member.islnk():
                # Looked up by exact name among members already extracted, never through tarfile's
                # own link resolution, which normalizes the name and would hand back any earlier
                # member it matches, the store included.
                target = extracted.get(member.linkname)
                if target is None:
                    raise BackupError("restore", _dangling_link_refusal(member))
                data = target
            if data.size > _MAX_RESTORE_MEMBER_BYTES:
                raise BackupError(
                    "restore",
                    f"config member exceeds the restore extract cap ({_MAX_RESTORE_MEMBER_BYTES} bytes)",
                )
            src = tar.extractfile(data)
            if src is None:
                continue
            # The directories this member's mkdir is about to CREATE, deepest first, read before the
            # mkdir so the ledger holds exactly what it made and never a directory that was already
            # there. The walk stops at the destination root; the second guard is belt-and-braces
            # against a path whose parent is itself (a filesystem root), which the `is_relative_to`
            # check above already rules out.
            new_dirs: list[Path] = []
            probe = out.parent
            while probe != root and probe != probe.parent and not probe.exists():
                new_dirs.append(probe)
                probe = probe.parent
            # A forged archive can carry `config/a` as a regular file AND `config/a/b` under it. Both
            # pass the name gate, and the second one's mkdir then re-raises FileExistsError because the
            # existing path is not a directory -- uncaught all the way out to a CLI traceback.
            try:
                out.parent.mkdir(parents=True, exist_ok=True)
            except (FileExistsError, NotADirectoryError) as exc:
                raise BackupError(
                    "restore",
                    f"archive carries a config member at {member.name} whose parent directory "
                    "collides with a member already extracted as a file",
                ) from exc
            if written is not None:
                written.extend(reversed(new_dirs))  # shallowest first: creation order
            streamed = 0
            # EXCLUSIVE create, so a member can never land on a file that is already there. The
            # overlapping-destination refusal is the control for the case that made this reachable
            # (BACKLOG #1717); this is the backstop, and it also covers a forged archive carrying the
            # same member name twice, where the second copy would otherwise silently replace the first.
            try:
                fh = open(out, "xb")  # noqa: SIM115 -- the `with` below owns it
            except FileExistsError as exc:
                raise BackupError(
                    "restore",
                    f"refusing to overwrite the existing file at {out} while restoring the config "
                    "bundle",
                ) from exc
            except OSError as exc:
                # `FileExistsError` alone does not cover the collision it looks like it covers. The
                # mirror image of the mkdir case above -- a forged archive carrying `config/a/b` and
                # then `config/a` -- asks to create a file where a DIRECTORY already sits, and the
                # exclusive open reports that as EACCES on Windows (measured: PermissionError), not
                # EEXIST. It escaped as a traceback from the one arm written to refuse it. Every other
                # OSError here (a full volume, a revoked ACL, a name the filesystem rejects) is a
                # refusal on the same terms rather than a traceback, so the arm is written wide and
                # carries the OS's own reason instead of asserting which cause it was.
                raise BackupError(
                    "restore",
                    f"could not create the config member at {out} while restoring the config bundle "
                    f"({safe_exc(exc)}); a directory may already sit at that path",
                ) from exc
            if written is not None:
                written.append(out)
            with fh:
                # Locked to its owner on the empty file, before the first byte: the bundle can carry
                # secrets (connections.toml), and securing it after the stream would leave the write
                # under the directory's inherited ACL on Windows for as long as the write takes.
                _secure_file(out)
                while True:
                    buf = src.read(1024 * 1024)
                    if not buf:
                        break
                    # Counting the streamed bytes IS the cap enforcement here (a lying header declares a
                    # small size and streams an unbounded one), so this loop cannot become copyfileobj.
                    streamed += len(buf)
                    if streamed > _MAX_RESTORE_MEMBER_BYTES or total + streamed > _MAX_CONFIG_BYTES:
                        raise BackupError(
                            "restore",
                            "config bundle stream exceeds the restore extract cap "
                            f"(per member {_MAX_RESTORE_MEMBER_BYTES} bytes, bundle total "
                            f"{_MAX_CONFIG_BYTES} bytes)",
                        )
                    fh.write(buf)
            total += streamed
            landed += 1
            extracted[member.name] = data
    if landed == 0:
        # "At least": the two settings are not the only causes (vault BACKLOG #5233). A backup whose
        # walk of the config dir adds no regular file also writes an archive with no config member.
        raise BackupError(
            "restore",
            "the archive carries no config bundle, so there is nothing for --config-to to restore. "
            "At least these leave an archive with none: the backup was taken with "
            "[backup].include_config=false, or with no config dir loaded, or its walk of the config "
            "dir added no regular file, such as a dir that is empty or holds only symbolic links",
        )
    return landed
