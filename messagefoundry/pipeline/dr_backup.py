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
import io
import json
import logging
import os
import tarfile
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from messagefoundry.config.settings import BackupSettings, StoreBackend, StoreSettings
from messagefoundry.last_resort import run_guarded
from messagefoundry.pipeline.alerts import AlertSink, LoggingAlertSink
from messagefoundry.pipeline.cluster import ClusterCoordinator, NullCoordinator
from messagefoundry.redaction import safe_exc
from messagefoundry.store import MessageStore, Store
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
    build_store_cipher,
    resolve_active_key,
    resolve_decrypt_keys,
)
from messagefoundry.store.crypto import (
    MARKER_PREFIX,
    CipherError,
    StoreKeylessError,
    cell_aad,
)

__all__ = [
    "BackupRunner",
    "BackupResult",
    "RestoreResult",
    "VerifyResult",
    "BackupError",
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
#: path, both limbs of it. :func:`_verify_archive_blocking`'s own plaintext limb is still uncounted;
#: it stages in the OS temp dir rather than beside the store, and giving it this bound means adding an
#: escape arm to that function's ordered ``except`` block, which is a wider change than the one this
#: constant documents.
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
#: restore-EXTRACT bound: its only read is in :func:`_restore_config_members`, which runs solely when
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
#: process's memory. 1 MiB is many times the largest manifest this writer produces — a fixed field
#: set plus one row count per table in the snapshot's own schema (BACKLOG #1722; every table, not a
#: hand-picked sample — see :func:`_count_tables`).
_MAX_MANIFEST_BYTES = 1024 * 1024  # 1 MiB


class BackupError(RuntimeError):
    """A backup run failed at a named phase (``snapshot``/``encrypt``/``write``/``verify``/
    ``destination``). Carries the ``kind`` so the caller can pass it to ``AlertSink.backup_failed`` and
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


@dataclass(frozen=True)
class RestoreResult:
    """What one ``messagefoundry restore`` produced — the CLI summary + tests. PHI-free: paths, sizes,
    counts, and one-way fingerprints only (never a body or key bytes)."""

    archive_path: str
    store_path: str
    store_bytes: int
    row_counts: dict[str, int]
    encrypted: bool
    key_id: str | None
    config_dir: str | None
    config_files: int


class BackupRunner:
    """Engine-managed DR backup (ADR 0049). Construct with the store + ``[backup]`` settings + the store
    settings (for the key source) + the loaded config dir; call :meth:`start`/:meth:`stop` for the
    supervised daily loop, or :meth:`run_once` for a single deterministic pass (the CLI + tests)."""

    def __init__(
        self,
        store: Store,
        settings: BackupSettings,
        *,
        store_settings: object,
        config_dir: str | Path | None,
        engine_version: str = "",
        instance: str = "",
        alert_sink: AlertSink | None = None,
        clock: Callable[[], float] = time.time,
        coordinator: ClusterCoordinator | None = None,
    ) -> None:
        self._store = store
        self._settings = settings
        # The store settings carry the KeyProvider seam (ADR 0019) — the archive's KEY SOURCE. Typed
        # loosely to avoid importing StoreSettings here; resolve_active_key takes it.
        self._store_settings = store_settings
        self._config_dir = Path(config_dir) if config_dir is not None else None
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
        self._frames: list[int] = []

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
                "(set [backup].allow_unencrypted=true for a synthetic/no-PHI box, or configure "
                "MEFOR_STORE_ENCRYPTION_KEY)",
            )
        key_id = key_fingerprint(key) if key is not None else None

        # Decide config-only vs full per backend + setting (AC-7). SQLite → full store snapshot; a
        # server-DB store → config-only (or skip) because the DB backup is DBA-delegated (#52). The CLI
        # --config-only flag forces config-only even on SQLite.
        config_only = force_config_only or self._is_server_db()
        if self._is_server_db() and not s.config_only_on_server_db:
            raise BackupError(
                "snapshot",
                f"store backend {self._backend_value()!r} is DBA-delegated (BACKLOG #52) and "
                "[backup].config_only_on_server_db=false — nothing to back up; the DB is the DBA's job",
            )

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

        # Build everything under one temp dir. The CONSISTENT SNAPSHOT must run on the ENGINE event loop
        # (store.snapshot_to serialises on the store lock and drives aiosqlite, which is bound to this
        # loop — it does its own off-loop PRAGMA work). The CPU/IO-heavy tar + AEAD then run OFF the loop
        # in a worker thread over the snapshot file (never blocking asyncio, never the whole store in RAM).
        with tempfile.TemporaryDirectory(prefix="mefor-backup-") as tmp:
            tmpdir = Path(tmp)
            snap_path: Path | None = None
            snapshot_sha256 = ""
            row_counts: dict[str, int] = {}
            if not config_only:
                snap_path = tmpdir / _STORE_MEMBER
                try:
                    await self._store.snapshot_to(snap_path, method=s.snapshot_method)
                except (
                    DbaDelegatedError
                ) as exc:  # defensive: config_only already handles the server DB
                    raise BackupError("snapshot", safe_exc(exc)) from exc
                except (OSError, ValueError, FileExistsError) as exc:
                    raise BackupError("snapshot", safe_exc(exc)) from exc
            try:
                snapshot_sha256, row_counts, archive_bytes = await asyncio.to_thread(
                    self._build_archive_blocking,
                    out_path=staging_path,
                    snap_path=snap_path,
                    key=key,
                    key_id=key_id,
                    config_only=config_only,
                    now=now,
                )
            except (OSError, BackupCodecError) as exc:
                kind = "write" if isinstance(exc, OSError) else "encrypt"
                raise BackupError(kind, safe_exc(exc)) from exc
            await self._charge_archive_invocations(key_id)

        verify: VerifyResult | None = None
        if s.verify_after_backup:
            # The just-written archive is sealed under the active key, so the active key is the only
            # candidate the post-write verify needs (the retired-key keyring matters only for the
            # standalone restore-verify of an OLDER archive — run_restore_verify, AC-5).
            verify = await asyncio.to_thread(
                _verify_archive_blocking,
                archive_path=str(staging_path),
                keys=[key] if key is not None else [],
                full=s.full_restore_verify,
                allow_unencrypted=s.allow_unencrypted,
                # The LIVE store settings, so a full verify opens the snapshot under this instance's
                # real cipher/keyring/provider rather than a bare default (see _full_open_check).
                store_settings=self._store_settings,
            )
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
            config_fingerprint=self._config_fingerprint(),
            row_counts=row_counts,
            verify=verify,
            pruned=pruned,
            encrypted=key is not None,
        )

    async def _charge_archive_invocations(self, key_id: str | None) -> None:
        """Charge this run's DR-frame AES-GCM invocations to the key's PERSISTED invocation bound
        (ASVS 11.3.4) — a post-run aggregate add, since the frames are written on a worker thread that
        holds no store handle.

        Without this the bound under-counts by every backup run: ``backup_codec`` constructs its own
        ``AESGCM`` from the raw DEK and never reaches ``AesGcmCipher._count_invocation``, yet a 10 GB
        store at the 1 MiB default chunk is ~10k invocations per run under that same key. Best-effort —
        an accounting failure must never fail an otherwise-successful backup."""
        frames = sum(self._frames)
        self._frames.clear()
        if not frames or key_id is None:
            return
        try:
            await self._store.add_cipher_invocations(key_id, frames)
        except Exception:  # noqa: BLE001 — advisory accounting; never fail a good backup
            log.warning(
                "DR backup: could not charge %d archive frame(s) to the AES-GCM invocation bound",
                frames,
                exc_info=True,
            )

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

    def _build_archive_blocking(
        self,
        *,
        out_path: Path,
        snap_path: Path | None,
        key: bytes | None,
        key_id: str | None,
        config_only: bool,
        now: float,
    ) -> tuple[str, dict[str, int], int]:
        """tar(store.db + config/ + manifest.json) → stream-encrypt to ``out_path``. Runs entirely
        OFF the event loop (the consistent snapshot at ``snap_path`` was already taken on the loop by the
        caller). Returns ``(snapshot_sha256, row_counts, archive_bytes)``. The tar goes to a temp file
        (not RAM) so a multi-GB store never sits in memory; the codec then streams it to the archive.

        ``out_path`` is the STAGING path, not the canonical archive name — the caller publishes that
        name by rename once the archive has passed every configured check (see :data:`_STAGING_SUFFIX`).
        The final ``fsync`` below is what makes that rename safe to treat as the publish point when
        ``verify_after_backup`` is off: the bytes are durable before the name appears."""
        snapshot_sha256 = ""
        row_counts: dict[str, int] = {}
        if snap_path is not None:
            snapshot_sha256 = _sha256_file(snap_path)
            row_counts = _count_tables(snap_path)

        manifest = {
            "format": "mfbak",
            # The .mfbak archive format version — parity with the AAD-bound codec header (ADR 0049
            # "What's in the archive"). The header's value is authoritative for decode; this is the
            # human-/tooling-readable copy inside the manifest.
            "format_version": FORMAT_VERSION,
            "engine_version": self._engine_version,
            "instance": self._instance,
            "created_utc": _utc_iso(now),
            "snapshot_method": self._settings.snapshot_method,
            "config_only": config_only,
            "backend": self._backend_value(),
            "key_id": key_id,  # one-way fingerprint, NEVER key bytes
            "config_fingerprint": self._config_fingerprint(),
            "snapshot_sha256": snapshot_sha256,
            "row_counts": row_counts,
        }
        manifest_bytes = json.dumps(manifest, sort_keys=True).encode("utf-8")

        with tempfile.TemporaryDirectory(prefix="mefor-tar-") as tar_tmp:
            tar_path = Path(tar_tmp) / "archive.tar"
            with tarfile.open(tar_path, "w") as tar:
                if snap_path is not None:
                    tar.add(snap_path, arcname=_STORE_MEMBER)
                if self._settings.include_config and self._config_dir is not None:
                    self._add_config_dir(tar)
                info = tarfile.TarInfo(_MANIFEST_MEMBER)
                info.size = len(manifest_bytes)
                info.mtime = int(now)
                tar.addfile(info, io.BytesIO(manifest_bytes))

            out_path.parent.mkdir(parents=True, exist_ok=True)
            with open(tar_path, "rb") as src, open(out_path, "wb") as dst:
                if key is not None:
                    # ASVS 11.3.4: every DR frame is an AES-GCM invocation under the SAME store DEK, so
                    # it consumes the same birthday budget. Record the count here (the worker thread
                    # holds no store) and charge it to the key's persisted bound after the run.
                    encrypt_stream(src, dst, key, on_frames=self._frames.append)
                else:
                    # No key + allow_unencrypted: write the plaintext tar verbatim (synthetic/no-PHI box).
                    while True:
                        buf = src.read(1024 * 1024)
                        if not buf:
                            break
                        dst.write(buf)
                dst.flush()
                os.fsync(dst.fileno())
        archive_bytes = out_path.stat().st_size
        return snapshot_sha256, row_counts, archive_bytes

    def _add_config_dir(self, tar: tarfile.TarFile) -> None:
        """Add the loaded config dir under ``config/`` — every regular file (incl. ``_*.py``,
        ``connections.toml``, ``codesets/``, fixtures). Symlinks are NOT followed (a symlink out of the
        bundle would smuggle an arbitrary host file into the archive); only regular files are added."""
        base = self._config_dir
        assert base is not None
        for path in sorted(base.rglob("*")):
            if path.is_symlink() or not path.is_file():
                continue
            rel = path.relative_to(base).as_posix()
            tar.add(path, arcname=f"{_CONFIG_PREFIX}{rel}")

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
            "snapshot_sha256": result.snapshot_sha256,
            "row_counts": result.row_counts,
            "verify": verify.status if verify is not None else "skipped",
            "verify_integrity_ok": verify.integrity_ok if verify is not None else None,
            # A COUNT of cipher-covered cells the full verify opened — PHI-free, and the one field that
            # distinguishes "the snapshot opened" from "its PHI was readable".
            "verify_decrypted_cells": verify.decrypted_cells if verify is not None else None,
            "pruned": result.pruned,
        }
        await self._store.record_audit(
            "dr_backup", actor="system", detail=json.dumps(detail, sort_keys=True), now=now
        )

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
        import base64

        key_b64 = resolve_active_key(self._store_settings)  # type: ignore[arg-type]
        if not key_b64:
            return None
        return base64.b64decode(key_b64)

    def _config_fingerprint(self) -> str | None:
        if self._config_dir is None:
            return None
        from messagefoundry.config.fingerprint import config_fingerprint

        try:
            return config_fingerprint(self._config_dir)
        except OSError:
            return None

    def _is_server_db(self) -> bool:
        return self._backend_value() in (StoreBackend.POSTGRES.value, StoreBackend.SQLSERVER.value)

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
        import shutil

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
    ``KEY_MISMATCH``."""
    for key in keys:
        if key_fingerprint(key) == header_key_id:
            return key
    return None


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
    allow_unencrypted: bool = False,
    store_settings: object | None = None,
) -> VerifyResult:
    """Lightweight (or full) restore-verify of a ``.mfbak`` archive — runs OFF the event loop.

    ``keys`` is the decrypt-capable keyring (active + retired, ADR 0049 AC-5 "incl. retired keys") — the
    archive is matched against the whole set so one taken under a now-retired key still verifies after a
    rotation; an empty list means "no key configured" (only valid for a plaintext archive).

    ASVS 5.2.3 (symmetric ``allow_unencrypted``): the write path refuses to *write* a plaintext archive
    when no key is configured unless ``[backup].allow_unencrypted`` is set; symmetrically, when a store key
    IS configured a **plaintext** archive is a downgrade signal (an attacker swapping the AEAD-sealed
    archive for an unauthenticated one) and is refused here as ``KEY_MISMATCH`` — unless ``allow_unencrypted``
    is set for a synthetic/no-PHI box.

    ``store_settings`` is this instance's live :class:`StoreSettings`. It is what a ``full`` verify opens
    the snapshot with, so the snapshot is read under the real cipher, keyring and key provider; without
    it a ``full`` verify FAILs rather than opening keyless (see :func:`_full_open_check`).

    Steps (ADR 0049): (1) key-fingerprint precheck — a mismatch is a clean ``KEY_MISMATCH`` BEFORE any
    decrypt; (2) decrypt the archive; (3) extract + open ``store.db`` read-only, run
    ``PRAGMA integrity_check``; (4) compare per-table row counts to the manifest. ``full`` additionally
    re-opens the snapshot through the real ``open_store`` path (cipher + migrations) and decrypts +
    authenticates every cipher-covered cell in it — heavier. That leg returns its own
    ``KEY_MISMATCH`` when the settings resolve no key for a snapshot that holds sealed cells, so an
    archive that is fine and a key configuration that is not are not both reported as ``FAIL``."""
    try:
        # (1) Pre-decryption key check (only meaningful for an encrypted archive). For a plaintext
        # archive (no codec header) there is no key to mismatch.
        match_key: bytes | None = None
        encrypted = _looks_encrypted(archive_path)
        if not encrypted and keys and not allow_unencrypted and Path(archive_path).is_file():
            # A store key is configured but the archive is plaintext — refuse (possible downgrade/tamper),
            # symmetric to the write-side fail-closed. allow_unencrypted opts a synthetic/no-PHI box back in.
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

        with tempfile.TemporaryDirectory(prefix="mefor-verify-") as tmp:
            tar_path = Path(tmp) / "archive.tar"
            # (2) decrypt (or copy a plaintext archive) to the tar.
            with open(archive_path, "rb") as src, open(tar_path, "wb") as dst:
                if encrypted:
                    assert match_key is not None
                    # Post-authentication resource bound on the temp dir (see the constant). An over-cap
                    # archive raises BackupCodecError, which the `except BackupCodecError` arm below
                    # already turns into a FAIL — no new failure arm, and the TemporaryDirectory
                    # discards the partial tar on the way out.
                    decrypt_stream(
                        src, dst, match_key, max_plaintext_bytes=_MAX_RESTORE_PLAINTEXT_BYTES
                    )
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
            snap = _extract_member(tar_path, _STORE_MEMBER, Path(tmp))
            if snap is None:
                return VerifyResult("FAIL", reason="archive has no store.db member")

            # (3) integrity_check (the fuller PRAGMA integrity_check, off the hot path).
            integrity_ok, integrity_msg = _integrity_check(snap)
            raw_counts = manifest.get("row_counts")
            manifest_counts = (
                {str(k): int(v) for k, v in raw_counts.items()}
                if isinstance(raw_counts, dict)
                else {}
            )
            row_counts = _count_tables(snap)
            if not integrity_ok:
                return VerifyResult(
                    "FAIL",
                    integrity_ok=False,
                    row_counts=row_counts,
                    manifest_counts=manifest_counts,
                    reason=f"integrity_check failed: {integrity_msg}",
                )
            # (4) row-count sanity vs the manifest (catches a torn/truncated snapshot).
            #
            # Compared over the MANIFEST's own keys, not by dict equality (BACKLOG #1722 follow-up).
            # `_count_tables` derives its table set from the file it is given, so `row_counts` here
            # reflects the RESTORED snapshot's own schema, which can legitimately be a superset of
            # what an OLDER manifest recorded — a manifest written before this table set was widened
            # (or before a later table existed at all) has fewer keys than the archive it describes
            # really has tables. `run_restore_verify` is explicitly a standalone check of an OLDER
            # archive (see its docstring and the AC-5 comment above), so that gap is an ordinary
            # thing to hit, not tampering, and dict equality would FAIL every such archive on sight.
            # A table the manifest tracked but the snapshot's schema no longer has (dropped, or never
            # existed there) reads as a 0, the same convention the old fixed-list `_count_tables` used
            # for a table absent from the schema — so a manifest count of 0 for it still passes, and a
            # nonzero one still correctly FAILs (real data loss). A table `row_counts` has that the
            # manifest never tracked is not compared at all: an older manifest cannot be faulted for
            # not knowing about a table it never counted.
            mismatches = {
                table: (manifest_counts[table], row_counts.get(table, 0))
                for table in manifest_counts
                if row_counts.get(table, 0) != manifest_counts[table]
            }
            if mismatches:
                return VerifyResult(
                    "FAIL",
                    integrity_ok=True,
                    row_counts=row_counts,
                    manifest_counts=manifest_counts,
                    reason=f"row-count mismatch on {sorted(mismatches)}: "
                    f"snapshot={row_counts} manifest={manifest_counts}",
                )
            decrypted_cells = 0
            if full:
                # The heavier end-to-end restore: open the snapshot through the real open_store path
                # (cipher + migrations) to prove it restores, decrypt + authenticate its PHI, then
                # discard it.
                full_status, full_msg, decrypted_cells = _full_open_check(
                    snap, _as_store_settings(store_settings)
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
    except BackupKeyMismatch as exc:
        return VerifyResult("KEY_MISMATCH", reason=safe_exc(exc))
    except BackupCodecError as exc:
        return VerifyResult("FAIL", reason=f"decrypt failed: {safe_exc(exc)}")
    except (OSError, tarfile.TarError) as exc:
        # `json.JSONDecodeError` is no longer named here: `_read_manifest_from_tar` reports a
        # manifest that will not parse as `TarError`, and nothing else in the block parses JSON
        # (`read_header` raises `BackupCodecError` for its own). A name for a type that cannot
        # arrive reads as a guard and guards nothing.
        return VerifyResult("FAIL", reason=safe_exc(exc))


async def run_restore_verify(
    archive_path: str,
    *,
    store_settings: object,
    full: bool = False,
    allow_unencrypted: bool = False,
) -> VerifyResult:
    """Verify an existing ``.mfbak`` archive WITHOUT activating it (ADR 0049 — 0049's owned primitive,
    which ADR 0048's cold-seed activation *calls*). Resolves the store's decrypt-capable keyring (active
    + retired, AC-5 "incl. retired keys"), runs the key-fingerprint precheck → decrypt → integrity_check
    → row-count compare, and returns a structured ``PASS``/``FAIL``/``KEY_MISMATCH``
    :class:`VerifyResult`. All heavy work runs off the event loop.

    ``allow_unencrypted`` (``[backup].allow_unencrypted``, default off) mirrors the write-side fail-closed:
    with it off, a plaintext archive is refused (``KEY_MISMATCH``) when a store key is configured (ASVS
    5.2.3 downgrade guard)."""
    import base64

    # The decrypt-capable keyring, NOT just the active key: a backup taken under a key that has since
    # been retired (a routine WP-5 rotation) must still verify, or ADR 0048's cold-seed activation would
    # falsely refuse a perfectly recoverable archive (AC-5: compare to the resolved key, incl. retired).
    keys = [
        base64.b64decode(k)
        for k in resolve_decrypt_keys(store_settings)  # type: ignore[arg-type]
    ]
    return await asyncio.to_thread(
        _verify_archive_blocking,
        archive_path=archive_path,
        keys=keys,
        full=full,
        allow_unencrypted=allow_unencrypted,
        # Threaded through so a full verify opens the snapshot under the SAME cipher/keyring/provider
        # the keyring above was resolved from, instead of a bare default (see _full_open_check).
        store_settings=store_settings,
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


def _count_tables(db_path: Path) -> dict[str, int]:
    """Row counts for EVERY table in ``db_path``'s own schema, via a plain read-only sqlite3
    connection (no engine store). The table set is DERIVED from ``sqlite_master`` at count time
    rather than a hand-picked sample (BACKLOG #1722): the old fixed four-table list
    (``messages``/``queue``/``message_events``/``audit_log``) covered 4 of this schema's 30 tables —
    a truncated or absent table among the other 26 (at least the auth tables ``users``/``sessions``/
    ``roles``/``webauthn_credentials`` and the audit chain's ``audit_chain_meta``) passed
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
    :func:`_verify_archive_blocking` is written to tolerate exactly that (keyed off the manifest's
    own keys, not dict equality) — this function only ever reports what IS in the schema, and does
    not itself guarantee cross-build equality.

    ``sqlite_%`` names are excluded: they are sqlite's own bookkeeping (e.g. ``sqlite_sequence`` for
    an ``AUTOINCREMENT`` column), not store data, and are not guaranteed to exist at all until some
    other operation (a first autoincrement insert, an ``ANALYZE``) creates them."""
    import sqlite3

    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
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
    """``PRAGMA integrity_check`` on a snapshot via a plain read-only sqlite3 connection."""
    import sqlite3

    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        results = [str(r[0]) for r in conn.execute("PRAGMA integrity_check")]
    finally:
        conn.close()
    ok = results == ["ok"]
    return ok, "ok" if ok else "; ".join(results)[:500]


def _full_open_check(snap: Path, settings: StoreSettings | None) -> tuple[str, str, int]:
    """Open the snapshot through the real ``open_store`` path, then decrypt + authenticate its PHI.
    Returns ``(status, message, decrypted_cells)`` — the ``VerifyResult`` status this leg earned, so the
    caller can hand it straight on. Heavier; only run for ``full_restore_verify``.

    ``KEY_MISMATCH`` is reserved for the one cause the keyring is unambiguously to blame for: the
    snapshot holds sealed (``mfenc:``) cells and these settings resolve **no** key for them, so nothing
    could have opened them. An operator reading that fixes their key configuration; reading ``FAIL``
    they would go looking for a bad archive, and the archive is fine. A cell that will not decrypt under
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
    archive against SQLite rather than dialling Postgres/SQL Server with a file path."""
    from messagefoundry.store.base import open_store

    if settings is None:
        # Fail-closed. The only thing available without the live settings is a keyless open, and a PASS
        # from one says nothing about an encrypted archive — which is the archive worth verifying.
        return "FAIL", "no live store settings were supplied for the full restore-verify", 0
    snap_settings = settings.model_copy(update={"path": str(snap), "backend": StoreBackend.SQLITE})

    async def _open() -> tuple[bool, str]:
        # Bind the store BEFORE the try. An open that raises — a keyless or wrong-key open, an
        # unreachable key provider — must surface ITS OWN cause, not a NameError from a finally closing
        # a store that was never created, and not the temp-directory cleanup error a leaked handle
        # raises over the top of it on Windows one frame up.
        store = await open_store(snap_settings)
        try:
            return await store.integrity_check()
        finally:
            await store.close()

    try:
        ok, msg = run_guarded(_open())
    except StoreKeylessError as exc:
        # The store's own eager `state`/`reference` warm-ups fail closed on a keyless open of an
        # encrypted store, and they reach this before the decrypt pass below ever runs. Same cause,
        # same verdict — an absent keyring, not a bad archive.
        return "KEY_MISMATCH", safe_exc(exc), 0
    except Exception as exc:  # a restore that won't even open is the thing we're trying to catch
        return "FAIL", safe_exc(exc), 0
    if not ok:
        return "FAIL", msg, 0
    return _decrypt_check(snap, snap_settings)


def _decrypt_check(snap: Path, settings: StoreSettings) -> tuple[str, str, int]:
    """Decrypt AND authenticate every cipher-covered cell retained in the snapshot, under the store's own
    cipher. Returns ``(status, message, cells)`` — a COUNT and a PHI-free reason, never a plaintext.

    Opening the store proves the file is a readable SQLite database. It does not prove the PHI inside it
    is readable, and those are the two different claims a disaster-recovery check gets confused about: a
    bit-flipped AEAD cell passes ``PRAGMA quick_check`` and every row count, so without this pass a full
    verify would report PASS on an archive whose bodies no longer decrypt. Each value is opened with the
    same cell-bound AAD the store writes (ASVS 11.3.3), so a ciphertext moved between cells fails its tag
    here exactly as it would at a live read.

    The cell list is the store's own ``MessageStore._CIPHER_COLUMNS`` — what the store declares
    encrypted-at-rest — rather than a list invented here, so a column added to the cipher's coverage is
    covered by this pass without a second edit. Its cipher-covered tables whose AAD binds to a
    composite/natural key (``response``, ``state``, ``reference``, ``shared_body``, ``attachment_chunk``,
    ``message_events``, ``connection_event``, ``alert_instance``) are NOT in that tuple and are therefore
    out of scope here: each is a bespoke pass inside the store rather than data any caller can read.
    Widening this means giving the store one declaration to publish, not copying its private passes into
    this module."""
    import sqlite3

    cipher = build_store_cipher(settings)
    cells = 0
    conn = sqlite3.connect(f"file:{snap}?mode=ro", uri=True)
    try:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for table, column in MessageStore._CIPHER_COLUMNS:
            if table not in tables:
                continue  # an older snapshot predating the table — not a verify failure
            names = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}  # constant table
            if column not in names or "id" not in names:
                continue
            # table/column are constants from _CIPHER_COLUMNS; only the marker prefix is a parameter.
            rows = conn.execute(
                f"SELECT id, {column} FROM {table} WHERE {column} LIKE ?", (f"{MARKER_PREFIX}%",)
            )
            for row_id, stored in rows:
                try:
                    plain = cipher.decrypt(str(stored), aad=cell_aad(table, column, row_id))
                except CipherError as exc:
                    # FAIL, not KEY_MISMATCH: CipherError cannot separate a corrupted ciphertext from a
                    # key that was never supplied, and the keyring here is not empty (the keyless case
                    # is the branch below). Reporting the softer verdict on a bit-flipped PHI cell is
                    # the reading that must not be talked down.
                    return (
                        "FAIL",
                        f"{table}.{column} id={row_id} did not decrypt: {safe_exc(exc)}",
                        cells,
                    )
                if cipher.is_encrypted(plain):
                    # The identity cipher hands an mfenc: value straight back (the #241 F2 keyless-open
                    # trap): the snapshot holds sealed cells and this open resolved no key for them.
                    # Nothing could have opened them, so the keyring is unambiguously the cause.
                    return (
                        "KEY_MISMATCH",
                        f"{table}.{column} is encrypted at rest but the store settings resolved no key "
                        "to open it (keyless open of an encrypted snapshot)",
                        cells,
                    )
                cells += 1
    except sqlite3.Error as exc:
        return "FAIL", safe_exc(exc), cells
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
    try:
        obj = json.loads(data)
    except ValueError as exc:
        # `ValueError` is the common base of both parse-side failures; naming only
        # `JSONDecodeError` would let the not-UTF-8 case through.
        raise tarfile.TarError(f"archive {_MANIFEST_MEMBER} could not be parsed: {exc}") from exc
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

    ``secure`` locks the output file to its owner with the store's own primitive the moment it exists,
    BEFORE the first byte is streamed into it. The restore path passes it: its staging directory sits
    on the destination volume, where ``TemporaryDirectory`` inherits whatever the parent grants on
    Windows, and the file is the whole decrypted store. Securing it after the stream, the way
    :func:`_place_restored_store` secures the file it publishes, would leave a multi-GB write of PHI
    under the inherited ACL for as long as the write takes. The verify path leaves it off and keeps the
    posture ``docs/PHI.md`` records for ``mefor-verify-*``.

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
        if member.size > max_member_bytes:
            raise tarfile.TarError(
                f"archive member exceeds the restore extract cap ({max_member_bytes} bytes)"
            )
        src = tar.extractfile(member)
        if src is None:
            return None
        streamed = 0
        with open(out, "wb") as fh:
            if secure:
                # Reuse the store's own PHI-at-rest primitive, on the empty file, before any of the
                # member's bytes reach it.
                from messagefoundry.store.store import _secure_file

                _secure_file(out)
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
    dest_store_path: str | Path,
    store_settings: object,
    config_dest: str | Path | None = None,
) -> RestoreResult:
    """Restore a ``.mfbak`` archive's store member to ``dest_store_path`` (ADR 0049's missing half; the
    primitive ADR 0048's cold seed consumes).

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

    **There is deliberately no ``allow_unencrypted`` here**, unlike :func:`run_restore_verify`. The
    downgrade guard stays at its strictest on the one path that writes bytes to disk. It carried such a
    parameter and nothing ever set it: the CLI documented in a comment that it withheld it on purpose,
    so the refusal's own remedy (*"set [backup].allow_unencrypted"*) named a setting this path does not
    read — a prescription an operator would have followed to no effect. The parameter is gone and the
    refusal now says the true thing: a plaintext archive restores only on a box with no store key."""
    import base64

    keys = [
        base64.b64decode(k)
        for k in resolve_decrypt_keys(store_settings)  # type: ignore[arg-type]
    ]
    return await asyncio.to_thread(
        _restore_blocking,
        archive_path=archive_path,
        dest_store_path=Path(dest_store_path),
        config_dest=Path(config_dest) if config_dest is not None else None,
        keys=keys,
    )


def _restore_blocking(
    *,
    archive_path: str,
    dest_store_path: Path,
    config_dest: Path | None,
    keys: list[bytes],
) -> RestoreResult:
    """The off-loop half of :func:`run_restore`: refuse -> decrypt -> extract -> verify -> place. Raises
    :class:`BackupError` with the failing ``kind`` (``archive``/``destination``/``verify``/``restore``,
    and ``cleanup`` for the one failure that follows a whole restore -- see below).

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
    store and bundle intact."""
    from messagefoundry.store.store import _secure_file

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

    dest_store_path.parent.mkdir(parents=True, exist_ok=True)
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
        # Stage on the DESTINATION volume, not the system temp dir: the extracted store is then placed
        # by a hard link rather than a second multi-GB copy, and the decrypted PHI never lands on a
        # shared temp volume that may be less protected than the store's own.
        #
        # "Less protected than the store's own" is a claim about the VOLUME, and it does not carry to
        # the files. `TemporaryDirectory` restricts the directory on POSIX, and on Windows under Python
        # 3.13+ writes its own protected DACL (SYSTEM, Administrators, OWNER RIGHTS -- measured on
        # 3.14.6) rather than inheriting the parent's. The two files staged inside it are the whole
        # decrypted archive and the whole store -- both full-body PHI at rest (docs/PHI.md section 3).
        # So each is locked to its owner with the store's own primitive the moment it exists and
        # before its first byte is written. Best-effort and non-fatal, per that primitive's contract.
        # The file `_place_restored_store` PUBLISHES gets the store-trio rule instead (ADR 0183 Wave 0b).
        # archive.tar and extracted_store.db keep what `_secure_file` leaves, which is NOT owner-only when
        # a file carries the temp directory's entries explicitly (it removes inherited entries only;
        # measured on the hosted runners, CI run 36039014999). A hard-linked placement then shares the
        # published DACL. A follow-up recorded in ADR 0163.
        with tempfile.TemporaryDirectory(
            prefix="mefor-restore-", dir=dest_store_path.parent
        ) as tmp:
            staging = Path(tmp)
            tar_path = staging / "archive.tar"
            with open(archive_path, "rb") as src, open(tar_path, "wb") as dst:
                _secure_file(tar_path)
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
                            src, dst, match_key, max_plaintext_bytes=_MAX_RESTORE_PLAINTEXT_BYTES
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
            if manifest.get("config_only"):
                raise BackupError(
                    "restore",
                    "this is a CONFIG-ONLY archive (a server-DB store's backup is DBA-delegated, "
                    "BACKLOG #52) — it carries no store to restore; restore the database from the "
                    "DBA's own backup and use --config-to for the config bundle",
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
        if not completed:
            raise
        # Only the staging directory's teardown runs after `completed`, so an OSError here IS that
        # teardown failing (on Windows, a scanner or the indexer still holding the extracted store
        # open). The store and bundle are intact; what is left is the plaintext staging directory,
        # which its own remover just failed to delete. A BackupError, so the CLI prints a refusal
        # line rather than a traceback, and a kind of its own, so the line does not read as the
        # restore having failed. The `finally` below sees `completed` and leaves the restore alone.
        bundle = f", and the config bundle at {config_dest}" if config_dest is not None else ""
        raise BackupError(
            "cleanup",
            f"the restore completed, but its staging directory {staging} could not be removed: "
            f"{safe_exc(exc)}. Intact: the restored store at {dest_store_path}{bundle}. The staging "
            "directory still holds the decrypted archive and store: delete it by hand once nothing "
            "holds it open. Do not re-run the restore; the destination is now in use.",
        ) from exc
    finally:
        if published and not completed:
            _discard_partial_restore(dest_store_path, config_written)

    return RestoreResult(
        archive_path=archive_path,
        store_path=str(dest_store_path),
        store_bytes=store_bytes,
        row_counts=row_counts,
        encrypted=encrypted,
        key_id=key_id,
        config_dir=str(config_dest) if config_dest is not None else None,
        config_files=config_files,
    )


def _discard_partial_restore(dest_store_path: Path, written: list[Path]) -> None:
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
    itself is never in the ledger (see :func:`_restore_config_members`). A directory this restore
    created is removed only while empty; one that gained a stranger's file since is kept and logged.

    Best-effort by construction. It runs while an exception is already propagating, so a cleanup error
    must never replace the failure the operator needs to read -- it is logged and swallowed. A restore
    that could not clean up is a worse report, not a different outcome."""
    try:
        dest_store_path.unlink(missing_ok=True)
    except OSError as exc:
        log.warning("could not remove the partially restored store at %s: %s", dest_store_path, exc)
    for path in reversed(written):
        try:
            if path.is_dir() and not path.is_symlink():
                path.rmdir()  # a directory this restore created, and only while it is empty
            else:
                path.unlink(missing_ok=True)
        except OSError as exc:
            log.warning("could not remove the partially restored config member %s: %s", path, exc)


def _verify_extracted_store(snap: Path, manifest: dict[str, object]) -> dict[str, int]:
    """``integrity_check`` + the manifest row-count compare on the extracted ``store.db``, run on the
    exact file about to be placed. Same two checks (and the same helpers) as
    :func:`_verify_archive_blocking` steps 3-4; returns the counts for the restore summary.

    The compare is keyed off the MANIFEST's own keys rather than dict equality, for the reason
    :func:`_verify_archive_blocking` gives at its step 4: :func:`_count_tables` derives its table set
    from the snapshot's own ``sqlite_master`` (BACKLOG #1722), so a manifest written before that set
    was widened records fewer tables than the archive really has. Restoring an archive taken by an
    EARLIER build is the ordinary case for this subcommand, so dict equality would refuse on sight the
    archives a restore exists to accept. A table the manifest tracked that the snapshot's schema lacks
    reads as 0, so a manifest count of 0 still passes and a nonzero one still raises: real data loss is
    still caught. A table the snapshot has that the manifest never tracked is not compared at all."""
    integrity_ok, integrity_msg = _integrity_check(snap)
    if not integrity_ok:
        raise BackupError("verify", f"the archive's store failed integrity_check: {integrity_msg}")
    row_counts = _count_tables(snap)
    raw_counts = manifest.get("row_counts")
    manifest_counts = (
        {str(k): int(v) for k, v in raw_counts.items()} if isinstance(raw_counts, dict) else {}
    )
    mismatches = sorted(
        table for table in manifest_counts if row_counts.get(table, 0) != manifest_counts[table]
    )
    if mismatches:
        raise BackupError(
            "verify",
            f"row-count mismatch on {mismatches} (a torn or truncated snapshot): "
            f"snapshot={row_counts} manifest={manifest_counts}",
        )
    return row_counts


def _refuse_existing_destination(dest_store_path: Path, config_dest: Path | None) -> None:
    """Refuse every destination that already holds something, BEFORE any decrypt work. Restoring over a
    live store is unrecoverable and a CLI cannot ask for permission, so the answer is no and the message
    names the path the operator must move or choose differently.

    The last arm refuses a pair of destinations that are individually empty and still collide, because
    this restore writes BOTH of them: see :func:`_refuse_config_dest_under_the_store`. Its mirror image
    needs the archive's member list and so runs later, in :func:`_refuse_colliding_config_members`."""
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
    exclusive create in :func:`_restore_config_members` is the backstop under this, not the control."""
    published = {
        _norm_for_compare(p)
        for p in (
            dest_store_path,
            *(dest_store_path.with_name(dest_store_path.name + s) for s in _SIDECAR_SUFFIXES),
        )
    }
    try:
        with tarfile.open(tar_path, "r:") as tar:
            for member in tar.getmembers():
                if not member.isfile() or not member.name.startswith(_CONFIG_PREFIX):
                    continue
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
    import shutil

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
    """Extract the archive's ``config/`` members into ``config_dest`` and return how many files landed.

    ``written`` is the caller's ledger of what this call created -- every directory it made under
    ``config_dest`` and every file it opened, each appended BEFORE any bytes land in it and in creation
    order, so :func:`_discard_partial_restore` can walk it backwards. ``config_dest`` itself is never
    recorded: an absent one is re-created by a retry, and one the operator prepared may carry ACLs
    worth more than the tidiness of deleting it. A file the exclusive create refused is not recorded
    either, because it is not this call's to remove.

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

    An archive with no config member is a REFUSAL, not a quiet empty directory — see :func:`run_restore`.
    """
    from messagefoundry.parsing.sniff import archive_member_name_reason
    from messagefoundry.store.store import _secure_file

    config_dest.mkdir(parents=True, exist_ok=True)
    root = config_dest.resolve()
    landed = 0
    total = 0
    with tarfile.open(tar_path, "r:") as tar:
        for member in tar.getmembers():
            if not member.isfile() or not member.name.startswith(_CONFIG_PREFIX):
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
            if member.size > _MAX_RESTORE_MEMBER_BYTES:
                raise BackupError(
                    "restore",
                    f"config member exceeds the restore extract cap ({_MAX_RESTORE_MEMBER_BYTES} bytes)",
                )
            src = tar.extractfile(member)
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
    if landed == 0:
        raise BackupError(
            "restore",
            "the archive carries no config bundle, so there is nothing for --config-to to restore "
            "(the backup was taken with [backup].include_config=false, or with no config dir loaded)",
        )
    return landed
