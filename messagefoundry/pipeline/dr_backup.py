# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Turnkey DR backup: scheduled + on-demand config + SQLite-store backup (ADR 0049, #60).

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
from messagefoundry.pipeline.alerts import AlertSink, LoggingAlertSink
from messagefoundry.pipeline.cluster import ClusterCoordinator, NullCoordinator
from messagefoundry.redaction import safe_exc
from messagefoundry.store import MessageStore, Store
from messagefoundry.store.backup_codec import (
    FORMAT_VERSION,
    BackupCodecError,
    BackupKeyMismatch,
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
    "VerifyResult",
    "BackupError",
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
#: **POST-AUTHENTICATION, and it must not be described as anything else.** Every byte counted here has
#: already passed its AES-GCM frame tag. The pre-authentication bounds are ``MAX_HEADER_BYTES``, the
#: declared ``chunk_size`` against ``MAX_CHUNK_SIZE``, and the per-frame ``ctlen`` — all in the codec,
#: all checked before the read they drive. This is a RESOURCE bound against an archive sealed under a
#: key the site legitimately holds: an oversized one, or one a key-holder crafted. It defends nothing
#: against an unauthenticated attacker, who cannot get a frame past its tag to be counted at all.
#:
#: **Why the per-member cap does not already cover this.** :func:`_extract_member` bounds ``store.db``
#: so a lying header or stream cannot exhaust the extract temp dir — but it runs on ``archive.tar``,
#: which the decrypt has already written to that same temp dir in full. So the member cap is reached
#: only after the disk it protects is spent. This moves the bound to the first write.
#:
#: **Why twice the member cap, and why a multiple rather than a literal.** A conforming archive is one
#: ``store.db`` — admitted up to :data:`_MAX_RESTORE_MEMBER_BYTES`, above which the verify FAILs at the
#: member cap anyway — plus the config bundle, the manifest and tar framing. So the cumulative ceiling
#: cannot sit AT the member cap without refusing a store snapshot that is itself legal, and nothing on
#: this branch bounds the config bundle, so there is no exact second term to add. Rather than fork a
#: second number, the remainder gets the ceiling the store gets: one whole extra maximal snapshot of
#: headroom, which no real config dir (a few Python modules, a TOML, some codesets) approaches.
#: Written as a multiple so it TRACKS the member cap: a literal would silently begin false-refusing
#: legal archives the day that cap was raised.
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
            if manifest_counts and row_counts != manifest_counts:
                return VerifyResult(
                    "FAIL",
                    integrity_ok=True,
                    row_counts=row_counts,
                    manifest_counts=manifest_counts,
                    reason=f"row-count mismatch: snapshot={row_counts} manifest={manifest_counts}",
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
    except (OSError, tarfile.TarError, json.JSONDecodeError) as exc:
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
    (``messages``/``queue``/``message_events``/``audit_log``) let a truncated or absent ``users``,
    ``state``, ``reference``, ``response``, ``attachment_chunk`` or ``search_presets`` table pass
    restore-verify PASS undetected — the row-count compare simply never looked at it. Called once
    against the just-taken snapshot when the manifest is written and once against the restored
    snapshot at verify time; both reads are against the identical file (the ``.mfbak`` codec is
    authenticated encryption, not a transform), so an untampered archive always compares equal
    regardless of which tables are in scope, and a widened scope only ever ADDS coverage.

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
        ok, msg = asyncio.run(_open())
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
    with tarfile.open(tar_path, "r:") as tar:
        info = tar.getmember(_MANIFEST_MEMBER)  # KeyError when absent, as before
        if info.size > _MAX_MANIFEST_BYTES:
            raise tarfile.TarError(
                f"archive manifest exceeds the read cap ({_MAX_MANIFEST_BYTES} bytes)"
            )
        member = tar.extractfile(info)
        if member is None:
            return {}
        data = member.read(_MAX_MANIFEST_BYTES + 1)
        if len(data) > _MAX_MANIFEST_BYTES:
            raise tarfile.TarError(
                f"archive manifest stream exceeds the read cap ({_MAX_MANIFEST_BYTES} bytes)"
            )
    obj = json.loads(data)
    return obj if isinstance(obj, dict) else {}


def _extract_member(
    tar_path: Path,
    name: str,
    dest_dir: Path,
    *,
    max_member_bytes: int = _MAX_RESTORE_MEMBER_BYTES,
) -> Path | None:
    """Extract a single archive member to ``dest_dir`` and return its path, or ``None`` when absent.

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
