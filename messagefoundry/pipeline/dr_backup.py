# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Turnkey DR backup: scheduled + on-demand config + SQLite-store backup (ADR 0049, #60).

:class:`BackupRunner` is a sibling of the :class:`~messagefoundry.pipeline.retention.RetentionRunner`:
a **leader-gated, daily-clock** background singleton that, on its schedule (and on demand via the
``messagefoundry backup`` CLI), takes a **consistent SQLite snapshot** (read-only against the live
store — it never claims/mutates/resets/completes a staged-queue row), bundles a copy of the loaded
config dir, encrypts the whole thing to a single ``.mfbak`` AES-256-GCM archive **keyed by the existing
store DEK** (ADR 0019 KeyProvider), writes it to a configured **local/UNC** destination (no cloud
target), applies keep-N retention, runs a **lightweight restore-verify** (open + ``integrity_check`` +
row-count), and records **one PHI-free ``dr_backup`` audit row** per run. On failure it raises
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

from messagefoundry.config.settings import BackupSettings, StoreBackend
from messagefoundry.pipeline.alerts import AlertSink, LoggingAlertSink
from messagefoundry.pipeline.cluster import ClusterCoordinator, NullCoordinator
from messagefoundry.redaction import safe_exc
from messagefoundry.store import Store
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
    resolve_active_key,
    resolve_decrypt_keys,
)

__all__ = [
    "BackupRunner",
    "BackupResult",
    "VerifyResult",
    "BackupError",
    "run_restore_verify",
]

log = logging.getLogger(__name__)

#: Tables whose row counts are recorded in the manifest + re-checked by the restore-verify (a truncated
#: snapshot the integrity check misses at the logical level shows up as a row-count mismatch). These
#: exist on every SQLite store schema (messages + the staged queue + the audit chain).
_VERIFY_TABLES = ("messages", "queue", "message_events", "audit_log")

#: Archive members inside the encrypted tar.
_STORE_MEMBER = "store.db"
_CONFIG_PREFIX = "config/"
_MANIFEST_MEMBER = "manifest.json"


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
            try:
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
        try:
            await asyncio.wait_for(self._stop.wait(), delay)
        except asyncio.TimeoutError:
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
        """Run a single backup pass: snapshot → bundle → encrypt → write → verify → prune → audit.

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

        ext = ".mfbak" if key is not None else ".mfbak.plain"
        stamp = _utc_stamp(now)
        inst = _safe_segment(self._instance) or "instance"
        archive_path = dest_dir / f"mefor-backup-{inst}-{stamp}{ext}"
        if (
            archive_path.exists()
        ):  # extremely unlikely (1s granularity) — never clobber a prior archive
            raise BackupError("write", f"archive already exists: {archive_path}")

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
                    archive_path=archive_path,
                    snap_path=snap_path,
                    key=key,
                    key_id=key_id,
                    config_only=config_only,
                    now=now,
                )
            except (OSError, BackupCodecError) as exc:
                kind = "write" if isinstance(exc, OSError) else "encrypt"
                raise BackupError(kind, safe_exc(exc)) from exc

        verify: VerifyResult | None = None
        if s.verify_after_backup:
            # The just-written archive is sealed under the active key, so the active key is the only
            # candidate the post-write verify needs (the retired-key keyring matters only for the
            # standalone restore-verify of an OLDER archive — run_restore_verify, AC-5).
            verify = await asyncio.to_thread(
                _verify_archive_blocking,
                archive_path=str(archive_path),
                keys=[key] if key is not None else [],
                full=s.full_restore_verify,
            )
            if not verify.ok:
                # A verify FAIL means the archive is unusable — but it must NOT be counted as the latest
                # good backup when pruning (so a failing backup never evicts the last good one, AC-6). We
                # leave the (bad) archive on disk for diagnosis and skip the prune, then fail loudly.
                raise BackupError(
                    "verify",
                    f"restore-verify {verify.status}: {verify.reason or 'archive did not verify'}",
                )

        # keep-N prune runs only AFTER a verified-good archive, so the new good one is never the thing
        # pruned and a verify-failed archive is never the "latest good" anchor (AC-6).
        pruned = self._prune_keep_n(dest_dir, inst, ext)

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

    # --- archive build (worker thread; no event loop, no store await) --------

    def _build_archive_blocking(
        self,
        *,
        archive_path: Path,
        snap_path: Path | None,
        key: bytes | None,
        key_id: str | None,
        config_only: bool,
        now: float,
    ) -> tuple[str, dict[str, int], int]:
        """tar(store.db + config/ + manifest.json) → stream-encrypt to ``archive_path``. Runs entirely
        OFF the event loop (the consistent snapshot at ``snap_path`` was already taken on the loop by the
        caller). Returns ``(snapshot_sha256, row_counts, archive_bytes)``. The tar goes to a temp file
        (not RAM) so a multi-GB store never sits in memory; the codec then streams it to the archive."""
        snapshot_sha256 = ""
        row_counts: dict[str, int] = {}
        if snap_path is not None:
            snapshot_sha256 = _sha256_file(snap_path)
            row_counts = _count_tables(snap_path, _VERIFY_TABLES)

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

            archive_path.parent.mkdir(parents=True, exist_ok=True)
            with open(tar_path, "rb") as src, open(archive_path, "wb") as dst:
                if key is not None:
                    encrypt_stream(src, dst, key)
                else:
                    # No key + allow_unencrypted: write the plaintext tar verbatim (synthetic/no-PHI box).
                    while True:
                        buf = src.read(1024 * 1024)
                        if not buf:
                            break
                        dst.write(buf)
                dst.flush()
                os.fsync(dst.fileno())
        archive_bytes = archive_path.stat().st_size
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

    def _prune_keep_n(self, dest_dir: Path, inst: str, ext: str) -> int:
        """Delete this instance's archives beyond the newest ``retention_keep`` at the destination.
        ``0`` = keep all. Only archives this runner writes (same instance prefix + extension) are
        candidates, so an operator's unrelated files at the destination are never touched. The just-
        written verified-good archive is the newest, so it is always within the kept set."""
        keep = self._settings.retention_keep
        if keep <= 0:
            return 0
        prefix = f"mefor-backup-{inst}-"
        # Anchor the glob to the EXACT _utc_stamp shape (YYYYMMDDThhmmssZ) + extension, not a loose
        # f"{prefix}*{ext}". A loose `*` would also match a stray diagnostic like
        # `mefor-backup-dev-<stamp>.corrupt.mfbak` (the `*` spans the `.corrupt`), so a left-behind
        # verify-failed file could be counted toward keep-N and evict a good archive. The anchored
        # pattern matches only the canonical archives this runner writes.
        pattern = f"{prefix}????????T??????Z{ext}"
        archives = sorted(
            (p for p in dest_dir.glob(pattern) if p.is_file()),
            key=lambda p: p.name,  # name carries a UTC timestamp → lexical sort == chronological
            reverse=True,
        )
        pruned = 0
        for stale in archives[keep:]:
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


def _verify_archive_blocking(*, archive_path: str, keys: list[bytes], full: bool) -> VerifyResult:
    """Lightweight (or full) restore-verify of a ``.mfbak`` archive — runs OFF the event loop.

    ``keys`` is the decrypt-capable keyring (active + retired, ADR 0049 AC-5 "incl. retired keys") — the
    archive is matched against the whole set so one taken under a now-retired key still verifies after a
    rotation; an empty list means "no key configured" (only valid for a plaintext archive).

    Steps (ADR 0049): (1) key-fingerprint precheck — a mismatch is a clean ``KEY_MISMATCH`` BEFORE any
    decrypt; (2) decrypt the archive; (3) extract + open ``store.db`` read-only, run
    ``PRAGMA integrity_check``; (4) compare per-table row counts to the manifest. ``full`` additionally
    re-opens the snapshot through the real ``open_store`` path (cipher + migrations) — heavier."""
    try:
        # (1) Pre-decryption key check (only meaningful for an encrypted archive). For a plaintext
        # archive (no codec header) there is no key to mismatch.
        match_key: bytes | None = None
        encrypted = _looks_encrypted(archive_path)
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
                    decrypt_stream(src, dst, match_key)
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
            row_counts = _count_tables(snap, _VERIFY_TABLES)
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
            if full:
                # The heavier end-to-end restore: open the snapshot through the real open_store path
                # (cipher + migrations) to prove it restores, then discard it.
                full_ok, full_msg = _full_open_check(snap)
                if not full_ok:
                    return VerifyResult(
                        "FAIL",
                        integrity_ok=True,
                        row_counts=row_counts,
                        manifest_counts=manifest_counts,
                        reason=f"full restore-open failed: {full_msg}",
                    )
            return VerifyResult(
                "PASS",
                integrity_ok=True,
                row_counts=row_counts,
                manifest_counts=manifest_counts,
            )
    except BackupKeyMismatch as exc:
        return VerifyResult("KEY_MISMATCH", reason=safe_exc(exc))
    except BackupCodecError as exc:
        return VerifyResult("FAIL", reason=f"decrypt failed: {safe_exc(exc)}")
    except (OSError, tarfile.TarError, json.JSONDecodeError) as exc:
        return VerifyResult("FAIL", reason=safe_exc(exc))


async def run_restore_verify(
    archive_path: str, *, store_settings: object, full: bool = False
) -> VerifyResult:
    """Verify an existing ``.mfbak`` archive WITHOUT activating it (ADR 0049 — 0049's owned primitive,
    which ADR 0048's cold-seed activation *calls*). Resolves the store's decrypt-capable keyring (active
    + retired, AC-5 "incl. retired keys"), runs the key-fingerprint precheck → decrypt → integrity_check
    → row-count compare, and returns a structured ``PASS``/``FAIL``/``KEY_MISMATCH``
    :class:`VerifyResult`. All heavy work runs off the event loop."""
    import base64

    # The decrypt-capable keyring, NOT just the active key: a backup taken under a key that has since
    # been retired (a routine WP-5 rotation) must still verify, or ADR 0048's cold-seed activation would
    # falsely refuse a perfectly recoverable archive (AC-5: compare to the resolved key, incl. retired).
    keys = [
        base64.b64decode(k)
        for k in resolve_decrypt_keys(store_settings)  # type: ignore[arg-type]
    ]
    return await asyncio.to_thread(
        _verify_archive_blocking, archive_path=archive_path, keys=keys, full=full
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


def _count_tables(db_path: Path, tables: tuple[str, ...]) -> dict[str, int]:
    """Per-table row counts on a snapshot file via a plain read-only sqlite3 connection (no engine
    store). A table absent from the schema is reported as 0 rather than raising."""
    import sqlite3

    counts: dict[str, int] = {}
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for table in tables:
            if table not in names:
                counts[table] = 0
                continue
            (n,) = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()  # table is a constant
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


def _full_open_check(snap: Path) -> tuple[bool, str]:
    """Open the snapshot through the real ``open_store`` path (cipher + migrations) on a copy, to prove
    an end-to-end restore. Heavier; only run for ``full_restore_verify``."""
    from messagefoundry.config.settings import StoreSettings
    from messagefoundry.store.base import open_store

    async def _open() -> tuple[bool, str]:
        store = await open_store(StoreSettings(path=str(snap)))
        try:
            ok, msg = await store.integrity_check()
            return ok, msg
        finally:
            await store.close()

    try:
        return asyncio.run(_open())
    except Exception as exc:  # a restore that won't even open is the thing we're trying to catch
        return False, safe_exc(exc)


def _read_manifest_from_tar(tar_path: Path) -> dict[str, object]:
    with tarfile.open(tar_path, "r") as tar:
        member = tar.extractfile(_MANIFEST_MEMBER)
        if member is None:
            return {}
        data = member.read()
    obj = json.loads(data)
    return obj if isinstance(obj, dict) else {}


def _extract_member(tar_path: Path, name: str, dest_dir: Path) -> Path | None:
    """Extract a single archive member to ``dest_dir`` and return its path, or ``None`` when absent.

    Path-traversal-safe by construction, NOT by an after-the-fact check: the member's *stored name* is
    never used as a filesystem path — we look the member up by name, then stream its CONTENT to a fixed
    output path (``dest_dir/extracted_store.db``). So a tampered tar whose member name is
    ``../../etc/passwd`` cannot escape ``dest_dir`` (the classic tar-extract CVE), because we never call
    ``tar.extract``/``extractall`` with the member's path. Keep it that way: if a future change extracts
    by the member's own name, add an explicit ``resolved.is_relative_to(dest_dir)`` guard first."""
    out = (dest_dir / "extracted_store.db").resolve()
    with tarfile.open(tar_path, "r") as tar:
        try:
            member = tar.getmember(name)
        except KeyError:
            return None
        src = tar.extractfile(member)
        if src is None:
            return None
        with open(out, "wb") as fh:
            while True:
                buf = src.read(1024 * 1024)
                if not buf:
                    break
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
