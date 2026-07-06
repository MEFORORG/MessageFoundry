# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Materializes reference sets off the message path (ADR 0006 Tier 1).

The :class:`ReferenceSyncRunner` is a supervised background loop (modelled on
:class:`~messagefoundry.pipeline.retention.RetentionRunner`) that, for each declared
:class:`~messagefoundry.config.wiring.ReferenceSpec`, periodically loads the external dataset from its
source and writes it into the store as a new versioned, encrypted snapshot
(:meth:`~messagefoundry.store.base.QueueStore.write_reference_snapshot`, build-new-then-atomic-flip).
A Handler then reads the snapshot **purely** via ``reference("name").get(key)`` — no per-message
external call, so the at-least-once re-run invariant holds by construction (ADR 0006).

Tier 1 ships the **file** source (a local CSV/TOML the engine re-reads on cadence — the path for an
externally-produced export). The **database** source (the engine querying SQL Server directly) is
ADR-0006 increment 2.

**Clustered (Track B Step 6).** Each pass splits in two: materialize-from-source runs **only on the
leader** (gated on the coordinator's ``is_leader()``), and — **only when clustered** — every node then
calls :meth:`~messagefoundry.store.base.QueueStore.converge_reference_cache` to read-through any newer
shared snapshot the leader wrote into its own in-process cache. So the external source is read once
(by the leader) and followers converge by reading the shared store — no N-fold source load, no stale
follower caches. Single-node is byte-identical: :class:`NullCoordinator` is always leader (so it
materializes from source every pass exactly as before) and reports ``is_clustered()`` ``False``, so the
convergence call is skipped entirely (not just a returns-``[]`` no-op) and no extra DB read happens per
pass.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from messagefoundry.config.code_sets import CodeSetError, load_code_set
from messagefoundry.config.settings import EgressSettings, ReferenceSettings
from messagefoundry.config.wiring import ReferenceSpec, resolve_env_settings
from messagefoundry.pipeline.alerts import AlertSink, LoggingAlertSink
from messagefoundry.pipeline.cluster import ClusterCoordinator, NullCoordinator
from messagefoundry.store import Store

__all__ = ["ReferenceSyncRunner", "ReferenceSyncError"]

log = logging.getLogger(__name__)


class ReferenceSyncError(RuntimeError):
    """A reference set's source could not be materialized (bad source kind, missing file, parse error)."""


def _egress_allows(host: str, port: object, allowed: list[str]) -> bool:
    """host[:port] membership in an ``[egress]`` allowlist entry (``"host"`` = any port, or ``"host:port"``).

    Same matching as the connector egress gate; reimplemented here (a few lines) to avoid importing a
    private symbol from the runner."""
    host = host.lower()
    for entry in allowed:
        allow_host, _, allow_port = entry.partition(":")
        if allow_host.strip().lower() == host and (
            not allow_port or str(port) == allow_port.strip()
        ):
            return True
    return False


@dataclass(frozen=True)
class _SyncPass:
    """What one :meth:`ReferenceSyncRunner.run_once` pass did."""

    synced: int  # sets re-materialized from source this pass (leader only)
    failed: int  # sets whose source failed (last-good snapshot kept)
    converged: int = (
        0  # sets a follower read-through'd from a newer shared snapshot (Track B Step 6)
    )

    @property
    def did_work(self) -> bool:
        return self.synced > 0 or self.failed > 0 or self.converged > 0


def _load_file_source(settings: Mapping[str, Any]) -> dict[str, Any]:
    """Load a file-backed reference source into a ``{key: value}`` dict (reuses the code-set loaders).

    ``settings`` is the resolved (env-substituted) ``FileRef`` settings: ``path`` (.csv/.toml, the
    code-set format) + ``encoding`` (currently informational — the loaders read utf-8)."""
    path = settings.get("path")
    if not path:
        raise ReferenceSyncError("file reference source requires a 'path'")
    try:
        return dict(load_code_set(path))  # CSV/TOML parse + dup-key check, shared with code sets
    except CodeSetError as exc:
        raise ReferenceSyncError(f"file reference source {path!r}: {exc}") from exc


def _cell(value: Any) -> Any:
    """Coerce a DB cell to a JSON-storable value (the snapshot value is ``json.dumps``'d at rest)."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    from messagefoundry.transports.database import _json_default  # lazy: avoids aioodbc import

    return _json_default(value)  # date/Decimal/bytes -> iso/str/base64


async def _load_database_source(
    settings: Mapping[str, Any], egress: EgressSettings | None
) -> dict[str, Any]:
    """Materialize a SQL-backed reference source (ADR 0006 increment 2) into ``{key: value}``.

    Runs the operator's read-only ``statement``; ``key_column`` is the key; ``value_column`` (if set)
    is the value, else the value is a dict of the other columns. The dial-out is gated by the
    fail-closed ``[egress].allowed_db`` allowlist (like a DATABASE poll source). Reuses
    ``transports/database.py`` for the DSN/pool (the SQL-Server ``[sqlserver]`` extra)."""
    from messagefoundry.transports.database import _build_dsn, _make_pool

    server = str(settings.get("server", ""))
    if egress is not None:
        # Under deny-by-default an empty allowed_db refuses the dial-out outright (parity with the
        # DATABASE source / db_lookup gates in wiring_runner.py — this is the one dial-out path that
        # otherwise ignored the flag).
        if egress.deny_by_default and not egress.allowed_db:
            raise ReferenceSyncError(
                "DATABASE reference source: [egress].deny_by_default is set and [egress].allowed_db "
                "is empty — list the reference server to permit it"
            )
        if egress.allowed_db and not _egress_allows(
            server, settings.get("port", 1433), egress.allowed_db
        ):
            raise ReferenceSyncError(
                f"DATABASE reference server {server!r} is not in the [egress].allowed_db allowlist"
            )
    key_col = settings.get("key_column")
    value_col = settings.get("value_column")
    statement = str(settings.get("statement", ""))
    if not key_col or not statement:
        raise ReferenceSyncError("DATABASE reference source requires 'statement' and 'key_column'")
    dsn = _build_dsn(dict(settings))  # fail-loud on weakened TLS / bad auth, before dialing
    pool = await _make_pool(dsn, int(settings.get("pool_max", 5)), autocommit=True)
    try:
        conn = await pool.acquire()
        try:
            cur = await conn.cursor()
            await cur.execute(statement)
            columns = [d[0] for d in cur.description]
            rows = list(await cur.fetchall())
        finally:
            await pool.release(conn)
    finally:
        pool.close()
        await pool.wait_closed()
    if key_col not in columns:
        raise ReferenceSyncError(f"key_column {key_col!r} not in the statement's result columns")
    out: dict[str, Any] = {}
    for row in rows:
        record = dict(zip(columns, row))
        key = str(record[key_col])
        if value_col is not None:
            out[key] = _cell(record.get(value_col))
        else:
            out[key] = {c: _cell(record[c]) for c in columns if c != key_col}
    return out


class ReferenceSyncRunner:
    """Supervises periodic materialization of declared reference sets into store snapshots (ADR 0006).

    ``specs`` is a *provider* (re-read each pass) so a config reload's new declarations are picked up;
    ``env_values`` resolves any :func:`~messagefoundry.config.wiring.env` refs in a source's settings.
    """

    def __init__(
        self,
        store: Store,
        specs: Callable[[], Iterable[ReferenceSpec]],
        settings: ReferenceSettings,
        *,
        env_values: Mapping[str, Any] | None = None,
        egress: EgressSettings | None = None,
        alert_sink: AlertSink | None = None,
        coordinator: ClusterCoordinator | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._store = store
        self._specs = specs
        self._settings = settings
        self._env_values = dict(env_values or {})
        self._egress = egress
        self._alert_sink: AlertSink = alert_sink or LoggingAlertSink()
        # Cluster coordination seam (Track B Step 6). None → the no-op NullCoordinator, whose
        # is_leader() is always True, so single-node materializes from source every pass EXACTLY as
        # before. In a cluster, only the leader materializes from source; every node still converges its
        # local read cache from the shared snapshot (the convergence call is a no-op on single-node).
        self._coordinator: ClusterCoordinator = coordinator or NullCoordinator()
        self._clock = clock
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        # Per-set last successful sync time (single-task state) — drives per-spec refresh cadence.
        self._last_sync: dict[str, float] = {}

    @property
    def enabled(self) -> bool:
        """True when at least one reference set is declared (else :meth:`start` spawns no task)."""
        return any(True for _ in self._specs())

    def start(self) -> None:
        """Spawn the supervised materialization loop (no-op when no reference sets are declared)."""
        if self._task is not None:
            return
        if not self.enabled:
            log.debug("no reference sets declared; reference sync not started")
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._run())
        log.info(
            "reference sync enabled: refresh_interval=%gs", self._settings.refresh_interval_seconds
        )

    async def stop(self) -> None:
        """Signal the loop and await its exit (idempotent)."""
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
        # One isolated pass per interval; a pass error is logged and the loop continues (a sync hiccup
        # must never take the engine down). Cooperatively cancellable via _stop.
        while not self._stop.is_set():
            try:
                await self.run_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("reference sync pass failed; will retry next interval")
            await self._sleep(self._settings.refresh_interval_seconds)

    async def _sleep(self, delay: float) -> None:
        """Sleep up to ``delay``, waking immediately on stop."""
        if delay <= 0:
            delay = 3600.0
        try:
            await asyncio.wait_for(self._stop.wait(), delay)
        except asyncio.TimeoutError:
            pass

    async def sync_all(self, now: float | None = None) -> _SyncPass:
        """Force a sync of **every** declared set regardless of cadence (the startup pass)."""
        return await self.run_once(now=now, force=True)

    async def run_once(self, now: float | None = None, *, force: bool = False) -> _SyncPass:
        """One reference-sync pass: (1) materialize-from-source the due sets ON THE LEADER ONLY, then
        (2) ALWAYS converge this node's read cache from the shared store (Track B Step 6).

        Step (1) materializes each declared set whose refresh is due (or all, if ``force``) by reading
        its external source and writing a new shared snapshot — but only when this node is the leader, so
        in a cluster the source is read once. A follower skips (1). :class:`NullCoordinator` is always
        leader, so single-node materializes from source every pass exactly as before. A set's source
        failure is isolated: logged + alerted and the last-good snapshot kept (the write is simply not
        attempted), so one bad source never blocks the others.

        Step (2) calls :meth:`~messagefoundry.store.base.QueueStore.converge_reference_cache` so a
        follower picks up the leader's just-written snapshot into its own in-process read cache (the
        read-through). It runs **only when clustered** (``coordinator.is_clustered()``): on a single
        node this handle is the sole writer, so its cache is always current and the call is skipped
        entirely — keeping single-node behaviour byte-identical (no extra DB round-trip per pass)."""
        now = self._clock() if now is None else now
        synced = failed = 0
        if self._coordinator.is_leader():
            # LEADER (or single-node): re-read the external source for the due sets and write the
            # shared snapshot. A follower skips this entirely so the source is read once per cluster.
            for spec in self._specs():
                last = self._last_sync.get(spec.name)  # None = never synced -> always due
                if not force and last is not None and (now - last) < spec.refresh_seconds:
                    continue
                try:
                    await self._sync_one(spec)
                    self._last_sync[spec.name] = now
                    synced += 1
                except Exception as exc:  # source failure → keep last-good, alert, continue
                    failed += 1
                    # Log/alert the set name + error CLASS only — never str(exc): a source error (e.g. a
                    # CSV duplicate-key) can embed a reference KEY, which may be PHI for a patient-keyed
                    # set (CLAUDE.md §9 / PHI.md §7 — no PHI in the general log). The operator knows which
                    # set failed and inspects the source themselves (the RetentionRunner "counts/category
                    # only" discipline). Full exception detail is intentionally not surfaced here.
                    kind = type(exc).__name__
                    log.warning(
                        "reference set %r sync failed (keeping last-good): %s", spec.name, kind
                    )
                    self._alert(spec.name, f"source sync failed ({kind})")
        # CLUSTERED ONLY: read-through any newer shared snapshot into the local cache so a follower
        # converges on what the leader materialized. Skipped entirely on a single node (is_clustered()
        # False), where this handle is the SOLE writer of its reference snapshots — so its cache is
        # always current and converge could never find a newer version. That short-circuit keeps
        # single-node Postgres byte-identical (no extra periodic JOIN/decrypt round-trip per pass), not
        # just SQLite/SQL Server (whose converge already returns []). The decrypt-failure isolation here
        # mirrors step (1)'s per-set guard: one un-decryptable set (e.g. a cross-node key mismatch) must
        # not abort the whole pass and the leader's materialization with it.
        refreshed: list[str] = []
        if self._coordinator.is_clustered():
            try:
                refreshed = await self._store.converge_reference_cache()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                # Convergence read/decrypt failed (e.g. a cross-node encryption-key mismatch). Log the
                # error CLASS only (a decrypt failure could carry snapshot bytes / a PHI-bearing key —
                # CLAUDE.md §9) and continue: keep the last-good local cache and retry next interval.
                kind = type(exc).__name__
                log.warning("reference cache convergence failed (keeping current cache): %s", kind)
                self._alert("<converge>", f"cache convergence failed ({kind})")
        if refreshed:
            # Names only (a set name is operator config, not PHI) at INFO so an operator can see a
            # follower converge; never the keys/values (which may be PHI).
            log.info(
                "reference cache converged %d set(s): %s", len(refreshed), ", ".join(refreshed)
            )
        result = _SyncPass(synced=synced, failed=failed, converged=len(refreshed))
        if result.did_work:
            await self._audit(result)
        return result

    async def _sync_one(self, spec: ReferenceSpec) -> None:
        # Resolve env() refs in the source settings against this instance's environment.
        settings = resolve_env_settings(spec.source.settings, self._env_values)
        kind = spec.source.kind
        if kind == "file":
            rows = await asyncio.to_thread(
                _load_file_source, settings
            )  # blocking file I/O off-loop
        elif kind == "database":
            rows = await _load_database_source(settings, self._egress)  # async aioodbc dial
        else:
            raise ReferenceSyncError(
                f"reference set {spec.name!r}: unknown source kind {kind!r} (file, database)"
            )
        # Unique per write regardless of sub-second timing: a uuid suffix on the wall-clock seconds, so
        # two re-materializations of the SAME set inside one second still get DISTINCT versions. A
        # follower's converge compares version strings, so an identical version would make it SKIP a
        # genuine re-materialization and keep stale data (Track B Step 6 correctness). The leading
        # seconds keep versions roughly time-ordered for an operator reading reference_version.
        version = f"v{int(self._clock())}-{uuid4().hex[:8]}"
        await self._store.write_reference_snapshot(name=spec.name, version=version, rows=rows)
        log.info(
            "reference set %r materialized: %d rows (version %s)", spec.name, len(rows), version
        )

    def _alert(self, name: str, detail: str) -> None:
        # The AlertSink has no reference-specific event yet; use connection_stopped as the generic
        # "a named component degraded" signal (never raises — be defensive anyway).
        try:
            self._alert_sink.connection_stopped(f"reference:{name}", detail=detail)
        except Exception:
            log.warning("reference sync alert sink failed", exc_info=True)

    async def _audit(self, result: _SyncPass) -> None:
        detail = json.dumps(
            {"synced": result.synced, "failed": result.failed, "converged": result.converged},
            sort_keys=True,
        )
        await self._store.record_audit("reference_sync", actor="system", detail=detail)
