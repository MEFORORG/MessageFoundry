# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The engine: owns the store and supervises the code-first :class:`RegistryRunner`.

This is the object the API layer (and tests) drive. It opens the durable store, recovers
any deliveries left ``inflight`` by a previous crash, and runs the wired Connection/Router/
Handler graph.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from messagefoundry.config.models import (
    AckAfter,
    BuildupThreshold,
    InternalErrorPolicy,
    OrderingMode,
    RetryPolicy,
)
from messagefoundry.config.settings import (
    CertMonitorSettings,
    ClusterSettings,
    EgressSettings,
    ReferenceSettings,
    RetentionSettings,
    ShadowSettings,
)
from messagefoundry.config.wiring import Registry, WiringError, load_config
from messagefoundry.pipeline.alerts import AlertSink
from messagefoundry.pipeline.cert_expiry import CertExpiryRunner, MonitoredCert, certs_from_registry
from messagefoundry.pipeline.cluster import ClusterCoordinator, NullCoordinator
from messagefoundry.pipeline.config_convergence import ConfigConvergenceRunner
from messagefoundry.pipeline.leader_tasks import LeaderMaintenanceRunner
from messagefoundry.pipeline.reference_sync import ReferenceSyncRunner
from messagefoundry.pipeline.retention import RetentionRunner
from messagefoundry.pipeline.state_convergence import StateConvergenceRunner
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStore, Store

__all__ = ["Engine", "ConfigReloadDenied"]

log = logging.getLogger(__name__)


class ConfigReloadDenied(Exception):
    """A /config/reload target resolved outside the allowed reload roots (RCE guard).

    The API maps this to 403. Because the loader executes Python from the target directory, a
    reload may only load from the server's startup ``--config`` dir or an explicitly configured
    ``config_reload_roots`` entry — never an arbitrary client-supplied path."""


def _within(path: Path, root: Path) -> bool:
    """True if ``path`` is ``root`` itself or nested under it (both already resolved)."""
    return path == root or root in path.parents


class Engine:
    def __init__(
        self,
        store: Store,
        *,
        poll_interval: float = 0.25,
        max_correlation_depth: int = 8,
        config_dir: str | Path | None = None,
        config_reload_roots: Sequence[str | Path] = (),
        inbound_bind_host: str = "127.0.0.1",
        allow_insecure_bind: bool = False,
        delivery_defaults: RetryPolicy | None = None,
        ordering_default: OrderingMode | None = None,
        internal_error_default: InternalErrorPolicy | None = None,
        buildup_default: BuildupThreshold | None = None,
        ack_after_default: AckAfter | None = None,
        alert_sink: AlertSink | None = None,
        retention_settings: RetentionSettings | None = None,
        cert_monitor_settings: CertMonitorSettings | None = None,
        api_tls_cert_file: str | None = None,
        reference_settings: ReferenceSettings | None = None,
        egress_settings: EgressSettings | None = None,
        shadow_settings: ShadowSettings | None = None,
        active_environment: str | None = None,
        env_values: Mapping[str, Any] | None = None,
        env_values_provider: Callable[[], Mapping[str, Any]] | None = None,
        coordinator: ClusterCoordinator | None = None,
        cluster_settings: ClusterSettings | None = None,
    ) -> None:
        self.store = store
        # Cluster coordination seam (Track B Step 3). None → the no-op NullCoordinator, so single-node
        # (SQLite and single-node Postgres) is byte-identical: is_leader() is always True and
        # start()/stop() do nothing. A DbCoordinator (built by build_coordinator on an enabled [cluster]
        # Postgres store) registers the node + heartbeats and (Step 4) elects a leader for active-passive
        # HA — exactly one node drains the graph. Threaded into every runner this engine builds.
        self._coordinator: ClusterCoordinator = coordinator or NullCoordinator()
        # [cluster] knobs (Track B Step 4). Only reclaim_interval_seconds is read here (the cadence of
        # the leader's lease-reclaim sweep); the rest drive build_coordinator upstream. None → the
        # ClusterSettings() defaults, which is fine because the leader sweep only spawns when the
        # coordinator reclaims inflight rows (i.e. a DbCoordinator), never for the single-node default.
        self._cluster_settings = cluster_settings or ClusterSettings()
        self._leader_maintenance: LeaderMaintenanceRunner | None = None
        # Config-reload convergence (Track B Step 6). Spawned ONLY in clustered mode (is_clustered()),
        # so single-node never pays for it. _applied_config_version is the shared config version this
        # node has applied; seeded at start() to the coordinator's current version (so a fresh node
        # doesn't self-reload) and advanced when this node bumps (operator reload) or converges (follower
        # reload). The node that bumps advances it itself, so its own convergence loop sees no change.
        self._config_convergence: ConfigConvergenceRunner | None = None
        self._applied_config_version: int = 0
        # Transform-state read-through convergence (Track B Step 6b). Spawned ONLY in clustered mode
        # (is_clustered()), so single-node never pays for it. Each tick it read-throughs any namespace a
        # sibling node wrote/purged into this node's local _state_cache (off the hot path, so state_get
        # stays a pure sync dict lookup). Mirrors _config_convergence's lifecycle.
        self._state_convergence: StateConvergenceRunner | None = None
        # The active environment name ([ai].environment / serve --env), passed to every runner this
        # engine builds so a Handler's current_environment() resolves to it (per-face transform logic).
        self._active_environment = active_environment
        self._poll_interval = poll_interval
        # [pipeline] re-ingress loop-prevention cap (ADR 0013 Increment 2); every runner inherits it.
        self._max_correlation_depth = max_correlation_depth
        # Where the runner reports operational alerts; None → the runner's default logging sink.
        self._alert_sink = alert_sink
        # [retention] enforcement. None (embedding/tests) → no retention task; the runner itself is a
        # no-op when nothing is configured, so passing default settings is also safe.
        self._retention_settings = retention_settings
        self._retention_runner: RetentionRunner | None = None
        # [cert_monitor] TLS-cert expiry monitor (Q5c). None (embedding/tests) → no monitor task. The
        # set of certs to watch is derived at scan time from the [api] TLS cert + the wired graph's MLLP
        # certs (read live, so a reload that adds/removes a TLS connection is picked up).
        self._cert_monitor_settings = cert_monitor_settings
        self._api_tls_cert_file = api_tls_cert_file
        self._cert_expiry_runner: CertExpiryRunner | None = None
        # [reference] enforcement (ADR 0006). None (embedding/tests) → default settings; the reference
        # sync runner is a no-op when the graph declares no reference sets.
        self._reference_settings = reference_settings
        self._reference_runner: ReferenceSyncRunner | None = None
        # Fail-closed outbound destination allowlist (WP-11c); passed to every runner this engine builds
        # (and the reload dry-run checker), so a denied destination is refused at start + on reload.
        self._egress_settings = egress_settings
        # [shadow] parallel-run egress suppression (#15); simulate_all_egress is threaded into every
        # runner this engine builds so a shadow instance suppresses all delivery. None → defaults (off).
        self._shadow_settings = shadow_settings or ShadowSettings()
        # The interface inbound listeners bind to; every runner this engine builds inherits it.
        self._inbound_bind_host = inbound_bind_host
        # The serve --allow-insecure-bind dev escape; every runner inherits it for the §0 exposed-gate.
        self._allow_insecure_bind = allow_insecure_bind
        # Global [delivery] defaults (retry + ordering + internal-error action + buildup thresholds);
        # every runner inherits them. A connection's own retry=/ordering=/internal_error=/buildup= wins.
        self._delivery_defaults = delivery_defaults
        self._ordering_default = ordering_default
        self._internal_error_default = internal_error_default
        self._buildup_default = buildup_default
        # Global [inbound] ACK-timing default (ADR 0001); every runner inherits it.
        self._ack_after_default = ack_after_default
        # This instance's environment values (DEV/PROD), shared with every runner the engine builds —
        # so env() references in a reloaded graph resolve against THIS environment (and a missing
        # value is refused here, on this engine, not on the box the graph was authored on). The
        # optional provider is re-invoked on each reload so a promote picks up edited values files
        # without a restart (review M-23); without it the values are static (embedding/tests).
        self._env_values_provider = env_values_provider
        initial = env_values_provider() if env_values_provider is not None else env_values
        self._env_values: dict[str, Any] = dict(initial or {})
        self._registry_runner: RegistryRunner | None = None
        # Active-passive graph supervisor (Workstream A1). In CLUSTERED mode the wired graph (listeners
        # + workers) runs ONLY while this node holds leadership: this task polls leadership and
        # starts/stops the graph on acquire/lose, so a standby stays warm without binding listeners or
        # processing. NEVER spawned single-node (NullCoordinator is always leader, so the graph is
        # brought up directly at start() — byte-identical). The lock serializes reconciles; the event
        # stops the loop. NOTE the hard guarantee against concurrent double-processing of any given row
        # is NOT this gate — it is the store's per-row leases (a standby's reclaim only takes EXPIRED
        # leases, so it can never claim a row the old leader still holds; Track B Step 2). This gate
        # promptly stops a demoted/fenced node from accepting NEW inbound work and initiating NEW
        # processing; the poll interval is bounded (at start()) to keep that stop prompt.
        self._graph_supervisor: asyncio.Task[None] | None = None
        self._graph_stop = asyncio.Event()
        self._graph_lock = asyncio.Lock()
        self._graph_reconcile_interval = 1.0
        # Set when start() runs; the "since" for since-engine-start metric counts.
        self.started_at: float = 0.0
        # The startup config dir is the default reload target and an implicit allowed root.
        self.config_dir: Path | None = Path(config_dir).resolve() if config_dir else None
        roots = [Path(r).resolve() for r in config_reload_roots]
        if self.config_dir is not None:
            roots.append(self.config_dir)
        # Empty => unconstrained (embedding/tests). The served path always sets config_dir.
        self._reload_roots: tuple[Path, ...] = tuple(dict.fromkeys(roots))
        # The directory the most recent reload loaded from (resolved) — for audit by the API.
        self.last_reload_dir: Path | None = None

    @classmethod
    async def create(
        cls,
        db_path: str | Path,
        *,
        poll_interval: float = 0.25,
        max_correlation_depth: int = 8,
        synchronous: str = "NORMAL",
        config_dir: str | Path | None = None,
        config_reload_roots: Sequence[str | Path] = (),
        inbound_bind_host: str = "127.0.0.1",
        allow_insecure_bind: bool = False,
        delivery_defaults: RetryPolicy | None = None,
        ordering_default: OrderingMode | None = None,
        internal_error_default: InternalErrorPolicy | None = None,
        buildup_default: BuildupThreshold | None = None,
        ack_after_default: AckAfter | None = None,
        alert_sink: AlertSink | None = None,
        retention_settings: RetentionSettings | None = None,
        cert_monitor_settings: CertMonitorSettings | None = None,
        api_tls_cert_file: str | None = None,
        reference_settings: ReferenceSettings | None = None,
        egress_settings: EgressSettings | None = None,
        shadow_settings: ShadowSettings | None = None,
        active_environment: str | None = None,
        env_values: Mapping[str, Any] | None = None,
        env_values_provider: Callable[[], Mapping[str, Any]] | None = None,
        coordinator: ClusterCoordinator | None = None,
        cluster_settings: ClusterSettings | None = None,
    ) -> "Engine":
        """Open a SQLite-backed engine from a path (convenience for tests/embedding). The service
        path goes through :func:`~messagefoundry.store.open_store` (backend-agnostic). The SQLite
        convenience path leaves ``coordinator`` unset → the no-op :class:`NullCoordinator`
        (single-node), so it is byte-identical to before this seam."""
        store = await MessageStore.open(db_path, synchronous=synchronous)
        return cls(
            store,
            poll_interval=poll_interval,
            max_correlation_depth=max_correlation_depth,
            config_dir=config_dir,
            config_reload_roots=config_reload_roots,
            inbound_bind_host=inbound_bind_host,
            allow_insecure_bind=allow_insecure_bind,
            delivery_defaults=delivery_defaults,
            ordering_default=ordering_default,
            internal_error_default=internal_error_default,
            buildup_default=buildup_default,
            ack_after_default=ack_after_default,
            alert_sink=alert_sink,
            retention_settings=retention_settings,
            cert_monitor_settings=cert_monitor_settings,
            api_tls_cert_file=api_tls_cert_file,
            reference_settings=reference_settings,
            egress_settings=egress_settings,
            shadow_settings=shadow_settings,
            active_environment=active_environment,
            env_values=env_values,
            env_values_provider=env_values_provider,
            coordinator=coordinator,
            cluster_settings=cluster_settings,
        )

    # --- code-first wiring ---------------------------------------------------

    def add_registry(self, registry: Registry) -> RegistryRunner:
        """Run a code-first Connection/Router/Handler graph (one runner for the whole graph)."""
        runner = RegistryRunner(
            registry,
            self.store,
            poll_interval=self._poll_interval,
            inbound_bind_host=self._inbound_bind_host,
            allow_insecure_bind=self._allow_insecure_bind,
            delivery_defaults=self._delivery_defaults,
            ordering_default=self._ordering_default,
            internal_error_default=self._internal_error_default,
            buildup_default=self._buildup_default,
            ack_after_default=self._ack_after_default,
            alert_sink=self._alert_sink,
            egress=self._egress_settings,
            simulate_all=self._shadow_settings.simulate_all_egress,
            env_values=self._env_values,
            active_environment=self._active_environment,
            coordinator=self._coordinator,
            max_correlation_depth=self._max_correlation_depth,
        )
        self._registry_runner = runner
        return runner

    @property
    def registry_runner(self) -> RegistryRunner | None:
        return self._registry_runner

    def _monitored_certs(self) -> list[MonitoredCert]:
        """The TLS certs the engine serves with right now: the ``[api]`` cert + the wired graph's MLLP
        ``tls_cert_file`` certs (read live off the registry, so a config reload is reflected). Passed to
        the :class:`CertExpiryRunner` as its cert source so each scan reflects the current graph."""
        registry = self._registry_runner.registry if self._registry_runner is not None else None
        return certs_from_registry(registry, self._api_tls_cert_file)

    @property
    def coordinator(self) -> ClusterCoordinator:
        """The cluster coordinator (NullCoordinator single-node, DbCoordinator clustered) — Track B
        Step 7. A public accessor so the observability API reads membership/leadership through the
        contract instead of reaching the private ``_coordinator`` attribute."""
        return self._coordinator

    # --- reference sets (ADR 0006) -------------------------------------------

    def _make_reference_runner(self) -> ReferenceSyncRunner:
        """Build the reference sync runner; its specs are read **live** from the current registry, so a
        reload's swapped declarations are picked up without rebuilding it."""
        return ReferenceSyncRunner(
            self.store,
            lambda: (
                self._registry_runner.registry.references.values()
                if self._registry_runner is not None
                else []
            ),
            self._reference_settings or ReferenceSettings(),
            env_values=self._env_values,
            egress=self._egress_settings,
            alert_sink=self._alert_sink,
            # Track B Step 6: gate materialize-from-source on the leader; every node still converges its
            # read cache from the shared snapshot. NullCoordinator (single-node) is always leader, so
            # this materializes from source every pass exactly as before.
            coordinator=self._coordinator,
        )

    async def _reconcile_reference_sync(self, *, startup: bool) -> None:
        """Ensure the reference runner exists, materialize the declared sets, and (re-)arm the loop.

        Called at :meth:`start` and after every successful :meth:`reload`, so: a set added by a reload
        materializes **immediately** (not only on the next refresh tick), a graph that goes from zero
        reference sets to ≥1 across a reload actually starts the loop, and an engine started without a
        graph then loaded via reload still gets a runner. ``start()`` is idempotent (a no-op when the
        loop is already up). The pre-sync runs on a reload unconditionally (so a new set resolves on the
        next message); at startup it honors ``[reference].sync_on_startup``. A sync failure is isolated
        per-set (last-good kept) and never blocks start/reload."""
        if self._reference_runner is None:
            self._reference_runner = self._make_reference_runner()
        if not startup or (self._reference_settings or ReferenceSettings()).sync_on_startup:
            await self._reference_runner.sync_all()
        self._reference_runner.start()

    # --- lifecycle -----------------------------------------------------------

    async def start(self) -> None:
        """Recover crashed in-flight rows (every stage), dead-letter outbound rows for removed
        outbounds, then start the wired graph."""
        self.started_at = time.time()
        # All-stages recovery: returns any row a crash left `inflight` — ingress rows mid-route and
        # outbound rows mid-delivery alike — to `pending` so the staged workers re-claim them
        # (staged pipeline, ADR 0001). The handoff/delivery transactions make the re-run idempotent.
        if not self._coordinator.reclaims_inflight():
            # Single-node (SQLite / single-node Postgres): the unconditional reset is immediate self-
            # recovery of this node's own crash residue — today's behavior, byte-identical.
            await self.store.reset_stale_inflight()
        # else clustered (Track B Step 4): the leader's periodic reclaim_expired_leases sweep (started
        # below) recovers expired-lease rows; the unconditional reset ignores leases and would steal a
        # live sibling's in-flight rows, so it must NOT run here.
        # Bring cluster membership + leader election up BEFORE the workers run, so the node's heartbeat
        # is registered and leadership is contended the moment it starts processing (Track B Step 3/4).
        # NullCoordinator (the single-node default) is a no-op here, so this line is free for SQLite /
        # single-node Postgres.
        await self._coordinator.start()
        # Track B Step 6b: in a cluster, turn ON the store's per-namespace state-version bumping BEFORE the
        # workers (hence transform_handoff) start, so the very first state write bumps and a sibling's
        # convergence loop can see it. Single-node (NullCoordinator, is_clustered() False) never calls this,
        # so no state_version rows are written and the backend stays byte-identical.
        if self._coordinator.is_clustered():
            self.store.enable_state_convergence()
        if self._registry_runner is not None:
            # Fail loud (not at the first received message) if the configured store can't run the
            # staged ingress pipeline: the inbound path unconditionally calls store.enqueue_ingress,
            # so a backend whose enqueue_ingress/handoff is a NotImplementedError stub (SQL Server,
            # gated on BACKLOG #1) would otherwise wedge every inbound at runtime with no ACK/NAK. This
            # check fails loud on EVERY node (leader or standby) — a misconfigured backend should refuse
            # at startup, not only when this node is promoted.
            if not getattr(self.store, "supports_ingest_stage", True):
                raise RuntimeError(
                    "the configured store backend does not support the staged ingress pipeline "
                    "(ADR 0001 Step A is SQLite-only; SQL Server staging is gated on BACKLOG #1) — "
                    "use the sqlite backend"
                )
            if not self._coordinator.is_clustered():
                # SINGLE-NODE (NullCoordinator, always leader): bring the graph up now, exactly as
                # before — byte-identical. The config-drift sweeps + reference materialize + listener
                # bring-up live in _start_graph (shared with the clustered leader path).
                await self._start_graph()
            else:
                # CLUSTERED (active-passive, Workstream A1): the graph runs ONLY on the leader, so do
                # NOT bring it up here — the graph supervisor (spawned at the end of start()) starts it
                # when this node acquires leadership and stops it on loss. A standby stays warm without
                # binding listeners or running workers. Start the reference-sync loop on EVERY node now
                # so a follower converges its read cache from the leader's snapshot (the leader also
                # materializes before listeners in _start_graph). Idempotent: _start_graph re-ensures it.
                if self._reference_runner is None:
                    self._reference_runner = self._make_reference_runner()
                self._reference_runner.start()
        # Retention/purge is independent of the message graph (a store-level maintenance task), so it
        # runs whether or not a graph is wired and survives config reloads. The runner is a no-op when
        # nothing is configured, so this only spawns a task when [retention] is actually set. It is a
        # leader-only WRITE singleton (purges bodies + writes audit rows), so it is gated on the
        # coordinator: in a cluster a follower's runner ticks but no-ops; single-node always leads.
        if self._retention_settings is not None:
            self._retention_runner = RetentionRunner(
                self.store,
                self._retention_settings,
                alert_sink=self._alert_sink,
                coordinator=self._coordinator,
            )
            self._retention_runner.start()
        # [cert_monitor] TLS-cert expiry monitor (Q5c) — a maintenance task like retention, independent
        # of the message graph and surviving reloads; a no-op when warn_days=0. NOT leader-gated: certs
        # are node-local files, so each node alerts on its own (the per-cert realert throttle bounds
        # spam). The served-cert set is recomputed each scan from the live registry + [api] cert.
        if self._cert_monitor_settings is not None:
            self._cert_expiry_runner = CertExpiryRunner(
                self._monitored_certs,
                self._cert_monitor_settings,
                alert_sink=self._alert_sink,
            )
            self._cert_expiry_runner.start()
        # Leader lease-reclaim sweep (Track B Step 4) — only in clustered mode (reclaims_inflight()),
        # so single-node / SQLite never spawns it. It is itself leader-gated each pass, so a follower's
        # runner ticks but no-ops; the current leader recovers crashed nodes' expired-lease rows.
        if self._coordinator.reclaims_inflight() and hasattr(self.store, "reclaim_expired_leases"):
            # Postgres active-passive: the leader's per-row lease reclaim recovers a crashed/fenced prior
            # leader's EXPIRED-lease rows (the standby never claims while a live leader holds the lease).
            self._leader_maintenance = LeaderMaintenanceRunner(
                self.store,  # type: ignore[arg-type]  # reclaim_expired_leases guarded above (Postgres)
                self._coordinator,
                interval_seconds=self._cluster_settings.reclaim_interval_seconds,
            )
            self._leader_maintenance.start()
        # else (SQL Server active-passive): no per-row leases, so there is no reclaim sweep — failover
        # recovery is the on-promotion reset_stale_inflight in _start_graph (the old leader self-fenced
        # before its lease expired, so re-pending its in-flight rows can't steal from a live processor).
        # Config-reload convergence (Track B Step 6) — only in clustered mode (is_clustered()), so
        # single-node / SQLite never spawns it. Seed the applied version to the coordinator's CURRENT
        # shared version BEFORE the loop starts, so a fresh node does not immediately self-reload (it is
        # already in sync with whatever reloads happened before it joined); then poll the cached version
        # each tick and reload this node's own config dir when it falls behind.
        if self._coordinator.is_clustered():
            self._applied_config_version = await self._coordinator.config_version()
            self._config_convergence = ConfigConvergenceRunner(
                self._coordinator,
                applied_version=lambda: self._applied_config_version,
                set_applied_version=self._set_applied_config_version,
                reload=self._converge_reload,
                interval_seconds=self._cluster_settings.heartbeat_seconds,
            )
            self._config_convergence.start()
            # Transform-state read-through convergence (Track B Step 6b) — each tick read-throughs any
            # namespace a sibling wrote/purged into this node's local _state_cache. Reuses the cluster
            # heartbeat interval (owner decision) and the same alert sink as the rest of the engine.
            self._state_convergence = StateConvergenceRunner(
                converge=self.store.converge_state_cache,
                interval_seconds=self._cluster_settings.heartbeat_seconds,
                alert_sink=self._alert_sink,
            )
            self._state_convergence.start()
        # Active-passive graph supervisor (Workstream A1) — spawned LAST (after _leader_maintenance
        # exists, so the on-promotion reclaim can fire) and ONLY in clustered mode with a wired graph.
        # It polls leadership and starts/stops the graph so only the leader binds listeners + runs
        # workers. The poll interval is kept short (relative to the fence/TTL margin) so a demoted/fenced
        # node stops accepting + initiating new work promptly; concurrent double-processing of a given
        # row is independently prevented by the store's per-row leases (see __init__). Single-node
        # never spawns it (the graph is already running, brought up directly above).
        if self._coordinator.is_clustered() and self._registry_runner is not None:
            ttl = self._cluster_settings.leader_lease_ttl_seconds
            fence = self._cluster_settings.leader_fence_timeout_seconds
            # Stay comfortably inside the (ttl - fence) margin and never slower than ~1s.
            self._graph_reconcile_interval = max(0.1, min(1.0, (ttl - fence) / 3.0))
            self._graph_stop.clear()
            # Reconcile ONCE synchronously before the loop: if this node is already the leader (it
            # acquired the lease on coordinator.start()'s first tick, or in tests a stand-in reports
            # leader immediately), the graph comes up during start() rather than a poll-interval later.
            # A real DbCoordinator is usually not-yet-leader here (the lease is acquired asynchronously),
            # so this is a no-op and the supervisor brings the graph up on promotion.
            await self._reconcile_graph()
            self._graph_supervisor = asyncio.create_task(self._graph_supervisor_loop())

    # --- active-passive graph gating (Workstream A1/A3/A4) -------------------

    async def _start_graph(self) -> None:
        """Bring the wired graph up: (A4) recover the prior leader's stranded in-flight rows + lane
        leases on promotion, (A3) dead-letter rows whose outbound/handler left the config, materialize
        reference sets, then start the listeners + workers. In a cluster this runs ONLY on the leader and
        is (re)invoked on each leadership acquire; single-node runs it once at startup. Idempotent
        against the runner's own ``running`` guard."""
        if self._registry_runner is None:
            return
        # A4 — on promotion (clustered Postgres), recover the prior leader's stranded in-flight rows
        # IMMEDIATELY (owner-scoped, lease-blind), instead of waiting out the ~[store].lease_ttl_seconds
        # per-row lease TTL — which was the dominant failover-recovery delay (#293: ~60s on PG vs ~7s on
        # SQL Server). This brings Postgres to parity with the SQL Server reset_stale_inflight path; the
        # periodic, lease-GATED sweep keeps running in the background (recovers a crashed prior leader's
        # expired-lease residue / tolerates clock skew). Single-node has no leader maintenance
        # (_leader_maintenance is None), and its own crash residue was already recovered by the
        # unconditional reset_stale_inflight in start().
        if self._leader_maintenance is not None:
            await self._leader_maintenance.recover_on_promotion()
        elif self._coordinator.is_clustered():
            # Active-passive without per-row leases (SQL Server): on promotion, re-pend the prior
            # leader's in-flight rows. The prior leader self-fenced and its leadership lease EXPIRED
            # before this node could acquire it, so it has stopped processing — and the graph runs ONLY
            # on the leader, so there is no live sibling whose rows an unconditional reset could steal.
            # (Single-node NullCoordinator is_clustered() is False, so this never runs there; its boot
            # residue was already recovered by the unconditional reset_stale_inflight in start().)
            await self.store.reset_stale_inflight()
        # A3 — dead-letter OUTBOUND/ROUTED rows whose destination/handler left the config (no worker
        # would ever drain them). Now part of graph bring-up, so in a cluster ONLY the leader (the one
        # node that runs the graph) sweeps — a restarting standby never dead-letters the primary's
        # in-flight rows (the hazard the old unconditional placement carried). Single-node is unchanged
        # (it always runs the graph). Keyed off THIS node's registry, so clustered nodes must still run
        # identical config (a coordinated, not rolling, restart for config changes).
        await self.store.dead_letter_missing_destinations(
            set(self._registry_runner.registry.outbound)
        )
        await self.store.dead_letter_missing_handlers(set(self._registry_runner.registry.handlers))
        # Reference sets (ADR 0006): materialize declared sets BEFORE listeners accept (a transform's
        # reference(...) resolves on the first message), then keep the periodic loop running (idempotent
        # — already started on every node in start() for clustered followers to converge). Leader-gated
        # materialize inside the runner; a sync failure is isolated per-set and never blocks intake.
        await self._reconcile_reference_sync(startup=True)
        await self._registry_runner.start()
        log.info("engine graph started — this node is processing")

    async def _stop_graph(self) -> None:
        """Tear the graph down on loss of leadership: stop the listeners + workers so a demoted node
        stops binding/processing. The reference-sync loop and the self-gated maintenance/convergence
        loops keep running (a follower still converges its caches), so only the runner is stopped."""
        if self._registry_runner is not None:
            await self._registry_runner.stop()
        log.info("engine graph stopped — this node is now standby")

    async def _reconcile_graph(self) -> None:
        """Align the running graph with this node's leadership: start it on becoming leader, stop it on
        losing leadership. Serialized by ``_graph_lock`` so overlapping triggers can't double act."""
        if self._registry_runner is None:
            return
        async with self._graph_lock:
            running = self._registry_runner.running
            if self._coordinator.is_leader() and not running:
                await self._start_graph()
                # Leadership can be lost DURING the (potentially slow) bring-up — a fence mid-start. If
                # so, tear straight back down within the same lock so a demoted node never keeps the
                # graph running for a whole extra poll cycle.
                if not self._coordinator.is_leader():
                    await self._stop_graph()
            elif not self._coordinator.is_leader() and running:
                await self._stop_graph()

    async def _graph_supervisor_loop(self) -> None:
        """Active-passive graph supervisor (Workstream A1): poll leadership and start/stop the graph so
        only the leader binds listeners + runs workers. Polled at ``_graph_reconcile_interval`` (kept
        short so a demotion/fence promptly stops this node accepting + initiating new work; the row/lane
        leases independently prevent concurrent double-processing of a given row). Clustered only;
        cooperatively stopped via ``_graph_stop`` (the loop wakes on it and exits between reconciles)."""
        while not self._graph_stop.is_set():
            try:
                await self._reconcile_graph()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("engine graph supervisor reconcile failed; will retry")
            try:
                await asyncio.wait_for(
                    self._graph_stop.wait(), timeout=self._graph_reconcile_interval
                )
            except asyncio.TimeoutError:
                pass

    def _set_applied_config_version(self, version: int) -> None:
        """Setter the convergence runner calls after a successful follower reload (Track B Step 6)."""
        self._applied_config_version = version

    async def _converge_reload(self) -> None:
        """Re-read THIS node's own startup config dir to converge on a cluster reload (Track B Step 6).

        Non-propagating (``propagate=False``): this is convergence, not initiation, so it must NOT bump
        the shared version token again (or nodes would chase each other's reloads). Passing ``None``
        reloads the startup ``--config`` dir."""
        await self.reload(propagate=False)

    async def reload(
        self,
        config_dir: str | Path | None = None,
        *,
        dry_run: bool = False,
        propagate: bool = False,
    ) -> Registry:
        """Load the code-first graph from ``config_dir`` and apply it to the running engine.

        ``config_dir`` defaults to the server's startup ``--config`` dir. Any explicit value must
        resolve **within** an allowed reload root (the startup dir + ``config_reload_roots``);
        otherwise :class:`ConfigReloadDenied` is raised — the loader executes Python, so an
        arbitrary client path must never be honoured. The resolved directory is recorded on
        :attr:`last_reload_dir` for auditing.

        Validates first (a bad config raises before anything is swapped, so the running graph is
        left untouched), then atomically swaps via the runner's quiesce-and-swap reload. If the
        engine was started without a graph, this loads and starts one. Returns the new Registry.

        ``dry_run`` performs the full validation **against this instance's environment** — it loads
        the graph and build-checks every connector, which resolves the graph's ``env()`` references
        against *this* engine's values, so a key the target environment doesn't define fails here —
        then returns **without swapping** the live graph. This is the promote pre-flight: it answers
        "will this graph go live cleanly on THIS environment?" without touching running traffic.

        ``propagate`` (Track B Step 6): on a SUCCESSFUL non-dry-run apply in a clustered deployment,
        bump the shared ``cluster_config`` version token so every OTHER node's convergence loop reloads
        its own (identically-deployed) config dir. The OPERATOR-initiated path (``/config/reload``)
        passes ``propagate=True``; the per-node convergence reload passes ``False`` (convergence, not
        initiation — bumping there would make nodes chase each other). A dry_run never bumps, and
        single-node (``is_clustered()`` False) never bumps. The initiator advances its OWN applied
        version right after bumping, so its convergence loop sees no change and does not re-reload.

        Raises ``ConfigReloadDenied`` (path outside the allowed roots), ``FileNotFoundError``
        (missing dir) or ``WiringError`` (invalid / empty config / unresolved env value) — the
        caller maps these to HTTP errors.
        """
        path = self._resolve_reload_target(config_dir)
        self.last_reload_dir = path
        if not path.is_dir():
            raise FileNotFoundError(f"config directory not found: {config_dir}")
        # Re-gather this environment's values so a reload/promote picks up edited environments/<env>.toml
        # (or MEFOR_VALUE_* changes) without a restart — otherwise the WiringError telling the operator
        # to add a missing value would never clear (review M-23).
        if self._env_values_provider is not None:
            self._env_values = dict(self._env_values_provider())
            if self._registry_runner is not None:
                self._registry_runner.set_env_values(self._env_values)
        # Off the event loop: load_config executes user config modules (arbitrary, potentially heavy
        # imports), which would otherwise stall every listener mid-reload (review low-3).
        registry = await asyncio.to_thread(load_config, path)  # raises WiringError on a bad config
        if not registry.inbound and not registry.outbound:
            raise WiringError(
                f"config directory {config_dir!r} declares no connections — "
                "refusing to reload to an empty graph"
            )
        runner = self._registry_runner
        if dry_run:
            # Validate against THIS environment without swapping: build-check every connector (which
            # resolves env() refs against this instance's values and raises on a missing key or bad
            # spec), then discard. Reuse the live runner if present; else a throwaway one carrying the
            # same bind host + env values, so the check sees exactly what a real reload would.
            checker = runner or RegistryRunner(
                registry,
                self.store,
                poll_interval=self._poll_interval,
                inbound_bind_host=self._inbound_bind_host,
                delivery_defaults=self._delivery_defaults,
                ordering_default=self._ordering_default,
                internal_error_default=self._internal_error_default,
                buildup_default=self._buildup_default,
                ack_after_default=self._ack_after_default,
                alert_sink=self._alert_sink,
                egress=self._egress_settings,
                simulate_all=self._shadow_settings.simulate_all_egress,
                env_values=self._env_values,
                coordinator=self._coordinator,
            )
            checker.build_check(registry)
            return registry
        if runner is None:
            runner = self.add_registry(registry)
            try:
                runner.build_check(registry)  # bad connector → WiringError (422), before any start
                await runner.start()
            except Exception:
                # Don't leave a half-started runner: a later reload would take the "runner exists"
                # path and no-op the start, wedging intake. Clear it so a retry re-enters cleanly.
                self._registry_runner = None
                raise
        else:
            await runner.reload(registry)
        # Reference sets (ADR 0006): re-arm + materialize after the swap, so a reference set added by
        # this reload syncs immediately (resolves on the next message, not only after the refresh
        # interval) and a 0->N change actually starts the loop. Idempotent when nothing changed.
        await self._reconcile_reference_sync(startup=False)
        # Config-reload convergence (Track B Step 6): only the OPERATOR-initiated path propagates. Bump
        # the shared version so other nodes converge, and advance THIS node's applied version to the new
        # value so its own convergence loop sees no change (feedback-avoidance — the initiator does not
        # re-reload). A no-op on single-node (is_clustered() False). The per-node convergence reload
        # passes propagate=False and so never bumps (it would otherwise make nodes chase each other).
        if propagate and self._coordinator.is_clustered():
            self._applied_config_version = await self._coordinator.bump_config_version()
        return registry

    def _resolve_reload_target(self, config_dir: str | Path | None) -> Path:
        """Resolve the reload target and enforce the allow-list (see :class:`ConfigReloadDenied`)."""
        if config_dir is None:
            if self.config_dir is None:
                raise WiringError("no config directory configured; pass one to reload")
            return self.config_dir
        path = Path(config_dir).resolve()
        if self._reload_roots and not any(_within(path, root) for root in self._reload_roots):
            # Don't echo the rejected path back to the client (info disclosure); log it server-side.
            log.warning("rejected /config/reload outside allowed roots: %s", path)
            raise ConfigReloadDenied("config directory is not an allowed reload root")
        return path

    async def replay(self, message_id: str) -> int:
        """Re-queue every delivery for a message and wake the delivery workers."""
        requeued = await self.store.replay(message_id)
        if self._registry_runner is not None and self._registry_runner.running:
            self._registry_runner.notify_work()
        return requeued

    async def replay_dead(
        self, *, channel_id: str | None = None, destination_name: str | None = None
    ) -> int:
        """Re-queue dead-lettered deliveries (optionally scoped) and wake the delivery workers."""
        requeued = await self.store.replay_dead(
            channel_id=channel_id, destination_name=destination_name
        )
        if requeued and self._registry_runner is not None and self._registry_runner.running:
            self._registry_runner.notify_work()
        return requeued

    async def stop(self) -> None:
        """Stop the retention task + the wired graph, then close the store."""
        log.info("engine stopping")
        # Quiesce the active-passive graph supervisor FIRST (Workstream A1) so it can't reconcile (and
        # re-start the graph) while we tear down. A no-op single-node (never spawned). Cooperative: set
        # the stop event and let any in-flight reconcile finish under the lock (so we never abandon a
        # half-started graph), falling back to cancel only if a reconcile hangs past the timeout. The
        # graph itself is then stopped by the registry_runner.stop() below, as before.
        if self._graph_supervisor is not None:
            self._graph_stop.set()
            supervisor = self._graph_supervisor
            self._graph_supervisor = None
            try:
                await asyncio.wait_for(supervisor, timeout=10.0)
            except asyncio.TimeoutError:
                # wait_for already cancelled the task on timeout; absorb its cancellation.
                await asyncio.gather(supervisor, return_exceptions=True)
        if self._retention_runner is not None:
            await self._retention_runner.stop()
        if self._cert_expiry_runner is not None:
            await self._cert_expiry_runner.stop()
        # Stop the leader sweep before deregistering membership (it consults the coordinator's gate, so
        # it must quiesce while the coordinator is still up). A no-op when single-node (never spawned).
        if self._leader_maintenance is not None:
            await self._leader_maintenance.stop()
        # Stop the config-convergence loop before the coordinator (it polls the coordinator's cached
        # version). A no-op when single-node (never spawned).
        if self._config_convergence is not None:
            await self._config_convergence.stop()
        # Stop the transform-state convergence loop before the coordinator/pool tear down (it polls the
        # store). A no-op when single-node (never spawned). (Track B Step 6b.)
        if self._state_convergence is not None:
            await self._state_convergence.stop()
            self._state_convergence = None
        if self._reference_runner is not None:
            await self._reference_runner.stop()
        if self._registry_runner is not None:
            await self._registry_runner.stop()
        # Deregister cluster membership after the runner has quiesced but before the store closes (the
        # coordinator marks its node left over the same pool). stop() is idempotent and safe even if
        # start() raised (then there's just nothing to cancel). NullCoordinator is a no-op.
        await self._coordinator.stop()
        await self.store.close()
