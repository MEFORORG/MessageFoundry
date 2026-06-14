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
    ClusterSettings,
    EgressSettings,
    ReferenceSettings,
    RetentionSettings,
)
from messagefoundry.config.wiring import Registry, WiringError, load_config
from messagefoundry.pipeline.alerts import AlertSink
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
        config_dir: str | Path | None = None,
        config_reload_roots: Sequence[str | Path] = (),
        inbound_bind_host: str = "127.0.0.1",
        delivery_defaults: RetryPolicy | None = None,
        ordering_default: OrderingMode | None = None,
        internal_error_default: InternalErrorPolicy | None = None,
        buildup_default: BuildupThreshold | None = None,
        ack_after_default: AckAfter | None = None,
        alert_sink: AlertSink | None = None,
        retention_settings: RetentionSettings | None = None,
        reference_settings: ReferenceSettings | None = None,
        egress_settings: EgressSettings | None = None,
        active_environment: str | None = None,
        env_values: Mapping[str, Any] | None = None,
        env_values_provider: Callable[[], Mapping[str, Any]] | None = None,
        coordinator: ClusterCoordinator | None = None,
        cluster_settings: ClusterSettings | None = None,
    ) -> None:
        self.store = store
        # Cluster coordination seam (Track B Step 3). None → the no-op NullCoordinator, so single-node
        # (SQLite and single-node Postgres) is byte-identical: is_leader()/owns_lane() are always True
        # and start()/stop() do nothing. A DbCoordinator (built by build_coordinator on an enabled
        # [cluster] Postgres store) registers the node + heartbeats and (Step 4) elects a leader; its
        # owns_lane() still reports True until Step 5. Threaded into every runner this engine builds.
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
        # Where the runner reports operational alerts; None → the runner's default logging sink.
        self._alert_sink = alert_sink
        # [retention] enforcement. None (embedding/tests) → no retention task; the runner itself is a
        # no-op when nothing is configured, so passing default settings is also safe.
        self._retention_settings = retention_settings
        self._retention_runner: RetentionRunner | None = None
        # [reference] enforcement (ADR 0006). None (embedding/tests) → default settings; the reference
        # sync runner is a no-op when the graph declares no reference sets.
        self._reference_settings = reference_settings
        self._reference_runner: ReferenceSyncRunner | None = None
        # Fail-closed outbound destination allowlist (WP-11c); passed to every runner this engine builds
        # (and the reload dry-run checker), so a denied destination is refused at start + on reload.
        self._egress_settings = egress_settings
        # The interface inbound listeners bind to; every runner this engine builds inherits it.
        self._inbound_bind_host = inbound_bind_host
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
        synchronous: str = "NORMAL",
        config_dir: str | Path | None = None,
        config_reload_roots: Sequence[str | Path] = (),
        inbound_bind_host: str = "127.0.0.1",
        delivery_defaults: RetryPolicy | None = None,
        ordering_default: OrderingMode | None = None,
        internal_error_default: InternalErrorPolicy | None = None,
        buildup_default: BuildupThreshold | None = None,
        ack_after_default: AckAfter | None = None,
        alert_sink: AlertSink | None = None,
        retention_settings: RetentionSettings | None = None,
        reference_settings: ReferenceSettings | None = None,
        egress_settings: EgressSettings | None = None,
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
            config_dir=config_dir,
            config_reload_roots=config_reload_roots,
            inbound_bind_host=inbound_bind_host,
            delivery_defaults=delivery_defaults,
            ordering_default=ordering_default,
            internal_error_default=internal_error_default,
            buildup_default=buildup_default,
            ack_after_default=ack_after_default,
            alert_sink=alert_sink,
            retention_settings=retention_settings,
            reference_settings=reference_settings,
            egress_settings=egress_settings,
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
            delivery_defaults=self._delivery_defaults,
            ordering_default=self._ordering_default,
            internal_error_default=self._internal_error_default,
            buildup_default=self._buildup_default,
            ack_after_default=self._ack_after_default,
            alert_sink=self._alert_sink,
            egress=self._egress_settings,
            env_values=self._env_values,
            active_environment=self._active_environment,
            coordinator=self._coordinator,
        )
        self._registry_runner = runner
        return runner

    @property
    def registry_runner(self) -> RegistryRunner | None:
        return self._registry_runner

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
            # gated on BACKLOG #1) would otherwise wedge every inbound at runtime with no ACK/NAK.
            if not getattr(self.store, "supports_ingest_stage", True):
                raise RuntimeError(
                    "the configured store backend does not support the staged ingress pipeline "
                    "(ADR 0001 Step A is SQLite-only; SQL Server staging is gated on BACKLOG #1) — "
                    "use the sqlite backend"
                )
            # Dead-letter OUTBOUND rows whose outbound was removed/renamed from the config — no worker
            # would ever drain them, so they'd strand forever (review H-5). After reset_stale_inflight
            # (so recovered inflight rows are considered) and before the workers start. Scoped to
            # outbound inside the store, so ingress rows (NULL destination) are never swept up.
            # NOTE (Track B Step 4): these two config-drift sweeps run UNCONDITIONALLY on every node,
            # NOT leader-gated, keyed off THIS node's in-process registry. They only dead-letter rows
            # whose destination/handler has LEFT *this* registry, and gating them on is_leader() at
            # startup would be racy (leadership is acquired asynchronously after coordinator.start()).
            # The "idempotent across nodes" property holds ONLY under the implicit assumption that every
            # clustered node runs IDENTICAL config: a node mid rolling-config-change whose registry has
            # not yet learned of a newly-added outbound/handler would dead-letter a sibling's valid rows,
            # and the sweep clears pending AND inflight rows without checking the lease holder, so it can
            # kill a row another node is actively leasing. Until that is hardened (a possible later
            # refinement = fold into the leader sweep / scope to rows whose lease is not still live),
            # clustered nodes MUST run identical config and config changes require a coordinated (not
            # rolling) restart. On a single node this is byte-identical to before (it always ran).
            await self.store.dead_letter_missing_destinations(
                set(self._registry_runner.registry.outbound)
            )
            # Likewise dead-letter ROUTED rows whose handler left the registry (a config edit during
            # downtime) — no transform worker can run a missing handler, so they'd strand forever (the
            # routed-stage analogue of the above; ADR 0001 Step B). Scoped to stage='routed' inside the
            # store. Unreachable on a non-staged backend (the supports_ingest_stage gate above raises).
            await self.store.dead_letter_missing_handlers(
                set(self._registry_runner.registry.handlers)
            )
            # Reference sets (ADR 0006): materialize declared sets BEFORE the listeners start, so a
            # transform's reference(...) resolves on the very first message; then run the periodic
            # refresh loop. A no-op when the graph declares none; a sync failure is isolated per-set
            # (last-good kept) and never blocks intake.
            # Track B Step 6: the reference sync runner is now leader-gated for materialize-from-source
            # AND converges every node's read cache from the shared snapshot (the runner holds this
            # engine's coordinator). So in a cluster the leader reads the external source once and writes
            # the shared snapshot; every follower converges by reading the shared table (no N-fold source
            # load, no stale follower caches). NullCoordinator (single-node) is always leader, so this is
            # byte-identical: materialize from source every pass, converge a no-op.
            await self._reconcile_reference_sync(startup=True)
            await self._registry_runner.start()
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
        # Leader lease-reclaim sweep (Track B Step 4) — only in clustered mode (reclaims_inflight()),
        # so single-node / SQLite never spawns it. It is itself leader-gated each pass, so a follower's
        # runner ticks but no-ops; the current leader recovers crashed nodes' expired-lease rows.
        if self._coordinator.reclaims_inflight():
            self._leader_maintenance = LeaderMaintenanceRunner(
                self.store,  # type: ignore[arg-type]  # Postgres-only reclaim_expired_leases; clustered ⇒ Postgres
                self._coordinator,
                interval_seconds=self._cluster_settings.reclaim_interval_seconds,
            )
            self._leader_maintenance.start()
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
        if self._retention_runner is not None:
            await self._retention_runner.stop()
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
