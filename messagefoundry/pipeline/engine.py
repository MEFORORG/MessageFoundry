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
from messagefoundry.config.settings import EgressSettings, RetentionSettings
from messagefoundry.config.wiring import Registry, WiringError, load_config
from messagefoundry.pipeline.alerts import AlertSink
from messagefoundry.pipeline.retention import RetentionRunner
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
        egress_settings: EgressSettings | None = None,
        env_values: Mapping[str, Any] | None = None,
        env_values_provider: Callable[[], Mapping[str, Any]] | None = None,
    ) -> None:
        self.store = store
        self._poll_interval = poll_interval
        # Where the runner reports operational alerts; None → the runner's default logging sink.
        self._alert_sink = alert_sink
        # [retention] enforcement. None (embedding/tests) → no retention task; the runner itself is a
        # no-op when nothing is configured, so passing default settings is also safe.
        self._retention_settings = retention_settings
        self._retention_runner: RetentionRunner | None = None
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
        egress_settings: EgressSettings | None = None,
        env_values: Mapping[str, Any] | None = None,
        env_values_provider: Callable[[], Mapping[str, Any]] | None = None,
    ) -> "Engine":
        """Open a SQLite-backed engine from a path (convenience for tests/embedding). The service
        path goes through :func:`~messagefoundry.store.open_store` (backend-agnostic)."""
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
            egress_settings=egress_settings,
            env_values=env_values,
            env_values_provider=env_values_provider,
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
        )
        self._registry_runner = runner
        return runner

    @property
    def registry_runner(self) -> RegistryRunner | None:
        return self._registry_runner

    # --- lifecycle -----------------------------------------------------------

    async def start(self) -> None:
        """Recover crashed in-flight rows (every stage), dead-letter outbound rows for removed
        outbounds, then start the wired graph."""
        self.started_at = time.time()
        # All-stages recovery: returns any row a crash left `inflight` — ingress rows mid-route and
        # outbound rows mid-delivery alike — to `pending` so the staged workers re-claim them
        # (staged pipeline, ADR 0001). The handoff/delivery transactions make the re-run idempotent.
        await self.store.reset_stale_inflight()
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
            await self._registry_runner.start()
        # Retention/purge is independent of the message graph (a store-level maintenance task), so it
        # runs whether or not a graph is wired and survives config reloads. The runner is a no-op when
        # nothing is configured, so this only spawns a task when [retention] is actually set.
        if self._retention_settings is not None:
            self._retention_runner = RetentionRunner(
                self.store, self._retention_settings, alert_sink=self._alert_sink
            )
            self._retention_runner.start()

    async def reload(
        self, config_dir: str | Path | None = None, *, dry_run: bool = False
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
        if self._registry_runner is not None:
            await self._registry_runner.stop()
        await self.store.close()
