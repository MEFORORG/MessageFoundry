# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Subprocess supervisor for L3 multi-process sharding.

``messagefoundry supervise`` discovers the shard ids declared in a config dir (see
:mod:`messagefoundry.pipeline.sharding`) and spawns ONE ``messagefoundry serve --shard <id>``
subprocess per shard, each with its own SQLite db file (``<stem>_<id>.db``) and its own API port
(``<base>+offset``). It then **monitors** the children on the asyncio loop, **restarts** any that
exit unexpectedly, and on a shutdown signal **stops them all cleanly** (terminate, then kill after a
grace period).

Why a supervisor (and not just N hand-run ``serve`` commands): an operator tags connections with a
shard name and runs one command; the supervisor turns the shard discovery into a fixed, reproducible
set of subprocess invocations (deterministic db file + port per shard), keeps the set alive, and
tears it down together. A single (default) shard yields a single subprocess — identical behaviour to
a plain ``serve``, so sharding is opt-in and invisible until used.

Concurrency: every child is an :class:`asyncio.subprocess.Process`; the supervise loop is pure
asyncio (no blocking the loop, cooperative cancellation). Each shard has a watcher task awaiting its
child's exit and relaunching it; shutdown cancels the watchers and drains the children.

Deferred (noted for follow-up, not built here): restart backoff / crash-loop breaker, per-shard
structured logging aggregation, graceful in-flight drain on restart, and a shared single-db
multi-shard mode (the MVP is one SQLite file per shard).
"""

from __future__ import annotations

import asyncio
import logging
import signal
import sys
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from messagefoundry.config.settings import StoreBackend
from messagefoundry.config.wiring import load_config
from messagefoundry.pipeline.sharding import require_unified_store, shard_ids

logger = logging.getLogger(__name__)

#: How long (seconds) to wait for a child to exit after a terminate() before escalating to kill().
DEFAULT_TERMINATE_GRACE = 10.0


@dataclass(frozen=True)
class ShardSpec:
    """The fixed launch parameters for one shard's subprocess.

    ``db_path`` and ``port`` are derived deterministically from the operator's ``--db``/``--port``
    bases so a restart re-attaches to the SAME store and re-binds the SAME API port. ``argv`` is the
    full ``python -m messagefoundry serve ...`` command line.
    """

    shard: str
    db_path: str
    port: int
    argv: tuple[str, ...]


def _shard_db_path(db_base: str, shard: str, *, single: bool) -> str:
    """Per-shard SQLite file: ``<stem>_<shard><suffix>`` (e.g. ``mefor_a.db``).

    A single default shard keeps the bare base path (so a non-sharded deployment's db file name is
    unchanged), making ``supervise`` on an untagged config byte-identical to ``serve --db <base>``.
    """
    if single:
        return db_base
    p = Path(db_base)
    return str(p.with_name(f"{p.stem}_{shard}{p.suffix}"))


def build_shard_specs(
    shard_list: Sequence[str],
    *,
    config: str,
    db_base: str,
    base_port: int,
    env: str | None = None,
    service_config: str | None = None,
    project_root: str | None = None,
    extra_serve_args: Sequence[str] = (),
    python_executable: str | None = None,
) -> list[ShardSpec]:
    """Derive a deterministic :class:`ShardSpec` per shard (db file + port + argv).

    Ports are assigned ``base_port + i`` in the SORTED shard order, so the mapping is stable across
    runs (a given shard always gets the same port). A single default shard keeps ``base_port`` and
    the bare ``db_base`` so it matches a plain ``serve``. ``python_executable`` defaults to
    :data:`sys.executable` (the same interpreter, so the child shares this venv).
    """
    ordered = sorted(shard_list)
    single = len(ordered) <= 1
    exe = python_executable or sys.executable
    specs: list[ShardSpec] = []
    for i, shard in enumerate(ordered):
        port = base_port + i
        db_path = _shard_db_path(db_base, shard, single=single)
        argv = [
            exe,
            "-m",
            "messagefoundry",
            "serve",
            "--config",
            config,
            "--shard",
            shard,
            "--db",
            db_path,
            "--port",
            str(port),
        ]
        if env is not None:
            argv += ["--env", env]
        if service_config is not None:
            argv += ["--service-config", service_config]
        if project_root is not None:
            # Anchor each shard's environments/<env>.toml resolution. By default that resolves against
            # the child's CWD (config/environments.py), so a spawned `serve --env <e>` can miss the env
            # value file; forwarding --project-root makes `supervise --env <e>` resolve it consistently.
            argv += ["--project-root", project_root]
        argv += list(extra_serve_args)
        specs.append(ShardSpec(shard=shard, db_path=db_path, port=port, argv=tuple(argv)))
    return specs


def discover_shard_specs(
    config: str,
    *,
    store_backend: StoreBackend,
    db_base: str,
    base_port: int,
    env: str | None = None,
    service_config: str | None = None,
    project_root: str | None = None,
    extra_serve_args: Sequence[str] = (),
    python_executable: str | None = None,
) -> list[ShardSpec]:
    """Load the config, discover its shard ids, and build a :class:`ShardSpec` per shard.

    Raises ``WiringError``/``FileNotFoundError`` from :func:`load_config` if the config is invalid,
    and ``ValueError`` if the graph declares no inbound connections (nothing to supervise), or if a
    ``>1``-shard config is on SQLite (the no-split-store guard — see :func:`require_unified_store`).
    """
    registry = load_config(config)
    ids = shard_ids(registry)
    if not ids:
        raise ValueError(
            f"config {config!r} declares no inbound connections — nothing to supervise"
        )
    # No-split-store guard (ADR 0063): >1 shard on SQLite would fan the message store into one file per
    # shard. Refuse it here — a sharded deployment must share ONE unified server-DB store.
    require_unified_store(store_backend, ids)
    return build_shard_specs(
        ids,
        config=config,
        db_base=db_base,
        base_port=base_port,
        env=env,
        service_config=service_config,
        project_root=project_root,
        extra_serve_args=extra_serve_args,
        python_executable=python_executable,
    )


#: A callable that launches a child for a spec and returns the process. Injectable so tests can swap a
#: real ``serve`` for a fast, deterministic stub child (no full engine, Windows-safe).
SpawnFn = Callable[["ShardSpec"], Awaitable["asyncio.subprocess.Process"]]


async def _default_spawn(spec: ShardSpec) -> asyncio.subprocess.Process:
    """Launch one shard subprocess from its argv (inherits stdout/stderr → NSSM/console)."""
    return await asyncio.create_subprocess_exec(*spec.argv)


@dataclass
class _Child:
    spec: ShardSpec
    process: asyncio.subprocess.Process


@dataclass
class Supervisor:
    """Spawns, monitors, restarts and stops one engine subprocess per shard.

    Inject ``spawn`` for tests (default: launch a real ``serve``). ``restart`` controls whether an
    unexpectedly-exited child is relaunched (the operator runtime sets it True; a one-shot smoke may
    set it False). ``terminate_grace`` is the seconds to wait after terminate() before kill().
    """

    specs: Sequence[ShardSpec]
    spawn: SpawnFn = _default_spawn
    restart: bool = True
    terminate_grace: float = DEFAULT_TERMINATE_GRACE
    _children: dict[str, _Child] = field(default_factory=dict, init=False)
    _stopping: asyncio.Event = field(default_factory=asyncio.Event, init=False)
    #: Per-shard restart counters — exposed for tests/observability (no backoff policy yet; deferred).
    restarts: dict[str, int] = field(default_factory=dict, init=False)

    async def run(self) -> None:
        """Spawn every shard, then watch them until cancelled or :meth:`stop` is called.

        Each shard runs under its own watcher task that relaunches it on an unexpected exit (when
        ``restart``). Cancelling :meth:`run` (or signalling stop) drains all children cleanly.
        """
        self._stopping.clear()
        watchers = [
            asyncio.create_task(self._watch(spec), name=f"shard:{spec.shard}")
            for spec in self.specs
        ]
        try:
            await asyncio.gather(*watchers)
        except asyncio.CancelledError:
            # Cooperative shutdown: signal the watchers to stop relaunching, then drain the children.
            self._stopping.set()
            for w in watchers:
                w.cancel()
            await asyncio.gather(*watchers, return_exceptions=True)
            await self._terminate_all()
            raise
        else:
            await self._terminate_all()

    async def _watch(self, spec: ShardSpec) -> None:
        """Keep one shard alive: spawn it, await exit, relaunch on an unexpected exit."""
        while not self._stopping.is_set():
            child = _Child(spec, await self.spawn(spec))
            self._children[spec.shard] = child
            logger.info(
                "shard %r started (pid=%s, port=%d)", spec.shard, child.process.pid, spec.port
            )
            try:
                rc = await child.process.wait()
            except asyncio.CancelledError:
                raise  # shutdown — leave the child for _terminate_all to drain
            if self._stopping.is_set():
                return
            if not self.restart:
                logger.info("shard %r exited rc=%s (restart disabled)", spec.shard, rc)
                return
            self.restarts[spec.shard] = self.restarts.get(spec.shard, 0) + 1
            logger.warning(
                "shard %r exited rc=%s — restarting (restart #%d)",
                spec.shard,
                rc,
                self.restarts[spec.shard],
            )

    def stop(self) -> None:
        """Signal a cooperative shutdown (idempotent). Watchers stop relaunching; children are drained
        by the running :meth:`run` once its watchers are cancelled. Safe to call from a signal handler."""
        self._stopping.set()

    async def _terminate_all(self) -> None:
        """Terminate every live child, escalating to kill() after ``terminate_grace`` seconds."""
        live = [c for c in self._children.values() if c.process.returncode is None]
        for child in live:
            try:
                child.process.terminate()
            except ProcessLookupError:
                pass  # already gone
        for child in live:
            try:
                await asyncio.wait_for(child.process.wait(), timeout=self.terminate_grace)
            except asyncio.TimeoutError:
                logger.warning(
                    "shard %r did not exit in %.0fs — killing",
                    child.spec.shard,
                    self.terminate_grace,
                )
                try:
                    child.process.kill()
                except ProcessLookupError:
                    pass
                await child.process.wait()


async def supervise(
    config: str,
    *,
    store_backend: StoreBackend,
    db_base: str,
    base_port: int,
    env: str | None = None,
    service_config: str | None = None,
    project_root: str | None = None,
    extra_serve_args: Sequence[str] = (),
    install_signal_handlers: bool = True,
) -> int:
    """Discover shards from ``config`` and run a :class:`Supervisor` until interrupted.

    Installs SIGINT/SIGTERM handlers (when ``install_signal_handlers``) that trigger a clean drain.
    Returns 0 on a clean shutdown, 2 on a config/discovery error.
    """
    from messagefoundry.config.wiring import WiringError

    try:
        specs = discover_shard_specs(
            config,
            store_backend=store_backend,
            db_base=db_base,
            base_port=base_port,
            env=env,
            service_config=service_config,
            project_root=project_root,
            extra_serve_args=extra_serve_args,
        )
    except (WiringError, FileNotFoundError, ValueError) as exc:
        logger.error("supervise: %s", exc)
        return 2

    logger.info(
        "supervising %d shard(s): %s",
        len(specs),
        ", ".join(f"{s.shard}->:{s.port}" for s in specs),
    )
    supervisor = Supervisor(specs)
    runner = asyncio.create_task(supervisor.run(), name="supervisor")

    if install_signal_handlers:
        loop = asyncio.get_running_loop()
        for sig in _shutdown_signals():
            try:
                loop.add_signal_handler(sig, runner.cancel)
            except (NotImplementedError, ValueError):
                # add_signal_handler is unsupported on Windows event loops; KeyboardInterrupt below
                # backstops Ctrl-C there. Non-fatal.
                pass

    try:
        await runner
    except asyncio.CancelledError:
        logger.info("supervise: shutting down")
    except KeyboardInterrupt:  # pragma: no cover - interactive Ctrl-C on Windows
        runner.cancel()
        await asyncio.gather(runner, return_exceptions=True)
    return 0


def _shutdown_signals() -> tuple[signal.Signals, ...]:
    """The OS signals that trigger a clean supervisor shutdown (SIGTERM is POSIX-only)."""
    sigs = [signal.SIGINT]
    term = getattr(signal, "SIGTERM", None)
    if term is not None:
        sigs.append(term)
    return tuple(sigs)
