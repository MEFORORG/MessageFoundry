# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Subprocess supervisor for L3 multi-process sharding.

``messagefoundry supervise`` discovers the shard ids declared in a config dir (see
:mod:`messagefoundry.pipeline.sharding`) and spawns ONE ``messagefoundry serve --shard <id>``
subprocess per shard, each on its own API port (``<base>+offset``). More than one engine shard must
share ONE server-DB store (ADR 0063, :func:`~messagefoundry.pipeline.sharding.require_unified_store`),
so the per-shard ``--db`` path (``<stem>_<id>.db``, the SQLite ``[store].path``) is not read by any
store a multi-shard fleet can run on; a single shard keeps the bare base path. It then **monitors**
the children on the asyncio loop, **restarts** any that exit unexpectedly, and on a shutdown signal
**stops them all cleanly**: ask, wait ``terminate_grace`` seconds, then force whatever is still
running.

Restarts back off (vault BACKLOG #2773). A child that exits within ``stable_uptime`` seconds of its
start is a FAST exit: each one in a row doubles the delay before the next launch, from
``restart_backoff_initial`` up to ``restart_backoff_max``, and ``crash_loop_limit`` of them in a row
trip the crash-loop breaker for THAT shard: it is not relaunched again, the ERROR line names it and
its exit history, and it stays listed in :attr:`Supervisor.crash_looped`. The other shards keep
running, so one shard's start-up failure is not a fleet outage (a crash in one supervised task stays
isolated). Only when every shard has tripped does ``supervise`` return non-zero. The supervisor has
no store and so no AlertSink; the ERROR log is its alert. A child that ran for ``stable_uptime``
resets both. Without this a start-up failure neither config load reproduces (a
store that cannot be reached, a port in use, a ``serve`` gate refusing) would relaunch in a tight
loop, each pass a full interpreter start and config load.

Why a supervisor (and not just N hand-run ``serve`` commands): an operator tags connections with a
shard name and runs one command; the supervisor turns the shard discovery into a fixed, reproducible
set of subprocess invocations (deterministic db file + port per shard), keeps the set alive, and
tears it down together. A single (default) shard yields a single subprocess — identical behaviour to
a plain ``serve``, so sharding is opt-in and invisible until used.

Concurrency: every child is an :class:`asyncio.subprocess.Process`; the supervise loop is pure
asyncio (no blocking the loop, cooperative cancellation). Each shard has a watcher task that races
its child's exit against the stop event and relaunches on a crash, so either :meth:`Supervisor.stop`
or a cancellation ends the watchers and the supervisor then drains the children.

Deferred (noted for follow-up, not built here): per-shard structured logging aggregation and
graceful in-flight drain on restart.
"""

from __future__ import annotations

import asyncio
import logging
import math
import os
import signal
import subprocess
import sys
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from messagefoundry.childenv import engine_environment, python_child_argv
from messagefoundry.config.settings import StoreBackend
from messagefoundry.config.wiring import Registry, load_config
from messagefoundry.controlchars import scrub_control_chars
from messagefoundry.pipeline import _config_preflight
from messagefoundry.pipeline.sharding import require_unified_store, shard_ids

logger = logging.getLogger(__name__)

#: How long (seconds) to wait for a child to exit after a terminate() before escalating to kill().
DEFAULT_TERMINATE_GRACE = 10.0

#: Restart backoff (vault BACKLOG #2773): the delay before relaunching after the first fast exit, and
#: the cap the doubling stops at. Ten fast exits in a row span about four minutes of retrying.
DEFAULT_RESTART_BACKOFF_INITIAL = 1.0
DEFAULT_RESTART_BACKOFF_MAX = 60.0
#: A child that ran at least this long (seconds) was not crash-looping: its exit resets the backoff.
DEFAULT_STABLE_UPTIME = 60.0
#: This many fast exits in a row trip the crash-loop breaker, and the shard is not relaunched again.
DEFAULT_CRASH_LOOP_LIMIT = 10


@dataclass(frozen=True)
class ShardSpec:
    """The fixed launch parameters for one shard's subprocess.

    ``db_path`` and ``port`` are derived deterministically from the operator's ``--db``/``--port``
    bases so a restart re-attaches to the SAME store and re-binds the SAME API port. ``argv`` is the
    full command line: :func:`messagefoundry.childenv.python_child_argv` for ``messagefoundry``,
    then ``serve ...``. That function says how the shard imports this build without searching the
    working directory.
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
    specs: list[ShardSpec] = []
    for i, shard in enumerate(ordered):
        port = base_port + i
        db_path = _shard_db_path(db_base, shard, single=single)
        argv = [
            *python_child_argv("messagefoundry", executable=python_executable),
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
    registry_guard: Callable[[Registry], None] | None = None,
) -> list[ShardSpec]:
    """Load the config, discover its shard ids, and build a :class:`ShardSpec` per shard.

    Raises ``WiringError``/``FileNotFoundError`` from :func:`load_config` if the config is invalid,
    and ``ValueError`` if the graph declares no inbound connections (nothing to supervise), or if a
    ``>1``-shard config is on SQLite (the no-split-store guard — see :func:`require_unified_store`).

    ``registry_guard`` is called with the whole graph after those checks, and refuses it by raising
    ``WiringError``. It is for a refusal each engine shard would make of that same graph, so the
    fleet refuses once instead of restarting engine shards that cannot start (vault BACKLOG
    #2368).
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
    if registry_guard is not None:
        registry_guard(registry)
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


#: The module the pre-flight child runs, and how long (seconds) it may take to load the config.
_PREFLIGHT_MODULE = _config_preflight.__name__
PREFLIGHT_SECONDS = 120.0


async def preflight_shard_config(config: str) -> str | None:
    """Load ``config`` once in a child that has an engine shard's import path. ``None`` means it
    loaded; otherwise the text says why an engine shard could not load it.

    The supervisor's own discovery loads the config in THIS process, where ``python -m`` put the
    working directory on the import path. An engine shard does not search the working directory
    (:func:`messagefoundry.childenv.python_child_argv`). So a config that imports a helper from
    there loads here and fails in every engine shard, and one that fails is restarted. Loading it
    under the engine shard's rule first makes that one refusal, before any of them exists."""
    process = await asyncio.create_subprocess_exec(
        *python_child_argv(_PREFLIGHT_MODULE),
        config,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.PIPE,
        env=engine_environment(),
    )
    try:
        _out, err = await asyncio.wait_for(process.communicate(), timeout=PREFLIGHT_SECONDS)
    except TimeoutError:
        process.kill()
        await process.wait()
        return (
            f"config {config!r} did not finish loading under an engine shard's import path "
            f"within {PREFLIGHT_SECONDS:g}s; no engine shard was started"
        )
    if process.returncode == 0:
        return None
    lines = [line for line in err.decode("utf-8", "replace").splitlines() if line.strip()]
    # One line, the child's own summary: the exception and its message, never a traceback.
    said = scrub_control_chars(lines[-1])[:300] if lines else f"exit {process.returncode}"
    refusal = (
        f"config {config!r} loads in the supervisor but not in an engine shard ({said}); "
        "no engine shard was started."
    )
    if process.returncode == _config_preflight.EXIT_IMPORT:
        refusal += (
            " An engine shard does not search the working directory for imports. A config helper "
            "must be "
            "a `_`-prefixed file beside the config, or an installed package."
        )
    return refusal


#: A callable that launches a child for a spec and returns the process. Injectable so tests can swap a
#: real ``serve`` for a fast, deterministic stub child (no full engine, Windows-safe).
SpawnFn = Callable[["ShardSpec"], Awaitable["asyncio.subprocess.Process"]]


async def _default_spawn(spec: ShardSpec) -> asyncio.subprocess.Process:
    """Launch one shard subprocess from its argv (inherits stdout/stderr → NSSM/console).

    On Windows the child goes into its OWN process group. That is what makes a *cooperative* stop
    deliverable at all: ``Process.terminate()`` there is ``TerminateProcess`` — a force with no
    request before it — so the supervisor asks with a ``CTRL_BREAK`` console event instead, and
    ``GenerateConsoleCtrlEvent`` can only be aimed at a process GROUP. Without the flag the child
    shares the console's group and the event would reach every process on that console, the sender
    included. POSIX needs no flag: ``terminate()`` is already SIGTERM.

    The new group also stops the console's own Ctrl-C from reaching the child, which is why
    :meth:`Supervisor._request_stop` has to deliver the break explicitly on every shutdown path.

    The child is a whole engine, so it gets the whole environment, secrets included, and gets it
    by name (:func:`messagefoundry.childenv.engine_environment`, vault BACKLOG #2587).
    """
    env = engine_environment()
    if sys.platform == "win32":
        return await asyncio.create_subprocess_exec(
            *spec.argv, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP, env=env
        )
    return await asyncio.create_subprocess_exec(*spec.argv, env=env)


@dataclass
class _Child:
    spec: ShardSpec
    process: asyncio.subprocess.Process


@dataclass
class Supervisor:
    """Spawns, monitors, restarts and stops one engine subprocess per shard.

    Inject ``spawn`` for tests (default: launch a real ``serve``). ``restart`` controls whether an
    unexpectedly-exited child is relaunched (the operator runtime sets it True; a one-shot smoke may
    set it False). ``terminate_grace`` is the seconds to wait after the stop request before forcing
    the child.

    The restart backoff and crash-loop breaker are the module docstring's; their knobs are
    ``restart_backoff_initial``, ``restart_backoff_max``, ``stable_uptime`` and
    ``crash_loop_limit``. ``clock`` (monotonic seconds) times each child's uptime and ``sleep``
    waits out a delay; both are injectable so a test can run a crash loop without real time.
    """

    specs: Sequence[ShardSpec]
    spawn: SpawnFn = _default_spawn
    restart: bool = True
    terminate_grace: float = DEFAULT_TERMINATE_GRACE
    restart_backoff_initial: float = DEFAULT_RESTART_BACKOFF_INITIAL
    restart_backoff_max: float = DEFAULT_RESTART_BACKOFF_MAX
    stable_uptime: float = DEFAULT_STABLE_UPTIME
    crash_loop_limit: int = DEFAULT_CRASH_LOOP_LIMIT
    clock: Callable[[], float] = time.monotonic
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep
    _children: dict[str, _Child] = field(default_factory=dict, init=False)
    _stopping: asyncio.Event = field(default_factory=asyncio.Event, init=False)
    #: Per-shard restart counters, exposed for tests and observability.
    restarts: dict[str, int] = field(default_factory=dict, init=False)
    #: Shards that tripped the crash-loop breaker in the current :meth:`run`: down, and not relaunched.
    crash_looped: set[str] = field(default_factory=set, init=False)

    def __post_init__(self) -> None:
        # Each of these would switch the protection off quietly: a limit of 0 trips on the first
        # exit even after a long stable run, a NaN or infinite limit never trips, a stable_uptime of
        # 0 or less (or NaN) never counts an exit as fast, and a delay of 0 or less relaunches at once.
        if not (isinstance(self.crash_loop_limit, int) and self.crash_loop_limit >= 1):
            raise ValueError(
                f"crash_loop_limit must be an integer >= 1, got {self.crash_loop_limit!r}"
            )
        for knob in ("restart_backoff_initial", "restart_backoff_max", "stable_uptime"):
            value = getattr(self, knob)
            if not (math.isfinite(value) and value > 0):
                raise ValueError(f"{knob} must be a finite number of seconds > 0, got {value!r}")

    async def run(self) -> None:
        """Spawn every shard, then watch them until cancelled or :meth:`stop` is called.

        Each shard runs under its own watcher task that relaunches it on an unexpected exit (when
        ``restart``). Either route drains all children cleanly: :meth:`stop` ends the watchers so
        ``gather`` returns and the ``else`` branch drains, and a cancellation or a watcher that
        raised takes the branch above, so no failure leaves sibling shards running undrained.
        """
        self._stopping.clear()
        self.crash_looped.clear()
        watchers = [
            asyncio.create_task(self._watch(spec), name=f"shard:{spec.shard}")
            for spec in self.specs
        ]
        try:
            await asyncio.gather(*watchers)
        except BaseException:
            # Cooperative shutdown, or one watcher raised: signal the others to stop relaunching,
            # then drain every child before the exception goes on.
            self._stopping.set()
            for w in watchers:
                w.cancel()
            await asyncio.gather(*watchers, return_exceptions=True)
            await self._terminate_all()
            raise
        else:
            await self._terminate_all()

    async def _watch(self, spec: ShardSpec) -> None:
        """Keep one shard alive: spawn it, await exit OR a stop request, relaunch on a crash after
        the backoff, and give up once the crash-loop breaker trips.

        The wait races the child's exit against ``_stopping``, so :meth:`stop` alone ends this
        watcher — awaiting the exit on its own left ``run``'s ``gather`` blocked until something
        cancelled it, and the event woke nobody. The backoff delay races it the same way.

        Under ``restart``, a launch that raises ``OSError`` (no memory for a process, no file
        handles, the interpreter missing mid-upgrade) counts as a fast exit, so it backs off and trips
        the breaker like any other start-up failure rather than ending the whole supervisor.

        A tripped breaker ends THIS watcher only; the sibling shards keep running, so one shard's
        bad start-up is not a fleet outage. The cost is accepted: the lanes that shard owns have no
        consumer, and their rows queue durably until the supervisor is restarted. That is at least
        its outbound lanes (ADR 0073, one static owner per lane) and the pass-through and loopback
        inbounds a sibling shard produces into (vault BACKLOG #2755). The ERROR line is what says so.
        """
        # The exits in the current run of fast ones, as "rc after Ns", for the ERROR line.
        history: list[str] = []
        while not self._stopping.is_set():
            started = self.clock()
            try:
                process = await self.spawn(spec)
            except OSError as exc:
                if not self.restart:
                    raise
                rc: int | str = f"launch failed ({exc})"
            else:
                self._children[spec.shard] = _Child(spec, process)
                logger.info(
                    "shard %r started (pid=%s, port=%d)", spec.shard, process.pid, spec.port
                )
                exit_rc = await self._unless_stopped(process.wait())
                if exit_rc is None:
                    return  # shutdown — leave the child for _terminate_all to drain
                rc = exit_rc
                if not self.restart:
                    logger.info("shard %r exited rc=%s (restart disabled)", spec.shard, rc)
                    return
            if self._stopping.is_set():
                return  # a launch that failed during shutdown is not a crash
            uptime = self.clock() - started
            if uptime < self.stable_uptime:
                history.append(f"rc={rc} after {uptime:.1f}s")
            else:
                history.clear()
            fast_exits = len(history)
            if fast_exits >= self.crash_loop_limit:
                self.crash_looped.add(spec.shard)
                alive = len(self.specs) - len(self.crash_looped)
                logger.error(
                    "shard %r exited %d times in a row, each within %gs of starting (%s): crash "
                    "loop, not restarting this shard again; %d other shard(s) still running, and "
                    "the lanes it owns queue until the supervisor is restarted.",
                    spec.shard,
                    fast_exits,
                    self.stable_uptime,
                    "; ".join(history),
                    alive,
                )
                return
            # The exponent is capped so a very large crash_loop_limit cannot overflow the float
            # before min() caps the delay; 2**32 seconds is past any restart_backoff_max anyway.
            delay = min(
                self.restart_backoff_max,
                self.restart_backoff_initial * float(2 ** min(max(fast_exits - 1, 0), 32)),
            )
            logger.warning(
                "shard %r exited rc=%s after %.1fs; restarting in %gs (restart #%d)",
                spec.shard,
                rc,
                uptime,
                delay,
                self.restarts.get(spec.shard, 0) + 1,
            )
            if delay > 0:
                await self._unless_stopped(self.sleep(delay))
            if self._stopping.is_set():
                return
            # Counted once the delay is over, so a stop during it does not record a restart that
            # never ran.
            self.restarts[spec.shard] = self.restarts.get(spec.shard, 0) + 1

    async def _unless_stopped[T](self, aw: Awaitable[T]) -> T | None:
        """Await ``aw`` unless a stop request comes first: its result, or ``None`` on a stop.

        Both waits are cancelled on EVERY exit path, the caller's own cancellation included, so
        neither outlives the call — no abandoned cleanup task, no shield. ``aw`` finishing with an
        exception raises it here rather than leaving it unretrieved."""
        task = asyncio.ensure_future(aw)
        stopping = asyncio.ensure_future(self._stopping.wait())
        try:
            await asyncio.wait({task, stopping}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            task.cancel()
            stopping.cancel()
        if self._stopping.is_set():
            if task.done() and not task.cancelled():
                task.exception()  # retrieved, so a failure racing the stop is not logged as lost
            return None
        return task.result()

    def stop(self) -> None:
        """Signal a cooperative shutdown (idempotent). The watchers stop relaunching and return, so
        the running :meth:`run` drains the children itself — no cancellation needed. Safe to call
        from a signal handler."""
        self._stopping.set()

    def _request_stop(self, child: _Child) -> None:
        """Ask one child to stop — the request half of request, wait, force.

        POSIX: ``terminate()`` is SIGTERM, already a request. Windows: ``terminate()`` is
        ``TerminateProcess``, so the request is a ``CTRL_BREAK`` aimed at the child's own process
        group. The send is gated on ``spawn is _default_spawn`` because that is the only launch here
        that sets ``CREATE_NEW_PROCESS_GROUP`` — an injected spawn's child shares the console's group,
        where the event would reach every process on that console, this one included. A refused break
        falls through to the force rather than leaving the child running.
        """
        if sys.platform == "win32" and self.spawn is _default_spawn:
            try:
                os.kill(child.process.pid, signal.CTRL_BREAK_EVENT)
            except OSError as exc:
                logger.warning(
                    "shard %r: CTRL_BREAK refused (%s) — forcing instead", child.spec.shard, exc
                )
            else:
                return
        try:  # noqa: SIM105
            child.process.terminate()
        except ProcessLookupError:
            pass  # already gone

    async def _terminate_all(self) -> None:
        """Ask every live child to stop, then force what is still running after ``terminate_grace``."""
        live = [c for c in self._children.values() if c.process.returncode is None]
        for child in live:
            self._request_stop(child)
        for child in live:
            try:
                await asyncio.wait_for(child.process.wait(), timeout=self.terminate_grace)
            except TimeoutError:
                logger.warning(
                    "shard %r did not exit in %.0fs — killing",
                    child.spec.shard,
                    self.terminate_grace,
                )
                try:  # noqa: SIM105
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
    registry_guard: Callable[[Registry], None] | None = None,
) -> int:
    """Discover shards from ``config`` and run a :class:`Supervisor` until interrupted.

    Installs SIGINT/SIGTERM handlers (when ``install_signal_handlers``) that trigger a clean drain.
    Runs while any engine shard is alive. Returns 0 on a clean shutdown, 1 when every engine shard
    tripped the crash-loop breaker, and 2 on a config/discovery error, which includes a graph
    ``registry_guard`` refuses (:func:`discover_shard_specs`).
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
            registry_guard=registry_guard,
        )
    except (WiringError, FileNotFoundError, ValueError) as exc:
        logger.error("supervise: %s", exc)
        return 2
    refusal = await preflight_shard_config(config)
    if refusal is not None:
        logger.error("supervise: %s", refusal)
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
            try:  # noqa: SIM105
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
    # run() returns on its own only once every watcher has. With every shard tripped, the whole
    # fleet is down, which is not a clean shutdown.
    if len(supervisor.crash_looped) == len(specs):
        logger.error(
            "supervise: every engine shard tripped the crash-loop breaker (%s); the whole fleet is "
            "down",
            ", ".join(sorted(supervisor.crash_looped)),
        )
        return 1
    if supervisor.crash_looped:
        logger.error(
            "supervise: stopped with engine shard(s) %s down after a crash loop",
            ", ".join(sorted(supervisor.crash_looped)),
        )
    return 0


def _shutdown_signals() -> tuple[signal.Signals, ...]:
    """The OS signals that trigger a clean supervisor shutdown (SIGTERM is POSIX-only)."""
    sigs = [signal.SIGINT]
    term = getattr(signal, "SIGTERM", None)
    if term is not None:
        sigs.append(term)
    return tuple(sigs)
