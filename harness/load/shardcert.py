# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""N-active engine-shard CERTIFICATION bench (ADR 0073).

Drives N **real** ``serve --shard`` engine processes against ONE unified server store, with the
``harness/config/shardcert`` graph whose shards deliver to OVERLAPPING outbound destinations, and
certifies the ADR 0073 invariants from the **sink/drain** signal (never a ``/stats``-poller peak):

* **No acknowledged loss** — every accept-ACKed message reaches the sink (``acked ⊆ delivered``).
* **Per-lane FIFO** — within each (source-shard, destination) lane the first-arrival order is
  monotonic (``lane_inversions == 0``), non-vacuously (``lanes_observed >= 2``).
* **No duplicate delivery** — no message delivered to the same lane twice on a clean run
  (``lane_repeats``); bounded at-least-once re-delivery is allowed only across a kill.
* **Single delivery consumer per outbound lane** — proven indirectly-but-robustly by no-loss +
  no-duplicate + no-stranded-INFLIGHT together: a mis-owned lane with no consumer would strand, and a
  double-consumed lane would duplicate.
* **Ownership-scoped crash recovery** (kill leg) — SIGKILL one shard mid-load; on its supervisor-style
  restart it recovers ONLY its owned lanes (``reset_stale_inflight(owned=...)``) while siblings are
  untouched, and the whole fleet drains with the invariants above intact.

This is the **local correctness** half of the throughput plan's clean-4-engine-no-loss bench: it
proves N-active is *safe* at a modest rate on one box. It does NOT establish the throughput/sizing
number — that needs the isolated AWS two-box rig (per-process CPU, client isolation). See
``OneDrive\...\aws-bench\n-active-4engine-certification-*``.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
import sys
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from messagefoundry.config.wiring import load_config
from messagefoundry.pipeline.sharding import (
    owned_destination_set,
    shard_ids,
)

from harness.load.corpus import build_corpus
from harness.load.correlator import Correlator
from harness.load.enginepoll import EnginePoller
from harness.load.failover import EngineNode
from harness.load.failover_track import FailoverTracker
from harness.load.ids import ControlIds
from harness.load.metrics import Counters, Histogram, LiveMetrics
from harness.load.profile import TypeMix, load_profile_text
from harness.load.sender import PersistentConnection
from harness.load.sink import CorrelationSink

_CONFIG_DIR = "harness/config/shardcert"

# A minimal corpus profile: one ADT^A01 mix (the graph routes every type identically, so the type is
# immaterial), a small template pool, one nominal phase/target to satisfy the profile schema. We drive
# with our own token bucket, not the profile's phases.
_CORPUS_PROFILE = """
[load]
name = "shardcert-corpus"
pool_size = 1
corpus_count_per_trigger = 10
[[load.target]]
name = "s"
host = "127.0.0.1"
port = 3600
types = ["ADT"]
[load.mix]
"ADT^A01" = 1.0
[[load.phase]]
name = "sustained"
kind = "sustained"
loop = "open"
rate_start = 40.0
duration_s = 10.0
"""

_TOKEN_BATCH_CAP = 4096
_MAX_TICK_SLEEP = 0.05


class ShardCertNode(EngineNode):
    """An :class:`EngineNode` that serves ONE shard: injects ``--shard <id>`` into the argv (and keeps
    per-PID :meth:`kill` for the crash leg, which ``supervise()`` does not expose). Everything else —
    the store, the graph shape, and the sink target — comes from the shared ``MEFOR_*`` env."""

    def __init__(
        self, shard: str, api_port: int, *, env: Mapping[str, str], config_dir: str, cwd: Path
    ) -> None:
        super().__init__(f"shard-{shard}", api_port, env=env, config_dir=config_dir, cwd=cwd)
        self.shard = shard

    async def start(self) -> None:
        self._proc = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "messagefoundry",
            "serve",
            "--config",
            self._config_dir,
            "--shard",
            self.shard,
            "--port",
            str(self.api_port),
            "--env",
            "dev",
            env=self._env,
            cwd=str(self._cwd),
            stdout=self._log,
            stderr=asyncio.subprocess.STDOUT,
        )


@dataclass
class ShardCertReport:
    """The certification outcome — sink/drain-derived, plus store diagnostics."""

    shards: tuple[str, ...]
    owned: dict[str, list[str]]  # shard -> owned destination lanes (rendezvous)
    killed_shard: str | None
    sent: int
    acked: int
    delivered_distinct: int
    sink_received: int
    acked_not_delivered: int
    lane_inversions: int
    lanes_observed: int
    lane_repeats: int
    engine_done: int
    engine_dead: int
    in_pipeline_final: int
    drained: bool
    drain_seconds: float | None
    stranded_nonterminal: int
    queue_breakdown: str
    recovery_seconds: float | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """Pass bar: zero acknowledged loss, drained pipeline, per-lane FIFO (non-vacuous), no
        dead-letters, no stranded non-terminal rows. Duplicates are allowed only across a kill."""
        dup_ok = self.lane_repeats == 0 if self.killed_shard is None else True
        return (
            self.acked > 0
            and self.acked_not_delivered == 0
            and self.drained
            and self.in_pipeline_final == 0
            and self.engine_dead == 0
            and self.lane_inversions == 0
            and self.lanes_observed >= 2
            and self.stranded_nonterminal == 0
            and dup_ok
        )

    def render(self) -> str:
        lines = [
            f"ShardCert {'/'.join(self.shards)}  verdict={'PASS' if self.ok else 'FAIL'}"
            + (f"  killed={self.killed_shard}" if self.killed_shard else "  (baseline, no kill)"),
            f"  sent={self.sent} acked={self.acked} delivered_distinct={self.delivered_distinct} "
            f"sink_received={self.sink_received}",
            f"  acked_not_delivered={self.acked_not_delivered} (0 = no acknowledged loss)",
            f"  lane_inversions={self.lane_inversions} lanes_observed={self.lanes_observed} "
            f"lane_repeats(dups)={self.lane_repeats}",
            f"  engine done={self.engine_done} dead={self.engine_dead} "
            f"in_pipeline_final={self.in_pipeline_final} drained={self.drained} "
            f"drain_s={self.drain_seconds}",
            f"  stranded_nonterminal_rows={self.stranded_nonterminal}",
            "  ownership: "
            + " ".join(f"{s}->[{','.join(self.owned[s]) or '-'}]" for s in self.shards),
            f"  {self.queue_breakdown}",
        ]
        if self.recovery_seconds is not None:
            lines.append(f"  recovery_seconds(reported, not gated)={self.recovery_seconds:.2f}")
        for n in self.notes:
            lines.append(f"  note: {n}")
        return "\n".join(lines)


# --- port helpers ------------------------------------------------------------


def _reserve_ports(n: int) -> list[int]:
    """Reserve ``n`` free loopback ports (bind :0 then close — the small close→bind race is the same
    pattern the failover harness uses; the engine binds moments later)."""
    socks = []
    try:
        for _ in range(n):
            s = socket.socket()
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", 0))
            socks.append(s)
        return [int(s.getsockname()[1]) for s in socks]
    finally:
        for s in socks:
            s.close()


def _free_contiguous(n: int, start: int = 3600, tries: int = 60) -> int:
    """A base port ``B`` such that ``B..B+n-1`` are all bindable — the graph needs the N shard inbound
    ports contiguous (``inbound_base + i``)."""
    base = start
    for _ in range(tries):
        socks = []
        ok = True
        try:
            for i in range(n):
                s = socket.socket()
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    s.bind(("127.0.0.1", base + i))
                    socks.append(s)
                except OSError:
                    ok = False
                    break
        finally:
            for s in socks:
                s.close()
        if ok:
            return base
        base += n + 7
    raise RuntimeError(f"could not find {n} contiguous free ports from {start}")


async def _await_health(url: str, *, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    async with httpx.AsyncClient(timeout=2.0) as client:
        while time.monotonic() < deadline:
            with contextlib.suppress(Exception):
                r = await client.get(f"{url}/health")
                if r.status_code == 200:
                    return True
            await asyncio.sleep(0.3)
    return False


async def _await_port(host: str, port: int, *, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            reader, writer = await asyncio.open_connection(host, port)
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            return True
        except OSError:
            await asyncio.sleep(0.2)
    return False


# --- store helpers (SQL Server) ----------------------------------------------


async def _reset_store(env: Mapping[str, str]) -> None:
    """DELETE the pipeline tables so a re-run starts clean (mirrors test_load_failover_sqlserver)."""
    import os

    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.sqlserver import SqlServerStore

    # The TLS-escape guard (insecure_tls_allowed) reads os.environ DIRECTLY, so the parent-process
    # store open needs the escape + creds in os.environ, not just the load_settings `environ=` arg.
    with _env_scope(dict(env)):
        settings = load_settings(environ=os.environ).store
        store = await SqlServerStore.open(settings)
    try:
        async with store._pool.acquire() as conn:
            cur = await conn.cursor()
            for table in (
                "queue",
                "outbox",
                "response",
                "delivered_keys",
                "state",
                "leader_lease",
                "nodes",
                "cluster_config",
                "messages",
            ):
                with contextlib.suppress(Exception):
                    await cur.execute(f"DELETE FROM {table}")
            await conn.commit()
    finally:
        await store.close()


async def _queue_breakdown(env: Mapping[str, str]) -> tuple[int, str]:
    """``(non-terminal row count, "stage/status=n ..." summary)`` read DIRECTLY from the store — the
    stranded-INFLIGHT detector (``store.stats()`` is outbound-scoped and would miss a stuck ingress/
    routed row)."""
    import os

    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.sqlserver import SqlServerStore

    with _env_scope(dict(env)):  # escape reads os.environ directly — see _reset_store
        settings = load_settings(environ=os.environ).store
        store = await SqlServerStore.open(settings)
    try:
        async with store._pool.acquire() as conn:
            cur = await conn.cursor()
            await cur.execute(
                "SELECT stage, status, COUNT(*) FROM queue GROUP BY stage, status "
                "ORDER BY stage, status"
            )
            rows = await cur.fetchall()
            await cur.execute("SELECT COUNT(*) FROM queue WHERE status NOT IN ('done', 'dead')")
            nonterminal = int((await cur.fetchone())[0])
    finally:
        await store.close()
    summary = "QUEUE " + (" ".join(f"{r[0]}/{r[1]}={r[2]}" for r in rows) or "<empty>")
    return nonterminal, summary


# --- the bench ---------------------------------------------------------------


async def run_shardcert(
    *,
    dests: int = 8,
    aggregate_rate: float = 40.0,
    hold_seconds: float = 20.0,
    kill: bool = False,
    kill_shard: str | None = None,
    kill_at_fraction: float = 0.4,
    drain_timeout: float = 90.0,
    store_env: Mapping[str, str] | None = None,
    cwd: Path | None = None,
) -> ShardCertReport:
    """Run the 4-shard certification bench once. ``store_env`` must point every serve process at the
    ONE unified server store (``MEFOR_STORE_*``) — see the module doc + the AWS handoff for the exact
    set; ``run_shardcert`` adds the graph shape (``MEFOR_SHARDCERT_*``) and the auth/insecure escapes.
    """
    import os

    cwd = cwd or Path.cwd()
    store_env = dict(store_env or {})

    # Discover the shard set + ownership from the graph (with `dests` applied) BEFORE serving.
    with _env_scope({"MEFOR_SHARDCERT_DESTS": str(dests)}):
        reg = load_config(_CONFIG_DIR)
    ids_list = shard_ids(reg)
    owned = {s: sorted(owned_destination_set(reg, s, ids_list)) for s in ids_list}
    n = len(ids_list)

    # Ports: N contiguous inbound, 1 sink, N API.
    inbound_base = _free_contiguous(n)
    sink_port, *api_ports = _reserve_ports(1 + n)

    # The shape env every serve process (and the config discovery) shares.
    shape_env = {
        "MEFOR_SHARDCERT_SHARDS": ",".join(ids_list),
        "MEFOR_SHARDCERT_INBOUND_BASE": str(inbound_base),
        "MEFOR_SHARDCERT_DESTS": str(dests),
        "MEFOR_SHARDCERT_SINK_HOST": "127.0.0.1",
        "MEFOR_SHARDCERT_SINK_PORT": str(sink_port),
        "MEFOR_SHARDCERT_TRANSFORM": "edit",
    }
    escapes = {
        "MEFOR_ALLOW_INSECURE_TLS": "1",
        "MEFOR_ALLOW_INSECURE_CONFIG_SOURCE": "1",
        "MEFOR_AUTH_ENABLED": "false",
        "MEFOR_INBOUND_BIND_HOST": "127.0.0.1",
    }
    store_env.setdefault("MEFOR_STORE_POOL_SIZE", "8")
    node_env = {**os.environ, **store_env, **shape_env, **escapes}

    await _reset_store(node_env)

    # Sink + correlation + tracker (span all shards).
    ids = ControlIds(prefix="SC")
    metrics = LiveMetrics(counters=Counters(), ack=Histogram(), e2e=Histogram())
    correlator = Correlator(capacity=1 << 20, metrics=metrics)
    tracker = FailoverTracker()
    corpus = build_corpus(load_profile_text(_CORPUS_PROFILE, where="<shardcert>"), ids)
    mix = TypeMix({"ADT^A01": 1.0})
    sink = CorrelationSink(
        ids, correlator, metrics, host="127.0.0.1", ports=(sink_port,), tracker=tracker
    )
    await sink.start()

    nodes: dict[str, ShardCertNode] = {}
    conns: list[PersistentConnection] = []
    poller: EnginePoller | None = None
    report_notes: list[str] = []
    killed = kill_shard if kill else None
    if kill and killed is None:
        # Kill the shard that owns the MOST lanes (maximizes recovery coverage).
        killed = max(ids_list, key=lambda s: len(owned[s]))
    recovery_seconds: float | None = None

    try:
        # Start shards STRICTLY one-at-a-time behind a health gate — the SS schema-init applock convoys
        # at N>=4 simultaneous opens (multishard.py:426 documents the 30s-timeout blowout).
        for i, s in enumerate(ids_list):
            node = ShardCertNode(s, api_ports[i], env=node_env, config_dir=_CONFIG_DIR, cwd=cwd)
            await node.start()
            nodes[s] = node
            if not await _await_health(node.url, timeout=60.0):
                raise RuntimeError(f"shard {s} did not become healthy\n{node.log_tail()}")
            if not await _await_port("127.0.0.1", inbound_base + i, timeout=30.0):
                raise RuntimeError(f"shard {s} inbound port {inbound_base + i} never bound")

        # One persistent connection per shard inbound (tracker wired for on_ack).
        for i, _s in enumerate(ids_list):
            pc = PersistentConnection(
                "127.0.0.1",
                inbound_base + i,
                correlator,
                metrics,
                expect_ack=True,
                tracker=tracker,
            )
            pc.start()
            conns.append(pc)

        # Drive load at an aggregate rate, round-robin across the N shard connections; optionally
        # SIGKILL one shard `kill_at_fraction` into the hold and keep driving the survivors.
        kill_deadline = time.monotonic() + hold_seconds * kill_at_fraction if kill else None
        did_kill = False
        kill_at: float | None = None
        loop = asyncio.get_running_loop()
        start = loop.time()
        next_due = start
        interval = 1.0 / aggregate_rate if aggregate_rate > 0 else 0.0
        sampler = corpus.sampler(mix)
        rr = 0
        while True:
            now = loop.time()
            if now - start >= hold_seconds:
                break
            if kill and not did_kill and time.monotonic() >= (kill_deadline or 0):
                nodes[killed].kill()  # type: ignore[index]
                kill_at = time.monotonic()
                did_kill = True
                report_notes.append(f"SIGKILLed shard {killed} at ~{kill_at_fraction:.0%} of hold")
            emitted = 0
            while next_due <= now and emitted < _TOKEN_BATCH_CAP:
                out = corpus.next(sampler)
                conn = conns[rr % len(conns)]
                rr += 1
                if not conn.submit_nowait(out):
                    metrics.counters.deferred += 1
                next_due += interval
                emitted += 1
            if next_due <= now:
                behind = int((now - next_due) / max(interval, 1e-6)) + 1
                metrics.counters.deferred += behind
                next_due = now + interval
            await asyncio.sleep(max(0.0, min(next_due - loop.time(), _MAX_TICK_SLEEP)))

        # Stop offering; grace in-flight ACKs.
        await asyncio.gather(*(c.stop(2.0) for c in conns))

        # Kill leg: restart the killed shard (supervisor-style) so its startup runs the
        # ownership-scoped reset over ITS lanes; time functional recovery.
        if kill and killed is not None:
            idx = ids_list.index(killed)
            restart = ShardCertNode(
                killed, api_ports[idx], env=node_env, config_dir=_CONFIG_DIR, cwd=cwd
            )
            await restart.start()
            nodes[killed] = restart
            if not await _await_health(restart.url, timeout=60.0):
                raise RuntimeError(f"shard {killed} did not restart\n{restart.log_tail()}")
            if kill_at is not None:
                recovery_seconds = time.monotonic() - kill_at

        # Aggregate drain over ALL shards (every shard back up): in_pipeline==0 across the fleet, read
        # from /stats — the authoritative drain signal, NOT a poller peak.
        urls = [nodes[s].url for s in ids_list]
        poller = EnginePoller(urls, None, origin=time.perf_counter())
        await poller.open()
        drain_s = await poller.await_drain(timeout=drain_timeout, interval=0.5)
        final = poller.final

        # Store-truth: stranded non-terminal rows + stage/status breakdown.
        stranded, breakdown = await _queue_breakdown(node_env)

    finally:
        if poller is not None:
            await poller.close()
        for pc in conns:
            with contextlib.suppress(Exception):
                await pc.stop(0.5)
        for node in nodes.values():
            with contextlib.suppress(Exception):
                await node.stop()
        with contextlib.suppress(Exception):
            await sink.stop()

    ctr = metrics.counters
    return ShardCertReport(
        shards=tuple(ids_list),
        owned=owned,
        killed_shard=killed,
        sent=ctr.sent,
        acked=ctr.acked,
        delivered_distinct=tracker.delivered_count,
        sink_received=ctr.sink_received,
        acked_not_delivered=tracker.acked_not_delivered(),
        lane_inversions=tracker.lane_inversions,
        lanes_observed=tracker.lanes_observed,
        lane_repeats=tracker.lane_repeats,
        engine_done=(final.done if final else 0),
        engine_dead=(final.dead if final else 0),
        in_pipeline_final=(final.in_pipeline if final else -1),
        drained=drain_s is not None,
        drain_seconds=drain_s,
        stranded_nonterminal=stranded,
        queue_breakdown=breakdown,
        recovery_seconds=recovery_seconds,
        notes=report_notes,
    )


class _env_scope:
    """Temporarily set env vars (so ``load_config`` reads the intended graph shape), restore on exit."""

    def __init__(self, env: Mapping[str, str]) -> None:
        self._env = dict(env)
        self._saved: dict[str, str | None] = {}

    def __enter__(self) -> None:
        import os

        for k, v in self._env.items():
            self._saved[k] = os.environ.get(k)
            os.environ[k] = v

    def __exit__(self, *exc: object) -> None:
        import os

        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
