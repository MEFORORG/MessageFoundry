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
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from messagefoundry.config.wiring import load_config
from messagefoundry.pipeline.sharding import (
    owned_destination_set,
    shard_ids,
)

from harness.load.coord import (
    DRIVE_COMPLETE,
    DRIVE_GO,
    DRIVE_START,
    DRIVER_ARMED,
    DRIVER_DONE,
    ENGINE_DRAINED,
    SHARDS_READY,
    SINK_BOUND,
    SINK_DONE,
    CoordTimeout,
    FileDropCoord,
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

# Intake-shortfall tolerance for the rate-ladder ceiling test. The token-bucket drive does NOT emit
# exactly ``offered`` messages: above ~200 msg/s it drops a handful of boundary tokens even in a
# perfectly HEALTHY run, so ``achieved_intake`` lands a few short of the theoretical ``offered``. This
# band absorbs that boundary-token noise so a healthy step is not mis-read as a throughput ceiling; a
# real intake shortfall (the fleet cannot ingest the offered rate) is far larger than this.
_INTAKE_TOL = 0.05

# The loopback interfaces a co-located run binds — these NEVER trip serve's off-loopback plaintext-MLLP
# exposure gate, so a co-located run's serve argv stays byte-identical (no extra flag). The two-box
# engine binds ``0.0.0.0`` (off-box reach), which DOES trip the gate → the dev override below.
_LOOPBACK_BIND_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


def _insecure_bind_args(env: Mapping[str, str]) -> list[str]:
    """``["--allow-insecure-bind"]`` when the serve subprocess binds its inbound listener on a
    NON-loopback interface (``MEFOR_INBOUND_BIND_HOST`` = ``0.0.0.0`` / a NIC IP), else ``[]``.

    A non-loopback plaintext MLLP bind trips serve's off-loopback exposure gate (ADR 0002 §0,
    ``check_mllp_tls_exposure``) and is REFUSED at start without this dev override. The two-box cert
    binds ``0.0.0.0`` so the off-box load-gen senders can reach the inbound ports, and accepts the
    cleartext risk on the trusted, firewalled bench network — never a co-located loopback run (the
    single-box ``run_shardcert`` + the SS-gated cert test), which omits the flag and keeps a
    byte-identical argv."""
    host = env.get("MEFOR_INBOUND_BIND_HOST")
    if host is None or host in _LOOPBACK_BIND_HOSTS or host.startswith("127."):
        return []
    return ["--allow-insecure-bind"]


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
            # A non-loopback shard bind (the two-box cert binds 0.0.0.0 for off-box reach) needs the dev
            # override so serve's off-loopback plaintext-MLLP gate warns instead of refusing; a co-located
            # loopback bind adds nothing (byte-identical argv — the single-box path is unchanged).
            *_insecure_bind_args(self._env),
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
    # --- sizing-bench extras (default sentinels ⇒ the correctness/kill path is unchanged) ---
    offered: int = 0  # intended load over the hold (round(aggregate_rate * hold_seconds))
    achieved_intake: int = 0  # messages the fleet accept-ACKed (== acked; the intake number)
    in_pipeline_peak: int = -1  # peak NOT-DONE rows during the hold; -1 = not sampled (default)
    ack_p50_ms: float = 0.0  # ACK-on-receipt latency (across every shard lane)
    ack_p99_ms: float = 0.0
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

    def to_json_dict(self) -> dict[str, object]:
        """Metrics + metadata only (never message bodies or control-id lists — PHI rule)."""
        return {
            "schema_version": 1,
            "kind": "shardcert",
            "verdict": "PASS" if self.ok else "FAIL",
            "shards": list(self.shards),
            "killed_shard": self.killed_shard,
            "owned": {s: list(self.owned[s]) for s in self.shards},
            "traffic": {
                "sent": self.sent,
                "acked": self.acked,
                "offered": self.offered,
                "achieved_intake": self.achieved_intake,
                "delivered_distinct": self.delivered_distinct,
                "sink_received": self.sink_received,
            },
            "correctness": {
                "acked_not_delivered": self.acked_not_delivered,
                "lane_inversions": self.lane_inversions,
                "lanes_observed": self.lanes_observed,
                "lane_repeats": self.lane_repeats,
                "stranded_nonterminal": self.stranded_nonterminal,
                "engine_dead": self.engine_dead,
            },
            "throughput": {
                "in_pipeline_peak": self.in_pipeline_peak,
                "in_pipeline_final": self.in_pipeline_final,
                "drained": self.drained,
                "drain_seconds": self.drain_seconds,
            },
            "ack_ms": {"p50": round(self.ack_p50_ms, 3), "p99": round(self.ack_p99_ms, 3)},
            "recovery_seconds": self.recovery_seconds,
            "queue_breakdown": self.queue_breakdown,
            "notes": self.notes,
        }


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


async def _queue_breakdown(env: Mapping[str, str]) -> tuple[int, int, str]:
    """``(non-terminal row count, all-stage dead-letter count, "stage/status=n ..." summary)`` read
    DIRECTLY from the store. Two store-truth signals the outbound-scoped ``store.stats()`` can't give:
    the stranded-INFLIGHT count (``stats()`` would miss a stuck ingress/routed row) AND the all-stage
    dead total. A router/handler regression dead-letters at the INGRESS or ROUTED stage
    (``dead_letter_now`` sets ``status=DEAD`` WITHOUT touching ``stage``), and ``stats().dead`` counts
    only ``stage=outbound`` — so those acked-on-receipt rows are acknowledged loss the engine's own
    store-truth verdict must catch without leaning on the driver half's sink-truth. Both are derived
    from the single ``GROUP BY stage, status`` scan below — no extra round trip."""
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
    dead_total = sum(int(r[2]) for r in rows if str(r[1]).lower() == "dead")
    summary = "QUEUE " + (" ".join(f"{r[0]}/{r[1]}={r[2]}" for r in rows) or "<empty>")
    return nonterminal, dead_total, summary


# --- the bench ---------------------------------------------------------------


async def _sample_in_pipeline_peak(
    urls: list[str], stop: asyncio.Event, out: list[int], *, interval: float = 0.5
) -> None:
    """Poll the fleet's aggregate in-pipeline gauge every ``interval`` until ``stop``, keeping the
    high-water in ``out[0]``. A dedicated short-lived poller so the SIZING bench can report the
    steady-state backlog peak; the correctness path never starts it (``capture_peak=False``), so its
    drive stays byte-identical."""
    poller = EnginePoller(urls, None, origin=time.perf_counter())
    await poller.open()
    # De-dup the unified-store gauge: each shard's /stats in_pipeline counts the WHOLE store and the poller
    # SUMS across the N shard URLs, so the aggregate is N× the true fleet backlog (#841). Divide by the
    # distinct-shard count to record a SINGLE store view as the high-water.
    n_shards = max(1, len(set(urls)))
    try:
        while not stop.is_set():
            sample = await poller.sample_once()
            if sample is not None:
                depth = sample.in_pipeline // n_shards
                if depth > out[0]:
                    out[0] = depth
            try:
                await asyncio.wait_for(stop.wait(), timeout=interval)
            except (asyncio.TimeoutError, TimeoutError):
                pass
    finally:
        await poller.close()


async def _sample_in_pipeline_trace(
    urls: list[str],
    stop: asyncio.Event,
    out: list[list[float]],
    *,
    interval: float = 2.0,
    origin: float | None = None,
) -> None:
    """Poll the fleet's aggregate in-pipeline gauge every ``interval`` until ``stop``, APPENDING each
    ``[elapsed_s, in_pipeline]`` reading to ``out`` (the full bounded trace, not just the peak). The PR-C2
    soak uses the trace SLOPE (flat/draining vs monotonic growth) to tell a sustainable plateau from a
    slow-saturation one; a short-lived poller so the correctness/climb path (``sample_in_pipeline=False``)
    adds no concurrent poller during the hold."""
    t0 = origin if origin is not None else time.perf_counter()
    poller = EnginePoller(urls, None, origin=t0)
    await poller.open()
    # De-inflate the unified-store in_pipeline: each shard's gauge counts the whole store and the poller
    # sums the N shard URLs (#841). Divide by the distinct-shard count so the recorded trace is a SINGLE
    # store view — which ALSO de-inflates the least-squares SLOPE by the same N, removing the accidental
    # N× slope sensitivity the soak's flat-or-draining gate would otherwise apply (paired with the tightened
    # _SLOPE_FLAT_TOL in shardcert_ladder.py and the bounded soak drain, D2).
    n_shards = max(1, len(set(urls)))
    try:
        while not stop.is_set():
            sample = await poller.sample_once()
            if sample is not None:
                out.append([round(time.perf_counter() - t0, 3), sample.in_pipeline / n_shards])
            try:
                await asyncio.wait_for(stop.wait(), timeout=interval)
            except (asyncio.TimeoutError, TimeoutError):
                pass
    finally:
        await poller.close()


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
    sink_host: str = "127.0.0.1",
    sink_port: int | None = None,
    capture_peak: bool = False,
) -> ShardCertReport:
    """Run the 4-shard certification bench once. ``store_env`` must point every serve process at the
    ONE unified server store (``MEFOR_STORE_*``) — see the module doc + the AWS handoff for the exact
    set; ``run_shardcert`` adds the graph shape (``MEFOR_SHARDCERT_*``) and the auth/insecure escapes.

    ``sink_port`` pins the correlation-sink port (default ``None`` ⇒ an ephemeral reserved port, the
    original behavior); ``sink_host`` is the sink bind host. ``capture_peak`` samples the fleet's
    aggregate in-pipeline gauge during the hold and reports ``in_pipeline_peak`` — the sizing bench
    turns it on; **off by default so the correctness/kill path drives byte-identically** (no extra
    poller during the hold, ``in_pipeline_peak`` stays ``-1``).
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
    # Lanes per shard (many-thin-lanes): the built graph has N*lanes inbound rows, so derive it from the
    # registry rather than re-reading the env (keeps the driver and the served graph in lock-step).
    lanes = (len(reg.inbound) // n) if n else 1

    # Ports: N*lanes contiguous inbound (lane l of shard i binds base + i*lanes + l), 1 sink (pinned or
    # ephemeral), N API. lanes == 1 ⇒ N contiguous inbound at base + i, byte-identical to today.
    inbound_base = _free_contiguous(n * lanes)
    if sink_port is None:
        sink_port, *api_ports = _reserve_ports(1 + n)
    else:
        api_ports = _reserve_ports(n)

    # The shape env every serve process (and the config discovery) shares.
    shape_env = {
        "MEFOR_SHARDCERT_SHARDS": ",".join(ids_list),
        "MEFOR_SHARDCERT_INBOUND_BASE": str(inbound_base),
        "MEFOR_SHARDCERT_DESTS": str(dests),
        "MEFOR_SHARDCERT_SINK_HOST": sink_host,
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
        ids, correlator, metrics, host=sink_host, ports=(sink_port,), tracker=tracker
    )
    await sink.start()

    nodes: dict[str, ShardCertNode] = {}
    conns: list[PersistentConnection] = []
    poller: EnginePoller | None = None
    peak_holder = [0]  # in_pipeline high-water during the hold (capture_peak only)
    peak_stop = asyncio.Event()
    peak_task: asyncio.Task[None] | None = None
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
            # Each shard binds `lanes` inbound ports (base + i*lanes + l); wait for every one.
            for lane in range(lanes):
                port = inbound_base + i * lanes + lane
                if not await _await_port("127.0.0.1", port, timeout=30.0):
                    raise RuntimeError(f"shard {s} inbound lane port {port} never bound")

        # One persistent connection per (shard, lane) inbound (tracker wired for on_ack) — N*lanes now.
        for i, _s in enumerate(ids_list):
            for lane in range(lanes):
                pc = PersistentConnection(
                    "127.0.0.1",
                    inbound_base + i * lanes + lane,
                    correlator,
                    metrics,
                    expect_ack=True,
                    tracker=tracker,
                )
                pc.start()
                conns.append(pc)

        # Sizing bench only: sample the fleet's in-pipeline high-water across the hold (off by default
        # ⇒ the correctness/kill path adds no concurrent poller during the drive).
        if capture_peak:
            peak_task = asyncio.create_task(
                _sample_in_pipeline_peak([nodes[s].url for s in ids_list], peak_stop, peak_holder)
            )

        # Drive load at an aggregate rate, round-robin across the N*lanes shard-lane connections;
        # optionally SIGKILL one shard `kill_at_fraction` into the hold and keep driving the survivors.
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

        # Hold over: stop the peak sampler (if any), then stop offering; grace in-flight ACKs.
        if peak_task is not None:
            peak_stop.set()
            with contextlib.suppress(Exception):
                await peak_task
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

        # Store-truth: stranded non-terminal rows + stage/status breakdown. (Single-box gates no-loss
        # on the SINK-truth `acked_not_delivered==0`, so the all-stage dead total is surfaced in the
        # breakdown but not separately gated here — see ShardCertEngineReport for the two-box rationale.)
        stranded, _dead_all, breakdown = await _queue_breakdown(node_env)

    finally:
        if peak_task is not None and not peak_task.done():
            peak_stop.set()
            peak_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await peak_task
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
    ack = metrics.ack.summary()
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
        # D4: de-dup the N×-summed unified-store poller aggregate to a single store view (#841). This value
        # feeds ShardCertReport.ok/drained, unlike the advisory drive-side poller cross-checks (left as N×).
        in_pipeline_final=(final.in_pipeline // max(1, len(ids_list)) if final else -1),
        drained=drain_s is not None,
        drain_seconds=drain_s,
        stranded_nonterminal=stranded,
        queue_breakdown=breakdown,
        offered=round(aggregate_rate * hold_seconds),
        achieved_intake=ctr.acked,
        in_pipeline_peak=(peak_holder[0] if capture_peak else -1),
        ack_p50_ms=ack.p50_ms,
        ack_p99_ms=ack.p99_ms,
        recovery_seconds=recovery_seconds,
        notes=report_notes,
    )


# --- ascending rate-ladder (ceiling hunt) ------------------------------------


@dataclass(frozen=True)
class ShardCertStepRecord:
    """One hold step of the ascending rate ladder — the sizing bench's per-rate view. Metrics +
    metadata only (never message bodies / control-id lists — PHI rule)."""

    aggregate_rate: float
    offered: int
    achieved_intake: int
    delivered: int
    in_pipeline_peak: int
    ack_p50_ms: float
    ack_p99_ms: float
    drain_seconds: float | None
    no_loss: bool
    lane_inversions: int
    lane_repeats: int
    stranded_nonterminal: int

    @property
    def ceiling(self) -> bool:
        """The fleet could not SUSTAIN the offered load at this rate — the ladder stops climbing.

        A **throughput** ceiling, kept distinct from a **correctness** break (loss/inversion/dup still
        FAILs the ladder verdict — see :attr:`ShardCertLadderReport.ok`): the fleet either did not stay
        lossless-and-drained (``not no_loss`` — real acknowledged loss, or a backlog that never drained
        inside the drain window), or its accept-**intake** fell materially short of the offered rate
        (``achieved_intake < offered * (1 - _INTAKE_TOL)`` — the engines could not even ingest that
        fast). Deliberately **not** ``delivered < offered``, a MEASURED quantity that false-trips on the
        healthy token-bucket boundary-drop above ~200 msg/s and stopped the ladder early."""
        return (not self.no_loss) or (self.achieved_intake < self.offered * (1 - _INTAKE_TOL))

    @classmethod
    def from_report(cls, aggregate_rate: float, report: ShardCertReport) -> ShardCertStepRecord:
        return cls(
            aggregate_rate=aggregate_rate,
            offered=report.offered,
            achieved_intake=report.achieved_intake,
            delivered=report.delivered_distinct,
            in_pipeline_peak=report.in_pipeline_peak,
            ack_p50_ms=report.ack_p50_ms,
            ack_p99_ms=report.ack_p99_ms,
            drain_seconds=report.drain_seconds,
            no_loss=report.acked_not_delivered == 0 and report.drained,
            lane_inversions=report.lane_inversions,
            lane_repeats=report.lane_repeats,
            stranded_nonterminal=report.stranded_nonterminal,
        )

    def to_json_dict(self) -> dict[str, object]:
        return {
            "aggregate_rate": round(self.aggregate_rate, 3),
            "offered": self.offered,
            "achieved_intake": self.achieved_intake,
            "delivered": self.delivered,
            "in_pipeline_peak": self.in_pipeline_peak,
            "ack_ms": {"p50": round(self.ack_p50_ms, 3), "p99": round(self.ack_p99_ms, 3)},
            "drain_seconds": self.drain_seconds,
            "no_loss": self.no_loss,
            "lane_inversions": self.lane_inversions,
            "lane_repeats": self.lane_repeats,
            "stranded_nonterminal": self.stranded_nonterminal,
            "ceiling": self.ceiling,
        }

    def render(self) -> str:
        loss = "OK" if self.no_loss else "LOSS"
        drain = "n/a" if self.drain_seconds is None else f"{self.drain_seconds:.1f}s"
        return (
            f"rate={self.aggregate_rate:g}/s offered={self.offered} intake={self.achieved_intake} "
            f"delivered={self.delivered} | in_pipeline_peak={self.in_pipeline_peak} "
            f"ack p50/p99={self.ack_p50_ms:.1f}/{self.ack_p99_ms:.1f}ms drain={drain} | "
            f"no_loss={loss} inversions={self.lane_inversions} repeats={self.lane_repeats} "
            f"stranded={self.stranded_nonterminal}" + ("  <= CEILING" if self.ceiling else "")
        )


@dataclass
class ShardCertLadderReport:
    """The ascending rate-ladder sweep — one :class:`ShardCertStepRecord` per hold step, stopping at
    the first step that fails to SUSTAIN the offered load (:attr:`ShardCertStepRecord.ceiling` — a
    non-draining/lossy step or a materially-short intake)."""

    records: list[ShardCertStepRecord] = field(default_factory=list)
    ceiling_rate: float | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """Every step held the correctness invariants WHILE climbing (no acknowledged loss, per-lane
        FIFO, no stranded rows). The ceiling itself is a MEASUREMENT, not a failure."""
        return bool(self.records) and all(
            r.no_loss and r.lane_inversions == 0 and r.stranded_nonterminal == 0
            for r in self.records
        )

    @property
    def exit_code(self) -> int:
        return 0 if self.ok else 1

    def to_json_dict(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "kind": "shardcert_ladder",
            "result": "PASS" if self.ok else "FAIL",
            "exit_code": self.exit_code,
            "ceiling_rate": self.ceiling_rate,
            "records": [r.to_json_dict() for r in self.records],
            "notes": self.notes,
        }

    def render(self) -> str:
        lines = [
            "ShardCert rate-ladder (ascending; stops when the offered rate is not sustained)",
            "",
        ]
        for r in self.records:
            lines.append("  " + r.render())
        lines.append("")
        if self.ceiling_rate is not None:
            lines.append(f"  ceiling ~ {self.ceiling_rate:g} msg/s (aggregate)")
        else:
            lines.append("  no ceiling reached across the ladder (raise the top rate)")
        for note in self.notes:
            lines.append(f"  note: {note}")
        lines.append("")
        lines.append(f"RESULT: {'PASS' if self.ok else 'FAIL'} -> exit {self.exit_code}")
        return "\n".join(lines)


def parse_rate_ladder(spec: str) -> list[float]:
    """Parse the ``--rate-ladder`` spec into an ascending list of aggregate rates. Two forms:
    ``"40,80,120"`` (explicit comma list) or ``"start:stop:step"`` (``"40:200:40"`` ⇒ 40,80,…,200)."""
    spec = spec.strip()
    if ":" in spec:
        parts = spec.split(":")
        if len(parts) != 3:
            raise ValueError(f"rate-ladder range must be start:stop:step, got {spec!r}")
        start, stop, step = (float(p) for p in parts)
        if step <= 0:
            raise ValueError(f"rate-ladder step must be > 0, got {step}")
        rates: list[float] = []
        r = start
        while r <= stop + 1e-9:
            rates.append(round(r, 6))
            r += step
        if not rates:
            raise ValueError(f"rate-ladder range {spec!r} produced no rates")
        return rates
    rates = [float(x) for x in spec.split(",") if x.strip()]
    if not rates:
        raise ValueError(f"rate-ladder list {spec!r} named no rates")
    return rates


async def _run_ladder_step(
    *,
    rate: float,
    dests: int,
    hold_seconds: float,
    drain_timeout: float,
    store_env: Mapping[str, str] | None,
    cwd: Path | None,
    sink_host: str,
    sink_port: int | None,
) -> ShardCertStepRecord:
    """Drive ONE ladder hold step at ``rate`` (a full fresh-fleet ``run_shardcert``, no kill, peak
    sampled) and fold it into a :class:`ShardCertStepRecord`. A module-level seam so a unit test can
    substitute a synthetic step and exercise the climb/stop logic without a live SQL Server."""
    report = await run_shardcert(
        dests=dests,
        aggregate_rate=rate,
        hold_seconds=hold_seconds,
        kill=False,
        drain_timeout=drain_timeout,
        store_env=store_env,
        cwd=cwd,
        sink_host=sink_host,
        sink_port=sink_port,
        capture_peak=True,
    )
    return ShardCertStepRecord.from_report(rate, report)


async def run_shardcert_ladder(
    *,
    rates: Sequence[float],
    dests: int = 8,
    hold_seconds: float = 60.0,
    drain_timeout: float = 120.0,
    store_env: Mapping[str, str] | None = None,
    cwd: Path | None = None,
    sink_host: str = "127.0.0.1",
    sink_port: int | None = None,
) -> ShardCertLadderReport:
    """Run the ascending rate-ladder ceiling hunt: for each aggregate rate (sorted ascending), drive one
    hold step and record it; STOP at the first step that fails to SUSTAIN the offered load
    (:attr:`ShardCertStepRecord.ceiling` — a non-draining/lossy step, or an intake that fell materially
    short of offered). Each step is a fresh fleet + fresh store (mirrors ``multishard``'s per-step
    isolation), so the recorded intake/delivered/backlog are clean per rate. Correctness is asserted per
    step via :attr:`ShardCertLadderReport.ok` — the ceiling is a measurement, not a failure."""
    report = ShardCertLadderReport()
    ordered = sorted(dict.fromkeys(float(r) for r in rates))  # ascending, de-duplicated
    if not ordered:
        raise ValueError("run_shardcert_ladder needs at least one rate")
    for rate in ordered:
        rec = await _run_ladder_step(
            rate=rate,
            dests=dests,
            hold_seconds=hold_seconds,
            drain_timeout=drain_timeout,
            store_env=store_env,
            cwd=cwd,
            sink_host=sink_host,
            sink_port=sink_port,
        )
        report.records.append(rec)
        if rec.ceiling:
            report.ceiling_rate = rate
            report.notes.append(
                f"ceiling at {rate:g} msg/s: intake {rec.achieved_intake} of offered {rec.offered} "
                f"(no_loss={rec.no_loss}; sustain bar = offered*(1-{_INTAKE_TOL:g}))"
            )
            break
    return report


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


# =====================================================================================================
# WS-C two-box split — the engine-launcher half + the driver half, coordinated by the file-drop
# handshake. The co-located `run_shardcert` above stays byte-identical (single process, no coord); these
# two run as SEPARATE processes (one per box). See harness/load/coord.py for the two-message protocol.
#
# Reconciled onto the #836 LANES-AWARE base: the engine reserves N*lanes contiguous inbound ports and the
# driver opens one persistent connection per (shard, lane) — `lanes` is discovered from the built graph
# (`len(reg.inbound) // n`, exactly as the single-box `run_shardcert` derives it) and advertised in
# SHARDS_READY so the two halves stay in lock-step across the box boundary.
# =====================================================================================================


# --- shared setup helpers (used by the split engine/driver halves) ---------------------------------


def _discover(dests: int) -> tuple[list[str], dict[str, list[str]], int, int]:
    """Discover the shard set, per-shard owned destination lanes, shard count ``n``, and lanes-per-shard
    from the ``shardcert`` graph (with ``dests`` applied + the ambient ``MEFOR_SHARDCERT_LANES_PER_SHARD``)
    BEFORE serving. ``lanes`` is derived from the built graph (``len(reg.inbound) // n``) — the SAME
    derivation the single-box :func:`run_shardcert` uses — so the driver and the served graph stay in
    lock-step. Pure read of the config; no engine/store side effects."""
    with _env_scope({"MEFOR_SHARDCERT_DESTS": str(dests)}):
        reg = load_config(_CONFIG_DIR)
    ids_list = shard_ids(reg)
    owned = {s: sorted(owned_destination_set(reg, s, ids_list)) for s in ids_list}
    n = len(ids_list)
    lanes = (len(reg.inbound) // n) if n else 1
    return ids_list, owned, n, lanes


def _shape_env(
    ids_list: list[str],
    inbound_base: int,
    dests: int,
    sink_host: str,
    sink_port: int,
    sink_ports: int = 1,
) -> dict[str, str]:
    """The ``MEFOR_SHARDCERT_*`` graph-shape env every ``serve --shard`` process shares. ``sink_host`` is
    where the shards deliver their outbound fan-out (the load-gen box on a two-box run; loopback
    co-located); ``sink_port``/``sink_ports`` are the base + width of the sink port band the driver binds
    (a SINGLE sink for the correctness cert — the fan-out width is exercised in a later PR). The
    lanes-per-shard + persistent knobs ride ambiently on ``os.environ`` (the CLI/caller sets them before
    config load), so the discovered graph and the served graph agree."""
    return {
        "MEFOR_SHARDCERT_SHARDS": ",".join(ids_list),
        "MEFOR_SHARDCERT_INBOUND_BASE": str(inbound_base),
        "MEFOR_SHARDCERT_DESTS": str(dests),
        "MEFOR_SHARDCERT_SINK_HOST": sink_host,
        "MEFOR_SHARDCERT_SINK_PORT": str(sink_port),
        "MEFOR_SHARDCERT_SINK_PORTS": str(sink_ports),
        "MEFOR_SHARDCERT_TRANSFORM": "edit",
    }


def _escapes(inbound_bind_host: str) -> dict[str, str]:
    """The auth/insecure-TLS test escapes + the inbound bind interface every shard binds (``0.0.0.0`` on
    a two-box run so the off-box load-gen senders can reach it; loopback co-located)."""
    return {
        "MEFOR_ALLOW_INSECURE_TLS": "1",
        "MEFOR_ALLOW_INSECURE_CONFIG_SOURCE": "1",
        "MEFOR_AUTH_ENABLED": "false",
        "MEFOR_INBOUND_BIND_HOST": inbound_bind_host,
    }


def _choose_killed(
    kill: bool, kill_shard: str | None, ids_list: list[str], owned: dict[str, list[str]]
) -> str | None:
    """The shard the kill leg SIGKILLs: the pinned ``kill_shard`` if given, else the shard owning the
    MOST lanes (maximizes ownership-scoped recovery coverage). ``None`` when the run has no kill leg."""
    if not kill:
        return None
    if kill_shard is not None:
        return kill_shard
    return max(ids_list, key=lambda s: len(owned[s]))


async def _start_shards(
    ids_list: list[str],
    api_ports: list[int],
    *,
    node_env: Mapping[str, str],
    cwd: Path,
    inbound_base: int,
    lanes: int,
    preflight_host: str,
    nodes: dict[str, ShardCertNode],
) -> None:
    """Start each ``serve --shard`` STRICTLY one-at-a-time behind a health gate + inbound-port preflight
    (the SS schema-init applock convoys at N>=4 simultaneous opens). Each shard binds ``lanes`` inbound
    ports (lane ``l`` of shard ``i`` on ``inbound_base + i*lanes + l``); EVERY one is readiness-gated at
    ``preflight_host``. Populates ``nodes`` as it goes — a partially-started fleet is left in ``nodes`` so
    the caller's ``finally`` still tears it down."""
    for i, s in enumerate(ids_list):
        node = ShardCertNode(s, api_ports[i], env=node_env, config_dir=_CONFIG_DIR, cwd=cwd)
        await node.start()
        nodes[s] = node
        if not await _await_health(node.url, timeout=60.0):
            raise RuntimeError(f"shard {s} did not become healthy\n{node.log_tail()}")
        for lane in range(lanes):
            port = inbound_base + i * lanes + lane
            if not await _await_port(preflight_host, port, timeout=30.0):
                raise RuntimeError(f"shard {s} inbound lane port {port} never bound")


async def _drive_load(
    conns: list[PersistentConnection],
    corpus: Any,
    mix: TypeMix,
    metrics: LiveMetrics,
    *,
    aggregate_rate: float,
    hold_seconds: float,
) -> None:
    """Drive an aggregate token-bucket load round-robin across the N*lanes shard-lane connections for
    ``hold_seconds`` — the DRIVER-half loop with NO kill (the SIGKILL stays engine-box-local on a timer).
    Same schedule/deferral accounting as the co-located bench's inline loop, minus the kill check."""
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


def _kill_delay(kill_at_fraction: float, hold_seconds: float) -> float:
    """How long after the driver's ``DRIVE_START`` the engine-local SIGKILL fires: ``fraction × hold``.
    Anchoring on the engine's OBSERVATION of ``DRIVE_START`` (not a shared wall clock) means the two
    boxes never compare monotonic clocks — the sub-poll-interval handshake latency is negligible."""
    return max(0.0, kill_at_fraction * hold_seconds)


async def _kill_after(node: ShardCertNode, delay: float) -> float:
    """Sleep ``delay`` seconds then SIGKILL ``node`` (a LOCAL PID — never remoted). Returns the monotonic
    kill instant so the engine half can time functional recovery from it."""
    await asyncio.sleep(delay)
    node.kill()
    return time.monotonic()


@dataclass
class ShardCertEngineReport:
    """The ENGINE half's outcome — the store-truth signals that need direct store access (stranded
    non-terminal rows + the stage/status breakdown) plus its OWN ``/stats`` drain gauge, the ownership
    map, and recovery timing. The sink/tracker VERDICT (no-loss, per-lane FIFO, duplicates) is the DRIVER
    half's report — the engine box never sees the sink."""

    shards: tuple[str, ...]
    owned: dict[str, list[str]]
    killed_shard: str | None
    stranded_nonterminal: int
    queue_breakdown: str
    # The engine drains its OWN /stats before the store-truth read, so it carries a self-contained
    # store-truth verdict (`ok`). Defaulted so an older report / a partial run deserializes unchanged.
    drained: bool = False
    engine_dead: int = 0
    # All-stage dead-letter count (store-truth). `engine_dead` above is `stats().dead`, which is
    # OUTBOUND-stage-scoped; a router/handler regression dead-letters at the INGRESS or ROUTED stage
    # (`dead_letter_now` leaves `stage` unchanged), which `engine_dead` misses. Those rows were
    # ACK-on-receipt'd, so they are acknowledged loss the engine's OWN store-truth verdict must catch
    # without leaning on the driver half's sink-truth. Defaulted so an older report deserializes unchanged.
    dead_total: int = 0
    in_pipeline_final: int = -1
    recovery_seconds: float | None = None
    #: D1: the engine-side drain duration (this box's own await_drain elapsed) — the RELIABLE drain the drive
    #: uses for the honest sustainable rate (its own remote drain misses under load). Guaranteed non-None
    #: whenever the fleet drained (drained ⇒ drain_s is not None). Defaulted so an older report deserializes
    #: unchanged.
    drain_seconds: float | None = None
    # Per-shard subprocess identity for the operator's EXTERNAL per-PID CPU capture (Get-Process
    # TotalProcessorTime deltas): shard id -> (node_id, live PID). The SAME map is advertised in
    # SHARDS_READY, so a per-PID CPU sample maps unambiguously to a node identity. On the kill leg the
    # killed shard's PID is its RESTARTED subprocess's (the one that survives to drain) — the pre-kill PID
    # is gone. Defaulted so an older report / a partial run deserializes unchanged.
    node_pids: dict[str, tuple[str, int | None]] = field(default_factory=dict)
    # Soak-only (default empty ⇒ the correctness/climb path is unchanged): a bounded in-HOLD trace of the
    # fleet's OWN /stats in_pipeline gauge, ``[[elapsed_s, in_pipeline], ...]``, sampled when
    # ``sample_in_pipeline=True``. Each shard's /stats in_pipeline counts the WHOLE unified store and the
    # poller sums the N shard URLs, so the sampler DE-DUPS by dividing each reading by the distinct-shard
    # count (#841) — the recorded absolute value AND the derived slope are a single store view, not N×. The
    # TREND (flat/draining vs monotonic growth) is the sustainable-vs-slow-saturation discriminator the
    # PR-C2 soak needs — a slow-saturation plateau looks lossless for ~60s but its backlog slope is
    # positive. Metadata only (a gauge count over time — never a payload / control-id).
    in_pipeline_trace: list[list[float]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """Engine-side store-truth pass bar: the fleet drained, no stranded non-terminal rows, and no
        dead-letters at ANY stage (`dead_total`, not just the outbound-scoped `engine_dead`) — an
        ingress/routed dead-letter is acked-on-receipt loss, so a self-contained store-truth verdict must
        fail on it. The no-loss / per-lane-FIFO / duplicate VERDICT is the DRIVER report's (it holds the
        sink/tracker); the engine owns the store-truth reconcile."""
        return (
            self.drained
            and self.stranded_nonterminal == 0
            and self.engine_dead == 0
            and self.dead_total == 0
        )

    def render(self) -> str:
        lines = [
            f"ShardCert ENGINE {'/'.join(self.shards)}  verdict={'PASS' if self.ok else 'FAIL'}"
            + (f"  killed={self.killed_shard}" if self.killed_shard else "  (baseline, no kill)"),
            f"  stranded_nonterminal_rows={self.stranded_nonterminal} "
            f"drained={self.drained} engine_dead={self.engine_dead} "
            f"dead_total={self.dead_total} "
            f"in_pipeline_final={self.in_pipeline_final}",
            "  ownership: "
            + " ".join(f"{s}->[{','.join(self.owned[s]) or '-'}]" for s in self.shards),
            f"  {self.queue_breakdown}",
        ]
        if self.node_pids:
            lines.append(
                "  node PIDs (for per-PID CPU correlation): "
                + " ".join(
                    f"{s}:{self.node_pids[s][0]}=pid{self.node_pids[s][1]}"
                    for s in self.shards
                    if s in self.node_pids
                )
            )
        if self.recovery_seconds is not None:
            lines.append(f"  recovery_seconds(reported, not gated)={self.recovery_seconds:.2f}")
        for note in self.notes:
            lines.append(f"  note: {note}")
        return "\n".join(lines)


@dataclass
class ShardCertDriverReport:
    """The DRIVER half's outcome — the sink/tracker-derived verdict signals (identical to the co-located
    ``ShardCertReport``'s), plus the engine done/dead/in_pipeline read from the REMOTE ``/stats`` at
    drain. The store-truth stranded/queue-breakdown is the ENGINE half's report."""

    shards: tuple[str, ...]
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
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """Driver-side pass bar: zero acknowledged loss, drained pipeline (remote ``/stats``), per-lane
        FIFO (non-vacuous), no dead-letters. Duplicates are allowed only across a kill. The stranded-row
        check lives on the ENGINE report (it needs direct store access)."""
        dup_ok = self.lane_repeats == 0 if self.killed_shard is None else True
        return (
            self.acked > 0
            and self.acked_not_delivered == 0
            and self.drained
            and self.in_pipeline_final == 0
            and self.engine_dead == 0
            and self.lane_inversions == 0
            and self.lanes_observed >= 2
            and dup_ok
        )

    def render(self) -> str:
        lines = [
            f"ShardCert DRIVER {'/'.join(self.shards)}  verdict={'PASS' if self.ok else 'FAIL'}"
            + (f"  killed={self.killed_shard}" if self.killed_shard else "  (baseline, no kill)"),
            f"  sent={self.sent} acked={self.acked} delivered_distinct={self.delivered_distinct} "
            f"sink_received={self.sink_received}",
            f"  acked_not_delivered={self.acked_not_delivered} (0 = no acknowledged loss)",
            f"  lane_inversions={self.lane_inversions} lanes_observed={self.lanes_observed} "
            f"lane_repeats(dups)={self.lane_repeats}",
            f"  engine done={self.engine_done} dead={self.engine_dead} "
            f"in_pipeline_final={self.in_pipeline_final} drained={self.drained} "
            f"drain_s={self.drain_seconds}",
        ]
        for note in self.notes:
            lines.append(f"  note: {note}")
        return "\n".join(lines)


async def run_shardcert_engine(
    *,
    dests: int = 8,
    hold_seconds: float = 20.0,
    kill: bool = False,
    kill_shard: str | None = None,
    kill_at_fraction: float = 0.4,
    drain_timeout: float = 90.0,
    sink_port: int,
    sink_ports: int = 1,
    store_env: Mapping[str, str] | None = None,
    cwd: Path | None = None,
    coord: FileDropCoord,
    inbound_bind_host: str = "0.0.0.0",
    sink_host: str = "127.0.0.1",
    claim_mode: str = "pooled",
    drive_start_timeout: float = 300.0,
    post_drain_grace: float = 3.0,
    signal_drained: bool = False,
    sample_in_pipeline: bool = False,
    sample_interval: float = 2.0,
) -> ShardCertEngineReport:
    """The ENGINE-box half (WS-C option #2). Brings the ``serve --shard`` fleet up against the ONE
    unified store, posts :data:`SHARDS_READY` with the topology, waits for the driver's
    :data:`DRIVE_START`, arms a LOCAL SIGKILL timer for the kill leg, restarts the killed shard, drains
    its OWN ``/stats``, reads the store-truth queue breakdown, and tears the fleet down. It NEVER drives
    load and NEVER binds the sink — those are the driver box's job (the client-isolation the
    attribution policy requires).

    Reconciled onto the #836 lanes-aware base: ``lanes`` per shard is discovered from the built graph and
    the fleet reserves + preflights ``N*lanes`` contiguous inbound ports (lane ``l`` of shard ``i`` on
    ``inbound_base + i*lanes + l``); the lanes-per-shard + persistent knobs are read ambiently from
    ``os.environ`` (the CLI sets them before config load, as the single-box path does). ``sink_host`` is
    the load-gen box (where the shards deliver); ``sink_port``/``sink_ports`` are the sink port band the
    driver binds (single sink for the correctness cert; the band is advertised now for the PR-C fan-out).
    ``store_env`` must point every ``serve`` at the unified store (``MEFOR_STORE_*``).

    ``claim_mode`` (``pooled`` | ``per_lane``, ADR 0066 §8.2) is set first-class on EVERY ``serve --shard``
    subprocess via ``MEFOR_PIPELINE_CLAIM_MODE`` so the pooled-vs-per_lane A/B arm is unambiguous in the
    run record, not left to whatever happened to be in the parent env.

    ``signal_drained`` (default OFF ⇒ the standalone C1 cert path is byte-identical) posts the
    :data:`ENGINE_DRAINED` message once the DIRECT store-truth read confirms the pipeline drained — the
    reliable drain gate the PR-C2 ladder's DRIVE half waits on before tallying its sinks, so a
    teardown-frozen in-flight tail is absorbed BEFORE the tally rather than mis-read as loss. It is posted
    with the store-truth (``drained``/``stranded``/``dead_total``/``in_pipeline_final``), never the remote
    poller's gauges."""
    import os

    cwd = cwd or Path.cwd()
    store_env = dict(store_env or {})
    ids_list, owned, n, lanes = _discover(dests)
    # Ports: N*lanes contiguous inbound (lane l of shard i on base + i*lanes + l), N API. The DRIVER binds
    # the sink — the ENGINE only advertises the port band.
    inbound_base = _free_contiguous(n * lanes)
    api_ports = _reserve_ports(n)
    shape_env = _shape_env(ids_list, inbound_base, dests, sink_host, sink_port, sink_ports)
    escapes = _escapes(inbound_bind_host)
    store_env.setdefault("MEFOR_STORE_POOL_SIZE", "8")
    node_env = {**os.environ, **store_env, **shape_env, **escapes}
    # First-class claim-mode pin (ADR 0066 §8.2): set explicitly so the A/B arm is unambiguous in the run
    # record, not left to whatever MEFOR_PIPELINE_CLAIM_MODE happened to be in the parent env.
    node_env["MEFOR_PIPELINE_CLAIM_MODE"] = claim_mode

    await _reset_store(node_env)

    killed = _choose_killed(kill, kill_shard, ids_list, owned)
    nodes: dict[str, ShardCertNode] = {}
    notes: list[str] = []
    recovery_seconds: float | None = None
    stranded = -1
    breakdown = "QUEUE <not-read>"
    drained = False
    engine_dead = 0
    in_pipeline_final = -1
    node_pids: dict[str, tuple[str, int | None]] = {}
    in_pipeline_trace: list[list[float]] = []
    try:
        # Bring the fleet up. Preflight the engine's OWN inbound bind on loopback (127.0.0.1 reaches a
        # 0.0.0.0 listener) — the DRIVER separately proves off-box reachability from its side.
        await _start_shards(
            ids_list,
            api_ports,
            node_env=node_env,
            cwd=cwd,
            inbound_base=inbound_base,
            lanes=lanes,
            preflight_host="127.0.0.1",
            nodes=nodes,
        )
        # Per-PID CPU-correlation map: each live shard subprocess's (node_id, PID). Captured right after
        # the fleet is up (before any kill) so the operator's EXTERNAL per-PID CPU capture maps each
        # reading to a shard/node identity. Advertised in SHARDS_READY AND returned in the report.
        node_pids = {s: (nodes[s].node_id, getattr(nodes[s], "pid", None)) for s in ids_list}
        # Message 1: advertise the topology the driver needs — the inbound base + lanes-per-shard (so the
        # driver opens N*lanes connections at base + i*lanes + l), the destination count, the sink port
        # BAND to bind (base + width), the API ports to poll, the shard set, which shard gets killed — plus
        # the per-shard subprocess identity (PID + node id + role) for external per-PID CPU attribution.
        # Metadata only — no PHI.
        coord.post(
            SHARDS_READY,
            {
                "shards": list(ids_list),
                "inbound_base": inbound_base,
                "lanes": lanes,
                "dests": dests,
                "api_ports": list(api_ports),
                "sink_port": sink_port,
                "sink_base": sink_port,
                "sink_ports": sink_ports,
                "killed": killed,
                "hold_seconds": hold_seconds,
                "kill_at_fraction": kill_at_fraction,
                "claim_mode": claim_mode,
                "nodes": [
                    {
                        "shard": s,
                        "node_id": node_pids[s][0],
                        "pid": node_pids[s][1],
                        "role": "engine-shard",
                    }
                    for s in ids_list
                ],
            },
        )
        # Message 2 (inbound): the driver has bound its sink + opened its senders and is now driving.
        drive = await coord.await_message(DRIVE_START, timeout=drive_start_timeout)
        notes.append(f"observed DRIVE_START (driver t0={drive.get('t0')})")
        t0_local = time.monotonic()

        # Arm the LOCAL SIGKILL timer relative to WHEN WE OBSERVED DRIVE_START (no cross-box clock
        # compare). The kill is a local PID op on a timer — WS-C has no remote-kill leg.
        kill_task: asyncio.Task[float] | None = None
        if kill and killed is not None:
            delay = _kill_delay(kill_at_fraction, hold_seconds)
            kill_task = asyncio.create_task(_kill_after(nodes[killed], delay))
            notes.append(
                f"armed local SIGKILL of {killed} at +{delay:.2f}s (~{kill_at_fraction:.0%} of hold)"
            )

        # Hold locally so the killed shard is restarted AFTER the hold (mirrors the co-located sequence).
        # Soak-only: sample the fleet's OWN in_pipeline gauge across the hold so the PR-C2 soak can report
        # the backlog SLOPE (flat/draining vs a slow-saturation positive slope). Off by default ⇒ the
        # correctness/climb path adds no concurrent poller during the hold.
        trace_stop = asyncio.Event()
        trace_task: asyncio.Task[None] | None = None
        if sample_in_pipeline:
            trace_task = asyncio.create_task(
                _sample_in_pipeline_trace(
                    [nodes[s].url for s in ids_list],
                    trace_stop,
                    in_pipeline_trace,
                    interval=sample_interval,
                )
            )
        try:
            await asyncio.sleep(max(0.0, hold_seconds - (time.monotonic() - t0_local)))
        finally:
            if trace_task is not None:
                trace_stop.set()
                with contextlib.suppress(Exception):
                    await trace_task
        kill_at: float | None = None
        if kill_task is not None:
            kill_at = await kill_task

        # Kill leg: restart the killed shard (supervisor-style) so its startup runs the ownership-scoped
        # reset over ITS lanes; time functional recovery from the kill instant.
        if kill and killed is not None:
            idx = ids_list.index(killed)
            restart = ShardCertNode(
                killed, api_ports[idx], env=node_env, config_dir=_CONFIG_DIR, cwd=cwd
            )
            await restart.start()
            nodes[killed] = restart
            # The restarted shard is a NEW subprocess (new PID) — refresh the correlation map so a
            # post-kill CPU sample attributes to the survivor process, not the reaped pre-kill one.
            node_pids[killed] = (restart.node_id, getattr(restart, "pid", None))
            if not await _await_health(restart.url, timeout=60.0):
                raise RuntimeError(f"shard {killed} did not restart\n{restart.log_tail()}")
            if kill_at is not None:
                recovery_seconds = time.monotonic() - kill_at

        # Drain the fleet's OWN /stats (keep the shards up until the store empties), then read the
        # store-truth stranded/breakdown before tearing down. The drain gauge + dead count give the engine
        # its self-contained store-truth verdict. A short post-drain grace so the driver's own REMOTE
        # drain poll doesn't race the shard teardown (both read the same store).
        urls = [nodes[s].url for s in ids_list]
        poller = EnginePoller(urls, None, origin=time.perf_counter())
        await poller.open()
        try:
            drain_s = await poller.await_drain(timeout=drain_timeout, interval=0.5)
            final = poller.final
        finally:
            await poller.close()
        drained = drain_s is not None
        engine_dead = final.dead if final else 0
        # D4: de-dup the N×-summed unified-store poller aggregate to a single store view (#841). This is
        # stored on ShardCertEngineReport AND posted in the ENGINE_DRAINED gate, so the two-box report's
        # engine_in_pipeline_final is the TRUE fleet backlog, not N× it.
        in_pipeline_final = final.in_pipeline // max(1, len(ids_list)) if final else -1
        stranded, dead_total, breakdown = await _queue_breakdown(node_env)
        # PR-C2 ladder drain gate (default OFF): once the DIRECT store read above confirms drain, tell the
        # DRIVE half it is safe to tally its sinks — the reliable authority (stranded/dead), never the
        # remote poller. Posted BEFORE the grace/teardown, but by construction stranded==0 means every
        # delivery already landed on the sink sockets, so there is no tail left to lose at teardown.
        if signal_drained:
            coord.post(
                ENGINE_DRAINED,
                {
                    "drained": drained,
                    "stranded": stranded,
                    "dead_total": dead_total,
                    "in_pipeline_final": in_pipeline_final,
                    # The RELIABLE engine-side drain time (this box's own await_drain). Guaranteed non-None
                    # whenever engine_ok (drained ⇒ drain_s is not None), so the drive uses it for the honest
                    # sustainable rate (D1) instead of its advisory remote drain, which misses under load.
                    "drain_seconds": drain_s,
                    # engine-side store-truth pass bar for THIS rung (drive folds it into the classifier)
                    "engine_ok": bool(
                        drained and stranded == 0 and engine_dead == 0 and dead_total == 0
                    ),
                },
            )
        await asyncio.sleep(post_drain_grace)
    finally:
        for node in nodes.values():
            with contextlib.suppress(Exception):
                await node.stop()

    return ShardCertEngineReport(
        shards=tuple(ids_list),
        owned=owned,
        killed_shard=killed,
        stranded_nonterminal=stranded,
        queue_breakdown=breakdown,
        drained=drained,
        engine_dead=engine_dead,
        dead_total=dead_total,
        in_pipeline_final=in_pipeline_final,
        recovery_seconds=recovery_seconds,
        drain_seconds=drain_s,
        node_pids=node_pids,
        in_pipeline_trace=in_pipeline_trace,
        notes=notes,
    )


async def run_shardcert_driver(
    *,
    engine_host: str,
    aggregate_rate: float = 40.0,
    hold_seconds: float = 20.0,
    drain_timeout: float = 90.0,
    coord: FileDropCoord,
    sink_host: str = "127.0.0.1",
    shards_ready_timeout: float = 300.0,
    inbound_ready_timeout: float = 60.0,
    allow_insecure: bool = False,
) -> ShardCertDriverReport:
    """The LOAD-GEN-box half (WS-C option #2). Waits for :data:`SHARDS_READY`, binds the correlation
    sink LOCALLY (``sink_host`` — the load-gen box) over the advertised port band, opens one persistent
    MLLP connection per (shard, lane) inbound against the ENGINE box
    (``engine_host:inbound_base + i*lanes + l`` — the lanes-aware many-thin-lane shape), posts
    :data:`DRIVE_START`, drives the aggregate load (NO kill — the engine owns that), then drains against
    the engine's REMOTE ``/stats`` and computes the sink/tracker verdict. It NEVER spawns an engine and
    NEVER touches the store — the whole point is CPU isolation from the engine box.

    The lanes-per-shard + sink port band are learned from SHARDS_READY (default ``lanes=1`` /
    ``sink_ports=1`` so an older engine's payload still drives), so the driver's connection set matches
    the served graph exactly."""
    ready = await coord.await_message(SHARDS_READY, timeout=shards_ready_timeout)
    ids_list = [str(s) for s in ready["shards"]]
    inbound_base = int(ready["inbound_base"])
    lanes = int(ready.get("lanes", 1))
    api_ports = [int(p) for p in ready["api_ports"]]
    sink_base = int(ready.get("sink_base", ready["sink_port"]))
    sink_ports = int(ready.get("sink_ports", 1))
    killed_raw = ready.get("killed")
    killed = str(killed_raw) if killed_raw is not None else None
    n = len(ids_list)

    ids = ControlIds(prefix="SC")
    metrics = LiveMetrics(counters=Counters(), ack=Histogram(), e2e=Histogram())
    correlator = Correlator(capacity=1 << 20, metrics=metrics)
    tracker = FailoverTracker()
    corpus = build_corpus(load_profile_text(_CORPUS_PROFILE, where="<shardcert>"), ids)
    mix = TypeMix({"ADT^A01": 1.0})
    # The sink binds on the LOAD-GEN box (`sink_host`) over the advertised port band — it IS the engine's
    # outbound destination and holds the verdict signal (tracker/correlator), so it lives with the drive
    # side. A single port for the correctness cert; the band is wider only for the PR-C sink fan-out.
    sink_bind_ports = tuple(sink_base + k for k in range(sink_ports))
    sink = CorrelationSink(
        ids, correlator, metrics, host=sink_host, ports=sink_bind_ports, tracker=tracker
    )
    conns: list[PersistentConnection] = []
    poller: EnginePoller | None = None
    notes: list[str] = []
    try:
        await sink.start()
        # One persistent connection per (shard, lane) inbound (N*lanes total), dialing the ENGINE box's
        # inbound IP at base + i*lanes + l — the lanes-aware many-thin-lane shape.
        for i in range(n):
            for lane in range(lanes):
                pc = PersistentConnection(
                    engine_host,
                    inbound_base + i * lanes + lane,
                    correlator,
                    metrics,
                    expect_ack=True,
                    tracker=tracker,
                )
                pc.start()
                conns.append(pc)
        # Prove the exact off-box reachability the drive will use before posting DRIVE_START — every
        # (shard, lane) inbound port.
        for i in range(n):
            for lane in range(lanes):
                port = inbound_base + i * lanes + lane
                if not await _await_port(engine_host, port, timeout=inbound_ready_timeout):
                    raise RuntimeError(
                        f"engine inbound {engine_host}:{port} not reachable from the load-gen box"
                    )
        # Message 2: tell the engine we're driving now (t0 informational — the engine anchors its kill
        # timer on ITS observation of this message, not on a cross-box clock).
        coord.post(DRIVE_START, {"t0": time.time()})
        await _drive_load(
            conns, corpus, mix, metrics, aggregate_rate=aggregate_rate, hold_seconds=hold_seconds
        )
        await asyncio.gather(*(c.stop(2.0) for c in conns))

        # Drain against the engines' REMOTE /stats — the authoritative drain signal, polled off-box.
        # allow_insecure: the remote engine API is plaintext http, so the poller needs it (loopback
        # never does) — else poller.open() fail-closes on the non-loopback http URL.
        urls = [f"http://{engine_host}:{p}" for p in api_ports]
        poller = EnginePoller(urls, None, origin=time.perf_counter(), allow_insecure=allow_insecure)
        await poller.open()
        drain_s = await poller.await_drain(timeout=drain_timeout, interval=0.5)
        final = poller.final
    finally:
        if poller is not None:
            with contextlib.suppress(Exception):
                await poller.close()
        for pc in conns:
            with contextlib.suppress(Exception):
                await pc.stop(0.5)
        with contextlib.suppress(Exception):
            await sink.stop()

    ctr = metrics.counters
    return ShardCertDriverReport(
        shards=tuple(ids_list),
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
        notes=notes,
    )


# =====================================================================================================
# WS-C multi-process SIZING drive (PR-C1) — over-provision the CLIENT tier into K sender processes + M
# sink processes, all on the load-gen box (NEVER co-located with the engine fleet — the attribution
# isolation), so a plateau reflects the ENGINE/STORE ceiling rather than a single sender's ~457/s ACK
# ceiling or a single sink's ~100-140/s. The coord channel is metadata-only, so splitting senders from
# sinks across processes forbids per-message acked↔delivered correlation (PR-B's FailoverTracker saw both
# sides in ONE proc); the reconcile becomes COUNT-BALANCE + engine store-truth, NOT per-message. See the
# PR-C spec + coord.py for the message protocol. The single-box run_shardcert + the PR-B two-box halves +
# the #836 ladder are UNCHANGED — this is purely additive, reusing their helpers.
# =====================================================================================================


# --- port/band partition helpers (fail loud — a silent gap understates delivered → false PASS) -------


def _partition_band(base: int, width: int, count: int) -> list[list[int]]:
    """Partition the contiguous port band ``[base, base+width)`` into ``count`` CONTIGUOUS, non-empty,
    non-overlapping chunks that EXACTLY tile the band (chunk ``k`` is the sink ``k`` binds).

    **Fail loud** (:class:`ValueError`) on ``count > width`` (some sink would bind no ports),
    ``count < 1`` / ``width < 1``, or any gap/overlap/empty chunk — a silently-unbound destination port
    would drop deliveries the reconcile never counts, understating ``S`` and FALSE-PASSing no-loss. The
    first ``width % count`` chunks are one port wider so the tiling is exact."""
    if count < 1:
        raise ValueError(f"sink_count must be >= 1, got {count}")
    if width < 1:
        raise ValueError(f"sink_ports must be >= 1, got {width}")
    if count > width:
        raise ValueError(
            f"sink_count ({count}) > sink_ports ({width}): a sink would bind no ports — give each sink "
            "at least one destination port (set sink_ports == dests and sink_count <= dests)"
        )
    q, r = divmod(width, count)
    chunks: list[list[int]] = []
    port = base
    for k in range(count):
        size = q + (1 if k < r else 0)
        chunks.append(list(range(port, port + size)))
        port += size
    # Belt-and-suspenders: the chunks must EXACTLY tile [base, base+width) with no gap/overlap/empty
    # chunk — fail loud if the arithmetic above ever failed to (defends against a future edit).
    flat = [p for chunk in chunks for p in chunk]
    if flat != list(range(base, base + width)) or any(not chunk for chunk in chunks):
        raise ValueError(
            f"sink band partition of [{base},{base + width}) into {count} did not tile cleanly: {chunks}"
        )
    return chunks


@dataclass
class ShardCertSinkReport:
    """One SINK process's outcome — the delivered/order tally over ITS owned destination-port chunk.

    Every accepted message fans to ALL ``dests`` outbound destinations, so a given (shard, lane, dest)
    FIFO lane always maps to exactly one sink (the one owning that dest's port) — per-lane ordering is
    sink-local-sound. And because every lane fans to every dest, EVERY sink observes EVERY lane, so
    ``lanes_observed`` is already the full lane count per sink (the coordinator asserts agreement / takes
    the max across sinks — it never SUMS, which would multiply-count the shared lanes). Counts + the
    bound port numbers (synthetic topology) only — never control-ids / bodies (PHI rule)."""

    sink_index: int
    sink_count: int
    ports: tuple[int, ...]
    sink_received: int
    lane_inversions: int
    lane_repeats: int
    lanes_observed: int
    notes: list[str] = field(default_factory=list)

    def render(self) -> str:
        lines = [
            f"ShardCert SINK {self.sink_index}/{self.sink_count}  "
            f"ports={','.join(str(p) for p in self.ports) or '-'}",
            f"  sink_received={self.sink_received} lane_inversions={self.lane_inversions} "
            f"lane_repeats(dups)={self.lane_repeats} lanes_observed={self.lanes_observed}",
        ]
        for n in self.notes:
            lines.append(f"  note: {n}")
        return "\n".join(lines)

    def to_json_dict(self) -> dict[str, object]:
        """Counts + synthetic port topology only (never message bodies / control-id lists — PHI rule)."""
        return {
            "schema_version": 1,
            "kind": "shardcert_sink",
            "sink_index": self.sink_index,
            "sink_count": self.sink_count,
            "ports": list(self.ports),
            "sink_received": self.sink_received,
            "lane_inversions": self.lane_inversions,
            "lane_repeats": self.lane_repeats,
            "lanes_observed": self.lanes_observed,
            "notes": self.notes,
        }


async def run_shardcert_sink(
    *,
    sink_host: str = "127.0.0.1",
    sink_base: int,
    sink_ports: int,
    sink_index: int,
    sink_count: int,
    coord: FileDropCoord,
    drive_complete_timeout: float = 600.0,
    post_complete_grace: float = 2.0,
) -> ShardCertSinkReport:
    """One SINK-tier process of the multi-process drive. Binds a :class:`CorrelationSink` (its OWN
    ``Correlator`` + ``FailoverTracker`` + ``LiveMetrics``) over its CONTIGUOUS chunk of the
    ``[sink_base, sink_base+sink_ports)`` (== ``dests``) destination-port band — chunk ``sink_index`` of
    the ``sink_count`` partition — posts :data:`SINK_BOUND`.``<sink_index>`` once bound, absorbs the
    engine's outbound fan-out until it observes the coordinator's :data:`DRIVE_COMPLETE` (or a bounded
    ``drive_complete_timeout``), then records its final tally and posts :data:`SINK_DONE`.``<sink_index>``.

    It binds a sink but NEVER drives load and NEVER spawns an engine — the sender tier
    (:func:`run_shardcert_driver_worker`) drives, the coordinator (:func:`run_shardcert_drive`) spawns.
    **Fail loud** if ``sink_index`` is out of range or the band does not partition cleanly (see
    :func:`_partition_band`) — a silently-unbound port would drop deliveries the reconcile never counts."""
    if not (0 <= sink_index < sink_count):
        raise ValueError(
            f"sink_index {sink_index} out of range [0,{sink_count}) — a sink can only bind an existing "
            "partition chunk"
        )
    chunk = _partition_band(sink_base, sink_ports, sink_count)[sink_index]
    chunk_ports = tuple(chunk)

    ids = ControlIds(prefix="SC")
    metrics = LiveMetrics(counters=Counters(), ack=Histogram(), e2e=Histogram())
    correlator = Correlator(capacity=1 << 20, metrics=metrics)
    tracker = FailoverTracker()
    sink = CorrelationSink(
        ids, correlator, metrics, host=sink_host, ports=chunk_ports, tracker=tracker
    )
    notes: list[str] = []
    try:
        await sink.start()
        # Advertise that THIS sink's port chunk is bound (metadata: which ports it owns) so the
        # coordinator can gate the drive on every sink being ready before releasing the senders.
        coord.post(
            f"{SINK_BOUND}.{sink_index}",
            {"sink_index": sink_index, "ports": list(chunk_ports)},
        )
        # Absorb the fan-out until the coordinator says the engine has drained (DRIVE_COMPLETE), then the
        # tally is final. A bounded max-wait so a lost DRIVE_COMPLETE can't hang the sink forever — it
        # reports its partial tally with a note (the coordinator's reconcile will catch the shortfall).
        try:
            await coord.await_message(DRIVE_COMPLETE, timeout=drive_complete_timeout)
        except CoordTimeout:
            notes.append(
                f"DRIVE_COMPLETE not observed within {drive_complete_timeout}s — reporting partial tally"
            )
        # A short grace so any in-flight delivery already on the socket is absorbed before the tally read.
        if post_complete_grace > 0:
            await asyncio.sleep(post_complete_grace)
    finally:
        with contextlib.suppress(Exception):
            await sink.stop()

    ctr = metrics.counters
    report = ShardCertSinkReport(
        sink_index=sink_index,
        sink_count=sink_count,
        ports=chunk_ports,
        sink_received=ctr.sink_received,
        lane_inversions=tracker.lane_inversions,
        lane_repeats=tracker.lane_repeats,
        lanes_observed=tracker.lanes_observed,
        notes=notes,
    )
    # Metadata-only DONE drop: counts + the synthetic port topology, never control-ids / bodies.
    coord.post(
        f"{SINK_DONE}.{sink_index}",
        {
            "sink_index": sink_index,
            "sink_received": report.sink_received,
            "lane_inversions": report.lane_inversions,
            "lane_repeats": report.lane_repeats,
            "lanes_observed": report.lanes_observed,
            "ports": list(chunk_ports),
        },
    )
    return report


# --- sender tier (band-slice worker, external sinks) -------------------------------------------------


def _band_slice(total_bands: int, driver_count: int, driver_index: int) -> tuple[int, int]:
    """Sender-worker ``driver_index``'s CONTIGUOUS band slice ``[start, stop)`` of the
    ``total_bands = shards*lanes`` inbound bands. ``B = ceil(total_bands/driver_count)``; worker ``j`` owns
    ``[j*B, min((j+1)*B, total_bands))`` (the last clamped to the end).

    **Fail loud** (:class:`ValueError`) on ``driver_index`` out of range, ``driver_count > total_bands``
    (a worker would drive no bands), or an EMPTY slice for this worker (a ``driver_count`` that doesn't
    tile the bands leaves some worker idle) — a silently-undriven band would understate offered/delivered
    and false-PASS the sizing reconcile. Choose a ``driver_count`` that tiles ``total_bands``."""
    if driver_count < 1:
        raise ValueError(f"driver_count must be >= 1, got {driver_count}")
    if not (0 <= driver_index < driver_count):
        raise ValueError(f"driver_index {driver_index} out of range [0,{driver_count})")
    if driver_count > total_bands:
        raise ValueError(
            f"driver_count ({driver_count}) > bands G={total_bands}: a worker would drive no bands — "
            "use at most one sender-worker per band"
        )
    b = -(-total_bands // driver_count)  # ceil division
    start = driver_index * b
    stop = min(start + b, total_bands)
    if start >= stop:
        raise ValueError(
            f"sender-worker {driver_index}/{driver_count} owns an EMPTY band slice of G={total_bands} "
            f"(B={b}); choose a driver_count that tiles the bands"
        )
    return start, stop


@dataclass
class ShardCertDriverWorkerReport:
    """One SENDER-tier process's outcome — the intake tally over ITS owned band slice. Counts only (never
    control-ids / message bodies — PHI rule); the delivered/order VERDICT is the sinks' + the coordinator's
    (a metadata-only coord can't correlate this proc's acks to another proc's deliveries per-message)."""

    driver_index: int
    driver_count: int
    bands: tuple[int, ...]
    sent: int
    acked: int
    ack_p50_ms: float
    ack_p99_ms: float
    notes: list[str] = field(default_factory=list)

    def render(self) -> str:
        lines = [
            f"ShardCert DRIVER-WORKER {self.driver_index}/{self.driver_count}  "
            f"bands={','.join(str(b) for b in self.bands) or '-'}",
            f"  sent={self.sent} acked={self.acked} "
            f"ack p50/p99={self.ack_p50_ms:.1f}/{self.ack_p99_ms:.1f}ms",
        ]
        for n in self.notes:
            lines.append(f"  note: {n}")
        return "\n".join(lines)

    def to_json_dict(self) -> dict[str, object]:
        """Counts + synthetic band topology only (never message bodies / control-id lists — PHI rule)."""
        return {
            "schema_version": 1,
            "kind": "shardcert_driver_worker",
            "driver_index": self.driver_index,
            "driver_count": self.driver_count,
            "bands": list(self.bands),
            "sent": self.sent,
            "acked": self.acked,
            "ack_ms": {"p50": round(self.ack_p50_ms, 3), "p99": round(self.ack_p99_ms, 3)},
            "notes": self.notes,
        }


async def run_shardcert_driver_worker(
    *,
    engine_host: str,
    aggregate_rate: float,
    hold_seconds: float,
    driver_index: int,
    driver_count: int,
    coord: FileDropCoord,
    shards_ready_timeout: float = 300.0,
    inbound_ready_timeout: float = 60.0,
    drive_go_timeout: float = 300.0,
) -> ShardCertDriverWorkerReport:
    """One SENDER-tier process of the multi-process drive. Learns the topology from :data:`SHARDS_READY`
    (``shards``, ``inbound_base``, ``lanes``), owns the CONTIGUOUS band slice ``_band_slice`` assigns it
    of the ``G = shards*lanes`` inbound bands (band ``g = i*lanes + l`` dials ``engine_host:inbound_base+g``),
    opens ONE :class:`PersistentConnection` per owned band, proves reachability, posts
    :data:`DRIVER_ARMED`.``<driver_index>``, WAITS for the coordinator's :data:`DRIVE_GO`, drives its slice
    at ``len(slice) * (aggregate_rate / G)`` for ``hold_seconds`` (:func:`_drive_load`, no kill), then posts
    :data:`DRIVER_DONE`.``<driver_index>`` with its sent/acked/ack-latency tally.

    It NEVER binds a sink (the external sink tier owns delivery) and NEVER spawns an engine — the whole
    point is CPU isolation and horizontal sender scale. **Fail loud** if the band slice is empty / the
    worker count exceeds the bands (see :func:`_band_slice`)."""
    ready = await coord.await_message(SHARDS_READY, timeout=shards_ready_timeout)
    ids_list = [str(s) for s in ready["shards"]]
    inbound_base = int(ready["inbound_base"])
    lanes = int(ready.get("lanes", 1))
    total_bands = len(ids_list) * lanes
    start, stop = _band_slice(total_bands, driver_count, driver_index)
    bands = tuple(range(start, stop))

    # Per-band offered rate is the aggregate divided across ALL G bands; this worker drives only its
    # owned bands, so its share is len(slice) * per_band (the whole fleet re-sums to `aggregate_rate`).
    per_band = aggregate_rate / total_bands if total_bands else 0.0
    worker_rate = len(bands) * per_band

    ids = ControlIds(prefix="SC")
    metrics = LiveMetrics(counters=Counters(), ack=Histogram(), e2e=Histogram())
    correlator = Correlator(capacity=1 << 20, metrics=metrics)
    corpus = build_corpus(load_profile_text(_CORPUS_PROFILE, where="<shardcert>"), ids)
    mix = TypeMix({"ADT^A01": 1.0})
    conns: list[PersistentConnection] = []
    notes: list[str] = []
    try:
        # One persistent connection per owned band, dialing the ENGINE box at inbound_base + g. No sink,
        # no tracker (the sinks own the delivery-side verdict; this proc only counts intake/ACK latency).
        for g in bands:
            pc = PersistentConnection(
                engine_host,
                inbound_base + g,
                correlator,
                metrics,
                expect_ack=True,
            )
            pc.start()
            conns.append(pc)
        # Prove the exact off-box reachability the drive will use before arming — every owned band port.
        for g in bands:
            port = inbound_base + g
            if not await _await_port(engine_host, port, timeout=inbound_ready_timeout):
                raise RuntimeError(
                    f"engine inbound {engine_host}:{port} not reachable from the load-gen box"
                )
        # Armed: connections open + reachable. Advertise the owned band indices (synthetic topology) and
        # wait for the coordinator to release every worker in lockstep.
        coord.post(
            f"{DRIVER_ARMED}.{driver_index}",
            {"driver_index": driver_index, "bands": list(bands)},
        )
        await coord.await_message(DRIVE_GO, timeout=drive_go_timeout)
        await _drive_load(
            conns, corpus, mix, metrics, aggregate_rate=worker_rate, hold_seconds=hold_seconds
        )
        await asyncio.gather(*(c.stop(2.0) for c in conns))
    finally:
        for pc in conns:
            with contextlib.suppress(Exception):
                await pc.stop(0.5)

    ctr = metrics.counters
    ack = metrics.ack.summary()
    report = ShardCertDriverWorkerReport(
        driver_index=driver_index,
        driver_count=driver_count,
        bands=bands,
        sent=ctr.sent,
        acked=ctr.acked,
        ack_p50_ms=ack.p50_ms,
        ack_p99_ms=ack.p99_ms,
        notes=notes,
    )
    # Metadata-only DONE drop: counts + ack latency + the synthetic band topology, never control-ids.
    coord.post(
        f"{DRIVER_DONE}.{driver_index}",
        {
            "driver_index": driver_index,
            "sent": report.sent,
            "acked": report.acked,
            "ack_p50_ms": report.ack_p50_ms,
            "ack_p99_ms": report.ack_p99_ms,
            "bands": list(bands),
        },
    )
    return report


# --- coordinator (spawns K senders + M sinks, aggregates, count-balance reconcile) -------------------


async def _spawn_proc(argv: list[str]) -> Any:
    """Spawn ``python -m harness <argv...>`` as a CHILD process (a sink or sender-worker tier). A
    module-level seam so a test can FAKE it (record argv + itself write the child's expected coord
    messages, so the coordinator's awaits resolve without a real subprocess/socket). stdout/stderr →
    PIPE for a diagnostic tail; the AUTHORITATIVE result is always the coord DONE file, never stdout.
    (Windows: ``create_subprocess_exec`` needs the Proactor loop — the platform default there.)"""
    return await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "harness",
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )


async def _await_indexed(
    coord: FileDropCoord, base_name: str, count: int, *, timeout: float
) -> list[dict[str, Any]]:
    """Await the per-child-index messages ``base_name.0 .. base_name.<count-1>`` (each posted by one
    child), returning their payloads in index order. Sequential awaits are fine — the children post
    around the same time, so the total wait is bounded by the slowest to appear, not their sum."""
    return [await coord.await_message(f"{base_name}.{i}", timeout=timeout) for i in range(count)]


async def _reap_child(label: str, proc: Any, *, grace: float) -> str:
    """Best-effort reap ONE spawned child + capture a short stdout tail for the diagnostic log (never
    the authority — that is the coord DONE file). A child that hasn't exited within ``grace`` is killed
    so the coordinator never hangs on an orphan."""
    out = b""
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=grace)
    except (asyncio.TimeoutError, TimeoutError):
        with contextlib.suppress(Exception):
            proc.kill()
        with contextlib.suppress(Exception):
            out, _ = await proc.communicate()
    except Exception:  # noqa: BLE001 - reaping is strictly best-effort diagnostics
        pass
    tail = (out or b"").decode("utf-8", "replace").strip().splitlines()[-4:]
    return f"[{label}] " + " / ".join(t.strip() for t in tail) if tail else f"[{label}] (no output)"


@dataclass
class ShardCertDriveReport:
    """The multi-process SIZING drive's verdict — a COUNT-BALANCE + engine-store-truth reconcile over the
    K sender-workers' intake and the M sinks' delivery tallies (a metadata-only coord can't correlate
    acked↔delivered per-message across processes, so no-loss is a count identity, NOT PR-B's per-message
    ``acked ⊆ delivered``). The coordinator reads the engine ``/stats`` REMOTELY, so the store-truth
    stranded / dead-at-any-stage authority stays the ENGINE half's report; this verdict is the count
    balance + per-lane FIFO/dup + the engine's REMOTE done/dead/in_pipeline. Counts + synthetic topology
    labels only — never control-ids / message bodies (PHI rule)."""

    shards: tuple[str, ...]
    dests: int  # fan-out factor: every accepted message fans to all `dests` outbound destinations
    driver_count: int
    sink_count: int
    aggregate_rate: float
    hold_seconds: float
    offered: int  # round(aggregate_rate * hold_seconds)
    sent: int  # Σ sender-worker sent
    acked: int  # A = Σ sender-worker acked (accept-ACK'd intake)
    sink_received: int  # S = Σ sink delivered copies
    lane_inversions: int  # Σ over sinks
    lane_repeats: int  # Σ over sinks (no kill ⇒ strict zero)
    lanes_observed: (
        int  # MAX over sinks (the non-vacuous FIFO gate — see the aggregation note; not Σ)
    )
    ack_p50_ms: (
        float  # max over sender-workers (per-proc histograms don't merge cleanly cross-proc)
    )
    ack_p99_ms: float  # max over sender-workers
    engine_done: int  # engine /stats outbound done (deliveries the store marked done) — REMOTE
    engine_dead: int  # engine /stats outbound dead — REMOTE
    in_pipeline_final: int  # engine /stats in_pipeline at drain — REMOTE
    drained: bool
    drain_seconds: float | None
    notes: list[str] = field(default_factory=list)

    @property
    def no_loss(self) -> bool:
        """Count-balance on SINK SOCKET-TRUTH ONLY (NO-KILL, strict): the sinks' socket-observed
        deliveries (``S``) equal the accept-ACK'd intake fanned out (``A * dests``), with both sides
        non-vacuous (``A > 0``, ``S > 0``).

        Deliberately does NOT gate on the poller terms (``drained``, ``engine_dead``, ``engine_done``):
        they are read from the engine ``/stats`` REMOTELY and are UNRELIABLE on a unified store — the
        gauges SUM ``done``/``dead`` over all shard APIs (4× overcount) and ``await_drain`` zeroes/misses
        under load (the exact metric ``mf-bench-attribution-policy`` + the C1 runbook say to NEVER gate
        on). The strand / dead-at-any-stage authority is the ENGINE half's report, which reads the store
        DIRECTLY (store-truth) and owns that verdict; the sinks are the DRIVE box's only reliable truth.
        The poller terms remain as ADVISORY cross-check fields (see ``render``/``to_json_dict``)."""
        fanout = self.acked * self.dests
        return self.sink_received == fanout and self.acked > 0 and self.sink_received > 0

    @property
    def ok(self) -> bool:
        """Pass bar: sink-truth no-loss AND per-lane FIFO (non-vacuous, ``lanes_observed >= 2``) AND no
        duplicates. The collector-nonzero gates (``A > 0``, ``S > 0``) fold into ``no_loss`` — a vacuous
        run that sent or delivered nothing must NOT silently certify. Excludes the poller terms
        (``drained``/``engine_dead``/``engine_done``) for the reason stated on ``no_loss``: they are
        advisory here; dead-letters + strands are the engine half's store-truth verdict, not the drive's."""
        return (
            self.no_loss
            and self.lane_inversions == 0
            and self.lanes_observed >= 2
            and self.lane_repeats == 0
        )

    @property
    def ceiling(self) -> bool:
        """The fleet could not SUSTAIN the offered load — reuse the #836 ladder step's ceiling logic
        (``not no_loss`` OR the accept-INTAKE fell materially short of offered beyond ``_INTAKE_TOL``),
        the measured-intake-shortfall rule, NEVER ``delivered < offered``."""
        return ShardCertStepRecord(
            aggregate_rate=self.aggregate_rate,
            offered=self.offered,
            achieved_intake=self.acked,
            delivered=self.sink_received,
            in_pipeline_peak=-1,  # the coordinator samples no in-hold peak (the engine half can)
            ack_p50_ms=self.ack_p50_ms,
            ack_p99_ms=self.ack_p99_ms,
            drain_seconds=self.drain_seconds,
            no_loss=self.no_loss,
            lane_inversions=self.lane_inversions,
            lane_repeats=self.lane_repeats,
            stranded_nonterminal=0,
        ).ceiling

    def render(self) -> str:
        a = self.acked
        lines = [
            f"ShardCert DRIVE {'/'.join(self.shards)}  verdict={'PASS' if self.ok else 'FAIL'}  "
            f"K={self.driver_count}sender x M={self.sink_count}sink  fanout(dests)={self.dests}",
            f"  rate={self.aggregate_rate:g}/s hold={self.hold_seconds:g}s offered={self.offered} "
            f"sent={self.sent} acked(A)={a} sink_received(S)={self.sink_received}",
            f"  no-loss (SINK truth): sink_received(S)={self.sink_received} "
            f"(expect A*dests={a * self.dests}) -> {'OK' if self.no_loss else 'LOSS'}",
            f"  FIFO: lane_inversions={self.lane_inversions} lanes_observed={self.lanes_observed} "
            f"lane_repeats(dups)={self.lane_repeats}",
            f"  ack p50/p99(max over senders)={self.ack_p50_ms:.1f}/{self.ack_p99_ms:.1f}ms "
            f"drain_s={self.drain_seconds}" + ("  <= CEILING" if self.ceiling else ""),
            # ADVISORY poller cross-check, NOT gated (unreliable on a unified store: 4x shard-API
            # overcount / zeroes under load; the engine half's DIRECT store-truth owns strand/dead).
            f"  advisory (poller x-check, NOT gated): engine_done={self.engine_done} "
            f"engine_dead={self.engine_dead} in_pipeline_final={self.in_pipeline_final} "
            f"drained={self.drained}",
        ]
        for n in self.notes:
            lines.append(f"  note: {n}")
        return "\n".join(lines)

    def to_json_dict(self) -> dict[str, object]:
        """Metrics + metadata only (never message bodies or control-id lists — PHI rule)."""
        return {
            "schema_version": 1,
            "kind": "shardcert_drive",
            "verdict": "PASS" if self.ok else "FAIL",
            "shards": list(self.shards),
            "topology": {
                "dests": self.dests,
                "driver_count": self.driver_count,
                "sink_count": self.sink_count,
            },
            "traffic": {
                "aggregate_rate": round(self.aggregate_rate, 3),
                "hold_seconds": self.hold_seconds,
                "offered": self.offered,
                "sent": self.sent,
                "acked": self.acked,
                "sink_received": self.sink_received,
            },
            "correctness": {
                # SINK socket-truth only — the gated verdict. See ``no_loss``/``ok`` for why the
                # poller terms (engine_done/engine_dead/drained) are excluded (they live in
                # ``advisory_poller`` below).
                "no_loss": self.no_loss,
                "lane_inversions": self.lane_inversions,
                "lanes_observed": self.lanes_observed,
                "lane_repeats": self.lane_repeats,
            },
            "throughput": {
                "drain_seconds": self.drain_seconds,
                "ceiling": self.ceiling,
            },
            "advisory_poller": {
                # Poller cross-check, NOT gated: unreliable on a unified store (4x shard-API overcount
                # on done/dead; await_drain zeroes/misses under load). Retained for telemetry; the
                # engine half's DIRECT store-truth is the strand/dead authority.
                "note": "poller cross-check, NOT gated (unreliable on a unified store)",
                "engine_done": self.engine_done,
                "engine_dead": self.engine_dead,
                "in_pipeline_final": self.in_pipeline_final,
                "drained": self.drained,
            },
            "ack_ms": {"p50": round(self.ack_p50_ms, 3), "p99": round(self.ack_p99_ms, 3)},
            "notes": self.notes,
        }


async def run_shardcert_drive(
    *,
    engine_host: str,
    aggregate_rate: float = 40.0,
    hold_seconds: float = 20.0,
    driver_count: int = 1,
    sink_count: int = 1,
    sink_host: str = "127.0.0.1",
    coord: FileDropCoord,
    shards_ready_timeout: float = 300.0,
    child_ready_timeout: float = 120.0,
    driver_done_timeout: float = 600.0,
    sink_done_timeout: float = 120.0,
    drain_timeout: float = 90.0,
    reap_grace: float = 10.0,
    allow_insecure: bool = False,
    await_engine_drained: bool = False,
    engine_drained_timeout: float = 300.0,
) -> ShardCertDriveReport:
    """The multi-process SIZING drive COORDINATOR (load-gen box). Learns the topology from
    :data:`SHARDS_READY` (the engine half posts it), spawns ``sink_count`` :func:`run_shardcert_sink` +
    ``driver_count`` :func:`run_shardcert_driver_worker` CHILD processes (seam :func:`_spawn_proc`),
    orchestrates the handshake, drains the engine's REMOTE ``/stats``, then aggregates the children's
    coord DONE files into a COUNT-BALANCE + engine-store-truth reconcile.

    Handshake order: await SHARDS_READY → spawn+await all :data:`SINK_BOUND` → spawn+await all
    :data:`DRIVER_ARMED` → post :data:`DRIVE_START` (the engine's kill anchor — no kill here) +
    :data:`DRIVE_GO` (release the senders) → await all :data:`DRIVER_DONE` → drain REMOTE ``/stats`` →
    post :data:`DRIVE_COMPLETE` → await all :data:`SINK_DONE` → reconcile.

    The coordinator + all spawned children run on the load-gen box — NEVER co-located with the engine
    fleet (the attribution isolation; an operator/runbook concern). **Fail loud** early on a mis-sized
    fleet (a sink partition or band slice that doesn't tile) rather than spawning doomed children.

    ``await_engine_drained`` (default OFF ⇒ the standalone C1 drive path is byte-identical) is the PR-C2
    ladder's **drain gate**: before signalling :data:`DRIVE_COMPLETE` (which releases the sinks to record
    their final tally), wait for the ENGINE half's RELIABLE store-truth :data:`ENGINE_DRAINED`. The remote
    ``/stats`` poller below is advisory (it can zero out under load on a unified store), so tallying on it
    alone risks reading a teardown-frozen in-flight tail as loss; awaiting the engine's DIRECT store read
    closes that window. Bounded + best-effort — a missing signal degrades to the advisory-drain fallback
    with a note, never a hang."""
    ready = await coord.await_message(SHARDS_READY, timeout=shards_ready_timeout)
    ids_list = [str(s) for s in ready["shards"]]
    dests = int(ready["dests"])
    sink_base = int(ready.get("sink_base", ready["sink_port"]))
    sink_ports = int(ready.get("sink_ports", 1))
    api_ports = [int(p) for p in ready["api_ports"]]
    lanes = int(ready.get("lanes", 1))

    if driver_count < 1 or sink_count < 1:
        raise ValueError("driver_count and sink_count must both be >= 1")
    # Fail LOUD here on a mis-sized fleet (a partition/slice that can't tile) — otherwise K/M silently
    # doomed children would each fail-loud + never post BOUND/ARMED, and the coordinator would only see
    # an opaque timeout. Validating up front turns that into a crisp setup error.
    _partition_band(sink_base, sink_ports, sink_count)
    total_bands = len(ids_list) * lanes
    for j in range(driver_count):
        _band_slice(total_bands, driver_count, j)

    # Fresh-run hygiene: clear the child/handshake drops this run will (re)post so a stale prior-run file
    # can't be mis-read. NOT SHARDS_READY — the engine posted it and we just consumed it.
    coord.clear_messages(
        DRIVE_START,
        DRIVE_GO,
        DRIVE_COMPLETE,
        *(f"{SINK_BOUND}.{m}" for m in range(sink_count)),
        *(f"{SINK_DONE}.{m}" for m in range(sink_count)),
        *(f"{DRIVER_ARMED}.{j}" for j in range(driver_count)),
        *(f"{DRIVER_DONE}.{j}" for j in range(driver_count)),
    )

    coord_dir = str(coord.directory)
    run_id = coord.run_id
    procs: list[tuple[str, Any]] = []
    notes: list[str] = []
    poller: EnginePoller | None = None
    try:
        # (1) Spawn the M sink children over CONTIGUOUS chunks of the [sink_base, sink_base+sink_ports)
        #     (== dests) band; await each SINK_BOUND.<m>.
        for m in range(sink_count):
            proc = await _spawn_proc(
                [
                    "shardcert-sink",
                    "--sink-host",
                    sink_host,
                    "--sink-base",
                    str(sink_base),
                    "--sink-ports",
                    str(sink_ports),
                    "--sink-index",
                    str(m),
                    "--sink-count",
                    str(sink_count),
                    "--coord-dir",
                    coord_dir,
                    "--run-id",
                    run_id,
                ]
            )
            procs.append((f"sink-{m}", proc))
        await _await_indexed(coord, SINK_BOUND, sink_count, timeout=child_ready_timeout)

        # (2) Spawn the K sender-worker children over CONTIGUOUS band slices; await each DRIVER_ARMED.<j>.
        for j in range(driver_count):
            proc = await _spawn_proc(
                [
                    "shardcert-driver-worker",
                    "--engine-host",
                    engine_host,
                    "--aggregate-rate",
                    str(aggregate_rate),
                    "--hold-seconds",
                    str(hold_seconds),
                    "--driver-index",
                    str(j),
                    "--driver-count",
                    str(driver_count),
                    "--coord-dir",
                    coord_dir,
                    "--run-id",
                    run_id,
                ]
            )
            procs.append((f"worker-{j}", proc))
        await _await_indexed(coord, DRIVER_ARMED, driver_count, timeout=child_ready_timeout)

        # (3) Release: DRIVE_START keeps the ENGINE half's handshake unchanged (its kill anchor; no kill
        #     here); DRIVE_GO releases the armed sender-workers into their hold in lockstep.
        coord.post(DRIVE_START, {"t0": time.time()})
        coord.post(DRIVE_GO, {"go": True})

        # (4) Await every sender-worker's DONE, then drain the engine's REMOTE /stats (the authoritative
        #     drain signal, polled off-box) before declaring the pipeline empty.
        driver_dones = await _await_indexed(
            coord, DRIVER_DONE, driver_count, timeout=driver_done_timeout
        )
        urls = [f"http://{engine_host}:{p}" for p in api_ports]
        # allow_insecure threads the plaintext-http-to-remote posture: the engine box's API is http and
        # off-box, so without it EngineClient fail-closes and poller.open() raises AFTER the children are
        # spawned. (A loopback co-located engine never needs it.) The finally below still tears the
        # children down on any early failure, but threading this is what makes the run succeed.
        poller = EnginePoller(urls, None, origin=time.perf_counter(), allow_insecure=allow_insecure)
        await poller.open()
        drain_s = await poller.await_drain(timeout=drain_timeout, interval=0.5)
        final = poller.final

        # (4b) PR-C2 ladder drain gate (default OFF): before releasing the sinks to tally, wait for the
        # ENGINE half's RELIABLE store-truth drain signal. The remote poller above is advisory (zeroes
        # under load on a unified store), so tallying on it alone can read a teardown-frozen tail as loss;
        # the engine's DIRECT store read closes that window. Best-effort — a missing signal degrades to the
        # advisory-drain fallback (note it) rather than hanging.
        if await_engine_drained:
            try:
                drained_msg = await coord.await_message(
                    ENGINE_DRAINED, timeout=engine_drained_timeout
                )
                notes.append(
                    f"engine drain gate: engine_ok={drained_msg.get('engine_ok')} "
                    f"stranded={drained_msg.get('stranded')} dead_total={drained_msg.get('dead_total')}"
                )
            except CoordTimeout:
                notes.append(
                    f"ENGINE_DRAINED not seen within {engine_drained_timeout}s — tallying on the "
                    "advisory remote-drain fallback (drain-window gate degraded)"
                )

        # (5) Signal drained → every sink records its final tally and posts SINK_DONE.<m>.
        coord.post(DRIVE_COMPLETE, {"t": time.time()})
        sink_dones = await _await_indexed(coord, SINK_DONE, sink_count, timeout=sink_done_timeout)
    finally:
        if poller is not None:
            with contextlib.suppress(Exception):
                await poller.close()
        # Reap CONCURRENTLY so an early failure (e.g. a poller.open() raise while M+K children are still
        # live, some blocked on DRIVE_COMPLETE) tears the whole tier down in ~one reap_grace, not
        # (M+K)*reap_grace — no lingering child processes on the load-gen box between ladder steps.
        if procs:
            notes.extend(
                await asyncio.gather(
                    *(_reap_child(label, proc, grace=reap_grace) for label, proc in procs)
                )
            )

    # (6) Aggregate the children's coord DONE files (the authority) + the engine's REMOTE drain gauge.
    a = sum(int(d["acked"]) for d in driver_dones)
    sent = sum(int(d["sent"]) for d in driver_dones)
    ack_p50 = max((float(d["ack_p50_ms"]) for d in driver_dones), default=0.0)
    ack_p99 = max((float(d["ack_p99_ms"]) for d in driver_dones), default=0.0)
    s_total = sum(int(d["sink_received"]) for d in sink_dones)
    inversions = sum(int(d["lane_inversions"]) for d in sink_dones)
    repeats = sum(int(d["lane_repeats"]) for d in sink_dones)
    # Take the MAX over sinks, NEVER the sum: a given (shard,[lane,]dest) FIFO lane maps to exactly one
    # sink, so distinct sinks observe distinct lane keys and their union is unknowable from counts alone.
    # But the FIFO check only needs ONE sink to have non-vacuously observed >= 2 lanes — the max gives
    # exactly that, whereas summing could clear the >= 2 gate from two sinks that each saw only 1 lane
    # (each individually vacuous), a false pass.
    lanes_observed = max((int(d["lanes_observed"]) for d in sink_dones), default=0)

    return ShardCertDriveReport(
        shards=tuple(ids_list),
        dests=dests,
        driver_count=driver_count,
        sink_count=sink_count,
        aggregate_rate=aggregate_rate,
        hold_seconds=hold_seconds,
        offered=round(aggregate_rate * hold_seconds),
        sent=sent,
        acked=a,
        sink_received=s_total,
        lane_inversions=inversions,
        lane_repeats=repeats,
        lanes_observed=lanes_observed,
        ack_p50_ms=ack_p50,
        ack_p99_ms=ack_p99,
        engine_done=(final.done if final else 0),
        engine_dead=(final.dead if final else 0),
        in_pipeline_final=(final.in_pipeline if final else -1),
        drained=drain_s is not None,
        drain_seconds=drain_s,
        notes=notes,
    )
