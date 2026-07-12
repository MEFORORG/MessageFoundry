# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Engine-side sampling — the aggregate view the per-message metrics can't give.

Polls the engine's HTTP API on an interval (``/stats``, ``/connections``, ``/status``) to track
engine-side throughput (Δdone/Δt), backlog, dead-letter accumulation, and DB/WAL growth over the run,
then measures **drain time** after offered load stops. The :class:`~messagefoundry.apiclient`
``EngineClient`` is synchronous (httpx), so every call runs in a thread via ``run_in_executor`` — the
load engine's event loop is never blocked. The harness reaches the engine only through this API; it
never touches the store.

**Cluster-wide aggregation.** A ``messagefoundry supervise`` cluster spreads inbounds across several
shard subprocesses, each with its own API. The poller takes a **list** of engine base-URLs (the
primary ``--engine`` plus any ``--shard-engine``, de-duped), polls each in turn off the event loop,
and **sums** each shard's read/written/backlog/in_pipeline/queue_depth/dead into one cluster sample
(the sum is order-independent, so the sequential per-shard reads need no ordering) — so the no-loss
reconcile compares cluster-aggregate ``read``/``written``/``backlog`` against the (already cluster-
aggregate) client ``sent``/``sink_received``, and drain requires **every** shard to empty. With a
single URL (the default) a sample is byte-identical to the one-shard behavior.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any, Iterable, Sequence, TypeVar

from messagefoundry.apiclient import ApiError, EngineClient

from harness.load.metrics import Counters

_T = TypeVar("_T")


def _first_not_none(values: Iterable[_T | None]) -> _T | None:
    """The first non-``None`` value, or ``None`` if all are ``None`` (per-process gauges: the connscale
    harness drives a single engine, so this is exactly that engine's reading)."""
    for value in values:
        if value is not None:
            return value
    return None


def _pool_attr(status: Any, name: str) -> int | None:
    """Read ``status.pool.<name>`` (the server-only pool field), or ``None`` on SQLite / an older
    engine whose ``SystemStatus`` has no ``pool`` field."""
    pool = getattr(status, "pool", None)
    if pool is None:
        return None
    value = getattr(pool, name, None)
    return int(value) if value is not None else None


def _pool_wait_attr(status: Any, name: str) -> float | None:
    """Read ``status.pool.acquire_wait.<name>`` (the PRIMARY pool-wait percentiles), or ``None``."""
    pool = getattr(status, "pool", None)
    if pool is None:
        return None
    wait = getattr(pool, "acquire_wait", None)
    if wait is None:
        return None
    value = getattr(wait, name, None)
    return float(value) if value is not None else None


@dataclass(frozen=True)
class EngineSample:
    """One engine-side observation. ``read``/``written``/``done``/``dead`` are cumulative since engine
    start, so run totals are last − first. Under a multi-shard cluster every field is the **sum**
    across all polled shards."""

    elapsed_s: float
    pending: int  # outbound stage, status=pending
    inflight: int  # outbound stage, status=inflight
    done: int  # outbound stage, status=done (delivered)
    dead: int  # outbound stage, status=dead (dead-lettered)
    read: int  # Σ inbound `read` (messages received)
    written: int  # Σ outbound `written` (deliveries made)
    out_dead: int  # Σ outbound `errored` (deliveries dead-lettered)
    queue_depth: int  # Σ outbound queue_depth (pending + inflight)
    in_pipeline: (
        int  # NOT-DONE rows across ALL stages (ingress+routed+outbound) — whole-pipeline gauge
    )
    db_size_bytes: int
    journal_mode: str
    synchronous: (
        str | None
    )  # SQLite durability mode ("normal"/"full"); None on server backends (B7)
    uptime_s: float
    # B11 connection-scale instrumentation (read-only, additive; default 0/None so an OLDER engine
    # without these fields deserializes to zeros — the established back-compat pattern). Summed across
    # shards where summable; pool gauges take the first server-store shard reporting one.
    empty_claims: int = 0  # Σ cumulative empty claims (wall #3)
    empty_claims_idle_poll: int = 0  # the idle-poll re-SELECT share
    empty_claims_wake_fanout: int = 0  # the per-commit wake-fanout (thundering-herd) share
    # A1 live cost counters (cumulative since engine start; run totals are last − first). committed_txns =
    # physical transactions committed (the 3+2H+2N/msg cost-model currency, ADR 0051); body_copies =
    # raw/payload body strings durably written (the 2+H+N/msg amplification). Σ across shards; default 0 so
    # an older engine without the /stats fields reads as zero.
    committed_txns: int = 0
    body_copies: int = 0
    executor_queue_depth: int | None = None  # default-pool submit-queue depth (wall #1; shim-only)
    executor_busy: int | None = None  # default-pool in-flight count (wall #1; shim-only)
    pool_size: int | None = None  # server-store pool: connections open (wall #2; None on SQLite)
    pool_idle: int | None = None  # server-store pool: connections free (idle==0 ⇒ saturated)
    pool_wait_p50_ms: float | None = None  # PRIMARY wall #2: acquire-wait percentiles (ms)
    pool_wait_p95_ms: float | None = None
    pool_wait_p99_ms: float | None = None
    pool_wait_max_ms: float | None = None

    @property
    def backlog(self) -> int:
        return self.pending + self.inflight


@dataclass(frozen=True)
class _ShardSample:
    """A single shard's contribution to one cluster sample (the per-URL summable parts)."""

    pending: int
    inflight: int
    done: int
    dead: int
    read: int
    written: int
    out_dead: int
    queue_depth: int
    in_pipeline: int
    db_size_bytes: int
    uptime_s: float
    journal_mode: str
    synchronous: str | None
    # B11 (read-only, additive): empty-claim counts (summable) + executor gauges + the server-store
    # pool snapshot. All default 0/None so an older engine without these fields reads as zeros.
    empty_claims: int = 0
    empty_claims_idle_poll: int = 0
    empty_claims_wake_fanout: int = 0
    committed_txns: int = 0  # A1 live cost counter (summable across shards)
    body_copies: int = 0  # A1 live cost counter (summable across shards)
    executor_queue_depth: int | None = None
    executor_busy: int | None = None
    pool_size: int | None = None
    pool_idle: int | None = None
    pool_wait_p50_ms: float | None = None
    pool_wait_p95_ms: float | None = None
    pool_wait_p99_ms: float | None = None
    pool_wait_max_ms: float | None = None


async def sample_until_reconciled(
    poller: EnginePoller, counters: Counters, *, timeout: float, interval: float
) -> EngineSample | None:
    """Re-sample the engine until the no-loss reconcile condition SETTLES — every CONFIRMED send has
    been read (``read >= sent - timeouts``) and every delivery has reached the sink
    (``sink_received >= written``) — or ``timeout`` elapses. The durable fix for the intake/delivery
    count-lag a noisy runner shows even after a clean drain: assert the actual settled condition, not
    a single fixed-instant sample (mf-ci-test-flakes). The baseline-relative deltas are used,
    mirroring the reconcile. On timeout the last sample is returned and the no-loss check reports the
    residual shortfall honestly (no masking).

    ``sent - timeouts`` because a ``timeouts``-counted message (in-flight at a connection close with
    no ACK seen — a mid-run reset or the stop-grace expiring) is UNCONFIRMED: ``sent`` was counted at
    write-buffer time, so the frame may never have left the closed socket. Waiting for ``read`` to
    reach the full ``sent`` would poll the entire timeout for a message that may never arrive; the
    reconcile applies the same accounting, so the settled condition must match it. With
    ``timeouts == 0`` (every healthy run) this is exactly ``read >= sent``. (This is only the
    STOP-SAMPLING heuristic — the reconcile itself additionally caps how many unconfirmed sends are
    excusable, so a timeout flood still fails the run regardless of when sampling stopped.)"""
    loop = asyncio.get_running_loop()
    base = poller.baseline
    start = loop.time()
    last = poller.final
    while loop.time() - start < timeout:
        sample = await poller.sample_once()
        if sample is not None:
            last = sample
            if base is not None:
                read = sample.read - base.read
                written = sample.written - base.written
                # Settled: every confirmed send fully read AND every counted delivery arrived at the
                # sink AND the pipeline is empty (no in-flight rows that could still move the counts).
                if (
                    read >= counters.sent - counters.timeouts
                    and counters.sink_received >= written
                    and sample.in_pipeline == 0
                ):
                    return sample
        await asyncio.sleep(interval)
    return last


class EnginePoller:
    """Samples one or more engine APIs off the event loop, aggregates them, and detects post-load
    drain across the whole cluster."""

    def __init__(
        self,
        engine_urls: str | Sequence[str],
        token: str | None,
        *,
        origin: float,
        allow_insecure: bool = False,
    ) -> None:
        # Accept a single URL (back-compat) or a list. The first URL is the "primary" whose `client`
        # is exposed for one-off preflight reads (served-ports check). `allow_insecure` (default False)
        # is REQUIRED to poll a REMOTE engine over plaintext http (a co-located loopback engine is
        # always allowed) — the two-box shardcert drives poll the engine box's http API off-box, so
        # they thread it True; without it EngineClient fail-closes on the non-loopback http URL.
        urls = [engine_urls] if isinstance(engine_urls, str) else list(engine_urls)
        if not urls:
            raise ValueError("EnginePoller needs at least one engine URL")
        # De-dup, order-preserving (primary first): passing the primary --engine ALSO as a
        # --shard-engine would otherwise double-count that shard's read/written/backlog and mask real
        # loss. Distinct shard APIs are unaffected; the single-URL default stays exactly one client.
        seen: set[str] = set()
        deduped: list[str] = []
        for url in urls:
            if url not in seen:
                seen.add(url)
                deduped.append(url)
        self._urls = deduped
        self._token = token
        self._origin = origin
        self._allow_insecure = allow_insecure
        self._clients: list[EngineClient] = []
        self._samples: list[EngineSample] = []

    @property
    def client(self) -> EngineClient | None:
        """The PRIMARY shard's client (set after :meth:`open`) — for one-off preflight reads."""
        return self._clients[0] if self._clients else None

    @property
    def samples(self) -> list[EngineSample]:
        return self._samples

    @property
    def baseline(self) -> EngineSample | None:
        return self._samples[0] if self._samples else None

    @property
    def final(self) -> EngineSample | None:
        return self._samples[-1] if self._samples else None

    async def open(self) -> None:
        await asyncio.get_running_loop().run_in_executor(None, self._open_sync)

    async def close(self) -> None:
        loop = asyncio.get_running_loop()
        clients, self._clients = self._clients, []
        for client in clients:
            await loop.run_in_executor(None, client.close)

    async def sample_once(self) -> EngineSample | None:
        sample = await asyncio.get_running_loop().run_in_executor(None, self._sample_sync)
        if sample is not None:
            self._samples.append(sample)
        return sample

    async def run(self, interval: float, stop: asyncio.Event) -> None:
        """Sample every ``interval`` seconds until ``stop`` is set."""
        await self.sample_once()
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), timeout=interval)
            except TimeoutError:
                await self.sample_once()

    async def await_drain(self, *, timeout: float, interval: float) -> float | None:
        """Poll until the **whole cluster's** pipeline is empty and inbound/delivery counters stop
        moving. Returns seconds-to-drain, or ``None`` on timeout.

        Drain requires the *aggregate* ``in_pipeline == 0`` (no NOT-DONE rows in ANY stage of ANY
        shard — ingress, routed, or outbound), the summed outbound backlog + per-edge ``queue_depth``
        at zero, and ``read``/``written`` unchanged across a poll. Because the cluster sample sums
        every shard, this only completes once **every** shard reports ``in_pipeline == 0`` and an
        empty backlog. The ``in_pipeline`` gauge (from ``/stats``) closes the prior blind spot: a
        fully **stalled** router/transform leaves the outbound backlog at 0 but ``in_pipeline > 0``,
        so it no longer reads as drained."""
        loop = asyncio.get_running_loop()
        start = loop.time()
        prev = self.final or await self.sample_once()
        while loop.time() - start < timeout:
            try:
                await asyncio.wait_for(asyncio.sleep(interval), timeout=interval + 1.0)
            except TimeoutError:  # pragma: no cover - defensive
                pass
            cur = await self.sample_once()
            if cur is None:
                continue
            stable = prev is not None and cur.read == prev.read and cur.written == prev.written
            if cur.backlog == 0 and cur.queue_depth == 0 and cur.in_pipeline == 0 and stable:
                return loop.time() - start
            prev = cur
        return None

    # --- sync helpers (run in the executor) ----------------------------------

    def _open_sync(self) -> None:
        clients: list[EngineClient] = []
        for url in self._urls:
            client = EngineClient(url, allow_insecure=self._allow_insecure)
            if self._token:
                client.set_token(self._token)  # does a /me request to validate
            clients.append(client)
        self._clients = clients

    def _sample_sync(self) -> EngineSample | None:
        """Sample every shard and SUM into one cluster observation.

        Reachability mirrors the single-shard semantics: a shard that is transiently unreachable makes
        the whole sample unavailable (return ``None`` → skip this tick, keep polling), rather than
        silently reporting a too-low aggregate that would poison the baseline/final no-loss math."""
        if not self._clients:
            return None
        shard_samples: list[_ShardSample] = []
        for client in self._clients:
            shard = self._sample_shard(client)
            if shard is None:
                return None  # one shard unreachable → skip the aggregate (keep polling)
            shard_samples.append(shard)
        # Journal mode + synchronous are reported per shard; they share a backend in practice, so take
        # the first (informational only — neither feeds the no-loss check).
        return EngineSample(
            elapsed_s=time.perf_counter() - self._origin,
            pending=sum(s.pending for s in shard_samples),
            inflight=sum(s.inflight for s in shard_samples),
            done=sum(s.done for s in shard_samples),
            dead=sum(s.dead for s in shard_samples),
            read=sum(s.read for s in shard_samples),
            written=sum(s.written for s in shard_samples),
            out_dead=sum(s.out_dead for s in shard_samples),
            queue_depth=sum(s.queue_depth for s in shard_samples),
            in_pipeline=sum(s.in_pipeline for s in shard_samples),
            db_size_bytes=sum(s.db_size_bytes for s in shard_samples),
            journal_mode=shard_samples[0].journal_mode,
            synchronous=shard_samples[0].synchronous,
            uptime_s=max(s.uptime_s for s in shard_samples),
            # B11: empty-claim counts SUM across shards (each shard runs its own workers). Executor
            # gauges + the pool snapshot are per-process; take the MAX queue depth/busy and the first
            # shard reporting a pool (in practice the connscale harness runs a single engine, so this
            # is exactly that one engine's reading).
            empty_claims=sum(s.empty_claims for s in shard_samples),
            empty_claims_idle_poll=sum(s.empty_claims_idle_poll for s in shard_samples),
            empty_claims_wake_fanout=sum(s.empty_claims_wake_fanout for s in shard_samples),
            committed_txns=sum(s.committed_txns for s in shard_samples),  # A1
            body_copies=sum(s.body_copies for s in shard_samples),  # A1
            executor_queue_depth=_first_not_none(s.executor_queue_depth for s in shard_samples),
            executor_busy=_first_not_none(s.executor_busy for s in shard_samples),
            pool_size=_first_not_none(s.pool_size for s in shard_samples),
            pool_idle=_first_not_none(s.pool_idle for s in shard_samples),
            pool_wait_p50_ms=_first_not_none(s.pool_wait_p50_ms for s in shard_samples),
            pool_wait_p95_ms=_first_not_none(s.pool_wait_p95_ms for s in shard_samples),
            pool_wait_p99_ms=_first_not_none(s.pool_wait_p99_ms for s in shard_samples),
            pool_wait_max_ms=_first_not_none(s.pool_wait_max_ms for s in shard_samples),
        )

    @staticmethod
    def _sample_shard(client: EngineClient) -> _ShardSample | None:
        try:
            stats = client.stats()
            conns = client.connections()
            status = client.status()
        except ApiError:
            return None  # transient unreachability — caller skips the whole sample
        ob = stats.outbox_by_status
        # `read` is populated only on inbound rows, `written` only on outbound rows — so summing the
        # non-None values partitions inbound vs outbound without guessing role/direction strings.
        read = sum(r.read for r in conns if r.read is not None)
        written = sum(r.written for r in conns if r.written is not None)
        out_dead = sum(r.errored or 0 for r in conns if r.written is not None)
        queue_depth = sum(r.queue_depth or 0 for r in conns if r.queue_depth is not None)
        return _ShardSample(
            pending=ob.get("pending", 0),
            inflight=ob.get("inflight", 0),
            done=ob.get("done", 0),
            dead=ob.get("dead", 0),
            read=read,
            written=written,
            out_dead=out_dead,
            queue_depth=queue_depth,
            in_pipeline=stats.in_pipeline,
            db_size_bytes=status.db.size_bytes,
            uptime_s=status.engine.uptime_seconds,
            journal_mode=status.db.journal_mode,
            synchronous=status.db.synchronous,
            # B11 read-only instrumentation. getattr-with-default so an OLDER engine (whose
            # StatsResponse/SystemStatus lack these fields) reads as zeros/None — the established
            # back-compat pattern (mirrors in_pipeline/synchronous). `pool` is the server-only field
            # (None on SQLite); its acquire_wait sub-object carries the PRIMARY pool-wait percentiles.
            empty_claims=getattr(stats, "empty_claims", 0) or 0,
            empty_claims_idle_poll=getattr(stats, "empty_claims_idle_poll", 0) or 0,
            empty_claims_wake_fanout=getattr(stats, "empty_claims_wake_fanout", 0) or 0,
            committed_txns=getattr(stats, "committed_txns", 0)
            or 0,  # A1 (getattr → older-engine safe)
            body_copies=getattr(stats, "body_copies", 0) or 0,  # A1 (getattr → older-engine safe)
            executor_queue_depth=getattr(stats, "executor_queue_depth", None),
            executor_busy=getattr(stats, "executor_busy", None),
            pool_size=_pool_attr(status, "size"),
            pool_idle=_pool_attr(status, "idle"),
            pool_wait_p50_ms=_pool_wait_attr(status, "p50_ms"),
            pool_wait_p95_ms=_pool_wait_attr(status, "p95_ms"),
            pool_wait_p99_ms=_pool_wait_attr(status, "p99_ms"),
            pool_wait_max_ms=_pool_wait_attr(status, "max_ms"),
        )
