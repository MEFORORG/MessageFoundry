# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Engine-side sampling — the aggregate view the per-message metrics can't give.

Polls the engine's HTTP API on an interval (``/stats``, ``/connections``, ``/status``) to track
engine-side throughput (Δdone/Δt), backlog, dead-letter accumulation, and DB/WAL growth over the run,
then measures **drain time** after offered load stops. The :class:`~messagefoundry.console.client`
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
from typing import Sequence

from messagefoundry.console.client import ApiError, EngineClient


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
    uptime_s: float

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


class EnginePoller:
    """Samples one or more engine APIs off the event loop, aggregates them, and detects post-load
    drain across the whole cluster."""

    def __init__(
        self, engine_urls: str | Sequence[str], token: str | None, *, origin: float
    ) -> None:
        # Accept a single URL (back-compat) or a list. The first URL is the "primary" whose `client`
        # is exposed for one-off preflight reads (served-ports check).
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
            client = EngineClient(url)
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
        # Journal mode is reported per shard; they share a backend in practice, so take the first
        # (informational only — it doesn't feed the no-loss check).
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
            uptime_s=max(s.uptime_s for s in shard_samples),
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
        )
