# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Engine-side sampling — the aggregate view the per-message metrics can't give.

Polls the engine's HTTP API on an interval (``/stats``, ``/connections``, ``/status``) to track
engine-side throughput (Δdone/Δt), backlog, dead-letter accumulation, and DB/WAL growth over the run,
then measures **drain time** after offered load stops. The :class:`~messagefoundry.console.client`
``EngineClient`` is synchronous (httpx), so every call runs in a thread via ``run_in_executor`` — the
load engine's event loop is never blocked. The harness reaches the engine only through this API; it
never touches the store.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

from messagefoundry.console.client import ApiError, EngineClient


@dataclass(frozen=True)
class EngineSample:
    """One engine-side observation. ``read``/``written``/``done``/``dead`` are cumulative since engine
    start, so run totals are last − first."""

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


class EnginePoller:
    """Samples the engine API off the event loop and detects post-load drain."""

    def __init__(self, engine_url: str, token: str | None, *, origin: float) -> None:
        self._url = engine_url
        self._token = token
        self._origin = origin
        self._client: EngineClient | None = None
        self._samples: list[EngineSample] = []

    @property
    def client(self) -> EngineClient | None:
        """The underlying client (set after :meth:`open`) — for one-off preflight reads."""
        return self._client

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
        if self._client is not None:
            await asyncio.get_running_loop().run_in_executor(None, self._client.close)
            self._client = None

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
        """Poll until the engine's whole pipeline is empty and inbound/delivery counters stop moving.
        Returns seconds-to-drain, or ``None`` on timeout.

        Drain requires ``in_pipeline == 0`` (no NOT-DONE rows in ANY stage — ingress, routed, or
        outbound), the outbound backlog + summed per-edge ``queue_depth`` at zero, and ``read``/
        ``written`` unchanged across a poll. The ``in_pipeline`` gauge (from ``/stats``) closes the prior
        blind spot: a fully **stalled** router/transform (hung, or rows stranded after a crash) leaves
        the outbound backlog at 0 but ``in_pipeline > 0``, so it no longer reads as drained."""
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
        client = EngineClient(self._url)
        if self._token:
            client.set_token(self._token)  # does a /me request to validate
        self._client = client

    def _sample_sync(self) -> EngineSample | None:
        if self._client is None:
            return None
        try:
            stats = self._client.stats()
            conns = self._client.connections()
            status = self._client.status()
        except ApiError:
            return None  # transient unreachability — skip this sample, keep polling
        ob = stats.outbox_by_status
        # `read` is populated only on inbound rows, `written` only on outbound rows — so summing the
        # non-None values partitions inbound vs outbound without guessing role/direction strings.
        read = sum(r.read for r in conns if r.read is not None)
        written = sum(r.written for r in conns if r.written is not None)
        out_dead = sum(r.errored or 0 for r in conns if r.written is not None)
        queue_depth = sum(r.queue_depth or 0 for r in conns if r.queue_depth is not None)
        return EngineSample(
            elapsed_s=time.perf_counter() - self._origin,
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
            journal_mode=status.db.journal_mode,
            uptime_s=status.engine.uptime_seconds,
        )
