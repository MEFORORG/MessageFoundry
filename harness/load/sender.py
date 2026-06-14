"""The MLLP sender — a pool of persistent, pipelined connections, plus type→target routing.

Unlike the GUI harness's one-socket-per-message ``SendWorker`` (RTT-bound), each
:class:`PersistentConnection` holds one TCP connection open and pipelines: the writer keeps sending
while ACKs come back in order on the reader side, so throughput is decoupled from round-trip latency.
ACK latency is timed per message (send→ACK) and streamed into a histogram; the message's end-to-end
timing is the correlation sink's job. Connections reconnect with capped backoff and stop cooperatively
(stop offering → grace for in-flight ACKs → cancel), mirroring the engine's own shutdown discipline.

A :class:`ConnectionPool` fans submissions across its connections; a :class:`Dispatcher` routes each
message to a pool whose target accepts its message type, weighted across eligible targets.
"""

from __future__ import annotations

import asyncio
import contextlib
import random
import time
from collections import deque
from collections.abc import Callable

from messagefoundry.transports.mllp import MLLPDecoder, frame

from harness.load.corpus import Outgoing
from harness.load.correlator import Correlator
from harness.load.metrics import LiveMetrics
from harness.load.profile import Target

OnDone = Callable[[], None]
_Job = tuple[Outgoing, OnDone | None]
_GET_POLL = 0.1  # how often an idle writer wakes to re-check the stop flag

_READ_BYTES = 65536
_ACCEPT = frozenset({"AA", "CA"})  # MSA-1 accept codes; anything else is a NAK
_BACKOFF_START = 0.1
_BACKOFF_MAX = 5.0


def _ack_code(payload: bytes) -> str:
    """MSA-1 from an ACK frame via a cheap segment scan (no full parse on the hot path)."""
    head_end = payload.find(b"\r")
    head = payload if head_end < 0 else payload[:head_end]
    if len(head) < 4:
        return ""
    sep = head[3:4]
    for seg in payload.split(b"\r"):
        if seg[:3] == b"MSA":
            parts = seg.split(sep)
            return parts[1].decode("ascii", "replace") if len(parts) > 1 else ""
    return ""


class PersistentConnection:
    """One persistent, pipelined MLLP connection to a single target endpoint."""

    def __init__(
        self,
        host: str,
        port: int,
        correlator: Correlator,
        metrics: LiveMetrics,
        *,
        expect_ack: bool = True,
        queue_max: int = 1000,
    ) -> None:
        self._host = host
        self._port = port
        self._correlator = correlator
        self._m = metrics
        self._expect_ack = expect_ack
        self._queue: asyncio.Queue[_Job] = asyncio.Queue(maxsize=queue_max)
        self._inflight: deque[tuple[int, int, str, OnDone | None]] = deque()
        self._stop = asyncio.Event()
        self._stop_grace = (
            2.0  # seconds to wait for in-flight ACKs at graceful stop (set by stop())
        )
        self._task: asyncio.Task[None] | None = None

    # --- public API ----------------------------------------------------------

    def start(self) -> None:
        self._task = asyncio.create_task(self._run(), name=f"loadconn-{self._host}:{self._port}")

    def submit_nowait(self, out: Outgoing, on_done: OnDone | None = None) -> bool:
        """Enqueue without blocking; ``False`` if the connection's buffer is full (caller defers)."""
        try:
            self._queue.put_nowait((out, on_done))
            return True
        except asyncio.QueueFull:
            return False

    async def submit(self, out: Outgoing, on_done: OnDone | None = None) -> None:
        """Enqueue, awaiting buffer space (closed-loop backpressure)."""
        await self._queue.put((out, on_done))

    @property
    def queued(self) -> int:
        return self._queue.qsize()

    async def stop(self, grace: float) -> None:
        # Set the flag; the writer drains whatever is queued, then exits when the queue is empty (so a
        # graceful stop still sends already-accepted work). No sentinel — that could wedge if the
        # connection is mid-reconnect with nothing draining the queue. `grace` bounds how long _serve
        # then waits for outstanding ACKs (set before the event so the writer sees it).
        self._stop_grace = grace
        self._stop.set()
        if self._task is not None:
            with contextlib.suppress(asyncio.CancelledError):
                await self._task

    # --- internals -----------------------------------------------------------

    async def _run(self) -> None:
        backoff = _BACKOFF_START
        while not self._stop.is_set():
            try:
                reader, writer = await asyncio.open_connection(self._host, self._port)
            except OSError:
                self._m.counters.errors += 1
                if await self._wait_backoff(backoff):
                    return
                backoff = min(backoff * 2, _BACKOFF_MAX)
                continue
            backoff = _BACKOFF_START
            try:
                await self._serve(reader, writer)
            except (OSError, ConnectionError):
                pass
            finally:
                self._fail_inflight()
                writer.close()
                with contextlib.suppress(ConnectionError, OSError):
                    await writer.wait_closed()
            if self._stop.is_set():
                return
            if await self._wait_backoff(backoff):  # brief pause before reconnect
                return

    async def _wait_backoff(self, seconds: float) -> bool:
        """Sleep ``seconds`` or until stop; return True if stopping."""
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(self._stop.wait(), timeout=seconds)
        return self._stop.is_set()

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        wtask = asyncio.create_task(self._write_loop(writer))
        rtask = asyncio.create_task(self._read_loop(reader)) if self._expect_ack else None
        tasks = {wtask} | ({rtask} if rtask else set())
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        # If the writer finished (queue drained on graceful stop), give in-flight ACKs the configured
        # grace (set by stop()) before cancelling the reader.
        if wtask in done and rtask is not None and not rtask.done():
            await self._grace_for_acks(rtask, self._stop_grace)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        for task in done:
            exc = task.exception()
            if exc is not None and not isinstance(exc, asyncio.CancelledError):
                raise exc

    async def _grace_for_acks(self, rtask: asyncio.Task[None], grace: float = 2.0) -> None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + grace
        while self._inflight and not rtask.done() and loop.time() < deadline:
            await asyncio.sleep(0.005)

    async def _write_loop(self, writer: asyncio.StreamWriter) -> None:
        while True:
            if self._stop.is_set() and self._queue.empty():
                return  # drained everything that was accepted before the stop
            try:
                job = await asyncio.wait_for(self._queue.get(), timeout=_GET_POLL)
            except TimeoutError:
                continue  # idle wake to re-check the stop flag
            out, on_done = job
            send_ns = time.perf_counter_ns()
            self._correlator.on_send(out.seq, send_ns)
            self._m.counters.sent += 1
            if self._expect_ack:
                self._inflight.append((out.seq, send_ns, out.control_id, on_done))
            writer.write(frame(out.payload))
            if not self._expect_ack:
                # No ACK expected: the message is "done" once written. Complete it BEFORE the drain
                # await — there is no await between popping the job and here, so a cancel/disconnect at
                # the drain can't strand the job (it is never in _inflight, so _fail_inflight wouldn't
                # release its closed-loop slot either).
                self._m.counters.acked += 1
                if on_done is not None:
                    on_done()
            await writer.drain()

    async def _read_loop(self, reader: asyncio.StreamReader) -> None:
        decoder = MLLPDecoder()
        while True:
            chunk = await reader.read(_READ_BYTES)
            if not chunk:
                return  # peer closed
            for ack in decoder.feed(chunk):
                self._on_ack(ack)

    def _on_ack(self, ack: bytes) -> None:
        ack_ns = time.perf_counter_ns()
        if not self._inflight:
            return  # an unexpected ACK with nothing outstanding
        # MLLP ACKs are in-order per connection (the engine ACKs on receipt in send order).
        _seq, send_ns, _cid, on_done = self._inflight.popleft()
        self._m.ack.record(float(ack_ns - send_ns))
        if _ack_code(ack) in _ACCEPT:
            self._m.counters.acked += 1
        else:
            self._m.counters.nak += 1
        if on_done is not None:
            on_done()

    def _fail_inflight(self) -> None:
        """On disconnect, count outstanding (sent, no ACK seen) as timeouts and release their slots."""
        if not self._inflight:
            return
        for _seq, _send_ns, _cid, on_done in self._inflight:
            self._m.counters.timeouts += 1
            if on_done is not None:
                on_done()
        self._inflight.clear()


class ConnectionPool:
    """A set of persistent connections to one target; submissions fan across them round-robin."""

    def __init__(
        self,
        target: Target,
        size: int,
        correlator: Correlator,
        metrics: LiveMetrics,
        *,
        queue_max: int = 1000,
    ) -> None:
        if size <= 0:
            raise ValueError("pool size must be positive")
        self._conns = [
            PersistentConnection(
                target.host,
                target.port,
                correlator,
                metrics,
                expect_ack=target.expect_ack,
                queue_max=queue_max,
            )
            for _ in range(size)
        ]
        self._rr = 0

    def start(self) -> None:
        for conn in self._conns:
            conn.start()

    def submit_nowait(self, out: Outgoing, on_done: OnDone | None = None) -> bool:
        """Try each connection (starting round-robin) until one accepts; ``False`` if all are full."""
        n = len(self._conns)
        for offset in range(n):
            conn = self._conns[(self._rr + offset) % n]
            if conn.submit_nowait(out, on_done):
                self._rr = (self._rr + offset + 1) % n
                return True
        return False

    async def submit(self, out: Outgoing, on_done: OnDone | None = None) -> None:
        """Await-enqueue to the least-loaded connection (closed-loop backpressure)."""
        conn = min(self._conns, key=lambda c: c.queued)
        await conn.submit(out, on_done)

    async def stop(self, grace: float) -> None:
        await asyncio.gather(*(conn.stop(grace) for conn in self._conns))


class Dispatcher:
    """Route a message (by type code) to a pool whose target accepts it, weighted across eligibles."""

    def __init__(self, pools: list[tuple[Target, ConnectionPool]], *, seed: str = "load") -> None:
        self._pools = pools
        self._rng = random.Random(f"{seed}-dispatch")

    def start(self) -> None:
        for _target, pool in self._pools:
            pool.start()

    def route(self, code: str) -> ConnectionPool | None:
        eligible = [(t, p) for t, p in self._pools if not t.types or code in t.types]
        if not eligible:
            return None
        if len(eligible) == 1:
            return eligible[0][1]
        # Use the same effective weight on both sides (clamp negatives to 0) so a weight-0 target is
        # genuinely never selected — matching the corpus Sampler's skip-on-<=0 convention. Earlier this
        # coerced 0 to 1.0 in the running sum, so a 0-weight target still drew traffic.
        weights = [max(0.0, t.weight) for t, _ in eligible]
        total = sum(weights)
        if total <= 0.0:  # all eligible targets weighted 0 → fall back to uniform choice
            return self._rng.choice(eligible)[1]
        x = self._rng.random() * total
        running = 0.0
        for (_target, pool), weight in zip(eligible, weights):
            running += weight
            if x <= running:
                return pool
        return eligible[-1][1]

    async def stop(self, grace: float) -> None:
        await asyncio.gather(*(pool.stop(grace) for _target, pool in self._pools))
