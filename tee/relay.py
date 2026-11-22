# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The tee relay: two MLLP listeners, always-ACK-on-receipt, fan-out, fail-closed.

Topology (backlog #14):

* **Listener A — Epic-facing (the tee):** receives the ``Epic -> Corepoint`` feed, **always ACKs AA on
  receipt**, then forwards the *unchanged* bytes to **Corepoint** (production) and **MEFOR** (shadow).
* **Listener B — Corepoint-copy-facing (optional):** receives copies of the ``Corepoint -> Epic`` feed
  (mirrored by a duplicate outbound send added to Corepoint's configuration), ACKs AA, forwards to MEFOR.

Failure model:

* The **Corepoint** leg is the production path. On a *transport* failure (on every one of a few quick
  tries, counting the first) the relay is **fail-closed**: it stops accepting on Listener A and drops
  live Epic connections so Epic sees the outage and queues/retries on its side. It does **not** exit
  (avoids a crash-loop against a down Corepoint); restart it once Corepoint is healthy. A Corepoint
  **NAK** is *logged, not* a trip — the partner is reachable, it just rejected one message.
* The **MEFOR** leg is shadow-only and fully **decoupled** (a bounded queue drained by its own worker), so
  a slow/down MEFOR never back-pressures or trips the production path. Its failures are logged and dropped.

Always-ACK trade-off: a message in flight at the instant of a Corepoint transport failure is AA'd-but-
undelivered; the trip bounds further loss and Epic's resend/queue covers the rest. (Decided: simple
fail-closed relay, not durable store-and-forward.)
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import suppress
from dataclasses import dataclass

from tee import mllp
from tee.store import RelayStore

__all__ = ["RelayConfig", "TeeRelay", "Endpoint"]

logger = logging.getLogger("tee.relay")

#: A ``(host, port)`` network endpoint.
Endpoint = tuple[str, int]

_READ_CHUNK = 4096


@dataclass(frozen=True)
class RelayConfig:
    """Static configuration for a :class:`TeeRelay`."""

    listen_epic: Endpoint
    corepoint: Endpoint
    mefor: Endpoint
    db_path: str
    listen_corepoint_copy: Endpoint | None = None
    max_frame_bytes: int = 16 * 1024 * 1024  # 16 MiB DoS guard
    receive_timeout: float = 60.0  # close inbound sockets idle this long (None/0 disables)
    connect_timeout: float = 10.0
    send_timeout: float = 30.0
    # Tries on the Corepoint leg, counting the first, before fail-closed; 1 means no retry.
    corepoint_attempts: int = 3
    corepoint_retry_delay: float = 1.0
    mefor_queue_max: int = (
        1000  # bounded shadow buffer; oldest copies dropped (with a log) when full
    )
    capture_bodies: bool = False  # off by default; when on, the DB holds PHI bodies for ALL feeds
    # How long stop() lets in-flight listener handlers finish, and then how long it lets the MEFOR
    # worker drain its queue, before cancelling what is left (so stop() takes at most twice this).
    stop_grace: float = 30.0
    capture_corepoint_copy: bool = (
        # Capture ONLY the Corepoint-copy feed (Corepoint's *output*) — the minimal-PHI posture for a
        # parity/compare run (#14): the bodies the compare tool diffs against MEFOR's transform output,
        # without persisting the whole Epic->Corepoint input stream. Implied by ``capture_bodies``.
        False
    )

    def __post_init__(self) -> None:
        # Refuse these here, before any listener binds: a zero/negative attempt count would skip the
        # Corepoint forward loop, so an ACKed Epic message would never be sent and fail-closed would
        # not trip; a zero/negative bound makes asyncio.Queue unbounded.
        for name in ("corepoint_attempts", "mefor_queue_max"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")


class ForwardError(Exception):
    """A transport-level failure forwarding to a downstream (connect / I/O / timeout / peer-close)."""


@dataclass
class _MeforItem:
    payload: bytes
    control_id: str | None
    message_type: str | None
    direction: str


async def _read_one_frame(reader: asyncio.StreamReader, max_frame_bytes: int) -> bytes:
    """Read bytes until one complete MLLP frame is decoded; raise :class:`ForwardError` on peer close."""
    decoder = mllp.FrameDecoder(max_frame_bytes=max_frame_bytes)
    while True:
        chunk = await reader.read(_READ_CHUNK)
        if not chunk:
            raise ForwardError("peer closed before sending an ACK")
        for message in decoder.feed(chunk):
            return message


async def _close_bounded(writer: asyncio.StreamWriter, timeout: float) -> None:
    """Close a connection, aborting it if the close has not finished within ``timeout``.

    A graceful close waits for buffered bytes to flush, which never happens if the peer stopped
    reading, so an unbounded ``wait_closed()`` would wedge the caller (and through it stop())."""
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout)
    except TimeoutError:
        writer.transport.abort()
    except OSError:
        pass


async def _forward_once(
    endpoint: Endpoint,
    payload: bytes,
    *,
    connect_timeout: float,
    send_timeout: float,
    max_frame_bytes: int,
) -> tuple[str, str | None, str | None]:
    """Forward one framed message to ``endpoint`` and read its ACK.

    Returns ``(outcome, ack_code, detail)`` where outcome is ``"accepted"`` (AA/CA) or ``"nak"`` (any
    negative or unrecognized code). Raises :class:`ForwardError` on any transport-level failure.
    """
    host, port = endpoint
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), connect_timeout
        )
    except (TimeoutError, OSError) as exc:
        raise ForwardError(f"connect to {host}:{port} failed: {exc}") from exc

    try:
        writer.write(mllp.frame(payload))
        await asyncio.wait_for(writer.drain(), send_timeout)
        ack = await asyncio.wait_for(_read_one_frame(reader, max_frame_bytes), send_timeout)
    except TimeoutError as exc:
        raise ForwardError(f"timed out talking to {host}:{port}") from exc
    except (OSError, mllp.FrameError) as exc:
        raise ForwardError(f"I/O error talking to {host}:{port}: {exc}") from exc
    finally:
        await _close_bounded(writer, send_timeout)

    code, detail = mllp.parse_ack(ack)
    outcome = "accepted" if code in ("AA", "CA") else "nak"
    return outcome, code, detail


class _WorkerStop:
    """Singleton sentinel queued by :meth:`TeeRelay.stop` so the MEFOR shadow worker exits cleanly
    out of its ``Queue.get()`` instead of being cancelled mid-wait.

    BACKLOG #17: on CPython 3.11, ``task.cancel()`` of a task parked in ``asyncio.Queue.get()``
    intermittently fails to complete — the getter future stays pending, the task stays in the
    ``cancelling`` state, and ``await self._mefor_worker`` in :meth:`stop` wedges until the test
    watchdog fires. (Reproduced on a py3.11 container; fixed in CPython 3.12, which is why py3.13 is
    clean and production — a single long-lived loop — never hits it.) Stopping via a queued sentinel
    sidesteps the cancellation path entirely."""


_WORKER_STOP = _WorkerStop()


class TeeRelay:
    """An MLLP tee relay. Build with a :class:`RelayConfig`, then ``start()`` / ``stop()`` (or
    ``serve_forever()`` for the CLI)."""

    def __init__(self, config: RelayConfig) -> None:
        self.config = config
        self.store: RelayStore | None = None
        self._tripped = asyncio.Event()
        # Set by the first stop(), even one before start(), and never cleared: a relay is
        # single-use, so a requested stop stays requested.
        self._shutdown = asyncio.Event()
        self._epic_server: asyncio.Server | None = None
        self._copy_server: asyncio.Server | None = None
        # Every live listener handler (both listeners), so stop() can let an in-flight message
        # finish its store writes and MEFOR enqueue before the worker and the store go away.
        self._handler_tasks: set[asyncio.Task[object]] = set()
        self._mefor_queue: asyncio.Queue[_MeforItem | _WorkerStop] = asyncio.Queue()
        self._mefor_worker: asyncio.Task[None] | None = None
        self._stop_task: asyncio.Future[None] | None = None
        # Set while start() runs, so a stop() racing it waits for every listener to be bound
        # rather than tearing down a partial set and memoizing that.
        self._start_done: asyncio.Event | None = None

    # -- properties ----------------------------------------------------------
    @property
    def tripped(self) -> bool:
        """True once the relay has fail-closed (Listener A stopped)."""
        return self._tripped.is_set()

    @property
    def epic_address(self) -> Endpoint:
        """The actually-bound ``(host, port)`` of Listener A (resolves an OS-assigned port 0)."""
        return _server_address(self._epic_server)

    @property
    def copy_address(self) -> Endpoint | None:
        return _server_address(self._copy_server) if self._copy_server is not None else None

    def _require_store(self) -> RelayStore:
        """Return the store, or raise if the relay isn't started — an ``-O``-safe replacement for an
        ``assert`` (assertions are stripped under ``python -O``)."""
        if self.store is None:
            raise RuntimeError("relay not started")
        return self.store

    async def _send_ack(self, writer: asyncio.StreamWriter, message: bytes) -> bool:
        """Write an ``AA`` ACK back to a peer, bounded by ``send_timeout``.

        Returns ``False`` (logged) if the peer is gone or too slow to read, so the caller can stop
        processing rather than hang forever in ``drain()`` or crash on a broken connection. The ``%r``
        of the exception carries no message body (PHI stays out of the log)."""
        try:
            writer.write(mllp.frame(mllp.build_ack(message)))
            await asyncio.wait_for(writer.drain(), self.config.send_timeout)
            return True
        except (TimeoutError, OSError) as exc:
            logger.warning("failed to ACK a peer (connection slow or closed): %r", exc)
            # Discard the queued ACK: left buffered, it could still reach the peer later for a
            # message the caller now neither forwards nor records.
            writer.transport.abort()
            return False

    # -- lifecycle -----------------------------------------------------------
    async def start(self) -> None:
        """Open the store and bind the listeners. A relay is single-use: a second start() is
        refused, and a stop() requested before or during this start() stays in force. One
        requested before it opens nothing and returns; one requested during it lets it finish
        binding, then tears everything down again, and it returns without serving."""
        # A start() that is running, or that ran at all, refuses: one that failed after opening the
        # store leaves it to stop(), whose teardown is memoized, so a second start() would open a
        # store and listeners that no later stop() closes.
        if self._start_done is not None or self._epic_server is not None:
            raise RuntimeError("relay already started")
        cfg = self.config
        self._start_done = asyncio.Event()
        if self._shutdown.is_set():
            # Stopped before it started: open nothing, so no port is bound even briefly.
            self._start_done.set()
            logger.info("tee relay stop requested before start(); not starting")
            return
        logger.warning(
            "tee relay is a TEST-DATA-ONLY validation tool — do not carry production PHI through it"
        )
        try:
            self.store = await RelayStore.open(cfg.db_path)
            self._mefor_queue = asyncio.Queue(maxsize=cfg.mefor_queue_max)
            self._mefor_worker = asyncio.create_task(self._run_mefor_worker())
            self._epic_server = await asyncio.start_server(self._handle_epic, *cfg.listen_epic)
            if cfg.listen_corepoint_copy is not None:
                self._copy_server = await asyncio.start_server(
                    self._handle_corepoint_copy, *cfg.listen_corepoint_copy
                )
        finally:
            self._start_done.set()
        if self._shutdown.is_set():
            # A stop() came during this start(): it stays in force, so tear down what was just
            # opened rather than serve. A stop() still waiting shares this teardown.
            logger.info("tee relay stop requested before start() finished; tearing down")
            await self.stop()
            return
        logger.info(
            "tee relay started: epic=%s -> corepoint=%s + mefor=%s%s (db=%s, capture_bodies=%s,"
            " capture_corepoint_copy=%s)",
            self.epic_address,
            cfg.corepoint,
            cfg.mefor,
            f", copy-listener={self.copy_address}" if self._copy_server else "",
            cfg.db_path,
            cfg.capture_bodies,
            cfg.capture_corepoint_copy,
        )

    async def serve_forever(self) -> None:
        """Start, then run until :meth:`stop` (or cancellation), then tear down. Returns once the
        teardown is done when a stop() came before or during the start."""
        await self.start()
        try:
            await self._shutdown.wait()
        finally:
            await self.stop()

    async def stop(self) -> None:
        """Tear the relay down. Runs once: a concurrent or repeated call (``serve_forever``'s own
        ``finally`` among them) waits for the same teardown rather than starting a second one.
        A stop() racing a start() waits for start() to finish binding, so the teardown covers every
        listener it opens. A stop() before start() has nothing to tear down, so it returns at once,
        but the stop stays requested: a later start() (or ``serve_forever()``) opens nothing and
        serves nothing."""
        self._shutdown.set()
        if self._start_done is not None:
            await self._start_done.wait()
        if self.store is None:
            return
        if self._stop_task is None:
            self._stop_task = asyncio.ensure_future(self._stop())
        await asyncio.shield(self._stop_task)

    async def _stop(self) -> None:
        await self._drain_listeners()
        if self._mefor_worker is not None:
            await self._drain_mefor_worker(self._mefor_worker)
        if self.store is not None:
            await self.store.close()

    async def _drain_listeners(self) -> None:
        """Close both listeners and wait, bounded by ``stop_grace``, for every handler to finish.

        Closing a server does not close its accepted connections, so ``close_clients`` closes them;
        a handler then reads EOF and leaves its loop. A handler already past its ACK keeps going
        until its store writes and its MEFOR enqueue are done: closing the store under it would
        leave an ACKed message with no record, and an enqueue after the worker's stop sentinel
        could evict the sentinel. Whatever is still running at the deadline has its connection
        aborted (a peer that stopped reading would otherwise hold a close open forever) and is
        cancelled, so a wedged peer can delay stop() but never hang it."""
        servers = [s for s in (self._epic_server, self._copy_server) if s is not None]
        for server in servers:
            server.close()
            server.close_clients()
        grace = self.config.stop_grace
        try:
            async with asyncio.timeout(grace):
                # wait_closed returns once every connection is gone, by which point each of their
                # handlers has run its first step and registered in _handler_tasks.
                for server in servers:
                    await server.wait_closed()
                if self._handler_tasks:
                    await asyncio.wait(set(self._handler_tasks))
        except TimeoutError:
            stragglers = set(self._handler_tasks)
            logger.warning(
                "%d listener handler(s) still running after %.1fs; aborting their connections"
                " and cancelling",
                len(stragglers),
                grace,
            )
            for server in servers:
                server.abort_clients()
            for task in stragglers:
                task.cancel()
            await asyncio.gather(*stragglers, return_exceptions=True)

    async def _drain_mefor_worker(self, worker: asyncio.Task[None]) -> None:
        """Let the shadow worker forward what is queued, then stop it, bounded by ``stop_grace``.

        The worker stops on a queued sentinel rather than a cancel() of a task parked in
        Queue.get(), which intermittently deadlocks on CPython 3.11 (BACKLOG #17, see _WorkerStop).
        No listener handler is left to enqueue by now, so a blocking put cannot be raced and
        nothing can displace the sentinel. A worker still busy at the deadline (MEFOR slow or
        down) is cancelled, which is safe because it is then not parked in an empty get()."""
        grace = self.config.stop_grace
        try:
            async with asyncio.timeout(grace):
                await self._mefor_queue.put(_WORKER_STOP)
                await asyncio.wait({worker})
        except TimeoutError:
            pending = self._mefor_queue.qsize()
            logger.warning(
                "MEFOR shadow worker still draining after %.1fs; cancelling it and dropping up to"
                " %d queued copies",
                grace,
                pending,
            )
            worker.cancel()
        with suppress(asyncio.CancelledError):
            await worker

    def _register_handler(self) -> None:
        """Record the running listener handler so stop() can wait for it."""
        task = asyncio.current_task()
        if task is not None:
            self._handler_tasks.add(task)
            task.add_done_callback(self._handler_tasks.discard)

    # -- fail-closed ---------------------------------------------------------
    async def _trip(self, reason: str) -> None:
        """Stop accepting on Listener A and drop live Epic connections (fail-closed). Idempotent."""
        if self._tripped.is_set():
            return
        self._tripped.set()
        logger.critical(
            "FAIL-CLOSED: stopping the Epic listener — %s. Epic will see the connection drop and "
            "should queue/retry; the MEFOR shadow leg and copy listener keep running. Restart the "
            "relay once Corepoint is healthy.",
            reason,
        )
        if self._epic_server is not None:
            self._epic_server.close()
            self._epic_server.close_clients()

    # -- Listener A: Epic -> (Corepoint + MEFOR) -----------------------------
    async def _handle_epic(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername")
        self._register_handler()
        try:
            if self._shutdown.is_set():  # accepted as stop() began: serve nothing
                return
            async for message in self._iter_frames(reader):
                if self._tripped.is_set():
                    break
                if self._shutdown.is_set():
                    _log_unacked_at_stop(message)
                    break
                try:
                    await self._process_epic_message(message, writer)
                except Exception as exc:  # a store/unexpected error must not kill the listener task
                    logger.warning("error processing an Epic message (%r); closing connection", exc)
                    break
        except _ConnectionClosed:
            pass
        except mllp.FrameError as exc:
            logger.warning("Epic connection %s framing error: %s; closing", peer, exc)
        finally:
            writer.close()
            with suppress(OSError):
                await writer.wait_closed()

    async def _process_epic_message(self, message: bytes, writer: asyncio.StreamWriter) -> None:
        store = self._require_store()
        cfg = self.config
        control_id, message_type = mllp.peek_fields(message)
        size = len(message)

        # 1. Always ACK on receipt — the relay is the ACK authority to Epic. If the ACK can't be sent
        #    (peer gone/slow), stop here: Epic will resend, so don't forward an unconfirmed message.
        if not await self._send_ack(writer, message):
            return

        async def record_corepoint(outcome: str, code: str | None, detail: str | None) -> None:
            await store.record_leg(
                direction="epic_to_corepoint",
                leg="corepoint",
                control_id=control_id,
                message_type=message_type,
                size_bytes=size,
                outcome=outcome,
                ack_code=code,
                detail=detail,
            )

        # Everything after the ACK sits under one cut-off handler: a stop() that runs out of grace
        # cancels this task wherever it is (the capture, the forward, or the leg's own write), and
        # an ACKed message must still leave a Corepoint row and a log line.
        result: tuple[str, str | None, str | None] | None = None  # the Corepoint leg, once known
        recorded = False
        try:
            if cfg.capture_bodies:
                await store.record_capture(
                    direction="epic_to_corepoint", control_id=control_id, raw=message
                )

            # 2. Production leg: Corepoint (a transport failure trips fail-closed; a NAK is only
            #    logged).
            try:
                result = await self._forward_corepoint(message)
            except ForwardError as exc:
                result = ("transport_error", None, str(exc))
                await record_corepoint(*result)
                recorded = True
                await self._trip(f"Corepoint unreachable: {exc}")
                return

            outcome, code, detail = result
            await record_corepoint(outcome, code, detail)
            recorded = True
            if outcome == "nak":
                logger.warning(
                    "Corepoint NAK (%s) control_id=%s type=%s: %s",
                    code,
                    control_id,
                    message_type,
                    detail,
                )

            # 3. Shadow leg: MEFOR (decoupled, best-effort — never blocks/trips the production
            #    path).
            self._enqueue_mefor(_MeforItem(message, control_id, message_type, "epic_to_corepoint"))
        except asyncio.CancelledError:
            if not recorded:
                await self._record_cut_off(control_id, result, record_corepoint)
            raise

    async def _record_cut_off(
        self,
        control_id: str | None,
        result: tuple[str, str | None, str | None] | None,
        record: Callable[[str, str | None, str | None], Awaitable[None]],
    ) -> None:
        """Log and record an ACKed Epic message that stop() cancelled before its Corepoint row.

        With the forward unfinished, delivery is unknown, so the row is a transport error (which
        ``naks`` lists). With the forward done, the row carries its real outcome; if the cancel hit
        the leg's own write after it reached the database, that outcome can then appear twice,
        which is safer than no row. The log names only the control id, never message content."""
        if result is None:
            logger.warning(
                "relay stop cut off an ACKed message before its Corepoint forward finished;"
                " delivery unknown control_id=%s",
                control_id,
            )
            result = (
                "transport_error",
                None,
                "cancelled by relay stop after the ACK; delivery unknown",
            )
        else:
            logger.warning(
                "relay stop cut off an ACKed message while recording its Corepoint leg"
                " (outcome=%s) control_id=%s",
                result[0],
                control_id,
            )
        try:
            await record(*result)
        except Exception as exc:  # noqa: BLE001 -- the cancel must still propagate
            logger.error("could not record the cut-off message (%r) control_id=%s", exc, control_id)

    async def _forward_corepoint(self, payload: bytes) -> tuple[str, str | None, str | None]:
        """Forward to Corepoint with a few quick retries; raise :class:`ForwardError` if all fail."""
        cfg = self.config
        last: ForwardError | None = None
        for attempt in range(1, cfg.corepoint_attempts + 1):
            try:
                return await _forward_once(
                    cfg.corepoint,
                    payload,
                    connect_timeout=cfg.connect_timeout,
                    send_timeout=cfg.send_timeout,
                    max_frame_bytes=cfg.max_frame_bytes,
                )
            except ForwardError as exc:
                last = exc
                logger.warning(
                    "Corepoint forward attempt %d/%d failed: %s",
                    attempt,
                    cfg.corepoint_attempts,
                    exc,
                )
                if attempt < cfg.corepoint_attempts:
                    await asyncio.sleep(cfg.corepoint_retry_delay)
        if last is None:  # unreachable: RelayConfig refuses corepoint_attempts < 1
            raise ForwardError("no Corepoint forward attempt was made")
        raise last

    # -- Listener B: Corepoint copies -> MEFOR -------------------------------
    async def _handle_corepoint_copy(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername")
        self._register_handler()
        try:
            if self._shutdown.is_set():  # accepted as stop() began: serve nothing
                return
            async for message in self._iter_frames(reader):
                if self._shutdown.is_set():
                    _log_unacked_at_stop(message)
                    break
                try:
                    if not await self._process_copy_message(message, writer):
                        break
                except Exception as exc:  # a store/unexpected error must not kill the listener task
                    logger.warning("error processing a copy message (%r); closing connection", exc)
                    break
        except _ConnectionClosed:
            pass
        except mllp.FrameError as exc:
            logger.warning("Copy connection %s framing error: %s; closing", peer, exc)
        finally:
            writer.close()
            with suppress(OSError):
                await writer.wait_closed()

    async def _process_copy_message(self, message: bytes, writer: asyncio.StreamWriter) -> bool:
        """ACK a Corepoint-copy message and forward it to MEFOR. Returns False if the peer is gone."""
        control_id, message_type = mllp.peek_fields(message)
        # Always ACK the copy feed so Corepoint's outbound send isn't disrupted.
        if not await self._send_ack(writer, message):
            return False
        # Corepoint's output is the parity baseline — capture it under EITHER the all-feeds flag or the
        # copy-only posture (so a compare run needn't persist the whole Epic->Corepoint input stream).
        if self.config.capture_bodies or self.config.capture_corepoint_copy:
            await self._require_store().record_capture(
                direction="corepoint_copy", control_id=control_id, raw=message
            )
        self._enqueue_mefor(_MeforItem(message, control_id, message_type, "corepoint_copy"))
        return True

    # -- MEFOR shadow leg (decoupled worker) ---------------------------------
    def _enqueue_mefor(self, item: _MeforItem) -> None:
        """Enqueue a copy for the MEFOR worker; drop the oldest if the buffer is full.

        Best-effort and non-blocking (uses ``put_nowait``) so a slow MEFOR never back-pressures the
        production path. A drop is **always** logged — including the rare race where a concurrent
        enqueuer takes the slot we freed, in which case we drop *this* item instead."""
        try:
            self._mefor_queue.put_nowait(item)
            return
        except asyncio.QueueFull:
            pass
        dropped_id: str | None = None
        try:
            dropped = self._mefor_queue.get_nowait()
            self._mefor_queue.task_done()
            dropped_id = dropped.control_id if isinstance(dropped, _MeforItem) else None
        except asyncio.QueueEmpty:
            pass
        try:
            self._mefor_queue.put_nowait(item)
            logger.warning(
                "MEFOR shadow queue full (%d); dropped oldest copy control_id=%s",
                self.config.mefor_queue_max,
                dropped_id,
            )
        except asyncio.QueueFull:
            logger.warning(
                "MEFOR shadow queue full (%d); dropped copy control_id=%s",
                self.config.mefor_queue_max,
                item.control_id,
            )

    async def _run_mefor_worker(self) -> None:
        cfg = self.config
        while True:
            item = await self._mefor_queue.get()
            if isinstance(item, _WorkerStop):  # clean shutdown signal from stop() (BACKLOG #17)
                self._mefor_queue.task_done()
                return
            try:
                try:
                    outcome, code, detail = await _forward_once(
                        cfg.mefor,
                        item.payload,
                        connect_timeout=cfg.connect_timeout,
                        send_timeout=cfg.send_timeout,
                        max_frame_bytes=cfg.max_frame_bytes,
                    )
                except ForwardError as exc:
                    outcome, code, detail = "transport_error", None, str(exc)
                await self._require_store().record_leg(
                    direction=item.direction,
                    leg="mefor",
                    control_id=item.control_id,
                    message_type=item.message_type,
                    size_bytes=len(item.payload),
                    outcome=outcome,
                    ack_code=code,
                    detail=detail,
                )
                if outcome != "accepted":
                    logger.info(
                        "MEFOR shadow leg %s control_id=%s: %s", outcome, item.control_id, detail
                    )
            except Exception as exc:  # noqa: BLE001 — the shadow worker must never die.
                # %r (not logger.exception): no traceback frames, so no payload can reach the log.
                logger.error("MEFOR shadow worker error (continuing): %r", exc)
            finally:
                self._mefor_queue.task_done()

    # -- shared frame iteration ----------------------------------------------
    async def _iter_frames(self, reader: asyncio.StreamReader) -> AsyncIterator[bytes]:
        """Yield complete MLLP frames from ``reader`` until it closes or goes idle.

        Raises :class:`_ConnectionClosed` on EOF / idle-timeout so the caller's loop ends cleanly.
        """
        cfg = self.config
        decoder = mllp.FrameDecoder(max_frame_bytes=cfg.max_frame_bytes)
        while True:
            try:
                if cfg.receive_timeout:
                    chunk = await asyncio.wait_for(reader.read(_READ_CHUNK), cfg.receive_timeout)
                else:
                    chunk = await reader.read(_READ_CHUNK)
            except TimeoutError:
                raise _ConnectionClosed from None
            except OSError:
                raise _ConnectionClosed from None
            if not chunk:
                raise _ConnectionClosed
            for message in decoder.feed(chunk):
                yield message


def _log_unacked_at_stop(message: bytes) -> None:
    """Log a frame read during stop() and left un-ACKed, so its sender resends it."""
    logger.info(
        "relay stopping; left a received message un-ACKed for resend control_id=%s",
        mllp.peek_fields(message)[0],
    )


class _ConnectionClosed(Exception):
    """Internal: an inbound connection closed or went idle (ends a read loop cleanly)."""


def _server_address(server: asyncio.Server | None) -> Endpoint:
    if server is None or not server.sockets:
        return ("", 0)
    host, port = server.sockets[0].getsockname()[:2]
    return (host, port)
