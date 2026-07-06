# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The tee relay: two MLLP listeners, always-ACK-on-receipt, fan-out, fail-closed.

Topology (backlog #14):

* **Listener A — Epic-facing (the tee):** receives the ``Epic -> Corepoint`` feed, **always ACKs AA on
  receipt**, then forwards the *unchanged* bytes to **Corepoint** (production) and **MEFOR** (shadow).
* **Listener B — Corepoint-copy-facing (optional):** receives copies of the ``Corepoint -> Epic`` feed
  (mirrored by a duplicate outbound send added to Corepoint's configuration), ACKs AA, forwards to MEFOR.

Failure model:

* The **Corepoint** leg is the production path. On a *transport* failure (after a few quick retries) the
  relay is **fail-closed**: it stops accepting on Listener A and drops live Epic connections so Epic sees
  the outage and queues/retries on its side. It does **not** exit (avoids a crash-loop against a down
  Corepoint); restart it once Corepoint is healthy. A Corepoint **NAK** is *logged, not* a trip — the
  partner is reachable, it just rejected one message.
* The **MEFOR** leg is shadow-only and fully **decoupled** (a bounded queue drained by its own worker), so
  a slow/down MEFOR never back-pressures or trips the production path. Its failures are logged and dropped.

Always-ACK trade-off: a message in flight at the instant of a Corepoint transport failure is AA'd-but-
undelivered; the trip bounds further loss and Epic's resend/queue covers the rest. (Decided: simple
fail-closed relay, not durable store-and-forward.)
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import suppress
from dataclasses import dataclass
from typing import AsyncIterator

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
    corepoint_attempts: int = 3  # quick retries on the Corepoint leg before tripping fail-closed
    corepoint_retry_delay: float = 1.0
    mefor_queue_max: int = (
        1000  # bounded shadow buffer; oldest copies dropped (with a log) when full
    )
    capture_bodies: bool = False  # off by default; when on, the DB holds PHI bodies for ALL feeds
    capture_corepoint_copy: bool = (
        # Capture ONLY the Corepoint-copy feed (Corepoint's *output*) — the minimal-PHI posture for a
        # parity/compare run (#14): the bodies the compare tool diffs against MEFOR's transform output,
        # without persisting the whole Epic->Corepoint input stream. Implied by ``capture_bodies``.
        False
    )


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
    except (OSError, asyncio.TimeoutError) as exc:
        raise ForwardError(f"connect to {host}:{port} failed: {exc}") from exc

    try:
        writer.write(mllp.frame(payload))
        await asyncio.wait_for(writer.drain(), send_timeout)
        ack = await asyncio.wait_for(_read_one_frame(reader, max_frame_bytes), send_timeout)
    except asyncio.TimeoutError as exc:
        raise ForwardError(f"timed out talking to {host}:{port}") from exc
    except (OSError, mllp.FrameError) as exc:
        raise ForwardError(f"I/O error talking to {host}:{port}: {exc}") from exc
    finally:
        writer.close()
        with suppress(OSError):
            await writer.wait_closed()

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
        self._shutdown = asyncio.Event()
        self._epic_server: asyncio.Server | None = None
        self._copy_server: asyncio.Server | None = None
        self._epic_writers: set[asyncio.StreamWriter] = set()
        self._mefor_queue: asyncio.Queue[_MeforItem | _WorkerStop] = asyncio.Queue()
        self._mefor_worker: asyncio.Task[None] | None = None

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
        except (asyncio.TimeoutError, OSError) as exc:
            logger.warning("failed to ACK a peer (connection slow or closed): %r", exc)
            return False

    # -- lifecycle -----------------------------------------------------------
    async def start(self) -> None:
        if self._epic_server is not None:
            raise RuntimeError("relay already started")
        cfg = self.config
        logger.warning(
            "tee relay is a TEST-DATA-ONLY validation tool — do not carry production PHI through it"
        )
        self.store = await RelayStore.open(cfg.db_path)
        self._mefor_queue = asyncio.Queue(maxsize=cfg.mefor_queue_max)
        self._mefor_worker = asyncio.create_task(self._run_mefor_worker())
        self._epic_server = await asyncio.start_server(self._handle_epic, *cfg.listen_epic)
        if cfg.listen_corepoint_copy is not None:
            self._copy_server = await asyncio.start_server(
                self._handle_corepoint_copy, *cfg.listen_corepoint_copy
            )
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
        """Start, then run until :meth:`stop` (or cancellation), then tear down."""
        await self.start()
        try:
            await self._shutdown.wait()
        finally:
            await self.stop()

    async def stop(self) -> None:
        self._shutdown.set()
        if self._epic_server is not None:
            self._epic_server.close()
        if self._copy_server is not None:
            self._copy_server.close()
        for writer in list(self._epic_writers):
            writer.close()
            with suppress(OSError):
                await writer.wait_closed()
        if self._mefor_worker is not None:
            # Stop the shadow worker by queueing a sentinel so it returns cleanly from its
            # Queue.get(), rather than cancel()-ing a task parked in get() — which intermittently
            # deadlocks on CPython 3.11 (BACKLOG #17, see _WorkerStop). put_nowait succeeds whenever
            # the worker is actually parked in get() (an empty queue is never full); the QueueFull
            # fallback only fires when the queue is non-empty, i.e. the worker is NOT in get(), so
            # cancel() is safe there.
            try:
                self._mefor_queue.put_nowait(_WORKER_STOP)
            except asyncio.QueueFull:
                self._mefor_worker.cancel()
            with suppress(asyncio.CancelledError):
                await self._mefor_worker
        if self.store is not None:
            await self.store.close()

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
        for writer in list(self._epic_writers):
            writer.close()
            with suppress(OSError):
                await writer.wait_closed()

    # -- Listener A: Epic -> (Corepoint + MEFOR) -----------------------------
    async def _handle_epic(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername")
        self._epic_writers.add(writer)
        try:
            async for message in self._iter_frames(reader):
                if self._tripped.is_set():
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
            self._epic_writers.discard(writer)
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

        if cfg.capture_bodies:
            await store.record_capture(
                direction="epic_to_corepoint", control_id=control_id, raw=message
            )

        # 2. Production leg: Corepoint (a transport failure trips fail-closed; a NAK is only logged).
        try:
            outcome, code, detail = await self._forward_corepoint(message)
        except ForwardError as exc:
            await store.record_leg(
                direction="epic_to_corepoint",
                leg="corepoint",
                control_id=control_id,
                message_type=message_type,
                size_bytes=size,
                outcome="transport_error",
                ack_code=None,
                detail=str(exc),
            )
            await self._trip(f"Corepoint unreachable: {exc}")
            return

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
        if outcome == "nak":
            logger.warning(
                "Corepoint NAK (%s) control_id=%s type=%s: %s",
                code,
                control_id,
                message_type,
                detail,
            )

        # 3. Shadow leg: MEFOR (decoupled, best-effort — never blocks/trips the production path).
        self._enqueue_mefor(_MeforItem(message, control_id, message_type, "epic_to_corepoint"))

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
        assert last is not None  # corepoint_attempts >= 1, so the loop ran and set `last`
        raise last

    # -- Listener B: Corepoint copies -> MEFOR -------------------------------
    async def _handle_corepoint_copy(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername")
        try:
            async for message in self._iter_frames(reader):
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
            except asyncio.TimeoutError:
                raise _ConnectionClosed from None
            except OSError:
                raise _ConnectionClosed from None
            if not chunk:
                raise _ConnectionClosed
            for message in decoder.feed(chunk):
                yield message


class _ConnectionClosed(Exception):
    """Internal: an inbound connection closed or went idle (ends a read loop cleanly)."""


def _server_address(server: asyncio.Server | None) -> Endpoint:
    if server is None or not server.sockets:
        return ("", 0)
    host, port = server.sockets[0].getsockname()[:2]
    return (host, port)
