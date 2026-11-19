# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""MLLP transport for the test harness.

Sending runs in a worker thread (blocking sockets) so a burst of N messages never freezes the
UI; receiving uses a ``QTcpServer`` (event-driven, mostly idle). Both reuse the engine's
byte-level framing (:class:`MLLPDecoder`, and the frame-byte rule of ADR 0205) and ACK builder
(:func:`build_ack`), so the harness frames and acknowledges like the engine: a send holding an MLLP
frame byte is refused (:func:`frame_checked`), and an ACK echoing one is neutralised
(:func:`frame_neutralised`). The Compose tab keeps the checked framer too unless the operator
ticks its opt-in to send frame bytes on purpose; only then does it pass the bare framer.
"""

from __future__ import annotations

import contextlib
import errno
import logging
import os
import select
import socket
import sys
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from PySide6.QtCore import QObject, QTimer, Signal
from PySide6.QtNetwork import QHostAddress, QTcpServer, QTcpSocket

from harness.frame_cap import resolve_max_frame_bytes
from messagefoundry.mllpcodec import (
    DEFAULT_MAX_FRAME_BYTES,
    AckMode,
    FrameEncodeError,
    FramePayloadError,
    MLLPDecoder,
    MLLPFrameError,
    build_ack,
    frame_checked,
    frame_neutralised,
)
from messagefoundry.parsing import HL7PeekError, Peek, normalize

# ACK-mode label -> (build_ack code, ack_mode). "none" sends no acknowledgement.
ACK_MODES: dict[str, tuple[str, AckMode]] = {
    "AA": ("AA", AckMode.ORIGINAL),
    "AE": ("AE", AckMode.ORIGINAL),
    "AR": ("AR", AckMode.ORIGINAL),
    "none": ("", AckMode.NONE),
}

# Fault-injection reply modes (beyond the plain ACK codes) for exercising the engine's *outbound*
# retry / dead-letter / independent-draining behavior when a destination peer misbehaves.
DELAY_AA = "delay then AA"  # reply AA after delay_seconds (> the engine's timeout → it retries)
CLOSE = "close (no reply)"  # drop the connection without acknowledging (immediate delivery failure)
FAIL_THEN_AA = "fail N then AA"  # AR for the first fail_first deliveries of a control id, then AA
REPLY_MODES = [*ACK_MODES, DELAY_AA, CLOSE, FAIL_THEN_AA]


@dataclass
class SendItem:
    seq: int
    code: str
    trigger: str
    control_id: str
    payload: str


@dataclass
class SendResult:
    item: SendItem
    ok: bool
    ack_code: str
    latency_ms: float
    error: str


@dataclass
class Received:
    when: str
    peer: str
    code: str
    trigger: str
    control_id: str
    raw: str
    seen: int = 1  # how many times this control id has arrived (>1 ⇒ an at-least-once duplicate)


def _ack_code(ack_text: str) -> str:
    try:
        return Peek.parse(normalize(ack_text)).field("MSA-1") or "?"
    except HL7PeekError:
        return "?"


# How often a dial in progress looks at the stop flag, so stop() is seen within about this long
# rather than after the whole connect timeout (BACKLOG #5947).
_STOP_POLL_S = 0.1
# What a non-blocking connect_ex returns while the dial is still in progress. Winsock says
# WSAEWOULDBLOCK. On POSIX only EINPROGRESS means that: an EAGAIN or EWOULDBLOCK there is a dial
# that failed, so it must surface as the error a blocking dial would have raised, not be polled as
# if it were still connecting.
_WSAEWOULDBLOCK = 10035
_DIAL_IN_PROGRESS_POSIX = frozenset({errno.EINPROGRESS})
_DIAL_IN_PROGRESS_WINDOWS = frozenset(
    {errno.EINPROGRESS, getattr(errno, "WSAEWOULDBLOCK", _WSAEWOULDBLOCK)}
)


def _dial_in_progress(code: int) -> bool:
    """Whether ``code`` from a non-blocking ``connect_ex`` means the dial is still in progress."""
    if sys.platform == "win32":
        return code in _DIAL_IN_PROGRESS_WINDOWS
    return code in _DIAL_IN_PROGRESS_POSIX


# The socket constructor the dial uses; a seam for a test that needs a dial which never settles.
_open_socket = socket.socket

log = logging.getLogger(__name__)


def pause_unless_stopped(stop: threading.Event, seconds: float) -> bool:
    """Sleep ``seconds``, or less if ``stop`` is set meanwhile; return True if it is set.

    ``time.sleep`` in :data:`_STOP_POLL_S` slices rather than one ``Event.wait``: on Windows an
    ``Event.wait`` rounds up to the system timer tick, about 15 ms, which would cap a rate of
    1000 messages a second at about 65."""
    deadline = time.monotonic() + seconds
    while not stop.is_set():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(remaining, _STOP_POLL_S))
    return True


def _socket_error(code: int) -> OSError:
    """The OSError subclass and text a blocking connect would have raised for ``code``."""
    if sys.platform == "win32":
        import ctypes

        return OSError(None, ctypes.FormatError(code), None, code)
    return OSError(code, os.strerror(code))


def _dial_settled(sock: socket.socket, wait_s: float) -> bool:
    """Whether a non-blocking dial has finished, either way, within ``wait_s``. Windows reports a
    failed dial only as an exceptional condition, so ``select`` watches for both there; elsewhere
    ``poll`` has no descriptor-number ceiling, which ``select`` has."""
    if not hasattr(select, "poll"):
        _, writable, failed = select.select([], [sock], [sock], wait_s)
        return bool(writable or failed)
    poller = select.poll()
    poller.register(sock, select.POLLOUT)
    return bool(poller.poll(wait_s * 1000))


class SendWorker(QObject):
    """Sends a batch of messages over MLLP, emitting one :class:`SendResult` per message.

    Lives in a worker thread: ``run`` blocks on sockets; :meth:`stop` is thread-safe and is seen
    promptly, whether the worker is dialling, waiting for an ACK, or pausing between messages.
    """

    result = Signal(object)  # SendResult
    finished = Signal()

    def __init__(
        self,
        host: str,
        port: int,
        items: Iterable[SendItem],
        *,
        timeout: float,
        rate: float,
        expect_ack: bool = True,
        framer: Callable[[str], bytes] = frame_checked,
    ) -> None:
        super().__init__()
        # frame_checked unless the caller sends hostile framing on purpose (the Compose tab's opt-in).
        self._framer = framer
        self._host = host
        self._port = port
        self._items = items
        self._timeout = timeout
        self._rate = rate
        self._expect_ack = expect_ack  # False: NONE-ack inbound — confirm no ACK in a short window
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._sock: socket.socket | None = None
        # Set before finished when the batch ended on a fault, so the tab can say so.
        self.failure = ""

    def stop(self) -> None:
        """Stop between messages, and interrupt an in-flight blocking recv on the current socket
        (so Stop / app-close don't hang for the full timeout against a slow or silent peer). A dial
        in progress and a pause between messages see the flag within :data:`_STOP_POLL_S`."""
        self._stop.set()
        with self._lock:
            if self._sock is not None:
                with contextlib.suppress(OSError):
                    self._sock.shutdown(socket.SHUT_RDWR)

    def run(self) -> None:
        # The items may be generated lazily on this thread, so a generator fault ends the batch
        # here; finished is emitted whatever happens, or the tab would wait on it for good.
        try:
            delay = 1.0 / self._rate if self._rate > 0 else 0.0
            for item in self._items:
                if self._stop.is_set():
                    break
                self.result.emit(self._send_one(item))
                if delay and pause_unless_stopped(self._stop, delay):
                    break
        except Exception as exc:  # noqa: BLE001 -- any fault ends the batch; the tab must hear why
            log.exception("harness send batch ended early")
            self.failure = f"{type(exc).__name__}: {exc}"
        finally:
            self.finished.emit()

    def _connect(self) -> socket.socket:
        """``socket.create_connection`` with the same timeout for each address, but each dial is
        a non-blocking connect polled in :data:`_STOP_POLL_S` slices, so :meth:`stop` aborts it. A
        blocking dial could not be interrupted, and held a window close for the whole connect
        timeout. The name lookup before it still blocks."""
        last: OSError | None = None
        for family, kind, proto, _name, addr in socket.getaddrinfo(
            self._host, self._port, type=socket.SOCK_STREAM
        ):
            sock: socket.socket | None = None
            try:
                sock = _open_socket(family, kind, proto)
                self._dial(sock, addr, time.monotonic() + self._timeout)
            except OSError as exc:
                if sock is not None:
                    sock.close()
                last = exc
                if self._stop.is_set():
                    break
                continue
            last = None  # an earlier address's error holds this frame in its traceback: a cycle
            return sock
        if last is None:
            raise OSError("getaddrinfo returned no address")
        try:
            raise last
        finally:
            # The raised error's traceback holds this frame; dropping the local breaks that cycle,
            # which would otherwise keep this worker alive until a collection on another thread.
            last = None

    def _dial(self, sock: socket.socket, addr: Any, deadline: float) -> None:
        sock.setblocking(False)
        code = sock.connect_ex(addr)
        if code and not _dial_in_progress(code):
            raise _socket_error(code)
        while code:
            if self._stop.is_set():
                raise ConnectionAbortedError("stopped while connecting")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("timed out")
            if _dial_settled(sock, min(_STOP_POLL_S, remaining)):
                code = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                if code:
                    raise _socket_error(code)
                break
        sock.settimeout(self._timeout)

    def _send_one(self, item: SendItem) -> SendResult:
        start = time.monotonic()
        # Framed before any dial: by default a payload holding an MLLP start or end byte would not
        # arrive as one message, so it is refused here with the reason and no connection is opened
        # (ADR 0205 rule 1, the engine's own delivery rule).
        try:
            wire = self._framer(item.payload)
        except (FramePayloadError, FrameEncodeError) as exc:
            latency = (time.monotonic() - start) * 1000.0
            return SendResult(item, False, "-", latency, f"not sent: {exc}")
        try:
            with self._connect() as sock:
                with self._lock:
                    self._sock = sock  # publish so stop() can interrupt a blocking recv
                    # A stop() that ran between the dial and the publish found no socket to shut
                    # down; read its flag under the same lock so it is not missed.
                    stopped = self._stop.is_set()
                try:
                    if stopped:
                        raise ConnectionAbortedError("stopped before sending")
                    sock.settimeout(self._timeout)
                    sock.sendall(wire)
                    if not self._expect_ack:
                        return self._read_no_ack(item, sock, start)
                    # The reply is the engine's, another party's, so it is bounded like the receive
                    # side (ASVS 5.1.1): an over-cap frame is refused below, never buffered whole.
                    decoder = MLLPDecoder(max_frame_bytes=DEFAULT_MAX_FRAME_BYTES)
                    ack = b""
                    while not ack:
                        chunk = self._recv(sock)
                        if not chunk:
                            raise ConnectionError("peer closed before sending an ACK")
                        for message in decoder.feed(chunk):
                            ack = message
                            break
                finally:
                    with self._lock:
                        self._sock = None
            latency = (time.monotonic() - start) * 1000.0
            code = _ack_code(ack.decode("utf-8", "replace"))
            return SendResult(item, code in ("AA", "CA"), code, latency, "")
        except MLLPFrameError as exc:
            latency = (time.monotonic() - start) * 1000.0
            return SendResult(item, False, "-", latency, f"reply refused: {exc}")
        except OSError as exc:
            latency = (time.monotonic() - start) * 1000.0
            return SendResult(item, False, "-", latency, str(exc))

    def _recv(self, sock: socket.socket) -> bytes:
        """``sock.recv(4096)`` under the worker's timeout, waited in :data:`_STOP_POLL_S` slices so
        :meth:`stop` is seen. Shutting the socket down does not wake a blocked receive on every
        platform while the peer stays silent; Windows is one where it does not."""
        deadline = time.monotonic() + self._timeout
        while True:
            if self._stop.is_set():
                raise ConnectionAbortedError("stopped while waiting for an ACK")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("timed out")
            sock.settimeout(min(_STOP_POLL_S, remaining))
            try:
                return sock.recv(4096)
            except TimeoutError:
                continue
            finally:
                sock.settimeout(self._timeout)

    def _read_no_ack(self, item: SendItem, sock: socket.socket, start: float) -> SendResult:
        """Fire-and-forget: confirm no ACK arrives in a short window (a NONE-ack inbound sends
        none). If one *does* arrive, report its code with ok=False so an unexpected ACK is flagged
        rather than silently passing."""
        sock.settimeout(0.5)
        try:
            chunk = sock.recv(4096)
        except (TimeoutError, OSError):
            chunk = b""
        latency = (time.monotonic() - start) * 1000.0
        if not chunk:
            return SendResult(item, True, "(none)", latency, "")
        try:
            for message in MLLPDecoder(max_frame_bytes=DEFAULT_MAX_FRAME_BYTES).feed(chunk):
                code = _ack_code(message.decode("utf-8", "replace"))
                return SendResult(item, False, code, latency, "unexpected ACK")
        except MLLPFrameError as exc:  # unreachable while one recv is 4096 bytes; kept for the cap
            return SendResult(item, False, "-", latency, f"reply refused: {exc}")
        return SendResult(item, False, "?", latency, "unexpected reply")


class MllpReceiver(QObject):
    """A localhost MLLP listener: emits each inbound message and replies per :attr:`ack_mode`.

    It bounds each frame at :attr:`max_frame_bytes`, the engine's MLLP default; ``0`` turns the cap
    off, as on the engine. The harness wheel is attached to every release and this listener takes
    frames from another party, so it is an ASVS 5.1.1 upload feature (``docs/CONNECTIONS.md``,
    BACKLOG #1127). An over-cap frame is never handed on or acknowledged: the connection is dropped,
    as the engine's MLLP source does, and :attr:`refused` says why. A frame accepted before the
    refusal still gets its ACK first, including a delayed one."""

    received = Signal(object)  # Received
    refused = Signal(str)  # "<peer>: <reason>" for a connection dropped over an over-cap frame

    def __init__(self) -> None:
        super().__init__()
        self._server = QTcpServer(self)
        self._server.newConnection.connect(self._on_new_connection)
        self._decoders: dict[QTcpSocket, MLLPDecoder] = {}
        self.ack_mode = "AA"  # any label in REPLY_MODES
        self.delay_seconds = 1.0  # DELAY_AA: how long to wait before acknowledging
        self.fail_first = 1  # FAIL_THEN_AA: reject this many deliveries per control id, then accept
        self._seen: dict[str, int] = {}  # control id -> arrivals (drives duplicate detection)
        # DELAY_AA acknowledgements not yet written, per connection, and the refused connections
        # held open only until theirs are. A refusal drops the decoder at once, so a refused
        # connection reads nothing more, but it must not take back an ACK already owed.
        self._pending_acks: dict[QTcpSocket, int] = {}
        self._closing: set[QTcpSocket] = set()
        self._max_frame_bytes: int | None = DEFAULT_MAX_FRAME_BYTES

    @property
    def max_frame_bytes(self) -> int | None:
        """The frame cap each new connection is given; ``0`` or ``None`` turns it off."""
        return self._max_frame_bytes

    @max_frame_bytes.setter
    def max_frame_bytes(self, value: int | None) -> None:
        resolve_max_frame_bytes(value)  # refuse a negative here, not inside a Qt slot later
        self._max_frame_bytes = value

    def is_listening(self) -> bool:
        return self._server.isListening()

    def port(self) -> int:
        return int(self._server.serverPort())

    def start(self, port: int) -> bool:
        self._seen.clear()
        return self._server.listen(QHostAddress(QHostAddress.SpecialAddress.LocalHost), port)

    def stop(self) -> None:
        for sock in [*self._decoders, *self._closing]:
            sock.disconnectFromHost()
        self._decoders.clear()
        self._closing.clear()
        self._pending_acks.clear()
        self._server.close()

    def _on_new_connection(self) -> None:
        while self._server.hasPendingConnections():
            sock = self._server.nextPendingConnection()
            self._decoders[sock] = MLLPDecoder(
                max_frame_bytes=resolve_max_frame_bytes(self._max_frame_bytes)
            )
            sock.readyRead.connect(lambda s=sock: self._on_ready_read(s))
            sock.disconnected.connect(lambda s=sock: self._cleanup(s))

    def _cleanup(self, sock: QTcpSocket) -> None:
        self._decoders.pop(sock, None)
        self._closing.discard(sock)
        self._pending_acks.pop(sock, None)
        sock.deleteLater()

    def _on_ready_read(self, sock: QTcpSocket) -> None:
        decoder = self._decoders.get(sock)
        if decoder is None:
            if sock in self._closing:
                sock.readAll()  # refused: discard, so a held-open socket cannot buffer without bound
            return
        try:
            for message in decoder.feed(bytes(sock.readAll().data())):
                text = message.decode("utf-8", "replace")
                rec = self._describe(sock, text)
                if rec.control_id:
                    self._seen[rec.control_id] = self._seen.get(rec.control_id, 0) + 1
                    rec.seen = self._seen[rec.control_id]
                self.received.emit(rec)
                self._reply(sock, text, rec.control_id, rec.seen)
        except MLLPFrameError as exc:
            # Drop the decoder first so a late readyRead finds nothing to feed. Disconnect rather
            # than abort: an ACK already written for a valid frame earlier in this read still goes.
            # A delayed ACK not yet written holds the connection open until it is (_delayed_aa).
            self._decoders.pop(sock, None)
            self.refused.emit(f"{sock.peerAddress().toString()}:{sock.peerPort()}: {exc}")
            if self._pending_acks.get(sock):
                self._closing.add(sock)
            else:
                sock.disconnectFromHost()

    def _reply(self, sock: QTcpSocket, text: str, control_id: str, seen: int) -> None:
        """Acknowledge per the active reply mode — including faults that make the engine retry."""
        mode = self.ack_mode
        if mode in ACK_MODES:
            code, ack_mode = ACK_MODES[mode]
            if code:
                self._write_ack(sock, text, code, ack_mode)
        elif mode == CLOSE:
            sock.disconnectFromHost()  # no ACK at all → the engine's send fails immediately
        elif mode == DELAY_AA:
            self._pending_acks[sock] = self._pending_acks.get(sock, 0) + 1
            QTimer.singleShot(
                max(0, int(self.delay_seconds * 1000)), lambda: self._delayed_aa(sock, text)
            )
        elif mode == FAIL_THEN_AA:
            code = "AA" if seen > self.fail_first else "AR"
            self._write_ack(sock, text, code, AckMode.ORIGINAL)

    def _delayed_aa(self, sock: QTcpSocket, text: str) -> None:
        if sock not in self._decoders and sock not in self._closing:
            return  # the engine may have timed out and closed by now
        remaining = self._pending_acks.get(sock, 1) - 1
        if remaining > 0:
            self._pending_acks[sock] = remaining
        else:
            self._pending_acks.pop(sock, None)
        try:
            self._write_ack(sock, text, "AA", AckMode.ORIGINAL)
            if sock in self._closing and remaining <= 0:
                # The last ACK owed on a refused connection is written: now drop it. Disconnect
                # sends what is buffered before it closes.
                self._closing.discard(sock)
                sock.disconnectFromHost()
        except RuntimeError:  # underlying socket already deleted
            self._closing.discard(sock)

    @staticmethod
    def _write_ack(sock: QTcpSocket, text: str, code: str, ack_mode: AckMode) -> None:
        # The ACK echoes the inbound's header values, which may hold a start byte as data: neutralised
        # so the engine always reads exactly one reply frame (the engine's own listeners do the same).
        sock.write(frame_neutralised(build_ack(text, code=code, ack_mode=ack_mode, timestamp="")))

    @staticmethod
    def _describe(sock: QTcpSocket, text: str) -> Received:
        peer = f"{sock.peerAddress().toString()}:{sock.peerPort()}"
        try:
            peek = Peek.parse(normalize(text))
            code = peek.message_code or "?"
            trigger = peek.trigger_event or ""
            control_id = peek.control_id or ""
        except HL7PeekError:
            code, trigger, control_id = "?", "", ""
        return Received(datetime.now().strftime("%H:%M:%S"), peer, code, trigger, control_id, text)
