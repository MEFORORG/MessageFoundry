# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""MLLP transport for the test harness.

Sending runs in a worker thread (blocking sockets) so a burst of N messages never freezes the
UI; receiving uses a ``QTcpServer`` (event-driven, mostly idle). Both reuse the engine's
byte-level framing (:func:`frame` / :class:`MLLPDecoder`) and ACK builder (:func:`build_ack`),
so the harness frames and acknowledges exactly like the engine.
"""

from __future__ import annotations

import contextlib
import socket
import threading
import time
from dataclasses import dataclass
from datetime import datetime

from PySide6.QtCore import QObject, QTimer, Signal
from PySide6.QtNetwork import QHostAddress, QTcpServer, QTcpSocket

from harness.frame_cap import resolve_max_frame_bytes
from messagefoundry.mllpcodec import (
    DEFAULT_MAX_FRAME_BYTES,
    AckMode,
    MLLPDecoder,
    MLLPFrameError,
    build_ack,
    frame,
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


class SendWorker(QObject):
    """Sends a batch of messages over MLLP, emitting one :class:`SendResult` per message.

    Lives in a worker thread: ``run`` blocks on sockets; :meth:`stop` is a thread-safe flag.
    """

    result = Signal(object)  # SendResult
    finished = Signal()

    def __init__(
        self,
        host: str,
        port: int,
        items: list[SendItem],
        *,
        timeout: float,
        rate: float,
        expect_ack: bool = True,
    ) -> None:
        super().__init__()
        self._host = host
        self._port = port
        self._items = items
        self._timeout = timeout
        self._rate = rate
        self._expect_ack = expect_ack  # False: NONE-ack inbound — confirm no ACK in a short window
        self._stop = False
        self._lock = threading.Lock()
        self._sock: socket.socket | None = None

    def stop(self) -> None:
        """Stop between messages, and interrupt an in-flight blocking recv on the current socket
        (so Stop / app-close don't hang for the full timeout against a slow or silent peer)."""
        self._stop = True
        with self._lock:
            if self._sock is not None:
                with contextlib.suppress(OSError):
                    self._sock.shutdown(socket.SHUT_RDWR)

    def run(self) -> None:
        delay = 1.0 / self._rate if self._rate > 0 else 0.0
        for item in self._items:
            if self._stop:
                break
            self.result.emit(self._send_one(item))
            if delay:
                time.sleep(delay)
        self.finished.emit()

    def _send_one(self, item: SendItem) -> SendResult:
        start = time.monotonic()
        try:
            with socket.create_connection((self._host, self._port), self._timeout) as sock:
                with self._lock:
                    self._sock = sock  # publish so stop() can interrupt a blocking recv
                try:
                    sock.settimeout(self._timeout)
                    sock.sendall(frame(item.payload))
                    if not self._expect_ack:
                        return self._read_no_ack(item, sock, start)
                    decoder = MLLPDecoder()
                    ack = b""
                    while not ack:
                        chunk = sock.recv(4096)
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
        except OSError as exc:
            latency = (time.monotonic() - start) * 1000.0
            return SendResult(item, False, "-", latency, str(exc))

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
        for message in MLLPDecoder().feed(chunk):
            code = _ack_code(message.decode("utf-8", "replace"))
            return SendResult(item, False, code, latency, "unexpected ACK")
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
        sock.write(frame(build_ack(text, code=code, ack_mode=ack_mode, timestamp="")))

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
