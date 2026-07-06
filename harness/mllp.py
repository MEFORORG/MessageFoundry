# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""MLLP transport for the test harness.

Sending runs in a worker thread (blocking sockets) so a burst of N messages never freezes the
UI; receiving uses a ``QTcpServer`` (event-driven, mostly idle). Both reuse the engine's
byte-level framing (:func:`frame` / :class:`MLLPDecoder`) and ACK builder (:func:`build_ack`),
so the harness frames and acknowledges exactly like the engine.
"""

from __future__ import annotations

import socket
import threading
import time
from dataclasses import dataclass
from datetime import datetime

from PySide6.QtCore import QObject, QTimer, Signal
from PySide6.QtNetwork import QHostAddress, QTcpServer, QTcpSocket

from messagefoundry.config import AckMode
from messagefoundry.parsing import HL7PeekError, Peek, normalize
from messagefoundry.transports.mllp import MLLPDecoder, build_ack, frame

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
                try:
                    self._sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

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
    """A localhost MLLP listener: emits each inbound message and replies per :attr:`ack_mode`."""

    received = Signal(object)  # Received

    def __init__(self) -> None:
        super().__init__()
        self._server = QTcpServer(self)
        self._server.newConnection.connect(self._on_new_connection)
        self._decoders: dict[QTcpSocket, MLLPDecoder] = {}
        self.ack_mode = "AA"  # any label in REPLY_MODES
        self.delay_seconds = 1.0  # DELAY_AA: how long to wait before acknowledging
        self.fail_first = 1  # FAIL_THEN_AA: reject this many deliveries per control id, then accept
        self._seen: dict[str, int] = {}  # control id -> arrivals (drives duplicate detection)

    def is_listening(self) -> bool:
        return self._server.isListening()

    def port(self) -> int:
        return int(self._server.serverPort())

    def start(self, port: int) -> bool:
        self._seen.clear()
        return self._server.listen(QHostAddress(QHostAddress.SpecialAddress.LocalHost), port)

    def stop(self) -> None:
        for sock in list(self._decoders):
            sock.disconnectFromHost()
        self._decoders.clear()
        self._server.close()

    def _on_new_connection(self) -> None:
        while self._server.hasPendingConnections():
            sock = self._server.nextPendingConnection()
            self._decoders[sock] = MLLPDecoder()
            sock.readyRead.connect(lambda s=sock: self._on_ready_read(s))
            sock.disconnected.connect(lambda s=sock: self._cleanup(s))

    def _cleanup(self, sock: QTcpSocket) -> None:
        self._decoders.pop(sock, None)
        sock.deleteLater()

    def _on_ready_read(self, sock: QTcpSocket) -> None:
        decoder = self._decoders.get(sock)
        if decoder is None:
            return
        for message in decoder.feed(bytes(sock.readAll().data())):
            text = message.decode("utf-8", "replace")
            rec = self._describe(sock, text)
            if rec.control_id:
                self._seen[rec.control_id] = self._seen.get(rec.control_id, 0) + 1
                rec.seen = self._seen[rec.control_id]
            self.received.emit(rec)
            self._reply(sock, text, rec.control_id, rec.seen)

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
            QTimer.singleShot(
                max(0, int(self.delay_seconds * 1000)), lambda: self._delayed_aa(sock, text)
            )
        elif mode == FAIL_THEN_AA:
            code = "AA" if seen > self.fail_first else "AR"
            self._write_ack(sock, text, code, AckMode.ORIGINAL)

    def _delayed_aa(self, sock: QTcpSocket, text: str) -> None:
        if sock not in self._decoders:  # the engine may have timed out and closed by now
            return
        try:
            self._write_ack(sock, text, "AA", AckMode.ORIGINAL)
        except RuntimeError:  # underlying socket already deleted
            pass

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
