"""The standalone test harness (``harness``): panels build; MLLP send + receive work."""

from __future__ import annotations

import socket
import threading
import time
from typing import Any

import pytest

pytest.importorskip("PySide6")

from messagefoundry.transports.mllp import MLLPDecoder, build_ack, frame  # noqa: E402
from harness.mllp import MllpReceiver, SendItem, SendWorker  # noqa: E402

_MSG = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01^ADT_A01|X1|P|2.5.1\rEVN|A01|20260101\r"


@pytest.fixture(scope="module")
def qapp() -> Any:
    from PySide6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


def test_window_and_panels_build(qapp: Any) -> None:
    from harness.window import HarnessWindow

    win = HarnessWindow()
    codes = [win.send_panel._code.itemText(i) for i in range(win.send_panel._code.count())]
    assert "ADT" in codes  # registry-driven type list
    assert win.send_panel._trigger.count() > 1  # "(random…)" + real triggers


def test_receiver_emits_and_acks(qapp: Any) -> None:
    recv = MllpReceiver()
    recv.ack_mode = "AA"
    got: list[Any] = []
    recv.received.connect(got.append)
    assert recv.start(0)  # 0 -> OS-assigned port
    port = recv.port()

    client = socket.create_connection(("127.0.0.1", port), 3)
    client.settimeout(0.2)
    client.sendall(frame(_MSG))
    decoder = MLLPDecoder()
    ack = b""
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline and not ack:
        qapp.processEvents()
        try:
            for message in decoder.feed(client.recv(4096)):
                ack = message
                break
        except TimeoutError:
            pass
    client.close()
    recv.stop()

    assert got and got[0].control_id == "X1" and got[0].code == "ADT"
    assert b"MSA|AA|X1" in ack


def test_send_worker_reports_ack(qapp: Any) -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def serve() -> None:
        conn, _ = server.accept()
        decoder = MLLPDecoder()
        with conn:
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                for message in decoder.feed(chunk):
                    ack = build_ack(message.decode("utf-8", "replace"), code="AA", timestamp="")
                    conn.sendall(frame(ack))
                    return

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()

    results: list[Any] = []
    worker = SendWorker(
        "127.0.0.1", port, [SendItem(1, "ADT", "A01", "X1", _MSG)], timeout=3.0, rate=0.0
    )
    worker.result.connect(results.append)
    worker.run()
    thread.join(timeout=3)
    server.close()

    assert results and results[0].ok and results[0].ack_code == "AA"


def test_send_worker_stop_interrupts_blocking_recv(qapp: Any) -> None:
    """stop() must abort an in-flight recv promptly (not block for the full timeout), so the
    window can close without destroying a still-running thread."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def serve() -> None:
        conn, _ = server.accept()
        with conn:  # read the frame, then keep reading; deliberately never ACK
            try:
                while conn.recv(4096):
                    pass
            except OSError:
                pass

    threading.Thread(target=serve, daemon=True).start()

    # Drive _send_one on a worker thread and capture its return directly (a Qt signal emitted from a
    # plain non-Qt thread wouldn't deliver). stop() from this thread must abort the blocked recv.
    worker = SendWorker("127.0.0.1", port, [], timeout=30.0, rate=0.0)
    out: list[Any] = []
    wt = threading.Thread(
        target=lambda: out.append(worker._send_one(SendItem(1, "ADT", "A01", "X1", _MSG))),
        daemon=True,
    )
    wt.start()
    time.sleep(0.3)  # let it block in recv waiting for an ACK that never comes
    worker.stop()
    wt.join(timeout=3)  # would hang ~30s without the socket-shutdown interrupt
    server.close()

    assert not wt.is_alive()
    assert out and not out[0].ok  # the interrupted send is reported as failed


def test_window_closes_cleanly(qapp: Any) -> None:
    """closeEvent shuts every panel down; with all panels idle it must not raise/crash."""
    from harness.window import HarnessWindow

    win = HarnessWindow()
    assert win.close()  # triggers closeEvent -> panel.shutdown() for all panels
