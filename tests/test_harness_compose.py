"""The harness Compose tab: presets seed the editor, fire-and-forget send skips the ACK wait, and
the ACK-expectation match logic classifies results correctly."""

from __future__ import annotations

import socket
import threading
from typing import Any

import pytest

pytest.importorskip("PySide6")

from messagefoundry.transports.mllp import MLLPDecoder, build_ack, frame  # noqa: E402
from harness.compose import _ACCEPT, _NONE, _REJECT, ComposePanel  # noqa: E402
from harness.mllp import SendItem, SendResult, SendWorker  # noqa: E402

_MSG = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01^ADT_A01|X1|P|2.5.1\rEVN|A01|20260101\r"
_OK_COL = 4


@pytest.fixture(scope="module")
def qapp() -> Any:
    from PySide6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


def test_presets_seed_the_editor(qapp: Any) -> None:
    panel = ComposePanel()
    panel._apply_preset(2)  # "No MSH segment"
    assert panel._editor.toPlainText().startswith("PID")
    panel._apply_preset(3)  # "Bad version (2.3)"
    assert "|2.3" in panel._editor.toPlainText()
    panel._apply_preset(4)  # "Clear"
    assert panel._editor.toPlainText() == ""


def test_send_worker_fire_and_forget_skips_ack_wait(qapp: Any) -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def serve() -> None:
        conn, _ = server.accept()
        with conn:
            conn.recv(4096)  # consume the frame, deliberately send no ACK (NONE-mode inbound)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()

    results: list[SendResult] = []
    worker = SendWorker(
        "127.0.0.1",
        port,
        [SendItem(1, "ADT", "A01", "X1", _MSG)],
        timeout=3.0,
        rate=0.0,
        expect_ack=False,
    )
    worker.result.connect(results.append)
    worker.run()
    thread.join(timeout=3)
    server.close()

    assert results and results[0].ok and results[0].ack_code == "(none)"
    assert results[0].latency_ms < 2000  # returned without blocking on the (absent) ACK


def test_ack_expectation_match_logic(qapp: Any) -> None:
    panel = ComposePanel()
    item = SendItem(1, "ADT", "A01", "X1", _MSG)

    def last_ok(expect: str, ack_code: str) -> str:
        panel._pending_expect = expect
        panel._on_mllp_result(SendResult(item, ack_code in ("AA", "CA"), ack_code, 1.0, ""))
        return panel._results.item(panel._results.rowCount() - 1, _OK_COL).text()

    assert last_ok(_ACCEPT, "AA") == "yes"
    assert last_ok(_ACCEPT, "AE") == "no"
    assert last_ok(_REJECT, "AR") == "yes"  # malformed message NAK'd as expected
    assert last_ok(_REJECT, "AA") == "no"
    assert last_ok(_NONE, "(none)") == "yes"


def test_no_ack_expectation_flags_an_unexpected_reply(qapp: Any) -> None:
    """Selecting 'No ACK' must FAIL if the peer actually does ACK (not silently pass)."""
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
                    conn.sendall(
                        frame(
                            build_ack(message.decode("utf-8", "replace"), code="AA", timestamp="")
                        )
                    )
                    return

    threading.Thread(target=serve, daemon=True).start()

    results: list[SendResult] = []
    worker = SendWorker(
        "127.0.0.1",
        port,
        [SendItem(1, "ADT", "A01", "X1", _MSG)],
        timeout=3.0,
        rate=0.0,
        expect_ack=False,
    )
    worker.result.connect(results.append)
    worker.run()
    server.close()

    assert results and results[0].ack_code == "AA" and not results[0].ok
    assert "unexpected" in results[0].error
