# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The harness Compose tab: presets seed the editor, fire-and-forget send skips the ACK wait, and
the ACK-expectation match logic classifies results correctly."""

from __future__ import annotations

import socket
import threading
from typing import Any

import pytest

pytest.importorskip("PySide6")

from harness.compose import _ACCEPT, _NONE, _REJECT, ComposePanel  # noqa: E402
from harness.mllp import SendItem, SendResult, SendWorker  # noqa: E402
from messagefoundry.transports.mllp import MLLPDecoder, build_ack, frame  # noqa: E402

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
        cell = panel._results.item(panel._results.rowCount() - 1, _OK_COL)
        assert cell is not None
        return cell.text()

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


@pytest.mark.parametrize(("over", "ok"), [(0, True), (1, False)])
def test_send_worker_bounds_the_ack_at_the_frame_cap(
    qapp: Any, monkeypatch: pytest.MonkeyPatch, over: int, ok: bool
) -> None:
    """The ACK is the engine's content (ASVS 5.1.1): at the cap it is read whole, one byte over it is
    refused and recorded, never buffered whole or cut short."""
    import harness.mllp as harness_mllp

    cap = 256
    monkeypatch.setattr(harness_mllp, "DEFAULT_MAX_FRAME_BYTES", cap)
    head = b"MSH|^~\\&|B|A|D|C|20260101||ACK|X1|P|2.5.1\rMSA|AA|X1|"
    reply = head + b"x" * (cap + over - len(head))
    server = socket.create_server(("127.0.0.1", 0))
    port = server.getsockname()[1]

    def serve() -> None:
        conn, _ = server.accept()
        with conn:
            conn.recv(65536)
            conn.sendall(frame(reply))
            conn.recv(1)  # hold open until the worker closes

    threading.Thread(target=serve, daemon=True).start()
    results: list[SendResult] = []
    worker = SendWorker(
        "127.0.0.1", port, [SendItem(1, "ADT", "A01", "X1", _MSG)], timeout=3.0, rate=0.0
    )
    worker.result.connect(results.append)
    worker.run()
    server.close()

    assert len(results) == 1
    if ok:
        assert results[0].ok and results[0].ack_code == "AA"
    else:
        assert not results[0].ok and results[0].error.startswith("reply refused:")


# --- framing: checked by default, unchecked only on the opt-in (ASVS 1.1.2) ----------------------

_HOSTILE = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01^ADT_A01|X\x0b1|P|2.5.1\rEVN|A01|20260101\r"
_ERROR_COL = 5


def _send_and_wait(panel: ComposePanel, qapp: Any) -> str:
    """Press Send, pump events until the worker thread reports, and return the Error cell."""
    import time

    rows = panel._results.rowCount()
    panel._send()
    deadline = time.monotonic() + 10.0
    while (panel._worker is not None or panel._results.rowCount() == rows) and (
        time.monotonic() < deadline
    ):
        qapp.processEvents()
        time.sleep(0.01)
    assert panel._worker is None and panel._results.rowCount() == rows + 1
    cell = panel._results.item(rows, _ERROR_COL)
    assert cell is not None
    return cell.text()


def _listener() -> socket.socket:
    server = socket.create_server(("127.0.0.1", 0))
    server.settimeout(0.3)
    return server


def test_compose_refuses_a_frame_byte_by_default_before_any_connection(qapp: Any) -> None:
    server = _listener()
    try:
        panel = ComposePanel()
        assert not panel._raw_frame.isChecked()  # the safe framer is the default
        panel._editor.setPlainText(_HOSTILE)
        panel._port.setValue(server.getsockname()[1])
        panel._expect.setCurrentText(_REJECT)
        error = _send_and_wait(panel, qapp)
        assert error.startswith("not sent: MLLP: payload holds the frame start byte 0x0B")
        assert "ADT" not in error  # the byte and its position, never the content
        with pytest.raises(TimeoutError):
            server.accept()  # no connection was opened
    finally:
        server.close()


def test_compose_sends_the_frame_byte_when_the_operator_opts_in(qapp: Any) -> None:
    server = _listener()
    server.settimeout(5.0)
    got: list[bytes] = []

    def serve() -> None:
        conn, _ = server.accept()
        with conn:
            conn.settimeout(5.0)
            data = b""
            while not data.endswith(b"\x1c\r"):
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            got.append(data)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        panel = ComposePanel()
        panel._raw_frame.setChecked(True)
        panel._editor.setPlainText(_HOSTILE)
        panel._port.setValue(server.getsockname()[1])
        panel._expect.setCurrentText(_NONE)
        _send_and_wait(panel, qapp)
        thread.join(timeout=5.0)
        assert not panel._raw_frame.isChecked()  # the opt-in covers one send, then clears
    finally:
        server.close()
    # The bare frame went out: the payload's own 0x0B sits inside the frame, as the operator asked.
    assert got and got[0] == frame(_HOSTILE)
