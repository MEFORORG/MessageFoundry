# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The harness Send tab generates a batch on the worker thread, caps its result rows, and shuts
down without ``QThread.terminate`` (BACKLOG #5949).

The tab generated every message of a batch of up to a million in a loop on the GUI thread before
the worker started, added a result row per message with no cap, and on close waited six seconds and
then terminated a worker that sat in a pause between messages.
"""

from __future__ import annotations

import socket
import threading
import time
from typing import Any

import pytest

pytest.importorskip("PySide6")

from harness import send  # noqa: E402
from harness.mllp import SendItem, SendResult  # noqa: E402
from messagefoundry_toolkit.generators import _core  # noqa: E402

_MSG = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01^ADT_A01|X1|P|2.5.1\rEVN|A01|20260101\r"


@pytest.fixture(scope="module")
def qapp() -> Any:
    from PySide6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


@pytest.fixture
def off_gui_generation(monkeypatch: pytest.MonkeyPatch) -> list[threading.Thread]:
    """Generation refuses the GUI thread and records where it ran."""
    threads: list[threading.Thread] = []

    def generate(code: str, trigger: str, index: int, **_kw: object) -> str:
        if threading.current_thread() is threading.main_thread():
            raise AssertionError("a message was generated on the GUI thread")
        threads.append(threading.current_thread())
        return _MSG

    monkeypatch.setattr(_core, "generate_message", generate)
    return threads


def _until(qapp: Any, cond: Any, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        qapp.processEvents()
        if cond():
            return True
        time.sleep(0.01)
    return False


def _item(seq: int) -> SendItem:
    return SendItem(seq, "ADT", "A01", f"X{seq}", _MSG)


# --- Send tab (BACKLOG #5949) ---------------------------------------------------------------------


def test_send_generates_on_the_worker_and_stops_inside_a_pause(
    qapp: Any, off_gui_generation: list[threading.Thread]
) -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(4)
    port = server.getsockname()[1]
    panel = send.SendPanel()
    panel._count.setValue(1_000_000)
    panel._rate.setValue(0.1)  # a ten-second pause between two messages
    panel._host.setText("127.0.0.1")
    panel._port.setValue(port)
    conn: socket.socket | None = None
    try:
        started = time.monotonic()
        panel._start()
        assert time.monotonic() - started < 2, "the batch was built before the worker started"
        # Accept and answer nothing: the worker waits for an ACK, which stop() interrupts, and
        # then would pause ten seconds before the next message.
        server.settimeout(10)
        conn, _ = server.accept()
        assert off_gui_generation
        thread = panel._thread
        assert thread is not None
        started = time.monotonic()
        panel.shutdown()
        assert time.monotonic() - started < 3, "shutdown waited out the read or the pause"
        assert thread.isFinished()
    finally:
        panel.shutdown()
        if conn is not None:
            conn.close()
        server.close()


def test_send_rows_are_capped_and_the_summary_counts_all(
    qapp: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(send, "MAX_RESULT_ROWS", 3)
    panel = send.SendPanel()
    try:
        for seq in range(1, 6):
            panel._on_result(SendResult(_item(seq), seq != 5, "AA" if seq != 5 else "AE", 1.0, ""))
        assert panel._results.rowCount() == 3
        text = panel._summary.text()
        assert "sent 5" in text and "accepted 4" in text and "failed 1" in text
        assert "first 3" in text
    finally:
        panel.shutdown()
