# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The harness MLLP send worker stops promptly while dialling, and the Compose tab's shutdown never
needs ``QThread.terminate`` (BACKLOG #5947).

The worker used a blocking ``socket.create_connection`` with a ten-second timeout, which ``stop()``
could not interrupt, and the tab's shutdown waited six seconds and then terminated the thread. Each
dial here never settles, standing in for an unreachable host.
"""

from __future__ import annotations

import errno
import threading
import time
from typing import Any

import pytest

pytest.importorskip("PySide6")

from harness import mllp  # noqa: E402
from harness.mllp import SendItem, SendWorker  # noqa: E402

_MSG = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01^ADT_A01|X1|P|2.5.1\rEVN|A01|20260101\r"


@pytest.fixture(scope="module")
def qapp() -> Any:
    from PySide6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


class _NeverConnects:
    """A socket whose non-blocking dial stays in progress until closed."""

    def __init__(self, *_a: object) -> None:
        self.closed = False

    def setblocking(self, _flag: bool) -> None:
        pass

    def connect_ex(self, _addr: object) -> int:
        return errno.EINPROGRESS

    def close(self) -> None:
        self.closed = True


@pytest.fixture
def unreachable(monkeypatch: pytest.MonkeyPatch) -> list[_NeverConnects]:
    opened: list[_NeverConnects] = []

    def open_socket(*a: object) -> _NeverConnects:
        sock = _NeverConnects(*a)
        opened.append(sock)
        return sock

    monkeypatch.setattr(mllp, "_open_socket", open_socket)
    monkeypatch.setattr(mllp, "_dial_settled", lambda _sock, wait_s: time.sleep(wait_s) or False)
    return opened


def test_stop_aborts_a_dial_in_progress(unreachable: list[_NeverConnects]) -> None:
    worker = SendWorker("127.0.0.1", 9, [], timeout=30.0, rate=0.0)
    out: list[Any] = []
    t = threading.Thread(
        target=lambda: out.append(worker._send_one(SendItem(1, "ADT", "A01", "X1", _MSG))),
        daemon=True,
    )
    t.start()
    time.sleep(0.3)
    started = time.monotonic()
    worker.stop()
    t.join(timeout=5)
    assert not t.is_alive(), "stop() did not reach a dial in progress"
    assert time.monotonic() - started < 2
    assert out and not out[0].ok
    assert unreachable and all(s.closed for s in unreachable)


def test_a_dial_still_times_out_at_the_connect_timeout(unreachable: list[_NeverConnects]) -> None:
    worker = SendWorker("127.0.0.1", 9, [], timeout=0.3, rate=0.0)
    res = worker._send_one(SendItem(1, "ADT", "A01", "X1", _MSG))
    assert not res.ok
    assert res.error == "timed out"


def test_compose_shutdown_joins_a_dialling_send_without_terminate(
    qapp: Any, unreachable: list[_NeverConnects], monkeypatch: pytest.MonkeyPatch
) -> None:
    from harness.compose import ComposePanel

    panel = ComposePanel()
    panel._editor.setPlainText(_MSG)
    panel._host.setText("127.0.0.1")
    panel._send()
    deadline = time.monotonic() + 5
    while not unreachable and time.monotonic() < deadline:
        time.sleep(0.01)
    assert unreachable, "the send never started dialling"
    thread = panel._thread
    assert thread is not None
    started = time.monotonic()
    panel.shutdown()
    assert time.monotonic() - started < 3, "shutdown waited out the grace and would terminate"
    assert thread.isFinished()
