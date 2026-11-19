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
import sys
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
        # What this platform's non-blocking connect returns while the dial is in progress.
        return mllp._WSAEWOULDBLOCK if sys.platform == "win32" else errno.EINPROGRESS

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

    def never_settles(_sock: object, wait_s: float) -> bool:
        time.sleep(wait_s)
        return False

    monkeypatch.setattr(mllp, "_dial_settled", never_settles)
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


def test_a_socket_that_cannot_be_made_moves_on_to_the_next_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # As socket.create_connection does: an address family the host lacks (IPv6 disabled, say) is
    # skipped, and the next address is dialled.
    import socket as socket_mod

    v6 = (socket_mod.AF_INET6, socket_mod.SOCK_STREAM, 0, "", ("::1", 9, 0, 0))
    v4 = (socket_mod.AF_INET, socket_mod.SOCK_STREAM, 0, "", ("127.0.0.1", 9))
    monkeypatch.setattr(socket_mod, "getaddrinfo", lambda *_a, **_kw: [v6, v4])
    tried: list[int] = []

    def open_socket(family: int, *_a: object) -> _NeverConnects:
        tried.append(family)
        if family == socket_mod.AF_INET6:
            raise OSError(97, "Address family not supported by protocol")
        return _NeverConnects()

    monkeypatch.setattr(mllp, "_open_socket", open_socket)
    monkeypatch.setattr(mllp, "_dial_settled", lambda _sock, _wait_s: True)
    monkeypatch.setattr(_NeverConnects, "getsockopt", lambda *_a: 0, raising=False)
    monkeypatch.setattr(_NeverConnects, "settimeout", lambda *_a: None, raising=False)
    worker = SendWorker("localhost", 9, [], timeout=1.0, rate=0.0)
    assert isinstance(worker._connect(), _NeverConnects)
    assert tried == [socket_mod.AF_INET6, socket_mod.AF_INET]


@pytest.mark.parametrize("code", sorted({errno.EAGAIN, errno.EWOULDBLOCK}))
def test_a_posix_eagain_dial_raises_its_own_error(
    monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    # On POSIX a non-blocking connect() returning EAGAIN or EWOULDBLOCK has failed; it is not a
    # dial in progress. Polled as if connecting, SO_ERROR reads 0 and the row reports a later
    # broken pipe instead of the real error a blocking dial raised.
    class _Refused(_NeverConnects):
        def connect_ex(self, _addr: object) -> int:
            return code

        def getsockopt(self, *_a: object) -> int:
            return 0

        def settimeout(self, _t: float) -> None:
            pass

    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(mllp, "_dial_settled", lambda _sock, _wait_s: True)
    worker = SendWorker("127.0.0.1", 9, [], timeout=1.0, rate=0.0)
    # Not pytest.raises: the traceback it keeps would hold the worker in a reference cycle.
    seen: int | None = None
    try:
        worker._dial(_Refused(), ("127.0.0.1", 9), time.monotonic() + 1.0)  # type: ignore[arg-type]
    except OSError as exc:
        seen = exc.errno
    assert seen == code


@pytest.mark.parametrize("code", [errno.EINPROGRESS, errno.EINTR], ids=["EINPROGRESS", "EINTR"])
def test_a_posix_dial_in_progress_is_polled_to_completion(
    monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    # A POSIX non-blocking connect() interrupted by a signal returns EINTR and goes on
    # asynchronously (CPython bpo-23618), as with EINPROGRESS: the dial is polled, not failed.
    class _Connects(_NeverConnects):
        def connect_ex(self, _addr: object) -> int:
            return code

        def getsockopt(self, *_a: object) -> int:
            return 0

        def settimeout(self, _t: float) -> None:
            pass

    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(mllp, "_dial_settled", lambda _sock, _wait_s: True)
    worker = SendWorker("127.0.0.1", 9, [], timeout=1.0, rate=0.0)
    # Not pytest.raises: the traceback it keeps would hold the worker in a reference cycle.
    failed: int | None = None
    try:
        worker._dial(_Connects(), ("127.0.0.1", 9), time.monotonic() + 1.0)  # type: ignore[arg-type]
    except OSError as exc:
        failed = exc.errno
    assert failed is None


def test_a_windows_dial_is_in_progress_only_on_wouldblock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    assert mllp._dial_in_progress(mllp._WSAEWOULDBLOCK)
    # On Windows errno.EINPROGRESS is WSAEINPROGRESS, a connect failure, not a dial in progress.
    assert not mllp._dial_in_progress(10036)


def test_the_pause_between_messages_keeps_a_fine_rate() -> None:
    # Event.wait rounds up to the Windows timer tick, about 15 ms, which capped 1000 msg/s at
    # about 65; the pause sleeps instead and still returns at once on stop.
    stop = threading.Event()
    started = time.perf_counter()
    for _ in range(20):
        assert mllp.pause_unless_stopped(stop, 0.001) is False
    assert (time.perf_counter() - started) / 20 < 0.010
    stop.set()
    started = time.perf_counter()
    assert mllp.pause_unless_stopped(stop, 30.0) is True
    assert time.perf_counter() - started < 0.5


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
