# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The harness Receive tab's fault-injection reply modes + at-least-once duplicate counting.

Each test drives the QTcpServer-backed receiver with a raw client socket, spinning the Qt event
loop so the server processes the connection, then asserts the reply (or lack of one) and the
per-control-id ``seen`` count the engine's retries would surface. The ``recv`` fixture drains
pending Qt events on teardown so one receiver's deferred socket deletions can't fire into the
next test (which segfaults).
"""

from __future__ import annotations

import socket
import time
from typing import Any, Iterator

import pytest

pytest.importorskip("PySide6")

from messagefoundry.transports.mllp import MLLPDecoder, frame  # noqa: E402
from harness.mllp import CLOSE, FAIL_THEN_AA, MllpReceiver, Received  # noqa: E402

_MSG = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01^ADT_A01|X1|P|2.5.1\rEVN|A01|20260101\r"


@pytest.fixture(scope="module")
def qapp() -> Any:
    from PySide6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


@pytest.fixture
def recv(qapp: Any) -> Iterator[MllpReceiver]:
    receiver = MllpReceiver()
    try:
        yield receiver
    finally:
        receiver.stop()
        for _ in range(10):  # flush deferred socket deleteLater while the receiver is still alive
            qapp.processEvents()


def _spin(qapp: Any, predicate: Any, timeout: float = 3.0) -> None:
    deadline = time.time() + timeout
    while not predicate():
        qapp.processEvents()
        time.sleep(0.02)
        if time.time() > deadline:
            raise AssertionError("condition not met within timeout")


def _send_once(qapp: Any, port: int) -> bytes:
    """Open one MLLP connection, send _MSG, and read a framed ACK. Returns the ACK payload bytes,
    or b"" if the peer closed without replying."""
    client = socket.create_connection(("127.0.0.1", port), 3)
    client.settimeout(0.1)
    client.sendall(frame(_MSG))
    ack = b""
    decoder = MLLPDecoder()
    deadline = time.time() + 3
    while not ack and time.time() < deadline:
        qapp.processEvents()
        try:
            chunk = client.recv(4096)
        except TimeoutError:
            continue
        if not chunk:  # peer closed without acknowledging
            break
        for message in decoder.feed(chunk):
            ack = message
            break
    client.close()
    return ack


def test_close_mode_drops_without_ack(qapp: Any, recv: MllpReceiver) -> None:
    recv.ack_mode = CLOSE
    got: list[Received] = []
    recv.received.connect(got.append)
    assert recv.start(0)
    ack = _send_once(qapp, recv.port())
    assert got and got[0].control_id == "X1"  # message was received…
    assert ack == b""  # …but the connection was dropped with no ACK


def test_fail_then_accept_rejects_then_accepts(qapp: Any, recv: MllpReceiver) -> None:
    recv.ack_mode = FAIL_THEN_AA
    recv.fail_first = 1  # first delivery NAK'd, second accepted
    got: list[Received] = []
    recv.received.connect(got.append)
    assert recv.start(0)
    first = _send_once(qapp, recv.port())
    _spin(qapp, lambda: len(got) >= 1)
    second = _send_once(qapp, recv.port())  # the engine's retry of the same control id
    _spin(qapp, lambda: len(got) >= 2)
    assert b"MSA|AR|X1" in first  # first attempt rejected
    assert b"MSA|AA|X1" in second  # retry accepted
    assert [r.seen for r in got] == [1, 2]  # duplicate surfaced via the occurrence counter


def test_duplicate_control_ids_are_counted(qapp: Any, recv: MllpReceiver) -> None:
    recv.ack_mode = "AA"
    got: list[Received] = []
    recv.received.connect(got.append)
    assert recv.start(0)
    _send_once(qapp, recv.port())
    _spin(qapp, lambda: len(got) >= 1)
    _send_once(qapp, recv.port())
    _spin(qapp, lambda: len(got) >= 2)
    assert [r.seen for r in got] == [1, 2]
