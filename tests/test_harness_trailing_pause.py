# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The harness send and file drop workers pause between two items, never after the last one
(BACKLOG #5855, #5856).

Both workers paced a batch by pausing after every item, the last one included, so a batch ended a
whole pause after its last send or drop: 100 seconds of a busy tab at 0.01 a second. PR 3118 made
that pause interruptible; these tests pin that no pause follows the last item, and that a stop
inside a pause between items still ends the batch at once.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

pytest.importorskip("PySide6")

from harness import mllp  # noqa: E402
from harness.file_transport import FileDropWorker  # noqa: E402
from harness.mllp import SendItem, SendResult, SendWorker  # noqa: E402

_MSG = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01^ADT_A01|X1|P|2.5.1\rEVN|A01|20260101\r"
# 0.01 a second is a 100-second pause: a batch that waits one out cannot finish inside a test.
_SLOW_RATE = 0.01


def _items(n: int) -> Iterator[SendItem]:
    # Lazy, as the tabs' generated batches are, so the worker cannot count the items up front.
    for seq in range(1, n + 1):
        yield SendItem(seq, "ADT", "A01", f"X{seq}", _MSG)


def _send_worker(
    n: int, sent: list[str], monkeypatch: pytest.MonkeyPatch, *, rate: float = _SLOW_RATE
) -> SendWorker:
    """A send worker whose sends are recorded in ``sent`` rather than dialled."""
    worker = SendWorker("127.0.0.1", 9, _items(n), timeout=1.0, rate=rate)

    def send_one(item: SendItem) -> SendResult:
        sent.append(item.control_id)
        return SendResult(item, True, "AA", 0.0, "")

    monkeypatch.setattr(worker, "_send_one", send_one)
    return worker


def _drop_worker(n: int, directory: Path) -> FileDropWorker:
    return FileDropWorker(str(directory), _items(n), rate=_SLOW_RATE)


def _start(worker: SendWorker | FileDropWorker) -> threading.Thread:
    t = threading.Thread(target=worker.run, daemon=True)
    t.start()
    return t


def _until(cond: Callable[[], bool], timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cond():
            return True
        time.sleep(0.01)
    return cond()


def test_paced_pauses_between_items_and_not_after_the_last(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    def pause(_stop: threading.Event, seconds: float) -> bool:
        events.append(f"pause {seconds}")
        return False

    monkeypatch.setattr(mllp, "pause_unless_stopped", pause)
    for item in mllp.paced(iter("abc"), threading.Event(), 0.5):
        events.append(item)
    assert events == ["a", "pause 2.0", "b", "pause 2.0", "c"]
    events.clear()
    assert list(mllp.paced(iter("abc"), threading.Event(), 0.0)) == ["a", "b", "c"]
    assert events == [], "a zero rate must not pause"


def test_paced_yields_nothing_once_stopped() -> None:
    stop = threading.Event()
    stop.set()
    assert list(mllp.paced(iter("abc"), stop, 0.0)) == []


def test_a_slow_send_batch_finishes_right_after_its_last_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RED when: the send worker pauses after its last message, so this batch of one would end
    100 seconds after the send instead of at once (BACKLOG #5856)."""
    sent: list[str] = []
    worker = _send_worker(1, sent, monkeypatch)
    t = _start(worker)
    try:
        t.join(timeout=3)
        assert not t.is_alive(), "the batch waited out a pause after its last message"
        assert sent == ["X1"]
    finally:
        worker.stop()
        t.join(timeout=5)


def test_a_slow_file_drop_finishes_right_after_its_last_file(tmp_path: Path) -> None:
    """RED when: the drop worker pauses after its last file, so this batch of one would end 100
    seconds after the drop instead of at once (BACKLOG #5855)."""
    worker = _drop_worker(1, tmp_path)
    t = _start(worker)
    try:
        t.join(timeout=3)
        assert not t.is_alive(), "the batch waited out a pause after its last file"
        assert len(list(tmp_path.glob("*.hl7"))) == 1
    finally:
        worker.stop()
        t.join(timeout=5)


def test_stop_inside_a_pause_between_messages_ends_the_send_batch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent: list[str] = []
    worker = _send_worker(3, sent, monkeypatch)
    t = _start(worker)
    try:
        assert _until(lambda: bool(sent)), "the first message was never sent"
        time.sleep(0.05)  # into the 100-second pause before the second message
        started = time.monotonic()
        worker.stop()
        t.join(timeout=3)
        assert not t.is_alive(), "stop() did not end the pause"
        assert time.monotonic() - started < 1
        assert sent == ["X1"]
    finally:
        worker.stop()
        t.join(timeout=5)


def test_stop_inside_a_pause_between_files_ends_the_drop_batch(tmp_path: Path) -> None:
    worker = _drop_worker(3, tmp_path)
    t = _start(worker)
    try:
        assert _until(lambda: bool(list(tmp_path.glob("*.hl7")))), "the first file never landed"
        time.sleep(0.05)  # into the 100-second pause before the second file
        started = time.monotonic()
        worker.stop()
        t.join(timeout=3)
        assert not t.is_alive(), "stop() did not end the pause"
        assert time.monotonic() - started < 1
        assert len(list(tmp_path.glob("*.hl7"))) == 1
    finally:
        worker.stop()
        t.join(timeout=5)


def test_a_send_batch_still_paces_between_messages(monkeypatch: pytest.MonkeyPatch) -> None:
    # A control for the batch-of-one tests: that batch ends at once because no pause follows the
    # last message, not because pacing went away. Three messages at 20 a second take two pauses
    # of 0.05 seconds. Whether a third pause follows the last is left to the batch-of-one tests,
    # not timed here.
    sent: list[str] = []
    worker = _send_worker(3, sent, monkeypatch, rate=20.0)
    started = time.monotonic()
    worker.run()
    elapsed = time.monotonic() - started
    assert sent == ["X1", "X2", "X3"]
    assert elapsed >= 0.09, f"expected two pauses of 0.05 s, took {elapsed:.3f} s"
