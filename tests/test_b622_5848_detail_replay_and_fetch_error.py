# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The harness message detail panel while a newer open is in flight, and when it fails (BACKLOG #5848).

Two defects at the time this file was written: Replay stayed enabled during a ``load()``, so a press
replayed the previously shown message under the newly selected row; and a fetch that raised
something other than ``ApiError`` had no ``on_error`` callback, so the previous message stayed on
screen with nothing said. The tests drive the real ``AsyncRunner`` so the submit wiring is covered.
Each pool gets two threads, because one fetch is held open while another must run beside it.
"""

from __future__ import annotations

import threading
import time
from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("PySide6")

from harness._console_widgets import MessageDetailPanel  # noqa: E402


@pytest.fixture(scope="module")
def qapp() -> Any:
    from PySide6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


def _detail(message_id: str) -> Any:
    return SimpleNamespace(
        id=message_id,
        message_type="ADT^A01",
        control_id=f"CTL-{message_id}",
        status="PROCESSED",
        received_at=1_780_000_000.0,
        error=None,
        outbox=[],
        events=[],
    )


class _FakeClient:
    """Opens ``m0`` at once; ``m1`` waits on ``release`` and then returns, or raises a RuntimeError
    when ``fails``. The real client wraps transport errors in ApiError, so a non-ApiError raise is a
    contract break such as a closed client. A fresh exception per call: a stored one would keep its
    traceback, and with it the panel's frame, alive in a Qt reference cycle."""

    def __init__(self, *, fails: bool = False) -> None:
        self.release = threading.Event()
        self.replayed: list[str] = []
        self._fails = fails

    def get_message(self, message_id: str) -> Any:
        if message_id != "m0":
            self.release.wait(5.0)
            if self._fails:
                raise RuntimeError("client closed")
        return _detail(message_id)

    def replay(self, message_id: str) -> None:
        self.replayed.append(message_id)


def _panel(client: _FakeClient) -> MessageDetailPanel:
    panel = MessageDetailPanel(client)  # type: ignore[arg-type]
    panel._runner._pool.setMaxThreadCount(2)  # a held m1 fetch must not queue m0 behind it
    return panel


def _pump_until(qapp: Any, predicate: Any, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError("condition not reached before the deadline")
        qapp.processEvents()
        time.sleep(0.01)


def test_replay_is_not_offered_while_a_newer_open_is_loading(qapp: Any) -> None:
    """m0 open with Replay enabled is the control; selecting m1 must withdraw Replay until m1
    lands, and a press in that window must replay nothing."""
    client = _FakeClient()
    panel = _panel(client)
    try:
        panel.load("m0")
        _pump_until(qapp, panel._replay.isEnabled)
        assert "CTL-m0" in panel._summary.text()

        panel.load("m1")
        assert not panel._replay.isEnabled()
        assert "CTL-m0" not in panel._summary.text()  # m0 is not left under the m1 selection
        panel._on_replay()  # a press that slipped through must not target m0
        assert client.replayed == []

        client.release.set()
        _pump_until(qapp, lambda: "CTL-m1" in panel._summary.text())
        assert panel._replay.isEnabled()
        panel._on_replay()
        assert client.replayed == ["m1"]
    finally:
        client.release.set()
        panel.stop()


def test_a_selection_made_during_replay_is_not_overridden_by_its_refresh(qapp: Any) -> None:
    """replay() can open a step-up prompt whose nested event loop selects another row. The refresh
    after the replay must not reopen the replayed message over that newer selection."""
    client = _FakeClient()
    panel = _panel(client)
    try:
        panel.load("m0")
        _pump_until(qapp, panel._replay.isEnabled)
        client.replay = lambda message_id: panel.load("m2")  # type: ignore[method-assign]
        panel._on_replay()
        assert panel._pending_id == "m2"
        client.release.set()
        _pump_until(qapp, lambda: "CTL-m2" in panel._summary.text())
    finally:
        client.release.set()
        panel.stop()
        del client.replay  # the stub holds the panel: break that cycle on this thread


def test_a_non_api_error_fetch_clears_the_previous_message_and_reports(qapp: Any) -> None:
    """A raise other than ApiError while opening m1 must not leave m0 under the new selection, and
    must say something. m0 rendered first is the control."""
    client = _FakeClient(fails=True)
    panel = _panel(client)
    errors: list[str] = []
    panel.error.connect(errors.append)
    try:
        panel.load("m0")
        _pump_until(qapp, lambda: "CTL-m0" in panel._summary.text())

        panel.load("m1")
        client.release.set()
        _pump_until(qapp, lambda: bool(errors))
        assert "CTL-m0" not in panel._summary.text()
        assert panel._message_id is None
        assert not panel._replay.isEnabled()
        assert not panel._show_body.isEnabled()
        assert "RuntimeError" in errors[0]
    finally:
        client.release.set()
        panel.stop()


def test_a_failed_open_superseded_by_a_newer_one_is_dropped(qapp: Any) -> None:
    """A late failure from an open the operator has moved past must not clear the newer open."""
    client = _FakeClient(fails=True)
    panel = _panel(client)
    errors: list[str] = []
    panel.error.connect(errors.append)
    raised: list[str] = []
    real_open_raised = panel._open_raised

    def _recording(message_id: str, open_seq: int, exc: BaseException) -> None:
        raised.append(message_id)
        real_open_raised(message_id, open_seq, exc)

    panel._open_raised = _recording  # type: ignore[method-assign]
    try:
        panel.load("m1")  # blocks, then fails
        panel.load("m0")  # supersedes it and lands
        _pump_until(qapp, lambda: "CTL-m0" in panel._summary.text())
        client.release.set()
        assert panel._runner._pool.waitForDone(5000)
        # Control: the failure was delivered, so the screen below is a drop, not a no-show.
        _pump_until(qapp, lambda: raised == ["m1"])
        assert "CTL-m0" in panel._summary.text()
        assert errors == []
    finally:
        client.release.set()
        panel.stop()
        del panel._open_raised  # the wrapper holds the panel: break that cycle on this thread
