# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The harness message detail panel while a newer open is in flight, and when it fails (BACKLOG #5848).

Two defects at the time this file was written: Replay stayed enabled during a ``load()``, so a press
replayed the previously shown message under the newly selected row; and a fetch that raised
something other than ``ApiError`` had no ``on_error`` callback, so the previous message stayed on
screen with nothing said. Both tests drive the real ``AsyncRunner`` so the submit wiring is covered.
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
    """Opens ``m0`` at once; ``m1`` waits on ``release`` and then returns, or raises an OSError
    when ``fails``. A fresh exception per call: a stored one would keep its traceback, and with it
    the panel's frame, alive in a Qt reference cycle."""

    def __init__(self, *, fails: bool = False) -> None:
        self.release = threading.Event()
        self.replayed: list[str] = []
        self._fails = fails

    def get_message(self, message_id: str) -> Any:
        if message_id != "m0":
            self.release.wait(5.0)
            if self._fails:
                raise OSError("connection reset")
        return _detail(message_id)

    def replay(self, message_id: str) -> None:
        self.replayed.append(message_id)


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
    panel = MessageDetailPanel(client)  # type: ignore[arg-type]
    try:
        panel.load("m0")
        _pump_until(qapp, panel._replay.isEnabled)
        assert "CTL-m0" in panel._summary.text()

        panel.load("m1")
        assert not panel._replay.isEnabled()
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


def test_a_non_api_error_fetch_clears_the_previous_message_and_reports(qapp: Any) -> None:
    """A transport failure (here OSError, not ApiError) while opening m1 must not leave m0 under
    the new selection, and must say something. m0 rendered first is the control."""
    client = _FakeClient(fails=True)
    panel = MessageDetailPanel(client)  # type: ignore[arg-type]
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
        assert "OSError" in errors[0]
    finally:
        client.release.set()
        panel.stop()


def test_a_failed_open_superseded_by_a_newer_one_is_dropped(qapp: Any) -> None:
    """A late failure from an open the operator has moved past must not clear the newer open."""
    client = _FakeClient(fails=True)
    panel = MessageDetailPanel(client)  # type: ignore[arg-type]
    errors: list[str] = []
    panel.error.connect(errors.append)
    try:
        panel.load("m1")  # blocks, then fails
        panel.load("m0")  # supersedes it and lands
        _pump_until(qapp, lambda: "CTL-m0" in panel._summary.text())
        client.release.set()
        panel._runner._pool.waitForDone(5000)
        for _ in range(20):
            qapp.processEvents()
        assert "CTL-m0" in panel._summary.text()
        assert errors == []
    finally:
        client.release.set()
        panel.stop()
