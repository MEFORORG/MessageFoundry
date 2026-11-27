# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The harness detail panel answers a step-up refusal of the open and the body read (BACKLOG #5945).

Both reads run on a worker thread through the polling client, which has no step-up handler, so a
step-up refusal there (at least from a host the session has not verified from) used to dead-end as
an error. The panel now hands it to the GUI-thread step-up, which re-proves for the action the
refusal named (``StepUpRequired.action``, ADR 0077), and repeats the read once.
"""

from __future__ import annotations

import copy
import json
import threading
import time
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QInputDialog  # noqa: E402

from harness._console_widgets import MessageDetailPanel  # noqa: E402
from harness.monitor import MonitorPanel  # noqa: E402
from messagefoundry.apiclient import (  # noqa: E402
    ApiError,
    EngineClient,
    IdpStepUpRequired,
    StepUpRequired,
)

_RAW = "MSH|^~\\&|S|F|R|RF|20260604||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"


@pytest.fixture(scope="module")
def qapp() -> Any:
    from PySide6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


def _detail(message_id: str) -> Any:
    return SimpleNamespace(
        id=message_id,
        message_type="ADT^A01",
        control_id="MSG1",
        status="PROCESSED",
        received_at=1_780_000_000.0,
        error=None,
        outbox=[],
        events=[],
    )


class _Client:
    """Refuses the first ``open_refusals`` opens and ``body_refusals`` body reads with ``error``."""

    def __init__(
        self, *, open_refusals: int = 0, body_refusals: int = 0, error: ApiError | None = None
    ) -> None:
        self._open_refusals = open_refusals
        self._body_refusals = body_refusals
        self._error = error or StepUpRequired("step-up required", status=403, action="act")
        self.opens = 0
        self.bodies = 0

    def get_message(self, message_id: str) -> Any:
        self.opens += 1
        if self.opens <= self._open_refusals:
            raise copy.copy(self._error)  # fresh: a shared one keeps every traceback
        return _detail(message_id)

    def get_message_body(self, message_id: str, *, surface: str) -> Any:
        self.bodies += 1
        if self.bodies <= self._body_refusals:
            raise copy.copy(self._error)  # fresh: a shared one keeps every traceback
        return SimpleNamespace(message_id=message_id, raw=_RAW)


class _StepUp:
    def __init__(self, answer: bool | Callable[[], bool]) -> None:
        self._answer = answer
        self.actions: list[str | None] = []
        self.threads: list[threading.Thread] = []

    def __call__(self, action: str | None) -> bool:
        self.actions.append(action)
        self.threads.append(threading.current_thread())
        return self._answer() if callable(self._answer) else self._answer


def _settle(qapp: Any, done: Callable[[], bool]) -> None:
    deadline = time.time() + 10
    while time.time() < deadline and not done():
        qapp.processEvents()
        time.sleep(0.01)
    assert done(), "the panel never reached the awaited state"
    # Keep pumping: a repeat or a second prompt that must NOT happen gets its chance to show.
    for _ in range(20):
        qapp.processEvents()
        time.sleep(0.005)


def _panel(client: Any, step_up: Any) -> tuple[MessageDetailPanel, list[str]]:
    panel = MessageDetailPanel(client, poll_client=client, step_up=step_up)
    errors: list[str] = []
    panel.error.connect(errors.append)
    return panel, errors


def _opened(panel: MessageDetailPanel) -> bool:
    return panel._message_id is not None


def test_a_refused_open_steps_up_on_the_gui_thread_and_repeats_once(qapp: Any) -> None:
    client = _Client(open_refusals=1)
    step_up = _StepUp(True)
    panel, errors = _panel(client, step_up)
    try:
        panel.load("m1")
        _settle(qapp, lambda: _opened(panel))
        assert step_up.actions == ["act"]
        assert step_up.threads == [threading.main_thread()]
        assert client.opens == 2
        assert "ADT^A01" in panel._summary.text()
        assert panel._show_body.isEnabled()
        assert errors == []
    finally:
        panel.stop()


def test_a_second_open_refusal_is_reported_not_prompted_again(qapp: Any) -> None:
    client = _Client(open_refusals=5)
    step_up = _StepUp(True)
    panel, errors = _panel(client, step_up)
    try:
        panel.load("m1")
        _settle(qapp, lambda: bool(errors))
        assert step_up.actions == ["act"]
        assert client.opens == 2
        assert errors == ["step-up required"]
        assert not _opened(panel)
    finally:
        panel.stop()


def test_a_declined_open_step_up_reports_the_refusal(qapp: Any) -> None:
    client = _Client(open_refusals=1)
    panel, errors = _panel(client, _StepUp(False))
    try:
        panel.load("m1")
        _settle(qapp, lambda: bool(errors))
        assert client.opens == 1
        assert errors == ["step-up required"]
        assert panel._summary.text() == "The message could not be opened."
    finally:
        panel.stop()


def test_a_refused_re_proof_reports_its_own_cause(qapp: Any) -> None:
    client = _Client(open_refusals=1)

    def refuse() -> bool:
        raise ApiError("re-verification failed", status=401)

    panel, errors = _panel(client, _StepUp(refuse))
    try:
        panel.load("m1")
        _settle(qapp, lambda: bool(errors))
        assert client.opens == 1
        assert errors == ["re-verification failed"]
    finally:
        panel.stop()


@pytest.mark.parametrize(
    "error",
    [IdpStepUpRequired("use the web console", status=403), ApiError("forbidden", status=403)],
    ids=["idp", "role-or-scope"],
)
def test_a_refusal_a_password_cannot_clear_is_not_prompted(qapp: Any, error: ApiError) -> None:
    client = _Client(open_refusals=1, error=error)
    step_up = _StepUp(True)
    panel, errors = _panel(client, step_up)
    try:
        panel.load("m1")
        _settle(qapp, lambda: bool(errors))
        assert step_up.actions == []
        assert errors == [str(error)]
    finally:
        panel.stop()


def test_an_open_superseded_during_the_prompt_is_dropped(qapp: Any) -> None:
    """The prompt's nested event loop can run a newer load(). That one wins, so the old open is
    neither repeated nor reported, even though the prompt re-proved."""
    client = _Client(open_refusals=1)
    box: list[MessageDetailPanel] = []

    def select_another_row() -> bool:
        box[0].load("m2")
        return True

    panel, errors = _panel(client, _StepUp(select_another_row))
    box.append(panel)
    try:
        panel.load("m1")
        _settle(qapp, lambda: _opened(panel))
        assert client.opens == 2  # the refused m1 open, then m2's; m1 was not repeated
        assert panel._message_id == "m2"
        assert errors == []
    finally:
        panel.stop()
        box.clear()  # panel -> step-up -> box -> panel


def test_a_refused_body_read_steps_up_and_repeats_once(qapp: Any) -> None:
    client = _Client(body_refusals=1)
    step_up = _StepUp(True)
    panel, errors = _panel(client, step_up)
    try:
        panel.load("m1")
        _settle(qapp, lambda: _opened(panel))
        panel._on_show_body()
        _settle(qapp, lambda: bool(panel._raw.toPlainText()))
        assert step_up.actions == ["act"]
        assert step_up.threads == [threading.main_thread()]
        assert client.bodies == 2
        assert panel._raw.toPlainText() == _RAW.replace("\r", "\n")
        assert panel._show_body.isEnabled()
        assert errors == []
    finally:
        panel.stop()


def test_a_declined_body_step_up_reports_and_offers_the_button_again(qapp: Any) -> None:
    client = _Client(body_refusals=5)
    step_up = _StepUp(False)
    panel, errors = _panel(client, step_up)
    try:
        panel.load("m1")
        _settle(qapp, lambda: _opened(panel))
        panel._on_show_body()
        _settle(qapp, lambda: bool(errors))
        assert step_up.actions == ["act"]
        assert client.bodies == 1
        assert errors == ["step-up required"]
        assert panel._raw.toPlainText() == ""
        assert panel._show_body.isEnabled()
    finally:
        panel.stop()


def test_a_second_body_refusal_is_reported_not_prompted_again(qapp: Any) -> None:
    client = _Client(body_refusals=5)
    step_up = _StepUp(True)
    panel, errors = _panel(client, step_up)
    try:
        panel.load("m1")
        _settle(qapp, lambda: _opened(panel))
        panel._on_show_body()
        _settle(qapp, lambda: bool(errors))
        assert step_up.actions == ["act"]
        assert client.bodies == 2
        assert errors == ["step-up required"]
        assert panel._show_body.isEnabled()
    finally:
        panel.stop()


def test_the_monitor_re_proves_a_polling_refusal_for_its_action(
    qapp: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End to end through the real client: the polling client's refusal names a per-action gate,
    the monitor's re-proof on the main client posts that action as the purpose, and the polling
    client's repeat then carries the single-use grant through the shared token cell."""
    reauths: list[dict[str, object]] = []
    granted: list[str] = []
    opens: list[str | None] = []

    def _send(request: httpx.Request, *args: object, **kwargs: object) -> httpx.Response:
        if request.url.path == "/me/reauth":
            body = json.loads(request.content)
            reauths.append(body)
            if "purpose" in body:
                granted.append(str(body["purpose"]))
            return httpx.Response(200, json={"token": "rotated"}, request=request)
        opens.append(request.headers.get("Authorization"))
        if "message_open" in granted:
            granted.remove("message_open")  # single-use
            detail = {
                "id": "m1",
                "channel_id": "IB_TEST_ADT",
                "received_at": 1_780_000_000.0,
                "source_type": "mllp",
                "control_id": "MSG1",
                "message_type": "ADT^A01",
                "status": "PROCESSED",
                "error": None,
                "outbox": [],
                "events": [],
            }
            return httpx.Response(200, json=detail, request=request)
        headers = {"X-Step-Up-Required": "1", "X-Step-Up-Action": "message_open"}
        return httpx.Response(403, json={"detail": "refused"}, headers=headers, request=request)

    client = EngineClient("http://127.0.0.1:8765")
    client._http.send = _send  # type: ignore[method-assign]
    client._token_cell.value = "original"  # set_token would read /me first
    poll = client.for_polling()
    poll._http.send = _send  # type: ignore[method-assign]
    monitor = MonitorPanel()
    monitor._client = client
    client.set_step_up_handler(monitor._step_up)
    monkeypatch.setattr(MonitorPanel, "_stop_poller", lambda self: None)
    monkeypatch.setattr(MonitorPanel, "_start_poller", lambda self: None)
    monkeypatch.setattr(QInputDialog, "getText", lambda *a, **k: ("typed-pw", True))
    panel, errors = _panel(poll, monitor._step_up)
    panel._client = client
    try:
        panel.load("m1")
        _settle(qapp, lambda: _opened(panel) or bool(errors))
        assert errors == []
        assert reauths == [{"password": "typed-pw", "purpose": "message_open"}]
        assert opens == ["Bearer original", "Bearer rotated"]
        assert "ADT^A01" in panel._summary.text()
    finally:
        panel.stop()
        # Break the client -> handler -> monitor and panel -> step-up -> monitor cycles.
        client.set_step_up_handler(None)
        panel._step_up = None
        monitor._client = None
        monitor.shutdown()
        poll.close()
        client.close()
