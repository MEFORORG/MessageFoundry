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
import logging
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
        self.opened: list[str] = []
        self.bodies = 0

    def get_message(self, message_id: str) -> Any:
        self.opens += 1
        self.opened.append(message_id)
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


class _GuardedStepUp:
    """Declines a step-up asked while its own prompt is up, as MonitorPanel._step_up does. While
    its first prompt is up, it runs ``during`` (the operator's act inside the prompt's nested
    event loop); a later prompt just answers. ``answer`` may be a callable, which may raise."""

    def __init__(
        self, during: Callable[[], None], answer: bool | Callable[[], bool] = True
    ) -> None:
        self._during: Callable[[], None] | None = during
        self._answer = answer
        self._open = False
        self.calls = 0
        self.actions: list[str | None] = []

    def __call__(self, action: str | None) -> bool:
        self.calls += 1
        self.actions.append(action)
        if self._open:
            return False
        self._open = True
        try:
            during, self._during = self._during, None
            if during is not None:
                during()
        finally:
            self._open = False
        return self._answer() if callable(self._answer) else self._answer


def _pump_until(qapp: Any, done: Callable[[], bool]) -> None:
    deadline = time.time() + 10
    while time.time() < deadline and not done():
        qapp.processEvents()
        time.sleep(0.01)
    assert done(), "the nested event loop never reached the awaited state"


def test_an_open_superseded_during_the_prompt_lets_the_newer_open_land(qapp: Any) -> None:
    """The prompt's nested event loop can run a newer load(). That one wins, so the old open is
    dropped. The newer open is still out when the prompt re-proves, so it is left to land rather
    than opened a second time: each open is an audited PHI read."""
    client = _Client(open_refusals=1)
    box: list[MessageDetailPanel] = []
    step_up = _GuardedStepUp(lambda: box[0].load("m2"))
    panel, errors = _panel(client, step_up)
    box.append(panel)
    try:
        panel.load("m1")
        _settle(qapp, lambda: _opened(panel))
        assert client.opened == ["m1", "m2"]
        assert step_up.calls == 1
        assert panel._message_id == "m2"
        assert errors == []
    finally:
        panel.stop()
        box.clear()  # panel -> step-up -> box -> panel


def test_a_new_selection_refused_during_the_prompt_is_reopened_after_the_proof(qapp: Any) -> None:
    """The newer open comes back refused while the prompt is up. That step-up is declined (one
    prompt at a time) and reported, and the proof the open prompt then makes opens it again."""
    client = _Client(open_refusals=2)
    box: list[MessageDetailPanel] = []

    def select_and_wait_for_its_refusal() -> None:
        box[0].load("m2")
        _pump_until(qapp, lambda: step_up.calls == 2)

    step_up = _GuardedStepUp(select_and_wait_for_its_refusal)
    panel, errors = _panel(client, step_up)
    box.append(panel)
    try:
        panel.load("m1")
        _settle(qapp, lambda: _opened(panel))
        assert client.opened == ["m1", "m2", "m2"]
        assert panel._message_id == "m2"
        assert errors == ["step-up required"]  # the declined nested step-up, reported
    finally:
        panel.stop()
        box.clear()


def test_a_new_selection_that_landed_during_the_prompt_is_not_reopened(qapp: Any) -> None:
    client = _Client(open_refusals=1)
    box: list[MessageDetailPanel] = []

    def select_and_wait_for_it() -> None:
        box[0].load("m2")
        _pump_until(qapp, lambda: box[0]._message_id == "m2")

    panel, errors = _panel(client, _GuardedStepUp(select_and_wait_for_it))
    box.append(panel)
    try:
        panel.load("m1")
        _settle(qapp, lambda: _opened(panel))
        assert client.opened == ["m1", "m2"]  # no second, audited open of m2
        assert errors == []
    finally:
        panel.stop()
        box.clear()


def test_a_prompt_that_raises_something_else_is_reported_not_wedged(qapp: Any) -> None:
    client = _Client(open_refusals=1)

    def broken() -> bool:
        raise RuntimeError("the poller would not restart")

    panel, errors = _panel(client, _StepUp(broken))
    try:
        panel.load("m1")
        _settle(qapp, lambda: bool(errors))
        assert errors == ["the message could not be opened: RuntimeError"]
        assert panel._summary.text() == "The message could not be opened."
    finally:
        panel.stop()


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


def test_a_body_superseded_during_its_prompt_is_not_painted(qapp: Any) -> None:
    """A newer open in the prompt's nested event loop wins: m1's body is neither repeated nor
    painted under m2, and m2's open, still out when the prompt re-proves, lands once."""
    client = _Client(body_refusals=1)
    box: list[MessageDetailPanel] = []
    panel, errors = _panel(client, _GuardedStepUp(lambda: box[0].load("m2")))
    box.append(panel)
    try:
        panel.load("m1")
        _settle(qapp, lambda: _opened(panel))
        panel._on_show_body()
        _settle(qapp, lambda: panel._message_id == "m2")
        assert client.bodies == 1
        assert client.opened == ["m1", "m2"]
        assert panel._raw.toPlainText() == ""
        assert errors == []
    finally:
        panel.stop()
        box.clear()


def test_a_refused_body_re_proof_reports_its_own_cause(qapp: Any) -> None:
    client = _Client(body_refusals=1)

    def refuse() -> bool:
        raise ApiError("re-verification failed", status=401)

    panel, errors = _panel(client, _StepUp(refuse))
    try:
        panel.load("m1")
        _settle(qapp, lambda: _opened(panel))
        panel._on_show_body()
        _settle(qapp, lambda: bool(errors))
        assert client.bodies == 1
        assert errors == ["re-verification failed"]
        assert panel._show_body.isEnabled()
    finally:
        panel.stop()


def test_show_body_stays_disabled_while_its_prompt_is_up(qapp: Any) -> None:
    client = _Client(body_refusals=1)
    box: list[MessageDetailPanel] = []
    seen: list[bool] = []

    def record_the_button() -> bool:
        seen.append(box[0]._show_body.isEnabled())
        return True

    panel, errors = _panel(client, _StepUp(record_the_button))
    box.append(panel)
    try:
        panel.load("m1")
        _settle(qapp, lambda: _opened(panel))
        panel._on_show_body()
        _settle(qapp, lambda: bool(panel._raw.toPlainText()))
        assert seen == [False]
        assert errors == []
    finally:
        panel.stop()
        box.clear()


class _ScriptedClient:
    """Answers each open, and each body read, by the next entry of its script: ``"ok"`` serves it,
    ``"401"`` and ``"429"`` fail it with that status, and any other string refuses it with a
    step-up naming that string as its action. An exhausted script serves."""

    def __init__(self, *, opens: list[str], bodies: list[str] | None = None) -> None:
        self._opens = list(opens)
        self._bodies = list(bodies or [])
        self.opened: list[str] = []
        self.bodies = 0

    @staticmethod
    def _next(script: list[str]) -> None:
        outcome = script.pop(0) if script else "ok"
        if outcome in ("401", "429"):
            raise ApiError(f"failed with {outcome}", status=int(outcome))
        if outcome != "ok":
            raise StepUpRequired("step-up required", status=403, action=outcome)

    def get_message(self, message_id: str) -> Any:
        self.opened.append(message_id)
        self._next(self._opens)
        return _detail(message_id)

    def get_message_body(self, message_id: str, *, surface: str) -> Any:
        self.bodies += 1
        self._next(self._bodies)
        return SimpleNamespace(message_id=message_id, raw=_RAW)


def _select_m2_and_wait_for_its_refusal(box: list[MessageDetailPanel], qapp: Any) -> None:
    panel = box[0]
    panel.load("m2")
    # Its refusal comes back while the prompt is up; that step-up is declined, so it is reported.
    _pump_until(qapp, lambda: panel._summary.text() == "The message could not be opened.")


def test_a_reopen_after_another_reads_proof_still_prompts_for_its_own_action(qapp: Any) -> None:
    """The proof was for the body read's action, so it need not cover the reopened open's. A
    step-up refusal of the reopen is prompted for, not reported as if it were the repeat."""
    client = _ScriptedClient(opens=["ok", "open", "open"], bodies=["body"])
    box: list[MessageDetailPanel] = []
    step_up = _GuardedStepUp(lambda: _select_m2_and_wait_for_its_refusal(box, qapp))
    panel, errors = _panel(client, step_up)
    box.append(panel)
    try:
        panel.load("m1")
        _settle(qapp, lambda: _opened(panel))
        panel._on_show_body()
        _settle(qapp, lambda: panel._message_id == "m2")
        # The body prompt; m2's refusal inside it, declined; the reopen's refusal, prompted.
        assert step_up.actions == ["body", "open", "open"]
        assert client.opened == ["m1", "m2", "m2", "m2"]
        assert errors == ["step-up required"]  # only the declined nested step-up
    finally:
        panel.stop()
        box.clear()


def test_a_reopen_refused_twice_prompts_once_and_reports(qapp: Any) -> None:
    client = _ScriptedClient(opens=["ok", "open", "open", "open", "open"], bodies=["body"])
    box: list[MessageDetailPanel] = []
    step_up = _GuardedStepUp(lambda: _select_m2_and_wait_for_its_refusal(box, qapp))
    panel, errors = _panel(client, step_up)
    box.append(panel)
    try:
        panel.load("m1")
        _settle(qapp, lambda: _opened(panel))
        panel._on_show_body()
        _settle(qapp, lambda: len(errors) == 2)
        assert step_up.actions == ["body", "open", "open"]
        assert client.opened == ["m1", "m2", "m2", "m2"]  # the reopen and its one repeat
        assert errors == ["step-up required", "step-up required"]
        assert not _opened(panel)
    finally:
        panel.stop()
        box.clear()


@pytest.mark.parametrize("refused", ["open", "401"], ids=["step-up", "rotation-race-401"])
def test_a_newer_open_refused_for_the_session_before_the_proof_is_sent_again_unprompted(
    qapp: Any, refused: str
) -> None:
    """The newer open is still out when the prompt re-proves, and comes back refused for the old
    session. It is sent again under the new one, not prompted for a password just typed, and not
    reported as a dead end."""
    client = _ScriptedClient(opens=["open", refused])
    box: list[MessageDetailPanel] = []
    step_up = _GuardedStepUp(lambda: box[0].load("m2"))
    panel, errors = _panel(client, step_up)
    box.append(panel)
    try:
        panel.load("m1")
        _settle(qapp, lambda: _opened(panel))
        assert step_up.calls == 1
        assert client.opened == ["m1", "m2", "m2"]
        assert panel._message_id == "m2"
        assert errors == []
    finally:
        panel.stop()
        box.clear()


def test_a_newer_open_that_failed_for_another_cause_is_not_reopened(qapp: Any) -> None:
    """A 429 from the PHI-read pacing is no refusal a proof clears, so it is reported once and the
    proof does not read the message again."""
    client = _ScriptedClient(opens=["open", "429"])
    box: list[MessageDetailPanel] = []

    def select_and_wait_for_its_failure() -> None:
        box[0].load("m2")
        _pump_until(qapp, lambda: bool(errors))

    step_up = _GuardedStepUp(select_and_wait_for_its_failure)
    panel, errors = _panel(client, step_up)
    box.append(panel)
    try:
        panel.load("m1")
        _settle(qapp, lambda: step_up.calls == 1 and not panel._runner._calls)
        assert client.opened == ["m1", "m2"]
        assert errors == ["failed with 429"]
        assert not _opened(panel)
    finally:
        panel.stop()
        box.clear()


def _refuse_re_proof() -> bool:
    raise ApiError("re-verification failed", status=401)


def test_a_refused_re_proof_of_a_superseded_open_is_still_reported(qapp: Any) -> None:
    client = _Client(open_refusals=1)
    box: list[MessageDetailPanel] = []
    step_up = _GuardedStepUp(lambda: box[0].load("m2"), answer=_refuse_re_proof)
    panel, errors = _panel(client, step_up)
    box.append(panel)
    try:
        panel.load("m1")
        _settle(qapp, lambda: _opened(panel))
        assert errors == ["re-verification failed"]
        assert panel._message_id == "m2"
        assert client.opened == ["m1", "m2"]
    finally:
        panel.stop()
        box.clear()


def test_a_refused_re_proof_of_a_superseded_body_read_is_still_reported(qapp: Any) -> None:
    client = _Client(body_refusals=1)
    box: list[MessageDetailPanel] = []
    step_up = _GuardedStepUp(lambda: box[0].load("m2"), answer=_refuse_re_proof)
    panel, errors = _panel(client, step_up)
    box.append(panel)
    try:
        panel.load("m1")
        _settle(qapp, lambda: _opened(panel))
        panel._on_show_body()
        _settle(qapp, lambda: panel._message_id == "m2")
        assert errors == ["re-verification failed"]
        assert client.bodies == 1
        assert panel._raw.toPlainText() == ""
    finally:
        panel.stop()
        box.clear()


_FAULT_TEXT = "PID|1||100^^^H^MR||DOE^JANE"  # what a fault's text could quote


def _broken_prompt() -> bool:
    raise RuntimeError(_FAULT_TEXT)


def _panel_warnings(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    """The panel module's own WARNING records, so an unrelated one cannot fail the test."""
    return [
        r
        for r in caplog.records
        if r.name == "harness._console_widgets" and r.levelno == logging.WARNING
    ]


def test_a_body_prompt_that_raises_something_else_is_reported_and_logged_without_its_text(
    qapp: Any, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG, logger="harness._console_widgets")
    client = _Client(body_refusals=1)
    panel, errors = _panel(client, _StepUp(_broken_prompt))
    try:
        panel.load("m1")
        _settle(qapp, lambda: _opened(panel))
        panel._on_show_body()
        _settle(qapp, lambda: bool(errors))
        assert errors == ["the body could not be read: RuntimeError"]
        assert panel._show_body.isEnabled()
        assert panel._raw.toPlainText() == ""
        warnings = _panel_warnings(caplog)
        assert [r.getMessage() for r in warnings] == [
            "message body read for m1 raised RuntimeError"
        ]
        assert _FAULT_TEXT not in caplog.text
    finally:
        panel.stop()


def test_a_superseded_body_prompt_fault_is_still_logged(
    qapp: Any, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG, logger="harness._console_widgets")
    client = _Client(body_refusals=1)
    box: list[MessageDetailPanel] = []
    step_up = _GuardedStepUp(lambda: box[0].load("m2"), answer=_broken_prompt)
    panel, errors = _panel(client, step_up)
    box.append(panel)
    try:
        panel.load("m1")
        _settle(qapp, lambda: _opened(panel))
        panel._on_show_body()
        _settle(qapp, lambda: panel._message_id == "m2")
        assert errors == []  # superseded: nothing is said on screen about m1's body
        warnings = _panel_warnings(caplog)
        assert [r.getMessage() for r in warnings] == [
            "message body read for m1 raised RuntimeError"
        ]
        assert _FAULT_TEXT not in caplog.text
    finally:
        panel.stop()
        box.clear()


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
