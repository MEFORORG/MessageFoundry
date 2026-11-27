# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The harness messages panel answers a step-up refusal of its content search (BACKLOG #5945).

The content and field-path search is step-up gated, and the panel runs it on a worker thread through
the polling client, which has no step-up handler. Before this fix the 403 surfaced as an error with no
way to re-prove short of signing in again. The panel now hands the refusal to a step-up callback on
the GUI thread and resubmits the search once.
"""

from __future__ import annotations

import threading
import time
from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("PySide6")

from harness._console_widgets import MessagesPanel  # noqa: E402
from messagefoundry.apiclient import ApiError, IdpStepUpRequired, StepUpRequired  # noqa: E402


@pytest.fixture(scope="module")
def qapp() -> Any:
    from PySide6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


def _msg(mid: str) -> Any:
    return SimpleNamespace(
        id=mid,
        received_at=1_780_000_000.0,
        channel_id="ch",
        event="ADT^A01",
        message_type="ADT",
        status="delivered",
        control_id=mid,
        summary="",
        metadata="",
    )


class _SearchClient:
    """Refuses the first ``refusals`` searches with ``error``, then answers one row."""

    def __init__(self, *, refusals: int, error: ApiError | None = None) -> None:
        self._refusals = refusals
        self._error = error or StepUpRequired("step-up required", status=403)
        self.searches = 0

    def list_messages(self, **_kw: Any) -> Any:
        return SimpleNamespace(messages=[], total=0)

    def search_messages(self, **_kw: Any) -> Any:
        self.searches += 1
        if self.searches <= self._refusals:
            raise self._error
        return SimpleNamespace(messages=[_msg("m1")], matched=1, scanned=1, truncated=False)


class _StepUp:
    def __init__(self, answer: bool) -> None:
        self.answer = answer
        self.calls = 0
        self.threads: list[threading.Thread] = []
        self.actions: list[str | None] = []

    def __call__(self, action: str | None) -> bool:
        self.calls += 1
        self.threads.append(threading.current_thread())
        self.actions.append(action)
        return self.answer


def _settle(qapp: Any, panel: MessagesPanel, client: _SearchClient, searches: int) -> None:
    deadline = time.time() + 10
    while time.time() < deadline:
        qapp.processEvents()
        if client.searches >= searches and not panel._loading:
            break
        time.sleep(0.01)
    for _ in range(20):
        qapp.processEvents()
        time.sleep(0.005)


def _search(
    qapp: Any, client: _SearchClient, step_up: _StepUp | None
) -> tuple[MessagesPanel, list]:
    panel = MessagesPanel(client, poll_client=client, step_up=step_up)  # type: ignore[arg-type]
    errors: list[str] = []
    panel.error.connect(errors.append)
    panel._content_filter.setText("needle")
    panel.refresh(autosize=True)
    return panel, errors


def test_a_refused_search_steps_up_on_the_gui_thread_and_resubmits(qapp: Any) -> None:
    client = _SearchClient(refusals=1)
    step_up = _StepUp(True)
    panel, errors = _search(qapp, client, step_up)
    try:
        _settle(qapp, panel, client, 2)
        assert step_up.calls == 1
        assert step_up.threads == [threading.main_thread()]
        assert client.searches == 2
        assert panel._table.rowCount() == 1
        assert errors == []
    finally:
        panel.stop()


@pytest.mark.parametrize("action", ["message_search", None], ids=["per-action", "session-window"])
def test_the_step_up_re_proves_for_the_action_the_refusal_named(
    qapp: Any, action: str | None
) -> None:
    """A per-action gate (ADR 0077) mints its grant only for a re-proof naming its action, and the
    polling client stashed nothing, so the panel passes the refusal's own action on."""
    client = _SearchClient(refusals=1, error=StepUpRequired("refused", status=403, action=action))
    step_up = _StepUp(True)
    panel, errors = _search(qapp, client, step_up)
    try:
        _settle(qapp, panel, client, 2)
        assert step_up.actions == [action]
        assert client.searches == 2
        assert errors == []
    finally:
        panel.stop()


def test_a_second_refusal_is_reported_not_prompted_again(qapp: Any) -> None:
    client = _SearchClient(refusals=5)
    step_up = _StepUp(True)
    panel, errors = _search(qapp, client, step_up)
    try:
        _settle(qapp, panel, client, 2)
        assert step_up.calls == 1
        assert client.searches == 2
        assert errors == ["step-up required"]
    finally:
        panel.stop()


def test_a_declined_step_up_reports_the_refusal(qapp: Any) -> None:
    client = _SearchClient(refusals=1)
    step_up = _StepUp(False)
    panel, errors = _search(qapp, client, step_up)
    try:
        _settle(qapp, panel, client, 1)
        assert step_up.calls == 1
        assert client.searches == 1
        assert errors == ["step-up required"]
    finally:
        panel.stop()


def test_a_refresh_during_the_prompt_neither_searches_nor_prompts_again(qapp: Any) -> None:
    # The prompt runs a nested event loop, so a refresh can arrive while it is up. It must latch,
    # not start a second search, and a declined prompt must not be followed by another.
    client = _SearchClient(refusals=5)
    panel_box: list[MessagesPanel] = []
    calls: list[int] = []

    def decline_after_a_refresh(_action: str | None) -> bool:
        calls.append(client.searches)
        panel_box[0].refresh(autosize=True)
        return False

    panel, errors = _search(qapp, client, None)
    panel_box.append(panel)
    panel._step_up = decline_after_a_refresh
    try:
        _settle(qapp, panel, client, 1)
        assert calls == [1]
        assert client.searches == 1
        assert errors == ["step-up required"]
    finally:
        panel.stop()


def test_an_idp_step_up_is_not_answered_with_a_password_prompt(qapp: Any) -> None:
    client = _SearchClient(refusals=1, error=IdpStepUpRequired("use the web console", status=403))
    step_up = _StepUp(True)
    panel, errors = _search(qapp, client, step_up)
    try:
        _settle(qapp, panel, client, 1)
        assert step_up.calls == 0
        assert errors == ["use the web console"]
    finally:
        panel.stop()


def test_a_403_that_is_not_a_step_up_is_not_answered_with_a_password_prompt(qapp: Any) -> None:
    # A role or scope refusal carries no X-Step-Up-Required, so the client raises a plain ApiError.
    client = _SearchClient(refusals=1, error=ApiError("forbidden", status=403))
    step_up = _StepUp(True)
    panel, errors = _search(qapp, client, step_up)
    try:
        _settle(qapp, panel, client, 1)
        assert step_up.calls == 0
        assert errors == ["forbidden"]
    finally:
        panel.stop()


def test_a_refused_re_proof_reports_its_own_cause(qapp: Any) -> None:
    client = _SearchClient(refusals=1)

    def refuse(_action: str | None) -> bool:
        raise ApiError("re-verification failed", status=401)

    panel, errors = _search(qapp, client, None)
    panel._step_up = refuse
    try:
        _settle(qapp, panel, client, 1)
        assert client.searches == 1
        assert errors == ["re-verification failed"]
        assert not panel._loading
    finally:
        panel.stop()
