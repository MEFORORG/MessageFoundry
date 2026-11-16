# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A resolved alert's re-alert cooldown goes with it (BACKLOG #5766).

An auto-resolve, or an operator's resolve, closes the condition. A recurrence inside the cooldown
is then a new incident: it must page and dispatch its rule's control action, not be throttled by
the cooldown the closed incident left behind. ``connection_started`` already ended its own pair's
cooldown (BACKLOG #1741); these tests pin every other inverse and the operator resolve, plus the
provisional half: a resolve that fails leaves the row open, so the cooldown comes back.
"""

from __future__ import annotations

import asyncio
import sqlite3
from typing import Any

import pytest

from messagefoundry.config.settings import AlertRule
from messagefoundry.pipeline.alert_sinks import NotifierAlertSink
from tests.test_alert_state import _drain, _RecordingStore


class _Control:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    async def __call__(self, action: str, target: str, *, default_target: bool) -> None:
        self.calls.append((action, target))


class _FailingResolveStore(_RecordingStore):
    async def resolve_alert_instances_for(
        self, *, event_type: str, connection: str, now: float | None = None
    ) -> int:
        raise sqlite3.OperationalError("synthetic: database is locked")


@pytest.fixture
def no_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    zeros = (0.0,) * len(NotifierAlertSink._INVERSE_RETRY_DELAYS)
    monkeypatch.setattr(NotifierAlertSink, "_INVERSE_RETRY_DELAYS", zeros)


def _sink(store: Any) -> tuple[NotifierAlertSink, list[dict[str, Any]], _Control]:
    rule = AlertRule(
        event_type="connection_error", connection="*", control_action="restart_outbound"
    )
    sink = NotifierAlertSink([], rules=[rule], store=store, realert_seconds=3600.0)
    pages: list[dict[str, Any]] = []

    def record(event: dict[str, Any], *, dropped: str | None) -> bool:
        pages.append(event)
        return True

    setattr(sink, "_enqueue", record)  # noqa: B010 - an instance attribute shadows the method
    control = _Control()
    sink.set_control_callback(control)
    return sink, pages, control


async def _settle(sink: NotifierAlertSink) -> None:
    await _drain(sink)
    for _ in range(10):
        if not sink._control_tasks:
            break
        await asyncio.gather(*list(sink._control_tasks), return_exceptions=True)
        await asyncio.sleep(0)


def _fail(sink: NotifierAlertSink) -> None:
    sink.connection_error("OB_X", kind="connection_lost", detail="refused")


@pytest.mark.parametrize("resolved", [True, False], ids=["auto-resolved", "control-unresolved"])
async def test_a_recurrence_after_an_auto_resolve_pages_and_restarts(resolved: bool) -> None:
    sink, pages, control = _sink(_RecordingStore())
    _fail(sink)
    await _settle(sink)
    if resolved:
        sink.connection_restored("OB_X")
        await _settle(sink)
    _fail(sink)  # inside the hour-long cooldown
    await _settle(sink)
    expected = 2 if resolved else 1
    assert len(pages) == expected
    assert control.calls == [("restart_outbound", "OB_X")] * expected


async def test_a_recurrence_after_an_operator_resolve_pages_and_restarts() -> None:
    sink, pages, control = _sink(_RecordingStore())
    _fail(sink)
    await _settle(sink)
    sink.forget("connection_error", "OB_X")  # the API's resolve route calls this
    _fail(sink)
    await _settle(sink)
    assert len(pages) == 2
    assert control.calls == [("restart_outbound", "OB_X")] * 2


@pytest.mark.usefixtures("no_backoff")
async def test_a_resolve_that_fails_brings_the_cooldown_back() -> None:
    # The row stayed open, so the incident did not end and the cooldown still holds.
    sink, pages, control = _sink(_FailingResolveStore())
    _fail(sink)
    await _settle(sink)
    sink.connection_restored("OB_X")
    await _settle(sink)
    _fail(sink)
    await _settle(sink)
    assert len(pages) == 1
    assert control.calls == [("restart_outbound", "OB_X")]


@pytest.mark.usefixtures("no_backoff")
async def test_an_operator_resolve_during_a_failing_auto_resolve_keeps_the_cooldown_cleared() -> (
    None
):
    # forget lands between the clear and its failed write: what the operator closed stays closed.
    sink, pages, _control = _sink(_FailingResolveStore())
    _fail(sink)
    await _settle(sink)
    sink.connection_restored("OB_X")
    sink.forget("connection_error", "OB_X")
    await _settle(sink)
    _fail(sink)
    await _settle(sink)
    assert len(pages) == 2
