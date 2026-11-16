# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A flapping lane's auto-resolve keeps the re-alert cooldown (ADR 0128 section 4).

BACKLOG #5766 proposed ending the cooldown on every auto-resolve and operator resolve. The runner
raises ``connection_restored`` on the first good delivery after a ``connection_error``, so on a
lane that fails every other delivery that would page, and fire a rule's ``restart_outbound``, on
every flap. ADR 0128 section 4 bounds the action to once per cooldown so a flapping lane cannot
trigger a restart storm, and its BACKLOG #1741 amendment keeps an operator's resolve by hand from
ending the window. This pins that bound for the auto-resolve and the operator resolve.
"""

from __future__ import annotations

from messagefoundry.config.settings import AlertRule
from messagefoundry.pipeline.alert_sinks import NotifierAlertSink
from tests.test_alert_control import _Control, _RecordingTransport
from tests.test_alert_control import _drain as _drain_control
from tests.test_alert_state import _drain, _RecordingStore


async def test_a_flapping_lane_pages_and_restarts_once_per_cooldown() -> None:
    rule = AlertRule(
        event_type="connection_error", connection="*", control_action="restart_outbound"
    )
    pages = _RecordingTransport()
    sink = NotifierAlertSink([pages], rules=[rule], store=_RecordingStore(), realert_seconds=3600.0)
    control = _Control()
    sink.set_control_callback(control)
    for _ in range(3):
        sink.connection_error("OB_X", kind="connection_lost", detail="refused")
        await _drain(sink)
        sink.connection_restored("OB_X")  # the auto-resolve
        await _drain(sink)
    sink.forget("connection_error", "OB_X")  # an operator's resolve by hand
    sink.connection_error("OB_X", kind="connection_lost", detail="refused")
    await _drain(sink)
    await _drain_control(sink)
    assert control.calls == [("restart_outbound", "OB_X")]
    assert len(pages.events) == 1
