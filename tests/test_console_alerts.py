# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Headless tests for the console Alerts page (BACKLOG #22, ADR 0014 + ADR 0044 #56).

Drives ``AlertsPage`` against a fake client returning a sample ``AlertsConfig`` + active
``AlertInstanceInfo`` list, and asserts the transports summary, the rules table, the active-alerts
table, and the Acknowledge / Resolve actions (ADR 0044) render/fire correctly.
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6")

from messagefoundry.api.models import (  # noqa: E402
    AlertInstanceInfo,
    AlertInstanceList,
    AlertRuleInfo,
    AlertsConfig,
)
from messagefoundry.console.client import ApiError  # noqa: E402


def _config(
    *,
    rules: list[AlertRuleInfo] | None = None,
    webhook_configured: bool = True,
    email_configured: bool = True,
) -> AlertsConfig:
    return AlertsConfig(
        webhook_configured=webhook_configured,
        webhook_timeout=10.0,
        webhook_allowed_hosts=["hooks.example.org"],
        email_configured=email_configured,
        email_smtp_port=587,
        email_use_tls=True,
        email_recipient_count=2,
        smtp_allowed_hosts=["smtp.example.org"],
        realert_seconds=300.0,
        rules=rules if rules is not None else [],
    )


def _instance(
    alert_id: int,
    *,
    event_type: str = "connection_error",
    connection: str = "OB_X",
    severity: str = "critical",
    status: str = "open",
    count: int = 1,
    reason: str | None = "refused",
) -> AlertInstanceInfo:
    return AlertInstanceInfo(
        id=alert_id,
        event_type=event_type,
        connection=connection,
        severity=severity,
        status=status,
        first_seen=100.0,
        last_seen=150.0,
        count=count,
        reason=reason,
    )


class FakeClient:
    """The EngineClient surface AlertsPage uses: canned AlertsConfig + active alerts + call recording."""

    def __init__(
        self,
        config: AlertsConfig,
        *,
        active: list[AlertInstanceInfo] | None = None,
        error: ApiError | None = None,
    ) -> None:
        self._config = config
        self._active = active if active is not None else []
        self._error = error
        self.calls = 0
        self.acked: list[int] = []
        self.resolved: list[int] = []

    def alerts_rules(self) -> AlertsConfig:
        self.calls += 1
        if self._error is not None:
            raise self._error
        return self._config

    def active_alerts(self) -> AlertInstanceList:
        if self._error is not None:
            raise self._error
        return AlertInstanceList(alerts=list(self._active))

    def ack_alert(self, alert_id: int) -> AlertInstanceInfo:
        self.acked.append(alert_id)
        return _instance(alert_id, status="acknowledged")

    def resolve_alert(self, alert_id: int) -> AlertInstanceInfo:
        self.resolved.append(alert_id)
        return _instance(alert_id, status="resolved")


@pytest.fixture(scope="module")
def qapp():
    from PySide6.QtWidgets import QApplication

    yield QApplication.instance() or QApplication([])


@pytest.fixture(autouse=True)
def _clean_table_settings(qapp):
    # ConfigurableTable persists its header order/sort under this QSettings key. Clear it around each
    # test so a sort order persisted by a real console run on this machine can't reorder the rule rows
    # and break the index-based assertions below.
    from PySide6.QtCore import QSettings

    QSettings().remove("alerts/header_state")
    QSettings().remove("alerts/active_header_state")
    yield
    QSettings().remove("alerts/header_state")
    QSettings().remove("alerts/active_header_state")


def _settle(qapp, runner) -> None:
    """Let the off-thread alerts read finish and deliver its result to the main thread."""
    runner._pool.waitForDone(5000)
    for _ in range(5):
        qapp.processEvents()


def test_rules_table_renders(qapp) -> None:
    from messagefoundry.console.alerts_page import AlertsPage

    # An ADR-0014-shaped rule set: a queue_buildup threshold rule routed to a webhook+email subset, a
    # storage suppress rule ([] transports), and a default-shaped catch-all (transports=None).
    config = _config(
        rules=[
            AlertRuleInfo(
                event_type="queue_buildup",
                connection="IB_ACME_*",
                min_depth=5000,
                min_oldest_seconds=120.0,
                severity="critical",
                transports=["webhook", "email"],  # multi-element subset -> joined
                cooldown_seconds=60.0,
            ),
            AlertRuleInfo(
                event_type="storage_threshold",
                connection="*",
                severity="info",
                transports=[],  # suppress
            ),
            AlertRuleInfo(
                event_type="any",
                connection="*",
                severity="warning",
                transports=None,  # all configured transports
            ),
        ]
    )
    page = AlertsPage(FakeClient(config))  # type: ignore[arg-type]
    page.reload()
    _settle(qapp, page._runner)

    assert page._table.rowCount() == 3
    # Row 0 — the threshold rule.
    assert page._table.item(0, 0).text() == "queue_buildup"  # Event type
    assert page._table.item(0, 1).text() == "IB_ACME_*"  # Connection
    assert page._table.item(0, 2).text() == "5000"  # Min depth
    assert page._table.item(0, 3).text() == "120"  # Min oldest (s) — no trailing .0
    assert page._table.item(0, 4).text() == "critical"  # Severity
    assert page._table.item(0, 5).text() == "webhook, email"  # Transports — multi-element joined
    assert page._table.item(0, 6).text() == "60"  # Cooldown (s)
    # Row 1 — empty transports renders as "suppress"; absent thresholds render blank.
    assert page._table.item(1, 5).text() == "suppress"
    assert page._table.item(1, 2).text() == ""  # min_depth None -> blank
    assert page._table.item(1, 3).text() == ""  # min_oldest_seconds None -> blank
    assert page._table.item(1, 6).text() == ""  # cooldown None -> blank
    # Row 2 — None transports renders as "all".
    assert page._table.item(2, 5).text() == "all"
    page.stop()


def test_transports_summary_renders(qapp) -> None:
    from messagefoundry.console.alerts_page import AlertsPage

    page = AlertsPage(FakeClient(_config()))  # type: ignore[arg-type]
    page.reload()
    _settle(qapp, page._runner)

    assert "configured" in page._webhook_label.text()
    assert "not configured" not in page._webhook_label.text()
    email = page._email_label.text()
    assert "2 recipient(s)" in email  # the COUNT is shown...
    assert "587" in email  # ...and the non-secret SMTP port...
    assert (
        "example.org" not in email or "smtp.example.org" in email
    )  # only allowed-hosts, no address
    assert page._realert_label.text() == "300s"
    page.stop()


def test_unconfigured_transports_show_not_configured(qapp) -> None:
    from messagefoundry.console.alerts_page import AlertsPage

    page = AlertsPage(
        FakeClient(_config(webhook_configured=False, email_configured=False, rules=[]))  # type: ignore[arg-type]
    )
    page.reload()
    _settle(qapp, page._runner)

    assert page._webhook_label.text() == "not configured"
    assert page._email_label.text() == "not configured"
    assert page._table.rowCount() == 0
    page.stop()


def test_refresh_reads_on_the_tick(qapp) -> None:
    # Unlike Dead Letters, the Alerts payload has no PHI and the route does no server-side audit, so
    # the silent auto-refresh tick is allowed to re-read (refresh() is NOT a no-op here).
    from messagefoundry.console.alerts_page import AlertsPage

    client = FakeClient(_config())
    page = AlertsPage(client)  # type: ignore[arg-type]
    page.reload()
    _settle(qapp, page._runner)
    assert client.calls == 1

    page.refresh()  # auto-refresh tick — DOES read
    _settle(qapp, page._runner)
    assert client.calls == 2
    page.stop()


def test_error_reaches_error_signal(qapp) -> None:
    from messagefoundry.console.alerts_page import AlertsPage

    denied = ApiError("403: monitoring:read required", status=403)
    page = AlertsPage(FakeClient(_config(), error=denied))  # type: ignore[arg-type]
    errors: list[str] = []
    page.error.connect(errors.append)

    page.reload()
    _settle(qapp, page._runner)

    assert errors == [str(denied)]
    assert page._table.rowCount() == 0  # nothing rendered on the failed read
    page.stop()


def test_load_after_stop_does_not_strand_loading(qapp) -> None:
    # A load() that lands AFTER stop() must not latch _loading=True forever: submit() no-ops on a
    # stopped runner, so neither _apply nor _on_error would fire. _load guards the stopped runner.
    from messagefoundry.console.alerts_page import AlertsPage

    client = FakeClient(_config())
    page = AlertsPage(client)  # type: ignore[arg-type]
    page.stop()

    page.reload()  # after stop()
    assert client.calls == 0  # no read was started
    assert page._loading is False  # not stranded


# --- active alerts table + ack/resolve actions (ADR 0044, #56) ---------------


def test_active_alerts_table_renders(qapp) -> None:
    from messagefoundry.console.alerts_page import AlertsPage

    active = [
        _instance(7, event_type="connection_error", connection="OB_X", severity="critical"),
        _instance(
            8,
            event_type="queue_buildup",
            connection="OB_Y",
            severity="warning",
            status="acknowledged",
            count=3,
        ),
    ]
    page = AlertsPage(FakeClient(_config(), active=active))  # type: ignore[arg-type]
    page.reload()
    _settle(qapp, page._runner)

    assert page._active_table.rowCount() == 2
    # Row 0 cells (Severity, Status, Event type, Connection, Count, ...).
    assert page._active_table.item(0, 0).text() == "critical"
    assert page._active_table.item(0, 1).text() == "open"
    assert page._active_table.item(0, 2).text() == "connection_error"
    assert page._active_table.item(0, 3).text() == "OB_X"
    assert page._active_table.item(0, 4).text() == "1"
    assert page._active_table.item(1, 1).text() == "acknowledged"
    assert page._active_table.item(1, 4).text() == "3"
    assert page._active_ids == [7, 8]
    page.stop()


def test_ack_and_resolve_actions_fire(qapp) -> None:
    from messagefoundry.console.alerts_page import AlertsPage

    client = FakeClient(_config(), active=[_instance(7), _instance(8, connection="OB_Y")])
    page = AlertsPage(client)  # type: ignore[arg-type]
    page.reload()
    _settle(qapp, page._runner)

    # No selection → actions disabled.
    assert not page._ack_btn.isEnabled()
    # Select row 0 (id 7) and acknowledge.
    page._active_table.selectRow(0)
    assert page._ack_btn.isEnabled()
    page._ack_selected()
    _settle(qapp, page._runner)  # the off-thread mutation + the reload it triggers
    _settle(qapp, page._runner)
    assert client.acked == [7]

    # Select row 1 (id 8) and resolve.
    page._active_table.selectRow(1)
    page._resolve_selected()
    _settle(qapp, page._runner)
    _settle(qapp, page._runner)
    assert client.resolved == [8]
    page.stop()
