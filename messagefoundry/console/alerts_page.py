# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Alerts page — active operator alert instances (ADR 0044, #56) + the loaded ``[alerts]`` transport
config + rule set (ADR 0014), with Acknowledge / Resolve actions on the active alerts.

The **Active alerts** section is a table over ``GET /alerts/active`` (open + acknowledged instances,
newest first) with Acknowledge / Resolve buttons that call ``POST /alerts/{id}/ack`` and
``/resolve``. The **Transports + Rules** section below is the read-only ``GET /alerts/rules`` view
(BACKLOG #22b): which transports are configured (present-or-not — no secrets/recipients), the global
re-alert interval, and the ordered rules.

Both reads run OFF the main thread (a slow/wedged engine would otherwise freeze the GUI); the result
is applied on the main thread. Both payloads carry **no PHI**, so the silent auto-refresh tick re-reads
safely. Per CLAUDE.md §10 the page imports only the ``api/`` Pydantic models + the HTTP client, never
the engine.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from PySide6.QtWidgets import (
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)
from PySide6.QtCore import Signal

from messagefoundry.api.models import AlertInstanceInfo, AlertRuleInfo, AlertsConfig
from messagefoundry.console._async import AsyncRunner
from messagefoundry.console.client import EngineClient
from messagefoundry.console.widgets import ConfigurableTable


def _fmt_secs(value: float) -> str:
    """A seconds value rendered without a trailing ``.0`` (e.g. ``300.0`` -> ``300``)."""
    return f"{value:g}"


def _fmt_ts(value: float) -> str:
    """An epoch rendered as a local short timestamp; blank for a falsy/None value."""
    if not value:
        return ""
    return datetime.fromtimestamp(value).strftime("%Y-%m-%d %H:%M:%S")


@dataclass(frozen=True)
class _AlertsData:
    """The combined alerts read (active instances + the rules config) applied on the main thread."""

    active: list[AlertInstanceInfo]
    config: AlertsConfig


class AlertsPage(QWidget):
    """Active alert instances (ack/resolve, ADR 0044) + the read-only ``[alerts]`` rules (ADR 0014)."""

    error = Signal(str)

    COLUMNS = [
        "Event type",
        "Connection",
        "Min depth",
        "Min oldest (s)",
        "Severity",
        "Transports",
        "Cooldown (s)",
    ]

    ACTIVE_COLUMNS = [
        "Severity",
        "Status",
        "Event type",
        "Connection",
        "Count",
        "First seen",
        "Last seen",
        "Reason",
    ]

    def __init__(self, client: EngineClient, *, poll_client: EngineClient | None = None) -> None:
        super().__init__()
        # The off-thread reads go through the read-only poll client; the ack/resolve MUTATIONS go
        # through the handler-bearing main-thread client (poll client is read-only).
        self._client = client
        self._poll = poll_client or client
        self._runner = AsyncRunner(self)
        self._loading = False  # in-flight read guard (don't pile up during a slow call)
        # A load requested while one is in flight is latched (not dropped) and re-fired on completion;
        # the autosize intent is OR-merged so a user reload that lands behind a silent tick still
        # autosizes once it actually runs.
        self._pending = False
        self._pending_autosize = False
        self._acting = False  # in-flight ack/resolve guard
        self._active_ids: list[int] = []  # row -> alert id, for the action buttons

        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.reload)
        self._ack_btn = QPushButton("Acknowledge")
        self._ack_btn.clicked.connect(self._ack_selected)
        self._resolve_btn = QPushButton("Resolve")
        self._resolve_btn.clicked.connect(self._resolve_selected)
        buttons = QHBoxLayout()
        buttons.addWidget(refresh_btn)
        buttons.addWidget(self._ack_btn)
        buttons.addWidget(self._resolve_btn)
        buttons.addStretch(1)

        # Active alerts (ADR 0044): open + acknowledged instances with the ack/resolve actions above.
        self._active_table = ConfigurableTable(
            self.ACTIVE_COLUMNS, settings_key="alerts/active_header_state"
        )
        self._active_table.itemSelectionChanged.connect(self._sync_action_buttons)

        # Transports summary. The endpoint reports each transport present-or-not with its non-secret
        # settings only (no webhook URL, no SMTP credentials, no recipient addresses).
        self._webhook_label = QLabel("—")
        self._webhook_label.setWordWrap(True)
        self._email_label = QLabel("—")
        self._email_label.setWordWrap(True)
        self._realert_label = QLabel("—")
        summary_form = QFormLayout()
        summary_form.addRow("Webhook:", self._webhook_label)
        summary_form.addRow("Email:", self._email_label)
        summary_form.addRow("Re-alert interval:", self._realert_label)
        summary = QGroupBox("Transports")
        summary.setLayout(summary_form)

        self._table = ConfigurableTable(self.COLUMNS, settings_key="alerts/header_state")

        layout = QVBoxLayout(self)
        layout.addLayout(buttons)
        layout.addWidget(QLabel("Active alerts (open + acknowledged):"))
        layout.addWidget(self._active_table, stretch=1)
        layout.addWidget(summary)
        layout.addWidget(QLabel("Rules (first match wins):"))
        layout.addWidget(self._table, stretch=1)
        self._sync_action_buttons()

    # --- page interface (auto-refresh timer + nav) ---------------------------

    def refresh(self) -> None:
        # Silent auto-refresh tick: re-read (read-only, no PHI/audit, so polling is safe) but DON'T
        # autosize — that would fight a manual column resize on every tick.
        self._load(autosize=False)

    def reload(self) -> None:
        # User-initiated (nav open / Refresh button): re-read and autosize columns to contents.
        self._load(autosize=True)

    def _load(self, *, autosize: bool) -> None:
        # Read the alerts config OFF the main thread; apply on the main thread (a slow/wedged engine
        # would otherwise freeze the GUI for the whole /alerts/rules call).
        if self._runner._stopped:
            # The page is being torn down (stop() ran). submit() would no-op, so neither _apply nor
            # _on_error would fire and _loading would latch True forever — strand a late load instead.
            return
        if self._loading:
            self._pending = True  # latch — re-fire when the in-flight read completes (don't drop)
            self._pending_autosize = self._pending_autosize or autosize
            return
        self._pending = False
        self._loading = True
        self._runner.submit(
            self._fetch,
            on_done=lambda data: self._apply(data, autosize=autosize),
            on_error=self._on_error,
        )

    def stop(self) -> None:
        """Stop the background runner (call on window close) so a late result can't touch dead widgets."""
        self._runner.stop()

    def _fetch(self) -> _AlertsData:
        """Runs on a worker thread — only blocking I/O, no widget access."""
        active = self._poll.active_alerts().alerts
        config = self._poll.alerts_rules()
        return _AlertsData(active=active, config=config)

    def _on_error(self, exc: BaseException) -> None:
        self._loading = False
        self.error.emit(str(exc))
        self._drain_pending()

    def _drain_pending(self) -> bool:
        """Re-fire a load that was latched while one was in flight. Returns True if it did."""
        if not self._pending:
            return False
        self._pending = False
        autosize = self._pending_autosize
        self._pending_autosize = False
        self._load(autosize=autosize)
        return True

    def _apply(self, data: _AlertsData, *, autosize: bool) -> None:
        """Runs on the main thread (result slot) — safe to touch widgets."""
        self._loading = False
        if self._drain_pending():
            return  # a load was requested mid-flight — re-fire it, skip this superseded result
        self._render_active(data.active, autosize=autosize)
        self._render_summary(data.config)
        self._table.begin_populate()
        self._table.setRowCount(len(data.config.rules))
        for row, rule in enumerate(data.config.rules):
            for col, text in enumerate(self._rule_cells(rule)):
                self._table.setItem(row, col, QTableWidgetItem(text))
        self._table.end_populate(autosize=autosize)

    def _render_active(self, active: list[AlertInstanceInfo], *, autosize: bool) -> None:
        self._active_ids = [a.id for a in active]
        self._active_table.begin_populate()
        self._active_table.setRowCount(len(active))
        for row, a in enumerate(active):
            for col, text in enumerate(self._active_cells(a)):
                self._active_table.setItem(row, col, QTableWidgetItem(text))
        self._active_table.end_populate(autosize=autosize)
        self._sync_action_buttons()

    @staticmethod
    def _active_cells(a: AlertInstanceInfo) -> list[str]:
        """The eight display cells for one active-alert row (in ``ACTIVE_COLUMNS`` order)."""
        return [
            a.severity,
            a.status,
            a.event_type,
            a.connection,
            str(a.count),
            _fmt_ts(a.first_seen),
            _fmt_ts(a.last_seen),
            a.reason or "",
        ]

    # --- ack / resolve actions (ADR 0044) ------------------------------------

    def _selected_alert_id(self) -> int | None:
        rows = {i.row() for i in self._active_table.selectedItems()}
        if len(rows) != 1:
            return None
        (row,) = rows
        if 0 <= row < len(self._active_ids):
            return self._active_ids[row]
        return None

    def _sync_action_buttons(self) -> None:
        enabled = (not self._acting) and self._selected_alert_id() is not None
        self._ack_btn.setEnabled(enabled)
        self._resolve_btn.setEnabled(enabled)

    def _ack_selected(self) -> None:
        self._act("ack")

    def _resolve_selected(self) -> None:
        self._act("resolve")

    def _act(self, action: str) -> None:
        # Run the mutation OFF the main thread (it goes through the handler-bearing main-thread client),
        # then reload the active list on completion. Guarded so a double-click can't fire twice.
        if self._acting or self._runner._stopped:
            return
        alert_id = self._selected_alert_id()
        if alert_id is None:
            return
        self._acting = True
        self._sync_action_buttons()

        def run() -> None:
            if action == "ack":
                self._client.ack_alert(alert_id)
            else:
                self._client.resolve_alert(alert_id)

        self._runner.submit(run, on_done=lambda _r: self._on_acted(), on_error=self._on_act_error)

    def _on_acted(self) -> None:
        self._acting = False
        self.reload()  # refresh the active list (the acted instance moved/left)

    def _on_act_error(self, exc: BaseException) -> None:
        self._acting = False
        self._sync_action_buttons()
        QMessageBox.warning(self, "Alert action failed", str(exc))

    def _render_summary(self, data: AlertsConfig) -> None:
        if data.webhook_configured:
            hosts = ", ".join(data.webhook_allowed_hosts) or "any"
            self._webhook_label.setText(
                f"configured · timeout {_fmt_secs(data.webhook_timeout)}s · allowed hosts: {hosts}"
            )
        else:
            self._webhook_label.setText("not configured")
        if data.email_configured:
            tls = "on" if data.email_use_tls else "off"
            hosts = ", ".join(data.smtp_allowed_hosts) or "any"
            self._email_label.setText(
                f"configured · {data.email_recipient_count} recipient(s) · SMTP port "
                f"{data.email_smtp_port} · TLS {tls} · allowed hosts: {hosts}"
            )
        else:
            self._email_label.setText("not configured")
        self._realert_label.setText(f"{_fmt_secs(data.realert_seconds)}s")

    def _rule_cells(self, rule: AlertRuleInfo) -> list[str]:
        """The seven display cells for one rule row (in ``COLUMNS`` order)."""
        # transports: None = all configured transports; [] = suppress (notify nothing); else the subset.
        if rule.transports is None:
            transports = "all"
        else:
            transports = ", ".join(rule.transports) or "suppress"
        return [
            rule.event_type,
            rule.connection,
            "" if rule.min_depth is None else str(rule.min_depth),
            "" if rule.min_oldest_seconds is None else _fmt_secs(rule.min_oldest_seconds),
            rule.severity,
            transports,
            "" if rule.cooldown_seconds is None else _fmt_secs(rule.cooldown_seconds),
        ]
