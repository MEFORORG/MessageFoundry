# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Alerts page — the loaded ``[alerts]`` transport config + rule set (ADR 0014), read-only.

A thin view over ``GET /alerts/rules`` (BACKLOG #22b): it shows whether the webhook/email transports
are configured (present-or-not — the endpoint deliberately returns **no** secrets or recipient
addresses), the global re-alert interval, and the ordered list of operator-authored alert rules.

The read runs OFF the main thread (a slow/wedged engine would otherwise freeze the GUI for the whole
``/alerts/rules`` call); the result is applied on the main thread. Unlike Dead Letters this payload
carries **no PHI** and the route is a cheap in-memory read with no server-side audit, so it is safe to
re-read on the silent auto-refresh tick. There is no action button — the page is purely read-only.
"""

from __future__ import annotations

from PySide6.QtWidgets import (
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)
from PySide6.QtCore import Signal

from messagefoundry.api.models import AlertRuleInfo, AlertsConfig
from messagefoundry.console._async import AsyncRunner
from messagefoundry.console.client import EngineClient
from messagefoundry.console.widgets import ConfigurableTable


def _fmt_secs(value: float) -> str:
    """A seconds value rendered without a trailing ``.0`` (e.g. ``300.0`` -> ``300``)."""
    return f"{value:g}"


class AlertsPage(QWidget):
    """Transports summary + a table of alert rules loaded from ``[alerts]`` (read-only, ADR 0014)."""

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

    def __init__(self, client: EngineClient, *, poll_client: EngineClient | None = None) -> None:
        super().__init__()
        # Read-only page: the alert-rules read runs off the main thread, so it goes through the
        # read-only poll client (never the handler-bearing main-thread client). There are no actions,
        # so the main-thread client is unused here beyond the default fallback.
        self._poll = poll_client or client
        self._runner = AsyncRunner(self)
        self._loading = False  # in-flight read guard (don't pile up during a slow call)
        # A load requested while one is in flight is latched (not dropped) and re-fired on completion;
        # the autosize intent is OR-merged so a user reload that lands behind a silent tick still
        # autosizes once it actually runs.
        self._pending = False
        self._pending_autosize = False

        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.reload)
        buttons = QHBoxLayout()
        buttons.addWidget(refresh_btn)
        buttons.addStretch(1)

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
        layout.addWidget(summary)
        layout.addWidget(QLabel("Rules (first match wins):"))
        layout.addWidget(self._table, stretch=1)

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

    def _fetch(self) -> AlertsConfig:
        """Runs on a worker thread — only blocking I/O, no widget access."""
        return self._poll.alerts_rules()

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

    def _apply(self, data: AlertsConfig, *, autosize: bool) -> None:
        """Runs on the main thread (result slot) — safe to touch widgets."""
        self._loading = False
        if self._drain_pending():
            return  # a load was requested mid-flight — re-fire it, skip this superseded result
        self._render_summary(data)
        self._table.begin_populate()
        self._table.setRowCount(len(data.rules))
        for row, rule in enumerate(data.rules):
            for col, text in enumerate(self._rule_cells(rule)):
                self._table.setItem(row, col, QTableWidgetItem(text))
        self._table.end_populate(autosize=autosize)

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
