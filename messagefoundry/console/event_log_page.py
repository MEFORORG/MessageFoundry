# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Event Log page — the Corepoint-style connection/transport event log (#46).

Lists connection-lifecycle + transport events (established/closed, the pre-ingress refuse/framing
failures, and outbound connection_lost/restored) newest-first, with a connection + event-kind filter.
The data is **metadata only** (no PHI — connection name, peer IP, scrubbed reason), so the read needs
only ``monitoring:read`` and — unlike the Dead Letters page — auto-refresh is safe (no per-read PHI
audit). The list read runs OFF the main thread so a slow/wedged engine can't freeze the GUI.
"""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from messagefoundry.api.models import ConnectionEventInfo
from messagefoundry.console._async import AsyncRunner
from messagefoundry.console.client import EngineClient
from messagefoundry.console.widgets import ConfigurableTable, fmt_ts

#: The bounded connection-event vocabulary (mirrors the engine's emit kinds) for the filter dropdown.
_KINDS = [
    "established",
    "closed",
    "peer_not_allowlisted",
    "at_capacity",
    "frame_oversize",
    "peer_reset",
    "framing_error",
    "connection_lost",
    "connection_restored",
]


class EventLogPage(QWidget):
    """Read-only table of connection/transport events with a connection + kind filter (#46)."""

    error = Signal(str)

    COLUMNS = ["Time", "Connection", "Direction", "Transport", "Event", "Peer", "Reason"]

    def __init__(self, client: EngineClient, *, poll_client: EngineClient | None = None) -> None:
        super().__init__()
        self._client = client
        self._poll = poll_client or client  # the list read runs off the main thread
        self._runner = AsyncRunner(self)
        self._loading = False
        self._pending = False

        self._connection = QLineEdit()
        self._connection.setPlaceholderText("Filter by connection (optional)")
        self._connection.returnPressed.connect(self.reload)
        self._kind = QComboBox()
        self._kind.addItem("All events", userData=None)
        for k in _KINDS:
            self._kind.addItem(k, userData=k)
        self._kind.currentIndexChanged.connect(self.reload)
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.reload)

        controls = QHBoxLayout()
        controls.addWidget(QLabel("Connection:"))
        controls.addWidget(self._connection)
        controls.addWidget(QLabel("Event:"))
        controls.addWidget(self._kind)
        controls.addWidget(refresh_btn)
        controls.addStretch(1)

        self._table = ConfigurableTable(self.COLUMNS, settings_key="event_log")

        layout = QVBoxLayout(self)
        layout.addLayout(controls)
        layout.addWidget(self._table)

    # --- page interface (auto-refresh timer + nav) ---------------------------

    def refresh(self) -> None:
        # Safe to reload on the silent auto-refresh tick: the event log is metadata-only, so the read
        # triggers no per-call PHI-exposure audit (unlike /dead-letters).
        self.reload()

    def reload(self) -> None:
        if self._runner._stopped:
            return
        if self._loading:
            self._pending = True
            return
        self._pending = False
        self._loading = True
        self._runner.submit(self._fetch, on_done=self._apply, on_error=self._on_error)

    def stop(self) -> None:
        """Stop the background runner (call on window close) so a late result can't touch dead widgets."""
        self._runner.stop()

    def _fetch(self) -> list[ConnectionEventInfo]:
        """Runs on a worker thread — only blocking I/O, no widget access."""
        connection = self._connection.text().strip() or None
        kind = self._kind.currentData()
        return self._poll.list_connection_events(connection=connection, kind=kind, limit=200)

    def _on_error(self, exc: BaseException) -> None:
        self._loading = False
        self.error.emit(str(exc))
        self._drain_pending()

    def _drain_pending(self) -> bool:
        if not self._pending:
            return False
        self._pending = False
        self.reload()
        return True

    def _apply(self, events: list[ConnectionEventInfo]) -> None:
        """Runs on the main thread (result slot) — safe to touch widgets."""
        self._loading = False
        if self._drain_pending():
            return  # a reload was requested mid-flight — re-fire it, skip this superseded result
        self._table.begin_populate()
        self._table.setRowCount(len(events))
        for row, e in enumerate(events):
            cells = [
                fmt_ts(e.ts),
                e.connection,
                e.direction,
                e.transport,
                e.kind,
                e.peer_host or "",
                e.reason or "",
            ]
            for col, text in enumerate(cells):
                self._table.setItem(row, col, QTableWidgetItem(text))
        self._table.end_populate(autosize=True)
