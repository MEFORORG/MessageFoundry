# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Connections dashboard: one row per endpoint (each inbound + each outbound connection).

A toolbar acts on the selected rows — Start/Stop/Restart operate on the selected **inbound**
connections; Purge clears the queue of the selected **outbound** connections. The table is fed by
the server-computed ``GET /connections`` rows, so the page stays thin. Clicking a row's *Logs*
link asks the shell to open the Log Search page filtered to that connection.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from PySide6.QtCore import QItemSelectionModel, Qt, Signal
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QMenu,
    QMessageBox,
    QPushButton,
    QTableWidgetItem,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from messagefoundry.api.models import ConnectionRow
from messagefoundry.console._async import AsyncRunner
from messagefoundry.console.client import ApiError, EngineClient
from messagefoundry.console.widgets import ConfigurableTable

_COLUMNS = [
    "Name",
    "Status",
    "Direction",
    "Method",
    "Logs",
    "Queue Depth",
    "Idle",
    "Alerts",
    "# Errored",
    "# Read",
    "# Written",
    "Peer",
    "Port",
    "Backlog",
    "Delivered Age",
]
_LOGS_COL = 4

# (role, channel_id, destination) identifies a row across refreshes for selection + actions.
_RowKey = tuple[str, str, str]


def _fmt_int(n: int | None) -> str:
    return "—" if n is None else str(n)


def _fmt_secs(s: float | None) -> str:
    if s is None:
        return "—"
    if s < 1:
        return "0s"
    if s < 60:
        return f"{s:.0f}s"
    if s < 3600:
        return f"{s / 60:.0f}m"
    return f"{s / 3600:.1f}h"


def _style_link(item: QTableWidgetItem) -> None:
    """Make a cell look like a clickable link (blue, underlined)."""
    item.setForeground(QBrush(QColor("#1a73e8")))
    font = item.font()
    font.setUnderline(True)
    item.setFont(font)


@dataclass(frozen=True)
class _Snapshot:
    """One off-thread refresh result, applied on the main thread. ``error`` set ⇒ the read failed
    (the table is left as-is); otherwise ``rows`` holds the endpoint list to render."""

    rows: list[ConnectionRow] | None
    error: str | None


class ConnectionsPage(QWidget):
    """Endpoint table + action toolbar."""

    error = Signal(str)
    open_logs = Signal(str)  # channel_id — ask the shell to open Log Search filtered to it

    def __init__(self, client: EngineClient, *, poll_client: EngineClient | None = None) -> None:
        super().__init__()
        self._client = client  # actions (start/stop/purge) — main thread, may step-up/MFA
        self._poll = poll_client or client  # reads — run off the main thread (see _async)
        self._runner = AsyncRunner(self)
        self._loading = False  # in-flight refresh guard (don't pile up during a slow call)
        # A refresh requested while one is in flight is latched (not dropped) and re-fired on
        # completion, so a post-action refresh (start/stop/purge) isn't lost when it lands during a
        # periodic tick. None = none pending; bool = pending autosize (OR-merged).
        self._pending: bool | None = None

        self._start = QPushButton("Start")
        self._stop = QPushButton("Stop")
        self._actions = QToolButton()
        self._actions.setText("Actions ▾")
        self._actions.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        menu = QMenu(self._actions)
        act_restart = menu.addAction("Restart")
        menu.addSeparator()
        act_purge_top = menu.addAction("Purge Top Message")
        act_purge_all = menu.addAction("Purge All Queued Messages")
        self._actions.setMenu(menu)

        self._start.clicked.connect(lambda: self._inbound_action(self._client.start_connection))
        self._stop.clicked.connect(lambda: self._inbound_action(self._client.stop_connection))
        act_restart.triggered.connect(lambda: self._inbound_action(self._client.restart_connection))
        act_purge_top.triggered.connect(lambda: self._purge("top"))
        act_purge_all.triggered.connect(lambda: self._purge("all"))

        toolbar = QHBoxLayout()
        toolbar.addWidget(QLabel("Connections"))
        toolbar.addStretch(1)
        toolbar.addWidget(self._start)
        toolbar.addWidget(self._stop)
        toolbar.addWidget(self._actions)

        self._table = ConfigurableTable(
            _COLUMNS, settings_key="connections/header_state", multi=True
        )
        self._table.itemSelectionChanged.connect(self._sync_toolbar)
        self._table.cellClicked.connect(self._on_cell_clicked)
        self._loaded = False  # autosize columns on the first (and user-initiated) loads

        layout = QVBoxLayout(self)
        layout.addLayout(toolbar)
        layout.addWidget(self._table)
        self._sync_toolbar()

    def refresh(self, *, autosize: bool = False) -> None:
        # Read the endpoint list OFF the main thread (a slow/wedged engine can stall /connections for
        # up to the client timeout); the result applies on the main thread via _apply.
        if self._loading:
            self._pending = autosize if self._pending is None else (self._pending or autosize)
            return  # a fetch is already in flight — latch this one, don't pile up or drop it
        self._pending = None
        self._loading = True
        self._runner.submit(
            self._fetch,
            on_done=lambda snap: self._apply(snap, autosize=autosize),
            on_error=self._on_error,
        )

    def stop(self) -> None:
        """Stop the background runner (call on window close) so a late result can't touch dead widgets."""
        self._runner.stop()

    def _on_error(self, exc: BaseException) -> None:
        # Belt-and-suspenders: connections() raises only ApiError (handled via the snapshot in _apply),
        # but an unexpected error must still clear the in-flight guard or the page wedges forever.
        self._loading = False
        self.error.emit(str(exc))
        self._drain_pending()

    def _drain_pending(self) -> bool:
        """Re-fire a refresh that was latched while one was in flight. Returns True if it did."""
        if self._pending is None:
            return False
        autosize = self._pending
        self._pending = None
        self.refresh(autosize=autosize)
        return True

    def _fetch(self) -> _Snapshot:
        """Runs on a worker thread — only blocking I/O, no widget access."""
        try:
            return _Snapshot(self._poll.connections(), None)
        except ApiError as exc:
            return _Snapshot(None, str(exc))

    def _apply(self, snap: _Snapshot, *, autosize: bool = False) -> None:
        """Runs on the main thread (result slot) — safe to touch widgets."""
        self._loading = False
        if self._drain_pending():
            return  # a refresh was requested mid-flight — re-fire it, skip this superseded snapshot
        if snap.error is not None:
            self.error.emit(snap.error)
            return
        rows = snap.rows or []
        selected = self._selected_keys()
        self._table.begin_populate()
        self._table.setRowCount(len(rows))
        for r, row in enumerate(rows):
            key: _RowKey = (row.role, row.channel_id, row.destination or "")
            cells = [
                row.name,
                f"{row.status} [SIMULATED]" if row.simulated else row.status,
                row.direction,
                row.method,
                "Logs",  # clickable cell -> open_logs (see _on_cell_clicked)
                _fmt_int(row.queue_depth),
                _fmt_secs(row.idle_seconds),
                _fmt_int(row.alerts_active),
                _fmt_int(row.errored),
                _fmt_int(row.read),
                _fmt_int(row.written),
                row.peer or "",
                _fmt_int(row.port),
                _fmt_secs(row.backlog_seconds),
                _fmt_secs(row.delivered_age_seconds),
            ]
            for c, text in enumerate(cells):
                item = QTableWidgetItem(text)
                if c == 0:
                    item.setData(Qt.ItemDataRole.UserRole, key)
                elif c == _LOGS_COL:
                    _style_link(item)
                self._table.setItem(r, c, item)
        self._table.end_populate(autosize=autosize or not self._loaded)
        self._loaded = True
        self._reselect(selected)

    def reload(self) -> None:
        """User-initiated load (nav/open) — autosizes columns to contents."""
        self.refresh(autosize=True)

    # --- selection -----------------------------------------------------------

    def _selected_keys(self) -> list[_RowKey]:
        model = self._table.selectionModel()
        if model is None:
            return []
        keys: list[_RowKey] = []
        for index in model.selectedRows():
            item = self._table.item(index.row(), 0)
            data = item.data(Qt.ItemDataRole.UserRole) if item else None
            if data:
                keys.append((data[0], data[1], data[2]))
        return keys

    def _reselect(self, keys: list[_RowKey]) -> None:
        model = self._table.selectionModel()
        if model is None or not keys:
            self._sync_toolbar()
            return
        wanted = set(keys)
        self._table.blockSignals(True)
        model.clearSelection()
        flags = QItemSelectionModel.SelectionFlag.Select | QItemSelectionModel.SelectionFlag.Rows
        for r in range(self._table.rowCount()):
            item = self._table.item(r, 0)
            data = item.data(Qt.ItemDataRole.UserRole) if item else None
            if data and (data[0], data[1], data[2]) in wanted:
                model.select(self._table.model().index(r, 0), flags)
        self._table.blockSignals(False)
        self._sync_toolbar()

    def _sync_toolbar(self) -> None:
        has = bool(self._selected_keys())
        self._start.setEnabled(has)
        self._stop.setEnabled(has)
        self._actions.setEnabled(has)

    # --- actions -------------------------------------------------------------

    def _inbound_action(self, action: Callable[[str], None]) -> None:
        """Start/Stop/Restart the inbound connection(s) in the selected source rows."""
        names: list[str] = []
        for role, channel_id, _dest in self._selected_keys():
            if role == "source" and channel_id not in names:
                names.append(channel_id)
        if not names:
            self.error.emit("Select one or more inbound (source) rows.")
            return
        try:
            for name in names:
                action(name)
        except ApiError as exc:
            self.error.emit(str(exc))
            return
        self.refresh()

    def _purge(self, scope: str) -> None:
        """Purge the queue of the outbound connection(s) in the selected destination rows."""
        names: list[str] = []
        for role, _channel_id, dest in self._selected_keys():
            if role == "destination" and dest and dest not in names:
                names.append(dest)
        if not names:
            self.error.emit("Select one or more outbound (destination) rows to purge.")
            return
        if scope == "all":
            # Bulk + destructive: cancels every queued delivery (they won't retry). Confirm, default
            # No, so an accidental click next to "Purge Top Message" can't wipe a queue (review M-28).
            answer = QMessageBox.question(
                self,
                "Purge all queued messages",
                f"Cancel ALL queued deliveries to {', '.join(names)}?\n\n"
                "Queued messages won't be sent and won't retry. This can't be undone.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
        try:
            for name in names:
                self._client.purge_connection(name, scope)
        except ApiError as exc:
            self.error.emit(str(exc))
            return
        self.refresh()

    def _on_cell_clicked(self, row: int, col: int) -> None:
        if col != _LOGS_COL:
            return
        item = self._table.item(row, 0)
        key = item.data(Qt.ItemDataRole.UserRole) if item else None
        if key:
            self.open_logs.emit(key[1])  # channel_id
