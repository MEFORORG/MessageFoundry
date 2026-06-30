# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Reusable PySide6 leaf widgets for the admin console.

The HL7 parse-tree view, the message browser, the single-message detail pane, and the
auto-refresh interval dialog. Pages (Connections / Log Search / …) compose these — see
``shell.py``, ``connections.py``, ``search.py``. Every widget takes an
:class:`~messagefoundry.console.client.EngineClient`-shaped object and exposes a
``refresh()`` so the UI can be driven (and smoke-tested headless) without user input.

API calls run synchronously on the GUI thread — localhost latency is negligible — and any
:class:`ApiError` is surfaced via the ``error`` signal rather than raising into Qt.
"""

from __future__ import annotations

import html
from dataclasses import dataclass
from datetime import datetime

from PySide6.QtCore import QPoint, QSettings, Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from messagefoundry.api.models import MessageDetail, MessageSummary
from messagefoundry.console._async import AsyncRunner
from messagefoundry.console.client import ApiError, EngineClient
from messagefoundry.console.theme import ERROR_TEXT
from messagefoundry.parsing import HL7PeekError, parse_tree

#: Shared "error red" for inline error text — the message-detail error, the auth dialogs'
#: error labels, and the heart's stopped state — so the palette can't drift across modules.
#: Sourced from the theme so there is a single source of truth for console colours.
ERROR_COLOR = ERROR_TEXT

__all__ = [
    "ParseTreeView",
    "MessageDetailPanel",
    "MessagesPanel",
    "RefreshSettingsDialog",
    "ConfigurableTable",
    "ERROR_COLOR",
    "fmt_ts",
    "fill_table",
]


def fmt_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def fill_table(table: QTableWidget, headers: list[str], *, multi: bool = False) -> None:
    table.setColumnCount(len(headers))
    table.setHorizontalHeaderLabels(headers)
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    mode = (
        QAbstractItemView.SelectionMode.ExtendedSelection
        if multi
        else QAbstractItemView.SelectionMode.SingleSelection
    )
    table.setSelectionMode(mode)
    table.verticalHeader().setVisible(False)
    table.horizontalHeader().setStretchLastSection(True)
    # Modern table chrome (purely visual): zebra striping instead of a hard grid, a touch more row
    # height, and a single-pixel-thin selection. The harsh default gridlines are dropped — the
    # alternating rows + theme borders carry the structure.
    table.setAlternatingRowColors(True)
    table.setShowGrid(False)
    table.verticalHeader().setDefaultSectionSize(30)
    table.horizontalHeader().setHighlightSections(False)


class ConfigurableTable(QTableWidget):
    """A table whose columns are left-aligned, reorderable (drag), sortable (click header), and
    show/hide-able (header right-click), with order/visibility/sort persisted across runs.

    Repopulate between :meth:`begin_populate` and :meth:`end_populate` so insertion is stable and
    the user's sort/layout survive an auto-refresh; pass ``autosize=True`` to fit columns to
    contents (do this on user-initiated loads, not silent ticks, so it won't fight a manual
    resize)."""

    def __init__(self, columns: list[str], *, settings_key: str, multi: bool = False) -> None:
        super().__init__(0, len(columns))
        self._columns = columns
        self._settings_key = settings_key
        self._suppress_save = True
        fill_table(self, columns, multi=multi)
        self.setSortingEnabled(True)
        header = self.horizontalHeader()
        header.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        header.setSectionsMovable(True)
        header.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        header.customContextMenuRequested.connect(self._show_header_menu)
        header.sectionMoved.connect(lambda *_: self._save_state())
        header.sortIndicatorChanged.connect(lambda *_: self._save_state())
        # No sort until the user clicks a header — preserve the server's natural row order
        # (e.g. messages newest-first, connections source-then-destinations).
        header.setSortIndicator(-1, Qt.SortOrder.AscendingOrder)
        self._restore_state()
        self._suppress_save = False

    def begin_populate(self) -> None:
        self._suppress_save = True
        self.setSortingEnabled(False)

    def end_populate(self, *, autosize: bool = False) -> None:
        self.setSortingEnabled(True)
        if autosize:
            self.resizeColumnsToContents()
        self._suppress_save = False

    def _restore_state(self) -> None:
        state = QSettings().value(self._settings_key)
        if state is not None:
            self.horizontalHeader().restoreState(state)

    def _save_state(self) -> None:
        if self._suppress_save:
            return
        QSettings().setValue(self._settings_key, self.horizontalHeader().saveState())

    def _show_header_menu(self, pos: QPoint) -> None:
        menu = QMenu(self)
        for col, label in enumerate(self._columns):
            act = menu.addAction(label)
            act.setCheckable(True)
            act.setChecked(not self.isColumnHidden(col))
            act.toggled.connect(lambda checked, c=col: self._set_column_visible(c, checked))
        menu.exec(self.horizontalHeader().mapToGlobal(pos))

    def _set_column_visible(self, col: int, visible: bool) -> None:
        self.setColumnHidden(col, not visible)
        self._save_state()


class ParseTreeView(QTreeWidget):
    """Renders an HL7 message as an explorable segment/field/component tree."""

    def __init__(self) -> None:
        super().__init__()
        self.setHeaderLabels(["Element", "Value"])
        self.header().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)

    def show_message(self, raw: str) -> None:
        self.clear()
        try:
            nodes = parse_tree(raw)
        except HL7PeekError as exc:
            self.addTopLevelItem(QTreeWidgetItem(["(unparseable)", str(exc)]))
            return
        for node in nodes:
            self.addTopLevelItem(self._item(node))
        self.expandToDepth(0)

    def _item(self, node: object) -> QTreeWidgetItem:
        # node is a parsing.TreeNode; value shown only on leaves to reduce noise.
        value = node.value if not node.children else ""  # type: ignore[attr-defined]
        item = QTreeWidgetItem([node.label, value])  # type: ignore[attr-defined]
        for child in node.children:  # type: ignore[attr-defined]
            item.addChild(self._item(child))
        return item


@dataclass(frozen=True)
class _DetailSnapshot:
    """One off-thread message-detail read, applied on the main thread. ``message_id`` lets a stale
    result (superseded by a newer ``load``) be dropped; ``error`` set ⇒ the read failed."""

    message_id: str
    detail: MessageDetail | None
    error: str | None


class MessageDetailPanel(QWidget):
    """Shows one message: summary, raw, parse tree, outbox, audit trail, and replay."""

    error = Signal(str)
    changed = Signal()  # emitted after a successful replay so lists can refresh

    def __init__(self, client: EngineClient, *, poll_client: EngineClient | None = None) -> None:
        super().__init__()
        self._client = client  # replay action — main thread, may step-up/MFA
        self._poll = poll_client or client  # message read — runs off the main thread
        self._runner = AsyncRunner(self)
        self._message_id: str | None = None
        self._pending_id: str | None = None  # the latest requested load (drops stale results)

        self._summary = QLabel("Select a message")
        self._summary.setWordWrap(True)
        self._replay = QPushButton("Replay")
        self._replay.setEnabled(False)
        self._replay.clicked.connect(self._on_replay)

        header = QHBoxLayout()
        header.addWidget(self._summary, stretch=1)
        header.addWidget(self._replay)

        self._tree = ParseTreeView()
        self._raw = QPlainTextEdit()
        self._raw.setReadOnly(True)
        self._outbox = QTableWidget(0, 5)
        fill_table(
            self._outbox, ["Destination", "Status", "Attempts", "Next attempt", "Last error"]
        )
        self._events = QTableWidget(0, 4)
        fill_table(self._events, ["Time", "Event", "Destination", "Detail"])

        tabs = QTabWidget()
        tabs.addTab(self._tree, "Parse tree")
        tabs.addTab(self._raw, "Raw")
        tabs.addTab(self._outbox, "Deliveries")
        tabs.addTab(self._events, "Audit / events")

        layout = QVBoxLayout(self)
        layout.addLayout(header)
        layout.addWidget(tabs)

    def clear(self) -> None:
        self._message_id = None
        self._pending_id = None  # a pending load() must not re-populate after an explicit clear
        self._summary.setText("Select a message")
        self._replay.setEnabled(False)
        self._tree.clear()
        self._raw.clear()
        self._outbox.setRowCount(0)
        self._events.setRowCount(0)

    def load(self, message_id: str) -> None:
        # Read the message OFF the main thread; apply on the main thread. A newer load() supersedes
        # an in-flight one (rapid row clicks / replay), so a stale result is dropped in _apply.
        self._pending_id = message_id
        self._runner.submit(lambda: self._fetch(message_id), on_done=self._apply)

    def stop(self) -> None:
        """Stop the background runner (call on window close) so a late result can't touch dead widgets."""
        self._runner.stop()

    def _fetch(self, message_id: str) -> _DetailSnapshot:
        """Runs on a worker thread — only blocking I/O, no widget access."""
        try:
            return _DetailSnapshot(message_id, self._poll.get_message(message_id), None)
        except ApiError as exc:
            return _DetailSnapshot(message_id, None, str(exc))

    def _apply(self, snap: _DetailSnapshot) -> None:
        """Runs on the main thread (result slot) — safe to touch widgets."""
        if snap.message_id != self._pending_id:
            return  # a newer load() (or a clear()) superseded this result
        if snap.error is not None:
            self.error.emit(snap.error)
            return
        detail = snap.detail
        assert detail is not None
        message_id = snap.message_id
        self._message_id = message_id
        self._replay.setEnabled(True)
        # Escape HL7-derived fields (message_type/control_id/error come from raw message content)
        # before interpolating into this rich-text label, so a crafted message can't inject HTML (H1).
        self._summary.setText(
            f"<b>{html.escape(detail.message_type or '?')}</b> "
            f"&nbsp; control={html.escape(detail.control_id or '?')} "
            f"&nbsp; status=<b>{html.escape(detail.status)}</b> "
            f"&nbsp; received {fmt_ts(detail.received_at)}"
            + (
                f"<br><span style='color:{ERROR_COLOR}'>{html.escape(detail.error)}</span>"
                if detail.error
                else ""
            )
        )
        self._tree.show_message(detail.raw)
        self._raw.setPlainText(detail.raw.replace("\r", "\n"))

        self._outbox.setRowCount(len(detail.outbox))
        for r, o in enumerate(detail.outbox):
            for c, text in enumerate(
                [
                    o.destination_name,
                    o.status,
                    str(o.attempts),
                    fmt_ts(o.next_attempt_at),
                    o.last_error or "",
                ]
            ):
                self._outbox.setItem(r, c, QTableWidgetItem(text))

        self._events.setRowCount(len(detail.events))
        for r, e in enumerate(detail.events):
            for c, text in enumerate([fmt_ts(e.ts), e.event, e.destination or "", e.detail or ""]):
                self._events.setItem(r, c, QTableWidgetItem(text))

    def _on_replay(self) -> None:
        if self._message_id is None:
            return
        try:
            self._client.replay(self._message_id)
        except ApiError as exc:
            self.error.emit(str(exc))
            return
        self.load(self._message_id)  # refresh detail (status/events updated)
        self.changed.emit()


@dataclass(frozen=True)
class _MessagesSnapshot:
    """One off-thread message-list (or content-search) read, applied on the main thread. ``error`` set
    ⇒ the read failed (the table is left as-is); otherwise ``messages`` is the page to render,
    ``count_text`` the status-bar label, and ``truncated`` whether a content search hit its scan cap (so
    the label can prompt the operator to narrow filters)."""

    messages: list[MessageSummary] | None
    count_text: str
    truncated: bool
    error: str | None


class MessagesPanel(QWidget):
    """A filterable message list with configurable columns (show/hide, reorder, sort, persisted).

    ``refresh(audit=True)`` records a PHI summary-display audit when the Summary column is visible
    and autosizes columns; the auto-refresh timer calls ``refresh()`` (no audit, no resize)."""

    error = Signal(str)
    message_selected = Signal(str)
    selection_cleared = Signal()  # the selected row vanished on refresh — clear the detail pane

    COLUMNS = [
        "Time",
        "Channel",
        "Event",
        "Msg. Type",
        "Status",
        "Control ID",
        "Summary",
        "Metadata",
    ]
    _SUMMARY_COL = 6

    def __init__(self, client: EngineClient, *, poll_client: EngineClient | None = None) -> None:
        super().__init__()
        self._client = client
        self._poll = poll_client or client  # message-list read — runs off the main thread
        self._runner = AsyncRunner(self)
        self._loading = False  # in-flight refresh guard (don't pile up during a slow call)
        # A refresh requested WHILE one is in flight is latched here (not dropped) and re-fired when
        # the in-flight read finishes, so a filter change (set_channel_filter / Enter / the Connections
        # 'Logs' link) or a post-replay refresh can't leave the filter box and the list mismatched —
        # which would never self-heal with auto-refresh off. None = none pending; bool = pending audit.
        self._pending: bool | None = None
        self._loaded = False  # autosize columns on the first (and user-initiated) loads

        self._channel_filter = QLineEdit()
        self._channel_filter.setPlaceholderText("channel id")
        self._status_filter = QLineEdit()
        self._status_filter.setPlaceholderText("status")
        # Content search (ADR 0046 #51): an HL7 field path (e.g. PID-3) OR a raw/summary substring. When
        # set, the panel switches from the metadata list to the scan-and-decrypt /messages/search route
        # (step-up gated server-side). The field-path box, when filled, takes precedence over content.
        self._content_filter = QLineEdit()
        self._content_filter.setPlaceholderText("content contains…")
        self._field_path_filter = QLineEdit()
        self._field_path_filter.setPlaceholderText("HL7 field (e.g. PID-3)")
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(lambda: self.refresh(audit=True))
        for box in (
            self._channel_filter,
            self._status_filter,
            self._content_filter,
            self._field_path_filter,
        ):
            box.returnPressed.connect(lambda: self.refresh(audit=True))

        filters = QHBoxLayout()
        filters.addWidget(QLabel("Search"))
        filters.addWidget(self._channel_filter)
        filters.addWidget(self._status_filter)
        filters.addWidget(self._content_filter)
        filters.addWidget(self._field_path_filter)
        filters.addWidget(refresh)

        self._table = ConfigurableTable(self.COLUMNS, settings_key="logsearch/header_state")
        self._table.itemSelectionChanged.connect(self._on_select)

        self._count = QLabel("")

        layout = QVBoxLayout(self)
        layout.addLayout(filters)
        layout.addWidget(self._table)
        layout.addWidget(self._count)

    def set_channel_filter(self, channel_id: str) -> None:
        """Filter to one channel and refresh (used by the Connections 'Logs' link)."""
        self._channel_filter.setText(channel_id)
        self._status_filter.clear()
        self._content_filter.clear()
        self._field_path_filter.clear()
        self.refresh(audit=True)

    def refresh(self, *, audit: bool = False) -> None:
        # Read the message list OFF the main thread (the 200-row read is the heaviest console query,
        # and a slow/wedged engine would otherwise freeze the GUI for the whole call). The query
        # parameters are read from the filter widgets HERE, on the main thread, then handed to the
        # worker — the worker must never touch a widget.
        if self._loading:
            # Don't pile up on a slow engine, but don't lose a filter change either — latch it
            # (OR-merge the audit flag) so it re-fires once the in-flight read completes.
            self._pending = audit if self._pending is None else (self._pending or audit)
            return
        self._pending = None
        summary_shown = not self._table.isColumnHidden(self._SUMMARY_COL)
        channel = self._channel_filter.text().strip() or None
        status = self._status_filter.text().strip() or None
        content = self._content_filter.text().strip() or None
        field_path = self._field_path_filter.text().strip() or None
        audit_summary = audit and summary_shown
        self._loading = True
        self._runner.submit(
            lambda: self._fetch(channel, status, content, field_path, audit_summary),
            on_done=lambda snap: self._apply(snap, autosize=audit),
            on_error=self._on_error,
        )

    def stop(self) -> None:
        """Stop the background runner (call on window close) so a late result can't touch dead widgets."""
        self._runner.stop()

    def _on_error(self, exc: BaseException) -> None:
        # Belt-and-suspenders: list_messages raises only ApiError (handled via the snapshot in _apply),
        # but an unexpected error must still clear the in-flight guard or the panel wedges forever.
        self._loading = False
        self.error.emit(str(exc))
        self._drain_pending()

    def _drain_pending(self) -> bool:
        """Re-fire a refresh that was latched while one was in flight. Returns True if it did."""
        if self._pending is None:
            return False
        audit = self._pending
        self._pending = None
        self.refresh(audit=audit)
        return True

    def _fetch(
        self,
        channel: str | None,
        status: str | None,
        content: str | None,
        field_path: str | None,
        audit_summary: bool,
    ) -> _MessagesSnapshot:
        """Runs on a worker thread — only blocking I/O, no widget access.

        With a content/field-path needle this routes to the scan-and-decrypt /messages/search endpoint
        (ADR 0046 #51) instead of the metadata list; the field-path box wins over the content box."""
        try:
            if field_path or content:
                # The field-path box, when filled, is the needle (the content box becomes its value
                # predicate); otherwise the content box is a raw/summary substring.
                search = self._poll.search_messages(
                    content=content if not field_path else None,
                    field_path=field_path,
                    field_value=content if field_path else None,
                    channel_id=channel,
                    status=status,
                    limit=200,
                )
                count = f"{search.matched} matched of {search.scanned} scanned"
                if search.truncated:
                    count += " — narrow your filters (scan cap hit)"
                return _MessagesSnapshot(list(search.messages), count, search.truncated, None)
            result = self._poll.list_messages(
                channel_id=channel, status=status, limit=200, audit_summary=audit_summary
            )
            return _MessagesSnapshot(
                list(result.messages),
                f"{len(result.messages)} shown of {result.total}",
                False,
                None,
            )
        except ApiError as exc:
            return _MessagesSnapshot(None, "", False, str(exc))

    def _apply(self, snap: _MessagesSnapshot, *, autosize: bool = False) -> None:
        """Runs on the main thread (result slot) — safe to touch widgets."""
        self._loading = False
        # A refresh was requested mid-flight (e.g. the filter changed) — re-fire it and skip rendering
        # this now-superseded snapshot, so the list always reflects the latest filter.
        if self._drain_pending():
            return
        if snap.error is not None:
            self.error.emit(snap.error)
            return
        messages = snap.messages
        assert messages is not None
        previously_selected = self._selected_id()
        self._table.begin_populate()
        self._table.setRowCount(len(messages))
        for r, m in enumerate(messages):
            cells = [
                fmt_ts(m.received_at),
                m.channel_id,
                m.event or "",
                m.message_type or "",
                m.status,
                m.control_id or "",
                m.summary or "",
                m.metadata or "",
            ]
            for c, text in enumerate(cells):
                item = QTableWidgetItem(text)
                if c == 0:
                    item.setData(Qt.ItemDataRole.UserRole, m.id)
                self._table.setItem(r, c, item)
        self._table.end_populate(autosize=(autosize or not self._loaded))
        self._loaded = True
        self._count.setText(snap.count_text)
        if previously_selected is not None and not self._reselect(previously_selected):
            # The selected message rolled off the list (deleted / filtered / aged past the 200-row
            # limit); tell the detail pane to clear so it stops showing a now-absent message (M2).
            self.selection_cleared.emit()

    def _on_select(self) -> None:
        message_id = self._selected_id()
        if message_id:
            self.message_selected.emit(message_id)

    def _selected_id(self) -> str | None:
        model = self._table.selectionModel()
        rows = model.selectedRows() if model else []
        if not rows:
            return None
        cell = self._table.item(rows[0].row(), 0)
        data = cell.data(Qt.ItemDataRole.UserRole) if cell else None
        return str(data) if data else None

    def _reselect(self, message_id: str) -> bool:
        """Restore a row selection after a refresh *without* re-emitting selection, so an
        auto-refresh tick keeps the highlighted row but doesn't reload the open detail pane.

        Returns True if the row was found and re-selected, False if the message is gone."""
        for r in range(self._table.rowCount()):
            cell = self._table.item(r, 0)
            if cell is not None and cell.data(Qt.ItemDataRole.UserRole) == message_id:
                self._table.blockSignals(True)
                self._table.selectRow(r)
                self._table.blockSignals(False)
                return True
        return False


class RefreshSettingsDialog(QDialog):
    """Modal picker for the console auto-refresh interval. ``0`` means *off*."""

    #: (label, seconds) presets shown in the dropdown.
    PRESETS: list[tuple[str, float]] = [
        ("Off", 0.0),
        ("1 second", 1.0),
        ("2 seconds", 2.0),
        ("5 seconds", 5.0),
        ("10 seconds", 10.0),
        ("30 seconds", 30.0),
    ]

    def __init__(self, current: float, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Auto-refresh interval")

        self._combo = QComboBox()
        for label, seconds in self.PRESETS:
            self._combo.addItem(label, seconds)
        # Keep a non-preset value (e.g. a custom --poll) selectable rather than snapping it.
        if not any(abs(current - s) < 1e-9 for _, s in self.PRESETS):
            self._combo.addItem(f"{current:g} seconds", float(current))
        self._select_current(current)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Refresh the active page every:"))
        layout.addWidget(self._combo)
        layout.addWidget(buttons)

    def _select_current(self, current: float) -> None:
        for i in range(self._combo.count()):
            if abs(float(self._combo.itemData(i)) - current) < 1e-9:
                self._combo.setCurrentIndex(i)
                return

    def selected_seconds(self) -> float:
        return float(self._combo.currentData())
