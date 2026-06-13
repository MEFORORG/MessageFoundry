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

from messagefoundry.console.client import ApiError, EngineClient
from messagefoundry.parsing import HL7PeekError, parse_tree

#: Shared "error red" for inline error text — the message-detail error, the auth dialogs'
#: error labels, and the heart's stopped state — so the palette can't drift across modules.
ERROR_COLOR = "#c62828"

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


class MessageDetailPanel(QWidget):
    """Shows one message: summary, raw, parse tree, outbox, audit trail, and replay."""

    error = Signal(str)
    changed = Signal()  # emitted after a successful replay so lists can refresh

    def __init__(self, client: EngineClient) -> None:
        super().__init__()
        self._client = client
        self._message_id: str | None = None

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
        self._summary.setText("Select a message")
        self._replay.setEnabled(False)
        self._tree.clear()
        self._raw.clear()
        self._outbox.setRowCount(0)
        self._events.setRowCount(0)

    def load(self, message_id: str) -> None:
        try:
            detail = self._client.get_message(message_id)
        except ApiError as exc:
            self.error.emit(str(exc))
            return
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

    def __init__(self, client: EngineClient) -> None:
        super().__init__()
        self._client = client
        self._loaded = False  # autosize columns on the first (and user-initiated) loads

        self._channel_filter = QLineEdit()
        self._channel_filter.setPlaceholderText("channel id")
        self._status_filter = QLineEdit()
        self._status_filter.setPlaceholderText("status")
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(lambda: self.refresh(audit=True))
        self._channel_filter.returnPressed.connect(lambda: self.refresh(audit=True))
        self._status_filter.returnPressed.connect(lambda: self.refresh(audit=True))

        filters = QHBoxLayout()
        filters.addWidget(QLabel("Search"))
        filters.addWidget(self._channel_filter)
        filters.addWidget(self._status_filter)
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
        self.refresh(audit=True)

    def refresh(self, *, audit: bool = False) -> None:
        summary_shown = not self._table.isColumnHidden(self._SUMMARY_COL)
        try:
            result = self._client.list_messages(
                channel_id=self._channel_filter.text().strip() or None,
                status=self._status_filter.text().strip() or None,
                limit=200,
                audit_summary=audit and summary_shown,
            )
        except ApiError as exc:
            self.error.emit(str(exc))
            return
        previously_selected = self._selected_id()
        self._table.begin_populate()
        self._table.setRowCount(len(result.messages))
        for r, m in enumerate(result.messages):
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
        self._table.end_populate(autosize=(audit or not self._loaded))
        self._loaded = True
        self._count.setText(f"{len(result.messages)} shown of {result.total}")
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
