"""File tab: drop generated messages for the engine's File inbound to poll, and watch a directory
its File outbound writes to. Two sections in one tab so the file round-trip is exercised in place.

Defaults match ``harness/config`` (``./harness_io/in`` and ``./harness_io/out``), so with
that config served the tab works without any further setup. Dropping runs in a worker thread (file
writes can block on a burst); watching is event-driven on the GUI thread (small local reads).
"""

from __future__ import annotations

import random

from PySide6.QtCore import Qt, QThread
from PySide6.QtWidgets import (
    QComboBox,
    QDoubleSpinBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from messagefoundry.console.widgets import ConfigurableTable
from messagefoundry.generators import _core
from messagefoundry.generators import all_types  # noqa: F401  (registers the built-in message types)
from harness.file_transport import DropResult, FileDropWorker, FolderWatcher
from harness.mllp import Received, SendItem

_RANDOM = "(random across all)"
_DROP_COLUMNS = ["#", "Type", "Trigger", "Control ID", "File", "Error"]
_WATCH_COLUMNS = ["Time", "File", "Type", "Trigger", "Control ID"]
_RAW_ROLE = Qt.ItemDataRole.UserRole


class FilePanel(QWidget):
    """Drop files into the engine's inbound directory; watch its outbound directory for arrivals."""

    def __init__(self) -> None:
        super().__init__()
        self._thread: QThread | None = None
        self._worker: FileDropWorker | None = None
        self._dropped = 0
        self._written = 0
        self._rng = random.Random()
        self._watch_count = 0

        layout = QVBoxLayout(self)
        layout.addWidget(self._build_drop())
        layout.addWidget(self._build_watch(), stretch=1)

    # --- drop ----------------------------------------------------------------

    def _build_drop(self) -> QGroupBox:
        self._code = QComboBox()
        self._code.addItems(_core.message_codes())
        self._code.currentTextChanged.connect(self._reload_triggers)
        self._trigger = QComboBox()
        self._count = QSpinBox()
        self._count.setRange(1, 1_000_000)
        self._count.setValue(50)
        self._drop_dir = QLineEdit("./harness_io/in")
        self._rate = QDoubleSpinBox()
        self._rate.setRange(0.0, 10_000.0)
        self._rate.setDecimals(1)
        self._rate.setSuffix(" file/s")
        self._rate.setSpecialValueText("max (0)")

        form = QFormLayout()
        form.addRow("Message type:", self._code)
        form.addRow("Trigger:", self._trigger)
        form.addRow("Count:", self._count)
        form.addRow("Directory:", self._drop_dir)
        form.addRow("Rate:", self._rate)

        self._drop_btn = QPushButton("Drop")
        self._drop_btn.clicked.connect(self._start_drop)
        self._stop_btn = QPushButton("Stop")
        self._stop_btn.setEnabled(False)
        self._stop_btn.clicked.connect(self._stop_drop)
        buttons = QHBoxLayout()
        buttons.addWidget(self._drop_btn)
        buttons.addWidget(self._stop_btn)
        buttons.addStretch(1)

        self._drop_summary = QLabel("")
        self._drop_results = ConfigurableTable(_DROP_COLUMNS, settings_key="harness/file/drop")

        box = QGroupBox("Drop → engine File inbound")
        inner = QVBoxLayout(box)
        inner.addLayout(form)
        inner.addLayout(buttons)
        inner.addWidget(self._drop_summary)
        inner.addWidget(self._drop_results)
        self._reload_triggers(self._code.currentText())
        return box

    def _reload_triggers(self, code: str) -> None:
        self._trigger.clear()
        if code:
            self._trigger.addItem(_RANDOM)
            self._trigger.addItems(_core.triggers_for(code))

    def _start_drop(self) -> None:
        code = self._code.currentText()
        if not code or self._worker is not None:
            return
        triggers = _core.triggers_for(code)
        choice = self._trigger.currentText()
        items: list[SendItem] = []
        for i in range(1, self._count.value() + 1):
            trigger = self._rng.choice(triggers) if choice == _RANDOM else choice
            payload = _core.generate_message(code, trigger, i)
            items.append(SendItem(i, code, trigger, _core.control_id(code, trigger, i), payload))

        self._drop_results.setRowCount(0)
        self._drop_results.setSortingEnabled(False)
        self._dropped = self._written = 0
        self._drop_summary.setText(f"dropping {len(items)} {code} file(s)…")

        self._thread = QThread(self)
        self._worker = FileDropWorker(self._drop_dir.text().strip(), items, rate=self._rate.value())
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.result.connect(self._on_drop_result)
        self._worker.finished.connect(self._on_drop_finished)
        self._thread.start()
        self._drop_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)

    def _stop_drop(self) -> None:
        if self._worker is not None:
            self._worker.stop()

    def _on_drop_result(self, res: DropResult) -> None:
        row = self._drop_results.rowCount()
        self._drop_results.insertRow(row)
        values = [
            str(res.item.seq),
            res.item.code,
            res.item.trigger,
            res.item.control_id,
            res.filename,
            res.error,
        ]
        for col, value in enumerate(values):
            self._drop_results.setItem(row, col, QTableWidgetItem(value))
        self._dropped += 1
        self._written += 0 if res.error else 1
        self._drop_summary.setText(
            f"dropped {self._dropped} · written {self._written} · failed {self._dropped - self._written}"
        )

    def _on_drop_finished(self) -> None:
        if self._thread is not None:
            self._thread.quit()
            self._thread.wait()
        self._worker = None
        self._thread = None
        self._drop_results.setSortingEnabled(True)
        self._drop_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self._drop_summary.setText(self._drop_summary.text() + " — done")

    def shutdown(self) -> None:
        """Stop the folder-watch timer and join the drop thread so the window closes cleanly."""
        self._watcher.stop()
        if self._worker is not None:
            self._worker.stop()
        if self._thread is not None:
            self._thread.quit()
            if not self._thread.wait(6000):
                self._thread.terminate()
                self._thread.wait()
            self._thread = None
        self._worker = None

    # --- watch ---------------------------------------------------------------

    def _build_watch(self) -> QGroupBox:
        self._watcher = FolderWatcher()
        self._watcher.received.connect(self._on_received)

        self._watch_dir = QLineEdit("./harness_io/out")
        self._watch_btn = QPushButton("Start watching")
        self._watch_btn.clicked.connect(self._toggle_watch)
        self._watch_status = QLabel("stopped")

        controls = QHBoxLayout()
        controls.addWidget(QLabel("Directory:"))
        controls.addWidget(self._watch_dir, stretch=1)
        controls.addWidget(self._watch_btn)
        controls.addWidget(self._watch_status)

        self._watch_table = ConfigurableTable(_WATCH_COLUMNS, settings_key="harness/file/watch")
        self._watch_table.itemSelectionChanged.connect(self._show_detail)
        self._detail = QPlainTextEdit()
        self._detail.setReadOnly(True)

        box = QGroupBox("Watch ← engine File outbound")
        inner = QVBoxLayout(box)
        inner.addLayout(controls)
        inner.addWidget(self._watch_table, stretch=2)
        inner.addWidget(QLabel("Message:"))
        inner.addWidget(self._detail, stretch=1)
        return box

    def _toggle_watch(self) -> None:
        if self._watcher.is_watching():
            self._watcher.stop()
            self._watch_btn.setText("Start watching")
            self._watch_status.setText("stopped")
            self._watch_dir.setEnabled(True)
            return
        if self._watcher.start(self._watch_dir.text().strip()):
            self._watch_btn.setText("Stop watching")
            self._watch_status.setText("watching")
            self._watch_dir.setEnabled(False)
        else:
            self._watch_status.setText("failed to watch directory")

    def _on_received(self, rec: Received) -> None:
        self._watch_count += 1
        self._watch_table.setSortingEnabled(False)
        self._watch_table.insertRow(0)
        for col, value in enumerate((rec.when, rec.peer, rec.code, rec.trigger, rec.control_id)):
            item = QTableWidgetItem(value)
            if col == 0:
                item.setData(_RAW_ROLE, rec.raw)  # keep raw on the row, survives re-sort
            self._watch_table.setItem(0, col, item)
        self._watch_table.setSortingEnabled(True)
        if self._watcher.is_watching():
            self._watch_status.setText(f"watching · {self._watch_count} seen")

    def _show_detail(self) -> None:
        items = self._watch_table.selectedItems()
        if not items:
            return
        first = self._watch_table.item(items[0].row(), 0)
        raw = first.data(_RAW_ROLE) if first else None
        if isinstance(raw, str):
            self._detail.setPlainText(raw.replace("\r", "\n"))
