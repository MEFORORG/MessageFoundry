# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Send tab: generate messages of a chosen type/trigger and fire them at an MLLP endpoint."""

from __future__ import annotations

import random

from PySide6.QtCore import QThread
from PySide6.QtWidgets import (
    QComboBox,
    QDoubleSpinBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from harness._async import join_worker_thread
from harness._batch import MAX_RESULT_ROWS, generated_items
from harness._batch import RANDOM_TRIGGER as _RANDOM
from harness._console_widgets import ConfigurableTable
from harness.mllp import SendResult, SendWorker
from messagefoundry_toolkit.generators import (
    _core,
    all_types,  # noqa: F401  (registers the built-in message types)
)

_COLUMNS = ["#", "Type", "Trigger", "Control ID", "ACK", "Latency (ms)", "Error"]


class SendPanel(QWidget):
    """Pick a message type/trigger + count, then send to host:port over MLLP."""

    def __init__(self) -> None:
        super().__init__()
        self._thread: QThread | None = None
        self._worker: SendWorker | None = None
        self._sent = 0
        self._ok = 0
        self._not_sent = 0
        self._rng = random.Random()

        self._code = QComboBox()
        self._code.addItems(_core.message_codes())
        self._code.currentTextChanged.connect(self._reload_triggers)
        self._trigger = QComboBox()
        self._count = QSpinBox()
        self._count.setRange(1, 1_000_000)
        self._count.setValue(100)
        self._host = QLineEdit("127.0.0.1")
        self._port = QSpinBox()
        self._port.setRange(1, 65535)
        self._port.setValue(2575)
        self._rate = QDoubleSpinBox()
        self._rate.setRange(0.0, 10_000.0)
        self._rate.setDecimals(1)
        self._rate.setSuffix(" msg/s")
        self._rate.setSpecialValueText("max (0)")  # 0 -> no throttle

        form = QFormLayout()
        form.addRow("Message type:", self._code)
        form.addRow("Trigger:", self._trigger)
        form.addRow("Count:", self._count)
        form.addRow("Host:", self._host)
        form.addRow("Port:", self._port)
        form.addRow("Rate:", self._rate)

        self._send_btn = QPushButton("Send")
        self._send_btn.clicked.connect(self._start)
        self._stop_btn = QPushButton("Stop")
        self._stop_btn.setEnabled(False)
        self._stop_btn.clicked.connect(self._stop)
        buttons = QHBoxLayout()
        buttons.addWidget(self._send_btn)
        buttons.addWidget(self._stop_btn)
        buttons.addStretch(1)

        self._summary = QLabel("")
        self._results = ConfigurableTable(_COLUMNS, settings_key="harness/send")

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addLayout(buttons)
        layout.addWidget(self._summary)
        layout.addWidget(self._results, stretch=1)

        self._reload_triggers(self._code.currentText())

    def _reload_triggers(self, code: str) -> None:
        self._trigger.clear()
        if code:
            self._trigger.addItem(_RANDOM)
            self._trigger.addItems(_core.triggers_for(code))

    def _start(self) -> None:
        code = self._code.currentText()
        if not code or self._worker is not None:
            return
        count = self._count.value()
        # Generated lazily, on the worker thread as each message is sent (BACKLOG #5949).
        items = generated_items(code, self._trigger.currentText(), count, self._rng)

        self._results.setRowCount(0)
        self._results.setSortingEnabled(False)
        self._sent = self._ok = self._not_sent = 0
        self._summary.setText(f"sending {count} {code} message(s)…")

        self._thread = QThread(self)
        self._worker = SendWorker(
            self._host.text().strip(),
            self._port.value(),
            items,
            timeout=10.0,
            rate=self._rate.value(),
        )
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.result.connect(self._on_result)
        self._worker.finished.connect(self._on_finished)
        self._thread.start()
        self._send_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)

    def _stop(self) -> None:
        if self._worker is not None:
            self._worker.stop()

    def _on_result(self, res: SendResult) -> None:
        row = self._results.rowCount()
        if row < MAX_RESULT_ROWS:
            self._results.insertRow(row)
            values = [
                str(res.item.seq),
                res.item.code,
                res.item.trigger,
                res.item.control_id,
                res.ack_code,
                f"{res.latency_ms:.0f}",
                res.error,
            ]
            for col, value in enumerate(values):
                self._results.setItem(row, col, QTableWidgetItem(value))
        # A payload refused before any dial (ADR 0205 rule 1) never reached the wire, so it is
        # counted apart from what was sent.
        if res.error.startswith("not sent:"):
            self._not_sent += 1
        else:
            self._sent += 1
            self._ok += 1 if res.ok else 0
        summary = f"sent {self._sent} · accepted {self._ok} · failed {self._sent - self._ok}"
        if self._not_sent:
            summary += f"; not sent {self._not_sent}"
        if self._sent + self._not_sent > MAX_RESULT_ROWS:
            summary += f" (table shows the first {MAX_RESULT_ROWS})"
        self._summary.setText(summary)

    def _on_finished(self) -> None:
        failure = self._worker.failure if self._worker is not None else ""
        if self._thread is not None:
            self._thread.quit()
            self._thread.wait()
        self._worker = None
        self._thread = None
        self._results.setSortingEnabled(True)
        self._send_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        ending = f" — stopped early: {failure}" if failure else " — done"
        self._summary.setText(self._summary.text() + ending)

    def shutdown(self) -> None:
        """Stop and join the send thread so the window can close without destroying a running
        QThread. stop() interrupts an in-flight recv, a dial and a pause between messages, so the
        join is normally prompt. What it cannot interrupt, a name lookup or a send to a peer that
        stopped reading, is waited out, never terminated."""
        if self._worker is not None:
            self._worker.stop()
        if self._thread is not None:
            join_worker_thread(self._thread)
            self._thread = None
        self._worker = None
