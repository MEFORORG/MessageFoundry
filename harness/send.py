# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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

from harness._console_widgets import ConfigurableTable
from messagefoundry.generators import _core
from messagefoundry.generators import all_types  # noqa: F401  (registers the built-in message types)
from harness.mllp import SendItem, SendResult, SendWorker

_RANDOM = "(random across all)"
_COLUMNS = ["#", "Type", "Trigger", "Control ID", "ACK", "Latency (ms)", "Error"]


class SendPanel(QWidget):
    """Pick a message type/trigger + count, then send to host:port over MLLP."""

    def __init__(self) -> None:
        super().__init__()
        self._thread: QThread | None = None
        self._worker: SendWorker | None = None
        self._sent = 0
        self._ok = 0
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
        triggers = _core.triggers_for(code)
        choice = self._trigger.currentText()
        items: list[SendItem] = []
        for i in range(1, self._count.value() + 1):
            trigger = self._rng.choice(triggers) if choice == _RANDOM else choice
            payload = _core.generate_message(code, trigger, i)
            items.append(SendItem(i, code, trigger, _core.control_id(code, trigger, i), payload))

        self._results.setRowCount(0)
        self._results.setSortingEnabled(False)
        self._sent = self._ok = 0
        self._summary.setText(f"sending {len(items)} {code} message(s)…")

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
        self._sent += 1
        self._ok += 1 if res.ok else 0
        self._summary.setText(
            f"sent {self._sent} · accepted {self._ok} · failed {self._sent - self._ok}"
        )

    def _on_finished(self) -> None:
        if self._thread is not None:
            self._thread.quit()
            self._thread.wait()
        self._worker = None
        self._thread = None
        self._results.setSortingEnabled(True)
        self._send_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self._summary.setText(self._summary.text() + " — done")

    def shutdown(self) -> None:
        """Stop and join the send thread so the window can close without destroying a running
        QThread (stop() interrupts an in-flight recv, so the join is prompt)."""
        if self._worker is not None:
            self._worker.stop()
        if self._thread is not None:
            self._thread.quit()
            if not self._thread.wait(6000):
                self._thread.terminate()
                self._thread.wait()
            self._thread = None
        self._worker = None
