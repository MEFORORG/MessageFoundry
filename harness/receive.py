# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Receive tab: an MLLP listener that shows inbound messages and replies per a chosen mode.

Beyond plain AA/AE/AR/none, the reply mode can inject faults — delay the ACK, drop the connection,
or reject the first N deliveries of a control id then accept — to drive the engine's *outbound*
retry, dead-letter, and independent-draining behavior. Repeated control ids (the engine's
at-least-once retries) are counted and the duplicates highlighted.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QComboBox,
    QDoubleSpinBox,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from harness._console_widgets import ConfigurableTable
from harness.mllp import REPLY_MODES, MllpReceiver, Received

_COLUMNS = ["Time", "Peer", "Type", "Trigger", "Control ID", "Seen #"]
_RAW_ROLE = Qt.ItemDataRole.UserRole
_DUP_BRUSH = QBrush(QColor("#fff3cd"))  # pale amber: this control id has arrived before


class ReceivePanel(QWidget):
    """Start/stop a localhost MLLP listener; show inbound messages + pick the reply/fault mode."""

    def __init__(self) -> None:
        super().__init__()
        self._receiver = MllpReceiver()
        self._receiver.received.connect(self._on_received)
        self._count = 0

        self._port = QSpinBox()
        self._port.setRange(1, 65535)
        self._port.setValue(2576)  # not 2575 — avoid clashing with the engine's MLLP source
        self._ack = QComboBox()
        self._ack.addItems(REPLY_MODES)
        self._ack.currentTextChanged.connect(self._set_ack_mode)
        self._delay = QDoubleSpinBox()
        self._delay.setRange(0.0, 600.0)
        self._delay.setDecimals(1)
        self._delay.setValue(1.0)
        self._delay.setSuffix(" s")
        self._delay.valueChanged.connect(lambda v: setattr(self._receiver, "delay_seconds", v))
        self._fail_n = QSpinBox()
        self._fail_n.setRange(0, 1000)
        self._fail_n.setValue(1)
        self._fail_n.valueChanged.connect(lambda v: setattr(self._receiver, "fail_first", v))
        self._toggle = QPushButton("Start listening")
        self._toggle.clicked.connect(self._toggle_listen)
        self._status = QLabel("stopped")

        controls = QHBoxLayout()
        controls.addWidget(QLabel("Port:"))
        controls.addWidget(self._port)
        controls.addWidget(QLabel("Reply:"))
        controls.addWidget(self._ack)
        controls.addWidget(QLabel("Delay:"))
        controls.addWidget(self._delay)
        controls.addWidget(QLabel("Fail N:"))
        controls.addWidget(self._fail_n)
        controls.addWidget(self._toggle)
        controls.addWidget(self._status, stretch=1)

        self._table = ConfigurableTable(_COLUMNS, settings_key="harness/recv")
        self._table.itemSelectionChanged.connect(self._show_detail)
        self._detail = QPlainTextEdit()
        self._detail.setReadOnly(True)

        layout = QVBoxLayout(self)
        layout.addLayout(controls)
        layout.addWidget(self._table, stretch=2)
        layout.addWidget(QLabel("Message:"))
        layout.addWidget(self._detail, stretch=1)

    def _set_ack_mode(self, mode: str) -> None:
        self._receiver.ack_mode = mode

    def _toggle_listen(self) -> None:
        if self._receiver.is_listening():
            self._receiver.stop()
            self._toggle.setText("Start listening")
            self._status.setText("stopped")
            self._port.setEnabled(True)
            return
        self._receiver.ack_mode = self._ack.currentText()
        self._receiver.delay_seconds = self._delay.value()
        self._receiver.fail_first = self._fail_n.value()
        if self._receiver.start(self._port.value()):
            self._toggle.setText("Stop listening")
            self._status.setText(f"listening on 127.0.0.1:{self._receiver.port()}")
            self._port.setEnabled(False)
        else:
            self._status.setText(f"failed to bind port {self._port.value()}")

    def _on_received(self, rec: Received) -> None:
        self._count += 1
        self._table.setSortingEnabled(False)
        self._table.insertRow(0)
        cells = (rec.when, rec.peer, rec.code, rec.trigger, rec.control_id, str(rec.seen))
        for col, value in enumerate(cells):
            item = QTableWidgetItem(value)
            if col == 0:
                item.setData(_RAW_ROLE, rec.raw)  # keep raw on the row, survives re-sort
            if rec.seen > 1:
                item.setBackground(_DUP_BRUSH)  # flag at-least-once duplicates
            self._table.setItem(0, col, item)
        self._table.setSortingEnabled(True)
        if self._receiver.is_listening():
            self._status.setText(
                f"listening on 127.0.0.1:{self._receiver.port()} · {self._count} received"
            )

    def _show_detail(self) -> None:
        items = self._table.selectedItems()
        if not items:
            return
        first = self._table.item(items[0].row(), 0)
        raw = first.data(_RAW_ROLE) if first else None
        if isinstance(raw, str):
            self._detail.setPlainText(raw.replace("\r", "\n"))

    def shutdown(self) -> None:
        """Close the listener + any open client sockets so the window can exit cleanly."""
        self._receiver.stop()
