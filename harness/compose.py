# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Compose tab: send an arbitrary raw HL7 message — including deliberately malformed ones — to
exercise the engine's error/validation paths the generators can't reach.

The generators only emit conformant 2.5.1, so they always route cleanly. This tab lets you paste
or hand-edit a message (or seed one from a preset) and send it over MLLP with an explicit **ACK
expectation** — Accept (AA/CA), Reject (AE/AR), or No ACK (verified with a short bounded wait, so
an unexpected reply is flagged rather than ignored) — or drop it as a file. Pair it with the Monitor tab
to confirm the resulting disposition (e.g. a no-MSH message → ERROR + AR NAK; a wrong-version
message into the strict inbound → ERROR + AE).
"""

from __future__ import annotations

from datetime import datetime

from PySide6.QtCore import QThread
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QComboBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QStackedWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from messagefoundry.console.widgets import ConfigurableTable
from messagefoundry.generators import _core
from messagefoundry.generators import all_types  # noqa: F401  (registers the built-in message types)
from messagefoundry.parsing import HL7PeekError, Peek, normalize
from harness.file_transport import DropResult, FileDropWorker
from harness.mllp import SendItem, SendResult, SendWorker

_COLUMNS = ["Time", "Transport", "Result", "Expected", "OK", "Error"]
_ACCEPT, _REJECT, _NONE = "Accept (AA/CA)", "Reject (AE/AR)", "No ACK"
_ACCEPT_CODES = ("AA", "CA")
_REJECT_CODES = ("AE", "AR", "CE", "CR")

# Editor seeds: one conformant message plus common malformations for the error/validation paths.
_BAD_VERSION = (
    "MSH|^~\\&|HARNESS|FAC|DEST|DFAC|20260101||ADT^A01^ADT_A01|COMPOSE1|P|2.3\n"
    "EVN|A01|20260101\nPID|1||100^^^H^MR||DOE^JANE"
)
_NO_MSH = "PID|1||100^^^H^MR||DOE^JANE\nPV1|1|I"


class ComposePanel(QWidget):
    """Edit a raw message and send it (MLLP with an ACK expectation, or as a file)."""

    def __init__(self) -> None:
        super().__init__()
        self._thread: QThread | None = None
        self._worker: SendWorker | FileDropWorker | None = None
        self._pending_expect = _ACCEPT

        self._editor = QPlainTextEdit()
        mono = QFont()
        mono.setStyleHint(QFont.StyleHint.Monospace)
        mono.setFamily("monospace")
        self._editor.setFont(mono)
        self._editor.setPlaceholderText("Paste or type raw HL7 (one segment per line)…")

        self._preset = QComboBox()
        self._preset.addItems(
            ["Insert preset…", "Valid ADT^A01", "No MSH segment", "Bad version (2.3)", "Clear"]
        )
        self._preset.activated.connect(self._apply_preset)

        # Transport-specific fields live in a stack switched by the transport selector.
        self._transport = QComboBox()
        self._transport.addItems(["MLLP", "File"])
        self._transport.currentIndexChanged.connect(self._on_transport_changed)

        self._host = QLineEdit("127.0.0.1")
        self._port = QSpinBox()
        self._port.setRange(1, 65535)
        self._port.setValue(2575)
        self._expect = QComboBox()
        self._expect.addItems([_ACCEPT, _REJECT, _NONE])
        mllp_page = QWidget()
        mllp_form = QFormLayout(mllp_page)
        mllp_form.addRow("Host:", self._host)
        mllp_form.addRow("Port:", self._port)
        mllp_form.addRow("Expect:", self._expect)

        self._dir = QLineEdit("./harness_io/in")
        file_page = QWidget()
        file_form = QFormLayout(file_page)
        file_form.addRow("Directory:", self._dir)

        self._stack = QStackedWidget()
        self._stack.addWidget(mllp_page)
        self._stack.addWidget(file_page)

        self._send_btn = QPushButton("Send")
        self._send_btn.clicked.connect(self._send)

        top = QHBoxLayout()
        top.addWidget(QLabel("Transport:"))
        top.addWidget(self._transport)
        top.addWidget(self._preset)
        top.addStretch(1)
        top.addWidget(self._send_btn)

        self._results = ConfigurableTable(_COLUMNS, settings_key="harness/compose")

        layout = QVBoxLayout(self)
        layout.addLayout(top)
        layout.addWidget(self._editor, stretch=2)
        layout.addWidget(self._stack)
        layout.addWidget(self._results, stretch=1)

    def _apply_preset(self, index: int) -> None:
        text = {
            1: _core.generate_message("ADT", "A01", 1).replace("\r", "\n"),
            2: _NO_MSH,
            3: _BAD_VERSION,
            4: "",
        }.get(index)
        if text is not None:
            self._editor.setPlainText(text)
        self._preset.setCurrentIndex(0)  # reset the menu label

    def _on_transport_changed(self, index: int) -> None:
        self._stack.setCurrentIndex(index)

    def _send(self) -> None:
        if self._worker is not None:
            return
        raw = normalize(self._editor.toPlainText())
        if not raw.strip():
            self._append("—", "—", "no", "nothing to send")
            return
        code, trigger, control_id = self._peek(raw)
        item = SendItem(1, code, trigger, control_id, raw)

        self._thread = QThread(self)
        if self._transport.currentText() == "MLLP":
            self._pending_expect = self._expect.currentText()
            worker: SendWorker | FileDropWorker = SendWorker(
                self._host.text().strip(),
                self._port.value(),
                [item],
                timeout=10.0,
                rate=0.0,
                expect_ack=self._pending_expect != _NONE,
            )
            worker.result.connect(self._on_mllp_result)
        else:
            worker = FileDropWorker(self._dir.text().strip(), [item], rate=0.0)
            worker.result.connect(self._on_file_result)
        worker.finished.connect(self._on_finished)
        self._worker = worker
        worker.moveToThread(self._thread)
        self._thread.started.connect(worker.run)
        self._thread.start()
        self._send_btn.setEnabled(False)

    @staticmethod
    def _peek(raw: str) -> tuple[str, str, str]:
        try:
            peek = Peek.parse(raw)
            return peek.message_code or "?", peek.trigger_event or "", peek.control_id or "compose"
        except HL7PeekError:
            return "?", "", "compose"

    def _on_mllp_result(self, res: SendResult) -> None:
        expect = self._pending_expect
        if expect == _NONE:
            ok = res.ack_code == "(none)"
        elif expect == _ACCEPT:
            ok = res.ack_code in _ACCEPT_CODES
        else:
            ok = res.ack_code in _REJECT_CODES
        self._append("MLLP", res.ack_code, "yes" if ok else "no", res.error)

    def _on_file_result(self, res: DropResult) -> None:
        self._append(
            "File", res.filename or "—", "no" if res.error else "yes", res.error, expected="—"
        )

    def _on_finished(self) -> None:
        if self._thread is not None:
            self._thread.quit()
            self._thread.wait()
        self._worker = None
        self._thread = None
        self._send_btn.setEnabled(True)

    def shutdown(self) -> None:
        """Stop and join the worker thread so the window can close cleanly."""
        if self._worker is not None:
            self._worker.stop()
        if self._thread is not None:
            self._thread.quit()
            if not self._thread.wait(6000):
                self._thread.terminate()
                self._thread.wait()
            self._thread = None
        self._worker = None

    def _append(
        self, transport: str, result: str, ok: str, error: str, *, expected: str | None = None
    ) -> None:
        row = self._results.rowCount()
        self._results.insertRow(row)
        expected_label = expected if expected is not None else self._pending_expect
        values = [
            datetime.now().strftime("%H:%M:%S"),
            transport,
            result,
            expected_label,
            ok,
            error,
        ]
        for col, value in enumerate(values):
            self._results.setItem(row, col, QTableWidgetItem(value))
