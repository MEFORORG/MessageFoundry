"""The harness window: Send, Receive, and Monitor tabs."""

from __future__ import annotations

from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import QTabWidget, QVBoxLayout, QWidget

from harness.compose import ComposePanel
from harness.file_panel import FilePanel
from harness.monitor import MonitorPanel
from harness.receive import ReceivePanel
from harness.send import SendPanel


class HarnessWindow(QWidget):
    """Standalone HL7 test harness: generate + send messages (MLLP or file), receive + ACK them,
    and watch what a running engine did with them (dispositions, deliveries, dead letters)."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("MessageFoundry Test Harness")
        self.send_panel = SendPanel()
        self.receive_panel = ReceivePanel()
        self.file_panel = FilePanel()
        self.compose_panel = ComposePanel()
        self.monitor_panel = MonitorPanel()

        tabs = QTabWidget()
        tabs.addTab(self.send_panel, "Send")
        tabs.addTab(self.receive_panel, "Receive")
        tabs.addTab(self.file_panel, "File")
        tabs.addTab(self.compose_panel, "Compose")
        tabs.addTab(self.monitor_panel, "Monitor")

        layout = QVBoxLayout(self)
        layout.addWidget(tabs)

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802 (Qt override)
        # Stop every panel's background work (worker threads, the poller, the MLLP listener, the
        # folder-watch timer) before the widget tree is torn down — otherwise a still-running
        # QThread is destroyed mid-flight ("QThread: Destroyed while thread is still running").
        for panel in (
            self.monitor_panel,
            self.send_panel,
            self.file_panel,
            self.compose_panel,
            self.receive_panel,
        ):
            panel.shutdown()
        super().closeEvent(event)
