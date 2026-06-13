"""Engine Status page: engine-process and database health.

Cheap fields refresh on the auto-refresh timer; the database integrity check is on-demand
(``PRAGMA quick_check`` can be slow on a large DB).
"""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from messagefoundry.console import service_control
from messagefoundry.console.client import ApiError, EngineClient

_ENGINE_ROWS = ["Reachable", "Version", "Uptime", "PID", "Channels", "Queue"]
_DB_ROWS = ["Path", "Size", "Free disk", "Journal mode", "Messages", "Events", "Audit entries"]


def _human_bytes(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def _human_uptime(seconds: float) -> str:
    s = int(seconds)
    days, s = divmod(s, 86400)
    hours, s = divmod(s, 3600)
    minutes, _ = divmod(s, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours or days:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    return " ".join(parts)


class EngineStatusPage(QWidget):
    """Read-only engine + database health, plus an on-demand integrity check."""

    error = Signal(str)

    def __init__(self, client: EngineClient, *, service_name: str = "MessageFoundry") -> None:
        super().__init__()
        self._client = client
        self._service_name = service_name
        self._engine = {row: QLabel("—") for row in _ENGINE_ROWS}
        self._db = {row: QLabel("—") for row in _DB_ROWS}

        engine_box = QGroupBox("Engine")
        engine_form = QFormLayout(engine_box)
        for row, label in self._engine.items():
            engine_form.addRow(f"{row}:", label)

        db_box = QGroupBox("Database")
        db_form = QFormLayout(db_box)
        for row, label in self._db.items():
            db_form.addRow(f"{row}:", label)

        # Windows service control (sc/net via UAC) — same-machine only; disabled in dev/no-service.
        service_box = QGroupBox(f"Service ({service_name})")
        self._service_state = QLabel("—")
        self._svc_start = QPushButton("Start")
        self._svc_stop = QPushButton("Stop")
        self._svc_restart = QPushButton("Restart")
        self._svc_install = QPushButton("Install service…")
        self._svc_install.setVisible(False)  # only shown when the service is not installed
        self._svc_start.clicked.connect(lambda: self._control("start"))
        self._svc_stop.clicked.connect(lambda: self._control("stop"))
        self._svc_restart.clicked.connect(lambda: self._control("restart"))
        self._svc_install.clicked.connect(self._install_service)
        self._svc_result = QLabel("")
        service_controls = QHBoxLayout()
        service_controls.addWidget(QLabel("State:"))
        service_controls.addWidget(self._service_state)
        service_controls.addStretch(1)
        service_controls.addWidget(self._svc_install)
        service_controls.addWidget(self._svc_start)
        service_controls.addWidget(self._svc_stop)
        service_controls.addWidget(self._svc_restart)
        service_layout = QVBoxLayout(service_box)
        service_layout.addLayout(service_controls)
        service_layout.addWidget(self._svc_result)

        self._integrity_btn = QPushButton("Run integrity check")
        self._integrity_btn.clicked.connect(self._run_integrity)
        self._integrity_result = QLabel("")
        integrity = QHBoxLayout()
        integrity.addWidget(self._integrity_btn)
        integrity.addWidget(self._integrity_result, stretch=1)

        layout = QVBoxLayout(self)
        layout.addWidget(engine_box)
        layout.addWidget(db_box)
        layout.addWidget(service_box)
        layout.addLayout(integrity)
        layout.addStretch(1)

    def refresh(self) -> None:
        self._refresh_service()  # independent of the API — works even when the engine is down
        try:
            status = self._client.status()
        except ApiError as exc:
            self._engine["Reachable"].setText("no")
            self.error.emit(str(exc))
            return
        e = status.engine
        self._engine["Reachable"].setText("yes")
        self._engine["Version"].setText(e.version)
        self._engine["Uptime"].setText(_human_uptime(e.uptime_seconds))
        self._engine["PID"].setText(str(e.pid))
        self._engine["Channels"].setText(f"{e.channels_running} running / {e.channels_total} total")
        queue = ", ".join(f"{k}={v}" for k, v in sorted(e.outbox_by_status.items()))
        self._engine["Queue"].setText(queue or "empty")

        d = status.db
        self._db["Path"].setText(d.path)
        self._db["Size"].setText(_human_bytes(d.size_bytes))
        self._db["Free disk"].setText(_human_bytes(d.disk_free_bytes))
        self._db["Journal mode"].setText(d.journal_mode)
        self._db["Messages"].setText(str(d.messages))
        self._db["Events"].setText(str(d.events))
        self._db["Audit entries"].setText(str(d.audit))

    def reload(self) -> None:
        self.refresh()

    def _refresh_service(self) -> None:
        state = service_control.service_state(self._service_name)
        self._service_state.setText(state)
        # Only enable actions that make sense for the current state; all off in dev/no-service.
        self._svc_start.setEnabled(state == "stopped")
        self._svc_stop.setEnabled(state == "running")
        self._svc_restart.setEnabled(state == "running")
        self._svc_install.setVisible(state == "not installed")  # offer install only then

    def _install_service(self) -> None:
        script = service_control.install_script_path()
        if script is None:
            self._svc_result.setText("Could not find install-service.ps1 — run it manually.")
            return
        if not self._confirm_install():
            return
        if service_control.install_service(str(script)):
            self._svc_result.setText("Launching installer — approve the UAC prompt.")
        else:
            self._svc_result.setText("Service install is only available on Windows.")

    def _confirm_install(self) -> bool:
        reply = QMessageBox.question(
            self,
            "Install MessageFoundry service",
            "This will install MessageFoundry as a Windows service:\n\n"
            "• Downloads NSSM (the service wrapper) if it isn't already present\n"
            "• Registers the service to start automatically at boot\n"
            "• Requires administrator rights — Windows will show a UAC prompt\n"
            "• Runs in a PowerShell window so you can read the result\n\n"
            "Stop any console-mode engine first so they don't share ports.\n\nProceed?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        return reply == QMessageBox.StandardButton.Yes

    def _control(self, action: str) -> None:
        if not self._confirm_admin(action):
            return
        # The confirm dialog already told the user what's about to happen, and the State readout
        # reflects the result — so don't leave a lingering "requested..." message here.
        if service_control.control_service(action, self._service_name):
            self._svc_result.setText("")
        else:
            self._svc_result.setText("Service control is only available on Windows.")

    def _confirm_admin(self, action: str) -> bool:
        text = (
            f"This will {action} the '{self._service_name}' service, which requires administrator "
            "rights — Windows will show a UAC prompt."
        )
        if action in ("stop", "restart"):
            text += (
                "\n\nThe engine API drops briefly, so the Engine/Database panels will read "
                "'unreachable' until it's back."
            )
        text += "\n\nProceed?"
        reply = QMessageBox.question(
            self,
            f"{action.capitalize()} service",
            text,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        return reply == QMessageBox.StandardButton.Yes

    def _run_integrity(self) -> None:
        try:
            result = self._client.integrity_check()
        except ApiError as exc:
            self.error.emit(str(exc))
            return
        self._integrity_result.setText("✓ ok" if result.ok else f"✗ {result.detail}")
