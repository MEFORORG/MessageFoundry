# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Engine Status page: engine-process, database, and active-passive cluster health.

All engine reads run **off the Qt main thread** (:class:`~messagefoundry.console._async.AsyncRunner`) and
apply on the main thread via the result slot, so a slow DB-backed read — e.g. ``/cluster/nodes`` while a
new primary is recovering during a failover — can't freeze the window. The database integrity check is
on-demand (``PRAGMA quick_check`` can run for many seconds on a large DB) and also off-thread.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QMessageBox,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from messagefoundry.api.models import ClusterNodeList, ClusterStatus, IntegrityResult, SystemStatus
from messagefoundry.console import service_control
from messagefoundry.console._async import AsyncRunner
from messagefoundry.console.client import ApiError, EngineClient

_ENGINE_ROWS = ["Reachable", "Version", "Uptime", "PID", "Channels", "Queue"]
_DB_ROWS = ["Path", "Size", "Free disk", "Journal mode", "Messages", "Events", "Audit entries"]
_NODE_COLS = ["Node", "Host", "PID", "Status", "Last seen", "Leader"]


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


def _ago(last_seen: float | None, now: float) -> str:
    if last_seen is None:
        return "—"
    delta = max(0, int(now - last_seen))
    return "just now" if delta < 1 else f"{delta}s ago"


@dataclass(frozen=True)
class _Snapshot:
    """One off-thread refresh result, applied on the main thread. ``error`` set ⇒ engine unreachable;
    ``cluster`` None ⇒ the cluster endpoints aren't available (older engine / not permitted)."""

    service_state: str
    status: SystemStatus | None
    cluster: tuple[ClusterStatus, ClusterNodeList] | None
    error: str | None


class EngineStatusPage(QWidget):
    """Read-only engine + database + cluster health, plus an on-demand integrity check."""

    error = Signal(str)

    def __init__(self, client: EngineClient, *, service_name: str = "MessageFoundry") -> None:
        super().__init__()
        self._client = client
        self._service_name = service_name
        self._runner = AsyncRunner(self)
        self._loading = False  # in-flight refresh guard (don't pile up during a slow call)
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

        # Active-passive cluster roster (Workstream G). Hidden until a /cluster read succeeds — a
        # single-node or older engine without the endpoints simply doesn't show it.
        self._cluster_box = QGroupBox("Cluster")
        self._cluster_box.setVisible(False)
        self._cl_mode = QLabel("—")
        self._cl_role = QLabel("—")
        self._cl_leader = QLabel("—")
        self._cl_lease = QLabel("—")
        cluster_form = QFormLayout()
        cluster_form.addRow("Mode:", self._cl_mode)
        cluster_form.addRow("This node:", self._cl_role)
        cluster_form.addRow("Leader:", self._cl_leader)
        cluster_form.addRow("Lease owner:", self._cl_lease)
        self._nodes = QTreeWidget()
        self._nodes.setColumnCount(len(_NODE_COLS))
        self._nodes.setHeaderLabels(_NODE_COLS)
        self._nodes.setRootIsDecorated(False)
        self._nodes.setUniformRowHeights(True)
        cluster_layout = QVBoxLayout(self._cluster_box)
        cluster_layout.addLayout(cluster_form)
        cluster_layout.addWidget(self._nodes)

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
        layout.addWidget(self._cluster_box)
        layout.addWidget(service_box)
        layout.addLayout(integrity)
        layout.addStretch(1)

    # --- refresh (off the main thread) ---------------------------------------

    def refresh(self) -> None:
        if self._loading:
            return  # a fetch is already in flight — don't pile up (e.g. during a slow failover)
        self._loading = True
        self._runner.submit(self._fetch, on_done=self._apply, on_error=self._on_error)

    def reload(self) -> None:
        self.refresh()

    def stop(self) -> None:
        """Stop the background runner (call on window close) so a late result can't touch dead widgets."""
        self._runner.stop()

    def _on_error(self, exc: BaseException) -> None:
        # Belt-and-suspenders: the reads in _fetch raise only ApiError (handled via the snapshot), but
        # an unexpected error must still clear the in-flight guard or the page wedges forever.
        self._loading = False
        self.error.emit(str(exc))

    def _fetch(self) -> _Snapshot:
        """Runs on a worker thread — only blocking I/O, no widget access."""
        svc = service_control.service_state(self._service_name)
        try:
            status = self._client.status()
        except ApiError as exc:
            return _Snapshot(svc, None, None, str(exc))
        cluster: tuple[ClusterStatus, ClusterNodeList] | None
        try:
            cluster = (self._client.cluster_status(), self._client.cluster_nodes())
        except ApiError:
            cluster = None  # endpoints not available / not permitted — keep the cluster box hidden
        return _Snapshot(svc, status, cluster, None)

    def _apply(self, snap: _Snapshot) -> None:
        """Runs on the main thread (result slot) — safe to touch widgets."""
        self._loading = False
        self._apply_service(snap.service_state)
        if snap.error is not None:
            self._engine["Reachable"].setText("no")
            self._cluster_box.setVisible(False)
            self.error.emit(snap.error)
            return
        assert snap.status is not None
        e = snap.status.engine
        self._engine["Reachable"].setText("yes")
        self._engine["Version"].setText(e.version)
        self._engine["Uptime"].setText(_human_uptime(e.uptime_seconds))
        self._engine["PID"].setText(str(e.pid))
        self._engine["Channels"].setText(f"{e.channels_running} running / {e.channels_total} total")
        queue = ", ".join(f"{k}={v}" for k, v in sorted(e.outbox_by_status.items()))
        self._engine["Queue"].setText(queue or "empty")

        d = snap.status.db
        self._db["Path"].setText(d.path)
        self._db["Size"].setText(_human_bytes(d.size_bytes))
        self._db["Free disk"].setText(_human_bytes(d.disk_free_bytes))
        self._db["Journal mode"].setText(d.journal_mode)
        self._db["Messages"].setText(str(d.messages))
        self._db["Events"].setText(str(d.events))
        self._db["Audit entries"].setText(str(d.audit))

        self._apply_cluster(snap.cluster)

    def _apply_cluster(self, cluster: tuple[ClusterStatus, ClusterNodeList] | None) -> None:
        if cluster is None:
            self._cluster_box.setVisible(False)
            return
        status, nodes = cluster
        self._cluster_box.setVisible(True)
        self._cl_mode.setText("clustered" if status.clustered else "single-node")
        self._cl_role.setText(f"{status.role} ({status.node_id})")
        self._cl_leader.setText(nodes.leader_node_id or "— (no live leader)")
        lease = nodes.lease_owner or "—"
        if nodes.lease_owner and nodes.lease_expires_at is not None:
            remaining = int(nodes.lease_expires_at - time.time())
            lease += f" (lease {'expired' if remaining < 0 else f'~{remaining}s left'})"
        self._cl_lease.setText(lease)

        now = time.time()
        self._nodes.clear()
        for n in nodes.nodes:
            item = QTreeWidgetItem(
                [
                    n.node_id,
                    n.host or "—",
                    str(n.pid) if n.pid is not None else "—",
                    n.status,
                    _ago(n.last_seen, now),
                    "✓ leader" if n.is_leader else "",
                ]
            )
            self._nodes.addTopLevelItem(item)
        for col in range(self._nodes.columnCount()):
            self._nodes.resizeColumnToContents(col)

    def _apply_service(self, state: str) -> None:
        self._service_state.setText(state)
        # Only enable actions that make sense for the current state; all off in dev/no-service.
        self._svc_start.setEnabled(state == "stopped")
        self._svc_stop.setEnabled(state == "running")
        self._svc_restart.setEnabled(state == "running")
        self._svc_install.setVisible(state == "not installed")  # offer install only then

    # --- service control (unchanged; same-machine sc/net via UAC) ------------

    def _install_service(self) -> None:
        script = service_control.install_script_path()
        if script is None:
            self._svc_result.setText("Could not find install-service.ps1 — run it manually.")
            return
        env = self._prompt_environment()
        if env is None:
            return  # cancelled or invalid — leave the page untouched
        if not self._confirm_install(env):
            return
        if service_control.install_service(str(script), env):
            self._svc_result.setText("Launching installer — approve the UAC prompt.")
        else:
            self._svc_result.setText("Service install is only available on Windows.")

    def _prompt_environment(self) -> str | None:
        """Ask which active environment the service should run as (ADR 0017: the operator chooses it
        explicitly — `serve` has no silent default). Returns the validated name, or None if the
        operator cancelled or entered an invalid name."""
        env, ok = QInputDialog.getText(
            self,
            "Active environment",
            "Which environment should the service run as?\n"
            "Selects environments/<name>.toml — e.g. dev, staging, prod, or a custom name.",
            text="prod",
        )
        if not ok:
            return None
        env = env.strip()
        if not service_control.is_safe_environment(env):
            QMessageBox.warning(
                self,
                "Invalid environment",
                "Use a simple name of letters, digits, '.', '_' or '-' "
                "(it selects environments/<name>.toml).",
            )
            return None
        return env

    def _confirm_install(self, env: str) -> bool:
        reply = QMessageBox.question(
            self,
            "Install MessageFoundry service",
            f"This will install MessageFoundry as a Windows service (environment: {env}):\n\n"
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

    # --- integrity check (off the main thread — quick_check can run for minutes) ---

    def _run_integrity(self) -> None:
        self._integrity_btn.setEnabled(False)
        self._integrity_result.setText("running…")
        self._runner.submit(
            self._client.integrity_check,
            on_done=self._apply_integrity,
            on_error=self._integrity_error,
        )

    def _apply_integrity(self, result: IntegrityResult) -> None:
        self._integrity_btn.setEnabled(True)
        self._integrity_result.setText("✓ ok" if result.ok else f"✗ {result.detail}")

    def _integrity_error(self, exc: BaseException) -> None:
        self._integrity_btn.setEnabled(True)
        self._integrity_result.setText("")
        self.error.emit(str(exc))
