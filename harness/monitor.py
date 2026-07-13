# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Monitor tab: connect to a running engine and observe what it actually did with traffic.

The harness's other tabs only see the transport edge (an ACK, a file). This tab closes the loop
by reading the engine's own API ([`EngineClient`][messagefoundry.apiclient.EngineClient]):
live queue/connection stats, the message store with per-message disposition + delivery trail, and
the dead-letter queue (with replay). It also drives a `config/reload`.

Threading split (CLAUDE.md §10): the **background** stats/connections/dead-letter poll runs off the
GUI thread in :class:`MonitorPoller` (a slow/unreachable engine must never freeze the UI), and
emits a snapshot via signal. **User-initiated** calls (login, message browsing/detail, replay,
reload, connection control) run briefly on the GUI thread. It reuses the
:class:`~harness._console_widgets.MessagesPanel` / :class:`~harness._console_widgets.MessageDetailPanel`
view widgets, rehomed here from the retired desktop console (BACKLOG #103).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from PySide6.QtCore import QMetaObject, QObject, Qt, QThread, QTimer, Signal, Slot
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSplitter,
    QStackedWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from messagefoundry.api.models import ConnectionRow, DeadLetterRow
from messagefoundry.apiclient import ApiError, EngineClient
from harness._console_widgets import (
    ConfigurableTable,
    MessageDetailPanel,
    MessagesPanel,
    fmt_ts,
)
from harness._login import LoginDialog

_DEFAULT_URL = "http://127.0.0.1:8765"
_POLL_INTERVAL_MS = 1500

_LIVE_COLUMNS = [
    "Name",
    "Role",
    "Status",
    "Method",
    "Queue",
    "# Read",
    "# Written",
    "# Errored",
    "Peer",
    "Port",
]
_DEAD_COLUMNS = ["Failed at", "Channel", "Destination", "Attempts", "Control ID", "Type", "Error"]

# (role, channel_id, destination) identifies a connections row for control actions.
_RowKey = tuple[str, str, str]


def _fmt_int(n: int | None) -> str:
    return "—" if n is None else str(n)


@dataclass
class MonitorSnapshot:
    """One off-thread poll of the engine's observable state."""

    stats: dict[str, int]
    connections: list[ConnectionRow]
    dead_letters: list[DeadLetterRow]


class MonitorPoller(QObject):
    """Polls stats/connections/dead-letters on a worker thread and emits a snapshot each tick.

    Built on the GUI thread, then ``moveToThread``'d; :meth:`start`/:meth:`stop` run in the
    worker's own event loop (which drives the :class:`QTimer`), so a slow or dead engine blocks
    only this thread, never the UI. It owns a private :class:`EngineClient` so it never shares a
    connection pool with the GUI-thread client.
    """

    snapshot = Signal(object)  # MonitorSnapshot
    failed = Signal(str)

    def __init__(
        self,
        base_url: str,
        token: str | None,
        *,
        interval_ms: int = _POLL_INTERVAL_MS,
        allow_insecure: bool = False,
        timeout: float = 3.0,
    ) -> None:
        super().__init__()
        self._base_url = base_url
        self._token = token
        self._interval_ms = interval_ms
        self._allow_insecure = allow_insecure
        self._timeout = timeout
        self._client: EngineClient | None = None
        self._timer: QTimer | None = None
        self._cancelled = False  # set from the GUI thread to abandon an in-flight poll (low-25)

    @Slot()
    def start(self) -> None:
        try:
            self._client = EngineClient(
                self._base_url, timeout=self._timeout, allow_insecure=self._allow_insecure
            )
            if self._token:
                self._client.set_token(self._token)
        except ApiError as exc:
            if self._client is not None:  # don't leak the httpx pool if set_token() failed
                self._client.close()
                self._client = None
            self.failed.emit(str(exc))
            return
        timer = QTimer(self)
        timer.timeout.connect(self._poll)
        timer.start(self._interval_ms)
        self._timer = timer
        self._poll()

    def request_cancel(self) -> None:
        """Signal an in-flight poll to abandon its remaining calls. Set from the GUI thread *before*
        the blocking ``stop()`` so shutdown waits at most for the one call already on the wire, not
        the full three-call cycle (the httpx timeout is per-phase, so a hung call can far exceed the
        nominal budget) — review low-25. A bare bool is safe to flip across threads under the GIL."""
        self._cancelled = True

    @Slot()
    def stop(self) -> None:
        self._cancelled = True
        if self._timer is not None:
            self._timer.stop()
            self._timer = None
        if self._client is not None:
            self._client.close()
            self._client = None

    def _poll(self) -> None:
        client = self._client
        if client is None or self._cancelled:
            return
        try:
            stats = client.stats().outbox_by_status
            if self._cancelled:
                return
            connections = client.connections()
            if self._cancelled:
                return
            dead_letters = client.list_dead_letters(limit=200).dead_letters
        except ApiError as exc:
            self.failed.emit(str(exc))
            return
        if self._cancelled:
            return
        self.snapshot.emit(
            MonitorSnapshot(stats=stats, connections=connections, dead_letters=dead_letters)
        )


class MonitorPanel(QWidget):
    """Connect/login bar over a stacked body: a disconnected placeholder, or the live view."""

    def __init__(self, *, allow_insecure: bool = False) -> None:
        super().__init__()
        self._allow_insecure = allow_insecure
        self._client: EngineClient | None = None
        self._thread: QThread | None = None
        self._poller: MonitorPoller | None = None

        # Sub-widgets of the connected view (rebuilt per connect, so they bind the live client).
        self._stats: QLabel | None = None
        self._live_table: ConfigurableTable | None = None
        self._dead_table: ConfigurableTable | None = None
        self._messages: MessagesPanel | None = None
        self._detail: MessageDetailPanel | None = None

        self._url = QLineEdit(_DEFAULT_URL)
        self._connect_btn = QPushButton("Connect")
        self._connect_btn.clicked.connect(self._toggle_connect)
        self._reload_btn = QPushButton("Reload config")
        self._reload_btn.setEnabled(False)
        self._reload_btn.clicked.connect(self._reload_config)
        self._status = QLabel("disconnected")

        bar = QHBoxLayout()
        bar.addWidget(QLabel("Engine:"))
        bar.addWidget(self._url, stretch=1)
        bar.addWidget(self._connect_btn)
        bar.addWidget(self._reload_btn)

        self._body = QStackedWidget()
        placeholder = QLabel("Not connected. Enter the engine API URL and press Connect.")
        placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._body.addWidget(placeholder)  # index 0

        layout = QVBoxLayout(self)
        layout.addLayout(bar)
        layout.addWidget(self._body, stretch=1)
        layout.addWidget(self._status)

    # --- connect / disconnect ------------------------------------------------

    def _toggle_connect(self) -> None:
        if self._client is not None:
            self._disconnect()
        else:
            self._connect()

    def _connect(self) -> None:
        url = self._url.text().strip()
        try:
            client = EngineClient(url, timeout=4.0, allow_insecure=self._allow_insecure)
            client.health()  # reachable?
        except ApiError as exc:
            self._set_status(str(exc), error=True)
            return
        if not self._ensure_auth(client):
            client.close()
            return

        self._client = client
        inner = self._build_inner()
        self._body.addWidget(inner)
        self._body.setCurrentWidget(inner)
        self._start_poller()

        self._connect_btn.setText("Disconnect")
        self._reload_btn.setEnabled(True)
        self._url.setEnabled(False)
        user = client.current_user
        who = f"{user.username} ({', '.join(user.roles) or 'no roles'})" if user else "no-auth"
        self._set_status(f"connected to {url} as {who}")

    def _ensure_auth(self, client: EngineClient) -> bool:
        """Return True if usable: a no-auth engine answers ``/auth/me`` directly; an authed one
        401/403s, so prompt sign-in via the :class:`LoginDialog`."""
        try:
            client.me()
            return True
        except ApiError as exc:
            if exc.status not in (401, 403):
                self._set_status(str(exc), error=True)
                return False
        dialog = LoginDialog(client, self)
        if not dialog.exec():
            self._set_status("sign-in cancelled")
            return False
        if dialog.must_change_password:
            # The token works but is restricted to the password-change routes, so every poll/action
            # would 403. Don't connect with it — the web console is where you rotate the password.
            self._set_status(
                "Account must change its password before use — do that in the web console first.",
                error=True,
            )
            return False
        return client.token is not None

    def _disconnect(self) -> None:
        self._stop_poller()
        if self._client is not None:
            try:
                self._client.logout()
            except ApiError:
                pass
            self._client.close()
            self._client = None
        inner = self._body.widget(1)
        if inner is not None:
            self._body.removeWidget(inner)
            inner.deleteLater()
        self._stats = self._live_table = self._dead_table = None
        self._messages = self._detail = None
        self._body.setCurrentIndex(0)
        self._connect_btn.setText("Connect")
        self._reload_btn.setEnabled(False)
        self._url.setEnabled(True)
        self._set_status("disconnected")

    def shutdown(self) -> None:
        """Stop the worker thread cleanly (called by the window on close)."""
        if self._client is not None:
            self._disconnect()

    # --- poller lifecycle ----------------------------------------------------

    def _start_poller(self) -> None:
        assert self._client is not None
        thread = QThread(self)
        # Short per-phase httpx timeout. _poll() makes 3 sequential calls; the timeout is per-phase
        # (connect/read/write), so a single hung call can exceed it — _stop_poller therefore also
        # cancels (low-25) so shutdown waits at most for the one call already on the wire.
        poller = MonitorPoller(
            self._client.base_url,
            self._client.token,
            allow_insecure=self._allow_insecure,
            timeout=1.5,
        )
        poller.moveToThread(thread)
        thread.started.connect(poller.start)
        poller.snapshot.connect(self._on_snapshot)
        poller.failed.connect(self._on_poll_failed)
        self._thread = thread
        self._poller = poller
        thread.start()

    def _stop_poller(self) -> None:
        poller, thread = self._poller, self._thread
        self._poller = self._thread = None
        if poller is not None:
            # Cancel first (from this GUI thread) so an in-flight _poll abandons its remaining calls;
            # then the blocking stop() runs on the worker, stopping its QTimer and closing its
            # EngineClient *before* we quit the loop. A plain QueuedConnection races quit() and is
            # almost always skipped (the loop exits before draining the posted slot), leaking the
            # httpx pool. Safe from deadlock because sender/receiver are always different threads.
            poller.request_cancel()
            QMetaObject.invokeMethod(poller, "stop", Qt.ConnectionType.BlockingQueuedConnection)
        if thread is not None:
            thread.quit()
            if not thread.wait(8000):  # stop() already released resources; ensure the thread exits
                thread.terminate()
                thread.wait()

    # --- connected view ------------------------------------------------------

    def _build_inner(self) -> QWidget:
        assert self._client is not None
        tabs = QTabWidget()

        # Live: stats summary + read-only connections table + inbound/outbound control.
        self._stats = QLabel("…")
        self._live_table = ConfigurableTable(_LIVE_COLUMNS, settings_key="harness/monitor/live")
        start = QPushButton("Start")
        stop = QPushButton("Stop")
        restart = QPushButton("Restart")
        purge = QPushButton("Purge")
        start.clicked.connect(lambda: self._inbound_action(self._client.start_connection))
        stop.clicked.connect(lambda: self._inbound_action(self._client.stop_connection))
        restart.clicked.connect(lambda: self._inbound_action(self._client.restart_connection))
        purge.clicked.connect(self._purge_outbound)
        live_buttons = QHBoxLayout()
        for btn in (start, stop, restart, purge):
            live_buttons.addWidget(btn)
        live_buttons.addStretch(1)
        live = QWidget()
        live_layout = QVBoxLayout(live)
        live_layout.addWidget(self._stats)
        live_layout.addLayout(live_buttons)
        live_layout.addWidget(self._live_table, stretch=1)
        tabs.addTab(live, "Live")

        # Messages: reuse the console's filter list + detail pane (user-initiated, GUI thread).
        self._messages = MessagesPanel(self._client)
        self._detail = MessageDetailPanel(self._client)
        self._messages.message_selected.connect(self._detail.load)
        self._messages.error.connect(lambda m: self._set_status(m, error=True))
        self._detail.error.connect(lambda m: self._set_status(m, error=True))
        self._detail.changed.connect(self._messages.refresh)
        msg_split = QSplitter(Qt.Orientation.Horizontal)
        msg_split.addWidget(self._messages)
        msg_split.addWidget(self._detail)
        msg_split.setStretchFactor(0, 1)
        msg_split.setStretchFactor(1, 1)
        tabs.addTab(msg_split, "Messages")
        self._messages.refresh()

        # Dead letters: read-only table (snapshot-fed) + scoped/bulk replay.
        self._dead_table = ConfigurableTable(_DEAD_COLUMNS, settings_key="harness/monitor/dead")
        replay_sel = QPushButton("Replay selected destination")
        replay_all = QPushButton("Replay all")
        replay_sel.clicked.connect(self._replay_selected_dead)
        replay_all.clicked.connect(self._replay_all_dead)
        dead_buttons = QHBoxLayout()
        dead_buttons.addWidget(replay_sel)
        dead_buttons.addWidget(replay_all)
        dead_buttons.addStretch(1)
        dead = QWidget()
        dead_layout = QVBoxLayout(dead)
        dead_layout.addLayout(dead_buttons)
        dead_layout.addWidget(self._dead_table, stretch=1)
        tabs.addTab(dead, "Dead Letters")

        return tabs

    @Slot(object)
    def _on_snapshot(self, snapshot: MonitorSnapshot) -> None:
        if self._stats is None or self._live_table is None or self._dead_table is None:
            return  # disconnected mid-flight
        ordered = sorted(snapshot.stats.items())
        self._stats.setText(
            "outbox — " + " · ".join(f"{k}: {v}" for k, v in ordered)
            if ordered
            else "outbox — (empty)"
        )

        table = self._live_table
        table.begin_populate()
        table.setRowCount(len(snapshot.connections))
        for r, row in enumerate(snapshot.connections):
            key: _RowKey = (row.role, row.channel_id, row.destination or "")
            cells = [
                row.name,
                row.role,
                row.status,
                row.method,
                _fmt_int(row.queue_depth),
                _fmt_int(row.read),
                _fmt_int(row.written),
                _fmt_int(row.errored),
                row.peer or "",
                _fmt_int(row.port),
            ]
            for c, text in enumerate(cells):
                item = QTableWidgetItem(text)
                if c == 0:
                    item.setData(Qt.ItemDataRole.UserRole, key)
                table.setItem(r, c, item)
        table.end_populate()

        dead = self._dead_table
        dead.begin_populate()
        dead.setRowCount(len(snapshot.dead_letters))
        for r, dl in enumerate(snapshot.dead_letters):
            cells = [
                fmt_ts(dl.failed_at),
                dl.channel_id,
                dl.destination_name,
                str(dl.attempts),
                dl.control_id or "",
                dl.message_type or "",
                dl.last_error or "",
            ]
            for c, text in enumerate(cells):
                item = QTableWidgetItem(text)
                if c == 0:
                    item.setData(Qt.ItemDataRole.UserRole, (dl.channel_id, dl.destination_name))
                dead.setItem(r, c, item)
        dead.end_populate()

    @Slot(str)
    def _on_poll_failed(self, message: str) -> None:
        self._set_status(f"poll failed: {message}", error=True)

    # --- actions (GUI thread) ------------------------------------------------

    def _selected_live_key(self) -> _RowKey | None:
        table = self._live_table
        if table is None:
            return None
        model = table.selectionModel()
        rows = model.selectedRows() if model else []
        if not rows:
            return None
        item = table.item(rows[0].row(), 0)
        data = item.data(Qt.ItemDataRole.UserRole) if item else None
        return data if isinstance(data, tuple) else None

    def _inbound_action(self, action: Callable[[str], None]) -> None:
        key = self._selected_live_key()
        if key is None or key[0] != "source":
            self._set_status("Select an inbound (source) row.", error=True)
            return
        try:
            action(key[1])
        except ApiError as exc:
            self._set_status(str(exc), error=True)

    def _purge_outbound(self) -> None:
        key = self._selected_live_key()
        if key is None or key[0] != "destination" or not key[2]:
            self._set_status("Select an outbound (destination) row to purge.", error=True)
            return
        assert self._client is not None
        try:
            result = self._client.purge_connection(key[2], "all")
        except ApiError as exc:
            self._set_status(str(exc), error=True)
            return
        self._set_status(f"purged {result.cancelled} queued delivery(ies) from {key[2]}")

    def _replay_selected_dead(self) -> None:
        table = self._dead_table
        if table is None:
            return
        model = table.selectionModel()
        rows = model.selectedRows() if model else []
        if not rows:
            self._set_status("Select a dead-letter row.", error=True)
            return
        item = table.item(rows[0].row(), 0)
        data = item.data(Qt.ItemDataRole.UserRole) if item else None
        if not isinstance(data, tuple):
            return
        channel_id, destination = data
        self._do_replay(channel_id=channel_id, destination_name=destination)

    def _replay_all_dead(self) -> None:
        if (
            QMessageBox.question(
                self,
                "Replay all dead letters",
                "Re-queue every dead-lettered delivery for redelivery?",
            )
            != QMessageBox.StandardButton.Yes
        ):
            return
        self._do_replay(channel_id=None, destination_name=None)

    def _do_replay(self, *, channel_id: str | None, destination_name: str | None) -> None:
        assert self._client is not None
        try:
            result = self._client.replay_dead_letters(
                channel_id=channel_id, destination_name=destination_name
            )
        except ApiError as exc:
            self._set_status(str(exc), error=True)
            return
        self._set_status(f"re-queued {result.requeued} dead-lettered delivery(ies)")

    def _reload_config(self) -> None:
        assert self._client is not None
        try:
            result = self._client.reload_config()
        except ApiError as exc:
            self._set_status(str(exc), error=True)
            return
        self._set_status(
            f"reloaded: {result.inbound} inbound · {result.outbound} outbound · "
            f"{result.routers} routers · {result.handlers} handlers"
        )

    # --- status --------------------------------------------------------------

    def _set_status(self, message: str, *, error: bool = False) -> None:
        self._status.setStyleSheet("color: #c62828;" if error else "")
        self._status.setText(message)
