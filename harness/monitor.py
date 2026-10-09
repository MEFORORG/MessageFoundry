# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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

import contextlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from PySide6.QtCore import QMetaObject, QObject, Qt, QThread, QTimer, Signal, Slot
from PySide6.QtWidgets import (
    QHBoxLayout,
    QInputDialog,
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

from harness._console_widgets import (
    ConfigurableTable,
    MessageDetailPanel,
    MessagesPanel,
    fmt_ts,
)
from harness._login import LoginDialog
from messagefoundry.api.models import ConnectionRow, DeadLetterRow, PendingApprovalResponse
from messagefoundry.api_tls_source import GENERATED_CERT_NAME
from messagefoundry.apiclient import ApiError, EngineClient

# https because the engine always serves TLS (ADR 0172). A stock engine's certificate is one it minted
# itself and no trust store holds it, so the bar beside the URL takes the PEM to pin.
_DEFAULT_URL = "https://127.0.0.1:8765"
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
        cacert: str | None = None,
    ) -> None:
        super().__init__()
        self._base_url = base_url
        self._token = token
        self._interval_ms = interval_ms
        self._allow_insecure = allow_insecure
        self._cacert = cacert
        self._timeout = timeout
        self._client: EngineClient | None = None
        self._timer: QTimer | None = None
        self._cancelled = False  # set from the GUI thread to abandon an in-flight poll (low-25)

    @Slot()
    def start(self) -> None:
        try:
            self._client = EngineClient(
                self._base_url,
                timeout=self._timeout,
                allow_insecure=self._allow_insecure,
                cacert=self._cacert,
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


def _deadline_sentence(expires_at: float | None) -> str:
    """The temporary password's deadline as a sentence to append, or ``""`` when there is none.

    BACKLOG #2009 (ASVS 6.4.5). The engine's login response already carries the instant its sign-in
    gate refuses on, so the harness states it as the web console does: the same UTC stamp and the
    same advice. A deadline the clock cannot render states nothing rather than raising."""
    if expires_at is None:
        return ""
    try:
        when = datetime.fromtimestamp(expires_at, UTC).strftime("%Y-%m-%d %H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return ""
    return (
        f" Your temporary password stops working at {when}."
        " After that, ask an administrator to reset it."
    )


class MonitorPanel(QWidget):
    """Connect/login bar over a stacked body: a disconnected placeholder, or the live view."""

    def __init__(self, *, allow_insecure: bool = False) -> None:
        super().__init__()
        self._allow_insecure = allow_insecure
        self._client: EngineClient | None = None
        # The handler-less reader the message panels use off the GUI thread (see _build_inner).
        self._poll_client: EngineClient | None = None
        self._thread: QThread | None = None
        self._poller: MonitorPoller | None = None

        # Sub-widgets of the connected view (rebuilt per connect, so they bind the live client).
        self._stats: QLabel | None = None
        self._live_table: ConfigurableTable | None = None
        self._dead_table: ConfigurableTable | None = None
        self._messages: MessagesPanel | None = None
        self._detail: MessageDetailPanel | None = None

        self._url = QLineEdit(_DEFAULT_URL)
        self._cacert = QLineEdit()
        self._cacert.setPlaceholderText(f"{GENERATED_CERT_NAME} (blank = OS trust store)")
        self._cacert.setToolTip(
            f"PEM to trust for the engine API. A stock engine mints {GENERATED_CERT_NAME} beside "
            "its store database."
        )
        self._connect_btn = QPushButton("Connect")
        self._connect_btn.clicked.connect(self._toggle_connect)
        self._reload_btn = QPushButton("Reload config")
        self._reload_btn.setEnabled(False)
        self._reload_btn.clicked.connect(self._reload_config)
        self._status = QLabel("disconnected")
        # Plain text: the status carries the engine's own error and hold text, and a QLabel's
        # default AutoText would render a string that looks like HTML as rich text (ASVS 1.1.2).
        self._status.setTextFormat(Qt.TextFormat.PlainText)

        bar = QHBoxLayout()
        bar.addWidget(QLabel("Engine:"))
        bar.addWidget(self._url, stretch=1)
        bar.addWidget(QLabel("Cert:"))
        bar.addWidget(self._cacert, stretch=1)
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
            client = EngineClient(
                url, timeout=4.0, allow_insecure=self._allow_insecure, cacert=self._cacert_path()
            )
        except ApiError as exc:
            self._set_status(str(exc), error=True)
            return
        try:
            client.health()  # reachable?
        except ApiError as exc:
            # An unverified minted cert fails here on a first connect, so close the pool it opened.
            client.close()
            self._set_status(str(exc), error=True)
            return
        if not self._ensure_auth(client):
            # A must-change sign-in leaves the client holding a session it will never use. End it
            # before dropping the client, or it stays live until it expires (BACKLOG #2091). The
            # engine lets a must-change session reach /auth/logout.
            if client.token is not None:
                with contextlib.suppress(ApiError):
                    client.logout()
            client.close()
            return

        # Built before the panel adopts the client: it reloads the pinned certificate and can fail,
        # and a failure must leave the panel disconnected, not half-connected.
        try:
            poll_client = client.for_polling()
        except ApiError as exc:
            # End the session the sign-in just made before dropping the client, as the must-change
            # refusal above does, or it stays live until it expires (BACKLOG #2091).
            if client.token is not None:
                with contextlib.suppress(ApiError):
                    client.logout()
            client.close()
            self._set_status(str(exc), error=True)
            return
        self._client = client
        self._poll_client = poll_client
        # Vault BACKLOG #2625: reload and purge take a step-up proof bound to their action, which
        # a sign-in does not mint, so answer the engine's step-up refusal with a re-proof.
        client.set_step_up_handler(self._step_up)
        inner = self._build_inner()
        self._body.addWidget(inner)
        self._body.setCurrentWidget(inner)
        self._start_poller()

        self._connect_btn.setText("Disconnect")
        self._reload_btn.setEnabled(True)
        self._url.setEnabled(False)
        self._cacert.setEnabled(False)
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
                "Account must change its password before use — do that in the web console first."
                + _deadline_sentence(dialog.credential_expires_at),
                error=True,
            )
            return False
        return client.token is not None

    def _step_up(self) -> bool:
        """Answer a step-up refusal (403 + ``X-Step-Up-Required``): ask for the password, masked,
        and re-prove it. ``EngineClient.reauth`` sends the action the refusal named as ``purpose``
        and adopts the re-keyed session, and the client then retries the call once.

        The re-proof rotates the session, so the poller's copy of the old token is dead: it is
        restarted on the new one. The password is passed straight to ``reauth`` and kept nowhere."""
        client = self._client
        # A dialog belongs on the GUI thread. Every worker read goes through the polling client,
        # which has no handler, so this is a second guard: refuse rather than build Qt off-thread.
        if client is None or QThread.currentThread() is not self.thread():
            return False
        password, ok = QInputDialog.getText(
            self,
            "Confirm it's you",
            "This action needs your password again:",
            QLineEdit.EchoMode.Password,
        )
        if not ok or not password:
            return False
        # A refused re-proof raises out of the action that asked for it, so the action's own error
        # report names the real cause ("re-verification failed") rather than the original 403.
        client.reauth(password)
        self._stop_poller()
        self._start_poller()
        return True

    def _disconnect(self) -> None:
        self._stop_poller()
        # Stop the panels' background readers first, so none is mid-call on a closed client and no
        # late result reaches a widget that is about to go.
        for panel in (self._messages, self._detail):
            if panel is not None:
                panel.stop()
        if self._poll_client is not None:
            self._poll_client.close()
            self._poll_client = None
        if self._client is not None:
            with contextlib.suppress(ApiError):
                self._client.logout()
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
        self._cacert.setEnabled(True)
        self._set_status("disconnected")

    def _cacert_path(self) -> str | None:
        """The pinned PEM, or None (blank field) to verify against the OS trust store."""
        return self._cacert.text().strip() or None

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
            cacert=self._cacert_path(),
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
        self._stats.setTextFormat(Qt.TextFormat.PlainText)  # the engine names the stat keys
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
        # Their reads run on worker threads, so they get a polling client: it shares the token but
        # carries no step-up handler, so a refusal there can never open a Qt dialog off the GUI
        # thread (vault BACKLOG #2625 gave the main client one).
        self._messages = MessagesPanel(self._client, poll_client=self._poll_client)
        self._detail = MessageDetailPanel(self._client, poll_client=self._poll_client)
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
        if isinstance(result, PendingApprovalResponse):
            self._set_held_status(result)
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
        if isinstance(result, PendingApprovalResponse):
            self._set_held_status(result)
            return
        self._set_status(f"re-queued {result.requeued} dead-lettered delivery(ies)")

    def _reload_config(self) -> None:
        assert self._client is not None
        try:
            result = self._client.reload_config()
        except ApiError as exc:
            self._set_status(str(exc), error=True)
            return
        if isinstance(result, PendingApprovalResponse):
            self._set_held_status(result)
            return
        self._set_status(
            f"reloaded: {result.inbound} inbound · {result.outbound} outbound · "
            f"{result.routers} routers · {result.handlers} handlers"
        )

    # --- status --------------------------------------------------------------

    def _set_held_status(self, held: PendingApprovalResponse) -> None:
        """Report a dual-control hold (ASVS 2.3.5): the engine accepted the request and did NOT run
        it, so this is neither a failure nor a completed action. A distinct second approver must
        release it, and the requester cannot release their own."""
        self._set_status(
            f"{held.operation} held for a second approver (approval {held.approval_id}): "
            f"{held.detail}"
        )

    def _set_status(self, message: str, *, error: bool = False) -> None:
        self._status.setStyleSheet("color: #c62828;" if error else "")
        self._status.setText(message)
