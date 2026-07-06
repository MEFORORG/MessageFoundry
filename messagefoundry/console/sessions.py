# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Self-service active-session inventory dialog (the WP-10 console view).

Lists the signed-in user's active sessions (``GET /me/sessions``) and lets them revoke an individual
session or sign out everywhere else. The **current** session is flagged and cannot be revoked here —
that is what "Sign out" does — so this dialog never logs the user out. Calls are synchronous like the
other console dialogs (localhost, modal; see :mod:`messagefoundry.console.client`).
"""

from __future__ import annotations

from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from messagefoundry.api.auth_models import SessionInfo
from messagefoundry.console.client import ApiError, EngineClient
from messagefoundry.console.widgets import ERROR_COLOR, fmt_ts


class SessionsDialog(QDialog):
    """The user's active sessions with per-row revoke + "sign out everywhere else"."""

    def __init__(self, client: EngineClient, *, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Active sessions — MessageFoundry")
        self._client = client
        self._sessions: list[SessionInfo] = []

        self._table = QTableWidget(0, 5)
        self._table.setHorizontalHeaderLabels(["Client", "Created", "Last used", "Expires", ""])
        header = self._table.horizontalHeader()
        if header is not None:
            header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)

        self._error = QLabel("")
        self._error.setStyleSheet(f"color: {ERROR_COLOR};")
        self._error.setWordWrap(True)

        self._others_btn = QPushButton("Sign out everywhere else")
        self._others_btn.clicked.connect(self._sign_out_others)
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self._reload)
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)

        buttons = QHBoxLayout()
        buttons.addWidget(self._others_btn)
        buttons.addStretch(1)
        buttons.addWidget(refresh_btn)
        buttons.addWidget(close_btn)

        layout = QVBoxLayout(self)
        layout.addWidget(self._table)
        layout.addWidget(self._error)
        layout.addLayout(buttons)

        self._reload()

    def _reload(self) -> None:
        self._error.clear()
        try:
            self._sessions = self._client.list_sessions()
        except ApiError as exc:
            self._error.setText(str(exc))
            return
        self._table.setRowCount(len(self._sessions))
        for row, session in enumerate(self._sessions):
            label = (session.client or "unknown") + ("  (this device)" if session.current else "")
            cells = [
                label,
                fmt_ts(session.created_at),
                fmt_ts(session.last_used_at),
                fmt_ts(session.expires_at),
            ]
            for col, text in enumerate(cells):
                self._table.setItem(row, col, QTableWidgetItem(text))
            # The current session is revoked via "Sign out", not here, so it gets a label not a button.
            if session.current:
                self._table.setCellWidget(row, 4, QLabel("current"))
            else:
                revoke = QPushButton("Revoke")
                revoke.clicked.connect(lambda _=False, sid=session.id: self._revoke(sid))
                self._table.setCellWidget(row, 4, revoke)
        # Nothing else to sign out when only this session exists.
        self._others_btn.setEnabled(any(not s.current for s in self._sessions))

    def _revoke(self, session_id: str) -> None:
        try:
            self._client.revoke_session(session_id)
        except ApiError as exc:
            self._error.setText(str(exc))
            return
        self._reload()

    def _sign_out_others(self) -> None:
        confirm = QMessageBox.question(
            self,
            "Sign out other sessions",
            "Revoke every other active session (all devices except this one)?",
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return
        try:
            detail = self._client.revoke_other_sessions()
        except ApiError as exc:
            self._error.setText(str(exc))
            return
        self._reload()
        QMessageBox.information(self, "Sessions revoked", detail)
