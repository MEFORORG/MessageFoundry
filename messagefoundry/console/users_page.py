"""Users administration page — visible only to users holding ``users:manage``.

Lists users with their roles and supports create / set-roles / delete. All operations go through the
HTTP API (which enforces permissions), so the page is a thin view; the engine is the source of truth.
"""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from messagefoundry.console.client import ApiError, EngineClient


def _scope_label(channels: list[str] | None) -> str:
    """Human-readable channel scope: all / none / the listed connections."""
    if channels is None:
        return "all"
    return ", ".join(channels) if channels else "(none)"


class UsersPage(QWidget):
    """Table of users + create/set-roles/delete actions (everything audited server-side)."""

    error = Signal(str)

    def __init__(self, client: EngineClient) -> None:
        super().__init__()
        self._client = client
        self._row_ids: list[str] = []  # user_id per table row
        self._row_scopes: list[list[str] | None] = []  # channel scope per row (None = all)
        # current roles per row, to prefill the Set-roles dialog (H3)
        self._row_roles: list[list[str]] = []

        self._table = QTableWidget(0, 5)
        self._table.setHorizontalHeaderLabels(
            ["Username", "Provider", "Roles", "Channel scope", "Status"]
        )
        header = self._table.horizontalHeader()
        if header is not None:
            header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)

        add_btn = QPushButton("Add user…")
        add_btn.clicked.connect(self._add_user)
        roles_btn = QPushButton("Set roles…")
        roles_btn.clicked.connect(self._set_roles)
        scope_btn = QPushButton("Set scope…")
        scope_btn.clicked.connect(self._set_scope)
        delete_btn = QPushButton("Delete")
        delete_btn.clicked.connect(self._delete)
        sessions_btn = QPushButton("Revoke sessions")
        sessions_btn.clicked.connect(self._revoke_sessions)
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.reload)

        buttons = QHBoxLayout()
        for button in (add_btn, roles_btn, scope_btn, delete_btn, sessions_btn, refresh_btn):
            buttons.addWidget(button)
        buttons.addStretch(1)

        layout = QVBoxLayout(self)
        layout.addLayout(buttons)
        layout.addWidget(self._table)

    # --- page interface (auto-refresh timer + nav) ---------------------------

    def refresh(self) -> None:
        # This page has no separate silent path (no PHI-summary audit or column autosize to skip),
        # so the auto-refresh tick and a user-initiated reload are the same full repopulate.
        self.reload()

    def reload(self) -> None:
        try:
            users = self._client.list_users()
        except ApiError as exc:
            self.error.emit(str(exc))
            return
        self._row_ids = [u.id for u in users]
        self._row_scopes = [u.channel_scope for u in users]
        self._row_roles = [list(u.roles) for u in users]
        self._table.setRowCount(len(users))
        for row, user in enumerate(users):
            cells = [
                user.username,
                user.auth_provider,
                ", ".join(user.roles),
                _scope_label(user.channel_scope),
                "disabled" if user.disabled else "active",
            ]
            for col, text in enumerate(cells):
                self._table.setItem(row, col, QTableWidgetItem(text))

    # --- actions -------------------------------------------------------------

    def _selected_user_id(self) -> str | None:
        row = self._table.currentRow()
        return self._row_ids[row] if 0 <= row < len(self._row_ids) else None

    def _available_roles(self) -> list[str]:
        try:
            return [r.id for r in self._client.list_roles()]
        except ApiError:
            return []

    def _pick_roles(self, current: list[str]) -> list[str] | None:
        available = ", ".join(self._available_roles())
        text, ok = QInputDialog.getText(
            self,
            "Roles",
            f"Comma-separated roles (available: {available}):",
            QLineEdit.EchoMode.Normal,
            ", ".join(current),
        )
        if not ok:
            return None
        return [r.strip() for r in text.split(",") if r.strip()]

    def _add_user(self) -> None:
        username, ok = QInputDialog.getText(self, "Add user", "Username:")
        if not ok or not username.strip():
            return
        password, ok = QInputDialog.getText(
            self, "Add user", "Password:", QLineEdit.EchoMode.Password
        )
        if not ok or not password:
            return
        roles = self._pick_roles([])
        if roles is None:
            return
        try:
            self._client.create_user(username.strip(), password, roles=roles)
        except ApiError as exc:
            self.error.emit(str(exc))
        self.reload()

    def _set_roles(self) -> None:
        # Resolve the row (not just the user_id) so we can prefill the dialog with the user's
        # current roles — otherwise it opens blank and submitting would clear/truncate them (H3).
        row = self._table.currentRow()
        if not (0 <= row < len(self._row_ids)):
            return
        user_id = self._row_ids[row]
        # Prefill the user's current roles so the PUT (which replaces the whole set) doesn't strip
        # them when the operator just wanted to tweak one — and confirm an empty submission (low-15).
        roles = self._pick_roles(self._row_roles[row])
        if roles is None:
            return
        if not roles and not self._confirm_strip_roles():
            return
        try:
            self._client.set_user_roles(user_id, roles)
        except ApiError as exc:
            self.error.emit(str(exc))
        self.reload()

    def _confirm_strip_roles(self) -> bool:
        reply = QMessageBox.question(
            self,
            "Remove all roles",
            "Submitting no roles removes every role from this user, leaving them with no access. "
            "Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        return reply == QMessageBox.StandardButton.Yes

    def _inbound_connections(self) -> list[str]:
        try:
            return sorted({c.channel_id for c in self._client.connections() if c.role == "source"})
        except ApiError:
            return []

    def _set_scope(self) -> None:
        row = self._table.currentRow()
        if not (0 <= row < len(self._row_ids)):
            return
        user_id = self._row_ids[row]
        current = self._row_scopes[row]
        available = ", ".join(self._inbound_connections())
        prefill = "*" if current is None else ", ".join(current)
        text, ok = QInputDialog.getText(
            self,
            "Channel scope",
            # '*' (or blank) = all channels; a comma-separated list restricts to those connections.
            f"Connections ('*' = all; available: {available}):",
            QLineEdit.EchoMode.Normal,
            prefill,
        )
        if not ok:
            return
        entries = [c.strip() for c in text.split(",") if c.strip()]
        channels = None if (not entries or entries == ["*"]) else entries
        try:
            self._client.set_channel_scope(user_id, channels)
        except ApiError as exc:
            self.error.emit(str(exc))
        self.reload()

    def _delete(self) -> None:
        user_id = self._selected_user_id()
        if user_id is None:
            return
        confirm = QMessageBox.question(self, "Delete user", "Delete the selected user?")
        if confirm != QMessageBox.StandardButton.Yes:
            return
        try:
            self._client.delete_user(user_id)
        except ApiError as exc:
            self.error.emit(str(exc))
        self.reload()

    def _revoke_sessions(self) -> None:
        """Admin force-sign-out: revoke all of the selected user's sessions (offboarding/compromise)."""
        user_id = self._selected_user_id()
        if user_id is None:
            return
        confirm = QMessageBox.question(
            self,
            "Revoke sessions",
            "Force-sign-out the selected user by revoking all of their active sessions?",
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return
        try:
            detail = self._client.revoke_user_sessions(user_id)
        except ApiError as exc:
            self.error.emit(str(exc))
            return
        QMessageBox.information(self, "Sessions revoked", detail)
