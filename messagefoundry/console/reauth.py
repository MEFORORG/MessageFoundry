# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Step-up re-verification dialog (ASVS 7.5.3, WP-L3-16 — console side).

The engine refuses a highly sensitive operation (user admin, replay, purge, config reload) with
**403 + ``X-Step-Up-Required``** when the session hasn't re-proved its credential within
``[auth].step_up_max_age_seconds``. :class:`ReauthDialog` collects the password and calls
``POST /me/reauth`` (local password re-verify, or an AD re-bind); :func:`make_step_up_handler` wires it
into :class:`~messagefoundry.console.client.EngineClient` so any sensitive action transparently
prompts-and-retries instead of surfacing a raw 403.
"""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QFormLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from messagefoundry.console.client import ApiError, EngineClient
from messagefoundry.console.widgets import ERROR_COLOR


class ReauthDialog(QDialog):
    """Collect the caller's current password and call :meth:`EngineClient.reauth` to refresh the
    step-up window. Accepts on success; surfaces a wrong password (403) inline."""

    def __init__(self, client: EngineClient, *, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Re-verify — MessageFoundry")
        self._client = client

        user = client.current_user
        is_ad = user is not None and user.auth_provider == "ad"
        prompt = QLabel(
            "This action needs you to re-verify. Re-enter your "
            + ("Active Directory password" if is_ad else "password")
            + " to continue."
        )
        prompt.setWordWrap(True)

        self._password = QLineEdit()
        self._password.setEchoMode(QLineEdit.EchoMode.Password)
        form = QFormLayout()
        form.addRow("Password", self._password)

        self._error = QLabel("")
        self._error.setStyleSheet(f"color: {ERROR_COLOR};")
        self._error.setWordWrap(True)

        confirm = QPushButton("Re-verify")
        confirm.setDefault(True)
        confirm.clicked.connect(self._attempt)

        layout = QVBoxLayout(self)
        layout.addWidget(prompt)
        layout.addLayout(form)
        layout.addWidget(self._error)
        layout.addWidget(confirm)

        self._password.returnPressed.connect(self._attempt)

    def _attempt(self) -> None:
        password = self._password.text()
        if not password:
            self._error.setText("Enter your password.")
            return
        try:
            self._client.reauth(password)
        except ApiError as exc:
            self._error.setText("Password is incorrect." if exc.status == 403 else str(exc))
            return
        self._password.clear()  # don't leave plaintext in the field (Qt doesn't zero buffers)
        self.accept()


def make_step_up_handler(client: EngineClient) -> Callable[[], bool]:
    """A handler for :meth:`EngineClient.set_step_up_handler`: prompt for re-verification on the active
    window and return ``True`` iff the user re-verified. Runs on the calling thread — the console's
    sensitive actions run on the Qt main thread, so the modal dialog shows directly."""

    def handler() -> bool:
        dialog = ReauthDialog(client, parent=QApplication.activeWindow())
        return dialog.exec() == QDialog.DialogCode.Accepted

    return handler
