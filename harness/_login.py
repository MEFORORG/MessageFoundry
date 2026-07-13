# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Sign-in dialog shown before the harness monitor window when the engine requires authentication.

Rehomed verbatim from the retired ``messagefoundry.console`` package (BACKLOG #103, ADR 0032 retired):
the harness reuses this dialog to authenticate its localhost API client.
"""

from __future__ import annotations

from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QFormLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from messagefoundry.apiclient import ApiError, EngineClient

from harness._console_widgets import ERROR_COLOR


class LoginDialog(QDialog):
    """Collects credentials and a provider, then calls :meth:`EngineClient.login`.

    On success the client holds the session token; the caller persists it (OS keyring) and opens
    the main window. ``providers()`` decides which provider options to offer.

    When the engine reports ``must_change_password`` the dialog still ``accept()``s so the
    entrypoint regains control, but exposes :attr:`must_change_password` and
    :attr:`entered_password` so it can chain a password change and re-prompt sign-in.
    """

    def __init__(self, client: EngineClient, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Sign in — MessageFoundry")
        self._client = client
        # Seams read by _authenticate() after the dialog is accepted.
        self.must_change_password = False
        self.mfa_required = False  # engine wants a second factor before sensitive ops (WP-14)
        self.entered_password = ""  # nosec B105 (empty seam init, not a credential)

        self._username = QLineEdit()
        self._password = QLineEdit()
        self._password.setEchoMode(QLineEdit.EchoMode.Password)
        self._provider = QComboBox()
        self._provider.addItem("Local", "local")
        try:
            providers = client.providers()
        except ApiError:
            providers = None
        if providers is not None and providers.ad:
            self._provider.addItem("Active Directory", "ad")

        form = QFormLayout()
        form.addRow("Username", self._username)
        form.addRow("Password", self._password)
        form.addRow("Provider", self._provider)

        self._error = QLabel("")
        self._error.setStyleSheet(f"color: {ERROR_COLOR};")
        self._error.setWordWrap(True)

        sign_in = QPushButton("Sign in")
        sign_in.setDefault(True)
        sign_in.clicked.connect(self._attempt)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(self._error)
        layout.addWidget(sign_in)

        self._username.returnPressed.connect(self._password.setFocus)
        self._password.returnPressed.connect(self._attempt)

    def _attempt(self) -> None:
        username = self._username.text().strip()
        password = self._password.text()
        provider = str(self._provider.currentData())
        if not username or not password:
            self._error.setText("Enter a username and password.")
            return
        try:
            result = self._client.login(username, password, provider=provider)
        except ApiError as exc:
            self._error.setText("Sign-in failed." if exc.status == 401 else str(exc))
            return
        if result.must_change_password and result.user.auth_provider == "ad":
            # The harness can't rotate AD passwords (the server rejects /me/password for AD
            # accounts) — advise and admit; the user changes it in Active Directory. (AD logins
            # don't set must_change_password today, so this branch is a forward-guard.)
            QMessageBox.information(
                self,
                "Password change required",
                "This Active Directory account must change its password. Update it in Active "
                "Directory (or ask an administrator) before your access is restricted.",
            )
        else:
            # Hand the must-change flag and the just-entered plaintext back to _authenticate.
            self.must_change_password = result.must_change_password
            self.entered_password = password
        # The engine accepted the password but wants a second factor (local MFA-enrolled / required
        # admin); _authenticate prompts for the TOTP code before opening the window (always False for
        # an MFA-delegated AD login).
        self.mfa_required = result.mfa_required
        self.accept()
