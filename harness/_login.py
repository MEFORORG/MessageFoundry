# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Sign-in dialog shown before the harness monitor window when the engine requires authentication.

Rehomed verbatim from the retired ``messagefoundry.console`` package (BACKLOG #103, ADR 0032 retired):
the harness reuses this dialog to authenticate its localhost API client.
"""

from __future__ import annotations

import logging

from PySide6.QtCore import Qt
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

from harness._async import AsyncRunner
from harness._console_widgets import ERROR_COLOR
from messagefoundry.api.auth_models import LoginResponse, ProvidersInfo
from messagefoundry.apiclient import ApiError, EngineClient

log = logging.getLogger(__name__)


class LoginDialog(QDialog):
    """Collects credentials and a provider, then calls :meth:`EngineClient.login`.

    On success the client holds the session token; the caller persists it (OS keyring) and opens
    the main window. ``providers()`` decides which provider options to offer.

    When the engine reports ``must_change_password`` the dialog still ``accept()``s so the
    entrypoint regains control, but exposes :attr:`must_change_password` and
    :attr:`entered_password` so it can chain a password change and re-prompt sign-in.

    Both engine calls run off the Qt main thread (BACKLOG #5946), so a stalled engine or a slow
    directory leaves the dialog responsive rather than frozen. While one is in flight the Sign in
    action is idle, and a close is held until the call answers: a sign-in may come back as a live
    session, which only the accept path hands back to the caller, so a successful one is still
    accepted, and a failed one or the provider read then closes the dialog.
    """

    def __init__(self, client: EngineClient, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Sign in — MessageFoundry")
        self._client = client
        # Seams read by MonitorPanel._ensure_auth() after the dialog is accepted.
        self.must_change_password = False
        # BACKLOG #2009 (ASVS 6.4.5): when must_change_password is set, the instant the engine stops
        # accepting the temporary password (LoginResponse.credential_expires_at), or None.
        self.credential_expires_at: float | None = None
        # The engine refuses every authorized route on this session until a second factor is
        # verified (WP-14); the monitor's _ensure_auth asks for it.
        self.mfa_required = False
        self.entered_password = ""  # nosec B105 (empty seam init, not a credential)

        self._username = QLineEdit()
        self._password = QLineEdit()
        self._password.setEchoMode(QLineEdit.EchoMode.Password)
        # ADR 0197 (BACKLOG #1131): the optional authenticator code of the COMBINED sign-in. With it
        # a local account with TOTP enrolled signs in past a sign-in lock someone else set.
        self._code = QLineEdit()
        self._code.setPlaceholderText("optional")
        self._code.setMaxLength(6)
        self._provider = QComboBox()
        self._provider.addItem("Local", "local")
        self._runner = AsyncRunner(self)
        # One engine call at a time on this client: the provider read first, then the sign-in.
        self._busy = True
        self._signing_in = False
        self._close_requested = False  # a close asked for while a call was in flight

        form = QFormLayout()
        form.addRow("Username", self._username)
        form.addRow("Password", self._password)
        form.addRow("Authenticator code", self._code)
        form.addRow("Provider", self._provider)

        self._error = QLabel("")
        # Plain text: this shows the engine's own refusal, and AutoText would render HTML in it.
        self._error.setTextFormat(Qt.TextFormat.PlainText)
        self._error.setStyleSheet(f"color: {ERROR_COLOR};")
        self._error.setWordWrap(True)

        sign_in = QPushButton("Sign in")
        sign_in.setDefault(True)
        sign_in.clicked.connect(self._attempt)
        self._sign_in = sign_in

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(self._error)
        layout.addWidget(sign_in)

        self._username.returnPressed.connect(self._password.setFocus)
        self._password.returnPressed.connect(self._attempt)

        self._sign_in.setEnabled(False)
        self._runner.submit(
            self._read_providers, on_done=self._on_providers, on_error=self._on_providers_error
        )

    def _read_providers(self) -> ProvidersInfo | None:
        """Runs on a worker thread. An engine that will not say leaves the Local option alone."""
        try:
            return self._client.providers()
        except ApiError as exc:
            log.info("sign-in providers unavailable; offering Local only: %s", exc)
            return None

    def _on_providers(self, providers: ProvidersInfo | None) -> None:
        if providers is not None and providers.ad:
            self._provider.addItem("Active Directory", "ad")
        self._idle()
        self._close_if_requested()

    def _on_providers_error(self, exc: BaseException) -> None:
        log.warning("sign-in provider read failed; offering Local only: %r", exc)
        self._idle()
        self._close_if_requested()

    def _idle(self) -> None:
        self._busy = False
        self._signing_in = False
        self._sign_in.setEnabled(True)

    def done(self, result: int) -> None:
        # While a call is in flight the dialog does not close: a sign-in may come back as a live
        # session, which closing now would drop unseen, and the client must not be closed under a
        # worker still using it. The close is remembered and taken when the call answers.
        if self._busy and result != QDialog.DialogCode.Accepted:
            self._close_requested = True
            self._error.setText("Waiting for the engine to answer; the dialog then closes.")
            return
        self._runner.stop()
        super().done(result)

    def _close_if_requested(self) -> bool:
        if self._close_requested:
            self.done(QDialog.DialogCode.Rejected)
            return True
        return False

    def _attempt(self) -> None:
        if self._busy:
            return
        username = self._username.text().strip()
        password = self._password.text()
        provider = str(self._provider.currentData())
        if not username or not password:
            self._error.setText("Enter a username and password.")
            return
        totp_code = self._code.text().strip() or None
        self._busy = True
        self._signing_in = True
        self._sign_in.setEnabled(False)
        self._error.setText("Signing in...")
        self._runner.submit(
            lambda: self._client.login(username, password, provider=provider, totp_code=totp_code),
            on_done=lambda result: self._on_login(result, password),
            on_error=self._on_login_error,
        )

    def _on_login_error(self, exc: BaseException) -> None:
        self._idle()
        if self._close_requested:
            self._close_if_requested()
            return
        if isinstance(exc, ApiError):
            self._error.setText("Sign-in failed." if exc.status == 401 else str(exc))
        else:
            self._error.setText(f"Sign-in failed: {exc}")

    def _on_login(self, result: LoginResponse, password: str) -> None:
        self._idle()
        self._error.setText("")
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
            # Hand the must-change flag and the just-entered plaintext back to the caller.
            self.must_change_password = result.must_change_password
            self.credential_expires_at = result.credential_expires_at
            self.entered_password = password
        # The engine accepted the credential but wants a second factor; the monitor's _ensure_auth
        # prompts for it before connecting (BACKLOG #5568). This used to be documented as always
        # False for a directory login; that delegation is retired (BACKLOG #1144), and a directory
        # session now reports the debt like any other.
        self.mfa_required = result.mfa_required
        self.accept()
