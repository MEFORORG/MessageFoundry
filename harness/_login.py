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
from messagefoundry.apiclient.client import _REVOKE_LOG_CHARS

log = logging.getLogger(__name__)


def _log_text(exc: BaseException, token: str | None = None) -> str:
    """The error's type name and text, for the caller to log with ``%r``.

    The text can carry an engine-supplied detail, which falls back to a whole response body. When
    ``token`` is given, every copy of it in the text becomes ``[token]``; only the logout of a
    cancelled sign-in passes one. The text is then cut to ``_REVOKE_LOG_CHARS`` characters. The cut
    counts characters before ``%r`` escapes them, and one escaped character can take up to ten, so
    the logged form can be about ten times that long. ``%r`` escapes a CR or LF, so neither can
    start a new log line."""
    text = f"{type(exc).__name__}: {exc}"
    if token:
        text = text.replace(token, "[token]")
    return text[:_REVOKE_LOG_CHARS]


class LoginDialog(QDialog):
    """Collects credentials and a provider, then calls :meth:`EngineClient.login`.

    When the dialog is accepted the client holds the session token; the caller persists it (OS
    keyring) and opens the main window. ``providers()`` decides which provider options to offer.

    When the engine reports ``must_change_password`` the dialog still ``accept()``s so the
    entrypoint regains control, but exposes :attr:`must_change_password` and
    :attr:`entered_password` so it can chain a password change and re-prompt sign-in.

    Both engine calls run off the Qt main thread (BACKLOG #5946), so a stalled engine or a slow
    directory leaves the dialog responsive rather than frozen. While one is in flight the Sign in
    action is idle, and a close is held until the call answers, then taken as a rejection. A
    sign-in that succeeded after a held close is logged out off the GUI thread before the dialog
    rejects. A logout refused with a 401 is taken as a session already ended. Any other failed
    logout is logged, and :attr:`session_may_remain` tells the caller the session may stay valid
    until it expires. A sign-in that got no reply after a held close sets it too, because the
    engine may have made a session the client never received.
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
        # Set when a cancelled sign-in's session could not be ended: it may stay valid until it
        # expires, and the caller says so.
        self.session_may_remain = False

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
            # WARNING, not INFO: the harness configures no logging, so the root logger stays at
            # WARNING and drops anything lower.
            log.warning("sign-in providers unavailable; offering Local only: %r", _log_text(exc))
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
        # While a call is in flight the dialog does not close: the client must not be closed under
        # a worker still using it. The close is remembered and taken when the call answers, as a
        # rejection even when the sign-in succeeded; _on_login then tries a logout first.
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
        if not isinstance(exc, ApiError):
            # An ApiError is the engine's answer and is shown below; anything else is a fault
            # here, logged with its traceback, not only shown.
            log.error("sign-in failed unexpectedly", exc_info=exc)
        self._idle()
        if self._close_requested:
            if isinstance(exc, ApiError):
                # The error is not shown once the close is taken, so it is logged instead (R8), at
                # WARNING: the harness sets up no logging, and the root logger drops lower levels.
                if exc.status is None:
                    # No reply, so the outcome is unknown: the engine may have made a session that
                    # this client never received and so cannot end.
                    self.session_may_remain = True
                    log.warning(
                        "sign-in got no reply after the dialog was closed, so a session may stay "
                        "valid until it expires: %r",
                        _log_text(exc),
                    )
                else:
                    log.warning("sign-in failed after the dialog was closed: %r", _log_text(exc))
            self._close_if_requested()
            return
        if isinstance(exc, ApiError):
            self._error.setText("Sign-in failed." if exc.status == 401 else str(exc))
        else:
            self._error.setText(f"Sign-in failed: {exc}")

    def _on_cancelled_logout_error(self, exc: BaseException, token: str | None) -> None:
        if isinstance(exc, ApiError) and exc.status == 401:
            # As the client's revoke path: a 401 most likely means the session has already ended.
            # The engine refuses with 401 for other reasons too, so the line says it refused.
            log.info(
                "the engine refused to end a cancelled sign-in's session (401); it has most "
                "likely already ended"
            )
            self._end_cancelled()
            return
        log.error(
            "could not end the session of a cancelled sign-in, so it may stay valid until it "
            "expires: %r",
            _log_text(exc, token),
        )
        self.session_may_remain = True
        self._end_cancelled()

    def _end_cancelled(self) -> None:
        self._idle()
        self._close_if_requested()

    def _on_login(self, result: LoginResponse, password: str) -> None:
        if self._close_requested:
            # Cancelled while the sign-in was in flight: the cancel wins. The session it made is
            # ended here, off the GUI thread like the sign-in, and the dialog then rejects whether
            # or not the logout succeeds. The dialog stays busy meanwhile, so a close still waits.
            self._signing_in = False
            token = self._client.token
            self._runner.submit(
                self._client.logout,
                on_done=lambda _result: self._end_cancelled(),
                on_error=lambda exc: self._on_cancelled_logout_error(exc, token),
            )
            return
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
