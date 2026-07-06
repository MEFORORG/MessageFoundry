# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""MFA (TOTP) console dialogs (WP-14, ASVS 6.3.3).

Two flows over :class:`~messagefoundry.console.client.EngineClient`:

- :class:`MfaVerifyDialog` + :func:`make_mfa_handler` — collect a 6-digit TOTP code (or a recovery
  code) and call ``verify_mfa``. Wired into the client as the **X-MFA-Required** handler so any
  sensitive action transparently prompts-and-retries (mirrors the step-up handler in ``reauth.py``),
  and shown at login when the engine reports ``mfa_required``.
- :class:`MfaEnrollDialog` / :func:`manage_mfa` — enroll a TOTP authenticator (show the setup key +
  ``otpauth://`` URI, confirm a live code, then reveal the one-time recovery codes) or turn MFA off.

Note: the setup key / URI are shown as text for manual entry — rendering an actual QR image would
need a new dependency (qrcode), which isn't pulled in; authenticator apps accept manual key entry.
"""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QFormLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from messagefoundry.console.client import ApiError, EngineClient
from messagefoundry.console.widgets import ERROR_COLOR


class MfaVerifyDialog(QDialog):
    """Collect a TOTP code (or single-use recovery code) and call :meth:`EngineClient.verify_mfa`.
    Accepts on success; surfaces a wrong code (401) inline."""

    def __init__(self, client: EngineClient, *, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Two-factor verification — MessageFoundry")
        self._client = client

        prompt = QLabel(
            "Enter the 6-digit code from your authenticator app (or a recovery code) to continue."
        )
        prompt.setWordWrap(True)

        self._code = QLineEdit()
        self._code.setPlaceholderText("123456")
        form = QFormLayout()
        form.addRow("Code", self._code)

        self._error = QLabel("")
        self._error.setStyleSheet(f"color: {ERROR_COLOR};")
        self._error.setWordWrap(True)

        confirm = QPushButton("Verify")
        confirm.setDefault(True)
        confirm.clicked.connect(self._attempt)

        layout = QVBoxLayout(self)
        layout.addWidget(prompt)
        layout.addLayout(form)
        layout.addWidget(self._error)
        layout.addWidget(confirm)

        self._code.returnPressed.connect(self._attempt)

    def _attempt(self) -> None:
        code = self._code.text().strip()
        if not code:
            self._error.setText("Enter a code.")
            return
        try:
            self._client.verify_mfa(code)
        except ApiError as exc:
            self._error.setText("That code is not valid." if exc.status == 401 else str(exc))
            return
        self._code.clear()  # don't leave the code in the field
        self.accept()


def make_mfa_handler(client: EngineClient) -> Callable[[], bool]:
    """Handler for :meth:`EngineClient.set_mfa_handler`: prompt for a second factor on the active
    window and return ``True`` iff verified. Runs on the calling thread (the console's sensitive
    actions run on the Qt main thread, so the modal dialog shows directly)."""

    def handler() -> bool:
        dialog = MfaVerifyDialog(client, parent=QApplication.activeWindow())
        return dialog.exec() == QDialog.DialogCode.Accepted

    return handler


class MfaEnrollDialog(QDialog):
    """Two-step TOTP enrollment: show the setup key + ``otpauth://`` URI, collect a confirming code,
    then reveal the one-time recovery codes. ``enroll_mfa()`` stages the secret (step-up gated, so the
    client's step-up handler may prompt for the password first)."""

    def __init__(self, client: EngineClient, *, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Enable two-factor authentication — MessageFoundry")
        self._client = client

        layout = QVBoxLayout(self)
        self._error = QLabel("")
        self._error.setStyleSheet(f"color: {ERROR_COLOR};")
        self._error.setWordWrap(True)

        try:
            enroll = client.enroll_mfa()
        except ApiError as exc:
            failed = QLabel(f"Could not start enrollment: {exc}")
            failed.setWordWrap(True)
            close = QPushButton("Close")
            close.clicked.connect(self.reject)
            layout.addWidget(failed)
            layout.addWidget(close)
            return

        intro = QLabel(
            "Add this account to an authenticator app (Google Authenticator, Microsoft "
            "Authenticator, Authy, 1Password): enter the setup key manually, or paste the setup URL "
            "if your app accepts it. Then enter the current 6-digit code to confirm."
        )
        intro.setWordWrap(True)

        key = QLineEdit(enroll.secret)
        key.setReadOnly(True)
        uri = QLineEdit(enroll.otpauth_uri)
        uri.setReadOnly(True)
        self._code = QLineEdit()
        self._code.setPlaceholderText("123456")
        form = QFormLayout()
        form.addRow("Setup key", key)
        form.addRow("Setup URL", uri)
        form.addRow("Code", self._code)

        confirm = QPushButton("Confirm")
        confirm.setDefault(True)
        confirm.clicked.connect(self._confirm)

        layout.addWidget(intro)
        layout.addLayout(form)
        layout.addWidget(self._error)
        layout.addWidget(confirm)
        self._code.returnPressed.connect(self._confirm)

    def _confirm(self) -> None:
        code = self._code.text().strip()
        if not code:
            self._error.setText("Enter the 6-digit code from your app.")
            return
        try:
            codes = self._client.confirm_mfa(code)
        except ApiError as exc:
            self._error.setText("That code is not valid." if exc.status == 400 else str(exc))
            return
        self._show_recovery_codes(codes)
        self.accept()

    def _show_recovery_codes(self, codes: list[str]) -> None:
        box = QMessageBox(self)
        box.setWindowTitle("Save your recovery codes")
        box.setIcon(QMessageBox.Icon.Information)
        box.setText(
            "Two-factor authentication is now on. Save these single-use recovery codes somewhere "
            "safe — each works once if you lose your authenticator. They will not be shown again."
        )
        box.setInformativeText("\n".join(codes) if codes else "(no recovery codes configured)")
        box.exec()


def manage_mfa(client: EngineClient, parent: QWidget | None = None) -> None:
    """Open the right MFA flow for the current state: enroll if off, or offer to turn it off if on."""
    try:
        status = client.mfa_status()
    except ApiError as exc:
        QMessageBox.warning(parent, "Two-factor authentication", str(exc))
        return
    if not status.enabled:
        MfaEnrollDialog(client, parent=parent).exec()
        return
    ask = QMessageBox.question(
        parent,
        "Two-factor authentication",
        f"Two-factor authentication is ON ({status.recovery_codes_remaining} recovery code(s) "
        "left).\n\nTurn it off? You will then sign in with your password only.",
        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        QMessageBox.StandardButton.No,
    )
    if ask != QMessageBox.StandardButton.Yes:
        return
    try:
        client.disable_mfa()
    except ApiError as exc:
        QMessageBox.warning(parent, "Two-factor authentication", str(exc))
        return
    QMessageBox.information(
        parent, "Two-factor authentication", "Two-factor authentication is now off."
    )
