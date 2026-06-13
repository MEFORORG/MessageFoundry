"""Password-change dialog used both for the forced-change-at-login flow and the in-app
"Change password…" affordance.

The server (``POST /me/password``) revokes all of the user's sessions on a successful change, so
:meth:`EngineClient.change_password` clears the client's token afterwards. Callers must therefore
re-prompt sign-in once this dialog is accepted.
"""

from __future__ import annotations

from PySide6.QtWidgets import (
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


class ChangePasswordDialog(QDialog):
    """Collects current/new/confirm passwords and calls :meth:`EngineClient.change_password`.

    ``current_password`` pre-fills (and hides) the current-password field for the forced
    change-at-login case, where the just-entered plaintext is already known and the server has
    accepted it. When empty (the in-app affordance), the field is shown so the user types it.
    Errors are surfaced inline (matching :class:`~messagefoundry.console.login.LoginDialog`):
    400 carries the server's policy detail, 403 means the current password was wrong.
    """

    def __init__(
        self,
        client: EngineClient,
        *,
        current_password: str = "",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Change password — MessageFoundry")
        self._client = client
        self._prefilled = bool(current_password)

        self._current = QLineEdit(current_password)
        self._current.setEchoMode(QLineEdit.EchoMode.Password)
        self._new = QLineEdit()
        self._new.setEchoMode(QLineEdit.EchoMode.Password)
        self._confirm = QLineEdit()
        self._confirm.setEchoMode(QLineEdit.EchoMode.Password)

        form = QFormLayout()
        # In the forced-change case the current password is already known/accepted — keep it out of
        # the form so the user only chooses a new one (it is still sent on submit).
        if not self._prefilled:
            form.addRow("Current password", self._current)
        form.addRow("New password", self._new)
        form.addRow("Confirm new password", self._confirm)

        self._error = QLabel("")
        self._error.setStyleSheet(f"color: {ERROR_COLOR};")
        self._error.setWordWrap(True)

        change = QPushButton("Change password")
        change.setDefault(True)
        change.clicked.connect(self._attempt)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(self._error)
        layout.addWidget(change)

        # Enter-key chaining mirrors LoginDialog: walk the visible fields then submit.
        if not self._prefilled:
            self._current.returnPressed.connect(self._new.setFocus)
        self._new.returnPressed.connect(self._confirm.setFocus)
        self._confirm.returnPressed.connect(self._attempt)

    def _attempt(self) -> None:
        current = self._current.text()
        new = self._new.text()
        confirm = self._confirm.text()
        if not current or not new or not confirm:
            self._error.setText("Enter your current password and a new password (twice).")
            return
        if new != confirm:
            self._error.setText("The new passwords do not match.")
            return
        try:
            self._client.change_password(current, new)
        except ApiError as exc:
            if exc.status == 403:
                self._error.setText("Current password is incorrect.")
            elif exc.status == 400:
                # The server detail already reads e.g. "password must contain a symbol"; strip the
                # client's "400: " status prefix so the policy text shows cleanly.
                self._error.setText(str(exc).removeprefix("400: "))
            else:
                self._error.setText(str(exc))
            return
        # Clear the plaintext from the fields now the change succeeded — defensive credential
        # hygiene, since Qt doesn't zero QLineEdit buffers on destruction (L1).
        for field in (self._current, self._new, self._confirm):
            field.clear()
        # change_password() has already cleared the client's token (the server revoked the
        # session); the caller must re-prompt sign-in.
        self.accept()
