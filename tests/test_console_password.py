# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Headless tests for the console password-change flow: the ChangePasswordDialog widget and the
forced-change-at-login wiring in LoginDialog. Runs Qt offscreen with a fake client; skipped if
PySide6 isn't installed."""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6")

from messagefoundry.api.auth_models import CurrentUser, LoginResponse  # noqa: E402
from messagefoundry.console.client import ApiError  # noqa: E402

_VALID = "Sup3rSecret!!"  # 12+ chars, mixed case, digit, symbol


@pytest.fixture(scope="module")
def qapp():
    from PySide6.QtWidgets import QApplication

    yield QApplication.instance() or QApplication([])


class FakeChangeClient:
    """Records change_password calls and can raise a canned ApiError to drive error paths."""

    def __init__(self, error: ApiError | None = None) -> None:
        self.error = error
        self.calls: list[tuple[str, str]] = []
        self.cleared = False

    def change_password(self, current: str, new: str) -> None:
        self.calls.append((current, new))
        if self.error is not None:
            raise self.error
        self.cleared = True  # mirror EngineClient.change_password clearing auth on success

    def clear_auth(self) -> None:
        self.cleared = True


# --- ChangePasswordDialog --------------------------------------------------------------------


def test_change_password_success(qapp) -> None:
    from PySide6.QtWidgets import QDialog

    from messagefoundry.console.change_password import ChangePasswordDialog

    client = FakeChangeClient()
    dlg = ChangePasswordDialog(client)  # type: ignore[arg-type]
    dlg._current.setText("OldPassw0rd!!")
    dlg._new.setText(_VALID)
    dlg._confirm.setText(_VALID)
    dlg._attempt()
    assert client.calls == [("OldPassw0rd!!", _VALID)]
    assert dlg.result() == QDialog.DialogCode.Accepted
    # L1: plaintext is cleared from the fields once the change succeeds (credential hygiene).
    assert dlg._current.text() == "" and dlg._new.text() == "" and dlg._confirm.text() == ""


def test_prefilled_current_is_hidden_and_sent(qapp) -> None:
    from messagefoundry.console.change_password import ChangePasswordDialog

    client = FakeChangeClient()
    dlg = ChangePasswordDialog(client, current_password="JustTyped1!")  # type: ignore[arg-type]
    # Forced-change case: the current field is prefilled and not shown in the form.
    assert dlg._current.text() == "JustTyped1!"
    assert not dlg._current.isVisibleTo(dlg)
    dlg._new.setText(_VALID)
    dlg._confirm.setText(_VALID)
    dlg._attempt()
    assert client.calls == [("JustTyped1!", _VALID)]


def test_new_neq_confirm_mismatch(qapp) -> None:
    from PySide6.QtWidgets import QDialog

    from messagefoundry.console.change_password import ChangePasswordDialog

    client = FakeChangeClient()
    dlg = ChangePasswordDialog(client)  # type: ignore[arg-type]
    dlg._current.setText("OldPassw0rd!!")
    dlg._new.setText(_VALID)
    dlg._confirm.setText("Different1!!")
    dlg._attempt()
    assert "do not match" in dlg._error.text().lower()
    assert client.calls == []  # no server call on a local validation failure
    assert dlg.result() != QDialog.DialogCode.Accepted


def test_empty_fields_blocked(qapp) -> None:
    from messagefoundry.console.change_password import ChangePasswordDialog

    client = FakeChangeClient()
    dlg = ChangePasswordDialog(client)  # type: ignore[arg-type]
    dlg._current.setText("OldPassw0rd!!")
    dlg._new.setText("")  # left blank
    dlg._confirm.setText(_VALID)
    dlg._attempt()
    assert dlg._error.text()  # an inline error is shown
    assert client.calls == []


def test_server_policy_violation_surfaced(qapp) -> None:
    from PySide6.QtWidgets import QDialog

    from messagefoundry.console.change_password import ChangePasswordDialog

    client = FakeChangeClient(error=ApiError("400: password must contain a symbol", status=400))
    dlg = ChangePasswordDialog(client)  # type: ignore[arg-type]
    dlg._current.setText("OldPassw0rd!!")
    dlg._new.setText("alllowercase")
    dlg._confirm.setText("alllowercase")
    dlg._attempt()
    assert "password must contain" in dlg._error.text()
    assert "400:" not in dlg._error.text()  # the status prefix is stripped
    assert dlg.result() != QDialog.DialogCode.Accepted  # stays open to retry


def test_server_wrong_current_403_surfaced(qapp) -> None:
    from PySide6.QtWidgets import QDialog

    from messagefoundry.console.change_password import ChangePasswordDialog

    client = FakeChangeClient(error=ApiError("403: current password is incorrect", status=403))
    dlg = ChangePasswordDialog(client)  # type: ignore[arg-type]
    dlg._current.setText("WrongOld1!!")
    dlg._new.setText(_VALID)
    dlg._confirm.setText(_VALID)
    dlg._attempt()
    assert "current password is incorrect" in dlg._error.text().lower()
    assert dlg.result() != QDialog.DialogCode.Accepted


# --- forced-change login flow ----------------------------------------------------------------


def _current_user(provider: str = "local") -> CurrentUser:
    return CurrentUser(
        user_id="u1",
        username="alice",
        auth_provider=provider,
        roles=["operator"],
        permissions=[],
    )


class FakeLoginClient:
    """Minimal client for LoginDialog: no AD providers, a configurable login result."""

    def __init__(self, result: LoginResponse) -> None:
        self._result = result
        self.login_calls: list[tuple[str, str, str]] = []

    def providers(self):  # noqa: ANN201 - duck-typed; ProvidersInfo-shaped enough for LoginDialog
        from messagefoundry.api.auth_models import ProvidersInfo

        return ProvidersInfo(local=True, ad=False)

    def login(self, username: str, password: str, *, provider: str = "local") -> LoginResponse:
        self.login_calls.append((username, password, provider))
        return self._result


def _login_response(must_change: bool, provider: str = "local") -> LoginResponse:
    return LoginResponse(
        token="tok", must_change_password=must_change, user=_current_user(provider)
    )


def test_login_must_change_exposes_seams(qapp) -> None:
    from messagefoundry.console.login import LoginDialog

    client = FakeLoginClient(_login_response(must_change=True))
    dlg = LoginDialog(client)  # type: ignore[arg-type]
    dlg._username.setText("alice")
    dlg._password.setText("JustTyped1!")
    dlg._attempt()
    # The dialog accepts so _authenticate regains control, and exposes the seams it needs to chain
    # a ChangePasswordDialog prefilled with the just-entered password.
    assert dlg.must_change_password is True
    assert dlg.entered_password == "JustTyped1!"


def test_login_normal_path_no_change(qapp) -> None:
    from messagefoundry.console.login import LoginDialog

    client = FakeLoginClient(_login_response(must_change=False))
    dlg = LoginDialog(client)  # type: ignore[arg-type]
    dlg._username.setText("alice")
    dlg._password.setText(_VALID)
    dlg._attempt()
    assert dlg.must_change_password is False


def test_login_ad_must_change_keeps_advisory(qapp, monkeypatch: pytest.MonkeyPatch) -> None:
    from messagefoundry.console import login

    shown: list[str] = []
    monkeypatch.setattr(
        login.QMessageBox,
        "information",
        staticmethod(lambda *a, **k: shown.append("info")),
    )
    client = FakeLoginClient(_login_response(must_change=True, provider="ad"))
    dlg = login.LoginDialog(client)  # type: ignore[arg-type]
    dlg._username.setText("alice")
    dlg._password.setText(_VALID)
    dlg._attempt()
    # AD accounts can't change in-app: advisory popup, and no in-app change is chained.
    assert shown == ["info"]
    assert dlg.must_change_password is False


def test_authenticate_forced_change_loops_to_resignin(
    qapp, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The _authenticate loop: must-change login -> change dialog -> re-prompt sign-in."""
    from PySide6.QtWidgets import QDialog

    from messagefoundry.console import __main__ as main_mod

    # First sign-in reports must_change; the re-prompt after the change succeeds.
    login_results = [_login_response(must_change=True), _login_response(must_change=False)]
    login_exec_calls = {"n": 0}

    class FakeLoginDialog:
        last: "FakeLoginDialog | None" = None

        def __init__(self, client: object) -> None:
            self._result = login_results[login_exec_calls["n"]]
            self.must_change_password = self._result.must_change_password
            self.mfa_required = self._result.mfa_required
            self.entered_password = "JustTyped1!"
            FakeLoginDialog.last = self

        def exec(self) -> int:
            login_exec_calls["n"] += 1
            return QDialog.DialogCode.Accepted

    change_opened: list[str] = []

    class FakeChangeDialog:
        def __init__(self, client: object, *, current_password: str = "") -> None:
            change_opened.append(current_password)

        def exec(self) -> int:
            return QDialog.DialogCode.Accepted  # change succeeded

    class Client:
        base_url = "http://127.0.0.1:8765"
        token = "tok"

        def providers(self):  # noqa: ANN201
            from messagefoundry.api.auth_models import ProvidersInfo

            return ProvidersInfo(local=True, ad=False)

        def clear_auth(self) -> None:
            pass

    monkeypatch.setattr(main_mod, "LoginDialog", FakeLoginDialog)
    monkeypatch.setattr(main_mod, "ChangePasswordDialog", FakeChangeDialog)
    monkeypatch.setattr(main_mod, "_load_token", lambda base_url: None)
    saved: list[str] = []
    monkeypatch.setattr(main_mod, "_save_token", lambda base_url, token: saved.append(token))

    assert main_mod._authenticate(Client()) is True  # type: ignore[arg-type]
    # The change dialog was opened prefilled with the just-typed password, then a fresh sign-in ran.
    assert change_opened == ["JustTyped1!"]
    assert login_exec_calls["n"] == 2  # initial + re-prompt after the change


def test_authenticate_forced_change_cancel_blocks(qapp, monkeypatch: pytest.MonkeyPatch) -> None:
    """Cancelling the change dialog re-prompts sign-in; cancelling sign-in returns False."""
    from PySide6.QtWidgets import QDialog

    from messagefoundry.console import __main__ as main_mod

    exec_calls = {"n": 0}

    class FakeLoginDialog:
        def __init__(self, client: object) -> None:
            self.must_change_password = exec_calls["n"] == 0  # first pass forces change
            self.mfa_required = False
            self.entered_password = "JustTyped1!"

        def exec(self) -> int:
            exec_calls["n"] += 1
            # First pass: accept (forces change). Second pass: user cancels sign-in.
            if exec_calls["n"] == 1:
                return QDialog.DialogCode.Accepted
            return QDialog.DialogCode.Rejected

    class FakeChangeDialog:
        def __init__(self, client: object, *, current_password: str = "") -> None:
            pass

        def exec(self) -> int:
            return QDialog.DialogCode.Rejected  # user bailed out of the change

    cleared: list[bool] = []

    class Client:
        base_url = "http://127.0.0.1:8765"
        token = None

        def providers(self):  # noqa: ANN201
            from messagefoundry.api.auth_models import ProvidersInfo

            return ProvidersInfo(local=True, ad=False)

        def clear_auth(self) -> None:
            cleared.append(True)

    monkeypatch.setattr(main_mod, "LoginDialog", FakeLoginDialog)
    monkeypatch.setattr(main_mod, "ChangePasswordDialog", FakeChangeDialog)
    monkeypatch.setattr(main_mod, "_load_token", lambda base_url: None)

    assert main_mod._authenticate(Client()) is False  # type: ignore[arg-type]
    assert cleared == [True]  # the restricted token was dropped on cancel
    assert exec_calls["n"] == 2  # forced-change sign-in, then the cancelled re-prompt


# --- header "Change password…" affordance ----------------------------------------------------


def _signed_in_window(qapp_, provider: str = "local"):
    """Build an AppWindow with a signed-in user so the header account menu is wired."""
    from tests.test_console_widgets import StubClient

    class SignedInClient(StubClient):
        @property
        def current_user(self):  # type: ignore[override]
            return _current_user(provider)

        def can(self, permission: str) -> bool:
            return False

    from messagefoundry.console.shell import AppWindow

    return AppWindow(SignedInClient(), poll_seconds=0.0)


def _menu_action(window, label: str):
    """Find a QAction in the header account (⋯) menu whose text contains `label` (None if absent)."""
    assert window._user_menu is not None
    for action in window._user_menu.actions():
        if label in action.text():
            return action
    return None


def test_header_menu_change_password_success(qapp, monkeypatch: pytest.MonkeyPatch) -> None:
    from PySide6.QtWidgets import QDialog

    from messagefoundry.console import shell

    class FakeChangeDialog:
        def __init__(self, client: object, parent: object | None = None) -> None:
            pass

        def exec(self) -> int:
            return QDialog.DialogCode.Accepted

    monkeypatch.setattr(shell, "ChangePasswordDialog", FakeChangeDialog)
    window = _signed_in_window(qapp)
    fired: list[bool] = []
    window.change_password_requested.connect(lambda: fired.append(True))
    _menu_action(window, "Change password").trigger()  # invoke the menu item
    assert fired == [True]  # success routes back to sign-in via the signal


def test_header_menu_change_password_cancel(qapp, monkeypatch: pytest.MonkeyPatch) -> None:
    from PySide6.QtWidgets import QDialog

    from messagefoundry.console import shell

    class FakeChangeDialog:
        def __init__(self, client: object, parent: object | None = None) -> None:
            pass

        def exec(self) -> int:
            return QDialog.DialogCode.Rejected

    monkeypatch.setattr(shell, "ChangePasswordDialog", FakeChangeDialog)
    window = _signed_in_window(qapp)
    fired: list[bool] = []
    window.change_password_requested.connect(lambda: fired.append(True))
    _menu_action(window, "Change password").trigger()
    assert fired == []  # cancel: no route-back


def test_header_menu_signout(qapp) -> None:
    window = _signed_in_window(qapp)
    fired: list[bool] = []
    window.logout_requested.connect(lambda: fired.append(True))
    _menu_action(window, "Sign out").trigger()
    assert fired == [True]


def test_header_menu_has_both_actions_for_local(qapp) -> None:
    window = _signed_in_window(qapp)
    assert _menu_action(window, "Change password") is not None
    assert _menu_action(window, "Sign out") is not None


def test_header_menu_omits_change_password_for_ad(qapp) -> None:
    # AD users can't rotate in-app: the menu drops Change password but keeps Sign out.
    window = _signed_in_window(qapp, provider="ad")
    assert _menu_action(window, "Change password") is None
    assert _menu_action(window, "Sign out") is not None
