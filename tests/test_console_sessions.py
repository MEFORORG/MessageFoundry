# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Console active-sessions dialog + admin force-sign-out (the WP-10 console view).

Headless Qt (offscreen). Stubs stand in for EngineClient; QMessageBox confirmations/info are
monkeypatched so the modal dialogs don't block."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from messagefoundry.api.auth_models import SessionInfo, UserSummary


class _SessionsClient:
    """The EngineClient surface the sessions dialog uses, with canned data + call recording."""

    def __init__(self, sessions: list[SessionInfo]) -> None:
        self._sessions = list(sessions)
        self.revoked: list[str] = []
        self.revoked_others = 0

    def list_sessions(self) -> list[SessionInfo]:
        return list(self._sessions)

    def revoke_session(self, session_id: str) -> None:
        self.revoked.append(session_id)
        self._sessions = [s for s in self._sessions if s.id != session_id]

    def revoke_other_sessions(self) -> str:
        kept = [s for s in self._sessions if s.current]
        n = len(self._sessions) - len(kept)
        self._sessions = kept
        self.revoked_others += 1
        return f"signed out {n} other session(s)"


class _AdminClient:
    """Minimal surface for the UsersPage admin force-sign-out test."""

    def __init__(self) -> None:
        self.revoked_users: list[str] = []

    def list_users(self) -> list[UserSummary]:
        return [
            UserSummary(
                id="u1",
                username="bob",
                auth_provider="local",
                disabled=False,
                roles=["operator"],
                channel_scope=None,
            )
        ]

    def revoke_user_sessions(self, user_id: str) -> str:
        self.revoked_users.append(user_id)
        return "revoked 2 session(s)"


@pytest.fixture(scope="module")
def qapp() -> Iterator[object]:
    from PySide6.QtWidgets import QApplication

    yield QApplication.instance() or QApplication([])


def _session(id_: str, *, current: bool = False, client: str | None = "Chrome") -> SessionInfo:
    return SessionInfo(
        id=id_,
        created_at=1_700_000_000.0,
        last_used_at=1_700_000_500.0,
        expires_at=1_700_100_000.0,
        client=client,
        current=current,
    )


def test_dialog_lists_sessions_and_flags_current(qapp: object) -> None:
    from messagefoundry.console.sessions import SessionsDialog

    dlg = SessionsDialog(_SessionsClient([_session("a", current=True), _session("b")]))
    assert dlg._table.rowCount() == 2
    assert "this device" in dlg._table.item(0, 0).text()  # current is flagged


def test_current_session_has_label_not_revoke_button(qapp: object) -> None:
    from PySide6.QtWidgets import QPushButton

    from messagefoundry.console.sessions import SessionsDialog

    dlg = SessionsDialog(_SessionsClient([_session("a", current=True), _session("b")]))
    assert not isinstance(dlg._table.cellWidget(0, 4), QPushButton)  # current → no revoke
    assert isinstance(dlg._table.cellWidget(1, 4), QPushButton)  # other → revoke button


def test_revoke_removes_the_session(qapp: object) -> None:
    from messagefoundry.console.sessions import SessionsDialog

    client = _SessionsClient([_session("a", current=True), _session("b")])
    dlg = SessionsDialog(client)
    dlg._revoke("b")
    assert client.revoked == ["b"]
    assert dlg._table.rowCount() == 1  # reloaded without b


def test_sign_out_others_disabled_when_alone(qapp: object) -> None:
    from messagefoundry.console.sessions import SessionsDialog

    dlg = SessionsDialog(_SessionsClient([_session("a", current=True)]))
    assert not dlg._others_btn.isEnabled()  # nothing else to sign out


def test_sign_out_others_confirmed(qapp: object, monkeypatch: pytest.MonkeyPatch) -> None:
    from messagefoundry.console import sessions as sess_mod
    from messagefoundry.console.sessions import SessionsDialog

    monkeypatch.setattr(
        sess_mod.QMessageBox, "question", lambda *a, **k: sess_mod.QMessageBox.StandardButton.Yes
    )
    monkeypatch.setattr(sess_mod.QMessageBox, "information", lambda *a, **k: None)
    client = _SessionsClient([_session("a", current=True), _session("b"), _session("c")])
    dlg = SessionsDialog(client)
    dlg._sign_out_others()
    assert client.revoked_others == 1
    assert dlg._table.rowCount() == 1  # only the current session remains


def test_sign_out_others_declined_does_nothing(
    qapp: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    from messagefoundry.console import sessions as sess_mod
    from messagefoundry.console.sessions import SessionsDialog

    monkeypatch.setattr(
        sess_mod.QMessageBox, "question", lambda *a, **k: sess_mod.QMessageBox.StandardButton.No
    )
    client = _SessionsClient([_session("a", current=True), _session("b")])
    dlg = SessionsDialog(client)
    dlg._sign_out_others()
    assert client.revoked_others == 0


def test_admin_revoke_user_sessions(qapp: object, monkeypatch: pytest.MonkeyPatch) -> None:
    from messagefoundry.console import users_page as up_mod
    from messagefoundry.console.users_page import UsersPage

    monkeypatch.setattr(
        up_mod.QMessageBox, "question", lambda *a, **k: up_mod.QMessageBox.StandardButton.Yes
    )
    monkeypatch.setattr(up_mod.QMessageBox, "information", lambda *a, **k: None)
    client = _AdminClient()
    page = UsersPage(client)  # type: ignore[arg-type]
    page.reload()  # off-thread (M-25 / backlog #2) — wait for the user list to apply before selecting
    page._runner._pool.waitForDone(5000)
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance()
    assert app is not None
    for _ in range(5):
        app.processEvents()
    page._table.selectRow(0)
    page._revoke_sessions()
    assert client.revoked_users == ["u1"]
    page.stop()
