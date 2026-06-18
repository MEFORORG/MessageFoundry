# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Headless tests for the console Users page — per-channel scope column + editor (C2)."""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6")

from messagefoundry.api.auth_models import UserSummary  # noqa: E402
from messagefoundry.api.models import ConnectionRow  # noqa: E402


def _user(username: str, scope: list[str] | None) -> UserSummary:
    return UserSummary(
        id=f"id-{username}",
        username=username,
        auth_provider="local",
        disabled=False,
        roles=["operator"],
        channel_scope=scope,
    )


def _source(channel_id: str) -> ConnectionRow:
    return ConnectionRow(
        role="source",
        channel_id=channel_id,
        channel_name=channel_id,
        destination=None,
        name=channel_id,
        status="running",
        direction="in",
        method="MLLP",
        peer="127.0.0.1",
        port=2575,
        queue_depth=None,
        idle_seconds=None,
        alerts_active=0,
        errored=0,
        read=0,
        written=None,
        backlog_seconds=None,
        delivered_age_seconds=None,
    )


class _Role:
    def __init__(self, role_id: str) -> None:
        self.id = role_id


class FakeClient:
    def __init__(self, users: list[UserSummary]) -> None:
        self._users = users
        self.scope_calls: list[tuple[str, list[str] | None]] = []
        self.role_calls: list[tuple[str, list[str]]] = []

    def list_users(self) -> list[UserSummary]:
        return self._users

    def list_roles(self) -> list[_Role]:
        return [_Role("administrator"), _Role("operator"), _Role("viewer")]

    def connections(self) -> list[ConnectionRow]:
        return [_source("IB_A"), _source("IB_B")]

    def set_channel_scope(self, user_id: str, channels: list[str] | None) -> None:
        self.scope_calls.append((user_id, channels))

    def set_user_roles(self, user_id: str, roles: list[str]) -> None:
        self.role_calls.append((user_id, roles))


@pytest.fixture(scope="module")
def qapp():
    from PySide6.QtWidgets import QApplication

    yield QApplication.instance() or QApplication([])


def _settle(qapp, runner) -> None:
    """Let the off-thread user-list reload finish and deliver its result to the main thread
    (UsersPage.reload now runs /users on a worker thread — M-25 / backlog #2)."""
    runner._pool.waitForDone(5000)
    for _ in range(5):
        qapp.processEvents()


def test_scope_label_renders_all_none_and_list() -> None:
    from messagefoundry.console.users_page import _scope_label

    assert _scope_label(None) == "all"
    assert _scope_label([]) == "(none)"
    assert _scope_label(["IB_A", "IB_B"]) == "IB_A, IB_B"


def test_users_page_shows_scope_column(qapp) -> None:
    from messagefoundry.console.users_page import UsersPage

    client = FakeClient([_user("alice", None), _user("bob", ["IB_A"])])
    page = UsersPage(client)  # type: ignore[arg-type]
    page.reload()
    _settle(qapp, page._runner)
    assert page._table.columnCount() == 5
    assert page._table.item(0, 3).text() == "all"  # alice: unscoped
    assert page._table.item(1, 3).text() == "IB_A"  # bob: scoped
    page.stop()


def test_set_scope_sends_list(qapp, monkeypatch: pytest.MonkeyPatch) -> None:
    from messagefoundry.console import users_page

    client = FakeClient([_user("bob", None)])
    page = users_page.UsersPage(client)  # type: ignore[arg-type]
    page.reload()
    _settle(qapp, page._runner)
    page._table.setCurrentCell(0, 0)
    monkeypatch.setattr(
        users_page.QInputDialog, "getText", staticmethod(lambda *a, **k: ("IB_A, IB_B", True))
    )
    page._set_scope()
    assert client.scope_calls == [("id-bob", ["IB_A", "IB_B"])]
    page.stop()


def test_set_scope_star_means_all(qapp, monkeypatch: pytest.MonkeyPatch) -> None:
    from messagefoundry.console import users_page

    client = FakeClient([_user("bob", ["IB_A"])])
    page = users_page.UsersPage(client)  # type: ignore[arg-type]
    page.reload()
    _settle(qapp, page._runner)
    page._table.setCurrentCell(0, 0)
    monkeypatch.setattr(
        users_page.QInputDialog, "getText", staticmethod(lambda *a, **k: ("*", True))
    )
    page._set_scope()
    assert client.scope_calls == [("id-bob", None)]  # '*' clears the scope (all channels)
    page.stop()


def test_set_roles_prefills_current_roles(qapp, monkeypatch: pytest.MonkeyPatch) -> None:
    # H3 / low-15: the Set-roles dialog prefills the user's current roles so a tweak doesn't strip them.
    from messagefoundry.console import users_page

    client = FakeClient([_user("bob", None)])  # _user() assigns roles=["operator"]
    page = users_page.UsersPage(client)  # type: ignore[arg-type]
    page.reload()
    _settle(qapp, page._runner)
    page._table.setCurrentCell(0, 0)
    captured: dict[str, str] = {}

    def fake_get_text(*args: object, **kwargs: object) -> tuple[str, bool]:
        captured["prefill"] = str(args[4])  # 5th positional arg is the prefilled text
        return ("operator, viewer", True)

    monkeypatch.setattr(users_page.QInputDialog, "getText", staticmethod(fake_get_text))
    page._set_roles()
    # H3: the dialog opens prefilled with the user's current roles, not blank, so submitting
    # can't silently wipe them.
    assert captured["prefill"] == "operator"  # prefilled from the row, not blank
    assert client.role_calls == [("id-bob", ["operator", "viewer"])]
    page.stop()


def test_set_roles_empty_submission_is_confirmed(qapp, monkeypatch: pytest.MonkeyPatch) -> None:
    # low-15: submitting no roles strips all access, so it must be confirmed; declining is a no-op.
    from messagefoundry.console import users_page

    client = FakeClient([_user("bob", None)])
    page = users_page.UsersPage(client)  # type: ignore[arg-type]
    page.reload()
    _settle(qapp, page._runner)
    page._table.setCurrentCell(0, 0)
    monkeypatch.setattr(
        users_page.QInputDialog, "getText", staticmethod(lambda *a, **k: ("", True))
    )
    monkeypatch.setattr(
        users_page.QMessageBox,
        "question",
        staticmethod(lambda *a, **k: users_page.QMessageBox.StandardButton.No),
    )
    page._set_roles()
    assert client.role_calls == []  # declined -> nothing stripped
    page.stop()
