# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5559: the console's user pages read an account only through the engine's checked read.

The detail page, the federated identity screen and its unlink confirmation, and the channel scope
save each read the account through ``AdminHandlers.checked_user``, which is the JSON plane's own
``_checked_user``. So a row altered outside the store, on a keyed store, is answered 423 with none
of what was planted shown, and the failure is handed to the seal-failure report, which writes the
``integrity.authority_seal_failed`` row and raises the alert. Before #5559 these read the store row
directly: the page showed the planted values with a 200 and nothing was recorded.

The users list keeps such an account by id alone (BACKLOG #5520) and now offers its delete, the
one action the console takes on it, since its detail page answers 423.

Every test has a control: the same read of an intact account, or of the same account before the
tampering.
"""

from __future__ import annotations

import sqlite3
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from _ui_clients import SAME_ORIGIN, cookie_login, mint_bound_proof, provision
from _webui_support import _client

from messagefoundry.auth import Role
from messagefoundry.auth.service import (
    AUTHORITY_SEAL_FAILED_ACTION,
    USER_SEAL_REFUSED,
    AuthService,
    UserSealRefused,
)
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.store import MessageStore

#: What the tampering writes. None of it may appear in an answer.
_PLANTED = "planted-outside-the-store"


@pytest.fixture
async def keyed(tmp_path: Path) -> AsyncIterator[tuple[Engine, Path]]:
    """An engine on a keyed store, so each account record carries an integrity seal."""
    path = tmp_path / "console_user_seal.db"
    store = await MessageStore.open(path, cipher=make_cipher(generate_key(), write_v2=True))
    engine = Engine(
        store, poll_interval=0.02, egress_settings=EgressSettings(deny_by_default=False)
    )
    try:
        yield engine, path
    finally:
        await engine.stop()


def _tamper(path: Path, user_id: str) -> None:
    """Alter the account's sealed fields on a connection that holds no store key."""
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            "UPDATE users SET display_name=?, channel_scope=?, oidc_issuer=?, oidc_subject=? "
            "WHERE id=?",
            (_PLANTED, f'["{_PLANTED}"]', _PLANTED, _PLANTED, user_id),
        )
        conn.commit()
    finally:
        conn.close()


async def _setup(engine: Engine) -> tuple[AuthService, list[str], str, str]:
    """An administrator ``root``, an intact viewer and a viewer whose row a test then alters."""
    alerts: list[str] = []
    service = AuthService(
        engine.store,
        AuthSettings(
            admin_write_min_interval_seconds=0,
            mfa_verify_min_elapsed_seconds=0,
            require_mfa=False,
        ),
        integrity_alert=alerts.append,
    )
    await service.initialize()
    await provision(service, "root", [Role.ADMINISTRATOR.value])
    intact = await provision(service, "intact", [Role.VIEWER.value])
    victim = await provision(service, "victim", [Role.VIEWER.value])
    return service, alerts, intact, victim


async def _seal_failures(engine: Engine, user_id: str) -> int:
    rows = await engine.store.list_audit(action=AUTHORITY_SEAL_FAILED_ACTION, limit=10_000)
    return sum(1 for row in rows if user_id in str(row["detail"]))


async def test_the_detail_page_answers_423_for_a_record_that_fails_its_seal(
    keyed: tuple[Engine, Path],
) -> None:
    engine, path = keyed
    service, alerts, intact, victim = await _setup(engine)
    async with _client(engine, service) as c:
        await cookie_login(c, "root")
        before = await c.get(f"/ui/users/{victim}")
        assert before.status_code == 200 and "victim" in before.text  # control: before tampering
        _tamper(path, victim)
        r = await c.get(f"/ui/users/{victim}")
        ok = await c.get(f"/ui/users/{intact}")
    assert r.status_code == 423
    assert _PLANTED not in r.text and "victim" not in r.text
    assert USER_SEAL_REFUSED in r.text
    assert await _seal_failures(engine, victim) == 1 and alerts
    assert ok.status_code == 200 and "intact" in ok.text  # control: an intact account


async def test_the_federated_screens_answer_423_for_a_record_that_fails_its_seal(
    keyed: tuple[Engine, Path],
) -> None:
    engine, path = keyed
    service, _alerts, intact, victim = await _setup(engine)
    _tamper(path, victim)
    async with _client(engine, service) as c:
        await cookie_login(c, "root")
        screen = await c.get(f"/ui/users/{victim}/federated-identity")
        confirm = await c.get(f"/ui/users/{victim}/federated-identity/unlink-confirm")
        ok = await c.get(f"/ui/users/{intact}/federated-identity")
    for r in (screen, confirm):
        assert r.status_code == 423, r.text
        assert _PLANTED not in r.text
    assert await _seal_failures(engine, victim) == 1  # one report per interval
    assert ok.status_code == 200 and "intact" in ok.text  # control


async def test_a_refused_scope_save_does_not_render_a_record_that_fails_its_seal(
    keyed: tuple[Engine, Path],
) -> None:
    """The channel scope save read the row raw, decided the manual-scope check from it, and
    re-rendered its refusals on the detail page. A post that would be refused for its form (an
    unknown scope mode) is answered 423 first, so nothing is decided from the planted row."""
    engine, path = keyed
    service, _alerts, intact, victim = await _setup(engine)
    _tamper(path, victim)
    form = {"scope_mode": "bogus"}
    async with _client(engine, service) as c:
        await cookie_login(c, "root")
        r = await c.post(f"/ui/users/{victim}/channel-scope", data=form, headers=SAME_ORIGIN)
        ok = await c.post(f"/ui/users/{intact}/channel-scope", data=form, headers=SAME_ORIGIN)
    assert r.status_code == 423
    assert _PLANTED not in r.text
    assert await _seal_failures(engine, victim) == 1
    assert ok.status_code == 400 and "unknown scope mode" in ok.text  # control


async def test_a_failing_account_is_listed_with_its_delete_and_the_delete_removes_it(
    keyed: tuple[Engine, Path],
) -> None:
    engine, path = keyed
    service, _alerts, intact, victim = await _setup(engine)
    _tamper(path, victim)
    async with _client(engine, service) as c:
        await cookie_login(c, "root")
        listed = await c.get("/ui/users")
        assert listed.status_code == 200
        assert f'action="/ui/users/{victim}/delete"' in listed.text
        assert _PLANTED not in listed.text
        # Control: an intact account is linked and offers no delete on the list.
        assert f'href="/ui/users/{intact}"' in listed.text
        assert f'action="/ui/users/{intact}/delete"' not in listed.text
        r = await c.post(f"/ui/users/{victim}/delete", headers=SAME_ORIGIN)
    assert r.status_code == 303 and r.headers["location"] == "/ui/users"
    assert await engine.store.get_user(victim) is None
    assert await engine.store.get_user(intact) is not None


async def test_a_page_after_a_landed_action_names_the_account_only_from_a_checked_read(
    keyed: tuple[Engine, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The password reset lands through the engine's own checks, then the page that hands over the
    one-time credential names the account. That name is read through the checked read; when it
    refuses, the page names the id and the credential is still shown, since it was issued. The
    refusal is stood in for at the service's checked reader, after the reset's own read."""
    engine, _path = keyed
    service, _alerts, intact, victim = await _setup(engine)
    async with _client(engine, service) as c:
        await cookie_login(c, "root")
        path = f"/ui/users/{intact}/reset-password"
        await mint_bound_proof(c, path)
        ok = await c.post(path, headers=SAME_ORIGIN)
        assert ok.status_code == 200 and "Convey this to intact " in ok.text  # control

        async def refused(user_id: str) -> None:
            raise UserSealRefused(USER_SEAL_REFUSED)

        monkeypatch.setattr(service, "checked_user", refused)
        path = f"/ui/users/{victim}/reset-password"
        await mint_bound_proof(c, path)
        r = await c.post(path, headers=SAME_ORIGIN)
    assert r.status_code == 200
    assert "Temporary password issued" in r.text and "<code>" in r.text
    assert f"Convey this to {victim} " in r.text and "Convey this to victim " not in r.text
