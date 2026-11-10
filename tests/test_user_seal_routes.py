# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5520: the admin user reads serve only an account record that passes its seal.

``GET /users``, ``GET /users/{id}/federated-identity``, ``GET /users/{id}/channel-scope`` and
``GET /users/{id}/permissions`` read through :meth:`AuthService.checked_user` and
:meth:`AuthService.list_checked_users`, so a row altered outside the store is never served with a
200, and its failure writes the ``integrity.authority_seal_failed`` row and raises the alert. The
list keeps such an account by id alone (:class:`IntegrityFailedUser`); each single-account read, and
``PATCH /users/{id}``, answers 423. Each test has a control: the same read of an intact account,
and of an unknown id, which stays a 404.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.api.auth_models import IntegrityFailedUser, UserListEntry, UserSummary
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
from messagefoundry.store.store import AdminRemoval, MessageStore
from tests.test_api_auth import ABSENT_USER_ID, _add, _auth, _login, _reauth
from tests.test_user_seal import _raw_for

#: What the tampering writes. None of it may appear in an answer.
_PLANTED = "planted-outside-the-store"


@pytest.fixture
async def keyed(tmp_path: Path) -> AsyncIterator[tuple[Engine, Path]]:
    path = tmp_path / "sealed_routes.db"
    store = await MessageStore.open(path, cipher=make_cipher(generate_key(), write_v2=True))
    engine = Engine(
        store, poll_interval=0.02, egress_settings=EgressSettings(deny_by_default=False)
    )
    try:
        yield engine, path
    finally:
        await engine.stop()


async def _tamper(path: Path, user_id: str) -> None:
    """Alter the account's sealed fields on a connection that holds no store key."""
    await _raw_for(path)(
        "UPDATE users SET display_name=?, channel_scope=?, oidc_issuer=?, oidc_subject=? WHERE id=?",
        (_PLANTED, f'["{_PLANTED}"]', _PLANTED, _PLANTED, user_id),
    )


async def _setup(engine: Engine) -> tuple[AuthService, list[str], str, str]:
    """An administrator, an intact viewer and a viewer whose row is then tampered with."""
    alerts: list[str] = []
    service = AuthService(
        engine.store,
        AuthSettings(admin_write_min_interval_seconds=0, require_mfa=False),
        integrity_alert=alerts.append,
    )
    await service.initialize()
    await _add(service, "root", Role.ADMINISTRATOR)
    intact = await _add(service, "intact", Role.VIEWER)
    victim = await _add(service, "victim", Role.VIEWER)
    return service, alerts, intact, victim


def _client(engine: Engine, service: AuthService) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=create_app(engine, auth=service), client=("127.0.0.1", 1))
    return httpx.AsyncClient(transport=transport, base_url="http://t")


async def _seal_failures(engine: Engine, user_id: str) -> int:
    rows = await engine.store.list_audit(action=AUTHORITY_SEAL_FAILED_ACTION, limit=10_000)
    return sum(1 for row in rows if user_id in str(row["detail"]))


async def test_get_users_lists_a_failing_account_by_id_alone(keyed: tuple[Engine, Path]) -> None:
    engine, path = keyed
    service, alerts, intact, victim = await _setup(engine)
    async with _client(engine, service) as c:
        token = (await _login(c, "root")).json()["token"]
        before = await c.get("/users", headers=_auth(token))
        assert before.status_code == 200
        # Control: before the tampering every row is a full summary.
        assert all("username" in row for row in before.json())
        await _tamper(path, victim)
        resp = await c.get("/users", headers=_auth(token))
    assert resp.status_code == 200
    assert _PLANTED not in resp.text
    rows = {row["id"]: row for row in resp.json()}
    # The pinned shape: the id and the flag, and nothing else of the row.
    assert rows[victim] == {"id": victim, "integrity_failed": True}
    # The intact account is untouched, its roles read from the checked record.
    assert rows[intact]["username"] == "intact"
    assert rows[intact]["roles"] == [Role.VIEWER.value]
    assert "integrity_failed" not in rows[intact]
    assert await _seal_failures(engine, victim) >= 1
    assert any(victim in alert for alert in alerts)


@pytest.mark.parametrize("suffix", ["federated-identity", "channel-scope", "permissions"])
async def test_a_single_account_read_answers_423_for_a_failing_record(
    keyed: tuple[Engine, Path], suffix: str
) -> None:
    engine, path = keyed
    service, alerts, intact, victim = await _setup(engine)
    await _tamper(path, victim)
    async with _client(engine, service) as c:
        token = (await _login(c, "root")).json()["token"]
        refused = await c.get(f"/users/{victim}/{suffix}", headers=_auth(token))
        served = await c.get(f"/users/{intact}/{suffix}", headers=_auth(token))
        absent = await c.get(f"/users/{ABSENT_USER_ID}/{suffix}", headers=_auth(token))
    assert refused.status_code == 423, refused.text
    assert refused.json()["detail"] == USER_SEAL_REFUSED
    assert _PLANTED not in refused.text
    assert await _seal_failures(engine, victim) >= 1
    assert any(victim in alert for alert in alerts)
    # Controls: an intact account is served, and an unknown one is still a 404.
    assert served.status_code == 200
    assert absent.status_code == 404


async def test_the_permissions_read_lists_the_checked_roles(keyed: tuple[Engine, Path]) -> None:
    """The role ids come from the record the seal covered, not a second, unchecked store read."""
    engine, _ = keyed
    service, _alerts, intact, _victim = await _setup(engine)

    async def no_bare_role_read(user_id: str) -> list[str]:
        raise AssertionError("the bare role-id reader was called")

    engine.store.get_user_role_ids = no_bare_role_read  # type: ignore[method-assign]
    async with _client(engine, service) as c:
        token = (await _login(c, "root")).json()["token"]
        resp = await c.get(f"/users/{intact}/permissions", headers=_auth(token))
        listed = await c.get("/users", headers=_auth(token))
    assert resp.status_code == 200 and resp.json()["roles"] == [Role.VIEWER.value]
    assert listed.status_code == 200


async def test_patch_answers_423_for_a_failing_record(keyed: tuple[Engine, Path]) -> None:
    engine, path = keyed
    service, _alerts, intact, victim = await _setup(engine)
    await _tamper(path, victim)
    async with _client(engine, service) as c:
        token = (await _login(c, "root")).json()["token"]
        _, token = await _reauth(c, token, purpose="admin_user_update")
        refused = await c.patch(
            f"/users/{victim}", json={"display_name": "x"}, headers=_auth(token)
        )
        _, token = await _reauth(c, token, purpose="admin_user_update")
        absent = await c.patch(
            f"/users/{ABSENT_USER_ID}", json={"display_name": "x"}, headers=_auth(token)
        )
        _, token = await _reauth(c, token, purpose="admin_user_update")
        served = await c.patch(f"/users/{intact}", json={"display_name": "x"}, headers=_auth(token))
    assert refused.status_code == 423, refused.text
    assert _PLANTED not in refused.text
    assert absent.status_code == 404
    assert served.status_code == 200, served.text
    assert await _seal_failures(engine, victim) >= 1


async def test_checked_user_tells_a_failing_record_from_a_missing_one(
    keyed: tuple[Engine, Path],
) -> None:
    engine, path = keyed
    service, _alerts, intact, victim = await _setup(engine)
    await _tamper(path, victim)
    checked = await service.checked_user(intact)
    assert checked is not None and checked.role_ids == (Role.VIEWER.value,)
    assert await service.checked_user(ABSENT_USER_ID) is None
    with pytest.raises(UserSealRefused):
        await service.checked_user(victim)
    listed = {entry.id: entry.user for entry in await service.list_checked_users()}
    assert listed[victim] is None and listed[intact] is not None


async def test_a_listed_account_deleted_mid_read_is_left_out(keyed: tuple[Engine, Path]) -> None:
    """A row the list read that is gone by its re-read is not an integrity failure."""
    engine, _ = keyed
    service, _alerts, _intact, victim = await _setup(engine)
    original = engine.store.list_users

    async def list_then_delete() -> list[object]:
        rows = await original()
        await engine.store.remove_unless_last_admin(
            victim, AdminRemoval.DELETE, admin_role_id=Role.ADMINISTRATOR.value
        )
        return list(rows)

    engine.store.list_users = list_then_delete  # type: ignore[method-assign,assignment]
    listed = await service.list_checked_users()
    assert victim not in {entry.id for entry in listed}
    assert await _seal_failures(engine, victim) == 0


def test_a_user_list_entry_reads_either_shape_and_never_the_other() -> None:
    """The pinned wire shape: a summary payload never reads as a failed row, and a failed row,
    which carries no name, provider, flag or roles, never reads as a summary."""
    from pydantic import TypeAdapter

    entry: TypeAdapter[UserListEntry] = TypeAdapter(UserListEntry)
    summary = entry.validate_python(
        {
            "id": "a",
            "username": "a",
            "auth_provider": "local",
            "disabled": False,
            "roles": [],
            "channel_scope_withheld": True,
        }
    )
    assert isinstance(summary, UserSummary)
    failed = entry.validate_python({"id": "b", "integrity_failed": True})
    assert isinstance(failed, IntegrityFailedUser)
    assert IntegrityFailedUser.model_fields.keys() == {"id", "integrity_failed"}
    with pytest.raises(ValueError):
        IntegrityFailedUser.model_validate({"id": "c"})
