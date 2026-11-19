# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A custom role deleted between a route's role check and its role write (BACKLOG #5968).

``_validate_roles`` reads the custom roles in a call of its own, before the write. A delete that
commits in between reaches the write, which the store refuses: with ``UnknownRoleError`` from
``existing_roles_only``, or with the driver's integrity error from a role foreign key. Each route
that writes roles answers that 400, as its up-front check does, never 500. ``POST /users`` also
removes the roleless account its first write committed, so a retry under the same name is not
refused as taken.

The race is staged by deleting the role inside the store write the route reaches, after the
route's check read it as present.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path
from typing import Any

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.service import AuthService, _role_write_refusal
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store.store import UnknownRoleError
from tests._admin_account import create_local_user_chosen

PW = "a-strong-test-passphrase"
AD_GROUP = "CN=Ops,OU=Groups,DC=example,DC=org"


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(
        tmp_path / "role_race.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


async def _service(engine: Engine) -> AuthService:
    # require_mfa=False and no write interval: a fresh login's step-up covers the admin routes, so
    # the answers below are the role write's and not a gate's.
    service = AuthService(
        engine.store, AuthSettings(require_mfa=False, admin_write_min_interval_seconds=0)
    )
    await service.initialize()
    return service


async def _make_user(service: AuthService, username: str, *roles: str) -> str:
    user_id = await create_local_user_chosen(
        service,
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=list(roles),
        actor="test",
    )
    await service.set_channel_scope(user_id, [ALL_CHANNELS], actor="test")
    return user_id


async def _admin_headers(service: AuthService, client: httpx.AsyncClient) -> dict[str, str]:
    user_id = await _make_user(service, "adm", Role.ADMINISTRATOR.value)
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id,
        password_hash=user.password_hash,
        must_change_password=False,
        password_generated=False,
    )
    login = await client.post(
        "/auth/login", json={"username": "adm", "password": PW, "provider": "local"}
    )
    assert login.status_code == 200, login.text
    return {"Authorization": f"Bearer {login.json()['token']}"}


def _client(engine: Engine, service: AuthService) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=create_app(engine, auth=service))
    return httpx.AsyncClient(transport=transport, base_url="http://t")


async def _custom_role(service: AuthService) -> str:
    role = await service.create_custom_role(
        display_name="Temp", description=None, permissions=["monitoring:read"], actor="test"
    )
    return role.id


def _delete_first(
    monkeypatch: pytest.MonkeyPatch, service: AuthService, method: str, role_id: str
) -> None:
    """Make the store's ``method`` delete ``role_id`` before it writes, once: the delete commits
    after the route's check and before the write's transaction, which is the race."""
    original: Callable[..., Awaitable[Any]] = getattr(service.store, method)
    fired = False

    async def racing(*args: Any, **kwargs: Any) -> Any:
        nonlocal fired
        if not fired:
            fired = True
            await service.delete_custom_role(role_id, actor="other-admin")
        return await original(*args, **kwargs)

    monkeypatch.setattr(service.store, method, racing)


async def test_create_user_racing_a_role_delete_is_400_and_leaves_no_account(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = await _service(engine)
    async with _client(engine, service) as c:
        headers = await _admin_headers(service, c)
        role_id = await _custom_role(service)
        _delete_first(monkeypatch, service, "set_user_roles", role_id)
        body = {"username": "newbie", "roles": [role_id], "email": "newbie@example.org"}
        r = await c.post("/users", headers=headers, json=body)
        assert r.status_code == 400, r.text
        assert r.json()["detail"] == f"unknown role(s): {role_id}"
        # The account the first write committed was removed, so the name is free again.
        assert await service.store.get_user_by_username("newbie") is None
        # Control: the retry, naming a role that exists, creates the account under that name.
        retry = {"username": "newbie", "roles": ["viewer"], "email": "newbie@example.org"}
        r = await c.post("/users", headers=headers, json=retry)
        assert r.status_code == 201, r.text


async def test_the_orphan_removal_after_a_role_write_race_is_audited(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #5968: removing the roleless account a refused role write left is a user deletion,
    so it writes the ``user.deleted`` row every other deletion writes, naming the account, the
    acting administrator and the race as its reason."""
    service = await _service(engine)
    async with _client(engine, service) as c:
        headers = await _admin_headers(service, c)
        role_id = await _custom_role(service)
        written: list[str] = []
        original: Callable[..., Awaitable[Any]] = service.store.set_user_roles

        async def recording(user_id: str, *args: Any, **kwargs: Any) -> Any:
            written.append(user_id)
            return await original(user_id, *args, **kwargs)

        monkeypatch.setattr(service.store, "set_user_roles", recording)
        _delete_first(monkeypatch, service, "set_user_roles", role_id)
        body = {"username": "orphan", "roles": [role_id], "email": "orphan@example.org"}
        r = await c.post("/users", headers=headers, json=body)
        assert r.status_code == 400, r.text
    [orphan_id] = written
    assert await service.store.get_user(orphan_id) is None
    rows = await service.store.list_audit(action="user.deleted", limit=10)
    [row] = [row for row in rows if json.loads(row["detail"])["user_id"] == orphan_id]
    assert row["actor"] == "adm"
    detail = json.loads(row["detail"])
    assert detail["username"] == "orphan" and detail["roles"] == [role_id]
    assert "role write" in detail["reason"]


async def test_a_refused_orphan_removal_row_keeps_the_400_and_is_logged(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """BACKLOG #5968: a store refusal of the orphan removal's ``user.deleted`` row does not mask
    the role refusal. The route still answers 400, the account is still removed, and the log
    line names the account."""
    service = await _service(engine)
    async with _client(engine, service) as c:
        headers = await _admin_headers(service, c)
        role_id = await _custom_role(service)
        _delete_first(monkeypatch, service, "set_user_roles", role_id)
        original: Callable[..., Awaitable[Any]] = service.store.record_audit

        async def refusing(action: str, *args: Any, **kwargs: Any) -> Any:
            if action == "user.deleted":
                raise sqlite3.OperationalError("synthetic audit refusal")
            return await original(action, *args, **kwargs)

        monkeypatch.setattr(service.store, "record_audit", refusing)
        body = {"username": "orphan2", "roles": [role_id], "email": "orphan2@example.org"}
        r = await c.post("/users", headers=headers, json=body)
        assert r.status_code == 400, r.text
    assert await service.store.get_user_by_username("orphan2") is None
    [record] = [
        rec for rec in caplog.records if "user.deleted row could not be written" in rec.message
    ]
    assert record.args is not None and len(record.args) == 1


async def test_set_roles_racing_a_role_delete_is_400_and_writes_nothing(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = await _service(engine)
    async with _client(engine, service) as c:
        headers = await _admin_headers(service, c)
        target = await _make_user(service, "target", Role.VIEWER.value)
        role_id = await _custom_role(service)
        _delete_first(monkeypatch, service, "remove_unless_last_admin", role_id)
        r = await c.put(f"/users/{target}/roles", headers=headers, json={"roles": [role_id]})
        assert r.status_code == 400, r.text
        assert r.json()["detail"] == f"unknown role(s): {role_id}"
        assert await service.store.get_user_role_ids(target) == [Role.VIEWER.value]


async def test_ad_group_map_racing_a_role_delete_is_400_and_writes_nothing(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    # On SQLite the map's role foreign key refuses the row, so this is the integrity-error path.
    service = await _service(engine)
    async with _client(engine, service) as c:
        headers = await _admin_headers(service, c)
        role_id = await _custom_role(service)
        _delete_first(monkeypatch, service, "set_ad_group_role_map", role_id)
        body = {"entries": [{"ad_group": AD_GROUP, "role": role_id}]}
        r = await c.put("/ad-group-map", headers=headers, json=body)
        assert r.status_code == 400, r.text
        assert r.json()["detail"] == f"unknown role(s): {role_id}"
        assert await service.list_ad_group_role_map() == []


def test_role_write_refusal_reads_both_store_refusals_and_nothing_else() -> None:
    unknown = UnknownRoleError(["custom:a"])
    assert _role_write_refusal(unknown, ["custom:a"], None) is unknown
    # An integrity error names no key: it is a deleted role only for the requested custom ids the
    # re-read no longer holds, and it names just those.
    fk = _role_write_refusal(
        sqlite3.IntegrityError("FOREIGN KEY constraint failed"),
        ["viewer", "custom:b", "custom:c"],
        ["viewer", "custom:c"],
    )
    assert fk is not None and fk.role_ids == ("custom:b",)
    # Controls: with every requested custom role still present, with only built-ins, with no role
    # at all, or with no re-read, the integrity error is something else, at least an audit-key
    # collision, and the caller re-raises it.
    integrity = sqlite3.IntegrityError("UNIQUE constraint failed: audit_log.seq")
    assert _role_write_refusal(integrity, ["custom:b"], ["custom:b"]) is None
    assert _role_write_refusal(integrity, ["viewer"], []) is None
    # A requested id that is not a custom role id is never read as a deleted custom role.
    assert _role_write_refusal(integrity, ["retired-builtin"], []) is None
    assert _role_write_refusal(integrity, [], []) is None
    assert _role_write_refusal(integrity, ["custom:b"], None) is None
    # Control: any other failure is not a role refusal and is re-raised by the caller.
    locked = sqlite3.OperationalError("database is locked")
    assert _role_write_refusal(locked, ["custom:a"], []) is None
    assert _role_write_refusal(RuntimeError("boom"), ["custom:a"], []) is None


async def test_set_roles_integrity_error_with_the_role_present_is_not_a_400(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An integrity error from the role write while every role it names still exists, here a
    staged audit-key collision, is not reported as an unknown role: the service re-raises it."""
    service = await _service(engine)
    target = await _make_user(service, "target", Role.VIEWER.value)
    role_id = await _custom_role(service)

    async def collide(*_args: Any, **_kwargs: Any) -> Any:
        raise sqlite3.IntegrityError("UNIQUE constraint failed: audit_log.seq")

    monkeypatch.setattr(service.store, "remove_unless_last_admin", collide)
    with pytest.raises(sqlite3.IntegrityError):
        await service.set_roles(target, [role_id], actor="test")
