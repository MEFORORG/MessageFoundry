# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""DR control RBAC + endpoints (#61, ADR 0048). POST /dr/activate and /dr/release are gated by the
dedicated dr:operate permission (held by ADMINISTRATOR, NOT a reuse of connections:control): an OPERATOR
(who holds connections:control but NOT dr:operate) is denied 403 and the denial is audited; an
ADMINISTRATOR is allowed. GET /dr/status reports the posture. A custom role may never grant dr:operate
(it is a carved-out escalation primitive)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth import Permission, Role
from messagefoundry.auth.permissions import (
    CUSTOM_ROLE_FORBIDDEN_PERMISSIONS,
    BUILTIN_ROLE_PERMISSIONS,
    CustomRoleError,
    validate_custom_role_permissions,
)
from messagefoundry.auth.service import AuthService
from messagefoundry.config.models import Priority
from messagefoundry.config.settings import AuthSettings, DrSettings, StoreSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store import MessageStore

PW = "Sup3rSecret!!DR"


# --- unit: the permission catalog + RBAC policy ------------------------------


def test_dr_operate_held_by_administrator_only() -> None:
    # dr:operate is a real catalog permission, held by ADMINISTRATOR, NOT by OPERATOR (which has
    # connections:control) — so DR control is NOT a reuse of connections:control (ratification 2026-06-28).
    assert Permission.DR_OPERATE in BUILTIN_ROLE_PERMISSIONS[Role.ADMINISTRATOR]
    assert Permission.DR_OPERATE not in BUILTIN_ROLE_PERMISSIONS[Role.OPERATOR]
    assert Permission.CONNECTIONS_CONTROL in BUILTIN_ROLE_PERMISSIONS[Role.OPERATOR]


def test_dr_operate_not_assignable_to_a_custom_role() -> None:
    # A site-failover-grade action must stay admin-only: a custom role can never grant dr:operate.
    assert Permission.DR_OPERATE in CUSTOM_ROLE_FORBIDDEN_PERMISSIONS
    with pytest.raises(CustomRoleError):
        validate_custom_role_permissions(["dr:operate"])


# --- endpoint RBAC -----------------------------------------------------------


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    store = await MessageStore.open(tmp_path / "rbac.db")
    eng = Engine(
        store,
        poll_interval=0.02,
        config_dir=None,
        store_settings=StoreSettings(path=str(tmp_path / "rbac.db")),
        dr_settings=DrSettings(enabled=True, activate=False, priority_threshold=Priority.CRITICAL),
    )
    await eng.start()
    yield eng
    await eng.stop()


async def _service(engine: Engine) -> AuthService:
    service = AuthService(engine.store, AuthSettings())
    await service.initialize()
    return service


def _client(engine: Engine, service: AuthService) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=create_app(engine, auth=service))
    return httpx.AsyncClient(transport=transport, base_url="http://t")


async def _add(service: AuthService, username: str, *roles: Role) -> None:
    user_id = await service.create_local_user(
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=[r.value for r in roles],
        actor="test",
    )
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id, password_hash=user.password_hash, must_change_password=False
    )


async def _login(c: httpx.AsyncClient, username: str) -> dict[str, str]:
    r = await c.post(
        "/auth/login", json={"username": username, "password": PW, "provider": "local"}
    )
    return {"Authorization": f"Bearer {r.json()['token']}"}


async def test_operator_denied_admin_allowed_and_audited(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)  # has connections:control, NOT dr:operate
    await _add(service, "dradmin", Role.ADMINISTRATOR)  # has dr:operate
    async with _client(engine, service) as c:
        # OPERATOR is denied 403 on /dr/activate (deny-by-default; connections:control is insufficient).
        op = await _login(c, "op")
        r = await c.post("/dr/activate", headers=op, json={})
        assert r.status_code == 403
        assert "dr:operate" in r.json()["detail"]

        # The denial was audited (permission-denied trail).
        rows = await engine.store.list_audit(limit=50)
        assert any(
            "denied" in (row["action"] or "") and "/dr/activate" in (row["detail"] or "")
            for row in rows
        )

        # ADMINISTRATOR is past the RBAC gate. With no seed archive configured the activation aborts at
        # the cold-seed step (422), NOT at RBAC (403) — proving dr:operate was accepted.
        adm = await _login(c, "dradmin")
        r = await c.post("/dr/activate", headers=adm, json={})
        assert r.status_code == 422  # reached the cold-seed fail-closed, not the RBAC wall

        # GET /dr/status is readable (monitoring:read) and reports the posture.
        s = await c.get("/dr/status", headers=adm)
        assert s.status_code == 200
        body = s.json()
        assert body["enabled"] is True and body["active"] is False
        assert body["threshold"] == "critical" and body["activation_mode"] == "manual"


async def test_release_requires_dr_operate(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op2", Role.OPERATOR)
    async with _client(engine, service) as c:
        op = await _login(c, "op2")
        r = await c.post("/dr/release", headers=op)
        assert r.status_code == 403
        assert "dr:operate" in r.json()["detail"]
