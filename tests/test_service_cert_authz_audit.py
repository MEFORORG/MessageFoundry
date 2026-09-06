# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The mTLS service-identity pathway leaves the SAME authorization trail as the bearer pathway.

ASVS 6.3.4 asks that controls be enforced CONSISTENTLY across every admission pathway, and the
authorization audit is one of those controls. ``require`` writes ``auth.permission_denied`` on a
refusal and ``auth.permission_granted`` on a pass (gated by ``[diagnostics].audit_all_authz``);
``require_service_cert`` wrote neither, so on a first deployment a service principal's authorization
decisions would leave no row in the hash-chained audit log at all -- only a ``log.warning`` on the
denial, which is neither tamper-evident nor queryable.

The 401 arm is deliberately unaudited and that is pinned here too, because "no row" has to be a
written decision rather than an omission: ``require`` does not audit its own 401 either (no identity
resolved, so there is no actor to name), and an audited 401 on a cert route would let a caller who
has proven nothing append to the chain at whatever rate it chooses.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import httpx
from fastapi import Depends

from messagefoundry.api import create_app
from messagefoundry.api.security import require_service_cert
from messagefoundry.api.tls_client_cert import MF_CLIENT_PEERCERT_STATE_KEY
from messagefoundry.auth import Identity, Permission, Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine

_GRANT = "auth.permission_granted"
_DENIED = "auth.permission_denied"


def _peercert(cn: str) -> dict[str, object]:
    """A synthetic ``ssl.getpeercert()`` dict with subject CN ``cn``."""
    return {"subject": ((("commonName", cn),),)}


def _wrap_with_cert(
    app: Any, peercert: object | None
) -> Callable[[Any, Any, Any], Awaitable[None]]:
    """Wrap an ASGI app to inject ``peercert`` into scope['state'], standing in for the connection-made
    shim the ASGI TestClient transport never runs. ``None`` = no client cert presented."""

    async def wrapped(scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] == "http" and peercert is not None:
            state = dict(scope.get("state") or {})
            state[MF_CLIENT_PEERCERT_STATE_KEY] = peercert
            scope = {**scope, "state": state}
        await app(scope, receive, send)

    return wrapped


async def _svc_app(
    tmp_path: Path, db: str, *roles: Role, audit_all_authz: bool = True
) -> tuple[Engine, Any]:
    """An engine + create_app wired with a cert-identity map for username 'svc' (given ``roles``)."""
    engine = await Engine.create(tmp_path / db, poll_interval=0.02)
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    assert await service.create_local_user(
        username="svc",
        password="Correct-horse-battery-9",
        display_name=None,
        email=None,
        roles=[r.value for r in roles],
        actor="test",
    )
    app = create_app(
        engine,
        auth=service,
        tls_client_cert_identities={"CN:svc.internal": "svc"},
        audit_all_authz=audit_all_authz,
    )
    return engine, app


#: Built once at module scope rather than inline in the route signature: B008 is exempted only for the
#: route layers under `messagefoundry/api/**`, and a test that defines a route is not one of them.
_USERS_MANAGE_CERT_DEP = require_service_cert(Permission.USERS_MANAGE)


def _add_privileged_route(app: Any) -> None:
    """A cert-gated route asking for a permission NO built-in role but Administrator grants.

    Needed because every built-in role grants ``MONITORING_READ``, so the shipped ``/service/identity``
    route cannot be made to refuse a role-holding principal -- the denial arm has no other way in."""

    @app.get("/t/users-manage")
    async def _needs_users_manage(  # type: ignore[misc]
        identity: Identity = Depends(_USERS_MANAGE_CERT_DEP),
    ) -> dict[str, str]:
        return {"username": identity.username}


async def _audit_actions(engine: Engine, action: str) -> list[Any]:
    return await engine.store.list_audit(action=action)


async def test_service_cert_permission_denial_writes_an_authorization_audit_row(
    tmp_path: Path,
) -> None:
    """A cert principal refused for a missing permission leaves the same row the bearer path leaves."""
    engine, app = await _svc_app(tmp_path, "svc_authz_denied.db", Role.VIEWER)
    _add_privileged_route(app)
    try:
        transport = httpx.ASGITransport(app=_wrap_with_cert(app, _peercert("svc.internal")))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
            assert (await client.get("/t/users-manage")).status_code == 403
        rows = await _audit_actions(engine, _DENIED)
        assert len(rows) == 1, "the service-cert refusal wrote no authorization-denied audit row"
        assert rows[0]["actor"] == "svc"
        detail = rows[0]["detail"] or ""
        assert Permission.USERS_MANAGE.value in detail
        assert "/t/users-manage" in detail
    finally:
        await engine.stop()


async def test_service_cert_grant_is_audited_on_the_shipped_default(tmp_path: Path) -> None:
    """``audit_all_authz`` is ON by default, so a satisfied cert route records the grant like a
    satisfied bearer route does -- GET included."""
    engine, app = await _svc_app(tmp_path, "svc_authz_grant.db", Role.VIEWER)
    try:
        transport = httpx.ASGITransport(app=_wrap_with_cert(app, _peercert("svc.internal")))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
            assert (await client.get("/service/identity")).status_code == 200
        rows = await _audit_actions(engine, _GRANT)
        assert len(rows) == 1, "the service-cert grant wrote no authorization-granted audit row"
        assert rows[0]["actor"] == "svc"
        detail = rows[0]["detail"] or ""
        assert Permission.MONITORING_READ.value in detail
        assert "/service/identity" in detail
    finally:
        await engine.stop()


async def test_service_cert_grant_follows_the_narrow_trail_when_audit_all_is_off(
    tmp_path: Path,
) -> None:
    """With the switch off the cert path narrows exactly as the bearer path does, rather than keeping
    a second rule: a GET carrying only ``MONITORING_READ`` is outside the sensitive set, so no row."""
    engine, app = await _svc_app(
        tmp_path, "svc_authz_narrow.db", Role.VIEWER, audit_all_authz=False
    )
    try:
        transport = httpx.ASGITransport(app=_wrap_with_cert(app, _peercert("svc.internal")))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
            assert (await client.get("/service/identity")).status_code == 200
        assert await _audit_actions(engine, _GRANT) == []
    finally:
        await engine.stop()


async def test_unauthenticated_service_cert_401_writes_no_authorization_row(
    tmp_path: Path,
) -> None:
    """The BOUND on the arm above. No cert and an unmapped cert both 401 with no identity resolved, so
    neither writes an authorization row -- a caller that has proven nothing cannot grow the chain."""
    engine, app = await _svc_app(tmp_path, "svc_authz_401.db", Role.VIEWER)
    _add_privileged_route(app)
    try:
        for peercert in (None, _peercert("attacker.evil")):
            transport = httpx.ASGITransport(app=_wrap_with_cert(app, peercert))
            async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
                assert (await client.get("/service/identity")).status_code == 401
                assert (await client.get("/t/users-manage")).status_code == 401
        assert await _audit_actions(engine, _DENIED) == []
        assert await _audit_actions(engine, _GRANT) == []
    finally:
        await engine.stop()
