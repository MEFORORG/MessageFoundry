# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The operator alert-state API (ADR 0044, #56): GET /alerts/active + ack/resolve (RBAC
monitoring:diagnose + per-channel scope) and the wired ConnectionRow.alerts_active open count."""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.models import ConnectorType
from messagefoundry.config.settings import AuthSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.pipeline import Engine

PW = "Sup3rSecret!!"


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "alerts.db", poll_interval=0.02)
    reg = Registry()
    reg.add_inbound(
        InboundConnection("IB_A", ConnectionSpec(ConnectorType.MLLP, {"port": 25770}), router="r")
    )
    reg.add_inbound(
        InboundConnection("IB_B", ConnectionSpec(ConnectorType.MLLP, {"port": 25771}), router="r")
    )
    reg.add_outbound(
        OutboundConnection("OB_X", ConnectionSpec(ConnectorType.FILE, {"directory": "./out"}))
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("OB_X", m))
    eng.add_registry(reg)
    yield eng
    await eng.stop()


@pytest.fixture
async def noauth_client(engine: Engine) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=create_app(engine, allow_no_auth=True))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        yield c


# --- GET /alerts/active + ack/resolve over the API ---------------------------


async def test_active_list_ack_resolve_round_trip(
    engine: Engine, noauth_client: httpx.AsyncClient
) -> None:
    await engine.store.upsert_alert_instance(
        event_type="connection_error", connection="OB_X", severity="critical", now=100.0
    )
    r = await noauth_client.get("/alerts/active")
    assert r.status_code == 200
    alerts = r.json()["alerts"]
    assert len(alerts) == 1
    a = alerts[0]
    assert a["event_type"] == "connection_error" and a["status"] == "open" and a["count"] == 1
    alert_id = a["id"]

    # ack: status flips, acked_by recorded, an alert_ack audit row written
    ra = await noauth_client.post(f"/alerts/{alert_id}/ack")
    assert ra.status_code == 200 and ra.json()["status"] == "acknowledged"
    assert ra.json()["acked_by"] is not None
    ack_rows = [r for r in await engine.store.list_audit(limit=100) if r["action"] == "alert_ack"]
    assert len(ack_rows) == 1
    assert "OB_X" not in (ack_rows[0]["detail"] or "")  # metadata-only (just the id), no body

    # acknowledged is still on the active list (visible) but no longer "open"
    still = (await noauth_client.get("/alerts/active")).json()["alerts"]
    assert [x["id"] for x in still] == [alert_id]

    # resolve: drops from the active list, audited
    rr = await noauth_client.post(f"/alerts/{alert_id}/resolve")
    assert rr.status_code == 200 and rr.json()["status"] == "resolved"
    assert (await noauth_client.get("/alerts/active")).json()["alerts"] == []
    resolve_rows = [
        r for r in await engine.store.list_audit(limit=100) if r["action"] == "alert_resolve"
    ]
    assert len(resolve_rows) == 1

    # ack/resolve of an unknown or already-resolved id → 404
    assert (await noauth_client.post(f"/alerts/{alert_id}/ack")).status_code == 404
    assert (await noauth_client.post("/alerts/999999/resolve")).status_code == 404


# --- ConnectionRow.alerts_active (AC-6) --------------------------------------


async def test_alerts_active_reflects_open_count(
    engine: Engine, noauth_client: httpx.AsyncClient
) -> None:
    # No alerts → every row reads 0 (the stub is gone, the real count is 0).
    rows = (await noauth_client.get("/connections")).json()
    src = next(r for r in rows if r["channel_id"] == "IB_A" and r["role"] == "source")
    assert src["alerts_active"] == 0

    # Two OPEN instances on IB_A → the source row reads 2; an acknowledged one is NOT counted.
    await engine.store.upsert_alert_instance(
        event_type="connection_stopped", connection="IB_A", severity="critical", now=100.0
    )
    await engine.store.upsert_alert_instance(
        event_type="queue_buildup", connection="IB_A", severity="warning", now=101.0
    )
    rows = (await noauth_client.get("/connections")).json()
    src = next(r for r in rows if r["channel_id"] == "IB_A" and r["role"] == "source")
    assert src["alerts_active"] == 2

    (acked,) = [
        x
        for x in (await engine.store.list_active_alert_instances())
        if x.event_type == "queue_buildup"
    ]
    await engine.store.ack_alert_instance(acked.id, actor="op")
    rows = (await noauth_client.get("/connections")).json()
    src = next(r for r in rows if r["channel_id"] == "IB_A" and r["role"] == "source")
    assert src["alerts_active"] == 1  # acknowledged dropped the badge


# --- RBAC: monitoring:diagnose + per-channel scope (AC-7) --------------------


async def _service(engine: Engine) -> AuthService:
    service = AuthService(engine.store, AuthSettings())
    await service.initialize()
    return service


def _client(engine: Engine, service: AuthService) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=create_app(engine, auth=service))
    return httpx.AsyncClient(transport=transport, base_url="http://t")


async def _add(service: AuthService, username: str, *roles: Role) -> str:
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
    return user_id


async def _login(c: httpx.AsyncClient, username: str) -> dict[str, str]:
    r = await c.post(
        "/auth/login", json={"username": username, "password": PW, "provider": "local"}
    )
    return {"Authorization": f"Bearer {r.json()['token']}"}


async def test_alerts_routes_require_diagnose(engine: Engine) -> None:
    # AC-7: monitoring:diagnose is required; a VIEWER (monitoring:read only) is denied.
    service = await _service(engine)
    await _add(service, "viewer", Role.VIEWER)
    await _add(service, "operator", Role.OPERATOR)
    await engine.store.upsert_alert_instance(
        event_type="connection_error", connection="IB_A", severity="critical", now=100.0
    )
    async with _client(engine, service) as c:
        vh = await _login(c, "viewer")
        assert (await c.get("/alerts/active", headers=vh)).status_code == 403
        (a,) = await engine.store.list_active_alert_instances()
        assert (await c.post(f"/alerts/{a.id}/ack", headers=vh)).status_code == 403

        oh = await _login(c, "operator")
        assert (await c.get("/alerts/active", headers=oh)).status_code == 200
        assert (await c.post(f"/alerts/{a.id}/ack", headers=oh)).status_code == 200


async def test_alerts_active_per_channel_scope(engine: Engine) -> None:
    # AC-7: a channel-scoped operator sees only their own connections' instances.
    service = await _service(engine)
    uid = await _add(service, "op", Role.OPERATOR)
    await service.set_channel_scope(uid, ["IB_A"], actor="admin")
    await engine.store.upsert_alert_instance(
        event_type="connection_stopped", connection="IB_A", severity="critical", now=100.0
    )
    await engine.store.upsert_alert_instance(
        event_type="connection_stopped", connection="IB_B", severity="critical", now=110.0
    )
    async with _client(engine, service) as c:
        h = await _login(c, "op")
        alerts = (await c.get("/alerts/active", headers=h)).json()["alerts"]
        assert {x["connection"] for x in alerts} == {"IB_A"}  # IB_B is out of scope


async def test_alerts_ack_resolve_out_of_scope_refused_no_mutation(engine: Engine) -> None:
    # AC-7 (mutation path): a channel-scoped operator may NOT ack/resolve an instance whose connection
    # is outside its scope. The mutation must be refused (404) with NO state change and NO audit row —
    # the gap before the fix was that the store UPDATE ran unscoped and an audit row was written.
    service = await _service(engine)
    uid = await _add(service, "op", Role.OPERATOR)
    await service.set_channel_scope(uid, ["IB_A"], actor="admin")
    # An OPEN instance on IB_B (out of scope for "op").
    await engine.store.upsert_alert_instance(
        event_type="connection_stopped", connection="IB_B", severity="critical", now=100.0
    )
    (inst,) = await engine.store.list_active_alert_instances()  # the IB_B instance
    assert inst.connection == "IB_B" and inst.status == "open"

    async with _client(engine, service) as c:
        h = await _login(c, "op")
        assert (await c.post(f"/alerts/{inst.id}/ack", headers=h)).status_code == 404
        assert (await c.post(f"/alerts/{inst.id}/resolve", headers=h)).status_code == 404

    # NO state change: the instance is still open, un-acked, un-resolved.
    (after,) = await engine.store.list_active_alert_instances()
    assert after.id == inst.id
    assert after.status == "open" and after.acked_by is None and after.resolved_at is None

    # NO audit row for the refused mutations (neither alert_ack nor alert_resolve under "op").
    audit = await engine.store.list_audit(limit=100)
    assert not [r for r in audit if r["action"] in ("alert_ack", "alert_resolve")]

    # Sanity: an IN-scope operator CAN ack the same kind of instance + IS audited.
    await engine.store.upsert_alert_instance(
        event_type="connection_stopped", connection="IB_A", severity="critical", now=200.0
    )
    in_scope = next(
        x for x in await engine.store.list_active_alert_instances() if x.connection == "IB_A"
    )
    async with _client(engine, service) as c:
        h = await _login(c, "op")
        assert (await c.post(f"/alerts/{in_scope.id}/ack", headers=h)).status_code == 200
    ack_rows = [r for r in await engine.store.list_audit(limit=100) if r["action"] == "alert_ack"]
    assert len(ack_rows) == 1
