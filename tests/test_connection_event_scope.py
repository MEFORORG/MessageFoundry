# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""SEC-008 — per-channel RBAC scope on the connection-event/topology read surface.

Covers both the store-level ``list_connection_events(allowed_channels=...)`` filter (inbound-only +
channel allow-set + outbound exclusion) and the four API read routes (/channels, /connections,
/events, /connections/{name}/events) that must not leak cross-tenant topology / peer IPs to a
channel-scoped caller."""

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
from messagefoundry.store.store import MessageStore

PW = "Sup3rSecret!!"


# --- store-level filter ------------------------------------------------------


async def _seed_store(s: MessageStore) -> None:
    await s.record_connection_event(
        connection="IB_A",
        transport="mllp",
        direction="inbound",
        kind="established",
        peer_host="10.0.0.1",
        now=100.0,
    )
    await s.record_connection_event(
        connection="IB_B",
        transport="mllp",
        direction="inbound",
        kind="closed",
        peer_host="10.0.0.2",
        reason="eof",
        now=200.0,
    )
    await s.record_connection_event(
        connection="OB_X",
        transport="mllp",
        direction="outbound",
        kind="connection_lost",
        message_id="m1",
        reason="refused",
        now=150.0,
    )


async def test_store_list_events_scope(tmp_path: Path) -> None:
    s = await MessageStore.open(tmp_path / "events.db")
    try:
        await _seed_store(s)
        # default (None) is unchanged: all three rows
        allrows = await s.list_connection_events(allowed_channels=None)
        assert {(e.connection, e.direction) for e in allrows} == {
            ("IB_A", "inbound"),
            ("IB_B", "inbound"),
            ("OB_X", "outbound"),
        }
        # scoped to IB_A: ONLY the IB_A inbound row — no IB_B (out of scope), no outbound OB_X (an
        # outbound spans channels and is excluded whenever a scope is set)
        scoped = await s.list_connection_events(allowed_channels=["IB_A"])
        assert [(e.connection, e.direction) for e in scoped] == [("IB_A", "inbound")]
        # scoped to nothing: empty
        assert await s.list_connection_events(allowed_channels=[]) == []
    finally:
        await s.close()


# --- API enforcement ---------------------------------------------------------

ADT = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\r"


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "scope.db", poll_interval=0.02)
    reg = Registry()
    reg.add_inbound(
        InboundConnection("IB_A", ConnectionSpec(ConnectorType.MLLP, {"port": 25750}), router="r")
    )
    reg.add_inbound(
        InboundConnection("IB_B", ConnectionSpec(ConnectorType.MLLP, {"port": 25751}), router="r")
    )
    reg.add_outbound(
        OutboundConnection("OB_X", ConnectionSpec(ConnectorType.FILE, {"directory": "./out"}))
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("OB_X", m))
    eng.add_registry(reg)
    # Seed inbound events on both inbounds + an outbound event on the shared outbound.
    await eng.store.record_connection_event(
        connection="IB_A",
        transport="mllp",
        direction="inbound",
        kind="established",
        peer_host="10.0.0.1",
        now=100.0,
    )
    await eng.store.record_connection_event(
        connection="IB_B",
        transport="mllp",
        direction="inbound",
        kind="closed",
        peer_host="10.0.0.2",
        reason="eof",
        now=200.0,
    )
    await eng.store.record_connection_event(
        connection="OB_X",
        transport="mllp",
        direction="outbound",
        kind="connection_lost",
        message_id="m1",
        reason="refused",
        now=150.0,
    )
    yield eng
    await eng.stop()


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


async def test_scoped_operator_topology_and_events_are_filtered(engine: Engine) -> None:
    service = await _service(engine)
    uid = await _add(service, "op", Role.OPERATOR)
    await service.set_channel_scope(uid, ["IB_A"], actor="admin")
    async with _client(engine, service) as c:
        h = await _login(c, "op")

        # /channels: only the scoped inbound
        chans = (await c.get("/channels", headers=h)).json()
        assert [ch["id"] for ch in chans] == ["IB_A"]

        # /connections: only IB_A's source row, and NO shared-outbound (OB_X) destination/peer row
        conns = (await c.get("/connections", headers=h)).json()
        assert {row["channel_id"] for row in conns} == {"IB_A"}
        assert all(row["role"] == "source" for row in conns)
        assert all(row["destination"] is None for row in conns)

        # /events: only IB_A's inbound events (no IB_B, no outbound OB_X)
        events = (await c.get("/events", headers=h)).json()
        assert {e["connection"] for e in events} == {"IB_A"}
        assert all(e["direction"] == "inbound" for e in events)

        # explicit out-of-scope connection= → 403 + audit
        assert (await c.get("/events", params={"connection": "IB_B"}, headers=h)).status_code == 403
        # per-connection route 403s for an out-of-scope inbound and for the shared outbound
        assert (await c.get("/connections/IB_B/events", headers=h)).status_code == 403
        assert (await c.get("/connections/OB_X/events", headers=h)).status_code == 403
        # but the operator's own inbound events ARE readable
        assert (await c.get("/connections/IB_A/events", headers=h)).status_code == 200

        assert any(a["action"] == "auth.channel_denied" for a in await engine.store.list_audit())


async def test_event_info_carries_no_phi_field(engine: Engine) -> None:
    service = await _service(engine)
    uid = await _add(service, "op", Role.OPERATOR)
    await service.set_channel_scope(uid, ["IB_A"], actor="admin")
    # Seed an in-scope inbound 'closed' so we can assert its reason is the safe_text-scrubbed value.
    await engine.store.record_connection_event(
        connection="IB_A",
        transport="mllp",
        direction="inbound",
        kind="closed",
        peer_host="10.0.0.1",
        reason="eof",
        now=300.0,
    )
    async with _client(engine, service) as c:
        h = await _login(c, "op")
        events = (await c.get("/events", headers=h)).json()
        assert events, "expected at least the IB_A inbound events"
        # The metadata-only shape: no body/summary/raw field can leak via this surface.
        assert set(events[0]) == {
            "id",
            "ts",
            "connection",
            "transport",
            "direction",
            "kind",
            "peer_host",
            "message_id",
            "reason",
        }
        closed = next(e for e in events if e["kind"] == "closed")
        # reason is the safe_text-scrubbed value, never a message body.
        assert closed["reason"] == "eof"


async def test_unscoped_operator_sees_full_estate(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)  # no scope → NULL → all channels
    async with _client(engine, service) as c:
        h = await _login(c, "op")
        chans = (await c.get("/channels", headers=h)).json()
        assert {ch["id"] for ch in chans} == {"IB_A", "IB_B"}
        events = (await c.get("/events", headers=h)).json()
        assert {e["connection"] for e in events} == {"IB_A", "IB_B", "OB_X"}
        # out-of-scope routes are unrestricted for an unscoped caller
        assert (await c.get("/events", params={"connection": "IB_B"}, headers=h)).status_code == 200
        assert (await c.get("/connections/IB_B/events", headers=h)).status_code == 200
