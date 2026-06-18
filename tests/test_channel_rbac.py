# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Phase-8 PR C — per-channel RBAC (DLQ-SCOPE): scope enforcement + admin endpoint."""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth import AuthProvider, Identity, Role
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
ADT = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "rbac.db", poll_interval=0.02)
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
    # Admin-created accounts force first-login rotation (WP-L3-12); clear it so these fixtures behave
    # like already-onboarded users (keeping the same hash).
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


# --- Identity unit -----------------------------------------------------------


def test_identity_can_access_channel() -> None:
    allc = Identity.build(user_id="1", username="u", auth_provider=AuthProvider.LOCAL, roles=[])
    assert allc.can_access_channel("anything")  # None scope = all
    scoped = Identity.build(
        user_id="2",
        username="s",
        auth_provider=AuthProvider.LOCAL,
        roles=[],
        allowed_channels=frozenset({"IB_A"}),
    )
    assert scoped.can_access_channel("IB_A")
    assert not scoped.can_access_channel("IB_B")
    assert not scoped.can_access_channel(None)


# --- store filter ------------------------------------------------------------


async def test_store_filters_by_allowed_channels(tmp_path: Path) -> None:
    s = await MessageStore.open(tmp_path / "f.db")
    try:
        await s.enqueue_message(channel_id="A", raw=ADT, deliveries=[])
        await s.enqueue_message(channel_id="B", raw=ADT, deliveries=[])
        assert {r["channel_id"] for r in await s.list_messages(allowed_channels=["A"])} == {"A"}
        assert await s.count_messages(allowed_channels=["A"]) == 1
        assert await s.list_messages(allowed_channels=[]) == []  # scoped to no channels
        assert len(await s.list_messages(allowed_channels=None)) == 2  # all
    finally:
        await s.close()


# --- API enforcement ---------------------------------------------------------


async def test_scoped_user_sees_only_in_scope_messages(engine: Engine) -> None:
    service = await _service(engine)
    uid = await _add(service, "op", Role.OPERATOR)
    await service.set_channel_scope(uid, ["IB_A"], actor="admin")
    await engine.store.enqueue_message(channel_id="IB_A", raw=ADT, deliveries=[])
    await engine.store.enqueue_message(channel_id="IB_B", raw=ADT, deliveries=[])
    async with _client(engine, service) as c:
        h = await _login(c, "op")
        rows = (await c.get("/messages", headers=h)).json()["messages"]
        assert {m["channel_id"] for m in rows} == {"IB_A"}


async def test_scoped_user_detail_and_replay_respect_scope(engine: Engine) -> None:
    service = await _service(engine)
    uid = await _add(service, "op", Role.OPERATOR)
    await service.set_channel_scope(uid, ["IB_A"], actor="admin")
    mid_a = await engine.store.enqueue_message(channel_id="IB_A", raw=ADT, deliveries=[("d", ADT)])
    mid_b = await engine.store.enqueue_message(channel_id="IB_B", raw=ADT, deliveries=[("d", ADT)])
    async with _client(engine, service) as c:
        h = await _login(c, "op")
        assert (await c.get(f"/messages/{mid_a}", headers=h)).status_code == 200
        assert (await c.get(f"/messages/{mid_b}", headers=h)).status_code == 404  # hidden, not 403
        assert (await c.post(f"/messages/{mid_a}/replay", headers=h)).status_code == 200
        assert (await c.post(f"/messages/{mid_b}/replay", headers=h)).status_code == 404
        # the out-of-scope attempts were audited
        assert any(a["action"] == "auth.channel_denied" for a in await engine.store.list_audit())


async def test_scoped_user_connection_control_and_purge(engine: Engine) -> None:
    service = await _service(engine)
    uid = await _add(service, "op", Role.OPERATOR)
    await service.set_channel_scope(uid, ["IB_A"], actor="admin")
    async with _client(engine, service) as c:
        h = await _login(c, "op")
        assert (
            await c.post("/connections/IB_B/stop", headers=h)
        ).status_code == 403  # out of scope
        assert (
            await c.post("/connections/IB_A/stop", headers=h)
        ).status_code != 403  # guard passes
        assert (
            await c.post("/connections/OB_X/purge", headers=h)
        ).status_code == 403  # scoped→no purge


async def test_scoped_user_cannot_test_or_read_shared_outbound(engine: Engine) -> None:
    # A graph so the outbound exists (the test/metadata endpoints 404 a missing name before the scope
    # check). A channel-scoped operator may probe/read their OWN inbound, but a shared outbound — which
    # spans channels — is off-limits, mirroring the purge boundary.
    reg = Registry()
    reg.add_inbound(
        InboundConnection("IB_A", ConnectionSpec(ConnectorType.MLLP, {"port": 2575}), router="r")
    )
    reg.add_outbound(
        OutboundConnection("OB_X", ConnectionSpec(ConnectorType.FILE, {"directory": "./out"}))
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("OB_X", m))
    engine.add_registry(reg)
    service = await _service(engine)
    uid = await _add(service, "op", Role.OPERATOR)
    await service.set_channel_scope(uid, ["IB_A"], actor="admin")
    async with _client(engine, service) as c:
        h = await _login(c, "op")
        assert (await c.post("/connections/OB_X/test", headers=h)).status_code == 403
        assert (await c.get("/connections/OB_X/metadata", headers=h)).status_code == 403
        # ...but the operator's own in-scope inbound metadata is readable.
        assert (await c.get("/connections/IB_A/metadata", headers=h)).status_code == 200
        assert any(a["action"] == "auth.channel_denied" for a in await engine.store.list_audit())


async def test_unscoped_user_and_admin_have_full_access(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)  # no scope set → NULL → all channels
    admin_id = await _add(service, "boss", Role.ADMINISTRATOR)
    await service.set_channel_scope(admin_id, ["IB_A"], actor="admin")  # ignored for admins
    mid_b = await engine.store.enqueue_message(channel_id="IB_B", raw=ADT, deliveries=[("d", ADT)])
    async with _client(engine, service) as c:
        for who in ("op", "boss"):
            h = await _login(c, who)
            assert (await c.get(f"/messages/{mid_b}", headers=h)).status_code == 200


async def test_channel_scope_admin_endpoint_roundtrip(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "boss", Role.ADMINISTRATOR)
    target = await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        h = await _login(c, "boss")
        assert (await c.get(f"/users/{target}/channel-scope", headers=h)).json()["channels"] is None
        r = await c.put(
            f"/users/{target}/channel-scope", json={"channels": ["IB_B", "IB_A"]}, headers=h
        )
        assert r.status_code == 200
        got = (await c.get(f"/users/{target}/channel-scope", headers=h)).json()["channels"]
        assert sorted(got) == ["IB_A", "IB_B"]
        assert any(
            a["action"] == "user.channel_scope_changed" for a in await engine.store.list_audit()
        )
