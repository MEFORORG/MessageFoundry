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
    # Channel-scope RBAC test, not an MFA test: pin require_mfa=False so the admin's step-up scope
    # endpoint isn't blocked first by the BACKLOG #187 secure default (require_mfa now ON).
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
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
        # The dual-role start/stop/restart handlers refuse a channel-scoped user on the shared outbound
        # too (an outbound spans channels — same boundary as test/metadata/purge), not a 404.
        assert (await c.post("/connections/OB_X/stop", headers=h)).status_code == 403
        assert (await c.post("/connections/OB_X/restart", headers=h)).status_code == 403
        # ...but the operator's own in-scope inbound metadata is readable.
        assert (await c.get("/connections/IB_A/metadata", headers=h)).status_code == 200
        assert any(a["action"] == "auth.channel_denied" for a in await engine.store.list_audit())


async def test_scoped_user_graph_edges_hides_shared_outbound(engine: Engine) -> None:
    """#76 review (SECURITY): GET /graph/edges must NOT leak shared-outbound topology or live status to a
    channel-scoped user — an outbound spans channels, so its state can reflect ANOTHER channel's
    downstream. Mirroring the connections dashboard (which shows a scoped user NO destination rows), a
    scoped caller sees ONLY the inbound→router→handler subgraph for their accessible inbounds: no shared-
    outbound node, no status, no handler→outbound edge, and no other channel's inbound/router/handler."""
    reg = Registry()
    reg.add_inbound(
        InboundConnection("IB_A", ConnectionSpec(ConnectorType.MLLP, {"port": 2601}), router="r_a")
    )
    reg.add_inbound(
        InboundConnection("IB_B", ConnectionSpec(ConnectorType.MLLP, {"port": 2602}), router="r_b")
    )
    reg.add_outbound(
        OutboundConnection("OB_SHARED", ConnectionSpec(ConnectorType.FILE, {"directory": "./out"}))
    )
    reg.add_router("r_a", lambda m: ["h_a"])
    reg.add_router("r_b", lambda m: ["h_b"])
    reg.add_handler("h_a", lambda m: Send("OB_SHARED", m))
    reg.add_handler("h_b", lambda m: Send("OB_SHARED", m))
    engine.add_registry(reg)
    service = await _service(engine)
    scoped_uid = await _add(service, "op", Role.OPERATOR)
    await service.set_channel_scope(scoped_uid, ["IB_A"], actor="admin")
    await _add(service, "boss", Role.OPERATOR)  # NO channel scope → unscoped

    async with _client(engine, service) as c:
        scoped = (await c.get("/graph/edges", headers=await _login(c, "op"))).json()
        full = (await c.get("/graph/edges", headers=await _login(c, "boss"))).json()

    # Scoped: only IB_A's subgraph (its router + handler). No IB_B, no shared outbound, no status leak.
    scoped_nodes = {(n["kind"], n["name"]) for n in scoped["nodes"]}
    assert ("inbound", "IB_A") in scoped_nodes
    assert ("router", "r_a") in scoped_nodes
    assert ("handler", "h_a") in scoped_nodes
    assert ("inbound", "IB_B") not in scoped_nodes  # another channel's inbound is hidden
    assert ("router", "r_b") not in scoped_nodes
    assert all(n["kind"] != "outbound" for n in scoped["nodes"])  # NO shared-outbound node/status
    # No edge touches a shared outbound (no handler→outbound edge, so no cross-channel state disclosure).
    assert all(
        e["source_kind"] != "outbound" and e["target_kind"] != "outbound" for e in scoped["edges"]
    )
    scoped_edges = {
        (e["source_kind"], e["source"], e["target_kind"], e["target"]) for e in scoped["edges"]
    }
    assert ("inbound", "IB_A", "router", "r_a") in scoped_edges
    assert ("router", "r_a", "handler", "h_a") in scoped_edges
    assert ("handler", "h_a", "outbound", "OB_SHARED") not in scoped_edges

    # Unscoped (no channel scope): the WHOLE estate, including the shared outbound + both channels.
    full_nodes = {(n["kind"], n["name"]) for n in full["nodes"]}
    assert ("outbound", "OB_SHARED") in full_nodes
    assert ("inbound", "IB_B") in full_nodes
    full_edges = {
        (e["source_kind"], e["source"], e["target_kind"], e["target"]) for e in full["edges"]
    }
    assert ("handler", "h_a", "outbound", "OB_SHARED") in full_edges


async def test_credential_test_route_authorizes_before_disclosing_config(engine: Engine) -> None:
    # Review follow-up (BACKLOG #111, ADR 0132): POST /connections/{name}/test-credential must AUTHORIZE
    # before revealing anything about a connection's type / alt-credential config. A channel-scoped
    # CONNECTIONS_TEST caller probing an OUT-OF-SCOPE name must get a UNIFORM 403 — a File endpoint WITH
    # an alt credential and a non-File / no-credential endpoint must be INDISTINGUISHABLE (no 400 that
    # leaks "this is a File endpoint with a credential"). Mirrors the sibling /test route's ordering.
    reg = Registry()
    reg.add_inbound(  # IN scope, File, NO credential -> an AUTHORIZED caller gets a 400 (proves the guard passed)
        InboundConnection(
            "IB_A", ConnectionSpec(ConnectorType.FILE, {"directory": "./a"}), router="r"
        )
    )
    reg.add_inbound(  # OUT of scope, File WITH an alt credential
        InboundConnection(
            "IB_CRED",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": "./b", "credential_username": "svc", "credential_password": "pw"},
            ),
            router="r",
        )
    )
    reg.add_inbound(  # OUT of scope, NOT a File / no credential
        InboundConnection("IB_MLLP", ConnectionSpec(ConnectorType.MLLP, {"port": 2576}), router="r")
    )
    reg.add_router("r", lambda m: [])
    engine.add_registry(reg)
    service = await _service(engine)
    uid = await _add(service, "op", Role.OPERATOR)  # OPERATOR holds CONNECTIONS_TEST
    await service.set_channel_scope(uid, ["IB_A"], actor="admin")
    async with _client(engine, service) as c:
        h = await _login(c, "op")
        # Out-of-scope: the File-with-credential and the non-File connection return the SAME 403 — the
        # caller cannot tell them apart, so the route discloses no pre-auth config/topology.
        r_cred = await c.post("/connections/IB_CRED/test-credential", headers=h)
        r_mllp = await c.post("/connections/IB_MLLP/test-credential", headers=h)
        assert r_cred.status_code == 403
        assert r_mllp.status_code == 403
        assert (
            r_cred.status_code == r_mllp.status_code
        )  # indistinguishable to an unauthorized caller
        # In scope: authorization passes, so an authorized caller does get the (config-disclosing) 400
        # for a File endpoint that has no alt credential — and a 404 for a truly unknown name.
        assert (await c.post("/connections/IB_A/test-credential", headers=h)).status_code == 400
        assert (await c.post("/connections/IB_NOPE/test-credential", headers=h)).status_code == 404


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
