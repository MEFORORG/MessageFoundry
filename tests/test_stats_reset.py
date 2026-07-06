# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Connections-dashboard statistics reset (console "Reset Statistics").

The dashboard counts are derived on the fly from store rows (since engine start), so a reset can't
delete rows — it records an in-memory per-connection baseline that the connections view subtracts.
These tests cover the engine offset logic (selected / all, gauge preservation, re-reset) and the
``POST /statistics/reset`` endpoint (functional, the destination-name guard, the permission gate, and
per-channel RBAC scoping)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine

PW = "Sup3rSecret!!"
ADT = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "stats.db", poll_interval=0.02)
    yield eng
    await eng.stop()


# --- engine offset logic -----------------------------------------------------


async def test_reset_selected_inbound_zeroes_read_and_keeps_gauges(engine: Engine) -> None:
    await engine.store.enqueue_message(channel_id="c1", raw=ADT, deliveries=[("d1", ADT)], now=10.0)
    await engine.store.enqueue_message(channel_id="c1", raw=ADT, deliveries=[("d1", ADT)], now=11.0)
    await engine.store.enqueue_message(channel_id="c2", raw=ADT, deliveries=[("d2", ADT)], now=12.0)

    before = await engine.connection_metrics_view(now=100.0, rate_window=1000.0)
    assert before.inbound["c1"].read == 2
    assert before.inbound["c2"].read == 1

    assert await engine.reset_stats(inbound=["c1"], now=50.0) == 1

    after = await engine.connection_metrics_view(now=100.0, rate_window=1000.0)
    assert after.inbound["c1"].read == 0  # reset
    assert after.inbound["c1"].last_at == 11.0  # live gauge preserved
    assert after.inbound["c2"].read == 1  # a different connection is untouched

    # Traffic that arrives after the reset is counted again.
    await engine.store.enqueue_message(channel_id="c1", raw=ADT, deliveries=[("d1", ADT)], now=60.0)
    again = await engine.connection_metrics_view(now=100.0, rate_window=1000.0)
    assert again.inbound["c1"].read == 1


async def test_reset_outbound_zeroes_written_keeps_queue_depth(engine: Engine) -> None:
    await engine.store.enqueue_message(channel_id="c1", raw=ADT, deliveries=[("d1", ADT)], now=10.0)
    item = (await engine.store.claim_ready(now=10.0))[0]
    await engine.store.mark_done(item.id, now=12.0)
    # A second delivery left pending so queue_depth is a non-zero live gauge.
    await engine.store.enqueue_message(channel_id="c1", raw=ADT, deliveries=[("d1", ADT)], now=20.0)

    before = await engine.connection_metrics_view(now=100.0, rate_window=1000.0)
    assert before.destinations[("c1", "d1")].written == 1
    assert before.destinations[("c1", "d1")].queue_depth == 1

    assert await engine.reset_stats(outbound=[("c1", "d1")], now=50.0) == 1

    after = await engine.connection_metrics_view(now=100.0, rate_window=1000.0)
    assert after.destinations[("c1", "d1")].written == 0  # reset
    assert after.destinations[("c1", "d1")].queue_depth == 1  # live gauge preserved


async def test_reset_all_zeroes_every_connection(engine: Engine) -> None:
    await engine.store.enqueue_message(channel_id="c1", raw=ADT, deliveries=[("d1", ADT)], now=10.0)
    await engine.store.enqueue_message(channel_id="c2", raw=ADT, deliveries=[("d2", ADT)], now=11.0)

    # Two inbound + two destination endpoints carried traffic.
    assert await engine.reset_stats(all_connections=True, now=50.0) == 4

    view = await engine.connection_metrics_view(now=100.0, rate_window=1000.0)
    assert view.inbound["c1"].read == 0
    assert view.inbound["c2"].read == 0


async def test_reset_again_rezeroes_after_more_traffic(engine: Engine) -> None:
    await engine.store.enqueue_message(channel_id="c1", raw=ADT, deliveries=[("d1", ADT)], now=10.0)
    await engine.reset_stats(inbound=["c1"], now=20.0)
    await engine.store.enqueue_message(channel_id="c1", raw=ADT, deliveries=[("d1", ADT)], now=30.0)

    mid = await engine.connection_metrics_view(now=100.0, rate_window=1000.0)
    assert mid.inbound["c1"].read == 1  # one message since the first reset

    await engine.reset_stats(inbound=["c1"], now=40.0)  # re-reset snapshots the live count
    end = await engine.connection_metrics_view(now=100.0, rate_window=1000.0)
    assert end.inbound["c1"].read == 0


async def test_view_is_passthrough_when_nothing_reset(engine: Engine) -> None:
    await engine.store.enqueue_message(channel_id="c1", raw=ADT, deliveries=[("d1", ADT)], now=10.0)
    raw = await engine.store.connection_metrics(
        since=engine.started_at, now=100.0, rate_window=1000.0
    )
    view = await engine.connection_metrics_view(now=100.0, rate_window=1000.0)
    assert view == raw  # byte-identical to the store metrics with no resets active


# --- API: functional (no-auth client) ----------------------------------------


@pytest.fixture
async def client(engine: Engine) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=create_app(engine, allow_no_auth=True))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        yield c


async def test_endpoint_reset_all_and_audits(engine: Engine, client: httpx.AsyncClient) -> None:
    await engine.store.enqueue_message(channel_id="c1", raw=ADT, deliveries=[("d1", ADT)], now=10.0)
    r = await client.post("/statistics/reset", json={"all": True})
    assert r.status_code == 200
    assert r.json()["reset"] >= 1
    view = await engine.connection_metrics_view(now=100.0, rate_window=1000.0)
    assert view.inbound["c1"].read == 0
    assert "stats_reset" in {a["action"] for a in await engine.store.list_audit()}


async def test_endpoint_reset_selected_source(engine: Engine, client: httpx.AsyncClient) -> None:
    await engine.store.enqueue_message(channel_id="c1", raw=ADT, deliveries=[("d1", ADT)], now=10.0)
    await engine.store.enqueue_message(channel_id="c2", raw=ADT, deliveries=[("d2", ADT)], now=11.0)
    r = await client.post(
        "/statistics/reset", json={"targets": [{"role": "source", "channel_id": "c1"}]}
    )
    assert r.status_code == 200
    assert r.json()["reset"] == 1
    view = await engine.connection_metrics_view(now=100.0, rate_window=1000.0)
    assert view.inbound["c1"].read == 0
    assert view.inbound["c2"].read == 1  # not targeted


async def test_endpoint_destination_target_requires_name(client: httpx.AsyncClient) -> None:
    r = await client.post(
        "/statistics/reset", json={"targets": [{"role": "destination", "channel_id": "c1"}]}
    )
    assert r.status_code == 422  # a destination row must carry its destination name


# --- API: RBAC (authenticated) -----------------------------------------------


async def _service(engine: Engine) -> AuthService:
    service = AuthService(engine.store, AuthSettings())
    await service.initialize()
    return service


def _authed_client(engine: Engine, service: AuthService) -> httpx.AsyncClient:
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


async def test_viewer_lacks_monitoring_diagnose(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "viewer", Role.VIEWER)  # has monitoring:read but not monitoring:diagnose
    async with _authed_client(engine, service) as c:
        h = await _login(c, "viewer")
        assert (await c.post("/statistics/reset", json={"all": True}, headers=h)).status_code == 403


async def test_operator_can_reset(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)  # monitoring:diagnose
    await engine.store.enqueue_message(channel_id="c1", raw=ADT, deliveries=[("d1", ADT)], now=10.0)
    async with _authed_client(engine, service) as c:
        h = await _login(c, "op")
        assert (await c.post("/statistics/reset", json={"all": True}, headers=h)).status_code == 200


async def test_scoped_user_cannot_reset_all(engine: Engine) -> None:
    service = await _service(engine)
    uid = await _add(service, "op", Role.OPERATOR)
    await service.set_channel_scope(uid, ["IB_A"], actor="admin")
    async with _authed_client(engine, service) as c:
        h = await _login(c, "op")
        # "Reset all" spans every channel — a channel-scoped user is refused (mirrors purge).
        assert (await c.post("/statistics/reset", json={"all": True}, headers=h)).status_code == 403


async def test_scoped_user_resets_only_in_scope_channel(engine: Engine) -> None:
    service = await _service(engine)
    uid = await _add(service, "op", Role.OPERATOR)
    await service.set_channel_scope(uid, ["IB_A"], actor="admin")
    await engine.store.enqueue_message(
        channel_id="IB_A", raw=ADT, deliveries=[("d", ADT)], now=10.0
    )
    async with _authed_client(engine, service) as c:
        h = await _login(c, "op")
        ok = await c.post(
            "/statistics/reset",
            json={"targets": [{"role": "source", "channel_id": "IB_A"}]},
            headers=h,
        )
        assert ok.status_code == 200 and ok.json()["reset"] == 1
        denied = await c.post(
            "/statistics/reset",
            json={"targets": [{"role": "source", "channel_id": "IB_B"}]},
            headers=h,
        )
        assert denied.status_code == 403  # out of scope
