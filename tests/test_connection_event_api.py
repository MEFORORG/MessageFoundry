# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""P4 — the GET /events + GET /connections/{name}/events read API (#46)."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.pipeline import Engine


@pytest.fixture
async def engine(tmp_path: Path):  # type: ignore[no-untyped-def]
    eng = await Engine.create(tmp_path / "events.db", poll_interval=0.02)
    yield eng
    await eng.stop()


@pytest.fixture
async def client(engine: Engine):  # type: ignore[no-untyped-def]
    transport = httpx.ASGITransport(app=create_app(engine, allow_no_auth=True))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        yield c


async def _seed(engine: Engine) -> None:
    await engine.store.record_connection_event(
        connection="IB_A",
        transport="mllp",
        direction="inbound",
        kind="established",
        peer_host="10.0.0.1",
        now=100.0,
    )
    await engine.store.record_connection_event(
        connection="IB_A",
        transport="mllp",
        direction="inbound",
        kind="closed",
        peer_host="10.0.0.1",
        reason="eof",
        now=200.0,
    )
    await engine.store.record_connection_event(
        connection="OB_B",
        transport="mllp",
        direction="outbound",
        kind="connection_lost",
        message_id="m1",
        reason="refused",
        now=150.0,
    )


async def test_events_newest_first_and_shape(engine: Engine, client: httpx.AsyncClient) -> None:
    await _seed(engine)
    r = await client.get("/events")
    assert r.status_code == 200
    body = r.json()
    assert [e["kind"] for e in body] == ["closed", "connection_lost", "established"]
    lost = next(e for e in body if e["kind"] == "connection_lost")
    assert lost["direction"] == "outbound" and lost["transport"] == "mllp"
    assert lost["message_id"] == "m1" and lost["connection"] == "OB_B"


async def test_events_filters(engine: Engine, client: httpx.AsyncClient) -> None:
    await _seed(engine)
    # per-connection route
    scoped = (await client.get("/connections/IB_A/events")).json()
    assert {e["kind"] for e in scoped} == {"established", "closed"}
    # kind filter
    by_kind = (await client.get("/events", params={"kind": "connection_lost"})).json()
    assert [e["kind"] for e in by_kind] == ["connection_lost"]
    # since filter
    recent = (await client.get("/events", params={"since": 175.0})).json()
    assert [e["kind"] for e in recent] == ["closed"]
    # limit clamp is accepted
    assert (await client.get("/events", params={"limit": 1})).status_code == 200
    assert (await client.get("/events", params={"limit": 99999})).status_code == 422  # le=1000
