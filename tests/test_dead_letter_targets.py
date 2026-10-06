# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1743 step 2: the dead-letter replay set comes from the store, not the rendered page.

The console used to build its per-channel and per-destination replay buttons from the rows on the
page it drew. A channel whose dead deliveries were all older than the first page had no button.
``QueueStore.list_replay_targets`` returns the distinct ``(channel_id, destination_name)`` pairs a
replay would re-queue rows for, over the whole dead set. ``GET /dead-letters`` hands them back as
``replay_targets``.

The seed puts one channel beyond the first page of ``list_dead``, and the first test checks the page
before it checks the targets. Without that control a green test could not tell "the read covers the
whole set" from "the read happens to match the page".

The store half runs on all three backends. Postgres and SQL Server are gated on
``MEFOR_TEST_POSTGRES`` and ``MEFOR_TEST_SQLSERVER`` like the rest of their suites.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.service import AuthService
from messagefoundry.config.models import RetryPolicy
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store import MessageStore
from tests._admin_account import create_local_user_chosen

PW = "a-strong-test-passphrase"
RAW = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"

_GATES = {
    "postgres": "MEFOR_TEST_POSTGRES",
    "sqlserver": "MEFOR_TEST_SQLSERVER",
}

_CLEARED = ("message_events", "delivered_keys", "response", "queue", "messages")


async def _open(backend: str, tmp_path: Path) -> Any:
    if backend == "sqlite":
        return await MessageStore.open(tmp_path / "dead_targets.db")
    from messagefoundry.config.settings import load_settings

    settings = load_settings(environ=os.environ).store
    if backend == "postgres":
        from messagefoundry.store.postgres import PostgresStore

        pg = await PostgresStore.open(settings)
        async with pg._pool.acquire() as conn:
            for table in _CLEARED:
                await conn.execute(f"DELETE FROM {table}")
        return pg
    from messagefoundry.store.sqlserver import SqlServerStore

    ss = await SqlServerStore.open(settings)
    async with ss._acquire() as conn, ss._cursor(conn) as cur:
        for table in _CLEARED:
            await cur.execute(f"DELETE FROM {table}")
        await ss._commit(conn)
    return ss


@pytest.fixture(params=["sqlite", "postgres", "sqlserver"])
async def store(request: pytest.FixtureRequest, tmp_path: Path) -> AsyncIterator[Any]:
    backend = str(request.param)
    gate = _GATES.get(backend)
    if gate is not None and not os.getenv(gate):
        pytest.skip(f"set {gate}=1 (+ MEFOR_STORE_* connection env) to run {backend} tests")
    s = await _open(backend, tmp_path)
    try:
        yield s
    finally:
        await s.close()


async def _dead(store: Any, channel_id: str, dest: str, *, now: float) -> str:
    """Enqueue one delivery and drive it to DEAD. Returns the message id."""
    mid: str = await store.enqueue_message(
        channel_id=channel_id, raw=RAW, deliveries=[(dest, "p")], now=now
    )
    item = (await store.claim_ready(now=now, destination_name=dest))[0]
    await store.mark_failed(item.id, "boom", RetryPolicy(max_attempts=1), now=now)
    return mid


async def _seed(store: Any) -> None:
    """An OLD dead delivery on IB_OLD, then three newer ones on IB_NEW across two destinations, a
    duplicate pair, and a PENDING delivery on IB_LIVE that must never count as dead."""
    await _dead(store, "IB_OLD", "OB_OLD", now=10.0)
    await _dead(store, "IB_NEW", "OB_A", now=20.0)
    await _dead(store, "IB_NEW", "OB_A", now=30.0)
    await _dead(store, "IB_NEW", "OB_B", now=40.0)
    await store.enqueue_message(channel_id="IB_LIVE", raw=RAW, deliveries=[("OB_LIVE", "p")])


async def test_the_targets_cover_the_whole_dead_set_not_the_first_page(store: Any) -> None:
    await _seed(store)
    # CONTROL: the first page of two misses IB_OLD, which is what the console used to build from.
    page = await store.list_dead(limit=2, allowed_channels=None)
    assert {r["channel_id"] for r in page} == {"IB_NEW"}

    assert await store.list_replay_targets(allowed_channels=None) == [
        ("IB_NEW", "OB_A"),
        ("IB_NEW", "OB_B"),
        ("IB_OLD", "OB_OLD"),
    ]


async def test_the_targets_honour_the_channel_and_destination_filters(store: Any) -> None:
    await _seed(store)
    assert await store.list_replay_targets(channel_id="IB_OLD", allowed_channels=None) == [
        ("IB_OLD", "OB_OLD")
    ]
    assert await store.list_replay_targets(destination_name="OB_B", allowed_channels=None) == [
        ("IB_NEW", "OB_B")
    ]
    assert await store.list_replay_targets(
        channel_id="IB_NEW", destination_name="OB_A", allowed_channels=None
    ) == [("IB_NEW", "OB_A")]
    # A filter naming a channel with nothing dead: the pending IB_LIVE row stays out.
    assert await store.list_replay_targets(channel_id="IB_LIVE", allowed_channels=None) == []


async def test_the_targets_honour_the_channel_scope(store: Any) -> None:
    await _seed(store)
    assert await store.list_replay_targets(allowed_channels=["IB_OLD"]) == [("IB_OLD", "OB_OLD")]
    # An empty scope matches nothing: the default for a user no one has granted a channel.
    assert await store.list_replay_targets(allowed_channels=[]) == []
    # A filter outside the scope cannot widen it.
    assert await store.list_replay_targets(channel_id="IB_NEW", allowed_channels=["IB_OLD"]) == []
    # None is the whole estate: every dead pair, named, so a backend reading None as "no
    # channels" cannot pass by comparing one read with itself (BACKLOG #2627).
    assert await store.list_replay_targets(allowed_channels=None) == [
        ("IB_NEW", "OB_A"),
        ("IB_NEW", "OB_B"),
        ("IB_OLD", "OB_OLD"),
    ]


async def test_with_bodies_intact_the_targets_match_the_listed_rows(store: Any) -> None:
    """Every row the full listing returns maps to a target, and every target has a row."""
    await _seed(store)
    rows = await store.list_dead(limit=500, allowed_channels=None)
    assert len(rows) == await store.count_dead(allowed_channels=None) == 4
    assert sorted({(r["channel_id"], r["destination_name"]) for r in rows}) == (
        await store.list_replay_targets(allowed_channels=None)
    )


async def test_a_pair_whose_bodies_retention_erased_is_not_a_target(store: Any) -> None:
    """``replay_dead`` skips a dead row whose body retention blanked (BACKLOG #1560). A button for
    that pair would step up, maybe file an approval, and re-queue nothing, so it names no target.

    The CONTROLS are that the row is still dead and still counted, and that a replay of its pair
    re-queues nothing. Without them an empty target list could mean the row was simply gone.
    """
    await _dead(store, "IB_OLD", "OB_OLD", now=10.0)
    await _dead(store, "IB_NEW", "OB_A", now=1_000_000.0)
    assert await store.purge_dead_letters(older_than=100.0, now=1_000_000.0) == 1

    assert await store.count_dead(allowed_channels=None) == 2
    assert await store.list_replay_targets(allowed_channels=None) == [("IB_NEW", "OB_A")]
    assert await store.replay_dead(channel_id="IB_OLD", now=1_000_001.0) == 0


# --- the JSON API: GET /dead-letters carries replay_targets and replayable_in_scope --------------


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(
        tmp_path / "dead_targets_api.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


async def _service(engine: Engine) -> AuthService:
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    return service


async def _add(service: AuthService, username: str, channels: list[str]) -> None:
    """An OPERATOR, because the ADMINISTRATOR role is the whole estate whatever its scope row says."""
    user_id = await create_local_user_chosen(
        service,
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.OPERATOR.value],
        actor="test",
    )
    await service.set_channel_scope(user_id, channels, actor="test")
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id,
        password_hash=user.password_hash,
        must_change_password=False,
        password_generated=False,
    )


async def _token(c: httpx.AsyncClient, username: str) -> dict[str, str]:
    r = await c.post(
        "/auth/login", json={"username": username, "password": PW, "provider": "local"}
    )
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def _pairs(body: dict[str, Any]) -> list[tuple[str, str]]:
    return [(t["channel_id"], t["destination_name"]) for t in body["replay_targets"]]


async def test_the_api_returns_targets_past_the_page_and_the_unfiltered_scope_flag(
    engine: Engine,
) -> None:
    await _seed(engine.store)
    service = await _service(engine)
    await _add(service, "all", [ALL_CHANNELS])
    transport = httpx.ASGITransport(app=create_app(engine, auth=service))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h = await _token(c, "all")
        body = (await c.get("/dead-letters", params={"limit": 1}, headers=h)).json()
        # CONTROL: the one row on the page is IB_NEW; IB_OLD is only in the targets.
        assert [r["channel_id"] for r in body["dead_letters"]] == ["IB_NEW"]
        assert _pairs(body) == [("IB_NEW", "OB_A"), ("IB_NEW", "OB_B"), ("IB_OLD", "OB_OLD")]
        assert (body["total"], body["replayable_in_scope"]) == (4, True)

        # A filter narrows the targets and the total, but not the scope flag.
        f = (await c.get("/dead-letters", params={"channel_id": "IB_OLD"}, headers=h)).json()
        assert _pairs(f) == [("IB_OLD", "OB_OLD")]
        assert (f["total"], f["replayable_in_scope"]) == (1, True)

        # A filter that matches nothing still reports the dead deliveries elsewhere in scope.
        e = (await c.get("/dead-letters", params={"channel_id": "IB_LIVE"}, headers=h)).json()
        assert (_pairs(e), e["total"], e["replayable_in_scope"]) == ([], 0, True)


async def test_the_api_scopes_targets_and_the_flag_to_the_callers_channels(
    engine: Engine,
) -> None:
    await _seed(engine.store)
    service = await _service(engine)
    await _add(service, "old_only", ["IB_OLD"])
    await _add(service, "nobody", ["IB_NONE"])
    transport = httpx.ASGITransport(app=create_app(engine, auth=service))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h = await _token(c, "old_only")
        body = (await c.get("/dead-letters", headers=h)).json()
        assert _pairs(body) == [("IB_OLD", "OB_OLD")]
        assert (body["total"], body["replayable_in_scope"]) == (1, True)

        # A filter naming a channel outside the scope finds nothing. The flag still reads the
        # caller's own channels, where IB_OLD is.
        f = (await c.get("/dead-letters", params={"channel_id": "IB_NEW"}, headers=h)).json()
        assert (_pairs(f), f["total"], f["replayable_in_scope"]) == ([], 0, True)

        # CONTROL for the flag: a caller whose scope holds no dead delivery reads False.
        n = await _token(c, "nobody")
        none = (await c.get("/dead-letters", headers=n)).json()
        assert (_pairs(none), none["total"], none["replayable_in_scope"]) == ([], 0, False)
