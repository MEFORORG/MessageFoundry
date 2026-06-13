"""Phase-8 PR C3 — AD-group → channel-scope mapping (store + service sync + admin API)."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth.permissions import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store.store import MessageStore

PW = "Sup3rSecret!!"


# --- store level -------------------------------------------------------------


async def test_scope_map_roundtrip_and_lookup(tmp_path: Path) -> None:
    s = await MessageStore.open(tmp_path / "s.db")
    try:
        await s.set_ad_group_scope_map([("GRP-A", "IB_A"), ("grp-a", "IB_B"), ("grp-all", "*")])
        rows = await s.list_ad_group_scope_map()
        assert {(r["ad_group"], r["channel"]) for r in rows} == {
            ("grp-a", "IB_A"),
            ("grp-a", "IB_B"),
            ("grp-all", "*"),
        }  # ad_group lower-cased, deduped
        assert await s.channels_for_ad_groups(["GRP-A"]) == {"IB_A", "IB_B"}
        assert await s.channels_for_ad_groups(["grp-all"]) == {"*"}
        assert await s.channels_for_ad_groups(["unmapped"]) == set()
    finally:
        await s.close()


# --- service sync ------------------------------------------------------------


async def _ad_user(store: MessageStore, username: str) -> object:
    await store.create_user(user_id=username, username=username, auth_provider="ad")
    return await store.get_user(username)


async def test_sync_persists_group_scope_and_audits(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "svc.db")
    try:
        service = AuthService(store, AuthSettings())
        await service.initialize()
        await store.set_ad_group_scope_map([("grp-a", "IB_A"), ("grp-a", "IB_B")])
        user = await _ad_user(store, "ada")

        refreshed = await service._sync_ad_channel_scope(user, frozenset(), ["GRP-A"])
        assert json.loads(refreshed.channel_scope) == ["IB_A", "IB_B"]  # persisted, sorted
        assert any(a["action"] == "auth.ad_scope_resynced" for a in await store.list_audit())
    finally:
        await store.close()


async def test_sync_star_means_all_and_admin_is_untouched(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "svc2.db")
    try:
        service = AuthService(store, AuthSettings())
        await service.initialize()
        await store.set_ad_group_scope_map([("grp-all", "*"), ("grp-a", "IB_A")])

        await _ad_user(store, "eve")
        await store.set_user_channel_scope("eve", json.dumps(["IB_A"]))  # previously scoped
        scoped = await store.get_user("eve")
        refreshed = await service._sync_ad_channel_scope(scoped, frozenset(), ["grp-all"])
        assert refreshed.channel_scope is None  # '*' clears to all channels

        admin = await _ad_user(store, "boss")
        out = await service._sync_ad_channel_scope(
            admin, frozenset({Role.ADMINISTRATOR}), ["grp-a"]
        )
        assert out.channel_scope is None  # admins always all; never scoped
    finally:
        await store.close()


async def test_sync_no_matching_group_leaves_scope_untouched(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "svc3.db")
    try:
        service = AuthService(store, AuthSettings())
        await service.initialize()
        await store.set_ad_group_scope_map([("grp-a", "IB_A")])
        await store.create_user(user_id="u", username="u", auth_provider="ad")
        await store.set_user_channel_scope("u", json.dumps(["MANUAL"]))  # a manual per-user scope
        user = await store.get_user("u")
        out = await service._sync_ad_channel_scope(user, frozenset(), ["other-group"])
        assert json.loads(out.channel_scope) == [
            "MANUAL"
        ]  # opt-in: untouched when no group matches
    finally:
        await store.close()


# --- admin API ---------------------------------------------------------------


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "api.db", poll_interval=0.02)
    yield eng
    await eng.stop()


async def test_ad_group_scope_map_admin_endpoint(engine: Engine) -> None:
    service = AuthService(engine.store, AuthSettings())
    await service.initialize()
    await service.create_local_user(
        username="boss",
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.ADMINISTRATOR.value],
        actor="test",
    )
    transport = httpx.ASGITransport(app=create_app(engine, auth=service))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        tok = (
            await c.post(
                "/auth/login", json={"username": "boss", "password": PW, "provider": "local"}
            )
        ).json()["token"]
        h = {"Authorization": f"Bearer {tok}"}
        assert (await c.get("/ad-group-scope-map", headers=h)).json()["entries"] == []
        body = {"entries": [{"ad_group": "Lab-Ops", "channel": "IB_LAB"}]}
        assert (await c.put("/ad-group-scope-map", json=body, headers=h)).status_code == 200
        got = (await c.get("/ad-group-scope-map", headers=h)).json()["entries"]
        assert got == [{"ad_group": "lab-ops", "channel": "IB_LAB"}]  # lower-cased group
        assert any(
            a["action"] == "ad_group_scope_map.updated" for a in await engine.store.list_audit()
        )
