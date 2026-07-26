# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Saved / layered Log-Search preset API (BACKLOG #151, ADR 0136).

CRUD + the bounded AND-compose layered query over search_messages. SQLite here; server parity on CI."""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine

PW = "Correct-Horse-Battery-Staple-9"
ADT = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||MRN999^^^H^MR||DOE^JANE\r"


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    e = await Engine.create(tmp_path / "p.db", poll_interval=0.02)
    try:
        yield e
    finally:
        await e.stop()


async def _user(engine: Engine, role: Role, name: str) -> AuthService:
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    uid = await service.create_local_user(
        username=name, password=PW, display_name=None, email=None, roles=[role.value], actor="t"
    )
    user = await service.store.get_user(uid)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        uid, password_hash=user.password_hash, must_change_password=False
    )
    return service


async def _login(c: httpx.AsyncClient, name: str) -> dict[str, str]:
    r = await c.post("/auth/login", json={"username": name, "password": PW, "provider": "local"})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


async def test_preset_crud_and_owner_scoping(engine: Engine) -> None:
    pytest.importorskip("psutil")
    from messagefoundry.api import create_app

    service = await _user(engine, Role.OPERATOR, "op")
    await service.create_local_user(
        username="op2",
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.OPERATOR.value],
        actor="t",
    )
    u2 = await service.store.get_user_by_username("op2")
    assert u2 is not None and u2.password_hash is not None
    await service.store.set_password(
        u2.id, password_hash=u2.password_hash, must_change_password=False
    )

    transport = httpx.ASGITransport(app=create_app(engine, auth=service))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h = await _login(c, "op")
        cr = await c.post(
            "/search/presets",
            json={"name": "acme", "criteria": {"content": "MRN999", "message_type": "ADT^A01"}},
            headers=h,
        )
        assert cr.status_code == 200, cr.text
        assert cr.json()["status"] == "created"
        pid = cr.json()["id"]

        lst = await c.get("/search/presets", headers=h)
        assert lst.status_code == 200 and [p["name"] for p in lst.json()["presets"]] == ["acme"]
        # list carries NO criteria (metadata only)
        assert "criteria" not in lst.json()["presets"][0] and "MRN999" not in lst.text

        # save-by-name replaces
        rep = await c.post(
            "/search/presets",
            json={"name": "acme", "criteria": {"content": "OTHER"}},
            headers=h,
        )
        assert (
            rep.status_code == 200
            and rep.json()["status"] == "replaced"
            and rep.json()["id"] == pid
        )

        # another user cannot see or delete op's preset
        h2 = await _login(c, "op2")
        assert (await c.get("/search/presets", headers=h2)).json()["presets"] == []
        assert (await c.delete(f"/search/presets/{pid}", headers=h2)).status_code == 404

        # op deletes their own
        assert (await c.delete(f"/search/presets/{pid}", headers=h)).status_code == 200
        assert (await c.get("/search/presets", headers=h)).json()["presets"] == []

    # create + delete were audited (needle shape only — never the value)
    audits = await engine.store.list_audit()
    detail = " ".join(
        str(a["detail"] or "") for a in audits if str(a["action"]).startswith("preset.")
    )
    assert "MRN999" not in detail and "OTHER" not in detail


async def test_layered_compose_and_conflicts(engine: Engine) -> None:
    pytest.importorskip("psutil")
    from messagefoundry.api import create_app

    # A message that matches the "MRN999" needle, on channel ch1.
    await engine.store.enqueue_message(
        channel_id="ch1",
        raw=ADT,
        deliveries=[("o", ADT)],
        control_id="MSG1",
        message_type="ADT^A01",
    )
    service = await _user(engine, Role.OPERATOR, "op")
    transport = httpx.ASGITransport(app=create_app(engine, auth=service))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h = await _login(c, "op")

        async def mk(name: str, criteria: dict[str, object]) -> str:
            r = await c.post(
                "/search/presets", json={"name": name, "criteria": criteria}, headers=h
            )
            assert r.status_code == 200, r.text
            return r.json()["id"]

        a = await mk(
            "needle", {"content": "MRN999", "message_type": "ADT^A01"}
        )  # needle + metadata
        b = await mk("meta_only", {"message_type": "ADT^A01"})  # metadata only, no needle
        cc = await mk("second_needle", {"content": "MRN999"})  # a 2nd content predicate
        e1 = await mk("chan1", {"channel_id": "ch1"})
        e2 = await mk("chan2", {"channel_id": "ch2"})

        # layer needle + metadata-only → composes and matches the seeded message
        r = await c.get("/search/layered", params={"presets": f"{a},{b}"}, headers=h)
        assert r.status_code == 200, r.text
        assert r.json()["matched"] == 1

        # two content predicates → 400
        assert (
            await c.get("/search/layered", params={"presets": f"{a},{cc}"}, headers=h)
        ).status_code == 400
        # zero content predicates (only metadata) → 400
        assert (await c.get("/search/layered", params={"presets": b}, headers=h)).status_code == 400
        # conflicting metadata (channel_id ch1 vs ch2) around the needle → 400
        assert (
            await c.get("/search/layered", params={"presets": f"{a},{e1},{e2}"}, headers=h)
        ).status_code == 400
        # unknown preset id → 404
        assert (
            await c.get("/search/layered", params={"presets": "nope"}, headers=h)
        ).status_code == 404

    audits = await engine.store.list_audit()
    layered = [a for a in audits if a["action"] == "preset.layered_search"]
    assert layered and "MRN999" not in " ".join(str(a["detail"] or "") for a in layered)


async def test_layered_requires_read_permission(engine: Engine) -> None:
    pytest.importorskip("psutil")
    from messagefoundry.api import create_app

    # AUDITOR holds neither messages:read nor a preset surface.
    service = await _user(engine, Role.AUDITOR, "aud")
    transport = httpx.ASGITransport(app=create_app(engine, auth=service))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h = await _login(c, "aud")
        assert (await c.get("/search/presets", headers=h)).status_code == 403
        assert (
            await c.post(
                "/search/presets", json={"name": "x", "criteria": {"content": "y"}}, headers=h
            )
        ).status_code == 403
