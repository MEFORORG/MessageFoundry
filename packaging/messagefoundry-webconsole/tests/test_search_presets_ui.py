# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""/ui saved / layered search-preset smoke tests (BACKLOG #151, ADR 0136)."""

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

PW = "Correct-Horse-Battery-Staple-9"
ADT = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||MRN999^^^H^MR||DOE^JANE\r"


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    e = await Engine.create(tmp_path / "pu.db", poll_interval=0.02)
    try:
        yield e
    finally:
        await e.stop()


async def _op(engine: Engine) -> AuthService:
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    uid = await service.create_local_user(
        username="op",
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.OPERATOR.value],
        actor="t",
    )
    user = await service.store.get_user(uid)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        uid, password_hash=user.password_hash, must_change_password=False
    )
    return service


async def test_preset_save_and_layer_ui(engine: Engine) -> None:
    await engine.store.enqueue_message(
        channel_id="ch1",
        raw=ADT,
        deliveries=[("o", ADT)],
        control_id="MSG1",
        message_type="ADT^A01",
    )
    service = await _op(engine)
    transport = httpx.ASGITransport(app=create_app(engine, auth=service, serve_ui=True))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        await c.post("/ui/login", data={"username": "op", "password": PW})

        # search page renders the (empty) presets section
        r = await c.get("/ui/messages/search")
        assert r.status_code == 200 and "Saved presets" in r.text

        # save a preset from the current search state
        s = await c.post(
            "/ui/messages/search/presets",
            data={"name": "acme", "content": "MRN999", "message_type": "ADT^A01"},
        )
        assert s.status_code in (200, 303), s.text

        # it now appears on the search page
        r = await c.get("/ui/messages/search")
        assert "acme" in r.text
        # find its id from the delete form action
        marker = "/ui/messages/search/presets/"
        pid = r.text.split(marker, 1)[1].split("/delete", 1)[0]

        # run a layered search over it → matches the seeded message
        lay = await c.get("/ui/messages/search/layered", params={"presets": pid})
        assert lay.status_code == 200, lay.text
        assert "match(es)" in lay.text

        # delete it
        d = await c.post(f"/ui/messages/search/presets/{pid}/delete")
        assert d.status_code in (200, 303)
        r = await c.get("/ui/messages/search")
        assert "acme" not in r.text
