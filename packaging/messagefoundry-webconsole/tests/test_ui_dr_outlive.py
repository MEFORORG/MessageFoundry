# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The console's DR release outlives the request deadline the way the JSON route does (vault
BACKLOG #2752).

``/ui/dr/release`` calls the engine's own ``dr_release`` handler in process, so the deadline that
cuts the console's request off is the same middleware, around the same handler. This drives the
console route with the deadline patched down and a drain that outlasts it, and checks the release
still completes and records its row: the protection the handler carries reaches the console too.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from _ui_clients import SAME_ORIGIN, auth_service, cookie_login, provision

from messagefoundry.api import create_app
from messagefoundry.config.settings import DrSettings, EgressSettings, StoreSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store import MessageStore


@pytest.fixture
async def dr_engine(tmp_path: Path) -> AsyncIterator[Engine]:
    store = await MessageStore.open(tmp_path / "ui-dr.db")
    eng = Engine(
        store,
        poll_interval=0.02,
        config_dir=None,
        store_settings=StoreSettings(path=str(tmp_path / "ui-dr.db")),
        dr_settings=DrSettings(enabled=True, activate=False),
        egress_settings=EgressSettings(deny_by_default=False),
    )
    await eng.start()
    yield eng
    await eng.stop()


async def test_a_console_release_cut_off_by_the_deadline_still_completes(
    dr_engine: Engine,
) -> None:
    coord = dr_engine.dr_coordinator
    assert coord is not None
    # Serving under the DR run-profile, as test_dr_failback.py simulates it.
    coord._active = True
    dr_engine._dr_active = True

    async def slow_drain() -> dict[str, object]:
        await asyncio.sleep(0.6)  # outlasts the 0.2 s deadline below
        dr_engine._dr_active = False
        return {"depth_left": 0}

    coord._deactivate_profile = slow_drain

    service = await auth_service(dr_engine)
    await provision(service, "boss", ["administrator"])
    app = create_app(dr_engine, auth=service, serve_ui=True)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        await cookie_login(c, "boss")
        # After the login: its password hash alone outlasts the deadline set here.
        app.state.request_timeout_seconds = 0.2
        r = await c.post("/ui/dr/release", headers=SAME_ORIGIN)
        assert r.status_code == 503

        deadline = asyncio.get_running_loop().time() + 10
        while app.state.outliving_operations.inflight:
            assert asyncio.get_running_loop().time() < deadline, "the release never finished"
            await asyncio.sleep(0.02)

    assert coord.active is False and dr_engine.dr_active is False
    rows = [
        json.loads(r["detail"])
        for r in await dr_engine.store.list_audit(limit=100)
        if r["action"] == "dr.release"
    ]
    assert rows == [{"depth_left": 0, "drained": True, "vip_hook_ran": False}]
