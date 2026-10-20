# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The console's DR release outlives the request deadline the way the JSON route does (vault
BACKLOG #2752).

``/ui/dr/release`` calls the engine's own ``dr_release`` handler in process, so the deadline that
cuts the console's request off is the same middleware, around the same handler. This drives the
console route with the middleware's own deadline firing while the release is in its drain, and
checks the release still completes and records its row: the protection the handler carries reaches
the console too.

The deadline is fired from inside the drain rather than set to a short wall time (vault BACKLOG
#3871), with the engine suite's ``tests/_deadline_capture.py``, which says why and how this suite
imports it.
"""

from __future__ import annotations

import inspect
import json
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from _ui_clients import SAME_ORIGIN, auth_service, cookie_login, provision

import messagefoundry
from messagefoundry.api import create_app
from messagefoundry.config.settings import DrSettings, EgressSettings, StoreSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store import MessageStore
from tests._deadline_capture import capture_deadlines, expect_cut_off

# ``tests`` and ``messagefoundry`` resolve through the import path, where an editable install from
# another worktree can come first: the test would then run one checkout's helper or engine against
# another's with no error. The engine conftest refuses the same case for its tooling manifest.
_ROOTS = {
    "this test": Path(__file__).resolve().parents[3],
    "the helper": Path(inspect.getfile(capture_deadlines)).resolve().parents[1],
    "the engine": Path(inspect.getfile(messagefoundry)).resolve().parents[1],
}
if len(set(_ROOTS.values())) != 1:
    raise RuntimeError(f"imported from more than one checkout: {_ROOTS}")


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


async def _audit(engine: Engine, action: str) -> list[object]:
    return [json.loads(row["detail"]) for row in await engine.store.list_audit(action=action)]


async def test_a_console_release_cut_off_by_the_deadline_still_completes(
    dr_engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    coord = dr_engine.dr_coordinator
    assert coord is not None
    # Serving under the DR run-profile, as test_dr_failback.py simulates it.
    coord._active = True
    dr_engine._dr_active = True

    service = await auth_service(dr_engine)
    await provision(service, "boss", ["administrator"])
    app = create_app(dr_engine, auth=service, serve_ui=True)
    outliving = app.state.outliving_operations

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        await cookie_login(c, "boss")  # under the default deadline, before the capture
        capture = capture_deadlines(monkeypatch, app)

        async def held_drain() -> dict[str, object]:
            await capture.cut_off()  # the release request's deadline fires here, in the drain
            dr_engine._dr_active = False
            return {"depth_left": 0}

        coord._deactivate_profile = held_drain
        async with capture.held():
            # Fired in the drain, so this also says the drain was reached.
            await expect_cut_off(capture, c.post("/ui/dr/release", headers=SAME_ORIGIN))
            # Cut off while the release was still running, and not cancelled with the request.
            assert outliving.inflight == ["DR release"]
            assert coord.active is True
            assert await _audit(dr_engine, "dr_release_failed") == []

    assert coord.active is False and dr_engine.dr_active is False
    assert await _audit(dr_engine, "dr.release") == [
        {"depth_left": 0, "drained": True, "vip_hook_ran": False}
    ]
    assert await _audit(dr_engine, "dr_release_failed") == []
