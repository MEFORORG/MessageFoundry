# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The console's DR release outlives the request deadline the way the JSON route does (vault
BACKLOG #2752).

``/ui/dr/release`` calls the engine's own ``dr_release`` handler in process, so the deadline that
cuts the console's request off is the same middleware, around the same handler. This drives the
console route with the middleware's own deadline firing while the release is in its drain, and
checks the release still completes and records its row: the protection the handler carries reaches
the console too.

The deadline is not set to a short wall time any more (vault BACKLOG #3871). It is wall time from
the start of the request, so on a loaded runner the auth dependencies alone outlasted 0.2 s: the
503 came before the handler started the release, nothing was registered to outlive, and the box
was still active when the test asserted. The test now captures the deadline the middleware opens
and brings it forward from inside the drain, so it fires there and nowhere else. The drain is held
until the 503 is in, and the test then waits on the operation itself, not on a clock.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from _ui_clients import SAME_ORIGIN, auth_service, cookie_login, provision

from messagefoundry.api import create_app, request_timeout
from messagefoundry.config.settings import DrSettings, EgressSettings, StoreSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store import MessageStore

#: Long enough that the deadline never fires on its own during the test: the drain fires it.
_GENEROUS_DEADLINE_SECONDS = 30.0


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


class _DeadlineCapture:
    """Stands in for ``asyncio`` inside the deadline middleware's module only, and keeps each
    deadline the middleware opens, so a test can make the real deadline fire when it chooses."""

    def __init__(self) -> None:
        self.deadlines: list[asyncio.Timeout] = []

    def timeout(self, delay: float | None) -> asyncio.Timeout:
        deadline = asyncio.timeout(delay)
        self.deadlines.append(deadline)
        return deadline

    def __getattr__(self, name: str) -> Any:
        return getattr(asyncio, name)


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

    capture = _DeadlineCapture()
    monkeypatch.setattr(request_timeout, "asyncio", capture)
    loop = asyncio.get_running_loop()
    drain_started = asyncio.Event()
    let_drain_end = asyncio.Event()

    async def held_drain() -> dict[str, object]:
        drain_started.set()
        # The release request's deadline fires now, inside the drain, whatever the request spent
        # reaching the handler. It is the last one opened: only that request is in flight.
        capture.deadlines[-1].reschedule(loop.time())
        # Held until the deadline has answered, so the drain cannot end first.
        await let_drain_end.wait()
        dr_engine._dr_active = False
        return {"depth_left": 0}

    coord._deactivate_profile = held_drain

    service = await auth_service(dr_engine)
    await provision(service, "boss", ["administrator"])
    app = create_app(dr_engine, auth=service, serve_ui=True)
    outliving = app.state.outliving_operations
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://t"
        ) as c:
            await cookie_login(c, "boss")  # under the default deadline
            app.state.request_timeout_seconds = _GENEROUS_DEADLINE_SECONDS
            # Bounded, so a deadline that never fires fails here rather than hanging the run.
            r = await asyncio.wait_for(
                c.post("/ui/dr/release", headers=SAME_ORIGIN),
                timeout=_GENEROUS_DEADLINE_SECONDS + 10,
            )
            # The middleware's own 503, not a handler's: the deadline cut the request off.
            assert r.status_code == 503, r.text
            assert r.json() == {"detail": "the server timed out building a response"}
            assert drain_started.is_set()
            # Cut off while the release was still running, and not cancelled with the request.
            assert outliving.inflight == ["DR release"]
            assert coord.active is True
            assert await _audit(dr_engine, "dr_release_failed") == []
            let_drain_end.set()
            assert await outliving.drain(timeout=10) == [], "the release never finished"
    finally:
        # After a failed assertion above, release the drain and wait for the release, so it does
        # not run on into the fixture's engine stop or the session's next test.
        let_drain_end.set()
        await outliving.drain(timeout=10)

    assert coord.active is False and dr_engine.dr_active is False
    assert await _audit(dr_engine, "dr.release") == [
        {"depth_left": 0, "drained": True, "vip_hook_ran": False}
    ]
    assert await _audit(dr_engine, "dr_release_failed") == []
