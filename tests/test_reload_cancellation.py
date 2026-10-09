# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A config reload cancelled partway restores intake, and the route outlives the request deadline
(vault BACKLOG #2753, finding D-1c).

``RegistryRunner.reload`` stopped every inbound BEFORE its ``try``, and its rollback arm caught only
``Exception``. A cancellation, such as the request deadline's, is a ``BaseException``: a reload cut
off in step 1 left the sources it had stopped down, and one cut off in the swap left the new
registry half bound, with no rollback and no ``config_reload`` audit row. The route now runs the
reload so that cancelling the caller does not cancel it (``api/outlive.py``), and the runner rolls
back on a cancellation too.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path
from typing import Any

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.api.app import _reload_or_record_interruption
from messagefoundry.auth import Role
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.service import AuthService
from messagefoundry.config.models import ConnectorType
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.pipeline import Engine, ReloadOutcome
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStore
from tests._admin_account import create_local_user_chosen

PW = "Sup3rSecret!!reload-outlive"


async def _wait(predicate: Callable[[], Awaitable[bool]], timeout: float = 10.0) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while not await predicate():
        if asyncio.get_running_loop().time() > deadline:
            raise AssertionError("condition not met within timeout")
        await asyncio.sleep(0.02)


def _registry(tmp_path: Path, *, inbound: str = "file_in", directory: str = "in") -> Registry:
    inbox, outdir = tmp_path / directory, tmp_path / "out"
    inbox.mkdir(exist_ok=True)
    reg = Registry()
    reg.add_outbound(
        OutboundConnection(
            "file_out",
            ConnectionSpec(
                ConnectorType.FILE, {"directory": str(outdir), "filename": "{MSH-10}.hl7"}
            ),
        )
    )
    reg.add_inbound(
        InboundConnection(
            inbound,
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.02},
            ),
            router="r",
        )
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("file_out", m))
    return reg


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "reload-cancel.db")
    yield s
    await s.close()


@pytest.fixture
async def runner(store: MessageStore, tmp_path: Path) -> AsyncIterator[RegistryRunner]:
    rr = RegistryRunner(
        _registry(tmp_path),
        store,
        poll_interval=0.02,
        egress=EgressSettings(deny_by_default=False),
    )
    await rr.start()
    assert rr.inbound_running("file_in")
    yield rr
    await rr.stop()


async def _cancel_once_entered(
    runner: RegistryRunner, new_registry: Registry, entered: asyncio.Event
) -> None:
    task = asyncio.create_task(runner.reload(new_registry))
    await asyncio.wait_for(entered.wait(), 10)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


async def test_a_reload_cancelled_in_step_1_restarts_the_sources_it_stopped(
    runner: RegistryRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    old = runner.registry
    entered = asyncio.Event()
    real_stop = runner._stop_inbound_unsafe
    calls = {"n": 0}

    async def stop_then_hang(name: str) -> None:
        await real_stop(name)  # the source really is stopped when the cancellation lands
        calls["n"] += 1
        if calls["n"] == 1:
            entered.set()
            await asyncio.Event().wait()

    monkeypatch.setattr(runner, "_stop_inbound_unsafe", stop_then_hang)
    await _cancel_once_entered(runner, _registry(tmp_path, inbound="file_in_v2"), entered)

    # Before the fix the stop loop ran outside the try, so this source stayed down.
    assert runner.registry is old
    assert runner.inbound_running("file_in")


async def test_a_reload_cancelled_in_the_swap_rolls_back_to_the_previous_graph(
    runner: RegistryRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    old = runner.registry
    entered = asyncio.Event()

    async def hung_reconcile(*_args: Any, **_kwargs: Any) -> None:
        entered.set()
        await asyncio.Event().wait()

    # Step 3, after the swap and the new listeners' restart: the deepest point of the guarded span.
    monkeypatch.setattr(runner, "_reconcile_outbounds", hung_reconcile)
    new = _registry(tmp_path, inbound="file_in_v2", directory="in_v2")
    await _cancel_once_entered(runner, new, entered)

    # Before the fix the arm caught only Exception: the new registry stayed, half bound.
    assert runner.registry is old
    assert runner.inbound_running("file_in")
    assert not runner.inbound_running("file_in_v2")


# --- the route ---------------------------------------------------------------------------------


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    s = await MessageStore.open(tmp_path / "route.db")
    eng = Engine(
        s,
        poll_interval=0.02,
        config_dir=None,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    await eng.start()
    yield eng
    await eng.stop()


async def _deployer(engine: Engine, deadline: float) -> tuple[httpx.AsyncClient, Any]:
    # This file's subject is the reload deadline, so it keeps the session window.
    # Vault BACKLOG #2625's action-bound proof is pinned in tests/test_bound_step_up_injection.py.
    service = AuthService(
        engine.store,
        AuthSettings(
            require_mfa=False, admin_write_min_interval_seconds=0, require_action_step_up=False
        ),
    )
    await service.initialize()
    user_id = await create_local_user_chosen(
        service,
        username="deployer",
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.ADMINISTRATOR.value],
        actor="test",
    )
    await service.set_channel_scope(user_id, [ALL_CHANNELS], actor="test")
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id,
        password_hash=user.password_hash,
        must_change_password=False,
        password_generated=False,
    )
    app = create_app(engine, auth=service)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as login:
        r = await login.post(
            "/auth/login", json={"username": "deployer", "password": PW, "provider": "local"}
        )
    assert r.status_code == 200, r.text
    # After the login: its password hash alone outlasts the deadline these tests set.
    app.state.request_timeout_seconds = deadline
    client = httpx.AsyncClient(
        transport=transport,
        base_url="http://t",
        headers={"Authorization": f"Bearer {r.json()['token']}"},
    )
    return client, app


async def _actions(store: Any) -> list[str]:
    return [r["action"] for r in await store.list_audit(limit=200)]


async def test_a_reload_cut_off_by_the_deadline_finishes_and_writes_its_row(
    engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry = _registry(tmp_path)

    async def slow_reload(*_args: Any, **_kwargs: Any) -> ReloadOutcome:
        await asyncio.sleep(0.6)  # outlasts the 0.2 s deadline below
        return ReloadOutcome(registry=registry, applied=True, directory=tmp_path)

    monkeypatch.setattr(engine, "reload_detail", slow_reload)
    client, app = await _deployer(engine, deadline=0.2)
    async with client:
        r = await client.post("/config/reload", json={})
    assert r.status_code == 503
    assert "timed out" in r.json()["detail"]

    async def settled() -> bool:
        return not app.state.outliving_operations.inflight

    await _wait(settled)
    actions = await _actions(engine.store)
    assert "config_reload" in actions  # the reload's own row, written after its caller left
    assert "config_reload_interrupted" not in actions


async def test_a_cancelled_reload_records_an_interrupted_row(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    # What still CAN cancel the reload, such as a shutdown, leaves a row naming the attempt.
    entered = asyncio.Event()

    async def hung_reload(*_args: Any, **_kwargs: Any) -> ReloadOutcome:
        entered.set()
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    monkeypatch.setattr(engine, "reload_detail", hung_reload)
    task = asyncio.create_task(
        _reload_or_record_interruption(engine, "/cfg", actor="deployer", client="127.0.0.1")
    )
    await asyncio.wait_for(entered.wait(), 10)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    rows = [
        r
        for r in await engine.store.list_audit(limit=50)
        if r["action"] == "config_reload_interrupted"
    ]
    assert len(rows) == 1
    assert json.loads(rows[0]["detail"]) == {"requested": "/cfg", "dry_run": False}
    assert rows[0]["actor"] == "deployer"
