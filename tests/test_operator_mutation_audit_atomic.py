# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An operator mutation and its audit row commit together, or neither does (BACKLOG #2624).

Before #2624 replay, resend and purge changed the store in one transaction and wrote their audit row
in a second. On the JSON plane the ``auth.permission_granted`` row that ``require`` writes first was
the only trace if the engine died between the two. The web console writes no such row, so a console
action could keep its change with nothing in the audit chain at all.

The store half runs ``tests/_operator_audit_atomic_contract.py`` on SQLite here, with group commit off
and on. The PostgreSQL and SQL Server suites run the same body. The API half drives the real routes,
the console's included, because that is where the row is built and handed to the store.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.service import AuthService
from messagefoundry.config.models import RetryPolicy
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store.store import MessageStore
from tests._admin_account import create_local_user_chosen
from tests._operator_audit_atomic_contract import (
    assert_operator_audit_atomic,
    failing_append,
)

PW = "a-strong-test-passphrase"
ADT = "MSH|^~\\&|S|F|R|RF|20260604||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"


@pytest.mark.parametrize("window_ms", [0.0, 5.0], ids=["inline", "group-commit"])
async def test_sqlite_operator_mutations_commit_with_their_audit_rows(
    tmp_path: Path, window_ms: float
) -> None:
    """Group commit changes only the inject: it is the one grouped body here (ADR 0001)."""
    store = await MessageStore.open(tmp_path / "atomic.db", group_commit_window_ms=window_ms)
    try:
        await assert_operator_audit_atomic(store)
    finally:
        await store.close()


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(
        tmp_path / "routes.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


async def _service(engine: Engine) -> AuthService:
    # Not an MFA or pacing test: both off, as the console suite pins them (BACKLOG #187, #2301).
    service = AuthService(
        engine.store,
        AuthSettings(
            admin_write_min_interval_seconds=0,
            mfa_verify_min_elapsed_seconds=0,
            require_mfa=False,
        ),
    )
    await service.initialize()
    uid = await create_local_user_chosen(
        service,
        username="op",
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.OPERATOR.value],
        actor="test",
    )
    await service.set_channel_scope(uid, [ALL_CHANNELS], actor="test")
    user = await service.store.get_user(uid)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        uid, password_hash=user.password_hash, must_change_password=False, password_generated=False
    )
    return service


def _client(engine: Engine, service: AuthService) -> httpx.AsyncClient:
    # raise_app_exceptions=False: a failed append must surface as the 500 a caller sees.
    app = create_app(engine, auth=service, serve_ui=True, webauthn_rp_from_request=True)
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    return httpx.AsyncClient(transport=transport, base_url="http://t")


async def _dead_message(engine: Engine) -> str:
    """One message whose only delivery is dead-lettered, so a replay re-queues exactly one row."""
    mid = await engine.store.enqueue_message(
        channel_id="ch1", raw=ADT, deliveries=[("archive", ADT)], source_type="file"
    )
    item = (await engine.store.claim_ready())[0]
    await engine.store.mark_failed(item.id, "boom", RetryPolicy(max_attempts=1))
    return mid


async def _status(engine: Engine, mid: str) -> str:
    rows = await engine.store.outbox_for(mid)
    assert len(rows) == 1
    return str(rows[0]["status"])


async def _replay(c: httpx.AsyncClient, mid: str, *, console: bool) -> httpx.Response:
    if console:
        await c.post("/ui/login", data={"username": "op", "password": PW})
        return await c.post(
            f"/ui/messages/{mid}/replay",
            headers={"Sec-Fetch-Site": "same-origin"},
            follow_redirects=False,
        )
    login = await c.post(
        "/auth/login", json={"username": "op", "password": PW, "provider": "local"}
    )
    token = login.json()["token"]
    return await c.post(f"/messages/{mid}/replay", headers={"Authorization": f"Bearer {token}"})


@pytest.mark.parametrize("console", [False, True], ids=["json", "console"])
async def test_a_replay_commits_its_attributed_row_with_the_requeue(
    engine: Engine, console: bool
) -> None:
    """The row the replay commits names the operator, on both planes. On the console it is the only
    row: no grant row is written before the route body there (BACKLOG #1197)."""
    service = await _service(engine)
    mid = await _dead_message(engine)
    async with _client(engine, service) as c:
        r = await _replay(c, mid, console=console)
    assert r.status_code == (303 if console else 200), r.text
    assert await _status(engine, mid) == "pending"
    rows = await engine.store.list_audit(action="message_replay")
    assert len(rows) == 1
    row = rows[0]
    assert (row["actor"], row["channel_id"], row["client"]) == ("op", "ch1", "127.0.0.1")
    assert json.loads(str(row["detail"])) == {"message_id": mid, "requeued": 1}


@pytest.mark.parametrize("console", [False, True], ids=["json", "console"])
async def test_a_replay_whose_audit_row_fails_requeues_nothing(
    engine: Engine, console: bool
) -> None:
    """The fault this item is about: the append fails after the re-queue was written. Before #2624
    the re-queue had already committed, so the replay ran with no record of who ran it."""
    service = await _service(engine)
    mid = await _dead_message(engine)
    async with _client(engine, service) as c:
        with failing_append(engine.store, "message_replay"):
            r = await _replay(c, mid, console=console)
    assert r.status_code == 500
    assert await _status(engine, mid) == "dead"
    assert await engine.store.list_audit(action="message_replay") == []
