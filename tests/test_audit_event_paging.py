# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Offset-and-total paging on the audit trail, the security-event feed and the event log
(BACKLOG #2438).

The store contract runs here against SQLite; ``tests/_audit_event_paging_contract.py`` holds it, and
the Postgres and SQL Server suites run the same body. The API tests check that each route carries
the offset through and states a total the caller can actually page through.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.api.app import TOTAL_COUNT_HEADER
from messagefoundry.auth import Role
from messagefoundry.auth.audit_visibility import LOCKED_REFUSAL_DETAIL
from messagefoundry.config.settings import EgressSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store.store import MessageStore
from tests._audit_event_paging_contract import (
    check_audit_paging,
    check_connection_event_paging,
    check_security_events_paging,
)
from tests.test_api_auth import _add, _auth, _client, _login, _service


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "paging.db")
    try:
        yield s
    finally:
        await s.close()


async def test_audit_pages_by_offset_after_the_exclusion(store: MessageStore) -> None:
    await check_audit_paging(store, "sqlite")


async def test_security_events_page_by_offset(store: MessageStore) -> None:
    await check_security_events_paging(store, "sqlite")


async def test_connection_events_page_by_offset_inside_the_channel_scope(
    store: MessageStore,
) -> None:
    await check_connection_event_paging(store, "sqlite")


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(
        tmp_path / "paging_api.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


async def _seed_trail(engine: Engine) -> None:
    """Six rows under one actor, two of them lock rows an Auditor may not read (BACKLOG #1131)."""
    for i, (action, detail) in enumerate(
        [
            ("message_view", "{}"),
            ("auth.account_locked", '{"provider": "local"}'),
            ("message_view", "{}"),
            ("auth.mfa_failed", LOCKED_REFUSAL_DETAIL),
            ("message_view", "{}"),
            ("message_view", "{}"),
        ]
    ):
        await engine.store.record_audit(action, actor="pager", detail=detail, now=1000.0 + i)


async def test_get_audit_pages_and_totals_what_the_caller_may_read(engine: Engine) -> None:
    """An Auditor's total leaves the lock rows out, as its pages do; an administrator's does not.
    Walking an Auditor's pages two at a time gives its one-shot listing, nothing skipped."""
    service = await _service(engine)
    await _add(service, "root", Role.ADMINISTRATOR)
    await _add(service, "aud", Role.AUDITOR)
    await _seed_trail(engine)
    async with _client(engine, service) as c:
        root = _auth((await _login(c, "root")).json()["token"])
        aud = _auth((await _login(c, "aud")).json()["token"])

        full = (await c.get("/audit", params={"actor": "pager"}, headers=root)).json()
        assert full["total"] == 6 and len(full["entries"]) == 6

        whole = (await c.get("/audit", params={"actor": "pager"}, headers=aud)).json()
        assert whole["total"] == 4 and len(whole["entries"]) == 4
        assert whole["offset"] == 0 and whole["limit"] == 100

        walked: list[float] = []
        for offset in (0, 2, 4):
            page = (
                await c.get(
                    "/audit",
                    params={"actor": "pager", "limit": 2, "offset": offset},
                    headers=aud,
                )
            ).json()
            assert page["total"] == 4 and page["offset"] == offset and page["limit"] == 2
            walked += [e["ts"] for e in page["entries"]]
        assert walked == [e["ts"] for e in whole["entries"]]
        assert (await c.get("/audit", params={"offset": -1}, headers=aud)).status_code == 422


async def test_get_me_security_events_pages_with_a_total(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "alice", Role.VIEWER)
    async with _client(engine, service) as c:
        h = _auth((await _login(c, "alice")).json()["token"])
        for i in range(3):
            await engine.store.record_audit("auth.test_seed", actor="alice", detail=f'{{"n":{i}}}')
        whole = (await c.get("/me/security-events", headers=h)).json()
        total = whole["total"]
        assert total == len(whole["events"]) >= 3
        second = (await c.get("/me/security-events?limit=1&offset=1", headers=h)).json()
        assert second["total"] == total and second["offset"] == 1 and second["limit"] == 1
        assert second["events"] == whole["events"][1:2]


async def test_get_events_takes_an_offset_and_states_the_total_in_a_header(engine: Engine) -> None:
    for i in range(5):
        await engine.store.record_connection_event(
            connection="IB_PAGE",
            transport="mllp",
            direction="inbound",
            kind="established",
            peer_host=None,
            now=100.0 + i,
        )
    app = create_app(engine, allow_no_auth=True)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        whole = await c.get("/events")
        assert whole.headers[TOTAL_COUNT_HEADER] == "5"
        page = await c.get("/events", params={"limit": 2, "offset": 2})
        assert page.status_code == 200
        assert page.headers[TOTAL_COUNT_HEADER] == "5"
        assert [e["id"] for e in page.json()] == [e["id"] for e in whole.json()][2:4]
        assert (await c.get("/events", params={"offset": -1})).status_code == 422
