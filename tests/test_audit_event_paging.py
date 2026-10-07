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
from messagefoundry.api.validation import PAGE_BIND_MAX
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


async def test_get_audit_pages_do_not_repeat_the_grant_row_each_read_writes(
    engine: Engine,
) -> None:
    """Every ``GET /audit`` writes its own ``auth.permission_granted`` row before it reads, so an
    unpinned offset walk repeats one row per page. Passing back ``before_id`` walks one snapshot:
    the pages join to the first page's listing with nothing repeated, and the total holds still."""
    service = await _service(engine)
    await _add(service, "root", Role.ADMINISTRATOR)
    await _seed_trail(engine)
    async with _client(engine, service) as c:
        root = _auth((await _login(c, "root")).json()["token"])
        first = (await c.get("/audit", params={"limit": 3}, headers=root)).json()
        pin, total = first["before_id"], first["total"]
        assert isinstance(pin, int) and total > 6
        seen = [(e["ts"], e["action"], e["detail"]) for e in first["entries"]]
        offset = 3
        while offset < total:
            page = (
                await c.get(
                    "/audit",
                    params={"limit": 3, "offset": offset, "before_id": pin},
                    headers=root,
                )
            ).json()
            assert page["total"] == total and page["before_id"] == pin
            seen += [(e["ts"], e["action"], e["detail"]) for e in page["entries"]]
            offset += 3
        assert len(seen) == total
        # The whole snapshot read at once is the same sequence the pages joined into.
        once = (
            await c.get("/audit", params={"limit": 1000, "before_id": pin}, headers=root)
        ).json()
        assert seen == [(e["ts"], e["action"], e["detail"]) for e in once["entries"]]


@pytest.mark.parametrize("path", ["/audit", "/me/security-events", "/events"])
async def test_an_offset_past_a_64_bit_bind_is_refused_not_a_500(engine: Engine, path: str) -> None:
    service = await _service(engine)
    await _add(service, "root", Role.ADMINISTRATOR)
    async with _client(engine, service) as c:
        h = _auth((await _login(c, "root")).json()["token"])
        for name in ("offset", "before_id"):
            too_big = await c.get(path, params={name: PAGE_BIND_MAX + 1}, headers=h)
            assert too_big.status_code == 422, (name, too_big.text)
        assert (await c.get(path, params={"offset": PAGE_BIND_MAX}, headers=h)).status_code == 200


async def test_get_me_security_events_pages_with_a_total(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "alice", Role.VIEWER)
    async with _client(engine, service) as c:
        h = _auth((await _login(c, "alice")).json()["token"])
        for i in range(3):
            await engine.store.record_audit("auth.test_seed", actor="alice", detail=f'{{"n":{i}}}')
        whole = (await c.get("/me/security-events", headers=h)).json()
        total, pin = whole["total"], whole["before_id"]
        assert total == len(whole["events"]) >= 3 and isinstance(pin, int)
        # A row the caller writes after the first page stays out of the pinned pages.
        await engine.store.record_audit("auth.test_seed", actor="alice", detail='{"n":"late"}')
        second = (
            await c.get(
                "/me/security-events",
                params={"limit": 1, "offset": 1, "before_id": pin},
                headers=h,
            )
        ).json()
        assert second["total"] == total and second["offset"] == 1 and second["limit"] == 1
        assert second["before_id"] == pin
        assert second["events"] == whole["events"][1:2]


async def test_get_events_pages_by_offset_under_a_snapshot_pin(engine: Engine) -> None:
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
        whole = (await c.get("/events")).json()
        assert whole["total"] == 5 and len(whole["events"]) == 5
        pin = whole["before_id"]
        assert pin == max(e["id"] for e in whole["events"]) + 1
        # A late event with an OLD ts lands mid-list, as a burst flush writes one. The pin keeps it
        # off the later pages, so page two is still rows two and three of the first read.
        await engine.store.record_connection_event(
            connection="IB_PAGE",
            transport="mllp",
            direction="inbound",
            kind="closed",
            peer_host=None,
            now=102.5,
        )
        page = await c.get("/events", params={"limit": 2, "offset": 2, "before_id": pin})
        assert page.status_code == 200
        body = page.json()
        assert body["total"] == 5 and body["before_id"] == pin
        assert [e["id"] for e in body["events"]] == [e["id"] for e in whole["events"]][2:4]
        assert (await c.get("/events", params={"offset": -1})).status_code == 422
