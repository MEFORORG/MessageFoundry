# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A caller outside ``AuthService`` that reads a users row that does not parse (``listed_users``
says which) never acts on invented fields (BACKLOG #5505).

The single-row user readers raise ``RowSealError`` for such a row; the store's list, and the
service's ``read_user_or_unreadable``, return a stand-in, whose fields other than the id are
invented. Synthetic accounts only.
"""

from __future__ import annotations

import sqlite3
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import EgressSettings
from messagefoundry.pipeline import Engine
from tests._approval_queue import release_blocked
from tests.test_api_auth import _add as _auth_add
from tests.test_api_auth import _auth, _login
from tests.test_api_auth import _client as _auth_client
from tests.test_api_auth import _service as _auth_service
from tests.test_approval_requester_recheck import (
    _assert_refused,
    _client_with_sink,
    _hold_replay,
    _Sink,
)
from tests.test_approvals import _add as _approvals_add
from tests.test_approvals import _service as _approvals_service
from tests.test_approvals import _token

#: A synthetic id in the shape the routes' ResourceId accepts.
_TARGET = "5505" * 8


@pytest.fixture
async def engine_at(tmp_path: Path) -> AsyncIterator[tuple[Engine, Path]]:
    path = tmp_path / "raw_callers.db"
    eng = await Engine.create(
        path, poll_interval=0.02, egress_settings=EgressSettings(deny_by_default=False)
    )
    yield eng, path
    await eng.stop()


def _corrupt(path: Path, user_id: str) -> None:
    """An out-of-band edit: a numeric users cell that no longer parses."""
    conn = sqlite3.connect(path)
    try:
        conn.execute("UPDATE users SET failed_attempts=? WHERE id=?", ("garbage", user_id))
        conn.commit()
    finally:
        conn.close()


@pytest.mark.parametrize("corrupt", [True, False])
async def test_an_unreadable_requester_is_refused_as_unverifiable_never_as_disabled(
    engine_at: tuple[Engine, Path], corrupt: bool
) -> None:
    engine, path = engine_at
    service = await _approvals_service(engine)
    maker = await _approvals_add(service, "maker", Role.OPERATOR)
    await _approvals_add(service, "checker", Role.ADMINISTRATOR)
    sink = _Sink()
    c, _ = _client_with_sink(engine, service, sink)
    async with c:
        approval_id = await _hold_replay(c, await _token(c, "maker"), {"channel_id": "IB_ACME_ADT"})
        if corrupt:
            _corrupt(path, maker)
            await _assert_refused(engine, c, approval_id, sink, "requester_unverifiable")
            return
        # The twin: a healthy requester is released, with no refusal recorded.
        checker = await _token(c, "checker")
        assert await release_blocked(c, approval_id, checker) is None
        r = await c.post(f"/approvals/{approval_id}/approve", headers=checker)
        assert r.status_code == 200, r.text
    assert sink.events == []
    assert await engine.store.list_audit(action="approval.stale_requester") == []


async def _spy_set_roles(service: AuthService, monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    calls: list[Any] = []
    real = service.set_roles

    async def spy(*args: Any, **kwargs: Any) -> Any:
        calls.append(args)
        return await real(*args, **kwargs)

    monkeypatch.setattr(service, "set_roles", spy)
    return calls


@pytest.mark.parametrize("provider", ["local", "ad"])
async def test_a_role_change_on_an_unreadable_account_is_refused_before_any_write(
    engine_at: tuple[Engine, Path], monkeypatch: pytest.MonkeyPatch, provider: str
) -> None:
    """The stand-in's ``auth_provider`` is invented, so a corrupt directory account must not be
    read as local: the route refuses on the read, before the AD check or the role write runs."""
    engine, path = engine_at
    service = await _auth_service(engine)
    await _auth_add(service, "root", Role.ADMINISTRATOR)
    await engine.store.create_user(
        user_id=_TARGET,
        username="target",
        auth_provider=provider,
        password_generated=False,
        audits=(),
    )
    _corrupt(path, _TARGET)
    calls = await _spy_set_roles(service, monkeypatch)
    async with _auth_client(engine, service) as c:
        h = _auth((await _login(c, "root")).json()["token"])
        r = await c.put(f"/users/{_TARGET}/roles", headers=h, json={"roles": ["operator"]})
    assert r.status_code == 409, r.text
    assert "integrity" in r.json()["detail"]
    assert calls == []


@pytest.mark.parametrize(("provider", "status"), [("local", 200), ("ad", 400)])
async def test_a_role_change_on_a_healthy_account_still_answers_as_before(
    engine_at: tuple[Engine, Path],
    monkeypatch: pytest.MonkeyPatch,
    provider: str,
    status: int,
) -> None:
    """The twin: a readable local account takes the change, a readable directory account is
    refused 400 by the AD check, as it was."""
    engine, _ = engine_at
    service = await _auth_service(engine)
    await _auth_add(service, "root", Role.ADMINISTRATOR)
    await engine.store.create_user(
        user_id=_TARGET,
        username="target",
        auth_provider=provider,
        password_generated=False,
        audits=(),
    )
    calls = await _spy_set_roles(service, monkeypatch)
    async with _auth_client(engine, service) as c:
        h = _auth((await _login(c, "root")).json()["token"])
        r = await c.put(f"/users/{_TARGET}/roles", headers=h, json={"roles": ["operator"]})
    assert r.status_code == status, r.text
    assert len(calls) == (1 if provider == "local" else 0)


async def test_an_unreadable_account_can_still_be_signed_out_and_deleted(
    engine_at: tuple[Engine, Path],
) -> None:
    """The admin routes that act by id take the account the list shows as failing: force
    sign-out and delete still work on it, and a deleted id is then 404."""
    engine, path = engine_at
    service = await _auth_service(engine)
    await _auth_add(service, "root", Role.ADMINISTRATOR)
    await engine.store.create_user(
        user_id=_TARGET,
        username="target",
        auth_provider="local",
        password_generated=False,
        audits=(),
    )
    _corrupt(path, _TARGET)
    async with _auth_client(engine, service) as c:
        h = _auth((await _login(c, "root")).json()["token"])
        assert (await c.delete(f"/users/{_TARGET}/sessions", headers=h)).status_code == 200
        assert (await c.delete(f"/users/{_TARGET}", headers=h)).status_code == 200
        assert (await c.delete(f"/users/{_TARGET}", headers=h)).status_code == 404
    assert _TARGET not in [u.id for u in await engine.store.list_users()]
