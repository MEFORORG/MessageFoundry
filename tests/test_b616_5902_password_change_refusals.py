# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5902: the password-change route's two unmapped refusals.

An unusable bundled breach corpus raised ``BreachCorpusUnavailable`` out of the route as a generic
500; it is now a named 503 that still refuses the change. And a caller whose user row was deleted
after its session was resolved, before or during the write, got a success and an
``auth.password_changed`` row, or an enrolment refusal, for an account that no longer exists; the
service now refuses with ``ValueError("no such user")``, which the route answers as a 401. Synthetic
accounts only.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable, Sequence
from pathlib import Path
from typing import Any

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth.passwords import hash_password
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store.base import Store
from messagefoundry.store.store import MessageStore
from tests.test_api_auth import _auth, _login
from tests.test_password_corpus_guard import bundled_corpus as bundled_corpus  # noqa: F401

_PASSWORD = "Str0ng-Synthetic-Pass!!"
_NEW_PASSWORD = "An0ther-Synthetic-Pass!!"


@pytest.fixture
async def store() -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(":memory:")
    try:
        yield s
    finally:
        await s.close()


async def _account(store: Store, *, require_mfa: bool = False) -> tuple[AuthService, Any]:
    """Local account u1, named bob, holding viewer; returns the service and its login identity."""
    service = AuthService(store, AuthSettings(require_mfa=require_mfa))
    await service.initialize()
    await store.create_user(
        user_id="u1",
        username="bob",
        auth_provider="local",
        email="bob@example.org",
        password_hash=hash_password(_PASSWORD),
        password_generated=False,
        audits=(),
    )
    await store.set_user_roles("u1", ["viewer"], assigned_by="test", audits=())
    out = await service.login("bob", _PASSWORD)
    assert out.ok and out.identity is not None
    return service, out.identity


async def _changed_rows(store: Store) -> list[Any]:
    return [r for r in await store.list_audit(limit=200) if r["action"] == "auth.password_changed"]


def _delete_during_write(monkeypatch: pytest.MonkeyPatch, store: Store, user_id: str) -> None:
    """Delete ``user_id`` just before the store's password write runs, the concurrent deletion."""
    real = store.set_password

    async def racing(uid: str, **kwargs: Any) -> bool:
        await store.delete_user(user_id)
        return await real(uid, **kwargs)

    monkeypatch.setattr(store, "set_password", racing)


async def test_a_row_deleted_before_the_change_is_refused(store: MessageStore) -> None:
    service, identity = await _account(store)
    await store.delete_user("u1")
    with pytest.raises(ValueError, match="no such user"):
        await service.change_password(identity, _NEW_PASSWORD)
    # The answer does not depend on the password typed: a weak one is not a policy refusal here.
    with pytest.raises(ValueError, match="no such user"):
        await service.change_password(identity, "weak")
    assert await _changed_rows(store) == []


async def test_a_row_deleted_during_the_write_is_refused(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, identity = await _account(store)
    _delete_during_write(monkeypatch, store, "u1")
    with pytest.raises(ValueError, match="no such user"):
        await service.change_password(identity, _NEW_PASSWORD)
    assert await _changed_rows(store) == []


async def test_a_covered_row_deleted_during_the_write_is_not_an_enrolment_refusal(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, identity = await _account(store, require_mfa=True)

    async def way_past(_user: Any) -> None:
        return None  # stand in for a factor that passes the early refusal

    monkeypatch.setattr(service, "_refuse_rotation_without_way_past", way_past)
    _delete_during_write(monkeypatch, store, "u1")
    with pytest.raises(ValueError, match="no such user"):
        await service.change_password(identity, _NEW_PASSWORD)
    assert await _changed_rows(store) == []


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(
        tmp_path / "b5902.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


async def _signed_in(engine: Engine) -> tuple[httpx.AsyncClient, AuthService, dict[str, str]]:
    service, _identity = await _account(engine.store)
    transport = httpx.ASGITransport(app=create_app(engine, auth=service), client=("127.0.0.1", 123))
    c = httpx.AsyncClient(transport=transport, base_url="http://t")
    login = await _login(c, "bob", _PASSWORD)
    assert login.status_code == 200, login.text
    return c, service, _auth(login.json()["token"])


async def test_an_unusable_corpus_is_a_named_503_and_no_change(
    engine: Engine,
    bundled_corpus: Callable[[Sequence[str] | None], None],  # noqa: F811
    tmp_path: Path,
) -> None:
    c, _service, headers = await _signed_in(engine)
    try:
        bundled_corpus(None)  # no corpus file at all: the screen cannot run
        r = await c.post(
            "/me/password",
            headers=headers,
            json={"current_password": _PASSWORD, "new_password": _NEW_PASSWORD},
        )
    finally:
        await c.aclose()
    assert r.status_code == 503, r.text
    assert "password screening is unavailable" in r.json()["detail"]
    # The decoded detail: a Windows path in the raw JSON body carries escaped backslashes.
    assert str(tmp_path) not in r.json()["detail"]
    assert await _changed_rows(engine.store) == []


async def test_a_deleted_account_is_a_401_not_a_success(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    c, _service, headers = await _signed_in(engine)
    # The row goes after the gate and the current-password check, as the store write starts.
    _delete_during_write(monkeypatch, engine.store, "u1")
    try:
        r = await c.post(
            "/me/password",
            headers=headers,
            json={"current_password": _PASSWORD, "new_password": _NEW_PASSWORD},
        )
    finally:
        await c.aclose()
    assert r.status_code == 401, r.text
    assert r.json()["detail"] == "session ended; sign in again"
    assert await _changed_rows(engine.store) == []
