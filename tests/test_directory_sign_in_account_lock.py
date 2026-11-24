# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5653: a directory sign-in mints and clears under the account's own discipline.

Three claims, each driven by injecting a write at the moment the race would need it:

* a disable or a lockout that commits while a directory sign-in is in flight is not answered with
  a live session: the sign-in reads the row again before the mint, and the store's insert refuses a
  disabled or locked row in its own locked transaction (``require_sign_in_eligible``);
* a lock that commits after the mint is not cleared by the sign-in's counter reset, which is a
  compare-and-set on the row it judged;
* two sign-ins of one account that both move its roles do not end each other's new session,
  because both legs complete in a per-account directory sign-in queue.

Item 1 (S11-33) is here too: a returning sign-in whose directory profile is unchanged writes no
profile row.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.auth import Role
from messagefoundry.auth.identity import SessionMechanism
from messagefoundry.auth.ldap import AdPrincipal
from messagefoundry.auth.service import AuthService
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store.store import sign_in_state_refused

OPS = "cn=mf-ops,dc=x"
VIEW = "cn=mf-view,dc=x"


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(
        tmp_path / "directory_sign_in_lock.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


def _principal(
    username: str = "jdoe", *, group: str = OPS, display_name: str = "J Doe"
) -> AdPrincipal:
    return AdPrincipal(
        username=username,
        display_name=display_name,
        email=None,
        dn=f"CN={username},DC=x",
        groups=frozenset({group}),
        directory_object_id=str(uuid.uuid5(uuid.NAMESPACE_URL, username)),
    )


async def _service(engine: Engine) -> AuthService:
    """``require_mfa`` off, so a directory sign-in with no factor owes none and runs the clear."""
    settings = AuthSettings(
        ad_enabled=True,
        kerberos_enabled=True,
        kerberos_realm="EXAMPLE.COM",
        ad_server="ldaps://x",
        ad_user_search_base="DC=x",
        ad_bind_dn="CN=svc,DC=x",
        ad_bind_password="x",
        login_rate_limit_enabled=False,
        require_mfa=False,
    )
    service = AuthService(engine.store, settings)
    await service.initialize()
    await engine.store.set_ad_group_role_map(
        [(OPS, Role.OPERATOR.value), (VIEW, Role.VIEWER.value)]
    )
    return service


async def _sign_in(service: AuthService, principal: AdPrincipal) -> Any:
    """The completion both directory legs call, inside the account's queue."""
    return await service._complete_ad_login(
        principal, None, mfa_verified=False, session_mechanism=SessionMechanism.KERBEROS
    )


async def _user_id(engine: Engine, username: str = "jdoe") -> str:
    row = await engine.store.get_user_by_username(username)
    assert row is not None
    return row.id


async def _live_sessions(engine: Engine, user_id: str) -> set[str]:
    return {s.token_hash for s in await engine.store.list_sessions(user_id)}


def _after(
    original: Callable[..., Awaitable[Any]], then: Callable[[], Awaitable[None]]
) -> Callable[..., Awaitable[Any]]:
    async def wrapped(*args: Any, **kwargs: Any) -> Any:
        result = await original(*args, **kwargs)
        await then()
        return result

    return wrapped


def _before(
    original: Callable[..., Awaitable[Any]], first: Callable[[], Awaitable[None]]
) -> Callable[..., Awaitable[Any]]:
    async def wrapped(*args: Any, **kwargs: Any) -> Any:
        await first()
        return await original(*args, **kwargs)

    return wrapped


async def test_a_disable_during_the_role_and_scope_writes_gets_no_session(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The disable lands after the sign-in's eligibility check and its role write, before the
    mint. Before the fix the mint read only the binding and the epoch, so the account got a live
    session and an ``auth.login_success`` row."""
    service = await _service(engine)
    assert (await _sign_in(service, _principal())).ok
    user_id = await _user_id(engine)
    before = await _live_sessions(engine, user_id)

    async def disable() -> None:
        await engine.store.set_user_disabled(user_id, disabled=True)

    monkeypatch.setattr(
        service, "_sync_ad_channel_scope", _after(service._sync_ad_channel_scope, disable)
    )
    out = await _sign_in(service, _principal())
    assert not out.ok
    assert out.reason == "disabled"
    assert out.token is None
    assert await _live_sessions(engine, user_id) <= before


async def test_a_disable_between_the_check_and_the_insert_is_refused_by_the_store(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The disable lands after the re-read before the mint, so only the insert can see it."""
    service = await _service(engine)
    assert (await _sign_in(service, _principal())).ok
    user_id = await _user_id(engine)
    before = await _live_sessions(engine, user_id)

    async def disable() -> None:
        await engine.store.set_user_disabled(user_id, disabled=True)

    monkeypatch.setattr(
        engine.store, "create_session", _before(engine.store.create_session, disable)
    )
    out = await _sign_in(service, _principal())
    assert not out.ok
    assert out.reason == "disabled"
    assert await _live_sessions(engine, user_id) <= before


async def test_a_lock_between_the_check_and_the_insert_is_refused_by_the_store(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = await _service(engine)
    assert (await _sign_in(service, _principal())).ok
    user_id = await _user_id(engine)
    before = await _live_sessions(engine, user_id)

    async def lock() -> None:
        await engine.store.record_login_failure(
            user_id, failed_attempts=5, locked_until=time.time() + 600
        )

    monkeypatch.setattr(engine.store, "create_session", _before(engine.store.create_session, lock))
    out = await _sign_in(service, _principal())
    assert not out.ok
    assert out.reason == "locked"
    assert await _live_sessions(engine, user_id) <= before
    row = await engine.store.get_user(user_id)
    assert row is not None and row.locked_until is not None


async def test_a_lock_set_after_the_mint_is_not_cleared_by_the_sign_in(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Before the fix ``record_login_success`` zeroed the counters unconditionally after the mint,
    so a lockout that committed in between was wiped by the sign-in it should have outlived."""
    service = await _service(engine)
    assert (await _sign_in(service, _principal())).ok
    user_id = await _user_id(engine)
    until = time.time() + 600

    async def lock() -> None:
        await engine.store.record_login_failure(user_id, failed_attempts=5, locked_until=until)

    monkeypatch.setattr(engine.store, "create_session", _after(engine.store.create_session, lock))
    await _sign_in(service, _principal())
    row = await engine.store.get_user(user_id)
    assert row is not None
    assert row.locked_until == pytest.approx(until)
    assert row.failed_attempts == 5


async def test_an_unchanged_row_still_has_its_counters_cleared(engine: Engine) -> None:
    """The compare-and-set clears as before when nothing moved."""
    service = await _service(engine)
    assert (await _sign_in(service, _principal())).ok
    user_id = await _user_id(engine)
    await engine.store.record_login_failure(user_id, failed_attempts=2, locked_until=None)
    assert (await _sign_in(service, _principal())).ok
    row = await engine.store.get_user(user_id)
    assert row is not None
    assert row.failed_attempts == 0


async def test_two_sign_ins_that_move_the_roles_keep_each_others_session(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Sign-in B reads the account after sign-in A has, and resumes only once A has minted. Before
    the fix B's role write found A's set already in place, counted it as its own change, and
    revoked every session of the account, A's new one included. In the queue B cannot read the
    account until A is done, so it finds the roles already its target and revokes nothing; the
    ``wait_for`` timeouts are what let A go on when B is held in the queue."""
    service = await _service(engine)
    assert (await _sign_in(service, _principal(group=OPS))).ok
    b_resolved = asyncio.Event()
    a_done = asyncio.Event()
    calls = 0
    original = service._upsert_ad_user

    async def upsert(*args: Any, **kwargs: Any) -> Any:
        nonlocal calls
        calls += 1
        mine = calls
        result = await original(*args, **kwargs)
        if mine == 1:
            # B is held in the queue once the fix is in, so the wait times out and A goes on.
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(b_resolved.wait(), timeout=1.0)
        else:
            b_resolved.set()
            await asyncio.wait_for(a_done.wait(), timeout=10.0)
        return result

    monkeypatch.setattr(service, "_upsert_ad_user", upsert)
    a = asyncio.create_task(_sign_in(service, _principal(group=VIEW)))
    await asyncio.sleep(0)
    b = asyncio.create_task(_sign_in(service, _principal(group=VIEW)))
    try:
        first = await a
        a_done.set()
        second = await b
    finally:
        # A failing ``a`` must not leave ``b`` waiting on ``a_done`` past the test.
        b.cancel()
        await asyncio.gather(b, return_exceptions=True)
    assert first.ok and second.ok
    assert await service.identity_for_token(first.token, activity=False) is not None
    assert await service.identity_for_token(second.token, activity=False) is not None


async def test_an_unchanged_directory_profile_writes_no_profile_row(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Item 1 (S11-33): a returning sign-in used to re-write and re-seal the same display name and
    address on every sign-in. A changed value is still written."""
    service = await _service(engine)
    assert (await _sign_in(service, _principal())).ok
    writes: list[str | None] = []
    original = engine.store.update_user_profile

    async def counted(user_id: str, **kwargs: Any) -> None:
        writes.append(kwargs.get("display_name"))
        await original(user_id, **kwargs)

    monkeypatch.setattr(engine.store, "update_user_profile", counted)
    assert (await _sign_in(service, _principal())).ok
    assert writes == []
    assert (await _sign_in(service, _principal(display_name="J Q Doe"))).ok
    assert writes == ["J Q Doe"]
    row = await engine.store.get_user_by_username("jdoe")
    assert row is not None and row.display_name == "J Q Doe"


@pytest.mark.parametrize("state", ["disabled", "locked"])
async def test_the_store_refuses_an_ineligible_row_only_when_asked(
    engine: Engine, state: str
) -> None:
    """The SQLite half of ``require_sign_in_eligible``; the server backends share
    ``sign_in_state_refused`` and are read by the server legs."""
    service = await _service(engine)
    assert (await _sign_in(service, _principal())).ok
    user_id = await _user_id(engine)
    now = time.time()
    if state == "disabled":
        await engine.store.set_user_disabled(user_id, disabled=True)
    else:
        await engine.store.record_login_failure(user_id, failed_attempts=5, locked_until=now + 600)

    async def mint(eligible: bool) -> bool:
        return await engine.store.create_session(
            token_hash=hash_token(uuid.uuid4().hex),
            user_id=user_id,
            expires_at=now + 3600,
            seed_reauth=False,
            auth_mechanism="kerberos",
            require_sign_in_eligible=eligible,
        )

    assert await mint(True) is False
    assert await mint(False) is True


def test_sign_in_state_refused_reads_each_backends_column_shapes() -> None:
    """Disabled as an int, a bool or a bit, and either lock live, refuse; a lapsed lock does not."""
    now = 1_000.0
    assert sign_in_state_refused(1, None, None, now)
    assert sign_in_state_refused(True, None, None, now)
    assert sign_in_state_refused(0, now + 1, None, now)
    assert sign_in_state_refused(0, None, now + 1, now)
    assert not sign_in_state_refused(0, now - 1, now, now)
    assert not sign_in_state_refused(False, None, None, now)
