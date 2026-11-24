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
import sqlite3
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

    assert await _mint(engine, user_id, eligible=True) is False
    assert await _mint(engine, user_id, eligible=False) is True


async def _mint(engine: Engine, user_id: str, *, eligible: bool) -> bool:
    return await engine.store.create_session(
        token_hash=hash_token(uuid.uuid4().hex),
        user_id=user_id,
        expires_at=time.time() + 3600,
        seed_reauth=False,
        auth_mechanism="kerberos",
        require_sign_in_eligible=eligible,
    )


@pytest.mark.parametrize("eligible", [True, False])
async def test_the_eligible_insert_reads_under_begin_immediate_on_sqlite(
    engine: Engine, eligible: bool
) -> None:
    """The eligibility read and the INSERT share one ``BEGIN IMMEDIATE``, so SQLite's write lock
    is held before the read. The insert without the guard keeps the deferred ``BEGIN`` (control)."""
    service = await _service(engine)
    assert (await _sign_in(service, _principal())).ok
    user_id = await _user_id(engine)
    db: Any = engine.store._db  # type: ignore[attr-defined]
    traced: list[str] = []
    await db.set_trace_callback(traced.append)
    try:
        assert await _mint(engine, user_id, eligible=eligible) is True
    finally:
        off: Any = None  # sqlite3 clears the trace on None; aiosqlite's stub types only a callable
        await db.set_trace_callback(off)
    select = next(i for i, s in enumerate(traced) if s.startswith("SELECT oidc_issuer"))
    begin = max(i for i, s in enumerate(traced[:select]) if s.startswith("BEGIN"))
    assert traced[begin] == ("BEGIN IMMEDIATE" if eligible else "BEGIN")
    assert any(s.startswith("INSERT INTO sessions") for s in traced[select:])


async def test_a_disable_committed_by_another_connection_is_refused_at_the_insert(
    engine: Engine, tmp_path: Path
) -> None:
    """Another connection to the same file stands in for another engine shard. It holds SQLite's
    write lock with a disable uncommitted while the insert starts; the insert waits at its
    ``BEGIN IMMEDIATE``, reads the committed disable, and refuses. Measured with the deferred
    ``BEGIN``: the insert read the row before the commit and its INSERT failed at once with
    ``database is locked``, so this test fails without the fix."""
    service = await _service(engine)
    assert (await _sign_in(service, _principal())).ok
    user_id = await _user_id(engine)
    before = await _live_sessions(engine, user_id)
    db: Any = engine.store._db  # type: ignore[attr-defined]
    traced: list[str] = []
    other = sqlite3.connect(
        tmp_path / "directory_sign_in_lock.db",
        isolation_level=None,
        timeout=5,
        check_same_thread=False,
    )
    try:
        # Off the event loop: a blocked BEGIN here must not stop an aiosqlite COMMIT it waits on.
        await asyncio.to_thread(other.execute, "BEGIN IMMEDIATE")
        await asyncio.to_thread(other.execute, "UPDATE users SET disabled=1 WHERE id=?", (user_id,))
        await db.set_trace_callback(traced.append)
        mint = asyncio.ensure_future(_mint(engine, user_id, eligible=True))
        # The control: the mint has issued its BEGIN before the other connection commits, so a
        # pass is not a mint that simply started after the commit.
        for _ in range(500):
            if any(s.startswith("BEGIN") for s in traced):
                break
            await asyncio.sleep(0.01)
        assert any(s.startswith("BEGIN") for s in traced)
        await asyncio.sleep(0.2)
        assert not mint.done()  # waiting on the other connection's write lock
        await asyncio.to_thread(other.execute, "COMMIT")
    finally:
        other.close()
    try:
        assert await mint is False
    finally:
        off: Any = None  # sqlite3 clears the trace on None; aiosqlite's stub types only a callable
        await db.set_trace_callback(off)
    assert await _live_sessions(engine, user_id) <= before


def test_sign_in_state_refused_reads_each_backends_column_shapes() -> None:
    """Disabled as an int, a bool or a bit, and either lock live, refuse; a lapsed lock does not."""
    now = 1_000.0
    assert sign_in_state_refused(1, None, None, now)
    assert sign_in_state_refused(True, None, None, now)
    assert sign_in_state_refused(0, now + 1, None, now)
    assert sign_in_state_refused(0, None, now + 1, now)
    assert not sign_in_state_refused(0, now - 1, now, now)
    assert not sign_in_state_refused(False, None, None, now)


def _sqlite_busy() -> sqlite3.OperationalError:
    exc = sqlite3.OperationalError("database is locked")
    exc.sqlite_errorcode = sqlite3.SQLITE_BUSY
    return exc


def _busy_begin_immediate(
    monkeypatch: pytest.MonkeyPatch,
    busy_times: int,
    *,
    error: Callable[[], Exception] = _sqlite_busy,
) -> list[bool]:
    """Make each ``BEGIN IMMEDIATE`` writer transaction answer busy ``busy_times`` times, as it
    does once ``busy_timeout`` is outlasted, and record each one opened. The deferred one runs."""
    from messagefoundry.store import store as store_module

    real = store_module._writer_txn
    opened: list[bool] = []
    monkeypatch.setattr(store_module, "_ADMIN_GRANT_BUSY_BACKOFF_SECONDS", 0.0)

    @contextlib.asynccontextmanager
    async def writer_txn(db: Any, lock: asyncio.Lock, *, immediate: bool = False) -> Any:
        if immediate:
            opened.append(True)
            if len(opened) <= busy_times:
                raise error()
        async with real(db, lock, immediate=immediate):
            yield

    monkeypatch.setattr(store_module, "_writer_txn", writer_txn)
    return opened


async def test_a_busy_begin_runs_the_insert_again(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Item B: a busy ``BEGIN IMMEDIATE`` is run again, so the re-read decides."""
    service = await _service(engine)
    assert (await _sign_in(service, _principal())).ok
    user_id = await _user_id(engine)
    opened = _busy_begin_immediate(monkeypatch, 2)
    assert await _mint(engine, user_id, eligible=True) is True
    assert len(opened) == 3


async def test_a_busy_that_outlasts_the_bound_refuses_the_sign_in(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Item B: a busy past the bound is a refused sign-in, not an ``OperationalError`` escaping
    ``_complete_ad_login`` after its role and profile writes, and no session is minted."""
    from messagefoundry.store.store import SESSION_MINT_ATTEMPTS

    service = await _service(engine)
    assert (await _sign_in(service, _principal())).ok
    user_id = await _user_id(engine)
    before = await _live_sessions(engine, user_id)
    opened = _busy_begin_immediate(monkeypatch, 10_000)
    assert await _mint(engine, user_id, eligible=True) is False
    assert len(opened) == SESSION_MINT_ATTEMPTS
    out = await _sign_in(service, _principal())
    assert not out.ok
    assert out.token is None
    assert await _live_sessions(engine, user_id) <= before


async def test_an_error_that_is_not_busy_is_raised_at_once(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control for item B: only the busy family is run again or read as a refusal."""
    service = await _service(engine)
    assert (await _sign_in(service, _principal())).ok
    user_id = await _user_id(engine)
    opened = _busy_begin_immediate(
        monkeypatch, 10_000, error=lambda: sqlite3.OperationalError("disk I/O error")
    )
    with pytest.raises(sqlite3.OperationalError, match="disk I/O error"):
        await _mint(engine, user_id, eligible=True)
    assert len(opened) == 1


@pytest.mark.parametrize("eligible", [True, False])
async def test_the_seal_is_made_with_no_transaction_open(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, eligible: bool
) -> None:
    """Item A: under a Vault Transit sealer the seal is an HTTP call, so it must not run while the
    writer holds its lock: on SQLite under BEGIN IMMEDIATE that would stall every engine shard."""
    from messagefoundry.store import store as store_module

    service = await _service(engine)
    assert (await _sign_in(service, _principal())).ok
    user_id = await _user_id(engine)
    store: Any = engine.store
    real = store_module.seal_session_async
    seals: list[tuple[bool, bool]] = []

    async def recording_seal(sealer: Any, record: Any) -> Any:
        seals.append((store._db.in_transaction, store._lock.locked()))
        return await real(sealer, record)

    monkeypatch.setattr(store_module, "seal_session_async", recording_seal)
    assert await _mint(engine, user_id, eligible=eligible) is True
    assert seals == [(False, False)]


async def test_an_epoch_raised_after_the_seal_is_sealed_again(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Item A's cost: the seal covers the session epochs read before the transaction. A revoke
    that raises one before the insert's locked read writes nothing, and the record is sealed again
    over the new epoch, so the session is not minted dead."""
    from messagefoundry.store import store as store_module
    from messagefoundry.store.store import no_audit_row

    service = await _service(engine)
    assert (await _sign_in(service, _principal())).ok
    user_id = await _user_id(engine)
    store: Any = engine.store
    real_seal = store_module.seal_session_async
    sealed_epochs: list[int] = []

    async def recording_seal(sealer: Any, record: Any) -> Any:
        sealed_epochs.append(record.user_epoch)
        if len(sealed_epochs) == 1:
            await store.revoke_user_sessions(user_id, audit=no_audit_row)
        return await real_seal(sealer, record)

    monkeypatch.setattr(store_module, "seal_session_async", recording_seal)
    token_hash = hash_token(uuid.uuid4().hex)
    assert await store.create_session(
        token_hash=token_hash,
        user_id=user_id,
        expires_at=time.time() + 3600,
        seed_reauth=False,
        auth_mechanism="kerberos",
        require_sign_in_eligible=True,
    )
    row = await store.get_user(user_id)
    session = await store.get_session(token_hash)
    assert row is not None and session is not None
    assert sealed_epochs == [row.session_epoch - 1, row.session_epoch]
    assert session.user_epoch == row.session_epoch


async def test_a_lock_that_lapses_while_the_insert_waits_is_judged_at_the_read(
    engine: Engine,
) -> None:
    """Item D: the eligibility read judges a lock's expiry once the writer lock is held, not at the
    time the insert began to wait for it. Held past a short lock, the insert then mints."""
    service = await _service(engine)
    assert (await _sign_in(service, _principal())).ok
    user_id = await _user_id(engine)
    store: Any = engine.store
    await store.record_login_failure(user_id, failed_attempts=5, locked_until=time.time() + 0.3)
    async with store._lock:
        mint = asyncio.ensure_future(_mint(engine, user_id, eligible=True))
        await asyncio.sleep(0.6)
        assert not mint.done()  # waiting on the writer lock this test holds
    assert await mint is True
