# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #3023: the session revoke that follows a committed auth change is retried, and a
revoke the store refuses on every attempt is audited.

``revoke_user_sessions`` runs after its caller's change has committed: a password change or reset,
an MFA reset, a disable, a role, scope or custom-role change, or a directory map save. A store
refusal there, such as ``StoreAcquireTimeout`` at the acquire limit, a statement timeout or a lost
connection, used to end the request with a 500, the account's other sessions live, and no row
recording either. Each caller now goes through ``AuthService._revoke_after_commit``.

Each case below drives the CALLER, not the helper (closing steps 2 and 4): the store's
``revoke_user_sessions`` is made to raise ``StoreAcquireTimeout``, once and then always. Once, the
retry lands and no session the change should end is left live. Always, the change stands, the
request still fails, and one ``auth.sessions_revoke_failed`` row names the change. SQLite stands in
for the server backends: the retry is in the service, which every backend shares. Synthetic
accounts only.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Awaitable, Callable
from typing import Any

import pytest

from messagefoundry.auth import service as service_module
from messagefoundry.auth.passwords import hash_password
from messagefoundry.auth.service import SESSIONS_REVOKE_FAILED_ACTION, AuthService
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.base import StoreAcquireTimeout
from messagefoundry.store.store import MessageStore

_PASSWORD = "Str0ng-Synthetic-Pass!!"
_NEW_PASSWORD = "An0ther-Synthetic-Pass!!"

#: A caller under test: it takes the service, the store and the account's own login identity.
Caller = Callable[[AuthService, MessageStore, Any], Awaitable[None]]


async def _change_password(service: AuthService, _store: MessageStore, identity: Any) -> None:
    await service.change_password(identity, _NEW_PASSWORD)


async def _admin_reset_password(service: AuthService, _s: MessageStore, _i: Any) -> None:
    await service.admin_reset_password("u1", actor="admin")


async def _admin_reset_mfa(service: AuthService, _s: MessageStore, _i: Any) -> None:
    await service.admin_reset_mfa("u1", actor="admin")


async def _disable(service: AuthService, _s: MessageStore, _i: Any) -> None:
    await service.update_user(
        "u1", display_name=None, email="bob@example.org", disabled=True, actor="admin"
    )


async def _set_roles(service: AuthService, _s: MessageStore, _i: Any) -> None:
    await service.set_roles("u1", ["operator"], actor="admin")


async def _set_channel_scope(service: AuthService, _s: MessageStore, _i: Any) -> None:
    await service.set_channel_scope("u1", ["IB_SYNTH"], actor="admin")


async def _custom_role_edit(service: AuthService, store: MessageStore, _i: Any) -> None:
    role = await service.create_custom_role(
        display_name="Synthetic",
        description=None,
        permissions=["messages:view_summary"],
        actor="admin",
    )
    await store.set_user_roles("u1", ["viewer", role.id], assigned_by="test")
    await service.update_custom_role(
        role.id,
        display_name="Synthetic",
        description=None,
        permissions=["messages:view_summary"],
        actor="admin",
    )


#: Each caller, the change name its miss row records, and the audit row it writes once the revoke
#: lands.
CALLERS = [
    pytest.param(
        _change_password, "password_changed", "auth.password_changed", id="change_password"
    ),
    pytest.param(
        _admin_reset_password, "password_reset", "auth.password_reset", id="admin_reset_password"
    ),
    pytest.param(_admin_reset_mfa, "mfa_reset", "auth.mfa_reset", id="admin_reset_mfa"),
    pytest.param(_disable, "account_disabled", "user.updated", id="disable"),
    pytest.param(_set_roles, "roles_changed", "user.roles_changed", id="set_roles"),
    pytest.param(
        _set_channel_scope,
        "channel_scope_changed",
        "user.channel_scope_changed",
        id="set_channel_scope",
    ),
    pytest.param(_custom_role_edit, "custom_role_saved", "role.updated", id="custom_role_edit"),
]


async def _account(store: MessageStore, service: AuthService) -> tuple[Any, list[str]]:
    """Account u1 with two live sessions; returns its identity and both session hashes."""
    for role in ("viewer", "operator"):
        await store.upsert_role(role_id=role, display_name=role)
    await store.create_user(
        user_id="u1",
        username="bob",
        auth_provider="local",
        email="bob@example.org",
        password_hash=hash_password(_PASSWORD),
        password_generated=False,
        audits=(),
    )
    await store.set_user_roles("u1", ["viewer"], assigned_by="test")
    hashes: list[str] = []
    identity: Any = None
    for _ in range(2):
        out = await service.login("bob", _PASSWORD)
        assert out.ok and out.identity is not None and out.token is not None
        identity = out.identity
        hashes.append(hash_token(out.token))
    return identity, hashes


def _refusing(store: MessageStore, times: int | None) -> list[int]:
    """Make ``revoke_user_sessions`` raise ``StoreAcquireTimeout`` ``times`` times (``None``:
    always) before it runs. Returns the call counter."""
    real = store.revoke_user_sessions
    calls = [0]

    async def revoke(user_id: str, **kwargs: Any) -> Any:
        calls[0] += 1
        if times is None or calls[0] <= times:
            raise StoreAcquireTimeout("synthetic pool shortage")
        return await real(user_id, **kwargs)

    store.revoke_user_sessions = revoke  # type: ignore[method-assign]
    return calls


async def _live(store: MessageStore, hashes: list[str]) -> list[str]:
    live = []
    for h in hashes:
        row = await store.get_session(h)
        if row is not None and row.revoked_at is None:
            live.append(h)
    return live


async def _actions(store: MessageStore) -> list[Any]:
    return list(await store.list_audit(limit=200))


@pytest.fixture(autouse=True)
def _no_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service_module, "_POST_COMMIT_REVOKE_BACKOFF_SECONDS", 0.0)


@pytest.mark.parametrize(("caller", "change", "audited"), CALLERS)
async def test_a_refused_revoke_after_the_change_is_retried(
    caller: Caller, change: str, audited: str
) -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(require_mfa=False))
        identity, hashes = await _account(store, service)
        assert await _live(store, hashes) == hashes  # the control: both sessions are live
        calls = _refusing(store, 1)
        await caller(service, store, identity)
        assert calls[0] >= 2, "the refused revoke was not run again"
        assert await _live(store, hashes) == [], f"{change} left a session it should end"
        rows = await _actions(store)
        assert any(r["action"] == audited for r in rows), f"{change} lost its own audit row"
        assert not any(r["action"] == SESSIONS_REVOKE_FAILED_ACTION for r in rows)
    finally:
        await store.close()


@pytest.mark.parametrize(("caller", "change", "audited"), CALLERS)
async def test_a_revoke_refused_on_every_attempt_is_audited_and_raised(
    caller: Caller, change: str, audited: str
) -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(require_mfa=False))
        identity, hashes = await _account(store, service)
        calls = _refusing(store, None)
        with pytest.raises(StoreAcquireTimeout):
            await caller(service, store, identity)
        assert calls[0] == service_module._POST_COMMIT_REVOKE_ATTEMPTS
        assert await _live(store, hashes) == hashes  # what the row exists to record
        missed = [r for r in await _actions(store) if r["action"] == SESSIONS_REVOKE_FAILED_ACTION]
        assert len(missed) == 1, f"{change}: {missed}"
        detail = json.loads(missed[0]["detail"])
        assert detail == {
            "user_id": "u1",
            "change": change,
            "attempts": service_module._POST_COMMIT_REVOKE_ATTEMPTS,
            "error": "StoreAcquireTimeout",
        }
    finally:
        await store.close()


async def test_a_directory_map_save_retries_each_accounts_revoke() -> None:
    """``_revoke_ad_sessions`` revokes one account at a time; the retry covers each of them."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(require_mfa=False))
        hashes = []
        for n in (1, 2):
            await store.create_user(
                user_id=f"ad{n}",
                username=f"dir-{n}",
                auth_provider="ad",
                directory_object_id=f"guid-{n}",
                now=1.0,
                password_generated=False,
                audits=(),
            )
            token_hash = f"{n}" * 64
            await store.create_session(token_hash=token_hash, user_id=f"ad{n}", expires_at=9e9)
            hashes.append(token_hash)
        calls = _refusing(store, 1)
        await service.set_ad_group_scope_map([], actor="admin")
        assert calls[0] == 3  # one refusal, its retry, then the second account
        assert await _live(store, hashes) == []
        rows = await _actions(store)
        assert any(r["action"] == "ad_group_scope_map.updated" for r in rows)
    finally:
        await store.close()


async def test_a_refusal_that_is_not_a_store_fault_is_raised_at_once() -> None:
    """Only a store refusal is retried: anything else is a defect, raised on the first call."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(require_mfa=False))
        await _account(store, service)
        calls = [0]

        async def broken(user_id: str, **kwargs: Any) -> Any:
            calls[0] += 1
            raise LookupError("synthetic defect")

        store.revoke_user_sessions = broken  # type: ignore[method-assign]
        with pytest.raises(LookupError):
            await service.set_roles("u1", ["operator"], actor="admin")
        assert calls[0] == 1
        assert not any(r["action"] == SESSIONS_REVOKE_FAILED_ACTION for r in await _actions(store))
    finally:
        await store.close()


async def test_a_refusal_past_the_budget_is_recorded_without_a_re_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A refusal that took longer than the budget, as a SQL Server pool wait of up to 60 s does, is
    recorded at once: a second such wait would reach the request deadline, which cancels the
    request before any row is written. Budget 0 stands in for the slow refusal."""
    monkeypatch.setattr(service_module, "_POST_COMMIT_REVOKE_BUDGET_SECONDS", 0.0)
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(require_mfa=False))
        await _account(store, service)
        calls = _refusing(store, None)
        with pytest.raises(StoreAcquireTimeout):
            await service.set_roles("u1", ["operator"], actor="admin")
        assert calls[0] == 1
        [missed] = [
            r for r in await _actions(store) if r["action"] == SESSIONS_REVOKE_FAILED_ACTION
        ]
        assert json.loads(missed["detail"])["attempts"] == 1
    finally:
        await store.close()


async def _two_holders_of_a_custom_role(
    store: MessageStore, service: AuthService
) -> tuple[str, dict[str, str]]:
    """Accounts h1 and h2 both holding one custom role, one live session each."""
    await store.upsert_role(role_id="viewer", display_name="viewer")
    role = await service.create_custom_role(
        display_name="Synthetic", description=None, permissions=["messages:view_summary"], actor="a"
    )
    sessions = {}
    for n in ("h1", "h2"):
        await store.create_user(
            user_id=n,
            username=f"name-{n}",
            auth_provider="local",
            password_hash="h",
            now=1.0,
            password_generated=False,
            audits=(),
        )
        await store.set_user_roles(n, ["viewer", role.id], assigned_by="test")
        sessions[n] = n[-1] * 64
        await store.create_session(token_hash=sessions[n], user_id=n, expires_at=9e9)
    return role.id, sessions


def _refusing_for(store: MessageStore, refused_id: str) -> None:
    """Make ``revoke_user_sessions`` refuse every attempt for ``refused_id`` alone."""
    real = store.revoke_user_sessions

    async def revoke(user_id: str, **kwargs: Any) -> Any:
        if user_id == refused_id:
            raise StoreAcquireTimeout("synthetic pool shortage")
        return await real(user_id, **kwargs)

    store.revoke_user_sessions = revoke  # type: ignore[method-assign]


async def test_a_batch_stops_at_the_account_given_up_on_and_counts_the_rest() -> None:
    """A custom-role edit revokes each holder in turn. The first holder's revoke refused every time
    is recorded and raised at once, so a failing store costs one account's wait, not one per
    account; its row counts the holder it did not reach."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(require_mfa=False))
        role_id, sessions = await _two_holders_of_a_custom_role(store, service)
        _refusing_for(store, "h1")
        with pytest.raises(StoreAcquireTimeout):
            await service.update_custom_role(
                role_id,
                display_name="Synthetic",
                description=None,
                permissions=["messages:view_summary"],
                actor="alice",
            )
        assert await _live(store, list(sessions.values())) == list(sessions.values())
        [missed] = [
            r for r in await _actions(store) if r["action"] == SESSIONS_REVOKE_FAILED_ACTION
        ]
        assert missed["actor"] == "alice"
        detail = json.loads(missed["detail"])
        assert detail["user_id"] == "h1" and detail["accounts_not_attempted"] == 1
    finally:
        await store.close()


async def test_a_defect_is_raised_at_once_and_not_recorded_as_a_refusal() -> None:
    """``sqlite3.ProgrammingError`` is a ``DatabaseError``, so ``_session_write_errors`` catches it,
    but it reads as a bug: re-running it fails the same way. It is raised on the first call."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(require_mfa=False))
        await _account(store, service)
        calls = [0]

        async def broken(user_id: str, **kwargs: Any) -> Any:
            calls[0] += 1
            raise sqlite3.ProgrammingError("synthetic bad bind")

        store.revoke_user_sessions = broken  # type: ignore[method-assign]
        with pytest.raises(sqlite3.ProgrammingError):
            await service.set_roles("u1", ["operator"], actor="admin")
        assert calls[0] == 1
        assert not any(r["action"] == SESSIONS_REVOKE_FAILED_ACTION for r in await _actions(store))
    finally:
        await store.close()


async def test_a_custom_role_delete_revokes_before_it_deletes_and_records_no_miss() -> None:
    """The delete revokes first, so a refusal has nothing committed behind it: it is raised at once,
    the role stays, and no ``auth.sessions_revoke_failed`` row claims a change that never ran."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(require_mfa=False))
        role_id, _ = await _two_holders_of_a_custom_role(store, service)
        calls = _refusing(store, None)
        with pytest.raises(StoreAcquireTimeout):
            await service.delete_custom_role(role_id, actor="alice")
        assert calls[0] == 1
        assert role_id in {r.id for r in await service.list_custom_roles()}
        assert not any(r["action"] == SESSIONS_REVOKE_FAILED_ACTION for r in await _actions(store))
    finally:
        await store.close()
