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
from collections.abc import Awaitable, Callable
from typing import Any

import pytest

from messagefoundry.auth import service as service_module
from messagefoundry.auth.passwords import hash_password
from messagefoundry.auth.service import SESSIONS_REVOKE_FAILED_ACTION, AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.base import StoreAcquireTimeout
from messagefoundry.store.store import MessageStore

_PASSWORD = "Str0ng-Synthetic-Pass!!"
_NEW_PASSWORD = "An0ther-Synthetic-Pass!!"

#: The caller, the change name its miss row records, and the audit row it writes once the revoke
#: lands. Each takes the service, the store and the account's own login identity.
Caller = Callable[[AuthService, MessageStore, Any], Awaitable[object]]


async def _change_password(service: AuthService, _store: MessageStore, identity: Any) -> object:
    return await service.change_password(identity, _NEW_PASSWORD)


async def _admin_reset_password(service: AuthService, _s: MessageStore, _i: Any) -> object:
    return await service.admin_reset_password("u1", actor="admin")


async def _admin_reset_mfa(service: AuthService, _s: MessageStore, _i: Any) -> object:
    return await service.admin_reset_mfa("u1", actor="admin")


async def _disable(service: AuthService, _s: MessageStore, _i: Any) -> object:
    return await service.update_user(
        "u1", display_name=None, email="bob@example.org", disabled=True, actor="admin"
    )


async def _set_roles(service: AuthService, _s: MessageStore, _i: Any) -> object:
    return await service.set_roles("u1", ["operator"], actor="admin")


async def _set_channel_scope(service: AuthService, _s: MessageStore, _i: Any) -> object:
    return await service.set_channel_scope("u1", ["IB_SYNTH"], actor="admin")


async def _custom_role_edit(service: AuthService, store: MessageStore, _i: Any) -> object:
    role = await service.create_custom_role(
        display_name="Synthetic",
        description=None,
        permissions=["messages:view_summary"],
        actor="admin",
    )
    await store.set_user_roles("u1", ["viewer", role.id], assigned_by="test")
    return await service.update_custom_role(
        role.id,
        display_name="Synthetic",
        description=None,
        permissions=["messages:view_summary"],
        actor="admin",
    )


CALLERS: list[tuple[str, Caller, str, str]] = [
    ("change_password", _change_password, "password_changed", "auth.password_changed"),
    ("admin_reset_password", _admin_reset_password, "password_reset", "auth.password_reset"),
    ("admin_reset_mfa", _admin_reset_mfa, "mfa_reset", "auth.mfa_reset"),
    ("disable", _disable, "account_disabled", "user.updated"),
    ("set_roles", _set_roles, "roles_changed", "user.roles_changed"),
    (
        "set_channel_scope",
        _set_channel_scope,
        "channel_scope_changed",
        "user.channel_scope_changed",
    ),
    ("custom_role_edit", _custom_role_edit, "custom_role_saved", "role.updated"),
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
        hashes.append(service_module.hash_token(out.token))
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


async def _actions(store: MessageStore) -> list[dict[str, Any]]:
    return list(await store.list_audit(limit=200))


@pytest.fixture(autouse=True)
def _no_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service_module, "_POST_COMMIT_REVOKE_BACKOFF_SECONDS", 0.0)


@pytest.mark.parametrize(
    ("name", "caller", "change", "audited"), CALLERS, ids=[c[0] for c in CALLERS]
)
async def test_a_refused_revoke_after_the_change_is_retried(
    name: str, caller: Caller, change: str, audited: str
) -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(require_mfa=False))
        identity, hashes = await _account(store, service)
        assert await _live(store, hashes) == hashes  # the control: both sessions are live
        calls = _refusing(store, 1)
        await caller(service, store, identity)
        assert calls[0] >= 2, "the refused revoke was not run again"
        assert await _live(store, hashes) == [], f"{name} left a session the change should end"
        rows = await _actions(store)
        assert any(r["action"] == audited for r in rows), f"{name} lost its own audit row"
        assert not any(r["action"] == SESSIONS_REVOKE_FAILED_ACTION for r in rows)
    finally:
        await store.close()


@pytest.mark.parametrize(
    ("name", "caller", "change", "audited"), CALLERS, ids=[c[0] for c in CALLERS]
)
async def test_a_revoke_refused_on_every_attempt_is_audited_and_raised(
    name: str, caller: Caller, change: str, audited: str
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
        assert len(missed) == 1, f"{name}: {missed}"
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
