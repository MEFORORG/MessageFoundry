# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #3023: the session revoke that follows a committed auth change is retried, and a
revoke the store refuses on every attempt is audited.

``revoke_user_sessions`` runs after its caller's change has committed: a password change or reset,
an MFA reset, a disable, a role, scope or custom-role change, a directory map save, a directory
sign-in's role resync, or the ``provision-admin`` repair. A store
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

import asyncio
import json
import sqlite3
from collections.abc import Awaitable, Callable
from typing import Any

import pytest

from messagefoundry.auth import service as service_module
from messagefoundry.auth.passwords import hash_password
from messagefoundry.auth.service import (
    SESSIONS_REVOKE_FAILED_ACTION,
    AuthService,
    FirstAdministratorRefused,
)
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.base import StoreAcquireTimeout
from messagefoundry.store.store import AdminGrant, MessageStore
from tests.test_ad_session_reconcile import _ad_settings, _principal

_PASSWORD = "Str0ng-Synthetic-Pass!!"
_NEW_PASSWORD = "An0ther-Synthetic-Pass!!"

#: A caller under test: it takes the service, the store and the account's own login identity.
Caller = Callable[[AuthService, MessageStore, Any], Awaitable[None]]
#: The account a caller changes: it builds the service, and returns it with the account's login
#: identity, where the caller needs one, and the hashes of its two live sessions.
Account = Callable[[MessageStore], Awaitable[tuple[AuthService, Any, list[str]]]]
#: A batch change under test, ready to run, with the hashes of every session it should end.
Change = tuple[Callable[[], Awaitable[None]], list[str]]


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
    await store.set_user_roles("u1", ["viewer", role.id], assigned_by="test", audits=())
    await service.update_custom_role(
        role.id,
        display_name="Synthetic",
        description=None,
        permissions=["messages:view_summary"],
        actor="admin",
    )


async def _provision_admin(service: AuthService, _s: MessageStore, _i: Any) -> None:
    await service.provision_first_administrator(
        username="bob", password=_NEW_PASSWORD, notify_email="ops@example.org", actor="host"
    )


async def _ad_sign_in(service: AuthService, _s: MessageStore, _i: Any) -> None:
    await service._complete_ad_login(_PRINCIPAL, None, mfa_verified=True)


async def _ad_role_map_save(service: AuthService, _s: MessageStore, _i: Any) -> None:
    await service.set_ad_group_map([(_GROUP, "operator")], actor="admin")


async def _account(store: MessageStore) -> tuple[AuthService, Any, list[str]]:
    """Local account u1 with two live sessions; returns the service, the account's identity and
    both session hashes."""
    service = AuthService(store, AuthSettings(require_mfa=False))
    identity, hashes = await _local_account(store, service)
    return service, identity, hashes


async def _roleless_account(store: MessageStore) -> tuple[AuthService, Any, list[str]]:
    """Local account u1, holding no role, with two live sessions: the row ``provision-admin``
    repairs."""
    service = AuthService(store, AuthSettings(require_mfa=False))
    await service.initialize()  # seeds the Administrator role the grant writes
    await _create_u1(store)
    return service, None, await _sessions(store, "u1")


_GROUP = "cn=mf-ops,dc=x"
_PRINCIPAL = _principal("bob", _GROUP)


async def _directory_account(store: MessageStore) -> tuple[AuthService, Any, list[str]]:
    """Directory account u1, holding viewer, with two live sessions, and a role map that maps its
    group to operator, written through the store so the setup ends no session."""
    service = AuthService(store, _ad_settings(require_mfa=False))
    await service.initialize()
    await _directory_user(store, "u1", "bob", _PRINCIPAL.directory_object_id)
    await store.set_user_roles("u1", ["viewer"], assigned_by="test", audits=())
    await store.set_ad_group_role_map([(_GROUP, "operator")])
    return service, None, await _sessions(store, "u1")


async def _directory_user(store: MessageStore, user_id: str, name: str, object_id: Any) -> None:
    await store.create_user(
        user_id=user_id,
        username=name,
        auth_provider="ad",
        directory_object_id=object_id,
        now=1.0,
        password_generated=False,
        audits=(),
    )


async def _sessions(store: MessageStore, user_id: str) -> list[str]:
    """Two live sessions for ``user_id``; returns their hashes."""
    hashes = []
    for n in (1, 2):
        token_hash = f"{user_id}{n}".encode().hex().ljust(64, "0")
        await store.create_session(token_hash=token_hash, user_id=user_id, expires_at=9e9)
        hashes.append(token_hash)
    return hashes


#: Each caller, the change name its miss row records, the audit row it writes once the revoke
#: lands, and the account it changes.
CALLERS = [
    pytest.param(
        _change_password,
        "password_changed",
        "auth.password_changed",
        _account,
        id="change_password",
    ),
    pytest.param(
        _admin_reset_password,
        "password_reset",
        "auth.password_reset",
        _account,
        id="admin_reset_password",
    ),
    pytest.param(_admin_reset_mfa, "mfa_reset", "auth.mfa_reset", _account, id="admin_reset_mfa"),
    pytest.param(_disable, "account_disabled", "user.updated", _account, id="disable"),
    pytest.param(_set_roles, "roles_changed", "user.roles_changed", _account, id="set_roles"),
    pytest.param(
        _set_channel_scope,
        "channel_scope_changed",
        "user.channel_scope_changed",
        _account,
        id="set_channel_scope",
    ),
    pytest.param(
        _custom_role_edit, "custom_role_saved", "role.updated", _account, id="custom_role_edit"
    ),
    pytest.param(
        _provision_admin,
        "first_administrator_repair",
        "auth.first_administrator_provisioned",
        _roleless_account,
        id="provision_admin",
    ),
    pytest.param(
        _ad_sign_in,
        "ad_roles_resynced",
        "auth.ad_roles_resynced",
        _directory_account,
        id="ad_sign_in_resync",
    ),
    pytest.param(
        _ad_role_map_save,
        "ad_role_map_saved",
        "ad_group_map.updated",
        _directory_account,
        id="ad_role_map_save",
    ),
]


async def _create_u1(store: MessageStore) -> None:
    """Local account u1, named bob, holding no role."""
    await store.create_user(
        user_id="u1",
        username="bob",
        auth_provider="local",
        email="bob@example.org",
        password_hash=hash_password(_PASSWORD),
        password_generated=False,
        audits=(),
    )


async def _local_account(store: MessageStore, service: AuthService) -> tuple[Any, list[str]]:
    """Account u1 with two live sessions; returns its identity and both session hashes."""
    for role in ("viewer", "operator"):
        await store.upsert_role(role_id=role, display_name=role)
    await _create_u1(store)
    await store.set_user_roles("u1", ["viewer"], assigned_by="test", audits=())
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
    monkeypatch.setattr(
        service_module,
        "_PROVISION_REVOKE_RETRY",
        service_module._PROVISION_REVOKE_RETRY._replace(backoff_seconds=0.0),
    )


@pytest.mark.parametrize(("caller", "change", "audited", "account"), CALLERS)
async def test_a_refused_revoke_after_the_change_is_retried(
    caller: Caller, change: str, audited: str, account: Account
) -> None:
    store = await MessageStore.open(":memory:")
    try:
        service, identity, hashes = await account(store)
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


#: The callers that run inside a request. ``provision-admin`` runs offline on a longer budget and
#: turns a give-up into its own refusal; its cases are at the end of this file.
REQUEST_CALLERS = [p for p in CALLERS if p.id != "provision_admin"]


@pytest.mark.parametrize(("caller", "change", "audited", "account"), REQUEST_CALLERS)
async def test_a_revoke_refused_on_every_attempt_is_audited_and_raised(
    caller: Caller, change: str, audited: str, account: Account
) -> None:
    store = await MessageStore.open(":memory:")
    try:
        service, identity, hashes = await account(store)
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
        await _local_account(store, service)
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
        await _local_account(store, service)
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
        await store.set_user_roles(n, ["viewer", role.id], assigned_by="test", audits=())
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


async def _custom_role_batch(store: MessageStore) -> Change:
    """A custom-role edit by alice over holders h1 and h2."""
    service = AuthService(store, AuthSettings(require_mfa=False))
    role_id, sessions = await _two_holders_of_a_custom_role(store, service)

    async def edit() -> None:
        await service.update_custom_role(
            role_id,
            display_name="Synthetic",
            description=None,
            permissions=["messages:view_summary"],
            actor="alice",
        )

    return edit, list(sessions.values())


async def _ad_role_map_batch(store: MessageStore) -> Change:
    """An AD role-map save by alice over directory accounts h1 and h2."""
    service = AuthService(store, AuthSettings(require_mfa=False))
    await service.initialize()  # seeds the role the map names
    hashes = []
    for n in ("h1", "h2"):
        await _directory_user(store, n, f"dir-{n}", f"guid-{n}")
        hashes += await _sessions(store, n)

    async def save() -> None:
        await service.set_ad_group_map([(_GROUP, "operator")], actor="alice")

    return save, hashes


@pytest.mark.parametrize(
    "batch",
    [
        pytest.param(_custom_role_batch, id="custom_role_edit"),
        pytest.param(_ad_role_map_batch, id="ad_role_map_save"),
    ],
)
async def test_a_batch_stops_at_the_account_given_up_on_and_counts_the_rest(
    batch: Callable[[MessageStore], Awaitable[Change]],
) -> None:
    """A custom-role edit or an AD role-map save revokes each account in turn. The first account's
    revoke refused every time is recorded and raised at once, so a failing store costs one
    account's wait, not one per account; its row counts the account it did not reach."""
    store = await MessageStore.open(":memory:")
    try:
        change, hashes = await batch(store)
        _refusing_for(store, "h1")
        with pytest.raises(StoreAcquireTimeout):
            await change()
        assert await _live(store, hashes) == hashes
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
        await _local_account(store, service)
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


# Vault BACKLOG #3023 residual (4): `provision-admin` is an offline command with no request
# deadline, so its repair-branch revokes run on `_PROVISION_REVOKE_RETRY`, a budget of minutes,
# and one given up on after the grant says which host command ends the earlier holder's session.
# The budgets are scaled down here so the cases run in well under a second; the request budget
# is scaled down with them, so "longer than the request budget" keeps its meaning.

#: The scaled request budget, and how long the store refuses: past the first, inside the
#: command's (scaled to 5 s).
_REQUEST_BUDGET = 0.1
_REFUSED_FOR = 0.3
#: How long each refused attempt takes, so a refusal spans real time rather than a call count.
_ATTEMPT_TAKES = 0.02

#: A session the earlier holder minted after the first revoke, before `set_password`: the one the
#: revoke after the grant exists to end.
_LATE_SESSION = "1a7e" * 16


def _scaled(monkeypatch: pytest.MonkeyPatch, **changes: Any) -> None:
    """The request budget at :data:`_REQUEST_BUDGET`, and the command's budget at 5 s with no
    pause and ``changes`` applied; its attempts stay as shipped unless ``changes`` names them."""
    monkeypatch.setattr(service_module, "_POST_COMMIT_REVOKE_BUDGET_SECONDS", _REQUEST_BUDGET)
    retry = service_module._PROVISION_REVOKE_RETRY._replace(
        backoff_seconds=0.0, budget_seconds=5.0, **changes
    )
    monkeypatch.setattr(service_module, "_PROVISION_REVOKE_RETRY", retry)


def _refusing_over_time(
    store: MessageStore, refused_for: float | None, *, first_lands: bool
) -> list[int]:
    """Make ``revoke_user_sessions`` refuse for ``refused_for`` seconds from its first refusal
    (``None``: always), each refusal taking :data:`_ATTEMPT_TAKES`. With ``first_lands`` the
    first call (the repair's, before the grant) lands instead, and a late session is then minted
    for the account, as a sign-in by its earlier holder before ``set_password`` would be. Returns
    the call counter."""
    real = store.revoke_user_sessions
    calls = [0]
    first_refused_at: list[float] = []

    async def revoke(user_id: str, **kwargs: Any) -> Any:
        calls[0] += 1
        if first_lands and calls[0] == 1:
            result = await real(user_id, **kwargs)
            await store.create_session(token_hash=_LATE_SESSION, user_id=user_id, expires_at=9e9)
            return result
        now = asyncio.get_running_loop().time()
        if not first_refused_at:
            first_refused_at.append(now)
        if refused_for is None or now - first_refused_at[0] < refused_for:
            await asyncio.sleep(_ATTEMPT_TAKES)
            raise StoreAcquireTimeout("synthetic pool shortage")
        return await real(user_id, **kwargs)

    store.revoke_user_sessions = revoke  # type: ignore[method-assign]
    return calls


async def test_provision_admin_waits_out_a_refusal_past_the_request_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The revoke after the grant is refused for longer than the request budget but less than
    the command's: it lands, and no session of the earlier holder survives on the Administrator."""
    _scaled(monkeypatch)
    store = await MessageStore.open(":memory:")
    try:
        service, _, hashes = await _roleless_account(store)
        calls = _refusing_over_time(store, _REFUSED_FOR, first_lands=True)
        await _provision_admin(service, store, None)
        assert calls[0] > 1 + service_module._POST_COMMIT_REVOKE_ATTEMPTS
        assert await _live(store, [*hashes, _LATE_SESSION]) == []
        assert "administrator" in await store.get_user_role_ids("u1")
        rows = await _actions(store)
        assert any(r["action"] == "auth.first_administrator_provisioned" for r in rows)
        assert not any(r["action"] == SESSIONS_REVOKE_FAILED_ACTION for r in rows)
    finally:
        await store.close()


async def test_a_request_caller_keeps_the_request_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    """The control for the case above: the same refusal, after a role change on a request, is
    given up on at the request budget's time limit: both attempt caps are lifted, so only the time
    limit can stop it. The shipped request budget is pinned too: a request caller must stay inside
    the API's 120 s request deadline."""
    assert service_module._POST_COMMIT_REVOKE_ATTEMPTS == 3
    assert service_module._POST_COMMIT_REVOKE_BUDGET_SECONDS == 15.0
    _scaled(monkeypatch, attempts=1000)
    monkeypatch.setattr(service_module, "_POST_COMMIT_REVOKE_ATTEMPTS", 1000)
    store = await MessageStore.open(":memory:")
    try:
        service, _, hashes = await _account(store)
        calls = _refusing_over_time(store, _REFUSED_FOR, first_lands=False)
        with pytest.raises(StoreAcquireTimeout):
            await service.set_roles("u1", ["operator"], actor="admin")
        # Stopped by the 0.1 s time limit, well short of the 0.3 s refusal at 0.02 s an attempt.
        assert calls[0] < _REFUSED_FOR / _ATTEMPT_TAKES
        assert await _live(store, hashes) == hashes
        [missed] = [
            r for r in await _actions(store) if r["action"] == SESSIONS_REVOKE_FAILED_ACTION
        ]
        assert json.loads(missed["detail"])["change"] == "roles_changed"
    finally:
        await store.close()


async def test_provision_admin_given_up_after_the_grant_names_the_recovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every revoke after the grant refused: the command is refused, so it exits non-zero, the
    role stands, the miss is audited, and the text names the host command that ends the session,
    since a re-run refuses an account that holds the role."""
    _scaled(monkeypatch, attempts=4)
    store = await MessageStore.open(":memory:")
    try:
        service, _, _ = await _roleless_account(store)
        calls = _refusing_over_time(store, None, first_lands=True)
        with pytest.raises(FirstAdministratorRefused) as refused:
            await _provision_admin(service, store, None)
        text = str(refused.value)
        assert "now holds the Administrator role" in text
        assert "messagefoundry admin-revoke-sessions" in text
        assert isinstance(refused.value.__cause__, StoreAcquireTimeout)
        assert calls[0] == 1 + 4
        assert await _live(store, [_LATE_SESSION]) == [_LATE_SESSION]  # what the row records
        assert "administrator" in await store.get_user_role_ids("u1")
        [missed] = [
            r for r in await _actions(store) if r["action"] == SESSIONS_REVOKE_FAILED_ACTION
        ]
        assert json.loads(missed["detail"]) == {
            "user_id": "u1",
            "change": "first_administrator_granted",
            "attempts": 4,
            "error": "StoreAcquireTimeout",
        }
        # The granted run is still recorded, saying the revoke did not land.
        [provisioned] = [
            r
            for r in await _actions(store)
            if r["action"] == "auth.first_administrator_provisioned"
        ]
        assert json.loads(provisioned["detail"])["earlier_sessions_revoked"] is False
        # A re-run is refused, which is why the text points elsewhere.
        assert await service.provision_refusal("bob", notify_email="ops@example.org") is not None
    finally:
        await store.close()


async def test_provision_admin_given_up_before_the_grant_grants_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The repair's first revoke runs on the command's budget too. Given up on, the run is refused
    before the password or the role, so a re-run completes the account."""
    _scaled(monkeypatch, attempts=4)
    store = await MessageStore.open(":memory:")
    try:
        service, _, hashes = await _roleless_account(store)
        before = await store.get_user("u1")
        calls = _refusing(store, None)
        with pytest.raises(FirstAdministratorRefused, match="set no password and granted no role"):
            await _provision_admin(service, store, None)
        assert calls[0] == 4
        assert await store.get_user_role_ids("u1") == []
        after = await store.get_user("u1")
        assert before is not None and after is not None
        assert after.password_hash == before.password_hash
        assert await _live(store, hashes) == hashes
        [missed] = [
            r for r in await _actions(store) if r["action"] == SESSIONS_REVOKE_FAILED_ACTION
        ]
        assert json.loads(missed["detail"])["change"] == "first_administrator_repair"
    finally:
        await store.close()


async def test_provision_admin_waits_out_a_refusal_before_the_grant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The first revoke, refused past the request budget, lands on the command's budget."""
    _scaled(monkeypatch)
    store = await MessageStore.open(":memory:")
    try:
        service, _, hashes = await _roleless_account(store)
        calls = _refusing_over_time(store, _REFUSED_FOR, first_lands=False)
        await _provision_admin(service, store, None)
        assert calls[0] > service_module._POST_COMMIT_REVOKE_ATTEMPTS
        assert await _live(store, hashes) == []
        assert "administrator" in await store.get_user_role_ids("u1")
    finally:
        await store.close()


@pytest.mark.parametrize("outcome", [AdminGrant.ADMIN_EXISTS, AdminGrant.ACCOUNT_CHANGED])
async def test_a_provision_refused_at_the_grant_revokes_the_accounts_sessions(
    monkeypatch: pytest.MonkeyPatch, outcome: AdminGrant
) -> None:
    """A run the grant refuses has already set the password, so a session minted with it in the
    window is ended before the refusal is raised. No role is written either way."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(require_mfa=False))
        await service.initialize()
        real_set_password = store.set_password
        minted: list[str] = []

        async def set_password(user_id: str, **kwargs: Any) -> Any:
            result = await real_set_password(user_id, **kwargs)
            await store.create_session(token_hash=_LATE_SESSION, user_id=user_id, expires_at=9e9)
            assert await _live(store, [_LATE_SESSION]) == [_LATE_SESSION]
            minted.append(user_id)
            return result

        async def grant(*_a: Any, **_k: Any) -> AdminGrant:
            return outcome

        monkeypatch.setattr(store, "set_password", set_password)
        monkeypatch.setattr(store, "grant_first_admin_unless_admin_exists", grant)
        with pytest.raises(FirstAdministratorRefused, match="no role") as refused:
            await _provision_admin(service, store, None)
        assert minted, "the window session was not minted"
        assert await _live(store, [_LATE_SESSION]) == []
        assert await store.get_user_role_ids(minted[0]) == []
        assert "also refused" not in str(refused.value)
    finally:
        await store.close()


async def test_a_provision_refused_at_the_grant_keeps_its_text_when_the_revoke_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The hardening revoke given up on does not replace the refusal: its text gains a note, and
    the miss is recorded."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(require_mfa=False))
        await service.initialize()

        async def grant(*_a: Any, **_k: Any) -> AdminGrant:
            return AdminGrant.ADMIN_EXISTS

        monkeypatch.setattr(store, "grant_first_admin_unless_admin_exists", grant)
        _refusing(store, None)
        with pytest.raises(FirstAdministratorRefused, match="another enabled Administrator") as r:
            await _provision_admin(service, store, None)
        assert "The store also refused to end that account's sessions" in str(r.value)
        [missed] = [
            row for row in await _actions(store) if row["action"] == SESSIONS_REVOKE_FAILED_ACTION
        ]
        assert json.loads(missed["detail"])["change"] == "first_administrator_refused"
    finally:
        await store.close()
