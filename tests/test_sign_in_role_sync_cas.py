# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #3085: a directory sign-in's role sync is a compare-and-set on the roles it read.

Another writer, a reconciler or a second sign-in, can write the account's roles between the
sign-in's read and its write. Each test plants that write there, through the store, and drives
both legs that share ``_complete_ad_login``: the Kerberos mint and the OIDC (federated) mint.

- a write in between is what the sign-in replaces: the audit row, the revoke and the
  Administrator-loss report are computed from it, not from the stale read;
- a write in between that already holds the sign-in's directory roles is success, and the
  sign-in changes nothing more;
- two lost compare-and-sets refuse the sign-in closed, with a ``role_sync_contended`` row, and
  leave what the other writer wrote.

Synthetic accounts only.
"""

from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import AsyncIterator, Sequence
from typing import Any

import pytest

from messagefoundry.auth.identity import SessionMechanism
from messagefoundry.auth.ldap import AdPrincipal
from messagefoundry.auth.service import (
    ACCOUNT_REFUSED,
    NO_ENABLED_ADMINISTRATOR_ACTION,
    ROLE_SYNC_CONTENDED,
    AuthService,
    LoginOutcome,
    _SignInRolesUnread,
    _UserLookup,
)
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.store import MessageStore
from tests._last_admin_store_contract import ADMIN, VIEWER

OPERATOR = "operator"
_GROUP = "cn=mf-ops,dc=x"
_PAIR = ("https://idp.example/tenant", "S-1-role-sync-cas")
_PRINCIPAL = AdPrincipal(
    username="jdoe",
    display_name="J Doe",
    email="j@x",
    dn="CN=jdoe,DC=x",
    groups=frozenset({_GROUP}),
    directory_object_id="3f1e6a40-5c0b-5b8e-9a51-0c6d3b0e7a85",
)
_SETTINGS = AuthSettings(
    ad_enabled=True,
    ad_server="ldaps://x",
    ad_user_search_base="DC=x",
    ad_bind_dn="CN=svc,DC=x",
    ad_bind_password="x",
)
LEGS = ("kerberos", "oidc")


@pytest.fixture
async def store() -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(":memory:")
    try:
        yield s
    finally:
        await s.close()


async def _sign_in(service: AuthService, leg: str) -> LoginOutcome:
    if leg == "kerberos":
        return await service._complete_ad_login(_PRINCIPAL, None, mfa_verified=True)
    return await service._complete_ad_login(
        _PRINCIPAL,
        None,
        mfa_verified=True,
        mech="oidc",
        session_mechanism=SessionMechanism.OIDC,
        federated_subject=_PAIR,
        idp_auth_time=time.time(),
    )


async def _signed_in(store: MessageStore, leg: str) -> tuple[AuthService, str, str]:
    """jdoe signed in once holding ``operator``, bound to :data:`_PAIR` on the OIDC leg. Returns
    the service, the account id and the live token of that leg's sign-in. The group map then
    moves through the store, not the service, whose map edit would end that session itself."""
    service = AuthService(store, _SETTINGS)
    await service.initialize()
    await service.set_ad_group_map([(_GROUP, OPERATOR)], actor="admin")
    first = await service._complete_ad_login(_PRINCIPAL, None, mfa_verified=True)
    user = await store.get_user_by_username("jdoe")
    assert user is not None
    if leg == "oidc":
        assert await store.set_user_federated_subject(user.id, *_PAIR) is not None
        first = await _sign_in(service, leg)
    assert first.ok and first.token is not None
    return service, user.id, first.token


def _interleave(
    monkeypatch: pytest.MonkeyPatch, store: MessageStore, sets: Sequence[Sequence[str]]
) -> list[int]:
    """Before each of the sign-in's role writes, write the next of ``sets`` as another writer
    would, between the sign-in's read and its write. Returns the role writes seen.

    The plain write is wrapped too, so on main, whose sign-in wrote with it, the race still lands
    and the tests fail on its outcome rather than on a call that never came."""
    real_cas = store.set_user_roles_if_held
    real_plain = store.set_user_roles
    seen: list[int] = []

    async def race(uid: str) -> None:
        if len(seen) < len(sets):
            await real_plain(uid, list(sets[len(seen)]), audits=())
        seen.append(1)

    async def racing(uid: str, role_ids: Sequence[str], **kw: Any) -> bool:
        await race(uid)
        return await real_cas(uid, role_ids, **kw)

    async def racing_plain(uid: str, role_ids: Sequence[str], **kw: Any) -> None:
        await race(uid)
        await real_plain(uid, role_ids, **kw)

    monkeypatch.setattr(store, "set_user_roles_if_held", racing)
    monkeypatch.setattr(store, "set_user_roles", racing_plain)
    return seen


async def _rows(store: MessageStore, action: str) -> list[dict[str, Any]]:
    return [json.loads(r["detail"] or "{}") for r in await store.list_audit(action=action)]


@pytest.mark.parametrize("leg", LEGS)
@pytest.mark.parametrize("target", [VIEWER, OPERATOR], ids=["changed", "unchanged"])
async def test_a_write_between_the_read_and_the_write_is_what_the_sign_in_replaces(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, leg: str, target: str
) -> None:
    """A reconciler-style write of Administrator lands between the sign-in's read of ``operator``
    and its write. The sign-in's compare-and-set loses, reads Administrator back, and replaces
    THAT: its row says so, the Administrator loss is reported, and the other sessions end.

    RED on main: the plain write replaced Administrator while every later step read the stale
    ``operator``. On the changed leg the row said ``from: operator`` and no loss was reported; on
    the unchanged leg the write took Administrator away with no row, no report and no revoke."""
    service, user_id, first = await _signed_in(store, leg)
    await store.set_ad_group_role_map([(_GROUP, target)])
    before = len(await _rows(store, "auth.ad_roles_resynced"))
    lost_before = len(await _rows(store, NO_ENABLED_ADMINISTRATOR_ACTION))
    _interleave(monkeypatch, store, [[ADMIN]])
    out = await _sign_in(service, leg)
    monkeypatch.undo()
    assert out.ok and out.token is not None
    assert await store.get_user_role_ids(user_id) == [target]
    rows = await _rows(store, "auth.ad_roles_resynced")
    assert len(rows) == before + 1
    assert rows[0] == {"from": [ADMIN], "to": [target]}, "the row named the stale read"
    lost = len(await _rows(store, NO_ENABLED_ADMINISTRATOR_ACTION)) - lost_before
    assert lost == 1, "the Administrator loss was computed from the stale read"
    assert await service.identity_for_token(first) is None, "a role change kept a stale session"


@pytest.mark.parametrize("leg", LEGS)
async def test_a_write_in_between_that_holds_the_directory_roles_is_success(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, leg: str
) -> None:
    """The other writer already wrote the directory's ``viewer``. The sign-in's compare-and-set on
    ``operator`` loses, reads ``viewer`` back, and stops: it writes nothing more, records no
    change and ends no session, since the writer that made the change owns those.

    RED on main: the sign-in wrote ``viewer`` again, recorded ``operator`` to ``viewer`` and ended
    the other sessions for a change it did not make."""
    service, user_id, first = await _signed_in(store, leg)
    await store.set_ad_group_role_map([(_GROUP, VIEWER)])
    before = await _rows(store, "auth.ad_roles_resynced")
    seen = _interleave(monkeypatch, store, [[VIEWER]])
    out = await _sign_in(service, leg)
    monkeypatch.undo()
    assert out.ok and out.token is not None
    assert out.roles_gained is None
    assert len(seen) == 1, "the sign-in wrote again after finding its roles in place"
    assert await store.get_user_role_ids(user_id) == [VIEWER]
    assert await _rows(store, "auth.ad_roles_resynced") == before
    assert await service.identity_for_token(first) is not None, "it ended a session for no change"


@pytest.mark.parametrize("leg", LEGS)
async def test_two_lost_compare_and_sets_refuse_the_sign_in_closed(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, leg: str
) -> None:
    """Another writer moves the roles before both of the sign-in's compare-and-sets, each time to
    a set that is not the directory's ``viewer``. The sign-in is refused, with an
    ``auth.login_failed`` row naming ``role_sync_contended``; no session is minted, and the other
    writer's roles stand. The refusal is of the sign-in, not of the role write.

    RED on main: the plain write overwrote the other writer and signed the user in."""
    service, user_id, first = await _signed_in(store, leg)
    await store.set_ad_group_role_map([(_GROUP, VIEWER)])
    before = await _rows(store, "auth.ad_roles_resynced")
    seen = _interleave(monkeypatch, store, [[ADMIN], [OPERATOR]])
    out = await _sign_in(service, leg)
    monkeypatch.undo()
    assert not out.ok and out.token is None
    assert out.reason == ROLE_SYNC_CONTENDED
    assert len(seen) == 2
    assert await store.get_user_role_ids(user_id) == [OPERATOR], "the sign-in overwrote the race"
    assert await _rows(store, "auth.ad_roles_resynced") == before
    refusals = [
        r for r in await _rows(store, "auth.login_failed") if r.get("reason") == ROLE_SYNC_CONTENDED
    ]
    expected: dict[str, Any] = {"provider": "ad", "reason": ROLE_SYNC_CONTENDED}
    if leg == "oidc":
        expected["mech"] = "oidc"
    assert len(refusals) == 1 and {k: refusals[0].get(k) for k in expected} == expected
    assert await service.identity_for_token(first) is not None, "a refused sign-in ended a session"
    assert len(await store.list_sessions(user_id)) == 1, "a refused sign-in minted a session"


@pytest.mark.parametrize("leg", LEGS)
async def test_a_record_that_fails_its_seal_when_read_again_refuses_the_sign_in(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, leg: str
) -> None:
    """After a lost compare-and-set the record is read again, twice since a refused read may be a
    re-key, and both reads fail the seal. The sign-in is refused as ``account_refused``, not as
    contention, and nothing is written."""
    service, user_id, first = await _signed_in(store, leg)
    await store.set_ad_group_role_map([(_GROUP, VIEWER)])
    seen = _interleave(monkeypatch, store, [[ADMIN]])
    real_lookup = service._lookup_user
    reads: list[str] = []

    async def lookup(uid: str) -> Any:
        if seen:
            reads.append(uid)
            return _UserLookup(None, True)
        return await real_lookup(uid)

    monkeypatch.setattr(service, "_lookup_user", lookup)
    out = await _sign_in(service, leg)
    monkeypatch.undo()
    assert not out.ok and out.reason == ACCOUNT_REFUSED
    assert len(seen) == 1 and len(reads) == 2
    assert await store.get_user_role_ids(user_id) == [ADMIN]
    assert len(await store.list_sessions(user_id)) == 1, "a refused sign-in minted a session"
    assert await service.identity_for_token(first) is not None


async def test_an_error_held_from_a_lost_write_is_raised_after_the_refusal(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The first write with its row raises a defect after another writer moved the roles; the
    retry without the row finds them moved and reads them back at another set. The second
    compare-and-set loses too, so the sign-in is refused, its row written, and the held defect is
    raised rather than dropped."""
    service, user_id, _first = await _signed_in(store, "kerberos")
    await store.set_ad_group_role_map([(_GROUP, VIEWER)])
    real_cas = store.set_user_roles_if_held
    real_plain = store.set_user_roles
    calls: list[int] = []

    async def racing(uid: str, role_ids: Sequence[str], **kw: Any) -> bool:
        calls.append(1)
        if len(calls) == 1:
            await real_plain(uid, [ADMIN], audits=())
            raise TypeError("synthetic defect")
        if len(calls) == 3:
            await real_plain(uid, [OPERATOR], audits=())
        return await real_cas(uid, role_ids, **kw)

    monkeypatch.setattr(store, "set_user_roles_if_held", racing)
    with pytest.raises(TypeError):
        await _sign_in(service, "kerberos")
    monkeypatch.undo()
    assert len(calls) == 3
    assert await store.get_user_role_ids(user_id) == [OPERATOR]
    refusals = [
        r for r in await _rows(store, "auth.login_failed") if r.get("reason") == ROLE_SYNC_CONTENDED
    ]
    assert len(refusals) == 1


async def test_a_read_error_after_a_lost_write_names_itself_on_the_held_error(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The first write raises a held defect and nothing lands; the read after it raises too. The
    held defect is the one raised, with the read's error named on it rather than dropped."""
    service, user_id, _first = await _signed_in(store, "kerberos")
    await store.set_ad_group_role_map([(_GROUP, VIEWER)])
    real_cas = store.set_user_roles_if_held
    real_plain = store.set_user_roles
    real_read_back = service._roles_read_back
    calls: list[int] = []

    async def racing(uid: str, role_ids: Sequence[str], **kw: Any) -> bool:
        calls.append(1)
        if len(calls) == 1:
            await real_plain(uid, [ADMIN], audits=())
            raise TypeError("synthetic defect")
        return await real_cas(uid, role_ids, **kw)

    async def lookup(_uid: str) -> Any:
        raise sqlite3.OperationalError("synthetic: disk I/O error")

    async def read_back(*args: Any, **kw: Any) -> bool | None:
        landed = await real_read_back(*args, **kw)
        monkeypatch.setattr(service, "_lookup_user_settled", lookup)
        return landed

    monkeypatch.setattr(store, "set_user_roles_if_held", racing)
    monkeypatch.setattr(service, "_roles_read_back", read_back)
    with pytest.raises(TypeError) as raised:
        await _sign_in(service, "kerberos")
    monkeypatch.undo()
    assert any("OperationalError" in note for note in raised.value.__notes__)
    assert len(calls) == 2
    assert await store.get_user_role_ids(user_id) == [ADMIN]


async def test_a_retry_whose_roles_cannot_be_read_back_ends_the_sessions_then_fails(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The first write is refused with its row after another writer moved the roles; the retry
    finds them moved and the read-back is refused. The change counts as written, so its row is
    written with ``read_back: refused`` and the other sessions end, and then the sign-in fails
    rather than mint a session on roles nobody read."""
    service, user_id, first = await _signed_in(store, "kerberos")
    await store.set_ad_group_role_map([(_GROUP, VIEWER)])
    real_cas = store.set_user_roles_if_held
    real_plain = store.set_user_roles
    real_lookup = service._lookup_user
    calls: list[int] = []

    async def racing(uid: str, role_ids: Sequence[str], **kw: Any) -> bool:
        calls.append(1)
        if len(calls) == 1:
            await real_plain(uid, [ADMIN], audits=())
            raise sqlite3.OperationalError("synthetic: disk I/O error")
        return await real_cas(uid, role_ids, **kw)

    async def lookup(uid: str) -> Any:
        if len(calls) >= 2:
            raise sqlite3.OperationalError("synthetic: disk I/O error")
        return await real_lookup(uid)

    monkeypatch.setattr(store, "set_user_roles_if_held", racing)
    monkeypatch.setattr(service, "_lookup_user", lookup)
    with pytest.raises(_SignInRolesUnread):
        await _sign_in(service, "kerberos")
    monkeypatch.undo()
    assert len(calls) == 2
    assert (await _rows(store, "auth.ad_roles_resynced"))[0] == {
        "from": [OPERATOR],
        "to": [VIEWER],
        "read_back": "refused",
    }
    assert await service.identity_for_token(first) is None, "an unread change kept a session"
    assert len(await store.list_sessions(user_id)) == 0, "an unread change minted a session"
