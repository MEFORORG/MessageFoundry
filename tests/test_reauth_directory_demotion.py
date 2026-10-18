# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The password re-bind step-up refuses a directory account the directory has demoted.

BACKLOG #3081 item 1. The code leg, the passkey leg (#2240) and the IdP leg (#2154) refuse an
account whose stored roles are not all among the roles its current groups map to. The password
re-bind got the groups back from the bind and did not look at them, so on a first deployment an
operator demoted in the directory would still have renewed its window, and been minted an action
grant, with its old roles until the reconciler's role pass or the next sign-in.

Each refusal asserts: no window renewed, no grant minted, nothing charged to the session's budget or
the account counter, nothing cleared from them, and no roles written. The same session steps up
once the directory gives the groups back, so the refusal was the role test and not a broken fake.
All directory data here is synthetic.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth.identity import Identity
from messagefoundry.auth.ldap import AdPrincipal
from messagefoundry.auth.service import (
    DIRECTORY_ROLES_DEMOTED,
    STEP_UP_ACTION_MFA_DISABLE,
    AuthService,
    DirectoryRefusal,
    _DirectoryRebind,
)
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store.store import MessageStore
from tests._fake_directory import RebindDirectory

_OBJECT_ID = "3b0f5a1e-7c2d-4e8f-9a6b-1d2c3e4f5a6b"
_OPERATORS = "cn=mf-operators,ou=groups,dc=test,dc=invalid"
_VIEWERS = "cn=mf-viewers,ou=groups,dc=test,dc=invalid"
_GOOD = "synthetic-good"  # nosec B105 -- the password RebindDirectory binds


def _principal(*groups: str) -> AdPrincipal:
    return AdPrincipal(
        username="jdoe",
        display_name="J Doe",
        email="jdoe@test.invalid",
        dn="CN=jdoe,OU=Staff,DC=test,DC=invalid",
        groups=frozenset(groups),
        directory_object_id=_OBJECT_ID,
    )


@dataclass
class _Session:
    service: AuthService
    # Binds a good password as ``bound``, whose groups a test moves between calls.
    directory: RebindDirectory
    identity: Identity
    token: str


@pytest.fixture
async def store() -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(":memory:")
    yield s
    await s.close()


async def _signed_in(store: MessageStore, *groups: str) -> _Session:
    """A directory session whose roles the sign-in wrote from ``groups``, under a two-group map."""
    directory = RebindDirectory(_principal(*groups))
    settings = AuthSettings(
        ad_enabled=True,
        ad_server="ldaps://dc.test.invalid",
        ad_user_search_base="OU=Staff,DC=test,DC=invalid",
        ad_bind_dn="CN=svc-mefor,OU=Service,DC=test,DC=invalid",
        ad_bind_password="synthetic",
        require_mfa=False,
    )
    service = AuthService(store, settings, ldap=directory)  # type: ignore[arg-type]
    await service.initialize()
    await service.set_ad_group_map([(_OPERATORS, "operator"), (_VIEWERS, "viewer")], actor="admin")
    out = await service._complete_ad_login(_principal(*groups), None, mfa_verified=True)
    assert out.ok and out.identity is not None and out.token is not None, out.error
    return _Session(service, directory, out.identity, out.token)


async def _reauth_reasons(store: MessageStore) -> list[str]:
    return [str(dict(r)["detail"]) for r in await store.list_audit(action="auth.reauth")]


@pytest.mark.parametrize("now_in", [(_VIEWERS,), ()], ids=["one-role-lost", "every-role-lost"])
async def test_a_directory_account_demoted_since_sign_in_is_refused_the_re_bind_step_up(
    store: MessageStore, now_in: tuple[str, ...]
) -> None:
    """RED when: ``reauth`` renews the window, or mints the action grant, of an account the
    directory has since demoted. The refusal must charge, register and clear nothing, and leave the
    stored roles for the reconciler to re-sync."""
    s = await _signed_in(store, _OPERATORS, _VIEWERS)
    assert set(await store.get_user_role_ids(s.identity.user_id)) == {"operator", "viewer"}
    token_hash = hash_token(s.token)
    # One wrong password first, so a refusal that popped the session's budget or cleared the account
    # counter would show as a drop from one to zero.
    wrong = await s.service.reauth(s.identity, "synthetic-wrong", token=s.token)
    assert not wrong.ok and wrong.directory_refusal is None
    before = await store.get_session(token_hash)
    assert before is not None
    s.directory.bound = _principal(*now_in)

    refused = await s.service.reauth(
        s.identity, _GOOD, token=s.token, purpose=STEP_UP_ACTION_MFA_DISABLE
    )

    assert not refused.ok and refused.token is None
    assert refused.directory_refusal is DirectoryRefusal.DEMOTED and refused.session_lost is False
    after = await store.get_session(token_hash)
    assert after is not None and after.revoked_at is None
    assert after.reauth_at == before.reauth_at, "the demoted account's window was renewed"
    assert not s.service._action_step_up_grants, "a demoted account was minted an action grant"
    assert s.service._session_reproof_failures(token_hash) == 1
    user = await store.get_user(s.identity.user_id)
    assert user is not None and user.failed_attempts == 1 and user.locked_until is None
    assert any(f'"reason": "{DIRECTORY_ROLES_DEMOTED}"' in d for d in await _reauth_reasons(store))
    assert set(await store.get_user_role_ids(s.identity.user_id)) == {"operator", "viewer"}
    # The groups came back with the bind: one directory call per attempt, no second read.
    assert s.directory.keys == [_OBJECT_ID, _OBJECT_ID]

    # CONTROL: once the directory gives the groups back, the same session steps up and is granted.
    s.directory.bound = _principal(_OPERATORS, _VIEWERS)
    granted = await s.service.reauth(
        s.identity, _GOOD, token=s.token, purpose=STEP_UP_ACTION_MFA_DISABLE
    )
    assert granted.ok and granted.token is not None
    assert await s.service.has_action_step_up(granted.token, STEP_UP_ACTION_MFA_DISABLE)


@pytest.mark.parametrize(
    "now_in", [(_VIEWERS,), (_OPERATORS, _VIEWERS)], ids=["unchanged", "promoted"]
)
async def test_a_directory_account_not_demoted_still_steps_up_by_re_bind(
    store: MessageStore, now_in: tuple[str, ...]
) -> None:
    """The control: an unchanged account steps up, and so does a promoted one, whose session holds
    fewer roles than the directory grants rather than more."""
    s = await _signed_in(store, _VIEWERS)
    s.directory.bound = _principal(*now_in)

    elevation = await s.service.reauth(s.identity, _GOOD, token=s.token)

    assert elevation.ok and elevation.token is not None
    assert await s.service.has_recent_step_up(elevation.token) is True
    assert not any(DIRECTORY_ROLES_DEMOTED in d for d in await _reauth_reasons(store))


async def test_the_re_bind_judges_the_roles_read_after_the_bind(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #3081 item 8: the leg judges the roles of the row read AFTER the bind, as the other
    legs do. Pinned by a bare role write during the bind, with no session revocation. That is an
    instrument, not a production interleaving: every production role writer also revokes the
    account's sessions. RED when the leg compares the roles it read before the bind, which still
    hold the role the directory took away."""
    s = await _signed_in(store, _OPERATORS, _VIEWERS)
    s.directory.bound = _principal(_VIEWERS)
    original = s.service._reauth_ad

    async def bind_then_resync(username: str, password: str, *, object_id: str) -> _DirectoryRebind:
        rebind = await original(username, password, object_id=object_id)
        await store.set_user_roles(s.identity.user_id, ["viewer"], assigned_by="ad-sync")
        return rebind

    monkeypatch.setattr(s.service, "_reauth_ad", bind_then_resync)

    elevation = await s.service.reauth(s.identity, _GOOD, token=s.token)

    assert elevation.ok and elevation.token is not None


async def test_a_role_map_that_fails_its_seal_is_no_demotion_on_the_re_bind(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #3082 on the re-bind leg (#3081): a failing role map grants nothing, so every stored
    role would read as lost, but a new sign-in reads the same map. The refusal is
    ``directory_role_map_unsealed`` and its fix is UNCONFIRMED, never sign out. RED when the
    re-bind calls it a demotion."""
    from messagefoundry.auth import service as service_module
    from messagefoundry.auth.service import DIRECTORY_ROLE_MAP_UNSEALED

    s = await _signed_in(store, _OPERATORS, _VIEWERS)
    monkeypatch.setattr(service_module, "ad_map_seal_ok", lambda _sealer, _current: False)

    refused = await s.service.reauth(s.identity, _GOOD, token=s.token)

    assert not refused.ok and refused.token is None and refused.session_lost is False
    assert refused.directory_refusal is DirectoryRefusal.UNCONFIRMED
    reasons = await _reauth_reasons(store)
    assert any(f'"reason": "{DIRECTORY_ROLE_MAP_UNSEALED}"' in d for d in reasons), reasons
    assert not any(f'"reason": "{DIRECTORY_ROLES_DEMOTED}"' in d for d in reasons), reasons


async def test_a_row_re_pointed_during_the_bind_is_refused_not_judged(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The bind's groups vouch only for the object it was keyed on. A row whose directory object id
    moved during the round trip is refused as ``directory_identity_conflict``, uncharged, rather
    than judged on another object's groups. RED when the leg compares the moved row's roles with
    those groups: here they still grant every role, so it would step up."""
    s = await _signed_in(store, _OPERATORS, _VIEWERS)
    original = s.service._reauth_ad

    async def bind_then_repoint(
        username: str, password: str, *, object_id: str
    ) -> _DirectoryRebind:
        rebind = await original(username, password, object_id=object_id)
        await store._db.execute(
            "UPDATE users SET directory_object_id = ? WHERE id = ?",
            ("9c8b7a6f-5e4d-4c3b-8a2f-1e0d9c8b7a6f", s.identity.user_id),
        )
        await store._db.commit()
        return rebind

    monkeypatch.setattr(s.service, "_reauth_ad", bind_then_repoint)

    elevation = await s.service.reauth(s.identity, _GOOD, token=s.token)

    assert not elevation.ok and elevation.token is None
    assert elevation.directory_refusal is DirectoryRefusal.UNCONFIRMED
    user = await store.get_user(s.identity.user_id)
    assert user is not None and user.failed_attempts == 0
    assert any('"reason": "directory_identity_conflict"' in d for d in await _reauth_reasons(store))


async def test_the_reauth_route_answers_a_demoted_account_with_the_sign_in_again_words(
    tmp_path: Path,
) -> None:
    """The caller-facing half SECURITY.md states: ``POST /me/reauth`` answers a right password on a
    demoted account 403 with the demotion words, never "re-verification failed" and never the
    outage words, since a new sign-in clears a demotion (BACKLOG #3082). RED when the demotion
    stops setting ``directory_refusal``, or sets it to the outage fix."""
    engine = await Engine.create(
        tmp_path / "reauth_demoted.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    try:
        assert isinstance(engine.store, MessageStore)
        s = await _signed_in(engine.store, _OPERATORS, _VIEWERS)
        s.directory.bound = _principal(_VIEWERS)
        transport = httpx.ASGITransport(
            app=create_app(engine, auth=s.service), client=("127.0.0.1", 123)
        )
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            r = await c.post(
                "/me/reauth",
                json={"password": _GOOD},
                headers={"Authorization": f"Bearer {s.token}"},
            )
        assert r.status_code == 403
        assert "sign out and sign in again" in r.json()["detail"]
        assert "could not confirm" not in r.json()["detail"]
    finally:
        await engine.stop()
