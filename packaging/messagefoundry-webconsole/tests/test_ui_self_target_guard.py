# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #3259 and #3260: the console's self-target refusals, by stored id, each audited.

At least nine admin routes refuse the caller's own account: reset-password, reset-mfa, federated
link and unlink, disable, delete, and since BACKLOG #1149 revoke-sessions, roles and channel-scope.
#3259 is the case-spelling bypass of four of the first six guards;
``api.auth_routes._refuse_if_self`` states why the console reaches it and the JSON plane does not.

The default SQLite test store compares case-sensitively, where a naive test gets a 404 "no such
user" whether or not the fix is in. So ``get_user`` is wrapped to fold case first, as a
case-insensitive collation would answer. The ``exact`` spelling is the control.

#3260 is the audit row: each refusal writes ``auth.self_target_refused`` naming the actor and the
caller's stored id, on both planes. The JSON plane's twin is ``tests/test_self_target_refusal_audit.py``.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator

import httpx
import pytest
from _ui_clients import SAME_ORIGIN, cookie_login, mint_bound_proof, provision, ui_client

from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store.store import UserRecord

#: (op, the path after /ui/users/{id}, the page whose re-auth mints the grant, form, refusal text).
#: ``None`` for the grant page means the route takes the login window, which a fresh login holds.
ROUTES = [
    ("password_reset", "/reset-password", "/reset-password", {}, "use change-password"),
    ("mfa_reset", "/reset-mfa", "/reset-mfa", {}, "use the self-service MFA settings"),
    (
        "federated_bind",
        "/federated-identity/link",
        "/federated-identity",
        {"subject": "S-1-me", "shown_issuer": "", "shown_subject": ""},
        "another administrator must change your own binding",
    ),
    (
        "federated_unbind",
        "/federated-identity/unlink",
        "/federated-identity/unlink-confirm",
        {"shown_issuer": "", "shown_subject": ""},
        "another administrator must change your own binding",
    ),
    (
        "disable",
        "/update",
        "",
        {"display_name": "", "email": "", "disabled": "on"},
        "cannot disable your own account",
    ),
    ("delete", "/delete", None, {}, "cannot delete your own account"),
    # BACKLOG #1149 (ASVS 7.5.2): each of these revokes the target's sessions on the login window.
    ("revoke_sessions", "/revoke-sessions", None, {}, "use the self-service session controls"),
    (
        "set_roles",
        "/roles",
        None,
        # Keeps Administrator, so only the self-guard stops the write and the session check bites.
        {"roles": "administrator"},
        "another administrator must change your own roles",
    ),
    (
        "channel_scope",
        "/channel-scope",
        None,
        {"scope_mode": "all"},
        "another administrator must change your own channel scope",
    ),
]


@pytest.fixture
async def root(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[tuple[httpx.AsyncClient, AuthService, str]]:
    """An administrator signed in over a store whose ``get_user`` folds case."""
    service = AuthService(
        engine.store,
        AuthSettings(
            require_mfa=False,
            admin_write_min_interval_seconds=0,
            oidc_issuer="https://idp.example",
        ),
    )
    await service.initialize()
    me = await provision(service, "root", [Role.ADMINISTRATOR.value])
    real = engine.store.get_user

    async def folded(user_id: str) -> UserRecord | None:
        return await real(user_id.lower())

    monkeypatch.setattr(engine.store, "get_user", folded)
    async with ui_client(engine, service) as c:
        await cookie_login(c, "root")
        yield c, service, me


@pytest.mark.parametrize("spelling", ["exact", "upper"])
@pytest.mark.parametrize(("op", "suffix", "grant_page", "form", "words"), ROUTES)
async def test_each_self_target_refusal_is_by_stored_id_and_audited(
    engine: Engine,
    root: tuple[httpx.AsyncClient, AuthService, str],
    spelling: str,
    op: str,
    suffix: str,
    grant_page: str | None,
    form: dict[str, str],
    words: str,
) -> None:
    c, _service, me = root
    assert me == me.lower(), "the stored id is lower-case hex, so upper-casing changes it"
    spelled = me if spelling == "exact" else me.upper()
    base = f"/ui/users/{spelled}"
    if grant_page is not None:
        await mint_bound_proof(c, base + grant_page)
    before = await engine.store.get_user(me)
    roles_before = await engine.store.get_user_role_ids(me)
    sessions_before = len(await engine.store.list_sessions(me))

    r = await c.post(base + suffix, data=form, headers=SAME_ORIGIN)

    assert r.status_code == 400, (r.status_code, r.text[:300])
    assert words in r.text
    rows = await engine.store.list_audit(action="auth.self_target_refused", limit=10)
    assert len(rows) == 1, "one refusal, one audit row"
    assert rows[0]["actor"] == "root"
    assert rows[0]["client"] == "127.0.0.1", "the refusal row dropped the caller's address"
    # The caller's stored id and the route, nothing more: no path spelling, no message content.
    assert json.loads(str(rows[0]["detail"])) == {"op": op, "user_id": me}
    # A backstop only. On the upper spelling the status and the row are what tell the fix apart: a
    # guard that let it through reached writes keyed by that spelling, which SQLite matches to no row.
    after = await engine.store.get_user(me)
    assert after is not None and before is not None
    assert (after.disabled, after.oidc_subject) == (before.disabled, before.oidc_subject)
    assert after.password_hash == before.password_hash, "a refused reset changed the credential"
    assert (after.channel_scope, after.channel_scope_source) == (
        before.channel_scope,
        before.channel_scope_source,
    )
    assert await engine.store.get_user_role_ids(me) == roles_before
    assert len(await engine.store.list_sessions(me)) == sessions_before, "a refusal ended sessions"


#: BACKLOG #1149's control: (path after /ui/users/{id}, form) for the three routes it closed.
SESSION_REVOKING = [
    (suffix, form)
    for op, suffix, _grant, form, _words in ROUTES
    if op in ("revoke_sessions", "set_roles", "channel_scope")
]


@pytest.mark.parametrize(("suffix", "form"), SESSION_REVOKING)
async def test_the_session_revoking_writes_still_reach_another_account(
    engine: Engine,
    root: tuple[httpx.AsyncClient, AuthService, str],
    suffix: str,
    form: dict[str, str],
) -> None:
    """The three routes BACKLOG #1149 closed to the caller still act on another account, on the
    login window, and write no refusal row. Exact spelling: an upper-cased id would reach writes
    keyed by that spelling, which this case-sensitive store matches to no row."""
    c, service, _me = root
    other = await provision(service, "viewer1", [Role.VIEWER.value])
    r = await c.post(f"/ui/users/{other}{suffix}", data=form, headers=SAME_ORIGIN)
    assert r.status_code == 303, (r.status_code, r.text[:300])
    assert await engine.store.list_audit(action="auth.self_target_refused", limit=10) == []


@pytest.mark.parametrize("op", ["password_reset", "mfa_reset"])
async def test_another_accounts_id_in_another_case_is_not_a_self_target(
    engine: Engine, root: tuple[httpx.AsyncClient, AuthService, str], op: str
) -> None:
    """The control for the stored-id branch: an upper-cased id that resolves to ANOTHER account is
    not the caller's, so the reset goes through and no refusal row is written."""
    c, service, _me = root
    other = await provision(service, "viewer1", [Role.VIEWER.value])
    suffix = {"password_reset": "/reset-password", "mfa_reset": "/reset-mfa"}[op]
    url = f"/ui/users/{other.upper()}{suffix}"
    await mint_bound_proof(c, url)
    r = await c.post(url, headers=SAME_ORIGIN)
    assert r.status_code == 200, (r.status_code, r.text[:300])
    assert await engine.store.list_audit(action="auth.self_target_refused", limit=10) == []


#: The channel-scope row of ``ROUTES``: its refusal text, which the tests below reuse.
_SCOPE_WORDS = next(words for op, *_rest, words in ROUTES if op == "channel_scope")

#: BACKLOG #3393: self-target channel-scope posts that a form check would refuse. The guard now
#: runs before every one of them.
_MALFORMED_SCOPE_FORMS = [
    pytest.param({"scope_mode": "bogus"}, id="unknown-mode"),
    pytest.param({"scope_mode": "list", "channels": ""}, id="empty-list"),
    pytest.param({"scope_mode": "list", "channels": "*"}, id="all-channels-token-in-list"),
    pytest.param({"scope_mode": "list", "channels": "not a connection!"}, id="bad-name"),
]


@pytest.mark.parametrize("spelling", ["exact", "upper"])
@pytest.mark.parametrize("form", _MALFORMED_SCOPE_FORMS)
async def test_a_malformed_self_target_scope_post_is_still_refused_and_audited(
    engine: Engine,
    root: tuple[httpx.AsyncClient, AuthService, str],
    spelling: str,
    form: dict[str, str],
) -> None:
    """RED when: ``/ui/users/{id}/channel-scope`` answers a malformed post aimed at the caller's
    own account with its form error, before the self-target guard runs, so no
    ``auth.self_target_refused`` row is written (BACKLOG #3393; #1149's round-2 finding 3)."""
    c, _service, me = root
    spelled = me if spelling == "exact" else me.upper()
    before = await engine.store.get_user(me)

    r = await c.post(f"/ui/users/{spelled}/channel-scope", data=form, headers=SAME_ORIGIN)

    assert r.status_code == 400, (r.status_code, r.text[:300])
    assert _SCOPE_WORDS in r.text
    rows = await engine.store.list_audit(action="auth.self_target_refused", limit=10)
    assert len(rows) == 1, "a malformed self-target post wrote no refusal row"
    assert json.loads(str(rows[0]["detail"])) == {"op": "channel_scope", "user_id": me}
    after = await engine.store.get_user(me)
    assert after is not None and before is not None
    assert (after.channel_scope, after.channel_scope_source) == (
        before.channel_scope,
        before.channel_scope_source,
    )


@pytest.mark.parametrize("form", _MALFORMED_SCOPE_FORMS)
async def test_a_malformed_scope_post_on_another_account_gets_its_form_error(
    engine: Engine, root: tuple[httpx.AsyncClient, AuthService, str], form: dict[str, str]
) -> None:
    """The control: the same posts aimed at another account still meet the form checks, and
    write no refusal row."""
    c, service, _me = root
    other = await provision(service, "viewer1", [Role.VIEWER.value])
    r = await c.post(f"/ui/users/{other}/channel-scope", data=form, headers=SAME_ORIGIN)
    assert r.status_code == 400, (r.status_code, r.text[:300])
    assert _SCOPE_WORDS not in r.text
    assert await engine.store.list_audit(action="auth.self_target_refused", limit=10) == []


#: The button each session-revoking route's form carries on a user page.
_BUTTONS = {
    "/roles": "Save roles",
    "/channel-scope": "Save channel scope",
    "/revoke-sessions": "Sign out all sessions",
}
#: (form action suffix, button) for the forms the caller's own user page no longer offers: every
#: route of ``SESSION_REVOKING``, so a route that joins it must have its form hidden too.
_SELF_HIDDEN_FORMS = [(suffix, _BUTTONS[suffix]) for suffix, _form in SESSION_REVOKING]
#: Forms the caller's own page still offers. Their routes refuse the caller's account too, so each
#: can only fail there; hiding them is outside BACKLOG #3393's scope, not a decision that they work.
_SELF_KEPT_FORMS = ["/update", "/reset-password", "/reset-mfa", "/delete"]


@pytest.mark.parametrize("spelling", ["exact", "upper"])
async def test_the_own_user_page_offers_no_roles_scope_or_sign_out_form(
    root: tuple[httpx.AsyncClient, AuthService, str], spelling: str
) -> None:
    """RED when: the caller's own user page offers Save roles, Save channel scope or Sign out all
    sessions, each a form whose route refuses the caller's own account (BACKLOG #3393; #1149's
    round-2 finding 2). Decided by the stored id, so the upper spelling is the caller's page too."""
    c, _service, me = root
    spelled = me if spelling == "exact" else me.upper()
    r = await c.get(f"/ui/users/{spelled}")
    assert r.status_code == 200, (r.status_code, r.text[:300])
    for suffix, button in _SELF_HIDDEN_FORMS:
        assert f'action="/ui/users/{me}{suffix}"' not in r.text, suffix
        assert button not in r.text, button
    for suffix in _SELF_KEPT_FORMS:
        assert f'action="/ui/users/{me}{suffix}"' in r.text, suffix
    assert "You cannot change your own roles here" in r.text
    assert "You cannot change your own channel scope here" in r.text
    assert 'href="/ui/account"' in r.text


async def test_another_users_page_still_offers_the_three_forms(
    root: tuple[httpx.AsyncClient, AuthService, str],
) -> None:
    """The control: another account's page renders all three forms and none of the notes."""
    c, service, _me = root
    other = await provision(service, "viewer1", [Role.VIEWER.value])
    r = await c.get(f"/ui/users/{other}")
    assert r.status_code == 200, (r.status_code, r.text[:300])
    for suffix, button in _SELF_HIDDEN_FORMS:
        assert f'action="/ui/users/{other}{suffix}"' in r.text, suffix
        assert button in r.text, button
    assert "You cannot change your own" not in r.text
