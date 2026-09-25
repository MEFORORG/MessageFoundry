# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1143 / #295 (ADR 0184): the admin routes that bind, rebind and unbind a federated identity.

``PUT`` and ``DELETE /users/{user_id}/federated-identity`` are the only way to create or remove a
federated binding, by the owner's 2026-09-06 ruling. A federated login never binds; an unbound one is
refused (ADR 0184 AC-4, pinned in ``tests/test_auth_oidc_service.py``).

Two properties carry the weight here, and each has a control:

- **The routes demand an ACTION-BOUND step-up.** A session that re-authenticated for a different
  action, or not at all, is refused before anything is written. The control is the same request
  succeeding once the grant names this action.
- **Every write leaves an audit row naming the actor**, and a rebind ends the account's sessions.

The issuer is not in the request: the service binds under the configured ``[auth].oidc_issuer``.
Federation itself stays off here -- an operator can bind accounts before turning it on.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path
from uuid import uuid4

import httpx
import pytest

from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine
from tests.test_api_auth import (
    ABSENT_USER_ID,
    _add,
    _auth,
    _client,
    _login,
    _reauth,
)

ISSUER = "https://idp.example"
ACTION = "admin_federated_identity"


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    """Local rather than imported: a fixture resolves by name in the module that requests it."""
    eng = await Engine.create(tmp_path / "federated_identity.db", poll_interval=0.02)
    yield eng
    await eng.stop()


async def _service(engine: Engine, **over: object) -> AuthService:
    settings: dict[str, object] = {"require_mfa": False, "oidc_issuer": ISSUER}
    settings.update(over)
    service = AuthService(engine.store, AuthSettings(**settings))  # type: ignore[arg-type]
    await service.initialize()
    return service


async def _ad_account(engine: Engine, username: str = "jdoe") -> str:
    """A directory mirror row, as a Kerberos sign-in leaves it: unbound."""
    user_id = uuid4().hex
    await engine.store.create_user(user_id=user_id, username=username, auth_provider="ad")
    return user_id


async def _admin(c: httpx.AsyncClient, service: AuthService) -> str:
    await _add(service, "root", Role.ADMINISTRATOR)
    return (await _login(c, "root")).json()["token"]


async def _audit(engine: Engine, action: str) -> list[dict[str, object]]:
    """Every audit row with ``action``. Filtered by the store, and past its default 50-row cap."""
    return [dict(a) for a in await engine.store.list_audit(action=action, limit=100_000)]


async def _audit_mark(engine: Engine) -> int:
    """The newest audit row's id, or 0 on an empty log. Rows after it are the ones written since."""
    newest = await engine.store.list_audit(limit=1)
    return int(newest[0]["id"]) if newest else 0


async def _federated_rows_since(engine: Engine, mark: int) -> list[dict[str, object]]:
    """Every ``auth.federated_subject_*`` audit row written after ``mark``, selected by id.

    By id rather than by position, for two reasons. ``list_audit`` returns NEWEST FIRST, so a slice
    past the old length picks the OLDEST rows. That passed only while the bootstrap admin's rows were
    the oldest; once #1526 retired that account, the setup bind was the oldest row and the slice
    reported it as written by the refusal. And ``list_audit`` stops at 50 rows by default, so on a log
    of 50 or more the old slice was always empty and could never fire."""
    rows = await engine.store.list_audit(limit=100_000)
    return [
        dict(a)
        for a in rows
        if int(a["id"]) > mark and str(a["action"]).startswith("auth.federated_subject_")
    ]


async def _pairs(engine: Engine, *user_ids: str) -> dict[str, tuple[str | None, str | None]]:
    """Each account's stored ``(issuer, sub)``; an absent account reads as unbound."""
    out: dict[str, tuple[str | None, str | None]] = {}
    for user_id in user_ids:
        user = await engine.store.get_user(user_id)
        out[user_id] = (None, None) if user is None else (user.oidc_issuer, user.oidc_subject)
    return out


async def test_bind_refuses_without_a_grant_bound_to_this_action(
    engine: Engine,
) -> None:
    """No grant, and a grant for a DIFFERENT action, are both refused with the step-up challenge
    naming this action, and nothing is written. The control is the third request: the same call with
    a grant for this action succeeds."""
    service = await _service(engine)
    target = await _ad_account(engine)
    async with _client(engine, service) as c:
        tok = await _admin(c, service)

        bare = await c.put(
            f"/users/{target}/federated-identity", json={"subject": "S-1-a"}, headers=_auth(tok)
        )
        assert bare.status_code == 403
        assert bare.headers.get("X-Step-Up-Action") == ACTION

        _r, tok = await _reauth(c, tok, purpose="admin_reset_password")
        assert _r.status_code == 200
        wrong = await c.put(
            f"/users/{target}/federated-identity", json={"subject": "S-1-a"}, headers=_auth(tok)
        )
        assert wrong.status_code == 403, "a grant for another action opened this route"

        user = await engine.store.get_user(target)
        assert user is not None and user.oidc_subject is None, "a refused request wrote a binding"
        assert await _audit(engine, "auth.federated_subject_bound") == []

        # CONTROL: the grant for THIS action lets the same request through.
        _r, tok = await _reauth(c, tok, purpose=ACTION)
        assert _r.status_code == 200
        ok = await c.put(
            f"/users/{target}/federated-identity", json={"subject": "S-1-a"}, headers=_auth(tok)
        )
        assert ok.status_code == 200, ok.text
        assert ok.json()["detail"] == "federated identity bound"


async def test_unbind_refuses_without_a_grant_bound_to_this_action(
    engine: Engine,
) -> None:
    service = await _service(engine)
    target = await _ad_account(engine)
    await service.bind_federated_subject(target, "S-1-a", actor="setup")
    async with _client(engine, service) as c:
        tok = await _admin(c, service)

        bare = await c.delete(f"/users/{target}/federated-identity", headers=_auth(tok))
        assert bare.status_code == 403
        assert bare.headers.get("X-Step-Up-Action") == ACTION
        user = await engine.store.get_user(target)
        assert user is not None and user.oidc_subject == "S-1-a", "a refused request unbound"

        # CONTROL.
        _r, tok = await _reauth(c, tok, purpose=ACTION)
        ok = await c.delete(f"/users/{target}/federated-identity", headers=_auth(tok))
        assert ok.status_code == 200, ok.text
        after = await engine.store.get_user(target)
        assert after is not None and (after.oidc_issuer, after.oidc_subject) == (None, None)


async def test_bind_rebind_and_unbind_each_leave_an_audit_row_naming_the_actor(
    engine: Engine,
) -> None:
    service = await _service(engine)
    target = await _ad_account(engine)
    await engine.store.create_session(token_hash="t-jdoe", user_id=target, expires_at=9e9, now=1.0)
    async with _client(engine, service) as c:
        tok = await _admin(c, service)

        _r, tok = await _reauth(c, tok, purpose=ACTION)
        r = await c.put(
            f"/users/{target}/federated-identity", json={"subject": "S-1-a"}, headers=_auth(tok)
        )
        assert r.status_code == 200, r.text
        [bound] = await _audit(engine, "auth.federated_subject_bound")
        assert bound["actor"] == "root"
        assert json.loads(str(bound["detail"])) == {
            "user_id": target,
            "username": "jdoe",
            "issuer": ISSUER,
            "subject": "S-1-a",
        }
        live = await engine.store.get_session("t-jdoe")
        assert live is not None and live.revoked_at is None, "a first bind revoked a session"

        # REBIND: the old identity's sessions end with its binding.
        _r, tok = await _reauth(c, tok, purpose=ACTION)
        r = await c.put(
            f"/users/{target}/federated-identity", json={"subject": "S-1-b"}, headers=_auth(tok)
        )
        assert r.status_code == 200, r.text
        assert r.json()["detail"] == "federated identity rebound; revoked 1 session(s)"
        [rebound] = await _audit(engine, "auth.federated_subject_rebound")
        assert rebound["actor"] == "root"
        assert json.loads(str(rebound["detail"])) == {
            "user_id": target,
            "username": "jdoe",
            "issuer": ISSUER,
            "subject": "S-1-b",
            "previous_issuer": ISSUER,
            "previous_subject": "S-1-a",
            "sessions_revoked": 1,
        }
        gone = await engine.store.get_session("t-jdoe")
        assert gone is not None and gone.revoked_at is not None

        # UNBIND, through the route, reusing BACKLOG #1474's service method.
        _r, tok = await _reauth(c, tok, purpose=ACTION)
        r = await c.delete(f"/users/{target}/federated-identity", headers=_auth(tok))
        assert r.status_code == 200, r.text
        [unbound] = await _audit(engine, "auth.federated_subject_unbound")
        assert unbound["actor"] == "root"
        assert json.loads(str(unbound["detail"]))["subject"] == "S-1-b"


@pytest.mark.parametrize(
    ("case", "status", "fragment"),
    [
        ("unknown user", 404, "no such user"),
        ("local account", 400, "only a directory"),
        ("same pair again", 400, "already holds that identity"),
        ("held elsewhere", 409, "already bound to another account"),
        ("padded subject", 400, "exact sub"),
        ("non-ASCII subject", 400, "printable ASCII"),
    ],
)
async def test_bind_refusals(
    engine: Engine,
    case: str,
    status: int,
    fragment: str,
) -> None:
    """Each refusal writes nothing and names its cause. ``same pair again`` matters most: a rebind to
    the pair already held would otherwise sign the account out for nothing."""
    service = await _service(engine)
    target = await _ad_account(engine)
    holder: str | None = None
    subject = "S-1-a"
    if case == "unknown user":
        target = ABSENT_USER_ID
    elif case == "local account":
        target = await service.create_local_user(
            username="jlocal",
            password="a-strong-test-passphrase",
            display_name=None,
            email=None,
            roles=[],
            actor="test",
        )
    elif case == "same pair again":
        await service.bind_federated_subject(target, subject, actor="setup")
    elif case == "held elsewhere":
        holder = await _ad_account(engine, "bsmith")
        await service.bind_federated_subject(holder, subject, actor="setup")
    elif case == "padded subject":
        subject = " S-1-a"
    elif case == "non-ASCII subject":
        subject = "S-1-\u00e9"
    if case != "unknown user":
        await engine.store.create_session(
            token_hash="t-target", user_id=target, expires_at=9e9, now=1.0
        )
    touched = [target] if holder is None else [target, holder]
    async with _client(engine, service) as c:
        tok = await _admin(c, service)
        _r, tok = await _reauth(c, tok, purpose=ACTION)
        mark = await _audit_mark(engine)
        pairs_before = await _pairs(engine, *touched)
        r = await c.put(
            f"/users/{target}/federated-identity", json={"subject": subject}, headers=_auth(tok)
        )
    assert r.status_code == status, r.text
    assert fragment in r.json()["detail"]
    assert await _pairs(engine, *touched) == pairs_before, "a refused bind moved a binding"
    written = await _federated_rows_since(engine, mark)
    assert written == [], f"a refused bind wrote {written!r}"
    if case != "unknown user":
        session = await engine.store.get_session("t-target")
        assert session is not None and session.revoked_at is None, "a refused bind signed out"


async def test_the_refusal_checks_catch_a_bind_written_after_the_mark(engine: Engine) -> None:
    """CONTROL for ``test_bind_refusals``: its two checks fire on a planted bind, and ignore one
    written before the mark.

    The older bind is what the position slice misread once #1526 retired the bootstrap admin: it is
    the oldest row in the log, and ``list_audit`` returns newest first."""
    service = await _service(engine)
    older = await _ad_account(engine, "bsmith")
    target = await _ad_account(engine)
    await service.bind_federated_subject(older, "S-1-a", actor="setup")

    mark = await _audit_mark(engine)
    pairs_before = await _pairs(engine, target, older)
    assert await _federated_rows_since(engine, mark) == [], "a row from before the mark was counted"

    # PLANTED: the write a defective refusal would make.
    await service.bind_federated_subject(target, "S-1-b", actor="planted")

    assert await _pairs(engine, target, older) != pairs_before, "the pair check missed a bind"
    written = await _federated_rows_since(engine, mark)
    assert [(a["action"], a["actor"]) for a in written] == [
        ("auth.federated_subject_bound", "planted")
    ], "the audit check missed a bind"

    # PLANTED, the holder half: a refusal that unbinds the account already holding the pair.
    mark = await _audit_mark(engine)
    holder_before = await _pairs(engine, older)
    await service.unbind_federated_subject(older, actor="planted")
    assert await _pairs(engine, older) != holder_before, "the pair check missed a holder unbind"
    assert [a["action"] for a in await _federated_rows_since(engine, mark)] == [
        "auth.federated_subject_unbound"
    ], "the audit check missed a holder unbind"


async def test_bind_refuses_when_no_issuer_is_configured(engine: Engine) -> None:
    """Without ``[auth].oidc_issuer`` there is no issuer whose tokens could ever present the pair."""
    service = await _service(engine, oidc_issuer=None)
    target = await _ad_account(engine)
    async with _client(engine, service) as c:
        tok = await _admin(c, service)
        _r, tok = await _reauth(c, tok, purpose=ACTION)
        r = await c.put(
            f"/users/{target}/federated-identity", json={"subject": "S-1-a"}, headers=_auth(tok)
        )
    assert r.status_code == 400
    assert "oidc_issuer" in r.json()["detail"]


async def test_unbind_of_an_unbound_account_is_a_400_and_unknown_is_a_404(
    engine: Engine,
) -> None:
    service = await _service(engine)
    target = await _ad_account(engine)
    async with _client(engine, service) as c:
        tok = await _admin(c, service)
        _r, tok = await _reauth(c, tok, purpose=ACTION)
        r = await c.delete(f"/users/{target}/federated-identity", headers=_auth(tok))
        assert r.status_code == 400 and "no federated binding" in r.json()["detail"]
        _r, tok = await _reauth(c, tok, purpose=ACTION)
        r = await c.delete(f"/users/{ABSENT_USER_ID}/federated-identity", headers=_auth(tok))
        assert r.status_code == 404


async def test_the_body_refuses_unknown_keys_and_an_issuer(engine: Engine) -> None:
    """The request carries no issuer. A client sending one is refused, not silently ignored, so it
    cannot believe it bound under an issuer of its choosing."""
    service = await _service(engine)
    target = await _ad_account(engine)
    async with _client(engine, service) as c:
        tok = await _admin(c, service)
        _r, tok = await _reauth(c, tok, purpose=ACTION)
        r = await c.put(
            f"/users/{target}/federated-identity",
            json={"subject": "S-1-a", "issuer": "https://evil.example"},
            headers=_auth(tok),
        )
    assert r.status_code == 422
    user = await engine.store.get_user(target)
    assert user is not None and user.oidc_subject is None


async def test_an_administrator_cannot_change_their_own_binding(engine: Engine) -> None:
    """As with the two reset routes: changing your own binding ends every session you hold, and on
    a site where you sign in only through the IdP it can lock the last administrator out. The
    CONTROL is the same call on another account, which succeeds."""
    service = await _service(engine)
    async with _client(engine, service) as c:
        tok = await _admin(c, service)
        root = await engine.store.get_user_by_username("root")
        assert root is not None
        for method in ("PUT", "DELETE"):
            _r, tok = await _reauth(c, tok, purpose=ACTION)
            r = await c.request(
                method,
                f"/users/{root.id}/federated-identity",
                json={"subject": "S-1-self"} if method == "PUT" else None,
                headers=_auth(tok),
            )
            assert r.status_code == 400, (method, r.text)
            assert "your own binding" in r.json()["detail"]
        target = await _ad_account(engine)
        _r, tok = await _reauth(c, tok, purpose=ACTION)
        ok = await c.put(
            f"/users/{target}/federated-identity", json={"subject": "S-1-a"}, headers=_auth(tok)
        )
        assert ok.status_code == 200, ok.text
