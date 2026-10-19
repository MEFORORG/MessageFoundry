# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #3260 on the JSON plane: each self-target refusal writes its own audit row.

Before this, the step-up gate's ``auth.permission_granted`` was the attempt's only row, so the
refusal itself went unrecorded. Each admin route that refuses the caller's own account now
writes ``auth.self_target_refused``, naming the actor and the caller's stored id. The console
plane, and the case-spelling bypass of vault BACKLOG #3259, are pinned in
``packaging/messagefoundry-webconsole/tests/test_ui_self_target_guard.py``.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.auth import Role
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.pipeline import Engine
from tests.test_api_auth import _DEFAULT_PEER, _add, _auth, _client, _login, _reauth, _service


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    """Local rather than imported: a fixture resolves by name in the module that requests it."""
    eng = await Engine.create(
        tmp_path / "self_target.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


_UNBOUND = {"expected_issuer": None, "expected_subject": None}

#: (op, method, path after /users/{id}, step-up purpose or None for the window, body, refusal text).
ROUTES: list[tuple[str, str, str, str | None, Any, str]] = [
    ("password_reset", "POST", "/reset-password", "admin_reset_password", None, "change-password"),
    ("mfa_reset", "POST", "/reset-mfa", "admin_reset_mfa", None, "self-service MFA settings"),
    (
        "federated_bind",
        "PUT",
        "/federated-identity",
        "admin_federated_identity",
        {"subject": "S-1-me", **_UNBOUND},
        "your own binding",
    ),
    (
        "federated_unbind",
        "DELETE",
        "/federated-identity",
        "admin_federated_identity",
        _UNBOUND,
        "your own binding",
    ),
    ("disable", "PATCH", "", "admin_user_update", {"disabled": True}, "cannot disable your own"),
    ("delete", "DELETE", "", None, None, "cannot delete your own"),
    # BACKLOG #1149 (ASVS 7.5.2): each of these revokes the target's sessions, so aimed at yourself
    # it would be a mass terminate on the login window alone.
    ("revoke_sessions", "DELETE", "/sessions", None, None, "self-service session controls"),
    # Keeps Administrator, so the last-admin guard passes and only the self-guard stops the write;
    # the session backstop below then discriminates.
    ("set_roles", "PUT", "/roles", None, {"roles": ["administrator"]}, "your own roles"),
    ("channel_scope", "PUT", "/channel-scope", None, {"channels": ["*"]}, "your own channel scope"),
]


@pytest.mark.parametrize(("op", "method", "suffix", "purpose", "body", "words"), ROUTES)
async def test_each_self_target_refusal_writes_its_own_audit_row(
    engine: Engine,
    op: str,
    method: str,
    suffix: str,
    purpose: str | None,
    body: Any,
    words: str,
) -> None:
    service = await _service(
        engine,
        AuthSettings(
            admin_write_min_interval_seconds=0,
            require_mfa=False,
            oidc_issuer="https://idp.example",
        ),
    )
    await _add(service, "root", Role.ADMINISTRATOR)
    me = await engine.store.get_user_by_username("root")
    assert me is not None
    async with _client(engine, service) as c:
        tok = (await _login(c, "root")).json()["token"]
        r, tok = await _reauth(c, tok, purpose=purpose)
        assert r.status_code == 200, r.text
        roles_before = await engine.store.get_user_role_ids(me.id)
        r = await c.request(method, f"/users/{me.id}{suffix}", json=body, headers=_auth(tok))
        # A backstop: a refusal that let the write through would have revoked this session.
        still = await c.get("/auth/me", headers=_auth(tok))
    assert r.status_code == 400, r.text
    assert still.status_code == 200, "the refused request ended the caller's session"
    assert await engine.store.get_user_role_ids(me.id) == roles_before
    assert words in r.json()["detail"]
    rows = await engine.store.list_audit(action="auth.self_target_refused", limit=10)
    assert len(rows) == 1, "one refusal, one audit row"
    assert rows[0]["actor"] == "root"
    assert rows[0]["client"] == _DEFAULT_PEER[0], "the refusal row dropped the caller's address"
    # The route and the caller's stored id: no credential, no body, no message content.
    assert json.loads(str(rows[0]["detail"])) == {"op": op, "user_id": me.id}


@pytest.mark.parametrize(
    ("method", "suffix", "body"),
    [
        ("DELETE", "", None),
        # BACKLOG #1149: the three routes it closed to the caller still act on another account, on
        # the same login window.
        ("DELETE", "/sessions", None),
        ("PUT", "/roles", {"roles": ["operator"]}),
        ("PUT", "/channel-scope", {"channels": ["*"]}),
    ],
)
async def test_another_account_writes_no_refusal_row(
    engine: Engine, method: str, suffix: str, body: Any
) -> None:
    """The control: the same route on another account is not a refusal, so it writes no such row."""
    service = await _service(engine)
    await _add(service, "root", Role.ADMINISTRATOR)
    await _add(service, "viewer1", Role.VIEWER)
    other = await engine.store.get_user_by_username("viewer1")
    assert other is not None
    async with _client(engine, service) as c:
        tok = (await _login(c, "root")).json()["token"]
        _r, tok = await _reauth(c, tok)
        r = await c.request(method, f"/users/{other.id}{suffix}", json=body, headers=_auth(tok))
    assert r.status_code == 200, r.text
    assert await engine.store.list_audit(action="auth.self_target_refused", limit=10) == []


# --- vault BACKLOG #3260, limb 2: a self-service revoke that ends nothing --------------------------

#: A well-formed session id that names no session.
_UNKNOWN_SESSION = "0" * 64


async def test_a_missed_session_revoke_writes_one_row_and_the_same_answer(engine: Engine) -> None:
    """RED when: ``DELETE /me/sessions/{id}`` answers its 404 with no audit row of its own (vault
    BACKLOG #3260, limb 2; owner ruling 2026-10-16), or the answer or the row tells an unknown id
    from another account's.

    One row per miss, with the id cut to 12 characters, and nothing else in its detail."""
    service = await _service(engine)
    await _add(service, "a", Role.VIEWER)
    await _add(service, "b", Role.VIEWER)
    async with _client(engine, service) as c:
        ta = (await _login(c, "a")).json()["token"]
        tb = (await _login(c, "b")).json()["token"]
        foreign = (await c.get("/me/sessions", headers=_auth(tb))).json()["sessions"][0]["id"]
        answers = []
        # The grant is single-use, so each attempt takes its own re-proof, as a caller's would.
        for target in (_UNKNOWN_SESSION, foreign):
            _r, ta = await _reauth(c, ta, purpose="session_terminate")
            assert _r.status_code == 200
            r = await c.delete(f"/me/sessions/{target}", headers=_auth(ta))
            answers.append((r.status_code, r.json()))
        still = await c.get("/auth/me", headers=_auth(tb))
    assert answers == [(404, {"detail": "no such session"})] * 2, answers
    assert still.status_code == 200, "a missed revoke ended another account's session"
    rows = await engine.store.list_audit(action="auth.session_revoke_missed", limit=10)
    assert len(rows) == 2, "one miss, one row"
    # Newest first: the foreign id's row, then the unknown id's.
    assert [json.loads(str(r["detail"])) for r in rows] == [
        {"session": foreign[:12]},
        {"session": _UNKNOWN_SESSION[:12]},
    ]
    for row in rows:
        assert row["actor"] == "a"
        assert row["client"] == _DEFAULT_PEER[0], "the miss row dropped the caller's address"
    assert await engine.store.list_audit(action="auth.session_revoked", limit=10) == []


async def test_a_revoke_of_your_own_session_writes_no_miss_row(engine: Engine) -> None:
    """The control: a revoke that ends a session writes ``auth.session_revoked``, not a miss."""
    service = await _service(engine)
    await _add(service, "u", Role.VIEWER)
    async with _client(engine, service) as c:
        t1 = (await _login(c, "u")).json()["token"]
        t2 = (await _login(c, "u")).json()["token"]
        _r, t2 = await _reauth(c, t2, purpose="session_terminate")
        sessions = (await c.get("/me/sessions", headers=_auth(t2))).json()["sessions"]
        other = next(s for s in sessions if not s["current"])
        r = await c.delete(f"/me/sessions/{other['id']}", headers=_auth(t2))
        gone = await c.get("/auth/me", headers=_auth(t1))
    assert r.status_code == 200, r.text
    assert gone.status_code == 401
    assert await engine.store.list_audit(action="auth.session_revoke_missed", limit=10) == []
    revoked = await engine.store.list_audit(action="auth.session_revoked", limit=10)
    assert len(revoked) == 1 and revoked[0]["client"] == _DEFAULT_PEER[0]
