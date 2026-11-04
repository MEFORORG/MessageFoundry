# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``DELETE /sessions`` and ``messagefoundry admin-revoke-sessions`` end every session (BACKLOG #2614).

The route takes ``users:manage``, the per-account revoke's permission, behind a single-use proof
bound to ``revoke_all_sessions``: a login-seeded window is not enough, nor is a grant minted for
another action. It keeps the caller's own session. The CLI command is the same act from the host,
for when the API is not trusted, on admin-unlock's gate. Both write an ``auth.session_revoked``
row with scope and count.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from messagefoundry.__main__ import main
from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.service import (
    STEP_UP_ACTION_REVOKE_ALL_SESSIONS,
    STEP_UP_ACTION_SESSION_TERMINATE,
    AuthService,
)
from messagefoundry.auth.tokens import hash_token, mint_token
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store.store import MessageStore, RevokeResult
from tests._admin_account import create_local_user_chosen
from tests._phi_gate_provisions import setenv_at_rest_opt_out
from tests.test_api_auth import PW, _clear_must_change
from tests.test_b2614_restore_record import _revoked
from tests.test_b2614_revoke_all import _sqlite_raw


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(
        tmp_path / "b2614_route.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


async def _service(engine: Engine) -> AuthService:
    service = AuthService(
        engine.store,
        AuthSettings(
            login_rate_limit_enabled=False, admin_write_min_interval_seconds=0, require_mfa=False
        ),
    )
    await service.initialize()
    return service


def _client(engine: Engine, service: AuthService) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=create_app(engine, auth=service), client=("127.0.0.1", 123))
    return httpx.AsyncClient(transport=transport, base_url="http://t")


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _local(service: AuthService, username: str, role: Role) -> None:
    user_id = await create_local_user_chosen(
        service,
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=[role.value],
        actor="test",
    )
    await _clear_must_change(service, user_id)


async def _login(c: httpx.AsyncClient, username: str) -> str:
    r = await c.post(
        "/auth/login", json={"username": username, "password": PW, "provider": "local"}
    )
    assert r.status_code == 200, r.text
    return str(r.json()["token"])


async def _reauth(c: httpx.AsyncClient, token: str, purpose: str) -> str:
    r = await c.post("/me/reauth", json={"password": PW, "purpose": purpose}, headers=_auth(token))
    assert r.status_code == 200, r.text
    return str(r.json()["token"])


async def _alive(c: httpx.AsyncClient, token: str) -> bool:
    return (await c.get("/auth/me", headers=_auth(token))).status_code == 200


async def test_the_route_ends_every_session_but_the_callers(engine: Engine) -> None:
    service = await _service(engine)
    await _local(service, "root", Role.ADMINISTRATOR)
    await _local(service, "ops", Role.OPERATOR)
    async with _client(engine, service) as c:
        root = await _login(c, "root")
        root_elsewhere = await _login(c, "root")
        ops = await _login(c, "ops")

        # Only the login window: refused, with the action named so the console can mint it.
        r = await c.delete("/sessions", headers=_auth(root))
        assert r.status_code == 403, r.text
        assert r.headers.get("X-Step-Up-Action") == STEP_UP_ACTION_REVOKE_ALL_SESSIONS
        # A grant minted for ending one's own other sessions is not this grant.
        root = await _reauth(c, root, STEP_UP_ACTION_SESSION_TERMINATE)
        r = await c.delete("/sessions", headers=_auth(root))
        assert r.status_code == 403, r.text
        assert await _alive(c, ops) and await _alive(c, root_elsewhere)  # nothing ended yet

        root = await _reauth(c, root, STEP_UP_ACTION_REVOKE_ALL_SESSIONS)
        r = await c.delete("/sessions", headers=_auth(root))
        assert r.status_code == 200, r.text
        assert "this session was kept" in r.json()["detail"]
        assert not await _alive(c, ops)
        assert not await _alive(c, root_elsewhere)
        assert await _alive(c, root)

        # The grant was single-use: a second call needs a new proof.
        r = await c.delete("/sessions", headers=_auth(root))
        assert r.status_code == 403, r.text

    rows = await engine.store.list_audit(action="auth.session_revoked", limit=10)
    details = [json.loads(row["detail"]) for row in rows]
    assert {"scope": "all_but_caller", "count": 2} in details
    assert any(row["actor"] == "root" for row in rows)


async def test_the_route_refuses_a_caller_without_users_manage(engine: Engine) -> None:
    service = await _service(engine)
    await _local(service, "ops", Role.OPERATOR)
    await _local(service, "root", Role.ADMINISTRATOR)
    async with _client(engine, service) as c:
        root = await _login(c, "root")
        ops = await _login(c, "ops")
        ops = await _reauth(c, ops, STEP_UP_ACTION_REVOKE_ALL_SESSIONS)
        r = await c.delete("/sessions", headers=_auth(ops))
        assert r.status_code == 403, r.text
        assert "X-Step-Up-Action" not in r.headers  # the permission refusal, not the proof's
        assert await _alive(c, root)


async def test_a_kept_session_that_fails_its_seal_is_counted_with_the_rest(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A kept session whose seal fails makes the store write nothing, so the service ends every
    session, the caller's own included. The count in the reply and the audit row must include that
    session: ended first by the seal-failure handler, the sweep found it gone and both were one
    short. The seal failure is injected at the store's keep-one revoke, the call that raises it."""
    from messagefoundry.store.row_seal import SESSION_KIND, RowSealError

    service = await _service(engine)
    await _local(service, "root", Role.ADMINISTRATOR)
    await _local(service, "ops", Role.OPERATOR)
    async with _client(engine, service) as c:
        root = await _login(c, "root")
        await _login(c, "root")
        await _login(c, "ops")

    store = engine.store
    real = store.revoke_all_sessions

    async def _refuse_the_keep(
        *, except_token_hash: str | None = None, now: float | None = None
    ) -> RevokeResult:
        if except_token_hash is not None:
            raise RowSealError(SESSION_KIND)
        return await real(now=now)

    monkeypatch.setattr(store, "revoke_all_sessions", _refuse_the_keep)
    revoked, kept = await service.revoke_every_session(
        actor="root", keep_token_hash=hash_token(root)
    )
    assert (revoked, kept) == (3, False)
    rows = await store.list_audit(action="auth.session_revoked", limit=10)
    assert [json.loads(row["detail"]) for row in rows] == [{"scope": "all", "count": 3}]
    row = await store.get_session(hash_token(root))
    assert row is not None and row.revoked_at is not None


async def _miss(store: MessageStore, db: Path, token_hash: str) -> str:
    """Leave the session ``token_hash`` names where an earlier per-account sweep's miss leaves
    it, and return its account. It has already passed the gate, as a request that straddles that
    sweep's commit has."""
    snapshot = await store.get_session(token_hash)
    assert snapshot is not None and snapshot.revoked_at is None
    await store.revoke_user_sessions(snapshot.user_id)
    await _sqlite_raw(db)(
        "UPDATE sessions SET revoked_at=NULL, seal=? WHERE token_hash=?",
        (snapshot.seal, token_hash),
    )
    return snapshot.user_id


async def test_a_caller_session_the_revoke_declines_is_ended_and_said_to_be(
    engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Follow-up to BACKLOG #4975: the every-account revoke does not stamp a kept session an
    earlier sweep missed, and ends it in its own transaction. So the reply's "this session was
    ended too" is true, the count in the reply and the audit row includes it, and presenting the
    session afterwards is refused as ended, with no seal-failure alert. The control is the first
    test here, where the same call keeps it."""
    service = await _service(engine)
    await _local(service, "root", Role.ADMINISTRATOR)
    await _local(service, "ops", Role.OPERATOR)
    store = engine.store
    assert isinstance(store, MessageStore)
    db = tmp_path / "b2614_route.db"
    real = store.revoke_all_sessions
    live: list[int] = []

    async def _missed_first(
        *, except_token_hash: str | None = None, now: float | None = None
    ) -> RevokeResult:
        if except_token_hash is not None:
            await _miss(store, db, except_token_hash)
            conn = sqlite3.connect(db)
            try:
                live.append(
                    conn.execute(
                        "SELECT COUNT(*) FROM sessions WHERE revoked_at IS NULL"
                    ).fetchone()[0]
                )
            finally:
                conn.close()
        return await real(except_token_hash=except_token_hash, now=now)

    async with _client(engine, service) as c:
        root = await _login(c, "root")
        ops = await _login(c, "ops")
        root = await _reauth(c, root, STEP_UP_ACTION_REVOKE_ALL_SESSIONS)
        monkeypatch.setattr(store, "revoke_all_sessions", _missed_first)
        r = await c.delete("/sessions", headers=_auth(root))
        assert r.status_code == 200, r.text
        assert live and live[0] >= 2  # the caller's row and ops', both unrevoked at the revoke
        assert r.json()["detail"] == f"revoked {live[0]} session(s); this session was ended too"
        # Read before anything presents the token: the gate would end a live one it refuses.
        assert await _revoked(store, root)  # ended by the revoke itself
        assert not await _alive(c, root)
        assert not await _alive(c, ops)
    rows = await store.list_audit(action="auth.session_revoked", limit=1)
    assert json.loads(rows[0]["detail"]) == {"scope": "all", "count": live[0]}
    assert not await store.list_audit(action="integrity.authority_seal_failed", limit=1)


async def test_signing_out_elsewhere_from_a_declined_session_counts_the_others_only(
    engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Follow-up to BACKLOG #4975: signing out everywhere else from a session an earlier sweep
    missed ends that session too, in the revoke's own transaction. The reply still counts the
    other sessions only, so it stays true, and the audit row says the caller's own ended. Presenting
    that session afterwards is refused as ended, with no seal-failure alert."""
    service = await _service(engine)
    await _local(service, "root", Role.ADMINISTRATOR)
    store = engine.store
    assert isinstance(store, MessageStore)
    db = tmp_path / "b2614_route.db"
    real = store.revoke_user_sessions

    async def _missed_first(
        user_id: str, *, except_token_hash: str | None = None, now: float | None = None
    ) -> RevokeResult:
        if except_token_hash is not None:
            await _miss(store, db, except_token_hash)
            # One other session, minted after the sweep, so it is current: the revoke ends it.
            await store.create_session(
                token_hash=hash_token(mint_token()), user_id=user_id, expires_at=4_000_000_000.0
            )
        return await real(user_id, except_token_hash=except_token_hash, now=now)

    async with _client(engine, service) as c:
        root = await _login(c, "root")
        root = await _reauth(c, root, STEP_UP_ACTION_SESSION_TERMINATE)
        monkeypatch.setattr(store, "revoke_user_sessions", _missed_first)
        r = await c.delete("/me/sessions", headers=_auth(root))
        assert r.status_code == 200, r.text
        assert r.json()["detail"] == "signed out 1 other session(s)"
        assert await _revoked(store, root)  # ended by the revoke, before the gate saw it
        assert not await _alive(c, root)
    rows = await store.list_audit(action="auth.session_revoked", limit=1)
    assert json.loads(rows[0]["detail"]) == {"scope": "self_all", "count": 1}
    assert not await store.list_audit(action="integrity.authority_seal_failed", limit=1)


async def _seed(db: Path) -> list[str]:
    store = await MessageStore.open(db)
    try:
        tokens = []
        for user_id in ("cli-a", "cli-b"):
            await store.create_user(
                user_id=user_id,
                username=user_id,
                auth_provider="local",
                display_name=None,
                email=None,
                password_hash="h",
                now=0.0,
                password_generated=False,
                audits=(),
            )
            token = mint_token()
            await store.create_session(
                token_hash=hash_token(token),
                user_id=user_id,
                expires_at=4_000_000_000.0,
                client="192.0.2.10",
                auth_mechanism="password",
            )
            tokens.append(token)
        return tokens
    finally:
        await store.close()


async def _state(db: Path, tokens: list[str]) -> tuple[list[bool], list[dict[str, object]]]:
    store = await MessageStore.open(db)
    try:
        revoked = []
        for token in tokens:
            row = await store.get_session(hash_token(token))
            revoked.append(row is not None and row.revoked_at is not None)
        audits = await store.list_audit(action="auth.session_revoked", limit=10)
        return revoked, [dict(a) for a in audits]
    finally:
        await store.close()


def test_the_cli_command_ends_every_session_and_audits_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    setenv_at_rest_opt_out(monkeypatch)  # a keyless store, as the admin-unlock tests use
    db = tmp_path / "cli.db"
    tokens = asyncio.run(_seed(db))
    assert asyncio.run(_state(db, tokens))[0] == [False, False]  # control

    assert main(["admin-revoke-sessions", "--db", str(db), "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == {"ok": True, "revoked": 2}
    revoked, audits = asyncio.run(_state(db, tokens))
    assert revoked == [True, True]
    assert len(audits) == 1
    assert json.loads(str(audits[0]["detail"])) == {"scope": "all", "count": 2}
    assert str(audits[0]["actor"]).startswith("cli:")


def test_the_cli_command_refuses_a_missing_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    missing = tmp_path / "nope.db"
    assert main(["admin-revoke-sessions", "--db", str(missing), "--json"]) == 2
    assert "refusing to create one" in json.loads(capsys.readouterr().out)["error"]
    assert not missing.exists()
