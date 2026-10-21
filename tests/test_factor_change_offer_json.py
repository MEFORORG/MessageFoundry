# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The JSON twins carry the offer to end the caller's other sessions after a factor change
(BACKLOG #3393, the JSON half of #1147; ASVS 7.4.3).

``POST /me/mfa/confirm`` and ``DELETE /me/mfa`` answer ``other_sessions``: how many sessions
``DELETE /me/sessions`` would end. The count is ``AuthService.count_other_sessions``, the store's
count with the revoke's own predicate, so it is pinned here against what the revoke then ends,
including a session the inventory hides. ``EngineClient`` surfaces the field on both calls."""

from __future__ import annotations

import time
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from _totp_clock import fresh_totp

from messagefoundry.apiclient import EngineClient, MfaConfirmed
from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.auth.tokens import hash_token, mint_token
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.pipeline import Engine
from tests.test_api_auth import _add, _auth, _client, _reauth
from tests.test_api_auth import _login as _api_login
from tests.test_api_auth import _service as _api_service


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(
        tmp_path / "offer.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


async def _service(engine: Engine) -> AuthService:
    # MFA not required, so a disable of the only factor is allowed; the timing floors off, so the
    # ceremony runs at machine speed.
    return await _api_service(
        engine,
        AuthSettings(
            admin_write_min_interval_seconds=0,
            mfa_verify_min_elapsed_seconds=0,
            login_rate_limit_enabled=False,
            require_mfa=False,
        ),
    )


async def _login(c: httpx.AsyncClient, username: str) -> str:
    r = await _api_login(c, username)
    assert r.status_code == 200, r.text
    token = r.json()["token"]
    assert isinstance(token, str)
    return token


async def _proof(c: httpx.AsyncClient, token: str, purpose: str) -> str:
    r, fresh = await _reauth(c, token, purpose=purpose)
    assert r.status_code == 200, r.text
    return fresh


async def _enroll(c: httpx.AsyncClient, token: str) -> tuple[httpx.Response, str]:
    """Enrol and confirm TOTP over the JSON API; the confirm's response and the token after it."""
    token = await _proof(c, token, "mfa_enroll")
    r = await c.post("/me/mfa/enroll", headers=_auth(token))
    assert r.status_code == 200, r.text
    secret = r.json()["secret"]
    token = await _proof(c, token, "mfa_confirm")
    r = await c.post("/me/mfa/confirm", json={"code": fresh_totp(secret)}, headers=_auth(token))
    assert r.status_code == 200, r.text
    return r, r.json()["token"]


async def test_the_count_is_what_the_revoke_ends_not_what_the_inventory_lists(
    engine: Engine,
) -> None:
    """RED when ``count_other_sessions`` counts the inventory (``list_sessions``) rather than the
    revoke's predicate: the expired session nobody revoked is hidden from the one and ended by the
    other. The current session is excepted only when its hash names a row."""
    service = await _service(engine)
    user_id = await _add(service, "op", Role.OPERATOR)
    now = time.time()
    current, live, lapsed = mint_token(), mint_token(), mint_token()
    for token, expires_at in ((current, now + 3600), (live, now + 3600), (lapsed, now - 60)):
        await service.store.create_session(
            token_hash=hash_token(token),
            user_id=user_id,
            expires_at=expires_at,
            auth_mechanism="password",
        )
    listed = {s.token_hash for s in await service.list_sessions(user_id)}
    assert listed == {hash_token(current), hash_token(live)}  # control: the inventory hides one
    assert await service.count_other_sessions(user_id, hash_token(current)) == 2
    # A hash that names none of the account's rows excepts nothing.
    assert await service.count_other_sessions(user_id, hash_token(mint_token())) == 3
    identity = await service.identity_for_token(current)
    assert identity is not None
    ended = await service.revoke_other_sessions(identity, hash_token(current), actor="op")
    assert ended == 2
    assert await service.count_other_sessions(user_id, hash_token(current)) == 0


async def test_confirm_and_disable_carry_the_offer(engine: Engine) -> None:
    """RED when either JSON reply drops ``other_sessions``, counts the caller's own session (the
    confirm re-keys it, so a count against the wrong token reads one more), or offers on a disable
    of TOTP that was never on."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        other = await _login(c, "op")
        token = await _login(c, "op")
        # A disable with TOTP never on succeeds and changes no factor: no offer.
        token = await _proof(c, token, "mfa_disable")
        r = await c.delete("/me/mfa", headers=_auth(token))
        assert r.status_code == 200, r.text
        assert r.json() == {"detail": "MFA disabled", "other_sessions": 0}

        r, token = await _enroll(c, token)
        body = r.json()
        assert len(body["recovery_codes"]) == 10
        assert body["other_sessions"] == 1  # the other sign-in, not this rotated session

        token = await _proof(c, token, "mfa_disable")
        r = await c.delete("/me/mfa", headers=_auth(token))
        assert r.status_code == 200, r.text
        assert r.json() == {"detail": "MFA disabled", "other_sessions": 1}
        # The offer ended nothing: the other session still answers.
        assert (await c.get("/auth/me", headers=_auth(other))).status_code == 200


async def test_the_confirm_offers_only_what_the_revoke_then_ends(engine: Engine) -> None:
    """RED when the confirm counts before its own session-cap run: that run ends the lapsed row
    planted here (``max_sessions_per_user`` defaults on), so a count read first offers 2 while the
    revoke that follows ends 1."""
    service = await _service(engine)
    user_id = await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _login(c, "op")
        token = await _login(c, "op")
        await service.store.create_session(
            token_hash=hash_token(mint_token()),
            user_id=user_id,
            expires_at=time.time() - 60,
            auth_mechanism="password",
        )
        r, token = await _enroll(c, token)
        assert r.json()["other_sessions"] == 1
        token = await _proof(c, token, "session_terminate")
        r = await c.delete("/me/sessions", headers=_auth(token))
        assert r.status_code == 200, r.text
        assert r.json() == {"detail": "signed out 1 other session(s)"}


async def test_a_store_fault_while_counting_costs_the_offer_and_nothing_else(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The count is read after the change committed, so a fault there answers 0 rather than raise:
    a raise on the confirm would lose the recovery codes in its reply. RED when it propagates."""
    service = await _service(engine)

    async def _fault(*_args: object, **_kwargs: object) -> int:
        raise RuntimeError("synthetic store fault")

    monkeypatch.setattr(service.store, "count_user_sessions", _fault)
    assert await service.count_other_sessions("u", hash_token(mint_token())) == 0


def _mock_client(replies: dict[str, object]) -> EngineClient:
    client = EngineClient("http://127.0.0.1:8765")
    client._http.close()
    client._http = httpx.Client(
        base_url="http://127.0.0.1:8765",
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json=replies[r.url.path])),
    )
    return client


def test_the_client_surfaces_the_offer_on_both_calls() -> None:
    """RED when ``EngineClient.confirm_mfa`` or ``disable_mfa`` drops ``other_sessions``."""
    client = _mock_client(
        {
            "/me/mfa/confirm": {"recovery_codes": ["c1"], "token": "r" * 43, "other_sessions": 2},
            "/me/mfa": {"detail": "MFA disabled", "other_sessions": 3},
        }
    )
    try:
        assert client.confirm_mfa("123456") == MfaConfirmed(
            recovery_codes=("c1",), other_sessions=2
        )
        assert client.disable_mfa().other_sessions == 3
    finally:
        client.close()
