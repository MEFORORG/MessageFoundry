# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #3025, closing step 3: a TOTP enrolment begin races a confirm as two live HTTP requests.

``tests/test_mfa.py`` already runs the interleaving through the service, and races two concurrent
service calls in one process. These tests take the race up one layer: two sessions on one account
send ``POST /me/mfa/confirm`` and ``POST /me/mfa/enroll`` concurrently through the real FastAPI app
(``create_app`` over ``httpx.ASGITransport``), each behind its own bound password step-up, so the
route dependencies, the step-up grants and the session rotation all run as they do for a browser.

The invariant both tests check: the factor that ends enabled is only ever a secret a successful
confirm verified, and a confirm that loses the race fails closed. It hands back no recovery codes,
enables nothing, and leaves no session of the account MFA-satisfied.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
from _totp_clock import pin_totp_clock

from messagefoundry.auth import Role, totp
from messagefoundry.auth.passwords import hash_password
from messagefoundry.auth.service import AuthService
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.pipeline import Engine
from tests.test_api_auth import _add, _auth, _client, _reauth
from tests.test_api_auth import _login as _api_login
from tests.test_api_auth import _service as _api_service

#: The pinned TOTP instant both tests confirm at. Only the ``totp`` module's clock is pinned, so
#: session expiry and audit timestamps stay on the real clock.
_T0 = 1_000_000.0


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(
        tmp_path / "mfa-race.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


async def _service(engine: Engine) -> AuthService:
    # MFA required, the shipped default, so each sign-in mints an MFA-pending session and only a
    # confirm that wins can satisfy one: that is what makes "no session left MFA-satisfied" a real
    # check. The login-to-MFA floor and the rate limits off, so the ceremony runs at machine speed
    # and the race is between the two requests, not against a timer.
    return await _api_service(
        engine,
        AuthSettings(
            admin_write_min_interval_seconds=0,
            mfa_verify_min_elapsed_seconds=0,
            login_rate_limit_enabled=False,
            require_mfa=True,
        ),
    )


async def _login(c: httpx.AsyncClient) -> str:
    r = await _api_login(c, "op")
    assert r.status_code == 200, r.text
    token = r.json()["token"]
    assert isinstance(token, str)
    return token


async def _proof(c: httpx.AsyncClient, token: str, purpose: str) -> str:
    r, fresh = await _reauth(c, token, purpose=purpose)
    assert r.status_code == 200, r.text
    return fresh


async def _two_sessions_one_staged(c: httpx.AsyncClient) -> tuple[str, str, str]:
    """Sign ``op`` in twice. The first session stages a secret and holds a confirm grant; the
    second holds an enroll grant. Returns ``(confirmer, beginner, staged_secret)``."""
    confirmer = await _login(c)
    beginner = await _login(c)
    confirmer = await _proof(c, confirmer, "mfa_enroll")
    r = await c.post("/me/mfa/enroll", headers=_auth(confirmer))
    assert r.status_code == 200, r.text
    staged = r.json()["secret"]
    assert isinstance(staged, str)
    confirmer = await _proof(c, confirmer, "mfa_confirm")
    beginner = await _proof(c, beginner, "mfa_enroll")
    return confirmer, beginner, staged


async def _no_session_left_elevated(service: AuthService, user_id: str) -> None:
    sessions = await service.list_sessions(user_id)
    assert all(s.mfa_verified_at is None for s in sessions), (
        "a confirm that lost the race left a session MFA-satisfied"
    )


async def test_a_begin_request_inside_the_confirm_requests_hashing_window_is_refused(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: a begin request from a second session, landing while the confirm request hashes
    its recovery codes, decides which secret the confirm enables (BACKLOG #3025).

    The window is the one ``test_a_begin_inside_the_confirm_window_cannot_choose_the_enabled_secret``
    in ``tests/test_mfa.py`` names, between the code check and the enable. Here it is held open by
    a hook on the first recovery-code hash: the confirm request parks there until the begin
    request has been answered, and the begin request is sent only once the confirm request is
    parked. **How we know the requests overlapped:** the timeline the hooks record must read
    confirm parked, begin staged, begin answered, confirm resumed, confirm answered. So the whole
    begin request, route dependencies and all, ran start to finish while the confirm request was
    in flight inside its window. A ten-second bound on the park turns a begin that never lands into
    a failed timeline assertion rather than a hang.

    Without the fix the confirm enables the begin's secret, which it never verified, and answers
    200 with recovery codes. With it the confirm answers 401, enables nothing and ends its own
    session; the begin's secret stays staged and confirms through its own ceremony."""
    service = await _service(engine)
    user_id = await _add(service, "op", Role.OPERATOR)
    pin_totp_clock(monkeypatch, _T0)
    async with _client(engine, service) as c:
        confirmer, beginner, first = await _two_sessions_one_staged(c)

        timeline: list[str] = []
        parked = asyncio.Event()
        answered = asyncio.Event()

        real_stage = engine.store.set_totp_secret

        async def stage(*args: Any, **kwargs: Any) -> Any:
            out = await real_stage(*args, **kwargs)
            timeline.append("begin staged")
            return out

        real_argon2 = service._argon2
        held = False

        async def argon2(fn: Callable[..., Any], *args: Any) -> Any:
            nonlocal held
            if fn is hash_password and not held:
                held = True
                timeline.append("confirm parked")
                parked.set()
                try:
                    await asyncio.wait_for(answered.wait(), timeout=10)
                except TimeoutError:
                    timeline.append("confirm timed out")
                timeline.append("confirm resumed")
            return await real_argon2(fn, *args)

        monkeypatch.setattr(engine.store, "set_totp_secret", stage)
        monkeypatch.setattr(service, "_argon2", argon2)

        async def confirm() -> httpx.Response:
            r = await c.post(
                "/me/mfa/confirm",
                json={"code": totp.totp(first, now=_T0)},
                headers=_auth(confirmer),
            )
            timeline.append("confirm answered")
            return r

        async def begin() -> httpx.Response:
            await asyncio.wait_for(parked.wait(), timeout=10)
            r = await c.post("/me/mfa/enroll", headers=_auth(beginner))
            timeline.append("begin answered")
            answered.set()
            return r

        confirmed, begun = await asyncio.gather(confirm(), begin())
        assert timeline == [
            "confirm parked",
            "begin staged",
            "begin answered",
            "confirm resumed",
            "confirm answered",
        ], timeline

        assert begun.status_code == 200, begun.text
        second = begun.json()["secret"]
        assert second != first

        assert confirmed.status_code == 401, (
            "the confirm enabled a secret it never verified",
            confirmed.status_code,
        )
        assert confirmed.json() == {"detail": "session ended; sign in again"}
        user = await engine.store.get_user(user_id)
        assert user is not None and user.totp_enabled is False
        assert await engine.store.get_totp_secret(user_id) == totp.new_enrolment(second)
        assert await engine.store.get_recovery_code_hashes(user_id) == []
        # The confirmer's rotated session is ended; only the beginner's remains, and it is not
        # MFA-satisfied.
        assert {s.token_hash for s in await service.list_sessions(user_id)} == {
            hash_token(beginner)
        }
        await _no_session_left_elevated(service, user_id)
        assert (await c.get("/auth/me", headers=_auth(confirmer))).status_code == 401
        rows = await engine.store.list_audit(actor="op", action="auth.mfa_enroll_refused", limit=10)
        assert len(rows) == 1
        assert json.loads(str(rows[0]["detail"]))["reason"] == "secret_replaced"

        # Control: the replacing secret confirms through its own ceremony, at a later step, since
        # the refused confirm spent the step it matched. What ends enabled is that secret.
        monkeypatch.setattr(service, "_argon2", real_argon2)
        beginner = await _proof(c, beginner, "mfa_confirm")
        t1 = _T0 + totp.DEFAULT_PERIOD
        pin_totp_clock(monkeypatch, t1)
        r = await c.post(
            "/me/mfa/confirm", json={"code": totp.totp(second, now=t1)}, headers=_auth(beginner)
        )
        assert r.status_code == 200, r.text
        assert len(r.json()["recovery_codes"]) == 10
        assert await engine.store.get_totp_secret(user_id) == totp.new_enrolment(second)
        user = await engine.store.get_user(user_id)
        assert user is not None and user.totp_enabled is True


@pytest.mark.parametrize("delay", [0.0, 0.01, 0.05, 0.2])
async def test_a_live_begin_request_racing_a_confirm_request_never_enables_an_unverified_secret(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, delay: float
) -> None:
    """BACKLOG #3025, closing step 3: two live HTTP requests race, with nothing ordering them.

    The confirm request and a begin request from a second session are sent concurrently; the begin
    is sent ``delay`` seconds after the confirm. Each recovery-code hash is slowed by a fixed sleep,
    which widens the window between the code check and the enable without choosing what lands in
    it. Where the begin lands is the scheduler's, so each run checks the invariant rather than one
    outcome: an enabled factor is the secret the confirm verified, a confirm answered 200 left it
    enabled, and any other answer carries no recovery codes, enables nothing and leaves no session
    MFA-satisfied.

    **How we know the requests overlapped:** the test reads the monotonic clock as each request is
    sent and answered, and asserts each was sent before the other was answered, so both were in
    flight through the app at once."""
    service = await _service(engine)
    user_id = await _add(service, "op", Role.OPERATOR)
    pin_totp_clock(monkeypatch, _T0)
    async with _client(engine, service) as c:
        confirmer, beginner, first = await _two_sessions_one_staged(c)

        real_argon2 = service._argon2

        async def slow_argon2(fn: Callable[..., Any], *args: Any) -> Any:
            if fn is hash_password:
                await asyncio.sleep(0.03)
            return await real_argon2(fn, *args)

        monkeypatch.setattr(service, "_argon2", slow_argon2)
        clock: dict[str, float] = {}

        async def confirm() -> httpx.Response:
            clock["confirm sent"] = time.monotonic()
            r = await c.post(
                "/me/mfa/confirm",
                json={"code": totp.totp(first, now=_T0)},
                headers=_auth(confirmer),
            )
            clock["confirm answered"] = time.monotonic()
            return r

        async def begin() -> httpx.Response:
            await asyncio.sleep(delay)
            clock["begin sent"] = time.monotonic()
            r = await c.post("/me/mfa/enroll", headers=_auth(beginner))
            clock["begin answered"] = time.monotonic()
            return r

        confirmed, begun = await asyncio.gather(confirm(), begin())
        assert clock["begin sent"] < clock["confirm answered"], clock
        assert clock["confirm sent"] < clock["begin answered"], clock

        user = await engine.store.get_user(user_id)
        assert user is not None
        if user.totp_enabled:
            assert await engine.store.get_totp_secret(user_id) == totp.new_enrolment(first), (
                "an enabled factor is not the secret the confirm verified"
            )
        if confirmed.status_code == 200:
            assert user.totp_enabled and len(confirmed.json()["recovery_codes"]) == 10
            # A begin that staged before the confirm's read makes the code wrong, and one that staged
            # inside the window makes the enable refuse, so a 200 leaves the begin only refusing.
            assert begun.status_code == 400, begun.text
        else:
            assert confirmed.status_code in (400, 401), confirmed.text
            assert "recovery_codes" not in confirmed.json()
            assert not user.totp_enabled
            assert await engine.store.get_recovery_code_hashes(user_id) == []
            await _no_session_left_elevated(service, user_id)
