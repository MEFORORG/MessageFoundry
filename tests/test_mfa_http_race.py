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
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from _totp_clock import pin_totp_clock

from messagefoundry.auth import Role, totp
from messagefoundry.auth.service import AuthService
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.pipeline import Engine
from tests._bound_proof import prove
from tests.test_api_auth import PW, _add, _auth, _client
from tests.test_api_auth import _login as _api_login
from tests.test_api_auth import _service as _api_service

#: The pinned TOTP instant both tests confirm at. Only the ``totp`` module's clock is pinned, so
#: session expiry and audit timestamps stay on the real clock.
_T0 = 1_000_000.0

#: One recovery code per confirm: each is a real argon2id hash, and nothing here needs ten.
_CODES = 1

#: The ``_elevated`` ceremony name the confirm rotates its session under, which is the step right
#: before the compare-and-set enable. ``/me/reauth`` also elevates, under another name.
_CONFIRM_CEREMONY = "mfa_enroll_confirm"


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
            mfa_recovery_code_count=_CODES,
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


async def _confirm(c: httpx.AsyncClient, token: str, secret: str, now: float) -> httpx.Response:
    return await c.post(
        "/me/mfa/confirm", json={"code": totp.totp(secret, now=now)}, headers=_auth(token)
    )


async def _two_sessions_one_staged(c: httpx.AsyncClient) -> tuple[str, str, str]:
    """Sign ``op`` in twice. The first session stages a secret and holds a confirm grant; the
    second holds an enroll grant. Returns ``(confirmer, beginner, staged_secret)``."""
    confirmer = await _login(c)
    beginner = await _login(c)
    confirmer = await prove(c, confirmer, PW, "mfa_enroll")
    r = await c.post("/me/mfa/enroll", headers=_auth(confirmer))
    assert r.status_code == 200, r.text
    staged = r.json()["secret"]
    assert isinstance(staged, str)
    confirmer = await prove(c, confirmer, PW, "mfa_confirm")
    beginner = await prove(c, beginner, PW, "mfa_enroll")
    return confirmer, beginner, staged


async def _assert_failed_closed(
    engine: Engine, service: AuthService, user_id: str, confirmed: httpx.Response
) -> None:
    """A confirm that lost: no codes handed back, nothing enabled, no session MFA-satisfied."""
    assert "recovery_codes" not in confirmed.json()
    user = await engine.store.get_user(user_id)
    assert user is not None and user.totp_enabled is False
    assert await engine.store.get_recovery_code_hashes(user_id) == []
    sessions = await service.list_sessions(user_id)
    assert all(s.mfa_verified_at is None for s in sessions), (
        "a confirm that lost the race left a session MFA-satisfied"
    )


async def test_a_begin_request_inside_the_confirm_requests_window_is_refused(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: a begin request from a second session, landing after the confirm request checked
    its code and rotated its session, decides which secret the confirm enables (BACKLOG #3025).

    The window is the one ``test_a_begin_inside_the_confirm_window_cannot_choose_the_enabled_secret``
    in ``tests/test_mfa.py`` opens, at the same point: right after the confirm's ``_elevated``
    rotation, so the confirmer's session is already stamped MFA-satisfied and the compare-and-set
    must end it. A hook parks the confirm request there until the begin request has been answered,
    and the begin request is sent only once the confirm request is parked. **How we know the
    requests overlapped:** the timeline the hooks record must read confirm parked, begin answered,
    confirm resumed, confirm answered. So the whole begin request, route dependencies and all, ran
    start to finish while the confirm request was in flight inside its window. A ten-second bound
    on each wait turns a request that never arrives into a ``TimeoutError`` rather than a hang.

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
        real_elevated = service._elevated

        async def elevated_then_park(*args: Any, **kwargs: Any) -> Any:
            out = await real_elevated(*args, **kwargs)
            if kwargs.get("ceremony") == _CONFIRM_CEREMONY and not parked.is_set():
                timeline.append("confirm parked")
                parked.set()
                await asyncio.wait_for(answered.wait(), timeout=10)
                timeline.append("confirm resumed")
            return out

        monkeypatch.setattr(service, "_elevated", elevated_then_park)

        async def confirm() -> httpx.Response:
            r = await _confirm(c, confirmer, first, _T0)
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
        await _assert_failed_closed(engine, service, user_id, confirmed)
        assert await engine.store.get_totp_secret(user_id) == totp.new_enrolment(second)
        # The confirmer's rotated session is ended; only the beginner's remains.
        assert {s.token_hash for s in await service.list_sessions(user_id)} == {
            hash_token(beginner)
        }
        assert (await c.get("/auth/me", headers=_auth(confirmer))).status_code == 401
        rows = await engine.store.list_audit(actor="op", action="auth.mfa_enroll_refused", limit=10)
        assert len(rows) == 1
        assert json.loads(str(rows[0]["detail"]))["reason"] == "secret_replaced"

        # Control: the replacing secret confirms through its own ceremony, at a later step, since
        # the refused confirm spent the step it matched. What ends enabled is that secret. The
        # hook has parked once and passes every later call through.
        beginner = await prove(c, beginner, PW, "mfa_confirm")
        t1 = _T0 + totp.DEFAULT_PERIOD
        pin_totp_clock(monkeypatch, t1)
        r = await _confirm(c, beginner, second, t1)
        assert r.status_code == 200, r.text
        assert len(r.json()["recovery_codes"]) == _CODES
        assert await engine.store.get_totp_secret(user_id) == totp.new_enrolment(second)
        user = await engine.store.get_user(user_id)
        assert user is not None and user.totp_enabled is True


@pytest.mark.parametrize("delay", [0.0, 0.01, 0.05, 0.2])
async def test_a_live_begin_request_racing_a_confirm_request_never_enables_an_unverified_secret(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, delay: float
) -> None:
    """BACKLOG #3025, closing step 3: two live HTTP requests race, with nothing ordering them.

    The confirm request and a begin request from a second session are sent concurrently; the begin
    is sent ``delay`` seconds after the confirm. The confirm's rotation is followed by a fixed
    sleep, which widens the window between the code check and the enable without choosing what
    lands in it; the test asserts the sleep ran once, so the widening cannot silently stop. Where
    the begin lands is the scheduler's, so each run checks the invariant rather than one outcome:
    an enabled factor is the secret the confirm verified, a confirm answered 200 left it enabled,
    and any other answer fails closed.

    **How we know the requests overlapped:** the test reads the monotonic clock as each request is
    sent and answered, and asserts each was sent before the other was answered, so both were in
    flight through the app at once."""
    service = await _service(engine)
    user_id = await _add(service, "op", Role.OPERATOR)
    pin_totp_clock(monkeypatch, _T0)
    async with _client(engine, service) as c:
        confirmer, beginner, first = await _two_sessions_one_staged(c)

        real_elevated = service._elevated
        widened: list[str] = []

        async def elevated_then_wait(*args: Any, **kwargs: Any) -> Any:
            out = await real_elevated(*args, **kwargs)
            if kwargs.get("ceremony") == _CONFIRM_CEREMONY:
                widened.append(_CONFIRM_CEREMONY)
                await asyncio.sleep(0.3)
            return out

        monkeypatch.setattr(service, "_elevated", elevated_then_wait)
        clock: dict[str, float] = {}

        async def confirm() -> httpx.Response:
            clock["confirm sent"] = time.monotonic()
            r = await _confirm(c, confirmer, first, _T0)
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
            assert widened == [_CONFIRM_CEREMONY]
            assert user.totp_enabled and len(confirmed.json()["recovery_codes"]) == _CODES
            # A begin that staged before the confirm's read makes the code wrong, and one that staged
            # inside the window makes the enable refuse, so a 200 leaves the begin only refusing.
            assert begun.status_code == 400, begun.text
        else:
            assert confirmed.status_code in (400, 401), confirmed.text
            # A 400 is a begin that staged before the code check, so no rotation ran to widen.
            assert widened == ([_CONFIRM_CEREMONY] if confirmed.status_code == 401 else [])
            await _assert_failed_closed(engine, service, user_id, confirmed)
