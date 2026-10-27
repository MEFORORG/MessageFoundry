# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #3025, closing step 3: a TOTP enrolment begin races a confirm as two live HTTP requests.

``tests/test_mfa.py`` already runs the interleaving through the service, and races two concurrent
service calls in one process. These tests take the race up one layer: two sessions on one account
send ``POST /me/mfa/confirm`` and ``POST /me/mfa/enroll`` concurrently through the real FastAPI app
(``create_app`` over ``httpx.ASGITransport``), each behind its own bound password step-up, so the
route dependencies, the step-up grants and the session rotation all run as they do for a JSON API
client such as the IDE or the harness. The web console's ``/ui/account/mfa/*`` routes reach the
same service calls through their own cookie, CSRF and step-up gates, which these tests do not run.

The invariant every test here checks: the factor that ends enabled is only ever a secret a
successful confirm verified, and a confirm that loses the race fails closed. It answers a refusal
whose body carries no recovery codes, enables nothing, and leaves no session of the account
MFA-satisfied.

The window a begin can land in opens when ``confirm_mfa_enrollment`` reads the staged secret's
cell, its first store read, and closes at the compare-and-set write the fix made conditional,
``store.enable_totp``. A begin that stages before that read makes the confirm's code wrong; one
that stages after the write commits finds TOTP enabled. Every hook here wraps ``enable_totp``, so
it acts at the window's tail, after the code check, the time-step consumption, the recovery-code
hashing, the session stamp and the session rotation. The forced test parks there before calling
the write. The unordered sweep sleeps there before the write, and for its last delay after it too.
The event-ordered test acts only once the write has committed, so its begin lands past the window.
A begin that stages anywhere inside the window meets the same write as one held at its tail.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncIterator, Coroutine
from pathlib import Path
from typing import Any

import httpx
import pytest

from messagefoundry.api.security import _STEP_UP_DETAIL
from messagefoundry.auth import Role, totp
from messagefoundry.auth.service import (
    STEP_UP_ACTION_MFA_CONFIRM,
    STEP_UP_ACTION_MFA_ENROLL,
    AuthService,
)
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.pipeline import Engine
from tests._bound_proof import prove
from tests._totp_clock import pin_totp_clock
from tests.test_api_auth import PW, _add, _auth, _client
from tests.test_api_auth import _login as _api_login
from tests.test_api_auth import _service as _api_service

#: The pinned TOTP instant both tests confirm at. Only the ``totp`` module's clock is pinned, so
#: session expiry and audit timestamps stay on the real clock.
_T0 = 1_000_000.0

#: One recovery code per confirm: each is a real argon2id hash, and nothing here needs ten.
_CODES = 1


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    # The shipped egress posture: nothing here sends anywhere.
    eng = await Engine.create(
        tmp_path / "mfa-race.db", poll_interval=0.02, egress_settings=EgressSettings()
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
    confirmer = await prove(c, confirmer, PW, STEP_UP_ACTION_MFA_ENROLL)
    r = await c.post("/me/mfa/enroll", headers=_auth(confirmer))
    assert r.status_code == 200, r.text
    staged = r.json()["secret"]
    assert isinstance(staged, str)
    confirmer = await prove(c, confirmer, PW, STEP_UP_ACTION_MFA_CONFIRM)
    beginner = await prove(c, beginner, PW, STEP_UP_ACTION_MFA_ENROLL)
    return confirmer, beginner, staged


async def _race(
    confirm: Coroutine[Any, Any, httpx.Response], begin: Coroutine[Any, Any, httpx.Response]
) -> tuple[httpx.Response, httpx.Response]:
    """Run both requests at once, the confirm's task first. A TaskGroup, not ``gather``, so a side
    that raises cancels the other rather than leaving it running past the test on the shared loop."""
    async with asyncio.TaskGroup() as tg:
        confirmed = tg.create_task(confirm)
        begun = tg.create_task(begin)
    return confirmed.result(), begun.result()


async def _assert_failed_closed(
    engine: Engine,
    service: AuthService,
    user_id: str,
    confirmed: httpx.Response,
    *,
    sessions_left: set[str],
) -> None:
    """A confirm that lost: a refusal status, and a body that is the refusal's detail alone, so it
    hands back no recovery codes and no token. Nothing is enabled, exactly ``sessions_left`` (token
    hashes) survive, and none of them is MFA-satisfied."""
    assert confirmed.status_code in (400, 401), confirmed.text
    body = confirmed.json()
    assert "recovery_codes" not in body, body
    assert set(body) == {"detail"}, body
    user = await engine.store.get_user(user_id)
    assert user is not None and user.totp_enabled is False
    assert await engine.store.get_recovery_code_hashes(user_id) == []
    sessions = await service.list_sessions(user_id)
    assert {s.token_hash for s in sessions} == sessions_left
    assert all(s.mfa_verified_at is None for s in sessions), (
        "a confirm that lost the race left a session MFA-satisfied"
    )


#: The begin's answer when it is refused for TOTP already being on: the service's ValueError.
_ALREADY_ENABLED = {"detail": "MFA is already enabled; disable it before re-enrolling"}


def _assert_begin_refused_once_enabled(begun: httpx.Response) -> None:
    """A begin that reached the account after the confirm's enable committed, from an MFA-pending
    session. It is refused in one of three ways, each pinned by its own headers or detail, and any
    other answer fails the test.

    ``require_reauth_only_action`` reads the factor-binding rule twice: once itself, then again
    inside ``_action_step_up_ok``. An enable that commits before the first read yields the
    MFA-required refusal, one that commits between the two reads yields the step-up refusal, and one
    that commits after both, but before the begin stages, leaves the service to refuse it as already
    enabled. The service's text has no constant to import, so it is spelled here."""
    if begun.status_code == 403 and begun.headers.get("X-MFA-Required") == "1":
        # The route's own read of the rule: the session must prove the factor the account now has.
        assert "X-Step-Up-Required" not in begun.headers, begun.headers
    elif begun.status_code == 403:
        # The second read, inside _action_step_up_ok: refused as a missing step-up for this action.
        assert begun.headers.get("X-Step-Up-Required") == "1", begun.headers
        assert begun.headers.get("X-Step-Up-Action") == STEP_UP_ACTION_MFA_ENROLL, begun.headers
        assert begun.json() == {"detail": _STEP_UP_DETAIL}, begun.text
    else:
        # Both reads ran before the commit, so the service found TOTP on, or its conditional stage
        # wrote nothing.
        assert begun.status_code == 400, begun.text
        assert begun.json() == _ALREADY_ENABLED, begun.text


async def test_a_begin_request_inside_the_confirm_requests_window_cannot_choose_the_enabled_secret(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: a begin request from a second session, landing after the confirm request checked
    its code and rotated its session, decides which secret the confirm enables (BACKLOG #3025).

    This is the window ``test_a_begin_inside_the_confirm_window_cannot_choose_the_enabled_secret``
    in ``tests/test_mfa.py`` opens: after the confirm's rotation, so the confirmer's session is
    already stamped MFA-satisfied and the compare-and-set must end it. A hook parks the confirm
    request at the top of ``enable_totp`` until the begin request has been answered, and the begin
    request is sent only once the confirm request is parked. **How we know the requests
    overlapped:** the timeline the hooks record must read confirm parked, begin answered, confirm
    resumed, confirm answered. So the whole begin request, route dependencies and all, ran start to
    finish while the confirm request was in flight inside its window.

    Each side releases the other however it ends: a confirm answered without parking lets the begin
    go, so the timeline assertion shows the confirm's reply rather than a timeout, and a failing
    begin lets the confirm resume. A ten-second bound on each wait is the backstop against a hang.

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
        real_enable = engine.store.enable_totp

        async def park_then_enable(*args: Any, **kwargs: Any) -> bool:
            if not parked.is_set():
                timeline.append("confirm parked")
                parked.set()
                await asyncio.wait_for(answered.wait(), timeout=10)
                timeline.append("confirm resumed")
            return await real_enable(*args, **kwargs)

        monkeypatch.setattr(engine.store, "enable_totp", park_then_enable)

        async def confirm() -> httpx.Response:
            try:
                r = await _confirm(c, confirmer, first, _T0)
                timeline.append("confirm answered")
                return r
            finally:
                parked.set()

        async def begin() -> httpx.Response:
            try:
                await asyncio.wait_for(parked.wait(), timeout=10)
                r = await c.post("/me/mfa/enroll", headers=_auth(beginner))
                timeline.append("begin answered")
                return r
            finally:
                answered.set()

        confirmed, begun = await _race(confirm(), begin())
        assert timeline == [
            "confirm parked",
            "begin answered",
            "confirm resumed",
            "confirm answered",
        ], (timeline, confirmed.status_code, confirmed.text)

        assert begun.status_code == 200, begun.text
        second = begun.json()["secret"]
        assert second != first

        assert confirmed.status_code == 401, (
            "the confirm enabled a secret it never verified",
            confirmed.status_code,
        )
        assert confirmed.json() == {"detail": "session ended; sign in again"}
        # The confirmer's rotated session is ended, not handed back; only the beginner's remains.
        await _assert_failed_closed(
            engine, service, user_id, confirmed, sessions_left={hash_token(beginner)}
        )
        assert await engine.store.get_totp_secret(user_id) == totp.new_enrolment(second)
        rows = await engine.store.list_audit(actor="op", action="auth.mfa_enroll_refused", limit=10)
        assert len(rows) == 1
        assert json.loads(str(rows[0]["detail"]))["reason"] == "secret_replaced"

        # Control: the replacing secret confirms through its own ceremony, at a later step, since
        # the refused confirm spent the step it matched. What ends enabled is that secret. The
        # hook has parked once and passes every later call through.
        beginner = await prove(c, beginner, PW, STEP_UP_ACTION_MFA_CONFIRM)
        t1 = _T0 + totp.DEFAULT_PERIOD
        pin_totp_clock(monkeypatch, t1)
        r = await _confirm(c, beginner, second, t1)
        assert r.status_code == 200, r.text
        assert len(r.json()["recovery_codes"]) == _CODES
        assert await engine.store.get_totp_secret(user_id) == totp.new_enrolment(second)
        user = await engine.store.get_user(user_id)
        assert user is not None and user.totp_enabled is True


#: The unordered test's hook sleeps, in seconds: before the enable's write, and after it.
_SLEEP_BEFORE_WRITE = 0.3
_SLEEP_AFTER_WRITE = 0.5
#: The begin's send delay aimed past the write and before the confirm's answer: the middle of the
#: after-write sleep, counted from the request's start. A loaded runner can push it back inside the
#: window, so the event-ordered test below is what reaches the after-write outcome every run.
_BEGIN_DELAY_PAST_THE_WRITE = _SLEEP_BEFORE_WRITE + _SLEEP_AFTER_WRITE / 2


async def test_a_begin_request_sent_once_the_enable_committed_is_refused_and_the_confirm_wins(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The after-write outcome, ordered by events rather than a delay, so it runs on every runner.

    A hook lets the confirm's ``enable_totp`` write commit, then holds the confirm request there
    until the begin request has been answered, and the begin request is sent only once the write
    has committed. **How we know the requests overlapped:** the timeline must read confirm
    enabled, begin answered, confirm resumed, confirm answered, so the whole begin ran while the
    confirm request was in flight, past its write.

    Both of the begin's gate reads then see TOTP on, so the route refuses it with the MFA-required
    403, and the confirm wins with its own secret. This does not go red without the fix: the begin
    lands after the window. It is the check that the confirm-wins branch of the sweep below is
    exercised at all."""
    service = await _service(engine)
    user_id = await _add(service, "op", Role.OPERATOR)
    pin_totp_clock(monkeypatch, _T0)
    async with _client(engine, service) as c:
        confirmer, beginner, first = await _two_sessions_one_staged(c)

        timeline: list[str] = []
        enabled = asyncio.Event()
        answered = asyncio.Event()
        real_enable = engine.store.enable_totp

        async def enable_then_hold(*args: Any, **kwargs: Any) -> bool:
            try:
                written = await real_enable(*args, **kwargs)
            finally:
                enabled.set()
            timeline.append("confirm enabled")
            await asyncio.wait_for(answered.wait(), timeout=10)
            timeline.append("confirm resumed")
            return written

        monkeypatch.setattr(engine.store, "enable_totp", enable_then_hold)

        async def confirm() -> httpx.Response:
            try:
                r = await _confirm(c, confirmer, first, _T0)
                timeline.append("confirm answered")
                return r
            finally:
                enabled.set()

        async def begin() -> httpx.Response:
            try:
                await asyncio.wait_for(enabled.wait(), timeout=10)
                r = await c.post("/me/mfa/enroll", headers=_auth(beginner))
                timeline.append("begin answered")
                return r
            finally:
                answered.set()

        confirmed, begun = await _race(confirm(), begin())
        assert timeline == [
            "confirm enabled",
            "begin answered",
            "confirm resumed",
            "confirm answered",
        ], (timeline, confirmed.status_code, confirmed.text)

        assert confirmed.status_code == 200, confirmed.text
        assert len(confirmed.json()["recovery_codes"]) == _CODES
        assert begun.status_code == 403, begun.text
        assert begun.headers.get("X-MFA-Required") == "1", begun.headers
        assert "X-Step-Up-Required" not in begun.headers, begun.headers
        user = await engine.store.get_user(user_id)
        assert user is not None and user.totp_enabled is True
        assert await engine.store.get_totp_secret(user_id) == totp.new_enrolment(first)


@pytest.mark.parametrize("delay", [0.0, 0.01, 0.05, 0.2, _BEGIN_DELAY_PAST_THE_WRITE])
async def test_a_live_begin_request_racing_a_confirm_request_never_enables_an_unverified_secret(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, delay: float
) -> None:
    """BACKLOG #3025, closing step 3: two live HTTP requests race, with nothing ordering them.

    The confirm request and a begin request from a second session are sent concurrently; the begin
    is sent ``delay`` seconds after the confirm request starts. A hook on ``enable_totp`` sleeps
    before the write, widening the window between the code check and the write. For the one delay
    aimed past the write it sleeps after the write too, widening the time between the write and the
    confirm's answer. It chooses nothing about what lands where, and the test asserts it ran on
    exactly the outcomes that reach the write, so the widening cannot silently stop.

    Each delay aims at one outcome, but the run asserts the invariant rather than the outcome, so a
    slow runner that moves a begin into a neighbouring outcome is still checked. **Nothing asserts
    that each outcome is reached**, so on a slow runner a delay can drift into its neighbour's
    outcome and the sweep still passes. Measured over six runs on one Windows workstation
    (2026-10-26): at 0.0 the begin either staged before the confirm read the row, so the code was
    wrong (400), or landed inside the window (401), and both happened; at 0.01, 0.05 and 0.2 it
    landed inside the window and the compare-and-set refused (401); at the last delay it landed
    after the write, so the confirm won (200) and the route's gate refused the begin (403). The
    delays count from the request's start, so on a loaded runner the last one can land inside the
    window instead; the event-ordered test above reaches the confirm-wins outcome on every run.
    Only a run that lands inside the window goes red without the fix. The forced test above is the
    one that always does.

    **How we know the requests overlapped:** the confirm's task is created first and is sent
    before the begin by construction; the test reads the monotonic clock as the begin is sent and
    as the confirm is answered, and asserts the begin was sent first, so both were in flight
    through the app at once."""
    service = await _service(engine)
    user_id = await _add(service, "op", Role.OPERATOR)
    pin_totp_clock(monkeypatch, _T0)
    sleep_after_write = _SLEEP_AFTER_WRITE if delay > _SLEEP_BEFORE_WRITE else 0.0
    async with _client(engine, service) as c:
        confirmer, beginner, first = await _two_sessions_one_staged(c)

        real_enable = engine.store.enable_totp
        enables: list[bool] = []

        async def widened_enable(*args: Any, **kwargs: Any) -> bool:
            await asyncio.sleep(_SLEEP_BEFORE_WRITE)
            written = await real_enable(*args, **kwargs)
            enables.append(written)
            await asyncio.sleep(sleep_after_write)
            return written

        monkeypatch.setattr(engine.store, "enable_totp", widened_enable)
        clock: dict[str, float] = {}

        async def confirm() -> httpx.Response:
            r = await _confirm(c, confirmer, first, _T0)
            clock["confirm answered"] = time.monotonic()
            return r

        async def begin() -> httpx.Response:
            await asyncio.sleep(delay)
            clock["begin sent"] = time.monotonic()
            return await c.post("/me/mfa/enroll", headers=_auth(beginner))

        confirmed, begun = await _race(confirm(), begin())
        assert clock["begin sent"] < clock["confirm answered"], clock

        user = await engine.store.get_user(user_id)
        assert user is not None
        if user.totp_enabled:
            assert await engine.store.get_totp_secret(user_id) == totp.new_enrolment(first), (
                "an enabled factor is not the secret the confirm verified"
            )
        if confirmed.status_code == 200:
            assert enables == [True]
            assert user.totp_enabled and len(confirmed.json()["recovery_codes"]) == _CODES
            # A begin that staged before the confirm's read makes the code wrong, and one that staged
            # inside the window makes the write refuse, so on a 200 the begin reached the account
            # after the write committed. It is refused with the MFA-required 403, the step-up 403 or
            # the service's 400; the helper says which interleaving yields which.
            _assert_begin_refused_once_enabled(begun)
        elif confirmed.status_code == 401:
            # The begin staged inside the window and the compare-and-set refused, ending the
            # confirmer's rotated session.
            assert enables == [False]
            assert begun.status_code == 200, begun.text
            assert await engine.store.get_totp_secret(user_id) == totp.new_enrolment(
                begun.json()["secret"]
            )
            await _assert_failed_closed(
                engine, service, user_id, confirmed, sessions_left={hash_token(beginner)}
            )
        else:
            # The begin staged before the confirm read the row, so the code was checked against
            # the begin's secret and failed; no enable ran and no session was rotated.
            assert confirmed.status_code == 400, confirmed.text
            # The route's wrong-code answer; it has no constant to import.
            assert confirmed.json() == {"detail": "invalid code"}, confirmed.text
            assert enables == []
            assert begun.status_code == 200, begun.text
            assert await engine.store.get_totp_secret(user_id) == totp.new_enrolment(
                begun.json()["secret"]
            )
            await _assert_failed_closed(
                engine,
                service,
                user_id,
                confirmed,
                sessions_left={hash_token(confirmer), hash_token(beginner)},
            )
