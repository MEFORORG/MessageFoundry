# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ASVS 6.3.3 on the cookie plane — the /ui half of the MFA access gate.

The JSON plane refuses a pending session with 403 + ``X-MFA-Required``; a browser cannot act on that,
so ``require_ui`` 303s it to ``/ui/mfa`` instead and confines it there until the second factor is
satisfied. The risk this file exists to pin is not the refusal — it is the LOOP: a confinement page
that is itself gated, or that a fresh account can never answer, bricks the console.

Each test names the mutation that must turn it RED.
"""

from __future__ import annotations

import asyncio
from uuid import uuid4

import httpx
import pytest
from _ui_clients import SAME_ORIGIN, create_local_user_chosen

from messagefoundry.api import create_app
from messagefoundry.auth import Role, totp
from messagefoundry.auth.identity import AuthProvider
from messagefoundry.auth.passwords import hash_password
from messagefoundry.auth.service import AuthService, Elevation
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine

PW = "a-strong-test-passphrase"  # >=15, no app/vendor terms — satisfies the ASVS policy (WP-3)


class _PinnedClock:
    """Minimal ``time`` stand-in exposing only ``time()`` at a fixed instant.

    A local twin of ``tests/_totp_clock._PinnedClock`` — this package has its own test root and does
    not import the engine suite's helpers. ``totp`` reads the wall clock solely as ``time.time()``, so
    swapping the module reference pins the TOTP step deterministically while leaving every other clock
    real.
    """

    def __init__(self, instant: float) -> None:
        self._instant = instant

    def time(self) -> float:
        return self._instant


def _pin_totp_clock(monkeypatch: pytest.MonkeyPatch, instant: float) -> None:
    """Pin the ``totp`` module clock so an enroll ceremony and a later /ui/mfa gate verify land in
    distinct, provably-adjacent steps — needed now that enrollment consumes the activating step
    (BACKLOG #1021), so a gate code from the SAME step would be refused as a replay."""
    monkeypatch.setattr(totp, "time", _PinnedClock(instant))


async def _service(engine: Engine, **kw: object) -> AuthService:
    service = AuthService(
        engine.store,
        AuthSettings(mfa_verify_min_elapsed_seconds=0, login_rate_limit_enabled=False, **kw),  # type: ignore[arg-type]
    )
    await service.initialize()
    return service


#: The first Administrator's name and temporary password. Synthetic; the password clears the default
#: policy. Not "admin", so it cannot collide with a test that names an account that on purpose.
_ADMIN_USERNAME = "test-admin"
_ADMIN_PW = "a-strong-operator-passphrase"


async def _must_change_admin(service: AuthService) -> str:
    """Write a must-change local Administrator with no factor, then run ``initialize()``. Returns its
    username.

    A local twin of ``tests/_admin_account.create_admin``, for the same reason ``_PinnedClock`` is
    one: this package has its own test root. It stood in for the first-run bootstrap account before
    ADR 0183 Amendment A retired it (BACKLOG #1136), and it keeps that credential state: admin-issued,
    must change, no factor. Wave 2 dropped its guard against a pre-existing ``admin`` row, as it did
    in the twin: nothing creates that row now.
    """
    user_id = uuid4().hex
    await service.store.create_user(
        user_id=user_id,
        username=_ADMIN_USERNAME,
        auth_provider=AuthProvider.LOCAL.value,
        password_hash=await asyncio.to_thread(hash_password, _ADMIN_PW),
        must_change_password=True,
        password_generated=False,
    )
    await service.initialize()  # seeds the roles the assignment below refers to
    await service.store.set_user_roles(user_id, [Role.ADMINISTRATOR.value], assigned_by="test")
    return _ADMIN_USERNAME


def _client(engine: Engine, service: AuthService) -> httpx.AsyncClient:
    # A browser connected directly to http://t: the request Host is its origin (BACKLOG #2219).
    app = create_app(engine, auth=service, serve_ui=True, webauthn_rp_from_request=True)
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")


async def _add(service: AuthService, username: str, *roles: Role) -> str:
    user_id = await create_local_user_chosen(
        service,
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=[r.value for r in roles],
        actor="test",
    )
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id,
        password_hash=user.password_hash,
        must_change_password=False,
        password_generated=False,
    )
    return user_id


async def _login(c: httpx.AsyncClient, username: str = "op") -> httpx.Response:
    return await c.post("/ui/login", data={"username": username, "password": PW})


async def _enroll_totp(service: AuthService, username: str = "op") -> str:
    """Activate TOTP out-of-band and return the secret.

    Uses a THROWAWAY service-level session for the ceremony: ``confirm_mfa_enrollment`` marks the
    session it ran on as MFA-satisfied, so enrolling through the browser client would leave that
    client already verified and the gate untested. The caller logs in afterwards, and that fresh
    session is enrolled-but-unverified — the state these tests are about.
    """
    user = await service.store.get_user_by_username(username)
    assert user is not None
    identity = await service.identity_for_user_id(user.id)
    assert identity is not None
    outcome = await service.login(username, PW)
    assert outcome.ok and outcome.token is not None
    enrollment = await service.begin_mfa_enrollment(identity)
    # `.ok`, not the result object: confirm_mfa_enrollment returns an Elevation (ASVS 7.2.4), and a
    # frozen dataclass is ALWAYS truthy — a bare assert on it would pass on a failed enrolment.
    assert (
        await service.confirm_mfa_enrollment(
            identity, totp.totp(enrollment.secret), token=outcome.token
        )
    ).ok
    return enrollment.secret


# --- confinement ------------------------------------------------------------


async def test_a_pending_session_is_confined_to_the_mfa_page(engine: Engine) -> None:
    """RED when: the mfa_satisfied check is removed from require_ui.

    A gated page, not a step-up one — a step-up page would bounce to /ui/reauth anyway and prove
    nothing about the ACCESS gate.
    """
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        assert (await _login(c)).status_code == 303
        r = await c.get("/ui/messages")
        assert r.status_code == 303
        assert r.headers["location"] == "/ui/mfa"


async def test_the_confinement_redirect_does_not_claim_the_session_ended(
    engine: Engine,
) -> None:
    """RED when: _mfa_redirect starts reusing _login_redirect.

    Clear-Site-Data marks a TERMINATED session (14.3.1). A pending session is alive and mid-sign-in;
    emitting it here would wipe the cache on an ordinary step and mislabel the state.
    """
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _login(c)
        r = await c.get("/ui/messages")
        assert r.headers.get("Clear-Site-Data") is None


async def test_the_login_post_lands_a_pending_session_on_the_gate(engine: Engine) -> None:
    """RED when: the mfa_required branch is dropped from the /ui/login redirect target."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        r = await _login(c)
        assert r.status_code == 303 and r.headers["location"] == "/ui/mfa"


# --- the page must not brick the account ------------------------------------


async def test_an_unenrolled_account_is_sent_to_enroll_not_to_an_empty_form(
    engine: Engine,
) -> None:
    """RED when: the enroll-first bounce is dropped from GET /ui/mfa.

    THE brick. A fresh account is MFA-required with NOTHING enrolled, so a code form would ask for a
    credential that cannot exist and the operator would be stuck on a page they cannot answer.
    """
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _login(c)
        r = await c.get("/ui/mfa")
        assert r.status_code == 303
        assert r.headers["location"] == "/ui/account?m=enroll_first"


async def test_the_account_page_and_password_page_stay_reachable_while_pending(
    engine: Engine,
) -> None:
    """RED when: allow_mfa_pending is dropped from /ui/account or /ui/account/password.

    /ui/account is the target of the enroll-first bounce and renders the enroll button; the password
    page is the other half of the deadlock carve-out. Gating either closes the only way out.
    """
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _login(c)
        assert (await c.get("/ui/account")).status_code == 200
        # Reachable, and under require_mfa with no TOTP it sends the holder to enrol first (ADR 0197
        # Amendment A, AC-A3) rather than to the factor page or back to itself.
        r = await c.get("/ui/account/password")
        assert r.status_code == 303 and r.headers["location"] == _ENROL_FIRST


async def test_the_watchdog_heartbeat_survives_confinement(engine: Engine) -> None:
    """RED when: allow_mfa_pending is dropped from /ui/session-status.

    The confinement page carries the same watchdog as every other page. If its heartbeat is gated,
    the page 303s its own poll and fights itself.
    """
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _login(c)
        assert (await c.get("/ui/session-status")).status_code == 200


# --- the page itself --------------------------------------------------------


async def test_the_page_asks_for_a_code_once_a_factor_exists(engine: Engine) -> None:
    """RED when: GET /ui/mfa stops rendering the code field for an enrolled session."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _enroll_totp(service)
        await _login(c)
        r = await c.get("/ui/mfa")
        assert r.status_code == 200
        assert 'name="code"' in r.text
        # It completes SIGN-IN, not a sensitive action: the password was proven seconds ago.
        assert 'name="password"' not in r.text


async def test_a_satisfied_session_is_bounced_off_the_page(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: the mfa_satisfied early-return is removed from GET /ui/mfa.

    Without it a verified operator who navigates back to /ui/mfa is asked to re-verify forever.
    """
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        # Enroll consumes the activating TOTP step (BACKLOG #1021), so the gate code must sit in a
        # strictly later step: pin the enroll ceremony to t0 and the gate verify to t0+period.
        t0 = 1_000_000.0
        _pin_totp_clock(monkeypatch, t0)
        secret = await _enroll_totp(service)
        await _login(c)
        t1 = t0 + totp.DEFAULT_PERIOD
        _pin_totp_clock(monkeypatch, t1)
        gate = await c.post("/ui/mfa", data={"code": totp.totp(secret, now=t1)})
        assert gate.status_code == 303
        r = await c.get("/ui/mfa")
        assert r.status_code == 303 and r.headers["location"] == "/ui"


async def test_a_valid_code_clears_the_gate(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: POST /ui/mfa stops calling verify_mfa (or stops redirecting on success)."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        # Enroll consumes the activating step (BACKLOG #1021); the gate code lives in a later step.
        t0 = 1_000_000.0
        _pin_totp_clock(monkeypatch, t0)
        secret = await _enroll_totp(service)
        await _login(c)
        assert (await c.get("/ui/messages")).status_code == 303  # confined
        t1 = t0 + totp.DEFAULT_PERIOD
        _pin_totp_clock(monkeypatch, t1)
        r = await c.post("/ui/mfa", data={"code": totp.totp(secret, now=t1)})
        assert r.status_code == 303 and r.headers["location"] == "/ui"
        assert (await c.get("/ui/messages")).status_code == 200  # released


async def test_a_rejected_code_is_never_echoed_back_into_the_form(engine: Engine) -> None:
    """RED when: the re-render starts passing the submitted code back as a field value.

    A TOTP or recovery code is a bearer credential, and a failed-attempt re-render is exactly where
    one leaks — into the HTML, and from there into any cache or screenshot.
    """
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _enroll_totp(service)
        await _login(c)
        r = await c.post("/ui/mfa", data={"code": "000000"})
        assert r.status_code == 400
        assert "000000" not in r.text


def test_a_passkey_only_account_gets_a_completing_assertion_not_a_dead_end() -> None:
    """RED when: pages.mfa_gate stops emitting data-mf-webauthn-done.

    A passkey-only account renders NO code field and NO submit button, so the assertion is the whole
    ceremony. app.js keys on this attribute to navigate; without it the reauth-page branch runs
    instead — "enter your password to continue" beside a page that has no password field — and the
    operator is stranded after a SUCCESSFUL verification. Rendered directly rather than driven
    through a ceremony because the dead end is a property of the markup, not of the crypto.
    """
    from messagefoundry_webconsole import pages

    html = str(pages.mfa_gate(totp_enrolled=False, webauthn_options='{"challenge":"x"}'))
    assert "data-mf-webauthn-done" in html
    assert 'name="code"' not in html
    assert 'name="password"' not in html

    # With TOTP enrolled the code field returns; the hook stays, so either factor completes.
    both = str(pages.mfa_gate(totp_enrolled=True, webauthn_options='{"challenge":"x"}'))
    assert 'name="code"' in both and "data-mf-webauthn-done" in both


async def test_must_change_outranks_the_second_factor_on_the_gate_page(
    engine: Engine,
) -> None:
    """RED when: GET /ui/mfa parks a must-change account with no factor on a page it cannot answer.

    A first Administrator on a temporary password is BOTH must-change and pending, with nothing to
    prove. Under require_mfa it goes to enrol first (ADR 0197 Amendment A), from the sign-in and from
    the gate page alike -- never to the code prompt. The cookie-plane twin of the JSON order.
    """
    service = AuthService(
        engine.store, AuthSettings(mfa_verify_min_elapsed_seconds=0, login_rate_limit_enabled=False)
    )
    admin = await _must_change_admin(service)
    async with _client(engine, service) as c:
        r = await c.post("/ui/login", data={"username": admin, "password": _ADMIN_PW})
        assert r.status_code == 303 and r.headers["location"] == _ENROL_FIRST
        r = await c.get("/ui/mfa")
        assert r.status_code == 303 and r.headers["location"] == _ENROL_FIRST


# --- ASVS 7.2.4: the cookie plane of session rotation on re-authentication ---


async def test_a_correct_code_then_a_wrong_password_leaves_a_working_cookie(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: POST /ui/reauth stops re-setting the cookie on its ERROR exits.

    ``/ui/reauth`` can rotate TWICE in one request — the code leg, then the password leg. A correct
    code followed by a wrong password rotates ONCE and then renders an error page. If that response
    does not carry the new cookie the browser is stranded on a dead one mid-ceremony, and the next
    click reads as an unexplained sign-out rather than a wrong password.

    Also RED when: the handler stops rebinding its local ``token`` between the two calls — the
    password leg would then run against the retired hash and fail closed on a CORRECT password.
    """
    service = await _service(engine, require_mfa=True)
    await _add(service, "op", Role.OPERATOR)
    t0 = 1_000_000.0
    _pin_totp_clock(monkeypatch, t0)
    secret = await _enroll_totp(service, "op")

    async with _client(engine, service) as c:
        assert (await _login(c)).status_code == 303
        before = c.cookies.get("mf_session")
        assert before is not None

        # A strictly later step: enrollment consumed its own (BACKLOG #1021).
        t1 = t0 + totp.DEFAULT_PERIOD
        _pin_totp_clock(monkeypatch, t1)
        r = await c.post(
            "/ui/reauth",
            data={
                "next": "/ui/account/mfa/disable",
                "code": totp.totp(secret, now=t1),
                "password": "definitely-not-the-password",
            },
            headers={"origin": "http://t"},
        )

        assert r.status_code == 200
        assert "Incorrect password." in r.text, (
            "the password leg did not run, or ran on a dead hash"
        )
        after = c.cookies.get("mf_session")
        assert after is not None and after != before, "the rotated cookie was not handed back"

        # The whole point: the browser can still act. A dead cookie would 303 to /ui/login.
        assert await service.identity_for_token(after) is not None
        assert await service.mfa_satisfied(after) is True, "the code leg's stamp did not survive"
        assert await service.identity_for_token(before) is None, (
            "the old cookie still authenticates"
        )


# --- ending sessions from a pending session (ASVS 6.3.3 / 7.5.2, BACKLOG #1951) -------------

_REVOKE_OTHERS = "/ui/account/sessions/revoke-others"


@pytest.mark.parametrize("action_step_up", (True, False), ids=("enforced", "opted-out"))
async def test_a_pending_session_cannot_end_an_enrolled_accounts_sessions(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, action_step_up: bool
) -> None:
    """The /ui twin of the engine's refusal. RED when: ``session_terminate`` leaves the set that
    ``factor_binding_is_blocked`` refuses, as seen through ``_ui_action_step_up_ok``.

    ``/ui/reauth`` already demands the code before it mints, so the console's own ceremony never
    hands a pending session this grant. The reachable chain crosses planes: the password holder
    replays the cookie token as a Bearer to the MFA-exempt ``POST /me/reauth``. So this stamps the
    step-up state directly and asks one question: does the route open on it? ``enforced`` plants the
    single-use grant; ``opted-out`` stamps the window, which is that branch's whole gate.
    """
    from messagefoundry.auth.service import STEP_UP_ACTION_SESSION_TERMINATE

    service = await _service(engine, require_action_step_up=action_step_up)
    await _add(service, "op", Role.OPERATOR)
    _pin_totp_clock(monkeypatch, 1_000_000.0)  # no step boundary between making and checking a code
    await _enroll_totp(service)
    other = await service.login("op", PW)  # the real user's other device
    assert other.ok and other.token is not None

    async with _client(engine, service) as c:
        assert (await _login(c)).status_code == 303  # the attacker knows the password only
        tok = c.cookies.get("mf_session")
        assert tok is not None
        assert await service.mfa_satisfied(tok) is False

        for path in (f"/ui/account/sessions/{hash_token(other.token)}/revoke", _REVOKE_OTHERS):
            if action_step_up:
                service._grant_action_step_up(hash_token(tok), STEP_UP_ACTION_SESSION_TERMINATE)
            else:
                await service.store.mark_session_reauthed(hash_token(tok))
                # The positive control: without it a refusal for a stale window would pass.
                assert await service.has_recent_step_up(tok) is True
            r = await c.post(path, headers=SAME_ORIGIN)
            # A SUCCESSFUL revoke also answers 303, so the location carries the verdict.
            assert r.status_code == 303
            assert r.headers["location"] == f"/ui/reauth?next={path}", (
                f"{path} ended a session from an MFA-pending session on the password alone"
            )

        assert await service.identity_for_token(other.token) is not None

    # Each refusal leaves a row, as the JSON twin's does: otherwise probing is silent.
    denied = [
        a["detail"] or ""
        for a in await engine.store.list_audit()
        if a["action"] == "auth.mfa_denied"
    ]
    assert sum("/ui/account/sessions/" in d for d in denied) == 2


async def test_a_session_that_proved_its_code_at_reauth_can_end_sessions(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: the refusal ignores ``mfa_satisfied`` and blocks every enrolled account.

    The console's own path for an enrolled, pending session: ``/ui/reauth`` takes the code, then the
    password, then mints. That must still end the other sessions.
    """
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    t0 = 1_000_000.0
    _pin_totp_clock(monkeypatch, t0)
    secret = await _enroll_totp(service)
    other = await service.login("op", PW)
    assert other.ok and other.token is not None

    async with _client(engine, service) as c:
        assert (await _login(c)).status_code == 303
        t1 = t0 + totp.DEFAULT_PERIOD  # a strictly later step: enrollment consumed its own
        _pin_totp_clock(monkeypatch, t1)
        minted = await c.post(
            "/ui/reauth",
            data={"next": _REVOKE_OTHERS, "code": totp.totp(secret, now=t1), "password": PW},
            headers=SAME_ORIGIN,
        )
        assert minted.status_code == 200
        r = await c.post(_REVOKE_OTHERS, headers=SAME_ORIGIN)
        assert r.status_code == 303
        assert r.headers["location"] == "/ui/account/sessions?m=signed_out_others"
        assert await service.identity_for_token(other.token) is None


async def test_an_account_with_no_factor_still_ends_sessions_from_a_pending_session(
    engine: Engine,
) -> None:
    """RED when: the refusal over-reaches and blocks the un-enrolled case too.

    A fresh account is pending under the default ``require_mfa`` and has no code to give. The
    password-only re-proof is its only way to end a session it does not recognise.
    """
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    other = await service.login("op", PW)
    assert other.ok and other.token is not None

    async with _client(engine, service) as c:
        assert (await _login(c)).status_code == 303
        tok = c.cookies.get("mf_session")
        assert tok is not None and await service.mfa_satisfied(tok) is False
        minted = await c.post(
            "/ui/reauth", data={"next": _REVOKE_OTHERS, "password": PW}, headers=SAME_ORIGIN
        )
        assert minted.status_code == 200
        r = await c.post(_REVOKE_OTHERS, headers=SAME_ORIGIN)
        assert r.status_code == 303
        assert r.headers["location"] == "/ui/account/sessions?m=signed_out_others"
        assert await service.identity_for_token(other.token) is None


# --- changing the password from a pending session (ASVS 6.3.3 / 7.5.1, BACKLOG #1954) -------

PW2 = "another-strong-test-passphrase"  # the rotated password; satisfies the same policy
_PASSWORD = "/ui/account/password"
#: Where a covered account with no TOTP is sent first (ADR 0197 Amendment A).
_ENROL_FIRST = "/ui/account?m=enroll_first"


async def _change_password(c: httpx.AsyncClient, *, current: str = PW) -> httpx.Response:
    return await c.post(
        _PASSWORD,
        data={"current_password": current, "new_password": PW2, "new_password2": PW2},
        headers=SAME_ORIGIN,
    )


async def _reset(service: AuthService, username: str = "op") -> str:
    """Admin-reset ``username``'s password and return the one-time temp. The factors stay."""
    user = await service.store.get_user_by_username(username)
    assert user is not None
    return (await service.admin_reset_password(user.id, actor="test")).password


async def test_a_pending_session_cannot_change_an_enrolled_accounts_password(
    engine: Engine,
) -> None:
    """The /ui twin of the engine's refusal. RED when: the password page lets a pending session on
    an account WITH a factor through.

    Changing the password revokes every session, so a password holder on a pending cookie could
    lock the real user out and sign them out everywhere. Both the form and the POST send it to the
    factor step instead, and each leaves a row.
    """
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    await _enroll_totp(service)
    other = await service.login("op", PW)  # the real user's other device
    assert other.ok and other.token is not None

    async with _client(engine, service) as c:
        assert (await _login(c)).headers["location"] == "/ui/mfa"
        form = await c.get(_PASSWORD)
        assert form.status_code == 303 and form.headers["location"] == "/ui/mfa"
        r = await _change_password(c)
        assert r.status_code == 303
        assert r.headers["location"] == "/ui/mfa", "a pending session changed the password"

    assert await service.identity_for_token(other.token) is not None
    assert (await service.login("op", PW)).ok  # the old password still works
    denied = [
        a["detail"] or ""
        for a in await engine.store.list_audit()
        if a["action"] == "auth.mfa_denied"
    ]
    assert sum(_PASSWORD in d for d in denied) == 2


async def test_a_reset_account_with_a_code_proves_it_and_then_rotates(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: ``/ui/login`` or the ``/ui/mfa`` routes confine a must-change session that still
    owes its factor.

    ``admin_reset_password`` keeps the account's factors, so the next session is must-change AND
    pending. The password page now wants the factor first, so sign-in has to lead to the factor
    page and that page has to answer it. Otherwise the two pages send the session to each other.
    """
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    t0 = 1_000_000.0
    _pin_totp_clock(monkeypatch, t0)
    secret = await _enroll_totp(service)
    temp = await _reset(service)

    async with _client(engine, service) as c:
        r = await c.post("/ui/login", data={"username": "op", "password": temp})
        assert r.status_code == 303 and r.headers["location"] == "/ui/mfa"
        # Any other page sends it straight to the factor page, not round through the password one,
        # and so does the step-up page.
        r = await c.get("/ui/messages")
        assert r.status_code == 303 and r.headers["location"] == "/ui/mfa"
        r = await c.get(f"/ui/reauth?next={_REVOKE_OTHERS}")
        assert r.status_code == 303 and r.headers["location"] == "/ui/mfa"
        denied = [
            a["detail"] or ""
            for a in await engine.store.list_audit()
            if a["action"] == "auth.mfa_denied"
        ]
        assert any("/ui/messages" in d for d in denied), "the confinement refusal left no row"
        page = await c.get("/ui/mfa")
        assert page.status_code == 200 and 'name="code"' in page.text
        t1 = t0 + totp.DEFAULT_PERIOD  # a strictly later step: enrollment consumed its own
        _pin_totp_clock(monkeypatch, t1)
        r = await c.post("/ui/mfa", data={"code": totp.totp(secret, now=t1)})
        assert r.status_code == 303 and r.headers["location"] == _PASSWORD
        # Proven, so the must-change confinement applies again, on the gate page too.
        r = await c.get("/ui/mfa")
        assert r.status_code == 303 and r.headers["location"] == _PASSWORD
        assert (await c.get(_PASSWORD)).status_code == 200
        r = await _change_password(c, current=temp)
        assert r.status_code == 303 and r.headers["location"] == "/ui/login?e=pwchanged"
    assert (await service.login("op", PW2)).ok


async def test_ui_reauth_webauthn_lets_a_reset_passkey_account_prove_it_and_rotate(
    engine: Engine,
) -> None:
    """RED when: ``ui_reauth_webauthn`` refuses a must-change session that still owes its factor.

    The one place a partial build strands someone. A passkey-only account has no code to type, so
    the assertion is its only way to prove the factor. If that route kept its blanket must-change
    refusal while the password page wants the factor first, this account could do neither.
    """
    pytest.importorskip("webauthn")
    import html
    import json
    import re

    from _soft_webauthn import SoftAuthenticator
    from webauthn.helpers import base64url_to_bytes

    service = await _service(engine)
    user_id = await _add(service, "op", Role.OPERATOR)
    # The passkey is registered with the requirement OFF: under it, a passkey cannot be a covered
    # account's first factor in wave 1 (ADR 0197 Amendment A). This builds the passkey-only state
    # an account can still reach from before the requirement covered it.
    setup_service = await _service(engine, require_mfa=False)
    identity = await setup_service.identity_for_user_id(user_id)
    assert identity is not None
    setup = await setup_service.login("op", PW)
    assert setup.ok and setup.token is not None
    options = json.loads(
        await setup_service.begin_webauthn_registration(
            identity, token=setup.token, rp_id="t", rp_name="t"
        )
    )
    key = SoftAuthenticator(rp_id="t", origin="http://t")
    registered = await setup_service.finish_webauthn_registration(
        identity,
        key.create_response(base64url_to_bytes(options["challenge"])),
        label="key",
        token=setup.token,
        rp_id="t",
        origin="http://t",
    )
    assert registered.ok
    temp = await _reset(service)

    async with _client(engine, service) as c:
        r = await c.post("/ui/login", data={"username": "op", "password": temp})
        assert r.status_code == 303 and r.headers["location"] == "/ui/mfa"
        page = await c.get("/ui/mfa")
        assert page.status_code == 200 and 'name="code"' not in page.text
        hook = re.search('data-mf-webauthn-get="([^"]*)"', page.text)
        assert hook is not None, "the gate page offered no passkey leg"
        challenge = json.loads(html.unescape(hook.group(1)))["challenge"]
        assertion = json.loads(key.get_response(base64url_to_bytes(challenge), sign_count=0))
        r = await c.post("/ui/reauth/webauthn", json={"response": assertion}, headers=SAME_ORIGIN)
        assert r.status_code == 200 and r.json() == {"ok": True}, r.text
        # Proven, so the route confines it again: the other half of the old blanket refusal.
        r = await c.post("/ui/reauth/webauthn", json={"response": {}}, headers=SAME_ORIGIN)
        assert r.status_code == 403 and r.json()["error"] == "password change required"
        # A passkey is not a way past the sign-in lock in wave 1 (ADR 0197 Amendment A), so the
        # rotation still waits for TOTP: the password page sends it to enrol, and a POST changes
        # nothing. The account is not stranded; the enrolment is open to it.
        r = await c.get(_PASSWORD)
        assert r.status_code == 303 and r.headers["location"] == _ENROL_FIRST
        r = await _change_password(c, current=temp)
        assert r.status_code == 303 and r.headers["location"] == _ENROL_FIRST
        assert (await c.get("/ui/account")).status_code == 200
    assert not (await service.login("op", PW2)).ok


async def test_a_must_change_account_with_no_factor_enrols_before_it_rotates(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ADR 0197 Amendment A, AC-A3, console plane. REWRITTEN: this was
    ``test_a_must_change_account_with_no_factor_still_rotates_first``, which pinned rotate-first.

    Under the default require_mfa, a must-change account with no TOTP is sent to enrol from the
    sign-in, the gate page and the password page, and ``POST /ui/account/password`` -- which calls
    the JSON handler in-process, past its ``Depends`` gate -- changes nothing. Once TOTP is on, the
    holder proves it and rotates. RED against the old order: the first POST rotated."""
    service = AuthService(
        engine.store, AuthSettings(mfa_verify_min_elapsed_seconds=0, login_rate_limit_enabled=False)
    )
    await service.initialize()
    await create_local_user_chosen(
        service,
        username="newbie",
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.OPERATOR.value],
        actor="test",
    )
    async with _client(engine, service) as c:
        r = await c.post("/ui/login", data={"username": "newbie", "password": PW})
        assert r.status_code == 303 and r.headers["location"] == _ENROL_FIRST
        for path in ("/ui/mfa", _PASSWORD):
            r = await c.get(path)
            assert r.status_code == 303 and r.headers["location"] == _ENROL_FIRST, path
        r = await _change_password(c, current=PW)
        assert r.status_code == 303 and r.headers["location"] == _ENROL_FIRST
        assert (await c.get("/ui/account")).status_code == 200  # the enrolment page is open
        # Session termination is not on the enrol-first path, matching the JSON plane.
        r = await c.get("/ui/account/sessions")
        assert r.status_code == 303 and r.headers["location"] == _ENROL_FIRST
    assert not (await service.login("newbie", PW2)).ok  # the rotation never landed
    # Sending an account to enrol refuses no factor it holds, so it is not an MFA denial.
    for path in ("/ui/mfa", _PASSWORD, "/ui/account/sessions", "/ui"):
        assert await _denials_for(engine, path) == 0, path

    t0 = 1_000_000.0
    _pin_totp_clock(monkeypatch, t0)
    secret = await _enroll_totp(service, "newbie")
    async with _client(engine, service) as c:
        r = await c.post("/ui/login", data={"username": "newbie", "password": PW})
        assert r.status_code == 303 and r.headers["location"] == "/ui/mfa"
        t1 = t0 + totp.DEFAULT_PERIOD
        _pin_totp_clock(monkeypatch, t1)
        r = await c.post("/ui/mfa", data={"code": totp.totp(secret, now=t1)}, headers=SAME_ORIGIN)
        assert r.status_code == 303 and r.headers["location"] == _PASSWORD
        r = await _change_password(c, current=PW)
        assert r.headers.get("location") == "/ui/login?e=pwchanged"
    assert (await service.login("newbie", PW2)).ok


async def test_with_the_requirement_off_a_must_change_account_still_rotates_first(
    engine: Engine,
) -> None:
    """The positive control for the rewrite above: with require_mfa off nothing covers the account,
    so the order stays as it was. A first Administrator on a temporary password and an
    administrator-created user both land on the password page and rotate there."""
    service = AuthService(
        engine.store,
        AuthSettings(
            mfa_verify_min_elapsed_seconds=0, login_rate_limit_enabled=False, require_mfa=False
        ),
    )
    admin = await _must_change_admin(service)
    await create_local_user_chosen(
        service,
        username="newbie",
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.OPERATOR.value],
        actor="test",
    )
    for username, password in ((admin, _ADMIN_PW), ("newbie", PW)):
        async with _client(engine, service) as c:
            r = await c.post("/ui/login", data={"username": username, "password": password})
            assert r.status_code == 303 and r.headers["location"] == _PASSWORD, username
            r = await _change_password(c, current=password)
            assert r.headers.get("location") == "/ui/login?e=pwchanged", username


_VANISH_ROUTES = ("login", "gated-page", "get-mfa", "post-mfa", "reauth-webauthn")


@pytest.mark.parametrize("vanish", ("session", "user"))
@pytest.mark.parametrize("route", _VANISH_ROUTES)
async def test_a_row_that_vanishes_mid_request_does_not_lift_the_confinement(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, vanish: str, route: str
) -> None:
    """RED when: ``rotation_comes_first`` negates ``password_change_owes_factor`` unguarded.

    BACKLOG #1974. An unknown state must confine a must-change session, never release it. The
    wrapper removes the row once, after the route has resolved the identity and before the check
    runs: the race this guards. The account has no factor, so the only wrong answers are the ones
    that release it: the factor page, the enroll bounce, the page itself, or a ceremony run. The
    password page or a sign-in redirect both hold. ``gated-page`` is the ``require_ui`` path through
    ``must_change_target``, which must also write no ``auth.mfa_denied`` row for an account with
    nothing to deny. ``user`` hides only the user row: ``delete_user`` would take the sessions with
    it, and this case would then test a missing session twice.
    """
    # require_mfa off (ADR 0197 Amendment A): with it on, a no-factor account now enrols first, and
    # the rotate-first confinement this guards exists only on the uncovered path.
    service = AuthService(
        engine.store,
        AuthSettings(
            mfa_verify_min_elapsed_seconds=0, login_rate_limit_enabled=False, require_mfa=False
        ),
    )
    await service.initialize()
    await create_local_user_chosen(
        service,
        username="newbie",
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.OPERATOR.value],
        actor="test",
    )
    real_check = service.password_change_owes_factor
    vanished: list[bool] = []

    async def no_user(user_id: str) -> None:
        return None

    async def vanishing_check(token: str | None) -> bool:
        assert token is not None
        if not vanished:
            vanished.append(True)
            if vanish == "session":
                # DELETE the row, as the expiry purge does. Revoking would not do: it only stamps
                # ``revoked_at``, and the row still answers the lookup this test is about.
                session = await service.store.get_session(hash_token(token))
                assert session is not None
                await service.store.purge_expired_sessions(now=session.expires_at + 1)
                assert await service.store.get_session(hash_token(token)) is None
            else:
                monkeypatch.setattr(service.store, "get_user", no_user)
        return await real_check(token)

    async with _client(engine, service) as c:
        if route != "login":
            # The sign-in runs the real check, so it lands on the password page as it should.
            r = await c.post("/ui/login", data={"username": "newbie", "password": PW})
            assert r.status_code == 303 and r.headers["location"] == _PASSWORD
        monkeypatch.setattr(service, "password_change_owes_factor", vanishing_check)
        if route == "login":
            r = await c.post("/ui/login", data={"username": "newbie", "password": PW})
        elif route == "gated-page":
            r = await c.get("/ui/messages")
        elif route == "get-mfa":
            r = await c.get("/ui/mfa")
        elif route == "post-mfa":
            r = await c.post("/ui/mfa", data={"code": "000000"}, headers=SAME_ORIGIN)
        else:
            r = await c.post("/ui/reauth/webauthn", json={"response": {}}, headers=SAME_ORIGIN)
        assert vanished, "the route never asked the check, so nothing vanished"
        if route == "reauth-webauthn":
            assert r.status_code in (401, 403), r.text  # refused before any ceremony ran
            return
        assert r.status_code == 303, r.text
        location = r.headers["location"]
        assert location == _PASSWORD or location.startswith("/ui/login"), location
    if route == "gated-page":
        denied = [a for a in await engine.store.list_audit() if a["action"] == "auth.mfa_denied"]
        assert not denied, "an account with no factor was audited as refused one"


async def test_a_satisfied_session_changes_the_password_as_before(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: the refusal ignores ``mfa_satisfied`` and blocks every enrolled account."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    t0 = 1_000_000.0
    _pin_totp_clock(monkeypatch, t0)
    secret = await _enroll_totp(service)
    async with _client(engine, service) as c:
        await _login(c)
        t1 = t0 + totp.DEFAULT_PERIOD
        _pin_totp_clock(monkeypatch, t1)
        verified = await c.post("/ui/mfa", data={"code": totp.totp(secret, now=t1)})
        assert verified.status_code == 303
        r = await _change_password(c)
        assert r.status_code == 303 and r.headers["location"] == "/ui/login?e=pwchanged"


# --- a refused pending session spends no admin-write budget (ASVS 6.3.3, BACKLOG #1973) -------

#: A session id no route resolves. The refusal runs in the gate, before the body looks at it.
_SOME_SESSION_ID = "0" * 64

#: The POSTs that refuse a pending session through ``require_ui``'s ``pending_refusal``, paired with
#: where that refusal sends it. The password route refuses before rotating (#1954); the rest are the
#: ``require_ui_reauth_only_action`` lanes (#1951). NOT every pending-exempt POST:
#: ``POST /ui/account/webauthn/verify`` rides ``require_ui_reauth_only``, which has no such hook and
#: still charges before its step-up check refuses. #1973 left it out of scope.
_PENDING_REFUSED_POSTS = (
    pytest.param(_PASSWORD, "/ui/mfa", id="password"),
    pytest.param(
        "/ui/account/mfa/enroll", "/ui/reauth?next=/ui/account/mfa/enroll", id="mfa-enroll"
    ),
    pytest.param(
        "/ui/account/mfa/verify", "/ui/reauth?next=/ui/account/mfa/confirm", id="mfa-verify"
    ),
    pytest.param(
        f"/ui/account/sessions/{_SOME_SESSION_ID}/revoke",
        f"/ui/reauth?next=/ui/account/sessions/{_SOME_SESSION_ID}/revoke",
        id="revoke-one",
    ),
    pytest.param(_REVOKE_OTHERS, f"/ui/reauth?next={_REVOKE_OTHERS}", id="revoke-others"),
    pytest.param(
        "/ui/account/webauthn/enroll",
        "/ui/reauth?next=/ui/account/webauthn/enroll",
        id="webauthn-enroll",
    ),
)

#: A password form that can never rotate: the two new passwords differ. On the password route it
#: keeps a control from signing the session out; every other route ignores the body.
_NO_ROTATION = {"current_password": PW, "new_password": PW2, "new_password2": PW2 + "-x"}


def _spy_admin_write(service: AuthService, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record every ``allow_admin_write`` charge from here on, and still apply it."""
    calls: list[str] = []
    real = service.allow_admin_write

    def spy(user_id: str) -> bool:
        calls.append(user_id)
        return real(user_id)

    monkeypatch.setattr(service, "allow_admin_write", spy)
    return calls


def _assert_past_the_gate(path: str, refused_to: str, r: httpx.Response) -> None:
    """A control's POST got past the pending refusal and was answered by what follows it.

    The password handler answers the mismatched form with a 400. Each reauth-only lane holds no
    step-up grant, so its step-up check sends it to the same ``/ui/reauth`` location the pending
    refusal uses; there the zero ``auth.mfa_denied`` rows the controls assert are what tell the two
    apart."""
    if path == _PASSWORD:
        assert r.status_code == 400, r.text
    else:
        assert r.status_code == 303 and r.headers["location"] == refused_to, r.text


async def _denials_for(engine: Engine, path: str) -> int:
    return sum(
        path in (a["detail"] or "")
        for a in await engine.store.list_audit(limit=500)
        if a["action"] == "auth.mfa_denied"
    )


@pytest.mark.parametrize(("path", "refused_to"), _PENDING_REFUSED_POSTS)
async def test_a_refused_pending_post_spends_none_of_the_users_admin_write_budget(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, path: str, refused_to: str
) -> None:
    """RED when: ``require_ui`` charges ``allow_admin_write`` before the route's pending refusal.

    The budget belongs to the user, not the session. A password holder on a pending cookie could
    otherwise POST here in a loop, be refused every time, and still throttle the real user's writes
    on every device. Each refusal must still leave exactly one ``auth.mfa_denied`` row.
    """
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    await _enroll_totp(service)

    async with _client(engine, service) as c:
        assert (await _login(c)).headers["location"] == "/ui/mfa"  # pending, password only
        calls = _spy_admin_write(service, monkeypatch)  # after login, so only the route counts
        for _ in range(3):
            r = await c.post(path, data=_NO_ROTATION, headers=SAME_ORIGIN)
            assert r.status_code == 303 and r.headers["location"] == refused_to, r.text

    assert calls == [], f"a refused pending session was charged: {calls}"
    assert await _denials_for(engine, path) == 3


@pytest.mark.parametrize(("path", "refused_to"), _PENDING_REFUSED_POSTS)
async def test_a_satisfied_session_is_still_charged_on_the_same_posts(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, path: str, refused_to: str
) -> None:
    """The control for the test above. RED when: the charge is skipped for everyone, or the spy is
    not wired, which would let an empty list there mean "not observed" rather than "not charged"."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    t0 = 1_000_000.0
    _pin_totp_clock(monkeypatch, t0)
    secret = await _enroll_totp(service)

    async with _client(engine, service) as c:
        await _login(c)
        t1 = t0 + totp.DEFAULT_PERIOD  # a strictly later step: enrollment consumed its own
        _pin_totp_clock(monkeypatch, t1)
        assert (
            await c.post("/ui/mfa", data={"code": totp.totp(secret, now=t1)})
        ).status_code == 303
        calls = _spy_admin_write(service, monkeypatch)
        _assert_past_the_gate(
            path, refused_to, await c.post(path, data=_NO_ROTATION, headers=SAME_ORIGIN)
        )

    assert len(calls) == 1, f"allow_admin_write calls: {calls}"
    assert await _denials_for(engine, path) == 0


#: The password page is not among them any more: under require_mfa an account with no TOTP is sent
#: to enrol before it may rotate (ADR 0197 Amendment A), which
#: ``test_a_must_change_account_with_no_factor_enrols_before_it_rotates`` pins.
_NO_FACTOR_PASSING_POSTS = tuple(p for p in _PENDING_REFUSED_POSTS if p.id != "password")


@pytest.mark.parametrize(("path", "refused_to"), _NO_FACTOR_PASSING_POSTS)
async def test_a_pending_session_with_no_factor_is_charged_and_not_refused(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, path: str, refused_to: str
) -> None:
    """RED when: the early refusal over-reaches to an account with no factor.

    That account is pending under the default ``require_mfa`` with nothing to prove, and these
    routes are how it enrols, rotates and ends sessions. It passes the gate, so it pays the budget
    like any other write, and it leaves no ``auth.mfa_denied`` row.
    """
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)

    async with _client(engine, service) as c:
        await _login(c)
        tok = c.cookies.get("mf_session")
        assert tok is not None and await service.mfa_satisfied(tok) is False
        calls = _spy_admin_write(service, monkeypatch)
        _assert_past_the_gate(
            path, refused_to, await c.post(path, data=_NO_ROTATION, headers=SAME_ORIGIN)
        )

    assert len(calls) == 1, f"allow_admin_write calls: {calls}"
    assert await _denials_for(engine, path) == 0


async def test_a_cross_site_pending_post_is_refused_before_it_is_audited(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: the early refusal runs before the same-origin check.

    A cross-site page must not be able to write ``auth.mfa_denied`` rows against a victim's
    pending cookie, nor spend its budget. It gets the plain cross-origin 403 and leaves nothing.
    """
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    await _enroll_totp(service)

    async with _client(engine, service) as c:
        await _login(c)
        calls = _spy_admin_write(service, monkeypatch)
        r = await c.post(_PASSWORD, data=_NO_ROTATION, headers={"Sec-Fetch-Site": "cross-site"})
        assert r.status_code == 403, r.text

    assert calls == []
    assert await _denials_for(engine, _PASSWORD) == 0


@pytest.mark.parametrize("enrolled", (False, True), ids=("no-factor", "with-a-factor"))
async def test_a_directory_account_still_gets_the_directory_refusal(
    engine: Engine, enrolled: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: the refusal pre-empts the directory 400.

    A pending directory session is left to the handler whether or not it holds an engine factor, as
    on the JSON plane: the 400 changes nothing and says where the password lives.
    """
    from messagefoundry.auth.ldap import AdPrincipal

    service = await _service(engine)
    principal = AdPrincipal(
        username="aduser",
        display_name=None,
        email=None,
        dn="CN=aduser,DC=x",
        groups=frozenset(),
        directory_object_id="1291e547-a91b-5700-88cb-a198a209fb05",
    )
    if enrolled:
        _pin_totp_clock(monkeypatch, 1_000_000.0)  # no step boundary between code and check
        setup = await service._complete_ad_login(principal, None, mfa_verified=False)
        assert setup.identity is not None and setup.token is not None
        enrollment = await service.begin_mfa_enrollment(setup.identity)
        confirmed = await service.confirm_mfa_enrollment(
            setup.identity, totp.totp(enrollment.secret), token=setup.token
        )
        assert confirmed.ok
    out = await service._complete_ad_login(principal, None, mfa_verified=False)
    assert out.ok and out.token is not None
    assert await service.mfa_satisfied(out.token) is False
    async with _client(engine, service) as c:
        c.cookies.set("mf_session", out.token)
        r = await _change_password(c)
        assert r.status_code == 400 and "managed in AD" in r.text


# --- a directory the account is not confirmed in (BACKLOG #2023) --------------------------------

_DIRECTORY_UNCONFIRMED_TEXT = "The directory could not confirm your account."


def _directory_refuses(service: AuthService, monkeypatch: pytest.MonkeyPatch) -> None:
    """Make ``verify_mfa`` answer as it does for a directory account the directory did not confirm.

    The service-level refusal is pinned in tests/test_mfa_directory_recheck.py. The subject here is
    only what the console SAYS, so the answer is stubbed rather than driven through a fake directory.
    """

    async def _refused(token: str | None, code: str, *, client: str | None = None) -> Elevation:
        return Elevation(directory_unconfirmed=True)

    monkeypatch.setattr(service, "verify_mfa", _refused)


async def test_the_gate_says_the_directory_could_not_confirm_the_account(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: /ui/mfa drops the directory_unconfirmed branch and calls the code wrong."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    await _enroll_totp(service)
    async with _client(engine, service) as c:
        await _login(c)
        _directory_refuses(service, monkeypatch)
        r = await c.post("/ui/mfa", data={"code": "123456"})
        assert r.status_code == 400
        assert _DIRECTORY_UNCONFIRMED_TEXT in r.text
        assert "That code wasn" not in r.text


async def test_the_reauth_code_leg_says_the_directory_could_not_confirm_the_account(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: /ui/reauth's code leg drops the directory_unconfirmed branch."""
    service = await _service(engine, require_mfa=True)
    await _add(service, "op", Role.OPERATOR)
    await _enroll_totp(service)
    async with _client(engine, service) as c:
        assert (await _login(c)).status_code == 303
        _directory_refuses(service, monkeypatch)
        r = await c.post(
            "/ui/reauth",
            data={"next": "/ui/account/mfa/disable", "code": "123456", "password": PW},
            headers={"origin": "http://t"},
        )
        assert r.status_code == 200
        assert _DIRECTORY_UNCONFIRMED_TEXT in r.text
        assert "Invalid code." not in r.text


@pytest.mark.parametrize("unconfirmed", [True, False], ids=["directory-refused", "wrong-password"])
async def test_the_reauth_password_leg_says_the_directory_could_not_confirm_the_account(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, unconfirmed: bool
) -> None:
    """BACKLOG #2027: a directory re-bind the directory could not judge (a row with no directory
    id, an entry that is not the row's own, no entry, an outage) never checked the password, so the
    form must not call it wrong. The service-level refusal is pinned in
    tests/test_ad_directory_identity.py; here the answer is stubbed and the subject is the words.

    RED when: /ui/reauth's password leg drops the directory_unconfirmed branch (the refused arm then
    reads "Incorrect password."), or applies it to an ordinary wrong password (the control arm)."""
    # No factor required and none enrolled, so the form goes straight to the password leg.
    service = await _service(engine, require_mfa=False)
    await _add(service, "op", Role.OPERATOR)

    async def _refused(identity: object, password: str, **_kwargs: object) -> Elevation:
        return Elevation(directory_unconfirmed=unconfirmed)

    async with _client(engine, service) as c:
        assert (await _login(c)).status_code == 303
        monkeypatch.setattr(service, "reauth", _refused)
        r = await c.post(
            "/ui/reauth",
            data={"next": "/ui/account/mfa/disable", "password": PW},
            headers={"origin": "http://t"},
        )
        assert r.status_code == 200
        assert (_DIRECTORY_UNCONFIRMED_TEXT in r.text) is unconfirmed
        assert ("Incorrect password." in r.text) is not unconfirmed


# --- the temporary credential's deadline on the factor and password pages (BACKLOG #2009) ------


def _console_stamp(ts: float) -> str:
    from datetime import UTC, datetime

    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%d %H:%M:%SZ")


async def test_the_factor_page_states_the_reset_credentials_deadline(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: /ui/mfa drops the deadline, or reads it from anything but the stored stamp.

    A reset holder with a second factor lands on /ui/mfa before the forced password page, so the
    first page they read has to state when the temporary password stops working. The instant is the
    one the issuing administrator was handed, which is the one the sign-in gate refuses on.
    """
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    _pin_totp_clock(monkeypatch, 1_000_000.0)
    await _enroll_totp(service)
    user = await service.store.get_user_by_username("op")
    assert user is not None
    issued = await service.admin_reset_password(user.id, actor="test")
    assert issued.expires_at is not None
    expected = f"It stops working at {_console_stamp(issued.expires_at)}."

    async with _client(engine, service) as c:
        r = await c.post("/ui/login", data={"username": "op", "password": issued.password})
        assert r.status_code == 303 and r.headers["location"] == "/ui/mfa"
        page = await c.get("/ui/mfa")
        assert page.status_code == 200 and expected in page.text
        # A refused code re-renders the page with the same deadline.
        bad = await c.post("/ui/mfa", data={"code": "000000"})
        assert bad.status_code == 400 and expected in bad.text


async def test_the_factor_page_states_no_deadline_for_a_password_the_holder_chose(
    engine: Engine,
) -> None:
    """Control for the test above: an account with no temporary credential sees no deadline."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    await _enroll_totp(service)
    async with _client(engine, service) as c:
        assert (await _login(c)).headers["location"] == "/ui/mfa"
        page = await c.get("/ui/mfa")
        assert page.status_code == 200 and 'name="code"' in page.text
        assert "stops working" not in page.text


def test_the_factor_page_builder_states_the_deadline_only_when_given_one() -> None:
    from messagefoundry_webconsole.pages import account as pages

    assert "stops working at" in str(
        pages.mfa_gate(totp_enrolled=True, credential_expires_at=1.8e9)
    )
    assert "stops working" not in str(pages.mfa_gate(totp_enrolled=True))
    # A deadline past what the clock can render drops the sentence instead of raising: this page is
    # a confinement page, so it must never 500.
    assert "stops working" not in str(
        pages.mfa_gate(totp_enrolled=True, credential_expires_at=1e15)
    )


async def test_the_password_page_refuses_to_rotate_a_credential_past_its_deadline(
    engine: Engine,
) -> None:
    """RED when: a cookie session opened before the deadline still rotates the lapsed password.

    The /ui twin of the JSON refusal: the page delegates to POST /me/password, so the refusal reaches
    it as that route's 403, and the holder reads why and what to do next.
    """
    service = await _service(engine, require_mfa=False)
    user_id = await _add(service, "op", Role.OPERATOR)
    temp = await _reset(service)
    async with _client(engine, service) as c:
        r = await c.post("/ui/login", data={"username": "op", "password": temp})
        assert r.status_code == 303 and r.headers["location"] == _PASSWORD
        await engine.store._db.execute(
            "UPDATE users SET password_changed_at=? WHERE id=?", (1.0, user_id)
        )
        await engine.store._db.commit()
        r = await _change_password(c, current=temp)
        assert r.status_code == 403, r.text
        assert "temporary password has expired" in r.text
    user = await service.store.get_user(user_id)
    assert user is not None and user.must_change_password is True


async def test_the_enrol_first_notice_offers_a_passkey_only_where_one_is_accepted(
    engine: Engine,
) -> None:
    """RED when: the enroll_first notice offers a passkey to a local account ``require_mfa`` covers
    that has no TOTP. The service refuses that account's passkey as a first factor (ADR 0197
    Amendment A), so the notice must name the authenticator app alone. With the requirement off
    nothing is refused, and the notice still offers both."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _login(c)
        # Pending with no factor: the gate page has nothing to ask, so it sends the session here.
        r = await c.get("/ui/mfa")
        assert r.status_code == 303 and r.headers["location"] == _ENROL_FIRST
        page = await c.get(_ENROL_FIRST)
    assert page.status_code == 200
    assert "enroll an authenticator app (TOTP) to continue" in page.text
    assert "TOTP app or passkey" not in page.text, "the notice offers a passkey the service refuses"

    off = await _service(engine, require_mfa=False)
    async with _client(engine, off) as c:
        await _login(c)
        page = await c.get(_ENROL_FIRST)
    assert page.status_code == 200
    assert "TOTP app or passkey" in page.text
