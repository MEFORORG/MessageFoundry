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

import httpx
import pytest
from _ui_clients import SAME_ORIGIN

from messagefoundry.api import create_app
from messagefoundry.auth import Role, totp
from messagefoundry.auth.service import AuthService
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
    service = AuthService(engine.store, AuthSettings(login_rate_limit_enabled=False, **kw))  # type: ignore[arg-type]
    await service.initialize()
    return service


def _client(engine: Engine, service: AuthService) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=create_app(engine, auth=service, serve_ui=True))
    return httpx.AsyncClient(transport=transport, base_url="http://t")


async def _add(service: AuthService, username: str, *roles: Role) -> str:
    user_id = await service.create_local_user(
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
        user_id, password_hash=user.password_hash, must_change_password=False
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
        assert (await c.get("/ui/account/password")).status_code == 200


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
    """RED when: GET /ui/mfa checks mfa before must_change.

    A bootstrap admin is BOTH. Leading with MFA parks it on a page it cannot answer until it has
    rotated — the cookie-plane twin of the JSON ordering rule.
    """
    service = AuthService(engine.store, AuthSettings(login_rate_limit_enabled=False))
    boot = await service.initialize()  # the FIRST initialize is what mints the bootstrap admin
    assert boot is not None
    async with _client(engine, service) as c:
        r = await c.post("/ui/login", data={"username": boot.username, "password": boot.password})
        assert r.status_code == 303 and r.headers["location"] == "/ui/account/password"
        r = await c.get("/ui/mfa")
        assert r.status_code == 303 and r.headers["location"] == "/ui/account/password"


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
    from messagefoundry.auth.tokens import hash_token

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
    identity = await service.identity_for_user_id(user_id)
    assert identity is not None
    setup = await service.login("op", PW)
    assert setup.ok and setup.token is not None
    options = json.loads(
        await service.begin_webauthn_registration(
            identity, token=setup.token, rp_id="t", rp_name="t"
        )
    )
    key = SoftAuthenticator(rp_id="t", origin="http://t")
    registered = await service.finish_webauthn_registration(
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
        assert (await c.get(_PASSWORD)).status_code == 200
        r = await _change_password(c, current=temp)
        assert r.status_code == 303 and r.headers["location"] == "/ui/login?e=pwchanged"
    assert (await service.login("op", PW2)).ok


async def test_a_must_change_account_with_no_factor_still_rotates_first(engine: Engine) -> None:
    """RED when: the refusal or the new sign-in order reaches an account with no factor.

    The bootstrap administrator and an administrator-created user are must-change with nothing to
    prove. Sending either to the factor page would bounce it to enroll, which the must-change
    confinement refuses: the brick. Both must still land on the password page and rotate there.
    """
    service = AuthService(engine.store, AuthSettings(login_rate_limit_enabled=False))
    boot = await service.initialize()  # the FIRST initialize mints the bootstrap admin
    assert boot is not None
    await service.create_local_user(
        username="newbie",
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.OPERATOR.value],
        actor="test",
    )
    for username, password in ((boot.username, boot.password), ("newbie", PW)):
        async with _client(engine, service) as c:
            r = await c.post("/ui/login", data={"username": username, "password": password})
            assert r.status_code == 303 and r.headers["location"] == _PASSWORD, username
            r = await c.get("/ui/mfa")
            assert r.status_code == 303 and r.headers["location"] == _PASSWORD, username
            # Nothing to prove, so the passkey leg stays shut to it too.
            r = await c.post("/ui/reauth/webauthn", json={"response": {}}, headers=SAME_ORIGIN)
            assert r.status_code == 403 and r.json()["error"] == "password change required"
            r = await _change_password(c, current=password)
            assert r.headers.get("location") == "/ui/login?e=pwchanged", username


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
        username="aduser", display_name=None, email=None, dn="CN=aduser,DC=x", groups=frozenset()
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
        assert r.status_code == 400 and "Active Directory" in r.text
