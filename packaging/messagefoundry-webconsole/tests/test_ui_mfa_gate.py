# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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
    assert await service.confirm_mfa_enrollment(
        identity, totp.totp(enrollment.secret), token=outcome.token
    )
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
