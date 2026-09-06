# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ASVS 7.2.4 — rotation WIRED at the five elevation call sites, asserted by BEHAVIOUR.

``tests/test_session_rotation_primitive.py`` pins ``_rotate_session_token`` itself. This file pins
that the five ceremonies which RAISE a session's authentication state actually call it, in the right
order, and hand the new token back.

**Why behaviour and not a call-pattern check.** The absence marker for this requirement was literally
"the primitive has no callers", so a test that asserted the primitive is now called would flip that
marker while proving nothing about the session. Every case below drives ``identity_for_token`` (the
seam every gate authenticates on) or a real route, so a rotation that re-keys the row but strands the
caller, or one that runs before its own stamps, still fails.

The five sites: ``reauth``, ``verify_mfa``, ``confirm_mfa_enrollment``, ``finish_webauthn_registration``,
``finish_webauthn_assertion``. Each test names the mutation that must turn it RED.
"""

from __future__ import annotations

import json

import pytest
from _totp_clock import fresh_totp, pin_totp_clock

from messagefoundry.auth import totp
from messagefoundry.auth.identity import Identity
from messagefoundry.auth.service import STEP_UP_ACTION_MFA_ENROLL, AuthService
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.store import MessageStore


async def _store() -> MessageStore:
    return await MessageStore.open(":memory:")


async def _service(**settings: object) -> tuple[AuthService, MessageStore]:
    store = await _store()
    settings.setdefault("login_rate_limit_enabled", False)
    return AuthService(store, AuthSettings(**settings)), store


async def _bootstrap_login(service: AuthService) -> tuple[Identity, str, str]:
    boot = await service.initialize()
    assert boot is not None
    out = await service.login("admin", boot.password)
    assert out.ok and out.identity is not None and out.token is not None
    return out.identity, out.token, boot.password


async def _enable_totp(
    service: AuthService,
    identity: Identity,
    token: str,
    *,
    monkeypatch: pytest.MonkeyPatch,
    instant: float,
) -> tuple[str, str]:
    """Enroll + confirm TOTP at a PINNED step. Returns (secret, the token the confirm rotated to).

    The step is pinned because enrollment CONSUMES its activating step (single-use, BACKLOG #1021),
    so a later ``verify_mfa`` must present a code from a strictly higher step. ``fresh_totp``
    guarantees headroom within a step but cannot advance one.
    """
    enroll = await service.begin_mfa_enrollment(identity)
    pin_totp_clock(monkeypatch, instant)
    elevation = await service.confirm_mfa_enrollment(
        identity, totp.totp(enroll.secret, now=instant), token=token
    )
    assert elevation.ok and elevation.token is not None
    return enroll.secret, elevation.token


async def _assert_rotated(service: AuthService, old: str, new: str | None) -> None:
    """The whole contract in one place: the old token is dead, the new one authenticates."""
    assert new is not None and new != old, "the ceremony handed back no new token"
    assert await service.identity_for_token(old) is None, (
        "the pre-elevation token still authenticates — it was elevated IN PLACE"
    )
    assert await service.identity_for_token(new) is not None, "the new token does not authenticate"


# --- one case per elevation site --------------------------------------------


async def test_reauth_rotates_the_session() -> None:
    """RED when: reauth stops calling _elevated (site 1 of 5).

    Without this, a token captured before a step-up would keep working with the step-up's freshly
    widened privileges on a first deployment.
    """
    service, store = await _service()
    try:
        identity, token, password = await _bootstrap_login(service)
        elevation = await service.reauth(identity, password, token=token)
        assert elevation.ok
        await _assert_rotated(service, token, elevation.token)
    finally:
        await store.close()


async def test_verify_mfa_rotates_the_session(monkeypatch: pytest.MonkeyPatch) -> None:
    """RED when: verify_mfa stops calling _elevated (site 2 of 5).

    THE site the requirement is about: a pre-MFA token captured before the second factor would
    otherwise be elevated in place to a fully authenticated session.
    """
    service, store = await _service(require_mfa=True)
    try:
        identity, token, password = await _bootstrap_login(service)
        t0 = 1_000_000.0
        secret, token = await _enable_totp(
            service, identity, token, monkeypatch=monkeypatch, instant=t0
        )

        # Re-login to get a genuinely MFA-PENDING session, which is the state under test.
        out = await service.login("admin", password)
        assert out.token is not None
        pending = out.token
        assert await service.mfa_satisfied(pending) is False

        # A strictly later step: enrollment consumed its own.
        t1 = t0 + totp.DEFAULT_PERIOD
        pin_totp_clock(monkeypatch, t1)
        elevation = await service.verify_mfa(pending, totp.totp(secret, now=t1))
        assert elevation.ok
        await _assert_rotated(service, pending, elevation.token)
        assert await service.mfa_satisfied(elevation.token) is True
    finally:
        await store.close()


async def test_confirm_mfa_enrollment_rotates_the_session() -> None:
    """RED when: confirm_mfa_enrollment stops calling _elevated (site 3 of 5).

    The FIRST-enrolment promotion leg. Skipping it is the exact trap of building only the two
    owner-named JSON routes: TOTP verify would rotate while the leg that turns a pending session into
    a satisfied one for a first enrolment would not.
    """
    service, store = await _service()
    try:
        identity, token, _ = await _bootstrap_login(service)
        enroll = await service.begin_mfa_enrollment(identity)

        elevation = await service.confirm_mfa_enrollment(
            identity, fresh_totp(enroll.secret), token=token
        )
        assert elevation.ok
        await _assert_rotated(service, token, elevation.token)
        # The one-time codes still come back — the result type carries them, not a separate return.
        assert len(elevation.recovery_codes) == 10
    finally:
        await store.close()


async def test_the_elevated_state_is_readable_on_the_new_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RED when: any stamp moves AFTER the rotation — the ORDERING INVARIANT, pinned.

    Every session UPDATE but revoke/rotate is rowcount-blind, so a stamp written after the re-key
    silently writes nothing and still reports success. The only way to see that is from the NEW
    session: it would read back unelevated. Asserted on both stamps verify_mfa makes.
    """
    service, store = await _service(require_mfa=True)
    try:
        identity, token, password = await _bootstrap_login(service)
        t0 = 1_000_000.0
        secret, _ = await _enable_totp(
            service, identity, token, monkeypatch=monkeypatch, instant=t0
        )

        out = await service.login("admin", password)
        assert out.token is not None
        t1 = t0 + totp.DEFAULT_PERIOD
        pin_totp_clock(monkeypatch, t1)
        elevation = await service.verify_mfa(out.token, totp.totp(secret, now=t1))
        assert elevation.ok and elevation.token is not None

        # mark_session_mfa_verified landed before the rotation...
        assert await service.mfa_satisfied(elevation.token) is True
        # ...and so did mark_session_reauthed (the step-up window verify_mfa seeds).
        assert await service.has_recent_step_up(elevation.token) is True
    finally:
        await store.close()


# --- the negative control ----------------------------------------------------


@pytest.mark.parametrize("ceremony", ["reauth", "verify_mfa", "confirm_mfa_enrollment"])
async def test_a_failed_elevation_rotates_nothing(
    ceremony: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: any site rotates UNCONDITIONALLY rather than on success.

    NOT decoration. Every other assertion in this file is satisfied by a service that rotates on
    every call, which would hand an attacker a session-killing oracle out of a wrong password and
    sign the user out on every typo. The original token MUST survive a failed proof.
    """
    service, store = await _service()
    try:
        identity, token, password = await _bootstrap_login(service)
        if ceremony == "reauth":
            elevation = await service.reauth(identity, "wrong-password", token=token)
        elif ceremony == "verify_mfa":
            await _enable_totp(
                service, identity, token, monkeypatch=monkeypatch, instant=1_000_000.0
            )
            out = await service.login("admin", password)
            assert out.token is not None
            token = out.token
            elevation = await service.verify_mfa(token, "000000")
        else:
            await service.begin_mfa_enrollment(identity)
            elevation = await service.confirm_mfa_enrollment(identity, "000000", token=token)

        assert elevation.ok is False
        assert elevation.token is None, "a failed ceremony handed back a token"
        assert elevation.session_lost is False, "a wrong proof is not a lost session"
        assert await service.identity_for_token(token) is not None, (
            "a FAILED elevation rotated the session — a wrong proof must change nothing"
        )
    finally:
        await store.close()


async def test_a_ceremony_on_a_revoked_session_fails_closed() -> None:
    """RED when: _elevated returns ok on a None rotate.

    A correct password against a session revoked underneath the ceremony must not yield a token that
    authenticates nothing, and must be distinguishable from a wrong password so the route can say
    "sign in again" rather than "incorrect".
    """
    service, store = await _service()
    try:
        identity, token, password = await _bootstrap_login(service)
        await service.store.revoke_session(hash_token(token))

        elevation = await service.reauth(identity, password, token=token)
        assert elevation.ok is False
        assert elevation.token is None
        assert elevation.session_lost is True
    finally:
        await store.close()


# --- the reauth grant trap ---------------------------------------------------


async def test_the_action_grant_is_minted_against_the_new_token() -> None:
    """RED when: reauth mints the purpose-bound grant BEFORE the rotation (or against the old hash).

    ADR 0077's grant is keyed on the session's token hash. Minted against the retired hash it is
    stranded: the ceremony the operator just completed silently no-ops and the next route demands
    another step-up. `_rekey_token_state` carries grants across, so minting early would ALSO appear
    to work — this pins that the grant is usable on the token the caller was actually handed.
    """
    service, store = await _service()
    try:
        identity, token, password = await _bootstrap_login(service)
        elevation = await service.reauth(
            identity, password, token=token, purpose=STEP_UP_ACTION_MFA_ENROLL
        )
        assert elevation.ok and elevation.token is not None

        # Spend it on the OLD token first: it must not be there.
        assert await service.has_action_step_up(token, STEP_UP_ACTION_MFA_ENROLL) is False
        assert await service.has_action_step_up(elevation.token, STEP_UP_ACTION_MFA_ENROLL) is True
    finally:
        await store.close()


# --- the WebAuthn legs -------------------------------------------------------


async def test_the_passkey_legs_rotate_the_session() -> None:
    """RED when: finish_webauthn_registration or finish_webauthn_assertion stops calling _elevated
    (sites 4 and 5 of 5).

    For a passkey-only account the assertion is the ONLY leg of POST /ui/mfa, so a build that rotated
    the TOTP sites alone would leave the cell claiming rotation-on-re-authentication while missing the
    passkey path entirely.
    """
    pytest.importorskip("webauthn")
    from webauthn.helpers import base64url_to_bytes

    from tests._soft_webauthn import SoftAuthenticator

    rp, origin = "t", "http://t"
    service, store = await _service(require_mfa=False)
    try:
        identity, token, password = await _bootstrap_login(service)
        soft = SoftAuthenticator(rp_id=rp, origin=origin)

        opts = json.loads(
            await service.begin_webauthn_registration(
                identity, token=token, rp_id=rp, rp_name="MessageFoundry"
            )
        )
        registration = await service.finish_webauthn_registration(
            identity,
            soft.create_response(base64url_to_bytes(opts["challenge"]), transports=["usb"]),
            label="k",
            token=token,
            rp_id=rp,
            origin=origin,
        )
        assert registration.ok
        await _assert_rotated(service, token, registration.token)
        token = registration.token
        assert token is not None

        # A fresh MFA-pending session, then the assertion leg.
        out = await service.login("admin", password)
        assert out.token is not None
        options = await service.begin_webauthn_assertion(out.token, rp_id=rp)
        assert options is not None
        assertion = await service.finish_webauthn_assertion(
            out.token,
            soft.get_response(base64url_to_bytes(json.loads(options)["challenge"])),
            rp_id=rp,
            origin=origin,
        )
        assert assertion.ok
        await _assert_rotated(service, out.token, assertion.token)
        assert await service.mfa_satisfied(assertion.token) is True
    finally:
        await store.close()
