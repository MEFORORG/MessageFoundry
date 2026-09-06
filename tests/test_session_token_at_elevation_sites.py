# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ASVS 7.2.4 — what happens to the CALLER'S SESSION TOKEN at every in-place elevation site.

Five service methods stamp elevated session state onto the SAME ``hash_token(token)`` the caller
already holds, so a token captured before an elevation is elevated in place rather than replaced. The
verb, the severity and the wiring plan are recorded once, in BACKLOG #1146; this file does not restate
them.

**What this file adds that the item's evidence does not.** Until now the gap's only instrument was a
tree-wide grep finding no caller of ``AuthService._rotate_session_token``. A grep answers "is this
identifier written anywhere", not "what does the session token do when a second factor completes" — so
the marker could flip on a rotation wired at one site while three others still elevate in place, and
nothing would notice. These tests ask the behavioural question directly, at the
``identity_for_token`` / ``mfa_satisfied`` / ``has_recent_step_up`` seam the API and console gates
actually authenticate on.

**Five tests assert the CURRENT behaviour, which is the gap.** That is deliberate: each names the
inversion that lands with the rotation wiring, so wiring a site turns exactly one test red and the
wiring commit flips one assertion rather than deleting a file.

**One test asserts a guarantee and must never invert** — the self-service password re-proof already
satisfies the verb's terminate limb. #1146 calls that a rationale-shaped disposition; nothing held it
until here.

Each test names the mutation that must turn it RED.
"""

from __future__ import annotations

import json

import pytest
from _extras_probe import OPTIONAL_EXTRAS, extra_is_installed
from _totp_clock import fresh_totp, pin_totp_clock

from messagefoundry.auth import totp
from messagefoundry.auth.identity import Identity
from messagefoundry.auth.service import STEP_UP_ACTION_SESSION_TERMINATE, AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.store import MessageStore

RP = "t"
ORIGIN = "http://t"

#: Only the two passkey arms need the optional [webauthn] extra, so this skips per-test rather than at
#: module scope the way tests/test_webauthn.py does — the other four arms must still run without it.
requires_webauthn = pytest.mark.skipif(
    not extra_is_installed(OPTIONAL_EXTRAS["webauthn"]),
    reason="the [webauthn] extra is not installed",
)


async def _service() -> tuple[MessageStore, AuthService]:
    # mfa_recovery_code_count=1 (precedent: tests/test_mfa.py) because every minted recovery code
    # costs an argon2 hash and no test here redeems one — the default 10 spends about 13 s of argon2
    # this file never reads, and the worst arm would sit inside the 60 s per-test watchdog's shadow on
    # a loaded runner.
    store = await MessageStore.open(":memory:")
    return store, AuthService(store, AuthSettings(mfa_recovery_code_count=1))


async def _bootstrap_login(service: AuthService) -> tuple[Identity, str, str]:
    """Bootstrap the admin and log it in; return (identity, token, password)."""
    boot = await service.initialize()
    assert boot is not None
    out = await service.login("admin", boot.password)
    assert out.ok and out.identity is not None and out.token is not None
    return out.identity, out.token, boot.password


async def _login(service: AuthService, password: str) -> str:
    out = await service.login("admin", password)
    assert out.ok and out.token is not None
    return out.token


async def _enroll_totp(
    service: AuthService, identity: Identity, token: str, *, now: float | None = None
) -> tuple[str, str]:
    """Run a real enrollment ceremony; returns ``(shared secret, the token to use next)``.

    Pass ``now`` (with the clock pinned there) when the test verifies a code LATER: enrollment
    consumes its activating step, so a later code from the same step is refused as a replay.

    Confirming an enrolment ELEVATES the session, so it re-keys it (ASVS 7.2.4) and the token passed
    in stops authenticating. The rotated one is returned rather than left for each caller to dig out
    of the Elevation, because a caller that kept the old one would 401 on its next line and read as a
    bug in the thing under test.
    """
    enroll = await service.begin_mfa_enrollment(identity)
    code = totp.totp(enroll.secret, now=now) if now is not None else fresh_totp(enroll.secret)
    elevation = await service.confirm_mfa_enrollment(identity, code, token=token)
    assert elevation.recovery_codes, "enrollment confirm returned no recovery codes"
    fresh = elevation.token
    assert isinstance(fresh, str) and fresh, "enrollment confirm returned no rotated token"
    return enroll.secret, fresh


async def _enroll_passkey(
    service: AuthService, identity: Identity, token: str
) -> tuple[object, str]:
    """Run a real registration ceremony against the in-repo soft authenticator.

    Returns ``(the authenticator, the token to use next)``. The first is opaque here because the
    ``webauthn`` import is deferred to the two gated tests — only ``_assert_passkey`` consumes it.
    The second exists because registration ELEVATES the enrolling session, so it re-keys it
    (ASVS 7.2.4) and the token passed in stops authenticating.
    """
    from webauthn.helpers import base64url_to_bytes

    from tests._soft_webauthn import SoftAuthenticator

    soft = SoftAuthenticator(rp_id=RP, origin=ORIGIN)
    options = await service.begin_webauthn_registration(
        identity, token=token, rp_id=RP, rp_name="MessageFoundry"
    )
    challenge = base64url_to_bytes(json.loads(options)["challenge"])
    elevation = await service.finish_webauthn_registration(
        identity,
        soft.create_response(challenge, transports=["usb"]),
        label="test key",
        token=token,
        rp_id=RP,
        origin=ORIGIN,
    )
    assert elevation.ok is True
    fresh = elevation.token
    assert isinstance(fresh, str) and fresh, "passkey registration returned no rotated token"
    return soft, fresh


async def _assert_passkey(service: AuthService, token: str, soft: object) -> tuple[bool, str]:
    """Run a real assertion ceremony for ``token`` with the authenticator ``_enroll_passkey`` built.

    Returns ``(ok, the token to use next)``. A successful assertion elevates and therefore re-keys;
    a failed one rotates nothing and hands the incoming token straight back, so a caller can rebind
    unconditionally without branching on the outcome.
    """
    from webauthn.helpers import base64url_to_bytes

    options = await service.begin_webauthn_assertion(token, rp_id=RP)
    assert options is not None
    challenge = base64url_to_bytes(json.loads(options)["challenge"])
    elevation = await service.finish_webauthn_assertion(
        token,
        soft.get_response(challenge),  # type: ignore[attr-defined]
        rp_id=RP,
        origin=ORIGIN,
    )
    return elevation.ok, (elevation.token if elevation.token is not None else token)


# --- the five in-place elevation sites --------------------------------------


async def test_the_totp_second_factor_elevates_the_pre_mfa_token_in_place(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RED when: verify_mfa stops rotating the session token.

    INVERTED when the wiring landed, exactly as this file was written to be. The pre-MFA token now
    stops authenticating at the moment of elevation, which is the arm the severity rested on: a token
    captured while the session was still MFA-pending no longer becomes a fully authenticated session
    when the legitimate user completes the second factor.

    BOTH of ``verify_mfa``'s stamps are still asserted, now against the NEW token. #1146 names the
    ordering trap — every session UPDATE but ``revoke_session``/``rotate_session`` is rowcount-blind —
    so a stamp written AFTER the rotation writes nothing and reports success. Reading the elevated
    state off the new token is what catches that: it is only there if both stamps landed first.
    """
    store, service = await _service()
    try:
        identity, enrolling, password = await _bootstrap_login(service)
        # Pin the TOTP clock so the enrollment and the second-factor verify sit in distinct,
        # provably-adjacent steps (tests/test_mfa.py convention): enrollment consumes its activating
        # step, so a verify from the SAME step is refused as a replay rather than accepted.
        t0 = 1_000_000.0
        pin_totp_clock(monkeypatch, t0)
        # The rotated token is discarded here on purpose: this arm logs in AFRESH below to get a
        # genuinely pre-MFA session, which is the thing under test.
        secret, _ = await _enroll_totp(service, identity, enrolling, now=t0)

        pre_mfa = await _login(service, password)
        assert await service.mfa_satisfied(pre_mfa) is False
        assert await service.has_recent_step_up(pre_mfa) is False

        t1 = t0 + totp.DEFAULT_PERIOD
        pin_totp_clock(monkeypatch, t1)
        elevation = await service.verify_mfa(pre_mfa, totp.totp(secret, now=t1))
        assert elevation.ok is True
        fresh = elevation.token
        assert isinstance(fresh, str) and fresh != pre_mfa

        assert await service.identity_for_token(pre_mfa) is None, (
            "the pre-MFA token stops authenticating at the moment of elevation"
        )
        assert await service.mfa_satisfied(fresh) is True, (
            "...and the elevation landed on the NEW token instead"
        )
        assert await service.has_recent_step_up(fresh) is True, (
            "...including the second stamp, the WP-L3-13 client re-anchor -- which is only "
            "readable here if it was written BEFORE the rotation, since it is rowcount-blind"
        )
    finally:
        await store.close()


async def test_the_totp_enrollment_confirm_elevates_the_enrolling_token_in_place() -> None:
    """RED when: confirm_mfa_enrollment stops rotating the session token.

    INVERTED when the wiring landed. Nothing here is a "re-auth" by name, so this leg is missed by
    any wiring scoped to the re-authentication routes — which is exactly why #1146 refused the
    owner-named two-route subset. The session's second factor now goes from pending to satisfied on a
    NEW token, and the one it had stops working.
    """
    store, service = await _service()
    try:
        identity, enrolling, _ = await _bootstrap_login(service)
        assert await service.mfa_satisfied(enrolling) is False

        _, fresh = await _enroll_totp(service, identity, enrolling)

        assert await service.identity_for_token(enrolling) is None, (
            "the enrolling token stops authenticating at the moment of elevation"
        )
        assert await service.mfa_satisfied(fresh) is True, (
            "...and the MFA-satisfied state landed on the NEW token instead"
        )
    finally:
        await store.close()


async def test_the_step_up_reauth_elevates_the_token_in_place() -> None:
    """RED when: reauth stops rotating the session token.

    INVERTED when the wiring landed. Both of this site's elevations are still asserted: the
    session-window stamp and the ADR 0077 action-bound grant, which has MOVED to the new hash as this
    docstring predicted it must. That pair is the #1146 ordering trap in miniature —
    ``_factor_binding_is_blocked`` resolves by the OLD token and fails closed, so it must run BEFORE
    the rotation, while the grant is minted AFTER against the new hash. Reading the grant off the new
    token is what proves both halves happened in that order.

    ``purpose`` is a NON-factor-binding action on purpose — ``_factor_binding_is_blocked`` would
    correctly refuse a binding one from a pending session whose account already has a factor, and
    that refusal would hide the grant this asserts.
    """
    store, service = await _service()
    try:
        # An MFA-pending session is born with NO step-up freshness (seed_reauth follows
        # mfa_verified), so the window opening below is the elevation and not login's own seed. The
        # bootstrap admin is already MFA-pending under the require_mfa default, so no enrollment is
        # needed to reach that state — see the enrollment arm above, which asserts exactly that.
        identity, token, password = await _bootstrap_login(service)
        assert await service.has_recent_step_up(token) is False

        elevation = await service.reauth(
            identity,
            password,
            token=token,
            client="10.0.0.7",
            purpose=STEP_UP_ACTION_SESSION_TERMINATE,
        )
        assert elevation.ok is True
        fresh = elevation.token
        assert isinstance(fresh, str) and fresh != token

        assert await service.identity_for_token(token) is None, (
            "the re-authenticated token stops authenticating at the moment of elevation"
        )
        assert await service.has_recent_step_up(fresh) is True, (
            "the step-up window opened on the NEW token -- which it can only be read on if the "
            "stamp landed before the rotation, since it is rowcount-blind"
        )
        # has_action_step_up is single-use, so this both proves the key and spends the grant.
        assert await service.has_action_step_up(fresh, STEP_UP_ACTION_SESSION_TERMINATE) is True, (
            "...and the action-bound grant was re-keyed onto the new token, not stranded on the old"
        )
        assert await service.has_action_step_up(token, STEP_UP_ACTION_SESSION_TERMINATE) is False, (
            "...and is NOT reachable on the retired one"
        )
    finally:
        await store.close()


@requires_webauthn
async def test_the_passkey_registration_elevates_the_enrolling_token_in_place() -> None:
    """RED when: finish_webauthn_registration stops rotating the session token.

    INVERTED when the wiring landed. For a passkey-only account this leg and the assertion below are
    the ONLY ways a session becomes MFA-satisfied, so wiring rotation on the TOTP routes alone would
    have left a cell reading "rotates on re-authentication" while the whole passkey path still
    elevated in place. That is the trap #1146 names against the owner-specified two-route subset, and
    this arm is what would have caught it.
    """
    store, service = await _service()
    try:
        identity, enrolling, _ = await _bootstrap_login(service)
        assert await service.mfa_satisfied(enrolling) is False

        _, fresh = await _enroll_passkey(service, identity, enrolling)

        assert await service.identity_for_token(enrolling) is None, (
            "the enrolling token stops authenticating at the moment of elevation"
        )
        assert await service.mfa_satisfied(fresh) is True, (
            "...and the MFA-satisfied state landed on the NEW token instead"
        )
    finally:
        await store.close()


@requires_webauthn
async def test_the_passkey_assertion_elevates_the_pre_mfa_token_in_place() -> None:
    """RED when: finish_webauthn_assertion stops rotating the session token.

    INVERTED when the wiring landed. Same shape as the TOTP arm — a token captured before the second
    factor is no longer elevated by the legitimate user's assertion; it stops working and a new one
    carries the elevation. Only the MFA leg is asserted here, and that is the site's whole contract:
    ADR 0068 decision 1 keeps ``reauth_at`` off the assertion path deliberately, so this arm must NOT
    grow a ``has_recent_step_up`` assertion on the way past.
    """
    store, service = await _service()
    try:
        identity, enrolling, password = await _bootstrap_login(service)
        soft, _ = await _enroll_passkey(service, identity, enrolling)

        pre_mfa = await _login(service, password)
        assert await service.mfa_satisfied(pre_mfa) is False

        ok, fresh = await _assert_passkey(service, pre_mfa, soft)
        assert ok is True
        assert fresh != pre_mfa

        assert await service.identity_for_token(pre_mfa) is None, (
            "the pre-MFA token stops authenticating at the moment of the assertion"
        )
        assert await service.mfa_satisfied(fresh) is True
    finally:
        await store.close()


# --- the arm that already satisfies the verb, and must keep doing so --------


async def test_a_password_change_terminates_the_callers_own_token() -> None:
    """RED when: change_password stops revoking the caller's own session.

    NOT an inversion candidate — the only test here that asserts a guarantee rather than a gap. The
    self-service password route re-proves a credential against an already-live session, which puts it
    inside the verb's scope, and it satisfies the terminate limb by revoking EVERY session for the
    user including the one that asked. Narrowing that revoke to "other sessions" would look like a
    usability fix and would silently move this arm into the gap above.
    """
    store, service = await _service()
    try:
        identity, token, _ = await _bootstrap_login(service)
        assert await service.identity_for_token(token) is not None

        assert await service.change_password(identity, "another-strong-test-passphrase") == []

        assert await service.identity_for_token(token) is None, (
            "the re-proving session must not survive its own password change"
        )
    finally:
        await store.close()
