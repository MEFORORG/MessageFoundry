# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""AuthService-level MFA (TOTP) tests (WP-14, ASVS 6.3.3).

Covers the full second-factor lifecycle on local accounts — enrollment → confirm → recovery codes,
the step-up MFA gate, the ``require_mfa`` administrator enforcement, recovery-code single-use, and
disable/admin-reset — plus the AD/Kerberos **delegation** guarantee (a directory login is never
prompted for an engine TOTP and is MFA-satisfied at issuance).
"""

from __future__ import annotations

import asyncio

import pytest
from _first_admin import FIRST_ADMIN, FIRST_ADMIN_PW, create_first_admin
from _totp_clock import fresh_totp, pin_totp_clock

from messagefoundry.auth import totp
from messagefoundry.auth.identity import AuthProvider, Identity
from messagefoundry.auth.ldap import AdPrincipal
from messagefoundry.auth.notifications import MFA_DISABLED, MFA_ENABLED, SecurityEvent
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.store import MessageStore, WebAuthnCredential


class _FakeNotifier:
    """Captures the out-of-band security events instead of emailing them."""

    def __init__(self) -> None:
        self.events: list[SecurityEvent] = []

    async def notify(self, event: SecurityEvent) -> None:
        self.events.append(event)


async def _store() -> MessageStore:
    return await MessageStore.open(":memory:")


async def _bootstrap_login(service: AuthService) -> tuple[Identity, str, str]:
    """Create the first Administrator and log it in; return (identity, token, password).

    BACKLOG #1020 retired the implicit first-run account, so this stands one up the way the
    ``admin-create`` CLI does before signing in."""
    await create_first_admin(service)
    out = await service.login(FIRST_ADMIN, FIRST_ADMIN_PW)
    assert out.ok and out.identity is not None and out.token is not None
    return out.identity, out.token, FIRST_ADMIN_PW


async def test_enroll_confirm_status_and_recovery_codes() -> None:
    store = await _store()
    try:
        notifier = _FakeNotifier()
        service = AuthService(store, AuthSettings(), security_notifier=notifier)
        identity, token, _ = await _bootstrap_login(service)

        enroll = await service.begin_mfa_enrollment(identity)
        assert enroll.secret and enroll.otpauth_uri.startswith("otpauth://totp/")
        assert (await service.mfa_status(identity)).enabled is False  # staged, not active

        recovery = await service.confirm_mfa_enrollment(
            identity, fresh_totp(enroll.secret), token=token
        )
        assert recovery is not None and len(recovery) == 10

        status = await service.mfa_status(identity)
        assert status.enabled and status.recovery_codes_remaining == 10 and status.required
        assert any(e.event_type == MFA_ENABLED for e in notifier.events)

        # Confirming the current session marked it MFA-satisfied.
        assert await service.mfa_satisfied(token) is True
    finally:
        await store.close()


async def test_login_requires_second_factor_after_enrollment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = await _store()
    try:
        service = AuthService(store, AuthSettings(mfa_recovery_code_count=2))
        identity, token, password = await _bootstrap_login(service)
        enroll = await service.begin_mfa_enrollment(identity)
        # Pin the TOTP clock so the enrollment confirm and the later login verify sit in distinct,
        # provably-adjacent steps: enrollment now consumes the activating step (BACKLOG #1021), so a
        # login code from the SAME step would be refused as a replay, not accepted.
        t0 = 1_000_000.0
        pin_totp_clock(monkeypatch, t0)
        activating = totp.totp(enroll.secret, now=t0)
        await service.confirm_mfa_enrollment(identity, activating, token=token)

        out = await service.login("admin", password)
        assert out.ok and out.mfa_required is True and out.token is not None
        assert await service.mfa_satisfied(out.token) is False  # step-up gate would 403

        wrong = "000000" if activating != "000000" else "111111"
        assert await service.verify_mfa(out.token, wrong) is False
        assert await service.mfa_satisfied(out.token) is False
        # The successful login verify must sit in a strictly later step than enrollment consumed.
        t1 = t0 + totp.DEFAULT_PERIOD
        pin_totp_clock(monkeypatch, t1)
        assert await service.verify_mfa(out.token, totp.totp(enroll.secret, now=t1)) is True
        assert await service.mfa_satisfied(out.token) is True
    finally:
        await store.close()


async def test_enrollment_consumes_the_activating_step(monkeypatch: pytest.MonkeyPatch) -> None:
    # BACKLOG #1021: the code that activates MFA is a live second factor, so it must be single-use like
    # any login code (ASVS 6.5.1). Before the fix, confirm went through the bool verify_totp wrapper,
    # which discarded the matched step and never consumed it — leaving the activating code replayable
    # on POST /auth/mfa-verify for the rest of its ~30 s step on first deployment. Pin the clock so the
    # confirm and the replay land in the SAME step S0: the replay is refused because enrollment already
    # spent S0, not because the code went stale at a boundary.
    store = await _store()
    try:
        service = AuthService(store, AuthSettings(mfa_recovery_code_count=1))
        identity, _token, password = await _bootstrap_login(service)
        enroll = await service.begin_mfa_enrollment(identity)

        t0 = 1_000_000.0
        pin_totp_clock(monkeypatch, t0)
        activating = totp.totp(enroll.secret, now=t0)
        # Confirm succeeds and consumes step S0 (returns the recovery codes, not None).
        assert await service.confirm_mfa_enrollment(identity, activating, token=_token) is not None

        # A fresh login, then replay the SAME activating code while still pinned to step S0: refused,
        # because enrollment already consumed S0 (the login path advances the high-water mark to S0
        # at enroll, so this replay resolves to a non-greater step).
        out = await service.login("admin", password)
        assert out.token is not None
        assert await service.verify_mfa(out.token, activating) is False
        assert await service.mfa_satisfied(out.token) is False
    finally:
        await store.close()


async def test_require_mfa_forces_admin_even_unenrolled() -> None:
    store = await _store()
    try:
        service = AuthService(store, AuthSettings(require_mfa=True))
        await create_first_admin(service)
        out = await service.login(FIRST_ADMIN, FIRST_ADMIN_PW)
        # Admin must MFA even though not enrolled — they can log in but can't satisfy step-up until
        # they enroll a TOTP authenticator.
        assert out.ok and out.mfa_required is True and out.token is not None
        assert await service.mfa_satisfied(out.token) is False
    finally:
        await store.close()


async def test_recovery_code_single_use() -> None:
    store = await _store()
    try:
        service = AuthService(store, AuthSettings(mfa_recovery_code_count=3))
        identity, token, password = await _bootstrap_login(service)
        enroll = await service.begin_mfa_enrollment(identity)
        codes = await service.confirm_mfa_enrollment(
            identity, fresh_totp(enroll.secret), token=token
        )
        assert codes is not None and len(codes) == 3

        out = await service.login("admin", password)
        assert out.token is not None
        assert await service.verify_mfa(out.token, codes[0]) is True  # consumes it
        assert (await service.mfa_status(identity)).recovery_codes_remaining == 2

        out2 = await service.login("admin", password)
        assert out2.token is not None
        assert await service.verify_mfa(out2.token, codes[0]) is False  # reuse rejected
        assert await service.verify_mfa(out2.token, codes[1]) is True  # a fresh one still works
    finally:
        await store.close()


async def test_totp_code_is_single_use_within_its_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # ASVS 6.5.1: a TOTP code is consumed on first use; replaying the SAME code (still valid inside its
    # ~30 s step window) on a fresh session is rejected, so a captured code can't be reused.
    store = await _store()
    try:
        service = AuthService(store, AuthSettings())
        identity, token, password = await _bootstrap_login(service)
        enroll = await service.begin_mfa_enrollment(identity)
        t0 = 1_000_000.0
        pin_totp_clock(monkeypatch, t0)
        activating = totp.totp(enroll.secret, now=t0)
        await service.confirm_mfa_enrollment(identity, activating, token=token)

        # Move to a step later than the one enrollment consumed (BACKLOG #1021); the login code and its
        # replay both live in THIS step, so the replay is refused for reuse, not for staleness.
        t1 = t0 + totp.DEFAULT_PERIOD
        pin_totp_clock(monkeypatch, t1)
        code = totp.totp(enroll.secret, now=t1)
        out = await service.login("admin", password)
        assert out.token is not None
        assert await service.verify_mfa(out.token, code) is True  # consumes the step

        out2 = await service.login("admin", password)
        assert out2.token is not None
        # Same code, still inside its window, fresh session → rejected (replay within the window).
        assert await service.verify_mfa(out2.token, code) is False
    finally:
        await store.close()


async def test_consume_totp_step_is_monotonic() -> None:
    # The store records the highest consumed TOTP time-step (single-use compare-and-set, ASVS 6.5.1):
    # a step <= the last consumed is rejected (replay/older), a strictly greater step is accepted.
    store = await _store()
    try:
        service = AuthService(store, AuthSettings())
        identity, _token, _password = await _bootstrap_login(service)
        uid = identity.user_id
        assert await store.consume_totp_step(uid, 1000) is True  # first use
        assert await store.consume_totp_step(uid, 1000) is False  # exact replay
        assert await store.consume_totp_step(uid, 999) is False  # older step
        assert await store.consume_totp_step(uid, 1001) is True  # advances the high-water mark
    finally:
        await store.close()


async def test_disable_and_admin_reset_clear_mfa(monkeypatch: pytest.MonkeyPatch) -> None:
    store = await _store()
    try:
        notifier = _FakeNotifier()
        # ``require_mfa=False`` is load-bearing, not incidental: this test's subject is that disable and
        # admin-reset CLEAR the enrollment, and under the default (``require_mfa=True``,
        # ``every_local_account``) the last-factor guard added for BACKLOG #1022 correctly refuses to
        # strip the account's only factor. The refusal itself is covered below, under the default; here
        # the documented opt-out puts the clear-semantics back in view. Enrolling a passkey instead
        # would have been the other way to get here — rejected because it would have made this test
        # depend on the optional [webauthn] extra.
        service = AuthService(
            store,
            AuthSettings(mfa_recovery_code_count=2, require_mfa=False),
            security_notifier=notifier,
        )
        identity, token, _ = await _bootstrap_login(service)
        enroll = await service.begin_mfa_enrollment(identity)
        t0 = 1_000_000.0
        pin_totp_clock(monkeypatch, t0)
        activating = totp.totp(enroll.secret, now=t0)
        await service.confirm_mfa_enrollment(identity, activating, token=token)

        await service.disable_mfa(identity)
        assert (await service.mfa_status(identity)).enabled is False
        assert any(e.event_type == MFA_DISABLED for e in notifier.events)

        # Re-enroll, then an admin reset clears it again and revokes sessions. The single-use high-water
        # mark PERSISTS across disable (disable_totp does not clear last_totp_step — correct and
        # conservative, do NOT clear it), so the re-enroll confirm must land in a LATER step than the
        # first enrollment consumed or it would be rejected as a replay and silently leave MFA disabled
        # (BACKLOG #1021). Assert it actually re-enabled so the admin reset below is proven to clear a
        # live enrollment, not a no-op.
        enroll2 = await service.begin_mfa_enrollment(identity)
        t1 = t0 + totp.DEFAULT_PERIOD
        pin_totp_clock(monkeypatch, t1)
        reenrolled = await service.confirm_mfa_enrollment(
            identity, totp.totp(enroll2.secret, now=t1), token=token
        )
        assert reenrolled is not None
        assert (await service.mfa_status(identity)).enabled is True
        await service.admin_reset_mfa(identity.user_id, actor="admin")
        assert (await service.mfa_status(identity)).enabled is False
    finally:
        await store.close()


# --- last-factor guard parity: TOTP-disable vs passkey-delete (BACKLOG #1022) ---
#
# Deliberately EXTRA-FREE (ADR 0068 section 4). The guard is a property of the account's factor state
# and has nothing to do with the optional ``[webauthn]`` extra, so the passkey side is staged through
# the ``AuthStore`` surface (the ``tests/_webauthn_store_contract.py`` precedent) rather than a real
# ceremony. A ``pytest.importorskip("webauthn")`` on this path would silently skip the guard on every
# leg that installs without the extra — a skip wearing a pass.


async def _stage_passkey(store: MessageStore, user_id: str, *, id_hash: str) -> None:
    await store.add_webauthn_credential(
        WebAuthnCredential(
            credential_id_hash=id_hash,
            credential_id=f"cred-{id_hash}",
            user_id=user_id,
            rp_id="t",
            public_key="cose-public-key-b64url",
            sign_count=0,
            transports=None,
            device_type="multi_device",
            backed_up=True,
            label=id_hash,
            aaguid="aaguid-0000",
            created_at=1000.0,
            last_used_at=None,
        )
    )


async def _enable_totp(service: AuthService, identity: Identity, token: str, at: float) -> None:
    enroll = await service.begin_mfa_enrollment(identity)
    await service.confirm_mfa_enrollment(identity, totp.totp(enroll.secret, now=at), token=token)
    assert (await service.mfa_status(identity)).enabled is True


async def test_disable_mfa_refused_when_totp_is_the_last_factor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # BACKLOG #1022 / ADR 0068 AC-10: TOTP-disable now refuses exactly where passkey-delete does.
    # RED when disable_mfa stops consulting has_webauthn_credentials + _mfa_required_for.
    store = await _store()
    try:
        service = AuthService(store, AuthSettings())  # require_mfa on by default
        identity, token, _ = await _bootstrap_login(service)
        pin_totp_clock(monkeypatch, 1_000_000.0)
        await _enable_totp(service, identity, token, 1_000_000.0)

        with pytest.raises(ValueError, match="enroll another factor first"):
            await service.disable_mfa(identity)
        assert (await service.mfa_status(identity)).enabled is True  # still on — the guard held
    finally:
        await store.close()


async def test_disable_mfa_allowed_while_a_passkey_remains(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The guard must NOT be a TOTP-only check: a user who keeps a passkey is still enrolled and stays
    # free to drop TOTP. RED when the guard degenerates into "an enrolled user keeps TOTP".
    store = await _store()
    try:
        service = AuthService(store, AuthSettings())
        identity, token, _ = await _bootstrap_login(service)
        pin_totp_clock(monkeypatch, 1_000_000.0)
        await _enable_totp(service, identity, token, 1_000_000.0)
        await _stage_passkey(store, identity.user_id, id_hash="pk1")

        await service.disable_mfa(identity)
        assert (await service.mfa_status(identity)).enabled is False
        assert await store.has_webauthn_credentials(identity.user_id) is True
    finally:
        await store.close()


async def test_disable_mfa_allowed_when_mfa_is_not_required(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The guard keys on _mfa_required_for, exactly as the passkey path does, so the documented
    # ``[auth].require_mfa = false`` opt-out still lets a voluntarily-enrolled user turn TOTP off.
    store = await _store()
    try:
        service = AuthService(store, AuthSettings(require_mfa=False))
        identity, token, _ = await _bootstrap_login(service)
        pin_totp_clock(monkeypatch, 1_000_000.0)
        await _enable_totp(service, identity, token, 1_000_000.0)

        await service.disable_mfa(identity)
        assert (await service.mfa_status(identity)).enabled is False
    finally:
        await store.close()


async def test_zero_factor_state_is_unreachable_by_either_removal_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The item's actual claim, and the reason the guard is stated over the STATE rather than over one
    route: with TOTP plus one passkey enrolled, EITHER removal is permitted first and the SECOND one is
    refused. Before the guard, the passkey-then-TOTP order reached zero enrolled factors while the
    TOTP-then-passkey order did not — the same end state, allowed or refused purely by ordering."""
    store = await _store()
    try:
        service = AuthService(store, AuthSettings())  # require_mfa on
        identity, token, _ = await _bootstrap_login(service)
        pin_totp_clock(monkeypatch, 1_000_000.0)

        # Order A — passkey first, then TOTP. This is the ordering that used to reach zero factors.
        await _enable_totp(service, identity, token, 1_000_000.0)
        await _stage_passkey(store, identity.user_id, id_hash="pk-a")
        assert await service.delete_webauthn_credential(identity, "pk-a") is True  # TOTP remains
        with pytest.raises(ValueError, match="enroll another factor first"):
            await service.disable_mfa(identity)
        assert (await service.mfa_status(identity)).enabled is True

        # Order B — TOTP first, then the passkey. Refused at the second step, as it always was.
        await _stage_passkey(store, identity.user_id, id_hash="pk-b")
        await service.disable_mfa(identity)  # a passkey remains, so this is permitted
        with pytest.raises(ValueError, match="enroll another factor first"):
            await service.delete_webauthn_credential(identity, "pk-b")

        # Whichever order was taken, exactly one factor survives.
        status = await service.mfa_status(identity)
        assert (status.enabled, status.webauthn_enrolled) == (False, True)
    finally:
        await store.close()


async def test_ad_login_is_mfa_satisfied_by_delegation() -> None:
    store = await _store()
    try:
        principal = AdPrincipal(
            username="jdoe",
            display_name="J Doe",
            email="j@x",
            dn="CN=jdoe,DC=x",
            groups=frozenset({"cn=mf-admins,dc=x"}),
        )

        class _FakeLdap:
            def authenticate(self, username: str, password: str) -> AdPrincipal | None:
                return principal if (username == "jdoe" and password == "pw") else None

            def resolve_principal(self, username: str) -> AdPrincipal | None:
                return principal if username == "jdoe" else None

        settings = AuthSettings(
            require_mfa=True,  # even with MFA required + an admin role, AD MFA is delegated
            ad_enabled=True,
            ad_server="ldaps://x",
            ad_user_search_base="DC=x",
            ad_bind_dn="CN=svc,DC=x",
            ad_bind_password="x",
        )
        service = AuthService(store, settings, ldap=_FakeLdap())  # type: ignore[arg-type]
        await service.initialize()
        await service.set_ad_group_map([("CN=MF-Admins,DC=x", "administrator")], actor="admin")

        out = await service.login("jdoe", "pw", provider=AuthProvider.AD)
        assert out.ok and out.token is not None
        assert out.mfa_required is False  # delegated to the directory, never an engine TOTP
        assert await service.mfa_satisfied(out.token) is True
    finally:
        await store.close()


async def test_recovery_code_consume_is_atomic_under_concurrency() -> None:
    # Security review (TOCTOU): N concurrent verify_mfa calls with the SAME recovery code, across N
    # distinct sessions, must consume it exactly once — only one session may become MFA-satisfied.
    store = await _store()
    try:
        service = AuthService(store, AuthSettings(mfa_recovery_code_count=3))
        identity, token, password = await _bootstrap_login(service)
        enroll = await service.begin_mfa_enrollment(identity)
        codes = await service.confirm_mfa_enrollment(
            identity, fresh_totp(enroll.secret), token=token
        )
        assert codes is not None

        outs = [await service.login("admin", password) for _ in range(5)]
        tokens = [o.token for o in outs]
        assert all(tokens)

        results = await asyncio.gather(*(service.verify_mfa(t, codes[0]) for t in tokens))
        assert sum(1 for r in results if r) == 1  # exactly one caller wins the single-use code
        assert (await service.mfa_status(identity)).recovery_codes_remaining == 2  # consumed once
    finally:
        await store.close()


async def test_mfa_failures_trip_the_per_account_lockout() -> None:
    # API review follow-up: the SECOND factor participates in the same per-account lockout as the
    # password path — sustained wrong codes lock the account (not just the shared IP limiter).
    store = await _store()
    try:
        service = AuthService(store, AuthSettings(mfa_recovery_code_count=2))  # lockout_threshold=5
        identity, token, password = await _bootstrap_login(service)
        enroll = await service.begin_mfa_enrollment(identity)
        await service.confirm_mfa_enrollment(identity, fresh_totp(enroll.secret), token=token)

        out = await service.login("admin", password)
        good = totp.totp(enroll.secret)
        wrong = "000000" if good != "000000" else "111111"
        for _ in range(5):  # exhaust lockout_threshold with wrong codes
            assert await service.verify_mfa(out.token, wrong) is False

        # The account is now locked: even a CORRECT code is refused...
        assert await service.verify_mfa(out.token, fresh_totp(enroll.secret)) is False
        # ...and the lock is shared with the password path (a fresh login is locked too).
        relogin = await service.login("admin", password)
        assert relogin.ok is False and relogin.error == "account locked"
    finally:
        await store.close()
