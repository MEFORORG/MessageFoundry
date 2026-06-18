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

from messagefoundry.auth import totp
from messagefoundry.auth.identity import AuthProvider, Identity
from messagefoundry.auth.ldap import AdPrincipal
from messagefoundry.auth.notifications import MFA_DISABLED, MFA_ENABLED, SecurityEvent
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.store import MessageStore


class _FakeNotifier:
    """Captures the out-of-band security events instead of emailing them."""

    def __init__(self) -> None:
        self.events: list[SecurityEvent] = []

    async def notify(self, event: SecurityEvent) -> None:
        self.events.append(event)


async def _store() -> MessageStore:
    return await MessageStore.open(":memory:")


async def _bootstrap_login(service: AuthService) -> tuple[Identity, str, str]:
    """Bootstrap the admin and log it in; return (identity, token, password) for the MFA flows."""
    boot = await service.initialize()
    assert boot is not None
    out = await service.login("admin", boot.password)
    assert out.ok and out.identity is not None and out.token is not None
    return out.identity, out.token, boot.password


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
            identity, totp.totp(enroll.secret), token=token
        )
        assert recovery is not None and len(recovery) == 10

        status = await service.mfa_status(identity)
        assert status.enabled and status.recovery_codes_remaining == 10 and status.required
        assert any(e.event_type == MFA_ENABLED for e in notifier.events)

        # Confirming the current session marked it MFA-satisfied.
        assert await service.mfa_satisfied(token) is True
    finally:
        await store.close()


async def test_login_requires_second_factor_after_enrollment() -> None:
    store = await _store()
    try:
        service = AuthService(store, AuthSettings(mfa_recovery_code_count=2))
        identity, token, password = await _bootstrap_login(service)
        enroll = await service.begin_mfa_enrollment(identity)
        await service.confirm_mfa_enrollment(identity, totp.totp(enroll.secret), token=token)

        out = await service.login("admin", password)
        assert out.ok and out.mfa_required is True and out.token is not None
        assert await service.mfa_satisfied(out.token) is False  # step-up gate would 403

        code = totp.totp(enroll.secret)
        wrong = "000000" if code != "000000" else "111111"
        assert await service.verify_mfa(out.token, wrong) is False
        assert await service.mfa_satisfied(out.token) is False
        assert await service.verify_mfa(out.token, code) is True
        assert await service.mfa_satisfied(out.token) is True
    finally:
        await store.close()


async def test_require_mfa_forces_admin_even_unenrolled() -> None:
    store = await _store()
    try:
        service = AuthService(store, AuthSettings(require_mfa=True))
        boot = await service.initialize()
        assert boot is not None
        out = await service.login("admin", boot.password)
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
            identity, totp.totp(enroll.secret), token=token
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


async def test_disable_and_admin_reset_clear_mfa() -> None:
    store = await _store()
    try:
        notifier = _FakeNotifier()
        service = AuthService(
            store, AuthSettings(mfa_recovery_code_count=2), security_notifier=notifier
        )
        identity, token, _ = await _bootstrap_login(service)
        enroll = await service.begin_mfa_enrollment(identity)
        await service.confirm_mfa_enrollment(identity, totp.totp(enroll.secret), token=token)

        await service.disable_mfa(identity)
        assert (await service.mfa_status(identity)).enabled is False
        assert any(e.event_type == MFA_DISABLED for e in notifier.events)

        # Re-enroll, then an admin reset clears it again and revokes sessions.
        enroll2 = await service.begin_mfa_enrollment(identity)
        await service.confirm_mfa_enrollment(identity, totp.totp(enroll2.secret), token=token)
        await service.admin_reset_mfa(identity.user_id, actor="admin")
        assert (await service.mfa_status(identity)).enabled is False
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
            identity, totp.totp(enroll.secret), token=token
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
        await service.confirm_mfa_enrollment(identity, totp.totp(enroll.secret), token=token)

        out = await service.login("admin", password)
        good = totp.totp(enroll.secret)
        wrong = "000000" if good != "000000" else "111111"
        for _ in range(5):  # exhaust lockout_threshold with wrong codes
            assert await service.verify_mfa(out.token, wrong) is False

        # The account is now locked: even a CORRECT code is refused...
        assert await service.verify_mfa(out.token, totp.totp(enroll.secret)) is False
        # ...and the lock is shared with the password path (a fresh login is locked too).
        relogin = await service.login("admin", password)
        assert relogin.ok is False and relogin.error == "account locked"
    finally:
        await store.close()
