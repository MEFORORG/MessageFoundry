# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""AuthService-level MFA (TOTP) tests (WP-14, ASVS 6.3.3).

Covers the full second-factor lifecycle — enrollment to confirm to recovery codes, the step-up MFA
gate, the ``require_mfa`` administrator enforcement, recovery-code single-use, and
disable/admin-reset — on a **local and a directory** account alike. The AD/Kerberos delegation
guarantee this file used to pin is retired (BACKLOG #1144): a directory sign-in no longer clears the
engine's MFA gates on an assertion the engine never receives.
"""

from __future__ import annotations

import asyncio
import inspect
import time
from typing import Any

import pytest
from _totp_clock import fresh_totp, pin_totp_clock
from pydantic import BaseModel

from messagefoundry.api import auth_models, models
from messagefoundry.auth import totp
from messagefoundry.auth.identity import Identity
from messagefoundry.auth.ldap import AdPrincipal
from messagefoundry.auth.notifications import (
    ACCOUNT_LOCKED,
    MFA_DISABLED,
    MFA_ENABLED,
    RECOVERY_CODE_USED,
    SecurityEvent,
)
from messagefoundry.auth.service import AuthService, _directory_login_refusal
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.store import MessageStore, WebAuthnCredential
from tests._admin_account import ADMIN_USERNAME, create_admin, login_admin


class _FakeNotifier:
    """Captures the out-of-band security events instead of emailing them."""

    def __init__(self) -> None:
        self.events: list[SecurityEvent] = []

    async def notify(self, event: SecurityEvent) -> None:
        self.events.append(event)


async def _store() -> MessageStore:
    return await MessageStore.open(":memory:")


async def test_enroll_confirm_status_and_recovery_codes() -> None:
    store = await _store()
    try:
        notifier = _FakeNotifier()
        service = AuthService(store, AuthSettings(), security_notifier=notifier)
        identity, token, _ = await login_admin(service)

        enroll = await service.begin_mfa_enrollment(identity)
        assert enroll.secret and enroll.otpauth_uri.startswith("otpauth://totp/")
        assert (await service.mfa_status(identity)).enabled is False  # staged, not active

        enrolled = await service.confirm_mfa_enrollment(
            identity, fresh_totp(enroll.secret), token=token
        )
        assert enrolled.ok and len(enrolled.recovery_codes) == 10
        assert enrolled.token is not None
        token = enrolled.token  # the confirm re-keyed the session (ASVS 7.2.4)

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
        identity, token, password = await login_admin(service)
        enroll = await service.begin_mfa_enrollment(identity)
        # Pin the TOTP clock so the enrollment confirm and the later login verify sit in distinct,
        # provably-adjacent steps: enrollment now consumes the activating step (BACKLOG #1021), so a
        # login code from the SAME step would be refused as a replay, not accepted.
        t0 = 1_000_000.0
        pin_totp_clock(monkeypatch, t0)
        activating = totp.totp(enroll.secret, now=t0)
        await service.confirm_mfa_enrollment(identity, activating, token=token)

        out = await service.login(ADMIN_USERNAME, password)
        assert out.ok and out.mfa_required is True and out.token is not None
        assert await service.mfa_satisfied(out.token) is False  # step-up gate would 403

        wrong = "000000" if activating != "000000" else "111111"
        assert (await service.verify_mfa(out.token, wrong)).ok is False
        assert await service.mfa_satisfied(out.token) is False
        # The successful login verify must sit in a strictly later step than enrollment consumed.
        t1 = t0 + totp.DEFAULT_PERIOD
        pin_totp_clock(monkeypatch, t1)
        verified = await service.verify_mfa(out.token, totp.totp(enroll.secret, now=t1))
        assert verified.ok is True
        # Read the satisfied state on the ROTATED token: the verify re-keyed the session (7.2.4),
        # so out.token no longer resolves and would report False for the wrong reason.
        assert await service.mfa_satisfied(verified.token) is True
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
        identity, _token, password = await login_admin(service)
        enroll = await service.begin_mfa_enrollment(identity)

        t0 = 1_000_000.0
        pin_totp_clock(monkeypatch, t0)
        activating = totp.totp(enroll.secret, now=t0)
        # Confirm succeeds and consumes step S0 (returns the recovery codes, not None).
        assert (await service.confirm_mfa_enrollment(identity, activating, token=_token)).ok

        # A fresh login, then replay the SAME activating code while still pinned to step S0: refused,
        # because enrollment already consumed S0 (the login path advances the high-water mark to S0
        # at enroll, so this replay resolves to a non-greater step).
        out = await service.login(ADMIN_USERNAME, password)
        assert out.token is not None
        assert (await service.verify_mfa(out.token, activating)).ok is False
        assert await service.mfa_satisfied(out.token) is False
    finally:
        await store.close()


async def test_require_mfa_forces_admin_even_unenrolled() -> None:
    store = await _store()
    try:
        service = AuthService(store, AuthSettings(require_mfa=True))
        admin = await create_admin(service)
        out = await service.login(admin.username, admin.password)
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
        identity, token, password = await login_admin(service)
        enroll = await service.begin_mfa_enrollment(identity)
        enrolled = await service.confirm_mfa_enrollment(
            identity, fresh_totp(enroll.secret), token=token
        )
        assert enrolled.ok and len(enrolled.recovery_codes) == 3
        codes = enrolled.recovery_codes

        out = await service.login(ADMIN_USERNAME, password)
        assert out.token is not None
        assert (await service.verify_mfa(out.token, codes[0])).ok is True  # consumes it
        assert (await service.mfa_status(identity)).recovery_codes_remaining == 2

        out2 = await service.login(ADMIN_USERNAME, password)
        assert out2.token is not None
        assert (await service.verify_mfa(out2.token, codes[0])).ok is False  # reuse rejected
        assert (
            await service.verify_mfa(out2.token, codes[1])
        ).ok is True  # a fresh one still works
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
        identity, token, password = await login_admin(service)
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
        out = await service.login(ADMIN_USERNAME, password)
        assert out.token is not None
        assert (await service.verify_mfa(out.token, code)).ok is True  # consumes the step

        out2 = await service.login(ADMIN_USERNAME, password)
        assert out2.token is not None
        # Same code, still inside its window, fresh session → rejected (replay within the window).
        assert (await service.verify_mfa(out2.token, code)).ok is False
    finally:
        await store.close()


async def test_consume_totp_step_is_monotonic() -> None:
    # The store records the highest consumed TOTP time-step (single-use compare-and-set, ASVS 6.5.1):
    # a step <= the last consumed is rejected (replay/older), a strictly greater step is accepted.
    store = await _store()
    try:
        service = AuthService(store, AuthSettings())
        identity, _token, _password = await login_admin(service)
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
        # require_mfa=False is DELIBERATE and new (BACKLOG #1022) — read this before "simplifying" it.
        # This test's subject is that disable and admin-reset CLEAR MFA. The self-service disable
        # below was incidentally exercising a defect: with MFA required, stripping your last second
        # factor is now refused, exactly as delete_webauthn_credential already refused it (ADR 0068
        # decision 5). Turning the requirement off keeps this test on its own subject; the refusal
        # and the still-allowed cases have their own tests below.
        service = AuthService(
            store,
            AuthSettings(mfa_recovery_code_count=2, require_mfa=False),
            security_notifier=notifier,
        )
        identity, token, _ = await login_admin(service)
        enroll = await service.begin_mfa_enrollment(identity)
        t0 = 1_000_000.0
        pin_totp_clock(monkeypatch, t0)
        activating = totp.totp(enroll.secret, now=t0)
        first = await service.confirm_mfa_enrollment(identity, activating, token=token)
        assert first.ok and first.token is not None
        token = first.token  # re-keyed by the confirm; the re-enroll below needs the live token

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
        assert reenrolled.ok
        assert (await service.mfa_status(identity)).enabled is True
        await service.admin_reset_mfa(identity.user_id, actor=ADMIN_USERNAME)
        assert (await service.mfa_status(identity)).enabled is False
    finally:
        await store.close()


async def test_a_directory_account_enrolls_and_satisfies_an_engine_factor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RED when: ``_mfa_required_for`` re-adds a provider exemption, or an enrollment ceremony
    re-adds a non-local refusal.

    This used to be ``test_ad_login_is_mfa_satisfied_by_delegation`` and asserted the reverse
    (BACKLOG #1144): a directory sign-in cleared every engine MFA gate on an assertion the engine
    never received. The two halves are one change — the exemption can only go once the account has a
    factor it can enrol — so this walks the whole path: mint, find the session unsatisfied, enrol,
    verify, find it satisfied.
    """
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
            require_mfa=True,  # MFA required + an admin role: the directory earns no exemption
            ad_enabled=True,
            ad_server="ldaps://x",
            ad_user_search_base="DC=x",
            ad_bind_dn="CN=svc,DC=x",
            ad_bind_password="x",
        )
        service = AuthService(store, settings, ldap=_FakeLdap())  # type: ignore[arg-type]
        await service.initialize()
        await service.set_ad_group_map([("CN=MF-Admins,DC=x", "administrator")], actor="admin")

        # The subject is the engine factor on a DIRECTORY account, not the login mechanism. The
        # simple-bind pathway is retired (BACKLOG #1137), so this mints through _complete_ad_login --
        # the shared tail where mfa_verified is stamped, reached identically by Kerberos and OIDC.
        # False is what the Kerberos leg passes: the ticket asserts nothing the engine can read.
        out = await service._complete_ad_login(principal, None, mfa_verified=False)
        assert out.ok and out.token is not None and out.identity is not None
        assert await service.mfa_satisfied(out.token) is False

        # The ceremony accepts the directory account -- the half that makes the mint above safe.
        t0 = 1_700_000_000.0
        pin_totp_clock(monkeypatch, t0)
        enroll = await service.begin_mfa_enrollment(out.identity)
        confirmed = await service.confirm_mfa_enrollment(
            out.identity, totp.totp(enroll.secret, now=t0), token=out.token
        )
        assert confirmed.recovery_codes  # minted for a directory account like any other
        # Confirming ROTATES the session (ASVS 7.2.4, BACKLOG #1146), so the satisfied state is read
        # on the new token; the one the mint returned has stopped authenticating by design.
        enrolled_token = confirmed.token
        assert isinstance(enrolled_token, str)
        assert await service.mfa_satisfied(enrolled_token) is True

        # A NEW directory session is still unsatisfied: the factor is now enrolled, so it is required
        # under either require_mfa_scope value, and only proving it lifts the gate. The later code
        # must live in a HIGHER step -- enrollment consumed t0's (BACKLOG #1021).
        second = await service._complete_ad_login(principal, None, mfa_verified=False)
        assert second.ok and second.token is not None
        assert await service.mfa_satisfied(second.token) is False
        t1 = t0 + totp.DEFAULT_PERIOD
        pin_totp_clock(monkeypatch, t1)
        verified = await service.verify_mfa(second.token, totp.totp(enroll.secret, now=t1))
        assert verified.ok is True
        assert isinstance(verified.token, str)
        assert await service.mfa_satisfied(verified.token) is True
    finally:
        await store.close()


async def test_recovery_code_consume_is_atomic_under_concurrency() -> None:
    # Security review (TOCTOU): N concurrent verify_mfa calls with the SAME recovery code, across N
    # distinct sessions, must consume it exactly once — only one session may become MFA-satisfied.
    store = await _store()
    try:
        service = AuthService(store, AuthSettings(mfa_recovery_code_count=3))
        identity, token, password = await login_admin(service)
        enroll = await service.begin_mfa_enrollment(identity)
        enrolled = await service.confirm_mfa_enrollment(
            identity, fresh_totp(enroll.secret), token=token
        )
        assert enrolled.ok
        codes = enrolled.recovery_codes

        outs = [await service.login(ADMIN_USERNAME, password) for _ in range(5)]
        tokens = [o.token for o in outs]
        assert all(tokens)

        results = await asyncio.gather(*(service.verify_mfa(t, codes[0]) for t in tokens))
        assert sum(1 for r in results if r.ok) == 1  # one caller wins the single-use code
        assert (await service.mfa_status(identity)).recovery_codes_remaining == 2  # consumed once
    finally:
        await store.close()


async def test_parallel_wrong_credentials_cannot_evade_the_account_lockout() -> None:
    """Security review (TOCTOU): N wrong credentials submitted AT ONCE must still lock the account.

    This is the concurrency proof for the atomic failure counter; ``store.next_lockout_state`` carries
    the race it closes and why the count cannot be computed outside the store's own lock.

    **Both legs feed that one counter, so both are asserted** -- wrong passwords through ``login`` and
    wrong TOTP codes through ``verify_mfa``. Each arm ends on whether the account is LOCKED, never on
    the count alone: a counter that reaches the threshold while ``locked_until`` stays NULL admits the
    very next guess, so the count cannot discriminate a fixed engine from a broken one. The burst is
    deliberately LARGER than the threshold, which is also what pins the one-notice-per-lockout
    contract -- past the threshold every further attempt lands while the lock is live, and only the
    attempt that crossed may notify.
    """
    store = await _store()
    try:
        threshold, burst = 3, 5
        notifier = _FakeNotifier()
        service = AuthService(
            store,
            AuthSettings(
                lockout_threshold=threshold, lockout_minutes=15, mfa_recovery_code_count=3
            ),
            security_notifier=notifier,
        )
        identity, token, password = await login_admin(service)

        # --- arm 1: parallel wrong PASSWORDS ------------------------------------------------------
        outs = await asyncio.gather(*(service.login(ADMIN_USERNAME, "wrong") for _ in range(burst)))
        assert not any(o.ok for o in outs)
        user = await store.get_user(identity.user_id)
        assert user is not None and user.failed_attempts == burst  # not one increment was lost
        refused = await service.login(ADMIN_USERNAME, password)
        assert not refused.ok and refused.error == "account locked"  # the RIGHT password is refused
        assert sum(1 for e in notifier.events if e.event_type == ACCOUNT_LOCKED) == 1

        # Clear the lock the way a lapsed window would, so arm 2 starts from an unlocked account.
        # This is the raw lockout-state write (ADR 0171's offline unlock), not the counting path.
        await store.record_login_failure(identity.user_id, failed_attempts=0, locked_until=None)

        # --- arm 2: parallel wrong TOTP codes -----------------------------------------------------
        enroll = await service.begin_mfa_enrollment(identity)
        enrolled = await service.confirm_mfa_enrollment(
            identity, fresh_totp(enroll.secret), token=token
        )
        assert enrolled.ok
        # A live code with its first digit advanced: guaranteed not to be the current step's code, so
        # this arm cannot flake on the 1-in-a-million chance a hard-coded "000000" is genuinely valid.
        live = fresh_totp(enroll.secret)
        wrong_code = f"{(int(live[0]) + 1) % 10}{live[1:]}"
        tokens = [(await service.login(ADMIN_USERNAME, password)).token for _ in range(burst)]
        assert all(tokens)
        results = await asyncio.gather(*(service.verify_mfa(t, wrong_code) for t in tokens))
        assert not any(r.ok for r in results)
        user = await store.get_user(identity.user_id)
        # ADR 0197: a wrong code on the second step feeds the SECOND-STEP counter, not the sign-in one.
        assert user is not None and user.second_step_failed_attempts == burst
        assert user.failed_attempts == 0
        locked_out = await service.login(ADMIN_USERNAME, password)
        assert not locked_out.ok and locked_out.error == "account locked"
    finally:
        await store.close()


# --- BACKLOG #1139 / ASVS 6.3.7: spending a recovery code -----------------------
#
# Consuming a single-use recovery code permanently DELETES a stored credential. It used to emit only
# the generic ``auth.mfa_verified`` row the caller writes, which carries no detail -- leaving the burn
# byte-indistinguishable from an ordinary TOTP verify, on the event that most often means the holder
# lost their authenticator or somebody else has their codes.


async def test_spending_a_recovery_code_is_audited_distinguishably_and_notified() -> None:
    store = await _store()
    try:
        notifier = _FakeNotifier()
        service = AuthService(
            store, AuthSettings(mfa_recovery_code_count=2), security_notifier=notifier
        )
        identity, token, password = await login_admin(service)
        await store.update_user_profile(
            identity.user_id, display_name=None, email="admin@example.org"
        )
        # THE TWO ADDRESSES MUST DIFFER OR THIS TEST CANNOT SEE THE DEFECT IT EXISTS FOR. ADR 0182
        # splits the directory mirror from the engine-owned notification target; with both set to
        # one string, a spent-code notice sent to `user.email` and one sent to `user.notify_email`
        # are indistinguishable, and the assertion below passes either way.
        await store.set_user_notify_email(identity.user_id, email="admin-notify@example.org")
        enroll = await service.begin_mfa_enrollment(identity)
        enrolled = await service.confirm_mfa_enrollment(
            identity, fresh_totp(enroll.secret), token=token
        )
        assert enrolled.ok and len(enrolled.recovery_codes) == 2
        codes = enrolled.recovery_codes

        out = await service.login(ADMIN_USERNAME, password)
        assert out.token is not None
        assert (await service.verify_mfa(out.token, codes[0], client="10.0.0.7")).ok is True

        spent = [e for e in notifier.events if e.event_type == RECOVERY_CODE_USED]
        assert len(spent) == 1
        ev = spent[0]
        assert ev.username == ADMIN_USERNAME
        assert ev.email == "admin-notify@example.org", (
            "a spent-recovery-code notice must go to the ENGINE-OWNED address, not the "
            "directory mirror -- see ADR 0182 / BACKLOG #1139"
        )
        assert ev.client_ip == "10.0.0.7"
        assert ev.detail["remaining"] == 1

        rows = [
            r
            for r in await store.list_audit(limit=50)
            if r["action"] == "auth.mfa_recovery_code_used"
        ]
        assert len(rows) == 1
        assert rows[0]["actor"] == ADMIN_USERNAME
        assert rows[0]["client"] == "10.0.0.7"
        assert '"remaining": 1' in rows[0]["detail"]
        # The code itself and its hash never reach the audit row or the notice.
        assert codes[0] not in rows[0]["detail"]

        # The mailbox is the arm that can be absent; the pull feed is the arm that cannot. It selects
        # ``auth.%`` rows whose ACTOR is the user, so an action named or attributed any other way
        # would be invisible to exactly the accounts the address gate already excludes.
        feed = await service.security_events_for(ADMIN_USERNAME)
        assert [e for e in feed if e["action"] == "auth.mfa_recovery_code_used"]
    finally:
        await store.close()


async def test_an_ordinary_totp_verify_spends_no_recovery_code_and_announces_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The control the test above needs: without it, a records-on-every-verify implementation would
    # pass and the audit log would still not tell the two mechanisms apart.
    store = await _store()
    try:
        notifier = _FakeNotifier()
        service = AuthService(
            store, AuthSettings(mfa_recovery_code_count=2), security_notifier=notifier
        )
        identity, token, password = await login_admin(service)
        enroll = await service.begin_mfa_enrollment(identity)
        # Enrollment consumes its activating step (BACKLOG #1021), so the login verify has to sit in
        # a strictly later one.
        t0 = 1_700_000_000.0
        pin_totp_clock(monkeypatch, t0)
        assert (
            await service.confirm_mfa_enrollment(
                identity, totp.totp(enroll.secret, now=t0), token=token
            )
        ).ok

        out = await service.login(ADMIN_USERNAME, password)
        assert out.token is not None
        t1 = t0 + totp.DEFAULT_PERIOD
        pin_totp_clock(monkeypatch, t1)
        assert (await service.verify_mfa(out.token, totp.totp(enroll.secret, now=t1))).ok is True

        assert [e for e in notifier.events if e.event_type == RECOVERY_CODE_USED] == []
        assert [
            r
            for r in await store.list_audit(limit=50)
            if r["action"] == "auth.mfa_recovery_code_used"
        ] == []
    finally:
        await store.close()


async def test_the_losing_racer_reports_no_second_consumption() -> None:
    # One code, five concurrent verifies, one winner. Exactly one set of records must exist -- the
    # obvious implementation (emit beside the store call, ignoring its return) writes five.
    store = await _store()
    try:
        notifier = _FakeNotifier()
        service = AuthService(
            store, AuthSettings(mfa_recovery_code_count=3), security_notifier=notifier
        )
        identity, token, password = await login_admin(service)
        enroll = await service.begin_mfa_enrollment(identity)
        enrolled = await service.confirm_mfa_enrollment(
            identity, fresh_totp(enroll.secret), token=token
        )
        assert enrolled.ok
        codes = enrolled.recovery_codes

        outs = [await service.login(ADMIN_USERNAME, password) for _ in range(5)]
        tokens = [o.token for o in outs]
        assert all(tokens)
        results = await asyncio.gather(*(service.verify_mfa(t, codes[0]) for t in tokens))
        assert sum(1 for r in results if r.ok) == 1

        assert len([e for e in notifier.events if e.event_type == RECOVERY_CODE_USED]) == 1
        assert (
            len(
                [
                    r
                    for r in await store.list_audit(limit=50)
                    if r["action"] == "auth.mfa_recovery_code_used"
                ]
            )
            == 1
        )
    finally:
        await store.close()


async def test_mfa_failures_trip_the_per_account_lockout() -> None:
    # API review follow-up: the SECOND factor participates in the same per-account lockout as the
    # password path — sustained wrong codes lock the account (not just the shared IP limiter).
    store = await _store()
    try:
        service = AuthService(store, AuthSettings(mfa_recovery_code_count=2))  # lockout_threshold=5
        identity, token, password = await login_admin(service)
        enroll = await service.begin_mfa_enrollment(identity)
        await service.confirm_mfa_enrollment(identity, fresh_totp(enroll.secret), token=token)

        out = await service.login(ADMIN_USERNAME, password)
        good = totp.totp(enroll.secret)
        wrong = "000000" if good != "000000" else "111111"
        for _ in range(5):  # exhaust lockout_threshold with wrong codes
            assert (await service.verify_mfa(out.token, wrong)).ok is False

        # The account is now locked: even a CORRECT code is refused...
        assert (await service.verify_mfa(out.token, fresh_totp(enroll.secret))).ok is False
        # ...and the lock is shared with the password path (a fresh login is locked too).
        relogin = await service.login(ADMIN_USERNAME, password)
        assert relogin.ok is False and relogin.error == "account locked"
    finally:
        await store.close()


async def _enrol_totp(service: AuthService, monkeypatch: pytest.MonkeyPatch) -> Identity:
    """Create an admin, log in, and activate TOTP — leaving the caller with exactly ONE second factor."""
    identity, token, _ = await login_admin(service)
    enroll = await service.begin_mfa_enrollment(identity)
    t0 = 1_000_000.0
    pin_totp_clock(monkeypatch, t0)
    await service.confirm_mfa_enrollment(identity, totp.totp(enroll.secret, now=t0), token=token)
    assert (await service.mfa_status(identity)).enabled is True
    return identity


async def test_disable_mfa_REFUSES_stripping_the_last_factor_when_mfa_is_required(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BACKLOG #1022: the asymmetry with delete_webauthn_credential.

    Both are self-service, both sit behind the same step-up gate, and both can take an account to
    ZERO second factors. delete_webauthn_credential asked whether MFA was still required and refused;
    this one never asked. require_mfa defaults to True, so this is the DEFAULT posture, not an exotic
    configuration.
    """
    store = await _store()
    try:
        service = AuthService(store, AuthSettings())  # require_mfa defaults True
        identity = await _enrol_totp(service, monkeypatch)
        with pytest.raises(ValueError) as exc:
            await service.disable_mfa(identity)
        assert "last second factor" in str(exc.value)
        # AND IT MUST NOT HAVE DISABLED ANYWAY. A refusal that already mutated the store is worse
        # than no refusal, because the error says the state was preserved when it was not.
        assert (await service.mfa_status(identity)).enabled is True
    finally:
        await store.close()


async def test_disable_mfa_is_ALLOWED_when_mfa_is_not_required(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # POSITIVE CONTROL for the refusal above. Without it, a disable_mfa that raised unconditionally
    # would satisfy that test while breaking every account that is permitted to turn MFA off.
    store = await _store()
    try:
        service = AuthService(store, AuthSettings(require_mfa=False))
        identity = await _enrol_totp(service, monkeypatch)
        await service.disable_mfa(identity)
        assert (await service.mfa_status(identity)).enabled is False
    finally:
        await store.close()


async def test_the_ADMIN_recovery_path_is_not_narrowed_by_the_guard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The guard above must not cost the escape hatch, and this is what proves it did not.

    admin_reset_mfa is "the always-available recovery for a locked-out passkey user" — a DIFFERENT
    method from disable_mfa, deliberately unguarded. Under exactly the conditions that make the
    self-service path refuse (MFA required, TOTP the only factor), the admin path must still clear.
    """
    store = await _store()
    try:
        service = AuthService(store, AuthSettings())  # require_mfa defaults True
        identity = await _enrol_totp(service, monkeypatch)
        await service.admin_reset_mfa(identity.user_id, actor="another-admin")
        assert (await service.mfa_status(identity)).enabled is False
    finally:
        await store.close()


# --- BACKLOG #1638: the failure counter clears at FULL authentication, not at the password step ----


async def test_a_password_only_login_does_not_reset_the_second_factor_failure_counter() -> None:
    """THE REGRESSION THE LEDGER ROW NAMES: a login between runs of wrong codes used to wipe them.

    ``record_login_success`` zeroes ``failed_attempts`` and NULLs ``locked_until`` in one UPDATE, and
    ``_login_local`` called it BEFORE the second factor was proven. So a holder of the first factor
    could guess the second indefinitely: four wrong codes, log in again, four more, and the counter
    never reached the threshold. Measured at engine ``2ffcf3347``: three such cycles never locked.

    The middle assertion is the one that fails without the fix. The outer two bound the behaviour
    rather than establishing it -- they would pass on an implementation that merely moved the call --
    so all three are kept: the counter must accumulate ACROSS a re-login, and the threshold must
    then still be reached.
    """
    store = await _store()
    try:
        # lockout_threshold defaults to 5. The recovery-code count is trimmed because every WRONG
        # code falls through to the argon2id recovery path, so it sets this test's runtime.
        service = AuthService(store, AuthSettings(mfa_recovery_code_count=2))
        identity, token, password = await login_admin(service)
        enroll = await service.begin_mfa_enrollment(identity)
        await service.confirm_mfa_enrollment(identity, fresh_totp(enroll.secret), token=token)

        good = totp.totp(enroll.secret)
        wrong = "000000" if good != "000000" else "111111"

        out = await service.login(ADMIN_USERNAME, password)
        assert out.ok and out.mfa_required, "the password step was treated as full authentication"
        for _ in range(4):  # one short of the threshold
            assert (await service.verify_mfa(out.token, wrong)).ok is False
        user = await store.get_user(identity.user_id)
        assert user is not None and user.second_step_failed_attempts == 4

        # The re-login. It must NOT clear what the wrong codes accumulated.
        again = await service.login(ADMIN_USERNAME, password)
        assert again.ok and again.mfa_required
        user = await store.get_user(identity.user_id)
        assert user is not None, "the account vanished"
        assert user.second_step_failed_attempts == 4, (
            "the password step reset the second factor's failure counter, so a first-factor holder "
            "can guess the second factor without bound"
        )

        # ...so the very next wrong code is the fifth, and it locks.
        assert (await service.verify_mfa(again.token, wrong)).ok is False
        user = await store.get_user(identity.user_id)
        assert user is not None and user.second_step_locked_until is not None, (
            "the threshold was never reached"
        )
        locked = await service.login(ADMIN_USERNAME, password)
        assert locked.ok is False and locked.error == "account locked"
    finally:
        await store.close()


async def test_completing_the_second_factor_still_clears_the_counter() -> None:
    """The must-not-fire arm. Moving the clear must not DELETE it: a user who proves both factors
    walks away with a clean row, or the next run of typos starts partway to a lockout it did not earn.

    **The passing factor is a RECOVERY CODE, not a live TOTP, and that is not incidental.** A TOTP
    code is single-use within its step (ASVS 6.5.1) and ``confirm_mfa_enrollment`` has just spent the
    current one, so a positive verify here needs a LATER step. The wrong codes in between fall
    through to the argon2id recovery-code path and cost real seconds, which makes the wait for that
    step a race rather than a delay. A recovery code has no step to consume, so this arm is
    deterministic; the TOTP path's own single-use property is pinned by its own test.
    """
    store = await _store()
    try:
        service = AuthService(store, AuthSettings(mfa_recovery_code_count=3))
        identity, token, password = await login_admin(service)
        enroll = await service.begin_mfa_enrollment(identity)
        enrolled = await service.confirm_mfa_enrollment(
            identity, fresh_totp(enroll.secret), token=token
        )
        assert enrolled.ok and len(enrolled.recovery_codes) == 3

        wrong = "000000" if totp.totp(enroll.secret) != "000000" else "111111"
        out = await service.login(ADMIN_USERNAME, password)
        for _ in range(3):
            assert (await service.verify_mfa(out.token, wrong)).ok is False
        user = await store.get_user(identity.user_id)
        assert user is not None and user.second_step_failed_attempts == 3

        assert (await service.verify_mfa(out.token, enrolled.recovery_codes[0])).ok is True
        user = await store.get_user(identity.user_id)
        assert user is not None
        assert user.second_step_failed_attempts == 0, (
            "the completed second factor left the counter standing"
        )
        assert user.second_step_locked_until is None and user.locked_until is None
    finally:
        await store.close()


async def test_an_account_owing_no_second_factor_still_clears_at_the_password_step() -> None:
    """The other must-not-fire arm: for an account with nothing left to prove, the password step IS
    full authentication, so the clear must still happen there. Without it the counter would only
    ever shed by waiting the lockout window out."""
    store = await _store()
    try:
        service = AuthService(store, AuthSettings(require_mfa=False))
        admin = await create_admin(service)
        for _ in range(3):
            assert (await service.login(ADMIN_USERNAME, "wrong-passphrase-entirely")).ok is False
        row = await store.get_user_by_username(ADMIN_USERNAME)
        assert row is not None and row.failed_attempts == 3

        out = await service.login(ADMIN_USERNAME, admin.password)
        assert out.ok and not out.mfa_required, "the account unexpectedly owes a second factor"
        row = await store.get_user_by_username(ADMIN_USERNAME)
        assert row is not None and row.failed_attempts == 0, (
            "a fully authenticated password-only login left the failure counter standing"
        )
    finally:
        await store.close()


async def test_the_totp_secret_is_returned_once_and_never_again() -> None:
    """ASVS 11.1.1's two-entity bound on a shared secret, the half the engine controls (BACKLOG #1162).

    The TOTP secret is the only shared secret the engine mints and uses as key material. By design
    it has two holders: the
    engine's store and the user's authenticator. The engine cannot see the authenticator side, so
    ``docs/ASVS-L2-PHASE0-CHANGES.md`` states that half as a deployment precondition. What the engine
    CAN promise is that it never hands the secret out a second time, which is what this pins:

    * staging again mints a FRESH secret rather than re-displaying the staged one;
    * once MFA is on, a new enrolment is refused, so the active secret is never returned again;
    * the status read carries no copy of it; and
    * the enrolment response is the only JSON API model with a field NAMED like a secret, so a new
      JSON model with such a field fails here. A field under another name does not; the
      enrolment response already carries the secret a second time, inside ``otpauth_uri``. An unrelated ``*secret*`` field fails too, on purpose: it
      must be looked at.

    What this does NOT cover: HTML pages (the web console renders the staged secret on its own
    enrolment page) and a route that returns a bare dict. The doc names both enrolment responses.

    Mutation: let ``begin_mfa_enrollment`` return the stored secret when MFA is already enabled, or
    add a ``secret`` field to ``MfaStatusResponse``. Red: the matching assertion below.
    """
    store = await _store()
    try:
        service = AuthService(store, AuthSettings())
        identity, token, _ = await login_admin(service)

        staged = await service.begin_mfa_enrollment(identity)
        restaged = await service.begin_mfa_enrollment(identity)
        assert restaged.secret != staged.secret, "re-staging re-displayed the staged secret"

        confirmed = await service.confirm_mfa_enrollment(
            identity, fresh_totp(restaged.secret), token=token
        )
        assert confirmed.ok

        with pytest.raises(ValueError, match="already enabled"):
            await service.begin_mfa_enrollment(identity)

        status = await service.mfa_status(identity)
        assert restaged.secret not in repr(status)
    finally:
        await store.close()

    carriers = sorted(
        f"{module.__name__}.{name}"
        for module in (auth_models, models)
        for name, obj in vars(module).items()
        if inspect.isclass(obj)
        and issubclass(obj, BaseModel)
        and obj.__module__ == module.__name__
        and any("secret" in field for field in obj.model_fields)
    )
    assert carriers == ["messagefoundry.api.auth_models.MfaEnrollResponse"], (
        f"API models with a field named like a secret: {carriers}. The TOTP secret may leave the "
        f"engine only in the enrolment response; a second carrier breaks the two-holder bound."
    )


# --- ADR 0197 (BACKLOG #1131, ASVS 6.1.1): two counters, and the combined sign-in -----------------
#
# The sign-in counter counts wrong passwords from a caller who has proved nothing; anyone who knows the
# username can feed it. The second-step counter counts failures from a caller who has proved ONE
# factor. A sign-in that carries the password AND a TOTP code passes the sign-in lock, but only on a
# local account with TOTP enrolled, so a caller who knows only the username can no longer keep that
# owner out through the lock. Every arm that checks a lock also reads the row back, because a lock
# test that only asserts a refusal passes against a store that never counted.

_LOCK_SETTINGS: dict[str, int] = {
    "lockout_threshold": 3,
    "lockout_minutes": 15,
    "mfa_recovery_code_count": 1,
}


class _Steps:
    """Pins the TOTP clock and hands out a code from a fresh step on every call.

    ``confirm_mfa_enrollment`` spends its step, and ``consume_totp_step`` refuses a non-greater step,
    so each code a test means to be ACCEPTED must come from a strictly later step."""

    def __init__(
        self, monkeypatch: pytest.MonkeyPatch, secret: str, start: float = 2_000_000.0
    ) -> None:
        self._monkeypatch = monkeypatch
        self._secret = secret
        self.now = start

    def next_code(self) -> str:
        self.now += totp.DEFAULT_PERIOD
        pin_totp_clock(self._monkeypatch, self.now)
        return totp.totp(self._secret, now=self.now)

    def wrong_code(self) -> str:
        """A code that is not valid at the current pinned step."""
        live = totp.totp(self._secret, now=self.now)
        return f"{(int(live[0]) + 1) % 10}{live[1:]}"

    @property
    def step(self) -> int:
        return int(self.now // totp.DEFAULT_PERIOD)


async def _totp_admin(
    service: AuthService, monkeypatch: pytest.MonkeyPatch
) -> tuple[Identity, str, _Steps]:
    """An Administrator with TOTP active. Returns ``(identity, password, steps)``."""
    identity, token, password = await login_admin(service)
    enroll = await service.begin_mfa_enrollment(identity)
    steps = _Steps(monkeypatch, enroll.secret)
    assert (await service.confirm_mfa_enrollment(identity, steps.next_code(), token=token)).ok
    return identity, password, steps


async def _set_sign_in_lock(store: MessageStore, user_id: str) -> None:
    """A live sign-in lock, a quarter hour out, written through the raw lockout-state write."""
    await store.record_login_failure(user_id, failed_attempts=3, locked_until=time.time() + 900)


async def _set_second_step_lock(store: MessageStore, user_id: str) -> None:
    """A live second-step lock, set through the real counting path."""
    for _ in range(_LOCK_SETTINGS["lockout_threshold"]):
        await store.increment_login_failure(
            user_id,
            counter="second_step",
            threshold=_LOCK_SETTINGS["lockout_threshold"],
            lockout_seconds=900.0,
            max_lockout_seconds=86_400.0,
            now=time.time(),
        )


def _spy_verified_hashes(service: AuthService, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record every stored hash the service hands to argon2, so a test can say "never verified"."""
    seen: list[str] = []
    real = service._argon2

    async def spy(fn: Any, *args: Any) -> Any:
        if args and isinstance(args[0], str) and args[0].startswith("$argon2"):
            seen.append(args[0])
        return await real(fn, *args)

    monkeypatch.setattr(service, "_argon2", spy)
    return seen


def _columns(user: Any) -> tuple[Any, ...]:
    return (
        user.failed_attempts,
        user.locked_until,
        user.lock_cycles,
        user.second_step_failed_attempts,
        user.second_step_locked_until,
        user.second_step_lock_cycles,
    )


async def test_AC1_a_combined_sign_in_passes_a_live_sign_in_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-1 and AC-8: the owner who holds both factors gets in while a username-only caller holds
    the sign-in lock, and the full authentication zeroes both counters and both cycle counts."""
    store = await _store()
    try:
        service = AuthService(store, AuthSettings(**_LOCK_SETTINGS))
        identity, password, steps = await _totp_admin(service, monkeypatch)
        await _set_sign_in_lock(store, identity.user_id)

        out = await service.login(ADMIN_USERNAME, password, totp_code=steps.next_code())
        assert out.ok and out.token is not None, "the combined sign-in was refused under the lock"
        assert out.mfa_required is False
        assert await service.mfa_satisfied(out.token) is True
        session = await store.get_session(hash_token(out.token))
        assert session is not None and session.reauth_at is not None, "no step-up window seeded"
        user = await store.get_user(identity.user_id)
        assert user is not None and _columns(user) == (0, None, 0, 0, None, 0)
    finally:
        await store.close()


async def test_AC2_a_password_only_sign_in_is_refused_under_the_sign_in_lock_before_any_verify(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = await _store()
    try:
        service = AuthService(store, AuthSettings(**_LOCK_SETTINGS))
        identity, password, _steps = await _totp_admin(service, monkeypatch)
        await _set_sign_in_lock(store, identity.user_id)
        before = await store.get_user(identity.user_id)
        assert before is not None and before.password_hash is not None
        seen = _spy_verified_hashes(service, monkeypatch)

        out = await service.login(ADMIN_USERNAME, password)
        assert not out.ok
        assert before.password_hash not in seen, "the stored password was verified under the lock"
        after = await store.get_user(identity.user_id)
        assert after is not None and _columns(after) == _columns(before)
    finally:
        await store.close()


async def test_AC2a_a_code_does_not_pass_the_lock_on_an_account_without_active_totp(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-2a: a not-yet-enrolled arm and a passkey-only arm, each with the RIGHT password.

    Without the enrolled-TOTP condition any six digits would turn a locked sign-in on these accounts
    into a live password check, bounded only by the sign-in rate limiter."""
    store = await _store()
    try:
        service = AuthService(store, AuthSettings(**_LOCK_SETTINGS))
        identity, _token, password = await login_admin(service)
        user = await store.get_user(identity.user_id)
        assert user is not None and user.password_hash is not None

        # --- not yet enrolled: a secret is staged, so the code is even VALID for it, but inactive --
        enroll = await service.begin_mfa_enrollment(identity)
        await _set_sign_in_lock(store, identity.user_id)
        before = await store.get_user(identity.user_id)
        assert before is not None
        seen = _spy_verified_hashes(service, monkeypatch)
        staged = _Steps(monkeypatch, enroll.secret)
        out = await service.login(ADMIN_USERNAME, password, totp_code=staged.next_code())
        assert not out.ok, "a staged, unconfirmed secret passed the sign-in lock"
        assert user.password_hash not in seen
        after = await store.get_user(identity.user_id)
        assert after is not None and _columns(after) == _columns(before)

        # --- passkey-only: a factor is enrolled, but it is not TOTP -------------------------------
        await store.set_totp_secret(identity.user_id, secret=None)
        await store.add_webauthn_credential(
            WebAuthnCredential(
                credential_id_hash="ac2a-passkey-hash",
                credential_id="ac2a-passkey-id",
                user_id=identity.user_id,
                rp_id="t",
                public_key="cose-public-key-b64url",
                sign_count=0,
                transports=None,
                device_type="multi_device",
                backed_up=True,
                label="key",
                aaguid=None,
                created_at=1000.0,
            )
        )
        out = await service.login(ADMIN_USERNAME, password, totp_code="123456")
        assert not out.ok, "six digits passed the sign-in lock on a passkey-only account"
        assert user.password_hash not in seen
        after = await store.get_user(identity.user_id)
        assert after is not None and _columns(after) == _columns(before)
    finally:
        await store.close()


async def test_AC3_one_factor_right_counts_on_the_second_step_counter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-3, both arms. When the CODE is the factor that verified, its step is consumed."""
    store = await _store()
    try:
        service = AuthService(store, AuthSettings(**_LOCK_SETTINGS))
        identity, password, steps = await _totp_admin(service, monkeypatch)

        # --- right password, wrong code ---------------------------------------------------------
        steps.next_code()
        out = await service.login(ADMIN_USERNAME, password, totp_code=steps.wrong_code())
        assert not out.ok
        user = await store.get_user(identity.user_id)
        assert user is not None and _columns(user) == (0, None, 0, 1, None, 0)

        # --- wrong password, right code: counted on the second step, and the step is SPENT --------
        code = steps.next_code()
        out = await service.login(ADMIN_USERNAME, "not-the-passphrase", totp_code=code)
        assert not out.ok
        user = await store.get_user(identity.user_id)
        assert user is not None and _columns(user) == (0, None, 0, 2, None, 0)
        assert await store.consume_totp_step(identity.user_id, steps.step) is False, (
            "the verified code's step was left unspent, so it can be replayed"
        )
    finally:
        await store.close()


async def test_AC4_neither_factor_right_leaves_the_second_step_counter_alone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-4, with the arm that sends ONE valid code beside many wrong passwords: only the first
    request counts the code as right, because the first spends the step."""
    store = await _store()
    try:
        service = AuthService(store, AuthSettings(**{**_LOCK_SETTINGS, "lockout_threshold": 10}))
        identity, _password, steps = await _totp_admin(service, monkeypatch)

        steps.next_code()
        out = await service.login(ADMIN_USERNAME, "wrong-one", totp_code=steps.wrong_code())
        assert not out.ok
        user = await store.get_user(identity.user_id)
        assert user is not None and _columns(user) == (1, None, 0, 0, None, 0)

        code = steps.next_code()
        for i in range(4):
            assert not (await service.login(ADMIN_USERNAME, f"wrong-{i}", totp_code=code)).ok
        user = await store.get_user(identity.user_id)
        # The first of the four spent the step and counted on the second step; the other three
        # presented a spent code, so they were wrong-and-wrong and counted on the sign-in counter.
        assert user is not None and _columns(user) == (4, None, 0, 1, None, 0)
    finally:
        await store.close()


async def test_AC5_the_second_step_lock_refuses_every_leg(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-5: password-only, combined, the second step on an existing session, and the directory
    sign-ins, each with the RIGHT credentials."""
    store = await _store()
    try:
        service = AuthService(store, AuthSettings(**_LOCK_SETTINGS))
        identity, password, steps = await _totp_admin(service, monkeypatch)
        pending = await service.login(ADMIN_USERNAME, password)
        assert pending.ok and pending.mfa_required and pending.token is not None
        await _set_second_step_lock(store, identity.user_id)
        before = await store.get_user(identity.user_id)
        assert before is not None and before.second_step_locked_until is not None

        assert not (await service.login(ADMIN_USERNAME, password)).ok
        assert not (await service.login(ADMIN_USERNAME, password, totp_code=steps.next_code())).ok
        assert not (await service.verify_mfa(pending.token, steps.next_code())).ok
        assert _directory_login_refusal(before, time.time()) == "locked"
        after = await store.get_user(identity.user_id)
        assert after is not None
        assert after.second_step_locked_until == before.second_step_locked_until
        assert after.second_step_lock_cycles == before.second_step_lock_cycles
    finally:
        await store.close()


async def test_verify_mfa_is_not_refused_by_the_sign_in_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ADR 0197 Decision 2: the second step on an existing session is refused by the second-step
    lock only. The sign-in lock is the one a caller with no factor can set."""
    store = await _store()
    try:
        service = AuthService(store, AuthSettings(**_LOCK_SETTINGS))
        identity, password, steps = await _totp_admin(service, monkeypatch)
        pending = await service.login(ADMIN_USERNAME, password)
        assert pending.token is not None
        await _set_sign_in_lock(store, identity.user_id)
        assert (await service.verify_mfa(pending.token, steps.next_code())).ok
    finally:
        await store.close()


async def test_AC10b_the_login_time_rehash_leaves_every_lockout_column_alone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-10b. The rehash used to call ``set_password``, which clears the lockout columns, so a
    password holder could shed a run of second-step failures once per argon2 parameter change."""
    store = await _store()
    try:
        service = AuthService(store, AuthSettings(**_LOCK_SETTINGS))
        identity, password, _steps = await _totp_admin(service, monkeypatch)
        await store.record_login_failure(identity.user_id, failed_attempts=2, locked_until=None)
        before = await store.get_user(identity.user_id)
        assert before is not None

        monkeypatch.setattr("messagefoundry.auth.service.needs_rehash", lambda _h: True)
        out = await service.login(ADMIN_USERNAME, password)
        assert out.ok and out.mfa_required, "the fixture owes a factor, so nothing should clear"
        after = await store.get_user(identity.user_id)
        assert after is not None and after.password_hash != before.password_hash, "no rehash ran"
        assert after.failed_attempts == 2, "the rehash cleared the failure count"
        assert _columns(after) == _columns(before)
    finally:
        await store.close()


async def _refused_outcomes(
    service: AuthService, store: MessageStore, identity: Identity, password: str, steps: _Steps
) -> list[tuple[str, str, str, str | None, Any]]:
    """Every refused combined-sign-in shape, as ``(label, username, password, code, setup)``.

    ``setup`` runs before the attempt and returns the code to send when the shape needs a fresh one.
    The lock arms come last because a live lock changes what every later attempt meets."""

    async def none() -> None:
        return None

    async def lock_sign_in() -> None:
        await _set_sign_in_lock(store, identity.user_id)

    async def lock_second_step() -> None:
        await _set_second_step_lock(store, identity.user_id)

    return [
        ("unknown user", "nobody-by-this-name", password, "wrong", none),
        ("wrong password, no code", ADMIN_USERNAME, "wrong", None, none),
        ("wrong password, wrong code", ADMIN_USERNAME, "wrong", "wrong", none),
        ("right password, wrong code", ADMIN_USERNAME, password, "wrong", none),
        ("wrong password, right code", ADMIN_USERNAME, "wrong", "right", none),
        ("sign-in lock live, both wrong", ADMIN_USERNAME, "wrong", "wrong", lock_sign_in),
        ("sign-in lock live, right code", ADMIN_USERNAME, "wrong", "right", none),
        ("second-step lock live, both right", ADMIN_USERNAME, password, "right", lock_second_step),
    ]


async def test_AC6_every_refused_combined_outcome_is_padded_into_the_first_slot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-6's service half, the deterministic arm. Each refused outcome must reach the failure pad
    exactly once and be held to the SAME deadline, the pad's first slot, so every one answers at
    the same instant.

    The pad's sleep is replaced, so this reads the slot each attempt was assigned instead of paying
    the wall clock; the arm below pays it. A failure branch that skipped the pad would record no
    slot, which the count catches. The budget is widened for this arm only, so a loaded test host
    cannot push one branch's argon2 into a later slot and read as a defect: what this arm pins is
    that every branch is padded, not how fast this machine is. The real budget is the wall-clock
    arm's."""
    from messagefoundry.auth import service as service_module

    monkeypatch.setattr(service_module, "_FAILURE_BUDGET_SECONDS", 5.0)

    store = await _store()
    try:
        service = AuthService(store, AuthSettings(**{**_LOCK_SETTINGS, "lockout_threshold": 50}))
        identity, password, steps = await _totp_admin(service, monkeypatch)
        slots: list[int] = []
        real_deadline = service_module._failure_deadline

        def spy(started: float, now: float, budget: float | None = None) -> float:
            deadline = real_deadline(started, now, budget)
            slots.append(round((deadline - started) / 5.0))
            return deadline

        async def no_sleep(_deadline: float) -> None:
            return None

        monkeypatch.setattr(service_module, "_failure_deadline", spy)
        monkeypatch.setattr(service_module, "_sleep_until", no_sleep)
        shapes = await _refused_outcomes(service, store, identity, password, steps)
        for label, username, pw, code, setup in shapes:
            await setup()
            sent = steps.next_code() if code == "right" else code
            if code == "wrong":
                steps.next_code()
                sent = steps.wrong_code()
            assert not (await service.login(username, pw, totp_code=sent)).ok, label
        assert slots == [1] * len(shapes), slots
    finally:
        await store.close()


async def test_AC6_refused_combined_sign_ins_take_the_same_wall_clock_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-6's timing arm, on the real clock and the real budget, three rounds of every refused
    outcome.

    Two properties, of different strength. **No refused outcome ever answers before the budget.**
    That is the hard one: an early answer is a branch that escaped the pad, told apart by timing
    alone, and ``_failure_deadline`` rounds up, so load cannot cause it. **Each outcome's MEDIAN
    answer lies in the first slot**, ``[budget, 2 x budget)``: a branch whose own work is
    systematically longer would sit in a later slot every round. One round spilling into the next
    slot on a loaded host is the documented overrun the pad logs, so the median, not every sample,
    carries that half."""
    from messagefoundry.auth import service as service_module

    budget = service_module._FAILURE_BUDGET_SECONDS
    store = await _store()
    try:
        service = AuthService(store, AuthSettings(**{**_LOCK_SETTINGS, "lockout_threshold": 500}))
        identity, password, steps = await _totp_admin(service, monkeypatch)
        timings: dict[str, list[float]] = {}
        for _round in range(3):
            await store.clear_lockout(identity.user_id)
            shapes = await _refused_outcomes(service, store, identity, password, steps)
            for label, username, pw, code, setup in shapes:
                await setup()
                sent = steps.next_code() if code == "right" else code
                if code == "wrong":
                    steps.next_code()
                    sent = steps.wrong_code()
                started = time.monotonic()
                ok = (await service.login(username, pw, totp_code=sent)).ok
                timings.setdefault(label, []).append(time.monotonic() - started)
                assert not ok, label
        rounded = {label: [round(t, 3) for t in ts] for label, ts in timings.items()}
        early = {label: ts for label, ts in rounded.items() if min(ts) < budget}
        assert not early, f"refused outcomes answered BEFORE the pad's deadline: {early}"
        late = {label: ts for label, ts in rounded.items() if not sorted(ts)[1] < 2 * budget}
        assert not late, f"refused outcomes whose median left the first padded slot: {late}"
    finally:
        await store.close()


async def test_AC11_parallel_combined_sign_ins_each_count_on_the_second_step(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-11's combined arm: a burst of right-password, wrong-code sign-ins, all at once, must count
    every one on the second-step counter and lock it, with exactly one lock notice."""
    store = await _store()
    try:
        threshold, burst = 3, 5
        notifier = _FakeNotifier()
        service = AuthService(
            store,
            AuthSettings(**{**_LOCK_SETTINGS, "lockout_threshold": threshold}),
            security_notifier=notifier,
        )
        identity, password, steps = await _totp_admin(service, monkeypatch)
        await store.set_user_notify_email(identity.user_id, email="owner@example.org")
        steps.next_code()
        wrong = steps.wrong_code()
        outs = await asyncio.gather(
            *(service.login(ADMIN_USERNAME, password, totp_code=wrong) for _ in range(burst))
        )
        assert not any(o.ok for o in outs)
        user = await store.get_user(identity.user_id)
        assert user is not None
        assert user.second_step_failed_attempts == burst, "an increment was lost to the race"
        assert user.second_step_locked_until is not None and user.second_step_lock_cycles == 1
        assert (user.failed_attempts, user.locked_until) == (0, None)
        assert sum(1 for e in notifier.events if e.event_type == ACCOUNT_LOCKED) == 1
    finally:
        await store.close()


# --- AC-10: the ACCOUNT_LOCKED notice is throttled by TIME, per lock kind --------------------------


class _Clock:
    """A settable wall clock, patched over ``time.time`` for the service and the store alike."""

    def __init__(self, start: float) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now


async def _notice_harness(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[MessageStore, AuthService, _FakeNotifier, _Clock, str]:
    from messagefoundry.auth import service as service_module

    clock = _Clock(1_900_000_000.0)
    monkeypatch.setattr(time, "time", clock)

    async def no_sleep(_deadline: float) -> None:
        return None

    monkeypatch.setattr(service_module, "_sleep_until", no_sleep)
    store = await _store()
    notifier = _FakeNotifier()
    # threshold 1: every wrong password sets a lock, so one request is one cycle. No TOTP, so the
    # sign-in lock keeps its fixed 15 minutes and a lock every 15 minutes is a steady campaign.
    service = AuthService(
        store,
        AuthSettings(lockout_threshold=1, lockout_minutes=15, require_mfa=False),
        security_notifier=notifier,
    )
    admin = await create_admin(service)
    await store.set_user_notify_email(admin.user_id, email="owner@example.org")
    return store, service, notifier, clock, admin.user_id


def _lock_notices(notifier: _FakeNotifier) -> list[SecurityEvent]:
    return [e for e in notifier.events if e.event_type == ACCOUNT_LOCKED]


async def test_AC10_a_lock_every_15_minutes_for_25_hours_mails_exactly_twice(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, service, notifier, clock, user_id = await _notice_harness(monkeypatch)
    try:
        for _ in range(100):  # 100 x 15 minutes = 25 hours
            assert not (await service.login(ADMIN_USERNAME, "wrong-passphrase")).ok
            clock.now += 15 * 60 + 1
        user = await store.get_user(user_id)
        assert user is not None and user.lock_cycles == 100
        rows = await store.list_audit(actor=ADMIN_USERNAME, action="auth.account_locked", limit=500)
        assert len(rows) == 100, "the auth.account_locked row must still be written every cycle"
        notices = _lock_notices(notifier)
        assert len(notices) == 2, f"expected two mails in 25 hours, got {len(notices)}"
        assert notices[0].detail["lock"] == "sign_in" and notices[0].detail["cycle"] == 1
        assert notices[1].detail["cycle"] > 90
    finally:
        await store.close()


async def test_AC10_an_unlock_then_a_new_lock_at_a_high_cycle_count_still_mails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A cycle-count throttle would go quiet here: ``admin-unlock`` keeps the cycle count, so a new
    campaign starts at a high one. The time throttle mails the first lock after a quiet day."""
    store, service, notifier, clock, user_id = await _notice_harness(monkeypatch)
    try:
        for _ in range(40):
            assert not (await service.login(ADMIN_USERNAME, "wrong-passphrase")).ok
            clock.now += 15 * 60 + 1
        assert len(_lock_notices(notifier)) == 1
        await store.clear_lockout(user_id)
        clock.now += 86_400 + 1
        assert not (await service.login(ADMIN_USERNAME, "wrong-passphrase")).ok
        notices = _lock_notices(notifier)
        assert len(notices) == 2, "the first lock after a quiet day sent no mail"
        assert notices[-1].detail["cycle"] == 41
    finally:
        await store.close()


async def test_AC10_the_two_lock_kinds_are_throttled_separately(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, service, notifier, clock, user_id = await _notice_harness(monkeypatch)
    try:
        assert not (await service.login(ADMIN_USERNAME, "wrong-passphrase")).ok
        user = await store.get_user(user_id)
        assert user is not None
        # A second-step lock minutes later is a different lock kind, so it mails too.
        clock.now += 60
        result = await store.increment_login_failure(
            user_id,
            counter="second_step",
            threshold=1,
            lockout_seconds=900.0,
            max_lockout_seconds=86_400.0,
            now=clock.now,
        )
        assert result.just_locked
        await service._record_lock(user, "second_step", result, client=None, factor="password")
        kinds = [e.detail["lock"] for e in _lock_notices(notifier)]
        assert kinds == ["sign_in", "second_step"]
    finally:
        await store.close()


async def test_a_non_ascii_digit_code_is_a_padded_wrong_code_not_a_crash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``str.isdigit`` is true for Arabic-Indic and fullwidth digits, and ``hmac.compare_digest``
    raises on non-ASCII text. The combined sign-in used to let that ``TypeError`` escape the failure
    pad as an unpadded 500, which named the account as TOTP-enrolled and, chained with the second-step
    lock, answered whether a password was right. Such a code must be an ordinary wrong code: refused,
    padded, and counted as the routing table says."""
    from messagefoundry.auth import service as service_module

    store = await _store()
    try:
        service = AuthService(store, AuthSettings(**{**_LOCK_SETTINGS, "lockout_threshold": 50}))
        identity, password, steps = await _totp_admin(service, monkeypatch)
        padded: list[float] = []

        async def record(deadline: float) -> None:
            padded.append(deadline)

        monkeypatch.setattr(service_module, "_sleep_until", record)
        steps.next_code()
        arabic_indic = "\u0660" * 6
        fullwidth = "\uff11" * 6
        for code in (arabic_indic, fullwidth):
            assert not (await service.login(ADMIN_USERNAME, password, totp_code=code)).ok
        assert len(padded) == 2, "a refusal escaped the failure pad"
        user = await store.get_user(identity.user_id)
        # Right password, wrong code, twice: the second-step counter, exactly as for "000000".
        assert user is not None and _columns(user) == (0, None, 0, 2, None, 0)
        assert totp.verify_totp_step(steps._secret, arabic_indic, window=1) is None
    finally:
        await store.close()


async def test_an_addressless_lock_notice_does_not_hold_back_a_later_mailable_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The throttle row records whether a mail could go out. An addressless account is throttled
    (so the log is not warned every 15 minutes), but once an address is set the next lock of that
    kind is mailed rather than held back by a notice nobody received."""
    store, service, notifier, clock, user_id = await _notice_harness(monkeypatch)
    try:
        user = await store.get_user(user_id)
        assert user is not None
        await store.set_user_notify_email(user_id, email="owner@example.org")
        # Start with no address: create a second account born without one.
        await store.create_user(
            user_id="u-noaddr",
            username="no-address",
            auth_provider="local",
            password_hash=user.password_hash,
        )
        bare = await store.get_user("u-noaddr")
        assert bare is not None and not bare.notify_email
        for _ in range(3):
            assert not (await service.login("no-address", "wrong-passphrase")).ok
            clock.now += 15 * 60 + 1
        rows = await store.list_audit(actor="no-address", action="auth.lock_notice", limit=10)
        assert len(rows) == 1 and '"mailed": false' in str(rows[0]["detail"])
        await store.set_user_notify_email("u-noaddr", email="later@example.org")
        before = len(_lock_notices(notifier))
        assert not (await service.login("no-address", "wrong-passphrase")).ok
        assert len(_lock_notices(notifier)) == before + 1, "the first mailable lock was held back"
    finally:
        await store.close()


async def test_a_directory_second_step_lock_names_the_directory_sign_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A directory account's first step is its directory sign-in, which this engine cannot reset,
    so its second-step notice says so and points at the directory."""
    from messagefoundry.pipeline.security_notify import _build_body

    store, service, notifier, clock, _user_id = await _notice_harness(monkeypatch)
    try:
        await store.create_user(
            user_id="u-ad", username="ad-user", auth_provider="ad", now=clock.now
        )
        await store.set_user_notify_email("u-ad", email="ad@example.org")
        ad = await store.get_user("u-ad")
        assert ad is not None
        result = await store.increment_login_failure(
            "u-ad",
            counter="second_step",
            threshold=1,
            lockout_seconds=900.0,
            max_lockout_seconds=86_400.0,
            now=clock.now,
        )
        await service._record_lock(ad, "second_step", result, client=None, factor="first_step")
        notice = _lock_notices(notifier)[-1]
        assert notice.detail["factor_right"] == "directory"
        body = _build_body(notice)
        assert "directory sign-in succeeded" in body and "password reset" not in body
    finally:
        await store.close()


async def test_a_corrupt_stored_secret_is_a_padded_wrong_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The combined sign-in reads the TOTP secret WITHOUT the password, so a secret that will not
    decrypt must not surface as an exception that names the account as enrolled."""
    from messagefoundry.auth import service as service_module
    from messagefoundry.store.crypto import CipherError

    store = await _store()
    try:
        service = AuthService(store, AuthSettings(**{**_LOCK_SETTINGS, "lockout_threshold": 50}))
        identity, password, steps = await _totp_admin(service, monkeypatch)
        padded: list[float] = []

        async def record(deadline: float) -> None:
            padded.append(deadline)

        async def broken(_user_id: str) -> str:
            raise CipherError("synthetic: the stored secret will not decrypt")

        monkeypatch.setattr(service_module, "_sleep_until", record)
        monkeypatch.setattr(store, "get_totp_secret", broken)
        assert not (await service.login(ADMIN_USERNAME, password, totp_code=steps.next_code())).ok
        assert len(padded) == 1
        user = await store.get_user(identity.user_id)
        assert user is not None and user.second_step_failed_attempts == 1
    finally:
        await store.close()


async def test_a_reauth_after_a_run_of_wrong_codes_still_flags_login_after_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ADR 0197 moved wrong codes to the second-step counter; the re-auth's 6.3.5 check sums both
    counters, as the login leg does, so the run still flags."""
    from messagefoundry.auth.notifications import LOGIN_AFTER_FAILURES

    store = await _store()
    try:
        notifier = _FakeNotifier()
        service = AuthService(
            store,
            AuthSettings(**{**_LOCK_SETTINGS, "lockout_threshold": 50}),
            security_notifier=notifier,
        )
        identity, password, steps = await _totp_admin(service, monkeypatch)
        out = await service.login(ADMIN_USERNAME, password, totp_code=steps.next_code())
        assert out.ok and out.token is not None and out.identity is not None
        for _ in range(3):
            await store.increment_login_failure(
                identity.user_id,
                counter="second_step",
                threshold=50,
                lockout_seconds=900.0,
                max_lockout_seconds=86_400.0,
                now=time.time(),
            )
        assert (await service.reauth(out.identity, password, token=out.token)).ok
        flagged = [e for e in notifier.events if e.event_type == LOGIN_AFTER_FAILURES]
        assert flagged and flagged[-1].detail == {"failed_attempts": 3}
    finally:
        await store.close()
