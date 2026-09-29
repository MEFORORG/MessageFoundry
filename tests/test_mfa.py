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
from messagefoundry.auth.ldap import AdPrincipal, DirectoryAnswer, DirectoryProbe
from messagefoundry.auth.notifications import (
    ACCOUNT_LOCKED,
    MFA_DISABLED,
    MFA_ENABLED,
    RECOVERY_CODE_USED,
    SecurityEvent,
)
from messagefoundry.auth.passwords import verify_password
from messagefoundry.auth.service import (
    _DUMMY_PASSWORD_HASH,
    AuthService,
    _credential_lock_key,
    _directory_login_refusal,
)
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

            def probe_principal(
                self, username: str, *, object_id: str | None = None
            ) -> DirectoryProbe:
                # verify_mfa asks the directory before it renews a directory account's window
                # (BACKLOG #2023); tests/test_mfa_directory_recheck.py covers the refusals.
                assert username == "jdoe"
                return DirectoryProbe(DirectoryAnswer.FOUND, principal)

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


def _count_verifies(monkeypatch: pytest.MonkeyPatch, service: AuthService) -> dict[str, int]:
    """Count the credential checks a burst actually ran, per leg, by wrapping the three verify seams.

    ``password`` counts argon2 verifies against a REAL stored hash, never the dummy one a refusal runs
    to keep its timing flat. ``code`` counts ``verify_mfa``'s factor check, and ``combined`` the
    combined sign-in's two-factor check. A refused attempt reaches none of them, so each count is the
    number of guesses the engine evaluated -- which is the quantity BACKLOG #1943 bounds."""
    counts = {"password": 0, "code": 0, "combined": 0}
    real_argon2 = service._argon2
    real_second = service._verify_second_factor
    real_both = service._check_both_factors

    async def argon2(fn: Any, *args: Any) -> Any:
        if fn is verify_password and args[0] != _DUMMY_PASSWORD_HASH:
            counts["password"] += 1
        return await real_argon2(fn, *args)

    async def second(user: Any, code: str, **kwargs: Any) -> bool:
        counts["code"] += 1
        return await real_second(user, code, **kwargs)

    async def both(user: Any, password: str, code: str, **kwargs: Any) -> tuple[bool, bool]:
        counts["combined"] += 1
        return await real_both(user, password, code, **kwargs)

    monkeypatch.setattr(service, "_argon2", argon2)
    monkeypatch.setattr(service, "_verify_second_factor", second)
    monkeypatch.setattr(service, "_check_both_factors", both)
    return counts


async def test_parallel_wrong_credentials_cannot_evade_the_account_lockout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Security review (TOCTOU): N wrong credentials submitted AT ONCE must still lock the account,
    and must get EXACTLY ``threshold`` guesses evaluated, however large the burst.

    The first half is the concurrency proof for the atomic failure counter;
    ``store.next_lockout_state`` carries the race it closes. The second half is BACKLOG #1943: the
    lock check ran before the verify and the count after it, so every guess already past the check
    was verified, and a burst of N got N guesses rather than ``threshold``. Attempts on one account
    now run one at a time, so the attempt after the locking one re-reads a locked row.

    **Every leg that is refused by a lock and feeds it is asserted** -- wrong passwords through
    ``login``, wrong TOTP codes through ``verify_mfa``, and the combined sign-in with one factor
    right. Each arm ends on whether the account is LOCKED, never on the count alone: a counter that
    reaches the threshold while the lock stays NULL admits the very next guess. The burst is
    deliberately LARGER than the threshold, which is what makes the verify count discriminate and
    also pins the one-notice-per-lockout contract.
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
        counts = _count_verifies(monkeypatch, service)

        # --- arm 1: parallel wrong PASSWORDS ------------------------------------------------------
        outs = await asyncio.gather(*(service.login(ADMIN_USERNAME, "wrong") for _ in range(burst)))
        assert not any(o.ok for o in outs)
        assert counts["password"] == threshold, "guesses past the lock check were still verified"
        assert [o.error for o in outs].count("account locked") == burst - threshold
        user = await store.get_user(identity.user_id)
        assert user is not None and user.failed_attempts == threshold  # none lost, none past it
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
        counts["code"] = 0
        results = await asyncio.gather(*(service.verify_mfa(t, wrong_code) for t in tokens))
        assert not any(r.ok for r in results)
        assert counts["code"] == threshold, "codes past the lock check were still verified"
        assert sum(1 for r in results if r.locked) == burst - threshold
        user = await store.get_user(identity.user_id)
        # ADR 0197: a wrong code on the second step feeds the SECOND-STEP counter, not the sign-in one.
        assert user is not None and user.second_step_failed_attempts == threshold
        assert user.failed_attempts == 0
        locked_out = await service.login(ADMIN_USERNAME, password)
        assert not locked_out.ok and locked_out.error == "account locked"

        # --- arm 3: parallel COMBINED sign-ins, right password and wrong code ---------------------
        # ADR 0197 routes one factor right to the second-step counter, and the second-step lock
        # refuses a combined sign-in, so this leg is bounded by the same lock as arm 2.
        await store.clear_lockout(identity.user_id)
        live = fresh_totp(enroll.secret)
        wrong_code = f"{(int(live[0]) + 1) % 10}{live[1:]}"
        counts["combined"] = 0
        outs = await asyncio.gather(
            *(service.login(ADMIN_USERNAME, password, totp_code=wrong_code) for _ in range(burst))
        )
        assert not any(o.ok for o in outs)
        assert counts["combined"] == threshold, "combined guesses past the lock were still verified"
        assert [o.error for o in outs].count("account locked") == burst - threshold
        user = await store.get_user(identity.user_id)
        assert user is not None and user.second_step_failed_attempts == threshold
        assert user.second_step_locked_until is not None

        # The per-account queue leaves no entry behind once every attempt has left it.
        assert service._credential_locks == {}, "the per-account lock entry must not leak"
    finally:
        await store.close()


async def test_a_right_password_queued_behind_the_locking_attempt_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RED when: a sign-in already past the lock check when the lock is set is still verified.

    BACKLOG #1943. ``threshold`` wrong passwords and then the RIGHT one, submitted at once. Before the
    fix every attempt read the row before any failure was counted, so the right password verified
    and signed in beside the attempt that locked the account. Now the attempts run in arrival order,
    one at a time, and the right password is refused by the lock its predecessors set, unverified.
    """
    store = await _store()
    try:
        threshold = 3
        service = AuthService(store, AuthSettings(lockout_threshold=threshold, lockout_minutes=15))
        identity, _token, password = await login_admin(service)
        counts = _count_verifies(monkeypatch, service)
        attempts = ["wrong"] * threshold + [password]
        outs = await asyncio.gather(*(service.login(ADMIN_USERNAME, pw) for pw in attempts))
        last = outs[-1]
        assert not last.ok and last.error == "account locked", "the queued right password got in"
        assert last.token is None
        assert counts["password"] == threshold
        user = await store.get_user(identity.user_id)
        assert user is not None and user.failed_attempts == threshold
        assert user.locked_until is not None
    finally:
        await store.close()


def test_the_credential_lock_key_folds_every_spelling_a_backend_may_match() -> None:
    """The queue is keyed on a username at least as coarse as any backend's match, so no spelling of
    one account escapes it. SQL Server's ``=`` ignores trailing spaces under any collation, and an
    existing SQL Server database keeps whatever case- or accent-insensitive collation it was
    created with (ADR 0169)."""
    assert _credential_lock_key("Admin ") == _credential_lock_key("admin")
    assert _credential_lock_key("ADMIN") == _credential_lock_key("admin")
    assert _credential_lock_key("\u00e1dmin") == _credential_lock_key("admin")  # accent
    assert _credential_lock_key("\uff41dmin") == _credential_lock_key("admin")  # fullwidth
    assert _credential_lock_key("adm\u00adin") == _credential_lock_key("admin")  # soft hyphen (Cf)
    assert _credential_lock_key("admin\u200b") == _credential_lock_key("admin")  # zero-width space
    # Spaces go last, so a space before a dropped character does not survive as a trailing one.
    assert _credential_lock_key("admin \u200b") == _credential_lock_key("admin")
    assert _credential_lock_key("admin \u0301") == _credential_lock_key("admin")
    assert _credential_lock_key("alice") != _credential_lock_key("bob")


def test_the_credential_lock_key_reads_a_bounded_prefix() -> None:
    """The key is computed on the event loop before any check, and NFKD expands U+FDFA about
    eighteenfold, so an unbounded name would stall the loop. Only a bounded prefix is read."""
    import messagefoundry.auth.service as svc

    cap = svc._CREDENTIAL_KEY_INPUT_MAX
    assert cap >= 256  # the store's column width: no real name is cut
    huge = "\ufdfa" * 1_000_000
    started = time.monotonic()
    key = _credential_lock_key(huge)
    assert time.monotonic() - started < 1.0
    assert key == _credential_lock_key("\ufdfa" * cap)
    # A cut merges names past the cap into one queue, which is coarser and so safe.
    assert _credential_lock_key("a" * cap + "x") == _credential_lock_key("a" * cap + "y")


async def test_parallel_store_increments_each_land_and_lock_once() -> None:
    """The concurrency proof for the atomic failure counter itself, one layer below the service.

    Since BACKLOG #1943 the service queues attempts on one account, so a service-level burst no
    longer reaches ``increment_login_failure`` concurrently and cannot catch a store that went back
    to read-add-write. The re-proof legs and other engine processes still do reach it concurrently.
    This drives the store call directly, past the threshold, on both counters: every increment must
    land, exactly one must report the lock, and the later ones must not extend it (AC-10a)."""
    store = await _store()
    try:
        user_id = (await create_admin(AuthService(store, AuthSettings()))).user_id
        threshold, burst, now = 3, 6, time.time()
        for counter in ("sign_in", "second_step"):
            results = await asyncio.gather(
                *(
                    store.increment_login_failure(
                        user_id,
                        counter=counter,
                        threshold=threshold,
                        lockout_seconds=900.0,
                        max_lockout_seconds=86_400.0,
                        now=now,
                    )
                    for _ in range(burst)
                )
            )
            assert sorted(r.attempts for r in results) == list(range(1, burst + 1)), counter
            assert sum(1 for r in results if r.just_locked) == 1, counter
            user = await store.get_user(user_id)
            assert user is not None
            until = user.locked_until if counter == "sign_in" else user.second_step_locked_until
            assert until == now + 900.0, f"{counter}: a later increment moved the lock"
    finally:
        await store.close()


async def test_a_burst_on_one_account_does_not_spend_the_budget_overrun_warning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RED when: the time an attempt waits in its account's queue counts toward the overrun warning.

    The warning is once per process and says the budget is too small for this HARDWARE. Queued one
    at a time, a burst on one account outruns a budget that every single attempt meets, so
    counting the wait would spend the warning on a false alarm and silence a real overrun later.
    The verify is replaced by a fixed 40 ms sleep so the arithmetic does not ride on the host's
    argon2 speed. Each failure holds the queue for one padded slot, so every attempt after the first
    waits at least one whole budget, while its own work stays well under it."""
    import messagefoundry.auth.service as svc

    store = await _store()
    try:
        service = AuthService(store, AuthSettings(lockout_threshold=50, lockout_minutes=15))
        await login_admin(service)
        warned: set[str] = set()
        monkeypatch.setattr(svc, "_BUDGET_OVERRUN_WARNED", warned)
        monkeypatch.setattr(svc, "_FAILURE_BUDGET_SECONDS", 0.3)

        async def slow_wrong(fn: Any, *args: Any) -> Any:
            await asyncio.sleep(0.04)
            return False

        monkeypatch.setattr(service, "_argon2", slow_wrong)
        started = time.monotonic()
        outs = await asyncio.gather(*(service.login(ADMIN_USERNAME, "wrong") for _ in range(8)))
        assert not any(o.ok for o in outs)
        assert time.monotonic() - started > 0.28, "the burst did not queue; this arm proves nothing"
        assert "login" not in warned, "queue wait was counted as work"
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

#: The lockout threshold these tests run at unless an arm says otherwise.
_LOCK_THRESHOLD = 3


def _lock_settings(threshold: int = _LOCK_THRESHOLD) -> AuthSettings:
    """The ADR 0197 arms' settings: a small threshold, the shipped 15-minute base, and one recovery
    code, so a wrong code on the two-step path walks one argon2 slot rather than ten."""
    return AuthSettings(lockout_threshold=threshold, lockout_minutes=15, mfa_recovery_code_count=1)


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
    for _ in range(_LOCK_THRESHOLD):
        await store.increment_login_failure(
            user_id,
            counter="second_step",
            threshold=_LOCK_THRESHOLD,
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
        service = AuthService(store, _lock_settings())
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
        service = AuthService(store, _lock_settings())
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
        service = AuthService(store, _lock_settings())
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
        service = AuthService(store, _lock_settings())
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
        service = AuthService(store, _lock_settings(10))
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
        service = AuthService(store, _lock_settings())
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
        service = AuthService(store, _lock_settings())
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
        service = AuthService(store, _lock_settings())
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
        service = AuthService(store, _lock_settings(50))
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
        service = AuthService(store, _lock_settings(500))
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
    on the second-step counter and lock it, with exactly one lock notice.

    The count is ``threshold``, not ``burst`` (BACKLOG #1943): sign-ins on one account run one at a
    time, so the attempts after the locking one are refused by its lock before any verify and are
    never counted. A count below ``threshold`` would still mean an increment was lost to the race."""
    store = await _store()
    try:
        threshold, burst = 3, 5
        notifier = _FakeNotifier()
        service = AuthService(
            store,
            _lock_settings(threshold),
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
        assert user.second_step_failed_attempts == threshold, "an increment lost, or one too many"
        assert [o.error for o in outs].count("account locked") == burst - threshold
        assert user.second_step_locked_until is not None and user.second_step_lock_cycles == 1
        assert (user.failed_attempts, user.locked_until) == (0, None)
        assert sum(1 for e in notifier.events if e.event_type == ACCOUNT_LOCKED) == 1
    finally:
        await store.close()


async def test_verify_mfa_and_the_sign_in_share_one_queue(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RED when: ``verify_mfa`` queues on a different key from the sign-in.

    BACKLOG #1943. Both legs feed and are refused by the second-step lock, so they must wait in one
    queue. ``threshold`` wrong codes are queued first, then a combined sign-in with the right
    password and a wrong code. In one queue the sign-in runs last, finds the lock the codes set, and
    is refused unverified. In two queues it runs beside them, reads the row before any code counted,
    and is verified: the overshoot again, across legs."""
    store = await _store()
    try:
        threshold = 3
        service = AuthService(store, _lock_settings(threshold))
        _identity, password, steps = await _totp_admin(service, monkeypatch)
        tokens = [(await service.login(ADMIN_USERNAME, password)).token for _ in range(threshold)]
        steps.next_code()
        wrong = steps.wrong_code()
        counts = _count_verifies(monkeypatch, service)
        codes = [asyncio.ensure_future(service.verify_mfa(t, wrong)) for t in tokens]
        try:
            # verify_mfa reads the session before it queues; wait until every code is in a queue.
            for _ in range(1000):
                if sum(e.users for e in service._credential_locks.values()) == threshold:
                    break
                await asyncio.sleep(0.001)
            else:
                pytest.fail("the wrong codes never reached the credential queue")
            signed = await service.login(ADMIN_USERNAME, password, totp_code=wrong)
            results = await asyncio.gather(*codes)
        finally:
            for pending in codes:
                pending.cancel()
            await asyncio.gather(*codes, return_exceptions=True)
        assert not any(r.ok for r in results)
        assert counts["code"] == threshold
        assert not signed.ok and signed.error == "account locked"
        assert counts["combined"] == 0, "the combined sign-in was verified past the lock"
    finally:
        await store.close()


async def test_a_burst_answers_on_the_same_slots_for_a_real_and_an_unknown_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RED when: the failure pad runs outside the per-account queue.

    BACKLOG #1943, ASVS 6.3.8. Queued one at a time, each attempt's raw work adds to the wait of the
    attempts behind it. Padded after the queue, a branch that does a little more work (a real name
    counts its failure in the store, an unknown one does not) pushes a burst's last answers into a
    later slot than the same burst on an unknown name. Padded inside the queue, every failure
    answers on a whole slot from its own start, whatever its branch.

    The verify is a fixed 40 ms sleep and the real name's failure count gains 60 ms, so the gap is
    far wider than the host's jitter. The budget is lowered to keep the run short."""
    import messagefoundry.auth.service as svc

    store = await _store()
    try:
        budget, burst = 0.25, 5
        monkeypatch.setattr(svc, "_FAILURE_BUDGET_SECONDS", budget)
        service = AuthService(store, AuthSettings(lockout_threshold=50, lockout_minutes=15))
        await login_admin(service)

        async def fixed_wrong(fn: Any, *args: Any) -> Any:
            await asyncio.sleep(0.04)
            return False

        real_increment = store.increment_login_failure

        async def slow_increment(*args: Any, **kwargs: Any) -> Any:
            await asyncio.sleep(0.06)
            return await real_increment(*args, **kwargs)

        monkeypatch.setattr(service, "_argon2", fixed_wrong)
        monkeypatch.setattr(store, "increment_login_failure", slow_increment)

        async def one(name: str) -> int:
            started = time.monotonic()
            out = await service.login(name, "wrong")
            assert not out.ok
            return round((time.monotonic() - started) / budget)

        async def slots(name: str) -> list[int]:
            return sorted(await asyncio.gather(*(one(name) for _ in range(burst))))

        real = await slots(ADMIN_USERNAME)
        unknown = await slots("no-such-operator")
        assert real == unknown, f"a burst's answer slots depend on the name: {real} vs {unknown}"
        assert real == list(range(1, burst + 1))
    finally:
        await store.close()


async def test_a_second_attempt_answers_on_a_slot_its_own_work_does_not_move(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RED when: a queued failure's pad counts only from its own start.

    BACKLOG #1943, ASVS 6.3.8. The attacker sends attempt A, then attempt B on the same name a
    moment later. B waits in the queue until A answers, so the wait eats most of B's slot, and
    whether B's own work then crosses the slot boundary shows how long that work took. A real name
    counts its failure in the store and an unknown one does not, so a real name answered a slot
    later. The pad now holds a queued failure at least half a budget past its turn, so B answers
    on the same slot for either name.

    The verify is a fixed 40 ms sleep and the real name's failure count gains 120 ms, so B's work
    is about 40 ms on the unknown name and 160 ms on the real one. B starts 120 ms after A, which
    puts the old slot boundary between the two."""
    import messagefoundry.auth.service as svc

    store = await _store()
    try:
        budget, offset = 0.4, 0.12
        monkeypatch.setattr(svc, "_FAILURE_BUDGET_SECONDS", budget)
        service = AuthService(store, AuthSettings(lockout_threshold=50, lockout_minutes=15))
        await login_admin(service)

        async def fixed_wrong(fn: Any, *args: Any) -> Any:
            await asyncio.sleep(0.04)
            return False

        real_increment = store.increment_login_failure

        async def slow_increment(*args: Any, **kwargs: Any) -> Any:
            await asyncio.sleep(0.12)
            return await real_increment(*args, **kwargs)

        monkeypatch.setattr(service, "_argon2", fixed_wrong)
        monkeypatch.setattr(store, "increment_login_failure", slow_increment)

        async def second_slot(name: str) -> int:
            first = asyncio.ensure_future(service.login(name, "wrong"))
            await asyncio.sleep(offset)
            started = time.monotonic()
            out = await service.login(name, "wrong")
            took = time.monotonic() - started
            assert not out.ok and not (await first).ok
            assert took > budget - offset, "the second attempt did not queue; this proves nothing"
            return round(took / budget)

        real = await second_slot(ADMIN_USERNAME)
        unknown = await second_slot("no-such-operator")
        assert real == unknown, (
            f"the second attempt's slot depends on the name: {real} vs {unknown}"
        )
    finally:
        await store.close()


class _TickingClock:
    """A stand-in for the ``totp`` module's ``time`` that starts at ``instant`` and then moves with
    the real monotonic clock, so a real wait in the queue carries the TOTP step forward."""

    def __init__(self, instant: float) -> None:
        self._instant = instant
        self._origin = time.monotonic()

    def time(self) -> float:
        return self._instant + (time.monotonic() - self._origin)


@pytest.mark.parametrize("leg", ["verify_mfa", "combined"])
async def test_a_live_code_that_goes_stale_in_the_queue_is_still_accepted(
    monkeypatch: pytest.MonkeyPatch, leg: str
) -> None:
    """RED when: a queued code is judged when it leaves the queue rather than when it arrived.

    BACKLOG #1943. A caller who knows only the username can keep an account's queue busy with
    padded wrong passwords. Judged after the wait, the owner's live code would be stale and would
    count on the second-step counter, which lets that caller set the second-step lock through the
    owner's own attempts. Here the code is live when the request arrives, one step boundary falls
    during the wait, and the code must still be accepted with nothing counted."""
    from messagefoundry.auth import totp as totp_mod

    store = await _store()
    try:
        service = AuthService(store, _lock_settings())
        identity, password, steps = await _totp_admin(service, monkeypatch)
        token = (await service.login(ADMIN_USERNAME, password)).token
        assert token is not None
        blocker = asyncio.ensure_future(service.login(ADMIN_USERNAME, "wrong"))
        for _ in range(1000):
            if service._credential_locks:
                break
            await asyncio.sleep(0.001)
        else:
            pytest.fail("the blocking attempt never took the queue")
        # 100 ms before a step boundary, in a step later than the one enrollment spent.
        instant = (steps.step + 2) * totp.DEFAULT_PERIOD - 0.1
        code = totp.totp(steps._secret, now=instant)
        monkeypatch.setattr(totp_mod, "time", _TickingClock(instant))
        arrived = time.monotonic()
        if leg == "verify_mfa":
            ok = (await service.verify_mfa(token, code)).ok
        else:
            ok = (await service.login(ADMIN_USERNAME, password, totp_code=code)).ok
        waited = time.monotonic() - arrived
        await blocker
        assert waited > 0.1, "the wait did not cross the step boundary; this proves nothing"
        assert ok, "a code live on arrival was judged stale after its wait in the queue"
        user = await store.get_user(identity.user_id)
        assert user is not None and user.second_step_failed_attempts == 0
    finally:
        await store.close()


async def test_a_session_revoked_mid_enrolment_leaves_mfa_off_and_retryable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RED when: ``confirm_mfa_enrollment`` enables TOTP before the session rotation succeeds.

    BACKLOG #1902. The plaintext recovery codes reach the user only inside the returned Elevation,
    and a session revoked mid-ceremony yields a lost one that carries nothing. Enabled first, that
    left MFA ON with codes nobody ever saw. The revoke lands in the gap between the good code and
    the rotation: MFA must stay off, and the staged secret must still confirm on a fresh session.
    """
    store = await _store()
    try:
        notifier = _FakeNotifier()
        service = AuthService(store, AuthSettings(), security_notifier=notifier)
        identity, token, password = await login_admin(service)
        enroll = await service.begin_mfa_enrollment(identity)
        t0 = 1_000_000.0
        pin_totp_clock(monkeypatch, t0)

        real_mark = store.mark_session_mfa_verified

        async def mark_then_revoke(token_hash: str, *, now: float | None = None) -> None:
            await real_mark(token_hash, now=now)
            await store.revoke_session(token_hash)

        monkeypatch.setattr(store, "mark_session_mfa_verified", mark_then_revoke)
        lost = await service.confirm_mfa_enrollment(
            identity, totp.totp(enroll.secret, now=t0), token=token
        )
        assert lost.ok is False and lost.session_lost is True
        assert lost.recovery_codes == ()
        assert (await service.mfa_status(identity)).enabled is False, (
            "MFA was enabled on a lost session, so its recovery codes were never delivered"
        )
        assert await store.get_recovery_code_hashes(identity.user_id) == []
        assert not any(e.event_type == MFA_ENABLED for e in notifier.events)
        actions = [e["action"] for e in await service.security_events_for(ADMIN_USERNAME)]
        assert "auth.session_rotation_failed" in actions
        assert "auth.mfa_enrolled" not in actions

        # The retry: sign in again and confirm the SAME staged secret. The activating step was
        # consumed (BACKLOG #1021), so the code must come from a later step.
        monkeypatch.setattr(store, "mark_session_mfa_verified", real_mark)
        again = await service.login(ADMIN_USERNAME, password)
        assert again.token is not None
        t1 = t0 + totp.DEFAULT_PERIOD
        pin_totp_clock(monkeypatch, t1)
        retried = await service.confirm_mfa_enrollment(
            identity, totp.totp(enroll.secret, now=t1), token=again.token
        )
        assert retried.ok and len(retried.recovery_codes) == 10
        assert (await service.mfa_status(identity)).enabled is True
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
        service = AuthService(store, _lock_settings(50))
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
            password_generated=False,
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
            user_id="u-ad",
            username="ad-user",
            auth_provider="ad",
            now=clock.now,
            password_generated=False,
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
        service = AuthService(store, _lock_settings(50))
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
            _lock_settings(50),
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


async def test_a_session_revoked_after_rotation_still_delivers_the_codes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RED when: a revoke landing after the rotation strands MFA on without its codes (BACKLOG #1902).

    The other side of the gap. Once the rotation has succeeded the Elevation carries the codes, so
    MFA may go on even if the new session is revoked before the enable commits: the codes are
    still handed back, and each one is a live recovery code.
    """
    store = await _store()
    try:
        service = AuthService(store, AuthSettings())
        identity, token, _ = await login_admin(service)
        enroll = await service.begin_mfa_enrollment(identity)

        real_enable = store.enable_totp

        async def revoke_then_enable(
            user_id: str, *, recovery_code_hashes: list[str], now: float | None = None
        ) -> None:
            await store.revoke_user_sessions(user_id)
            await real_enable(user_id, recovery_code_hashes=recovery_code_hashes, now=now)

        monkeypatch.setattr(store, "enable_totp", revoke_then_enable)
        enrolled = await service.confirm_mfa_enrollment(
            identity, fresh_totp(enroll.secret), token=token
        )
        assert enrolled.ok and len(enrolled.recovery_codes) == 10
        assert (await service.mfa_status(identity)).enabled is True
        hashes = await store.get_recovery_code_hashes(identity.user_id)
        assert len(hashes) == len(enrolled.recovery_codes)
    finally:
        await store.close()


# --- ADR 0197 Amendment A, wave 1 (BACKLOG #1131): every account is born with a way past ----------
#
# A lock exists to bound guesses. On an engine-generated 192-bit credential it bounds nothing, so
# wrong passwords arm no sign-in lock while one stands (AC-A1). Under the shipped require_mfa the
# holder enrols TOTP BEFORE replacing it (AC-A3), so the rotation that ends every session never
# leaves a guessable password with no way past. These arms walk the service, not the store.


async def _created_holder(service: AuthService, *, username: str = "holder") -> tuple[str, str]:
    """Create a local Viewer through the admin surface. Returns ``(user_id, issued_password)``."""
    await service.initialize()
    created = await service.create_local_user(
        username=username,
        display_name=None,
        email=f"{username}@example.org",
        roles=["viewer"],
        actor="test-admin",
    )
    return created.user_id, created.credential.password


def _way_past(user: Any) -> bool:
    """The invariant wave 1 exists for: a covered local account either holds an unguessable
    generated credential (nothing to get past) or TOTP (option E's combined sign-in)."""
    return bool(user.password_generated or user.totp_enabled)


async def test_a_created_account_cannot_be_locked_while_its_issued_credential_stands() -> None:
    """AC-A1 + AC-A2, through ``create_local_user`` -- the arm that catches a ``create_user`` call
    that forgot the ``password_generated`` keyword, because that account would lock here."""
    store = await _store()
    try:
        threshold = 3
        service = AuthService(store, AuthSettings(lockout_threshold=threshold, lockout_minutes=15))
        user_id, issued = await _created_holder(service)
        row = await store.get_user(user_id)
        assert row is not None and row.password_generated and row.must_change_password
        # AC-A2: 192 bits from the CSPRNG, not an administrator's choice.
        assert len(issued) >= 32
        for _ in range(threshold * 3):
            assert (await service.login("holder", "a-wrong-guess-xyz")).ok is False
        row = await store.get_user(user_id)
        assert row is not None
        # Counted and audited, never locked.
        assert row.failed_attempts == threshold * 3 and row.locked_until is None
        failed_rows = await store.list_audit(limit=100, action="auth.login_failed")
        assert len(failed_rows) >= threshold * 3
        out = await service.login("holder", issued)
        assert out.ok and out.must_change_password
    finally:
        await store.close()


async def test_the_walk_from_creation_to_a_chosen_password_never_leaves_the_holder_lockable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-A3, the whole first sign-in. At every step the account holds a way past, and each step
    that would break that is refused: the rotation before TOTP, and a passkey as the first factor."""
    from messagefoundry.auth.service import FactorEnrolmentRequired

    store = await _store()
    try:
        service = AuthService(store, AuthSettings())  # require_mfa on, the shipped default
        user_id, issued = await _created_holder(service)
        assert _way_past(await store.get_user(user_id))

        out = await service.login("holder", issued)
        assert out.ok and out.identity is not None and out.token is not None
        identity, token = out.identity, out.token

        # The rotation is refused IN THE SERVICE while no TOTP exists, and writes nothing.
        with pytest.raises(FactorEnrolmentRequired):
            await service.change_password(identity, "a-brand-new-chosen-passphrase")
        row = await store.get_user(user_id)
        assert row is not None and row.password_generated and _way_past(row)
        assert await service.must_enrol_before_rotating(identity)

        # A passkey cannot be the first factor: it has no way past the lock in wave 1.
        with pytest.raises(FactorEnrolmentRequired):
            await service.begin_webauthn_registration(
                identity, token=token, rp_id="localhost", rp_name="MessageFoundry"
            )

        # Enrolment is allowed, and it is TOTP.
        enroll = await service.begin_mfa_enrollment(identity)
        t0 = 1_000_000.0
        pin_totp_clock(monkeypatch, t0)
        confirmed = await service.confirm_mfa_enrollment(
            identity, totp.totp(enroll.secret, now=t0), token=token
        )
        assert confirmed.ok
        row = await store.get_user(user_id)
        assert row is not None and row.totp_enabled and row.password_generated
        assert not await service.must_enrol_before_rotating(identity)

        # Now the rotation lands, and the account is option E's case: chosen password, TOTP.
        assert await service.change_password(identity, "a-brand-new-chosen-passphrase") == []
        row = await store.get_user(user_id)
        assert row is not None
        assert (row.password_generated, row.totp_enabled, row.must_change_password) == (
            False,
            True,
            False,
        )
        assert _way_past(row)
    finally:
        await store.close()


async def test_an_account_with_no_must_change_flag_gets_the_same_gate() -> None:
    """AC-A3, "with or without the must-change flag": an account whose TOTP went while the
    requirement was off holds a chosen password and no flag. When the requirement is back on, its
    rotation is refused all the same. With the requirement off, it rotates as today."""
    from messagefoundry.auth.service import FactorEnrolmentRequired

    store = await _store()
    try:
        admin = await create_admin(AuthService(store, AuthSettings()))
        await store.set_password(
            admin.user_id,
            password_hash=await asyncio.to_thread(hash_password_for_test, admin.password),
            must_change_password=False,
            password_generated=False,
        )
        off = AuthService(store, AuthSettings(require_mfa=False))
        out = await off.login(admin.username, admin.password)
        assert out.ok and out.identity is not None
        assert not out.identity.must_change_password

        on = AuthService(store, AuthSettings())
        with pytest.raises(FactorEnrolmentRequired):
            await on.change_password(out.identity, "another-chosen-passphrase-1")
        row = await store.get_user(admin.user_id)
        assert row is not None and verify_password(row.password_hash or "", admin.password)

        # Positive control: the requirement off, the same call rotates.
        assert await off.change_password(out.identity, "another-chosen-passphrase-2") == []
    finally:
        await store.close()


def hash_password_for_test(password: str) -> str:
    from messagefoundry.auth.passwords import hash_password

    return hash_password(password)


async def test_a_factor_reset_racing_the_rotation_refuses_the_rotation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """N-B2 part 4: ``change_password`` checks for TOTP, hashes, then writes. An administrator's
    factor reset that lands in that gap clears TOTP; the write then matches no row, and the holder
    is refused rather than left with a chosen password and no way past."""
    from messagefoundry.auth.service import FactorEnrolmentRequired

    store = await _store()
    try:
        service = AuthService(store, AuthSettings())
        user_id, issued = await _created_holder(service)
        out = await service.login("holder", issued)
        assert out.identity is not None and out.token is not None
        enroll = await service.begin_mfa_enrollment(out.identity)
        t0 = 1_000_000.0
        pin_totp_clock(monkeypatch, t0)
        assert (
            await service.confirm_mfa_enrollment(
                out.identity, totp.totp(enroll.secret, now=t0), token=out.token
            )
        ).ok

        real_argon2 = service._argon2
        raced: list[object] = []

        async def argon2_with_a_reset_in_the_gap(fn: Any, *args: Any) -> Any:
            if not raced:
                raced.append("reset")  # first: the reset hashes its own credential through here
                await service.admin_reset_mfa(user_id, actor="test-admin")
            return await real_argon2(fn, *args)

        monkeypatch.setattr(service, "_argon2", argon2_with_a_reset_in_the_gap)
        with pytest.raises(FactorEnrolmentRequired):
            await service.change_password(out.identity, "a-chosen-passphrase-in-the-race")
        row = await store.get_user(user_id)
        assert row is not None
        # The reset's generated credential stands; the holder's chosen one never landed.
        assert row.password_generated and not row.totp_enabled
        assert _way_past(row)
    finally:
        await store.close()


async def test_admin_reset_mfa_issues_a_credential_before_it_clears_any_factor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-A4 + N-B2 part 5: the reset returns a generated credential, writes it FIRST, and leaves
    the account unlockable until the holder claims it."""
    store = await _store()
    try:
        threshold = 3
        service = AuthService(store, AuthSettings(lockout_threshold=threshold, lockout_minutes=15))
        identity = await _enrol_totp(service, monkeypatch)
        order: list[str] = []
        real_set_password = store.set_password
        real_disable = store.disable_totp
        real_delete = store.delete_all_webauthn_credentials

        async def spy_set_password(*a: Any, **k: Any) -> bool:
            order.append("set_password")
            return await real_set_password(*a, **k)

        async def spy_disable(*a: Any, **k: Any) -> None:
            order.append("disable_totp")
            await real_disable(*a, **k)

        async def spy_delete(*a: Any, **k: Any) -> int:
            order.append("delete_webauthn")
            return await real_delete(*a, **k)

        monkeypatch.setattr(store, "set_password", spy_set_password)
        monkeypatch.setattr(store, "disable_totp", spy_disable)
        monkeypatch.setattr(store, "delete_all_webauthn_credentials", spy_delete)
        issued = await service.admin_reset_mfa(identity.user_id, actor="another-admin")
        assert issued is not None and len(issued.password) >= 32
        assert order[0] == "set_password", order
        assert order.index("set_password") < order.index("disable_totp")

        row = await store.get_user(identity.user_id)
        assert row is not None and row.password_generated and not row.totp_enabled
        for _ in range(threshold * 2):
            assert (await service.login(ADMIN_USERNAME, "a-wrong-guess-xyz")).ok is False
        row = await store.get_user(identity.user_id)
        assert row is not None and row.locked_until is None
        assert (await service.login(ADMIN_USERNAME, issued.password)).ok
    finally:
        await store.close()


async def test_disable_mfa_refuses_removing_totp_while_covered_even_beside_a_passkey(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-A3a: a passkey is a second factor, but not a way past the sign-in lock in wave 1, so a
    covered account keeps its TOTP however many passkeys it holds."""
    store = await _store()
    try:
        service = AuthService(store, AuthSettings())
        identity = await _enrol_totp(service, monkeypatch)
        await store.add_webauthn_credential(
            WebAuthnCredential(
                credential_id_hash="w1-passkey-hash",
                credential_id="w1-passkey-id",
                user_id=identity.user_id,
                rp_id="t",
                public_key="cose-public-key-b64url",
                sign_count=0,
                transports=None,
                device_type="multi_device",
                backed_up=True,
                label="laptop",
                aaguid=None,
                created_at=1000.0,
            )
        )
        with pytest.raises(ValueError) as exc:
            await service.disable_mfa(identity)
        assert "last second factor" in str(exc.value)
        assert (await service.mfa_status(identity)).enabled is True
    finally:
        await store.close()


# --- ADR 0197 Amendment A, AC-A9: the census of accounts with no way past -------------------------


async def test_the_census_names_a_covered_chosen_password_with_no_totp_and_only_that(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A must-change Administrator whose password was typed for it (``create_admin``) is covered,
    holds a chosen credential and no TOTP: named. A generated credential, a TOTP holder, a disabled
    account and a directory account are not. With the requirement off, nothing is covered."""
    store = await _store()
    try:
        service = AuthService(store, AuthSettings())
        await create_admin(service)
        await _created_holder(service, username="generated")
        enrolled_id, _ = await _created_holder(service, username="enrolled")
        await store.set_totp_secret(enrolled_id, secret="JBSWY3DPEHPK3PXP")
        await store.enable_totp(enrolled_id, recovery_code_hashes=[])
        disabled_id, _ = await _created_holder(service, username="disabled")
        await store.set_password(
            disabled_id, password_hash="h", password_generated=False, must_change_password=False
        )
        await store.set_user_disabled(disabled_id, disabled=True)
        await store.create_user(
            user_id="dir-1", username="directory", auth_provider="ad", password_generated=False
        )
        census = await service.lockable_account_census()
        assert census.no_way_past == (ADMIN_USERNAME,)
        assert census.undecryptable_totp == ()
        assert not census.clean

        off = await AuthService(store, AuthSettings(require_mfa=False)).lockable_account_census()
        assert off.clean
    finally:
        await store.close()


async def test_the_census_names_an_enabled_totp_secret_the_engine_cannot_decrypt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The owner's way past is the combined sign-in; with an unreadable secret it becomes "right
    password, wrong code", which feeds the second-step lock. The census names it."""
    from messagefoundry.store.crypto import CipherError

    store = await _store()
    try:
        service = AuthService(store, AuthSettings())
        identity = await _enrol_totp(service, monkeypatch)
        assert (await service.lockable_account_census()).clean
        real = store.get_totp_secret

        async def broken(user_id: str) -> str | None:
            if user_id == identity.user_id:
                raise CipherError("synthetic: the key this blob was sealed under is gone")
            return await real(user_id)

        monkeypatch.setattr(store, "get_totp_secret", broken)
        census = await service.lockable_account_census()
        assert census.undecryptable_totp == (ADMIN_USERNAME,)
        assert census.no_way_past == ()
    finally:
        await store.close()


async def test_the_census_names_nothing_on_a_store_built_through_the_new_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every account made and claimed through the shipped paths is generated or holds TOTP."""
    store = await _store()
    try:
        service = AuthService(store, AuthSettings())
        user_id, issued = await _created_holder(service)
        out = await service.login("holder", issued)
        assert out.identity is not None and out.token is not None
        assert (await service.lockable_account_census()).clean
        enroll = await service.begin_mfa_enrollment(out.identity)
        t0 = 1_000_000.0
        pin_totp_clock(monkeypatch, t0)
        confirmed = await service.confirm_mfa_enrollment(
            out.identity, totp.totp(enroll.secret, now=t0), token=out.token
        )
        assert confirmed.ok
        assert await service.change_password(out.identity, "a-brand-new-chosen-passphrase") == []
        assert (await service.lockable_account_census()).clean
        await service.admin_reset_mfa(user_id, actor="test-admin")
        assert (await service.lockable_account_census()).clean
    finally:
        await store.close()


async def test_the_startup_census_warns_and_audits_and_does_not_refuse(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """AC-A9: a finding is a WARNING and one audit row naming usernames, never a raise."""
    store = await _store()
    try:
        service = AuthService(store, AuthSettings())
        await create_admin(service)
        with caplog.at_level("WARNING", logger="messagefoundry.auth.service"):
            census = await service.report_lockable_account_census()
        assert census.no_way_past == (ADMIN_USERNAME,)
        assert any(ADMIN_USERNAME in r.getMessage() for r in caplog.records)
        rows = await store.list_audit(limit=10, action="auth.lockable_account_census")
        assert len(rows) == 1 and ADMIN_USERNAME in str(rows[0]["detail"])
        assert "JBSWY" not in str(rows[0]["detail"])
    finally:
        await store.close()


async def test_the_mfa_enabled_notice_to_a_must_change_account_says_who_to_tell(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """N-B2 "a new credential to protect": an interceptor can now enrol without rotating, so the
    MFA_ENABLED notice to a must-change account tells the holder what an unexpected one means."""
    from messagefoundry.pipeline.security_notify import _build_body

    store = await _store()
    try:
        notifier = _FakeNotifier()
        service = AuthService(store, AuthSettings(), security_notifier=notifier)
        _user_id, issued = await _created_holder(service)
        out = await service.login("holder", issued)
        assert out.identity is not None and out.token is not None
        enroll = await service.begin_mfa_enrollment(out.identity)
        t0 = 1_000_000.0
        pin_totp_clock(monkeypatch, t0)
        await service.confirm_mfa_enrollment(
            out.identity, totp.totp(enroll.secret, now=t0), token=out.token
        )
        event = next(e for e in notifier.events if e.event_type == MFA_ENABLED)
        assert event.detail.get("issued_credential") is True
        body = _build_body(event)
        assert "have not signed in" in body and "administrator" in body
    finally:
        await store.close()


# --- review round 1 (ADR 0197 Amendment A) -------------------------------------------------------


async def test_a_rotation_landing_between_the_resets_writes_cannot_leave_a_chosen_password_bare(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The other ordering of the reset/rotation race. The reset writes its credential, then a
    holder's rotation -- which read TOTP on -- lands its conditional write before the reset clears
    TOTP. The reset writes its credential again once the factors are gone, so the account ends with
    the generated credential, never a chosen password with no factor. And the holder hears of the
    password change as a PASSWORD_RESET, with its deadline."""
    from messagefoundry.auth.notifications import PASSWORD_RESET

    store = await _store()
    try:
        notifier = _FakeNotifier()
        service = AuthService(store, AuthSettings(), security_notifier=notifier)
        identity = await _enrol_totp(service, monkeypatch)
        real_disable = store.disable_totp

        async def rotation_lands_first(user_id: str, **k: Any) -> None:
            assert await store.set_password(
                user_id,
                password_hash=await asyncio.to_thread(hash_password_for_test, "a-chosen-one-99x"),
                password_generated=False,
                must_change_password=False,
                require_totp=True,
            ), "the holder's conditional write must match here, TOTP is still on"
            await real_disable(user_id, **k)

        monkeypatch.setattr(store, "disable_totp", rotation_lands_first)
        issued = await service.admin_reset_mfa(identity.user_id, actor="another-admin")
        assert issued is not None
        row = await store.get_user(identity.user_id)
        assert row is not None and row.password_generated and not row.totp_enabled
        assert (await service.login(ADMIN_USERNAME, issued.password)).ok
        assert not (await service.login(ADMIN_USERNAME, "a-chosen-one-99x")).ok
        assert any(e.event_type == PASSWORD_RESET for e in notifier.events)
    finally:
        await store.close()


async def test_the_census_reads_every_account_it_should_and_nothing_it_should_not(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A directory account's unusable TOTP secret is named. A local row with no hash is not: nobody
    can sign into it. A keyless read that hands ciphertext through counts as unusable. Any other
    store error is not a finding, so it propagates rather than sending an operator to reset a
    healthy account."""
    from messagefoundry.auth.service import lockable_account_census

    store = await _store()
    try:
        await store.create_user(
            user_id="dir-totp", username="directory", auth_provider="ad", password_generated=False
        )
        await store.set_totp_secret("dir-totp", secret="JBSWY3DPEHPK3PXP")
        await store.enable_totp("dir-totp", recovery_code_hashes=[])
        await store.create_user(
            user_id="hashless",
            username="half-built",
            auth_provider="local",
            password_generated=False,
        )
        real = store.get_totp_secret

        async def ciphertext_through(user_id: str) -> str | None:
            if user_id == "dir-totp":
                return "mfenc:v2:not-a-base32-key"
            return await real(user_id)

        monkeypatch.setattr(store, "get_totp_secret", ciphertext_through)
        census = await lockable_account_census(store, AuthSettings())
        assert census.undecryptable_totp == ("directory",)
        assert census.no_way_past == ()

        async def unreachable(user_id: str) -> str | None:
            raise ConnectionError("synthetic: the store went away")

        monkeypatch.setattr(store, "get_totp_secret", unreachable)
        with pytest.raises(ConnectionError):
            await lockable_account_census(store, AuthSettings())
    finally:
        await store.close()


async def test_a_passkey_can_still_be_revoked_by_a_covered_account_with_no_totp() -> None:
    """Review round 1: removing a passkey cannot take away a way past in wave 1, so a covered
    account holding two passkeys and no TOTP may still remove a lost one."""
    store = await _store()
    try:
        service = AuthService(store, AuthSettings())
        identity, _token, _pw = await login_admin(service)
        for n in (1, 2):
            await store.add_webauthn_credential(
                WebAuthnCredential(
                    credential_id_hash=f"pk-{n}-hash",
                    credential_id=f"pk-{n}-id",
                    user_id=identity.user_id,
                    rp_id="t",
                    public_key="cose-public-key-b64url",
                    sign_count=0,
                    transports=None,
                    device_type="multi_device",
                    backed_up=True,
                    label=f"key {n}",
                    aaguid=None,
                    created_at=1000.0,
                )
            )
        assert await service.delete_webauthn_credential(identity, "pk-1-hash")
        assert len(await store.list_webauthn_credentials(identity.user_id)) == 1
    finally:
        await store.close()
