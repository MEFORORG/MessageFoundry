# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1138, ASVS 6.3.5: re-proof failures count toward the account lockout, and each session
gets a bounded number of them.

Owner ruling 2026-09-23: failed re-authentication and step-up attempts count toward engine account
lockout, directory (AD) accounts included. Before this change the post-session credential ceremonies
-- ``POST /me/reauth`` (and the console's ``POST /ui/reauth``, which calls the same
``AuthService.reauth``) and ``POST /me/password`` -- verified a password without counting a failure.
So someone holding a stolen session could guess the password with no bound but the per-actor
ceremony budget.

How the tests read the ruling (design E, Manager decision 2026-09-24): a re-proof failure counts on
the account's shared counter, so it can lock the account and fire ``ACCOUNT_LOCKED``; the lock gates
SIGN-IN, not the re-proofs of a session that already exists; and each session may fail at most
``lockout_threshold`` re-proofs before that session is revoked. A stolen session therefore gets that
many guesses in total, and an attacker who can only lock the account from the sign-in page cannot
take step-up away from the owner's live sessions.

All credentials and directory data here are synthetic.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from _totp_clock import fresh_totp

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.identity import Identity
from messagefoundry.auth.ldap import AdPrincipal, LdapError
from messagefoundry.auth.notifications import (
    ACCOUNT_LOCKED,
    LOGIN_AFTER_FAILURES,
    SUSPICIOUS_LOGIN_FAILURE_THRESHOLD,
    SecurityEvent,
)
from messagefoundry.auth.passwords import hash_password
from messagefoundry.auth.service import AuthService
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store.store import MessageStore

GOOD = "Synth3tic-Pass-Phrase!!"
WRONG = "not-the-password"
NEW_GOOD = "Another-synth3tic-phrase!!"
AD_GOOD = "synthetic-ad-good"


@pytest.fixture(autouse=True)
def _no_failure_pad(monkeypatch: pytest.MonkeyPatch) -> None:
    # The login leg pads a failure to a deadline in real time; tests/test_asvs_login_deadline.py owns
    # that property and nothing here asserts on timing.
    async def _no_sleep(deadline: float) -> None:
        return None

    monkeypatch.setattr("messagefoundry.auth.service._sleep_until", _no_sleep)


class _FakeNotifier:
    def __init__(self) -> None:
        self.events: list[SecurityEvent] = []

    async def notify(self, event: SecurityEvent) -> None:
        self.events.append(event)


def _actions(feed: list[dict[str, Any]], action: str) -> list[dict[str, Any]]:
    return [e for e in feed if e["action"] == action]


async def _local_user(store: MessageStore, username: str = "bob") -> None:
    await store.upsert_role(role_id="viewer", display_name="Viewer")
    await store.create_user(
        user_id=f"u-{username}",
        username=username,
        auth_provider="local",
        email=None,
        password_hash=hash_password(GOOD),
    )


async def _signed_in(service: AuthService, username: str = "bob") -> tuple[Identity, str]:
    out = await service.login(username, GOOD, client="10.0.0.7")
    assert out.ok and out.identity is not None and out.token is not None, out.error
    return out.identity, out.token


async def _lock_state(store: MessageStore, user_id: str) -> tuple[int, float | None]:
    user = await store.get_user(user_id)
    assert user is not None
    return user.failed_attempts, user.locked_until


async def _session_revoked(store: MessageStore, token: str) -> bool:
    session = await store.get_session(hash_token(token))
    return session is None or session.revoked_at is not None


async def _lock_by_sign_in(service: AuthService, username: str, attempts: int) -> None:
    for _ in range(attempts):
        assert not (await service.login(username, WRONG)).ok


# --- (a) re-auth failures lock the account at the login threshold -------------------------------


async def test_failed_reauth_attempts_lock_the_account_at_the_login_threshold() -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(lockout_threshold=3, require_mfa=False))
        await _local_user(store)
        identity, token = await _signed_in(service)

        for _ in range(2):
            out = await service.reauth(identity, WRONG, token=token, client="10.0.0.7")
            assert not out.ok and not out.session_lost
        attempts, locked_until = await _lock_state(store, "u-bob")
        assert attempts == 2, "every failed re-auth must be counted on the account's row"
        assert locked_until is None, "below the threshold the account stays unlocked"

        # The crossing attempt.
        await service.reauth(identity, WRONG, token=token, client="10.0.0.7")
        _, locked_until = await _lock_state(store, "u-bob")
        assert locked_until is not None and locked_until > time.time()

        # The SAME lock the login leg enforces: a correct password at sign-in is now refused.
        refused = await service.login("bob", GOOD)
        assert not refused.ok and refused.error == "account locked"
    finally:
        await store.close()


async def test_reauth_and_login_failures_share_one_counter() -> None:
    """Not a parallel counter: one wrong sign-in plus two wrong re-auths is three, and locks."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(lockout_threshold=3, require_mfa=False))
        await _local_user(store)
        identity, token = await _signed_in(service)  # a clean sign-in, counter at zero

        assert not (await service.login("bob", WRONG)).ok
        for _ in range(2):
            assert not (await service.reauth(identity, WRONG, token=token)).ok
        _, locked_until = await _lock_state(store, "u-bob")
        assert locked_until is not None, "login and re-auth failures must feed one counter"
    finally:
        await store.close()


# --- (b) the lock gates sign-in, not the re-proofs of a live session ------------------------------


async def test_a_sign_in_lock_does_not_block_step_up_on_a_live_session() -> None:
    """An attacker who only knows the username can lock the account from the sign-in page, every
    lock window, indefinitely. If that lock also refused re-proofs, the owner's live sessions would
    lose step-up for as long as the attacker kept it up. The lock gates sign-in only."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(require_mfa=False))
        await _local_user(store)
        identity, token = await _signed_in(service)
        await _lock_by_sign_in(service, "bob", service.policy.lockout_threshold)
        attempts, locked_until = await _lock_state(store, "u-bob")
        assert locked_until is not None

        out = await service.reauth(identity, GOOD, token=token)
        assert out.ok and out.token is not None, "a live session must keep step-up during a lock"
        # The lock stands: a good re-proof during it neither lifts nor restarts the counter.
        assert await _lock_state(store, "u-bob") == (attempts, locked_until)
        assert not (await service.login("bob", GOOD)).ok, "sign-in stays locked"
    finally:
        await store.close()


async def _api_user(service: AuthService, username: str = "carol") -> None:
    user_id = await service.create_local_user(
        username=username,
        password=GOOD,
        display_name=None,
        email=None,
        roles=[Role.VIEWER.value],
        actor="test",
    )
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id, password_hash=user.password_hash, must_change_password=False
    )


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "reauth-lockout.db", poll_interval=0.02)
    yield eng
    await eng.stop()


async def _api_login(c: httpx.AsyncClient, username: str = "carol") -> dict[str, str]:
    r = await c.post(
        "/auth/login", json={"username": username, "password": GOOD, "provider": "local"}
    )
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


async def test_a_sign_in_lock_does_not_block_a_password_change_on_a_live_session(
    engine: Engine,
) -> None:
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    await _api_user(service)
    transport = httpx.ASGITransport(app=create_app(engine, auth=service))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        headers = await _api_login(c)
        await _lock_by_sign_in(service, "carol", service.policy.lockout_threshold)
        locked = await service.store.get_user_by_username("carol")
        assert locked is not None and locked.locked_until is not None

        r = await c.post(
            "/me/password",
            headers=headers,
            json={"current_password": GOOD, "new_password": NEW_GOOD},
        )
        assert r.status_code == 200, r.text
    changed = await service.store.get_user_by_username("carol")
    assert changed is not None and changed.password_hash != locked.password_hash
    # The owner's own rotation is an in-band way out of the lock again, as it was before #1138.
    assert changed.locked_until is None


async def test_a_reproof_failure_does_not_extend_a_live_lock() -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(require_mfa=False))
        await _local_user(store)
        identity, token = await _signed_in(service)
        await _lock_by_sign_in(service, "bob", service.policy.lockout_threshold)
        before = await _lock_state(store, "u-bob")
        assert before[1] is not None

        out = await service.reauth(identity, WRONG, token=token)
        assert not out.ok and not out.locked, "checked as a wrong password, not refused as locked"
        assert await _lock_state(store, "u-bob") == before, "the lock must not be re-armed"
        # It is still charged to the session.
        assert service._reproof_session_failures[hash_token(token)] == 1
    finally:
        await store.close()


# --- (b2) each session gets at most lockout_threshold failed re-proofs ----------------------------


async def test_a_sessions_reproof_budget_revokes_it_at_the_threshold(engine: Engine) -> None:
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    await _api_user(service)
    identity, token = await _signed_in(service, "carol")
    threshold = service.policy.lockout_threshold
    for _ in range(threshold - 1):
        out = await service.reauth(identity, WRONG, token=token)
        assert not out.ok and not out.session_lost
    out = await service.reauth(identity, WRONG, token=token)
    assert out.session_lost, "the threshold-th failure must end the session"
    assert await _session_revoked(service.store, token)

    transport = httpx.ASGITransport(app=create_app(engine, auth=service))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.post(
            "/me/reauth", headers={"Authorization": f"Bearer {token}"}, json={"password": GOOD}
        )
        assert r.status_code == 401


async def test_a_stolen_session_gets_at_most_threshold_guesses_across_lock_cycles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The account lock releases itself every lock window. Charged only to the account, a stolen
    session would get ``threshold`` guesses per window, forever. Charged to the session, it gets
    ``threshold`` in total."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(require_mfa=False))
        await _local_user(store)
        identity, token = await _signed_in(service)
        verifies = 0
        real_argon2 = service._argon2

        async def counting(fn: Any, *args: Any) -> Any:
            nonlocal verifies
            verifies += 1
            return await real_argon2(fn, *args)

        monkeypatch.setattr(service, "_argon2", counting)
        for _ in range(4 * service.policy.lockout_threshold):
            await service.reauth(identity, WRONG, token=token)
            attempts, locked_until = await _lock_state(store, "u-bob")
            if locked_until is not None:  # the lock window passes, as the clock would move it
                await store.record_login_failure(
                    "u-bob", failed_attempts=attempts, locked_until=time.time() - 1
                )
        assert verifies == service.policy.lockout_threshold
    finally:
        await store.close()


async def test_a_parallel_burst_on_one_session_is_capped_at_the_threshold() -> None:
    """Re-proofs for one account run one at a time and check the session first, so a burst queued
    on one session cannot be verified past its budget, and a correct guess behind it is refused."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(lockout_threshold=3, require_mfa=False))
        await _local_user(store)
        identity, token = await _signed_in(service)
        burst = [service.reauth(identity, WRONG, token=token) for _ in range(8)]
        burst.append(service.reauth(identity, GOOD, token=token))
        results = await asyncio.gather(*burst)
        assert not results[-1].ok, "a correct guess queued behind the cap must be refused"
        attempts, locked_until = await _lock_state(store, "u-bob")
        assert attempts == 3 and locked_until is not None
        assert await _session_revoked(store, token)
        assert service._reproof_locks == {}, "the per-account lock entry must not leak"
        assert hash_token(token) not in service._reproof_session_failures
    finally:
        await store.close()


async def test_a_lock_set_by_another_leg_during_the_verify_does_not_block_or_get_cleared(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A sign-in failure can lock the account while a re-proof waits on its verify. The re-proof
    still succeeds, since the lock gates sign-in only, and it must not clear the lock it did not see
    at the start."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(lockout_threshold=3, require_mfa=False))
        await _local_user(store)
        identity, token = await _signed_in(service)
        assert not (await service.login("bob", WRONG)).ok  # one earlier failure on the row
        real_argon2 = service._argon2

        async def lock_lands_mid_verify(fn: Any, *args: Any) -> Any:
            result = await real_argon2(fn, *args)
            await store.record_login_failure(
                "u-bob", failed_attempts=3, locked_until=time.time() + 900
            )
            return result

        monkeypatch.setattr(service, "_argon2", lock_lands_mid_verify)
        out = await service.reauth(identity, GOOD, token=token)
        assert out.ok
        attempts, locked_until = await _lock_state(store, "u-bob")
        assert locked_until is not None and attempts == 3, "the re-proof lifted a live lock"
    finally:
        await store.close()


async def test_a_wrong_current_password_counts_and_is_audited_once() -> None:
    """``POST /me/password`` re-proves the current password, so it is a re-auth ceremony too."""
    # Imported here so the module still collects against a tree that predates the type.
    from messagefoundry.auth.service import CurrentPasswordCheck

    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(lockout_threshold=3, require_mfa=False))
        await _local_user(store)
        identity, token = await _signed_in(service)
        for _ in range(2):
            got = await service.verify_current_password(
                identity, WRONG, token=token, client="10.0.0.8"
            )
            assert got is CurrentPasswordCheck.WRONG
        got = await service.verify_current_password(identity, WRONG, token=token, client="10.0.0.8")
        assert got is CurrentPasswordCheck.SESSION_ENDED
        assert (await _lock_state(store, "u-bob"))[1] is not None

        feed = await service.security_events_for("bob")
        locked = _actions(feed, "auth.account_locked")
        assert len(locked) == 1
        assert locked[0]["detail"] is None  # no richer than the attempt's own row
        failed = _actions(feed, "auth.password_change_failed")
        assert [f["detail"] for f in failed] == [
            '{"reason": "session_revoked"}',
            '{"reason": "bad_password"}',
            '{"reason": "bad_password"}',
        ]
    finally:
        await store.close()


# --- (c) the crossing attempt is audited and reaches the feed -----------------------------------


async def test_the_reauth_crossing_attempt_audits_account_locked_once_and_notifies() -> None:
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        service = AuthService(
            store,
            AuthSettings(lockout_threshold=3, require_mfa=False),
            security_notifier=notifier,
        )
        await _local_user(store)
        identity, token = await _signed_in(service)
        for _ in range(3):
            await service.reauth(identity, WRONG, token=token, client="10.0.0.9")

        feed = await service.security_events_for("bob")
        locked = _actions(feed, "auth.account_locked")
        assert len(locked) == 1
        # Mirrors the auth.reauth row beside it; the failure count stays in the notice.
        assert locked[0]["detail"] == '{"provider": "local"}'
        reauths = _actions(feed, "auth.reauth")
        assert len(reauths) == 3, "each attempt audited exactly once"
        assert '"session_revoked": true' in str(reauths[0]["detail"])
        assert '"session_revoked": false' in str(reauths[-1]["detail"])

        notices = [e for e in notifier.events if e.event_type == ACCOUNT_LOCKED]
        assert len(notices) == 1
        assert notices[0].detail == {"failed_attempts": 3}
        assert notices[0].client_ip == "10.0.0.9"
    finally:
        await store.close()


async def test_the_json_routes_count_end_the_session_and_the_feed_shows_it(
    engine: Engine,
) -> None:
    service = AuthService(engine.store, AuthSettings(lockout_threshold=3, require_mfa=False))
    await service.initialize()
    await _api_user(service)
    transport = httpx.ASGITransport(app=create_app(engine, auth=service))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        headers = await _api_login(c)
        before = await service.store.get_user_by_username("carol")
        assert before is not None

        # Two wrong re-auths and one wrong current password: one counter, three failures. The third
        # also exhausts this session's budget, so it ends the session.
        for _ in range(2):
            r = await c.post("/me/reauth", headers=headers, json={"password": WRONG})
            assert r.status_code == 403
        r = await c.post(
            "/me/password",
            headers=headers,
            json={"current_password": WRONG, "new_password": NEW_GOOD},
        )
        assert r.status_code == 401 and r.json()["detail"] == "session ended; sign in again"

        # The session is gone: even the right password gets nowhere on it.
        r = await c.post("/me/reauth", headers=headers, json={"password": GOOD})
        assert r.status_code == 401
        r = await c.post(
            "/me/password",
            headers=headers,
            json={"current_password": GOOD, "new_password": NEW_GOOD},
        )
        assert r.status_code == 401
    after = await service.store.get_user_by_username("carol")
    assert after is not None and after.password_hash == before.password_hash
    assert after.locked_until is not None
    feed = await service.security_events_for("carol")
    assert [e["action"] for e in feed].count("auth.account_locked") == 1


# --- (d) a directory account's failed re-bind counts toward ENGINE lockout ----------------------


def _principal() -> AdPrincipal:
    return AdPrincipal(
        username="dana",
        display_name="Dana",
        email="dana@test.invalid",
        dn="CN=dana,OU=Staff,DC=test,DC=invalid",
        groups=frozenset({"CN=mf-operators,OU=Groups,DC=test,DC=invalid"}),
    )


class _FakeDirectory:
    """Accepts one synthetic credential; ``down`` simulates an unreachable directory."""

    def __init__(self) -> None:
        self.binds = 0
        self.down = False
        self.known = True  # False = the directory has no such principal (renamed, disabled, ...)

    def authenticate(self, username: str, password: str) -> AdPrincipal | None:
        self.binds += 1
        if self.down:
            raise LdapError("synthetic: directory unreachable")
        return _principal() if password == AD_GOOD and self.known else None

    def resolve_principal(self, username: str, **_: object) -> AdPrincipal | None:
        return _principal() if self.known else None


async def _ad_service(
    store: MessageStore, directory: _FakeDirectory, *, threshold: int = 3
) -> AuthService:
    settings = AuthSettings(
        ad_enabled=True,
        ad_server="ldaps://dc.test.invalid",
        ad_user_search_base="OU=Staff,DC=test,DC=invalid",
        ad_bind_dn="CN=svc,OU=Service,DC=test,DC=invalid",
        ad_bind_password="synthetic",
        lockout_threshold=threshold,
        require_mfa=False,
    )
    service = AuthService(store, settings, ldap=directory)  # type: ignore[arg-type]
    await service.initialize()
    await service.set_ad_group_map(
        [("CN=mf-operators,OU=Groups,DC=test,DC=invalid", Role.VIEWER.value)], actor="test"
    )
    return service


async def test_a_directory_accounts_failed_rebind_counts_toward_engine_lockout() -> None:
    store = await MessageStore.open(":memory:")
    try:
        directory = _FakeDirectory()
        service = await _ad_service(store, directory)
        out = await service._complete_ad_login(_principal(), None, mfa_verified=True)
        assert out.ok and out.identity is not None and out.token is not None, out.error
        identity, token = out.identity, out.token

        # A directory OUTAGE is not a guess: it must not count, or a DC blip would lock every
        # operator who tried to step up during it.
        directory.down = True
        assert not (await service.reauth(identity, AD_GOOD, token=token)).ok
        assert (await _lock_state(store, identity.user_id))[0] == 0
        directory.down = False

        # Nor is a principal the directory cannot find: every re-bind fails whatever is typed, so
        # counting it would lock the engine row, and so the Kerberos and OIDC sign-ins, for nothing.
        directory.known = False
        for _ in range(3):
            assert not (await service.reauth(identity, AD_GOOD, token=token)).ok
        assert (await _lock_state(store, identity.user_id))[0] == 0
        directory.known = True

        for _ in range(3):
            assert not (await service.reauth(identity, WRONG, token=token)).ok
        _, locked_until = await _lock_state(store, identity.user_id)
        assert locked_until is not None, (
            "a rejected directory re-bind must count toward engine lockout"
        )

        feed = await service.security_events_for("dana")
        locked = _actions(feed, "auth.account_locked")
        assert len(locked) == 1
        assert locked[0]["detail"] == '{"provider": "ad"}'

        # The third rejected bind also spent the session's budget: it is revoked, and nothing more
        # reaches the directory through it.
        assert await _session_revoked(store, token)
        binds_before = directory.binds
        assert (await service.reauth(identity, AD_GOOD, token=token)).session_lost
        assert directory.binds == binds_before
    finally:
        await store.close()


async def test_an_ad_session_sends_at_most_threshold_binds() -> None:
    """Each rejected re-bind reaches the DC and counts there too. Charged only to the engine lock,
    a stolen session would send ``threshold`` binds every lock window, which a domain lockout policy
    can turn into a domain lockout. Charged to the session, it sends ``threshold`` in total."""
    store = await MessageStore.open(":memory:")
    try:
        directory = _FakeDirectory()
        service = await _ad_service(store, directory, threshold=5)
        out = await service._complete_ad_login(_principal(), None, mfa_verified=True)
        assert out.ok and out.identity is not None and out.token is not None, out.error
        for _ in range(20):
            await service.reauth(out.identity, WRONG, token=out.token)
            attempts, locked_until = await _lock_state(store, out.identity.user_id)
            if locked_until is not None:  # the lock window passes
                await store.record_login_failure(
                    out.identity.user_id, failed_attempts=attempts, locked_until=time.time() - 1
                )
        assert directory.binds == 5, "the 6th attempt must never reach the directory"
    finally:
        await store.close()


def test_the_security_doc_says_reauth_counts_and_does_not_lock_the_directory() -> None:
    doc = (Path(__file__).resolve().parents[1] / "docs" / "SECURITY.md").read_text(encoding="utf-8")
    assert "auth.account_locked" in doc and "auth.login_after_failures" in doc
    assert "auth.password_change_failed" in doc
    assert "never writes a lock to the directory account" in doc


# --- (e) a successful re-auth after failures is labelled like a login after failures ------------


async def test_a_reauth_success_after_failures_is_flagged_and_clears_the_counter() -> None:
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        service = AuthService(
            store,
            AuthSettings(lockout_threshold=10, require_mfa=False),
            security_notifier=notifier,
        )
        await _local_user(store)
        identity, token = await _signed_in(service)
        for _ in range(SUSPICIOUS_LOGIN_FAILURE_THRESHOLD):
            await service.reauth(identity, WRONG, token=token)
        out = await service.reauth(identity, GOOD, token=token, client="10.0.0.4")
        assert out.ok and out.token is not None

        feed = await service.security_events_for("bob")
        flagged = _actions(feed, "auth.login_after_failures")
        assert len(flagged) == 1
        assert flagged[0]["detail"] == '{"provider": "local"}'
        notices = [e for e in notifier.events if e.event_type == LOGIN_AFTER_FAILURES]
        assert [n.detail for n in notices] == [
            {"failed_attempts": SUSPICIOUS_LOGIN_FAILURE_THRESHOLD}
        ]
        # Full authentication on a session that owes no factor clears the counter, as login does.
        assert (await _lock_state(store, "u-bob"))[0] == 0
        assert (await service.reauth(identity, GOOD, token=out.token)).ok
        assert (
            len(_actions(await service.security_events_for("bob"), "auth.login_after_failures"))
            == 1
        )
    finally:
        await store.close()


async def test_a_reauth_success_one_failure_short_is_not_flagged() -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(lockout_threshold=10, require_mfa=False))
        await _local_user(store)
        identity, token = await _signed_in(service)
        for _ in range(SUSPICIOUS_LOGIN_FAILURE_THRESHOLD - 1):
            await service.reauth(identity, WRONG, token=token)
        assert (await service.reauth(identity, GOOD, token=token)).ok
        assert not _actions(await service.security_events_for("bob"), "auth.login_after_failures")
    finally:
        await store.close()


async def test_a_password_reauth_on_an_mfa_pending_session_does_not_clear_code_failures() -> None:
    """BACKLOG #1638 parity. The counter clears at FULL authentication. A password re-auth on a
    session still owing its second factor is not that, so it must not shed a run of wrong codes --
    otherwise password, four wrong codes, re-auth, four wrong codes would never lock."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(lockout_threshold=5, mfa_recovery_code_count=2))
        boot = await service.initialize()
        assert boot is not None
        first = await service.login("admin", boot.password)
        assert first.ok and first.identity is not None and first.token is not None
        enroll = await service.begin_mfa_enrollment(first.identity)
        assert (
            await service.confirm_mfa_enrollment(
                first.identity, fresh_totp(enroll.secret), token=first.token
            )
        ).ok

        pending = await service.login("admin", boot.password)
        assert pending.ok and pending.identity is not None and pending.token is not None
        live = fresh_totp(enroll.secret)
        wrong_code = f"{(int(live[0]) + 1) % 10}{live[1:]}"
        for _ in range(2):
            assert not (await service.verify_mfa(pending.token, wrong_code)).ok
        assert (await service.reauth(pending.identity, boot.password, token=pending.token)).ok
        user = await store.get_user_by_username("admin")
        assert user is not None and user.failed_attempts == 2
    finally:
        await store.close()


# --- (4) clearing rules match login's ------------------------------------------------------------


async def test_a_reauth_lock_expires_on_the_login_clock_and_an_admin_reset_clears_it() -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(lockout_threshold=3, require_mfa=False))
        await _local_user(store)
        identity, token = await _signed_in(service)
        for _ in range(3):
            await service.reauth(identity, WRONG, token=token)
        attempts, locked_until = await _lock_state(store, "u-bob")
        assert locked_until is not None

        assert not (await service.login("bob", GOOD)).ok, "sign-in is locked"
        # Timed expiry: move the stored deadline into the past, as the clock would. The session that
        # failed three times was revoked, so the proof is a fresh sign-in.
        await store.record_login_failure("u-bob", failed_attempts=attempts, locked_until=1.0)
        assert (await service.login("bob", GOOD)).ok

        identity, token = await _signed_in(service)
        for _ in range(3):
            await service.reauth(identity, WRONG, token=token)
        assert (await _lock_state(store, "u-bob"))[1] is not None
        await service.admin_reset_password("u-bob", actor="test-admin")
        assert (await _lock_state(store, "u-bob"))[1] is None, "the admin reset clears the lock"
    finally:
        await store.close()


def test_the_admin_unlock_cli_clears_a_lock_set_by_reauth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from messagefoundry.__main__ import main

    monkeypatch.chdir(tmp_path)
    db = tmp_path / "reauth-unlock.db"

    async def lock() -> tuple[Identity, str]:
        store = await MessageStore.open(db)
        try:
            service = AuthService(store, AuthSettings(lockout_threshold=3, require_mfa=False))
            await _local_user(store, "admin")
            identity, token = await _signed_in(service, "admin")
            for _ in range(3):
                await service.reauth(identity, WRONG, token=token)
            assert (await _lock_state(store, "u-admin"))[1] is not None
            return identity, token
        finally:
            await store.close()

    asyncio.run(lock())
    assert main(["admin-unlock", "--username", "admin", "--db", str(db)]) == 0
    capsys.readouterr()

    async def sign_in_after_unlock() -> bool:
        store = await MessageStore.open(db)
        try:
            service = AuthService(store, AuthSettings(lockout_threshold=3, require_mfa=False))
            # The session that failed three times was revoked, so the proof is a fresh sign-in.
            return (await service.login("admin", GOOD)).ok
        finally:
            await store.close()

    assert asyncio.run(sign_in_after_unlock()), "admin-unlock must lift a lock that re-auth set"
