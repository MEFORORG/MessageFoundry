# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1138, ASVS 6.3.5: a failed re-authentication counts toward the engine account lockout.

Owner ruling 2026-09-23: failed re-authentication and step-up attempts count, directory (AD) accounts
included. Before this change the post-session credential ceremonies -- ``POST /me/reauth`` (and the
console's ``POST /ui/reauth``, which calls the same ``AuthService.reauth``) and ``POST /me/password``
-- verified a password without counting a failure or checking ``locked_until``. So someone holding a
stolen session could guess the password with no bound but the per-actor ceremony budget, and could
keep guessing after the account was locked.

These tests reuse the LOGIN leg's policy as the yardstick: the same counter, the same threshold, the
same refusal of a locked account, the same ``auth.account_locked`` / ``auth.login_after_failures``
rows, and the same clearing rules. Engine lockout sets ``locked_until`` on the engine's own row; it
never writes to the directory, which is why it is safe to apply to an AD account.

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


# --- (b) a locked account is refused at re-auth and at the password change ----------------------


async def test_a_locked_account_is_refused_reauth_even_with_the_right_password() -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(lockout_threshold=3, require_mfa=False))
        await _local_user(store)
        identity, token = await _signed_in(service)
        for _ in range(3):
            await service.reauth(identity, WRONG, token=token)
        attempts_at_lock, locked_until_at_lock = await _lock_state(store, "u-bob")
        assert locked_until_at_lock is not None

        out = await service.reauth(identity, GOOD, token=token, purpose="mfa_enroll")
        assert not out.ok and out.token is None and not out.session_lost
        assert await service.identity_for_token(token) is not None, "nothing rotated"
        assert not await service.has_action_step_up(token, "mfa_enroll"), "no grant was minted"

        # (5) Refusing a locked account must not re-arm or extend the lock, which the login leg never
        # does either: its pre-check refuses before any failure is registered.
        await service.reauth(identity, WRONG, token=token)
        assert await _lock_state(store, "u-bob") == (attempts_at_lock, locked_until_at_lock)

        # The refusal is audited once, on the attempt's own row, and says why.
        rows = [r for r in await store.list_audit(limit=100) if r["action"] == "auth.reauth"]
        assert len(rows) == 5
        assert '"locked": true' in str(rows[0]["detail"])
    finally:
        await store.close()


async def test_a_locked_account_cannot_verify_its_current_password() -> None:
    """``POST /me/password`` re-proves the current password, so it is a re-auth ceremony too."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(lockout_threshold=3, require_mfa=False))
        await _local_user(store)
        identity, _ = await _signed_in(service)

        for _ in range(3):
            assert not await service.verify_current_password(identity, WRONG, client="10.0.0.8")
        state = await _lock_state(store, "u-bob")
        assert state[1] is not None, "wrong current passwords must lock the account"

        assert not await service.verify_current_password(identity, GOOD, client="10.0.0.8")
        assert await _lock_state(store, "u-bob") == state, "a refusal must not extend the lock"

        feed = await service.security_events_for("bob")
        assert len(_actions(feed, "auth.account_locked")) == 1
        # Each attempt is audited once. Before this change a failed current-password check wrote
        # nothing at all, so a guessing run was invisible in the user's feed.
        failed = _actions(feed, "auth.password_change_failed")
        assert len(failed) == 4
        assert failed[0]["detail"] == '{"reason": "locked"}'
        assert failed[-1]["detail"] == '{"reason": "bad_password"}'
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
        assert len(_actions(feed, "auth.reauth")) == 3, "each attempt audited exactly once"

        notices = [e for e in notifier.events if e.event_type == ACCOUNT_LOCKED]
        assert len(notices) == 1
        assert notices[0].detail == {"failed_attempts": 3}
        assert notices[0].client_ip == "10.0.0.9"
    finally:
        await store.close()


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "reauth-lockout.db", poll_interval=0.02)
    yield eng
    await eng.stop()


async def _api_user(service: AuthService) -> None:
    user_id = await service.create_local_user(
        username="carol",
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


async def test_the_json_routes_lock_the_account_and_the_feed_shows_it(engine: Engine) -> None:
    service = AuthService(engine.store, AuthSettings(lockout_threshold=3, require_mfa=False))
    await service.initialize()
    await _api_user(service)
    transport = httpx.ASGITransport(app=create_app(engine, auth=service))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.post(
            "/auth/login", json={"username": "carol", "password": GOOD, "provider": "local"}
        )
        assert r.status_code == 200, r.text
        headers = {"Authorization": f"Bearer {r.json()['token']}"}

        # Two wrong re-auths and one wrong current password: one counter, three failures.
        for _ in range(2):
            r = await c.post("/me/reauth", headers=headers, json={"password": WRONG})
            assert r.status_code == 403
        r = await c.post(
            "/me/password",
            headers=headers,
            json={"current_password": WRONG, "new_password": NEW_GOOD},
        )
        assert r.status_code == 403

        # Locked: the right password is refused on both routes, and the password is not changed.
        assert (
            await c.post("/me/reauth", headers=headers, json={"password": GOOD})
        ).status_code == 403
        r = await c.post(
            "/me/password",
            headers=headers,
            json={"current_password": GOOD, "new_password": NEW_GOOD},
        )
        assert r.status_code == 403

        feed = await c.get("/me/security-events", headers=headers)
        assert feed.status_code == 200, feed.text
        body = feed.json()
        events = body["events"] if isinstance(body, dict) else body
        assert [e["action"] for e in events].count("auth.account_locked") == 1
    assert not (await service.login("carol", NEW_GOOD)).ok, "the locked change must not have landed"


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

    def authenticate(self, username: str, password: str) -> AdPrincipal | None:
        self.binds += 1
        if self.down:
            raise LdapError("synthetic: directory unreachable")
        return _principal() if password == AD_GOOD else None

    def resolve_principal(self, username: str, **_: object) -> AdPrincipal | None:
        return _principal()


async def _ad_service(store: MessageStore, directory: _FakeDirectory) -> AuthService:
    settings = AuthSettings(
        ad_enabled=True,
        ad_server="ldaps://dc.test.invalid",
        ad_user_search_base="OU=Staff,DC=test,DC=invalid",
        ad_bind_dn="CN=svc,OU=Service,DC=test,DC=invalid",
        ad_bind_password="synthetic",
        lockout_threshold=3,
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

        # Locked: the engine refuses BEFORE asking the directory, so a locked engine row never feeds
        # guesses to the domain's own lockout counter.
        binds_before = directory.binds
        assert not (await service.reauth(identity, AD_GOOD, token=token)).ok
        assert directory.binds == binds_before
    finally:
        await store.close()


def test_the_security_doc_says_reauth_counts_and_does_not_lock_the_directory() -> None:
    doc = (Path(__file__).resolve().parents[1] / "docs" / "SECURITY.md").read_text(encoding="utf-8")
    assert "auth.account_locked" in doc and "auth.login_after_failures" in doc
    assert "auth.password_change_failed" in doc
    assert "never locks the directory account" in doc


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

        # Timed expiry: move the stored deadline into the past, as the clock would.
        await store.record_login_failure("u-bob", failed_attempts=attempts, locked_until=1.0)
        assert (await service.reauth(identity, GOOD, token=token)).ok

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

    identity, token = asyncio.run(lock())
    assert main(["admin-unlock", "--username", "admin", "--db", str(db)]) == 0
    capsys.readouterr()

    async def reauth_after_unlock() -> bool:
        store = await MessageStore.open(db)
        try:
            service = AuthService(store, AuthSettings(lockout_threshold=3, require_mfa=False))
            return (await service.reauth(identity, GOOD, token=token)).ok
        finally:
            await store.close()

    assert asyncio.run(reauth_after_unlock()), "admin-unlock must lift a lock that re-auth set"
