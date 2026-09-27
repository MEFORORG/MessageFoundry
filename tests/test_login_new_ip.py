# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The first-seen login-address signal (BACKLOG #288, ASVS 8.2.4).

At every session mint the engine compares the sign-in's client address with the account's own
``auth.login_success`` history. A first-seen address writes ``auth.login_new_ip``, sends the
``login_new_ip`` notice, and mints the session WITHOUT step-up freshness. That is a challenge
only: the login itself always succeeds. With nothing to compare against -- the account's first
sign-in ever, or no client address at all -- the signal fails open and audits
``auth.login_address_unevaluated`` with the reason.

Synthetic accounts and RFC 5737 / RFC 1918 addresses only.
"""

from __future__ import annotations

import pytest

from messagefoundry.auth import Role
from messagefoundry.auth import service as service_module
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.ldap import AdPrincipal
from messagefoundry.auth.notifications import LOGIN_NEW_IP, SecurityEvent
from messagefoundry.auth.service import AuthService
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.store import MessageStore

PW = "a-strong-test-passphrase"  # >= 15, no app/vendor terms: satisfies the ASVS policy (WP-3)


class _FakeNotifier:
    def __init__(self) -> None:
        self.events: list[SecurityEvent] = []

    async def notify(self, event: SecurityEvent) -> None:
        self.events.append(event)


class _RaisingNotifier:
    """A notifier that always fails, to prove a broken channel cannot refuse a login."""

    async def notify(self, event: SecurityEvent) -> None:
        raise OSError("synthetic relay failure")


async def _service(
    store: MessageStore, notifier: object | None = None, **over: object
) -> AuthService:
    settings = AuthSettings(require_mfa=False, **over)  # type: ignore[arg-type]
    service = AuthService(store, settings, security_notifier=notifier)  # type: ignore[arg-type]
    await service.initialize()
    return service


async def _operator(service: AuthService, username: str = "oper") -> str:
    uid = await service.create_local_user(
        username=username,
        password=PW,
        display_name=None,
        email=f"{username}@example.org",
        roles=[Role.OPERATOR.value],
        actor="t",
    )
    await service.set_channel_scope(uid, [ALL_CHANNELS], actor="t")
    user = await service.store.get_user(uid)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        uid, password_hash=user.password_hash, must_change_password=False
    )
    return uid


async def _actions(store: MessageStore, username: str) -> list[str]:
    """This account's audit actions, oldest first."""
    rows = await store.list_audit(actor=username, limit=500)
    return [str(r["action"]) for r in reversed(rows)]


async def _seeded(store: MessageStore, token: str | None) -> bool:
    assert token is not None
    session = await store.get_session(hash_token(token))
    assert session is not None
    return session.reauth_at is not None


def _new_ip_notices(notifier: _FakeNotifier) -> list[SecurityEvent]:
    return [e for e in notifier.events if e.event_type == LOGIN_NEW_IP]


async def test_first_login_ever_fails_open_and_audits_no_baseline() -> None:
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        service = await _service(store, notifier)
        await _operator(service)
        out = await service.login("oper", PW, client="10.1.1.1")
        assert out.ok
        assert await _seeded(store, out.token)
        assert _new_ip_notices(notifier) == []
        rows = await store.list_audit(actor="oper", action="auth.login_address_unevaluated")
        assert len(rows) == 1
        assert '"reason": "no_baseline"' in str(rows[0]["detail"])
        assert "auth.login_new_ip" not in await _actions(store, "oper")
        # The login's own row stays the newest one for it.
        assert (await _actions(store, "oper"))[-1] == "auth.login_success"
    finally:
        await store.close()


async def test_a_known_address_writes_nothing_and_keeps_the_seed() -> None:
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        service = await _service(store, notifier)
        await _operator(service)
        assert (await service.login("oper", PW, client="10.1.1.1")).ok
        before = await _actions(store, "oper")
        out = await service.login("oper", PW, client="10.1.1.1")
        assert out.ok
        assert await _seeded(store, out.token)
        added = (await _actions(store, "oper"))[len(before) :]
        assert added == ["auth.login_success"]
        assert _new_ip_notices(notifier) == []
    finally:
        await store.close()


async def test_a_first_seen_address_is_audited_notified_and_unseeded() -> None:
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        service = await _service(store, notifier)
        await _operator(service)
        assert (await service.login("oper", PW, client="10.1.1.1")).ok
        out = await service.login("oper", PW, client="198.51.100.7")
        assert out.ok and out.token is not None and out.identity is not None
        # The challenge: no step-up freshness, so the first sensitive action re-proves a credential.
        assert not await _seeded(store, out.token)
        rows = await store.list_audit(actor="oper", action="auth.login_new_ip")
        assert len(rows) == 1
        assert rows[0]["client"] == "198.51.100.7"
        assert '"provider": "local"' in str(rows[0]["detail"])
        notices = _new_ip_notices(notifier)
        assert len(notices) == 1
        assert notices[0].client_ip == "198.51.100.7"
        assert notices[0].email == "oper@example.org"
        assert (await _actions(store, "oper"))[-1] == "auth.login_success"
        # Once signed in from it, the address is known: the next sign-in is not challenged.
        again = await service.login("oper", PW, client="198.51.100.7")
        assert again.ok and await _seeded(store, again.token)
        assert len(_new_ip_notices(notifier)) == 1
    finally:
        await store.close()


async def test_loopback_forms_are_one_host() -> None:
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        service = await _service(store, notifier)
        await _operator(service)
        assert (await service.login("oper", PW, client="127.0.0.1")).ok
        out = await service.login("oper", PW, client="::1")
        assert out.ok and await _seeded(store, out.token)
        assert _new_ip_notices(notifier) == []
    finally:
        await store.close()


async def test_no_client_address_fails_open_and_audits_unknown_address() -> None:
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        service = await _service(store, notifier)
        await _operator(service)
        assert (await service.login("oper", PW, client="10.1.1.1")).ok
        out = await service.login("oper", PW, client=None)
        assert out.ok and await _seeded(store, out.token)
        rows = await store.list_audit(actor="oper", action="auth.login_address_unevaluated")
        assert any('"reason": "unknown_address"' in str(r["detail"]) for r in rows)
        assert _new_ip_notices(notifier) == []
    finally:
        await store.close()


async def test_an_address_outside_the_lookback_reads_as_new(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A returning account whose history aged out is NOT the first-login case: it has signed in
    before (``last_login_at`` is set), so an unrecognised address is NEW, not unevaluated."""
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        service = await _service(store, notifier)
        await _operator(service)
        assert (await service.login("oper", PW, client="10.1.1.1")).ok
        monkeypatch.setattr(service_module, "_LOGIN_ADDRESS_LOOKBACK_SECONDS", -3600)
        out = await service.login("oper", PW, client="10.1.1.1")
        assert out.ok and not await _seeded(store, out.token)
        assert len(_new_ip_notices(notifier)) == 1
    finally:
        await store.close()


async def test_a_failing_notifier_never_refuses_the_login() -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, _RaisingNotifier())
        await _operator(service)
        assert (await service.login("oper", PW, client="10.1.1.1")).ok
        out = await service.login("oper", PW, client="203.0.113.9")
        assert out.ok and out.token is not None
        assert len(await store.list_audit(actor="oper", action="auth.login_new_ip")) == 1
    finally:
        await store.close()


async def test_a_wrong_password_from_a_new_address_writes_no_signal_row() -> None:
    """The signal runs only after the credential verified, so a failed guess cannot feed it."""
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        service = await _service(store, notifier)
        await _operator(service)
        assert (await service.login("oper", PW, client="10.1.1.1")).ok
        assert not (await service.login("oper", "wrong-" + PW, client="203.0.113.9")).ok
        assert await store.list_audit(actor="oper", action="auth.login_new_ip") == []
        assert _new_ip_notices(notifier) == []
    finally:
        await store.close()


# --- the directory leg (Kerberos and OIDC share _complete_ad_login) ---------------------------


class _FakeLdap:
    def authenticate(self, username: str, password: str) -> AdPrincipal | None:
        return None

    def resolve_principal(self, username: str) -> AdPrincipal | None:
        return None


def _principal(username: str) -> AdPrincipal:
    return AdPrincipal(
        username=username,
        display_name=f"{username} Example",
        email=f"{username}@example.org",
        dn=f"CN={username},DC=x",
        groups=frozenset({"cn=mf-ops,dc=x"}),
        directory_object_id="12345678-1234-1234-1234-56789abcdef0",
    )


async def test_the_directory_leg_audits_and_notifies_a_first_seen_address() -> None:
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        settings = AuthSettings(
            ad_enabled=True,
            ad_server="ldaps://x",
            ad_user_search_base="DC=x",
            ad_bind_dn="CN=svc,DC=x",
            ad_bind_password="x",
        )
        service = AuthService(
            store,
            settings,
            ldap=_FakeLdap(),  # type: ignore[arg-type]
            security_notifier=notifier,
        )
        await service.initialize()
        await service.set_ad_group_map([("CN=MF-Ops,DC=x", "operator")], actor="admin")
        first = await service._complete_ad_login(
            _principal("jsmith"), "10.2.2.2", mfa_verified=True
        )
        assert first.ok
        unevaluated = await store.list_audit(
            actor="jsmith", action="auth.login_address_unevaluated"
        )
        assert len(unevaluated) == 1
        known = await service._complete_ad_login(
            _principal("jsmith"), "10.2.2.2", mfa_verified=True
        )
        assert known.ok
        assert _new_ip_notices(notifier) == []
        new = await service._complete_ad_login(
            _principal("jsmith"), "198.51.100.44", mfa_verified=True
        )
        assert new.ok
        rows = await store.list_audit(actor="jsmith", action="auth.login_new_ip")
        assert len(rows) == 1 and '"provider": "ad"' in str(rows[0]["detail"])
        assert [e.client_ip for e in _new_ip_notices(notifier)] == ["198.51.100.44"]
        # Every directory login is already born unseeded; the signal does not change that.
        assert not await _seeded(store, new.token)
    finally:
        await store.close()


async def test_a_password_step_row_that_still_owed_a_factor_is_not_a_baseline() -> None:
    """Review finding, BACKLOG #288: ``auth.login_success`` is written at the PASSWORD step, even
    when a second factor is still owed. A holder of the password alone must not be able to plant an
    address as known by stopping at the MFA prompt. The factor leg's own row does count."""
    store = await MessageStore.open(":memory:")
    try:
        baseline = await _service(store)
        await _operator(baseline)
        assert (await baseline.login("oper", PW, client="10.1.1.1")).ok
        notifier = _FakeNotifier()
        owed = AuthService(store, AuthSettings(require_mfa=True), security_notifier=notifier)
        await owed.initialize()
        first = await owed.login("oper", PW, client="203.0.113.5")
        assert first.ok and first.mfa_required
        second = await owed.login("oper", PW, client="203.0.113.5")
        assert second.ok and second.mfa_required
        # Both attempts read as NEW: the first one's password-step row did not make the address known.
        assert len(await store.list_audit(actor="oper", action="auth.login_new_ip")) == 2
        # The audit row is written every time; the notice is debounced per account.
        assert len(_new_ip_notices(notifier)) == 1
        # A finished second factor from that address is what makes it known.
        await store.record_audit("auth.mfa_verified", actor="oper", client="203.0.113.5")
        assert (await owed.login("oper", PW, client="203.0.113.5")).ok
        assert len(await store.list_audit(actor="oper", action="auth.login_new_ip")) == 2
    finally:
        await store.close()


async def test_a_failed_history_read_fails_open(monkeypatch: pytest.MonkeyPatch) -> None:
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        service = await _service(store, notifier)
        await _operator(service)
        assert (await service.login("oper", PW, client="10.1.1.1")).ok

        async def _broken(**_kw: object) -> list[object]:
            raise RuntimeError("synthetic store fault")

        real = store.list_audit
        monkeypatch.setattr(store, "list_audit", _broken)
        out = await service.login("oper", PW, client="203.0.113.9")
        monkeypatch.setattr(store, "list_audit", real)
        assert out.ok and await _seeded(store, out.token)
        rows = await store.list_audit(actor="oper", action="auth.login_address_unevaluated")
        assert any('"reason": "read_failed"' in str(r["detail"]) for r in rows)
        assert _new_ip_notices(notifier) == []
    finally:
        await store.close()
