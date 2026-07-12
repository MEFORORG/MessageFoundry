# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Admin-interface defense-in-depth: the new-client-IP contextual-risk signal (WP-L3-13, ASVS 8.4.2).

When ``[auth].admin_new_ip_step_up`` is on, a step-up (sensitive admin) request arriving from a client
address the session has not verified from is treated as higher-risk: it audits + notifies and FORCES a
fresh step-up, which a successful ``POST /me/reauth`` from that address clears (re-anchoring the
session). It is advisory + step-up-forcing only — it never changes an authz decision and never blocks
the non-admin request path. Default off, and a single-host loopback deployment, are byte-identical
no-ops (the request and the session share one address).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth import Role, totp
from messagefoundry.auth.notifications import ADMIN_NEW_IP, SecurityEvent
from messagefoundry.auth.identity import Identity
from messagefoundry.auth.service import AuthService
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store.store import MessageStore

PW = "a-strong-test-passphrase"  # ≥15, no app/vendor terms — satisfies the ASVS policy (WP-3)
NEW_USER = {"username": "newbie", "password": PW, "roles": ["viewer"]}


class _FakeNotifier:
    """Captures the out-of-band security events instead of emailing them."""

    def __init__(self) -> None:
        self.events: list[SecurityEvent] = []

    async def notify(self, event: SecurityEvent) -> None:
        self.events.append(event)


async def _enabled_admin(service: AuthService, *, client: str) -> tuple[str, Identity]:
    """Create an enabled admin (no forced first-login rotation) + a live session from ``client``."""
    uid = await service.create_local_user(
        username="boss",
        password=PW,
        display_name=None,
        email="boss@example.test",
        roles=[Role.ADMINISTRATOR.value],
        actor="t",
    )
    user = await service.store.get_user(uid)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        uid, password_hash=user.password_hash, must_change_password=False
    )
    out = await service.login("boss", PW, client=client)
    assert out.ok and out.token is not None and out.identity is not None
    return out.token, out.identity


# --- service / store unit ----------------------------------------------------
async def test_disabled_by_default_is_a_noop() -> None:
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        service = AuthService(store, AuthSettings(), security_notifier=notifier)  # default off
        await service.initialize()
        token, _ = await _enabled_admin(service, client="10.1.1.1")
        # Even a wildly different address is a no-op while the feature is off.
        assert await service.flag_new_client_ip(token, "10.9.9.9", path="/users") is False
        assert notifier.events == []
    finally:
        await store.close()


async def test_new_ip_flags_audits_and_notifies() -> None:
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        service = AuthService(
            store, AuthSettings(admin_new_ip_step_up=True), security_notifier=notifier
        )
        await service.initialize()
        token, _ = await _enabled_admin(service, client="10.1.1.1")
        # Same address → not new; no side effects.
        assert await service.flag_new_client_ip(token, "10.1.1.1", path="/users") is False
        assert notifier.events == []
        # A different address → flagged, audited, and notified.
        assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is True
        assert any(
            e.event_type == ADMIN_NEW_IP and e.client_ip == "10.2.2.2" for e in notifier.events
        )
        rows = await store.list_audit(limit=20)
        assert any(r["action"] == "auth.admin_action_new_ip" for r in rows)
    finally:
        await store.close()


async def test_missing_baseline_and_bad_tokens_not_flagged() -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(admin_new_ip_step_up=True))
        await service.initialize()
        uid = await service.create_local_user(
            username="x",
            password=PW,
            display_name=None,
            email=None,
            roles=[Role.VIEWER.value],
            actor="t",
        )
        # A session with no recorded login address is never penalized (avoids spurious friction).
        await store.create_session(
            token_hash=hash_token("noip"), user_id=uid, expires_at=2e12, client=None
        )
        assert await service.flag_new_client_ip("noip", "10.2.2.2", path="/x") is False
        # Missing / unknown tokens are never flagged.
        assert await service.flag_new_client_ip(None, "10.2.2.2", path="/x") is False
        assert await service.flag_new_client_ip("nope", "10.2.2.2", path="/x") is False
    finally:
        await store.close()


async def test_reauth_reanchors_session_to_the_new_ip() -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(admin_new_ip_step_up=True))
        await service.initialize()
        token, identity = await _enabled_admin(service, client="10.1.1.1")
        assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is True
        # Re-verifying from the new address re-anchors the session, clearing the signal.
        assert await service.reauth(identity, PW, token=token, client="10.2.2.2") is True
        assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is False
        # The original address is now the unexpected one.
        assert await service.flag_new_client_ip(token, "10.1.1.1", path="/users") is True
    finally:
        await store.close()


async def test_repeat_from_same_new_ip_is_deduped() -> None:
    """The step-up is forced on every hit, but the audit row + out-of-band notice fire only once per
    (session, new-IP) — a replayed token can't inflate the audit log / notifications. A genuinely
    different address re-emits."""
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        service = AuthService(
            store, AuthSettings(admin_new_ip_step_up=True), security_notifier=notifier
        )
        await service.initialize()
        token, _ = await _enabled_admin(service, client="10.1.1.1")
        # First hit from a new address → flagged, audited, notified.
        assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is True
        # Repeat from the SAME address → still forces step-up, but no new audit row / notice.
        assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is True
        actions = [r["action"] for r in await store.list_audit(limit=50)]
        assert actions.count("auth.admin_action_new_ip") == 1
        assert sum(1 for e in notifier.events if e.event_type == ADMIN_NEW_IP) == 1
        # A DIFFERENT new address is a distinct event → re-emits.
        assert await service.flag_new_client_ip(token, "10.3.3.3", path="/users") is True
        actions = [r["action"] for r in await store.list_audit(limit=50)]
        assert actions.count("auth.admin_action_new_ip") == 2
        assert sum(1 for e in notifier.events if e.event_type == ADMIN_NEW_IP) == 2
    finally:
        await store.close()


async def test_loopback_addresses_treated_as_same_host() -> None:
    """A dual-stack loopback box (session anchored at ::1, a later request from 127.0.0.1) is one host
    — the feature stays a true no-op on loopback even when enabled. A real address is still new."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(admin_new_ip_step_up=True))
        await service.initialize()
        uid = await service.create_local_user(
            username="x",
            password=PW,
            display_name=None,
            email=None,
            roles=[Role.ADMINISTRATOR.value],
            actor="t",
        )
        await store.create_session(
            token_hash=hash_token("lb"), user_id=uid, expires_at=2e12, client="::1"
        )
        assert await service.flag_new_client_ip("lb", "127.0.0.1", path="/users") is False
        assert await service.flag_new_client_ip("lb", "::1", path="/users") is False
        # A genuine non-loopback address is still flagged.
        assert await service.flag_new_client_ip("lb", "10.0.0.5", path="/users") is True
    finally:
        await store.close()


async def test_verify_mfa_reanchors_session_to_the_new_ip() -> None:
    """Completing the second factor (TOTP) from a new address re-anchors the session, like reauth — so
    an MFA-required admin who roamed clears the new-IP signal with one credential proof, not two."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(admin_new_ip_step_up=True))
        boot = await service.initialize()
        assert boot is not None
        out = await service.login("admin", boot.password, client="10.1.1.1")
        assert out.ok and out.identity is not None and out.token is not None
        identity, token = out.identity, out.token
        enroll = await service.begin_mfa_enrollment(identity)
        await service.confirm_mfa_enrollment(
            identity, totp.totp(enroll.secret), token=token, client="10.1.1.1"
        )
        # Roam to a new address → flagged.
        assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is True
        # Completing MFA from the new address re-anchors the session (parity with reauth).
        assert await service.verify_mfa(token, totp.totp(enroll.secret), client="10.2.2.2") is True
        assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is False
    finally:
        await store.close()


# --- API enforcement ---------------------------------------------------------
@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "newip.db", poll_interval=0.02)
    yield eng
    await eng.stop()


def _client_at(engine: Engine, service: AuthService, ip: str) -> httpx.AsyncClient:
    """An API client whose requests originate from ``ip`` (set on the ASGI scope)."""
    transport = httpx.ASGITransport(app=create_app(engine, auth=service), client=(ip, 12345))
    return httpx.AsyncClient(transport=transport, base_url="http://t")


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _add_admin(service: AuthService, username: str) -> None:
    user_id = await service.create_local_user(
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.ADMINISTRATOR.value],
        actor="test",
    )
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id, password_hash=user.password_hash, must_change_password=False
    )


async def _login_token(c: httpx.AsyncClient, username: str = "boss") -> str:
    r = await c.post(
        "/auth/login", json={"username": username, "password": PW, "provider": "local"}
    )
    assert r.status_code == 200, r.text
    return str(r.json()["token"])


async def test_admin_route_from_new_ip_forces_step_up_then_clears(engine: Engine) -> None:
    # New-client-IP step-up test (admin route), not an MFA test: pin require_mfa=False so the admin's
    # step-up op isn't blocked first by the BACKLOG #187 secure default (require_mfa now ON).
    service = AuthService(engine.store, AuthSettings(admin_new_ip_step_up=True, require_mfa=False))
    await service.initialize()
    await _add_admin(service, "boss")
    async with _client_at(engine, service, "10.0.0.1") as a:
        token = await _login_token(a)
        # From the SAME address the fresh login may act (network-location + step-up freshness hold).
        assert (await a.post("/users", headers=_auth(token), json=NEW_USER)).status_code == 201
    # Same token, a DIFFERENT client address → forced step-up.
    n2 = {"username": "n2", "password": PW, "roles": ["viewer"]}
    async with _client_at(engine, service, "10.9.9.9") as b:
        blocked = await b.post("/users", headers=_auth(token), json=n2)
        assert blocked.status_code == 403
        assert blocked.headers.get("X-Step-Up-Required") == "1"
        # A non-sensitive route from the new address is NOT blocked (advisory + admin-scope only).
        assert (await b.get("/auth/me", headers=_auth(token))).status_code == 200
        # Re-verifying from the new address re-anchors the session; the admin op then succeeds.
        ok = await b.post("/me/reauth", headers=_auth(token), json={"password": PW})
        assert ok.status_code == 200
        assert (await b.post("/users", headers=_auth(token), json=n2)).status_code == 201


async def test_known_ip_with_feature_on_is_unobtrusive(engine: Engine) -> None:
    # New-client-IP step-up test (admin route), not an MFA test: pin require_mfa=False so the admin's
    # step-up op isn't blocked first by the BACKLOG #187 secure default (require_mfa now ON).
    service = AuthService(engine.store, AuthSettings(admin_new_ip_step_up=True, require_mfa=False))
    await service.initialize()
    await _add_admin(service, "boss")
    async with _client_at(engine, service, "10.0.0.1") as a:
        token = await _login_token(a)
        # Same address throughout → no extra friction beyond the normal login step-up freshness.
        assert (await a.post("/users", headers=_auth(token), json=NEW_USER)).status_code == 201


async def test_disabled_by_default_new_ip_does_not_force_step_up(engine: Engine) -> None:
    service = AuthService(engine.store, AuthSettings(require_mfa=False))  # admin_new_ip default off
    await service.initialize()
    await _add_admin(service, "boss")
    async with _client_at(engine, service, "10.0.0.1") as a:
        token = await _login_token(a)
    async with _client_at(engine, service, "10.9.9.9") as b:
        # Feature off → the new address is irrelevant; the fresh login's step-up still holds → 201.
        assert (await b.post("/users", headers=_auth(token), json=NEW_USER)).status_code == 201


async def test_new_ip_never_overrides_rbac(engine: Engine) -> None:
    """A viewer lacking ``users:manage`` is denied for *permission* — RBAC runs before the step-up /
    IP logic, so the IP signal neither grants nor is even consulted (it never changes an authz
    decision)."""
    # New-client-IP step-up test (admin route), not an MFA test: pin require_mfa=False so the admin's
    # step-up op isn't blocked first by the BACKLOG #187 secure default (require_mfa now ON).
    service = AuthService(engine.store, AuthSettings(admin_new_ip_step_up=True, require_mfa=False))
    await service.initialize()
    uid = await service.create_local_user(
        username="viewer1",
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.VIEWER.value],
        actor="t",
    )
    user = await service.store.get_user(uid)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        uid, password_hash=user.password_hash, must_change_password=False
    )
    async with _client_at(engine, service, "10.0.0.1") as a:
        token = await _login_token(a, "viewer1")
    async with _client_at(engine, service, "10.9.9.9") as b:
        denied = await b.post("/users", headers=_auth(token), json=NEW_USER)
        assert denied.status_code == 403
        # Missing permission — NOT a step-up / MFA prompt.
        assert denied.headers.get("X-Step-Up-Required") is None
        assert denied.headers.get("X-MFA-Required") is None
