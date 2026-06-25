# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""API authentication + RBAC enforcement: login, deny-by-default, PHI gating, user admin, audit."""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth import Role, totp
from messagefoundry.auth.ldap import AdPrincipal
from messagefoundry.auth.service import AuthService
from messagefoundry.config.ai_policy import DataClass
from messagefoundry.config.models import RetryPolicy
from messagefoundry.config.settings import AiSettings, AuthSettings, StoreSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.store import MessageStore

PW = "a-strong-test-passphrase"  # ≥15, no app/vendor terms — satisfies the ASVS policy (WP-3)
ADT = "MSH|^~\\&|S|F|R|RF|20260604||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "auth_api.db", poll_interval=0.02)
    yield eng
    await eng.stop()


async def _service(engine: Engine, settings: AuthSettings | None = None) -> AuthService:
    service = AuthService(engine.store, settings or AuthSettings())
    await service.initialize()  # seeds roles + a bootstrap admin we don't use here
    return service


def _client(engine: Engine, service: AuthService) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=create_app(engine, auth=service))
    return httpx.AsyncClient(transport=transport, base_url="http://t")


async def _add(service: AuthService, username: str, *roles: Role) -> None:
    user_id = await service.create_local_user(
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=[r.value for r in roles],
        actor="test",
    )
    await _clear_must_change(service, user_id)


async def _clear_must_change(service: AuthService, user_id: str) -> None:
    # Admin-created accounts force first-login rotation (WP-L3-12). These helper fixtures stand in for
    # already-onboarded users, so clear the flag (keeping the same hash) to keep their logins usable.
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id, password_hash=user.password_hash, must_change_password=False
    )


async def _login(
    c: httpx.AsyncClient, username: str, password: str = PW, provider: str = "local"
) -> httpx.Response:
    return await c.post(
        "/auth/login", json={"username": username, "password": password, "provider": provider}
    )


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def test_unauthenticated_is_rejected_but_health_is_open(engine: Engine) -> None:
    service = await _service(engine)
    async with _client(engine, service) as c:
        assert (await c.get("/health")).status_code == 200
        assert (await c.get("/stats")).status_code == 401
        assert (await c.get("/connections")).status_code == 401


async def test_security_events_feed_lists_callers_auth_events(engine: Engine) -> None:
    # WP-L3-05 (ASVS 6.3.5/6.3.7): /me/security-events surfaces the caller's own audited auth.* events.
    service = await _service(engine)
    await _add(service, "viewer", Role.VIEWER)
    async with _client(engine, service) as c:
        token = (await _login(c, "viewer")).json()["token"]  # audits auth.login_success
        await _login(c, "viewer", "wrong")  # audits auth.login_failed (same actor)
        r = await c.get("/me/security-events", headers=_auth(token))
        assert r.status_code == 200
        actions = [e["action"] for e in r.json()["events"]]
        assert "auth.login_success" in actions
        assert "auth.login_failed" in actions
    # unauthenticated callers can't read it
    async with _client(engine, service) as c:
        assert (await c.get("/me/security-events")).status_code == 401


async def test_security_events_feed_is_scoped_to_caller(engine: Engine) -> None:
    # WP-L3-05 follow-up: the feed is horizontally isolated (no IDOR) — a caller sees ONLY their own
    # audited auth.* events, never another user's. alice never fails a login, so bob's failed attempt
    # leaking into her feed (a broken actor= filter) is caught precisely.
    service = await _service(engine)
    await _add(service, "alice", Role.VIEWER)
    await _add(service, "bob", Role.VIEWER)
    async with _client(engine, service) as c:
        alice_token = (await _login(c, "alice")).json()["token"]  # alice: success only
        await _login(c, "bob", "wrong")  # bob: a failed attempt (actor=bob)
        bob_token = (await _login(c, "bob")).json()["token"]
        alice_actions = [
            e["action"]
            for e in (await c.get("/me/security-events", headers=_auth(alice_token))).json()[
                "events"
            ]
        ]
        bob_actions = [
            e["action"]
            for e in (await c.get("/me/security-events", headers=_auth(bob_token))).json()["events"]
        ]
    assert "auth.login_success" in alice_actions
    assert "auth.login_failed" not in alice_actions  # bob's failure must NOT appear in alice's feed
    assert "auth.login_failed" in bob_actions  # bob sees his own failure


async def test_mfa_enroll_confirm_and_step_up_gate(engine: Engine) -> None:
    # WP-14 / ASVS 6.3.3: the full TOTP lifecycle over the API + the step-up MFA gate. An MFA-required
    # session 403s on a require_step_up route with X-MFA-Required until POST /auth/mfa-verify.
    service = await _service(engine, AuthSettings(login_rate_limit_enabled=False))
    await _add(service, "adm", Role.ADMINISTRATOR)
    async with _client(engine, service) as c:
        tok = (await _login(c, "adm")).json()["token"]

        # Enrollment is step-up gated; the login itself counts as the first credential verification
        # (sudo-timestamp model), so a just-logged-in session can enroll within the step-up window.
        r = await c.post("/me/mfa/enroll", headers=_auth(tok))
        assert r.status_code == 200
        secret = r.json()["secret"]

        # Confirm with a live code → activates MFA + returns the one-time recovery codes.
        r = await c.post("/me/mfa/confirm", json={"code": totp.totp(secret)}, headers=_auth(tok))
        assert r.status_code == 200 and len(r.json()["recovery_codes"]) == 10
        st = (await c.get("/me/mfa", headers=_auth(tok))).json()
        assert st["enabled"] is True and st["required"] is True

        # A fresh login now flags mfa_required and the new session is un-MFA'd.
        lr = (await _login(c, "adm")).json()
        assert lr["mfa_required"] is True
        tok2 = lr["token"]

        # A require_step_up route is blocked with X-MFA-Required until the 2nd factor is verified.
        r = await c.put("/ad-group-map", json={"entries": []}, headers=_auth(tok2))
        assert r.status_code == 403 and r.headers.get("X-MFA-Required") == "1"
        r = await c.post("/auth/mfa-verify", json={"code": totp.totp(secret)}, headers=_auth(tok2))
        assert r.status_code == 200
        # Now it passes (password step-up satisfied at login; MFA now satisfied).
        r = await c.put("/ad-group-map", json={"entries": []}, headers=_auth(tok2))
        assert r.status_code == 200


async def test_mfa_verify_accepts_recovery_code_once(engine: Engine) -> None:
    service = await _service(
        engine, AuthSettings(login_rate_limit_enabled=False, mfa_recovery_code_count=3)
    )
    await _add(service, "adm", Role.ADMINISTRATOR)
    async with _client(engine, service) as c:
        tok = (await _login(c, "adm")).json()["token"]
        secret = (await c.post("/me/mfa/enroll", headers=_auth(tok))).json()["secret"]
        confirm = await c.post(
            "/me/mfa/confirm", json={"code": totp.totp(secret)}, headers=_auth(tok)
        )
        recovery = confirm.json()["recovery_codes"]

        # Fresh login → satisfy the 2nd factor with a recovery code.
        tok2 = (await _login(c, "adm")).json()["token"]
        r = await c.post("/auth/mfa-verify", json={"code": recovery[0]}, headers=_auth(tok2))
        assert r.status_code == 200

        # The same recovery code can't be reused; a fresh one still works.
        tok3 = (await _login(c, "adm")).json()["token"]
        r = await c.post("/auth/mfa-verify", json={"code": recovery[0]}, headers=_auth(tok3))
        assert r.status_code == 401
        r = await c.post("/auth/mfa-verify", json={"code": recovery[1]}, headers=_auth(tok3))
        assert r.status_code == 200


async def test_mfa_enrollment_requires_explicit_reauth_for_require_mfa_admin(
    engine: Engine,
) -> None:
    # Security review (bootstrap bypass): a require_mfa Administrator's fresh, not-yet-enrolled session
    # is MFA-pending, so it is NOT step-up-fresh — enrollment is refused until an explicit password
    # re-verify. This stops a stolen pre-MFA token from binding an attacker-controlled authenticator.
    service = await _service(engine, AuthSettings(require_mfa=True, login_rate_limit_enabled=False))
    await _add(service, "adm", Role.ADMINISTRATOR)
    async with _client(engine, service) as c:
        lr = (await _login(c, "adm")).json()
        assert lr["mfa_required"] is True
        tok = lr["token"]
        # No explicit reauth yet → enroll is step-up-refused (the login no longer seeds step-up here).
        r = await c.post("/me/mfa/enroll", headers=_auth(tok))
        assert r.status_code == 403 and r.headers.get("X-Step-Up-Required") == "1"
        # Re-prove the password, then enrollment proceeds.
        r = await c.post("/me/reauth", json={"password": PW}, headers=_auth(tok))
        assert r.status_code == 200
        r = await c.post("/me/mfa/enroll", headers=_auth(tok))
        assert r.status_code == 200


async def test_security_events_feed_payload_is_phi_free(engine: Engine) -> None:
    # The feed carries only non-PHI audit metadata (ts/action/detail) — never message bodies or
    # credential material. Mirrors the PHI-free assertion already made on the email-notification body.
    service = await _service(engine)
    await _add(service, "viewer", Role.VIEWER)
    async with _client(engine, service) as c:
        token = (await _login(c, "viewer")).json()["token"]
        await _login(c, "viewer", "wrong")
        r = await c.get("/me/security-events", headers=_auth(token))
        assert r.status_code == 200
        body = r.text
    assert "MSH|" not in body and "PID|" not in body  # no HL7/PHI markers
    assert PW not in body  # the caller's password is never echoed back into the feed


async def test_health_version_disclosed_only_when_authenticated(engine: Engine) -> None:
    # WP-L3-07 (ASVS 13.4.6): liveness is open, but the build version (a fingerprinting detail) is
    # withheld from a tokenless caller and disclosed only to an authenticated one.
    service = await _service(engine)
    await _add(service, "viewer", Role.VIEWER)
    async with _client(engine, service) as c:
        anon = (await c.get("/health")).json()
        assert anon["status"] == "ok"
        assert anon["version"] is None  # no fingerprint for a tokenless probe

        token = (await _login(c, "viewer")).json()["token"]
        authed = (await c.get("/health", headers=_auth(token))).json()
        assert authed["version"]  # authenticated → version disclosed


async def test_login_then_permission_enforced(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "viewer", Role.VIEWER)
    async with _client(engine, service) as c:
        assert (await _login(c, "viewer", "wrong")).status_code == 401
        ok = await _login(c, "viewer")
        assert ok.status_code == 200
        token = ok.json()["token"]
        assert ok.json()["user"]["roles"] == ["viewer"]
        assert (await c.get("/stats", headers=_auth(token))).status_code == 200  # monitoring:read
        assert (await c.post("/connections/x/start", headers=_auth(token))).status_code == 403
        assert (await c.get("/auth/me", headers=_auth(token))).json()["username"] == "viewer"
        # logout revokes the token immediately
        assert (await c.post("/auth/logout", headers=_auth(token))).status_code == 200
        assert (await c.get("/stats", headers=_auth(token))).status_code == 401


async def test_cluster_endpoints_gated_by_monitoring_read(engine: Engine) -> None:
    # Track B Step 7: /cluster/status + /cluster/nodes are gated by Permission.MONITORING_READ. A VIEWER
    # holds it (200 on both); a user with NO roles lacks it (403); fail-closed for no/invalid token (401).
    service = await _service(engine)
    await _add(service, "vw", Role.VIEWER)
    await _add(service, "norole")  # created with an empty roles list → no permissions
    async with _client(engine, service) as c:
        # No token under enabled auth → fail closed (401), not an open read.
        assert (await c.get("/cluster/status")).status_code == 401
        assert (await c.get("/cluster/nodes")).status_code == 401
        # An invalid token is equally rejected.
        bad = _auth("not-a-real-token")
        assert (await c.get("/cluster/status", headers=bad)).status_code == 401
        assert (await c.get("/cluster/nodes", headers=bad)).status_code == 401
        # VIEWER (has monitoring:read) → 200 on both.
        vw = _auth((await _login(c, "vw")).json()["token"])
        assert (await c.get("/cluster/status", headers=vw)).status_code == 200
        nodes = await c.get("/cluster/nodes", headers=vw)
        assert nodes.status_code == 200 and len(nodes.json()["nodes"]) == 1
        # A role-less user lacks monitoring:read → 403 on both.
        nr = _auth((await _login(c, "norole")).json()["token"])
        assert (await c.get("/cluster/status", headers=nr)).status_code == 403
        assert (await c.get("/cluster/nodes", headers=nr)).status_code == 403


async def test_phi_raw_view_requires_operator(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    await _add(service, "vw", Role.VIEWER)
    mid = await engine.store.enqueue_message(channel_id="ch1", raw=ADT, deliveries=[])
    async with _client(engine, service) as c:
        op = (await _login(c, "op")).json()["token"]
        vw = (await _login(c, "vw")).json()["token"]
        assert (await c.get(f"/messages/{mid}", headers=_auth(op))).status_code == 200
        assert (
            await c.get(f"/messages/{mid}", headers=_auth(vw))
        ).status_code == 403  # no view_raw
        assert (await c.get("/messages", headers=_auth(vw))).status_code == 200  # messages:read ok


async def test_outbound_payloads_require_view_raw(engine: Engine) -> None:
    # #14: the transformed outbound payload is PHI body — same gate as the raw view. A VIEWER (no
    # view_raw) is refused; an OPERATOR sees the decrypted transformed payload.
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    await _add(service, "vw", Role.VIEWER)
    mid = await engine.store.enqueue_message(
        channel_id="ch1", raw=ADT, deliveries=[("archive", "MSH|transformed")]
    )
    async with _client(engine, service) as c:
        op = (await _login(c, "op")).json()["token"]
        vw = (await _login(c, "vw")).json()["token"]
        ok = await c.get(f"/messages/{mid}/outbound", headers=_auth(op))
        assert ok.status_code == 200
        assert ok.json()["payloads"][0]["payload"] == "MSH|transformed"
        assert (
            await c.get(f"/messages/{mid}/outbound", headers=_auth(vw))
        ).status_code == 403  # no view_raw


async def test_detail_disposition_text_visible_to_operator_and_audited(engine: Engine) -> None:
    # #120: get_message gates error/last_error/event-detail on view_summary and audits the view, but an
    # Operator (holds view_summary + view_raw) must still SEE them — the redaction must not strip an
    # authorized caller's disposition text. The null path (view_raw without view_summary) is unit-tested
    # in test_field_authz; no built-in role holds that combo, so it isn't reachable end-to-end.
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    retry = RetryPolicy(max_attempts=1, backoff_seconds=1, backoff_multiplier=1)
    mid = await engine.store.enqueue_message(
        channel_id="ch1", raw=ADT, deliveries=[("OB", "p")], now=0.0
    )
    item = (await engine.store.claim_ready(now=0.0))[0]
    await engine.store.mark_failed(item.id, "delivery rejected by partner", retry, now=0.0)
    async with _client(engine, service) as c:
        op = _auth((await _login(c, "op")).json()["token"])
        r = await c.get(f"/messages/{mid}", headers=op)
        assert r.status_code == 200
        assert r.json()["outbox"][0]["last_error"] == "delivery rejected by partner"
    actions = [dict(a)["action"] for a in await engine.store.list_audit(limit=50)]
    assert "message_view" in actions  # opening the detail (raw) view is audited


async def test_admin_user_crud_and_audit(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "root", Role.ADMINISTRATOR)
    async with _client(engine, service) as c:
        h = _auth((await _login(c, "root")).json()["token"])
        created = await c.post(
            "/users", headers=h, json={"username": "newbie", "password": PW, "roles": ["viewer"]}
        )
        assert created.status_code == 201 and created.json()["roles"] == ["viewer"]
        uid = created.json()["id"]
        # weak password + unknown role are rejected
        assert (
            await c.post("/users", headers=h, json={"username": "w", "password": "short"})
        ).status_code == 400
        assert (
            await c.post(
                "/users", headers=h, json={"username": "x", "password": PW, "roles": ["wizard"]}
            )
        ).status_code == 400
        # role change, listing, self-delete guard, delete
        assert (
            await c.put(f"/users/{uid}/roles", headers=h, json={"roles": ["operator"]})
        ).status_code == 200
        assert any(u["username"] == "newbie" for u in (await c.get("/users", headers=h)).json())
        me_id = (await c.get("/auth/me", headers=h)).json()["user_id"]
        assert (await c.delete(f"/users/{me_id}", headers=h)).status_code == 400
        assert (await c.delete(f"/users/{uid}", headers=h)).status_code == 200
        # the audit trail is readable and attributes the create to the admin
        audit = (await c.get("/audit", headers=h)).json()["entries"]
        assert any(e["action"] == "user.created" and e["actor"] == "root" for e in audit)


async def test_viewer_cannot_read_audit_or_manage_users(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "vw", Role.VIEWER)
    async with _client(engine, service) as c:
        h = _auth((await _login(c, "vw")).json()["token"])
        assert (await c.get("/audit", headers=h)).status_code == 403
        assert (await c.get("/users", headers=h)).status_code == 403


async def test_change_own_password_revokes_sessions(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "u", Role.VIEWER)
    async with _client(engine, service) as c:
        h = _auth((await _login(c, "u")).json()["token"])
        # wrong current password is refused (no session-only takeover)
        assert (
            await c.post(
                "/me/password",
                headers=h,
                json={"current_password": "nope", "new_password": "a-brand-new-passphrase"},
            )
        ).status_code == 403
        # correct current password, but the new one is too weak -> policy 400
        assert (
            await c.post(
                "/me/password",
                headers=h,
                json={"current_password": PW, "new_password": "weak"},
            )
        ).status_code == 400
        assert (
            await c.post(
                "/me/password",
                headers=h,
                json={"current_password": PW, "new_password": "a-brand-new-passphrase"},
            )
        ).status_code == 200
        assert (await c.get("/auth/me", headers=h)).status_code == 401  # old session revoked
        assert (await _login(c, "u", "a-brand-new-passphrase")).status_code == 200


# --- WP-8: anti-automation on the PHI-read endpoints (ASVS 2.4.1) -------------


async def test_phi_read_throttle_caps_per_actor_across_endpoints(engine: Engine) -> None:
    service = await _service(engine, AuthSettings(phi_read_rate_limit_per_actor=3))
    await _add(service, "vw", Role.VIEWER)
    async with _client(engine, service) as c:
        h = _auth((await _login(c, "vw")).json()["token"])
        for _ in range(3):
            assert (await c.get("/messages", headers=h)).status_code == 200
        throttled = await c.get("/messages", headers=h)
        assert throttled.status_code == 429 and "retry-after" in throttled.headers
        # the per-actor cap is shared across PHI-read endpoints (one bucket per user)
        assert (await c.get("/dead-letters", headers=h)).status_code == 429


async def test_phi_read_throttle_is_per_actor(engine: Engine) -> None:
    service = await _service(engine, AuthSettings(phi_read_rate_limit_per_actor=2))
    await _add(service, "a", Role.VIEWER)
    await _add(service, "b", Role.VIEWER)
    async with _client(engine, service) as c:
        ha = _auth((await _login(c, "a")).json()["token"])
        hb = _auth((await _login(c, "b")).json()["token"])
        for _ in range(2):
            assert (await c.get("/messages", headers=ha)).status_code == 200
        assert (await c.get("/messages", headers=ha)).status_code == 429  # actor a throttled
        assert (await c.get("/messages", headers=hb)).status_code == 200  # actor b unaffected


async def test_phi_read_raw_view_is_throttled(engine: Engine) -> None:
    mid = await engine.store.enqueue_message(channel_id="c", raw=ADT, deliveries=[])
    service = await _service(engine, AuthSettings(phi_read_rate_limit_per_actor=1))
    await _add(service, "op", Role.OPERATOR)  # OPERATOR holds messages:view_raw
    async with _client(engine, service) as c:
        h = _auth((await _login(c, "op")).json()["token"])
        assert (await c.get(f"/messages/{mid}", headers=h)).status_code == 200
        assert (await c.get(f"/messages/{mid}", headers=h)).status_code == 429  # raw view throttled


async def test_phi_read_throttle_off_by_setting(engine: Engine) -> None:
    service = await _service(engine, AuthSettings(phi_read_rate_limit_enabled=False))
    await _add(service, "vw", Role.VIEWER)
    async with _client(engine, service) as c:
        h = _auth((await _login(c, "vw")).json()["token"])
        for _ in range(8):
            assert (await c.get("/messages", headers=h)).status_code == 200  # no cap when disabled


# --- WP-10: session inventory + targeted revoke (ASVS 7.5.2/7.4.5/7.1.2) ------


async def test_list_and_revoke_own_session(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "u", Role.VIEWER)
    async with _client(engine, service) as c:
        t1 = (await _login(c, "u")).json()["token"]
        t2 = (await _login(c, "u")).json()["token"]
        h2 = _auth(t2)
        sessions = (await c.get("/me/sessions", headers=h2)).json()["sessions"]
        assert len(sessions) == 2 and sum(s["current"] for s in sessions) == 1  # one marked current
        other = next(s for s in sessions if not s["current"])  # the t1 session
        assert (await c.delete(f"/me/sessions/{other['id']}", headers=h2)).status_code == 200
        assert (await c.get("/auth/me", headers=_auth(t1))).status_code == 401  # revoked
        assert (await c.get("/auth/me", headers=h2)).status_code == 200  # current still valid
        assert len((await c.get("/me/sessions", headers=h2)).json()["sessions"]) == 1


async def test_revoke_other_sessions_keeps_current(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "u", Role.VIEWER)
    async with _client(engine, service) as c:
        t1 = (await _login(c, "u")).json()["token"]
        t2 = (await _login(c, "u")).json()["token"]
        resp = await c.delete("/me/sessions", headers=_auth(t2))  # sign out everywhere else
        assert resp.status_code == 200 and "1" in resp.json()["detail"]
        assert (await c.get("/auth/me", headers=_auth(t1))).status_code == 401
        assert (await c.get("/auth/me", headers=_auth(t2))).status_code == 200


async def test_cannot_revoke_another_users_session(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "a", Role.VIEWER)
    await _add(service, "b", Role.VIEWER)
    async with _client(engine, service) as c:
        ta = (await _login(c, "a")).json()["token"]
        tb = (await _login(c, "b")).json()["token"]
        b_sid = (await c.get("/me/sessions", headers=_auth(tb))).json()["sessions"][0]["id"]
        # a tries to revoke b's session → 404 (ownership-checked, doesn't confirm/touch it)
        assert (await c.delete(f"/me/sessions/{b_sid}", headers=_auth(ta))).status_code == 404
        assert (await c.get("/auth/me", headers=_auth(tb))).status_code == 200  # b still signed in


async def test_admin_revokes_a_users_sessions(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "root", Role.ADMINISTRATOR)
    await _add(service, "u", Role.VIEWER)
    async with _client(engine, service) as c:
        admin = _auth((await _login(c, "root")).json()["token"])
        tu = (await _login(c, "u")).json()["token"]
        uid = (await c.get("/auth/me", headers=_auth(tu))).json()["user_id"]
        assert (await c.delete(f"/users/{uid}/sessions", headers=admin)).status_code == 200
        assert (await c.get("/auth/me", headers=_auth(tu))).status_code == 401  # force-signed-out
        assert (await c.delete("/users/nope/sessions", headers=admin)).status_code == 404


async def test_session_cap_evicts_oldest_on_login(engine: Engine) -> None:
    service = await _service(engine, AuthSettings(max_sessions_per_user=2))
    await _add(service, "u", Role.VIEWER)
    async with _client(engine, service) as c:
        t1 = (await _login(c, "u")).json()["token"]
        t2 = (await _login(c, "u")).json()["token"]
        t3 = (await _login(c, "u")).json()["token"]  # exceeds cap=2 → evicts the oldest (t1)
        assert (await c.get("/auth/me", headers=_auth(t1))).status_code == 401
        assert (await c.get("/auth/me", headers=_auth(t2))).status_code == 200
        assert (await c.get("/auth/me", headers=_auth(t3))).status_code == 200
        assert len((await c.get("/me/sessions", headers=_auth(t3))).json()["sessions"]) == 2


async def test_ad_login_maps_groups_and_grants_permission(engine: Engine) -> None:
    principal = AdPrincipal(
        username="jdoe",
        display_name="J Doe",
        email=None,
        dn="CN=jdoe,DC=x",
        groups=frozenset({"cn=mf-ops,dc=x"}),
    )

    class _FakeLdap:
        def authenticate(self, username: str, password: str) -> AdPrincipal | None:
            return principal if (username == "jdoe" and password == "pw") else None

        def resolve_principal(self, username: str) -> AdPrincipal | None:
            return principal if username == "jdoe" else None

    settings = AuthSettings(
        ad_enabled=True,
        ad_server="ldaps://x",
        ad_user_search_base="DC=x",
        ad_bind_dn="CN=svc,DC=x",
        ad_bind_password="x",
    )
    service = AuthService(engine.store, settings, ldap=_FakeLdap())  # type: ignore[arg-type]
    await service.initialize()
    await service.set_ad_group_map([("CN=MF-Ops,DC=x", "operator")], actor="admin")
    async with _client(engine, service) as c:
        r = await _login(c, "jdoe", "pw", provider="ad")
        assert r.status_code == 200 and r.json()["user"]["roles"] == ["operator"]
        assert r.json()["user"]["auth_provider"] == "ad"
        h = _auth(r.json()["token"])
        # operator has connections:control — a missing connection yields 404 (not 403)
        assert (await c.post("/connections/none/start", headers=h)).status_code == 404
        assert (await c.get("/auth/providers", headers=h)).json()["ad"] is True


async def test_disabled_auth_fails_closed_unless_opted_in(engine: Engine) -> None:
    # SYS-1: disabled auth no longer silently opens routes — it fails closed by default...
    service = AuthService(engine.store, AuthSettings(enabled=False))
    transport = httpx.ASGITransport(app=create_app(engine, auth=service))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        assert (await c.get("/stats")).status_code == 503
    # ...unless the embedding/served path opts in explicitly (create_managed_app does this when
    # auth is off, guarded by __main__'s loopback-only check).
    transport = httpx.ASGITransport(app=create_app(engine, auth=service, allow_no_auth=True))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        assert (await c.get("/stats")).status_code == 200


async def test_patch_user_preserves_omitted_fields(engine: Engine) -> None:
    # M-20: a partial PATCH (only `disabled`) must NOT null the omitted display_name/email.
    service = await _service(engine)
    await _add(service, "root", Role.ADMINISTRATOR)
    uid = await service.create_local_user(
        username="jane",
        password=PW,
        display_name="Jane Doe",
        email="jane@example.org",
        roles=["viewer"],
        actor="test",
    )
    async with _client(engine, service) as c:
        h = _auth((await _login(c, "root")).json()["token"])
        r = await c.patch(f"/users/{uid}", headers=h, json={"disabled": True})
        assert r.status_code == 200
    user = await engine.store.get_user(uid)
    assert user is not None
    assert user.disabled and user.display_name == "Jane Doe"  # omitted fields preserved
    assert user.email == "jane@example.org"


async def test_admin_created_account_forces_first_login_rotation(engine: Engine) -> None:
    # WP-L3-12 (ASVS 6.4.6): a user created via the admin API must rotate the admin-set password on
    # first login before reaching any protected route.
    service = await _service(engine)
    await _add(service, "root", Role.ADMINISTRATOR)
    async with _client(engine, service) as c:
        admin = _auth((await _login(c, "root")).json()["token"])
        created = await c.post(
            "/users", headers=admin, json={"username": "carol", "password": PW, "roles": ["viewer"]}
        )
        assert created.status_code == 201
        first = await _login(c, "carol")
        assert first.status_code == 200 and first.json()["must_change_password"] is True
        # the rotation gate blocks protected routes until carol changes the admin-set password
        blocked = _auth(first.json()["token"])
        assert (await c.get("/stats", headers=blocked)).status_code == 403


async def test_admin_reset_password_endpoint(engine: Engine) -> None:
    # WP-L3-12 (ASVS 6.4.6): admin reset returns a one-time temp once; it's permission-gated; the temp
    # forces rotation; self/unknown/AD targets are refused appropriately.
    service = await _service(engine)
    await _add(service, "root", Role.ADMINISTRATOR)
    await _add(service, "vw", Role.VIEWER)
    carol_id = await service.create_local_user(
        username="carol",
        password=PW,
        display_name=None,
        email="carol@example.org",
        roles=["viewer"],
        actor="root",
    )
    await engine.store.create_user(user_id="ad9", username="ad9", auth_provider="ad")
    async with _client(engine, service) as c:
        admin = _auth((await _login(c, "root")).json()["token"])
        viewer = _auth((await _login(c, "vw")).json()["token"])
        # deny-by-default: a viewer lacks users:manage
        assert (
            await c.post(f"/users/{carol_id}/reset-password", headers=viewer)
        ).status_code == 403
        # admin reset → a one-time temp returned once
        reset = await c.post(f"/users/{carol_id}/reset-password", headers=admin)
        assert reset.status_code == 200
        temp = reset.json()["temp_password"]
        assert temp and reset.json()["must_change_password"] is True
        # the temp logs carol in (rotation required); rotating it clears the gate
        relog = await _login(c, "carol", temp)
        assert relog.status_code == 200 and relog.json()["must_change_password"] is True
        rotated = await c.post(
            "/me/password",
            headers=_auth(relog.json()["token"]),
            json={"current_password": temp, "new_password": "rotated-strong-passphrase-7"},
        )
        assert rotated.status_code == 200
        # unknown → 404; AD user → 400; your own account → 400 (use change-password)
        assert (await c.post("/users/nope/reset-password", headers=admin)).status_code == 404
        assert (await c.post("/users/ad9/reset-password", headers=admin)).status_code == 400
        me_id = (await c.get("/auth/me", headers=admin)).json()["user_id"]
        assert (await c.post(f"/users/{me_id}/reset-password", headers=admin)).status_code == 400


# --- M5: GET /security/posture (authenticated, permission-gated, no key bytes) ----------------------


def _posture_client(
    engine: Engine,
    service: AuthService,
    *,
    ai_settings: AiSettings | None = None,
    store_settings: StoreSettings | None = None,
) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(
        app=create_app(engine, auth=service, ai_settings=ai_settings, store_settings=store_settings)
    )
    return httpx.AsyncClient(transport=transport, base_url="http://t")


async def test_security_posture_requires_auth_and_permission(engine: Engine) -> None:
    # M5: GET /security/posture is authenticated + permission-gated (MONITORING_READ), NOT GET /health.
    service = await _service(engine)
    await _add(service, "vw", Role.VIEWER)  # holds monitoring:read
    await _add(service, "norole")  # empty roles → lacks monitoring:read
    async with _posture_client(engine, service) as c:
        assert (await c.get("/security/posture")).status_code == 401  # no token → fail closed
        assert (
            await c.get("/security/posture", headers=_auth("not-a-real-token"))
        ).status_code == 401  # invalid token
        nr = _auth((await _login(c, "norole")).json()["token"])
        assert (await c.get("/security/posture", headers=nr)).status_code == 403  # lacks permission
        vw = _auth((await _login(c, "vw")).json()["token"])
        assert (
            await c.get("/security/posture", headers=vw)
        ).status_code == 200  # authed + permitted


async def test_security_posture_keyless_reports_off(engine: Engine) -> None:
    # The default engine fixture opens a keyless SQLite store → encryption off, no key_id, sqlite backend.
    service = await _service(engine)
    await _add(service, "vw", Role.VIEWER)
    ai = AiSettings(environment="staging", data_class=DataClass.PHI, production=False)
    store = StoreSettings(allow_unencrypted_phi=True)
    async with _posture_client(engine, service, ai_settings=ai, store_settings=store) as c:
        vw = _auth((await _login(c, "vw")).json()["token"])
        body = (await c.get("/security/posture", headers=vw)).json()
    assert body["encryption_enabled"] is False
    assert body["key_id"] is None
    assert body["backend"] == "sqlite"
    assert body["data_class"] == "phi" and body["production"] is False
    assert body["environment"] == "staging"
    assert body["allow_unencrypted_phi"] is True and body["require_encryption"] is False
    assert body["plaintext_columns"] == []  # encryption off → N/A
    assert body["key_source"] == "auto"


async def test_security_posture_encrypted_exposes_fingerprint_not_key_bytes(
    tmp_path: Path, engine: Engine
) -> None:
    # With encryption ON, the route reports encryption_enabled + the active key FINGERPRINT only — the
    # raw key bytes (or its base64) MUST NOT appear anywhere in the response (SECRET-1).
    key_b64 = generate_key()
    store = await MessageStore.open(tmp_path / "enc.db", cipher=make_cipher(key_b64))
    enc_engine = Engine(store, poll_interval=0.02)
    try:
        service = AuthService(enc_engine.store, AuthSettings())
        await service.initialize()
        await _add(service, "vw", Role.VIEWER)
        ai = AiSettings(environment="prod", data_class=DataClass.PHI, production=True)
        store_settings = StoreSettings(encryption_key=key_b64, key_provider="env")
        async with _posture_client(
            enc_engine, service, ai_settings=ai, store_settings=store_settings
        ) as c:
            resp = await c.get(
                "/security/posture",
                headers=_auth((await _login(c, "vw")).json()["token"]),
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["encryption_enabled"] is True
        # The active_key_id is the cipher's fingerprint (16 hex), not key material.
        assert body["key_id"] == store.cipher_info().active_key_id
        assert body["key_id"] and len(body["key_id"]) == 16
        assert body["key_source"] == "env"
        # Hard no-key-bytes assertion: neither the base64 key nor its decoded bytes leak in the payload.
        raw = resp.text
        assert key_b64 not in raw
        import base64

        assert base64.b64decode(key_b64).hex() not in raw
    finally:
        await enc_engine.stop()


def test_security_posture_sqlserver_reports_no_plaintext_residual() -> None:
    # H4 (S5) retired the SQL Server error/last_error/message_events.detail plaintext residual — those
    # columns now route through the same store cipher as SQLite/Postgres, so the per-backend coverage
    # helper reports NO residual on any backend. Unit-level: the helper is the source of that list.
    from messagefoundry.api.app import _plaintext_columns

    # Every backend has full at-rest coverage now → empty on each.
    assert _plaintext_columns("sqlserver", encryption_enabled=True) == []
    assert _plaintext_columns("sqlite", encryption_enabled=True) == []
    assert _plaintext_columns("postgres", encryption_enabled=True) == []
    # Encryption off is N/A everywhere (the encryption_enabled=false bit conveys it).
    assert _plaintext_columns("sqlserver", encryption_enabled=False) == []
