"""API authentication + RBAC enforcement: login, deny-by-default, PHI gating, user admin, audit."""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.ldap import AdPrincipal
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine

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
    await service.create_local_user(
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=[r.value for r in roles],
        actor="test",
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
