"""Phase-3b session-lifecycle hardening: backward-clock guard (AUTH-CLOCK), idle-vs-activity
(AUTH-IDLE), per-user session cap (AUTH-SESS-CAP), AD-resync revoke (AUTH-AD-REVOKE), Kerberos
reject audit (AUTH-K-AUDIT), and WS token extraction (API-3)."""

from __future__ import annotations

import time

from messagefoundry.api.security import ws_token
from messagefoundry.auth.identity import AuthProvider
from messagefoundry.auth.ldap import AdPrincipal
from messagefoundry.auth.service import AuthService
from messagefoundry.auth.tokens import hash_token, mint_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.store import MessageStore

PW = "Sup3rSecret!!"


async def _store() -> MessageStore:
    return await MessageStore.open(":memory:")


async def _local_user(service: AuthService, username: str) -> None:
    await service.create_local_user(
        username=username, password=PW, display_name=None, email=None, roles=[], actor="test"
    )


# --- AUTH-CLOCK --------------------------------------------------------------


async def test_backward_clock_step_revokes_session() -> None:
    store = await _store()
    try:
        service = AuthService(store, AuthSettings())
        await store.create_user(user_id="u", username="u", auth_provider="local")
        # A session stamped in the "future" (as if the wall clock later stepped back) must be
        # rejected and revoked, not silently honoured.
        token = mint_token()
        future = time.time() + 10_000
        await store.create_session(
            token_hash=hash_token(token), user_id="u", expires_at=future + 3600, now=future
        )
        assert await service.identity_for_token(token) is None
        session = await store.get_session(hash_token(token))
        assert session is not None and session.revoked_at is not None
    finally:
        await store.close()


# --- AUTH-IDLE ---------------------------------------------------------------


async def test_idle_clock_only_refreshed_on_user_activity() -> None:
    store = await _store()
    try:
        service = AuthService(store, AuthSettings())
        await service.initialize()
        await _local_user(service, "alice")
        token = (await service.login("alice", PW)).token
        assert token is not None
        before = (await store.get_session(hash_token(token))).last_used_at  # type: ignore[union-attr]
        time.sleep(0.02)
        # Background re-check must NOT advance the idle clock...
        assert await service.identity_for_token(token, activity=False) is not None
        mid = (await store.get_session(hash_token(token))).last_used_at  # type: ignore[union-attr]
        assert mid == before
        # ...but a user-driven request does.
        assert await service.identity_for_token(token, activity=True) is not None
        after = (await store.get_session(hash_token(token))).last_used_at  # type: ignore[union-attr]
        assert after > before
    finally:
        await store.close()


# --- AUTH-SESS-CAP -----------------------------------------------------------


async def test_enforce_session_cap_revokes_oldest() -> None:
    store = await _store()
    try:
        await store.create_user(user_id="u", username="u", auth_provider="local")
        big = time.time() + 10_000
        for h, created in (("h1", 1.0), ("h2", 2.0), ("h3", 3.0)):
            await store.create_session(token_hash=h, user_id="u", expires_at=big, now=created)
        await store.enforce_session_cap("u", keep=2)
        assert (await store.get_session("h1")).revoked_at is not None  # type: ignore[union-attr]
        assert (await store.get_session("h2")).revoked_at is None  # type: ignore[union-attr]
        assert (await store.get_session("h3")).revoked_at is None  # type: ignore[union-attr]
    finally:
        await store.close()


async def test_login_enforces_per_user_session_cap() -> None:
    store = await _store()
    try:
        service = AuthService(store, AuthSettings(max_sessions_per_user=2))
        await service.initialize()
        await _local_user(service, "bob")
        tokens = [(await service.login("bob", PW)).token for _ in range(3)]
        active = [t for t in tokens if t and await service.identity_for_token(t) is not None]
        assert len(active) == 2  # only the two newest sessions survive the cap
    finally:
        await store.close()


# --- AUTH-AD-REVOKE ----------------------------------------------------------


def _ad_settings() -> AuthSettings:
    return AuthSettings(
        ad_enabled=True,
        ad_server="ldaps://x",
        ad_user_search_base="DC=x",
        ad_bind_dn="CN=svc,DC=x",
        ad_bind_password="x",
    )


async def test_ad_role_change_on_relogin_revokes_other_sessions() -> None:
    store = await _store()
    try:
        principal = AdPrincipal(
            username="jdoe",
            display_name="J Doe",
            email="j@x",
            dn="CN=jdoe,DC=x",
            groups=frozenset({"cn=mf-ops,dc=x"}),
        )

        class _FakeLdap:
            def authenticate(self, username: str, password: str) -> AdPrincipal | None:
                return principal if username == "jdoe" else None

            def resolve_principal(self, username: str) -> AdPrincipal | None:
                return principal if username == "jdoe" else None

        service = AuthService(store, _ad_settings(), ldap=_FakeLdap())  # type: ignore[arg-type]
        await service.initialize()
        await service.set_ad_group_map([("cn=mf-ops,dc=x", "operator")], actor="admin")
        t1 = (await service.login("jdoe", "pw", provider=AuthProvider.AD)).token
        assert t1 is not None and await service.identity_for_token(t1) is not None

        # Directory-side role change: the next login resolves different roles.
        await service.set_ad_group_map([("cn=mf-ops,dc=x", "viewer")], actor="admin")
        t2 = (await service.login("jdoe", "pw", provider=AuthProvider.AD)).token
        assert t2 is not None

        assert await service.identity_for_token(t1) is None  # prior session revoked on delta
        assert await service.identity_for_token(t2) is not None
        assert any(a["action"] == "auth.ad_roles_resynced" for a in await store.list_audit())
    finally:
        await store.close()


# --- AUTH-K-AUDIT ------------------------------------------------------------


async def test_kerberos_reject_is_audited() -> None:
    store = await _store()
    try:
        service = AuthService(store, AuthSettings())  # kerberos disabled
        out = await service.authenticate_kerberos(b"sometoken")
        assert not out.ok
        audit = await store.list_audit()
        assert any(
            a["action"] == "auth.login_failed" and "kerberos" in (a["detail"] or "") for a in audit
        )
    finally:
        await store.close()


# --- API-3: WS token extraction ----------------------------------------------


class _FakeWS:
    def __init__(self, headers: dict[str, str], query: dict[str, str]) -> None:
        self.headers = headers
        self.query_params = query


def test_ws_token_is_header_only() -> None:
    # API-3 / WP-1: the Authorization header is the ONLY accepted source. The deprecated ?token=
    # query fallback was removed — a session token in a URL leaks into proxy/access logs and Referer.
    assert ws_token(_FakeWS({"Authorization": "Bearer H"}, {"token": "Q"})) == "H"  # type: ignore[arg-type]
    assert ws_token(_FakeWS({}, {"token": "Q"})) is None  # type: ignore[arg-type]  # query ignored now
    assert ws_token(_FakeWS({}, {})) is None  # type: ignore[arg-type]
