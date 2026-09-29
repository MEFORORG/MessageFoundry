# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Phase-3b session-lifecycle hardening: backward-clock guard (AUTH-CLOCK), idle-vs-activity
(AUTH-IDLE), per-user session cap (AUTH-SESS-CAP), AD-resync revoke (AUTH-AD-REVOKE), Kerberos
reject audit (AUTH-K-AUDIT), and WS token extraction (API-3)."""

from __future__ import annotations

import time

import pytest

from messagefoundry.api.security import ws_token
from messagefoundry.auth import totp
from messagefoundry.auth.ldap import AdPrincipal
from messagefoundry.auth.service import AuthService
from messagefoundry.auth.tokens import hash_token, mint_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.store import MessageStore
from tests._admin_account import ADMIN_USERNAME, login_admin
from tests._totp_clock import pin_totp_clock

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
        # `now` pinned beside the rows: the cap counts only sessions still inside the idle window.
        await store.enforce_session_cap(
            "u", keep=2, idle_seconds=1800, split_mfa_pending=False, now=4.0
        )
        assert (await store.get_session("h1")).revoked_at is not None  # type: ignore[union-attr]
        assert (await store.get_session("h2")).revoked_at is None  # type: ignore[union-attr]
        assert (await store.get_session("h3")).revoked_at is None  # type: ignore[union-attr]
    finally:
        await store.close()


async def test_session_cap_contract_sqlite() -> None:
    """SQLite leg of the BACKLOG #1900 contract: the cap counts only LIVE sessions. The live
    Postgres and SQL Server suites run the same shared assertions."""
    store = await _store()
    try:
        from tests._session_cap_contract import assert_session_cap_contract

        await assert_session_cap_contract(store)
    finally:
        await store.close()


async def test_login_cap_skips_lapsed_sessions() -> None:
    """BACKLOG #1900, service level: a login past the cap must not sign out a live device because
    NEWER lapsed rows sit on record. Pins that ``_issue_session`` hands the store the same idle
    timeout ``identity_for_token`` validates against, in seconds: too large or too small fails."""
    store = await _store()
    try:
        settings = AuthSettings(max_sessions_per_user=2)
        service = AuthService(store, settings)
        await service.initialize()
        await _local_user(service, "carol")
        user = await store.get_user_by_username("carol")
        assert user is not None
        live_device = (await service.login("carol", PW)).token
        assert live_device is not None
        now = time.time()
        idle = settings.session_idle_timeout_minutes * 60
        # The live device was last used a minute inside the idle window. An idle timeout passed too
        # SMALL (minutes read as seconds, say) would call it lapsed and revoke it.
        await store.touch_session(hash_token(live_device), now=now - idle + 60)
        # Two rows created AFTER the live device, so they outrank it by created_at, yet both are dead
        # to the validator: one idle past the timeout, one past its absolute expiry. A timeout passed
        # too LARGE would count the idle one as live and evict the device in its favour.
        idle_gone, abs_gone = hash_token(mint_token()), hash_token(mint_token())
        await store.create_session(
            token_hash=idle_gone, user_id=user.id, expires_at=now + 3600, now=now
        )
        await store.touch_session(idle_gone, now=now - idle - 60)
        await store.create_session(
            token_hash=abs_gone, user_id=user.id, expires_at=now - 1, now=now
        )

        second = (await service.login("carol", PW)).token
        assert second is not None
        assert await service.identity_for_token(live_device) is not None, (
            "the cap signed out a live device to make room for lapsed rows"
        )
        assert await service.identity_for_token(second) is not None
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


# --- BACKLOG #2076: a sign-in still owing its second factor cannot evict a full session ------


async def _enrolled_admin(
    service: AuthService, monkeypatch: pytest.MonkeyPatch
) -> tuple[str, str, list[str]]:
    """An Administrator with TOTP enrolled. Returns ``(full_token, password, recovery_codes)``: the
    enrolment session, which completing enrolment leaves fully signed in, and single-use codes that
    complete later sign-ins without racing the TOTP clock."""
    identity, token, password = await login_admin(service)
    enroll = await service.begin_mfa_enrollment(identity)
    t0 = 1_000_000.0
    pin_totp_clock(monkeypatch, t0)
    done = await service.confirm_mfa_enrollment(
        identity, totp.totp(enroll.secret, now=t0), token=token
    )
    assert done.ok and done.token is not None and done.recovery_codes
    return done.token, password, list(done.recovery_codes)


async def _full_sign_in(service: AuthService, password: str, code: str) -> str:
    pending = (await service.login(ADMIN_USERNAME, password)).token
    assert pending is not None
    done = await service.verify_mfa(pending, code)
    assert done.ok and done.token is not None
    return done.token


async def _is_full(service: AuthService, token: str) -> bool:
    return await service.identity_for_token(token) is not None and await service.mfa_satisfied(
        token
    )


async def test_password_only_sign_ins_leave_full_sessions_live(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BACKLOG #2076, closing criterion 3. A caller holding only the password signs in more times
    than the cap allows. Every fully signed-in session must still be live afterwards, and the
    pending sign-ins stay bounded by the cap themselves."""
    store = await _store()
    try:
        cap = 2
        service = AuthService(
            store, AuthSettings(mfa_verify_min_elapsed_seconds=0, max_sessions_per_user=cap)
        )
        full_first, password, codes = await _enrolled_admin(service, monkeypatch)
        full_second = await _full_sign_in(service, password, codes[0])
        assert await _is_full(service, full_first) and await _is_full(service, full_second)

        pending = [(await service.login(ADMIN_USERNAME, password)).token for _ in range(cap + 3)]
        assert all(t is not None for t in pending)

        assert await _is_full(service, full_first), (
            "a password-only sign-in evicted a fully signed-in session (BACKLOG #2076)"
        )
        assert await _is_full(service, full_second)
        live_pending = [t for t in pending if t and await service.identity_for_token(t) is not None]
        assert len(live_pending) == cap, "pending sign-ins must stay bounded by the cap"
    finally:
        await store.close()


async def test_completing_mfa_evicts_the_oldest_full_sibling_not_itself(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BACKLOG #2076: completing the second factor moves a session into the full group, so the cap
    runs again. The session that just completed must survive even though it SIGNED IN before its
    siblings; the oldest-completed sibling goes instead."""
    store = await _store()
    try:
        service = AuthService(
            store, AuthSettings(mfa_verify_min_elapsed_seconds=0, max_sessions_per_user=2)
        )
        _first, password, codes = await _enrolled_admin(service, monkeypatch)
        # Signs in now, completes last: the oldest `created_at` among the survivors.
        waiting = (await service.login(ADMIN_USERNAME, password)).token
        assert waiting is not None
        sibling_a = await _full_sign_in(service, password, codes[0])
        sibling_b = await _full_sign_in(service, password, codes[1])
        assert await _is_full(service, sibling_a) and await _is_full(service, sibling_b)

        done = await service.verify_mfa(waiting, codes[2])
        assert done.ok and done.token is not None

        assert await _is_full(service, done.token), (
            "the session that just completed MFA was evicted because it signed in first"
        )
        assert await _is_full(service, sibling_b)
        assert await service.identity_for_token(sibling_a) is None, (
            "the cap must hold full sessions to `keep`: the oldest-completed sibling goes"
        )
    finally:
        await store.close()


async def test_a_password_step_up_never_revokes_the_session_it_hands_back() -> None:
    """BACKLOG #2076, review round 1: the cap re-runs only for a ceremony that stamps a second
    factor. A re-proof does not re-rank the row, so a cap run there could revoke the session it was
    rotating and still report success. Shape: the cap is lowered while the user holds more sessions
    than the new cap, and the OLDEST device steps up."""
    store = await _store()
    try:
        roomy = AuthService(store, AuthSettings(max_sessions_per_user=5, require_mfa=False))
        await roomy.initialize()
        await _local_user(roomy, "dana")
        tokens = [(await roomy.login("dana", PW)).token for _ in range(4)]
        oldest = tokens[0]
        assert oldest is not None

        tight = AuthService(store, AuthSettings(max_sessions_per_user=2, require_mfa=False))
        identity = await tight.identity_for_token(oldest)
        assert identity is not None
        stepped = await tight.reauth(identity, PW, token=oldest)

        assert stepped.ok and stepped.token is not None
        assert await tight.identity_for_token(stepped.token) is not None, (
            "a step-up reported success and handed back a session the cap had just revoked"
        )
    finally:
        await store.close()


def test_the_factor_ceremony_set_matches_the_ceremonies_that_stamp() -> None:
    """``_FACTOR_CEREMONIES`` decides where the cap re-runs after an elevation. Pin it against the
    code: every service method that stamps ``mark_session_mfa_verified`` and then elevates must name
    a ceremony in the set, and no method that elevates WITHOUT stamping may. A new factor ceremony
    that forgot the set would otherwise skip the cap silently."""
    import ast
    import inspect
    import textwrap

    from messagefoundry.auth import service as service_module

    tree = ast.parse(textwrap.dedent(inspect.getsource(service_module.AuthService)))
    stamping: set[str] = set()
    other: set[str] = set()
    for fn in ast.walk(tree):
        if not isinstance(fn, ast.AsyncFunctionDef):
            continue
        calls = [n for n in ast.walk(fn) if isinstance(n, ast.Call)]
        names = {c.func.attr for c in calls if isinstance(c.func, ast.Attribute)}
        for call in calls:
            if not (
                isinstance(call.func, ast.Attribute)
                and call.func.attr in {"_elevated", "_elevated_hash"}
            ):
                continue
            for kw in call.keywords:
                if kw.arg == "ceremony" and isinstance(kw.value, ast.Constant):
                    target = stamping if "mark_session_mfa_verified" in names else other
                    target.add(str(kw.value.value))
    assert stamping, "found no stamping ceremony -- the scan is broken, not the code"
    assert other, "found no re-proof ceremony -- the scan is broken, not the code"
    assert stamping == service_module._FACTOR_CEREMONIES
    assert not other & service_module._FACTOR_CEREMONIES


# --- BACKLOG #2096: one liveness rule, in Python and in SQL ------------------------------------


def test_session_is_live_matches_the_sql_liveness_predicate() -> None:
    """``SessionRecord.is_live`` and ``_SESSION_LIVE_SQL`` are the one rule in two languages: the
    validator uses the first, the session cap the second. Pin them together on a grid that puts a
    row ON, just inside and just past each of the four comparisons, evaluated by SQLite itself."""
    import itertools
    import sqlite3

    from messagefoundry.store.store import (
        _SESSION_LIVE_SQL,
        SessionRecord,
        _session_live_params,
    )

    now, idle = 10_000.0, 600.0
    stamps = (now - idle - 1, now - idle, now - 1, now, now + 1)
    expiries = (now - 1, now, now + 1)
    db = sqlite3.connect(":memory:")
    try:
        db.execute(
            "CREATE TABLE sessions (id INTEGER PRIMARY KEY, created_at REAL, last_used_at REAL,"
            " expires_at REAL)"
        )
        rows: dict[int, SessionRecord] = {}
        for i, (created, used, expires) in enumerate(itertools.product(stamps, stamps, expiries)):
            db.execute("INSERT INTO sessions VALUES (?,?,?,?)", (i, created, used, expires))
            rows[i] = SessionRecord(
                token_hash=str(i),
                user_id="u",
                created_at=created,
                expires_at=expires,
                last_used_at=used,
                revoked_at=None,
                client=None,
            )
        live_sql = {
            r[0]
            for r in db.execute(
                f"SELECT id FROM sessions WHERE {_SESSION_LIVE_SQL}",
                _session_live_params(now, idle),
            )
        }
    finally:
        db.close()
    live_py = {i for i, r in rows.items() if r.is_live(now=now, idle_seconds=idle)}
    assert live_py == live_sql
    # The grid must exercise both answers, or the equality above proves nothing.
    assert live_py and len(live_py) < len(rows)


async def test_superseding_a_clock_stepped_session_is_not_audited_as_live() -> None:
    """BACKLOG #2096, criterion 2: ``was_live`` uses the validator's rule, clock-step checks
    included. A prior session stamped ahead of now is one the validator refuses, so ending it at a
    fresh sign-in must not write an ``auth.session_revoked`` row claiming a live session ended."""
    store = await _store()
    try:
        service = AuthService(store, AuthSettings(require_mfa=False))
        await service.initialize()
        await _local_user(service, "erin")
        user = await store.get_user_by_username("erin")
        assert user is not None
        ahead = mint_token()
        future = time.time() + 10_000
        await store.create_session(
            token_hash=hash_token(ahead), user_id=user.id, expires_at=future + 3600, now=future
        )
        live = (await service.login("erin", PW)).token
        assert live is not None

        await service.login("erin", PW, supersedes=ahead)
        await service.login("erin", PW, supersedes=live)

        ended = [a for a in await store.list_audit() if a["action"] == "auth.session_revoked"]
        # The control: superseding the LIVE session is audited, so the scan is armed.
        assert len(ended) == 1, [a["detail"] for a in ended]
        assert hash_token(live)[:12] in (ended[0]["detail"] or "")
        stepped = await store.get_session(hash_token(ahead))
        assert stepped is not None and stepped.revoked_at is not None, "it must still be ended"
    finally:
        await store.close()


async def test_the_session_inventory_hides_idle_expired_sessions() -> None:
    """BACKLOG #2096, criterion 3: the self-service inventory must not list a session the
    validator would refuse for idleness or absolute expiry. The internal "does this user hold a
    session" reads pass no idle timeout and still see the idle one.

    A session stamped ahead of the clock stays listed. Unpresented, it is live again once the clock
    catches up, so the user must still be able to see it and end it."""
    store = await _store()
    try:
        settings = AuthSettings(require_mfa=False)
        service = AuthService(store, settings)
        await service.initialize()
        await _local_user(service, "finn")
        user = await store.get_user_by_username("finn")
        assert user is not None
        live = (await service.login("finn", PW)).token
        assert live is not None
        idle = hash_token(mint_token())
        now = time.time()
        await store.create_session(token_hash=idle, user_id=user.id, expires_at=now + 3600, now=now)
        await store.touch_session(idle, now=now - settings.session_idle_timeout_minutes * 60 - 5)
        expired = hash_token(mint_token())
        await store.create_session(
            token_hash=expired, user_id=user.id, expires_at=now - 1, now=now - 60
        )
        ahead = hash_token(mint_token())
        await store.create_session(
            token_hash=ahead, user_id=user.id, expires_at=now + 7200, now=now + 3600
        )

        listed = {s.token_hash for s in await service.list_sessions(user.id)}
        assert idle not in listed, "the inventory listed an idle-expired session"
        assert expired not in listed, "the inventory listed an expired session"
        assert ahead in listed, "the inventory hid a clock-stepped session the user cannot end"
        assert listed == {hash_token(live), ahead}
        assert idle in {s.token_hash for s in await store.list_sessions(user.id)}
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
        # AD PASSWORD LOGIN is retired (BACKLOG #1137); this session is a fixture, so it mints

        # through the surviving tail Kerberos and OIDC both end at.

        t1 = (await service._complete_ad_login(principal, None, mfa_verified=True)).token
        assert t1 is not None and await service.identity_for_token(t1) is not None

        # Directory-side role change: the next login resolves different roles.
        await service.set_ad_group_map([("cn=mf-ops,dc=x", "viewer")], actor="admin")
        t2 = (await service._complete_ad_login(principal, None, mfa_verified=True)).token
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


# --- ADR 0142 AC-6: the federated session cap, and its byte-identity guard ----


async def _session_for(store: MessageStore, token: str) -> tuple[float, float]:
    """Return ``(created_at, expires_at)`` for a minted token."""
    session = await store.get_session(hash_token(token))
    assert session is not None
    return session.created_at, session.expires_at


async def test_local_and_ad_session_expiry_is_unchanged_by_the_cap_seam() -> None:
    """AC-6's second half: `_issue_session` grew a `max_expires_at` knob, and every shipped caller
    must keep landing on the flat local absolute lifetime. Asserted on the DERIVED lifetime rather
    than a wall-clock deadline so the test cannot flake on a slow box."""
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
        await _local_user(service, "alice")

        absolute = AuthSettings().session_absolute_hours * 3600
        local_token = (await service.login("alice", PW)).token
        assert local_token is not None
        created, expires = await _session_for(store, local_token)
        assert expires - created == pytest.approx(absolute, abs=2)

        # AD PASSWORD LOGIN is retired (BACKLOG #1137); this session is a fixture, so it mints

        # through the surviving tail Kerberos and OIDC both end at.

        ad_token = (await service._complete_ad_login(principal, None, mfa_verified=True)).token
        assert ad_token is not None
        created, expires = await _session_for(store, ad_token)
        assert expires - created == pytest.approx(absolute, abs=2)
    finally:
        await store.close()


async def test_ad_login_success_audit_detail_is_byte_identical() -> None:
    """The mech/evidence seam must be OMITTED, not null-valued, for the shipped directory paths —
    `_json` is `json.dumps(sort_keys=True)`, so a null key is a different stored string."""
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
        # AD PASSWORD LOGIN is retired (BACKLOG #1137). The byte-identity property is about the
        # audit row the SURVIVING directory paths write, so it is pinned on their shared tail.
        assert (await service._complete_ad_login(principal, None, mfa_verified=True)).ok

        rows = [a for a in await store.list_audit() if a["action"] == "auth.login_success"]
        assert len(rows) == 1
        assert rows[0]["detail"] == '{"provider": "ad", "roles": []}'
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
