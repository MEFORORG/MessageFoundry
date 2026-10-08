# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Security-hardening regression tests for the auth subsystem.

Each test pins one fix from the security review so it can't silently regress:
  H1  PHI summaries are redacted for callers lacking messages:view_summary
  H2  AD requires LDAPS unless an explicit insecure override is set
  M2  must_change_password is enforced server-side (not merely advisory)
  M4  an AD login cannot adopt/overwrite a like-named local account
  M5  the last enabled administrator cannot be stripped of the admin role
  M6  /me/password requires the current password (defeats session-only takeover)

M3 pinned that the first-run bootstrap password went to a restricted file and never the log. ADR
0183 Amendment A, Wave 2, retired that account, so no such password or file exists and M3 went
with it. ``tests/test_start_without_an_administrator.py`` pins that no file is written.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from _totp_clock import fresh_totp
from pydantic import ValidationError
from starlette.datastructures import Address

from messagefoundry.api import create_app
from messagefoundry.api.app import _session_reaper
from messagefoundry.auth import Role, hash_password
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.ldap import AdPrincipal, LdapAuthenticator, LdapError
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store import MessageStatus
from messagefoundry.store.store import MessageStore
from tests._admin_account import ADMIN_USERNAME, create_admin, create_local_user_chosen

PW = "a-strong-test-passphrase"  # ≥15, no app/vendor terms — satisfies the ASVS policy (WP-3)
ADT = "MSH|^~\\&|S|F|R|RF|20260604||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(
        tmp_path / "auth_hardening.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


async def _service(engine: Engine, settings: AuthSettings | None = None) -> AuthService:
    # require_mfa=False by default: every test here pins an RBAC / redaction / audit fix, none of them
    # the second factor, so the ASVS 6.3.3 access gate would only stand between the fixture and the
    # behaviour under test. The tests that DO exercise the gate build their own AuthSettings.
    service = AuthService(engine.store, settings or AuthSettings(require_mfa=False))
    await service.initialize()
    return service


def _client(engine: Engine, service: AuthService, **app_kwargs: object) -> httpx.AsyncClient:
    """The shared authenticated client. ``app_kwargs`` pass straight through to ``create_app``, so a
    test that needs one non-default app setting does not have to re-implement the transport wiring."""
    transport = httpx.ASGITransport(app=create_app(engine, auth=service, **app_kwargs))  # type: ignore[arg-type]
    return httpx.AsyncClient(transport=transport, base_url="http://t")


async def _add(service: AuthService, username: str, *roles: Role) -> None:
    user_id = await create_local_user_chosen(
        service,
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=[r.value for r in roles],
        actor="test",
    )
    # BACKLOG #1152: an unset channel scope now DENIES. Grant the estate explicitly so this
    # fixture still stands for an operator who has been provisioned; the channel axis itself
    # is exercised in tests/test_channel_rbac.py.
    await service.set_channel_scope(user_id, [ALL_CHANNELS], actor="test")
    # Admin-created accounts force first-login rotation (WP-L3-12); clear it so these fixtures behave
    # like already-onboarded users (keeping the same hash).
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id,
        password_hash=user.password_hash,
        must_change_password=False,
        password_generated=False,
    )


async def _login(c: httpx.AsyncClient, username: str, password: str = PW):
    return await c.post(
        "/auth/login", json={"username": username, "password": password, "provider": "local"}
    )


async def _reauth(
    c: httpx.AsyncClient, token: str, *, purpose: str | None = None, password: str = PW
) -> tuple[httpx.Response, str]:
    """POST /me/reauth; ``purpose`` mints the single-use per-action grant (ADR 0077).

    Returns ``(response, the token to use next)``: a successful re-auth re-keys the session
    (ASVS 7.2.4), so the caller must adopt the new bearer or every later request 401s. A refusal
    rotates nothing and hands the incoming token back."""
    body: dict[str, str] = {"password": password}
    if purpose is not None:
        body["purpose"] = purpose
    r = await c.post("/me/reauth", json=body, headers=_auth(token))
    if r.status_code != 200:
        return r, token
    fresh = r.json().get("token")
    assert isinstance(fresh, str) and fresh, "an elevation route returned no rotated token"
    return r, fresh


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# --- H1: PHI summary is an access control, not just an audit trigger ----------


async def test_summary_redacted_for_caller_without_view_summary(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)  # operator holds messages:view_summary
    await _add(service, "vw", Role.VIEWER)  # viewer holds messages:read only
    # An ERROR-disposition row whose error text quotes field values (PHI) — gated with the summary.
    await engine.store.record_received(
        channel_id="ch1",
        raw=ADT,
        status=MessageStatus.ERROR,
        error="bad PID-5: DOE^JANE",
        summary="MRN 1 · DOE",
    )
    async with _client(engine, service) as c:
        op = _auth((await _login(c, "op")).json()["token"])
        vw = _auth((await _login(c, "vw")).json()["token"])
        op_msg = (await c.get("/messages", headers=op)).json()["messages"][0]
        vw_msg = (await c.get("/messages", headers=vw)).json()["messages"][0]
        # The LIST is the census surface, so an authorized operator sees the summary MASKED here
        # (ASVS 14.2.6); only an explicit per-message reveal lifts it (BACKLOG #2346). The error text
        # is masked whole on the list too (BACKLOG #2436), and the viewer's nulls below are what
        # keep this a test of redaction as well as of the mask.
        assert op_msg["summary"] == "MRN **** · ****"
        assert op_msg["error"] == "****"
        assert vw_msg["summary"] is None  # redacted: viewer lacks messages:view_summary
        assert vw_msg["error"] is None  # error text is PHI-gated the same way (low-8)


# --- H2: AD must use LDAPS unless explicitly overridden ----------------------


def test_ad_requires_ldaps_unless_overridden() -> None:
    with pytest.raises(ValidationError):
        AuthSettings(
            ad_enabled=True,
            ad_server="ldap://dc",
            ad_user_search_base="DC=x",
            ad_bind_dn="CN=svc,DC=x",
            ad_bind_password="x",
        )
    # ldaps is accepted, as is an explicit trusted-network override
    AuthSettings(
        ad_enabled=True,
        ad_server="ldaps://dc",
        ad_user_search_base="DC=x",
        ad_bind_dn="CN=svc,DC=x",
        ad_bind_password="x",
    )
    AuthSettings(
        ad_enabled=True,
        ad_server="ldap://dc",
        ad_user_search_base="DC=x",
        ad_allow_insecure_ldap=True,
        ad_bind_dn="CN=svc,DC=x",
        ad_bind_password="x",
    )


# --- M2: must_change_password is enforced server-side ------------------------


async def test_must_change_password_blocks_until_rotated(engine: Engine) -> None:
    # M2 + ASVS 6.3.3, re-ordered by ADR 0197 Amendment A (AC-A3). An unclaimed admin is must_change
    # AND mfa_pending with no factor. It used to rotate first; that passed the holder through "a
    # chosen password, no factor, no session", which anyone who knows the username could lock. Now
    # it ENROLS TOTP first, from the pending must-change session, then rotates. The pair is still
    # escapable -- the bricked-fresh-account regression this test was written against.
    # The login-to-MFA floor is off: the confirm below runs at once on the signed-in session, and
    # the floor covers it (BACKLOG #2389).
    service = AuthService(
        engine.store, AuthSettings(mfa_verify_min_elapsed_seconds=0, login_rate_limit_enabled=False)
    )
    admin = await create_admin(service)
    async with _client(engine, service) as c:
        login = await _login(c, admin.username, admin.password)
        assert login.status_code == 200 and login.json()["must_change_password"] is True
        tok = str(login.json()["token"])
        # a rotation-required session may not reach protected routes...
        blocked = await c.get("/users", headers=_auth(tok))
        assert blocked.status_code == 403
        # ...and it is the PASSWORD refusal, not the MFA one, naming the step that comes first.
        assert blocked.headers.get("X-MFA-Required") is None
        assert "password change required" in blocked.text
        assert "enrol an authenticator app first" in blocked.text
        # ...the self-service routes stay reachable...
        assert (await c.get("/auth/me", headers=_auth(tok))).status_code == 200
        # ...but the rotation waits for TOTP.
        refused = await c.post(
            "/me/password",
            headers=_auth(tok),
            json={"current_password": admin.password, "new_password": "a-rotated-passphrase-99"},
        )
        assert refused.status_code == 403 and "enrol an authenticator app first" in refused.text

        # The account is NOT bricked: the enrolment is reachable from the must-change session.
        r, tok = await _reauth(c, tok, purpose="mfa_enroll", password=admin.password)
        assert r.status_code == 200
        secret = (await c.post("/me/mfa/enroll", headers=_auth(tok))).json()["secret"]
        r, tok = await _reauth(c, tok, purpose="mfa_confirm", password=admin.password)
        assert r.status_code == 200
        confirmed = await c.post(
            "/me/mfa/confirm", json={"code": fresh_totp(secret)}, headers=_auth(tok)
        )
        assert confirmed.status_code == 200
        tok = str(confirmed.json()["token"])  # the confirm re-keyed the session (ASVS 7.2.4)
        # Still must-change, and now nothing comes first: the refusal says rotate, only.
        blocked = await c.get("/users", headers=_auth(tok))
        assert blocked.status_code == 403 and "enrol" not in blocked.text
        rotated = await c.post(
            "/me/password",
            headers=_auth(tok),
            json={"current_password": admin.password, "new_password": "a-rotated-passphrase-99"},
        )
        assert rotated.status_code == 200

        # Rotating ended every session. The next sign-in owes the TOTP it enrolled.
        tok = (await _login(c, admin.username, "a-rotated-passphrase-99")).json()["token"]
        pending = await c.get("/users", headers=_auth(tok))
        assert pending.status_code == 403 and pending.headers.get("X-MFA-Required") == "1"


async def _no_sleep(deadline: float) -> None:
    """Stands in for ``service._sleep_until``, the failure-equalizing pad, so a refusal costs no
    wall-clock time. The deadline suite owns the pad's own property."""


async def test_ad_login_conflicting_with_local_account_is_rejected(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """M4, driven through a directory leg that still reaches ``_complete_ad_login`` (BACKLOG #1971).

    This used to post ``/auth/login`` with ``provider="ad"``. Directory PASSWORD sign-in is retired,
    so ``_dispatch_login`` refused that request before any directory work and the 401 held with the
    conflict branch deleted. Windows SSO (``POST /auth/negotiate``) is a live leg into the same
    method, so the principal it resolves meets the like-named LOCAL account there.

    The 401 alone cannot tell the refusals apart, so the test also pins the branch's own audit row,
    that the directory was really consulted, and that the local account survived unadopted.
    """
    principal = AdPrincipal(
        username=ADMIN_USERNAME,  # collides with the LOCAL admin created below
        display_name=None,
        email=None,
        dn=f"CN={ADMIN_USERNAME},DC=x",
        groups=frozenset(),
        # A real immutable id, so the object-id-missing refusal cannot stand in for this one.
        # Measured with the conflict branch deleted: a later check still refuses, as
        # ``directory_identity_conflict``, so the 401 holds either way and only the audit reason
        # below turns red.
        directory_object_id="12345678-1234-1234-1234-56789abcdef0",
    )
    resolved: list[str] = []

    class _FakeLdap:
        def resolve_principal(self, username: str, **_: object) -> AdPrincipal | None:
            resolved.append(username)
            return principal if username == ADMIN_USERNAME else None

    # The SPNEGO acceptor needs a real KDC; the principal it would name is the input under test.
    monkeypatch.setattr(
        "messagefoundry.auth.service.kerberos_principal", lambda _t, _s: ADMIN_USERNAME
    )
    monkeypatch.setattr("messagefoundry.auth.service._sleep_until", _no_sleep)
    settings = AuthSettings(
        ad_enabled=True,
        kerberos_enabled=True,
        ad_server="ldaps://x",
        ad_user_search_base="DC=x",
        ad_bind_dn="CN=svc,DC=x",
        ad_bind_password="x",
    )
    service = AuthService(engine.store, settings, ldap=_FakeLdap())  # type: ignore[arg-type]
    await create_admin(service)  # the LOCAL account the AD login must not adopt
    before = await engine.store.get_user_by_username(ADMIN_USERNAME)
    assert before is not None and before.auth_provider == "local"

    async with _client(engine, service) as c:
        r = await c.post("/auth/negotiate", headers={"Authorization": "Negotiate c3BuZWdv"})
    assert r.status_code == 401  # the AD sign-in cannot take over the local account
    assert ADMIN_USERNAME in resolved, "the directory leg never ran, so the branch was not reached"

    failures = [
        dict(a)
        for a in await engine.store.list_audit(action="auth.login_failed", actor=ADMIN_USERNAME)
    ]
    reasons = [json.loads(str(a["detail"]))["reason"] for a in failures]
    assert reasons == ["local_account_conflict"], (
        f"the refusal was not the provider-confusion branch: {failures}"
    )
    assert await engine.store.list_audit(action="auth.login_success", actor=ADMIN_USERNAME) == []
    after = await engine.store.get_user_by_username(ADMIN_USERNAME)
    assert after is not None
    assert (after.id, after.auth_provider, after.directory_object_id) == (
        before.id,
        "local",
        before.directory_object_id,
    ), "the AD sign-in adopted the local account"


# --- M5: the last administrator is protected ---------------------------------


async def test_cannot_remove_last_administrator(engine: Engine) -> None:
    # Last-admin guard test (step-up admin CRUD), not an MFA test: pin require_mfa=False so the
    # BACKLOG #187 secure default (require_mfa now ON) doesn't 403 the roles/CRUD ops first.
    service = AuthService(
        engine.store, AuthSettings(admin_write_min_interval_seconds=0, require_mfa=False)
    )
    admin = await create_admin(service)
    async with _client(engine, service) as c:
        h = _auth((await _login(c, admin.username, admin.password)).json()["token"])
        # clear the must-change flag so the admin can operate
        await c.post(
            "/me/password",
            headers=h,
            json={"current_password": admin.password, "new_password": "a-rotated-passphrase-99"},
        )
        h = _auth((await _login(c, admin.username, "a-rotated-passphrase-99")).json()["token"])
        my_id = (await c.get("/auth/me", headers=h)).json()["user_id"]
        # stripping admin from the only administrator is refused
        assert (
            await c.put(f"/users/{my_id}/roles", headers=h, json={"roles": ["viewer"]})
        ).status_code == 400
        # add a second admin, and the demotion is now allowed
        assert (
            await c.post(
                "/users",
                headers=h,
                json={
                    "username": "root2",
                    "roles": ["administrator"],
                    "email": "root2@example.org",
                },
            )
        ).status_code == 201
        assert (
            await c.put(f"/users/{my_id}/roles", headers=h, json={"roles": ["viewer"]})
        ).status_code == 200


# --- M6: changing a password needs the current one ---------------------------


async def test_change_password_requires_current(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "u", Role.VIEWER)
    async with _client(engine, service) as c:
        h = _auth((await _login(c, "u")).json()["token"])
        wrong = await c.post(
            "/me/password",
            headers=h,
            json={"current_password": "not-it", "new_password": "a-brand-new-passphrase"},
        )
        assert wrong.status_code == 403
        # the original session still works (the failed attempt did not revoke it)
        assert (await c.get("/auth/me", headers=h)).status_code == 200
        ok = await c.post(
            "/me/password",
            headers=h,
            json={"current_password": PW, "new_password": "a-brand-new-passphrase"},
        )
        assert ok.status_code == 200


# --- L7: AD requires a service-account bind (no anonymous bind) ---------------


def test_ad_requires_service_account_bind() -> None:
    # the settings validator refuses AD without a service account
    with pytest.raises(ValidationError):
        AuthSettings(ad_enabled=True, ad_server="ldaps://dc", ad_user_search_base="DC=x")
    # and the authenticator refuses to construct one (defense in depth)
    unchecked = AuthSettings.model_construct(
        ad_enabled=True, ad_server="ldaps://dc", ad_user_search_base="DC=x"
    )
    with pytest.raises(LdapError):
        LdapAuthenticator(unchecked)


# --- L3: a lapsed lockout window restarts the failure counter ----------------


async def test_lockout_counter_resets_after_window(engine: Engine) -> None:
    service = AuthService(engine.store, AuthSettings(lockout_threshold=3, lockout_minutes=15))
    await engine.store.upsert_role(role_id="viewer", display_name="Viewer")
    await engine.store.create_user(
        user_id="u1",
        username="bob",
        auth_provider="local",
        password_hash=hash_password(PW),
        password_generated=False,
    )
    # simulate a prior lockout whose window has already lapsed
    await engine.store.record_login_failure(
        "u1", failed_attempts=3, locked_until=time.time() - 1.0, now=time.time()
    )
    out = await service.login("bob", "wrong")
    assert not out.ok and out.error == "invalid credentials"  # not re-locked
    user = await engine.store.get_user("u1")
    assert user is not None and user.failed_attempts == 1 and user.locked_until is None


# --- ADR 0197 AC-6: every refused sign-in answers alike on both surfaces ---------------------------


async def test_every_refused_combined_sign_in_answers_alike_on_the_json_and_console_surfaces(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-6 (BACKLOG #1131), the route half. Unknown user, wrong password, right password with a
    wrong code, wrong password with a right code, and each lock live, all answer the same status and
    body on ``POST /auth/login`` and the same redirect on ``POST /ui/login``. The combined sign-in's
    success is today's success, so the field that carries the code is the only change to the call."""
    from _totp_clock import pin_totp_clock

    from messagefoundry.auth import totp

    service = await _service(
        engine,
        AuthSettings(require_mfa=False, lockout_threshold=50, login_rate_limit_enabled=False),
    )
    await _add(service, "carol")
    user = await engine.store.get_user_by_username("carol")
    assert user is not None
    secret = totp.generate_secret()
    await engine.store.set_totp_secret(user.id, secret=secret)
    assert await engine.store.enable_totp(user.id, recovery_code_hashes=[])
    now = [3_000_000.0]

    def code(valid: bool) -> str:
        now[0] += totp.DEFAULT_PERIOD
        pin_totp_clock(monkeypatch, now[0])
        live = totp.totp(secret, now=now[0])
        return live if valid else f"{(int(live[0]) + 1) % 10}{live[1:]}"

    async def lock(counter: str) -> None:
        for _ in range(50):
            await engine.store.increment_login_failure(
                user.id,
                counter=counter,
                threshold=50,
                lockout_seconds=900.0,
                max_lockout_seconds=86_400.0,
                now=time.time(),
            )

    async with _client(engine, service, serve_ui=True) as c:
        # The positive control: the combined sign-in succeeds and answers exactly today's shape.
        ok = await c.post(
            "/auth/login", json={"username": "carol", "password": PW, "totp_code": code(True)}
        )
        assert ok.status_code == 200 and ok.json()["mfa_required"] is False
        assert set(ok.json()) == set(
            (await c.post("/auth/login", json={"username": "carol", "password": PW})).json()
        ), "the combined sign-in's answer gained or lost a field"

        async def both(username: str, password: str, kind: str | None) -> None:
            """One attempt on each surface. ``kind`` is None (no code), "right" or "wrong"; each
            surface gets its own code, because a right code spent on one would be a replay on
            the other and change the shape under test."""
            body: dict[str, str] = {"username": username, "password": password}
            if kind is not None:
                body["totp_code"] = code(kind == "right")
            r = await c.post("/auth/login", json=body)
            answers.append((r.status_code, r.text))
            if kind is not None:
                body["totp_code"] = code(kind == "right")
            ui = await c.post("/ui/login", data=body, follow_redirects=False)
            redirects.append((ui.status_code, ui.headers.get("location")))

        answers: list[tuple[int, str]] = []
        redirects: list[tuple[int, str | None]] = []
        await both("nobody-by-this-name", PW, "wrong")
        await both("carol", "wrong-passphrase", None)
        await both("carol", "wrong-passphrase", "wrong")
        await both("carol", PW, "wrong")
        await both("carol", "wrong-passphrase", "right")
        await lock("sign_in")
        await both("carol", "wrong-passphrase", "wrong")
        await both("carol", PW, None)
        await lock("second_step")
        await both("carol", PW, "right")
        assert set(answers) == {(401, '{"detail":"invalid credentials"}')}, answers
        assert set(redirects) == {(303, "/ui/login?e=bad")}, redirects

        # Non-ASCII digits are an ordinary refusal on both surfaces, never a 500 (ADR 0197). The
        # JSON body is refused by shape, the same for every account; the console treats the code as
        # a wrong one.
        for odd in ("\u0660" * 6, "\uff11" * 6):
            r = await c.post(
                "/auth/login", json={"username": "carol", "password": PW, "totp_code": odd}
            )
            assert r.status_code == 422, r.text
            ui = await c.post(
                "/ui/login",
                data={"username": "carol", "password": PW, "totp_code": odd},
                follow_redirects=False,
            )
            assert (ui.status_code, ui.headers.get("location")) == (303, "/ui/login?e=bad")


# --- L6: nested-group LDAP filter escapes the user DN ------------------------


def test_nested_group_filter_escapes_user_dn() -> None:
    captured: dict[str, object] = {}

    class _Conn:
        entries: list[object] = []
        result: dict[str, object] | None = None  # no referral

        def search(self, **kw: object) -> None:
            captured.update(kw)

    auth = LdapAuthenticator(
        AuthSettings(
            ad_enabled=True,
            ad_server="ldaps://x",
            ad_user_search_base="DC=x",
            ad_group_search_base="DC=x",
            ad_bind_dn="CN=svc,DC=x",
            ad_bind_password="x",
        )
    )
    auth._resolve_groups(_Conn(), "CN=a*b(c),DC=x", [])
    flt = str(captured["search_filter"])
    assert "\\2a" in flt and "\\28" in flt  # '*' and '(' are RFC 4515-escaped
    assert ":=CN=a*b" not in flt  # the raw, unescaped DN is never interpolated


def test_find_user_rejects_disabled_ad_account() -> None:
    # M-18: a disabled AD account (userAccountControl ACCOUNTDISABLE bit) must not authenticate —
    # _find_user is the shared lookup for both password AD login and Kerberos SSO.
    class _Attr:
        def __init__(self, value: object) -> None:
            self.value = value
            self.values = value if isinstance(value, list) else [value]

    class _Entry:
        entry_dn = "CN=jane,DC=x"

        def __init__(self, attrs: dict[str, object]) -> None:
            self._a = attrs

        def __contains__(self, k: str) -> bool:
            return k in self._a

        def __getitem__(self, k: str) -> _Attr:
            return _Attr(self._a[k])

    class _Conn:
        def __init__(self, entry: _Entry) -> None:
            self.entries = [entry]
            self.result: dict[str, object] | None = None  # no referral

        def search(self, **kw: object) -> None:
            pass

    auth = LdapAuthenticator(
        AuthSettings(
            ad_enabled=True,
            ad_server="ldaps://x",
            ad_user_search_base="DC=x",
            ad_bind_dn="CN=svc,DC=x",
            ad_bind_password="x",
        )
    )
    base = {"sAMAccountName": "jane", "displayName": "Jane", "mail": "j@x", "memberOf": []}
    # 0x202 = NORMAL_ACCOUNT | ACCOUNTDISABLE -> rejected (treated as not found)
    assert auth._find_user(_Conn(_Entry({**base, "userAccountControl": "514"})), "jane") is None
    # 0x200 = NORMAL_ACCOUNT (enabled) -> found
    found = auth._find_user(_Conn(_Entry({**base, "userAccountControl": "512"})), "jane")
    assert found is not None and found["username"] == "jane"


# --- L1: unknown-user login still runs an argon2 verify (timing equalizer) ---


async def test_unknown_user_login_runs_password_verify(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    import messagefoundry.auth.service as svc

    calls = {"n": 0}
    real = svc.verify_password

    def counting(stored_hash: str, password: str) -> bool:
        calls["n"] += 1
        return real(stored_hash, password)

    monkeypatch.setattr(svc, "verify_password", counting)
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    out = await service.login("ghost-user-does-not-exist", "whatever")
    assert not out.ok
    assert calls["n"] >= 1  # the dummy verify ran for the unknown user


# --- #1167 (ASVS 11.2.4): the recovery-code walk must cost the same whatever is presented --------


@pytest.mark.parametrize(
    ("present", "why"),
    [("first", "matches slot 0"), ("last", "matches the final slot"), ("wrong", "matches nothing")],
)
async def test_recovery_code_verify_cost_does_not_vary_with_the_code(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, present: str, why: str
) -> None:
    """The argon2 verify COUNT must be the configured slot count in every case.

    It used to `return` on the first match, so the number of ~64 MiB verifications was a function of
    which code was presented -- and on the failure path, of how many codes REMAINED, so timing one
    failed attempt leaked the user's remaining recovery-code count.

    THIS IS A CONSTANT-WORK CLAIM, NOT A CONSTANT-TIME ONE. The argon2 verifies dominate by orders
    of magnitude and are what this pins; the store round trip on a match is not equalized and is not
    claimed to be. See ADR 0170.
    """
    import messagefoundry.auth.service as svc

    calls = {"n": 0}
    real = svc.verify_password
    monkeypatch.setattr(
        svc,
        "verify_password",
        lambda stored, pw: (calls.__setitem__("n", calls["n"] + 1), real(stored, pw))[1],
    )

    slots = 10
    service = await _service(engine, AuthSettings(require_mfa=False, mfa_recovery_code_count=slots))
    await _add(service, "rec", Role.VIEWER)
    user = await engine.store.get_user_by_username("rec")
    assert user is not None
    # Deliberately fewer live codes than slots: the padding is what makes a FAILED attempt stop
    # leaking how many remain, which is the half an attacker with only the password can measure.
    codes = ["AAAA-1111", "BBBB-2222", "CCCC-3333"]
    # enable_totp needs a staged secret (BACKLOG #2224); this test never verifies a TOTP code.
    await engine.store.set_totp_secret(user.id, secret="JBSWY3DPEHPK3PXP")
    assert await engine.store.enable_totp(
        user.id, recovery_code_hashes=[hash_password(c) for c in codes]
    )

    presented = {"first": codes[0], "last": codes[-1], "wrong": "ZZZZ-9999"}[present]
    calls["n"] = 0
    ok = await service._verify_second_factor(user, presented)

    assert ok is (present != "wrong"), why
    assert calls["n"] == slots, (
        f"{why}: {calls['n']} argon2 verifies against {slots} slots -- the count varies with the "
        "code presented, so it still leaks. 3 would mean it short-circuits on the live codes only"
    )


@pytest.mark.parametrize(
    ("present", "expect_ok"), [("fresh", True), ("replayed", False), ("wrong", False)]
)
async def test_a_failed_totp_attempt_costs_the_recovery_walk_whatever_the_reason(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, present: str, expect_ok: bool
) -> None:
    """A replayed TOTP and a wrong code must both fail after the same argon2 work (#1167, ADR 0170).

    A replayed code matches the secret, so the branch used to return the store's refusal with no
    argon2 work at all, while a wrong code fell through to the full recovery-code walk. Both return
    False, and the wall clock told them apart. The ``wrong`` row is the control: it already paid
    the walk, so it pins the work the ``replayed`` row must match. A success stays fast (zero), and
    is not claimed to be equal.

    The HASHES are pinned as well as the count: a replay that padded with the dummy hash alone
    would cost differently from a wrong code as soon as the live codes and the dummy were minted
    under different argon2 parameters.
    """
    import messagefoundry.auth.service as svc
    from messagefoundry.auth import totp

    used: list[str] = []
    real = svc.verify_password

    def counting(stored_hash: str, password: str) -> bool:
        used.append(stored_hash)
        return real(stored_hash, password)

    monkeypatch.setattr(svc, "verify_password", counting)

    slots = 10
    service = await _service(engine, AuthSettings(require_mfa=False, mfa_recovery_code_count=slots))
    await _add(service, "totpeq", Role.VIEWER)
    user = await engine.store.get_user_by_username("totpeq")
    assert user is not None
    secret = totp.generate_secret()
    await engine.store.set_totp_secret(user.id, secret=secret)
    # Fewer live codes than slots, so a walk that forgot the padding would show as 2, not 10.
    live = [hash_password(c) for c in ("AAAA-1111", "BBBB-2222")]
    assert await engine.store.enable_totp(user.id, recovery_code_hashes=live)
    walk = live + [svc._DUMMY_PASSWORD_HASH] * (slots - len(live))
    # A fixed arrival moment, so the step cannot roll over between minting and verifying the code.
    arrived = 1_900_000_000.0
    code = totp.totp(secret, now=arrived)
    if present == "replayed":
        assert await service._verify_second_factor(user, code, arrived=arrived) is True
    elif present == "wrong":
        code = f"{(int(code) + 1) % 1_000_000:06d}"

    used.clear()
    ok = await service._verify_second_factor(user, code, arrived=arrived)

    assert ok is expect_ok
    expected = [] if expect_ok else walk
    assert len(used) == len(expected), (
        f"{present}: {len(used)} argon2 verifies, expected {len(expected)}. A replayed code "
        "making 0 means the TOTP branch still returns before the recovery-code work"
    )
    assert used == expected, f"{present}: the verifies did not run against the walk's own hashes"
    if present == "replayed":
        assert await engine.store.get_recovery_code_hashes(user.id) == live, "a code was spent"


# --- L13: a secret in the config file is warned about ------------------------


def test_secret_in_config_file_warns(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    from messagefoundry.config.settings import load_settings

    cfg = tmp_path / "messagefoundry.toml"
    cfg.write_text('[store]\npassword = "in-the-file"\n', encoding="utf-8")
    with caplog.at_level(logging.WARNING):
        load_settings(config_path=cfg)
    assert "password" in caplog.text and "env" in caplog.text.lower()


# --- L14: the session reaper purges expired sessions -------------------------


async def test_session_reaper_purges_expired_sessions(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    from messagefoundry.api import app as api_app

    # The reaper waits before its first pass (BACKLOG #2283), so shorten both waits.
    monkeypatch.setattr(api_app, "_SESSION_REAP_INTERVAL", 0.01)
    monkeypatch.setattr(api_app, "_SESSION_REAP_FIRST_DELAY", 0.01)
    await engine.store.create_user(
        user_id="u",
        username="reaper",
        auth_provider="local",
        password_hash=hash_password(PW),
        password_generated=False,
    )
    await engine.store.create_session(
        token_hash="expired-hash", user_id="u", expires_at=1.0, now=1.0
    )
    # BACKLOG #2096: an idle-expired row goes too, since the validator refuses it on presentation.
    # A row inside the idle window is the control: the purge must not take it. The reaper purges as
    # of `_SESSION_REAP_STEP_TOLERANCE` before its reading (BACKLOG #2283), so the idle row is idle
    # past the window by more than that.
    now = time.time()
    lag = api_app._SESSION_REAP_STEP_TOLERANCE
    await engine.store.create_session(
        token_hash="idle-hash", user_id="u", expires_at=now + 3600, now=now - 600 - lag - 100
    )
    await engine.store.create_session(
        token_hash="live-hash", user_id="u", expires_at=now + 3600, now=now - 10
    )
    task = asyncio.create_task(_session_reaper(engine.store, idle_seconds=600))
    try:
        for _ in range(50):
            await asyncio.sleep(0.01)
            if await engine.store.get_session("idle-hash") is None:
                break
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
    assert await engine.store.get_session("expired-hash") is None
    assert await engine.store.get_session("idle-hash") is None
    assert await engine.store.get_session("live-hash") is not None


async def test_session_reaper_skips_a_pass_after_a_forward_clock_step(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BACKLOG #2283: a forward wall-clock step makes every session look idle, and a purge cannot
    be undone. The pass that sees the wall clock outrun the monotonic clock deletes nothing. The
    next pass compares against that one, so a step that holds is purged by then. A drift inside the
    tolerance is the control: that pass purges as usual. The first reading is a baseline and purges
    nothing, so a clock already wrong at start-up is never purged by on sight."""
    from messagefoundry.api import app as api_app

    idle = 1800.0
    tolerance = api_app._SESSION_REAP_STEP_TOLERANCE
    hour = 3600.0
    # (wall, monotonic) per reading. Reading 0 is the start-up baseline. Pass 1 drifts inside the
    # tolerance; pass 2 steps forward by a day; pass 3 holds the step.
    readings = [
        (1_000.0, 50.0),
        (1_000.0 + hour + tolerance, 50.0 + hour),
        (1_000.0 + 2 * hour + tolerance + 86_400, 50.0 + 2 * hour),
        (1_000.0 + 3 * hour + tolerance + 86_400, 50.0 + 3 * hour),
    ]
    purged = await _run_reaper(monkeypatch, readings, idle_seconds=idle)
    assert purged == [readings[1][0] - tolerance, readings[3][0] - tolerance], (
        "the reaper purged on its start-up baseline or right after a forward clock step; each purge"
        " must also use its own pass's reading, less the tolerance"
    )


async def test_a_step_under_the_tolerance_deletes_no_session_the_validator_accepts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BACKLOG #2283: with a 5-minute idle window, a forward step of 400 s is longer than the window
    and shorter than the 600 s tolerance, so the guard lets the pass run. Purged as of its own
    reading, that pass would delete a session used 250 s ago and one with 100 s of life left, both
    of which the validator accepts at the true time. The pass purges as of the tolerance earlier,
    so both survive. A row idle for 1000 real seconds is the control: it still goes."""
    from messagefoundry.api import app as api_app

    idle = 300.0
    step = 400.0
    assert idle < step < api_app._SESSION_REAP_STEP_TOLERANCE, "the step must sit between"
    true_now = 1_000_000.0
    store = await MessageStore.open(":memory:")
    try:
        await store.create_user(
            user_id="u", username="stepped", auth_provider="local", password_generated=False
        )

        async def _row(h: str, *, last_used: float, expires: float) -> None:
            await store.create_session(
                token_hash=h, user_id="u", expires_at=expires, now=true_now - 2000
            )
            await store.touch_session(h, now=last_used)

        await _row("used-250s-ago", last_used=true_now - 250, expires=true_now + 10_000)
        await _row("expires-in-100s", last_used=true_now, expires=true_now + 100)
        await _row("idle-1000s", last_used=true_now - 1000, expires=true_now + 10_000)
        # Baseline an hour before; the pass reads the wall clock an hour plus the step later.
        readings = [(true_now - 3600, 50.0), (true_now + step, 50.0 + 3600)]
        await _run_reaper(monkeypatch, readings, idle_seconds=idle, inner=store)

        assert await store.get_session("used-250s-ago") is not None, (
            "a forward step under the tolerance purged a session used inside its idle window"
        )
        assert await store.get_session("expires-in-100s") is not None, (
            "a forward step under the tolerance purged a session before its absolute expiry"
        )
        assert await store.get_session("idle-1000s") is None, "the control row was not purged"
    finally:
        await store.close()


async def _run_reaper(
    monkeypatch: pytest.MonkeyPatch,
    readings: list[tuple[float, float]],
    *,
    idle_seconds: float,
    inner: MessageStore | None = None,
) -> list[float | None]:
    """Run the reaper over ``readings`` of (wall, monotonic), one per pass after the baseline, and
    return the ``now`` each purge was given. With ``inner``, each purge also runs against it."""
    from messagefoundry.api import app as api_app

    monkeypatch.setattr(api_app, "_SESSION_REAP_INTERVAL", 0)
    monkeypatch.setattr(api_app, "_SESSION_REAP_FIRST_DELAY", 0)
    wall = iter(r[0] for r in readings)
    mono = iter(r[1] for r in readings)
    purged: list[float | None] = []
    done = asyncio.Event()

    class _Store:
        async def purge_expired_sessions(
            self, *, now: float | None = None, idle_seconds: float | None = None
        ) -> None:
            purged.append(now)
            if inner is not None:
                await inner.purge_expired_sessions(now=now, idle_seconds=idle_seconds)

    def _wall() -> float:
        try:
            return next(wall)
        except StopIteration:
            done.set()
            raise asyncio.CancelledError from None

    task = asyncio.create_task(
        _session_reaper(  # type: ignore[arg-type]
            _Store(), idle_seconds=idle_seconds, wall=_wall, mono=lambda: next(mono)
        )
    )
    await asyncio.wait_for(done.wait(), timeout=5)
    with contextlib.suppress(asyncio.CancelledError):
        await task
    return purged


# --- F1: /dead-letters gates the PHI summary the same way as /messages -------


async def test_dead_letter_summary_redacted_for_non_viewers(engine: Engine) -> None:
    from messagefoundry.config.models import RetryPolicy

    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)  # holds messages:view_summary
    await _add(service, "vw", Role.VIEWER)  # messages:read only
    await engine.store.enqueue_message(
        channel_id="ch1", raw=ADT, deliveries=[("archive", ADT)], summary="MRN 1 · DOE"
    )
    item = (await engine.store.claim_ready())[0]
    await engine.store.mark_failed(item.id, "boom", RetryPolicy(max_attempts=1))  # dead-letter it
    async with _client(engine, service) as c:
        op = _auth((await _login(c, "op")).json()["token"])
        vw = _auth((await _login(c, "vw")).json()["token"])
        op_dead = (await c.get("/dead-letters", headers=op)).json()["dead_letters"][0]
        vw_dead = (await c.get("/dead-letters", headers=vw)).json()["dead_letters"][0]
        assert op_dead["summary"] == "MRN **** · ****"  # list surface: masked (ASVS 14.2.6)
        assert vw_dead["summary"] is None  # redacted: viewer lacks messages:view_summary


# --- F6: must_change_password also locks a session out of the WebSocket -------


class _FakeState:
    auth: object | None = None


class _FakeApp:
    def __init__(self, auth: object) -> None:
        self.state = _FakeState()
        self.state.auth = auth


class _FakeURL:
    path = "/ws/stats"


#: The peer address both doubles below report, and the value the ADR 0150 ``client`` assertions in this
#: file compare against. A real :class:`starlette.datastructures.Address` rather than a hand-rolled
#: stand-in, so borrowing starlette's own type is what stops these doubles drifting from the shape the
#: server really passes. The doubles hand it to ``client_ip`` as the ``scope["client"]`` pair.
#: RFC 5737 TEST-NET-1, so nothing here can resolve to a real host.
#:
#: It must be a REAL address and never None. A double reporting None would let every ``client``
#: assertion in this file degenerate to ``None == None`` — passing against the unfixed code, which is
#: the failure mode BACKLOG #1644's tests exist to avoid rather than reproduce.
_PEER = Address("192.0.2.77", 51234)


class _FakeWS:
    def __init__(self, auth: object, token: str | None) -> None:
        self.app = _FakeApp(auth)
        self.query_params: dict[str, str] = {}
        # The token rides the Authorization header — the deprecated ?token= query fallback was
        # removed (WP-1, ASVS Session Management): a token in a URL leaks into proxy/access logs.
        self.headers: dict[str, str] = {"Authorization": f"Bearer {token}"} if token else {}
        self.url = _FakeURL()
        # BACKLOG #1644: authorize_ws now stamps the peer address onto its three audit rows, so a
        # double without this attribute raises AttributeError rather than failing an assertion.
        # client_ip reads the scope's pair, as on a real connection (BACKLOG #2289).
        self.scope = {"client": tuple(_PEER)}


async def test_must_change_password_blocks_websocket(engine: Engine) -> None:
    from messagefoundry.api.security import authorize_ws
    from messagefoundry.auth import Permission

    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    admin = await create_admin(service)
    admin_login = await service.login(admin.username, admin.password)
    # A failed login would leave no token, and a token-less WS is refused too, which would pass the
    # denial below for the wrong reason.
    assert admin_login.ok and admin_login.token is not None
    admin_token = admin_login.token
    # the not-yet-rotated admin (holds monitoring:read) is denied the WS
    denied = await authorize_ws(_FakeWS(service, admin_token), Permission.MONITORING_READ)  # type: ignore[arg-type]
    assert denied is None
    # a normal user with the permission is allowed through
    await _add(service, "vw", Role.VIEWER)
    vw_token = (await service.login("vw", PW)).token
    allowed = await authorize_ws(_FakeWS(service, vw_token), Permission.MONITORING_READ)  # type: ignore[arg-type]
    assert allowed is not None and allowed.username == "vw"


async def test_ws_permission_denied_is_audited(engine: Engine) -> None:
    # low-9: a WebSocket authorization denial is audited like the HTTP require() path is.
    from messagefoundry.api.security import authorize_ws
    from messagefoundry.auth import Permission

    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    await _add(service, "vw", Role.VIEWER)
    vw_token = (await service.login("vw", PW)).token
    # VIEWER holds monitoring:read but not config:deploy → requesting it on the WS is denied + audited.
    denied = await authorize_ws(_FakeWS(service, vw_token), Permission.CONFIG_DEPLOY)  # type: ignore[arg-type]
    assert denied is None
    rows = [a for a in await engine.store.list_audit() if a["action"] == "auth.permission_denied"]
    assert rows and rows[-1]["actor"] == "vw" and "/ws/stats" in (rows[-1]["detail"] or "")
    # BACKLOG #1644 (ADR 0150) — WHERE FROM, not only who and what. RED when the ``client=`` argument
    # is dropped from ``authorize_ws``'s denial call: the row reverts to NULL, which under the
    # docs/PHI.md section 6 contract asserts no client was in scope. One was.
    assert rows[-1]["client"] == _PEER.host


async def test_ws_permission_granted_is_audited_for_sensitive_only(engine: Engine) -> None:
    # BACKLOG #195a (ASVS 16.3.2): with the trail NARROWED (audit_all_authz off — this app.state is
    # hand-built and carries no attribute, so the getattr fallback applies), an authorization GRANT is
    # audited for the sensitive surface and a /ws/stats MONITORING_READ grant is not. BACKLOG #1277
    # made the WIDE trail the shipped default, so this pins the narrowed configuration, not the ship.
    from messagefoundry.api.security import authorize_ws
    from messagefoundry.auth import Permission

    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    await _add(service, "adm", Role.ADMINISTRATOR)
    await _add(service, "vw", Role.VIEWER)
    adm_token = (await service.login("adm", PW)).token
    vw_token = (await service.login("vw", PW)).token

    # A monitoring:read WS grant (the shipped stats feed) leaves NO permission_granted row.
    allowed = await authorize_ws(_FakeWS(service, vw_token), Permission.MONITORING_READ)  # type: ignore[arg-type]
    assert allowed is not None and allowed.username == "vw"
    rows = [a for a in await engine.store.list_audit() if a["action"] == "auth.permission_granted"]
    assert rows == []  # a polled read grant must never be audited

    # A sensitive WS grant (config:deploy) DOES leave an audited row attributed to the admin.
    ok = await authorize_ws(_FakeWS(service, adm_token), Permission.CONFIG_DEPLOY)  # type: ignore[arg-type]
    assert ok is not None and ok.username == "adm"
    rows = [a for a in await engine.store.list_audit() if a["action"] == "auth.permission_granted"]
    assert len(rows) == 1
    assert rows[-1]["actor"] == "adm" and "config:deploy" in (rows[-1]["detail"] or "")
    assert "/ws/stats" in (rows[-1]["detail"] or "")
    assert rows[-1]["client"] == _PEER.host  # BACKLOG #1644 — the GRANT side carries it too


# --- RBAC-4: HTTP require() grant/deny audit precision ------------------------
# The HTTP twin of the WS grant/deny tests above (:513/:529). authorize_ws has no method guard, so the
# WS tests can't prove the HTTP `method != "GET"` deviation (ASVS 16.3.2): a sensitive-permission READ
# (GET /approvals, which carries APPROVALS_APPROVE) must NOT be grant-audited even though the permission
# IS in _GRANT_AUDIT_PERMISSIONS. These pin the exact HTTP set: sensitive-READ → zero, sensitive-WRITE →
# one grant, under-privileged WRITE → 403 + one deny. Backend-agnostic so the SS/PG store suites re-run
# it and prove the row lands server-side, not just on SQLite.


class _FakeReqURL:
    def __init__(self, path: str) -> None:
        self.path = path


class _FakeRequest:
    """Minimal ASGI-shaped Request for driving ``api.security.require()`` directly — the HTTP sibling of
    :class:`_FakeWS`. ``require()`` reads only ``.app.state.auth``, ``.headers``, ``.url.path``,
    ``.method`` and — since BACKLOG #1644 — ``.scope["client"]`` (``allow_no_auth`` is absent → fail-closed,
    matching a served app)."""

    def __init__(self, auth: object, token: str | None, *, method: str, path: str) -> None:
        self.app = _FakeApp(auth)
        self.method = method
        self.headers: dict[str, str] = {"Authorization": f"Bearer {token}"} if token else {}
        self.url = _FakeReqURL(path)
        self.scope = {"client": tuple(_PEER)}  # BACKLOG #1644 — see the note on :class:`_FakeWS`


async def _assert_http_grant_deny_precision(store: object) -> None:
    """RBAC-4 (ASVS 16.3.2): with the trail NARROWED, the HTTP ``require()`` grant/deny audit set is
    EXACT and the ``method != "GET"`` guard REFUSES to audit a sensitive-permission READ. Driven against
    any Store so the SS/PG legs prove the deny/grant row is actually written on the server backend
    (``record_audit`` / ``list_audit``), not merely on SQLite. The assertions are negative: each proves a
    guard refuses.

    NARROWED, not shipped: every request below rides a ``_FakeRequest`` whose ``app.state`` carries no
    ``audit_all_authz`` attribute, so ``_audit_all_authz``'s ``False`` fallback applies. BACKLOG #1277
    made the wide trail the default an app built through ``create_app`` runs."""
    from fastapi import HTTPException

    from messagefoundry.api.security import require
    from messagefoundry.auth import Permission

    # require_mfa=False: this asserts the GRANT/DENY audit set precisely, and the 6.3.3 access gate
    # sits ABOVE the permission loop — leaving it on would refuse every request with auth.mfa_denied
    # before any grant/deny row could be written, testing the wrong guard.
    service = AuthService(store, AuthSettings(require_mfa=False))  # type: ignore[arg-type]
    # The exact audit counts below need a fresh store. This asks it the same way in every mode,
    # which a check on initialize()'s return value (the first-run account) no longer does.
    assert await store.count_users() == 0  # type: ignore[attr-defined]
    await service.initialize()
    await _add(service, "adm", Role.ADMINISTRATOR)  # holds approvals:approve + messages:purge
    await _add(service, "op", Role.OPERATOR)  # holds messages:purge, NOT approvals:approve
    await _add(service, "vw", Role.VIEWER)  # holds neither
    adm = (await service.login("adm", PW)).token
    op = (await service.login("op", PW)).token
    vw = (await service.login("vw", PW)).token

    async def _rows(action: str, permission: str) -> list[dict[str, object]]:
        return [
            a
            for a in await store.list_audit()  # type: ignore[attr-defined]
            if a["action"] == action and permission in str(a["detail"] or "")
        ]

    # (1) NEGATIVE method guard, which applies only while the trail is NARROWED (this app.state carries
    # no audit_all_authz attribute; BACKLOG #1277 made the wide trail the shipped default): a
    # sensitive-permission READ — GET /approvals, carrying APPROVALS_APPROVE — must leave ZERO grant
    # rows, because require()'s `method != "GET"` guard refuses to audit it.
    ident = await require(Permission.APPROVALS_APPROVE)(
        _FakeRequest(service, adm, method="GET", path="/approvals")  # type: ignore[arg-type]
    )
    assert (
        ident.username == "adm"
    )  # the request itself is AUTHORIZED — only the grant-audit is withheld
    assert await _rows("auth.permission_granted", "approvals:approve") == []
    # Contrast — proves it was the METHOD guard, not the permission set: the SAME permission on a
    # NON-GET request DOES record exactly one grant. Without the method!=GET line this pair is identical.
    await require(Permission.APPROVALS_APPROVE)(
        _FakeRequest(service, adm, method="POST", path="/approvals/r1/approve")  # type: ignore[arg-type]
    )
    assert len(await _rows("auth.permission_granted", "approvals:approve")) == 1

    # (2) A sensitive-WRITE grant (messages:purge on a POST) records EXACTLY ONE row — no more, no less.
    await require(Permission.MESSAGES_PURGE)(
        _FakeRequest(service, op, method="POST", path="/connections/IB_X/purge")  # type: ignore[arg-type]
    )
    assert len(await _rows("auth.permission_granted", "messages:purge")) == 1

    # (3) An under-privileged caller (VIEWER lacks messages:purge) is REFUSED: require() raises 403 AND
    # writes EXACTLY ONE permission_denied row naming the permission + path. Nothing is grant-audited.
    with pytest.raises(HTTPException) as exc:
        await require(Permission.MESSAGES_PURGE)(
            _FakeRequest(service, vw, method="POST", path="/connections/IB_X/purge")  # type: ignore[arg-type]
        )
    assert exc.value.status_code == 403
    denied = await _rows("auth.permission_denied", "messages:purge")
    assert len(denied) == 1
    assert denied[0]["actor"] == "vw"
    assert "/connections/IB_X/purge" in str(denied[0]["detail"] or "")
    # BACKLOG #1644 (ADR 0150): the refusal records WHERE FROM. Asserted inside this shared helper
    # rather than beside it so the SQL Server and Postgres legs prove the ``client`` COLUMN is written
    # on a server backend too, not only on SQLite — the same reason the rest of the helper is shaped
    # this way. RED when ``client=`` is dropped from require()'s denial call.
    assert denied[0]["client"] == _PEER.host
    # The refused caller left NO grant row — deny-by-default really denied (belt-and-braces).
    purge_grants = await _rows("auth.permission_granted", "messages:purge")
    assert [g for g in purge_grants if g["actor"] == "vw"] == []
    # The GRANT side carries the address too, so one threading can't land without the other. Reuses
    # the rows just fetched rather than re-querying — this helper runs against SQL Server and
    # Postgres as well, where a needless round-trip is not free.
    assert purge_grants[0]["client"] == _PEER.host


async def test_http_grant_deny_audit_precision(engine: Engine) -> None:
    # RBAC-4 (ASVS 16.3.2), SQLite half: HTTP require() grant/deny audit precision. The method!=GET guard
    # refuses to audit a sensitive READ (GET /approvals w/ approvals:approve), a sensitive WRITE grants
    # exactly once, and an under-privileged WRITE is denied + audited exactly once. The SS/PG store suites
    # re-run the same helper to prove the row is written on the real server backend.
    await _assert_http_grant_deny_precision(engine.store)


async def test_audit_all_authz_audits_every_grant_but_never_phi_view(engine: Engine) -> None:
    # BACKLOG #244 (ASVS 16.3.2): with [diagnostics].audit_all_authz ON, require()/authorize_ws audit
    # EVERY authorization grant — including a read-permission GET the narrow set withholds — but the
    # PHI-view grants stay excluded even under 'all' (the PHI-access audit path already records those;
    # no double row).
    #
    # THE SWITCH IS DRIVEN ON app.state HERE, NOT LEFT TO A DEFAULT, and that is what keeps this test
    # about the MECHANISM. BACKLOG #1277 made ON the shipped default; the default itself is pinned by
    # test_a_plain_authenticated_get_leaves_a_grant_row_on_the_shipped_default below, which goes through
    # create_app because a hand-built app.state cannot testify about a factory's default.
    from messagefoundry.api.security import authorize_ws, require
    from messagefoundry.auth import Permission

    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    await _add(
        service, "adm", Role.ADMINISTRATOR
    )  # holds read + view_summary + purge + monitoring:read
    adm = (await service.login("adm", PW)).token

    async def _grants(permission: str) -> list[dict[str, object]]:
        return [
            a
            for a in await engine.store.list_audit()
            if a["action"] == "auth.permission_granted" and permission in str(a["detail"] or "")
        ]

    def _on(method: str, path: str) -> _FakeRequest:
        r = _FakeRequest(service, adm, method=method, path=path)
        r.app.state.audit_all_authz = True  # gate ON
        return r

    # (1) OFF (this hand-built app.state carries no audit_all_authz attr, so _audit_all_authz's getattr
    # fallback of False applies): a read-permission GET leaves NO grant row. That fallback is a property
    # of a state nobody set, NOT the shipped posture — create_app always writes the attribute.
    await require(Permission.MONITORING_READ)(
        _FakeRequest(service, adm, method="GET", path="/stats")  # type: ignore[arg-type]
    )
    assert await _grants("monitoring:read") == []

    # (2) ON: the SAME read-permission GET now writes EXACTLY ONE grant row.
    await require(Permission.MONITORING_READ)(_on("GET", "/stats"))  # type: ignore[arg-type]
    assert len(await _grants("monitoring:read")) == 1

    # (3) ON: a PHI-view GET is STILL not grant-audited (excluded even under 'all' — the PHI-access audit
    # path records that view; a grant row here would be a double.)
    await require(Permission.MESSAGES_VIEW_SUMMARY)(_on("GET", "/messages"))  # type: ignore[arg-type]
    assert await _grants("messages:view_summary") == []

    # (4) ON: a sensitive non-GET route still records EXACTLY ONE grant (the sensitive path is unchanged).
    await require(Permission.MESSAGES_PURGE)(_on("POST", "/connections/IB_X/purge"))  # type: ignore[arg-type]
    assert len(await _grants("messages:purge")) == 1

    # (5) ON: authorize_ws honors the same gate — the /ws/stats MONITORING_READ read grant is now audited
    # (bringing the monitoring:read total to 2: the HTTP grant from (2) + this WS grant).
    ws = _FakeWS(service, adm)
    ws.app.state.audit_all_authz = True
    ok = await authorize_ws(ws, Permission.MONITORING_READ)  # type: ignore[arg-type]
    assert ok is not None and ok.username == "adm"
    assert len(await _grants("monitoring:read")) == 2


async def test_a_plain_authenticated_get_leaves_a_grant_row_on_the_shipped_default(
    engine: Engine,
) -> None:
    """BACKLOG #1277: the full authorization trail is what a stock app runs.

    Driven through ``create_app`` and real HTTP rather than :class:`_FakeRequest`, because the claim
    under test is about the DEFAULT, and a hand-built ``app.state`` supplies its own — the double
    would pass whatever the factory does. ``GET /stats`` is the plainest case there is: an
    authenticated read on ``monitoring:read``, the permission the old narrow set deliberately withheld.

    The second half is the POSITIVE CONTROL and it is not optional. Without it, an implementation that
    audited unconditionally — ignoring the switch entirely — would satisfy the first half and be
    indistinguishable from the real change.
    """
    service = await _service(engine)
    await _add(service, "adm", Role.ADMINISTRATOR)

    async def _grants() -> list[dict[str, object]]:
        return [
            a
            for a in await engine.store.list_audit()
            if a["action"] == "auth.permission_granted"
            and "monitoring:read" in str(a["detail"] or "")
        ]

    # The shipped app: no audit_all_authz argument, so create_app's own default governs.
    async with _client(engine, service) as c:
        headers = _auth((await _login(c, "adm")).json()["token"])
        assert await _grants() == []  # login is not a require()-gated route, so nothing yet
        assert (await c.get("/stats", headers=headers)).status_code == 200
        rows = await _grants()
        assert len(rows) == 1, "a plain authenticated GET must leave exactly one grant row"
        assert rows[0]["actor"] == "adm" and "/stats" in str(rows[0]["detail"] or "")

    # POSITIVE CONTROL: the same request on an app that set the switch false writes NOTHING more.
    async with _client(engine, service, audit_all_authz=False) as c:
        assert (await c.get("/stats", headers=headers)).status_code == 200
    assert len(await _grants()) == 1, "audit_all_authz=false must still suppress a read grant"


# --- AUTHN-6: LDAP connectivity failures map to LdapError; empty pw is fail-closed ---


def _ldaps_authenticator() -> LdapAuthenticator:
    # a fully-configured LDAPS + service-account authenticator (no live AD is contacted below)
    return LdapAuthenticator(
        AuthSettings(
            ad_enabled=True,
            ad_server="ldaps://x",
            ad_user_search_base="DC=x",
            ad_bind_dn="CN=svc,DC=x",
            ad_bind_password="x",
        )
    )


def test_ldap_connectivity_failure_maps_to_ldap_error(monkeypatch: pytest.MonkeyPatch) -> None:
    # AUTHN-6: a real connectivity failure (LDAPSocketOpenError, an LDAPException subclass) on the
    # service-account bind must surface as LdapError from BOTH the password and Kerberos lookup paths —
    # exercises the pragma:no-cover except arms in authenticate()/resolve_principal(). Offline: no AD.
    from ldap3.core.exceptions import LDAPSocketOpenError

    auth = _ldaps_authenticator()

    def boom() -> object:
        raise LDAPSocketOpenError("cannot reach the domain controller")

    monkeypatch.setattr(auth, "_service_conn", boom)
    with pytest.raises(LdapError):
        auth.authenticate("someuser", "some-passphrase")
    with pytest.raises(LdapError):
        auth.resolve_principal("someuser")


def test_ldap_empty_password_never_binds(monkeypatch: pytest.MonkeyPatch) -> None:
    # AUTHN-6: an empty password would trigger an anonymous LDAP bind (which many DCs accept),
    # silently authenticating anyone — so authenticate() must fail closed BEFORE any bind. We prove
    # no bind is attempted by making _service_conn explode if it is ever reached.
    #
    # This guard is also what keeps _equalizing_bind (the #1140 / ASVS 6.3.8 timing equalizer) from
    # ever issuing an anonymous bind, because the equalizer is only reachable AFTER _service_conn
    # succeeds. Anyone equalizing the remaining unpadded branches could read this early return as
    # the last one left and delete it; this test is what that would cost.
    auth = _ldaps_authenticator()

    def must_not_be_called() -> object:
        raise AssertionError("empty password must not reach the service-account bind")

    monkeypatch.setattr(auth, "_service_conn", must_not_be_called)
    bind = auth.authenticate("someuser", "")
    assert bind.principal is None and bind.answer is None  # no lookup ran (BACKLOG #2434)
