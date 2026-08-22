# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Security-hardening regression tests for the auth subsystem.

Each test pins one fix from the security review so it can't silently regress:
  H1  PHI summaries are redacted for callers lacking messages:view_summary
  H2  AD requires LDAPS unless an explicit insecure override is set
  M2  must_change_password is enforced server-side (not merely advisory)
  M3  the bootstrap one-time password goes to a restricted file, never the log
  M4  an AD login cannot adopt/overwrite a like-named local account
  M5  the last enabled administrator cannot be stripped of the admin role
  M6  /me/password requires the current password (defeats session-only takeover)
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from _totp_clock import fresh_totp
from pydantic import ValidationError

from messagefoundry.api import create_app
from messagefoundry.api.app import _emit_bootstrap_admin, _session_reaper
from messagefoundry.auth import Role, hash_password
from messagefoundry.auth.ldap import AdPrincipal, LdapAuthenticator, LdapError
from messagefoundry.auth.service import AuthService, BootstrapAdmin
from messagefoundry.config.settings import AuthSettings, StoreSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store import MessageStatus

PW = "a-strong-test-passphrase"  # ≥15, no app/vendor terms — satisfies the ASVS policy (WP-3)
ADT = "MSH|^~\\&|S|F|R|RF|20260604||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "auth_hardening.db", poll_interval=0.02)
    yield eng
    await eng.stop()


async def _service(engine: Engine, settings: AuthSettings | None = None) -> AuthService:
    # require_mfa=False by default: every test here pins an RBAC / redaction / audit fix, none of them
    # the second factor, so the ASVS 6.3.3 access gate would only stand between the fixture and the
    # behaviour under test. The tests that DO exercise the gate build their own AuthSettings.
    service = AuthService(engine.store, settings or AuthSettings(require_mfa=False))
    await service.initialize()
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
    # Admin-created accounts force first-login rotation (WP-L3-12); clear it so these fixtures behave
    # like already-onboarded users (keeping the same hash).
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id, password_hash=user.password_hash, must_change_password=False
    )


async def _login(c: httpx.AsyncClient, username: str, password: str = PW, provider: str = "local"):
    return await c.post(
        "/auth/login", json={"username": username, "password": password, "provider": provider}
    )


async def _reauth(
    c: httpx.AsyncClient, token: str, *, purpose: str | None = None, password: str = PW
) -> httpx.Response:
    """POST /me/reauth; ``purpose`` mints the single-use per-action grant (ADR 0077)."""
    body: dict[str, str] = {"password": password}
    if purpose is not None:
        body["purpose"] = purpose
    return await c.post("/me/reauth", json=body, headers=_auth(token))


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
        assert op_msg["summary"] == "MRN 1 · DOE"
        assert op_msg["error"] == "bad PID-5: DOE^JANE"
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
    # M2 + ASVS 6.3.3. A bootstrap admin is must_change AND (since 6.3.3) mfa_pending at the same
    # instant, so this pins BOTH the refusal ORDER and the fact that the pair is escapable — the
    # bricked-fresh-account regression. Order is load-bearing: GET /me/mfa is MFA-exempt but NOT
    # must-change-exempt, so leading with MFA would send this account to /auth/mfa-verify, which it
    # cannot satisfy before rotating. The account must be told to rotate FIRST.
    service = AuthService(engine.store, AuthSettings(login_rate_limit_enabled=False))
    boot = await service.initialize()
    assert boot is not None
    async with _client(engine, service) as c:
        login = await _login(c, boot.username, boot.password)
        assert login.status_code == 200 and login.json()["must_change_password"] is True
        h = _auth(login.json()["token"])
        # a rotation-required session may not reach protected routes...
        blocked = await c.get("/users", headers=h)
        assert blocked.status_code == 403
        # ...and it is the PASSWORD refusal, not the MFA one, even though both apply.
        assert blocked.headers.get("X-MFA-Required") is None
        assert "password change required" in blocked.text
        # ...but the self-service routes stay reachable
        assert (await c.get("/auth/me", headers=h)).status_code == 200
        rotated = await c.post(
            "/me/password",
            headers=h,
            json={"current_password": boot.password, "new_password": "a-rotated-passphrase-99"},
        )
        assert rotated.status_code == 200

        # Rotating clears must_change, but the second factor is still owed: the fresh session is
        # MFA-pending and now carries the OTHER refusal.
        tok = (await _login(c, "admin", "a-rotated-passphrase-99")).json()["token"]
        pending = await c.get("/users", headers=_auth(tok))
        assert pending.status_code == 403 and pending.headers.get("X-MFA-Required") == "1"

        # The account is NOT bricked: enrollment rides require_reauth_only_action, which opts out of
        # the access gate, so the escape path is reachable from the pending session itself.
        assert (
            await _reauth(c, tok, purpose="mfa_enroll", password="a-rotated-passphrase-99")
        ).status_code == 200
        secret = (await c.post("/me/mfa/enroll", headers=_auth(tok))).json()["secret"]
        assert (
            await _reauth(c, tok, purpose="mfa_confirm", password="a-rotated-passphrase-99")
        ).status_code == 200
        confirmed = await c.post(
            "/me/mfa/confirm", json={"code": fresh_totp(secret)}, headers=_auth(tok)
        )
        assert confirmed.status_code == 200
        # Confirming satisfies THIS session's factor, so the estate is reachable again.
        assert (await c.get("/users", headers=_auth(tok))).status_code == 200


# --- M3: bootstrap one-time password goes to a file, not the log -------------


def test_bootstrap_password_written_to_file_not_log(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    store_settings = StoreSettings(path=str(tmp_path / "mf.db"))
    boot = BootstrapAdmin(username="admin", password="S3cret-One-Time-Value")
    with caplog.at_level(logging.WARNING):
        _emit_bootstrap_admin(boot, store_settings)
    secret_file = tmp_path / "bootstrap-admin.txt"
    assert secret_file.exists()
    assert "S3cret-One-Time-Value" in secret_file.read_text()
    # the credential must never appear in the (NSSM-captured) log
    assert "S3cret-One-Time-Value" not in caplog.text
    assert "bootstrap-admin.txt" in caplog.text


def test_bootstrap_file_and_log_state_the_expiry_deadline(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # ASVS 6.4.5 arm 1: the renewal deadline ships WITH the credential — the file body and the log line
    # both carry the ISO instant, so "claim it before <ISO>" is not an out-of-band assumption.
    import datetime

    exp = 1_800_000_000.0
    iso = datetime.datetime.fromtimestamp(exp, tz=datetime.UTC).isoformat()
    store_settings = StoreSettings(path=str(tmp_path / "mf.db"))
    boot = BootstrapAdmin(username="admin", password="one-time-value", expires_at=exp)
    with caplog.at_level(logging.WARNING):
        _emit_bootstrap_admin(boot, store_settings)
    body = (tmp_path / "bootstrap-admin.txt").read_text()
    assert iso in body and "expires" in body
    assert iso in caplog.text  # the deadline is not a secret — safe to log
    assert "one-time-value" not in caplog.text  # ...the password still is not


def test_bootstrap_states_no_deadline_when_expiry_is_off(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # expires_at=None (bootstrap_expiry_hours=0) → no deadline line; byte-compatible with pre-6.4.5.
    store_settings = StoreSettings(path=str(tmp_path / "mf.db"))
    boot = BootstrapAdmin(username="admin", password="one-time-value", expires_at=None)
    with caplog.at_level(logging.WARNING):
        _emit_bootstrap_admin(boot, store_settings)
    assert "expires" not in (tmp_path / "bootstrap-admin.txt").read_text()


# --- M4: AD login cannot adopt a like-named local account --------------------


async def test_ad_login_conflicting_with_local_account_is_rejected(engine: Engine) -> None:
    principal = AdPrincipal(
        username="admin",  # collides with the LOCAL bootstrap admin
        display_name=None,
        email=None,
        dn="CN=admin,DC=x",
        groups=frozenset(),
    )

    class _FakeLdap:
        def authenticate(self, username: str, password: str) -> AdPrincipal | None:
            return principal if (username == "admin" and password == "pw") else None

        def resolve_principal(self, username: str) -> AdPrincipal | None:
            return principal if username == "admin" else None

    settings = AuthSettings(
        ad_enabled=True,
        ad_server="ldaps://x",
        ad_user_search_base="DC=x",
        ad_bind_dn="CN=svc,DC=x",
        ad_bind_password="x",
    )
    service = AuthService(engine.store, settings, ldap=_FakeLdap())  # type: ignore[arg-type]
    await service.initialize()  # creates the LOCAL 'admin'
    async with _client(engine, service) as c:
        r = await _login(c, "admin", "pw", provider="ad")
        assert r.status_code == 401  # the AD bind cannot take over the local account


# --- M5: the last administrator is protected ---------------------------------


async def test_cannot_remove_last_administrator(engine: Engine) -> None:
    # Last-admin guard test (step-up admin CRUD), not an MFA test: pin require_mfa=False so the
    # BACKLOG #187 secure default (require_mfa now ON) doesn't 403 the roles/CRUD ops first.
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    boot = await service.initialize()
    assert boot is not None
    async with _client(engine, service) as c:
        h = _auth((await _login(c, "admin", boot.password)).json()["token"])
        # clear the must-change flag so the admin can operate
        await c.post(
            "/me/password",
            headers=h,
            json={"current_password": boot.password, "new_password": "a-rotated-passphrase-99"},
        )
        h = _auth((await _login(c, "admin", "a-rotated-passphrase-99")).json()["token"])
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
                json={"username": "root2", "password": PW, "roles": ["administrator"]},
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
        user_id="u1", username="bob", auth_provider="local", password_hash=hash_password(PW)
    )
    # simulate a prior lockout whose window has already lapsed
    await engine.store.record_login_failure(
        "u1", failed_attempts=3, locked_until=time.time() - 1.0, now=time.time()
    )
    out = await service.login("bob", "wrong")
    assert not out.ok and out.error == "invalid credentials"  # not re-locked
    user = await engine.store.get_user("u1")
    assert user is not None and user.failed_attempts == 1 and user.locked_until is None


# --- L6: nested-group LDAP filter escapes the user DN ------------------------


def test_nested_group_filter_escapes_user_dn() -> None:
    captured: dict[str, object] = {}

    class _Conn:
        entries: list[object] = []

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
    await engine.store.enable_totp(user.id, recovery_code_hashes=[hash_password(c) for c in codes])

    presented = {"first": codes[0], "last": codes[-1], "wrong": "ZZZZ-9999"}[present]
    calls["n"] = 0
    ok = await service._verify_second_factor(user, presented)

    assert ok is (present != "wrong"), why
    assert calls["n"] == slots, (
        f"{why}: {calls['n']} argon2 verifies against {slots} slots -- the count varies with the "
        "code presented, so it still leaks. 3 would mean it short-circuits on the live codes only"
    )


# --- L13: a secret in the config file is warned about ------------------------


def test_secret_in_config_file_warns(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    from messagefoundry.config.settings import load_settings

    cfg = tmp_path / "messagefoundry.toml"
    cfg.write_text('[store]\npassword = "in-the-file"\n', encoding="utf-8")
    with caplog.at_level(logging.WARNING):
        load_settings(config_path=cfg)
    assert "password" in caplog.text and "env" in caplog.text.lower()


# --- L14: the session reaper purges expired sessions -------------------------


async def test_session_reaper_purges_expired_sessions(engine: Engine) -> None:
    await engine.store.create_user(
        user_id="u", username="reaper", auth_provider="local", password_hash=hash_password(PW)
    )
    await engine.store.create_session(
        token_hash="expired-hash", user_id="u", expires_at=1.0, now=1.0
    )
    task = asyncio.create_task(_session_reaper(engine.store))
    try:
        for _ in range(50):
            await asyncio.sleep(0.01)
            if await engine.store.get_session("expired-hash") is None:
                break
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
    assert await engine.store.get_session("expired-hash") is None


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
        assert op_dead["summary"] == "MRN 1 · DOE"
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


class _FakeWS:
    def __init__(self, auth: object, token: str | None) -> None:
        self.app = _FakeApp(auth)
        self.query_params: dict[str, str] = {}
        # The token rides the Authorization header — the deprecated ?token= query fallback was
        # removed (WP-1, ASVS Session Management): a token in a URL leaks into proxy/access logs.
        self.headers: dict[str, str] = {"Authorization": f"Bearer {token}"} if token else {}
        self.url = _FakeURL()


async def test_must_change_password_blocks_websocket(engine: Engine) -> None:
    from messagefoundry.api.security import authorize_ws
    from messagefoundry.auth import Permission

    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    boot = await service.initialize()
    assert boot is not None
    boot_token = (await service.login("admin", boot.password)).token
    # the not-yet-rotated bootstrap admin (holds monitoring:read) is denied the WS
    denied = await authorize_ws(_FakeWS(service, boot_token), Permission.MONITORING_READ)  # type: ignore[arg-type]
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
    assert await service.initialize() is not None
    await _add(service, "vw", Role.VIEWER)
    vw_token = (await service.login("vw", PW)).token
    # VIEWER holds monitoring:read but not config:deploy → requesting it on the WS is denied + audited.
    denied = await authorize_ws(_FakeWS(service, vw_token), Permission.CONFIG_DEPLOY)  # type: ignore[arg-type]
    assert denied is None
    rows = [a for a in await engine.store.list_audit() if a["action"] == "auth.permission_denied"]
    assert rows and rows[-1]["actor"] == "vw" and "/ws/stats" in (rows[-1]["detail"] or "")


async def test_ws_permission_granted_is_audited_for_sensitive_only(engine: Engine) -> None:
    # BACKLOG #195a (ASVS 16.3.2): an authorization GRANT is audited for the sensitive surface, and a
    # read-feed grant (the shipped /ws/stats MONITORING_READ) is NOT — so console polling can't flood
    # the hash-chained audit log (the documented 16.3.2 read-polling deviation).
    from messagefoundry.api.security import authorize_ws
    from messagefoundry.auth import Permission

    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    assert await service.initialize() is not None
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
    :class:`_FakeWS`. ``require()`` reads only ``.app.state.auth``, ``.headers``, ``.url.path`` and
    ``.method`` (``allow_no_auth`` is absent → fail-closed, matching a served app)."""

    def __init__(self, auth: object, token: str | None, *, method: str, path: str) -> None:
        self.app = _FakeApp(auth)
        self.method = method
        self.headers: dict[str, str] = {"Authorization": f"Bearer {token}"} if token else {}
        self.url = _FakeReqURL(path)


async def _assert_http_grant_deny_precision(store: object) -> None:
    """RBAC-4 (ASVS 16.3.2): the HTTP ``require()`` grant/deny audit set is EXACT and the ``method !=
    "GET"`` guard REFUSES to audit a sensitive-permission READ. Driven against any Store so the SS/PG
    legs prove the deny/grant row is actually written on the server backend (``record_audit`` /
    ``list_audit``), not merely on SQLite. The assertions are negative: each proves a guard refuses."""
    from fastapi import HTTPException

    from messagefoundry.api.security import require
    from messagefoundry.auth import Permission

    # require_mfa=False: this asserts the GRANT/DENY audit set precisely, and the 6.3.3 access gate
    # sits ABOVE the permission loop — leaving it on would refuse every request with auth.mfa_denied
    # before any grant/deny row could be written, testing the wrong guard.
    service = AuthService(store, AuthSettings(require_mfa=False))  # type: ignore[arg-type]
    assert await service.initialize() is not None
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

    # (1) NEGATIVE method guard (the 16.3.2 read-polling deviation): a sensitive-permission READ — GET
    # /approvals, carrying APPROVALS_APPROVE — must leave ZERO grant rows. require()'s `method != "GET"`
    # guard REFUSES to audit it, so console polling of the sensitive read surface can't flood the chain.
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
    # The refused caller left NO grant row — deny-by-default really denied (belt-and-braces).
    purge_grants = await _rows("auth.permission_granted", "messages:purge")
    assert [g for g in purge_grants if g["actor"] == "vw"] == []


async def test_http_grant_deny_audit_precision(engine: Engine) -> None:
    # RBAC-4 (ASVS 16.3.2), SQLite half: HTTP require() grant/deny audit precision. The method!=GET guard
    # refuses to audit a sensitive READ (GET /approvals w/ approvals:approve), a sensitive WRITE grants
    # exactly once, and an under-privileged WRITE is denied + audited exactly once. The SS/PG store suites
    # re-run the same helper to prove the row is written on the real server backend.
    await _assert_http_grant_deny_precision(engine.store)


async def test_audit_all_authz_audits_every_grant_but_never_phi_view(engine: Engine) -> None:
    # BACKLOG #244 (ASVS 16.3.2): with [diagnostics].audit_all_authz ON (threaded onto app.state),
    # require()/authorize_ws audit EVERY authorization grant — including a read-permission GET that the
    # shipped deviation withholds — but the PHI-view grants stay excluded even under 'all' (the PHI-access
    # audit path already records those; no double row). Default OFF is byte-identical (the precision test
    # above proves the withheld read grants).
    from messagefoundry.api.security import authorize_ws, require
    from messagefoundry.auth import Permission

    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    assert await service.initialize() is not None
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

    # (1) OFF (default app.state has no audit_all_authz attr → getattr default False): a read-permission
    # GET leaves NO grant row — the shipped 16.3.2 read-polling deviation is unchanged when the gate is off.
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
    auth = _ldaps_authenticator()

    def must_not_be_called() -> object:
        raise AssertionError("empty password must not reach the service-account bind")

    monkeypatch.setattr(auth, "_service_conn", must_not_be_called)
    assert auth.authenticate("someuser", "") is None
