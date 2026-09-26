# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1139 (ASVS 6.3.7): an account with no notification address sets one before anything else.

The notifier drops a notice for an account with no ``notify_email``, so such an account is told
nothing out of band about a change to its authentication details. At least three paths give birth
to one. This file drives the three known ones to the confinement, the way out of it, and the two
conditions that keep the confinement from doing harm: it applies only while a notice channel is wired, and it never lets a
session that still owes its second factor choose the address.
"""

from __future__ import annotations

import json
import logging
import os
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx
import pytest
from _totp_clock import pin_totp_clock
from starlette.datastructures import Address

from messagefoundry.api import create_app
from messagefoundry.api.security import NOTIFY_EMAIL_REQUIRED_DETAIL, authorize_ws
from messagefoundry.auth import Permission, Role, totp
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.ldap import AdPrincipal
from messagefoundry.auth.notifications import NOTIFY_EMAIL_SET, SecurityEvent
from messagefoundry.auth.service import AuthService, NotifyEmailAlreadySet
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store.store import MessageStore

PW = "a-strong-test-passphrase"
ADDRESS = "ops@example.org"


class _FakeNotifier:
    """Captures events instead of mailing them. Its presence is what "a channel is wired" means."""

    def __init__(self) -> None:
        self.events: list[SecurityEvent] = []

    async def notify(self, event: SecurityEvent) -> None:
        self.events.append(event)


def _no_mfa(**overrides: Any) -> AuthSettings:
    return AuthSettings(require_mfa=False, login_rate_limit_enabled=False, **overrides)


async def _add_local(service: AuthService, username: str, *, email: str | None = None) -> str:
    """An onboarded local Administrator: the create path, with the forced rotation cleared."""
    user_id = await service.create_local_user(
        username=username,
        password=PW,
        display_name=None,
        email=email,
        roles=[Role.ADMINISTRATOR.value],
        actor="test",
    )
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id, password_hash=user.password_hash, must_change_password=False
    )
    await service.set_channel_scope(user_id, [ALL_CHANNELS], actor="test")
    return user_id


async def _flag_after_login(service: AuthService, username: str, password: str = PW) -> bool:
    out = await service.login(username, password)
    assert out.ok and out.identity is not None and out.token is not None
    # Read it back through the token too, which is what every gate resolves.
    resolved = await service.identity_for_token(out.token)
    assert resolved is not None
    assert resolved.must_set_notify_email is out.identity.must_set_notify_email
    return resolved.must_set_notify_email


# --- the three birth paths -------------------------------------------------------------------------
# There were four. The fourth, the first-run bootstrap administrator, was retired by ADR 0183
# Amendment A, Wave 2 (BACKLOG #1136), and its test went with it. The first administrator of an
# install now comes from `provision-admin`, whose no-address arm is pinned below.


async def test_a_local_account_created_without_an_address_is_confined_and_one_with_is_not() -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, _no_mfa(), security_notifier=_FakeNotifier())
        await service.initialize()
        await _add_local(service, "bare")
        await _add_local(service, "addressed", email=ADDRESS)
        assert await _flag_after_login(service, "bare") is True
        assert await _flag_after_login(service, "addressed") is False
    finally:
        await store.close()


async def test_provision_admin_confines_only_when_email_was_left_out() -> None:
    for notify_email, expected in ((ADDRESS, False), (None, True)):
        store = await MessageStore.open(":memory:")
        try:
            service = AuthService(store, _no_mfa(), security_notifier=_FakeNotifier())
            await service.provision_first_administrator(
                username="first", password=PW, notify_email=notify_email, actor="cli:test"
            )
            assert await _flag_after_login(service, "first") is expected
        finally:
            await store.close()


async def test_a_directory_account_whose_directory_returns_no_mail_is_confined() -> None:
    store = await MessageStore.open(":memory:")
    try:
        settings = AuthSettings(
            require_mfa=False,
            ad_enabled=True,
            ad_server="ldaps://x",
            ad_user_search_base="DC=x",
            ad_bind_dn="CN=svc,DC=x",
            ad_bind_password="x",
        )
        service = AuthService(store, settings, security_notifier=_FakeNotifier())
        await service.initialize()
        for name, mail, expected in (("nomail", None, True), ("withmail", ADDRESS, False)):
            principal = AdPrincipal(
                username=name,
                display_name=name,
                email=mail,
                dn=f"CN={name},DC=x",
                groups=frozenset(),
            )
            # The shared completion tail that simple bind, Kerberos and OIDC all reach; its create
            # branch is `_upsert_ad_user` meeting a principal it has not seen.
            out = await service._complete_ad_login(principal, None, mfa_verified=True)
            assert out.ok and out.identity is not None
            assert out.identity.must_set_notify_email is expected, name
            # And on every later request, which resolves the token rather than reusing the login's.
            resolved = await service.identity_for_token(out.token)
            assert resolved is not None and resolved.must_set_notify_email is expected, name
    finally:
        await store.close()


# BACKLOG #2014. A directory `mail` the address form would refuse to suggest. The first puts a
# Cyrillic small a (U+0430) in place of the Latin `a` in `admin@example.org`; the second is the same
# trick in its ASCII Punycode form; the third is not one mailbox at all.
_UNADOPTABLE_DIRECTORY_MAIL = (
    ("cyrillic", "\u0430dmin@example.org"),
    ("punycode", "admin@xn--exmple-cua.com"),
    ("noshape", "not an address"),
)


def _ad_service(store: MessageStore) -> AuthService:
    settings = AuthSettings(
        require_mfa=False,
        ad_enabled=True,
        ad_server="ldaps://x",
        ad_user_search_base="DC=x",
        ad_bind_dn="CN=svc,DC=x",
        ad_bind_password="x",
    )
    return AuthService(store, settings, security_notifier=_FakeNotifier())


def _directory_principal(name: str, mail: str | None) -> AdPrincipal:
    return AdPrincipal(
        username=name, display_name=name, email=mail, dn=f"CN={name},DC=x", groups=frozenset()
    )


async def test_a_directory_mail_the_form_would_not_suggest_is_not_adopted_at_birth(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Someone who can write `mail` but cannot sign in must not choose where notices go (#2014)."""
    # Every engine logger. Not the root: aiosqlite logs bound SQL parameters at DEBUG itself.
    caplog.set_level(logging.DEBUG, logger="messagefoundry")
    store = await MessageStore.open(":memory:")
    try:
        service = _ad_service(store)
        await service.initialize()
        for name, mail in _UNADOPTABLE_DIRECTORY_MAIL:
            # The same test the address form's suggestion applies; this row is only honest while
            # that test refuses the input.
            assert AuthService.suggested_notify_email(mail) is None, name
            out = await service._complete_ad_login(
                _directory_principal(name, mail), None, mfa_verified=True
            )
            assert out.ok and out.identity is not None, name
            user = await store.get_user_by_username(name)
            assert user is not None, name
            assert user.notify_email is None, name
            # The profile mirror still carries what the directory said. Only the engine-owned
            # notification target refuses it.
            assert user.email == mail, name
            # So the holder is confined and chooses an address, as with no `mail` at all.
            assert out.identity.must_set_notify_email is True, name
            rows = await store.list_audit(action="auth.ad_notify_email_not_adopted", actor=name)
            assert len(rows) == 1, name
            # The row says an address was refused, never which one. Compared whole, because a
            # substring test cannot see a non-ASCII address that JSON wrote as an escape.
            assert json.loads(rows[0]["detail"]) == {"user_id": user.id, "source": "directory"}
        # Nor does any engine log line, at any level.
        for _name, mail in _UNADOPTABLE_DIRECTORY_MAIL:
            assert mail not in caplog.text
        assert "created without a notification address" in caplog.text
    finally:
        await store.close()


async def test_a_plain_directory_mail_is_still_adopted_at_birth() -> None:
    """The control for the test above: a plain ASCII address is seeded, confines nothing, and
    records no refusal."""
    store = await MessageStore.open(":memory:")
    try:
        service = _ad_service(store)
        await service.initialize()
        mail = "admin@example.com"
        out = await service._complete_ad_login(
            _directory_principal("plain", f"  {mail} "), None, mfa_verified=True
        )
        assert out.ok and out.identity is not None
        user = await store.get_user_by_username("plain")
        assert user is not None and user.notify_email == mail
        assert out.identity.must_set_notify_email is False
        assert await store.list_audit(action="auth.ad_notify_email_not_adopted") == []
    finally:
        await store.close()


async def test_an_administrator_typed_address_is_still_seeded_as_typed() -> None:
    """#2014 narrows the DIRECTORY birth only. An administrator who types an address at creation is
    a different party making a decision, and that path is unchanged."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, _no_mfa(), security_notifier=_FakeNotifier())
        await service.initialize()
        typed = _UNADOPTABLE_DIRECTORY_MAIL[0][1]
        user_id = await _add_local(service, "typed", email=typed)
        user = await store.get_user(user_id)
        assert user is not None and user.notify_email == typed
        assert await store.list_audit(action="auth.ad_notify_email_not_adopted") == []
    finally:
        await store.close()


# --- the conditions -------------------------------------------------------------------------------


async def test_no_account_is_confined_while_no_notice_channel_is_wired() -> None:
    """A site with no mail relay notifies nobody, so the confinement would lock it out for nothing."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, _no_mfa())  # no security_notifier
        await service.initialize()
        await _add_local(service, "bare")
        assert await _flag_after_login(service, "bare") is False
    finally:
        await store.close()


async def test_filling_the_address_ends_it_audits_and_notifies_the_new_address() -> None:
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        service = AuthService(store, _no_mfa(), security_notifier=notifier)
        await service.initialize()
        await _add_local(service, "bare")
        out = await service.login("bare", PW)
        assert out.identity is not None and out.identity.must_set_notify_email is True

        # Blank, not a mailbox at all, two mailboxes, and a display name: each refused, nothing
        # written. The comma list would fan every later notice out to both addresses.
        for bad in ("   ", "x", "a@b.org, c@d.org", "Ops <a@b.org>", "a b@c.org", "a@localhost"):
            with pytest.raises(ValueError):
                await service.fill_own_notify_email(out.identity, bad)
        user = await store.get_user(out.identity.user_id)
        assert user is not None and user.notify_email is None
        assert await service.fill_own_notify_email(out.identity, f"  {ADDRESS} ") is True
        assert await _flag_after_login(service, "bare") is False
        user = await store.get_user(out.identity.user_id)
        assert user is not None and user.notify_email == ADDRESS

        sent = [e for e in notifier.events if e.event_type == NOTIFY_EMAIL_SET]
        assert len(sent) == 1 and sent[0].email == ADDRESS and sent[0].username == "bare"
        rows = [a for a in await store.list_audit() if a["action"] == "auth.notify_email_set"]
        # Actor is the holder, so the row reaches their own /me/security-events feed; no address in it.
        assert len(rows) == 1 and rows[0]["actor"] == "bare"
        assert ADDRESS not in (rows[0]["detail"] or "")

        # Re-sending the same address writes nothing; a different one is refused, never a repoint.
        assert await service.fill_own_notify_email(out.identity, ADDRESS) is False
        with pytest.raises(NotifyEmailAlreadySet):
            await service.fill_own_notify_email(out.identity, "other@example.org")
        user = await store.get_user(out.identity.user_id)
        assert user is not None and user.notify_email == ADDRESS
        assert len([e for e in notifier.events if e.event_type == NOTIFY_EMAIL_SET]) == 1
    finally:
        await store.close()


# --- the API gate ---------------------------------------------------------------------------------


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "notify_confine.db", poll_interval=0.02)
    yield eng
    await eng.stop()


def _client(engine: Engine, service: AuthService) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=create_app(engine, auth=service), client=("127.0.0.1", 123))
    return httpx.AsyncClient(transport=transport, base_url="http://t")


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _login(c: httpx.AsyncClient, username: str) -> dict[str, Any]:
    r = await c.post("/auth/login", json={"username": username, "password": PW})
    assert r.status_code == 200, r.text
    body: dict[str, Any] = r.json()
    return body


def _rotated(response: httpx.Response, token: str) -> str:
    if response.status_code != 200:
        return token
    fresh = response.json().get("token")
    assert isinstance(fresh, str) and fresh
    return fresh


async def test_the_api_confines_a_session_until_it_sets_an_address(engine: Engine) -> None:
    service = AuthService(engine.store, _no_mfa(), security_notifier=_FakeNotifier())
    await service.initialize()
    await _add_local(service, "bare")
    async with _client(engine, service) as c:
        tok = (await _login(c, "bare"))["token"]

        refused = await c.get("/users", headers=_auth(tok))
        assert refused.status_code == 403
        assert refused.json()["detail"] == NOTIFY_EMAIL_REQUIRED_DETAIL
        assert refused.headers.get("X-Notify-Email-Required") == "1"
        # The way out and the harmless self-service reads stay reachable.
        assert (await c.get("/auth/me", headers=_auth(tok))).status_code == 200
        assert (await c.get("/me/mfa", headers=_auth(tok))).status_code == 200
        # Ending one's own sessions is a factor-gate escape (mfa_gate=False), exempt here as it is on
        # the console. Whatever else it answers, it is not the address refusal.
        ended = await c.delete("/me/sessions", headers=_auth(tok))
        assert ended.headers.get("X-Notify-Email-Required") is None, ended.text

        blank = await c.post("/me/notify-email", json={"email": " "}, headers=_auth(tok))
        assert blank.status_code == 400
        two = await c.post(
            "/me/notify-email", json={"email": "a@b.org, c@d.org"}, headers=_auth(tok)
        )
        assert two.status_code == 400
        ok = await c.post("/me/notify-email", json={"email": ADDRESS}, headers=_auth(tok))
        assert ok.status_code == 200, ok.text
        assert (await c.get("/users", headers=_auth(tok))).status_code == 200

        again = await c.post("/me/notify-email", json={"email": ADDRESS}, headers=_auth(tok))
        assert again.status_code == 200
        other = await c.post(
            "/me/notify-email", json={"email": "other@example.org"}, headers=_auth(tok)
        )
        assert other.status_code == 409


async def test_the_api_does_not_confine_without_a_notice_channel(engine: Engine) -> None:
    service = AuthService(engine.store, _no_mfa())
    await service.initialize()
    await _add_local(service, "bare")
    async with _client(engine, service) as c:
        tok = (await _login(c, "bare"))["token"]
        assert (await c.get("/users", headers=_auth(tok))).status_code == 200


async def test_a_session_owing_its_factor_cannot_choose_the_address_and_nothing_deadlocks(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``require_mfa`` covers this Administrator, it has no factor, and it has no address.

    Enrolment has to be reachable while the account is address-confined, or the account could never
    satisfy the factor gate that the address route sits behind. Then, on a later sign-in that owes
    the factor, the address route answers with the factor refusal: a password alone must never
    choose where the account's notices go."""
    service = AuthService(
        engine.store,
        AuthSettings(login_rate_limit_enabled=False),  # require_mfa on, the default
        security_notifier=_FakeNotifier(),
    )
    await service.initialize()
    await _add_local(service, "adm")
    async with _client(engine, service) as c:
        login = await _login(c, "adm")
        assert login["mfa_required"] is True
        tok = login["token"]

        r = await c.post(
            "/me/reauth", json={"password": PW, "purpose": "mfa_enroll"}, headers=_auth(tok)
        )
        assert r.status_code == 200
        tok = _rotated(r, tok)
        r = await c.post("/me/mfa/enroll", headers=_auth(tok))
        assert r.status_code == 200, r.text
        secret = r.json()["secret"]
        r = await c.post(
            "/me/reauth", json={"password": PW, "purpose": "mfa_confirm"}, headers=_auth(tok)
        )
        tok = _rotated(r, tok)
        t0 = 1_000_000.0
        pin_totp_clock(monkeypatch, t0)
        r = await c.post(
            "/me/mfa/confirm", json={"code": totp.totp(secret, now=t0)}, headers=_auth(tok)
        )
        assert r.status_code == 200, r.text

        # A fresh sign-in owes the factor.
        pending = (await _login(c, "adm"))["token"]
        r = await c.post("/me/notify-email", json={"email": ADDRESS}, headers=_auth(pending))
        assert r.status_code == 403 and r.headers.get("X-MFA-Required") == "1"
        user = await engine.store.get_user_by_username("adm")
        assert user is not None and user.notify_email is None

        t1 = t0 + totp.DEFAULT_PERIOD
        pin_totp_clock(monkeypatch, t1)
        r = await c.post(
            "/auth/mfa-verify", json={"code": totp.totp(secret, now=t1)}, headers=_auth(pending)
        )
        assert r.status_code == 200
        pending = _rotated(r, pending)
        # Proven: still confined on an ordinary route, and now free to set the address.
        assert (await c.get("/users", headers=_auth(pending))).status_code == 403
        r = await c.post("/me/notify-email", json={"email": ADDRESS}, headers=_auth(pending))
        assert r.status_code == 200, r.text
        assert (await c.get("/users", headers=_auth(pending))).status_code == 200


class _FakeState:
    auth: object = None


class _FakeApp:
    def __init__(self, auth: object) -> None:
        self.state = _FakeState()
        self.state.auth = auth


class _FakeURL:
    path = "/ws/stats"


class _FakeWS:
    def __init__(self, auth: object, token: str) -> None:
        self.app = _FakeApp(auth)
        self.headers = {"Authorization": f"Bearer {token}"}
        self.url = _FakeURL()
        self.client = Address("192.0.2.77", 51234)


async def test_the_websocket_refuses_a_confined_session(engine: Engine) -> None:
    service = AuthService(engine.store, _no_mfa(), security_notifier=_FakeNotifier())
    await service.initialize()
    user_id = await _add_local(service, "bare")
    out = await service.login("bare", PW)
    assert out.token is not None
    ws = _FakeWS(service, out.token)
    assert await authorize_ws(ws, Permission.MONITORING_READ) is None  # type: ignore[arg-type]
    await service.store.set_user_notify_email(user_id, email=ADDRESS)
    allowed = await authorize_ws(ws, Permission.MONITORING_READ)  # type: ignore[arg-type]
    assert allowed is not None and allowed.username == "bare"


async def test_a_password_only_websocket_probe_is_still_audited(engine: Engine) -> None:
    """The address refusal sits BELOW the factor check on the socket too.

    ``require_mfa`` covers this Administrator, it has no factor and no address. A handshake with its
    password-only token must be refused AND leave the ``auth.mfa_denied`` row, which is the trail a
    stolen-password probe is meant to leave. Refusing on the address first would drop that row."""
    service = AuthService(
        engine.store,
        AuthSettings(login_rate_limit_enabled=False),  # require_mfa on, the default
        security_notifier=_FakeNotifier(),
    )
    await service.initialize()
    await _add_local(service, "adm")
    out = await service.login("adm", PW)
    assert out.token is not None and out.mfa_required is True
    assert await authorize_ws(_FakeWS(service, out.token), Permission.MONITORING_READ) is None  # type: ignore[arg-type]
    rows = [a for a in await engine.store.list_audit() if a["action"] == "auth.mfa_denied"]
    assert len(rows) == 1 and rows[0]["actor"] == "adm"


# --- the three store backends ---------------------------------------------------------------------
# The confinement reads `users.notify_email` and writes it through `set_user_notify_email`, both of
# which each backend already carries. No backend gained a column. So the server legs prove the
# derivation and the fill against a real server row, and they skip locally without their env.


_SQLSERVER_ON = bool(os.getenv("MEFOR_TEST_SQLSERVER"))
_POSTGRES_ON = bool(os.getenv("MEFOR_TEST_POSTGRES"))


async def _open_backend(backend: str, tmp_path: Path) -> Any:
    if backend == "sqlite":
        return await MessageStore.open(tmp_path / "confine.db")
    from messagefoundry.config.settings import load_settings

    settings = load_settings(environ=os.environ).store
    if backend == "sqlserver":
        from messagefoundry.store.sqlserver import SqlServerStore

        return await SqlServerStore.open(settings)
    from messagefoundry.store.postgres import PostgresStore

    return await PostgresStore.open(settings)


@pytest.fixture(params=["sqlite", "sqlserver", "postgres"])
async def backend_store(request: pytest.FixtureRequest, tmp_path: Path) -> AsyncIterator[Any]:
    backend = request.param
    if backend == "sqlserver" and not _SQLSERVER_ON:
        pytest.skip("set MEFOR_TEST_SQLSERVER=1 (+ MEFOR_STORE_* env) to run the SQL Server case")
    if backend == "postgres" and not _POSTGRES_ON:
        pytest.skip("set MEFOR_TEST_POSTGRES=1 (+ MEFOR_STORE_* env) to run the Postgres case")
    store = await _open_backend(backend, tmp_path)
    try:
        yield store
    finally:
        await store.close()


async def test_the_confinement_holds_on_every_store_backend(backend_store: Any) -> None:
    service = AuthService(backend_store, _no_mfa(), security_notifier=_FakeNotifier())
    # A server database is shared across the run, so the name is unique rather than truncated.
    name = f"confine-{uuid4().hex[:12]}"
    user_id = uuid4().hex
    await backend_store.create_user(user_id=user_id, username=name, auth_provider="local")
    try:
        identity = await service.identity_for_user_id(user_id)
        assert identity is not None and identity.must_set_notify_email is True
        assert await service.fill_own_notify_email(identity, ADDRESS) is True
        after = await service.identity_for_user_id(user_id)
        assert after is not None and after.must_set_notify_email is False
        with pytest.raises(NotifyEmailAlreadySet):
            await service.fill_own_notify_email(identity, "other@example.org")
    finally:
        # The server databases outlive the run, so the row this test wrote goes with it.
        await backend_store.delete_user(user_id)


async def test_every_store_backend_can_create_an_account_without_adopting_its_address(
    backend_store: Any,
) -> None:
    """BACKLOG #2014. The directory birth keeps the profile address and seeds no notification
    target. Each backend binds its own INSERT, so each one is driven."""
    name = f"noadopt-{uuid4().hex[:12]}"
    user_id = uuid4().hex
    mail = _UNADOPTABLE_DIRECTORY_MAIL[0][1]
    await backend_store.create_user(
        user_id=user_id, username=name, auth_provider="ad", email=mail, adopt_notify_email=False
    )
    try:
        user = await backend_store.get_user(user_id)
        assert user is not None and user.email == mail and user.notify_email is None
    finally:
        await backend_store.delete_user(user_id)
