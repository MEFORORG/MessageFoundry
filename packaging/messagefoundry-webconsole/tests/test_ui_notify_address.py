# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1139 (ASVS 6.3.7): the console confines an account with no notification address.

The cookie mirror of the JSON gate in ``api/security.py``. An account with no ``notify_email``, on an
instance that sends security notices, is sent to ``/ui/account/notify-address`` from every /ui route
until it sets one. The account pages stay reachable, and the address page sits behind the factor
gate, so a cookie that has proven only the password cannot choose where notices go.
"""

from __future__ import annotations

from types import SimpleNamespace

import httpx
from _ui_clients import PW, SAME_ORIGIN, cookie_login, provision

from messagefoundry.api import create_app
from messagefoundry.auth import Permission, Role
from messagefoundry.auth.notifications import NOTIFY_EMAIL_SET, SecurityEvent
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine

PAGE = "/ui/account/notify-address"
ADDRESS = "ops@example.org"


class _FakeNotifier:
    def __init__(self) -> None:
        self.events: list[SecurityEvent] = []

    async def notify(self, event: SecurityEvent) -> None:
        self.events.append(event)


async def _service(
    engine: Engine, *, notifier: _FakeNotifier | None, require_mfa: bool = False
) -> AuthService:
    service = AuthService(
        engine.store,
        AuthSettings(require_mfa=require_mfa, login_rate_limit_enabled=False),
        security_notifier=notifier,
    )
    await service.initialize()
    return service


def _client(engine: Engine, service: AuthService) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=create_app(engine, auth=service, serve_ui=True))
    return httpx.AsyncClient(transport=transport, base_url="http://t")


async def test_an_addressless_account_is_confined_until_it_sets_one(engine: Engine) -> None:
    notifier = _FakeNotifier()
    service = await _service(engine, notifier=notifier)
    user_id = await provision(service, "bare", [Role.OPERATOR.value])
    async with _client(engine, service) as c:
        await cookie_login(c, "bare")
        for path in ("/ui", "/ui/messages"):
            r = await c.get(path)
            assert r.status_code == 303, path
            assert r.headers["location"] == PAGE, path
        # The account pages are ways out of the gates ahead of this one, so they stay reachable.
        assert (await c.get("/ui/account")).status_code == 200
        assert (await c.get("/ui/account/password")).status_code == 200

        page = await c.get(PAGE)
        assert page.status_code == 200
        assert "no address for them yet" in page.text

        blank = await c.post(PAGE, data={"email": "  "}, headers=SAME_ORIGIN)
        assert blank.status_code == 400
        user = await engine.store.get_user(user_id)
        assert user is not None and user.notify_email is None

        done = await c.post(PAGE, data={"email": ADDRESS}, headers=SAME_ORIGIN)
        assert done.status_code == 303 and done.headers["location"] == "/ui"
        assert (await c.get("/ui")).status_code == 200
        user = await engine.store.get_user(user_id)
        assert user is not None and user.notify_email == ADDRESS
        assert [e.email for e in notifier.events if e.event_type == NOTIFY_EMAIL_SET] == [ADDRESS]

        # Released: the page itself now has nothing to do and sends the operator on.
        r = await c.get(PAGE)
        assert r.status_code == 303 and r.headers["location"] == "/ui/account"


async def test_a_cross_site_post_cannot_set_the_address(engine: Engine) -> None:
    service = await _service(engine, notifier=_FakeNotifier())
    user_id = await provision(service, "bare", [Role.OPERATOR.value])
    async with _client(engine, service) as c:
        await cookie_login(c, "bare")
        r = await c.post(
            PAGE, data={"email": "attacker@example.org"}, headers={"Sec-Fetch-Site": "cross-site"}
        )
        assert r.status_code == 403
    user = await engine.store.get_user(user_id)
    assert user is not None and user.notify_email is None


async def test_no_confinement_without_a_notice_channel(engine: Engine) -> None:
    service = await _service(engine, notifier=None)
    await provision(service, "bare", [Role.OPERATOR.value])
    async with _client(engine, service) as c:
        await cookie_login(c, "bare")
        assert (await c.get("/ui")).status_code == 200


async def test_the_address_page_sits_behind_the_factor_gate(engine: Engine) -> None:
    """``require_mfa`` covers this Administrator and it has no factor, so its cookie is pending.

    The address page must send it to prove a factor first, and must not accept the address."""
    service = await _service(engine, notifier=_FakeNotifier(), require_mfa=True)
    user_id = await provision(service, "adm", [Role.ADMINISTRATOR.value])
    async with _client(engine, service) as c:
        r = await c.post("/ui/login", data={"username": "adm", "password": PW})
        assert r.status_code in (200, 303)
        r = await c.get(PAGE)
        assert r.status_code == 303 and r.headers["location"] == "/ui/mfa"
        r = await c.post(PAGE, data={"email": ADDRESS}, headers=SAME_ORIGIN)
        assert r.status_code == 303 and r.headers["location"] == "/ui/mfa"
    user = await engine.store.get_user(user_id)
    assert user is not None and user.notify_email is None


async def test_a_second_address_is_refused_out_loud(engine: Engine) -> None:
    """A second tab that submits a different address must not read a quiet redirect as a save."""
    service = await _service(engine, notifier=_FakeNotifier())
    user_id = await provision(service, "bare", [Role.OPERATOR.value])
    async with _client(engine, service) as c:
        await cookie_login(c, "bare")
        assert (await c.post(PAGE, data={"email": ADDRESS}, headers=SAME_ORIGIN)).status_code == 303
        again = await c.post(PAGE, data={"email": "other@example.org"}, headers=SAME_ORIGIN)
        assert again.status_code == 409
        assert "already has a notification address" in again.text
    user = await engine.store.get_user(user_id)
    assert user is not None and user.notify_email == ADDRESS


# --- slice 2: the form suggests the profile address, and only a submit writes it -------------------

DIRECTORY_ADDRESS = "holder@example.org"
SUGGESTED_LINE = "Change it if it is not yours."


async def _set_count(engine: Engine) -> int:
    return len(
        [a for a in await engine.store.list_audit() if a["action"] == "auth.notify_email_set"]
    )


async def test_the_form_suggests_the_profile_address_and_a_get_writes_nothing(
    engine: Engine,
) -> None:
    """The profile ``email`` starts in the input. The GET alone sets nothing, audits nothing and sends
    no notice; submitting the suggested value then fills ``notify_email`` through the existing POST."""
    notifier = _FakeNotifier()
    service = await _service(engine, notifier=notifier)
    user_id = await provision(service, "bare", [Role.OPERATOR.value])
    # The directory-sync write: it names ``email`` and never ``notify_email``.
    await engine.store.update_user_profile(user_id, display_name=None, email=DIRECTORY_ADDRESS)
    async with _client(engine, service) as c:
        await cookie_login(c, "bare")
        page = await c.get(PAGE)
        assert page.status_code == 200
        assert f'value="{DIRECTORY_ADDRESS}"' in page.text
        assert "Suggested from your account record." in page.text
        assert SUGGESTED_LINE in page.text

        user = await engine.store.get_user(user_id)
        assert user is not None and user.notify_email is None
        assert await _set_count(engine) == 0
        assert notifier.events == []
        # Still confined: showing the suggestion released nothing.
        r = await c.get("/ui")
        assert r.status_code == 303 and r.headers["location"] == PAGE

        done = await c.post(PAGE, data={"email": DIRECTORY_ADDRESS}, headers=SAME_ORIGIN)
        assert done.status_code == 303 and done.headers["location"] == "/ui"
    user = await engine.store.get_user(user_id)
    assert user is not None and user.notify_email == DIRECTORY_ADDRESS
    assert await _set_count(engine) == 1
    assert [e.email for e in notifier.events if e.event_type == NOTIFY_EMAIL_SET] == [
        DIRECTORY_ADDRESS
    ]


async def test_the_form_is_empty_when_the_account_has_no_address(engine: Engine) -> None:
    service = await _service(engine, notifier=_FakeNotifier())
    user_id = await provision(service, "bare", [Role.OPERATOR.value])
    user = await engine.store.get_user(user_id)
    assert user is not None and user.email is None and user.notify_email is None
    async with _client(engine, service) as c:
        await cookie_login(c, "bare")
        page = await c.get(PAGE)
    assert page.status_code == 200
    assert 'name="email"' in page.text
    assert "value=" not in page.text.split('name="email"', 1)[1].split(">", 1)[0]
    assert SUGGESTED_LINE not in page.text


async def test_a_blank_profile_address_is_not_suggested(engine: Engine) -> None:
    service = await _service(engine, notifier=_FakeNotifier())
    user_id = await provision(service, "bare", [Role.OPERATOR.value])
    await engine.store.update_user_profile(user_id, display_name=None, email="   ")
    async with _client(engine, service) as c:
        await cookie_login(c, "bare")
        page = await c.get(PAGE)
    assert page.status_code == 200
    assert SUGGESTED_LINE not in page.text


async def test_a_suggested_address_is_escaped(engine: Engine) -> None:
    """A directory writes ``mail``, so the value is not ours to trust inside an attribute."""
    hostile = 'x"><script>alert(1)</script>&y@example.org'
    service = await _service(engine, notifier=_FakeNotifier())
    user_id = await provision(service, "bare", [Role.OPERATOR.value])
    await engine.store.update_user_profile(user_id, display_name=None, email=hostile)
    async with _client(engine, service) as c:
        await cookie_login(c, "bare")
        page = await c.get(PAGE)
    assert page.status_code == 200
    assert 'value="x&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;&amp;y@example.org"' in page.text
    assert "<script>alert(1)" not in page.text
    user = await engine.store.get_user(user_id)
    assert user is not None and user.notify_email is None


def test_the_hint_names_the_directory_for_a_directory_account() -> None:
    from messagefoundry_webconsole import pages

    directory = pages.notify_address_page(suggested=DIRECTORY_ADDRESS, from_directory=True)
    assert "Suggested from your directory record. Change it if it is not yours." in directory
    local = pages.notify_address_page(suggested=DIRECTORY_ADDRESS, from_directory=False)
    assert "Suggested from your account record. Change it if it is not yours." in local
    assert SUGGESTED_LINE not in pages.notify_address_page(from_directory=True)


class _FakeWS:
    """A same-origin browser handshake carrying the session cookie, for ``authorize_ui_ws``."""

    def __init__(self, app: object, cookie: str) -> None:
        self.headers = {"origin": "http://t", "host": "t"}
        self.app = app
        self.url = SimpleNamespace(scheme="ws", path="/ws/stats")
        self.cookies = {"mf_session": cookie}


async def test_the_console_socket_refuses_a_confined_session_below_the_factor_check(
    engine: Engine,
) -> None:
    """Refused while the address is owed, and a password-only probe still leaves its MFA row."""
    from messagefoundry_webconsole import authorize_ui_ws

    service = await _service(engine, notifier=_FakeNotifier())
    await provision(service, "bare", [Role.OPERATOR.value])
    app = create_app(engine, auth=service, serve_ui=True)
    token = (await service.login("bare", PW)).token
    assert token is not None
    identity, _ = await authorize_ui_ws(_FakeWS(app, token), Permission.MONITORING_READ)  # type: ignore[arg-type]
    assert identity is None

    pending = await _service(engine, notifier=_FakeNotifier(), require_mfa=True)
    await provision(pending, "adm", [Role.ADMINISTRATOR.value])
    app = create_app(engine, auth=pending, serve_ui=True)
    out = await pending.login("adm", PW)
    assert out.token is not None and out.mfa_required is True
    identity, _ = await authorize_ui_ws(_FakeWS(app, out.token), Permission.MONITORING_READ)  # type: ignore[arg-type]
    assert identity is None
    rows = [a for a in await engine.store.list_audit() if a["action"] == "auth.mfa_denied"]
    assert [r["actor"] for r in rows] == ["adm"]
