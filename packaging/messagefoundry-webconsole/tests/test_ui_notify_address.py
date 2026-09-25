# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1139 (ASVS 6.3.7): the console confines an account with no notification address.

The cookie mirror of the JSON gate in ``api/security.py``. An account with no ``notify_email``, on an
instance that sends security notices, is sent to ``/ui/account/notify-address`` from every /ui route
until it sets one. The account pages stay reachable, and the address page sits behind the factor
gate, so a cookie that has proven only the password cannot choose where notices go.
"""

from __future__ import annotations

import httpx
from _ui_clients import PW, SAME_ORIGIN, cookie_login, provision

from messagefoundry.api import create_app
from messagefoundry.auth import Role
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
