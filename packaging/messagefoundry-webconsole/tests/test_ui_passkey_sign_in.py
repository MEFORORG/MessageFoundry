# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ADR 0197 Amendment A, wave 2 (option N-G, BACKLOG #3373): the combined passkey sign-in on the
console plane.

The sign-in page offers every caller a passkey button. ``POST /ui/login/passkey`` stages a
usernameless challenge and sets its handle as an HttpOnly cookie; ``POST /ui/login`` then carries
the assertion beside the password, so a passkey-only owner gets past a sign-in lock that someone
who knows only the username set. Each test names the mutation that turns it RED.
"""

from __future__ import annotations

import json
import time

import httpx
import pytest
from _ui_clients import SAME_ORIGIN, create_local_user_chosen

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine

pytest.importorskip("webauthn")

PW = "a-strong-test-passphrase"
_COOKIE = "mf_passkey_signin"


def _client(engine: Engine, service: AuthService) -> httpx.AsyncClient:
    # A browser connected directly to http://t: the request Host is its origin (BACKLOG #2219).
    app = create_app(engine, auth=service, serve_ui=True, webauthn_rp_from_request=True)
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")


async def _service(engine: Engine) -> AuthService:
    service = AuthService(
        engine.store,
        AuthSettings(mfa_verify_min_elapsed_seconds=0, login_rate_limit_enabled=False),
    )
    await service.initialize()
    return service


async def _passkey_only_operator(service: AuthService) -> tuple[str, object]:
    """A local account whose only factor is a discoverable passkey, registered through the real
    ceremony. Returns its id and the soft authenticator."""
    from _soft_webauthn import SoftAuthenticator
    from webauthn.helpers import base64url_to_bytes

    user_id = await create_local_user_chosen(
        service,
        username="op",
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.OPERATOR.value],
        actor="test",
    )
    identity = await service.identity_for_user_id(user_id)
    assert identity is not None
    setup = await service.login("op", PW)
    assert setup.ok and setup.token is not None
    options = json.loads(
        await service.begin_webauthn_registration(
            identity, token=setup.token, rp_id="t", rp_name="t"
        )
    )
    key = SoftAuthenticator(rp_id="t", origin="http://t", user_handle=user_id.encode())
    registered = await service.finish_webauthn_registration(
        identity,
        key.create_response(base64url_to_bytes(options["challenge"])),
        label="key",
        token=setup.token,
        rp_id="t",
        origin="http://t",
    )
    assert registered.ok
    return user_id, key


async def test_the_sign_in_page_offers_the_passkey_leg_to_every_caller(engine: Engine) -> None:
    """RED when: the login page stops rendering the passkey button or its hidden assertion field."""
    service = await _service(engine)
    async with _client(engine, service) as c:
        page = await c.get("/ui/login")
    assert page.status_code == 200
    assert 'data-mf-passkey-sign-in="/ui/login/passkey"' in page.text
    assert 'name="passkey_assertion"' in page.text


async def test_the_begin_leg_stages_a_usernameless_challenge_behind_an_http_only_cookie(
    engine: Engine,
) -> None:
    """AC-A7 on the console plane. RED when: the options name a credential, or the handle travels
    in the body or in a cookie a script can read."""
    service = await _service(engine)
    async with _client(engine, service) as c:
        r = await c.post("/ui/login/passkey", headers=SAME_ORIGIN)
    assert r.status_code == 200, r.text
    options = r.json()["options"]
    assert options["allowCredentials"] == [] and options["rpId"] == "t"
    cookie = r.headers["set-cookie"]
    assert cookie.split("=", 1)[0] == _COOKIE
    low = cookie.lower()
    assert "httponly" in low and "samesite=strict" in low and "max-age=120" in low
    assert cookie.split("=", 1)[1].split(";", 1)[0] not in r.text, "the handle is in the body"


async def test_the_begin_leg_refuses_a_cross_site_post(engine: Engine) -> None:
    """RED when: the begin leg loses its same-origin check, so another site could stage challenges."""
    service = await _service(engine)
    async with _client(engine, service) as c:
        r = await c.post("/ui/login/passkey", headers={"Sec-Fetch-Site": "cross-site"})
    assert r.status_code == 403
    assert "set-cookie" not in r.headers


async def test_a_passkey_only_owner_signs_in_past_a_live_sign_in_lock(engine: Engine) -> None:
    """AC-A6 end to end. RED when: ``POST /ui/login`` stops passing the assertion and its cookie
    to the engine, or the engine stops letting the combined passkey sign-in past the lock."""
    from webauthn.helpers import base64url_to_bytes

    service = await _service(engine)
    user_id, key = await _passkey_only_operator(service)
    await service.store.record_login_failure(
        user_id, failed_attempts=3, locked_until=time.time() + 900
    )
    async with _client(engine, service) as c:
        refused = await c.post("/ui/login", data={"username": "op", "password": PW})
        assert refused.status_code == 303
        assert refused.headers["location"] == "/ui/login?e=bad", "the lock is not live"

        begun = await c.post("/ui/login/passkey", headers=SAME_ORIGIN)
        assert begun.status_code == 200
        challenge = base64url_to_bytes(begun.json()["options"]["challenge"])
        assertion = key.get_response(challenge)  # type: ignore[attr-defined]
        r = await c.post(
            "/ui/login",
            data={"username": "op", "password": PW, "passkey_assertion": assertion},
        )
        assert r.status_code == 303 and r.headers["location"] != "/ui/login?e=bad", r.headers
        set_cookies = r.headers.get_list("set-cookie")
        assert any(h.startswith("mf_session=") for h in set_cookies)
        cleared = [h for h in set_cookies if h.startswith(f"{_COOKIE}=")]
        assert cleared and "max-age=0" in cleared[0].lower(), "the spent handle was not cleared"
    user = await service.store.get_user(user_id)
    assert user is not None and user.locked_until is None and user.failed_attempts == 0
