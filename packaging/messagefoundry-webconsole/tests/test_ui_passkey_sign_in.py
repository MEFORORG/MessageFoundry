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
import types
from typing import Any

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


def _client(
    engine: Engine, service: AuthService, *, address: str | None = None
) -> httpx.AsyncClient:
    # A browser connected directly to http://t: the request Host is its origin (BACKLOG #2219).
    # ``address`` is the peer address the app sees; the limiter is the service's, so two clients
    # over one service draw on one limiter.
    app = create_app(engine, auth=service, serve_ui=True, webauthn_rp_from_request=True)
    transport = (
        httpx.ASGITransport(app=app)
        if address is None
        else httpx.ASGITransport(app=app, client=(address, 51234))
    )
    return httpx.AsyncClient(transport=transport, base_url="http://t")


async def _service(engine: Engine, **overrides: Any) -> AuthService:
    service = AuthService(
        engine.store,
        AuthSettings(
            mfa_verify_min_elapsed_seconds=0,
            login_rate_limit_enabled=False,
            admin_write_min_interval_seconds=0,
            **overrides,
        ),
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


async def test_a_must_change_account_may_register_a_passkey_as_its_first_factor(
    engine: Engine,
) -> None:
    """ADR 0197 Amendment A wave 2, AC-A3 on the console plane: a covered must-change account with
    no factor enrols one before it rotates, and from wave 2 a discoverable passkey qualifies, so the
    enrol-first confinement admits the passkey registration. RED when: ``ENROL_FIRST_UI_ROUTES``
    drops the passkey legs, which sends the first POST to the enrolment page instead."""
    service = await _service(engine)
    await create_local_user_chosen(
        service,
        username="newbie",
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.OPERATOR.value],
        actor="test",
    )
    async with _client(engine, service) as c:
        r = await c.post("/ui/login", data={"username": "newbie", "password": PW})
        assert r.status_code == 303
        r = await c.post("/ui/account/webauthn/enroll", headers=SAME_ORIGIN)
        assert r.status_code == 303 and r.headers["location"].startswith("/ui/reauth?next="), (
            r.headers
        )
        r = await c.post(
            "/ui/reauth",
            data={"next": "/ui/account/webauthn/enroll", "password": PW},
            headers=SAME_ORIGIN,
        )
        assert r.status_code == 200 and 'action="/ui/account/webauthn/enroll"' in r.text
        r = await c.post("/ui/account/webauthn/enroll", headers=SAME_ORIGIN)
        assert r.status_code == 200 and "data-mf-webauthn-create" in r.text


async def _counted_service(engine: Engine, budget: int, *, per_ip: int = 1000) -> AuthService:
    """A service whose sign-in limiter (control 2) admits ``budget`` attempts in all, and ``per_ip``
    from any one address, so a test reads what a request cost by spending the rest."""
    service = AuthService(
        engine.store,
        AuthSettings(
            mfa_verify_min_elapsed_seconds=0,
            login_rate_limit_per_ip=per_ip,
            login_rate_limit_global=budget,
            login_rate_limit_window_seconds=60.0,
            admin_write_min_interval_seconds=0,
        ),
    )
    await service.initialize()
    return service


def _left(service: AuthService) -> int:
    """Spend what is left of the sign-in budget, and say how much that was. Each attempt comes
    from an address of its own, so a per-address budget never stops the count short."""
    n = 0
    while service.allow_login_attempt(f"probe-{n}") and n < 100:
        n += 1
    return n


async def test_a_passkey_sign_in_costs_one_sign_in_unit(engine: Engine) -> None:
    """BACKLOG #3937 item 2: the begin leg charges control 2, and ``POST /ui/login`` does not charge
    it again for the challenge that leg staged. RED when: the sign-in POST charges before it pops
    the staged challenge, which makes a passkey sign-in cost two units."""
    from webauthn.helpers import base64url_to_bytes

    service = await _counted_service(engine, budget=5)
    _, key = await _passkey_only_operator(service)
    async with _client(engine, service) as c:
        begun = await c.post("/ui/login/passkey", headers=SAME_ORIGIN)
        assert begun.status_code == 200
        challenge = base64url_to_bytes(begun.json()["options"]["challenge"])
        assertion = key.get_response(challenge)  # type: ignore[attr-defined]
        r = await c.post(
            "/ui/login",
            data={"username": "op", "password": PW, "passkey_assertion": assertion},
        )
        assert r.status_code == 303 and r.headers["location"] != "/ui/login?e=bad", r.headers
    assert _left(service) == 4, "a passkey sign-in did not cost exactly one unit"


@pytest.mark.parametrize("cookie", [None, "forged-handle"])
async def test_a_sign_in_with_no_staged_challenge_is_charged(
    engine: Engine, cookie: str | None
) -> None:
    """BACKLOG #3937 item 2: only a challenge the begin leg staged waives the sign-in POST's own
    charge. RED when: the POST skips its charge on the mere presence of the handle cookie or of an
    assertion, so a forged handle buys sign-in attempts control 2 never counted."""
    service = await _counted_service(engine, budget=5)
    async with _client(engine, service) as c:
        if cookie is not None:
            c.cookies.set(_COOKIE, cookie)
        r = await c.post(
            "/ui/login",
            data={"username": "nobody", "password": PW, "passkey_assertion": "{}"},
        )
        assert r.status_code == 303 and r.headers["location"] == "/ui/login?e=bad"
    assert _left(service) == 4, "a sign-in with no staged challenge was not charged"


async def test_a_staged_challenge_is_popped_by_the_sign_in_post_even_without_an_assertion(
    engine: Engine,
) -> None:
    """BACKLOG #3937 item 2: the route always pops, never peeks, so a challenge that waived one
    charge cannot waive a second. RED when: the POST reads the challenge without taking it."""
    service = await _counted_service(engine, budget=5)
    async with _client(engine, service) as c:
        begun = await c.post("/ui/login/passkey", headers=SAME_ORIGIN)
        assert begun.status_code == 200
        for _ in range(2):
            r = await c.post("/ui/login", data={"username": "nobody", "password": PW})
            assert r.status_code == 303
    # The begin leg, the first POST waived by the staged challenge, the second charged.
    assert _left(service) == 3
    assert len(service._preauth_challenges) == 0


@pytest.mark.parametrize("assertion", [None, "{}"], ids=["password-only", "with-assertion"])
async def test_a_begin_leg_from_one_address_pays_for_the_sign_in_post_from_another(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, assertion: str | None
) -> None:
    """BACKLOG #3937 step 28: pins the SHIPPED behaviour, whose change is that row's open decision.
    The begin leg charges control 2 under ITS address, and ``POST /ui/login`` renews that hit
    without charging or consulting the POST's address, so a POST from B carrying a handle A's begin
    leg staged, with or without an assertion, is admitted even while control 2 refuses B. A's hit
    is moved to the POST's moment, under A, and counts once in the global budget. The begin leg had
    already charged A and the global budget, as a POST from A would have, so an attacker holding
    both addresses gains no attempt. A third party holding the handle cookie would spend A's hit
    instead of its own, and pop A's challenge, so A's ceremony is spent. If that decision requires
    the two addresses to match, this test is inverted with it, not kept green.

    RED when: the skip charges or consults B's address (the POST is refused); the renewal frees
    A's hit or leaves it at the begin leg's moment (a later window finds A free); or the renewal
    leaves A's hit out of the global window, or counts it twice."""
    clock = [1_000.0]
    # The limiter module's own clock only, so no step can age out of the window under load.
    monkeypatch.setattr(
        "messagefoundry.auth.ratelimit.time", types.SimpleNamespace(monotonic=lambda: clock[0])
    )
    service = await _counted_service(engine, budget=5, per_ip=1)
    limiter = service._login_limiter
    assert limiter is not None
    login = {"username": "nobody", "password": PW}
    paying = login if assertion is None else {**login, "passkey_assertion": assertion}
    a = _client(engine, service, address="192.0.2.10")
    b = _client(engine, service, address="192.0.2.20")
    async with a, b:
        begun = await a.post("/ui/login/passkey", headers=SAME_ORIGIN)
        assert begun.status_code == 200
        # B spends its one unit, so control 2 now refuses B.
        assert (await b.post("/ui/login", data=login)).status_code == 303
        assert (await b.post("/ui/login", data=login)).status_code == 429
        b.cookies.update(a.cookies)  # the handle cookie, as the begin leg set it
        assert b.cookies.get(_COOKIE)
        clock[0] += 59
        paid = await b.post("/ui/login", data=paying)
        assert paid.status_code == 303, "the shipped cross-address skip now asks B's address"
        assert paid.headers["location"] == "/ui/login?e=bad"
        assert b.cookies.get(_COOKIE) is None, "the refusal did not clear the handle cookie"
    # Global at t=59: B's charged POST (t=0) and A's hit, moved to t=59; a refusal is not counted.
    assert len(limiter._global_hits) == 2, "the renewal did not keep A's hit once in the window"
    clock[0] += 2  # A's begin-leg stamp (t=0) has aged out; the hit the POST moved (t=59) has not
    assert not service.allow_login_attempt("192.0.2.10"), "the renewal did not move A's hit"


async def test_a_passkey_row_that_does_not_parse_is_the_uniform_refusal_on_ui_login(
    engine: Engine,
) -> None:
    """BACKLOG #3937: the console sign-in rides the same ``auth.login`` seam, so the failure that
    sets the lock writes the lock notice, which asks whether the account holds a discoverable
    passkey. A passkey row that does not parse must leave that the redirect every wrong password
    gets, never a 500, and the failure is still counted. RED when: the notice's passkey read lets
    the parse error out."""
    service = await _service(engine, lockout_threshold=3)
    user_id, _ = await _passkey_only_operator(service)
    from messagefoundry.store.store import MessageStore

    store = engine.store
    assert isinstance(store, MessageStore)
    db = store._db
    await db.execute(
        "UPDATE webauthn_credentials SET transports='not json' WHERE user_id=?", (user_id,)
    )
    await db.commit()
    app = create_app(engine, auth=service, serve_ui=True, webauthn_rp_from_request=True)
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        for _ in range(3):
            r = await c.post("/ui/login", data={"username": "op", "password": "wrong-" + PW})
            assert r.status_code == 303, (r.status_code, r.text)
            assert r.headers["location"] == "/ui/login?e=bad"
    user = await service.store.get_user(user_id)
    assert user is not None and user.locked_until is not None, "the failure was not counted"
