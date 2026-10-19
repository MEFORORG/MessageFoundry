# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #3293 -- the console's PHI-read, sign-in and ceremony 429s send the caller's own wait.

They sent literals: ``Retry-After: 10`` on a ``require_ui(phi=True)`` view against a 60 s window,
and ``Retry-After: 30`` on ``POST /ui/login``, ``/ui/mfa``, ``/ui/reauth`` and
``/ui/reauth/webauthn`` against a 60 s window. A client that honoured either would have retried
inside the window and been refused again. BACKLOG #2144 had already done this for the admin-write floor
(``test_ui_admin_write_pacing.py``).

Every window here is 37.5 s, not the shipped 60 s, so neither retired literal can pass by matching.
The limiter's own clock is faked, so no test sleeps. All data here is synthetic.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from types import SimpleNamespace

import httpx
import pytest
from _ui_clients import create_local_user_chosen

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine

PW = "a-strong-test-passphrase"  # >=15, no app/vendor terms -- satisfies the ASVS policy (WP-3)
SAME_ORIGIN = {"Sec-Fetch-Site": "same-origin"}
WINDOW = 37.5


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """The limiters' monotonic clock, set by the test."""
    now = [1000.0]
    monkeypatch.setattr(
        "messagefoundry.auth.ratelimit.time", SimpleNamespace(monotonic=lambda: now[0])
    )
    return now


async def _service(engine: Engine, **over: object) -> AuthService:
    values: dict[str, object] = {
        "require_mfa": False,
        "admin_write_min_interval_seconds": 0,
        "mfa_verify_min_elapsed_seconds": 0,
        **over,
    }
    service = AuthService(engine.store, AuthSettings(**values))  # type: ignore[arg-type]
    await service.initialize()
    return service


def _client(engine: Engine, service: AuthService) -> httpx.AsyncClient:
    # The browser connects directly to http://t, so the request Host is its origin; without saying
    # so the passkey leg answers 409 before its limiter (_webui_support._client says the same).
    app = create_app(engine, auth=service, serve_ui=True, webauthn_rp_from_request=True)
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")


async def _add(service: AuthService, username: str, role: Role) -> str:
    user_id = await create_local_user_chosen(
        service,
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=[role.value],
        actor="test",
    )
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id,
        password_hash=user.password_hash,
        must_change_password=False,
        password_generated=False,
    )
    return user_id


async def _ui_login(c: httpx.AsyncClient, username: str) -> None:
    r = await c.post("/ui/login", data={"username": username, "password": PW}, headers=SAME_ORIGIN)
    assert r.status_code in (200, 303), r.status_code


async def test_phi_view_429_is_the_actors_wait_and_matches_the_json_gate(
    engine: Engine, clock: list[float]
) -> None:
    """``require_ui(phi=True)`` and the JSON ``require_phi_read`` send the same wait, at one instant."""
    service = await _service(
        engine, phi_read_rate_limit_per_actor=2, phi_read_rate_limit_window_seconds=WINDOW
    )
    await _add(service, "vw", Role.VIEWER)
    async with _client(engine, service) as ui, _client(engine, service) as api:
        await _ui_login(ui, "vw")
        signed_in = await api.post(
            "/auth/login", json={"username": "vw", "password": PW, "provider": "local"}
        )
        bearer = {"Authorization": f"Bearer {signed_in.json()['token']}"}
        assert (await ui.get("/ui/messages")).status_code == 200  # t=1000
        clock[0] = 1010.0
        assert (await api.get("/messages", headers=bearer)).status_code == 200  # budget spent
        clock[0] = 1020.0
        # The t=1000 read leaves the window at 1037.5: 17.5 s away, rounded up.
        for refused in (await ui.get("/ui/messages"), await api.get("/messages", headers=bearer)):
            assert (refused.status_code, refused.headers["Retry-After"]) == (429, "18")
        clock[0] = 1038.0
        assert (await ui.get("/ui/messages")).status_code == 200  # the header was honest


async def test_sign_in_429_is_this_addresss_wait(engine: Engine, clock: list[float]) -> None:
    service = await _service(
        engine,
        login_rate_limit_per_ip=2,
        login_rate_limit_global=1000,
        login_rate_limit_window_seconds=WINDOW,
    )
    async with _client(engine, service) as c:

        async def attempt() -> httpx.Response:
            return await c.post(
                "/ui/login", data={"username": "nobody", "password": PW}, headers=SAME_ORIGIN
            )

        assert (await attempt()).status_code != 429  # t=1000
        clock[0] = 1010.0
        assert (await attempt()).status_code != 429  # this address's budget is spent
        clock[0] = 1020.0
        refused = await attempt()
        assert (refused.status_code, refused.headers["Retry-After"]) == (429, "18")
        clock[0] = 1037.4
        early = await attempt()
        assert (early.status_code, early.headers["Retry-After"]) == (429, "1")
        clock[0] = 1038.0
        assert (await attempt()).status_code != 429


async def test_sign_in_429_on_a_full_all_clients_budget_is_the_whole_window(
    engine: Engine, clock: list[float]
) -> None:
    """The true wait would be set by OTHER addresses' attempts, so the caller is told the window."""
    service = await _service(
        engine,
        login_rate_limit_per_ip=50,
        login_rate_limit_global=2,
        login_rate_limit_window_seconds=WINDOW,
    )
    async with _client(engine, service) as c:
        form = {"username": "nobody", "password": PW}
        assert (await c.post("/ui/login", data=form, headers=SAME_ORIGIN)).status_code != 429
        clock[0] = 1030.0
        assert (await c.post("/ui/login", data=form, headers=SAME_ORIGIN)).status_code != 429
        clock[0] = 1031.0
        refused = await c.post("/ui/login", data=form, headers=SAME_ORIGIN)
        # Not the 7 s until the first attempt ages out: the whole window, rounded up.
        assert (refused.status_code, refused.headers["Retry-After"]) == (429, "38")


_CEREMONIES: dict[str, Callable[[httpx.AsyncClient], Awaitable[httpx.Response]]] = {
    "POST /ui/mfa": lambda c: c.post("/ui/mfa", data={"code": "000000"}, headers=SAME_ORIGIN),
    "POST /ui/reauth": lambda c: c.post(
        "/ui/reauth",
        data={"next": "/ui/account/sessions/revoke-others", "password": PW},
        headers=SAME_ORIGIN,
    ),
    "POST /ui/reauth/webauthn": lambda c: c.post(
        "/ui/reauth/webauthn", json={"response": {}}, headers=SAME_ORIGIN
    ),
}


@pytest.mark.parametrize("route", sorted(_CEREMONIES))
async def test_ceremony_429_is_the_accounts_wait(
    engine: Engine, clock: list[float], route: str
) -> None:
    """The three console ceremony 429s that carried ``Retry-After: 30`` send the per-actor
    ceremony budget's wait for this account. The budget is spent through the service, so the test
    is about the header and not about what a failed ceremony does to the session."""
    service = await _service(
        engine,
        login_rate_limit_per_ip=2,
        login_rate_limit_global=1000,
        login_rate_limit_window_seconds=WINDOW,
    )
    uid = await _add(service, "op", Role.OPERATOR)
    other = await _add(service, "op2", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _ui_login(c, "op")
        assert service.allow_reauth_attempt(uid)  # t=1000
        clock[0] = 1010.0
        assert service.allow_reauth_attempt(uid)  # this account's ceremony budget is spent
        clock[0] = 1020.0
        assert service.allow_reauth_attempt(other)  # another account changes nothing here
        refused = await _CEREMONIES[route](c)
        assert refused.status_code == 429, (route, refused.status_code)
        assert refused.headers["Retry-After"] == "18", route
