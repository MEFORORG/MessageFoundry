# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2454, the cookie half: a request carrying the session cookie twice is refused.

Starlette's ``request.cookies`` keeps only the LAST copy of a name, so a front end that read the
first would have judged a different session from the one the console reads. Every console read of
the cookie goes through ``_auth.session_token``, which counts the copies over the raw ``Cookie``
lines first. HTTP answers 400; the WebSocket cookie hook declines the handshake.
"""

from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest
from _ui_clients import auth_service, cookie_login, provision, ui_client
from starlette.datastructures import Headers

from messagefoundry.api import create_app
from messagefoundry.auth import Permission, Role
from messagefoundry.pipeline import Engine
from messagefoundry_webconsole import authorize_ui_ws
from messagefoundry_webconsole._auth import REPEATED_SESSION_COOKIE_DETAIL, session_cookie_copies

_NAME = "mf_session"  # the cookie name over the plain-http test transport


async def _signed_in_cookie(engine: Engine) -> tuple[httpx.AsyncClient, str]:
    service = await auth_service(engine)
    await provision(service, "op", [Role.OPERATOR.value])
    client = ui_client(engine, service)
    await cookie_login(client, "op")
    token = client.cookies.get(_NAME)
    assert token, "control: the sign-in left a session cookie"
    client.cookies.clear()  # every request below names its Cookie lines itself
    return client, token


@pytest.mark.parametrize(
    "cookie_lines",
    [
        pytest.param(["{n}={t}; {n}={t}"], id="identical-in-one-line"),
        pytest.param(["{n}=forged; {n}={t}"], id="different-in-one-line"),
        pytest.param(["{n}={t}", "{n}=forged"], id="split-across-two-lines"),
    ],
)
async def test_a_page_refuses_a_repeated_session_cookie(
    engine: Engine, cookie_lines: list[str]
) -> None:
    c, token = await _signed_in_cookie(engine)
    try:
        # Control: the one cookie reaches the page.
        single = await c.get("/ui", headers={"Cookie": f"{_NAME}={token}"})
        assert single.status_code == 200, single.status_code
        # Another cookie with another name beside it is not a repeat.
        other = await c.get("/ui", headers={"Cookie": f"theme=dark; {_NAME}={token}"})
        assert other.status_code == 200, other.status_code
        lines = [("Cookie", line.format(n=_NAME, t=token)) for line in cookie_lines]
        repeated = await c.get("/ui", headers=httpx.Headers(lines))
    finally:
        await c.aclose()
    assert repeated.status_code == 400, repeated.status_code
    assert repeated.json() == {"detail": REPEATED_SESSION_COOKIE_DETAIL}


def _handshake(app: object, cookie_lines: list[str]) -> SimpleNamespace:
    """A same-origin browser handshake. ``cookies`` mirrors Starlette's last-copy-wins dict."""
    headers = Headers(
        raw=[(b"origin", b"http://t"), (b"host", b"t")]
        + [(b"cookie", line.encode()) for line in cookie_lines]
    )
    token = cookie_lines[-1].split(";")[-1].split("=", 1)[1].strip()
    return SimpleNamespace(
        headers=headers,
        app=app,
        url=SimpleNamespace(scheme="ws", path="/ws/stats"),
        cookies={_NAME: token},
        client=SimpleNamespace(host="127.0.0.1", port=123),
    )


async def test_the_socket_cookie_hook_declines_a_repeated_session_cookie(engine: Engine) -> None:
    service = await auth_service(engine)
    await provision(service, "op", [Role.OPERATOR.value])
    token = (await service.login("op", "a-strong-test-passphrase")).token
    assert token is not None
    app = create_app(engine, auth=service, serve_ui=True, loopback=True)
    single = _handshake(app, [f"{_NAME}={token}"])
    identity, _ = await authorize_ui_ws(single, Permission.MONITORING_READ)  # type: ignore[arg-type]
    assert identity is not None, "control: one cookie authenticates the socket"
    repeated = _handshake(app, [f"{_NAME}={token}; {_NAME}={token}"])
    assert await authorize_ui_ws(repeated, Permission.MONITORING_READ) == (None, None)  # type: ignore[arg-type]


def test_the_copy_count_files_chunks_as_starlette_does() -> None:
    """A chunk with no ``=`` is filed under the empty name by Starlette, so it is not a copy; a
    name that only starts with the cookie's name is a different cookie."""

    def copies(*lines: str) -> int:
        conn = SimpleNamespace(
            headers=Headers(raw=[(b"cookie", line.encode()) for line in lines]),
            app=SimpleNamespace(state=SimpleNamespace()),
            url=SimpleNamespace(scheme="http"),
        )
        return session_cookie_copies(conn)  # type: ignore[arg-type]

    assert copies(f"{_NAME}=a") == 1
    assert copies(f" {_NAME} = a ;{_NAME}=b") == 2
    assert copies(f"{_NAME}=a", f"{_NAME}=b") == 2
    assert copies(_NAME, f"{_NAME}=a") == 1
    assert copies(f"{_NAME}x=a; x{_NAME}=b; {_NAME}=c") == 1
    assert copies() == 0
