# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``EngineClient.login`` ends the session it replaces (ASVS 7.2.4, BACKLOG #1901).

``POST /auth/login`` returns a token and revokes nothing: a bearer is not ambient, so dropping the
old one is the client's own act, and ending it is the client's job (see the comment on the engine's
``login`` route). ``login`` used to overwrite the held token and walk away, so the replaced session
would have stayed valid on first deployment until it idled out. PR 1434 (BACKLOG #1146) fixed the
same shape for the web console and the IDE's ``signIn``; this is the Python client's half.

The first test drives a real engine end to end, because the ledger's closing test is that the OLD
token is refused. The rest stub the transport to pin what an end-to-end run cannot force: a failed
sign-in ends nothing, a failed revoke never fails the sign-in, and the revoke can never prompt.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncIterator, Callable
from pathlib import Path

import httpx
import pytest
from starlette.types import ASGIApp

from messagefoundry.api import create_app
from messagefoundry.api.auth_models import CurrentUser, LoginResponse
from messagefoundry.apiclient import ApiError, EngineClient
from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine

PW = "a-strong-test-passphrase"  # >=15, no app/vendor terms -- satisfies the ASVS policy (WP-3)
_BASE = "http://127.0.0.1:8765"


# --- end to end: the replaced token is refused by a real engine --------------------------------


class _LoopBridge(httpx.BaseTransport):
    """A SYNC transport that hands each request to the ASGI app on the test's event loop.

    ``EngineClient`` is blocking, and the engine's store lives on the test loop, so the client runs
    in a worker thread and every request crosses back to that loop. The body is passed through raw,
    so the client's own bounded read (``_buffer_bounded``) still does the decoding."""

    def __init__(self, app: ASGIApp, loop: asyncio.AbstractEventLoop) -> None:
        self._asgi = httpx.ASGITransport(app=app, client=("127.0.0.1", 123))
        self._loop = loop

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        async def _forward() -> tuple[int, httpx.Headers, bytes]:
            response = await self._asgi.handle_async_request(request)
            assert isinstance(response.stream, httpx.AsyncByteStream)
            body = b"".join([chunk async for chunk in response.stream])
            return response.status_code, response.headers, body

        future = asyncio.run_coroutine_threadsafe(_forward(), self._loop)
        status, headers, body = future.result(timeout=30)
        return httpx.Response(status, headers=headers, stream=httpx.ByteStream(body))


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "login_supersession.db", poll_interval=0.02)
    yield eng
    await eng.stop()


async def _service_with_operator(engine: Engine) -> AuthService:
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    user_id = await service.create_local_user(
        username="op",
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.OPERATOR.value],
        actor="test",
    )
    # Admin-created accounts owe a first-login change; this one stands in for an onboarded user.
    user = await engine.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await engine.store.set_password(
        user_id, password_hash=user.password_hash, must_change_password=False
    )
    return service


async def test_a_second_login_ends_only_the_session_it_replaced(engine: Engine) -> None:
    """RED when: ``login`` stops revoking the held token, or revokes the NEW one instead.

    ``elsewhere`` is a session of the same user that this client never held. It must survive, or the
    fix has become a whole-user revoke that signs every other tool out.

    The user holds three sessions here, under the default cap of five, on purpose. At the cap, the
    engine's ``/auth/login`` evicts the oldest other session BEFORE the client can revoke the one it
    replaced, so ``elsewhere`` would go too. That ordering is the engine's to fix, not this client's.
    """
    service = await _service_with_operator(engine)
    app = create_app(engine, auth=service)
    elsewhere = (await service.login("op", PW)).token
    assert elsewhere is not None

    client = EngineClient(_BASE)
    client._http.close()
    client._http = httpx.Client(
        base_url=_BASE, transport=_LoopBridge(app, asyncio.get_running_loop())
    )
    try:
        first = (await asyncio.to_thread(client.login, "op", PW)).token
        second = (await asyncio.to_thread(client.login, "op", PW)).token
    finally:
        client.close()
    assert first != second
    assert client.token == second

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=("127.0.0.1", 123)), base_url="http://t"
    ) as direct:

        async def _me(token: str) -> int:
            reply = await direct.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
            return reply.status_code

        assert await _me(first) == 401, "the replaced token is still accepted"
        assert await _me(second) == 200, "the sign-in revoked its own new token"
        assert await _me(elsewhere) == 200, "a session this client never held was ended"


# --- stubbed transport: the edges an end-to-end run cannot force --------------------------------


def _login_body(token: str, **flags: bool) -> dict[str, object]:
    user = CurrentUser(
        user_id="0" * 32, username="op", auth_provider="local", roles=[], permissions=[]
    )
    return LoginResponse(token=token, user=user, **flags).model_dump(mode="json")


def _scripted(
    client: EngineClient,
    logout: Callable[[httpx.Request], httpx.Response],
    **login_flags: bool,
) -> list[httpx.Request]:
    """Answer ``/auth/login`` with a fresh token per call (401 on a wrong password), and hand every
    ``/auth/logout`` to ``logout``. Returns the requests in the order they reached the transport."""
    sent: list[httpx.Request] = []

    def _send(request: httpx.Request, *args: object, **kwargs: object) -> httpx.Response:
        sent.append(request)
        if request.url.path == "/auth/login":
            if json.loads(request.content)["password"] != PW:
                return httpx.Response(401, json={"detail": "invalid credentials"}, request=request)
            body = _login_body(f"tok-{len(sent)}", **login_flags)
            return httpx.Response(200, json=body, request=request)
        return logout(request)

    client._http.send = _send  # type: ignore[method-assign]
    return sent


def _logouts(sent: list[httpx.Request]) -> list[str]:
    """The bearer each ``/auth/logout`` presented, in order."""
    return [r.headers["authorization"] for r in sent if r.url.path == "/auth/logout"]


def _ok(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"detail": "logged out"}, request=request)


@pytest.mark.parametrize(
    "login_flags",
    [{}, {"mfa_required": True}, {"must_change_password": True}],
    ids=["signed-in", "mfa-pending", "must-change"],
)
def test_the_revoke_presents_the_replaced_token_and_follows_the_new_sign_in(
    login_flags: dict[str, bool],
) -> None:
    """RED when: the revoke goes out BEFORE the new sign-in, or presents the new token, or is
    skipped because the new session still owes a second factor or a password change. The client has
    dropped the old token in every case, so leaving it live would only strand it.

    A first sign-in holds nothing, so it revokes nothing."""
    client = EngineClient(_BASE)
    sent = _scripted(client, _ok, **login_flags)
    try:
        client.login("op", PW)
        held = client.token
        client.login("op", PW)
    finally:
        client.close()
    assert [r.url.path for r in sent] == ["/auth/login", "/auth/login", "/auth/logout"]
    assert _logouts(sent) == [f"Bearer {held}"]
    assert client.token != held


def test_a_failed_sign_in_ends_nothing_and_keeps_the_held_token() -> None:
    """RED when: the held token is revoked (or dropped) before the new sign-in is known to succeed.
    A mistyped password must not sign the user out of the session they already had."""
    client = EngineClient(_BASE)
    sent = _scripted(client, _ok)
    try:
        client.login("op", PW)
        held = client.token
        with pytest.raises(ApiError) as excinfo:
            client.login("op", "not-the-password")
    finally:
        client.close()
    assert excinfo.value.status == 401
    assert _logouts(sent) == []
    assert client.token == held


def _refused(status: int) -> Callable[[httpx.Request], httpx.Response]:
    def _answer(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json={"detail": "refused"}, request=request)

    return _answer


def _unreachable(request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("connection refused", request=request)


def _echoes_the_bearer(request: httpx.Request) -> httpx.Response:
    """An engine whose error detail repeats the bearer it was sent. None does today; the WARNING
    carries the engine's detail, so the scrub has to hold whatever the detail says."""
    detail = request.headers["authorization"]
    return httpx.Response(500, json={"detail": detail}, request=request)


def _forges_a_log_line(request: httpx.Request) -> httpx.Response:
    """A plain-text error body with a line break and far more text than a log line should carry."""
    body = "bad gateway\nCRITICAL forged entry\n" + "x" * 5000
    return httpx.Response(502, text=body, request=request)


def _stream_breaks(request: httpx.Request) -> httpx.Response:
    raise httpx.StreamClosed()  # a RuntimeError, not an httpx.HTTPError


@pytest.mark.parametrize(
    ("logout", "level"),
    [
        (_refused(401), logging.INFO),
        (_refused(500), logging.WARNING),
        (_unreachable, logging.WARNING),
        (_echoes_the_bearer, logging.WARNING),
        (_forges_a_log_line, logging.WARNING),
        (_stream_breaks, logging.WARNING),
    ],
    ids=[
        "already-ended-401",
        "server-error-500",
        "network-failure",
        "detail-echoes-bearer",
        "detail-forges-a-line",
        "stream-error",
    ],
)
def test_a_failed_revoke_never_fails_the_sign_in_and_never_logs_the_token(
    logout: Callable[[httpx.Request], httpx.Response],
    level: int,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """RED when: a revoke failure escapes ``login``, or the log line carries a bearer.

    A 401 is the common case, since the old token had usually expired already, so it is INFO. Any
    other failure leaves a live session behind and is a WARNING."""
    client = EngineClient(_BASE)
    _scripted(client, logout)
    try:
        client.login("op", PW)
        held = client.token
        assert held is not None
        with caplog.at_level(logging.INFO, logger="messagefoundry.apiclient.client"):
            result = client.login("op", PW)
    finally:
        client.close()
    assert client.token == result.token != held
    records = [r for r in caplog.records if r.name == "messagefoundry.apiclient.client"]
    assert [r.levelno for r in records] == [level]
    logged = records[0].getMessage()
    assert held not in logged and result.token not in logged
    assert "\n" not in logged and "\r" not in logged, "engine text forged a log line"
    assert len(logged) < 1000, "an engine error body reached the log unbounded"


def test_the_revoke_never_prompts_for_mfa_or_step_up() -> None:
    """RED when: the revoke is sent with the MFA or step-up retry armed.

    Either handler opens a modal prompt in a GUI caller. A prompt for a session the user just left
    would be baffling, and ``/auth/logout`` is exempt from both gates anyway."""
    prompted: list[str] = []

    def _prompt_mfa() -> bool:
        prompted.append("mfa")
        return True

    def _prompt_step_up() -> bool:
        prompted.append("step-up")
        return True

    client = EngineClient(_BASE)
    client.set_mfa_handler(_prompt_mfa)
    client.set_step_up_handler(_prompt_step_up)

    def _demand_both(request: httpx.Request) -> httpx.Response:
        headers = {"X-MFA-Required": "totp", "X-Step-Up-Required": "true"}
        return httpx.Response(403, json={"detail": "x"}, headers=headers, request=request)

    sent = _scripted(client, _demand_both)
    try:
        client.login("op", PW)
        client.login("op", PW)
    finally:
        client.close()
    assert prompted == []
    assert len(_logouts(sent)) == 1, "the refused revoke was retried"
