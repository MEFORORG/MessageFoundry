# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``EngineClient.login`` ends the session it replaces (ASVS 7.2.4, BACKLOG #1901, #2281).

``POST /auth/login`` returns a token and, left alone, revokes nothing: a bearer is not ambient, so
dropping the old one is the client's own act (see the comment on the engine's ``login`` route).
``login`` first overwrote the held token and walked away, so the replaced session would have stayed
valid on first deployment until it idled out. It then ended that token with its own
``POST /auth/logout`` after the sign-in (BACKLOG #1901). That ran AFTER the engine's per-user session
cap, so for a user at the cap the sign-in pushed out another of their sessions first. ``login`` now
names the token in the sign-in body's ``supersedes`` field and the engine ends it before the cap
counts (BACKLOG #2096 is the engine half, #2281 this client's).

The first tests drive a real engine end to end, because the closing test is what the engine does
with each token. The rest stub the transport to pin what an end-to-end run cannot force: which
token ``login`` names, and what a poll clone does with a read that is refused while a sign-in is
replacing the shared token. ``set_token`` signs nothing in, so it still ends the token it replaces
with ``POST /auth/logout``. The tests that a failed revoke never fails a call and never prompts now
drive ``set_token``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
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
from tests._admin_account import create_local_user_chosen

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


async def _service_with_operator(engine: Engine, *, max_sessions: int = 5) -> AuthService:
    service = AuthService(
        engine.store, AuthSettings(require_mfa=False, max_sessions_per_user=max_sessions)
    )
    await service.initialize()
    user_id = await create_local_user_chosen(
        service,
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
        user_id,
        password_hash=user.password_hash,
        must_change_password=False,
        password_generated=False,
    )
    return service


def _bridged(app: ASGIApp) -> EngineClient:
    """An ``EngineClient`` whose requests reach ``app`` on the running test loop."""
    client = EngineClient(_BASE)
    client._http.close()
    client._http = httpx.Client(
        base_url=_BASE, transport=_LoopBridge(app, asyncio.get_running_loop())
    )
    return client


async def _statuses(app: ASGIApp, tokens: list[str]) -> list[int]:
    """What ``GET /auth/me`` answers for each token, asked directly of the engine."""
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=("127.0.0.1", 123)), base_url="http://t"
    ) as direct:
        return [
            (await direct.get("/auth/me", headers={"Authorization": f"Bearer {token}"})).status_code
            for token in tokens
        ]


async def test_a_second_login_ends_only_the_session_it_replaced(engine: Engine) -> None:
    """RED when: ``login`` stops naming the held token, or the NEW one is ended instead.

    ``elsewhere`` is a session of the same user that this client never held. It must survive, or the
    fix has become a whole-user revoke that signs every other tool out.

    The user holds three sessions here, under the default cap of five. The cap case is the next test.
    """
    service = await _service_with_operator(engine)
    app = create_app(engine, auth=service)
    elsewhere = (await service.login("op", PW)).token
    assert elsewhere is not None

    client = _bridged(app)
    try:
        first = (await asyncio.to_thread(client.login, "op", PW)).token
        second = (await asyncio.to_thread(client.login, "op", PW)).token
    finally:
        client.close()
    assert first != second
    assert client.token == second

    replaced, held, other = await _statuses(app, [first, second, elsewhere])
    assert replaced == 401, "the replaced token is still accepted"
    assert held == 200, "the sign-in revoked its own new token"
    assert other == 200, "a session this client never held was ended"


async def test_a_second_login_at_the_session_cap_keeps_the_users_other_sessions(
    engine: Engine,
) -> None:
    """RED when: ``login`` goes back to ending the replaced token AFTER the sign-in (BACKLOG #2281).

    The user is exactly at the cap: two sessions held by other tools and one held by this client.
    The second sign-in mints a fourth row. The engine ends the superseded one before its cap counts,
    so three remain and nothing is pushed out. With the old order the cap ran first, at four rows,
    and revoked the user's oldest session, which is ``others[0]``, a tool that did nothing.
    """
    cap = 3
    service = await _service_with_operator(engine, max_sessions=cap)
    app = create_app(engine, auth=service)
    others = []
    for _ in range(cap - 1):
        token = (await service.login("op", PW)).token
        assert token is not None
        others.append(token)

    client = _bridged(app)
    try:
        first = (await asyncio.to_thread(client.login, "op", PW)).token
        assert await _statuses(app, [*others, first]) == [200] * cap, "the setup overran the cap"
        second = (await asyncio.to_thread(client.login, "op", PW)).token
    finally:
        client.close()

    replaced, held, *kept = await _statuses(app, [first, second, *others])
    assert replaced == 401, "the replaced token is still accepted"
    assert held == 200, "the sign-in revoked its own new token"
    assert kept == [200] * len(others), "the cap pushed out a session this client never held"


async def test_a_refused_login_ends_no_session_on_the_engine(engine: Engine) -> None:
    """RED when: the engine ends the token a sign-in names before it has accepted the credential.

    The client names the held token on every sign-in attempt, so the refusal has to be the engine's:
    a mistyped password must not sign the user out of the session they already had."""
    service = await _service_with_operator(engine)
    app = create_app(engine, auth=service)
    client = _bridged(app)
    try:
        first = (await asyncio.to_thread(client.login, "op", PW)).token
        with pytest.raises(ApiError) as excinfo:
            await asyncio.to_thread(client.login, "op", "not-the-password-at-all")
    finally:
        client.close()
    assert excinfo.value.status == 401
    assert client.token == first
    assert await _statuses(app, [first]) == [200], "a refused sign-in ended the held session"


async def test_a_must_change_session_can_log_itself_out(engine: Engine) -> None:
    """RED when: ``/auth/logout`` leaves the engine's must-change exemption, or the client's
    ``logout`` stops ending the session.

    The harness monitor ends a must-change session it refuses to use with ``logout`` (BACKLOG
    #2091). Its own test stubs the client, so this is the link to a real engine: the confined
    session reaches ``/auth/logout``, and its token is refused afterwards."""
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    await create_local_user_chosen(
        service,
        username="op",
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.OPERATOR.value],
        actor="test",
    )  # admin-created, so it still owes the first-login change
    app = create_app(engine, auth=service)
    client = _bridged(app)
    try:
        result = await asyncio.to_thread(client.login, "op", PW)
        assert result.must_change_password is True
        await asyncio.to_thread(client.logout)
    finally:
        client.close()
    assert client.token is None
    assert await service.identity_for_token(result.token) is None, "the session is still live"


# --- stubbed transport: the edges an end-to-end run cannot force --------------------------------


def _login_body(
    token: str, *, mfa_required: bool = False, must_change_password: bool = False
) -> dict[str, object]:
    # The flags are named rather than splatted: ``LoginResponse`` also takes ``token_type: str``,
    # so strict mypy refuses a ``**dict[str, bool]`` into it.
    user = CurrentUser(
        user_id="0" * 32, username="op", auth_provider="local", roles=[], permissions=[]
    )
    return LoginResponse(
        token=token,
        user=user,
        mfa_required=mfa_required,
        must_change_password=must_change_password,
    ).model_dump(mode="json")


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


def _superseded(sent: list[httpx.Request]) -> list[str | None]:
    """The token each ``/auth/login`` named as ``supersedes``, in order; None where it named none."""
    named: list[str | None] = []
    for request in sent:
        if request.url.path == "/auth/login":
            value = json.loads(request.content).get("supersedes")
            assert value is None or isinstance(value, str)
            named.append(value)
    return named


def _ok(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"detail": "logged out"}, request=request)


@pytest.mark.parametrize(
    "login_flags",
    [{}, {"mfa_required": True}, {"must_change_password": True}],
    ids=["signed-in", "mfa-pending", "must-change"],
)
def test_a_second_login_names_the_held_token_and_sends_no_logout(
    login_flags: dict[str, bool],
) -> None:
    """RED when: ``login`` stops naming the held token as ``supersedes``, names the NEW one, skips
    it because a session still owes a second factor or a password change, or goes back to ending it
    with its own ``POST /auth/logout`` after the sign-in, which runs after the engine's session cap
    (BACKLOG #2281). The client drops the old token in every case, so leaving it live would only
    strand it.

    A first sign-in holds nothing, so its body carries no ``supersedes`` field at all."""
    client = EngineClient(_BASE)
    sent = _scripted(client, _ok, **login_flags)
    try:
        client.login("op", PW)
        held = client.token
        client.login("op", PW)
    finally:
        client.close()
    assert [r.url.path for r in sent] == ["/auth/login", "/auth/login"]
    assert _superseded(sent) == [None, held]
    assert "supersedes" not in json.loads(sent[0].content), "an empty field was sent, not omitted"
    assert client.token != held


def test_a_failed_sign_in_ends_nothing_and_keeps_the_held_token() -> None:
    """RED when: the held token is revoked (or dropped) before the new sign-in is known to succeed.
    A mistyped password must not sign the user out of the session they already had.

    The refused attempt still names the held token. The engine ends it only on success, which
    ``test_a_refused_login_ends_no_session_on_the_engine`` checks against a real engine."""
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


def _me_then(
    logout: Callable[[httpx.Request], httpx.Response],
) -> Callable[[httpx.Request], httpx.Response]:
    """Accept the ``/auth/me`` check ``set_token`` makes, and hand its ``/auth/logout`` to ``logout``."""

    def _answer(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/auth/me":
            return _engine(request)
        return logout(request)

    return _answer


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
def test_a_failed_revoke_never_fails_set_token_and_never_logs_the_token(
    logout: Callable[[httpx.Request], httpx.Response],
    level: int,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """RED when: a revoke failure escapes ``set_token``, or the log line carries a bearer.

    ``set_token`` is the one call left that ends a replaced token with its own ``/auth/logout``: it
    signs nothing in, so no sign-in request can carry ``supersedes``. A 401 is the common case,
    since the old token had usually expired already, so it is INFO. Any other failure leaves a live
    session behind and is a WARNING."""
    client = EngineClient(_BASE)
    sent = _scripted(client, _me_then(logout))
    try:
        client.login("op", PW)
        issued = client.token
        assert issued is not None
        with caplog.at_level(logging.INFO, logger="messagefoundry.apiclient.client"):
            client.set_token("tok-shared")
    finally:
        client.close()
    assert client.token == "tok-shared"
    assert _logouts(sent) == [f"Bearer {issued}"]
    records = [r for r in caplog.records if r.name == "messagefoundry.apiclient.client"]
    assert [r.levelno for r in records] == [level]
    logged = records[0].getMessage()
    assert issued not in logged and "tok-shared" not in logged
    assert "\n" not in logged and "\r" not in logged, "engine text forged a log line"
    assert len(logged) < 1000, "an engine error body reached the log unbounded"


def test_the_set_token_revoke_never_prompts_for_mfa_or_step_up() -> None:
    """RED when: the revoke ``set_token`` sends is sent with the MFA or step-up retry armed.

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

    sent = _scripted(client, _me_then(_demand_both))
    try:
        client.login("op", PW)
        client.set_token("tok-shared")
    finally:
        client.close()
    assert prompted == []
    assert len(_logouts(sent)) == 1, "the refused revoke was retried"


def test_set_token_holds_the_new_token_before_it_revokes_the_replaced_one() -> None:
    """RED when: ``set_token`` revokes the replaced token BEFORE it adopts the new one.

    A poll clone reads the token through the cell it shares with this client. While the revoke is
    in flight, a clone that still read the replaced token would send a token the engine is ending,
    and its background reads would fail. The stub records what the clone reads at that moment.
    ``login`` cannot order it this way, because the engine ends the old token inside the sign-in;
    the poll-clone tests at the end of this file cover that case."""
    client = EngineClient(_BASE)
    poll = client.for_polling()
    seen_by_poll: list[str | None] = []

    def _logout(request: httpx.Request) -> httpx.Response:
        seen_by_poll.append(poll.token)
        return _ok(request)

    _scripted(client, _me_then(_logout))
    try:
        client.login("op", PW)
        client.set_token("tok-shared")
    finally:
        poll.close()
        client.close()
    assert seen_by_poll == ["tok-shared"], "the revoke ran while the replaced token was held"


def _engine(request: httpx.Request) -> httpx.Response:
    """Answer the calls a ``set_token`` or a rotation makes, and accept every ``/auth/logout``."""
    if request.url.path == "/auth/me":
        user = CurrentUser(
            user_id="0" * 32, username="op", auth_provider="local", roles=[], permissions=[]
        )
        return httpx.Response(200, json=user.model_dump(mode="json"), request=request)
    if request.url.path == "/auth/mfa-verify":
        return httpx.Response(200, json={"token": "tok-rotated"}, request=request)
    return _ok(request)


def _held_by_login(client: EngineClient) -> list[str]:
    client.login("op", PW)
    return []


def _held_by_set_token(client: EngineClient) -> list[str]:
    client.set_token("tok-shared")
    return []


def _set_token_after_login(client: EngineClient) -> list[str]:
    client.login("op", PW)
    issued = client.token
    assert issued is not None
    client.set_token("tok-shared")
    return [issued]


def _rotated_from_set_token(client: EngineClient) -> list[str]:
    client.set_token("tok-shared")
    client.verify_mfa("123456")
    return []


@pytest.mark.parametrize(
    ("hold", "named"),
    [
        (_held_by_login, True),
        (_held_by_set_token, False),
        (_set_token_after_login, False),
        (_rotated_from_set_token, True),
    ],
    ids=["login", "set-token", "set-token-after-login", "rotated-from-set-token"],
)
def test_login_names_only_a_token_the_engine_issued_to_this_client(
    hold: Callable[[EngineClient], list[str]], named: bool
) -> None:
    """RED when: ``login`` names a token adopted with ``set_token`` as ``supersedes``, or stops
    naming one the engine issued to this client.

    A ``set_token`` token comes from outside, such as a keyring or a shared ``--token``, and another
    process may be using it. Naming it would have the engine sign that process out. A rotation is
    different: it already ended the adopted token for every holder, so the rotated token is this
    client's alone.

    Each ``hold`` returns the tokens it ended itself, and the logout assertion covers the WHOLE run.
    Only "set-token-after-login" ends one: its ``set_token`` ends the token the sign-in issued
    (BACKLOG #2091). The ``login`` that follows sends no ``/auth/logout`` of its own in any case."""
    client = EngineClient(_BASE)
    sent = _scripted(client, _engine)
    try:
        ended_by_hold = hold(client)
        held = client.token
        result = client.login("op", PW)
    finally:
        client.close()
    assert client.token == result.token != held
    assert _logouts(sent) == [f"Bearer {token}" for token in ended_by_hold]
    assert _superseded(sent)[-1] == (held if named else None)


# --- set_token ends the token it replaces when this client was issued it (BACKLOG #2091) --------


def test_set_token_ends_the_token_a_sign_in_issued_after_the_engine_answers() -> None:
    """RED when: ``set_token`` drops a token the engine issued to this client and leaves it live,
    ends it before ``/auth/me`` answers, or presents the NEW token on the revoke.

    The adopted token is still marked as not issued here, so a later sign-in leaves it live."""
    client = EngineClient(_BASE)
    sent = _scripted(client, _engine)
    try:
        client.login("op", PW)
        issued = client.token
        client.set_token("tok-shared")
    finally:
        client.close()
    assert [r.url.path for r in sent] == ["/auth/login", "/auth/me", "/auth/logout"]
    assert _logouts(sent) == [f"Bearer {issued}"]
    assert client.token == "tok-shared"
    assert client._token_cell.issued_here is False


def test_set_token_leaves_a_token_adopted_from_outside_live() -> None:
    """RED when: ``set_token`` ends a token that an earlier ``set_token`` adopted. Another process
    may be using that one, as :meth:`EngineClient.login` also assumes."""
    client = EngineClient(_BASE)
    sent = _scripted(client, _engine)
    try:
        client.set_token("tok-shared")
        client.set_token("tok-other")
    finally:
        client.close()
    assert _logouts(sent) == []
    assert client.token == "tok-other"


def test_set_token_with_the_held_token_ends_nothing_and_keeps_its_provenance() -> None:
    """RED when: adopting the token already held ends it, which signs the client out, or marks it as
    adopted from outside, so the next sign-in stops naming it and leaves it live."""
    client = EngineClient(_BASE)
    sent = _scripted(client, _engine)
    try:
        client.login("op", PW)
        issued = client.token
        assert issued is not None
        client.set_token(issued)
        assert _logouts(sent) == []
        assert client._token_cell.issued_here is True
        client.login("op", PW)
    finally:
        client.close()
    assert _logouts(sent) == []
    assert _superseded(sent)[-1] == issued


def test_set_token_still_ends_the_issued_token_when_the_new_one_is_refused() -> None:
    """RED when: a refused ``set_token`` strands the issued token it replaced.

    ``set_token`` replaces the held token before ``/auth/me`` answers, so a refusal leaves this
    client without the old one either way. The refusal still reaches the caller."""

    def _refuses_me(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/auth/me":
            return httpx.Response(401, json={"detail": "invalid token"}, request=request)
        return _ok(request)

    client = EngineClient(_BASE)
    sent = _scripted(client, _refuses_me)
    try:
        client.login("op", PW)
        issued = client.token
        with pytest.raises(ApiError) as excinfo:
            client.set_token("tok-bad")
    finally:
        client.close()
    assert excinfo.value.status == 401
    assert _logouts(sent) == [f"Bearer {issued}"]


# --- a read refused while a sign-in replaces the shared token (BACKLOG #2281) ----------------


def test_a_poll_read_refused_mid_sign_in_waits_for_it_and_follows_the_new_token() -> None:
    """RED when: a poll clone's read, refused because a sign-in on the shared cell has just ended
    its token, reaches the caller as a 401 instead of following the sign-in.

    ``login`` names the held token as ``supersedes``, so the engine ends it INSIDE the sign-in
    request, before the new token reaches the cell. The stub holds the sign-in open until the
    clone's read has been refused, then checks the clone is still waiting before it answers.
    Without the cell's ``replacing`` lock the clone would find the old token still in the cell and
    give up at once."""
    client = EngineClient(_BASE)
    poll = client.for_polling()
    _scripted(client, _ok)
    client.login("op", PW)
    old = client.token
    poll_bearers: list[str] = []
    refused = threading.Event()
    outcome: list[CurrentUser | ApiError] = []

    def _poll_send(request: httpx.Request, *args: object, **kwargs: object) -> httpx.Response:
        bearer = request.headers["authorization"]
        poll_bearers.append(bearer)
        if bearer == f"Bearer {old}":
            refused.set()
            return httpx.Response(401, json={"detail": "invalid token"}, request=request)
        return _engine(request)

    poll._http.send = _poll_send  # type: ignore[method-assign]

    def _read() -> None:
        try:
            outcome.append(poll.me())
        except ApiError as exc:
            outcome.append(exc)

    reader = threading.Thread(target=_read, daemon=True)
    still_waiting: list[bool] = []
    send_login = client._http.send

    def _sign_in_held_open(
        request: httpx.Request, *args: object, **kwargs: object
    ) -> httpx.Response:
        if request.url.path == "/auth/login":
            reader.start()
            assert refused.wait(5), "the poll read never reached the engine"
            reader.join(0.2)
            still_waiting.append(reader.is_alive())
        return send_login(request)  # the scripted engine reads only the request

    client._http.send = _sign_in_held_open  # type: ignore[method-assign]
    try:
        result = client.login("op", PW)
        reader.join(10)
    finally:
        poll.close()
        client.close()
    assert still_waiting == [True], "the refused read did not wait for the sign-in in flight"
    assert not reader.is_alive()
    assert len(outcome) == 1 and isinstance(outcome[0], CurrentUser), outcome
    assert poll_bearers == [f"Bearer {old}", f"Bearer {result.token}"]


def test_a_refused_read_is_sent_once_when_nothing_replaced_its_token() -> None:
    """RED when: a 401 on a read is retried although the cell still holds the token it was sent on.
    That 401 is the engine's real answer, such as an expired session, and must reach the caller."""
    client = EngineClient(_BASE)
    sent = _scripted(client, _refused(401))
    try:
        client.login("op", PW)
        with pytest.raises(ApiError) as excinfo:
            client.me()
    finally:
        client.close()
    assert excinfo.value.status == 401
    assert [r.url.path for r in sent] == ["/auth/login", "/auth/me"]


def _replaces_and_refuses(client: EngineClient) -> Callable[[httpx.Request], httpx.Response]:
    """Refuse every call with a 401, after moving the shared cell to a fresh token, as a sign-in
    that finished while the call was in flight would."""
    replaced: list[str] = []

    def _answer(request: httpx.Request) -> httpx.Response:
        replaced.append(f"tok-replaced-{len(replaced) + 1}")
        client._hold_issued(replaced[-1])
        return httpx.Response(401, json={"detail": "invalid token"}, request=request)

    return _answer


@pytest.mark.parametrize(
    ("method", "sends"), [("GET", 2), ("POST", 1)], ids=["read-once-more", "write-never"]
)
def test_a_read_refused_after_its_token_was_replaced_is_resent_once_and_a_write_never(
    method: str, sends: int
) -> None:
    """RED when: a refused read is not followed onto the token now in the cell, is followed more
    than once, or a refused WRITE is sent twice. A 401 on a write can be the route's own answer,
    such as a wrong code on ``/auth/mfa-verify``, so a second send would count twice."""
    client = EngineClient(_BASE)
    sent = _scripted(client, _replaces_and_refuses(client))
    try:
        client.login("op", PW)
        with pytest.raises(ApiError) as excinfo:
            client._request(method, "/auth/me")
    finally:
        client.close()
    assert excinfo.value.status == 401
    bearers = [r.headers["authorization"] for r in sent[1:]]
    assert bearers == ["Bearer tok-1", "Bearer tok-replaced-1"][:sends]
