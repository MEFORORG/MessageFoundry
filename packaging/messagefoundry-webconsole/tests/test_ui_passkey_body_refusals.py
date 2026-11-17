# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Two console refusals the engine's own models could not reach (vault BACKLOG #5341, #5342).

``POST /ui/reauth/webauthn`` and ``POST /ui/account/webauthn/verify`` parse their JSON body
themselves, before the engine's ceremony code sees it, so a body nested too deep for the stack
raised ``RecursionError`` out of the route. ``POST /ui/login`` parses its form without pydantic,
so the JSON route's sign-in name rule (no NUL) does not cover it, nor the combined passkey sign-in
that rides the same form: the service's own refusal, before the account lookup, does. All data here
is synthetic.
"""

from __future__ import annotations

import asyncio
import json
import threading
from collections.abc import Callable, Coroutine
from pathlib import Path
from typing import Any

import httpx
import pytest
from _ui_clients import PW, SAME_ORIGIN, cookie_login, provision
from _webui_support import _client, _service

from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import EgressSettings
from messagefoundry.pipeline import Engine

#: How deep the too-deep body nests: inside the 1 MiB body cap, and far past what json's C decoder
#: can reach on :data:`_SMALL_STACK`, since each level costs it at least two C frames.
_DEPTH = 400_000
#: The stack the request runs on. A fixed thread stack, because a main thread's stack is the
#: platform's: 100_000 levels raised RecursionError on Windows and decoded on the Linux runner.
_SMALL_STACK = 2 * 1024 * 1024
_TOO_DEEP = "[" * _DEPTH + "]" * _DEPTH


#: Each route's too-deep body, and the refusal it answers. The re-auth route hands the body to the
#: service, whose audited refusal answers; the enrolment route cannot read the label, so it answers
#: its own malformed-body refusal.
_DEEP_BODIES = {
    "/ui/reauth/webauthn": (
        '{"response": ' + _TOO_DEEP + "}",
        {"ok": False, "error": "passkey verification failed"},
    ),
    "/ui/account/webauthn/verify": (
        '{"label": "k", "response": ' + _TOO_DEEP + "}",
        {"ok": False, "error": "malformed request"},
    ),
}


def _on_a_small_stack[T](call: Callable[[], Coroutine[Any, Any, T]]) -> T:
    """Run ``call`` in its own event loop on a thread whose stack is :data:`_SMALL_STACK`,
    re-raising what it raised. The route parses the body on the loop's thread, so the loop and the
    engine it serves are built there too."""
    result: list[T] = []
    raised: list[BaseException] = []

    def _run() -> None:
        try:
            result.append(asyncio.run(call()))
        except BaseException as exc:  # handed back to the test thread, which re-raises it
            raised.append(exc)

    previous = threading.stack_size(_SMALL_STACK)
    try:
        worker = threading.Thread(target=_run)
        worker.start()
    finally:
        threading.stack_size(previous)
    worker.join()
    if raised:
        raise raised[0]
    return result[0]


@pytest.mark.parametrize("route", sorted(_DEEP_BODIES))
def test_a_body_nested_too_deep_is_a_refusal_not_a_500(tmp_path: Path, route: str) -> None:
    """vault BACKLOG #5341. Red: the route's own ``request.json()`` raised ``RecursionError``,
    which its catch did not list, so it escaped the route (a 500 on a served engine)."""
    body, refusal = _DEEP_BODIES[route]

    async def _parse() -> object:
        return json.loads(body)

    # The precondition that makes this test about RecursionError: on the stack the route runs on,
    # json refuses the body that way. Were that stack ever deep enough to decode it, this fails
    # rather than passing on some other path.
    with pytest.raises(RecursionError):
        _on_a_small_stack(_parse)

    async def _post() -> httpx.Response:
        engine = await Engine.create(
            tmp_path / "webui.db",
            poll_interval=0.02,
            egress_settings=EgressSettings(deny_by_default=False),
        )
        try:
            service = await _service(engine)
            await provision(service, "op", [Role.OPERATOR.value])
            async with _client(engine, service) as c:
                await cookie_login(c, "op")
                return await c.post(
                    route,
                    content=body,
                    headers={**SAME_ORIGIN, "Content-Type": "application/json"},
                )
        finally:
            await engine.stop()

    r = _on_a_small_stack(_post)
    assert (r.status_code, r.json()) == (400, refusal)


def _spy_login(service: AuthService, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    reached: list[str] = []
    real_login = service.login

    async def _spy(username: str, *args: Any, **kwargs: Any) -> Any:
        reached.append(username)
        return await real_login(username, *args, **kwargs)

    monkeypatch.setattr(service, "login", _spy)
    return reached


def _spy_lookup(engine: Engine, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    looked_up: list[str] = []
    real_lookup = engine.store.get_user_by_username

    async def _spy(username: str) -> Any:
        looked_up.append(username)
        return await real_lookup(username)

    monkeypatch.setattr(engine.store, "get_user_by_username", _spy)
    return looked_up


async def _failed_actors(engine: Engine) -> list[str]:
    return [
        str(row["actor"])
        for row in await engine.store.list_audit()
        if row["action"] == "auth.login_failed"
    ]


@pytest.mark.parametrize("username", ["op\x00", "\x00", "o\x00p"])
async def test_the_form_sign_in_refuses_a_nul_username_before_the_store(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, username: str
) -> None:
    """vault BACKLOG #5342, the form route. Red: the NUL reached the store's account lookup, where
    at least a PostgreSQL store refuses a NUL in a text bind. The service refuses it as an unknown
    name before the lookup, with the audit row naming it escaped."""
    service = await _service(engine)
    reached = _spy_login(service, monkeypatch)
    looked_up = _spy_lookup(engine, monkeypatch)
    async with _client(engine, service) as c:
        r = await c.post(
            "/ui/login", data={"username": username, "password": PW}, headers=SAME_ORIGIN
        )
    assert (r.status_code, r.headers["location"]) == (303, "/ui/login?e=bad")
    assert reached == [username]
    assert all("\x00" not in name for name in looked_up), looked_up
    assert await _failed_actors(engine) == [username.replace("\x00", "\\u0000")]


async def test_the_combined_passkey_sign_in_refuses_a_nul_username_and_ends_its_challenge(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """vault BACKLOG #5342, the combined passkey sign-in, which rides the same form. Red: as above.
    The refusal also clears the challenge cookie, as any refused sign-in after the pop does."""
    pytest.importorskip("webauthn")
    service = await _service(engine)
    looked_up = _spy_lookup(engine, monkeypatch)
    async with _client(engine, service) as c:
        begun = await c.post("/ui/login/passkey", headers=SAME_ORIGIN)
        assert begun.status_code == 200, begun.text
        r = await c.post(
            "/ui/login",
            data={"username": "o\x00p", "password": "", "passkey_assertion": "{}"},
            headers=SAME_ORIGIN,
        )
    assert (r.status_code, r.headers["location"]) == (303, "/ui/login?e=bad")
    assert all("\x00" not in name for name in looked_up), looked_up
    cleared = [h for h in r.headers.get_list("set-cookie") if "passkey" in h.lower()]
    assert cleared and all("max-age=0" in h.lower() for h in cleared), cleared


@pytest.mark.parametrize("username", ["o\x01p", "nobody"])
async def test_the_form_sign_in_still_reaches_the_service_for_other_names(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, username: str
) -> None:
    """The control: another control character and an ordinary unknown name still reach
    ``AuthService.login``, which refuses them as it decides."""
    service = await _service(engine)
    reached = _spy_login(service, monkeypatch)
    async with _client(engine, service) as c:
        r = await c.post(
            "/ui/login", data={"username": username, "password": PW}, headers=SAME_ORIGIN
        )
    assert (r.status_code, r.headers["location"]) == (303, "/ui/login?e=bad")
    assert reached == [username]
