# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Two console refusals the engine's own models could not reach (vault BACKLOG #5341, #5342).

``POST /ui/reauth/webauthn`` and ``POST /ui/account/webauthn/verify`` parse their JSON body
themselves, before the engine's ceremony code sees it, so a body nested too deep for the stack
raised ``RecursionError`` out of the route. ``POST /ui/login`` parses its form without pydantic,
so the JSON route's sign-in name rule (no NUL) did not cover it, nor the combined passkey sign-in
that rides the same form. All data here is synthetic.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import pytest
from _ui_clients import PW, SAME_ORIGIN, cookie_login, provision
from _webui_support import _client, _service

from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.pipeline import Engine

#: Deep enough that json refuses it on any stack these tests run on, and inside the 1 MiB body cap.
_DEPTH = 100_000
_TOO_DEEP = "[" * _DEPTH + "]" * _DEPTH


_DEEP_BODIES = {
    "/ui/reauth/webauthn": '{"response": ' + _TOO_DEEP + "}",
    "/ui/account/webauthn/verify": '{"label": "k", "response": ' + _TOO_DEEP + "}",
}


@pytest.mark.parametrize("route", sorted(_DEEP_BODIES))
async def test_a_body_nested_too_deep_is_a_malformed_request_not_a_500(
    engine: Engine, route: str
) -> None:
    """vault BACKLOG #5341. Red: the route's own ``request.json()`` raised ``RecursionError``,
    which its catch did not list, so it escaped the route (a 500 on a served engine)."""
    body = _DEEP_BODIES[route]
    # The precondition that makes this test about RecursionError: on this stack json refuses the
    # body that way. Were the stack ever deep enough to decode it, this fails rather than passing on
    # some other path.
    with pytest.raises(RecursionError):
        json.loads(body)
    service = await _service(engine)
    await provision(service, "op", [Role.OPERATOR.value])
    async with _client(engine, service) as c:
        await cookie_login(c, "op")
        r = await c.post(
            route,
            content=body,
            headers={**SAME_ORIGIN, "Content-Type": "application/json"},
        )
    assert (r.status_code, r.json()) == (400, {"ok": False, "error": "malformed request"})


def _spy_login(service: AuthService, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    reached: list[str] = []
    real_login = service.login

    async def _spy(username: str, *args: Any, **kwargs: Any) -> Any:
        reached.append(username)
        return await real_login(username, *args, **kwargs)

    monkeypatch.setattr(service, "login", _spy)
    return reached


@pytest.mark.parametrize("username", ["op\x00", "\x00", "o\x00p"])
async def test_the_form_sign_in_refuses_a_nul_username_before_the_service(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, username: str
) -> None:
    """vault BACKLOG #5342, the form route. Red: the NUL reached ``AuthService.login``, where a
    PostgreSQL store's lookup would raise an error the route does not catch. The service writes no
    audit row for it, so the route logs the refusal, without the name."""
    service = await _service(engine)
    reached = _spy_login(service, monkeypatch)
    async with _client(engine, service) as c:
        with caplog.at_level(logging.WARNING, logger="messagefoundry_webconsole.routes.core"):
            r = await c.post(
                "/ui/login", data={"username": username, "password": PW}, headers=SAME_ORIGIN
            )
    assert (r.status_code, r.headers["location"]) == (303, "/ui/login?e=bad")
    assert reached == []
    [record] = [rec for rec in caplog.records if "held a NUL" in rec.getMessage()]
    # The client is the line's only argument, so no form of the name reaches the general log.
    assert record.args == ("127.0.0.1",)


async def test_the_combined_passkey_sign_in_refuses_a_nul_username_and_ends_its_challenge(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """vault BACKLOG #5342, the combined passkey sign-in, which rides the same form. Red: as above.
    The refusal also clears the challenge cookie, as a refused sign-in after the service does."""
    pytest.importorskip("webauthn")
    service = await _service(engine)
    reached = _spy_login(service, monkeypatch)
    async with _client(engine, service) as c:
        begun = await c.post("/ui/login/passkey", headers=SAME_ORIGIN)
        assert begun.status_code == 200, begun.text
        r = await c.post(
            "/ui/login",
            data={"username": "o\x00p", "password": "", "passkey_assertion": "{}"},
            headers=SAME_ORIGIN,
        )
    assert (r.status_code, r.headers["location"]) == (303, "/ui/login?e=bad")
    assert reached == []
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
