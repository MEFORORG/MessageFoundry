# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5646 -- every /ui message-search route refuses a session presented from a new address.

The search routes gate with ``require_ui_step_up`` (and the preset delete with ``require_ui``) and
pass no ``phi=True``, so the new-address refusal ``require_ui`` asks for a PHI read never runs for
them. The step-up factory asks the same question itself, through ``flag_new_client_ip``; the delete
is a write, which ``require_ui`` asks for. Nothing drove a search route from a second address, so a
change that dropped either call would have stayed green.

**Each route has a REFUSE and an ALLOW arm differing ONLY in the client address.** One session,
signed in at :data:`SIGN_IN`, is presented from :data:`SIGN_IN` (ALLOW: the handler runs) and from
:data:`ELSEWHERE` (REFUSE: a 303 to ``/ui/reauth`` and the handler does not run). The step-up
window, the permission and the budgets are the same for both, so only the address check can tell
them apart. Each REFUSE arm also requires the ``auth.new_address_reverify_required`` audit row for
its path, so a refusal for some other reason does not pass.

Mutants, run by hand when this landed: replacing the ``flag_new_client_ip`` call in
``require_ui_step_up`` with ``False`` failed the four step-up routes' cases; making
``_refuse_from_new_address`` return without asking failed the delete case.

All data here is synthetic.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable

import httpx
import pytest
from _webui_support import _add, _cookie_login, _seed, _service
from fastapi.routing import APIRoute

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.pipeline import Engine

#: The address the session signs in from, and so has verified.
SIGN_IN = "10.0.0.1"
#: An address the session has never verified from: a replayed cookie.
ELSEWHERE = "10.9.9.9"

SAME_ORIGIN = {"Sec-Fetch-Site": "same-origin"}
PRESETS = "/ui/messages/search/presets"
MARKER = PRESETS + "/"


def _client_from(engine: Engine, service: AuthService, ip: str) -> httpx.AsyncClient:
    """A browser at ``ip``. The app is the shipped mount; only the peer address varies."""
    app = create_app(engine, auth=service, serve_ui=True, webauthn_rp_from_request=True)
    transport = httpx.ASGITransport(app=app, client=(ip, 51000))
    return httpx.AsyncClient(transport=transport, base_url="http://t")


async def _preset_ids(c: httpx.AsyncClient) -> set[str]:
    """The ids of the session's presets, read from the search page's delete forms."""
    page = (await c.get("/ui/messages/search")).text
    return {chunk.split("/delete", 1)[0] for chunk in page.split(MARKER)[1:]}


async def _save_preset(c: httpx.AsyncClient, name: str) -> str:
    before = await _preset_ids(c)
    r = await c.post(
        PRESETS,
        data={"name": name, "content": "DOE", "message_type": "ADT^A01"},
        headers=SAME_ORIGIN,
    )
    assert (r.status_code, r.headers.get("location")) == (303, "/ui/messages/search"), r.text
    (pid,) = await _preset_ids(c) - before
    return pid


#: What one arm sends: the client and the id of a preset the session owns.
Send = Callable[[httpx.AsyncClient, str], Awaitable[httpx.Response]]


async def _search_form(c: httpx.AsyncClient, _pid: str) -> httpx.Response:
    return await c.get("/ui/messages/search")


async def _search_run(c: httpx.AsyncClient, _pid: str) -> httpx.Response:
    return await c.post(
        "/ui/messages/search/run", data={"message_type": "ADT^A01"}, headers=SAME_ORIGIN
    )


async def _save(c: httpx.AsyncClient, pid: str) -> httpx.Response:
    # A name of its own per arm: a repeated name replaces the existing preset, which the id check
    # below could not tell from a refusal.
    return await c.post(PRESETS, data={"name": f"new-{pid}", "content": "DOE"}, headers=SAME_ORIGIN)


async def _delete(c: httpx.AsyncClient, pid: str) -> httpx.Response:
    return await c.post(f"{PRESETS}/{pid}/delete", headers=SAME_ORIGIN)


async def _layered(c: httpx.AsyncClient, pid: str) -> httpx.Response:
    return await c.get("/ui/messages/search/layered", params={"presets": pid})


#: (route path as mounted, method, request, the ALLOW status). Every mounted /ui/messages/search*
#: route must appear here: test_every_search_route_is_covered reads the live route table.
CASES: tuple[tuple[str, str, Send, int], ...] = (
    ("/ui/messages/search", "GET", _search_form, 200),
    ("/ui/messages/search/run", "POST", _search_run, 200),
    (PRESETS, "POST", _save, 303),
    (PRESETS + "/{preset_id}/delete", "POST", _delete, 303),
    ("/ui/messages/search/layered", "GET", _layered, 200),
)


async def _new_address_paths(engine: Engine) -> list[str]:
    return [
        json.loads(str(dict(a)["detail"]))["path"]
        for a in await engine.store.list_audit(
            action="auth.new_address_reverify_required", limit=100
        )
    ]


@pytest.mark.parametrize(
    ("path", "method", "send", "allowed"), CASES, ids=[f"{m} {p}" for p, m, _, _ in CASES]
)
async def test_a_search_route_refuses_a_session_from_a_new_address(
    engine: Engine, path: str, method: str, send: Send, allowed: int
) -> None:
    """RED when: a /ui message-search route serves a session presented from an address it never
    verified from (BACKLOG #5646). The ALLOW arm is the same session from its sign-in address."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    await _seed(engine)
    async with _client_from(engine, service, SIGN_IN) as home:
        assert (await _cookie_login(home, "op")).status_code == 303
        token = home.cookies.get("mf_session")
        assert token is not None
        # Two presets, so the delete arms each have one to remove and the layered arms one to run.
        allow_pid = await _save_preset(home, "allow")
        refuse_pid = await _save_preset(home, "refuse")
        before = await _preset_ids(home)

        # ALLOW: the handler ran. The search pages render the search form; the writes land back on it.
        ok = await send(home, allow_pid)
        assert ok.status_code == allowed, (ok.status_code, ok.headers.get("location"))
        if allowed == 303:
            assert ok.headers["location"] == "/ui/messages/search"
        else:
            assert "Saved presets" in ok.text
        assert await _new_address_paths(engine) == []
        after_allow = await _preset_ids(home)

    async with _client_from(engine, service, ELSEWHERE) as away:
        away.cookies.set("mf_session", token)
        refused = await send(away, refuse_pid)
        assert refused.status_code == 303, refused.status_code
        assert refused.headers["location"].startswith("/ui/reauth?next="), refused.headers
    # The refusal was the address check, recorded for this route's request path.
    assert await _new_address_paths(engine) == [path.replace("{preset_id}", refuse_pid)]

    async with _client_from(engine, service, SIGN_IN) as home:
        home.cookies.set("mf_session", token)
        # The refused write changed nothing: no preset saved, none deleted.
        assert await _preset_ids(home) == after_allow
    if method == "POST" and path == PRESETS:
        assert len(after_allow) == len(before) + 1  # the ALLOW save did add one
    if path.endswith("/delete"):
        assert after_allow == before - {allow_pid}
        assert refuse_pid in after_allow


async def test_every_search_route_is_covered(engine: Engine) -> None:
    """RED when: a /ui/messages/search route is mounted without a case above, so it would ship with
    no test of its new-address refusal. Read from the live route table, not a list kept by hand."""
    app = create_app(engine, auth=await _service(engine), serve_ui=True)
    mounted = {
        (route.path, method)
        for route in app.routes
        if isinstance(route, APIRoute) and route.path.startswith("/ui/messages/search")
        for method in route.methods or ()
        if method != "HEAD"
    }
    covered = {(path, method) for path, method, _, _ in CASES}
    # The control: the walk found the routes it exists for, so an empty set is not a pass.
    assert ("/ui/messages/search", "GET") in mounted, mounted
    assert mounted == covered, mounted ^ covered
