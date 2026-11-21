# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5646 -- every /ui message-search route refuses a session presented from a new address.

Four search routes gate with ``require_ui_step_up``, which builds its ``require_ui`` base with
``new_address_check=False`` and hands it ``step_up_new_address``, so the base asks the question on
every request, through ``flag_new_client_ip``. The preset delete gates with plain ``require_ui``,
which asks it for a write. Nothing drove a search route from
a second address, so a change that dropped either call would have stayed green.

**Each route has a REFUSE and an ALLOW arm built the same way.** One session, signed in at
:data:`SIGN_IN`, is sent from :data:`SIGN_IN` (ALLOW: the handler runs) and then from
:data:`ELSEWHERE` (REFUSE: a 303 to ``/ui/reauth``, and the handler does not run), through one app.
The step-up window and the permission are the same for both, so the address is what decides. The
arms are not otherwise identical: they run in turn, and a delete or layered arm names its own
preset. Each REFUSE arm also requires the ``auth.new_address_reverify_required`` audit row for its
request path, so a refusal for some other reason does not pass.

Mutants, run by hand: replacing the ``flag_new_client_ip`` call in ``require_ui``'s
``step_up_new_address`` branch with ``False`` fails the four step-up routes' cases (until BACKLOG
#5646 that call sat in ``require_ui_step_up`` itself); making ``_refuse_from_new_address`` return
without asking fails the delete case.

**A refused request spends nothing** (BACKLOG #5646). Each REFUSE arm also requires that neither
the admin-write nor the PHI-read budget was asked for while it ran. The step-up gate used to ask
the address question after its ``require_ui`` base had returned, so a refused write had already
spent the actor's admin-write budget. The ALLOW arms are the control that the spy sees each
charge at all: each write's charges the admin-write budget, and each of the three searches' (form,
run, layered) the PHI-read one.

All data here is synthetic.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import NamedTuple
from urllib.parse import quote

import httpx
import pytest
from _webui_support import _add, _cookie_login, _seed, _service
from fastapi.routing import APIRoute

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.pipeline import Engine

#: The address the session signs in from, and so has verified.
SIGN_IN = "10.0.0.1"
#: An address the session has never verified from: a replayed cookie.
ELSEWHERE = "10.9.9.9"

SAME_ORIGIN = {"Sec-Fetch-Site": "same-origin"}
SEARCH = "/ui/messages/search"
PRESETS = SEARCH + "/presets"
DELETE = PRESETS + "/{preset_id}/delete"

#: What one arm sends: the client and the id of a preset the session owns.
Sender = Callable[[httpx.AsyncClient, str], Awaitable[httpx.Response]]


async def _search_form(c: httpx.AsyncClient, _pid: str) -> httpx.Response:
    return await c.get(SEARCH)


async def _search_run(c: httpx.AsyncClient, _pid: str) -> httpx.Response:
    # A content criterion, so the handler reaches the search itself rather than the bare form.
    return await c.post(SEARCH + "/run", data={"content": "DOE"}, headers=SAME_ORIGIN)


async def _save(c: httpx.AsyncClient, pid: str) -> httpx.Response:
    # A name of its own per arm: a repeated name replaces the existing preset, which the id check
    # below could not tell from a refusal.
    return await c.post(PRESETS, data={"name": f"new-{pid}", "content": "DOE"}, headers=SAME_ORIGIN)


async def _delete(c: httpx.AsyncClient, pid: str) -> httpx.Response:
    return await c.post(DELETE.replace("{preset_id}", pid), headers=SAME_ORIGIN)


async def _layered(c: httpx.AsyncClient, pid: str) -> httpx.Response:
    return await c.get(SEARCH + "/layered", params={"presets": pid})


class Case(NamedTuple):
    id: str
    path: str  # as mounted
    method: str
    send: Sender
    allowed: int  # the ALLOW arm's status
    #: The REFUSE arm's ``next``, pinned exactly so a refusal from some other gate does not pass.
    next_path: str


#: Every mounted /ui/messages/search* route: test_every_search_route_is_covered reads the live table.
CASES = (
    Case("form", SEARCH, "GET", _search_form, 200, SEARCH),
    Case("run", SEARCH + "/run", "POST", _search_run, 200, SEARCH),
    # A body-carrying write, so its refusal continues to the search form, a registered unlock page
    # (BACKLOG #5646). It used to continue to its own POST path, which /ui/reauth refuses.
    Case("save_preset", PRESETS, "POST", _save, 303, SEARCH),
    # A plain require_ui write lands on /ui after the re-auth: its body cannot be carried through.
    Case("delete_preset", DELETE, "POST", _delete, 303, "/ui"),
    # The presets ride the continuation (BACKLOG #5646): without them the run answers 400. The
    # placeholder is the REFUSE arm's preset id.
    Case("layered", SEARCH + "/layered", "GET", _layered, 200, SEARCH + "/layered?presets={pid}"),
)


async def _new_address_paths(engine: Engine) -> list[str]:
    return [
        json.loads(str(dict(a)["detail"]))["path"]
        for a in await engine.store.list_audit(
            action="auth.new_address_reverify_required", limit=100
        )
    ]


@pytest.mark.parametrize("case", CASES, ids=[case.id for case in CASES])
async def test_a_search_route_refuses_a_session_from_a_new_address(
    engine: Engine, case: Case
) -> None:
    """RED when: a /ui message-search route serves a session presented from an address it never
    verified from (BACKLOG #5646). The ALLOW arm is the same session from its sign-in address."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    user = await service.store.get_user_by_username("op")
    assert user is not None
    await _seed(engine)

    # Every budget charge a gate or handler asks for, recorded by a spy over this instance.
    charges: list[str] = []
    admin_write, phi_read = service.allow_admin_write, service.allow_phi_read

    def spy_admin_write(actor: str) -> bool:
        charges.append("admin_write")
        return admin_write(actor)

    def spy_phi_read(actor: str) -> bool:
        charges.append("phi_read")
        return phi_read(actor)

    service.allow_admin_write = spy_admin_write  # type: ignore[method-assign]
    service.allow_phi_read = spy_phi_read  # type: ignore[method-assign]

    async def preset_ids() -> set[str]:
        # Read from the store, not a gated page, so a refused or throttled read cannot pass for
        # "no presets".
        return {p["id"] for p in await engine.store.list_search_presets(user.id)}

    app = create_app(engine, auth=service, serve_ui=True, webauthn_rp_from_request=True)

    def browser(ip: str) -> httpx.AsyncClient:
        transport = httpx.ASGITransport(app=app, client=(ip, 51000))
        return httpx.AsyncClient(transport=transport, base_url="http://t")

    async with browser(SIGN_IN) as home:
        assert (await _cookie_login(home, "op")).status_code == 303
        token = home.cookies.get("mf_session")
        assert token is not None
        # Two presets, so the delete arms each have one to remove and the layered arms one to run.
        for name in ("allow", "refuse"):
            r = await home.post(
                PRESETS,
                data={"name": name, "content": "DOE", "message_type": "ADT^A01"},
                headers=SAME_ORIGIN,
            )
            assert (r.status_code, r.headers.get("location")) == (303, SEARCH), r.text
        listed = await engine.store.list_search_presets(user.id)
        by_name = {p["name"]: p["id"] for p in listed}
        allow_pid, refuse_pid = by_name["allow"], by_name["refuse"]
        before = set(by_name.values())

        # ALLOW: the handler ran. The search pages render the form; the writes land back on it.
        charges.clear()
        ok = await case.send(home, allow_pid)
        assert ok.request.method == case.method
        assert ok.status_code == case.allowed, (ok.status_code, ok.headers.get("location"))
        if case.allowed == 303:
            assert ok.headers["location"] == SEARCH
        else:
            assert "Saved presets" in ok.text
        assert await _new_address_paths(engine) == []
        after_allow = await preset_ids()
        # The controls for the spend check below: an admitted write does charge the write budget,
        # and an admitted search the PHI-read one.
        if case.method == "POST":
            assert "admin_write" in charges, charges
        if case.id in ("form", "run", "layered"):
            assert "phi_read" in charges, charges

    charges.clear()
    async with browser(ELSEWHERE) as away:
        away.cookies.set("mf_session", token)
        refused = await case.send(away, refuse_pid)
    assert refused.request.method == case.method
    location = refused.headers.get("location", "")
    assert refused.status_code == 303, (refused.status_code, location)
    expected = quote(case.next_path.format(pid=refuse_pid), safe="/")
    assert location == f"/ui/reauth?next={expected}", location
    # A refused request spends nothing (BACKLOG #5646): no budget was asked for.
    assert charges == [], charges
    # The refusal was the address check, recorded for this route's request path.
    assert await _new_address_paths(engine) == [case.path.replace("{preset_id}", refuse_pid)]
    # The refused request changed nothing: no preset saved, none deleted.
    assert await preset_ids() == after_allow
    if case.path == PRESETS:
        assert len(after_allow) == len(before) + 1  # the ALLOW save did add one
    if case.path == DELETE:
        assert after_allow == before - {allow_pid}
        assert refuse_pid in after_allow


async def test_every_search_route_is_covered(engine: Engine) -> None:
    """RED when: a /ui/messages/search route is mounted without a case above, so it would ship with
    no test of its new-address refusal. Read from the live route table, not a list kept by hand."""
    app = create_app(engine, auth=await _service(engine), serve_ui=True)
    mounted = {
        (route.path, method)
        for route in app.routes
        if isinstance(route, APIRoute) and route.path.startswith(SEARCH)
        for method in route.methods or ()
        if method != "HEAD"
    }
    covered = {(case.path, case.method) for case in CASES}
    # The control: the walk found the routes it exists for, so an empty set is not a pass.
    assert (SEARCH, "GET") in mounted, mounted
    assert mounted == covered, mounted ^ covered


@pytest.mark.parametrize(
    ("target", "admitted"),
    [
        (SEARCH + "/layered", True),
        (SEARCH + "/layered?presets=a", True),
        (SEARCH + "/layered?presets=a&presets=b", True),
        (SEARCH + "/layered?presets=a&other=1", False),
        (SEARCH + "/layered?other=1", False),
    ],
)
def test_the_layered_continuation_admits_only_presets(target: str, admitted: bool) -> None:
    """The layered unlock pattern takes the run's ``presets`` query and nothing else (BACKLOG
    #5646), so a continuation carrying any other parameter is not one /ui/reauth will follow."""
    from messagefoundry_webconsole._auth import is_unlock_action

    assert is_unlock_action(target) is admitted
