# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1738 -- the ADR 0092 serve-hop refusal was missing on the console's PHI routes.

``enforce_phi_read_hop`` is folded into ``api.security.require_phi_read``, so every JSON PHI-read
route takes it through its ``Depends``. The console reaches ``get_message`` / ``list_messages`` /
``list_dead_letters`` / ``download_attachment`` IN-PROCESS, by reference, which skips that
``Depends`` entirely -- and ``require_ui(..., phi=True)`` re-applied the permission and the per-actor
budget but not the hop refusal. On first deployment a production-PHI instance whose serve hop is not
proven secure would therefore have refused a JSON PHI read and served the same body through ``/ui``.

**This suite is written so a silent no-op cannot pass it.** Each REFUSE assertion is paired with an
ALLOW arm built the same way, differing ONLY in ``phi_read_hop_secure``. A fix that never reaches
``request.app.state.phi_read_hop_disposition`` -- a hardcoded raise, or a gate keyed on something
else -- fails one arm or the other. The disposition is DERIVED by ``create_app`` from the posture
here, never stamped onto ``app.state`` by hand, so the test exercises the shipped seam.

``test_ui_plane_states_the_phi_read_hop_gap`` in the engine's ``tests/test_security_doc_drift.py``
holds the doc side, both ways.

All data here is synthetic.
"""

from __future__ import annotations

import re
from typing import Any

import httpx
import pytest
from _ui_clients import create_local_user_chosen
from fastapi.routing import APIRoute

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AiSettings, AuthSettings
from messagefoundry.pipeline import Engine

PW = "a-strong-test-passphrase"  # >=15, no app/vendor terms -- satisfies the ASVS policy (WP-3)
ADT = "MSH|^~\\&|S|F|R|RF|20260604||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"

#: The PHI needle. Asserting on this rather than only on a status code is what makes a REFUSE arm
#: mean "the body did not leave" instead of "some 403 happened".
NEEDLE = "DOE^JANE"


async def _service(engine: Engine) -> AuthService:
    # require_mfa=False for the same reason the sibling /ui suites pin it: these tests exercise the
    # hop refusal, not MFA enrollment, and an unenrolled session would otherwise divert to /ui/account.
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    return service


def _client(engine: Engine, service: AuthService, *, secure_hop: bool) -> httpx.AsyncClient:
    """A real mounted console on a PRODUCTION-PHI instance, whose serve hop is or is not proven
    secure. ``secure_hop`` is the ONLY variable between the two arms of every test below."""
    app = create_app(
        engine,
        auth=service,
        serve_ui=True,
        ai_settings=AiSettings(environment="prod"),
        phi_read_hop_secure=secure_hop,
    )
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")


async def _add(service: AuthService, username: str, *roles: Role) -> None:
    user_id = await create_local_user_chosen(
        service,
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=[r.value for r in roles],
        actor="test",
    )
    await service.set_channel_scope(user_id, [ALL_CHANNELS], actor="test")
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id,
        password_hash=user.password_hash,
        must_change_password=False,
        password_generated=False,
    )


async def _login(c: httpx.AsyncClient, username: str = "op") -> None:
    r = await c.post("/ui/login", data={"username": username, "password": PW})
    assert r.status_code in (200, 303), r.status_code


async def _seed(engine: Engine) -> str:
    return await engine.store.enqueue_message(
        channel_id="ch1",
        raw=ADT,
        deliveries=[("archive", ADT)],
        control_id="MSG1",
        message_type="ADT^A01",
        source_type="file",
    )


#: The tenth ``phi=True`` route, and the only non-GET one, so it is exercised on its own below
#: rather than in the GET loop. It rides ``require_ui_step_up`` like ``/edit`` does.
EDIT_RESEND = "/ui/messages/{message_id}/edit-resend"


#: The GET message routes whose gate passes ``phi=True``, as the route TEMPLATES the app mounts,
#: exercised with a seeded message (the derived walk below covers every ``phi=True`` gate, these
#: included, with placeholder ids). Read from ``messagefoundry_webconsole/routes/core.py``. BACKLOG
#: #2346 added ``/summary`` and ``/body``, and BACKLOG #2436 ``/errors``: the detail page with a
#: reveal declared.
#:
#: More than the four handlers BACKLOG #1738 names: ``parse-tree`` reaches the body fetch too, and the
#: edit pair rides ``require_ui_step_up``, which builds its base as ``require_ui(*perms, phi=phi,
#: ...)`` -- so a call placed in ``require_ui``'s ``phi`` arm covers the pair with no call site of its
#: own. That forwarding is why the pair is asserted here rather than assumed.
PHI_GET_ROUTES = (
    "/ui/messages",
    "/ui/messages/{message_id}",
    "/ui/messages/{message_id}/summary",
    "/ui/messages/{message_id}/body",
    "/ui/messages/{message_id}/errors",
    "/ui/messages/{message_id}/parse-tree",
    "/ui/messages/{message_id}/attachments/{attachment_id}",
    "/ui/dead-letters",
    "/ui/messages/{message_id}/edit",
)


def _phi_routes(message_id: str) -> list[str]:
    """:data:`PHI_GET_ROUTES` filled in for one seeded message."""
    return [t.format(message_id=message_id, attachment_id="deadbeef") for t in PHI_GET_ROUTES]


async def test_an_unproven_serve_hop_refuses_every_ui_phi_route(engine: Engine) -> None:
    """The REFUSE arm. A production-PHI instance over an unproven hop 403s the whole set, and the
    PHI body never reaches the response."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    mid = await _seed(engine)
    async with _client(engine, service, secure_hop=False) as c:
        await _login(c)
        for path in _phi_routes(mid):
            r = await c.get(path)
            assert r.status_code == 403, f"{path} was not refused: {r.status_code}"
            assert "PHI read refused" in r.text, f"{path} refused for some other reason: {r.text}"
            assert NEEDLE not in r.text, f"{path} leaked the body on its refusal"


async def test_the_edit_resend_post_is_refused_before_it_reads_the_stored_body(
    engine: Engine,
) -> None:
    """The tenth route, and the one a GET-only loop would miss.

    ``POST /ui/messages/{id}/edit-resend`` re-reads the PRISTINE stored copy on its reject path, so it
    emits PHI exactly as the GET editor does. It gets the refusal from the same ``phi`` arm, and it
    gets it in the DEPENDENCY -- before the route body parses the form or re-reads the message."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    mid = await _seed(engine)
    headers = {"Sec-Fetch-Site": "same-origin"}
    async with _client(engine, service, secure_hop=False) as c:
        await _login(c)
        r = await c.post(EDIT_RESEND.format(message_id=mid), data={"raw": ADT}, headers=headers)
        assert r.status_code == 403, r.status_code
        assert "PHI read refused" in r.text, r.text
        assert NEEDLE not in r.text
    # Control: the same POST over a proven hop is not refused on posture. It may still be turned away
    # for a stale step-up window, which is a different gate and not this test's subject.
    async with _client(engine, service, secure_hop=True) as c:
        await _login(c)
        ok = await c.post(EDIT_RESEND.format(message_id=mid), data={"raw": ADT}, headers=headers)
        assert "PHI read refused" not in ok.text, ok.text


async def test_a_proven_serve_hop_still_serves_the_same_routes(engine: Engine) -> None:
    """The ALLOW control arm, and the half that makes the test above mean something.

    Without it a fix that refuses UNCONDITIONALLY -- or one that never reads
    ``request.app.state.phi_read_hop_disposition`` at all and raises on every ``phi=True`` request --
    passes the REFUSE arm perfectly while breaking the console outright. The two apps differ in
    exactly one constructor argument."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    mid = await _seed(engine)
    async with _client(engine, service, secure_hop=True) as c:
        await _login(c)
        for path in _phi_routes(mid):
            r = await c.get(path)
            assert r.status_code != 403, f"{path} was refused over a PROVEN hop: {r.status_code}"
        # The browse pair actually renders, so the ALLOW arm is a served page and not merely a
        # non-403: a redirect everywhere would satisfy the loop above.
        listing = await c.get("/ui/messages")
        assert listing.status_code == 200, listing.status_code
        # /body, because the bare detail page shows no body until the operator asks (BACKLOG #2346).
        detail = await c.get(f"/ui/messages/{mid}/body")
        assert detail.status_code == 200, detail.status_code
        assert NEEDLE in detail.text, "the raw view served no body over a proven hop"


async def test_the_refusal_lands_after_identity_so_a_visitor_still_gets_the_login_page(
    engine: Engine,
) -> None:
    """THE PLACEMENT, which is a decision the row did not make and the code now does.

    The JSON plane refuses BEFORE any identity work. The console must not: a browser with no session
    has to reach ``/ui/login``, and refusing first would answer an unauthenticated ``GET
    /ui/messages`` with a 403 whose message names the instance's serve-hop posture -- handing an
    anonymous visitor a configuration read the JSON plane never gives them (it answers 401 either
    way). So the call sits inside the ``phi`` block, below the session check and the permission loop.

    Pinned because the two orders are indistinguishable on an AUTHENTICATED request, which is every
    other test in this file."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    mid = await _seed(engine)
    async with _client(engine, service, secure_hop=False) as c:
        for path in _phi_routes(mid):  # no login: this client holds no session cookie
            r = await c.get(path, follow_redirects=False)
            assert r.status_code == 303, (
                f"{path} did not redirect an anonymous visitor: {r.status_code}"
            )
            assert r.headers["location"].startswith("/ui/login"), r.headers["location"]
            assert "PHI read refused" not in r.text, f"{path} disclosed the posture to a visitor"


async def test_a_forbidden_actor_is_still_refused_on_permission_not_on_posture(
    engine: Engine,
) -> None:
    """The same ordering, one rung further in: the permission loop runs BEFORE the hop guard, so an
    actor who lacks ``messages:view_raw`` learns nothing about the serve hop either.

    A VIEWER holds ``messages:read`` and not ``messages:view_raw``, so the raw view is a plain
    authorization refusal on both hop postures."""
    service = await _service(engine)
    await _add(service, "vw", Role.VIEWER)
    mid = await _seed(engine)
    async with _client(engine, service, secure_hop=False) as c:
        await _login(c, "vw")
        # /body, the one detail route that renders the body, so the NEEDLE check can fail
        # (BACKLOG #2346: the bare detail page never renders it). The bare page is refused too.
        for path in (f"/ui/messages/{mid}/body", f"/ui/messages/{mid}"):
            r = await c.get(path)
            assert r.status_code == 403, (path, r.status_code)
            assert "PHI read refused" not in r.text, "posture disclosed to an unauthorized actor"
            assert NEEDLE not in r.text


#: Two routes an OPERATOR can actually reach, so a 403 here can only come from the hop guard. Not
#: ``/ui/audit``: it needs ``audit:read``, which the operator role does not hold, so it answers 403
#: from the permission loop on BOTH hop postures and would report a creeping guard that is not there.
@pytest.mark.parametrize("path", ["/ui", "/ui/connections"])
async def test_a_non_phi_console_route_is_untouched_by_the_refusal(
    engine: Engine, path: str
) -> None:
    """The guard is bound to the ``phi=True`` arm, so it must not creep onto the rest of the console.

    An operator on a refusing instance still monitors it -- the refusal withholds message BODIES, not
    the whole operator surface. A fix placed above the ``phi`` block would 403 these and nothing else
    in this file would notice."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service, secure_hop=False) as c:
        await _login(c)
        r = await c.get(path)
        assert r.status_code == 200, (
            f"{path} was refused on a PHI-refusing instance: {r.status_code}"
        )


# --- BACKLOG #5646: the three console message-search routes -----------------------------------------
#
# These three gate with ``require_ui_step_up(MESSAGES_READ)`` and NO ``phi=True``, on purpose: the
# JSON handlers they call in-process (``search_messages``, ``layered_search``) charge the per-actor
# read budget in their own bodies, so a gate-level ``phi=`` would charge it twice (BACKLOG #1025).
# The serve-hop refusal therefore has to come from those handler bodies, which call
# ``enforce_phi_read_hop`` before any decrypt. Nothing in the gate shows that, so it is pinned here
# on the shipped seam, one REFUSE and one ALLOW arm per route, differing ONLY in
# ``phi_read_hop_secure``.
#
# The short-circuit renders (the bare form, a refused filter, the no-preset layered 400) never reach
# those handlers and are not exercised here: they render the form and the caller's preset names.

#: The search criterion each arm sends. ``JANE`` is a substring of the seeded PID-5, so the ALLOW arm
#: has a match to render; it is not :data:`NEEDLE`, so finding NEEDLE in a response means a body or
#: summary left, never that the criterion was echoed.
CONTENT_TERM = "JANE"

#: The criteria-bearing search routes, by the template the app mounts, each with the request that
#: makes it run a search. ``presets`` is filled in by :func:`_run_search` once a preset is saved.
SEARCH_ROUTES: dict[tuple[str, str], dict[str, Any]] = {
    ("GET", "/ui/messages/search"): {"params": {"field_path": "PID-5"}},
    ("POST", "/ui/messages/search/run"): {
        "data": {"content": CONTENT_TERM},
        "headers": {"Sec-Fetch-Site": "same-origin"},
    },
    ("GET", "/ui/messages/search/layered"): {},
}

#: Every other mounted message or search route whose gate does NOT pass ``phi=True``, each with why
#: it is not a PHI read this file must refuse. :func:`test_every_message_route_is_classified` fails
#: on a route in neither set, so a new search or message route cannot escape this file by being left
#: off a hand-kept list.
NOT_PHI_READ_ROUTES: dict[tuple[str, str], str] = {
    ("POST", "/ui/messages/search/presets"): "saves a preset, then 303s to the bare form",
    ("POST", "/ui/messages/search/presets/{preset_id}/delete"): "deletes a preset, then 303s",
    ("GET", "/ui/messages/{message_id}/resend-confirm"): "renders the id and two names only",
    ("GET", "/ui/messages/{message_id}/resend-done"): "renders the resend record, not the message",
    ("POST", "/ui/messages/{message_id}/resend"): "queues a resend, then 303s to resend-done",
    ("POST", "/ui/messages/{message_id}/replay"): "re-queues a message, then 303s",
    ("POST", "/ui/dead-letters/replay-all"): "re-queues dead letters, then 303s",
    ("POST", "/ui/dead-letters/{channel_id}/replay"): "re-queues dead letters, then 303s",
    ("POST", "/ui/dead-letters/{channel_id}/{destination_name}/replay"): "re-queues, then 303s",
}


async def _save_preset(c: httpx.AsyncClient) -> str:
    """Save one content preset and return its id, read from the bare form's delete action.

    The bare form is a short-circuit render that never reaches ``search_messages``, so it is served
    on both hop postures; that is what lets the REFUSE arm build its preset the same way."""
    saved = await c.post(
        "/ui/messages/search/presets",
        data={"name": "p1", "content": CONTENT_TERM},
        headers={"Sec-Fetch-Site": "same-origin"},
    )
    assert saved.status_code == 303, (saved.status_code, saved.text)
    form = await c.get("/ui/messages/search")
    assert form.status_code == 200, form.status_code
    marker = "/ui/messages/search/presets/"
    assert marker in form.text, "the saved preset is not listed"
    return form.text.split(marker, 1)[1].split("/delete", 1)[0]


async def _run_search(
    engine: Engine, route: tuple[str, str], *, secure_hop: bool
) -> httpx.Response:
    """Seed a message, log in on a FRESH client (so the step-up window is fresh), and send the
    criteria-bearing request for ``route``. Both arms below go through here, so ``secure_hop`` is
    the only thing that can differ between them.

    ``follow_redirects=False`` so a 303 to ``/ui/reauth`` is seen as the 303 it is: a stale step-up
    is a different gate, never a pass."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    await _seed(engine)
    method, path = route
    kwargs = dict(SEARCH_ROUTES[route])
    async with _client(engine, service, secure_hop=secure_hop) as c:
        await _login(c)
        if path == "/ui/messages/search/layered":
            kwargs["params"] = {"presets": await _save_preset(c)}
        return await c.request(method, path, follow_redirects=False, **kwargs)


@pytest.mark.parametrize("route", list(SEARCH_ROUTES))
async def test_an_unproven_serve_hop_refuses_the_search_routes(
    engine: Engine, route: tuple[str, str]
) -> None:
    """The REFUSE arm for each search route: a 403 naming the hop refusal, with no body in it."""
    r = await _run_search(engine, route, secure_hop=False)
    assert r.status_code == 403, f"{route} was not refused: {r.status_code}"
    assert "PHI read refused" in r.text, f"{route} refused for some other reason: {r.text}"
    assert NEEDLE not in r.text, f"{route} leaked the body on its refusal"


@pytest.mark.parametrize("route", list(SEARCH_ROUTES))
async def test_a_proven_serve_hop_still_serves_the_search_routes(
    engine: Engine, route: tuple[str, str]
) -> None:
    """The ALLOW arm, built the same way. A served 200 that ran the search, not merely a non-403:
    a redirect to ``/ui/reauth`` would mean the arm never reached the handler at all."""
    r = await _run_search(engine, route, secure_hop=True)
    assert r.status_code == 200, f"{route} was not served over a PROVEN hop: {r.status_code}"
    assert "PHI read refused" not in r.text, r.text
    assert "1 match(es)" in r.text, f"{route} served no search result over a proven hop"


def _gate_passes_phi(call: object) -> bool:
    """Whether a route dependency is, or wraps, a ``require_ui`` gate built with ``phi=True``.

    Read from the closures, as ``test_every_phi_page_has_a_reauth_continuation`` does, so no marker is
    needed in product code. The step-up factories keep their ``require_ui`` gate in a ``base`` cell,
    which is how the edit pair's ``phi=True`` is found."""
    code = getattr(call, "__code__", None)
    if code is None:
        return False
    closure = getattr(call, "__closure__", None) or ()
    cells = dict(zip(code.co_freevars, (c.cell_contents for c in closure), strict=True))
    if getattr(call, "__qualname__", "") == "require_ui.<locals>.dependency":
        return bool(cells.get("phi"))
    return "base" in cells and _gate_passes_phi(cells["base"])


def _mounted_ui_routes(engine: Engine, service: AuthService) -> list[tuple[str, str, bool, str]]:
    """Every mounted /ui route as ``(method, path, gate passes phi=True, endpoint module)``."""
    app = create_app(engine, auth=service, serve_ui=True)
    found = []
    for route in app.router.routes:
        if not (isinstance(route, APIRoute) and route.path.startswith("/ui")):
            continue
        phi = any(_gate_passes_phi(dep.call) for dep in route.dependant.dependencies)
        for method in route.methods or ():
            found.append((method, route.path, phi, route.endpoint.__module__))
    return found


async def test_every_phi_gated_route_is_refused_over_an_unproven_hop(engine: Engine) -> None:
    """Derived from the LIVE route table: every /ui route whose gate passes ``phi=True``, wherever
    its path, 403s with the hop refusal, and does not over a proven hop.

    The refusal runs in the gate, before the route body, so a placeholder id reaches it as well as a
    real one; that is what lets a route nobody listed by hand be exercised. The two arms differ only
    in ``phi_read_hop_secure``."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    gated = sorted(
        (method, path) for method, path, phi, _ in _mounted_ui_routes(engine, service) if phi
    )
    # The control: the walk found the routes it exists for, so an empty walk is not a pass.
    assert {("GET", p) for p in PHI_GET_ROUTES} <= set(gated), gated
    assert ("POST", EDIT_RESEND) in gated, gated
    for secure_hop in (False, True):
        async with _client(engine, service, secure_hop=secure_hop) as c:
            await _login(c)
            for method, path in gated:
                concrete = re.sub(r"\{[^}]+\}", "x1", path)
                r = await c.request(method, concrete, follow_redirects=False)
                refused = r.status_code == 403 and "PHI read refused" in r.text
                assert refused is not secure_hop, (secure_hop, method, path, r.status_code)


async def test_every_message_route_is_classified(engine: Engine) -> None:
    """Derived from the LIVE route table, so a route added later cannot silently escape this file.

    Every mounted ``/ui/messages*`` and ``/ui/dead-letters*`` route, and every route the search
    module registers wherever its path, whose gate does NOT pass ``phi=True``, must be a search route
    this file exercises (:data:`SEARCH_ROUTES`) or one :data:`NOT_PHI_READ_ROUTES` names with a
    reason. The ``phi=True`` ones are covered by the derived walk above. A new one fails here until
    someone decides which it is."""
    service = await _service(engine)
    in_scope = {
        (method, path)
        for method, path, phi, module in _mounted_ui_routes(engine, service)
        if not phi
        and (
            path.startswith(("/ui/messages", "/ui/dead-letters"))
            or module == "messagefoundry_webconsole.routes.search"
        )
    }
    classified = set(SEARCH_ROUTES) | set(NOT_PHI_READ_ROUTES)
    assert in_scope == classified, (
        f"unclassified (mounted, in neither set): {sorted(in_scope - classified)}\n"
        f"stale (classified, not mounted): {sorted(classified - in_scope)}"
    )
