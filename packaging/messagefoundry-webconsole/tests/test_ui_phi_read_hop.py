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
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any, NamedTuple

import httpx
import pytest
from _ui_clients import create_local_user_chosen
from fastapi.routing import APIRoute

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AiSettings, AuthSettings, StoreSettings
from messagefoundry.pipeline import Engine
from messagefoundry.uploads import UploadStore
from messagefoundry_webconsole.routes.uploaded_logs import BROWSE_HOP_REFUSED_CODE

PW = "a-strong-test-passphrase"  # >=15, no app/vendor terms -- satisfies the ASVS policy (WP-3)
ADT = "MSH|^~\\&|S|F|R|RF|20260604||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"

#: The PHI needle. Asserting on this rather than only on a status code is what makes a REFUSE arm
#: mean "the body did not leave" instead of "some 403 happened".
NEEDLE = "DOE^JANE"


async def _service(engine: Engine, *, write_floor: bool = True) -> AuthService:
    # require_mfa=False for the same reason the sibling /ui suites pin it: these tests exercise the
    # hop refusal, not MFA enrollment, and an unenrolled session would otherwise divert to /ui/account.
    # write_floor=False only for the handler-guarded arms: an upload arm sends two writes back to
    # back, and the write-pacing floor would answer the second 429, a gate those arms are not about.
    settings = AuthSettings(require_mfa=False)
    if not write_floor:
        settings = AuthSettings(require_mfa=False, admin_write_min_interval_seconds=0)
    service = AuthService(engine.store, settings)
    await service.initialize()
    return service


def _client(
    engine: Engine, service: AuthService, *, secure_hop: bool, uploads_dir: Path | None = None
) -> httpx.AsyncClient:
    """A real mounted console on a PRODUCTION-PHI instance, whose serve hop is or is not proven
    secure. ``secure_hop`` is the ONLY variable between the two arms of every test below.
    ``uploads_dir`` turns the uploaded-logs store on, for the arms that browse a file."""
    app = create_app(
        engine,
        auth=service,
        serve_ui=True,
        ai_settings=AiSettings(environment="prod"),
        phi_read_hop_secure=secure_hop,
        store_settings=(
            None
            if uploads_dir is None
            else StoreSettings(uploads_dir=str(uploads_dir), max_upload_bytes=1_000_000)
        ),
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


#: The non-GET message route whose gate passes ``phi=True``, so it is exercised on its own below
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
    """The edit-resend POST, the message route a GET-only loop would miss.

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


# --- BACKLOG #5646: the routes whose hop refusal lives in the handler, not the gate ---------------
#
# These gate with ``require_ui_step_up`` and NO ``phi=True``, on purpose: the in-process handlers they
# call pace the read budget themselves, so a gate ``phi=`` would charge it twice. The rule and its
# reasoning are stated once, in ``require_ui_step_up``'s docstring (BACKLOG #1025). Their hop refusal
# is the handler's own ``enforce_phi_read_hop`` call, which the gate walk below cannot see, so each
# gets a REFUSE and an ALLOW arm here, differing ONLY in ``phi_read_hop_secure``.
#
# The search routes' short-circuit renders (the bare form, a refused filter, the no-preset layered
# 400) never reach those handlers and are not exercised here. The uploaded-logs filter's refused-
# criteria re-render does reach its handler, and is not exercised here either.

#: The search criterion the content arms send. ``JANE`` is a substring of the seeded PID-5, so the
#: ALLOW arm has a match to render; it is not :data:`NEEDLE`, so finding NEEDLE in a response means a
#: body or summary left, never that the criterion was echoed.
CONTENT_TERM = "JANE"

SAME_ORIGIN = {"Sec-Fetch-Site": "same-origin"}


async def _save_preset(c: httpx.AsyncClient) -> str:
    """Save one content preset and return its id, read from the bare form's delete action. The store
    is fresh, so the one delete action on the page is this preset's.

    The bare form is a short-circuit render that never reaches ``search_messages``, so it is served
    on both hop postures; that is what lets the REFUSE arm build its preset the same way."""
    saved = await c.post(
        "/ui/messages/search/presets",
        data={"name": "p1", "content": CONTENT_TERM},
        headers=SAME_ORIGIN,
    )
    assert saved.status_code == 303, (saved.status_code, saved.text)
    form = await c.get("/ui/messages/search")
    assert form.status_code == 200, form.status_code
    ids: list[str] = re.findall(r"/ui/messages/search/presets/([^/\"]+)/delete", form.text)
    assert len(ids) == 1, ids
    return ids[0]


async def _upload(c: httpx.AsyncClient) -> str:
    """Upload :data:`ADT` as a log file and return its file id, read off the listing's browse link.
    Uploading is a write with no hop refusal, so it works on both postures."""
    up = await c.post(
        "/ui/uploaded-logs/upload",
        files={"file": ("acme.hl7", ADT, "application/octet-stream")},
        headers=SAME_ORIGIN,
        follow_redirects=False,
    )
    assert (up.status_code, up.headers.get("location")) == (303, "/ui/uploaded-logs"), up.text
    listing = await c.get("/ui/uploaded-logs")
    ids: set[str] = set(re.findall(r"/ui/uploaded-logs/file/([0-9a-f]{32})", listing.text))
    assert len(ids) == 1, ids
    return ids.pop()


#: The request builder for each route: given a logged-in client, return the ``httpx`` request
#: arguments, with ``path_args`` filling the route template.
_Setup = Callable[[httpx.AsyncClient], Awaitable[dict[str, Any]]]


async def _field_path_search(_c: httpx.AsyncClient) -> dict[str, Any]:
    return {"params": {"field_path": "PID-5"}}


async def _content_search(_c: httpx.AsyncClient) -> dict[str, Any]:
    return {"data": {"content": CONTENT_TERM}, "headers": SAME_ORIGIN}


async def _layered_search(c: httpx.AsyncClient) -> dict[str, Any]:
    return {"params": {"presets": await _save_preset(c)}}


async def _browse_upload(c: httpx.AsyncClient) -> dict[str, Any]:
    return {"path_args": {"file_id": await _upload(c)}}


async def _filter_upload(c: httpx.AsyncClient) -> dict[str, Any]:
    return {
        "path_args": {"file_id": await _upload(c)},
        "data": {"content": CONTENT_TERM},
        "headers": SAME_ORIGIN,
    }


def _refused_in_place(r: httpx.Response) -> bool:
    """The search pages pass the handler's hop 403 through as it is."""
    return r.status_code == 403 and "PHI read refused" in r.text


def _refused_to_listing(r: httpx.Response) -> bool:
    """The uploaded-logs pages turn the handler's 403 into a 303 to the listing with a fixed code
    (``routes/uploaded_logs.py``, ``_BROWSE_CODES``), the only 403 that handler raises."""
    return (r.status_code, r.headers.get("location")) == (
        303,
        f"/ui/uploaded-logs?e={BROWSE_HOP_REFUSED_CODE}",
    )


class _Guarded(NamedTuple):
    setup: _Setup
    refused: Callable[[httpx.Response], bool]
    #: The text the ALLOW arm must render, so a 200 that ran nothing does not pass. Anchored with
    #: ``\b`` so ``11 match(es)`` is not read as one.
    served: str
    #: Which read the handler decrypts through, spied on so a refusal that lands after the decrypt
    #: fails: ``store`` is ``Store.search_messages``, ``upload`` is ``UploadStore.read_bytes``.
    decrypt: str


#: Every route whose hop refusal is the handler's own call.
HANDLER_GUARDED_ROUTES: dict[tuple[str, str], _Guarded] = {
    ("GET", "/ui/messages/search"): _Guarded(
        _field_path_search, _refused_in_place, r"\b1 match\(es\)", "store"
    ),
    ("POST", "/ui/messages/search/run"): _Guarded(
        _content_search, _refused_in_place, r"\b1 match\(es\)", "store"
    ),
    ("GET", "/ui/messages/search/layered"): _Guarded(
        _layered_search, _refused_in_place, r"\b1 match\(es\)", "store"
    ),
    ("GET", "/ui/uploaded-logs/file/{file_id}"): _Guarded(
        _browse_upload, _refused_to_listing, r"\b1 of 1 message\(s\)", "upload"
    ),
    ("POST", "/ui/uploaded-logs/file/{file_id}/filter"): _Guarded(
        _filter_upload, _refused_to_listing, r"\b1 of 1 message\(s\)", "upload"
    ),
}

#: Every other in-scope route whose gate does NOT pass ``phi=True``, each with why it is not a PHI
#: read this file must refuse. :func:`test_every_message_route_is_classified` fails on an in-scope
#: route in neither set, so a new one there cannot escape this file by being left off a hand-kept
#: list. A route outside that test's scope can; its docstring names the scope.
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
    (
        "GET",
        "/ui/uploaded-logs/file/{file_id}/resend-confirm",
    ): "renders the file name, an index and a target",
    ("POST", "/ui/uploaded-logs/file/{file_id}/resend"): "queues a resend, then 303s",
    ("GET", "/ui/uploaded-logs/file/{file_id}/delete-confirm"): "renders the file id and name only",
    ("POST", "/ui/uploaded-logs/file/{file_id}/delete"): "deletes the file, then 303s",
}


async def _run_guarded(
    engine: Engine,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    route: tuple[str, str],
    *,
    secure_hop: bool,
) -> tuple[httpx.Response, int]:
    """Seed a message, log in on a FRESH client (so the step-up window is fresh), build the route's
    request, and send it. Both arms below go through here, so ``secure_hop`` is the only thing that
    can differ between them. Returns the response and how many decrypting reads the REQUEST itself
    made (the setup's reads are not counted).

    ``follow_redirects=False`` so a 303 to ``/ui/reauth`` is seen as the 303 it is: a stale step-up
    is a different gate, never a pass."""
    service = await _service(engine, write_floor=False)
    await _add(service, "op", Role.OPERATOR)
    await _seed(engine)
    method, template = route
    spec = HANDLER_GUARDED_ROUTES[route]
    reads = 0
    owner: Any = engine.store if spec.decrypt == "store" else UploadStore
    name = "search_messages" if spec.decrypt == "store" else "read_bytes"
    real = getattr(owner, name)

    # One spy fits both: patched on the instance, ``real`` is bound and ``args`` carries no self;
    # patched on the class, ``real`` is the plain function and ``args`` starts with self.
    async def spy(*args: Any, **kwargs: Any) -> Any:
        nonlocal reads
        reads += 1
        return await real(*args, **kwargs)

    async with _client(
        engine, service, secure_hop=secure_hop, uploads_dir=tmp_path / "uploads"
    ) as c:
        await _login(c)
        kwargs = await spec.setup(c)
        path = template.format(**kwargs.pop("path_args", {}))
        monkeypatch.setattr(owner, name, spy)
        try:
            r = await c.request(method, path, follow_redirects=False, **kwargs)
        finally:
            monkeypatch.undo()
    return r, reads


@pytest.mark.parametrize("route", list(HANDLER_GUARDED_ROUTES), ids=" ".join)
async def test_an_unproven_serve_hop_refuses_the_handler_guarded_routes(
    engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, route: tuple[str, str]
) -> None:
    """The REFUSE arm: the hop refusal, and no decrypting read behind it.

    The read spy is the instrument here, not :data:`NEEDLE`: these pages render metadata and
    summaries only, even when served, so a needle check could not fail. A refusal moved below the
    decrypt fails the spy."""
    r, reads = await _run_guarded(engine, tmp_path, monkeypatch, route, secure_hop=False)
    assert HANDLER_GUARDED_ROUTES[route].refused(r), f"{route} was not refused: {r.status_code}"
    assert reads == 0, f"{route} decrypted {reads} time(s) before refusing"


@pytest.mark.parametrize("route", list(HANDLER_GUARDED_ROUTES), ids=" ".join)
async def test_a_proven_serve_hop_still_serves_the_handler_guarded_routes(
    engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, route: tuple[str, str]
) -> None:
    """The ALLOW arm, built the same way. A served 200 that ran the search, not merely a non-403:
    a redirect to ``/ui/reauth`` would mean the arm never reached the handler at all."""
    r, reads = await _run_guarded(engine, tmp_path, monkeypatch, route, secure_hop=True)
    assert r.status_code == 200, f"{route} was not served over a PROVEN hop: {r.status_code}"
    assert re.search(HANDLER_GUARDED_ROUTES[route].served, r.text), f"{route} served no result"
    # The positive control for the REFUSE arm's zero: the spy sees a served read.
    assert reads >= 1, f"{route} made no decrypting read, so the REFUSE arm's zero proves nothing"


def _gate_passes_phi(call: object) -> bool:
    """Whether a dependency is, or wraps, a ``require_ui`` gate built with ``phi=True``.

    Read from the closures, as ``test_every_phi_page_has_a_reauth_continuation`` in
    ``test_webui_oidc.py`` does, so no marker is needed in product code. Only a ``base`` cell is
    followed, which is where the step-up factories keep their ``require_ui`` gate; a hook closing
    over some other gate is not read as this one's."""
    code = getattr(call, "__code__", None)
    if code is None:
        return False
    cells: dict[str, object] = {}
    for var, cell in zip(code.co_freevars, getattr(call, "__closure__", None) or (), strict=True):
        try:
            cells[var] = cell.cell_contents
        except ValueError:  # an empty cell: a name the factory never bound
            continue
    if getattr(call, "__qualname__", "") == "require_ui.<locals>.dependency":
        return bool(cells.get("phi"))
    return "base" in cells and _gate_passes_phi(cells["base"])


def _route_passes_phi(dependant: Any) -> bool:
    """Whether any dependency of a route, at any depth, is a ``phi=True`` gate."""
    return any(
        _gate_passes_phi(dep.call) or _route_passes_phi(dep) for dep in dependant.dependencies
    )


def _mounted_ui_routes(engine: Engine, service: AuthService) -> list[tuple[str, str, bool, str]]:
    """Every mounted /ui route as ``(method, path, gate passes phi=True, endpoint module)``."""
    app = create_app(engine, auth=service, serve_ui=True)
    found = []
    for route in app.router.routes:
        if not (isinstance(route, APIRoute) and route.path.startswith("/ui")):
            continue
        phi = _route_passes_phi(route.dependant)
        for method in route.methods or ():
            found.append((method, route.path, phi, route.endpoint.__module__))
    return found


async def test_every_phi_gated_route_is_refused_over_an_unproven_hop(engine: Engine) -> None:
    """Derived from the LIVE route table: every /ui route whose gate passes ``phi=True``, wherever
    its path, 403s with the hop refusal over an unproven hop, and is not refused over a proven one.

    The refusal runs in the gate, before the route body, so a placeholder id reaches it as well as a
    real one; that is what lets a route nobody listed by hand be exercised. The ALLOW arm shows only
    that the hop refusal did not fire: a placeholder request then gets whatever the route answers
    next (at least a 404, a 422, a 303 to ``/ui/reauth`` or a same-origin 403), and serving the page
    is the seeded tests' job above. An ADMINISTRATOR holds every permission, so the permission loop,
    which runs before the hop guard, never answers in its place."""
    service = await _service(engine)
    await _add(service, "admin", Role.ADMINISTRATOR)
    gated = sorted(
        (method, path) for method, path, phi, _ in _mounted_ui_routes(engine, service) if phi
    )
    # The control: the walk found the routes it exists for, so an empty walk is not a pass.
    assert {("GET", p) for p in PHI_GET_ROUTES} <= set(gated), gated
    assert ("POST", EDIT_RESEND) in gated, gated
    for secure_hop in (False, True):
        async with _client(engine, service, secure_hop=secure_hop) as c:
            await _login(c, "admin")
            for method, path in gated:
                concrete = re.sub(r"\{[^}]+\}", "x1", path)
                r = await c.request(method, concrete, follow_redirects=False)
                refused = r.status_code == 403 and "PHI read refused" in r.text
                assert refused is not secure_hop, (secure_hop, method, path, r.status_code)


async def test_every_message_route_is_classified(engine: Engine) -> None:
    """Derived from the LIVE route table, so a route added later in scope cannot silently escape
    this file.

    In scope, and only these: every mounted ``/ui/messages*``, ``/ui/dead-letters*`` and ``/ui/uploaded-logs/file*``
    route, and every route the search module registers wherever its path. Each one whose gate passes
    ``phi=True`` is covered by the walk above; each other one must be in
    :data:`HANDLER_GUARDED_ROUTES` or named with a reason in :data:`NOT_PHI_READ_ROUTES`. A new one
    fails here until someone decides which it is."""
    service = await _service(engine)
    mounted = {
        (method, path): phi
        for method, path, phi, module in _mounted_ui_routes(engine, service)
        if path.startswith(("/ui/messages", "/ui/dead-letters", "/ui/uploaded-logs/file"))
        or module == "messagefoundry_webconsole.routes.search"
    }
    classified = set(HANDLER_GUARDED_ROUTES) | set(NOT_PHI_READ_ROUTES)
    # A classified route that gained a gate-level phi=True is reported as that, not as unmounted:
    # for a handler-guarded one it is the BACKLOG #1025 double charge.
    assert not [r for r in classified if mounted.get(r)], (
        f"classified, but now gated phi=True: {sorted(r for r in classified if mounted.get(r))}"
    )
    unguarded = {r for r, phi in mounted.items() if not phi}
    assert unguarded == classified, (
        f"unclassified (mounted, in neither set): {sorted(unguarded - classified)}\n"
        f"stale (classified, not mounted): {sorted(classified - unguarded)}"
    )
