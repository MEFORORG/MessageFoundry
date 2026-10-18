# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Browser ops dashboard (/ui, ADR 0065 / BACKLOG #75): serving, confined-cookie auth, headers, XSS,
the audited detail view, attachments, connection controls and message replay."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import httpx
import pytest
from _ui_clients import create_local_user_chosen
from _webui_support import (
    ADT,
    EDITED,
    PW,
    XSS_RAW,
    _add,
    _add_with_role_ids,
    _client,
    _cookie_login,
    _mint_action,
    _seed,
    _service,
)

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.pipeline import Engine
from messagefoundry_webconsole.pages.connections import UNPROVISIONED_NOTICE

# The repo root is three levels up from this file (packaging/messagefoundry-webconsole/tests/) — the
# suite moved out of the engine's tests/ into the package's own suite (Option B Phase 2, ADR 0065).
SAMPLES_CONFIG = Path(__file__).resolve().parents[3] / "samples" / "config"


# --- AC-1: off by default ----------------------------------------------------


async def test_ui_absent_when_disabled(engine: Engine) -> None:
    service = await _service(engine)
    async with _client(engine, service, serve_ui=False) as c:
        assert (await c.get("/ui")).status_code == 404
        assert (await c.get("/ui/login")).status_code == 404
        assert (await c.get("/ui/static/app.css")).status_code == 404
        # The JSON API is unaffected.
        assert (await c.get("/health")).status_code == 200


async def test_ui_present_when_enabled(engine: Engine) -> None:
    service = await _service(engine)
    async with _client(engine, service) as c:
        r = await c.get("/ui/login")
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]
        assert (await c.get("/ui/static/app.css")).status_code == 200
        assert (await c.get("/ui/static/app.js")).status_code == 200


# --- AC-2: the cookie is confined to /ui; the JSON API stays header-only ------


async def test_cookie_not_accepted_on_json_api(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        assert c.cookies.get("mf_session")  # the browser now holds the session cookie
        # ...but presenting ONLY that cookie to a JSON API route must be rejected (bearer header only).
        assert (await c.get("/connections")).status_code == 401
        assert (await c.get("/stats")).status_code == 401
        assert (await c.get("/messages")).status_code == 401


async def test_header_bearer_still_authorizes_json(engine: Engine) -> None:
    # Sanity: the native bearer path is untouched by the cookie mode.
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        token = (await c.post("/auth/login", json={"username": "op", "password": PW})).json()[
            "token"
        ]
        r = await c.get("/connections", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200


# --- AC-3: login sets a confined cookie; logout clears + revokes --------------


async def test_login_sets_confined_cookie_and_logout_revokes(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        r = await _cookie_login(c, "op")
        assert r.status_code == 303 and r.headers["location"] == "/ui"
        set_cookie = r.headers["set-cookie"].lower()
        assert "mf_session=" in set_cookie
        assert "httponly" in set_cookie
        assert "samesite=strict" in set_cookie
        assert "secure" not in set_cookie  # http request → Secure not set (scheme-gated)
        # The session works for /ui.
        assert (await c.get("/ui")).status_code == 200
        # Log out: cookie cleared AND the server-side session revoked.
        out = await c.post("/ui/logout")
        assert out.status_code == 303
        # After logout the (now-revoked) session no longer grants /ui — a fresh request redirects.
        c.cookies.clear()
        assert (await c.get("/ui")).status_code == 303  # → /ui/login


async def test_unprovisioned_operator_is_told_why_the_console_is_empty(engine: Engine) -> None:
    """BACKLOG #1152: the first-run affordance for the deny-by-default channel scope.

    A fresh non-administrator is granted no channel, so every list is legitimately empty for them.
    The landing page must SAY so — an unexplained empty console reads as broken RBAC on day one,
    and the reflex fix for that symptom is to widen somebody's grant. It is deliberately a page
    banner and not a start-time refusal, which would make a fresh single-operator install
    unbootable for the same condition: asserted here by the page answering 200."""
    service = await _service(engine)
    uid = await create_local_user_chosen(
        service,
        username="fresh",
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.OPERATOR.value],
        actor="test",
    )
    user = await service.store.get_user(uid)
    assert user is not None and user.password_hash is not None
    assert user.channel_scope is None  # nobody has granted anything: the shipped create path
    await service.store.set_password(
        uid, password_hash=user.password_hash, must_change_password=False, password_generated=False
    )
    async with _client(engine, service) as c:
        await _cookie_login(c, "fresh")
        r = await c.get("/ui")
        assert r.status_code == 200  # the console still loads; it explains itself
        assert UNPROVISIONED_NOTICE in r.text
        # Grant a channel and the notice goes away — the banner tracks the scope, not the emptiness
        # of the estate (this engine has no connections configured either way).
        await service.set_channel_scope(uid, ["IB_A"], actor="admin")
        await _cookie_login(c, "fresh")  # the scope change revoked the session
        granted = await c.get("/ui")
        assert granted.status_code == 200
        assert UNPROVISIONED_NOTICE not in granted.text


async def test_bad_credentials_redirect_without_cookie(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        r = await c.post("/ui/login", data={"username": "op", "password": "wrong-password-xyz"})
        assert r.status_code == 303 and r.headers["location"] == "/ui/login?e=bad"
        assert not c.cookies.get("mf_session")


async def test_unauthenticated_ui_redirects_to_login(engine: Engine) -> None:
    service = await _service(engine)
    async with _client(engine, service) as c:
        r = await c.get("/ui")
        assert r.status_code == 303 and r.headers["location"] == "/ui/login"


# --- AC-4: attacker-influenced HL7 is escaped --------------------------------


async def test_hostile_hl7_is_escaped(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    mid = await _seed(engine, raw=XSS_RAW, control_id="X1")
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        # /body: the bare detail page renders no body until the operator asks (BACKLOG #2346).
        r = await c.get(f"/ui/messages/{mid}/body")
        assert r.status_code == 200
        body = r.text
        assert "<script>alert(1)</script>" not in body  # never rendered as live markup
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body  # escaped instead


# --- AC-5: /ui security headers ----------------------------------------------


async def test_ui_security_headers(engine: Engine) -> None:
    service = await _service(engine)
    async with _client(engine, service) as c:
        r = await c.get("/ui/login")
        csp = r.headers["content-security-policy"]
        assert "script-src 'self'" in csp
        assert "unsafe-eval" not in csp and "unsafe-inline" not in csp
        assert "frame-ancestors 'none'" in csp
        assert r.headers["cache-control"] == "no-store"
        # The existing hardening still applies.
        assert r.headers["x-frame-options"] == "DENY"
        assert r.headers["x-content-type-options"] == "nosniff"


async def test_phi_json_reads_are_no_store(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    mid = await _seed(engine)
    async with _client(engine, service) as c:
        token = (await c.post("/auth/login", json={"username": "op", "password": PW})).json()[
            "token"
        ]
        r = await c.get(f"/messages/{mid}", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert r.headers["cache-control"] == "no-store"


# --- AC-7: the /ui detail view reuses the audited PHI path --------------------


async def test_ui_message_detail_audits_like_json(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    mid = await _seed(engine)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.get(f"/ui/messages/{mid}")
        assert r.status_code == 200
    audits = await engine.store.list_audit(limit=100)
    dumped = [dict(a) for a in audits]
    assert any(
        "message_view" in str(row.values())
        and mid in str(row.values())
        and "op" in str(row.values())
        for row in dumped
    ), "the /ui raw view must record the same message_view audit as GET /messages/{id}"


async def test_ui_body_reads_audit_as_console_body_views(engine: Engine) -> None:
    """BACKLOG #2345 and #2346: every page that shows the body reads it through the engine's audited
    body fetch tagged ``console``, and only a route that declares ``body`` does. The bare detail page
    opens the message and reads no body; ``/body`` (the "Show raw message" link), the parse tree, the
    editor and the edit POST's reject arm each read it once. The body really rendering on each of
    those is the control: a page that silently lost it would write no row and render no ``MSH``."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    mid = await _seed(engine)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")  # a fresh login counts as a recent step-up, for the editor
        await _mint_action(c, f"/ui/messages/{mid}/edit")  # vault BACKLOG #2625
        bare = await c.get(f"/ui/messages/{mid}")
        assert bare.status_code == 200 and "ADT^A01|MSG1" not in bare.text
        assert f'href="/ui/messages/{mid}/body"' in bare.text  # the act is offered, not taken
        page = await c.get(f"/ui/messages/{mid}/body")
        assert page.status_code == 200 and "ADT^A01|MSG1" in page.text
        tree = await c.get(f"/ui/messages/{mid}/parse-tree")
        assert tree.status_code == 200 and "PID" in tree.text
        editor = await c.get(f"/ui/messages/{mid}/edit")
        assert editor.status_code == 200 and "ADT^A01|MSG1" in editor.text
        # A direct send with no outbound named takes the reject arm before anything is sent.
        rejected = await c.post(
            f"/ui/messages/{mid}/edit-resend",
            data={"raw": EDITED, "idempotency_key": "k1", "mode": "direct", "to": ""},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        # DOE^JANE is in the stored body only, not in EDITED, so this is the pristine copy.
        assert rejected.status_code == 400 and "DOE^JANE" in rejected.text
    rows = [dict(a) for a in await engine.store.list_audit(limit=100)]
    body_views = [r for r in rows if r["action"] == "message_body_view"]
    assert [json.loads(r["detail"]) for r in body_views] == [
        {"message_id": mid, "surface": "console"}
    ] * 4
    assert all(r["actor"] == "op" for r in body_views)
    # Four opens: the bare page, /body, the editor and the reject arm open the message; the parse
    # tree shows no metadata and does not. This message has no summary, so even /body's declared
    # reveal unmasks nothing and records none; the summary test below covers a real reveal.
    opens = [json.loads(r["detail"]) for r in rows if r["action"] == "message_view"]
    assert [o["revealed"] for o in opens] == [[]] * 4


async def test_the_summary_is_revealed_only_by_a_route_that_declares_it(engine: Engine) -> None:
    """BACKLOG #2346, ASVS 14.2.6: the bare detail page is where the dead-letter "view" link, the
    replay redirect and a typed URL land, and none of those is an act aimed at the summary, so it
    shows the summary masked, exactly as the list does. ``/summary`` is where the list links from the
    masked summary, and it shows it complete. Both halves read the SAME stored value, so this cannot
    pass by the two pages carrying different data."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    stored = "MRN 100001 · DOE, JANE"
    masked = "MRN ****0001 · D**, J**"
    mid = await engine.store.enqueue_message(
        channel_id="ch1",
        raw=ADT,
        deliveries=[("archive", ADT)],
        control_id="MSG1",
        message_type="ADT^A01",
        source_type="file",
        summary=stored,
    )
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        listing = await c.get("/ui/messages")
        assert masked in listing.text and stored not in listing.text
        # The list links from the masked summary to the route that reveals it.
        assert f'href="/ui/messages/{mid}/summary"' in listing.text
        bare = await c.get(f"/ui/messages/{mid}")
        assert bare.status_code == 200
        assert masked in bare.text and stored not in bare.text
        assert f'href="/ui/messages/{mid}/summary"' in bare.text  # the Reveal link
        revealed = await c.get(f"/ui/messages/{mid}/summary")
        assert revealed.status_code == 200 and stored in revealed.text
        assert "ADT^A01|MSG1" not in revealed.text  # a summary reveal is not a body reveal
        # And the reveal did not become a status: the next bare open is masked again.
        again = await c.get(f"/ui/messages/{mid}")
        assert masked in again.text and stored not in again.text
        # "Show raw message" reveals the summary too: the summary is derived from the body.
        with_body = await c.get(f"/ui/messages/{mid}/body")
        assert stored in with_body.text and "ADT^A01|MSG1" in with_body.text
    # The audit says which open unmasked it: bare, /summary, bare, /body.
    opens = sorted(
        (dict(a)["id"], json.loads(dict(a)["detail"])["revealed"])
        for a in await engine.store.list_audit(limit=100)
        if dict(a)["action"] == "message_view"
    )
    assert [revealed for _id, revealed in opens] == [[], ["summary"], [], ["summary"]]


#: A distinctive delivery error. It stands in for a value the engine's scrubber missed, which is
#: the exposure BACKLOG #2436 masks.
_DELIVERY_ERROR = "partner rejected segment ZQX7"


async def _seed_dead_letter(engine: Engine) -> str:
    """One message whose only delivery is dead-lettered with :data:`_DELIVERY_ERROR`, which lands
    in the delivery's ``last_error`` and in the ``dead`` event's ``detail``."""
    mid = await _seed(engine)
    outbox = await engine.store.outbox_for(mid)
    await engine.store.dead_letter_now(outbox[0]["id"], _DELIVERY_ERROR)
    return mid


async def test_the_error_text_is_revealed_only_by_the_route_that_declares_it(
    engine: Engine,
) -> None:
    """BACKLOG #2436, ASVS 14.2.6, owner ruling R12: the detail page and the dead-letter list show
    each error-tier value masked on load, with a "Reveal" link to ``/errors``, and ``/errors`` shows
    it whole. The engine masks it in the response, so the page cannot carry it. Every half reads
    the SAME stored value, so this cannot pass by the pages carrying different data."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    mid = await _seed_dead_letter(engine)
    reveal = f'href="/ui/messages/{mid}/errors"'
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        bare = await c.get(f"/ui/messages/{mid}")
        assert bare.status_code == 200
        assert _DELIVERY_ERROR not in bare.text and "****" in bare.text
        assert reveal in bare.text
        dead = await c.get("/ui/dead-letters")
        assert dead.status_code == 200
        assert _DELIVERY_ERROR not in dead.text and reveal in dead.text
        revealed = await c.get(f"/ui/messages/{mid}/errors")
        assert revealed.status_code == 200
        # Twice: the delivery's last error and the dead event's detail.
        assert revealed.text.count(_DELIVERY_ERROR) == 2
        assert reveal not in revealed.text  # nothing left to reveal
        assert "ADT^A01|MSG1" not in revealed.text  # an error reveal is not a body reveal
        # And the reveal did not become a status: the next bare open is masked again.
        again = await c.get(f"/ui/messages/{mid}")
        assert _DELIVERY_ERROR not in again.text and reveal in again.text
        # A body reveal is aimed at the body, not at the delivery errors.
        with_body = await c.get(f"/ui/messages/{mid}/body")
        assert "ADT^A01|MSG1" in with_body.text and _DELIVERY_ERROR not in with_body.text
    # The audit says which open unmasked it: bare, /errors, bare, /body.
    opens = sorted(
        (dict(a)["id"], json.loads(dict(a)["detail"])["revealed"])
        for a in await engine.store.list_audit(limit=100)
        if dict(a)["action"] == "message_view"
    )
    assert [revealed for _id, revealed in opens] == [
        [],
        ["events.detail", "outbox.last_error"],
        [],
        [],
    ]


async def test_a_caller_without_view_summary_gets_no_error_text_and_no_reveal_link(
    engine: Engine,
) -> None:
    """The control for the mask: it only hides what permission allows. A Viewer holds
    ``messages:read`` and not ``messages:view_summary``, so the dead-letter list gives it null
    rather than a mask, and offers no reveal. It lacks ``messages:view_raw`` too, so the row's
    "view" link is gone as well (BACKLOG #2440) and the message id renders as plain text, which is
    the evidence the row rendered. The Operator on the same row is the positive control."""
    service = await _service(engine)
    await _add(service, "vw", Role.VIEWER)
    await _add(service, "op", Role.OPERATOR)
    mid = await _seed_dead_letter(engine)
    reveal = f'href="/ui/messages/{mid}/errors"'
    async with _client(engine, service) as c:
        await _cookie_login(c, "vw")
        dead = await c.get("/ui/dead-letters")
        assert dead.status_code == 200 and f"<td>{mid}</td>" in dead.text
        assert f'href="/ui/messages/{mid}"' not in dead.text
        assert _DELIVERY_ERROR not in dead.text and reveal not in dead.text
        assert "****" not in dead.text
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        dead = await c.get("/ui/dead-letters")
        assert reveal in dead.text and f'href="/ui/messages/{mid}"' in dead.text


async def test_a_view_summary_role_without_view_raw_sees_the_mask_and_no_reveal_link(
    engine: Engine,
) -> None:
    """BACKLOG #2440 limb (ii). A custom role holding ``messages:view_summary`` but not
    ``messages:view_raw`` gets the masked error on the dead-letter list, and the reveal route answers
    it 403, so the page must not offer a link to it. The Operator on the same row is the positive
    control that the link still renders for a caller the route will answer."""
    service = await _service(engine)
    role = await service.create_custom_role(
        display_name="Summary Reader",
        description=None,
        permissions=["messages:read", "messages:view_summary"],
        actor="test",
    )
    await _add_with_role_ids(service, "summ", [role.id])
    await _add(service, "op", Role.OPERATOR)
    mid = await _seed_dead_letter(engine)
    reveal = f'href="/ui/messages/{mid}/errors"'
    async with _client(engine, service) as c:
        await _cookie_login(c, "summ")
        dead = await c.get("/ui/dead-letters")
        assert dead.status_code == 200 and f"<td>{mid}</td>" in dead.text
        assert "****" in dead.text, "the role holds view_summary, so the error arrives masked"
        assert _DELIVERY_ERROR not in dead.text
        assert reveal not in dead.text
        assert f'href="/ui/messages/{mid}"' not in dead.text
        # Why both links must go: both routes refuse this role.
        assert (await c.get(f"/ui/messages/{mid}/errors")).status_code == 403
        assert (await c.get(f"/ui/messages/{mid}")).status_code == 403
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        dead = await c.get("/ui/dead-letters")
        assert "****" in dead.text and reveal in dead.text
        assert f'href="/ui/messages/{mid}"' in dead.text


async def test_the_replay_redirect_lands_on_a_page_that_reveals_nothing(engine: Engine) -> None:
    """BACKLOG #2346: a replay is not an act aimed at the summary or the body, so the page it
    redirects to reveals neither. The redirect target is asserted, not assumed."""
    service = await _service(engine)
    await _add(service, "boss", Role.ADMINISTRATOR)
    mid = await _seed(engine)
    async with _client(engine, service) as c:
        await _cookie_login(c, "boss")
        r = await c.post(
            f"/ui/messages/{mid}/replay",
            headers={"Sec-Fetch-Site": "same-origin"},
            follow_redirects=False,
        )
        assert r.status_code == 303 and r.headers["location"] == f"/ui/messages/{mid}"


#: The two console helpers allowed to call the engine's open and body fetch. Every other function in
#: ``messagefoundry_webconsole/routes/`` must go through them, so the reveal table decides.
_REVEAL_HELPERS = frozenset({"_open_message", "_message_body"})
_ENGINE_READS = frozenset({"get_message", "get_message_body"})


def _dotted(func: object) -> str:
    """``a.b.c`` for a call target, or ``""`` for anything that is not a plain name chain."""
    import ast

    parts: list[str] = []
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value
    if not isinstance(func, ast.Name):
        return ""
    parts.append(func.id)
    return ".".join(reversed(parts))


def _direct_engine_reads(source: str) -> list[str]:
    """Functions whose OWN body (not a nested function's) calls ``<...>.core.get_message`` or
    ``<...>.core.get_message_body``, other than the two helpers. Nested functions are reported
    under their own names, so the edit POST's ``_reject`` arm is checked, not hidden inside
    ``register``."""
    import ast

    found: list[str] = []

    def _own_calls(fn: ast.AST) -> list[str]:
        out: list[str] = []
        stack = list(ast.iter_child_nodes(fn))
        while stack:
            node = stack.pop()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                continue
            if isinstance(node, ast.Call):
                out.append(_dotted(node.func))
            stack.extend(ast.iter_child_nodes(node))
        return out

    for fn in ast.walk(ast.parse(source)):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if fn.name in _REVEAL_HELPERS:
            continue
        for name in _own_calls(fn):
            parts = name.split(".")
            if len(parts) >= 2 and parts[-2] == "core" and parts[-1] in _ENGINE_READS:
                found.append(f"{fn.name}: {name}")
    return found


def test_the_direct_engine_read_detector_fires() -> None:
    """The control for the scan below. A detector that finds nothing anywhere proves nothing, so it
    is shown to fire on the shapes it exists for, and to spare the helpers."""
    planted = """
async def handler():
    await core.get_message_body(mid, request)
async def other():
    async def _reject():
        await deps.core.get_message(mid, request)
    return _reject
async def _open_message():
    return await core.get_message(mid, request)
"""
    assert _direct_engine_reads(planted) == [
        "handler: core.get_message_body",
        "_reject: deps.core.get_message",
    ]


def test_every_ui_route_that_reads_a_body_or_opens_a_message_is_in_the_reveal_table() -> None:
    """The reveal table is the single statement of which /ui message routes show a body or a
    summary, and this checks the code against it from the syntax tree of every module in
    ``routes/``. At least these hold: no function but the two helpers calls the engine's open or
    body fetch directly, which would go around the table; every route handler that reaches
    ``_message_body`` or ``_open_message`` (directly, through a nested function, or through
    ``_detail_page``) has a row; one that reads the body outside the detail page declares ``body``;
    and every row names a mounted route. A route reaching the helpers through some new wrapper is
    not followed, so this is a floor, not a proof."""
    import ast
    import inspect
    import pkgutil

    import messagefoundry_webconsole.routes as routes_pkg
    from messagefoundry_webconsole.routes.core import UI_MESSAGE_REVEALS

    sources = [
        inspect.getsource(__import__(f"{routes_pkg.__name__}.{m.name}", fromlist=["_"]))
        for m in pkgutil.iter_modules(routes_pkg.__path__)
    ]
    assert len(sources) > 1, "the scan found one module or none: a broken instrument"
    direct = [hit for src in sources for hit in _direct_engine_reads(src)]
    assert direct == [], f"these call the engine's open or body fetch around the helpers: {direct}"

    readers: set[str] = set()
    openers: set[str] = set()
    for src in sources:
        for fn in ast.walk(ast.parse(src)):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            calls = {_dotted(n.func) for n in ast.walk(fn) if isinstance(n, ast.Call)}
            paths = [
                d.args[0].value
                for d in fn.decorator_list
                if isinstance(d, ast.Call)
                and _dotted(d.func).startswith("app.")
                and d.args
                and isinstance(d.args[0], ast.Constant)
                and isinstance(d.args[0].value, str)
            ]
            for path in paths:
                if calls & {"_message_body", "_detail_page"}:
                    readers.add(path)
                if calls & {"_open_message", "_detail_page"}:
                    openers.add(path)
    assert readers, "the scan found no body-reading route: a broken instrument, not a clean tree"
    assert (readers | openers) <= set(UI_MESSAGE_REVEALS), sorted(
        (readers | openers) - set(UI_MESSAGE_REVEALS)
    )
    # A reader that is not a detail route fetches the body unconditionally, so it must declare it.
    for path in readers - {
        "/ui/messages/{message_id}",
        "/ui/messages/{message_id}/summary",
        "/ui/messages/{message_id}/body",
        "/ui/messages/{message_id}/errors",
    }:
        assert "body" in UI_MESSAGE_REVEALS[path], path
    assert UI_MESSAGE_REVEALS["/ui/messages/{message_id}"] == frozenset()
    assert "summary" in UI_MESSAGE_REVEALS["/ui/messages/{message_id}/body"]
    # BACKLOG #2436: only /errors reveals the error text, and it reveals nothing else.
    assert [p for p, r in UI_MESSAGE_REVEALS.items() if "errors" in r] == [
        "/ui/messages/{message_id}/errors"
    ]
    assert UI_MESSAGE_REVEALS["/ui/messages/{message_id}/errors"] == frozenset({"errors"})
    mounted = {getattr(r, "path", "") for r in create_app(serve_ui=True).routes}
    assert set(UI_MESSAGE_REVEALS) <= mounted, sorted(set(UI_MESSAGE_REVEALS) - mounted)


async def test_a_route_that_does_not_declare_body_cannot_fetch_one(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fail closed: the console refuses to fetch a body for a route whose row lacks ``body``. Shown
    by emptying the parse tree's own row, because that handler fetches the body unconditionally: the
    same request that renders the tree in the test above now errors and writes no
    ``message_body_view`` row. The raise is expected, so the transport is told not to re-raise it."""
    import messagefoundry_webconsole.routes.core as core_routes

    patched = dict(core_routes.UI_MESSAGE_REVEALS)
    patched["/ui/messages/{message_id}/parse-tree"] = frozenset()
    monkeypatch.setattr(core_routes, "UI_MESSAGE_REVEALS", patched)
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    mid = await _seed(engine)
    app = create_app(engine, auth=service, serve_ui=True, webauthn_rp_from_request=True)
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        await _cookie_login(c, "op")
        r = await c.get(f"/ui/messages/{mid}/parse-tree")
        assert r.status_code == 500 and "PID" not in r.text
    actions = [dict(a)["action"] for a in await engine.store.list_audit(limit=100)]
    assert "message_body_view" not in actions


async def test_the_json_body_fetch_refuses_a_forged_console_surface(engine: Engine) -> None:
    """BACKLOG #2345: ``console`` in the audit row means the web console's in-process call, and the
    engine writes it itself. The query parameter does not accept it, so an HTTP caller claiming it
    is refused before any body is read, and no row is written. The ``harness`` request on the same
    client is the control: the route serves an honest caller."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    mid = await _seed(engine)
    async with _client(engine, service) as c:
        token = (await c.post("/auth/login", json={"username": "op", "password": PW})).json()[
            "token"
        ]
        headers = {"Authorization": f"Bearer {token}"}
        forged = await c.get(f"/messages/{mid}/raw?surface=console", headers=headers)
        assert forged.status_code == 422 and "MSH|" not in forged.text
        honest = await c.get(f"/messages/{mid}/raw?surface=harness", headers=headers)
        assert honest.status_code == 200 and honest.json()["raw"] == ADT
    body_views = [
        json.loads(dict(a)["detail"])["surface"]
        for a in await engine.store.list_audit(limit=100)
        if dict(a)["action"] == "message_body_view"
    ]
    assert body_views == ["harness"]


# --- #149 Phase 3b: the attachments panel + audited /ui download --------------

_DOC = b"%PDF-1.4\nsynthetic webconsole document \x00\x01 not real PHI\n%%EOF\n"
_DOC_B64 = base64.b64encode(_DOC).decode("ascii")


async def _seed_streaming(engine: Engine, *, channel_id: str = "ch1") -> tuple[str, str]:
    ref = await engine.store.put_attachment([_DOC_B64], "application/pdf")
    mid = await engine.store.enqueue_ingress(
        channel_id=channel_id, raw=ADT, control_id="MSG1", attachment_refs=[ref]
    )
    return mid, ref


def test_message_detail_renders_attachments_panel() -> None:
    # Pure page render: a MessageDetail carrying an attachment shows the panel + a download link; a
    # message with none shows no panel (no import of the engine store needed).
    from messagefoundry.api.models import AttachmentInfo, MessageDetail
    from messagefoundry_webconsole.pages import message_detail

    ref = "a" * 64
    detail = MessageDetail(
        id="m1",
        channel_id="ch1",
        received_at=0.0,
        source_type="file",
        control_id="MSG1",
        message_type="ADT^A01",
        status="processed",
        error=None,
        outbox=[],
        events=[],
        attachments=[AttachmentInfo(id=ref, content_type="application/pdf", total_bytes=2048)],
    )
    html = str(message_detail(detail, "MSH|skel", summary_revealed=True, errors_revealed=True))
    assert "Attachments" in html
    assert "application/pdf" in html
    assert f"/ui/messages/m1/attachments/{ref}" in html  # the download link
    assert "2.0 KiB" in html  # human size

    empty = detail.model_copy(update={"attachments": []})
    assert "Attachments" not in str(
        message_detail(empty, "MSH|skel", summary_revealed=True, errors_revealed=True)
    )


async def test_ui_attachment_download_round_trips_and_audits(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    mid, ref = await _seed_streaming(engine)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        # The detail page shows the panel + link.
        page = await c.get(f"/ui/messages/{mid}")
        assert page.status_code == 200
        assert f"/ui/messages/{mid}/attachments/{ref}" in page.text
        # The download reuses the engine's audited path (session cookie carries the auth, not a bearer).
        r = await c.get(f"/ui/messages/{mid}/attachments/{ref}")
        assert r.status_code == 200
        assert r.content == _DOC  # byte-for-byte round-trip
        assert r.headers["content-disposition"].startswith("attachment; filename=")
    assert any(a["action"] == "attachment_download" for a in await engine.store.list_audit())


async def test_ui_attachment_download_requires_view_raw(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "vw", Role.VIEWER)  # no view_raw
    mid, ref = await _seed_streaming(engine)
    async with _client(engine, service) as c:
        await _cookie_login(c, "vw")
        r = await c.get(f"/ui/messages/{mid}/attachments/{ref}")
        assert r.status_code == 403


# --- AC-6: off-loopback /ui requires TLS, even under --allow-insecure-bind ----


def test_serve_ui_offloopback_requires_tls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from messagefoundry.__main__ import main
    from messagefoundry.store.crypto import generate_key

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    # The /ui exposure gate is the subject, so the gates AHEAD of it are stood down by name. This
    # said `handles_real_patient_data = false` until BACKLOG #1279 retired it; the key is refused
    # at load now, which made this test refuse for the wrong reason while still exiting 2.
    #
    # The four lines are inlined rather than imported from `tests/_phi_gate_provisions.py`: this is a
    # SEPARATE distributable package and nothing here imports from the engine repo's test tree. That
    # constant's docstring is the explanation of what each line gives up.
    (tmp_path / "messagefoundry.toml").write_text(
        'security.enforcement = "warn"\n'
        "security.block_unlisted_outbound = true\n"
        "alerts.security_notifications_required = false\n"
        'security.local_access_only = false\nsecurity.listen_address = "0.0.0.0"\n'
        "security.serve_web_console = true\n",
        encoding="utf-8",
    )
    # --allow-insecure-bind clears the JSON-API cleartext gate, but the stricter /ui gate still refuses.
    rc = main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "dev", "--allow-insecure-bind"])
    assert rc == 2
    assert "browser ops dashboard" in capsys.readouterr().err


# --- M2: connection controls (writes) — CSRF + permission + confinement ------


async def test_control_rejects_cross_site_post(engine: Engine) -> None:
    # An authenticated operator POST carrying a cross-site Sec-Fetch-Site is refused (CSRF defense-in-
    # depth). require_ui passes (valid cookie + CONNECTIONS_CONTROL), so this isolates assert_same_origin.
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.post("/ui/connections/anything/stop", headers={"Sec-Fetch-Site": "cross-site"})
        assert r.status_code == 403


async def test_control_requires_control_permission(engine: Engine) -> None:
    # A VIEWER (no connections:control) is refused even same-origin — require_ui enforces the permission
    # the direct handler call would otherwise skip.
    service = await _service(engine)
    await _add(service, "viewer", Role.VIEWER)
    async with _client(engine, service) as c:
        await _cookie_login(c, "viewer")
        r = await c.post("/ui/connections/anything/stop", headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code == 403


async def test_control_cookie_not_accepted_on_json_route(engine: Engine) -> None:
    # Confinement extends to the write routes: the JSON control route with only the cookie still 401s.
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        assert (await c.post("/connections/anything/stop")).status_code == 401


async def test_control_same_origin_reaches_handler(engine: Engine) -> None:
    # A same-origin operator POST passes auth + CSRF and reaches the control handler (which then errors
    # on the unknown connection) — proving the gate lets a legitimate request through (not 401/403).
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.post(
            "/ui/connections/no-such-conn/stop", headers={"Sec-Fetch-Site": "same-origin"}
        )
        assert r.status_code not in (401, 403)


# --- M2b: message replay (step-up) + the browser re-auth flow -----------------


async def test_replay_rejects_cross_site_post(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    mid = await _seed(engine)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.post(f"/ui/messages/{mid}/replay", headers={"Sec-Fetch-Site": "cross-site"})
        assert r.status_code == 403


async def test_replay_requires_replay_permission(engine: Engine) -> None:
    # A viewer (no messages:replay) is refused before any step-up/CSRF logic.
    service = await _service(engine)
    await _add(service, "viewer", Role.VIEWER)
    mid = await _seed(engine)
    async with _client(engine, service) as c:
        await _cookie_login(c, "viewer")
        r = await c.post(f"/ui/messages/{mid}/replay", headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code == 403


async def test_replay_cookie_not_accepted_on_json_route(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    mid = await _seed(engine)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        assert (await c.post(f"/messages/{mid}/replay")).status_code == 401


async def test_replay_after_login_stepup_reaches_handler(engine: Engine) -> None:
    # A fresh login counts as a recent step-up, so replay is NOT bounced to /ui/reauth — it reaches the
    # replay handler (proving require_ui_step_up passes for a just-authenticated operator).
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    mid = await _seed(engine)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.post(f"/ui/messages/{mid}/replay", headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code not in (401, 403)
        assert "reauth" not in r.headers.get("location", "")


async def test_reauth_rejects_unsafe_next(engine: Engine) -> None:
    # The `next` param the re-auth flow auto-retries MUST be a /ui replay action — never an arbitrary
    # URL (anti open-redirect / anti open-POST gadget). Rejected values bounce to /ui, not to the target.
    service = await _service(engine)
    async with _client(engine, service) as c:
        # "/ui/audit" stands for an unregistered /ui page. This used "/ui/messages" until vault
        # BACKLOG #2620 registered the PHI pages as unlock continuations.
        # The backslash, whitespace and encoded forms are what a browser, or a decoding router, takes
        # off-origin (vault BACKLOG #2790); the anchored registry must refuse them like "//".
        for bad in (
            "https://evil.example/x",
            "//evil.example",
            "/\\evil.example",
            "\\\\evil.example",
            " //evil.example",
            "/\t/evil.example",
            "/%2F%2Fevil.example",
            "/ui\\..\\..\\evil.example",
            "/ui/audit",
            "/etc/passwd",
        ):
            r = await c.get("/ui/reauth", params={"next": bad})
            assert r.status_code == 303 and r.headers["location"] == "/ui"


async def test_reauth_form_renders_for_safe_next(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.get("/ui/reauth", params={"next": "/ui/messages/abc123/replay"})
        assert r.status_code == 200
        assert 'name="password"' in r.text
        assert 'name="next"' in r.text


async def test_reauth_rejects_cross_site_post(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.post(
            "/ui/reauth",
            data={"next": "/ui/messages/abc/replay", "password": PW},
            headers={"Sec-Fetch-Site": "cross-site"},
        )
        assert r.status_code == 403
