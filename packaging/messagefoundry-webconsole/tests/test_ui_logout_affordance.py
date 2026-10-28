# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ASVS 7.4.4 — a visible, one-click sign-out on EVERY authenticated /ui page.

The full chrome (``_default_nav``) always rendered one. Five authenticated pages dropped the nav for
focus/confinement and so rendered none: the step-up re-auth form, reauth-continue, the forced
must-change-password page, passkey enrolment, and the federated (OIDC) landing hop. They now render
``minimal_nav()`` — wordmark + the same POST /ui/logout form.

Three layers, because pinning the five fixed pages cannot catch a SIXTH bare page written later:

* per-builder render assertions on all five, plus the inverse on the two pages that must STAY bare
  (they are unauthenticated, so a sign-out control there would be meaningless);
* a static **builder enumeration** over ``messagefoundry_webconsole/pages/*.py`` — ``page()`` is
  defined once, imported unaliased by every pages module and called nowhere else, so asserting that
  every ``page(...)`` call passing ``nav=`` either passes ``minimal_nav()`` or belongs to the
  unauthenticated allow-list is a COMPLETE guard; and
* an end-to-end confinement test: a must-change-password account, which every other ``/ui`` route
  303s back to the change-password page, can now see and use Sign out.
"""

from __future__ import annotations

import ast
import time
from pathlib import Path

import httpx
import pytest
from _ui_clients import create_local_user_chosen

import messagefoundry_webconsole
from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.service import _LOGOUT_LINEAGE_SECONDS, AuthService
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine
from messagefoundry_webconsole import pages
from tests._logout_rows import logout_details, logout_rows

PW = "a-strong-test-passphrase"  # >=15, no app/vendor terms — satisfies the ASVS policy (WP-3)

LOGOUT_FORM = 'action="/ui/logout"'

#: The pages/*.py builders allowed to suppress the nav entirely: both are reached WITHOUT a session.
UNAUTHENTICATED_BARE_BUILDERS = frozenset({"login", "sso_challenge"})

_PAGES_DIR = Path(messagefoundry_webconsole.__file__).parent / "pages"


# --- the five authenticated pages that were bare --------------------------------------------------


def test_reauth_page_renders_sign_out() -> None:
    assert LOGOUT_FORM in pages.reauth(
        "/ui/messages/1/replay", label="Replay a message", continues=True, mfa_needed=False
    )


def test_reauth_continue_page_renders_sign_out() -> None:
    assert LOGOUT_FORM in pages.reauth_continue("/ui/messages/1/replay", "Replay a message")


def test_forced_password_page_renders_sign_out() -> None:
    """The severe case: require_ui 303s a must_change_password session back here from every other
    /ui route, so without this the operator had no reachable sign-out at all."""
    assert LOGOUT_FORM in pages.password_page(forced=True)


def test_normal_password_page_still_carries_the_full_nav() -> None:
    """The non-confined branch of the same builder is untouched — it keeps the full chrome (and its
    'My account' back-link), so the edit landed on the ``forced`` branch only."""
    normal = pages.password_page(forced=False)
    assert LOGOUT_FORM in normal
    assert 'href="/ui/account"' in normal
    assert "navstatus" in normal  # full chrome => the live status glyphs are present


def test_webauthn_enroll_page_renders_sign_out() -> None:
    assert LOGOUT_FORM in pages.webauthn_enroll_page("{}")


def test_oidc_landing_page_renders_sign_out() -> None:
    """The federated landing hop is authenticated: GET /ui/oidc/callback returns this document AND
    sets the session cookie on that same response, so the browser is signed in as of this page."""
    landing = pages.oidc_landing()
    assert LOGOUT_FORM in landing
    assert 'http-equiv="refresh"' in landing  # the hop itself is unchanged


def test_minimal_nav_omits_the_permission_gated_status_poll() -> None:
    """minimal_nav carries NO ``data-mf-nav-status`` container: that hook makes app.js poll
    GET /ui/nav-status (~15s), which needs monitoring:read — on a reauth / must-change / passkey page
    that poll would 303-loop to the login or change-password page."""
    for markup in (
        pages.reauth("/ui/x", label="Do x", continues=True, mfa_needed=False),
        pages.reauth_continue("/ui/x", "Do x"),
        pages.password_page(forced=True),
        pages.webauthn_enroll_page("{}"),
        pages.oidc_landing(),
    ):
        assert "data-mf-nav-status" not in markup
        assert "navmenu" not in markup  # no nav groups either — confinement intent preserved


# --- the inverse: the unauthenticated pages must STAY bare ----------------------------------------


def test_unauthenticated_pages_render_no_sign_out() -> None:
    assert LOGOUT_FORM not in pages.login()
    assert LOGOUT_FORM not in pages.sso_challenge()


# --- builder enumeration: a NEW bare authenticated page fails here --------------------------------


def _page_calls_with_nav(tree: ast.AST) -> list[tuple[str, ast.Call]]:
    """Every ``page(...)`` call passing an explicit ``nav=``, paired with the top-level builder it
    sits in. Module-level calls are attributed to ``"<module>"`` so they cannot slip through."""
    found: list[tuple[str, ast.Call]] = []
    assert isinstance(tree, ast.Module)
    for top in tree.body:
        owner = top.name if isinstance(top, (ast.FunctionDef, ast.AsyncFunctionDef)) else "<module>"
        for node in ast.walk(top):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "page"
                and any(kw.arg == "nav" for kw in node.keywords)
            ):
                found.append((owner, node))
    return found


def _is_minimal_nav_call(node: ast.expr) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "minimal_nav"
    )


def test_every_nav_suppressing_page_builder_is_accounted_for() -> None:
    """A page builder may only suppress the shared chrome by passing ``nav=minimal_nav()`` (which
    still renders Sign out) unless it is one of the two UNAUTHENTICATED entry pages. Writing a new
    ``nav=Markup("")`` page fails here — which pinning the five fixed pages could never do."""
    offenders: list[str] = []
    seen_builders: set[str] = set()
    for path in sorted(_PAGES_DIR.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for owner, call in _page_calls_with_nav(tree):
            seen_builders.add(owner)
            nav = next(kw.value for kw in call.keywords if kw.arg == "nav")
            if _is_minimal_nav_call(nav) or owner in UNAUTHENTICATED_BARE_BUILDERS:
                continue
            offenders.append(f"{path.name}:{call.lineno} in {owner}()")
    # The walk must still be finding the known sites — a silently-empty walk would "pass" forever.
    assert seen_builders >= {
        "login",
        "sso_challenge",
        "oidc_landing",
        "reauth",
        "reauth_continue",
        "password_page",
        "webauthn_enroll_page",
    }, seen_builders
    assert not offenders, (
        "these page builders suppress the shared chrome without rendering a sign-out control; "
        f"pass nav=minimal_nav() instead (ASVS 7.4.4): {offenders}"
    )


# --- end-to-end: the confined must-change session can actually sign out ---------------------------


#: Non-loopback peers, pinned so an assertion on the audited ``client`` compares a value this file
#: chose rather than a transport default. The sign-in comes from a different address than the
#: sign-out, so the row cannot pass by recording the address the session was minted from.
LOGIN_PEER = ("198.51.100.10", 40000)
PEER_ADDRESS = "198.51.100.23"


async def _service(engine: Engine) -> AuthService:
    service = AuthService(engine.store, AuthSettings())
    await service.initialize()
    return service


async def test_must_change_session_can_see_and_use_sign_out(engine: Engine) -> None:
    """A must_change_password account is confined to /ui/account/password. The page now renders the
    Sign-out form, and POST /ui/logout — which has no Depends gate precisely so this works — really
    revokes the session."""
    # require_mfa off: under it a no-factor account enrols before it rotates (ADR 0197 Amendment
    # A) and lands on /ui/account instead. The rotate-first confinement is what this test is about.
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    await create_local_user_chosen(
        service,
        username="rotate",
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.OPERATOR.value],
        actor="test",
    )
    app = create_app(engine, auth=service, serve_ui=True)
    transport = httpx.ASGITransport(app=app, client=LOGIN_PEER)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        login = await c.post("/ui/login", data={"username": "rotate", "password": PW})
        assert login.status_code == 303
        assert login.headers["location"] == "/ui/account/password"
        # every other /ui route bounces back here — the confinement the affordance had to survive
        assert (await c.get("/ui")).status_code == 303
        confined = await c.get("/ui/account/password")
        assert confined.status_code == 200
        assert LOGOUT_FORM in confined.text
        # BACKLOG #3339: the same session signs out from another address.
        elsewhere = httpx.ASGITransport(app=app, client=(PEER_ADDRESS, 51234))
        async with httpx.AsyncClient(transport=elsewhere, base_url="http://t") as away:
            away.cookies.set("mf_session", str(c.cookies.get("mf_session")))
            out = await away.post("/ui/logout")
        assert out.status_code == 303
        # the session is really gone: the change-password page now bounces to login
        assert (await c.get("/ui/account/password")).status_code in (302, 303, 401)
    # BACKLOG #3029: the route passes no actor, so the auth.logout row names the owner of the
    # session it ended rather than carrying a NULL actor. BACKLOG #3339: it also records the
    # address the sign-out came from.
    assert await logout_rows(engine.store) == [("rotate", PEER_ADDRESS, "revoked")]


async def test_ui_logout_with_a_cookie_naming_no_session_still_records_the_address(
    engine: Engine,
) -> None:
    """BACKLOG #3339, the control. A cookie that names no session ends nothing, so the row has no
    owner to name and says ``nothing_to_revoke``; the client address is still recorded. Read beside
    the test above, it shows the actor there comes from the session, not from the request.

    Such rows are bounded per client address (BACKLOG #3749 item 6); one is well inside the
    budget, which ``tests/test_session_supersession.py`` drives."""
    service = await _service(engine)
    out = await _sign_out_with(engine, service, "a-token-that-names-no-session")
    assert out.status_code == 303
    assert await logout_rows(engine.store) == [(None, PEER_ADDRESS, "nothing_to_revoke")]


async def _signed_in_operator(engine: Engine) -> tuple[AuthService, str]:
    """A service with one operator, and a console session cookie for it, minted from LOGIN_PEER."""
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
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
    user = await engine.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await engine.store.set_password(
        user_id,
        password_hash=user.password_hash,
        must_change_password=False,
        password_generated=False,
    )
    outcome = await service.login("op", PW)
    assert outcome.ok and outcome.token is not None
    return service, outcome.token


async def _sign_out_with(engine: Engine, service: AuthService, cookie: str) -> httpx.Response:
    transport = httpx.ASGITransport(
        app=create_app(engine, auth=service, serve_ui=True), client=(PEER_ADDRESS, 51234)
    )
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        c.cookies.set("mf_session", cookie)
        return await c.post("/ui/logout")


async def test_ui_logout_with_a_cookie_an_elevation_just_retired_ends_its_successor(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #3715, #3749 item 3. An elevation in another tab re-keys the session while this
    tab's sign-out is in flight, so the cookie it sends names no session. Within 5 seconds of
    the elevation the sign-out follows the link, ends the session under its new token, and the
    row names the owner, where it used to keep a NULL actor and leave the session live. The clock
    is set 2 seconds inside the bound, so a slow runner has that much room."""
    service, old = await _signed_in_operator(engine)
    successor = await service._rotate_session_token(old)
    assert successor is not None, "the rotation failed closed, so the race was not driven"
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + _LOGOUT_LINEAGE_SECONDS - 2.0)
    out = await _sign_out_with(engine, service, old)
    assert out.status_code == 303
    assert await service.identity_for_token(successor, activity=False) is None
    assert await logout_rows(engine.store) == [("op", PEER_ADDRESS, "revoked")]
    assert await logout_details(engine.store) == [
        {
            "outcome": "revoked",
            "session": hash_token(successor)[:12],
            "presented": hash_token(old)[:12],
        }
    ]


async def test_ui_logout_with_a_cookie_retired_past_the_window_ends_nothing(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control for the test above, one second past the 5-second window. This route carries no
    credential, so a retired cookie leads nowhere after that: nothing is revoked, the row says
    ``nothing_to_revoke`` and has no owner to name."""
    service, old = await _signed_in_operator(engine)
    successor = await service._rotate_session_token(old)
    assert successor is not None
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + _LOGOUT_LINEAGE_SECONDS + 1.0)
    out = await _sign_out_with(engine, service, old)
    assert out.status_code == 303
    assert await service.identity_for_token(successor, activity=False) is not None
    assert await logout_rows(engine.store) == [(None, PEER_ADDRESS, "nothing_to_revoke")]


async def test_ui_logout_clears_the_cookie_when_the_row_fails_after_the_revoke(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #3884 item 1. Once the session ended, a refused ``auth.logout`` row used to raise
    through the route, which answered 500 and never cleared the cookie or sent Clear-Site-Data.
    The sign-out has happened, so the route must still finish it."""
    service, token = await _signed_in_operator(engine)
    real_record = engine.store.record_audit

    async def _refuse_logout_row(action: str, **kwargs: object) -> object:
        if action == "auth.logout":
            raise OSError("the audit store refused the row")
        return await real_record(action, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(engine.store, "record_audit", _refuse_logout_row)
    out = await _sign_out_with(engine, service, token)
    assert out.status_code == 303
    assert "clear-site-data" in out.headers
    assert any(
        "mf_session=" in header and "max-age=0" in header.lower()
        for header in out.headers.get_list("set-cookie")
    ), out.headers.get_list("set-cookie")
    assert await service.identity_for_token(token, activity=False) is None
