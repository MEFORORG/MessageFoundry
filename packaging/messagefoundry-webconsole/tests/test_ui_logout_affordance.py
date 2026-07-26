# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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
from pathlib import Path

import httpx

import messagefoundry_webconsole
from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine
from messagefoundry_webconsole import pages

PW = "a-strong-test-passphrase"  # >=15, no app/vendor terms — satisfies the ASVS policy (WP-3)

LOGOUT_FORM = 'action="/ui/logout"'

#: The pages/*.py builders allowed to suppress the nav entirely: both are reached WITHOUT a session.
UNAUTHENTICATED_BARE_BUILDERS = frozenset({"login", "sso_challenge"})

_PAGES_DIR = Path(messagefoundry_webconsole.__file__).parent / "pages"


# --- the five authenticated pages that were bare --------------------------------------------------


def test_reauth_page_renders_sign_out() -> None:
    assert LOGOUT_FORM in pages.reauth("/ui/messages/1/replay", mfa_needed=False)


def test_reauth_continue_page_renders_sign_out() -> None:
    assert LOGOUT_FORM in pages.reauth_continue("/ui/messages/1/replay")


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
        pages.reauth("/ui/x", mfa_needed=False),
        pages.reauth_continue("/ui/x"),
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


async def _service(engine: Engine) -> AuthService:
    service = AuthService(engine.store, AuthSettings())
    await service.initialize()
    return service


async def test_must_change_session_can_see_and_use_sign_out(engine: Engine) -> None:
    """A must_change_password account is confined to /ui/account/password. The page now renders the
    Sign-out form, and POST /ui/logout — which has no Depends gate precisely so this works — really
    revokes the session."""
    service = await _service(engine)
    await service.create_local_user(
        username="rotate",
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.OPERATOR.value],
        actor="test",
    )
    transport = httpx.ASGITransport(app=create_app(engine, auth=service, serve_ui=True))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        login = await c.post("/ui/login", data={"username": "rotate", "password": PW})
        assert login.status_code == 303
        assert login.headers["location"] == "/ui/account/password"
        # every other /ui route bounces back here — the confinement the affordance had to survive
        assert (await c.get("/ui")).status_code == 303
        confined = await c.get("/ui/account/password")
        assert confined.status_code == 200
        assert LOGOUT_FORM in confined.text
        out = await c.post("/ui/logout")
        assert out.status_code == 303
        # the session is really gone: the change-password page now bounces to login
        assert (await c.get("/ui/account/password")).status_code in (302, 303, 401)
