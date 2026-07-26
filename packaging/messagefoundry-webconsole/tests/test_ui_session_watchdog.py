# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ASVS 14.3.1 — a session that ends must not leave PHI rendered in the tab.

Explicit logout already revoked server-side and deleted the cookie, but nothing emitted
``Clear-Site-Data`` and nothing on the client ever noticed a session ending by idle or absolute
timeout, so the rendered page (and its bfcache copy) survived the session indefinitely.

Four mechanisms are pinned here:

* **The idle clock is real again.** Every navved page — including every PHI page — polls
  ``/ui/nav-status`` every ~15s, and that poll used to refresh ``last_used_at``. An abandoned tab
  therefore never idled out at all, which defeated automatic logoff and would ALSO have neutered a
  server-anchored watchdog (its anchor would be refreshed every 15s forever). The timer-driven
  background routes now validate with ``activity=False``.
* **The watchdog's heartbeat**, ``GET /ui/session-status``: reachable only with a live session, itself
  non-activity, and reporting the absolute deadline as REMAINING SECONDS read from the session record.
* **``Clear-Site-Data: "cache"``** on EVERY response that ends a session's browser-visible life: the
  logout 303, the change-password 303 (which revokes every session for the user), every server-driven
  expiry/revoke redirect, and the post-termination login render. Cookie deletion and the header are
  fused in one helper so a termination route cannot write one without the other.
* **The client contract** in ``app.js``: blank the document BEFORE navigating, anchor to server
  interaction and never to DOM activity, and surface the auth redirect instead of following it — on
  every fetch, not only the watchdog's own probe.
"""

from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace

import httpx
from starlette.requests import Request as StarletteRequest
from starlette.responses import Response as StarletteResponse

import messagefoundry_webconsole
from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine
from messagefoundry_webconsole import pages
from messagefoundry_webconsole._auth import clear_session_cookie
from messagefoundry_webconsole.routes.core import _CLEAR_SITE_DATA_LOGIN_CODES

PW = "a-strong-test-passphrase"  # >=15, no app/vendor terms — satisfies the ASVS policy (WP-3)

_APP_JS = Path(messagefoundry_webconsole.__file__).parent / "static/app.js"


async def _service(engine: Engine) -> AuthService:
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    return service


def _client(engine: Engine, service: AuthService) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=create_app(engine, auth=service, serve_ui=True))
    return httpx.AsyncClient(transport=transport, base_url="http://t")


async def _add(service: AuthService, username: str, *roles: Role) -> None:
    user_id = await service.create_local_user(
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=[r.value for r in roles],
        actor="test",
    )
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id, password_hash=user.password_hash, must_change_password=False
    )


async def _session_last_used(service: AuthService, user_id: str) -> float:
    sessions = await service.list_sessions(user_id)
    assert len(sessions) == 1, sessions
    return sessions[0].last_used_at


# --- the precondition: background polls must not slide the idle clock -----------------------------


async def test_background_polls_do_not_refresh_the_idle_clock(engine: Engine) -> None:
    """The defect this cell rests on. The nav-status / live-connections / live-flow polls are
    TIMER-driven, not user activity: if they refresh ``last_used_at``, an abandoned tab showing PHI
    never idles out on the server, and a client watchdog anchored to server interaction would be
    reset every 15s and could never fire."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        assert (
            await c.post("/ui/login", data={"username": "op", "password": PW})
        ).status_code == 303
        user = await service.store.get_user_by_username("op")
        assert user is not None
        before = await _session_last_used(service, user.id)
        for path in ("/ui/nav-status", "/ui/connections", "/ui/monitoring/live"):
            assert (await c.get(path)).status_code == 200, path
        assert (await c.get("/ui/session-status")).status_code == 200
        assert await _session_last_used(service, user.id) == before


async def test_a_real_navigation_still_refreshes_the_idle_clock(engine: Engine) -> None:
    """The inverse, so the fix is a scalpel and not a blanket: an operator actually loading a page IS
    user activity and must keep the session alive."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        assert (
            await c.post("/ui/login", data={"username": "op", "password": PW})
        ).status_code == 303
        user = await service.store.get_user_by_username("op")
        assert user is not None
        # rewind the stored clock so a refresh is unambiguously observable
        sessions = await service.list_sessions(user.id)
        rewound = sessions[0].last_used_at - 600
        await engine.store.touch_session(sessions[0].token_hash, now=rewound)
        assert await _session_last_used(service, user.id) == rewound
        assert (await c.get("/ui")).status_code == 200
        assert await _session_last_used(service, user.id) > rewound


# --- the watchdog heartbeat -----------------------------------------------------------------------


async def test_session_status_reports_remaining_seconds(engine: Engine) -> None:
    """Remaining SECONDS, not a wall-clock the client would have to trust — and taken from the session
    RECORD, so a federated session capped below ``session_absolute_hours`` is respected."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        assert (
            await c.post("/ui/login", data={"username": "op", "password": PW})
        ).status_code == 303
        r = await c.get("/ui/session-status")
        assert r.status_code == 200
        remaining = r.json()["expires_secs"]
        user = await service.store.get_user_by_username("op")
        assert user is not None
        record = (await service.list_sessions(user.id))[0]
        # matches the record's own deadline (to the second), and is a duration, not an epoch
        assert isinstance(remaining, int)
        assert 0 < remaining <= AuthSettings().session_absolute_hours * 3600
        assert abs(remaining - (record.expires_at - record.created_at)) <= 5


async def test_session_status_redirects_once_the_session_is_gone(engine: Engine) -> None:
    """Reaching the probe AT ALL is the liveness verdict: once the session is revoked the server 303s
    to the login page, which the client (fetching with redirect:"manual") reads as termination."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        assert (
            await c.post("/ui/login", data={"username": "op", "password": PW})
        ).status_code == 303
        assert (await c.get("/ui/session-status")).status_code == 200
        await c.post("/ui/logout")
        gone = await c.get("/ui/session-status", follow_redirects=False)
        assert gone.status_code == 303
        assert gone.headers["location"] == "/ui/login"


async def test_session_status_is_reachable_by_a_confined_must_change_session(
    engine: Engine,
) -> None:
    """The must-change page is authenticated and renders chrome, so its watchdog must work: the probe
    allows the confined session instead of 303ing it into a change-password loop."""
    service = await _service(engine)
    await service.create_local_user(
        username="rotate",
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.OPERATOR.value],
        actor="test",
    )
    async with _client(engine, service) as c:
        assert (
            await c.post("/ui/login", data={"username": "rotate", "password": PW})
        ).status_code == 303
        assert (await c.get("/ui/session-status")).status_code == 200


# --- Clear-Site-Data --------------------------------------------------------------------------------


async def test_logout_emits_clear_site_data_cache_only(engine: Engine) -> None:
    """ "cache" only: "cookies" is already covered by the explicit cookie deletion, and "storage"
    would wipe the deliberately-persistent, PHI-free mfcols:v2 column preferences (14.3.3)."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        assert (
            await c.post("/ui/login", data={"username": "op", "password": PW})
        ).status_code == 303
        out = await c.post("/ui/logout")
        assert out.status_code == 303
        assert out.headers["clear-site-data"] == '"cache"'
        assert "storage" not in out.headers["clear-site-data"]


async def test_expired_login_render_emits_clear_site_data(engine: Engine) -> None:
    """The watchdog's landing page is a post-termination render, so it carries the header too — the
    watchdog navigates there when it can no longer confirm the session, possibly without ever having
    reached the logout route."""
    service = await _service(engine)
    async with _client(engine, service) as c:
        expired = await c.get("/ui/login?e=expired")
        assert expired.status_code == 200
        assert expired.headers["clear-site-data"] == '"cache"'
        assert "Your session ended" in expired.text
    # an ordinary FIRST VISIT — no session cookie at all — is not a termination and must not carry
    # it. Scoped to a fresh client on purpose: the same URL requested WITH a dead session cookie IS
    # a post-termination landing and must carry the header (see the two tests below), so asserting
    # its absence on a cookie-bearing client would pin the very gap this cell is about.
    async with _client(engine, service) as fresh:
        plain = await fresh.get("/ui/login")
        assert not plain.cookies
        assert "clear-site-data" not in {k.lower() for k in plain.headers}


async def _expire_the_session(service: AuthService, username: str) -> None:
    """Age ``last_used_at`` past ``session_idle_timeout_minutes`` — a SERVER-driven idle timeout, the
    residual's own named scenario, reached without waiting 30 minutes."""
    user = await service.store.get_user_by_username(username)
    assert user is not None
    sessions = await service.list_sessions(user.id)
    assert sessions
    idle_seconds = AuthSettings().session_idle_timeout_minutes * 60
    await service.store.touch_session(
        sessions[0].token_hash, now=sessions[0].last_used_at - idle_seconds - 60
    )


async def test_server_driven_idle_expiry_redirect_carries_clear_site_data(engine: Engine) -> None:
    """THE residual scenario: "a session ending by idle/absolute timeout leaves the rendered PHI page
    in the tab's DOM". The server's own expiry path is a 303 to the login page from ``require_ui`` —
    reached by every PHI navigation, and by revoke / admin-disable / AD-reconcile too. It must carry
    the header itself, so the control does not depend on the client watchdog having run (with
    JavaScript blocked it never does) or on which login URL the browser lands on."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        assert (
            await c.post("/ui/login", data={"username": "op", "password": PW})
        ).status_code == 303
        await _expire_the_session(service, "op")
        gone = await c.get("/ui/messages", follow_redirects=False)
        assert gone.status_code == 303
        assert gone.headers["clear-site-data"] == '"cache"'
        # and it names the reason, so the operator does not meet an unexplained login form
        assert gone.headers["location"] == "/ui/login?e=expired"


async def test_post_termination_login_render_carries_clear_site_data(engine: Engine) -> None:
    """Belt: the landing render carries it too, keyed on the DEAD COOKIE rather than only on the
    outcome code — a browser that arrives at /ui/login from a bookmark or the Back button after the
    server ended its session is just as much a post-termination landing."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        assert (
            await c.post("/ui/login", data={"username": "op", "password": PW})
        ).status_code == 303
        await _expire_the_session(service, "op")
        landing = await c.get("/ui/login")  # no ?e= code at all
        assert landing.status_code == 200
        assert landing.headers["clear-site-data"] == '"cache"'


async def test_revoked_session_navigation_carries_clear_site_data(engine: Engine) -> None:
    """The other server-driven terminations ride the same redirect: "sign out everywhere else", an
    admin disable and the AD reconciler all revoke server-side and surface as this 303."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        assert (
            await c.post("/ui/login", data={"username": "op", "password": PW})
        ).status_code == 303
        user = await service.store.get_user_by_username("op")
        assert user is not None
        await service.revoke_sessions_for_user(user.id, actor="admin")
        gone = await c.get("/ui/dead-letters", follow_redirects=False)
        assert gone.status_code == 303
        assert gone.headers["clear-site-data"] == '"cache"'


async def test_password_change_carries_clear_site_data_on_both_legs(engine: Engine) -> None:
    """The WIDEST termination the console offers, and the one an operator reaches for after a
    suspected compromise: ``POST /ui/account/password`` revokes EVERY session for the user
    (``AuthService.change_password`` -> ``revoke_user_sessions``), deletes the cookie and 303s to the
    login page. It emitted no ``Clear-Site-Data`` on either leg — the 303 wrote only the cookie
    deletion, and the landing render could not compensate because ``pwchanged`` was not an
    allow-listed code and the stale-cookie fallback sees nothing (that same response had just deleted
    the cookie). So Back / bfcache could resurrect the rendered PHI page across a full revoke."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    new_pw = "another-strong-test-passphrase"
    async with _client(engine, service) as c:
        assert (
            await c.post("/ui/login", data={"username": "op", "password": PW})
        ).status_code == 303
        changed = await c.post(
            "/ui/account/password",
            data={"current_password": PW, "new_password": new_pw, "new_password2": new_pw},
            follow_redirects=False,
        )
        assert changed.status_code == 303, changed.text
        assert changed.headers["location"] == "/ui/login?e=pwchanged"
        assert changed.headers["clear-site-data"] == '"cache"'
    # …and the landing render carries it on a FRESH client — no cookie, so the stale-cookie fallback
    # cannot supply it and only the allow-listed outcome code can. That is the belt for a browser
    # that reaches the login page by another route after the revoke.
    async with _client(engine, service) as fresh:
        landing = await fresh.get("/ui/login?e=pwchanged")
        assert landing.status_code == 200
        assert not fresh.cookies
        assert landing.headers["clear-site-data"] == '"cache"'


def test_clearing_the_session_cookie_and_the_header_cannot_be_written_apart() -> None:
    """The STRUCTURAL fix behind the test above. ``Clear-Site-Data`` used to be a second line each
    terminating route had to remember beside ``clear_session_cookie`` — and one of the two routes did
    not. Deleting the session cookie IS the browser-visible end of a session, so the helper emits
    both; this pins that a future termination route cannot get one without the other."""
    request = StarletteRequest(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": "/ui/logout",
            "raw_path": b"/ui/logout",
            "query_string": b"",
            "root_path": "",
            "headers": [(b"host", b"t")],
            "client": ("127.0.0.1", 1234),
            "server": ("t", 80),
            "app": SimpleNamespace(state=SimpleNamespace()),
        }
    )
    resp = StarletteResponse()
    clear_session_cookie(resp, request)
    assert resp.headers["clear-site-data"] == '"cache"'
    assert "mf_session=" in resp.headers["set-cookie"]


def test_expired_is_an_allow_listed_login_code() -> None:
    """The code must render real copy — an unlisted code renders an EMPTY banner, so the operator
    would be bounced to a bare login form with no explanation."""
    assert "Your session ended" in pages.login("expired")
    assert "banner" in pages.login("expired")
    # every Clear-Site-Data code must ALSO explain itself — a code that earns the header is by
    # definition a post-termination landing, and a bare form is the worst place to be silent.
    # Derived from the allow-list, so a code added there without login copy reds here.
    assert "pwchanged" in _CLEAR_SITE_DATA_LOGIN_CODES
    for code in sorted(_CLEAR_SITE_DATA_LOGIN_CODES):
        assert "banner" in pages.login(code), code


# --- the client contract ----------------------------------------------------------------------------


async def test_every_authenticated_page_carries_the_watchdog_hook(engine: Engine) -> None:
    """The hook rides the <nav>, which is rendered only on authenticated pages — so it is present on
    the PHI pages and on the five minimal-nav pages, and absent from the unauthenticated ones."""
    service = await _service(engine)
    await _add(service, "op", Role.ADMINISTRATOR)
    async with _client(engine, service) as c:
        anonymous = await c.get("/ui/login")
        assert "data-mf-session-watchdog" not in anonymous.text
        assert (
            await c.post("/ui/login", data={"username": "op", "password": PW})
        ).status_code == 303
        for path in ("/ui", "/ui/messages", "/ui/dead-letters", "/ui/account", "/ui/status"):
            page = await c.get(path)
            assert page.status_code == 200, path
            assert "data-mf-session-watchdog" in page.text, path
    # the confinement chrome carries it too — those pages are authenticated
    for markup in (
        pages.reauth("/ui/x", mfa_needed=False),
        pages.password_page(forced=True),
        pages.webauthn_enroll_page("{}"),
        pages.oidc_landing(),
        pages.reauth_continue("/ui/x"),
    ):
        assert "data-mf-session-watchdog" in markup
    assert "data-mf-session-watchdog" not in pages.sso_challenge()


def test_app_js_blanks_the_document_before_redirecting() -> None:
    """The binding ordering contract: ``location.replace`` can fail or hang exactly when the engine is
    unreachable — the stale-contact case — so the DOM must already be empty by then."""
    src = _APP_JS.read_text(encoding="utf-8")
    watchdog = src.split("[data-mf-session-watchdog]", 1)[1].split("feature(", 1)[0]
    blank = watchdog.index("document.body.replaceChildren()")
    replace = watchdog.index("window.location.replace")
    assert blank < replace, "the watchdog must blank the document BEFORE navigating away"


def test_app_js_watchdog_is_anchored_to_the_server_not_to_dom_activity() -> None:
    """A local-activity reset would leave rendered PHI up after the server had terminated the session
    — the exact failure this cell targets. Pin that no DOM-activity listener resets the anchor, that
    the probe surfaces (rather than follows) the auth redirect, and that a failed probe does NOT
    refresh the anchor."""
    src = _APP_JS.read_text(encoding="utf-8")
    watchdog = src.split("[data-mf-session-watchdog]", 1)[1].split("feature(", 1)[0]
    for dom_activity in ("mousemove", "keydown", "keypress", "scroll", "touchstart", "click"):
        assert dom_activity not in watchdog, dom_activity
    assert 'redirect: "manual"' in watchdog
    assert 'resp.type === "opaqueredirect"' in watchdog
    # lastServerContact is advanced in exactly ONE place besides its initializer, and only AFTER a
    # successful probe body was parsed — so an unreachable engine never refreshes the anchor.
    assignments = [m.start() for m in re.finditer(r"lastServerContact = Date\.now\(\);", watchdog)]
    assert len(assignments) == 2, assignments  # the initializer + the post-parse refresh
    body_parse = watchdog.index("JSON.parse(await resp.text())")
    assert assignments[0] < watchdog.index("async function probe()") < body_parse < assignments[1]


def test_app_js_runs_every_feature_init_in_isolation() -> None:
    """A security control must not share a failure domain with cosmetic page enhancers. The registry
    runner used to be a bare ``if (el) pair[1](el)`` loop, so a throw in ANY init aborted the rest —
    and ``[data-mf-table]``, which initialises on the Messages and Dead-letters PHI pages, was
    registered ahead of the watchdog. Pin that each init is wrapped."""
    src = _APP_JS.read_text(encoding="utf-8")
    runner = src.split("function runInit(", 1)[1].split("\n  }", 1)[0]
    assert runner.index("try {") < runner.index("pair[1](el)") < runner.index("catch (e)")


def test_app_js_starts_the_session_watchdog_before_every_page_enhancer() -> None:
    """Ordering, not just isolation: the watchdog is registered on the SECURITY registry and that
    registry is replayed first, so no page feature can be in front of the control that discards
    rendered PHI. This fails if the watchdog is moved back onto the ordinary registry."""
    src = _APP_JS.read_text(encoding="utf-8")
    assert 'securityFeature("[data-mf-session-watchdog]"' in src
    assert 'feature("[data-mf-session-watchdog]"' not in src.replace("securityFeature(", "")
    assert src.index("securityInits.forEach(runInit)") < src.index("inits.forEach(runInit)")


def _fetch_option_objects(src: str) -> list[str]:
    """Every ``await fetch(…, { … })`` options object in ``app.js``, by brace matching."""
    objects: list[str] = []
    for call in [m.end() for m in re.finditer(r"await fetch\(", src)]:
        start = src.index("{", call)
        depth = 0
        for i in range(start, len(src)):
            if src[i] == "{":
                depth += 1
            elif src[i] == "}":
                depth -= 1
                if depth == 0:
                    objects.append(src[start : i + 1])
                    break
    return objects


def test_every_app_js_fetch_surfaces_an_auth_redirect_instead_of_following_it() -> None:
    """A same-origin 303 is followed TRANSPARENTLY by ``fetch`` under the default
    ``redirect: "follow"``, so a handler left at the default can never observe ``resp.status === 303``
    — the expiry branch is dead code in a real browser and the poller instead assigns a 200 LOGIN PAGE
    into the container it was refreshing. Every fetch in the console talks to a same-origin route whose
    only redirect is the auth 303, so every one of them must ask for ``redirect: "manual"``. Derived by
    parsing each call's options object, so a NEW fetch added without it reds here."""
    src = _APP_JS.read_text(encoding="utf-8")
    options = _fetch_option_objects(src)
    assert len(options) == src.count("await fetch("), options
    assert len(options) >= 9, len(options)  # the guard must not pass vacuously
    missing = [o for o in options if 'redirect: "manual"' not in o]
    assert not missing, missing


def test_no_app_js_expiry_branch_tests_a_bare_303() -> None:
    """The companion property: once a fetch surfaces the redirect, the branch must RECOGNISE the
    opaque response (type "opaqueredirect", status 0) — testing 303 alone would still never fire."""
    src = _APP_JS.read_text(encoding="utf-8")
    for match in re.finditer(r"resp\.status === 303", src):
        window = src[max(0, match.start() - 160) : match.start()]
        assert "opaqueredirect" in window, src[match.start() - 200 : match.start() + 60]


def test_app_js_watchdog_probe_is_the_non_activity_endpoint() -> None:
    """It must poll ``/ui/session-status`` — the route wired with ``activity=False``. Pointing it at
    an activity-refreshing route would make the watchdog keep alive the session it is watching."""
    src = _APP_JS.read_text(encoding="utf-8")
    watchdog = src.split("[data-mf-session-watchdog]", 1)[1].split("feature(", 1)[0]
    assert 'fetch("/ui/session-status"' in watchdog
    assert '"/ui/login?e=expired"' in watchdog
