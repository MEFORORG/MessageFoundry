# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ASVS 3.5.1 — origin validation on EVERY state-changing /ui POST, including the three that had
none: ``POST /ui/login``, ``POST /ui/logout`` and ``POST /ui/csp-report``.

Two layers:

* **HTTP behaviour** — both branches of the check are exercised on login and logout (the modern
  ``Sec-Fetch-Site`` branch AND the older ``Origin``-only fallback), plus the two shapes that must
  still succeed (a same-origin browser form POST by either header), and the one that must not: a
  POST carrying neither header, which fails closed (BACKLOG #1116, #1124). The login
  assertions additionally pin that a rejected attempt sets NO cookie; the logout assertions pin that
  the session SURVIVES a rejected attempt.
* **Static enumeration** — an AST walk of every ``@app.post`` handler in
  ``messagefoundry_webconsole/routes/`` asserting each one reaches an origin guard as its first
  statement (directly, or via a local helper it immediately delegates to). Pinning the three
  previously-unguarded routes alone could not catch a NEW unguarded POST; this can.
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from _ui_clients import HEADERLESS_UI_REQUEST, create_local_user_chosen
from fastapi import HTTPException
from starlette.datastructures import Headers

import messagefoundry_webconsole
import messagefoundry_webconsole._auth as webconsole_auth
from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine

PW = "a-strong-test-passphrase"  # >=15, no app/vendor terms — satisfies the ASVS policy (WP-3)

#: RFC 5737 TEST-NET-2 has no hostname form; use a reserved example domain for the hostile origin.
EVIL_ORIGIN = "http://evil.example"

#: The refusal each branch of ``assert_same_origin`` gives, so a test can say WHICH branch refused.
_CROSS_SITE = "cross-site request rejected"
_CROSS_ORIGIN = "cross-origin request rejected"
_UNRECOGNISED = "unrecognised Sec-Fetch-Site value rejected"

#: Sends one request with no fetch metadata at all; the suite's browser stand-in leaves it alone.
HEADERLESS = {HEADERLESS_UI_REQUEST: True}


async def _service(engine: Engine) -> AuthService:
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    return service


def _client(engine: Engine, service: AuthService) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=create_app(engine, auth=service, serve_ui=True))
    return httpx.AsyncClient(transport=transport, base_url="http://t")


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
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id,
        password_hash=user.password_hash,
        must_change_password=False,
        password_generated=False,
    )


def _creds(username: str = "op") -> dict[str, str]:
    return {"username": username, "password": PW}


# --- POST /ui/login: the unauthenticated leg where SameSite=Strict supplies nothing ---------------


async def test_login_rejects_sec_fetch_cross_site_without_setting_a_cookie(engine: Engine) -> None:
    """A cross-site credential POST is 403'd and mints NOTHING: no session cookie is set, so
    login-CSRF cannot plant a session in the victim's browser."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        r = await c.post("/ui/login", data=_creds(), headers={"Sec-Fetch-Site": "cross-site"})
        assert r.status_code == 403
        assert "set-cookie" not in {k.lower() for k in r.headers}


async def test_login_rejects_same_site_sibling_subdomain(engine: Engine) -> None:
    """``same-site`` (a sibling subdomain) is rejected too — /ui is strictly same-ORIGIN."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        r = await c.post("/ui/login", data=_creds(), headers={"Sec-Fetch-Site": "same-site"})
        assert r.status_code == 403
        assert "set-cookie" not in {k.lower() for k in r.headers}


async def test_login_rejects_foreign_origin_without_sec_fetch(engine: Engine) -> None:
    """The OLDER-browser fallback: no ``Sec-Fetch-Site``, a foreign ``Origin`` — still 403, still no
    cookie. Pins the second branch of the check, which the Sec-Fetch tests short-circuit past."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        r = await c.post("/ui/login", data=_creds(), headers={"Origin": EVIL_ORIGIN})
        assert r.status_code == 403
        assert "set-cookie" not in {k.lower() for k in r.headers}


async def test_login_rejection_precedes_the_rate_limiter(engine: Engine) -> None:
    """The guard is the FIRST statement, so a cross-site flood burns no per-address login budget: a
    legitimate same-origin login still succeeds immediately after many rejected cross-site POSTs."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        for _ in range(25):
            blocked = await c.post(
                "/ui/login", data=_creds(), headers={"Sec-Fetch-Site": "cross-site"}
            )
            assert blocked.status_code == 403
        ok = await c.post("/ui/login", data=_creds(), headers={"Sec-Fetch-Site": "same-origin"})
        assert ok.status_code == 303
        assert "set-cookie" in {k.lower() for k in ok.headers}


async def test_login_same_origin_succeeds_by_either_header(engine: Engine) -> None:
    """The shapes that must keep working: a browser form POST naming itself same-origin, and an
    older browser's POST that carries a matching ``Origin`` and no ``Sec-Fetch-Site``."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        browser = await c.post(
            "/ui/login",
            data=_creds(),
            headers={"Sec-Fetch-Site": "same-origin", "Origin": "http://t"},
        )
        assert browser.status_code == 303
        assert (await c.get("/ui")).status_code == 200
    async with _client(engine, service) as c2:
        older = await c2.post("/ui/login", data=_creds(), headers={"Origin": "http://t"})
        assert older.status_code == 303
        assert (await c2.get("/ui")).status_code == 200


@pytest.mark.parametrize(
    "value",
    ["x", "sameorigin", "Same-Origin", "SAME-ORIGIN", "NONE", "same-origin, none", "same-origin\t"],
    ids=["unknown", "no-hyphen", "mixed-case", "upper-case", "upper-none", "list", "padded"],
)
async def test_a_write_with_an_unrecognised_sec_fetch_site_fails_closed(
    engine: Engine, value: str
) -> None:
    """A write is accepted on ``Sec-Fetch-Site`` only for the two exact tokens ``same-origin`` and
    ``none``. Any other non-empty value passed before, because the check refused two values and
    allowed the rest. It is refused now, a matching ``Origin`` beside it changes nothing, and no
    cookie is set.

    The control is the same client and credentials with the exact token, which signs in."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        for extra in ({}, {"Origin": "http://t"}):
            r = await c.post("/ui/login", data=_creds(), headers={"Sec-Fetch-Site": value, **extra})
            assert r.status_code == 403, (value, extra, r.status_code)
            assert "set-cookie" not in {k.lower() for k in r.headers}
        for accepted in ("none", "same-origin"):
            ok = await c.post("/ui/login", data=_creds(), headers={"Sec-Fetch-Site": accepted})
            assert ok.status_code == 303, accepted


def test_a_padded_sec_fetch_site_is_refused_by_the_check_itself() -> None:
    """The HTTP layer may trim a header value before the route sees it, so the padded cases are
    also put to ``assert_same_origin`` directly, where nothing trims them."""
    state = SimpleNamespace(public_origin=None, loopback=False, webauthn_rp_from_request=True)

    def request(method: str, value: str) -> Any:
        return SimpleNamespace(
            method=method,
            headers=Headers({"sec-fetch-site": value, "host": "t"}),
            app=SimpleNamespace(state=state),
        )

    for value in (" same-origin", "same-origin ", "\tnone", "Same-Origin", "x"):
        with pytest.raises(HTTPException) as refused:
            webconsole_auth.assert_same_origin(request("POST", value))
        assert refused.value.status_code == 403, value
        assert refused.value.detail == _UNRECOGNISED, (value, refused.value.detail)
        # A GET keeps its earlier rule: only cross-site and same-site are refused there.
        webconsole_auth.assert_same_origin(request("GET", value))
    for value in ("same-origin", "none"):
        webconsole_auth.assert_same_origin(request("POST", value))
    # control: the GET arm is live, so the passes above are the rule and not a dead branch
    for value in ("cross-site", "same-site"):
        with pytest.raises(HTTPException) as refused:
            webconsole_auth.assert_same_origin(request("GET", value))
        assert (refused.value.status_code, refused.value.detail) == (403, _CROSS_SITE), value


def test_a_get_with_any_sec_fetch_site_line_deliberately_does_not_read_origin() -> None:
    """DELIBERATE, and narrowing it is an owner call. On a GET, a present ``Sec-Fetch-Site`` line
    settles the request, an empty or unknown one included, and ``Origin`` is never read. So a GET
    with such a line and a FOREIGN ``Origin`` is not refused. That is the ``origin/main`` rule,
    which owner rulings R4 and R4b of 2026-09-28 keep for the sign-in GETs.

    Put to the function directly: over HTTP the fetch-metadata middleware and the route's own
    checks sit around it, and this pins what ``assert_same_origin`` itself does.

    Controls: the same foreign ``Origin`` with NO ``Sec-Fetch-Site`` line is refused on a GET, and
    the same headers on a POST are refused, so the passes are this rule and not a dead check."""
    state = SimpleNamespace(public_origin=None, loopback=False, webauthn_rp_from_request=True)

    def request(method: str, headers: dict[str, str]) -> Any:
        return SimpleNamespace(
            method=method,
            headers=Headers({"host": "t", "origin": EVIL_ORIGIN, **headers}),
            app=SimpleNamespace(state=state),
        )

    # Which branch refuses the POST differs: an empty line is absence, so Origin decides; an
    # unknown value is refused before Origin is read.
    for value, branch in (("", _CROSS_ORIGIN), ("x", _UNRECOGNISED)):
        webconsole_auth.assert_same_origin(request("GET", {"sec-fetch-site": value}))
        with pytest.raises(HTTPException) as refused:
            webconsole_auth.assert_same_origin(request("POST", {"sec-fetch-site": value}))
        assert (refused.value.status_code, refused.value.detail) == (403, branch), value
    with pytest.raises(HTTPException) as refused:
        webconsole_auth.assert_same_origin(request("GET", {}))
    assert (refused.value.status_code, refused.value.detail) == (403, _CROSS_ORIGIN)


# --- the rule table in the assert_same_origin docstring, driven row by row --------------------------

_TABLE_METHODS = {"write": ("POST", "PUT", "DELETE", "PATCH"), "GET": ("GET",)}
#: Each table state as the header values that realise it. ``None`` is "no such line".
_TABLE_SITES: dict[str, tuple[str | None, ...]] = {
    "absent": (None,),
    "empty": ("",),
    "cross-site or same-site": ("cross-site", "same-site"),
    "same-origin or none": ("same-origin", "none"),
    "any other value": ("x", "Same-Origin", "NONE", " same-origin", "same-origin, none"),
}
_TABLE_ORIGINS: dict[str, tuple[str | None, ...]] = {
    "absent or empty": (None, ""),
    "matches": ("http://t",),
    "does not match": (EVIL_ORIGIN, "null", "http://t.evil.example"),
}
_TABLE_ORIGINS["any"] = tuple(v for values in list(_TABLE_ORIGINS.values()) for v in values)


def _rule_table() -> list[tuple[str, str, str, str]]:
    """The rows of the simple table in ``assert_same_origin``'s docstring."""
    lines = (webconsole_auth.assert_same_origin.__doc__ or "").splitlines()
    rules = [i for i, line in enumerate(lines) if line.strip().startswith("======")]
    assert len(rules) == 3, "the docstring no longer holds one simple table"
    widths = [len(part) for part in lines[rules[0]].split()]
    assert len(widths) == 4, widths
    rows: list[tuple[str, str, str, str]] = []
    for line in lines[rules[1] + 1 : rules[2]]:
        cells, at = [], len(line) - len(line.lstrip())
        for width in widths:
            cells.append(line[at : at + width].strip())
            at += width + 2
        rows.append((cells[0], cells[1], cells[2], cells[3]))
    return rows


def _verdict(method: str, site: str | None, origin: str | None) -> str:
    headers = {"host": "t"}
    if site is not None:
        headers["sec-fetch-site"] = site
    if origin is not None:
        headers["origin"] = origin
    state = SimpleNamespace(public_origin=None, loopback=False, webauthn_rp_from_request=True)
    request: Any = SimpleNamespace(
        method=method, headers=Headers(headers), app=SimpleNamespace(state=state)
    )
    try:
        webconsole_auth.assert_same_origin(request)
    except HTTPException as refused:
        assert refused.status_code == 403, (method, site, origin, refused.status_code)
        return "refuse"
    return "accept"


def test_the_docstring_rule_table_is_what_the_function_does() -> None:
    """The docstring of ``assert_same_origin`` is the ONE complete statement of the /ui origin
    rule, and every other document points at it. Hand-written copies of that rule disagreed with
    the code three times on this branch. So the table is read out of the docstring and the function
    is driven over every row, with several concrete header values per state.

    It also checks the table is COMPLETE: every method, ``Sec-Fetch-Site`` state and ``Origin``
    state is covered by exactly one row, so a case cannot be left out of the statement."""
    rows = _rule_table()
    # positive controls: the parse found real rows, and both verdicts appear, so a table that
    # parsed to nothing or a function that accepted everything could not pass
    assert len(rows) >= 12, rows
    assert {row[3] for row in rows} == {"accept", "refuse"}, rows
    covered: dict[tuple[str, str, str], int] = {}
    for method, site, origin, verdict in rows:
        assert method in _TABLE_METHODS and site in _TABLE_SITES and origin in _TABLE_ORIGINS, (
            method,
            site,
            origin,
        )
        states = [s for s in _TABLE_ORIGINS if s != "any"] if origin == "any" else [origin]
        for state in states:
            covered[(method, site, state)] = covered.get((method, site, state), 0) + 1
        for verb in _TABLE_METHODS[method]:
            for site_value in _TABLE_SITES[site]:
                for origin_value in _TABLE_ORIGINS[origin]:
                    got = _verdict(verb, site_value, origin_value)
                    assert got == verdict, (
                        f"the docstring table says {method} / Sec-Fetch-Site {site} / Origin "
                        f"{origin} is a {verdict}, but {verb} with Sec-Fetch-Site={site_value!r} "
                        f"Origin={origin_value!r} is a {got}"
                    )
    expected = {
        (method, site, origin)
        for method in _TABLE_METHODS
        for site in _TABLE_SITES
        for origin in _TABLE_ORIGINS
        if origin != "any"
    }
    assert set(covered) == expected, sorted(expected ^ set(covered))
    assert set(covered.values()) == {1}, {k: v for k, v in covered.items() if v != 1}


def test_a_post_with_origin_null_and_no_sec_fetch_site_is_refused() -> None:
    """``docs/BROWSER-SUPPORT.md`` leans on this: a browser that sends ``Origin: null`` on its form
    POST and no ``Sec-Fetch-Site`` is refused as a mismatch, by the Origin branch and not by the
    neither-header one. The control is the same POST with a matching ``Origin``."""
    state = SimpleNamespace(public_origin=None, loopback=False, webauthn_rp_from_request=True)

    def request(origin: str) -> Any:
        return SimpleNamespace(
            method="POST",
            headers=Headers({"host": "t", "origin": origin}),
            app=SimpleNamespace(state=state),
        )

    with pytest.raises(HTTPException) as refused:
        webconsole_auth.assert_same_origin(request("null"))
    assert (refused.value.status_code, refused.value.detail) == (403, _CROSS_ORIGIN)
    webconsole_auth.assert_same_origin(request("http://t"))


async def test_login_with_neither_header_fails_closed_without_setting_a_cookie(
    engine: Engine,
) -> None:
    """BACKLOG #1116, #1124. A sign-in POST carrying NEITHER ``Sec-Fetch-Site`` NOR ``Origin`` used
    to pass, and on this route no session cookie exists for ``SameSite=Strict`` to withhold, so
    nothing at all bounded it. It is refused now, and mints nothing. An empty ``Origin`` is absence.

    The control is the same client and credentials with ``Origin`` added, which signs in: the 403 is
    the missing header, not a bad password or a spent budget."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        for headers in ({}, {"Origin": ""}, {"Sec-Fetch-Site": ""}):
            r = await c.post("/ui/login", data=_creds(), headers=headers, extensions=HEADERLESS)
            assert r.status_code == 403, headers
            assert "neither Sec-Fetch-Site nor Origin" in r.text
            assert "set-cookie" not in {k.lower() for k in r.headers}
        assert (await c.get("/ui", follow_redirects=False)).status_code != 200
        ok = await c.post(
            "/ui/login", data=_creds(), headers={"Origin": "http://t"}, extensions=HEADERLESS
        )
        assert ok.status_code == 303


# --- POST /ui/logout: forced logout (the route has NO Depends gate, by design) --------------------


async def test_logout_rejects_cross_site_and_the_session_survives(engine: Engine) -> None:
    """A cross-site forced-logout POST is 403'd AND leaves the session intact — the dashboard still
    renders on the same cookie afterwards."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        assert (await c.post("/ui/login", data=_creds())).status_code == 303
        r = await c.post("/ui/logout", headers={"Sec-Fetch-Site": "cross-site"})
        assert r.status_code == 403
        assert (await c.get("/ui")).status_code == 200  # session SURVIVED


async def test_logout_rejects_foreign_origin_and_the_session_survives(engine: Engine) -> None:
    """Same, through the ``Origin``-only fallback branch (no ``Sec-Fetch-Site``)."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        assert (await c.post("/ui/login", data=_creds())).status_code == 303
        r = await c.post("/ui/logout", headers={"Origin": EVIL_ORIGIN})
        assert r.status_code == 403
        assert (await c.get("/ui")).status_code == 200  # session SURVIVED


async def test_logout_same_origin_revokes_and_neither_header_does_not(engine: Engine) -> None:
    """A genuine same-origin Sign-out still revokes. A POST carrying neither provenance header is
    refused and the session SURVIVES it (BACKLOG #1116, #1124), where it used to revoke."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        assert (await c.post("/ui/login", data=_creds())).status_code == 303
        out = await c.post(
            "/ui/logout", headers={"Sec-Fetch-Site": "same-origin", "Origin": "http://t"}
        )
        assert out.status_code == 303
        assert (await c.get("/ui")).status_code in (302, 303, 401)
    async with _client(engine, service) as c2:
        assert (await c2.post("/ui/login", data=_creds())).status_code == 303
        assert (await c2.post("/ui/logout", extensions=HEADERLESS)).status_code == 403
        assert (await c2.get("/ui")).status_code == 200  # session SURVIVED
        assert (await c2.post("/ui/logout", headers={"Origin": "http://t"})).status_code == 303
        assert (await c2.get("/ui")).status_code in (302, 303, 401)


async def test_an_authenticated_write_with_neither_header_fails_closed(engine: Engine) -> None:
    """The same refusal on a write behind ``require_ui``, which asserts provenance before it spends
    the actor's budget. The control is the same POST with ``Origin``, which is not a 403."""
    service = await _service(engine)
    await _add(service, "op", Role.ADMINISTRATOR)
    async with _client(engine, service) as c:
        assert (await c.post("/ui/login", data=_creds())).status_code == 303
        refused = await c.post("/ui/config/reload", extensions=HEADERLESS)
        assert refused.status_code == 403
        assert "neither Sec-Fetch-Site nor Origin" in refused.text
        named = await c.post("/ui/config/reload", headers={"Origin": "http://t"})
        assert named.status_code != 403, named.text


# --- POST /ui/csp-report: the third unguarded POST, narrow guard ----------------------------------


async def test_csp_report_rejects_a_foreign_sites_report(engine: Engine) -> None:
    """A report a FOREIGN site's CSP aimed at our endpoint (log amplification) is refused."""
    service = await _service(engine)
    async with _client(engine, service) as c:
        r = await c.post(
            "/ui/csp-report",
            json={"csp-report": {"document-uri": "http://evil.example/x"}},
            headers={"Sec-Fetch-Site": "cross-site"},
        )
        assert r.status_code == 403


async def test_csp_report_accepts_conforming_delivery_shapes(engine: Engine) -> None:
    """Every conforming delivery shape still 204s. The Reporting-API (``report-to``) case is the
    load-bearing one: the user agent's reporting agent sends it OUT OF BAND with no ``Sec-Fetch-*``
    and may stamp ``Origin: null``, so a full same-origin check would 403 every modern report."""
    service = await _service(engine)
    body = {"csp-report": {"document-uri": "http://t/ui/login"}}
    async with _client(engine, service) as c:
        same_origin = await c.post(
            "/ui/csp-report", json=body, headers={"Sec-Fetch-Site": "same-origin"}
        )
        assert same_origin.status_code == 204
        agent = await c.post("/ui/csp-report", json=body, headers={"Origin": "null"})
        assert agent.status_code == 204
        # Still accepted with neither header: this sink uses the NARROWER assert_not_cross_site, and a
        # reporting agent sends no fetch metadata. The fail-closed rule is assert_same_origin's alone.
        headerless = await c.post("/ui/csp-report", json=body, extensions=HEADERLESS)
        assert headerless.status_code == 204


# --- BACKLOG #2217: behind a trusted proxy the forwarded Host is not our origin -------------------
#
# The posture: a loopback bind, trusted_proxies set, no [api].public_origin. create_app derives
# webauthn_rp_from_request=False from exactly those arguments, as serve does from ApiSettings. The
# control is the same bind with no proxy, which must keep the Host fallback. Mutation: drop the
# proxied_loopback_host guard from _origin_matches or _request_origin. Red: the proxied arms
# match, as on main.

_PROXY = ["127.0.0.1"]
_PUBLIC_ORIGIN = "https://ops.example.test"


def _posture_client(
    engine: Engine,
    service: AuthService,
    *,
    trusted_proxies: list[str],
    public_origin: str | None = None,
) -> httpx.AsyncClient:
    app = create_app(
        engine,
        auth=service,
        serve_ui=True,
        loopback=True,
        trusted_proxies=trusted_proxies,
        public_origin=public_origin,
    )
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")


async def test_an_origin_matching_a_proxied_host_is_refused(engine: Engine) -> None:
    """An older browser's POST whose Origin equals the Host the proxy forwarded is 403'd and mints no
    cookie, because a client can set that Host. The same request on a direct loopback bind signs in."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    matching = {"Origin": "http://t"}  # equals the Host the request carries
    async with _posture_client(engine, service, trusted_proxies=_PROXY) as c:
        r = await c.post("/ui/login", data=_creds(), headers=matching)
        assert r.status_code == 403
        assert "set-cookie" not in {k.lower() for k in r.headers}
    async with _posture_client(engine, service, trusted_proxies=[]) as control:
        r = await control.post("/ui/login", data=_creds(), headers=matching)
        assert r.status_code == 303  # the refusal above is the proxy's doing


async def test_behind_a_trusted_proxy_the_public_origin_is_the_only_match(engine: Engine) -> None:
    """The recovery the startup warning names: with the external origin set, it matches and the
    forwarded Host does not. A modern browser's Sec-Fetch-Site branch is unaffected by either."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _posture_client(
        engine, service, trusted_proxies=_PROXY, public_origin=_PUBLIC_ORIGIN
    ) as c:
        host = await c.post("/ui/login", data=_creds(), headers={"Origin": "http://t"})
        assert host.status_code == 403
        ok = await c.post("/ui/login", data=_creds(), headers={"Origin": _PUBLIC_ORIGIN})
        assert ok.status_code == 303
    async with _posture_client(engine, service, trusted_proxies=_PROXY) as modern:
        r = await modern.post("/ui/login", data=_creds(), headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code == 303


class _Handshake:
    """A browser WebSocket handshake whose Origin equals its Host, carrying a session cookie."""

    def __init__(self, app: object, cookie: str) -> None:
        self.headers = Headers({"origin": "http://t", "host": "t"})  # has getlist (BACKLOG #2454)
        self.app = app
        self.url = SimpleNamespace(scheme="ws", path="/ws/stats")
        self.cookies = {"mf_session": cookie}
        self.client = SimpleNamespace(host="127.0.0.1", port=123)


async def test_the_socket_origin_check_does_not_trust_a_proxied_host(engine: Engine) -> None:
    """CSWSH: the handshake's Origin matches its Host, and a valid cookie rides it. Behind a trusted
    proxy that proves nothing, so the cookie path declines; on a direct loopback bind it admits."""
    from messagefoundry.auth import Permission
    from messagefoundry_webconsole import authorize_ui_ws

    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    token = (await service.login("op", PW)).token
    assert token is not None
    for proxies, admitted in ((_PROXY, False), ([], True)):
        app = create_app(
            engine, auth=service, serve_ui=True, loopback=True, trusted_proxies=proxies
        )
        identity, _ = await authorize_ui_ws(_Handshake(app, token), Permission.MONITORING_READ)  # type: ignore[arg-type]
        assert (identity is not None) is admitted, proxies


def test_the_csp_report_filter_has_no_origin_behind_a_trusted_proxy() -> None:
    """The canary filter's own origin is unknown behind a trusted proxy, so a report WARNs rather than
    being filed as our canary on the strength of a forwarded Host. The control keeps the Host."""
    from starlette.requests import Request

    from messagefoundry_webconsole.routes.core import _request_origin

    def origin_for(proxies: list[str], *, loopback: bool = True) -> str | None:
        # The state create_app itself derives, so a wrong derivation there fails here too.
        app = create_app(serve_ui=False, loopback=loopback, trusted_proxies=proxies)
        scope = {
            "type": "http",
            "scheme": "https",
            "method": "POST",
            "path": "/ui/csp-report",
            "query_string": b"",
            "headers": [(b"host", b"t")],
            "app": app,
        }
        return _request_origin(Request(scope))

    assert origin_for(_PROXY) is None
    assert origin_for([]) == "https://t"
    # Off loopback the fallback is unchanged: the console cannot tell a proxy from a direct browser.
    assert origin_for(_PROXY, loopback=False) == "https://t"


# --- Static enumeration: no /ui POST may ship without an origin guard -----------------------------

_GUARDS = frozenset({"assert_same_origin", "assert_not_cross_site"})
_ROUTES_DIR = Path(messagefoundry_webconsole.__file__).parent / "routes"


def _guard_call(node: ast.stmt) -> str | None:
    """The guard name if ``node`` is a bare ``assert_*_origin(request)``-style call statement."""
    if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
        func = node.value.func
        if isinstance(func, ast.Name) and func.id in _GUARDS:
            return func.id
    return None


def _first_real_statement(body: list[ast.stmt]) -> ast.stmt | None:
    """The first statement of a function body, skipping a leading docstring."""
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
        return body[1] if len(body) > 1 else None
    return body[0] if body else None


def _guards_at_top(fn: ast.AsyncFunctionDef | ast.FunctionDef) -> bool:
    stmt = _first_real_statement(fn.body)
    return stmt is not None and _guard_call(stmt) is not None


def _delegated_call_names(fn: ast.AsyncFunctionDef | ast.FunctionDef) -> set[str]:
    """Names of functions this handler calls, so a handler that immediately hands off to a shared
    local helper (the connection-control / dead-letter-replay pattern) is credited with the helper's
    guard rather than being reported as unguarded."""
    names: set[str] = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            names.add(node.func.id)
    return names


def test_every_ui_post_route_asserts_request_origin() -> None:
    """Builder enumeration (ASVS 3.5.1): every ``@app.post`` handler under ``routes/`` reaches an
    origin guard as its first statement — directly, or through a local helper whose own first
    statement is one. A NEW /ui POST written without a guard fails here."""
    unguarded: list[str] = []
    checked = 0
    for path in sorted(_ROUTES_DIR.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        functions = {
            node.name: node
            for node in ast.walk(tree)
            if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef))
        }
        guarded_helpers = {name for name, fn in functions.items() if _guards_at_top(fn)}
        for fn in functions.values():
            posts = [
                d
                for d in fn.decorator_list
                if isinstance(d, ast.Call)
                and isinstance(d.func, ast.Attribute)
                and d.func.attr == "post"
            ]
            if not posts:
                continue
            checked += 1
            if _guards_at_top(fn) or (_delegated_call_names(fn) & guarded_helpers):
                continue
            unguarded.append(f"{path.name}:{fn.lineno} {fn.name}")
    assert checked >= 50, (
        f"the POST-route walk found only {checked} handlers — did it stop working?"
    )
    assert not unguarded, (
        "these /ui POST handlers reach no origin guard as their first statement "
        f"(ASVS 3.5.1): {unguarded}"
    )
