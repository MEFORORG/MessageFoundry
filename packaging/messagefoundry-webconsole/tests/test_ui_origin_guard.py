# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ASVS 3.5.1 — origin validation on EVERY state-changing /ui POST, including the three that had
none: ``POST /ui/login``, ``POST /ui/logout`` and ``POST /ui/csp-report``.

Two layers:

* **HTTP behaviour** — both branches of the check are exercised on login and logout (the modern
  ``Sec-Fetch-Site`` branch AND the older ``Origin``-only fallback), plus the two shapes that must
  still succeed (a same-origin browser form POST, and a header-less non-browser client). The login
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

import httpx

import messagefoundry_webconsole
from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine

PW = "a-strong-test-passphrase"  # >=15, no app/vendor terms — satisfies the ASVS policy (WP-3)

#: RFC 5737 TEST-NET-2 has no hostname form; use a reserved example domain for the hostile origin.
EVIL_ORIGIN = "http://evil.example"


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


async def test_login_same_origin_and_headerless_still_succeed(engine: Engine) -> None:
    """The two shapes that must keep working: a same-origin browser form POST, and a header-less
    non-browser client (which cannot be CSRF-ridden, so the fallthrough is safe by construction)."""
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
        headerless = await c2.post("/ui/login", data=_creds())
        assert headerless.status_code == 303
        assert (await c2.get("/ui")).status_code == 200


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


async def test_logout_same_origin_and_headerless_still_revoke(engine: Engine) -> None:
    """A genuine same-origin Sign-out still revokes, and so does the header-less non-browser leg."""
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
        assert (await c2.post("/ui/logout")).status_code == 303
        assert (await c2.get("/ui")).status_code in (302, 303, 401)


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
        headerless = await c.post("/ui/csp-report", json=body)
        assert headerless.status_code == 204


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
