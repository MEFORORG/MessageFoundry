# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0065 §hardening / BACKLOG #192: /ui browser hardening — __Host- cookie prefix, per-response
nonce CSP, COOP/CORP, CSP reporting. HTTP-level (httpx ASGITransport), asserting the loopback-vs-
effective-https split: byte-identical over cleartext http; hardening engages over https; org opt-out
reverts to the pre-#192 posture without downgrading transport security."""

from __future__ import annotations

import re

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine

PW = "a-strong-test-passphrase"  # >=15, no app/vendor terms — satisfies the ASVS policy (WP-3)
_NONCE_RE = re.compile(r"script-src 'nonce-([A-Za-z0-9_-]+)' 'strict-dynamic'")


async def _service(engine: Engine) -> AuthService:
    service = AuthService(engine.store, AuthSettings())
    await service.initialize()
    return service


def _client(engine: Engine, service: AuthService, *, scheme: str) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=create_app(engine, auth=service, serve_ui=True))
    return httpx.AsyncClient(transport=transport, base_url=f"{scheme}://t")


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


async def _login(c: httpx.AsyncClient, username: str) -> httpx.Response:
    return await c.post("/ui/login", data={"username": username, "password": PW})


# --- #192-1: __Host- cookie prefix is scheme-conditional -----------------------------------------


async def test_http_cookie_is_byte_identical(engine: Engine) -> None:
    """Over cleartext loopback the session cookie is unchanged: plain ``mf_session``, HttpOnly,
    SameSite=Strict, NO Secure, NO __Host- prefix (byte-identity with pre-#192)."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service, scheme="http") as c:
        r = await _login(c, "op")
        assert r.status_code == 303
        set_cookie = r.headers["set-cookie"]
        low = set_cookie.lower()
        assert set_cookie.split("=", 1)[0] == "mf_session"
        assert "__host-" not in low
        assert "httponly" in low and "samesite=strict" in low
        assert "secure" not in low


async def test_https_uses_host_prefixed_secure_cookie(engine: Engine) -> None:
    """Over https the cookie upgrades to ``__Host-mf_session`` + Secure (+ Path=/, no Domain), and the
    session it names is actually usable on a follow-up authenticated request."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service, scheme="https") as c:
        r = await _login(c, "op")
        assert r.status_code == 303
        set_cookie = r.headers["set-cookie"]
        low = set_cookie.lower()
        assert set_cookie.split("=", 1)[0] == "__Host-mf_session"
        assert "secure" in low and "httponly" in low and "samesite=strict" in low
        assert "path=/" in low and "domain=" not in low
        # the __Host- cookie the jar kept authenticates the dashboard
        dash = await c.get("/ui")
        assert dash.status_code == 200


async def test_https_logout_clears_host_prefixed_cookie(engine: Engine) -> None:
    """Logout over https deletes the ``__Host-`` name with Secure so the browser accepts the expiry,
    and the session no longer authenticates."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service, scheme="https") as c:
        await _login(c, "op")
        out = await c.post("/ui/logout")
        assert out.status_code == 303
        set_cookie = out.headers["set-cookie"]
        assert set_cookie.split("=", 1)[0] == "__Host-mf_session"
        assert "secure" in set_cookie.lower()
        # session revoked -> dashboard bounces to login (303) rather than 200
        follow = await c.get("/ui")
        assert follow.status_code in (302, 303, 401)


# --- #192-2/3/4: per-response nonce CSP + COOP/CORP + reporting (effective-https only) ------------


async def test_https_nonce_csp_coop_and_reporting(engine: Engine) -> None:
    service = await _service(engine)
    async with _client(engine, service, scheme="https") as c:
        r1 = await c.get("/ui/login")
        csp1 = r1.headers["content-security-policy"]
        m1 = _NONCE_RE.search(csp1)
        assert m1, csp1
        # script-src carries a nonce, not 'self'
        script_src = csp1.split("script-src", 1)[1].split(";", 1)[0]
        assert "'self'" not in script_src
        assert "unsafe-inline" not in csp1 and "unsafe-eval" not in csp1
        assert "frame-ancestors 'none'" in csp1
        # reporting wired both ways + the modern endpoints header
        assert "report-to mf-csp" in csp1 and "report-uri /ui/csp-report" in csp1
        assert r1.headers["reporting-endpoints"] == 'mf-csp="/ui/csp-report"'
        # cross-origin isolation headers
        assert r1.headers["cross-origin-opener-policy"] == "same-origin"
        assert r1.headers["cross-origin-resource-policy"] == "same-origin"
        # the rendered <script> tag carries the SAME nonce as the header
        assert f'nonce="{m1.group(1)}"' in r1.text
        # a second response mints a DIFFERENT nonce
        r2 = await c.get("/ui/login")
        m2 = _NONCE_RE.search(r2.headers["content-security-policy"])
        assert m2 and m2.group(1) != m1.group(1)


async def test_http_hardening_is_a_noop(engine: Engine) -> None:
    """Over cleartext loopback the middleware is a strict no-op: the engine's static self-CSP stands,
    no nonce, no COOP, no reporting header, and the <script> tag carries no nonce."""
    service = await _service(engine)
    async with _client(engine, service, scheme="http") as c:
        r = await c.get("/ui/login")
        csp = r.headers["content-security-policy"]
        assert "script-src 'self'" in csp
        assert "nonce-" not in csp and "strict-dynamic" not in csp
        assert "cross-origin-opener-policy" not in r.headers
        assert "reporting-endpoints" not in r.headers
        assert 'nonce="' not in r.text
        # the pre-existing hardening still applies (engine seam untouched)
        assert r.headers["cache-control"] == "no-store"
        assert r.headers["x-frame-options"] == "DENY"


async def test_static_asset_not_wrapped_over_https(engine: Engine) -> None:
    """A /ui/static asset is outside the HTML scope: the nonce middleware does not touch it (no nonce
    CSP, no COOP), so static caching/headers stay as the engine emits them."""
    service = await _service(engine)
    async with _client(engine, service, scheme="https") as c:
        r = await c.get("/ui/static/app.js")
        assert r.status_code == 200
        csp = r.headers.get("content-security-policy", "")
        assert "nonce-" not in csp
        assert "cross-origin-opener-policy" not in r.headers


# --- #192-4: the CSP violation report endpoint ---------------------------------------------------


async def test_csp_report_endpoint_accepts_and_204(engine: Engine) -> None:
    service = await _service(engine)
    async with _client(engine, service, scheme="https") as c:
        # a well-formed LEGACY report-uri report — unauthenticated, returns 204
        legacy = await c.post(
            "/ui/csp-report",
            json={
                "csp-report": {
                    "document-uri": "https://t/ui/login",
                    "violated-directive": "script-src",
                    "blocked-uri": "inline",
                }
            },
        )
        assert legacy.status_code == 204
        # a MODERN Reporting-API report-to array (application/reports+json) — the shape the wired
        # Reporting-Endpoints header actually elicits — is also accepted, still 204
        modern = await c.post(
            "/ui/csp-report",
            json=[
                {
                    "type": "csp-violation",
                    "body": {
                        "documentURL": "https://t/ui/login",
                        "effectiveDirective": "script-src",
                        "blockedURL": "inline",
                    },
                }
            ],
        )
        assert modern.status_code == 204
        # a malformed body is tolerated (defensive parse), still 204
        bad = await c.post("/ui/csp-report", content=b"not json at all")
        assert bad.status_code == 204
        # an empty body is tolerated, still 204
        empty = await c.post("/ui/csp-report", content=b"")
        assert empty.status_code == 204


def test_csp_report_summary_shapes() -> None:
    """Unit-level: the summariser handles both delivery shapes and hostile input without raising."""
    from messagefoundry_webconsole.routes.core import _csp_report_summary

    legacy = _csp_report_summary(
        {
            "csp-report": {
                "document-uri": "u",
                "violated-directive": "script-src",
                "blocked-uri": "b",
            }
        }
    )
    assert "document-uri=u" in legacy and "violated-directive=script-src" in legacy
    modern = _csp_report_summary(
        [{"body": {"documentURL": "u", "effectiveDirective": "script-src", "blockedURL": "b"}}]
    )
    assert "document-uri=u" in modern and "blocked-uri=b" in modern
    assert _csp_report_summary({}) == "empty"
    assert _csp_report_summary([]) == "empty"
    assert _csp_report_summary("hostile") == "non-object"
    assert _csp_report_summary(12345) == "non-object"
    # a huge field is bounded (256 chars per value)
    big = _csp_report_summary({"csp-report": {"document-uri": "x" * 5000}})
    assert len(big) < 400


# --- #192: secure-by-default WITH an explicit org opt-out ----------------------------------------


async def test_opt_out_reverts_to_legacy_over_https(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With the opt-out env set, https reverts to the pre-#192 posture — plain ``mf_session`` name and
    static self-CSP, no nonce/COOP — but Secure stays on (transport security never downgraded)."""
    monkeypatch.setenv("MEFOR_WEBCONSOLE_DISABLE_BROWSER_HARDENING", "1")
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service, scheme="https") as c:
        r = await _login(c, "op")
        set_cookie = r.headers["set-cookie"]
        low = set_cookie.lower()
        assert set_cookie.split("=", 1)[0] == "mf_session"  # __Host- prefix reverted
        assert "secure" in low  # transport security still enforced over https
        page = await c.get("/ui/login")
        csp = page.headers["content-security-policy"]
        assert "script-src 'self'" in csp and "nonce-" not in csp
        assert "cross-origin-opener-policy" not in page.headers
        # the reverted plain cookie still authenticates (name resolver agrees on read)
        assert (await c.get("/ui")).status_code == 200
