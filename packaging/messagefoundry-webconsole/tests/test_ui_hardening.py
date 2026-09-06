# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0065 §hardening / BACKLOG #192: /ui browser hardening — __Host- cookie prefix, per-response
nonce CSP, COOP/CORP, CSP reporting. HTTP-level (httpx ASGITransport), asserting the loopback-vs-
effective-https split: byte-identical over cleartext http; hardening engages over https; org opt-out
reverts to the pre-#192 posture without downgrading transport security."""

from __future__ import annotations

import re
from types import SimpleNamespace

import httpx
import pytest
from starlette.requests import Request as StarletteRequest
from starlette.responses import Response as StarletteResponse

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine
from messagefoundry_webconsole._auth import (
    BROWSER_HARDENING_OPT_OUT_ENV,
    clear_oidc_flow_cookie,
    clear_session_cookie,
    oidc_flow_cookie_name,
    session_cookie_name,
    set_oidc_flow_cookie,
    set_session_cookie,
)

PW = "a-strong-test-passphrase"  # >=15, no app/vendor terms — satisfies the ASVS policy (WP-3)
_NONCE_RE = re.compile(r"script-src 'nonce-([A-Za-z0-9_-]+)' 'strict-dynamic'")


async def _service(engine: Engine) -> AuthService:
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    return service


def _client(
    engine: Engine, service: AuthService, *, scheme: str, loopback: bool = False
) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(
        app=create_app(engine, auth=service, serve_ui=True, loopback=loopback)
    )
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


async def test_https_insecure_context_banner_is_nonced(engine: Engine) -> None:
    """3.7.5: over effective-https the page shell carries the nonce'd insecure-context feature-detect
    script, stamped with the SAME per-response nonce as the CSP header, with no inline on* handler."""
    service = await _service(engine)
    async with _client(engine, service, scheme="https") as c:
        r = await c.get("/ui/login")
        m = _NONCE_RE.search(r.headers["content-security-policy"])
        assert m, r.headers["content-security-policy"]
        nonce = m.group(1)
        # the feature-detect script + its stable banner id are present
        assert "window.isSecureContext" in r.text
        assert "mf-insecure-context-banner" in r.text
        # the inline banner <script> carries the per-response nonce (same one as the header)
        assert (
            '<script nonce="' + nonce + '">(function(){try{if(window.isSecureContext' in r.text
        ), r.text
        # degrade-never-block: no inline event handlers anywhere in the shell
        assert "onload=" not in r.text and "onerror=" not in r.text


async def test_http_hardening_is_a_noop(engine: Engine) -> None:
    """Over cleartext http WITHOUT the loopback secure-context signal (app.state.loopback unset — e.g.
    an off-loopback cleartext bind with no exposure_protected) the middleware is a strict no-op: the
    engine's static self-CSP stands, no nonce, no COOP, no reporting header, and the <script> tag
    carries no nonce. (A loopback secure-context DOES engage the http-safe headers — see the ADR 0143
    hybrid test below.)"""
    service = await _service(engine)
    async with _client(engine, service, scheme="http") as c:
        r = await c.get("/ui/login")
        csp = r.headers["content-security-policy"]
        assert "script-src 'self'" in csp
        assert "nonce-" not in csp and "strict-dynamic" not in csp
        assert "cross-origin-opener-policy" not in r.headers
        assert "reporting-endpoints" not in r.headers
        assert 'nonce="' not in r.text
        # 3.7.5 byte-identity: no feature-detect banner over cleartext loopback (nonce None -> not
        # emitted; the loopback ``script-src 'self'`` CSP would otherwise block an un-nonced inline script)
        assert "window.isSecureContext" not in r.text
        assert "mf-insecure-context-banner" not in r.text
        # the pre-existing hardening still applies (engine seam untouched)
        assert r.headers["cache-control"] == "no-store"
        assert r.headers["x-frame-options"] == "DENY"


# --- ADR 0143: the loopback secure-context hybrid (headers engage, cookie stays plain) ------------


async def test_loopback_http_engages_headers_but_keeps_plain_cookie(engine: Engine) -> None:
    """ADR 0143 HYBRID: over a loopback secure-context (http://127.0.0.1, ``app.state.loopback``) the
    http-SAFE headers ENGAGE (nonce-CSP + COOP + CORP + Reporting-Endpoints), but the session cookie
    STAYS the plain ``mf_session`` (no Secure / __Host-) — a browser rejects a Secure/__Host- cookie
    over http, so keying the cookie on loopback would break login. The two are CONSISTENT: headers on,
    cookie plain, and the plain cookie still authenticates the dashboard. HSTS stays OFF (no auto-TLS)."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service, scheme="http", loopback=True) as c:
        # the http-safe hardening engages on the /ui HTML surface even over cleartext http
        page = await c.get("/ui/login")
        csp = page.headers["content-security-policy"]
        assert _NONCE_RE.search(csp), csp
        assert "strict-dynamic" in csp and "frame-ancestors 'none'" in csp
        assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
        assert page.headers["cross-origin-opener-policy"] == "same-origin"
        assert page.headers["cross-origin-resource-policy"] == "same-origin"
        assert page.headers["reporting-endpoints"] == 'mf-csp="/ui/csp-report"'
        # HSTS stays OFF over loopback http (no auto-TLS on loopback — ADR 0143)
        assert "strict-transport-security" not in {k.lower() for k in page.headers}
        # the session cookie STAYS the plain mf_session — NOT __Host-, NO Secure
        r = await _login(c, "op")
        set_cookie = r.headers["set-cookie"]
        low = set_cookie.lower()
        assert set_cookie.split("=", 1)[0] == "mf_session"
        assert "__host-" not in low and "secure" not in low
        assert "httponly" in low and "samesite=strict" in low
        # headers-on + cookie-plain are consistent: the plain cookie still authenticates the dashboard
        assert (await c.get("/ui")).status_code == 200


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
    """Unit-level: the normaliser handles both delivery shapes and hostile input without raising, and
    the summariser bounds every field. ``_csp_report_bodies`` returns a LIST (ASVS 3.7.5): a
    Reporting-API POST batches reports, and collapsing the batch to its first entry is what let a real
    violation be classified by the enforcement canary sitting in front of it."""
    from messagefoundry_webconsole.routes.core import _csp_report_bodies, _csp_report_summary

    legacy = _csp_report_bodies(
        {
            "csp-report": {
                "document-uri": "u",
                "violated-directive": "script-src",
                "blocked-uri": "b",
            }
        }
    )
    assert legacy is not None and len(legacy) == 1
    summary = _csp_report_summary(legacy[0])
    assert "document-uri=u" in summary and "violated-directive=script-src" in summary
    modern = _csp_report_bodies(
        [
            {"body": {"documentURL": "u", "effectiveDirective": "script-src", "blockedURL": "b"}},
            {"body": {"blockedURL": "inline"}},
        ]
    )
    # EVERY entry survives normalization — not just the first
    assert modern is not None and len(modern) == 2
    assert "document-uri=u" in _csp_report_summary(modern[0])
    assert "blocked-uri=inline" in _csp_report_summary(modern[1])
    assert _csp_report_bodies({}) == [{}]
    assert _csp_report_bodies([]) == []
    assert _csp_report_bodies("hostile") is None
    assert _csp_report_bodies(12345) is None
    assert _csp_report_summary({}) == "empty"
    # a huge field is bounded (256 chars per value)
    big = _csp_report_summary({"document-uri": "x" * 5000})
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
        assert "window.isSecureContext" not in page.text  # opt-out reverts -> banner not emitted
        # the reverted plain cookie still authenticates (name resolver agrees on read)
        assert (await c.get("/ui")).status_code == 200


# --- BACKLOG #1117: the CLEAR site consults the same conjuncts as the SET site --------------------
#
# The set site keys Secure on ``effective_https`` ALONE and the name on ``effective_https AND
# browser_hardening_enabled()``. The clear site used to infer Secure from the resolved NAME, so under
# the org opt-out over https it took the unprefixed branch and reached Starlette's ``delete_cookie``
# defaults (``secure=False, httponly=False, samesite="lax"``) -- dropping three attributes the set
# had just written. These pin the two sites to one expression.


def _cookie_request(scheme: str, *, exposure_protected: bool = False) -> StarletteRequest:
    """A bare Request carrying only what the cookie helpers read: the scheme and ``app.state``."""
    return StarletteRequest(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "scheme": scheme,
            "path": "/ui/logout",
            "raw_path": b"/ui/logout",
            "query_string": b"",
            "root_path": "",
            "headers": [(b"host", b"t")],
            "client": ("127.0.0.1", 1234),
            "server": ("t", 443 if scheme == "https" else 80),
            "app": SimpleNamespace(
                state=SimpleNamespace(exposure_protected=exposure_protected, loopback=False)
            ),
        }
    )


#: The attributes a browser reads as security posture. Deliberately NOT the whole attribute set: a
#: deletion also carries ``max-age``/``expires``, which the set legitimately does not.
_GUARD_ATTRS = ("secure", "httponly", "samesite")


def _guards(response: StarletteResponse) -> tuple[str, dict[str, str]]:
    """The cookie NAME plus its security attributes, from the one ``Set-Cookie`` on the response."""
    lines = [v.decode() for k, v in response.raw_headers if k == b"set-cookie"]
    assert len(lines) == 1, lines
    head, _, rest = lines[0].partition(";")
    attrs: dict[str, str] = {}
    for part in rest.split(";"):
        if not part.strip():
            continue
        key, _, value = part.strip().partition("=")
        if key.strip().lower() in _GUARD_ATTRS:
            attrs[key.strip().lower()] = value.strip().lower()
    return head.split("=", 1)[0], attrs


_POSTURES = [
    pytest.param("https", True, id="https-hardened"),
    pytest.param("https", False, id="https-org-opt-out"),
    pytest.param("http", True, id="cleartext-hardened"),
    pytest.param("http", False, id="cleartext-org-opt-out"),
]


@pytest.mark.parametrize(("scheme", "hardening"), _POSTURES)
def test_session_clear_carries_the_same_guards_as_the_set(
    scheme: str, hardening: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On EVERY posture the session deletion carries the same name, Secure, HttpOnly and SameSite as
    the emission it revokes. A deletion that drops Secure is a cookie written without Secure, which is
    what ASVS 3.3.1 grades -- and one that drops HttpOnly hands script a name the set had hidden."""
    if hardening:
        monkeypatch.delenv(BROWSER_HARDENING_OPT_OUT_ENV, raising=False)
    else:
        monkeypatch.setenv(BROWSER_HARDENING_OPT_OUT_ENV, "1")
    request = _cookie_request(scheme)

    written = StarletteResponse()
    set_session_cookie(written, "a-token", request=request)
    cleared = StarletteResponse()
    clear_session_cookie(cleared, request)

    set_name, set_attrs = _guards(written)
    clear_name, clear_attrs = _guards(cleared)
    # the positive control: the instrument DOES see Secure move with the scheme, so an all-passing
    # comparison below cannot be two empty dicts agreeing with each other.
    assert ("secure" in set_attrs) is (scheme == "https"), set_attrs
    assert clear_name == set_name
    assert clear_attrs == set_attrs


@pytest.mark.parametrize(("scheme", "hardening"), _POSTURES)
def test_oidc_flow_clear_carries_the_same_guards_as_the_set(
    scheme: str, hardening: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same symmetry for the ADR 0142 flow cookie, whose clear runs on EVERY terminal callback --
    so it is the more frequently emitted of the two deletions, not the rarer one."""
    if hardening:
        monkeypatch.delenv(BROWSER_HARDENING_OPT_OUT_ENV, raising=False)
    else:
        monkeypatch.setenv(BROWSER_HARDENING_OPT_OUT_ENV, "1")
    request = _cookie_request(scheme)

    written = StarletteResponse()
    set_oidc_flow_cookie(written, "a-flow-id", request=request, max_age=300)
    cleared = StarletteResponse()
    clear_oidc_flow_cookie(cleared, request)

    set_name, set_attrs = _guards(written)
    clear_name, clear_attrs = _guards(cleared)
    assert ("secure" in set_attrs) is (scheme == "https"), set_attrs
    assert clear_name == set_name
    assert clear_attrs == set_attrs


def test_session_clear_follows_exposure_protected_not_only_the_wire_scheme() -> None:
    """The ``tls_terminated_upstream`` topology ADR 0172 deliberately excludes: the engine speaks
    plaintext to a declared proxy, so the wire scheme is http while the BROWSER's origin is https and
    ``exposure_protected`` is true. The set writes Secure there; so must the clear."""
    request = _cookie_request("http", exposure_protected=True)
    written = StarletteResponse()
    set_session_cookie(written, "a-token", request=request)
    cleared = StarletteResponse()
    clear_session_cookie(cleared, request)
    assert "secure" in _guards(written)[1]  # control: the set really does key on the declaration
    assert _guards(cleared) == _guards(written)


# --- BACKLOG #1118 / ASVS 3.3.3: the prefix on the one topology that still speaks cleartext -------


def test_upstream_terminator_emits_the_host_prefixed_names_over_a_cleartext_wire() -> None:
    """Both cookies carry the ``__Host-`` prefix on the ``tls_terminated_upstream`` topology, whose
    wire scheme is http.

    ADR 0172 makes the engine always serve TLS, so the shipped default is https and the prefix falls
    out of code that was already correct. The declared-proxy topology is the one ADR 0172 excludes:
    the proxy terminates TLS in front and speaks plaintext to the engine, so minting here would break
    the proxy's own hop and the engine mints nothing. The BROWSER's origin is still https, which is
    what the prefix is about, and ``effective_https`` reaches that fact only through its
    ``exposure_protected`` disjunct.

    **Why the NAME needs its own arm.** The sibling above builds this exact posture but grades Secure
    and set/clear symmetry. Deleting the disjunct does turn it red -- measured -- yet it reports a
    lost Secure attribute, which sends a reader to the wrong conjunct. Nothing anywhere asserted what
    the name IS on the one topology that still reaches the app over a cleartext wire, and every other
    cleartext test in this file runs with ``exposure_protected`` false.
    """
    proxied = _cookie_request("http", exposure_protected=True)
    session = StarletteResponse()
    set_session_cookie(session, "a-token", request=proxied)
    flow = StarletteResponse()
    set_oidc_flow_cookie(flow, "a-flow-id", request=proxied, max_age=300)
    assert _guards(session)[0] == "__Host-mf_session"
    assert _guards(flow)[0] == "__Host-mf_oidc_flow"

    # NEGATIVE CONTROL -- the same cleartext wire with NO declaration is a genuinely plaintext bind,
    # where the bare name is correct: a browser rejects a `__Host-` cookie that is not Secure. Without
    # this arm the assertions above would also pass if the resolver had been hard-coded to the prefix.
    plain = _cookie_request("http", exposure_protected=False)
    bare_session = StarletteResponse()
    set_session_cookie(bare_session, "a-token", request=plain)
    bare_flow = StarletteResponse()
    set_oidc_flow_cookie(bare_flow, "a-flow-id", request=plain, max_age=300)
    assert _guards(bare_session)[0] == "mf_session"
    assert _guards(bare_flow)[0] == "mf_oidc_flow"
    assert "secure" not in _guards(bare_session)[1]  # and it is Secure-less, which is why


_NAME_POSTURES = [
    pytest.param("https", False, True, id="shipped-default-https"),
    pytest.param("http", True, True, id="upstream-terminator"),
    pytest.param("http", False, True, id="genuinely-plaintext"),
    pytest.param("https", False, False, id="https-org-opt-out"),
]


@pytest.mark.parametrize(("scheme", "exposure", "hardening"), _NAME_POSTURES)
def test_the_name_a_response_writes_is_the_name_a_later_request_reads(
    scheme: str, exposure: bool, hardening: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On every posture the SET writes the same cookie name the READ looks for (BACKLOG #1118).

    ``session_cookie_name`` calls itself "the ONE resolver every set/clear/read site threads through,
    so the name a response writes and the name a later request reads always agree". The clear and read
    sites did thread through it; **the two SET sites recomputed the same expression inline**, so the
    guarantee the docstring asserted did not structurally exist -- a compensating control resting on a
    false premise (SDS-3.7). The expressions agreed, so nothing was wrong on the wire; an edit to
    either copy alone is what this closes.

    The failure that split would produce is silent and total: the browser holds the name the set
    wrote, ``session_token`` asks for the name the resolver returns, finds nothing, and the operator
    is bounced back to login forever with no error naming a cause.
    """
    if hardening:
        monkeypatch.delenv(BROWSER_HARDENING_OPT_OUT_ENV, raising=False)
    else:
        monkeypatch.setenv(BROWSER_HARDENING_OPT_OUT_ENV, "1")
    request = _cookie_request(scheme, exposure_protected=exposure)

    session = StarletteResponse()
    set_session_cookie(session, "a-token", request=request)
    flow = StarletteResponse()
    set_oidc_flow_cookie(flow, "a-flow-id", request=request, max_age=300)

    assert _guards(session)[0] == session_cookie_name(request)
    assert _guards(flow)[0] == oidc_flow_cookie_name(request)
    # VACUITY CONTROL: the resolver is not a constant across this parametrisation, so the equalities
    # above are comparing something that actually moves.
    expected_prefixed = (scheme == "https" or exposure) and hardening
    assert session_cookie_name(request).startswith("__Host-") is expected_prefixed


async def test_opt_out_logout_over_https_still_deletes_with_secure(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End to end through the real logout route, on the posture that used to lose three attributes:
    the org opt-out over https."""
    monkeypatch.setenv(BROWSER_HARDENING_OPT_OUT_ENV, "1")
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service, scheme="https") as c:
        await _login(c, "op")
        out = await c.post("/ui/logout")
        assert out.status_code == 303
        set_cookie = out.headers["set-cookie"]
        low = set_cookie.lower()
        assert set_cookie.split("=", 1)[0] == "mf_session"  # opt-out keeps the bare name
        assert "secure" in low and "httponly" in low and "samesite=strict" in low
        # and the deletion really ended the session
        assert (await c.get("/ui")).status_code in (302, 303, 401)
