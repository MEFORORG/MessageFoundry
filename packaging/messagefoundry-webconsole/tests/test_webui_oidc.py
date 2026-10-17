# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""/ui federated login legs (ADR 0142), the browser's address on console actions (ADR 0150), the search
form, the login deadline, and a replayed cookie from a second address."""

from __future__ import annotations

import asyncio
import json
import re
import time
from pathlib import Path
from urllib.parse import parse_qsl, quote, urlsplit

import httpx
import pytest
from _ui_clients import create_local_user_chosen
from _webui_support import (
    PW,
    _add,
    _add_with_role_ids,
    _boss_client,
    _client,
    _cookie_login,
    _post_pairs,
    _seed,
    _service,
    _uid,
)

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.passwords import hash_password
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.pipeline import Engine

# --- W4-5 (ADR 0142): the browser federated-login legs ---------------------------------------------
# Mock-seam coverage only, and a DEEPER mock stack than the Kerberos block above (fake IdP + fake JWKS
# + fake LDAP): no real IdP exists in test infra. Real-IdP evidence is lab runbook cells L6a-L18.


def _oidc_settings(**over: object) -> AuthSettings:
    base: dict[str, object] = {
        "ad_enabled": True,
        "ad_server": "ldaps://x",
        "ad_user_search_base": "DC=x",
        "ad_bind_dn": "CN=svc,DC=x",
        "ad_bind_password": "x",
        "ad_domain": "corp.example",
        "oidc_enabled": True,
        "oidc_issuer": "https://idp.example",
        "oidc_client_id": "mefor-console",
        "oidc_client_secret": "shhh",
        "oidc_authorization_endpoint": "https://idp.example/authorize",
        "oidc_token_endpoint": "https://idp.example/token",
        "oidc_jwks_uri": "https://idp.example/jwks",
        "oidc_allowed_endpoints": ["idp.example"],
        # The start-to-callback floor is off: these callbacks return at machine speed (BACKLOG #2301).
        "oidc_callback_min_elapsed_seconds": 0,
    }
    base.update(over)
    return AuthSettings(**base)  # type: ignore[arg-type]


def _oidc_service(engine: Engine, **over: object) -> AuthService:
    from messagefoundry.auth.ldap import AdPrincipal, DirectoryAnswer, DirectoryBind

    principal = AdPrincipal(
        username="jdoe",
        display_name="J Doe",
        email="j@x",
        dn="CN=jdoe,DC=x",
        groups=frozenset({"cn=mf-admins,dc=x"}),
        # BACKLOG #1143 slice C: a bindable row carries the directory's objectGUID.
        directory_object_id="guid-jdoe",
    )

    class _FakeLdap:
        def authenticate(self, username: str, password: str, **_: object) -> DirectoryBind:
            if username != "jdoe":
                return DirectoryBind(DirectoryAnswer.NOT_FOUND)
            return DirectoryBind(DirectoryAnswer.FOUND, principal)

        def resolve_principal(
            self, username: str, *, object_id: str | None = None
        ) -> AdPrincipal | None:
            return principal if username == "jdoe" else None

    return AuthService(engine.store, _oidc_settings(**over), ldap=_FakeLdap())  # type: ignore[arg-type]


def _oidc_client(
    engine: Engine, service: AuthService, *, peer: str = "127.0.0.1"
) -> httpx.AsyncClient:
    # public_origin is required: the redirect_uri derives from it, never from the Host header.
    app = create_app(engine, auth=service, serve_ui=True, public_origin="https://ops.example")
    transport = httpx.ASGITransport(app=app, client=(peer, 123))
    return httpx.AsyncClient(transport=transport, base_url="http://t")


async def _oidc_audits(engine: Engine) -> list[str]:
    audit = await engine.store.list_audit()
    needle = '"mech": "oidc"'
    return [str(a["detail"]) for a in audit if a["detail"] and needle in str(a["detail"])]


async def test_oidc_routes_absent_when_disabled(engine: Engine) -> None:
    """AC-1: with federation off the legs are not registered AT ALL - not merely disabled. The
    unchanged tests/golden/ui_routes.txt is the other half of this proof."""
    service = await _service(engine)
    async with _client(engine, service) as c:
        for path in ("/ui/oidc/start", "/ui/oidc/callback"):
            assert (await c.get(path)).status_code == 404
        assert "/ui/oidc/start" not in (await c.get("/ui/login")).text


async def test_oidc_login_link_tracks_availability(engine: Engine) -> None:
    service = _oidc_service(engine)
    await service.initialize()
    async with _oidc_client(engine, service) as c:
        assert "/ui/oidc/start" in (await c.get("/ui/login")).text
        # Non-sticky: a known-down IdP hides the LINK, but the route stays registered so the start
        # leg can still attempt per-request and recover without a restart (AC-8).
        service.mark_oidc_unavailable("boom")
        assert "/ui/oidc/start" not in (await c.get("/ui/login")).text
        # BOTH outcomes are 303, so the status alone cannot tell AC-8 compliance from the exact
        # regression this guards. Assert the DESTINATION: the start leg must still reach the IdP
        # while the advisory flag is set, not bounce to ?e=oidc_unavailable.
        # ASVS 3.7.3: flow-minting moved to the POST leg — the GET now renders the "leaving this
        # site" interstitial and stages nothing. AC-8 is a property of the leg that ATTEMPTS, so
        # this targets the POST.
        r = await c.post("/ui/oidc/start", follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"].startswith("https://idp.example/authorize?")


@pytest.mark.parametrize(
    ("status", "link_stays"),
    [(400, True), (401, True), (503, True), (None, False)],
    ids=["400", "401", "503", "transport-failure"],
)
async def test_a_bad_authorization_code_cannot_hide_the_oidc_link(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, status: int | None, link_stays: bool
) -> None:
    """BACKLOG #1948, driven as a signed-out caller would: start a flow, then call back with a code
    the token endpoint refuses. The real ``exchange_code`` runs against an opener that answers
    ``status``, so the sequence reaches the service the way it would live.

    Any received status is the endpoint answering. A 400 is RFC 6749's ``invalid_grant``, the
    caller's own doing, and the link and ``/auth/providers`` must survive it, or any visitor could
    switch federated sign-in off. A 401 is the engine's own secret, and it is audited rather than
    hidden, so that no body has to be read to tell the two apart. A 503 no longer hides the link
    either (Manager decision 2026-10-06): a faulty IdP may answer a caller's bad code with one, and
    this arm used to pin the opposite. The transport-failure arm is the control: an IdP no answer
    arrives from must still hide the link, so this test can fail."""
    import io
    import urllib.error

    class _TokenEndpoint:
        def open(self, req: object, timeout: float = 0.0) -> object:
            if status is None:
                raise urllib.error.URLError(ConnectionRefusedError("connection refused"))
            raise urllib.error.HTTPError(
                "https://idp.example/token",
                status,
                "refused",
                {},  # type: ignore[arg-type]
                io.BytesIO(b'{"error":"invalid_grant"}'),
            )

    async def _no_pad(_deadline: float) -> None:
        return None

    monkeypatch.setattr("messagefoundry.auth.service._sleep_until", _no_pad)
    service = _oidc_service(engine)
    await service.initialize()
    service._oidc_opener = _TokenEndpoint()  # type: ignore[assignment]
    async with _oidc_client(engine, service) as c:
        start = await c.post("/ui/oidc/start", follow_redirects=False)
        state = dict(parse_qsl(urlsplit(start.headers["location"]).query))["state"]
        r = await c.get(
            "/ui/oidc/callback",
            params={"code": "not-a-code-the-idp-issued", "state": state},
            headers={
                "Sec-Fetch-Site": "cross-site",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Dest": "document",
            },
            follow_redirects=False,
        )
        assert r.status_code == 303 and r.headers["location"] == "/ui/login?e=oidc_failed"
        assert ("/ui/oidc/start" in (await c.get("/ui/login")).text) is link_stays
        assert (await c.get("/auth/providers")).json()["oidc"] is link_stays
    assert service.oidc_available is link_stays


async def test_oidc_start_redirects_to_the_idp_and_sets_the_flow_cookie(engine: Engine) -> None:
    service = _oidc_service(engine)
    await service.initialize()
    async with _oidc_client(engine, service) as c:
        # ASVS 3.7.3: the GET renders the interstitial and mints NOTHING; the 303 + PKCE params +
        # flow cookie this test is about now belong to the POST leg. Asserted here rather than
        # retargeted silently, because "the start leg 303s to the IdP" stopped being true of the GET.
        interstitial = await c.get("/ui/oidc/start", follow_redirects=False)
        assert interstitial.status_code == 200
        assert "leaving" in interstitial.text.lower()
        assert "set-cookie" not in {k.lower() for k in interstitial.headers}
        r = await c.post("/ui/oidc/start", follow_redirects=False)
        assert r.status_code == 303
        location = r.headers["location"]
        assert location.startswith("https://idp.example/authorize?")
        assert "code_challenge_method=S256" in location
        assert "response_type=code" in location
        # The redirect_uri is built from public_origin, NOT the request Host.
        assert quote("https://ops.example/ui/oidc/callback", safe="") in location
        cookie = r.headers.get("set-cookie", "")
        assert "mf_oidc_flow=" in cookie
        # SameSite=Lax, NOT Strict: Lax is what survives the IdP top-level cross-site GET return.
        assert "samesite=lax" in cookie.lower()
        assert "httponly" in cookie.lower()


async def test_oidc_callback_without_the_flow_cookie_is_refused(engine: Engine) -> None:
    """AC-7: a valid (state, code) pair with no browser binding must not mint a session - otherwise
    whoever presents the pair gets the session minted into THEIR browser.

    The reject row records the caller's address (vault BACKLOG #2132): a spray of cookie-less
    callbacks is the cheapest one to send, and the operator needs its source."""
    service = _oidc_service(engine)
    await service.initialize()
    async with _oidc_client(engine, service, peer="192.0.2.46") as c:
        r = await c.get("/ui/oidc/callback?code=abc&state=xyz", follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] == "/ui/login?e=flow_binding_missing"
        assert "mf_session" not in r.headers.get("set-cookie", "")
        assert any("flow_binding_missing" in d for d in await _oidc_audits(engine))
    [row] = [
        a
        for a in await engine.store.list_audit(action="auth.login_failed")
        if "flow_binding_missing" in (a["detail"] or "")
    ]
    assert row["client"] == "192.0.2.46"


@pytest.mark.parametrize(
    ("reason", "slug"),
    [
        ("start_non_navigation_fetch", "non_navigation_fetch"),
        ("start_failed", "start_failed"),
        ("callback_non_navigation_fetch", "non_navigation_fetch"),
        ("idp_error", "idp_error"),
        ("malformed_callback", "malformed_callback"),
    ],
)
async def test_every_other_oidc_route_reject_records_the_client(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, reason: str, slug: str
) -> None:
    """Vault BACKLOG #3197. The other five ``/ui/oidc`` route rejects, beside the cookie-less
    callback above: each writes its closed-set reason under ``auth.login_failed`` with the caller's
    address, so a spray of any of them shows its source (#2132). The control for each arm is its
    own reason: the row asserted is the one this reject writes, not a row from some other refusal."""
    from messagefoundry.auth import oidc as _oidc

    service = _oidc_service(engine)
    await service.initialize()
    probe = {"Sec-Fetch-Mode": "cors"}
    async with _oidc_client(engine, service, peer="192.0.2.47") as c:
        if reason == "start_non_navigation_fetch":
            r = await c.post("/ui/oidc/start", headers=probe, follow_redirects=False)
        elif reason == "start_failed":

            async def refuse(**_kw: object) -> tuple[str, str]:
                raise _oidc.FlowError("refused")

            monkeypatch.setattr(service, "begin_oidc_login", refuse)
            r = await c.post("/ui/oidc/start", follow_redirects=False)
        else:
            # A real flow, because an error= or malformed callback is audited under its own reason
            # only once its state matches (BACKLOG #3198).
            start = await c.post("/ui/oidc/start", follow_redirects=False)
            state = dict(parse_qsl(urlsplit(start.headers["location"]).query))["state"]
            query = {
                "callback_non_navigation_fetch": "?code=abc&state=xyz",
                "idp_error": "?error=access_denied&state=" + quote(state),
                "malformed_callback": "?state=" + quote(state),
            }[reason]
            headers = probe if reason == "callback_non_navigation_fetch" else {}
            r = await c.get("/ui/oidc/callback" + query, headers=headers, follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] == "/ui/login?e=oidc_failed"
        if reason == "callback_non_navigation_fetch":
            # BACKLOG #3198: a refusal that consumed nothing keeps the flow cookie, so a same-site
            # fetch cannot clear it and cancel the sign-in in flight.
            assert "mf_oidc_flow" not in r.headers.get("set-cookie", "")
    rows = [
        a
        for a in await engine.store.list_audit(action="auth.login_failed")
        if json.loads(a["detail"] or "{}").get("reason") == slug
    ]
    assert len(rows) == 1, rows
    assert rows[0]["client"] == "192.0.2.47"


@pytest.mark.parametrize(
    "query",
    ["?error=access_denied", "?error=access_denied&state=forged", "?code=abc", "?state=forged"],
    ids=["error-no-state", "error-wrong-state", "code-no-state", "no-code-wrong-state"],
)
async def test_a_forged_error_or_malformed_callback_keeps_the_sign_in_in_flight(
    engine: Engine, query: str
) -> None:
    """BACKLOG #3198. RED when: the sign-in leg ends its flow on an ``error=`` or malformed callback
    without checking ``state``. Any page can send the browser here with the SameSite=Lax flow
    cookie, so that let a forged ``?error=`` cancel the sign-in in flight. The forged callback is
    refused as ``state_mismatch`` and keeps the flow and the cookie. The control is the IdP's own
    ``error=`` with the flow's ``state``, which ends the flow and clears the cookie."""
    service = _oidc_service(engine)
    await service.initialize()
    assert service._oidc_flows is not None
    async with _oidc_client(engine, service) as c:
        start = await c.post("/ui/oidc/start", follow_redirects=False)
        state = dict(parse_qsl(urlsplit(start.headers["location"]).query))["state"]
        flow_id = c.cookies.get("mf_oidc_flow")
        assert flow_id

        forged = await c.get("/ui/oidc/callback" + query, follow_redirects=False)
        assert forged.status_code == 303
        assert forged.headers["location"] == "/ui/login?e=oidc_failed"
        assert "mf_oidc_flow" not in forged.headers.get("set-cookie", "")
        assert service._oidc_flows.peek(flow_id) is not None
        assert any('"reason": "state_mismatch"' in d for d in await _oidc_audits(engine))

        real = await c.get(
            "/ui/oidc/callback?error=access_denied&state=" + quote(state), follow_redirects=False
        )
        assert real.status_code == 303
        assert "mf_oidc_flow=" in real.headers.get("set-cookie", "")
        assert service._oidc_flows.peek(flow_id) is None
        assert any('"reason": "idp_error"' in d for d in await _oidc_audits(engine))


async def test_a_forged_state_callback_keeps_the_flow_and_its_cookie(engine: Engine) -> None:
    """BACKLOG #3198: a callback with a wrong ``state`` consumes nothing. Any page can send the
    browser here with the SameSite=Lax flow cookie, so clearing that cookie, or popping the flow,
    would let a forged callback cancel the sign-in in flight. The flow and the cookie both wait for
    the real IdP return."""
    service = _oidc_service(engine)
    await service.initialize()
    async with _oidc_client(engine, service) as c:
        start = await c.post("/ui/oidc/start", follow_redirects=False)
        state = dict(parse_qsl(urlsplit(start.headers["location"]).query))["state"]
        flow_id = c.cookies.get("mf_oidc_flow")
        assert flow_id
        r = await c.get(
            "/ui/oidc/callback",
            params={"code": "authcode", "state": "forged-" + state},
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert r.headers["location"] == "/ui/login?e=flow_binding_missing"
        assert "mf_oidc_flow" not in r.headers.get("set-cookie", "")
        assert c.cookies.get("mf_oidc_flow") == flow_id
        assert service._oidc_flows is not None
        assert service._oidc_flows.peek(flow_id) is not None
        assert any("state_mismatch" in d for d in await _oidc_audits(engine))


async def test_oidc_callback_survives_a_cross_site_navigation(engine: Engine) -> None:
    """The IdP redirect back is LEGITIMATELY Sec-Fetch-Site: cross-site. If a same-origin assertion
    were added here every real login would 403 while every hermetic test still passed."""
    service = _oidc_service(engine)
    await service.initialize()
    async with _oidc_client(engine, service) as c:
        r = await c.get(
            "/ui/oidc/callback?code=abc&state=xyz",
            headers={
                "Sec-Fetch-Site": "cross-site",
                "Sec-Fetch-Mode": "navigate",
                # The IdP's redirect back IS a top-level navigation and carries this. #1122 made the
                # middleware's destination check an allowlist; note it deliberately does NOT also
                # demand Sec-Fetch-User, because this hop has none when the IdP session is already
                # established.
                "Sec-Fetch-Dest": "document",
            },
            follow_redirects=False,
        )
        # Refused for the MISSING COOKIE, not for being cross-site (403 would mean the wrong gate).
        assert r.status_code == 303
        assert r.headers["location"] == "/ui/login?e=flow_binding_missing"


async def test_oidc_callback_never_reflects_idp_error_text(engine: Engine) -> None:
    service = _oidc_service(engine)
    await service.initialize()
    async with _oidc_client(engine, service) as c:
        c.cookies.set("mf_oidc_flow", "someflow")
        r = await c.get(
            "/ui/oidc/callback?error=" + quote("<script>alert(1)</script>"),
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert r.headers["location"] == "/ui/login?e=oidc_failed"
        assert "script" not in r.headers["location"]


async def test_oidc_rate_limit_writes_no_audit_rows(engine: Engine) -> None:
    """Both legs are unauthenticated, so an attacker looping them must not be an unbounded audit-write
    amplifier. Mirrors the Kerberos anti-flood invariant."""
    service = _oidc_service(engine)
    await service.initialize()
    async with _oidc_client(engine, service) as c:
        seen_limit = False
        for _ in range(40):
            r = await c.get("/ui/oidc/callback?code=a&state=b", follow_redirects=False)
            if r.headers.get("location") == "/ui/login?e=rate_limited":
                seen_limit = True
                break
        assert seen_limit, "expected the shared login limiter to engage"
        before = len(await _oidc_audits(engine))
        for _ in range(20):
            await c.get("/ui/oidc/callback?code=a&state=b", follow_redirects=False)
        assert len(await _oidc_audits(engine)) == before  # throttled attempts write ZERO rows


async def test_oidc_full_round_trip_lands_a_session_via_meta_refresh(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Start -> IdP -> callback, with the token endpoint and JWKS faked. The callback must be 200 HTML
    with a meta refresh, NOT a 303: the session cookie is SameSite=Strict and would be withheld on a
    follow-up navigation the browser still considers cross-site-initiated."""
    import json as _json
    import time as _time

    from cryptography.hazmat.primitives import serialization as _ser
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa

    from messagefoundry.auth import oidc as _oidc
    from messagefoundry.config.models import SignatureAlgorithm as _Alg
    from messagefoundry.transports.signing import CompactJwtSigner as _Signer

    key = _rsa.generate_private_key(public_exponent=65537, key_size=3072)

    def _b64u_uint(v: int) -> str:
        import base64 as _b64

        raw = v.to_bytes((v.bit_length() + 7) // 8, "big")
        return _b64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    nums = key.public_key().public_numbers()
    jwk = {
        "kty": "RSA",
        "kid": "k1",
        "use": "sig",
        "alg": "RS256",
        "n": _b64u_uint(nums.n),
        "e": _b64u_uint(nums.e),
    }
    jwks = _json.dumps({"keys": [jwk]}).encode()

    service = _oidc_service(engine)
    service._oidc_jwks = _oidc.JwksCache(lambda: jwks)
    await service.initialize()
    await service.set_ad_group_map([("cn=mf-admins,dc=x", "administrator")], actor="admin")
    # BACKLOG #1143 (ADR 0184): a federated login selects its account by the (issuer, sub) pair and
    # never binds, so the account is bound through the admin path first.
    await engine.store.create_user(
        user_id="f" * 32,
        username="jdoe",
        auth_provider="ad",
        directory_object_id="guid-jdoe",
        password_generated=False,
    )
    await service.bind_federated_subject(
        "f" * 32, "S-1-5-21-fed", expected_issuer=None, expected_subject=None, actor="admin"
    )

    async with _oidc_client(engine, service) as c:
        # ASVS 3.7.3: a real operator now traverses the interstitial, so the round trip does too --
        # GET renders "you are leaving this site" and stages nothing, the Continue POST mints the
        # flow and 303s. Kept as two hops rather than shortcut to the POST: this test's value is that
        # it walks the path a browser actually walks.
        leaving = await c.get("/ui/oidc/start", follow_redirects=False)
        assert leaving.status_code == 200
        assert "leaving" in leaving.text.lower()
        start = await c.post("/ui/oidc/start", follow_redirects=False)
        assert start.status_code == 303
        params = dict(parse_qsl(urlsplit(start.headers["location"]).query))
        flow_id = c.cookies.get("mf_oidc_flow")
        assert flow_id

        pem = key.private_bytes(
            encoding=_ser.Encoding.PEM,
            format=_ser.PrivateFormat.PKCS8,
            encryption_algorithm=_ser.NoEncryption(),
        ).decode("ascii")
        now = _time.time()
        id_token = _Signer(
            private_key=pem,
            algorithm=_Alg.RS256,
            key_id="k1",
            setting="test_idp_signing_key",
        ).sign(
            {
                "iss": "https://idp.example",
                "aud": "mefor-console",
                "sub": "S-1-5-21-fed",
                "exp": now + 600,
                "iat": now,
                "auth_time": now,  # REQUIRED since BACKLOG #1150 (max_age is always requested)
                "nonce": params["nonce"],
                "preferred_username": "jdoe@corp.example",
                "amr": ["pwd", "mfa"],
            }
        )
        monkeypatch.setattr(_oidc, "exchange_code", lambda **kw: {"id_token": id_token})

        r = await c.get(
            "/ui/oidc/callback?code=authcode&state=" + quote(params["state"]),
            headers={
                "Sec-Fetch-Site": "cross-site",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Dest": "document",  # what a browser sends; see #1122
            },
            follow_redirects=False,
        )
        assert r.status_code == 200, r.text
        head = r.text.split("</head>")[0]
        assert 'http-equiv="refresh"' in head and "0;url=/ui" in head
        assert "<script>" not in r.text  # CSP-compatible: no inline JS in the landing hop
        set_cookie = r.headers.get("set-cookie", "")
        assert "mf_session=" in set_cookie
        assert "samesite=strict" in set_cookie.lower()  # the SESSION cookie stays Strict

        # The flow is single-use SERVER-side. Re-presenting the original flow cookie by hand is
        # what proves that: the success response cleared the cookie, so a plain replay would be
        # refused by the missing-cookie branch and would pass even if the cache were replayable.
        replay = await c.get(
            "/ui/oidc/callback?code=authcode&state=" + quote(params["state"]),
            headers={"Cookie": "mf_oidc_flow=" + flow_id},
            follow_redirects=False,
        )
        assert replay.status_code == 303
        assert replay.headers["location"] == "/ui/login?e=flow_binding_missing"
        assert "mf_session=" not in replay.headers.get("set-cookie", "")
        assert any("state_unknown" in d for d in await _oidc_audits(engine))


def _managed_oidc_app(tmp_path: object, *, oidc_enabled: bool) -> object:
    """Build the app the way `messagefoundry serve` does — via create_managed_app.

    This is NOT the same construction path as `_oidc_client` above. create_managed_app attaches the
    AuthService inside the LIFESPAN, after mount_ui has already fixed the route table, whereas
    create_app(auth=...) sets app.state.auth before mounting. A registrar that gated on
    app.state.auth therefore registered nothing under `serve` while passing every other test here.
    """
    from messagefoundry.api import create_managed_app

    extra: dict[str, object] = {}
    if oidc_enabled:
        extra = {
            "oidc_issuer": "https://idp.example",
            "oidc_client_id": "mefor-console",
            "oidc_client_secret": "shhh",
            "oidc_authorization_endpoint": "https://idp.example/authorize",
            "oidc_token_endpoint": "https://idp.example/token",
            "oidc_jwks_uri": "https://idp.example/jwks",
            "oidc_allowed_endpoints": ["idp.example"],
        }
    settings = AuthSettings(
        ad_enabled=True,
        ad_server="ldaps://x",
        ad_user_search_base="DC=x",
        ad_bind_dn="CN=svc,DC=x",
        ad_bind_password="x",
        ad_domain="corp.example",
        oidc_enabled=oidc_enabled,
        **extra,  # type: ignore[arg-type]
    )
    return create_managed_app(
        db_path=str(tmp_path / "prod.db"),  # type: ignore[operator]
        auth_settings=settings,
        serve_ui=True,
        public_origin="https://ops.example",
        egress_settings=EgressSettings(deny_by_default=False),
    )


def test_oidc_routes_register_on_the_production_serve_path(tmp_path: Path) -> None:
    """REGRESSION (found by review, not by the suite): the registrar must gate on injected CONFIG,
    never on app.state.auth. Under create_managed_app the AuthService is attached in the lifespan,
    long after mount_ui fixes the route table, so an app.state.auth gate silently registers nothing
    in production while /ui/login still advertises the link and /auth/providers still reports true."""
    app = _managed_oidc_app(tmp_path, oidc_enabled=True)
    paths = {r.path for r in app.routes if "oidc" in getattr(r, "path", "")}  # type: ignore[attr-defined]
    # BACKLOG #296 added the federated step-up's start leg, gated on the same config.
    assert paths == {"/ui/oidc/start", "/ui/oidc/callback", "/ui/reauth/oidc"}


def test_oidc_routes_absent_on_the_production_path_when_disabled(tmp_path: Path) -> None:
    """The other half: default-off must still mean NOT REGISTERED on the production path (AC-1)."""
    app = _managed_oidc_app(tmp_path, oidc_enabled=False)
    paths = {r.path for r in app.routes if "oidc" in getattr(r, "path", "")}  # type: ignore[attr-defined]
    assert paths == set()


# --- ADR 0150: console-originated actions carry the BROWSER's address --------------------------


async def test_console_action_audits_the_browser_address(engine: Engine) -> None:
    """A /ui action must attribute its audit row to the operator's host.

    The console is mounted IN-PROCESS on the engine's own FastAPI app (ADR 0065 / ``mount_ui``), so a
    /ui route's ``Request`` IS the browser's — there is no second hop to collapse the address onto the
    engine. This pins that: were the console ever re-fronted by a proxy, or were a synthetic Request
    substituted at the seam, every console action would silently start attributing to the engine host
    and this fails.
    """
    service = await _service(engine)
    await _add(service, "boss", Role.ADMINISTRATOR)
    app = create_app(engine, auth=service, serve_ui=True)
    transport = httpx.ASGITransport(app=app, client=("10.7.7.7", 44321))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        await _cookie_login(c, "boss")
        r = await c.post(
            "/ui/statistics/reset",
            headers={
                "Sec-Fetch-Site": "same-origin",
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        assert r.status_code == 303

    rows = [dict(x) for x in await engine.store.list_audit(limit=50, action="stats_reset")]
    assert rows, "the console reset did not produce a stats_reset audit row"
    assert rows[0]["client"] == "10.7.7.7"  # the BROWSER, not the engine/loopback
    # The cookie login that preceded it is attributed to the same host.
    logins = [dict(x) for x in await engine.store.list_audit(limit=50, action="auth.login_success")]
    assert logins and logins[0]["client"] == "10.7.7.7"
    ok, message = await engine.store.verify_audit_chain()
    assert ok, message


# --- BACKLOG #1184 (ASVS 14.2.1): the console search form posts the needle -------------------------


async def test_search_form_posts_the_needle_instead_of_putting_it_on_the_url(
    engine: Engine,
) -> None:
    """A GET form puts whatever the operator typed into the browser's address bar, its history and
    every log between them. The content-search form must therefore submit as a POST.

    Asserted on the rendered HTML (the form's own method) and then on behaviour: the POST returns
    results for a term that never appears in the request URL."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    mid = await _seed(engine)  # ADT with PID-3 = 100
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        form = await c.get("/ui/messages/search")
        assert form.status_code == 200
        # The page carries several forms (the preset controls are POSTs already), so pin the SEARCH
        # form's own opening tag rather than the page's method vocabulary.
        assert 'method="get" action="/ui/messages/search"' not in form.text, (
            "the content-search form still submits on the URL"
        )
        assert 'method="post" action="/ui/messages/search/run"' in form.text
        assert 'name="field_value"' in form.text  # control: it is still the search form

        r = await c.post(
            "/ui/messages/search/run",
            data={"field_path": "PID-3", "field_value": "100"},
        )
        assert r.status_code == 200, r.text
        assert "match(es)" in r.text
        assert f"/ui/messages/{mid}" in r.text
        assert "100" not in str(r.request.url), f"the needle rode the URL: {r.request.url}"


async def test_search_get_ignores_a_needle_left_on_the_query_string(engine: Engine) -> None:
    """An old bookmark carrying ``?content=`` renders the bare form rather than running a search, so
    a URL-borne needle cannot select PHI.

    Positive control in the same run: ``?field_path=`` on the SAME route still runs a search, which
    is what distinguishes "the needle is gone" from "the route stopped searching"."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    await _seed(engine)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        stale = await c.get("/ui/messages/search", params={"content": "MSH"})
        assert stale.status_code == 200, stale.text
        assert "match(es)" not in stale.text, "a query-string needle still ran a search"
        control = await c.get("/ui/messages/search", params={"field_path": "PID-3"})
        assert control.status_code == 200
        assert "match(es)" in control.text  # control: field_path is kept and still searches


# --- BACKLOG #1141 (ASVS 6.4.5): console surfaces state the deadline the login gate enforces ------
#
# Each test pins the RENDERED instant to the stored ``password_changed_at`` and then to the gate
# itself: a page reading a fresh clock renders a different second, and a gate re-opened at twice the
# window still admits the credential after the rendered instant. Both must turn these red.

_EXPIRY_HOURS = 72


async def _expiring_service(engine: Engine, hours: int = _EXPIRY_HOURS) -> AuthService:
    service = AuthService(
        engine.store,
        AuthSettings(
            require_mfa=False, login_rate_limit_enabled=False, initial_password_expiry_hours=hours
        ),
    )
    await service.initialize()
    return service


def _console_stamp(ts: float) -> str:
    from datetime import UTC, datetime

    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%d %H:%M:%SZ")


async def _move_deadline_to(engine: Engine, user_id: str, deadline: float) -> None:
    """Move the stored stamp so the 6.4.1 deadline lands on ``deadline`` (the gate reads the clock)."""
    await engine.store._db.execute(
        "UPDATE users SET password_changed_at=? WHERE id=?",
        (deadline - _EXPIRY_HOURS * 3600, user_id),
    )
    await engine.store._db.commit()


async def _stored_deadline(engine: Engine, user_id: str) -> float:
    user = await engine.store.get_user(user_id)
    assert user is not None and user.password_changed_at is not None
    return user.password_changed_at + _EXPIRY_HOURS * 3600


async def test_create_user_form_states_the_initial_password_window(engine: Engine) -> None:
    # (a) The form renders before the account exists, so it states the WINDOW from the setting.
    service = await _expiring_service(engine)
    async with _boss_client(engine, service) as c:
        r = await c.get("/ui/users/new")
        assert r.status_code == 200
        assert "It stops working 72 hours after you create the account" in r.text
    # Control: at expiry 0 there is no window, and the sentence is absent rather than softened.
    off = await _expiring_service(engine, hours=0)
    async with _client(engine, off) as c:
        await _cookie_login(c, "boss")
        r = await c.get("/ui/users/new")
        assert r.status_code == 200
        assert "sets up an authenticator app, then chooses a password" in r.text
        assert "stops working" not in r.text


async def test_the_page_after_create_states_the_initial_password_deadline(engine: Engine) -> None:
    # (a) The create POST answers with the credential page, which states the instant off the
    # stored stamp, and so does the user's own page.
    service = await _expiring_service(engine)
    async with _boss_client(engine, service) as c:
        r = await _post_pairs(c, "/ui/users", [("username", "hana"), ("email", "hana@x.org")])
        assert r.status_code == 200
        hana = await _uid(service, "hana")
        assert _console_stamp(await _stored_deadline(engine, hana)) in r.text
        assert "stops working at" in r.text
        # ADR 0197 Amendment A: the engine generated hana's credential. Give her the test's password
        # so the holder arms below can sign in with a known one, keeping the deadline stamp.
        row = await service.store.get_user(hana)
        assert row is not None and row.password_generated
        await engine.store.set_password_hash(
            hana, password_hash=await asyncio.to_thread(hash_password, PW)
        )
        page = await c.get(f"/ui/users/{hana}")
        assert _console_stamp(await _stored_deadline(engine, hana)) in page.text
        assert "stops working at" in page.text

        # The page tracks the STORED stamp, and the gate agrees with it on both sides.
        await _move_deadline_to(engine, hana, time.time() + 30)
        page = await c.get(f"/ui/users/{hana}")
        assert _console_stamp(await _stored_deadline(engine, hana)) in page.text
        async with _client(engine, service) as holder:
            await holder.post("/ui/login", data={"username": "hana", "password": PW})
            assert "mf_session" in holder.cookies  # before it: works
        await _move_deadline_to(engine, hana, time.time() - 1)
        page = await c.get(f"/ui/users/{hana}")
        assert _console_stamp(await _stored_deadline(engine, hana)) in page.text
        async with _client(engine, service) as holder:
            refused = await holder.post("/ui/login", data={"username": "hana", "password": PW})
            assert refused.headers["location"] != "/ui/account/password"  # after it: refused
            assert "mf_session" not in holder.cookies

        # Control: an account whose holder set their own password shows no deadline.
        boss_page = await c.get(f"/ui/users/{await _uid(service, 'boss')}")
        assert "stops working at" not in boss_page.text


async def test_forced_change_page_states_the_deadline_the_gate_refuses_at(engine: Engine) -> None:
    # (d) The one surface the holder always reaches, with no address or mail relay needed.
    service = await _expiring_service(engine)
    ivan = await create_local_user_chosen(
        service,
        username="ivan",
        password=PW,
        display_name=None,
        email=None,
        roles=["viewer"],
        actor="t",
    )
    await _move_deadline_to(engine, ivan, time.time() + 30)
    expected = _console_stamp(await _stored_deadline(engine, ivan))
    async with _client(engine, service) as c:
        r = await _cookie_login(c, "ivan")
        assert r.headers["location"] == "/ui/account/password"  # before it: works
        page = await c.get("/ui/account/password")
        assert f"Your temporary password stops working at {expected}." in page.text
        # A rejected attempt re-renders with the same deadline.
        bad = await c.post(
            "/ui/account/password",
            data={"current_password": PW, "new_password": "x", "new_password2": "y"},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert bad.status_code == 400 and expected in bad.text
    await _move_deadline_to(engine, ivan, time.time() - 1)
    async with _client(engine, service) as c:
        r = await _cookie_login(c, "ivan")
        assert r.headers["location"] != "/ui/account/password"  # after it: refused


def test_the_voluntary_change_page_states_no_deadline() -> None:
    # Control for the page builder: the deadline sentence belongs to the forced variant only.
    from messagefoundry_webconsole.pages import account as pages

    # Relative to now: since BACKLOG #2298 a deadline already passed is stated as passed.
    ahead = time.time() + 3600
    assert "stops working" in str(pages.password_page(forced=True, credential_expires_at=ahead))
    assert "stops working" not in str(pages.password_page(forced=True))
    assert "stops working" not in str(
        pages.password_page(forced=False, credential_expires_at=ahead)
    )
    # A deadline past what the clock can render drops the sentence instead of raising: this page is
    # the only one a must-change holder can reach, so it must never 500.
    assert "stops working" not in str(pages.password_page(forced=True, credential_expires_at=1e15))


def test_the_forced_change_page_states_a_passed_deadline_as_passed() -> None:
    """RED when: the forced page tells a holder a lapsed password "stops working" at a past instant.

    BACKLOG #2298 (ASVS 6.4.5). One second past the deadline, the sentence is in the past tense and
    names the one remedy left. The control is the test above, with a deadline an hour ahead."""
    from messagefoundry_webconsole.pages import account as pages

    passed = time.time() - 1
    text = str(pages.password_page(forced=True, credential_expires_at=passed))
    assert f"Your temporary password stopped working at {_console_stamp(passed)}." in text
    assert "Ask an administrator to reset it." in text
    assert "stops working" not in text


def test_the_create_form_states_a_large_window_in_plain_digits() -> None:
    from messagefoundry_webconsole.pages import admin as pages

    assert "stops working 1,000,000 hours after" in str(
        pages.user_new_page([], credential_window_hours=1_000_000.0)
    )
    assert "stops working 1 hour after" in str(pages.user_new_page([], credential_window_hours=1.0))


# --- vault BACKLOG #2620: a replayed cookie from a second address --------------------------------


def _client_from(engine: Engine, service: AuthService, ip: str) -> httpx.AsyncClient:
    """A browser at ``ip``, otherwise as :func:`_client`."""
    app = create_app(engine, auth=service, serve_ui=True, webauthn_rp_from_request=True)
    transport = httpx.ASGITransport(app=app, client=(ip, 51000))
    return httpx.AsyncClient(transport=transport, base_url="http://t")


async def test_a_cookie_replayed_from_a_second_address_is_sent_to_reauth(engine: Engine) -> None:
    """RED when: a session cookie presented from a host it never verified from reads a message page
    or calls a paced write (vault BACKLOG #2620).

    The PHI arm sends it to ``/ui/reauth`` and back to the page; a write lands on ``/ui`` after the
    re-auth. The same cookie from the sign-in address is the control, and a non-PHI page from the new
    address is the proof the base gate still lets it through."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    mid = await _seed(engine)
    same = {"Sec-Fetch-Site": "same-origin"}
    async with _client_from(engine, service, "10.0.0.1") as a:
        assert (await _cookie_login(a, "op")).status_code == 303
        tok = a.cookies.get("mf_session")
        assert tok is not None
        # The control: the sign-in address reads and writes.
        assert (await a.get(f"/ui/messages/{mid}")).status_code == 200
        r = await a.post("/ui/statistics/reset", headers=same)
        assert (r.status_code, r.headers["location"]) == (303, "/ui/status")
    async with _client_from(engine, service, "10.9.9.9") as b:
        b.cookies.set("mf_session", tok)
        for page in (f"/ui/messages/{mid}", "/ui/messages", "/ui/dead-letters"):
            r = await b.get(page)
            assert (r.status_code, r.headers.get("location")) == (303, f"/ui/reauth?next={page}")
        # A filtered or deferred list comes back with its query, never as a broader read.
        listed = "/ui/messages?channel_id=ch1&defer=1"
        r = await b.get(listed)
        assert r.headers.get("location") == "/ui/reauth?next=" + quote(listed, safe="/")
        assert (await b.get("/ui/reauth", params={"next": listed})).status_code == 200
        r = await b.post("/ui/statistics/reset", headers=same)
        assert (r.status_code, r.headers["location"]) == (303, "/ui/reauth?next=/ui")
        # Not every request: the dashboard is no PHI page and no write.
        assert (await b.get("/ui")).status_code == 200
        # /ui/reauth accepts both continuations, so the operator is not stranded on /ui.
        assert (await b.get(f"/ui/reauth?next=/ui/messages/{mid}")).status_code == 200
        assert (await b.get("/ui/reauth?next=/ui")).status_code == 200
        done = await b.post(
            "/ui/reauth", data={"next": f"/ui/messages/{mid}", "password": PW}, headers=same
        )
        assert (done.status_code, done.headers["location"]) == (303, f"/ui/messages/{mid}")
        # Keep only the rotated cookie. The jar files the hand-set copy and the server's under
        # different domains, so both would ride the next request, and two copies are refused
        # (BACKLOG #2454). A browser holds one: the engine's cookie is host-only.
        rotated = done.cookies["mf_session"]
        b.cookies.clear()
        b.cookies.set("mf_session", rotated)
        # The re-auth re-anchored the session at this address.
        assert (await b.get(f"/ui/messages/{mid}")).status_code == 200
    seen = [
        json.loads(str(dict(a)["detail"]))["path"]
        for a in await engine.store.list_audit(action="auth.admin_action_new_ip", limit=100)
    ]
    assert seen == [f"/ui/messages/{mid}"]  # one row: a first sighting, then deduped


async def test_a_refused_new_address_spends_no_budget(engine: Engine) -> None:
    """RED when: a request refused for a new address first charges the holder's PHI-read or
    admin-write budget (vault BACKLOG #2620, the BACKLOG #1973 rule). With a budget of one, the
    holder still reads and writes once after the refusals."""
    service = AuthService(
        engine.store,
        AuthSettings(
            admin_write_min_interval_seconds=0,
            admin_write_rate_limit_per_actor=1,
            phi_read_rate_limit_per_actor=1,
            require_mfa=False,
        ),
    )
    await service.initialize()
    await _add(service, "op", Role.OPERATOR)
    mid = await _seed(engine)
    same = {"Sec-Fetch-Site": "same-origin"}
    async with _client_from(engine, service, "10.0.0.1") as a:
        await _cookie_login(a, "op")
        tok = a.cookies.get("mf_session")
        assert tok is not None
    async with _client_from(engine, service, "10.9.9.9") as b:
        b.cookies.set("mf_session", tok)
        for _ in range(3):
            assert (await b.get(f"/ui/messages/{mid}")).status_code == 303
            assert (await b.post("/ui/statistics/reset", headers=same)).status_code == 303
    async with _client_from(engine, service, "10.0.0.1") as a:
        a.cookies.set("mf_session", tok)
        assert (await a.get(f"/ui/messages/{mid}")).status_code == 200
        r = await a.post("/ui/statistics/reset", headers=same)
        assert (r.status_code, r.headers["location"]) == (303, "/ui/status")


async def test_every_phi_page_has_a_reauth_continuation(engine: Engine) -> None:
    """RED when: a ``require_ui(..., phi=True)`` GET page is added without registering it as an
    unlock continuation (vault BACKLOG #2620). Its new-address refusal sends the browser to
    ``/ui/reauth?next=<path>``, and an unregistered ``next`` bounces to ``/ui`` with the session
    still anchored elsewhere, so the operator could never reach the page from the new address.

    Walks the mounted routes and reads ``phi`` and ``new_address_check`` from each ``require_ui``
    dependency's closure, so the set is derived and not a list kept by hand."""
    from fastapi.routing import APIRoute

    from messagefoundry_webconsole._auth import is_unlock_action

    service = await _service(engine)
    app = create_app(engine, auth=service, serve_ui=True)
    checked: list[str] = []
    for route in app.routes:
        if not isinstance(route, APIRoute) or not route.path.startswith("/ui"):
            continue
        if "GET" not in route.methods:
            continue
        for dep in route.dependant.dependencies:
            call = dep.call
            code = getattr(call, "__code__", None)
            if (
                code is None
                or getattr(call, "__qualname__", "") != "require_ui.<locals>.dependency"
            ):
                continue
            closure = getattr(call, "__closure__", None) or ()
            cells = dict(zip(code.co_freevars, (c.cell_contents for c in closure), strict=True))
            if cells.get("phi") and cells.get("new_address_check"):
                concrete = re.sub(r"\{[^}]+\}", "x1", route.path)
                assert is_unlock_action(concrete), f"{route.path} has no unlock continuation"
                # Query-tolerant, so a filtered page comes back filtered.
                assert is_unlock_action(concrete + "?a=1"), f"{route.path} drops its query"
                checked.append(route.path)
    # The control: the walk found the PHI pages it exists for, so a zero is not a pass.
    assert "/ui/messages/{message_id}" in checked and "/ui/dead-letters" in checked, checked


async def test_the_password_page_is_not_refused_for_a_new_address(engine: Engine) -> None:
    """RED when: a must-change session's password POST from a new address is sent to
    ``/ui/reauth``. That page sends a must-change session straight back to the password page, so
    the refusal would loop with no message (vault BACKLOG #2620, review round 1). A mismatched
    pair proves the handler ran: it answers 400 in place."""
    service = await _service(engine)
    await _add(service, "fresh", Role.OPERATOR)
    user = await service.store.get_user_by_username("fresh")
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user.id,
        password_hash=user.password_hash,
        must_change_password=True,
        password_generated=False,
    )
    async with _client_from(engine, service, "10.0.0.1") as a:
        await _cookie_login(a, "fresh")
        tok = a.cookies.get("mf_session")
        assert tok is not None
    async with _client_from(engine, service, "10.9.9.9") as b:
        b.cookies.set("mf_session", tok)
        r = await b.post(
            "/ui/account/password",
            data={"current_password": PW, "new_password": "a" * 20, "new_password2": "b" * 20},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 400, r.headers.get("location")


def test_a_new_address_continuation_never_drops_a_query_or_overflows() -> None:
    """RED when: a refused GET's continuation drops its query (a broader read after the re-auth)
    or exceeds ``/ui/reauth``'s 512-character cap on ``next`` (a 422 with no form). Either way the
    landing is used instead (vault BACKLOG #2620, review round 2)."""
    from starlette.requests import Request

    from messagefoundry_webconsole._auth import _new_address_continuation

    def req(method: str, path: str, query: str = "") -> Request:
        scope = {
            "type": "http",
            "method": method,
            "path": path,
            "raw_path": path.encode(),
            "query_string": query.encode(),
            "headers": [],
        }
        return Request(scope)

    land = "/ui/account"
    assert _new_address_continuation(req("GET", "/ui/messages"), landing=land) == "/ui/messages"
    filtered = req("GET", "/ui/messages", "channel_id=ch1&defer=1")
    assert (
        _new_address_continuation(filtered, landing=land) == "/ui/messages?channel_id=ch1&defer=1"
    )
    long_name = "/ui/connection/" + "n" * 600 + "/events/1/reason"
    assert _new_address_continuation(req("GET", long_name), landing=land) == land
    assert _new_address_continuation(req("GET", "/ui/audit"), landing=land) == land
    assert _new_address_continuation(req("POST", "/ui/messages"), landing=land) == land


async def test_the_continuation_cap_is_the_reauth_pages_own(engine: Engine) -> None:
    """RED when: ``_REAUTH_NEXT_MAX`` and ``GET /ui/reauth``'s own cap on ``next`` drift apart
    (vault BACKLOG #3052 item 18). The unit test above reads the constant, so a refused PHI read
    whose continuation fits it could still be answered 422, with no form, by the page it is sent
    to. A query-tolerant unlock target exactly at the cap renders; one character over is refused."""
    from messagefoundry_webconsole._auth import _REAUTH_NEXT_MAX, is_unlock_action

    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    base = "/ui/messages?channel_id="
    at_cap = base + "c" * (_REAUTH_NEXT_MAX - len(base))
    assert len(at_cap) == _REAUTH_NEXT_MAX and is_unlock_action(at_cap)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        assert (await c.get("/ui/reauth", params={"next": at_cap})).status_code == 200
        assert (await c.get("/ui/reauth", params={"next": at_cap + "c"})).status_code == 422


async def test_a_cross_site_write_from_a_new_address_writes_no_row(engine: Engine) -> None:
    """RED when: ``require_ui`` asks the new-address question before its same-origin check (vault
    BACKLOG #3052 item 11). In that order a cross-site page holding a replayed cookie would make
    the engine write ``auth.admin_action_new_ip`` and send the notice before the write is refused.

    The write carries no ``Sec-Fetch-Site`` and a foreign ``Origin``, as an older browser's would:
    the fetch-metadata middleware lets an absent header through, so the refusal under test is
    ``require_ui``'s own. The same-origin write from the same address is the control: it is sent
    to ``/ui/reauth`` and writes the row, so the zero above it is not a signal that cannot fire."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client_from(engine, service, "10.0.0.1") as a:
        await _cookie_login(a, "op")
        tok = a.cookies.get("mf_session")
        assert tok is not None
    async with _client_from(engine, service, "10.9.9.9") as b:
        b.cookies.set("mf_session", tok)
        r = await b.post("/ui/statistics/reset", headers={"Origin": "https://attacker.example"})
        # require_ui's own refusal, by its detail, so an earlier gate cannot pass this vacuously.
        assert (r.status_code, r.json().get("detail")) == (403, "cross-origin request rejected")
        assert await engine.store.list_audit(action="auth.admin_action_new_ip", limit=10) == []
        r = await b.post("/ui/statistics/reset", headers={"Sec-Fetch-Site": "same-origin"})
        assert (r.status_code, r.headers["location"]) == (303, "/ui/reauth?next=/ui")
    assert len(await engine.store.list_audit(action="auth.admin_action_new_ip", limit=10)) == 1


async def test_a_refused_write_without_monitoring_read_lands_on_the_account_page(
    engine: Engine,
) -> None:
    """RED when: a write refused for a new address continues to ``/ui`` for a session without
    ``monitoring:read`` (vault BACKLOG #3052 item 12). ``/ui`` would refuse that session, so after
    the re-auth it would land on a 403. A custom role holding ``monitoring:diagnose`` alone can
    make the write; the Operator in ``test_a_cookie_replayed_from_a_second_address_is_sent_to_reauth``
    is the control that lands on ``/ui``."""
    service = await _service(engine)
    role = await service.create_custom_role(
        display_name="Counter Resetter",
        description=None,
        permissions=["monitoring:diagnose"],
        actor="test",
    )
    await _add_with_role_ids(service, "resetter", [role.id])
    same = {"Sec-Fetch-Site": "same-origin"}
    async with _client_from(engine, service, "10.0.0.1") as a:
        await _cookie_login(a, "resetter")
        tok = a.cookies.get("mf_session")
        assert tok is not None
        # The control at the sign-in address: the role may make this write, so it is not refused.
        # Where its success lands is not this test's subject.
        r = await a.post("/ui/statistics/reset", headers=same)
        assert r.status_code == 303 and not r.headers["location"].startswith("/ui/reauth")
    async with _client_from(engine, service, "10.9.9.9") as b:
        b.cookies.set("mf_session", tok)
        r = await b.post("/ui/statistics/reset", headers=same)
        assert (r.status_code, r.headers["location"]) == (303, "/ui/reauth?next=/ui/account")
