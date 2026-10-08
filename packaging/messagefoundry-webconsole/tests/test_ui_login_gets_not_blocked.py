# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A sign-in GET is never blocked for missing fetch metadata (BACKLOG #1116, #1124).

``assert_same_origin`` refuses a WRITE that carries neither ``Sec-Fetch-Site`` nor ``Origin``. The
first cut of that rule applied to every method, and one sign-in GET reaches the check: ``GET
/ui/oidc/start`` runs the POST leg directly when its interstitial is skipped. A browser sends no
``Origin`` on a GET navigation, so one that also sent no ``Sec-Fetch-Site`` got a JSON 403 where it
had a redirect to the identity provider.

Owner rulings R4 and R4b of 2026-09-28 hold that the three safe-method sign-in routes are never
blocked for that: ``GET /ui/sso``, ``GET /ui/oidc/callback``, and ``GET /ui/oidc/start`` when no
interstitial is needed. Each case below sends a GET with NEITHER header and asserts the answer the
route gave before the rule existed. The values were measured on ``origin/main`` with this file.

The last two tests are the other side: the same start leg still refuses what it refused before on
a GET, and a POST with neither header is still refused.
"""

from __future__ import annotations

import time
from urllib.parse import parse_qsl, urlsplit

import httpx
import pytest
from _ui_clients import HEADERLESS_UI_REQUEST
from _ui_clients import SAME_ORIGIN as _SAME
from test_ui_directory_admin_alert import _SUBJECT, _service, _Sink

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.oidc import FederatedPrincipal
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import SecuritySettings
from messagefoundry.pipeline import Engine

_NEGOTIATE = {"Authorization": "Negotiate c3BuZWdvLXRva2Vu"}
#: Sends the request exactly as written; the suite's browser stand-in adds nothing to it.
_HEADERLESS = {HEADERLESS_UI_REQUEST: True}


def _client(engine: Engine, service: AuthService, *, interstitial: bool) -> httpx.AsyncClient:
    """The mounted console. ``interstitial=False`` is the configuration under which ``GET
    /ui/oidc/start`` skips its "leaving this site" page and runs the POST leg itself."""
    app = create_app(
        engine,
        auth=service,
        serve_ui=True,
        public_origin="https://ops.example",
        security_settings=SecuritySettings(external_link_interstitial=interstitial),
    )
    app.state.notifier = _Sink()
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")


def _names_no_provenance(response: httpx.Response) -> bool:
    """Whether the request that produced ``response`` really went out with neither header."""
    sent = response.request.headers
    return "sec-fetch-site" not in sent and "origin" not in sent


async def test_sso_get_with_neither_header_signs_in(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``GET /ui/sso``: the challenge leg answers 401 Negotiate, and the token leg mints a session."""
    service = await _service(engine, held=Role.OPERATOR, bind=False)
    monkeypatch.setattr("messagefoundry.auth.service.kerberos_principal", lambda _t, _s: "jdoe")
    async with _client(engine, service, interstitial=True) as c:
        challenge = await c.get("/ui/sso", extensions=_HEADERLESS)
        assert _names_no_provenance(challenge)
        assert challenge.status_code == 401, challenge.text
        assert challenge.headers["www-authenticate"] == "Negotiate"
        r = await c.get("/ui/sso", headers=_NEGOTIATE, extensions=_HEADERLESS)
    assert _names_no_provenance(r)
    assert (r.status_code, r.headers["location"]) == (303, "/ui"), r.text
    assert "mf_session=" in r.headers.get("set-cookie", "")


async def test_oidc_callback_get_with_neither_header_signs_in(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``GET /ui/oidc/callback``: the identity provider's return mints a session."""
    service = await _service(engine, held=Role.OPERATOR, bind=True)

    def _exchange(*_a: object, **_k: object) -> FederatedPrincipal:
        return FederatedPrincipal(
            username="jdoe",
            subject=_SUBJECT,
            issuer="https://idp.example",
            amr=("pwd", "mfa"),
            acr=None,
            expires_at=time.time() + 600,
            auth_time=time.time(),
        )

    monkeypatch.setattr(service, "_exchange_and_validate", _exchange)
    async with _client(engine, service, interstitial=True) as c:
        start = await c.post("/ui/oidc/start", headers=_SAME, follow_redirects=False)
        assert start.status_code == 303, start.text
        state = dict(parse_qsl(urlsplit(start.headers["location"]).query))["state"]
        r = await c.get(
            "/ui/oidc/callback",
            params={"code": "authcode", "state": state},
            extensions=_HEADERLESS,
            follow_redirects=False,
        )
    assert _names_no_provenance(r)
    assert r.status_code == 200, r.text
    assert "0;url=/ui" in r.text.split("</head>")[0]
    assert "mf_session=" in r.headers.get("set-cookie", "")


async def test_oidc_start_get_with_neither_header_redirects_to_the_idp(engine: Engine) -> None:
    """``GET /ui/oidc/start`` with no interstitial needed: the flow is minted and the browser is
    sent to the identity provider. This is the case the first cut answered with a JSON 403."""
    service = await _service(engine, held=Role.OPERATOR, bind=True)
    async with _client(engine, service, interstitial=False) as c:
        r = await c.get("/ui/oidc/start", extensions=_HEADERLESS, follow_redirects=False)
    assert _names_no_provenance(r)
    assert r.status_code == 303, r.text
    assert r.headers["location"].startswith("https://idp.example/authorize?")
    assert "mf_oidc_flow=" in r.headers.get("set-cookie", "")


@pytest.mark.parametrize(
    "headers",
    [
        {"Sec-Fetch-Site": "cross-site"},
        {"Sec-Fetch-Site": "same-site"},
        {"Origin": "http://evil.example"},
    ],
    ids=["cross-site", "same-site", "foreign-origin"],
)
async def test_oidc_start_get_still_refuses_what_it_refused(
    engine: Engine, headers: dict[str, str]
) -> None:
    """Not weakened: the skipped-interstitial GET names a foreign source and mints nothing."""
    service = await _service(engine, held=Role.OPERATOR, bind=True)
    async with _client(engine, service, interstitial=False) as c:
        r = await c.get(
            "/ui/oidc/start",
            # A complete user-started navigation, so the fetch-metadata middleware lets a
            # same-site one through and the refusal measured is assert_same_origin's own.
            headers={
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-User": "?1",
                **headers,
            },
            follow_redirects=False,
        )
    assert r.status_code == 403, r.text
    assert "set-cookie" not in r.headers


async def test_oidc_start_post_with_neither_header_is_still_refused(engine: Engine) -> None:
    """The write keeps the fail-closed rule; the control is the same POST naming its origin."""
    service = await _service(engine, held=Role.OPERATOR, bind=True)
    async with _client(engine, service, interstitial=False) as c:
        refused = await c.post("/ui/oidc/start", extensions=_HEADERLESS, follow_redirects=False)
        assert _names_no_provenance(refused)
        assert refused.status_code == 403
        assert "neither Sec-Fetch-Site nor Origin" in refused.text
        assert "set-cookie" not in refused.headers
        named = await c.post("/ui/oidc/start", headers=_SAME, follow_redirects=False)
        assert named.status_code == 303, named.text
