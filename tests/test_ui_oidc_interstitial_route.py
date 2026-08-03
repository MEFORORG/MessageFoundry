# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ASVS 3.7.3 at the ROUTE level: does the interstitial actually interpose?

``test_external_link_interstitial.py`` proves the predicate decides correctly. That is necessary and
not sufficient — a correct predicate wired to nothing still ships a console that redirects off-site
silently. These tests exercise the registered routes.

The registrar is driven directly with a hand-built :class:`UiDeps` rather than through ``create_app``:
the policy reaches the route as CONFIG (seam v17) precisely so it does not depend on the AuthService,
and testing it that way keeps the test honest about which layer is under test.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

from messagefoundry.api._ui_seam import UiDeps
from messagefoundry_webconsole.routes import oidc as oidc_routes


class _FakeAuth:
    """The narrow slice of AuthService the start legs touch before they would reach the IdP."""

    oidc_enabled = True
    oidc_flow_ttl_seconds = 300

    def allow_login_attempt(self, _client: str | None) -> bool:
        return True

    async def audit_oidc_reject(self, _reason: str) -> None:  # pragma: no cover - not reached here
        return None


def _client(**policy: Any) -> TestClient:
    app = FastAPI()
    deps = UiDeps(
        engine_seam=0,
        get_engine=lambda: None,
        get_gate=lambda: None,
        cookie_secure=lambda *_a, **_k: False,
        default_scan_limit=100,
        core=None,  # type: ignore[arg-type]
        admin=None,  # type: ignore[arg-type]
        oidc_enabled=True,
        **policy,
    )
    oidc_routes.register(app, deps)
    app.state.auth = _FakeAuth()
    app.state.public_origin = ""  # start leg bails before the IdP; we assert on the interstitial
    return TestClient(app, follow_redirects=False)


def test_an_external_idp_gets_the_interstitial_not_a_redirect() -> None:
    """The control itself: a third-party IdP must produce a page with a destination and a cancel."""
    r = _client(
        organization_domains=("hospital.example",),
        oidc_authorization_host="login.microsoftonline.com",
    ).get("/ui/oidc/start")
    assert r.status_code == 200
    body = r.text
    assert "You are leaving this site" in body or "leaving" in body.lower()
    assert "login.microsoftonline.com" in body
    assert 'method="post"' in body  # Continue is a form, not a link
    assert "Cancel" in body


def test_an_internal_idp_is_not_interstitialed() -> None:
    """An operator's own AD FS is a different host and still inside their control.

    Asserted as "not the interstitial" rather than "is a 303": the start leg has several legitimate
    303 outcomes and pinning one would make this test about flow plumbing instead of about 3.7.3.
    """
    r = _client(
        organization_domains=("hospital.example",),
        oidc_authorization_host="adfs.hospital.example",
    ).get("/ui/oidc/start")
    assert r.status_code != 200 or "leaving" not in r.text.lower()


def test_with_no_org_domains_even_a_plausible_idp_is_interstitialed() -> None:
    """Secure-by-default reaches the route, not just the predicate."""
    r = _client(organization_domains=(), oidc_authorization_host="adfs.hospital.example").get(
        "/ui/oidc/start"
    )
    assert r.status_code == 200
    assert "adfs.hospital.example" in r.text


def test_the_allowlist_escape_suppresses_the_interstitial() -> None:
    """The documented escape works — and this test exists so the warning in the docs is not a lie."""
    r = _client(
        organization_domains=("hospital.example",),
        external_link_allowlist=("login.microsoftonline.com",),
        oidc_authorization_host="login.microsoftonline.com",
    ).get("/ui/oidc/start")
    assert r.status_code != 200 or "leaving" not in r.text.lower()


def test_turning_the_interstitial_off_suppresses_it() -> None:
    r = _client(
        organization_domains=("hospital.example",),
        external_link_interstitial=False,
        oidc_authorization_host="login.microsoftonline.com",
    ).get("/ui/oidc/start")
    assert r.status_code != 200 or "leaving" not in r.text.lower()


def test_an_unconfigured_idp_host_still_gets_the_interstitial() -> None:
    """Unknown destination is not a reason to skip the warning — fail toward showing it."""
    r = _client(organization_domains=("hospital.example",), oidc_authorization_host="").get(
        "/ui/oidc/start"
    )
    assert r.status_code == 200


def test_the_interstitial_page_carries_no_destination_url_to_post_back() -> None:
    """⭐ The one that stops this being an open redirect.

    If the rendered page carried the target URL in a form field or query string, the POST leg would
    be steerable by anyone who could get an operator to load a crafted page — an interstitial that is
    itself an open redirect, which is strictly worse than having none. The destination must live in
    configuration and server-side state only.
    """
    r = _client(
        organization_domains=("hospital.example",),
        oidc_authorization_host="login.microsoftonline.com",
    ).get("/ui/oidc/start")
    assert r.status_code == 200
    assert "https://login.microsoftonline.com" not in r.text  # host shown, full URL never
    assert 'action="/ui/oidc/start"' in r.text  # posts back to us, carrying nothing


@pytest.mark.parametrize("method", ["get", "post"])
def test_both_start_legs_exist(method: str) -> None:
    """The GET renders, the POST acts. Losing either silently breaks sign-in or the control."""
    c = _client(
        organization_domains=("hospital.example",),
        oidc_authorization_host="login.microsoftonline.com",
    )
    r = getattr(c, method)("/ui/oidc/start")
    assert r.status_code != 405
