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

import re
from typing import Any
from urllib.parse import urlsplit

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
    # Anchored to the element that renders it, not a bare substring of the whole page. Two reasons:
    # a substring test passes if the host appears ANYWHERE (a stray comment, an unrelated attribute),
    # and CodeQL flags `host in page` as incomplete-URL-sanitization because that is exactly the
    # shape of a broken redirect check. Asserting the rendered tag is both stronger and unambiguous.
    assert "<code>login.microsoftonline.com</code>" in body
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
    assert "<code>adfs.hospital.example</code>" in r.text


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
    # PARSE the Continue form's action rather than string-matching the page. A string-absence check
    # ("the IdP URL does not appear") passes for the wrong reason the moment the markup changes shape;
    # parsing asserts the actual property — the form posts to a LOCAL PATH with no host component and
    # no query, so there is nothing in it for an attacker to steer.
    action = re.search(r'<form[^>]*action="([^"]*)"[^>]*class="login"', r.text)
    assert action, "the Continue form is missing"
    target = urlsplit(action.group(1))
    assert target.scheme == "" and target.netloc == "", (
        "the Continue form must post to a local path"
    )
    assert target.path == "/ui/oidc/start"
    assert target.query == "", "no destination may ride in the query string"


def test_a_cross_site_post_to_the_start_leg_is_refused() -> None:
    """⛔ ASVS 3.5.1 — the assertion the rest of this file could not make.

    Every other test here sends NO `Sec-Fetch-*` headers, so the origin guard never fires and they
    would all pass just as happily with it deleted. This one supplies the header a real browser sends
    on a cross-site form submission and asserts the 403.

    Why it matters specifically to 3.7.3: the GET/POST split moved flow-minting behind a POST, and a
    cross-site `<form method=post>` is still `Sec-Fetch-Mode: navigate` — so the navigate check does
    NOT stop it. Without the origin guard the split relocates the drive-by sign-in hole rather than
    closing it, which is what the first version of this change did while claiming otherwise.
    """
    c = _client(
        organization_domains=("hospital.example",),
        oidc_authorization_host="login.microsoftonline.com",
    )
    r = c.post(
        "/ui/oidc/start", headers={"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate"}
    )
    assert r.status_code == 403


def test_a_same_origin_post_is_not_refused_by_the_guard() -> None:
    """Reach control. Without it, a guard that 403s EVERYTHING would pass the test above."""
    c = _client(
        organization_domains=("hospital.example",),
        oidc_authorization_host="login.microsoftonline.com",
    )
    r = c.post(
        "/ui/oidc/start", headers={"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate"}
    )
    assert r.status_code != 403


def test_a_cross_site_GET_renders_the_interstitial_and_stages_nothing() -> None:
    """The GET is deliberately NOT origin-guarded, and the reason is worth stating precisely.

    An external page CAN link here and get our interstitial rendered. That is acceptable because the
    page is **side-effect free**: no flow is staged, no cookie is set, nothing is minted, and the only
    way onward is a Continue button that POSTs — and the POST *is* guarded (see the two tests above).
    So a drive-by can cause a harmless page to render; it cannot cause a sign-in to start.

    ⚠️ Asserted here rather than left implicit because the first version of this change claimed the
    split "closed the standing hole where any external page could start a federated sign-in by linking
    here". Half true: the LINK no longer starts one. What actually closes it is the origin guard on
    the POST, not the split.
    """
    c = _client(
        organization_domains=("hospital.example",),
        oidc_authorization_host="login.microsoftonline.com",
    )
    r = c.get(
        "/ui/oidc/start", headers={"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate"}
    )
    assert r.status_code == 200
    assert "leaving" in r.text.lower()
    assert not r.cookies  # nothing staged


def test_a_cross_site_GET_with_an_INTERNAL_idp_is_refused() -> None:
    """⛔ The asymmetry, asserted so it cannot be forgotten.

    With an internal IdP there is no interstitial, so the GET delegates straight to the minting leg —
    and inherits its origin guard. The consequence a reader needs: for an INTERNAL-IdP deployment the
    GET still mints a flow, exactly as before this change. The bounded-flow-cache DoS lever is closed
    for external IdPs (where the interstitial interposes) and is merely ORIGIN-GUARDED for internal
    ones. The earlier claim that the split closed it outright was too broad.
    """
    c = _client(
        organization_domains=("hospital.example",),
        oidc_authorization_host="adfs.hospital.example",
    )
    r = c.get(
        "/ui/oidc/start", headers={"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate"}
    )
    assert r.status_code == 403


@pytest.mark.parametrize("method", ["get", "post"])
def test_both_start_legs_exist(method: str) -> None:
    """The GET renders, the POST acts. Losing either silently breaks sign-in or the control."""
    c = _client(
        organization_domains=("hospital.example",),
        oidc_authorization_host="login.microsoftonline.com",
    )
    r = getattr(c, method)("/ui/oidc/start")
    assert r.status_code != 405
