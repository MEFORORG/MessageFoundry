# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The cross-site refusal reaches the /ui/static MOUNT, and does not overreach (BACKLOG #1371).

The middleware itself landed under #1371 -- this header previously cited #1122, which is the ASVS
3.5.3 research item and a different subject; the miscitation is recorded as debt on #1334. #1122 then
TIGHTENED the carve-out here (the destination allowlist and the same-site user-activation rule), and
the tests carrying that work name it individually below.

``assert_not_cross_site`` runs as a route dependency, and ``/ui/static`` is a Starlette ``Mount``
rather than an ``APIRoute`` — a dependency never runs for it, so the asset tier was the one /ui
surface the per-route check could not reach. That gap is why this is middleware, and the first test
here is the only one that would notice if it were moved back to a dependency.

The rest pin constraints that each look like a hardening improvement and each break shipped
behaviour. The NAVIGATION one was not caught by this file — ``test_webui.py`` caught it, because a
first cut of this middleware read ``Sec-Fetch-Site`` alone and 403'd every real SSO login. These
tests exist so the rule is pinned where the rule lives:

* **absent is allowed** — the tray's own ``GET /ui`` probe builds its httpx client with no headers at
  all, and 332 headerless /ui call sites exist in this corpus. Failing closed on absence refuses every
  non-browser client.
* **403, never 404** — ``tray/probe.py`` classifies 404 as ``DISABLED`` and everything else as
  ``ENABLED``, so a 404 here makes the shipped Windows tray report a healthy console as switched off.
* **a cross-site top-level NAVIGATION is allowed** — an intranet link and the OIDC callback redirect
  are both cross-site by construction. Refusing them breaks login while every hermetic test that
  omits the headers still passes, which is precisely how it got shipped into this branch once.
"""

from __future__ import annotations

import httpx

from messagefoundry.api import create_app
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine


async def _service(engine: Engine) -> AuthService:
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    return service


def _client(engine: Engine, service: AuthService) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=create_app(engine, auth=service, serve_ui=True))
    return httpx.AsyncClient(transport=transport, base_url="http://t")


async def test_the_static_mount_is_covered_which_a_route_dependency_cannot_be(
    engine: Engine,
) -> None:
    """THE REASON THIS IS MIDDLEWARE. Move the check back to a dependency and only this goes red.

    A ``Mount`` runs no route dependencies, so before #1122 a cross-site fetch of an asset was served
    normally while the same fetch of an HTML route was refused.
    """
    service = await _service(engine)
    async with _client(engine, service) as c:
        r = await c.get("/ui/static/app.css", headers={"Sec-Fetch-Site": "cross-site"})
    assert r.status_code == 403, (
        f"a cross-site fetch of a /ui/static asset was not refused (got {r.status_code}) — the "
        "check is not reaching the Mount"
    )


async def test_a_headerless_request_is_allowed_because_the_tray_sends_none(
    engine: Engine,
) -> None:
    """POSITIVE CONTROL, and the half that would break shipped behaviour if inverted.

    ``Sec-Fetch-Site`` is browser-populated. The tray probe, every non-browser client and 332 call
    sites in this corpus omit it entirely. This must NOT 403 — if it does, the tray's console item
    and most of this suite go with it.

    **This is also the fence on the half #1122 deliberately did NOT change.** Every rule #1122 added
    is reached only after ``Sec-Fetch-Site`` arrived, so a client sending no fetch metadata is exactly
    as unaffected as before. Measured 2026-09-04 by inverting that one condition and running this
    suite: **231 of 408 tests** go red. Failing closed is a browser-support decision, not a hardening
    pass, and it is not taken. The three paths span the mount, an HTML route and a PHI route.
    """
    service = await _service(engine)
    async with _client(engine, service) as c:
        for path in ("/ui/static/app.css", "/ui", "/ui/messages/m1/attachments/a1"):
            r = await c.get(path)
            assert r.status_code != 403, (
                f"a headerless request to {path} was refused; absence must be allowed"
            )


async def test_a_refusal_is_403_and_never_404_because_404_disables_the_tray(
    engine: Engine,
) -> None:
    """404 would look like route-disclosure hardening and would silently disable the tray's console.

    ``tray/probe.py`` maps 404 to ``DISABLED`` and EVERY other status to ``ENABLED``, so the status
    choice here is load-bearing on a different component's UI.
    """
    service = await _service(engine)
    async with _client(engine, service) as c:
        r = await c.get("/ui", headers={"Sec-Fetch-Site": "cross-site"})
    assert r.status_code == 403, f"expected 403, got {r.status_code}"
    assert r.status_code != 404, "404 makes the Windows tray report a healthy console as DISABLED"


async def test_same_origin_and_none_still_pass(engine: Engine) -> None:
    """SECOND POSITIVE CONTROL: a guard that refused everything would satisfy the first test alone."""
    service = await _service(engine)
    async with _client(engine, service) as c:
        for site in ("same-origin", "none"):
            r = await c.get("/ui/static/app.css", headers={"Sec-Fetch-Site": site})
            assert r.status_code != 403, f"Sec-Fetch-Site: {site} must not be refused"


async def test_a_cross_site_top_level_navigation_is_allowed_because_a_real_login_is_one(
    engine: Engine,
) -> None:
    """THE REGRESSION THIS FILE MISSED FIRST TIME. Reading ``Sec-Fetch-Site`` alone 403s every SSO login.

    The IdP redirect back to ``/ui/oidc/callback`` and a plain intranet link into the console are both
    ``Sec-Fetch-Site: cross-site`` with ``Sec-Fetch-Mode: navigate``. ``_auth``'s per-route helper never
    sees one — its callers are a CSP sink and state-changing POSTs — so lifting its membership test to
    every /ui request without also reading the MODE refuses traffic the product depends on.

    **It is ALSO the pin on #1122's asymmetry: the cross-site half is deliberately not asked for
    ``Sec-Fetch-User``.** Demanding ``?1`` on both halves would look symmetrical and would refuse
    silent re-authentication — the IdP's redirect back is a server-driven 302 with no user activation
    once the IdP session is established. A cross-site request also arrives with no cookie under
    ``SameSite=Strict``, so it carries none of the authority that makes the same-site rule necessary.
    Mutating the middleware to require ``?1`` on both halves turns this test red.
    """
    service = await _service(engine)
    async with _client(engine, service) as c:
        r = await c.get(
            "/ui",
            headers={
                "Sec-Fetch-Site": "cross-site",
                "Sec-Fetch-Mode": "navigate",
                # A real browser ALWAYS sends this on a top-level navigation. It became load-bearing
                # in #1122, which made the destination an allowlist; before that the header was
                # omitted here and the request passed a denylist unread.
                "Sec-Fetch-Dest": "document",
            },
        )
    assert r.status_code != 403, (
        "a cross-site TOP-LEVEL NAVIGATION was refused — this is what an intranet link and the OIDC "
        "callback both look like, so this 403 is every real SSO login failing"
    )


async def test_a_cross_site_non_navigation_fetch_is_still_refused(engine: Engine) -> None:
    """NEGATIVE CONTROL for the carve-out: it must not have opened the door generally.

    A cross-site ``cors`` fetch is the drive-by ambient-auth probe ASVS 3.5.3 is about. Only
    ``navigate`` earns the exemption.
    """
    service = await _service(engine)
    async with _client(engine, service) as c:
        r = await c.get(
            "/ui/static/app.css",
            headers={"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "cors"},
        )
    assert r.status_code == 403, (
        f"a cross-site non-navigation fetch was allowed (got {r.status_code}) — the navigation "
        "carve-out must not cover ordinary fetches"
    )


async def test_a_cross_site_navigation_carrying_a_post_is_refused(engine: Engine) -> None:
    """METHOD is part of "safe": a cross-site navigation with a POST is a CSRF form submission.

    No supported flow makes one — the OIDC callback is a GET and ``response_mode=form_post`` is not
    implemented — so the carve-out is limited to GET/HEAD rather than to ``navigate`` alone.
    """
    service = await _service(engine)
    async with _client(engine, service) as c:
        r = await c.post(
            "/ui",
            headers={
                "Sec-Fetch-Site": "cross-site",
                "Sec-Fetch-Mode": "navigate",
                # Sent so the METHOD is the only thing left to refuse it. Without this the request
                # would now also fail the #1122 destination allowlist, and the test would pass for
                # a reason it does not name.
                "Sec-Fetch-Dest": "document",
            },
        )
    assert r.status_code == 403, (
        f"a cross-site POST navigation was not refused (got {r.status_code}) — that is a CSRF form "
        "submission wearing the navigation carve-out"
    )


async def test_only_a_document_destination_gets_the_navigation_carve_out(engine: Engine) -> None:
    """``object``/``embed``/``iframe``/``frame`` report ``Sec-Fetch-Mode: navigate`` while loading INTO
    someone else's page. That is framing rather than navigation, so the destination has to be checked
    too or the carve-out hands back the embedding it was meant to refuse.

    **This is one ALLOWLIST test rather than two denylist tests, and #1122 is why.** The rule shipped
    naming ``object`` and ``embed`` -- the two framing destinations anyone thinks of. Measured on the
    built app before the fix: those two were refused, while ``iframe``, ``frame`` and a request
    carrying NO ``Sec-Fetch-Dest`` at all were served. All five are now one condition, so they belong
    in one loop; splitting them again would encode the shape of the denylist rather than of the code.
    ``None`` here means the header is omitted, which is how a denylist is skipped unread.
    """
    service = await _service(engine)
    async with _client(engine, service) as c:
        for dest in ("object", "embed", "iframe", "frame", None):
            headers = {"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate"}
            if dest is not None:
                headers["Sec-Fetch-Dest"] = dest
            r = await c.get("/ui", headers=headers)
            assert r.status_code == 403, (
                f"Sec-Fetch-Dest: {dest or '<omitted>'} was allowed through the navigation carve-out "
                f"(got {r.status_code}) — only 'document' is a top-level navigation"
            )


# --------------------------------------------------------------------------------------------------
# BACKLOG #1122. The same-site half of the refused set arrives WITH the session cookie attached, and
# the shipped carve-out waved it through. The destination half of #1122's fix is folded into
# test_only_a_document_destination_gets_the_navigation_carve_out above rather than repeated here.
# --------------------------------------------------------------------------------------------------


async def test_a_same_site_navigation_needs_user_activation_because_the_cookie_rides_along(
    engine: Engine,
) -> None:
    """THE ONE REFUSED CLASS THAT ARRIVES WITH AUTHORITY, and why this half is not like the other.

    ``SameSite=Strict`` keys on the SITE, and a site ignores the port. On the shipped loopback default
    ``http://127.0.0.1:9999`` is therefore SAME-SITE to the console, so a page there can script
    ``window.open`` at a /ui URL and the operator's session cookie is attached — which a cross-site
    page cannot do. ``Sec-Fetch-User`` is what separates the operator's own click from that script:
    a scripted ``window.open``, a ``location =`` and a ``<meta http-equiv=refresh>`` all navigate
    without it.
    """
    service = await _service(engine)
    async with _client(engine, service) as c:
        for label, extra in (
            ("no Sec-Fetch-User at all", {}),
            ("Sec-Fetch-User: ?0", {"Sec-Fetch-User": "?0"}),
        ):
            r = await c.get(
                "/ui/messages/m1/attachments/a1",
                headers={
                    "Sec-Fetch-Site": "same-site",
                    "Sec-Fetch-Mode": "navigate",
                    "Sec-Fetch-Dest": "document",
                    **extra,
                },
            )
            assert r.status_code == 403, (
                f"a same-site navigation with {label} was allowed (got {r.status_code}) — that is a "
                "sibling local port scripting a navigation with the operator's cookie attached"
            )


async def test_an_operator_click_from_a_sibling_port_is_still_allowed(engine: Engine) -> None:
    """POSITIVE CONTROL for the rule above: it must refuse the script, not the human.

    Without this, refusing every same-site navigation outright would satisfy the previous test and
    would break a genuine same-site intranet link (``wiki.corp.example`` to ``console.corp.example``).
    """
    service = await _service(engine)
    async with _client(engine, service) as c:
        r = await c.get(
            "/ui",
            headers={
                "Sec-Fetch-Site": "same-site",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-User": "?1",
            },
        )
    assert r.status_code != 403, (
        "a USER-ACTIVATED same-site navigation was refused — that is an operator clicking an "
        "intranet link, and refusing it breaks a supported deployment shape"
    )
