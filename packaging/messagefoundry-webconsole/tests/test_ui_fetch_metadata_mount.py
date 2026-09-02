# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The cross-site refusal reaches the /ui/static MOUNT, and does not overreach (BACKLOG #1122).

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
    """
    service = await _service(engine)
    async with _client(engine, service) as c:
        r = await c.get("/ui/static/app.css")
    assert r.status_code != 403, "a headerless request was refused; absence must be allowed"


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
    """
    service = await _service(engine)
    async with _client(engine, service) as c:
        r = await c.get(
            "/ui",
            headers={"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate"},
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
            headers={"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate"},
        )
    assert r.status_code == 403, (
        f"a cross-site POST navigation was not refused (got {r.status_code}) — that is a CSRF form "
        "submission wearing the navigation carve-out"
    )


async def test_object_and_embed_do_not_get_the_navigation_carve_out(engine: Engine) -> None:
    """``object``/``embed`` report ``Sec-Fetch-Mode: navigate`` while loading INTO someone else's page.

    That is framing rather than navigation, so the destination has to be checked too or the carve-out
    hands back the embedding it was meant to refuse.
    """
    service = await _service(engine)
    async with _client(engine, service) as c:
        for dest in ("object", "embed"):
            r = await c.get(
                "/ui",
                headers={
                    "Sec-Fetch-Site": "cross-site",
                    "Sec-Fetch-Mode": "navigate",
                    "Sec-Fetch-Dest": dest,
                },
            )
            assert r.status_code == 403, (
                f"Sec-Fetch-Dest: {dest} was allowed through the navigation carve-out (got "
                f"{r.status_code}) — that is cross-site framing, not navigation"
            )
