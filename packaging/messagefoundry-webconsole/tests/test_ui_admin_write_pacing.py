# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""BACKLOG #287 -- the per-actor non-GET write floor was missing on the console.

Surfaced while researching BACKLOG #1115 (ASVS 2.4.2), which names the gap in its severity
paragraph; the parity work itself is #287's, and #287 is a live item behind the ledger's publishing
boundary rather than a closed one.

The engine charges every non-GET admin write against a per-actor budget
(``AuthService.allow_admin_write``, wired through ``api.security._enforce_admin_write_pacing`` on
``require_paced`` / ``require_step_up`` / ``require_step_up_action``). The console's ``require_ui_*``
twins charged NOTHING, and the console reaches the handlers **in-process** -- it holds no HTTP client
at all -- so a ``/ui`` write never passed through the engine dependency that does the charging. The
only pacing floor in the product was therefore absent on the one surface a human actually uses.

This is an INCOMPLETE APPLICATION OF A PRINCIPLE THE FILE ALREADY STATES rather than an oversight:
``require_ui``'s own docstring explains that the /ui PHI views call the JSON handlers directly and so
must re-apply the equivalent permission and throttle, and ``phi=True`` duly charges
``allow_phi_read``. The same paragraph then declines to charge admin writes against the PHI quota --
correctly, since that quota measures PHI reads -- and no admin-write quota was put in its place.

Scope, stated honestly: this closes the RATE floor, not ASVS 2.4.2's flow-timing verb. A per-request
budget is not "realistic human timing" across a multi-step flow, and 2.4.2 cannot honestly reach pass
on the strength of this alone.

All data here is synthetic.
"""

from __future__ import annotations

import httpx

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine

PW = "a-strong-test-passphrase"  # >=15, no app/vendor terms -- satisfies the ASVS policy (WP-3)

#: Small enough to exhaust in a test without a sleep, and distinct from the shipped default so a
#: pass cannot come from the default happening to match.
BUDGET = 4


async def _service(engine: Engine, **over: object) -> AuthService:
    settings = AuthSettings(
        require_mfa=False,
        admin_write_rate_limit_per_actor=BUDGET,
        admin_write_rate_limit_window_seconds=60.0,  # long, so the window cannot refill mid-test
        **over,  # type: ignore[arg-type]
    )
    service = AuthService(engine.store, settings)
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


async def _login(c: httpx.AsyncClient, username: str = "op") -> None:
    r = await c.post(
        "/ui/login",
        data={"username": username, "password": PW},
        headers={"Sec-Fetch-Site": "same-origin"},
    )
    assert r.status_code in (200, 303), r.status_code


#: A plain `require_ui` write -- no step-up grant needed. The connection does not exist, which is the
#: point: the DEPENDENCY resolves before the handler, so the budget is charged even though the route
#: itself would 404. That keeps the test about pacing and not about connection fixtures.
WRITE = "/ui/connections/nonexistent/stop"


async def test_ui_non_get_charges_the_per_actor_budget_and_429s_when_spent(
    engine: Engine,
) -> None:
    """The floor itself: past the budget the console refuses with 429 rather than serving."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _login(c)
        codes = []
        for _ in range(BUDGET + 3):
            r = await c.post(WRITE, headers={"Sec-Fetch-Site": "same-origin"})
            codes.append(r.status_code)
        assert 429 in codes, f"no request was ever throttled: {codes}"


async def test_the_throttle_arrives_only_after_the_budget_not_immediately(
    engine: Engine,
) -> None:
    """A limiter that refused the FIRST write would also make the test above pass while breaking the
    console outright, so pin that the early writes are served."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _login(c)
        first = await c.post(WRITE, headers={"Sec-Fetch-Site": "same-origin"})
        assert first.status_code != 429, "the very first write was throttled"


async def test_get_is_never_charged(engine: Engine) -> None:
    """NON-GET only, matching the engine. Reading a page many times must not exhaust a write budget:
    the console's nav polls on a timer, so charging GETs would throttle an idle operator."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _login(c)
        codes = [(await c.get("/ui/connections")).status_code for _ in range(BUDGET + 6)]
        assert 429 not in codes, f"a GET was charged against the write budget: {codes}"


async def test_the_budget_is_per_actor_not_global(engine: Engine) -> None:
    """One operator exhausting their budget must not lock out a different operator -- a global
    counter would pass the first test while turning any single busy admin into an estate-wide
    denial of service."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    await _add(service, "op2", Role.OPERATOR)
    async with _client(engine, service) as spender:
        await _login(spender, "op")
        for _ in range(BUDGET + 3):
            await spender.post(WRITE, headers={"Sec-Fetch-Site": "same-origin"})
    async with _client(engine, service) as other:
        await _login(other, "op2")
        r = await other.post(WRITE, headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code != 429, "a second actor was throttled by the first actor's spending"


async def test_a_cross_site_write_is_refused_without_spending_the_victims_budget(
    engine: Engine,
) -> None:
    """PROVENANCE BEFORE SPEND -- the ordering is the security property, and this test is the reason
    it is written that way.

    The routes call ``assert_same_origin`` INLINE, which runs after the dependency. A first cut of
    this floor charged the budget in the dependency and so charged it before provenance was
    established: a cross-origin page could then spend a victim's budget using the victim's
    SameSite cookie and throttle their console from off-origin, and the cross-site request came back
    429 instead of 403 -- announcing that it had been counted.

    So: a cross-site write must be 403, and must leave the budget untouched for the real operator.
    """
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _login(c)
        for _ in range(BUDGET + 5):
            r = await c.post(WRITE, headers={"Sec-Fetch-Site": "cross-site"})
            assert r.status_code == 403, f"cross-site write was not refused: {r.status_code}"
        # The budget is untouched, so the operator's own next write is still served.
        legit = await c.post(WRITE, headers={"Sec-Fetch-Site": "same-origin"})
        assert legit.status_code != 429, "an off-origin attacker spent the victim's write budget"
