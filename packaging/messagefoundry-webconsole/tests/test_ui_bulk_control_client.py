# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The console BULK connection control must attribute its denial rows to the browser.

BACKLOG #1742, ADR 0150. ``_dual_role_control`` takes an optional ``client`` and threads it into
``_audit_channel_denied``. The JSON per-name routes pass ``client=client_ip(request)``; the console
per-name routes forward the browser's ``Request`` into those same JSON handlers. ``ui_bulk_control``
passed neither, so a bulk-initiated denial would land with a NULL client.

ADR 0150 gives NULL a meaning: no client was in scope. A browser-initiated control HAS a client in
scope, so a NULL there would not be missing data, it would be a false statement about the row's
provenance -- and a refusal is the row an investigator most wants a host for.

Each test names the mutation that must turn it RED.
"""

from __future__ import annotations

import base64
from urllib.parse import urlencode

import httpx

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine

PW = "a-strong-test-passphrase"  # >=15, no app/vendor terms -- satisfies the ASVS policy (WP-3)

#: The audit action ``_audit_channel_denied`` writes. The console must carry a client on the SAME
#: action the JSON plane writes, or a query over the engine's vocabulary reads the console's
#: refusals as unattributed.
_ACTION = "auth.channel_denied"

#: In scope for the test operator, so a control against it is permitted rather than denied.
_ALLOWED = "IB_ALLOWED"
#: Outside that scope, so controlling it is the per-channel RBAC denial under test.
_DENIED = "IB_DENIED"

#: What ``httpx.ASGITransport`` reports as the peer, and so what ``client_ip`` extracts.
_BROWSER = "127.0.0.1"


async def _service(engine: Engine) -> AuthService:
    # The MFA ACCESS gate sits above the permission loop, so an un-enrolled session 303s to /ui/mfa
    # and never reaches the control route (AuthService.audit_mfa_denied states why).
    service = AuthService(
        engine.store, AuthSettings(require_mfa=False, login_rate_limit_enabled=False)
    )
    await service.initialize()
    return service


def _client(engine: Engine, service: AuthService) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=create_app(engine, auth=service, serve_ui=True))
    return httpx.AsyncClient(transport=transport, base_url="http://t")


async def _scoped_operator(service: AuthService) -> None:
    """An OPERATOR holding CONNECTIONS_CONTROL but scoped to ``_ALLOWED`` alone.

    The scope is set BEFORE the caller logs in: ``set_channel_scope`` revokes the user's sessions,
    so scoping an already-logged-in client would log it straight back out.
    """
    user_id = await service.create_local_user(
        username="op",
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.OPERATOR.value],
        actor="test",
    )
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id, password_hash=user.password_hash, must_change_password=False
    )
    await service.set_channel_scope(user_id, [_ALLOWED], actor="test")


async def _login(c: httpx.AsyncClient) -> None:
    r = await c.post("/ui/login", data={"username": "op", "password": PW})
    assert r.status_code == 303, f"login did not succeed: {r.status_code}"


def _row_key(role: str, channel_id: str, destination: str = "") -> str:
    """Mint a selection checkbox value exactly as ``pages.connections._row_key`` does:
    ``role|b64url(channel_id)|b64url(destination)``."""

    def b(value: str) -> str:
        return base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii")

    return f"{role}|{b(channel_id)}|{b(destination)}"


async def _post_pairs(
    c: httpx.AsyncClient, url: str, pairs: list[tuple[str, str]]
) -> httpx.Response:
    """Same-origin urlencoded POST with REPEATED fields -- httpx's dict ``data=`` collapses the
    duplicate ``sel`` keys the bulk surface is built on."""
    return await c.post(
        url,
        content=urlencode(pairs),
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Sec-Fetch-Site": "same-origin",
        },
    )


async def _denials(engine: Engine) -> list[dict[str, object]]:
    # Filter in SQL, not in Python: `limit` applies BEFORE any client-side filter, so scanning a
    # window of all actions could push a denial row out of it as this file grows logins or targets.
    return [dict(r) for r in await engine.store.list_audit(limit=200, action=_ACTION)]


async def test_the_per_name_console_control_records_the_browser_address(engine: Engine) -> None:
    """RED when: the console per-name control stops forwarding the browser's ``Request``.

    THIS IS THE POSITIVE CONTROL for the bulk test below, and it is not decoration. A bulk test
    asserting "client is not NULL" could fail for reasons that have nothing to do with the bulk
    route -- an audit column nothing ever writes, a denial path that takes no client at all, a
    transport that reports no peer. Proving the SAME denial, through the sibling route, on the same
    engine and the same transport, DOES land an address isolates the bulk route as the difference.
    """
    service = await _service(engine)
    await _scoped_operator(service)

    async with _client(engine, service) as c:
        await _login(c)
        assert await _denials(engine) == [], (
            "a denial row already existed before the control action, so a row found afterwards "
            "would not be attributable to it"
        )
        r = await _post_pairs(c, f"/ui/connections/{_DENIED}/stop", [])
        assert r.status_code == 403, f"expected the per-channel refusal, got {r.status_code}"

    rows = await _denials(engine)
    assert len(rows) == 1, f"expected exactly one {_ACTION} row, got {len(rows)}"
    assert rows[0]["client"] == _BROWSER, (
        "the per-name console control must attribute the denial to the browser's address; this "
        f"assertion is what makes the bulk test below meaningful. row={rows[0]!r}"
    )


async def test_the_bulk_console_control_records_the_browser_address(engine: Engine) -> None:
    """RED when: ``ui_bulk_control`` drops ``client=client_ip(request)`` from its
    ``dual_role_control`` call -- which is the pre-fix code, and this test fails against it.

    The bulk surface is what an operator reaches for when acting on many connections at once, so it
    is the likeliest source of a refusal worth investigating. It must not be the one path that
    files that refusal anonymously.

    KEPT DELIBERATELY even though the multi-target test below fails on this same mutation: this is
    the single-target repro, so when both go red this one localizes the fault without the reader
    having to rule out the per-target loop first.
    """
    service = await _service(engine)
    await _scoped_operator(service)

    async with _client(engine, service) as c:
        await _login(c)
        assert await _denials(engine) == [], (
            "a denial row already existed before the bulk action, so a row found afterwards would "
            "not be attributable to it"
        )
        r = await _post_pairs(
            c,
            "/ui/connections/bulk-control",
            [("action", "stop"), ("sel", _row_key("source", _DENIED))],
        )
        # The batch captures each per-target failure and renders it, so the refusal is a 200 page.
        assert r.status_code == 200, f"the batch should absorb the 403, got {r.status_code}"
        assert "403" in r.text, "the result page should report the refusal for the target"

    rows = await _denials(engine)
    assert len(rows) == 1, f"expected exactly one {_ACTION} row, got {len(rows)}"
    assert rows[0]["client"] == _BROWSER, (
        "ADR 0150: a browser-initiated bulk control has a client in scope, so its denial row must "
        f"carry the browser's address rather than NULL. row={rows[0]!r}"
    )


async def test_every_denied_target_in_one_batch_is_attributed(engine: Engine) -> None:
    """RED when: the client reaches only the first target rather than every ``dual_role_control``
    call in the loop.

    A bulk refusal is a SEQUENCE. Attributing the first target and leaving the rest NULL would hide
    the shape of exactly the sweep this audit exists to make visible, while still passing a
    single-target test.
    """
    service = await _service(engine)
    await _scoped_operator(service)
    targets = [f"{_DENIED}_{n}" for n in (1, 2, 3)]

    async with _client(engine, service) as c:
        await _login(c)
        r = await _post_pairs(
            c,
            "/ui/connections/bulk-control",
            [("action", "stop"), *[("sel", _row_key("source", t)) for t in targets]],
        )
        assert r.status_code == 200

    clients = [r["client"] for r in await _denials(engine)]
    assert clients == [_BROWSER] * len(targets), (
        f"expected one attributed row per denied target, got {clients}"
    )


async def test_a_permitted_bulk_target_is_not_denied(engine: Engine) -> None:
    """RED when: the scope fixture stops discriminating -- a guard that denied EVERYTHING would make
    the tests above pass while proving nothing about per-channel RBAC.

    ``_ALLOWED`` is in scope, so it reaches the 404 for a name no runner serves rather than the 403,
    and writes no denial row at all.
    """
    service = await _service(engine)
    await _scoped_operator(service)

    async with _client(engine, service) as c:
        await _login(c)
        r = await _post_pairs(
            c,
            "/ui/connections/bulk-control",
            [("action", "stop"), ("sel", _row_key("source", _ALLOWED))],
        )
        assert r.status_code == 200
        assert "404" in r.text, f"an in-scope name should reach the 404, not the 403: {r.text!r}"

    assert await _denials(engine) == [], (
        "an in-scope target must write no channel-denied row; if it does, the guard is denying "
        "everything and the attribution tests above are vacuous"
    )
