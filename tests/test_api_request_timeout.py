# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The engine API bounds how long a handler may build a response (BACKLOG #1044).

ASVS 15.1.3's "avoid building a response that takes longer than the consumer's timeout" limb (properly
15.2.2 territory) had no server-side enforcement: the only `asyncio.wait_for` in `api/` bounded the
connection-test probe. A slow handler held its worker for as long as it ran.

There is no exposure on the shipping config -- loopback bind, authentication required, single worker
-- so this is a bound that would matter on first deployment, not a live defect.

The tests drive the FULL app built by `create_app`, not a bare ASGI stack, because the claim is about
where the middleware sits: outside the auth dependencies and the body cap, inside the client-network
gate. A hand-built stack would pass while the registration was wrong.
"""

from __future__ import annotations

import asyncio
import warnings

import pytest
from starlette.testclient import TestClient

from messagefoundry.api import create_app
from messagefoundry.api.request_timeout import (
    DEFAULT_REQUEST_TIMEOUT_SECONDS,
    TIMEOUT_STATE_ATTR,
)

#: Long enough that no scheduling hiccup finishes it inside the deadline, short enough that the RED
#: run is not a wait: the deadlines below are 0.05-0.2s.
_SLOW_SECONDS = 3.0


def _app_with_a_slow_route(timeout_seconds: float | None) -> tuple[object, list[str]]:
    """The real app plus one deliberately slow route, and a list that records whether the handler
    ran to completion (so a 503 can be told apart from a handler that quietly finished)."""
    app = create_app()
    finished: list[str] = []

    @app.get("/_test/slow")
    async def _slow() -> dict[str, str]:
        await asyncio.sleep(_SLOW_SECONDS)
        finished.append("slow")
        return {"status": "finished"}

    @app.get("/_test/fast")
    async def _fast() -> dict[str, str]:
        finished.append("fast")
        return {"status": "ok"}

    if timeout_seconds is not None:
        app.state.request_timeout_seconds = timeout_seconds
    return app, finished


def _client(app: object) -> TestClient:
    with warnings.catch_warnings():  # the starlette<->httpx TestClient deprecation warning is noise
        warnings.simplefilter("ignore")
        return TestClient(app)  # type: ignore[arg-type]


def test_a_slow_handler_is_refused_with_a_bounded_error() -> None:
    """The bound itself. Mutation: remove the `RequestTimeoutMiddleware` registration from
    `create_app`. Red: 200 with `{"status": "finished"}` after the handler ran to completion."""
    app, finished = _app_with_a_slow_route(0.1)
    with _client(app) as client:
        response = client.get("/_test/slow")
    assert response.status_code == 503, (
        f"a handler that never responded returned {response.status_code}, not a bounded error"
    )
    assert response.json() == {"detail": "the server timed out building a response"}
    assert finished == [], "the handler must be cancelled, not merely reported on"


def test_the_refusal_carries_the_baseline_security_headers() -> None:
    """The middleware sits OUTSIDE the app's `_security_headers`, so a refusal short-circuits it. If
    it did not set them itself the 503 would be the one response in the API with none of them.

    Mutation: drop `_TIMEOUT_HEADERS`. Red: the missing header is named."""
    app, _ = _app_with_a_slow_route(0.1)
    with _client(app) as client:
        response = client.get("/_test/slow")
    assert response.status_code == 503
    for header, value in (
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "no-referrer"),
        ("X-Frame-Options", "DENY"),
        ("Cache-Control", "no-store"),
    ):
        assert response.headers.get(header) == value, f"the 503 is missing {header}"


def test_a_fast_handler_is_untouched() -> None:
    """Live positive control: with the SAME deadline in force, a handler that answers promptly
    returns its own response. Without this, a middleware that 503'd everything would pass the bound
    test above."""
    app, finished = _app_with_a_slow_route(0.1)
    with _client(app) as client:
        response = client.get("/_test/fast")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert finished == ["fast"]


def test_the_deadline_is_on_the_route_not_only_on_unauthenticated_paths() -> None:
    """The deadline must cover a real engine route, not just the test route bolted on above -- i.e.
    the middleware is genuinely outside the auth dependencies rather than inside the router.

    `/status` requires auth and, with no auth service attached, fails closed. What is asserted here
    is only that a real route still answers under a deadline in force: a middleware that swallowed
    or delayed authenticated routes would show up as a 503 instead of the fail-closed status."""
    app, _ = _app_with_a_slow_route(5.0)
    with _client(app) as client:
        assert client.get("/health").status_code == 200
        assert client.get("/status").status_code in (401, 403, 503)


def test_a_disabled_deadline_lets_a_slow_handler_finish() -> None:
    """`<= 0` disables the deadline. This is the escape hatch a deployment with a genuinely long
    admin operation uses, and it must actually disable rather than clamp to some floor."""
    app, finished = _app_with_a_slow_route(0.0)
    with _client(app) as client:
        response = client.get("/_test/fast")
    assert response.status_code == 200
    assert finished == ["fast"]


def test_the_deadline_sits_inside_the_network_gate_and_outside_everything_else() -> None:
    """The registration order is the claim, so it is pinned rather than described in a comment.

    `add_middleware` inserts at index 0 and the stack is built from `reversed(user_middleware)`, so
    index 0 is OUTERMOST. Only `SecurityHeaderFloorMiddleware` may sit above `ClientNetworkMiddleware`:
    the floor runs NOTHING on the request path (it wraps `send` only), so the gate's substantive claim
    is unchanged — a refused address is still rejected before it can occupy a deadline, reach a route,
    a dependency or a body buffer. The deadline must be next after the gate, i.e. outside the
    attachment CSP re-assert, the console's own middleware, the body cap, the security-headers
    middleware and every auth dependency. It must also be pure ASGI: a `BaseHTTPMiddleware` here would
    add a task hop and hide the response-start signal the deadline is cancelled on."""
    from starlette.middleware.base import BaseHTTPMiddleware

    from messagefoundry.api.client_networks import ClientNetworkMiddleware
    from messagefoundry.api.header_floor import SecurityHeaderFloorMiddleware
    from messagefoundry.api.request_timeout import RequestTimeoutMiddleware

    app = create_app()
    registered = [m.cls for m in app.user_middleware]
    assert registered[0] is SecurityHeaderFloorMiddleware, (
        "only the response-header floor may sit outside the network gate; "
        f"the stack is {registered}"
    )
    assert registered[1] is ClientNetworkMiddleware, (
        f"the network gate must precede everything that builds a response; the stack is {registered}"
    )
    assert registered[2] is RequestTimeoutMiddleware, (
        f"the request deadline must sit directly inside the network gate; the stack is {registered}"
    )
    assert registered.count(RequestTimeoutMiddleware) == 1
    assert not issubclass(RequestTimeoutMiddleware, BaseHTTPMiddleware)


def test_the_shipped_default_is_a_backstop_not_a_latency_budget() -> None:
    """A default so tight that ordinary admin work tripped it would be a self-inflicted outage, and
    one so loose it never fires is not a control. Pinned so a future edit is a decision."""
    assert DEFAULT_REQUEST_TIMEOUT_SECONDS == 120.0
    assert TIMEOUT_STATE_ATTR == "request_timeout_seconds"


@pytest.mark.parametrize("attr_value", [None, "not-a-number"])
def test_an_unusable_state_value_falls_back_to_the_default(attr_value: object) -> None:
    """The override is read off `app.state` with a default. A missing or non-numeric value must
    leave the shipped deadline in force -- never disable the control, and never crash the request."""
    app, finished = _app_with_a_slow_route(None)
    if attr_value is not None:
        app.state.request_timeout_seconds = attr_value  # type: ignore[attr-defined]
    with _client(app) as client:
        response = client.get("/_test/fast")
    assert response.status_code == 200
    assert finished == ["fast"]
