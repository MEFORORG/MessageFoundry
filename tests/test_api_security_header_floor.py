# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The baseline security headers must be on EVERY response, including the ones no route produced.

`_security_headers` is the INNERMOST user middleware, so every emitter outside it escaped: the request
body cap's four short-circuits shipped with none of the baseline, and an unhandled exception shipped
with none of it either (a handler registered for Exception/500 becomes ServerErrorMiddleware's, which
Starlette places outside `user_middleware` entirely). These tests assert the SECURITY property on the
error paths themselves — a normal 200 carrying the headers was already true before the fix and proves
nothing about it.

Every short-circuit is driven through a hand-built ASGI scope rather than a client, because two of the
four are unreachable through one: no HTTP client will emit `Content-Length` together with
`Transfer-Encoding`, or a non-integer `Content-Length`.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

import pytest
from starlette.types import Message, Receive, Scope, Send

from messagefoundry.api.app import create_app
from messagefoundry.api.header_floor import (
    BASELINE_SECURITY_HEADERS,
    HSTS_HEADER,
    HSTS_VALUE,
    SecurityHeaderFloorMiddleware,
)
from messagefoundry.api.request_timeout import TIMEOUT_STATE_ATTR, RequestTimeoutMiddleware

_BASELINE_NAMES = tuple(name.lower() for name, _ in BASELINE_SECURITY_HEADERS)


async def _drive(
    app: Any,
    *,
    method: str = "GET",
    path: str = "/health",
    headers: tuple[tuple[str, str], ...] = (),
    scheme: str = "http",
    client: tuple[str, int] = ("127.0.0.1", 50000),
    expect_raise: bool = False,
    scope_app: Any = None,
) -> tuple[int, dict[str, str]]:
    """Send one request straight into the ASGI app; return (status, lower-cased headers).

    ``scope_app`` populates ``scope["app"]``, which is the only way a hand-composed middleware stack
    can reach the ``app.state`` knobs the real app supplies — ``RequestTimeoutMiddleware`` reads its
    deadline from there and otherwise degrades to the shipped 120s default."""
    scope: Scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": method,
        "scheme": scheme,
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers],
        "client": client,
        "server": ("127.0.0.1", 8765),
    }
    if scope_app is not None:
        scope["app"] = scope_app
    sent: list[Message] = []

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Message) -> None:
        sent.append(message)

    if expect_raise:
        # ServerErrorMiddleware ALWAYS re-raises after sending the 500 response, so an unhandled
        # exception must be caught here or the assertions below never run at all. Matched on the
        # route's own sentinel rather than bare Exception, so a DIFFERENT failure surfaces instead of
        # being swallowed into a passing test.
        with pytest.raises(RuntimeError, match="deliberate"):
            await app(scope, receive, send)
    else:
        await app(scope, receive, send)

    start = next(m for m in sent if m["type"] == "http.response.start")
    got = {k.decode().lower(): v.decode() for k, v in start["headers"]}
    return int(start["status"]), got


class _BareApp:
    """An ASGI app that emits a response with the headers under test deliberately absent."""

    def __init__(self, status: int = 413, headers: tuple[tuple[bytes, bytes], ...] = ()) -> None:
        self.status = status
        self.headers = headers

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await send(
            {"type": "http.response.start", "status": self.status, "headers": list(self.headers)}
        )
        await send({"type": "http.response.body", "body": b"{}"})


async def test_the_driver_reports_a_missing_header_as_missing() -> None:
    """VACUITY GUARD, and it is the load-bearing test in this file.

    Every other assertion here is "the header is present". An instrument that reported every header
    present would pass all of them while proving nothing. So drive an app that emits NO baseline
    headers and assert the driver sees their absence, then wrap that same app in the floor and assert
    the same driver now sees them. The pair is what makes the presence assertions evidence."""
    bare = _BareApp()
    status, headers = await _drive(bare)
    assert status == 413
    assert [n for n in _BASELINE_NAMES if n in headers] == [], (
        f"the driver must observe absence for this file's assertions to mean anything; got {headers}"
    )

    status, headers = await _drive(SecurityHeaderFloorMiddleware(bare))
    assert status == 413, "the floor must not alter the status"
    assert [n for n in _BASELINE_NAMES if n in headers] == list(_BASELINE_NAMES)


async def test_the_floor_never_overwrites_a_header_an_inner_emitter_assigned() -> None:
    """The floor runs LAST on the response path, so it must setdefault and never assign.

    Four inner writers ASSIGN a Content-Security-Policy or Cache-Control and depend on
    last-writer-wins — the /ui CSP overlay, the attachment sandbox CSP, the console's nonce CSP and
    the two denial header sets. An assigning floor would silently replace them; this pins the
    difference on a header the floor does own, which is the strictest case."""
    app = SecurityHeaderFloorMiddleware(
        _BareApp(status=200, headers=((b"x-frame-options", b"SAMEORIGIN"),))
    )
    _, headers = await _drive(app)
    assert headers["x-frame-options"] == "SAMEORIGIN"
    assert headers["x-content-type-options"] == "nosniff"  # the ones it did not find, it still sets


@pytest.mark.parametrize(
    ("label", "request_headers", "expected_status"),
    [
        (
            "ambiguous CL+TE framing",
            (("content-length", "10"), ("transfer-encoding", "chunked")),
            400,
        ),
        ("chunked without a Content-Length", (("transfer-encoding", "chunked"),), 411),
        ("non-integer Content-Length", (("content-length", "not-a-number"),), 400),
        ("oversized Content-Length", (("content-length", "99999999"),), 413),
    ],
)
async def test_a_body_cap_refusal_carries_the_baseline_headers(
    label: str, request_headers: tuple[tuple[str, str], ...], expected_status: int
) -> None:
    """Each of the body cap's four short-circuits returns its own JSONResponse from one layer OUTSIDE
    `_security_headers`, so before the floor every one of them shipped bare. These are pre-auth
    refusals reachable by anyone who can open a socket — exactly the responses a browser most needs
    nosniff and frame-deny on."""
    app = create_app(allow_no_auth=True)
    status, headers = await _drive(app, method="POST", path="/messages", headers=request_headers)
    assert status == expected_status, label
    missing = [n for n in _BASELINE_NAMES if n not in headers]
    assert missing == [], f"{label} shipped without {missing}"


async def test_an_unhandled_exception_carries_the_baseline_headers() -> None:
    """The 500 is the one path NO middleware can reach.

    Starlette's `build_middleware_stack` routes an Exception/500 handler to ServerErrorMiddleware and
    places it OUTSIDE `user_middleware`, so the outermost floor is still inside it. `_unhandled_
    exception` therefore sets the baseline on its own response; this asserts that it does, and that
    the status and PHI-free body are unchanged by the addition."""
    app = create_app(allow_no_auth=True)

    @app.get("/_test/boom")
    async def _boom() -> None:
        raise RuntimeError("deliberate")

    status, headers = await _drive(app, path="/_test/boom", expect_raise=True)
    assert status == 500
    missing = [n for n in _BASELINE_NAMES if n not in headers]
    assert missing == [], f"the unhandled-exception response shipped without {missing}"


async def test_the_500_body_and_status_are_unchanged_by_the_header_addition() -> None:
    """This change adds headers. It must not alter the generic body (ASVS 16.5.1 — no internal detail
    reaches the client) or the status, so both are pinned alongside the header assertions."""
    from starlette.testclient import TestClient

    app = create_app(allow_no_auth=True)

    @app.get("/_test/boom2")
    async def _boom() -> None:
        raise RuntimeError("deliberate")

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/_test/boom2")
    assert response.status_code == 500
    assert response.json() == {"detail": "internal error"}
    assert "deliberate" not in response.text and "RuntimeError" not in response.text


async def test_hsts_on_an_escaped_response_follows_the_scheme_not_a_blanket_default() -> None:
    """HSTS is scheme-conditional everywhere else, and the floor must not become the one emitter that
    ships it over cleartext. The http leg is also a second negative control: it shows the assertions
    above are not simply reporting every header as present."""
    app = create_app(allow_no_auth=True)
    over_http = (("content-length", "99999999"),)

    status, headers = await _drive(app, method="POST", path="/messages", headers=over_http)
    assert status == 413
    assert HSTS_HEADER.lower() not in headers, "HSTS must not be asserted over cleartext"

    status, headers = await _drive(
        app, method="POST", path="/messages", headers=over_http, scheme="https"
    )
    assert status == 413
    assert headers[HSTS_HEADER.lower()] == HSTS_VALUE


async def test_an_operator_declared_https_terminator_gets_hsts_on_the_escaped_paths() -> None:
    """`exposure_protected` is the operator's declaration that the browser-facing scheme is https;
    behind a proxy that omits X-Forwarded-Proto the per-request scheme reads http. Both the floor and
    the 500 handler must honour it, or the escaped responses are the only ones that silently do not."""
    app = create_app(allow_no_auth=True, exposure_protected=True)

    @app.get("/_test/boom3")
    async def _boom() -> None:
        raise RuntimeError("deliberate")

    _, headers = await _drive(
        app, method="POST", path="/messages", headers=(("content-length", "99999999"),)
    )
    assert headers[HSTS_HEADER.lower()] == HSTS_VALUE

    _, headers = await _drive(app, path="/_test/boom3", expect_raise=True)
    assert headers[HSTS_HEADER.lower()] == HSTS_VALUE


async def test_the_timeout_and_network_denial_hand_copies_now_get_hsts_from_the_floor() -> None:
    """`client_networks._DENIAL_HEADERS` and `request_timeout._TIMEOUT_HEADERS` are static tuples that
    cannot decide a scheme-conditional header, so neither carries HSTS — a copy drifting from its
    original is the exact failure the floor exists to end.

    BOTH hand-copies are asserted, because the name says both. The denial is drivable through the real
    app; the timeout needs a handler that never responds, so its leg composes the same two middlewares
    in the same order the app registers them (floor outside, deadline inside) against a stalling inner
    app. Each leg asserts the tuple's OWN header survived alongside the HSTS the floor added, so this
    cannot pass by the floor having flattened the hand-copy."""
    app = create_app(allow_no_auth=True)
    app.state.client_networks = ("10.0.0.0/8",)

    # Loopback is unconditionally allowed by client_network_allowed, so the denial has to be driven
    # from an off-list NON-loopback address or the gate never fires and this test measures nothing.
    status, headers = await _drive(
        app, path="/messages", scheme="https", client=("192.0.2.7", 50000)
    )
    assert status == 403
    assert headers["x-content-type-options"] == "nosniff"  # its own hand-copy, untouched
    assert headers[HSTS_HEADER.lower()] == HSTS_VALUE  # supplied by the floor, not by the tuple

    class _Stalls:
        """Never sends a response start, so the deadline is what produces the 503."""

        async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
            await asyncio.Event().wait()

    class _FastDeadline:
        state = SimpleNamespace(**{TIMEOUT_STATE_ATTR: 0.01})

    timeout_stack = SecurityHeaderFloorMiddleware(RequestTimeoutMiddleware(_Stalls()))
    status, headers = await _drive(timeout_stack, scheme="https", scope_app=_FastDeadline())
    assert status == 503
    assert headers["x-content-type-options"] == "nosniff"  # _TIMEOUT_HEADERS, untouched
    assert headers[HSTS_HEADER.lower()] == HSTS_VALUE  # supplied by the floor, not by the tuple

    # NEGATIVE CONTROL for the leg above: without the floor the same stack yields the same 503 with
    # NO HSTS, so the assertion is evidence about the floor rather than about the tuple.
    status, headers = await _drive(
        RequestTimeoutMiddleware(_Stalls()), scheme="https", scope_app=_FastDeadline()
    )
    assert status == 503
    assert HSTS_HEADER.lower() not in headers
