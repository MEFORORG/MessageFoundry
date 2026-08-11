# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Server-side request deadline for the engine API (BACKLOG #1044, ASVS 15.1.3 / 15.2.2).

ASVS 15.1.3's "avoid building a response that takes longer than the consumer's timeout" limb had no
server-side enforcement: the only ``asyncio.wait_for`` in ``api/`` bounded the connection-test probe,
and nothing bounded a handler. A slow handler held its worker for as long as it ran, with the client's
own timeout the only thing that ever gave up — and a client giving up does not free the server.

**The bound is on BUILDING the response, not on sending it.** The deadline is cancelled the instant
``http.response.start`` goes out, so a response that has begun streaming — an attachment download, a
large log body — is never cut mid-body over a slow link. That is also the limb ASVS words: the cost
being bounded is the handler's, not the network's.

**Pure ASGI, not** ``BaseHTTPMiddleware``: no task hop, and the response-start signal is visible
directly. It is registered inside :class:`~messagefoundry.api.client_networks.ClientNetworkMiddleware`
(a refused address is rejected before it can occupy a deadline) and outside everything else, so the
deadline covers auth dependencies, the body cap and the route alike.

Being outside the app's ``_security_headers`` middleware, the refusal sets the baseline response
headers itself rather than shipping a 503 with none of them — the same reason
``ClientNetworkMiddleware`` carries its own ``_DENIAL_HEADERS``.
"""

from __future__ import annotations

import asyncio
import logging

from starlette.types import ASGIApp, Message, Receive, Scope, Send

__all__ = ["RequestTimeoutMiddleware", "DEFAULT_REQUEST_TIMEOUT_SECONDS", "TIMEOUT_STATE_ATTR"]

_log = logging.getLogger(__name__)

#: Wall-clock ceiling on building one HTTP response, in seconds. Deliberately generous: this is a
#: runaway-handler backstop, not a latency budget, and every route that has its own expectation
#: already carries a tighter one (the connection-test probe caps itself at 35s). A deployment with a
#: genuinely long admin operation — an integrity check over a very large store — raises it through
#: the state attribute below rather than losing the backstop everywhere else.
DEFAULT_REQUEST_TIMEOUT_SECONDS = 120.0

#: ``app.state`` attribute that overrides the default; ``<= 0`` disables the deadline entirely.
#: Read per request with a default, the same posture ``ClientNetworkMiddleware`` uses for its own
#: state, so a bare ASGI scope with no app degrades to the shipped default rather than crashing.
#: This is the seam a ``[api]`` knob would set; it is not wired to config today.
TIMEOUT_STATE_ATTR = "request_timeout_seconds"

#: Set directly because this middleware sits OUTSIDE the app's ``_security_headers``, so a refusal
#: short-circuits it. Mirrors ``client_networks._DENIAL_HEADERS`` minus its denial marker.
_TIMEOUT_HEADERS: tuple[tuple[bytes, bytes], ...] = (
    (b"content-type", b"application/json"),
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"no-referrer"),
    (b"x-frame-options", b"DENY"),
    (b"cache-control", b"no-store"),
)

#: PHI-free, and it names no path, no parameter and no internal detail — a timeout is exactly the
#: signal an attacker probes for expensive routes with.
_TIMEOUT_BODY = b'{"detail":"the server timed out building a response"}'


class RequestTimeoutMiddleware:
    """Refuse with 503 when a handler has not begun responding within the deadline."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        # Lifespan and websockets pass through untouched: a websocket is long-lived BY DESIGN, and
        # swallowing lifespan would break startup/shutdown outright.
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        state = getattr(scope.get("app"), "state", None)
        seconds = getattr(state, TIMEOUT_STATE_ATTR, DEFAULT_REQUEST_TIMEOUT_SECONDS)
        if not isinstance(seconds, int | float) or seconds <= 0:
            await self.app(scope, receive, send)
            return

        started = False

        try:
            async with asyncio.timeout(seconds) as deadline:

                async def send_wrapper(message: Message) -> None:
                    nonlocal started
                    if message["type"] == "http.response.start":
                        started = True
                        # The handler produced a response; from here the clock belongs to the
                        # network, not to us. Cancelling the deadline is what keeps a slow
                        # attachment download from being cut mid-body.
                        deadline.reschedule(None)
                    await send(message)

                await self.app(scope, receive, send_wrapper)
        except TimeoutError:
            if started:
                # Unreachable while the reschedule above stands, and deliberately not swallowed:
                # the response is already on the wire, so there is nothing to replace it with.
                raise
            # Logged, not silent — a control that refuses work must be visible or an operator
            # cannot tell a deadline from an outage. The path is engine-routed, never a body.
            _log.warning(
                "request timed out after %.1fs building a response for %s %s",
                seconds,
                scope.get("method", "?"),
                scope.get("path", "?"),
            )
            await send(
                {
                    "type": "http.response.start",
                    "status": 503,
                    "headers": list(_TIMEOUT_HEADERS),
                }
            )
            await send({"type": "http.response.body", "body": _TIMEOUT_BODY})
