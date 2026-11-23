# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Server-side request deadline for the engine API (BACKLOG #1044, ASVS 15.1.3 / 15.2.2).

ASVS 15.1.3's "avoid building a response that takes longer than the consumer's timeout" limb had no
server-side enforcement: the only ``asyncio.wait_for`` in ``api/`` bounded the connection-test probe,
and nothing bounded a handler. A slow handler held its worker for as long as it ran, with the client's
own timeout the only thing that ever gave up — and a client giving up does not free the server.

**The bound is on BUILDING the response, not on sending it.** The deadline is cancelled the instant
``http.response.start`` goes out, so a response that has begun streaming — an attachment download, a
large log body — is never cut mid-body over a slow link. That is also the limb ASVS words: the cost
being bounded is the handler's, not the network's.

**One response start does not end the handler.** The body limit answers a counted over-cap body with
a 413 from inside the route's own read, so the route is still running when that start goes out. The
limit sets :data:`BODY_REFUSED_KEY` first, and the deadline then stays armed until the route returns.
While the 413 is written the deadline is held off to at least :data:`_REFUSAL_WRITE_GRACE_SECONDS`
past its start, so a client that keeps reading gets the whole 413 within that grace. Once the host
has taken the 413, or the write fails, the deadline is back on its own time.

**The deadline cancels only the task running the route.** If the read that crossed the cap ran on
that task, a client stalling the write past the later of the grace and the deadline's own time is
cut off with the route, and can be left with a 413 head and no body. If the read ran on a task of
its own, the deadline does not cancel the write: the route is cut off and the request ends here,
while the write runs on until the host's send returns or raises, or something else cancels that
task.

**Pure ASGI, not** ``BaseHTTPMiddleware``: no task hop, and the response-start signal is visible
directly. It is registered inside :class:`~messagefoundry.api.client_networks.ClientNetworkMiddleware`
(a refused address is rejected before it can occupy a deadline) and outside everything that builds a
response, so the deadline covers auth dependencies, the body cap and the route alike.

**The deadline ends the response, and on some routes not the work.** At least DR activate, DR
release and config reload (inline, from ``/ui``, and released through the approval gate) run their
operation through :class:`~messagefoundry.api.outlive.OutlivingOperations`,
so cancelling the handler here leaves the operation running to its own outcome row rather than half
done (vault BACKLOG #2751-#2753). At least the approval gate's outcome writes shield themselves the
same way, and the engine runs a connection flag write as its own task. Anything nobody shields is
cancelled with the handler.

Being outside the app's ``_security_headers`` middleware, the refusal sets the baseline response
headers itself rather than shipping a 503 with none of them — the same reason
``ClientNetworkMiddleware`` carries its own ``_DENIAL_HEADERS``. That hand-copy is now a belt to
:class:`~messagefoundry.api.header_floor.SecurityHeaderFloorMiddleware`'s braces rather than the only
thing standing: the floor is registered further out still and ``setdefault``s the same baseline, which
is also what supplies the ``Strict-Transport-Security`` the static tuple below structurally cannot.
"""

from __future__ import annotations

import asyncio
import logging

# By name: tests/_deadline_capture.py replaces this module's ``asyncio`` with ``timeout`` alone.
from asyncio import get_running_loop

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from messagefoundry.controlchars import scrub_log_argument

__all__ = [
    "BODY_REFUSED_KEY",
    "DEFAULT_REQUEST_TIMEOUT_SECONDS",
    "RequestTimeoutMiddleware",
    "TIMEOUT_STATE_ATTR",
]

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

#: Scope key the body limit sets just before its counted 413: that 413 is this request's response,
#: and the route it interrupted has not returned. Anything the route sends from here on is dropped.
BODY_REFUSED_KEY = "messagefoundry.body_refused"

#: How long from its start the body limit's 413 has to be written before the deadline may cut it.
#: The 413 is a few dozen bytes, so only a client that stops reading uses this. It is also the most
#: a stalled write can add to the route's deadline.
_REFUSAL_WRITE_GRACE_SECONDS = 5.0

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
        refusal_due: float | None = None  # the deadline's own time, while the 413 is being written
        refusal_handed_over = False
        route_running = True
        began = get_running_loop().time()

        try:
            async with asyncio.timeout(seconds) as deadline:

                def deadline_can_move() -> bool:
                    # An expired or exited deadline cannot be rescheduled. A concurrent read can
                    # still be writing the 413 after the route returned and the deadline exited.
                    return route_running and not deadline.expired()

                def end_refusal_hold() -> None:
                    nonlocal refusal_due
                    if refusal_due is not None and deadline_can_move():
                        deadline.reschedule(refusal_due)
                    refusal_due = None

                async def send_wrapper(message: Message) -> None:
                    nonlocal started, refusal_due, refusal_handed_over
                    refused = bool(scope.get(BODY_REFUSED_KEY))
                    if message["type"] == "http.response.start":
                        started = True
                        # The handler produced a response; from here the clock belongs to the
                        # network, not to us. Cancelling the deadline is what keeps a slow
                        # attachment download from being cut mid-body. A body-limit 413 is not
                        # the handler's response, and the handler is still running, so the
                        # deadline is only held off while the 413 is written.
                        if not refused:
                            deadline.reschedule(None)
                        elif deadline_can_move() and (due := deadline.when()) is not None:
                            refusal_due = due
                            earliest = get_running_loop().time() + _REFUSAL_WRITE_GRACE_SECONDS
                            deadline.reschedule(max(due, earliest))
                    try:
                        await send(message)
                    except BaseException:
                        end_refusal_hold()
                        raise
                    if (
                        refused
                        and message["type"] == "http.response.body"
                        and not message.get("more_body")
                    ):
                        refusal_handed_over = True
                        end_refusal_hold()

                try:
                    await self.app(scope, receive, send_wrapper)
                finally:
                    route_running = False
        except TimeoutError:
            if started:
                if scope.get(BODY_REFUSED_KEY) and deadline.expired():
                    # The deadline did its work on the route, so there is no error left to raise.
                    # The 413 was this request's response, whole or not, so no 503 follows it.
                    # A host's send can return for a client already gone, so this cannot say the
                    # client received the 413, only that the host took it. The time is measured
                    # because a write of the 413 can hold the cut up to the grace past the deadline.
                    _log.warning(
                        "request ended %.1fs after it began, cut off by its %.1fs deadline while "
                        "still running %s, on %s %s",
                        get_running_loop().time() - began,
                        seconds,
                        "after the body limit's 413 was handed to the host"
                        if refusal_handed_over
                        else "with the body limit's 413 not fully handed to the host",
                        scrub_log_argument(str(scope.get("method", "?"))),
                        scrub_log_argument(str(scope.get("path", "?"))),
                    )
                    return
                # Not this deadline: an ordinary response start cancelled it, and past a counted
                # 413 it has not expired. So at least a route's own TimeoutError lands here, and it
                # is not swallowed: the response has started, so nothing can replace it.
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
