# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The unconditional floor under the API's baseline security response headers (ASVS 3.4.4 / 3.4.5).

The app's ``_security_headers`` middleware is registered FIRST in ``create_app``, which makes it the
INNERMOST user middleware (``add_middleware`` inserts at index 0 and the stack is built from
``reversed(user_middleware)``). Any response that originates OUTSIDE it therefore ships without the
baseline headers unless its emitter hand-copies them, and hand-copying has already failed twice over:

* the request body cap's four short-circuits (ambiguous CL+TE framing, chunked-without-length,
  invalid ``Content-Length``, oversized body) are emitted one layer out and carried NONE of them; and
* ``client_networks._DENIAL_HEADERS`` and ``request_timeout._TIMEOUT_HEADERS`` do hand-copy, but both
  copies are missing ``Strict-Transport-Security`` — a copy drifts from its original silently.

So this is a FLOOR rather than a seventh hand-copy: a pure-ASGI send wrapper registered LAST (hence
the OUTERMOST user middleware) that ``setdefault``s the baseline onto every ``http.response.start``.
``setdefault`` is what makes it non-disturbing. Four writers ASSIGN a ``Content-Security-Policy`` or
``Cache-Control`` and depend on last-writer-wins — the engine's /ui CSP overlay, the attachment
sandbox CSP, the console's nonce CSP, and the two denial header sets above — and an ASSIGNING floor
running last would silently overwrite every one of them. It writes only names none of them own.

**It cannot close the unhandled 500, and must not be described as if it does.** Starlette routes a
handler registered for ``Exception``/``500`` to ``ServerErrorMiddleware``, which
``build_middleware_stack`` places OUTSIDE ``user_middleware`` by construction, so NO user middleware —
this one included — is in that response's path. ``_unhandled_exception`` in :mod:`.app` sets the same
baseline on its own response using the constants below. Both halves are required for full coverage.

**Path-conditional headers are deliberately NOT reproduced here.** ``Cache-Control: no-store`` and the
/ui CSP key on the request path, and a second copy of ``_NO_STORE_PREFIXES`` plus the /ui path test
would be a drift hazard worse than the gap it closes — that is the very failure this module exists to
end. The consequence is bounded and stated rather than hidden: a 413 or a 500 on a ``no-store`` path
still lacks ``Cache-Control``. Both bodies are fixed engine-authored strings ("request body too
large", "internal error") carrying no PHI and no per-caller detail, so nothing cacheable is at stake.
"""

from __future__ import annotations

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

__all__ = [
    "BASELINE_SECURITY_HEADERS",
    "HSTS_HEADER",
    "HSTS_VALUE",
    "SecurityHeaderFloorMiddleware",
    "hsts_applies",
]

#: The scheme-independent baseline, in ONE place. ``_security_headers``, the unhandled-exception
#: handler and this floor all read it, so the set cannot drift between the emitters again.
BASELINE_SECURITY_HEADERS: tuple[tuple[str, str], ...] = (
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("X-Frame-Options", "DENY"),
)

#: HSTS is scheme-conditional, so it is separate from the baseline above rather than in it.
HSTS_HEADER = "Strict-Transport-Security"
HSTS_VALUE = "max-age=31536000; includeSubDomains"


def hsts_applies(scheme: str, exposure_protected: bool) -> bool:
    """Whether ``Strict-Transport-Security`` belongs on a response built for ``scheme``.

    ONE definition of "effective https", shared by every emitter. A second, divergent one is the real
    failure mode here: a floor that emitted HSTS unconditionally would set it over cleartext, which
    browsers ignore but which contradicts the web console's documented contract that the engine emits
    it only over real https or an operator-declared terminator.

    ``exposure_protected`` is that declaration (L5b, ADR 0068 §8): behind a proxy that omits
    X-Forwarded-Proto the per-request scheme reads ``http`` even though the browser-facing scheme is
    ``https``, so the operator's declaration overrides it."""
    return scheme == "https" or exposure_protected


class SecurityHeaderFloorMiddleware:
    """``setdefault`` the baseline security headers onto every HTTP response, whatever emitted it.

    Pure ASGI, not ``BaseHTTPMiddleware``: no task hop, and — the load-bearing property — it does
    NOTHING on the request path. It calls straight through, wrapping only ``send``. That is what lets
    it sit outside :class:`~messagefoundry.api.client_networks.ClientNetworkMiddleware` without
    weakening it: a refused address still reaches no route, no dependency and no body buffer, because
    this middleware runs no request-path work at all before the gate does.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        # Lifespan and websockets carry no HTTP response headers, and swallowing lifespan would break
        # startup/shutdown outright.
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # getattr-with-default throughout, the same posture ClientNetworkMiddleware uses: a bare ASGI
        # harness may hand us a scope with no app, and a header floor must degrade to "emit the
        # scheme-independent baseline" rather than crash the response it exists to harden.
        state = getattr(scope.get("app"), "state", None)
        want_hsts = hsts_applies(
            scope.get("scheme", ""), bool(getattr(state, "exposure_protected", False))
        )

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in BASELINE_SECURITY_HEADERS:
                    headers.setdefault(name, value)
                if want_hsts:
                    headers.setdefault(HSTS_HEADER, HSTS_VALUE)
            await send(message)

        await self.app(scope, receive, send_wrapper)
