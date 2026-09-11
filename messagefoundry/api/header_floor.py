# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The unconditional floor under the API's baseline security response headers (ASVS 3.4.1/3.4.4/3.4.6).

The app's ``_security_headers`` middleware is registered FIRST in ``create_app``, which makes it the
INNERMOST user middleware (``add_middleware`` inserts at index 0 and the stack is built from
``reversed(user_middleware)``). Any response that originates OUTSIDE it therefore ships without the
baseline headers unless its emitter hand-copies them, and hand-copying has already failed twice over:

* the request body cap's four short-circuits (ambiguous CL+TE framing, chunked-without-length,
  invalid ``Content-Length``, oversized body) are emitted one layer out and carried NONE of them; and
* ``client_networks._DENIAL_HEADERS`` and ``request_timeout._TIMEOUT_HEADERS`` do hand-copy, but both
  copies are missing ``Strict-Transport-Security`` -- a copy drifts from its original silently.

So this is a FLOOR rather than a seventh hand-copy: a pure-ASGI send wrapper registered LAST (hence
the OUTERMOST user middleware) that applies the baseline to every ``http.response.start``.

**Two write modes, and the difference is load-bearing.**

``setdefault`` for the single-valued names (:data:`BASELINE_SECURITY_HEADERS`, :data:`HSTS_HEADER`).
Four writers ASSIGN a ``Content-Security-Policy`` or ``Cache-Control`` and depend on last-writer-wins
-- the engine's /ui CSP overlay, the attachment sandbox CSP, the console's nonce CSP, and the two
denial header sets above -- and an ASSIGNING floor running last would silently overwrite every one of
them.

``append`` for ``frame-ancestors`` (ASVS 3.4.6), because ``setdefault`` on a header that already
exists is a NO-OP and the responses that most need the directive are exactly the ones already
carrying a policy that omits it. CSP Level 3 enforces each policy header field INDEPENDENTLY and the
effect is their intersection, so a second field naming only ``frame-ancestors 'none'`` cannot weaken
the attachment sandbox or the per-response nonce policy -- it can only deny more. **This is why the
module no longer claims to "write only names none of them own":** appending a
``Content-Security-Policy`` writes a name four other writers do own. What makes that safe is not
ownership, it is the intersection semantics plus :func:`csp_names_frame_ancestors`, which skips the
append whenever a policy already on the response names the directive, so a writer that HAS made a
frame-ancestors decision keeps it.

**HSTS is emitted only where a user agent is permitted to note it** (:func:`hsts_notable`, ASVS
3.4.1). Since ADR 0172 the engine mints a self-signed pair and serves https by default, so the
scheme condition alone would stamp a one-year ``includeSubDomains`` policy onto every response of a
stock loopback install -- an origin RFC 6797 section 8.1.1 forbids a user agent from noting, over a
chain section 8.4 treats as a transport error. That is a control that would report success while
doing nothing, and ``includeSubDomains`` on a policy a browser DID note would force https on every
other http service on that host for a year. ``config/settings.py`` already refuses exactly this shape
when an OPERATOR declares it through ``[api].public_origin``; this is the same refusal applied to the
engine's own default posture.

**It cannot close the unhandled 500, and must not be described as if it does.** Starlette routes a
handler registered for ``Exception``/``500`` to ``ServerErrorMiddleware``, which
``build_middleware_stack`` places OUTSIDE ``user_middleware`` by construction, so NO user middleware --
this one included -- is in that response's path. ``_unhandled_exception`` in :mod:`.app` sets the same
baseline on its own response using the constants below. Both halves are required for full coverage.

**Path-conditional headers are deliberately NOT reproduced here.** ``Cache-Control: no-store`` and the
/ui CSP key on the request path, and a second copy of ``_NO_STORE_PREFIXES`` plus the /ui path test
would be a drift hazard worse than the gap it closes -- that is the very failure this module exists to
end. The consequence is bounded and stated rather than hidden: a 413 or a 500 on a ``no-store`` path
still lacks ``Cache-Control``. Both bodies are fixed engine-authored strings ("request body too
large", "internal error") carrying no PHI and no per-caller detail, so nothing cacheable is at stake.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

__all__ = [
    "BASELINE_SECURITY_HEADERS",
    "CSP_HEADER",
    "FRAME_ANCESTORS_CSP",
    "FRAME_ANCESTORS_DIRECTIVE",
    "HSTS_HEADER",
    "HSTS_VALUE",
    "SecurityHeaderFloorMiddleware",
    "csp_names_frame_ancestors",
    "host_is_ip_literal",
    "hsts_applies",
    "hsts_notable",
    "request_host",
    "served_chain_is_self_signed",
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

CSP_HEADER = "Content-Security-Policy"
FRAME_ANCESTORS_DIRECTIVE = "frame-ancestors"
#: The whole second policy this floor appends. ``'none'`` is the strictest value the directive takes,
#: and the requirement's posture limb is default-DENY, so there is no narrower correct answer.
FRAME_ANCESTORS_CSP = f"{FRAME_ANCESTORS_DIRECTIVE} 'none'"


def hsts_applies(scheme: str, exposure_protected: bool) -> bool:
    """Whether the browser-facing hop for a response built for ``scheme`` is effectively https.

    ONE definition of "effective https", shared by every emitter. A second, divergent one is the real
    failure mode here: a floor that emitted HSTS unconditionally would set it over cleartext, which
    browsers ignore but which contradicts the web console's documented contract that the engine emits
    it only over real https or an operator-declared terminator.

    ``exposure_protected`` is that declaration (L5b, ADR 0068 section 8): behind a proxy that omits
    X-Forwarded-Proto the per-request scheme reads ``http`` even though the browser-facing scheme is
    ``https``, so the operator's declaration overrides it.

    **This is a necessary condition for HSTS, not the emission gate.** Emitters call
    :func:`hsts_notable`, which adds the two RFC 6797 tests this predicate cannot see."""
    return scheme == "https" or exposure_protected


def host_is_ip_literal(host: str) -> bool:
    """Whether ``host`` is an IP literal rather than a DNS name.

    RFC 6797 section 8.1.1: a user agent MUST NOT note an IP-literal host as a Known HSTS Host, so a
    ``Strict-Transport-Security`` header emitted for one is required to be discarded. ``ipaddress`` is
    the classifier rather than a regex because it is the same parser ``ApiSettings`` uses to refuse an
    IP-literal ``[api].public_origin`` under a declared TLS posture, and the two must not disagree
    about what counts (``tests/test_api_security_header_floor.py`` pins that they do not).

    Accepts the forms a Host header and an ASGI ``server`` tuple actually carry: a bracketed IPv6
    literal and an IPv6 zone id are both stripped before the parse."""
    candidate = host.strip()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    try:
        ipaddress.ip_address(candidate.split("%", 1)[0])
    except ValueError:
        return False
    return True


def served_chain_is_self_signed(scheme: str, exposure_protected: bool) -> bool:
    """Whether the certificate this response is served under is the engine's OWN minted pair.

    RFC 6797 section 8.4: a user agent MUST NOT process the header when the connection had transport
    errors, and a self-signed chain is one -- so HSTS over the minted placeholder is inert by
    construction (ADR 0172 calls that pair "a PLACEHOLDER TO BE REPLACED, not an endorsed production
    terminator").

    **Derived rather than plumbed, and the derivation is exact given how ``serve`` builds the app.**
    ``ApiSettings.exposure_protected`` is ``tls_enabled or (tls_terminated_upstream and
    trusted_proxies)`` and ``tls_enabled`` is ``bool(tls_cert_file)``, so an OPERATOR-supplied chain
    always makes it true, and a declared upstream terminator (where the engine mints nothing and
    serves cleartext to the proxy) makes it true as well. ``https`` on the wire with it FALSE is
    therefore exactly the posture ``ensure_api_tls_material`` reaches by minting. ``serve`` passes
    ``exposure_protected=settings.api.exposure_protected`` computed from the ORIGINAL settings, not
    from the ``model_copy`` carrying the minted path, which is what keeps that equivalence true; a
    change to that line has to move this predicate with it."""
    return scheme == "https" and not exposure_protected


def hsts_notable(scheme: str, exposure_protected: bool, *, host: str) -> bool:
    """Whether ``Strict-Transport-Security`` belongs on a response -- the emission gate (ASVS 3.4.1).

    ``host`` is keyword-only and REQUIRED so that no emitter can silently fall back to the permissive
    answer by forgetting it. Pass the request's host (``request.url.hostname`` / the Host header);
    ``""`` when it genuinely cannot be resolved, which does not by itself suppress the header."""
    if not hsts_applies(scheme, exposure_protected):
        return False
    if host_is_ip_literal(host):
        return False
    return not served_chain_is_self_signed(scheme, exposure_protected)


def csp_names_frame_ancestors(policies: Iterable[str]) -> bool:
    """Whether any serialized CSP in ``policies`` already names ``frame-ancestors``.

    Parsed per CSP Level 3: a policy is ``;``-separated directives, each a name followed by optional
    whitespace-separated values, and directive names are ASCII case-insensitive. A substring test
    would be wrong in both directions -- it would match the token inside a ``report-uri`` path, and it
    would miss ``FRAME-ANCESTORS``."""
    for policy in policies:
        for serialized in policy.split(";"):
            directive = serialized.strip()
            if directive and directive.split(None, 1)[0].casefold() == FRAME_ANCESTORS_DIRECTIVE:
                return True
    return False


def _bare_host(authority: str) -> str:
    """Strip a port and IPv6 brackets from an authority. A bare (unbracketed) IPv6 literal has more
    than one colon and no port, so it is returned whole rather than truncated at its first group."""
    value = authority.strip()
    if value.startswith("["):
        end = value.find("]")
        return value[1:end] if end > 0 else value[1:]
    if value.count(":") == 1:
        return value.split(":", 1)[0]
    return value


def request_host(scope: Scope) -> str:
    """The host this response is being built for, as a bare host with no port or brackets.

    The Host header is client-supplied, so it is read as untrusted DATA and used only to make the
    header floor STRICTER (an IP-literal Host suppresses HSTS). A forged DNS-name Host cannot make
    the engine emit HSTS on a posture that would not otherwise carry it, because the self-signed and
    scheme tests do not consult it at all. Falls back to the ASGI ``server`` tuple, which the client
    cannot influence, when no Host header is present."""
    for name, value in scope.get("headers") or ():
        if name == b"host":
            return _bare_host(bytes(value).decode("latin-1"))
    server = scope.get("server")
    if server:
        return _bare_host(str(server[0]))
    return ""


class SecurityHeaderFloorMiddleware:
    """Apply the baseline security headers to every HTTP response, whatever emitted it.

    Pure ASGI, not ``BaseHTTPMiddleware``: no task hop, and -- the load-bearing property -- it does
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
        want_hsts = hsts_notable(
            scope.get("scheme", ""),
            bool(getattr(state, "exposure_protected", False)),
            host=request_host(scope),
        )

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in BASELINE_SECURITY_HEADERS:
                    headers.setdefault(name, value)
                if want_hsts:
                    headers.setdefault(HSTS_HEADER, HSTS_VALUE)
                # APPEND, never setdefault: setdefault is a no-op on a response that already carries a
                # policy, which is precisely the attachment sandbox and the /ui nonce policy. See the
                # module docstring for why a second field cannot weaken either.
                if not csp_names_frame_ancestors(headers.getlist(CSP_HEADER)):
                    headers.append(CSP_HEADER, FRAME_ANCESTORS_CSP)
            await send(message)

        await self.app(scope, receive, send_wrapper)
