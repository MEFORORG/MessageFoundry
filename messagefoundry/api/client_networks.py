# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""``[security].allowed_client_networks`` — the operator-surface source-address gate.

Refuses an operator API / web-console request whose client address falls outside every configured
network, in ASGI middleware: OUTSIDE every route, dependency, body cap and auth check, and covering
the ``/ws/stats`` WebSocket and the ``/ui/static`` mount as well as the JSON routes.

**Which address is evaluated, and why it is the right one.** This reads ``scope["client"][0]`` — the
address the SERVER reports — and parses **no forwarding header, ever**. uvicorn's
``ProxyHeadersMiddleware`` is the single X-Forwarded-For trust point in the process: it rewrites
``scope["client"]`` from XFF when, and only when, the socket peer matches ``forwarded_allow_ips``,
which ``__main__`` feeds verbatim from ``[api].trusted_proxies``. So:

* **R1, direct bind, no proxy declared** — ``trusted_proxies`` is empty, ``_TrustedHosts([])`` matches
  no peer, the XFF branch never runs, and ``scope["client"]`` is the raw socket peer. An attacker's
  ``X-Forwarded-For`` is ignored outright.
* **R2, declared proxy** (the RECOMMENDED off-box topology: engine still bound to 127.0.0.1, nginx
  faces the network) — ``trusted_proxies`` names the proxy, so uvicorn has already replaced
  ``scope["client"]`` with the real client before any app middleware runs. Self-spoofing is defeated
  by uvicorn's reverse walk, PROVIDED no attacker address is itself inside ``trusted_proxies`` — which
  is why ``ServiceSettings._client_allowlist_requires_pinned_proxies`` refuses a multi-address
  ``trusted_proxies`` entry once this allow-list is in use.
* **R3, UNDECLARED proxy** — nothing is declared, so no rewrite happens and every request in the world
  resolves to the proxy's address (127.0.0.1 for an on-box proxy). The control is **INERT**. This
  feature does not close R3 and must never be documented as if it does; the monoculture tripwire below
  only *detects* it.

Adding a second, in-app XFF parse would create a divergent trust path and is the single worst thing
that could be done to this module.

**Pure ASGI, not BaseHTTPMiddleware.** ``BaseHTTPMiddleware.__call__`` opens with
``if scope["type"] != "http": await self.app(...); return`` — it passes every WebSocket scope straight
through. A ``BaseHTTPMiddleware`` gate would leave ``/ws/stats`` reachable from any address.

It **returns** a response and never raises ``HTTPException``: ``add_middleware`` inserts user
middleware between ``ServerErrorMiddleware`` (outer) and ``ExceptionMiddleware`` (inner), so a raised
``HTTPException`` here would surface as a 500.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.types import ASGIApp, Receive, Scope, Send

from messagefoundry.netaddr import client_network_allowed

_log = logging.getLogger(__name__)

#: Machine-readable marker on every network denial, so a client (the web console's pollers) can tell
#: "your address is not permitted" apart from an RBAC 403 and react differently.
DENIAL_MARKER = "client-network"
DENIAL_HEADER = "X-MessageFoundry-Denied"

#: Paths exempt from the gate. ``/health`` is the TOKENLESS liveness probe an off-box monitor, load
#: balancer or the notification-area tray polls; it discloses nothing beyond liveness (the build
#: version is auth-gated), and its ``observed_client`` field is the ONE self-service diagnostic a
#: locked-out operator has — ``curl http://engine:8765/health`` from the machine that cannot get in
#: tells them exactly which address the engine sees. Exempting it is what keeps a CIDR lockout
#: debuggable instead of a silent "the console is down".
_EXEMPT_PATHS = frozenset({"/health"})

#: One warning per (address, hour). A denial flood must not fill the rotating log, but silence must
#: not be the only signal either — the posture counters below carry the rest.
_LOG_INTERVAL_SECONDS = 3600.0
#: Hard cap on the rate-limiter's memory so a source-rotating flood cannot grow it unbounded.
_LOG_TRACKED_ADDRESSES = 64

#: Monoculture tripwire: how many requests must be observed before "every client looks the same"
#: becomes evidence rather than noise.
_MONOCULTURE_MIN_OBSERVATIONS = 50

_DENIAL_HEADERS = {
    # A denial short-circuits both the engine's _security_headers and the console's
    # UiSecurityHeadersMiddleware, so set the baseline directly rather than ship a 403 with none of
    # them. api.header_floor.SecurityHeaderFloorMiddleware is registered further out still and
    # setdefaults the same names, so these are now a belt to its braces — and it, not this dict, is
    # what supplies the Strict-Transport-Security a static header set cannot decide on.
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Cache-Control": "no-store",
    DENIAL_HEADER: DENIAL_MARKER,
}

_DENIAL_HTML = """<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Blocked — network not permitted</title>
<style>
 body{{font:16px/1.5 system-ui,sans-serif;margin:0;padding:3rem 1.5rem;color:#111;background:#fafafa}}
 main{{max-width:38rem;margin:0 auto}}
 h1{{font-size:1.35rem;margin:0 0 1rem}}
 code{{background:#eee;padding:.1rem .35rem;border-radius:3px}}
 p{{margin:0 0 1rem}}
</style>
<main>
<h1>Blocked: your network is not permitted</h1>
<p>This MessageFoundry console restricts which source networks may reach it. Your request was
refused before sign-in.</p>
<p>The engine saw your address as <code>{observed}</code>.</p>
<p>An operator can permit it by adding a network covering that address to
<code>[security].allowed_client_networks</code> and restarting the engine. If the address above is not
the one you expect, a reverse proxy or NAT is rewriting it &mdash; the engine can only match what it
observes.</p>
</main>
"""


def _escape(value: str) -> str:
    """Minimal HTML escape for the observed address. It is a header/socket-derived string, so it is
    attacker-influenceable in principle even though a parsed IP cannot contain markup."""
    return (
        value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    )


def _wants_html(scope: Scope) -> bool:
    path = scope.get("path") or ""
    if path == "/ui" or path.startswith("/ui/"):
        return True
    for name, value in scope.get("headers") or ():
        if name == b"accept":
            return b"text/html" in value.lower()
    return False


class ClientNetworkMiddleware:
    """Enforce ``[security].allowed_client_networks`` on every HTTP and WebSocket scope.

    Registered UNCONDITIONALLY (not "only when the list is non-empty"): with an empty list the very
    first branch passes the scope straight through, so behaviour is identical, and registering
    unconditionally removes the failure mode where the control silently is not installed after a
    config edit."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        # Lifespan (and anything else non-request) MUST pass through untouched — swallowing it would
        # break startup/shutdown outright.
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        # Starlette sets scope["app"] before building/entering the middleware stack, so state is
        # available here. getattr-with-default throughout: a bare ASGI test harness may hand us a
        # scope with no app, and the gate must degrade to "no restriction", not to a crash.
        state = getattr(scope.get("app"), "state", None)
        networks: tuple[str, ...] = getattr(state, "client_networks", ()) if state else ()
        if not networks or scope.get("path") in _EXEMPT_PATHS:
            await self.app(scope, receive, send)
            return

        client = scope.get("client")
        host = client[0] if client else None
        _record_observation(state, host)
        if client_network_allowed(host, networks):
            await self.app(scope, receive, send)
            return

        _record_denial(state, host)
        if scope["type"] == "websocket":
            # Pre-accept refusal: the socket is closed before the handshake completes, so the route
            # never runs and no frame is ever sent. NOTE: uvicorn maps a pre-handshake websocket.close
            # to HTTP 403 and DISCARDS the code, so 1008 is observable in-process (and in tests) but
            # not on the wire.
            await send({"type": "websocket.close", "code": 1008})
            return
        await self._deny_http(scope, receive, send, host)

    async def _deny_http(
        self, scope: Scope, receive: Receive, send: Send, host: str | None
    ) -> None:
        observed = host or "unknown"
        response: Response
        if _wants_html(scope):
            response = HTMLResponse(
                _DENIAL_HTML.format(observed=_escape(observed)),
                status_code=403,
                headers={
                    # Self-contained page, no external assets: a locked-out browser cannot fetch
                    # /ui/static either (this gate covers the mount), so anything external would 403.
                    # default-src 'none' means NO script can run at all; style-src 'unsafe-inline' is
                    # for the one inline <style> block and carries no injection surface — the whole
                    # page is engine-authored and the single interpolated value is an HTML-escaped
                    # address that has already been rejected as an IP by the matcher.
                    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
                    **_DENIAL_HEADERS,
                },
            )
        else:
            response = JSONResponse(
                {
                    "detail": (
                        "client address is not permitted by [security].allowed_client_networks"
                    ),
                    "denied": DENIAL_MARKER,
                    # Echoing the OBSERVED address is deliberate: on a LAN threat model the caller
                    # already knows its own address, and withholding it removes the one datum that
                    # makes the failure self-diagnosing -- turning every lockout, and every
                    # proxy/NAT misresolution, into a "firewall or DNS?" escalation.
                    "observed_client": host,
                },
                status_code=403,
                headers=dict(_DENIAL_HEADERS),
            )
        await response(scope, receive, send)


def _record_observation(state: Any, host: str | None) -> None:
    """Feed the address-monoculture tripwire.

    Signature: the allow-list is in use, NO proxy is declared, and after a meaningful number of
    requests every single one has resolved to the SAME loopback address. That is R3 (an undeclared
    reverse proxy on the engine box) — the one topology where the control is inert *and silent*, since
    the loopback exemption admits every request instead of producing visible 403s. (A container bridge
    gateway or a SNAT'ing firewall collapses clients onto a NON-loopback address, which the allow-list
    denies loudly; those need no tripwire.)

    O(1) and bounded: once a second distinct address appears the tripwire can never fire, so we stop
    tracking rather than accumulate a set an address-rotating client could grow without limit."""
    if state is None or host is None:
        return
    if getattr(state, "client_address_monoculture", False):
        return  # one-shot: already fired
    if getattr(state, "trusted_proxies", ()):
        return  # a declared proxy IS the supported way to see real client addresses
    seen: str | None = getattr(state, "_client_first_address", None)
    if seen is None:
        state._client_first_address = host
        state._client_observations = 1
        return
    if seen != host:
        state._client_observations = -1  # poisoned: more than one address, never fires
        return
    count: int = getattr(state, "_client_observations", 0)
    if count < 0:
        return
    count += 1
    state._client_observations = count
    if count < _MONOCULTURE_MIN_OBSERVATIONS:
        return
    # Only loopback is the silent case (see the docstring): a non-loopback monoculture already 403s.
    if not (host == "127.0.0.1" or host == "::1" or host.startswith("::ffff:127.")):
        state._client_observations = -1
        return
    state.client_address_monoculture = True
    _log.warning(
        "[security].allowed_client_networks is set, but every one of the last %d operator requests "
        "resolved to %s and no [api].trusted_proxies is declared — the allow-list is INERT. A reverse "
        "proxy is almost certainly in front of the engine without being declared, so the engine never "
        "sees a real client address. Declare the proxy in [api].trusted_proxies. See "
        "docs/security/OFF-LOOPBACK-DEPLOYMENT.md.",
        count,
        host,
    )


def _record_denial(state: Any, host: str | None) -> None:
    """Count + log a refusal. Counters back ``GET /security/posture`` so an operator can answer "is
    this control firing?" without log-file access; the log line names the observed address and the
    setting, because an undiagnosable CIDR rejection is the most likely way this control gets ripped
    back out again. Logged to the rotating general log, NOT the audit chain: this is pre-auth (no
    actor) and a flood must not grow the audit DB — the same reasoning as the body-cap rejections."""
    if state is None:
        return
    state.client_denials = getattr(state, "client_denials", 0) + 1
    state.client_denied_last = host
    now = time.monotonic()
    seen: dict[str, float] = getattr(state, "_client_denial_log_at", None) or {}
    last = seen.get(host or "")
    if last is not None and now - last < _LOG_INTERVAL_SECONDS:
        return
    if len(seen) >= _LOG_TRACKED_ADDRESSES:
        seen.clear()  # bound the rate-limiter; a rotating flood re-logs rather than grows
    seen[host or ""] = now
    state._client_denial_log_at = seen
    _log.warning(
        "refused an operator API/console request from %s: outside [security].allowed_client_networks "
        "(%s). This is the SOURCE-NETWORK allow-list, not authentication or RBAC. If that address is "
        "not the client's real one, a reverse proxy or NAT is rewriting it and [api].trusted_proxies "
        "may be undeclared.",
        host or "an unknown address",
        ", ".join(getattr(state, "client_networks", ())) or "unset",
    )
