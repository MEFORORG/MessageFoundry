# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Source-address matching — the ONE place an IP allow-list decision is made.

Two callers share this, deliberately, so the operator surface and the ingest listeners can never
disagree about what a CIDR entry means:

* the inbound connectors' per-connection ``source_ip_allowlist`` (:func:`peer_ip_allowed`), which
  matches an asyncio ``peername`` tuple, and
* ``[security].allowed_client_networks`` (:func:`client_network_allowed`), which matches the
  operator API/web-console client address from the ASGI ``scope["client"]``.

**Neutral and stdlib-only** — no engine, config, FastAPI or Qt imports — so both the transports
(which must not import the API) and the API (which must not import the transports) can depend on it.
Lives at the package root for that reason, next to the other neutral leaves
(``service_status``/``redaction``).
"""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence
from typing import Any

__all__ = ["peer_ip_allowed", "client_network_allowed"]


def _peer_ip(peername: Any) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Extract the peer IP from asyncio's ``writer.get_extra_info('peername')`` — a ``(host, port)``
    tuple for IP sockets. Returns ``None`` when there is no resolvable IP (e.g. a UNIX socket)."""
    if not isinstance(peername, tuple) or not peername:
        return None
    host = peername[0]
    if not isinstance(host, str):
        return None
    try:
        return ipaddress.ip_address(host.split("%")[0])  # strip an IPv6 zone id (fe80::1%eth0)
    except ValueError:
        return None


def peer_ip_allowed(peername: Any, allowlist: Sequence[str] | None) -> bool:
    """Whether a connecting peer is permitted by an inbound ``source_ip_allowlist`` (Tier 4
    operability). ``allowlist`` holds IP addresses and/or CIDR networks; ``None``/empty permits
    everyone (the ``[egress]`` allowlist convention). A peer with no resolvable IP is **denied** when
    an allowlist is set (fail closed). Entries are validated at wiring time; a malformed one is
    skipped here defensively. An IPv4-mapped IPv6 peer (``::ffff:a.b.c.d`` on a dual-stack socket)
    also matches an IPv4 allowlist entry."""
    if not allowlist:
        return True
    addr = _peer_ip(peername)
    if addr is None:
        return False
    candidates: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = [addr]
    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped is not None:
        candidates.append(mapped)
    for entry in allowlist:
        try:
            network = ipaddress.ip_network(entry, strict=False)  # a bare IP becomes a /32 or /128
        except ValueError:
            continue
        if any(candidate in network for candidate in candidates):
            return True
    return False


def client_network_allowed(host: str | None, allowlist: Sequence[str] | None) -> bool:
    """Whether an operator API / web-console request from ``host`` is permitted by
    ``[security].allowed_client_networks``.

    ``host`` is ``scope["client"][0]`` — the address uvicorn reports, which its
    ``ProxyHeadersMiddleware`` has ALREADY rewritten from ``X-Forwarded-For`` when (and only when)
    the socket peer matched ``[api].trusted_proxies``. This function must never be handed a
    forwarding header: a second in-app trust path would inevitably diverge from uvicorn's.

    Empty/``None`` allow-list = **no restriction** (the default — byte-identical to the pre-control
    behaviour), checked FIRST so the default path never even parses an address.

    **Loopback is always allowed**, unconditionally and with no knob. The credential-less on-box
    clients — the tray's tokenless ``/health`` poll (ADR 0113), a browser opening ``/ui`` on the
    engine host, ``messagefoundry check``, the harness/apiclient, a container HEALTHCHECK — cannot be
    named in a ward-subnet allow-list, so restricting the console must never lock the box out of its
    own console. Note this is deliberately NOT conditioned on the absence of ``X-Forwarded-For``: in
    the RECOMMENDED off-box topology the proxy runs ON the engine host and proxies to 127.0.0.1, so
    an on-box operator's request legitimately arrives with XFF present and resolves to loopback. The
    forgery that a conditional rule was meant to stop is closed instead by requiring every
    ``[api].trusted_proxies`` entry to be a single host once this allow-list is in use
    (``ServiceSettings._client_allowlist_requires_pinned_proxies``).

    An address the platform did not give us (``scope["client"] is None`` — a UNIX socket) or one that
    will not parse (starlette's ``TestClient`` sends the literal ``"testclient"``) is **DENIED**: it
    cannot be proven in-network, so fail closed.

    The loopback carve-out lives HERE and not in :func:`peer_ip_allowed` — an ingest listener that
    allow-lists a partner's address must NOT silently also admit anything on the local box.
    """
    if not allowlist:
        return True
    if host is None:
        return False
    addr = _peer_ip((host, 0))
    if addr is None:
        return False
    mapped = getattr(addr, "ipv4_mapped", None)
    if addr.is_loopback or (mapped is not None and mapped.is_loopback):
        return True
    return peer_ip_allowed((host, 0), allowlist)
