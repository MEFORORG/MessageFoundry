# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Source-address matching — the ONE place an IP allow-list decision is made.

Two callers share this, deliberately, so the operator surface and the ingest listeners can never
disagree about what a CIDR entry means:

* the inbound connectors' per-connection ``source_ip_allowlist`` (:func:`peer_ip_allowed`), which
  matches an asyncio ``peername`` tuple, and
* ``[security].allowed_client_networks`` (:func:`client_network_allowed`), which matches the
  operator API/web-console client address from the ASGI ``scope["client"]``.

It also holds the one rule for whether a ``source_ip_allowlist`` is narrow enough to count as a
peer control (:func:`allowlist_restricts`). The HTTP intake gate and the DICOM server's gate
both ask it, so the two agree on whether a list counts (vault BACKLOG #2622). What each does with a
list that does not count is its own: the HTTP gate refuses only on an enforcing instance and warns
otherwise, and the DICOM gate refuses on every instance.

**Neutral and stdlib-only** — no engine, config, FastAPI or Qt imports — so both the transports
(which must not import the API) and the API (which must not import the transports) can depend on it.
Lives at the package root for that reason, next to the other neutral leaves
(``service_status``/``redaction``).
"""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence
from typing import Any, Final

__all__ = [
    "ALLOWLIST_MIN_PREFIX_V4",
    "ALLOWLIST_MIN_PREFIX_V6",
    "IPV4_COMPATIBLE",
    "IPV4_EMBEDDING_PREFIXES",
    "IPV4_MAPPED",
    "IPV4_MAPPED_BASE",
    "NAT64_LOCAL_USE",
    "NAT64_WELL_KNOWN",
    "SIX_TO_FOUR",
    "allowlist_restricts",
    "client_network_allowed",
    "host_address",
    "ipv4_meaning",
    "not_a_host_address",
    "peer_ip_allowed",
]

#: Minimum prefix length an entry of ``source_ip_allowlist`` must carry before it counts as an
#: effective peer control (ADR 0154 D7). Generous on purpose — ``/8`` admits ``10.0.0.0/8``, a
#: legitimate private scope — but it excludes ``0.0.0.0/0`` and ``::/0``, which allow-list the entire
#: internet while reading, in a config file, exactly like a restriction.
ALLOWLIST_MIN_PREFIX_V4: Final = 8
ALLOWLIST_MIN_PREFIX_V6: Final = 32

#: The IPv4-mapped block. An entry or address inside it names IPv4 hosts in their IPv6 spelling
#: (BACKLOG #3042).
IPV4_MAPPED: Final = ipaddress.IPv6Network("::ffff:0:0/96")
IPV4_MAPPED_BASE: Final = int(IPV4_MAPPED.network_address)

#: IPv6 prefixes whose addresses carry an IPv4 client: the NAT64 well-known and local-use prefixes
#: (RFC 6052, RFC 8215), Teredo (RFC 4380), 6to4 (RFC 3056) and the deprecated IPv4-compatible
#: form. Only the span limit on the HTTP listener's ``trusted_proxies``
#: (``config.listener_proxies``) reads ``IPV4_EMBEDDING_PREFIXES`` (BACKLOG #5525). The listener's
#: budget keying, at least ``_budget_key``, ``_embedded_client`` and ``_is_phantom``, reads
#: ``NAT64_WELL_KNOWN``, ``NAT64_LOCAL_USE``, ``IPV4_COMPATIBLE`` and ``ipaddress``'s Teredo and
#: 6to4 readings instead. :func:`allowlist_restricts` reads :data:`_IPV4_EMBEDDING_RANGES`, which,
#: unlike ``IPV4_EMBEDDING_PREFIXES``, also holds the IPv4-mapped block and SIIT
#: (``::ffff:0:0:0/96``) and leaves out 6to4.
NAT64_WELL_KNOWN: Final = ipaddress.IPv6Network("64:ff9b::/96")
NAT64_LOCAL_USE: Final = ipaddress.IPv6Network("64:ff9b:1::/48")
SIX_TO_FOUR: Final = ipaddress.IPv6Network("2002::/16")
IPV4_COMPATIBLE: Final = ipaddress.IPv6Network("::/96")
IPV4_EMBEDDING_PREFIXES: Final = (
    NAT64_WELL_KNOWN,
    NAT64_LOCAL_USE,
    ipaddress.IPv6Network("2001::/32"),
    SIX_TO_FOUR,
    IPV4_COMPATIBLE,
)

#: RFC 1122's "this network" block. ``ipaddress`` names only its first address, as unspecified: it
#: reads the rest, such as ``0.1.2.3``, as neither unspecified nor reserved (BACKLOG #3765).
_THIS_NETWORK: Final = ipaddress.IPv4Network("0.0.0.0/8")


def ipv4_meaning(
    network: ipaddress.IPv4Network | ipaddress.IPv6Network,
) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """``network`` as the IPv4 range it names when it sits inside the mapped block, else itself, so
    ``::ffff:0:0/96`` counts as the whole IPv4 family it trusts (BACKLOG #3042)."""
    # Every caller passes a zoneless network: a zoned entry is refused, or stripped of its zone.
    if isinstance(network, ipaddress.IPv6Network) and network.subnet_of(IPV4_MAPPED):
        return ipaddress.IPv4Network(
            (int(network.network_address) & 0xFFFF_FFFF, network.prefixlen - IPV4_MAPPED.prefixlen)
        )
    return network


def not_a_host_address(text: str) -> bool:
    """Whether the canonical IPv4 ``text`` is not one host's address: at least the whole
    ``0.0.0.0/8`` block, a multicast group, and the reserved class E range, which holds the limited
    broadcast ``255.255.255.255`` (BACKLOG #3075, #3765). No identity provider or link is served
    from one, and some browsers route ``0.0.0.0`` to the local machine. This does not refuse
    loopback: a ``127.0.0.1`` entry still loads, as ``localhost`` does.

    The console keeps its own copy, ``_is_one_host`` in ``messagefoundry_webconsole/_external.py``,
    for an entry that reaches it another way. ``tests/test_domain_shape.py`` compares the two on a
    ``/16`` grid."""
    address = ipaddress.IPv4Address(text)
    return address in _THIS_NETWORK or address.is_multicast or address.is_reserved


def host_address(text: str | None) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """A plain address, a socket peer or a forwarded hop's host, normalised; ``None`` when it is
    not one.

    An IPv6 zone is dropped, as :func:`_peer_ip` drops it, so a key or a recorded address never
    carries text after a ``%``. An IPv4-mapped address is read as its IPv4 address, so one host
    reads the same whichever spelling a dual-stack socket or proxy gives. Unlike :func:`_peer_ip`,
    which splits the text at ``%`` first, an IPv4 text carrying a ``%`` is refused: it has no zone."""
    if text is None:
        return None
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address):
        if address.scope_id is not None:
            address = ipaddress.IPv6Address(int(address))
        if address.ipv4_mapped is not None:
            return address.ipv4_mapped
    return address


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


#: What :func:`allowlist_restricts` accepts as an entry.
_ALLOWLIST_ENTRY_TYPES: Final = (
    str,
    ipaddress.IPv4Network,
    ipaddress.IPv6Network,
    ipaddress.IPv4Address,
    ipaddress.IPv6Address,
)

#: IPv6 ranges that carry an IPv4 address, each with the bit at which :func:`allowlist_restricts`
#: takes the IPv4 address to start. Where the position varies (RFC 8215 local-use NAT64) or is
#: obfuscated (Teredo's client address), the latest position, bit 96, is used: it demands the most
#: fixed bits, so the guess can only fail closed.
_IPV4_EMBEDDING_RANGES: Final = (
    (ipaddress.IPv6Network("::ffff:0:0/96"), 96),  # IPv4-mapped, how a dual-stack socket reports
    (ipaddress.IPv6Network("::/96"), 96),  # IPv4-compatible, deprecated but parseable
    (ipaddress.IPv6Network("64:ff9b::/96"), 96),  # NAT64 well-known prefix, RFC 6052
    (ipaddress.IPv6Network("64:ff9b:1::/48"), 96),  # NAT64 local-use prefix, RFC 8215
    (ipaddress.IPv6Network("::ffff:0:0:0/96"), 96),  # IPv4-translated (SIIT), RFC 6145
    (ipaddress.IPv6Network("2001::/32"), 96),  # Teredo, RFC 4380
)
# 6to4 (2002::/16, IPv4 from bit 16) is left out: an entry the IPv6 floor admits fixes at least
# 16 of its IPv4 bits. A network-specific NAT64 prefix is the operator's own and cannot be listed.


def allowlist_restricts(allowlist: Any) -> bool:
    """Whether a ``source_ip_allowlist`` actually limits who may connect, so a gate may count it as
    a peer control.

    **Strength-based, not presence-based.** ``["0.0.0.0/0"]`` parses fine and restricts nobody. So
    every entry must be at least a :data:`ALLOWLIST_MIN_PREFIX_V4` (IPv4) or
    :data:`ALLOWLIST_MIN_PREFIX_V6` (IPv6) network, and ONE too-wide entry defeats the whole list.
    An empty or missing list restricts nobody, and so does an unparseable entry, which cannot be
    shown to restrict anyone.

    **Fail closed on shape** (vault BACKLOG #5393). Only a list, tuple or set counts, so a mapping
    is not read as its keys. Only a string or an :mod:`ipaddress` object counts as an entry, since
    ``ip_network`` reads the integer ``5`` and ``True`` as host addresses. The gates hand this a
    list of strings today, so these refusals guard a direct caller.

    **An IPv6 entry is also judged by the IPv4 space it embeds.** ``::ffff:0:0/96`` is a /96, far past
    the IPv6 floor, yet a dual-stack listener sees every IPv4 peer inside it. So an entry that
    overlaps a range in :data:`_IPV4_EMBEDDING_RANGES` must leave at least
    :data:`ALLOWLIST_MIN_PREFIX_V4` bits of the embedded IPv4 address fixed, counted from the bit
    that table names, and one that contains a whole range does not count at all."""
    if not isinstance(allowlist, (list, tuple, set, frozenset)) or not allowlist:
        return False
    for entry in allowlist:
        if not isinstance(entry, _ALLOWLIST_ENTRY_TYPES):
            return False
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            return False
        if isinstance(net, ipaddress.IPv4Network):
            if net.prefixlen < ALLOWLIST_MIN_PREFIX_V4:
                return False
            continue
        if net.prefixlen < ALLOWLIST_MIN_PREFIX_V6:
            return False
        for embedding, ipv4_start in _IPV4_EMBEDDING_RANGES:
            if not net.overlaps(embedding):
                continue
            if net.prefixlen < embedding.prefixlen:
                return False  # it holds the whole range, so every embedded IPv4 address
            if net.prefixlen - ipv4_start < ALLOWLIST_MIN_PREFIX_V4:
                return False
    return True
