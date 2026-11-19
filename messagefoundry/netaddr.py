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
    "ALLOWLIST_MAX_IPV4_ADDRESSES",
    "ALLOWLIST_MIN_PREFIX_V4",
    "ALLOWLIST_MIN_PREFIX_V6",
    "ALLOWLIST_RULE_TEXT",
    "IPV4_COMPATIBLE",
    "IPV4_EMBEDDINGS",
    "IPV4_EMBEDDING_PREFIXES",
    "IPV4_MAPPED",
    "IPV4_MAPPED_BASE",
    "IPV4_TRANSLATED",
    "NAT64_LOCAL_USE",
    "NAT64_WELL_KNOWN",
    "SIX_TO_FOUR",
    "TEREDO",
    "allowlist_restricts",
    "allowlist_shortfall",
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

#: The most IPv4 addresses the whole-list count of a ``source_ip_allowlist`` may reach and the list
#: still count (vault BACKLOG #5393): twice what one entry at the IPv4 floor admits. The count is
#: not every address the list admits: it leaves out at least the plain-space loopback and
#: multicast blocks (:data:`_NOT_A_PEER_V4`) and plain IPv6 entries, as :func:`allowlist_shortfall`
#: says. Without it, entries that each meet the
#: floor, such as the 256 ``/8`` networks, together admit the IPv4 internet. Twice a ``/8`` leaves
#: room for ``10.0.0.0/8`` beside the other RFC 1918 private ranges (``172.16.0.0/12``,
#: ``192.168.0.0/16``) and RFC 6598's shared address space, a ``/10``. An IPv4-embedded IPv6 entry
#: counts the IPv4 addresses it can carry, as :func:`allowlist_shortfall` says.
ALLOWLIST_MAX_IPV4_ADDRESSES: Final = 2 * 2 ** (32 - ALLOWLIST_MIN_PREFIX_V4)

#: The IPv4-mapped block. An entry or address inside it names IPv4 hosts in their IPv6 spelling
#: (BACKLOG #3042).
IPV4_MAPPED: Final = ipaddress.IPv6Network("::ffff:0:0/96")
IPV4_MAPPED_BASE: Final = int(IPV4_MAPPED.network_address)

#: IPv6 prefixes whose addresses carry an IPv4 client: the NAT64 well-known and local-use prefixes
#: (RFC 6052, RFC 8215), Teredo (RFC 4380), 6to4 (RFC 3056), IPv4-translated or SIIT (RFC 6145)
#: and the deprecated IPv4-compatible form.
NAT64_WELL_KNOWN: Final = ipaddress.IPv6Network("64:ff9b::/96")
NAT64_LOCAL_USE: Final = ipaddress.IPv6Network("64:ff9b:1::/48")
TEREDO: Final = ipaddress.IPv6Network("2001::/32")
SIX_TO_FOUR: Final = ipaddress.IPv6Network("2002::/16")
IPV4_TRANSLATED: Final = ipaddress.IPv6Network("::ffff:0:0:0/96")
IPV4_COMPATIBLE: Final = ipaddress.IPv6Network("::/96")

#: The bit at which the IPv4 address starts in every range below but 6to4. Where the position
#: varies (RFC 8215 local-use NAT64) or is obfuscated (Teredo's client address), this latest
#: position is used: it demands the most fixed bits, so the guess can only fail closed.
_LATE_IPV4_START: Final = 96

#: THE table of IPv6 ranges that carry an IPv4 address, each with the bit at which the IPv4
#: address is taken to start (vault BACKLOG #5393: one table where there were two that disagreed
#: on SIIT and 6to4). :func:`allowlist_shortfall` reads all of it, and
#: :data:`IPV4_EMBEDDING_PREFIXES` is derived from it. A network-specific NAT64 prefix is the
#: operator's own and cannot be listed.
IPV4_EMBEDDINGS: Final[tuple[tuple[ipaddress.IPv6Network, int], ...]] = (
    (IPV4_MAPPED, _LATE_IPV4_START),  # how a dual-stack socket reports an IPv4 peer
    (IPV4_COMPATIBLE, _LATE_IPV4_START),
    (NAT64_WELL_KNOWN, _LATE_IPV4_START),
    (NAT64_LOCAL_USE, _LATE_IPV4_START),
    (IPV4_TRANSLATED, _LATE_IPV4_START),
    (TEREDO, _LATE_IPV4_START),
    (SIX_TO_FOUR, 16),  # 2002:V4ADDR::/48
)

#: The ranges of :data:`IPV4_EMBEDDINGS` whose addresses the HTTP listener's failed-attempt budget
#: does not key on their ``/64``, read by the span limit on its ``trusted_proxies``
#: (``config.listener_proxies``, BACKLOG #5525), which must count keys the way the budget makes
#: them. Two are left out. The IPv4-mapped block is read as the IPv4 range it names
#: (:func:`ipv4_meaning`) before this is asked. SIIT is left out because the budget keying does
#: not read it as carrying an IPv4 client: ``_embedded_client`` finds none in it, so
#: ``_budget_key`` keys its addresses on their ``/64``, and ``_is_phantom`` reads every SIIT
#: address as one no client can hold, since SIIT lies in the unassigned rest of ``::/8``
#: (``_IETF_RESERVED``). That keying reads ``NAT64_WELL_KNOWN``,
#: ``NAT64_LOCAL_USE``, ``IPV4_COMPATIBLE`` and ``ipaddress``'s Teredo and 6to4 readings, not this
#: table.
IPV4_EMBEDDING_PREFIXES: Final = tuple(
    network for network, _start in IPV4_EMBEDDINGS if network not in (IPV4_MAPPED, IPV4_TRANSLATED)
)

#: IPv4 space a remote peer's packet cannot carry as its source: loopback, which a host drops as a
#: martian when it arrives on another interface, and multicast, never a unicast source. The
#: whole-list count in :func:`allowlist_shortfall` leaves it out of the plain IPv4 space only, so
#: listing ``127.0.0.0/8`` beside the private ranges does not use up the cap. The same blocks
#: reached through another range of :data:`IPV4_EMBEDDINGS`, NAT64 for one, are counted. "This
#: network" (``0.0.0.0/8``) and the reserved class E block are counted: at least Linux can be set
#: to use them as unicast addresses. Not counting loopback is not a claim that a loopback entry
#: admits no remote client: an on-box relay, such as a reverse proxy, a port forward or an SSH
#: tunnel, connects from loopback for whoever it forwards, and neither gate weighs that.
_NOT_A_PEER_V4: Final = (
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("224.0.0.0/4"),
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

# 6to4 starts its IPv4 address at bit 16, so an entry inside it that meets the IPv6 floor fixes at
# least 16 IPv4 bits, more than the IPv4 floor: the per-entry rule never refuses one there. It is
# in IPV4_EMBEDDINGS for the whole-list count, where each such entry still admits IPv4 addresses.


#: Ranges of :data:`IPV4_EMBEDDINGS` whose IPv4 address starts at bit 96, named in
#: :data:`ALLOWLIST_RULE_TEXT` as written there; ``str()`` of the mapped block prints it dotted.
#: tests/test_allowlist_restricts.py pins them to the table.
_RULE_TEXT_LATE_RANGES: Final = ("::ffff:0:0/96", "64:ff9b::/96", "2001::/32")

#: The bit at which 6to4's IPv4 address starts, read from the table for the rule text.
_SIX_TO_FOUR_IPV4_START: Final = dict(IPV4_EMBEDDINGS)[SIX_TO_FOUR]

#: The rule :func:`allowlist_shortfall` applies, as one clause both gates' refusals quote, so the
#: floors, the examples and the derived ``/104`` are stated once in code (vault BACKLOG #5393).
ALLOWLIST_RULE_TEXT: Final = (
    f"every entry parses and is no wider than /{ALLOWLIST_MIN_PREFIX_V4} (IPv4) or "
    f"/{ALLOWLIST_MIN_PREFIX_V6} (IPv6); no IPv6 entry holds a prefix the gate reads as carrying "
    "IPv4 addresses, as "
    f"{NAT64_WELL_KNOWN.supernet(new_prefix=ALLOWLIST_MIN_PREFIX_V6)} does; an IPv6 entry inside "
    f"one fixes at least {ALLOWLIST_MIN_PREFIX_V4} bits of the IPv4 address it carries, so is at "
    f"least a /{_LATE_IPV4_START + ALLOWLIST_MIN_PREFIX_V4} inside a prefix whose IPv4 address "
    f"starts at bit {_LATE_IPV4_START}, at least {', '.join(_RULE_TEXT_LATE_RANGES[:-1])} and "
    f"{_RULE_TEXT_LATE_RANGES[-1]}, while inside 6to4's {SIX_TO_FOUR}, whose IPv4 address starts "
    f"at bit {_SIX_TO_FOUR_IPV4_START}, the IPv6 floor already fixes that many; and the entries "
    f"together count at most {ALLOWLIST_MAX_IPV4_ADDRESSES:,} IPv4 addresses, "
    f"two /{ALLOWLIST_MIN_PREFIX_V4} networks' worth, an IPv6 entry inside any prefix the gate "
    "reads as carrying IPv4 addresses, 6to4 included, counting the IPv4 addresses it can carry, "
    "any other IPv6 entry, a site's own NAT64 prefix among them, counting none, and loopback and "
    "multicast not counted where a plain IPv4 or IPv4-mapped entry lists them"
)


def _embedded_ipv4(net: ipaddress.IPv6Network, ipv4_start: int) -> ipaddress.IPv4Network:
    """The IPv4 range an IPv6 entry inside an :data:`IPV4_EMBEDDINGS` range can carry, read from
    bit ``ipv4_start``. An entry that fixes every IPv4 bit, or more, carries one address."""
    fixed = min(net.prefixlen - ipv4_start, 32)
    value = (int(net.network_address) >> (96 - ipv4_start)) & 0xFFFF_FFFF
    return ipaddress.IPv4Network((value, fixed), strict=False)


def _peer_addresses(blocks: list[ipaddress.IPv4Network]) -> int:
    """How many addresses in ``blocks``, already collapsed so disjoint, lie outside
    :data:`_NOT_A_PEER_V4`."""
    total = 0
    for block in blocks:
        total += block.num_addresses
        for excluded in _NOT_A_PEER_V4:
            # Aligned networks either nest or are disjoint, and the excluded ones are disjoint.
            if block.subnet_of(excluded):
                total -= block.num_addresses
            elif excluded.subnet_of(block):
                total -= excluded.num_addresses
    return total


def allowlist_restricts(allowlist: Any) -> bool:
    """Whether a ``source_ip_allowlist`` actually limits who may connect, so a gate may count it as
    a peer control: :func:`allowlist_shortfall` finds nothing wrong with it."""
    return allowlist_shortfall(allowlist) is None


def allowlist_shortfall(allowlist: Any) -> str | None:
    """Why a ``source_ip_allowlist`` does not count as a peer control, or ``None`` when it does. The
    reason names the rule that failed and quotes no entry, so a refusal can carry it.

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
    overlaps a range in :data:`IPV4_EMBEDDINGS` must leave at least
    :data:`ALLOWLIST_MIN_PREFIX_V4` bits of the embedded IPv4 address fixed, counted from the bit
    that table names, and one that contains a whole range does not count at all.

    **The list is also judged whole** (vault BACKLOG #5393). Entries that each meet a floor can
    together admit the IPv4 internet, so the list's IPv4 address count, as
    :data:`ALLOWLIST_RULE_TEXT` defines it, may be at most :data:`ALLOWLIST_MAX_IPV4_ADDRESSES`.
    That count is not every IPv4 address the list admits, as the rest of this paragraph says. Plain IPv4 entries and IPv4-mapped ones are one space,
    where an overlap is counted once. Each other range in :data:`IPV4_EMBEDDINGS` is counted
    apart, since its addresses cannot be matched to plain IPv4 ones with certainty, so the same
    hosts listed under two ranges count twice, which can only fail closed. In the plain IPv4
    space, address space no remote peer's packet can carry as its source (:data:`_NOT_A_PEER_V4`)
    is not counted. Plain
    IPv6 entries outside those ranges are judged by the per-entry floor alone."""
    if not isinstance(allowlist, (list, tuple, set, frozenset)) or not allowlist:
        return "it is not a non-empty list of addresses and networks"
    # The IPv4 ranges the list admits, keyed by the embedding range they arrive under, or by None
    # for plain IPv4 and IPv4-mapped entries.
    admitted: dict[ipaddress.IPv6Network | None, list[ipaddress.IPv4Network]] = {}
    # A set's order follows string hashing, which changes per process, so the first failing entry,
    # and with it the reason, would too: read a set in a fixed order.
    entries = sorted(allowlist, key=repr) if isinstance(allowlist, (set, frozenset)) else allowlist
    for entry in entries:
        if not isinstance(entry, _ALLOWLIST_ENTRY_TYPES):
            return "an entry is not an address or network"
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            return "an entry does not parse"
        if isinstance(net, ipaddress.IPv4Network):
            if net.prefixlen < ALLOWLIST_MIN_PREFIX_V4:
                return f"an IPv4 entry is wider than /{ALLOWLIST_MIN_PREFIX_V4}"
            admitted.setdefault(None, []).append(net)
            continue
        if net.prefixlen < ALLOWLIST_MIN_PREFIX_V6:
            return f"an IPv6 entry is wider than /{ALLOWLIST_MIN_PREFIX_V6}"
        for embedding, ipv4_start in IPV4_EMBEDDINGS:
            if not net.overlaps(embedding):
                continue
            if net.prefixlen < embedding.prefixlen:
                # It holds the whole range, so every embedded IPv4 address.
                return "an IPv6 entry holds a prefix that carries IPv4 addresses"
            if net.prefixlen - ipv4_start < ALLOWLIST_MIN_PREFIX_V4:
                return (
                    "an IPv6 entry inside a prefix that carries IPv4 addresses fixes fewer than "
                    f"{ALLOWLIST_MIN_PREFIX_V4} bits of the IPv4 address"
                )
            # Overlapping and no wider, so inside it, and the ranges are disjoint: one match.
            key = None if embedding == IPV4_MAPPED else embedding
            admitted.setdefault(key, []).append(_embedded_ipv4(net, ipv4_start))
    total = 0
    for key, ranges in admitted.items():
        blocks = list(ipaddress.collapse_addresses(ranges))
        # Only the plain space can be matched to the excluded blocks: Teredo, for one, inverts it.
        total += _peer_addresses(blocks) if key is None else sum(b.num_addresses for b in blocks)
    if total > ALLOWLIST_MAX_IPV4_ADDRESSES:
        return (
            f"the entries together count {total:,} IPv4 addresses toward the cap, more than "
            f"{ALLOWLIST_MAX_IPV4_ADDRESSES:,}"
        )
    return None
