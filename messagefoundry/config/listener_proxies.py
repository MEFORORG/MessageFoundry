# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The reader of an inbound ``Http(trusted_proxies=...)`` list (BACKLOG #5525).

The ``Http`` factory, ``listener_trusted_proxy_hops`` and the HTTP listener all read the list
through :func:`read_trusted_proxies`, so the load, the posture entry and the running listener
cannot disagree on an entry. It lives in ``config/`` so the factory reads it without importing a
transport, and the listener imports it as a public contract rather than reaching into
``config.settings`` for private names. Each entry is still read by ``config.settings``'s one reader
of ``[api].trusted_proxies``, so the two lists refuse the same forms.
"""

from __future__ import annotations

import bisect
import functools
import ipaddress
from typing import Any

from messagefoundry.config.settings import (
    TrustedProxyRefusal,
    _classify_proxy_entries,
    _parse_trusted_proxy,
)
from messagefoundry.netaddr import IPV4_EMBEDDING_PREFIXES, IPV4_MAPPED, SIX_TO_FOUR, ipv4_meaning

__all__ = [
    "IPV6_KEY_PREFIX",
    "ProxyNetwork",
    "TrustedProxies",
    "read_trusted_proxies",
    "trusted_proxy_networks",
]

ProxyNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
_HopAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

#: The prefix an IPv6 budget key keeps. A host is usually handed a whole ``/64`` and may pick any
#: address in it, so keying on the full address would let it mint a fresh budget per address.
IPV6_KEY_PREFIX = 64

#: The most budget keys the listed ranges of one family may hold together: addresses for IPv4, and
#: ``/64`` networks for IPv6, the unit an IPv6 key is. ``2**16`` is one ``/16`` of IPv4 or one
#: ``/48`` of IPv6. Every host inside a listed range is trusted as a proxy and may write any
#: ``X-Forwarded-For`` it likes, so this bounds the address space trusted that way, counted in
#: the unit a key is; an IPv6 ``/64`` may still hold many hosts. It is a size, not a
#: whole-family test, so a near-whole range such as ``2000::/3``, or ``/1`` to ``/3`` pieces
#: that leave one gap, is refused as the refused ``'*'`` is (BACKLOG #5525).
_PROXY_SPAN_LIMIT = 1 << 16

#: How many validated lists :func:`read_trusted_proxies` keeps. A list the span limit admits may
#: hold 65,536 entries, so the bound is half the 64 it was: posture and audit read every
#: listener's list in turn, so a config with more distinct lists than this re-parses them on each
#: read, and lists a reload replaced stay pinned until evicted, at most this many.
_CACHED_LISTS = 32


class TrustedProxies:
    """A validated ``trusted_proxies`` list: its networks as listed, and whether an address falls
    inside one, by bisecting the collapsed ranges of its family. The span limit allows 65,536
    single-host entries, and the listener's walk asks once per hop on the event loop, so a linear
    scan of the list would cost a padded header millions of checks."""

    __slots__ = ("_ends", "_starts", "networks")

    def __init__(
        self,
        networks: tuple[ProxyNetwork, ...],
        collapsed: dict[int, list[ProxyNetwork]] | None = None,
    ) -> None:
        self.networks = networks
        if collapsed is None:
            collapsed = _collapsed(networks)
        # collapse_addresses sorts and merges, so the ranges are disjoint and ascending.
        self._starts = {v: [int(n.network_address) for n in c] for v, c in collapsed.items()}
        self._ends = {v: [int(n.broadcast_address) for n in c] for v, c in collapsed.items()}

    def __bool__(self) -> bool:
        return bool(self.networks)

    def __contains__(self, address: _HopAddress) -> bool:
        # Matched within the address's own family, so no spelling crosses over.
        starts = self._starts[address.version]
        value = int(address)
        index = bisect.bisect_right(starts, value) - 1
        return index >= 0 and value <= self._ends[address.version][index]


def _collapsed(networks: tuple[ProxyNetwork, ...]) -> dict[int, list[ProxyNetwork]]:
    # A mapped range is matched as the IPv4 range it names, the form every hop and peer is read
    # in, so a caller that builds TrustedProxies from raw networks still matches it.
    meant = [ipv4_meaning(n) for n in networks]
    v4 = [n for n in meant if isinstance(n, ipaddress.IPv4Network)]
    v6 = [n for n in meant if isinstance(n, ipaddress.IPv6Network)]
    return {
        4: list(ipaddress.collapse_addresses(v4)),
        6: list(ipaddress.collapse_addresses(v6)),
    }


_NONE = TrustedProxies(())


def trusted_proxy_networks(value: Any) -> tuple[ProxyNetwork, ...]:
    """The networks of :func:`read_trusted_proxies`, for a caller that only reads the list."""
    return read_trusted_proxies(value).networks


def read_trusted_proxies(value: Any) -> TrustedProxies:
    """Read ``Http(trusted_proxies=...)`` into the networks the forwarded-address walk matches
    (BACKLOG #5525). Raises ``ValueError``; the ``Http`` factory and the listener both call it.

    Each entry is read by ``_parse_trusted_proxy``, the one reader of ``[api].trusted_proxies``,
    so this list refuses the same forms: ``'*'``, an entry uvicorn would read as a literal that
    never matches, and an IPv6 entry with a zone. It does NOT read ``[api].trusted_proxies`` itself:
    trusting the admin API's proxy says nothing about who fronts a partner intake socket. Entries
    that together trust a whole address family, as ``_classify_proxy_entries`` counts them (two
    ``/1`` halves included), are refused here too, since that is ``'*'`` written as networks; the
    ``[api]`` load only warns about those. So are entries that together span more than
    :data:`_PROXY_SPAN_LIMIT` budget keys of one family, more than a ``/16`` of IPv4 or a ``/48``
    of IPv6. An IPv4-mapped entry is read as the IPv4 range it names, the form the listener's hop
    reader hands the walk, so one proxy matches in either spelling."""
    if value is None:
        return _NONE
    if isinstance(value, str):
        # Its own message: a MEFOR_VALUE_* variable is always text, so "must be a list" alone
        # would send an operator looking for a list syntax the variable cannot hold.
        raise ValueError(
            "Http trusted_proxies must be a list of proxy addresses or CIDR networks, and it is "
            "text (value withheld). An env() value from a MEFOR_VALUE_* variable is always text: "
            "write the list in environments/<env>.toml, or list the proxies in the config"
        )
    if not isinstance(value, (list, tuple)):
        raise ValueError(
            "Http trusted_proxies must be a list of proxy addresses or CIDR networks, "
            "e.g. trusted_proxies=['10.0.0.5']"
        )
    for index, entry in enumerate(value):
        if not isinstance(entry, str):
            raise ValueError(f"Http trusted_proxies item {index} must be a string (value withheld)")
    return _validated(tuple(value))


@functools.lru_cache(maxsize=_CACHED_LISTS)
def _validated(value: tuple[str, ...]) -> TrustedProxies:
    """:func:`read_trusted_proxies` for a list already known to hold strings. Cached, because
    ``GET /security/posture`` and each start and reload audit read every listener's list again on
    the event loop; a refusal raises, so it is never cached and every read refuses it again. Each
    entry is parsed once and each family collapsed once, for the span check and the matcher both."""
    if not value:
        return _NONE
    networks: list[ProxyNetwork] = []
    for index, entry in enumerate(value):
        reason = None
        try:
            parsed = _parse_trusted_proxy(entry)
        except TrustedProxyRefusal as exc:
            reason = exc.reason
        except ValueError:
            # Any other refusal may carry ipaddress's text, which quotes the entry: never pass it on.
            reason = "is not a valid IP address or CIDR network"
        if reason is not None:
            # Raised outside the parse's handler and never quoted: the parse's message echoes the
            # entry, and no factory refusal may quote a configured value (vault BACKLOG #3249,
            # #3765). Its advice is also the API's, about uvicorn, which this listener is not.
            raise ValueError(
                f"Http trusted_proxies item {index} {reason}; it is refused "
                "by the rule [api].trusted_proxies follows (value withheld)"
            )
        networks.append(ipv4_meaning(ipaddress.ip_network(parsed)))
    collapsed = _collapsed(tuple(networks))
    # A key is an IPv4 address or an IPv6 /64, so an IPv6 range counts its /64s, a host as one,
    # except where it overlaps a prefix whose addresses each key on themselves.
    spans = (
        (4, "/16", sum(n.num_addresses for n in collapsed[4])),
        (
            6,
            "/48",
            sum(_v6_key_count(n) for n in collapsed[6] if isinstance(n, ipaddress.IPv6Network)),
        ),
    )
    for version, floor, keys in spans:
        if keys > _PROXY_SPAN_LIMIT:
            # Every whole-family list spans more than the limit (see _v6_key_count), so the
            # classifier, which parses the list again, runs on this refusal path only, to say
            # which refusal it is.
            whole_family, _ = _classify_proxy_entries(value)
            if whole_family:
                raise ValueError(
                    "Http trusted_proxies entries together trust a whole address family, as the "
                    "refused '*' does, so every client would count as a proxy and could choose "
                    "its own failed-attempt budget key. List the reverse proxy's exact address(es) "
                    "instead (values withheld)."
                )
            raise ValueError(
                f"Http trusted_proxies entries together span more than a {floor} of IPv{version}. "
                "Every host inside a listed range may write its own X-Forwarded-For and so choose "
                "its own failed-attempt budget key. List the reverse proxy's exact address(es), or "
                f"ranges that together stay within a {floor} (values withheld)."
            )
    return TrustedProxies(tuple(networks), collapsed)


def _v6_key_count(network: ipaddress.IPv6Network) -> int:
    """How many budget keys an IPv6 range holds: its ``/64`` networks, or, where it overlaps an
    IPv4-embedding prefix, where a key is an address or an embedded IPv4 client, its addresses,
    which bound the keys there. Inside 6to4 a key is one ``/48``, its IPv4 holder's site.

    A range holding the IPv4-mapped block counts its addresses too: each mapped address keys as
    the IPv4 address it names, so ``::fffe:0:0/95`` holds every IPv4 key. That is also what makes
    every list ``_classify_proxy_entries`` calls whole-family exceed the span limit, which
    :func:`_validated` relies on to run the classifier on the refusal path only. A range inside
    the mapped block never reaches here: it is read as the IPv4 range it names."""
    if network.subnet_of(SIX_TO_FOUR):
        return max(1, network.num_addresses >> 80)
    if network.overlaps(IPV4_MAPPED) or any(
        network.overlaps(prefix) for prefix in IPV4_EMBEDDING_PREFIXES
    ):
        return network.num_addresses
    return max(1, network.num_addresses >> (128 - IPV6_KEY_PREFIX))
