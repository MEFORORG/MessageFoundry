# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Whether a ``source_ip_allowlist`` counts as a peer control (vault BACKLOG #5393).

``allowlist_restricts`` decides it for both the HTTP intake gate and the DICOM server's gate, so a
list it wrongly counts would let either treat an open listener as peer-controlled.
"""

from __future__ import annotations

import ipaddress
from typing import Any

import pytest

from messagefoundry.netaddr import allowlist_restricts, peer_ip_allowed


@pytest.mark.parametrize(
    "allowlist",
    [
        ["10.0.0.0/8"],
        ["192.0.2.0/24", "198.51.100.7"],
        ("10.1.0.0/16",),
        frozenset({"10.1.0.0/16"}),
        ["2001:db8::/32"],
        ["2001:db8:1::/48"],
        ["::ffff:10.0.0.0/104"],  # an IPv4-mapped /8, the IPv4 floor
        ["::ffff:192.0.2.0/120"],
        ["64:ff9b::192.0.2.0/120"],
        ["2002:c000:0200::/40"],  # 6to4 over 192.0.2.0/24
        ["::1"],
        [ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_address("192.0.2.1")],
    ],
)
def test_a_narrow_list_restricts(allowlist: Any) -> None:
    assert allowlist_restricts(allowlist) is True


@pytest.mark.parametrize(
    "allowlist",
    [
        None,
        [],
        ["0.0.0.0/0"],
        ["10.0.0.0/7"],
        ["::/0"],
        ["10.0.0.0/8", "0.0.0.0/0"],  # one wide entry defeats the list
        ["not-an-address"],
        # An IPv6 prefix past the IPv6 floor that still spans the IPv4 internet.
        ["::ffff:0:0/96"],
        ["::ffff:0.0.0.0/100"],
        ["::/96"],
        ["::/32"],  # holds all of ::ffff:0:0/96
        ["0:0:0:0:0:ffff::/80"],
        ["64:ff9b::/96"],
        ["64:ff9b:1::/48"],
        ["2001::/32"],  # every Teredo client
        # Not a list of network strings.
        "10.0.0.0/8",  # iterates as characters, and "1" parses as 0.0.0.1/32
        "1",
        b"10.0.0.0/8",
        {"10.0.0.0/8": True},
        [5],  # str(5) parses as 0.0.0.5/32
        [True],
        [None],
    ],
)
def test_an_open_or_malformed_list_does_not_restrict(allowlist: Any) -> None:
    assert allowlist_restricts(allowlist) is False


def test_the_mapped_prefix_admits_an_internet_ipv4_peer() -> None:
    # Why ::ffff:0:0/96 must not count: a dual-stack listener reports an IPv4 peer in it.
    assert peer_ip_allowed(("::ffff:203.0.113.9", 0), ["::ffff:0:0/96"]) is True
