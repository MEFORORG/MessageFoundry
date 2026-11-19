# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Whether a ``source_ip_allowlist`` counts as a peer control (vault BACKLOG #5393).

``allowlist_restricts`` decides it for both the HTTP intake gate and the DICOM server's gate, so a
list it wrongly counts would let either treat an open listener as peer-controlled.
"""

from __future__ import annotations

import ipaddress
import os
import subprocess
import sys
from typing import Any

import pytest

from messagefoundry import netaddr
from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.config.tls_policy import HopPosture
from messagefoundry.config.wiring import WiringError
from messagefoundry.netaddr import (
    ALLOWLIST_MAX_IPV4_ADDRESSES,
    ALLOWLIST_RULE_TEXT,
    IPV4_EMBEDDING_PREFIXES,
    IPV4_EMBEDDINGS,
    IPV4_MAPPED,
    IPV4_TRANSLATED,
    SIX_TO_FOUR,
    allowlist_restricts,
    allowlist_shortfall,
    peer_ip_allowed,
)
from messagefoundry.pipeline.wiring_runner import check_http_intake_auth
from messagefoundry.transports.dicom import DicomScpSource


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
        ["64:ff9b::/32"],  # meets the /32 floor, and holds 64:ff9b::/96 and 64:ff9b:1::/48
        ["0:0:0:0:0:ffff::/80"],
        ["64:ff9b::/96"],
        ["64:ff9b:1::/48"],
        ["2001::/32"],  # every Teredo client
        ["::ffff:0:0:0/96"],  # IPv4-translated, every client behind a SIIT translator
        # Not a list of network strings.
        "10.0.0.0/8",
        "1",
        b"10.0.0.0/8",
        {"10.0.0.0/8": True},  # a mapping would read as its keys
        [5],  # ip_network(5) is 0.0.0.5/32
        [True],  # ip_network(True) is 0.0.0.1/32
        [None],
    ],
)
def test_an_open_or_malformed_list_does_not_restrict(allowlist: Any) -> None:
    assert allowlist_restricts(allowlist) is False


def test_the_mapped_prefix_admits_an_internet_ipv4_peer() -> None:
    # Why ::ffff:0:0/96 must not count: a dual-stack listener reports an IPv4 peer in it.
    assert peer_ip_allowed(("::ffff:203.0.113.9", 0), ["::ffff:0:0/96"]) is True


# An entry that HOLDS an IPv4-carrying prefix is refused at any width, so each gate's refusal must
# name that case, not only an entry inside one.
_HOLDS_NAT64 = ["64:ff9b::/32"]


def test_the_http_gate_names_an_entry_that_holds_an_ipv4_carrying_prefix() -> None:
    source = Source(
        type=ConnectorType.HTTP,
        settings={"host": "0.0.0.0", "port": 8080, "source_ip_allowlist": _HOLDS_NAT64},
    )
    with pytest.raises(WiringError) as exc:
        check_http_intake_auth(source, "IB_HTTP", posture=HopPosture(enforcing=True))
    msg = str(exc.value)
    assert "does not count: an IPv6 entry holds a prefix that carries IPv4 addresses" in msg
    assert "no IPv6 entry holds a prefix the gate reads as carrying IPv4" in msg
    assert "64:ff9b::/32 does" in msg
    assert "is at least a /104 inside" in msg


def test_the_dicom_gate_names_an_entry_that_holds_an_ipv4_carrying_prefix() -> None:
    settings: dict[str, object] = {
        "ae_title": "MEFOR_SCP",
        "host": "0.0.0.0",
        "port": 0,
        "source_ip_allowlist": _HOLDS_NAT64,
    }
    with pytest.raises(ValueError) as exc:
        DicomScpSource(Source(type=ConnectorType.DIMSE, settings=settings))
    msg = str(exc.value)
    assert "peer control: an IPv6 entry holds a prefix that carries IPv4 addresses" in msg
    assert "no IPv6 entry holds a prefix the gate reads as carrying IPv4" in msg
    assert "64:ff9b::/32 does" in msg
    assert "is at least a /104 inside" in msg


# --- the list judged whole, and one rule text (vault BACKLOG #5393 added items 1 and 2) ----------


def _slash8s(*octets: int, prefix: str = "") -> list[str]:
    """Whole /8 networks, generated rather than written out, as ``prefix`` + ``N.0.0.0`` + its
    length: /8, or /104 under an IPv6 ``prefix``."""
    length = 104 if prefix else 8
    return [f"{prefix}{octet}.0.0.0/{length}" for octet in octets]


@pytest.mark.parametrize(
    "allowlist",
    [
        # The RFC 1918 private ranges together, a list the cap is set to leave counting.
        ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
        _slash8s(10, 11),  # exactly the cap
        # An IPv4 entry and its IPv4-mapped spelling are one range, counted once.
        [*_slash8s(10, 11), "::ffff:10.0.0.0/104"],
        [*_slash8s(10, 11), "10.1.0.0/16"],  # an overlap is counted once
        # Space no remote peer's packet can carry as its source is not counted: loopback, multicast.
        ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"],
        [*_slash8s(10, 11), *_slash8s(*range(224, 240))],
        ["10.0.0.0/8", "2001:db8::/32", "2001:db9::/32"],  # plain IPv6 carries no IPv4
    ],
)
def test_a_list_within_the_ipv4_cap_restricts(allowlist: list[str]) -> None:
    assert allowlist_restricts(allowlist) is True


@pytest.mark.parametrize(
    "allowlist",
    [
        _slash8s(*range(256)),  # every /8: the IPv4 internet
        _slash8s(*range(0, 256, 2)),  # half of it, with no two entries adjacent
        _slash8s(10, 11, 12),
        _slash8s(*range(256), prefix="::ffff:"),  # the internet, IPv4-mapped
        [*_slash8s(10, 12), *_slash8s(11, prefix="::ffff:")],
        _slash8s(10, 11, 12, prefix="64:ff9b::"),  # through NAT64
        # The same hosts through NAT64 are counted apart from their plain IPv4 spelling.
        [*_slash8s(10, 11), *_slash8s(10, prefix="64:ff9b::")],
        [f"2002:{index:x}::/32" for index in range(513)],  # 513 IPv4 /16s through 6to4
        # "This network" and class E are counted: at least Linux can use them as unicast.
        _slash8s(10, 11, 0),
        [*_slash8s(10, 11), *_slash8s(*range(240, 256))],
    ],
)
def test_entries_that_together_pass_the_ipv4_cap_do_not_restrict(allowlist: list[str]) -> None:
    assert allowlist_restricts(allowlist) is False
    assert "IPv4 addresses a remote peer can hold, more than" in (
        allowlist_shortfall(allowlist) or ""
    )


def test_a_sets_reason_does_not_follow_its_hash_order() -> None:
    # Each failing entry gives a different reason, so reading a set in hash order would make the
    # refusal text change between processes.
    code = (
        "from messagefoundry.netaddr import allowlist_shortfall;"
        "print(allowlist_shortfall({'10.0.0.0/7', '::/0', 'x', '0.0.0.0/0', '::ffff:0:0/96'}))"
    )
    reasons = {
        subprocess.run(
            [sys.executable, "-c", code],
            env={**os.environ, "PYTHONHASHSEED": str(seed)},
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        for seed in range(6)
    }
    assert len(reasons) == 1, reasons


def test_the_http_gate_names_no_allowlist_shortfall_when_a_mode_is_set() -> None:
    # Under a named intake_auth mode the gate does not weigh the list, so its shortfall is not the
    # reason for the refusal.
    source = Source(
        type=ConnectorType.HTTP,
        settings={
            "host": "0.0.0.0",
            "port": 8080,
            "intake_auth": "api_key",
            "source_ip_allowlist": ["0.0.0.0/0"],
        },
    )
    with pytest.raises(WiringError) as exc:
        check_http_intake_auth(source, "IB_HTTP", posture=HopPosture(enforcing=True))
    assert "does not count:" not in str(exc.value)


def test_the_cap_is_twice_the_ipv4_floor() -> None:
    assert 2 * ipaddress.ip_network("10.0.0.0/8").num_addresses == ALLOWLIST_MAX_IPV4_ADDRESSES


def test_one_embedding_table_serves_the_allowlist_and_the_proxy_span() -> None:
    ranges = [network for network, _start in IPV4_EMBEDDINGS]
    # The two tables once disagreed (SIIT in one, 6to4 in the other); both now read this one.
    assert {SIX_TO_FOUR, IPV4_TRANSLATED} <= set(ranges)
    # The span count leaves out the mapped block, read as IPv4 first, and SIIT, which the budget
    # keys on its /64; every other range is the table's.
    assert set(IPV4_EMBEDDING_PREFIXES) == set(ranges) - {IPV4_MAPPED, IPV4_TRANSLATED}
    # Disjoint, which the whole-list count relies on to place an entry in one range.
    assert not any(a.overlaps(b) for i, a in enumerate(ranges) for b in ranges[i + 1 :])


def test_the_ranges_the_rule_text_names_start_their_ipv4_at_bit_96() -> None:
    starts = {str(network): start for network, start in IPV4_EMBEDDINGS}
    for spelled in netaddr._RULE_TEXT_LATE_RANGES:
        network = ipaddress.ip_network(spelled)
        assert any(network == other for other, _start in IPV4_EMBEDDINGS), spelled
        assert starts[str(network)] == 96, spelled
        assert spelled in ALLOWLIST_RULE_TEXT


def test_a_6to4_entry_at_the_ipv6_floor_restricts() -> None:
    # 6to4's IPv4 address starts at bit 16, so the /104 the rule text names for the others does
    # not bind it: a /32 there fixes 16 IPv4 bits.
    assert allowlist_restricts(["2002:a00::/32"]) is True


def test_both_gates_quote_the_one_rule_text_and_name_the_cap() -> None:
    rule = ALLOWLIST_RULE_TEXT
    assert "/104" in rule and "64:ff9b::/32" in rule
    assert f"{ALLOWLIST_MAX_IPV4_ADDRESSES:,} IPv4 addresses" in rule
    wide = _slash8s(*range(0, 256, 2))
    http = Source(
        type=ConnectorType.HTTP,
        settings={"host": "0.0.0.0", "port": 8080, "source_ip_allowlist": wide},
    )
    with pytest.raises(WiringError) as http_exc:
        check_http_intake_auth(http, "IB_HTTP", posture=HopPosture(enforcing=True))
    dicom = Source(
        type=ConnectorType.DIMSE,
        settings={
            "ae_title": "MEFOR_SCP",
            "host": "0.0.0.0",
            "port": 0,
            "source_ip_allowlist": wide,
        },
    )
    with pytest.raises(ValueError) as dicom_exc:
        DicomScpSource(dicom)
    shortfall = allowlist_shortfall(wide)
    assert shortfall is not None and "more than" in shortfall
    for msg in (str(http_exc.value), str(dicom_exc.value)):
        assert rule in msg
        assert shortfall in msg  # which rule failed, not only the whole rule
