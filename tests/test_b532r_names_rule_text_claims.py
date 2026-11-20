# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Pins the claims the allow-list rule text and the netaddr comments make about the code (vault
BACKLOG #5393), so a change to the code that falsifies one fails here rather than leaving the
prose wrong."""

from __future__ import annotations

import ipaddress
from pathlib import Path

from messagefoundry import netaddr
from messagefoundry.netaddr import (
    ALLOWLIST_MAX_IPV4_ADDRESSES,
    ALLOWLIST_MIN_PREFIX_V4,
    ALLOWLIST_MIN_PREFIX_V6,
    ALLOWLIST_RULE_TEXT,
    IPV4_EMBEDDINGS,
    IPV4_TRANSLATED,
    SIX_TO_FOUR,
    allowlist_restricts,
    allowlist_shortfall,
)
from messagefoundry.transports.http_listener import _budget_key, _embedded_client, _is_phantom

_DEPLOYMENT = Path(__file__).resolve().parents[1] / "docs" / "DEPLOYMENT.md"


def test_the_rule_text_names_6to4_and_its_ipv4_start() -> None:
    start = dict(IPV4_EMBEDDINGS)[SIX_TO_FOUR]
    assert f"6to4's {SIX_TO_FOUR}, whose IPv4 address starts at bit {start}" in ALLOWLIST_RULE_TEXT
    # "the IPv6 floor already fixes that many" holds only while this does.
    assert ALLOWLIST_MIN_PREFIX_V6 - start >= ALLOWLIST_MIN_PREFIX_V4


def test_6to4_entries_count_toward_the_cap_as_the_rule_text_says() -> None:
    assert "6to4 included, counting the IPv4 addresses it" in ALLOWLIST_RULE_TEXT
    # 2002:XXYY::/32 carries the IPv4 /16 XX.YY.0.0, so 2 * 2**24 / 2**16 = 512 such entries reach
    # the cap and one more passes it. A 6to4 entry counting none would let any number through.
    per_entry = 2 ** (32 - (ALLOWLIST_MIN_PREFIX_V6 - dict(IPV4_EMBEDDINGS)[SIX_TO_FOUR]))
    at_cap = ALLOWLIST_MAX_IPV4_ADDRESSES // per_entry
    entries = [
        str(ipaddress.IPv6Network(((0x2002 << 112) | (i << 96), 32))) for i in range(at_cap + 1)
    ]
    assert allowlist_restricts(entries[:at_cap]) is True
    shortfall = allowlist_shortfall(entries)
    assert shortfall is not None and "more than" in shortfall


def test_the_same_hosts_under_nat64_and_plain_count_twice_as_the_rule_text_says() -> None:
    assert "apart for each such prefix" in ALLOWLIST_RULE_TEXT
    assert "IPv4-mapped entries counted as one space" in ALLOWLIST_RULE_TEXT
    # 10/8 as plain and as IPv4-mapped is one space: it counts once.
    assert allowlist_restricts(["10.0.0.0/8", "::ffff:10.0.0.0/104", "192.168.0.0/16"]) is True
    # The same 10/8 under NAT64 counts apart, so with 192.168/16 it passes the cap.
    shortfall = allowlist_shortfall(["10.0.0.0/8", "64:ff9b::a00:0/104", "192.168.0.0/16"])
    assert shortfall is not None and "more than" in shortfall


def test_loopback_in_the_plain_space_is_left_out_of_the_count_not_the_list() -> None:
    # The docstring says the count, not the admitted addresses, is what the cap bounds.
    # 10/8 and 192.168/16 count 16,842,752; were 127/8 counted too, the sum would pass the cap.
    private = ["10.0.0.0/8", "192.168.0.0/16"]
    assert allowlist_restricts(private) is True
    assert allowlist_restricts([*private, "127.0.0.0/8"]) is True


def test_siit_is_read_as_the_ipv4_embedding_prefixes_comment_says() -> None:
    assert IPV4_TRANSLATED not in netaddr.IPV4_EMBEDDING_PREFIXES
    for text in ("::ffff:0:c000:221", "::ffff:0:a00:1"):
        address = ipaddress.IPv6Address(text)
        assert _embedded_client(address) is None
        assert _budget_key(address) == str(ipaddress.IPv6Network((address, 64), strict=False))
        assert _is_phantom(address) is True


def test_the_dicom_listener_row_points_at_the_rule_text() -> None:
    row = next(
        line
        for line in _DEPLOYMENT.read_text(encoding="utf-8").splitlines()
        if line.startswith("| **DICOM C-STORE SCP**")
    )
    assert "`ALLOWLIST_RULE_TEXT` in [netaddr.py](../messagefoundry/netaddr.py)" in row
    assert "cap" in row
    assert "floors in the caveat above" not in row
