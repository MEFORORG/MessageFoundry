# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Leak-check gaps left after BACKLOG #5532: an id type past the first subcomponent, and IPv6
addresses (BACKLOG #5654, and #5533 item 8's ``_is_mrn_type`` limb).

The MRN-typed check read the id type as written, decoded whole and as its first subcomponent, so
``X&MR`` and a padded ``MR\\X20\\`` passed; and no detector looked for an IPv6 address. The rest of
#5654's subject, escaped tokens, escaped IPv4, escaped SSNs and phones and an id type in the first
subcomponent, was fixed under #5532 and is pinned by ``tests/test_anon_b214_5532.py``.

Every value here is synthetic: made-up ids, and IPv6 addresses assembled from parts.
"""

from __future__ import annotations

from types import ModuleType

import pytest

from messagefoundry_toolkit.anon import leak as engine_leak
from messagefoundry_toolkit.anon.rules import DEFAULT_RULES
from tee.anon import leak as tee_leak
from tests.test_anon_core import _NO_SCANNER

_HEAD = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|M1|P|2.5.1\rPID|1||1^^^H^MR||X^Y"
_LEAKS = pytest.mark.parametrize("leak", [engine_leak, tee_leak], ids=["engine", "tee"])


def _zpd(value: str, head: str = _HEAD) -> str:
    return f"{head}\rZPD|1|||{value}"


# --- #5654: an MRN type in any subcomponent, padded or not -----------------------------------------


@_LEAKS
@pytest.mark.parametrize(
    "value",
    [
        "M1^^^H^X&MR",
        "M1^^^H^X&M\\X52\\",
        "M1^^^H^X&Y&MRN",
        "M1^^^H^MR\\X20\\",
        "M1^^^H^\\X20\\MRN",
        "M1^^^H^ MR ",
    ],
    ids=["second-sub", "second-sub-escaped", "third-sub", "padded-hex", "lead-pad", "spaces"],
)
def test_an_mrn_type_past_the_first_subcomponent_or_padded_is_a_hit(
    leak: ModuleType, value: str
) -> None:
    hits = leak.structural_phi_hits(_zpd(value), {"PID-3", "PID-5"})
    assert any("MRN" in hit and "ZPD-4" in hit for hit in hits), hits


@_LEAKS
@pytest.mark.parametrize("value", ["M1^^^H^X&MRX", "M1^^^H^X&M R", "^^^H^X&MR"])
def test_a_near_miss_or_an_mrn_type_with_no_id_is_no_hit(leak: ModuleType, value: str) -> None:
    assert leak.structural_phi_hits(_zpd(value), {"PID-3", "PID-5"}) == []


def test_a_message_subcomponent_read_sees_the_type() -> None:
    """The reading the detector now takes is one the engine's own parser gives."""
    from messagefoundry.parsing.message import Message

    assert Message.parse(_zpd("M1^^^H^X&MR")).field("ZPD-4.5.2") == "MR"


# --- #5654: IPv6 -----------------------------------------------------------------------------------

#: A global unicast address, assembled from parts so no literal sits in this file.
_GLOBAL = ":".join(["2a01", "4f8", "", "5"])


@_NO_SCANNER
@_LEAKS
@pytest.mark.parametrize(
    "written",
    [
        _GLOBAL,
        _GLOBAL.upper(),
        f"host {_GLOBAL}.",
        f"[{_GLOBAL}]:443",
        _GLOBAL.replace(":", "\\X3A\\"),
        "::ffff:" + ":".join(["808", "808"]),
    ],
    ids=["plain", "upper", "sentence", "bracketed", "escaped-colons", "mapped-hex"],
)
def test_a_routable_ipv6_address_is_a_hit(leak: ModuleType, written: str) -> None:
    report = leak.leak_report(_zpd(written), rules=DEFAULT_RULES)
    assert leak.IPV6_REASON in report.hits, report.hits
    assert not any(_GLOBAL in hit for hit in report.hits)
    # A bare-string call reads it too: the token scan covers the whole text.
    assert leak.IPV6_REASON in leak.leak_check(_zpd(written))


@_NO_SCANNER
@_LEAKS
@pytest.mark.parametrize(
    "written",
    [
        "::1",
        "::",
        "fe80::1",
        "fd12:3456::1",
        "ff02::1",
        "2001:db8::1",
        "::ffff:10.0.0.1",
        "::ffff:a00:1",
        "10:30:45",
        "a:b",
        "1:2:3:4:5:6:7:8:9",
    ],
    ids=[
        "loopback",
        "unspecified",
        "link-local",
        "unique-local",
        "multicast",
        "documentation",
        "mapped-private-dotted",
        "mapped-private-hex",
        "a-time",
        "one-colon",
        "too-many-groups",
    ],
)
def test_an_allowed_or_non_address_is_no_ipv6_hit(leak: ModuleType, written: str) -> None:
    report = leak.leak_report(_zpd(written), rules=DEFAULT_RULES)
    assert leak.IPV6_REASON not in report.hits, report.hits
