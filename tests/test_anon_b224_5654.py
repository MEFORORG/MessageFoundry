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

import messagefoundry_toolkit.anon as engine_anon
import tee.anon as tee_anon
from messagefoundry_toolkit.anon import leak as engine_leak
from messagefoundry_toolkit.anon.rules import DEFAULT_RULES
from tee.anon import leak as tee_leak
from tests.test_anon_core import _NO_SCANNER

_HEAD = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|M1|P|2.5.1\rPID|1||1^^^H^MR||X^Y"
_LEAKS = pytest.mark.parametrize("leak", [engine_leak, tee_leak], ids=["engine", "tee"])
_SIDES = pytest.mark.parametrize("anon", [engine_anon, tee_anon], ids=["engine", "tee"])


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
        "M1^^^H^MR\\H\\",
    ],
    ids=[
        "second-sub",
        "second-sub-escaped",
        "third-sub",
        "padded-hex",
        "lead-pad",
        "spaces",
        "highlighting-dropped",
    ],
)
def test_an_mrn_type_past_the_first_subcomponent_or_padded_is_a_hit(
    leak: ModuleType, value: str
) -> None:
    hits = leak.structural_phi_hits(_zpd(value), {"PID-3", "PID-5"})
    assert any("MRN" in hit and "ZPD-4" in hit for hit in hits), hits


@_LEAKS
@pytest.mark.parametrize(
    "value",
    ["70553^PET&MR^C4", "A1^Smith&mr", "A1^X\\T\\MR"],
    ids=["second-component-sub", "name-sub", "escaped-sub"],
)
def test_an_mr_subcomponent_outside_cx_5_is_no_hit(leak: ModuleType, value: str) -> None:
    """Outside CX.5 only a whole component counts, so an ``MR`` subcomponent there is text."""
    assert leak.structural_phi_hits(_zpd(value), {"PID-3", "PID-5"}) == []


@_LEAKS
@pytest.mark.parametrize(
    "value",
    [
        "12345^MR",
        "MRN^12345",
        "12345^^^MR",
        "1234^DOE^JOHN^^^MR",
        "A1^^^ MR",
        "A1^^^^X^MR",
        "12345^M\\X52\\",
        "12345^MR\\X00\\",
        "M1^^^H^MR\\X7F\\",
        "M1^^^H^MR\\X9C\\",
        "M1^^^H^MR\\XAD\\",
        "12345^M\\X00\\R",
        "M1^^^H^M\\X00\\R",
        "12345^MR​",
        "12345^﻿MR",
        "12345^M\x00R",
        "12345^MR&L",
        "12345^^^MR&L",
        "12345^MRN&ISO",
    ],
    ids=[
        "second",
        "first-as-type",
        "fourth",
        "xcn-sixth",
        "fourth-padded",
        "sixth",
        "second-escaped",
        "nul-padded",
        "del-padded-cx-5",
        "c1-padded-cx-5",
        "soft-hyphen-padded-cx-5",
        "nul-inside",
        "nul-inside-cx-5",
        "zero-width-padded",
        "bom-padded",
        "raw-nul-inside",
        "second-first-sub",
        "fourth-first-sub",
        "mrn-first-sub",
    ],
)
def test_a_whole_component_mr_anywhere_is_a_hit(leak: ModuleType, value: str) -> None:
    """A component that is ``MR`` or ``MRN`` whole counts in any position, as on main, trimmed of
    whitespace and control characters."""
    hits = leak.structural_phi_hits(_zpd(value), {"PID-3", "PID-5"})
    assert any("MRN" in hit and "ZPD-4" in hit for hit in hits), hits


@_NO_SCANNER
@_SIDES
def test_anonymize_checked_passes_an_unescaped_modality(anon: ModuleType) -> None:
    text = f"{_HEAD}\rOBR|1|ORD1||70553^PET&MR^C4"
    assert anon.anonymize_checked(text, salt="b224-5654-salt-0123456789abcdef")


@_LEAKS
def test_an_mr_type_in_a_cx_5_subcomponent_is_still_a_hit(leak: ModuleType) -> None:
    hits = leak.structural_phi_hits(_zpd("ID^^^AUTH^MR&local"), {"PID-3", "PID-5"})
    assert any("MRN" in hit and "ZPD-4" in hit for hit in hits), hits


@_LEAKS
@pytest.mark.parametrize("value", ["M1^^^H^X&MRX", "M1^^^H^X&M R", "^^^H^X&MR"])
def test_a_near_miss_or_an_mrn_type_with_no_id_is_no_hit(leak: ModuleType, value: str) -> None:
    assert leak.structural_phi_hits(_zpd(value), {"PID-3", "PID-5"}) == []


_ORDINARY_MR_TEXT = pytest.mark.parametrize(
    "segment",
    [
        "OBR|1|ORD1||70553^MR BRAIN W\\T\\WO CONTRAST^C4",
        "OBX|1|TX|123^MR HEAD\\T\\NECK^L",
        "OBR|1|ORD1||70553^X^C4|||||||||Prior Mr Smith study\\.br\\see notes",
        "OBR|1|ORD1||70553^PET\\T\\MR^C4",
        "OBR|1|ORD1||70553^MR\\T\\CT BRAIN^C4",
        "ZPD|1|||A1^Mr\\S\\Smith",
    ],
    ids=[
        "obr-4-procedure",
        "obx-3-observation",
        "obr-13-note",
        "obr-4-hybrid-modality",
        "obr-4-modality-first",
        "escaped-component-separator",
    ],
)


@_LEAKS
@_ORDINARY_MR_TEXT
def test_the_word_mr_in_ordinary_escaped_text_is_no_mrn(leak: ModuleType, segment: str) -> None:
    """The MRN-typed check never splits a decoded part again, on an escaped delimiter or on
    whitespace, so the word ``MR`` or ``Mr`` in a procedure name or a note is not an id type."""
    hits = leak.structural_phi_hits(f"{_HEAD}\r{segment}", {"PID-3", "PID-5"})
    assert not any("MRN" in hit for hit in hits), hits


@_NO_SCANNER
@_SIDES
@_ORDINARY_MR_TEXT
def test_anonymize_checked_passes_ordinary_mr_text(anon: ModuleType, segment: str) -> None:
    assert anon.anonymize_checked(f"{_HEAD}\r{segment}", salt="b224-5654-salt-0123456789abcdef")


def test_a_message_subcomponent_read_sees_the_type() -> None:
    """The reading the detector now takes is one the engine's own parser gives."""
    from messagefoundry.parsing.message import Message

    assert Message.parse(_zpd("M1^^^H^X&MR")).field("ZPD-4.5.2") == "MR"


# --- #5654: IPv6 -----------------------------------------------------------------------------------

#: A synthetic routable address in 4000::/3, space IANA has not allocated, so it names no real
#: network. Assembled from parts so no literal sits in this file.
_GLOBAL = ":".join(["4000", "a1", "", "5"])
#: A synthetic routable IPv4 address the guard does not allow: the first address of the reserved
#: class E block, written as the low 32 bits of an IPv6 address (``f000:1``) or dotted, from parts.
_RESERVED_V4_HEX = ":".join(["f000", "1"])
_RESERVED_V4 = ".".join(["240", "0", "0", "1"])


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
        "::ffff:" + _RESERVED_V4_HEX,
        "Addr:::ffff:" + _RESERVED_V4_HEX,
        f"x {_GLOBAL}.443",
        f"{_GLOBAL}.Bad",
        f"{_GLOBAL[:-1]}:",
        "::" + _RESERVED_V4,
        f"IP:{_GLOBAL[:-1]}",
        f"Net:{_GLOBAL[:-1]}/32",
        "ff3e:40:" + _GLOBAL.replace("::5", "::1"),
    ],
    ids=[
        "plain",
        "upper",
        "sentence",
        "bracketed",
        "escaped-colons",
        "mapped-hex",
        "label-colon",
        "addr-dot-port",
        "dot-word",
        "list-colon",
        "compatible-routable",
        "label-colon-before-trailing-double",
        "label-colon-and-prefix-length",
        "multicast-with-unicast-prefix",
    ],
)
def test_a_routable_ipv6_address_is_a_hit(leak: ModuleType, written: str) -> None:
    report = leak.leak_report(_zpd(written), rules=DEFAULT_RULES)
    assert f"unmapped {leak.IPV6_REASON} in ZPD-4" in report.structural_hits, report.hits
    assert not any(_GLOBAL in hit for hit in report.hits)


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
        "::10.0.0.1",
        "3fff::1",
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
        "compatible-private",
        "documentation-3fff",
    ],
)
def test_an_allowed_or_non_address_is_no_ipv6_hit(leak: ModuleType, written: str) -> None:
    report = leak.leak_report(_zpd(written), rules=DEFAULT_RULES)
    assert not any(leak.IPV6_REASON in hit for hit in report.hits), report.hits


@_NO_SCANNER
@_SIDES
def test_a_surrogate_is_never_refused_as_an_ipv6_address(anon: ModuleType) -> None:
    """``_fake_like`` writes a capital for each letter of an id, so a mapped PID-3 that holds
    ``::`` can come out as a hex word joined to ``::``. The IPv6 check reads only unmapped
    fields, so no salt makes the anonymizer refuse its own output."""
    raw = f"{_HEAD.split(chr(13))[0]}\rPID|1||SYS::1234^^^H^MR||X^Y"
    for n in range(300):
        anon.anonymize_checked(raw, salt=f"b224-ipv6-salt-{n:04d}-0123456789abcdef")


@_LEAKS
def test_an_ipv6_address_in_a_mapped_field_is_not_read(leak: ModuleType) -> None:
    text = f"{_HEAD.split(chr(13))[0]}\rPID|1||{_GLOBAL}^^^H^MR||X^Y"
    assert not any(leak.IPV6_REASON in hit for hit in leak.structural_phi_hits(text, {"PID-3"}))


def _msh24(value: str) -> str:
    """A message whose header holds ``value`` in MSH-24, its sending network address, after a full
    MSH-7 timestamp with an offset."""
    header = f"MSH|^~\\&|A|B|C|D|20260101120000-0500||ADT^A01|M1|P|2.5.1{'|' * 12}{value}"
    return f"{header}\rPID|1||1^^^H^MR||X^Y"


@_NO_SCANNER
@_LEAKS
@pytest.mark.parametrize(
    "written",
    [f"NET^{_GLOBAL}^DNS", _GLOBAL, _GLOBAL.replace(":", "\\X3A\\")],
    ids=["hd", "bare", "escaped-colons"],
)
def test_a_routable_ipv6_address_in_the_header_is_a_hit(leak: ModuleType, written: str) -> None:
    """The walk skips the header, so an address in MSH-24 passed while a routable IPv4 address
    there was refused by the whole-message scan. The header's fields from MSH-3 on are read for
    an IPv6 address too (BACKLOG #5654)."""
    text = _msh24(written)
    assert text.split("\r")[0].split("|")[23] == written  # MSH-24: field 1 is the separator
    report = leak.leak_report(text, rules=DEFAULT_RULES)
    assert f"unmapped {leak.IPV6_REASON} in MSH-24" in report.structural_hits, report.hits
    assert not any(_GLOBAL in hit for hit in report.hits)


@_NO_SCANNER
@_SIDES
def test_anonymize_checked_refuses_a_routable_ipv6_address_in_the_header(anon: ModuleType) -> None:
    with pytest.raises(anon.LeakError, match="IPv6"):
        anon.anonymize_checked(
            _msh24(f"NET^{_GLOBAL}^DNS"), salt="b224-ipv6-header-0123456789abcdef"
        )


@_NO_SCANNER
@_LEAKS
@pytest.mark.parametrize(
    "written",
    ["NET^2001:db8::1^DNS", "NET^fe80::1^DNS", "NET^fd12:3456::1^DNS", "NET^host.example^DNS"],
    ids=["documentation", "link-local", "unique-local", "a-name"],
)
def test_an_allowed_address_in_the_header_is_no_ipv6_hit(leak: ModuleType, written: str) -> None:
    report = leak.leak_report(_msh24(written), rules=DEFAULT_RULES)
    assert not any(leak.IPV6_REASON in hit for hit in report.hits), report.hits


@_NO_SCANNER
@_SIDES
def test_an_ordinary_header_is_not_refused(anon: ModuleType) -> None:
    """A header's timestamp, version and ids hold no IPv6 address, so reading it refuses nothing."""
    raw = _msh24("")
    out = anon.anonymize_checked(raw, salt="b224-ipv6-header-0123456789abcdef")
    assert out.split("\r")[0] == raw.split("\r")[0]


@_LEAKS
def test_a_rule_on_a_header_field_takes_it_out_of_the_ipv6_read(leak: ModuleType) -> None:
    """A field a rule rewrites holds the rule's output, so the header read skips it as the walk
    skips every mapped field."""
    text = _msh24(f"NET^{_GLOBAL}^DNS")
    assert any(leak.IPV6_REASON in hit for hit in leak.structural_phi_hits(text, set()))
    assert not any(leak.IPV6_REASON in hit for hit in leak.structural_phi_hits(text, {"MSH-24"}))


@_NO_SCANNER
@_SIDES
def test_a_keep_on_a_header_field_leaves_it_in_the_ipv6_read(anon: ModuleType) -> None:
    """A keep rewrites nothing, so the field stays in scope, as a kept body field does."""
    rules = (*anon.DEFAULT_RULES, anon.FieldRule("MSH-24", anon.SurrogateKind.KEEP))
    with pytest.raises(anon.LeakError, match="IPv6 address in MSH-24"):
        anon.anonymize_checked(
            _msh24(f"NET^{_GLOBAL}^DNS"), salt="b224-ipv6-header-0123456789abcdef", rules=rules
        )


@_LEAKS
def test_a_header_field_is_numbered_the_header_way(leak: ModuleType) -> None:
    """Field 1 of the header is the separator, so the read starts at MSH-3, after the encoding
    characters, and names each field by its MSH number."""
    text = f"MSH|^~\\&|{_GLOBAL}|B|C|D|20260101||ADT^A01|M1|P|2.5.1\rPID|1||1^^^H^MR||X^Y"
    assert leak._header_ipv6_hits(text, set()) == [f"unmapped {leak.IPV6_REASON} in MSH-3"]


@_NO_SCANNER
@_SIDES
def test_an_address_after_the_encoding_characters_is_refused(anon: ModuleType) -> None:
    """The anonymizer and the engine's parser take four encoding characters from MSH-2, and no
    rule may rewrite it, so
    text after them reaches the output and is read for an address."""
    raw = f"MSH|^~\\&{_GLOBAL}|A|B|C|D|20260101||ADT^A01|M1|P|2.5.1\rPID|1||1^^^H^MR||X^Y"
    with pytest.raises(anon.LeakError, match="IPv6 address in MSH-2") as refused:
        anon.anonymize_checked(raw, salt="b224-ipv6-header-0123456789abcdef")
    # The refusal says to repair the header, since no rule may rewrite MSH-2.
    assert "No rule can rewrite MSH-2" in str(refused.value)


@_NO_SCANNER
@_SIDES
def test_a_truncation_character_after_the_encoding_characters_is_no_address(
    anon: ModuleType,
) -> None:
    raw = "MSH|^~\\&#|A|B|C|D|20260101||ADT^A01|M1|P|2.7\rPID|1||1^^^H^MR||X^Y"
    anon.anonymize_checked(raw, salt="b224-ipv6-header-0123456789abcdef")


_FULL = ":".join(["4000", "a1", "0", "0", "0", "0", "0", "5"])


@_LEAKS
@pytest.mark.parametrize(
    "written",
    [
        f"Device:{_FULL}",
        "Source:::ffff:" + _RESERVED_V4_HEX,
        f"1.{_GLOBAL}",
        f"{_FULL}:443",
        f"IPv6:{_FULL}:443",
        f"Connect to {_GLOBAL}.443.",
    ],
    ids=[
        "hex-label-full",
        "hex-label-mapped",
        "dotted-prefix",
        "full-colon-port",
        "label-and-port",
        "dot-port-and-sentence-dot",
    ],
)
def test_a_label_or_port_joined_to_an_address_is_dropped(leak: ModuleType, written: str) -> None:
    assert leak._has_routable_ipv6(written, lambda ip: True)


@_LEAKS
@pytest.mark.parametrize("written", ["fd00:1::5", "fe80:1::1", "fe80::1:5"])
def test_a_well_formed_allowed_address_is_not_shortened(leak: ModuleType, written: str) -> None:
    """The label and port drops run only when nothing parses, so an allowed address is never read
    as the routable one its tail would make."""
    assert not leak._has_routable_ipv6(written, lambda ip: True)


@_LEAKS
@pytest.mark.parametrize(
    "written",
    ["ff3e::8000:1", "Note::", "std::bad_alloc", "00:1A:2B:FF:FE:3C:4D:5E", "1:2:3:4:5:6:7:8:9"],
)
def test_the_refusals_phi_md_names_hold(leak: ModuleType, written: str) -> None:
    """docs/PHI.md section 9 says these refuse though they hold no routable address: every
    P-flagged multicast address, a hex word joined to ``::``, a colon-written EUI-64, and nine
    colon-separated hex groups, read as an address and a ``:port``."""
    assert leak._has_routable_ipv6(written, lambda ip: True)


@_LEAKS
def test_a_long_hex_run_is_scanned_in_linear_time(leak: ModuleType) -> None:
    """A hex-encoded payload is one long run of candidate characters. The run is matched whole,
    so the scan does not backtrack over it; the old pattern took seconds at 60 KB."""
    import time

    def seconds(repeats: int) -> float:
        payload = "0123456789ABCDEF" * repeats + "::"
        started = time.perf_counter()
        assert not leak._has_routable_ipv6(payload, lambda ip: True)
        return time.perf_counter() - started

    # Four times the input takes about four times as long when the scan is linear, sixteen when
    # it is quadratic, which took seconds at 320 KB. The bound sits between them, with a floor
    # that keeps a noisy runner's sub-millisecond timings from deciding it.
    small, large = seconds(5_000), seconds(20_000)
    assert large < max(small * 10, 0.25)
