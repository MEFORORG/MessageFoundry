# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Pure X12 codec (messagefoundry.parsing.x12) — delimiters, peek, interchange framing, message,
integrity, and the console-carve-out import-purity guard (ADR 0012)."""

from __future__ import annotations

import subprocess
import sys

import pytest

from messagefoundry.parsing.x12 import (
    X12FrameReader,
    X12Message,
    X12Peek,
    X12PeekError,
    check_integrity,
    discover_delimiters,
    find_isa_start,
    split,
)


def isa(
    *,
    el: str = "*",
    comp: str = ":",
    term: str = "~",
    rep: str = "^",
    version: str = "00501",
    sender: str = "SENDERID",
    receiver: str = "RECEIVERID",
    control: str = "000000001",
    usage: str = "P",
) -> str:
    """A fixed-length (106-char) ISA header with configurable delimiters/version."""
    seg = (
        "ISA"
        + el
        + "00"
        + el
        + " " * 10
        + el
        + "00"
        + el
        + " " * 10
        + el
        + "ZZ"
        + el
        + sender.ljust(15)
        + el
        + "ZZ"
        + el
        + receiver.ljust(15)
        + el
        + "240101"
        + el
        + "1200"
        + el
        + rep
        + el
        + version
        + el
        + control
        + el
        + "0"
        + el
        + usage
        + el
        + comp
    )
    assert len(seg) == 105, f"ISA pre-terminator length {len(seg)} (want 105)"
    return seg + term


def interchange(
    *,
    el: str = "*",
    comp: str = ":",
    term: str = "~",
    rep: str = "^",
    version: str = "00501",
    control: str = "000000001",
    usage: str = "P",
    groups: list[tuple[str, str, list[str]]] | None = None,
) -> str:
    """A complete interchange. ``groups`` = list of (GS01 functional id, GS08 version, [ST01 ids])."""
    if groups is None:
        groups = [("HS", "005010X279A1", ["270"])]
    head = isa(el=el, comp=comp, term=term, rep=rep, version=version, control=control, usage=usage)
    body = ""
    for gi, (fid, gver, txs) in enumerate(groups, 1):
        body += el.join(["GS", fid, "SAPP", "RAPP", "20240101", "1200", str(gi), "X", gver]) + term
        for ti, tx in enumerate(txs, 1):
            body += el.join(["ST", tx, f"{ti:04d}"]) + term
            body += el.join(["SE", "2", f"{ti:04d}"]) + term  # ST + SE = 2 segments
        body += el.join(["GE", str(len(txs)), str(gi)]) + term
    body += el.join(["IEA", str(len(groups)), control]) + term
    return head + body


# --- delimiter discovery -----------------------------------------------------


def test_discover_default_delimiters() -> None:
    d = discover_delimiters(interchange())
    assert (d.element, d.component, d.segment, d.repetition) == ("*", ":", "~", "^")


def test_discover_non_default_delimiters() -> None:
    d = discover_delimiters(interchange(el="|", comp="^", term="'", rep="~"))
    assert (d.element, d.component, d.segment, d.repetition) == ("|", "^", "'", "~")


def test_repetition_separator_gated_on_version() -> None:
    # 00501+ : ISA11 is the repetition separator.
    assert discover_delimiters(interchange(version="00501", rep="^")).repetition == "^"
    # 00401 and earlier : ISA11 is the literal "U", NOT a delimiter.
    assert discover_delimiters(interchange(version="00401", rep="U")).repetition is None


def test_crlf_segment_terminator() -> None:
    d = discover_delimiters(interchange(term="\r\n"))
    assert d.segment == "\r\n"


def test_leading_whitespace_and_bom_tolerated() -> None:
    raw = "" + chr(65279) + "  \r\n" + interchange()
    assert find_isa_start(raw) == 5  # BOM(1) + 2 spaces + CR + LF = 5 chars before "ISA"
    assert X12Peek.parse(raw).sender_id == "SENDERID"


def test_truncated_isa_raises() -> None:
    with pytest.raises(X12PeekError, match="truncated"):
        discover_delimiters(isa()[:60])


def test_non_distinct_delimiters_raise() -> None:
    with pytest.raises(X12PeekError, match="not mutually distinct"):
        discover_delimiters(interchange(comp="*"))  # component == element


def test_sanity_gate_catches_misplaced_separator() -> None:
    raw = list(interchange())
    raw[6] = "X"  # corrupt a fixed element-separator position
    with pytest.raises(X12PeekError, match="malformed"):
        discover_delimiters("".join(raw))


def test_non_x12_input_raises() -> None:
    with pytest.raises(X12PeekError, match="does not begin with an ISA"):
        find_isa_start("MSH|^~\\&|not x12")


# --- peek --------------------------------------------------------------------


def test_peek_interchange_identity() -> None:
    p = X12Peek.parse(interchange(usage="T"))
    assert p.sender_id == "SENDERID" and p.sender_qual == "ZZ"
    assert p.receiver_id == "RECEIVERID" and p.receiver_qual == "ZZ"
    assert p.version == "00501" and p.control_number == "000000001"
    assert p.usage == "T" and p.is_test is True


def test_peek_groups_multi_gs_multi_st_with_gs08() -> None:
    raw = interchange(
        groups=[
            ("HC", "005010X222A1", ["837"]),
            ("HB", "005010X279A1", ["270", "271"]),
        ]
    )
    groups = X12Peek.parse(raw).groups()
    assert len(groups) == 2
    assert groups[0].functional_id == "HC" and groups[0].version == "005010X222A1"
    assert groups[0].transactions == ("837",)
    assert groups[1].functional_id == "HB" and groups[1].version == "005010X279A1"
    assert groups[1].transactions == ("270", "271")
    assert X12Peek.parse(raw).transaction_ids() == ["837", "270", "271"]


def test_peek_segment_ids() -> None:
    ids = X12Peek.parse(interchange()).segment_ids()
    assert ids[0] == "ISA" and ids[-1] == "IEA" and "GS" in ids and "ST" in ids


def test_peek_accepts_bytes() -> None:
    assert X12Peek.parse(interchange().encode("utf-8")).version == "00501"


# --- interchange splitting ---------------------------------------------------


def test_split_single() -> None:
    one = interchange()
    assert split(one) == [one]


def test_split_two_concatenated() -> None:
    a = interchange(control="000000001")
    b = interchange(control="000000002")
    assert split(a + b) == [a, b]


def test_split_skips_inter_interchange_noise() -> None:
    a, b = interchange(), interchange(control="000000002")
    assert split(a + "\r\n\r\n" + b) == [a, b]


def test_split_surfaces_unterminated_remainder() -> None:
    a = interchange()
    partial = isa(control="000000009") + "GS*HS*A*B*20240101*1200*1*X*005010X279A1~"  # no IEA
    out = split(a + partial)
    assert out[0] == a and out[1] == partial


def test_split_tolerates_cosmetic_newlines_after_terminator() -> None:
    pretty = interchange().replace("~", "~\n")
    parts = split(pretty)
    assert len(parts) == 1 and parts[0].lstrip().startswith("ISA") and "IEA" in parts[0]


# --- streaming byte frame reader ---------------------------------------------


def test_frame_reader_byte_at_a_time() -> None:
    data = interchange().encode("utf-8")
    reader = X12FrameReader()
    out: list[bytes] = []
    for i in range(len(data)):
        out.extend(reader.feed(data[i : i + 1]))
    assert out == [data]


def test_frame_reader_two_in_one_feed() -> None:
    a = interchange(control="000000001").encode("utf-8")
    b = interchange(control="000000002").encode("utf-8")
    assert list(X12FrameReader().feed(a + b)) == [a, b]


def test_frame_reader_crlf_terminator() -> None:
    data = interchange(term="\r\n").encode("utf-8")
    assert list(X12FrameReader().feed(data)) == [data]


def test_frame_reader_iea_in_data_does_not_truncate() -> None:
    raw = (
        isa()
        + "GS*HS*A*B*20240101*1200*1*X*005010X279A1~ST*270*0001~REF*XX*IEADATA~SE*3*0001~GE*1*1~IEA*1*000000001~"
    )
    data = raw.encode("utf-8")
    assert list(X12FrameReader().feed(data)) == [data]


def test_frame_reader_oversize_raises() -> None:
    from messagefoundry.parsing.x12 import X12FrameError

    reader = X12FrameReader(max_interchange_bytes=64)
    with pytest.raises(X12FrameError):
        list(reader.feed(interchange().encode("utf-8")))


# --- integrity ---------------------------------------------------------------


def test_integrity_clean_interchange_ties_out() -> None:
    assert check_integrity(interchange()) == []


def test_integrity_flags_control_number_and_count_mismatches() -> None:
    bad = interchange().replace("IEA*1*000000001~", "IEA*9*999999999~")
    problems = check_integrity(bad)
    assert any("IEA02" in p for p in problems)
    assert any("IEA01" in p for p in problems)


# --- mutable message ---------------------------------------------------------


def test_message_round_trip_clean() -> None:
    raw = interchange()
    assert X12Message.parse(raw).encode() == raw


def test_message_round_trip_custom_delimiters() -> None:
    raw = interchange(el="|", comp="^", term="'", rep="~")
    assert X12Message.parse(raw).encode() == raw


def test_message_get_set_element_and_component() -> None:
    msg = X12Message.parse(interchange())
    assert msg["BHT-03"] is None  # no BHT in the minimal interchange
    msg = X12Message.parse(
        isa() + "GS*HS*A*B*20240101*1200*1*X*005010X279A1~ST*270*0001~"
        "NM1*IL*1*DOE*JANE~SE*3*0001~GE*1*1~IEA*1*000000001~"
    )
    assert msg["NM1-03"] == "DOE"
    msg["NM1-03"] = "SMITH"
    assert msg["NM1-03"] == "SMITH"
    msg.set("NM1-04", "JOHN")
    assert msg["NM1-04"] == "JOHN"
    assert "NM1*IL*1*SMITH*JOHN" in msg.encode()


def test_message_occurrence_selects_segment() -> None:
    msg = X12Message.parse(
        isa() + "GS*HS*A*B*20240101*1200*1*X*005010X279A1~ST*270*0001~"
        "HL*1**20*1~HL*2*1*21*1~SE*3*0001~GE*1*1~IEA*1*000000001~"
    )
    assert msg.get("HL-01", occurrence=1) == "1"
    assert msg.get("HL-01", occurrence=2) == "2"
    assert msg.count_segments("HL") == 2


def test_message_add_and_delete_segments() -> None:
    msg = X12Message.parse(
        isa()
        + "GS*HS*A*B*20240101*1200*1*X*005010X279A1~ST*270*0001~SE*2*0001~GE*1*1~IEA*1*000000001~"
    )
    msg.add_segment("REF*EI*123456789", index=msg.segment_ids().index("SE"))
    assert "REF*EI*123456789" in msg.encode()
    assert msg.delete_segments("REF") == 1
    assert "REF*EI" not in msg.encode()


def test_message_set_rejects_delimiter_injection() -> None:
    msg = X12Message.parse(
        isa()
        + "GS*HS*A*B*20240101*1200*1*X*005010X279A1~ST*270*0001~NM1*IL*1*DOE~SE*2*0001~GE*1*1~IEA*1*000000001~"
    )
    with pytest.raises(ValueError, match="delimiter"):
        msg.set("NM1-03", "BAD*VALUE")  # element separator would inject a field
    with pytest.raises(ValueError, match="delimiter"):
        msg.set("NM1-03", "BAD~VALUE")  # segment terminator would inject a segment


def test_message_refuses_envelope_segment_edits() -> None:
    msg = X12Message.parse(interchange())
    with pytest.raises(ValueError, match="envelope"):
        msg.add_segment("ISA*00*x")
    with pytest.raises(ValueError, match="envelope"):
        msg.delete_segments("IEA")


# --- review follow-ups: additional edge-case coverage ------------------------


def test_peek_orphan_st_without_gs() -> None:
    # An ST with no enclosing GS is malformed, but the peek must not lose it: it surfaces as a group
    # with None envelope fields carrying the transaction (count-and-log: nothing silently dropped).
    raw = isa() + "ST*270*0001~SE*2*0001~IEA*1*000000001~"
    groups = X12Peek.parse(raw).groups()
    assert len(groups) == 1
    assert groups[0].functional_id is None and groups[0].version is None
    assert groups[0].control_number is None and groups[0].transactions == ("270",)


def test_frame_reader_crlf_terminator_byte_at_a_time() -> None:
    # A 2-byte CR+LF terminator split across single-byte socket reads must still frame verbatim.
    data = interchange(term="\r\n").encode("utf-8")
    reader = X12FrameReader()
    out: list[bytes] = []
    for i in range(len(data)):
        out.extend(reader.feed(data[i : i + 1]))
    assert out == [data]


def test_integrity_group_and_transaction_mismatches() -> None:
    # GS06/GE02 control-number mismatch.
    assert any("GE02" in p for p in check_integrity(interchange().replace("GE*1*1~", "GE*1*9~")))
    # ST02/SE02 control-number mismatch.
    assert any(
        "SE02" in p for p in check_integrity(interchange().replace("SE*2*0001~", "SE*2*9999~"))
    )
    # SE01 segment-count mismatch.
    assert any(
        "SE01" in p for p in check_integrity(interchange().replace("SE*2*0001~", "SE*9*0001~"))
    )


@pytest.mark.parametrize(
    "path", ["NM1-0", "NM1-00.1", "NM1-03.0", "NM1", "nm1-03", "NM1_03", "NM1-3.x"]
)
def test_message_invalid_paths_rejected(path: str) -> None:
    msg = X12Message.parse(
        isa()
        + "GS*HS*A*B*20240101*1200*1*X*005010X279A1~ST*270*0001~NM1*IL*1*DOE~SE*2*0001~GE*1*1~IEA*1*000000001~"
    )
    with pytest.raises(X12PeekError):
        msg.get(path)


def test_message_add_segment_at_boundaries() -> None:
    base = (
        isa()
        + "GS*HS*A*B*20240101*1200*1*X*005010X279A1~ST*270*0001~SE*2*0001~GE*1*1~IEA*1*000000001~"
    )
    inserted = X12Message.parse(base)
    inserted.add_segment("REF*EI*1", index=1)  # right after ISA
    assert inserted.segment_ids()[1] == "REF"
    appended = X12Message.parse(base)
    appended.add_segment("REF*EI*2")  # default → appended last
    assert appended.segment_ids()[-1] == "REF"
    count = len(X12Message.parse(base).segment_ids())
    for bad_index in (0, -1, count + 1):
        with pytest.raises(ValueError):
            X12Message.parse(base).add_segment("REF*EI*9", index=bad_index)


def test_message_large_interchange_round_trip() -> None:
    raw = interchange(groups=[("HS", "005010X279A1", ["270"] * 50)])
    msg = X12Message.parse(raw)
    assert msg.encode() == raw  # byte-identical round-trip at scale
    assert msg.count_segments("ST") == 50
    assert check_integrity(raw) == []
    assert X12Peek.parse(raw).transaction_ids() == ["270"] * 50


# --- console carve-out: import purity ---------------------------------------


def test_parsing_x12_pulls_no_heavy_engine_or_gui_modules() -> None:
    """Importing parsing.x12 must NOT pull in the engine internals or the GUI (ADR 0012 + CLAUDE.md §4
    carve-out): no pipeline/store/transports/api/console. (``config`` is excluded here because the root
    ``messagefoundry/__init__`` imports config *models* unconditionally — a baseline shared by all of
    parsing/; that x12's own sources don't import config is enforced by the static test below.)"""
    code = (
        "import sys, messagefoundry.parsing.x12 as _;"
        "heavy=('messagefoundry.pipeline','messagefoundry.store','messagefoundry.transports',"
        "'messagefoundry.api','messagefoundry.console');"
        "bad=sorted(m for m in sys.modules if m.startswith(heavy));"
        "print('\\n'.join(bad));"
        "sys.exit(1 if bad else 0)"
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert result.returncode == 0, f"parsing.x12 pulled heavy engine/GUI modules:\n{result.stdout}"


def test_parsing_x12_sources_import_no_engine_packages() -> None:
    """Every parsing.x12 module must import zero engine packages — config included (the ADR's
    'refer to the content type by the literal "x12"' rule) — so the codec stays pure."""
    import pathlib

    import messagefoundry.parsing.x12 as pkg

    forbidden = (
        "messagefoundry.config",
        "messagefoundry.transports",
        "messagefoundry.pipeline",
        "messagefoundry.store",
        "messagefoundry.api",
        "messagefoundry.console",
    )
    offenders: list[str] = []
    for module_file in sorted(pathlib.Path(pkg.__file__).parent.glob("*.py")):
        for line in module_file.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            for pkg_name in forbidden:
                if stripped.startswith((f"import {pkg_name}", f"from {pkg_name}")):
                    offenders.append(f"{module_file.name}: {stripped}")
    assert not offenders, "parsing.x12 sources import engine packages:\n" + "\n".join(offenders)
