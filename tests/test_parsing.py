"""Parsing layer: tolerant peek (routing fields + path access) and strict validate."""

from __future__ import annotations

from pathlib import Path

import pytest

from messagefoundry.parsing import HL7PeekError, Peek, normalize, validate

SAMPLES = Path(__file__).resolve().parents[1] / "samples" / "messages"
ADT = (SAMPLES / "adt_a01.hl7").read_text(encoding="utf-8")


# --- normalize ---------------------------------------------------------------


@pytest.mark.parametrize("sep", ["\r", "\n", "\r\n"])
def test_normalize_collapses_line_endings_to_cr(sep: str) -> None:
    raw = sep.join(["MSH|^~\\&|A", "EVN|A01"])
    assert normalize(raw) == "MSH|^~\\&|A\rEVN|A01"


def test_normalize_decodes_bytes() -> None:
    assert normalize(b"MSH|^~\\&|A\nEVN|x") == "MSH|^~\\&|A\rEVN|x"


def test_normalize_honors_encoding_and_strict_errors() -> None:
    # the right encoding decodes correctly (a latin-1 'ü' is 0xFC)
    assert normalize("Müller".encode("latin-1"), encoding="latin-1") == "Müller"
    # tolerant default replaces an undecodable byte so the hot path keeps routing
    assert "�" in normalize(b"\xff")
    # strict surfaces a genuine decode failure (the engine routes it to the ERROR disposition, H-3)
    with pytest.raises(UnicodeDecodeError):
        normalize(b"\xff", encoding="utf-8", errors="strict")


# --- peek: component access on separator-less fields (regression) ------------


def test_field_component_on_value_without_separators() -> None:
    # A `.1` component on a field that has no `^` must return the whole value, not the first
    # character (python-hl7 stores such a field as a bare string).
    p = Peek.parse("MSH|^~\\&|A|B|C|D|20260604||ADT^A01|M|P|2.5.1\rORC|RE|PLACER123\r")
    assert p.field("ORC-2") == "PLACER123"
    assert p.field("ORC-2.1") == "PLACER123"  # regression: was "P"
    assert p.field("ORC-2.2") is None  # no second component
    # Components still resolve correctly when separators ARE present:
    assert p.field("MSH-9.1") == "ADT"
    assert p.field("MSH-9.2") == "A01"


# --- peek: routing fields ----------------------------------------------------


def test_peek_extracts_routing_fields() -> None:
    p = Peek.parse(ADT)
    assert p.message_type == "ADT^A01"
    assert p.message_code == "ADT"
    assert p.trigger_event == "A01"
    assert p.control_id == "MSG00001"
    assert p.version == "2.5.1"
    assert p.sending_app == "SENDINGAPP"
    assert p.receiving_facility == "RECEIVINGFAC"


def test_peek_routing_dict_has_no_phi() -> None:
    routing = Peek.parse(ADT).routing()
    assert routing["message_type"] == "ADT^A01"
    assert routing["control_id"] == "MSG00001"
    # PID/PV1 content (PHI) must never leak into the routing summary.
    assert "DOE" not in str(routing)
    assert "100001" not in str(routing)


def test_peek_lists_segments_in_order() -> None:
    assert Peek.parse(ADT).segments() == ["MSH", "EVN", "PID", "PV1"]


# --- peek: arbitrary field paths ---------------------------------------------


def test_field_path_levels() -> None:
    p = Peek.parse(ADT)
    assert p.field("MSH-9") == "ADT^A01"  # whole field
    assert p.field("MSH-9.1") == "ADT"  # component
    assert p.field("PID-5.1") == "DOE"  # component of a PHI field
    assert p.field("PID-5.1.1") == "DOE"  # subcomponent


def test_field_missing_segment_or_field_is_none() -> None:
    p = Peek.parse(ADT)
    assert p.field("ZZZ-1") is None  # no such segment
    assert p.field("MSH-99") is None  # field past end
    assert p.field("PID-99.1") is None  # component of absent field


def test_field_msh_offset_is_handled() -> None:
    # MSH-1 is the field separator, MSH-2 the encoding chars — python-hl7 offsets
    # these so MSH-3 onward line up with the spec. Guard that we stay aligned.
    p = Peek.parse(ADT)
    assert p.field("MSH-1") == "|"
    assert p.field("MSH-2") == "^~\\&"
    assert p.field("MSH-3") == "SENDINGAPP"


def test_field_first_repetition() -> None:
    p = Peek.parse("MSH|^~\\&|A|B|C|D|20260101||ADT^A01|1|P|2.5\rPID|||A~B~C")
    assert p.field("PID-3") == "A~B~C"  # full field shows repetitions
    assert p.field("PID-3.1") == "A"  # component resolves first rep


def test_invalid_path_raises() -> None:
    p = Peek.parse(ADT)
    with pytest.raises(HL7PeekError):
        p.field("not a path")
    with pytest.raises(HL7PeekError):
        p.field("MSH")  # missing field number


# --- peek: tolerance & failure modes -----------------------------------------


def test_peek_tolerates_nonconformant_but_parseable() -> None:
    # Minimal/odd but has an MSH and parses — must not raise (routing must continue).
    p = Peek.parse("MSH|^~\\&|||||||FOO^BAR|XYZ")
    assert p.message_code == "FOO"
    assert p.control_id == "XYZ"


def test_peek_rejects_non_hl7() -> None:
    with pytest.raises(HL7PeekError):
        Peek.parse("this is not HL7")
    with pytest.raises(HL7PeekError):
        Peek.parse("")


# --- strict validate ---------------------------------------------------------


def test_validate_accepts_conformant_message() -> None:
    result = validate(ADT)
    assert result.ok
    assert bool(result) is True
    assert result.version == "2.5.1"
    assert result.errors == []


def test_validate_flags_missing_required_segment() -> None:
    # ADT_A01 requires a PID; drop it.
    bad = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|1|P|2.5.1\rEVN|A01|20260101"
    result = validate(bad)
    assert not result.ok
    assert result.errors


def test_validate_reports_version_mismatch() -> None:
    result = validate(ADT, expected_version="2.3")
    assert not result.ok
    assert any("version mismatch" in e for e in result.errors)


def test_validate_empty_message() -> None:
    result = validate("   ")
    assert not result.ok
    assert result.errors


# --- size/segment caps (DoS guards, HL7-2) -----------------------------------


def test_peek_rejects_oversized_message() -> None:
    big = "MSH|^~\\&|" + "A" * 100
    with pytest.raises(HL7PeekError, match="max size"):
        Peek.parse(big, max_bytes=20)


def test_peek_rejects_too_many_segments() -> None:
    msg = "MSH|^~\\&|x\r" + "OBX|1\r" * 50
    with pytest.raises(HL7PeekError, match="max segments"):
        Peek.parse(msg, max_segments=10)


def test_peek_default_caps_allow_a_normal_message() -> None:
    # The generous defaults must never reject a real message.
    assert Peek.parse(ADT).message_code == "ADT"


def test_validate_rejects_oversized_message() -> None:
    # Caps are checked before the (slow) strict parse, so a huge message is cheap to reject.
    result = validate(ADT, max_bytes=20)
    assert not result.ok
    assert any("max size" in e for e in result.errors)


def test_validate_rejects_too_many_segments() -> None:
    msg = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|1|P|2.5.1\r" + "OBX|1\r" * 50
    result = validate(msg, max_segments=10)
    assert not result.ok
    assert any("max segments" in e for e in result.errors)
