"""The mutable Message primitive: read/set fields by path, then re-encode."""

from __future__ import annotations

import pytest

from messagefoundry.parsing import Message

ADT = (
    "MSH|^~\\&|SENDAPP|SENDFAC|RECVAPP|RECVFAC|20260101||ADT^A01^ADT_A01|MSG1|P|2.5.1\r"
    "EVN|A01|20260101\r"
    "PID|1||100^^^HOSP^MR||DOE^JANE^Q||19800101|F\r"
)

# PID-3 with two repetitions (a second identifier) — ubiquitous in real feeds.
PID_REP = (
    "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1|P|2.5.1\r"
    "PID|1||111^^^AUTHA^MR~222^^^AUTHB^MR||DOE^JANE\r"
)


def test_read_fields_and_components() -> None:
    m = Message.parse(ADT)
    assert m["MSH-9.1"] == "ADT"
    assert m["MSH-9.2"] == "A01"
    assert m.field("MSH-9") == "ADT^A01^ADT_A01"
    assert m["PID-5.1"] == "DOE"
    assert m["PID-5.2"] == "JANE"
    assert m["PID-3.1"] == "100"
    assert m["PID-99"] is None  # absent field -> None
    assert m["ZZZ-1"] is None  # absent segment -> None


def test_convenience_properties_and_segments() -> None:
    m = Message.parse(ADT)
    assert m.message_code == "ADT"
    assert m.trigger_event == "A01"
    assert m.control_id == "MSG1"
    assert m.message_type == "ADT^A01^ADT_A01"
    assert m.segments() == ["MSH", "EVN", "PID"]


def test_set_and_roundtrip() -> None:
    m = Message.parse(ADT)
    m["MSH-3"] = "FOUNDRY"  # whole field
    m.set("PID-5.3", "MIDDLE")  # overwrite a component, siblings preserved
    assert m["MSH-3"] == "FOUNDRY"
    assert m["PID-5.1"] == "DOE"
    assert m["PID-5.3"] == "MIDDLE"
    # re-encode parses back and reflects the edits
    again = Message.parse(m.encode())
    assert again["MSH-3"] == "FOUNDRY"
    assert again["PID-5.1"] == "DOE"
    assert again["PID-5.3"] == "MIDDLE"


def test_set_extends_components() -> None:
    m = Message.parse(ADT)
    m.set("MSH-3.2", "NS")  # MSH-3 was the single component "SENDAPP"
    assert m["MSH-3.1"] == "SENDAPP"
    assert m["MSH-3.2"] == "NS"


def test_set_absent_segment_raises() -> None:
    m = Message.parse(ADT)
    with pytest.raises(KeyError):
        m.set("ZZZ-1", "x")


# --- HL7 escaping on write / unescaping on read (XFORM-1/2/3) -----------------


def test_set_component_escapes_delimiters_and_round_trips() -> None:
    m = Message.parse(ADT)
    m["PID-5.1"] = "O^Brien"  # a caret in a component must stay data, not split into components
    assert m["PID-5.1"] == "O^Brien"  # read unescapes
    assert m["PID-5.2"] == "JANE"  # the sibling component is untouched (no injected component)
    # survives a full re-encode → re-parse cycle
    again = Message.parse(m.encode())
    assert again["PID-5.1"] == "O^Brien"
    assert again["PID-5.2"] == "JANE"


def test_set_rejects_segment_separator() -> None:
    m = Message.parse(ADT)
    with pytest.raises(ValueError, match="segment separator"):
        m.set("PID-5.1", "MRN\rZZZ|injected")  # CR would inject a new segment downstream
    with pytest.raises(ValueError, match="segment separator"):
        m["PID-3"] = "a\nb"  # LF normalizes to CR on the wire — also rejected


def test_whole_field_write_keeps_structure_but_blocks_cr() -> None:
    m = Message.parse(ADT)
    m["PID-5"] = "X^Y"  # whole-field write: separators are the caller's structure
    assert m["PID-5.1"] == "X"
    assert m["PID-5.2"] == "Y"
    with pytest.raises(ValueError):
        m["PID-5"] = "X\rY"


def test_custom_separators_round_trip() -> None:
    # Non-standard encoding characters: component '@', escape '%'. set/field must use MSH-2, not
    # hardcoded defaults (XFORM-2/3), or the value would be split/escaped on the wrong chars.
    m = Message.parse("MSH|@#%&|APP\rPID|1||X||DOE@JANE\r")
    assert m["PID-5.1"] == "DOE"
    assert m["PID-5.2"] == "JANE"
    m["PID-5.1"] = "O@Brien"  # '@' is the component sep here → must be escaped as data
    assert m["PID-5.1"] == "O@Brien"
    assert m["PID-5.2"] == "JANE"


# --- field repetitions (H-9) -------------------------------------------------


def test_component_read_uses_first_repetition() -> None:
    m = Message.parse(PID_REP)
    # A component read of a repeating field takes the FIRST repetition (matching Peek), not
    # cross-repetition text like "AUTHA^MR~222..." (review H-9).
    assert m["PID-3.1"] == "111"
    assert m["PID-3.4"] == "AUTHA"
    # whole-field read still returns every repetition
    assert m.field("PID-3") == "111^^^AUTHA^MR~222^^^AUTHB^MR"


def test_set_preserves_sibling_repetitions() -> None:
    m = Message.parse(PID_REP)
    m.set("PID-3.4", "NEWAUTH")  # edit a component of repetition 1
    assert m["PID-3.4"] == "NEWAUTH"
    # the SECOND repetition (a distinct patient identifier) must survive, not be merged away (H-9)
    assert m.field("PID-3") == "111^^^NEWAUTH^MR~222^^^AUTHB^MR"
    again = Message.parse(m.encode())
    assert again.field("PID-3") == "111^^^NEWAUTH^MR~222^^^AUTHB^MR"
    assert again["PID-3.4"] == "NEWAUTH"


# --- whole-field field-separator guard (M-12) + non-Latin-1 chars (M-13) -----


def test_whole_field_write_rejects_field_separator() -> None:
    m = Message.parse(ADT)
    with pytest.raises(ValueError, match="field separator"):
        m["PID-5"] = "DOE|JANE"  # '|' would split into extra fields downstream (review M-12)
    # the same value via a component path is fine — '|' is escaped as data, not new fields
    m["PID-5.1"] = "DOE|JANE"
    assert m["PID-5.1"] == "DOE|JANE"
    again = Message.parse(m.encode())
    assert again["PID-5.1"] == "DOE|JANE"
    assert again["PID-6"] is None  # did NOT leak into a new field


def test_component_write_preserves_non_latin1_characters() -> None:
    m = Message.parse(ADT)
    m["PID-5.1"] = (
        "李"  # CJK (>U+00FF): python-hl7's escape() corrupts this; ours passes it through
    )
    assert m["PID-5.1"] == "李"
    assert Message.parse(m.encode())["PID-5.1"] == "李"
    m["PID-5.2"] = "Müller^X"  # mixes a >U+00FF char with a delimiter that must be escaped
    assert m["PID-5.2"] == "Müller^X"
    assert Message.parse(m.encode())["PID-5.2"] == "Müller^X"
