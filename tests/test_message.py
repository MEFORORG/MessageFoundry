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


# --- C-2: segment occurrences (the Nth OBX) ----------------------------------

ORU = (
    "MSH|^~\\&|A|B|C|D|20260101||ORU^R01|MSG1|P|2.5.1\r"
    "PID|1||X||DOE\r"
    "OBX|1|NM|GLU^Glucose||100|mg/dL\r"
    "OBX|2|NM|NA^Sodium||140|mmol/L\r"
)


def test_count_segments() -> None:
    m = Message.parse(ORU)
    assert m.count_segments("OBX") == 2
    assert m.count_segments("PID") == 1
    assert m.count_segments("ZZZ") == 0


def test_read_segment_occurrence() -> None:
    m = Message.parse(ORU)
    assert m.field("OBX-5") == "100"  # default = first occurrence
    assert m.field("OBX-5", occurrence=1) == "100"
    assert m.field("OBX-5", occurrence=2) == "140"
    assert m.field("OBX-3.2", occurrence=2) == "Sodium"
    assert m.field("OBX-5", occurrence=3) is None  # absent occurrence


def test_write_segment_occurrence_isolated() -> None:
    m = Message.parse(ORU)
    m.set("OBX-5", "99", occurrence=2)
    assert m.field("OBX-5", occurrence=2) == "99"
    assert m.field("OBX-5") == "100"  # the first OBX is untouched
    again = Message.parse(m.encode())
    assert again.field("OBX-5", occurrence=2) == "99"
    assert again.field("OBX-5") == "100"


def test_write_segment_occurrence_extends_fields() -> None:
    m = Message.parse(ORU)
    m.set("OBX-11", "ABNORMAL", occurrence=2)  # field past the segment's current length
    assert m.field("OBX-11", occurrence=2) == "ABNORMAL"
    assert Message.parse(m.encode()).field("OBX-11", occurrence=2) == "ABNORMAL"


def test_write_absent_occurrence_raises() -> None:
    m = Message.parse(ORU)
    with pytest.raises(KeyError):
        m.set("OBX-5", "x", occurrence=3)


def test_occurrence_and_repetition_are_one_based() -> None:
    m = Message.parse(ORU)
    for bad in ({"occurrence": 0}, {"repetition": 0}):
        with pytest.raises(ValueError):
            m.field("OBX-5", **bad)  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            m.set("OBX-5", "x", **bad)  # type: ignore[arg-type]


# --- C-2: field repetitions (iterate / address / append) ---------------------


def test_repetitions_whole_field_and_component() -> None:
    m = Message.parse(PID_REP)
    assert m.repetitions("PID-3") == ["111^^^AUTHA^MR", "222^^^AUTHB^MR"]
    assert m.repetitions("PID-3.1") == ["111", "222"]
    assert m.repetitions("PID-3.4") == ["AUTHA", "AUTHB"]
    assert m.repetitions("PID-99") == []  # absent field
    assert m.repetitions("PID-5") == ["DOE^JANE"]  # single-rep field -> one element


def test_read_specific_repetition() -> None:
    m = Message.parse(PID_REP)
    assert m.field("PID-3", repetition=2) == "222^^^AUTHB^MR"
    assert m.field("PID-3.1", repetition=2) == "222"
    assert m.field("PID-3.4", repetition=2) == "AUTHB"
    assert m.field("PID-3.4", repetition=3) is None  # absent repetition


def test_whole_field_repetition_none_vs_one_is_deliberate() -> None:
    # Intentional, documented asymmetry: for a WHOLE-field read, repetition=None means "unscoped"
    # (every repetition, the legacy default) while repetition=1 scopes to just the first rep. For a
    # COMPONENT read the two coincide (both = first rep). This is the None-sentinel pattern, not a bug.
    m = Message.parse(PID_REP)
    assert m.field("PID-3") == "111^^^AUTHA^MR~222^^^AUTHB^MR"  # None -> all reps
    assert m.field("PID-3", repetition=1) == "111^^^AUTHA^MR"  # 1 -> only the first rep
    assert m.field("PID-3.4") == m.field("PID-3.4", repetition=1) == "AUTHA"  # component: same


def test_write_specific_repetition_preserves_siblings() -> None:
    m = Message.parse(PID_REP)
    m.set("PID-3.4", "NEW", repetition=2)
    assert m.field("PID-3.4") == "AUTHA"  # rep 1 untouched
    assert m.field("PID-3.4", repetition=2) == "NEW"
    assert m.field("PID-3") == "111^^^AUTHA^MR~222^^^NEW^MR"


def test_write_repetition_extends() -> None:
    m = Message.parse(PID_REP)
    m.set("PID-3.1", "999", repetition=3)  # rep 3 does not exist yet
    assert m.field("PID-3", repetition=3) == "999"
    assert m.repetitions("PID-3.1") == ["111", "222", "999"]


def test_whole_field_write_with_repetition_replaces_one_rep() -> None:
    m = Message.parse(PID_REP)
    m.set("PID-3", "ZZZ^^^AUTHZ", repetition=1)  # replace rep 1 whole, keep rep 2
    assert m.field("PID-3") == "ZZZ^^^AUTHZ~222^^^AUTHB^MR"
    with pytest.raises(ValueError, match="repetition separator"):
        m.set("PID-3", "a~b", repetition=1)  # the value targets one rep


def test_add_repetition() -> None:
    m = Message.parse(PID_REP)
    m.add_repetition("PID-3", "333^^^AUTHC^MR")
    assert m.repetitions("PID-3.4") == ["AUTHA", "AUTHB", "AUTHC"]
    again = Message.parse(m.encode())
    assert again.field("PID-3.4", repetition=3) == "AUTHC"


def test_add_repetition_to_empty_field_becomes_first() -> None:
    m = Message.parse(PID_REP)
    m.add_repetition("PID-10", "FIRST")  # PID-10 absent
    assert m.field("PID-10") == "FIRST"
    assert m.repetitions("PID-10") == ["FIRST"]


def test_add_repetition_rejects_component_path_and_separators() -> None:
    m = Message.parse(PID_REP)
    with pytest.raises(ValueError, match="whole-field path"):
        m.add_repetition("PID-3.1", "x")
    with pytest.raises(ValueError, match="repetition separator"):
        m.add_repetition("PID-3", "a~b")
    with pytest.raises(ValueError, match="field separator"):
        m.add_repetition("PID-3", "a|b")
    with pytest.raises(ValueError, match="segment separator"):
        m.add_repetition("PID-3", "a\rb")


# --- C-2: segment add / delete -----------------------------------------------


def test_add_segment_append_and_reparse_structure() -> None:
    m = Message.parse(ORU)
    m.add_segment("ODS|R|^ODS123|GEN^Regular^Diet")
    assert m.count_segments("ODS") == 1
    assert m.segments()[-1] == "ODS"
    assert m.field("ODS-3.1") == "GEN"
    assert m.field("ODS-3.2") == "Regular"
    again = Message.parse(m.encode())  # re-parses into real components, byte-identical
    assert again.field("ODS-3.2") == "Regular"
    assert "ODS|R|^ODS123|GEN^Regular^Diet" in m.encode()


def test_add_segment_at_index() -> None:
    m = Message.parse(ORU)
    m.add_segment("ZAL|1|note", index=1)  # just after MSH
    assert m.segments() == ["MSH", "ZAL", "PID", "OBX", "OBX"]
    with pytest.raises(ValueError, match="out of range"):
        m.add_segment("ZAL|2", index=99)


def test_add_segment_guards() -> None:
    m = Message.parse(ORU)
    with pytest.raises(ValueError, match="MSH"):
        m.add_segment("MSH|^~\\&|x")  # no second MSH
    with pytest.raises(ValueError, match="segment id"):
        m.add_segment("ABCD|x")  # 4-char id
    with pytest.raises(ValueError, match="no CR/LF"):
        m.add_segment("ZAL|1\rZAL|2")  # one segment per call


def test_add_segment_custom_separators() -> None:
    m = Message.parse("MSH|@#%&|APP\rPID|1||X||DOE@JANE\r")
    m.add_segment("ODS|R|GEN@Regular")  # '@' is this message's component separator
    assert m.field("ODS-2.1") == "GEN"
    assert m.field("ODS-2.2") == "Regular"
    assert Message.parse(m.encode()).field("ODS-2.2") == "Regular"


def test_delete_segments() -> None:
    m = Message.parse(ORU)
    assert m.delete_segments("OBX") == 2
    assert m.count_segments("OBX") == 0
    assert m.segments() == ["MSH", "PID"]
    assert m.delete_segments("ZZZ") == 0  # absent -> 0
    with pytest.raises(ValueError, match="MSH"):
        m.delete_segments("MSH")


def test_clear_then_rebuild_repeating_block() -> None:
    # The Corepoint "rebuild the ODS block" pattern, now expressible without string-slicing.
    m = Message.parse(ORU)
    keep = [m.field("OBX-3.1", occurrence=i) for i in (1, 2)]
    m.delete_segments("OBX")
    for code in keep:
        m.add_segment(f"OBX|1|NM|{code}||OK")
    assert m.count_segments("OBX") == 2
    assert [m.field("OBX-3.1", occurrence=i) for i in (1, 2)] == ["GLU", "NA"]
    assert m.field("OBX-5") == "OK"
