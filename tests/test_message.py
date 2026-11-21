# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The mutable Message primitive: read/set fields by path, then re-encode."""

from __future__ import annotations

import copy
from collections.abc import Callable, ItemsView

import pytest

from messagefoundry.parsing import HL7PeekError, Message, Peek, _builtin_hl7

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


# --- header delimiter fields (BACKLOG #5972) -----------------------------------

#: A batch-led message: the parser reads its separators from the BHS line, not from the MSH.
_BATCH = "BHS|^~\\&|A|B\rMSH|^~\\&|A|B|C|D|20260101||ADT^A01|M1|P|2.5.1\rPID|1||X^Y\r"


@pytest.mark.parametrize(
    ("path", "value"),
    [
        ("MSH-1", "#"),
        ("MSH-2", "#~\\&"),
        ("MSH-2", "^~\\"),  # a short MSH-2
        ("MSH-2.1", "#"),
    ],
)
@pytest.mark.parametrize("as_data", [False, True])
def test_a_write_that_changes_a_delimiter_field_is_refused(
    path: str, value: str, as_data: bool
) -> None:
    """A changed MSH-1 or MSH-2 would advertise delimiters the rest of the message is not written
    in, while the separators the parser read stay as they were: mixed-delimiter HL7. So the write
    raises and the message is left exactly as it was."""
    m = Message.parse(ADT)
    before = m.encode()
    write = m.set_data if as_data else m.set
    with pytest.raises(ValueError, match="holds the message's delimiters"):
        write(path, value)
    assert m.encode() == before
    assert m["PID-5.1"] == "DOE"


def test_a_repetition_scoped_delimiter_write_is_refused() -> None:
    m = Message.parse(ADT)
    with pytest.raises(ValueError, match="holds the message's delimiters"):
        m.set("MSH-2", "#~\\&", repetition=1)
    with pytest.raises(ValueError, match="holds the message's delimiters"):
        m.set("MSH-2", m["MSH-2"] or "", repetition=2)
    with pytest.raises(ValueError, match="holds the message's delimiters"):
        m.add_repetition("MSH-2", "x")


def test_a_repetition_1_passthrough_of_a_delimiter_field_changes_nothing() -> None:
    """A copy loop that passes ``repetition=1`` writes the same bytes as one that passes none."""
    m = Message.parse(ADT)
    before = m.encode()
    m.set("MSH-2", m["MSH-2"] or "", repetition=1)
    m.set("MSH-2", m.field("MSH-2", repetition=1) or "", repetition=1)
    m.set("MSH-2.1", m.field("MSH-2.1") or "")
    assert m.encode() == before


def test_msh_2_past_its_four_encoding_characters_can_change() -> None:
    """The delimiters do not move, so a v2.7 truncation character may be added or dropped."""
    m = Message.parse(ADT.replace("MSH|^~\\&|", "MSH|^~\\&#|", 1))
    m.set("MSH-2", "^~\\&")
    assert m.encode() == ADT
    m.set("MSH-2", "^~\\&#")
    assert Message.parse(m.encode())["MSH-2"] == "^~\\&#"
    assert m["PID-5.2"] == "JANE"
    # The truncation character must be one printable, non-space, non-delimiter character, as a
    # per-outbound re-encode of a batch header requires (BACKLOG #5802).
    for refused in ("^~\\&|", "^~\\&^", "^~\\&~", "^~\\& ", "^~\\&\x07", "^~\\&##"):
        with pytest.raises(ValueError, match="holds the message's delimiters"):
            m.set("MSH-2", refused)
    assert Message.parse(m.encode())["MSH-2"] == "^~\\&#"


def test_a_delimiter_refusal_names_only_what_the_field_accepts() -> None:
    """The refusal must be true of the write it refuses. Field 2 also accepts a changed v2.7
    truncation character, so its text must not say only the text already there is accepted, and
    ``add_repetition`` accepts nothing there."""
    m = Message.parse(ADT)
    with pytest.raises(ValueError) as field_1:
        m.set("MSH-1", "#")
    assert "must leave it reading as it does. Re-encode" in str(field_1.value)
    with pytest.raises(ValueError) as field_2:
        m.set("MSH-2", "#~\\&")
    assert "change only the one v2.7 truncation character" in str(field_2.value)
    # A component or repetition-2 write at field 2 cannot change the truncation character, so its
    # refusal must not offer that.
    scoped_writes: list[tuple[str, int | None]] = [("MSH-2.2", None), ("MSH-2", 2)]
    for path, repetition in scoped_writes:
        with pytest.raises(ValueError) as scoped:
            m.set(path, "x", repetition=repetition)
        assert "truncation" not in str(scoped.value)
        assert "must leave it reading as it does. Re-encode" in str(scoped.value)
    with pytest.raises(ValueError) as added:
        m.add_repetition("MSH-2", "x")
    assert "a repetition cannot be added to it" in str(added.value)
    for refusal in (field_1.value, field_2.value, added.value):
        assert "already holds" not in str(refusal)
    # The accepted truncation-character write the field-2 text names really is accepted.
    m.set("MSH-2", "^~\\&#")
    assert m["MSH-2"] == "^~\\&#"


def test_a_delimiter_write_of_the_text_already_there_changes_nothing() -> None:
    """A passthrough copy of the header (``set("MSH-2", msg["MSH-2"])``) still works."""
    m = Message.parse(ADT)
    before = m.encode()
    m.set("MSH-1", m["MSH-1"] or "")
    m.set_data("MSH-2", m["MSH-2"] or "")
    assert m.encode() == before


@pytest.mark.parametrize(
    ("raw", "path", "occurrence"),
    [
        (_BATCH, "BHS-1", 1),
        (_BATCH, "BHS-2", 1),
        (_BATCH, "MSH-2", 1),
        ("FHS|^~\\&|A\r" + _BATCH, "FHS-2", 1),
        ("FHS|^~\\&|A\r" + _BATCH, "BHS-1", 1),
        (_BATCH + "MSH|^~\\&|A|B\rPID|2\r", "MSH-2", 2),
    ],
)
def test_a_batch_header_delimiter_write_is_refused(raw: str, path: str, occurrence: int) -> None:
    """BHS and FHS fields 1 and 2 hold the delimiters the whole batch or file is split on, and an
    inner MSH-1 or MSH-2, at any occurrence, that differed from them would contradict its body."""
    m = Message.parse(raw)
    before = m.encode()
    with pytest.raises(ValueError, match="holds the message's delimiters"):
        m.set(path, "#", occurrence=occurrence)
    with pytest.raises(ValueError, match="holds the message's delimiters"):
        m.add_repetition(path, "x", occurrence=occurrence)
    assert m.encode() == before


@pytest.mark.parametrize("header", ["BHS", "FHS"])
def test_add_segment_refuses_a_header_segment(header: str) -> None:
    """A split line numbers a header's delimiter fields as MSH-3 onward, so it would encode as a
    garbled line; it is refused as a second MSH is."""
    m = Message.parse(ADT)
    before = m.encode()
    with pytest.raises(ValueError, match=f"refusing to add a {header} header segment"):
        m.add_segment(f"{header}|^~\\&|Z")
    assert m.encode() == before


# --- reads and writes use the delimiters the parser read (BACKLOG #5972) ------

#: Messages the parser accepts whose delimiters do not come from four MSH-2 characters: a short
#: MSH-2 (the parser fills the missing ones as ``^ ~ \\ &``), and a BHS- or FHS-led message with
#: no MSH, whose separators come from the batch or file header.
_PARSER_FILLED = {
    "short-msh-2": "MSH|^~|A|B|C|D|20260101||ADT^A01|M1|P|2.5\rPID|1||111^^^X~222^^^Y||DOE^JANE\r",
    "bhs-led": "BHS|^~\\&|A|B\rPID|1||111^^^X~222^^^Y||DOE^JANE\r",
    "fhs-led": "FHS|^~\\&|A|B\rPID|1||111^^^X~222^^^Y||DOE^JANE\r",
}


@pytest.mark.parametrize("raw", list(_PARSER_FILLED.values()), ids=list(_PARSER_FILLED))
def test_a_read_uses_the_delimiters_the_parser_read(raw: str) -> None:
    """BACKLOG #5972: every ``Message`` read used to raise on these, though the parser had already
    split them and ``Peek.field`` (the Router's read) read them. The two reads now agree."""
    m = Message.parse(raw)
    assert m._encoding_chars() == ("|", "^", "~", "\\", "&")
    assert m["PID-3.1"] == "111"
    assert m.repetitions("PID-3.1") == ["111", "222"]
    assert m.field("PID-3", repetition=2) == "222^^^Y"
    assert m["PID-5.2"] == "JANE"
    if raw.startswith("MSH"):
        assert Peek.parse(raw).field("PID-3.1") == m["PID-3.1"]


@pytest.mark.parametrize("raw", list(_PARSER_FILLED.values()), ids=list(_PARSER_FILLED))
def test_a_write_uses_the_delimiters_the_parser_read(raw: str) -> None:
    """A component write escapes by the delimiters every line is split on, so it round-trips."""
    m = Message.parse(raw)
    m.set("PID-5.1", "O^Brien&Co")
    m.add_repetition("PID-3", "333^^^Z")
    m.add_segment("NTE|1||note")
    again = Message.parse(m.encode())
    assert again["PID-5.1"] == "O^Brien&Co"
    assert again["PID-5.2"] == "JANE"
    assert again.repetitions("PID-3.1") == ["111", "222", "333"]
    assert again["NTE-3"] == "note"


@pytest.mark.parametrize(
    ("raw", "header"),
    [
        (_PARSER_FILLED["short-msh-2"], "MSH"),
        (_PARSER_FILLED["bhs-led"], "BHS"),
        (_PARSER_FILLED["fhs-led"], "FHS"),
    ],
)
def test_a_parser_filled_header_still_refuses_a_delimiter_change(raw: str, header: str) -> None:
    """The write half of BACKLOG #5972 holds on these too: fields 1 and 2 of the leading header
    take only what they already read, and a passthrough copy is still accepted."""
    m = Message.parse(raw)
    before = m.encode()
    with pytest.raises(ValueError, match="holds the message's delimiters"):
        m.set(f"{header}-1", "#")
    with pytest.raises(ValueError, match="holds the message's delimiters"):
        m.set(f"{header}-2", "#~\\&")
    m.set(f"{header}-2", m[f"{header}-2"] or "")
    assert m.encode() == before


def test_an_inner_msh_naming_other_delimiters_does_not_steer_a_write() -> None:
    """A batch is split on its first line's delimiters, so a write escapes by those, not by an
    inner MSH-2 that names ``#`` as the component separator: escaping by the MSH let a ``^`` in
    the value through raw, where the split read it as structure (BACKLOG #5972)."""
    m = Message.parse("BHS|^~\\&|A\rMSH|#~\\&|A|B\rPID|1||X^Y\r")
    assert m["PID-3.1"] == "X"
    m.set("PID-3.1", "A^B")
    again = Message.parse(m.encode())
    assert again["PID-3.1"] == "A^B"
    assert again["PID-3.2"] == "Y"


def test_a_filled_default_that_is_already_a_separator_is_refused_at_parse() -> None:
    """A short MSH-2 whose filled default is already another separator would make two structures
    one character, so a component join would read back as a field or a repetition. The parse
    refuses it, at the listener's ``Peek.parse`` too (BACKLOG #5972)."""
    for raw in (
        "MSH^^A^B^C^D^20260101^^ADT^A01^M1^P^2.5\rPID^1^^111^^DOE\r",
        "MSH|~|A|B\rPID|1||111\r",
        "MSH|^~&|A|B\rPID|1||111\r",
    ):
        with pytest.raises(HL7PeekError, match="a default filled in for one"):
            Message.parse(raw)
        with pytest.raises(HL7PeekError, match="a default filled in for one"):
            Peek.parse(raw)
    # The control: a short MSH-2 whose filled defaults are new characters still parses.
    assert Message.parse(_PARSER_FILLED["short-msh-2"])["PID-3.1"] == "111"


def test_a_short_msh_2_may_be_completed_to_the_characters_the_parser_filled() -> None:
    """The header can be made to declare the delimiters the body is written in; any other
    completion would move one, and stays refused."""
    m = Message.parse(_PARSER_FILLED["short-msh-2"])
    with pytest.raises(ValueError, match="holds the message's delimiters"):
        m.set("MSH-2", "^~#&")
    m.set("MSH-2", "^~\\&")
    again = Message.parse(m.encode())
    assert again["MSH-2"] == "^~\\&"
    assert again.repetitions("PID-3.1") == ["111", "222"]


@pytest.mark.parametrize("header", ["BHS", "FHS"])
def test_the_leading_batch_header_cannot_be_deleted(header: str) -> None:
    """Every line is read and written in the leading header's delimiters, so deleting it would
    leave the message led by a line that names others (BACKLOG #5972). A later one may go."""
    m = Message.parse(f"{header}|#~\\&|A\rMSH|^~\\&|A|B\rPID|1||X#Y\r")
    before = m.encode()
    with pytest.raises(ValueError, match=f"refusing to delete the {header} header"):
        m.delete_segments(header)
    assert m.encode() == before
    batch = Message.parse("FHS|^~\\&|A\rBHS|^~\\&|A\rMSH|^~\\&|A|B\rPID|1\r")
    assert batch.delete_segments("BHS") == 1


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
            m.field("OBX-5", **bad)
        with pytest.raises(ValueError):
            m.set("OBX-5", "x", **bad)


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


def test_add_segment_bare_id_is_settable() -> None:
    # Regression: a bare segment id (no field separator) must graft a SETTABLE segment. A fieldless
    # graft would be no occurrence at all (BACKLOG #5917), so add_segment normalizes it to "ZAL|".
    m = Message.parse(ORU)
    m.add_segment("ZAL")  # bare id, no fields
    assert m.count_segments("ZAL") == 1
    m.set("ZAL-2", "hello")
    assert m.field("ZAL-2") == "hello"
    assert Message.parse(m.encode()).field("ZAL-2") == "hello"
    # A bare id is equivalent to the trailing-separator form.
    m2 = Message.parse(ORU)
    m2.add_segment("ZAL|")
    m2.set("ZAL-2", "hello")
    assert m.encode() == m2.encode()


# A fieldless bare ``PID`` line (no field separator) directly before a populated one (BACKLOG #5917).
# Message skips a fieldless line for its occurrence-addressed reads, presence check, count and
# writes, as Peek does, so a planted bare ``PID`` cannot make a default-occurrence write land on a
# different segment from the one Peek and Message read.
_MSH = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1|P|2.5.1\r"
BARE_THEN_POPULATED = _MSH + "PID\rPID|1||X^Y~Q||DOE^JANE\r"


def _pid_lines(m: Message) -> list[str]:
    return [line for line in m.encode().split("\r") if line.startswith("PID")]


def test_a_fieldless_line_is_not_an_occurrence() -> None:
    m = Message.parse(BARE_THEN_POPULATED)
    assert Peek.parse(BARE_THEN_POPULATED).field("PID-5") == "DOE^JANE"
    assert m.count_segments("PID") == 1
    assert m.field("PID-3") == "X^Y~Q"
    assert m.field("PID-5") == "DOE^JANE"
    assert m.field("PID-3", occurrence=2) is None
    assert m.repetitions("PID-3") == ["X^Y", "Q"]
    # segments() stays positional: it lists every line, the fieldless one included, as Peek's does.
    assert m.segments() == ["MSH", "PID", "PID"]
    assert Peek.parse(BARE_THEN_POPULATED).segments() == m.segments()


def test_a_split_fieldless_line_is_still_not_an_occurrence() -> None:
    # The other tests reach _is_fieldless's lazy-raw branch; split every line first so its
    # split-fields branch is pinned on the count, read and write paths too.
    m = Message.parse(BARE_THEN_POPULATED)
    for index in range(len(m.segments())):
        _builtin_hl7._ensure_split(m._m, index)
    assert m.count_segments("PID") == 1
    assert m.field("PID-5") == "DOE^JANE"
    m.set("PID-5", "")
    assert _pid_lines(m) == ["PID", "PID|1||X^Y~Q||"]


@pytest.mark.parametrize(
    ("label", "op", "populated_after"),
    [
        ("whole-field scrub", lambda m: m.set("PID-5", ""), "PID|1||X^Y~Q||"),
        ("whole-field", lambda m: m.set("PID-3", "NEW"), "PID|1||NEW||DOE^JANE"),
        ("component", lambda m: m.set("PID-3.2", "NEW"), "PID|1||X^NEW~Q||DOE^JANE"),
        ("subcomponent", lambda m: m.set("PID-3.1.2", "S"), "PID|1||X&S^Y~Q||DOE^JANE"),
        ("repetition", lambda m: m.set("PID-3", "Z", repetition=2), "PID|1||X^Y~Z||DOE^JANE"),
        ("set-data", lambda m: m.set_data("PID-5", "A^B"), "PID|1||X^Y~Q||A\\S\\B"),
        ("add-repetition", lambda m: m.add_repetition("PID-3", "R"), "PID|1||X^Y~Q~R||DOE^JANE"),
    ],
)
def test_an_occurrence_one_write_skips_a_fieldless_line(
    label: str, op: Callable[[Message], None], populated_after: str
) -> None:
    m = Message.parse(BARE_THEN_POPULATED)
    op(m)
    # The bare line is untouched (no empty field copied over the populated PID), and the write
    # landed on the populated PID, the one Peek also calls occurrence 1.
    assert _pid_lines(m) == ["PID", populated_after], label
    reparsed = Message.parse(m.encode())
    peek = Peek.parse(m.encode())
    for path in ("PID-1", "PID-3", "PID-5"):
        assert peek.field(path) == reparsed.field(path), (label, path)


def test_message_and_peek_number_occurrences_alike_around_fieldless_lines() -> None:
    # Peek reads occurrence 1 only; the occurrence-addressed Peek path is extract_field, so compare
    # Message against it at every occurrence, before and after a write.
    raw = _MSH + "OBX\rOBX|1|ST|A\rOBX\rOBX\rOBX|2|ST|B\r"
    m = Message.parse(raw)
    assert Peek.parse(raw).field("OBX-3") == m.field("OBX-3") == "A"
    assert m.count_segments("OBX") == 2

    def peek_at(message: Message, occurrence: int) -> str | None:
        parsed = _builtin_hl7.parse(message.encode())
        return _builtin_hl7.extract_field(parsed, "OBX", 3, None, None, occurrence=occurrence)

    assert [m.field("OBX-3", occurrence=o) for o in (1, 2, 3)] == ["A", "B", None]
    assert [peek_at(m, o) for o in (1, 2, 3)] == ["A", "B", None]
    m.set("OBX-3", "second", occurrence=2)
    assert peek_at(m, 2) == m.field("OBX-3", occurrence=2) == "second"
    assert _builtin_hl7.segment_ids(_builtin_hl7.parse(m.encode())).count("OBX") == 5
    with pytest.raises(KeyError, match="occurrence 3"):
        m.set("OBX-3", "x", occurrence=3)


def test_a_lone_fieldless_line_is_an_absent_segment() -> None:
    # A fieldless line is not an occurrence, so a lone one reads, counts and writes as an absent
    # segment: None, 0, and the normal missing-segment KeyError. delete_segments still removes it.
    m = Message.parse(_MSH + "PID\r")
    assert m.count_segments("PID") == 0
    assert m.field("PID-3") is None
    with pytest.raises(KeyError, match="cannot set absent segment 'PID'"):
        m.set("PID-3", "NEW")
    with pytest.raises(KeyError, match="cannot set absent segment 'PID'"):
        m.set_data("PID-3", "NEW")
    with pytest.raises(KeyError, match="cannot add a repetition to absent segment 'PID'"):
        m.add_repetition("PID-3", "NEW")
    assert m.delete_segments("PID") == 1
    assert m.segments() == ["MSH"]


def test_delete_segments_removes_a_fieldless_line() -> None:
    m = Message.parse(BARE_THEN_POPULATED)
    assert m.delete_segments("PID") == 2
    assert m.segments() == ["MSH"]


def test_groups_stay_positional_and_number_members_as_message_does() -> None:
    # A fieldless OBR still opens a group (as it opens a split_by_obr part), so a group edit never
    # reaches past it into the next order; a fieldless OBX is no member occurrence, so a group read
    # translates to the occurrence Message.field uses.
    raw = _MSH + "OBR|1\rOBX|1|ST|A\rOBR\rOBX\rOBX|2|ST|B\rOBR|2\rOBX|3|ST|C\r"
    m = Message.parse(raw)
    groups = m.groups("OBR")
    assert [g.segment_ids() for g in groups] == [
        ["OBR", "OBX"],
        ["OBR", "OBX", "OBX"],
        ["OBR", "OBX"],
    ]
    assert groups[1].field("OBR-1") is None
    assert groups[1].count("OBX") == 1
    assert groups[1].field("OBX-3") == "B"
    assert groups[2].field("OBR-1") == "2" and groups[2].field("OBX-3") == "C"
    groups[0].rebuild(["OBX|1|ST|NEW"])
    assert m.encode().split("\r")[1:-1] == [
        "OBR|1",
        "OBX|1|ST|NEW",
        "OBR",
        "OBX",
        "OBX|2|ST|B",
        "OBR|2",
        "OBX|3|ST|C",
    ]


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


class _ReadOnRemoveLazy(dict[int, str]):
    """A ``_lazy`` map that runs a reader right after an entry leaves it, the instant a reader on
    another thread sharing a :meth:`Message.copy` tree could land in, on a GIL build or a
    free-threaded one (BACKLOG #5801)."""

    def __init__(self, msg: _builtin_hl7.ParsedMessage, seen: list[str]) -> None:
        super().__init__(msg["_lazy"])
        self._msg = msg
        self._seen = seen

    def _read(self, key: int) -> None:
        self._seen.append(_builtin_hl7._encode_segment(self._msg, key, self._msg["seps"]))

    def pop(self, key: int, *default: object) -> object:  # type: ignore[override]
        present = key in self
        value = super().pop(key, *default)
        if present:
            self._read(key)
        return value


def test_lazy_split_stores_fields_before_dropping_the_raw_line() -> None:
    # The lazy split must never leave a moment where the raw line is gone and the fields are not yet
    # stored: a reader of a shared copy there would encode PID as its bare id, its fields dropped.
    m = Message.parse(ADT)
    clone = m.copy()  # shares the backing tree until a write
    tree = clone._m
    seen: list[str] = []
    tree["_lazy"] = _ReadOnRemoveLazy(tree, seen)
    pid = _builtin_hl7.segment_index(tree, "PID", 1)
    assert pid is not None

    assert m["PID-5.1"] == "DOE"  # the first touch splits PID in the shared tree

    assert seen == ["PID|1||100^^^HOSP^MR||DOE^JANE^Q||19800101|F"]
    assert pid not in tree["_lazy"]
    tree["raw"] = None  # drop parse's cached text, so the encode is rebuilt from the split fields
    assert clone.encode() == ADT


class _SplitDuringCopySegments(list[_builtin_hl7.Segment]):
    """A ``segments`` list whose deepcopy lets a lazy split of ``seg_index`` run right after it is
    copied: a reader on another thread finishing its split in the middle of a copy-on-write copy."""

    def __init__(self, msg: _builtin_hl7.ParsedMessage, seg_index: int) -> None:
        super().__init__(msg["segments"])
        self._msg = msg
        self._seg_index = seg_index

    def __deepcopy__(self, memo: dict[int, object]) -> list[_builtin_hl7.Segment]:
        copied = copy.deepcopy(list(self), memo)
        _builtin_hl7._ensure_split(self._msg, self._seg_index)
        return copied


def test_a_split_during_the_copy_on_write_deepcopy_keeps_the_segment() -> None:
    # The copy-on-write copy (_builtin_hl7.clone) reads _lazy first. Were segments read before it, a
    # split landing between the two would leave the private copy with neither the raw line nor the
    # fields, and it would encode PID as its bare id (BACKLOG #5801).
    m = Message.parse(ADT)
    clone = m.copy()
    tree = m._m
    pid = _builtin_hl7.segment_index(tree, "PID", 1)
    assert pid is not None and pid in tree["_lazy"]
    tree["segments"] = _SplitDuringCopySegments(tree, pid)

    clone.set("PID-8", "M")  # the write takes the private deepcopy

    assert pid not in tree["_lazy"]  # the split did run in the middle of the copy
    assert clone["PID-5.1"] == "DOE"
    assert clone.encode() == ADT.replace("19800101|F", "19800101|M")
    tree["raw"] = None  # rebuild the original from its split fields, not parse's cached text
    assert m.encode() == ADT


class _SplitWhenCopied(str):
    """A raw line whose deepcopy runs a lazy split of another segment: a reader on another thread
    popping ``_lazy`` while a copy-on-write copy is walking it. clone() never deep-copies a raw
    line, so on the fixed code the hook does not fire; the test guards against a return to
    ``copy.deepcopy`` of the tree, and the never-walks test below covers any other walk."""

    msg: _builtin_hl7.ParsedMessage
    other: int

    def __deepcopy__(self, memo: dict[int, object]) -> str:
        _builtin_hl7._ensure_split(self.msg, self.other)
        return str(self)


def test_a_split_while_the_copy_walks_lazy_does_not_raise() -> None:
    # Iterating _lazy while another thread's split pops an entry raised RuntimeError ("dictionary
    # changed size during iteration") from copy.deepcopy (BACKLOG #5801, added item 1).
    m = Message.parse(ADT)
    clone = m.copy()
    tree = m._m
    pid = _builtin_hl7.segment_index(tree, "PID", 1)
    assert pid is not None and pid in tree["_lazy"]
    evn = pid - 1
    assert evn in tree["_lazy"]
    hook = _SplitWhenCopied(tree["_lazy"][evn])
    hook.msg, hook.other = tree, pid
    tree["_lazy"][evn] = hook

    clone.set("PID-8", "M")  # the write takes the private copy

    assert clone["PID-5.1"] == "DOE"
    assert clone.encode() == ADT.replace("19800101|F", "19800101|M")
    tree["raw"] = None
    assert m.encode() == ADT


class _SplitOnWalkLazy(dict[int, str]):
    """A ``_lazy`` map that splits another segment the moment Python code walks its ``items()`` (as
    ``copy.deepcopy`` and a comprehension over it do), as a reader on another thread could.
    ``dict.copy`` runs in C and does not call it. ``__iter__`` is left alone on purpose: overriding
    it would send ``dict.copy`` down its generic path, which a real ``_lazy`` never takes."""

    def __init__(self, msg: _builtin_hl7.ParsedMessage, other: int) -> None:
        super().__init__(msg["_lazy"])
        self._msg = msg
        self._other = other

    def _split(self) -> None:
        _builtin_hl7._ensure_split(self._msg, self._other)

    def items(self) -> ItemsView[int, str]:  # type: ignore[override]
        self._split()
        return super().items()


def test_the_copy_on_write_copy_never_walks_the_shared_lazy_map() -> None:
    # Any Python-level walk of a shared _lazy (a deepcopy, a comprehension) can meet a concurrent
    # split's pop; the copy must take it in one C call instead (BACKLOG #5801, added item 1).
    m = Message.parse(ADT)
    clone = m.copy()
    tree = m._m
    pid = _builtin_hl7.segment_index(tree, "PID", 1)
    assert pid is not None and pid in tree["_lazy"]
    tree["_lazy"] = _SplitOnWalkLazy(tree, pid)

    clone.set("PID-8", "M")  # the write takes the private copy

    assert pid in tree["_lazy"]  # no walk ran, so no split ran
    assert clone.encode() == ADT.replace("19800101|F", "19800101|M")


@pytest.mark.parametrize("copier", [copy.copy, copy.deepcopy], ids=["copy", "deepcopy"])
def test_the_copy_module_takes_the_copy_on_write_path(copier: Callable[[Message], Message]) -> None:
    m = Message.parse(ADT)
    tree = m._m
    pid = _builtin_hl7.segment_index(tree, "PID", 1)
    assert pid is not None
    tree["_lazy"] = _SplitOnWalkLazy(tree, pid)

    other = copier(m)
    other.set("PID-8", "M")

    assert pid in tree["_lazy"]  # the shared map was never walked
    assert m["PID-8"] == "F"  # the write did not reach the original
    assert other["PID-8"] == "M"


class _TaggedMessage(Message):
    tag: str


def test_a_deep_copy_shares_nothing_and_leaves_the_source_unflagged() -> None:
    m = _TaggedMessage(Message.parse(ADT)._m)
    m.tag = "t"
    deep = copy.deepcopy(m)
    assert m._shared is False and deep._shared is False
    assert deep._m is not m._m and deep._m["segments"] is not m._m["segments"]
    assert type(deep) is _TaggedMessage and deep.tag == "t"
    m.set("PID-8", "M")  # the source writes in place, with nothing shared
    assert deep["PID-8"] == "F"
    shallow = copy.copy(m)
    assert type(shallow) is _TaggedMessage and m._shared and shallow._shared
