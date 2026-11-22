# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A field-path search reads every segment occurrence and field repetition (BACKLOG #5883).

``row_matches`` read ``Peek.field``, which takes the first occurrence and the first repetition, so a
search would under-report a message whose value sits in a later ``OBX`` or a later ``PID-3``
repetition. ``_builtin_hl7.field_values`` has no parity oracle of its own, so these tables pin it to
``extract_field``'s semantics. Synthetic data only.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from types import FrameType
from typing import Any

import pytest

from messagefoundry.parsing import _builtin_hl7
from messagefoundry.parsing.peek import DEFAULT_MAX_SEGMENTS, Peek, parse_path
from messagefoundry.store.content_search import make_spec, row_matches
from messagefoundry.uploads import browse_messages

MSH = "MSH|^~\\&|S|F|R|RF|20260101||ORU^R01|MSG1|P|2.5.1"


def _body(*segments: str) -> str:
    return "\r".join((MSH, *segments)) + "\r"


def _values(raw: str, path: str) -> list[str]:
    seg, fld, comp, sub = parse_path(path)
    return list(_builtin_hl7.field_values(Peek.parse(raw).message, seg, fld, comp, sub))


def _matches(raw: str, path: str, value: str | None = None) -> bool:
    spec = make_spec(content=None, field_path=path, field_value=value)
    return row_matches(spec, raw=raw, summary=None)


# --- The defect, through row_matches ------------------------------------------------------------


@pytest.mark.parametrize(
    ("segments", "path", "value"),
    [
        (("OBX|1|ST|A||first", "OBX|2|ST|B||second"), "OBX-5", "second"),  # later occurrence
        (("PID|1||AAA^^^H~BBB^^^H",), "PID-3.1", "BBB"),  # later repetition
        (("OBX|1|ST|A||x~y", "OBX|2|ST|B||p~q"), "OBX-5.1", "q"),  # both at once
        (("PID|1||AAA~B^C",), "PID-3.2", "C"),  # the first repetition has no component 2
    ],
)
def test_a_value_past_the_first_occurrence_or_repetition_matches(
    segments: tuple[str, ...], path: str, value: str
) -> None:
    raw = _body(*segments)
    assert _matches(raw, path, value) is True
    assert _matches(raw, path, "NOT-THERE") is False  # control: the needle still discriminates


def test_presence_is_true_when_only_a_later_occurrence_holds_the_field() -> None:
    raw = _body("OBX|1|ST|A||", "OBX|2|ST|B||later")
    assert Peek.parse(raw).field("OBX-5") is None  # the first-only read this row widens
    assert _matches(raw, "OBX-5") is True


def test_presence_is_true_when_only_a_later_repetition_holds_the_component() -> None:
    raw = _body("PID|1||~BBB^X")
    assert Peek.parse(raw).field("PID-3.2") is None
    assert _matches(raw, "PID-3.2") is True


def test_presence_stays_false_when_no_occurrence_holds_the_field() -> None:
    assert _matches(_body("OBX|1|ST|A||", "OBX|2|ST|B||"), "OBX-5") is False
    assert _matches(_body("OBX|1|ST|A||x"), "ZZZ-1") is False


def test_a_whole_field_needle_may_still_span_the_repetition_delimiter() -> None:
    """A whole-field read is the structural text. Splitting it by repetition would lose this match,
    which the first-occurrence ``Peek.field`` read makes."""
    assert _matches(_body("PID|1||AAA~BBB"), "PID-3", "AAA~BBB") is True


@pytest.mark.parametrize("raw", ["not hl7", "", "   ", "PID|1||AAA"])
def test_a_body_peek_refuses_stays_no_match(raw: str) -> None:
    assert _matches(raw, "PID-3") is False


def test_a_none_raw_stays_no_match() -> None:
    assert (
        row_matches(
            make_spec(content=None, field_path="PID-3", field_value=None), raw=None, summary="x"
        )
        is False
    )


def test_the_upload_browse_path_sees_a_later_repetition() -> None:
    """``row_matches``' other caller, which runs on one already-authorized file."""
    data = (_body("PID|1||AAA~BBB") + _body("PID|1||CCC")).encode()
    spec = make_spec(content=None, field_path="PID-3.1", field_value="BBB")
    result = browse_messages(
        data, spec=spec, message_type=None, control_id=None, limit=10, offset=0
    )
    assert result.total_messages == 2  # control: the split saw both messages
    assert result.matched == 1


# --- field_values against extract_field's semantics --------------------------------------------


@pytest.mark.parametrize(
    ("segments", "path", "expected"),
    [
        # MSH numbering: MSH-1 and MSH-2 are the delimiters, read raw and never split.
        ((), "MSH-1", ["|"]),
        ((), "MSH-2", ["^~\\&"]),
        ((), "MSH-2.1", ["^~\\&"]),
        ((), "MSH-2.2", []),
        ((), "MSH-3", ["S"]),
        ((), "MSH-9.2", ["R01"]),
        # Repetitions: a whole-field read is one structural value per occurrence.
        (("PID|1||A~B",), "PID-3", ["A~B"]),
        (("PID|1||A~B",), "PID-3.1", ["A", "B"]),
        (("PID|1||A~~C",), "PID-3.1", ["A", "C"]),
        # Components, and a repetition too shallow for the path yields nothing rather than failing.
        (("PID|1||A^B~C^D",), "PID-3.2", ["B", "D"]),
        (("PID|1||A~C^D",), "PID-3.2", ["D"]),
        (("PID|1||A^B",), "PID-3.9", []),
        # Sub-components.
        (("PID|1||A&B^C~D&E",), "PID-3.1.2", ["B", "E"]),
        (("PID|1||A&B",), "PID-3.1", ["A"]),  # first-child descent
        (("PID|1||A^B",), "PID-3.1.2", []),  # past a leaf
        # Escapes: a leaf is unescaped, a whole-field read is not.
        (("PID|1||A\\T\\B~C\\S\\D",), "PID-3.1", ["A&B", "C^D"]),
        (("PID|1||A\\T\\B",), "PID-3", ["A\\T\\B"]),
        # Occurrences, in order; a bare fieldless line is not an occurrence.
        (("OBX|1|ST|A||x", "OBX|2|ST|B||y"), "OBX-5", ["x", "y"]),
        (("OBX", "OBX|2|ST|B||y"), "OBX-5", ["y"]),
        (("OBX|1", "OBX|2|ST|B||y"), "OBX-5", ["y"]),  # a short occurrence has no such field
    ],
)
def test_field_values_table(segments: tuple[str, ...], path: str, expected: list[str]) -> None:
    assert _values(_body(*segments), path) == expected


@pytest.mark.parametrize(
    ("segments", "path"),
    [
        ((), "MSH-1"),
        ((), "MSH-2"),
        ((), "MSH-2.1"),
        ((), "MSH-9"),
        ((), "MSH-9.1"),
        ((), "MSH-9.2"),
        (("PID|1||A^B&C~D",), "PID-3"),
        (("PID|1||A^B&C~D",), "PID-3.1"),
        (("PID|1||A^B&C~D",), "PID-3.2"),
        (("PID|1||A^B&C~D",), "PID-3.2.2"),
        (("PID|1||A\\T\\B^C",), "PID-3.1"),
        (("PID|1||A",), "PID-3.1.1"),
        (("OBX", "OBX|2|ST|B||y"), "OBX-5"),
    ],
)
def test_the_first_value_agrees_with_peek_field(segments: tuple[str, ...], path: str) -> None:
    """Whatever ``Peek.field`` reads, the walk yields first, so a widened search loses no match."""
    raw = _body(*segments)
    read = Peek.parse(raw).field(path)
    assert read is not None, "a case here must read a value, or the agreement is vacuous"
    assert _values(raw, path)[0] == read


# --- Where widening must not invent a match -----------------------------------------------------


@pytest.mark.parametrize(
    ("header", "field"),
    [
        ("MSH|~|S|F|R|RF|20260101", "AAA~BBB"),  # the default repetition is the declared component
        ("MSH|~~\\&|S|F|R|RF|20260101", "AAA~BBB"),  # declared the same
        ("MSH|^&\\&|S|F|R|RF|20260101", "AAA&BBB"),  # repetition and sub-component the same
    ],
)
def test_a_repetition_character_shared_with_another_separator_is_not_walked(
    header: str, field: str
) -> None:
    """Such a character does not mark a repetition, so ``BBB`` is not a second one's component 1."""
    raw = f"{header}\rPID|1||{field}\r"
    assert _values(raw, "PID-3.1") == [Peek.parse(raw).field("PID-3.1")]
    assert _matches(raw, "PID-3.1", "BBB") is False


def test_the_walk_stops_at_a_later_header_with_other_separators() -> None:
    """The parse splits every line on the first header's separators, so text past a header that
    declares others would be mis-split into values that header's message does not hold."""
    raw = _body("PID|1||Y", "MSH$^~\\&$OTHER$F$R", "PID|1||Z")
    assert _values(raw, "PID-3") == ["Y"]
    assert _matches(raw, "MSH-3", "F") is False
    assert _values(raw, "MSH-3") == ["S"]


def test_a_later_header_with_the_same_separators_does_not_stop_the_walk() -> None:
    raw = _body("PID|1||Y", MSH, "PID|1||Z")
    assert _values(raw, "PID-3") == ["Y", "Z"]


def test_a_first_occurrence_past_a_differing_header_is_still_read() -> None:
    """``Peek.field`` reads it, so stopping before it would lose that first-occurrence match."""
    raw = _body("MSH$^~\\&$OTHER", "PID|1||Y")
    assert Peek.parse(raw).field("PID-3") == "Y"
    assert _matches(raw, "PID-3", "Y") is True


@pytest.mark.parametrize(
    ("header", "field", "invented"),
    [
        ("MSH|^\\\\&|S|F", "A\\T\\B", "B"),  # repetition and escape are one character
        ("MSH|^\\|S|F", "A\\T\\B", "B"),  # the same, from the default escape
        ("MSH|^R\\&|S|F", "A\\R\\B", "B"),  # the repetition is a letter inside an escape
    ],
)
def test_a_split_through_an_escape_is_not_walked(header: str, field: str, invented: str) -> None:
    raw = f"{header}\rPID|1||{field}\r"
    assert _values(raw, "PID-3.1") == [Peek.parse(raw).field("PID-3.1")]
    assert _matches(raw, "PID-3.1", invented) is False


def test_a_balanced_escape_does_not_stop_the_repetition_walk() -> None:
    assert _values(_body("PID|1||A\\T\\B~C"), "PID-3.1") == ["A&B", "C"]


@pytest.mark.parametrize(
    ("header", "field"), [("MSH$^~\\&$OTHER", "Y~Z"), ("MSH$~^\\&$OTHER", "Y~Z")]
)
def test_past_a_differing_header_only_the_first_value_is_read(header: str, field: str) -> None:
    raw = _body(header, f"PID|1||{field}", "PID|1||W")
    assert _values(raw, "PID-3.1") == [Peek.parse(raw).field("PID-3.1")] == ["Y"]
    assert _matches(raw, "PID-3.1", "Z") is False
    assert _matches(raw, "PID-3.1", "W") is False


def test_a_short_first_occurrence_past_a_differing_header_reads_nothing_later() -> None:
    raw = _body("MSH$^~\\&$OTHER", "OBX|1", "OBX|2|ST|A||later")
    assert Peek.parse(raw).field("OBX-5") is None
    assert _values(raw, "OBX-5") == []


def test_empty_repetitions_are_not_split_into_a_retained_tree(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The nested split is built only for a non-empty repetition, never for the whole field."""
    real = _builtin_hl7._split_reps
    split: list[str] = []

    def spy(text: str, seps: tuple[str, str, str, str, str]) -> list[list[list[str]]]:
        split.append(text)
        return real(text, seps)

    raw = _body("OBX|1|ST|A||x", "OBX|2|ST|B||" + "~" * 1_000, "OBX|3|ST|C||y~~z")
    monkeypatch.setattr(_builtin_hl7, "_split_reps", spy)
    assert _values(raw, "OBX-5.1") == ["x", "y", "z"]
    assert split == ["x", "y", "z"]  # a whole-field tree would show its text with `~` here


@pytest.mark.parametrize(
    ("header", "field", "path", "value"),
    [
        ("MSH|^|S|F", "A^B~C^D", "PID-3.2", "D"),  # only the component separator is declared
        ("MSH|^|S|F", "A~B", "PID-3.1", "B"),
    ],
)
def test_an_undeclared_repetition_character_is_not_walked(
    header: str, field: str, path: str, value: str
) -> None:
    raw = f"{header}\rPID|1||{field}\r"
    assert _values(raw, path) == [Peek.parse(raw).field(path)]
    assert _matches(raw, path, value) is False


def test_later_occurrences_are_still_read_under_an_undeclared_repetition_character() -> None:
    raw = "MSH|^|S|F\rPID|1||A^B\rPID|1||C^D\r"
    assert _values(raw, "PID-3.2") == ["B", "D"]


@pytest.mark.parametrize("value", ["\\.fi\\", '""', "   ", "x"])
def test_later_presence_agrees_with_the_first_occurrence_test(value: str) -> None:
    """Each value is present later exactly when ``Peek.field`` calls it present as a first value.
    The trailing segment keeps a run of spaces from being stripped with the message's end."""
    as_first = _body(f"OBX|1|ST|A||{value}", "ZZZ|1")
    as_later = _body("OBX|1|ST|A||", f"OBX|2|ST|B||{value}", "ZZZ|1")
    assert _matches(as_later, "OBX-5") is (Peek.parse(as_first).field("OBX-5") is not None)


@pytest.mark.parametrize("later", ["~", "^", "&", "~~", "^~&", "&^~^"])
def test_a_later_delimiter_only_occurrence_is_not_present(later: str) -> None:
    raw = _body("OBX|1|ST|A||", f"OBX|2|ST|B||{later}")
    assert _matches(raw, "OBX-5") is False
    assert _matches(raw, "OBX-5", later) is False


@pytest.mark.parametrize("later", ["x", "~x", "^x", "x&", "\\T\\", "~\\"])
def test_a_later_occurrence_with_content_is_present(later: str) -> None:
    assert _matches(_body("OBX|1|ST|A||", f"OBX|2|ST|B||{later}"), "OBX-5") is True


@pytest.mark.parametrize("first", ["~", "^", "&", "~~", "^~&"])
def test_a_delimiter_only_first_occurrence_reads_as_peek_field_does(first: str) -> None:
    """``Peek.field`` reads this value as present, and the first occurrence's result does not move."""
    raw = _body(f"OBX|1|ST|A||{first}", "OBX|2|ST|B||")
    assert Peek.parse(raw).field("OBX-5") == first
    assert _matches(raw, "OBX-5") is True
    assert _matches(raw, "OBX-5", first) is True


def test_a_later_header_keeps_its_delimiter_fields() -> None:
    assert _values(_body("MSH|^~|S2"), "MSH-2") == ["^~\\&", "^~"]


def test_a_stray_escape_still_stops_the_repetition_walk() -> None:
    """Pins the open under-report the docstring states, so a change to it is a decision."""
    raw = _body("PID|1||AAA~BBB~C:\\DIR")
    assert _values(raw, "PID-3.1") == ["AAA"]
    assert _matches(raw, "PID-3.1", "BBB") is False


def test_a_header_like_line_still_stops_the_walk() -> None:
    """Pins the other open under-report the docstring states."""
    assert _values(_body("PID|1||Y", "BHSZ|note", "PID|1||Z"), "PID-3") == ["Y"]


def test_the_walk_leaves_no_component_cache_on_the_parsed_message() -> None:
    raw = _body("OBX|1|ST|A||x~y", "OBX|2|ST|B||p~q")
    message = Peek.parse(raw).message
    assert list(_builtin_hl7.field_values(message, "OBX", 5, 1, None)) == ["x", "y", "p", "q"]
    assert all(isinstance(s["fields"][5], str) for s in message["segments"][1:])


# --- Linear cost at the segment cap -------------------------------------------------------------


def _traced_lines(call: Callable[[], Any]) -> int:
    """How many lines of ``_builtin_hl7`` ``call`` executes: deterministic, unlike a clock."""
    count = 0
    target = _builtin_hl7.__file__

    def local(_frame: FrameType, event: str, _arg: Any) -> Any:
        nonlocal count
        if event == "line":
            count += 1
        return local

    def tracer(frame: FrameType, _event: str, _arg: Any) -> Any:
        return local if frame.f_code.co_filename == target else None

    previous = sys.gettrace()
    sys.settrace(tracer)
    try:
        call()
    finally:
        sys.settrace(previous)
    return count


def _walk_cost(raw: str, path: str) -> int:
    seg, fld, comp, sub = parse_path(path)
    message = Peek.parse(raw).message
    return _traced_lines(lambda: list(_builtin_hl7.field_values(message, seg, fld, comp, sub)))


def test_the_walk_is_linear_in_segments_up_to_the_cap() -> None:
    """A walk through ``extract_field(occurrence=n)`` rescans from the top for each n: quadratic,
    so doubling the segments would quadruple this count."""
    full = DEFAULT_MAX_SEGMENTS - 2  # the cap counts the MSH and the empty tail after the last \r
    half = full // 2
    at_cap = _body(*["OBX|1|ST|A||x~y"] * full)
    assert len(_values(at_cap, "OBX-5.1")) == 2 * full  # control: the body parsed and was walked
    one = _walk_cost(_body(*["OBX|1|ST|A||x~y"] * half), "OBX-5.1")
    two = _walk_cost(at_cap, "OBX-5.1")
    assert two / one < 2.5


def test_the_cost_instrument_can_see_a_quadratic_walk() -> None:
    """Control for the ratio above: the walk this helper avoids reads about 4x at double the size."""

    def rescanning_cost(segments: int) -> int:
        message = Peek.parse(_body(*["OBX|1|ST|A||x"] * segments)).message
        return _traced_lines(
            lambda: [
                _builtin_hl7.extract_field(message, "OBX", 5, 1, None, occurrence=n)
                for n in range(1, segments + 1)
            ]
        )

    assert rescanning_cost(400) / rescanning_cost(200) > 3.5


def test_the_walk_is_linear_in_repetitions() -> None:
    one = _walk_cost(_body("PID|1||" + "~".join(["A^B"] * 5_000)), "PID-3.2")
    two = _walk_cost(_body("PID|1||" + "~".join(["A^B"] * 10_000)), "PID-3.2")
    assert two / one < 2.5
