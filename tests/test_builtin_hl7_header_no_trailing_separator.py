# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A header line with no field separator after its encoding characters (BACKLOG #2589, #2998).

HL7 lets a segment omit its trailing empty fields, so ``MSH|^~\\&`` and ``BHS|^~\\&`` are headers
holding field 1 and field 2 and nothing more. The built-in parser's ``find`` for the separator ending
field 2 returned ``-1`` on them: field 2 lost its last character, the whole line reappeared as field 3
onward, and a re-encode wrote the line out of shape. These pin the line read in shape: field 2 to the
end of the line, nothing after it, and a re-encode that gives the line back. Synthetic values only.
"""

from __future__ import annotations

import random
import tracemalloc

import pytest

from messagefoundry.parsing import _builtin_hl7
from messagefoundry.parsing._builtin_hl7 import message_escape_char
from messagefoundry.parsing.message import Message
from messagefoundry.parsing.peek import HL7PeekError, Peek

_MSH = "MSH|^~\\&|SND|SFAC|RCV|RFAC|20260101000000||ADT^A01|C1|P|2.5.1"
_PID = "PID|1||100^^^H^MR||DOE^JANE"


@pytest.mark.parametrize("trailing", ["", "|"], ids=["no-separator", "control-trailing-separator"])
def test_a_header_of_only_its_encoding_characters_reads_in_shape(trailing: str) -> None:
    """#2589: ``MSH|^~\\&`` read MSH-2 as ``^~\\`` and MSH-3 as ``MSH``, and every later field read
    raised from ``_encoding_chars``. ``MSH|^~\\&|`` is the control; both read the same."""
    msg = Message.parse(f"MSH|^~\\&{trailing}\r{_PID}")
    assert msg.field("MSH-1") == "|"
    assert msg.field("MSH-2") == "^~\\&"
    assert msg.field("MSH-3") is None
    assert msg.field("MSH-9") is None
    assert msg.field("PID-3.1") == "100"
    assert msg.field("PID-5.2") == "JANE"
    assert Peek.parse(f"MSH|^~\\&{trailing}\r{_PID}").field("PID-3.1") == "100"


def test_the_last_encoding_character_is_read_when_no_separator_follows() -> None:
    """The slice that dropped the last character also dropped a custom subcomponent separator, so
    the parser and ``Message``'s own MSH-2 read disagreed. Both, and the pre-parse escape read, now
    take every character to the end of the line."""
    raw = "MSH|^~!#\rPID|1||A#B"
    assert _builtin_hl7.separators(_builtin_hl7.parse(raw)) == ("|", "^", "~", "#", "!")
    assert message_escape_char(raw) == "!"
    msg = Message.parse(raw)
    assert msg.field("MSH-2") == "^~!#"
    assert msg.field("PID-3.1.2") == "B"


#: Header lines with fewer than two field separators, the shapes #2998 names, and their controls.
_SHORT_HEADERS = [
    "BHS|^~\\&",
    "FHS|^~\\&",
    "MSH|^~\\&",
    "BHS|SYNTHTEXT",
    "BHS|",
    "BHS|^~\\&|",  # control: one separator after the encoding characters
    "BHS|^~\\&|SND|SFAC",  # control: an ordinary header line
]

#: Every short line in both places, but for two: a leading ``MSH`` line is the message header (the
#: 'later' case covers it), and a leading ``BHS|`` is refused (the test after the round trip).
_ROUND_TRIP_CASES = [
    pytest.param(line, place, id=f"{place}-{line}")
    for line in _SHORT_HEADERS
    for place in ("later", "leading")
    if not (place == "leading" and (line.startswith("MSH") or line == "BHS|"))
]


@pytest.mark.parametrize(("line", "place"), _ROUND_TRIP_CASES)
def test_a_short_header_line_round_trips_through_parse_and_encode(line: str, place: str) -> None:
    """#2998 step 4. Setting a field elsewhere makes ``encode`` rebuild every eager line from its
    fields. Before the fix ``BHS|SYNTHTEXT`` came back as ``BHS|SYNTHTEX|BHS|SYNTHTEXT``."""
    lines = [_MSH, _PID, line] if place == "later" else [line, _MSH, _PID]
    msg = Message.parse("\r".join(lines))
    msg.set("PID-8", "F")
    out = msg.encode().split("\r")
    assert line in out
    assert msg.encode_raw_separators().split("\r") == out
    assert Message.parse(msg.encode()).encode() == msg.encode()


def test_a_leading_header_with_no_encoding_character_is_the_contract_error() -> None:
    """#2998 step 4's other outcome: a leading ``BHS|`` has nothing to read separators from."""
    with pytest.raises(HL7PeekError, match="too short to read its encoding characters"):
        Message.parse("\r".join(["BHS|", _MSH, _PID]))


@pytest.mark.parametrize("line", ["MSH|^~\\&", "MSH|^~\\&|"])
def test_the_delimiter_rewrite_keeps_a_later_header_line_in_shape(line: str) -> None:
    """The third header re-join, the outbound delimiter override, follows the same three-or-four
    entry split for a later MSH line: an unchanged delimiter set gives the line back. A BHS or FHS
    line is not covered here: that path writes it with its field separator doubled, on ``main``
    before this change too."""
    parsed = _builtin_hl7.parse("\r".join([_MSH, _PID, line]))
    assert line in _builtin_hl7.encode_with_separators(parsed, parsed["seps"]).split("\r")


#: Bodies whose first line ``strip`` would change: padded single lines, whitespace past the encoding
#: characters, a trailing ``\r`` run, and a normal multi-line message as the control. The last two
#: hold whitespace inside the head and data after it on the last line, pinning that the head is
#: trimmed only when nothing but whitespace follows it.
_ESCAPE_BODIES = [
    "MSH|^~!&|S\rPID|1\r",
    "MSH|^~!&|S\r",
    "MSH|^~!",
    " \t\rMSH|^~! \r",
    "MSH|^~ ",
    "MSH|^~ \r\n \r",
    "MSH|^~  \t\t\t\t\t\t",
    "MSH|^~\x1c\r\x1c",
    "MSH|^~! \rPID|1",
    "\x0bMSH|^~\\&\x0c",
    "MSH|^~!#ABCDEFGH   \r ",
    "MSH|^~  |S",
    "MSH|^~  X",
]


def _head_reference(body: str) -> str:
    return body.strip().split("\r", 1)[0][: _builtin_hl7._SEPARATOR_HEAD]


@pytest.mark.parametrize("body", _ESCAPE_BODIES)
def test_the_escape_read_takes_the_first_line_parse_takes(body: str) -> None:
    """The pre-parse escape read finds the first line in place. It must be the line ``parse`` takes
    through ``strip``, or the budget and the parser could disagree on the escape character."""
    assert _builtin_hl7._first_line_head(body) == _head_reference(body)
    assert message_escape_char(body) == _builtin_hl7.parse(body)["seps"][4]


def test_the_escape_read_matches_strip_over_random_bodies() -> None:
    """A seeded sweep of short bodies over header characters, separators and several kinds of
    whitespace, so a shape the list above misses still meets the reference."""
    rng = random.Random(2589)
    alphabet = "MSH|^~\\&!X \t\r\n\x0b\x0c\x1c\x85　"
    for _ in range(20_000):
        body = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 14)))
        assert _builtin_hl7._first_line_head(body) == _head_reference(body), repr(body)


@pytest.mark.parametrize("tail", ["\r", "\rPID|1\r"], ids=["single-line", "multi-line"])
def test_the_escape_read_copies_nothing_of_the_body(tail: str) -> None:
    """The pre-ACK escape read allocates a bounded amount, not a copy of a body ending in ``\\r``."""
    body = "MSH|^~!&|" + "A" * 2_000_000 + tail
    started_here = not tracemalloc.is_tracing()
    if started_here:
        tracemalloc.start()
    tracemalloc.reset_peak()
    before, _ = tracemalloc.get_traced_memory()
    try:
        assert message_escape_char(body) == "!"
        _, peak = tracemalloc.get_traced_memory()
    finally:
        if started_here:
            tracemalloc.stop()
    assert peak - before < 100_000
