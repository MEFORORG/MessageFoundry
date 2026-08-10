# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""BACKLOG #1089 — an HL7 field path index below 1 must be REFUSED, not wrapped around.

``parsing/peek.py::_PATH_RE`` matches ``\\d+`` for every index, so ``PID-5.0`` parsed with
``comp=0``; every consumer then indexes ``x[n - 1]``, which for ``0`` is Python's ``x[-1]`` — the
LAST part. Measured against the pre-guard tree on 2026-08-10 with the exact ``RAW`` below:

    Peek.field("PID-5.0")           -> "DOE"                     (a component nobody asked for)
    Message.field("PID-5.0")        -> "L"                       (a DIFFERENT wrong answer)
    Message.set("PID-5.0", v)       -> PID-5 becomes "DOE^JANE^Q^^^^PWNED"
    Message.set("PID-5.1.0", v)     -> PID-5 becomes "SUBPWN^JANE^Q^^^^L"
    Message.set("PID-0", "XXX")     -> the ENCODED message carries "XXX|1||MRN123..." — the segment
                                       id itself was rewritten, so a receiver sees a segment that
                                       does not exist

None of those raised. The write cases are the ones that matter: a read returning the wrong component
is visible to a careful operator, a write that silently replaces one is not, and the message
delivers looking successful with no exception, no ``ERROR`` disposition and no dead-letter.

The WRITE arms therefore assert two things — the call raises, **and** the message is byte-identical
afterwards. A guard that raised after mutating would pass the first assertion alone.

``parsing/x12/message.py::_parse_path`` has had this guard since it shipped; the HL7 side, which is
the default content type, had neither the guard nor a test. Its twin
(``test_x12_parsing.py::test_message_invalid_paths_rejected``) covers only the read path.
"""

from __future__ import annotations

import pytest

from messagefoundry.parsing.message import Message
from messagefoundry.parsing.peek import HL7PeekError, Peek, parse_path
from messagefoundry.store.content_search import ContentSearchError, SearchTarget, make_spec

RAW = (
    "MSH|^~\\&|SEND|FAC|RECV|RFAC|20260101120000||ADT^A01|MSGID001|P|2.5.1\r"
    "PID|1||MRN123^^^FAC^MR||DOE^JANE^Q^^^^L||19800101|F\r"
)

# Every shape the regex admits with an index below 1. "00"/"000" are here because the guard must
# compare the PARSED INTEGER, not the digit text — a `!= "0"` check would let "00" straight through.
BELOW_ONE = [
    "PID-0",  # field 0 — python-hl7's segment-id slot; a write here renames the segment
    "PID-00",
    "PID-5.0",  # component 0 — the filed case
    "PID-5.00",
    "PID-5.1.0",  # subcomponent 0
    "MSH-0",
    "MSH-9.0",
]

# The guard must not over-reject: these are ordinary 1-based paths and stay valid.
VALID = ["PID-5", "PID-5.1", "PID-5.1.1", "MSH-9.1", "PID-10"]


@pytest.mark.parametrize("path", BELOW_ONE)
def test_parse_path_rejects_index_below_one(path: str) -> None:
    with pytest.raises(HL7PeekError, match="1-based"):
        parse_path(path)


@pytest.mark.parametrize("path", VALID)
def test_parse_path_still_accepts_one_based(path: str) -> None:
    seg, fld, comp, sub = parse_path(path)
    assert seg and fld >= 1
    assert comp is None or comp >= 1
    assert sub is None or sub >= 1


# --- read path ---------------------------------------------------------------


@pytest.mark.parametrize("path", BELOW_ONE)
def test_peek_field_read_rejects_index_below_one(path: str) -> None:
    peek = Peek.parse(RAW)
    with pytest.raises(HL7PeekError, match="1-based"):
        peek.field(path)


@pytest.mark.parametrize("path", BELOW_ONE)
def test_message_field_read_rejects_index_below_one(path: str) -> None:
    msg = Message.parse(RAW)
    with pytest.raises(HL7PeekError, match="1-based"):
        msg.field(path)


@pytest.mark.parametrize("path", BELOW_ONE)
def test_message_repetitions_read_rejects_index_below_one(path: str) -> None:
    msg = Message.parse(RAW)
    with pytest.raises(HL7PeekError, match="1-based"):
        msg.repetitions(path)


def test_read_of_a_valid_path_is_unchanged() -> None:
    """Positive control for the read arms: the guard did not break ordinary component access."""
    peek = Peek.parse(RAW)
    assert peek.field("PID-5") == "DOE^JANE^Q^^^^L"
    assert peek.field("PID-5.1") == "DOE"
    assert Message.parse(RAW).field("PID-5.2") == "JANE"


# --- write path (the one that corrupts data) ---------------------------------


@pytest.mark.parametrize("path", BELOW_ONE)
def test_message_set_rejects_index_below_one_and_leaves_the_message_intact(path: str) -> None:
    msg = Message.parse(RAW)
    before = msg.encode()
    with pytest.raises(HL7PeekError, match="1-based"):
        msg.set(path, "PWNED")
    assert msg.encode() == before, (
        f"set({path!r}) raised but still mutated the message — the whole point of the guard is that"
        " nothing is written"
    )
    assert "PWNED" not in msg.encode()


@pytest.mark.parametrize("path", BELOW_ONE)
def test_message_setitem_rejects_index_below_one(path: str) -> None:
    msg = Message.parse(RAW)
    before = msg.encode()
    with pytest.raises(HL7PeekError, match="1-based"):
        msg[path] = "PWNED"
    assert msg.encode() == before


@pytest.mark.parametrize("path", ["PID-0", "PID-00", "MSH-0"])
def test_message_add_repetition_rejects_field_index_below_one(path: str) -> None:
    msg = Message.parse(RAW)
    before = msg.encode()
    with pytest.raises(HL7PeekError, match="1-based"):
        msg.add_repetition(path, "PWNED")
    assert msg.encode() == before


def test_segment_id_is_not_rewritable_through_field_zero() -> None:
    """The sharpest pre-guard case: ``set("PID-0", ...)`` rewrote the SEGMENT ID in the encoded
    output, so the delivered message carried a segment the receiver has no definition for."""
    msg = Message.parse(RAW)
    with pytest.raises(HL7PeekError, match="1-based"):
        msg.set("PID-0", "XXX")
    assert "\rPID|" in msg.encode()
    assert "XXX" not in msg.encode()


def test_write_of_a_valid_path_still_works() -> None:
    """Positive control for the write arms: the guard did not break ordinary component writes."""
    msg = Message.parse(RAW)
    msg.set("PID-5.1", "SMITH")
    assert msg.field("PID-5") == "SMITH^JANE^Q^^^^L"


# --- the operator-facing surface ---------------------------------------------


@pytest.mark.parametrize("path", BELOW_ONE)
def test_content_search_field_path_rejects_index_below_one(path: str) -> None:
    """``api/app.py``'s ``field_path`` query parameter reaches ``parse_path`` through
    ``make_spec``, so the bad path can arrive from OUTSIDE, not only from a Handler author's typo.
    It must surface as the existing request error (a 4xx), not as a wrong-component match."""
    with pytest.raises(ContentSearchError, match="1-based"):
        make_spec(
            content=None, field_path=path, field_value=None, target=SearchTarget.RAW, scan_limit=10
        )
