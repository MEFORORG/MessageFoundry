# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``encode_batch`` — BHS…BTS batch envelope encoder (BACKLOG #134 / ADR 0082).

The encode-side inverse of ``split_batch``: N MSH messages → one BHS…BTS envelope, framed from the
head member's own separators, deterministic (BHS-7/BHS-11 supplied by the caller — no clock), and
round-trippable back through ``split_batch``.
"""

from __future__ import annotations

import random
import tracemalloc

import pytest

from messagefoundry.parsing import encode_batch, split_batch
from messagefoundry.parsing.message import Message

M1 = "MSH|^~\\&|A|B|C|D|20260101010101||ADT^A01|MSG1|P|2.5.1\rPID|1||100||DOE^JOHN\r"
M2 = "MSH|^~\\&|A|B|C|D|20260101010102||ADT^A02|MSG2|P|2.5.1\rPID|1||200||ROE^JANE\r"
M3 = "MSH|^~\\&|A|B|C|D|20260101010103||ADT^A03|MSG3|P|2.5.1\r"


def test_wraps_n_messages_in_one_bhs_bts_envelope() -> None:
    env = encode_batch([M1, M2, M3], control_id="7", timestamp="20260101120000")
    segs = env.split("\r")
    assert segs[0].startswith("BHS|^~\\&")  # separators from the head member
    assert "BTS|3" in env  # BTS-1 == the framed count
    # exactly one BHS and one BTS
    assert env.count("\rBHS") == 0 and env.startswith("BHS")
    assert sum(1 for s in segs if s.startswith("BHS")) == 1
    assert sum(1 for s in segs if s.startswith("BTS")) == 1
    # all three members are present, in order, verbatim
    assert env.index("MSG1") < env.index("MSG2") < env.index("MSG3")


def test_bhs7_timestamp_and_bhs11_control_id_land_at_the_right_fields() -> None:
    env = encode_batch([M1], control_id="42", timestamp="20260101120000")
    bhs = env.split("\r")[0]
    fields = bhs.split("|")
    # fields[0]="BHS", fields[1]=encoding chars (BHS-2), BHS-1 is the separator itself.
    # So BHS-N is fields[N-1] for N>=2: BHS-7 -> fields[6], BHS-11 -> fields[10].
    assert fields[6] == "20260101120000"  # BHS-7 batch creation time
    assert fields[10] == "42"  # BHS-11 batch control id
    assert fields[2] == fields[3] == fields[4] == fields[5] == ""  # BHS-3..6 empty placeholders
    assert fields[7] == fields[8] == fields[9] == ""  # BHS-8..10 empty placeholders


def test_deterministic_same_inputs_same_bytes() -> None:
    a = encode_batch([M1, M2], control_id="5", timestamp="20260101120000")
    b = encode_batch([M1, M2], control_id="5", timestamp="20260101120000")
    assert a == b  # no clock; a re-run re-derives byte-identical output


def test_round_trips_through_split_batch() -> None:
    # split_batch drops the envelope and yields the members in order; the bodies must survive verbatim.
    env = encode_batch([M1, M2, M3], control_id="1", timestamp="20260101120000")
    members = split_batch(env)
    assert len(members) == 3
    assert [Message.parse(m).control_id for m in members] == ["MSG1", "MSG2", "MSG3"]
    # the PID survived on the multi-segment members
    assert "DOE^JOHN" in members[0] and "ROE^JANE" in members[1]


def test_custom_separators_are_read_from_the_head_never_hardcoded() -> None:
    # A feed whose field sep is '#' (not '|') must frame the BHS with ITS separators, not |^~\&.
    custom = "MSH#@~\\&#A#B#C#D#20260101##ADT@A01#MSGX#P#2.5.1\r"
    fs, comp, rep, esc, sub = Message.parse(custom)._encoding_chars()
    assert fs == "#"  # sanity: the primitive read the custom field separator
    env = encode_batch([custom], control_id="9", timestamp="20260101120000")
    bhs = env.split("\r")[0]
    assert bhs.startswith("BHS#@~\\&")  # BHS-1='#', BHS-2='@~\&' — from the member, not hardcoded
    assert "|" not in bhs  # the hardcoded default never leaks in
    # BHS-7/BHS-11 still land correctly under the custom field separator.
    fields = bhs.split("#")
    assert fields[6] == "20260101120000" and fields[10] == "9"


def test_empty_list_raises() -> None:
    with pytest.raises(ValueError, match="at least one message"):
        encode_batch([], control_id="1", timestamp="20260101120000")


def test_message_objects_and_strings_both_accepted() -> None:
    env = encode_batch([Message.parse(M1), M2], control_id="3", timestamp="20260101120000")
    assert "MSG1" in env and "MSG2" in env and "BTS|2" in env


# --- BACKLOG #5919: the head is read for MSH-1/MSH-2 alone, and no member is copied ---------------

_TS = "20260101120000"


def _no_parse(*_args: object, **_kwargs: object) -> Message:
    raise AssertionError("encode_batch parsed a member")


@pytest.mark.parametrize("head", [M1, "  \r\n" + M1, M1.replace("\r", "\n")])
def test_the_head_member_is_not_parsed(monkeypatch: pytest.MonkeyPatch, head: str) -> None:
    # Only MSH-1 and MSH-2 are needed, so a full parse of a large head is waste.
    monkeypatch.setattr(Message, "parse", staticmethod(_no_parse))
    env = encode_batch([head, M2], control_id="1", timestamp=_TS)
    assert env.startswith("BHS|^~\\&|")


def test_members_are_not_copied_before_the_join() -> None:
    # The envelope's own join is the one copy a member needs. A strip of each member and a CR
    # appended to the whole envelope each copied it again, multiplying peak memory.
    body = "OBX|1|ED|DOC||" + "A" * (4 * 1024 * 1024) + "\r"
    members: list[Message | str] = [
        f"MSH|^~\\&|A|B|C|D|{_TS}||ORU^R01|M{i}|P|2.5.1\r{body}" for i in range(3)
    ]
    total = sum(len(m) for m in members if isinstance(m, str))
    started_here = not tracemalloc.is_tracing()
    if started_here:
        tracemalloc.start()
    tracemalloc.reset_peak()
    before, _ = tracemalloc.get_traced_memory()
    try:
        env = encode_batch(members, control_id="1", timestamp=_TS)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        if started_here:
            tracemalloc.stop()
    assert len(env) > total  # positive control: the envelope holds every member
    # An ASCII str costs about one byte per character; one envelope is about `total` bytes.
    assert peak - before < 1.5 * total, peak - before


_Reading = tuple[str, str, str, str, str] | type[ValueError]


def _parser_reading(head: str) -> _Reading:
    try:
        return Message.parse(head)._encoding_chars()
    except ValueError:  # HL7PeekError is one
        return ValueError


def _batch_reading(head: str) -> _Reading:
    try:
        bhs = encode_batch([head], control_id="1", timestamp=_TS).split("\r", 1)[0]
    except ValueError:
        return ValueError
    return bhs[3], bhs[4], bhs[5], bhs[6], bhs[7]


@pytest.mark.parametrize(
    "head",
    [
        "  \r\n" + M1,  # leading whitespace, as the parser strips it
        M1.replace("\r", "\n"),  # LF line endings
        "MSH|^~\\&#|A|B|C|D|20260101||ADT^A01|MSG1|P|2.7\r",  # MSH-2 with a fifth char (v2.7)
        "MSH#@~\\&#A#B\r",  # custom delimiters
        "MSH|^~\\&",  # MSH-2 and nothing more
        "MSH|^~\\ \r",  # a trailing space the parser's strip removes, leaving MSH-2 short
        "MSH|^~\\\t",
        "MSH|^~\\ \rPID|1\r",  # the same space kept, as more follows it
        "MSH\r",
        "MSH|^~\r",
        "MSH|^~|A|B\r",
        "MSH|",
        "not an HL7 message",
        "\N{ZERO WIDTH NO-BREAK SPACE}" + M1,  # a byte order mark, which the parser refuses
        "BHS|^~\\&\rMSH#@~\\&#A#B\r",  # an envelope-led head, parsed as before
        "BHS|^~\\&\rPID|1\r",
    ],
)
def test_the_head_separators_match_the_parser(head: str) -> None:
    # The contract Message._encoding_chars kept: the separators it reads, or a refusal rather than
    # a guess.
    assert _batch_reading(head) == _parser_reading(head)


def test_a_malformed_later_line_is_not_the_separator_reads_to_refuse() -> None:
    # The one place the reading parts from a parse, by design: the parser refuses a later header
    # line too short to read, and finding it takes the whole-body scan BACKLOG #5919 removed. The
    # head's own separators are read, not guessed. On the delivery path the caller's parse of the
    # head for MSH-10 still refuses such a head before this runs.
    head = "MSH|^~\\&|A\rMSH"
    assert _parser_reading(head) is ValueError
    assert _batch_reading(head) == ("|", "^", "~", "\\", "&")


def test_the_head_separators_match_the_parser_over_random_heads() -> None:
    rng = random.Random(5919)
    alphabet = "MSH|^~\\&# \t\r\nA"
    for _ in range(5000):
        head = "MSH" + "".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 12)))
        assert _batch_reading(head) == _parser_reading(head), repr(head)


@pytest.mark.parametrize(
    ("member", "framed"),
    [
        ("MSH|^~\\&|A\rPID|1\r", "MSH|^~\\&|A\rPID|1\r"),
        ("MSH|^~\\&|A\rPID|1", "MSH|^~\\&|A\rPID|1\r"),  # no trailing CR
        ("MSH|^~\\&|A\rPID|1\r\r\r", "MSH|^~\\&|A\rPID|1\r"),  # several trailing CRs
        ("MSH|^~\\&|A\r\nPID|1\n", "MSH|^~\\&|A\rPID|1\r"),  # LF line endings
        ("\r\rMSH|^~\\&|A\r", "MSH|^~\\&|A\r"),  # leading CRs
    ],
)
def test_each_member_is_framed_with_one_trailing_cr(member: str, framed: str) -> None:
    env = encode_batch([M1, member], control_id="1", timestamp=_TS)
    assert env == "BHS|^~\\&|||||" + _TS + "||||1\r" + M1 + framed + "BTS|2\r"
