# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""``encode_batch`` — BHS…BTS batch envelope encoder (BACKLOG #134 / ADR 0082).

The encode-side inverse of ``split_batch``: N MSH messages → one BHS…BTS envelope, framed from the
head member's own separators, deterministic (BHS-7/BHS-11 supplied by the caller — no clock), and
round-trippable back through ``split_batch``.
"""

from __future__ import annotations

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
