# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An HL7 write or re-encode never lets data become structure (ADR 0206, vault BACKLOG #2558,
#2559 and #2560).

Each section pins one rule of the ADR. A test named for an audit probe reproduces that probe from
the injection audit and fails on the code before ADR 0206. Synthetic data only.

The backslash is built with ``chr(92)``, so no escape text in this file depends on how it was
written to disk.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from messagefoundry import actions
from messagefoundry.checks import _check_handler_security
from messagefoundry.lens import parse_source, rewrite_source
from messagefoundry.parsing.message import Message

CR, BS = "\r", chr(92)
ENC = "^~" + BS + "&"
MSH = f"MSH|{ENC}|SND|FAC|RCV|FAC|20260101120000||ADT^A01|CTRL1|P|2.5"
MSH2 = f"MSH|{ENC}|FORGED|FAC|RCV|FAC|20260101120000||ADT^A08|CTRL2|P|2.5"


def _esc(code: str) -> str:
    return BS + code + BS


#: Audit probe P5's source value: one component holding escaped component, repetition and
#: subcomponent separators. Decoded, it reads ``A^B~C&D``.
P5_VALUE = "A" + _esc("S") + "B" + _esc("R") + "C" + _esc("T") + "D"
P5_BODY = MSH + CR + "PID|1||" + P5_VALUE + "^^^MRN||DOE^JANE" + CR + "PV1|1|I" + CR


def _segment(msg: Message, index: int) -> str:
    return msg.encode().split(CR)[index]


# --- rule 1: a decoded leaf is data at every destination level (#2558) ----------------------------


def test_P5_copy_field_from_a_component_to_a_whole_field_stays_one_value() -> None:
    msg = Message.parse(P5_BODY)
    actions.copy_field(msg, "PID-3.1", "PV1-19")
    # Before ADR 0206 the PV1 line ended "A^B~C&D": two repetitions and a second component.
    assert msg.repetitions("PV1-19") == [P5_VALUE]
    assert msg.field("PV1-19.1") == "A^B~C&D"
    assert msg.field("PV1-19.2") is None
    assert _segment(msg, 2).endswith("|" + P5_VALUE)


def test_P5_control_a_component_destination_was_already_escaped() -> None:
    msg = Message.parse(P5_BODY)
    actions.copy_field(msg, "PID-3.1", "PV1-19.1")
    assert _segment(msg, 2).endswith("|" + P5_VALUE)


def test_a_subcomponent_source_is_data_too() -> None:
    body = MSH + CR + "PID|1||X&" + P5_VALUE + "^^^MRN" + CR + "PV1|1|I" + CR
    msg = Message.parse(body)
    actions.copy_field(msg, "PID-3.1.2", "PV1-19")
    assert msg.repetitions("PV1-19") == [P5_VALUE]


def test_a_whole_field_copy_still_carries_its_structure() -> None:
    # Draft 2 consequence: a field-to-field copy of a whole field copies raw text, structure and all.
    msg = Message.parse(MSH + CR + "PID|1||111^^^MRN~222^^^SSN" + CR + "PV1|1|I" + CR)
    actions.copy_field(msg, "PID-3", "PV1-19")
    assert msg.field("PV1-19") == "111^^^MRN~222^^^SSN"
    assert msg.repetitions("PV1-19") == ["111^^^MRN", "222^^^SSN"]


def test_split_field_writes_decoded_pieces_as_data() -> None:
    value = "X" + _esc("S") + "Y-Z" + _esc("R") + "W"
    msg = Message.parse(MSH + CR + "PID|1||1||" + value + "^JANE" + CR + "PV1|1|I" + CR)
    actions.split_field(msg, "PID-5.1", "-", ["PV1-19", "PV1-20"])
    assert msg.field("PV1-19") == "X" + _esc("S") + "Y"
    assert msg.field("PV1-19.1") == "X^Y"
    assert msg.field("PV1-20") == "Z" + _esc("R") + "W"
    assert msg.repetitions("PV1-20") == ["Z" + _esc("R") + "W"]


def test_split_field_of_a_whole_field_keeps_writing_raw_text() -> None:
    msg = Message.parse(MSH + CR + "PID|1||1||DOE^JANE" + CR + "PV1|1|I" + CR)
    actions.split_field(msg, "PID-5", "/", ["PV1-19"])
    assert msg.field("PV1-19.2") == "JANE"


def test_set_data_escapes_a_whole_field_and_set_keeps_its_meaning() -> None:
    msg = Message.parse(P5_BODY)
    msg.set_data("PV1-19", "A^B~C&D|E" + BS)
    assert msg.field("PV1-19.1") == "A^B~C&D|E" + BS
    assert msg.repetitions("PV1-19") == [msg.field("PV1-19")]
    # Rule 2: author-supplied text through set() is still structure.
    msg.set("PV1-20", "A^B")
    assert msg.field("PV1-20.2") == "B"


def test_set_data_scopes_to_one_repetition_and_leaves_the_others() -> None:
    msg = Message.parse(MSH + CR + "PID|1||111^^^MRN~222^^^SSN" + CR)
    msg.set_data("PID-3", "9~9", repetition=2)
    assert msg.repetitions("PID-3") == ["111^^^MRN", "9" + _esc("R") + "9"]


def test_set_data_at_a_leaf_is_set() -> None:
    a, b = Message.parse(P5_BODY), Message.parse(P5_BODY)
    a.set_data("PID-5.2", "O^B")
    b.set("PID-5.2", "O^B")
    assert a.encode() == b.encode()


@pytest.mark.parametrize("bad", [CR, "\n"])
def test_set_data_still_refuses_a_segment_separator(bad: str) -> None:
    msg = Message.parse(P5_BODY)
    with pytest.raises(ValueError, match="segment separator"):
        msg.set_data("PV1-19", "A" + bad + "B")


def test_set_data_reads_the_messages_own_separators() -> None:
    body = "MSH#!@$%#SND#FAC#RCV#FAC#20260101120000##ADT!A01#C1#P#2.5" + CR + "PV1#1#I" + CR
    msg = Message.parse(body)
    msg.set_data("PV1-19", "a!b@c%d#e")
    assert msg.field("PV1-19.1") == "a!b@c%d#e"
    assert msg.field("PV1-19.2") is None


# --- rule 3: the hand-written form is flagged by the advisory lint (#2558) ------------------------


def _lint(tmp_path: Path, body: str) -> str:
    (tmp_path / "feed.py").write_text(textwrap.dedent(body), encoding="utf-8")
    result = _check_handler_security(tmp_path)
    return "" if result.skipped else result.detail


@pytest.mark.parametrize(
    "line",
    [
        'msg.set("PV1-19", msg.field("PID-3.1"))',
        'msg.set("PV1-19", msg.field("PID-3.1") or "")',
        'msg.set("PV1-19", msg.field("PID-3.1.2").upper())',
        'msg["PV1-19"] = msg["PID-3.1"]',
        'msg.set("PV1-19", other.field("PID-3.1"), repetition=2)',
    ],
)
def test_the_lint_flags_a_decoded_leaf_written_to_a_whole_field(tmp_path: Path, line: str) -> None:
    detail = _lint(tmp_path, f'@handler("h")\ndef h(msg, other=None):\n    {line}\n')
    assert "[leaf-to-whole-field]" in detail


def test_the_lint_follows_a_name_bound_in_the_same_scope(tmp_path: Path) -> None:
    body = """
    @handler("h")
    def h(msg):
        mrn = msg.field("PID-3.1") or ""
        msg.set("PV1-19", mrn)
    """
    assert "[leaf-to-whole-field]" in _lint(tmp_path, body)


@pytest.mark.parametrize(
    "line",
    [
        'msg.set_data("PV1-19", msg.field("PID-3.1"))',
        'msg.set("PV1-19.1", msg.field("PID-3.1"))',
        'msg.set("PV1-19", msg.field("PID-3"))',
        'msg.set("PV1-19", "A^B")',
        "msg.set(dst, msg.field(src))",
        'msg["PV1-19.1"] = msg["PID-3.1"]',
    ],
)
def test_the_lint_does_not_flag_safe_or_unknowable_shapes(tmp_path: Path, line: str) -> None:
    detail = _lint(tmp_path, f'@handler("h")\ndef h(msg, dst="", src=""):\n    {line}\n')
    assert "[leaf-to-whole-field]" not in detail


# --- rule 1 in the lens: the Steps view's Copy Field writes a leaf as data (#2558) ----------------

LENS_SOURCE = """\
from messagefoundry import handler, set_field


@handler("H")
def h(msg):
    set_field(msg, "PID-3.1", "X")
"""


def _lens_insert_copy(src: str | dict[str, str], dst: str) -> str:
    anchor = parse_source(LENS_SOURCE)[0]["rows"][0]
    return rewrite_source(
        LENS_SOURCE,
        {
            "op": "insert_row",
            "line_start": anchor["line_start"],
            "line_end": anchor["line_end"],
            "position": "after",
            "action": "copy_field",
            "params": {"src": src, "dst": dst},
        },
    )


def _copy_rows(source: str) -> list[dict[str, object]]:
    return [r for r in parse_source(source)[0]["rows"] if r.get("action") == "copy_field"]


def test_the_lens_inserts_a_copy_from_a_leaf_with_set_data_and_reads_it_back() -> None:
    out = _lens_insert_copy("PID-3.1", "PV1-19")
    assert 'msg.set_data("PV1-19", msg.field("PID-3.1") or "")' in out
    rows = _copy_rows(out)
    assert len(rows) == 1 and rows[0]["params"] == {"src": "PID-3.1", "dst": "PV1-19"}


@pytest.mark.parametrize("src", ["PID-3", {"expr": "src_path"}])
def test_the_lens_keeps_set_for_a_whole_field_or_an_expression_source(
    src: str | dict[str, str],
) -> None:
    out = _lens_insert_copy(src, "PV1-19")
    assert "msg.set(" in out and "set_data" not in out
    assert len(_copy_rows(out)) == 1


def test_a_set_data_call_that_is_not_a_copy_is_a_code_row() -> None:
    source = LENS_SOURCE + '    msg.set_data("PV1-19", "A")\n'
    rows = parse_source(source)[0]["rows"]
    assert [r.get("kind") for r in rows][-1] == "code"
