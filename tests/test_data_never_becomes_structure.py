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
from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.lens import parse_source, rewrite_source
from messagefoundry.parsing import _builtin_hl7
from messagefoundry.parsing.message import Message, reencode_with_separators
from messagefoundry.transports.base import NegativeAckError
from messagefoundry.transports.mllp import MLLPDestination

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


# --- rule 4: the delimiter rewrite escapes a target delimiter found in a leaf (#2559) -------------

STANDARD = ("|", "^", "~", "&", BS)
#: Audit probe P3: the sender declares ``#`` as the field separator, so a literal ``|`` is data.
P3_SOURCE = (
    "MSH#"
    + ENC
    + "#SND#FAC#RCV#FAC#20260101120000##ADT^A01#CTRL1#P#2.5"
    + CR
    + "PID#1##111##DOE|INJECTED|X^JANE"
    + CR
)


def test_P3_a_literal_target_field_separator_stays_inside_its_field() -> None:
    out = Message.parse(reencode_with_separators(P3_SOURCE, STANDARD))
    # Before ADR 0206 the downstream parse gave PID-5, PID-6 and PID-7 as three fields.
    assert out.field("PID-5.1") == "DOE|INJECTED|X"
    assert out.field("PID-5.2") == "JANE"
    assert out.field("PID-6") is None and out.field("PID-7") is None
    assert out.field("PID-5") == "DOE" + _esc("F") + "INJECTED" + _esc("F") + "X^JANE"


def test_P3_control_the_engine_saw_one_field_on_the_way_in() -> None:
    inbound = Message.parse(P3_SOURCE)
    assert inbound.field("PID-5.1") == "DOE|INJECTED|X"
    assert inbound.field("PID-6") is None


@pytest.mark.parametrize(
    ("source_enc", "literal", "code"),
    [
        pytest.param("@~" + BS + "&", "^", "S", id="component"),
        pytest.param("^@" + BS + "&", "~", "R", id="repetition"),
        pytest.param("^~" + BS + "@", "&", "T", id="subcomponent"),
        pytest.param("^~!&", BS, "E", id="escape"),
    ],
)
def test_every_target_delimiter_found_in_a_leaf_is_escaped(
    source_enc: str, literal: str, code: str
) -> None:
    src = (
        f"MSH|{source_enc}|SND|FAC|RCV|FAC|20260101120000||ADT|C1|P|2.5"
        + CR
        + f"PID|1||A{literal}B"
        + CR
    )
    out = reencode_with_separators(src, STANDARD)
    assert out.split(CR)[1] == "PID|1||A" + _esc(code) + "B"
    assert Message.parse(out).field("PID-3.1") == "A" + literal + "B"


def test_escapes_and_structure_survive_the_slow_path() -> None:
    # A field that needs the escape walk still maps its separators and existing escape sequences.
    src = (
        "MSH#^~!&#SND#FAC#RCV#FAC#20260101120000##ADT#C1#P#2.5"
        + CR
        + "PID#1##A|B^C!S!D~E&F!X41!"
        + CR
    )
    out = Message.parse(reencode_with_separators(src, STANDARD))
    assert out.field("PID-3.1") == "A|B"
    assert out.field("PID-3.2") == "C^D"
    assert out.field("PID-3.1.1", repetition=2) == "E"
    assert out.field("PID-3.1.2", repetition=2) == "FA"


def test_a_field_with_no_target_delimiter_is_byte_identical_to_before() -> None:
    src = (
        "MSH#^~"
        + BS
        + "&#SND#FAC#RCV#FAC#20260101120000##ADT^A01#C1#P#2.5"
        + CR
        + "PID#1##DOE^J"
        + CR
    )
    assert reencode_with_separators(src, STANDARD).split(CR)[1] == "PID|1||DOE^J"


@pytest.mark.parametrize(
    "pid",
    [
        pytest.param(
            "PID#1##A" + BS + "Z|Y" + BS + "B", id="escape-sequence-holds-a-target-delimiter"
        ),
        pytest.param("PID#1##AB" + BS + "Z|Y", id="unclosed-escape-holds-a-target-delimiter"),
        pytest.param("P|D#1##A", id="segment-id-holds-the-target-field-separator"),
    ],
)
def test_a_value_the_target_set_cannot_carry_is_refused(pid: str) -> None:
    src = "MSH#" + ENC + "#SND#FAC#RCV#FAC#20260101120000##ADT#C1#P#2.5" + CR + pid + CR
    with pytest.raises(_builtin_hl7.DelimiterRewriteRefused) as caught:
        reencode_with_separators(src, STANDARD)
    assert "INJECTED" not in str(caught.value) and "Z|Y" not in str(caught.value)


async def test_the_mllp_override_refusal_is_permanent_and_dials_nothing() -> None:
    dest = MLLPDestination(
        Destination(
            name="out",
            type=ConnectorType.MLLP,
            settings={"host": "127.0.0.1", "port": 1, "encoding_characters": "|^~" + BS + "&"},
        )
    )
    bad = P3_SOURCE.replace("DOE|INJECTED|X", "A" + BS + "Z|Y" + BS)
    with pytest.raises(NegativeAckError) as caught:
        await dest.send(bad)
    assert caught.value.permanent is True and caught.value.code == "reencode"
    assert "Z|Y" not in str(caught.value)


async def test_a_non_hl7_payload_under_the_override_is_permanent_too() -> None:
    dest = MLLPDestination(
        Destination(
            name="out",
            type=ConnectorType.MLLP,
            settings={"host": "127.0.0.1", "port": 1, "encoding_characters": "#@*!%"},
        )
    )
    with pytest.raises(NegativeAckError, match="encoding-character override failed") as caught:
        await dest.send("not an HL7 message")
    assert caught.value.permanent is True
