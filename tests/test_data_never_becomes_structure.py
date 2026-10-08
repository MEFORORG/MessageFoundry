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

import ast
import asyncio
import random
import textwrap
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from messagefoundry import actions, checks
from messagefoundry.checks import _check_handler_security
from messagefoundry.config.models import (
    ConnectorType,
    ContentType,
    Destination,
    Source,
    Validation,
)
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.lens import (
    CONTRACT_V2,
    REFUSAL_COLUMN_LIMIT,
    LensRewriteError,
    _argument_dump,
    parse_source,
    rewrite_source,
)
from messagefoundry.parsing import _builtin_hl7
from messagefoundry.parsing import split as split_mod
from messagefoundry.parsing.message import Message, reencode_with_separators
from messagefoundry.parsing.peek import starts_with_msh
from messagefoundry.parsing.sniff import _LEADING_WS
from messagefoundry.parsing.split import split_batch, split_batch_bytes
from messagefoundry.pipeline import ingress_guards, wiring_runner
from messagefoundry.pipeline.dryrun import dry_run, split_messages
from messagefoundry.pipeline.dryrun_trace import trace_dry_run
from messagefoundry.store import MessageStatus, MessageStore
from messagefoundry.transports.base import NegativeAckError
from messagefoundry.transports.file import FileSource
from messagefoundry.transports.mllp import MLLPDestination
from tests.test_remotefile_transport import (
    _FakeClient,
    _FakeLedger,
    _RecordingHandler,
    _settle,
)
from tests.test_remotefile_transport import _src as _remote_src

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


@pytest.mark.parametrize("strict", [False, True])
@pytest.mark.parametrize(
    "line",
    [
        pytest.param('msg.set("PV1-19", msg.field("PID-3.1"))', id="hl7"),
        pytest.param("msg.set(\"CLM-05\", f\"{msg['CLM-05.1'] or ''}:B:1\")", id="x12-composite"),
    ],
)
def test_the_lint_advice_names_the_x12_case_where_set_data_raises(
    tmp_path: Path, line: str, strict: bool
) -> None:
    # Vault #2862: the lint reads paths, not formats, so it flags the X12 composite too. Its
    # advice must not send an X12 author to a set_data that refuses the component separator.
    (tmp_path / "feed.py").write_text(f'@handler("h")\ndef h(msg):\n    {line}\n', "utf-8")
    result = _check_handler_security(tmp_path, strict=strict)
    assert "feed.py:3 [leaf-to-whole-field]" in result.detail
    advice = result.detail.partition(". leaf-to-whole-field: ")[2]
    assert advice.startswith("on HL7, write a value read from a component or subcomponent with")
    assert "On X12, set_data refuses the component separator in a whole element" in advice
    # Keeping set is offered to the X12 case alone; on HL7 it is the unsafe write.
    assert advice.index("keep set") > advice.index("On X12")
    assert "write each component on its own path" in advice
    # Strict mode is unchanged: a finding blocks, and advisory mode never does.
    assert (result.ok, result.required) == (not strict, strict)


def test_an_unscanned_write_gets_the_same_advice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _too_deep(*_args: object) -> bool:
        raise RecursionError

    monkeypatch.setattr(checks, "_flows", _too_deep)
    detail = _lint(tmp_path, '@handler("h")\ndef h(msg):\n    msg.set("PV1-19", "x")\n')
    assert "[leaf-to-whole-field-unscanned]" in detail
    assert ". leaf-to-whole-field: on HL7, write a value read from a component" in detail


def test_the_lint_gives_no_leaf_advice_without_a_leaf_finding(tmp_path: Path) -> None:
    detail = _lint(tmp_path, '@handler("h")\ndef h(msg):\n    print(msg)\n')
    assert "[phi-to-log]" in detail
    assert "set_data" not in detail


# --- rule 1 in the lens: the Steps view's Copy Field writes a leaf as data (#2558) ----------------

LENS_SOURCE = """\
from messagefoundry import handler, set_field

# An expression source must name an inert module literal (Manager decision 2026-10-07).
src_path = "PID-3"


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


async def test_a_non_hl7_payload_under_raw_separators_is_permanent_too() -> None:
    dest = MLLPDestination(
        Destination(
            name="out",
            type=ConnectorType.MLLP,
            settings={"host": "127.0.0.1", "port": 1},
            hl7_raw_separators=True,
        )
    )
    with pytest.raises(NegativeAckError, match="hl7_raw_separators emit failed") as caught:
        await dest.send("not an HL7 message")
    assert caught.value.permanent is True and caught.value.code == "reencode"


def test_an_override_that_only_renames_separators_takes_the_plain_translate() -> None:
    # The field separator never appears inside a field's text, so the same field separator under a
    # new component set needs no escape walk and gives exactly the old single-translate output.
    src = MSH + CR + "PID|1||A^B~C&D" + CR
    out = reencode_with_separators(src, ("|", "@", "*", "%", "!"))
    assert out.split(CR)[1] == "PID|1||A@B*C%D"


# --- rule 5: a source that does not split refuses a body with a second MSH (#2560) ----------------

#: Audit probe P6: two messages in one body.
P6_BODY = MSH + CR + "PID|1||111" + CR + MSH2 + CR + "PID|1||999" + CR
ONE = MSH + CR + "PID|1||111" + CR


def _mllp_ic(content_type: ContentType = ContentType.HL7V2) -> InboundConnection:
    return InboundConnection(
        "in",
        ConnectionSpec(ConnectorType.MLLP, {"host": "0.0.0.0", "port": 2575}),
        router="r",
        content_type=content_type,
        validation=Validation(strict=False, hl7_version="2.5"),
    )


def test_P6_control_the_parser_still_reads_one_message_with_one_control_id() -> None:
    # The parser is unchanged: rule 5 refuses at the source, where a disposition can be recorded.
    two = Message.parse(P6_BODY)
    assert two.segments() == ["MSH", "PID", "MSH", "PID"] and two.control_id == "CTRL1"


@pytest.mark.parametrize(
    "body",
    [
        pytest.param(P6_BODY, id="P6-two-messages"),
        pytest.param("FHS|" + ENC + CR + "BHS|" + ENC + CR + P6_BODY, id="enveloped-batch"),
        pytest.param(CR + " " + P6_BODY, id="leading-whitespace"),
        pytest.param(ONE + "MSHX|" + ENC + "|A" + CR, id="any-line-the-parser-reads-as-MSH"),
    ],
)
def test_ingress_refuses_a_second_msh(body: str) -> None:
    with pytest.raises(ingress_guards.IngressMultipleMessagesRejected) as caught:
        ingress_guards.check_decoded(body, _mllp_ic())
    assert caught.value.phase == "decode"
    assert caught.value.reason == ingress_guards.MULTIPLE_MESSAGES_REJECTED_REASON
    assert isinstance(caught.value, ingress_guards.IngressBodyRejected)


@pytest.mark.parametrize(
    "body",
    [
        pytest.param(ONE, id="one-message"),
        pytest.param(CR + CR + ONE, id="leading-blank-lines"),
        pytest.param(
            "FHS|" + ENC + CR + "BHS|" + ENC + CR + ONE + "BTS|1" + CR, id="one-enveloped"
        ),
        pytest.param(ONE.replace("111", "MSH"), id="MSH-as-field-data"),
        pytest.param(" " + "\t", id="blank"),
    ],
)
def test_ingress_admits_one_message(body: str) -> None:
    ingress_guards.check_decoded(body, _mllp_ic())


def test_the_second_msh_refusal_is_hl7v2_only() -> None:
    ingress_guards.check_decoded('{"a": "x' + CR + 'MSH"}', _mllp_ic(ContentType.JSON))


@pytest.fixture
async def store(tmp_path: Path) -> Any:
    s = await MessageStore.open(tmp_path / "msh.db")
    yield s
    await s.close()


def _registry(ic: InboundConnection) -> Registry:
    reg = Registry()
    reg.add_inbound(ic)
    reg.add_outbound(
        OutboundConnection("out", ConnectionSpec(ConnectorType.FILE, {"directory": "."}))
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("out", m))
    return reg


async def _rows(store: MessageStore) -> list[dict[str, Any]]:
    cur = await store._db.execute("SELECT status, error FROM messages")
    return [dict(r) for r in await cur.fetchall()]


async def test_P6_the_mllp_listener_naks_and_records_error(store: MessageStore) -> None:
    reg = _registry(_mllp_ic())
    runner = wiring_runner.RegistryRunner(reg, store, egress=EgressSettings(deny_by_default=False))
    ack = await runner._handle_inbound(reg.inbound["in"], P6_BODY.encode("utf-8"))
    assert ack is not None and "MSA|AR|" in ack and "more than one MSH in body" in ack
    assert await _rows(store) == [
        {
            "status": MessageStatus.ERROR.value,
            "error": ingress_guards.MULTIPLE_MESSAGES_REJECTED_REASON,
        }
    ]


async def test_P6_the_http_listener_records_error_and_commits_nothing(store: MessageStore) -> None:
    ic = InboundConnection(
        "in",
        ConnectionSpec(ConnectorType.HTTP, {"host": "127.0.0.1", "port": 8080, "path": "/in"}),
        router="r",
        content_type=ContentType.HL7V2,
        validation=Validation(strict=False, hl7_version="2.5"),
    )
    reg = _registry(ic)
    runner = wiring_runner.RegistryRunner(reg, store, egress=EgressSettings(deny_by_default=False))
    assert await runner._handle_inbound_http(ic, P6_BODY.encode("utf-8")) is None
    assert [r["status"] for r in await _rows(store)] == [MessageStatus.ERROR.value]


def test_the_dry_run_refuses_what_the_listener_refuses() -> None:
    result = dry_run(_registry(_mllp_ic()), P6_BODY.encode("utf-8"), inbound="in")
    assert result.disposition is MessageStatus.ERROR
    assert result.error == ingress_guards.MULTIPLE_MESSAGES_REJECTED_REASON


def test_split_batch_bytes_splits_a_batch_and_hands_one_message_over_untouched() -> None:
    assert split_batch_bytes(ONE.encode("latin-1"), "latin-1") == [ONE.encode("latin-1")]
    batch = ("FHS|" + ENC + CR + P6_BODY).replace("111", "M" + chr(0xFC)).encode("latin-1")
    parts = split_batch_bytes(batch, "latin-1")
    assert [p.decode("latin-1").split("|")[9] for p in parts] == ["CTRL1", "CTRL2"]
    assert "M" + chr(0xFC) in parts[0].decode("latin-1")
    undecodable = P6_BODY.encode("utf-16")
    assert split_batch_bytes(undecodable, "utf-8") == [undecodable]
    assert split_batch_bytes(P6_BODY.encode(), "no-such-codec") == [P6_BODY.encode()]


async def test_the_remote_file_source_splits_a_batch_like_the_file_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _FakeClient(files={"/in/batch.hl7": P6_BODY.encode("utf-8")})
    src = _remote_src(monkeypatch, client)
    handler = _RecordingHandler()
    src._handler = handler
    await _settle(src)
    await src._poll_once()
    assert [b.decode("utf-8") for b in handler.bodies] == [
        # split_batch's own shape: the CR before a later MSH goes with the boundary.
        MSH + CR + "PID|1||111",
        MSH2 + CR + "PID|1||999" + CR,
    ]
    assert "/in/.processed/batch.hl7" in client.files


async def test_the_remote_file_source_hands_a_non_hl7_file_over_verbatim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = b'{"a": "MSH"}'
    client = _FakeClient(files={"/in/a.json": body})
    src = _remote_src(monkeypatch, client, pattern="*.json")
    src.content_type = ContentType.JSON
    handler = _RecordingHandler()
    src._handler = handler
    await _settle(src)
    await src._poll_once()
    assert handler.bodies == [body]


async def test_a_stop_part_way_through_a_remote_batch_leaves_the_file(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _FakeClient(files={"/in/batch.hl7": P6_BODY.encode("utf-8")})
    src = _remote_src(monkeypatch, client)

    class _StopAfterFirst(_RecordingHandler):
        async def __call__(self, raw: bytes) -> str | None:
            src._stop.set()
            return await super().__call__(raw)

    handler = _StopAfterFirst()
    src._handler = handler
    await _settle(src)
    await src._poll_once()
    assert len(handler.bodies) == 1
    assert "/in/batch.hl7" in client.files and "/in/.processed/batch.hl7" not in client.files


# --- review repair: no leading message is dropped by the batch split (#2560) ----------------------

MSH3 = MSH.replace("CTRL1", "CTRL3")
THREE = [
    MSH + CR + "PID|1||111" + CR,
    MSH2 + CR + "PID|1||222" + CR,
    MSH3 + CR + "PID|1||333" + CR,
]
#: What a file may carry before its first ``MSH``: a byte order mark, a space or a tab.
LEADS = [
    pytest.param(chr(0xFEFF), id="bom"),
    pytest.param(" ", id="space"),
    pytest.param(chr(9), id="tab"),
]


def _remote_ic() -> InboundConnection:
    return InboundConnection(
        "in",
        ConnectionSpec(ConnectorType.REMOTEFILE, {"host": "sftp.example.com", "remote_dir": "/in"}),
        router="r",
        content_type=ContentType.HL7V2,
        validation=Validation(strict=False, hl7_version="2.5"),
    )


@pytest.mark.parametrize("lead", LEADS)
@pytest.mark.parametrize("count", [1, 2, 3])
async def test_every_message_of_a_noise_led_remote_file_gets_a_disposition(
    monkeypatch: pytest.MonkeyPatch, store: MessageStore, lead: str, count: int
) -> None:
    body = (lead + "".join(THREE[:count])).encode("utf-8")
    client = _FakeClient(files={"/in/batch.hl7": body})
    src = _remote_src(monkeypatch, client)
    ic = _remote_ic()
    runner = wiring_runner.RegistryRunner(
        _registry(ic), store, egress=EgressSettings(deny_by_default=False)
    )
    src._handler = runner._make_handler(ic)
    await _settle(src)
    await src._poll_once()
    # One row per message the file holds: none is dropped and none is folded into another's ERROR.
    rows = await _rows(store)
    assert len(rows) == count
    assert {r["status"] for r in rows} == {MessageStatus.RECEIVED.value}


@pytest.mark.parametrize("lead", LEADS)
@pytest.mark.parametrize("count", [1, 2, 3])
def test_split_batch_keeps_a_first_message_led_by_noise(lead: str, count: int) -> None:
    text = lead + "".join(THREE[:count])
    parts = split_batch(text)
    assert len(parts) == count
    if count > 1:
        assert [p.split("|")[9] for p in parts] == ["CTRL1", "CTRL2", "CTRL3"][:count]
    raw = text.encode("utf-8")
    bytes_parts = split_batch_bytes(raw, "utf-8")
    assert len(bytes_parts) == count
    if count == 1:
        # One message goes over as its bytes, less a leading byte order mark (see below).
        assert bytes_parts == [raw.removeprefix(chr(0xFEFF).encode("utf-8"))]


def test_a_first_chunk_that_is_not_an_envelope_is_kept_for_the_parser() -> None:
    parts = split_batch("JUNK|1" + CR + "".join(THREE[:2]))
    assert len(parts) == 3 and parts[0] == "JUNK|1"
    enveloped = split_batch("FHS|" + ENC + CR + "BHS|" + ENC + CR + "".join(THREE[:2]))
    assert [p.split("|")[9] for p in enveloped] == ["CTRL1", "CTRL2"]
    # Only the envelope header lines are dropped; a segment after them is kept for the parser.
    stray = split_batch("BHS|" + ENC + CR + "EVN|junk" + CR + "".join(THREE[:2]))
    assert len(stray) == 3 and stray[0] == "EVN|junk"
    # Whitespace the content sniff does not list (a file separator, U+2028) is still not a message.
    for blank in (chr(0x1C), chr(0x2028)):
        assert len(split_batch(blank + CR + "".join(THREE[:2]))) == 2


def test_the_dry_run_split_keeps_a_bom_led_first_message_as_the_live_split_does() -> None:
    raw = (chr(0xFEFF) + "".join(THREE)).encode("utf-8")
    parts = split_messages(raw)
    assert [p.decode("utf-8") for p in parts] == [
        m.decode("utf-8") for m in split_batch_bytes(raw, "utf-8")
    ]
    assert parts[0].startswith(b"MSH|")


async def test_the_file_source_keeps_a_bom_led_first_message(tmp_path: Path) -> None:
    source = FileSource(Source(type=ConnectorType.FILE, settings={"directory": str(tmp_path)}))
    handler = _RecordingHandler()
    source._handler = handler
    assert await source._emit((chr(0xFEFF) + "".join(THREE)).encode("utf-8")) is True
    assert [b.decode("utf-8").split("|")[9] for b in handler.bodies] == ["CTRL1", "CTRL2", "CTRL3"]


def test_split_batch_bytes_hands_a_single_message_over_without_decoding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _no_split(_raw: object) -> list[str]:
        raise AssertionError("a one-message file was decoded and split")

    monkeypatch.setattr(split_mod, "split_batch", _no_split)
    # A file led by a byte order mark is decoded under UTF-8, so the mark can be read past; see
    # below. Under a single-byte charset those bytes are three characters, and no decode is paid.
    for lead in (" ", ""):
        raw = (lead + THREE[0]).encode("utf-8")
        assert split_batch_bytes(raw, "utf-8") == [raw]
        lf = raw.replace(CR.encode(), chr(10).encode())
        assert split_batch_bytes(lf, "latin-1") == [lf]
    marked = (chr(0xFEFF) + THREE[0]).encode("utf-8")
    assert split_batch_bytes(marked, "cp1252") == [marked]


def test_the_msh_opening_check_is_the_parsers_strip() -> None:
    # One check serves the parser and the one-message hand-off; it must read what a strip reads.
    for code in [*range(0x3100), 0xFEFF]:
        text = chr(code) * 2 + "MSH|"
        assert starts_with_msh(text) == text.lstrip().startswith("MSH"), code
    assert not starts_with_msh("PID|MSH")


def test_the_leading_mark_check_reads_the_whitespace_the_sniff_tolerates() -> None:
    bom = chr(0xFEFF).encode("utf-8")
    for byte in range(256):
        lead = bytes([byte])
        matched = split_mod._LEADING_BOM.match(lead * 3 + bom) is not None
        assert matched == (lead in _LEADING_WS), byte
    assert split_mod._LEADING_BOM.match(bom + b"MSH") is not None
    assert split_mod._LEADING_BOM.match(b"MSH" + bom) is None


def test_split_batch_bytes_still_splits_an_encoding_the_byte_check_cannot_read() -> None:
    raw = "".join(THREE).encode("utf-16")
    assert len(split_batch_bytes(raw, "utf-16")) == 3


async def test_a_stop_before_the_first_message_hands_nothing_over_and_still_prunes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _FakeClient(
        files={"/in/a.hl7": THREE[0].encode("utf-8"), "/in/b.hl7": "".join(THREE).encode("utf-8")}
    )
    src = _remote_src(monkeypatch, client, after_read="leave")
    ledger = _FakeLedger()
    src.processed_ledger = ledger
    handler = _RecordingHandler()
    src._handler = handler
    original = split_mod.split_batch_bytes
    loop = asyncio.get_running_loop()
    loop_thread = threading.get_ident()
    stop_ran = threading.Event()

    def _set_stop() -> None:
        src._stop.set()
        stop_ran.set()

    def _stop_on_the_batch(raw: bytes, encoding: str) -> list[bytes]:
        if raw.count(b"MSH") > 1:
            if threading.get_ident() == loop_thread:
                # A split run inline is already on the loop, where the Event lives. Waiting here
                # would block the one thread that can run the stop.
                _set_stop()
            else:
                # The split runs in a worker thread, so the stop is queued to the loop. The worker
                # then waits until the loop has run it, because queueing alone does not order it.
                # A worker can finish before the loop registers the future's done-callback. asyncio
                # then completes the awaited future without yielding. The poller would read the
                # flag while the stop is still queued.
                loop.call_soon_threadsafe(_set_stop)
                stop_ran.wait(30)
        return original(raw, encoding)

    monkeypatch.setattr(
        "messagefoundry.transports.remotefile.split_batch_bytes", _stop_on_the_batch
    )
    await _settle(src)
    await src._poll_once()
    # The poll split b.hl7 and the stop ran. A poll that never reached b.hl7 (not settled, filtered
    # out, or past the tick ceiling) would pass the two assertions below without this one.
    assert stop_ran.is_set(), "the stop never ran: the poll did not split b.hl7"
    # a.hl7 was handed over and recorded; b.hl7 met the stop before its first message.
    assert [b.decode("utf-8").split("|")[9] for b in handler.bodies] == ["CTRL1"]
    assert len(ledger.keys) == 1 and ledger.pruned == 1


# --- review repair: a separator escape means what the engine read, under the target set (#2559) ---


def _reencode(field_text: str, target: tuple[str, str, str, str, str], path: str) -> str | None:
    src = MSH + CR + "OBX|1|ST|C||" + field_text + CR
    return Message.parse(reencode_with_separators(src, target)).field(path)


@pytest.mark.parametrize(
    ("field_text", "target", "read"),
    [
        pytest.param(
            "SMITH " + _esc("T") + " SONS", ("|", "^", "~", "#", BS), "SMITH & SONS", id="T-to-#"
        ),
        pytest.param("A" + _esc("S") + "B", ("|", "!", "~", "&", BS), "A^B", id="S-under-!"),
        pytest.param("A!B", ("|", "!", "~", "&", BS), "A!B", id="literal-!"),
        pytest.param("C:" + _esc("E") + "x", ("|", "^", "~", "&", "#"), "C:" + BS + "x", id="E"),
        pytest.param("A" + _esc("F") + "B", ("#", "^", "~", "&", BS), "A|B", id="F-under-#"),
        pytest.param("A" + _esc("R") + "B", ("|", "^", "@", "&", BS), "A~B", id="R-under-@"),
        pytest.param("A" + _esc("H") + "B", ("|", "^", "~", "&", "#"), "A_B", id="H-kept"),
    ],
)
def test_a_separator_escape_reads_the_same_after_the_rewrite(
    field_text: str, target: tuple[str, str, str, str, str], read: str
) -> None:
    assert Message.parse(MSH + CR + "OBX|1|ST|C||" + field_text + CR).field("OBX-5.1") == read
    assert _reencode(field_text, target, "OBX-5.1") == read


def test_an_escaped_and_a_literal_component_stay_distinct_under_the_target() -> None:
    target = ("|", "!", "~", "&", BS)
    src = MSH + CR + "OBX|1|ST|C||A" + _esc("S") + "B|A!B" + CR
    out = reencode_with_separators(src, target).split(CR)[1].split("|")
    assert out[5] != out[6]
    assert out[5] == "A^B" and out[6] == "A" + _esc("S") + "B"


@pytest.mark.parametrize(
    ("field_text", "target"),
    [
        pytest.param("C:" + BS + "dir!x", ("|", "!", "~", "&", BS), id="unclosed-holds-component"),
        pytest.param("C:" + BS + "dir!x", ("|", "!", "~", "&", "#"), id="new-escape-char"),
        pytest.param("AB" + BS + "Z#Y", ("#", "^", "~", "&", BS), id="unclosed-holds-field-sep"),
    ],
)
def test_an_unclosed_escape_holding_a_target_delimiter_is_carried(
    field_text: str, target: tuple[str, str, str, str, str]
) -> None:
    seen = Message.parse(MSH + CR + "OBX|1|ST|C||" + field_text + CR).field("OBX-5.1")
    assert seen == field_text
    assert _reencode(field_text, target, "OBX-5.1") == seen


# --- review repair: the Steps view re-picks the copy's write when its source changes (#2558) -----


def _edit_copy_src(write: str, old_src: str, new_src: str) -> str:
    source = LENS_SOURCE + f'    msg.{write}("PV1-19", msg.field("{old_src}") or "")\n'
    row = _copy_rows(source)[0]
    return rewrite_source(
        source,
        {
            "op": "set_params",
            "line_start": row["line_start"],
            "line_end": row["line_end"],
            "params": {"src": new_src},
        },
    )


def test_a_copy_edited_from_a_leaf_to_a_whole_field_source_writes_with_set() -> None:
    out = _edit_copy_src("set_data", "PID-3.1", "PID-3")
    assert 'msg.set("PV1-19", msg.field("PID-3") or "")' in out
    assert _copy_rows(out)[0]["params"] == {"src": "PID-3", "dst": "PV1-19"}


def test_a_copy_edited_from_a_whole_field_to_a_leaf_source_writes_with_set_data() -> None:
    out = _edit_copy_src("set", "PID-3", "PID-3.1")
    assert 'msg.set_data("PV1-19", msg.field("PID-3.1") or "")' in out
    assert _copy_rows(out)[0]["params"] == {"src": "PID-3.1", "dst": "PV1-19"}


def test_a_copy_edit_that_keeps_the_level_keeps_the_write() -> None:
    out = _edit_copy_src("set_data", "PID-3.1", "PID-4.2")
    assert 'msg.set_data("PV1-19", msg.field("PID-4.2") or "")' in out


def test_a_copy_whose_destination_is_edited_to_a_whole_field_writes_with_set_data() -> None:
    source = LENS_SOURCE + '    msg.set("NK1-2.1", msg.field("PID-5.1") or "")\n'
    row = _copy_rows(source)[0]
    edit = {"op": "set_params", "line_start": row["line_start"], "line_end": row["line_end"]}
    out = rewrite_source(source, {**edit, "params": {"dst": "NK1-2"}})
    assert 'msg.set_data("NK1-2", msg.field("PID-5.1") or "")' in out
    # At a leaf destination the two writes are the same, so an edit there leaves the method alone.
    out = rewrite_source(source, {**edit, "params": {"dst": "NK1-3.1"}})
    assert 'msg.set("NK1-3.1", msg.field("PID-5.1") or "")' in out


def test_a_copy_re_pick_that_would_pass_the_column_limit_is_refused() -> None:
    # 95 columns as written; set_data would make it 100+, which ruff would re-wrap.
    line = (
        '    msg.set("PV1-19", msg.field("PID-3", occurrence=an_occurrence) or "", occurrence=n)\n'
    )
    pad = 95 - len(line.rstrip("\n"))
    line = line.replace("an_occurrence", "an_occurrence" + "x" * pad)
    source = LENS_SOURCE + line
    row = _copy_rows(source)[0]
    edit = {"op": "set_params", "line_start": row["line_start"], "line_end": row["line_end"]}
    with pytest.raises(LensRewriteError) as caught:
        rewrite_source(source, {**edit, "params": {"src": "PID-3.1"}})
    assert caught.value.code == REFUSAL_COLUMN_LIMIT


# --- review repair: the lint follows the value, not every read near it (#2558) --------------------


@pytest.mark.parametrize(
    "line",
    [
        'msg.set("PV1-19", TABLE[msg.field("PID-3.1")])',
        'msg.set("PV1-19", TABLE.get(msg.field("PID-3.1"), "X"))',
        'msg.set("PV1-19", "A" if msg.field("PID-3.1") else "B")',
        'msg.set("PV1-19", str(len(msg.field("PID-3.1") or "")))',
        'msg.set("PV1-19", next(r for r in reps if msg.field("PID-3.5") == r))',
        'msg.set("PV1-19", "Y" if msg.field("PID-3.1").startswith("9") else "N")',
        'msg.set("PV1-19", max(reps, key=lambda r: msg.field("PID-3.1")))',
        'msg.set("PV1-19", str((lambda reps: reps)(TABLE)))',
    ],
)
def test_the_lint_ignores_a_leaf_that_does_not_flow_into_the_value(
    tmp_path: Path, line: str
) -> None:
    body = f'TABLE = {{}}\n@handler("h")\ndef h(msg, reps=()):\n    {line}\n'
    assert "[leaf-to-whole-field]" not in _lint(tmp_path, body)


@pytest.mark.parametrize(
    "line",
    [
        'msg.set("PV1-19", TABLE.get("k", msg.field("PID-3.1")))',
        'msg.set("PV1-19", msg.field("PID-3.1") if ok else "B")',
        'msg.set("PV1-19", "-".join([msg.field("PID-3.1") or "", "x"]))',
        'msg.set("PV1-19", f"{msg.field(\'PID-3.1\')}")',
        'msg.set("PV1-19", str(msg.field("PID-3.1")))',
        'msg.set("PV1-19", next(r for r in [msg.field("PID-3.1")] if r))',
        'msg.set("PV1-19", (msg.field("PID-3.1") or "")[:3])',
        'msg.set("PV1-19", (lambda: msg.field("PID-3.1"))())',
        'msg.set("PV1-19", {msg.field("PID-3.1"): 1}.popitem()[0])',
    ],
)
def test_the_lint_still_flags_a_leaf_that_flows_into_the_value(tmp_path: Path, line: str) -> None:
    body = f'TABLE = {{}}\n@handler("h")\ndef h(msg, ok=True):\n    {line}\n'
    assert "[leaf-to-whole-field]" in _lint(tmp_path, body)


def test_the_lint_follows_a_name_only_through_its_value(tmp_path: Path) -> None:
    clean = """
    @handler("h")
    def h(msg):
        flag = msg.field("PID-3.1") == "X"
        code = "A" if flag else "B"
        msg.set("PV1-19", code)
    """
    assert "[leaf-to-whole-field]" not in _lint(tmp_path, clean)
    tainted = """
    @handler("h")
    def h(msg):
        a = b = ""
        a = b
        b = a + (msg.field("PID-3.1") or "")
        msg.set("PV1-19", a)
    """
    assert "[leaf-to-whole-field]" in _lint(tmp_path, tainted)
    # A comprehension reads its first iterable before it binds the target of the same name.
    shadowed = """
    @handler("h")
    def h(msg):
        x = msg.field("PID-3.1") or ""
        msg.set("PV1-19", "".join([x for x in x]))
    """
    assert "[leaf-to-whole-field]" in _lint(tmp_path, shadowed)


def test_the_shipped_results_relay_sample_is_clean() -> None:
    root = Path(__file__).resolve().parents[1] / "samples" / "results_relay"
    result = _check_handler_security(root)
    assert "[leaf-to-whole-field]" not in result.detail


@pytest.mark.parametrize(("source", "flagged"), [("PID-3", False), ("PID-3.1", True)])
def test_the_lint_resolves_a_deep_doubling_chain_quickly(
    tmp_path: Path, source: str, flagged: bool
) -> None:
    # A clean chain is the slow one without a memo: no read short-circuits, so every name is resolved
    # once per path to it, 2**40 times here.
    lines = [f'    v0 = msg.field("{source}") or ""']
    lines += [f"    v{i} = v{i - 1} + v{i - 1}" for i in range(1, 41)]
    body = '@handler("h")\ndef h(msg):\n' + "\n".join(lines) + '\n    msg.set("PV1-19", v40)\n'
    started = time.perf_counter()
    assert ("[leaf-to-whole-field]" in _lint(tmp_path, body)) is flagged
    assert time.perf_counter() - started < 2.0


# --- final repair round: the lint, the lens template, set_data, the remote split (#2558, #2560) ---


@pytest.mark.parametrize(("source", "flagged"), [("PID-3", False), ("PID-3.1", True)])
def test_the_lint_walks_a_very_long_concatenation_without_crashing(
    tmp_path: Path, source: str, flagged: bool
) -> None:
    # 5000 terms nest 5000 deep in the AST, past the interpreter's recursion limit.
    chain = " + ".join(['"x"'] * 5000)
    read = f'(msg.field("{source}") or "")'
    body = (
        '@handler("h")\ndef h(msg):\n'
        f"    v = {chain} + {read}\n"
        '    msg.set("PV1-19", v)\n'
        f'    msg.set("PV1-20", {chain} + {read})\n'
    )
    detail = _lint(tmp_path, body)
    assert detail.count("[leaf-to-whole-field]") == (2 if flagged else 0)
    assert "unscanned" not in detail


def test_a_write_the_lint_cannot_walk_is_noted_and_never_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _too_deep(*_args: object) -> bool:
        raise RecursionError

    monkeypatch.setattr(checks, "_flows", _too_deep)
    detail = _lint(tmp_path, '@handler("h")\ndef h(msg):\n    msg.set("PV1-19", "x")\n')
    assert "feed.py:3 [leaf-to-whole-field-unscanned]" in detail


def _native_rows(source: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = parse_source(source, contract=CONTRACT_V2)[0]["rows"]
    return rows


def _set_value(source: str, value: Any) -> str:
    row = _native_rows(source)[-1]
    return rewrite_source(
        source,
        {
            "op": "set_params",
            "line_start": row["line_start"],
            "line_end": row["line_end"],
            "params": {"value": value},
        },
        contract=CONTRACT_V2,
    )


def test_a_set_field_template_copying_a_leaf_writes_with_set_data_and_reads_back() -> None:
    source = LENS_SOURCE + '    msg.set("PV1-19", "X")\n'
    parts = [{"text": "MRN "}, {"path": "PID-3.1"}]
    out = _set_value(source, {"parts": parts})
    assert "    msg.set_data(\"PV1-19\", f\"MRN {msg['PID-3.1'] or ''}\")\n" in out
    row = _native_rows(out)[-1]
    assert row["action"] == "set_field" and row["param_parts"]["value"] == parts
    # Back to authored text: the write goes back to set, which takes it as structure.
    back = _set_value(out, "A^B")
    assert back.endswith('    msg.set("PV1-19", "A^B")\n')
    assert _native_rows(back)[-1]["action"] == "set_field"


@pytest.mark.parametrize(
    "parts",
    [
        pytest.param([{"path": "PID-3"}], id="whole-field-read"),
        pytest.param([{"text": "A^"}, {"path": "PID-3.1"}], id="authored-structure"),
        pytest.param(
            [{"path": "PID-3.1"}, {"text": "~"}, {"path": "PID-4.1"}], id="authored-repetition"
        ),
        pytest.param(
            [{"path": "PID-3"}, {"text": " "}, {"path": "PID-3.1"}], id="a-whole-field-read-too"
        ),
    ],
)
def test_a_set_field_template_that_is_not_a_leaf_copy_keeps_set(
    parts: list[dict[str, str]],
) -> None:
    out = _set_value(LENS_SOURCE + '    msg.set("PV1-19", "X")\n', {"parts": parts})
    assert "set_data" not in out
    assert _native_rows(out)[-1]["action"] == "set_field"


def test_an_inserted_set_field_template_copying_a_leaf_writes_with_set_data() -> None:
    anchor = parse_source(LENS_SOURCE)[0]["rows"][0]
    out = rewrite_source(
        LENS_SOURCE,
        {
            "op": "insert_row",
            "line_start": anchor["line_start"],
            "line_end": anchor["line_end"],
            "position": "after",
            "action": "set_field",
            "params": {"path": "PV1-19", "value": {"expr": "f\"{msg['PID-3.1'] or ''}\""}},
        },
    )
    assert "msg.set_data(\"PV1-19\", f\"{msg['PID-3.1'] or ''}\")" in out
    assert _native_rows(out)[-1]["action"] == "set_field"


def test_a_set_field_template_into_a_leaf_keeps_set() -> None:
    # At a leaf destination set and set_data write the same thing, so the lens keeps set there.
    out = _set_value(
        LENS_SOURCE + '    msg.set("PV1-19.1", "X")\n', {"parts": [{"path": "PID-3.1"}]}
    )
    assert "    msg.set(\"PV1-19.1\", f\"{msg['PID-3.1'] or ''}\")\n" in out
    assert _native_rows(out)[-1]["action"] == "set_field"


def test_a_set_field_template_holding_a_field_separator_writes_with_set_data() -> None:
    # set refuses a field separator in a whole field, so text holding one can only mean data.
    parts = [{"text": "A|"}, {"path": "PID-3.1"}]
    out = _set_value(LENS_SOURCE + '    msg.set("PV1-19", "X")\n', {"parts": parts})
    assert "    msg.set_data(\"PV1-19\", f\"A|{msg['PID-3.1'] or ''}\")\n" in out
    assert _native_rows(out)[-1]["param_parts"]["value"] == parts


def _set_path(source: str, path: str) -> str:
    row = _native_rows(source)[-1]
    return rewrite_source(
        source,
        {
            "op": "set_params",
            "line_start": row["line_start"],
            "line_end": row["line_end"],
            "params": {"path": path},
        },
        contract=CONTRACT_V2,
    )


def test_a_set_field_path_edit_re_picks_the_write() -> None:
    source = LENS_SOURCE + "    msg.set_data(\"PV1-19\", f\"{msg['PID-3.1'] or ''}\")\n"
    to_leaf = _set_path(source, "PV1-19.1")
    assert to_leaf.endswith("    msg.set(\"PV1-19.1\", f\"{msg['PID-3.1'] or ''}\")\n")
    assert _native_rows(to_leaf)[-1]["action"] == "set_field"
    back = _set_path(to_leaf, "PV1-20")
    assert back.endswith("    msg.set_data(\"PV1-20\", f\"{msg['PID-3.1'] or ''}\")\n")
    assert _native_rows(back)[-1]["action"] == "set_field"


def test_an_edit_that_changes_nothing_leaves_a_hand_written_write_alone() -> None:
    source = LENS_SOURCE + "    msg.set(\"PV1-19\", f\"{msg['PID-3.1'] or ''}\")\n"
    row = _native_rows(source)[-1]
    assert _set_value(source, {"parts": row["param_parts"]["value"]}) == source


def test_an_edit_that_only_respells_a_quote_leaves_the_write_alone() -> None:
    source = LENS_SOURCE + "    msg.set('PV1-19', f\"{msg['PID-3.1'] or ''}\")\n"
    out = _set_path(source, "PV1-19")
    assert "msg.set(" in out and "set_data" not in out


def test_an_edit_that_only_drops_a_u_prefix_leaves_the_write_alone() -> None:
    source = LENS_SOURCE + "    msg.set(u\"PV1-19\", f\"{msg['PID-3.1'] or ''}\")\n"
    out = _set_path(source, "PV1-19")
    assert "msg.set(" in out and "set_data" not in out


@pytest.mark.parametrize("sep", [":", ">", "*"])
def test_a_set_field_template_holding_an_x12_separator_writes_with_set_data(sep: str) -> None:
    # Vault #2861: the lens protects HL7, the default, and holds no X12 separator. On X12 the
    # set_data line raises on a component separator rather than split it (tests/test_x12_parsing.py).
    parts = [{"path": "PID-3.1"}, {"text": f"{sep}B"}]
    out = _set_value(LENS_SOURCE + '    msg.set("PV1-19", "X")\n', {"parts": parts})
    assert f"    msg.set_data(\"PV1-19\", f\"{{msg['PID-3.1'] or ''}}{sep}B\")\n" in out
    row = _native_rows(out)[-1]
    assert row["action"] == "set_field" and row["param_parts"]["value"] == parts


@pytest.mark.parametrize("sep", [":", ">", "*"])
def test_an_hl7_template_holding_an_x12_separator_keeps_an_escaped_leaf_as_data(sep: str) -> None:
    # Vault #2861's reading: "MRN: {PID-3.1}" over PID-3.1 = 12\S\34. While these characters kept
    # set, the decoded 12^34 landed as two components of PV1-19. set_data keeps it one.
    body = MSH + CR + "PID|1||12" + _esc("S") + "34^^^MRN" + CR + "PV1|1|I" + CR
    parts = [{"text": f"MRN{sep} "}, {"path": "PID-3.1"}]
    out = _set_value(LENS_SOURCE + '    msg.set("PV1-19", "X")\n', {"parts": parts})
    line = out.splitlines()[-1].strip()
    assert line.startswith('msg.set_data("PV1-19", ')
    msg = Message.parse(body)
    exec(line, {"msg": msg})  # the lens's own output, run as the handler body would run it
    assert msg.field("PV1-19.1") == f"MRN{sep} 12^34"
    assert msg.field("PV1-19.2") is None
    assert _segment(msg, 2).endswith(f"|MRN{sep} 12" + _esc("S") + "34")


@pytest.mark.parametrize(
    "value",
    [
        pytest.param('"X"', id="plain-literal"),
        pytest.param("f\"A^{msg['PID-3.1'] or ''}\"", id="authored-structure"),
        pytest.param("f\"{msg['PID-3'] or ''}\"", id="whole-field-read"),
    ],
)
def test_any_set_data_value_into_a_leaf_reads_back_as_set_field(value: str) -> None:
    # At a leaf destination set_data and set write the same thing, so the value does not matter.
    row = _native_rows(LENS_SOURCE + f'    msg.set_data("PV1-19.1", {value})\n')[-1]
    assert row["action"] == "set_field"


@pytest.mark.parametrize("method", ["set", "set_data"])
@pytest.mark.parametrize(
    "value",
    [
        pytest.param('"A^B"', id="literal-with-a-separator"),
        pytest.param("family", id="expression"),
        pytest.param("f\"A^{msg['PID-3.1'] or ''}\"", id="authored-structure"),
    ],
)
def test_a_path_edit_never_moves_a_leafs_data_write_into_a_whole_field_as_set(
    method: str, value: str
) -> None:
    # At a leaf either write escaped the value, so it was data; set into a whole field would make
    # its separators structure, and set_data there would not read back as a step. So it is refused.
    source = LENS_SOURCE + f'    msg.{method}("PV1-19.1", {value})\n'
    with pytest.raises(LensRewriteError, match="as data"):
        _set_path(source, "PV1-19")
    # Naming the value too, unchanged, is the same edit.
    row = _native_rows(source)[-1]
    if value != "family":
        parts = row.get("param_parts", {}).get("value")
        resent = {"parts": parts} if parts is not None else ast.literal_eval(value)
        with pytest.raises(LensRewriteError, match="as data"):
            rewrite_source(
                source,
                {
                    "op": "set_params",
                    "line_start": row["line_start"],
                    "line_end": row["line_end"],
                    "params": {"path": "PV1-19", "value": resent},
                },
                contract=CONTRACT_V2,
            )
    # Another leaf is fine: there the two writes are the same.
    assert _native_rows(_set_path(source, "PV1-20.1"))[-1]["action"] == "set_field"
    # A value edit is the author writing anew, so the pick runs as it does on insert.
    if value != "family":
        assert _set_value(source, "C^D").endswith('    msg.set("PV1-19.1", "C^D")\n')


@pytest.mark.parametrize(
    ("line", "path", "want"),
    [
        pytest.param('msg.set("PV1-19.1", "AB")', "PV1-19", 'msg.set("PV1-19", "AB")', id="plain"),
        # Vault #2861: an X12 separator is plain text to the lens, which HL7 writes the same at a
        # leaf and in a whole field. So the move is not refused, and either write becomes set.
        pytest.param(
            'msg.set("PV1-19.1", "A:B")',
            "PV1-19",
            'msg.set("PV1-19", "A:B")',
            id="plain-with-an-x12-separator",
        ),
        pytest.param(
            'msg.set_data("PV1-19.1", "A:B")',
            "PV1-19",
            'msg.set("PV1-19", "A:B")',
            id="plain-set-data-with-an-x12-separator",
        ),
        pytest.param(
            "msg.set_data(\"PV1-19\", f\"{msg['PID-3.1'] or ''}\")",
            "PV1-20",
            "msg.set_data(\"PV1-20\", f\"{msg['PID-3.1'] or ''}\")",
            id="whole-to-whole-data-template",
        ),
        pytest.param(
            "msg.set_data(\"PV1-19.1\", f\"{msg['PID-3.1'] or ''}\")",
            "PV1-19",
            "msg.set_data(\"PV1-19\", f\"{msg['PID-3.1'] or ''}\")",
            id="leaf-to-whole-data-template",
        ),
        pytest.param(
            'msg.set("PV1-19", family)', "PV1-19.1", 'msg.set("PV1-19.1", family)', id="to-leaf"
        ),
    ],
)
def test_a_path_edit_that_keeps_the_meaning_is_not_refused(line: str, path: str, want: str) -> None:
    out = _set_path(LENS_SOURCE + f"    {line}\n", path)
    assert out.splitlines()[-1] == f"    {want}"


def test_a_set_data_template_holding_a_colon_reads_back_as_set_field() -> None:
    # Vault #2861: a colon no longer keeps set, so this is the line the lens writes, and it reads
    # back as the step that wrote it.
    source = LENS_SOURCE + "    msg.set_data(\"PV1-19\", f\"MRN: {msg['PID-3.1'] or ''}\")\n"
    row = _native_rows(source)[-1]
    assert row["action"] == "set_field"
    assert row["param_parts"]["value"] == [{"text": "MRN: "}, {"path": "PID-3.1"}]


def test_the_no_change_test_leaves_the_tree_it_reads_as_it_was() -> None:
    tree = ast.parse('msg.set(u"PV1-19", "x")')
    first = ast.dump(tree)
    assert _argument_dump(tree) == ast.dump(ast.parse('msg.set("PV1-19", "x")'))
    assert ast.dump(tree) == first


def test_a_set_data_template_into_a_leaf_still_reads_back_as_set_field() -> None:
    # At a leaf set_data is set, so a line the lens would write elsewhere still reads as a step.
    source = LENS_SOURCE + "    msg.set_data(\"PV1-19.1\", f\"{msg['PID-3.1'] or ''}\")\n"
    row = _native_rows(source)[-1]
    assert row["action"] == "set_field"
    assert row["param_parts"]["value"] == [{"path": "PID-3.1"}]
    # A set_data template the lens would never write is code, not a step.
    authored = LENS_SOURCE + "    msg.set_data(\"PV1-19\", f\"A^{msg['PID-3.1'] or ''}\")\n"
    assert _native_rows(authored)[-1].get("action") != "set_field"


NO_MSH = "BHS|" + ENC + CR + "PID|1||111" + CR


@pytest.mark.parametrize(
    ("body", "path", "value", "kwargs"),
    [
        pytest.param(NO_MSH, "ZZZ-3", "A^B", {}, id="absent-segment-no-msh"),
        pytest.param(ONE, "ZZZ-3", "A^B", {}, id="absent-segment"),
        pytest.param(ONE, "PID", "A" + CR + "B", {}, id="bad-path-and-cr"),
        pytest.param(ONE, "PID-x", "A^B", {"occurrence": 0}, id="bad-path-and-occurrence"),
        pytest.param(ONE, "MSH-1", "A|B", {}, id="msh-1"),
        pytest.param(ONE, "MSH-2", "A|B", {}, id="msh-2"),
        pytest.param(ONE, "MSH-2", ENC, {}, id="msh-2-unchanged"),
    ],
)
def test_set_data_fails_exactly_as_set_fails_for_the_same_write(
    body: str, path: str, value: str, kwargs: dict[str, int]
) -> None:
    outcomes: list[object] = []
    for method in ("set", "set_data"):
        msg = Message.parse(body)
        try:
            getattr(msg, method)(path, value, **kwargs)
        except (KeyError, ValueError) as exc:
            outcomes.append(type(exc))
        else:
            outcomes.append(msg.encode())
    assert outcomes[0] == outcomes[1]


def _copy_leaf_as_data(msg: Message) -> Send:
    msg.set_data("PV1-19", msg.field("PID-3.1") or "")
    return Send("out", msg)


def _copy_leaf_to_a_leaf(msg: Message) -> Send:
    msg.set("PV1-19.1", msg.field("PID-3.1") or "")
    return Send("out", msg)


@pytest.mark.parametrize("handler_fn", [_copy_leaf_as_data, _copy_leaf_to_a_leaf])
def test_the_dry_run_trace_records_a_set_data_write_as_set_records_it(handler_fn: Any) -> None:
    reg = _registry(_mllp_ic())
    reg.handlers["h"] = handler_fn
    trace = trace_dry_run(reg, P5_BODY.encode("utf-8"), inbound="in", show_phi=True)
    inv = next(i for i in trace["invocations"] if i["kind"] == "handler")
    writes = [w for ev in inv["events"] for w in ev.get("writes", [])]
    assert [w["value"] for w in writes] == ["A^B~C&D"]


async def test_the_remote_split_runs_off_the_event_loop_and_keeps_file_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    loop_thread = threading.get_ident()
    threads: list[int] = []
    original = split_mod.split_batch_bytes

    def _spy(raw: bytes, encoding: str) -> list[bytes]:
        threads.append(threading.get_ident())
        return original(raw, encoding)

    monkeypatch.setattr("messagefoundry.transports.remotefile.split_batch_bytes", _spy)
    client = _FakeClient(files={"/in/batch.hl7": "".join(THREE).encode("utf-8")})
    src = _remote_src(monkeypatch, client)
    handler = _RecordingHandler()
    src._handler = handler
    await _settle(src)
    await src._poll_once()
    assert threads and loop_thread not in threads
    assert [b.decode("utf-8").split("|")[9] for b in handler.bodies] == ["CTRL1", "CTRL2", "CTRL3"]


@pytest.mark.parametrize("count", [1, 2])
async def test_a_bom_led_remote_file_gets_the_same_disposition_per_message(
    monkeypatch: pytest.MonkeyPatch, store: MessageStore, count: int
) -> None:
    body = (chr(0xFEFF) + "".join(THREE[:count])).encode("utf-8")
    client = _FakeClient(files={"/in/batch.hl7": body})
    src = _remote_src(monkeypatch, client)
    ic = _remote_ic()
    runner = wiring_runner.RegistryRunner(
        _registry(ic), store, egress=EgressSettings(deny_by_default=False)
    )
    src._handler = runner._make_handler(ic)
    await _settle(src)
    await src._poll_once()
    assert [r["status"] for r in await _rows(store)] == [MessageStatus.RECEIVED.value] * count


@pytest.mark.parametrize("lead", ["", " "])
def test_one_bom_led_message_loses_its_mark_before_hand_off(lead: str) -> None:
    raw = (lead + chr(0xFEFF) + " " + THREE[0]).encode("utf-8")
    want = THREE[0].encode("utf-8")
    assert split_batch_bytes(raw, "utf-8") == [want]
    assert split_messages(raw) == [want]
    # Not followed by MSH, the mark stays, and the parser records the ERROR as for any noise.
    junk = (chr(0xFEFF) + "JUNK|1" + CR).encode("utf-8")
    assert split_batch_bytes(junk, "utf-8") == [junk]
    # Under a charset where those bytes are three letters, they are not a mark at all.
    latin = (chr(0xFEFF) + THREE[0]).encode("utf-8")
    assert split_batch_bytes(latin, "latin-1") == [latin]


async def test_the_file_source_hands_one_bom_led_message_over_without_its_mark(
    tmp_path: Path,
) -> None:
    source = FileSource(Source(type=ConnectorType.FILE, settings={"directory": str(tmp_path)}))
    handler = _RecordingHandler()
    source._handler = handler
    assert await source._emit((chr(0xFEFF) + THREE[0]).encode("utf-8")) is True
    assert handler.bodies == [THREE[0].encode("utf-8")]


ENVELOPED_ONE = "FHS|" + ENC + CR + "BHS|" + ENC + CR + THREE[0] + "BTS|1" + CR + "FTS|1" + CR


async def test_one_enveloped_message_goes_over_as_the_split_reads_it(tmp_path: Path) -> None:
    # The parser refuses a body led by FHS, so one message in an envelope goes as a batch member.
    raw = ENVELOPED_ONE.encode("utf-8")
    want = (THREE[0] + "BTS|1" + CR + "FTS|1" + CR).encode("utf-8")
    assert split_batch_bytes(raw, "utf-8") == [want]
    assert split_messages(raw) == [want]
    source = FileSource(Source(type=ConnectorType.FILE, settings={"directory": str(tmp_path)}))
    handler = _RecordingHandler()
    source._handler = handler
    assert await source._emit(raw) is True
    assert handler.bodies == [want]


async def test_one_enveloped_remote_message_is_recorded(
    monkeypatch: pytest.MonkeyPatch, store: MessageStore
) -> None:
    client = _FakeClient(files={"/in/one.hl7": ENVELOPED_ONE.encode("utf-8")})
    src = _remote_src(monkeypatch, client)
    ic = _remote_ic()
    runner = wiring_runner.RegistryRunner(
        _registry(ic), store, egress=EgressSettings(deny_by_default=False)
    )
    src._handler = runner._make_handler(ic)
    await _settle(src)
    await src._poll_once()
    assert [r["status"] for r in await _rows(store)] == [MessageStatus.RECEIVED.value]


def test_one_bom_led_message_goes_over_as_the_split_reads_it() -> None:
    # Past a byte order mark the message is handed over as a batch member is: line ends become CR.
    lf = chr(10)
    raw = (chr(0xFEFF) + THREE[0].replace(CR, lf)).encode("utf-8")
    assert split_batch_bytes(raw, "utf-8") == [THREE[0].encode("utf-8")]
    assert split_messages(raw) == [THREE[0].encode("utf-8")]
    # With nothing the parser refuses before MSH, a one-message file keeps its own line ends.
    plain = (" " + THREE[0].replace(CR, lf)).encode("utf-8")
    assert split_batch_bytes(plain, "utf-8") == [plain]
    assert split_messages(plain) == [plain]


def _rewrite_all(fields: list[str], target: tuple[str, str, str, str, str]) -> list[str]:
    out = []
    for field in fields:
        try:
            out.append(reencode_with_separators(MSH + CR + "OBX|1|ST|C||" + field + CR, target))
        except ValueError as exc:
            out.append(type(exc).__name__)
    return out


@pytest.mark.parametrize(
    "target",
    [
        pytest.param(("|", "^", "~", "#", BS), id="sub-#"),
        pytest.param(("|", "!", "~", "&", BS), id="comp-!"),
        pytest.param(("#", "^", "~", "&", BS), id="field-#"),
        pytest.param(("|", "^", "~", "&", "#"), id="esc-#"),
    ],
)
def test_the_split_rewrite_matches_the_character_walk(
    monkeypatch: pytest.MonkeyPatch, target: tuple[str, str, str, str, str]
) -> None:
    # Random fields over escapes, separators, target delimiters and escape letters, including
    # unclosed escapes, empty sequences and separators inside an open one. Fixed seed.
    rng = random.Random(2559)
    alphabet = ["A", "x", BS, BS, "^", "~", "&", "#", "!", "F", "S", "T", "R", "E", "H", ".br"]
    fields = ["".join(rng.choices(alphabet, k=rng.randint(0, 24))) for _ in range(400)]
    fast = _rewrite_all(fields, target)
    monkeypatch.setattr(_builtin_hl7._LeafRewrite, "__call__", _builtin_hl7._LeafRewrite._walk)
    assert fast == _rewrite_all(fields, target)


def test_a_field_of_many_distinct_escapes_rewrites_past_the_cache_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # More distinct sequences than the cache keeps, each also repeated, in one field.
    count = _builtin_hl7._SEQUENCE_CACHE_MAX * 3
    seqs = [BS + "Z" + format(n, "x") + BS + "#" for n in range(count)]
    field = "".join(seqs + seqs)
    target = ("|", "^", "~", "#", BS)
    fast = _rewrite_all([field], target)
    # The rewrite ran: each "#" became data under the target set, where it is the subcomponent mark.
    assert fast[0].count(_esc("T")) == 2 * count
    monkeypatch.setattr(_builtin_hl7._LeafRewrite, "__call__", _builtin_hl7._LeafRewrite._walk)
    assert fast == _rewrite_all([field], target)
