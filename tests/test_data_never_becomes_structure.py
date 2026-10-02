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
import time
from pathlib import Path
from typing import Any

import pytest

from messagefoundry import actions
from messagefoundry.checks import _check_handler_security
from messagefoundry.config.models import (
    ConnectorType,
    ContentType,
    Destination,
    Source,
    Validation,
)
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.lens import (
    REFUSAL_COLUMN_LIMIT,
    LensRewriteError,
    parse_source,
    rewrite_source,
)
from messagefoundry.parsing import _builtin_hl7
from messagefoundry.parsing import split as split_mod
from messagefoundry.parsing.message import Message, reencode_with_separators
from messagefoundry.parsing.split import split_batch, split_batch_bytes
from messagefoundry.pipeline import ingress_guards, wiring_runner
from messagefoundry.pipeline.dryrun import dry_run, split_messages
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
    runner = wiring_runner.RegistryRunner(reg, store)
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
    runner = wiring_runner.RegistryRunner(reg, store)
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
    runner = wiring_runner.RegistryRunner(_registry(ic), store)
    src._handler = runner._make_handler(ic)
    await _settle(src)
    await src._poll_once()
    # One row per message the file holds: none is dropped and none is folded into another's ERROR.
    rows = await _rows(store)
    assert len(rows) == count
    if lead != chr(0xFEFF) or count > 1:
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
        assert bytes_parts == [raw]


def test_a_first_chunk_that_is_not_an_envelope_is_kept_for_the_parser() -> None:
    parts = split_batch("JUNK|1" + CR + "".join(THREE[:2]))
    assert len(parts) == 3 and parts[0] == "JUNK|1"
    enveloped = split_batch("FHS|" + ENC + CR + "BHS|" + ENC + CR + "".join(THREE[:2]))
    assert [p.split("|")[9] for p in enveloped] == ["CTRL1", "CTRL2"]
    # Only the envelope header lines are dropped; a segment after them is kept for the parser.
    stray = split_batch("BHS|" + ENC + CR + "EVN|junk" + CR + "".join(THREE[:2]))
    assert len(stray) == 3 and stray[0] == "EVN|junk"


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
    for lead in (chr(0xFEFF), " ", ""):
        raw = (lead + THREE[0]).encode("utf-8")
        assert split_batch_bytes(raw, "utf-8") == [raw]
        lf = raw.replace(CR.encode(), chr(10).encode())
        assert split_batch_bytes(lf, "latin-1") == [lf]


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

    def _stop_on_the_batch(raw: bytes, encoding: str) -> list[bytes]:
        if raw.count(b"MSH") > 1:
            src._stop.set()
        return original(raw, encoding)

    monkeypatch.setattr(
        "messagefoundry.transports.remotefile.split_batch_bytes", _stop_on_the_batch
    )
    await _settle(src)
    await src._poll_once()
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
