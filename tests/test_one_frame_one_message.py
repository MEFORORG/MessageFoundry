# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""One outbound frame holds exactly one message (ADR 0205, vault BACKLOG #2557).

Each section pins one rule of the ADR, and the tests marked as an audit probe reproduce that probe
from the injection audit. Such tests, the controls aside, were measured failing on the code before
ADR 0205: the payload was framed without a look inside it, a leaf write emitted a decoded hex escape
raw, and ingress took an HL7 v2 body with an embedded MLLP start byte. The three AC-5 probes were
rewritten after that measurement and their new bodies were not run against that code; what was
measured for them instead is in ADR 0205's AC-5 note of 2026-11-13. Synthetic data only.

Control bytes are written as escapes, never literally, so a byte grep of this file finds none.
"""

from __future__ import annotations

import asyncio
import random
import re
from contextlib import aclosing
from pathlib import Path
from typing import Any

import pytest

import messagefoundry.transports.framing as framing_mod
from messagefoundry import actions
from messagefoundry.config.models import (
    ConnectorType,
    ContentType,
    Destination,
    RetryPolicy,
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
from messagefoundry.framing import MLLP_CODEC, STX_ETX_CODEC, FrameCodec
from messagefoundry.parsing import _builtin_hl7, normalize, split
from messagefoundry.parsing import message as message_module
from messagefoundry.parsing.dicom.hl7_map import encode_segment
from messagefoundry.parsing.message import Message
from messagefoundry.parsing.peek import starts_with_msh
from messagefoundry.pipeline import ingress_guards, wiring_runner
from messagefoundry.pipeline.dryrun import dry_run
from messagefoundry.store import MessageStatus, MessageStore, OutboxStatus
from messagefoundry.transports.base import NegativeAckError
from messagefoundry.transports.framing import (
    MULTIPLE_MESSAGES_CODE,
    frame_for_delivery,
    frame_reply,
)
from messagefoundry.transports.mllp import MLLPDestination, MLLPSource
from messagefoundry.transports.tcp import TcpDestination, TcpSource
from messagefoundry.transports.timer import TimerSource
from messagefoundry.transports.x12 import X12Source
from tests._mllp_recorder import MllpRecorder

SB, EB, CR, BS, NUL = "\x0b", "\x1c", "\r", chr(92), "\x00"
ENC = "^~" + BS + "&"
MSH = f"MSH|{ENC}|SND|FAC|RCV|FAC|20260101120000||ADT^A01|CTRL1|P|2.5"
MSH2 = f"MSH|{ENC}|FORGED|FAC|RCV|FAC|20260101120000||ADT^A08|CTRL2|P|2.5"
HEX_EB_SB = BS + "X1C" + BS + BS + "X0B" + BS
SEPS = ("|", "^", "~", "&", BS)
CLEAN = MSH + CR + "PID|1||111^^^MRN||DOE^JANE" + CR
#: Audit probe P1: raw end, CR and start bytes, then a second message, in one body.
SMUGGLED = (
    MSH
    + CR
    + "PID|1||111^^^MRN||DOE^JANE"
    + EB
    + CR
    + SB
    + MSH2
    + CR
    + "PID|1||999^^^MRN||ROE"
    + CR
)
#: Audit probe P1, reverse direction: the STX/ETX codec's bytes inside an HL7 body.
SMUGGLED_STX = MSH + CR + "PID|1||111\x03\x02" + MSH2 + CR
#: Audit probe P15: an embedded start byte only, which an MLLP frame keeps as data.
EMBEDDED_SB = MSH + CR + "PID|1||111" + CR + SB + MSH2 + CR + "PID|1||999" + CR
#: ADR 0209: two whole messages in one payload, as a Handler bug or a pasted batch would Send it.
TWO = CLEAN + MSH2 + CR + "PID|1||999^^^MRN||ROE" + CR


def _frames(codec: FrameCodec, wire: bytes) -> list[bytes]:
    return list(codec.decoder().feed(wire))


def _pid5(msg: Message) -> str:
    """PID-5 as the encoder writes it, escapes and all."""
    pid = next(line for line in msg.encode().split(CR) if line.startswith("PID"))
    return pid.split("|")[5]


# --- rule 1: a delivery never frames a payload holding its codec's start or end byte -------------


def test_a_clean_payload_frames_exactly_as_before() -> None:
    assert frame_for_delivery(MLLP_CODEC, CLEAN, "utf-8", transport="MLLP") == MLLP_CODEC.frame(
        CLEAN
    )


#: An explicit TCP codec whose end byte is above 0x7F. CLEAN holds neither byte, so only the
#: added character can trip it: "É" encodes in UTF-8 as 0xC3 0x89, which a character check misses.
EXPLICIT = FrameCodec(start=0x05, end=0xC3)


@pytest.mark.parametrize(
    ("codec", "payload", "transport"),
    [
        pytest.param(MLLP_CODEC, SMUGGLED, "MLLP", id="P1-mllp-end-and-start"),
        pytest.param(STX_ETX_CODEC, SMUGGLED_STX, "TCP", id="P1-reverse-stx-etx"),
        pytest.param(MLLP_CODEC, EMBEDDED_SB, "MLLP", id="P15-start-byte-only"),
        pytest.param(EXPLICIT, CLEAN.replace("JANE", "J" + chr(0xC9) + "NE"), "TCP", id="explicit"),
    ],
)
def test_a_frame_byte_in_the_payload_is_a_permanent_refusal(
    codec: FrameCodec, payload: str, transport: str
) -> None:
    # Before ADR 0205 the codec wrapped these as asked, and the decoder read two frames (or one
    # frame holding a second start byte). This is the shape the audit measured.
    with pytest.raises(NegativeAckError) as caught:
        frame_for_delivery(codec, payload, "utf-8", transport=transport)
    assert caught.value.permanent is True
    assert caught.value.code == "framing"
    assert str(caught.value).startswith(transport + ": payload holds the frame ")
    # The text names a byte and a position, never the content.
    assert "DOE" not in str(caught.value) and "FORGED" not in str(caught.value)


def test_the_explicit_codec_control_frames_a_clean_payload() -> None:
    # The control for the explicit case above: the same codec frames CLEAN, so that refusal is the
    # added character's, not something CLEAN already held.
    assert frame_for_delivery(EXPLICIT, CLEAN, "utf-8", transport="TCP") == EXPLICIT.frame(CLEAN)


def test_an_unencodable_payload_is_the_content_free_permanent_refusal() -> None:
    with pytest.raises(NegativeAckError) as caught:
        frame_for_delivery(MLLP_CODEC, CLEAN.replace("JANE", "JÉNE"), "ascii", transport="MLLP")
    assert caught.value.permanent is True and caught.value.code == "encoding"


def _mllp(persistent: bool, no_ack: bool) -> MLLPDestination:
    settings: dict[str, object] = {
        "host": "127.0.0.1",
        "port": 1,
        "timeout_seconds": 1,
        "persistent": persistent,
        "no_ack": no_ack,
    }
    return MLLPDestination(Destination(name="out", type=ConnectorType.MLLP, settings=settings))


def _tcp(persistent: bool = False) -> TcpDestination:
    settings: dict[str, object] = {
        "host": "127.0.0.1",
        "port": 1,
        "framing": "stx_etx",
        "timeout_seconds": 1,
        "persistent": persistent,
    }
    return TcpDestination(Destination(name="out", type=ConnectorType.TCP, settings=settings))


async def _never_dial() -> Any:
    raise AssertionError("the refused payload opened a connection")


async def _refused_before_any_dial(
    monkeypatch: pytest.MonkeyPatch, dest: MLLPDestination | TcpDestination, payload: str
) -> NegativeAckError:
    """Send ``payload`` through ``dest``'s real ``send()`` with a dial that fails the test, close
    ``dest``, and return the refusal. The send-path tests of ADR 0205 and ADR 0209 share it, so
    each keeps only the payload it sends and what it asserts of the refusal."""
    async with aclosing(dest):
        monkeypatch.setattr(dest, "_dial", _never_dial)
        with pytest.raises(NegativeAckError) as caught:
            await dest.send(payload)
    return caught.value


@pytest.mark.parametrize("persistent", [False, True])
@pytest.mark.parametrize("no_ack", [False, True])
async def test_all_four_mllp_send_paths_refuse_before_any_dial(
    monkeypatch: pytest.MonkeyPatch, persistent: bool, no_ack: bool
) -> None:
    refusal = await _refused_before_any_dial(monkeypatch, _mllp(persistent, no_ack), SMUGGLED)
    assert refusal.permanent is True


@pytest.mark.parametrize("persistent", [False, True])
async def test_both_tcp_send_paths_refuse_before_any_dial(
    monkeypatch: pytest.MonkeyPatch, persistent: bool
) -> None:
    refusal = await _refused_before_any_dial(monkeypatch, _tcp(persistent), SMUGGLED_STX)
    assert refusal.permanent is True and str(refusal).startswith("TCP: ")


# --- rule 2: a leaf write never emits a raw control character -----------------------------------


def _write_back_decoded(msg: Message, src: str, dst: str) -> None:
    """The AC-5 edits that hand the leaf escaper a decoded control (ADR 0205, AC-5 note of
    2026-11-13): ``copy_field`` from a component, then a component write of the decoded read back
    onto ``src`` itself, which rule 2 governs whatever an action's design."""
    actions.copy_field(msg, src, dst)
    msg.set(src, msg.field(src) or "")


def test_P2_a_hex_escaped_frame_byte_survives_a_component_edit_escaped() -> None:
    msg = Message.parse(MSH + CR + "PID|1||111^^^MRN||doe" + HEX_EB_SB + "x^jane" + CR)
    actions.convert_case(msg, "PID-5.1", "upper")
    assert _pid5(msg) == "DOE" + HEX_EB_SB + "X^jane"
    _write_back_decoded(msg, "PID-5.1", "PID-5.3")
    encoded = msg.encode()
    assert SB not in encoded and EB not in encoded
    assert _pid5(msg) == "DOE" + HEX_EB_SB + "X^jane^DOE" + HEX_EB_SB + "X"
    # The read side still decodes it, so the round trip is faithful rather than lossy.
    assert msg.field("PID-5.1") == msg.field("PID-5.3") == "DOE" + EB + SB + "X"


def test_P2_a_hex_escaped_nul_does_not_re_enter_raw() -> None:
    msg = Message.parse(MSH + CR + "PID|1||111||doe" + BS + "X00" + BS + "^jane" + CR)
    actions.convert_case(msg, "PID-5.1", "upper")
    assert _pid5(msg) == "DOE" + BS + "X00" + BS + "^jane"
    _write_back_decoded(msg, "PID-5.1", "PID-5.3")
    assert NUL not in msg.encode()
    assert msg.field("PID-5.1") == msg.field("PID-5.3") == "DOE" + NUL


def test_P2_control_a_decoded_cr_is_still_refused() -> None:
    # convert_case edits the wire text and keeps a hex-escaped CR escaped (BACKLOG #5928), so no raw
    # CR reaches the wire and the value cannot split into a forged segment.
    msg = Message.parse(MSH + CR + "PID|1||111||doe" + BS + "X0D" + BS + "EVN^jane" + CR)
    actions.convert_case(msg, "PID-5.1", "upper")
    assert _pid5(msg) == "DOE" + BS + "X0D" + BS + "EVN^jane"
    assert [line[:3] for line in msg.encode().split(CR) if line] == ["MSH", "PID"]
    # The control (ADR 0205, AC-6 note): a CR written back as data is still refused and the message
    # is left unchanged, whether the CR is literal or decoded from the message's own \X0D\.
    before = msg.encode()
    with pytest.raises(ValueError, match="segment separator"):
        msg.set("PID-5.1", "doe" + CR + "EVN")
    decoded = msg.field("PID-5.1")
    assert decoded == "DOE" + CR + "EVN"
    with pytest.raises(ValueError, match="segment separator"):
        msg.set("PID-5.1", decoded)
    with pytest.raises(ValueError, match="segment separator"):
        actions.copy_field(msg, "PID-5.1", "PID-5.3")
    with pytest.raises(ValueError, match="segment separator"):
        actions.replace_literal(msg, "PID-5.1", "DOE", "doe" + CR + "EVN")
    assert msg.encode() == before


def test_P10_mllp_in_edit_mllp_out_is_one_frame() -> None:
    body = (
        MSH
        + CR
        + "PID|1||111^^^MRN||DOE^JANE|||||||||||||last"
        + HEX_EB_SB
        + CR
        + "PID|1||999^^^MRN||ROE^RICH"
        + CR
    )
    assert len(_frames(MLLP_CODEC, MLLP_CODEC.frame(Message.parse(body).encode()))) == 1
    msg = Message.parse(body)
    actions.convert_case(msg, "PID-18.1", "upper")
    assert len(_frames(MLLP_CODEC, MLLP_CODEC.frame(msg.encode()))) == 1
    _write_back_decoded(msg, "PID-18.1", "PID-19.1")
    # The first frame check above ran before copy_field. If copy_field raises, the msg.set write and
    # this second frame check do not run, and the test fails on that exception instead.
    assert len(_frames(MLLP_CODEC, MLLP_CODEC.frame(msg.encode()))) == 1
    assert msg.field("PID-18.1") == msg.field("PID-19.1") == "LAST" + EB + SB


@pytest.mark.parametrize(
    ("char", "escaped"),
    [
        (SB, BS + "X0B" + BS),
        (EB, BS + "X1C" + BS),
        (NUL, BS + "X00" + BS),
        ("\x01", BS + "X01" + BS),
        ("\x1b", BS + "X1B" + BS),
        ("\x7f", BS + "X7F" + BS),
        ("\t", "\t"),  # TAB is benign whitespace and passes raw
    ],
)
def test_every_leaf_escaper_hex_escapes_c0_and_del_except_tab(char: str, escaped: str) -> None:
    msg = Message.parse(CLEAN)
    msg.set("PID-5.2", "JA" + char + "NE")
    assert _pid5(msg) == "DOE^JA" + escaped + "NE"
    assert msg.field("PID-5.2") == "JA" + char + "NE"
    assert _builtin_hl7.escape_leaf("a" + char + "b", SEPS) == "a" + escaped + "b"
    assert encode_segment("ZXX", ["a" + char + "b"]) == "ZXX|a" + escaped + "b"


def test_the_structural_escapes_are_unchanged() -> None:
    expected = "O" + BS + "S" + BS + "B" + BS + "F" + BS + "x" + BS + "R" + BS + "y"
    expected += BS + "T" + BS + "z" + BS + "E" + BS
    assert _builtin_hl7.escape_leaf("O^B|x~y&z" + BS, SEPS) == expected


def test_a_separator_that_is_an_escape_letter_is_not_escaped_twice() -> None:
    # MSH-2 "F~\&": the component separator is F, the letter of the field-separator escape. A
    # chained replace rescanned the escape it had just written and turned \F\ into \\S\\. This pins
    # the one-pass output only: a re-parse still splits \F\ on F, a residual ADR 0205 leaves open.
    msh = "MSH|F~" + BS + "&|SND|FAC|RCV|FAC|20260101120000||ADTFA01|CTRL1|P|2.5"
    msg = Message.parse(msh + CR + "PID|1||111||DOEFJANE" + CR)
    msg.set("PID-5.1", "a|b")
    assert _pid5(msg) == "a" + BS + "F" + BS + "bFJANE"
    seps = ("|", "F", "~", "&", BS)
    assert _builtin_hl7.escape_leaf("a|b", seps) == "a" + BS + "F" + BS + "b"
    assert _builtin_hl7.unescape(_builtin_hl7.escape_leaf("a|bF", seps), seps) == "a|bF"


def _reference_escape(value: str, seps: tuple[str, str, str, str, str]) -> str:
    """An independent one-pass escaper: a regex alternation over every character to escape, with
    the alphabet written out here rather than read from the module under test."""
    field_sep, comp_sep, rep_sep, sub_sep, esc = seps
    controls = [chr(cp) for cp in range(0x20) if cp not in (0x09, 0x0A, 0x0D)] + [chr(0x7F)]
    table = {ch: f"{esc}X{ord(ch):02X}{esc}" for ch in controls}
    for char, code in ((sub_sep, "T"), (rep_sep, "R"), (comp_sep, "S"), (field_sep, "F")):
        table[char] = f"{esc}{code}{esc}"
    table[esc] = f"{esc}E{esc}"
    pattern = re.compile("[" + "".join(re.escape(ch) for ch in table) + "]")
    return pattern.sub(lambda m: table[m.group()], value)


#: Characters an escape body is made of. An escape character drawn from these cannot round-trip
#: through ``unescape``, which closes a sequence at the next escape character, so the inverse
#: check below draws its escape character from outside them.
_ESCAPE_BODY = frozenset("EFSRTX0123456789ABCDEF")


def test_escape_leaf_matches_a_reference_across_separator_sets() -> None:
    rng = random.Random(2557)
    letters = "EFSRTXHNabz"
    digits = "0129"
    punctuation = "|^~&" + BS + "#$*!@"
    controls = "".join(chr(cp) for cp in (0x00, 0x01, 0x0B, 0x1B, 0x1C, 0x1F, 0x7F))
    pool = letters + digits + punctuation + controls
    data = pool + "\t " + chr(0xE9) + chr(0x738B)
    for _ in range(3000):
        field_sep, comp_sep, rep_sep, sub_sep, esc = rng.sample(pool, 5)
        seps = (field_sep, comp_sep, rep_sep, sub_sep, esc)
        value = "".join(rng.choice(data) for _ in range(rng.randrange(0, 12)))
        escaped = _builtin_hl7.escape_leaf(value, seps)
        assert escaped == _reference_escape(value, seps), (seps, value)
        if esc not in _ESCAPE_BODY:
            assert _builtin_hl7.unescape(escaped, seps) == value, (seps, value)


# --- rule 3: a whole-field write, add_repetition and add_segment refuse 0x0B, 0x1C and NUL --------


@pytest.mark.parametrize("char", [SB, EB, NUL])
def test_writes_that_take_structure_refuse_frame_bytes_and_nul(char: str) -> None:
    msg = Message.parse(CLEAN)
    with pytest.raises(ValueError, match="frame byte or NUL"):
        msg.set("PID-5", "DOE^JA" + char + "NE")
    with pytest.raises(ValueError, match="frame byte or NUL"):
        msg.add_repetition("PID-3", "222" + char)
    with pytest.raises(ValueError, match="frame byte or NUL"):
        msg.add_segment("ZXX|a" + char)
    assert msg.encode() == CLEAN  # nothing was written


def test_the_three_frame_byte_tables_stay_in_step() -> None:
    # parsing may not import the codec, so the model spells MLLP's bytes as literals; this pins them
    # to the codec, to the ingress guard's copy, and to the leaf escaper's alphabet.
    frame = {chr(MLLP_CODEC.start), chr(MLLP_CODEC.end)}
    assert set(message_module._STRUCTURE_REFUSED) == frame | {NUL}
    assert set(ingress_guards._MLLP_FRAME_CHARS) == frame
    assert set(message_module._STRUCTURE_REFUSED) <= set(_builtin_hl7._HEX_ESCAPED_CONTROLS)


def test_other_c0_characters_still_pass_a_whole_field_write() -> None:
    msg = Message.parse(CLEAN)
    msg.set("PID-5", "DOE^JA\x01NE")
    assert _pid5(msg) == "DOE^JA\x01NE"


# --- rule 4: ingress refuses an HL7 v2 body with an embedded 0x0B or 0x1C -------------------------


def _ic(content_type: ContentType = ContentType.HL7V2) -> InboundConnection:
    return InboundConnection(
        "in",
        ConnectionSpec(ConnectorType.MLLP, {"host": "0.0.0.0", "port": 2575}),
        router="r",
        content_type=content_type,
        validation=Validation(strict=False, hl7_version="2.5"),
    )


@pytest.mark.parametrize(
    "body",
    [
        pytest.param(EMBEDDED_SB, id="P15-embedded-start"),
        pytest.param(SMUGGLED, id="P1-embedded-end-and-start"),
        pytest.param(CLEAN.replace(CR + "PID", CR + EB + CR + "PID"), id="blank-line-between"),
        pytest.param(CLEAN.replace("JANE", "JA" + SB + "NE"), id="inside-a-field"),
    ],
)
def test_ingress_refuses_an_embedded_frame_byte(body: str) -> None:
    with pytest.raises(ingress_guards.IngressFrameByteRejected) as caught:
        ingress_guards.check_decoded(body, _ic())
    assert caught.value.phase == "decode"
    assert caught.value.reason == ingress_guards.FRAME_BYTE_REJECTED_REASON


@pytest.mark.parametrize(
    "body",
    [
        pytest.param(SB + CLEAN, id="leading-start"),
        pytest.param(EB + CLEAN, id="leading-end"),
        pytest.param(" " + SB + CR + CLEAN, id="leading-run"),
        pytest.param(CLEAN + EB, id="trailing-end"),
        pytest.param(SB + CLEAN + EB + CR, id="a-whole-mllp-frame-saved-to-a-file"),
    ],
)
def test_a_frame_byte_around_the_message_stays_tolerated_and_never_reaches_the_encode(
    body: str,
) -> None:
    # The parser strips the whitespace at both ends with str.strip(), and the encode drops it (audit
    # probe P16), so such a byte cannot carry a second message and never reaches a delivery.
    ingress_guards.check_decoded(body, _ic())
    encoded = Message.parse(body).encode()
    assert SB not in encoded and EB not in encoded


def test_the_refusal_is_hl7v2_only() -> None:
    ingress_guards.check_decoded('{"a": "b' + SB + '"}', _ic(ContentType.JSON))


@pytest.fixture
async def store(tmp_path: Path) -> Any:
    s = await MessageStore.open(tmp_path / "frame.db")
    yield s
    await s.close()


def _registry() -> Registry:
    reg = Registry()
    reg.add_inbound(_ic())
    reg.add_outbound(
        OutboundConnection("out", ConnectionSpec(ConnectorType.FILE, {"directory": "."}))
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("out", m))
    return reg


async def test_P15_the_listener_naks_and_records_error(store: MessageStore) -> None:
    reg = _registry()
    runner = wiring_runner.RegistryRunner(reg, store, egress=EgressSettings(deny_by_default=False))
    ack = await runner._handle_inbound(reg.inbound["in"], EMBEDDED_SB.encode("utf-8"))
    assert ack is not None and "MSA|AR|" in ack and "MLLP frame byte in body" in ack
    cur = await store._db.execute("SELECT status, error FROM messages")
    rows = [dict(r) for r in await cur.fetchall()]
    assert rows == [
        {"status": MessageStatus.ERROR.value, "error": ingress_guards.FRAME_BYTE_REJECTED_REASON}
    ]
    preview = dry_run(reg, EMBEDDED_SB.encode("utf-8"))
    assert preview.disposition is MessageStatus.ERROR
    assert preview.error == ingress_guards.FRAME_BYTE_REJECTED_REASON


async def test_a_leading_frame_byte_is_still_received(store: MessageStore) -> None:
    reg = _registry()
    runner = wiring_runner.RegistryRunner(reg, store, egress=EgressSettings(deny_by_default=False))
    await runner._handle_inbound(reg.inbound["in"], (SB + CLEAN).encode("utf-8"))
    cur = await store._db.execute("SELECT status FROM messages")
    assert [dict(r)["status"] for r in await cur.fetchall()] == [MessageStatus.RECEIVED.value]


async def test_a_trailing_frame_byte_is_received_and_kept_in_the_stored_raw(
    store: MessageStore,
) -> None:
    # The listener stores the decoded text as received, so the stored raw keeps a trailing 0x1C.
    # The encode drops it, which is what pass-through sends; a path that sent the stored raw would
    # meet rule 1 and dead-letter, as the last assertion shows.
    reg = _registry()
    runner = wiring_runner.RegistryRunner(reg, store, egress=EgressSettings(deny_by_default=False))
    await runner._handle_inbound(reg.inbound["in"], (CLEAN + EB).encode("utf-8"))
    cur = await store._db.execute("SELECT id, status FROM messages")
    ((mid, status),) = [tuple(r) for r in await cur.fetchall()]
    assert status == MessageStatus.RECEIVED.value
    stored = await store.get_message(mid)
    assert stored is not None and stored["raw"].endswith(EB)
    assert EB not in Message.parse(stored["raw"]).encode()
    with pytest.raises(NegativeAckError):
        frame_for_delivery(MLLP_CODEC, stored["raw"], "utf-8", transport="MLLP")


# --- rule 1 at the delivery stage: a shadow (simulate) outbound ---------------------------------

DEST = "OB_FRAME"
DONE = (MessageStatus.PROCESSED.value, OutboxStatus.DONE.value)
DEAD = (MessageStatus.ERROR.value, OutboxStatus.DEAD.value)


def _send_recorder(**field: Any) -> MllpRecorder:
    """The shared recording MLLP destination, on this file's lane."""
    return MllpRecorder(DEST, **field)


async def _enqueue(store: MessageStore, bodies: list[str]) -> list[str]:
    return [
        await store.enqueue_message(channel_id="c1", raw=b, deliveries=[(DEST, b)], now=100.0 + i)
        for i, b in enumerate(bodies)
    ]


@pytest.mark.parametrize(
    ("setting", "field"),
    [
        pytest.param({}, {"hl7_raw_separators": True}, id="raw-separators"),
        pytest.param({"encoding_characters": "|^~" + BS + "&"}, {}, id="encoding-characters"),
    ],
)
async def test_check_frame_sees_the_payload_after_the_send_rewrites(
    setting: dict[str, object], field: dict[str, Any]
) -> None:
    # A delimiter rewrite re-serializes the message, which drops a frame byte at either end, so a
    # live send of CLEAN + 0x1C goes out. check_frame must judge the same rewritten bytes, or a
    # shadow outbound would dead-letter what a live one delivers.
    settings: dict[str, object] = {"host": "127.0.0.1", "port": 1, **setting}
    config = Destination(name=DEST, type=ConnectorType.MLLP, settings=settings, **field)
    async with aclosing(MLLPDestination(config)) as rewriting, aclosing(_send_recorder()) as plain:
        rewriting.check_frame(CLEAN + EB)
        with pytest.raises(NegativeAckError):
            rewriting.check_frame(EMBEDDED_SB)  # an interior start byte survives any rewrite
        with pytest.raises(NegativeAckError):
            plain.check_frame(CLEAN + EB)  # control: no rewrite, the byte reaches the frame


async def test_the_tcp_destination_check_frame_refuses_with_its_label() -> None:
    settings: dict[str, object] = {"host": "127.0.0.1", "port": 1, "framing": "stx_etx"}
    tcp = TcpDestination(Destination(name=DEST, type=ConnectorType.TCP, settings=settings))
    async with aclosing(tcp) as dest:
        dest.check_frame(CLEAN)
        with pytest.raises(NegativeAckError) as caught:
            dest.check_frame(SMUGGLED_STX)
    assert caught.value.permanent is True and str(caught.value).startswith("TCP: ")


@pytest.mark.parametrize(
    ("body", "expected", "field", "reason"),
    [
        pytest.param(SMUGGLED, DEAD, {}, "frame", id="smuggled"),
        pytest.param(CLEAN, DONE, {}, "", id="clean-control"),
        # ADR 0209: two messages in one payload dead-letter in shadow as a live send refuses them.
        pytest.param(TWO, DEAD, {}, "more than one MSH segment", id="two-messages"),
        # A live send refuses a payload its rewrite cannot re-encode, permanently (ADR 0204,
        # ADR 0206), and check_frame shares that rewrite, so shadow dead-letters it too.
        pytest.param(
            "plain text, no MSH",
            DEAD,
            {"hl7_raw_separators": True},
            "emit failed",
            id="unparseable",
        ),
    ],
)
async def test_a_shadow_outbound_records_what_a_live_send_would(
    store: MessageStore,
    body: str,
    expected: tuple[str, str],
    field: dict[str, Any],
    reason: str,
) -> None:
    # Rule 1 runs inside connector.send(), which a simulate outbound skips. Before the fix shadow
    # marked the smuggled row PROCESSED, where a live send would have dead-lettered it. The batch
    # twin is in tests/test_outbound_batch.py, which runs on every store backend.
    (mid,) = await _enqueue(store, [body])
    dest = _send_recorder(**field)
    runner = wiring_runner.RegistryRunner(
        Registry(), store, poll_interval=0.02, egress=EgressSettings(deny_by_default=False)
    )
    runner._destinations[DEST] = dest
    runner._retry[DEST] = RetryPolicy()
    runner._simulate[DEST] = True
    item = await store.claim_next_fifo(DEST)
    assert item is not None
    async with aclosing(dest):
        await runner._process_delivery_item(DEST, item)
    assert dest.sent == []
    msg = await store.get_message(mid)
    (row,) = await store.outbox_for(mid)
    assert msg is not None and (msg["status"], row["status"]) == expected
    error = str(row["last_error"] or "")
    assert "DOE" not in error and reason in error


# --- the reply path: a listener's reply is one frame, and framing it never raises ---------------


@pytest.fixture(autouse=True)
def _fresh_reply_warning_state(monkeypatch: pytest.MonkeyPatch) -> None:
    """Each test starts with empty warn-once sets, and its additions are discarded after it. The
    sets are module state, so a test counting warnings read whatever an earlier test, or an earlier
    run of itself in the same process, had added (PR 2975's open finding on BACKLOG #5799).
    Mutation: drop this fixture and add the connection to the fallback set before the run. Red:
    the fallback warning test sees no warning."""
    monkeypatch.setattr(framing_mod, "_reply_fallback_logged", set())
    monkeypatch.setattr(framing_mod, "_reply_replacement_logged", set())


def test_frame_reply_neutralises_a_frame_byte_instead_of_raising() -> None:
    reply = MSH + CR + "MSA|AA|C" + SB + "1" + EB + CR
    wire = frame_reply(MLLP_CODEC, reply, "utf-8")
    assert wire.count(b"\x0b") == 1 and wire.count(b"\x1c") == 1
    assert _frames(MLLP_CODEC, wire) == [(MSH + CR + "MSA|AA|C 1 " + CR).encode("utf-8")]
    assert frame_reply(MLLP_CODEC, CLEAN, "utf-8") == MLLP_CODEC.frame(CLEAN)


@pytest.mark.parametrize("encoding", ["not-a-real-codec", "undefined", "base64"])
def test_frame_reply_sends_utf8_when_the_inbound_charset_cannot_encode_it(encoding: str) -> None:
    """BACKLOG #2431: the runner answers an unusable codec name with AE, and that AE must still
    reach the sender rather than raise here after the ERROR row is written."""
    assert frame_reply(MLLP_CODEC, CLEAN, encoding) == MLLP_CODEC.frame(CLEAN)


def test_frame_reply_logs_its_utf8_fallback_by_connection_without_the_setting(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """CLAUDE.md section 6: the fallback is never silent. The setting is configuration that may hold
    anything, so the warning names the connection and leaves the value out."""
    with caplog.at_level("WARNING", logger="messagefoundry.transports.framing"):
        frame_reply(MLLP_CODEC, CLEAN, "zz-secretish-codec", connection="IB_FALLBACK_LOG_ADT")
        # Every message on that inbound fails alike, so a second reply adds no line.
        frame_reply(MLLP_CODEC, CLEAN, "zz-secretish-codec", connection="IB_FALLBACK_LOG_ADT")
    warnings = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
    assert len(warnings) == 1
    assert "IB_FALLBACK_LOG_ADT" in warnings[0] and "utf-8" in warnings[0]
    assert "zz-secretish-codec" not in warnings[0]


def test_frame_reply_still_raises_when_a_usable_charset_cannot_hold_the_reply() -> None:
    """``idna`` is a usable codec that raises for one reply. That is the reply's fault, so it is not
    sent in utf-8 under an "unusable charset" warning, as ``decode_body`` decides it by the name."""
    with pytest.raises(UnicodeError) as ei:
        frame_reply(MLLP_CODEC, "a" * 64, "idna", connection="IB_IDNA")
    # Round-one review of #5799: the strict encode's error holds the whole reply as `object`, so the
    # refusal is raised outside the handler and chains nothing.
    assert ei.value.__cause__ is None and ei.value.__context__ is None


@pytest.mark.parametrize("encoding", ["ascii", "latin-1", "cp1252"])
def test_frame_reply_replaces_what_a_narrow_charset_cannot_hold(
    encoding: str, caplog: pytest.LogCaptureFixture
) -> None:
    """BACKLOG #5799: the listener replies after the commit, so a raise here closed the connection
    unanswered and the sender resent a message already stored. The reply now stays in its declared
    charset with each character it cannot hold replaced, and is sent. Mutation: re-raise the
    UnicodeEncodeError in frame_reply. Red: the call raises."""
    reply = MSH + CR + "MSA|AA|CTRL1|中文" + CR
    connection = f"IB_NARROW_{encoding.upper()}"
    # The warn-once sets are module state, emptied for each test by _fresh_reply_warning_state.
    with caplog.at_level("WARNING", logger="messagefoundry.transports.framing"):
        wire = frame_reply(MLLP_CODEC, reply, encoding, connection=connection)
        # A narrow charset meets the same characters on every message, so a second reply adds no
        # line, as the utf-8 fallback's warning does not.
        frame_reply(MLLP_CODEC, reply, encoding, connection=connection)
    assert _frames(MLLP_CODEC, wire) == [(MSH + CR + "MSA|AA|CTRL1|??" + CR).encode(encoding)]
    warnings = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
    assert len(warnings) == 1
    assert connection in warnings[0] and "replaced" in warnings[0]
    # Neither the reply nor the setting reaches the log, and this is not the utf-8 fallback.
    assert "CTRL1" not in warnings[0] and encoding not in warnings[0]
    assert "utf-8" not in warnings[0]


def test_the_reporting_variants_flag_a_replaced_reply_every_time() -> None:
    """BACKLOG #5799 item 1: the warning is once per connection, but the flag a listener writes its
    ``reply_replaced`` event from is set on every reply replaced, and on no other. A clean reply and
    the utf-8 fallback for an unusable charset name are not replacements."""
    reply = MSH + CR + "MSA|AA|CTRL1|\u00e9" + CR
    for _ in range(2):
        wire, replaced = framing_mod.frame_reply_reporting(
            MLLP_CODEC, reply, "ascii", connection="IB_FLAG"
        )
        assert replaced and wire == frame_reply(MLLP_CODEC, reply, "ascii", connection="IB_FLAG")
        assert framing_mod.encode_reply_reporting(reply, "ascii", connection="IB_FLAG")[1]
    assert not framing_mod.frame_reply_reporting(MLLP_CODEC, CLEAN, "ascii")[1]
    assert not framing_mod.encode_reply_reporting(reply, "utf-8")[1]
    assert not framing_mod.encode_reply_reporting(reply, "not-a-real-codec")[1]
    # A frame byte turned into a space is not a charset replacement, and sets no flag.
    framed, replaced = framing_mod.frame_reply_reporting(
        MLLP_CODEC, MSH + CR + "MSA|AA|C" + SB + "1" + CR, "ascii"
    )
    assert not replaced and framed.count(b"\x0b") == 1


@pytest.mark.parametrize(
    "msh2",
    ["?~" + BS + "&", "^?" + BS + "&", "^~?&", "^~" + BS + "?"],
    ids=["comp", "rep", "esc", "sub"],
)
def test_frame_reply_refuses_a_replacement_that_is_one_of_the_replys_delimiters(msh2: str) -> None:
    """BACKLOG #5799, round-two review: HL7 lets a sender pick ``?`` as a delimiter, and the ACK
    echoes it, so a ``?`` written for an unencodable character would become structure (ADR 0206).
    Such a reply is refused with the fixed error, chaining nothing. Mutation: drop the delimiter
    check in _encode_replacing. Red: the call returns a reply with an extra delimiter."""
    reply = f"MSH|{msh2}|R|RF|S|F|20260101||ACK|CTRL1|P|2.5" + CR + "MSA|AA|CTRL1|中" + CR
    with pytest.raises(UnicodeError, match="collide with one of its own delimiters") as ei:
        frame_reply(MLLP_CODEC, reply, "ascii", connection="IB_QDELIM")
    assert ei.value.__cause__ is None and ei.value.__context__ is None


def test_control_a_field_separator_of_question_mark_is_refused_too() -> None:
    reply = "MSH?^~" + BS + "&?R?RF" + CR + "MSA?AA?CTRL1?中" + CR
    with pytest.raises(UnicodeError, match="collide with one of its own delimiters"):
        frame_reply(MLLP_CODEC, reply, "ascii", connection="IB_QDELIM")
    # And a reply needing no replacement is untouched by the check, delimiters and all.
    clean = "MSH?^~" + BS + "&?R?RF" + CR
    assert frame_reply(MLLP_CODEC, clean, "ascii") == MLLP_CODEC.frame(clean.encode("ascii"))


def test_frame_reply_refuses_a_delimiter_the_charset_cannot_hold() -> None:
    """Round-three review of #5799: an unencodable MSH-1 would itself become ``?`` beside a replaced
    data character, and the two would read as one delimiter. Mutation: drop the encodability test
    from the delimiter check. Red: the call returns a reply whose fields have shifted."""
    reply = "MSH\u00a6^~" + BS + "&\u00a6R\u00a6RF" + CR + "MSA\u00a6AA\u00a6CTRL1\u00a6\u4e2d" + CR
    with pytest.raises(UnicodeError, match="collide with one of its own delimiters") as ei:
        frame_reply(MLLP_CODEC, reply, "ascii", connection="IB_UNENCODABLE_DELIM")
    assert ei.value.__cause__ is None and ei.value.__context__ is None
    # Control: latin-1 holds the delimiter, so only the data character is replaced and it answers.
    wire = frame_reply(MLLP_CODEC, reply, "latin-1", connection="IB_UNENCODABLE_DELIM")
    assert wire == MLLP_CODEC.frame(reply.replace("\u4e2d", "?").encode("latin-1"))


@pytest.mark.parametrize("head", ["MSH", "MSH\r\n"], ids=["bare-msh", "msh-then-lf"])
def test_frame_reply_reads_no_delimiters_from_a_header_too_short_to_declare_them(head: str) -> None:
    """Round-three review of #5799: a first line of ``MSH`` alone raised IndexError out of the
    delimiter read. It declares no delimiters, so the reply is replaced and answered. Mutation:
    measure the whole reply rather than its first line. Red: IndexError."""
    reply = head + "\r" + "MSA|AA|CTRL1|\u4e2d" + CR
    wire = frame_reply(MLLP_CODEC, reply, "ascii", connection="IB_SHORT_MSH")
    assert wire == MLLP_CODEC.frame(reply.replace("\u4e2d", "?").encode("ascii"))


@pytest.mark.parametrize("lead", ["\ufeff", " \ufeff\r\n"], ids=["bom", "whitespace-and-bom"])
def test_frame_reply_reads_delimiters_past_a_leading_bom(lead: str) -> None:
    """Round-three review of #5799: a leading BOM hid the header, so a reply declaring ``?`` was
    sent with ``?`` written into its data. The BOM and whitespace are skipped as the engine's
    tolerated leading noise is. Mutation: drop the lstrip. Red: the call returns a reply."""
    reply = lead + "MSH|?~" + BS + "&|R|RF" + CR + "MSA|AA|CTRL1|\u4e2d" + CR
    with pytest.raises(UnicodeError, match="collide with one of its own delimiters"):
        frame_reply(MLLP_CODEC, reply, "latin-1", connection="IB_BOM")


def _isa(
    *, element: str = "*", component: str = ":", repetition: str = "^", term: str = "~"
) -> str:
    """A 106-character synthetic ISA header (106 plus one for a CR+LF terminator)."""
    fields = ["ISA", "00", " " * 10, "00", " " * 10, "ZZ", "SENDER".ljust(15), "ZZ"]
    fields += ["RECEIVER".ljust(15), "260101", "1200", repetition, "00501", "000000001", "0", "P"]
    return element.join([*fields, component]) + term


@pytest.mark.parametrize(
    ("header", "term"),
    [
        (_isa(component="?"), "~"),
        (_isa(repetition="?"), "~"),
        (_isa(element="?"), "~"),
        (_isa(term="?"), "?"),
    ],
    ids=["isa-component", "isa-repetition", "isa-element", "isa-terminator"],
)
def test_encode_reply_refuses_a_replacement_that_is_an_x12_replys_delimiter(
    header: str, term: str
) -> None:
    """BACKLOG #5799 item 2: the X12 listener's reply is an interchange, which declares its
    delimiters in its ISA, and X12 lets a sender pick ``?`` as one. Only an ``MSH``-led reply was
    read, so a ``?`` written for an unencodable character became structure. Red on the code
    before: the call returns the replaced reply."""
    element = header[3]
    reply = header + element.join(["TA1", "000000001", "260101", "1200", "A", "000中"]) + term
    with pytest.raises(UnicodeError, match="collide with one of its own delimiters") as ei:
        framing_mod.encode_reply(reply, "ascii", connection="IB_X12_QDELIM")
    assert ei.value.__cause__ is None and ei.value.__context__ is None


@pytest.mark.parametrize("term", ["~", "\r\n"], ids=["tilde", "crlf"])
def test_control_an_x12_reply_with_ordinary_delimiters_is_replaced_and_sent(term: str) -> None:
    """Control for the X12 refusal: with no ``?`` delimiter the data character is replaced, the
    reply is sent, and a CR+LF terminator reads as the two characters it is."""
    reply = _isa(term=term) + "TA1*000000001*260101*1200*A*000中" + term
    body, replaced = framing_mod.encode_reply_reporting(reply, "ascii", connection="IB_X12_OK")
    assert replaced and body == reply.replace("中", "?").encode("ascii")
    # A truncated ISA is no header the X12 read accepts, so it declares nothing and is replaced.
    short = "ISA*00*中" + "~"
    assert framing_mod.encode_reply(short, "ascii") == b"ISA*00*?~"


@pytest.mark.parametrize("head", ["BHS", "FHS"])
def test_frame_reply_reads_a_batch_headers_delimiters_as_an_msh(head: str) -> None:
    """BACKLOG #5799 item 2: a ``BHS`` or ``FHS`` header declares its delimiters in MSH-1 and MSH-2's
    layout, so a batch-led reply declaring ``?`` is refused as an ``MSH``-led one is. Red on the
    code before: the call returns a reply with ``?`` written into its data."""
    reply = head + "|?~" + BS + "&|R|RF" + CR + "MSH|?~" + BS + "&|R" + CR + "MSA|AA|C|中" + CR
    with pytest.raises(UnicodeError, match="collide with one of its own delimiters"):
        frame_reply(MLLP_CODEC, reply, "latin-1", connection="IB_BATCH_QDELIM")
    # Control: ordinary delimiters, so only the data character is replaced and it answers.
    plain = reply.replace("|?~", "|^~")
    wire = frame_reply(MLLP_CODEC, plain, "latin-1", connection="IB_BATCH_QDELIM")
    assert wire == MLLP_CODEC.frame(plain.replace("中", "?").encode("latin-1"))


def test_frame_reply_refuses_leading_noise_the_charset_cannot_hold() -> None:
    """Round-four review of #5799: with ordinary delimiters, a BOM-led reply was replaced into
    "?MSH|...", which no parser reads as an ACK. Mutation: drop the leading-noise check in
    _encode_replacing. Red: the call returns that reply."""
    reply = "\ufeffMSH|^~" + BS + "&|R|RF" + CR + "MSA|AA|CTRL1|\u4e2d" + CR
    with pytest.raises(UnicodeError, match="noise before its first segment") as ei:
        frame_reply(MLLP_CODEC, reply, "latin-1", connection="IB_BOM_LEAD")
    assert ei.value.__cause__ is None and ei.value.__context__ is None
    # Control: encodable leading whitespace stays, and only the data character is replaced.
    spaced = " MSH|^~" + BS + "&|R|RF" + CR + "MSA|AA|CTRL1|中" + CR
    wire = frame_reply(MLLP_CODEC, spaced, "latin-1", connection="IB_BOM_LEAD")
    assert wire == MLLP_CODEC.frame(spaced.replace("中", "?").encode("latin-1"))


@pytest.mark.parametrize("declared", [b"latin-1", 8859])
def test_a_listener_resolves_a_non_str_encoding_as_the_decode_does(declared: object) -> None:
    """BACKLOG #2431: a non-str name used to reach ``str.encode`` and raise ``TypeError``, so the AE
    the runner built for it was never sent. Both listeners now hold the name the decode reads."""
    mllp = MLLPSource(
        Source(
            type=ConnectorType.MLLP,
            settings={"host": "127.0.0.1", "port": 0, "encoding": declared},
        )
    )
    tcp = TcpSource(
        Source(
            type=ConnectorType.TCP,
            settings={"host": "127.0.0.1", "port": 0, "framing": "stx_etx", "encoding": declared},
        )
    )
    assert mllp.encoding == tcp.encoding == str(declared)
    assert frame_reply(MLLP_CODEC, CLEAN, mllp.encoding) == MLLP_CODEC.frame(CLEAN)
    assert frame_reply(STX_ETX_CODEC, CLEAN, tcp.encoding) == STX_ETX_CODEC.frame(CLEAN)


@pytest.mark.parametrize("declared", [None, ""])
def test_the_timer_and_x12_sources_read_an_undeclared_encoding_as_utf8(declared: object) -> None:
    """BACKLOG #2431: an explicit ``None`` or empty ``encoding`` is "not declared", as on the
    listeners. These sources used ``str()`` of it, so a timer refused to build on a ``LookupError``
    for a codec named ``None`` and an X12 source held that name for its replies."""
    timer = TimerSource(
        Source(
            type=ConnectorType.TIMER,
            settings={"body": "x", "run_once": True, "encoding": declared},
        )
    )
    x12 = X12Source(
        Source(
            type=ConnectorType.X12,
            settings={"host": "127.0.0.1", "port": 0, "encoding": declared},
        )
    )
    assert timer.encoding == x12.encoding == "utf-8"
    assert timer._body_bytes == b"x"


async def test_the_mllp_listener_sends_its_reply_when_its_encoding_is_not_a_str() -> None:
    async def handler(raw: bytes) -> str:
        return CLEAN

    source = MLLPSource(
        Source(
            type=ConnectorType.MLLP,
            settings={"host": "127.0.0.1", "port": 0, "encoding": b"latin-1"},
        )
    )
    await source.start(handler)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
        try:
            writer.write(MLLP_CODEC.frame(CLEAN))
            await writer.drain()
            got = await asyncio.wait_for(reader.readuntil(b"\x1c"), 5)
        finally:
            writer.close()
    finally:
        await source.stop()
    assert got == MLLP_CODEC.frame(CLEAN)[: len(got)]


async def test_the_mllp_listener_sends_one_frame_when_its_reply_holds_a_start_byte() -> None:
    reply = f"MSH|{ENC}|R|F|S|F|20260101||ACK|C{SB}1|P|2.5{CR}MSA|AA|C{SB}1{CR}"

    async def handler(raw: bytes) -> str:
        return reply

    source = MLLPSource(Source(type=ConnectorType.MLLP, settings={"host": "127.0.0.1", "port": 0}))
    await source.start(handler)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
        try:
            writer.write(MLLP_CODEC.frame(CLEAN))
            await writer.drain()
            got = await asyncio.wait_for(reader.readuntil(b"\x1c"), 5)
        finally:
            writer.close()
    finally:
        await source.stop()
    assert got.count(b"\x0b") == 1


def test_the_mllp_handler_fault_nak_is_one_frame_when_the_header_holds_a_start_byte() -> None:
    source = MLLPSource(Source(type=ConnectorType.MLLP, settings={"host": "127.0.0.1", "port": 0}))
    header = f"MSH|{ENC}|S|F|R|F|20260101||ADT^A01|C{SB}1|P|2.5{CR}"
    framed = source._handler_failure_nak(header.encode("utf-8"))
    assert framed is not None
    nak = framed[0]
    assert nak.count(b"\x0b") == 1 and nak.count(b"\x1c") == 1


async def test_the_tcp_listener_sends_one_frame_when_its_reply_holds_its_start_byte() -> None:
    reply = f"MSH|{ENC}|R|F|S|F|20260101||ACK|C\x021|P|2.5{CR}MSA|AA|C\x021{CR}"

    async def handler(raw: bytes) -> str:
        return reply

    source = TcpSource(
        Source(
            type=ConnectorType.TCP, settings={"host": "127.0.0.1", "port": 0, "framing": "stx_etx"}
        )
    )
    await source.start(handler)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
        try:
            writer.write(STX_ETX_CODEC.frame(CLEAN))
            await writer.drain()
            got = await asyncio.wait_for(reader.readuntil(b"\x03"), 5)
        finally:
            writer.close()
    finally:
        await source.stop()
    assert got.count(b"\x02") == 1


# --- ADR 0209: an MLLP or TCP delivery refuses an MSH-led payload holding a second MSH ----------
# The shadow single-row case is the "two-messages" row of the shadow test above; the batch cases
# are in tests/test_outbound_batch.py.

#: TWO with a byte order mark between its first message and its second MSH.
MARKED = CLEAN + split._BOM + TWO[len(CLEAN) :]
#: TWO with each line-end shape a Handler may produce, with leading whitespace, and with byte
#: order marks where two texts read without stripping them would put them.
TWO_VARIANTS = [
    pytest.param(TWO, id="cr"),
    pytest.param(TWO.replace(CR, "\n"), id="lf"),
    pytest.param(TWO.replace(CR, "\r\n"), id="crlf"),
    pytest.param("\r\n" + TWO, id="leading-whitespace"),
    pytest.param(MARKED, id="byte-order-mark-between"),
    pytest.param(MARKED.replace(CR, "\n"), id="lf-byte-order-mark-between"),
    pytest.param(split._BOM + TWO, id="byte-order-mark"),
]
#: The whitespace and byte order marks that lead a body, which the delivery reading reads past.
_LEAD_PAST_BOM = re.compile(r"\A[\s" + split._BOM + r"]*")
#: A relayed X12 interchange, which a TCP outbound carries opaquely and never reads as HL7.
X12 = (
    "ISA*00*          *00*          *ZZ*SENDER         *ZZ*RECEIVER       *260101*1200*^*00501"
    "*000000001*0*P*:~GS*HC*SENDER*RECEIVER*20260101*1200*1*X*005010X222A1~ST*837*0001~"
    "SE*2*0001~GE*1*1~IEA*1*000000001~"
)
#: Message content the refusal text must never carry.
CONTENT = ("SND", "FORGED", "DOE", "ROE", "CTRL1", "CTRL2", "111", "999")


def _assert_two_messages_refusal(exc: NegativeAckError, transport: str) -> None:
    assert exc.permanent is True
    assert exc.code == MULTIPLE_MESSAGES_CODE
    assert str(exc).startswith(transport + ": payload holds more than one MSH segment")
    assert [word for word in CONTENT if word in str(exc)] == []


def _record_wire(monkeypatch: pytest.MonkeyPatch, dest: Any) -> list[bytes]:
    """Replace ``dest``'s connect-per-send path with a recorder of the framed bytes it is handed,
    so the real ``send()`` runs up to the dial."""
    sent: list[bytes] = []

    async def record(wire: bytes, *_: Any) -> None:
        sent.append(wire)

    monkeypatch.setattr(dest, "_send_once", record)
    return sent


@pytest.mark.parametrize("payload", TWO_VARIANTS)
@pytest.mark.parametrize("persistent", [False, True])
@pytest.mark.parametrize("no_ack", [False, True])
async def test_all_four_mllp_send_paths_refuse_two_messages_before_any_dial(
    monkeypatch: pytest.MonkeyPatch, persistent: bool, no_ack: bool, payload: str
) -> None:
    # Before ADR 0209 each path framed the payload as asked: one frame, two messages, one ACK.
    refusal = await _refused_before_any_dial(monkeypatch, _mllp(persistent, no_ack), payload)
    _assert_two_messages_refusal(refusal, "MLLP")


@pytest.mark.parametrize("payload", TWO_VARIANTS)
@pytest.mark.parametrize("persistent", [False, True])
async def test_both_tcp_send_paths_refuse_two_messages_before_any_dial(
    monkeypatch: pytest.MonkeyPatch, persistent: bool, payload: str
) -> None:
    refusal = await _refused_before_any_dial(monkeypatch, _tcp(persistent), payload)
    _assert_two_messages_refusal(refusal, "TCP")


async def test_the_mllp_send_control_frames_one_message(monkeypatch: pytest.MonkeyPatch) -> None:
    # The control for the refusals above: the same destination sends one message as one frame.
    async with aclosing(_mllp(persistent=False, no_ack=False)) as dest:
        sent = _record_wire(monkeypatch, dest)
        await dest.send(CLEAN)
    assert sent == [MLLP_CODEC.frame(CLEAN)]


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param(CLEAN, id="one-hl7-message"),
        pytest.param(X12, id="x12-relay"),
        # Only an MSH-led payload is read: an opaque payload that merely carries MSH lines is not.
        pytest.param("relay header\n" + TWO.replace(CR, "\n"), id="not-msh-led"),
    ],
)
async def test_the_tcp_send_carries_one_message_and_an_opaque_relay(
    monkeypatch: pytest.MonkeyPatch, payload: str
) -> None:
    async with aclosing(_tcp()) as dest:
        sent = _record_wire(monkeypatch, dest)
        await dest.send(payload)
    assert sent == [STX_ETX_CODEC.frame(payload)]


@pytest.mark.parametrize(
    ("dest", "kwargs", "transport"),
    [
        pytest.param(lambda: _send_recorder(), {}, "MLLP", id="mllp"),
        pytest.param(lambda: _send_recorder(), {"rewrite": False}, "MLLP", id="mllp-as-stored"),
        pytest.param(
            lambda: _send_recorder(hl7_raw_separators=True), {}, "MLLP", id="mllp-raw-separators"
        ),
        # The delimiter override re-encodes first; the refusal is still this one, not "reencode".
        pytest.param(
            lambda: MLLPDestination(
                Destination(
                    name=DEST,
                    type=ConnectorType.MLLP,
                    settings={"host": "127.0.0.1", "port": 1, "encoding_characters": "#@*!%"},
                )
            ),
            {},
            "MLLP",
            id="mllp-delimiter-override",
        ),
        pytest.param(lambda: _tcp(), {}, "TCP", id="tcp"),
    ],
)
async def test_check_frame_refuses_two_messages_as_a_send_does(
    dest: Any, kwargs: dict[str, Any], transport: str
) -> None:
    # check_frame is what a batch member (rewrite=False) and a shadow outbound are judged by, so
    # it must answer as a live send does; CLEAN is the control.
    async with aclosing(dest()) as built:
        built.check_frame(CLEAN, **kwargs)
        with pytest.raises(NegativeAckError) as caught:
            built.check_frame(TWO, **kwargs)
    _assert_two_messages_refusal(caught.value, transport)


@pytest.mark.parametrize(
    "body",
    [*TWO_VARIANTS, CLEAN, CLEAN.replace(CR, "\n"), "relay header\n" + TWO, X12],
)
def test_the_delivery_reading_is_the_ingress_reading_of_an_msh_led_payload(body: str) -> None:
    # The ingress guard reads normalized text; a delivery reads the payload as it will send it.
    # Each must find what the other finds. The ingress guard reads the marks after a line break
    # itself (BACKLOG #5918), so only the lead's are dropped: the parser refuses a body one leads,
    # and the delivery reading reads past them.
    normalized = _LEAD_PAST_BOM.sub("", normalize(body), count=1)
    expected = starts_with_msh(normalized) and split._holds_more_than_one_message(normalized)
    assert split._sends_more_than_one_message(body) is expected


# --- BACKLOG #5918: a later MSH that byte order marks lead is a boundary at ingress too ---------
# Before the fix only the delivery reading looked past a mark after a line break, so the file split
# and the ingress guard read TWO with a mark before its second MSH as one message: it was ACKed,
# then dead-lettered at the outbound frame.

#: The second message of TWO, its MSH led by one or two byte order marks.
MARKED_TWO = [
    pytest.param(MARKED, id="one-mark"),
    pytest.param(CLEAN + split._BOM * 2 + TWO[len(CLEAN) :], id="two-marks"),
    pytest.param(MARKED.replace(CR, "\n"), id="lf-one-mark"),
]


@pytest.mark.parametrize("body", MARKED_TWO)
def test_the_ingress_guard_refuses_a_second_msh_that_marks_lead(body: str) -> None:
    with pytest.raises(ingress_guards.IngressMultipleMessagesRejected):
        ingress_guards.check_decoded(normalize(body), _ic())


@pytest.mark.parametrize("body", MARKED_TWO)
def test_the_file_split_cuts_past_the_marks_before_a_later_msh(body: str) -> None:
    # Each member must start with MSH, or the parser records the second one as an ERROR: the split
    # finds what it finds in the same body with no mark.
    unmarked = split.split_batch(TWO)
    assert len(unmarked) == 2
    assert split.split_batch(body) == unmarked
    raw = body.encode("utf-8")
    assert split._needs_a_decode(raw, "utf-8") is True
    assert split.split_batch_bytes(raw, "utf-8") == [m.encode("utf-8") for m in unmarked]
    # Each member the split hands over passes the ingress guard on its own.
    for member in unmarked:
        ingress_guards.check_decoded(member, _ic())


def test_a_mark_inside_a_line_or_before_another_segment_is_not_a_boundary() -> None:
    # Controls: only a line break, then marks, then MSH, is the wider boundary.
    inside = MSH + CR + "PID|1||111" + split._BOM + "MSH" + CR
    before_pid = MSH + CR + split._BOM + "PID|1||111" + CR
    for body in (inside, before_pid):
        assert split._holds_more_than_one_message(body) is False
        assert split.split_batch(body) == [body]
        assert split._needs_a_decode(body.encode("utf-8"), "utf-8") is False


def test_a_single_byte_charset_reads_a_utf8_mark_as_three_characters_it_keeps() -> None:
    # The byte scan matches the mark's bytes under any ASCII-safe charset, but cp1252 decodes them
    # to three characters that are not a mark, so the file is still one message, as before.
    raw = MARKED.encode("utf-8")
    assert split.split_batch_bytes(raw, "cp1252") == [raw]
