# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""One outbound frame holds exactly one message (ADR 0205, vault BACKLOG #2557).

Each section pins one rule of the ADR, and the tests marked as an audit probe reproduce that probe
from the injection audit. Every such test fails on the code before ADR 0205: the payload was framed
without a look inside it, a leaf write emitted a decoded hex escape raw, and ingress took an HL7 v2
body with an embedded MLLP start byte. Synthetic data only.

Control bytes are written as escapes, never literally, so a byte grep of this file finds none.
"""

from __future__ import annotations

import asyncio
import random
import re
from pathlib import Path
from typing import Any

import pytest

from messagefoundry import actions
from messagefoundry.config.models import (
    ConnectorType,
    ContentType,
    Destination,
    RetryPolicy,
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
from messagefoundry.framing import MLLP_CODEC, STX_ETX_CODEC, FrameCodec
from messagefoundry.parsing import _builtin_hl7
from messagefoundry.parsing import message as message_module
from messagefoundry.parsing.dicom.hl7_map import encode_segment
from messagefoundry.parsing.message import Message
from messagefoundry.pipeline import ingress_guards, wiring_runner
from messagefoundry.pipeline.dryrun import dry_run
from messagefoundry.store import MessageStatus, MessageStore, OutboxStatus
from messagefoundry.transports.base import NegativeAckError
from messagefoundry.transports.framing import frame_for_delivery, frame_reply
from messagefoundry.transports.mllp import MLLPDestination, MLLPSource
from messagefoundry.transports.tcp import TcpDestination, TcpSource

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


async def _never_dial() -> Any:
    raise AssertionError("the refused payload opened a connection")


@pytest.mark.parametrize("persistent", [False, True])
@pytest.mark.parametrize("no_ack", [False, True])
async def test_all_four_mllp_send_paths_refuse_before_any_dial(
    monkeypatch: pytest.MonkeyPatch, persistent: bool, no_ack: bool
) -> None:
    dest = _mllp(persistent, no_ack)
    monkeypatch.setattr(dest, "_dial", _never_dial)
    try:
        with pytest.raises(NegativeAckError) as caught:
            await dest.send(SMUGGLED)
    finally:
        await dest.aclose()
    assert caught.value.permanent is True


@pytest.mark.parametrize("persistent", [False, True])
async def test_both_tcp_send_paths_refuse_before_any_dial(
    monkeypatch: pytest.MonkeyPatch, persistent: bool
) -> None:
    settings: dict[str, object] = {
        "host": "127.0.0.1",
        "port": 1,
        "framing": "stx_etx",
        "timeout_seconds": 1,
        "persistent": persistent,
    }
    dest = TcpDestination(Destination(name="out", type=ConnectorType.TCP, settings=settings))
    monkeypatch.setattr(dest, "_dial", _never_dial)
    try:
        with pytest.raises(NegativeAckError) as caught:
            await dest.send(SMUGGLED_STX)
    finally:
        await dest.aclose()
    assert caught.value.permanent is True and str(caught.value).startswith("TCP: ")


# --- rule 2: a leaf write never emits a raw control character -----------------------------------


def test_P2_a_hex_escaped_frame_byte_survives_a_component_edit_escaped() -> None:
    msg = Message.parse(MSH + CR + "PID|1||111^^^MRN||doe" + HEX_EB_SB + "x^jane" + CR)
    actions.convert_case(msg, "PID-5.1", "upper")
    encoded = msg.encode()
    assert SB not in encoded and EB not in encoded
    assert "DOE" + HEX_EB_SB + "X^jane" in encoded
    # The read side still decodes it, so the round trip is faithful rather than lossy.
    assert msg.field("PID-5.1") == "DOE" + EB + SB + "X"


def test_P2_a_hex_escaped_nul_does_not_re_enter_raw() -> None:
    msg = Message.parse(MSH + CR + "PID|1||111||doe" + BS + "X00" + BS + "^jane" + CR)
    actions.convert_case(msg, "PID-5.1", "upper")
    assert NUL not in msg.encode()


def test_P2_control_a_decoded_cr_is_still_refused() -> None:
    msg = Message.parse(MSH + CR + "PID|1||111||doe" + BS + "X0D" + BS + "EVN^jane" + CR)
    with pytest.raises(ValueError, match="segment separator"):
        actions.convert_case(msg, "PID-5.1", "upper")


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
    # chained replace rescanned the escape it had just written and turned \F\ into \\S\\.
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
    runner = wiring_runner.RegistryRunner(reg, store)
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
    runner = wiring_runner.RegistryRunner(reg, store)
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
    runner = wiring_runner.RegistryRunner(reg, store)
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


class _SendRecorder(MLLPDestination):
    """A real MLLP destination, so its ``check_frame`` is the real one, whose send only records."""

    def __init__(self) -> None:
        settings: dict[str, object] = {"host": "127.0.0.1", "port": 1}
        super().__init__(Destination(name=DEST, type=ConnectorType.MLLP, settings=settings))
        self.sent: list[str] = []

    async def send(self, payload: str, *, metadata: Any = None) -> None:
        self.sent.append(payload)


async def _enqueue(store: MessageStore, bodies: list[str]) -> list[str]:
    return [
        await store.enqueue_message(channel_id="c1", raw=b, deliveries=[(DEST, b)], now=100.0 + i)
        for i, b in enumerate(bodies)
    ]


@pytest.mark.parametrize(
    ("body", "expected"),
    [pytest.param(SMUGGLED, DEAD, id="smuggled"), pytest.param(CLEAN, DONE, id="clean-control")],
)
async def test_a_shadow_outbound_records_what_a_live_send_would(
    store: MessageStore, body: str, expected: tuple[str, str]
) -> None:
    # Rule 1 runs inside connector.send(), which a simulate outbound skips. Before the fix shadow
    # marked the smuggled row PROCESSED, where a live send would have dead-lettered it. The batch
    # twin is in tests/test_outbound_batch.py, which runs on every store backend.
    (mid,) = await _enqueue(store, [body])
    dest = _SendRecorder()
    runner = wiring_runner.RegistryRunner(Registry(), store, poll_interval=0.02)
    runner._destinations[DEST] = dest
    runner._retry[DEST] = RetryPolicy()
    runner._simulate[DEST] = True
    item = await store.claim_next_fifo(DEST)
    assert item is not None
    await runner._process_delivery_item(DEST, item)
    assert dest.sent == []
    msg = await store.get_message(mid)
    (row,) = await store.outbox_for(mid)
    assert msg is not None and (msg["status"], row["status"]) == expected
    error = str(row["last_error"] or "")
    assert "DOE" not in error and (expected == DONE or "frame" in error)


# --- the reply path: a listener's reply is one frame, and framing it never raises ---------------


def test_frame_reply_neutralises_a_frame_byte_instead_of_raising() -> None:
    reply = MSH + CR + "MSA|AA|C" + SB + "1" + EB + CR
    wire = frame_reply(MLLP_CODEC, reply, "utf-8")
    assert wire.count(b"\x0b") == 1 and wire.count(b"\x1c") == 1
    assert _frames(MLLP_CODEC, wire) == [(MSH + CR + "MSA|AA|C 1 " + CR).encode("utf-8")]
    assert frame_reply(MLLP_CODEC, CLEAN, "utf-8") == MLLP_CODEC.frame(CLEAN)


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
    nak = source._handler_failure_nak(header.encode("utf-8"))
    assert nak is not None and nak.count(b"\x0b") == 1 and nak.count(b"\x1c") == 1


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
