# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Unit tests for the vendored MLLP codec (tee/mllp.py)."""

from __future__ import annotations

import pytest

from messagefoundry import mllpcodec
from messagefoundry.parsing import Peek
from tee import mllp

# A synthetic HL7 ADT message (segments CR-delimited). No real PHI.
SAMPLE = (
    b"MSH|^~\\&|EPIC|SENDFAC|MFOR|RECVFAC|20240101120000||ADT^A01|CTRL123|P|2.5.1\r"
    b"PID|1||MRN001^^^HOSP||DOE^JOHN\r"
)


def test_frame_roundtrip() -> None:
    framed = mllp.frame(SAMPLE)
    assert framed[0] == mllp.SB
    assert framed[-2] == mllp.EB
    assert framed[-1] == mllp.CR
    decoder = mllp.FrameDecoder()
    out = list(decoder.feed(framed))
    assert out == [SAMPLE]


def test_decoder_handles_split_and_multiple_frames() -> None:
    blob = mllp.frame(b"one") + mllp.frame(b"two")
    decoder = mllp.FrameDecoder()
    collected: list[bytes] = []
    # Feed one byte at a time — exercises the cross-chunk reassembly.
    for i in range(len(blob)):
        collected.extend(decoder.feed(blob[i : i + 1]))
    assert collected == [b"one", b"two"]


def test_decoder_discards_interframe_noise() -> None:
    decoder = mllp.FrameDecoder()
    # Junk before SB and a stray CR trailer after EB must be ignored.
    data = b"garbage" + mllp.frame(b"payload") + b"\x0d\x0dmore-noise"
    assert list(decoder.feed(data)) == [b"payload"]


def test_decoder_oversize_raises() -> None:
    decoder = mllp.FrameDecoder(max_frame_bytes=4)
    with pytest.raises(mllp.FrameError):
        list(decoder.feed(bytes([mllp.SB]) + b"toolong"))


def test_build_ack_is_aa_and_echoes_control_id() -> None:
    ack = mllp.build_ack(SAMPLE, timestamp="20240101120001")
    text = ack.decode("latin-1")
    assert "MSA|AA|CTRL123" in text
    # Sender/receiver are swapped so the ACK routes back the way it came.
    assert "MSH|^~\\&|MFOR|RECVFAC|EPIC|SENDFAC|" in text


def test_build_ack_reads_custom_separator() -> None:
    msg = b"MSH#^~\\&#A#B#C#D#20240101##ADT^A01#XYZ#P#2.5.1\r"
    ack = mllp.build_ack(msg).decode("latin-1")
    assert "MSA#AA#XYZ" in ack


def test_build_ack_on_non_hl7_still_acks() -> None:
    # Always-ACK: even unparseable input yields a generic AA (empty control id).
    ack = mllp.build_ack(b"not an hl7 message").decode("latin-1")
    assert ack.startswith("MSH|")
    assert "MSA|AA|" in ack


def test_parse_ack() -> None:
    assert mllp.parse_ack(mllp.build_ack(SAMPLE)) == ("AA", None)
    nak = mllp.build_ack(SAMPLE, code="AE")
    # build_ack puts the control id in MSA-3? No — MSA-3 only carries text; here it's empty.
    assert mllp.parse_ack(nak)[0] == "AE"


def test_parse_ack_with_detail() -> None:
    ack = b"MSH|^~\\&|A|B|C|D|20240101||ACK|1|P|2.5.1\rMSA|AR|1|rejected reason\r"
    assert mllp.parse_ack(ack) == ("AR", "rejected reason")


@pytest.mark.parametrize("sep", ["M", "S"])
def test_parse_ack_reads_a_field_separator_that_is_a_letter_of_msa(sep: str) -> None:
    ack = f"MSH{sep}^~\\&{sep}X\rMSA{sep}AE{sep}C1{sep}why\r".encode()
    assert mllp.parse_ack(ack) == ("AE", "why")


def test_parse_ack_unreadable() -> None:
    assert mllp.parse_ack(b"junk") == (None, None)


def test_peek_fields() -> None:
    assert mllp.peek_fields(SAMPLE) == ("CTRL123", "ADT^A01")
    assert mllp.peek_fields(b"junk") == (None, None)


def test_segment_injection_is_stripped() -> None:
    # A CR/LF smuggled into an echoed field must not create a new segment in the ACK.
    evil = b"MSH|^~\\&|E\rPV1|evil|VIL|MFOR|RECV|20240101||ADT^A01|C1|P|2.5.1\r"
    ack = mllp.build_ack(evil).decode("latin-1")
    # The injected 'PV1|evil' must not appear as its own segment in the ACK.
    assert "\rPV1|evil" not in ack


#: Synthetic inbound headers whose delimiters collide with text the ACK writes itself (BACKLOG
#: #2875): MSH-2 "^AB", MSH-1 "K" (a letter of "ACK"), a component separator that splits MSH-7's
#: offset, and an MSH-10 that holds an escape.
_COLLIDING_HEADERS = {
    "msh2-letters": b"MSH|^AB|APP|FAC|RCV|RFC|20260101||ORU^R01|C^1|P|2.5.1\r",
    "msh1-letter": b"MSHK^~\\&KAPPKFACKRCVKRFCK20260101KKORU^R01KC|1KPK2.5.1\r",
    "msh2-minus": b"MSH|-~\\&|APP|FAC|RCV|RFC|20260101||ORU^R01|C1|P|2.5.1\r",
    "msh1-escape": b"MSHK^~\\&KAPPKFACKRCVKRFCK20260101KKORU^R01KC\\F\\1KPK2.5.1\r",
}


@pytest.mark.parametrize("code", ["AA", "AE", "AR"])
@pytest.mark.parametrize("inbound", _COLLIDING_HEADERS.values(), ids=list(_COLLIDING_HEADERS))
def test_build_ack_reads_back_when_the_inbound_delimiters_collide_with_its_own_text(
    inbound: bytes, code: str
) -> None:
    ack = mllp.build_ack(inbound, code=code, timestamp="20260101000000-0500")
    assert ack.startswith(b"MSH|^~\\&|"), ack
    assert mllp.parse_ack(ack) == (code, None)
    assert mllp.peek_fields(ack)[1] == "ACK"
    # The tee reads no component; the engine's parser reads the ACK down to the subcomponent.
    peek = Peek.parse(ack.decode("latin-1"))
    assert (peek.field("MSH-9.1.1"), peek.field("MSA-1.1.1")) == ("ACK", code)
    assert peek.field("MSH-7.1.1") == "20260101000000-0500"


@pytest.mark.parametrize(
    ("name", "msa"),
    [("msh1-letter", b"MSA|AA|"), ("msh1-escape", b"MSA|AA|"), ("msh2-letters", b"MSA|AA|C^1")],
)
def test_build_ack_blanks_an_echoed_value_a_default_delimiter_would_restructure(
    name: str, msa: bytes
) -> None:
    # "|" is data under field separator K, so "C|1" is blanked; under MSH-2 "^AB" the "^" is the
    # component separator in both sets, so "C^1" is kept. The engine's build_ack has the same rule.
    ack = mllp.build_ack(_COLLIDING_HEADERS[name])
    assert ack.endswith(b"\r" + msa + b"\r"), ack
    assert ack.startswith(b"MSH|^~\\&|RCV|RFC|APP|FAC|"), ack


@pytest.mark.parametrize("sep", ["M", "S", "H"])
def test_build_ack_reads_a_field_separator_that_is_a_letter_of_msh(sep: str) -> None:
    inbound = f"MSH{sep}^~\\&{sep}APP{sep}FAC{sep}RCV{sep}RFC{sep}20260101{sep}{sep}ORU^R01{sep}C1"
    ack = mllp.build_ack(f"{inbound}{sep}P{sep}2.5.1\r".encode())
    assert ack.startswith(b"MSH|^~\\&|RCV|RFC|APP|FAC|"), ack
    assert ack.endswith(b"|ACK|C1|P|2.5.1\rMSA|AA|C1\r"), ack


def test_the_tee_and_the_engine_share_the_fallback_rule() -> None:
    # The tee cannot import the engine, so its copy of the rule is pinned to the engine's here.
    assert mllp._ACK_LITERAL_CHARS == mllpcodec._ACK_LITERAL_CHARS
    assert mllp._DEFAULT_ROLES == mllpcodec._DEFAULT_ROLES
    for field_sep, enc in (("|", "^AB"), ("D", "^~\\&"), ("|", "-~\\^"), ("#", "@@!%"), ("|", "A")):
        assert mllp._roles(field_sep, enc) == mllpcodec._roles(field_sep, enc)
    others = (
        b"MSH#@*!%#APP#FAC#RCV#RFC#20260101##ORU@R01#C|1#P#2.5.1\r",  # punctuation: echoed
        b"MSHD^~\\&DAPPDFACDRCVDRFCD20260101DDORU^R01DC|1DPD2.5.1\r",  # a letter ACKs never hold
        b"MSH^^APP^FAC^RCV^RFC^20260101^^ORU~R01^C1^P^2.5.1\r",  # the field separator in MSH-2
        b"MSH|^~^&|APP|FAC|RCV|RFC|20260101||ORU^R01|C1|P|2.5.1\r",  # two roles, one character
        b"MSHF^~\\&FAPPFSACFRCVFRXCF20260101FFORU^R01FC1FPF2.5.1\r",  # the F of an escape
        b"MSH|A|APP|FAC|RCV|RFC|20260101||ORU^R01|X~Y|P|2.5.1\r",  # a short MSH-2
        b"MSH|^~E&|APP|FAC|RCV|RFC|20260101||ORU^R01|CEFE1|P|2.5.1\r",  # a letter escape
    )
    for inbound in (*_COLLIDING_HEADERS.values(), *others):
        engine = mllpcodec.build_ack(inbound.decode("latin-1"), timestamp="20260101")
        assert mllp.build_ack(inbound, timestamp="20260101").decode("latin-1") == engine


def test_build_ack_still_echoes_punctuation_delimiters() -> None:
    # The control: delimiters the ACK never writes as text are echoed, as before BACKLOG #2875.
    ack = mllp.build_ack(b"MSH#@*!%#APP#FAC#RCV#RFC#20260101##ORU@R01#C|1#P#2.5.1\r")
    assert ack.startswith(b"MSH#@*!%#RCV#RFC#APP#FAC#"), ack
    assert ack.endswith(b"\rMSA#AA#C|1\r"), ack
