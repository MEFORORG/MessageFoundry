# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Unit tests for the vendored MLLP codec (tee/mllp.py)."""

from __future__ import annotations

import pytest

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
