# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Base64-PDF-in-OBX-5 round-trip + escape-safety (SYNTHETIC-TEST-PLAN §1.0.b / tests 1.1.1-1.1.2).

A scanned document rides an ORU/MDM message as a base64 ED ``OBX-5`` field. These prove the engine's
``Message`` model carries that payload byte-exact through read → set → encode → re-parse, and that the
base64 alphabet (``+ / =``) is never mangled by HL7 delimiter-escaping.
"""

from __future__ import annotations

import base64
from collections.abc import Callable

import pytest

from messagefoundry.generators.documents import mdm_with_pdf, oru_with_pdf, synthetic_pdf
from messagefoundry.parsing.message import Message

_Builder = Callable[[bytes], str]


def _last_obx_data(msg: Message) -> str | None:
    """The base64 data (``OBX-5.5``) of the last OBX — where the builders append the ED segment."""
    return msg.field("OBX-5.5", occurrence=msg.count_segments("OBX"))


def test_synthetic_pdf_is_pdf_shaped() -> None:
    pdf = synthetic_pdf()
    assert pdf.startswith(b"%PDF-")
    assert pdf.rstrip().endswith(b"%%EOF")
    assert synthetic_pdf() == pdf  # deterministic


def test_synthetic_pdf_sized_and_deterministic() -> None:
    a = synthetic_pdf(n_bytes=4096, seed="s1")
    b = synthetic_pdf(n_bytes=4096, seed="s1")
    assert a == b
    assert len(a) == 4096
    assert synthetic_pdf(n_bytes=4096, seed="s2") != a  # the seed varies the filler


@pytest.mark.parametrize("builder", [oru_with_pdf, mdm_with_pdf])
def test_base64_pdf_read_back_exact(builder: _Builder) -> None:
    pdf = synthetic_pdf(n_bytes=2048, seed="rt")
    expected_b64 = base64.b64encode(pdf).decode("ascii")
    msg = Message.parse(builder(pdf))
    occ = msg.count_segments("OBX")
    assert msg.field("OBX-2", occurrence=occ) == "ED"  # encapsulated-data value type
    assert msg.field("OBX-5.1", occurrence=occ) is None  # source-application component empty
    assert _last_obx_data(msg) == expected_b64  # data component, byte-for-byte (no escape mangling)


@pytest.mark.parametrize("builder", [oru_with_pdf, mdm_with_pdf])
def test_base64_pdf_round_trip_byte_identical(builder: _Builder) -> None:
    pdf = synthetic_pdf(n_bytes=2048, seed="rt")
    encoded = builder(pdf)
    reparsed = Message.parse(encoded)
    decoded = base64.b64decode(_last_obx_data(reparsed) or "")
    assert decoded == pdf  # the PDF survives encode → re-parse intact
    assert decoded.startswith(b"%PDF-")
    assert decoded.rstrip().endswith(b"%%EOF")
    assert Message.parse(encoded).encode() == encoded  # re-encode is stable


def test_base64_alphabet_not_escaped() -> None:
    # A payload whose base64 exercises +, /, and = must survive set/field/encode verbatim — the HL7
    # delimiter-escaper must leave the base64 alphabet untouched.
    pdf = b"%PDF-1.4\n" + bytes(range(256)) * 4 + b"\n%%EOF\n"
    b64 = base64.b64encode(pdf).decode("ascii")
    assert any(c in b64 for c in "+/=")  # the fixture actually hits the special chars
    msg = Message.parse(oru_with_pdf(pdf))
    assert msg.field("OBX-5.5", occurrence=msg.count_segments("OBX")) == b64
    assert b64 in msg.encode()  # carried verbatim on the wire (no \S\ / \F\ escapes introduced)
