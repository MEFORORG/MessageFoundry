# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5520, filing review finding 3: the content sniffs skip leading noise by copying a
bounded head, not the body.

The upload gate (``uploads.validate_upload_content``: ``nontext_upload_reason``, then the
``.hl7``/``.xml`` sniff), the file transports' ``_content_matches_declared`` and the network
listeners' ``text_sniff_head`` read past leading white space and a BOM before they compare a
signature. They did that with ``lstrip``, which copies the rest of the body when anything is
stripped, so a body that starts with one space cost a second copy of itself. Each skip now finds
the first byte past the noise in place and copies only a short head. The positive control shows
the instrument sees a whole-body copy; the clean-body control shows a body with nothing to skip.
"""

from __future__ import annotations

import tracemalloc
from collections.abc import Callable

import pytest

from messagefoundry.content_type import ContentType
from messagefoundry.parsing import sniff
from messagefoundry.parsing.sniff import (
    _content_matches_declared,
    nontext_upload_reason,
    text_sniff_head,
)
from messagefoundry.uploads import validate_upload_content

_SIZE = 4 * 1024 * 1024
_NOISE = [b" ", b"\r\n", b"\xef\xbb\xbf", b" \xef\xbb\xbf\t"]


def _peak(call: Callable[[], object]) -> int:
    tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        call()
        return tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


def test_the_instrument_sees_a_whole_body_copy() -> None:
    """Positive control: the copy the old skip made is over the bound the tests below hold."""
    body = b" MSH|" + b"a" * _SIZE
    assert _peak(lambda: body.lstrip(b" ")) >= _SIZE


@pytest.mark.parametrize("noise", _NOISE)
@pytest.mark.parametrize("name", ["x.hl7", "x.txt", "x.xml"])
def test_the_upload_gate_does_not_copy_a_body_with_leading_noise(noise: bytes, name: str) -> None:
    payload = (b"<a>" if name.endswith(".xml") else b"MSH|") + b"a" * _SIZE
    noisy = noise + payload
    # Control: a body with nothing to skip.
    assert _peak(lambda: validate_upload_content(name, payload)) < _SIZE // 8
    assert _peak(lambda: validate_upload_content(name, noisy)) < _SIZE // 8


@pytest.mark.parametrize("noise", _NOISE)
@pytest.mark.parametrize("content_type", [ContentType.HL7V2, ContentType.JSON, ContentType.X12])
def test_the_file_sniff_does_not_copy_a_body_with_leading_noise(
    noise: bytes, content_type: ContentType
) -> None:
    body = noise + b"x" * _SIZE
    assert _peak(lambda: _content_matches_declared(content_type, body)) < _SIZE // 8


@pytest.mark.parametrize("noise", ["  ", "\r\n", chr(0xFEFF), " " + chr(0xFEFF) + "\t"])
def test_the_listener_sniff_does_not_copy_a_text_with_leading_noise(noise: str) -> None:
    text = noise + "MSH|" + "a" * _SIZE
    assert text_sniff_head(text) == b"MSH|aaaa"
    assert _peak(lambda: text_sniff_head(text)) < _SIZE // 8


@pytest.mark.parametrize(
    "body",
    [
        b"%PDF-1.7 rest",
        b"  \r\n%PDF-1.7 rest",
        b"\xef\xbb\xbf%PDF-1.7",
        b" \xef\xbb\xbf \x89PNG\r\n\x1a\n...",
        b"\n" * 100_000 + b"PK\x03\x04",
    ],
)
def test_a_container_behind_leading_noise_is_still_refused(body: bytes) -> None:
    reason = nontext_upload_reason(body)
    assert reason is not None and "container" in reason


@pytest.mark.parametrize(
    ("content_type", "body", "agrees"),
    [
        (ContentType.XML, b"\n\n  <a/>", True),
        (ContentType.XML, b"\xef\xbb\xbf <a/>", True),
        (ContentType.XML, b"  x<a/>", False),
        (ContentType.JSON, b"\t\r\n{}", True),
        (ContentType.JSON, b" \xef\xbb\xbf[1]", True),
        (ContentType.JSON, b"   ", False),
        (ContentType.X12, b"\x0b\x0cISA*00", True),
        (ContentType.X12, b"ISX", False),
        (ContentType.HL7V2, b"\x0b\r\nMSH|", True),
        (ContentType.HL7V2, b" \xef\xbb\xbf\tFHS|", True),
        # The HL7 sniff's own noise set has no form feed.
        (ContentType.HL7V2, b"\x0cMSH|", False),
        (ContentType.HL7V2, b"  PID|", False),
    ],
)
def test_the_content_sniffs_read_the_same_head(
    content_type: ContentType, body: bytes, agrees: bool
) -> None:
    """What the sniffs admit is unchanged."""
    assert _content_matches_declared(content_type, body) is agrees


def test_the_written_out_noise_classes_match_the_noise_sets() -> None:
    """_PAST_LEADING_WS and _PAST_LEADING_WS_STR are literals so the static regex scan can read
    them; each must match exactly what its noise set does not hold, checked over every byte and
    every code point, so the literal cannot drift from the set."""
    for byte in range(256):
        one = bytes([byte])
        assert (sniff._PAST_LEADING_WS.fullmatch(one) is None) == (one in sniff._LEADING_WS), byte
    for code in range(0x110000):
        char = chr(code)
        skipped = sniff._PAST_LEADING_WS_STR.fullmatch(char) is None
        assert skipped == (char in sniff._LEADING_WS_STR), code
