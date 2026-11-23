# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5520, filing review finding 3: the upload gate's leading-noise skip copies a bounded
head, not the body.

``nontext_upload_reason`` reads past leading white space and a UTF-8 BOM before it compares a
container's magic bytes. It did that with ``bytes.lstrip``, which copies the rest of the body when
anything is stripped, so a body that starts with one space cost a second copy of itself. The skip
now finds the first byte past the noise in place and copies only a short head. Each test has a
control: the same body with no leading noise, which never copied, and the refusals the skip feeds.
"""

from __future__ import annotations

import tracemalloc

import pytest

from messagefoundry.content_type import ContentType
from messagefoundry.parsing.sniff import _content_matches_declared, nontext_upload_reason

_SIZE = 4 * 1024 * 1024


def _peak(body: bytes) -> int:
    tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        assert nontext_upload_reason(body) is None
        return tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


@pytest.mark.parametrize("noise", [b" ", b"\r\n", b"\xef\xbb\xbf", b" \xef\xbb\xbf\t"])
def test_leading_noise_does_not_copy_the_body(noise: bytes) -> None:
    body = noise + b"MSH|" + b"a" * _SIZE
    clean = b"MSH|" + b"a" * _SIZE
    # Control: a body with nothing to skip.
    assert _peak(clean) < _SIZE // 8
    assert _peak(body) < _SIZE // 8


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
    ],
)
def test_the_content_sniffs_read_the_same_head(
    content_type: ContentType, body: bytes, agrees: bool
) -> None:
    """The format sniffs share the skip: what they admit is unchanged."""
    assert _content_matches_declared(content_type, body) is agrees
