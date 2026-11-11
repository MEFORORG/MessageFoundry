# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The one shortening rule for alert subjects (vault BACKLOG #3543), in a leaf module so the store
can bound a row's ref with it (ADR 0217, *A ref is for reading*) without importing ``pipeline/``.
``pipeline/intake_bound.py`` re-exports it for its existing callers."""

from __future__ import annotations

import binascii

#: Hex digits of the CRC-32 that stands in for the part of a text :func:`shorten_with_checksum`
#: cuts. A checksum, not a cryptographic digest: it only has to tell two texts apart in a subject a
#: reader sees. A CRC-32 is easy to forge, so two texts with one head can be made to shorten
#: alike. Under ADR 0217 only the Unverifiable subject also carries a SHA-256 suffix of the whole
#: value, which keys its throttle and cap. A Forged page's reason carries the shortened ref alone,
#: so a planted id can be made to read like a genuine one there.
_CHECKSUM_HEX = 8


def shorten_with_checksum(text: str, limit: int, *, keep_tail: bool = False) -> str:
    """``text`` when it is at most ``limit`` characters, else a form at most that long that stands
    for it: the head of ``text``, ``~`` and a checksum of the whole text, or with ``keep_tail``,
    ``~``, the checksum, ``~`` and the tail. The same text always gives the same result, and two
    texts with one head (or tail) almost never do. The one shortening rule for alert subjects
    (vault BACKLOG #3543): a node label keeps its head, a CRL path its tail, which holds the file
    name. ``limit`` is assumed to leave room for the checksum.

    binascii, not zlib: the same CRC-32, and this module reads no archive or compressed stream.
    ``backslashreplace``, so a text with a lone surrogate still gets a checksum instead of
    raising."""
    if len(text) <= limit:
        return text
    digest = f"{binascii.crc32(text.encode('utf-8', 'backslashreplace')):0{_CHECKSUM_HEX}x}"
    if keep_tail:
        # Sliced from a start index, never ``text[-n:]``: n = 0 would keep the whole text.
        start = len(text) - max(0, limit - _CHECKSUM_HEX - len("~~"))
        return f"~{digest}~{text[start:]}"
    return f"{text[: max(0, limit - _CHECKSUM_HEX - len('~'))]}~{digest}"
