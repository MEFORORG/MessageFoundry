# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``b64_head`` reads only the prefix it needs, refuses a non-positive size and validates its
alphabet (BACKLOG #5805). The documents here are synthetic bytes, never real content."""

from __future__ import annotations

import base64
import tracemalloc

import pytest

from messagefoundry.parsing.sniff import b64_head

PNG = b"\x89PNG\r\n\x1a\n" + bytes(range(64))


def test_b64_head_allocates_for_its_prefix_not_the_document() -> None:
    """Mutation: compact ``b64`` whole before slicing. Red: the peak holds a copy of the line-wrapped
    document, several MiB, where the prefix needs a few hundred bytes."""
    encoded = base64.b64encode(PNG * 65536).decode("ascii")  # about 6 MiB of base64
    wrapped = "\r\n".join(encoded[i : i + 76] for i in range(0, len(encoded), 76))
    # Traced already (-X tracemalloc) or not, the peak is measured from here, and tracing someone
    # else started is left on.
    started_here = not tracemalloc.is_tracing()
    if started_here:
        tracemalloc.start()
    try:
        before, _ = tracemalloc.get_traced_memory()
        tracemalloc.reset_peak()
        head = b64_head(wrapped)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        if started_here:
            tracemalloc.stop()
    assert head.startswith(b"\x89PNG\r\n\x1a\n")
    assert peak - before < 64 * 1024


@pytest.mark.parametrize("wrap", [1, 4, 76])
def test_b64_head_reads_through_wrapping_wider_than_its_first_window(wrap: int) -> None:
    """Control: whitespace-heavy wrapping still yields the exact leading bytes."""
    encoded = base64.b64encode(PNG).decode("ascii")
    wrapped = "\r\n  ".join(encoded[i : i + wrap] for i in range(0, len(encoded), wrap))
    assert b64_head(wrapped) == PNG[:33]


@pytest.mark.parametrize("max_bytes", [0, -3, -4096])
def test_b64_head_gives_nothing_for_a_size_of_zero_or_less(max_bytes: int) -> None:
    """Red on the code before BACKLOG #5805: a negative size became a negative slice end, so it
    decoded nearly the whole payload. Zero gave ``b""`` there too."""
    assert b64_head(base64.b64encode(PNG * 100).decode("ascii"), max_bytes) == b""


def test_b64_head_refuses_a_character_outside_the_alphabet() -> None:
    """Mutation: decode without ``validate=True``. Red: the four leading ``*`` are skipped and the
    rest of the window lines up into the PNG signature."""
    forged = "****" + base64.b64encode(PNG).decode("ascii")
    assert b64_head(forged) == b""
