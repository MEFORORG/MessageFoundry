# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``b64_head`` reads only the prefix it needs, refuses a non-positive size and validates its
alphabet (BACKLOG #5805). The documents here are synthetic bytes, never real content."""

from __future__ import annotations

import base64

import pytest

from messagefoundry.parsing.sniff import b64_head

PNG = b"\x89PNG\r\n\x1a\n" + bytes(range(64))


class _WholeSplitRecorder(str):
    """A ``str`` that records the length of every ``split`` called on itself, so a test can tell a
    read of the whole document from a read of slices of it (a slice is a plain ``str``)."""

    splits: list[int]

    def split(self, sep: str | None = None, maxsplit: int = -1) -> list[str]:  # type: ignore[override]
        self.splits.append(len(self))
        return super().split(sep, maxsplit)


def test_b64_head_never_compacts_the_whole_document() -> None:
    """Mutation: compact ``b64`` whole before slicing. Red: a split of the full length."""
    doc = _WholeSplitRecorder(base64.b64encode(PNG * 4096).decode("ascii"))
    doc.splits = []
    assert b64_head(doc).startswith(b"\x89PNG\r\n\x1a\n")
    assert doc.splits == []


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
