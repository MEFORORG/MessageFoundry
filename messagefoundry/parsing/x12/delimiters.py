# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Fixed-offset X12 ISA delimiter discovery — the X12 analog of reading the HL7 MSH separators.

An ASC X12 interchange opens with a **fixed-length 106-character ISA segment** whose element layout is
rigid, so the four delimiters are read by *absolute offset* rather than guessed:

* **element separator** — the character at offset ``+3`` (immediately after the literal ``ISA``);
* **component separator** — ISA16, at offset ``+104``;
* **segment terminator** — offset ``+105`` (or the two-character ``CR``+``LF`` at ``+105..+106`` when a
  partner terminates segments that way);
* **repetition separator** — ISA11, at offset ``+82`` — **but only from version 00501**; in 00401 and
  earlier ISA11 carries the literal ``U`` (Interchange Control Standards Identifier) and there is no
  repetition separator.

Trading partners legitimately vary all four delimiters, so hardcoding ``*~:^`` is wrong. We discover
them and **fail loud** (:class:`~messagefoundry.parsing.x12.errors.X12PeekError`) on a malformed /
non-X12 header rather than guess — inbound EDI is untrusted, so bad input is routed to the
error/dead-letter path. This module is **pure** (no I/O, no engine imports): it works on ``str`` only.
"""

from __future__ import annotations

from dataclasses import dataclass

from messagefoundry.parsing.x12.errors import X12PeekError

__all__ = [
    "Delimiters",
    "discover_delimiters",
    "find_isa_start",
    "ISA_SEGMENT_LEN",
    "ELEMENT_SEP_OFFSETS",
    "DEFAULT_MAX_INTERCHANGE_BYTES",
]

#: An ISA segment is ``ISA`` + 16 fixed-width elements + the segment terminator at offset 105.
ISA_SEGMENT_LEN = 106

#: A pathological interchange would otherwise be buffered/parsed whole; cap it (``None`` disables).
#: Matches the HL7/MLLP/file ingress caps (16 MiB).
DEFAULT_MAX_INTERCHANGE_BYTES = 16 * 1024 * 1024

# ISA01..ISA16 fixed element widths (the X12 standard), used to *derive* the element-separator offsets
# below instead of hand-typing them — so the rigid layout is documented once, in code.
_ISA_ELEMENT_WIDTHS = (2, 10, 2, 10, 2, 15, 2, 15, 6, 4, 1, 5, 9, 1, 1, 1)


def _element_separator_offsets() -> tuple[int, ...]:
    """The absolute offsets that must all hold the element separator in a well-formed ISA, derived
    from the fixed element widths: ``(3, 6, 17, 20, 31, 34, 50, 53, 69, 76, 81, 83, 89, 99, 101,
    103)``. Offset 3 (the *defining* separator) is first; the rest are the sanity-gate positions."""
    offsets: list[int] = []
    pos = 3  # the first element separator sits immediately after the literal "ISA"
    for width in _ISA_ELEMENT_WIDTHS:
        offsets.append(pos)
        pos += 1 + width
    return tuple(offsets)


ELEMENT_SEP_OFFSETS = _element_separator_offsets()
_COMPONENT_SEP_OFFSET = 104  # ISA16
_SEGMENT_TERM_OFFSET = 105
_REPETITION_SEP_OFFSET = 82  # ISA11
_VERSION_START, _VERSION_END = 84, 89  # ISA12 (5 chars), e.g. "00501"
_REPETITION_MIN_VERSION = "00501"  # ISA11 is a repetition separator from 005010 onward

# Leading characters tolerated before the ISA: whitespace + the UTF-8 BOM (U+FEFF) — pretty-printed or
# BOM-prefixed feeds.
_LEADING_NOISE = " \t\r\n\x0b\x0c\ufeff"


@dataclass(frozen=True)
class Delimiters:
    r"""The four X12 delimiters discovered from an ISA header.

    ``segment`` is the segment terminator — normally one character, but ``"\r\n"`` when a partner
    terminates segments with ``CR``+``LF``. ``repetition`` is ``None`` for ISA12 < 00501 (ISA11 is the
    literal ``"U"``, not a delimiter).
    """

    element: str
    component: str
    segment: str
    repetition: str | None


def find_isa_start(raw: str, start: int = 0) -> int:
    """Index of the ``ISA`` that opens the next interchange at/after ``start`` (skipping leading
    whitespace/BOM). Raises :class:`X12PeekError` if no ``ISA`` is found there."""
    i = start
    n = len(raw)
    while i < n and raw[i] in _LEADING_NOISE:
        i += 1
    if raw[i : i + 3] != "ISA":
        raise X12PeekError("X12 interchange does not begin with an ISA segment")
    return i


def discover_delimiters(raw: str, isa_start: int | None = None) -> Delimiters:
    """Read the four delimiters by absolute offset from the ISA at ``isa_start`` (auto-located when
    ``None``). Raises :class:`X12PeekError` on a truncated/malformed ISA or non-distinct delimiters."""
    start = find_isa_start(raw) if isa_start is None else isa_start
    if len(raw) < start + ISA_SEGMENT_LEN:
        raise X12PeekError(
            f"X12 ISA header truncated: need {ISA_SEGMENT_LEN} characters, got {len(raw) - start}"
        )

    element = raw[start + 3]
    component = raw[start + _COMPONENT_SEP_OFFSET]
    terminator = raw[start + _SEGMENT_TERM_OFFSET]
    # The terminator is one character, or CR+LF when raw[+105]=CR is immediately followed by LF.
    if terminator == "\r" and raw[start + 106 : start + 107] == "\n":
        segment = "\r\n"
    else:
        segment = terminator

    # ISA11 is a repetition separator only from version 00501; earlier it is the literal "U".
    version = raw[start + _VERSION_START : start + _VERSION_END]
    repetition: str | None = (
        raw[start + _REPETITION_SEP_OFFSET] if version >= _REPETITION_MIN_VERSION else None
    )

    # Sanity gate: every fixed element-separator position (except the defining one at +3) must hold the
    # element separator — catches a mis-sized / non-X12 header before we trust the offsets.
    for offset in ELEMENT_SEP_OFFSETS[1:]:
        if raw[start + offset] != element:
            raise X12PeekError(
                f"X12 ISA header malformed: expected element separator {element!r} at offset {offset}"
            )

    # The delimiters must be mutually distinct or tokenizing is ambiguous. Compare the single-character
    # terminator (raw[+105]) so a CR+LF terminator is checked by its CR.
    distinct = [element, component, terminator]
    if repetition is not None:
        distinct.append(repetition)
    if len(set(distinct)) != len(distinct):
        raise X12PeekError(f"X12 delimiters are not mutually distinct: {distinct!r}")

    return Delimiters(element=element, component=component, segment=segment, repetition=repetition)
