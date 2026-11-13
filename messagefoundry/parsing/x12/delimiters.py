# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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

from collections.abc import Iterator
from dataclasses import dataclass

from messagefoundry.parsing.x12.errors import X12PeekError

__all__ = [
    "Delimiters",
    "discover_delimiters",
    "find_isa_start",
    "isa_end",
    "isa_separators_line_up",
    "iter_segments",
    "skip_leading_noise",
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
# The sanity-gate positions: every element-separator offset but the defining one at +3.
_GATE_SEP_OFFSETS = ELEMENT_SEP_OFFSETS[1:]
# (element number, start, end) of each ISA element's data relative to the ISA start, from the same
# widths: ISA01 is (1, 4, 6) and ISA16 is (16, 104, 105).
_ISA_ELEMENT_SPANS = tuple(
    (number, offset + 1, offset + 1 + width)
    for number, (offset, width) in enumerate(
        zip(ELEMENT_SEP_OFFSETS, _ISA_ELEMENT_WIDTHS, strict=True), 1
    )
)
_COMPONENT_SEP_OFFSET = 104  # ISA16
_SEGMENT_TERM_OFFSET = 105
_REPETITION_SEP_OFFSET = 82  # ISA11
_VERSION_START, _VERSION_END = 84, 89  # ISA12 (5 chars), e.g. "00501"
_REPETITION_MIN_VERSION = "00501"  # ISA11 is a repetition separator from 005010 onward
# Cosmetic whitespace tolerated before a segment (a pretty-printed feed puts a newline after each one).
_SEGMENT_WHITESPACE = " \t\r\n\x0b\x0c"

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


def skip_leading_noise(raw: str, start: int = 0) -> int:
    """Index of the first character at/after ``start`` that is not whitespace or a BOM
    (``len(raw)`` if there is none)."""
    i, n = start, len(raw)
    while i < n and raw[i] in _LEADING_NOISE:
        i += 1
    return i


def find_isa_start(raw: str, start: int = 0) -> int:
    """Index of the ``ISA`` that opens the next interchange at/after ``start`` (skipping leading
    whitespace/BOM). Raises :class:`X12PeekError` if no ``ISA`` is found there."""
    i = skip_leading_noise(raw, start)
    if raw[i : i + 3] != "ISA":
        raise X12PeekError("X12 interchange does not begin with an ISA segment")
    return i


def isa_separators_line_up(buf: str | bytes | bytearray, isa: int) -> bool:
    """Whether the ``ISA`` at ``isa`` could open an interchange: every fixed element-separator
    position present in ``buf`` holds the character at +3. Positions past the end of ``buf`` are not
    yet known, so a short header passes. Structural only, the same positions as the sanity gate in
    :func:`discover_delimiters`: it never reads element data, so an ISA with a delimiter inside an
    element still passes and the parse refuses it (BACKLOG #5536, #5921)."""
    sep = buf[isa + 3 : isa + 4]
    for offset in _GATE_SEP_OFFSETS:
        found = buf[isa + offset : isa + offset + 1]
        if not found:
            return True
        if found != sep:
            return False
    return True


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
    if terminator == "\r" and raw[start + 106 : start + 107] == "\n":  # noqa: SIM108
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
    for offset in _GATE_SEP_OFFSETS:
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

    # The element separator and the segment terminator may not appear in ISA element data (the X12
    # standard's own rule). The engine reads the ISA by offset, but a tokenizer that splits it on them,
    # a partner's for one, would let a terminator inside ISA06 open a segment there, so a sender id
    # could forge an ST or an IEA, or an element separator shift every ISA element after it (BACKLOG
    # #5536). For a CR+LF terminator both characters are refused. The component and repetition
    # separators are not: nothing splits the ISA on them, and a 00501 header still carrying ISA11 "U"
    # would otherwise refuse every id holding a U. Every element is checked, ISA11 and ISA16 too: the
    # distinctness check above already keeps the element separator and the terminator's first
    # character out of them, and an LF there beside a CR+LF terminator is refused here. The message
    # names the element only, never its value.
    forbidden = set(element) | set(segment)
    for number, lo, hi in _ISA_ELEMENT_SPANS:
        if not forbidden.isdisjoint(raw[start + lo : start + hi]):
            raise X12PeekError(
                f"X12 ISA header malformed: ISA-{number:02d} holds a delimiter character; "
                "the element separator and segment terminator may not appear in element data"
            )

    return Delimiters(element=element, component=component, segment=segment, repetition=repetition)


def isa_end(isa_start: int, delimiters: Delimiters) -> int:
    """Index just past the ISA's own segment terminator, where the first body segment begins
    (``isa_start + 106``, or ``+ 107`` for a ``CR``+``LF`` terminator)."""
    return isa_start + _SEGMENT_TERM_OFFSET + len(delimiters.segment)


def iter_segments(raw: str, isa_start: int, delimiters: Delimiters) -> Iterator[list[str]]:
    """Yield each segment of the interchange at ``isa_start`` as its element list (``[tag, e1, …]``),
    stopping after ``IEA``. Tolerates cosmetic whitespace before a segment.

    The ISA's list is ``ISA`` and its 16 elements, each read at its fixed span, and the body is
    tokenized only from :func:`isa_end` on, so nothing in the fixed-width header can open a segment or
    shift an element (BACKLOG #5536). ``delimiters`` must come from :func:`discover_delimiters` on
    this ISA."""
    element, terminator = delimiters.element, delimiters.segment
    yield ["ISA", *(raw[isa_start + lo : isa_start + hi] for _, lo, hi in _ISA_ELEMENT_SPANS)]
    # Walk with find rather than split the remainder, so the body is neither copied whole nor split
    # past the IEA (X12Peek runs this walk on the routing path).
    pos, n = isa_end(isa_start, delimiters), len(raw)
    while pos < n:
        idx = raw.find(terminator, pos)
        end = n if idx == -1 else idx
        stripped = raw[pos:end].lstrip(_SEGMENT_WHITESPACE)
        pos = end + len(terminator)
        if not stripped:
            continue
        fields = stripped.split(element)
        yield fields
        if fields[0] == "IEA":
            return
