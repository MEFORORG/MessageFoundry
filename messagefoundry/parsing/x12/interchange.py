# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Interchange framing for X12 — splitting one stream into complete ``ISA…IEA`` interchanges.

X12-over-TCP has **no transport sentinel**: the *frame is the interchange*, bounded by the opening
``ISA`` and the closing ``IEA`` segment, and the segment terminator is **discovered from each ISA
header** (it may even be a two-byte ``CR``+``LF``). The shared single-byte
:class:`~messagefoundry.transports.framing.FrameDecoder` cannot express any of that, so X12 needs its
own assembler. It lives **here**, in the pure parsing layer, so it is unit-testable without a socket
and reusable by File/console paths; :mod:`messagefoundry.transports.x12` is a thin socket wrapper.

Two surfaces:

* :func:`split` — split a complete ``str`` buffer into interchange substrings (for a Router/console
  handed a ``RawMessage`` that carries more than one interchange).
* :class:`X12FrameReader` — a stateful **byte** reassembler (feed it socket chunks, it yields complete
  interchange bytes) for the transport.

The ``IEA`` trailer is recognised only at a **segment boundary** (the three bytes immediately after a
segment terminator, tolerating cosmetic whitespace), so ``IEA`` appearing inside element data never
truncates an interchange early. Both surfaces preserve the interchange **verbatim** (cosmetic newlines
included) — re-encoding/normalisation is :class:`~messagefoundry.parsing.x12.message.X12Message`'s job.
"""

from __future__ import annotations

from collections.abc import Iterator

from messagefoundry.parsing.x12.delimiters import (
    ISA_SEGMENT_LEN,
    discover_delimiters,
    find_isa_start,
)
from messagefoundry.parsing.x12.errors import X12FrameError, X12PeekError

__all__ = ["split", "X12FrameReader", "check_integrity"]

# Offset of the segment terminator within the ISA (mirrors delimiters._SEGMENT_TERM_OFFSET, but kept
# local so the byte reader needs only this module + the public ISA length).
_SEGMENT_TERM_OFFSET = 105
_WHITESPACE_BYTES = b" \t\r\n\x0b\x0c"
_WHITESPACE_STR = " \t\r\n\x0b\x0c"


def split(raw: str) -> list[str]:
    """Split a complete buffer into its ``ISA…IEA`` interchange substrings (verbatim).

    Inter-interchange whitespace/BOM is skipped. A trailing fragment that opens with ``ISA`` but never
    closes with ``IEA`` is returned as the final (malformed) element so nothing is silently dropped —
    the caller can dead-letter it. Raises :class:`X12PeekError` if a fragment's ISA header is itself
    unparseable (truncated/malformed)."""
    out: list[str] = []
    pos = 0
    n = len(raw)
    while pos < n:
        try:
            isa = find_isa_start(raw, pos)
        except X12PeekError:
            break  # no further interchange — only trailing noise remains
        terminator = discover_delimiters(raw, isa).segment
        end = _find_iea_end_str(raw, isa, terminator)
        if end is None:
            out.append(raw[isa:])  # unterminated final interchange — surface it, don't lose it
            break
        out.append(raw[isa:end])
        pos = end
    return out


def _find_iea_end_str(raw: str, isa: int, terminator: str) -> int | None:
    """Index just past the terminator that closes the ``IEA`` segment of the interchange at ``isa``,
    or None if it is not complete. ``IEA`` is matched only at a segment boundary."""
    seg_start = isa
    while True:
        idx = raw.find(terminator, seg_start)
        if idx == -1:
            return None
        if raw[seg_start:idx].lstrip(_WHITESPACE_STR)[:3] == "IEA":
            return idx + len(terminator)
        seg_start = idx + len(terminator)


class X12FrameReader:
    """Stateful byte reassembler that yields complete X12 interchanges from a raw TCP stream.

    Feed it whatever bytes arrive; it yields each complete ``ISA…IEA<terminator>`` interchange (bytes,
    verbatim) as it completes. Inter-interchange noise is discarded. ``max_interchange_bytes`` caps a
    single open interchange (``None`` disables) — exceeding it raises :class:`X12FrameError` so the
    transport drops the connection rather than buffer without bound.
    """

    def __init__(self, max_interchange_bytes: int | None = None) -> None:
        self._buf = bytearray()
        self.max_interchange_bytes = max_interchange_bytes

    def feed(self, data: bytes) -> Iterator[bytes]:
        self._buf.extend(data)
        while True:
            frame = self._take_one()
            if frame is None:
                return
            yield frame

    def _take_one(self) -> bytes | None:
        buf = self._buf
        isa = buf.find(b"ISA")
        if isa == -1:
            # No ISA yet: discard noise but keep a 2-byte tail in case "IS" straddles two reads.
            if len(buf) > 2:
                del buf[: len(buf) - 2]
            self._check_cap()
            return None
        if isa > 0:
            del buf[:isa]  # drop inter-interchange noise before the ISA
        if len(buf) < ISA_SEGMENT_LEN:
            self._check_cap()
            return None  # need the full ISA to discover the terminator
        if (
            buf[_SEGMENT_TERM_OFFSET : _SEGMENT_TERM_OFFSET + 1] == b"\r"
            and len(buf) < ISA_SEGMENT_LEN + 1
        ):
            # +105 is CR, so the terminator may be a 2-byte CR+LF; wait for +106 before reading it so a
            # terminator split exactly across two socket reads is still read whole (not a bare CR).
            self._check_cap()
            return None
        terminator = self._terminator(buf)
        # Cheap guard: don't walk segments until an IEA could plausibly be present.
        if buf.find(b"IEA", 3) == -1:
            self._check_cap()
            return None
        seg_start = 0
        while True:
            idx = buf.find(terminator, seg_start)
            if idx == -1:
                self._check_cap()
                return None  # IEA not complete yet
            if bytes(buf[seg_start:idx]).lstrip(_WHITESPACE_BYTES)[:3] == b"IEA":
                end = idx + len(terminator)
                if self.max_interchange_bytes is not None and end > self.max_interchange_bytes:
                    # A complete interchange that still exceeds the cap is rejected (a too-large
                    # message), not relayed — mirrors the eager cap on the shared FrameDecoder.
                    self._buf.clear()
                    raise X12FrameError(
                        f"X12 interchange ({end} bytes) exceeds the "
                        f"{self.max_interchange_bytes}-byte cap"
                    )
                frame = bytes(buf[:end])
                del buf[:end]
                return frame
            seg_start = idx + len(terminator)

    @staticmethod
    def _terminator(buf: bytearray) -> bytes:
        """The segment terminator from the ISA at the front of ``buf`` — one byte, or CR+LF."""
        term = bytes(buf[_SEGMENT_TERM_OFFSET : _SEGMENT_TERM_OFFSET + 1])
        if term == b"\r" and buf[106:107] == b"\n":
            return b"\r\n"
        return term

    def _check_cap(self) -> None:
        if self.max_interchange_bytes is not None and len(self._buf) > self.max_interchange_bytes:
            self._buf.clear()
            raise X12FrameError(
                f"X12 interchange exceeded {self.max_interchange_bytes} bytes before the IEA segment"
            )


def check_integrity(raw: str) -> list[str]:
    """Structural integrity tie-out for one interchange (a pure helper, opt-in).

    Returns a list of human-readable problems (empty when the interchange ties out): the control-number
    pairs ISA13==IEA02, GS06==GE02, ST02==SE02, and the counts GE01==#ST, IEA01==#GS. This is *not*
    implementation-guide validation (deferred) — just the envelope self-consistency a receiver can cheaply
    confirm. Raises :class:`X12PeekError` only if the interchange header itself is unparseable."""
    isa = find_isa_start(raw)
    delims = discover_delimiters(raw, isa)
    element, terminator = delims.element, delims.segment
    segments: list[list[str]] = []
    for chunk in raw[isa:].split(terminator):
        stripped = chunk.lstrip(_WHITESPACE_STR)
        if not stripped:
            continue
        segments.append(stripped.split(element))
        if segments[-1][0] == "IEA":
            break

    problems: list[str] = []

    def get(fields: list[str], i: int) -> str:
        return fields[i].strip() if i < len(fields) else ""

    isa_seg = segments[0] if segments and segments[0][0] == "ISA" else None
    iea_seg = next((s for s in segments if s[0] == "IEA"), None)
    if isa_seg is not None and iea_seg is not None:
        # ISA13 is read by offset (fixed-width); IEA02 from the tokenized IEA segment.
        isa13 = raw[isa + 90 : isa + 99].strip()
        if isa13 != get(iea_seg, 2):
            problems.append(f"ISA13 {isa13!r} != IEA02 {get(iea_seg, 2)!r}")
        gs_count = sum(1 for s in segments if s[0] == "GS")
        if get(iea_seg, 1) != str(gs_count):
            problems.append(f"IEA01 {get(iea_seg, 1)!r} != actual GS count {gs_count}")

    # Per functional group: GS06==GE02 and GE01==#ST in the group.
    current_gs: list[str] | None = None
    st_in_group = 0
    # Per transaction set: ST02==SE02 and SE01==#segments in the set (inclusive of ST and SE).
    current_st: list[str] | None = None
    seg_in_set = 0
    for fields in segments:
        tag = fields[0]
        if current_st is not None:
            seg_in_set += 1
        if tag == "GS":
            current_gs, st_in_group = fields, 0
        elif tag == "ST":
            current_st, seg_in_set = fields, 1  # the ST itself is segment 1 of the set
            st_in_group += 1
        elif tag == "SE":
            if current_st is not None:
                if get(fields, 2) != get(current_st, 2):
                    problems.append(f"SE02 {get(fields, 2)!r} != ST02 {get(current_st, 2)!r}")
                if get(fields, 1) != str(seg_in_set):
                    problems.append(f"SE01 {get(fields, 1)!r} != actual segment count {seg_in_set}")
            current_st = None
        elif tag == "GE":
            if current_gs is not None:
                if get(fields, 2) != get(current_gs, 6):
                    problems.append(f"GE02 {get(fields, 2)!r} != GS06 {get(current_gs, 6)!r}")
                if get(fields, 1) != str(st_in_group):
                    problems.append(f"GE01 {get(fields, 1)!r} != actual ST count {st_in_group}")
            current_gs = None
    return problems
