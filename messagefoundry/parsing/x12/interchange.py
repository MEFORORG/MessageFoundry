# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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

import re
from collections.abc import Iterator

from messagefoundry.parsing.x12.delimiters import (
    _GATE_SEP_OFFSETS,
    _LEADING_NOISE,
    _SEGMENT_TERM_OFFSET,
    _SEGMENT_WHITESPACE,
    ISA_SEGMENT_LEN,
    _isa_delimiters_distinct,
    discover_delimiters,
    find_isa_start,
    isa_separators_line_up,
    iter_segments,
    skip_leading_noise,
)
from messagefoundry.parsing.x12.errors import X12FrameError

__all__ = ["split", "X12FrameReader", "check_integrity"]

# A segment that is the IEA trailer, after cosmetic whitespace. Matched in place with pos/endpos, so the
# check never copies a segment, however long. The class is a literal copy of _SEGMENT_WHITESPACE, not
# built from it, so the static ReDoS scan in tests/test_security_static.py can read the pattern;
# test_iea_segment_whitespace_matches_the_shared_set in tests/test_x12_parsing.py keeps the two equal.
_IEA_SEGMENT = re.compile(rb"[ \t\r\n\x0b\x0c]*IEA")
# The whitespace run that opens a segment, for the check whether the segment opens with ``ISA``
# (BACKLOG #5921). Literal classes for the same reason, and the same test keeps them equal.
_SEGMENT_WS_RUN = re.compile(rb"[ \t\r\n\x0b\x0c]*")
_SEGMENT_WS_RUN_STR = re.compile(r"[ \t\r\n\x0b\x0c]*")
#: Line-end bytes a sender may put after an interchange's closing terminator, such as a newline after
#: ``IEA*...~``. Up to :data:`_FRAME_TAIL_MAX` of them directly after a completed interchange are its
#: ending, however reads split them (vault BACKLOG #2938). The cap keeps a peer from trickling them
#: to hold a listener's frame deadline off: past it they are inter-interchange noise like any byte.
#: The same rule as ``messagefoundry.framing.FrameDecoder``'s, written as a local copy because
#: ``parsing`` may not import ``messagefoundry.framing`` (its import allowlist in
#: tests/test_dependency_boundaries.py). So the two can drift; the x12 and MLLP rows of
#: ``test_line_end_bytes_ending_a_frame_do_not_start_the_frame_deadline`` in
#: tests/test_listener_admission.py pin that both allow two line ends and cut on a third.
_FRAME_TAIL_BYTES = b"\r\n"
_FRAME_TAIL_MAX = 2


def split(raw: str) -> list[str]:
    """Split a complete buffer into its ``ISA…IEA`` interchange substrings (verbatim).

    Whitespace/BOM between elements is skipped. Nothing else is dropped: every other run of data
    becomes an element (BACKLOG #5921). An ``ISA`` *passes* when it is a whole header opening with
    a literal ``ISA`` and :func:`isa_separators_line_up` accepts it.

    * An ``ISA`` that passes is walked from past its fixed-width header to its ``IEA`` (read with
      the terminator at its +105), and returned verbatim through that ``IEA`` segment's terminator.
      This holds even where :func:`discover_delimiters` refuses it, for a delimiter inside ISA
      element data (BACKLOG #5536): the element is the whole interchange, never cut at a forged
      segment, so the parse of it refuses it. If a segment opening with an ``ISA`` that passes
      comes first (after this interchange's terminator and any whitespace), the element ends at
      the terminator before it, verbatim, so an interchange with no ``IEA`` does not swallow the
      next one; that ``ISA`` starts the next element. A segment that opens with a literal ``ISA``
      that fails, such as ``ISA~`` or a ``<terminator>ISA`` in binary data, is data in this
      interchange, so a complete one is not cut there; from it on, the element also ends at the
      next ``ISA`` that passes, anywhere, if its ``IEA`` has not come first, whitespace before
      that ``ISA`` included. Before such a failing ``ISA``, a later ``ISA`` behind anything
      else, such as a BOM or junk, does not end the walk. A passing interchange that reaches the
      end of the buffer with neither is the final element.
    * An ``ISA`` that fails, or one too short to hold a header, is a malformed interchange. One
      that fails ends at its own ``IEA``, read the same way, or at the next ``ISA`` that passes,
      wherever that is, whichever comes first. One too short to hold a header has no terminator to
      read, so it ends at the next ``ISA`` that passes, its own ``IEA`` and anything after it
      included.
    * A run that does not open with ``ISA`` is returned as its own element and ends at the next
      ``ISA`` that passes, so a trigram in it ("VISA", "ISAAC") does not end it.
    * A malformed or non-ISA element that ends at a later ``ISA`` loses the whitespace/BOM before
      that ``ISA``.

    An element is not checked beyond that. A malformed one does not parse, but one cut at a later
    ``ISA`` before its ``IEA`` may: :func:`check_integrity` reports its missing trailers, and
    X12Peek and X12Message do not. A buffer with no ``ISA`` at all returns its data as one element,
    and an empty or whitespace/BOM-only buffer returns ``[]``. :class:`X12FrameReader` frames an
    ``ISA`` the same way, but it discards a run that does not open with ``ISA``, and it keeps the
    whitespace before a later ``ISA`` in a malformed frame, so the two can differ there."""
    out: list[str] = []
    pos = 0
    n = len(raw)
    # The next ISA that passes, at or after the last search's start. Every ISA between that start and
    # it failed, so it stays the answer while the search would start at or before it: reusing it keeps
    # a run of many malformed interchanges linear. Only a run that does not pass needs it. Below
    # ``len(raw)`` it is a passing ISA, so reaching it needs no second check.
    good = -1
    while pos < n:
        start = skip_leading_noise(raw, pos)
        if start == n:
            break
        if start == good or _isa_complete_str(raw, start):
            end, at_iea = _walk_str(raw, start, cut_at_isa=True)
            if end is None:
                # Unterminated final interchange — surface it, don't lose it.
                out.append(raw[start:])
                break
            # Kept verbatim, as the reader frames it, whether it ends at its IEA or at a later ISA.
            out.append(raw[start:end])
            pos = end
            if not at_iea:
                # The walk ended at an ISA that passes, after whitespace only: it is not checked again.
                good = skip_leading_noise(raw, end)
            continue
        if good <= start:
            good = _next_isa_str(raw, start + 1)
        if raw.startswith("ISA", start):
            # A malformed header: bound it by the next ISA that passes so it cannot swallow that one.
            end, at_iea = _malformed_end_str(raw, start, good)
        else:
            end, at_iea = good, False  # non-ISA data — surface it
        # Ended at its own IEA it is kept verbatim, its terminator too, even a whitespace one.
        out.append(raw[start:end] if at_iea else raw[start:end].rstrip(_LEADING_NOISE))
        pos = end
    return out


def _isa_complete_str(raw: str, isa: int) -> bool:
    """Whether a whole ISA header, opening with a literal ``ISA``, is at ``isa`` and
    :func:`isa_separators_line_up` accepts it. In a complete buffer a header too short to tell is no
    header. The literal is checked here because the separator check never reads it, and the reader
    only ever starts a frame at a literal ``ISA``: a lowercase "isa" is data on both surfaces."""
    return (
        len(raw) >= isa + ISA_SEGMENT_LEN
        and raw.startswith("ISA", isa)
        and isa_separators_line_up(raw, isa)
    )


def _terminator_str(raw: str, isa: int) -> str:
    """The segment terminator at the ISA's +105: one character, or CR+LF. Empty past the end."""
    term = raw[isa + _SEGMENT_TERM_OFFSET : isa + _SEGMENT_TERM_OFFSET + 1]
    if term == "\r" and raw[isa + ISA_SEGMENT_LEN : isa + ISA_SEGMENT_LEN + 1] == "\n":
        return "\r\n"
    return term


def _next_isa_str(raw: str, start: int) -> int:
    """Index of the next ``ISA`` at/after ``start`` that :func:`_isa_complete_str` accepts, or
    ``len(raw)`` if there is none."""
    while (i := raw.find("ISA", start)) != -1:
        if _isa_complete_str(raw, i):
            return i
        start = i + 1
    return len(raw)


def _malformed_end_str(raw: str, isa: int, bound: int) -> tuple[int, bool]:
    """Where the malformed interchange at ``isa`` ends, and whether that is its own ``IEA``: just
    past its ``IEA`` segment, read with the terminator at its +105, when that comes before ``bound``;
    otherwise ``bound``."""
    if isa + ISA_SEGMENT_LEN > bound:
        return bound, False
    end, at_iea = _walk_str(raw, isa, bound)
    return (bound, False) if end is None else (end, at_iea)


def _walk_str(
    raw: str, isa: int, bound: int | None = None, *, cut_at_isa: bool = False
) -> tuple[int | None, bool]:
    """Walk the segments of the interchange at ``isa``, read with the terminator at its +105, from
    past its fixed-width header (so the ISA is never searched) up to ``bound`` (the end of ``raw``
    by default). Returns the index just past the terminator that closes its ``IEA`` segment and
    True, or None and False if that is not complete before ``bound``. ``IEA`` is matched only at a
    segment boundary.

    With ``cut_at_isa``, a segment that opens, after any whitespace, with an ``ISA`` that
    :func:`_isa_complete_str` accepts ends the walk too: it returns that segment's start, just past
    the terminator before it, and False, so the whitespace before that ``ISA`` falls between the
    two elements. A literal ``ISA`` that fails is data, and the walk goes on, but from there only
    up to the next ``ISA`` that passes, anywhere: the walk returns that ``ISA``'s index and False
    if its ``IEA`` does not come first, so junk or a cut-off header after an interchange with no
    ``IEA`` does not let it swallow the next one. The same rule as :class:`X12FrameReader`'s
    passing walk. The segment-start check runs at each segment start the walk reaches anyway and
    stops at the first gate position that differs; the bound is searched once per walk, from the
    failing ``ISA``, so a chain of interchanges is walked once, however they are separated."""
    terminator = _terminator_str(raw, isa)
    if not terminator:
        return None, False
    seg_start = isa + _SEGMENT_TERM_OFFSET + len(terminator)
    end = len(raw) if bound is None else bound
    # The end of the last whitespace run read, already decided not to end the walk. A whitespace
    # terminator can end segments inside that run, and the run from each ends at the same place.
    ws_end = -1
    while True:
        if cut_at_isa and seg_start > ws_end:
            run = _SEGMENT_WS_RUN_STR.match(raw, seg_start, end)
            ws_end = seg_start if run is None else run.end()  # a star pattern: never None
            # Only an ISA that passes ends the walk; one that fails, such as an "ISA~" segment, is
            # data. The check stops at the first gate that differs, so it stays bounded.
            if raw.startswith("ISA", ws_end):
                if _isa_complete_str(raw, ws_end):
                    return seg_start, False
                # Searched once per walk, from here, so a chain of walks searches each byte once.
                end, cut_at_isa = _next_isa_str(raw, ws_end + 1), False
        idx = raw.find(terminator, seg_start, end)
        if idx == -1:
            # Short of the buffer end, ``end`` is a bound: a later ISA that passes, or the caller's.
            return (end, False) if end < len(raw) else (None, False)
        if (
            # With cut_at_isa the segment's opening whitespace has been read already.
            raw.startswith("IEA", ws_end, idx)
            if cut_at_isa
            else raw[seg_start:idx].lstrip(_SEGMENT_WHITESPACE)[:3] == "IEA"
        ):
            return idx + len(terminator), True
        seg_start = idx + len(terminator)


class X12FrameReader:
    """Stateful byte reassembler that yields complete X12 interchanges from a raw TCP stream.

    Feed it whatever bytes arrive; it yields each complete ``ISA…IEA<terminator>`` interchange (bytes,
    verbatim) as it completes. Inter-interchange noise before an ``ISA`` is discarded. An ``ISA`` that
    fails :func:`isa_separators_line_up` (an "ISA" trigram in noise, padded text, or a corrupted
    header) is framed through its own ``IEA`` or up to the next ``ISA`` that passes, whichever comes
    first, so it cannot swallow that interchange and is not dropped either (BACKLOG #5921). An
    interchange whose ``ISA`` passes is framed through its ``IEA`` or through the terminator before
    a later segment that opens with an ``ISA`` that passes (only that terminator and whitespace
    before it), so one with no ``IEA`` does not swallow a next one that follows it that way; the
    whitespace between is discarded as noise. A frame cut at a passing ``ISA`` before its ``IEA``
    still parses; :func:`check_integrity` reports its missing trailers. A segment opening with a
    literal ``ISA`` that fails, such as ``ISA~``, is data in the interchange, and from it on the
    frame is bounded as a suspect's is, by the next ``ISA`` that passes; one whose header has not
    all arrived is held, with the open frame, until it has. This reader refuses
    no frame for its content. At least the shared ingress guards (the charset decode, the NUL check
    and the size bound) and a Router or Handler that peeks or parses the frame may refuse it later.
    ``max_interchange_bytes`` caps a
    single open interchange (``None`` disables) — exceeding it raises :class:`X12FrameError` so the
    transport drops the connection rather than buffer without bound.
    """

    def __init__(self, max_interchange_bytes: int | None = None) -> None:
        self._buf = bytearray()
        self.max_interchange_bytes = max_interchange_bytes
        # Resume points for the segment walk over the open interchange at the front of ``_buf``. The
        # feed size is the sender's choice, so rescanning from the ISA on every feed would make
        # reassembly quadratic (BACKLOG #1595). ``_seg_start`` is where the segment still being
        # received begins; ``_scan`` is where the terminator search picks up, at or after it.
        self._seg_start = 0
        self._scan = 0
        # Whether the walk is bounded by the next ISA that passes: the ISA at the front of ``_buf``
        # failed the structural check, so it may be an "ISA" trigram in noise rather than an
        # interchange (BACKLOG #5921), or a passing walk met a failing ISA opening a segment. And
        # where the search for a
        # later ISA that passes so far picks up. See :meth:`_bound`. ``_probe`` counts from the start
        # of the stream, with ``_dropped`` the bytes cut off the front of ``_buf`` so far, so a search
        # already made is not repeated for the next suspect in the same buffer.
        self._suspect = False
        self._probe = 0
        self._dropped = 0
        # How many gate positions of the candidate at ``_probe_gate_at`` (counted like ``_probe``)
        # have been read and hold its separator, so a candidate still arriving is read once.
        self._probe_gate = 0
        self._probe_gate_at = -1
        # For a passing walk, whether the segment at ``_seg_start`` has been decided not to end the
        # walk (it does not open with an ISA that passes), and how far the whitespace run opening it
        # has been read, so a run still arriving is read once rather than once per feed.
        self._seg_decided = False
        self._seg_ws = 0
        # How many gate positions of an ISA opening that segment have been read and hold its
        # separator, so a header still arriving is checked once rather than once per feed. Nonzero
        # only while that ISA is undecided: deciding it, or taking the frame, resets it.
        self._isa_gate = 0
        #: Line-end bytes the last completed interchange may still take as its ending; 0 once any
        #: other byte has followed it. See :data:`_FRAME_TAIL_BYTES`.
        self._tail_left = 0
        #: Whether the most recent :meth:`feed` held nothing but line-end bytes ending the
        #: interchange before it. Such a read finishes that interchange rather than starting anything,
        #: which is how a listener's frame deadline tells it from inter-interchange noise (vault
        #: BACKLOG #2938). Set when :meth:`feed` is called, before its generator is iterated. It only
        #: observes: the bytes still go to the buffer, so the noise handling is unchanged.
        self.trailer_only = False

    @property
    def in_frame(self) -> bool:
        """``True`` while an interchange is open: its ``ISA`` has arrived and its ``IEA`` has not.
        Noise before an ``ISA`` opens nothing. The listener's frame deadline runs off this
        (vault BACKLOG #2606), as it runs off :attr:`FrameDecoder.in_frame` for delimiter framing."""
        return self._buf.startswith(b"ISA")

    def feed(self, data: bytes) -> Iterator[bytes]:
        """Yield each interchange completed by ``data``, carrying any partial one to the next call.

        :attr:`trailer_only` is decided here, eagerly, so it never describes an earlier read; the
        reassembly itself still runs lazily as the generator is iterated. The allowance it reads is
        set as an interchange is taken, so drain one call's generator before the next call, as the
        listener does; a caller that stops early reads the next call's flag against a stale
        allowance.
        """
        self.trailer_only = bool(data) and _only_line_ends(data, self._tail_left)
        # Any other byte ends the allowance: what follows it is not the interchange's ending. An
        # empty read holds no byte, so it leaves the allowance as it was, as FrameDecoder does.
        if data and not self.trailer_only:
            self._tail_left = 0
        else:
            self._tail_left -= len(data)
        return self._frames(data)

    def _frames(self, data: bytes) -> Iterator[bytes]:
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
                self._drop(len(buf) - 2)
            self._check_cap()
            return None
        if isa > 0:
            self._drop(isa)  # drop inter-interchange noise before the ISA
        # An "ISA" whose fixed separator positions disagree may be a trigram in noise. Taking it as an
        # interchange start let its walk swallow a real interchange behind it (BACKLOG #5921). It may
        # also be a real interchange with a corrupted header, so it is not dropped either: it is walked
        # like any other, but never past the next ISA that passes, and is framed at that ISA if its own
        # IEA has not come first. The check is structural only, so #5536 still frames a delimiter in
        # ISA data whole. Until the walk starts a short header is checked again on each feed. A
        # passing ISA needs its whole header to confirm it, so a suspect is never cut while its own
        # header is short: a bound short of +106 is met in the walk below, whose search then finds
        # nothing before the bound.
        if not self._suspect and self._seg_start == 0 and not isa_separators_line_up(buf, 0):
            self._suspect = True
            self._probe = max(self._probe, self._dropped + 1)
        bound, confirmed = self._bound() if self._suspect else (len(buf), False)
        if len(buf) < ISA_SEGMENT_LEN or (
            buf[_SEGMENT_TERM_OFFSET : _SEGMENT_TERM_OFFSET + 1] == b"\r"
            and len(buf) < ISA_SEGMENT_LEN + 1
        ):
            # Need the full ISA to discover the terminator. If +105 is CR the terminator may be a
            # 2-byte CR+LF, so wait for +106 before reading it: a terminator split exactly across two
            # socket reads is still read whole (not a bare CR).
            self._check_cap(bound)
            return None
        terminator = self._terminator(buf)
        if self._seg_start == 0:
            # The walk starts past the ISA's own terminator. The ISA is fixed-width, so a terminator
            # byte inside its element data (a "~IEA" in ISA06) must not end a segment there: that
            # cut the frame at the ISA and dropped the real body as noise (BACKLOG #5536). Such an
            # ISA is framed whole here. This reader does not refuse it; at least the shared ingress
            # guards and anything that peeks or parses the frame may.
            self._seg_start = self._scan = _SEGMENT_TERM_OFFSET + len(terminator)
            self._seg_ws, self._seg_decided = self._seg_start, False
        # Walk the segments, resuming where the last feed stopped. The ISA stays at the front of the
        # buffer until its frame is taken or the buffer is cleared, and both reset the resume points,
        # so they always describe this interchange. Each byte is searched about once in total.
        while True:
            if not self._suspect and not self._seg_decided:
                # A passing walk ends at a segment that opens with an ISA that passes, so an
                # interchange with no IEA does not swallow the next one (BACKLOG #5921). The frame
                # ends at the terminator before it; the whitespace between is noise. A literal
                # "ISA" that fails is data, so a complete interchange holding an "ISA~" segment is
                # not cut. Checked at each segment start the walk reaches, so it stays linear
                # however the interchanges are separated. split ends its walk the same way.
                run = _SEGMENT_WS_RUN.match(buf, self._seg_ws)
                self._seg_ws = ws = self._seg_ws if run is None else run.end()
                if len(buf) < ws + 3 and b"ISA".startswith(buf[ws:]):
                    # Whitespace, "I" or "IS" so far: what opens this segment has not arrived. The
                    # whitespace is charged, so a peer cannot grow the buffer with it unbounded;
                    # a trailing "I" or "IS" is not, as it may be the next ISA's.
                    self._check_cap(ws)
                    return None
                if buf.startswith(b"ISA", ws):
                    passes = self._isa_passes(ws)
                    if passes is None:
                        # Not enough of the header has arrived to tell an ISA that passes from
                        # data, so hold. The bytes from it are not charged: at most one header.
                        self._check_cap(ws)
                        return None
                    if passes:
                        # The whitespace before the cut is charged as the wait above charges it, so
                        # whether the cap refuses this frame does not depend on how reads split it.
                        self._check_cap(ws)
                        return self._take(self._seg_start)
                    # An "ISA" that fails, such as an "ISA~" segment, is data in this interchange.
                    # It may also be junk or a cut-off header between an interchange with no IEA
                    # and the next one, so from here the walk is bounded by the next ISA that
                    # passes, anywhere, as a suspect's is: a complete interchange still reaches
                    # its IEA first, and one with no IEA does not swallow the next.
                    self._suspect = True
                    self._probe = max(self._probe, self._dropped + ws + 1)
                    bound, confirmed = self._bound()
                self._seg_decided, self._isa_gate = True, 0
            idx = buf.find(terminator, self._scan, bound)
            if idx == -1:
                if confirmed:
                    return self._take(bound)
                # Back off by all but one terminator byte, so a CR+LF split across two feeds is found.
                self._scan = max(self._seg_start, bound - len(terminator) + 1)
                self._check_cap(bound)
                return None  # IEA not complete yet
            if (
                # A passing walk has read this segment's opening whitespace already.
                buf.startswith(b"IEA", self._seg_ws, idx)
                if not self._suspect
                else _IEA_SEGMENT.match(buf, self._seg_start, idx)
            ):
                return self._take(idx + len(terminator))
            self._seg_start = self._scan = idx + len(terminator)
            # A whitespace terminator can end a segment inside the run already read: the run from
            # here ends at the same byte, already decided, so it is not read again.
            if self._seg_start > self._seg_ws:
                self._seg_ws, self._seg_decided = self._seg_start, False

    def _isa_passes(self, isa: int) -> bool | None:
        """Whether the ``ISA`` at ``isa``, opening the segment a passing walk is at, passes
        :func:`isa_separators_line_up` as a whole header, resumed from :attr:`_isa_gate`. See
        :func:`_whole_isa_passes`."""
        verdict, self._isa_gate = _whole_isa_passes(self._buf, isa, self._isa_gate)
        return verdict

    def _take(self, end: int) -> bytes:
        """Cut the frame ``_buf[:end]`` off the front and reset the walk for what follows it."""
        if self.max_interchange_bytes is not None and end > self.max_interchange_bytes:
            # A complete frame that still exceeds the cap is rejected (a too-large message), not
            # relayed — mirrors the eager cap on the shared FrameDecoder.
            self._clear()
            raise X12FrameError(
                f"X12 interchange ({end} bytes) exceeds the {self.max_interchange_bytes}-byte cap"
            )
        buf = self._buf
        frame = bytes(buf[:end])
        self._drop(end)
        self._reset_walk()
        # What the read held past the frame: line ends alone are owed to it, so the allowance left
        # is what they have not used yet.
        tail = _only_line_ends(buf, _FRAME_TAIL_MAX)
        self._tail_left = _FRAME_TAIL_MAX - len(buf) if tail else 0
        return frame

    def _bound(self) -> tuple[int, bool]:
        """How far a suspect's walk may search: the first later ``ISA`` in ``_buf`` whose separator
        positions that have arrived pass :func:`isa_separators_line_up`, and whether all of them
        have arrived. While there is none it is ``len(_buf)``, less a trailing ``I`` or ``IS`` held
        back as the possible start of one, and False. A candidate that fails is passed at once; one
        still arriving is searched again on the next feed, so each byte is searched about once."""
        buf = self._buf
        base = self._dropped
        while (i := buf.find(b"ISA", self._probe - base)) != -1:
            # The gates already read hold only for the candidate they were read at.
            gate = self._probe_gate if self._probe_gate_at == base + i else 0
            verdict, gate = _whole_isa_passes(buf, i, gate)
            if verdict is not False:
                self._probe = self._probe_gate_at = base + i
                self._probe_gate = gate
                return i, bool(verdict)
            self._probe = base + i + 1
        # Keep the last two bytes in the search, in case "IS" straddles two reads. The walk stops
        # short of them too: they may open the next ISA, and a frame cut inside it would lose that
        # interchange in small reads only.
        held = 2 if buf.endswith(b"IS") else 1 if buf.endswith(b"I") else 0
        self._probe = max(self._probe, base + len(buf) - 2)
        return len(buf) - held, False

    def _drop(self, n: int) -> None:
        """Cut ``n`` bytes off the front of ``_buf``, keeping :attr:`_probe`'s origin."""
        del self._buf[:n]
        self._dropped += n

    def _reset_walk(self) -> None:
        self._seg_start = self._scan = self._seg_ws = self._isa_gate = 0
        self._seg_decided = False
        self._suspect = False

    @staticmethod
    def _terminator(buf: bytearray) -> bytes:
        """The segment terminator from the ISA at the front of ``buf`` — one byte, or CR+LF."""
        term = bytes(buf[_SEGMENT_TERM_OFFSET : _SEGMENT_TERM_OFFSET + 1])
        if term == b"\r" and buf[106:107] == b"\n":
            return b"\r\n"
        return term

    def _clear(self) -> None:
        self._drop(len(self._buf))
        self._reset_walk()
        # No interchange precedes a cleared buffer, so no line end is owed to one.
        self._tail_left = 0

    def _check_cap(self, bound: int | None = None) -> None:
        # Called from every path that returns with the interchange still open. Only one of those can
        # grow the buffer without bound: the segment walk. The rest are already capped by the control
        # flow that reaches them (a 2-byte noise tail, or a partial ISA, so 106 bytes at most), and
        # could not fire unless the cap were smaller than one ISA header. tests/test_x12_parsing.py
        # pins the walk's cap twice, with and without "IEA" in element data; keep both if this moves.
        # ``bound`` is where the open frame must end, at a later ISA: the bytes past it belong to that
        # ISA, which is never more than one header still arriving, so they are not charged to this
        # frame. Charging them made the refusal depend on how the stream was split into reads. A
        # passing walk passes the end of the whitespace that may come before a next ISA instead: it
        # charges that whitespace both while it waits and when it cuts there, so the refusal still
        # does not depend on the reads, though the frame it then takes leaves the whitespace out. With
        # no later ISA yet, a trailing "I" or "IS" may be the start of one, so it is not charged
        # either; a frame that really ends in them is still measured whole by _take.
        buf = self._buf
        held = len(buf) if bound is None else min(bound, len(buf))
        if held == len(buf):
            held -= 2 if buf.endswith(b"IS") else 1 if buf.endswith(b"I") else 0
        if self.max_interchange_bytes is not None and held > self.max_interchange_bytes:
            self._clear()
            raise X12FrameError(
                f"X12 interchange exceeded {self.max_interchange_bytes} bytes before the IEA segment"
            )


def _whole_isa_passes(buf: bytearray, isa: int, gate: int) -> tuple[bool | None, int]:
    """Whether the ``ISA`` at ``isa`` passes :func:`isa_separators_line_up` as a whole header: True
    or False, or None while the bytes that decide it have not arrived, and how many gate positions
    have been read and hold its separator. Pass that count back on the next feed: the gates are
    read in order from it, so a header trickled in is read about once, and the first that differs
    ends the check (an ``ISA~`` segment fails at its +6)."""
    sep = buf[isa + 3 : isa + 4]
    if not sep:
        return None, gate
    while gate < len(_GATE_SEP_OFFSETS):
        at = isa + _GATE_SEP_OFFSETS[gate]
        found = buf[at : at + 1]
        if not found:
            return None, gate
        if found != sep:
            return False, gate
        gate += 1
    if len(buf) < isa + ISA_SEGMENT_LEN:
        return None, gate
    # Every gate holds the separator, so only the distinctness rule is left.
    return _isa_delimiters_distinct(buf, isa), gate


def _only_line_ends(data: bytes | bytearray, limit: int) -> bool:
    """Whether ``data`` is at most ``limit`` bytes, every one a line end. The length is checked
    first, so a large buffer is never copied by the strip."""
    return len(data) <= limit and not data.strip(_FRAME_TAIL_BYTES)


def check_integrity(raw: str) -> list[str]:
    """Structural integrity tie-out for one interchange (a pure helper, opt-in).

    Returns a list of human-readable problems (empty when the interchange ties out): the control-number
    pairs ISA13==IEA02, GS06==GE02, ST02==SE02, the counts GE01==#ST, IEA01==#GS, and an ST, GS or
    ISA left without its SE, GE or IEA. This is *not*
    implementation-guide validation (deferred) — just the envelope self-consistency a receiver can cheaply
    confirm. Raises :class:`X12PeekError` only if the interchange header itself is unparseable."""
    isa = find_isa_start(raw)
    segments = list(iter_segments(raw, isa, discover_delimiters(raw, isa)))

    problems: list[str] = []

    def get(fields: list[str], i: int) -> str:
        return fields[i].strip() if i < len(fields) else ""

    iea_seg = next((s for s in segments if s[0] == "IEA"), None)
    if iea_seg is not None:  # iter_segments always yields the ISA first
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
        # A set or group a new one opens over never closed: report it rather than overwrite it.
        if tag in ("GS", "ST", "GE") and current_st is not None:
            problems.append(f"ST02 {get(current_st, 2)!r} has no SE")
            current_st = None
        if tag == "GS":
            if current_gs is not None:
                problems.append(f"GS06 {get(current_gs, 6)!r} has no GE")
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
    # A frame cut at a later ISA before its trailers still parses, so report what never closed
    # (BACKLOG #5921). The values are control numbers, never message content.
    if current_st is not None:
        problems.append(f"ST02 {get(current_st, 2)!r} has no SE")
    if current_gs is not None:
        problems.append(f"GS06 {get(current_gs, 6)!r} has no GE")
    if iea_seg is None:
        problems.append("no IEA segment")
    return problems
