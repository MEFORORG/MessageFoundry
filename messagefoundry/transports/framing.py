# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Configurable delimiter framing — the shared codec under MLLP and raw-TCP transports.

A *frame codec* wraps each message in a small envelope of fixed bytes::

    <start> payload-bytes <end>[<trailer>]

MLLP is one preset of this (``start=0x0B``, ``end=0x1C``, ``trailer=0x0D`` — VT/FS+CR);
raw X12-over-TCP feeds use others (STX/ETX, ``0x02``/``0x03``, no trailer). The single most
common place toy engines break is framing: forgetting a trailer, treating the start/end bytes
as message content, or assuming one message per TCP read. A real peer may split a message
across reads or pack several into one. :class:`FrameDecoder` is a stateful, byte-accurate
reassembler that handles both, for any configured delimiters.

Length-prefix framing (a leading byte count instead of an end delimiter) is **out of scope**
here and is a documented follow-up — this codec is delimiter-framed only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator

__all__ = [
    "FrameError",
    "FrameCodec",
    "FrameDecoder",
    "MLLP_CODEC",
    "STX_ETX_CODEC",
    "PRESETS",
    "codec_for",
]


class FrameError(ValueError):
    """Raised when a frame exceeds its configured byte cap before the end delimiter.

    Signals the caller to drop the connection rather than buffer an unbounded frame.
    """


@dataclass(frozen=True)
class FrameCodec:
    """A delimiter framing scheme: a ``start`` byte, an ``end`` byte, and an optional ``trailer``.

    All three are byte values in ``0..255``. ``frame()`` wraps a payload; :meth:`decoder` builds a
    stateful streaming :class:`FrameDecoder`. The ``trailer`` (e.g. MLLP's CR) is **emitted** when
    framing but **not required** when decoding — a tolerant receiver treats any inter-frame bytes,
    including a stray trailer after the end delimiter, as noise to discard.
    """

    start: int
    end: int
    trailer: int | None = None

    def __post_init__(self) -> None:
        for name, value in (("start", self.start), ("end", self.end), ("trailer", self.trailer)):
            if value is None:
                continue
            if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 255:
                raise ValueError(f"frame {name} must be a byte value in 0..255, got {value!r}")
        if self.start == self.end:
            raise ValueError("frame start and end delimiters must differ")

    def frame(self, payload: str | bytes, encoding: str = "utf-8") -> bytes:
        """Wrap a message: ``start payload end [trailer]``."""
        body = payload.encode(encoding) if isinstance(payload, str) else bytes(payload)
        tail = [self.end] if self.trailer is None else [self.end, self.trailer]
        return bytes([self.start]) + body + bytes(tail)

    def decoder(self, max_frame_bytes: int | None = None) -> FrameDecoder:
        """A fresh stateful reassembler for this scheme."""
        return FrameDecoder(self, max_frame_bytes=max_frame_bytes)


class FrameDecoder:
    """Stateful frame reassembler for a :class:`FrameCodec`.

    Feed it whatever bytes arrive; it yields complete message payloads (delimiters stripped) as they
    complete. Bytes outside a frame — a stray trailer after the end delimiter, keep-alives, or junk
    before the next start byte — are discarded, matching tolerant real-world receivers.
    """

    #: Exception type raised on an over-cap frame. A subclass (e.g. MLLP's historical
    #: ``MLLPFrameError``) can override this so callers' existing ``except`` clauses keep matching.
    error_class: type[FrameError] = FrameError

    def __init__(self, codec: FrameCodec, max_frame_bytes: int | None = None) -> None:
        self._codec = codec
        self._buf = bytearray()
        self._in_block = False
        self.max_frame_bytes = max_frame_bytes

    @property
    def in_frame(self) -> bool:
        """``True`` while a frame is open (start byte seen, end byte not yet) — i.e. partial-frame
        bytes are buffered. Lets a request/response caller that expects exactly one reply detect a
        peer that packed extra frame bytes after it (the ADR 0067 reuse desync guard)."""
        return self._in_block

    def feed(self, data: bytes) -> Iterator[bytes]:
        start, end = self._codec.start, self._codec.end
        for byte in data:
            if not self._in_block:
                if byte == start:
                    self._in_block = True
                    self._buf.clear()
                # else: discard inter-frame noise (trailer after end, keep-alives, etc.)
                continue
            if byte == end:
                # End of block. Any trailer that follows is left to be discarded as inter-frame
                # noise, so a missing/extra trailer is tolerated.
                self._in_block = False
                yield bytes(self._buf)
                self._buf.clear()
            else:
                if self.max_frame_bytes is not None and len(self._buf) >= self.max_frame_bytes:
                    # Oversized open frame: a peer that never sends the end delimiter would grow the
                    # buffer without bound. Reset state and signal the caller to drop the connection.
                    self._buf.clear()
                    self._in_block = False
                    raise self.error_class(
                        f"frame exceeded {self.max_frame_bytes} bytes before the end delimiter"
                    )
                self._buf.append(byte)


#: MLLP preset: VT start, FS end, CR trailer (``0x0B``/``0x1C``/``0x0D``).
MLLP_CODEC = FrameCodec(start=0x0B, end=0x1C, trailer=0x0D)
#: STX/ETX preset: ``0x02``/``0x03``, no trailer — the most common raw-X12-over-TCP framing.
STX_ETX_CODEC = FrameCodec(start=0x02, end=0x03, trailer=None)

#: Named framing presets selectable by string (e.g. ``Tcp(framing="stx_etx")``). ``vt_fs`` aliases
#: ``mllp`` (they are the same bytes), since some estates name the same scheme either way.
PRESETS: dict[str, FrameCodec] = {
    "mllp": MLLP_CODEC,
    "vt_fs": MLLP_CODEC,
    "stx_etx": STX_ETX_CODEC,
}


def codec_for(
    framing: str | None,
    *,
    start: int | None = None,
    end: int | None = None,
    trailer: int | None = None,
) -> FrameCodec:
    """Resolve a :class:`FrameCodec` from a config surface (a preset name OR explicit byte ints).

    Either pass ``framing`` (a key in :data:`PRESETS`) **or** explicit ``start``/``end`` (with an
    optional ``trailer``) — not both. A bad preset name or out-of-range/contradictory bytes raise
    ``ValueError`` (surfaced loud at connector construction, not deep in a read loop)."""
    explicit = start is not None or end is not None or trailer is not None
    if framing is not None:
        if explicit:
            raise ValueError(
                "specify either a framing preset OR explicit start/end/trailer bytes, not both"
            )
        try:
            return PRESETS[framing.lower()]
        except KeyError:
            raise ValueError(
                f"unknown framing preset {framing!r}; expected one of {', '.join(sorted(PRESETS))}"
            ) from None
    if start is None or end is None:
        raise ValueError(
            "framing requires a preset name or both start and end delimiter bytes (start/end)"
        )
    return FrameCodec(start=start, end=end, trailer=trailer)
