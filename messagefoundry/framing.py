# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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

**A stdlib-only leaf, outside** ``transports/`` **on purpose (BACKLOG #1697).** Importing anything
under ``messagefoundry.transports`` runs that package's ``__init__``, which registers every
connector. A client such as the test harness needs the codec and none of the connectors, so the
codec lives here and :mod:`messagefoundry.transports.framing` re-exports it for engine callers. Keep
this module free of engine imports: :mod:`messagefoundry.mllpcodec` builds on it for the same reason.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

__all__ = [
    "FrameError",
    "FrameByteFault",
    "FramePayloadError",
    "FrameEncodeError",
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
class FrameByteFault:
    """Where a payload holds its codec's own ``start`` or ``end`` byte (ADR 0205 rule 1).

    Carries the byte and its position, never the content, so its text is safe to log or show.
    """

    role: str  # "start" or "end"
    byte: int
    position: int

    def describe(self, transport: str) -> str:
        """The refusal text: one wording for the engine's delivery refusal and the harness's."""
        return (
            f"{transport}: payload holds the frame {self.role} byte 0x{self.byte:02X} at byte "
            f"{self.position}; it would not arrive as one message, so it is not sent"
        )


class FramePayloadError(ValueError):
    """Raised by :meth:`FrameCodec.frame_checked` for a payload that would not arrive as one frame.

    Not a :class:`FrameError`: that one means a peer's frame went over its cap, and a caller that
    drops the connection on it must not drop one for a payload this side refused to send.
    """

    def __init__(self, fault: FrameByteFault, transport: str) -> None:
        super().__init__(fault.describe(transport))
        self.fault = fault
        self.transport = transport

    def __reduce__(self) -> tuple[type[FramePayloadError], tuple[FrameByteFault, str]]:
        # The constructor takes (fault, transport), not the message, so pickle and copy need this.
        return (type(self), (self.fault, self.transport))


class FrameEncodeError(ValueError):
    """Raised by :meth:`FrameCodec.frame_checked` and :meth:`FrameCodec.frame_neutralised` for a
    payload the charset cannot hold. Its text names the position only: a bare
    :class:`UnicodeEncodeError` quotes the character and carries the whole payload."""


def _body(payload: str | bytes, encoding: str) -> bytes:
    return payload.encode(encoding) if isinstance(payload, str) else bytes(payload)


def _encoded(payload: str | bytes, encoding: str, transport: str) -> bytes:
    # The raise sits OUTSIDE the except on purpose, as in transports.base.encode_wire_body: a
    # UnicodeEncodeError carries the whole payload as ``.object``, and ``raise ... from None`` still
    # leaves it reachable through ``__context__``. Only the offset leaves the handler.
    position: int
    try:
        return _body(payload, encoding)
    except UnicodeEncodeError as exc:
        position = exc.start
    raise FrameEncodeError(
        f"{transport}: payload cannot be encoded as {encoding} at character {position}; "
        "it is not sent"
    )


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
        body = _body(payload, encoding)
        tail = [self.end] if self.trailer is None else [self.end, self.trailer]
        return bytes([self.start]) + body + bytes(tail)

    # The ONE definition of "a payload that would break framing" (ADR 0205 rule 1). The engine's
    # delivery and reply framers (messagefoundry/transports/framing.py) and the test harness's
    # senders and ACK writers all judge a payload here. A decoder ends a frame at the end byte
    # alone, whatever follows it, so the end byte is refused on its own and not only as end+trailer;
    # the trailer is not a frame byte to a decoder (MLLP's is CR, the segment terminator), so it is
    # not checked. `frame` above stays unchecked, because the fuzzer and the hostile scenarios frame
    # hostile bytes on purpose.

    def find_frame_byte(self, body: bytes) -> FrameByteFault | None:
        """The first of this codec's start or end byte in ``body``, or None when it holds neither.

        The start byte is looked for first, then the end byte, each at its first position. The check
        is on bytes, because a receiver's decoder scans bytes."""
        for role, byte in (("start", self.start), ("end", self.end)):
            position = body.find(byte)
            if position >= 0:
                return FrameByteFault(role, byte, position)
        return None

    def neutralise(self, body: bytes) -> bytes:
        """``body`` with each of this codec's start and end bytes replaced by a space.

        For a REPLY, which must still go as exactly one frame: an acknowledgement echoes header
        values from the inbound message, and an inbound frame may carry a start byte as data. A
        space is what the ACK builder already puts in place of an echoed CR or LF. A clean ``body``
        comes back as is, uncopied; compare with ``!=`` to learn whether anything was replaced."""
        if self.start not in body and self.end not in body:
            return body
        return body.replace(bytes([self.start]), b" ").replace(bytes([self.end]), b" ")

    def frame_checked(
        self, payload: str | bytes, encoding: str = "utf-8", *, transport: str = "frame"
    ) -> bytes:
        """:meth:`frame`, refusing a payload whose encoded bytes hold the start or end byte.

        Raises :class:`FramePayloadError`, whose text names the byte and its position and never the
        content, or :class:`FrameEncodeError` for a payload the charset cannot hold. Nothing is
        stripped or escaped: no framing here has an escape mechanism."""
        body = _encoded(payload, encoding, transport)
        fault = self.find_frame_byte(body)
        if fault is not None:
            raise FramePayloadError(fault, transport)
        return self.frame(body)

    def frame_neutralised(self, payload: str | bytes, encoding: str = "utf-8") -> bytes:
        """:meth:`frame` after :meth:`neutralise`: one frame for a reply, for any codec whose start
        and end bytes are not the space. Raises :class:`FrameEncodeError` as :meth:`frame_checked`."""
        return self.frame(self.neutralise(_encoded(payload, encoding, "reply")))

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
        #: True after a feed whose last byte closed a frame, when the codec has a trailer: the
        #: trailer may still arrive, alone, in the next read.
        self._owes_trailer = False
        #: Whether the most recent :meth:`feed` held nothing but the trailer the frame before it
        #: still owed. Such a read finishes that frame rather than starting anything, which is how
        #: a listener's frame deadline tells it from inter-frame noise (vault BACKLOG #2847).
        self.trailer_only = False

    @property
    def in_frame(self) -> bool:
        """``True`` while a frame is open (start byte seen, end byte not yet) — i.e. partial-frame
        bytes are buffered. Lets a request/response caller that expects exactly one reply detect a
        peer that packed extra frame bytes after it (the ADR 0067 reuse desync guard)."""
        return self._in_block

    def feed(self, data: bytes) -> Iterator[bytes]:
        """Yield each payload completed by ``data``, carrying any partial frame to the next call.

        Delimiters are located with :meth:`bytes.find` and payloads copied a slice at a time, so a
        read costs two C-level scans per frame rather than one Python loop iteration per byte.
        Still a lazy generator: a listener that awaits between frames sees each payload as its end
        delimiter is reached, and an over-cap frame later in the same read cannot retract one
        already yielded.
        """
        start, end, trailer = self._codec.start, self._codec.end, self._codec.trailer
        cap = self.max_frame_bytes
        view = memoryview(data)
        size = len(data)
        self.trailer_only = self._owes_trailer and size == 1 and data[0] == trailer
        self._owes_trailer = False
        pos = 0
        while True:
            if not self._in_block:
                opened = data.find(start, pos)
                if opened < 0:
                    return  # nothing opens a frame in the rest: inter-frame noise, discarded
                self._in_block = True
                self._buf.clear()
                pos = opened + 1
            closed = data.find(end, pos)
            # Charge the cap against what this frame would hold, so an end delimiter sitting past
            # the cap cannot rescue an over-cap frame. The buffer may reach exactly max_frame_bytes;
            # one byte beyond it raises, the boundary the per-byte scan drew.
            pending = (size if closed < 0 else closed) - pos
            if cap is not None and len(self._buf) + pending > cap:
                # Oversized open frame: a peer that never sends the end delimiter would grow the
                # buffer without bound. Reset state and signal the caller to drop the connection.
                self._buf.clear()
                self._in_block = False
                raise self.error_class(f"frame exceeded {cap} bytes before the end delimiter")
            if closed < 0:
                self._buf += view[pos:]  # frame still open — resume on the next read
                return
            if self._buf:
                self._buf += view[pos:closed]
                payload = bytes(self._buf)
                self._buf.clear()
            else:
                payload = bytes(view[pos:closed])  # whole frame in this read: no staging copy
            # End of block. Any trailer that follows is left to be discarded as inter-frame
            # noise, so a missing/extra trailer is tolerated.
            self._in_block = False
            pos = closed + 1
            self._owes_trailer = pos == size and trailer is not None
            yield payload


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
