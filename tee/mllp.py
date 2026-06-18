# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Minimal, self-contained MLLP codec for the tee relay — **vendored, not imported from the engine**.

The relay is a standalone application with no ``messagefoundry`` dependency, so the ~100 lines of MLLP
framing + a best-effort HL7 ACK builder it needs are duplicated here deliberately (a small,
information-hiding trade-off for dependency-free standalone-ness). It is stdlib-only.

Scope: enough HL7 awareness to (1) frame/deframe MLLP, (2) build a syntactically-valid ``AA``
acknowledgement that echoes the inbound control id and swaps sender/receiver, and (3) read an MSA-1
code + MSA-3 text out of a downstream's ACK. The relay forwards message **payloads byte-for-byte** and
never re-parses or mutates them — only the ACK path looks inside a message.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Iterator

__all__ = [
    "SB",
    "EB",
    "CR",
    "FrameError",
    "FrameDecoder",
    "frame",
    "build_ack",
    "parse_ack",
    "peek_fields",
]

# MLLP framing bytes: VT start-block, FS end-block, CR trailer (the standard 0x0B / 0x1C / 0x0D).
SB = 0x0B
EB = 0x1C
CR = 0x0D

# Default MSH-1 field separator / MSH-2 encoding characters, used when the inbound can't be parsed.
_DEFAULT_FIELD_SEP = "|"
_DEFAULT_ENC = "^~\\&"

# HL7 segments are CR-delimited, but tolerant peers emit LF/CRLF too — split on any run of either.
_SEG_SPLIT = re.compile(r"[\r\n]+")


class FrameError(ValueError):
    """Raised when a frame exceeds its byte cap before the end delimiter (drop the connection)."""


class FrameDecoder:
    """Stateful MLLP frame reassembler.

    Feed it whatever bytes arrive; it yields complete message payloads (framing stripped) as they
    complete. Bytes outside a frame — a stray CR after EB, keep-alives, junk before the next SB — are
    discarded, matching tolerant real-world receivers. A frame over ``max_frame_bytes`` raises
    :class:`FrameError` so the caller drops the connection rather than buffer unbounded input.
    """

    def __init__(self, max_frame_bytes: int | None = None) -> None:
        self._buf = bytearray()
        self._in_block = False
        self.max_frame_bytes = max_frame_bytes

    def feed(self, data: bytes) -> Iterator[bytes]:
        for byte in data:
            if not self._in_block:
                if byte == SB:
                    self._in_block = True
                    self._buf.clear()
                # else: discard inter-frame noise (trailer after EB, keep-alives, etc.)
                continue
            if byte == EB:
                self._in_block = False
                yield bytes(self._buf)
                self._buf.clear()
            else:
                if self.max_frame_bytes is not None and len(self._buf) >= self.max_frame_bytes:
                    # A peer that never sends the end delimiter would grow the buffer without bound.
                    self._buf.clear()
                    self._in_block = False
                    raise FrameError(
                        f"frame exceeded {self.max_frame_bytes} bytes before the end delimiter"
                    )
                self._buf.append(byte)


def frame(payload: bytes) -> bytes:
    """Wrap a payload in an MLLP block: ``SB payload EB CR``."""
    return bytes([SB]) + payload + bytes([EB, CR])


def _field(parts: list[str], index: int) -> str:
    """Return the field at ``index`` (0-based on the MSH split) or ``""`` if absent — never raises."""
    return parts[index] if 0 <= index < len(parts) else ""


def _no_seg_sep(value: str) -> str:
    """Strip CR/LF from an echoed value so an attacker-controlled inbound field can't inject a new
    segment into the ACK we send back (HL7 segment-injection defense)."""
    return value.replace("\r", " ").replace("\n", " ")


def _msh_fields(message: bytes) -> tuple[str, list[str]]:
    """Best-effort ``(field_sep, MSH split)`` for ``message``; ``(default, [])`` if it isn't HL7.

    Decoded as latin-1 so it never raises and every byte round-trips exactly (so echoed fields keep
    their original bytes when re-encoded latin-1). The message is *not* otherwise interpreted.
    """
    first = _SEG_SPLIT.split(message.decode("latin-1"), maxsplit=1)[0]
    if not first.startswith("MSH") or len(first) < 4:
        return _DEFAULT_FIELD_SEP, []
    field_sep = first[3]
    return field_sep, first.split(field_sep)


def build_ack(message: bytes, *, code: str = "AA", timestamp: str | None = None) -> bytes:
    """Build an HL7 acknowledgement for ``message`` (default ``AA`` — the relay always accepts).

    Reads the field separator + encoding characters from the inbound MSH (never hardcoded), echoes the
    control id into MSA-2, swaps sender/receiver so the ACK routes back the way it came, and sanitizes
    every echoed field against segment injection. If ``message`` isn't parseable HL7 it still returns a
    generic ``AA`` (the relay always ACKs on receipt). Encoded latin-1 to preserve the inbound's bytes.
    """
    field_sep, parts = _msh_fields(message)
    enc = _field(parts, 1) or _DEFAULT_ENC
    sending_app = _no_seg_sep(_field(parts, 2))
    sending_fac = _no_seg_sep(_field(parts, 3))
    receiving_app = _no_seg_sep(_field(parts, 4))
    receiving_fac = _no_seg_sep(_field(parts, 5))
    control = _no_seg_sep(_field(parts, 9))
    version = _no_seg_sep(_field(parts, 11)) or "2.5.1"
    ts = timestamp or datetime.now().strftime("%Y%m%d%H%M%S")

    msh = field_sep.join(
        [
            "MSH",
            _no_seg_sep(enc),
            receiving_app,
            receiving_fac,
            sending_app,
            sending_fac,
            ts,
            "",
            "ACK",
            control,
            "P",
            version,
        ]
    )
    msa = field_sep.join(["MSA", code, control])
    return (msh + "\r" + msa + "\r").encode("latin-1")


def parse_ack(ack: bytes) -> tuple[str | None, str | None]:
    """Return ``(MSA-1 code, MSA-3 text)`` from a downstream's ACK; ``(None, None)`` if unreadable.

    MSA-1 is the acknowledgement code (AA/AE/AR or CA/CE/CR); MSA-3 is the optional reason text. The
    field separator is read from the ACK's own MSH-1.
    """
    segments = _SEG_SPLIT.split(ack.decode("latin-1"))
    field_sep = _DEFAULT_FIELD_SEP
    for seg in segments:
        if seg.startswith("MSH") and len(seg) > 3:
            field_sep = seg[3]
            break
    for seg in segments:
        if seg.startswith("MSA"):
            parts = seg.split(field_sep)
            return (_field(parts, 1) or None), (_field(parts, 3) or None)
    return None, None


def peek_fields(message: bytes) -> tuple[str | None, str | None]:
    """Best-effort ``(control_id, message_type)`` for the relay log — never raises.

    MSH-10 (control id) and MSH-9 (message type) are message identifiers, not PHI.
    """
    _, parts = _msh_fields(message)
    if not parts:
        return None, None
    return (_field(parts, 9) or None), (_field(parts, 8) or None)
