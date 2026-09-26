# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""MLLP framing, the HL7 ACK builder and :class:`AckMode`: the client-importable half of MLLP.

MLLP wraps each message in a *block*::

    <0x0B> message-bytes <0x1C><0x0D>
     SB                   EB    CR

:class:`MLLPDecoder` is a stateful, byte-accurate reassembler: a real peer may split a message
across reads or pack several into one.

ACKs are built from the inbound MSH (echoing its encoding characters, swapping
sender/receiver, copying the original control id into MSA-2). ``ack_mode`` selects the
MSA-1 code family: ``original`` → AA/AE/AR, ``enhanced`` → CA/CE/CR.

**Why this module exists (BACKLOG #1697).** A client may import ``parsing/`` and nothing else from
the engine (CLAUDE.md section 4). The test harness, the load tools and ``samples/send_mllp.py`` all
need to frame, decode and acknowledge MLLP, and the only home these had was
:mod:`messagefoundry.transports.mllp`, whose import registers every connector and loads the
configuration layer. So they live here, and ``transports.mllp`` and ``config.models`` re-export them.

**Keep this a leaf.** It imports the stdlib, :mod:`messagefoundry.framing`,
:mod:`messagefoundry.timezone` and, inside :func:`build_ack` only, ``parsing.peek``. It must import
nothing from ``transports/``, ``config/`` or the package root: ``config.models`` imports
:class:`AckMode` from here, so any of those would be a cycle as well as a broken boundary.

That is a promise about THIS module's imports, not about everything a call reaches. The first
:func:`build_ack` call loads ``parsing``, and ``parsing``'s package init still reaches three
``config`` modules; that pull-in is BACKLOG #1596's to remove, not this module's.
"""

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING

from messagefoundry.framing import MLLP_CODEC, FrameDecoder, FrameError
from messagefoundry.timezone import hl7_now

if TYPE_CHECKING:
    from messagefoundry.parsing.peek import Peek

__all__ = [
    "SB",
    "EB",
    "CR",
    "DEFAULT_MAX_FRAME_BYTES",
    "AckMode",
    "MLLPFrameError",
    "frame",
    "MLLPDecoder",
    "build_ack",
]

# MLLP framing is the VT/FS+CR preset of the shared, configurable codec (messagefoundry.framing);
# these names + frame()/MLLPDecoder are the MLLP-specific surface.
SB = 0x0B  # start block  (VT)
EB = 0x1C  # end block    (FS)
CR = 0x0D  # carriage return

#: The default MLLP frame cap (a DoS guard). Overridable per connection via MLLP() settings; see
#: docs/CONNECTIONS.md. A falsy value (None/0) in settings disables the cap explicitly.
DEFAULT_MAX_FRAME_BYTES = 16 * 1024 * 1024  # 16 MiB — fits embedded base64 docs, bounds OOM


class AckMode(str, Enum):  # noqa: UP042
    """HL7 acknowledgement mode for MLLP/TCP sources."""

    ORIGINAL = "original"  # MSA generated from the inbound message
    ENHANCED = "enhanced"  # application + commit acks (MSH-15/16)
    NONE = "none"


# MLLP's frame-too-large error is the shared codec error under its historical name (subclassing keeps
# `except MLLPFrameError` working while the codec raises the generic FrameError internally).
class MLLPFrameError(FrameError):
    """Raised when an MLLP frame exceeds its configured byte cap before end-of-block.

    Signals the caller to drop the connection rather than buffer an unbounded frame.
    """


def frame(payload: str | bytes, encoding: str = "utf-8") -> bytes:
    """Wrap a message in an MLLP block: ``SB payload EB CR`` (the VT/FS+CR codec preset)."""
    return MLLP_CODEC.frame(payload, encoding)


class MLLPDecoder(FrameDecoder):
    """Stateful MLLP frame reassembler — the :class:`~messagefoundry.framing.FrameDecoder`
    bound to the MLLP (VT/FS+CR) codec.

    Feed it whatever bytes arrive; it yields complete message payloads (framing bytes
    stripped) as they complete. Bytes outside a frame — including a stray CR after EB or
    junk before the next SB — are discarded, matching tolerant real-world receivers. A frame
    over ``max_frame_bytes`` raises :class:`MLLPFrameError`.
    """

    error_class = MLLPFrameError

    def __init__(self, max_frame_bytes: int | None = None) -> None:
        super().__init__(MLLP_CODEC, max_frame_bytes=max_frame_bytes)


# --- ACK building ------------------------------------------------------------

# MSH-1 default field separator and MSH-2 default encoding characters.
_DEFAULT_FIELD_SEP = "|"
_DEFAULT_ENC = "^~\\&"


def _no_seg_sep(value: str) -> str:
    """Strip CR/LF from an echoed ACK value so an attacker-controlled inbound field can't inject a
    new segment into the ACK we send back (HL7-3)."""
    return value.replace("\r", " ").replace("\n", " ")


def _escape_ack_text(text: str, *, field_sep: str, enc: str) -> str:
    """Sanitize free-text MSA-3: drop CR/LF and escape the escape char + field separator so the
    text can't introduce extra fields/segments (the inbound-derived NACK reason is untrusted)."""
    esc = enc[2] if len(enc) > 2 else "\\"
    text = _no_seg_sep(text)
    # Escape the escape char first (so the substitution below stays reversible), then the field sep.
    return text.replace(esc, f"{esc}E{esc}").replace(field_sep, f"{esc}F{esc}")


_CODES = {
    AckMode.ORIGINAL: {"AA": "AA", "AE": "AE", "AR": "AR"},
    AckMode.ENHANCED: {"AA": "CA", "AE": "CE", "AR": "CR"},
}


def build_ack(
    inbound: str | bytes | Peek,
    *,
    code: str = "AA",
    text: str | None = None,
    ack_mode: AckMode = AckMode.ORIGINAL,
    control_id: str | None = None,
    timestamp: str = "",
) -> str:
    """Build an HL7 acknowledgement for ``inbound``.

    ``code`` is the logical outcome — ``"AA"`` (accept), ``"AE"`` (error) or ``"AR"``
    (reject) — mapped to the MSA-1 value appropriate for ``ack_mode``. ``text`` becomes
    MSA-3 (e.g. a NACK reason). ``control_id`` is the ACK's own MSH-10 (defaults to
    echoing the inbound control id). ``timestamp`` is MSH-7; pass one to pin it (tests),
    otherwise it defaults to the current HL7 DTM so strict senders that reject an empty
    MSH-7 don't NAK-loop and re-send (review low-6).

    The default MSH-7 carries an **explicit numeric UTC offset** (``YYYYMMDDHHMMSS±ZZZZ``, the
    HL7 v2 DTM/TS form). A bare local stamp would be ambiguous across a daylight-saving fall-back —
    the same wall-clock hour occurs twice — so a receiver correlating an acknowledgement against its
    own UTC-stamped record would mis-order events by an hour. An explicit offset pins the instant.
    An operator-supplied ``timestamp`` is used verbatim; the caller owns its form.
    """
    # Imported here, not at module top: `parsing`'s package init reaches `config.models` (BACKLOG
    # #1596), and `config.models` imports AckMode from this module, so a top-level import is a
    # cycle. It also keeps a framing-only client from loading the parsing library at all.
    from messagefoundry.parsing.peek import HL7PeekError, Peek

    if code not in _CODES[AckMode.ORIGINAL]:
        raise ValueError(f"unknown ack code {code!r} (expected AA, AE or AR)")
    timestamp = timestamp or hl7_now(with_offset=True)
    msa1 = _CODES[ack_mode if ack_mode is not AckMode.NONE else AckMode.ORIGINAL][code]

    try:
        peek = inbound if isinstance(inbound, Peek) else Peek.parse(inbound)
    except HL7PeekError:
        peek = None

    field_sep = (peek.field("MSH-1") if peek else None) or _DEFAULT_FIELD_SEP
    enc = (peek.field("MSH-2") if peek else None) or _DEFAULT_ENC
    # Every value below is echoed from the (untrusted) inbound message, so strip CR/LF to prevent
    # segment injection into the ACK; MSA-3 free text is additionally escaped (HL7-3).
    sending_app = _no_seg_sep((peek.sending_app if peek else None) or "")
    sending_fac = _no_seg_sep((peek.sending_facility if peek else None) or "")
    receiving_app = _no_seg_sep((peek.receiving_app if peek else None) or "")
    receiving_fac = _no_seg_sep((peek.receiving_facility if peek else None) or "")
    version = _no_seg_sep((peek.version if peek else None) or "2.5.1")
    original_control = _no_seg_sep((peek.control_id if peek else None) or "")
    ack_control = _no_seg_sep(control_id if control_id is not None else original_control)

    # Swap sender/receiver: the ACK goes back the way it came.
    msh_fields = [
        "MSH",
        _no_seg_sep(enc),
        receiving_app,
        receiving_fac,
        sending_app,
        sending_fac,
        timestamp,
        "",
        "ACK",
        ack_control,
        "P",
        version,
    ]
    msh = field_sep.join(msh_fields)
    msa_fields = ["MSA", msa1, original_control]
    if text:
        msa_fields.append(_escape_ack_text(text, field_sep=field_sep, enc=enc))
    msa = field_sep.join(msa_fields)
    return msh + "\r" + msa + "\r"
