# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""MLLP framing, the HL7 ACK builder and :class:`AckMode`: the client-importable half of MLLP.

MLLP wraps each message in a *block*::

    <0x0B> message-bytes <0x1C><0x0D>
     SB                   EB    CR

:class:`MLLPDecoder` is a stateful, byte-accurate reassembler: a real peer may split a message
across reads or pack several into one.

ACKs are built from the inbound MSH (echoing its encoding characters, swapping
sender/receiver, copying the original control id into MSA-2), except where those encoding
characters collide with the ACK's own text (BACKLOG #2875; ``_ack_echo``). ``ack_mode`` selects the
MSA-1 code family: ``original`` → AA/AE/AR, ``enhanced`` → CA/CE/CR.

**Why this module exists (BACKLOG #1697).** A client may not import the engine's runtime packages
(CLAUDE.md section 4; the enforced form is the client walk in ``tests/test_dependency_boundaries.py``,
which forbids ``config``, ``pipeline``, ``store`` and ``transports``). The test harness, the load
tools and ``samples/send_mllp.py`` all
need to frame, decode and acknowledge MLLP, and the only home these had was
:mod:`messagefoundry.transports.mllp`, whose import registers every connector and loads the
configuration layer. So they live here, and ``transports.mllp`` and ``config.models`` re-export them.

**Keep this a leaf.** It imports the stdlib, :mod:`messagefoundry.framing`,
:mod:`messagefoundry.timezone` and, inside :func:`build_ack` only, ``parsing.peek``. It must import
nothing from ``transports/``, ``config/`` or the package root: ``config.models`` imports
:class:`AckMode` from here, so any of those would be a cycle as well as a broken boundary.

That is a promise about THIS module's imports, not about everything a call reaches. The first
:func:`build_ack` call loads ``parsing``. Since BACKLOG #1596 that reaches no ``config`` module
either, and ``tests/test_dependency_boundaries.py`` pins both halves.
"""

from __future__ import annotations

import logging
import string
from enum import Enum
from typing import TYPE_CHECKING

from messagefoundry.framing import (
    MLLP_CODEC,
    FrameDecoder,
    FrameEncodeError,
    FrameError,
    FramePayloadError,
)
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
    "FramePayloadError",
    "FrameEncodeError",
    "frame",
    "frame_checked",
    "frame_neutralised",
    "MLLPDecoder",
    "build_ack",
]

logger = logging.getLogger(__name__)

# MLLP framing is the VT/FS+CR preset of the shared, configurable codec (messagefoundry.framing);
# these names + frame()/MLLPDecoder are the MLLP-specific surface.
SB = 0x0B  # start block  (VT)
EB = 0x1C  # end block    (FS)
CR = 0x0D  # carriage return

#: The default MLLP frame cap (a DoS guard). Overridable per connection via MLLP() settings; see
#: docs/CONNECTIONS.md. None/0 in settings, in any spelling, disables the cap explicitly.
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


def frame_checked(payload: str | bytes, encoding: str = "utf-8") -> bytes:
    """:func:`frame`, refusing a payload that holds an MLLP frame byte, by the rule the engine's own
    MLLP delivery refuses by (ADR 0205 rule 1), which is stated once, at
    :meth:`~messagefoundry.framing.FrameCodec.find_frame_byte`.

    Raises :class:`~messagefoundry.framing.FramePayloadError`, or
    :class:`~messagefoundry.framing.FrameEncodeError` for a payload ``encoding`` cannot hold."""
    return MLLP_CODEC.frame_checked(payload, encoding, transport="MLLP")


def frame_neutralised(payload: str | bytes, encoding: str = "utf-8") -> bytes:
    """:func:`frame` with each MLLP frame byte in the payload replaced by a space: always one frame.

    For an acknowledgement, which echoes values from an inbound message that may hold a start byte
    as data. The engine's listeners reply by the same rule
    (:meth:`~messagefoundry.framing.FrameCodec.neutralise`)."""
    return MLLP_CODEC.frame_neutralised(payload, encoding)


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


def _roles(field_sep: str, enc: str) -> dict[str, str]:
    """Each delimiter character to its role, in MSH-2 order, a short MSH-2 filled from the defaults
    as the parser fills it. Where two roles share a character the first wins; one with no role is
    data."""
    roles: dict[str, str] = {}
    enc = enc[:4] + _DEFAULT_ENC[len(enc[:4]) :]
    for char, role in zip(field_sep + enc, "FSRET", strict=True):
        roles.setdefault(char, role)
    return roles


_DEFAULT_ROLES = _roles(_DEFAULT_FIELD_SEP, _DEFAULT_ENC)

_CODES = {
    AckMode.ORIGINAL: {"AA": "AA", "AE": "AE", "AR": "AR"},
    AckMode.ENHANCED: {"AA": "CA", "AE": "CE", "AR": "CR"},
}

#: The characters of the ACK's fixed text: the segment ids, ``ACK``, ``P``, every MSA-1 code, the
#: letters of the ``\E\`` and ``\F\`` escapes :func:`_escape_ack_text` writes, the default MSH-7
#: (digits and a ``+``/``-`` offset) and the default version ``2.5.1``. An inbound delimiter from
#: this set would split that text when the ACK is read back, so the ACK is built under the defaults
#: instead (BACKLOG #2875). Not covered: a caller's own ``timestamp`` or ``control_id``, and the
#: rest of MSA-3's free text, of which only the escape character and field separator are escaped.
_ACK_LITERAL_CHARS = frozenset(
    "MSH"
    + "MSA"
    + "ACK"
    + "P"
    + "EF"
    + "".join(_CODES[AckMode.ENHANCED].values())
    + "".join(_CODES[AckMode.ORIGINAL].values())
    + string.digits
    + "+-."
)


def _ack_echo(peek: Peek | None) -> tuple[str, str, str, str, str, str, str, str]:
    """The inbound header values an ACK echoes, or their defaults when there is no ``peek``.

    Returns ``(field_sep, enc, sending_app, sending_fac, receiving_app, receiving_fac, version,
    control_id)``. Every value is echoed from the (untrusted) inbound message, so CR/LF is stripped to
    prevent segment injection into the ACK; MSA-3 free text is escaped separately (HL7-3).

    The inbound's MSH-1 and MSH-2 are echoed unless one of them holds a character of the ACK's
    fixed text (:data:`_ACK_LITERAL_CHARS`), or two delimiters share a character. Then the defaults
    ``|^~\\&`` are returned instead, so the ACK reads back as an ACK (BACKLOG #2875). An echoed
    value is then kept only where it holds neither set's escape character and each default delimiter
    in it has the same role in the inbound (``C^1`` under MSH-2 ``^AB``); any other is blanked.
    Blanked, not escaped: the value is raw text split under the inbound's delimiters, so escaping it
    would flatten its structure and re-escape its own escapes (``\\F\\`` names the field separator of
    whichever set reads it), and an escaped control id would no longer match the one the store
    recorded. Under the inbound's own delimiters the values need neither, because they were split
    under them.
    """
    if peek is None:
        return _DEFAULT_FIELD_SEP, _DEFAULT_ENC, "", "", "", "", "2.5.1", ""
    field_sep = peek.field("MSH-1") or _DEFAULT_FIELD_SEP
    enc = peek.field("MSH-2") or _DEFAULT_ENC
    # The characters an echoed value may not hold; none unless the ACK falls back to the defaults.
    unsafe: frozenset[str] = frozenset()
    roles = _roles(field_sep, enc)
    # Fewer than five roles means two share a character, the parser's default-filled slots included.
    if len(roles) < 5 or not _ACK_LITERAL_CHARS.isdisjoint(field_sep + enc):
        unsafe = frozenset(c for c, role in _DEFAULT_ROLES.items() if roles.get(c) != role)
        unsafe |= {_DEFAULT_ENC[2], enc[2:3] or _DEFAULT_ENC[2]}
        field_sep, enc = _DEFAULT_FIELD_SEP, _DEFAULT_ENC

    def echo(value: str | None, default: str = "") -> str:
        value = _no_seg_sep(value or "")
        return (value if unsafe.isdisjoint(value) else "") or default

    return (
        field_sep,
        enc,
        echo(peek.sending_app),
        echo(peek.sending_facility),
        echo(peek.receiving_app),
        echo(peek.receiving_facility),
        echo(peek.version, "2.5.1"),
        echo(peek.control_id),
    )


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

    The ACK echoes the inbound's MSH-1 and MSH-2, except where one of them holds a character of the
    ACK's fixed text; then the ACK, and the NAK this also builds, goes out under ``|^~\\&``
    (BACKLOG #2875; :func:`_ack_echo` holds the rule). MSA-3's escape character and field separator
    are escaped under whichever set is used.
    """
    # Imported here, not at module top, so a framing-only client never loads the parsing library.
    # It was also a cycle once: `parsing` reached `config.models`, which imports AckMode from here.
    # BACKLOG #1596 removed that edge; the first reason still holds.
    from messagefoundry.parsing.peek import PEEK_READ_FAULTS, HL7PeekError, Peek

    if code not in _CODES[AckMode.ORIGINAL]:
        raise ValueError(f"unknown ack code {code!r} (expected one of AA/AE/AR)")
    timestamp = timestamp or hl7_now(with_offset=True)
    msa1 = _CODES[ack_mode if ack_mode is not AckMode.NONE else AckMode.ORIGINAL][code]

    try:
        peek = inbound if isinstance(inbound, Peek) else Peek.parse(inbound)
    except HL7PeekError:
        peek = None

    try:
        echo = _ack_echo(peek)
    except PEEK_READ_FAULTS as exc:
        # BACKLOG #1594: this function builds the NAK for a message that just failed, so it must
        # never raise on one Peek.parse accepted. A faulting read degrades to the no-peek defaults;
        # the ACK then carries no echoed header values, which is what an unparseable inbound gets.
        logger.warning(
            "ACK header echo failed (%s); building the ACK without it", type(exc).__name__
        )
        echo = _ack_echo(None)
    (
        field_sep,
        enc,
        sending_app,
        sending_fac,
        receiving_app,
        receiving_fac,
        version,
        original_control,
    ) = echo
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
