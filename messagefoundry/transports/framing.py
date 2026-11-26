# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Configurable delimiter framing, re-exported from its leaf home :mod:`messagefoundry.framing`.

The codec moved out of ``transports/`` so a client can import it without registering every
connector (BACKLOG #1697). Engine callers keep importing it from here.

The MLLP and TCP destinations and listeners frame through the functions defined here (ADR 0205). :meth:`FrameCodec.frame` stays unchecked, because a client such as the test harness frames
hostile bytes on purpose. What counts as a frame byte, and the refusal's wording, are defined once in
the leaf (:meth:`FrameCodec.find_frame_byte`, :meth:`FrameCodec.neutralise`), which the harness's own
senders and ACK writers use too.
"""

from __future__ import annotations

import logging
import time

from messagefoundry.config.wiring import _is_text_codec
from messagefoundry.framing import (
    MLLP_CODEC,
    PRESETS,
    STX_ETX_CODEC,
    FrameByteFault,
    FrameCodec,
    FrameDecoder,
    FrameEncodeError,
    FrameError,
    FramePayloadError,
    codec_for,
)
from messagefoundry.parsing._builtin_hl7 import HEADER_IDS, _extract_separators
from messagefoundry.parsing.sniff import _LEADING_WS_STR
from messagefoundry.parsing.split import _sends_more_than_one_message
from messagefoundry.parsing.x12.delimiters import (
    _COMPONENT_SEP_OFFSET,
    _REPETITION_MIN_VERSION,
    _REPETITION_SEP_OFFSET,
    _SEGMENT_TERM_OFFSET,
    _VERSION_END,
    _VERSION_START,
    ELEMENT_SEP_OFFSETS,
    ISA_SEGMENT_LEN,
)
from messagefoundry.transports.base import NegativeAckError, encode_wire_body

__all__ = [
    "FRAMING_CODE",
    "MULTIPLE_MESSAGES_CODE",
    "REPLY_REPLACED_EVENT_SECONDS",
    "ReplyReplacements",
    "FrameError",
    "FrameByteFault",
    "FramePayloadError",
    "FrameEncodeError",
    "FrameCodec",
    "FrameDecoder",
    "MLLP_CODEC",
    "STX_ETX_CODEC",
    "PRESETS",
    "check_frame_bytes",
    "codec_for",
    "declared_encoding",
    "encode_reply",
    "encode_reply_reporting",
    "frame_for_delivery",
    "frame_reply",
    "frame_reply_reporting",
]

logger = logging.getLogger(__name__)

#: The :class:`NegativeAckError` code of an MLLP or TCP delivery refused for holding more than one
#: ``MSH`` segment (ADR 0209).
MULTIPLE_MESSAGES_CODE = "multiple-messages"

#: The :class:`NegativeAckError` code of a payload holding its codec's own start or end byte
#: (ADR 0205 rule 1).
FRAMING_CODE = "framing"

#: The listeners whose reply-charset fallback has been logged. One line per connection, not per
#: reply: an unusable name fails every message alike, and each one already has its ERROR row.
#: Bounded by the configured inbounds, since the key is a connection name.
_reply_fallback_logged: set[str] = set()

#: The listeners whose reply-character replacement has been logged, once per connection for the
#: same reason (BACKLOG #5799): a narrow charset meets the same characters on every message. The
#: MLLP, raw-TCP and X12 listeners also send a ``reply_replaced`` connection event, which
#: :class:`ReplyReplacements` throttles; it is stored only when connection events are captured.
_reply_replacement_logged: set[str] = set()

#: The shortest gap between two ``reply_replaced`` events from one listener, the same window as the
#: ``tls_handshake_failed`` throttle.
REPLY_REPLACED_EVENT_SECONDS = 60.0


class ReplyReplacements:
    """One listener's throttle for its ``reply_replaced`` connection events (BACKLOG #5799).

    A narrow charset meets the same characters on every message, so one event per replaced reply
    would grow with message volume and could crowd other kinds out of the runner's bounded event
    queue. The first replaced reply is reported at once; after that, at most one report per
    :data:`REPLY_REPLACED_EVENT_SECONDS`, made by the first replaced reply past the window and
    carrying the count since the last report. Unlike the ``tls_handshake_failed`` throttle there is
    no trailing report: replies counted after the last report are not reported until another reply
    is replaced past the window, and not at all if none is. The reason is a count and fixed text,
    never the charset setting or any part of the reply. Runs on the listener's event loop."""

    def __init__(self) -> None:
        self._unreported = 0
        self._reported_at: float | None = None

    def note(self) -> str | None:
        """Count one replaced reply, and return the reason of the event due now, if one is."""
        self._unreported += 1
        now = time.monotonic()
        if self._reported_at is not None and now - self._reported_at < REPLY_REPLACED_EVENT_SECONDS:
            return None
        count, self._unreported, self._reported_at = self._unreported, 0, now
        return (
            f"{count} reply(ies) since the last report held characters the inbound charset "
            "cannot encode, and each was replaced"
        )


def frame_for_delivery(codec: FrameCodec, payload: str, encoding: str, *, transport: str) -> bytes:
    """Frame one outbound ``payload`` for the wire, or refuse it permanently (ADR 0205 rule 1).

    A payload whose ENCODED bytes hold the codec's own start or end byte would leave as two frames,
    or as one frame with a second start byte inside it. A receiver's decoder works on bytes, so the
    bytes are what is checked, after the encode. Nothing is stripped or escaped: no framing here has
    an escape mechanism, and stripping would change clinical data silently.

    The refusal is :class:`NegativeAckError` with ``permanent=True``, so the delivery worker
    dead-letters the row at once instead of retrying it for the whole budget. Its text names the
    byte and its position, never the content. The encode goes through :func:`encode_wire_body`, so a
    payload the charset cannot hold is the same content-free permanent failure other destinations
    raise. Call this once per send, before any dial, so a refused payload opens no connection and
    never discards a healthy persistent one. :func:`check_frame_bytes` also refuses a payload
    holding more than one message (ADR 0209)."""
    return codec.frame(check_frame_bytes(codec, payload, encoding, transport=transport))


def check_frame_bytes(codec: FrameCodec, payload: str, encoding: str, *, transport: str) -> bytes:
    """The delivery checks without the frame: refuse ``payload`` as :func:`frame_for_delivery`
    does, or return it encoded and unframed. The delivery stage calls it, through a destination's
    ``check_frame``, where no single-payload send runs: on each member of an MLLP batch, and on a
    shadow (simulate) outbound, so both record the disposition a live send would.

    It refuses, in order, at least: a payload holding more than one message
    (:func:`_refuse_more_than_one_message`, ADR 0209), one the charset cannot encode
    (:func:`encode_wire_body`), and ADR 0205 rule 1 on the encoded bytes."""
    _refuse_more_than_one_message(payload, transport)
    body = encode_wire_body(payload, encoding, transport=transport)
    # The judgement and its wording are the leaf's (FrameCodec.find_frame_byte), shared with the test
    # harness; what is engine-only is the permanent delivery failure it becomes here.
    fault = codec.find_frame_byte(body)
    if fault is not None:
        raise NegativeAckError(fault.describe(transport), code=FRAMING_CODE, permanent=True)
    return body


def _refuse_more_than_one_message(payload: str, transport: str) -> None:
    """Refuse an ``MSH``-led ``payload`` that holds a second ``MSH`` line (ADR 0209): one frame is
    one message to the receiver. It sits under :func:`check_frame_bytes`, so it reaches at least a
    live send, a batch member and a shadow outbound. A payload not led
    by ``MSH`` is never read, so a relayed X12 interchange and the ``BHS`` envelope a batching
    outbound sends (ADR 0082) pass. The text names the rule, never the content."""
    if _sends_more_than_one_message(payload):
        raise NegativeAckError(
            f"{transport}: payload holds more than one MSH segment, and one frame carries one "
            "message (ADR 0209)",
            code=MULTIPLE_MESSAGES_CODE,
            permanent=True,
        )


def declared_encoding(declared: object) -> str:
    """The charset name an inbound's ``encoding`` setting declares (default ``utf-8``).

    The one rule for the name, read by the MLLP, TCP and X12 listeners for their replies, by the
    sources that encode or decode with the setting themselves (at least the file, remote-file,
    timer, X12 and database sources), and by :func:`~messagefoundry.pipeline.ingress_guards.ingress_encoding`
    for the decode (BACKLOG #2431).
    An explicit ``None`` or empty value means "not declared", so it falls back as an absent key does.
    Config load refuses an inbound ``env()`` reference, every non-``str`` value but ``None`` and any
    name naming no text codec (``Registry.encoding_problems``, BACKLOG #2431), so at run time this
    sees a ``str`` or ``None``. The ``str()`` stays as a
    backstop: a value that got past load anyway is never a ``TypeError`` out of ``encode`` or
    ``decode``. Its ``str()`` either names a codec (``1252`` reads as ``cp1252``) or fails as a
    ``LookupError`` the decode refuses and :func:`encode_reply` falls back from."""
    return str(declared) if declared else "utf-8"


def frame_reply(codec: FrameCodec, reply: str, encoding: str, *, connection: str = "") -> bytes:
    """Frame a listener's reply, with each of the codec's start and end bytes replaced by a space.

    A listener replies AFTER it has committed the message, so a raise here would leave the sender
    with no reply at all. The reply is an engine-built acknowledgement that echoes header values
    from the inbound message, and an inbound body may carry a start byte (an MLLP frame keeps one
    as data). So the reply is neutralised rather than refused: the sender still gets exactly one
    frame, and an echoed control id that held a frame byte simply stops matching. A space is what
    the ACK builder already puts in place of an echoed CR or LF. The replacement is on bytes, for the
    reason :func:`frame_for_delivery` checks bytes. The reply is encoded by :func:`encode_reply`,
    which says what it does with a charset that cannot hold it. This drops the flag saying whether
    characters were replaced, so a listener calls :func:`frame_reply_reporting` instead and writes
    the ``reply_replaced`` event from it (BACKLOG #5799)."""
    return frame_reply_reporting(codec, reply, encoding, connection=connection)[0]


def frame_reply_reporting(
    codec: FrameCodec, reply: str, encoding: str, *, connection: str = ""
) -> tuple[bytes, bool]:
    """:func:`frame_reply`, and whether characters the charset cannot hold were replaced, so a
    listener can write a ``reply_replaced`` connection event for that reply (BACKLOG #5799)."""
    body, replaced = encode_reply_reporting(reply, encoding, connection=connection)
    if codec.start in body or codec.end in body:
        logger.warning(
            "reply held a frame start or end byte; each was replaced by a space before framing"
        )
    # The replacement is the leaf's rule, shared with the test harness's ACK writers.
    return codec.frame(codec.neutralise(body)), replaced


def encode_reply(reply: str, encoding: str, *, connection: str = "") -> bytes:
    """Encode a listener's post-commit reply in its declared charset. The listeners call
    :func:`encode_reply_reporting`, which does this and also says whether characters were replaced:
    :func:`frame_reply_reporting` for the MLLP and raw-TCP listeners, and the X12 listener directly,
    since it writes its reply unframed (BACKLOG #5958).

    A reply whose charset NAME is unusable is sent in ``utf-8`` instead: a name
    that names no text codec, or one that refuses every conversion, would otherwise leave the ``AE``
    the runner built for exactly that misconfiguration unsent (BACKLOG #2431). A usable charset that
    cannot hold one reply's characters is not that misconfiguration, so the reply is not moved to
    ``utf-8``: it stays in the declared charset, and each character the charset cannot hold becomes
    the codec's replacement character, for the same reason :func:`frame_reply` turns a frame byte
    into a space (BACKLOG #5799). Before, that reply raised to the listener's last-resort arm, which
    closed the connection unanswered, so the sender resent a message already stored. At least a
    codec that cannot replace, such as ``idna``, and an ``MSH``-led reply whose own delimiters
    include the replacement ``?`` still raise (:func:`_encode_replacing` names more), with a fixed
    ``UnicodeError`` that chains nothing, since the strict encode's error holds the whole reply. Usable is decided by
    probing the NAME, as ``decode_body`` decides it: a usable codec can also raise a bare
    ``UnicodeError`` for one reply, which still raises here. ``connection`` names the listener in
    the warning each fallback logs, once per connection for each, since a narrow charset meets the
    same characters message after message. The charset setting and the reply are never logged: the
    setting is configuration that may hold anything, and the reply echoes the message."""
    return encode_reply_reporting(reply, encoding, connection=connection)[0]


def encode_reply_reporting(
    reply: str, encoding: str, *, connection: str = ""
) -> tuple[bytes, bool]:
    """:func:`encode_reply`, and whether characters the charset cannot hold were replaced. The
    warning is logged once per connection; the flag is set on every reply replaced, for the
    listener's ``reply_replaced`` connection event (BACKLOG #5799). A reply sent in ``utf-8``
    because the charset name is unusable is not a replacement, and the flag is False."""
    unencodable = False
    try:
        body = reply.encode(encoding)
    except UnicodeEncodeError:
        # Decided here and encoded below, so nothing raised later chains this error's `object`.
        unencodable = True
    except (LookupError, UnicodeError):
        if _is_text_codec(encoding):
            raise
        if connection not in _reply_fallback_logged:
            _reply_fallback_logged.add(connection)
            logger.warning(
                "inbound %r: the reply charset is unusable, so its replies are encoded in utf-8 "
                "instead (logged once per connection)",
                connection,
            )
        body = reply.encode("utf-8")
    if unencodable:
        return _encode_replacing(reply, encoding, connection), True
    return body, False


def _encode_replacing(reply: str, encoding: str, connection: str) -> bytes:
    """``reply`` in ``encoding`` with each character the charset cannot hold replaced, for
    :func:`encode_reply`. A codec that refuses the ``replace`` handler raises a fixed
    ``UnicodeError``, outside the handler, so neither error's text or ``object`` rides the chain.
    The warning names the connection, never the reply or the setting.

    The ``replace`` handler writes ``?`` on encode. An HL7 reply declares its own delimiters in
    MSH-1 and MSH-2 (or a ``BHS`` or ``FHS`` header's same fields), and an X12 reply in its ``ISA``;
    both standards let a sender pick ``?`` as one, so where it is a delimiter or the segment
    terminator a replaced data character would become structure (ADR 0206). That reply is refused
    with the same fixed error instead. So is one with a delimiter the charset cannot hold: the
    delimiter itself would become ``?`` beside replaced data characters, and both would read as
    one delimiter. :func:`_reply_delimiters` says which headers are read; a reply led by none of
    them declares no delimiters to collide with."""
    delimiters = _reply_delimiters(reply)
    if _REPLACEMENT in delimiters or not all(_encodes(d, encoding) for d in delimiters):
        raise UnicodeError(
            "the reply holds characters its charset cannot encode, and the replacement would "
            "collide with one of its own delimiters"
        )
    # Leading noise the charset cannot hold, such as a BOM, would be replaced too, and a reply led by
    # "?MSH" is no reply any parser reads. Refused like the collisions above. Read only.
    lead = reply[: len(reply) - len(reply.lstrip(_LEADING_WS_STR))]
    if not _encodes(lead, encoding):
        raise UnicodeError(
            "the reply holds characters its charset cannot encode, including in the noise before "
            "its first segment"
        )
    body: bytes | None
    try:
        body = reply.encode(encoding, errors="replace")
    except (LookupError, UnicodeError):
        body = None
    if body is None:
        raise UnicodeError("the reply holds characters its charset can neither encode nor replace")
    if connection not in _reply_replacement_logged:
        _reply_replacement_logged.add(connection)
        logger.warning(
            "inbound %r: a reply held characters its charset cannot encode; each was replaced "
            "before it was sent (logged once per connection)",
            connection,
        )
    return body


#: What Python's ``replace`` error handler writes in place of a character on encode.
_REPLACEMENT = "?"


def _encodes(delimiter: str, encoding: str) -> bool:
    """Whether one delimiter character survives a strict encode, so ``replace`` leaves it alone."""
    try:
        delimiter.encode(encoding)
    except (LookupError, UnicodeError):
        return False
    return True


def _reply_delimiters(reply: str) -> frozenset[str]:
    """The delimiters a ``reply`` declares, plus its segment terminator. Read only: nothing here
    changes the reply.

    Two layouts are read (BACKLOG #5799 item 2: before, only the first line of an ``MSH``-led reply
    was read, so an X12 reply or a batch member declaring ``?`` had ``?`` written into its data).
    An HL7 reply led by one of ``HEADER_IDS`` (``MSH``, ``BHS``, ``FHS``) is read on every segment
    that starts with one of them, each in the MSH-1/MSH-2 layout ``_extract_separators`` reads, so
    a batch member's own ``MSH`` counts as its envelope does. Its segments end at CR when the reply
    holds one, so an LF inside a field is data, and at LF only in a reply with no CR; that
    terminator, and the LF of a CR+LF end, are declared too. An X12 reply led by ``ISA`` is read
    at the ISA's fixed delimiter offsets only when :func:`_isa_is_fixed_width` holds for it. Those
    offsets are read raw, without the distinctness check ``discover_delimiters`` makes and without
    the terminator half of its element-data check, so a fixed-width ISA that read refuses for one
    of those still declares what its offsets hold: at least ISA11 and ISA16 both ``?``, and an
    ISA16 equal to the element separator. ISA11 is declared only from version 00501, as that read
    takes it as a delimiter. An ISA that is not fixed-width declares nothing, as every
    ``ISA``-led reply did before this read: in an unpadded ISA, offsets 82, 104 and 105 can hold
    element data, and reading them would refuse a reply whose data there the charset cannot hold.
    That leaves a residual, as before: an ISA that is not fixed-width is neither refused where
    ``?`` is one of its delimiters, so ``?`` is written into its data, nor where a delimiter is a
    character the charset cannot encode, even where its separators sit at their fixed offsets. At
    least these are not fixed-width: an ISA whose elements are unpadded, one cut short, and one
    whose element separator also appears before ISA16 away from its separator offsets, whether in
    element data (an ISA06 of ``AC*MER``), in ISA11 in any version, or in the ``ISA`` tag itself
    (an element separator of ``I``, ``S`` or ``A``). A reply with any other lead declares nothing
    here.

    Leading whitespace and a BOM are skipped first, as the engine's one definition of tolerated
    leading noise (``sniff._LEADING_WS_STR``) skips them. A header line of ``MSH`` alone has no
    field separator to read and declares nothing, rather than indexing past its end."""
    body = reply.lstrip(_LEADING_WS_STR)
    if body.startswith("ISA"):
        if not _isa_is_fixed_width(body):
            return frozenset()
        isa = {body[i] for i in _ISA_DELIMITER_OFFSETS}
        if body[_VERSION_START:_VERSION_END] >= _REPETITION_MIN_VERSION:
            isa.add(body[_REPETITION_SEP_OFFSET])  # before 00501, ISA11 is data, not a delimiter
        if body[_SEGMENT_TERM_OFFSET : _SEGMENT_TERM_OFFSET + 2] == "\r\n":
            isa.add("\n")  # a CR+LF terminator is two characters, and `?` for either breaks it
        return frozenset(isa)
    if not body.startswith(HEADER_IDS):
        return frozenset()
    terminator = "\r" if "\r" in body else "\n"
    found = {terminator}
    for segment in body.split(terminator):
        if terminator == "\r" and segment.startswith("\n"):
            found.add("\n")  # a CR+LF end: the LF opens the next piece
            segment = segment[1:]
        if segment.startswith(HEADER_IDS) and len(segment) >= 4:
            found.update(_extract_separators(segment))
    return frozenset(found)


#: The ISA's delimiter offsets read in every version, from ``parsing.x12.delimiters``: the element
#: separator (+3), ISA16 (the component separator) and the segment terminator. ISA11, the
#: repetition separator, is read only from 00501, as ``discover_delimiters`` reads it.
_ISA_DELIMITER_OFFSETS = (ELEMENT_SEP_OFFSETS[0], _COMPONENT_SEP_OFFSET, _SEGMENT_TERM_OFFSET)


def _isa_is_fixed_width(body: str) -> bool:
    """Whether the ``ISA`` that opens ``body`` is laid out at its fixed widths: all
    ``ISA_SEGMENT_LEN`` characters are present and every element-separator offset holds the
    character at +3, and no other offset before ISA16 holds it, the ``ISA`` tag and ISA11 included,
    as X12 keeps the element separator out of element data. So ``ISA`` followed by a run of one
    character is not read as one. ISA16's width is not checked: an empty or a longer ISA16 that
    passes puts other characters at offsets 104 and 105, and they are read as delimiters."""
    if len(body) < ISA_SEGMENT_LEN:
        return False
    element = body[ELEMENT_SEP_OFFSETS[0]]
    lined_up = all(body[i] == element for i in ELEMENT_SEP_OFFSETS)
    return lined_up and body.count(element, 0, _COMPONENT_SEP_OFFSET) == len(ELEMENT_SEP_OFFSETS)
