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
from messagefoundry.parsing.split import _sends_more_than_one_message
from messagefoundry.transports.base import NegativeAckError, encode_wire_body

__all__ = [
    "MULTIPLE_MESSAGES_CODE",
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
    "frame_for_delivery",
    "frame_reply",
]

logger = logging.getLogger(__name__)

#: The :class:`NegativeAckError` code of an MLLP or TCP delivery refused for holding more than one
#: ``MSH`` segment (ADR 0209).
MULTIPLE_MESSAGES_CODE = "multiple-messages"

#: The listeners whose reply-charset fallback has been logged. One line per connection, not per
#: reply: an unusable name fails every message alike, and each one already has its ERROR row.
#: Bounded by the configured inbounds, since the key is a connection name.
_reply_fallback_logged: set[str] = set()


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
        raise NegativeAckError(fault.describe(transport), code="framing", permanent=True)
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

    The one rule for the name, read by the MLLP and TCP listeners for their replies, by the sources
    that encode or decode with the setting themselves (at least the file, remote-file, timer, X12
    and database sources), and by :func:`~messagefoundry.pipeline.ingress_guards.ingress_encoding`
    for the decode (BACKLOG #2431).
    An explicit ``None`` or empty value means "not declared", so it falls back as an absent key does.
    Config load refuses an inbound ``env()`` reference, any other non-``str`` value and any name
    naming no text codec (``Registry.encoding_problems``, BACKLOG #2431), so at run time this sees a
    ``str`` or ``None``. The ``str()`` stays as a
    backstop: a value that got past load anyway fails as a ``LookupError`` the decode refuses and
    :func:`frame_reply` falls back from, never as a ``TypeError`` out of ``encode`` or ``decode``."""
    return str(declared) if declared else "utf-8"


def frame_reply(codec: FrameCodec, reply: str, encoding: str, *, connection: str = "") -> bytes:
    """Frame a listener's reply, with each of the codec's start and end bytes replaced by a space.

    A listener replies AFTER it has committed the message, so a raise here would leave the sender
    with no reply at all. The reply is an engine-built acknowledgement that echoes header values
    from the inbound message, and an inbound body may carry a start byte (an MLLP frame keeps one
    as data). So the reply is neutralised rather than refused: the sender still gets exactly one
    frame, and an echoed control id that held a frame byte simply stops matching. A space is what
    the ACK builder already puts in place of an echoed CR or LF. The replacement is on bytes, for the
    reason :func:`frame_for_delivery` checks bytes.

    For the same reason a reply whose charset NAME is unusable is sent in ``utf-8`` instead: a name
    that names no text codec, or one that refuses every conversion, would otherwise leave the ``AE``
    the runner built for exactly that misconfiguration unsent (BACKLOG #2431). A usable charset that
    cannot hold one reply's characters still raises, which the listener's last-resort arm owns.
    Usable is decided by probing the NAME, as ``decode_body`` decides it: a usable codec such as
    ``idna`` can raise a bare ``UnicodeError`` for one reply, which still raises here.
    ``connection`` names the listener in the warning the fallback logs, once per connection. The
    charset setting itself is not logged, since it is configuration that may hold anything."""
    try:
        body = reply.encode(encoding)
    except UnicodeEncodeError:
        raise
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
    if codec.start in body or codec.end in body:
        logger.warning(
            "reply held a frame start or end byte; each was replaced by a space before framing"
        )
    # The replacement is the leaf's rule, shared with the test harness's ACK writers.
    return codec.frame(codec.neutralise(body))
