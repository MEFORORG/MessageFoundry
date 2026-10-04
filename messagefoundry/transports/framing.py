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
from messagefoundry.transports.base import NegativeAckError, encode_wire_body

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
    "check_frame_bytes",
    "codec_for",
    "frame_for_delivery",
    "frame_reply",
]

logger = logging.getLogger(__name__)


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
    never discards a healthy persistent one."""
    return codec.frame(check_frame_bytes(codec, payload, encoding, transport=transport))


def check_frame_bytes(codec: FrameCodec, payload: str, encoding: str, *, transport: str) -> bytes:
    """Rule 1's check alone: encode ``payload`` and refuse it as :func:`frame_for_delivery` does,
    returning the encoded body unframed. The delivery stage calls it, through a destination's
    ``check_frame``, where no single-payload send runs: on each member of an MLLP batch, and on a
    shadow (simulate) outbound, so both record the disposition a live send would."""
    body = encode_wire_body(payload, encoding, transport=transport)
    # The judgement and its wording are the leaf's (FrameCodec.find_frame_byte), shared with the test
    # harness; what is engine-only is the permanent delivery failure it becomes here.
    fault = codec.find_frame_byte(body)
    if fault is not None:
        raise NegativeAckError(fault.describe(transport), code="framing", permanent=True)
    return body


def frame_reply(codec: FrameCodec, reply: str, encoding: str) -> bytes:
    """Frame a listener's reply, with each of the codec's start and end bytes replaced by a space.

    A listener replies AFTER it has committed the message, so a raise here would leave the sender
    with no reply at all. The reply is an engine-built acknowledgement that echoes header values
    from the inbound message, and an inbound body may carry a start byte (an MLLP frame keeps one
    as data). So the reply is neutralised rather than refused: the sender still gets exactly one
    frame, and an echoed control id that held a frame byte simply stops matching. A space is what
    the ACK builder already puts in place of an echoed CR or LF. The replacement is on bytes, for the
    reason :func:`frame_for_delivery` checks bytes."""
    body = reply.encode(encoding)
    if codec.start in body or codec.end in body:
        logger.warning(
            "reply held a frame start or end byte; each was replaced by a space before framing"
        )
    # The replacement is the leaf's rule, shared with the test harness's ACK writers.
    return codec.frame(codec.neutralise(body))
