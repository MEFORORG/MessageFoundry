# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Byte-bounded reads of the reply the engine asked for on an egress hop (ASVS 15.2.2).

Every outbound HTTP connector reads the partner's response body back into memory. A bare
``resp.read()`` reads until EOF, so on a first deployment a hostile or malfunctioning partner
would be able to make the engine buffer an arbitrarily large body. That is a loss-of-availability
surface no ingress bound can reach, because the engine opened the connection itself and the reply
is not a received message.

:func:`read_bounded` asks for one byte past the ceiling and refuses at that byte, so the peak
buffer is the ceiling plus one rather than whatever the peer chose to send. The bound is enforced
**on the socket read**, not after the fact, which is the same shape the OIDC relying party already
uses at ``auth/oidc_http.py`` and ``auth/oidc/flow.py``.

**This is egress, not ingress.** The count-and-log invariant (CLAUDE.md section 2) governs
received messages: nothing here can drop one, because nothing here reads one. What these bounds
refuse is a *reply* to a request the engine made.

**No new dead-letter cause.** :class:`ResponseTooLargeError` subclasses
:class:`~messagefoundry.transports.base.DeliveryError`, so an over-cap reply lands on the same
retry-then-dead-letter path an unreadable reply has always taken (a timeout mid-read, a reset
socket). It is deliberately **not** a permanent
:class:`~messagefoundry.transports.base.NegativeAckError`: promoting it would fail a message
straight to the dead-letter queue on a peer-side fault, which is a behaviour change the bound does
not need.
"""

from __future__ import annotations

from typing import Protocol

from messagefoundry.parsing.peek import DEFAULT_MAX_MESSAGE_BYTES
from messagefoundry.transports.base import DeliveryError

__all__ = [
    "DEFAULT_MAX_RESPONSE_BYTES",
    "MAX_TOKEN_RESPONSE_BYTES",
    "ResponseTooLargeError",
    "read_bounded",
    "read_bounded_text",
]

#: Ceiling on any response body the engine reads back off an egress hop.
#:
#: **This is not a new number.** It is :data:`messagefoundry.parsing.peek.DEFAULT_MAX_MESSAGE_BYTES`
#: (16 MiB), the engine's existing one-message ceiling: the MLLP frame cap, the pre-parse segment
#: cap, the ``max_file_bytes`` default on the file and remote-file connectors, and the DICOM inflate
#: guard all resolve to the same 16 MiB. The argument for reusing it is that the largest body the
#: engine is willing to accept **as a message** is a defensible ceiling on the largest body it is
#: willing to buffer from a *reply* to one.
#:
#: It is generous for every real reply this engine reads. A FHIR write returns the created resource
#: or an ``OperationOutcome``; a STOW-RS reply is a small result document; a SOAP reply is one
#: envelope; a ``fhir_lookup`` search returns one page of a ``Bundle``, bounded by the server's own
#: page size. All are orders of magnitude under 16 MiB, so no honest clinical reply is refused by
#: this number and a hostile or broken peer cannot push the engine past it.
DEFAULT_MAX_RESPONSE_BYTES = DEFAULT_MAX_MESSAGE_BYTES

#: Ceiling on an OAuth2 client-credentials or SMART Backend Services token-endpoint response.
#:
#: A token response is a small JSON object: a bearer, a TTL, and a scope list. 256 KiB is far past
#: any of them and is the same number, chosen for the same reason, that the engine's own OIDC
#: relying party applies to the same shape of response at
#: ``messagefoundry/auth/oidc/flow.py`` (``_MAX_TOKEN_RESPONSE_BYTES``). The two constants are kept
#: separate on purpose, because ``transports/`` must not grow an import edge into ``auth/``;
#: ``tests/test_bounded_egress_reads.py`` pins them equal so they cannot drift apart unnoticed.
MAX_TOKEN_RESPONSE_BYTES = 256 * 1024


class ResponseTooLargeError(DeliveryError):
    """An egress reply exceeded its byte bound, so the engine refused to buffer the rest.

    A :class:`~messagefoundry.transports.base.DeliveryError`, therefore transient: the delivery
    worker retries it under the connection's own retry policy and dead-letters it the same way it
    dead-letters any other reply the engine could not read.
    """


class _SupportsRead(Protocol):
    """Anything with a byte-count-limited ``read``: an ``http.client.HTTPResponse``, the
    ``urllib.error.HTTPError`` that wraps one on a non-2xx, or a binary file handle."""

    def read(self, amt: int, /) -> bytes: ...


def read_bounded(
    reader: _SupportsRead,
    *,
    limit: int = DEFAULT_MAX_RESPONSE_BYTES,
    connector: str,
) -> bytes:
    """Return at most ``limit`` bytes from ``reader``, or raise :class:`ResponseTooLargeError`.

    Asks the socket for ``limit + 1`` bytes. Getting that many proves the body is over the bound
    without ever buffering the whole of it, so the refusal costs one byte of headroom rather than
    the peer's whole payload. Nothing is silently truncated: a body at or under the bound comes back
    whole, and a body past it raises.

    ``connector`` names the hop in the error text and MUST already be PHI-safe and secret-safe. Every
    call site passes a redacted URL or a connection name, never a body, a token, or a query.
    """
    if limit < 1:
        # A zero or negative ceiling would mean "unbounded", which is the defect this module exists
        # to close. Caught here as a programming error rather than shipped as a disable switch.
        raise ValueError(f"read_bounded needs a positive limit, got {limit}")
    body = bytes(reader.read(limit + 1))
    if len(body) > limit:
        raise ResponseTooLargeError(
            f"{connector} returned a response body over the {limit}-byte bound; "
            "refusing to buffer the rest"
        )
    return body


def read_bounded_text(
    reader: _SupportsRead,
    *,
    limit: int = DEFAULT_MAX_RESPONSE_BYTES,
    connector: str,
    encoding: str,
) -> str:
    """:func:`read_bounded`, decoded with ``errors="replace"``.

    The replacement policy matches every call site this replaces: a reply that is not valid in its
    declared encoding is still worth classifying, and the connectors never echo it.
    """
    return read_bounded(reader, limit=limit, connector=connector).decode(encoding, errors="replace")
