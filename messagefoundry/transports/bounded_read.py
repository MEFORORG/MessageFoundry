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

**A ceiling is not a completeness check, and this module once carried only the ceiling** (BACKLOG
#1575). Bounding the read answered "did the peer send too much?" and nothing answered "did the peer
send all of what it promised?", so a partner that declared ``Content-Length: 50`` and closed after
5 bytes produced a short read that came back as an ordinary value. On a first deployment that would
be reported as a successful delivery. :func:`read_bounded` now checks both, **ceiling first** --
an over-cap reply also leaves bytes outstanding, so testing completeness first would misreport
:class:`ResponseTooLargeError` as a truncation.

**Three reply framings, and only one of them can be detectably short.** ``http.client`` tracks the
declared remainder on ``HTTPResponse.length``, and what it holds after a read is the whole
discriminator:

* **fixed-length** (``Content-Length``) -- ``length`` counts down to ``0`` on a complete body and
  stops at a positive number on a truncated one. This is the only shape
  :class:`TruncatedResponseError` is raised for by the length comparison.
* **chunked** (``Transfer-Encoding: chunked``) -- ``length`` is ``None`` throughout, because the
  framing is in the stream rather than a header. A chunked reply declares no length, so it must
  never be failed for lacking one. ``http.client`` catches a *truncated* chunked stream itself by
  raising :class:`http.client.IncompleteRead`, which is translated here into the same error.
* **EOF-delimited** (no ``Content-Length``, not chunked, ``Connection: close``) -- ``length`` is
  also ``None``. The close *is* the framing, so a short body is the peer's whole reply and is
  legitimate.

**Truncation of an EOF-delimited reply is undetectable by construction, and nothing here claims
otherwise.** A peer that declared no length and closed early is indistinguishable from one that
closed on purpose -- there is no promise to compare against. So the shapes this module refuses are
**at least** the two above; do not read the list as covering every way a reply can be incomplete.

A ``204``/``304``/``1xx``, and any reply to a ``HEAD``, are fixed-length-of-zero: ``http.client``
sets ``length = 0`` before the read, so an empty body is complete, not truncated. A reader with no
``length`` attribute at all -- a plain binary file handle -- is unaffected.

A caller that DISCARDS the body wants :func:`drain_bounded` instead, which keeps the byte bound and
refuses nothing about the reply's shape.
"""

from __future__ import annotations

import http.client
from typing import Protocol

from messagefoundry.parsing.peek import DEFAULT_MAX_MESSAGE_BYTES
from messagefoundry.transports.base import DeliveryError

__all__ = [
    "DEFAULT_MAX_RESPONSE_BYTES",
    "MAX_TOKEN_RESPONSE_BYTES",
    "EgressReplyError",
    "ResponseTooLargeError",
    "TruncatedResponseError",
    "drain_bounded",
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


class EgressReplyError(DeliveryError):
    """Base for every refusal of a reply the engine read back off an egress hop.

    Exists so a call site that TRANSLATES one of these into its own error type can catch the
    family rather than one member. Catching a member is how the first cut of #1575 shipped a bug:
    adding :class:`TruncatedResponseError` beside :class:`ResponseTooLargeError` left
    ``ai_broker``'s ``AiBrokerError`` and ``fhir_lookup``'s ``FhirLookupError`` translations
    matching only the older sibling, so the new one escaped each of them unmapped. Catch this
    class, not a subclass, anywhere a refusal has to change type.
    """


class ResponseTooLargeError(EgressReplyError):
    """An egress reply exceeded its byte bound, so the engine refused to buffer the rest.

    A :class:`~messagefoundry.transports.base.DeliveryError`, therefore transient: the delivery
    worker retries it under the connection's own retry policy and dead-letters it the same way it
    dead-letters any other reply the engine could not read.
    """


class TruncatedResponseError(EgressReplyError):
    """An egress reply stopped short of the length the peer itself declared.

    The egress twin of the ingress refusal at ``transports/http_listener.py``'s ``_read_exactly``
    (BACKLOG #1657): a peer that closes mid-body has broken its own framing, so what arrived is a
    fragment and must not be handed on as the reply.

    A :class:`~messagefoundry.transports.base.DeliveryError`, therefore transient and retryable,
    for the same reason :class:`ResponseTooLargeError` is: a connection cut mid-body is a peer-side
    or network fault, and the next attempt may well complete. Promoting it to a permanent
    :class:`~messagefoundry.transports.base.NegativeAckError` would dead-letter a message on a
    dropped socket.
    """


class _SupportsRead(Protocol):
    """Anything with a byte-count-limited ``read``: an ``http.client.HTTPResponse``, the
    ``urllib.error.HTTPError`` that wraps one on a non-2xx, or a binary file handle.

    ``HTTPResponse.length`` is read through :func:`getattr` rather than declared here, because a
    binary file handle has no such attribute and reads through this helper all the same.
    ``HTTPError`` delegates the attribute to the response it wraps, so the non-2xx path is covered
    without naming it."""

    def read(self, amt: int, /) -> bytes: ...


def read_bounded(
    reader: _SupportsRead,
    *,
    limit: int = DEFAULT_MAX_RESPONSE_BYTES,
    connector: str,
) -> bytes:
    """Return the reply body, bounded at ``limit`` bytes and checked for completeness.

    Asks the socket for ``limit + 1`` bytes. Getting that many proves the body is over the bound
    without ever buffering the whole of it, so the refusal costs one byte of headroom rather than
    the peer's whole payload. A body past the bound raises :class:`ResponseTooLargeError`, and one
    that stopped short of its own declared length raises :class:`TruncatedResponseError` -- see the
    module docstring for which framings can be short and why the ceiling is tested first.

    Use :func:`drain_bounded` instead where the body is DISCARDED.

    ``connector`` names the hop in the error text and MUST already be PHI-safe and secret-safe. Every
    call site passes a redacted URL or a connection name, never a body, a token, or a query. The
    byte counts in the messages below are framing metadata, not content.
    """
    body = _read_capped(reader, limit, connector)
    # AFTER the ceiling check inside _read_capped, never before: an over-cap reply also leaves bytes
    # outstanding (the read stopped at limit + 1 by design), so testing completeness first would
    # report a body that is too LARGE as one that is too SHORT.
    remaining = getattr(reader, "length", None)
    if isinstance(remaining, int) and remaining > 0:
        raise TruncatedResponseError(
            f"{connector} declared a response body {len(body) + remaining} bytes long but sent "
            f"{len(body)}; refusing to treat a truncated reply as the peer's answer"
        )
    return body


def drain_bounded(
    reader: _SupportsRead,
    *,
    limit: int = DEFAULT_MAX_RESPONSE_BYTES,
    connector: str,
) -> None:
    """Read a reply body and throw it away, bounded, refusing nothing about its SHAPE.

    The operation a probe or a connection-hygiene drain actually wants. The byte bound still
    applies, because an unbounded drain is a memory exhaustion whether or not anyone reads the
    bytes -- so :class:`ResponseTooLargeError` still propagates. What it never raises is
    :class:`TruncatedResponseError`: a caller that discards the body has no answer to be wrong
    about. The peer responding IS the whole question a probe asks, and an alert webhook has already
    been accepted by the time its reply is drained, so failing either on a short body would report
    an unreachable partner that answered, or a failed alert the host took.

    A separate function rather than a flag on :func:`read_bounded`, because a truncation can be
    detected on TWO paths -- the declared-length comparison and the
    :class:`~http.client.IncompleteRead` translation -- and a boolean gating one of them silently
    left the other live. This form cannot be half-applied.
    """
    try:
        _read_capped(reader, limit, connector)
    except TruncatedResponseError:
        return


def _read_capped(reader: _SupportsRead, limit: int, connector: str) -> bytes:
    """The byte ceiling, shared by :func:`read_bounded` and :func:`drain_bounded`.

    Raises :class:`ResponseTooLargeError` past the bound, and :class:`TruncatedResponseError` for a
    stream the peer cut mid-body (which ``http.client`` reports as
    :class:`~http.client.IncompleteRead`). Completeness against a DECLARED length is the caller's
    business, because only :func:`read_bounded` wants it.
    """
    if limit < 1:
        # A zero or negative ceiling would mean "unbounded", which is the defect this module exists
        # to close. Caught here as a programming error rather than shipped as a disable switch.
        raise ValueError(f"read_bounded needs a positive limit, got {limit}")
    cut_short = False
    try:
        body = bytes(reader.read(limit + 1))
    except http.client.IncompleteRead:
        # http.client detects this shape itself but raises an HTTPException, which matches none of
        # the connectors' except arms and would escape send() as an internal error.
        cut_short = True
    if cut_short:
        # Raised OUTSIDE the except block ON PURPOSE. IncompleteRead holds the partial body on
        # `.partial` and in `.args[0]`, and `_read_chunked` chains an inner IncompleteRead that
        # holds it too -- so raising INSIDE the handler would keep reply bytes reachable through
        # `__context__.__cause__.partial` for any sink logging with exc_info, PHI by CLAUDE.md
        # section 9. `from None` alone does not do this: it clears `__cause__` and leaves
        # `__context__`. Leaving the handler first clears the exception being handled, so the new
        # error references nothing.
        #
        # No byte count: `partial` is EMPTY for the common chunked case (`_read_chunked` appends to
        # its accumulator only after a whole chunk arrives), so a count here would report 0 for a
        # peer that sent real bytes and read as "the peer sent nothing".
        raise TruncatedResponseError(
            f"{connector} closed the connection part-way through the response body"
        )
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
    declared encoding is still worth classifying, and the connectors never echo it. The completeness
    check runs BEFORE the decode, so ``errors="replace"`` never gets the chance to turn a fragment
    into a plausible-looking string.
    """
    return read_bounded(reader, limit=limit, connector=connector).decode(encoding, errors="replace")
