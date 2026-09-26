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
  never be failed for lacking one. A *truncated* chunked stream is caught by the chunk decoder
  below and raised as the same error. For any other reader, ``http.client``'s
  :class:`~http.client.IncompleteRead` is translated into it.
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

**Framing comes before length, and** ``http.client`` **does not check it** (BACKLOG #1125, ASVS
4.2.1). ``http.client`` reads the FIRST ``Transfer-Encoding`` field and treats the reply as chunked
only when that one value, compared case-insensitively, is ``chunked``; otherwise it frames by the
FIRST ``Content-Length``, parsed with :func:`int`. So ``Transfer-Encoding: gzip, chunked`` beside
``Content-Length: 3`` reads three bytes of raw chunk framing, two ``Content-Length`` fields of 3
and 5 read whichever came first, and ``Content-Length: 1_0`` reads ten bytes. Each of those would
hand a wrong body to the caller as the peer's answer, with no truncation for the checks above to
see.
:func:`reply_framing_fault` refuses them before any body byte is read, under RFC 9112 section 6.
See its docstring for the shapes and for why each one is refused. It also refuses a header block
the HTTP reader did not parse cleanly, because a framing header after a malformed line is lost.

**A chunked body is decoded here, not by** ``http.client`` (BACKLOG #1979). ``http.client`` parses
each chunk-size line with ``int(line, 16)``, so ``-5``, ``1_0``, ``+5``, ``0x5`` and `` 5 `` all
parse. A negative size reaches ``fp.read(-5)``, which reads to the end of the stream, so the
``limit + 1`` argument stopped bounding what was buffered. It also tosses the two bytes after each
chunk's data without looking at them. :func:`read_reply_body` reads a chunked
``http.client.HTTPResponse`` itself, from the response's underlying stream, under the RFC 9112
section 7.1 grammar, and stops at the caller's byte count. Every bounded read here goes through it,
and so do the OIDC token and JWKS reads.
"""

from __future__ import annotations

import email.message
import email.parser
import functools
import http.client
import logging
import re
from typing import Protocol

from messagefoundry.parsing.peek import DEFAULT_MAX_MESSAGE_BYTES
from messagefoundry.transports.base import DeliveryError

__all__ = [
    "DEFAULT_MAX_RESPONSE_BYTES",
    "MAX_TOKEN_RESPONSE_BYTES",
    "AmbiguousFramingError",
    "EgressReplyError",
    "ResponseTooLargeError",
    "TruncatedResponseError",
    "drain_bounded",
    "read_bounded",
    "read_bounded_text",
    "read_reply_body",
    "reply_framing_fault",
]

logger = logging.getLogger(__name__)

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


class AmbiguousFramingError(EgressReplyError):
    """An egress reply declared its body length in a way RFC 9112 does not allow, or that
    ``http.client`` would read differently from the one legal reading.

    Refused BEFORE any body byte is read. Most of the refused shapes make ``http.client`` hand
    back the wrong bytes as the reply: raw chunk framing, the shorter of two lengths, or ten bytes
    for ``1_0``. The rest happen to read the right bytes today, and are refused because RFC 9112
    calls them an error: ``Transfer-Encoding`` beside ``Content-Length``, a ``+5`` or ``5, 5``
    length, and ``Transfer-Encoding`` on HTTP/1.0. There, a correct read depends on which field
    ``http.client`` happens to consult first. The shapes are listed on :func:`reply_framing_fault`.

    Also raised part-way through a chunked body, at the first chunk-size line, chunk terminator or
    trailer line that breaks the RFC 9112 section 7.1 grammar. By then some bytes have been read,
    but none past the caller's byte count, and none is returned.

    A :class:`~messagefoundry.transports.base.DeliveryError`, therefore transient, like its two
    siblings: the delivery worker records it on the row, retries under the connection's policy and
    dead-letters it when the policy runs out. It is not a permanent
    :class:`~messagefoundry.transports.base.NegativeAckError`, because a misframed reply may come
    from an intermediary on one path rather than from the partner itself.
    """

    def __init__(self, message: str, *, reason: str) -> None:
        super().__init__(message)
        #: The fixed reason text, never a peer byte, so a caller can word its own message.
        self.reason = reason

    def __reduce__(self) -> tuple[object, ...]:
        # BaseException pickles and copies as cls(*self.args), and args holds only the message, so
        # the keyword-only reason must travel with the constructor or the rebuild raises TypeError.
        return (functools.partial(type(self), reason=self.reason), self.args, self.__dict__)


class _SupportsRead(Protocol):
    """Anything with a byte-count-limited ``read``: an ``http.client.HTTPResponse``, the
    ``urllib.error.HTTPError`` that wraps one on a non-2xx, or a binary file handle.

    ``HTTPResponse.length`` is read through :func:`getattr` rather than declared here, because a
    binary file handle has no such attribute and reads through this helper all the same.
    ``HTTPError`` delegates the attribute to the response it wraps, so the non-2xx path is covered
    without naming it."""

    def read(self, amt: int, /) -> bytes: ...


class _SupportsReadline(_SupportsRead, Protocol):
    """The buffered stream under an ``http.client.HTTPResponse``, as the chunk decoder uses it."""

    def readline(self, size: int, /) -> bytes: ...


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
    fault = reply_framing_fault(reader)
    if fault is not None:
        raise _framing_error(connector, fault)
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

    It does not apply :func:`reply_framing_fault` either, for the same reason. A misframed reply
    changes WHICH bytes are read, and a drain uses none of them. ``urllib`` closes the connection
    after each ``open()``, so no later reply shares the stream a misread could desynchronise. The
    byte bound still applies to whatever the header framing selects.

    A chunked body is decoded under the strict grammar here too, because that decoder is what keeps
    a negative chunk size inside the byte bound (BACKLOG #1979). A drain stops at the first line it
    cannot parse and does not raise. It logs a WARNING instead, so the stop is recorded rather than
    silent. The WARNING carries a fixed reason, the request method and the status code, and nothing
    else. It leaves ``connector`` out on purpose. Callers build it from configuration, at least a
    redacted URL or a webhook host, and this log line should not depend on each caller's redaction
    being complete. The cost is that the line does not name the hop. The exceptions this module
    raises still carry ``connector``, and so rely on the caller's redaction.
    """
    try:
        _read_capped(reader, limit, connector)
    except TruncatedResponseError:
        return
    except AmbiguousFramingError as exc:
        method = getattr(reader, "_method", None)
        status = getattr(reader, "status", None)
        logger.warning(
            "The reply to a %s request had a malformed body (status %s, %s); the drain stopped "
            "there, and the call is not failed because the body is discarded",
            method if method in _LOGGED_METHODS else "HTTP",
            status if isinstance(status, int) else "unknown",
            exc.reason,
        )


#: The request methods the drain WARNING may name. Anything else is logged as "HTTP", so the line
#: holds only text from this module. HEAD is absent because a HEAD reply is never decoded, so it
#: cannot reach the WARNING.
_LOGGED_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})


#: Statuses whose reply has no body (RFC 9112 section 6.3, rule 1). See reply_framing_fault.
_BODYLESS_STATUSES = frozenset({204, 304})


def _status_has_no_body(status: int) -> bool:
    """RFC 9112 section 6.3, rule 1: a 1xx, 204 or 304 reply has no body, whatever it declares."""
    return status in _BODYLESS_STATUSES or 100 <= status < 200


def reply_framing_fault(reader: object) -> str | None:
    """Return why ``reader``'s body framing is refused, or ``None`` when it is unambiguous.

    RFC 9112 section 6 allows one reading of a reply's length, and a recipient that picks another is
    how a smuggled or split response gets through. Refused, at least:

    * A header block the HTTP reader did not parse cleanly. ``http.client`` hands the header lines
      to the email parser, which stops at the first line that is not a field line, records a
      defect, and keeps every later line as unparsed payload. So a ``Content-Length`` or
      ``Transfer-Encoding`` after a malformed line, or after a name with whitespace before its
      colon, is silently lost, and the body is framed by what came before it or read to close.
      Under a ``multipart/*`` or ``message/*`` type the lost lines are built into a preamble,
      parts, an epilogue or a nested message instead, and are refused all the same. Also refused:
      an mbox ``From `` line, which that parser takes silently, a field name that is not an RFC
      9110 token, and a field value holding a control character. This check runs first, on every
      status and on ``HEAD``. How it decides is on :func:`_header_block_fault`.
      **Known to be missed, at least:** a bare CR followed by text that reads as a field line.
      The email parser splits the line there and records nothing, so that text counts as a header
      of its own, and the parse tree looks clean. Catching it needs the raw header bytes, and
      ``http.client`` discards them before this function runs. Other shapes that leave no trace in
      the parse tree would be missed the same way.
    * ``Transfer-Encoding`` on an HTTP/1.0 reply. Section 6.1 says the framing is then faulty.
    * ``Transfer-Encoding`` beside ``Content-Length``. Section 6.1 calls this a possible smuggling
      attempt that "ought to be handled as an error".
    * ``Transfer-Encoding`` whose codings, across every field, are anything but the single coding
      ``chunked``. If chunked is not the final coding, section 6.3 frames the body by connection
      close, and ``http.client`` would instead frame it by a ``Content-Length`` or read raw chunk
      framing. If chunked IS final behind another coding such as ``gzip, chunked``, the framing is
      legal, but ``http.client`` recognises chunked only as the whole field value and decodes no
      other transfer coding. It would return the raw framing, so the engine refuses a reply it
      cannot read rather than misreading it.
    * ``Transfer-Encoding: chunked`` that ``http.client`` did not take as chunked, which
      trailing whitespace in the value is enough to cause. The rule is the reader's own
      ``chunked`` flag, so the guard tracks what the read would actually do.
    * A ``Content-Length`` that is not ``1*DIGIT``. :func:`int` accepts ``+5``, ``1_0`` and
      ``5, 5`` fails it, and section 6.3 calls an invalid length an unrecoverable error.
    * More than one ``Content-Length`` field with different values. ``http.client`` takes the
      first; section 6.3 calls this an unrecoverable error. Identical repeats are allowed.
    * A ``Content-Length`` that is all digits but that ``http.client`` could not parse, so it left
      the length unset and would read to close. Past 4300 digits :func:`int` refuses the string.

    A reply to ``HEAD`` is not checked: ``http.client`` returns no body for it whatever the headers
    say. A ``204``, a ``304`` and any ``1xx`` have no body either, and ``http.client`` sets
    ``length = 0`` for them, so a ``Content-Length`` there frames nothing; a ``304`` routinely
    carries its representation's length. But ``http.client`` tests ``chunked`` before ``length``,
    so ``Transfer-Encoding`` on one of those statuses would still make it read a chunked body that
    section 6.3 says does not exist. That one header is refused there, and nothing else is checked.

    A reader with no parsed headers, such as a binary file handle, has no framing to refuse and
    returns ``None``.

    The reason strings are fixed text and never echo a header value.
    """
    headers = getattr(reader, "headers", None)
    get_all = getattr(headers, "get_all", None)
    if not callable(get_all):
        return None
    if isinstance(headers, email.message.Message):
        header_fault = _header_block_fault(headers)
        if header_fault is not None:
            return header_fault
    # A private attribute, read defensively: HTTPResponse keeps the request method only there, and
    # HTTPError delegates attribute reads to the response it wraps.
    if getattr(reader, "_method", None) == "HEAD":
        return None
    te_fields: list[str] = [str(v) for v in (get_all("Transfer-Encoding") or [])]
    cl_fields: list[str] = [str(v).strip(" \t") for v in (get_all("Content-Length") or [])]
    status = getattr(reader, "status", None)
    if isinstance(status, int) and _status_has_no_body(status):
        return "Transfer-Encoding on a response that has no body" if te_fields else None
    if te_fields:
        if getattr(reader, "version", None) == 10:
            return "Transfer-Encoding on an HTTP/1.0 response"
        if cl_fields:
            return "Transfer-Encoding and Content-Length together"
        codings = [c.strip(" \t").lower() for field in te_fields for c in field.split(",")]
        codings = [c for c in codings if c]
        if not codings or codings[-1] != "chunked":
            return "Transfer-Encoding whose final coding is not chunked"
        if "chunked" in codings[:-1]:
            return "the chunked transfer coding applied more than once"
        if codings != ["chunked"]:
            return "a transfer coding other than chunked, which the engine does not decode"
        if getattr(reader, "chunked", None) is False:
            return "a chunked Transfer-Encoding value the HTTP reader did not recognise"
        return None
    if cl_fields:
        if not all(v.isascii() and v.isdigit() for v in cl_fields):
            return "a Content-Length that is not a plain decimal number"
        # Compared as digit strings, not with int(): past 4300 digits int() raises ValueError, and a
        # ValueError would reach the connectors' invalid-request-value arm as the wrong error.
        if len({v.lstrip("0") or "0" for v in cl_fields}) > 1:
            return "more than one Content-Length, with different values"
        # The same int() limit inside http.client: a length it cannot parse leaves `length` None,
        # and the reply is then read to close instead of to the length it declared.
        if getattr(reader, "length", 0) is None:
            return "a Content-Length the HTTP reader could not use"
    return None


def _read_capped(reader: _SupportsRead, limit: int, connector: str) -> bytes:
    """The byte ceiling, shared by :func:`read_bounded` and :func:`drain_bounded`.

    Raises :class:`ResponseTooLargeError` past the bound. :func:`read_reply_body` raises
    :class:`TruncatedResponseError` for a stream the peer cut mid-body, and
    :class:`AmbiguousFramingError` for a chunked body that breaks its grammar. Completeness against a
    DECLARED length is the caller's business, because only :func:`read_bounded` wants it.
    """
    if limit < 1:
        # A zero or negative ceiling would mean "unbounded", which is the defect this module exists
        # to close. Caught here as a programming error rather than shipped as a disable switch.
        raise ValueError(f"read_bounded needs a positive limit, got {limit}")
    body = read_reply_body(reader, limit + 1, connector=connector)
    if len(body) > limit:
        raise ResponseTooLargeError(
            f"{connector} returned a response body over the {limit}-byte bound; "
            "refusing to buffer the rest"
        )
    return body


def read_reply_body(reader: _SupportsRead, amt: int, *, connector: str) -> bytes:
    """Read at most ``amt`` bytes of a reply body, as ``reader.read(amt)`` would, but strictly.

    The low-level read under the bounded helpers here. It applies no ceiling of its own: a caller
    asks for one byte past its bound and judges the length. It does not call
    :func:`reply_framing_fault` either; the caller does that first where it wants the header checks.

    A chunked ``http.client.HTTPResponse``, or the ``HTTPError`` that wraps one, is decoded by
    :func:`_read_chunked_strict` rather than by ``http.client``. Anything else is read with
    ``reader.read(amt)``. **Call it once per response, not in a loop:** a chunked response is closed
    after the call, so a second call returns ``b""`` as if the body had ended.

    Raises :class:`TruncatedResponseError` when the peer closed part-way through the body, and
    :class:`AmbiguousFramingError` when a chunked body breaks the RFC 9112 section 7.1 grammar.
    """
    if amt < 1:
        # A negative count means "read to end of stream", which is the defect this function closes.
        raise ValueError(f"read_reply_body needs a positive byte count, got {amt}")
    resp = _chunked_response(reader)
    if resp is not None:
        return _read_chunked_strict(resp, amt, connector)
    cut_short = False
    try:
        body = bytes(reader.read(amt))
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
        # error references nothing. This arm now serves only readers other than a chunked
        # HTTPResponse, which _read_chunked_strict decodes.
        raise _truncated_error(connector)
    return body


def _framing_error(connector: str, reason: str) -> AmbiguousFramingError:
    # The reason is always a fixed string from this module, never a header value or a body byte, so
    # the message carries nothing the peer supplied.
    return AmbiguousFramingError(
        f"{connector} framed its response body ambiguously ({reason}); refusing to read it",
        reason=reason,
    )


def _truncated_error(connector: str) -> TruncatedResponseError:
    return TruncatedResponseError(
        f"{connector} closed the connection part-way through the response body"
    )


# --- the header block -----------------------------------------------------------------------------

#: An RFC 9110 section 5.6.2 token, the grammar of a field name and of a chunk extension name.
_TCHARS = r"!#$%&'*+\-.^_`|~0-9A-Za-z"
_TOKEN = f"[{_TCHARS}]+"
_FIELD_NAME = re.compile(_TOKEN)
#: A folded line break inside a raw field value, which RFC 9112 section 5.2 lets a user agent
#: accept in a response, and the controls RFC 9110 section 5.5 forbids in a value (HTAB allowed).
_OBS_FOLD = re.compile(r"\r?\n[ \t]")
_VALUE_CTL = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")


def _header_block_fault(headers: email.message.Message) -> str | None:
    """Why the header block did not parse as RFC 9112 field lines, or ``None`` when it did.

    The test is a comparison, not a list of places a lost line can land. ``http.client`` discards
    the raw header bytes before any caller sees the reply, so this rebuilds the block from the
    fields the email parser DID find, parses that with an empty body, and requires the two parse
    trees to match. A clean block has an empty body, so its tree is exactly the reference's. A line
    the parser did not take as a field line must have gone somewhere else: a defect, an mbox
    envelope, a body string, a nested message, or a ``multipart/*`` preamble, part or epilogue.
    A line that lands in any of those makes the trees differ, whatever the ``Content-Type`` says
    (BACKLOG #1125). A line lost without leaving a trace in the tree is missed. At least one such
    shape is known: see :func:`reply_framing_fault`.

    A Message built in code, with no body parsed, has no lost line to find. Its payload is
    ``None``, which the parser never leaves on a block it read, so the comparison is skipped.

    Each reason is a fixed string that names the header block, and never echoes a field value.
    """
    parsed = headers.get_payload() is not None or bool(headers.defects)
    reference = _reparse_fields(headers) if parsed else headers
    if _defect_names(headers) != _defect_names(reference):
        return "a header line the HTTP reader could not parse"
    if _parse_tree(headers) != _parse_tree(reference):
        return "header lines the HTTP reader left unparsed"
    for name, value in headers.raw_items():
        if not _FIELD_NAME.fullmatch(name):
            return "a header field name that is not a token"
        if _VALUE_CTL.search(_OBS_FOLD.sub(" ", value)):
            return "a header field value holding a control character"
    return None


def _reparse_fields(msg: email.message.Message) -> email.message.Message:
    """``msg``'s own fields, re-parsed as a clean header block with an empty body.

    The same parser class and policy ``http.client`` used, so a ``multipart/*`` or ``message/*``
    type builds the same empty structure it builds for a clean reply. Values are raw, folds
    included, and the parser strips the space after the colon, so each field parses back as itself.
    """
    block = "".join(f"{name}: {value}\r\n" for name, value in msg.raw_items()) + "\r\n"
    reparsed: email.message.Message = email.parser.Parser(
        _class=type(msg), policy=msg.policy
    ).parsestr(block)
    return reparsed


def _defect_names(msg: email.message.Message) -> list[str]:
    return [type(d).__name__ for d in msg.defects]


def _parse_tree(msg: email.message.Message) -> tuple[object, ...]:
    """Everything the email parser built from a header block, as a comparable value.

    Covers each place the parser can put a line: the fields, an mbox envelope, the defects, the
    preamble and epilogue of a ``multipart/*`` body, and the payload, recursing into nested parts.
    """
    payload = msg.get_payload()
    body: object = payload
    if isinstance(payload, list):
        body = tuple(
            _parse_tree(part)
            if isinstance(part, email.message.Message)
            else ("not a message", type(part).__name__)
            for part in payload
        )
    return (
        msg.get_unixfrom(),
        tuple(msg.raw_items()),
        _defect_names(msg),
        msg.preamble,
        msg.epilogue,
        body,
    )


# --- the chunked body -----------------------------------------------------------------------------
#
# RFC 9112 section 7.1:
#   chunked-body = *chunk last-chunk trailer-section CRLF
#   chunk        = chunk-size [ chunk-ext ] CRLF chunk-data CRLF
#   chunk-size   = 1*HEXDIG
#   last-chunk   = 1*("0") [ chunk-ext ] CRLF
#   chunk-ext    = *( BWS ";" BWS chunk-ext-name [ BWS "=" BWS chunk-ext-val ] )
#   chunk-ext-val = token / quoted-string

#
# The patterns are str, matched against each line decoded as latin-1 by _read_chunk_line, which maps
# every byte to the code point of the same value. So \x80-\xff below means the same bytes it would
# in a bytes pattern, and the static ReDoS scan in tests/test_security_static.py reads them.
#
# The extension group repeats POSSESSIVELY (*+). Each element has one parse: the token class and
# the whitespace exclude ";", "=" and '"', and a quoted string ends at the first '"' that no
# backslash escapes, because its plain text excludes both '"' and "\". So a ";" inside a quoted
# value cannot start a repetition, and giving one back can never lead to a match. Possessive says
# so to the regex engine and to the scan. If _QUOTED ever admits '"' or "\" in its plain text, or
# loses its closing quote, that no longer holds: possessive would then refuse legal lines.

_QUOTED = r'"(?:[\t \x21\x23-\x5b\x5d-\x7e\x80-\xff]|\\[\t \x21-\x7e\x80-\xff])*"'
_CHUNK_EXT = (
    r"(?:[ \t]*;[ \t]*" + _TOKEN + r"(?:[ \t]*=[ \t]*(?:" + _TOKEN + "|" + _QUOTED + r"))?)*+"
)
_CHUNK_SIZE_LINE = re.compile("([0-9A-Fa-f]+)" + _CHUNK_EXT)
#: A trailer field line. It is discarded unread, but a line that is not one is a framing fault.
_TRAILER_LINE = re.compile(_TOKEN + r":[\t\x20-\x7e\x80-\xff]*")
#: A folded continuation of the trailer line before it, accepted as a header fold is.
_TRAILER_FOLD = re.compile(r"[ \t][\t\x20-\x7e\x80-\xff]*")

#: The line and field-count limits ``http.client`` applies to header lines, applied here to chunk
#: lines and trailer fields. Neither is a new number.
_MAX_LINE = 65536
_MAX_TRAILER_FIELDS = 100


def _chunked_response(reader: object) -> http.client.HTTPResponse | None:
    """The chunked ``HTTPResponse`` behind ``reader``, or ``None`` when there is none.

    A 2xx arrives as the ``HTTPResponse`` itself. A non-2xx arrives as the ``urllib`` ``HTTPError``
    that wraps it, which keeps the response on ``.fp``.
    """
    resp = reader if isinstance(reader, http.client.HTTPResponse) else getattr(reader, "fp", None)
    if isinstance(resp, http.client.HTTPResponse) and resp.chunked is True:
        return resp
    return None


def _read_chunked_strict(resp: http.client.HTTPResponse, amt: int, connector: str) -> bytes:
    """Decode ``resp``'s chunked body from its underlying stream, returning at most ``amt`` bytes.

    Closes the response afterwards, whatever happened, so nothing reads the rest of a stream this
    decoder stopped part-way through.
    """
    try:
        fp = resp.fp
        if fp is None:
            return b""  # already read or closed, which is what http.client returns too
        if getattr(resp, "_method", None) == "HEAD" or _status_has_no_body(resp.status):
            # No body exists (RFC 9112 section 6.3), whatever the headers say. http.client would
            # try to read a chunked one here and wait on the peer for it.
            return b""
        return _decode_chunked(fp, amt, connector)
    finally:
        resp.close()


#: The most one ``read`` asks for. A chunk-size line can declare far more than the peer sends, and
#: ``BufferedReader.read(n)`` allocates ``n`` bytes before it learns that, so a large chunk is read
#: in pieces of this size. ``http.client._safe_read`` grows its buffer for the same reason.
_READ_PIECE = 1024 * 1024


def _decode_chunked(fp: _SupportsReadline, amt: int, connector: str) -> bytes:
    # One bytearray rather than a list of chunks: a peer sending many tiny chunks would otherwise
    # cost an object per chunk, far past the byte bound.
    body = bytearray()
    while True:
        line = _read_chunk_line(fp, connector)
        if line is None:
            raise _truncated_error(connector)
        match = _CHUNK_SIZE_LINE.fullmatch(line)
        if match is None:
            raise _framing_error(connector, "a chunk-size line that is not plain hexadecimal")
        size = int(match.group(1), 16)
        if size == 0:
            break
        want = min(size, amt - len(body))
        while want:
            data = fp.read(min(want, _READ_PIECE))
            if not data:
                raise _truncated_error(connector)
            body += data
            want -= len(data)
        if len(body) >= amt:
            # The caller's count is reached. The rest of the stream is left unread, and the
            # response is closed by the caller of this function.
            return bytes(body)
        after = fp.read(2)
        if len(after) < 2:
            raise _truncated_error(connector)
        if after != b"\r\n":
            raise _framing_error(connector, "chunk data not followed by CRLF")
    field_seen = False
    for _ in range(_MAX_TRAILER_FIELDS + 1):
        line = _read_chunk_line(fp, connector)
        if not line:
            # An empty line ends the trailer section. A clean end of stream between lines ends it
            # too. The last chunk has arrived by then, so the body is settled. http.client accepts
            # this ending as well, because some servers send it.
            return bytes(body)
        if _TRAILER_LINE.fullmatch(line) is not None:
            field_seen = True
        elif not (field_seen and _TRAILER_FOLD.fullmatch(line)):
            raise _framing_error(connector, "a trailer line that is not a header field")
    # Folded continuation lines count toward the limit too, which keeps the loop bounded.
    raise _framing_error(connector, "more trailer lines than the reader allows")


def _read_chunk_line(fp: _SupportsReadline, connector: str) -> str | None:
    """One CRLF-terminated line of the chunked framing, without its CRLF, decoded as latin-1.

    Decoded here, once, so every grammar check gets the str its pattern needs. latin-1 maps each
    byte to one code point and cannot fail. ``None`` when the stream ended cleanly before the line
    began. A line cut part-way is a truncation.
    """
    line = fp.readline(_MAX_LINE + 1)
    if not line:
        return None
    if len(line) > _MAX_LINE:
        raise _framing_error(connector, "a chunked-body line longer than the reader allows")
    if not line.endswith(b"\n"):
        raise _truncated_error(connector)
    if not line.endswith(b"\r\n"):
        raise _framing_error(connector, "a chunked-body line not ended by CRLF")
    return line[:-2].decode("latin-1")


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
