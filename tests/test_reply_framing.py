# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Ambiguous reply framing is refused before the body is read (BACKLOG #1125, ASVS 4.2.1).

How ``http.client`` frames a reply, and the rules that refuse each shape, are stated once in
``messagefoundry/transports/bounded_read.py``. These tests measure them. The comment on each shape
records what the engine read as the body before the fix.

Every shape is served as raw bytes by a real local socket and read through a real ``urllib`` opener,
because the defect lives in how ``http.client`` parses the wire. A hand-written response double
would test the author's model of the stdlib instead.

Synthetic data only.
"""

from __future__ import annotations

import ast
import asyncio
import contextlib
import copy
import email.message
import http.client
import importlib
import io
import logging
import pickle
import socket
import ssl
import sys
import threading
import unicodedata
import urllib.request
from collections import Counter
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import NamedTuple

import pytest

from messagefoundry.auth.oidc_http import IdpReplyCutShortError, IdpReplyUnusableError
from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import FHIR, Rest, Soap
from messagefoundry.transports import build_destination
from messagefoundry.transports.base import DeliveryError, NegativeAckError
from messagefoundry.transports.bounded_read import (
    REPLY_MISFRAMED_CODE,
    AmbiguousFramingError,
    EgressReplyError,
    MalformedReplyHeadError,
    ResponseTooLargeError,
    StrictHTTPHandler,
    StrictHTTPResponse,
    StrictHTTPSHandler,
    TruncatedResponseError,
    build_strict_opener,
    drain_bounded,
    read_bounded,
    reply_framing_fault,
)
from messagefoundry.transports.fhir import FhirDestination
from messagefoundry.transports.rest import RestDestination
from messagefoundry.transports.soap import SoapDestination

_OK = b"HTTP/1.1 200 OK\r\n"
_CHUNKS = b"5\r\nhello\r\n0\r\n\r\n"

#: Each shape, and what the engine read as the body before the fix. The before-readings are
#: recorded here as the measured defect; the tests assert only the refusal.
_AMBIGUOUS: dict[str, bytes] = {
    # read b"5\r\n": three bytes of chunk framing
    "gzip-chunked-with-length": _OK
    + b"Transfer-Encoding: gzip, chunked\r\nContent-Length: 3\r\n\r\n"
    + _CHUNKS,
    # read b"5\r\n"
    "chunked-identity-with-length": _OK
    + b"Transfer-Encoding: chunked, identity\r\nContent-Length: 3\r\n\r\n"
    + _CHUNKS,
    # read b"5\r\n"
    "gzip-with-length": _OK + b"Transfer-Encoding: gzip\r\nContent-Length: 3\r\n\r\n" + _CHUNKS,
    # read the raw framing to close; legal under RFC 9112 but not decodable by http.client
    "gzip-chunked-no-length": _OK + b"Transfer-Encoding: gzip, chunked\r\n\r\n" + _CHUNKS,
    # read b"hello": decoded as chunked though chunked is not the final coding
    "chunked-then-gzip-field": _OK
    + b"Transfer-Encoding: chunked\r\nTransfer-Encoding: gzip\r\n\r\n"
    + _CHUNKS,
    # read b"hello": the Content-Length was silently ignored
    "chunked-with-length": _OK
    + b"Transfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n"
    + _CHUNKS,
    # read b"5\r\nhello\r\n0\r\n\r\n": trailing whitespace hid the chunked coding from http.client
    "chunked-trailing-space": _OK + b"Transfer-Encoding: chunked \r\n\r\n" + _CHUNKS,
    # read b"hel": the first of two lengths
    "two-lengths-3-and-5": _OK + b"Content-Length: 3\r\nContent-Length: 5\r\n\r\nhello",
    # read b"hellohello": int() accepts the underscore
    "length-1_0": _OK + b"Content-Length: 1_0\r\n\r\nhellohello",
    # read b"hello": int() accepts the sign
    "length-plus-5": _OK + b"Content-Length: +5\r\n\r\nhello",
    # read b"hello" to close: int() refused the list, so the length was dropped
    "length-list-5-5": _OK + b"Content-Length: 5, 5\r\n\r\nhello",
    # read b"hello": Transfer-Encoding on HTTP/1.0
    "http10-chunked": b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + _CHUNKS,
    # read b"hello" as the body of a 204, a status with no body; and the TE+CL shape refused on a 200
    "no-content-chunked": b"HTTP/1.1 204 No Content\r\n"
    + b"Transfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n"
    + _CHUNKS,
    # read b"hello": chunked applied twice, which RFC 9112 section 6.1 forbids
    "chunked-twice": _OK
    + b"Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n"
    + _CHUNKS,
}

#: Framings that are unambiguous and must still read as b"hello".
_CONTROLS: dict[str, bytes] = {
    "plain-length": _OK + b"Content-Length: 5\r\n\r\nhello",
    "plain-chunked": _OK + b"Transfer-Encoding: chunked\r\n\r\n" + _CHUNKS,
    "chunked-upper-case": _OK + b"Transfer-Encoding: CHUNKED\r\n\r\n" + _CHUNKS,
    "identical-lengths": _OK + b"Content-Length: 5\r\nContent-Length: 5\r\n\r\nhello",
    "leading-zero-length": _OK + b"Content-Length: 005\r\n\r\nhello",
    "eof-delimited": _OK + b"Connection: close\r\n\r\nhello",
    "http10-length": b"HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello",
}


@contextlib.contextmanager
def _serve(raw: bytes) -> Iterator[str]:
    """Serve ``raw`` verbatim to one request on a loopback socket; yield the URL."""
    listener = socket.create_server(("127.0.0.1", 0))
    # Bounded, so a test whose connector refuses before connecting cannot leave accept() blocked.
    listener.settimeout(5)
    port = listener.getsockname()[1]

    def run() -> None:
        with listener:
            try:
                conn, _ = listener.accept()
            except TimeoutError:
                return
            with conn:
                conn.settimeout(5)
                buf = b""
                while b"\r\n\r\n" not in buf:
                    chunk = conn.recv(4096)
                    if not chunk:
                        return
                    buf += chunk
                head, _, body = buf.partition(b"\r\n\r\n")
                # Drain the request body, so closing with unread bytes cannot reset the socket
                # before the client has read the reply.
                for line in head.split(b"\r\n"):
                    name, _, value = line.partition(b":")
                    if name.strip().lower() == b"content-length":
                        want = int(value.strip())
                        while len(body) < want:
                            chunk = conn.recv(4096)
                            if not chunk:
                                break
                            body += chunk
                conn.sendall(raw)
                conn.shutdown(socket.SHUT_WR)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}/svc"
    finally:
        thread.join(timeout=5)


def _open(url: str) -> http.client.HTTPResponse:
    resp = urllib.request.build_opener().open(url, timeout=5)
    assert isinstance(resp, http.client.HTTPResponse)
    return resp


def _soap(url: str) -> SoapDestination:
    d = build_destination(
        Destination(
            name="OB_SOAP",
            type=ConnectorType.SOAP,
            settings=Soap(url=url, capture_response=True).settings,
        ),
        egress=EgressSettings(deny_by_default=False),
    )
    assert isinstance(d, SoapDestination)
    return d


def _rest(url: str) -> RestDestination:
    d = build_destination(
        Destination(
            name="OB_REST",
            type=ConnectorType.REST,
            settings=Rest(url=url, capture_response=True).settings,
        ),
        egress=EgressSettings(deny_by_default=False),
    )
    assert isinstance(d, RestDestination)
    return d


def _fhir(url: str) -> FhirDestination:
    d = build_destination(
        Destination(name="OB_FHIR", type=ConnectorType.FHIR, settings=FHIR(url=url).settings),
        egress=EgressSettings(deny_by_default=False),
    )
    assert isinstance(d, FhirDestination)
    return d


def _assert_framing_refusal(exc: BaseException) -> None:
    assert isinstance(exc, AmbiguousFramingError)
    if isinstance(exc, MalformedReplyHeadError):
        # Refused while the head was read, before the body framing is known (BACKLOG #2052).
        assert "framed its reply ambiguously" in str(exc)
    else:
        assert "framed its response body ambiguously" in str(exc)


def _assert_captured_2xx_refusal(exc: BaseException) -> None:
    """What a send with ``capture_response`` on raises for a misframed 2xx reply.

    A bad head is refused while it is read, before any status can be trusted, so it stays the
    retryable refusal above. A body misframed under a 2xx head is a permanent refusal since
    BACKLOG #2989: the request is not sent again, and the body is needed here. The reason is the
    same fixed text the retryable refusal carried."""
    if isinstance(exc, MalformedReplyHeadError):
        _assert_framing_refusal(exc)
        return
    assert isinstance(exc, NegativeAckError)
    assert (exc.code, exc.permanent, exc.config_fault) == (REPLY_MISFRAMED_CODE, True, False)
    assert f"{REPLY_MISFRAMED_CODE}, not sent again" in str(exc)
    assert exc.__context__ is None


# --- the shared reader --------------------------------------------------------------------------


@pytest.mark.parametrize("shape", list(_AMBIGUOUS), ids=list(_AMBIGUOUS))
def test_read_bounded_refuses_ambiguous_framing(shape: str) -> None:
    with (
        _serve(_AMBIGUOUS[shape]) as url,
        _open(url) as resp,
        pytest.raises(EgressReplyError) as raised,
    ):
        read_bounded(resp, connector="c")
    _assert_framing_refusal(raised.value)


@pytest.mark.parametrize("shape", list(_CONTROLS), ids=list(_CONTROLS))
def test_read_bounded_reads_unambiguous_framing(shape: str) -> None:
    with _serve(_CONTROLS[shape]) as url, _open(url) as resp:
        assert read_bounded(resp, connector="c") == b"hello"


# --- the outbound call paths that use it --------------------------------------------------------


@pytest.mark.parametrize("shape", list(_AMBIGUOUS), ids=list(_AMBIGUOUS))
def test_soap_captured_reply_refuses_ambiguous_framing(shape: str) -> None:
    """The SOAP captured-reply path. It never becomes a captured reply: see
    :func:`_assert_captured_2xx_refusal` for which refusal it is."""
    with _serve(_AMBIGUOUS[shape]) as url:
        dest = _soap(url)
        with pytest.raises(DeliveryError) as raised:
            asyncio.run(dest.send("<soap:Envelope/>"))
    _assert_captured_2xx_refusal(raised.value)


@pytest.mark.parametrize("shape", list(_AMBIGUOUS), ids=list(_AMBIGUOUS))
def test_rest_reply_refuses_ambiguous_framing(shape: str) -> None:
    with _serve(_AMBIGUOUS[shape]) as url:
        dest = _rest(url)
        with pytest.raises(DeliveryError) as raised:
            asyncio.run(dest.send('{"a": 1}'))
    _assert_captured_2xx_refusal(raised.value)


@pytest.mark.parametrize("shape", list(_CONTROLS), ids=list(_CONTROLS))
def test_soap_captured_reply_reads_unambiguous_framing(shape: str) -> None:
    with _serve(_CONTROLS[shape]) as url:
        reply = asyncio.run(_soap(url).send("<soap:Envelope/>"))
    assert reply is not None
    assert reply.body == "hello"
    assert reply.outcome == "accepted"


def test_soap_fault_body_with_ambiguous_framing_is_classified_on_status(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A non-2xx reply is read only to classify it. A misframed fault body is logged and dropped,
    and the delivery still fails on the status, the same as an over-cap fault body."""
    raw = (
        b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 3\r\nContent-Length: 5\r\n\r\nhello"
    )
    with (
        _serve(raw) as url,
        caplog.at_level(logging.WARNING),
        pytest.raises(DeliveryError) as raised,
    ):
        asyncio.run(_soap(url).send("<soap:Envelope/>"))
    assert type(raised.value) is DeliveryError
    assert "HTTP 500" in str(raised.value)
    assert "could not read whole" in caplog.text


# --- the rule itself, on parsed responses --------------------------------------------------------


def _wire(
    raw: bytes,
    method: str = "GET",
    cls: type[http.client.HTTPResponse] = http.client.HTTPResponse,
) -> http.client.HTTPResponse:
    """A real parsed ``HTTPResponse`` (or ``cls``) over ``raw``, with no socket involved."""

    class _Sock:
        def makefile(self, *a: object, **k: object) -> io.BytesIO:
            return io.BytesIO(raw)

        def close(self) -> None:
            pass

    resp = cls(_Sock(), method=method)  # type: ignore[arg-type]
    resp.begin()
    return resp


def test_a_bodyless_reply_is_read_as_empty_whatever_its_length_says() -> None:
    """A 304 routinely carries its representation's Content-Length, and http.client reads no body
    for it. Measured by reading, not by the guard's return value alone."""
    raw = b"HTTP/1.1 304 Not Modified\r\nContent-Length: 3\r\nContent-Length: 5\r\n\r\nhello"
    assert read_bounded(_wire(raw), connector="c") == b""
    raw = b"HTTP/1.1 204 No Content\r\nContent-Length: 1_0\r\n\r\nhello"
    assert read_bounded(_wire(raw), connector="c") == b""


def test_a_304_carrying_a_chunked_body_is_refused() -> None:
    """A 304 is non-2xx, so urllib raises it as HTTPError and no connector captures it. The reader
    still sees it on the fault-body path, where http.client would read b"hello" before the fix."""
    raw = b"HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: chunked\r\n\r\n" + _CHUNKS
    with pytest.raises(AmbiguousFramingError):
        read_bounded(_wire(raw), connector="c")


def test_a_reply_to_head_is_read_as_empty_whatever_its_framing_says() -> None:
    both = b"Transfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n" + _CHUNKS
    resp = _wire(_OK + both, method="HEAD")
    assert reply_framing_fault(resp) is None
    assert read_bounded(resp, connector="c") == b""
    assert reply_framing_fault(_wire(_OK + both)) is not None  # the control: the same bytes to GET


def test_a_length_http_client_cannot_parse_is_refused() -> None:
    """Past the int() digit limit (4300 by default) http.client drops the length and reads to
    close. The guard compares digit strings, so it neither raises ValueError itself nor lets the
    unparsed length through."""
    digits = sys.get_int_max_str_digits()
    if digits == 0:
        pytest.skip("int() digit limit disabled in this process; the shape cannot arise")
    raw = _OK + b"Content-Length: " + b"0" * digits + b"5\r\n\r\nhello"
    resp = _wire(raw)
    assert resp.length is None  # the stdlib reading this test depends on
    assert reply_framing_fault(resp) == "a Content-Length the HTTP reader could not use"


def test_a_reader_without_headers_has_no_framing_to_refuse() -> None:
    assert reply_framing_fault(io.BytesIO(b"hello")) is None
    assert read_bounded(io.BytesIO(b"hello"), connector="c") == b"hello"


def test_the_refusal_names_no_header_value() -> None:
    raw = _OK + b"Content-Length: 3\r\nContent-Length: 99999SECRET\r\n\r\nhello"
    with pytest.raises(EgressReplyError) as raised:
        read_bounded(_wire(raw), connector="c")
    assert "SECRET" not in str(raised.value)
    assert "99999" not in str(raised.value)


def test_drain_bounded_does_not_refuse_framing() -> None:
    """A drain discards the body, so which bytes it reads changes nothing. The byte bound still
    holds (tested in test_bounded_egress_reads.py)."""
    drain_bounded(_wire(_AMBIGUOUS["two-lengths-3-and-5"]), connector="c")


def test_the_refusal_is_transient_and_in_the_reply_family() -> None:
    assert issubclass(AmbiguousFramingError, EgressReplyError)
    assert issubclass(AmbiguousFramingError, DeliveryError)
    assert not issubclass(AmbiguousFramingError, NegativeAckError)


def test_a_repeated_chunked_coding_is_named_as_such() -> None:
    """The reason lands on the delivery row, so it must name the fault the peer made."""
    resp = _wire(_AMBIGUOUS["chunked-twice"])
    assert reply_framing_fault(resp) == "the chunked transfer coding applied more than once"


# --- the engine's own OIDC relying party reads the same way ---------------------------------------
#
# Not an outbound connection, but the same stdlib reader on a reply the engine asked for. The token
# leg raises TokenRefusedError, a FlowError: a misframed reply is the endpoint answering, so it
# does not mark the IdP unavailable (BACKLOG #1948, ADR 0142 Amendment E). The JWKS leg raises an
# IdpReplyError, an http.client.HTTPException, which reaches the (OSError, ValueError,
# HTTPException) arm in auth/service.py. A misframed reply is IdpReplyUnusableError, an answer
# that does not mark the IdP; one cut short is IdpReplyCutShortError, a transport failure
# (BACKLOG #3221, ADR 0142 Amendment G). The JWKS leg must NOT raise JwksError: claims.py retypes
# that as ClaimsError("unknown_kid"), a token-verification reject. These tests pin the types; the
# service mapping is pinned in tests/test_oidc_idp_flag_transport_only.py.

_TOKEN_JSON = b'{"id_token": "x.y.z"}'


def _json_reply(headers: bytes) -> bytes:
    return _OK + headers + b"\r\n" + _TOKEN_JSON


def _exchange(url: str) -> object:
    from messagefoundry.auth import oidc

    return oidc.exchange_code(
        token_endpoint=url,
        client_id="c",
        client_auth=None,
        code="x",
        redirect_uri="http://localhost/cb",
        code_verifier="v",
        opener=urllib.request.build_opener(),
    )


def test_oidc_token_exchange_refuses_ambiguous_framing() -> None:
    from messagefoundry.auth import oidc

    raw = _json_reply(b"Content-Length: 3\r\nContent-Length: %d\r\n" % len(_TOKEN_JSON))
    with _serve(raw) as url, pytest.raises(oidc.TokenRefusedError, match="ambiguously") as raised:
        _exchange(url)
    # The endpoint answered (BACKLOG #1948): a status arrived, so this is not a transport failure.
    assert raised.value.status == 200


def test_oidc_token_exchange_reads_unambiguous_framing() -> None:
    raw = _json_reply(b"Content-Length: %d\r\n" % len(_TOKEN_JSON))
    with _serve(raw) as url:
        payload = _exchange(url)
    assert payload == {"id_token": "x.y.z"}


def test_oidc_jwks_fetch_refuses_ambiguous_framing() -> None:
    from messagefoundry.auth.oidc.jwks import JwksError
    from messagefoundry.auth.oidc_http import jwks_fetcher

    raw = _json_reply(b"Transfer-Encoding: gzip\r\nContent-Length: 3\r\n")
    with (
        _serve(raw) as url,
        pytest.raises(IdpReplyUnusableError, match="ambiguously") as raised,
    ):
        jwks_fetcher(url, urllib.request.build_opener())()
    assert not isinstance(raised.value, (JwksError, ValueError))


def test_oidc_jwks_fetch_reads_unambiguous_framing() -> None:
    from messagefoundry.auth.oidc_http import jwks_fetcher

    raw = _json_reply(b"Content-Length: %d\r\n" % len(_TOKEN_JSON))
    with _serve(raw) as url:
        assert jwks_fetcher(url, urllib.request.build_opener())() == _TOKEN_JSON


# --- a header block that did not parse cleanly (BACKLOG #1125, ASVS 4.2.1) -----------------------
#
# http.client hands the header lines to the email parser. At the first line that is not a field
# line, that parser stops, records a defect and keeps every later line as unparsed payload. So a
# framing header after a bad line is silently lost, and the reply is framed by whatever came
# before it.

#: A second, complete response the peer appends. Read to close, it came back inside the body.
_SECOND = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nworld"

#: The code-review probe: under multipart/mixed a CR CR LF hides a Transfer-Encoding, and before the
#: fix read_bounded returned b"5\r\n", raw chunk framing, with no fault. Its control is
#: "crcrlf-hides-chunked" below: the same hiding line with no multipart type.
_MULTIPART_HIDES_CHUNKED = (
    _OK
    + b"Content-Type: multipart/mixed; boundary=b\r\nContent-Length: 3\r\n"
    + b"X-A: a\r\r\nTransfer-Encoding: chunked\r\n--b\r\r\n--b--\r\n\r\n"
    + _CHUNKS
)

_BAD_HEADERS: dict[str, bytes] = {
    # read b"hello" + the whole second response, to close: the Content-Length after the bad line
    # was lost, so nothing framed the body
    "malformed-line-drops-later-length": _OK
    + b"X-Good: 1\r\nNOT A FIELD LINE\r\nContent-Length: 5\r\n\r\nhello"
    + _SECOND,
    # read b"5\r\n": the Transfer-Encoding after the bad line was lost to the Content-Length
    "length-then-bad-line-then-chunked": _OK
    + b"Content-Length: 3\r\nNOT A FIELD LINE\r\nTransfer-Encoding: chunked\r\n\r\n"
    + _CHUNKS,
    # read b"5\r\n": whitespace before the colon made the email parser end the block there
    "space-before-colon": _OK
    + b"Content-Length: 3\r\nTransfer-Encoding : chunked\r\n\r\n"
    + _CHUNKS,
    # read b"hello" to close: a tab before the colon, the same defect
    "tab-before-colon": _OK + b"X-Good: 1\r\nX-Bad\t: 1\r\nContent-Length: 5\r\n\r\nhello",
    # read b"hello": the field with no name was dropped with a defect and nothing else noticed
    "missing-field-name": _OK + b": orphan\r\nContent-Length: 5\r\n\r\nhello",
    # read b"hello": a first line that continues nothing
    "leading-continuation": _OK + b" X-Folded: 1\r\nContent-Length: 5\r\n\r\nhello",
    # read b"hello": a "From " line, which the email parser takes silently as an mbox envelope
    "mbox-envelope-line": _OK + b"From nobody\r\nContent-Length: 5\r\n\r\nhello",
    # read b"hello": a field name that is not an RFC 9110 token
    "name-not-a-token": _OK + b"X(Y): 1\r\nContent-Length: 5\r\n\r\nhello",
    # read b"hello": a "From " line that ENDS the block is pushed back with no defect at all
    "mbox-line-last": _OK + b"Content-Length: 5\r\nFrom nobody\r\n\r\nhello",
    # read b"hello": a NUL inside a field value
    "nul-in-value": _OK + b"X-A: a\x00b\r\nContent-Length: 5\r\n\r\nhello",
    # read b"hello": a DEL inside a field value
    "del-in-value": _OK + b"X-A: a\x7fb\r\nContent-Length: 5\r\n\r\nhello",
    # read b"5\r\nhello\r\n0\r\n\r\n" to close: CR CR LF read as the blank line that ends the
    # block, so the Transfer-Encoding after it was lost, with no defect recorded
    "crcrlf-hides-chunked": _OK + b"X-A: a\r\r\nTransfer-Encoding: chunked\r\n\r\n" + _CHUNKS,
    # the same, under message/rfc822: the lost lines were parsed as a nested message
    "message-type-hides-chunked": _OK
    + b"Content-Type: message/rfc822\r\nX-A: a\r\r\nTransfer-Encoding: chunked\r\n\r\n"
    + _CHUNKS,
    # read b"helloEXTRA": a hidden Content-Length under message/http
    "message-type-hides-length": _OK
    + b"Content-Type: message/http\r\nX-A: a\r\r\nContent-Length: 5\r\n\r\nhelloEXTRA",
    # read b"hello": a closing "From " line under message/rfc822 became the nested envelope
    "message-type-mbox-line-last": _OK
    + b"Content-Type: message/rfc822\r\nContent-Length: 5\r\nFrom nobody\r\n\r\nhello",
    # read b"5\r\n": under multipart/* the lost lines land in the MIME preamble, parts and epilogue,
    # which the first cut of this check never looked at (code-review finding, BACKLOG #1125)
    "multipart-type-hides-chunked": _MULTIPART_HIDES_CHUNKED,
    # read b"5\r\n": the hidden line is the whole of the multipart body, with no boundary at all
    "multipart-body-hides-chunked": _OK
    + b"Content-Type: multipart/mixed; boundary=b\r\nContent-Length: 3\r\n"
    + b"X-A: a\r\r\nTransfer-Encoding: chunked\r\n\r\n"
    + _CHUNKS,
    # read b"5\r\n": the hidden line sits after the close boundary, in the epilogue
    "multipart-epilogue-hides-chunked": _OK
    + b"Content-Type: multipart/mixed; boundary=b\r\nContent-Length: 3\r\n"
    + b"X-A: a\r\r\n--b\r\n\r\n--b--\r\nTransfer-Encoding: chunked\r\n\r\n"
    + _CHUNKS,
    # read b"5\r\n": under MTOM's multipart/related, the hidden line opens a part never closed
    "multipart-related-part-hides-chunked": _OK
    + b"Content-Type: multipart/related; boundary=b\r\nContent-Length: 3\r\n"
    + b"X-A: a\r\r\n--b\r\nTransfer-Encoding: chunked\r\n\r\n"
    + _CHUNKS,
}

#: Header blocks that are legal, though the email parser records defects or nests parts for them.
_HEADER_CONTROLS: dict[str, bytes] = {
    "multipart-related-mtom": _OK
    + b'Content-Type: multipart/related; type="application/xop+xml"; boundary=abc\r\n'
    + b"Content-Length: 5\r\n\r\nhello",
    "multipart-no-boundary": _OK
    + b"Content-Type: multipart/mixed\r\nContent-Length: 5\r\n\r\nhello",
    "message-rfc822": _OK + b"Content-Type: message/rfc822\r\nContent-Length: 5\r\n\r\nhello",
    "obs-fold": _OK + b"X-Folded: a\r\n b\r\nContent-Length: 5\r\n\r\nhello",
    "obs-text-value": _OK + b"X-A: caf\xe9\tb\r\nContent-Length: 5\r\n\r\nhello",
    # The email parser records a defect for this pair, but every header line is a field line.
    # Refused before the header check compared parse trees; read since.
    "multipart-with-transfer-encoding-field": _OK
    + b"Content-Type: multipart/related; boundary=x\r\nContent-Transfer-Encoding: base64\r\n"
    + b"Content-Length: 5\r\n\r\nhello",
}

#: A SOAP-with-MTOM reply as a partner would send it: multipart/related with the XOP parameters, a
#: root part and one attachment, in the body. The header check must pass it, and the body must come
#: back whole, under either framing.
_MTOM_BODY = (
    b"--uuid:mf-1\r\n"
    b'Content-Type: application/xop+xml; charset=UTF-8; type="text/xml"\r\n'
    b"Content-Transfer-Encoding: binary\r\n"
    b"Content-ID: <root.message@example.test>\r\n\r\n"
    b'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>'
    b'<r><xop:Include xmlns:xop="http://www.w3.org/2004/08/xop/include" href="cid:a1"/></r>'
    b"</soap:Body></soap:Envelope>\r\n"
    b"--uuid:mf-1\r\n"
    b"Content-Type: application/octet-stream\r\n"
    b"Content-Transfer-Encoding: binary\r\n"
    b"Content-ID: <a1>\r\n\r\n"
    b"MSH|^~\\&|SYNTHETIC\r\n"
    b"--uuid:mf-1--\r\n"
)
_MTOM_TYPE = (
    b'Content-Type: multipart/related; type="application/xop+xml"; boundary="uuid:mf-1"; '
    b'start="<root.message@example.test>"; start-info="text/xml"\r\n'
)


def _chunked(body: bytes) -> bytes:
    return b"%x\r\n" % len(body) + body + b"\r\n0\r\n\r\n"


@pytest.mark.parametrize("framing", ["length", "chunked"])
def test_a_legitimate_mtom_reply_still_reads_whole(framing: str) -> None:
    if framing == "length":
        raw = _OK + _MTOM_TYPE + b"Content-Length: %d\r\n\r\n" % len(_MTOM_BODY) + _MTOM_BODY
    else:
        raw = _OK + _MTOM_TYPE + b"Transfer-Encoding: chunked\r\n\r\n" + _chunked(_MTOM_BODY)
    assert reply_framing_fault(_wire(raw)) is None
    with _serve(raw) as url, _open(url) as resp:
        assert read_bounded(resp, connector="c") == _MTOM_BODY


def test_a_multipart_type_does_not_hide_a_lost_header_line() -> None:
    """The code-review probe and its control. Before the fix the multipart form returned b"5\\r\\n"
    with no fault, while the same hiding line with no multipart type was already refused."""
    for raw in (_MULTIPART_HIDES_CHUNKED, _BAD_HEADERS["crcrlf-hides-chunked"]):
        fault = reply_framing_fault(_wire(raw))
        assert fault is not None
        assert "header" in fault
        with pytest.raises(AmbiguousFramingError):
            read_bounded(_wire(raw), connector="c")


def test_a_code_built_multipart_header_block_is_not_refused() -> None:
    """A Message built in code has no parsed body, so no line can be lost in it. Re-parsing its
    multipart type would add body-structure defects it never had, and refuse a clean block."""

    class _Built:
        status = 200

        def __init__(self) -> None:
            self.headers = email.message.Message()
            self.headers["Content-Type"] = "multipart/related; boundary=b"
            self.headers["Content-Length"] = "5"

    assert reply_framing_fault(_Built()) is None


def test_the_framing_error_survives_pickle_and_copy() -> None:
    """``reason`` is keyword-only and not in ``args``, so the default exception reduce could not
    rebuild it. A copy or a cross-process hop must keep both the message and the reason."""
    original = AmbiguousFramingError("c framed its body ambiguously", reason="a fixed reason")
    for clone in (
        pickle.loads(pickle.dumps(original)),
        copy.copy(original),
        copy.deepcopy(original),
    ):
        assert type(clone) is AmbiguousFramingError
        assert str(clone) == str(original)
        assert clone.reason == "a fixed reason"
        assert clone.args == original.args


@pytest.mark.parametrize("shape", list(_HEADER_CONTROLS), ids=list(_HEADER_CONTROLS))
def test_read_bounded_reads_a_legal_header_block(shape: str) -> None:
    with _serve(_HEADER_CONTROLS[shape]) as url, _open(url) as resp:
        assert read_bounded(resp, connector="c") == b"hello"


@pytest.mark.parametrize("shape", list(_HEADER_CONTROLS), ids=list(_HEADER_CONTROLS))
def test_soap_captured_reply_reads_a_legal_header_block(shape: str) -> None:
    with _serve(_HEADER_CONTROLS[shape]) as url:
        reply = asyncio.run(_soap(url).send("<soap:Envelope/>"))
    assert reply is not None
    assert reply.body == "hello"


def _assert_header_refusal(exc: BaseException) -> None:
    _assert_framing_refusal(exc)
    assert "header" in str(exc)


@pytest.mark.parametrize("shape", list(_BAD_HEADERS), ids=list(_BAD_HEADERS))
def test_read_bounded_refuses_a_header_block_that_did_not_parse(shape: str) -> None:
    with (
        _serve(_BAD_HEADERS[shape]) as url,
        _open(url) as resp,
        pytest.raises(EgressReplyError) as raised,
    ):
        read_bounded(resp, connector="c")
    _assert_header_refusal(raised.value)


@pytest.mark.parametrize("shape", list(_BAD_HEADERS), ids=list(_BAD_HEADERS))
def test_soap_captured_reply_refuses_a_header_block_that_did_not_parse(shape: str) -> None:
    with _serve(_BAD_HEADERS[shape]) as url:
        dest = _soap(url)
        with pytest.raises(DeliveryError) as raised:
            asyncio.run(dest.send("<soap:Envelope/>"))
    _assert_captured_2xx_refusal(raised.value)
    assert "header" in str(raised.value)


@pytest.mark.parametrize("shape", list(_BAD_HEADERS), ids=list(_BAD_HEADERS))
def test_rest_reply_refuses_a_header_block_that_did_not_parse(shape: str) -> None:
    with _serve(_BAD_HEADERS[shape]) as url:
        dest = _rest(url)
        with pytest.raises(DeliveryError) as raised:
            asyncio.run(dest.send('{"a": 1}'))
    _assert_captured_2xx_refusal(raised.value)
    assert "header" in str(raised.value)


def test_a_header_defect_is_refused_even_on_a_bodyless_reply() -> None:
    """The defect check comes before the bodyless and HEAD exemptions: a header block that did not
    parse is untrustworthy whatever the status."""
    raw = b"HTTP/1.1 204 No Content\r\nNOT A FIELD LINE\r\n\r\n"
    assert reply_framing_fault(_wire(raw)) is not None
    assert reply_framing_fault(_wire(_BAD_HEADERS["space-before-colon"], method="HEAD")) is not None


# --- the chunked body grammar (BACKLOG #1979 and #1125) ------------------------------------------
#
# http.client parses a chunk-size line with int(line, 16) and tosses two bytes after each chunk's
# data without looking at them. RFC 9112 section 7.1 allows 1*HEXDIG, an optional extension after
# ";", and CRLF at the end of each line and after each chunk's data.

_TE = _OK + b"Transfer-Encoding: chunked\r\n\r\n"

_BAD_CHUNKS: dict[str, bytes] = {
    # read 16 bytes, b"hellohellohello!": int() accepts the underscore
    "size-1_0": _TE + b"1_0\r\nhellohellohello!\r\n0\r\n\r\n",
    # read b"hello": int(x, 16) accepts the 0x prefix
    "size-0x5": _TE + b"0x5\r\nhello\r\n0\r\n\r\n",
    # read b"hello": int() accepts the sign
    "size-plus-5": _TE + b"+5\r\nhello\r\n0\r\n\r\n",
    # read b"hello": int() strips surrounding whitespace
    "size-leading-space": _TE + b" 5\r\nhello\r\n0\r\n\r\n",
    "size-trailing-space": _TE + b"5 \r\nhello\r\n0\r\n\r\n",
    # read b"hello": a negative zero ended the body
    "last-chunk-minus-0": _TE + b"5\r\nhello\r\n-0\r\n\r\n",
    # read b"hello": a bare LF ended the size line
    "size-line-bare-lf": _TE + b"5\nhello\r\n0\r\n\r\n",
    # read b"hello": bare LFs ended the last chunk and the trailer section
    "last-chunk-bare-lf": _TE + b"5\r\nhello\r\n0\n\n",
    # read b"hello": the two bytes after the data were tossed unread
    "no-crlf-after-data": _TE + b"5\r\nhelloXY0\r\n\r\n",
    # read b"hello": a bare CR inside the size line
    "size-line-bare-cr": _TE + b"5\r;x\r\nhello\r\n0\r\n\r\n",
    # IncompleteRead, but only AFTER buffering to end of stream: _safe_read(-5) calls fp.read(-5)
    "negative-size": _TE + b"-5\r\n" + b"A" * 20_000,
    # read b"hello": a trailer line that is not a field line was discarded unread
    "trailer-not-a-field": _TE + b"5\r\nhello\r\n0\r\nnot a field\r\n\r\n",
    # read b"hello": a fold with no field line before it
    "trailer-fold-first": _TE + b"5\r\nhello\r\n0\r\n b\r\n\r\n",
    # A byte from 0x80 up is not a hex digit, even where latin-1 decodes it to a letter or a digit
    # sign. The grammar matches decoded lines, so these pin that the decode widens nothing.
    "size-high-byte": _TE + b"5\xb5\r\nhello\r\n0\r\n\r\n",
    "extension-name-high-byte": _TE + b"5;n\xe9=1\r\nhello\r\n0\r\n\r\n",
}

#: Chunked framings that are legal and must still read as b"hello".
_CHUNK_CONTROLS: dict[str, bytes] = {
    "plain": _TE + _CHUNKS,
    "two-chunks": _TE + b"2\r\nhe\r\n3\r\nllo\r\n0\r\n\r\n",
    "extension": _TE + b"5;name=value\r\nhello\r\n0\r\n\r\n",
    "extension-quoted": _TE + b'5 ; n="a \\" b"; flag\r\nhello\r\n0;done\r\n\r\n',
    "leading-zeros": _TE + b"0005\r\nhello\r\n000\r\n\r\n",
    "trailer-section": _TE + b"5\r\nhello\r\n0\r\nX-Checksum: abc\r\nX-Other: 1\r\n\r\n",
    "trailer-folded": _TE + b"5\r\nhello\r\n0\r\nX-A: 1\r\n b\r\n\r\n",
    # obs-text, bytes 0x80 to 0xFF, is legal in a quoted extension value and in a trailer value.
    # A decode other than latin-1 would raise on these or stop matching them.
    "extension-quoted-obs-text": _TE + b'5;n="caf\xe9 \xff"\r\nhello\r\n0\r\n\r\n',
    "trailer-obs-text": _TE + b"5\r\nhello\r\n0\r\nX-A: caf\xe9\xff\r\n\r\n",
    # A ";" inside a quoted value starts no new extension. The possessive group relies on that.
    "extension-quoted-semicolon": _TE + b'5;n="a;b";m=1\r\nhello\r\n0\r\n\r\n',
}


def _wire_counted(raw: bytes, method: str = "GET") -> tuple[http.client.HTTPResponse, io.BytesIO]:
    """``_wire``, also returning the stream so a test can measure how far the reader consumed it.

    The stream ignores ``close()``, because both readers close it at the end of the body and a
    closed ``BytesIO`` cannot report its position."""

    class _Stream(io.BytesIO):
        def close(self) -> None:
            pass

    stream = _Stream(raw)

    class _Sock:
        def makefile(self, *a: object, **k: object) -> io.BytesIO:
            return stream

        def close(self) -> None:
            pass

    resp = http.client.HTTPResponse(_Sock(), method=method)  # type: ignore[arg-type]
    resp.begin()
    return resp, stream


@pytest.mark.parametrize("shape", list(_BAD_CHUNKS), ids=list(_BAD_CHUNKS))
def test_read_bounded_refuses_malformed_chunk_framing(shape: str) -> None:
    with (
        _serve(_BAD_CHUNKS[shape]) as url,
        _open(url) as resp,
        pytest.raises(EgressReplyError) as raised,
    ):
        read_bounded(resp, limit=1000, connector="c")
    _assert_framing_refusal(raised.value)


@pytest.mark.parametrize("shape", list(_CHUNK_CONTROLS), ids=list(_CHUNK_CONTROLS))
def test_read_bounded_reads_legal_chunk_framing(shape: str) -> None:
    with _serve(_CHUNK_CONTROLS[shape]) as url, _open(url) as resp:
        assert read_bounded(resp, connector="c") == b"hello"


@pytest.mark.parametrize("size", [b"1A", b"1a", b"01A"])
def test_hex_chunk_sizes_read_in_either_case(size: bytes) -> None:
    alphabet = b"abcdefghijklmnopqrstuvwxyz"
    raw = _TE + size + b"\r\n" + alphabet + b"\r\n0\r\n\r\n"
    with _serve(raw) as url, _open(url) as resp:
        assert read_bounded(resp, connector="c") == alphabet


def test_a_negative_chunk_size_cannot_get_past_the_byte_bound() -> None:
    """BACKLOG #1979, measured on the stream rather than on the return value: before the fix the
    reader consumed all 200,000 bytes behind a 1,000-byte limit, then raised a truncation."""
    raw = _TE + b"-5\r\n" + b"A" * 200_000
    resp, stream = _wire_counted(raw)
    with pytest.raises(AmbiguousFramingError):
        read_bounded(resp, limit=1000, connector="c")
    assert stream.tell() <= len(_TE) + 4


def test_a_huge_chunk_size_is_still_cut_at_the_bound() -> None:
    raw = _TE + b"FFFFFFFFFFFF\r\n" + b"A" * 200_000
    resp, stream = _wire_counted(raw)
    with pytest.raises(ResponseTooLargeError):
        read_bounded(resp, limit=1000, connector="c")
    assert stream.tell() <= len(_TE) + 14 + 1001


def test_a_chunked_body_cut_mid_chunk_is_still_a_truncation() -> None:
    with pytest.raises(TruncatedResponseError, match="part-way through the response body"):
        read_bounded(_wire(_TE + b"50\r\nhello"), connector="c")


def test_a_chunked_body_with_no_last_chunk_is_a_truncation() -> None:
    with pytest.raises(TruncatedResponseError):
        read_bounded(_wire(_TE + b"5\r\nhello\r\n"), connector="c")


def test_a_chunked_body_ending_cleanly_after_its_last_chunk_still_reads() -> None:
    """http.client accepts a stream that ends after the last chunk with no final CRLF, because some
    servers send it. Which bytes are the body is settled by then, so refusing would only turn a
    delivered POST into a retry. A trailer line cut part-way is still a truncation."""
    assert read_bounded(_wire(_TE + b"5\r\nhello\r\n0\r\n"), connector="c") == b"hello"
    raw = _TE + b"5\r\nhello\r\n0\r\nX-T: 1\r\n"
    assert read_bounded(_wire(raw), connector="c") == b"hello"
    with pytest.raises(TruncatedResponseError):
        read_bounded(_wire(_TE + b"5\r\nhello\r\n0\r\nX-T"), connector="c")


def test_the_chunk_refusal_names_no_body_or_line_bytes() -> None:
    with pytest.raises(EgressReplyError) as raised:
        read_bounded(_wire(_TE + b"SECRET\r\nhello\r\n0\r\n\r\n"), connector="c")
    assert "SECRET" not in str(raised.value)


@pytest.mark.parametrize("shape", list(_BAD_CHUNKS), ids=list(_BAD_CHUNKS))
def test_soap_captured_reply_refuses_malformed_chunk_framing(shape: str) -> None:
    with _serve(_BAD_CHUNKS[shape]) as url:
        dest = _soap(url)
        with pytest.raises(DeliveryError) as raised:
            asyncio.run(dest.send("<soap:Envelope/>"))
    _assert_captured_2xx_refusal(raised.value)


@pytest.mark.parametrize("shape", list(_BAD_CHUNKS), ids=list(_BAD_CHUNKS))
def test_rest_reply_refuses_malformed_chunk_framing(shape: str) -> None:
    with _serve(_BAD_CHUNKS[shape]) as url:
        dest = _rest(url)
        with pytest.raises(DeliveryError) as raised:
            asyncio.run(dest.send('{"a": 1}'))
    _assert_captured_2xx_refusal(raised.value)


@pytest.mark.parametrize("shape", list(_CHUNK_CONTROLS), ids=list(_CHUNK_CONTROLS))
def test_soap_captured_reply_reads_legal_chunk_framing(shape: str) -> None:
    with _serve(_CHUNK_CONTROLS[shape]) as url:
        reply = asyncio.run(_soap(url).send("<soap:Envelope/>"))
    assert reply is not None
    assert reply.body == "hello"


def test_a_malformed_chunked_fault_body_is_classified_on_status(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The non-2xx path reads through the same helper, so the grammar reaches a fault body too."""
    raw = b"HTTP/1.1 500 Internal Server Error\r\nTransfer-Encoding: chunked\r\n\r\n-5\r\n"
    with (
        _serve(raw + b"A" * 2000) as url,
        caplog.at_level(logging.WARNING),
        pytest.raises(DeliveryError) as raised,
    ):
        asyncio.run(_soap(url).send("<soap:Envelope/>"))
    assert type(raised.value) is DeliveryError
    assert "HTTP 500" in str(raised.value)
    assert "could not read whole" in caplog.text


# --- a drain keeps the bound on a malformed chunked body, and records where it stopped ------------


@pytest.mark.parametrize("shape", list(_BAD_CHUNKS), ids=list(_BAD_CHUNKS))
def test_drain_bounded_stops_at_malformed_chunk_framing(
    shape: str, caplog: pytest.LogCaptureFixture
) -> None:
    """A drain refuses nothing, but it stops at a line it cannot parse, and logs that it stopped
    rather than stopping silently."""
    raw = _BAD_CHUNKS[shape]
    resp, stream = _wire_counted(raw)
    with caplog.at_level(logging.WARNING):
        drain_bounded(resp, limit=1000, connector="https://h.example.test/p?token=SECRET")
    assert stream.tell() <= min(len(raw), len(_TE) + 40)
    assert "The reply to a GET request had a malformed body (status 200, " in caplog.text
    assert "is not failed" in caplog.text
    assert "refusing" not in caplog.text
    # The connector is built from configuration, so the WARNING leaves it out entirely.
    assert "h.example.test" not in caplog.text
    assert "SECRET" not in caplog.text


def test_the_drain_warning_names_only_a_known_method(caplog: pytest.LogCaptureFixture) -> None:
    """A method outside the allow-list is logged as "HTTP", so the line holds only module text."""
    resp, _stream = _wire_counted(_BAD_CHUNKS["size-0x5"], method="X-SECRET-VERB")
    with caplog.at_level(logging.WARNING):
        drain_bounded(resp, limit=1000, connector="c")
    assert "The reply to a HTTP request had a malformed body (status 200, " in caplog.text
    assert "SECRET" not in caplog.text


@pytest.mark.parametrize("shape", list(_CHUNK_CONTROLS), ids=list(_CHUNK_CONTROLS))
def test_drain_bounded_reads_legal_chunk_framing_quietly(
    shape: str, caplog: pytest.LogCaptureFixture
) -> None:
    resp, stream = _wire_counted(_CHUNK_CONTROLS[shape])
    with caplog.at_level(logging.WARNING):
        drain_bounded(resp, connector="c")
    assert stream.tell() == len(_CHUNK_CONTROLS[shape])
    assert caplog.text == ""


def test_a_drain_of_a_bodyless_chunked_reply_reads_nothing() -> None:
    """A 204 has no body (RFC 9112 section 6.3), so a drain must not wait on one."""
    raw = b"HTTP/1.1 204 No Content\r\nTransfer-Encoding: chunked\r\n\r\n" + _CHUNKS
    resp, stream = _wire_counted(raw)
    drain_bounded(resp, connector="c")
    assert stream.tell() == raw.index(_CHUNKS)


# --- the OIDC reads share the grammar ------------------------------------------------------------


def _chunked_json(size_line: bytes) -> bytes:
    return _TE + size_line + b"\r\n" + _TOKEN_JSON + b"\r\n0\r\n\r\n"


#: The legal size line for _TOKEN_JSON: hex digits and nothing else.
_PLAIN_SIZE = b"%x" % len(_TOKEN_JSON)

_OIDC_BAD: dict[str, bytes] = {
    "negative-size": _TE + b"-5\r\n" + b"A" * 20_000,
    "size-0x": _chunked_json(b"0x%x" % len(_TOKEN_JSON)),
    "size-underscore": _chunked_json(b"1_5"),
    # int() accepts the sign, so http.client alone reads this reply whole and at the right length
    "size-plus": _chunked_json(b"+" + _PLAIN_SIZE),
    "header-defect": _OK
    + b"Content-Length: 3\r\nTransfer-Encoding : chunked\r\n\r\n"
    + _chunked_json(b"%x" % len(_TOKEN_JSON))[len(_TE) :],
}


@pytest.mark.parametrize("shape", list(_OIDC_BAD), ids=list(_OIDC_BAD))
def test_oidc_token_exchange_refuses_malformed_framing(shape: str) -> None:
    from messagefoundry.auth import oidc

    # A reply arrived, so the endpoint answered and this must not mark the IdP (BACKLOG #1948).
    with (
        _serve(_OIDC_BAD[shape]) as url,
        pytest.raises(oidc.TokenRefusedError, match="ambiguously"),
    ):
        _exchange(url)


@pytest.mark.parametrize("shape", list(_OIDC_BAD), ids=list(_OIDC_BAD))
def test_oidc_jwks_fetch_refuses_malformed_framing(shape: str) -> None:
    from messagefoundry.auth.oidc.jwks import JwksError
    from messagefoundry.auth.oidc_http import jwks_fetcher

    with (
        _serve(_OIDC_BAD[shape]) as url,
        pytest.raises(IdpReplyUnusableError, match="ambiguously") as raised,
    ):
        jwks_fetcher(url, urllib.request.build_opener())()
    assert not isinstance(raised.value, (JwksError, ValueError))


#: Legal size lines for the OIDC reads. "plain" is the plain chunked control BACKLOG #1979 asks
#: for. It differs from the "size-plus" arm of _OIDC_BAD by the sign alone.
_OIDC_LEGAL_SIZES: dict[str, bytes] = {
    "plain": _PLAIN_SIZE,
    "extension": b"%X;ext=1" % len(_TOKEN_JSON),
}


@pytest.mark.parametrize("shape", list(_OIDC_LEGAL_SIZES), ids=list(_OIDC_LEGAL_SIZES))
def test_oidc_reads_legal_chunk_framing(shape: str) -> None:
    from messagefoundry.auth.oidc_http import jwks_fetcher

    raw = _chunked_json(_OIDC_LEGAL_SIZES[shape])
    with _serve(raw) as url:
        assert _exchange(url) == {"id_token": "x.y.z"}
    with _serve(raw) as url:
        assert jwks_fetcher(url, urllib.request.build_opener())() == _TOKEN_JSON


def test_oidc_token_exchange_maps_a_cut_chunked_body_to_flow_error() -> None:
    """Before the fix, http.client's IncompleteRead escaped exchange_code unmapped."""
    from messagefoundry.auth import oidc

    # Cut short is a transport failure, the one outcome that may mark the IdP (BACKLOG #1948).
    with (
        _serve(_TE + b"50\r\n" + _TOKEN_JSON) as url,
        pytest.raises(oidc.TokenEndpointUnreachableError),
    ):
        _exchange(url)


def test_oidc_token_exchange_refuses_a_body_short_of_its_content_length() -> None:
    """The token read goes through read_bounded, so it gets the declared-length check too. Before,
    the short body reached json.loads and failed there, or parsed if the cut fell after a brace."""
    from messagefoundry.auth import oidc

    raw = _json_reply(b"Content-Length: %d\r\n" % (len(_TOKEN_JSON) + 40))
    with _serve(raw) as url, pytest.raises(oidc.TokenEndpointUnreachableError, match="part-way"):
        _exchange(url)


def test_oidc_jwks_fetch_refuses_a_body_short_of_its_content_length() -> None:
    """Before, the fragment reached JwksCache as invalid JSON, and the login was audited as an
    unknown key rather than an unavailable IdP."""
    from messagefoundry.auth.oidc_http import jwks_fetcher

    raw = _json_reply(b"Content-Length: %d\r\n" % (len(_TOKEN_JSON) + 40))
    with _serve(raw) as url, pytest.raises(IdpReplyCutShortError, match="declared length"):
        jwks_fetcher(url, urllib.request.build_opener())()


def test_oidc_jwks_fetch_reads_a_chunked_body_cut_short_as_cut_short() -> None:
    """BACKLOG #3221: a chunked JWKS body cut mid-chunk is a transport failure, as on the token
    leg, so it must not fall to the family arm and read as an unusable answer."""
    from messagefoundry.auth.oidc_http import jwks_fetcher

    raw = _OK + b"Transfer-Encoding: chunked\r\n\r\n50\r\nhello"
    with _serve(raw) as url, pytest.raises(IdpReplyCutShortError, match="cut short"):
        jwks_fetcher(url, urllib.request.build_opener())()


def test_both_oidc_reads_retype_the_whole_refusal_family(monkeypatch: pytest.MonkeyPatch) -> None:
    """A refusal added to bounded_read later must still land on FlowError or HTTPException. Caught
    by member instead of by family, it would escape the login as an unhandled DeliveryError."""
    from messagefoundry.auth import oidc, oidc_http
    from messagefoundry.transports import bounded_read

    def refuse(*_a: object, **_k: object) -> bytes:
        raise EgressReplyError("a future sibling")

    monkeypatch.setattr(bounded_read, "read_bounded", refuse)
    monkeypatch.setattr(oidc_http, "read_reply_body", refuse)
    raw = _json_reply(b"Content-Length: %d\r\n" % len(_TOKEN_JSON))
    with _serve(raw) as url, pytest.raises(oidc.FlowError):
        _exchange(url)
    with _serve(raw) as url, pytest.raises(IdpReplyUnusableError):
        oidc_http.jwks_fetcher(url, urllib.request.build_opener())()


# --- a bare CR in the reply head (BACKLOG #2052, ASVS 4.2.1) -------------------------------------
#
# http.client reads each head line up to LF, and the email parser then breaks a line at a lone CR
# as well. So the shapes below reach the engine as extra fields, with nothing in the parse tree for
# reply_framing_fault to see. A proxy that treats the CR as invalid, or as a space, sees one field.
# StrictHTTPResponse refuses them while the head is read, on every opener build_strict_opener makes.

#: Each shape, and what the engine read as the body before the fix.
_BARE_CR: dict[str, bytes] = {
    # read b"hello": the CR made a Content-Length the proxy never saw, and EXTRA was cut off
    "cr-hides-length": _OK + b"X-A: a\rContent-Length: 5\r\n\r\nhelloEXTRA",
    # read b"hello": the same, with the CR in the first field of the block
    "cr-in-first-field": _OK + b"Via: p\rContent-Length: 5\r\nX-B: b\r\n\r\nhelloEXTRA",
    # read b"hello": a CR in the status line's reason phrase
    "cr-in-reason-phrase": b"HTTP/1.1 200 O\rK\r\nContent-Length: 5\r\n\r\nhello",
    # read b"hello": a CR in the head of an interim 100 reply, which http.client reads and skips
    "cr-in-interim-head": b"HTTP/1.1 100 Continue\r\nX-A: a\rb\r\n\r\n"
    + _OK
    + b"Content-Length: 5\r\n\r\nhello",
    # refused after the parse since #1125; now refused while the head is read
    "cr-cr-lf": _OK + b"X-A: a\r\r\nContent-Length: 5\r\n\r\nhello",
}

#: Heads with no bare CR, which must still read as b"hello" through a strict opener.
_STRICT_CONTROLS: dict[str, bytes] = {
    **_CONTROLS,
    **_HEADER_CONTROLS,
    # RFC 9112 section 2.2 lets a recipient take a bare LF as the line end, and http.client does.
    "bare-lf-line-ends": b"HTTP/1.1 200 OK\nContent-Length: 5\n\nhello",
    "clean-interim-head": b"HTTP/1.1 100 Continue\r\n\r\n"
    + _OK
    + b"Content-Length: 5\r\n\r\nhello",
}


def _strict_open(url: str) -> http.client.HTTPResponse:
    resp = build_strict_opener().open(url, timeout=5)
    assert isinstance(resp, http.client.HTTPResponse)
    return resp


def _assert_bare_cr_refusal(exc: BaseException) -> None:
    assert isinstance(exc, MalformedReplyHeadError)
    _assert_header_refusal(exc)
    assert exc.reason == "a bare CR in the reply's status line or header block"


def test_the_stock_reader_does_not_see_a_bare_cr() -> None:
    """The control: without the strict class, the lead shape reads clean and returns the wrong
    body. If http.client ever starts refusing it, this goes red and the class can be reviewed."""
    resp = _wire(_BARE_CR["cr-hides-length"])
    assert reply_framing_fault(resp) is None
    assert read_bounded(resp, connector="c") == b"hello"


@pytest.mark.parametrize("shape", list(_BARE_CR), ids=list(_BARE_CR))
def test_a_strict_opener_refuses_a_bare_cr_in_the_head(shape: str) -> None:
    with _serve(_BARE_CR[shape]) as url, pytest.raises(MalformedReplyHeadError) as raised:
        _strict_open(url)
    _assert_bare_cr_refusal(raised.value)


@pytest.mark.parametrize("shape", list(_STRICT_CONTROLS), ids=list(_STRICT_CONTROLS))
def test_a_strict_opener_reads_a_head_with_no_bare_cr(shape: str) -> None:
    with _serve(_STRICT_CONTROLS[shape]) as url, _strict_open(url) as resp:
        assert read_bounded(resp, connector="c") == b"hello"


@pytest.mark.parametrize("shape", list(_BARE_CR), ids=list(_BARE_CR))
def test_rest_reply_refuses_a_bare_cr_in_the_head(shape: str) -> None:
    with _serve(_BARE_CR[shape]) as url:
        dest = _rest(url)
        with pytest.raises(DeliveryError) as raised:
            asyncio.run(dest.send('{"a": 1}'))
    _assert_bare_cr_refusal(raised.value)
    assert not isinstance(raised.value, NegativeAckError)


@pytest.mark.parametrize("shape", list(_BARE_CR), ids=list(_BARE_CR))
def test_soap_captured_reply_refuses_a_bare_cr_in_the_head(shape: str) -> None:
    with _serve(_BARE_CR[shape]) as url:
        dest = _soap(url)
        with pytest.raises(DeliveryError) as raised:
            asyncio.run(dest.send("<soap:Envelope/>"))
    _assert_bare_cr_refusal(raised.value)


def test_the_connection_tests_keep_the_bare_cr_refusal_as_it_is() -> None:
    """``MalformedReplyHeadError`` is an ``HTTPException`` too, and BACKLOG #2058 gave the REST and
    FHIR probes an ``HTTPException`` arm. The refusal must pass through that arm unchanged, reason
    and all, rather than be retyped as a plain malformed-reply ``DeliveryError``."""
    for build in (_rest, _fhir):
        with _serve(_BARE_CR["cr-hides-length"]) as url:
            dest = build(url)
            with pytest.raises(DeliveryError) as raised:
                asyncio.run(dest.test_connection())
        _assert_bare_cr_refusal(raised.value)


def test_a_fhir_delivery_keeps_the_bare_cr_refusal_as_it_is() -> None:
    with _serve(_BARE_CR["cr-hides-length"]) as url:
        dest = _fhir(url)
        with pytest.raises(DeliveryError) as raised:
            asyncio.run(dest.send('{"resourceType": "Patient"}'))
    _assert_bare_cr_refusal(raised.value)


def test_a_bare_cr_on_a_non_2xx_reply_is_refused_not_classified() -> None:
    """The status code sits in the refused head, so the delivery fails on the head, not the code."""
    raw = b"HTTP/1.1 500 Internal Server Error\r\nX-A: a\rContent-Length: 5\r\n\r\nhello"
    with _serve(raw) as url:
        dest = _rest(url)
        with pytest.raises(DeliveryError) as raised:
            asyncio.run(dest.send('{"a": 1}'))
    _assert_bare_cr_refusal(raised.value)


def test_the_bare_cr_refusal_names_no_head_bytes() -> None:
    raw = _OK + b"X-Secret: SECRET\rContent-Length: 5\r\n\r\nhello"
    with pytest.raises(MalformedReplyHeadError) as raised:
        _wire(raw, cls=StrictHTTPResponse)
    assert "SECRET" not in str(raised.value)


def test_an_over_long_head_line_is_still_refused_as_too_long() -> None:
    """A line cut at http.client's size limit can end in the CR of its own CRLF. That is a line
    that is too long, not a bare CR, so the stock refusal must still be the one raised."""
    raw = _OK + b"X-A: " + b"a" * (65536 - len(b"X-A: ")) + b"\r\nContent-Length: 5\r\n\r\nhello"
    with pytest.raises(http.client.LineTooLong):
        _wire(raw, cls=StrictHTTPResponse)


def test_the_body_is_read_from_the_real_stream_after_the_head() -> None:
    """Only the head is guarded. A CR inside the body is the body's business."""
    resp = _wire(_OK + b"Content-Length: 5\r\n\r\nhe\rlo", cls=StrictHTTPResponse)
    assert isinstance(resp.fp, io.BytesIO)
    assert read_bounded(resp, connector="c") == b"he\rlo"


def test_the_bare_cr_refusal_is_both_a_framing_error_and_an_http_exception() -> None:
    """A framing error, so a connector's EgressReplyError arm takes it. An HTTPException, so the
    OIDC JWKS leg's caller, which maps only http.client's own faults, takes it too."""
    assert issubclass(MalformedReplyHeadError, AmbiguousFramingError)
    assert issubclass(MalformedReplyHeadError, http.client.HTTPException)
    assert not issubclass(MalformedReplyHeadError, NegativeAckError)
    original = MalformedReplyHeadError("m", reason="r")
    clone = pickle.loads(pickle.dumps(original))
    assert type(clone) is MalformedReplyHeadError
    assert clone.reason == "r"


def _token_provider(which: str, url: str) -> object:
    """One of the two bearer-token providers, pointed at ``url``, on its own shipped opener."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    from messagefoundry.config.models import SignatureAlgorithm
    from messagefoundry.transports.http_auth import OAuth2ClientCredentialsProvider
    from messagefoundry.transports.smart import SmartBackendTokenProvider

    if which == "oauth2":
        return OAuth2ClientCredentialsProvider(token_url=url, client_id="c", client_secret="s")
    key = (
        ec.generate_private_key(ec.SECP384R1())
        .private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        .decode()
    )
    return SmartBackendTokenProvider(
        token_url=url, client_id="c", private_key=key, algorithm=SignatureAlgorithm.ES384
    )


@pytest.mark.parametrize("which", ["smart", "oauth2"])
def test_a_token_request_keeps_the_bare_cr_refusal_as_it_is(which: str) -> None:
    """The shared token reader has an ``HTTPException`` arm, and the refusal is an
    ``HTTPException`` too. It must pass through that arm unchanged, reason and all, rather than be
    retyped as a plain malformed-reply ``DeliveryError`` (the Lander's review of PR 1662)."""
    raw = _json_reply(b"X-A: a\rContent-Length: %d\r\n" % len(_TOKEN_JSON))
    with _serve(raw) as url:
        provider = _token_provider(which, url)
        with pytest.raises(DeliveryError) as raised:
            provider.access_token()  # type: ignore[attr-defined]
    _assert_bare_cr_refusal(raised.value)


def test_oidc_jwks_fetch_refuses_a_bare_cr_as_an_http_exception() -> None:
    from messagefoundry.auth.oidc.jwks import JwksError
    from messagefoundry.auth.oidc_http import build_idp_opener, jwks_fetcher

    raw = _json_reply(b"X-A: a\rContent-Length: %d\r\n" % len(_TOKEN_JSON))
    with _serve(raw) as url, pytest.raises(http.client.HTTPException) as raised:
        jwks_fetcher(url, build_idp_opener(None))()
    assert isinstance(raised.value, MalformedReplyHeadError)
    assert not isinstance(raised.value, (JwksError, ValueError))


def test_oidc_token_exchange_refuses_a_bare_cr() -> None:
    from messagefoundry.auth import oidc
    from messagefoundry.auth.oidc_http import build_idp_opener

    raw = _json_reply(b"X-A: a\rContent-Length: %d\r\n" % len(_TOKEN_JSON))
    # A reply arrived, so it is an answer and must not mark the IdP (BACKLOG #1948).
    with _serve(raw) as url, pytest.raises(oidc.TokenRefusedError, match="ambiguously"):
        oidc.exchange_code(
            token_endpoint=url,
            client_id="c",
            client_auth=None,
            code="x",
            redirect_uri="http://localhost/cb",
            code_verifier="v",
            opener=build_idp_opener(None),
        )


# --- build_strict_opener, and which openers use it -----------------------------------------------


def _opener_handlers(opener: urllib.request.OpenerDirector) -> list[object]:
    # `handlers` is a real instance attribute that typeshed does not declare.
    handlers: list[object] = vars(opener)["handlers"]
    return handlers


def _assert_strict(opener: urllib.request.OpenerDirector) -> None:
    handlers = _opener_handlers(opener)
    assert sum(isinstance(h, StrictHTTPHandler) for h in handlers) == 1
    assert sum(isinstance(h, StrictHTTPSHandler) for h in handlers) == 1
    for h in handlers:
        if isinstance(h, (urllib.request.HTTPHandler, urllib.request.HTTPSHandler)):
            assert isinstance(h, (StrictHTTPHandler, StrictHTTPSHandler)), type(h).__name__


def test_the_strict_opener_keeps_the_https_context_it_was_given() -> None:
    """The TLS assertions ran on that context object, so the handler must carry the same one."""
    stock = urllib.request.HTTPSHandler()
    opener = build_strict_opener(stock, urllib.request.HTTPHandler())
    _assert_strict(opener)
    strict = next(h for h in _opener_handlers(opener) if isinstance(h, StrictHTTPSHandler))
    assert strict._context is stock._context  # type: ignore[attr-defined]  # noqa: SLF001


def test_the_strict_https_handler_opens_a_strict_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No TLS peer is needed: what matters is which connection class the handler asks for."""
    seen: dict[str, object] = {}

    def capture(self: object, http_class: type, req: object, **kw: object) -> None:
        seen["class"] = http_class
        seen["context"] = kw.get("context")

    handler = StrictHTTPSHandler()
    monkeypatch.setattr(StrictHTTPSHandler, "do_open", capture)
    handler.https_open(urllib.request.Request("https://example.test/"))
    http_class = seen["class"]
    assert isinstance(http_class, type)
    assert issubclass(http_class, http.client.HTTPSConnection)
    assert http_class.response_class is StrictHTTPResponse
    assert seen["context"] is handler._context  # type: ignore[attr-defined]  # noqa: SLF001


def test_the_strict_opener_refuses_a_handler_that_would_open_with_the_stock_class() -> None:
    class _Custom(urllib.request.HTTPSHandler):
        pass

    class _Default(urllib.request.BaseHandler):
        def default_open(self, req: urllib.request.Request) -> None:
            return None

    for handler in (_Custom(), _Custom, _Default()):
        with pytest.raises(TypeError, match="stock response class"):
            build_strict_opener(handler)


def test_the_strict_opener_converts_urllibs_own_handler_classes() -> None:
    _assert_strict(build_strict_opener(urllib.request.HTTPHandler, urllib.request.HTTPSHandler))


def test_the_strict_opener_refuses_a_handler_whose_context_it_cannot_reach() -> None:
    """urllib keeps the context on a private attribute. A runtime that renames it must stop the
    build, not yield a strict handler that quietly built a context of its own."""
    handler = urllib.request.HTTPSHandler()
    del handler._context  # type: ignore[attr-defined]  # noqa: SLF001
    with pytest.raises(TypeError, match="cannot reach the TLS context"):
        build_strict_opener(handler)


def test_every_engine_opener_reads_replies_strictly() -> None:
    from messagefoundry.auth.oidc_http import build_idp_opener
    from messagefoundry.pipeline import alert_sinks
    from messagefoundry.transports import rest

    for opener in (
        rest._shared_no_redirect_opener(),
        rest._insecure_opener(),
        rest._expiry_relaxed_opener("example.test"),
        alert_sinks._shared_no_redirect_opener(),
        build_idp_opener(None),
    ):
        _assert_strict(opener)


def test_a_proxy_handler_may_sit_on_a_strict_opener() -> None:
    """A ProxyHandler hands the request back after rewriting it, so a strict handler still opens."""
    _assert_strict(
        build_strict_opener(urllib.request.ProxyHandler({"https": "http://proxy.test:3128"}))
    )


#: Names of the calls that make an opener or a connection with the stock response class.
_STOCK_OPENER_CALLS = frozenset(
    {
        "build_opener",
        "urlopen",
        "urlretrieve",
        "OpenerDirector",
        "HTTPConnection",
        "HTTPSConnection",
    }
)

#: Import origins that share a name above but build no urllib opener or ``http.client``
#: connection. Each must be an absolute, importable origin. starlette's ``HTTPConnection`` wraps an
#: ASGI scope and dials nothing.
_NOT_STOCK_OPENERS = frozenset({"starlette.requests.HTTPConnection"})


class _Bindings(NamedTuple):
    #: ``bound name -> dotted origins``, from every ``import`` in the file at any depth. A name
    #: bound by two imports keeps both. A relative import keeps its leading dots rather than
    #: resolving the package, so it never equals an absolute origin on the allow-list.
    imports: dict[str, set[str]]
    #: Names some other statement also binds: an assignment, a ``def`` or ``class``, a parameter.
    shadowed: set[str]
    #: A star import can rebind any name, so no import origin is trusted alone.
    star: bool


def _bindings(tree: ast.AST) -> _Bindings:
    imports: dict[str, set[str]] = {}
    shadowed: set[str] = set()
    star = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                # ``import http.client as h`` binds ``h``; ``import http.client`` binds ``http``.
                if alias.asname:
                    imports.setdefault(alias.asname, set()).add(alias.name)
                else:
                    top = alias.name.partition(".")[0]
                    imports.setdefault(top, set()).add(top)
        elif isinstance(node, ast.ImportFrom):
            module = "." * node.level + (node.module or "")
            for alias in node.names:
                if alias.name == "*":
                    star = True
                else:
                    origin = f"{module}.{alias.name}" if node.module else module + alias.name
                    imports.setdefault(alias.asname or alias.name, set()).add(origin)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            shadowed.add(node.id)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            shadowed.add(node.name)
        elif isinstance(node, ast.arg):
            shadowed.add(node.arg)
        elif isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and node.name:
            shadowed.add(node.name)
    return _Bindings(imports, shadowed, star)


def _getattr_target(node: ast.expr) -> tuple[ast.expr, str] | None:
    """``getattr(obj, "name")`` as ``(obj, "name")``, which reads the same as ``obj.name``."""
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "getattr"
        and len(node.args) >= 2
        and isinstance(node.args[1], ast.Constant)
        and isinstance(node.args[1].value, str)
    ):
        return node.args[0], node.args[1].value
    return None


def _call_origins(func: ast.expr, bindings: _Bindings) -> set[tuple[str, bool]]:
    """Each ``(dotted origin, came from an import)`` a call's target can be.

    The root name goes through the file's imports. A root no import binds (a local name, ``self``,
    a call result) keeps its spelling, and so does a root the file also binds another way or that
    a star import could rebind. The last part of a spelling still names the call, so the scan fails
    closed on it."""
    attrs: list[str] = []
    while True:
        if isinstance(func, ast.Attribute):
            attrs.append(func.attr)
            func = func.value
        elif target := _getattr_target(func):
            func, attr = target
            attrs.append(attr)
        else:
            break
    tail = ".".join(reversed(attrs))
    if not isinstance(func, ast.Name):
        return {(tail, False)} if tail else set()
    roots = {(root, True) for root in bindings.imports.get(func.id, ())}
    if not roots or bindings.star or func.id in bindings.shadowed:
        roots.add((func.id, False))
    return {(f"{root}.{tail}" if tail else root, imported) for root, imported in roots}


def _is_stock(origin: str, imported: bool, names: frozenset[str] = _STOCK_OPENER_CALLS) -> bool:
    """Any part of ``origin`` is one of ``names``, and no allow-listed import gave it."""
    if imported and any(
        origin == entry or origin.startswith(entry + ".") for entry in _NOT_STOCK_OPENERS
    ):
        return False
    return not names.isdisjoint(origin.split("."))


def _name_chain(node: ast.expr) -> Iterator[ast.expr]:
    """The ``Name``/``Attribute``/``getattr`` nodes :func:`_call_origins` reads to resolve ``node``,
    and nothing under them, so a call inside a receiver, as in ``urlopen(u).read``, is still
    judged on its own."""
    while True:
        yield node
        if isinstance(node, ast.Attribute):
            node = node.value
        elif target := _getattr_target(node):
            node = target[0]
        else:
            return


def _stock_calls(tree: ast.AST, module: str | None = None) -> list[tuple[int, str]]:
    """``(line, origin)`` for each call, and each other use of a name as a value, whose origin
    names a stock name in any part, and for each class with such a base, or with a base naming a
    class ``_SANCTIONED_STOCK_SITES`` lets stand, whose origin reads ``class Name(base origin)``.
    A value naming a sanctioned class counts too, outside ``module``, the file under
    ``messagefoundry/`` that defines that class.

    The import decides, not the spelling: ``from http.client import HTTPConnection as C`` then
    ``C(host)`` is a stock call, and starlette's ``HTTPConnection`` under its own name is not. An
    origin outside urllib and ``http.client`` that names a stock name is still an offence unless
    ``_NOT_STOCK_OPENERS`` names it, because urllib3's connections, for one, read a reply head with
    ``http.client``'s class too. The allow-list clears only an origin an import gave, never a
    spelling. Any part counts, so ``urllib.request.OpenerDirector.add_handler(opener, handler)``,
    which skips a subclass's own ``add_handler``, is an offence too. A value counts, so a stock
    class held in a variable, handed to ``do_open``, set as a pool's ``ConnectionCls`` or put in
    the bases ``type`` is called with is an offence; a name in an annotation is not, though a call
    inside one is. A base is resolved the way a call's target is, so a subclass of
    ``urllib.request.OpenerDirector`` is found under any alias or dotted spelling. So is a class
    statement built on a sanctioned class, and outside the module that defines it, a value naming
    one, such as a ``type`` call's bases, since that sanction's check sees only the class itself.

    At least these pass unseen: a stock class reached by ``getattr`` with a name that is not a
    constant; a stock name re-exported under another name by a second module and imported from
    there, which a scan of one file at a time cannot see; a urllib3 or requests constructor, such
    as ``urllib3.PoolManager`` or ``requests.Session``, that builds a stock connection inside the
    library; a stock handler driven directly, as in ``urllib.request.HTTPSHandler().https_open``,
    since engine code builds stock handlers to hand to build_strict_opener; a value naming a
    sanctioned class inside the module that defines it; and a handler added to a sanctioned opener
    by ``super`` or by editing its handler tables, which ``_ConfinedOpener`` itself refuses when it
    opens. No planted control pins these."""
    bindings = _bindings(tree)
    elsewhere = frozenset(name for name, home in _SANCTIONED_CLASSES.items() if home != module)
    found: list[tuple[int, str]] = []
    judged: set[int] = set()  # names a call, a base or an annotation already accounts for
    for node in ast.walk(tree):
        annotations: list[ast.expr | None] = []
        if isinstance(node, (ast.arg, ast.AnnAssign)):
            annotations.append(node.annotation)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            annotations.append(node.returns)
        judged.update(
            id(n)
            for a in annotations
            if a is not None
            for n in ast.walk(a)
            if isinstance(n, (ast.Name, ast.Attribute))
        )
    # ast.walk is breadth-first, so an outer name is judged before the names inside it. A set, so
    # one use whose root resolves two ways is reported once per origin; sorted only so a failure
    # lists them in a stable order.
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            judged.update(id(n) for n in _name_chain(node.func))
            calls = {o for o, i in _call_origins(node.func, bindings) if _is_stock(o, i)}
            found.extend((node.lineno, origin) for origin in sorted(calls))
        elif isinstance(node, ast.ClassDef):
            judged.update(id(n) for base in node.bases for n in _name_chain(base))
            names = _STOCK_OPENER_CALLS | frozenset(_SANCTIONED_CLASSES)
            bases = {
                origin
                for base in node.bases
                for origin, imported in _call_origins(base, bindings)
                if _is_stock(origin, imported, names)
            }
            found.extend((node.lineno, f"class {node.name}({origin})") for origin in sorted(bases))
        elif (
            isinstance(node, (ast.Name, ast.Attribute))
            and isinstance(node.ctx, ast.Load)
            and id(node) not in judged
        ):
            judged.update(id(n) for n in _name_chain(node))
            names = _STOCK_OPENER_CALLS | elsewhere
            values = {o for o, i in _call_origins(node, bindings) if _is_stock(o, i, names)}
            found.extend((node.lineno, origin) for origin in sorted(values))
    return found


def _strict_opener_is_strict() -> None:
    """build_strict_opener's own call: it hands build_opener the strict http and https handlers."""
    _assert_strict(build_strict_opener())


def _strict_connections_read_strictly() -> None:
    """The strict connections: each one's response_class is StrictHTTPResponse, so each reads a
    reply head the way build_strict_opener's handlers do."""
    from messagefoundry.transports import bounded_read

    connections: list[type] = [
        bounded_read._StrictHTTPConnection,  # noqa: SLF001
        bounded_read._StrictHTTPSConnection,  # noqa: SLF001
    ]
    try:
        from messagefoundry.transports import strict_requests
    except ModuleNotFoundError as exc:
        # Without the [vault] extra nothing can build its connections, so there is nothing to read.
        if exc.name not in ("requests", "urllib3"):
            raise
    else:
        pools = strict_requests._narrowed_pool_classes(  # noqa: SLF001
            ssl.create_default_context, connector="probe", judge_proxy_leg=lambda _c, _h: None
        )
        connections += [
            strict_requests._StrictHeadHTTPConnection,  # noqa: SLF001
            strict_requests._StrictHeadHTTPSConnection,  # noqa: SLF001
            pools["https"].ConnectionCls,  # NarrowedHTTPSConnection
        ]
    for connection in connections:
        assert getattr(connection, "response_class", None) is StrictHTTPResponse, connection


def _schema_opener_is_confined() -> None:
    """xmlschema's opener in parsing/xml/schema.py, which parsing/ cannot build with
    build_strict_opener from transports/, and which build_opener would fill with urllib's default
    handlers. The _ConfinedOpener docstring lists the refusals that keep it from opening an http
    or https URL or reading a reply head; this checks each. That such a URL is refused is also
    ``tests/test_xml_schema_lockdown.py::test_a_non_file_url_reaching_the_opener_is_a_refused_resource``.
    """
    from messagefoundry.parsing.xml.schema import _ConfinedFiles, _ConfinedOpener, _ResourceRefused

    files = _ConfinedFiles(())
    opener = _ConfinedOpener(files)
    assert _opener_handlers(opener) == [files]
    assert {n for n in dir(files) if n.endswith("_open")} == {"file_open", "unknown_open"}
    with pytest.raises(TypeError, match="no other"):
        opener.add_handler(urllib.request.HTTPHandler())
    assert _opener_handlers(opener) == [files]

    class _WithHttps(_ConfinedFiles):
        def https_open(self, req: urllib.request.Request) -> None:
            raise AssertionError("never reached")

    with pytest.raises(TypeError, match="no subclass"):
        _ConfinedOpener(_WithHttps(()))
    # A non-file scheme is refused before any handler runs.
    with pytest.raises(_ResourceRefused, match="scheme is not file"):
        opener.open("https://127.0.0.1:9/x.xsd")
    # A file URL meets the handler checks; the file is never reached, so it need not exist.
    file_url = "file:///nonexistent-5537/x.xsd"
    # A handler that skips add_handler's refusal, as super(_ConfinedOpener, o).add_handler does.
    urllib.request.OpenerDirector.add_handler(opener, urllib.request.HTTPSHandler())
    with pytest.raises(TypeError, match="besides its confined-file handler"):
        opener.open(file_url)
    # Or one placed straight in a handler table add_handler fills.
    for table in ("handle_error", "process_request", "process_response"):
        tampered = _ConfinedOpener(_ConfinedFiles(()))
        vars(tampered)[table].setdefault("https", []).append(urllib.request.HTTPSHandler())
        with pytest.raises(TypeError, match="besides its confined-file handler"):
            tampered.open(file_url)

    def never(*args: object) -> None:
        raise AssertionError("an injected open method ran")

    # An https_open set on the one handler, which the tables carry in under "https", is not called
    # through the opener's own open().
    injected = _ConfinedFiles(())
    injected.https_open = never  # type: ignore[attr-defined]
    carrying = _ConfinedOpener(injected)
    assert vars(carrying)["handle_open"]["https"] == [injected]
    with pytest.raises(_ResourceRefused, match="scheme is not file"):
        carrying.open("https://127.0.0.1:9/x.xsd")
    # A default_open on it, which would run before file_open for a file URL, is refused too.
    defaulted = _ConfinedFiles(())
    defaulted.default_open = never  # type: ignore[attr-defined]
    with pytest.raises(TypeError, match="open method it does not define"):
        _ConfinedOpener(defaulted).open(file_url)


#: ``(module under messagefoundry/, origin as _stock_calls reports it) -> the check it rests on``,
#: whose docstring says why it may stand. Each must be found exactly once, and the scan runs each
#: check.
_SANCTIONED_STOCK_SITES: dict[tuple[str, str], Callable[[], None]] = {
    ("transports/bounded_read.py", "urllib.request.build_opener"): _strict_opener_is_strict,
    (
        "transports/bounded_read.py",
        "class _StrictHTTPConnection(http.client.HTTPConnection)",
    ): _strict_connections_read_strictly,
    (
        "transports/bounded_read.py",
        "class _StrictHTTPSConnection(http.client.HTTPSConnection)",
    ): _strict_connections_read_strictly,
    (
        "transports/strict_requests.py",
        "class _StrictHeadHTTPConnection(urllib3.connection.HTTPConnection)",
    ): _strict_connections_read_strictly,
    (
        "transports/strict_requests.py",
        "class _StrictHeadHTTPSConnection(urllib3.connection.HTTPSConnection)",
    ): _strict_connections_read_strictly,
    (
        "transports/strict_requests.py",
        "class NarrowedHTTPSConnection(_StrictHeadHTTPSConnection)",
    ): _strict_connections_read_strictly,
    (
        "parsing/xml/schema.py",
        "class _ConfinedOpener(urllib.request.OpenerDirector)",
    ): _schema_opener_is_confined,
}

#: ``class -> the module defining it`` for each sanctioned ``class Name(...)`` site. A base naming
#: one is reported, and so is a value naming one outside that module.
_SANCTIONED_CLASSES = {
    origin.removeprefix("class ").partition("(")[0]: module
    for module, origin in _SANCTIONED_STOCK_SITES
    if origin.startswith("class ")
}


def test_no_engine_module_builds_a_stock_opener() -> None:
    """A source scan, because some openers (the SOAP mutual-TLS one, at least) need key material to
    build. Every urllib opener and ``http.client`` connection in the engine must come from
    build_strict_opener, except the sites ``_SANCTIONED_STOCK_SITES`` names. Calls and class
    bases are found in the syntax tree, so a docstring that names one is neither, and each is judged
    by where its import says it came from (``_stock_calls``). Each sanctioned site's check runs
    here, the ``transports/strict_requests.py`` ones only where the ``[vault]`` extra is installed,
    since nothing can build those connections without it."""
    for entry in _NOT_STOCK_OPENERS:
        module, _, name = entry.rpartition(".")
        assert hasattr(importlib.import_module(module), name), f"{entry} is not an import origin"
    root = Path(__file__).resolve().parents[1] / "messagefoundry"
    stock: list[str] = []
    sanctioned: Counter[tuple[str, str]] = Counter()
    for path in root.rglob("*.py"):
        # utf-8-sig: a byte-order mark would otherwise fail the parse for a reason unrelated to
        # openers.
        text = path.read_text(encoding="utf-8-sig")
        # Most files name none of them, and skipping the parse keeps the scan cheap. An aliased
        # import still spells the stock name in the import itself. NFKC is how the parser reads
        # an identifier, so a look-alike spelling is not skipped either.
        normalized = unicodedata.normalize("NFKC", text)
        if not any(name in normalized for name in _STOCK_OPENER_CALLS | set(_SANCTIONED_CLASSES)):
            continue
        rel = path.relative_to(root).as_posix()
        for lineno, origin in _stock_calls(ast.parse(text), rel):
            if (rel, origin) in _SANCTIONED_STOCK_SITES:
                sanctioned[rel, origin] += 1
            else:
                stock.append(f"{rel}:{lineno} {origin}")
    # Exactly once each: a second site under the same name is not the one sanctioned, and a site
    # the scan no longer finds means the scan stopped seeing it, or the sanction is stale.
    assert sanctioned == dict.fromkeys(_SANCTIONED_STOCK_SITES, 1), sanctioned
    for check in set(_SANCTIONED_STOCK_SITES.values()):
        check()
    assert stock == [], (
        "build the opener with build_strict_opener; if an import gave the origin and it is another "
        "library's class that builds no urllib opener or http.client connection, add that absolute "
        f"origin to _NOT_STOCK_OPENERS: {stock}"
    )


@pytest.mark.parametrize(
    ("source", "offending"),
    [
        pytest.param(
            "from http.client import HTTPConnection as C\nC('h')", True, id="aliased-http-client"
        ),
        pytest.param(
            "from urllib.request import urlopen as fetch\nfetch('u')", True, id="aliased-urllib"
        ),
        pytest.param("import http.client as h\nh.HTTPConnection('h')", True, id="module-alias"),
        pytest.param(
            "from urllib import request as r\nr.build_opener()", True, id="submodule-alias"
        ),
        pytest.param("import urllib.request\nurllib.request.OpenerDirector()", True, id="dotted"),
        pytest.param(
            "from http.client import HTTPSConnection\nHTTPSConnection('h')", True, id="direct"
        ),
        pytest.param(
            "import urllib.request as ur\ngetattr(ur, 'urlopen')('u')", True, id="getattr"
        ),
        pytest.param("HTTPConnection('h')", True, id="unimported-name"),
        pytest.param("self.urlopen('u')", True, id="unresolved-receiver"),
        pytest.param(
            "import urllib3\nurllib3.connection.HTTPConnection('h')", True, id="other-library"
        ),
        pytest.param(
            "from starlette.requests import HTTPConnection\n"
            "def f():\n    from http.client import HTTPConnection\n    HTTPConnection('h')",
            True,
            id="rebound-by-import",
        ),
        pytest.param(
            "import http.client\nfrom starlette.requests import HTTPConnection\n"
            "def f(HTTPConnection=http.client.HTTPConnection):\n    HTTPConnection('h')",
            True,
            id="rebound-by-parameter",
        ),
        pytest.param(
            "from starlette.requests import HTTPConnection\nfrom http.client import *\n"
            "HTTPConnection('h')",
            True,
            id="star-import",
        ),
        pytest.param(
            "starlette.requests.HTTPConnection(scope)", True, id="allow-listed-spelling-unimported"
        ),
        pytest.param(
            "from starlette.requests import HTTPConnection\nHTTPConnection(scope)",
            False,
            id="starlette-own-name",
        ),
        pytest.param(
            "import starlette.requests\nstarlette.requests.HTTPConnection(scope)",
            False,
            id="starlette-dotted",
        ),
        pytest.param(
            "from messagefoundry.transports.bounded_read import build_strict_opener\n"
            "build_strict_opener()",
            False,
            id="strict-opener",
        ),
        pytest.param(
            "import urllib.request\nclass O(urllib.request.OpenerDirector): pass\nO()",
            True,
            id="subclass-of-a-stock-class",
        ),
        pytest.param(
            "from urllib.request import OpenerDirector as D\nclass O(D): pass",
            True,
            id="aliased-base",
        ),
        pytest.param(
            "from urllib import request as r\nclass O(object, r.OpenerDirector): pass",
            True,
            id="second-base-submodule-alias",
        ),
        pytest.param(
            "import http.client as h\ndef f():\n    class C(h.HTTPSConnection): pass",
            True,
            id="nested-subclass-of-a-connection",
        ),
        pytest.param(
            "import urllib.request as ur\nclass O(getattr(ur, 'OpenerDirector')): pass",
            True,
            id="getattr-base",
        ),
        pytest.param(
            "import urllib3\nclass C(urllib3.connection.HTTPConnection): pass",
            True,
            id="other-library-base",
        ),
        pytest.param(
            "from starlette.requests import HTTPConnection\nclass R(HTTPConnection): pass",
            False,
            id="starlette-base",
        ),
        pytest.param(
            "from starlette.requests import HTTPConnection\nHTTPConnection.url_for(c, 'n')",
            False,
            id="starlette-attribute",
        ),
        pytest.param(
            "import urllib.request\nurllib.request.OpenerDirector.add_handler(o, h)",
            True,
            id="unbound-stock-method",
        ),
        pytest.param(
            "from messagefoundry.parsing.xml.schema import _ConfinedOpener as Q\nclass W(Q): pass",
            True,
            id="subclass-of-a-sanctioned-class",
        ),
        pytest.param(
            "from messagefoundry.transports import bounded_read as b\n"
            "class L(b._StrictHTTPSConnection): pass",
            True,
            id="subclass-of-a-sanctioned-connection",
        ),
        pytest.param(
            "import urllib.request\nclass H(urllib.request.BaseHandler): pass",
            False,
            id="handler-base",
        ),
        pytest.param(
            "import urllib.request\ndef f(o: urllib.request.OpenerDirector): return o.open('u')",
            False,
            id="annotation-not-a-call",
        ),
        pytest.param(
            "import http.client\nC = http.client.HTTPConnection\nC('h')",
            True,
            id="class-held-in-a-variable",
        ),
        pytest.param(
            "import urllib.request\nO = type('O', (urllib.request.OpenerDirector,), {})",
            True,
            id="type-call-with-a-stock-base",
        ),
        pytest.param(
            "import http.client\ndef https_open(self, req):\n"
            "    return self.do_open(http.client.HTTPSConnection, req)",
            True,
            id="stock-class-handed-to-do-open",
        ),
        pytest.param(
            "import urllib3\nclass P(urllib3.HTTPSConnectionPool):\n"
            "    ConnectionCls = urllib3.connection.HTTPSConnection",
            True,
            id="stock-connection-as-a-pool-class",
        ),
        pytest.param(
            "import urllib.request\ndata = urllib.request.urlopen(u).read()",
            True,
            id="chained-call-on-a-stock-call",
        ),
        pytest.param(
            "import urllib.request\nurllib.request.build_opener(h).open(r)",
            True,
            id="chained-open-on-a-stock-opener",
        ),
        pytest.param(
            "import urllib.request\nstatus = urllib.request.urlopen(u).status",
            True,
            id="attribute-of-a-stock-call",
        ),
        pytest.param(
            "import urllib.request\nfrom typing import Annotated\n"
            "def f(x: Annotated[int, urllib.request.build_opener()]): ...",
            True,
            id="call-inside-an-annotation",
        ),
        pytest.param(
            "import http.client, six\n"
            "class X(six.with_metaclass(M, http.client.HTTPConnection)): ...",
            True,
            id="stock-class-inside-a-base-call",
        ),
        pytest.param(
            "import urllib.request\nurllib.request.urlretrieve(u, f)", True, id="urlretrieve"
        ),
        pytest.param(
            "from messagefoundry.parsing.xml.schema import _ConfinedOpener\nQ = _ConfinedOpener",
            True,
            id="sanctioned-class-held-in-a-variable",
        ),
        pytest.param(
            "from messagefoundry.transports import bounded_read as b\n"
            "L = type('L', (b._StrictHTTPSConnection,), {})",
            True,
            id="type-call-with-a-sanctioned-base",
        ),
        pytest.param(
            "import http.client\nx: http.client.HTTPConnection | None = None",
            False,
            id="variable-annotation-not-a-value",
        ),
        pytest.param(
            "import http.client\ndef f() -> http.client.HTTPConnection: ...",
            False,
            id="return-annotation-not-a-value",
        ),
    ],
)
def test_the_stock_opener_guard_judges_the_import_not_the_spelling(
    source: str, offending: bool
) -> None:
    """The guard's own control: each planted shape it exists to catch reads as an offence, and the
    neighbouring shapes that build no stock opener do not (BACKLOG #3360)."""
    found = _stock_calls(ast.parse(source))
    assert bool(found) is offending, found


def test_a_site_whose_root_resolves_two_ways_is_reported_once() -> None:
    """The exactly-once count on a sanctioned site would otherwise read a shadowed root, such as a
    parameter named ``urllib``, as a second site."""
    source = (
        "import urllib.request\nclass O(urllib.request.OpenerDirector): pass\n"
        "def f(urllib):\n    urllib.request.urlopen('u')\n"
    )
    assert _stock_calls(ast.parse(source)) == [
        (2, "class O(urllib.request.OpenerDirector)"),
        (4, "urllib.request.urlopen"),
    ]


def test_a_sanctioned_class_is_a_value_only_inside_its_own_module() -> None:
    """Its own module hands it to do_open or a pool, which is how it is used; anywhere else a value
    naming it can build a subclass its sanction's check never sees."""
    tree = ast.parse("class _ConfinedOpener: ...\nQ = _ConfinedOpener\n")
    assert _stock_calls(tree, "parsing/xml/schema.py") == []
    assert _stock_calls(tree, "parsing/xml/other.py") == [(2, "_ConfinedOpener")]
