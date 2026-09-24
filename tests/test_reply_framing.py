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

import asyncio
import contextlib
import http.client
import io
import logging
import socket
import sys
import threading
import urllib.request
from collections.abc import Iterator

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.wiring import Rest, Soap
from messagefoundry.transports import build_destination
from messagefoundry.transports.base import DeliveryError, NegativeAckError
from messagefoundry.transports.bounded_read import (
    AmbiguousFramingError,
    EgressReplyError,
    ResponseTooLargeError,
    TruncatedResponseError,
    drain_bounded,
    read_bounded,
    reply_framing_fault,
)
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
        )
    )
    assert isinstance(d, SoapDestination)
    return d


def _rest(url: str) -> RestDestination:
    d = build_destination(
        Destination(
            name="OB_REST",
            type=ConnectorType.REST,
            settings=Rest(url=url, capture_response=True).settings,
        )
    )
    assert isinstance(d, RestDestination)
    return d


def _assert_framing_refusal(exc: BaseException) -> None:
    assert isinstance(exc, AmbiguousFramingError)
    assert "framed its response body ambiguously" in str(exc)


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
    """The SOAP captured-reply path: the refusal is a DeliveryError, so the delivery worker records
    it on the row, retries it and dead-letters it. It never becomes a captured reply."""
    with _serve(_AMBIGUOUS[shape]) as url:
        dest = _soap(url)
        with pytest.raises(DeliveryError) as raised:
            asyncio.run(dest.send("<soap:Envelope/>"))
    _assert_framing_refusal(raised.value)
    assert not isinstance(raised.value, NegativeAckError)


@pytest.mark.parametrize("shape", list(_AMBIGUOUS), ids=list(_AMBIGUOUS))
def test_rest_reply_refuses_ambiguous_framing(shape: str) -> None:
    with _serve(_AMBIGUOUS[shape]) as url:
        dest = _rest(url)
        with pytest.raises(DeliveryError) as raised:
            asyncio.run(dest.send('{"a": 1}'))
    _assert_framing_refusal(raised.value)


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


def _wire(raw: bytes, method: str = "GET") -> http.client.HTTPResponse:
    """A real parsed ``HTTPResponse`` over ``raw``, with no socket involved."""

    class _Sock:
        def makefile(self, *a: object, **k: object) -> io.BytesIO:
            return io.BytesIO(raw)

        def close(self) -> None:
            pass

    resp = http.client.HTTPResponse(_Sock(), method=method)  # type: ignore[arg-type]
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
# leg raises FlowError (a ValueError) and the JWKS leg an http.client.HTTPException. Both reach the
# (OSError, ValueError, HTTPException) arm in auth/service.py's authenticate_oidc, which records an
# unavailable IdP. The JWKS leg must NOT raise JwksError: claims.py retypes that as
# ClaimsError("unknown_kid"), a token-verification reject. These tests pin the types, not the
# service mapping.

_TOKEN_JSON = b'{"id_token": "x.y.z"}'


def _json_reply(headers: bytes) -> bytes:
    return _OK + headers + b"\r\n" + _TOKEN_JSON


def _exchange(url: str) -> object:
    from messagefoundry.auth import oidc

    return oidc.exchange_code(
        token_endpoint=url,
        client_id="c",
        client_secret=None,
        code="x",
        redirect_uri="http://localhost/cb",
        code_verifier="v",
        opener=urllib.request.build_opener(),
    )


def test_oidc_token_exchange_refuses_ambiguous_framing() -> None:
    from messagefoundry.auth import oidc

    raw = _json_reply(b"Content-Length: 3\r\nContent-Length: %d\r\n" % len(_TOKEN_JSON))
    with _serve(raw) as url, pytest.raises(oidc.FlowError, match="ambiguously"):
        _exchange(url)


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
        pytest.raises(http.client.HTTPException, match="ambiguously") as raised,
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
}


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
    _assert_header_refusal(raised.value)
    assert not isinstance(raised.value, NegativeAckError)


@pytest.mark.parametrize("shape", list(_BAD_HEADERS), ids=list(_BAD_HEADERS))
def test_rest_reply_refuses_a_header_block_that_did_not_parse(shape: str) -> None:
    with _serve(_BAD_HEADERS[shape]) as url:
        dest = _rest(url)
        with pytest.raises(DeliveryError) as raised:
            asyncio.run(dest.send('{"a": 1}'))
    _assert_header_refusal(raised.value)


def test_a_header_defect_is_refused_even_on_a_bodyless_reply() -> None:
    """The defect check comes before the bodyless and HEAD exemptions: a header block that did not
    parse is untrustworthy whatever the status."""
    raw = b"HTTP/1.1 204 No Content\r\nNOT A FIELD LINE\r\n\r\n"
    assert reply_framing_fault(_wire(raw)) is not None
    assert reply_framing_fault(_wire(_BAD_HEADERS["space-before-colon"], method="HEAD")) is not None


def test_an_obs_fold_is_not_a_header_defect() -> None:
    """RFC 9112 section 5.2 lets a user agent accept a folded field value in a response. The control
    for the defect arm: a legal but unusual header block must still read."""
    raw = _OK + b"X-Folded: a\r\n b\r\nContent-Length: 5\r\n\r\nhello"
    assert read_bounded(_wire(raw), connector="c") == b"hello"


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
}

#: Chunked framings that are legal and must still read as b"hello".
_CHUNK_CONTROLS: dict[str, bytes] = {
    "plain": _TE + _CHUNKS,
    "two-chunks": _TE + b"2\r\nhe\r\n3\r\nllo\r\n0\r\n\r\n",
    "extension": _TE + b"5;name=value\r\nhello\r\n0\r\n\r\n",
    "extension-quoted": _TE + b'5 ; n="a \\" b"; flag\r\nhello\r\n0;done\r\n\r\n',
    "leading-zeros": _TE + b"0005\r\nhello\r\n000\r\n\r\n",
    "trailer-section": _TE + b"5\r\nhello\r\n0\r\nX-Checksum: abc\r\nX-Other: 1\r\n\r\n",
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


def test_a_chunked_body_cut_before_the_final_crlf_is_a_truncation() -> None:
    """http.client accepted this, because "a vanishingly small number of sites" do it. The body is
    whole, but the peer broke its own framing, and the refusal is the same retryable one."""
    with pytest.raises(TruncatedResponseError):
        read_bounded(_wire(_TE + b"5\r\nhello\r\n0\r\n"), connector="c")


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
    _assert_framing_refusal(raised.value)
    assert not isinstance(raised.value, NegativeAckError)


@pytest.mark.parametrize("shape", list(_BAD_CHUNKS), ids=list(_BAD_CHUNKS))
def test_rest_reply_refuses_malformed_chunk_framing(shape: str) -> None:
    with _serve(_BAD_CHUNKS[shape]) as url:
        dest = _rest(url)
        with pytest.raises(DeliveryError) as raised:
            asyncio.run(dest.send('{"a": 1}'))
    _assert_framing_refusal(raised.value)


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
        drain_bounded(resp, limit=1000, connector="probe-c")
    assert stream.tell() <= min(len(raw), len(_TE) + 40)
    assert "probe-c" in caplog.text


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


_OIDC_BAD: dict[str, bytes] = {
    "negative-size": _TE + b"-5\r\n" + b"A" * 20_000,
    "size-0x": _chunked_json(b"0x%x" % len(_TOKEN_JSON)),
    "size-underscore": _chunked_json(b"1_5"),
    "header-defect": _OK
    + b"Content-Length: 3\r\nTransfer-Encoding : chunked\r\n\r\n"
    + _chunked_json(b"%x" % len(_TOKEN_JSON))[len(_TE) :],
}


@pytest.mark.parametrize("shape", list(_OIDC_BAD), ids=list(_OIDC_BAD))
def test_oidc_token_exchange_refuses_malformed_framing(shape: str) -> None:
    from messagefoundry.auth import oidc

    with _serve(_OIDC_BAD[shape]) as url, pytest.raises(oidc.FlowError, match="ambiguously"):
        _exchange(url)


@pytest.mark.parametrize("shape", list(_OIDC_BAD), ids=list(_OIDC_BAD))
def test_oidc_jwks_fetch_refuses_malformed_framing(shape: str) -> None:
    from messagefoundry.auth.oidc.jwks import JwksError
    from messagefoundry.auth.oidc_http import jwks_fetcher

    with (
        _serve(_OIDC_BAD[shape]) as url,
        pytest.raises(http.client.HTTPException, match="ambiguously") as raised,
    ):
        jwks_fetcher(url, urllib.request.build_opener())()
    assert not isinstance(raised.value, (JwksError, ValueError))


def test_oidc_reads_legal_chunk_framing() -> None:
    from messagefoundry.auth.oidc_http import jwks_fetcher

    raw = _chunked_json(b"%X;ext=1" % len(_TOKEN_JSON))
    with _serve(raw) as url:
        assert _exchange(url) == {"id_token": "x.y.z"}
    with _serve(raw) as url:
        assert jwks_fetcher(url, urllib.request.build_opener())() == _TOKEN_JSON


def test_oidc_token_exchange_maps_a_cut_chunked_body_to_flow_error() -> None:
    """Before the fix, http.client's IncompleteRead escaped exchange_code unmapped."""
    from messagefoundry.auth import oidc

    with _serve(_TE + b"50\r\n" + _TOKEN_JSON) as url, pytest.raises(oidc.FlowError):
        _exchange(url)


def test_oidc_token_exchange_refuses_a_body_short_of_its_content_length() -> None:
    """The token read goes through read_bounded, so it gets the declared-length check too. Before,
    the short body reached json.loads and failed there, or parsed if the cut fell after a brace."""
    from messagefoundry.auth import oidc

    raw = _json_reply(b"Content-Length: %d\r\n" % (len(_TOKEN_JSON) + 40))
    with _serve(raw) as url, pytest.raises(oidc.FlowError, match="part-way"):
        _exchange(url)
