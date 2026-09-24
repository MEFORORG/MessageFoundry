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
