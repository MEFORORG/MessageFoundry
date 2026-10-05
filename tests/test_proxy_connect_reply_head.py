# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A web proxy's own reply to ``CONNECT`` is read strictly (vault BACKLOG #2170, ASVS 4.2.1).

For an ``https`` target behind an HTTP proxy, ``http.client`` first sends ``CONNECT`` and reads the
proxy's reply in ``HTTPConnection._tunnel``. That method builds the connection's ``response_class``,
calls ``_read_status`` and ``_read_headers`` on it, and never calls ``begin``. The strict head read
(BACKLOG #2052) used to be put on in ``begin``, so this one head was read leniently on every egress
hop. ``StrictHTTPResponse`` now carries its guard from construction.

Every test here drives a real socket. A loopback fake proxy answers ``CONNECT`` with a scripted raw
head, records the request head it got, and records the first bytes the client sent afterwards. So
"refused" is measured twice: by the error raised, and by nothing having entered the tunnel.

Three layers are measured: a bare strict opener, a REST connection with ``proxy_url``, and the Vault
hop's ``requests`` adapter. Each refusal has two controls. A clean ``CONNECT`` reply still tunnels,
with a TLS reply read inside it. And with the construction-time guard undone, the same bare-CR reply
is taken and the client starts TLS, so the refusal is that guard's doing.

Synthetic data only: every host name is reserved, and the certificate is made for the test.
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime
import http.client
import io
import socket
import ssl
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import Any, NamedTuple

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.wiring import Rest
from messagefoundry.transports import build_destination
from messagefoundry.transports.base import DeliveryError
from messagefoundry.transports.bounded_read import (
    MalformedReplyHeadError,
    StrictHTTPResponse,
    build_strict_opener,
    read_bounded,
)
from messagefoundry.transports.rest import RestDestination
from tests._egress_policy import permitting
from tests._extras_probe import OPTIONAL_EXTRAS, extra_is_installed

_needs_vault = pytest.mark.skipif(
    not extra_is_installed(OPTIONAL_EXTRAS["vault"]),
    reason="the [vault] extra (hvac + requests + urllib3) is not installed in this interpreter",
)

#: The target every test names. Reserved, so a request that escaped the fake proxy reaches nothing.
_HOST = "partner.example.test"
_TARGET = f"https://{_HOST}/ingest"

_ESTABLISHED = b"HTTP/1.1 200 Connection established\r\n"

#: ``CONNECT`` reply heads holding a bare CR. Before the fix the first three opened the tunnel.
_BARE_CR: dict[str, bytes] = {
    "cr-in-a-header-line": _ESTABLISHED + b"X-A: a\rProxy-Agent: p\r\n\r\n",
    "cr-in-the-first-header-line": _ESTABLISHED + b"Via: p\rX-B: b\r\nX-C: c\r\n\r\n",
    "cr-in-the-reason-phrase": b"HTTP/1.1 200 Connection\restablished\r\n\r\n",
    # A refused tunnel: http.client reads the whole head before it looks at the status code.
    "cr-on-a-407": b"HTTP/1.1 407 Proxy Authentication Required\r\nX-A: a\rb\r\n\r\n",
}

#: The shapes whose status is 200, so a lenient reader goes on to start TLS inside the tunnel.
_TUNNEL_OPENING = [name for name in _BARE_CR if name != "cr-on-a-407"]

#: Clean heads, which must still open the tunnel.
_CLEAN: dict[str, bytes] = {
    "no-headers": _ESTABLISHED + b"\r\n",
    "one-header": _ESTABLISHED + b"Proxy-Agent: synthetic\r\n\r\n",
    # RFC 9112 section 2.2 lets a recipient take a bare LF as the line end, and http.client does.
    "bare-lf-line-ends": b"HTTP/1.1 200 Connection established\nProxy-Agent: synthetic\n\n",
}

_INNER_BODY = b'{"ok": true}'
_INNER_REPLY = (
    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
    + str(len(_INNER_BODY)).encode()
    + b"\r\nConnection: close\r\n\r\n"
    + _INNER_BODY
)

#: Every variable urllib and requests read a proxy or a bypass list from.
_PROXY_ENV = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "REQUEST_METHOD")


@pytest.fixture(autouse=True)
def no_ambient_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Only the proxy a test names can route a request, and no bypass list can send one direct."""
    for name in _PROXY_ENV:
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(name.lower(), raising=False)
    for source in ("registry", "macosx_sysconf"):
        monkeypatch.setattr(urllib.request, f"getproxies_{source}", dict, raising=False)
        monkeypatch.setattr(
            urllib.request, f"proxy_bypass_{source}", lambda host: False, raising=False
        )


class _Tls(NamedTuple):
    ca_file: Path
    server: ssl.SSLContext


@pytest.fixture
def tls(tmp_path: Path) -> _Tls:
    """A self-signed certificate for the target's name, and a server context that presents it."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, _HOST)])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(_HOST)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_file = tmp_path / "target.pem"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file = tmp_path / "target.key"
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(cert_file, key_file)
    return _Tls(cert_file, server)


def _read_head(conn: socket.socket | ssl.SSLSocket) -> bytes:
    head = b""
    while b"\r\n\r\n" not in head:
        data = conn.recv(4096)
        if not data:
            break
        head += data
    return head


class _ConnectProxy:
    """A loopback forward proxy that answers each request with one scripted raw head.

    ``heads`` holds each request head it received. ``after`` holds, per connection, the first bytes
    the client sent once the reply was out: empty when the client hung up, and a TLS record when
    it went on into the tunnel. With ``inner`` set, the proxy plays the target too: it runs TLS on
    the tunnel, reads one request and sends ``_INNER_REPLY``.
    """

    def __init__(self, reply: bytes, *, inner: ssl.SSLContext | None = None) -> None:
        self._reply = reply
        self._inner = inner
        self.heads: list[bytes] = []
        self.after: list[bytes] = []
        self.inner_requests: list[bytes] = []
        self._listener = socket.socket()
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(4)
        # So a test that stalls fails in seconds rather than hanging the serving thread.
        self._listener.settimeout(5)
        self.port = self._listener.getsockname()[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self._listener.accept()
            except TimeoutError:
                continue  # idle, not closed: a slow test must still find the proxy serving
            except OSError:
                return
            conn.settimeout(5)
            # Suppressed: the client hung up or refused the handshake. What was recorded stands.
            with conn, contextlib.suppress(OSError):
                self._answer(conn)

    def _answer(self, conn: socket.socket) -> None:
        self.heads.append(_read_head(conn))
        conn.sendall(self._reply)
        if self._inner is None:
            try:
                self.after.append(conn.recv(64))
            except OSError:
                self.after.append(b"")
            return
        with self._inner.wrap_socket(conn, server_side=True) as tunnel:
            self.inner_requests.append(_read_head(tunnel))
            tunnel.sendall(_INNER_REPLY)

    def __enter__(self) -> _ConnectProxy:
        return self

    def __exit__(self, *exc: object) -> None:
        # shutdown wakes a blocked accept() on Linux, where close() alone does not.
        with contextlib.suppress(OSError):
            self._listener.shutdown(socket.SHUT_RDWR)
        self._listener.close()
        self._thread.join(timeout=10)


def _assert_connect_was_sent(proxy: _ConnectProxy) -> None:
    assert len(proxy.heads) == 1
    assert proxy.heads[0].startswith(f"CONNECT {_HOST}:".encode())


def _undo_the_construction_time_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    """The mutation: build the strict response as the stock class builds one, with no guard on
    its stream. Nothing else puts one on, so every head is then read as the stock class reads it."""
    monkeypatch.setattr(StrictHTTPResponse, "__init__", http.client.HTTPResponse.__init__)


# --- the urllib openers ---------------------------------------------------------------------------


def _opener(proxy: _ConnectProxy, tls: _Tls | None = None) -> urllib.request.OpenerDirector:
    handlers: list[urllib.request.BaseHandler] = [urllib.request.ProxyHandler({"https": proxy.url})]
    if tls is not None:
        handlers.append(
            urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=tls.ca_file))
        )
    return build_strict_opener(*handlers)


@pytest.mark.parametrize("shape", list(_BARE_CR))
def test_a_bare_cr_in_the_connect_reply_is_refused_on_a_strict_opener(shape: str) -> None:
    with _ConnectProxy(_BARE_CR[shape]) as proxy, pytest.raises(MalformedReplyHeadError) as raised:
        _opener(proxy).open(_TARGET, timeout=5)
    _assert_connect_was_sent(proxy)
    assert proxy.after == [b""], "nothing may enter a tunnel whose opening reply was refused"
    # The same refusal a partner's reply head gets (BACKLOG #2052): fixed text, no head bytes.
    assert raised.value.reason == "a bare CR in the reply's status line or header block"
    assert "Proxy-Agent" not in str(raised.value)


@pytest.mark.parametrize("shape", list(_CLEAN))
def test_control_a_clean_connect_reply_still_tunnels(shape: str, tls: _Tls) -> None:
    """The tunnel opens, TLS runs inside it, and the target's reply is read through it."""
    with (
        _ConnectProxy(_CLEAN[shape], inner=tls.server) as proxy,
        _opener(proxy, tls).open(_TARGET, timeout=5) as resp,
    ):
        assert read_bounded(resp, connector="c") == _INNER_BODY
    _assert_connect_was_sent(proxy)
    assert len(proxy.inner_requests) == 1
    assert proxy.inner_requests[0].startswith(b"GET /ingest HTTP/1.1\r\n")


@pytest.mark.parametrize("shape", _TUNNEL_OPENING)
def test_control_without_the_construction_time_guard_the_same_reply_opens_the_tunnel(
    shape: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Mutation control. The reply is taken, and the client sends a TLS handshake record into the
    tunnel. The fake proxy then hangs up, so the open fails on the handshake, not on the head."""
    _undo_the_construction_time_guard(monkeypatch)
    with _ConnectProxy(_BARE_CR[shape]) as proxy, pytest.raises(urllib.error.URLError):
        _opener(proxy).open(_TARGET, timeout=5)
    _assert_connect_was_sent(proxy)
    assert proxy.after[0][:1] == b"\x16", "a TLS handshake record must have entered the tunnel"


def test_control_without_the_construction_time_guard_a_407_is_reported_by_its_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mutation control for the one shape that opens no tunnel: the lenient reader classifies the
    reply by a status code that sits in a head the strict reader refuses."""
    _undo_the_construction_time_guard(monkeypatch)
    with (
        _ConnectProxy(_BARE_CR["cr-on-a-407"]) as proxy,
        pytest.raises(urllib.error.URLError, match="Tunnel connection failed: 407"),
    ):
        _opener(proxy).open(_TARGET, timeout=5)


def test_the_response_reads_its_body_from_the_real_stream_after_begin() -> None:
    """The guard is on from construction and off once ``begin`` has read the head, so a CR inside
    a body is still the body's business."""

    class _Sock:
        def makefile(self, *a: object, **k: object) -> io.BytesIO:
            return io.BytesIO(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhe\rlo")

    resp = StrictHTTPResponse(_Sock())  # type: ignore[arg-type]
    assert type(resp.fp).__name__ == "_BareCRGuard"
    resp.begin()
    assert type(resp.fp).__name__ == "BytesIO"
    assert read_bounded(resp, connector="c") == b"he\rlo"


# --- a REST connection with proxy_url -------------------------------------------------------------


def _rest(proxy: _ConnectProxy) -> RestDestination:
    settings = Rest(url=_TARGET).settings
    settings["proxy_url"] = proxy.url
    dest = build_destination(
        Destination(name="OB_REST", type=ConnectorType.REST, settings=settings),
        egress=permitting(settings),
    )
    assert isinstance(dest, RestDestination)
    return dest


def test_a_rest_send_fails_as_a_delivery_error_on_a_bare_cr_connect_reply() -> None:
    """The refusal leaves ``send`` as the framing refusal itself, a ``DeliveryError``, so the
    delivery worker retries and dead-letters it as it does a refused partner reply head."""
    with _ConnectProxy(_BARE_CR["cr-in-a-header-line"]) as proxy:
        dest = _rest(proxy)
        with pytest.raises(DeliveryError) as raised:
            asyncio.run(dest.send('{"a": 1}'))
    assert isinstance(raised.value, MalformedReplyHeadError)
    _assert_connect_was_sent(proxy)
    assert proxy.after == [b""]


def test_control_a_rest_send_reaches_the_tls_handshake_without_the_guard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _undo_the_construction_time_guard(monkeypatch)
    with _ConnectProxy(_BARE_CR["cr-in-a-header-line"]) as proxy:
        dest = _rest(proxy)
        with pytest.raises(DeliveryError) as raised:
            asyncio.run(dest.send('{"a": 1}'))
    assert not isinstance(raised.value, MalformedReplyHeadError)
    assert proxy.after[0][:1] == b"\x16"


# --- the Vault hop --------------------------------------------------------------------------------

_VAULT_URL = f"https://{_HOST}:8200/v1/secret/data/mefor/ad"


@pytest.fixture
def vault_session() -> Iterator[Any]:
    """A ``requests`` session with the Vault hop's adapter on both schemes, reading no environment."""
    import requests

    from messagefoundry.transports.strict_requests import StrictReplyAdapter

    with requests.Session() as session:
        session.trust_env = False
        adapter = StrictReplyAdapter(
            connector="Vault test hop", ssl_context_factory=ssl.create_default_context
        )
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        yield session


@_needs_vault
@pytest.mark.parametrize("shape", list(_BARE_CR))
def test_a_bare_cr_in_the_connect_reply_is_refused_on_the_vault_hop(
    shape: str, vault_session: Any
) -> None:
    """urllib3 2.8.0 on this Python calls ``http.client``'s own ``_tunnel``, so the same guard
    covers it. The adapter names the refusal and does not leave it as a ``ConnectionError``."""
    with (
        _ConnectProxy(_BARE_CR[shape]) as proxy,
        pytest.raises(MalformedReplyHeadError, match="Vault test hop"),
    ):
        vault_session.get(_VAULT_URL, timeout=5, proxies={"https": proxy.url})
    _assert_connect_was_sent(proxy)
    assert proxy.after == [b""]


@_needs_vault
def test_control_a_clean_connect_reply_still_tunnels_on_the_vault_hop(
    tls: _Tls, vault_session: Any
) -> None:
    with _ConnectProxy(_CLEAN["one-header"], inner=tls.server) as proxy:
        response = vault_session.get(
            _VAULT_URL, timeout=5, proxies={"https": proxy.url}, verify=str(tls.ca_file)
        )
    assert response.status_code == 200
    assert response.content == _INNER_BODY
    _assert_connect_was_sent(proxy)


@_needs_vault
@pytest.mark.parametrize("shape", _TUNNEL_OPENING)
def test_control_without_the_guard_the_vault_hop_opens_the_tunnel(
    shape: str, vault_session: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    import requests

    _undo_the_construction_time_guard(monkeypatch)
    with (
        _ConnectProxy(_BARE_CR[shape]) as proxy,
        pytest.raises(requests.exceptions.RequestException),
    ):
        vault_session.get(_VAULT_URL, timeout=5, proxies={"https": proxy.url})
    assert proxy.after[0][:1] == b"\x16"
