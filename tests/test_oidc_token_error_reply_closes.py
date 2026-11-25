# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``exchange_code`` lets go of the token endpoint's TLS socket when the endpoint refuses (BACKLOG
#6903).

An HTTP error status, or a 3xx the no-redirect handler declines, reaches ``exchange_code`` as a
``urllib.error.HTTPError`` that holds the unread reply and, through it, the socket. These tests
drive the production opener, ``build_idp_opener``, over real TLS on loopback, with the garbage
collector off, and ask the SERVER whether the client's side of the connection closed. A socket
that only a collection would release reads as still open.

The positive control holds the ``HTTPError`` the way a leak would, and the same instrument must
then read the connection as open. Without it, a server that saw every connection close, whatever
the client did, would pass the arms. All certificates are synthetic and made per test.
"""

from __future__ import annotations

import contextlib
import datetime
import gc
import ipaddress
import socket
import ssl
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from messagefoundry.auth import oidc
from messagefoundry.auth.oidc_http import build_idp_opener

#: How long the server waits for the client to close after it has sent the whole reply. Generous,
#: so a slow runner cannot read a late close as a leak. A close ends the wait at once, so the
#: margin costs a passing arm nothing.
_CLOSE_WAIT_SECONDS = 10.0

#: The control's wait. Only long enough to show a held socket stays open.
_CONTROL_WAIT_SECONDS = 1.0

_ERROR_BODY = b'{"error": "invalid_grant"}'
_REFUSED_400 = (
    b"HTTP/1.1 400 Bad Request\r\n"
    b"Content-Type: application/json\r\n"
    b"Content-Length: %d\r\n"
    b"\r\n" % len(_ERROR_BODY)
) + _ERROR_BODY

_REDIRECT_302 = (
    b"HTTP/1.1 302 Found\r\n"
    b"Location: https://127.0.0.1:1/elsewhere\r\n"
    b"Content-Length: 5\r\n"
    b"\r\n"
    b"moved"
)


def _ca() -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """A throwaway CA carrying the key usage and key identifier a strict verifier asks for.
    Synthetic."""
    now = datetime.datetime.now(datetime.UTC)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mefor-6903-test-ca")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _leaf_for_loopback(
    tmp_path: Path, ca_key: ec.EllipticCurvePrivateKey, ca: x509.Certificate
) -> ssl.SSLContext:
    """A server context presenting a leaf for ``127.0.0.1``, issued by ``ca``. Synthetic."""
    now = datetime.datetime.now(datetime.UTC)
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]))
        .issuer_name(ca.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=10))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "leaf.crt", tmp_path / "leaf.key"
    cert_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(str(cert_path), str(key_path))
    return server


def _read_request(conn: ssl.SSLSocket) -> None:
    """Read one request, its body included, so the reply is not sent over unread bytes."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = conn.recv(4096)
        if not chunk:
            return
        buf += chunk
    head, _, body = buf.partition(b"\r\n\r\n")
    for line in head.split(b"\r\n"):
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            want = int(value.strip())
            while len(body) < want:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                body += chunk


def _client_side_after(conn: ssl.SSLSocket, wait: float) -> str:
    """``"closed"`` once the client's side of ``conn`` ends within ``wait`` seconds, else
    ``"open"``. A clean EOF, a ragged one and a reset all mean the client let the socket go."""
    conn.settimeout(wait)
    try:
        data = conn.recv(1)
    except TimeoutError:
        return "open"
    except (ssl.SSLError, ConnectionError):
        return "closed"
    return "closed" if data == b"" else "sent more"


@contextlib.contextmanager
def _tls_endpoint(
    tmp_path: Path, reply: bytes, *, wait: float
) -> Iterator[tuple[str, str, list[str]]]:
    """Serve ``reply`` to one TLS request on loopback, then watch the client's side for ``wait``
    seconds. Yields the endpoint URL, the CA anchor path, and a list the server appends its one
    reading to."""
    ca_key, ca = _ca()
    anchor = tmp_path / "ca.pem"
    anchor.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    server_ctx = _leaf_for_loopback(tmp_path, ca_key, ca)
    listener = socket.create_server(("127.0.0.1", 0))
    listener.settimeout(10)
    port = listener.getsockname()[1]
    seen: list[str] = []

    def run() -> None:
        with listener:
            try:
                raw, _ = listener.accept()
            except TimeoutError:
                seen.append("no connection")
                return
            raw.settimeout(10)
            with server_ctx.wrap_socket(raw, server_side=True) as conn:
                _read_request(conn)
                conn.sendall(reply)
                seen.append(_client_side_after(conn, wait))

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    try:
        yield f"https://127.0.0.1:{port}/token", str(anchor), seen
    finally:
        thread.join(timeout=wait + 15)


def _exchange(url: str, opener: urllib.request.OpenerDirector) -> None:
    oidc.exchange_code(
        token_endpoint=url,
        client_id="synthetic-client",
        client_auth=None,
        code="synthetic-code",
        redirect_uri="https://127.0.0.1/cb",
        code_verifier="synthetic-verifier",
        opener=opener,
        timeout=10.0,
    )


@contextlib.contextmanager
def _collector_off() -> Iterator[None]:
    was = gc.isenabled()
    gc.collect()  # start clean, so nothing an earlier test left behind is freed mid-arm
    gc.disable()
    try:
        yield
    finally:
        if was:
            gc.enable()


@pytest.mark.parametrize(
    ("reply", "status"),
    [(_REFUSED_400, 400), (_REDIRECT_302, 302)],
    ids=["http-400", "declined-302"],
)
def test_a_refused_token_exchange_closes_its_tls_socket_without_a_collection(
    tmp_path: Path, reply: bytes, status: int
) -> None:
    """RED when: the ``HTTPError`` arm, or anything it hands the reply to, keeps the reply alive
    after ``exchange_code`` raises, so only the garbage collector would close the socket."""
    with _collector_off():
        with _tls_endpoint(tmp_path, reply, wait=_CLOSE_WAIT_SECONDS) as (url, anchor, seen):
            opener = build_idp_opener(anchor, enforcing=False)
            with pytest.raises(oidc.TokenRefusedError) as raised:
                _exchange(url, opener)
        assert raised.value.status == status
        assert seen == ["closed"], "the client's TLS socket outlived exchange_code"


def test_the_instrument_reads_a_held_error_reply_as_open(tmp_path: Path) -> None:
    """POSITIVE CONTROL. An ``HTTPError`` still referenced keeps its socket open, and the server
    reads that as open. Without this, a server that read every connection as closed would pass the
    arms above."""
    held: list[urllib.error.HTTPError] = []
    with _collector_off():
        try:
            with _tls_endpoint(tmp_path, _REFUSED_400, wait=_CONTROL_WAIT_SECONDS) as (
                url,
                anchor,
                seen,
            ):
                opener = build_idp_opener(anchor, enforcing=False)
                req = urllib.request.Request(url, data=b"x=1", method="POST")  # noqa: S310
                try:
                    opener.open(req, timeout=10.0)
                except urllib.error.HTTPError as exc:
                    held.append(exc)
            assert seen == ["open"], "a held error reply must read as an open socket"
        finally:
            for kept in held:
                kept.close()
    assert len(held) == 1 and held[0].code == 400
