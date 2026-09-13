# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``probe_tcp_reachable`` speaks the destination's own transport (BACKLOG #1178, ASVS 12.3.1).

The shared reachability probe used by ``test_connection`` on the socket destinations used to open a
plaintext socket unconditionally. On a ``tls=true`` MLLP destination that is the engine falling back
to an unencrypted protocol on a hop its own configuration says is encrypted -- and, the half an
operator feels, a broken certificate, CA or hostname passing a green connection test and then
failing every delivery, because the probe never performed the handshake the real dial does.

**The load-bearing test here is the negative one.** A probe that ACCEPTED an ``ssl_context`` and
ignored it would pass every "TLS server, TLS probe" assertion, because the plaintext probe passes
those too -- a TCP connect to a TLS listener returns cleanly on the client side and only the server
notices. So the suite pins the two cases whose answers DIFFER between a probe that handshakes and
one that does not: a TLS probe against a PLAINTEXT server must fail, and a verifying probe against a
wrong-named certificate must fail. ``test_a_plaintext_probe_cannot_tell_tls_from_cleartext``
demonstrates the defect itself, and is the reason those two exist.
"""

from __future__ import annotations

import asyncio
import datetime
import ipaddress
import ssl
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from messagefoundry.transports.base import DeliveryError, probe_tcp_reachable

pytestmark = pytest.mark.anyio


def _cert(
    tmp_path: Path, *, common_name: str, san: x509.SubjectAlternativeName
) -> tuple[Path, Path]:
    """Write a self-signed EC cert + key PEM; return (cert_path, key_path).

    ``san`` is a parameter rather than a fixed ``127.0.0.1`` so a WRONG-name certificate can be
    minted from the same helper -- the mismatch case is what proves ``server_hostname`` is threaded
    through, and a helper that could only mint the right name could not express it.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC))
        .not_valid_after(datetime.datetime(2040, 1, 1, tzinfo=datetime.UTC))
        .add_extension(san, critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / f"{common_name}-cert.pem"
    key_path = tmp_path / f"{common_name}-key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


def _localhost_cert(tmp_path: Path) -> tuple[Path, Path]:
    return _cert(
        tmp_path,
        common_name="localhost",
        san=x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
    )


def _wrong_name_cert(tmp_path: Path) -> tuple[Path, Path]:
    return _cert(
        tmp_path,
        common_name="not-the-host",
        san=x509.SubjectAlternativeName([x509.DNSName("not-the-host.invalid")]),
    )


async def _serve(*, ssl_context: ssl.SSLContext | None) -> tuple[asyncio.AbstractServer, int]:
    """Start a listener on an ephemeral loopback port that accepts and immediately drops."""

    async def _accept(_r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        w.close()

    server = await asyncio.start_server(_accept, "127.0.0.1", 0, ssl=ssl_context)
    return server, server.sockets[0].getsockname()[1]


def _server_ctx(cert: Path, key: Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    return ctx


def _verifying_client_ctx(ca: Path) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=str(ca))
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


# --- the defect this change fixes -------------------------------------------------------------


async def test_a_plaintext_probe_cannot_tell_tls_from_cleartext(tmp_path: Path) -> None:
    """A probe with NO context reports a TLS-only listener reachable without speaking TLS to it.

    This is the shipped behaviour the fix replaces, pinned so the reason for the keyword argument
    stays legible: the client's TCP connect returns cleanly and only the server ever notices that no
    handshake followed. It is also why the TLS-server-plus-TLS-probe assertion below proves nothing
    on its own.
    """
    cert, key = _localhost_cert(tmp_path)
    server, port = await _serve(ssl_context=_server_ctx(cert, key))
    try:
        await probe_tcp_reachable("127.0.0.1", port, 5.0, "TEST")  # no raise: reports "reachable"
    finally:
        server.close()
        await server.wait_closed()


# --- the two cases that discriminate a real handshake from an ignored argument -----------------


async def test_a_tls_probe_fails_against_a_plaintext_listener(tmp_path: Path) -> None:
    """Passing a context must actually handshake, so a cleartext peer must FAIL the probe.

    A ``probe_tcp_reachable`` that accepted ``ssl_context`` and dropped it would pass every other
    test in this file. This one it cannot pass.
    """
    cert, _key = _localhost_cert(tmp_path)
    server, port = await _serve(ssl_context=None)
    try:
        with pytest.raises(DeliveryError, match=r"(connect|TLS handshake) to 127\.0\.0\.1"):
            await probe_tcp_reachable(
                "127.0.0.1", port, 5.0, "TEST", ssl_context=_verifying_client_ctx(cert)
            )
    finally:
        server.close()
        await server.wait_closed()


async def test_a_verifying_probe_rejects_a_wrong_named_certificate(tmp_path: Path) -> None:
    """``server_hostname`` is threaded, so the probe verifies exactly what delivery verifies.

    Without it the handshake would still complete and the probe would pass -- verifying LESS than
    the hop it is testing, which is the failure mode a connection test exists to catch.
    """
    wrong_cert, wrong_key = _wrong_name_cert(tmp_path)
    server, port = await _serve(ssl_context=_server_ctx(wrong_cert, wrong_key))
    try:
        with pytest.raises(DeliveryError, match=r"(connect|TLS handshake) to 127\.0\.0\.1"):
            await probe_tcp_reachable(
                "127.0.0.1", port, 5.0, "TEST", ssl_context=_verifying_client_ctx(wrong_cert)
            )
    finally:
        server.close()
        await server.wait_closed()


# --- the fix works, and the plaintext connectors are untouched ---------------------------------


async def test_a_tls_probe_completes_the_handshake_against_a_matching_listener(
    tmp_path: Path,
) -> None:
    cert, key = _localhost_cert(tmp_path)
    server, port = await _serve(ssl_context=_server_ctx(cert, key))
    try:
        await probe_tcp_reachable(
            "127.0.0.1", port, 5.0, "TEST", ssl_context=_verifying_client_ctx(cert)
        )
    finally:
        server.close()
        await server.wait_closed()


async def test_the_default_stays_plaintext_for_connectors_that_have_no_tls() -> None:
    """TCP and X12 have zero ``ssl`` references, so their probe is honestly cleartext and must
    remain byte-identical: omitting the keyword opens the same plain socket as before."""
    server, port = await _serve(ssl_context=None)
    try:
        await probe_tcp_reachable("127.0.0.1", port, 5.0, "TEST")
    finally:
        server.close()
        await server.wait_closed()
