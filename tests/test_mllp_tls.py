# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""WP-13b — MLLP-over-TLS (ADR 0002): the per-connection SSL-context builder + a real TLS round-trip."""

from __future__ import annotations

import asyncio
import contextlib
import datetime
import ipaddress
import logging
import ssl
import sys
import time
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.config.wiring import MLLP, WiringError, redacted_settings
from messagefoundry.pipeline.wiring_runner import check_mllp_tls_exposure
from messagefoundry.transports import mllp as mllp_module
from messagefoundry.transports.base import DeliveryError
from messagefoundry.transports.mllp import (
    MLLPDestination,
    MLLPSource,
    _mllp_ssl_context,
    build_ack,
    frame,
)

ADT = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||100||DOE^JANE\r"


def _cert(tmp_path: Path) -> tuple[str, str]:
    """A self-signed EC cert (SAN 127.0.0.1, CA:TRUE so it doubles as the trust anchor) + key PEM."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC))
        .not_valid_after(datetime.datetime(2040, 1, 1, tzinfo=datetime.UTC))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cp, kp = tmp_path / "c.pem", tmp_path / "k.pem"
    cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    kp.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return str(cp), str(kp)


# --- _mllp_ssl_context -------------------------------------------------------


def test_no_tls_returns_none() -> None:
    assert _mllp_ssl_context({}, server=True) is None
    assert _mllp_ssl_context({"tls": False}, server=False) is None


def test_server_requires_cert() -> None:
    with pytest.raises(ValueError, match="tls_cert_file"):
        _mllp_ssl_context({"tls": True}, server=True)


def test_server_context_tls_1_2_no_mtls_by_default(tmp_path: Path) -> None:
    cert, key = _cert(tmp_path)
    ctx = _mllp_ssl_context({"tls": True, "tls_cert_file": cert, "tls_key_file": key}, server=True)
    assert ctx is not None
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
    assert ctx.verify_mode == ssl.CERT_NONE  # no client auth unless tls_ca_file is set


def test_server_mtls_requires_client_cert(tmp_path: Path) -> None:
    cert, key = _cert(tmp_path)
    ctx = _mllp_ssl_context(
        {"tls": True, "tls_cert_file": cert, "tls_key_file": key, "tls_ca_file": cert}, server=True
    )
    assert ctx is not None and ctx.verify_mode == ssl.CERT_REQUIRED


def test_client_default_verifies_with_hostname(tmp_path: Path) -> None:
    cert, _ = _cert(tmp_path)
    ctx = _mllp_ssl_context({"tls": True, "tls_ca_file": cert}, server=False)
    assert ctx is not None
    assert ctx.check_hostname is True
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2


def test_client_verify_false_refused_without_escape(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    with pytest.raises(ValueError, match="tls_verify=false"):
        _mllp_ssl_context({"tls": True, "tls_verify": False}, server=False)


def test_client_verify_false_allowed_with_escape(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MEFOR_ALLOW_INSECURE_TLS", "1")
    ctx = _mllp_ssl_context({"tls": True, "tls_verify": False}, server=False)
    assert ctx is not None
    assert ctx.check_hostname is False and ctx.verify_mode == ssl.CERT_NONE


# --- real TLS round-trip -----------------------------------------------------


@pytest.mark.parametrize("persistent", [True, False])
async def test_mllp_tls_round_trip_verified(tmp_path: Path, persistent: bool) -> None:
    # An inbound TLS listener + an outbound client that VERIFIES the server cert (against the pinned
    # self-signed CA) and its hostname (127.0.0.1 SAN). A message flows only over the encrypted,
    # verified channel — proving start_server(ssl=) / open_connection(ssl=, server_hostname=) are
    # wired — in both connection modes (ADR 0067 AC-12).
    cert, key = _cert(tmp_path)
    received: list[bytes] = []

    async def handler(raw: bytes) -> str:
        received.append(raw)
        return build_ack(raw, code="AA")

    source = MLLPSource(
        Source(
            type=ConnectorType.MLLP,
            settings={
                "host": "127.0.0.1",
                "port": 0,
                "tls": True,
                "tls_cert_file": cert,
                "tls_key_file": key,
            },
        )
    )
    await source.start(handler)
    try:
        dest = MLLPDestination(
            Destination(
                name="out",
                type=ConnectorType.MLLP,
                settings={
                    "host": "127.0.0.1",
                    "port": source.sockport,
                    "timeout_seconds": 5,
                    "tls": True,
                    "tls_ca_file": cert,
                    "tls_check_hostname": True,
                    "persistent": persistent,
                },
            )
        )
        try:
            await dest.send(ADT)  # returns only on a verified-TLS channel + positive ACK
        finally:
            await dest.aclose()
    finally:
        await source.stop()
    assert received == [ADT.encode("utf-8")]


async def test_mllp_plaintext_client_cannot_talk_to_tls_listener(tmp_path: Path) -> None:
    # A plaintext outbound to a TLS-only listener must fail (the bytes never reach the handler as a
    # valid frame) — confirms the listener really requires TLS, not that TLS is cosmetic.
    cert, key = _cert(tmp_path)
    received: list[bytes] = []

    async def handler(raw: bytes) -> str:
        received.append(raw)
        return build_ack(raw, code="AA")

    source = MLLPSource(
        Source(
            type=ConnectorType.MLLP,
            settings={
                "host": "127.0.0.1",
                "port": 0,
                "tls": True,
                "tls_cert_file": cert,
                "tls_key_file": key,
            },
        )
    )
    await source.start(handler)
    try:
        dest = MLLPDestination(
            Destination(
                name="out",
                type=ConnectorType.MLLP,
                settings={"host": "127.0.0.1", "port": source.sockport, "timeout_seconds": 3},
            )
        )
        from messagefoundry.transports import DeliveryError

        with pytest.raises(DeliveryError):
            await dest.send(ADT)
    finally:
        await source.stop()
    assert received == []  # the plaintext bytes never decoded into a message


# --- §0 exposed-gate: refuse non-loopback plaintext MLLP ----------------------


def _mllp_source(host: str, *, tls: bool = False) -> Source:
    return Source(type=ConnectorType.MLLP, settings={"host": host, "port": 2575, "tls": tls})


def test_exposed_gate_refuses_non_loopback_plaintext() -> None:
    with pytest.raises(WiringError, match="without TLS"):
        check_mllp_tls_exposure(_mllp_source("0.0.0.0"), "IB", allow_insecure_bind=False)


def test_exposed_gate_allows_loopback_plaintext() -> None:
    check_mllp_tls_exposure(_mllp_source("127.0.0.1"), "IB", allow_insecure_bind=False)  # no raise


def test_exposed_gate_allows_non_loopback_with_tls() -> None:
    check_mllp_tls_exposure(_mllp_source("0.0.0.0", tls=True), "IB", allow_insecure_bind=False)


def test_exposed_gate_allows_non_loopback_plaintext_with_escape() -> None:
    # The dev escape downgrades the refuse to a (logged) warning — no raise.
    check_mllp_tls_exposure(_mllp_source("0.0.0.0"), "IB", allow_insecure_bind=True)


def test_exposed_gate_ignores_non_mllp() -> None:
    # TCP/X12/FILE listeners aren't MLLP, so this gate doesn't touch them (out of ADR-0002 scope).
    src = Source(type=ConnectorType.FILE, settings={"directory": "x"})
    check_mllp_tls_exposure(src, "IB", allow_insecure_bind=False)  # no raise


# --- tls_key_password: passphrase-encrypted private keys (container parity with the API) -----------


def _encrypted_cert(tmp_path: Path, passphrase: str) -> tuple[str, str]:
    """A self-signed EC cert + a private key PEM **encrypted** with ``passphrase`` (PKCS#8)."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC))
        .not_valid_after(datetime.datetime(2040, 1, 1, tzinfo=datetime.UTC))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cp, kp = tmp_path / "enc-c.pem", tmp_path / "enc-k.pem"
    cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    kp.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(passphrase.encode("utf-8")),
        )
    )
    return str(cp), str(kp)


def test_server_loads_encrypted_key_with_password(tmp_path: Path) -> None:
    cert, key = _encrypted_cert(tmp_path, "s3cr3t-pass")
    ctx = _mllp_ssl_context(
        {
            "tls": True,
            "tls_cert_file": cert,
            "tls_key_file": key,
            "tls_key_password": "s3cr3t-pass",
        },
        server=True,
    )
    assert ctx is not None
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2


def test_server_encrypted_key_wrong_password_fails(tmp_path: Path) -> None:
    # Proves the passphrase is actually applied: a WRONG password can't decrypt the key → ssl.SSLError.
    cert, key = _encrypted_cert(tmp_path, "s3cr3t-pass")
    with pytest.raises(ssl.SSLError):
        _mllp_ssl_context(
            {"tls": True, "tls_cert_file": cert, "tls_key_file": key, "tls_key_password": "WRONG"},
            server=True,
        )


def test_server_encrypted_key_missing_password_raises_not_prompts(tmp_path: Path) -> None:
    # An encrypted key with NO tls_key_password must fail deterministically (ssl.SSLError), NOT fall back
    # to OpenSSL's blocking TTY prompt — there is no TTY under a service account / in a container. The
    # empty-bytes password callback guarantees a raise here (this test would HANG without that guard).
    cert, key = _encrypted_cert(tmp_path, "s3cr3t-pass")
    with pytest.raises(ssl.SSLError):
        _mllp_ssl_context({"tls": True, "tls_cert_file": cert, "tls_key_file": key}, server=True)


def test_outbound_mtls_loads_encrypted_client_key_with_password(tmp_path: Path) -> None:
    # The same passphrase path on the OUTBOUND client-identity (mTLS) cert.
    cert, key = _encrypted_cert(tmp_path, "client-pass")
    ctx = _mllp_ssl_context(
        {
            "tls": True,
            "tls_ca_file": cert,  # verify the peer against this anchor
            "tls_cert_file": cert,  # present a client identity (mTLS)
            "tls_key_file": key,
            "tls_key_password": "client-pass",
        },
        server=False,
    )
    assert ctx is not None and ctx.verify_mode == ssl.CERT_REQUIRED


def test_factory_carries_tls_key_password_and_redacts_it() -> None:
    spec = MLLP(
        port=2575, tls=True, tls_cert_file="c.pem", tls_key_file="k.pem", tls_key_password="pw"
    )
    assert spec.settings["tls_key_password"] == "pw"
    # Defence in depth: an inline passphrase is scrubbed from the /metadata view (it should be an env() ref).
    assert redacted_settings(spec.settings)["tls_key_password"] == "***"


def _ca_and_crl(tmp_path: Path, *, revoked_serial: int = 4000) -> str:
    """A CA bundled with its own fresh CRL, written as one PEM -- it loads only where the same CA is loaded first (BACKLOG #1890).

    Separate from :func:`_cert` because that one is self-signed-and-CA:TRUE for convenience, while a
    CRL has to be signed by the key whose certificate is the trust anchor.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mllp-crl-ca")])
    now = datetime.datetime.now(datetime.UTC)
    ca = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca.subject)
        .last_update(now - datetime.timedelta(days=1))
        .next_update(now + datetime.timedelta(days=30))
        .add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(revoked_serial)
            .revocation_date(now - datetime.timedelta(hours=1))
            .build()
        )
        .sign(key, hashes.SHA256())
    )
    bundle = tmp_path / "ca_and_crl.pem"
    bundle.write_bytes(
        ca.public_bytes(serialization.Encoding.PEM) + crl.public_bytes(serialization.Encoding.PEM)
    )
    return str(bundle)


def test_server_mtls_loads_the_crl_when_configured(tmp_path: Path) -> None:
    # BACKLOG #1005. The setting must reach the trust store, not merely be accepted by the factory.
    # cert_store_stats()["crl"] is the only thing separating "loaded" from "silently ignored" --
    # a context can carry the check flag with zero CRLs and then refuse EVERY client.
    cert, key = _cert(tmp_path)
    bundle = _ca_and_crl(tmp_path)
    ctx = _mllp_ssl_context(
        {
            "tls": True,
            "tls_cert_file": cert,
            "tls_key_file": key,
            "tls_ca_file": bundle,
            "tls_crl_file": bundle,
        },
        server=True,
    )
    assert ctx is not None
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.cert_store_stats()["crl"] >= 1
    assert ctx.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


def test_server_mtls_without_a_crl_does_no_revocation_checking(tmp_path: Path) -> None:
    # NEGATIVE CONTROL, and it pins the SHIPPED GAP this item is filed against: mTLS on, chain
    # verified, RFC 5280 strictness applied -- and no revocation whatsoever, so a partner
    # certificate revoked this morning keeps authenticating until its notAfter.
    #
    # If this ever starts failing, revocation arrived by some other route and the item's premise
    # needs re-deriving. Do not relax it to make it pass.
    cert, key = _cert(tmp_path)
    ctx = _mllp_ssl_context(
        {"tls": True, "tls_cert_file": cert, "tls_key_file": key, "tls_ca_file": cert},
        server=True,
    )
    assert ctx is not None
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert not (ctx.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF)


def test_a_crl_without_mtls_is_not_loaded(tmp_path: Path) -> None:
    # PLACEMENT GUARD. The CRL call lives INSIDE the mTLS branch: with no client certificate
    # required there is nothing to revoke, and loading one anyway would set a check flag on a
    # context that never asks for a peer certificate.
    cert, key = _cert(tmp_path)
    ctx = _mllp_ssl_context(
        {
            "tls": True,
            "tls_cert_file": cert,
            "tls_key_file": key,
            "tls_crl_file": _ca_and_crl(tmp_path),
        },
        server=True,
    )
    assert ctx is not None
    assert ctx.verify_mode == ssl.CERT_NONE
    assert not (ctx.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF)


# --- the connection test speaks the hop's own transport (#1178, ASVS 12.3.1) -------------------


async def test_test_connection_handshakes_against_a_tls_listener(tmp_path: Path) -> None:
    """A verified TLS destination's reachability probe completes the handshake, not just the TCP
    connect. Passing on its own proves little -- the plaintext probe passed here too, because a
    TCP connect to a TLS listener returns cleanly on the client side. Its partner below is the
    test that discriminates."""
    cert, key = _cert(tmp_path)
    source = MLLPSource(
        Source(
            type=ConnectorType.MLLP,
            settings={
                "host": "127.0.0.1",
                "port": 0,
                "tls": True,
                "tls_cert_file": cert,
                "tls_key_file": key,
            },
        )
    )
    await source.start(lambda raw: build_ack(raw, code="AA"))
    try:
        dest = MLLPDestination(
            Destination(
                name="out",
                type=ConnectorType.MLLP,
                settings={
                    "host": "127.0.0.1",
                    "port": source.sockport,
                    "timeout_seconds": 5,
                    "tls": True,
                    "tls_ca_file": cert,
                    "tls_check_hostname": True,
                },
            )
        )
        try:
            await dest.test_connection()
        finally:
            await dest.aclose()
    finally:
        await source.stop()


async def test_test_connection_on_a_tls_destination_fails_against_a_cleartext_peer(
    tmp_path: Path,
) -> None:
    """THE DISCRIMINATOR. Before #1178 this passed: the probe opened a plaintext socket, so a
    tls=true destination reported a cleartext peer reachable and the operator learned nothing until
    the first delivery failed. Two things would now have to be true for it to pass again -- the
    probe would have to stop carrying the context, or stop handshaking with it."""
    cert, _key = _cert(tmp_path)
    plaintext = MLLPSource(
        Source(type=ConnectorType.MLLP, settings={"host": "127.0.0.1", "port": 0})
    )
    await plaintext.start(lambda raw: build_ack(raw, code="AA"))
    try:
        dest = MLLPDestination(
            Destination(
                name="out",
                type=ConnectorType.MLLP,
                settings={
                    "host": "127.0.0.1",
                    "port": plaintext.sockport,
                    "timeout_seconds": 5,
                    "tls": True,
                    "tls_ca_file": cert,
                    "tls_check_hostname": True,
                },
            )
        )
        try:
            with pytest.raises(
                DeliveryError, match=r"MLLP (connect|TLS handshake) to 127\.0\.0\.1"
            ):
                await dest.test_connection()
        finally:
            await dest.aclose()
    finally:
        await plaintext.stop()


async def test_a_plaintext_destination_still_probes_plaintext(tmp_path: Path) -> None:
    """The control for the pair above, and the guarantee for TCP and X12: a destination with no
    context passes none, so its probe is the same plain socket as before."""
    plaintext = MLLPSource(
        Source(type=ConnectorType.MLLP, settings={"host": "127.0.0.1", "port": 0})
    )
    await plaintext.start(lambda raw: build_ack(raw, code="AA"))
    try:
        dest = MLLPDestination(
            Destination(
                name="out",
                type=ConnectorType.MLLP,
                settings={
                    "host": "127.0.0.1",
                    "port": plaintext.sockport,
                    "timeout_seconds": 5,
                },
            )
        )
        try:
            assert dest._ssl is None
            await dest.test_connection()
        finally:
            await dest.aclose()
    finally:
        await plaintext.stop()


# --- a socket that never handshakes is bounded in time (BACKLOG #1606) ---------------------------
#
# `_on_client` runs only once the TLS handshake completes, so until then a connection is in neither
# `_clients` nor the `max_connections` count. These tests pin the two bounds that now cover that
# window: the handshake timeout closes a silent socket, and stop() closes one still waiting on it.
# Each waits on an EVENT (the socket closing, or asyncio accepting it) under a generous deadline, and
# no real client ever has to beat a shortened bound, so a slow runner makes them slower, not red.


def _tls_source(tmp_path: Path) -> tuple[MLLPSource, str]:
    """A TLS listener, and the cert a client pins to reach it."""
    cert, key = _cert(tmp_path)
    source = MLLPSource(
        Source(
            type=ConnectorType.MLLP,
            settings={
                "host": "127.0.0.1",
                "port": 0,
                "tls": True,
                "tls_cert_file": cert,
                "tls_key_file": key,
            },
        )
    )
    return source, cert


async def _closed_by_listener(reader: asyncio.StreamReader, *, within: float) -> None:
    """Fail unless the listener closes this raw socket within ``within`` seconds. The listener
    aborts the transport, so the close arrives as EOF on some platforms and as a reset on others
    (the Windows Proactor); both mean the socket is gone. Like `_wait_until_dropped` in
    test_connection_event_emit.py, but it also accepts an abort and names a timeout plainly."""
    try:
        data = await asyncio.wait_for(reader.read(1024), timeout=within)
    except TimeoutError:
        pytest.fail(f"the unhandshaken socket was still open after {within} s")
    except ConnectionError:
        data = b""
    # A TLS server sends nothing before the ClientHello, so any byte here is a different defect.
    assert data == b""


async def _close_raw(writer: asyncio.StreamWriter) -> None:
    """Close the test's own raw socket inside the test that opened it. The suite shares one event
    loop, so an unawaited close would finish during some later, unrelated test."""
    writer.close()
    with contextlib.suppress(TimeoutError, ConnectionError):
        await asyncio.wait_for(writer.wait_closed(), timeout=mllp_module._CLIENT_SHUTDOWN_GRACE)


async def _accepted(source: MLLPSource, count: int) -> None:
    """Wait until asyncio has ACCEPTED ``count`` connections on the listener.

    A client-side connect returns once the kernel completes it, which can be before the event loop
    accepts it. A stop() racing that gap closes the listening socket instead, and the stop test
    would pass without exercising the path it names. ``Server._clients`` is CPython-private, so a
    rename fails this loudly rather than letting the test pass vacuously."""
    server = source._server
    assert server is not None
    deadline = time.monotonic() + 5.0
    while len(server._clients) < count:  # type: ignore[attr-defined]
        if time.monotonic() > deadline:
            pytest.fail(f"the listener never accepted {count} connection(s)")
        await asyncio.sleep(0.01)


async def test_a_socket_that_never_handshakes_is_closed_at_the_handshake_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Without a timeout asyncio's default of 60 s applied, so the read below hit its 5 s deadline.
    monkeypatch.setattr(mllp_module, "_TLS_HANDSHAKE_TIMEOUT", 0.3)
    source, cert = _tls_source(tmp_path)
    received: list[bytes] = []

    async def handler(raw: bytes) -> str:
        received.append(raw)
        return build_ack(raw, code="AA")

    await source.start(handler)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
        try:
            await _closed_by_listener(reader, within=5.0)
        finally:
            await _close_raw(writer)
    finally:
        await source.stop()
    # The same listener, restarted with the real bound, still serves a real TLS client. Restarted
    # rather than reused so that client never races the 0.3 s bound set above.
    monkeypatch.setattr(mllp_module, "_TLS_HANDSHAKE_TIMEOUT", 10.0)
    await source.start(handler)
    try:
        dest = MLLPDestination(
            Destination(
                name="out",
                type=ConnectorType.MLLP,
                settings={
                    "host": "127.0.0.1",
                    "port": source.sockport,
                    "timeout_seconds": 5,
                    "tls": True,
                    "tls_ca_file": cert,
                    "tls_check_hostname": True,
                },
            )
        )
        try:
            await dest.send(ADT)
        finally:
            await dest.aclose()
    finally:
        await source.stop()
    assert received == [ADT.encode("utf-8")]


async def test_stop_closes_a_socket_still_waiting_on_its_handshake(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # Pinned far above the shutdown grace, so only stop() can close this socket in time. Left at a
    # value below the grace, the handshake bound alone would release wait_closed() and this test
    # would pass with the close_clients() call deleted.
    monkeypatch.setattr(mllp_module, "_TLS_HANDSHAKE_TIMEOUT", 60.0)
    source, _cert_path = _tls_source(tmp_path)

    async def handler(raw: bytes) -> str:
        return build_ack(raw, code="AA")

    await source.start(handler)
    stopped = False
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
        try:
            await _accepted(source, 1)
            assert source._clients == set()  # outside the listener's own set, as the item says
            started = time.monotonic()
            with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.mllp"):
                await source.stop()
            stopped = True
            # Before the fix stop() spent the whole shutdown grace in wait_closed() and gave up.
            assert time.monotonic() - started < mllp_module._CLIENT_SHUTDOWN_GRACE
            assert "exceeded shutdown grace" not in caplog.text
            await _closed_by_listener(reader, within=mllp_module._CLIENT_SHUTDOWN_GRACE)
        finally:
            await _close_raw(writer)
    finally:
        if not stopped:
            await source.stop()


@pytest.mark.parametrize("tls", [True, False])
async def test_the_tls_bounds_reach_start_server_only_with_tls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tls: bool
) -> None:
    """The handshake and close-exchange bounds reach asyncio with TLS, and neither does without it,
    since asyncio refuses both when there is no `ssl`. The close-exchange bound has no behavioural
    test of its own: it needs a peer that ignores close_notify, and asyncio's default of 30 s would
    make the red arm of such a test slow."""
    seen: dict[str, object] = {}
    real_start_server = asyncio.start_server

    async def spy(*args: object, **kwargs: object) -> asyncio.Server:
        seen.update(kwargs)
        return await real_start_server(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(asyncio, "start_server", spy)  # mllp calls it through the module
    if tls:
        source, _cert_path = _tls_source(tmp_path)
    else:
        source = MLLPSource(
            Source(type=ConnectorType.MLLP, settings={"host": "127.0.0.1", "port": 0})
        )

    async def handler(raw: bytes) -> str:
        return build_ack(raw, code="AA")

    await source.start(handler)
    await source.stop()
    if tls:
        assert seen["ssl_handshake_timeout"] == mllp_module._TLS_HANDSHAKE_TIMEOUT
        assert seen["ssl_shutdown_timeout"] == mllp_module._TLS_SHUTDOWN_TIMEOUT
    else:
        assert seen.get("ssl_handshake_timeout") is None
        assert seen.get("ssl_shutdown_timeout") is None


# --- stop() on a loop whose server has no close_clients() (BACKLOG #1606) ------------------------
#
# uvicorn runs the engine on uvloop wherever it is installed, and `uvicorn[standard]` installs it for
# CPython outside Windows. uvloop's Server (0.22.1) has no close_clients(). stop() called it
# unguarded, so on Linux every reload failed at its first listener: that listener stayed unbound and
# none was restarted. The connscale smoke caught it on ubuntu only, as "connection(s) never came back
# after the reload probe". The suite's own loop is the stdlib one on every platform, so without these
# tests nothing in it runs stop() against that server shape.


class _ServerWithoutCloseClients:
    """A stdlib server seen through uvloop 0.22.1's Server surface: no close_clients()."""

    def __init__(self, inner: asyncio.Server) -> None:
        self._inner = inner

    @property
    def sockets(self) -> tuple[object, ...]:
        return tuple(self._inner.sockets)

    def close(self) -> None:
        self._inner.close()

    async def wait_closed(self) -> None:
        await self._inner.wait_closed()


def _plain_source() -> MLLPSource:
    return MLLPSource(Source(type=ConnectorType.MLLP, settings={"host": "127.0.0.1", "port": 0}))


async def _ack(raw: bytes) -> str:
    return build_ack(raw, code="AA")


async def _in_handler(source: MLLPSource, count: int) -> None:
    """Wait until ``count`` connections have reached `_on_client`, on any event loop."""
    deadline = time.monotonic() + 5.0
    while len(source._clients) < count:
        if time.monotonic() > deadline:
            pytest.fail(f"{count} connection(s) never reached the listener's handler")
        await asyncio.sleep(0.01)


async def _served(source: MLLPSource) -> None:
    """A real client gets a message through ``source``."""
    dest = MLLPDestination(
        Destination(
            name="out",
            type=ConnectorType.MLLP,
            settings={"host": "127.0.0.1", "port": source.sockport, "timeout_seconds": 5},
        )
    )
    try:
        await dest.send(ADT)
    finally:
        await dest.aclose()


async def test_stop_works_when_the_server_has_no_close_clients() -> None:
    source = _plain_source()
    await source.start(_ack)
    reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
    try:
        await _in_handler(source, 1)  # so stop() meets a live connection, not a kernel backlog
        assert source._server is not None
        source._server = _ServerWithoutCloseClients(source._server)  # type: ignore[assignment]
        # Before the fix this raised AttributeError, after closing the listening socket.
        await source.stop()
        await _closed_by_listener(reader, within=mllp_module._CLIENT_SHUTDOWN_GRACE)
    finally:
        await _close_raw(writer)
    # The same instance comes back, as a listener restarted in place does.
    await source.start(_ack)
    try:
        await _served(source)
    finally:
        await source.stop()


async def test_a_connection_reaching_the_handler_after_stop_is_refused_unread() -> None:
    """On uvloop stop() cannot close a socket still in its TLS handshake, so one can finish it after
    stop() began and reach `_on_client`. It must be closed there, never counted, tracked or read."""
    received: list[bytes] = []

    async def handler(raw: bytes) -> str:
        received.append(raw)
        return build_ack(raw, code="AA")

    source = _plain_source()
    await source.start(handler)
    await source.stop()

    closed: list[bool] = []

    class _Writer:
        def close(self) -> None:
            closed.append(True)

    reader = asyncio.StreamReader()
    reader.feed_data(frame(ADT))
    reader.feed_eof()
    await source._on_client(reader, _Writer())  # type: ignore[arg-type]
    assert closed == [True]
    assert received == []
    assert source._clients == set()
    assert source._client_tasks == set()
    # A restart of the same instance serves again.
    await source.start(handler)
    try:
        await _served(source)
    finally:
        await source.stop()
    assert received == [ADT.encode("utf-8")]


@pytest.mark.skipif(sys.platform == "win32", reason="uvloop does not run on Windows")
@pytest.mark.parametrize("tls", [False, True])
def test_stop_and_restart_on_uvloop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tls: bool
) -> None:
    """The real loop, not a stand-in for it. It skips where uvloop is not installed. With TLS the
    socket never handshakes, so stop() cannot close it on uvloop; the handshake bound, shortened
    here, is what closes it."""
    uvloop = pytest.importorskip("uvloop")
    monkeypatch.setattr(mllp_module, "_TLS_HANDSHAKE_TIMEOUT", 0.5)

    async def scenario() -> None:
        source = _tls_source(tmp_path)[0] if tls else _plain_source()
        await source.start(_ack)
        reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
        try:
            if tls:
                # Nothing public counts a socket still in its handshake, so give the loop a moment
                # to accept it. On a runner too slow for that, the close below is the listening
                # socket's reset rather than the bound, and the test passes without reaching it.
                await asyncio.sleep(0.2)
            else:
                await _in_handler(source, 1)
            started = time.monotonic()
            await source.stop()
            assert time.monotonic() - started < mllp_module._CLIENT_SHUTDOWN_GRACE
            await _closed_by_listener(reader, within=5.0)
        finally:
            await _close_raw(writer)
        plain = _plain_source()
        await plain.start(_ack)
        try:
            await _served(plain)
        finally:
            await plain.stop()

    asyncio.run(scenario(), loop_factory=uvloop.new_event_loop)
