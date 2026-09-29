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
from collections.abc import Callable
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.config.wiring import MLLP, WiringError, redacted_settings
from messagefoundry.keywrap import KeyWrapRefused
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
from tests._approved_key_wrap import approved_pkcs8_pem

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
    # The approved wrap: the loader refuses BestAvailableEncryption's 2048 iterations (#1352).
    kp.write_bytes(approved_pkcs8_pem(key, passphrase))
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
    # An encrypted key with NO tls_key_password must fail deterministically, NOT fall back to
    # OpenSSL's blocking TTY prompt — there is no TTY under a service account / in a container. Since
    # BACKLOG #1352 the key-wrap check refuses it before OpenSSL reads the key; the empty-bytes
    # password callback stays behind it as the backstop.
    cert, key = _encrypted_cert(tmp_path, "s3cr3t-pass")
    with pytest.raises(KeyWrapRefused, match="no passphrase is configured"):
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
# These tests pin the two TIME bounds on a socket that has not finished its handshake: the handshake
# timeout closes a silent socket, and stop() closes one still waiting on it. The COUNT bounds on the
# same socket are pinned in the section at the end of this file.
# Each waits on an EVENT (the socket closing, or asyncio accepting it) under a generous deadline, and
# no real client ever has to beat a shortened bound, so a slow runner makes them slower, not red.


def _tls_source(tmp_path: Path, **extra: object) -> tuple[MLLPSource, str]:
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
                **extra,
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


@pytest.mark.parametrize("mode", ["plain", "listener_tls", "loop_tls"])
async def test_the_tls_bounds_reach_whichever_side_runs_the_handshake(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    """On the stdlib loop the listener binds plain TCP and upgrades each admitted socket itself
    (BACKLOG #1606), so the handshake and close-exchange bounds reach ``start_tls``. On any other
    loop (``loop_tls``, forced here, which is what uvloop gets) the loop runs the handshake and the
    bounds reach ``start_server``. Without TLS neither sees them. A real TLS client gets a message
    through in both TLS modes. The close-exchange bound has no behavioural test of its own: it needs
    a peer that ignores close_notify, and asyncio's default of 30 s would make the red arm of such a
    test slow."""
    tls = mode != "plain"
    if mode == "loop_tls":
        monkeypatch.setattr(mllp_module, "_upgrades_tls_itself", lambda _loop: False)
    served: dict[str, object] = {}
    upgraded: list[dict[str, object]] = []
    real_start_server = asyncio.start_server
    real_start_tls = asyncio.StreamWriter.start_tls

    async def spy_server(*args: object, **kwargs: object) -> asyncio.Server:
        served.update(kwargs)
        return await real_start_server(*args, **kwargs)  # type: ignore[arg-type]

    async def spy_tls(self: asyncio.StreamWriter, *args: object, **kwargs: object) -> None:
        upgraded.append(kwargs)
        await real_start_tls(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(asyncio, "start_server", spy_server)  # mllp calls it through the module
    monkeypatch.setattr(asyncio.StreamWriter, "start_tls", spy_tls)
    cert: str | None = None
    if tls:
        source, cert = _tls_source(tmp_path)
    else:
        source = _plain_source()
    await source.start(_ack)
    try:
        settings: dict[str, object] = {
            "host": "127.0.0.1",
            "port": source.sockport,
            "timeout_seconds": 5,
        }
        if cert is not None:
            settings.update(tls=True, tls_ca_file=cert, tls_check_hostname=True)
        dest = MLLPDestination(Destination(name="out", type=ConnectorType.MLLP, settings=settings))
        try:
            await dest.send(ADT)
        finally:
            await dest.aclose()
    finally:
        await source.stop()
    bounds = {
        "ssl_handshake_timeout": mllp_module._TLS_HANDSHAKE_TIMEOUT,
        "ssl_shutdown_timeout": mllp_module._TLS_SHUTDOWN_TIMEOUT,
    }
    if mode == "loop_tls":
        assert served["ssl"] is not None
        assert {k: served[k] for k in bounds} == bounds
        assert upgraded == []
        return
    assert served.get("ssl") is None
    assert served.get("ssl_handshake_timeout") is None
    # The destination's own client-side handshake does not go through StreamWriter.start_tls, so
    # the one call seen is the listener's.
    assert upgraded == ([bounds] if tls else [])


def test_only_the_stdlib_loop_upgrades_tls_itself() -> None:
    """uvloop's Loop is an AbstractEventLoop and not a BaseEventLoop, so this is what sends it to the
    loop-level handshake; see `_upgrades_tls_itself` for why."""

    class _OtherLoop(asyncio.AbstractEventLoop):
        pass

    stdlib = asyncio.new_event_loop()
    try:
        assert mllp_module._upgrades_tls_itself(stdlib) is True
    finally:
        stdlib.close()
    assert mllp_module._upgrades_tls_itself(_OtherLoop()) is False


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
    """The real loop, not a stand-in for it. It skips where uvloop is not installed. uvloop keeps the
    loop-level TLS handshake (`_upgrades_tls_itself`), so with TLS a socket that never handshakes is
    outside the listener's own set and stop() cannot close it there; the handshake bound, shortened
    here, is what closes it. A real TLS client then gets a message through a TLS listener on this
    loop, which is the check that the loop-level path still serves."""
    uvloop = pytest.importorskip("uvloop")
    monkeypatch.setattr(mllp_module, "_TLS_HANDSHAKE_TIMEOUT", 0.5)

    async def scenario() -> None:
        source, cert = _tls_source(tmp_path) if tls else (_plain_source(), None)
        await source.start(_ack)
        assert source._upgrade_tls is False
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
            await _closed_by_listener(reader, within=mllp_module._CLIENT_SHUTDOWN_GRACE)
        finally:
            await _close_raw(writer)
        if cert is not None:
            # Restored first, so the real client never races the shortened bound.
            monkeypatch.setattr(mllp_module, "_TLS_HANDSHAKE_TIMEOUT", 10.0)
            await source.start(_ack)
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
        plain = _plain_source()
        await plain.start(_ack)
        try:
            await _served(plain)
        finally:
            await plain.stop()

    asyncio.run(scenario(), loop_factory=uvloop.new_event_loop)


# --- the caps and the allowlist reach a socket before its handshake (BACKLOG #1606) --------------
#
# The handshake bound above limits how LONG an unhandshaken socket lives. These pin how MANY: the
# listener accepts plain TCP, applies `source_ip_allowlist`, `max_connections` and
# `max_connections_per_host` exactly as the plain-TCP path does, and only then starts TLS on the
# admitted socket. So a peer holding sockets that never send a ClientHello spends real slots, and a
# peer the allowlist excludes never gets a handshake at all. The handshake bound is pinned far above
# every wait here, so only the cap or the allowlist can close the socket in time. Each wait polls a
# condition under a bounded deadline, so a slow runner makes these slower, not red.


class _Events:
    """A connection-event sink that records ``(kind, peer_host, reason)``."""

    def __init__(self) -> None:
        self.seen: list[tuple[str, str | None, str | None]] = []

    async def __call__(self, kind: str, peer_host: str | None, reason: str | None) -> None:
        self.seen.append((kind, peer_host, reason))

    def kinds(self) -> list[str]:
        return [kind for kind, _host, _reason in self.seen]


async def _until(predicate: Callable[[], bool], what: str, *, within: float = 5.0) -> None:
    """Poll ``predicate`` under a bounded deadline, failing with ``what`` if it never holds."""
    deadline = time.monotonic() + within
    while not predicate():
        if time.monotonic() > deadline:
            pytest.fail(what)
        await asyncio.sleep(0.01)


@pytest.mark.parametrize(
    ("caps", "reason"),
    [
        ({"max_connections": 1, "max_connections_per_host": 0}, None),
        ({"max_connections": 0, "max_connections_per_host": 1}, "max_connections_per_host"),
    ],
    ids=["max_connections", "max_connections_per_host"],
)
async def test_an_unhandshaken_socket_spends_a_connection_slot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caps: dict[str, int], reason: str | None
) -> None:
    monkeypatch.setattr(mllp_module, "_TLS_HANDSHAKE_TIMEOUT", 60.0)
    source, _cert_path = _tls_source(tmp_path, **caps)
    events = _Events()
    source.on_connection_event = events
    await source.start(_ack)
    try:
        _r1, w1 = await asyncio.open_connection("127.0.0.1", source.sockport)
        w2: asyncio.StreamWriter | None = None
        try:
            # Before the fix a socket that sent no ClientHello was outside the count entirely.
            await _until(
                lambda: source._active == 1,
                "a socket still in its TLS handshake was not counted against the caps",
            )
            r2, w2 = await asyncio.open_connection("127.0.0.1", source.sockport)
            await _closed_by_listener(r2, within=5.0)
            await _until(lambda: "at_capacity" in events.kinds(), "no at_capacity event")
            assert events.seen == [("at_capacity", "127.0.0.1", reason)]
        finally:
            await _close_raw(w1)
            if w2 is not None:
                await _close_raw(w2)
        # The slot comes back when the unhandshaken socket goes, and no `established` or `closed`
        # was emitted for it: it never became a session.
        await _until(lambda: source._active == 0, "the slot was not released")
        assert source._per_host == {}
        assert events.kinds() == ["at_capacity"]
    finally:
        await asyncio.wait_for(source.stop(), timeout=10.0)


async def test_a_peer_outside_the_allowlist_is_refused_before_its_handshake(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(mllp_module, "_TLS_HANDSHAKE_TIMEOUT", 60.0)
    source, _cert_path = _tls_source(tmp_path, source_ip_allowlist=["10.0.0.1"])
    events = _Events()
    source.on_connection_event = events
    await source.start(_ack)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
        try:
            # Before the fix the allowlist was checked only after the handshake, so this socket sat
            # open, unchecked, until the handshake bound.
            await _closed_by_listener(reader, within=5.0)
        finally:
            await _close_raw(writer)
        await _until(
            lambda: "peer_not_allowlisted" in events.kinds(), "no peer_not_allowlisted event"
        )
        assert events.kinds() == ["peer_not_allowlisted"]
        assert source._active == 0
    finally:
        await asyncio.wait_for(source.stop(), timeout=10.0)


async def test_a_failed_handshake_gives_its_slot_back_and_emits_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A socket admitted before its handshake and then aborted at the handshake bound must free both
    counters, or a handful of silent sockets would lock a peer out for good. It emits no event: it
    was never a session, and before this change a failed handshake emitted nothing either."""
    monkeypatch.setattr(mllp_module, "_TLS_HANDSHAKE_TIMEOUT", 0.3)
    source, _cert_path = _tls_source(tmp_path)
    events = _Events()
    source.on_connection_event = events
    await source.start(_ack)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
        try:
            await _closed_by_listener(reader, within=5.0)
        finally:
            await _close_raw(writer)
        await _until(lambda: source._active == 0, "the slot was not released")
        assert source._per_host == {}
        assert events.kinds() == []
    finally:
        await asyncio.wait_for(source.stop(), timeout=10.0)


async def test_a_peer_dropping_as_its_handshake_completes_is_closed_quietly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """CPython's ``StreamWriter.start_tls`` stores ``None`` as the transport, then raises
    ``AttributeError``, when the connection is closed cleanly during the handshake. The stop tests
    above reach that for real; this stand-in upgrade leaves the writer exactly that way on demand, so
    the guard is pinned without a timing race. Unguarded, the listener's own close then raised
    ``AttributeError`` again and the task logged a failure."""

    async def upgrade_then_lose(
        self: asyncio.StreamWriter, *args: object, **kwargs: object
    ) -> None:
        self.transport.close()
        self._transport = None  # type: ignore[attr-defined]  # what start_tls leaves behind
        raise AttributeError("'NoneType' object has no attribute 'get_extra_info'")

    monkeypatch.setattr(asyncio.StreamWriter, "start_tls", upgrade_then_lose)
    source, _cert_path = _tls_source(tmp_path)
    events = _Events()
    source.on_connection_event = events
    await source.start(_ack)
    try:
        with caplog.at_level(logging.ERROR, logger="messagefoundry.transports.mllp"):
            reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
            try:
                await _closed_by_listener(reader, within=5.0)
            finally:
                await _close_raw(writer)
            await _until(lambda: source._active == 0, "the slot was not released")
            await _until(lambda: not source._client_tasks, "the client task did not finish")
        assert "task failed" not in caplog.text
        assert events.kinds() == []
        assert source._per_host == {}
    finally:
        await asyncio.wait_for(source.stop(), timeout=10.0)


async def test_stop_closes_an_unhandshaken_socket_without_close_clients(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Where the listener upgrades TLS itself (the stdlib loop), a socket still in its handshake is
    tracked with every other client, so stop() closes it even on a server with no close_clients().
    Before the fix only close_clients() could reach it. uvloop keeps the loop-level handshake and is
    NOT covered by this: there stop() leaves such a socket to the handshake bound, which
    `test_stop_and_restart_on_uvloop` pins."""
    monkeypatch.setattr(mllp_module, "_TLS_HANDSHAKE_TIMEOUT", 60.0)
    source, _cert_path = _tls_source(tmp_path)
    await source.start(_ack)
    stopped = False
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
        try:
            # Before the fix this never held: the listener's own set saw a socket only once its
            # handshake was done.
            await _until(
                lambda: len(source._clients) == 1,
                "a socket still in its TLS handshake is not tracked by the listener",
            )
            assert source._server is not None
            source._server = _ServerWithoutCloseClients(source._server)  # type: ignore[assignment]
            started = time.monotonic()
            await source.stop()
            stopped = True
            assert time.monotonic() - started < mllp_module._CLIENT_SHUTDOWN_GRACE
            await _closed_by_listener(reader, within=mllp_module._CLIENT_SHUTDOWN_GRACE)
        finally:
            await _close_raw(writer)
    finally:
        if not stopped:
            await source.stop()


async def test_the_reader_follows_the_socket_into_tls(tmp_path: Path) -> None:
    """``StreamWriter.start_tls`` moves the writer and the protocol onto the TLS transport but leaves
    the reader on the raw socket, so the reader's flow control would pause the raw socket under the
    TLS layer and a close could then wait out the close-exchange bound. The listener moves the
    reader across itself; this pins it for a real handshake."""
    source, cert = _tls_source(tmp_path)
    seen: list[bool] = []
    real_start_tls = source._start_tls

    async def spy(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> bool:
        ok = await real_start_tls(reader, writer)
        seen.append(ok and reader._transport is writer.transport)  # type: ignore[attr-defined]
        return ok

    source._start_tls = spy  # type: ignore[method-assign]
    await source.start(_ack)
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
    assert seen == [True]
