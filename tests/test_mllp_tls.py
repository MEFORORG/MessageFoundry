# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""WP-13b — MLLP-over-TLS (ADR 0002): the per-connection SSL-context builder + a real TLS round-trip."""

from __future__ import annotations

import datetime
import ipaddress
import ssl
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.config.wiring import MLLP, WiringError, redacted_settings
from messagefoundry.pipeline.wiring_runner import check_mllp_tls_exposure
from messagefoundry.transports.mllp import (
    MLLPDestination,
    MLLPSource,
    _mllp_ssl_context,
    build_ack,
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
        .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2040, 1, 1, tzinfo=datetime.timezone.utc))
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


async def test_mllp_tls_round_trip_verified(tmp_path: Path) -> None:
    # An inbound TLS listener + an outbound client that VERIFIES the server cert (against the pinned
    # self-signed CA) and its hostname (127.0.0.1 SAN). A message flows only over the encrypted,
    # verified channel — proving start_server(ssl=) / open_connection(ssl=, server_hostname=) are wired.
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
                },
            )
        )
        await dest.send(ADT)  # returns only on a verified-TLS channel + positive ACK
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
        .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2040, 1, 1, tzinfo=datetime.timezone.utc))
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
