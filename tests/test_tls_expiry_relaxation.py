# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""#129 (ADR 0094) — granular expiry-only TLS relaxation (``tls_allow_expired``).

The safety properties are the whole point, so they are asserted end-to-end over a real TLS handshake
with cryptography-minted certs (a tiny CA + leaves whose ``notAfter`` is in the PAST):

* an EXPIRED cert with a valid chain + hostname is ACCEPTED **only** when the flag is set;
* a WRONG-hostname cert and a BROKEN-chain cert are STILL REJECTED even with the flag set;
* with the flag OFF, an expired cert is still rejected (byte-identical default).

Plus unit coverage of :func:`relax_verify_expiry` and the per-transport context builders that thread the
flag (mllp / ftps / dicom-SCU), and a check that the #200 posture-refusal never keys on it.
"""

from __future__ import annotations

import datetime
import ipaddress
import logging
import ssl
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.config.tls_policy import relax_verify_expiry
from messagefoundry.transports import DeliveryError
from messagefoundry.transports.dicom import _client_ssl_context
from messagefoundry.transports.mllp import MLLPDestination, MLLPSource, _mllp_ssl_context, build_ack
from messagefoundry.transports.remotefile import _ftps_ssl_context

ADT = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||100||DOE^JANE\r"

#: The exact OpenSSL bit :func:`relax_verify_expiry` ORs in — asserted directly so a future OpenSSL
#: constant drift is caught here, not silently in a live handshake.
_NO_CHECK_TIME = 0x200000

# Windows (`str(...)` of an epoch-aware datetime) — a window that starts well before "now" so a valid
# reference cert is unambiguously current, and a PAST window so the expired one is unambiguously lapsed.
_PAST_NB = datetime.datetime(2021, 1, 1, tzinfo=datetime.timezone.utc)
_PAST_NA = datetime.datetime(2022, 1, 1, tzinfo=datetime.timezone.utc)  # notAfter < now → EXPIRED
_LONG_NB = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
_LONG_NA = datetime.datetime(2040, 1, 1, tzinfo=datetime.timezone.utc)  # current


def _ca(
    tmp_path: Path, name: str = "Test CA"
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """A self-signed CA (RFC 5280-conformant: SKI + AKI + KeyUsage) so the leaves it signs pass the
    ``VERIFY_X509_STRICT`` flag ``harden_verify_flags`` ORs on."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_LONG_NB)
        .not_valid_after(_LONG_NA)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _leaf(
    ca_key: ec.EllipticCurvePrivateKey,
    ca_cert: x509.Certificate,
    *,
    san: x509.GeneralName,
    nb: datetime.datetime,
    na: datetime.datetime,
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nb)
        .not_valid_after(na)
        .add_extension(x509.SubjectAlternativeName([san]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


def _write(
    tmp_path: Path, stem: str, key: ec.EllipticCurvePrivateKey, cert: x509.Certificate
) -> tuple[str, str]:
    cp, kp = tmp_path / f"{stem}-c.pem", tmp_path / f"{stem}-k.pem"
    cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    kp.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return str(cp), str(kp)


def _ca_pem(tmp_path: Path, stem: str, cert: x509.Certificate) -> str:
    p = tmp_path / f"{stem}-ca.pem"
    p.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return str(p)


# --- relax_verify_expiry (the shared helper) ---------------------------------


def test_relax_sets_no_check_time_bit_and_warns(caplog: pytest.LogCaptureFixture) -> None:
    ctx = ssl.create_default_context()
    before = ctx.verify_flags
    with caplog.at_level(logging.WARNING):
        relax_verify_expiry(ctx, host="partner.example")
    assert ctx.verify_flags & _NO_CHECK_TIME  # the time check is relaxed
    assert ctx.verify_mode == ssl.CERT_REQUIRED  # verification stays ON (not CERT_NONE)
    assert ctx.check_hostname is True  # hostname check untouched
    assert (before & _NO_CHECK_TIME) == 0  # it was the relaxation that set it
    assert any("expiry validation is RELAXED" in r.message for r in caplog.records)
    assert any("partner.example" in r.message for r in caplog.records)


def test_relax_is_noop_on_cert_none_context() -> None:
    # A verify-off context must never be *touched* — there is nothing to relax and it must not be
    # silently mutated into a subtly different posture.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    before = ctx.verify_flags
    relax_verify_expiry(ctx, host="x")
    assert ctx.verify_flags == before
    assert not (ctx.verify_flags & _NO_CHECK_TIME)


# --- the per-transport context builders thread the flag ----------------------


def test_mllp_context_relaxes_only_when_flag_set(tmp_path: Path) -> None:
    ca_key, ca_cert = _ca(tmp_path)
    ca_pem = _ca_pem(tmp_path, "m", ca_cert)
    off = _mllp_ssl_context({"tls": True, "tls_ca_file": ca_pem}, server=False)
    on = _mllp_ssl_context(
        {"tls": True, "tls_ca_file": ca_pem, "tls_allow_expired": True}, server=False
    )
    assert off is not None and on is not None
    assert not (off.verify_flags & _NO_CHECK_TIME)  # default OFF = byte-identical
    assert on.verify_flags & _NO_CHECK_TIME
    assert on.verify_mode == ssl.CERT_REQUIRED and on.check_hostname is True


def test_ftps_context_relaxes_only_when_flag_set(tmp_path: Path) -> None:
    ca_key, ca_cert = _ca(tmp_path)
    ca_pem = _ca_pem(tmp_path, "f", ca_cert)
    off = _ftps_ssl_context({"host": "h", "tls_ca_file": ca_pem})
    on = _ftps_ssl_context({"host": "h", "tls_ca_file": ca_pem, "tls_allow_expired": True})
    assert not (off.verify_flags & _NO_CHECK_TIME)
    assert on.verify_flags & _NO_CHECK_TIME and on.verify_mode == ssl.CERT_REQUIRED


def test_dicom_scu_context_relaxes_only_when_flag_set(tmp_path: Path) -> None:
    ca_key, ca_cert = _ca(tmp_path)
    ca_pem = _ca_pem(tmp_path, "d", ca_cert)
    off = _client_ssl_context({"tls": True, "tls_ca_file": ca_pem})
    on = _client_ssl_context({"tls": True, "tls_ca_file": ca_pem, "tls_allow_expired": True})
    assert off is not None and on is not None
    assert not (off.verify_flags & _NO_CHECK_TIME)
    assert on.verify_flags & _NO_CHECK_TIME and on.check_hostname is True


def test_verify_off_path_ignores_allow_expired(monkeypatch: pytest.MonkeyPatch) -> None:
    # tls_verify=false is CERT_NONE; tls_allow_expired must not touch that path (it stays a plain
    # verify-off context, still gated by the escape) — no NO_CHECK_TIME bit smuggled onto it.
    monkeypatch.setenv("MEFOR_ALLOW_INSECURE_TLS", "1")
    ctx = _mllp_ssl_context(
        {"tls": True, "tls_verify": False, "tls_allow_expired": True}, server=False
    )
    assert ctx is not None
    assert ctx.verify_mode == ssl.CERT_NONE
    assert not (ctx.verify_flags & _NO_CHECK_TIME)


# --- the safety properties over a real MLLP-over-TLS handshake ---------------


async def _round_trip(tmp_path: Path, *, server_cert: tuple[str, str], dest_settings: dict) -> None:
    """Stand up a TLS MLLP listener presenting ``server_cert`` and deliver one message with
    ``dest_settings``. Returns normally on success; raises DeliveryError if the client rejects."""
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
                "tls_cert_file": server_cert[0],
                "tls_key_file": server_cert[1],
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
                    **dest_settings,
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


async def test_expired_cert_accepted_only_with_flag(tmp_path: Path) -> None:
    ca_key, ca_cert = _ca(tmp_path)
    ca_pem = _ca_pem(tmp_path, "e", ca_cert)
    # An EXPIRED leaf whose SAN matches 127.0.0.1 and whose chain is valid.
    lk, lc = _leaf(
        ca_key,
        ca_cert,
        san=x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        nb=_PAST_NB,
        na=_PAST_NA,
    )
    server_cert = _write(tmp_path, "e-leaf", lk, lc)

    # Flag OFF → the expired cert is rejected (byte-identical default).
    with pytest.raises(DeliveryError):
        await _round_trip(
            tmp_path, server_cert=server_cert, dest_settings={"tls": True, "tls_ca_file": ca_pem}
        )

    # Flag ON → accepted (chain + hostname were valid; only expiry was relaxed).
    await _round_trip(
        tmp_path,
        server_cert=server_cert,
        dest_settings={"tls": True, "tls_ca_file": ca_pem, "tls_allow_expired": True},
    )


async def test_wrong_hostname_still_rejected_with_flag(tmp_path: Path) -> None:
    ca_key, ca_cert = _ca(tmp_path)
    ca_pem = _ca_pem(tmp_path, "wh", ca_cert)
    # Expired AND wrong host: SAN names a different host, so hostname verification must still fail even
    # though expiry is relaxed — the flag does not weaken the hostname check.
    lk, lc = _leaf(
        ca_key, ca_cert, san=x509.DNSName("not-127-0-0-1.example"), nb=_PAST_NB, na=_PAST_NA
    )
    server_cert = _write(tmp_path, "wh-leaf", lk, lc)
    with pytest.raises(DeliveryError):
        await _round_trip(
            tmp_path,
            server_cert=server_cert,
            dest_settings={
                "tls": True,
                "tls_ca_file": ca_pem,
                "tls_allow_expired": True,
                "tls_check_hostname": True,
            },
        )


async def test_broken_chain_still_rejected_with_flag(tmp_path: Path) -> None:
    ca_key, ca_cert = _ca(tmp_path, name="Real CA")
    other_key, other_cert = _ca(tmp_path, name="Other CA")
    other_pem = _ca_pem(tmp_path, "bc", other_cert)
    # A (current-window, right-host) leaf signed by the REAL CA, but the client trusts a DIFFERENT CA:
    # the chain does not build. Relaxing expiry must not paper over an untrusted chain.
    lk, lc = _leaf(
        ca_key,
        ca_cert,
        san=x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        nb=_PAST_NB,
        na=_PAST_NA,
    )
    server_cert = _write(tmp_path, "bc-leaf", lk, lc)
    with pytest.raises(DeliveryError):
        await _round_trip(
            tmp_path,
            server_cert=server_cert,
            dest_settings={
                "tls": True,
                "tls_ca_file": other_pem,  # wrong trust anchor → chain fails
                "tls_allow_expired": True,
            },
        )


# --- #200 (ADR 0092): tls_allow_expired is NOT an insecure hop the refusal keys on ---------------


def test_allow_expired_is_not_a_refused_insecure_hop() -> None:
    # TLS is ON (verification stays on) with tls_allow_expired — the MLLP outbound must build NO
    # cleartext InsecureHopGuard (that guard is only for a plaintext/verify-off hop), so #200 never
    # refuses an expiry-relaxed-but-verified hop. Construction succeeds with no posture stamped.
    dest = MLLPDestination(
        Destination(
            name="out",
            type=ConnectorType.MLLP,
            settings={
                "host": "203.0.113.10",  # non-loopback, but TLS is on + verifying
                "port": 2575,
                "tls": True,
                "tls_ca_file": None,
                "tls_allow_expired": True,
            },
        )
    )
    assert dest._hop_guard is None  # a verified TLS hop needs no cleartext guard
    assert dest._ssl is not None and dest._ssl.verify_flags & _NO_CHECK_TIME
