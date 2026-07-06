# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Security-hardening regression tests for the DICOM C-STORE SCP/SCU transport (ADR 0025):

* SEC-016 — the SCP server and SCU client TLS contexts must load a passphrase-encrypted private key
  via a deterministic empty-bytes callback (parity with MLLP / the API listener, WP-13b) so an
  encrypted key with no/wrong passphrase fails fast with ``ssl.SSLError`` at build time instead of
  blocking on OpenSSL's interactive TTY prompt (no TTY under an NSSM service account / container).
* SEC-012 — a non-loopback C-STORE SCP with no peer controls (no calling-AE allowlist, no
  source_ip_allowlist, no mTLS) is refused at construction (deny-by-default, ADR 0025 §9).

These tests exercise only the pure ``ssl`` context builders and ``DicomScpSource.__init__`` (which
builds the TLS context but does NOT import pynetdicom), so they run WITHOUT the ``[dicom]`` extra.
"""

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

from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.config.wiring import DICOM
from messagefoundry.transports.dicom import (
    DicomScpSource,
    _client_ssl_context,
    _server_ssl_context,
)

_PASSPHRASE = "s3cr3t-dicom-pass"


def test_dicom_factory_carries_tls_key_password() -> None:
    # SEC-016: tls_key_password must flow through the DICOM() factory ("the factory IS the schema") so
    # it reaches dicom.py's settings dict — otherwise the passphrase callback is unreachable.
    spec = DICOM(ae_title="X", tls_key_password="pw")
    assert spec.settings["tls_key_password"] == "pw"
    # Default (unset) is None, the unencrypted-key path.
    assert DICOM(ae_title="X").settings["tls_key_password"] is None


def _cert(tmp_path: Path, *, encrypt: str | None) -> tuple[str, str]:
    """A self-signed EC cert + key PEM. ``encrypt`` (a passphrase) PKCS#8-encrypts the key; ``None``
    writes it unencrypted. Mirrors the helper pattern in tests/test_mllp_tls.py / test_dicom_scp.py."""
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
    enc: serialization.KeySerializationEncryption = (
        serialization.BestAvailableEncryption(encrypt.encode("utf-8"))
        if encrypt is not None
        else serialization.NoEncryption()
    )
    tag = "enc" if encrypt is not None else "plain"
    cp, kp = tmp_path / f"{tag}-c.pem", tmp_path / f"{tag}-k.pem"
    cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    kp.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc)
    )
    return str(cp), str(kp)


# --- SEC-016: passphrase-encrypted private-key callback (server context) ---------------------------


def test_server_ssl_loads_encrypted_key_with_password(tmp_path: Path) -> None:
    cert, key = _cert(tmp_path, encrypt=_PASSPHRASE)
    ctx = _server_ssl_context(
        {"tls": True, "tls_cert_file": cert, "tls_key_file": key, "tls_key_password": _PASSPHRASE}
    )
    assert ctx is not None
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2


def test_server_ssl_encrypted_key_wrong_password_raises(tmp_path: Path) -> None:
    # A wrong passphrase proves the password is actually applied (not silently ignored).
    cert, key = _cert(tmp_path, encrypt=_PASSPHRASE)
    with pytest.raises(ssl.SSLError):
        _server_ssl_context(
            {"tls": True, "tls_cert_file": cert, "tls_key_file": key, "tls_key_password": "wrong"}
        )


def test_server_ssl_encrypted_key_missing_password_raises_not_prompts(tmp_path: Path) -> None:
    # Regression proof for SEC-016: without the empty-bytes callback this would BLOCK on OpenSSL's
    # interactive TTY prompt (hanging the headless service). With the callback it fails fast.
    cert, key = _cert(tmp_path, encrypt=_PASSPHRASE)
    with pytest.raises(ssl.SSLError):
        _server_ssl_context({"tls": True, "tls_cert_file": cert, "tls_key_file": key})


def test_server_ssl_unencrypted_key_unchanged(tmp_path: Path) -> None:
    # The empty-bytes callback is never invoked for a plain key — prior behavior preserved.
    cert, key = _cert(tmp_path, encrypt=None)
    ctx = _server_ssl_context({"tls": True, "tls_cert_file": cert, "tls_key_file": key})
    assert ctx is not None
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2


# --- SEC-016: passphrase-encrypted private-key callback (client / mTLS context) --------------------


def test_client_ssl_loads_encrypted_mtls_key_with_password(tmp_path: Path) -> None:
    # mTLS client identity with a passphrase-encrypted key (a reasonable key-at-rest choice). A
    # tls_ca_file pins the trust anchor so the build doesn't depend on the system store.
    cert, key = _cert(tmp_path, encrypt=_PASSPHRASE)
    ctx = _client_ssl_context(
        {
            "tls": True,
            "tls_cert_file": cert,
            "tls_key_file": key,
            "tls_ca_file": cert,
            "tls_key_password": _PASSPHRASE,
        }
    )
    assert ctx is not None
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2


def test_client_ssl_encrypted_mtls_key_missing_password_raises(tmp_path: Path) -> None:
    cert, key = _cert(tmp_path, encrypt=_PASSPHRASE)
    with pytest.raises(ssl.SSLError):
        _client_ssl_context(
            {"tls": True, "tls_cert_file": cert, "tls_key_file": key, "tls_ca_file": cert}
        )


# --- SEC-012: fail-closed peer controls on a non-loopback SCP --------------------------------------


def _scp(host: str, **overrides: object) -> DicomScpSource:
    settings: dict[str, object] = {"ae_title": "MEFOR_SCP", "host": host, "port": 0}
    settings.update(overrides)
    return DicomScpSource(Source(type=ConnectorType.DIMSE, settings=settings))


def test_nonloopback_scp_without_any_peer_control_fails_closed() -> None:
    with pytest.raises(ValueError) as exc:
        _scp("0.0.0.0")
    msg = str(exc.value)
    assert "calling_ae_allowlist" in msg
    assert "source_ip_allowlist" in msg
    assert "mTLS" in msg


def test_nonloopback_scp_with_calling_ae_allowlist_ok() -> None:
    _scp("0.0.0.0", calling_ae_allowlist=["MOD1"])  # no raise


def test_nonloopback_scp_with_source_ip_allowlist_ok() -> None:
    _scp("0.0.0.0", source_ip_allowlist=["10.0.0.0/8"])  # no raise


def test_nonloopback_scp_with_mtls_ok(tmp_path: Path) -> None:
    # tls + tls_ca_file → CERT_REQUIRED (real peer authentication); the cert is built on disk because
    # _server_ssl_context runs at __init__.
    cert, key = _cert(tmp_path, encrypt=None)
    _scp("0.0.0.0", tls=True, tls_cert_file=cert, tls_key_file=key, tls_ca_file=cert)  # no raise


def test_nonloopback_tls_without_ca_still_fails_closed(tmp_path: Path) -> None:
    # Server TLS WITHOUT a tls_ca_file is encryption, not peer authentication — mtls_on is False, so a
    # non-loopback SCP with no AE/IP allowlist still fails closed (proves the tls-AND-ca distinction).
    cert, key = _cert(tmp_path, encrypt=None)
    with pytest.raises(ValueError):
        _scp("0.0.0.0", tls=True, tls_cert_file=cert, tls_key_file=key)


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1", "::ffff:127.0.0.1"])
def test_loopback_scp_without_controls_ok(host: str) -> None:
    # The common dev/single-box case (loopback, no peer controls) must not regress.
    _scp(host)  # no raise


def test_default_host_is_loopback_and_ok() -> None:
    # An inbound with no host injected falls back to 127.0.0.1 — the construction guard is a no-op.
    DicomScpSource(Source(type=ConnectorType.DIMSE, settings={"ae_title": "MEFOR_SCP", "port": 0}))
