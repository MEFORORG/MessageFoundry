# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""WP-13a — in-process API TLS (ADR 0002): the SSL-context builder, ApiSettings validation, and the
serve-time wiring + bind-guard (a non-loopback API bind is allowed once TLS is configured)."""

from __future__ import annotations

import datetime
import ssl
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from pydantic import ValidationError

from messagefoundry.__main__ import main
from messagefoundry.api.tls import build_api_ssl_context
from messagefoundry.config.settings import ApiSettings

SAMPLES_CONFIG = Path(__file__).resolve().parent.parent / "samples" / "config"


def _self_signed(tmp_path: Path, *, password: str | None = None) -> tuple[Path, Path]:
    """Write a self-signed EC cert + key PEM to tmp_path; return (cert_path, key_path)."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2040, 1, 1, tzinfo=datetime.timezone.utc))
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    enc: serialization.KeySerializationEncryption = (
        serialization.BestAvailableEncryption(password.encode())
        if password
        else serialization.NoEncryption()
    )
    key_path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc)
    )
    return cert_path, key_path


# --- build_api_ssl_context ---------------------------------------------------


def test_context_defaults_to_tls_1_2_server(tmp_path: Path) -> None:
    cert, key = _self_signed(tmp_path)
    ctx = build_api_ssl_context(ApiSettings(tls_cert_file=str(cert), tls_key_file=str(key)))
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2  # NIST 800-52r2 floor
    assert ctx.verify_mode == ssl.CERT_NONE  # no client auth unless a client CA is set


def test_context_enforces_tls_1_3_floor(tmp_path: Path) -> None:
    cert, key = _self_signed(tmp_path)
    ctx = build_api_ssl_context(
        ApiSettings(tls_cert_file=str(cert), tls_key_file=str(key), tls_min_version="1.3")
    )
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_3


def test_context_requires_cert() -> None:
    with pytest.raises(ValueError, match="tls_cert_file"):
        build_api_ssl_context(
            ApiSettings()
        )  # tls_enabled is False → caller shouldn't call, but guard


def test_context_loads_encrypted_key_with_password(tmp_path: Path) -> None:
    cert, key = _self_signed(tmp_path, password="s3cret")
    # Right password loads; the wrong one raises (proves the password is actually used).
    build_api_ssl_context(
        ApiSettings(tls_cert_file=str(cert), tls_key_file=str(key), tls_key_password="s3cret")
    )
    with pytest.raises(ssl.SSLError):
        build_api_ssl_context(
            ApiSettings(tls_cert_file=str(cert), tls_key_file=str(key), tls_key_password="wrong")
        )


def test_context_mtls_requires_client_cert(tmp_path: Path) -> None:
    cert, key = _self_signed(tmp_path)
    ctx = build_api_ssl_context(
        ApiSettings(tls_cert_file=str(cert), tls_key_file=str(key), tls_client_ca_file=str(cert))
    )
    assert ctx.verify_mode == ssl.CERT_REQUIRED  # opt-in mTLS demands + verifies a client cert


# --- ApiSettings validation --------------------------------------------------


def test_tls_min_version_must_be_1_2_or_1_3() -> None:
    with pytest.raises(ValidationError, match="tls_min_version"):
        ApiSettings(tls_min_version="1.1")


def test_tls_key_without_cert_is_rejected() -> None:
    with pytest.raises(ValidationError, match="require .*tls_cert_file"):
        ApiSettings(tls_key_file="key.pem")


def test_tls_enabled_property() -> None:
    assert ApiSettings(tls_cert_file="cert.pem").tls_enabled is True
    assert ApiSettings().tls_enabled is False


# --- serve wiring + bind-guard -----------------------------------------------


def test_serve_allows_non_loopback_bind_with_tls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # TLS configured → a non-loopback bind is the first-class secure path: allowed WITHOUT
    # --allow-insecure-bind, and uvicorn.run gets an ssl_context_factory yielding a real SSLContext.
    from messagefoundry.store.crypto import generate_key

    cert, key = _self_signed(tmp_path)
    captured: dict[str, Any] = {}
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: captured.update(k))
    (tmp_path / "messagefoundry.toml").write_text(
        f'[api]\nhost = "0.0.0.0"\ntls_cert_file = "{cert.as_posix()}"\n'
        f'tls_key_file = "{key.as_posix()}"\n',
        encoding="utf-8",
    )
    assert main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "dev"]) == 0  # no flag needed
    err = capsys.readouterr().err
    assert "refusing to serve" not in err  # TLS is the allowed path, not the refused one
    factory = captured["ssl_context_factory"]
    assert isinstance(factory(None, None), ssl.SSLContext)


def test_serve_loopback_without_tls_passes_no_ssl_factory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from messagefoundry.store.crypto import generate_key

    captured: dict[str, Any] = {}
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: captured.update(k))
    (tmp_path / "messagefoundry.toml").write_text('[api]\nhost = "127.0.0.1"\n', encoding="utf-8")
    assert main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "dev"]) == 0
    assert "ssl_context_factory" not in captured  # plaintext loopback: no TLS wiring


# --- WP-15: reverse-proxy / upstream TLS termination -------------------------


def test_tls_terminated_upstream_requires_trusted_proxies() -> None:
    with pytest.raises(ValidationError, match="trusted_proxies"):
        ApiSettings(tls_terminated_upstream=True)  # no proxy declared → unverifiable claim


def test_exposure_protected_property() -> None:
    assert ApiSettings().exposure_protected is False
    assert ApiSettings(tls_cert_file="c.pem").exposure_protected is True  # in-process TLS
    assert (
        ApiSettings(tls_terminated_upstream=True, trusted_proxies=["10.0.0.1"]).exposure_protected
        is True  # upstream TLS behind a trusted proxy
    )


def test_serve_allows_non_loopback_with_upstream_tls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # A declared TLS-terminating proxy satisfies the exposed-gate WITHOUT in-process TLS: allowed
    # without --allow-insecure-bind, and uvicorn trusts XFF only from the proxy (no ssl context).
    from messagefoundry.store.crypto import generate_key

    captured: dict[str, Any] = {}
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: captured.update(k))
    (tmp_path / "messagefoundry.toml").write_text(
        '[api]\nhost = "0.0.0.0"\ntls_terminated_upstream = true\ntrusted_proxies = ["10.0.0.7"]\n',
        encoding="utf-8",
    )
    assert main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "dev"]) == 0
    assert "refusing to serve" not in capsys.readouterr().err
    assert captured["forwarded_allow_ips"] == ["10.0.0.7"]  # XFF trusted only from the proxy
    assert "ssl_context_factory" not in captured  # TLS is at the proxy, not in-process


def test_serve_forwarded_allow_ips_empty_when_no_proxy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from messagefoundry.store.crypto import generate_key

    captured: dict[str, Any] = {}
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: captured.update(k))
    (tmp_path / "messagefoundry.toml").write_text('[api]\nhost = "127.0.0.1"\n', encoding="utf-8")
    assert main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "dev"]) == 0
    # Trust nothing by default (override uvicorn's loopback default), so XFF can't spoof the source IP.
    assert captured["forwarded_allow_ips"] == []
    # WP-L3-07 (ASVS 13.4.6): the `Server: uvicorn` banner is suppressed.
    assert captured["server_header"] is False
