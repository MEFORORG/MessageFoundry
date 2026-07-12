# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""WP-13a — in-process API TLS (ADR 0002): the SSL-context builder, ApiSettings validation, and the
serve-time wiring + bind-guard (a non-loopback API bind is allowed once TLS is configured)."""

from __future__ import annotations

import datetime
import ssl
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from pydantic import ValidationError

from starlette.requests import Request

from messagefoundry.__main__ import main
from messagefoundry.api import create_app
from messagefoundry.api.security import (
    client_cert_principal,
    peer_cert_from_request,
    require_service_cert,
    resolve_client_cert_identity,
)
from messagefoundry.api.tls import build_api_ssl_context
from messagefoundry.api.tls_client_cert import (
    MF_CLIENT_PEERCERT_STATE_KEY,
    client_cert_http_protocol_class,
    enriched_app_state,
    extract_verified_peercert,
)
from messagefoundry.auth import Permission, Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import ApiSettings, AuthSettings
from messagefoundry.config.tls_policy import validate_proxy_tls_posture
from messagefoundry.pipeline import Engine

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
    # ADR 0078: in-process TLS off-loopback now ALSO requires the operator to attest a revocation-
    # checking terminator/PKI (the engine does no OCSP/CRL) — set the opt-out env so this stays a start.
    from messagefoundry.store.crypto import generate_key

    cert, key = _self_signed(tmp_path)
    captured: dict[str, Any] = {}
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    monkeypatch.setenv("MEFOR_TLS_REVOCATION_ATTESTED", "1")  # ADR 0078 opt-out
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


def test_serve_mtls_with_cert_map_swaps_in_shim_protocol(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # ADR 0083 activation: in-process mTLS (client CA) + a cert-identity map → the scope-populating shim
    # is passed to uvicorn as the `http` protocol so a verified peer cert reaches the resolver.
    from messagefoundry.store.crypto import generate_key

    cert, key = _self_signed(tmp_path)
    captured: dict[str, Any] = {}
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    monkeypatch.setenv("MEFOR_TLS_REVOCATION_ATTESTED", "1")  # ADR 0078 opt-out (off-loopback TLS)
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: captured.update(k))
    (tmp_path / "messagefoundry.toml").write_text(
        f'[api]\nhost = "0.0.0.0"\ntls_cert_file = "{cert.as_posix()}"\n'
        f'tls_key_file = "{key.as_posix()}"\ntls_client_ca_file = "{cert.as_posix()}"\n'
        'tls_client_cert_identities = { "CN:svc" = "svc" }\n',
        encoding="utf-8",
    )
    assert main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "dev"]) == 0
    http_cls = captured.get("http")
    assert http_cls is not None
    assert "connection_made" in vars(http_cls)  # the shim's per-connection cert-stashing override


def test_serve_mtls_without_cert_map_keeps_stock_protocol(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Mutual-auth-only (client CA but NO cert-identity map, e.g. console mTLS) keeps the stock protocol:
    # no behaviour change without a client CA + map. So uvicorn gets no `http` override.
    from messagefoundry.store.crypto import generate_key

    cert, key = _self_signed(tmp_path)
    captured: dict[str, Any] = {}
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    monkeypatch.setenv("MEFOR_TLS_REVOCATION_ATTESTED", "1")
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: captured.update(k))
    (tmp_path / "messagefoundry.toml").write_text(
        f'[api]\nhost = "0.0.0.0"\ntls_cert_file = "{cert.as_posix()}"\n'
        f'tls_key_file = "{key.as_posix()}"\ntls_client_ca_file = "{cert.as_posix()}"\n',
        encoding="utf-8",
    )
    assert main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "dev"]) == 0
    assert "http" not in captured  # stock protocol — the shim is never wired without a map


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


# --- #200: Posture-B (upstream TLS termination) declared-floor validation --------------------


def test_validate_proxy_tls_posture_accepts_empty_and_coherent() -> None:
    # An empty declaration is coherent (presence is enforced separately at serve-time), and a NIST
    # version floor + forward-secret cipher list passes.
    validate_proxy_tls_posture(None, None)
    validate_proxy_tls_posture("1.2", None)
    validate_proxy_tls_posture("1.3", "ECDHE+AESGCM")


def test_validate_proxy_tls_posture_rejects_bad_version() -> None:
    with pytest.raises(ValueError, match="proxy_tls_min_version"):
        validate_proxy_tls_posture("1.1", None)


def test_validate_proxy_tls_posture_rejects_non_forward_secret_ciphers() -> None:
    # A declared floor must not itself name a static-RSA (non-forward-secret) key exchange (11.6.2).
    with pytest.raises(ValueError, match="proxy_tls_ciphers"):
        validate_proxy_tls_posture("1.2", "AES128-SHA")


def test_proxy_settings_validate_at_load() -> None:
    with pytest.raises(ValidationError, match="proxy_tls_min_version"):
        ApiSettings(proxy_tls_min_version="1.0")
    # The declared-floor / intra-service predicates read cleanly.
    ok = ApiSettings(
        tls_terminated_upstream=True,
        trusted_proxies=["10.0.0.1"],
        proxy_intra_service_auth="mtls",
        proxy_tls_min_version="1.2",
    )
    assert ok.proxy_intra_service_declared is True
    assert ok.proxy_tls_floor_declared is True
    default = ApiSettings()
    assert default.proxy_intra_service_declared is False
    assert default.proxy_tls_floor_declared is False


def test_cert_identity_map_requires_client_ca() -> None:
    # A cert-identity allow-list is meaningless without in-process mTLS to verify the peer cert first.
    with pytest.raises(ValidationError, match="tls_client_ca_file"):
        ApiSettings(tls_client_cert_identities={"CN:svc": "svc"})


# --- #200: Posture-B fail-closed serve gate (refuse prod-PHI / warn non-prod / quiet synthetic) ----
#
# In Posture-B the engine cannot verify the proxy→engine internal hop or observe the proxy's TLS/KEX,
# so a PHI-PRODUCTION bind must AFFIRMATIVELY DECLARE both (attestations made fail-closed). Mirrors the
# require_mfa posture exactly. create_managed_app + uvicorn are mocked so no socket is opened. The keyless
# gate is pre-satisfied with an encryption key so only the Posture-B posture decides prod refusals.

_SECURE_RETENTION = "[retention]\nmessages_days = 30\ndead_letter_days = 30\n"
_SECURE_ALERTS = '[alerts]\nemail_smtp_host = "smtp.example.org"\nemail_from = "sec@example.org"\n'


def _posture_b_toml(tmp_path: Path, *, intra: str = "none", floor: str | None = None) -> None:
    """A non-loopback Posture-B bind (declared proxy) with every NON-Posture-B exposure gate satisfied
    (egress deny-by-default + secure retention + SMTP alerts), so only the intra-service-auth + KEX-floor
    attestations are under test. ``intra``/``floor`` toggle the two Posture-B knobs."""
    lines = [
        "[api]",
        'host = "0.0.0.0"',
        "tls_terminated_upstream = true",
        'trusted_proxies = ["10.0.0.9"]',
        f'proxy_intra_service_auth = "{intra}"',
    ]
    if floor is not None:
        lines.append(f'proxy_tls_min_version = "{floor}"')
    body = (
        "\n".join(lines)
        + "\n[egress]\ndeny_by_default = true\n"
        + _SECURE_RETENTION
        + _SECURE_ALERTS
    )
    (tmp_path / "messagefoundry.toml").write_text(body, encoding="utf-8")


def _run_posture_b(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, env: str, key: bool = True
) -> int:
    monkeypatch.chdir(tmp_path)
    if key:
        monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", "x" * 44)
    else:
        monkeypatch.delenv("MEFOR_STORE_ENCRYPTION_KEY", raising=False)
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: object())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    return main(["serve", "--config", str(SAMPLES_CONFIG), "--env", env])


def test_serve_refuses_posture_b_prod_without_intra_service_auth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Floor declared but intra-service-auth undeclared ("none") → prod-PHI refuses fail-closed.
    _posture_b_toml(tmp_path, intra="none", floor="1.2")
    assert _run_posture_b(tmp_path, monkeypatch, env="prod") == 2
    err = capsys.readouterr().err
    assert "refusing to serve on a production PHI" in err
    assert "proxy_intra_service_auth" in err


def test_serve_refuses_posture_b_prod_without_kex_floor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Intra-service-auth declared but no proxy_tls_min_version → prod-PHI refuses fail-closed.
    _posture_b_toml(tmp_path, intra="mtls", floor=None)
    assert _run_posture_b(tmp_path, monkeypatch, env="prod") == 2
    err = capsys.readouterr().err
    assert "refusing to serve on a production PHI" in err
    assert "proxy_tls_min_version" in err


def test_serve_warns_posture_b_in_staging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Non-production PHI (staging) only WARNS and still starts — the fail-closed refuse is prod-only.
    _posture_b_toml(tmp_path, intra="none", floor=None)
    assert _run_posture_b(tmp_path, monkeypatch, env="staging") == 0
    err = capsys.readouterr().err
    assert "proxy_intra_service_auth" in err and "refusing to serve" not in err


def test_serve_posture_b_prod_with_attestations_starts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Both attestations declared → the Posture-B gate opens; a production PHI bind starts (every other
    # prod gate pre-satisfied), so the Posture-B refusal text is absent.
    _posture_b_toml(tmp_path, intra="mtls", floor="1.2")
    assert _run_posture_b(tmp_path, monkeypatch, env="prod") == 0
    assert "refusing to serve on a production PHI" not in capsys.readouterr().err


def test_serve_posture_b_synthetic_is_quiet(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # A synthetic instance (dev) stays quiet on the Posture-B posture (byte-identical — parity with the
    # keyless / MFA gates), even with both attestations undeclared.
    _posture_b_toml(tmp_path, intra="none", floor=None)
    assert _run_posture_b(tmp_path, monkeypatch, env="dev", key=False) == 0
    assert "proxy_intra_service_auth" not in capsys.readouterr().err


def test_serve_loopback_emits_no_new_stderr(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Loopback byte-identity gate: a 127.0.0.1 serve is unchanged by #200 — no Posture-B / TLS stderr.
    from messagefoundry.store.crypto import generate_key

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    (tmp_path / "messagefoundry.toml").write_text('[api]\nhost = "127.0.0.1"\n', encoding="utf-8")
    assert main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "dev"]) == 0
    assert capsys.readouterr().err == ""  # nothing new on the loopback path


# --- #200: mTLS client-cert → Identity resolver (positive + negative) ------------------------------


def _peercert(cn: str, *sans: tuple[str, str]) -> dict[str, object]:
    """A synthetic ``ssl.getpeercert()`` dict with subject CN ``cn`` and optional SANs."""
    cert: dict[str, object] = {"subject": ((("commonName", cn),),)}
    if sans:
        cert["subjectAltName"] = sans
    return cert


def test_client_cert_principal_maps_cn_and_san() -> None:
    cert_map = {"CN:svc.internal": "svc-user", "SAN:DNS:api.internal": "api-user"}
    # Positive: subject CN maps.
    assert client_cert_principal(_peercert("svc.internal"), cert_map) == "svc-user"
    # Positive: a SAN maps (qualified by type).
    assert (
        client_cert_principal(_peercert("other", ("DNS", "api.internal")), cert_map) == "api-user"
    )


def test_client_cert_principal_denies_unmapped_and_empty() -> None:
    cert_map = {"CN:svc.internal": "svc-user"}
    # Negative: a spoofed / unmapped CN resolves to nothing (deny-by-default).
    assert client_cert_principal(_peercert("attacker.evil"), cert_map) is None
    # No cert, or an empty map, also deny.
    assert client_cert_principal(None, cert_map) is None
    assert client_cert_principal(_peercert("svc.internal"), {}) is None


def test_peer_cert_from_request_none_under_stock_scope() -> None:
    # HONEST LIMITATION: stock uvicorn puts no transport in the ASGI scope, so no peer cert surfaces.
    req = Request({"type": "http", "headers": []})
    assert peer_cert_from_request(req) is None


class _FakeSSL:
    def __init__(self, cert: object | None) -> None:
        self._cert = cert

    def getpeercert(self) -> object | None:
        return self._cert


class _FakeTransport:
    def __init__(self, ssl_obj: _FakeSSL) -> None:
        self._ssl = ssl_obj

    def get_extra_info(self, name: str) -> object | None:
        return self._ssl if name == "ssl_object" else None


def _cert_request(app: object, peercert: object | None) -> Request:
    """A Request whose ASGI scope carries a transport exposing ``peercert`` (simulating a TLS-extension-
    capable server that populates scope['transport'] — which stock uvicorn does not)."""
    scope = {
        "type": "http",
        "app": app,
        "headers": [],
        "transport": _FakeTransport(_FakeSSL(peercert)),
    }
    return Request(scope)


async def test_resolve_client_cert_identity_positive_and_negative(tmp_path: Path) -> None:
    engine = await Engine.create(tmp_path / "mtls.db", poll_interval=0.02)
    try:
        service = AuthService(engine.store, AuthSettings(require_mfa=False))
        await service.initialize()
        user_id = await service.create_local_user(
            username="svc",
            password="Correct-horse-battery-9",
            display_name=None,
            email=None,
            roles=[Role.OPERATOR.value],
            actor="test",
        )
        assert user_id
        app = create_app(
            engine,
            auth=service,
            tls_client_cert_identities={"CN:svc.internal": "svc"},
        )
        # Positive: a verified peer cert whose CN maps resolves to the mapped principal's Identity.
        pos = await resolve_client_cert_identity(_cert_request(app, _peercert("svc.internal")))
        assert pos is not None and pos.username == "svc"
        # Negative: an unmapped / spoofed CN is denied (no identity).
        neg = await resolve_client_cert_identity(_cert_request(app, _peercert("attacker.evil")))
        assert neg is None
        # Negative: no client cert presented (empty getpeercert()) → denied.
        assert await resolve_client_cert_identity(_cert_request(app, {})) is None
    finally:
        await engine.stop()


# --- ADR 0083 activation: scope-populating shim (tls_client_cert) ----------------------------------


class _PlainTransport:
    """A non-TLS transport: get_extra_info('ssl_object') is None (nothing to surface)."""

    def get_extra_info(self, name: str) -> object | None:
        return None


class _RaisingSSL:
    """An ssl_object whose getpeercert() raises ValueError (handshake not yet complete)."""

    def getpeercert(self) -> object:
        raise ValueError("handshake not complete")


def test_extract_verified_peercert_variants() -> None:
    cert = _peercert("svc.internal")
    # A verified client cert surfaces as its getpeercert() dict.
    assert extract_verified_peercert(_FakeTransport(_FakeSSL(cert))) == cert  # type: ignore[arg-type]
    # Server-only TLS (empty getpeercert()) surfaces nothing — deny-by-default upstream.
    assert extract_verified_peercert(_FakeTransport(_FakeSSL({}))) is None  # type: ignore[arg-type]
    # A None cert, a plaintext transport, and an incomplete handshake all surface nothing.
    assert extract_verified_peercert(_FakeTransport(_FakeSSL(None))) is None  # type: ignore[arg-type]
    assert extract_verified_peercert(_PlainTransport()) is None  # type: ignore[arg-type]
    assert extract_verified_peercert(_FakeTransport(_RaisingSSL())) is None  # type: ignore[arg-type]


def test_enriched_app_state_snapshots_only_with_cert() -> None:
    base = {"shared": 1}
    # No cert → the SAME dict is returned (byte-identical; nothing stashed, no mutation).
    same = enriched_app_state(base, _FakeTransport(_FakeSSL({})))  # type: ignore[arg-type]
    assert same is base
    # A verified cert → a fresh per-connection copy carrying the cert; the shared dict is untouched.
    cert = _peercert("svc.internal")
    enriched = enriched_app_state(base, _FakeTransport(_FakeSSL(cert)))  # type: ignore[arg-type]
    assert enriched is not base
    assert enriched[MF_CLIENT_PEERCERT_STATE_KEY] == cert
    assert enriched["shared"] == 1
    assert MF_CLIENT_PEERCERT_STATE_KEY not in base  # producer never mutates the shared state


class _StubProtocolBase:
    """A stand-in for uvicorn's HTTP protocol: carries app_state + records connection_made(transport)."""

    def __init__(self) -> None:
        self.app_state: dict[str, Any] = {"shared": 1}
        self.made: object | None = None

    def connection_made(self, transport: object) -> None:
        self.made = transport


def test_client_cert_protocol_enriches_app_state_post_handshake() -> None:
    cls = client_cert_http_protocol_class(base=_StubProtocolBase)
    proto = cls()
    transport = _FakeTransport(_FakeSSL(_peercert("svc.internal")))
    proto.connection_made(transport)  # type: ignore[attr-defined]
    # super().connection_made ran (base behaviour preserved) AND the verified cert is now in app_state.
    assert proto.made is transport  # type: ignore[attr-defined]
    assert proto.app_state[MF_CLIENT_PEERCERT_STATE_KEY] == _peercert("svc.internal")  # type: ignore[attr-defined]
    assert proto.app_state["shared"] == 1  # type: ignore[attr-defined]


def test_client_cert_protocol_no_cert_is_byte_identical() -> None:
    cls = client_cert_http_protocol_class(base=_StubProtocolBase)
    proto = cls()
    before = proto.app_state  # type: ignore[attr-defined]
    proto.connection_made(_FakeTransport(_FakeSSL({})))  # type: ignore[attr-defined]
    # No client cert → app_state is the SAME object: nothing stashed, byte-identical to stock.
    assert proto.app_state is before  # type: ignore[attr-defined]
    assert MF_CLIENT_PEERCERT_STATE_KEY not in proto.app_state  # type: ignore[attr-defined]


def test_peer_cert_from_request_reads_shim_state_key() -> None:
    cert = _peercert("svc.internal")
    # The activated path: the shim stashed the verified cert under scope['state'][key].
    req = Request({"type": "http", "headers": [], "state": {MF_CLIENT_PEERCERT_STATE_KEY: cert}})
    assert peer_cert_from_request(req) == cert
    # An empty stash is treated as no cert (deny-by-default).
    empty = Request({"type": "http", "headers": [], "state": {MF_CLIENT_PEERCERT_STATE_KEY: {}}})
    assert peer_cert_from_request(empty) is None


# --- ADR 0083 activation: require_service_cert (fenced cert-only dependency) ------------------------


def test_require_service_cert_refuses_phi_permissions() -> None:
    # A cert-identity has no step-up/MFA — wiring it onto a PHI-view permission must fail LOUD at build.
    with pytest.raises(ValueError, match="PHI"):
        require_service_cert(Permission.MESSAGES_VIEW_RAW)
    with pytest.raises(ValueError, match="PHI"):
        require_service_cert(Permission.MESSAGES_VIEW_SUMMARY, Permission.MONITORING_READ)
    # A non-PHI service permission builds a dependency.
    assert callable(require_service_cert(Permission.MONITORING_READ))


def _wrap_with_cert(
    app: Any, peercert: object | None
) -> Callable[[Any, Any, Any], Awaitable[None]]:
    """Wrap an ASGI app to inject ``peercert`` into scope['state'] — standing in for the connection-made
    shim (which the ASGI TestClient transport never runs). ``None`` = no client cert presented."""

    async def wrapped(scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] == "http" and peercert is not None:
            state = dict(scope.get("state") or {})
            state[MF_CLIENT_PEERCERT_STATE_KEY] = peercert
            scope = {**scope, "state": state}
        await app(scope, receive, send)

    return wrapped


async def _svc_app(tmp_path: Path, db: str, *roles: Role) -> tuple[Any, Any]:
    """An engine + create_app wired with a cert-identity map for username 'svc' (given ``roles``)."""
    engine = await Engine.create(tmp_path / db, poll_interval=0.02)
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    uid = await service.create_local_user(
        username="svc",
        password="Correct-horse-battery-9",
        display_name=None,
        email=None,
        roles=[r.value for r in roles],
        actor="test",
    )
    assert uid
    app = create_app(engine, auth=service, tls_client_cert_identities={"CN:svc.internal": "svc"})
    return engine, app


async def test_service_identity_route_authenticates_via_client_cert(tmp_path: Path) -> None:
    engine, app = await _svc_app(tmp_path, "svc_id.db", Role.VIEWER)
    try:
        # Positive: a verified, mapped client cert authenticates the service route (no bearer token).
        transport = httpx.ASGITransport(app=_wrap_with_cert(app, _peercert("svc.internal")))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            r = await c.get("/service/identity")
            assert r.status_code == 200
            body = r.json()
            assert body["username"] == "svc"
            assert body["auth"] == "mtls-client-cert"
            assert "viewer" in body["roles"]
        # Negative: no client cert → 401 (deny-by-default), byte-identical to stock uvicorn.
        t_none = httpx.ASGITransport(app=_wrap_with_cert(app, None))
        async with httpx.AsyncClient(transport=t_none, base_url="http://t") as c:
            assert (await c.get("/service/identity")).status_code == 401
        # Negative: a spoofed / unmapped CN → 401.
        t_spoof = httpx.ASGITransport(app=_wrap_with_cert(app, _peercert("attacker.evil")))
        async with httpx.AsyncClient(transport=t_spoof, base_url="http://t") as c:
            assert (await c.get("/service/identity")).status_code == 401
    finally:
        await engine.stop()


async def test_client_cert_cannot_bypass_phi_or_step_up_routes(tmp_path: Path) -> None:
    # THE #1 security invariant (ADR 0083): a cert-identity — even one mapped to a FULL ADMINISTRATOR —
    # must NEVER satisfy a require_phi_read / require_step_up route. It has no session/MFA/step-up, and
    # those routes only ever consult the bearer plane, so a cert-only caller is denied (would be 200 on a
    # bypass). This is the guardrail against wiring the resolver as a drop-in for require().
    engine, app = await _svc_app(tmp_path, "svc_bypass.db", Role.ADMINISTRATOR)
    try:
        transport = httpx.ASGITransport(app=_wrap_with_cert(app, _peercert("svc.internal")))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            # PHI list route (require_phi_read) — cert present, no bearer → denied, NOT 200.
            assert (await c.get("/messages")).status_code == 401
            # Step-up route (require_step_up) — same denial.
            assert (await c.get("/messages/search")).status_code == 401
            # And the service route itself works for this same principal, proving the cert IS valid — it
            # is the ROUTE plane, not a broken cert, that fences PHI off.
            assert (await c.get("/service/identity")).status_code == 200
    finally:
        await engine.stop()
