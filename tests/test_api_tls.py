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
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
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
from messagefoundry.config.settings import ApiSettings, AuthSettings, CertMonitorSettings
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
        .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC))
        .not_valid_after(datetime.datetime(2040, 1, 1, tzinfo=datetime.UTC))
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
    # GIVEN 1 (ADR 0148): declare synthetic so the PHI egress/retention/notify gates stay quiet — the
    # TLS bind-guard is the subject here.
    (tmp_path / "messagefoundry.toml").write_text(
        f"security.handles_real_patient_data = false\n"
        f'security.local_access_only = false\nsecurity.listen_address = "0.0.0.0"\n'
        f'[api]\ntls_cert_file = "{cert.as_posix()}"\n'
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
    # GIVEN 1 (ADR 0148): declare synthetic so the PHI gates stay quiet — the mTLS shim wiring is under test.
    (tmp_path / "messagefoundry.toml").write_text(
        f"security.handles_real_patient_data = false\n"
        f'security.local_access_only = false\nsecurity.listen_address = "0.0.0.0"\n'
        f'[api]\ntls_cert_file = "{cert.as_posix()}"\n'
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
    # GIVEN 1 (ADR 0148): declare synthetic so the PHI gates stay quiet — the stock-protocol path is under test.
    (tmp_path / "messagefoundry.toml").write_text(
        f"security.handles_real_patient_data = false\n"
        f'security.local_access_only = false\nsecurity.listen_address = "0.0.0.0"\n'
        f'[api]\ntls_cert_file = "{cert.as_posix()}"\n'
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
    (tmp_path / "messagefoundry.toml").write_text(
        "security.handles_real_patient_data = false\nsecurity.local_access_only = true\n",
        encoding="utf-8",
    )
    assert main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "dev"]) == 0
    assert "ssl_context_factory" not in captured  # plaintext loopback: no TLS wiring


# --- WP-15: reverse-proxy / upstream TLS termination -------------------------


def test_tls_terminated_upstream_requires_trusted_proxies() -> None:
    with pytest.raises(ValidationError, match="trusted_proxies"):
        ApiSettings(tls_terminated_upstream=True)  # no proxy declared → unverifiable claim


def test_trusted_proxies_rejects_wildcard() -> None:
    # "*" makes uvicorn trust EVERY peer and echo back the client-authored leftmost X-Forwarded-For,
    # so any client can declare its own source address. It also satisfied the pairing check above.
    with pytest.raises(ValidationError, match="trusts the X-Forwarded-For header from EVERY peer"):
        ApiSettings(tls_terminated_upstream=True, trusted_proxies=["*"])


@pytest.mark.parametrize(
    # All non-routable/reserved forms on purpose: the repo's customer/PHI leak guard rejects a routable
    # literal even in test data, and a private-range host:port proves the same parse failure. RFC 1918
    # over RFC 5737 TEST-NET here: 10.x is unambiguously private, so a future tightening of the guard's
    # "looks routable" heuristic can't reach it.
    "entry",
    ["10.0.0.", "proxy.example.org", "10.0.0.1/33", "", "10.0.0.1:8080"],
)
def test_trusted_proxies_rejects_unparseable_entry(entry: str) -> None:
    # uvicorn degrades a malformed entry to a "trusted literal" that never matches — the pairing check
    # passes while nothing is actually trusted, silently collapsing every client to the proxy address.
    with pytest.raises(ValidationError, match="not a valid IP address or CIDR network"):
        ApiSettings(trusted_proxies=[entry])


@pytest.mark.parametrize(
    "entries",
    [
        [],  # the shipped default — trust nothing
        ["127.0.0.1"],
        ["10.0.0.1", "10.0.0.2"],
        ["10.0.0.0/24"],
        ["::1"],
        ["2001:db8::/64"],
    ],
)
def test_trusted_proxies_accepts_valid_addresses_and_networks(entries: list[str]) -> None:
    assert ApiSettings(trusted_proxies=entries).trusted_proxies == entries


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
    # GIVEN 1 (ADR 0148): declare synthetic so the PHI gates stay quiet — the upstream-TLS exposed-gate
    # is the subject here.
    (tmp_path / "messagefoundry.toml").write_text(
        "security.handles_real_patient_data = false\n"
        'security.local_access_only = false\nsecurity.listen_address = "0.0.0.0"\n'
        '[api]\ntls_terminated_upstream = true\ntrusted_proxies = ["10.0.0.7"]\n',
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
    (tmp_path / "messagefoundry.toml").write_text(
        "security.handles_real_patient_data = false\nsecurity.local_access_only = true\n",
        encoding="utf-8",
    )
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

_SECURE_ALERTS = '[alerts]\nemail_smtp_host = "smtp.example.org"\nemail_from = "sec@example.org"\n'


def _posture_b_toml(
    tmp_path: Path,
    *,
    intra: str = "none",
    floor: str | None = None,
    enforcement: str | None = None,
    synthetic: bool = False,
    loopback: bool = False,
) -> None:
    """A non-loopback Posture-B bind (declared proxy) with every NON-Posture-B exposure gate satisfied
    (egress deny-by-default + secure retention + SMTP alerts), so only the intra-service-auth + KEX-floor
    attestations are under test. ``intra``/``floor`` toggle the two Posture-B knobs."""
    lines = [
        "[api]",
        "tls_terminated_upstream = true",
        'trusted_proxies = ["10.0.0.9"]',
        f'proxy_intra_service_auth = "{intra}"',
    ]
    if floor is not None:
        lines.append(f'proxy_tls_min_version = "{floor}"')
    # [security] posture switches lead (document root); non-security [api] plumbing follows.
    # enforcement=warn reproduces the historical non-production dial (the Posture-B gate WARNS + starts).
    # loopback=True is the topology OFF-LOOPBACK-DEPLOYMENT.md RECOMMENDS: the engine stays on
    # 127.0.0.1 and the proxy on the same host faces the network. The bind-keyed gates never fire
    # there, which is exactly why the attestation gate had to move onto the declaration.
    body = (
        (f'security.enforcement = "{enforcement}"\n' if enforcement else "")
        + ("security.handles_real_patient_data = false\n" if synthetic else "")
        + (
            ""
            if loopback
            else 'security.local_access_only = false\nsecurity.listen_address = "0.0.0.0"\n'
        )
        + "security.block_unlisted_outbound = true\n"
        "security.delete_message_bodies_after_days = 30\n"
        # ADR 0152 rung 2: a declared TLS terminator counts as EXPOSED, so a PHI instance here also
        # warns without an in-use data-protection declaration. Declared with the rest of the
        # non-Posture-B plumbing so these cases keep testing the two Posture-B attestations and not
        # the last rung in the ladder.
        "security.memory_encryption_operator_declared = true\n"
        + "\n".join(lines)
        + "\n[retention]\ndead_letter_days = 30\n"
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
    # enforcement=warn reproduces the historical non-production dial: the Posture-B gate WARNS + starts
    # (the security dial is decoupled from the production tier — staging under default enforce refuses).
    _posture_b_toml(tmp_path, intra="none", floor=None, enforcement="warn")
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


def test_serve_warns_not_refuses_posture_b_on_loopback_behind_declared_proxy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The gate used to require `not is_loopback`, so the RECOMMENDED topology (engine on 127.0.0.1,
    # proxy on the same host facing the network) never consulted it at all — the discouraged direct
    # NIC bind got the check and the recommended one did not. Now the DECLARATION triggers it, but the
    # loopback arm WARNS and still starts: refusing would hard-stop working deployments on upgrade.
    _posture_b_toml(tmp_path, intra="none", floor=None, loopback=True)
    assert _run_posture_b(tmp_path, monkeypatch, env="prod") == 0
    err = capsys.readouterr().err
    assert "proxy_intra_service_auth" in err and "proxy_tls_min_version" in err
    assert "refusing to serve" not in err
    assert "recommended loopback-behind-proxy topology" in err


def test_serve_still_refuses_posture_b_off_loopback_after_the_loopback_widening(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Regression pin: widening the gate onto the declaration must be ADDITIVE. The off-loopback
    # production-PHI arm keeps refusing exactly as before — a warning was added, never a refusal removed.
    _posture_b_toml(tmp_path, intra="none", floor=None, loopback=False)
    assert _run_posture_b(tmp_path, monkeypatch, env="prod") == 2
    assert "refusing to serve on a production PHI" in capsys.readouterr().err


def test_serve_posture_b_loopback_synthetic_is_quiet(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The widening must not make a synthetic loopback dev box noisy — byte-identical, as for the
    # keyless/MFA gates.
    _posture_b_toml(tmp_path, intra="none", floor=None, synthetic=True, loopback=True)
    assert _run_posture_b(tmp_path, monkeypatch, env="dev", key=False) == 0
    assert "proxy_intra_service_auth" not in capsys.readouterr().err


def test_serve_posture_b_synthetic_is_quiet(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # A synthetic instance (dev) stays quiet on the Posture-B posture (byte-identical — parity with the
    # keyless / MFA gates), even with both attestations undeclared. GIVEN 1 (ADR 0148): dev derives PHI
    # now, so declare the synthetic opt-out explicitly.
    _posture_b_toml(tmp_path, intra="none", floor=None, synthetic=True)
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
    (tmp_path / "messagefoundry.toml").write_text(
        "security.handles_real_patient_data = false\nsecurity.local_access_only = true\n",
        encoding="utf-8",
    )
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


def test_client_cert_principal_cn_cannot_collide_with_pinned_san() -> None:
    # AUTHN-18 CELL A: the CN/SAN namespaces are DISJOINT (_cert_name_candidates yields "CN:<v>" vs
    # "SAN:DNS:<v>"), so a spoofed commonName can never collide with a pinned DNS SAN — the cross-
    # namespace impersonation the deny-by-default chain must refuse.
    # A bare CN whose string EQUALS a pinned SAN value resolves to NO principal (it is a CN:, not SAN:DNS:).
    assert (
        client_cert_principal(_peercert("api.internal"), {"SAN:DNS:api.internal": "api-user"})
        is None
    )
    # Mirror: a SAN DNS value equal to a pinned CN is likewise denied (SAN:DNS: never matches a CN: key).
    assert (
        client_cert_principal(
            _peercert("x", ("DNS", "svc.internal")), {"CN:svc.internal": "svc-user"}
        )
        is None
    )


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


async def test_disabled_mapped_account_denied_via_cert_path(tmp_path: Path) -> None:
    # AUTHN-18 CELL B: identity_for_username's disabled branch (service.py:807) fails CLOSED through the
    # cert plane. A VALID, MAPPED, verified cert whose backing account was DISABLED is still denied — a
    # pinned cert map can never keep a deactivated service account alive.
    engine = await Engine.create(tmp_path / "mtls_disabled.db", poll_interval=0.02)
    try:
        service = AuthService(engine.store, AuthSettings(require_mfa=False))
        await service.initialize()
        uid = await service.create_local_user(
            username="svc",
            password="Correct-horse-battery-9",
            display_name=None,
            email=None,
            roles=[Role.OPERATOR.value],
            actor="test",
        )
        assert uid
        # Deactivate the account AFTER creating + mapping it — the cert map still points at "svc".
        await service.update_user(uid, display_name=None, email=None, disabled=True, actor="test")
        app = create_app(
            engine, auth=service, tls_client_cert_identities={"CN:svc.internal": "svc"}
        )
        # Resolver: a verified, MAPPED cert for the now-disabled account resolves to no identity.
        assert (
            await resolve_client_cert_identity(_cert_request(app, _peercert("svc.internal")))
            is None
        )
        # Route: the /service/identity route denies the same disabled principal → 401 (deny-by-default).
        transport = httpx.ASGITransport(app=_wrap_with_cert(app, _peercert("svc.internal")))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            assert (await c.get("/service/identity")).status_code == 401
    finally:
        await engine.stop()


# --- ASVS 6.4.5 arm 3: a service caller's client cert is watched at the mTLS handshake -------------


class _RecordingCertSink:
    """Captures cert_expiry alerts (an AlertSink stand-in — only the one method is exercised)."""

    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.events: list[dict[str, Any]] = []

    def cert_expiry(self, name: str, *, path: str, not_after: str, days_remaining: int) -> None:
        if self.fail:
            raise RuntimeError("sink down")
        self.events.append(
            {
                "name": name,
                "path": path,
                "not_after": not_after,
                "days_remaining": days_remaining,
            }
        )


def _expiring_peercert(cn: str, *, in_days: float) -> dict[str, object]:
    """A verified peer cert for ``cn`` whose notAfter is ``in_days`` out, in OpenSSL's textual form."""
    when = datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=in_days)
    cert = _peercert(cn)
    cert["notAfter"] = when.strftime("%b %d %H:%M:%S %Y GMT")
    return cert


async def _cert_app(engine: Engine, **state: Any) -> Any:
    """An app with the cert map wired, plus whatever app.state the monitor arm reads."""
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    # Idempotent: some cases build two apps over one store (the user then already exists).
    if await engine.store.get_user_by_username("svc") is None:
        assert await service.create_local_user(
            username="svc",
            password="Correct-horse-battery-9",
            display_name=None,
            email=None,
            roles=[Role.OPERATOR.value],
            actor="test",
        )
    app = create_app(engine, auth=service, tls_client_cert_identities={"CN:svc.internal": "svc"})
    for key, value in state.items():
        setattr(app.state, key, value)
    return app


async def test_service_cert_inside_warn_window_raises_cert_expiry(tmp_path: Path) -> None:
    # The residual's acceptance test: a service-cert handshake inside the warn window raises cert_expiry
    # with the caller's label. The engine never holds this cert as a FILE — the handshake is the only
    # place its expiry is observable — so without this arm a service caller's cert expires unannounced.
    engine = await Engine.create(tmp_path / "certwarn.db", poll_interval=0.02)
    try:
        sink = _RecordingCertSink()
        app = await _cert_app(
            engine, notifier=sink, cert_monitor_settings=CertMonitorSettings(warn_days=30)
        )
        ident = await resolve_client_cert_identity(
            _cert_request(app, _expiring_peercert("svc.internal", in_days=10))
        )
        # Advisory: the alert never gates the resolution — the caller still authenticates.
        assert ident is not None and ident.username == "svc"
        assert len(sink.events) == 1
        event = sink.events[0]
        assert event["name"] == "api-client:svc"  # the caller's label, namespaced
        assert event["days_remaining"] == 9  # floor of just-under-10 days
        assert "handshake" in event["path"]  # honest provenance: there is no local PEM file
    finally:
        await engine.stop()


async def test_service_cert_outside_warn_window_is_silent(tmp_path: Path) -> None:
    engine = await Engine.create(tmp_path / "certok.db", poll_interval=0.02)
    try:
        sink = _RecordingCertSink()
        app = await _cert_app(
            engine, notifier=sink, cert_monitor_settings=CertMonitorSettings(warn_days=30)
        )
        ident = await resolve_client_cert_identity(
            _cert_request(app, _expiring_peercert("svc.internal", in_days=400))
        )
        assert ident is not None
        assert sink.events == []  # comfortably valid → nothing to say
    finally:
        await engine.stop()


async def test_client_cert_expiry_alert_is_throttled_per_cert(tmp_path: Path) -> None:
    # This runs on a PER-REQUEST path: without the throttle a chatty caller would drive an
    # alert_instance upsert per request (durable alert-state is written BEFORE the sink's own
    # notification throttle). A renewed cert (new notAfter) must still alert immediately.
    engine = await Engine.create(tmp_path / "certthrottle.db", poll_interval=0.02)
    try:
        sink = _RecordingCertSink()
        app = await _cert_app(
            engine, notifier=sink, cert_monitor_settings=CertMonitorSettings(warn_days=30)
        )
        cert = _expiring_peercert("svc.internal", in_days=10)
        for _ in range(5):
            assert await resolve_client_cert_identity(_cert_request(app, cert)) is not None
        assert len(sink.events) == 1  # five requests, one alert
        # A DIFFERENT notAfter is a different cert — it is not muted by the replaced cert's cooldown.
        renewed = _expiring_peercert("svc.internal", in_days=20)
        assert await resolve_client_cert_identity(_cert_request(app, renewed)) is not None
        assert len(sink.events) == 2
    finally:
        await engine.stop()


async def test_client_cert_expiry_silent_when_monitor_off_or_unwired(tmp_path: Path) -> None:
    # warn_days=0 disables the monitor; an app with no [cert_monitor] on state (the direct create_app /
    # embedding path) is likewise inert — deny-by-default for a monitoring signal.
    engine = await Engine.create(tmp_path / "certoff.db", poll_interval=0.02)
    try:
        off = _RecordingCertSink()
        app_off = await _cert_app(
            engine, notifier=off, cert_monitor_settings=CertMonitorSettings(warn_days=0)
        )
        assert await resolve_client_cert_identity(
            _cert_request(app_off, _expiring_peercert("svc.internal", in_days=1))
        )
        assert off.events == []

        unwired = _RecordingCertSink()
        app_unwired = await _cert_app(engine, notifier=unwired)  # no cert_monitor_settings at all
        assert await resolve_client_cert_identity(
            _cert_request(app_unwired, _expiring_peercert("svc.internal", in_days=1))
        )
        assert unwired.events == []
    finally:
        await engine.stop()


async def test_unmapped_cert_never_raises_an_expiry_alert(tmp_path: Path) -> None:
    # The alert label space must stay bounded by the operator's OWN allow-list: an unmapped/spoofed cert
    # is denied before the check, so a stranger cannot drive alert volume or grow the throttle dict.
    engine = await Engine.create(tmp_path / "certunmapped.db", poll_interval=0.02)
    try:
        sink = _RecordingCertSink()
        app = await _cert_app(
            engine, notifier=sink, cert_monitor_settings=CertMonitorSettings(warn_days=30)
        )
        assert (
            await resolve_client_cert_identity(
                _cert_request(app, _expiring_peercert("attacker.evil", in_days=1))
            )
            is None
        )
        assert sink.events == []
    finally:
        await engine.stop()


async def test_client_cert_expiry_check_never_breaks_authentication(tmp_path: Path) -> None:
    # A monitoring signal hangs off an AUTH path: a sink that raises must degrade to "no alert", never
    # to a failed authentication.
    engine = await Engine.create(tmp_path / "certraise.db", poll_interval=0.02)
    try:
        app = await _cert_app(
            engine,
            notifier=_RecordingCertSink(fail=True),
            cert_monitor_settings=CertMonitorSettings(warn_days=30),
        )
        ident = await resolve_client_cert_identity(
            _cert_request(app, _expiring_peercert("svc.internal", in_days=1))
        )
        assert ident is not None and ident.username == "svc"
    finally:
        await engine.stop()


async def test_cert_without_notafter_still_authenticates(tmp_path: Path) -> None:
    # A peer cert dict carrying no parseable notAfter simply yields no alert (the pre-6.4.5 shape).
    engine = await Engine.create(tmp_path / "certnona.db", poll_interval=0.02)
    try:
        sink = _RecordingCertSink()
        app = await _cert_app(
            engine, notifier=sink, cert_monitor_settings=CertMonitorSettings(warn_days=30)
        )
        ident = await resolve_client_cert_identity(_cert_request(app, _peercert("svc.internal")))
        assert ident is not None and ident.username == "svc"
        assert sink.events == []
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


# --- #200 residual: cert-authenticated intra-service auth is AUDITED (ADR 0083/0092) ---------------


async def test_service_cert_auth_emits_audit_event(tmp_path: Path) -> None:
    # Residual (Posture-B tail): a successful mTLS cert authentication must not be a SILENT admission — it
    # writes a `service_cert_auth` row into the tamper-evident audit chain naming the mapped principal.
    engine, app = await _svc_app(tmp_path, "svc_audit.db", Role.VIEWER)
    try:
        transport = httpx.ASGITransport(app=_wrap_with_cert(app, _peercert("svc.internal")))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            assert (await c.get("/service/identity")).status_code == 200
        rows = await engine.store.list_audit(action="service_cert_auth")
        assert len(rows) == 1
        assert rows[0]["actor"] == "svc"
        # PHI/secret-safe: the audit detail carries only the auth plane + route, never a cert body.
        assert "mtls-client-cert" in (rows[0]["detail"] or "")
        # Negative: a denied (spoofed) cert never authenticates, so it writes NO audit row.
        t_spoof = httpx.ASGITransport(app=_wrap_with_cert(app, _peercert("attacker.evil")))
        async with httpx.AsyncClient(transport=t_spoof, base_url="http://t") as c:
            assert (await c.get("/service/identity")).status_code == 401
        assert len(await engine.store.list_audit(action="service_cert_auth")) == 1
    finally:
        await engine.stop()


# --- #200 residual: runtime KEX enforcement + a real (mutual) TLS handshake on the built context ----


def _handshake(
    server_ctx: ssl.SSLContext, client_ctx: ssl.SSLContext, *, client_cert: tuple[Path, Path] | None
) -> str | None:
    """Drive a REAL TLS handshake over a loopback socket using ``server_ctx`` (the exact context the serve
    path builds via :func:`build_api_ssl_context`). Returns the negotiated cipher name on success; raises
    ``ssl.SSLError`` when the handshake is refused. ``client_cert`` presents a client cert (mTLS)."""
    import socket
    import threading

    if client_cert is not None:
        client_ctx.load_cert_chain(certfile=str(client_cert[0]), keyfile=str(client_cert[1]))
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(1)
    host, port = lsock.getsockname()
    server_err: list[BaseException] = []

    def _serve_once() -> None:
        try:
            raw, _ = lsock.accept()
        except OSError:
            return
        try:
            ss = server_ctx.wrap_socket(raw, server_side=True)  # the handshake
        except (
            OSError
        ) as exc:  # a handshake refusal (e.g. missing/invalid client cert) — the real signal
            server_err.append(exc)
            raw.close()
            return
        # Handshake OK: a one-byte ping-pong so the client does not RST-close before the server finishes
        # the handshake (a Windows race that would masquerade as a handshake failure). Post-handshake
        # teardown aborts are ignored — only a handshake refusal is the signal.
        try:
            ss.sendall(b"1")
            ss.recv(16)
        except OSError:
            pass
        finally:
            try:  # noqa: SIM105
                ss.close()
            except OSError:
                pass

    t = threading.Thread(target=_serve_once, daemon=True)
    t.start()
    client_cipher: str | None = None
    client_err: BaseException | None = None
    try:
        with socket.create_connection((host, port), timeout=5) as raw:  # noqa: SIM117
            with client_ctx.wrap_socket(raw, server_hostname="localhost") as cs:
                cipher = cs.cipher()
                client_cipher = cipher[0] if cipher else None
                cs.recv(
                    16
                )  # wait for the server's ping so we don't close before it exits the handshake
                cs.sendall(b"ok")
    except (
        OSError
    ) as exc:  # ssl.SSLError subclasses OSError; a server-side abort surfaces as OSError too
        client_err = exc
    finally:
        t.join(timeout=5)
        lsock.close()
    # A refusal may surface on EITHER side (TLS 1.3: the client can finish before the server validates the
    # peer cert, so a missing-client-cert rejection appears server-side, and a rejected client sees a
    # connection abort). Surface either as an OSError so the caller can assert on it uniformly.
    if client_err is not None:
        raise client_err
    if server_err:
        raise server_err[0]
    return client_cipher


def _strict_ca_and_leaf(tmp_path: Path) -> tuple[Path, Path, Path]:
    """A RFC 5280-conformant CA + a localhost leaf (serverAuth+clientAuth EKU) that pass the
    ``VERIFY_X509_STRICT`` flag ``build_api_ssl_context`` ORs on. Returns ``(ca_pem, leaf_cert, leaf_key)``;
    the single leaf serves as BOTH the server cert and (for mTLS) the client cert, and the CA PEM is the
    shared trust anchor for both directions."""
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "MEFOR Test CA")])
    nb = datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC)
    na = datetime.datetime(2040, 1, 1, tzinfo=datetime.UTC)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nb)
        .not_valid_after(na)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False
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
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nb)
        .not_valid_after(na)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_pem = tmp_path / "ca.pem"
    leaf_c = tmp_path / "leaf-c.pem"
    leaf_k = tmp_path / "leaf-k.pem"
    ca_pem.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    leaf_c.write_bytes(leaf_cert.public_bytes(serialization.Encoding.PEM))
    leaf_k.write_bytes(
        leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return ca_pem, leaf_c, leaf_k


def _verifying_client_ctx(ca: Path) -> ssl.SSLContext:
    return ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca))


#: Key-exchange groups OUTSIDE `APPROVED_KEX_GROUPS` that a client can pin via `set_ecdh_curve`.
#: `x448` and `X25519MLKEM768` are deliberately absent — they are TLS groups but not EC curve NAMES, so
#: `set_ecdh_curve` raises on them and this technique cannot measure them.
_NON_APPROVED_KEX_PROBES = ("ffdhe2048", "ffdhe3072", "secp521r1", "secp224r1", "sect571r1")

#: The approved groups, spelled for `set_ecdh_curve` — `prime256v1`, never `secp256r1` (see
#: APPROVED_KEX_GROUPS: the group-list alias and the EC curve name differ for exactly this curve).
_APPROVED_KEX_PROBES = ("X25519", "secp384r1", "prime256v1")


def _kex_group_accepted(server_ctx: ssl.SSLContext, ca: Path, group: str) -> bool:
    """Does ``server_ctx`` complete a handshake with a client offering ONLY ``group``?"""
    client = _verifying_client_ctx(ca)
    # A ValueError here is a bug in this test's group table, not a finding — let it raise loudly rather
    # than degrade into "not accepted", which would silently manufacture the result we want.
    client.set_ecdh_curve(group)
    try:
        return bool(_handshake(server_ctx, client, client_cert=None))
    except OSError:
        return False


def test_which_kex_groups_the_built_context_actually_accepts(tmp_path: Path) -> None:
    """MEASURE the built context's key-exchange groups (ASVS 11.6.2).

    This replaces a test that asserted the opposite of the truth and stayed green by skipping. It read:
    "a client offering ONLY ffdhe2048 ... shares no key-exchange group with the pinned server, so the
    handshake is refused — runtime enforcement". It reached that assertion only through client-side
    ``set_groups``, a **Python 3.15** API, so on every interpreter this project runs on it hit
    ``pytest.skip``. And the claim was false: measured, this context ACCEPTS ffdhe2048, because
    ``harden_kex_groups`` pins nothing. A skip was concealing a wrong assertion, which is worse than no
    test — ADR 0092 §4(b) cited it as proof.

    ``set_ecdh_curve`` is the API that does exist, and it genuinely constrains the TLS 1.3
    ``supported_groups``: verified separately that a server pinned to ``prime256v1`` refuses a client
    pinned to ``secp384r1`` (``NO_SUITABLE_KEY_SHARE``) while the unpinned control accepts it. One group
    per handshake is enough to enumerate what the server will take.

    Asserted as INVARIANTS, not as an exact table: the accepted set comes from the linked OpenSSL's
    default group list and a CI leg may link a different build. What must hold is that *every* approved
    group gets in (else the server is over-restricted, or the harness is broken, and the second
    assertion would pass for the wrong reason) and that *some* non-approved group gets in (proving the
    approved list is not enforced). The measured table is printed on failure either way.

    Mutation: make ``_kex_group_accepted`` return True unconditionally. Red — the "genuinely weak curves
    stay out" assertions fail, so a probe that cannot distinguish anything is caught.
    """
    ca, cert, key = _strict_ca_and_leaf(tmp_path)
    server_ctx = build_api_ssl_context(
        ApiSettings(tls_cert_file=str(cert), tls_key_file=str(key), tls_min_version="1.3")
    )

    # Positive control first: a default client must negotiate a forward-secret TLS 1.3 suite at all.
    cipher = _handshake(server_ctx, _verifying_client_ctx(ca), client_cert=None)
    assert cipher and cipher.startswith("TLS_")

    approved = {g: _kex_group_accepted(server_ctx, ca, g) for g in _APPROVED_KEX_PROBES}
    non_approved = {g: _kex_group_accepted(server_ctx, ca, g) for g in _NON_APPROVED_KEX_PROBES}
    table = f"approved={approved} non_approved={non_approved}"

    assert all(approved.values()), f"the built context refuses an APPROVED group — {table}"

    # The residual of record: the approved list is NOT enforced, because a group outside it gets in.
    leaked = sorted(g for g, ok in non_approved.items() if ok)
    assert leaked, (
        "no non-approved key-exchange group was accepted, so the built context now DOES constrain "
        "groups to the approved list. That is an improvement, not a test failure — re-score ASVS "
        f"11.6.2, update docs/PHI.md §4 and the register, then tighten this test. {table}"
    )

    # ...and the genuinely weak curves stay out, so the residual is "wider than policy", not "insecure".
    # If either of these fails it is a real finding on that OpenSSL build, not a flake.
    assert not non_approved["secp224r1"], f"a 112-bit-strength curve was accepted — {table}"
    assert not non_approved["sect571r1"], f"a binary-field curve was accepted — {table}"


def test_real_mutual_tls_handshake_on_built_context(tmp_path: Path) -> None:
    # A REAL mutual-TLS handshake against the exact server context the serve path builds (CERT_REQUIRED via
    # tls_client_ca_file). A client presenting the trusted cert completes; a client presenting NO cert is
    # refused by the server. This is the handshake-level integration the core shipment left as unit-only.
    ca, cert, key = _strict_ca_and_leaf(tmp_path)
    server_ctx = build_api_ssl_context(
        ApiSettings(tls_cert_file=str(cert), tls_key_file=str(key), tls_client_ca_file=str(ca))
    )
    assert server_ctx.verify_mode == ssl.CERT_REQUIRED
    # Positive: the client presents the trusted leaf cert → mutual handshake succeeds.
    cipher = _handshake(server_ctx, _verifying_client_ctx(ca), client_cert=(cert, key))
    assert cipher
    # Negative: no client cert → the server (CERT_REQUIRED) refuses the handshake.
    with pytest.raises(OSError):
        _handshake(server_ctx, _verifying_client_ctx(ca), client_cert=None)


# NOTE (residual, honest scope): a full uvicorn-on-a-real-socket mTLS handshake through the serve path
# (build_api_ssl_context wired into a live uvicorn bind) is a CI/infra-bound integration left to the
# windows-service-smoke / TLS CI legs — the handshake logic above exercises the SAME server context the
# serve path builds, so the drift it would catch is the uvicorn wiring, not the TLS policy itself.
