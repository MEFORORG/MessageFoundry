# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Pinned internal-CA trust anchor (#190, ADR 0093).

Covers the pure resolver precedence (connection-ca wins; system/augment/pinned; pinned excludes the
OS default roots; the loopback exemption), the byte-identical default (no ``[tls]`` block), and the
composition with the connectors' existing fail-closed no-CA / ``tls_verify=false`` refusals — the
internal CA SUPPLIES a trust anchor to a still-verifying context, it never disables verification.
"""

from __future__ import annotations

import datetime
import ssl
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import ServiceSettings, TlsSettings, load_settings
from messagefoundry.config.tls_policy import (
    TrustAnchor,
    TrustAnchorPolicy,
    build_verifying_client_context,
    resolve_trust_anchor,
)
from messagefoundry.transports.mllp import _mllp_ssl_context


def _ca_pem(tmp_path: Path, cn: str = "mefor-internal-ca") -> str:
    """A self-signed CA cert PEM (CA:TRUE) usable as a trust anchor."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2040, 1, 1, tzinfo=datetime.timezone.utc))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    p = tmp_path / f"{cn}.pem"
    p.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return str(p)


# --- pure resolver precedence -------------------------------------------------


def test_connection_ca_wins_verbatim_over_every_mode() -> None:
    # A connection that names its own tls_ca_file is authoritative regardless of the instance policy.
    for mode in ("system", "augment", "pinned"):
        policy = TrustAnchorPolicy(internal_ca_file="/org/internal-ca.pem", mode=mode)  # type: ignore[arg-type]
        anchor = resolve_trust_anchor(
            connection_ca_file="/conn/own-ca.pem", host="pacs.internal", policy=policy
        )
        assert anchor == TrustAnchor(cafile="/conn/own-ca.pem", load_system_roots=False)


def test_system_mode_is_os_trust_store_only() -> None:
    anchor = resolve_trust_anchor(
        connection_ca_file=None,
        host="pacs.internal",
        policy=TrustAnchorPolicy(internal_ca_file="/org/internal-ca.pem", mode="system"),
    )
    assert anchor == TrustAnchor(cafile=None, load_system_roots=True)


def test_augment_mode_is_os_roots_plus_internal_ca() -> None:
    anchor = resolve_trust_anchor(
        connection_ca_file=None,
        host="pacs.internal",
        policy=TrustAnchorPolicy(internal_ca_file="/org/internal-ca.pem", mode="augment"),
    )
    assert anchor == TrustAnchor(cafile="/org/internal-ca.pem", load_system_roots=True)


def test_pinned_mode_is_internal_ca_only_no_default_roots() -> None:
    anchor = resolve_trust_anchor(
        connection_ca_file=None,
        host="pacs.internal",
        policy=TrustAnchorPolicy(internal_ca_file="/org/internal-ca.pem", mode="pinned"),
    )
    assert anchor == TrustAnchor(cafile="/org/internal-ca.pem", load_system_roots=False)


def test_unset_internal_ca_falls_back_to_system_even_in_pinned() -> None:
    # No internal CA configured → nothing to pin → the OS trust store (byte-identical).
    anchor = resolve_trust_anchor(
        connection_ca_file=None,
        host="pacs.internal",
        policy=TrustAnchorPolicy(internal_ca_file=None, mode="pinned"),
    )
    assert anchor == TrustAnchor(cafile=None, load_system_roots=True)


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "", "::1", "127.5.6.7"])
def test_loopback_hop_is_exempt(host: str) -> None:
    # An on-box hop needs no org-PKI anchor — the internal CA is for verifying internal NETWORK peers.
    anchor = resolve_trust_anchor(
        connection_ca_file=None,
        host=host,
        policy=TrustAnchorPolicy(internal_ca_file="/org/internal-ca.pem", mode="pinned"),
    )
    assert anchor == TrustAnchor(cafile=None, load_system_roots=True)


# --- build_verifying_client_context: which roots are trusted ------------------


def test_pinned_context_excludes_default_roots(tmp_path: Path) -> None:
    ca = _ca_pem(tmp_path)
    pinned = build_verifying_client_context(TrustAnchor(cafile=ca, load_system_roots=False))
    system = build_verifying_client_context(TrustAnchor(cafile=None, load_system_roots=True))
    # Pinned trusts exactly the one internal CA; the OS store carries many roots.
    assert len(pinned.get_ca_certs()) == 1
    assert len(system.get_ca_certs()) > 1
    # Verification stays ON in every mode (never CERT_NONE) — the anchor only picks roots.
    assert pinned.verify_mode == ssl.CERT_REQUIRED
    assert pinned.check_hostname is True


def test_augment_context_is_system_plus_internal(tmp_path: Path) -> None:
    ca = _ca_pem(tmp_path)
    system = build_verifying_client_context(TrustAnchor(cafile=None, load_system_roots=True))
    augment = build_verifying_client_context(TrustAnchor(cafile=ca, load_system_roots=True))
    # Augment = the OS roots plus exactly the one extra internal CA (self-signed → not already present).
    assert len(augment.get_ca_certs()) == len(system.get_ca_certs()) + 1


# --- byte-identical default (no [tls] block) ----------------------------------


def test_service_settings_default_tls_is_system_noop(tmp_path: Path) -> None:
    cfg = tmp_path / "messagefoundry.toml"
    cfg.write_text("[api]\nport = 9000\n", encoding="utf-8")  # no [tls] section at all
    settings = load_settings(config_path=cfg, environ={})
    assert settings.tls.policy() == TrustAnchorPolicy(internal_ca_file=None, mode="system")


def test_default_destination_policy_is_system_noop() -> None:
    dest = Destination(name="OB_X", type=ConnectorType.MLLP)
    assert dest.trust_anchor_policy == TrustAnchorPolicy(internal_ca_file=None, mode="system")


def test_default_policy_context_is_byte_identical_to_no_policy(tmp_path: Path) -> None:
    # A default (system) policy resolves to exactly the historical create_default_context(cafile=ca).
    ca = _ca_pem(tmp_path)
    s = {"tls": True, "host": "db.example", "tls_verify": True, "tls_ca_file": ca}
    none_ctx = _mllp_ssl_context(s, server=False, trust_anchor_policy=None)
    sys_ctx = _mllp_ssl_context(s, server=False, trust_anchor_policy=TrustAnchorPolicy())
    assert none_ctx is not None and sys_ctx is not None
    # Connection's own CA wins under both → exactly that one anchor, no OS roots.
    assert len(none_ctx.get_ca_certs()) == 1 == len(sys_ctx.get_ca_certs())


# --- compose with the existing no-CA / verify-off refusals --------------------


def test_internal_ca_supplied_makes_the_internal_hop_verify(tmp_path: Path) -> None:
    # With no per-connection CA, a pinned internal CA supplies the trust anchor the internal hop needs.
    ca = _ca_pem(tmp_path)
    s = {"tls": True, "host": "pacs.internal", "tls_verify": True}
    ctx = _mllp_ssl_context(
        s,
        server=False,
        trust_anchor_policy=TrustAnchorPolicy(internal_ca_file=ca, mode="pinned"),
    )
    assert ctx is not None
    # Exactly the internal CA is trusted (pinned excludes the OS default roots) and verification is ON.
    assert len(ctx.get_ca_certs()) == 1
    assert ctx.verify_mode == ssl.CERT_REQUIRED


def test_internal_ca_never_bypasses_the_verify_off_refusal() -> None:
    # tls_verify=false is MITM-able and refused (no escape here); supplying an internal CA must NOT
    # silence that refusal — the anchor only picks roots for a still-verifying context.
    s = {"tls": True, "host": "pacs.internal", "tls_verify": False}
    with pytest.raises(ValueError, match="tls_verify=false"):
        _mllp_ssl_context(
            s,
            server=False,
            trust_anchor_policy=TrustAnchorPolicy(internal_ca_file="/org/ca.pem", mode="pinned"),
        )


def test_verify_off_path_is_cert_none_regardless_of_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    # With the dev escape set, verify-off is permitted — and stays CERT_NONE; the internal CA is inert
    # on that path (it never turns an unverified hop into a verified one, and vice-versa).
    monkeypatch.setenv("MEFOR_ALLOW_INSECURE_TLS", "1")
    s = {"tls": True, "host": "pacs.internal", "tls_verify": False}
    ctx = _mllp_ssl_context(
        s,
        server=False,
        trust_anchor_policy=TrustAnchorPolicy(internal_ca_file="/org/ca.pem", mode="pinned"),
    )
    assert ctx is not None
    assert ctx.verify_mode == ssl.CERT_NONE
    assert ctx.check_hostname is False


# --- the [tls] section loads from TOML + threads onto the outbound ------------


def test_tls_section_loads_from_toml(tmp_path: Path) -> None:
    ca = _ca_pem(tmp_path)
    cfg = tmp_path / "messagefoundry.toml"
    cfg.write_text(
        f'[tls]\ninternal_ca_file = "{Path(ca).as_posix()}"\ntrust_anchor_mode = "augment"\n',
        encoding="utf-8",
    )
    settings = load_settings(config_path=cfg, environ={})
    assert settings.tls.internal_ca_file == Path(ca).as_posix()
    assert settings.tls.trust_anchor_mode == "augment"
    assert settings.tls.policy() == TrustAnchorPolicy(
        internal_ca_file=Path(ca).as_posix(), mode="augment"
    )


def test_invalid_trust_anchor_mode_rejected(tmp_path: Path) -> None:
    cfg = tmp_path / "messagefoundry.toml"
    cfg.write_text('[tls]\ntrust_anchor_mode = "nonsense"\n', encoding="utf-8")
    with pytest.raises(ValueError):
        load_settings(config_path=cfg, environ={})


def test_settings_tls_defaults_when_omitted() -> None:
    assert ServiceSettings().tls == TlsSettings()


def test_pinned_mode_without_internal_ca_is_rejected_at_load(tmp_path: Path) -> None:
    # "pinned" excludes public CAs — with no internal_ca_file it would silently fall back to the full
    # OS trust store (fail-open). Refuse it at load rather than let the exclusion collapse.
    cfg = tmp_path / "messagefoundry.toml"
    cfg.write_text('[tls]\ntrust_anchor_mode = "pinned"\n', encoding="utf-8")
    with pytest.raises(ValueError, match="pinned.*requires.*internal_ca_file"):
        load_settings(config_path=cfg, environ={})


def test_pinned_mode_without_internal_ca_is_rejected_direct() -> None:
    with pytest.raises(ValueError, match="pinned.*requires.*internal_ca_file"):
        TlsSettings(trust_anchor_mode="pinned")


def test_pinned_mode_with_internal_ca_loads(tmp_path: Path) -> None:
    ca = _ca_pem(tmp_path)
    cfg = tmp_path / "messagefoundry.toml"
    cfg.write_text(
        f'[tls]\ninternal_ca_file = "{Path(ca).as_posix()}"\ntrust_anchor_mode = "pinned"\n',
        encoding="utf-8",
    )
    settings = load_settings(config_path=cfg, environ={})
    assert settings.tls.policy() == TrustAnchorPolicy(
        internal_ca_file=Path(ca).as_posix(), mode="pinned"
    )


def test_augment_mode_without_internal_ca_is_allowed() -> None:
    # augment-without-CA equals system (harmless), so it loads — only pinned needs the anchor.
    s = TlsSettings(trust_anchor_mode="augment")
    assert s.policy() == TrustAnchorPolicy(internal_ca_file=None, mode="augment")
