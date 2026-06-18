# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for the shared TLS key-exchange policy (ASVS 11.6.2, WP-L3-10 code half)."""

from __future__ import annotations

import ssl
import types

import pytest

from messagefoundry.config.tls_policy import (
    APPROVED_KEX_GROUPS,
    _is_forward_secret,
    harden_kex_groups,
    harden_verify_flags,
    validate_tls_ciphers,
)


# --- _is_forward_secret: deterministic classification, no OpenSSL dependency -------------------
@pytest.mark.parametrize(
    "cipher,expected",
    [
        ({"name": "ECDHE-RSA-AES256-GCM-SHA384"}, True),
        ({"name": "ECDHE-ECDSA-CHACHA20-POLY1305"}, True),
        ({"name": "DHE-RSA-AES256-GCM-SHA384"}, True),  # finite-field DHE is still forward-secret
        ({"name": "TLS_AES_256_GCM_SHA384"}, True),  # TLS 1.3 suite name
        ({"name": "AES256-GCM-SHA384", "protocol": "TLSv1.3"}, True),  # 1.3 via protocol field
        ({"name": "AES256-SHA", "description": "Kx=RSA Au=RSA Enc=AES(256)"}, False),  # static RSA
        ({"name": "AES128-GCM-SHA256", "description": "Kx=RSA"}, False),
        ({"name": "weird", "description": "Kx=ECDH/RSA"}, True),  # description fallback
    ],
)
def test_is_forward_secret(cipher: dict[str, object], expected: bool) -> None:
    assert _is_forward_secret(cipher) is expected


# --- validate_tls_ciphers ----------------------------------------------------------------------
def test_validate_accepts_ecdhe_string() -> None:
    s = "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"
    assert validate_tls_ciphers(s) == s


def test_validate_accepts_ecdhe_family_alias() -> None:
    # OpenSSL family aliases resolve to ECDHE suites (plus the always-on TLS 1.3 suites).
    assert validate_tls_ciphers("ECDHE+AESGCM") == "ECDHE+AESGCM"


def test_validate_rejects_unparseable() -> None:
    with pytest.raises(ValueError, match="not a valid OpenSSL cipher string"):
        validate_tls_ciphers("TOTALLY-NOT-A-CIPHER")


def test_validate_rejects_non_forward_secret() -> None:
    # A static-RSA suite either fails to parse on a hardened OpenSSL or resolves to a non-FS suite;
    # both outcomes are a ValueError (the suite is refused, not silently accepted).
    with pytest.raises(ValueError):
        validate_tls_ciphers("AES256-SHA")


# --- harden_kex_groups -------------------------------------------------------------------------
def test_harden_does_not_raise_on_real_context() -> None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    harden_kex_groups(ctx)  # no-op pre-3.13, set_groups on 3.13+ — either way must not raise


def test_harden_is_noop_without_set_groups() -> None:
    # A runtime/object lacking set_groups is handled gracefully (older interpreters).
    fake = types.SimpleNamespace()
    harden_kex_groups(fake)  # type: ignore[arg-type]


def test_approved_groups_are_ecdhe_curves() -> None:
    assert APPROVED_KEX_GROUPS.split(":") == ["X25519", "secp384r1", "secp256r1"]


# --- harden_verify_flags -----------------------------------------------------------------------
def test_harden_verify_flags_sets_strict() -> None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    harden_verify_flags(ctx)
    # VERIFY_X509_STRICT is ORed in so a presented chain must be RFC 5280-conformant (ASVS 12.1.4).
    assert ctx.verify_flags & ssl.VERIFY_X509_STRICT


def test_harden_verify_flags_is_idempotent() -> None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    harden_verify_flags(ctx)
    first = ctx.verify_flags
    harden_verify_flags(ctx)  # ORing the same flag twice must not flip or clear anything
    assert ctx.verify_flags == first
    assert ctx.verify_flags & ssl.VERIFY_X509_STRICT


def test_harden_verify_flags_preserves_existing_flags() -> None:
    # The OR must add VERIFY_X509_STRICT without dropping flags a context already carries.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    harden_verify_flags(ctx)
    assert ctx.verify_flags & ssl.VERIFY_X509_PARTIAL_CHAIN
    assert ctx.verify_flags & ssl.VERIFY_X509_STRICT
