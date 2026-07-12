# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for the shared TLS key-exchange policy (ASVS 11.6.2, WP-L3-10 code half)."""

from __future__ import annotations

import ssl
import types
from itertools import product

import pytest

from messagefoundry.config.tls_policy import (
    APPROVED_KEX_GROUPS,
    TLS_REVOCATION_ATTESTED_ENV,
    HopDisposition,
    HopPosture,
    InsecureHopRefused,
    _is_forward_secret,
    active_hop_posture,
    current_hop_posture,
    enforce_insecure_hop,
    harden_kex_groups,
    harden_verify_flags,
    in_process_tls_revocation_refused,
    insecure_hop_disposition,
    is_loopback_hop_host,
    tls_revocation_attested,
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


# --- certificate-revocation posture (ASVS 12.1.4, ADR 0078) -----------------------------------
@pytest.mark.parametrize(
    "tls_enabled,is_loopback,proxy_terminated,attested,expected_refuse",
    [
        # loopback default (no TLS) — never trips; byte-identical start
        (False, True, False, False, False),
        # loopback WITH in-process TLS — still never trips (not network-reachable)
        (True, True, False, False, False),
        # off-loopback PLAINTEXT (no in-process cert) — the gate keys on tls_enabled, so it passes
        (False, False, False, False, False),
        # off-loopback in-process TLS, no proxy, no attestation — THE fail-closed refusal
        (True, False, False, False, True),
        # off-loopback in-process TLS behind a declared proxy — revocation proven in front
        (True, False, True, False, False),
        # off-loopback in-process TLS with the operator attestation opt-out
        (True, False, False, True, False),
        # both proofs present — still starts
        (True, False, True, True, False),
    ],
)
def test_in_process_tls_revocation_refused_matrix(
    tls_enabled: bool,
    is_loopback: bool,
    proxy_terminated: bool,
    attested: bool,
    expected_refuse: bool,
) -> None:
    assert (
        in_process_tls_revocation_refused(
            tls_enabled=tls_enabled,
            is_loopback=is_loopback,
            proxy_terminated=proxy_terminated,
            attested=attested,
        )
        is expected_refuse
    )


@pytest.mark.parametrize("val", ["1", "true", "TRUE", "Yes", "on"])
def test_tls_revocation_attested_truthy(val: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(TLS_REVOCATION_ATTESTED_ENV, val)
    assert tls_revocation_attested() is True


@pytest.mark.parametrize("val", ["", "0", "false", "no", "off", "  "])
def test_tls_revocation_attested_falsy(val: str, monkeypatch: pytest.MonkeyPatch) -> None:
    # The secure default: unset or any non-truthy value means NOT attested → the gate refuses.
    monkeypatch.setenv(TLS_REVOCATION_ATTESTED_ENV, val)
    assert tls_revocation_attested() is False


def test_tls_revocation_attested_unset_is_false(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(TLS_REVOCATION_ATTESTED_ENV, raising=False)
    assert tls_revocation_attested() is False


# --- #200 (ADR 0092) posture-keyed transport-hop refusal ---------------------------------------


@pytest.mark.parametrize(
    "host,expected",
    [
        ("127.0.0.1", True),
        ("127.5.6.7", True),  # all of 127.0.0.0/8, not just .0.0.1
        ("::1", True),
        ("localhost", True),
        ("LOCALHOST", True),  # case-insensitive
        ("", True),  # empty host = on-box bind with no host component
        ("10.0.0.5", False),
        ("example.com", False),
        # A name that WOULD resolve to loopback is still remote — is_loopback_hop_host never resolves DNS.
        ("localhost.attacker.example", False),
        ("0.0.0.0", False),  # wildcard bind is not loopback
    ],
)
def test_is_loopback_hop_host(host: str, expected: bool) -> None:
    assert is_loopback_hop_host(host) is expected


def test_insecure_hop_disposition_full_precedence_table() -> None:
    """Exhaustively assert the owner-ratified precedence over every input combination."""
    for is_phi, production, is_loopback_hop, hop_attested, audited_opt_out in product(
        [False, True], repeat=5
    ):
        got = insecure_hop_disposition(
            is_phi=is_phi,
            production=production,
            is_loopback_hop=is_loopback_hop,
            hop_attested=hop_attested,
            audited_opt_out=audited_opt_out,
        )
        # Explicit early-return precedence: loopback -> attested -> synthetic -> opt-out -> prod -> else.
        if is_loopback_hop:
            expected = HopDisposition.ALLOW
        elif hop_attested:
            expected = HopDisposition.ALLOW
        elif not is_phi:
            expected = HopDisposition.ALLOW
        elif audited_opt_out:
            expected = HopDisposition.WARN
        elif production:
            expected = HopDisposition.REFUSE
        else:
            expected = HopDisposition.WARN
        assert got is expected, (is_phi, production, is_loopback_hop, hop_attested, audited_opt_out)


def test_insecure_hop_prod_phi_refuses_and_escape_cannot_relax() -> None:
    """The headline case: a prod-PHI hop refuses, and the (clamped-to-False on prod) escape cannot help."""
    base = dict(is_phi=True, production=True, is_loopback_hop=False, hop_attested=False)
    # The escape (audited_opt_out) is clamped to False on prod upstream (settings.hop_insecure_escape_
    # downgrades), so the realistic prod input is False here → REFUSE.
    assert insecure_hop_disposition(**base, audited_opt_out=False) is HopDisposition.REFUSE
    # Attestation is the ONLY per-hop way across a prod-PHI hop:
    assert (
        insecure_hop_disposition(
            is_phi=True,
            production=True,
            is_loopback_hop=False,
            hop_attested=True,
            audited_opt_out=False,
        )
        is HopDisposition.ALLOW
    )


def test_insecure_hop_staging_phi_still_refuses_only_when_prod() -> None:
    # Non-prod PHI (staging/dev-with-phi) WARNs, it does not refuse — the gradient adds coverage, it
    # never turns a staging hop that only warns today into a refusal.
    assert (
        insecure_hop_disposition(
            is_phi=True,
            production=False,
            is_loopback_hop=False,
            hop_attested=False,
            audited_opt_out=False,
        )
        is HopDisposition.WARN
    )
    # ...and a non-prod audited opt-out also WARNs (the escape relaxes REFUSE->WARN only, non-prod).
    assert (
        insecure_hop_disposition(
            is_phi=True,
            production=False,
            is_loopback_hop=False,
            hop_attested=False,
            audited_opt_out=True,
        )
        is HopDisposition.WARN
    )


def test_enforce_insecure_hop_refuse_raises() -> None:
    with pytest.raises(InsecureHopRefused) as exc:
        enforce_insecure_hop(
            HopDisposition.REFUSE, message="cleartext http to db.example", cell="REST egress"
        )
    assert "REST egress" in str(exc.value)
    assert isinstance(exc.value, ValueError)  # flows through connector-construction error handling


def test_enforce_insecure_hop_warn_logs_and_audits() -> None:
    audited: list[str] = []
    enforce_insecure_hop(
        HopDisposition.WARN,
        message="cleartext http to seg.internal",
        cell="REST egress",
        audit_sink=audited.append,
    )
    assert audited == ["REST egress: cleartext http to seg.internal"]


def test_enforce_insecure_hop_allow_is_noop() -> None:
    audited: list[str] = []
    enforce_insecure_hop(
        HopDisposition.ALLOW, message="loopback", cell="REST egress", audit_sink=audited.append
    )
    assert audited == []  # no audit, no raise


def test_hop_posture_fail_closed_defaults_unknown_to_strict() -> None:
    assert HopPosture.fail_closed(is_phi=None, production=None) == HopPosture(
        is_phi=True, production=True
    )
    # A fully-declared posture passes through unchanged (not strictest-by-default).
    assert HopPosture.fail_closed(is_phi=False, production=False) == HopPosture(
        is_phi=False, production=False
    )
    assert HopPosture.fail_closed(is_phi=True, production=None) == HopPosture(
        is_phi=True, production=True
    )


def test_active_hop_posture_stamps_and_restores() -> None:
    assert current_hop_posture() is None
    posture = HopPosture(is_phi=True, production=True)
    with active_hop_posture(posture):
        assert current_hop_posture() is posture
        # nesting restores the outer value on exit
        with active_hop_posture(None):
            assert current_hop_posture() is None
        assert current_hop_posture() is posture
    assert current_hop_posture() is None
