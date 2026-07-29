# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for the shared TLS key-exchange policy (ASVS 11.6.2, WP-L3-10 code half)."""

from __future__ import annotations

import inspect
import ssl
import types
from itertools import product

import pytest

from messagefoundry.config import tls_policy
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
    fips_attestation,
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


# --- fips_attestation: report-only FIPS-provider read-out (#73, ADR 0120) ----------------------


def test_fips_attestation_shape_and_never_raises() -> None:
    # AC-1: returns (bool|None, str); on this OpenSSL build the primitive is present → a real bool. The
    # version string is always ssl.OPENSSL_VERSION. It must never raise.
    fips_mode, openssl_version = fips_attestation()
    assert fips_mode in (True, False)  # get_fips_mode present on a stdlib OpenSSL CPython
    assert isinstance(openssl_version, str) and openssl_version
    assert openssl_version == ssl.OPENSSL_VERSION


def test_fips_attestation_undeterminable_without_primitive(monkeypatch: pytest.MonkeyPatch) -> None:
    # AC-1: on an alternative / non-OpenSSL build with no _hashlib.get_fips_mode, the getattr guard
    # yields None ("undeterminable") rather than raising. Simulate the missing primitive.
    fake = types.SimpleNamespace()  # no get_fips_mode attribute
    monkeypatch.setattr(tls_policy, "_hashlib", fake)
    fips_mode, openssl_version = fips_attestation()
    assert fips_mode is None
    assert openssl_version == ssl.OPENSSL_VERSION


@pytest.mark.parametrize("raw,expected", [(0, False), (1, True), (2, True)])
def test_fips_attestation_maps_int_flag_to_bool(
    monkeypatch: pytest.MonkeyPatch, raw: int, expected: bool
) -> None:
    # AC-1: the OpenSSL int flag (get_fips_mode returns int) is mapped to a plain bool.
    fake = types.SimpleNamespace(get_fips_mode=lambda: raw)
    monkeypatch.setattr(tls_policy, "_hashlib", fake)
    fips_mode, _ = fips_attestation()
    assert fips_mode is expected


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


def _legacy_insecure_hop_disposition(
    *,
    is_phi: bool,
    enforcing: bool,
    is_loopback_hop: bool,
    hop_attested: bool,
    audited_opt_out: bool,
) -> HopDisposition:
    """The PRE-ADR-0153 precedence, kept verbatim as the reference for the no-loosen property test.

    This is the only place the deleted ``not is_phi -> ALLOW`` arm still exists. Comparing the shipped
    authority against it across the whole OLD input space is what turns ADR 0153's central claim —
    "strictly stricter, provably" — into a check that can FAIL, rather than a sentence in a document.
    """
    if is_loopback_hop:
        return HopDisposition.ALLOW
    if hop_attested:
        return HopDisposition.ALLOW
    if not is_phi:
        return HopDisposition.ALLOW
    if audited_opt_out:
        return HopDisposition.WARN
    if enforcing:
        return HopDisposition.REFUSE
    return HopDisposition.WARN


def test_insecure_hop_disposition_full_precedence_table() -> None:
    """Exhaustively assert the ADR 0153 precedence over every input combination (2**4, not 2**5)."""
    for enforcing, is_loopback_hop, hop_attested, cleartext_accepted in product(
        [False, True], repeat=4
    ):
        got = insecure_hop_disposition(
            enforcing=enforcing,
            is_loopback_hop=is_loopback_hop,
            hop_attested=hop_attested,
            cleartext_accepted=cleartext_accepted,
        )
        # Explicit early-return precedence: loopback -> attested -> accepted -> not-enforcing -> REFUSE.
        if is_loopback_hop or hop_attested:
            expected = HopDisposition.ALLOW
        elif cleartext_accepted or not enforcing:
            expected = HopDisposition.WARN
        else:
            expected = HopDisposition.REFUSE
        assert got is expected, (enforcing, is_loopback_hop, hop_attested, cleartext_accepted)


def test_insecure_hop_disposition_no_longer_takes_a_data_label() -> None:
    """ADR 0153 decisions 1 + 5, as a detector that CAN fail if either parameter is reintroduced.

    Asserting the arms alone would not catch a re-added ``is_phi=False -> ALLOW`` arm hidden behind a
    defaulted parameter, because every existing call site would keep passing. The signature IS the
    contract, so the signature is what is pinned."""
    params = set(inspect.signature(insecure_hop_disposition).parameters)
    assert "is_phi" not in params, (
        "no data label may reach the cleartext-hop authority (ADR 0153 #1)"
    )
    assert "audited_opt_out" not in params, (
        "MEFOR_ALLOW_INSECURE_TLS may no longer influence a cleartext-hop decision (ADR 0153 #5)"
    )
    assert params == {"enforcing", "is_loopback_hop", "hop_attested", "cleartext_accepted"}


def test_insecure_hop_disposition_is_strictly_stricter_than_before() -> None:
    """ADR 0153's central claim: over the OLD input space, no input moves toward ALLOW.

    "Because the deleted arm returned ALLOW, removing it can only ever turn a crossing into a WARN or a
    REFUSE, never the reverse" — i.e. ADR 0092 decision 5 (no-loosen) holds by construction. This is the
    executable form of that sentence: for every one of the old 32 rows the new disposition is never
    *weaker* than the old one. ``cleartext_accepted`` is held FALSE throughout, since it is the new
    deliberate loosening and would correctly relax a REFUSE to WARN."""
    strictness = {HopDisposition.ALLOW: 0, HopDisposition.WARN: 1, HopDisposition.REFUSE: 2}
    for is_phi, enforcing, is_loopback_hop, hop_attested, audited_opt_out in product(
        [False, True], repeat=5
    ):
        before = _legacy_insecure_hop_disposition(
            is_phi=is_phi,
            enforcing=enforcing,
            is_loopback_hop=is_loopback_hop,
            hop_attested=hop_attested,
            audited_opt_out=audited_opt_out,
        )
        after = insecure_hop_disposition(
            enforcing=enforcing,
            is_loopback_hop=is_loopback_hop,
            hop_attested=hop_attested,
            cleartext_accepted=False,
        )
        assert strictness[after] >= strictness[before], (
            is_phi,
            enforcing,
            is_loopback_hop,
            hop_attested,
            audited_opt_out,
            before,
            after,
        )


def test_insecure_hop_enforcing_refuses_and_only_attestation_or_acceptance_crosses() -> None:
    """The headline case: an enforcing cleartext hop refuses, whatever the instance's data label."""
    base = dict(enforcing=True, is_loopback_hop=False)  # noqa: C408
    assert (
        insecure_hop_disposition(**base, hop_attested=False, cleartext_accepted=False)
        is HopDisposition.REFUSE
    )
    # Attestation ("this hop IS secure by other means") crosses it silently...
    assert (
        insecure_hop_disposition(**base, hop_attested=True, cleartext_accepted=False)
        is HopDisposition.ALLOW
    )
    # ...and acceptance ("this hop is NOT secure and we accept that") crosses it LOUDLY, never as an
    # ALLOW. That difference is the whole reason the two stay separate fields (ADR 0153 decision 2).
    assert (
        insecure_hop_disposition(**base, hop_attested=False, cleartext_accepted=True)
        is HopDisposition.WARN
    )


def test_insecure_hop_non_enforcing_warns_and_acceptance_still_only_warns() -> None:
    # The [security].enforcement dial of ADR 0148 is deliberately RETAINED as arm 4: a non-enforcing
    # instance warns rather than refuses, and still logs + audits every hop. Nothing goes silent.
    assert (
        insecure_hop_disposition(
            enforcing=False, is_loopback_hop=False, hop_attested=False, cleartext_accepted=False
        )
        is HopDisposition.WARN
    )
    # An acceptance on a non-enforcing instance is still WARN — it can never escalate to ALLOW.
    assert (
        insecure_hop_disposition(
            enforcing=False, is_loopback_hop=False, hop_attested=False, cleartext_accepted=True
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
    assert HopPosture.fail_closed(is_phi=None, enforcing=None) == HopPosture(
        is_phi=True, enforcing=True
    )
    # A fully-declared posture passes through unchanged (not strictest-by-default).
    assert HopPosture.fail_closed(is_phi=False, enforcing=False) == HopPosture(
        is_phi=False, enforcing=False
    )
    assert HopPosture.fail_closed(is_phi=True, enforcing=None) == HopPosture(
        is_phi=True, enforcing=True
    )


def test_active_hop_posture_stamps_and_restores() -> None:
    assert current_hop_posture() is None
    posture = HopPosture(is_phi=True, enforcing=True)
    with active_hop_posture(posture):
        assert current_hop_posture() is posture
        # nesting restores the outer value on exit
        with active_hop_posture(None):
            assert current_hop_posture() is None
        assert current_hop_posture() is posture
    assert current_hop_posture() is None
