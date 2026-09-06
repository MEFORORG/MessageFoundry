# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for the shared TLS key-exchange policy (ASVS 11.6.2, WP-L3-10 code half)."""

from __future__ import annotations

import contextlib
import inspect
import ssl
import types
from itertools import product
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config import tls_policy
from messagefoundry.config.tls_policy import (
    _APPROVED_TLS_SUITES,
    _MIN_TLS_STRENGTH_BITS,
    APPROVED_KEX_GROUPS,
    TLS_REVOCATION_ATTESTED_ENV,
    HopDisposition,
    HopPosture,
    InsecureHopRefused,
    _is_encrypting,
    _is_forward_secret,
    _is_peer_authenticated,
    _is_strong_enough,
    _weak_suite_labels,
    active_hop_posture,
    build_smtp_tls_context,
    current_hop_posture,
    enforce_insecure_hop,
    fips_attestation,
    harden_cipher_suites,
    harden_crl_check,
    harden_kex_groups,
    harden_verify_flags,
    in_process_tls_revocation_refused,
    insecure_hop_disposition,
    is_loopback_hop_host,
    kex_groups_report,
    smtp_login_approved,
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
    harden_kex_groups(ctx)  # must never raise, whatever the runtime can or cannot pin


def test_the_group_pin_is_inert_on_this_runtime_and_says_so() -> None:
    """A liveness receipt for ASVS 11.6.2 — written to FAIL on the interpreter upgrade.

    ``SSLContext.set_groups`` is a **Python 3.15** addition, so ``harden_kex_groups`` pins nothing on
    any interpreter this project runs on and ``APPROVED_KEX_GROUPS`` reaches none of its call
    sites. That was already true; what was missing was any way to NOTICE. The tests that stood here
    asserted (a) that the call does not raise, (b) that it no-ops on an object without the API, and (c)
    the contents of a string constant — all three pass identically whether or not a single group is
    ever pinned. That is how the docstring came to claim "Python 3.13+" and how ADR 0092 §4(b), PHI.md
    §4 and the ASVS scorecard all came to assert a control that does not execute.

    Asserted **unconditionally** on purpose: an ``if hasattr(ctx, "set_groups")`` branch here would
    restore exactly the property being removed — a test that cannot fail.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    pinned = harden_kex_groups(ctx)
    assert pinned is None, (
        f"harden_kex_groups pinned {pinned!r}, so this interpreter HAS a group-list API and the ASVS "
        f"11.6.2 residual has CHANGED. This is good news, not a bug. Re-derive, in one change: the "
        f"harden_kex_groups docstring, docs/PHI.md §4, docs/ASVS-L2-PHASE0-CHANGES.md, the ADR 0092 "
        f"§4(b) amendment and the 11.6.2 register row — then rewrite this test to assert the pin TOOK, "
        f"via ctx.get_groups(), which lands in the same Python version."
    )
    assert not hasattr(ctx, "set_groups"), (
        "set_groups EXISTS but harden_kex_groups still returned None, so the pin is failing silently — "
        "worse than being unavailable, because the docs would read as satisfied. See the "
        "logger.warning path."
    )


def test_harden_reports_none_without_set_groups() -> None:
    # An object lacking the API must be handled gracefully AND report that nothing was pinned.
    fake = types.SimpleNamespace()
    assert harden_kex_groups(fake) is None  # type: ignore[arg-type]


def test_harden_reports_the_list_it_pinned_when_the_api_exists() -> None:
    """The return value must be REAL, not incidentally-``None``.

    ``test_the_group_pin_is_inert_on_this_runtime_and_says_so`` asserts ``is None`` — which a function
    with no ``return`` statement at all also satisfies. On its own it therefore does NOT prove the
    reporting works: reverting this helper to its old ``-> None`` signature would leave it green. Drive
    the pinning path with a stand-in context that *has* ``set_groups`` so both halves of the contract
    are covered, and assert the group list actually reached it.
    """

    class _Pinnable:
        def __init__(self) -> None:
            self.pinned: list[str] = []

        def set_groups(self, grouplist: str) -> None:
            self.pinned.append(grouplist)

    ctx = _Pinnable()
    assert harden_kex_groups(ctx) == APPROVED_KEX_GROUPS  # type: ignore[arg-type]
    assert ctx.pinned == [APPROVED_KEX_GROUPS], "the group list never reached set_groups"


def test_a_pin_that_raises_reports_nothing_pinned() -> None:
    """An OpenSSL build that REJECTS the group list must report ``None``, not the list.

    This was the shipped bug: the helper logged the warning and then fell off the end, so the caller
    could not distinguish "pinned" from "tried and failed" — and once the helper started reporting, the
    failure path returning the list would have been a lie with a warning line next to it.
    """

    class _Rejecting:
        def set_groups(self, grouplist: str) -> None:
            raise ValueError("this OpenSSL build rejects the group list")

    assert harden_kex_groups(_Rejecting()) is None  # type: ignore[arg-type]


def test_approved_groups_are_ecdhe_curves() -> None:
    assert APPROVED_KEX_GROUPS.split(":") == ["X25519", "secp384r1", "secp256r1"]
    # NB `secp256r1` is a valid OpenSSL group-list alias but NOT a valid EC curve name — that spelling
    # is `prime256v1`, and set_ecdh_curve("secp256r1") raises ValueError. Both are correct in their own
    # API; do not "normalise" them to one.


# --- kex_groups_report: report-only KEX read-out (#338, ASVS 11.6.2) ----------------------------
def test_kex_groups_report_reports_inherited_today() -> None:
    """#338: the report-only KEX read-out says the approved groups are INHERITED on this runtime.

    ``SSLContext.set_groups`` is a Python 3.15 API, so ``harden_kex_groups`` pins nothing on any
    interpreter this project currently runs on. The read-out must therefore report "inherited" (never
    "pinned:") and name the approved group list it WOULD pin, so an operator reading it sees what is at
    stake. It is a pure read-out over a throwaway probe context — report-only, and it never raises. On
    the Python 3.15 interpreter that grows the API this flips to "pinned:", the same signal the
    ``test_the_group_pin_is_inert_on_this_runtime_and_says_so`` tripwire fires on.
    """
    report = kex_groups_report()
    assert isinstance(report, str) and report  # a non-empty string
    assert "inherited" in report  # nothing is pinned on a pre-3.15 interpreter
    assert APPROVED_KEX_GROUPS in report  # names the approved list it WOULD pin
    assert "pinned:" not in report  # the "pinned:" branch is 3.15-only


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


# --- ASVS 12.1.2: forward secrecy is ASSERTED on every shipped context, not inherited ---------------


def test_every_shipped_context_shape_negotiates_only_forward_secret_suites() -> None:
    """The evidence an assessor actually wants: the suite count and the non-FS count, PRINTED.

    ``validate_tls_ciphers`` already rejects a *configured* string that admits static RSA/DH — but it
    only fires when an operator sets the knob. A context built without one inherits the interpreter's
    default list and nothing checked it. That inheritance-without-assertion is the real 12.1.2
    residual (the residual of record overstates it as "no cipher knob at all", which is false).

    This prints rather than merely asserting because a green dot proves nothing to a reader: the
    output states what was examined, so "0 non-forward-secret" is a measurement rather than a claim.
    """
    from messagefoundry.config.tls_policy import _is_forward_secret

    shapes = {
        "PROTOCOL_TLS_SERVER": ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER),
        "default(SERVER_AUTH)": ssl.create_default_context(ssl.Purpose.SERVER_AUTH),
        "default(CLIENT_AUTH)": ssl.create_default_context(ssl.Purpose.CLIENT_AUTH),
        "PROTOCOL_TLS_CLIENT": ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT),
    }
    findings: list[str] = []
    examined = 0
    for name, ctx in shapes.items():
        suites = ctx.get_ciphers()
        non_fs = sorted({str(c.get("name", "?")) for c in suites if not _is_forward_secret(c)})
        print(f"{name}: {len(suites)} suites examined, {len(non_fs)} non-forward-secret")
        assert suites, f"{name} resolved to NO suites — the measurement is vacuous"
        examined += 1
        if non_fs:
            findings.append(f"{name}: {non_fs}")
    # Deliberately NOT capsys: capturing the report would verify it was produced while hiding it from
    # the reader, which defeats the point. pytest shows these lines with -s (and on failure), so
    # `pytest -s -k forward_secret` IS the evidence artefact.
    assert examined == len(shapes), f"expected {len(shapes)} shapes measured, got {examined}"
    assert not findings, (
        f"shipped TLS context shape(s) would negotiate non-forward-secret suites: {findings}. "
        f"A suite admitting static RSA/DH lets a future key compromise decrypt recorded PHI traffic."
    )


def test_harden_cipher_suites_raises_on_a_non_forward_secret_context() -> None:
    """The assertion must actually fire — proven by building a context that violates it rather than
    by trusting that it would.

    Mutation: delete the raise in ``harden_cipher_suites``. Red: DID NOT RAISE. Without this test the
    function is only ever exercised on contexts that pass, so it could be a no-op and every call site
    would still look green.
    """
    from messagefoundry.config.tls_policy import harden_cipher_suites

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        ctx.set_ciphers("AES256-SHA:@SECLEVEL=0")  # static-RSA kx, no forward secrecy
    except ssl.SSLError:
        pytest.skip(
            "this OpenSSL build cannot enable a static-RSA suite — nothing to assert against"
        )
    if all(_fs(c) for c in ctx.get_ciphers()):  # pragma: no cover - build-dependent
        pytest.skip("this OpenSSL build resolved the static-RSA request to FS suites only")
    with pytest.raises(ValueError, match="non-forward-secret"):
        harden_cipher_suites(ctx, connector="test listener")


def _fs(cipher: object) -> bool:
    from messagefoundry.config.tls_policy import _is_forward_secret

    assert isinstance(cipher, dict)
    return _is_forward_secret(cipher)


def test_every_context_that_pins_kex_groups_also_asserts_forward_secrecy() -> None:
    """Call-site coverage — the half the function-level tests cannot see.

    Mutation-proven gap: deleting ``harden_cipher_suites`` from one MLLP context site left the whole
    TLS suite GREEN, because the other tests exercise the FUNCTION, not its wiring. A new listener or
    destination could ship a context with no forward-secrecy assertion and nothing would notice —
    which is precisely how the original 12.1.2 residual arose (inheritance without assertion).

    Derived, not a hardcoded site list: ``harden_kex_groups(ctx)`` already marks every place the
    engine builds and hardens a TLS context, so the two must be co-located. A new context that pins
    groups but skips the assertion fails here.
    """
    pkg = Path(tls_policy.__file__).resolve().parent.parent
    problems: list[str] = []
    for path in sorted(pkg.rglob("*.py")):
        if path.name == "tls_policy.py":
            continue  # the definitions themselves
        text = path.read_text(encoding="utf-8")
        kex = [
            n
            for n, ln in enumerate(text.splitlines(), 1)
            if "harden_kex_groups(" in ln and not ln.lstrip().startswith(("#", "*"))
        ]
        assertions = text.count("harden_cipher_suites(")
        if kex and assertions < len(kex):
            rel = path.relative_to(pkg.parent).as_posix()
            problems.append(
                f"{rel}: {len(kex)} kex-pin site(s) at lines {kex}, {assertions} assertion(s)"
            )
    assert not problems, (
        f"TLS context site(s) that pin key-exchange groups but do NOT assert forward secrecy: "
        f"{problems}. Every built context must be checked (ASVS 12.1.2) — the suite list is inherited "
        f"from the interpreter unless something asserts it."
    )


def test_the_call_site_scan_examined_real_files() -> None:
    """Liveness receipt for the scan above: it is a `not found` over an rglob, so a moved package or a
    changed helper name would make it pass over nothing."""
    pkg = Path(tls_policy.__file__).resolve().parent.parent
    sites = sum(
        1
        for p in pkg.rglob("*.py")
        for ln in p.read_text(encoding="utf-8").splitlines()
        if "harden_kex_groups(ctx)" in ln and not ln.lstrip().startswith("#")
    )
    assert sites >= 5, (
        f"expected the known TLS context sites, found {sites} — the scan is not landing"
    )


# --- #323: build_smtp_tls_context REFUSES an untrusted peer (behavioural, not attribute) ------------
#
# The connector tests assert this context's ATTRIBUTES (verify_mode, check_hostname). That is not the
# same claim as "it refuses a bad certificate", and an attribute check cannot establish it — the whole
# defect being fixed was a context whose attributes were never inspected by anyone. These drive a REAL
# TLS handshake against a locally-minted self-signed server so the refusal is OBSERVED. Run against the
# pre-#323 code path (smtplib's default context) every REFUSED case below returns HANDSHAKE OK, which
# is precisely the bug.
#
# No network: binds 127.0.0.1 on an ephemeral port, and the server thread only completes a handshake
# and closes — it speaks no SMTP, because the property under test is the TLS layer, not the protocol.


@pytest.fixture(scope="module")
def _tls_peer(tmp_path_factory: pytest.TempPathFactory) -> tuple[int, str]:
    """A local TLS server with a self-signed 'localhost' cert. Yields (port, ca_pem_path)."""
    import datetime
    import socket
    import threading

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    tmp = tmp_path_factory.mktemp("smtp_tls")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_p, key_p = tmp / "server.pem", tmp / "server.key"
    cert_p.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_p.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )

    srv = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    srv.load_cert_chain(cert_p, key_p)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)

    def _accept_loop() -> None:
        while True:
            try:
                conn, _ = listener.accept()
            except OSError:
                return  # listener closed at teardown
            threading.Thread(target=_handshake, args=(conn,), daemon=True).start()

    def _handshake(conn: socket.socket) -> None:
        # A client that (correctly) refuses us aborts mid-handshake, so OSError here is the EXPECTED
        # path for the refusal tests, not an error -- suppress on both legs.
        with contextlib.suppress(OSError):
            srv.wrap_socket(conn, server_side=True).close()
        with contextlib.suppress(OSError):
            conn.close()

    threading.Thread(target=_accept_loop, daemon=True).start()
    yield listener.getsockname()[1], str(cert_p)
    listener.close()


def _handshake_result(ctx: ssl.SSLContext, port: int, server_hostname: str) -> str:
    import socket

    try:
        with (
            socket.create_connection(("127.0.0.1", port), timeout=10) as sock,
            ctx.wrap_socket(sock, server_hostname=server_hostname),
        ):
            return "ok"
    except ssl.SSLCertVerificationError:
        return "refused"
    except OSError:  # a reset mid-refusal still means the client did not accept the peer
        return "refused"


def test_smtp_context_refuses_an_untrusted_peer(_tls_peer: tuple[int, str]) -> None:
    """THE regression fence for #323. Pre-fix this returned 'ok' — any certificate was accepted."""
    port, _ = _tls_peer
    ctx = build_smtp_tls_context(host="localhost", cell="Email destination")
    assert _handshake_result(ctx, port, "localhost") == "refused"


def test_smtp_context_accepts_a_peer_signed_by_the_connection_ca(
    _tls_peer: tuple[int, str],
) -> None:
    """tls_ca_file is the supported route for a private-CA relay — it must actually work, or the
    only remaining escape would be turning verification off."""
    port, ca = _tls_peer
    ctx = build_smtp_tls_context(host="localhost", cell="Email destination", ca_file=ca)
    assert _handshake_result(ctx, port, "localhost") == "ok"


def test_smtp_context_enforces_hostname(_tls_peer: tuple[int, str]) -> None:
    """A trusted chain is not enough: the cert must match the host we meant to reach."""
    port, ca = _tls_peer
    ctx = build_smtp_tls_context(host="localhost", cell="Email destination", ca_file=ca)
    assert _handshake_result(ctx, port, "wrong.example") == "refused"


def test_smtp_context_check_hostname_false_relaxes_only_the_name(
    _tls_peer: tuple[int, str],
) -> None:
    """tls_check_hostname=False drops the name check while KEEPING chain validation."""
    port, ca = _tls_peer
    ctx = build_smtp_tls_context(
        host="localhost", cell="Email destination", ca_file=ca, check_hostname=False
    )
    assert _handshake_result(ctx, port, "wrong.example") == "ok"


def test_smtp_context_verify_false_accepts_anything(_tls_peer: tuple[int, str]) -> None:
    """The escape genuinely disables verification — asserted so nobody 'hardens' it into a
    silently-broken state where the escape no longer connects and operators cannot tell why."""
    port, _ = _tls_peer
    ctx = build_smtp_tls_context(host="localhost", cell="Email destination", verify=False)
    assert _handshake_result(ctx, port, "localhost") == "ok"


# --- BACKLOG #1171 (ASVS 11.4.1): SMTP AUTH mechanism + the channel it may run on -----------------


class _FakeSmtp:
    """Records which AUTH mechanism was driven. Mirrors only what smtp_login_approved touches."""

    def __init__(self, offers: str) -> None:
        self.esmtp_features = {"auth": offers}
        self.used: str | None = None

    def ehlo_or_helo_if_needed(self) -> None:
        pass

    def has_extn(self, name: str) -> bool:
        return name in self.esmtp_features

    def auth(self, mechanism: str, authobject: object, *, initial_response_ok: bool = True) -> None:
        self.used = mechanism

    def auth_plain(self, challenge: object = None) -> str:
        return ""

    def auth_login(self, challenge: object = None) -> str:
        return ""

    def auth_cram_md5(self, challenge: object = None) -> str:
        return ""


def test_cram_md5_is_never_chosen_even_when_the_server_offers_it() -> None:
    """smtplib's own order is ['CRAM-MD5','PLAIN','LOGIN'] -- CRAM-MD5 FIRST.

    CRAM-MD5 is an HMAC over MD5, which Appendix C marks D: disallowed for any cryptographic purpose.
    So every unrestricted smtp.login() tried a disallowed hash before anything else. With both on
    offer the approved one must win.
    """
    smtp = _FakeSmtp("CRAM-MD5 PLAIN")
    smtp_login_approved(smtp, "u", "p", channel_encrypted=True, cell="EMAIL")
    assert smtp.used == "PLAIN", f"a disallowed mechanism was chosen: {smtp.used}"


def test_a_server_offering_only_a_disallowed_mechanism_is_refused() -> None:
    smtp = _FakeSmtp("CRAM-MD5")
    with pytest.raises(InsecureHopRefused) as ei:
        smtp_login_approved(smtp, "u", "p", channel_encrypted=True, cell="EMAIL")
    assert "none of which is approved" in str(ei.value)
    assert smtp.used is None, "it authenticated anyway"


def test_auth_over_an_unencrypted_channel_is_refused() -> None:
    """THE HALF THAT MAKES THE OTHER HALF SAFE.

    PLAIN and LOGIN SEND THE PASSWORD; CRAM-MD5 does not. Restricting the mechanism without also
    requiring encryption would close a conformance gap by putting a cleartext password on the wire --
    strictly worse than the gap. Ruled build-both-or-neither for that reason.
    """
    smtp = _FakeSmtp("PLAIN LOGIN")
    with pytest.raises(InsecureHopRefused) as ei:
        smtp_login_approved(smtp, "u", "p", channel_encrypted=False, cell="ALERT")
    assert "SEND THE PASSWORD" in str(ei.value)
    assert smtp.used is None, "the password went out over an unencrypted channel"


def test_no_environment_escape_lifts_the_cleartext_auth_refusal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The refusal is ABSOLUTE, matching the construction gate it backs up.

    All three SMTP cells refuse a username beside use_tls=false at construction even with
    MEFOR_ALLOW_INSECURE_TLS set (the refuse_cleartext_credentials posture, not the escapable
    payload-hop posture). A send-time backstop that the env var could lift would be weaker than the
    gate it backs up. This replaces an escape_permitted=True arm that no shipped call site reached.

    The positive control against "it just refuses everything" is
    test_cram_md5_is_never_chosen_even_when_the_server_offers_it, which authenticates.
    """
    monkeypatch.setenv("MEFOR_ALLOW_INSECURE_TLS", "1")
    smtp = _FakeSmtp("PLAIN LOGIN")
    with pytest.raises(InsecureHopRefused) as ei:
        smtp_login_approved(smtp, "u", "p", channel_encrypted=False, cell="ALERT")
    assert smtp.used is None, "the escape put a cleartext password on the wire"
    # The text must not send an operator to a variable that cannot lift this refusal: following it
    # would weaken every other hop on the instance and still be refused here.
    assert "MEFOR_ALLOW_INSECURE_TLS" not in str(ei.value)


def test_the_helper_takes_no_escape_parameter() -> None:
    """Pins the deletion. A re-added escape is a hole behind an absolute construction gate."""
    assert "escape_permitted" not in inspect.signature(smtp_login_approved).parameters


# --- BACKLOG #1317: forward secrecy is not sufficient -------------------------------------------
#
# Both suites below are FORWARD-SECRET and passed every gate before this item. ECDHE-RSA-NULL-SHA is
# authenticated and encrypts NOTHING; ADH-AES256-GCM-SHA384 is strongly encrypted and authenticates
# NOBODY. The four rows pinned here are the exact measurement that filed the item.

_NULL_CIPHER = "ECDHE-RSA-NULL-SHA"
_ANON_CIPHER = "ADH-AES256-GCM-SHA384"
_GOOD_CIPHER = "ECDHE-RSA-AES256-GCM-SHA384"


def _ciphers_available(spec: str) -> bool:
    """Whether this OpenSSL build can resolve ``spec`` at all, so a skip is honest rather than a pass."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        ctx.set_ciphers(spec)
    except ssl.SSLError:
        return False
    return any(c.get("name") == spec for c in ctx.get_ciphers())


@pytest.mark.parametrize(
    ("spec", "why"),
    [
        (_NULL_CIPHER, "NULL cipher: forward-secret, authenticated, transmits plaintext"),
        (_ANON_CIPHER, "anonymous: forward-secret, encrypted, authenticates no peer"),
    ],
)
def test_validate_tls_ciphers_rejects_what_forward_secrecy_cannot_see(spec: str, why: str) -> None:
    if not _ciphers_available(spec):
        pytest.skip(f"this OpenSSL build cannot resolve {spec}")
    with pytest.raises(ValueError):
        validate_tls_ciphers(spec)


@pytest.mark.parametrize("require_approved", [True, False])
def test_validate_tls_ciphers_still_accepts_a_good_suite(require_approved: bool) -> None:
    """POSITIVE CONTROL for every rejection in this file. Without it they are indistinguishable from
    a validator that refuses everything, which would pass them all for entirely the wrong reason.
    Both call shapes, because BACKLOG #1166 added a check that runs on the ``False`` one too."""
    assert (
        validate_tls_ciphers(_GOOD_CIPHER, require_approved_suites=require_approved) == _GOOD_CIPHER
    )


def test_validate_tls_ciphers_rejects_an_unlisted_suite_that_passes_every_property() -> None:
    """The allow-list earns its place here. ECDHE-RSA-AES256-SHA384 is forward-secret, encrypting and
    authenticated -- it satisfies all three predicates and is still refused, because it is not named.
    This is the row that distinguishes a strict positive allow-list from a pile of property checks."""
    unlisted = "ECDHE-RSA-AES256-SHA384"
    if not _ciphers_available(unlisted):
        pytest.skip(f"this OpenSSL build cannot resolve {unlisted}")
    probe = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    probe.set_ciphers(unlisted)
    entry = next(c for c in probe.get_ciphers() if c.get("name") == unlisted)
    assert _is_forward_secret(entry) and _is_encrypting(entry) and _is_peer_authenticated(entry)
    assert unlisted not in _APPROVED_TLS_SUITES
    with pytest.raises(ValueError, match="approved list"):
        validate_tls_ciphers(unlisted)


def test_the_two_new_predicates_read_the_openssl_description() -> None:
    assert not _is_encrypting(
        {"name": "x", "description": "x TLSv1 Kx=ECDH Au=RSA Enc=None Mac=SHA1"}
    )
    assert _is_encrypting({"name": "x", "description": "x TLSv1.2 Enc=AESGCM(256) Mac=AEAD"})
    assert not _is_peer_authenticated(
        {"name": "x", "description": "x Kx=DH Au=None Enc=AESGCM(256)"}
    )
    assert _is_peer_authenticated({"name": "x", "description": "x Kx=ECDH Au=RSA Enc=AESGCM(256)"})
    # Au=any is NOT anonymous -- TLS 1.3 reports it because authentication is negotiated separately.
    assert _is_peer_authenticated(
        {"name": "x", "description": "x TLSv1.3 Kx=any Au=any Enc=AESGCM(256)"}
    )


def test_harden_cipher_suites_asserts_on_no_shipped_default() -> None:
    """The safety property the whole change rests on. If any default context shape carried a NULL,
    anonymous or sub-floor suite, the assertions in harden_cipher_suites would refuse every
    deployment. Ships as a test rather than a measurement in a commit message so a future OpenSSL
    cannot break it silently. The strength row is BACKLOG #1166's and rides the same loop."""
    for make in (
        lambda: ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER),
        lambda: ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT),
        ssl.create_default_context,
    ):
        ctx = make()
        assert {int(c["strength_bits"]) for c in ctx.get_ciphers()} == {128, 256}
        harden_cipher_suites(ctx, connector="test-default-shape")


def test_harden_cipher_suites_does_not_apply_the_operator_allow_list() -> None:
    """The allow-list is AEAD-only and the shipped default carries six CBC-SHA2 suites. Applying it to
    an INHERITED context would refuse every current configuration, so this pins that it is not. The
    assertion is on the SIX being present and tolerated, not merely on the call succeeding."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    cbc = [c["name"] for c in ctx.get_ciphers() if "Mac=AEAD" not in str(c.get("description", ""))]
    assert cbc, "control: the default is expected to carry non-AEAD suites on this build"
    assert any(n not in _APPROVED_TLS_SUITES for n in cbc)
    harden_cipher_suites(ctx, connector="test-inherited-default")


def test_harden_cipher_suites_raises_on_a_null_cipher_context() -> None:
    if not _ciphers_available(_NULL_CIPHER):
        pytest.skip("this OpenSSL build cannot resolve a NULL cipher")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.set_ciphers(_NULL_CIPHER)
    with pytest.raises(ValueError, match="NULL-cipher"):
        harden_cipher_suites(ctx, connector="test-null")


# --- BACKLOG #1166: the three properties above are still not enough ------------------------------
#
# What a truncated-tag suite is, and why the earlier checks cannot see it, is stated once on
# _is_strong_enough -- along with the fact that WHICH suites carry that shape differs per OpenSSL
# build. Recorded HERE and nowhere else:
#
# MEASURED at engine commit 2b8bccb43 on Windows, BEFORE this gate: validate_tls_ciphers(
# require_approved_suites=False) ACCEPTED a string naming the sub-floor suites that build offers, and
# harden_cipher_suites ACCEPTED the resulting context. So both were live and neither asked.
#
# THE ITEM'S OWN REPRO IS STALE AND WAS RE-MEASURED FALSE. #1166 records that
# `ECDHE-ECDSA-NULL-SHA:ECDHE-RSA-NULL-SHA:@SECLEVEL=0` is accepted; at this commit both functions
# REFUSE it, because BACKLOG #1317 landed the NULL check after that measurement was taken. The gap
# that survives is narrower and different, and it is the one pinned here.

# WHICH REAL SUITES ARE SUB-FLOOR IS A PROPERTY OF THE LINKED OPENSSL, NOT OF THIS GATE, AND THE
# FIRST CUT OF THESE TESTS GOT THAT WRONG. It hardcoded ECDHE-ECDSA-AES256-CCM8 as a 64-bit suite,
# which holds on the Windows build and NOT on ubuntu-latest, where the same name rates 256. Four
# tests went red there, and the sharpest was the approved-list arm: it had been PASSING on Windows
# because _APPROVED_TLS_SUITES refused the suite, not because this gate did. That is the same defect
# class #1166 is about -- an assertion that passes for a reason other than the control it names.
#
# So the real-suite rows below DISCOVER a sub-floor suite on the build they are running on, and skip
# with a reason naming that build when there is none. They never assert that one exists. The
# synthesised rows after them carry the discrimination on EVERY platform, so a skip here cannot
# quietly gut the proof.


def _a_sub_floor_suite() -> str | None:
    """A real suite on THIS OpenSSL that clears the three earlier checks and still rates below the
    floor, or ``None`` if this build offers none. The gate's whole point is the gap between those
    three predicates and the rating, so this looks for exactly that shape."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        ctx.set_ciphers("ALL:COMPLEMENTOFALL:@SECLEVEL=0")
    except ssl.SSLError:
        return None
    for c in ctx.get_ciphers():
        if (
            _is_forward_secret(c)
            and _is_encrypting(c)
            and _is_peer_authenticated(c)
            and not _is_strong_enough(c)
        ):
            return str(c["name"])
    return None


def _weak_entry(name: str = "FAKE-ECDHE-WEAK", bits: int = 64) -> dict[str, object]:
    """A synthesised cipher entry that clears all three earlier predicates and is sub-floor. Lets the
    gate be tested where no real OpenSSL suite has this shape."""
    return {
        "name": name,
        "description": f"{name} TLSv1.2 Kx=ECDH Au=RSA Enc=AESCCM8(256) Mac=AEAD",
        "strength_bits": bits,
        "alg_bits": 256,
    }


class _FixedSuiteContext(ssl.SSLContext):
    """A real ``SSLContext`` whose resolved suite list is ours. Subclassed rather than duck-typed so
    it satisfies ``harden_cipher_suites``' annotation and exercises the true call path."""

    suites: list[dict[str, object]]

    def get_ciphers(self) -> list[dict[str, object]]:  # type: ignore[override]
        return self.suites


def test_the_synthesised_weak_entry_defeats_all_three_earlier_predicates() -> None:
    """The premise, asserted on an entry we control so it holds on every build. If this stops
    holding, the strength gate is redundant and the rows below prove nothing."""
    entry = _weak_entry()
    assert _is_forward_secret(entry) and _is_encrypting(entry) and _is_peer_authenticated(entry)
    assert not _is_strong_enough(entry)
    assert int(entry["alg_bits"]) >= _MIN_TLS_STRENGTH_BITS  # type: ignore[arg-type]


def test_harden_cipher_suites_raises_on_a_sub_floor_context_every_build() -> None:
    """THE DISCRIMINATING ROW, and it runs everywhere. Drives the real function over a context whose
    only suite is sub-floor."""
    ctx = _FixedSuiteContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.suites = [_weak_entry()]
    with pytest.raises(ValueError, match="bits of security"):
        harden_cipher_suites(ctx, connector="test-weak")

    # POSITIVE CONTROL in the same test: a strong synthesised suite passes, so the raise above is
    # about the rating and not about the fake being rejected wholesale.
    ctx.suites = [_weak_entry(bits=256)]
    harden_cipher_suites(ctx, connector="test-strong")


class _ShimmedSSL:
    """Just enough of the ``ssl`` module for ``validate_tls_ciphers``' internal probe, with the
    resolved suite list under our control.

    Needed because that function builds its own context, so unlike ``harden_cipher_suites`` it takes
    no injectable seam. Without this the strength branch of ``validate_tls_ciphers`` is covered ONLY
    by the real-suite rows, and on a build that skips them a mutation deleting that branch goes
    unnoticed -- measured vacuous before this was added."""

    SSLError = ssl.SSLError
    PROTOCOL_TLS_SERVER = ssl.PROTOCOL_TLS_SERVER

    def __init__(self, suites: list[dict[str, object]]) -> None:
        self._suites = suites

    def SSLContext(self, _protocol: object) -> Any:  # noqa: N802 — mirrors the stdlib name
        suites = self._suites

        class _Probe:
            def set_ciphers(self, value: str) -> None:
                return None

            def get_ciphers(self) -> list[dict[str, object]]:
                return suites

        return _Probe()


@pytest.mark.parametrize("require_approved", [True, False])
def test_validate_tls_ciphers_rejects_a_sub_floor_suite_every_build(
    monkeypatch: pytest.MonkeyPatch, require_approved: bool
) -> None:
    """THE DISCRIMINATING ROW for the other gate, and it runs everywhere.

    The ``True`` shape also pins the ORDER, which is the part that bit: on Windows the first cut
    passed because ``_APPROVED_TLS_SUITES`` refused the suite, and the ubuntu run proved it by
    showing the allow-list message where the strength message was expected. The strength check runs
    FIRST, so an operator is told the real reason rather than a bare 'not on the list'."""
    monkeypatch.setattr(tls_policy, "ssl", _ShimmedSSL([_weak_entry()]))
    with pytest.raises(ValueError, match="bits of security"):
        validate_tls_ciphers("anything", require_approved_suites=require_approved)


def test_validate_tls_ciphers_accepts_a_strong_synthesised_suite(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """POSITIVE CONTROL for the row above: with the same shim and a strong entry it returns, so the
    raise there is about the rating and not about the shim."""
    strong = _weak_entry(name="ECDHE-RSA-AES256-GCM-SHA384", bits=256)
    monkeypatch.setattr(tls_policy, "ssl", _ShimmedSSL([strong]))
    assert validate_tls_ciphers("anything", require_approved_suites=False) == "anything"


def test_weak_suite_labels_reports_the_offenders_with_their_ratings() -> None:
    """The collector both gates share. Names and ratings, strong entries omitted."""
    resolved = [_weak_entry("A", 64), _weak_entry("B", 256), _weak_entry("C", 112)]
    assert _weak_suite_labels(resolved) == ["A (64 bits)", "C (112 bits)"]


@pytest.mark.parametrize("require_approved", [True, False])
def test_validate_tls_ciphers_rejects_a_real_sub_floor_suite(require_approved: bool) -> None:
    """Both call shapes over a REAL suite, when this build has one. The ``False`` shape is the point:
    it is the ``proxy_tls_ciphers`` declaration path, where the allow-list deliberately does not run
    and this gate is the only thing left. On a build with no sub-floor suite this skips rather than
    asserting the inventory -- the row above carries the proof there."""
    name = _a_sub_floor_suite()
    if name is None:
        pytest.skip(
            f"this OpenSSL ({ssl.OPENSSL_VERSION}) offers no suite that clears forward secrecy, "
            f"encryption and peer authentication while rating below {_MIN_TLS_STRENGTH_BITS} bits"
        )
    with pytest.raises(ValueError, match="bits of security"):
        validate_tls_ciphers(f"{name}:@SECLEVEL=0", require_approved_suites=require_approved)


def test_harden_cipher_suites_raises_on_a_real_sub_floor_context() -> None:
    name = _a_sub_floor_suite()
    if name is None:
        pytest.skip(f"this OpenSSL ({ssl.OPENSSL_VERSION}) offers no sub-floor suite")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.set_ciphers(f"{name}:@SECLEVEL=0")
    with pytest.raises(ValueError, match="bits of security"):
        harden_cipher_suites(ctx, connector="test-weak-real")


def test_is_strong_enough_fails_closed_on_an_ungradeable_entry() -> None:
    """Pins the fail-closed rule stated on ``_is_strong_enough``: a dict we cannot grade must not
    pass."""
    assert _is_strong_enough({"name": "x", "strength_bits": 128})
    assert not _is_strong_enough({"name": "x", "strength_bits": 64})
    assert not _is_strong_enough({"name": "x"})  # absent
    assert not _is_strong_enough({"name": "x", "strength_bits": "256"})  # not an int
    assert not _is_strong_enough({"name": "x", "strength_bits": None})


def test_the_tls_strength_floor_is_not_the_key_material_floor() -> None:
    """A guard on the confusion #1166 warns about. _MIN_TLS_STRENGTH_BITS grades NEGOTIABLE SUITES.
    The floor actually in force on operator KEY MATERIAL at the load_cert_chain sites is OpenSSL's
    security level, which is 2 (roughly 112 bits) and READ-ONLY -- named nowhere else in the tree.
    Raising that is a counterparty-facing decision this change deliberately does not make."""
    assert _MIN_TLS_STRENGTH_BITS == 128
    ctx = ssl.create_default_context()
    assert ctx.security_level == 2
    with pytest.raises(AttributeError):
        ctx.security_level = 3  # type: ignore[misc]


# --- BACKLOG #1005: opt-in CRL checking on the verifying server contexts -----------------------------
#
# Both traps from the item are ASSERTIONS here, not comments. Re-measured on this worktree
# (CPython 3.14.6 / OpenSSL 3.5.7) before any of this was written:
#
#   arm                                crls  good client   revoked client
#   CA only, no CRL flag (shipped)        0  ACCEPTED      ACCEPTED          <- the gap
#   cafile= CA + FRESH crl, flag ON       1  ACCEPTED      REFUSED: revoked  <- the control works
#   cadata= CA + FRESH crl, flag ON       0  REFUSED       REFUSED           <- TRAP 1
#   cafile= CA + STALE crl, flag ON       1  REFUSED       REFUSED           <- TRAP 2
#
# TRAP 1 is why the helper asserts cert_store_stats()["crl"] >= 1: a loader that silently loads
# ZERO CRLs still sets the flag, and then refuses EVERY client with "unable to get certificate
# CRL". Nothing at load time says so. The count is the only thing that distinguishes "loaded"
# from "silently ignored".
#
# TRAP 2 is why an expired CRL is refused at BUILD time: past nextUpdate, OpenSSL refuses every
# client rather than just revoked ones, so an unrefreshed CRL is an outage whose first symptom is
# every partner dropping at once. Failing loudly at startup beats failing at a partner handshake.


@pytest.fixture(scope="module")
def _crl_material(tmp_path_factory: pytest.TempPathFactory) -> dict[str, str]:
    """A throwaway CA plus a fresh and an expired CRL. Synthetic, no PHI, never leaves tmp."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    tmp = tmp_path_factory.mktemp("crl1005")
    now = datetime.datetime.now(datetime.UTC)
    day = datetime.timedelta(days=1)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "crl-probe-ca")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - day)
        .not_valid_after(now + 365 * day)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    def crl(next_update: datetime.datetime) -> bytes:
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(ca.subject)
            .last_update(now - 2 * day)
            .next_update(next_update)
            .add_revoked_certificate(
                x509.RevokedCertificateBuilder()
                .serial_number(4000)
                .revocation_date(now - day)
                .build()
            )
        )
        return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)

    def leaf(cn: str, serial: int, *, server: bool) -> tuple[bytes, bytes]:
        """A CA-issued leaf. `serial` 4000 is the one the CRL above revokes."""
        lk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        oid = (
            x509.oid.ExtendedKeyUsageOID.SERVER_AUTH
            if server
            else x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH
        )
        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
            .issuer_name(ca.subject)
            .public_key(lk.public_key())
            .serial_number(serial)
            .not_valid_before(now - day)
            .not_valid_after(now + 90 * day)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([oid]), critical=False)
        )
        if server:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False
            )
        cert = builder.sign(key, hashes.SHA256())
        return (
            cert.public_bytes(serialization.Encoding.PEM),
            lk.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        )

    ca_pem = ca.public_bytes(serialization.Encoding.PEM)
    out: dict[str, str] = {}

    def put(name: str, data: bytes) -> None:
        p = tmp / name
        p.write_bytes(data)
        out[name.split(".")[0]] = str(p)

    put("ca_only.pem", ca_pem)
    put("ca_and_fresh.pem", ca_pem + crl(now + 30 * day))
    put("ca_and_expired.pem", ca_pem + crl(now - day))
    for cn, serial, is_server, stem in (
        ("localhost", 2000, True, "server"),
        ("good-client", 3000, False, "good"),
        ("revoked-client", 4000, False, "revoked"),
    ):
        cert_pem, key_pem = leaf(cn, serial, server=is_server)
        put(f"{stem}.pem", cert_pem)
        put(f"{stem}_key.pem", key_pem)
    return out


def _verifying_ctx() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def test_harden_crl_check_loads_the_crl_and_sets_the_flag(_crl_material: dict[str, str]) -> None:
    # POSITIVE CONTROL for the two refusals below: the helper CAN succeed, so those tests are not
    # green merely because it rejects everything handed to it.
    ctx = _verifying_ctx()
    harden_crl_check(ctx, _crl_material["ca_and_fresh"])
    assert ctx.cert_store_stats()["crl"] >= 1
    assert ctx.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


def test_harden_crl_check_refuses_a_file_carrying_no_crl(_crl_material: dict[str, str]) -> None:
    # TRAP 1. Without this assertion the context comes back with the flag set and nothing to check
    # against, and every client -- good or revoked -- is refused "unable to get certificate CRL".
    # The failure is a total outage that reads, at the call site, like a working control.
    with pytest.raises(ValueError, match="no CRL"):
        harden_crl_check(_verifying_ctx(), _crl_material["ca_only"])


def test_harden_crl_check_refuses_an_already_expired_crl(_crl_material: dict[str, str]) -> None:
    # TRAP 2 preflight. Past nextUpdate OpenSSL refuses EVERY client, not just revoked ones, so an
    # unrefreshed CRL takes a live interface down. Refuse it loudly at construction instead of at
    # the first partner handshake, where the operator sees only "every partner dropped at once".
    with pytest.raises(ValueError, match="expired"):
        harden_crl_check(_verifying_ctx(), _crl_material["ca_and_expired"])


def test_harden_crl_check_refuses_a_missing_file(tmp_path: Path) -> None:
    # A configured-but-absent CRL must not degrade to "no revocation checking". Fail-closed by
    # construction is the whole reason this item is sized 5 rather than 3.
    with pytest.raises(ValueError, match="does not exist"):
        harden_crl_check(_verifying_ctx(), str(tmp_path / "nope.pem"))


def _crl_handshake(crl_bundle: str | None, client_stem: str, mat: dict[str, str]) -> str:
    """Complete one real mTLS handshake. Returns "ACCEPTED" or the OpenSSL refusal reason.

    TLS 1.2 is pinned so client authentication happens IN the handshake and the server-side
    outcome is unambiguous -- under 1.3 the client cert arrives after the server has finished and
    the failure surfaces on a later read instead.
    """
    import socket
    import threading

    srv_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    srv_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    srv_ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    srv_ctx.load_cert_chain(mat["server"], mat["server_key"])
    srv_ctx.verify_mode = ssl.CERT_REQUIRED
    srv_ctx.load_verify_locations(cafile=mat["ca_only"])
    if crl_bundle is not None:
        harden_crl_check(srv_ctx, crl_bundle)

    cli_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    cli_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    cli_ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    cli_ctx.load_verify_locations(cafile=mat["ca_only"])
    cli_ctx.load_cert_chain(mat[client_stem], mat[f"{client_stem}_key"])

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    box: dict[str, str] = {}

    def accept() -> None:
        try:
            conn, _ = listener.accept()
            with srv_ctx.wrap_socket(conn, server_side=True):
                box["result"] = "ACCEPTED"
        except ssl.SSLError as exc:
            box["result"] = str(exc)
        except OSError as exc:  # pragma: no cover - transport teardown race
            box["result"] = f"OSError: {exc}"

    thread = threading.Thread(target=accept)
    thread.start()
    with (
        contextlib.suppress(OSError, ssl.SSLError),
        socket.create_connection(("127.0.0.1", port), timeout=10) as sock,
        cli_ctx.wrap_socket(sock, server_hostname="localhost"),
    ):
        pass
    thread.join(timeout=10)
    listener.close()
    return box.get("result", "NO SERVER RESULT")


def test_a_revoked_client_is_refused_by_a_crl_checked_context(
    _crl_material: dict[str, str],
) -> None:
    # THE CLAIM THAT MATTERS. Every other test in this block asserts that a flag is set or that a
    # bad input is refused; none of them establishes that revocation actually happens. This drives
    # a real mTLS handshake with a certificate the CRL names.
    result = _crl_handshake(_crl_material["ca_and_fresh"], "revoked", _crl_material)
    assert "revoked" in result.lower(), result


def test_a_good_client_is_accepted_by_the_same_context(_crl_material: dict[str, str]) -> None:
    # POSITIVE CONTROL, and it is what separates a working revocation check from a context that
    # refuses everyone -- which is exactly what trap 1 produces and what a flag assertion cannot
    # tell apart.
    assert _crl_handshake(_crl_material["ca_and_fresh"], "good", _crl_material) == "ACCEPTED"


def test_without_the_crl_the_revoked_client_gets_in(_crl_material: dict[str, str]) -> None:
    # THE GAP ITSELF, pinned as a NEGATIVE CONTROL. This is the shipped posture the item is filed
    # against: CA loaded, CERT_REQUIRED set, no CRL -- and a certificate revoked this morning
    # authenticates until its notAfter. If this ever starts failing, revocation arrived by some
    # other route and the item's premise needs re-deriving rather than the test relaxing.
    assert _crl_handshake(None, "revoked", _crl_material) == "ACCEPTED"
