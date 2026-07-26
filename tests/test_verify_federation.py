# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The `verify --section federation` section (ADR 0142, BACKLOG #274).

The thing worth testing here is the HONESTY contract, not the happy path: a section that reported
PASS for config the settings validators already guarantee would be a wall of green proving nothing,
and a rung that was never reached must never read as passing.
"""

from __future__ import annotations

import base64
import json
import time
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from messagefoundry.config.models import SignatureAlgorithm
from messagefoundry.config.settings import ServiceSettings
from messagefoundry.transports.signing import CompactJwtSigner
from messagefoundry.verify.federation import run_federation_checks
from messagefoundry.verify.model import CheckResult, Status
from messagefoundry.verify.runner import ALL_SECTIONS

NONCE = "n-verify-1"


@pytest.fixture(scope="module")
def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _b64u_uint(v: int) -> str:
    raw = v.to_bytes((v.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _jwks_bytes(key: rsa.RSAPrivateKey, kid: str = "k1") -> bytes:
    n = key.public_key().public_numbers()
    return json.dumps(
        {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": kid,
                    "use": "sig",
                    "alg": "RS256",
                    "n": _b64u_uint(n.n),
                    "e": _b64u_uint(n.e),
                }
            ]
        }
    ).encode()


def _mint(key: rsa.RSAPrivateKey, **over: Any) -> str:
    now = time.time()
    claims: dict[str, Any] = {
        "iss": "https://idp.example",
        "aud": "mefor-console",
        "sub": "S-1-5-21-fed",
        "exp": now + 600,
        "iat": now,
        "nonce": NONCE,
        "preferred_username": "jdoe@corp.example",
        "amr": ["pwd", "mfa"],
    }
    claims.update(over)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    return CompactJwtSigner(private_key=pem, algorithm=SignatureAlgorithm.RS256, key_id="k1").sign(
        claims
    )


def _mint_raw(key: rsa.RSAPrivateKey, claims: dict[str, Any]) -> str:
    """Sign an EXACT claims dict — needed to omit a claim entirely, which _mint cannot express."""
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    return CompactJwtSigner(private_key=pem, algorithm=SignatureAlgorithm.RS256, key_id="k1").sign(
        claims
    )


def _settings(**over: Any) -> ServiceSettings:
    auth: dict[str, Any] = {
        "ad_enabled": True,
        "ad_server": "ldaps://x",
        "ad_user_search_base": "DC=x",
        "ad_bind_dn": "CN=svc,DC=x",
        "ad_bind_password": "x",
        "ad_domain": "corp.example",
        "oidc_enabled": True,
        "oidc_issuer": "https://idp.example",
        "oidc_client_id": "mefor-console",
        "oidc_client_secret": "shhh",
        "oidc_authorization_endpoint": "https://idp.example/authorize",
        "oidc_token_endpoint": "https://idp.example/token",
        "oidc_jwks_uri": "https://idp.example/jwks",
        "oidc_allowed_endpoints": ["idp.example"],
    }
    auth.update(over)
    return ServiceSettings.model_validate(
        {"auth": auth, "api": {"public_origin": "https://ops.example"}}
    )


def _by_id(rows: list[CheckResult]) -> dict[str, CheckResult]:
    return {r.id: r for r in rows}


def test_federation_is_a_runnable_section() -> None:
    assert "federation" in ALL_SECTIONS
    # manual.ad stays: it covers AD/Kerberos sign-in, not federation, and ids are namespaced.
    assert all(not s.startswith("fed") for s in ALL_SECTIONS if s != "federation")


def test_disabled_emits_exactly_one_skip_row() -> None:
    """A non-federated deployment's report gains ONE line and its exit code is unchanged."""
    rows = run_federation_checks(ServiceSettings())
    assert len(rows) == 1
    assert rows[0].id == "fed.enabled"
    assert rows[0].status is Status.SKIP


def test_no_settings_skips_rather_than_erroring() -> None:
    rows = run_federation_checks(None)
    assert [r.status for r in rows] == [Status.SKIP]


def test_config_facts_are_manual_never_pass() -> None:
    """The validators already refuse an unusable [auth].oidc_* combination at load, so a PASS on
    config would be a check that cannot fail. Only genuinely fallible things may PASS."""
    rows = _by_id(run_federation_checks(_settings()))
    for rid in ("fed.enabled", "fed.algorithms", "fed.mfa_gate", "fed.username_binding"):
        assert rows[rid].status is Status.MANUAL, rid
    # The pinned endpoints must be visible as evidence, or the MANUAL row is unactionable.
    assert "idp.example" in rows["fed.enabled"].evidence
    assert "corp.example" in rows["fed.username_binding"].evidence


def test_a_disabled_mfa_gate_is_reported_not_hidden() -> None:
    rows = _by_id(run_federation_checks(_settings(oidc_require_mfa_claim=False)))
    assert rows["fed.mfa_gate"].status is Status.MANUAL
    assert "DISABLED" in rows["fed.mfa_gate"].detail


def test_secret_and_tls_can_actually_pass() -> None:
    rows = _by_id(run_federation_checks(_settings()))
    assert rows["fed.client_secret"].status is Status.PASS
    assert "shhh" not in rows["fed.client_secret"].detail  # never echo the value
    assert rows["fed.idp_tls"].status is Status.PASS


def test_an_unreadable_ca_file_fails(tmp_path: Path) -> None:
    rows = _by_id(
        run_federation_checks(_settings(oidc_tls_ca_cert_file=str(tmp_path / "nope.pem")))
    )
    assert rows["fed.idp_tls"].status is Status.FAIL


def test_replay_is_skipped_without_both_inputs() -> None:
    rows = _by_id(run_federation_checks(_settings(), id_token_file="only-one.txt"))
    assert rows["fed.replay"].status is Status.SKIP
    assert "--fed-jwks" in rows["fed.replay"].detail


def test_replay_all_rungs_pass_with_the_real_nonce(
    rsa_key: rsa.RSAPrivateKey, tmp_path: Path
) -> None:
    tok = tmp_path / "t.jwt"
    tok.write_text(_mint(rsa_key), encoding="ascii")
    jwks = tmp_path / "j.json"
    jwks.write_bytes(_jwks_bytes(rsa_key))

    rows = _by_id(
        run_federation_checks(_settings(), id_token_file=str(tok), jwks_file=str(jwks), nonce=NONCE)
    )
    assert rows["fed.jwks"].status is Status.PASS
    for rid in (
        "fed.replay.key",
        "fed.replay.signature",
        "fed.replay.claims",
        "fed.replay.nonce",
        "fed.replay.mfa",
        "fed.replay.username",
    ):
        assert rows[rid].status is Status.PASS, rid
    assert rows["fed.replay.principal"].status is Status.MANUAL
    assert "jdoe" in rows["fed.replay.principal"].evidence


def test_without_a_nonce_the_binding_rung_skips_and_later_rungs_are_not_claimed_passed(
    rsa_key: rsa.RSAPrivateKey, tmp_path: Path
) -> None:
    """Substituting the token's own nonce would make that rung a check that cannot fail. It must
    SKIP — and everything downstream of it must SKIP too, never PASS: unreached is not passing."""
    tok = tmp_path / "t.jwt"
    tok.write_text(_mint(rsa_key), encoding="ascii")
    jwks = tmp_path / "j.json"
    jwks.write_bytes(_jwks_bytes(rsa_key))

    rows = _by_id(run_federation_checks(_settings(), id_token_file=str(tok), jwks_file=str(jwks)))
    assert rows["fed.replay.key"].status is Status.PASS
    assert rows["fed.replay.signature"].status is Status.PASS
    assert rows["fed.replay.claims"].status is Status.PASS
    assert rows["fed.replay.nonce"].status is Status.SKIP
    assert rows["fed.replay.mfa"].status is Status.SKIP
    assert rows["fed.replay.username"].status is Status.SKIP
    assert "fed.replay.principal" not in rows


@pytest.mark.parametrize(
    ("over", "failing_rung"),
    [
        ({"iss": "https://evil.example"}, "fed.replay.claims"),
        ({"aud": "someone-else"}, "fed.replay.claims"),
        ({"amr": ["pwd"]}, "fed.replay.mfa"),
        ({"preferred_username": "Administrator@attacker.example"}, "fed.replay.username"),
    ],
)
def test_a_bad_token_fails_exactly_the_right_rung(
    rsa_key: rsa.RSAPrivateKey, tmp_path: Path, over: dict[str, Any], failing_rung: str
) -> None:
    tok = tmp_path / "t.jwt"
    tok.write_text(_mint(rsa_key, **over), encoding="ascii")
    jwks = tmp_path / "j.json"
    jwks.write_bytes(_jwks_bytes(rsa_key))

    rows = _by_id(
        run_federation_checks(_settings(), id_token_file=str(tok), jwks_file=str(jwks), nonce=NONCE)
    )
    assert rows[failing_rung].status is Status.FAIL, rows[failing_rung]
    order = [
        rid
        for rid, _, _ in __import__("messagefoundry.verify.federation", fromlist=["_RUNGS"])._RUNGS
    ]
    idx = order.index(failing_rung)
    for rid in order[:idx]:
        assert rows[rid].status is Status.PASS, f"{rid} should have been reached and passed"
    for rid in order[idx + 1 :]:
        assert rows[rid].status is Status.SKIP, f"{rid} was never reached; it must not read as PASS"


def test_a_stale_capture_skips_rather_than_failing(
    rsa_key: rsa.RSAPrivateKey, tmp_path: Path
) -> None:
    """An expired captured token is a stale artefact, not a deployment defect."""
    tok = tmp_path / "t.jwt"
    tok.write_text(_mint(rsa_key, exp=time.time() - 10_000), encoding="ascii")
    jwks = tmp_path / "j.json"
    jwks.write_bytes(_jwks_bytes(rsa_key))

    rows = _by_id(
        run_federation_checks(_settings(), id_token_file=str(tok), jwks_file=str(jwks), nonce=NONCE)
    )
    assert rows["fed.replay.claims"].status is Status.SKIP
    assert "expired" in rows["fed.replay.claims"].detail


def test_a_bad_jwks_fails_and_no_rung_claims_a_pass(tmp_path: Path) -> None:
    tok = tmp_path / "t.jwt"
    tok.write_text("not.a.token", encoding="ascii")
    jwks = tmp_path / "j.json"
    jwks.write_bytes(b"{not json")

    rows = _by_id(run_federation_checks(_settings(), id_token_file=str(tok), jwks_file=str(jwks)))
    assert rows["fed.jwks"].status is Status.FAIL
    assert all(
        rows[rid].status is Status.SKIP
        for rid in ("fed.replay.key", "fed.replay.signature", "fed.replay.claims")
    )


def test_the_section_never_raises_on_a_missing_file() -> None:
    rows = run_federation_checks(
        _settings(), id_token_file="/nonexistent/a.jwt", jwks_file="/nonexistent/b.json"
    )
    assert any(r.status is Status.FAIL for r in rows)


def test_every_closed_set_reason_is_mapped_to_exactly_one_rung() -> None:
    """The per-rung verdict is derived from the reason slug ALONE, so the map must be total and
    unambiguous. An UNMAPPED slug would silently report every rung PASS on a real failure; a slug in
    TWO rungs would blame a rung that passed. Both shipped once — `malformed_token` was raised from
    key selection AND signature verification, and `expired` covered three different faults."""
    from messagefoundry.auth.oidc import REASONS
    from messagefoundry.verify.federation import _RUNGS

    mapped: dict[str, list[str]] = {}
    for rid, _title, reasons in _RUNGS:
        for reason in reasons:
            mapped.setdefault(reason, []).append(rid)

    assert set(mapped) <= REASONS, f"maps slugs not in the closed set: {set(mapped) - REASONS}"
    unmapped = REASONS - set(mapped)
    assert not unmapped, f"reason slugs with no rung (would report every rung PASS): {unmapped}"
    ambiguous = {r: rids for r, rids in mapped.items() if len(rids) > 1}
    assert not ambiguous, (
        f"slugs mapped to more than one rung (would blame a passing rung): {ambiguous}"
    )


def test_a_missing_exp_fails_rather_than_claiming_the_capture_is_stale(
    rsa_key: rsa.RSAPrivateKey, tmp_path: Path
) -> None:
    """An IdP that mints no usable `exp` is a real defect — it is the datum AC-6 caps the session at.
    Reporting it as a stale capture would state something false AND exit 0."""
    base: dict[str, Any] = {
        "iss": "https://idp.example",
        "aud": "mefor-console",
        "sub": "S-1-5-21-fed",
        "iat": time.time(),
        "nonce": NONCE,
        "preferred_username": "jdoe@corp.example",
        "amr": ["pwd", "mfa"],
    }
    cases: list[dict[str, Any]] = [
        dict(base),  # exp omitted entirely
        dict(base, exp="9999999999"),  # exp as a JSON string
        dict(base, exp=True),  # exp as a boolean
    ]
    jwks = tmp_path / "j.json"
    jwks.write_bytes(_jwks_bytes(rsa_key))

    for i, claims in enumerate(cases):
        tok = tmp_path / f"t{i}.jwt"
        tok.write_text(_mint_raw(rsa_key, claims), encoding="ascii")
        rows = _by_id(
            run_federation_checks(
                _settings(), id_token_file=str(tok), jwks_file=str(jwks), nonce=NONCE
            )
        )
        row = rows["fed.replay.claims"]
        assert row.status is Status.FAIL, f"case {i}: {row}"
        assert "expired" not in row.detail, f"case {i}: must not claim the capture is stale"


def test_a_disabled_mfa_gate_skips_its_rung_instead_of_passing_it(
    rsa_key: rsa.RSAPrivateKey, tmp_path: Path
) -> None:
    """With the gate off, _check_mfa_gate returns before reading a claim, so PASS would be a verdict
    for a check that cannot fail — and would contradict the DISABLED row in the same report."""
    tok = tmp_path / "t.jwt"
    tok.write_text(_mint(rsa_key, amr=["pwd"]), encoding="ascii")
    jwks = tmp_path / "j.json"
    jwks.write_bytes(_jwks_bytes(rsa_key))

    rows = _by_id(
        run_federation_checks(
            _settings(oidc_require_mfa_claim=False),
            id_token_file=str(tok),
            jwks_file=str(jwks),
            nonce=NONCE,
        )
    )
    assert rows["fed.replay.mfa"].status is Status.SKIP
    assert "disabled" in rows["fed.replay.mfa"].detail.lower()
    assert rows["fed.replay.username"].status is Status.PASS  # the ladder still walked past it
