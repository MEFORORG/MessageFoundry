# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Adversarial cases for ``verify_compact_jws`` — the OIDC ``id_token`` verify path (ADR 0142).

This is the highest-risk-per-line code in the federated-SSO build: a bug here is a silent, total
authentication bypass, and unlike a library we own every line of it. So the negatives carry the
weight — a positive-path test proves almost nothing about a verifier.

Two attacks are foreclosed one level up and are asserted here anyway, because the *reason* they are
foreclosed (``SignatureAlgorithm`` is a closed enum with no ``none`` and no ``HS*``) is a property of
a file someone could edit without ever opening this one:

  * ``{"alg":"none"}`` — the unsigned-token attack;
  * RS256 → HS256 confusion — verifying an HMAC with the RSA *public* key as the shared secret.
"""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from messagefoundry.config.models import SignatureAlgorithm
from messagefoundry.transports.signing import (
    CompactJwtSigner,
    SigningError,
    b64u_decode,
    b64u_encode,
    unverified_jws_header,
    verify_compact_jws,
)

_RS256 = [SignatureAlgorithm.RS256]


@pytest.fixture(scope="module")
def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def ec_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _pem(key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey) -> str:
    from cryptography.hazmat.primitives import serialization

    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


def _mint(
    key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
    alg: SignatureAlgorithm,
    claims: dict[str, Any] | None = None,
) -> str:
    """A real token from the shipped signer — never a hand-rolled one, so the fixture cannot drift
    from what the engine actually produces."""
    signer = CompactJwtSigner(private_key=_pem(key), algorithm=alg)
    return signer.sign(claims if claims is not None else {"sub": "jdoe", "iss": "https://idp"})


def _retarget(jws: str, *, header: dict[str, Any] | None, payload: dict[str, Any] | None) -> str:
    """Rebuild a JWS with a swapped header and/or payload, keeping the ORIGINAL signature."""
    h, p, s = jws.split(".")
    if header is not None:
        h = b64u_encode(json.dumps(header).encode())
    if payload is not None:
        p = b64u_encode(json.dumps(payload).encode())
    return f"{h}.{p}.{s}"


# --- positive control ------------------------------------------------------------------------------


def test_valid_token_returns_its_claims(rsa_key: rsa.RSAPrivateKey) -> None:
    """The verified claims come back from the verifier itself — the caller never re-parses."""
    jws = _mint(rsa_key, SignatureAlgorithm.RS256, {"sub": "jdoe", "amr": ["mfa"]})
    claims = verify_compact_jws(jws, rsa_key.public_key(), allowed_algorithms=_RS256)
    assert claims["sub"] == "jdoe"
    assert claims["amr"] == ["mfa"]


def test_es256_round_trip(ec_key: ec.EllipticCurvePrivateKey) -> None:
    jws = _mint(ec_key, SignatureAlgorithm.ES256)
    claims = verify_compact_jws(
        jws, ec_key.public_key(), allowed_algorithms=[SignatureAlgorithm.ES256]
    )
    assert claims["sub"] == "jdoe"


# --- the two classic JWT attacks -------------------------------------------------------------------


def test_alg_none_is_unrepresentable(rsa_key: rsa.RSAPrivateKey) -> None:
    """``{"alg":"none"}`` must fail to coerce BEFORE any key is touched."""
    jws = _retarget(_mint(rsa_key, SignatureAlgorithm.RS256), header={"alg": "none"}, payload=None)
    with pytest.raises(SigningError, match="unsupported or missing JWS alg"):
        verify_compact_jws(jws, rsa_key.public_key(), allowed_algorithms=_RS256)


def test_hs256_confusion_is_unrepresentable(rsa_key: rsa.RSAPrivateKey) -> None:
    """RS256->HS256: the enum has no HMAC member, so it never reaches a verify."""
    jws = _retarget(_mint(rsa_key, SignatureAlgorithm.RS256), header={"alg": "HS256"}, payload=None)
    with pytest.raises(SigningError, match="unsupported or missing JWS alg"):
        verify_compact_jws(jws, rsa_key.public_key(), allowed_algorithms=_RS256)


def test_none_and_hs_are_absent_from_the_enum() -> None:
    """Guards the *reason* the two tests above pass — a property of config/models.py."""
    values = {a.value.lower() for a in SignatureAlgorithm}
    assert "none" not in values
    assert not any(v.startswith("hs") for v in values), (
        "an HMAC member would reopen the RS256->HS256 key-confusion attack"
    )


# --- tampering -------------------------------------------------------------------------------------


def test_tampered_payload_fails(rsa_key: rsa.RSAPrivateKey) -> None:
    """The attack that matters: swap the subject, keep the signature."""
    jws = _retarget(_mint(rsa_key, SignatureAlgorithm.RS256), header=None, payload={"sub": "admin"})
    with pytest.raises(InvalidSignature):
        verify_compact_jws(jws, rsa_key.public_key(), allowed_algorithms=_RS256)


def test_tampered_signature_fails(rsa_key: rsa.RSAPrivateKey) -> None:
    h, p, s = _mint(rsa_key, SignatureAlgorithm.RS256).split(".")
    raw = bytearray(b64u_decode(s))
    raw[0] ^= 0x01
    with pytest.raises(InvalidSignature):
        verify_compact_jws(
            f"{h}.{p}.{b64u_encode(bytes(raw))}",
            rsa_key.public_key(),
            allowed_algorithms=_RS256,
        )


def test_signature_from_a_different_key_fails(rsa_key: rsa.RSAPrivateKey) -> None:
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jws = _mint(other, SignatureAlgorithm.RS256)
    with pytest.raises(InvalidSignature):
        verify_compact_jws(jws, rsa_key.public_key(), allowed_algorithms=_RS256)


def test_wrong_key_type_for_alg_is_refused(
    rsa_key: rsa.RSAPrivateKey, ec_key: ec.EllipticCurvePrivateKey
) -> None:
    jws = _mint(rsa_key, SignatureAlgorithm.RS256)
    with pytest.raises(SigningError, match="needs an RSA public key"):
        verify_compact_jws(jws, ec_key.public_key(), allowed_algorithms=_RS256)


# --- the algorithm pin -----------------------------------------------------------------------------


def test_unpinned_algorithm_is_refused(ec_key: ec.EllipticCurvePrivateKey) -> None:
    """A genuinely signed ES256 token must still be refused where only RS256 is expected."""
    jws = _mint(ec_key, SignatureAlgorithm.ES256)
    with pytest.raises(SigningError, match="not in the allowed set"):
        verify_compact_jws(jws, ec_key.public_key(), allowed_algorithms=_RS256)


def test_empty_pin_is_refused(rsa_key: rsa.RSAPrivateKey) -> None:
    """An empty allow-list permits nothing; say so rather than failing obscurely later."""
    jws = _mint(rsa_key, SignatureAlgorithm.RS256)
    with pytest.raises(SigningError, match="must not be empty"):
        verify_compact_jws(jws, rsa_key.public_key(), allowed_algorithms=[])


def test_pin_is_required_at_the_type_level(rsa_key: rsa.RSAPrivateKey) -> None:
    """Unlike the detached variant, the pin has no default — 'the caller forgot' is unexpressible."""
    jws = _mint(rsa_key, SignatureAlgorithm.RS256)
    with pytest.raises(TypeError):
        verify_compact_jws(jws, rsa_key.public_key())  # type: ignore[call-arg]


# --- malformed input -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("jws", "reason"),
    [
        ("", "three segments"),
        ("a.b", "three segments"),
        ("a.b.c.d", "three segments"),
        ("..", "non-empty"),
        ("a..c", "non-empty"),
        ("!!!.e30.c2ln", "not valid base64url JSON"),
    ],
)
def test_structurally_invalid_tokens_are_refused(
    jws: str, reason: str, rsa_key: rsa.RSAPrivateKey
) -> None:
    with pytest.raises(SigningError, match=reason):
        verify_compact_jws(jws, rsa_key.public_key(), allowed_algorithms=_RS256)


def test_non_object_header_is_refused(rsa_key: rsa.RSAPrivateKey) -> None:
    jws = f"{b64u_encode(b'[1,2]')}.{b64u_encode(b'{}')}.{b64u_encode(b'x')}"
    with pytest.raises(SigningError, match="must be a JSON object"):
        verify_compact_jws(jws, rsa_key.public_key(), allowed_algorithms=_RS256)


def test_non_object_payload_is_refused_after_a_valid_signature(
    rsa_key: rsa.RSAPrivateKey,
) -> None:
    """A correctly SIGNED but non-object payload is still refused — signature != well-formed claims."""
    header = b64u_encode(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    payload = b64u_encode(b'"not-an-object"')
    from messagefoundry.transports.signing import _sign  # noqa: PLC0415

    sig = _sign(rsa_key, SignatureAlgorithm.RS256, f"{header}.{payload}".encode("ascii"))
    with pytest.raises(SigningError, match="payload must be a JSON object"):
        verify_compact_jws(
            f"{header}.{payload}.{b64u_encode(sig)}",
            rsa_key.public_key(),
            allowed_algorithms=_RS256,
        )


def test_signature_is_over_the_received_segments_not_a_reencoding(
    rsa_key: rsa.RSAPrivateKey,
) -> None:
    """A non-canonical (padded) payload segment must not validate.

    If the verifier re-encoded the *decoded* payload to build the signing input, a token whose
    payload segment carries '=' padding would verify while the bytes actually parsed differ from the
    bytes actually signed. Verifying over the received segments closes that.
    """
    h, p, s = _mint(rsa_key, SignatureAlgorithm.RS256).split(".")
    padded = base64.urlsafe_b64encode(b64u_decode(p)).decode("ascii")  # keeps '=' padding
    if padded == p:  # pragma: no cover - only when the payload length is a multiple of 3
        pytest.skip("payload needs no padding; the non-canonical variant is identical")
    with pytest.raises((InvalidSignature, SigningError)):
        verify_compact_jws(f"{h}.{padded}.{s}", rsa_key.public_key(), allowed_algorithms=_RS256)


# --- the unverified header peek --------------------------------------------------------------------


def test_unverified_header_exposes_kid_without_verifying(rsa_key: rsa.RSAPrivateKey) -> None:
    """Key selection needs `kid` before verification is possible; nothing else may trust it."""
    h = b64u_encode(json.dumps({"alg": "RS256", "kid": "key-1"}).encode())
    jws = f"{h}.{b64u_encode(b'{}')}.{b64u_encode(b'not-a-signature')}"
    assert unverified_jws_header(jws)["kid"] == "key-1"
    # ...and the same token still fails to verify.
    with pytest.raises((InvalidSignature, SigningError)):
        verify_compact_jws(jws, rsa_key.public_key(), allowed_algorithms=_RS256)
