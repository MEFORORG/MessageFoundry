# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A JWK's ``alg`` binds its key (BACKLOG #5517): a key naming an algorithm the engine does not
verify is skipped, a key whose ``alg`` does not fit it is skipped, a JWKS left with no usable key
is refused, and a token whose ``alg`` differs from the one its key is restricted to is refused.

Hermetic: every key is generated here, and the JWKS is served from memory.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from messagefoundry.auth import oidc
from messagefoundry.auth.oidc.jwks import JwkAlgMismatch
from messagefoundry.config.models import SignatureAlgorithm
from messagefoundry.transports.signing import CompactJwtSigner

_NOW = 1_000_000


@pytest.fixture(scope="module")
def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


def _b64u_uint(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _rsa_jwk(key: rsa.RSAPrivateKey, kid: str, **extra: Any) -> dict[str, Any]:
    nums = key.public_key().public_numbers()
    return {"kty": "RSA", "kid": kid, "n": _b64u_uint(nums.n), "e": _b64u_uint(nums.e), **extra}


def _ec_jwk(key: ec.EllipticCurvePrivateKey, kid: str, crv: str, **extra: Any) -> dict[str, Any]:
    nums = key.public_key().public_numbers()
    return {
        "kty": "EC",
        "kid": kid,
        "crv": crv,
        "x": _b64u_uint(nums.x),
        "y": _b64u_uint(nums.y),
        **extra,
    }


def _jwks(*jwks: dict[str, Any]) -> bytes:
    return json.dumps({"keys": list(jwks)}).encode()


def _mint(key: rsa.RSAPrivateKey, kid: str, alg: SignatureAlgorithm) -> str:
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    claims: Mapping[str, Any] = {
        "iss": "https://idp.example",
        "aud": "mefor-console",
        "sub": "S-1-5-21-abc",
        "exp": _NOW + 300,
        "iat": _NOW,
        "auth_time": _NOW,
        "nonce": "n-123",
        "preferred_username": "jdoe@corp.example",
        "amr": ["pwd", "mfa"],
    }
    signer = CompactJwtSigner(
        private_key=pem, algorithm=alg, key_id=kid, setting="test_idp_signing_key"
    )
    return signer.sign(dict(claims))


def _policy(*algs: SignatureAlgorithm) -> oidc.OidcClaimPolicy:
    return oidc.OidcClaimPolicy(
        issuer="https://idp.example",
        client_id="mefor-console",
        signing_algorithms=list(algs),
        nonce="n-123",
        max_age_seconds=43200,
        allowed_username_domains=frozenset({"corp.example"}),
    )


def _cache(body: bytes) -> oidc.JwksCache:
    return oidc.JwksCache(lambda: body)


@pytest.mark.parametrize("alg", ["RSA-OAEP", "RSA-OAEP-256", "RSA1_5", "HS256", "none", "PS512"])
def test_a_key_naming_an_unsupported_alg_is_refused(rsa_key: rsa.RSAPrivateKey, alg: str) -> None:
    # No use and no key_ops: the alg is the only thing saying this is not a verify key.
    with pytest.raises(oidc.JwksError, match="not a supported signature algorithm"):
        oidc.jwk_to_public_key(_rsa_jwk(rsa_key, "enc", alg=alg))


def test_a_non_string_alg_is_refused(rsa_key: rsa.RSAPrivateKey) -> None:
    with pytest.raises(oidc.JwksError, match="alg must be a string"):
        oidc.jwk_to_public_key(_rsa_jwk(rsa_key, "k", alg=["RS256"]))


def test_a_jwks_of_only_encryption_keys_is_refused(rsa_key: rsa.RSAPrivateKey) -> None:
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    body = _jwks(_rsa_jwk(rsa_key, "e1", alg="RSA-OAEP"), _rsa_jwk(other, "e2", alg="RSA-OAEP-256"))
    with pytest.raises(oidc.JwksError, match="no usable signing keys"):
        oidc.parse_jwks(body)


def test_an_encryption_key_beside_a_signing_key_is_left_out(rsa_key: rsa.RSAPrivateKey) -> None:
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    body = _jwks(_rsa_jwk(rsa_key, "sig", alg="RS256"), _rsa_jwk(other, "enc", alg="RSA-OAEP"))
    assert set(oidc.parse_jwks(body)) == {"sig"}


@pytest.mark.parametrize("encryption_first", [False, True])
def test_a_skipped_key_sharing_a_kid_does_not_depend_on_order(
    rsa_key: rsa.RSAPrivateKey, encryption_first: bool
) -> None:
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    sig = _rsa_jwk(rsa_key, "k1", alg="RS256")
    enc = _rsa_jwk(other, "k1", alg="RSA-OAEP")
    body = _jwks(enc, sig) if encryption_first else _jwks(sig, enc)
    assert set(oidc.parse_jwks(body)) == {"k1"}
    # Two USABLE keys sharing a kid are still refused.
    with pytest.raises(oidc.JwksError, match="two keys with kid"):
        oidc.parse_jwks(_jwks(sig, _rsa_jwk(other, "k1", alg="RS256")))


@pytest.mark.parametrize(
    ("make", "crv", "alg"),
    [
        ("rsa", None, "ES256"),
        ("p256", "P-256", "RS256"),
        ("p256", "P-256", "ES384"),
        ("p384", "P-384", "ES256"),
    ],
)
def test_an_alg_that_does_not_fit_its_key_is_refused(
    rsa_key: rsa.RSAPrivateKey, make: str, crv: str | None, alg: str
) -> None:
    if make == "rsa":
        jwk = _rsa_jwk(rsa_key, "k", alg=alg)
    else:
        curve = ec.SECP256R1() if make == "p256" else ec.SECP384R1()
        assert crv is not None
        jwk = _ec_jwk(ec.generate_private_key(curve), "k", crv, alg=alg)
    with pytest.raises(oidc.JwksError, match="does not fit its key"):
        oidc.jwk_to_public_key(jwk)


def test_a_fitting_alg_and_no_alg_are_both_admitted(rsa_key: rsa.RSAPrivateKey) -> None:
    p384 = ec.generate_private_key(ec.SECP384R1())
    assert isinstance(oidc.jwk_to_public_key(_rsa_jwk(rsa_key, "a", alg="PS256")), rsa.RSAPublicKey)
    assert isinstance(oidc.jwk_to_public_key(_rsa_jwk(rsa_key, "b")), rsa.RSAPublicKey)
    key = oidc.jwk_to_public_key(_ec_jwk(p384, "c", "P-384", alg="ES384"))
    assert isinstance(key, ec.EllipticCurvePublicKey)


def test_the_cache_refuses_a_token_alg_the_key_is_not_restricted_to(
    rsa_key: rsa.RSAPrivateKey,
) -> None:
    cache = _cache(_jwks(_rsa_jwk(rsa_key, "k1", alg="RS256"), _rsa_jwk(rsa_key, "k2")))
    assert isinstance(cache.get_key("k1", alg=SignatureAlgorithm.RS256), rsa.RSAPublicKey)
    with pytest.raises(JwkAlgMismatch, match="restricted to RS256"):
        cache.get_key("k1", alg=SignatureAlgorithm.PS256)
    # A key that names no alg is not restricted by one.
    assert isinstance(cache.get_key("k2", alg=SignatureAlgorithm.PS256), rsa.RSAPublicKey)


def test_a_token_signed_under_another_alg_than_its_key_names_is_rejected(
    rsa_key: rsa.RSAPrivateKey,
) -> None:
    """Both algorithms are pinned and the RSA key verifies either, so only the JWK's alg says the
    PS256 token must not verify under this key."""
    body = _jwks(_rsa_jwk(rsa_key, "k1", use="sig", alg="RS256"))
    policy = _policy(SignatureAlgorithm.RS256, SignatureAlgorithm.PS256)
    # Control: the token the key is restricted to verifies.
    good = _mint(rsa_key, "k1", SignatureAlgorithm.RS256)
    assert oidc.validate_id_token(good, policy, _cache(body), clock=lambda: _NOW + 100).username
    other = _mint(rsa_key, "k1", SignatureAlgorithm.PS256)
    with pytest.raises(oidc.ClaimsError) as caught:
        oidc.validate_id_token(other, policy, _cache(body), clock=lambda: _NOW + 100)
    assert caught.value.reason == "key_rejected"
