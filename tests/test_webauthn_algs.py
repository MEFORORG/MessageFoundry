# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The relying party's credential-algorithm floor (BACKLOG #1166, ASVS 11.2.3).

``messagefoundry/auth/webauthn.py`` pins :data:`SUPPORTED_COSE_ALGS` instead of inheriting
py_webauthn's default set. These rows drive the REAL library on both ceremony halves, because the
two halves fail differently and only one of them refuses anything:

* ``generate_registration_options`` decides what the browser is OFFERED. An authenticator may
  ignore it, so on its own it is a hint, not a control.
* ``verify_registration_response`` decides what is ACCEPTED. This is the refusal.

A change that restricted only the first would read like a fix and admit exactly the same
credentials, so every enforcement row here goes through ``wa.verify_registration``.

The RSA credential builder is local rather than in ``tests/_soft_webauthn.py``: that helper exists
to produce credentials the engine ACCEPTS, and these rows need one it must refuse. ``tests/`` sits
outside ``crypto_inventory_check.py``'s ``WALK_ROOTS``, so the ``cryptography`` import here
registers nothing.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import struct

import pytest

pytest.importorskip("webauthn")

from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from webauthn.helpers import bytes_to_base64url, encode_cbor  # noqa: E402
from webauthn.helpers.cose import COSEAlgorithmIdentifier  # noqa: E402

from messagefoundry.auth import webauthn as wa  # noqa: E402
from tests._soft_webauthn import SoftAuthenticator  # noqa: E402

RP = "t"
ORIGIN = "http://t"

_FLAG_UP = 0x01
_FLAG_AT = 0x40
_AAGUID = b"\x00" * 16

#: Every RSA identifier the pinned library defines (PSS, PKCS#1 v1.5, and the deprecated SHA-1
#: one). None of them constrains the modulus, which is the property this floor turns on.
_RSA_ALGS = frozenset(
    {
        COSEAlgorithmIdentifier.RSASSA_PSS_SHA_256,
        COSEAlgorithmIdentifier.RSASSA_PSS_SHA_384,
        COSEAlgorithmIdentifier.RSASSA_PSS_SHA_512,
        COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
        COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_384,
        COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_512,
        COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_1,
    }
)

# Key generation is the slow part of these rows, so each modulus size is built once.
_rsa_keys: dict[int, rsa.RSAPrivateKey] = {}


def _rsa_key(bits: int) -> rsa.RSAPrivateKey:
    if bits not in _rsa_keys:
        _rsa_keys[bits] = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return _rsa_keys[bits]


def _cose_rsa(public: rsa.RSAPublicKey, alg: int) -> bytes:
    nums = public.public_numbers()
    return encode_cbor(
        {
            1: 3,  # kty: RSA
            3: alg,
            -1: nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big"),
            -2: nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big"),
        }
    )


def _rsa_registration_response(challenge: bytes, *, bits: int, alg: int) -> str:
    """A well-formed ``navigator.credentials.create`` response carrying an RSA credential.

    Everything except the credential's key type matches what the soft authenticator produces, so a
    refusal can only be the algorithm screen.
    """
    key = _rsa_key(bits)
    credential_id = secrets.token_bytes(32)
    attested = (
        _AAGUID
        + struct.pack(">H", len(credential_id))
        + credential_id
        + _cose_rsa(key.public_key(), alg)
    )
    auth_data = (
        hashlib.sha256(RP.encode("utf-8")).digest()
        + bytes([_FLAG_UP | _FLAG_AT])
        + struct.pack(">I", 0)
        + attested
    )
    client_data = json.dumps(
        {
            "type": "webauthn.create",
            "challenge": bytes_to_base64url(challenge),
            "origin": ORIGIN,
        }
    ).encode("utf-8")
    return json.dumps(
        {
            "id": bytes_to_base64url(credential_id),
            "rawId": bytes_to_base64url(credential_id),
            "response": {
                "clientDataJSON": bytes_to_base64url(client_data),
                "attestationObject": bytes_to_base64url(
                    encode_cbor({"fmt": "none", "attStmt": {}, "authData": auth_data})
                ),
            },
            "type": "public-key",
            "clientExtensionResults": {},
        }
    )


def _advertised_algs() -> list[int]:
    options = json.loads(
        wa.registration_options(
            rp_id=RP,
            rp_name="MessageFoundry",
            user_id="u1",
            user_name="admin",
            challenge=secrets.token_bytes(wa.CHALLENGE_BYTES),
        )
    )
    return [param["alg"] for param in options["pubKeyCredParams"]]


def test_the_advertised_set_is_the_pinned_set_not_the_library_default() -> None:
    """The browser is offered exactly ``SUPPORTED_COSE_ALGS``, in order."""
    from webauthn.registration.generate_registration_options import (
        default_supported_pub_key_algs,
    )

    advertised = _advertised_algs()
    assert advertised == list(wa.SUPPORTED_COSE_ALGS)
    # The row only means something while the library default is WIDER than the pin. If a future
    # release narrows its own default to match, this says so rather than passing vacuously.
    assert set(default_supported_pub_key_algs) - set(advertised), (
        "py_webauthn's default set no longer exceeds the pinned set, so this file's premise has "
        "moved; re-derive the floor against the new default rather than deleting the row"
    )


def test_no_rsa_identifier_is_advertised_because_none_constrains_the_modulus() -> None:
    """The floor's whole reason: an RSA identifier fixes padding and hash, never key size."""
    assert _RSA_ALGS.isdisjoint(wa.SUPPORTED_COSE_ALGS)
    assert COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256 not in wa.SUPPORTED_COSE_ALGS


def test_every_pinned_identifier_resolves_to_a_library_identifier() -> None:
    """A pin the library no longer defines must fail loudly, not silently widen the set."""
    resolved = wa._supported_pub_key_algs()
    assert [int(alg) for alg in resolved] == list(wa.SUPPORTED_COSE_ALGS)
    assert all(isinstance(alg, COSEAlgorithmIdentifier) for alg in resolved)


def test_advertised_and_enforced_sets_cannot_drift() -> None:
    """Both ceremony halves read one source, so the offer can never outrun the refusal."""
    assert _advertised_algs() == [int(alg) for alg in wa._supported_pub_key_algs()]


@pytest.mark.parametrize("bits", [2048, 1024])
def test_an_rs256_credential_is_refused_at_any_modulus_size(bits: int) -> None:
    """RSA-2048 is roughly 112 bits and RSA-1024 far less; both were ACCEPTED before this floor."""
    challenge = secrets.token_bytes(wa.CHALLENGE_BYTES)
    response = _rsa_registration_response(
        challenge, bits=bits, alg=int(COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256)
    )
    with pytest.raises(wa.WebAuthnVerificationError) as caught:
        wa.verify_registration(response_json=response, challenge=challenge, rp_id=RP, origin=ORIGIN)
    # Named so the row cannot pass on some unrelated malformation of the fixture.
    assert "-257" in str(caught.value)


def test_an_es256_credential_still_registers_and_asserts() -> None:
    """The positive control: the floor refuses RSA without breaking the credentials it keeps."""
    challenge = secrets.token_bytes(wa.CHALLENGE_BYTES)
    soft = SoftAuthenticator(rp_id=RP, origin=ORIGIN)
    registered = wa.verify_registration(
        response_json=soft.create_response(challenge),
        challenge=challenge,
        rp_id=RP,
        origin=ORIGIN,
    )
    assert registered.credential_id == soft.credential_id

    challenge = secrets.token_bytes(wa.CHALLENGE_BYTES)
    assert (
        wa.verify_assertion(
            response_json=soft.get_response(challenge),
            challenge=challenge,
            rp_id=RP,
            origin=ORIGIN,
            public_key=registered.public_key,
            current_sign_count=0,
        )
        == 0
    )


def test_the_rsa_fixture_is_well_formed_apart_from_its_key_type() -> None:
    """Without this, the refusal rows could be passing on a broken response rather than the floor.

    Same builder, same challenge, but carrying the identifier the library still accepts by default:
    if THIS is refused, the fixture is wrong and the rows above prove nothing.
    """
    challenge = secrets.token_bytes(wa.CHALLENGE_BYTES)
    response = _rsa_registration_response(
        challenge, bits=2048, alg=int(COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256)
    )
    from webauthn import verify_registration_response

    verified = verify_registration_response(
        credential=response,
        expected_challenge=challenge,
        expected_rp_id=RP,
        expected_origin=ORIGIN,
    )
    assert verified.credential_id
