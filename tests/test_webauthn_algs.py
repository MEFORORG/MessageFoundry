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
from collections.abc import Callable

import pytest

pytest.importorskip("webauthn")

from cryptography.hazmat.primitives.asymmetric import ed25519, rsa  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402
from webauthn.helpers import bytes_to_base64url, encode_cbor, parse_cbor  # noqa: E402
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
    return _registration_response(challenge, _cose_rsa(_rsa_key(bits).public_key(), alg))


def _registration_response(challenge: bytes, cose_key: bytes) -> str:
    """A well-formed ``navigator.credentials.create`` response carrying ``cose_key`` verbatim."""
    credential_id = secrets.token_bytes(32)
    attested = _AAGUID + struct.pack(">H", len(credential_id)) + credential_id + cose_key
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


# --- the curve half of the floor: a credential must be usable at the moment it enrols ----------
#
# The identifier pin above leans on one property: a credential whose curve is unknown or does not
# match its key can never produce a verifiable assertion. True, but it used to be found out at the
# FIRST ASSERTION, after the credential had enrolled, and on the mismatched-curve path it arrived as
# a raw ``ValueError`` from ``cryptography`` that ``verify_assertion`` did not catch -- a 500, not
# the audited invalid-input path ADR 0068 decision 1 requires. These rows move the refusal to
# registration and pin the assertion side as a backstop.

_P256 = 1
_P384 = 2
_ED25519 = 6


def _ed25519_raw(key: ed25519.Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _okp(key: ed25519.Ed25519PrivateKey, *, alg: int = -8, crv: int = _ED25519) -> bytes:
    return encode_cbor({1: 1, 3: alg, -1: crv, -2: _ed25519_raw(key)})


def _relabelled(cose_key: bytes, **changes: int | None) -> bytes:
    """``cose_key`` with COSE labels changed; a ``None`` value drops the label."""
    names = {"kty": 1, "alg": 3, "crv": -1}
    fields = dict(parse_cbor(cose_key))
    for name, value in changes.items():
        if value is None:
            fields.pop(names[name], None)
        else:
            fields[names[name]] = value
    return encode_cbor(fields)


def _p256() -> bytes:
    return SoftAuthenticator(rp_id=RP, origin=ORIGIN).cose_public_key()


#: Credentials the pinned library ENROLLED before this check, measured at engine ``0076e3cec``, and
#: which no assertion can ever verify against. Each is refused at registration now.
_UNUSABLE_CREDENTIALS: dict[str, Callable[[], bytes]] = {
    "EC2 with an unknown curve": lambda: _relabelled(_p256(), crv=99),
    "EC2 labelled P-384 over a P-256 point": lambda: _relabelled(_p256(), crv=_P384),
    "EC2 labelled with the Ed25519 curve": lambda: _relabelled(_p256(), crv=_ED25519),
    "EC2 point that is on no curve": lambda: encode_cbor(
        {1: 2, 3: -7, -1: _P256, -2: b"\x01" * 32, -3: b"\x02" * 32}
    ),
    "EC2 coordinate that is not a byte string": lambda: encode_cbor(
        {1: 2, 3: -7, -1: _P256, -2: 5, -3: 6}
    ),
    "OKP labelled P-256": lambda: _okp(ed25519.Ed25519PrivateKey.generate(), crv=_P256),
    "OKP with an unknown curve": lambda: _okp(ed25519.Ed25519PrivateKey.generate(), crv=99),
    "OKP key of the wrong length": lambda: encode_cbor(
        {1: 1, 3: -8, -1: _ED25519, -2: b"\x01" * 5}
    ),
    "EdDSA identifier on an EC2 key": lambda: _relabelled(_p256(), alg=-8),
    "ES256 identifier on an OKP key": lambda: _okp(ed25519.Ed25519PrivateKey.generate(), alg=-7),
}

#: COSE structures the pinned library did not refuse cleanly: each raised a raw ``KeyError`` or
#: ``TypeError`` out of ``verify_registration``, measured at ``0076e3cec`` -- a 500 at enrolment.
_MALFORMED_CREDENTIALS: dict[str, Callable[[], bytes]] = {
    "an empty map": lambda: encode_cbor({}),
    "a key type and nothing else": lambda: encode_cbor({1: 2}),
    "a bare integer": lambda: encode_cbor(5),
    "a short array": lambda: encode_cbor([1]),
    "an EC2 key with no curve": lambda: _relabelled(_p256(), crv=None),
}


@pytest.mark.parametrize("build", _UNUSABLE_CREDENTIALS.values(), ids=_UNUSABLE_CREDENTIALS.keys())
def test_a_credential_no_assertion_could_verify_is_refused_at_registration(
    build: Callable[[], bytes],
) -> None:
    """It used to enrol and then fail at first use, which is later and louder than it needs to be."""
    challenge = secrets.token_bytes(wa.CHALLENGE_BYTES)
    with pytest.raises(wa.WebAuthnVerificationError):
        wa.verify_registration(
            response_json=_registration_response(challenge, build()),
            challenge=challenge,
            rp_id=RP,
            origin=ORIGIN,
        )


@pytest.mark.parametrize(
    "build", _MALFORMED_CREDENTIALS.values(), ids=_MALFORMED_CREDENTIALS.keys()
)
def test_a_malformed_credential_key_is_invalid_input_not_a_crash(
    build: Callable[[], bytes],
) -> None:
    """Only :class:`wa.WebAuthnVerificationError` reaches the service's audited refusal."""
    challenge = secrets.token_bytes(wa.CHALLENGE_BYTES)
    with pytest.raises(wa.WebAuthnVerificationError):
        wa.verify_registration(
            response_json=_registration_response(challenge, build()),
            challenge=challenge,
            rp_id=RP,
            origin=ORIGIN,
        )


def test_the_curve_rows_use_a_well_formed_response() -> None:
    """The positive control for the two tables above: the same builder, carrying an honest key.

    If this is refused, the builder is broken and the refusal rows prove nothing. EdDSA rides
    through ``_registration_response`` too, so the OKP arm of the check is shown to admit Ed25519.
    """
    for cose_key in (_p256(), _okp(ed25519.Ed25519PrivateKey.generate())):
        challenge = secrets.token_bytes(wa.CHALLENGE_BYTES)
        registered = wa.verify_registration(
            response_json=_registration_response(challenge, cose_key),
            challenge=challenge,
            rp_id=RP,
            origin=ORIGIN,
        )
        assert registered.public_key == cose_key


@pytest.mark.parametrize(
    "stored",
    [
        lambda soft: soft.cose_public_key(crv=_P384),
        lambda soft: _relabelled(soft.cose_public_key(), crv=None),
        lambda soft: soft.cose_public_key(crv=99),
    ],
    ids=["labelled P-384 over a P-256 point", "no curve", "unknown curve"],
)
def test_an_unusable_stored_key_fails_assertion_as_invalid_input(
    stored: Callable[[SoftAuthenticator], bytes],
) -> None:
    """The backstop. Registration now refuses these, but a stored key is data the assertion path
    must not trust: a raw ``ValueError`` or ``KeyError`` here escapes the service's audited
    refusal and becomes a 500."""
    soft = SoftAuthenticator(rp_id=RP, origin=ORIGIN)
    challenge = secrets.token_bytes(wa.CHALLENGE_BYTES)
    with pytest.raises(wa.WebAuthnVerificationError):
        wa.verify_assertion(
            response_json=soft.get_response(challenge),
            challenge=challenge,
            rp_id=RP,
            origin=ORIGIN,
            public_key=stored(soft),
            current_sign_count=0,
        )


def test_every_pinned_identifier_names_the_key_type_it_arrives_in() -> None:
    """Widening :data:`wa.SUPPORTED_COSE_ALGS` must force a decision about the key type check.

    Without a row, an added identifier would be refused at registration for every credential, which
    is loud; this says why before a user finds out.
    """
    assert set(wa._COSE_KTY_FOR_ALG) == set(wa.SUPPORTED_COSE_ALGS)
