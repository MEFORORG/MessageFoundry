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
import logging
import secrets
import struct
from collections.abc import Callable

import pytest

pytest.importorskip("webauthn")

from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa  # noqa: E402
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


def _relabelled(cose_key: bytes, **changes: object) -> bytes:
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


def _eddsa() -> bytes:
    return _okp(ed25519.Ed25519PrivateKey.generate())


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

#: COSE structures the pinned library did not refuse cleanly: each raised a raw ``KeyError``,
#: ``IndexError`` or ``TypeError`` out of ``verify_registration``, measured at ``0076e3cec`` -- a 500 at enrolment.
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
    for cose_key in (_p256(), _eddsa()):
        _assert_registers(cose_key)


_LARGER_CURVES = pytest.mark.parametrize(
    ("curve", "crv", "size"),
    [(ec.SECP384R1(), _P384, 48), (ec.SECP521R1(), 3, 66)],
    ids=["P-384", "P-521"],
)


def _cose_es256(key: ec.EllipticCurvePrivateKey, crv: int, size: int) -> bytes:
    nums = key.public_key().public_numbers()
    return encode_cbor(
        {
            1: 2,
            3: -7,
            -1: crv,
            -2: nums.x.to_bytes(size, "big"),
            -3: nums.y.to_bytes(size, "big"),
        }
    )


@_LARGER_CURVES
def test_es256_on_a_curve_other_than_p256_is_refused_at_registration(
    curve: ec.EllipticCurve, crv: int, size: int, caplog: pytest.LogCaptureFixture
) -> None:
    """Owner ruling 2026-09-23: ES256 is bound to P-256, the pairing RFC 9053 section 2.1 recommends.

    These keys are real and would verify, so this is a deliberate refusal and not a raw failure:
    it reaches the audited path as ``WebAuthnVerificationError`` and logs no WARNING.
    """
    challenge = secrets.token_bytes(wa.CHALLENGE_BYTES)
    response = _registration_response(
        challenge, _cose_es256(ec.generate_private_key(curve), crv, size)
    )
    logger = "messagefoundry.auth.webauthn"
    with (
        caplog.at_level(logging.WARNING, logger=logger),
        pytest.raises(wa.WebAuthnVerificationError) as caught,
    ):
        wa.verify_registration(response_json=response, challenge=challenge, rp_id=RP, origin=ORIGIN)
    assert "-7" in str(caught.value)
    assert not [r for r in caplog.records if r.name == logger]


@_LARGER_CURVES
def test_a_stored_es256_key_on_a_larger_curve_still_asserts(
    curve: ec.EllipticCurve, crv: int, size: int
) -> None:
    """The pin is registration-only, on purpose: a key enrolled before it must not lock anyone out.

    It verifies and clears the floor, so ``verify_assertion`` does not re-screen its curve.
    """
    key = ec.generate_private_key(curve)
    soft = SoftAuthenticator(rp_id=RP, origin=ORIGIN, _key=key)  # signs ECDSA over SHA-256
    challenge = secrets.token_bytes(wa.CHALLENGE_BYTES)
    assert (
        wa.verify_assertion(
            response_json=soft.get_response(challenge),
            challenge=challenge,
            rp_id=RP,
            origin=ORIGIN,
            public_key=_cose_es256(key, crv, size),
            current_sign_count=0,
        )
        == 0
    )


def _assert_registers(cose_key: bytes) -> None:
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
        lambda soft: encode_cbor([1]),
    ],
    ids=["labelled P-384 over a P-256 point", "no curve", "a short array"],
)
def test_an_unusable_stored_key_fails_assertion_as_invalid_input(
    stored: Callable[[SoftAuthenticator], bytes],
) -> None:
    """The backstop. Registration now refuses these, but a stored key is data the assertion path
    must not trust: a raw ``ValueError``, ``KeyError`` or ``IndexError`` here escapes the
    service's audited refusal and becomes a 500. Each row raised one of those at ``0076e3cec``."""
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
    assert set(wa._COSE_KEY_SHAPE_FOR_ALG) == set(wa.SUPPORTED_COSE_ALGS)


def test_a_raw_library_failure_is_logged_by_type_and_a_library_refusal_is_not(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Widening the catch must not make a defect silent.

    A raw exception out of the library is what a malformed key produces, and also what a bug on
    our side produces. It used to be a 500; now it is an audited refusal, so the type is logged.
    A ``WebAuthnException`` is the library refusing on purpose and is not logged here.
    """
    soft = SoftAuthenticator(rp_id=RP, origin=ORIGIN)
    logger = "messagefoundry.auth.webauthn"

    def assert_with(stored: bytes) -> None:
        challenge = secrets.token_bytes(wa.CHALLENGE_BYTES)
        with pytest.raises(wa.WebAuthnVerificationError):
            wa.verify_assertion(
                response_json=soft.get_response(challenge),
                challenge=challenge,
                rp_id=RP,
                origin=ORIGIN,
                public_key=stored,
                current_sign_count=0,
            )

    with caplog.at_level(logging.WARNING, logger=logger):
        assert_with(soft.cose_public_key(crv=99))  # UnsupportedEC2Curve: the library's own
    assert not [r for r in caplog.records if r.name == logger]

    caplog.clear()
    with caplog.at_level(logging.WARNING, logger=logger):
        assert_with(encode_cbor([1]))  # IndexError: raw
    warnings = [r for r in caplog.records if r.name == logger]
    assert [r.levelno for r in warnings] == [logging.WARNING]
    assert "IndexError" in warnings[0].getMessage()
    assert "assertion" in warnings[0].getMessage()

    caplog.clear()
    challenge = secrets.token_bytes(wa.CHALLENGE_BYTES)
    with (
        caplog.at_level(logging.WARNING, logger=logger),
        pytest.raises(wa.WebAuthnVerificationError),
    ):
        wa.verify_registration(
            response_json=_registration_response(challenge, encode_cbor({})),
            challenge=challenge,
            rp_id=RP,
            origin=ORIGIN,
        )
    warnings = [r for r in caplog.records if r.name == logger]
    assert len(warnings) == 1 and "KeyError" in warnings[0].getMessage()
    assert "registration" in warnings[0].getMessage()


# --- the pin compares CBOR integers, not values that merely equal one (BACKLOG #1953) ----------
#
# Python's ``bool`` is a subclass of ``int`` and ``1.0 == 1``, so a COSE key decoded with ``true`` or
# ``1.0`` where an integer belongs compares equal to the identifier it imitates. The library indexes
# the decoded CBOR by label and compares its values with ``==``, and the P-256 pin used ``int()``,
# so every row below ENROLLED at engine ``5ccff7cb3``: a real key whose one defect is a stand-in
# for an integer, as a parameter value or as the label that names it, or an array standing in for
# the map, whose positions the library's indexing reads as labels.


def _rekeyed(cose_key: bytes, label: int, stand_in: object) -> bytes:
    """``cose_key`` with the entry under ``label`` moved to the key ``stand_in``, value unchanged."""
    fields = dict(parse_cbor(cose_key))
    fields[stand_in] = fields.pop(label)
    return encode_cbor(fields)


def _as_array(cose_key: bytes, **changes: object) -> bytes:
    """``cose_key`` as a CBOR array, each value at the position the library reads for its label."""
    fields: dict[int, object] = dict(parse_cbor(_relabelled(cose_key, **changes)))
    positive = max(label for label in fields if label >= 0) + 1
    array: list[object] = [0] * (positive - min(label for label in fields if label < 0))
    for label, value in fields.items():
        array[label] = value
    return encode_cbor(array)


#: Every row reaches the shape check: each passed the library's own screens at ``5ccff7cb3``.
_NON_INTEGER_COSE_KEYS: dict[str, Callable[[], bytes]] = {
    "ES256 with crv true": lambda: _relabelled(_p256(), crv=True),
    "ES256 with crv 1.0": lambda: _relabelled(_p256(), crv=1.0),
    "ES256 with alg -7.0": lambda: _relabelled(_p256(), alg=-7.0),
    "ES256 with kty 2.0": lambda: _relabelled(_p256(), kty=2.0),
    "EdDSA with kty true": lambda: _relabelled(_eddsa(), kty=True),
    "EdDSA with crv 6.0": lambda: _relabelled(_eddsa(), crv=6.0),
    "EdDSA with alg -8.0": lambda: _relabelled(_eddsa(), alg=-8.0),
    "ES256 with the kty label written true": lambda: _rekeyed(_p256(), 1, True),
    "ES256 with the alg label written 3.0": lambda: _rekeyed(_p256(), 3, 3.0),
    "ES256 with the crv label written -1.0": lambda: _rekeyed(_p256(), -1, -1.0),
    "ES256 with the x label written -2.0": lambda: _rekeyed(_p256(), -2, -2.0),
    "EdDSA with the kty label written true": lambda: _rekeyed(_eddsa(), 1, True),
}

#: The same keys with the map written as an array. Each also ENROLLED at ``5ccff7cb3``.
_ARRAY_COSE_KEYS: dict[str, Callable[[], bytes]] = {
    "ES256 as an array": lambda: _as_array(_p256()),
    "ES256 as an array with crv true": lambda: _as_array(_p256(), crv=True),
    "EdDSA as an array with kty true": lambda: _as_array(_eddsa(), kty=True),
}


@pytest.mark.parametrize(
    ("build", "refusal"),
    [(build, "COSE key ") for build in _NON_INTEGER_COSE_KEYS.values()]
    + [(build, "COSE key must be a map") for build in _ARRAY_COSE_KEYS.values()],
    ids=[*_NON_INTEGER_COSE_KEYS, *_ARRAY_COSE_KEYS],
)
def test_a_stand_in_for_a_cose_integer_is_refused_at_registration(
    build: Callable[[], bytes], refusal: str, caplog: pytest.LogCaptureFixture
) -> None:
    """A deliberate refusal on the audited path, like the curve pin: no WARNING is logged.

    The message pins WHICH check refused: the screen's all start ``COSE key``, and the shape pin's
    starts ``COSE algorithm``, so a row cannot pass on the pin or on a broken fixture. An array
    row must meet the map rule itself, not the label rule, which would also refuse its byte
    strings when iterated as labels.
    """
    challenge = secrets.token_bytes(wa.CHALLENGE_BYTES)
    logger = "messagefoundry.auth.webauthn"
    with (
        caplog.at_level(logging.WARNING, logger=logger),
        pytest.raises(wa.WebAuthnVerificationError) as caught,
    ):
        wa.verify_registration(
            response_json=_registration_response(challenge, build()),
            challenge=challenge,
            rp_id=RP,
            origin=ORIGIN,
        )
    assert str(caught.value).startswith(refusal)
    assert not [r for r in caplog.records if r.name == logger]


def test_the_stand_in_rows_are_otherwise_well_formed() -> None:
    """The positive control for the table above: the same two rewrites, carrying the integer.

    If these were refused, the rows would prove only that the rewrite breaks a key, not that the
    type check refuses it. A text-string label is a legal COSE label (RFC 9052 section 7) that
    names no parameter the checks read, so it rides along here and must not be refused.
    """
    _assert_registers(_relabelled(_p256(), kty=2, alg=-7, crv=_P256))
    _assert_registers(_relabelled(_eddsa(), kty=1, alg=-8, crv=_ED25519))
    for label in (1, 3, -1, -2):
        _assert_registers(_rekeyed(_p256(), label, label))
        _assert_registers(_rekeyed(_eddsa(), label, label))
    with_text_label = dict(parse_cbor(_p256()))
    with_text_label["note"] = "x"
    _assert_registers(encode_cbor(with_text_label))
