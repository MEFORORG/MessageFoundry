# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""A minimal software WebAuthn authenticator for tests (ADR 0068 decision 13).

Generates FRESH registration (``fmt="none"`` — no attestation signature needed) and assertion
responses that drive py_webauthn's REAL ``verify_registration_response`` /
``verify_authentication_response`` end-to-end, matching the repo's live-crypto test convention
(live TOTP codes, real argon2). Chosen over py_webauthn's canned fixtures (their registration and
authentication fixtures are NOT matched credential pairs, so canned inputs can never test
register→login) and over the stale ``soft-webauthn`` PyPI package (2022, drags python-fido2).

Uses only the already-locked ``cryptography`` (ECDSA-P256/SHA256) + ``webauthn.helpers`` CBOR/
base64url encoders — zero new test dependencies. ``tests/`` sits outside
``scripts/security/crypto_inventory_check.py``'s scan root, so the crypto imports here
deliberately trip nothing (recorded in the PR description).

Requires the ``[webauthn]`` extra — import this module only from importorskip-gated tests.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import struct
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from webauthn.helpers import bytes_to_base64url, encode_cbor

_FLAG_UP = 0x01  # user present — verify_registration_response requires it by default
_FLAG_AT = 0x40  # attested credential data included (registration only)
_AAGUID = b"\x00" * 16


def _client_data(kind: str, challenge: bytes, origin: str) -> bytes:
    """clientDataJSON: the challenge MUST be UNPADDED base64url (py_webauthn byte-compares the
    decode against ``expected_challenge``)."""
    return json.dumps(
        {"type": kind, "challenge": bytes_to_base64url(challenge), "origin": origin}
    ).encode("utf-8")


def _cose_ec2_public_key(key: ec.EllipticCurvePrivateKey) -> bytes:
    nums = key.public_key().public_numbers()
    return encode_cbor(
        {
            1: 2,  # kty: EC2
            3: -7,  # alg: ES256
            -1: 1,  # crv: P-256
            -2: nums.x.to_bytes(32, "big"),
            -3: nums.y.to_bytes(32, "big"),
        }
    )


@dataclass
class SoftAuthenticator:
    """One software passkey: holds the private key and mimics the two browser ceremonies."""

    rp_id: str = "t"
    origin: str = "http://t"
    sign_count: int = 0
    credential_id: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    _key: ec.EllipticCurvePrivateKey = field(
        default_factory=lambda: ec.generate_private_key(ec.SECP256R1())
    )

    @property
    def credential_id_b64(self) -> str:
        return bytes_to_base64url(self.credential_id)

    def _rp_hash(self) -> bytes:
        return hashlib.sha256(self.rp_id.encode("utf-8")).digest()

    def create_response(self, challenge: bytes, *, transports: list[str] | None = None) -> str:
        """A ``navigator.credentials.create`` response JSON (fmt="none" — time-stable, no
        attestation cert chain; the passkey norm and this repo's requested policy)."""
        attested = (
            _AAGUID
            + struct.pack(">H", len(self.credential_id))
            + self.credential_id
            + _cose_ec2_public_key(self._key)
        )
        auth_data = (
            self._rp_hash()
            + bytes([_FLAG_UP | _FLAG_AT])
            + struct.pack(">I", self.sign_count)
            + attested
        )
        attestation_object = encode_cbor({"fmt": "none", "attStmt": {}, "authData": auth_data})
        response: dict[str, object] = {
            "clientDataJSON": bytes_to_base64url(
                _client_data("webauthn.create", challenge, self.origin)
            ),
            "attestationObject": bytes_to_base64url(attestation_object),
        }
        if transports is not None:
            response["transports"] = transports
        return json.dumps(
            {
                "id": self.credential_id_b64,
                "rawId": self.credential_id_b64,
                "response": response,
                "type": "public-key",
                "clientExtensionResults": {},
            }
        )

    def get_response(self, challenge: bytes, *, sign_count: int | None = None) -> str:
        """A ``navigator.credentials.get`` response JSON: a REAL ECDSA-P256/SHA256 DER signature
        over ``authenticatorData + sha256(clientDataJSON)``. ``sign_count`` defaults to
        auto-increment; pass an explicit value (incl. a replayed one) for counter tests — 0 stays
        0 forever, the synced-passkey shape."""
        if sign_count is None and self.sign_count > 0:
            self.sign_count += 1
        count = self.sign_count if sign_count is None else sign_count
        client_data = _client_data("webauthn.get", challenge, self.origin)
        auth_data = self._rp_hash() + bytes([_FLAG_UP]) + struct.pack(">I", count)
        signature = self._key.sign(
            auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256())
        )
        return json.dumps(
            {
                "id": self.credential_id_b64,
                "rawId": self.credential_id_b64,
                "response": {
                    "clientDataJSON": bytes_to_base64url(client_data),
                    "authenticatorData": bytes_to_base64url(auth_data),
                    "signature": bytes_to_base64url(signature),
                    "userHandle": None,
                },
                "type": "public-key",
                "clientExtensionResults": {},
            }
        )
