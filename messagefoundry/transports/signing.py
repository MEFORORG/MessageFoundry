# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Opt-in per-connection **detached-JWS** message signing for REST/SOAP outbound (ASVS 4.1.5, ADR 0018).

A signed outbound puts a message-level digital signature **on top of** the transport (TLS) so a
partner — or any downstream hop — can verify the payload's **integrity and origin** independent of the
channel. It is OFF unless a connection configures it (:class:`~messagefoundry.config.models.OutboundSigning`).

**What is minted.** A **detached JWS** (RFC 7515 Appendix F): the compact serialization
``BASE64URL(protected) || '.' || '' || '.' || BASE64URL(signature)`` (``header..signature`` — the
payload segment is empty), where the signature is computed over
``ASCII(BASE64URL(protected) || '.' || BASE64URL(payload))``. The payload itself stays the HTTP body
(not duplicated in the header); the receiver reconstructs the signing input from the **exact body
bytes it received** and the detached header, then verifies against the agreed **public** key.

**Where it is minted.** In the connector's ``send()`` boundary — over the exact bytes that go on the
wire (for SOAP WS-\\* that is the wrapped envelope, built in ``send()``) — and **inside the off-loop
worker thread** ``send()`` already uses. That is *past the queue boundary*, exactly like the
WS-Security timestamp/nonce (ADR 0015 §1): a re-run/retry re-mints the signature, so routers and
transforms stay pure and the at-least-once invariant holds even for the randomized algorithms (PS256/
ES256 produce a fresh signature per call — fine here, never in a transform).

**Crypto.** Core ``cryptography`` only — **no new dependency** (ADR 0018). RSA (``RS256`` PKCS1-v1_5,
``PS256`` PSS) or ECDSA (``ES256`` P-256), all SHA-256. ECDSA's DER signature is converted to the JOSE
fixed-width ``r||s`` form (and back on verify), as JWS requires.

**Key management.** The private key is operator-supplied as inline PEM (via ``env()``) or a PEM file
path (OS-protected, like a TLS key); it never leaves the box — only the public-verifiable signature
does. A managed key provider (HSM/KMS/Vault) is the separate ADR 0019 follow-up.
"""

from __future__ import annotations

import base64
import json
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from messagefoundry.config.models import (
    ConnectorType,
    Destination,
    OutboundSigning,
    SignatureAlgorithm,
)

if (
    TYPE_CHECKING
):  # only for the with_signing() annotation — avoid importing the heavy wiring module
    from collections.abc import Iterable

    from messagefoundry.config.wiring import ConnectionSpec

__all__ = [
    "MessageSigner",
    "SigningError",
    "signer_from_destination",
    "verify_detached_jws",
    "with_signing",
]

# A signing key is RSA or EC; these are the two key/public-key type pairs we accept.
_PrivateKey = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey
_PublicKey = rsa.RSAPublicKey | ec.EllipticCurvePublicKey

# ES256 = ECDSA on P-256: each of r and s is a fixed 32-byte big-endian integer in the JOSE encoding.
_P256_COORD_BYTES = 32


class SigningError(ValueError):
    """A signing key/algorithm/JWS was misconfigured or malformed.

    Raised loud at connector construction (a bad key fails at ``check``/dry-run/start, like a bad TLS
    cert) or from :func:`verify_detached_jws` on a structurally invalid JWS. A *signature mismatch* on
    verify is the library's :class:`cryptography.exceptions.InvalidSignature`, not this."""


def _b64u_encode(raw: bytes) -> str:
    """Base64url without padding (RFC 7515 §2)."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64u_decode(text: str) -> bytes:
    """Inverse of :func:`_b64u_encode` (re-pads before decoding)."""
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _read_key_material(private_key: str) -> bytes:
    """The PEM bytes of the signing key: the value verbatim if it is inline PEM, else read from the
    path it names (a PEM key file, OS-protected like a TLS key)."""
    if "-----BEGIN" in private_key:
        return private_key.encode("utf-8")
    try:
        with open(private_key, "rb") as handle:
            return handle.read()
    except OSError as exc:
        # Name the failure but never echo the path's contents; the path itself is operator config.
        raise SigningError(
            f"could not read the signing-key file {private_key!r}: {exc.strerror}"
        ) from exc


def _load_private_key(private_key: str, password: str | None) -> _PrivateKey:
    """Load + validate the PEM private key (RSA or EC). Errors are PHI/secret-free — they never
    interpolate the key bytes or the (cryptography) deserialization detail, which could echo material."""
    material = _read_key_material(private_key)
    pw = password.encode("utf-8") if password else None
    try:
        key = serialization.load_pem_private_key(material, password=pw)
    except (ValueError, TypeError):
        raise SigningError(
            "could not load the signing private key — check the PEM, and the password for an "
            "encrypted key (set private_key_password via env())"
        ) from None
    if not isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
        raise SigningError(
            f"signing key must be an RSA or EC (ECDSA) private key, got {type(key).__name__}"
        )
    return key


def _require_key_for_alg(key: _PrivateKey, alg: SignatureAlgorithm) -> None:
    """Reject a key that can't produce ``alg`` — loud at construction, not a wire-time surprise."""
    if alg in (SignatureAlgorithm.RS256, SignatureAlgorithm.PS256):
        if not isinstance(key, rsa.RSAPrivateKey):
            raise SigningError(f"{alg.value} requires an RSA private key, got {type(key).__name__}")
    else:  # ES256
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise SigningError(f"ES256 requires an EC private key, got {type(key).__name__}")
        if key.curve.name != "secp256r1":
            raise SigningError(
                f"ES256 requires a P-256 (secp256r1) key, got curve {key.curve.name!r}"
            )


def _sign(key: _PrivateKey, alg: SignatureAlgorithm, data: bytes) -> bytes:
    """The raw JOSE signature bytes for ``data`` under ``alg`` (ECDSA DER → fixed-width ``r||s``)."""
    if alg is SignatureAlgorithm.ES256:
        if not isinstance(
            key, ec.EllipticCurvePrivateKey
        ):  # defensive — guaranteed by construction
            raise SigningError("ES256 requires an EC key")
        der = key.sign(data, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return r.to_bytes(_P256_COORD_BYTES, "big") + s.to_bytes(_P256_COORD_BYTES, "big")
    if not isinstance(key, rsa.RSAPrivateKey):  # defensive — guaranteed by construction
        raise SigningError("RS256/PS256 require an RSA key")
    if alg is SignatureAlgorithm.PS256:
        return key.sign(
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
            hashes.SHA256(),
        )
    return key.sign(data, padding.PKCS1v15(), hashes.SHA256())


def _verify(public_key: _PublicKey, alg: SignatureAlgorithm, data: bytes, signature: bytes) -> None:
    """Verify ``signature`` over ``data`` under ``alg``; raises
    :class:`cryptography.exceptions.InvalidSignature` on mismatch, :class:`SigningError` on a
    structurally wrong signature/key."""
    if alg is SignatureAlgorithm.ES256:
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise SigningError(f"ES256 needs an EC public key, got {type(public_key).__name__}")
        if len(signature) != 2 * _P256_COORD_BYTES:
            raise SigningError("ES256 signature must be 64 bytes (r||s)")
        r = int.from_bytes(signature[:_P256_COORD_BYTES], "big")
        s = int.from_bytes(signature[_P256_COORD_BYTES:], "big")
        public_key.verify(encode_dss_signature(r, s), data, ec.ECDSA(hashes.SHA256()))
        return
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise SigningError(f"{alg.value} needs an RSA public key, got {type(public_key).__name__}")
    pad: padding.AsymmetricPadding = (
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH)
        if alg is SignatureAlgorithm.PS256
        else padding.PKCS1v15()
    )
    public_key.verify(signature, data, pad, hashes.SHA256())


class MessageSigner:
    """Mints (and can verify) a detached JWS over a payload for one connection's signing config.

    Built once at connector construction — the key is loaded and validated here, so a bad key/algorithm
    fails loud at ``check``/dry-run/start. ``signature_headers`` is then called per delivery in the
    connector's off-loop ``send()`` worker."""

    def __init__(self, config: OutboundSigning) -> None:
        self.algorithm: SignatureAlgorithm = config.algorithm
        self.key_id: str | None = config.key_id
        self.header_name: str = config.header_name
        self._key: _PrivateKey = _load_private_key(config.private_key, config.private_key_password)
        _require_key_for_alg(self._key, self.algorithm)
        # The protected header is static per connection (only the signature varies per payload); a
        # compact, sorted JSON encoding makes RS256 byte-stable across runs.
        header: dict[str, str] = {"alg": self.algorithm.value}
        if self.key_id:
            header["kid"] = self.key_id
        self._protected_b64 = _b64u_encode(
            json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
        )

    @property
    def public_key(self) -> _PublicKey:
        """The verifying (public) key — for tests, round-trips, and exporting to a partner."""
        return self._key.public_key()

    def detached_jws(self, payload: bytes) -> str:
        """The detached-JWS compact serialization (``header..signature``) over ``payload``."""
        signing_input = f"{self._protected_b64}.{_b64u_encode(payload)}".encode("ascii")
        signature = _sign(self._key, self.algorithm, signing_input)
        return f"{self._protected_b64}..{_b64u_encode(signature)}"

    def signature_headers(self, payload: bytes) -> dict[str, str]:
        """The HTTP header(s) to add for ``payload``: ``{header_name: <detached JWS>}``."""
        return {self.header_name: self.detached_jws(payload)}

    def verify(self, jws: str, payload: bytes) -> None:
        """Verify a JWS this signer produced against ``payload`` (the self-verify / round-trip path)."""
        verify_detached_jws(jws, payload, self.public_key, allowed_algorithms=(self.algorithm,))


def verify_detached_jws(
    jws: str,
    payload: bytes,
    public_key: _PublicKey,
    *,
    allowed_algorithms: Iterable[SignatureAlgorithm | str] | None = None,
) -> None:
    """Verify a detached JWS (``header..signature``) over ``payload`` with ``public_key``.

    This is the **verify counterpart** of the signer — what a receiver (or a test) runs. ``payload`` is
    the exact body bytes the message arrived as. Returns ``None`` on success; raises
    :class:`cryptography.exceptions.InvalidSignature` if the signature does not match, or
    :class:`SigningError` if the JWS is malformed / its ``alg`` is unsupported or not in
    ``allowed_algorithms`` (pass the algorithms you expect to pin against an ``alg`` downgrade)."""
    parts = jws.split(".")
    if len(parts) != 3:
        raise SigningError(
            "detached JWS must be 'header..signature' (three '.'-separated segments)"
        )
    protected_b64, detached, signature_b64 = parts
    if detached != "":
        raise SigningError("detached JWS payload segment must be empty (RFC 7515 detached content)")
    try:
        header = json.loads(_b64u_decode(protected_b64))
    except (ValueError, UnicodeDecodeError) as exc:
        raise SigningError("detached JWS protected header is not valid base64url JSON") from exc
    try:
        alg = SignatureAlgorithm(header.get("alg"))
    except ValueError as exc:
        raise SigningError(f"unsupported or missing JWS alg {header.get('alg')!r}") from exc
    if allowed_algorithms is not None:
        allowed = {SignatureAlgorithm(a) for a in allowed_algorithms}
        if alg not in allowed:
            raise SigningError(
                f"JWS alg {alg.value} is not in the allowed set {sorted(a.value for a in allowed)}"
            )
    signing_input = f"{protected_b64}.{_b64u_encode(payload)}".encode("ascii")
    _verify(public_key, alg, signing_input, _b64u_decode(signature_b64))


def signer_from_destination(config: Destination) -> MessageSigner | None:
    """The :class:`MessageSigner` for an outbound, or ``None`` when signing is off.

    Prefers the typed :attr:`Destination.sign` the runner assembled; falls back to flat ``sign_*``
    settings so a directly-built ``Destination`` (e.g. in a test) signs too. ``None`` when unconfigured
    or ``enabled=False`` — every existing outbound is unchanged."""
    signing = config.sign or OutboundSigning.from_settings(config.settings)
    if signing is None or not signing.enabled:
        return None
    return MessageSigner(signing)


def with_signing(
    spec: ConnectionSpec,
    *,
    private_key: object,
    algorithm: SignatureAlgorithm | str = SignatureAlgorithm.RS256,
    key_id: str | None = None,
    header_name: str = "X-JWS-Signature",
    private_key_password: object | None = None,
    enabled: bool = True,
) -> ConnectionSpec:
    """Enable opt-in detached-JWS signing on a **REST/SOAP** outbound spec (ASVS 4.1.5, ADR 0018).

    Compose it over the ``Rest()`` / ``Soap()`` factory — which supplies every transport default — so
    signing is one code-first call and nothing about the connector changes::

        from messagefoundry import Rest, env, outbound
        from messagefoundry.transports.signing import with_signing

        outbound("OB_ACME_ADT", with_signing(
            Rest(url=env("acme_url")),
            private_key=env("acme_sign_key"),   # inline PEM via env(), or a PEM file path
            algorithm="ES256",
            key_id="acme-2026",
        ))

    ``private_key`` and ``private_key_password`` may be :func:`~messagefoundry.config.wiring.env`
    references (resolved per environment) — keep every secret in ``env()``. Mutates ``spec``'s settings
    in place and returns it. Signing is OFF on any spec this was not called on."""
    if spec.type not in (ConnectorType.REST, ConnectorType.SOAP):
        raise SigningError(
            f"message signing applies to REST/SOAP outbound only, not {spec.type.value!r} (ADR 0018)"
        )
    spec.settings.update(
        {
            "sign_enabled": enabled,
            "sign_algorithm": SignatureAlgorithm(algorithm).value,
            "sign_private_key": private_key,
            "sign_private_key_password": private_key_password,
            "sign_key_id": key_id,
            "sign_header": header_name,
        }
    )
    return spec
