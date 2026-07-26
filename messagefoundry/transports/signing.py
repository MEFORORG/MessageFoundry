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

**Crypto.** Core ``cryptography`` only — **no new dependency** (ADR 0018/0024). RSA (``RS256``/``RS384``
PKCS1-v1_5, ``PS256`` PSS) or ECDSA (``ES256`` P-256, ``ES384`` P-384); SHA-256 except ``RS384``/``ES384``
which are SHA-384. ECDSA's DER signature is converted to the JOSE fixed-width ``r||s`` form (and back on
verify), as JWS requires.

**Compact JWT.** Beside the detached JWS, :class:`CompactJwtSigner` mints an **attached** compact
JWS/JWT (``header.payload.signature`` — a populated payload segment) for the SMART Backend Services
``client_assertion`` (ADR 0024), reusing the same key-load + sign primitives.

**Key management.** The private key is operator-supplied as inline PEM (via ``env()``) or a PEM file
path (OS-protected, like a TLS key); it never leaves the box — only the public-verifiable signature
does. A managed key provider (HSM/KMS/Vault) is the separate ADR 0019 follow-up.
"""

from __future__ import annotations

import base64
import json
from typing import TYPE_CHECKING, Any

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
    from collections.abc import Iterable, Mapping

    from messagefoundry.config.wiring import ConnectionSpec

__all__ = [
    "CompactJwtSigner",
    "MessageSigner",
    "SigningError",
    "b64u_decode",
    "b64u_encode",
    "require_public_key_for_alg",
    "signer_from_destination",
    "unverified_jws_header",
    "verify_compact_jws",
    "verify_detached_jws",
    "with_signing",
]

# A signing key is RSA or EC; these are the two key/public-key type pairs we accept.
_PrivateKey = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey
_PublicKey = rsa.RSAPublicKey | ec.EllipticCurvePublicKey

# ES256 = ECDSA on P-256: each of r and s is a fixed 32-byte big-endian integer in the JOSE encoding.
_P256_COORD_BYTES = 32
# ES384 = ECDSA on P-384: each of r and s is a fixed 48-byte big-endian integer (ADR 0024).
_P384_COORD_BYTES = 48


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


# Public aliases: an OIDC relying party (ADR 0142) rebuilds public keys from JWK `n`/`e`/`x`/`y`, which
# are base64url — the same codec, and it must be the SAME implementation rather than a second one that
# could disagree about padding. Aliases, not renames, so every existing call site stays untouched.
b64u_encode = _b64u_encode
b64u_decode = _b64u_decode


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


# The ECDSA algorithms and their (curve name, friendly name, JOSE coordinate width, hash) — keeps
# _sign/_verify and _require_key_for_alg consistent about P-256/SHA-256 vs P-384/SHA-384.
_EC_PARAMS: dict[SignatureAlgorithm, tuple[str, str, int, type[hashes.HashAlgorithm]]] = {
    SignatureAlgorithm.ES256: ("secp256r1", "P-256", _P256_COORD_BYTES, hashes.SHA256),
    SignatureAlgorithm.ES384: ("secp384r1", "P-384", _P384_COORD_BYTES, hashes.SHA384),
}
# RSA algorithms that use PKCS1-v1_5 padding, and the hash each one signs with.
_RSA_PKCS1_HASH: dict[SignatureAlgorithm, type[hashes.HashAlgorithm]] = {
    SignatureAlgorithm.RS256: hashes.SHA256,
    SignatureAlgorithm.RS384: hashes.SHA384,
}


def _require_key_for_alg(key: _PrivateKey, alg: SignatureAlgorithm) -> None:
    """Reject a key that can't produce ``alg`` — loud at construction, not a wire-time surprise."""
    if alg in _EC_PARAMS:  # ES256 / ES384 — ECDSA on a specific curve
        curve_name, friendly, _, _ = _EC_PARAMS[alg]
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise SigningError(f"{alg.value} requires an EC private key, got {type(key).__name__}")
        if key.curve.name != curve_name:
            raise SigningError(
                f"{alg.value} requires a {friendly} ({curve_name}) key, got curve {key.curve.name!r}"
            )
    else:  # RS256 / RS384 / PS256 — RSA
        if not isinstance(key, rsa.RSAPrivateKey):
            raise SigningError(f"{alg.value} requires an RSA private key, got {type(key).__name__}")


def require_public_key_for_alg(key: _PublicKey, alg: SignatureAlgorithm) -> None:
    """Reject a **public** key that cannot verify ``alg`` — the verify-path mirror of
    :func:`_require_key_for_alg` (ADR 0142). ``_verify`` already refuses a wrong key *type* and a
    wrong signature *length*, but an EC key on the wrong curve for the pinned ``alg`` (e.g. a P-384
    key presented for ES256) should be refused explicitly at key-selection time, before any signature
    math. Raises :class:`SigningError`."""
    if alg in _EC_PARAMS:
        curve_name, friendly, _, _ = _EC_PARAMS[alg]
        if not isinstance(key, ec.EllipticCurvePublicKey):
            raise SigningError(f"{alg.value} requires an EC public key, got {type(key).__name__}")
        if key.curve.name != curve_name:
            raise SigningError(
                f"{alg.value} requires a {friendly} ({curve_name}) key, got curve {key.curve.name!r}"
            )
    elif not isinstance(key, rsa.RSAPublicKey):
        raise SigningError(f"{alg.value} requires an RSA public key, got {type(key).__name__}")


def _sign(key: _PrivateKey, alg: SignatureAlgorithm, data: bytes) -> bytes:
    """The raw JOSE signature bytes for ``data`` under ``alg`` (ECDSA DER → fixed-width ``r||s``)."""
    if alg in _EC_PARAMS:
        if not isinstance(
            key, ec.EllipticCurvePrivateKey
        ):  # defensive — guaranteed by construction
            raise SigningError(f"{alg.value} requires an EC key")
        _, _, coord, hash_cls = _EC_PARAMS[alg]
        der = key.sign(data, ec.ECDSA(hash_cls()))
        r, s = decode_dss_signature(der)
        return r.to_bytes(coord, "big") + s.to_bytes(coord, "big")
    if not isinstance(key, rsa.RSAPrivateKey):  # defensive — guaranteed by construction
        raise SigningError("RS256/RS384/PS256 require an RSA key")
    if alg is SignatureAlgorithm.PS256:
        return key.sign(
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
            hashes.SHA256(),
        )
    return key.sign(data, padding.PKCS1v15(), _RSA_PKCS1_HASH[alg]())


def _verify(public_key: _PublicKey, alg: SignatureAlgorithm, data: bytes, signature: bytes) -> None:
    """Verify ``signature`` over ``data`` under ``alg``; raises
    :class:`cryptography.exceptions.InvalidSignature` on mismatch, :class:`SigningError` on a
    structurally wrong signature/key."""
    if alg in _EC_PARAMS:
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise SigningError(
                f"{alg.value} needs an EC public key, got {type(public_key).__name__}"
            )
        _, _, coord, hash_cls = _EC_PARAMS[alg]
        if len(signature) != 2 * coord:
            raise SigningError(f"{alg.value} signature must be {2 * coord} bytes (r||s)")
        r = int.from_bytes(signature[:coord], "big")
        s = int.from_bytes(signature[coord:], "big")
        public_key.verify(encode_dss_signature(r, s), data, ec.ECDSA(hash_cls()))
        return
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise SigningError(f"{alg.value} needs an RSA public key, got {type(public_key).__name__}")
    if alg is SignatureAlgorithm.PS256:
        pad: padding.AsymmetricPadding = padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH
        )
        rsa_hash: hashes.HashAlgorithm = hashes.SHA256()
    else:
        pad = padding.PKCS1v15()
        rsa_hash = _RSA_PKCS1_HASH[alg]()
    public_key.verify(signature, data, pad, rsa_hash)


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


class CompactJwtSigner:
    """Mints an **attached compact JWS/JWT** (``header.payload.signature``) for an OAuth2
    ``client_assertion`` — the SMART Backend Services credential (ADR 0024).

    Unlike :class:`MessageSigner` (a *detached* JWS over an HTTP body, with an **empty** payload
    segment), this carries the base64url-encoded **claim set** in the payload segment, as a JWT
    requires. Built once — the key is loaded + validated here (a bad key/curve fails loud at
    construction), then :meth:`sign` is called per token request with fresh claims (``jti``/``exp``).
    Core ``cryptography`` only; SMART **SHALL** support ``RS384``/``ES384`` (SHA-384), but any
    :class:`SignatureAlgorithm` works."""

    def __init__(
        self,
        *,
        private_key: str,
        algorithm: SignatureAlgorithm,
        private_key_password: str | None = None,
        key_id: str | None = None,
    ) -> None:
        self.algorithm = algorithm
        self.key_id = key_id
        self._key: _PrivateKey = _load_private_key(private_key, private_key_password)
        _require_key_for_alg(self._key, algorithm)

    @property
    def public_key(self) -> _PublicKey:
        """The verifying (public) key — for tests / round-trips / exporting to the auth server."""
        return self._key.public_key()

    def sign(self, claims: Mapping[str, Any]) -> str:
        """The compact-JWT serialization ``BASE64URL(header).BASE64URL(claims).BASE64URL(sig)`` over
        ``claims``. The signature covers ``ASCII(header_b64 + '.' + claims_b64)`` (RFC 7515 §3)."""
        header: dict[str, str] = {"alg": self.algorithm.value, "typ": "JWT"}
        if self.key_id:
            header["kid"] = self.key_id
        header_b64 = _b64u_encode(
            json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
        )
        claims_b64 = _b64u_encode(
            json.dumps(dict(claims), separators=(",", ":"), sort_keys=True).encode("utf-8")
        )
        signing_input = f"{header_b64}.{claims_b64}".encode("ascii")
        signature = _sign(self._key, self.algorithm, signing_input)
        return f"{header_b64}.{claims_b64}.{_b64u_encode(signature)}"


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


def unverified_jws_header(jws: str) -> dict[str, Any]:
    """The protected header of a compact JWS, **without verifying anything** (RFC 7515 §4).

    Named for the danger. A relying party must read ``kid`` *before* it can select a key, so this step
    is unavoidable — but nothing it returns is trustworthy. Use it to pick a key and for nothing else;
    every value that matters (``alg`` included) is re-read from the verified header inside
    :func:`verify_compact_jws`."""
    parts = jws.split(".")
    if len(parts) != 3:
        raise SigningError("compact JWS must be 'header.payload.signature' (three segments)")
    try:
        header = json.loads(_b64u_decode(parts[0]))
    except (ValueError, UnicodeDecodeError) as exc:
        raise SigningError("compact JWS protected header is not valid base64url JSON") from exc
    if not isinstance(header, dict):
        raise SigningError("compact JWS protected header must be a JSON object")
    return header


def verify_compact_jws(
    jws: str,
    public_key: _PublicKey,
    *,
    allowed_algorithms: Iterable[SignatureAlgorithm | str],
) -> dict[str, Any]:
    """Verify an **attached** compact JWS (``header.payload.signature``) and RETURN ITS CLAIMS.

    The verify counterpart for a token *we did not mint* — an OIDC ``id_token`` (ADR 0142). It cannot
    reuse :func:`verify_detached_jws`, which rejects any populated payload segment by design.

    **It returns the claims deliberately.** Handing back the verified payload is what stops a caller
    from parsing its own copy of the token: a verify that returns ``None`` invites
    ``verify(tok); claims = json.loads(...)``, and the moment those two reads can differ you have the
    signature-wrapping bug class this codebase already carries on the XML path. There is exactly one
    parse, and it happens after the signature checks out.

    ``allowed_algorithms`` is **required**, unlike the detached variant's optional pin. This function
    consumes attacker-reachable input, so "the caller forgot to pin" must not be expressible. Note the
    two classic JWT attacks are foreclosed one level up regardless: ``SignatureAlgorithm`` is a closed
    enum with **no** ``none`` and **no** ``HS*`` member, so ``{"alg":"none"}`` and an RS256→HS256
    confusion both fail to coerce before any key is touched.

    Raises :class:`SigningError` on a malformed JWS, an unsupported/unpinned ``alg``, or a payload that
    is not a JSON object; :class:`cryptography.exceptions.InvalidSignature` on a signature mismatch.
    Returns the decoded claims on success. **It verifies the SIGNATURE only** — ``iss``, ``aud``,
    ``exp``, ``nonce`` and friends are the caller's ladder.
    """
    parts = jws.split(".")
    if len(parts) != 3:
        raise SigningError("compact JWS must be 'header.payload.signature' (three segments)")
    protected_b64, payload_b64, signature_b64 = parts
    if not protected_b64 or not payload_b64 or not signature_b64:
        raise SigningError("compact JWS segments must all be non-empty")

    header = unverified_jws_header(jws)
    try:
        alg = SignatureAlgorithm(header.get("alg"))
    except ValueError as exc:
        raise SigningError(f"unsupported or missing JWS alg {header.get('alg')!r}") from exc
    allowed = {SignatureAlgorithm(a) for a in allowed_algorithms}
    if not allowed:
        raise SigningError("allowed_algorithms must not be empty (a pin that permits nothing)")
    if alg not in allowed:
        raise SigningError(
            f"JWS alg {alg.value} is not in the allowed set {sorted(a.value for a in allowed)}"
        )

    # Verify over the EXACT received segments — never a re-encoding of the decoded payload, which
    # would let a non-canonical base64url variant validate against different bytes than we parse.
    signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
    try:
        signature = _b64u_decode(signature_b64)
    except (ValueError, UnicodeDecodeError) as exc:
        raise SigningError("compact JWS signature segment is not valid base64url") from exc
    _verify(public_key, alg, signing_input, signature)

    try:
        claims = json.loads(_b64u_decode(payload_b64))
    except (ValueError, UnicodeDecodeError) as exc:
        raise SigningError("compact JWS payload is not valid base64url JSON") from exc
    if not isinstance(claims, dict):
        raise SigningError("compact JWS payload must be a JSON object")
    return claims


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
