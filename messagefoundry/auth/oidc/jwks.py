# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""JWKS handling for the OIDC relying party (ADR 0142): JWK → public key, with a key-material floor,
plus a bounded, TTL'd, min-refetch-throttled key cache.

The closed ``SignatureAlgorithm`` enum forecloses ``alg:none`` and RS256→HS256 confusion at the
verify step (``transports/signing.py``). It does **not** foreclose a *weak* key — a 512-bit RSA JWK
verifies "correctly" and is forgeable in minutes — so this module enforces an explicit floor before a
key is ever handed to the verifier: ``kty`` ∈ {RSA, EC}; RSA modulus ≥ 2048 bits; EC curve ∈
{P-256, P-384}; ``use`` (if present) == ``sig``; ``key_ops`` (if present) contains ``verify``;
``alg`` (if present) names a supported JWS algorithm that fits the key; and a JWKS is **refused**
if two usable keys share a ``kid`` (take-the-first is an attacker's lever).

A key's ``alg`` is kept beside it (BACKLOG #5517): :meth:`JwksCache.get_key` refuses a token whose
``alg`` differs from the one the key is restricted to, so an IdP's restriction is not dropped. A
key naming an algorithm the engine does not verify (an encryption algorithm such as ``RSA-OAEP``
included) is skipped like any other key below the floor, so a JWKS of only such keys yields no
usable key and is refused.

**No network here by construction.** :class:`JwksCache` takes a ``fetch`` callable; production wiring
supplies one built on a hardened, CA-pinned opener, and tests supply an in-memory counter. The cache
enforces a **global monotonic min-refetch floor**, so an ``id_token`` bearing an unknown ``kid`` can
trigger at most one upstream fetch per ``min_refetch_seconds`` — an unauthenticated caller cannot
amplify into a fetch storm against the IdP.
"""

from __future__ import annotations

import base64
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import ec, rsa

from messagefoundry.config.models import SignatureAlgorithm
from messagefoundry.redaction import json_loads_or_refusal
from messagefoundry.transports.signing import (
    SigningError,
    _PublicKey,  # verify-path public-key union
    require_public_key_for_alg,
)

# ADR 0142 key-material floor. RSA below 2048 bits is forgeable; the JOSE curves we verify are the two
# the signer already supports (ES256/ES384).
_MIN_RSA_BITS = 2048
_JOSE_CURVES: dict[str, Callable[[], ec.EllipticCurve]] = {
    "P-256": ec.SECP256R1,
    "P-384": ec.SECP384R1,
}

DEFAULT_JWKS_TTL_SECONDS = 3600.0
DEFAULT_JWKS_MIN_REFETCH_SECONDS = 300.0
# A JWKS document larger than this is refused unread — a defensive bound on a remote body the engine
# fetches on an unauthenticated caller's behalf.
_MAX_JWKS_BYTES = 512 * 1024


class JwksError(ValueError):
    """A JWKS document or an individual JWK was malformed, unsupported, or below the key floor."""


class JwkAlgMismatch(JwksError):
    """The key a token's ``kid`` selects is restricted, by its JWK ``alg``, to an algorithm other
    than the one the token names (BACKLOG #5517). A refusal of the key, not a missing ``kid``."""


class JwksAmbiguousKid(JwksError):
    """The JWKS document gives two usable keys the same ``kid``, so the set is refused whole. A fault
    in the IdP's key set, not in the token. Raised by :func:`parse_jwks`, and by a
    :class:`JwksCache` lookup whose own fetch returned such a set; ``claims.py`` records that
    lookup's refusal as ``ambiguous_kid``."""


@dataclass(frozen=True, slots=True)
class _BoundKey:
    """One JWKS key and the algorithm its JWK ``alg`` restricts it to, ``None`` when it names none
    (``alg`` is OPTIONAL in RFC 7517 section 4.4)."""

    key: _PublicKey
    alg: SignatureAlgorithm | None


def _b64u_uint(value: str) -> int:
    """Decode a base64url JWK integer parameter (``n``/``e``/``x``/``y``) to a big-endian int."""
    if not isinstance(value, str) or value == "":
        raise JwksError("JWK integer parameter must be a non-empty base64url string")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as exc:
        raise JwksError("JWK integer parameter is not valid base64url") from exc
    if raw == b"":
        raise JwksError("JWK integer parameter decoded to empty")
    return int.from_bytes(raw, "big")


def _check_use_and_ops(jwk: dict[str, object]) -> None:
    """``use`` (if present) must be ``sig``; ``key_ops`` (if present) must permit ``verify``."""
    use = jwk.get("use")
    if use is not None and use != "sig":
        raise JwksError(f"JWK use={use!r} is not a signature key (expected 'sig')")
    key_ops = jwk.get("key_ops")
    if key_ops is not None and (not isinstance(key_ops, list) or "verify" not in key_ops):
        raise JwksError("JWK key_ops does not permit 'verify'")


def _jwk_alg(jwk: dict[str, object]) -> SignatureAlgorithm | None:
    """The algorithm ``jwk``'s ``alg`` restricts it to, or ``None`` when it names none. An ``alg``
    the engine does not verify, an encryption algorithm included, raises :class:`JwksError`."""
    alg = jwk.get("alg")
    if alg is None:
        return None
    if not isinstance(alg, str):
        raise JwksError("JWK alg must be a string")
    supported = sorted(a.value for a in SignatureAlgorithm)
    if alg not in supported:
        raise JwksError(
            f"JWK alg {alg[:32]!r} is not a supported signature algorithm "
            f"(expected one of {supported})"
        )
    return SignatureAlgorithm(alg)


def jwk_to_public_key(jwk: dict[str, object]) -> _PublicKey:
    """Build a verifying public key from one JWK, enforcing the ADR 0142 key-material floor.

    Raises :class:`JwksError` on anything below the floor — an unsupported ``kty``, an undersized RSA
    modulus, an unknown EC curve, a ``use``/``key_ops`` that forbids verification, or an ``alg``
    that is not a supported signature algorithm or does not fit the key (BACKLOG #5517).
    """
    return _bound_key(jwk).key


def _bound_key(jwk: dict[str, object]) -> _BoundKey:
    """:func:`jwk_to_public_key`, keeping the algorithm the JWK restricts the key to."""
    _check_use_and_ops(jwk)
    alg = _jwk_alg(jwk)
    key = _floor_key(jwk)
    if alg is not None:
        try:
            require_public_key_for_alg(key, alg)
        except SigningError as exc:
            raise JwksError(f"JWK alg does not fit its key: {exc}") from exc
    return _BoundKey(key, alg)


def _floor_key(jwk: dict[str, object]) -> _PublicKey:
    """The key ``jwk`` holds, by ``kty``, enforcing the key-material floor."""
    kty = jwk.get("kty")
    if kty == "RSA":
        n = _b64u_uint(_require_str(jwk, "n"))
        e = _b64u_uint(_require_str(jwk, "e"))
        if n.bit_length() < _MIN_RSA_BITS:
            raise JwksError(
                f"RSA key is {n.bit_length()} bits; the floor is {_MIN_RSA_BITS} "
                "(a smaller modulus is forgeable)"
            )
        return rsa.RSAPublicNumbers(e, n).public_key()
    if kty == "EC":
        crv = jwk.get("crv")
        if not isinstance(crv, str) or crv not in _JOSE_CURVES:
            raise JwksError(
                f"unsupported EC curve {crv!r} (expected one of {sorted(_JOSE_CURVES)})"
            )
        x = _b64u_uint(_require_str(jwk, "x"))
        y = _b64u_uint(_require_str(jwk, "y"))
        curve = _JOSE_CURVES[crv]()
        return ec.EllipticCurvePublicNumbers(x, y, curve).public_key()
    raise JwksError(f"unsupported JWK kty {kty!r} (expected 'RSA' or 'EC')")


def _require_str(jwk: dict[str, object], field: str) -> str:
    value = jwk.get(field)
    if not isinstance(value, str):
        raise JwksError(f"JWK is missing the required string field {field!r}")
    return value


def parse_jwks(body: bytes) -> dict[str, _PublicKey]:
    """Parse a JWKS document into ``{kid: public_key}``, applying the floor to each key.

    A key with **no** ``kid`` is skipped (the RP selects by ``kid``, so an unlabelled key is
    unusable), but a ``kid`` two usable keys share is a hard :class:`JwksError` — silently taking
    the first of two same-``kid`` keys is a downgrade lever. Keys the floor rejects are skipped, so one rolled-in
    weak key does not blank the whole set — unless it leaves nothing usable, which raises.
    """
    return {kid: bound.key for kid, bound in _parse_bound(body).items()}


def _parse_bound(body: bytes) -> dict[str, _BoundKey]:
    """:func:`parse_jwks`, keeping the algorithm each JWK restricts its key to (BACKLOG #5517)."""
    # Returns rather than raises, so the refusal carries no chain holding the body (BACKLOG #2085),
    # and json's depth-limit RecursionError is a JwksError rather than an unaudited 500.
    doc, refused = json_loads_or_refusal(body)
    if refused is not None:
        raise JwksError("JWKS body is not valid JSON")
    if not isinstance(doc, dict) or not isinstance(doc.get("keys"), list):
        raise JwksError("JWKS must be an object with a 'keys' array")

    keys: dict[str, _BoundKey] = {}
    skipped = 0
    for entry in doc["keys"]:
        if not isinstance(entry, dict):
            skipped += 1
            continue
        kid = entry.get("kid")
        if not isinstance(kid, str) or kid == "":
            skipped += 1  # unlabelled → unusable by kid
            continue
        try:
            bound = _bound_key(entry)
        except (JwksError, ValueError):
            # ValueError as well as JwksError: the floor's own checks raise JwksError, but the final
            # construction step in `cryptography` (RSAPublicNumbers/EllipticCurvePublicNumbers
            # .public_key()) raises a bare ValueError for a structurally invalid key — an off-curve
            # EC point, an even RSA exponent. Catching only JwksError let one such key abort the
            # whole parse, blanking the set AND (via the cache's already-stamped fetch attempt)
            # refusing every federated login until the min-refetch floor elapsed.
            skipped += 1  # a single weak/unsupported key must not blank the set
            continue
        # Checked among the USABLE keys only, after the floor, so the answer does not depend on
        # key order: a skipped key (an encryption key sharing a signing key's kid, say) is never a
        # second candidate, before or after the usable one (BACKLOG #5517).
        if kid in keys:
            raise JwksAmbiguousKid(f"JWKS contains two keys with kid {kid!r} (ambiguous; refused)")
        keys[kid] = bound
    if not keys:
        raise JwksError(f"JWKS yielded no usable signing keys ({skipped} skipped)")
    return keys


@dataclass(slots=True)
class _CacheState:
    keys: dict[str, _BoundKey]
    fetched_at: float


class JwksCache:
    """A bounded, TTL'd key cache with a global min-refetch floor (ADR 0142).

    ``fetch`` is injected — this class opens no socket. It returns the raw JWKS bytes for the
    configured URI; production wiring builds it on a hardened, CA-pinned opener.

    Lookup semantics:

    * a cached key for the ``kid`` within the TTL is returned without any fetch;
    * a miss (unknown ``kid``, or the TTL has expired) triggers **at most one** fetch per
      ``min_refetch_seconds``, globally — the amplification bound — after which an unknown ``kid``
      simply raises :class:`JwksError` until the floor elapses;
    * a fetch that fails leaves the previous good keys in place (fail-static within the TTL).
    """

    def __init__(
        self,
        fetch: Callable[[], bytes],
        *,
        ttl_seconds: float = DEFAULT_JWKS_TTL_SECONDS,
        min_refetch_seconds: float = DEFAULT_JWKS_MIN_REFETCH_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._fetch = fetch
        self._ttl = ttl_seconds
        self._min_refetch = min_refetch_seconds
        self._clock = clock
        self._state: _CacheState | None = None
        self._last_fetch_attempt: float | None = None
        #: GUARDS THE WHOLE OF ``get_key``, INCLUDING ITS FAST PATH, AND THE FAST PATH IS THE
        #: NON-OBVIOUS HALF. ``_refresh`` arms the refetch floor BEFORE it publishes the parsed
        #: keys, so between those two writes the cache advertises "already fetching" while still
        #: holding nothing. A concurrent reader in that window finds no keys AND is refused a
        #: fetch, and raises. Locking only the miss path would not close it: the hazard is the
        #: ORDER the two attributes become visible in, not a torn read of either.
        #:
        #: A blocking lock is safe here because ``get_key`` never runs on the event loop. Its one
        #: caller outside this module is ``claims.py`` ``get_key(kid, alg=alg)``, reached from
        #: ``service.py``'s ``_exchange_and_validate``, which the caller runs under
        #: ``asyncio.to_thread``. Verified by search, not assumed.
        self._gate = threading.Lock()

    def _may_fetch(self, now: float) -> bool:
        return (
            self._last_fetch_attempt is None or now - self._last_fetch_attempt >= self._min_refetch
        )

    def _refresh(self, now: float) -> None:
        self._last_fetch_attempt = now
        body = self._fetch()
        if len(body) > _MAX_JWKS_BYTES:
            raise JwksError(f"JWKS body exceeds the {_MAX_JWKS_BYTES}-byte bound")
        self._state = _CacheState(keys=_parse_bound(body), fetched_at=now)

    def get_key(self, kid: str, *, alg: SignatureAlgorithm) -> _PublicKey:
        """Return the verifying key for ``kid``, refetching within the amplification bound on a miss.

        ``alg`` is the algorithm the token names. A key whose JWK restricts it to another algorithm
        raises :class:`JwkAlgMismatch` (BACKLOG #5517). A key whose JWK names none is returned, and
        the caller still checks that it fits ``alg``.

        Raises :class:`JwksError` in at least these cases: the key is unknown and the min-refetch
        floor has not elapsed; a forced refetch still does not yield the ``kid``; or a refetch, for
        an unknown ``kid`` or a cached one past its TTL, returns a body the parse refuses. That last
        is :class:`JwksAmbiguousKid` when the set gives two usable keys one ``kid``.
        """
        bound = self._lookup(kid)
        if bound.alg is not None and bound.alg != alg:
            raise JwkAlgMismatch(
                f"kid {kid!r} is restricted to {bound.alg.value}; the token names {alg.value}"
            )
        return bound.key

    def _lookup(self, kid: str) -> _BoundKey:
        """The cached or refetched key for ``kid``, under the gate ``__init__`` describes."""
        with self._gate:
            now = self._clock()
            state = self._state
            fresh = state is not None and now - state.fetched_at < self._ttl
            if state is not None and fresh and kid in state.keys:
                return state.keys[kid]

            if not self._may_fetch(now):
                # Serve a still-cached key even past the soft TTL rather than fail while throttled...
                if state is not None and kid in state.keys:
                    return state.keys[kid]
                raise JwksError(
                    f"no key for kid {kid!r}; JWKS refetch is throttled "
                    f"(min {self._min_refetch:.0f}s between fetches)"
                )
            self._refresh(now)
            assert self._state is not None  # _refresh sets it or raises
            if kid not in self._state.keys:
                raise JwksError(f"kid {kid!r} not present in the JWKS after refetch")
            return self._state.keys[kid]
