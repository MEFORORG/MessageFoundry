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
import math
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from cryptography.hazmat.primitives.asymmetric import ec, rsa

from messagefoundry.config.models import SignatureAlgorithm
from messagefoundry.redaction import json_loads_or_refusal
from messagefoundry.transports.base import float_setting
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
#: The JWKS fetch timeout. ``oidc_http`` names it ``DEFAULT_IDP_TIMEOUT_SECONDS`` and passes it to
#: urllib, where it bounds each socket operation of a fetch, not the fetch as a whole and not
#: host-name resolution, so a refresh can run longer than this. The token endpoint leg does not use
#: it: ``flow.exchange_code`` keeps its own 10 s default.
IDP_TIMEOUT_SECONDS = 10.0
#: How long a lookup waits for the gate a refresh holds across its fetch before it is refused
#: (BACKLOG #6905): the IdP timeout, so a hung IdP degrades the login rather than pinning each
#: waiting lookup for as long as the fetch runs. It bounds the WAIT, not the refresh. A waiter whose
#: wait runs out is refused even if that refresh later fails and leaves the old keys in place. It
#: also bounds how long a key within its TTL is served past the start of a refresh in flight.
DEFAULT_JWKS_GATE_WAIT_SECONDS = IDP_TIMEOUT_SECONDS
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


class JwksRefreshBusy(JwksError):
    """A :class:`JwksCache` lookup waited the whole ``gate_wait_seconds`` for a refresh in progress,
    and its read of the published keys after the wait served no key: its ``kid`` had no key within
    the TTL, :meth:`JwksCache._may_skip_gate` did not allow the read, or the published snapshot
    changed under it (BACKLOG #6905). A slow or stalled IdP, not a fault in the
    token; ``claims.py`` records the refusal as ``jwks_refresh_busy``, never ``unknown_kid``."""


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


@dataclass(frozen=True, slots=True)
class _CacheState:
    """One published key set. Never mutated, only replaced whole, which is what lets
    :meth:`JwksCache._lookup` read it without the gate (BACKLOG #6905). ``keys`` is a read-only view,
    so the "never mutated" half holds at run time and not only in the type."""

    keys: Mapping[str, _BoundKey]
    fetched_at: float


def _require_interval(name: str, value: float) -> float:
    """``value`` as an int or a finite float, or :class:`ValueError` (BACKLOG #6904).

    Only what the settings can never produce is refused: a NaN or an infinity, a bool, text, or any
    other type. Every comparison against NaN is false, so a NaN floor refuses every refetch after
    the first and wedges key rotation for good, as an infinite floor does. Any int stays legal and
    behaves as it always has, a negative one included: ``min_refetch_seconds`` of ``0`` or less
    removes the amplification bound, a choice the security-loosening report names. Range limits are
    the settings layer's to set, where the operator sees them at load. The refusal withholds the
    value.
    """
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ValueError(f"JwksCache {name} must be an int or a float (value withheld)")
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError(f"JwksCache {name} must be finite (value withheld)")
    return value


def _require_gate_wait(value: float) -> float:
    """``value`` as a gate wait above 0 and at most ``threading.TIMEOUT_MAX``, or
    :class:`ValueError` (BACKLOG #6905). Zero would refuse every lookup that meets a refresh in
    progress, and ``Lock.acquire`` raises ``OverflowError`` past ``TIMEOUT_MAX``."""
    if isinstance(value, str):
        raise ValueError("JwksCache gate_wait_seconds must be a number, not text (value withheld)")
    seconds = float_setting(value, knob="gate_wait_seconds", transport="JwksCache")
    if not 0 < seconds <= threading.TIMEOUT_MAX:
        raise ValueError(
            "JwksCache gate_wait_seconds must be above 0 and at most threading.TIMEOUT_MAX "
            "(value withheld)"
        )
    return seconds


class JwksCache:
    """A bounded, TTL'd key cache with a global min-refetch floor (ADR 0142).

    ``fetch`` is injected — this class opens no socket. It returns the raw JWKS bytes for the
    configured URI; production wiring builds it on a hardened, CA-pinned opener.

    Lookup semantics:

    * a cached key for the ``kid`` within the TTL is returned without any fetch, and without waiting
      on a fetch another caller has in progress while that fetch is younger than
      ``gate_wait_seconds``. Past that age it waits like a miss, so a key a stalled refresh would
      withdraw stops verifying once that much time has passed (BACKLOG #6905);
    * a miss (unknown ``kid``, or the TTL has expired) triggers **at most one** fetch per
      ``min_refetch_seconds``, globally — the amplification bound — after which an unknown ``kid``
      simply raises :class:`JwksError` until the floor elapses. A miss that arrives while a fetch
      is in progress waits for the gate that fetch holds, at most ``gate_wait_seconds``. If it gets
      the gate it decides again against the keys it finds: the new ones, or on a failed fetch the
      old ones. If its wait runs out first, it reads the published keys once more, and a key within
      the TTL is served only if :meth:`_may_skip_gate` allows and the published snapshot is still
      the one it read. Otherwise it is refused with :class:`JwksRefreshBusy`, even if that fetch
      later fails and leaves the old keys in place. A key past the TTL is never served instead
      (BACKLOG #6905). The wait is bounded; the fetch is bounded only per socket operation;
    * a fetch that fails leaves the previous good keys in place (fail-static within the TTL).

    ``ttl_seconds`` and ``min_refetch_seconds`` must be an int or a finite float, and
    ``gate_wait_seconds`` a number above 0 and at most ``threading.TIMEOUT_MAX``, or construction
    raises :class:`ValueError` (BACKLOG #6904).
    """

    def __init__(
        self,
        fetch: Callable[[], bytes],
        *,
        ttl_seconds: float = DEFAULT_JWKS_TTL_SECONDS,
        min_refetch_seconds: float = DEFAULT_JWKS_MIN_REFETCH_SECONDS,
        clock: Callable[[], float] = time.monotonic,
        gate_wait_seconds: float = DEFAULT_JWKS_GATE_WAIT_SECONDS,
    ) -> None:
        self._fetch = fetch
        self._ttl = _require_interval("ttl_seconds", ttl_seconds)
        self._min_refetch = _require_interval("min_refetch_seconds", min_refetch_seconds)
        self._gate_wait = _require_gate_wait(gate_wait_seconds)
        self._clock = clock
        self._state: _CacheState | None = None
        self._last_fetch_attempt: float | None = None
        #: When the refresh in flight began, on the real monotonic clock and not the injected one,
        #: because the gate wait it is compared with is real time; ``None`` while none runs. Written
        #: under the gate, read without it (BACKLOG #6905).
        self._refresh_started: float | None = None
        #: GUARDS THE MISS PATH, AND IS HELD ACROSS THE FETCH ON PURPOSE. ``_refresh`` arms the
        #: refetch floor BEFORE it publishes the parsed keys, so between those two writes the cache
        #: advertises "already fetching" while still holding nothing. A reader that saw the floor
        #: in that window would find no keys AND be refused a fetch, and raise. Every reader of the
        #: floor holds the gate, so it either queues behind the fetch or sees what it published,
        #: and concurrent misses cost the IdP one fetch.
        #:
        #: A LOOKUP OF A KEY WITHIN THE TTL DOES NOT TAKE IT (BACKLOG #6905). Taking it there made
        #: such a lookup sit out a stalled IdP. That read touches ``_state`` and
        #: ``_refresh_started``, never the floor, so the ordering hazard above does not reach it.
        #: ``_state`` is an immutable snapshot replaced in one assignment, so the read sees the old
        #: keys or the new ones, and it serves a key only if the snapshot it read is still the
        #: published one after it reads ``_refresh_started`` (``_read_without_gate``), so a refresh
        #: that publishes and clears that time between the two reads cannot get an older snapshot
        #: served. A key PAST the TTL still
        #: takes the gate, so it waits out a fetch in progress and is never served once that fetch
        #: has withdrawn it. Nor does a key within the TTL skip it once the refresh in flight is as
        #: old as the gate wait: the fetch has no overall bound, and skipping it for the whole of a
        #: stall would keep a key that refresh withdraws verifying for as long as the stall lasts.
        #:
        #: EVERY WAIT FOR IT IS BOUNDED, AND RUNNING OUT FAILS CLOSED (BACKLOG #6905). A stalled
        #: IdP otherwise pinned each waiting lookup, and the ``asyncio.to_thread`` worker under it,
        #: for as long as the fetch ran. ``DEFAULT_JWKS_GATE_WAIT_SECONDS`` says why 10 s. The
        #: lookup that holds it for the fetch is not bounded by that wait, only by the fetch's own
        #: per-socket-operation timeout.
        #:
        #: A blocking wait is safe here because ``get_key`` never runs on the event loop. Its one
        #: caller outside this module is ``claims.py`` ``get_key(kid, alg=alg)``, reached from
        #: ``service.py``'s ``_exchange_and_validate``, which the caller runs under
        #: ``asyncio.to_thread``. Verified by search, not assumed.
        self._gate = threading.Lock()

    def _may_fetch(self, now: float) -> bool:
        return (
            self._last_fetch_attempt is None or now - self._last_fetch_attempt >= self._min_refetch
        )

    def _refresh(self, now: float) -> _CacheState:
        self._last_fetch_attempt = now
        self._refresh_started = time.monotonic()
        try:
            body = self._fetch()
            if len(body) > _MAX_JWKS_BYTES:
                raise JwksError(f"JWKS body exceeds the {_MAX_JWKS_BYTES}-byte bound")
            state = _CacheState(keys=MappingProxyType(_parse_bound(body)), fetched_at=now)
            self._state = state
            return state
        finally:
            self._refresh_started = None

    def _may_skip_gate(self) -> bool:
        """Whether a key within its TTL may be served without the gate: no refresh is in flight, or
        the one in flight is younger than the gate wait (BACKLOG #6905)."""
        started = self._refresh_started
        return started is None or time.monotonic() - started < self._gate_wait

    def get_key(self, kid: str, *, alg: SignatureAlgorithm) -> _PublicKey:
        """Return the verifying key for ``kid``, refetching within the amplification bound on a miss.

        ``alg`` is the algorithm the token names. A key whose JWK restricts it to another algorithm
        raises :class:`JwkAlgMismatch` (BACKLOG #5517). A key whose JWK names none is returned, and
        the caller still checks that it fits ``alg``.

        Raises :class:`JwksError` in at least these cases: the key is unknown and the min-refetch
        floor has not elapsed; a forced refetch still does not yield the ``kid``; a refetch, for an
        unknown ``kid`` or a cached one past its TTL, returns a body the cache refuses (too large,
        not JSON, no usable key), which is :class:`JwksAmbiguousKid` when the set gives two usable
        keys one ``kid``; or the wait for a refresh in progress runs out before the ``kid`` is
        current, which is :class:`JwksRefreshBusy`. That last refusal can reach a cached key past
        its TTL, which the throttled path would otherwise serve (BACKLOG #6905).
        """
        bound = self._lookup(kid)
        if bound.alg is not None and bound.alg != alg:
            raise JwkAlgMismatch(
                f"kid {kid!r} is restricted to {bound.alg.value}; the token names {alg.value}"
            )
        return bound.key

    def _fresh(self, state: _CacheState | None, kid: str, now: float) -> _BoundKey | None:
        """``kid``'s key in ``state`` if ``state`` is within its TTL, else ``None``."""
        if state is None or now - state.fetched_at >= self._ttl:
            return None
        return state.keys.get(kid)

    def _read_without_gate(self, kid: str) -> _BoundKey | None:
        """``kid``'s key from the published snapshot, if it is within the TTL and
        :meth:`_may_skip_gate` allows, else ``None``. The snapshot must still be the published one
        after the skip check: a refresh that publishes and clears ``_refresh_started`` between the
        two reads would otherwise let a snapshot older than that refresh be served (BACKLOG #6905).
        """
        state = self._state
        bound = self._fresh(state, kid, self._clock())
        if bound is None or not self._may_skip_gate() or self._state is not state:
            return None
        return bound

    def _lookup(self, kid: str) -> _BoundKey:
        """The cached or refetched key for ``kid``. A key within the TTL is read without the gate
        while :meth:`_may_skip_gate` allows; every other lookup runs under it, as ``__init__``
        describes."""
        bound = self._read_without_gate(kid)
        if bound is not None:
            return bound

        if not self._gate.acquire(timeout=self._gate_wait):
            # The refresh may have published the kid as the wait ran out; one gate-free read of
            # what it published, never a key past the TTL, and on the same terms as the first read.
            bound = self._read_without_gate(kid)
            if bound is not None:
                return bound
            raise JwksRefreshBusy(
                f"kid {kid!r} could not be confirmed current; waited {self._gate_wait:g}s for a "
                "JWKS refresh in progress to release the cache"
            )
        try:
            return self._lookup_holding_gate(kid)
        finally:
            self._gate.release()

    def _lookup_holding_gate(self, kid: str) -> _BoundKey:
        now = self._clock()
        state = self._state
        bound = self._fresh(state, kid, now)
        if bound is not None:
            return bound

        if not self._may_fetch(now):
            # Serve a still-cached key even past the soft TTL rather than fail while throttled...
            stale = None if state is None else state.keys.get(kid)
            if stale is not None:
                return stale
            raise JwksError(
                f"no key for kid {kid!r}; JWKS refetch is throttled "
                f"(min {self._min_refetch:.0f}s between fetches)"
            )
        bound = self._refresh(now).keys.get(kid)
        if bound is None:
            raise JwksError(f"kid {kid!r} not present in the JWKS after refetch")
        return bound
