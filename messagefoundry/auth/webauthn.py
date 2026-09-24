# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""WebAuthn/FIDO2 passkeys — the browser second factor (WP-14b, ADR 0068; BACKLOG #11).

Pure ceremony layer over the ``webauthn`` library (duo-labs/py_webauthn — an optional
``[webauthn]`` extra, lazy-imported so extra-less installs still import this module): no FastAPI,
no store access, no session knowledge (CLAUDE.md §3 — the HTTP/cookie surface lives in ``api/``,
the persistence in ``store/``, both driven by ``auth/service.py``).

Ceremony **challenges are minted first-party** (``secrets.token_bytes(64)``) and passed as the
explicit ``challenge=`` kwarg — a real crypto call site, registered in
``scripts/security/crypto_inventory_check.py`` (ASVS 11.1.3) and documented in
``docs/ASVS-L2-PHASE0-CHANGES.md`` §4 (first-party evidence for ASVS 6.7.2). They live in
a bounded, TTL'd, process-local :class:`ChallengeCache` (the rate-limiter precedent — single API
process is structural; ADR 0068 records the store-backed table as the multi-node upgrade path).

Policy pins (ADR 0068 §1/§6): ``attestation=NONE`` (passkey norm — no attestation certificates are
requested or stored, keeping ASVS 6.7.1 N/A), ``user_verification=PREFERRED`` (the knowledge
factor is the password that accompanies every step-up; ``REQUIRED`` would brick PIN-less U2F keys
for no factor gain), and the credential algorithm set (:data:`SUPPORTED_COSE_ALGS`).
"""

from __future__ import annotations

import json
import logging
import secrets
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # the [webauthn] extra is optional — the runtime import is lazy, per-call
    from webauthn.helpers.cose import COSEAlgorithmIdentifier

_log = logging.getLogger(__name__)

CHALLENGE_BYTES = 64
CHALLENGE_TTL_SECONDS = 120.0
PER_USER_PENDING_CAP = 16
GLOBAL_PENDING_CAP = 4096

#: The COSE algorithm identifiers (IANA COSE Algorithms registry) this relying party will register:
#: EdDSA and ES256. Deliberately NARROWER than py_webauthn's default set, which also carries RS256
#: (-257) — ASVS 11.2.3 asks every primitive for at least 128 bits of security, and an RSA
#: identifier cannot promise that. ``-257`` fixes the padding and the hash and leaves the MODULUS
#: unbounded, so an authenticator answers it with whatever size it holds. Measured against this
#: module before the restriction landed (BACKLOG #1166): RS256 over a 2048-bit modulus registered
#: and was accepted, and so did RS256 over a **1024**-bit one.
#:
#: EdDSA (-8) and ES256 (-7) carry no equivalent hole. The curve rides in the credential rather
#: than in the identifier, but a credential whose curve is unknown or does not match its key cannot
#: produce a verifiable assertion, so no sub-floor EC2 or OKP credential is ever usable. Such a
#: credential used to register and then fail at every assertion; :func:`_require_usable_public_key`
#: now refuses it at registration. That is the property the RSA identifier cannot offer, and it is
#: why the floor can be expressed here as a set of identifiers.
#:
#: **Stated rather than hidden: this refuses an authenticator that offers only RS256.** TPM-backed
#: Windows Hello is the population that registers RSA credentials. Those operators keep TOTP, which
#: ADR 0068's 2026-07-17 amendment already records as the alternative second factor. It is NOT an
#: operator setting on purpose: a knob that re-admits -257 would be exactly the operator-supplied
#: weak configuration this requirement is failing on.
#:
#: Plain ints so this module still imports without the extra; :func:`_supported_pub_key_algs`
#: resolves them to the library enum at call time.
SUPPORTED_COSE_ALGS: tuple[int, ...] = (-8, -7)

#: The COSE key type and curve (IANA COSE Key Types and Elliptic Curves registries) each pinned
#: identifier must arrive in: EdDSA as OKP (1) on Ed25519 (6), ES256 as EC2 (2) on P-256 (1).
#: The library screens the IDENTIFIER at registration and never checks that the key beside it is
#: the kind that identifier signs with, so an EdDSA-labelled EC2 key used to enrol and then fail
#: at every assertion. A test pins that every entry of :data:`SUPPORTED_COSE_ALGS` has a row here,
#: so widening the set forces a decision about it.
#:
#: **ES256 is bound to P-256 by owner ruling 2026-09-23** (BACKLOG #1166). ES256 on P-384 or
#: P-521 verifies and clears the 128-bit floor, so this is not a strength control. It is the
#: pairing RFC 9053 section 2.1 recommends for interoperability (SHA-256 with P-256 only), and
#: the one the WebAuthn specification describes for -7. Registration only: see
#: :func:`verify_assertion` for why a stored key is not re-screened.
_COSE_KEY_SHAPE_FOR_ALG: dict[int, tuple[int, int]] = {-8: (1, 6), -7: (2, 1)}

_INSTALL_HINT = (
    "WebAuthn support requires the [webauthn] extra: pip install messagefoundry[webauthn]"
)


def available() -> bool:
    """True when the optional ``webauthn`` library is importable.

    The UI hides the passkey surface (a message, never a crash) on extra-less installs; the
    startup advisory for *enrolled-credentials-without-extra* lives in ``__main__.py`` (ADR 0068).
    """
    try:
        import webauthn  # noqa: F401
    except ImportError:
        return False
    return True


def _require_webauthn() -> None:
    try:
        import webauthn  # noqa: F401
    except ImportError as exc:  # pragma: no cover - exercised via monkeypatched raiser in tests
        raise RuntimeError(_INSTALL_HINT) from exc


class WebAuthnVerificationError(ValueError):
    """A registration/assertion response failed verification (invalid input, never a bug)."""


class ChallengeCacheFullError(RuntimeError):
    """The global pending-ceremony safety bound was hit — new ceremonies are refused.

    Reachable only via mass account provisioning (per-user caps confine ordinary abuse to
    self-eviction); ``admin_reset_mfa`` remains the always-available recovery (ADR 0068 §2).
    """


def _supported_pub_key_algs() -> list[COSEAlgorithmIdentifier]:
    """Resolve :data:`SUPPORTED_COSE_ALGS` to the library enum (lazy — the extra is optional).

    Both ceremony halves call this, so the set the relying party ADVERTISES and the set it ACCEPTS
    cannot drift apart. That is the whole control: advertisement is a hint an authenticator may
    ignore, and ``verify_registration_response`` is the only place a credential is refused.
    """
    from webauthn.helpers.cose import COSEAlgorithmIdentifier

    return [COSEAlgorithmIdentifier(alg) for alg in SUPPORTED_COSE_ALGS]


def _invalid_input_errors() -> tuple[type[Exception], ...]:
    """Every exception py_webauthn raises for bad input, which must all reach the audited path.

    ``WebAuthnException`` is the library's own base class. The other three entries catch four raw
    exception types (``LookupError`` covers both ``KeyError`` and ``IndexError``) that it lets
    out when a COSE key is malformed rather than merely wrong: its key decoder indexes an
    untyped CBOR value, so a missing label is a ``KeyError``, a short array an ``IndexError``, a
    bare integer a ``TypeError``, and a point that is not on its stated curve a ``ValueError`` from
    ``cryptography``. Measured at engine ``0076e3cec`` on the pinned ``webauthn==3.0.0`` (BACKLOG
    #1166). Each is attacker-shaped input, so each must land on the audited invalid-input path ADR
    0068 decision 1 requires rather than escape as a 500. Use it only around library calls, never
    around our own logic, where the same exceptions would mean a bug.

    A function rather than a constant because the library import is lazy (the extra is optional).
    """
    from webauthn.helpers.exceptions import WebAuthnException

    return (WebAuthnException, LookupError, TypeError, ValueError)


def _refusal(exc: Exception, *, ceremony: str) -> WebAuthnVerificationError:
    """Turn a caught library exception into the audited refusal, and log the raw ones.

    A ``WebAuthnException`` is the library refusing input on purpose, and the service audits it.
    A raw exception is the library falling over, which is expected for a malformed key but is
    ALSO what a defect on our side looks like, for example a store handing back a NULL sign
    count. Before BACKLOG #1166 that was a loud 500; widening the catch would have made it
    silent. So the exception TYPE is logged at WARNING. Only the type: the message can quote
    input, and nothing from a ceremony response belongs in the general log.
    """
    from webauthn.helpers.exceptions import WebAuthnException

    if not isinstance(exc, WebAuthnException):
        _log.warning(
            "WebAuthn %s refused on a raw %s from the library, treated as invalid input",
            ceremony,
            type(exc).__name__,
        )
    return WebAuthnVerificationError(str(exc))


def _require_usable_public_key(cose_key: bytes) -> None:
    """Refuse a credential public key that no assertion could ever verify against.

    Runs the SAME decode and key construction the assertion path runs, so a credential that passes
    here cannot fail there for a reason its key alone decides. Before this check a credential whose
    curve was unknown, whose point was not on its stated curve, or whose key type did not match its
    identifier ENROLLED, and was found out only at first use (BACKLOG #1166). No sub-floor key ever
    became usable, but the refusal came late, and on the mismatched-curve path it came as a raw
    ``ValueError`` that escaped as a 500.

    It also binds each identifier to one key type and curve (:data:`_COSE_KEY_SHAPE_FOR_ALG`),
    so an ES256 credential on P-384 or P-521 is refused here although it would verify. That is
    the owner's 2026-09-23 ruling, and it is a deliberate refusal, so it is not logged.
    """
    from webauthn.helpers import decode_credential_public_key, decoded_public_key_to_cryptography

    try:
        decoded = decode_credential_public_key(cose_key)
        decoded_public_key_to_cryptography(decoded)
        alg, kty = int(decoded.alg), int(decoded.kty)
        crv = getattr(decoded, "crv", None)
        shape = (kty, None if crv is None else int(crv))
    except _invalid_input_errors() as exc:
        raise _refusal(exc, ceremony="registration") from exc
    if _COSE_KEY_SHAPE_FOR_ALG.get(alg) != shape:
        raise WebAuthnVerificationError(
            f"COSE algorithm {alg} is accepted only as key type and curve "
            f"{_COSE_KEY_SHAPE_FOR_ALG.get(alg)}, not {shape}"
        )


def new_challenge() -> bytes:
    """Mint a first-party 64-byte ceremony challenge (single-use, cached with a TTL)."""
    return secrets.token_bytes(CHALLENGE_BYTES)


@dataclass(frozen=True, slots=True)
class PendingCeremony:
    """One staged ceremony: the challenge, its owner, and its monotonic expiry."""

    challenge: bytes
    user_id: str
    deadline: float


class ChallengeCache:
    """Bounded, TTL'd, process-local staging for in-flight ceremony challenges.

    Key = ``(session token-hash, kind)`` — the *service* computes the token hash and passes it in
    (this module never sees a session token), so the cache is only ever fed by authenticated
    traffic. Semantics (ADR 0068 §2): starting a new ceremony overwrites that session's pending
    one; entries expire after ``ttl_seconds`` (``time.monotonic()`` — wall-clock steps can't widen
    the window); a user at their pending cap evicts **their own oldest** entry (self-harm only —
    one principal can never deny another's ceremonies); the global safety bound refuses new
    ceremonies with a cause-naming error.
    """

    def __init__(
        self,
        *,
        ttl_seconds: float = CHALLENGE_TTL_SECONDS,
        per_user_cap: int = PER_USER_PENDING_CAP,
        global_cap: int = GLOBAL_PENDING_CAP,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._ttl = ttl_seconds
        self._per_user_cap = per_user_cap
        self._global_cap = global_cap
        self._clock = clock
        self._entries: dict[tuple[str, str], PendingCeremony] = {}

    def _prune(self, now: float) -> None:
        expired = [k for k, e in self._entries.items() if e.deadline <= now]
        for k in expired:
            del self._entries[k]

    def put(self, key: tuple[str, str], user_id: str, challenge: bytes) -> None:
        """Stage ``challenge`` for ``key``, enforcing the per-user and global bounds."""
        now = self._clock()
        self._prune(now)
        if key not in self._entries:
            mine = [(k, e) for k, e in self._entries.items() if e.user_id == user_id]
            if len(mine) >= self._per_user_cap:
                # Evict this user's own oldest pending ceremony — never another principal's.
                oldest = min(mine, key=lambda item: item[1].deadline)
                del self._entries[oldest[0]]
            elif len(self._entries) >= self._global_cap:
                raise ChallengeCacheFullError(
                    "WebAuthn ceremony refused: the engine-wide pending-ceremony safety bound "
                    f"({self._global_cap}) is full. Retry shortly; if this persists, investigate "
                    "mass ceremony traffic (admin_reset_mfa remains available for recovery)."
                )
        self._entries[key] = PendingCeremony(challenge, user_id, now + self._ttl)

    def pop(self, key: tuple[str, str]) -> PendingCeremony | None:
        """Consume the pending ceremony for ``key`` (single-use); None if absent or expired."""
        entry = self._entries.pop(key, None)
        if entry is None or entry.deadline <= self._clock():
            return None
        return entry

    def rekey(self, old_token_hash: str, new_token_hash: str) -> int:
        """Move every pending ceremony from one session token hash to another (ASVS 7.2.4).

        Ceremonies are keyed ``(token_hash, purpose)``. When a session is rotated mid-ceremony the
        store row is re-keyed atomically, but this cache is process-local — so without this move a
        registration or assertion started before the rotation could never be finished. That is a dead
        end for the user, not a retry: the challenge is single-use and the ceremony has to be
        restarted from the beginning.

        **Deadlines are carried, never refreshed** — a session rotation must not extend the TTL of an
        in-flight ceremony. Returns the number of entries moved (0 is the normal case).

        Public rather than a reach into the internals from ``AuthService``: the caller has no business
        knowing this cache is a dict keyed by tuples, and an attribute-level reach would break
        silently the day that changes.
        """
        moved = [(k, e) for k, e in self._entries.items() if k[0] == old_token_hash]
        for key, entry in moved:
            del self._entries[key]
            self._entries[(new_token_hash, key[1])] = entry
        return len(moved)


@dataclass(frozen=True, slots=True)
class RegistrationResult:
    """The verified outcome of a registration ceremony, decoupled from library types."""

    credential_id: bytes
    public_key: bytes
    sign_count: int
    transports: list[str] | None
    device_type: str
    backed_up: bool
    aaguid: str


def registration_options(
    *,
    rp_id: str,
    rp_name: str,
    user_id: str,
    user_name: str,
    challenge: bytes,
    exclude_credential_ids: Sequence[bytes] = (),
) -> str:
    """Build the browser ``navigator.credentials.create`` options as a JSON string.

    ``attestation=NONE``, ``user_verification=PREFERRED`` and :data:`SUPPORTED_COSE_ALGS` are
    pinned here (module docstring); ``exclude_credential_ids`` carries the user's existing
    credentials so re-registering the same authenticator is refused client-side.
    """
    _require_webauthn()
    from webauthn import generate_registration_options
    from webauthn.helpers import options_to_json
    from webauthn.helpers.structs import (
        AttestationConveyancePreference,
        AuthenticatorSelectionCriteria,
        PublicKeyCredentialDescriptor,
        UserVerificationRequirement,
    )

    options = generate_registration_options(
        rp_id=rp_id,
        rp_name=rp_name,
        user_id=user_id.encode("utf-8"),
        user_name=user_name,
        challenge=challenge,
        attestation=AttestationConveyancePreference.NONE,
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.PREFERRED
        ),
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=cid) for cid in exclude_credential_ids
        ],
        supported_pub_key_algs=_supported_pub_key_algs(),
    )
    return options_to_json(options)


def verify_registration(
    *, response_json: str, challenge: bytes, rp_id: str, origin: str
) -> RegistrationResult:
    """Verify an attestation response against the staged challenge; raise on any invalid input.

    **This is where :data:`SUPPORTED_COSE_ALGS` is enforced**, not merely advertised: an
    authenticator that answers with an identifier outside the set is refused here, and a refusal
    lands on the same audited invalid-input path as any other bad response. So does a credential
    whose key no assertion could verify against (:func:`_require_usable_public_key`).

    ``transports`` ride ``RegistrationCredential.response.transports`` (struct path verified
    against webauthn 3.0.0 at build time per ADR 0068's open item) — extracted defensively from
    the raw JSON so a shape drift degrades to ``None``, never a crash.
    """
    _require_webauthn()
    from webauthn import verify_registration_response

    try:
        verified = verify_registration_response(
            credential=response_json,
            expected_challenge=challenge,
            expected_rp_id=rp_id,
            expected_origin=origin,
            supported_pub_key_algs=_supported_pub_key_algs(),
        )
    except _invalid_input_errors() as exc:
        # The BASE class, deliberately (PR-A review HIGH): structurally-malformed browser input
        # raises siblings of InvalidRegistrationResponse (InvalidJSONStructure, InvalidCBORData,
        # ...) — every library-side rejection must land on the audited return-False/400 path,
        # never an unhandled 500. The raw decode errors join it for the same reason (BACKLOG
        # #1166): a malformed COSE key raised them straight out of this call.
        raise _refusal(exc, ceremony="registration") from exc
    _require_usable_public_key(verified.credential_public_key)
    return RegistrationResult(
        credential_id=verified.credential_id,
        public_key=verified.credential_public_key,
        sign_count=verified.sign_count,
        transports=_transports_from_response(response_json),
        device_type=verified.credential_device_type.value,
        backed_up=verified.credential_backed_up,
        aaguid=verified.aaguid,
    )


def assertion_options(
    *, rp_id: str, challenge: bytes, allow_credential_ids: Sequence[bytes]
) -> str:
    """Build the browser ``navigator.credentials.get`` options as a JSON string."""
    _require_webauthn()
    from webauthn import generate_authentication_options
    from webauthn.helpers import options_to_json
    from webauthn.helpers.structs import (
        PublicKeyCredentialDescriptor,
        UserVerificationRequirement,
    )

    options = generate_authentication_options(
        rp_id=rp_id,
        challenge=challenge,
        allow_credentials=[PublicKeyCredentialDescriptor(id=cid) for cid in allow_credential_ids],
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    return options_to_json(options)


def verify_assertion(
    *,
    response_json: str,
    challenge: bytes,
    rp_id: str,
    origin: str,
    public_key: bytes,
    current_sign_count: int,
) -> int:
    """Verify an assertion; return the authenticator's new sign count.

    py_webauthn enforces counter increment only when both counts are >0 (synced-passkey 0/0 is
    accepted); the *service* layer applies the strict compare-and-set on top (a CAS miss is the
    clone signal — ADR 0068 §4).

    The stored key is deliberately NOT re-screened against :data:`_COSE_KEY_SHAPE_FOR_ALG`. A key
    enrolled before the 2026-09-23 P-256 pin may be ES256 on P-384 or P-521. It still verifies
    and still clears the floor, so refusing it here would lock its owner out for no security
    gain. A key that cannot verify still fails here, as invalid input.
    """
    _require_webauthn()
    from webauthn import verify_authentication_response

    try:
        verified = verify_authentication_response(
            credential=response_json,
            expected_challenge=challenge,
            expected_rp_id=rp_id,
            expected_origin=origin,
            credential_public_key=public_key,
            credential_current_sign_count=current_sign_count,
        )
    except _invalid_input_errors() as exc:
        # The BASE class, deliberately (PR-A review HIGH): malformed input raises siblings of
        # InvalidAuthenticationResponse — every rejection lands audited, never a 500. The
        # sign-count regression message ("...sign count...") still rides through for the
        # service's clone-signal classification. The raw decode errors are the backstop for a
        # STORED key registration would now refuse (BACKLOG #1166): one enrolled before that check,
        # or damaged since, decodes here and used to escape as a raw ValueError or KeyError.
        raise _refusal(exc, ceremony="assertion") from exc
    return verified.new_sign_count


def credential_id_from_response(response_json: str) -> bytes:
    """Extract the raw credential id from a ceremony response (for the service's hash lookup).

    Raises :class:`WebAuthnVerificationError` on malformed input — the caller treats it exactly
    like a failed verification (invalid input, audited, never a 500).
    """
    _require_webauthn()
    from webauthn.helpers import base64url_to_bytes

    try:
        parsed = json.loads(response_json)
        raw_id = parsed["rawId"] if isinstance(parsed, dict) else None
        if not isinstance(raw_id, str) or not raw_id:
            raise WebAuthnVerificationError("ceremony response has no rawId")
        return base64url_to_bytes(raw_id)
    except (ValueError, KeyError, TypeError) as exc:
        if isinstance(exc, WebAuthnVerificationError):
            raise
        raise WebAuthnVerificationError("malformed ceremony response") from exc


def _transports_from_response(response_json: str) -> list[str] | None:
    """Best-effort ``response.transports`` extraction (browser hint — absence is fine)."""
    try:
        parsed = json.loads(response_json)
        transports = parsed.get("response", {}).get("transports")
    except (ValueError, AttributeError):  # pragma: no cover - verify_registration already parsed
        return None
    if isinstance(transports, list) and all(isinstance(t, str) for t in transports):
        return list(transports) or None
    return None
