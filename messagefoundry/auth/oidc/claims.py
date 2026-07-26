# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The OIDC ``id_token`` claim-validation ladder (ADR 0142).

Given a compact ``id_token``, the pinned config, and a :class:`~messagefoundry.auth.oidc.jwks.JwksCache`,
this verifies the signature (via ``transports.signing.verify_compact_jws``) and then walks the OIDC
core claim checks — ``iss``, ``aud``/``azp``, ``exp``/``iat``/``nbf`` within a bounded skew, ``nonce``
— and finally the optional MFA-claim gate (``amr``/``acr``), which is BACKLOG #99(g)'s real control.

Every rejection is a :class:`ClaimsError` carrying a **closed-set reason slug** (:data:`REASONS`) — the
browser layer maps that slug to an allow-listed error code and audits it, never reflecting IdP text.
The engine verifies what the IdP **asserts**, cryptographically; it does not and cannot prove the IdP
*enforced* MFA. The success value is a :class:`FederatedPrincipal` carrying the resolved username,
``sub``, the evidence recorded in the audit, and the verified ``exp`` the engine session is capped at.
"""

from __future__ import annotations

import hmac
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field

from messagefoundry.auth.oidc.jwks import JwksCache, JwksError
from messagefoundry.config.models import SignatureAlgorithm
from messagefoundry.transports.signing import (
    SigningError,
    require_public_key_for_alg,
    unverified_jws_header,
    verify_compact_jws,
)

# Closed set of reject reasons. The browser layer refuses any slug not in here, so a new reason cannot
# silently reflect attacker/IdP-influenced text into a response or an audit row.
REASONS: frozenset[str] = frozenset(
    {
        "malformed_token",
        "malformed_payload",
        "claim_not_numeric",
        "unknown_kid",
        "ambiguous_kid",
        "key_rejected",
        "bad_signature",
        "claim_iss",
        "claim_aud",
        "claim_azp",
        "expired",
        "not_yet_valid",
        "issued_in_future",
        "nonce_mismatch",
        "mfa_claim_missing",
        "username_claim_missing",
        "username_domain_not_allowed",
    }
)


class ClaimsError(ValueError):
    """A verified-or-rejected ``id_token`` failed a rung. ``reason`` is always in :data:`REASONS`."""

    def __init__(self, reason: str, detail: str = "") -> None:
        if reason not in REASONS:
            raise AssertionError(f"reason {reason!r} is not in the closed REASONS set")
        self.reason = reason
        super().__init__(detail or reason)


@dataclass(frozen=True, slots=True)
class OidcClaimPolicy:
    """The pinned config the ladder checks against (a settings-free value, so the ladder is testable)."""

    issuer: str
    client_id: str
    signing_algorithms: Sequence[SignatureAlgorithm]
    nonce: str
    username_claim: str = "preferred_username"
    username_strip_domain: bool = True
    #: Lower-cased UPN suffixes the username claim may carry when ``username_strip_domain`` is on.
    #: Empty + stripping enabled means every login is refused — fail-closed by construction, so a
    #: caller that forgets to populate it cannot accidentally strip unchecked.
    allowed_username_domains: frozenset[str] = frozenset()
    require_mfa_claim: bool = True
    mfa_amr_values: Sequence[str] = field(default_factory=lambda: ("mfa",))
    required_acr_values: Sequence[str] = field(default_factory=tuple)
    clock_skew_seconds: int = 60


@dataclass(frozen=True, slots=True)
class FederatedPrincipal:
    """The verified outcome of a federated login — the username to resolve against on-prem AD, the
    evidence folded into the ``auth.login_success`` audit detail, and the verified ``exp``."""

    username: str
    subject: str
    amr: tuple[str, ...]
    acr: str | None
    # The signature-verified ``exp`` (epoch seconds). ADR 0142 AC-6 caps the engine session at it, so
    # a federated session can never outlive the assertion it was minted from. Carried as a typed field
    # precisely so no caller re-parses the raw token to recover it.
    expires_at: float


def _select_key_and_alg(
    id_token: str, policy: OidcClaimPolicy, jwks: JwksCache
) -> tuple[object, SignatureAlgorithm]:
    try:
        header = unverified_jws_header(id_token)
    except SigningError as exc:
        raise ClaimsError("malformed_token", str(exc)) from exc
    kid = header.get("kid")
    if not isinstance(kid, str) or kid == "":
        raise ClaimsError("unknown_kid", "id_token header carries no kid")
    try:
        alg = SignatureAlgorithm(header.get("alg"))
    except ValueError as exc:
        raise ClaimsError("key_rejected", f"unsupported alg {header.get('alg')!r}") from exc
    if alg not in set(policy.signing_algorithms):
        raise ClaimsError("key_rejected", f"alg {alg.value} is not pinned")
    try:
        key = jwks.get_key(kid)
    except JwksError as exc:
        raise ClaimsError("unknown_kid", str(exc)) from exc
    try:
        require_public_key_for_alg(key, alg)
    except SigningError as exc:
        raise ClaimsError("key_rejected", str(exc)) from exc
    return key, alg


def _verify_signature(id_token: str, key: object, policy: OidcClaimPolicy) -> Mapping[str, object]:
    from cryptography.exceptions import InvalidSignature

    try:
        return verify_compact_jws(
            id_token,
            key,  # type: ignore[arg-type]  # narrowed by require_public_key_for_alg
            allowed_algorithms=policy.signing_algorithms,
        )
    except InvalidSignature as exc:
        raise ClaimsError("bad_signature", "id_token signature did not verify") from exc
    except SigningError as exc:
        # A DISTINCT slug from _select_key_and_alg's "malformed_token": this raise is at the
        # SIGNATURE rung, and in the payload-shape cases it fires AFTER the signature has already
        # verified. One slug across two rungs made the failing rung underivable from the reason,
        # which is exactly what `verify --section federation` reports off.
        raise ClaimsError("malformed_payload", str(exc)) from exc


def _check_core_claims(claims: Mapping[str, object], policy: OidcClaimPolicy, now: float) -> float:
    """Walk the core OIDC claim checks and **return the verified ``exp``** (ADR 0142 AC-6).

    The `exp` is returned rather than discarded so the session cap has a second operand that came
    from the *signature-verified* claims. A caller must never re-parse the token to recover it — that
    is the second-read bug class ``verify_compact_jws`` exists to foreclose.
    """
    if claims.get("iss") != policy.issuer:
        raise ClaimsError("claim_iss", "iss does not match the pinned issuer")

    aud = claims.get("aud")
    audiences = {aud} if isinstance(aud, str) else set(aud) if isinstance(aud, list) else set()
    if policy.client_id not in audiences:
        raise ClaimsError("claim_aud", "aud does not contain the client_id")
    # With multiple audiences, azp MUST be present and equal to our client_id (OIDC core 3.1.3.7/2).
    if len(audiences) > 1 and claims.get("azp") != policy.client_id:
        raise ClaimsError("claim_azp", "multi-aud token without a matching azp")

    skew = policy.clock_skew_seconds
    exp = _require_number(claims, "exp", "expired")
    if now > exp + skew:
        raise ClaimsError("expired", "id_token exp is in the past")
    if "iat" in claims:
        iat = _require_number(claims, "iat", "issued_in_future")
        if iat > now + skew:
            raise ClaimsError("issued_in_future", "id_token iat is in the future")
    if "nbf" in claims:
        nbf = _require_number(claims, "nbf", "not_yet_valid")
        if now + skew < nbf:
            raise ClaimsError("not_yet_valid", "id_token nbf is in the future")

    token_nonce = claims.get("nonce")
    if not isinstance(token_nonce, str) or not hmac.compare_digest(token_nonce, policy.nonce):
        raise ClaimsError("nonce_mismatch", "id_token nonce does not match the flow nonce")

    return exp


def _require_number(claims: Mapping[str, object], field_name: str, _reason: str) -> float:
    """Read a numeric claim, or raise ``claim_not_numeric``.

    A missing / string / boolean ``exp`` is a DIFFERENT fault from an ``exp`` in the past: the
    first says the IdP does not mint the datum ADR 0142 AC-6 caps the session at; the second says
    a captured token went stale. Both used to raise the caller-supplied slug (``expired`` for
    ``exp``), so nothing downstream could tell a real deployment defect from a benign artefact.
    """
    value = claims.get(field_name)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ClaimsError("claim_not_numeric", f"{field_name} is missing or non-numeric")
    return float(value)


def _check_mfa_gate(
    claims: Mapping[str, object], policy: OidcClaimPolicy
) -> tuple[tuple[str, ...], str | None]:
    """Enforce the amr/acr MFA gate (BACKLOG #99(g)); return the observed ``(amr, acr)``."""
    raw_amr = claims.get("amr")
    amr = tuple(v for v in raw_amr if isinstance(v, str)) if isinstance(raw_amr, list) else ()
    acr = claims.get("acr")
    acr_str = acr if isinstance(acr, str) else None

    if not policy.require_mfa_claim:
        return amr, acr_str

    amr_ok = bool(set(policy.mfa_amr_values) & set(amr)) if policy.mfa_amr_values else False
    acr_ok = acr_str in set(policy.required_acr_values) if policy.required_acr_values else False
    if not (amr_ok or acr_ok):
        raise ClaimsError(
            "mfa_claim_missing",
            "id_token carries no configured amr/acr MFA indication",
        )
    return amr, acr_str


def _resolve_username(claims: Mapping[str, object], policy: OidcClaimPolicy) -> str:
    """Resolve the on-prem account name from the username claim.

    When stripping a UPN suffix, the suffix is **checked against an operator-pinned allow-list
    first**. Without that check the local part alone decides which AD object is resolved, and the
    claim is neither unique nor stable (OIDC Core §5.7) and is self-editable on several IdPs — so a
    principal could simply assert ``Administrator@somewhere.else`` and log in as the on-prem
    Administrator. That is *chosen* privilege escalation, not the accidental "wrong-user login" the
    roles-come-from-LDAP design bounds.
    """
    raw = claims.get(policy.username_claim)
    if not isinstance(raw, str) or raw == "":
        raise ClaimsError(
            "username_claim_missing",
            f"id_token has no usable {policy.username_claim!r} claim",
        )
    if not policy.username_strip_domain:
        # Used verbatim: no suffix is discarded, so there is nothing to attest to.
        return raw

    local, sep, domain = raw.partition("@")
    if not sep or not local:
        raise ClaimsError(
            "username_domain_not_allowed",
            f"{policy.username_claim!r} carries no UPN suffix to check",
        )
    # rpartition would let "admin@evil.example@corp.example" pass by matching only the LAST label,
    # so the suffix is everything after the FIRST '@' — matching how the local part is taken.
    if domain.strip().lower() not in policy.allowed_username_domains:
        raise ClaimsError(
            "username_domain_not_allowed",
            f"{policy.username_claim!r} UPN suffix is not in the configured allow-list",
        )
    return local


def validate_id_token(
    id_token: str,
    policy: OidcClaimPolicy,
    jwks: JwksCache,
    *,
    clock: Callable[[], float] = time.time,
) -> FederatedPrincipal:
    """Verify an ``id_token`` end to end and return the :class:`FederatedPrincipal`, or raise
    :class:`ClaimsError` with a closed-set ``reason``.

    Order is deliberate: signature first (nothing downstream trusts an unverified claim), then the
    core OIDC claims, then the MFA gate, then username resolution. ``clock`` is wall-clock ``time.time``
    (token lifetimes are wall-clock, unlike the monotonic caches) and injectable for tests.
    """
    key, _alg = _select_key_and_alg(id_token, policy, jwks)
    claims = _verify_signature(id_token, key, policy)
    expires_at = _check_core_claims(claims, policy, clock())
    amr, acr = _check_mfa_gate(claims, policy)
    username = _resolve_username(claims, policy)

    subject = claims.get("sub")
    return FederatedPrincipal(
        username=username,
        subject=subject if isinstance(subject, str) else "",
        amr=amr,
        acr=acr,
        expires_at=expires_at,
    )
