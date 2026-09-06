# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The OIDC ``id_token`` claim-validation ladder (ADR 0142).

Given a compact ``id_token``, the pinned config, and a :class:`~messagefoundry.auth.oidc.jwks.JwksCache`,
this verifies the signature (via ``transports.signing.verify_compact_jws``) and then walks the OIDC
core claim checks — ``iss``, ``aud``/``azp``, ``exp``/``iat``/``nbf`` within a bounded skew, ``nonce``
— then the optional MFA-claim gate (``amr``/``acr``), which is BACKLOG #99(g)'s real control, and
finally the ``auth_time`` recency gate (BACKLOG #1144 step 3).

Recency and the ``max_age`` parameter :func:`~messagefoundry.auth.oidc.flow.build_authorization_url`
sends are ONE control split across two modules, and neither half is meaningful alone: requesting a
maximum authentication age and never checking what comes back asserts a recentness that was never
established, while checking ``auth_time`` without requesting ``max_age`` would refuse conforming
providers, since OIDC Core 2 makes the claim REQUIRED only when it was asked for. That is why the
request parameter is a required keyword and the policy field carries no default.

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
        "claim_sub_missing",
        "wrong_token_type",
        "unexpected_events_claim",
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
        # The recency rung (BACKLOG #1144 step 3). THREE slugs, not one, because they indict three
        # different parties: `missing` says the IdP did not honour a `max_age` OIDC Core 2 makes
        # binding, `stale` says the human's authentication event is genuinely too old (the only one
        # of the three that is normal operation), and `in_future` says a clock is materially wrong.
        # Collapsing them would repeat the fault this module already fixed twice — see
        # `_require_number` and `_verify_signature` on what one slug across two faults cost.
        "auth_time_missing",
        "auth_time_stale",
        "auth_time_in_future",
        "username_claim_missing",
        "username_domain_not_allowed",
    }
)

#: The recency window the engine requests and enforces, in seconds — 12 hours.
#:
#: Matched to `[security].max_session_hours` (12), the engine's own absolute session ceiling: a
#: federated login may not stand on an authentication event older than the longest session the engine
#: would have kept from it anyway. Any larger value asserts a "recent" authentication the engine
#: itself would already have timed out.
#:
#: It is a CONSTANT rather than an off switch. A setting that only chooses the WINDOW is legitimate
#: operator tuning; a setting that could switch the CHECK off would let configuration buy a pass on
#: the requirement, which is the trap BACKLOG #1144 names. When the `[auth].oidc_max_age_seconds`
#: field lands, it replaces the two call-site references to this constant and nothing else — the
#: ladder keeps validating unconditionally either way.
DEFAULT_MAX_AGE_SECONDS: int = 43200


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
    #: The `max_age` (seconds) that was sent on the authorization request, and therefore the window
    #: `auth_time` is checked against. Carries **no default**, deliberately: the ladder's right to
    #: refuse an absent `auth_time` rests entirely on the engine having asked for `max_age` (OIDC
    #: Core 2 makes the claim REQUIRED only then), so every constructor must state the window it
    #: asked for rather than inherit one. Mirrors the required keyword on `build_authorization_url`.
    max_age_seconds: int
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
    # The pinned issuer this assertion was verified against (``policy.issuer``, which ``_check_core_claims``
    # already proved the token's ``iss`` equals). Carried alongside ``subject`` so the relying party can
    # PIN the local federated account's identity to the non-reassignable ``(issuer, sub)`` tuple (BACKLOG
    # #1015): the AD-backed account is still resolved BY its username (ADR 0142 keeps roles LDAP-sourced),
    # but a login whose reassignable username resolves to an account already bound to a DIFFERENT
    # ``(issuer, sub)`` is refused — so a reassigned username cannot take over the prior holder's account.
    # A ``sub`` is only guaranteed stable WITHIN one issuer, so the binding needs both halves even though
    # a single issuer is pinned today.
    issuer: str
    amr: tuple[str, ...]
    acr: str | None
    # The signature-verified ``exp`` (epoch seconds). ADR 0142 AC-6 caps the engine session at it, so
    # a federated session can never outlive the assertion it was minted from. Carried as a typed field
    # precisely so no caller re-parses the raw token to recover it.
    expires_at: float
    # The signature-verified ``auth_time`` (epoch seconds) — WHEN the IdP authenticated the human,
    # which is a different question from when it minted the token (``iat``). BACKLOG #1144 step 3.
    #
    # Already CLAMPED to the validation-time clock, so it is never in the future: the rung tolerates
    # up to ``clock_skew_seconds`` of IdP clock lead, and the caller derives a session deadline from
    # this value, so an unclamped lead would let skew BUY session lifetime. Tolerance may excuse a
    # value, never extend a bound.
    auth_time: float


#: The ``typ`` values an ``id_token`` may declare, after normalisation. RFC 7519 §5.1 makes the header
#: advisory and OIDC Core does not mandate it, so an ABSENT ``typ`` is accepted — refusing it would
#: lock out conforming IdPs that omit it.
_ID_TOKEN_TYPS: frozenset[str] = frozenset({"jwt"})


def _assert_id_token_typ(header: Mapping[str, object]) -> None:
    """Refuse a JWS whose header DECLARES a class other than ``id_token`` (ASVS 9.2.2).

    The tokens this excludes — an access token (``at+jwt``, RFC 9068), a back-channel logout token
    (``logout+jwt``), a security event token (``secevent+jwt``) — are minted by the **same issuer
    under the same key**, so every check downstream of key selection passes on them. Without this the
    only thing between an access token and an accepted federated login is nonce equality.

    Normalisation is ``.strip().lower().removeprefix("application/")``, lower-casing **before** the
    prefix strip: RFC 7515 §4.1.9 lets the ``application/`` prefix be omitted and media types are
    case-insensitive, so ``Application/JWT`` is a legal spelling of ``jwt``. Stripping first would
    leave ``Application/JWT`` un-normalised and refuse a conforming token.

    Called at the TOP of key selection, before the kid guard and the alg pin, so a wrong-class token
    is audited as ``wrong_token_type`` rather than as whichever unrelated rung it happens to trip.
    """
    typ = header.get("typ")
    if typ is None:
        return
    if not isinstance(typ, str):
        raise ClaimsError("wrong_token_type", "id_token header typ is not a string")
    if typ.strip().lower().removeprefix("application/") not in _ID_TOKEN_TYPS:
        raise ClaimsError("wrong_token_type", f"id_token header declares typ {typ!r}")


def _select_key_and_alg(
    id_token: str, policy: OidcClaimPolicy, jwks: JwksCache
) -> tuple[object, SignatureAlgorithm]:
    try:
        header = unverified_jws_header(id_token)
    except SigningError as exc:
        raise ClaimsError("malformed_token", str(exc)) from exc
    _assert_id_token_typ(header)
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


def _nonce_matches(received: str, expected: str) -> bool:
    """Constant-time nonce comparison — mirrors ``flow.state_matches`` at the encoding boundary.

    ``hmac.compare_digest`` raises ``TypeError`` on a ``str`` carrying non-ASCII, so comparing the
    token nonce directly turns a hostile ``nonce`` like ``n-éé`` into an unhandled 500 that skips the
    audited ``nonce_mismatch`` branch. The flow nonce we minted is base64url, so a non-ASCII token
    nonce cannot match anyway — this is a plain non-match, not a special case.
    """
    try:
        return hmac.compare_digest(received.encode("ascii"), expected.encode("ascii"))
    except UnicodeEncodeError:
        return False


def _check_core_claims(
    claims: Mapping[str, object], policy: OidcClaimPolicy, now: float
) -> tuple[float, str]:
    """Walk the core OIDC claim checks and **return the verified ``(exp, sub)``** (ADR 0142 AC-6).

    Both are returned rather than discarded so the session cap and the audit subject have operands
    that came from the *signature-verified* claims. A caller must never re-parse the token to recover
    either — that is the second-read bug class ``verify_compact_jws`` exists to foreclose.
    """
    # ASVS 9.2.2, ahead of every other claim check. A claim set carrying ``events`` is a Security
    # Event Token (RFC 8417) — a back-channel logout token or similar — not an ``id_token``, and the
    # two must not be interchangeable. This runs FIRST because a logout token carries no ``nonce``:
    # checked in ladder order it would be refused as ``nonce_mismatch``, which indicts the browser
    # binding and tells the operator the wrong thing about why the login failed.
    if "events" in claims:
        raise ClaimsError(
            "unexpected_events_claim",
            "claim set carries an events claim (RFC 8417 SET, not an id_token)",
        )

    if claims.get("iss") != policy.issuer:
        raise ClaimsError("claim_iss", "iss does not match the pinned issuer")

    aud = claims.get("aud")
    # A ``list`` aud whose elements are unhashable (a list-of-lists, or a list carrying a dict)
    # raises ``TypeError`` from ``set(aud)`` — the one malformed shape that escapes past the fall-
    # through to an empty set. Convert it into the same audited ``claim_aud`` rejection the
    # membership check below emits, rather than a 500 with no closed-set audit row. The body is kept
    # to the single set-building expression so the only TypeError caught is the one from that call.
    try:
        audiences = {aud} if isinstance(aud, str) else set(aud) if isinstance(aud, list) else set()
    except TypeError as exc:
        raise ClaimsError("claim_aud", "aud is malformed") from exc
    if policy.client_id not in audiences:
        raise ClaimsError("claim_aud", "aud does not contain the client_id")
    # With multiple audiences, azp MUST be present and equal to our client_id (OIDC core 3.1.3.7/2).
    if len(audiences) > 1 and claims.get("azp") != policy.client_id:
        raise ClaimsError("claim_azp", "multi-aud token without a matching azp")

    skew = policy.clock_skew_seconds
    exp = _require_number(claims, "exp", "expired")
    if now > exp + skew:
        raise ClaimsError("expired", "id_token exp is in the past")
    # ``iat`` is REQUIRED of an id_token by OIDC Core 2, so it is read unconditionally rather than
    # behind an `if "iat" in claims` guard. A token omitting it is not an id_token; the omission
    # surfaces as ``claim_not_numeric`` at this rung, the same slug a non-numeric ``iat`` already
    # raised, so no new reason enters the closed set.
    iat = _require_number(claims, "iat", "issued_in_future")
    if iat > now + skew:
        raise ClaimsError("issued_in_future", "id_token iat is in the future")
    if "nbf" in claims:
        nbf = _require_number(claims, "nbf", "not_yet_valid")
        if now + skew < nbf:
            raise ClaimsError("not_yet_valid", "id_token nbf is in the future")

    token_nonce = claims.get("nonce")
    if not isinstance(token_nonce, str) or not _nonce_matches(token_nonce, policy.nonce):
        raise ClaimsError("nonce_mismatch", "id_token nonce does not match the flow nonce")

    # ``sub`` is REQUIRED of an id_token by OIDC Core 2 and is the only stable identifier the
    # assertion carries. It was previously read with an `else ""` fallback at construction, so a
    # token without one minted a principal whose subject was the empty string — and that empty
    # subject was written into the ``auth.login_success`` audit as if it were evidence.
    subject = claims.get("sub")
    if not isinstance(subject, str) or subject == "":
        raise ClaimsError("claim_sub_missing", "id_token carries no usable sub claim")

    return exp, subject


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


def _check_recency(claims: Mapping[str, object], policy: OidcClaimPolicy, now: float) -> float:
    """Enforce the federated recentness gate and return the verified ``auth_time``, clamped to ``now``.

    BACKLOG #1144 step 3, and the half that turns a request into a control. The engine sends
    ``max_age`` on every authorization request; OIDC Core 2 then makes ``auth_time`` REQUIRED in the
    returned ``id_token``, and OIDC Core's Authentication Request section obliges the provider to
    actively re-authenticate the
    end user only IF the elapsed time exceeds that value. That conditional is why single sign-on
    survives: everyone inside the window is redirected back silently, and only a genuinely stale
    authentication costs a credential prompt.

    Sending ``max_age`` and never reading ``auth_time`` would be strictly worse than sending nothing.
    It reads as a recency control in the request, in the settings reference and in a review, while
    accepting an authentication of any age — the shape this item was filed to close.

    Three refusals, each its own slug:

    * **absent or non-numeric** — the IdP did not honour a request it is required to honour. Silently
      proceeding would assert a recentness that was never established, so it is a hard refusal rather
      than a fallback. This is also why the request parameter is not optional: were it omissible, a
      conforming IdP that legitimately omitted ``auth_time`` would be refused here.
    * **older than the window, plus ``clock_skew_seconds``** — the ordinary case, and the one the
      control exists for. The grace is the same one ``exp`` already gets at the core-claims rung, and
      here it does two jobs: it absorbs an IdP clock running behind ours, and it absorbs the browser
      round trip. A provider honours ``max_age`` as measured at the AUTHORIZE request, but the ladder
      measures at the CALLBACK, so without the grace a conforming provider that answered a boundary
      case exactly right would have its token refused for the time the redirect itself took.
    * **further ahead than ``clock_skew_seconds``** — refused because clamping alone cannot contain
      it. ``now - min(auth_time, now)`` is zero for ANY future value, so a provider whose clock ran an
      hour fast would let an hour-old authentication satisfy a five-minute window. Inside the grace it
      is tolerated and clamped, mirroring how ``iat`` is already handled at the core-claims rung.
    """
    raw = claims.get("auth_time")
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        # `bool` is excluded explicitly: `isinstance(True, int)` holds in Python, so a boolean claim
        # would otherwise be read as epoch 1 and refused as `auth_time_stale` — a slug blaming the
        # END USER for what is an IdP defect.
        raise ClaimsError(
            "auth_time_missing",
            "id_token carries no numeric auth_time, though max_age was requested",
        )
    auth_time = float(raw)
    skew = policy.clock_skew_seconds
    if auth_time > now + skew:
        raise ClaimsError("auth_time_in_future", "id_token auth_time is in the future")
    if now - auth_time > policy.max_age_seconds + skew:
        raise ClaimsError(
            "auth_time_stale",
            "the IdP authentication event is older than the requested max_age",
        )
    return min(auth_time, now)


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
    core OIDC claims, then the MFA gate, then recency, then username resolution. ``clock`` is
    wall-clock ``time.time`` (token lifetimes are wall-clock, unlike the monotonic caches) and
    injectable for tests.

    Recency sits immediately after the MFA gate because the two answer the same kind of question — what
    the IdP asserts about the authentication EVENT, strength then age — and because both must run after
    ``_check_core_claims`` has pinned the issuer. A rung that read ``auth_time`` before the issuer was
    matched would be reading a datum from a token the engine has not yet agreed to trust.

    ``clock()`` is read ONCE and shared by the core-claims and recency rungs. Two reads would let
    ``exp`` and ``auth_time`` be judged against different instants — small, but it is the kind of
    inconsistency that makes a boundary test pass and a boundary login fail.
    """
    now = clock()
    key, _alg = _select_key_and_alg(id_token, policy, jwks)
    claims = _verify_signature(id_token, key, policy)
    expires_at, subject = _check_core_claims(claims, policy, now)
    amr, acr = _check_mfa_gate(claims, policy)
    auth_time = _check_recency(claims, policy, now)
    username = _resolve_username(claims, policy)

    return FederatedPrincipal(
        username=username,
        subject=subject,
        issuer=policy.issuer,
        amr=amr,
        acr=acr,
        expires_at=expires_at,
        auth_time=auth_time,
    )
