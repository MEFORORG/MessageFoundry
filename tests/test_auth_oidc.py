# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Hermetic tests for the OIDC relying-party package (ADR 0142, BACKLOG #274).

No network: id_tokens are minted with the shipped ``CompactJwtSigner`` over throwaway keys, and the
JWKS is served from an in-memory counter. The claim ladder, the key-material floor, the flow-cache
bounds, and the amplification bound are all exercised here; the browser wiring is tested at the
web-console layer.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from messagefoundry.auth import oidc
from messagefoundry.auth.oidc import claims as claims_mod
from messagefoundry.config.models import SignatureAlgorithm
from messagefoundry.transports.signing import CompactJwtSigner

# --- helpers ---------------------------------------------------------------------------------------


def _pem(key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey) -> str:
    from cryptography.hazmat.primitives import serialization

    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


def _b64u_uint(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _rsa_jwk(key: rsa.RSAPrivateKey, kid: str) -> dict[str, Any]:
    nums = key.public_key().public_numbers()
    return {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": _b64u_uint(nums.n),
        "e": _b64u_uint(nums.e),
    }


def _jwks_bytes(*jwks: dict[str, Any]) -> bytes:
    return json.dumps({"keys": list(jwks)}).encode()


def _mint(key: rsa.RSAPrivateKey, kid: str, claims: Mapping[str, Any]) -> str:
    # The signer stamps `kid` into the JWS header from key_id — which is exactly what the claims
    # ladder reads to select the verifying key, mirroring a real IdP.
    signer = CompactJwtSigner(private_key=_pem(key), algorithm=SignatureAlgorithm.RS256, key_id=kid)
    return signer.sign(dict(claims))


@pytest.fixture(scope="module")
def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _policy(nonce: str = "n-123", **over: Any) -> oidc.OidcClaimPolicy:
    base: dict[str, Any] = {
        "issuer": "https://idp.example",
        "client_id": "mefor-console",
        "signing_algorithms": [SignatureAlgorithm.RS256],
        "nonce": nonce,
        # _good_claims() carries preferred_username "jdoe@corp.example"; stripping is fail-closed
        # without an allow-list, so the suffix has to be attested here.
        "allowed_username_domains": frozenset({"corp.example"}),
    }
    base.update(over)
    return oidc.OidcClaimPolicy(**base)


def _good_claims(nonce: str = "n-123", **over: Any) -> dict[str, Any]:
    now = 1_000_000
    base: dict[str, Any] = {
        "iss": "https://idp.example",
        "aud": "mefor-console",
        "sub": "S-1-5-21-abc",
        "exp": now + 300,
        "iat": now,
        "nonce": nonce,
        "preferred_username": "jdoe@corp.example",
        "amr": ["pwd", "mfa"],
    }
    base.update(over)
    return base


# --- jwks: the key-material floor ------------------------------------------------------------------


def test_rsa_jwk_round_trips(rsa_key: rsa.RSAPrivateKey) -> None:
    key = oidc.jwk_to_public_key(_rsa_jwk(rsa_key, "k1"))
    assert isinstance(key, rsa.RSAPublicKey)


def test_undersized_rsa_is_refused() -> None:
    small = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    with pytest.raises(oidc.JwksError, match="1024 bits; the floor is 2048"):
        oidc.jwk_to_public_key(_rsa_jwk(small, "weak"))


def test_ec_p256_round_trips() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    nums = key.public_key().public_numbers()
    jwk: dict[str, Any] = {
        "kty": "EC",
        "kid": "e1",
        "crv": "P-256",
        "x": _b64u_uint(nums.x),
        "y": _b64u_uint(nums.y),
    }
    assert isinstance(oidc.jwk_to_public_key(jwk), ec.EllipticCurvePublicKey)


def test_unknown_curve_is_refused() -> None:
    with pytest.raises(oidc.JwksError, match="unsupported EC curve"):
        oidc.jwk_to_public_key({"kty": "EC", "kid": "e", "crv": "P-521", "x": "AA", "y": "AA"})


def test_unknown_kty_is_refused() -> None:
    with pytest.raises(oidc.JwksError, match="unsupported JWK kty"):
        oidc.jwk_to_public_key({"kty": "oct", "kid": "s", "k": "AAAA"})


def test_use_enc_is_refused(rsa_key: rsa.RSAPrivateKey) -> None:
    jwk = _rsa_jwk(rsa_key, "k1") | {"use": "enc"}
    with pytest.raises(oidc.JwksError, match="not a signature key"):
        oidc.jwk_to_public_key(jwk)


def test_key_ops_without_verify_is_refused(rsa_key: rsa.RSAPrivateKey) -> None:
    jwk = _rsa_jwk(rsa_key, "k1") | {"key_ops": ["encrypt"]}
    with pytest.raises(oidc.JwksError, match="key_ops does not permit"):
        oidc.jwk_to_public_key(jwk)


def test_duplicate_kid_is_refused(rsa_key: rsa.RSAPrivateKey) -> None:
    body = _jwks_bytes(_rsa_jwk(rsa_key, "dup"), _rsa_jwk(rsa_key, "dup"))
    with pytest.raises(oidc.JwksError, match="two keys with kid"):
        oidc.parse_jwks(body)


def test_one_weak_key_does_not_blank_the_set(rsa_key: rsa.RSAPrivateKey) -> None:
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    keys = oidc.parse_jwks(_jwks_bytes(_rsa_jwk(rsa_key, "good"), _rsa_jwk(weak, "weak")))
    assert set(keys) == {"good"}


def test_a_structurally_invalid_key_does_not_blank_the_set(rsa_key: rsa.RSAPrivateKey) -> None:
    """The floor's own checks raise JwksError, but `cryptography`'s final construction step raises a
    bare ValueError for an off-curve EC point or an even RSA exponent. Catching only JwksError let one
    such key abort the whole parse — blanking the set and (because the cache had already stamped its
    fetch attempt) refusing every federated login until the min-refetch floor elapsed."""
    off_curve = {"kty": "EC", "kid": "bad", "crv": "P-256", "x": _b64u_uint(1), "y": _b64u_uint(1)}
    keys = oidc.parse_jwks(_jwks_bytes(off_curve, _rsa_jwk(rsa_key, "good")))
    assert set(keys) == {"good"}

    even_exponent = _rsa_jwk(rsa_key, "bad2") | {"e": _b64u_uint(2)}
    keys = oidc.parse_jwks(_jwks_bytes(even_exponent, _rsa_jwk(rsa_key, "good")))
    assert set(keys) == {"good"}


def test_all_keys_weak_raises() -> None:
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    with pytest.raises(oidc.JwksError, match="no usable signing keys"):
        oidc.parse_jwks(_jwks_bytes(_rsa_jwk(weak, "weak")))


# --- jwks cache: TTL + amplification bound ---------------------------------------------------------


class _CountingFetch:
    def __init__(self, body: bytes) -> None:
        self.body = body
        self.calls = 0

    def __call__(self) -> bytes:
        self.calls += 1
        return self.body


def test_cache_hit_does_not_refetch(rsa_key: rsa.RSAPrivateKey) -> None:
    fetch = _CountingFetch(_jwks_bytes(_rsa_jwk(rsa_key, "k1")))
    clock = [0.0]
    cache = oidc.JwksCache(fetch, clock=lambda: clock[0])
    cache.get_key("k1")
    cache.get_key("k1")
    assert fetch.calls == 1


def test_unknown_kid_is_throttled_by_the_min_refetch_floor(rsa_key: rsa.RSAPrivateKey) -> None:
    """An unknown kid must not amplify into a fetch per request."""
    fetch = _CountingFetch(_jwks_bytes(_rsa_jwk(rsa_key, "k1")))
    clock = [0.0]
    cache = oidc.JwksCache(fetch, min_refetch_seconds=300.0, clock=lambda: clock[0])
    cache.get_key("k1")  # 1 fetch, warms the cache
    for _ in range(50):
        with pytest.raises(oidc.JwksError):
            cache.get_key("attacker-kid")  # no new fetch: throttled
    assert fetch.calls == 1
    clock[0] = 400.0  # past the floor -> exactly one more fetch is allowed
    with pytest.raises(oidc.JwksError):
        cache.get_key("attacker-kid")
    assert fetch.calls == 2


def test_ttl_expiry_triggers_a_refetch(rsa_key: rsa.RSAPrivateKey) -> None:
    fetch = _CountingFetch(_jwks_bytes(_rsa_jwk(rsa_key, "k1")))
    clock = [0.0]
    cache = oidc.JwksCache(
        fetch, ttl_seconds=100.0, min_refetch_seconds=10.0, clock=lambda: clock[0]
    )
    cache.get_key("k1")
    clock[0] = 200.0
    cache.get_key("k1")
    assert fetch.calls == 2


# --- the claim ladder ------------------------------------------------------------------------------


def _cache_for(rsa_key: rsa.RSAPrivateKey, kid: str = "k1") -> oidc.JwksCache:
    return oidc.JwksCache(_CountingFetch(_jwks_bytes(_rsa_jwk(rsa_key, kid))))


def test_happy_path_returns_principal(rsa_key: rsa.RSAPrivateKey) -> None:
    jws = _mint(rsa_key, "k1", _good_claims())
    principal = oidc.validate_id_token(jws, _policy(), _cache_for(rsa_key), clock=lambda: 1_000_100)
    assert principal.username == "jdoe"  # domain stripped
    assert principal.subject == "S-1-5-21-abc"
    assert "mfa" in principal.amr
    # ADR 0142 AC-6: the SIGNATURE-VERIFIED exp is carried out of the ladder so the session cap never
    # has to re-parse the token to find it (that second read is the bug class verify_compact_jws
    # forecloses). 1_000_000 + 300 is _good_claims()'s exp.
    assert principal.expires_at == 1_000_300


def test_verified_exp_is_carried_not_reparsed(rsa_key: rsa.RSAPrivateKey) -> None:
    """The exp on the principal must track the token's own claim, not a fixed default."""
    jws = _mint(rsa_key, "k1", _good_claims(exp=1_002_500))
    principal = oidc.validate_id_token(jws, _policy(), _cache_for(rsa_key), clock=lambda: 1_000_100)
    assert principal.expires_at == 1_002_500


def test_federated_principal_carries_issuer(rsa_key: rsa.RSAPrivateKey) -> None:
    """BACKLOG #1015: the principal carries the pinned ``issuer`` so the relying party can key the local
    account on the non-reassignable ``(issuer, sub)`` tuple, not on the reassignable username. It is the
    policy issuer (already proven equal to the token's ``iss`` by the core-claim rung), not sub-only."""
    jws = _mint(rsa_key, "k1", _good_claims())
    principal = oidc.validate_id_token(jws, _policy(), _cache_for(rsa_key), clock=lambda: 1_000_100)
    assert principal.issuer == "https://idp.example"
    assert principal.subject == "S-1-5-21-abc"


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        ({"iss": "https://evil"}, "claim_iss"),
        ({"aud": "someone-else"}, "claim_aud"),
        ({"exp": 900_000}, "expired"),
        ({"iat": 2_000_000}, "issued_in_future"),
        ({"nonce": "wrong"}, "nonce_mismatch"),
        ({"amr": ["pwd"]}, "mfa_claim_missing"),
        ({"preferred_username": ""}, "username_claim_missing"),
    ],
)
def test_claim_rungs_reject_with_closed_slugs(
    rsa_key: rsa.RSAPrivateKey, mutate: dict[str, Any], reason: str
) -> None:
    jws = _mint(rsa_key, "k1", _good_claims(**mutate))
    with pytest.raises(oidc.ClaimsError) as exc:
        oidc.validate_id_token(jws, _policy(), _cache_for(rsa_key), clock=lambda: 1_000_100)
    assert exc.value.reason == reason
    assert exc.value.reason in oidc.REASONS


def test_bad_signature_is_rejected(rsa_key: rsa.RSAPrivateKey) -> None:
    """A token signed by a different key than the JWKS advertises for that kid."""
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jws = _mint(other, "k1", _good_claims())
    with pytest.raises(oidc.ClaimsError) as exc:
        oidc.validate_id_token(jws, _policy(), _cache_for(rsa_key), clock=lambda: 1_000_100)
    assert exc.value.reason == "bad_signature"


def test_unknown_kid_rejected(rsa_key: rsa.RSAPrivateKey) -> None:
    jws = _mint(rsa_key, "k1", _good_claims())
    with pytest.raises(oidc.ClaimsError) as exc:
        oidc.validate_id_token(
            jws, _policy(), _cache_for(rsa_key, kid="other"), clock=lambda: 1_000_100
        )
    assert exc.value.reason == "unknown_kid"


def test_multi_aud_without_azp_rejected(rsa_key: rsa.RSAPrivateKey) -> None:
    jws = _mint(rsa_key, "k1", _good_claims(aud=["mefor-console", "another"]))
    with pytest.raises(oidc.ClaimsError) as exc:
        oidc.validate_id_token(jws, _policy(), _cache_for(rsa_key), clock=lambda: 1_000_100)
    assert exc.value.reason == "claim_azp"


def test_multi_aud_with_matching_azp_accepted(rsa_key: rsa.RSAPrivateKey) -> None:
    jws = _mint(rsa_key, "k1", _good_claims(aud=["mefor-console", "another"], azp="mefor-console"))
    principal = oidc.validate_id_token(jws, _policy(), _cache_for(rsa_key), clock=lambda: 1_000_100)
    assert principal.username == "jdoe"


# --- claims: two malformed-IdP shapes reject as audited ClaimsErrors, not 500s (BACKLOG #1016) -----


def test_a_non_ascii_nonce_is_a_mismatch_not_a_crash(rsa_key: rsa.RSAPrivateKey) -> None:
    """A non-ASCII token nonce must reject as an audited ``nonce_mismatch``, not an unhandled 500.
    ``hmac.compare_digest`` raises ``TypeError`` on a str carrying non-ASCII, so without the encoding
    guard a hostile ``nonce`` would, on first deployment, surface as a 500 that skips the closed-set
    audit row every other claim rejection emits. The policy nonce is ASCII ``n-123``."""
    jws = _mint(rsa_key, "k1", _good_claims(nonce="n-éé"))
    with pytest.raises(oidc.ClaimsError) as exc:
        oidc.validate_id_token(jws, _policy(), _cache_for(rsa_key), clock=lambda: 1_000_100)
    assert exc.value.reason == "nonce_mismatch"
    assert exc.value.reason in oidc.REASONS


@pytest.mark.parametrize("aud", [[["mefor-console"]], [{"a": 1}]])
def test_an_unhashable_aud_element_is_claim_aud_not_a_crash(
    rsa_key: rsa.RSAPrivateKey, aud: Any
) -> None:
    """A ``list`` aud carrying an unhashable element (a nested list, or a dict) raises ``TypeError``
    from ``set(aud)`` — the one malformed shape that escapes the fall-through to an empty set. It
    must reject as an audited ``claim_aud``, not a 500. A top-level dict/int/None already falls
    through cleanly, so reaching the guard proves it fired: pre-fix the path raises before the
    membership check below it could run."""
    jws = _mint(rsa_key, "k1", _good_claims(aud=aud))
    with pytest.raises(oidc.ClaimsError) as exc:
        oidc.validate_id_token(jws, _policy(), _cache_for(rsa_key), clock=lambda: 1_000_100)
    assert exc.value.reason == "claim_aud"
    assert exc.value.reason in oidc.REASONS


def test_the_malformed_shape_guards_do_not_over_reject_a_valid_token(
    rsa_key: rsa.RSAPrivateKey,
) -> None:
    """Negative control (guard-the-guard): the two malformed-shape guards must not reject an ordinary
    valid token — an ASCII nonce equal to the policy nonce and a plain str aud validate byte-
    identically. The existing ``{"nonce": "wrong"}`` rung already proves an ASCII wrong-nonce still
    routes to ``nonce_mismatch``, so the encoding guard does not swallow real mismatches."""
    jws = _mint(rsa_key, "k1", _good_claims())
    principal = oidc.validate_id_token(jws, _policy(), _cache_for(rsa_key), clock=lambda: 1_000_100)
    assert principal.username == "jdoe"
    assert principal.subject == "S-1-5-21-abc"


def test_mfa_gate_off_accepts_a_password_only_token(rsa_key: rsa.RSAPrivateKey) -> None:
    jws = _mint(rsa_key, "k1", _good_claims(amr=["pwd"]))
    principal = oidc.validate_id_token(
        jws, _policy(require_mfa_claim=False), _cache_for(rsa_key), clock=lambda: 1_000_100
    )
    assert principal.amr == ("pwd",)


def test_acr_satisfies_the_mfa_gate(rsa_key: rsa.RSAPrivateKey) -> None:
    jws = _mint(rsa_key, "k1", _good_claims(amr=["pwd"], acr="phrh"))
    policy = _policy(mfa_amr_values=[], required_acr_values=["phrh"])
    principal = oidc.validate_id_token(jws, policy, _cache_for(rsa_key), clock=lambda: 1_000_100)
    assert principal.acr == "phrh"


def test_every_reason_slug_is_declared() -> None:
    """The ClaimsError constructor refuses any reason outside the closed set."""
    with pytest.raises(AssertionError):
        claims_mod.ClaimsError("not_a_real_reason")


# --- claims: token-class assertion (ASVS 9.2.2) ----------------------------------------------------

#: Sentinel for "mint this token with NO typ header at all" — distinct from ``typ: null``.
_OMIT_TYP = object()


def _mint_with_typ(
    key: rsa.RSAPrivateKey, kid: str, claims: Mapping[str, Any], typ: Any = _OMIT_TYP
) -> str:
    """Mint a **properly signed** compact JWS carrying an arbitrary ``typ`` header.

    ``CompactJwtSigner.sign`` hardcodes ``{"alg": ..., "typ": "JWT"}``, so the shipped signer cannot
    express the wrong-class token this rung exists to refuse. The signature below is computed over
    the real header bytes, so a refusal proves the **typ assertion** fired — not that a retargeted or
    hand-spliced signature failed to verify, which would make every test here pass for the wrong
    reason and stay green if the assertion were deleted.
    """
    from messagefoundry.transports.signing import _b64u_encode, _sign

    header: dict[str, Any] = {"alg": SignatureAlgorithm.RS256.value, "kid": kid}
    if typ is not _OMIT_TYP:
        header["typ"] = typ
    header_b64 = _b64u_encode(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
    claims_b64 = _b64u_encode(
        json.dumps(dict(claims), separators=(",", ":"), sort_keys=True).encode()
    )
    signature = _sign(key, SignatureAlgorithm.RS256, f"{header_b64}.{claims_b64}".encode("ascii"))
    return f"{header_b64}.{claims_b64}.{_b64u_encode(signature)}"


def test_the_hand_mint_helper_produces_a_genuinely_valid_token(rsa_key: rsa.RSAPrivateKey) -> None:
    """Guard-the-guard: without this, every ``_mint_with_typ`` test could be passing because the
    helper mints garbage rather than because the assertion under test fired."""
    jws = _mint_with_typ(rsa_key, "k1", _good_claims(), typ="JWT")
    principal = oidc.validate_id_token(jws, _policy(), _cache_for(rsa_key), clock=lambda: 1_000_100)
    assert principal.username == "jdoe"


@pytest.mark.parametrize(
    "typ",
    [
        "at+jwt",  # RFC 9068 access token — same issuer, same key, passes every other rung
        "application/at+jwt",  # the RFC 7515 §4.1.9 long form of the same
        "logout+jwt",  # OIDC back-channel logout token
        "secevent+jwt",  # RFC 8417 security event token
        "JOSE",
        "",  # declared-but-empty is a declaration, not an absence
        123,  # non-string
    ],
)
def test_a_declared_non_id_token_typ_is_refused(rsa_key: rsa.RSAPrivateKey, typ: Any) -> None:
    jws = _mint_with_typ(rsa_key, "k1", _good_claims(), typ=typ)
    with pytest.raises(oidc.ClaimsError) as exc:
        oidc.validate_id_token(jws, _policy(), _cache_for(rsa_key), clock=lambda: 1_000_100)
    assert exc.value.reason == "wrong_token_type"


def test_an_absent_typ_still_validates(rsa_key: rsa.RSAPrivateKey) -> None:
    """RFC 7519 §5.1 makes ``typ`` advisory and OIDC Core does not mandate it, so a conforming IdP
    that omits it must still authenticate. Making ``typ`` mandatory is a federation outage."""
    jws = _mint_with_typ(rsa_key, "k1", _good_claims())
    principal = oidc.validate_id_token(jws, _policy(), _cache_for(rsa_key), clock=lambda: 1_000_100)
    assert principal.username == "jdoe"


@pytest.mark.parametrize("typ", ["JWT", "jwt", "application/jwt", "Application/JWT", "  JWT  "])
def test_a_media_type_prefixed_or_differently_cased_typ_still_validates(
    rsa_key: rsa.RSAPrivateKey, typ: str
) -> None:
    """``Application/JWT`` is the case that pins the normalisation ORDER: lower-case must happen
    BEFORE ``removeprefix("application/")``. Swap the two and this value alone still carries the
    prefix, so a conforming token is refused — the other four spellings pass either way."""
    jws = _mint_with_typ(rsa_key, "k1", _good_claims(), typ=typ)
    principal = oidc.validate_id_token(jws, _policy(), _cache_for(rsa_key), clock=lambda: 1_000_100)
    assert principal.username == "jdoe"


def test_an_events_bearing_claim_set_is_refused_under_its_own_slug(
    rsa_key: rsa.RSAPrivateKey,
) -> None:
    """A Security Event Token (RFC 8417) is not an id_token even when the issuer and key match."""
    jws = _mint(
        rsa_key,
        "k1",
        _good_claims(events={"http://schemas.openid.net/event/backchannel-logout": {}}),
    )
    with pytest.raises(oidc.ClaimsError) as exc:
        oidc.validate_id_token(jws, _policy(), _cache_for(rsa_key), clock=lambda: 1_000_100)
    assert exc.value.reason == "unexpected_events_claim"


def test_the_events_rejection_precedes_the_nonce_rung(rsa_key: rsa.RSAPrivateKey) -> None:
    """A real back-channel logout token carries ``events`` and NO ``nonce``. If the events check ran
    in ladder order it would be refused as ``nonce_mismatch`` — indicting the browser binding and
    telling the operator the wrong thing about why the login failed."""
    logout_ish = _good_claims(events={"http://schemas.openid.net/event/backchannel-logout": {}})
    del logout_ish["nonce"]
    jws = _mint(rsa_key, "k1", logout_ish)
    with pytest.raises(oidc.ClaimsError) as exc:
        oidc.validate_id_token(jws, _policy(), _cache_for(rsa_key), clock=lambda: 1_000_100)
    assert exc.value.reason == "unexpected_events_claim"


@pytest.mark.parametrize(
    ("drop", "reason"),
    [("sub", "claim_sub_missing"), ("iat", "claim_not_numeric")],
)
def test_a_token_missing_a_required_id_token_claim_is_refused(
    rsa_key: rsa.RSAPrivateKey, drop: str, reason: str
) -> None:
    """The positive arm. ``sub`` and ``iat`` are REQUIRED of an id_token by OIDC Core 2. Before this,
    a token with no ``sub`` minted ``FederatedPrincipal(subject="")`` and that empty string was
    written into the ``auth.login_success`` audit as though it were evidence."""
    without = _good_claims()
    del without[drop]
    jws = _mint(rsa_key, "k1", without)
    with pytest.raises(oidc.ClaimsError) as exc:
        oidc.validate_id_token(jws, _policy(), _cache_for(rsa_key), clock=lambda: 1_000_100)
    assert exc.value.reason == reason


@pytest.mark.parametrize("bad_sub", ["", 12345, None])
def test_a_non_string_or_empty_sub_is_refused(rsa_key: rsa.RSAPrivateKey, bad_sub: Any) -> None:
    jws = _mint(rsa_key, "k1", _good_claims(sub=bad_sub))
    with pytest.raises(oidc.ClaimsError) as exc:
        oidc.validate_id_token(jws, _policy(), _cache_for(rsa_key), clock=lambda: 1_000_100)
    assert exc.value.reason == "claim_sub_missing"


# --- flow: PKCE + the flow cache -------------------------------------------------------------------


def test_pkce_challenge_is_s256_of_the_verifier() -> None:
    import hashlib

    verifier, challenge = oidc.generate_pkce()
    expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=")
    assert challenge == expected.decode()


def test_flow_round_trip_binds_and_is_single_use() -> None:
    cache = oidc.FlowCache(clock=lambda: 0.0)
    flow_id, flow = oidc.start_flow(cache, return_to="/ui", client_ip="10.0.0.1", clock=lambda: 0.0)
    got = cache.pop(flow_id)
    assert got is not None and got.state == flow.state
    assert cache.pop(flow_id) is None  # single-use


def test_flow_expires() -> None:
    clock = [0.0]
    cache = oidc.FlowCache(ttl_seconds=100.0, clock=lambda: clock[0])
    flow_id, _ = oidc.start_flow(
        cache, return_to="/ui", client_ip="10.0.0.1", ttl_seconds=100.0, clock=lambda: clock[0]
    )
    clock[0] = 200.0
    assert cache.pop(flow_id) is None


def test_flow_cache_rejects_when_full_never_evicts() -> None:
    """A start-leg flood must be REFUSED, not silently drop an earlier legitimate flow."""
    cache = oidc.FlowCache(global_cap=2, per_ip_cap=99, clock=lambda: 0.0)
    a, _ = oidc.start_flow(cache, return_to="/ui", client_ip="10.0.0.1", clock=lambda: 0.0)
    oidc.start_flow(cache, return_to="/ui", client_ip="10.0.0.2", clock=lambda: 0.0)
    with pytest.raises(oidc.FlowCacheFullError):
        oidc.start_flow(cache, return_to="/ui", client_ip="10.0.0.3", clock=lambda: 0.0)
    assert cache.pop(a) is not None  # the earliest flow survived the flood


def test_per_ip_cap_contains_one_source() -> None:
    cache = oidc.FlowCache(global_cap=99, per_ip_cap=2, clock=lambda: 0.0)
    oidc.start_flow(cache, return_to="/ui", client_ip="10.0.0.9", clock=lambda: 0.0)
    oidc.start_flow(cache, return_to="/ui", client_ip="10.0.0.9", clock=lambda: 0.0)
    with pytest.raises(oidc.FlowCacheFullError):
        oidc.start_flow(cache, return_to="/ui", client_ip="10.0.0.9", clock=lambda: 0.0)
    # a different source is unaffected
    oidc.start_flow(cache, return_to="/ui", client_ip="10.0.0.8", clock=lambda: 0.0)


def test_state_comparison_is_constant_time() -> None:
    assert oidc.state_matches("abc", "abc")
    assert not oidc.state_matches("abc", "abd")


def test_authorization_url_carries_pkce_and_response_mode() -> None:
    import urllib.parse

    url = oidc.build_authorization_url(
        authorization_endpoint="https://idp.example/authorize",
        client_id="mefor-console",
        redirect_uri="http://localhost:8765/ui/oidc/callback",
        state="st",
        nonce="no",
        code_challenge="ch",
        scopes=["openid", "profile"],
    )
    q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    assert q["code_challenge_method"] == ["S256"]
    assert q["response_type"] == ["code"]
    assert q["scope"] == ["openid profile"]


# --- exchange_code: hermetic (injected opener) -----------------------------------------------------


class _FakeResp:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self, _n: int = -1) -> bytes:
        return self._body

    def __enter__(self) -> _FakeResp:
        return self

    def __exit__(self, *_a: object) -> None:
        return None


class _FakeOpener:
    def __init__(self, body: bytes) -> None:
        self._body = body
        self.request: Any = None

    def open(self, req: Any, timeout: float = 0.0) -> _FakeResp:
        self.request = req
        return _FakeResp(self._body)


def test_exchange_code_posts_pkce_and_returns_payload() -> None:
    opener = _FakeOpener(json.dumps({"id_token": "x.y.z", "token_type": "Bearer"}).encode())
    payload = oidc.exchange_code(
        token_endpoint="https://idp.example/token",
        client_id="mefor-console",
        client_secret="s3cr3t",
        code="the-code",
        redirect_uri="http://localhost:8765/ui/oidc/callback",
        code_verifier="the-verifier",
        opener=opener,  # type: ignore[arg-type]
    )
    assert payload["id_token"] == "x.y.z"
    sent = opener.request.data.decode()
    assert "grant_type=authorization_code" in sent
    assert "code_verifier=the-verifier" in sent


def test_exchange_code_without_id_token_raises() -> None:
    opener = _FakeOpener(json.dumps({"access_token": "a"}).encode())
    with pytest.raises(oidc.FlowError, match="no id_token"):
        oidc.exchange_code(
            token_endpoint="https://idp.example/token",
            client_id="c",
            client_secret=None,
            code="x",
            redirect_uri="http://localhost/cb",
            code_verifier="v",
            opener=opener,  # type: ignore[arg-type]
        )


class _TripwireOpener:
    """An opener that fails the test if it is ever reached — the shape a "refused before the wire"
    claim needs. A stub that returned a body could not tell a refusal apart from a completed POST."""

    def open(self, req: Any, timeout: float = 0.0) -> Any:
        raise AssertionError("an unmeasured token-endpoint request reached the opener")


def test_exchange_code_refuses_an_over_length_token_endpoint() -> None:
    """BACKLOG #1048 (ASVS 4.2.5): the token-exchange POST had no send-time length guard — the whole
    ``auth`` package carried zero length measurement, so the one outbound request the OIDC relying
    party makes was the unmeasured limb of the 4.2.5 partial.

    ``token_endpoint`` is operator-static config (validated https at load), so this is the weaker of
    the two limbs and not attacker-influenced. It still earns the bound: an ``env()`` value that
    resolved to an unexpected blob surfaces here as a clear refusal instead of a wire-level surprise
    on the first federated login.

    Mutation: delete the ``find_outbound_length_violation`` call in ``exchange_code``. Red:
    AssertionError from the tripwire — the over-long request reached the opener."""
    with pytest.raises(oidc.FlowError, match="over the 8192-char limit"):
        oidc.exchange_code(
            token_endpoint="https://idp.example/" + "t" * 9000,
            client_id="c",
            client_secret=None,
            code="x",
            redirect_uri="http://localhost/cb",
            code_verifier="v",
            opener=_TripwireOpener(),  # type: ignore[arg-type]
        )


def test_exchange_code_length_guard_reuses_the_one_outbound_bound() -> None:
    """The limit is not re-declared in ``auth``: the guard calls the same measurement every other
    HTTP egress uses, so there is one definition of "too long" and no third constant to drift.

    Live positive control for the refusal above — it proves the number that test matches is the
    shipped limit rather than a value that merely happens to agree with it."""
    from messagefoundry.transports.rest import MAX_OUTBOUND_URL_LEN

    assert MAX_OUTBOUND_URL_LEN == 8192, (
        "the shared outbound URL bound moved; the OIDC guard follows it automatically but the "
        "message the refusal test matches does not"
    )


def test_exchange_code_still_posts_an_endpoint_that_fits() -> None:
    """Positive control: a normal endpoint must still reach the opener. Without it, a guard that
    refused EVERY token exchange would pass the refusal test above."""
    opener = _FakeOpener(json.dumps({"id_token": "x.y.z"}).encode())
    payload = oidc.exchange_code(
        token_endpoint="https://idp.example/token",
        client_id="c",
        client_secret=None,
        code="x",
        redirect_uri="http://localhost/cb",
        code_verifier="v",
        opener=opener,  # type: ignore[arg-type]
    )
    assert payload["id_token"] == "x.y.z"
    assert opener.request is not None, "the request must have been handed to the opener"


def test_non_ascii_state_is_a_plain_non_match_not_a_crash() -> None:
    """``state`` is raw query-string input, and ``hmac.compare_digest`` RAISES TypeError on a str
    carrying non-ASCII. Comparing directly would turn ``?state=café`` into an unhandled 500 on an
    unauthenticated route — skipping the audited ``state_mismatch`` branch entirely, so a prober
    could evade the closed-set audit trail the ADR requires of every reject path."""
    assert oidc.state_matches("abc123", "café") is False
    assert oidc.state_matches("abc123", "日本語") is False
    assert oidc.state_matches("abc123", "") is False
    # The ASCII path is unchanged — still a real constant-time comparison, not a weakened one.
    assert oidc.state_matches("abc123", "abc123") is True
    assert oidc.state_matches("abc123", "abc124") is False
