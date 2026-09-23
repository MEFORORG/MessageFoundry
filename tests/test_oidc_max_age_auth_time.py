# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The federated authentication-recency bound: ``max_age`` out, ``auth_time`` back (BACKLOG #296 /
#1150, ASVS 6.8.4 / 7.6.1).

Five parts, one test group each: the setting (a non-zero default with no off switch), the
authorization URL (``max_age`` is always sent), the claims ladder (``auth_time`` required and bounded,
two new closed-set slugs), the typed principal field, and the session deadline (the ``min()`` gains
``auth_time + max_age``). The verifier rung placement is pinned here too, because a slug in no rung
or in two rungs makes ``verify --section federation`` misattribute a refusal.

Hermetic: tokens are minted with the shipped ``CompactJwtSigner`` over throwaway keys, and the
token-endpoint exchange is stubbed at the seam ``auth/service.py`` calls.
"""

from __future__ import annotations

import time
import urllib.parse
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import ValidationError

from messagefoundry.auth import oidc
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.store import MessageStore
from messagefoundry.verify.federation import _RUNGS, run_federation_checks
from messagefoundry.verify.model import Status
from tests import test_auth_oidc as ladder
from tests import test_auth_oidc_service as svc
from tests import test_verify_federation as vf

#: The shipped default. Pinned here AND in tests/test_security_doc_drift.py, so moving it reds both
#: the behaviour tests and the documented decision table.
DEFAULT_MAX_AGE = 43200

#: The ladder tests use a fixed clock; test_auth_oidc._good_claims mints at this instant.
LADDER_NOW = 1_000_000
LADDER_CLOCK = LADDER_NOW + 100

#: The least session an accepted auth_time must leave (claims.MIN_RECENCY_REMAINING_SECONDS).
MIN_LEFT = 60


@pytest.fixture(scope="module")
def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _validate(rsa_key: rsa.RSAPrivateKey, claims: dict[str, Any], **policy: Any) -> Any:
    jws = ladder._mint(rsa_key, "k1", claims)
    return oidc.validate_id_token(
        jws, ladder._policy(**policy), ladder._cache_for(rsa_key), clock=lambda: LADDER_CLOCK
    )


def _refusal(rsa_key: rsa.RSAPrivateKey, claims: dict[str, Any], **policy: Any) -> str:
    with pytest.raises(oidc.ClaimsError) as exc:
        _validate(rsa_key, claims, **policy)
    return exc.value.reason


# --- part 1: the setting -----------------------------------------------------------------------------


def test_the_default_is_non_zero_and_bounded() -> None:
    assert AuthSettings().oidc_max_age_seconds == DEFAULT_MAX_AGE
    # The default must sit inside its own validator's range, or a stock config would not load.
    assert (
        AuthSettings(oidc_max_age_seconds=DEFAULT_MAX_AGE).oidc_max_age_seconds == DEFAULT_MAX_AGE
    )


@pytest.mark.parametrize("off", [None, 0, -1])
def test_there_is_no_off_switch(off: Any) -> None:
    """None and 0 are the two spellings an "off" would take. Both are refused at load."""
    with pytest.raises(ValidationError, match="oidc_max_age_seconds"):
        AuthSettings(oidc_max_age_seconds=off)


@pytest.mark.parametrize(
    ("value", "ok"), [(299, False), (300, True), (86400, True), (86401, False)]
)
def test_the_validator_clamps_both_ends(value: int, ok: bool) -> None:
    if ok:
        assert AuthSettings(oidc_max_age_seconds=value).oidc_max_age_seconds == value
    else:
        with pytest.raises(ValidationError, match="between 300 and 86400"):
            AuthSettings(oidc_max_age_seconds=value)


# --- part 2: the authorization URL -------------------------------------------------------------------


def _url(**over: Any) -> str:
    kwargs: dict[str, Any] = {
        "authorization_endpoint": "https://idp.example/authorize",
        "client_id": "mefor-console",
        "redirect_uri": "https://ops.example/ui/oidc/callback",
        "state": "st",
        "nonce": "no",
        "code_challenge": "ch",
        "scopes": ["openid"],
        "max_age": 3600,
    }
    kwargs.update(over)
    return oidc.build_authorization_url(**kwargs)


def test_the_authorization_url_sends_max_age() -> None:
    q = urllib.parse.parse_qs(urllib.parse.urlsplit(_url(max_age=3600)).query)
    assert q["max_age"] == ["3600"]


def test_max_age_has_no_default_on_the_url_builder() -> None:
    """A caller cannot build a URL that forgets max_age: the parameter is required."""
    kwargs: dict[str, Any] = {
        "authorization_endpoint": "https://idp.example/authorize",
        "client_id": "c",
        "redirect_uri": "https://ops.example/cb",
        "state": "s",
        "nonce": "n",
        "code_challenge": "ch",
        "scopes": ["openid"],
    }
    with pytest.raises(TypeError, match="max_age"):
        oidc.build_authorization_url(**kwargs)


@pytest.mark.parametrize("bad", [0, -5])
def test_the_url_builder_refuses_a_non_positive_max_age(bad: int) -> None:
    """max_age=0 is prompt=login under another name, which throws away single sign-on."""
    with pytest.raises(ValueError, match="max_age"):
        _url(max_age=bad)


async def test_the_service_sends_the_configured_max_age(rsa_key: rsa.RSAPrivateKey) -> None:
    """The setting reaches the wire, not just the builder: default, then an operator value."""
    for over, expected in (({}, str(DEFAULT_MAX_AGE)), ({"oidc_max_age_seconds": 900}, "900")):
        store = await MessageStore.open(":memory:")
        try:
            service = await svc._service(store, rsa_key, **over)
            _flow_id, url = await service.begin_oidc_login(
                client="127.0.0.1", public_origin="https://ops.example"
            )
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
            assert q["max_age"] == [expected]
        finally:
            await store.close()


# --- part 3: the claims ladder -----------------------------------------------------------------------


def test_a_missing_auth_time_is_refused(rsa_key: rsa.RSAPrivateKey) -> None:
    claims = ladder._good_claims()
    del claims["auth_time"]
    assert _refusal(rsa_key, claims) == "auth_time_missing"


def test_a_null_auth_time_is_the_same_fault_as_a_missing_one(rsa_key: rsa.RSAPrivateKey) -> None:
    assert _refusal(rsa_key, ladder._good_claims(auth_time=None)) == "auth_time_missing"


def test_a_stale_auth_time_is_refused(rsa_key: rsa.RSAPrivateKey) -> None:
    # 59 s of the bound left: one second under the minimum session the ladder insists on.
    stale = LADDER_CLOCK - DEFAULT_MAX_AGE + MIN_LEFT - 1
    assert _refusal(rsa_key, ladder._good_claims(auth_time=stale)) == "auth_time_stale"


def test_a_stale_auth_time_gets_no_clock_skew_grace(rsa_key: rsa.RSAPrivateKey) -> None:
    """Unlike exp, the stale side has no skew grace: a token past max_age but inside the 60 s skew
    would mint a session that is already dead, so the ladder refuses it outright."""
    inside_skew = LADDER_CLOCK - DEFAULT_MAX_AGE - 30
    assert _refusal(rsa_key, ladder._good_claims(auth_time=inside_skew)) == "auth_time_stale"


def test_the_stale_bound_follows_the_policy_value(rsa_key: rsa.RSAPrivateKey) -> None:
    """Discriminating control: the SAME token passes a wide bound and fails a narrow one, so the
    refusal is the comparison against max_age and not something else about the token."""
    claims = ladder._good_claims(auth_time=LADDER_CLOCK - 1000)
    assert _validate(rsa_key, claims, max_age_seconds=3600).auth_time == LADDER_CLOCK - 1000
    assert _refusal(rsa_key, claims, max_age_seconds=600) == "auth_time_stale"


def test_an_auth_time_leaving_the_minimum_session_is_accepted(rsa_key: rsa.RSAPrivateKey) -> None:
    edge = LADDER_CLOCK - DEFAULT_MAX_AGE + MIN_LEFT
    principal = _validate(rsa_key, ladder._good_claims(auth_time=edge))
    assert principal.auth_time == edge


def test_an_auth_time_in_the_future_is_refused(rsa_key: rsa.RSAPrivateKey) -> None:
    """A future authentication would push auth_time + max_age later than any real one could."""
    future = LADDER_CLOCK + 60 + 1
    assert _refusal(rsa_key, ladder._good_claims(auth_time=future)) == "issued_in_future"


@pytest.mark.parametrize("bad", ["1000000", True, [1_000_000], {"t": 1}])
def test_a_non_numeric_auth_time_is_malformed_not_missing(
    rsa_key: rsa.RSAPrivateKey, bad: Any
) -> None:
    assert _refusal(rsa_key, ladder._good_claims(auth_time=bad)) == "claim_not_numeric"


@pytest.mark.parametrize("claim", ["auth_time", "exp", "iat", "nbf"])
@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
def test_a_non_finite_time_claim_is_refused(
    rsa_key: rsa.RSAPrivateKey, claim: str, bad: float
) -> None:
    """json.loads accepts NaN and Infinity. NaN compares False against every bound, so a NaN exp
    used to pass the expiry check and then, inside the service's min(), drop the auth_time cap."""
    assert _refusal(rsa_key, ladder._good_claims(**{claim: bad})) == "claim_not_numeric"


def test_the_policy_refuses_to_be_built_without_a_bound() -> None:
    base: dict[str, Any] = {
        "issuer": "https://idp.example",
        "client_id": "c",
        "signing_algorithms": [],
        "nonce": "n",
    }
    with pytest.raises(TypeError, match="max_age_seconds"):
        oidc.OidcClaimPolicy(**base)
    for bad in (0, -1):
        with pytest.raises(ValueError, match="max_age_seconds"):
            oidc.OidcClaimPolicy(**base, max_age_seconds=bad)


def test_both_new_slugs_are_in_the_closed_set() -> None:
    assert {"auth_time_missing", "auth_time_stale"} <= oidc.REASONS


def test_each_new_slug_indicts_exactly_the_claims_rung() -> None:
    for slug in ("auth_time_missing", "auth_time_stale"):
        rungs = [rid for rid, _, reasons in _RUNGS if slug in reasons]
        assert rungs == ["fed.replay.claims"], (slug, rungs)


def test_the_recency_check_runs_before_the_nonce_rung(rsa_key: rsa.RSAPrivateKey) -> None:
    """The slugs sit in the claims rung, so the check must run before the nonce compare. A token
    failing BOTH must report the recency fault, or the verifier would blame the browser binding."""
    claims = ladder._good_claims(nonce="some-other-nonce")
    del claims["auth_time"]
    assert _refusal(rsa_key, claims) == "auth_time_missing"


# --- part 4: the typed principal field ---------------------------------------------------------------


def test_the_principal_carries_the_verified_auth_time(rsa_key: rsa.RSAPrivateKey) -> None:
    principal = _validate(rsa_key, ladder._good_claims(auth_time=LADDER_NOW - 42))
    assert principal.auth_time == LADDER_NOW - 42
    assert isinstance(principal.auth_time, float)


# --- part 5: the session deadline --------------------------------------------------------------------


async def _session_for(
    rsa_key: rsa.RSAPrivateKey,
    monkeypatch: pytest.MonkeyPatch,
    store: MessageStore,
    claims: dict[str, Any],
    **settings_over: Any,
) -> Any:
    service = await svc._service(store, rsa_key, **settings_over)
    svc._stub_exchange(monkeypatch, svc._mint(rsa_key, claims))
    return await service.authenticate_oidc(
        svc.AUTH_CODE, svc._flow(), redirect_uri="https://ops.example/ui/oidc/callback"
    )


async def test_the_session_ends_max_age_after_the_idp_authentication(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An IdP SSO session 11 hours old buys a 1-hour engine session, not a 12-hour one. The token's
    exp is 30 days out, so neither exp nor the absolute cap can be what binds here."""
    store = await MessageStore.open(":memory:")
    try:
        now = time.time()
        auth_time = now - 11 * 3600
        out = await _session_for(
            rsa_key,
            monkeypatch,
            store,
            svc._claims(exp=now + 30 * 86400, auth_time=auth_time),
        )
        assert out.ok and out.token is not None
        session = await store.get_session(hash_token(out.token))
        assert session is not None
        assert session.expires_at == pytest.approx(auth_time + DEFAULT_MAX_AGE, abs=2)
    finally:
        await store.close()


async def test_the_deadline_is_a_min_so_a_tighter_bound_still_wins(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A fresh IdP authentication must not LENGTHEN anything: exp and oidc_session_max_hours still
    bind when they are tighter than auth_time + max_age."""
    store = await MessageStore.open(":memory:")
    try:
        now = time.time()
        exp = now + 300
        out = await _session_for(rsa_key, monkeypatch, store, svc._claims(exp=exp, auth_time=now))
        assert out.ok and out.token is not None
        session = await store.get_session(hash_token(out.token))
        assert session is not None
        assert session.expires_at == pytest.approx(exp, abs=2)
    finally:
        await store.close()

    store = await MessageStore.open(":memory:")
    try:
        now = time.time()
        out = await _session_for(
            rsa_key,
            monkeypatch,
            store,
            svc._claims(exp=now + 30 * 86400, auth_time=now),
            oidc_session_max_hours=1,
        )
        assert out.ok and out.token is not None
        session = await store.get_session(hash_token(out.token))
        assert session is not None
        assert session.expires_at == pytest.approx(now + 3600, abs=2)
    finally:
        await store.close()


async def test_an_auth_time_just_past_max_age_never_mints_a_dead_session(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A deadline already behind now is refused under the recency slug and audited, never minted
    as a session that dies on its first request."""
    store = await MessageStore.open(":memory:")
    try:
        now = time.time()
        out = await _session_for(
            rsa_key,
            monkeypatch,
            store,
            svc._claims(auth_time=now - DEFAULT_MAX_AGE - 10),
        )
        assert not out.ok and out.token is None
        assert out.reason == "auth_time_stale"
        rows = await svc._audit_rows(store, "auth.login_failed")
        assert any('"reason": "auth_time_stale"' in (r["detail"] or "") for r in rows)
    finally:
        await store.close()


async def test_a_missing_auth_time_refuses_the_federated_login(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = await MessageStore.open(":memory:")
    try:
        claims = svc._claims()
        del claims["auth_time"]
        out = await _session_for(rsa_key, monkeypatch, store, claims)
        assert not out.ok and out.token is None
        assert out.reason == "auth_time_missing"
        rows = await svc._audit_rows(store, "auth.login_failed")
        assert any('"reason": "auth_time_missing"' in (r["detail"] or "") for r in rows)
    finally:
        await store.close()


async def test_the_service_backstop_refuses_a_deadline_that_passed_after_the_ladder(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The ladder leaves at least a minute; the LDAP round trip after it can eat that. Drive the
    service branch directly with a principal whose deadline is already behind now."""
    store = await MessageStore.open(":memory:")
    try:
        service = await svc._service(store, rsa_key)
        now = time.time()
        principal = oidc.FederatedPrincipal(
            username="jdoe",
            subject="S-1-5-21-federated",
            issuer="https://idp.example",
            amr=("mfa",),
            acr=None,
            expires_at=now + 3600,
            auth_time=now - DEFAULT_MAX_AGE - 1,
        )
        monkeypatch.setattr(service, "_exchange_and_validate", lambda *_a: principal)
        out = await service.authenticate_oidc(
            svc.AUTH_CODE, svc._flow(), redirect_uri="https://ops.example/ui/oidc/callback"
        )
        assert not out.ok and out.token is None
        assert out.reason == "auth_time_stale"
        rows = await svc._audit_rows(store, "auth.login_failed")
        assert any('"reason": "auth_time_stale"' in (r["detail"] or "") for r in rows)
    finally:
        await store.close()


async def test_a_future_auth_time_inside_the_skew_cannot_lengthen_the_session(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The ladder accepts an IdP clock up to the skew ahead. The service clamps auth_time to now,
    so the session still ends max_age from now and not max_age plus the IdP's lead."""
    store = await MessageStore.open(":memory:")
    try:
        now = time.time()
        out = await _session_for(
            rsa_key,
            monkeypatch,
            store,
            svc._claims(exp=now + 30 * 86400, auth_time=now + 30),
            oidc_max_age_seconds=3600,
        )
        assert out.ok and out.token is not None
        session = await store.get_session(hash_token(out.token))
        assert session is not None
        assert session.expires_at == pytest.approx(now + 3600, abs=2)
    finally:
        await store.close()


async def test_a_nan_exp_cannot_drop_the_recency_cap(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End to end: an 11-hour-old IdP sign-in with exp=NaN used to mint a 12-hour session, because
    NaN passed the expiry check and then won the min(). It is refused as malformed now."""
    store = await MessageStore.open(":memory:")
    try:
        out = await _session_for(
            rsa_key,
            monkeypatch,
            store,
            svc._claims(exp=float("nan"), auth_time=time.time() - 11 * 3600),
        )
        assert not out.ok and out.token is None
        assert out.reason == "claim_not_numeric"
    finally:
        await store.close()


# --- the offline verifier ----------------------------------------------------------------------------


def _replay(rsa_key: rsa.RSAPrivateKey, tmp_path: Path, token: str) -> dict[str, Any]:
    tok = tmp_path / "t.jwt"
    tok.write_text(token, encoding="ascii")
    jwks = tmp_path / "j.json"
    jwks.write_bytes(vf._jwks_bytes(rsa_key))
    return vf._by_id(
        run_federation_checks(
            vf._settings(), id_token_file=str(tok), jwks_file=str(jwks), nonce=vf.NONCE
        )
    )


def test_the_verifier_reports_the_bound_as_a_manual_config_row() -> None:
    rows = vf._by_id(run_federation_checks(vf._settings(oidc_max_age_seconds=900)))
    assert rows["fed.max_age"].status is Status.MANUAL
    assert "max_age=900s" in rows["fed.max_age"].evidence


def test_a_replayed_token_missing_auth_time_fails_the_claims_rung(
    rsa_key: rsa.RSAPrivateKey, tmp_path: Path
) -> None:
    """A missing auth_time is an IdP ignoring max_age: a real deployment defect, so FAIL."""
    now = time.time()
    claims = {
        "iss": "https://idp.example",
        "aud": "mefor-console",
        "sub": "S-1-5-21-fed",
        "exp": now + 600,
        "iat": now,
        "nonce": vf.NONCE,
        "preferred_username": "jdoe@corp.example",
        "amr": ["pwd", "mfa"],
    }
    rows = _replay(rsa_key, tmp_path, vf._mint_raw(rsa_key, claims))
    assert rows["fed.replay.claims"].status is Status.FAIL
    assert "auth_time_missing" in rows["fed.replay.claims"].detail
    assert rows["fed.replay.nonce"].status is Status.SKIP


def test_a_replayed_token_with_a_live_exp_and_an_old_auth_time_fails(
    rsa_key: rsa.RSAPrivateKey, tmp_path: Path
) -> None:
    """exp is checked first, so a merely old capture reads as expired and SKIPs. A token whose exp
    is still live but whose auth_time is past max_age is an IdP that answered a max_age request with
    an old sign-in instead of re-authenticating: a deployment defect, so FAIL, never SKIP."""
    token = vf._mint(rsa_key, auth_time=time.time() - DEFAULT_MAX_AGE - 3600)
    rows = _replay(rsa_key, tmp_path, token)
    assert rows["fed.replay.claims"].status is Status.FAIL
    assert "auth_time_stale" in rows["fed.replay.claims"].detail
    assert rows["fed.replay.nonce"].status is Status.SKIP


def test_a_replayed_good_token_shows_auth_time_in_the_principal_row(
    rsa_key: rsa.RSAPrivateKey, tmp_path: Path
) -> None:
    rows = _replay(rsa_key, tmp_path, vf._mint(rsa_key))
    assert rows["fed.replay.claims"].status is Status.PASS
    assert "auth_time=" in rows["fed.replay.principal"].evidence
