# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2325: the OIDC ``acr``/``amr`` settings, hardened.

Before this, a TOML list ``[""]`` was truthy, so it passed the MFA-family guard at load, and the claim
gate then compared raw values. A blank required ``acr`` accepted a token whose ``acr`` was ``""`` as
MFA, and a blank ``amr`` did the same for an ``amr`` holding ``""``. Each test below comes with a near
neighbour that must still pass, so a check that refused everything would fail here too.
"""

from __future__ import annotations

import urllib.parse
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from messagefoundry.auth import oidc
from messagefoundry.auth.oidc import claims as claims_mod
from messagefoundry.checks import _check_oidc_auth_params
from messagefoundry.config.models import SignatureAlgorithm
from messagefoundry.config.settings import AuthSettings


def _oidc(**over: Any) -> AuthSettings:
    """OIDC-enabled auth settings with the fields the model requires (it needs AD for roles)."""
    base: dict[str, Any] = {
        "ad_enabled": True,
        "ad_server": "ldaps://dc.test.invalid",
        "ad_user_search_base": "OU=Staff,DC=test,DC=invalid",
        "ad_bind_dn": "CN=svc-mefor,OU=Service,DC=test,DC=invalid",
        "ad_bind_password": "synthetic",
        "ad_domain": "test.invalid",
        "oidc_enabled": True,
        "oidc_issuer": "https://idp.test.invalid",
        "oidc_client_id": "mefor-console",
        "oidc_client_secret": "synthetic",
        "oidc_authorization_endpoint": "https://idp.test.invalid/authorize",
        "oidc_token_endpoint": "https://idp.test.invalid/token",
        "oidc_jwks_uri": "https://idp.test.invalid/jwks",
        "oidc_allowed_endpoints": ["idp.test.invalid"],
    }
    base.update(over)
    return AuthSettings(**base)


# --- load: list values are stripped and blanks dropped, in the list form too ----------------------


@pytest.mark.parametrize("blank", [[""], ["  "], ["", "\t"]])
def test_a_blank_only_amr_list_leaves_no_gate_and_is_refused(blank: list[str]) -> None:
    """The amendment's shape: ``oidc_mfa_amr_values = [""]`` with no acr list. It used to load, and
    the gate then accepted an ``amr`` holding ``""``. Normalised, the list is empty, so the gate
    can never match and the existing refusal fires."""
    with pytest.raises(ValidationError, match="MFA gate that can never match"):
        _oidc(oidc_mfa_amr_values=blank, oidc_required_acr_values=[])


def test_a_blank_only_acr_list_with_no_amr_is_refused() -> None:
    with pytest.raises(ValidationError, match="MFA gate that can never match"):
        _oidc(oidc_mfa_amr_values=[], oidc_required_acr_values=["", " "])


def test_list_values_are_stripped_and_blanks_dropped() -> None:
    """The near neighbour: real values survive, stripped, in their order."""
    auth = _oidc(
        oidc_mfa_amr_values=["", " mfa ", "hwk"],
        oidc_required_acr_values=[" phr", "", "phrh "],
    )
    assert auth.oidc_mfa_amr_values == ["mfa", "hwk"]
    assert auth.oidc_required_acr_values == ["phr", "phrh"]


def test_the_env_string_form_is_normalised_as_before() -> None:
    auth = _oidc(oidc_mfa_amr_values=" mfa , ,hwk", oidc_required_acr_values="")
    assert auth.oidc_mfa_amr_values == ["mfa", "hwk"]
    assert auth.oidc_required_acr_values == []


def test_the_list_normalising_is_scoped_to_the_claim_lists() -> None:
    """Only the two lists compared with a token claim lose blanks. A blank signing algorithm is
    still refused at load, as before, rather than dropped into an empty list that refuses every
    login at runtime."""
    with pytest.raises(ValidationError, match="must all be supported"):
        _oidc(oidc_signing_algorithms=[""])


def test_a_non_string_list_item_is_still_refused_by_its_type() -> None:
    """The normaliser leaves a non-string item alone, so the field's own type check refuses it."""
    with pytest.raises(ValidationError):
        _oidc(oidc_mfa_amr_values=["mfa", 7])


# --- load: the acr request ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "loaded"), [("   ", None), ("\t\n", None), (" phr  phrh ", "phr phrh")]
)
def test_the_acr_request_is_normalised(raw: str, loaded: str | None) -> None:
    """A whitespace-only request names no class, so it loads as None and is never sent."""
    auth = _oidc(oidc_acr_values=raw, oidc_required_acr_values=["phr", "phrh"])
    assert auth.oidc_acr_values == loaded


def test_an_acr_request_while_the_gate_is_off_is_refused() -> None:
    """Finding 1. With ``oidc_require_mfa_claim`` off, ``_check_mfa_gate`` returns before it reads
    ``acr``, so the request is checked by nothing, even with a required list set."""
    with pytest.raises(ValidationError) as caught:
        _oidc(
            oidc_require_mfa_claim=False,
            oidc_acr_values="urn:example:acr-sentinel",
            oidc_required_acr_values=["urn:example:acr-sentinel"],
        )
    text = str(caught.value)
    assert "while oidc_require_mfa_claim is false" in text
    # The refusal names the keys and never quotes the configured value.
    assert "acr-sentinel" not in text


@pytest.mark.parametrize(
    "over",
    [
        {"oidc_require_mfa_claim": False},  # the gate off with no request
        {"oidc_require_mfa_claim": False, "oidc_acr_values": "   "},  # a blank request is none
        {"oidc_acr_values": "phr", "oidc_required_acr_values": ["phr"]},  # the gate on
    ],
)
def test_the_near_neighbours_of_the_gate_off_refusal_load(over: dict[str, Any]) -> None:
    assert _oidc(**over).oidc_enabled is True


def test_an_acr_request_is_not_refused_while_oidc_is_off() -> None:
    """No authorization request is built with OIDC off, so there is nothing to refuse."""
    auth = AuthSettings(oidc_require_mfa_claim=False, oidc_acr_values="phr")
    assert auth.oidc_acr_values == "phr"


# --- the claim gate: a blank configured value never matches --------------------------------------


def _policy(**over: Any) -> oidc.OidcClaimPolicy:
    base: dict[str, Any] = {
        "issuer": "https://idp.test.invalid",
        "client_id": "mefor-console",
        "signing_algorithms": [SignatureAlgorithm.RS256],
        "nonce": "n",
        "max_age_seconds": 43200,
    }
    base.update(over)
    return oidc.OidcClaimPolicy(**base)


@pytest.mark.parametrize(
    "claims",
    [
        pytest.param({"amr": ["pwd"], "acr": ""}, id="empty-acr"),
        pytest.param({"amr": ["pwd"]}, id="no-acr-claim-at-all"),
        pytest.param({}, id="no-amr-and-no-acr"),
    ],
)
def test_a_blank_required_acr_accepts_no_token(claims: dict[str, object]) -> None:
    """A policy built by another constructor can still hold a blank value, so the gate ignores one."""
    policy = _policy(mfa_amr_values=[], required_acr_values=["", " "])
    with pytest.raises(oidc.ClaimsError) as caught:
        claims_mod._check_mfa_gate(claims, policy)
    assert caught.value.reason == "mfa_claim_missing"


def test_a_blank_amr_value_accepts_no_token() -> None:
    policy = _policy(mfa_amr_values=[""], required_acr_values=[])
    with pytest.raises(oidc.ClaimsError):
        claims_mod._check_mfa_gate({"amr": [""]}, policy)


def test_a_none_list_from_another_constructor_is_no_values() -> None:
    """The old falsy check read None as no values; the blank filter must not raise on it."""
    assert oidc.accepted_claim_values(None) == frozenset()  # type: ignore[arg-type]
    with pytest.raises(oidc.ClaimsError):
        claims_mod._check_mfa_gate(
            {"amr": ["mfa"]}, _policy(mfa_amr_values=None, required_acr_values=["phr"])
        )


def test_a_bare_string_is_one_value_and_a_non_string_matches_nothing() -> None:
    """A bare ``"mfa"`` is one value, never the letters m, f and a, and a non-string item refuses
    through ClaimsError rather than raising outside it."""
    with pytest.raises(oidc.ClaimsError):
        claims_mod._check_mfa_gate({"amr": ["m"]}, _policy(mfa_amr_values="mfa"))
    claims_mod._check_mfa_gate({"amr": ["mfa"]}, _policy(mfa_amr_values="mfa"))
    with pytest.raises(oidc.ClaimsError):
        claims_mod._check_mfa_gate({"amr": ["pwd"]}, _policy(mfa_amr_values=[None]))


@pytest.mark.parametrize(
    ("claims", "policy_over"),
    [
        (
            {"amr": ["pwd"], "acr": "phr"},
            {"mfa_amr_values": [], "required_acr_values": ["", "phr"]},
        ),
        ({"amr": ["mfa"]}, {"mfa_amr_values": ["", "mfa"], "required_acr_values": []}),
    ],
)
def test_a_real_value_beside_a_blank_still_matches(
    claims: dict[str, object], policy_over: dict[str, Any]
) -> None:
    """The control: the gate still accepts a configured, non-blank value."""
    claims_mod._check_mfa_gate(claims, _policy(**policy_over))


# --- the authorization request --------------------------------------------------------------------


def _acr_param(acr_values: str | None) -> list[str] | None:
    url = oidc.build_authorization_url(
        authorization_endpoint="https://idp.test.invalid/authorize",
        client_id="mefor-console",
        redirect_uri="https://ops.test.invalid/ui/oidc/callback",
        state="st",
        nonce="no",
        code_challenge="ch",
        scopes=["openid", "profile"],
        max_age=43200,
        acr_values=acr_values,
    )
    return urllib.parse.parse_qs(urllib.parse.urlsplit(url).query).get("acr_values")


def test_a_blank_acr_request_is_not_sent() -> None:
    assert _acr_param("   ") is None
    assert _acr_param(None) is None
    assert _acr_param(" phr  phrh ") == ["phr phrh"]  # the control: a real request still goes


# --- the check note no longer overclaims -----------------------------------------------------------


def _toml(tmp_path: Path, extra: str) -> Path:
    path = tmp_path / "messagefoundry.toml"
    path.write_text(
        '[store]\nbackend = "sqlite"\n\n[ai]\nenvironment = "dev"\n\n'
        "[security]\nblock_unlisted_outbound = true\n"
        'web_console_public_address = "https://mefor.example.invalid"\n\n'
        "[auth]\nad_enabled = true\n"
        'ad_server = "ldaps://dc.example.invalid"\n'
        'ad_user_search_base = "dc=example,dc=invalid"\n'
        'ad_bind_dn = "cn=svc,dc=example,dc=invalid"\n'
        'ad_bind_password = "placeholder-not-a-real-secret"\n'
        "oidc_enabled = true\n"
        'oidc_issuer = "https://idp.example.invalid"\n'
        'oidc_client_id = "mefor-console"\n'
        'oidc_client_secret = "placeholder-not-a-real-secret"\n'
        'oidc_authorization_endpoint = "https://idp.example.invalid/authorize"\n'
        'oidc_token_endpoint = "https://idp.example.invalid/token"\n'
        'oidc_jwks_uri = "https://idp.example.invalid/jwks"\n'
        'oidc_allowed_endpoints = ["idp.example.invalid"]\n'
        'oidc_allowed_username_domains = ["example.invalid"]\n' + extra,
        encoding="utf-8",
    )
    return path


def test_the_required_acr_note_says_the_amr_arm_still_admits(tmp_path: Path) -> None:
    """Finding 5. With the default ``oidc_mfa_amr_values`` a token with no acr still signs in on its
    amr, so the note must not say the required list refuses a login without the class."""
    result = _check_oidc_auth_params(
        tmp_path, service_config=_toml(tmp_path, 'oidc_required_acr_values = ["phr"]\n')
    )
    assert "never asked for the assurance" in result.detail
    assert "refuses a login without" not in result.detail
    assert "signs in without one" in result.detail


def test_the_note_drops_the_amr_clause_when_no_amr_is_accepted(tmp_path: Path) -> None:
    result = _check_oidc_auth_params(
        tmp_path,
        service_config=_toml(
            tmp_path, 'oidc_required_acr_values = ["phr"]\noidc_mfa_amr_values = []\n'
        ),
    )
    assert "never asked for the assurance" in result.detail
    assert "signs in without one" not in result.detail
    # With no amr value the acr arm is the only one, so here the list does refuse such a login.
    assert "refuses a login without that acr" in result.detail


def test_the_note_says_a_required_acr_is_inert_with_the_gate_off(tmp_path: Path) -> None:
    """A required list with the gate off still loads (no request is sent), and the note must not
    say the list accepts anything as MFA: the gate reads no acr then."""
    result = _check_oidc_auth_params(
        tmp_path,
        service_config=_toml(
            tmp_path, 'oidc_require_mfa_claim = false\noidc_required_acr_values = ["phr"]\n'
        ),
    )
    assert result.ok is True
    assert "accepts no token as MFA" in result.detail
    assert "signs in without one" not in result.detail


def test_an_acr_request_with_the_gate_off_is_a_load_failure_in_check(tmp_path: Path) -> None:
    result = _check_oidc_auth_params(
        tmp_path,
        service_config=_toml(
            tmp_path,
            'oidc_require_mfa_claim = false\noidc_acr_values = "phr"\n'
            'oidc_required_acr_values = ["phr"]\n',
        ),
    )
    assert result.ok is False
    assert "settings did not load" in result.detail
    assert "while oidc_require_mfa_claim is false" in result.detail
