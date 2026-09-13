# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The OIDC authorization-parameter advisory (#1159, ASVS 10.2.3).

``smart-scope`` covers the outbound SMART leg of "the OAuth client only requests the required scopes
(or other authorization parameters)". This is the relying-party leg. Four ``[auth]`` settings reach
the authorization URL through no content check at all -- ``oidc_scopes`` (its only validator
comma-splits an env string and screens nothing), ``oidc_acr_values``, ``oidc_prompt``, and
``oidc_username_claim``, which is the setting that decides which of them is actually required.

**The discriminator is the point, not the plumbing.** A check that reported every configuration, or
none, would be useless in the same way, so every test here comes in a pair: a configuration that
must fire and a near neighbour that must stay quiet. The clean case at the bottom is the negative
control for the whole file -- it uses the shipped defaults, which are already minimal
(``preferred_username`` lives in ``profile``), and an advisory that fired on it would teach operators
to ignore the line.

The load-bearing test is ``test_a_username_claim_whose_scope_is_not_requested_fires``. That is not a
least-privilege report: on a first deployment it would be a federated login that fails at its last
hop, on a live user, raising ``username_claim_missing`` -- and it is computable the moment the config
loads.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from messagefoundry.checks import _check_oidc_auth_params

_OIDC_BASE = {
    "ad_enabled": "true",
    "ad_server": '"ldaps://dc.example.invalid"',
    "ad_user_search_base": '"dc=example,dc=invalid"',
    "ad_bind_dn": '"cn=svc,dc=example,dc=invalid"',
    "ad_bind_password": '"placeholder-not-a-real-secret"',
    "oidc_enabled": "true",
    "oidc_issuer": '"https://idp.example.invalid"',
    "oidc_client_id": '"mefor-console"',
    "oidc_client_secret": '"placeholder-not-a-real-secret"',
    "oidc_authorization_endpoint": '"https://idp.example.invalid/authorize"',
    "oidc_token_endpoint": '"https://idp.example.invalid/token"',
    "oidc_jwks_uri": '"https://idp.example.invalid/jwks"',
    "oidc_allowed_endpoints": '["idp.example.invalid"]',
    "oidc_allowed_username_domains": '["example.invalid"]',
}


def _toml(tmp_path: Path, **auth: str) -> Path:
    """Write a minimal ``messagefoundry.toml`` with ``[auth]`` overrides applied to the OIDC base."""
    merged = {**_OIDC_BASE, **auth}
    body = "\n".join(f"{k} = {v}" for k, v in merged.items())
    path = tmp_path / "messagefoundry.toml"
    path.write_text(
        # The redirect origin is `[security].web_console_public_address`; `[api].public_origin` is
        # the retired spelling and is REFUSED at load (ADR 0118), so using it here would make every
        # assertion in this file read a "settings did not load" detail instead of the advisory.
        '[store]\nbackend = "sqlite"\n\n'
        '[ai]\nenvironment = "dev"\n\n'
        "[security]\nblock_unlisted_outbound = true\n"
        'web_console_public_address = "https://mefor.example.invalid"\n\n'
        f"[auth]\n{body}\n",
        encoding="utf-8",
    )
    return path


def _detail(tmp_path: Path, **auth: str) -> str:
    result = _check_oidc_auth_params(tmp_path, service_config=_toml(tmp_path, **auth))
    assert result.name == "oidc-auth-params"
    assert result.required is False, "this advisory must never gate the commit check"
    assert result.ok is True
    return result.detail


# --- the load-bearing case: a login that would fail at its last hop ----------------------------


def test_a_username_claim_whose_scope_is_not_requested_fires(tmp_path: Path) -> None:
    """``email`` as the username claim without the ``email`` scope is a broken login, not a
    preference. Every federated sign-in would reach ``username_claim_missing``."""
    detail = _detail(tmp_path, oidc_username_claim='"email"', oidc_scopes='["openid", "profile"]')
    assert "username_claim_missing" in detail
    assert "'email'" in detail


def test_the_same_claim_with_its_scope_requested_stays_quiet(tmp_path: Path) -> None:
    """The near neighbour. Adding the scope must silence it -- a check that fired on both would be
    reporting the claim rather than the mismatch."""
    detail = _detail(tmp_path, oidc_username_claim='"email"', oidc_scopes='["openid", "email"]')
    assert "username_claim_missing" not in detail


# --- over-grant, at scope granularity ----------------------------------------------------------


def test_a_scope_carrying_no_claim_the_engine_reads_fires(tmp_path: Path) -> None:
    detail = _detail(tmp_path, oidc_scopes='["openid", "profile", "email", "address"]')
    assert "carry no claim this engine reads" in detail
    assert "'address'" in detail and "'email'" in detail
    assert "'profile'" not in detail, "profile carries preferred_username and is required here"


def test_a_custom_username_claim_suppresses_the_over_grant_arm(tmp_path: Path) -> None:
    """Which scope carries a non-standard claim is the identity provider's to say, so no over-grant
    conclusion is drawn from it. Reporting one would be inventing a requirement."""
    detail = _detail(
        tmp_path,
        oidc_username_claim='"urn:acme:upn"',
        oidc_scopes='["openid", "profile", "address"]',
    )
    assert "carry no claim this engine reads" not in detail
    assert "not an OIDC Core standard claim" in detail


def test_a_missing_openid_scope_fires(tmp_path: Path) -> None:
    detail = _detail(tmp_path, oidc_scopes='["profile"]')
    assert "omits 'openid'" in detail


# --- the ACR asymmetry, both directions --------------------------------------------------------


def test_requiring_an_acr_the_request_never_asks_for_fires(tmp_path: Path) -> None:
    """The engine would refuse a login for an assurance level it never asked the provider to apply."""
    detail = _detail(tmp_path, oidc_required_acr_values='["phr"]')
    assert "never asked for the assurance" in detail


def test_requesting_an_acr_that_is_not_enforced_fires(tmp_path: Path) -> None:
    detail = _detail(tmp_path, oidc_acr_values='"phr"')
    assert "does not enforce on the returned token" in detail


def test_a_matched_acr_pair_stays_quiet(tmp_path: Path) -> None:
    """Both arms silent when the request and the requirement agree -- the discriminator for the two
    above, which a check that always reported an ACR line would fail."""
    detail = _detail(tmp_path, oidc_acr_values='"phr"', oidc_required_acr_values='["phr"]')
    assert "acr" not in detail.lower()


# --- prompt ------------------------------------------------------------------------------------


def test_an_unknown_prompt_value_fires(tmp_path: Path) -> None:
    detail = _detail(tmp_path, oidc_prompt='"reauthenticate"')
    assert "outside the OIDC Core set" in detail


def test_none_combined_with_another_prompt_fires(tmp_path: Path) -> None:
    detail = _detail(tmp_path, oidc_prompt='"none login"')
    assert "'none' to appear alone" in detail


def test_a_known_prompt_value_stays_quiet(tmp_path: Path) -> None:
    detail = _detail(tmp_path, oidc_prompt='"login"')
    assert "prompt" not in detail.lower()


# --- the negative control for the whole file, and the two non-findings -------------------------


def test_the_shipped_defaults_report_clean(tmp_path: Path) -> None:
    """``["openid", "profile"]`` with ``preferred_username`` is exactly minimal, and the check must
    say so out loud rather than going quiet -- an absent line is indistinguishable from a check that
    did not run. This is the control that proves the assertions above are not passing on noise."""
    detail = _detail(tmp_path)
    assert "asks for exactly what it reads" in detail
    assert "preferred_username" in detail


def test_oidc_disabled_reports_that_and_stops(tmp_path: Path) -> None:
    path = tmp_path / "messagefoundry.toml"
    path.write_text(
        '[store]\nbackend = "sqlite"\n\n[ai]\nenvironment = "dev"\n\n'
        "[security]\nblock_unlisted_outbound = true\n",
        encoding="utf-8",
    )
    result = _check_oidc_auth_params(tmp_path, service_config=path)
    assert result.ok is True and result.skipped is False
    assert "oidc_enabled=false" in result.detail


def test_no_service_toml_skips(tmp_path: Path) -> None:
    result = _check_oidc_auth_params(tmp_path, suppress_search=True)
    assert result.skipped is True


def test_a_present_but_unloadable_config_fails_rather_than_skipping(tmp_path: Path) -> None:
    """Present-but-refused is a failure, not a skip (BACKLOG #1318): rendering both states
    identically is what let a shipped config pass a gate that had actually rejected it."""
    path = tmp_path / "messagefoundry.toml"
    path.write_text('[store]\nbackend = "not-a-backend"\n', encoding="utf-8")
    result = _check_oidc_auth_params(tmp_path, service_config=path)
    assert result.ok is False and result.skipped is False
    assert "settings did not load" in result.detail


def test_the_advisory_is_registered_in_run_checks() -> None:
    """A check nothing calls reports nothing. Pinned by source, because ``run_checks`` needs a real
    config dir to execute and this asserts wiring rather than behaviour."""
    import inspect

    from messagefoundry import checks

    assert "_check_oidc_auth_params(" in inspect.getsource(checks.run_checks)


@pytest.mark.parametrize("claim", ["name", "given_name", "family_name", "nickname"])
def test_every_profile_claim_is_attributed_to_profile(tmp_path: Path, claim: str) -> None:
    """The scope table is only useful if it covers the claims an operator would actually pick. Each
    of these must be satisfied by ``profile`` and must not report a missing scope."""
    detail = _detail(tmp_path, oidc_username_claim=f'"{claim}"')
    assert "username_claim_missing" not in detail
    assert "not an OIDC Core standard claim" not in detail


# --- the issuer/endpoint split (#1158, ASVS 10.2.2) ---------------------------------------------


def test_an_endpoint_on_a_different_host_from_the_issuer_fires(tmp_path: Path) -> None:
    """Nothing else relates the four pinned OIDC settings to each other. `_require_oidc_fields`
    checks each independently for https and for allow-list membership, so a configuration that
    authorizes the browser at one host and POSTs the code, the PKCE verifier and the client secret
    to another loads clean -- the shape RFC 9700 section 4.4.2 names."""
    detail = _detail(
        tmp_path,
        oidc_token_endpoint='"https://tokens.example.invalid/token"',
        oidc_allowed_endpoints='["idp.example.invalid", "tokens.example.invalid"]',
    )
    assert "oidc_token_endpoint=tokens.example.invalid" in detail
    assert "idp.example.invalid" in detail


def test_all_four_on_one_host_stays_quiet(tmp_path: Path) -> None:
    """The discriminator. The base fixture puts every endpoint on the issuer's host, so a check
    that reported the split unconditionally would fire here too."""
    detail = _detail(tmp_path)
    assert "oidc_issuer is hosted at" not in detail


def test_the_split_is_reported_and_not_refused(tmp_path: Path) -> None:
    """ADVISORY BY DESIGN, and the reason is the specification rather than caution. OIDC Discovery
    makes the issuer an IDENTIFIER whose metadata may advertise endpoints on any host, so host
    equality is not a property a conforming provider must have. Refusing on it would reject correct
    configurations, which is why this asserts the config still LOADS while the note is emitted."""
    result = _check_oidc_auth_params(
        tmp_path,
        service_config=_toml(
            tmp_path,
            oidc_jwks_uri='"https://keys.example.invalid/jwks"',
            oidc_allowed_endpoints='["idp.example.invalid", "keys.example.invalid"]',
        ),
    )
    assert result.ok is True and result.required is False and result.skipped is False
    assert "settings did not load" not in result.detail
    assert "oidc_jwks_uri=keys.example.invalid" in result.detail
