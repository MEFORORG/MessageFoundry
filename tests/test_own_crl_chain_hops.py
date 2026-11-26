# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #5511, the hops with CRL settings of their own: an opt-in whole-chain check.

The OIDC legs (``[auth].oidc_tls_crl_file``) and the LDAPS bind (``[auth].ad_tls_crl_file``) set
only the leaf CRL flag, so with a two-tier PKI a server whose intermediate CA the root's CRL
revokes completes the handshake. ``[auth].oidc_tls_crl_check_chain`` and
``[auth].ad_tls_crl_check_chain`` turn on the whole-chain check there. Each needs the hop's CRL
file and its own CA file, and is refused at load without them, so no chain check runs on the OS
trust store. Off, each hop keeps the leaf check.

The two-tier PKI and the in-memory handshake are the API suite's: the "client" leaf it mints
carries ``localhost`` and serverAuth, so here it is the server's certificate, sent with its
intermediate. All material is synthetic and minted there. No PHI.
"""

from __future__ import annotations

import gc
import ssl
from collections.abc import Callable
from pathlib import Path

import pytest
from pydantic import ValidationError

from messagefoundry.auth.oidc_http import build_idp_opener
from messagefoundry.config.settings import AuthSettings
from messagefoundry.config.tls_policy import assert_ldap3_tls_suites
from messagefoundry.pipeline import crl_reload
from messagefoundry.transports.rest import opener_tls_context
from tests import test_api_tls_client_trust as _api_suite
from tests.test_api_tls_client_trust import _TwoTier
from tests.test_outbound_crl_chain import _server
from tests.test_trust_anchor_byte_binding import _handshake

# Fixtures bound by name, so pytest applies them in this module too.
two_tier = _api_suite.two_tier
_fresh_registry = _api_suite._fresh_registry

_OIDC_CHAIN = "[auth].oidc_tls_crl_check_chain"
_AD_CHAIN = "[auth].ad_tls_crl_check_chain"

#: A hop's context builder: CA file, CRL file, and whether the chain check is on.
_Build = Callable[..., ssl.SSLContext]


def _oidc_context(ca_file: Path, crl: Path, *, chain: bool) -> ssl.SSLContext:
    opener = build_idp_opener(
        str(ca_file), enforcing=False, crl_file=str(crl), crl_check_chain=chain
    )
    ctx = opener_tls_context(opener, connector="OIDC (test)")
    assert ctx is not None
    return ctx


def _ldaps_context(ca_file: Path, crl: Path, *, chain: bool) -> ssl.SSLContext:
    factory = assert_ldap3_tls_suites(
        validate=ssl.CERT_REQUIRED,
        ca_certs_data=ca_file.read_text(encoding="ascii"),
        connector="LDAPS (test)",
        crl_file=str(crl),
        crl_check_chain=chain,
    )
    # A bind builds a fresh context from the same recipe; check one of those too.
    return factory()


_HOPS = pytest.mark.parametrize("build", [_oidc_context, _ldaps_context], ids=["oidc", "ldaps"])
_HOPS_WITH_SETTINGS = pytest.mark.parametrize(
    ("build", "chain_setting", "ca_setting"),
    [
        (_oidc_context, _OIDC_CHAIN, "[auth].oidc_tls_ca_cert_file"),
        (_ldaps_context, _AD_CHAIN, "[auth].ad_tls_ca_cert_file"),
    ],
    ids=["oidc", "ldaps"],
)


@_HOPS
def test_a_revoked_intermediate_refuses_its_servers(build: _Build, two_tier: _TwoTier) -> None:
    """Red before the fix: the leaf flag alone never read the root's CRL, so the server got in."""
    ctx = build(two_tier.root_file, two_tier.revokes_intermediate, chain=True)
    assert ctx.verify_flags & ssl.VERIFY_CRL_CHECK_CHAIN == ssl.VERIFY_CRL_CHECK_CHAIN
    assert not ctx.verify_flags & ssl.VERIFY_X509_PARTIAL_CHAIN
    with pytest.raises(ssl.SSLError, match="revoked"):
        _handshake(ctx, _server(two_tier))


@_HOPS
def test_the_chain_check_admits_a_server_whose_chain_nobody_revoked(
    build: _Build, two_tier: _TwoTier
) -> None:
    """The control for the refusal above: the chain flag is not a CRL that refuses everyone."""
    _handshake(build(two_tier.root_file, two_tier.revokes_nothing, chain=True), _server(two_tier))


@_HOPS
def test_off_the_hop_keeps_the_leaf_check(build: _Build, two_tier: _TwoTier) -> None:
    """Unset, nothing changes: the leaf flag alone, and the revoked intermediate still gets in."""
    ctx = build(two_tier.root_file, two_tier.revokes_intermediate, chain=False)
    assert ctx.verify_flags & ssl.VERIFY_CRL_CHECK_CHAIN == ssl.VERIFY_CRL_CHECK_LEAF
    _handshake(ctx, _server(two_tier))


@_HOPS_WITH_SETTINGS
def test_a_crl_file_missing_a_cas_own_crl_refuses_naming_the_hops_settings(
    build: _Build, chain_setting: str, ca_setting: str, two_tier: _TwoTier
) -> None:
    """The start rule, worded for this hop's server chain and its own settings, never [tls]'s."""
    with pytest.raises(ValueError) as caught:
        build(two_tier.root_file, two_tier.inter_crl_file, chain=True)
    text = str(caught.value)
    assert "no CRL of their own" in text
    assert chain_setting in text
    assert ca_setting in text
    assert "[tls]." not in text
    assert "client" not in text


@_HOPS_WITH_SETTINGS
def test_a_ca_file_holding_an_unrooted_intermediate_refuses(
    build: _Build, chain_setting: str, ca_setting: str, two_tier: _TwoTier
) -> None:
    with pytest.raises(ValueError) as caught:
        build(two_tier.inter_file, two_tier.revokes_nothing, chain=True)
    text = str(caught.value)
    assert "do not chain to a self-signed root" in text
    assert chain_setting in text
    assert ca_setting in text
    assert "[tls]." not in text


def test_the_oidc_builder_refuses_the_chain_check_with_no_ca_file(two_tier: _TwoTier) -> None:
    """On the OS trust store the start rule cannot be met, so the build refuses, not skips."""
    with pytest.raises(ValueError, match=r"oidc_tls_ca_cert_file"):
        build_idp_opener(
            None, enforcing=False, crl_file=str(two_tier.revokes_nothing), crl_check_chain=True
        )


def test_the_ldaps_builder_refuses_the_chain_check_with_no_ca_data(two_tier: _TwoTier) -> None:
    with pytest.raises(ValueError, match=r"ad_tls_ca_cert_file"):
        assert_ldap3_tls_suites(
            validate=ssl.CERT_REQUIRED,
            ca_certs_data=None,
            connector="LDAPS (test)",
            crl_file=str(two_tier.revokes_nothing),
            crl_check_chain=True,
        )


@pytest.mark.parametrize("prefix", ["oidc", "ad"])
def test_the_chain_setting_needs_the_hops_crl_file_and_ca_file(
    prefix: str, two_tier: _TwoTier
) -> None:
    """Refused at load: without either file the setting would read as a check that never runs."""
    with pytest.raises(ValidationError, match=rf"requires \[auth\]\.{prefix}_tls_crl_file:"):
        AuthSettings.model_validate(
            {
                f"{prefix}_tls_crl_check_chain": True,
                f"{prefix}_tls_ca_cert_file": str(two_tier.root_file),
            }
        )
    with pytest.raises(ValidationError, match=rf"requires \[auth\]\.{prefix}_tls_ca_cert_file:"):
        AuthSettings.model_validate(
            {
                f"{prefix}_tls_crl_check_chain": True,
                f"{prefix}_tls_crl_file": str(two_tier.revokes_nothing),
            }
        )
    loaded = AuthSettings.model_validate(
        {
            f"{prefix}_tls_crl_check_chain": True,
            f"{prefix}_tls_crl_file": str(two_tier.revokes_nothing),
            f"{prefix}_tls_ca_cert_file": str(two_tier.root_file),
        }
    )
    assert getattr(loaded, f"{prefix}_tls_crl_check_chain") is True
    assert AuthSettings().model_dump()[f"{prefix}_tls_crl_check_chain"] is False


def test_the_running_hop_reload_words_the_oidc_own_crl_rule_for_its_settings(
    two_tier: _TwoTier, tmp_path: Path
) -> None:
    """The reload applies the start rule to a replaced file on a chain-checking OIDC context, in
    the same words, naming the hop's own settings rather than a client CA."""
    crl = tmp_path / "idp-crl.pem"
    crl.write_bytes(two_tier.revokes_nothing.read_bytes())
    ctx = _oidc_context(two_tier.root_file, crl, chain=True)

    crl.write_bytes(two_tier.inter_crl_file.read_bytes())
    gc.collect()
    (outcome,) = [o for o in crl_reload.reload_replaced_crls() if Path(o.path) == crl.resolve()]
    assert outcome.refusal is not None and outcome.refusal.remedy == crl_reload.FIX
    assert "no CRL of their own" in outcome.refusal.reason
    assert _OIDC_CHAIN in outcome.refusal.reason
    assert "client CA" not in outcome.refusal.reason
    assert outcome.reloaded == 0
    _handshake(ctx, _server(two_tier))  # the copy it holds still admits the server


def test_each_builder_refuses_the_chain_check_with_no_crl_file(two_tier: _TwoTier) -> None:
    """The builder's own check behind the load-time refusal: no CRL file means no check, so the
    chain setting refuses rather than reading as on."""
    with pytest.raises(ValueError, match=r"oidc_tls_crl_check_chain is set with no"):
        build_idp_opener(str(two_tier.root_file), enforcing=False, crl_check_chain=True)
    with pytest.raises(ValueError, match=r"ad_tls_crl_check_chain is set with no"):
        assert_ldap3_tls_suites(
            validate=ssl.CERT_REQUIRED,
            ca_certs_data=two_tier.root_file.read_text(encoding="ascii"),
            connector="LDAPS (test)",
            crl_check_chain=True,
        )
