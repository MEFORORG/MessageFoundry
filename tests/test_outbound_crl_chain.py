# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #5511, outbound half: ``[tls].crl_check_chain`` checks a server's whole chain.

``[tls].crl_file`` sets only the leaf CRL flag on the outbound hops it reaches, so with a two-tier
PKI a server whose intermediate CA the root's CRL revokes completes the handshake. The opt-in
``[tls].crl_check_chain`` turns on the whole-chain check on a hop that trusts operator CAs alone,
clears ``VERIFY_X509_PARTIAL_CHAIN`` there, refuses at build a CA file holding a CA that is not
self-signed, and refuses at build a hop on the OS trust store. Off, every arm is as before.

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

from messagefoundry.config.settings import TlsSettings
from messagefoundry.config.tls_policy import (
    TrustAnchor,
    TrustAnchorPolicy,
    build_anchored_https_handler,
    build_verifying_client_context,
    resolve_trust_anchor,
    urllib_handler_context,
)
from messagefoundry.pipeline import crl_reload
from tests import test_api_tls_client_trust as _api_suite
from tests.test_api_tls_client_trust import _TwoTier
from tests.test_trust_anchor_byte_binding import _handshake

# Fixtures bound by name, so pytest applies them in this module too.
two_tier = _api_suite.two_tier
_fresh_registry = _api_suite._fresh_registry

_HOST = "partner.example"  # off loopback, so [tls].crl_file reaches the hop
_CONNECTION = "OB_PARTNER_ADT"

_Builder = Callable[[TrustAnchor], ssl.SSLContext]


def _context(anchor: TrustAnchor) -> ssl.SSLContext:
    return build_verifying_client_context(anchor)


def _https(anchor: TrustAnchor) -> ssl.SSLContext:
    handler = build_anchored_https_handler(anchor=anchor, connector="rest")
    return urllib_handler_context(handler, connector="rest")


_BUILDERS = pytest.mark.parametrize("build", [_context, _https], ids=["context", "https"])


def _server(pki: _TwoTier) -> ssl.SSLContext:
    """A server sending the leaf and the intermediate that issued it."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(pki.client_bundle, pki.client_key)
    return ctx


def _anchor(
    crl: Path,
    *,
    chain: bool = True,
    ca_file: Path | None = None,
    internal_ca: Path | None = None,
    mode: str = "system",
) -> TrustAnchor:
    policy = TrustAnchorPolicy(
        internal_ca_file=None if internal_ca is None else str(internal_ca),
        mode=mode,  # type: ignore[arg-type]
        crl_file=str(crl),
        crl_check_chain=chain,
    )
    return resolve_trust_anchor(
        connection_ca_file=None if ca_file is None else str(ca_file),
        host=_HOST,
        policy=policy,
        connection=_CONNECTION,
    )


def _pinned_anchors(pki: _TwoTier, crl: Path, *, chain: bool = True) -> list[TrustAnchor]:
    """The two operator-CA arms: a connection's own tls_ca_file, and a pinned internal CA."""
    return [
        _anchor(crl, chain=chain, ca_file=pki.root_file),
        _anchor(crl, chain=chain, internal_ca=pki.root_file, mode="pinned"),
    ]


@_BUILDERS
def test_a_revoked_intermediate_refuses_its_servers(build: _Builder, two_tier: _TwoTier) -> None:
    """Red before the fix: the leaf flag alone never read the root's CRL, so the server got in."""
    for anchor in _pinned_anchors(two_tier, two_tier.revokes_intermediate):
        ctx = build(anchor)
        assert ctx.verify_flags & ssl.VERIFY_CRL_CHECK_CHAIN == ssl.VERIFY_CRL_CHECK_CHAIN
        assert not ctx.verify_flags & ssl.VERIFY_X509_PARTIAL_CHAIN
        with pytest.raises(ssl.SSLError, match="revoked"):
            _handshake(ctx, _server(two_tier))


@_BUILDERS
def test_the_chain_check_admits_a_server_whose_chain_nobody_revoked(
    build: _Builder, two_tier: _TwoTier
) -> None:
    """The control for the refusal above: the chain flag is not a CRL that refuses everyone."""
    for anchor in _pinned_anchors(two_tier, two_tier.revokes_nothing):
        _handshake(build(anchor), _server(two_tier))


@_BUILDERS
def test_a_ca_file_holding_an_intermediate_refuses_the_build(
    build: _Builder, two_tier: _TwoTier, tmp_path: Path
) -> None:
    """With PARTIAL_CHAIN set the chain would end at the intermediate and every handshake be refused
    with "unable to get certificate CRL", so the build refuses, naming the CA setting."""
    bundle = tmp_path / "root-and-inter.pem"
    bundle.write_bytes(two_tier.root_file.read_bytes() + two_tier.inter_file.read_bytes())
    with pytest.raises(
        ValueError,
        match=rf"\[tls\]\.crl_check_chain is set, and tls_ca_file of connection "
        rf"'{_CONNECTION}' loads CA\(s\) that are not self-signed: 'CN=Client Issuing'",
    ):
        build(_anchor(two_tier.revokes_nothing, ca_file=bundle))
    with pytest.raises(ValueError, match=r"\[tls\]\.internal_ca_file loads CA\(s\) that are not"):
        build(_anchor(two_tier.revokes_nothing, internal_ca=bundle, mode="pinned"))


@_BUILDERS
def test_the_os_trust_store_arms_refuse_the_build(build: _Builder, two_tier: _TwoTier) -> None:
    """No CRL file names the OS roots, so the whole-chain check cannot hold on augment or system."""
    augment = _anchor(two_tier.revokes_nothing, internal_ca=two_tier.root_file, mode="augment")
    with pytest.raises(ValueError, match=r"crl_check_chain is set, .* the augment arm"):
        build(augment)
    with pytest.raises(ValueError, match=r"crl_check_chain is set, .* the system arm"):
        build(_anchor(two_tier.revokes_nothing))


@_BUILDERS
def test_a_missing_root_crl_refuses_the_build_in_outbound_words(
    build: _Builder, two_tier: _TwoTier, tmp_path: Path
) -> None:
    """Only the intermediate's CRL: every server would be refused, so the build refuses, naming
    the root and the outbound settings rather than the inbound client-CA ones."""
    crl = tmp_path / "inter-crl-only.pem"
    crl.write_bytes(two_tier.inter_crl_file.read_bytes())
    with pytest.raises(ValueError) as caught:
        build(_anchor(crl, ca_file=two_tier.root_file))
    text = str(caught.value)
    assert text.startswith("[tls].crl_file (")
    assert "the CA(s) 'CN=Client Root'" in text
    assert "loaded from this hop's CA setting (a connection's tls_ca_file" in text
    assert "[tls].crl_check_chain checks the whole server chain" in text
    assert "client CA" not in text and "clients" not in text


@_BUILDERS
def test_off_every_arm_keeps_the_leaf_check(build: _Builder, two_tier: _TwoTier) -> None:
    """The control: with the setting off each arm builds as before, leaf flag only, and the
    revoked intermediate's server is admitted, which is the gap the setting closes."""
    crl = two_tier.revokes_intermediate
    for anchor in _pinned_anchors(two_tier, crl, chain=False):
        assert not anchor.crl_check_chain
        ctx = build(anchor)
        assert ctx.verify_flags & ssl.VERIFY_CRL_CHECK_CHAIN == ssl.VERIFY_CRL_CHECK_LEAF
        assert ctx.verify_flags & ssl.VERIFY_X509_PARTIAL_CHAIN
        _handshake(ctx, _server(two_tier))
    for anchor in (
        _anchor(crl, chain=False, internal_ca=two_tier.root_file, mode="augment"),
        _anchor(crl, chain=False),
    ):
        ctx = build(anchor)
        assert ctx.verify_flags & ssl.VERIFY_CRL_CHECK_CHAIN == ssl.VERIFY_CRL_CHECK_LEAF


def test_a_loopback_hop_stays_exempt(two_tier: _TwoTier) -> None:
    """A loopback hop gets no CRL, so it gets no chain check either, and builds on any arm."""
    anchor = resolve_trust_anchor(
        connection_ca_file=None,
        host="127.0.0.1",
        policy=TrustAnchorPolicy(crl_file=str(two_tier.revokes_nothing), crl_check_chain=True),
    )
    assert anchor.crl_file is None and not anchor.crl_check_chain
    build_verifying_client_context(anchor)


def test_a_reload_applies_the_same_rules(two_tier: _TwoTier, tmp_path: Path) -> None:
    """The running-hop reload keys on the chain flag the outbound context now carries. A file
    leaving the root without its own CRL is a file to fix, worded for the outbound hop, and the
    hop keeps its copy."""
    crl = tmp_path / "outbound-crl.pem"
    crl.write_bytes(two_tier.revokes_nothing.read_bytes())
    ctx = build_verifying_client_context(_anchor(crl, ca_file=two_tier.root_file))

    crl.write_bytes(two_tier.inter_crl_file.read_bytes())
    gc.collect()
    (outcome,) = [o for o in crl_reload.reload_replaced_crls() if Path(o.path) == crl.resolve()]
    assert outcome.refusal is not None and outcome.refusal.remedy == crl_reload.FIX
    assert "loaded from this hop's CA setting" in outcome.refusal.reason
    assert "client CA" not in outcome.refusal.reason
    assert outcome.reloaded == 0
    _handshake(ctx, _server(two_tier))  # the copy it holds still admits the server


def test_the_setting_needs_a_crl_file_and_reaches_the_policy(two_tier: _TwoTier) -> None:
    with pytest.raises(ValueError, match=r"crl_check_chain = true requires \[tls\]\.crl_file"):
        TlsSettings(crl_check_chain=True)
    policy = TlsSettings(crl_file=str(two_tier.revokes_nothing), crl_check_chain=True).policy()
    assert policy.crl_check_chain
    assert not TlsSettings(crl_file=str(two_tier.revokes_nothing)).policy().crl_check_chain
