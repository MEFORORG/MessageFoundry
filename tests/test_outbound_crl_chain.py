# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #5511, outbound half: ``[tls].crl_check_chain`` checks a server's whole chain.

``[tls].crl_file`` sets only the leaf CRL flag on the outbound hops it reaches, so with a two-tier
PKI a server whose intermediate CA the root's CRL revokes completes the handshake. The opt-in
``[tls].crl_check_chain`` turns on the whole-chain check on a hop that trusts operator CAs alone,
clears ``VERIFY_X509_PARTIAL_CHAIN`` there, refuses at build a CA file holding a CA with no path to
a self-signed root in that file, and refuses at build a hop on the OS trust store. Off, every arm
is as before.

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
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import EgressSettings, TlsSettings
from messagefoundry.config.tls_policy import (
    OS_ROOTS_CHAIN_CHECK_REASON,
    TrustAnchor,
    TrustAnchorPolicy,
    _require_rooted_cas,
    build_anchored_https_handler,
    build_verifying_client_context,
    context_checks_revocation,
    resolve_trust_anchor,
    urllib_handler_context,
)
from messagefoundry.config.wiring import FHIR, DICOMweb, Rest, Soap
from messagefoundry.pipeline import crl_reload
from messagefoundry.pki import OUTBOUND_HTTP_URL_CASE, cas_not_reaching_a_root, own_crl_refusal
from messagefoundry.transports import build_destination
from messagefoundry.transports.fhir import FhirLookupExecutor
from messagefoundry.transports.rest import opener_tls_context
from tests import test_api_tls_client_trust as _api_suite
from tests.test_api_tls_client_trust import _TwoTier
from tests.test_trust_anchor_byte_binding import _handshake

# Fixtures bound by name, so pytest applies them in this module too.
two_tier = _api_suite.two_tier
_fresh_registry = _api_suite._fresh_registry

_HOST = "partner.example"  # off loopback, so [tls].crl_file reaches the hop
_CONNECTION = "OB_PARTNER_ADT"
_ECH_SIDECAR = "http://127.0.0.1:8123"  # nothing here dials it

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


def _root_and_intermediate(pki: _TwoTier, tmp_path: Path) -> Path:
    bundle = tmp_path / "root-and-inter.pem"
    bundle.write_bytes(pki.root_file.read_bytes() + pki.inter_file.read_bytes())
    return bundle


@_BUILDERS
def test_a_ca_file_holding_an_intermediate_beside_its_root_is_admitted(
    build: _Builder, two_tier: _TwoTier, tmp_path: Path
) -> None:
    """Red on d24ca1bc059, which refused any CA that is not self-signed. With PARTIAL_CHAIN cleared
    the chain runs on through the loaded intermediate to the loaded root, so the hop admits a
    server nobody revoked and still refuses one under the revoked intermediate."""
    bundle = _root_and_intermediate(two_tier, tmp_path)
    for crl, admitted in ((two_tier.revokes_nothing, True), (two_tier.revokes_intermediate, False)):
        for anchor in (
            _anchor(crl, ca_file=bundle),
            _anchor(crl, internal_ca=bundle, mode="pinned"),
        ):
            ctx = build(anchor)
            assert not ctx.verify_flags & ssl.VERIFY_X509_PARTIAL_CHAIN
            if admitted:
                _handshake(ctx, _server(two_tier))
            else:
                with pytest.raises(ssl.SSLError, match="revoked"):
                    _handshake(ctx, _server(two_tier))


@_BUILDERS
def test_an_intermediate_whose_root_the_ca_file_does_not_hold_refuses_the_build(
    build: _Builder, two_tier: _TwoTier
) -> None:
    """No chain through that intermediate can end at a root once PARTIAL_CHAIN is cleared, so
    every handshake would be refused; the build refuses instead, naming the CA setting."""
    with pytest.raises(
        ValueError,
        match=rf"\[tls\]\.crl_check_chain is set, and tls_ca_file of connection "
        rf"'{_CONNECTION}' loads CA\(s\) that do not chain to a self-signed root CA in that "
        rf"file: 'CN=Client Issuing'",
    ):
        build(_anchor(two_tier.revokes_nothing, ca_file=two_tier.inter_file))
    with pytest.raises(ValueError, match=r"\[tls\]\.internal_ca_file loads CA\(s\) that do not"):
        build(_anchor(two_tier.revokes_nothing, internal_ca=two_tier.inter_file, mode="pinned"))


def test_a_ca_reaches_a_root_through_loaded_cas_in_any_order() -> None:
    """Three tiers listed leaf-most first still root, which takes more than one pass; a CA whose
    named issuer is loaded under another key does not, since each link is checked by signature."""
    root_key, mid_key, low_key, other_key = (
        ec.generate_private_key(ec.SECP256R1()) for _ in range(4)
    )
    root = _api_suite._cert("Root", root_key, "Root", root_key, ca=True)
    mid = _api_suite._cert("Mid", mid_key, "Root", root_key, ca=True)
    low = _api_suite._cert("Low", low_key, "Mid", mid_key, ca=True)
    forged = _api_suite._cert("Forged", low_key, "Root", other_key, ca=True)
    der = [c.public_bytes(serialization.Encoding.DER) for c in (low, mid, root)]
    assert cas_not_reaching_a_root(der) == []
    assert cas_not_reaching_a_root(der[:2]) == [
        f"'CN=Low' (serial number {low.serial_number:#x})",
        f"'CN=Mid' (serial number {mid.serial_number:#x})",
    ]
    forged_der = forged.public_bytes(serialization.Encoding.DER)
    assert cas_not_reaching_a_root([*der, forged_der]) == [
        f"'CN=Forged' (serial number {forged.serial_number:#x})"
    ]


def test_clearing_partial_chain_keeps_a_flag_above_verify_flags_own_bits(
    two_tier: _TwoTier,
) -> None:
    """Red on d24ca1bc059: ``~ssl.VERIFY_X509_PARTIAL_CHAIN`` is the complement within the
    IntFlag's own members, so ``&=`` with it also cleared any higher bit, such as OpenSSL's
    ``X509_V_FLAG_NO_ALT_CHAINS`` (0x100000), which VerifyFlags does not name."""
    no_alt_chains = 0x100000
    assert not no_alt_chains & sum(int(flag) for flag in ssl.VerifyFlags)
    ctx = ssl.create_default_context(cafile=str(two_tier.root_file))
    ctx.verify_flags |= no_alt_chains
    _require_rooted_cas(ctx, _anchor(two_tier.revokes_nothing, ca_file=two_tier.root_file))
    assert ctx.verify_flags & no_alt_chains
    assert not ctx.verify_flags & ssl.VERIFY_X509_PARTIAL_CHAIN


@_BUILDERS
def test_a_ca_file_holding_a_certificate_that_is_no_ca_refuses_the_build(
    build: _Builder, two_tier: _TwoTier, tmp_path: Path
) -> None:
    """A pinned server leaf is not listed by get_ca_certs, and with PARTIAL_CHAIN cleared no chain
    could end at it, so it is refused at build rather than at every handshake."""
    bundle = tmp_path / "root-and-leaf.pem"
    leaf = two_tier.client_bundle.read_text("ascii").split("-----END CERTIFICATE-----")[0]
    bundle.write_text(
        two_tier.root_file.read_text("ascii") + leaf + "-----END CERTIFICATE-----\n", "ascii"
    )
    with pytest.raises(ValueError, match=r"loads 1 certificate\(s\) that are not CAs"):
        build(_anchor(two_tier.revokes_nothing, ca_file=bundle))


def test_an_anchor_cannot_check_the_chain_without_a_crl() -> None:
    with pytest.raises(ValueError, match="needs a crl_file"):
        TrustAnchor(cafile="ca.pem", load_system_roots=False, crl_check_chain=True)


@_BUILDERS
def test_the_os_trust_store_arms_refuse_the_build(build: _Builder, two_tier: _TwoTier) -> None:
    """Augment and system refuse the build, each refusal giving the one reason
    (OS_ROOTS_CHAIN_CHECK_REASON) and naming the settings that get round it, since the docs it
    once pointed at do not ship in the wheel."""
    augment = _anchor(two_tier.revokes_nothing, internal_ca=two_tier.root_file, mode="augment")
    system = _anchor(two_tier.revokes_nothing)
    for anchor, arm in ((augment, "augment"), (system, "system")):
        with pytest.raises(
            ValueError, match=rf"crl_check_chain is set, .* the {arm} arm"
        ) as refused:
            build(anchor)
        text = str(refused.value)
        assert OS_ROOTS_CHAIN_CHECK_REASON in text
        for setting in (
            "a connection's own tls_ca_file",
            "[alerts].email_tls_ca_file",
            '[tls].internal_ca_file with [tls].trust_anchor_mode = "pinned"',
            "unset [tls].crl_check_chain",
        ):
            assert setting in text
        assert "docs/CONFIGURATION.md" not in text
        assert "ech_sidecar" not in text
        assert "rather than honoured unchecked" in text


def _ech_rest(policy: TrustAnchorPolicy, settings: dict[str, object] | None = None) -> object:
    """A REST destination that sends through a loopback ECH sidecar, built as the loader builds
    it. Revocation is attested so the revocation guard admits it on any posture."""
    return build_destination(
        Destination(
            name=_CONNECTION,
            type=ConnectorType.REST,
            settings={
                **Rest(url=f"https://{_HOST}/x").settings,
                "ech_egress": True,
                "ech_sidecar": _ECH_SIDECAR,
                **(settings or {}),
            },
            trust_anchor_policy=policy,
            tls_revocation_attested=True,
            tls_revocation_attested_reason="synthetic attestation for this test",
        ),
        egress=EgressSettings(deny_by_default=False, allowed_ech_sidecar=["127.0.0.1:8123"]),
    )


def test_an_ech_rest_hop_on_the_os_roots_refuses_without_promising_a_check(
    two_tier: _TwoTier,
) -> None:
    """Red before the fix: an ECH hop got the generic refusal, whose "To chain-check this hop,
    give it operator CAs alone" promised a check the sidecar hop never runs."""
    for mode, internal in (("system", None), ("augment", str(two_tier.root_file))):
        policy = TrustAnchorPolicy(
            internal_ca_file=internal,
            mode=mode,  # type: ignore[arg-type]
            crl_file=str(two_tier.revokes_nothing),
            crl_check_chain=True,
        )
        with pytest.raises(ValueError, match=r"crl_check_chain is set, and this REST") as refused:
            _ech_rest(policy)
        text = str(refused.value)
        assert "sends through its ECH sidecar (ech_sidecar)" in text
        assert "no CRL in [tls].crl_file is checked against the partner" in text
        assert OS_ROOTS_CHAIN_CHECK_REASON in text
        assert "rather than honoured unchecked" not in text
        assert "To clear this refusal, unset [tls].crl_check_chain" in text
        assert "through its own tls_ca_file or [tls].internal_ca_file" in text
        assert "token server" not in text and "[alerts]" not in text
        assert "verifies it" not in text
        assert "None of these makes the engine check the partner's revocation" in text
        assert "To chain-check" not in text


def _http_rest(policy: TrustAnchorPolicy, settings: dict[str, object] | None = None) -> object:
    """A REST destination whose url is http, accepted as cleartext, built as the loader builds it."""
    return build_destination(
        Destination(
            name=_CONNECTION,
            type=ConnectorType.REST,
            settings={**Rest(url=f"http://{_HOST}/x").settings, **(settings or {})},
            trust_anchor_policy=policy,
            cleartext_accepted=True,
            cleartext_reason="synthetic cleartext reason for this test",
            tls_revocation_attested=True,
            tls_revocation_attested_reason="synthetic attestation for this test",
        ),
        egress=EgressSettings(deny_by_default=False),
    )


@pytest.mark.parametrize("extra", [{}, {"tls_allow_expired": True}], ids=["plain", "expired"])
def test_an_http_rest_hop_on_the_os_roots_refuses_without_claiming_tls(
    two_tier: _TwoTier, extra: dict[str, object]
) -> None:
    """Red before the fix: an http hop got the generic refusal, which said it "verifies its
    server" and promised a chain check, though the hop makes no TLS connection."""
    for mode, internal in (("system", None), ("augment", str(two_tier.root_file))):
        policy = TrustAnchorPolicy(
            internal_ca_file=internal,
            mode=mode,  # type: ignore[arg-type]
            crl_file=str(two_tier.revokes_nothing),
            crl_check_chain=True,
        )
        with pytest.raises(ValueError, match=r"crl_check_chain is set, and this REST") as refused:
            _http_rest(policy, extra)
        text = str(refused.value)
        assert "has an http url, so it sends to the partner without TLS" in text
        assert "verifies its server" not in text
        assert "To chain-check" not in text
        assert "rather than honoured unchecked" not in text
        assert OS_ROOTS_CHAIN_CHECK_REASON in text
        assert "None of these makes the engine check the partner's revocation" in text


def test_an_http_rest_hop_builds_on_the_remedies_its_refusal_names(two_tier: _TwoTier) -> None:
    """Each way out the http refusal names builds: the connection's own tls_ca_file, and a pinned
    internal CA."""
    crl = str(two_tier.revokes_nothing)
    _http_rest(
        TrustAnchorPolicy(crl_file=crl, crl_check_chain=True),
        {"tls_ca_file": str(two_tier.root_file)},
    )
    _http_rest(
        TrustAnchorPolicy(
            internal_ca_file=str(two_tier.root_file),
            mode="pinned",
            crl_file=crl,
            crl_check_chain=True,
        )
    )


def _http_family(kind: str, policy: TrustAnchorPolicy, settings: dict[str, object]) -> object:
    """A SOAP, FHIR or DICOMweb destination, or a FhirLookup executor, whose url is http and
    accepted as cleartext."""
    url = f"http://{_HOST}/x"
    if kind == "fhir_lookup":
        return FhirLookupExecutor(
            {
                "epic": {
                    "url": url,
                    "cleartext_accepted": True,
                    "cleartext_reason": "synthetic cleartext reason for this test",
                    **settings,
                }
            },
            egress=EgressSettings(deny_by_default=False),
            trust_anchor_policy=policy,
        )
    built = (
        Soap(url=url) if kind == "soap" else FHIR(url=url) if kind == "fhir" else DICOMweb(url=url)
    )
    ctype = {
        "soap": ConnectorType.SOAP,
        "fhir": ConnectorType.FHIR,
        "dicomweb": ConnectorType.DICOMWEB,
    }[kind]
    return build_destination(
        Destination(
            name=_CONNECTION,
            type=ctype,
            settings={**built.settings, **settings},
            trust_anchor_policy=policy,
            cleartext_accepted=True,
            cleartext_reason="synthetic cleartext reason for this test",
            tls_revocation_attested=True,
            tls_revocation_attested_reason="synthetic attestation for this test",
        ),
        egress=EgressSettings(deny_by_default=False),
    )


_HTTP_FAMILY = pytest.mark.parametrize("kind", ["soap", "fhir", "fhir_lookup", "dicomweb"])


@_HTTP_FAMILY
def test_an_http_family_hop_on_the_os_roots_refuses_without_claiming_tls(
    two_tier: _TwoTier, kind: str
) -> None:
    """Red before the fix: an http SOAP, FHIR, FhirLookup or DICOMweb hop got the generic
    refusal, which said it "verifies its server" and promised a chain check."""
    for mode, internal in (("system", None), ("augment", str(two_tier.root_file))):
        policy = TrustAnchorPolicy(
            internal_ca_file=internal,
            mode=mode,  # type: ignore[arg-type]
            crl_file=str(two_tier.revokes_nothing),
            crl_check_chain=True,
        )
        with pytest.raises(ValueError, match=r"crl_check_chain is set, and this ") as refused:
            _http_family(kind, policy, {})
        text = str(refused.value)
        assert "has an http url, so it sends to the partner without TLS" in text
        assert "verifies its server" not in text
        assert "To chain-check" not in text
        assert "REST" not in text
        assert "None of these makes the engine check the partner's revocation" in text


@_HTTP_FAMILY
def test_an_http_family_hop_builds_on_the_remedies_its_refusal_names(
    two_tier: _TwoTier, kind: str
) -> None:
    """Each way out the refusal names builds: the connection's own tls_ca_file, and a pinned
    internal CA."""
    crl = str(two_tier.revokes_nothing)
    _http_family(
        kind,
        TrustAnchorPolicy(crl_file=crl, crl_check_chain=True),
        {"tls_ca_file": str(two_tier.root_file)},
    )
    _http_family(
        kind,
        TrustAnchorPolicy(
            internal_ca_file=str(two_tier.root_file),
            mode="pinned",
            crl_file=crl,
            crl_check_chain=True,
        ),
        {},
    )


@_HTTP_FAMILY
def test_an_http_hop_on_its_ca_file_remedy_is_told_it_checks_no_server_chain(
    two_tier: _TwoTier, kind: str, tmp_path: Path
) -> None:
    """Red on a1f268bad59: an http hop that follows the tls_ca_file remedy still meets the own-CRL
    and rooted-CA refusals, which said only that the whole server chain is checked. Each now
    scopes that to a hop over TLS and names the http case."""
    root_crl_missing = tmp_path / "inter-crl-only.pem"
    root_crl_missing.write_bytes(two_tier.inter_crl_file.read_bytes())
    for crl, ca_file, said in (
        (root_crl_missing, two_tier.root_file, "the CA(s) 'CN=Client Root'"),
        (two_tier.revokes_nothing, two_tier.inter_file, "do not chain to a self-signed root"),
    ):
        with pytest.raises(ValueError) as refused:
            _http_family(
                kind,
                TrustAnchorPolicy(crl_file=str(crl), crl_check_chain=True),
                {"tls_ca_file": str(ca_file)},
            )
        text = str(refused.value)
        assert said in text
        assert OUTBOUND_HTTP_URL_CASE in text
        assert "checks the whole server chain against this file\n" not in text
    assert "on a hop that sends to its server over TLS" in own_crl_refusal(
        [("CN=Client Root", 1)], outbound=True
    )


def test_an_ech_rest_hop_pinned_by_its_ca_file_builds_and_checks_no_crl(
    two_tier: _TwoTier,
) -> None:
    """What the ECH refusal says, measured: with the connection's own tls_ca_file the hop builds,
    and the opener it sends on checks no CRL, leaf or chain, since the sidecar dials the partner."""
    policy = TrustAnchorPolicy(crl_file=str(two_tier.revokes_nothing), crl_check_chain=True)
    dest = _ech_rest(policy, {"tls_ca_file": str(two_tier.root_file)})
    opener = dest._opener  # type: ignore[attr-defined]
    assert not context_checks_revocation(opener_tls_context(opener, connector="probe"))


def test_an_ech_rest_hop_pinned_by_its_ca_file_still_meets_the_own_crl_rule(
    two_tier: _TwoTier, tmp_path: Path
) -> None:
    """The ECH hop's build still applies the chain-check refusals to the context it builds for the
    partner: a CRL file with no CRL from the root is refused, naming the root."""
    crl = tmp_path / "inter-crl-only.pem"
    crl.write_bytes(two_tier.inter_crl_file.read_bytes())
    policy = TrustAnchorPolicy(crl_file=str(crl), crl_check_chain=True)
    with pytest.raises(ValueError, match=r"the CA\(s\) 'CN=Client Root'"):
        _ech_rest(policy, {"tls_ca_file": str(two_tier.root_file)})


def test_the_configuration_row_the_settings_comment_names_exists() -> None:
    """TlsSettings.crl_check_chain's comment points at this row; it must be there to find."""
    doc = Path(__file__).resolve().parents[1] / "docs" / "CONFIGURATION.md"
    text = doc.read_text(encoding="utf-8")
    assert "| `crl_check_chain` | bool | `false` |" in text
    # The symbol the row, ADR 0173 and the settings comment point at; importing it above
    # proves it exists.
    assert "`OS_ROOTS_CHAIN_CHECK_REASON`" in text


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
    assert "loaded from this hop's CA setting (such as a connection's tls_ca_file" in text
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


def _reordered(crl: Path) -> bytes:
    """The same CRLs, intermediate's first: new bytes for the reload, no newer CRL needed."""
    marker = b"-----BEGIN X509 CRL-----"
    blocks = [marker + block for block in crl.read_bytes().split(marker)[1:]]
    assert len(blocks) == 2
    return blocks[1] + blocks[0]


@pytest.mark.parametrize("with_intermediate", [False, True], ids=["root-only", "root-and-inter"])
def test_the_no_issuer_remedy_holds_under_the_chain_check(
    two_tier: _TwoTier, tmp_path: Path, with_intermediate: bool
) -> None:
    """The reload's ``no_issuer`` remedy says adding the issuing intermediate to the hop's own CA
    file lets later reloads verify its CRL. Red on d24ca1bc059 for the second case, whose build
    refused that CA file under the chain check, so the remedy could not be followed there."""
    ca_file = (
        _root_and_intermediate(two_tier, tmp_path) if with_intermediate else two_tier.root_file
    )
    crl = tmp_path / "outbound-crl.pem"
    crl.write_bytes(two_tier.revokes_nothing.read_bytes())
    ctx = build_verifying_client_context(_anchor(crl, ca_file=ca_file))

    crl.write_bytes(_reordered(two_tier.revokes_nothing))
    gc.collect()
    (outcome,) = [o for o in crl_reload.reload_replaced_crls() if Path(o.path) == crl.resolve()]
    if with_intermediate:
        assert outcome.refusal is None and outcome.reloaded == 1
    else:
        assert outcome.refusal is not None and outcome.refusal.remedy == crl_reload.NO_ISSUER
        assert outcome.reloaded == 0
    _handshake(ctx, _server(two_tier))


def test_the_setting_needs_a_crl_file_and_reaches_the_policy(two_tier: _TwoTier) -> None:
    with pytest.raises(ValueError, match=r"crl_check_chain = true requires \[tls\]\.crl_file"):
        TlsSettings(crl_check_chain=True)
    policy = TlsSettings(crl_file=str(two_tier.revokes_nothing), crl_check_chain=True).policy()
    assert policy.crl_check_chain
    assert not TlsSettings(crl_file=str(two_tier.revokes_nothing)).policy().crl_check_chain
