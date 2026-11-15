# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #5627 and #5628: what the API listener trusts about a client certificate.

#5627, the client CRL (``[api].tls_client_crl_file``):

* **The whole chain is checked.** A two-tier PKI, root loaded as the client CA, an intermediate
  the client sends: with the root's CRL revoking the intermediate, the built listener refuses the
  client in a real handshake. The control is the same CRL loaded for the leaf alone, which admits
  it, so the refusal is the chain flag and not a CRL that refuses everyone.
* **The CRL takes the client CA's ACL and path preflight.** A CRL another principal can write, or
  replace through its path, refuses the build under ``enforce`` and warns under ``warn``.

#5628, the client-certificate shim:

* **A declared proxy's certificate is never stashed**, so callers behind the proxy cannot act as
  its mapped principal. Its control is the same certificate from another peer, which is stashed.
* **A leaf with no clientAuth extended key usage maps to nobody**, in a real handshake that
  OpenSSL accepts. Its control is the same leaf with clientAuth.
* **The issuer lookup is remembered**, so a repeat client costs no signature check, and the memory
  is bounded.

All material is synthetic and minted here. No PHI.
"""

from __future__ import annotations

import datetime
import inspect
import ipaddress
import logging
import ssl
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from messagefoundry import pki as pki_module
from messagefoundry.__main__ import _client_cert_shim
from messagefoundry.api.tls import build_api_ssl_context
from messagefoundry.api.tls_client_cert import (
    MF_CLIENT_PEERCERT_STATE_KEY,
    client_cert_http_protocol_class,
    enriched_app_state,
    parse_trusted_proxies,
    peer_is_trusted_proxy,
)
from messagefoundry.auth import trust_anchors as ta
from messagefoundry.auth.anchor_path import PathVerdict
from messagefoundry.auth.trust_anchors import TrustAnchorError
from messagefoundry.config.settings import ApiSettings
from messagefoundry.config.tls_policy import harden_crl_check
from messagefoundry.credential import VERIFIED_ISSUER_KEY
from messagefoundry.pki import IssuerIndex
from tests.test_api_tls import _new_ca, _pem, _shim_view
from tests.test_trust_anchor_byte_binding import _handshake

_NOW = datetime.datetime.now(datetime.UTC)
_DAY = datetime.timedelta(days=1)


# --- a two-tier PKI: root, intermediate, leaf --------------------------------------------------------


def _ku(*, ca: bool) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=True,
        key_cert_sign=ca,
        crl_sign=ca,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        encipher_only=False,
        decipher_only=False,
    )


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(
    subject: str,
    key: ec.EllipticCurvePrivateKey,
    issuer: str,
    signer: ec.EllipticCurvePrivateKey,
    *,
    ca: bool,
) -> x509.Certificate:
    """SKI, AKI and KeyUsage are set because the API context turns on ``VERIFY_X509_STRICT``."""
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(_name(issuer))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - _DAY)
        .not_valid_after(_NOW + 90 * _DAY)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), False
        )
        .add_extension(_ku(ca=ca), critical=True)
    )
    if not ca:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]), False
        ).add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            False,
        )
    return builder.sign(signer, hashes.SHA256())


def _crl(
    issuer: str, signer: ec.EllipticCurvePrivateKey, revoked: x509.Certificate | None
) -> bytes:
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(_name(issuer))
        .last_update(_NOW - _DAY)
        .next_update(_NOW + 30 * _DAY)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), False
        )
        .add_extension(x509.CRLNumber(1), False)
    )
    if revoked is not None:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(revoked.serial_number)
            .revocation_date(_NOW - _DAY)
            .build()
        )
    return builder.sign(signer, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)


def _key_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


@dataclass(frozen=True)
class _TwoTier:
    root_file: Path  # the client CA the listener loads
    server_cert: Path
    server_key: Path
    client_bundle: Path  # the leaf, then the intermediate it sends
    client_key: Path
    revokes_intermediate: Path  # the root's CRL revoking the intermediate, + the intermediate's CRL
    revokes_nothing: Path  # both CRLs, revoking nothing


@pytest.fixture(scope="module")
def two_tier(tmp_path_factory: pytest.TempPathFactory) -> _TwoTier:
    d = tmp_path_factory.mktemp("two-tier")
    root_key, inter_key, leaf_key, server_key = (
        ec.generate_private_key(ec.SECP256R1()) for _ in range(4)
    )
    root = _cert("Client Root", root_key, "Client Root", root_key, ca=True)
    inter = _cert("Client Issuing", inter_key, "Client Root", root_key, ca=True)
    leaf = _cert("svc", leaf_key, "Client Issuing", inter_key, ca=False)
    server = _cert("server", server_key, "Client Root", root_key, ca=False)
    inter_crl = _crl("Client Issuing", inter_key, None)
    files = {
        "root.pem": _pem(root),
        "server.pem": _pem(server),
        "server-key.pem": _key_pem(server_key),
        "client.pem": _pem(leaf) + _pem(inter),
        "client-key.pem": _key_pem(leaf_key),
        "revokes-inter.pem": _crl("Client Root", root_key, inter) + inter_crl,
        "revokes-nothing.pem": _crl("Client Root", root_key, None) + inter_crl,
    }
    for name, data in files.items():
        (d / name).write_bytes(data)
    return _TwoTier(
        d / "root.pem",
        d / "server.pem",
        d / "server-key.pem",
        d / "client.pem",
        d / "client-key.pem",
        d / "revokes-inter.pem",
        d / "revokes-nothing.pem",
    )


def _settings(pki: _TwoTier, crl: Path) -> ApiSettings:
    return ApiSettings(
        tls_cert_file=str(pki.server_cert),
        tls_key_file=str(pki.server_key),
        tls_client_ca_file=str(pki.root_file),
        tls_client_crl_file=str(crl),
    )


def _client(pki: _TwoTier) -> ssl.SSLContext:
    """TLS 1.2, so the server's verdict on the client certificate lands inside the handshake."""
    ctx = ssl.create_default_context(cadata=pki.root_file.read_text("ascii"))
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(pki.client_bundle, pki.client_key)
    return ctx


@pytest.fixture
def clean_anchor_checks(monkeypatch: pytest.MonkeyPatch) -> None:
    """ACL and path verdicts pinned clean, so a result does not depend on this machine's ACLs."""
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: True)
    monkeypatch.setattr(ta, "anchor_path_verdict", lambda _p: PathVerdict(ok=True))


# --- #5627: the whole chain ---------------------------------------------------------------------------


@pytest.mark.usefixtures("clean_anchor_checks")
def test_a_revoked_intermediate_refuses_its_clients(two_tier: _TwoTier) -> None:
    """Red before the fix: the leaf-only flag never read the root's CRL, so the client got in."""
    ctx = build_api_ssl_context(_settings(two_tier, two_tier.revokes_intermediate))
    assert ctx.verify_flags & ssl.VERIFY_CRL_CHECK_CHAIN == ssl.VERIFY_CRL_CHECK_CHAIN
    with pytest.raises(ssl.SSLError, match="revoked"):
        _handshake(_client(two_tier), ctx)


@pytest.mark.usefixtures("clean_anchor_checks")
def test_the_chain_check_admits_a_client_whose_chain_nobody_revoked(two_tier: _TwoTier) -> None:
    """The control for the refusal above: the chain flag is not a CRL that refuses everyone."""
    ctx = build_api_ssl_context(_settings(two_tier, two_tier.revokes_nothing))
    _handshake(_client(two_tier), ctx)


@pytest.mark.usefixtures("clean_anchor_checks")
def test_control_the_leaf_check_alone_admits_the_revoked_intermediates_client(
    two_tier: _TwoTier,
) -> None:
    """The instrument's control: the same CRL file under the leaf flag, as the listener loaded it
    before the fix, admits the client, so the CRL above really does revoke something."""
    leaf_only = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    leaf_only.load_cert_chain(two_tier.server_cert, two_tier.server_key)
    leaf_only.verify_mode = ssl.CERT_REQUIRED
    leaf_only.load_verify_locations(cadata=two_tier.root_file.read_text("ascii"))
    harden_crl_check(leaf_only, str(two_tier.revokes_intermediate), record_held_copy=False)
    assert not leaf_only.verify_flags & (ssl.VERIFY_CRL_CHECK_CHAIN & ~ssl.VERIFY_CRL_CHECK_LEAF)
    _handshake(_client(two_tier), leaf_only)


# --- #5627: the ACL and path preflight -----------------------------------------------------------------


def _crl_only(monkeypatch: pytest.MonkeyPatch, crl: Path, *, acl: bool, path: bool) -> None:
    """Clean verdicts for every file but ``crl``, which gets ``acl`` and ``path``."""
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda p: acl if Path(p) == crl else True)
    monkeypatch.setattr(
        ta,
        "anchor_path_verdict",
        lambda p: PathVerdict(ok=path if Path(p) == crl else True),
    )


@pytest.mark.parametrize(
    ("acl", "path", "finding"),
    [
        pytest.param(False, True, "writable by a non-owner", id="writable-dacl"),
        pytest.param(True, False, "can be replaced through its path", id="replaceable-path"),
    ],
)
def test_a_crl_another_principal_can_replace_refuses_under_enforce(
    two_tier: _TwoTier, monkeypatch: pytest.MonkeyPatch, acl: bool, path: bool, finding: str
) -> None:
    """Red before the fix: the CRL had no ACL or path check, so the context built."""
    _crl_only(monkeypatch, two_tier.revokes_nothing, acl=acl, path=path)
    with pytest.raises(TrustAnchorError, match=r"\[api\]\.tls_client_crl_file") as err:
        build_api_ssl_context(_settings(two_tier, two_tier.revokes_nothing), enforcing=True)
    assert finding in str(err.value)


def test_a_crl_whose_acl_cannot_be_read_refuses_under_enforce(
    two_tier: _TwoTier, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A CRL has no pin, so an unreadable ACL has no escape."""
    monkeypatch.setattr(
        ta,
        "dacl_is_owner_only",
        lambda p: None if Path(p) == two_tier.revokes_nothing else True,
    )
    monkeypatch.setattr(ta, "anchor_path_verdict", lambda _p: PathVerdict(ok=True))
    with pytest.raises(TrustAnchorError, match="could not settle"):
        build_api_ssl_context(_settings(two_tier, two_tier.revokes_nothing), enforcing=True)


def test_a_writable_crl_warns_and_loads_under_warn(
    two_tier: _TwoTier, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _crl_only(monkeypatch, two_tier.revokes_nothing, acl=False, path=True)
    with caplog.at_level(logging.WARNING, logger=ta.__name__):
        ctx = build_api_ssl_context(_settings(two_tier, two_tier.revokes_nothing), enforcing=False)
    assert ctx.cert_store_stats()["crl"] >= 1
    assert any("[api].tls_client_crl_file" in r.getMessage() for r in caplog.records)


@pytest.mark.usefixtures("clean_anchor_checks")
def test_a_missing_crl_still_refuses_with_its_own_message(
    two_tier: _TwoTier, tmp_path: Path
) -> None:
    with pytest.raises(ValueError, match="does not exist"):
        build_api_ssl_context(_settings(two_tier, tmp_path / "absent.pem"))


# --- #5628: a declared proxy's certificate -------------------------------------------------------------


class _SSL:
    def __init__(self, cert: dict[str, Any]) -> None:
        self._cert = cert

    def getpeercert(self, binary_form: bool = False) -> object:
        return b"" if binary_form else self._cert


class _Transport:
    def __init__(self, peer: object, cert: dict[str, Any]) -> None:
        self._peer = peer
        self._ssl = _SSL(cert)

    def get_extra_info(self, name: str) -> object:
        return {"ssl_object": self._ssl, "peername": self._peer}.get(name)


_CERT = {"subject": ((("commonName", "proxy.internal"),),)}


def test_a_certificate_from_a_declared_proxy_is_not_stashed() -> None:
    proxies = parse_trusted_proxies(["10.0.0.5", "192.0.2.0/24"])
    base: dict[str, Any] = {"shared": 1}
    for peer in (("10.0.0.5", 443), ("192.0.2.9", 443), ("::ffff:10.0.0.5", 443, 0, 0)):
        transport: Any = _Transport(peer, _CERT)
        assert enriched_app_state(base, transport, trusted_proxies=proxies) is base, peer


def test_control_the_same_certificate_from_another_peer_is_stashed() -> None:
    proxies = parse_trusted_proxies(["10.0.0.5"])
    transport: Any = _Transport(("10.0.0.6", 443), _CERT)
    state = enriched_app_state({}, transport, trusted_proxies=proxies)
    assert state[MF_CLIENT_PEERCERT_STATE_KEY]["subject"] == _CERT["subject"]
    # And with no proxy declared, a peer is never a proxy, whatever its address.
    direct: Any = _Transport(("10.0.0.5", 1), _CERT)
    assert MF_CLIENT_PEERCERT_STATE_KEY in enriched_app_state({}, direct)


@pytest.mark.parametrize("peer", [None, (), ("not-an-address", 1), 7])
def test_a_peer_that_cannot_be_placed_counts_as_a_proxy(peer: object) -> None:
    transport: Any = _Transport(peer, _CERT)
    assert peer_is_trusted_proxy(transport, parse_trusted_proxies(["10.0.0.5"]))
    assert not peer_is_trusted_proxy(transport, ())


def test_the_shim_class_skips_a_declared_proxys_certificate(
    caplog: pytest.LogCaptureFixture,
) -> None:
    class _Base:
        def __init__(self) -> None:
            self.app_state: dict[str, Any] = {}

        def connection_made(self, transport: object) -> None:
            pass

    with caplog.at_level(logging.WARNING):
        cls: Any = client_cert_http_protocol_class(_Base, trusted_proxies=["10.0.0.5"])
    assert any("[api].trusted_proxies" in r.getMessage() for r in caplog.records)
    from_proxy, direct = cls(), cls()
    from_proxy.connection_made(_Transport(("10.0.0.5", 1), _CERT))
    direct.connection_made(_Transport(("10.0.0.6", 1), _CERT))
    assert MF_CLIENT_PEERCERT_STATE_KEY not in from_proxy.app_state
    assert MF_CLIENT_PEERCERT_STATE_KEY in direct.app_state


def test_serve_must_name_the_proxies_when_it_builds_the_shim() -> None:
    """Keyword-only with no default, so a call site that forgot them fails rather than skips."""
    parameter = inspect.signature(_client_cert_shim).parameters["trusted_proxies"]
    assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
    assert parameter.default is inspect.Parameter.empty


def test_trusted_proxies_parse_to_both_ipv4_spellings() -> None:
    proxies = parse_trusted_proxies(["10.0.0.5"])
    assert ipaddress.ip_address("10.0.0.5") in proxies
    assert ipaddress.ip_address("::ffff:10.0.0.5") in proxies


# --- #5628: clientAuth extended key usage ---------------------------------------------------------------


def test_a_leaf_with_no_extended_key_usage_maps_to_nobody(tmp_path: Path) -> None:
    """Red before the fix: OpenSSL admits a client leaf with no extended key usage, and the shim
    named its issuer, so it mapped like any client certificate."""
    ca = _new_ca(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Service CA")]))
    view = _shim_view(tmp_path, ca, [ca[0]], client_auth=False)  # the handshake verified it
    assert view[VERIFIED_ISSUER_KEY] == ""


def test_control_the_same_leaf_with_client_auth_maps(tmp_path: Path) -> None:
    ca = _new_ca(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Service CA")]))
    view = _shim_view(tmp_path, ca, [ca[0]])
    assert view[VERIFIED_ISSUER_KEY] == "CN=Service CA"


def _leaf_der(ca: Any, usage: list[x509.ObjectIdentifier] | None) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name("svc"))
        .issuer_name(ca[0].subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - _DAY)
        .not_valid_after(_NOW + _DAY)
    )
    if usage is not None:
        builder = builder.add_extension(x509.ExtendedKeyUsage(usage), critical=False)
    return builder.sign(ca[1], hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def test_only_client_auth_names_an_issuer_when_it_is_required() -> None:
    ca = _new_ca(_name("Service CA"))
    index = IssuerIndex(_pem(ca[0]).decode("ascii"))
    cases = {
        "none": (None, ""),
        "server-only": ([ExtendedKeyUsageOID.SERVER_AUTH], ""),
        "any": ([ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE], ""),
        "client": ([ExtendedKeyUsageOID.CLIENT_AUTH], "CN=Service CA"),
    }
    for label, (usage, expected) in cases.items():
        der = _leaf_der(ca, usage)
        assert index.issuer_of(der, require_client_auth=True) == expected, label
        # Not asked for, the extended key usage changes nothing: the other listeners' behaviour.
        assert index.issuer_of(der) == "CN=Service CA", label


# --- #5628: the issuer lookup is remembered, and bounded -----------------------------------------------


def test_a_repeat_leaf_costs_no_second_signature_check(monkeypatch: pytest.MonkeyPatch) -> None:
    ca = _new_ca(_name("Service CA"))
    index = IssuerIndex(_pem(ca[0]).decode("ascii"))
    der = _leaf_der(ca, [ExtendedKeyUsageOID.CLIENT_AUTH])
    real = pki_module._directly_issued
    calls: list[int] = []

    def _counting(leaf: x509.Certificate, issuer: x509.Certificate) -> bool:
        calls.append(1)
        return real(leaf, issuer)

    monkeypatch.setattr(pki_module, "_directly_issued", _counting)
    first = index.issuer_of(der, require_client_auth=True)
    checks = len(calls)
    assert first == "CN=Service CA" and checks >= 1
    assert index.issuer_of(der, require_client_auth=True) == first
    assert len(calls) == checks  # remembered, not checked again


def test_the_remembered_answers_are_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pki_module, "ISSUER_CACHE_SIZE", 2)
    ca = _new_ca(_name("Service CA"))
    index = IssuerIndex(_pem(ca[0]).decode("ascii"))
    for _ in range(5):
        index.issuer_of(_leaf_der(ca, [ExtendedKeyUsageOID.CLIENT_AUTH]))
    assert len(index._answers) == 2
