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
import gc
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
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID

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
from messagefoundry.pipeline import crl_reload
from messagefoundry.pki import IssuerIndex
from tests import test_crl_reload as _reload_suite
from tests.test_api_tls import _new_ca, _pem, _shim_view
from tests.test_trust_anchor_byte_binding import _handshake

_NOW = datetime.datetime.now(datetime.UTC)
_DAY = datetime.timedelta(days=1)
_DER = serialization.Encoding.DER

# The reload suite's autouse fixture, bound here by name so pytest applies it in this module too:
# no held copies, refusals or reload pass state carried in from another test.
_fresh_registry = _reload_suite._fresh_registry


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
    issuer: str,
    signer: ec.EllipticCurvePrivateKey,
    revoked: x509.Certificate | None,
    *,
    akid: bool = True,
    age: datetime.timedelta = _DAY,
) -> bytes:
    """``akid=False`` leaves out the Authority Key Identifier, so the CRL names no key; ``age`` is
    how long before now its lastUpdate falls."""
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(_name(issuer))
        .last_update(_NOW - age)
        .next_update(_NOW + 30 * _DAY)
        .add_extension(x509.CRLNumber(1), False)
    )
    if akid:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), False
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
    inter_file: Path  # the intermediate alone
    inter_crl_file: Path  # the intermediate's CRL alone


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
        "inter.pem": _pem(inter),
        "inter-crl.pem": inter_crl,
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
        d / "inter.pem",
        d / "inter-crl.pem",
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


def _crl_checked_server(
    cert: Path, key: Path, ca_file: Path, crl: Path, *, chain: bool = False
) -> ssl.SSLContext:
    """A server context that requires a client certificate and checks it against ``crl``, built
    by hand rather than by the listener, so a test can show what OpenSSL does with that CRL. The
    chain flag is set by hand too: ``harden_crl_check(chain=True)`` refuses a CA without its own
    CRL before OpenSSL could be asked (vault BACKLOG #5511)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=ca_file)
    harden_crl_check(ctx, str(crl), record_held_copy=False)
    if chain:
        ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_CHAIN
    return ctx


@pytest.mark.usefixtures("clean_anchor_checks")
def test_control_the_leaf_check_alone_admits_the_revoked_intermediates_client(
    two_tier: _TwoTier,
) -> None:
    """The instrument's control: the same CRL file under the leaf flag, as the listener loaded it
    before the fix, admits the client, so the CRL above really does revoke something."""
    leaf_only = _crl_checked_server(
        two_tier.server_cert, two_tier.server_key, two_tier.root_file, two_tier.revokes_intermediate
    )
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
@pytest.mark.parametrize("with_intermediate", [True, False], ids=["root-and-inter", "root-alone"])
def test_a_loaded_ca_with_no_crl_of_its_own_refuses_the_build(
    two_tier: _TwoTier, tmp_path: Path, with_intermediate: bool
) -> None:
    """Only the intermediate's CRL in the file, the root loaded with or without the intermediate:
    under the chain check every client would be refused at the handshake (the root-alone case was
    measured by review round 2), so the build refuses instead."""
    ca_file = tmp_path / "client-ca.pem"
    ca_file.write_bytes(
        two_tier.root_file.read_bytes()
        + (two_tier.inter_file.read_bytes() if with_intermediate else b"")
    )
    crl_file = tmp_path / "inter-crl-only.pem"
    crl_file.write_bytes(two_tier.inter_crl_file.read_bytes())
    settings = _settings(two_tier, crl_file).model_copy(update={"tls_client_ca_file": str(ca_file)})
    with pytest.raises(
        ValueError, match="client CA.s. 'CN=Client Root'.* have no CRL of their own"
    ):
        build_api_ssl_context(settings)
    # The control: with the root's CRL added, the same CA file builds and admits the client.
    crl_file.write_bytes(two_tier.revokes_nothing.read_bytes())
    _handshake(_client(two_tier), build_api_ssl_context(settings))


@dataclass(frozen=True)
class _Rollover:
    """One CA name, ``CN=Client Root``, under two keys, with a client leaf under the new key and
    a server certificate under the old one. Every CRL here is minted on demand."""

    d: Path
    old_key: ec.EllipticCurvePrivateKey
    new_key: ec.EllipticCurvePrivateKey
    old_root: Path
    new_root: Path
    server_cert: Path
    server_key: Path
    client_bundle: Path
    client_key: Path

    def crl(self, name: str, *crls: bytes) -> Path:
        path = self.d / name
        path.write_bytes(b"".join(crls))
        return path

    def settings(self, ca_files: list[Path], crl: Path) -> ApiSettings:
        ca_file = self.d / "client-ca.pem"
        ca_file.write_bytes(b"".join(p.read_bytes() for p in ca_files))
        return ApiSettings(
            tls_cert_file=str(self.server_cert),
            tls_key_file=str(self.server_key),
            tls_client_ca_file=str(ca_file),
            tls_client_crl_file=str(crl),
        )

    def client(self) -> ssl.SSLContext:
        """TLS 1.2, as :func:`_client`, so the server's verdict lands inside the handshake."""
        ctx = ssl.create_default_context(cadata=self.old_root.read_text("ascii"))
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(self.client_bundle, self.client_key)
        return ctx


@pytest.fixture
def rollover(tmp_path: Path) -> _Rollover:
    old_key, new_key, leaf_key, server_key = (
        ec.generate_private_key(ec.SECP256R1()) for _ in range(4)
    )
    files = {
        "old-root.pem": _pem(_cert("Client Root", old_key, "Client Root", old_key, ca=True)),
        "new-root.pem": _pem(_cert("Client Root", new_key, "Client Root", new_key, ca=True)),
        "server.pem": _pem(_cert("server", server_key, "Client Root", old_key, ca=False)),
        "server-key.pem": _key_pem(server_key),
        "client.pem": _pem(_cert("svc", leaf_key, "Client Root", new_key, ca=False)),
        "client-key.pem": _key_pem(leaf_key),
    }
    for name, data in files.items():
        (tmp_path / name).write_bytes(data)
    return _Rollover(
        d=tmp_path,
        old_key=old_key,
        new_key=new_key,
        old_root=tmp_path / "old-root.pem",
        new_root=tmp_path / "new-root.pem",
        server_cert=tmp_path / "server.pem",
        server_key=tmp_path / "server-key.pem",
        client_bundle=tmp_path / "client.pem",
        client_key=tmp_path / "client-key.pem",
    )


@pytest.mark.usefixtures("clean_anchor_checks")
@pytest.mark.parametrize("akid", [True, False], ids=["names-key", "names-no-key"])
def test_a_crl_whose_issuer_differs_from_its_ca_only_in_spacing_builds_and_admits(
    rollover: _Rollover, akid: bool
) -> None:
    """Red before the fix: the check compared the CRL's issuer name with the CA's subject with
    white space exact, so a CRL from ``CN=Client Root `` refused the start, while OpenSSL drops
    that space, takes the CRL as the CA's own, and admits the client. With no authority key
    identifier, the CA's key verifying the CRL is what makes it the CA's."""
    crl = rollover.crl("spaced.pem", _crl("Client Root ", rollover.new_key, None, akid=akid))
    ctx = build_api_ssl_context(rollover.settings([rollover.new_root], crl))
    _handshake(rollover.client(), ctx)


@pytest.mark.usefixtures("clean_anchor_checks")
def test_a_crl_the_cas_key_signed_under_another_name_refuses_the_build(
    rollover: _Rollover,
) -> None:
    """OpenSSL finds a CRL by name, so a CRL the CA's key signed under ``CN=Renamed Root`` is no
    CRL for ``CN=Client Root``: the start refuses, and by hand the handshake does too."""
    crl = rollover.crl("renamed.pem", _crl("Renamed Root", rollover.new_key, None))
    settings = rollover.settings([rollover.new_root], crl)
    with pytest.raises(
        ValueError, match="client CA.s. 'CN=Client Root'.* have no CRL of their own"
    ):
        build_api_ssl_context(settings)
    by_hand = _crl_checked_server(
        rollover.server_cert,
        rollover.server_key,
        Path(str(settings.tls_client_ca_file)),
        crl,
        chain=True,
    )
    with pytest.raises(ssl.SSLError, match="unable to get certificate CRL"):
        _handshake(rollover.client(), by_hand)


@pytest.mark.usefixtures("clean_anchor_checks")
def test_a_same_name_rollover_whose_crls_name_no_key_refuses_the_build(
    rollover: _Rollover,
) -> None:
    """Each key signed a CRL, but neither CRL names its key, so OpenSSL tells them apart by date
    alone: with the old key's CRL the newer one, the new key's client fails with ``CRL signature
    failure``. The start refuses both CAs instead. The control, at the end, is the same two CRLs
    and dates with each naming its key, which build and admit that client."""

    def crls(name: str, *, akid: bool) -> Path:
        return rollover.crl(
            name,
            _crl("Client Root", rollover.old_key, None, akid=akid, age=_DAY / 4),
            _crl("Client Root", rollover.new_key, None, akid=akid),
        )

    crl = crls("no-akid.pem", akid=False)
    settings = rollover.settings([rollover.old_root, rollover.new_root], crl)
    with pytest.raises(
        ValueError, match="client CA.s. 'CN=Client Root'.* have no CRL of their own"
    ) as err:
        build_api_ssl_context(settings)
    for root in (rollover.old_root, rollover.new_root):
        serial = x509.load_pem_x509_certificate(root.read_bytes()).serial_number
        assert f"(serial number {serial:#x})" in str(err.value)
    by_hand = _crl_checked_server(
        rollover.server_cert,
        rollover.server_key,
        Path(str(settings.tls_client_ca_file)),
        crl,
        chain=True,
    )
    with pytest.raises(ssl.SSLError, match="CRL signature failure"):
        _handshake(rollover.client(), by_hand)
    keyed = settings.model_copy(update={"tls_client_crl_file": str(crls("akid.pem", akid=True))})
    _handshake(rollover.client(), build_api_ssl_context(keyed))


@pytest.mark.usefixtures("clean_anchor_checks")
def test_a_newer_crl_naming_no_key_beside_each_cas_own_refuses_the_build(
    rollover: _Rollover,
) -> None:
    """Each key has its own CRL naming it, and a newer CRL from the old key names no key, so
    OpenSSL may pick it for the new key's clients and fail them with ``CRL signature failure``.
    Every CRL a CA fits must be its own, so the start refuses the new key's CA."""
    crl = rollover.crl(
        "poisoned.pem",
        _crl("Client Root", rollover.old_key, None),
        _crl("Client Root", rollover.new_key, None),
        _crl("Client Root", rollover.old_key, None, akid=False, age=_DAY / 4),
    )
    settings = rollover.settings([rollover.old_root, rollover.new_root], crl)
    with pytest.raises(
        ValueError, match="client CA.s. 'CN=Client Root'.* have no CRL of their own"
    ) as err:
        build_api_ssl_context(settings)
    new_serial = x509.load_pem_x509_certificate(rollover.new_root.read_bytes()).serial_number
    assert f"(serial number {new_serial:#x})" in str(err.value)
    by_hand = _crl_checked_server(
        rollover.server_cert,
        rollover.server_key,
        Path(str(settings.tls_client_ca_file)),
        crl,
        chain=True,
    )
    with pytest.raises(ssl.SSLError, match="CRL signature failure"):
        _handshake(rollover.client(), by_hand)


@pytest.mark.usefixtures("clean_anchor_checks")
def test_a_same_name_rollover_with_only_the_old_keys_crl_refuses_the_build(
    rollover: _Rollover,
) -> None:
    """Red before the fix: the old key's CRL carries the name both CAs share, so it counted for
    both and the start passed, while every client under the new key is refused at the handshake.
    The control: with the new key's CRL added, the same CA file builds and admits that client."""
    old_crl = _crl("Client Root", rollover.old_key, None)
    old_only = rollover.crl("old-only.pem", old_crl)
    settings = rollover.settings([rollover.old_root, rollover.new_root], old_only)
    with pytest.raises(
        ValueError, match="client CA.s. 'CN=Client Root'.* have no CRL of their own"
    ) as err:
        build_api_ssl_context(settings)
    # It names the new key's CA alone, by serial number, since the two share a name.
    serials = {
        root: f"{x509.load_pem_x509_certificate(root.read_bytes()).serial_number:#x}"
        for root in (rollover.old_root, rollover.new_root)
    }
    assert f"(serial number {serials[rollover.new_root]})" in str(err.value)
    assert serials[rollover.old_root] not in str(err.value)
    # The handshake the refusal speaks for: the old key's CRL alone refuses the new key's client.
    by_hand = _crl_checked_server(
        rollover.server_cert,
        rollover.server_key,
        Path(str(settings.tls_client_ca_file)),
        old_only,
        chain=True,
    )
    with pytest.raises(ssl.SSLError, match="unable to get certificate CRL"):
        _handshake(rollover.client(), by_hand)
    both = rollover.crl("both.pem", old_crl, _crl("Client Root", rollover.new_key, None))
    _handshake(
        rollover.client(),
        build_api_ssl_context(settings.model_copy(update={"tls_client_crl_file": str(both)})),
    )


@pytest.mark.usefixtures("clean_anchor_checks")
def test_control_a_loaded_ca_with_no_crl_at_all_still_refuses_the_build(
    rollover: _Rollover,
) -> None:
    """The control for the two above, green before the fix and after it: matching by key still
    refuses a loaded CA that signed no CRL in the file, here one of another name beside the new
    key's CA and its CRL."""
    other_key = ec.generate_private_key(ec.SECP256R1())
    other = rollover.d / "other-ca.pem"
    other.write_bytes(_pem(_cert("Other CA", other_key, "Other CA", other_key, ca=True)))
    crl = rollover.crl("new-only.pem", _crl("Client Root", rollover.new_key, None))
    with pytest.raises(ValueError, match="client CA.s. 'CN=Other CA'.* have no CRL of their own"):
        build_api_ssl_context(rollover.settings([rollover.new_root, other], crl))


def test_a_crl_that_is_there_but_unreadable_refuses_naming_its_setting(
    two_tier: _TwoTier, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _denied(path: str) -> bytes:
        if Path(path) == two_tier.revokes_nothing:
            raise PermissionError(13, "Permission denied")
        return Path(path).read_bytes()

    monkeypatch.setattr(ta, "_read_regular_file", _denied)
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: True)
    monkeypatch.setattr(ta, "anchor_path_verdict", lambda _p: PathVerdict(ok=True))
    with pytest.raises(TrustAnchorError, match=r"\[api\]\.tls_client_crl_file: could not read"):
        build_api_ssl_context(_settings(two_tier, two_tier.revokes_nothing))


@pytest.mark.usefixtures("clean_anchor_checks")
def test_a_missing_crl_still_refuses_with_its_own_message(
    two_tier: _TwoTier, tmp_path: Path
) -> None:
    with pytest.raises(ValueError, match="does not exist"):
        build_api_ssl_context(_settings(two_tier, tmp_path / "absent.pem"))


def test_a_ca_whose_akid_fit_cannot_be_read_has_no_crl_of_its_own(
    rollover: _Rollover, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Red before the fix: where reading the CA for the authority key identifier match raised,
    :func:`pki._signed_by` took the CA as fitting, so a CRL its key verified counted as its own,
    while :func:`pki._signature_state` takes such a CA as fitting nothing. It fails closed now:
    the CA cannot be shown to have a CRL of its own. The control is the same CA and CRL read."""
    new = x509.load_pem_x509_certificate(rollover.new_root.read_bytes())
    ders = [new.public_bytes(serialization.Encoding.DER)]
    own = _crl("Client Root", rollover.new_key, None)
    assert pki_module.cas_without_own_crl(ders, own) == []  # the control: read, it is its own
    real = pki_module._akid_fit

    def fit(akid: Any, ca: Any) -> bool | None:
        if ca.cert == new:
            raise x509.UnsupportedGeneralNameType("x400Address is not supported")
        return real(akid, ca)

    monkeypatch.setattr(pki_module, "_akid_fit", fit)
    assert pki_module.cas_without_own_crl(ders, own) == [
        (new.subject.rfc4514_string(), new.serial_number)
    ]


@pytest.mark.parametrize(
    "error",
    [x509.DuplicateExtension("twice", ExtensionOID.SUBJECT_KEY_IDENTIFIER), ValueError("bad")],
    ids=["duplicate", "unreadable"],
)
def test_a_ca_whose_subject_key_identifier_cannot_be_read_has_no_crl_of_its_own(
    rollover: _Rollover, error: Exception
) -> None:
    """Red before the fix: :func:`pki._akid_fit` read a CA whose Subject Key Identifier raised as
    ruled out by a CRL that names a key, so that CRL was no candidate for it, and a CA with
    another CRL it signed passed. OpenSSL skips the key identifier check where it reads no
    identifier, so it may judge the CA's clients by that CRL. It fails closed now. The control is
    the same CRL and a CA whose identifier reads."""

    class _Extensions:
        def get_extension_for_class(self, _kind: object) -> object:
            raise error

    class _Unread:
        extensions = _Extensions()

    keyed = x509.load_pem_x509_crl(_crl("Client Root", rollover.new_key, None))
    akid = pki_module._crl_extensions(keyed).akid
    assert akid is not None and akid.key_identifier is not None
    new = rollover.new_root.read_bytes()
    read = pki_module._listed_ca(x509.load_pem_x509_certificate(new).public_bytes(_DER))
    assert pki_module._signed_by(keyed, akid, read) is True  # the control
    unread = pki_module._ListedCa(read.name, _Unread(), read.serial)  # type: ignore[arg-type]
    assert pki_module._signed_by(keyed, akid, unread) is False
    # Red before the second fix: a serial the CRL's AKID names that is not this CA's rules the CA
    # out, as OpenSSL's match does, before its unreadable identifier is read.
    other = x509.load_pem_x509_crl(
        x509.CertificateRevocationListBuilder()
        .issuer_name(_name("Client Root"))
        .last_update(_NOW - _DAY)
        .next_update(_NOW + 30 * _DAY)
        .add_extension(
            x509.AuthorityKeyIdentifier(
                key_identifier=akid.key_identifier,
                authority_cert_issuer=[x509.DirectoryName(_name("Client Root"))],
                authority_cert_serial_number=read.serial + 1,
            ),
            False,
        )
        .sign(rollover.new_key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
    )
    other_akid = pki_module._crl_extensions(other).akid
    assert pki_module._signed_by(other, other_akid, unread) is None


@pytest.mark.usefixtures("clean_anchor_checks")
def test_a_reload_reports_a_proven_bad_signature_as_a_start_does(rollover: _Rollover) -> None:
    """Red before the fix: with the own-CRL rule checked first, a forged CRL naming the old key
    was reported as a CA without its own CRL, telling the operator to add a CRL that is already
    there, while a start reports the proven bad signature. The reload follows the start's order."""
    crl = rollover.crl(
        "held.pem",
        _crl("Client Root", rollover.old_key, None, age=2 * _DAY),
        _crl("Client Root", rollover.new_key, None, age=2 * _DAY),
    )
    ctx = build_api_ssl_context(rollover.settings([rollover.old_root, rollover.new_root], crl))
    forged = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(_name("Client Root"))
        .last_update(_NOW - _DAY / 4)
        .next_update(_NOW + 30 * _DAY)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(rollover.old_key.public_key()),
            False,
        )
        .sign(ec.generate_private_key(ec.SECP256R1()), hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
    )
    crl.write_bytes(
        _crl("Client Root", rollover.old_key, None, age=_DAY / 2)
        + _crl("Client Root", rollover.new_key, None, age=_DAY / 2)
        + forged
    )
    gc.collect()
    (outcome,) = [o for o in crl_reload.reload_replaced_crls() if Path(o.path) == crl.resolve()]
    assert outcome.refusal is not None
    assert outcome.refusal.remedy == crl_reload.BAD_SIGNATURE, outcome.refusal
    assert outcome.reloaded == 0
    _handshake(rollover.client(), ctx)  # the copy it holds still admits the client
    with pytest.raises(ValueError, match="does not verify the CRL's signature"):
        build_api_ssl_context(rollover.settings([rollover.old_root, rollover.new_root], crl))


@pytest.mark.usefixtures("clean_anchor_checks")
def test_a_reload_reports_a_ca_without_its_own_crl_as_a_file_to_fix_before_any_signature(
    rollover: _Rollover,
) -> None:
    """Red before the fix: the reload checked the own-CRL rule after the signature check, whose
    finding ends that context's checks, so a replacement that drops the old key's CRL and adds an
    intermediate's CRL no listed CA issued was reported with a restart, and the restart is then
    refused. It is a file to fix, as a start says."""
    old_own = _crl("Client Root", rollover.old_key, None, age=2 * _DAY)
    new_own = _crl("Client Root", rollover.new_key, None, age=2 * _DAY)
    crl = rollover.crl("held.pem", old_own, new_own)
    ctx = build_api_ssl_context(rollover.settings([rollover.old_root, rollover.new_root], crl))
    crl.write_bytes(
        _crl("Client Root", rollover.new_key, None, age=_DAY / 2)
        + _crl("Some Intermediate", ec.generate_private_key(ec.SECP256R1()), None)
    )
    gc.collect()
    (outcome,) = [o for o in crl_reload.reload_replaced_crls() if Path(o.path) == crl.resolve()]
    assert outcome.refusal is not None and outcome.refusal.remedy == crl_reload.FIX
    assert "have no CRL of their own" in outcome.refusal.reason
    assert outcome.reloaded == 0
    _handshake(rollover.client(), ctx)


@pytest.mark.usefixtures("clean_anchor_checks")
def test_a_reload_refuses_a_file_a_start_would_refuse_for_a_ca_without_its_own_crl(
    rollover: _Rollover,
) -> None:
    """Red before the fix: the running-hop reload did not apply the own-CRL rule, so a
    replacement carrying a newer CRL from the old key that names no key, which a start refuses
    (:func:`test_a_newer_crl_naming_no_key_beside_each_cas_own_refuses_the_build`), loaded live.
    Now the reload refuses it as a file to fix, and the hop keeps the copy it holds, which still
    admits the new key's client. The control is a proper refresh, which the reload applies."""
    old_own = _crl("Client Root", rollover.old_key, None, age=2 * _DAY)
    new_own = _crl("Client Root", rollover.new_key, None, age=2 * _DAY)
    crl = rollover.crl("held.pem", old_own, new_own)
    ctx = build_api_ssl_context(rollover.settings([rollover.old_root, rollover.new_root], crl))
    _handshake(rollover.client(), ctx)

    def one_pass() -> crl_reload.ReloadOutcome:
        gc.collect()
        (mine,) = [o for o in crl_reload.reload_replaced_crls() if Path(o.path) == crl.resolve()]
        return mine

    crl.write_bytes(
        _crl("Client Root", rollover.old_key, None, age=_DAY / 2)
        + _crl("Client Root", rollover.new_key, None, age=_DAY / 2)
        + _crl("Client Root", rollover.old_key, None, akid=False, age=_DAY / 4)
    )
    outcome = one_pass()
    assert outcome.refusal is not None and outcome.refusal.remedy == crl_reload.FIX
    assert "have no CRL of their own" in outcome.refusal.reason
    new_serial = x509.load_pem_x509_certificate(rollover.new_root.read_bytes()).serial_number
    assert f"(serial number {new_serial:#x})" in outcome.refusal.reason
    assert outcome.reloaded == 0
    _handshake(rollover.client(), ctx)  # the copy it holds still admits the client

    crl.write_bytes(
        _crl("Client Root", rollover.old_key, None, age=_DAY / 2)
        + _crl("Client Root", rollover.new_key, None, age=_DAY / 2)
    )
    control = one_pass()
    assert control.refusal is None and control.reloaded == 1
    _handshake(rollover.client(), ctx)


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
    assert MF_CLIENT_PEERCERT_STATE_KEY in enriched_app_state({}, direct, trusted_proxies=())


@pytest.mark.parametrize("peer", [None, (), ("not-an-address", 1), 7])
def test_a_peer_that_cannot_be_placed_counts_as_a_proxy(peer: object) -> None:
    transport: Any = _Transport(peer, _CERT)
    assert peer_is_trusted_proxy(transport, parse_trusted_proxies(["10.0.0.5"]))
    assert not peer_is_trusted_proxy(transport, ())


def test_the_shim_class_skips_a_declared_proxys_certificate() -> None:
    class _Base:
        def __init__(self) -> None:
            self.app_state: dict[str, Any] = {}

        def connection_made(self, transport: object) -> None:
            pass

    cls: Any = client_cert_http_protocol_class(_Base, trusted_proxies=["10.0.0.5"])
    from_proxy, direct = cls(), cls()
    from_proxy.connection_made(_Transport(("10.0.0.5", 1), _CERT))
    direct.connection_made(_Transport(("10.0.0.6", 1), _CERT))
    assert MF_CLIENT_PEERCERT_STATE_KEY not in from_proxy.app_state
    assert MF_CLIENT_PEERCERT_STATE_KEY in direct.app_state


@pytest.mark.usefixtures("bounded_warn_only_retention", "verified_log_forwarding")
def test_serve_never_stashes_a_declared_proxys_certificate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Through ``serve``: with mTLS, a cert-identity map and ``[api].trusted_proxies`` declared, the
    HTTP class uvicorn is handed does not stash the certificate a declared proxy presents, and does
    stash the same certificate from another peer. It reads only what ``serve`` hands uvicorn and
    names nothing the fix added, so lifted out of this module (whose imports do name such things),
    it fails on the code before the fix on the stash itself, not on a missing name."""
    from messagefoundry.__main__ import main
    from messagefoundry.store.crypto import generate_key
    from tests.test_api_tls import SAMPLES_CONFIG, _self_signed

    cert, key = _self_signed(tmp_path)
    captured: dict[str, Any] = {}
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    monkeypatch.setenv("MEFOR_TLS_REVOCATION_ATTESTED", "1")  # ADR 0078 opt-out (off-loopback TLS)
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: captured.update(k))
    # GIVEN 1 (ADR 0148): declare synthetic so the PHI gates stay quiet; the shim is under test.
    (tmp_path / "messagefoundry.toml").write_text(
        "security.block_unlisted_outbound = true\n"
        "security.allow_unencrypted_phi = true\n"
        "security.allow_unencrypted_phi_under_strict_enforcement = true\n"
        "alerts.security_notifications_required = false\n"
        'security.local_access_only = false\nsecurity.listen_address = "0.0.0.0"\n'
        # Warn, so the proxy-hop gates (#3538, ASVS 12.1.1's probe of a public origin) let a
        # declared proxy start without a reachable front door; they are not under test.
        'security.enforcement = "warn"\n'
        f'[api]\ntls_cert_file = "{cert.as_posix()}"\n'
        f'tls_key_file = "{key.as_posix()}"\ntls_client_ca_file = "{cert.as_posix()}"\n'
        'trusted_proxies = ["10.0.0.5"]\nproxy_tls_min_version = "1.2"\n'
        'tls_client_cert_identities = { "CN=Test CA" = '
        '{ "CN:svc" = "0123456789abcdef0123456789abcdef" } }\n',
        encoding="utf-8",
    )
    assert main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "dev"]) == 0
    http_cls: Any = captured["http"]
    assert "connection_made" in vars(http_cls), "serve did not hand uvicorn the shim"
    # uvicorn's own connection_made needs a live loop and config; stand down the first class from
    # outside this package, so the shim and every layer of ours beneath it still run.
    server_base = next(c for c in http_cls.__mro__ if not c.__module__.startswith("messagefoundry"))
    monkeypatch.setattr(server_base, "connection_made", lambda self, transport: None)

    def _connect(peer: tuple[str, int]) -> dict[str, Any]:
        protocol: Any = object.__new__(http_cls)
        protocol.app_state = {}
        protocol.connection_made(_Transport(peer, _CERT))
        state: dict[str, Any] = protocol.app_state
        return state

    assert MF_CLIENT_PEERCERT_STATE_KEY not in _connect(("10.0.0.5", 443)), (
        "a declared proxy's certificate was stashed, so callers behind it would act as its "
        "mapped principal"
    )
    assert MF_CLIENT_PEERCERT_STATE_KEY in _connect(("10.0.0.6", 443))


@pytest.mark.parametrize("build", [_client_cert_shim, client_cert_http_protocol_class])
def test_every_shim_builder_must_be_given_the_proxies(build: Any) -> None:
    """Keyword-only with no default, so a call site that forgot them fails rather than skips."""
    parameter = inspect.signature(build).parameters["trusted_proxies"]
    assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
    assert parameter.default is inspect.Parameter.empty


def test_the_resolvers_transport_fallback_skips_a_declared_proxys_certificate() -> None:
    """The fallback in peer_cert_from_request reads scope['transport'] for a server that puts it
    there; the proxy rule must hold on that path too."""
    from types import SimpleNamespace

    from starlette.requests import Request

    from messagefoundry.api.security import peer_cert_from_request

    app = SimpleNamespace(state=SimpleNamespace(trusted_proxies=("10.0.0.5",)))
    for peer, expected in ((("10.0.0.5", 1), None), (("10.0.0.6", 1), _CERT["subject"])):
        scope = {"type": "http", "headers": [], "app": app, "transport": _Transport(peer, _CERT)}
        cert = peer_cert_from_request(Request(scope))
        assert (cert["subject"] if cert else None) == expected, peer


def test_the_resolvers_transport_fallback_reads_a_connection_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BACKLOG #5788: the fallback's verified read runs once per connection, not per request; a
    second connection is read on its own, and a read with no verified issuer is not kept."""
    from types import SimpleNamespace

    from starlette.requests import Request

    import messagefoundry.api.security as security_module
    from messagefoundry.api.security import peer_cert_from_request
    from messagefoundry.api.tls_client_cert import peercert_from_ssl_object

    reads: list[object] = []
    unissued: list[object] = []

    def counting(ssl_object: Any) -> Any:
        reads.append(ssl_object)
        cert = peercert_from_ssl_object(ssl_object)
        issuer = "" if ssl_object in unissued else "CN=Service CA"
        return None if cert is None else {**cert, VERIFIED_ISSUER_KEY: issuer}

    monkeypatch.setattr(security_module, "peercert_from_ssl_object", counting)
    app = SimpleNamespace(state=SimpleNamespace(trusted_proxies=()))
    first, second = _Transport(("10.0.0.6", 1), _CERT), _Transport(("10.0.0.7", 1), _CERT)
    third = _Transport(("10.0.0.8", 1), _CERT)
    unissued.append(third._ssl)
    for transport in (first, first, first, second, third, third):
        scope = {"type": "http", "headers": [], "app": app, "transport": transport}
        cert = peer_cert_from_request(Request(scope))
        assert cert is not None and cert["subject"] == _CERT["subject"]
    assert reads == [first._ssl, second._ssl, third._ssl, third._ssl]
    # A connection whose peer now presents another leaf, as a renegotiation can, is read again.
    monkeypatch.setattr(
        first._ssl, "getpeercert", lambda binary_form=False: b"another" if binary_form else _CERT
    )
    scope = {"type": "http", "headers": [], "app": app, "transport": first}
    assert peer_cert_from_request(Request(scope)) is not None
    assert reads[-1] is first._ssl and len(reads) == 5


@pytest.mark.usefixtures("clean_anchor_checks")
def test_the_proxy_and_cert_map_warning_is_logged_when_the_context_is_built(
    two_tier: _TwoTier, caplog: pytest.LogCaptureFixture
) -> None:
    """Logged by build_api_ssl_context, which serve calls once logging is configured."""
    settings = _settings(two_tier, two_tier.revokes_nothing).model_copy(
        update={
            "tls_client_cert_identities": {"CN=Client Root": {"CN:svc": "0" * 32}},
            "trusted_proxies": ["10.0.0.5"],
        }
    )
    with caplog.at_level(logging.WARNING):
        build_api_ssl_context(settings)
    assert any("declared proxy maps to no principal" in r.getMessage() for r in caplog.records)


def test_trusted_proxies_parse_to_both_ipv4_spellings() -> None:
    proxies = parse_trusted_proxies(["10.0.0.5"])
    assert ipaddress.ip_network("10.0.0.5/32") in proxies
    assert ipaddress.ip_network("::ffff:10.0.0.5/128") in proxies


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


def test_a_leaf_with_a_duplicated_extension_names_no_issuer_rather_than_raising(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """cryptography raises DuplicateExtension, which is not a ValueError, when it reads a leaf
    listing one extension twice. issuer_of promises never to raise, so it names no issuer."""
    ca = _new_ca(_name("Service CA"))
    index = IssuerIndex(_pem(ca[0]).decode("ascii"))
    der = _leaf_der(ca, [ExtendedKeyUsageOID.CLIENT_AUTH])

    def _duplicated(_leaf: x509.Certificate) -> bool:
        raise x509.DuplicateExtension("listed twice", ExtendedKeyUsageOID.CLIENT_AUTH)

    monkeypatch.setattr(pki_module, "_names_client_auth", _duplicated)
    assert index.issuer_of(der, require_client_auth=True) == ""


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
    assert index._answers.cache_info().currsize == 2
