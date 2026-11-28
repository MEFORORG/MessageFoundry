# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Behavioural reds for vault BACKLOG #5627, #5628 and #5904, the API listener's client trust.

The fixes landed in engine PR 2982 (merge ``56dda19b13``). Every test here imports only names
that already existed on that merge's first parent, ``717bb0ef3b4``, so the module runs unchanged
against that tree and against main, and the fail-before reading is this module's own:

* #5627: a revoked intermediate CA refuses the clients under it; a CRL another principal can
  write refuses the build under ``enforce``.
* #5628: a leaf with no clientAuth extended key usage maps to nobody, in a real handshake that
  OpenSSL accepts; a repeat leaf costs no second issuer signature check.
* #5904: :func:`~messagefoundry.api.security.resolve_client_cert_identity` does not authenticate a
  request whose socket peer is a declared proxy as the principal the proxy's own certificate maps
  to, so the identity can no longer disagree with the forwarded address the audit records.

Each refusal has a control that admits, so a refusal is the fix and not a fixture that refuses
everyone. All material is synthetic and minted here. No PHI.
"""

from __future__ import annotations

import asyncio
import datetime
import ssl
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from messagefoundry import pki as pki_module
from messagefoundry.api.security import resolve_client_cert_identity
from messagefoundry.api.tls import build_api_ssl_context
from messagefoundry.api.tls_client_cert import peercert_from_ssl_object
from messagefoundry.auth import trust_anchors as ta
from messagefoundry.auth.anchor_path import PathVerdict
from messagefoundry.auth.trust_anchors import TrustAnchorError
from messagefoundry.config.settings import ApiSettings
from messagefoundry.credential import VERIFIED_ISSUER_KEY

_NOW = datetime.datetime.now(datetime.UTC)
_DAY = datetime.timedelta(days=1)
_USER_ID = "0" * 32
_PROXY = "10.0.0.5"


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(
    subject: str,
    key: ec.EllipticCurvePrivateKey,
    issuer: str,
    signer: ec.EllipticCurvePrivateKey,
    *,
    ca: bool,
    client_auth: bool = True,
) -> x509.Certificate:
    """SKI, AKI and KeyUsage are set because the API context turns on ``VERIFY_X509_STRICT``. A leaf
    carries serverAuth and clientAuth, or no extended key usage at all with ``client_auth=False``."""
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
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=ca,
                crl_sign=ca,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    if not ca:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]), False
        )
        if client_auth:
            builder = builder.add_extension(
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
        .add_extension(x509.CRLNumber(1), False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), False
        )
    )
    if revoked is not None:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(revoked.serial_number)
            .revocation_date(_NOW - _DAY)
            .build()
        )
    return builder.sign(signer, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)


_pem = pki_module.cert_to_pem
_key_pem = pki_module.key_to_pem


def _handshake(client: ssl.SSLContext, server: ssl.SSLContext) -> ssl.SSLObject:
    """A real TLS handshake in memory; the server's ``SSLObject``, or :class:`ssl.SSLError` from
    whichever side refuses."""
    c_in, c_out, s_in, s_out = (ssl.MemoryBIO() for _ in range(4))
    c = client.wrap_bio(c_in, c_out, server_hostname="localhost")
    s = server.wrap_bio(s_in, s_out, server_side=True)
    done = {"c": False, "s": False}
    for _ in range(50):
        for name, obj in (("c", c), ("s", s)):
            if done[name]:
                continue
            try:
                obj.do_handshake()
                done[name] = True
            except ssl.SSLWantReadError:
                pass
        s_in.write(c_out.read())
        c_in.write(s_out.read())
        if done["c"] and done["s"]:
            return s
    raise AssertionError("handshake neither completed nor failed within 50 rounds")


class _Pki:
    """A root the listener loads, an intermediate the client sends, and files for each case."""

    def __init__(self, d: Path) -> None:
        root_key, inter_key, server_key, leaf_key, direct_key, bare_key = (
            ec.generate_private_key(ec.SECP256R1()) for _ in range(6)
        )
        root = _cert("Client Root", root_key, "Client Root", root_key, ca=True)
        inter = _cert("Client Issuing", inter_key, "Client Root", root_key, ca=True)
        leaf = _cert("svc", leaf_key, "Client Issuing", inter_key, ca=False)
        server = _cert("server", server_key, "Client Root", root_key, ca=False)
        # Leaves the root issues directly, so the issuer index (which names a DIRECT issuer) names it.
        direct = _cert("svc", direct_key, "Client Root", root_key, ca=False)
        bare = _cert("svc", bare_key, "Client Root", root_key, ca=False, client_auth=False)
        inter_crl = _crl("Client Issuing", inter_key, None)
        self.dir = d
        files = {
            "root.pem": _pem(root),
            "server.pem": _pem(server),
            "server-key.pem": _key_pem(server_key),
            "chain-client.pem": _pem(leaf) + _pem(inter) + _key_pem(leaf_key),
            "direct-client.pem": _pem(direct) + _key_pem(direct_key),
            "bare-client.pem": _pem(bare) + _key_pem(bare_key),
            "revokes-inter.pem": _crl("Client Root", root_key, inter) + inter_crl,
            "revokes-nothing.pem": _crl("Client Root", root_key, None) + inter_crl,
        }
        for name, data in files.items():
            (d / name).write_bytes(data)

    def path(self, name: str) -> Path:
        return self.dir / name

    def settings(self, **update: Any) -> ApiSettings:
        return ApiSettings(
            tls_cert_file=str(self.path("server.pem")),
            tls_key_file=str(self.path("server-key.pem")),
            tls_client_ca_file=str(self.path("root.pem")),
            **update,
        )

    def client(self, bundle: str) -> ssl.SSLContext:
        """TLS 1.2, so the server's verdict on the client certificate lands inside the handshake."""
        ctx = ssl.create_default_context(cadata=self.path("root.pem").read_text("ascii"))
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(self.path(bundle))
        return ctx

    def mapped(self) -> ApiSettings:
        """The cert-identity map naming the direct leaf's subject under the root."""
        return self.settings(tls_client_cert_identities={"CN=Client Root": {"CN:svc": _USER_ID}})


@pytest.fixture(scope="module")
def pki(tmp_path_factory: pytest.TempPathFactory) -> _Pki:
    return _Pki(tmp_path_factory.mktemp("client-trust-reds"))


@pytest.fixture
def clean_anchor_checks(monkeypatch: pytest.MonkeyPatch) -> None:
    """ACL and path verdicts pinned clean, so a result does not depend on this machine's ACLs."""
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: True)
    monkeypatch.setattr(ta, "anchor_path_verdict", lambda _p: PathVerdict(ok=True))


# --- #5627 ------------------------------------------------------------------------------------------


@pytest.mark.usefixtures("clean_anchor_checks")
def test_a_revoked_intermediate_refuses_its_clients(pki: _Pki) -> None:
    ctx = build_api_ssl_context(
        pki.settings(tls_client_crl_file=str(pki.path("revokes-inter.pem")))
    )
    with pytest.raises(ssl.SSLError, match="revoked"):
        _handshake(pki.client("chain-client.pem"), ctx)


@pytest.mark.usefixtures("clean_anchor_checks")
def test_control_a_chain_nobody_revoked_is_admitted(pki: _Pki) -> None:
    ctx = build_api_ssl_context(
        pki.settings(tls_client_crl_file=str(pki.path("revokes-nothing.pem")))
    )
    _handshake(pki.client("chain-client.pem"), ctx)


@pytest.mark.parametrize(("acl", "path"), [(False, True), (True, False)], ids=["dacl", "path"])
def test_a_crl_another_principal_can_replace_refuses_under_enforce(
    pki: _Pki, monkeypatch: pytest.MonkeyPatch, acl: bool, path: bool
) -> None:
    crl = pki.path("revokes-nothing.pem")
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda p: acl if Path(p) == crl else True)
    monkeypatch.setattr(
        ta, "anchor_path_verdict", lambda p: PathVerdict(ok=path if Path(p) == crl else True)
    )
    with pytest.raises(TrustAnchorError, match=r"\[api\]\.tls_client_crl_file"):
        build_api_ssl_context(pki.settings(tls_client_crl_file=str(crl)), enforcing=True)


# --- #5628 ------------------------------------------------------------------------------------------


@pytest.mark.usefixtures("clean_anchor_checks")
def test_a_leaf_with_no_client_auth_usage_maps_to_nobody(pki: _Pki) -> None:
    """OpenSSL admits a client leaf with no extended key usage at all, so the handshake verifies."""
    view = peercert_from_ssl_object(
        _handshake(pki.client("bare-client.pem"), build_api_ssl_context(pki.mapped()))
    )
    assert view is not None, "the handshake did not verify the client certificate"
    assert view[VERIFIED_ISSUER_KEY] == ""


@pytest.mark.usefixtures("clean_anchor_checks")
def test_control_the_same_issuer_with_client_auth_maps(pki: _Pki) -> None:
    view = peercert_from_ssl_object(
        _handshake(pki.client("direct-client.pem"), build_api_ssl_context(pki.mapped()))
    )
    assert view is not None and view[VERIFIED_ISSUER_KEY] == "CN=Client Root"


@pytest.mark.usefixtures("clean_anchor_checks")
def test_a_repeat_client_costs_no_second_issuer_signature_check(
    pki: _Pki, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two connections from one leaf on one listener: only the first checks a signature for the
    issuer lookup. The shim makes that lookup through ``peercert_from_ssl_object``, called here
    directly, inside ``connection_made`` on the event loop. ``_directly_issued`` is a private seam,
    pinned on purpose: no public one shows a signature check, and a rename fails the patch loudly."""
    real = pki_module._directly_issued
    calls: list[int] = []

    def counting(leaf: x509.Certificate, issuer: x509.Certificate) -> bool:
        calls.append(1)
        return real(leaf, issuer)

    monkeypatch.setattr(pki_module, "_directly_issued", counting)
    ctx = build_api_ssl_context(pki.mapped())
    calls.clear()  # the build's own checks are not the per-connection lookup counted here
    client = pki.client("direct-client.pem")
    first = peercert_from_ssl_object(_handshake(client, ctx))
    after_first = len(calls)
    second = peercert_from_ssl_object(_handshake(client, ctx))
    assert first is not None and second is not None
    assert first[VERIFIED_ISSUER_KEY] == second[VERIFIED_ISSUER_KEY] == "CN=Client Root"
    assert after_first >= 1
    assert len(calls) == after_first, "the second connection checked the issuer's signature again"


# --- #5904 ------------------------------------------------------------------------------------------


class _Transport:
    def __init__(self, ssl_object: ssl.SSLObject, peer: tuple[str, int]) -> None:
        self._extra = {"ssl_object": ssl_object, "peername": peer}

    def get_extra_info(self, name: str) -> object:
        return self._extra.get(name)


class _Auth:
    async def identity_for_cert_user_id(self, user_id: str) -> Any:
        return SimpleNamespace(username="svc-account", user_id=user_id)


@pytest.mark.usefixtures("clean_anchor_checks")
def test_a_declared_proxys_own_certificate_is_no_caller_identity(pki: _Pki) -> None:
    """A proxy that re-encrypts presents its own mapped certificate on every forwarded request.
    Resolved, every caller behind it would act as its principal while the audit names the caller's
    forwarded address. The control is the same certificate from a peer that is no proxy.

    This drives the resolver's ``scope['transport']`` fallback, the path whose call shape is the
    same on both trees. The shim's own proxy rule, its ``trusted_proxies`` keyword new with the
    fix, is covered in ``tests/test_api_tls_client_trust.py`` (through ``serve`` as well)."""
    from starlette.requests import Request

    settings = pki.mapped()
    ctx = build_api_ssl_context(settings)
    state = SimpleNamespace(
        auth=_Auth(),
        tls_client_cert_identities=settings.tls_client_cert_identities,
        trusted_proxies=(_PROXY,),
    )
    app = SimpleNamespace(state=state)
    client = pki.client("direct-client.pem")

    def resolve(peer: tuple[str, int]) -> Any:
        ssl_object = _handshake(client, ctx)
        scope = {
            "type": "http",
            "headers": [],
            "app": app,
            "transport": _Transport(ssl_object, peer),
        }
        return asyncio.run(resolve_client_cert_identity(Request(scope)))

    assert resolve((_PROXY, 443)) is None
    direct = resolve(("10.0.0.6", 443))
    assert direct is not None and direct.user_id == _USER_ID
