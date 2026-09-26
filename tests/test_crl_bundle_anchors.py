# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1890: loading a CRL file must not add trust anchors to the hop.

``harden_crl_check`` loads through ``load_verify_locations(cafile=)``, and that call adds every
certificate in the named file as well as every CRL. Before this fix, a CRL file that also carried a
CA made that CA a trusted issuer for the hop, beside the pinned CA and outside the pin's check. Now a
load that changes the trust store's certificate count is refused.

What this file proves, and the instrument for each:

* **The trust store's CERTIFICATE count.** A CRL file carrying a planted CA, or a non-CA
  certificate, refuses. A bare CRL and the pinned CA's own CA+CRL file load, and leave ``x509`` and
  ``x509_ca`` where the pinned CA left them while the CRL count rises.
* **Real listeners, the ones the row names.** ``[api].tls_client_crl_file``, the MLLP builder (which
  also serves the inbound HTTP listener) and the DICOM SCP refuse to build with the planted bundle.
  Built with the pinned CA's own bundle, each admits the pinned CA's client and refuses the planted
  CA's client in a real handshake.
* **The control for the handshake.** The planted bundle loaded by path onto a built listener admits
  the planted client. So the bundle really would have widened the hop; the refusal is not guarding
  a file that could never have admitted anyone. That is also why the bundle carries the planted CA's
  own CRL: under ``VERIFY_CRL_CHECK_LEAF`` a client whose issuer has no CRL is refused anyway.

All material is synthetic and minted here. No PHI.
"""

from __future__ import annotations

import datetime
import hashlib
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from messagefoundry.api.tls import build_api_ssl_context
from messagefoundry.auth import trust_anchors as ta
from messagefoundry.auth.anchor_path import PathVerdict
from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.config.settings import ApiSettings
from messagefoundry.config.tls_policy import HopPosture, harden_crl_check
from messagefoundry.config.wiring import WiringError
from messagefoundry.pipeline.wiring_runner import check_inbound_revocation
from messagefoundry.transports.dicom import _server_ssl_context
from messagefoundry.transports.mllp import _mllp_ssl_context
from tests.test_trust_anchor_byte_binding import _handshake, _subjects

_NOW = datetime.datetime.now(datetime.UTC)
_DAY = datetime.timedelta(days=1)


# --- a tiny PKI that keeps each CA's key, so each CA can sign its own CRL ---------------------------


@dataclass(frozen=True)
class _Ca:
    pem: bytes  # the CA certificate
    crl: bytes  # a fresh CRL this CA signed, revoking nothing
    leaf: str  # a localhost leaf for server and client auth, a file path
    leaf_key: str


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


def _make_ca(d: Path, cn: str) -> _Ca:
    """SKI, AKI and KeyUsage are present because the listener contexts turn on ``VERIFY_X509_STRICT``."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key())
    ca = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - _DAY)
        .not_valid_after(_NOW + 365 * _DAY)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
        .add_extension(aki, False)
        .add_extension(_ku(ca=True), critical=True)
        .sign(key, hashes.SHA256())
    )
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(name)
        .last_update(_NOW - _DAY)
        .next_update(_NOW + 30 * _DAY)
        .add_extension(aki, False)
        .add_extension(x509.CRLNumber(1), False)
        .sign(key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - _DAY)
        .not_valid_after(_NOW + 90 * _DAY)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False)
        .add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), False)
        .add_extension(aki, False)
        .add_extension(_ku(ca=False), critical=True)
        .sign(key, hashes.SHA256())
    )
    leaf_path, key_path = d / f"{cn}-leaf.pem", d / f"{cn}-leaf-key.pem"
    leaf_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return _Ca(
        pem=ca.public_bytes(serialization.Encoding.PEM),
        crl=crl.public_bytes(serialization.Encoding.PEM),
        leaf=str(leaf_path),
        leaf_key=str(key_path),
    )


@dataclass(frozen=True)
class _Pki:
    pinned: _Ca
    planted: _Ca
    pinned_ca_file: Path  # the CA the operator pinned
    bare_crl: Path  # the pinned CA's CRL and nothing else: the documented shape
    own_bundle: Path  # the pinned CA plus its own CRL: the shape the old wording described
    planted_bundle: Path  # a planted CA, the pinned CA's CRL, and the planted CA's CRL


@pytest.fixture(scope="module")
def pki(tmp_path_factory: pytest.TempPathFactory) -> _Pki:
    d = tmp_path_factory.mktemp("crl-pki")
    pinned, planted = _make_ca(d, "pinned-ca"), _make_ca(d, "planted-ca")
    files = {
        "pinned-ca.pem": pinned.pem,
        "bare-crl.pem": pinned.crl,
        "own-bundle.pem": pinned.pem + pinned.crl,
        # The pinned CA's CRL comes FIRST: the freshness check reads the first CRL block.
        "planted-bundle.pem": planted.pem + pinned.crl + planted.crl,
    }
    for name, data in files.items():
        (d / name).write_bytes(data)
    return _Pki(
        pinned,
        planted,
        d / "pinned-ca.pem",
        d / "bare-crl.pem",
        d / "own-bundle.pem",
        d / "planted-bundle.pem",
    )


def _pinned_ctx(pki: _Pki) -> ssl.SSLContext:
    """A verifying server context holding exactly the pinned CA, loaded the way the listeners load it."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cadata=pki.pinned.pem.decode("ascii"))
    return ctx


# --- the trust store's certificate count --------------------------------------------------------------


def test_a_planted_ca_in_the_crl_file_refuses(pki: _Pki) -> None:
    """Red before the fix: the load succeeded and x509 and x509_ca went from 1 to 2."""
    ctx = _pinned_ctx(pki)
    before = ctx.cert_store_stats()
    assert (before["x509"], before["x509_ca"], before["crl"]) == (1, 1, 0)
    with pytest.raises(
        ValueError, match=r"carries 1 certificate\(s\) not already in this hop.s trust store"
    ):
        harden_crl_check(ctx, str(pki.planted_bundle))


def test_a_non_ca_certificate_in_the_crl_file_refuses_too(pki: _Pki, tmp_path: Path) -> None:
    """Why the count is ``x509`` and not ``x509_ca``: a non-CA certificate is not counted as a CA
    but still joins the store."""
    crl_file = tmp_path / "crl-plus-leaf.pem"
    crl_file.write_bytes(pki.pinned.crl + Path(pki.planted.leaf).read_bytes())
    with pytest.raises(ValueError, match="1 certificate"):
        harden_crl_check(_pinned_ctx(pki), str(crl_file))


def test_a_bare_crl_and_the_pinned_cas_own_bundle_both_load(pki: _Pki) -> None:
    """Controls, so the refusals above are not a helper that rejects everything. OpenSSL adds no
    certificate the store already holds, so the pinned CA's own bundle leaves the count alone."""
    for crl_file in (pki.bare_crl, pki.own_bundle):
        ctx = _pinned_ctx(pki)
        harden_crl_check(ctx, str(crl_file))
        stats = ctx.cert_store_stats()
        assert (stats["x509"], stats["x509_ca"], stats["crl"]) == (1, 1, 1), crl_file.name
        assert _subjects(ctx) == ["pinned-ca"]
        assert ctx.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


def test_a_bundle_loaded_before_its_ca_refuses_rather_than_widens(pki: _Pki) -> None:
    """The ordering case, pinned as documented behaviour. Every call site loads the CA first. A
    caller that did not would see the pinned CA's own bundle refused: fail closed, not wider."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.verify_mode = ssl.CERT_REQUIRED
    with pytest.raises(ValueError, match="1 certificate"):
        harden_crl_check(ctx, str(pki.own_bundle))


# --- real listeners -------------------------------------------------------------------------------------


def _client(presenting: _Ca, pki: _Pki) -> ssl.SSLContext:
    """TLS 1.2, so the server's verdict on the client certificate lands inside the handshake."""
    ctx = ssl.create_default_context(cadata=pki.pinned.pem.decode("ascii"))
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(presenting.leaf, presenting.leaf_key)
    return ctx


@pytest.fixture
def clean_anchor_checks(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin the ACL and path verdicts to clean, so the result does not depend on this machine's ACLs.
    The pin still runs and still has to match."""
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: True)
    monkeypatch.setattr(ta, "anchor_path_verdict", lambda _p: PathVerdict(ok=True))


def _api_listener(pki: _Pki, crl_file: Path) -> ssl.SSLContext:
    api = ApiSettings(
        tls_cert_file=pki.pinned.leaf,
        tls_key_file=pki.pinned.leaf_key,
        tls_client_ca_file=str(pki.pinned_ca_file),
        tls_client_ca_pin=hashlib.sha256(pki.pinned.pem).hexdigest(),
        tls_client_crl_file=str(crl_file),
    )
    return build_api_ssl_context(api, enforcing=True)


def _inbound_settings(pki: _Pki, crl_file: Path) -> dict[str, Any]:
    return {
        "tls": True,
        "tls_cert_file": pki.pinned.leaf,
        "tls_key_file": pki.pinned.leaf_key,
        "tls_ca_file": str(pki.pinned_ca_file),
        "tls_ca_pin": hashlib.sha256(pki.pinned.pem).hexdigest(),
        "tls_crl_file": str(crl_file),
    }


def _mllp_listener(pki: _Pki, crl_file: Path) -> ssl.SSLContext:
    ctx = _mllp_ssl_context(_inbound_settings(pki, crl_file), server=True, name="adt-in")
    assert ctx is not None
    return ctx


def _dicom_listener(pki: _Pki, crl_file: Path) -> ssl.SSLContext:
    ctx = _server_ssl_context(_inbound_settings(pki, crl_file), name="pacs-in")
    assert ctx is not None
    return ctx


_LISTENERS = [
    pytest.param(_api_listener, id="api-tls_client_crl_file"),
    pytest.param(_mllp_listener, id="mllp-and-http-listener-tls_crl_file"),
    pytest.param(_dicom_listener, id="dicom-scp-tls_crl_file"),
]

_Build = Callable[[_Pki, Path], ssl.SSLContext]


@pytest.mark.usefixtures("clean_anchor_checks")
@pytest.mark.parametrize("build", _LISTENERS)
def test_a_listener_refuses_a_crl_bundle_carrying_a_ca_the_pin_excludes(
    build: _Build, pki: _Pki
) -> None:
    """Step 5 of the row, tested rather than read. Red before the fix: the listener built, and the
    planted client was ACCEPTED (see the control below for what that bundle admits)."""
    with pytest.raises(ValueError, match="not already in this hop"):
        build(pki, pki.planted_bundle)


@pytest.mark.usefixtures("clean_anchor_checks")
@pytest.mark.parametrize("build", _LISTENERS)
def test_a_listener_with_the_pinned_cas_own_bundle_admits_only_the_pinned_client(
    build: _Build, pki: _Pki
) -> None:
    ctx = build(pki, pki.own_bundle)
    assert _subjects(ctx) == ["pinned-ca"]
    _handshake(_client(pki.pinned, pki), ctx)
    with pytest.raises(ssl.SSLError):
        _handshake(_client(pki.planted, pki), ctx)


@pytest.mark.usefixtures("clean_anchor_checks")
@pytest.mark.parametrize("build", _LISTENERS)
def test_control_the_planted_bundle_loaded_by_path_admits_the_planted_client(
    build: _Build, pki: _Pki
) -> None:
    """The instrument's control. Load the planted bundle onto a built listener the way the helper
    used to, and the planted client gets in."""
    ctx = build(pki, pki.bare_crl)
    ctx.load_verify_locations(cafile=str(pki.planted_bundle))
    assert sorted(_subjects(ctx)) == ["pinned-ca", "planted-ca"]
    _handshake(_client(pki.planted, pki), ctx)


# --- the inbound refusal no longer steers an operator into the widening -----------------------------


def test_the_inbound_revocation_refusal_asks_for_a_crl_not_a_ca() -> None:
    """The refusal used to say "a PEM carrying the CA and its CRL", which is the widening in words."""
    source = Source(
        type=ConnectorType.MLLP,
        name="adt-in",
        settings={"tls": True, "tls_cert_file": "c.pem", "tls_ca_file": "ca.pem"},
    )
    with pytest.raises(WiringError) as err:
        check_inbound_revocation(source, "adt-in", posture=HopPosture(enforcing=True))
    text = str(err.value)
    assert "tls_crl_file (a PEM file holding the CA's CRL)" in text
    assert "the CA and its CRL" not in text
