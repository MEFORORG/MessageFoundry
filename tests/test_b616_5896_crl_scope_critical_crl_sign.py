# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #5896: a start refuses a CRL that OpenSSL would never judge a peer by.

Three shapes the start used to load clean, each of which then failed every handshake it judged
with a TLS error that does not name the CRL file:

* an Issuing Distribution Point that limits the CRL to attribute certificates or some reasons,
  or makes it indirect (RFC 5280 section 5.2.5), which the engine's OpenSSL, with no extended CRL
  support, never judges a certificate by. A CRL of CA certificates only is not refused;
* a critical extension OpenSSL does not handle, on the CRL or on an entry whose extensions
  ``cryptography`` reads (sections 5.2, 5.3); an entry that does not read gives no verdict;
* a signing CA whose key usage does not include cRLSign (section 6.3.3), refused on a
  whole-chain hop and logged at WARNING on a leaf hop.

The instrument for each is ``judge_crl_bytes`` or ``harden_crl_check``, and its control is
OpenSSL itself: the same bytes, loaded with the engine's checks left out, refuse a real handshake
that the full-scope, correctly profiled CRL passes. All material is synthetic and minted here.
"""

from __future__ import annotations

import datetime
import logging
import ssl
import time
import weakref
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from messagefoundry import pki as pki_module
from messagefoundry.config import loaded_crls
from messagefoundry.config.tls_policy import harden_crl_check, judge_crl_bytes
from messagefoundry.pki import NO_CRL_SIGN, judge_crl_signatures
from tests.test_crl_reload import _key_pem, _leaf
from tests.test_crl_signature_at_start import _ders, _hop, _raw_hop
from tests.test_trust_anchor_byte_binding import _handshake

_NOW = datetime.datetime.now(datetime.UTC)
_DAY = datetime.timedelta(days=1)
_PEM = serialization.Encoding.PEM
_NAME = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mefor-5896-ca")])
_PRIVATE = x509.ObjectIdentifier("1.3.6.1.4.1.55555.5896.1")
_SETTING = "[tls].crl_file"


@pytest.fixture(autouse=True)
def _fresh_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(loaded_crls, "_HELD", weakref.WeakKeyDictionary())
    monkeypatch.setattr(loaded_crls, "_UNCONFIRMED", {})


def _ku(*, crl_sign: bool) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=True,
        key_cert_sign=True,
        crl_sign=crl_sign,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        encipher_only=False,
        decipher_only=False,
    )


def _ca(key: ec.EllipticCurvePrivateKey, *, crl_sign: bool = True) -> x509.Certificate:
    return (
        x509.CertificateBuilder()
        .subject_name(_NAME)
        .issuer_name(_NAME)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - _DAY)
        .not_valid_after(_NOW + 365 * _DAY)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), False)
        .add_extension(_ku(crl_sign=crl_sign), critical=True)
        .sign(key, hashes.SHA256())
    )


def _idp(**limits: object) -> x509.IssuingDistributionPoint:
    fields: dict[str, object] = {
        "full_name": None,
        "relative_name": None,
        "only_contains_user_certs": False,
        "only_contains_ca_certs": False,
        "only_some_reasons": None,
        "indirect_crl": False,
        "only_contains_attribute_certs": False,
    }
    fields.update(limits)
    return x509.IssuingDistributionPoint(**fields)  # type: ignore[arg-type]


def _crl(
    key: ec.EllipticCurvePrivateKey,
    *,
    extensions: list[tuple[x509.ExtensionType, bool]] = (),  # type: ignore[assignment]
    entry: list[tuple[x509.ExtensionType, bool]] | None = None,
) -> bytes:
    """A current CRL from ``key`` that names that key, with ``extensions`` (value, critical) on
    the CRL and, with ``entry``, one revoked entry carrying those extensions. The entry's serial
    is no leaf's."""
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(_NAME)
        .last_update(_NOW - _DAY)
        .next_update(_NOW + 7 * _DAY)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), False)
        .add_extension(x509.CRLNumber(1), False)
    )
    for value, critical in extensions:
        builder = builder.add_extension(value, critical)
    if entry is not None:
        revoked = x509.RevokedCertificateBuilder().serial_number(1).revocation_date(_NOW - _DAY)
        for value, critical in entry:
            revoked = revoked.add_extension(value, critical)
        builder = builder.add_revoked_certificate(revoked.build())
    return builder.sign(key, hashes.SHA256()).public_bytes(_PEM)


class _Pki:
    def __init__(self, tmp_path: Path, *, crl_sign: bool = True) -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.ca_file = tmp_path / "ca.pem"
        self.ca_file.write_bytes(_ca(self.key, crl_sign=crl_sign).public_bytes(_PEM))
        leaf, leaf_key = _leaf(_NAME, self.key)
        (tmp_path / "leaf.pem").write_bytes(leaf.public_bytes(_PEM))
        (tmp_path / "leaf-key.pem").write_bytes(_key_pem(leaf_key))
        self.tmp = tmp_path

    def server(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.tmp / "leaf.pem", self.tmp / "leaf-key.pem")
        return ctx

    def crl_file(self, pem: bytes, name: str = "crl.pem") -> Path:
        path = self.tmp / name
        path.write_bytes(pem)
        return path

    def raw_hop(self, crl: Path) -> ssl.SSLContext:
        """OpenSSL with the engine's CRL checks left out."""
        return _raw_hop(self.ca_file, crl)

    def hop(self, crl: Path) -> ssl.SSLContext:
        """An outbound hop built the way the engine builds one, CRL checks included."""
        return _hop(self.ca_file, crl)


def _judge(pem: bytes) -> None:
    judge_crl_bytes(pem, label=_SETTING, now=time.time(), refuse_unread_extensions=True)


_OUT_OF_SCOPE = {
    "attribute-only": (
        _idp(only_contains_attribute_certs=True),
        "covers attribute certificates only",
    ),
    "some-reasons": (
        _idp(only_some_reasons=frozenset({x509.ReasonFlags.key_compromise})),
        "covers only some revocation reasons",
    ),
    "indirect": (_idp(indirect_crl=True), "is an indirect CRL"),
}


@pytest.mark.parametrize("shape", sorted(_OUT_OF_SCOPE))
def test_a_crl_scoped_away_from_leaves_refuses_at_start(tmp_path: Path, shape: str) -> None:
    pki = _Pki(tmp_path)
    idp, words = _OUT_OF_SCOPE[shape]
    pem = _crl(pki.key, extensions=[(idp, True)])

    with pytest.raises(ValueError, match=words) as refused:
        _judge(pem)
    assert str(refused.value).startswith(_SETTING)
    with pytest.raises(ValueError, match=words):
        pki.hop(pki.crl_file(pem))

    # Control: OpenSSL loads the same bytes, and then refuses the handshake.
    with pytest.raises(ssl.SSLError):
        _handshake(pki.raw_hop(pki.crl_file(pem)), pki.server())


def test_a_full_scope_crl_and_a_user_only_crl_still_load(tmp_path: Path) -> None:
    """The positive controls: the documented shape, a bare full-scope base CRL, and an IDP that
    limits a CRL to user certificates, which covers the leaf a leaf check judges."""
    pki = _Pki(tmp_path)
    for name, pem in (
        ("bare.pem", _crl(pki.key)),
        ("user.pem", _crl(pki.key, extensions=[(_idp(only_contains_user_certs=True), True)])),
    ):
        _judge(pem)
        crl = pki.crl_file(pem, name)
        _handshake(pki.raw_hop(crl), pki.server())  # OpenSSL passes it
        _handshake(pki.hop(crl), pki.server())  # and so does the engine's hop


def test_a_ca_only_crl_is_not_refused(tmp_path: Path) -> None:
    """An ARL, a CRL of CA certificates only, is in scope for the CAs of a chain: a root's ARL
    beside its intermediate's full CRL passes a whole-chain check. The engine has no chain to
    judge it against, so it loads (code review round 1 of this row)."""
    pki = _Pki(tmp_path)
    _judge(_crl(pki.key, extensions=[(_idp(only_contains_ca_certs=True), True)]))


def test_an_entry_that_does_not_read_gives_no_verdict() -> None:
    """An entry whose extensions ``cryptography`` refuses, such as a duplicate extension or an
    unknown reason code, loaded before #5896, so the entry check gives no verdict on it rather
    than refusing the start. Stood in by an entry whose extensions raise each such error."""

    class _Entry:
        def __init__(self, error: Exception) -> None:
            self._error = error

        @property
        def extensions(self) -> x509.Extensions:
            raise self._error

    key = ec.generate_private_key(ec.SECP256R1())
    crl = x509.load_pem_x509_crl(_crl(key))
    read = pki_module._crl_extensions(crl)
    for n, error in enumerate(
        (
            x509.DuplicateExtension("twice", _PRIVATE),
            ValueError("Unsupported reason code: 7"),
            x509.UnsupportedGeneralNameType("x400Address"),
        )
    ):

        class _Crl:
            def __iter__(self, error: Exception = error) -> object:
                return iter([_Entry(error)])

        stand_in: x509.CertificateRevocationList = _Crl()  # type: ignore[assignment]
        assert pki_module._unhandled_critical(stand_in, read, b"stand-in %d" % n) is None


def test_an_unhandled_critical_crl_extension_refuses_at_start(tmp_path: Path) -> None:
    pki = _Pki(tmp_path)
    private = x509.UnrecognizedExtension(_PRIVATE, b"\x05\x00")
    pem = _crl(pki.key, extensions=[(private, True)])

    with pytest.raises(ValueError, match=f"critical extension {_PRIVATE.dotted_string}"):
        _judge(pem)
    with pytest.raises(ssl.SSLError, match="critical"):
        _handshake(pki.raw_hop(pki.crl_file(pem)), pki.server())

    # Control: the same extension, not critical, loads and passes.
    calm = _crl(pki.key, extensions=[(private, False)])
    _judge(calm)
    _handshake(pki.hop(pki.crl_file(calm, "calm.pem")), pki.server())


def test_a_critical_authority_key_identifier_is_handled(tmp_path: Path) -> None:
    """OpenSSL handles a critical AKID, so it is not refused. The CRL's own AKID is replaced by a
    critical one."""
    pki = _Pki(tmp_path)
    pem = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(_NAME)
        .last_update(_NOW - _DAY)
        .next_update(_NOW + 7 * _DAY)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(pki.key.public_key()), True
        )
        .sign(pki.key, hashes.SHA256())
        .public_bytes(_PEM)
    )
    _judge(pem)
    _handshake(pki.hop(pki.crl_file(pem)), pki.server())


def test_an_unhandled_critical_entry_extension_refuses_at_start(tmp_path: Path) -> None:
    pki = _Pki(tmp_path)
    private = x509.UnrecognizedExtension(_PRIVATE, b"\x05\x00")
    pem = _crl(pki.key, entry=[(private, True)])

    with pytest.raises(ValueError, match="on a revoked entry"):
        _judge(pem)
    with pytest.raises(ssl.SSLError, match="critical"):
        _handshake(pki.raw_hop(pki.crl_file(pem)), pki.server())

    # Control: an entry whose extension is not critical loads and passes.
    calm = _crl(pki.key, entry=[(private, False)])
    _judge(calm)
    _handshake(pki.hop(pki.crl_file(calm, "calm.pem")), pki.server())


def test_a_crl_from_a_ca_without_crl_sign_refuses_a_whole_chain_start(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    pki = _Pki(tmp_path, crl_sign=False)
    pem = _crl(pki.key)
    crl = pki.crl_file(pem)

    _judge(pem)  # no CA list there: the signature check is where it is caught
    [signature] = judge_crl_signatures(pem, _ders(pki.ca_file))
    assert signature.state == "verified" and signature.without_crl_sign
    whole_chain = ssl.create_default_context(cafile=str(pki.ca_file))
    with pytest.raises(ValueError, match="does not include cRLSign") as refused:
        harden_crl_check(whole_chain, str(crl), setting=_SETTING, chain=True)
    assert NO_CRL_SIGN in str(refused.value)
    assert str(refused.value).startswith(_SETTING)

    # A leaf check warns and loads: a root that signs only intermediates is never judged by its
    # own CRL there, so the engine cannot tell this file fails.
    with caplog.at_level(logging.WARNING, logger="messagefoundry"):
        pki.hop(crl)
    assert any(NO_CRL_SIGN in r.getMessage() for r in caplog.records)

    # Control: OpenSSL loads it, and the handshake fails on the key usage.
    with pytest.raises(ssl.SSLError, match="(?i)key ?usage"):
        _handshake(pki.raw_hop(crl), pki.server())


def test_the_leaf_hop_crl_sign_warning_is_not_repeated_per_build(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The Postgres store builds a context per connection and an AD bind one per bind, so the
    leaf-hop warning is logged once for the file's current bytes, not once per build."""
    pki = _Pki(tmp_path, crl_sign=False)
    crl = pki.crl_file(_crl(pki.key))

    def warned() -> int:
        return sum(NO_CRL_SIGN in r.getMessage() for r in caplog.records)

    with caplog.at_level(logging.WARNING, logger="messagefoundry"):
        for _ in range(3):
            pki.hop(crl)
        assert warned() == 1
        assert any("the file is loaded" in r.getMessage() for r in caplog.records)
        # Control: a new version of the file logs again.
        # an ECDSA signature differs per signing, so these bytes are new
        crl.write_bytes(_crl(pki.key))
        pki.hop(crl)
        assert warned() == 2


def test_a_crl_from_a_ca_with_crl_sign_loads(tmp_path: Path) -> None:
    pki = _Pki(tmp_path, crl_sign=True)
    pem = _crl(pki.key)
    [signature] = judge_crl_signatures(pem, _ders(pki.ca_file))
    assert signature.state == "verified" and not signature.without_crl_sign
    _handshake(pki.hop(pki.crl_file(pem)), pki.server())


def test_a_ca_without_key_usage_is_not_refused(tmp_path: Path) -> None:
    """OpenSSL refuses only a CA that carries a key usage lacking cRLSign, so a CA with no key
    usage at all is not flagged."""
    key = ec.generate_private_key(ec.SECP256R1())
    ca = (
        x509.CertificateBuilder()
        .subject_name(_NAME)
        .issuer_name(_NAME)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - _DAY)
        .not_valid_after(_NOW + 365 * _DAY)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
        .sign(key, hashes.SHA256())
    )
    [signature] = judge_crl_signatures(_crl(key), [ca.public_bytes(serialization.Encoding.DER)])
    assert signature.state == "verified" and not signature.without_crl_sign
