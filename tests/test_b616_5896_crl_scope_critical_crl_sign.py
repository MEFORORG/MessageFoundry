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
from messagefoundry.config.tls_policy import (
    _CRL_JUDGMENT_FAILED,
    _CRL_SIGN_MISSING_ON_LEAF,
    _CRL_UNCONFIRMED,
    harden_crl_check,
    judge_crl_bytes,
)
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
#: What every CRL-signature line says, once a build has loaded the file.
_LOADED = "This TLS context loaded the file and checks revocation with it"
_TLS_LOGGER = "messagefoundry.config.tls_policy"


@pytest.fixture(autouse=True)
def _fresh_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(loaded_crls, "_HELD", weakref.WeakKeyDictionary())
    monkeypatch.setattr(loaded_crls, "_UNCONFIRMED", {})
    monkeypatch.setattr(pki_module, "_ENTRY_VERDICTS", {})


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
        assert any(
            NO_CRL_SIGN in r.getMessage() and _LOADED.lower() in r.getMessage().lower()
            for r in caplog.records
        )
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


# --- the lines are logged only once the build's outcome is known --------------------------------

_OTHER = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mefor-5896-stranger")])


def _opening(template: str) -> str:
    """The fixed words a line template starts with after its label, to find the line by."""
    return template.removeprefix("%s: ").split("%", 1)[0]


def _stranger_crl() -> bytes:
    """A current CRL from an issuer no CA in these tests carries, so its signature is unlisted."""
    key = ec.generate_private_key(ec.SECP256R1())
    return (
        x509.CertificateRevocationListBuilder()
        .issuer_name(_OTHER)
        .last_update(_NOW - _DAY)
        .next_update(_NOW + 7 * _DAY)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), False)
        .sign(key, hashes.SHA256())
        .public_bytes(_PEM)
    )


def _lines(caplog: pytest.LogCaptureFixture, template: str) -> list[logging.LogRecord]:
    return [r for r in caplog.records if _opening(template) in r.getMessage()]


def test_a_refused_whole_chain_build_logs_no_line_about_the_file(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A file holding a CRL from a CA without cRLSign and an unlisted CRL: a whole-chain build
    refuses it on the first and logs neither the unconfirmed WARNING nor the cRLSign one."""
    pki = _Pki(tmp_path, crl_sign=False)
    crl = pki.crl_file(_crl(pki.key) + _stranger_crl())
    whole_chain = ssl.create_default_context(cafile=str(pki.ca_file))
    with (
        caplog.at_level(logging.WARNING, logger=_TLS_LOGGER),
        pytest.raises(ValueError, match="does not include cRLSign"),
    ):
        harden_crl_check(whole_chain, str(crl), setting=_SETTING, chain=True)
    assert not [r for r in caplog.records if r.name == _TLS_LOGGER]

    # Control: the leaf build of the same file loads it and logs both lines, each saying so.
    with caplog.at_level(logging.WARNING, logger=_TLS_LOGGER):
        pki.hop(crl)
    for template in (_CRL_UNCONFIRMED, _CRL_SIGN_MISSING_ON_LEAF):
        (line,) = _lines(caplog, template)
        assert _LOADED.lower() in line.getMessage().lower()


def test_a_whole_chain_crl_sign_refusal_after_a_failure_logs_no_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The judgment fails on block 2, after block 1 reads verified from a CA without cRLSign. The
    whole-chain build refuses on block 1 and logs no ERROR, the failure riding as the refusal's
    cause. The leaf build of the same file is the control: it loads, and logs the ERROR once and
    the cRLSign WARNING once, however many contexts it builds."""
    pki = _Pki(tmp_path, crl_sign=False)
    crl = pki.crl_file(_crl(pki.key) + _crl(pki.key))
    real = pki_module._signature_state
    calls = 0

    def second_fails(
        crl: x509.CertificateRevocationList, cas: list[pki_module._ListedCa]
    ) -> pki_module.CrlSignatureState:
        nonlocal calls
        calls += 1
        if calls % 2 == 0:
            raise RuntimeError("a defect in the check")
        return real(crl, cas)

    monkeypatch.setattr(pki_module, "_signature_state", second_fails)
    whole_chain = ssl.create_default_context(cafile=str(pki.ca_file))
    with (
        caplog.at_level(logging.WARNING, logger=_TLS_LOGGER),
        pytest.raises(ValueError, match="does not include cRLSign") as refused,
    ):
        harden_crl_check(whole_chain, str(crl), setting=_SETTING, chain=True)
    assert isinstance(refused.value.__cause__, RuntimeError)
    assert "after the first 1 (RuntimeError)" in str(refused.value)
    assert "remove it from this hop's CA setting" in str(refused.value)
    assert not [r for r in caplog.records if r.name == _TLS_LOGGER]

    with caplog.at_level(logging.WARNING, logger=_TLS_LOGGER):
        for _ in range(2):
            pki.hop(crl)
    (error,) = _lines(caplog, _CRL_JUDGMENT_FAILED)
    assert error.levelno == logging.ERROR and error.exc_info is not None
    assert "after judging 1 of them" in error.getMessage()
    assert _LOADED in error.getMessage()
    assert len(_lines(caplog, _CRL_SIGN_MISSING_ON_LEAF)) == 1


def _scan(ca_file: Path) -> tuple[str, str] | None:
    """The expiry scan's verdict on the CA file ``ca_file``, which no CRL setting names."""
    from messagefoundry.pipeline.cert_expiry import _ca_file_crl_refusal

    return _ca_file_crl_refusal(
        ca_file.read_bytes(), time.time(), None, ca_file_only=True, on_unchecked=lambda: None
    )


@pytest.mark.parametrize("shape", ["some-reasons", "indirect"])
def test_the_ca_file_scan_passes_an_out_of_scope_crl_beside_a_usable_one(
    tmp_path: Path, shape: str
) -> None:
    """Finding 2 of engine PR 3099, the Lander's hold. A CA file holds its CA, a usable CRL and a
    reason-scoped or indirect CRL from the same issuer. The scan must not call it a
    file to replace before restarting, which is what it said once ``judge_every_crl`` refused the
    out-of-scope CRL for every caller. The same bytes in a CRL setting still refuse that start."""
    pki = _Pki(tmp_path)
    idp, words = _OUT_OF_SCOPE[shape]
    out_of_scope = _crl(pki.key, extensions=[(idp, True)])
    bundle = pki.crl_file(pki.ca_file.read_bytes() + _crl(pki.key) + out_of_scope, "bundle.pem")

    # Start-up accepts the CA file: a hop built on it, with a usable CRL setting, starts, and its
    # handshake passes with the CA file's CRLs loaded beside the setting's.
    hop = _hop(bundle, pki.crl_file(_crl(pki.key)))
    _handshake(hop, pki.server())

    assert _scan(bundle) is None

    # Control: as a CRL setting, the out-of-scope CRL still refuses a start.
    with pytest.raises(ValueError, match=words):
        pki.hop(pki.crl_file(out_of_scope, "scoped.pem"))


def test_the_ca_file_scan_still_alerts_on_a_ca_file_start_up_refuses(tmp_path: Path) -> None:
    """The control for the test above: a CA file whose CRL block OpenSSL cannot load refuses a
    start, and the scan still calls it one to fix before restarting."""
    pki = _Pki(tmp_path)
    good = _crl(pki.key)
    lines = good.splitlines(keepends=True)
    broken = b"".join([lines[0], b"bm90IGEgQ1JM\n", lines[-1]])
    bundle = pki.crl_file(pki.ca_file.read_bytes() + broken, "bundle.pem")

    with pytest.raises((ssl.SSLError, ValueError)):
        _hop(bundle, pki.crl_file(good))

    verdict = _scan(bundle)
    assert verdict is not None
    assert verdict[1].startswith(("Replace the CRL in the CA file", "Fix the CA file"))


@pytest.mark.parametrize("shape", ["some-reasons", "indirect"])
def test_the_ca_file_scan_alerts_where_a_crl_setting_names_the_ca_file_too(
    tmp_path: Path, shape: str
) -> None:
    """Finding 1 of the review of the first repair of engine PR 3099. Where a CRL setting also
    names the CA file, as ``[store].ssl_crl_file`` can, a start judges that file as a CRL setting
    and refuses the out-of-scope CRL. So the scan, asked with ``ca_file_only=False``, must still
    say to replace it before restarting."""
    from messagefoundry.pipeline.cert_expiry import _ca_file_crl_refusal

    pki = _Pki(tmp_path)
    idp, words = _OUT_OF_SCOPE[shape]
    bundle = pki.crl_file(
        pki.ca_file.read_bytes() + _crl(pki.key) + _crl(pki.key, extensions=[(idp, True)]),
        "bundle.pem",
    )

    # The start that names the bundle as a CRL setting refuses it.
    with pytest.raises(ValueError, match=words):
        _hop(bundle, bundle)

    verdict = _ca_file_crl_refusal(
        bundle.read_bytes(), time.time(), None, ca_file_only=False, on_unchecked=lambda: None
    )
    assert verdict is not None
    assert verdict[1].startswith(
        "Replace the CRL in the CA file with one the engine can judge before restarting"
    )
