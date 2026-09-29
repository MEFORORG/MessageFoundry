# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""XML-DSig ``verify()`` refuses a signature made with an RSA key under 2048 bits (BACKLOG #1166).

The measurement that found the defect, and the ruling that sets the number, are recorded once, on
``_MIN_RSA_BITS`` and ``_signing_key_refusal`` in ``messagefoundry/parsing/xml/signature.py``.

THE RSA-1024 AND RSA-2047 KEYS HERE ARE NEGATIVE CONTROLS. They exist only to be refused. None is offered to a
peer, written outside ``tmp_path``, or used for anything but the refusal this file asserts. A
static "weak cryptographic key" alert against them is right about the code and wrong about the risk;
deleting them would delete the only proof the floor fires.

All material is minted at run time. No certificate or key is embedded in this file.
"""

from __future__ import annotations

import datetime as dt
from functools import cache
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("signxml")

from cryptography import x509  # noqa: E402 - after the [xml]-extra skip on purpose
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

# The reason constants are read off the module at call time, not imported, so this file COLLECTS
# against code that predates them and its assertions -- not an ImportError -- report the defect.
from messagefoundry.parsing.xml import signature as sigmod  # noqa: E402
from messagefoundry.parsing.xml.signature import verify  # noqa: E402

_BODY = b"<Order><Item>SYNTHETIC-WIDGET</Item><Qty>1</Qty></Order>"
_SignerKey = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey


@cache
def _rsa(bits: int) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


@cache
def _ca_rsa(bits: int) -> rsa.RSAPrivateKey:
    """A CA key distinct from every leaf key, so no chain here is a same-key degenerate one."""
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


@cache
def _p256() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _cert(
    subject_key: _SignerKey, issuer_key: _SignerKey, subject: str, issuer: str, *, ca: bool
) -> x509.Certificate:
    now = dt.datetime.now(dt.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)]))
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=not ca,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=ca,
                crl_sign=ca,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            critical=False,
        )
    )
    if not ca:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
        )
    return builder.sign(issuer_key, hashes.SHA256())


def _pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _sign(key: _SignerKey, cert: x509.Certificate) -> bytes:
    from lxml import etree
    from signxml.signer import XMLSigner

    alg = "ecdsa-sha256" if isinstance(key, ec.EllipticCurvePrivateKey) else "rsa-sha256"
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    # A test-only signer over a synthetic body parsed from a literal, never untrusted input.
    root = etree.fromstring(_BODY)  # noqa: S320
    signed = XMLSigner(signature_algorithm=alg).sign(root, key=key_pem, cert=[_pem(cert).decode()])
    return bytes(etree.tostring(signed))


def _signed_and_anchor(
    key: _SignerKey, anchor: str, tmp_path: Path, *, ca_bits: int = 2048
) -> tuple[bytes, dict[str, Any]]:
    """A document signed by ``key`` and the ``verify`` keyword that trusts it on ``anchor``'s path."""
    if anchor == "x509_cert":
        cert = _cert(key, key, "partner-signer", "partner-signer", ca=False)
        return _sign(key, cert), {"x509_cert": _pem(cert)}
    # The CA is held at 2048 on purpose: signxml already refuses a weak CA, so a weak CA here would
    # make the 1024 arm fail for signxml's reason rather than the floor's.
    ca_key = _ca_rsa(ca_bits)
    ca = _cert(ca_key, ca_key, "partner-ca", "partner-ca", ca=True)
    leaf = _cert(key, ca_key, "partner-signer", "partner-ca", ca=False)
    ca_file = tmp_path / "partner-ca.pem"
    ca_file.write_bytes(_pem(ca))
    return _sign(key, leaf), {"ca_pem_file": str(ca_file)}


_ANCHORS = ["x509_cert", "ca_pem_file"]


@pytest.mark.parametrize("anchor", _ANCHORS)
@pytest.mark.parametrize("bits", [2048, 3072])
def test_a_signature_at_or_above_the_floor_verifies(bits: int, anchor: str, tmp_path: Path) -> None:
    """POSITIVE CONTROL: without it, a floor that refused every RSA key would pass the test below."""
    doc, kwargs = _signed_and_anchor(_rsa(bits), anchor, tmp_path)
    result = verify(doc, **kwargs)
    assert result.verified, f"RSA-{bits} on the {anchor} path was refused: {result.reason}"
    assert result.reason is None


@pytest.mark.parametrize("anchor", _ANCHORS)
@pytest.mark.parametrize("bits", [1024, 2047])
def test_an_rsa_signature_under_the_floor_is_refused_as_data(
    bits: int, anchor: str, tmp_path: Path
) -> None:
    """The defect is the 1024 arm. The 2047 arm pins the boundary one bit below the floor."""
    doc, kwargs = _signed_and_anchor(_rsa(bits), anchor, tmp_path)
    result = verify(doc, **kwargs)
    assert result.verified is False, f"RSA-{bits} verified on the {anchor} path"
    assert result.reason == sigmod.WEAK_SIGNING_KEY


@pytest.mark.parametrize("anchor", _ANCHORS)
@pytest.mark.parametrize("bits", [1024, 2048])
def test_a_tampered_body_still_fails_on_its_digest(bits: int, anchor: str, tmp_path: Path) -> None:
    """TAMPER CONTROL: the floor must not mask, or stand in for, the integrity check.

    Both key sizes fail on the digest, so the weak-key reason never hides a tampered body.
    """
    doc, kwargs = _signed_and_anchor(_rsa(bits), anchor, tmp_path)
    tampered = doc.replace(b"<Qty>1</Qty>", b"<Qty>9</Qty>")
    assert tampered != doc
    result = verify(tampered, **kwargs)
    assert result.verified is False
    assert result.reason == "InvalidDigest"


@pytest.mark.parametrize("anchor", _ANCHORS)
def test_an_ec_p256_signature_is_untouched_by_the_rsa_floor(anchor: str, tmp_path: Path) -> None:
    """The floor is RSA-only. A P-256 key (about 128 bits) must still verify on both paths."""
    doc, kwargs = _signed_and_anchor(_p256(), anchor, tmp_path)
    result = verify(doc, **kwargs)
    assert result.verified, f"P-256 on the {anchor} path was refused: {result.reason}"
    assert result.reason is None


def test_a_weak_ca_key_is_refused_by_the_chain_check(tmp_path: Path) -> None:
    """The floor reads only the LEAF key. It relies on signxml's chain verifier to refuse a weak CA
    key on the ``ca_pem_file`` path; this pins that reliance so a looser library fails here."""
    doc, kwargs = _signed_and_anchor(_rsa(2048), "ca_pem_file", tmp_path, ca_bits=1024)
    result = verify(doc, **kwargs)
    assert result.verified is False
    assert result.reason == "InvalidCertificate"


def test_an_unreadable_signing_key_is_refused_not_passed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail closed: a floor that cannot read the key must not return ``verified=True``."""
    from signxml.verifier import XMLVerifier

    class _Result:
        signature_key = b"not a public key"

    monkeypatch.setattr(XMLVerifier, "verify", lambda self, *a, **k: _Result())
    result = verify(b"<root/>", x509_cert=b"unit-test-anchor-sentinel")
    assert result.verified is False
    assert result.reason == sigmod.UNREADABLE_SIGNING_KEY


@pytest.mark.parametrize("shape", ["empty", "weak-second"])
def test_a_list_result_is_checked_whole(shape: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """signxml returns a LIST when more than one reference is expected. An empty list names no key
    and must not pass; a list is refused if ANY entry's key is under the floor."""
    from signxml.verifier import XMLVerifier

    def _result(key: rsa.RSAPrivateKey) -> Any:
        class _R:
            signature_key = key.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )

        return _R()

    listed: list[Any] = [] if shape == "empty" else [_result(_rsa(2048)), _result(_rsa(1024))]
    expected = sigmod.UNREADABLE_SIGNING_KEY if shape == "empty" else sigmod.WEAK_SIGNING_KEY
    monkeypatch.setattr(XMLVerifier, "verify", lambda self, *a, **k: listed)
    result = verify(b"<root/>", x509_cert=b"unit-test-anchor-sentinel")
    assert result.verified is False
    assert result.reason == expected


def test_the_floor_is_2048_and_the_reasons_carry_no_content() -> None:
    """The number is owner ruling R6's, recorded on ``_MIN_RSA_BITS``. The reasons are fixed
    category names, so no key material or document text can reach a log."""
    assert sigmod._MIN_RSA_BITS == 2048
    for reason in (sigmod.WEAK_SIGNING_KEY, sigmod.UNREADABLE_SIGNING_KEY):
        assert reason.isalpha(), reason
