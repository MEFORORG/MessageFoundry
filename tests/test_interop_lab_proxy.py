# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ASVS 11.3.1 interop LAB PROXY. THESE RESULTS ARE NOT PARTNER DATA (BACKLOG #2377).

Each test here hands what the engine signs to a verifier the engine did not write, and checks it
verifies. That shows a stock implementation accepts the output. It does NOT show that any real
Direct/HISP peer or REST/SOAP partner accepts it: no partner system, partner configuration or
partner certificate is involved, and every key, certificate and message is synthetic, minted in the
test. Read a pass as "a conformant third-party verifier accepts this in a lab", and never as partner
interoperability evidence. The owner ruling that defines this measurement lives in the
maintainer-internal record, not in this repository.

Two halves:

* **DIRECT (S/MIME).** The ``openssl`` command-line tool decrypts the whole serialized S/MIME
  message the connector handed to SMTP, then runs ``openssl cms -verify`` on the SignedData inside
  it. It covers the RSASSA-PKCS1-v1_5 signer (the default), the RSASSA-PSS signer
  (``signature_padding = "pss"``) and an ECDSA signer. No engine code reads the received bytes.
  Skipped, with the reason, when no OpenSSL 3.0 or later with a ``cms`` command is on PATH.
* **JWS (transports/signing.py).** PyJWT verifies the PS256 and RS256 output of both signers: the
  detached JWS a REST/SOAP outbound carries, and the compact JWT a SMART client assertion carries.
  PyJWT is a separate JOSE implementation. It builds the signing input and picks the PSS parameters
  itself. It does share the ``cryptography`` package for the RSA arithmetic, so the independence is
  at the JOSE layer, not at the primitive.

Each half has negative controls, so a verifier that accepted everything could not pass. DIRECT has
two: a changed content byte, and an untampered message checked against a CA that did not issue it.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING, Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from messagefoundry.config.models import OutboundSigning, SignatureAlgorithm
from messagefoundry.transports.direct import DirectDestination
from messagefoundry.transports.signing import (
    _MIN_RSA_BITS,
    CompactJwtSigner,
    MessageSigner,
    b64u_encode,
)
from tests.test_direct_transport import (
    _SYNTHETIC_HL7,
    _dest,
    _ec_signer,
    _FakeSMTP,
    _install_fake,
    _mint_ca,
    _write_key,
    _write_pem,
    pki,  # noqa: F401  -- a pytest fixture, used by name below
)

if TYPE_CHECKING:
    from jwt.types import Options


def _openssl_with_cms() -> tuple[str | None, str]:
    """The openssl on PATH and, when it cannot run these tests, the reason.

    It must have a ``cms`` command that takes ``-no-CAstore``, which means OpenSSL 3.0 or later.
    Keyed on the help text rather than on the exit code, so an openssl whose ``-help`` exits
    non-zero still runs these tests instead of skipping them."""
    found = shutil.which("openssl")
    if found is None:
        return None, "no openssl on PATH"
    try:
        probe = subprocess.run(  # noqa: S603 -- fixed argv, no shell
            [found, "cms", "-help"], capture_output=True, check=False, timeout=60
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, f"the openssl at {found} did not run ({type(exc).__name__})"
    if b"no-CAstore" not in probe.stdout + probe.stderr:
        return None, f"the openssl at {found} has no cms command taking -no-CAstore (needs 3.0+)"
    return found, ""


_OPENSSL, _WHY_NOT = _openssl_with_cms()
_NO_OPENSSL = (
    f"{_WHY_NOT}, so the DIRECT lab proxy cannot run here; it is a lab proxy (not partner data) "
    "and needs a stock third-party CMS verifier"
)

# Synthetic, never a real payload (CLAUDE.md section 9).
_JWS_BODY = b'{"resourceType":"Bundle","id":"lab-proxy-synthetic","type":"message"}'


# --- DIRECT: openssl cms -verify on the SignedData ------------------------------------------------


def _openssl(*args: str) -> subprocess.CompletedProcess[bytes]:
    assert _OPENSSL is not None
    return subprocess.run(  # noqa: S603 -- fixed argv, no shell, synthetic test files only
        [_OPENSSL, *args], capture_output=True, check=False, timeout=60
    )


async def _signed_data(
    monkeypatch: pytest.MonkeyPatch, material: dict[str, Any], tmp_path: Path, signer: str
) -> Path:
    """Send one synthetic message through the connector, have openssl decrypt it, and return the
    path of the SignedData DER openssl recovered.

    openssl reads the whole S/MIME message the connector handed to SMTP (``-inform SMIME``), so it
    parses the MIME wrapper and the base64 itself, then decrypts with the recipient's key."""
    overrides: dict[str, Any] = {}
    if signer == "pss":
        overrides["signature_padding"] = "pss"
    elif signer == "ecdsa":
        overrides.update(_ec_signer(material, tmp_path))
    _install_fake(monkeypatch)
    await DirectDestination(_dest(material, **overrides)).send(_SYNTHETIC_HL7)
    [smtp] = _FakeSMTP.instances
    [msg] = smtp.sent

    wire = tmp_path / "wire.eml"
    wire.write_bytes(msg.as_bytes())
    recip_key = tmp_path / "recip.key"
    _write_key(recip_key, material["recip_key"])
    signed = tmp_path / "signed.p7s.der"
    done = _openssl(
        "cms", "-decrypt", "-binary", "-inform", "SMIME", "-in", str(wire),
        "-recip", material["recipient_cert"], "-inkey", str(recip_key), "-out", str(signed),
    )  # fmt: skip
    assert done.returncode == 0, done.stderr.decode(errors="replace")
    return signed


def _openssl_verify(signed: Path, ca: Path, out: Path) -> subprocess.CompletedProcess[bytes]:
    # -no-CApath and -no-CAstore keep trust to the one CA file, so a pass cannot come from the
    # host's own store, and the unrelated-CA control below cannot pass by accident.
    return _openssl(
        "cms", "-verify", "-binary", "-inform", "DER", "-in", str(signed),
        "-CAfile", str(ca), "-no-CApath", "-no-CAstore", "-out", str(out),
    )  # fmt: skip


def _signer_info_algorithm(signed: Path) -> str:
    """The SignerInfo signatureAlgorithm, as ``openssl cms -cmsout -print`` names it."""
    printed = _openssl("cms", "-cmsout", "-print", "-inform", "DER", "-in", str(signed))
    assert printed.returncode == 0, printed.stderr.decode(errors="replace")
    found = re.search(
        r"signerInfos:.*?signatureAlgorithm:\s*algorithm:\s*(\S+)",
        printed.stdout.decode(errors="replace"),
        re.DOTALL,
    )
    assert found is not None, "openssl printed no SignerInfo signatureAlgorithm"
    return found.group(1)


# Each signer arm, and the SignerInfo signatureAlgorithm openssl must report for it. Checking it
# stops a padding setting that silently did nothing from passing as a PSS result.
_SIGNER_ALGORITHM = {
    "pkcs1v15": "rsaEncryption",
    "pss": "rsassaPss",
    "ecdsa": "ecdsa-with-SHA256",
}


@pytest.mark.skipif(_OPENSSL is None, reason=_NO_OPENSSL)
@pytest.mark.parametrize("signer", sorted(_SIGNER_ALGORITHM))
async def test_lab_proxy_not_partner_data_openssl_cms_verifies_direct_signeddata(
    monkeypatch: pytest.MonkeyPatch,
    pki: dict[str, Any],  # noqa: F811
    tmp_path: Path,
    signer: str,
) -> None:
    """LAB PROXY, NOT PARTNER DATA: stock ``openssl cms -verify`` accepts DIRECT's SignedData.

    openssl does both receiving steps itself: it decrypts the S/MIME message with the recipient
    key, then verifies the SignerInfo against the test CA, with its default S/MIME signing purpose
    check. The content it recovers must be the synthetic body, byte for byte."""
    signed = await _signed_data(monkeypatch, pki, tmp_path, signer)
    assert _signer_info_algorithm(signed) == _SIGNER_ALGORITHM[signer]

    content = tmp_path / "content.bin"
    done = _openssl_verify(signed, Path(pki["trust_anchor"]), content)
    assert done.returncode == 0, done.stderr.decode(errors="replace")
    assert b"Verification successful" in done.stderr
    assert content.read_bytes() == _SYNTHETIC_HL7.encode("utf-8")


@pytest.mark.skipif(_OPENSSL is None, reason=_NO_OPENSSL)
async def test_lab_proxy_not_partner_data_openssl_cms_rejects_tampered_direct_content(
    monkeypatch: pytest.MonkeyPatch,
    pki: dict[str, Any],  # noqa: F811
    tmp_path: Path,
) -> None:
    """LAB PROXY, NOT PARTNER DATA, negative control: one changed content byte fails the verify.

    Without this, a pass above could come from an openssl invocation that checks no digest."""
    signed = await _signed_data(monkeypatch, pki, tmp_path, "pkcs1v15")
    der = signed.read_bytes()
    body = _SYNTHETIC_HL7.encode("utf-8")
    assert der.count(body) == 1
    at = der.index(body) + body.index(b"DOE")
    signed.write_bytes(der[:at] + b"R" + der[at + 1 :])  # DOE -> ROE, same length

    done = _openssl_verify(signed, Path(pki["trust_anchor"]), tmp_path / "content.bin")
    assert done.returncode != 0
    assert b"Verification failure" in done.stderr


@pytest.mark.skipif(_OPENSSL is None, reason=_NO_OPENSSL)
async def test_lab_proxy_not_partner_data_openssl_cms_rejects_an_unrelated_ca(
    monkeypatch: pytest.MonkeyPatch,
    pki: dict[str, Any],  # noqa: F811
    tmp_path: Path,
) -> None:
    """LAB PROXY, NOT PARTNER DATA, negative control: the untampered message fails against a CA
    that did not issue the signer.

    Without this, a pass above could come from an openssl invocation that checks no chain."""
    signed = await _signed_data(monkeypatch, pki, tmp_path, "pkcs1v15")
    _, other_ca = _mint_ca()
    other = tmp_path / "other-ca.crt"
    _write_pem(other, other_ca)

    done = _openssl_verify(signed, other, tmp_path / "content.bin")
    assert done.returncode != 0
    assert b"Verification failure" in done.stderr


# --- JWS: an independent JOSE library verifies signing.py's PS256 and RS256 ----------------------


@pytest.fixture(scope="module")
def rsa_key() -> rsa.RSAPrivateKey:
    """One synthetic RSA key at the signer's own floor, shared because RSA-3072 is slow to mint."""
    return rsa.generate_private_key(public_exponent=65537, key_size=_MIN_RSA_BITS)


@pytest.fixture(scope="module")
def other_key() -> rsa.RSAPrivateKey:
    """A second synthetic key that signed nothing, for the wrong-key controls."""
    return rsa.generate_private_key(public_exponent=65537, key_size=_MIN_RSA_BITS)


def _pem(key: rsa.RSAPrivateKey) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")


def _reattach(detached: str, payload: bytes) -> str:
    """RFC 7515 Appendix F: a receiver of a detached JWS puts the base64url payload back in the
    empty middle segment and verifies the result as an ordinary compact JWS."""
    protected, middle, signature = detached.split(".")
    assert middle == ""
    return f"{protected}.{b64u_encode(payload)}.{signature}"


_JWS_ALGS = [SignatureAlgorithm.PS256, SignatureAlgorithm.RS256]
_CLAIMS = {"iss": "lab-client", "sub": "lab-client", "jti": "lab-proxy-1"}
# Signature only. The claim checks are off because this measures the JWS, and a synthetic claim set
# has no real audience or lifetime to check against.
_SIGNATURE_ONLY: Options = {"verify_exp": False, "verify_aud": False, "verify_iat": False}


@pytest.mark.parametrize("alg", _JWS_ALGS, ids=lambda a: a.value)
def test_lab_proxy_not_partner_data_pyjwt_verifies_detached_jws(
    rsa_key: rsa.RSAPrivateKey, alg: SignatureAlgorithm
) -> None:
    """LAB PROXY, NOT PARTNER DATA: PyJWT verifies the detached JWS a REST/SOAP outbound carries."""
    signer = MessageSigner(OutboundSigning(algorithm=alg, private_key=_pem(rsa_key), key_id="lab"))
    token = _reattach(signer.detached_jws(_JWS_BODY), _JWS_BODY)

    verified = jwt.PyJWS().decode_complete(token, rsa_key.public_key(), algorithms=[alg.value])
    assert verified["payload"] == _JWS_BODY
    assert verified["header"] == {"alg": alg.value, "kid": "lab"}


@pytest.mark.parametrize("alg", _JWS_ALGS, ids=lambda a: a.value)
def test_lab_proxy_not_partner_data_pyjwt_verifies_compact_jwt(
    rsa_key: rsa.RSAPrivateKey, alg: SignatureAlgorithm
) -> None:
    """LAB PROXY, NOT PARTNER DATA: PyJWT verifies the compact JWT a SMART client assertion carries."""
    signer = CompactJwtSigner(private_key=_pem(rsa_key), algorithm=alg, setting="lab_key")
    token = signer.sign(_CLAIMS)

    decoded = jwt.decode(
        token, rsa_key.public_key(), algorithms=[alg.value], options=_SIGNATURE_ONLY
    )
    assert decoded == _CLAIMS
    assert jwt.get_unverified_header(token) == {"alg": alg.value, "typ": "JWT"}


@pytest.mark.parametrize("alg", _JWS_ALGS, ids=lambda a: a.value)
def test_lab_proxy_not_partner_data_pyjwt_rejects_a_changed_body(
    rsa_key: rsa.RSAPrivateKey, other_key: rsa.RSAPrivateKey, alg: SignatureAlgorithm
) -> None:
    """LAB PROXY, NOT PARTNER DATA, negative control: PyJWT refuses a body the detached JWS did not
    sign, and refuses the right body under a key that did not sign it."""
    signer = MessageSigner(OutboundSigning(algorithm=alg, private_key=_pem(rsa_key)))
    detached = signer.detached_jws(_JWS_BODY)

    with pytest.raises(jwt.InvalidSignatureError):
        jwt.PyJWS().decode_complete(
            _reattach(detached, _JWS_BODY.replace(b"Bundle", b"Bundlf")),
            rsa_key.public_key(),
            algorithms=[alg.value],
        )
    with pytest.raises(jwt.InvalidSignatureError):
        jwt.PyJWS().decode_complete(
            _reattach(detached, _JWS_BODY), other_key.public_key(), algorithms=[alg.value]
        )


@pytest.mark.parametrize("alg", _JWS_ALGS, ids=lambda a: a.value)
def test_lab_proxy_not_partner_data_pyjwt_rejects_a_changed_claim(
    rsa_key: rsa.RSAPrivateKey, other_key: rsa.RSAPrivateKey, alg: SignatureAlgorithm
) -> None:
    """LAB PROXY, NOT PARTNER DATA, negative control: PyJWT refuses a compact JWT whose claims were
    changed after signing, and refuses the real one under a key that did not sign it."""
    signer = CompactJwtSigner(private_key=_pem(rsa_key), algorithm=alg, setting="lab_key")
    header, _, signature = signer.sign(_CLAIMS).split(".")
    forged = b64u_encode(b'{"iss":"lab-client","jti":"lab-proxy-1","sub":"someone-else"}')

    with pytest.raises(jwt.InvalidSignatureError):
        jwt.decode(
            f"{header}.{forged}.{signature}",
            rsa_key.public_key(),
            algorithms=[alg.value],
            options=_SIGNATURE_ONLY,
        )
    with pytest.raises(jwt.InvalidSignatureError):
        jwt.decode(
            signer.sign(_CLAIMS),
            other_key.public_key(),
            algorithms=[alg.value],
            options=_SIGNATURE_ONLY,
        )
