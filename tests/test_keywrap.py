# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Private-key loaders refuse a weak passphrase wrap and floor the KDF (BACKLOG #1352, #1171).

Every weak fixture here is paired with an approved control that must still LOAD through the same
real loader. A refusal test with no such control passes against a loader that refuses everything.

The fixtures are built in memory from synthetic keys. ``cryptography`` writes the legacy PEM and its
own 2048-iteration PKCS#8 default. It cannot write PKCS#8 at a chosen iteration count or PRF (its
``encryption_builder`` serves only OpenSSH and PKCS#12), so ``tests/_approved_key_wrap.py`` assembles the
EncryptedPrivateKeyInfo DER itself from ``cryptography``'s PBKDF2 and AES-CBC primitives. The
approved control loading through OpenSSL and ``cryptography`` is what proves those files are real.
"""

from __future__ import annotations

import ast
import base64
import datetime
import ssl
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, NamedTuple

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from messagefoundry import keywrap
from messagefoundry.keywrap import KeyWrapRefused, key_wrap_refusal
from tests._approved_key_wrap import (
    AES256_CBC,
    PBES2,
    PBKDF2,
    SCRYPT,
    integer,
    octets,
    oid,
    pem,
    pkcs8_pem,
    seq,
)

_PASSPHRASE = "synthetic-test-passphrase"  # a fixture value, not a secret


def _pkcs8(key: ec.EllipticCurvePrivateKey, *, prf: str | None, iterations: int) -> bytes:
    return pkcs8_pem(key, _PASSPHRASE, prf=prf, iterations=iterations)


def _wrap_only(algorithm: bytes) -> bytes:
    """An EncryptedPrivateKeyInfo with ``algorithm`` and dummy ciphertext: enough for the checker,
    which reads only the wrap, for schemes no pinned library writes."""
    return seq(algorithm, octets(b"\x00" * 32))


# --- fixtures -----------------------------------------------------------------------------------


class Material(NamedTuple):
    key: ec.EllipticCurvePrivateKey
    cert_pem: bytes
    #: Each wrap in :data:`_WEAK`, plus ``"approved"``, built ONCE: a 600,000-iteration wrap costs a
    #: noticeable fraction of a second to write, and the parametrized tests reuse every one.
    wraps: dict[str, bytes]


@pytest.fixture(scope="module")
def material() -> Material:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "keywrap.test")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    wraps = {wrap_id: build(key) for wrap_id, build, _ in _WEAK}
    wraps["approved"] = _pkcs8(key, prf="sha256", iterations=600_000)
    return Material(key, cert.public_bytes(serialization.Encoding.PEM), wraps)


def _legacy_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.BestAvailableEncryption(_PASSPHRASE.encode()),
    )


def _best_available_pkcs8(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(_PASSPHRASE.encode()),
    )


#: Weak wraps: (id, builder, a fragment the refusal must carry). Each one is DECRYPTABLE with the
#: fixture passphrase, so against the unfixed loaders it loads.
_WEAK: list[tuple[str, Callable[[ec.EllipticCurvePrivateKey], bytes], str]] = [
    ("legacy-proc-type-pem", _legacy_pem, "legacy OpenSSL PEM encryption"),
    ("pbes2-no-prf", lambda k: _pkcs8(k, prf=None, iterations=600_000), "prf field is absent"),
    ("pbes2-sha1-prf", lambda k: _pkcs8(k, prf="sha1", iterations=600_000), "PBKDF2-HMAC-SHA-1"),
    ("pbes2-sha224-prf", lambda k: _pkcs8(k, prf="sha224", iterations=600_000), "approved"),
    ("best-available-2048", _best_available_pkcs8, "2048 iterations"),
    ("sha256-one-under", lambda k: _pkcs8(k, prf="sha256", iterations=599_999), "599999"),
]

#: (wrap id, refusal fragment) for the parametrized loader tests.
_WEAK_CASES = [(wrap_id, why) for wrap_id, _, why in _WEAK]

#: The approved control, ``material.wraps["approved"]``, is PBKDF2-HMAC-SHA-256 at exactly the
#: 600,000 floor.


def _write(tmp_path: Path, name: str, data: bytes) -> str:
    path = tmp_path / name
    path.write_bytes(data)
    return str(path)


# --- the real loaders ---------------------------------------------------------------------------
#
# Each takes (cert path, key path or None for a combined PEM, passphrase or None) and runs the
# shipped loader. The password-less loaders take no passphrase argument at all.


def _api(cert: str, key: str | None, pw: str | None) -> object:
    from messagefoundry.api.tls import build_api_ssl_context
    from messagefoundry.config.settings import ApiSettings

    return build_api_ssl_context(
        ApiSettings(tls_cert_file=cert, tls_key_file=key, tls_key_password=pw)
    )


def _mllp_settings(cert: str, key: str | None, pw: str | None) -> dict[str, Any]:
    s: dict[str, Any] = {"tls": True, "tls_cert_file": cert, "host": "127.0.0.1"}
    if key is not None:
        s["tls_key_file"] = key
    if pw is not None:
        s["tls_key_password"] = pw
    return s


def _mllp_server(cert: str, key: str | None, pw: str | None) -> object:
    from messagefoundry.transports.mllp import _mllp_ssl_context

    return _mllp_ssl_context(_mllp_settings(cert, key, pw), server=True)


def _mllp_client(cert: str, key: str | None, pw: str | None) -> object:
    from messagefoundry.transports.mllp import _mllp_ssl_context

    return _mllp_ssl_context(_mllp_settings(cert, key, pw), server=False)


def _dicom_server(cert: str, key: str | None, pw: str | None) -> object:
    from messagefoundry.transports.dicom import _server_ssl_context

    return _server_ssl_context(_mllp_settings(cert, key, pw))


def _dicom_client(cert: str, key: str | None, pw: str | None) -> object:
    from messagefoundry.transports.dicom import _client_ssl_context

    return _client_ssl_context(_mllp_settings(cert, key, pw))


def _ftps(cert: str, key: str | None, pw: str | None) -> object:
    from messagefoundry.transports.remotefile import _ftps_ssl_context

    return _ftps_ssl_context(_mllp_settings(cert, key, pw))


def _soap(cert: str, key: str | None, pw: str | None) -> object:
    from messagefoundry.transports.soap import _client_cert_opener

    # SOAP requires both files; a combined PEM is named twice.
    return _client_cert_opener(cert, key if key is not None else cert, pw)


def _syslog(cert: str, key: str | None, pw: str | None) -> object:
    from messagefoundry.logging_setup import SyslogForward, _build_tls_context

    assert key is None and pw is None  # the forwarder takes a combined PEM and no passphrase
    return _build_tls_context(
        SyslogForward(host="127.0.0.1", protocol="tls", tls_verify=False, tls_client_cert=cert)
    )


def _apiclient(cert: str, key: str | None, pw: str | None) -> object:
    from messagefoundry.apiclient.client import _build_verify_context

    assert pw is None  # the client takes no passphrase
    return _build_verify_context(cert, cert, key)


def _signing(key_pem: bytes, pw: str | None) -> object:
    from messagefoundry.transports.signing import _load_private_key

    return _load_private_key("sign_private_key", key_pem.decode(), pw)


def _direct(key_path: str, pw: str | None) -> object:
    from messagefoundry.transports.direct import DirectDestination

    # The method reads only its arguments; `self` is never touched.
    loader: Any = DirectDestination._load_private_key
    return loader(None, key_path, pw)


#: The ssl sites that take a passphrase, by name.
_SSL_WITH_PASSPHRASE: dict[str, Callable[[str, str | None, str | None], object]] = {
    "api-listener": _api,
    "mllp-listener": _mllp_server,
    "mllp-client": _mllp_client,
    "dicom-scp": _dicom_server,
    "dicom-scu": _dicom_client,
    "ftps": _ftps,
    "soap-mtls": _soap,
}

#: The ssl sites that take no passphrase at all.
_SSL_WITHOUT_PASSPHRASE: dict[str, Callable[[str, str | None, str | None], object]] = {
    "syslog-forwarder": _syslog,
    "apiclient": _apiclient,
}


# --- weak wraps are refused, the approved control loads -----------------------------------------


@pytest.mark.parametrize(("wrap", "why"), _WEAK_CASES)
@pytest.mark.parametrize("site", sorted(_SSL_WITH_PASSPHRASE))
def test_an_ssl_loader_refuses_a_weak_wrap(
    tmp_path: Path, material: Material, site: str, wrap: str, why: str
) -> None:
    cert = _write(tmp_path, "cert.pem", material.cert_pem)
    key = _write(tmp_path, "key.pem", material.wraps[wrap])
    with pytest.raises(KeyWrapRefused, match=why):
        _SSL_WITH_PASSPHRASE[site](cert, key, _PASSPHRASE)


@pytest.mark.parametrize("site", sorted(_SSL_WITH_PASSPHRASE))
def test_an_ssl_loader_refuses_a_weak_wrap_in_a_combined_pem(
    tmp_path: Path, material: Material, site: str
) -> None:
    # No keyfile: OpenSSL reads the key out of the certificate file, so that file is checked.
    combined = _write(tmp_path, "both.pem", material.cert_pem + _legacy_pem(material.key))
    with pytest.raises(KeyWrapRefused, match="legacy OpenSSL PEM encryption"):
        _SSL_WITH_PASSPHRASE[site](combined, None, _PASSPHRASE)


@pytest.mark.parametrize("site", sorted(_SSL_WITH_PASSPHRASE))
def test_an_ssl_loader_still_loads_the_approved_wrap(
    tmp_path: Path, material: Material, site: str
) -> None:
    cert = _write(tmp_path, "cert.pem", material.cert_pem)
    key = _write(tmp_path, "key.pem", material.wraps["approved"])
    assert _SSL_WITH_PASSPHRASE[site](cert, key, _PASSPHRASE) is not None
    combined = _write(tmp_path, "both.pem", material.cert_pem + material.wraps["approved"])
    assert _SSL_WITH_PASSPHRASE[site](combined, None, _PASSPHRASE) is not None


@pytest.mark.parametrize("site", sorted(_SSL_WITH_PASSPHRASE))
def test_an_ssl_loader_still_loads_an_unencrypted_key(
    tmp_path: Path, material: Material, site: str
) -> None:
    plain = material.key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    cert = _write(tmp_path, "cert.pem", material.cert_pem)
    key = _write(tmp_path, "key.pem", plain)
    assert _SSL_WITH_PASSPHRASE[site](cert, key, None) is not None


class _Reached(Exception):
    """load_cert_chain was called: the key reached OpenSSL."""


@pytest.fixture
def spy_load_cert_chain(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    """Stand in for ``load_cert_chain`` so an encrypted key with no passphrase can never reach
    OpenSSL's terminal prompt, even on code without the fix. Reaching it raises."""
    calls: list[object] = []

    def fake(self: ssl.SSLContext, *args: object, **kwargs: object) -> None:
        calls.append(args)
        raise _Reached

    monkeypatch.setattr(ssl.SSLContext, "load_cert_chain", fake)
    return calls


@pytest.mark.parametrize("site", sorted({**_SSL_WITH_PASSPHRASE, **_SSL_WITHOUT_PASSPHRASE}))
def test_an_encrypted_key_with_no_passphrase_never_reaches_openssl(
    tmp_path: Path, material: Material, site: str, spy_load_cert_chain: list[object]
) -> None:
    loaders = {**_SSL_WITH_PASSPHRASE, **_SSL_WITHOUT_PASSPHRASE}
    combined = _write(tmp_path, "both.pem", material.cert_pem + material.wraps["approved"])
    with pytest.raises(KeyWrapRefused, match="no passphrase is configured"):
        loaders[site](combined, None, None)
    assert spy_load_cert_chain == []


@pytest.mark.parametrize("site", sorted(_SSL_WITHOUT_PASSPHRASE))
def test_a_passphrase_less_loader_refuses_a_weak_wrap_and_loads_a_plain_key(
    tmp_path: Path, material: Material, site: str
) -> None:
    weak = _write(tmp_path, "weak.pem", material.cert_pem + _legacy_pem(material.key))
    with pytest.raises(KeyWrapRefused, match="legacy OpenSSL PEM encryption"):
        _SSL_WITHOUT_PASSPHRASE[site](weak, None, None)
    plain = material.key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    good = _write(tmp_path, "good.pem", material.cert_pem + plain)
    assert _SSL_WITHOUT_PASSPHRASE[site](good, None, None) is not None


@pytest.mark.parametrize(("wrap", "why"), _WEAK_CASES)
def test_the_signing_loader_refuses_a_weak_wrap(material: Material, wrap: str, why: str) -> None:
    from messagefoundry.transports.signing import SigningError

    with pytest.raises(SigningError, match=why):
        _signing(material.wraps[wrap], _PASSPHRASE)


def test_the_signing_loader_loads_the_approved_wrap_and_refuses_a_missing_passphrase(
    material: Material,
) -> None:
    from messagefoundry.transports.signing import SigningError

    approved = material.wraps["approved"]
    assert _signing(approved, _PASSPHRASE) is not None
    with pytest.raises(SigningError, match="set sign_private_key_password"):
        _signing(approved, None)


@pytest.mark.parametrize(("wrap", "why"), _WEAK_CASES)
def test_the_direct_loader_refuses_a_weak_wrap(
    tmp_path: Path, material: Material, wrap: str, why: str
) -> None:
    key = _write(tmp_path, "key.pem", material.wraps[wrap])
    with pytest.raises(ValueError, match=why):
        _direct(key, _PASSPHRASE)


def test_the_direct_loader_refuses_a_weak_der_wrap_and_loads_the_approved_one(
    tmp_path: Path, material: Material
) -> None:
    def der_of(pem: bytes) -> bytes:
        return base64.b64decode(b"".join(pem.splitlines()[1:-1]))

    weak = _write(tmp_path, "weak.der", der_of(_best_available_pkcs8(material.key)))
    with pytest.raises(ValueError, match="2048 iterations"):
        _direct(weak, _PASSPHRASE)
    good_der = _write(tmp_path, "good.der", der_of(material.wraps["approved"]))
    assert _direct(good_der, _PASSPHRASE) is not None
    good_pem = _write(tmp_path, "good.pem", material.wraps["approved"])
    assert _direct(good_pem, _PASSPHRASE) is not None


# --- the checker itself -------------------------------------------------------------------------


def _check(material: bytes, *, given: bool = True) -> str | None:
    return key_wrap_refusal(
        material, setting="the key", unlock_setting="its passphrase", passphrase_given=given
    )


def test_the_sha512_floor(material: Material) -> None:
    # 210,000 iterations, the Appendix C floor for HMAC-SHA-512.
    assert _check(_pkcs8(material.key, prf="sha512", iterations=210_000)) is None
    refusal = _check(_pkcs8(material.key, prf="sha512", iterations=209_999))
    assert refusal is not None and "209999" in refusal


def test_a_prf_outside_appendix_c_is_refused(material: Material) -> None:
    refusal = _check(_pkcs8(material.key, prf="sha384", iterations=600_000))
    assert refusal is not None and "HMAC-SHA-256 or HMAC-SHA-512" in refusal


def test_the_refusal_names_the_library_default_and_how_to_rewrap(material: Material) -> None:
    refusal = _check(_best_available_pkcs8(material.key))
    assert refusal is not None
    assert "BestAvailableEncryption default" in refusal
    assert f"-v2prf hmacWithSHA256 -iter {600_000}" in refusal


@pytest.mark.parametrize(
    ("scheme", "why"),
    [
        (seq(oid("1.2.840.113549.1.5.3"), seq(octets(b"s" * 8), integer(2048))), "PBES1"),
        (seq(oid("1.2.840.113549.1.5.10"), seq(octets(b"s" * 8), integer(2048))), "PBES1"),
        (seq(oid("1.2.840.113549.1.12.1.3"), seq(octets(b"s" * 8), integer(2048))), "PKCS#12"),
        (seq(oid("1.2.840.113549.1.12.1.6"), seq(octets(b"s" * 8), integer(2048))), "PKCS#12"),
        (seq(oid("1.2.840.99999.1")), "does not recognise"),
    ],
)
def test_pbes1_pkcs12_and_unknown_schemes_are_refused(scheme: bytes, why: str) -> None:
    der = _wrap_only(scheme)
    for form in (der, pem(der)):
        refusal = _check(form)
        assert refusal is not None and why in refusal


def _scrypt_wrap(n: int, r: int, p: int) -> bytes:
    kdf = seq(oid(SCRYPT), seq(octets(b"s" * 16), integer(n), integer(r), integer(p)))
    return _wrap_only(seq(oid(PBES2), seq(kdf, seq(oid(AES256_CBC), octets(b"i" * 16)))))


@pytest.mark.parametrize(
    ("n", "r", "p", "approved"),
    [
        (1 << 17, 8, 1, True),
        (1 << 16, 8, 1, False),  # the openssl CLI's -scrypt default is 2^14, below this
        (1 << 16, 8, 2, True),
        (1 << 15, 8, 2, False),
        (1 << 15, 8, 3, True),
        (1 << 17, 4, 1, False),
    ],
)
def test_the_scrypt_floor(n: int, r: int, p: int, approved: bool) -> None:
    refusal = _check(_scrypt_wrap(n, r, p))
    assert (refusal is None) is approved, refusal


def test_an_unparseable_encrypted_key_is_refused_not_passed() -> None:
    # Three zero bytes: base64 that decodes, under the label, and no key structure at all.
    assert _check(pem(b"\x00\x00\x00")) is not None
    truncated_params = _wrap_only(seq(oid(PBES2), seq(seq(oid(PBKDF2)))))
    assert _check(pem(truncated_params)) is not None
    assert _check(truncated_params) is not None


def test_an_unencrypted_key_and_a_certificate_pass(material: Material) -> None:
    for fmt in (serialization.PrivateFormat.PKCS8, serialization.PrivateFormat.TraditionalOpenSSL):
        for enc in (serialization.Encoding.PEM, serialization.Encoding.DER):
            plain = material.key.private_bytes(enc, fmt, serialization.NoEncryption())
            assert _check(plain, given=False) is None
    assert _check(material.cert_pem, given=False) is None


def test_the_refusal_carries_no_key_bytes_or_passphrase(material: Material) -> None:
    pem = _legacy_pem(material.key)
    refusal = _check(pem)
    assert refusal is not None
    assert _PASSPHRASE not in refusal
    body = b"".join(pem.splitlines()[3:-1]).decode()
    for i in range(0, len(body) - 16, 16):
        assert body[i : i + 16] not in refusal


def test_an_unreadable_file_is_left_to_the_loader(tmp_path: Path) -> None:
    # Unchanged behaviour for a missing path: the loader raises its own error, not this module.
    keywrap.refuse_weak_key_file(
        tmp_path / "absent.pem",
        setting="k",
        unlock_setting=None,
        passphrase_given=False,
    )


def test_an_oversize_key_file_is_refused(tmp_path: Path) -> None:
    big = tmp_path / "big.pem"
    big.write_bytes(b"x" * ((1 << 20) + 1))
    with pytest.raises(KeyWrapRefused, match="too large"):
        keywrap.refuse_weak_key_file(big, setting="k", unlock_setting=None, passphrase_given=False)


def test_the_leaf_imports_only_the_standard_library() -> None:
    # apiclient imports this module, so it must stay a stdlib-only leaf.
    tree = ast.parse(Path(keywrap.__file__).read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    assert imported, "the walk found no imports at all"
    outside = sorted(m for m in imported if m.split(".")[0] not in sys.stdlib_module_names)
    assert outside == [], outside
