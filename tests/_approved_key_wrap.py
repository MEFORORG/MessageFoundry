# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Write a passphrase-protected PKCS#8 key the engine's loaders accept (BACKLOG #1352, #1171).

The loaders refuse ``cryptography``'s ``BestAvailableEncryption``: it writes PBKDF2-HMAC-SHA-256 at
2048 iterations, under the 600,000 floor. ``cryptography`` cannot write PKCS#8 at a chosen iteration
count or PRF (its ``encryption_builder`` serves only OpenSSH and PKCS#12), so this module assembles
the EncryptedPrivateKeyInfo DER from ``cryptography``'s own PBKDF2 and AES-CBC primitives. Tests
that need an encrypted key use :func:`approved_pkcs8_pem`; ``tests/test_keywrap.py`` also uses
:func:`pkcs8_pem` to build the weak variants.

The output is a real key file: the loaders' own tests decrypt it through OpenSSL and ``cryptography``.
Keys and passphrases here are synthetic.
"""

from __future__ import annotations

import base64
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, hmac, padding, serialization
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.serialization.pkcs12 import PKCS12PrivateKeyTypes

PBES2 = "1.2.840.113549.1.5.13"
PBKDF2 = "1.2.840.113549.1.5.12"
PBMAC1 = "1.2.840.113549.1.5.14"
SCRYPT = "1.3.6.1.4.1.11591.4.11"
AES256_CBC = "2.16.840.1.101.3.4.1.42"
NULL = b"\x05\x00"

#: PBKDF2 PRFs by short name: (OID, the hash cryptography derives with).
PRF: dict[str, tuple[str, hashes.HashAlgorithm]] = {
    "sha1": ("1.2.840.113549.2.7", hashes.SHA1()),
    "sha224": ("1.2.840.113549.2.8", hashes.SHA224()),
    "sha256": ("1.2.840.113549.2.9", hashes.SHA256()),
    "sha384": ("1.2.840.113549.2.10", hashes.SHA384()),
    "sha512": ("1.2.840.113549.2.11", hashes.SHA512()),
}


def tlv(tag: int, body: bytes) -> bytes:
    n = len(body)
    if n < 0x80:
        return bytes([tag, n]) + body
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(raw)]) + raw + body


def seq(*parts: bytes) -> bytes:
    return tlv(0x30, b"".join(parts))


def integer(value: int) -> bytes:
    return tlv(0x02, value.to_bytes(value.bit_length() // 8 + 1, "big"))


def oid(dotted: str) -> bytes:
    arcs = [int(a) for a in dotted.split(".")]
    out = bytearray([40 * arcs[0] + arcs[1]])
    for arc in arcs[2:]:
        chunk = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunk.append(0x80 | (arc & 0x7F))
            arc >>= 7
        out += bytes(reversed(chunk))
    return tlv(0x06, bytes(out))


def octets(value: bytes) -> bytes:
    return tlv(0x04, value)


def pem(der: bytes, label: str = "ENCRYPTED PRIVATE KEY") -> bytes:
    body = base64.b64encode(der)
    lines = [body[i : i + 64] for i in range(0, len(body), 64)]
    return (
        f"-----BEGIN {label}-----\n".encode()
        + b"\n".join(lines)
        + f"\n-----END {label}-----\n".encode()
    )


def pkcs8_pem(
    key: PrivateKeyTypes, passphrase: str | bytes, *, prf: str | None, iterations: int
) -> bytes:
    """A PBES2 / PBKDF2 / AES-256-CBC encrypted PKCS#8 key, as PEM. ``prf=None`` omits the field,
    which RFC 8018 reads as HMAC-SHA-1."""
    secret = passphrase.encode("utf-8") if isinstance(passphrase, str) else passphrase
    plain = key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    salt, iv = os.urandom(16), os.urandom(16)
    prf_oid, digest = PRF["sha1" if prf is None else prf]
    derived = PBKDF2HMAC(algorithm=digest, length=32, salt=salt, iterations=iterations).derive(
        secret
    )
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plain) + padder.finalize()
    encryptor = Cipher(algorithms.AES(derived), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    kdf_fields = [octets(salt), integer(iterations)]
    if prf is not None:
        kdf_fields.append(seq(oid(prf_oid), NULL))
    der = seq(
        seq(
            oid(PBES2),
            seq(seq(oid(PBKDF2), seq(*kdf_fields)), seq(oid(AES256_CBC), octets(iv))),
        ),
        octets(ciphertext),
    )
    return pem(der)


def approved_pkcs8_pem(key: PrivateKeyTypes, passphrase: str | bytes) -> bytes:
    """PKCS#8 PBES2 with PBKDF2-HMAC-SHA-256 at 600,000 iterations: the floor, and accepted."""
    return pkcs8_pem(key, passphrase, prf="sha256", iterations=600_000)


def approved_pfx(
    key: PKCS12PrivateKeyTypes,
    cert: x509.Certificate,
    passphrase: bytes,
    cas: list[x509.Certificate] | None = None,
    *,
    iterations: int = 600_000,
) -> bytes:
    """A PKCS#12 bundle the engine accepts: PBES2 AES-256-CBC bags at ``iterations`` and a PBMAC1
    (RFC 9579) MAC keyed by PBKDF2-HMAC-SHA-256 at ``iterations``.

    ``cryptography`` writes the bags but cannot write PBMAC1: its own MAC is keyed by the PKCS#12
    KDF, which the engine refuses. So its MacData is replaced here by a PBMAC1 one over the same
    authSafe content. PBMAC1's password is the UTF-8 bytes, measured against OpenSSL 3.5.7."""
    return with_pbmac1(
        pkcs12_bundle(key, cert, passphrase, cas, iterations=iterations),
        passphrase,
        iterations=iterations,
    )


def pkcs12_bundle(
    key: PKCS12PrivateKeyTypes,
    cert: x509.Certificate,
    passphrase: bytes,
    cas: list[x509.Certificate] | None = None,
    *,
    iterations: int = 600_000,
    mac_hash: hashes.HashAlgorithm | None = None,
) -> bytes:
    """``cryptography``'s own bundle: PBES2 AES-256-CBC bags at ``iterations``, and its MAC keyed
    by the PKCS#12 KDF over ``mac_hash`` (SHA-256 by default)."""
    enc = (
        serialization.PrivateFormat.PKCS12.encryption_builder()
        .kdf_rounds(iterations)
        .key_cert_algorithm(pkcs12.PBES.PBESv2SHA256AndAES256CBC)
        .hmac_hash(mac_hash or hashes.SHA256())
        .build(passphrase)
    )
    return pkcs12.serialize_key_and_certificates(b"mefor", key, cert, cas, enc)


def _tlv_at(buf: bytes, pos: int) -> tuple[int, int]:
    """(value start, value end) of the DER TLV at ``pos``."""
    first = buf[pos + 1]
    if first < 0x80:
        return pos + 2, pos + 2 + first
    count = first & 0x7F
    start = pos + 2 + count
    return start, start + int.from_bytes(buf[pos + 2 : pos + 2 + count], "big")


def with_pbmac1(pfx: bytes, passphrase: bytes, *, iterations: int, prf: str = "sha256") -> bytes:
    """``pfx`` with its MacData replaced by a PBMAC1 one keyed by PBKDF2 over ``prf``."""
    outer_start, _ = _tlv_at(pfx, 0)
    _, after_version = _tlv_at(pfx, outer_start)
    auth_safe_start, after_auth_safe = _tlv_at(pfx, after_version)
    # authSafe ContentInfo: contentType OID, then [0] EXPLICIT OCTET STRING. The MAC covers the
    # OCTET STRING's value.
    _, after_type = _tlv_at(pfx, auth_safe_start)
    explicit_start, _ = _tlv_at(pfx, after_type)
    content_start, content_end = _tlv_at(pfx, explicit_start)
    prf_oid, digest = PRF[prf]
    salt = os.urandom(16)
    mac_key = PBKDF2HMAC(algorithm=digest, length=32, salt=salt, iterations=iterations).derive(
        passphrase
    )
    signer = hmac.HMAC(mac_key, digest)
    signer.update(pfx[content_start:content_end])
    params = seq(
        seq(
            oid(PBKDF2),
            seq(octets(salt), integer(iterations), integer(32), seq(oid(prf_oid), NULL)),
        ),
        seq(oid(prf_oid), NULL),
    )
    mac_data = seq(seq(seq(oid(PBMAC1), params), octets(signer.finalize())), octets(b"\x00" * 8))
    return seq(pfx[outer_start:after_auth_safe], mac_data)
