# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Refuse a weak passphrase wrap on a private key BEFORE a loader decrypts it (BACKLOG #1352, #1171).

Decrypting a passphrase-protected key file derives a key from a password, so ASVS 11.4.4 applies
at every private-key loader (owner ruling R1 of 2026-09-24), and 11.4.1 applies to the hash that
derivation is built on. Neither ``cryptography`` nor ``ssl`` will say which derivation a file uses:
both decrypt whatever they are handed. So each loader hands the key bytes here first, and this
module reads the wrap and refuses it unless it is one ASVS 5.0 Appendix C approves at its required
parameters.

What is refused, by default and with no setting to turn it off:

* **Legacy OpenSSL PEM encryption** (a ``Proc-Type: 4,ENCRYPTED`` header). Its key comes from
  ``EVP_BytesToKey`` over MD5 at one iteration, whatever cipher ``DEK-Info`` names.
* **PKCS#8 PBES1** (MD5 or SHA-1 derivation) and the **PKCS#12 PBE** schemes (the SHA-1 PKCS#12
  derivation), when they appear as the wrap of a PKCS#8 key.
* **PBES2 with PBKDF2** unless its PRF is HMAC-SHA-256 at :data:`PBKDF2_MIN_ITERATIONS` or more, or
  HMAC-SHA-512 at its own floor. A PBKDF2 block with NO ``prf`` field means HMAC-SHA-1 by RFC 8018's
  default, so it is refused like an explicit SHA-1 one.
* **PBES2 with scrypt** below Appendix C's floor: ``r >= 8``, and ``N`` at least 2^17, 2^16 or 2^15
  for ``p`` of 1, 2, or 3 and up.
* Any other derivation this module does not recognise, and an encrypted key it cannot parse.
* An encrypted key where the loader has NO passphrase to give. Refused here, before OpenSSL's
  default password callback could stop to prompt at a terminal that a service does not have.

``cryptography``'s own ``BestAvailableEncryption`` writes PBKDF2-HMAC-SHA-256 at 2048 iterations,
far under the floor, so a key written that way is refused and the refusal says so.

What this does NOT check, so a reader does not assume it: the content cipher inside PBES2 (that is a
cipher question, not a derivation one), PKCS#12 bundles and ``cert import``, and SFTP keys, which
paramiko opens itself. The last two are the second phase of BACKLOG #1352.

**Keep this a leaf.** It imports the standard library only, so ``apiclient`` and every transport
can import it without crossing a package boundary. Its refusal text names the SETTING, never the key
bytes, the passphrase or the file path: a mis-set ``env()`` can put key material where a path
belongs.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

__all__ = [
    "PBKDF2_MIN_ITERATIONS",
    "REWRAP_RECIPE",
    "KeyWrapRefused",
    "key_wrap_refusal",
    "refuse_weak_cert_chain_key",
    "refuse_weak_key_file",
    "refuse_weak_key_wrap",
]

#: PBKDF2 PRFs this module accepts, by OID, with the iteration floor ASVS 5.0 Appendix C sets for
#: each. Only the two status-A rows of its password-based KDF table are here. PBKDF2-HMAC-SHA-1 is
#: status L there and a SHA-1-based KDF is D in its general KDF table, so it is refused outright.
PBKDF2_MIN_ITERATIONS: Final[Mapping[str, tuple[str, int]]] = {
    "1.2.840.113549.2.9": ("HMAC-SHA-256", 600_000),
    "1.2.840.113549.2.11": ("HMAC-SHA-512", 210_000),
}

#: scrypt's floor from the same table: the smallest ``N`` for a given ``p``, with ``r`` at 8.
_SCRYPT_MIN_R: Final = 8


def _scrypt_min_n(p: int) -> int:
    if p <= 1:
        return 1 << 17
    if p == 2:
        return 1 << 16
    return 1 << 15


#: How to re-wrap a refused key. The openssl CLI is named because ``cryptography`` cannot write a
#: PKCS#8 key with a chosen iteration count: its ``encryption_builder`` serves only OpenSSH and
#: PKCS#12, and ``BestAvailableEncryption`` is fixed at 2048. The same command reads a legacy
#: ``Proc-Type`` PEM as its input.
#: The count is formatted in from the table rather than spelled out, so the two cannot drift.
REWRAP_RECIPE: Final = (
    "Re-wrap the key as PKCS#8 PBES2 with PBKDF2-HMAC-SHA-256 at {n} iterations or more, for "
    "example: openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256 -iter {n} "
    "-in <old key> -out <new key>"
).format(n=PBKDF2_MIN_ITERATIONS["1.2.840.113549.2.9"][1])

#: Bytes read from a key file before giving up. A PEM key, or a key with its certificate chain, is
#: a few kilobytes; a file past this is refused rather than half inspected.
_MAX_KEY_FILE_BYTES: Final = 1 << 20

_PBES2: Final = "1.2.840.113549.1.5.13"
_PBKDF2: Final = "1.2.840.113549.1.5.12"
_SCRYPT: Final = "1.3.6.1.4.1.11591.4.11"
_HMAC_SHA1: Final = "1.2.840.113549.2.7"
_PBES1: Final = frozenset(f"1.2.840.113549.1.5.{n}" for n in (1, 3, 4, 6, 10, 11))
_PKCS12_PBE: Final = frozenset(f"1.2.840.113549.1.12.1.{n}" for n in range(1, 7))

_PEM_BLOCK: Final = re.compile(
    rb"-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END \1-----",
    re.DOTALL,
)
_LEGACY_HEADER: Final = re.compile(
    rb"^\s*Proc-Type:\s*4\s*,\s*ENCRYPTED", re.MULTILINE | re.IGNORECASE
)


class KeyWrapRefused(ValueError):
    """A private key's passphrase wrap is not one this engine will decrypt, or it has no passphrase.

    A ``ValueError``, because the key file is operator configuration. The message names the setting
    and the reason, and never carries key bytes, the passphrase or the file path."""


class _Malformed(Exception):
    """The DER did not parse. Carries no data from the input."""


@dataclass(frozen=True)
class _Tlv:
    tag: int
    start: int  # first byte of the value
    end: int  # one past the last byte of the value


def _read_tlv(buf: bytes, pos: int, limit: int) -> _Tlv:
    """One DER tag-length-value at ``pos``. Definite lengths only; a single-byte tag only."""
    if pos + 2 > limit:
        raise _Malformed
    tag = buf[pos]
    if tag & 0x1F == 0x1F:
        raise _Malformed
    first = buf[pos + 1]
    pos += 2
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        if count == 0 or count > 4 or pos + count > limit:
            raise _Malformed  # 0x80 is BER's indefinite length, which DER forbids
        length = int.from_bytes(buf[pos : pos + count], "big")
        pos += count
    if pos + length > limit:
        raise _Malformed
    return _Tlv(tag, pos, pos + length)


def _children(buf: bytes, tlv: _Tlv) -> list[_Tlv]:
    """The TLVs inside a constructed value, which must fill it exactly."""
    out: list[_Tlv] = []
    pos = tlv.start
    while pos < tlv.end:
        child = _read_tlv(buf, pos, tlv.end)
        out.append(child)
        pos = child.end
    return out


def _oid(buf: bytes, tlv: _Tlv) -> str:
    if tlv.tag != 0x06 or tlv.end == tlv.start:
        raise _Malformed
    body = buf[tlv.start : tlv.end]
    first = body[0]
    arcs = [min(first // 40, 2), first - 40 * min(first // 40, 2)]
    value = 0
    for byte in body[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcs.append(value)
            value = 0
    if body[-1] & 0x80:
        raise _Malformed
    return ".".join(str(a) for a in arcs)


def _uint(buf: bytes, tlv: _Tlv) -> int:
    if tlv.tag != 0x02 or tlv.end == tlv.start:
        raise _Malformed
    value = int.from_bytes(buf[tlv.start : tlv.end], "big", signed=True)
    if value < 0:
        raise _Malformed
    return value


def _algorithm(buf: bytes, tlv: _Tlv) -> tuple[str, _Tlv | None]:
    """An AlgorithmIdentifier: its OID and its parameters, if any."""
    if tlv.tag != 0x30:
        raise _Malformed
    parts = _children(buf, tlv)
    if not parts or len(parts) > 2:
        raise _Malformed
    return _oid(buf, parts[0]), (parts[1] if len(parts) == 2 else None)


def _encrypted_pkcs8_algorithm(der: bytes) -> tuple[str, _Tlv | None] | None:
    """The wrap algorithm of an EncryptedPrivateKeyInfo, or ``None`` when ``der`` is not that shape.

    The shape is ``SEQUENCE { AlgorithmIdentifier, OCTET STRING }``. An unencrypted PKCS#8 or a
    traditional key opens with an INTEGER instead, so it returns ``None``."""
    outer = _read_tlv(der, 0, len(der))
    if outer.tag != 0x30 or outer.end != len(der):
        raise _Malformed
    parts = _children(der, outer)
    if len(parts) != 2 or parts[0].tag != 0x30 or parts[1].tag != 0x04:
        return None
    return _algorithm(der, parts[0])


def _pbes2_problem(buf: bytes, params: _Tlv | None) -> str | None:
    """Why a PBES2 parameter block is refused, or ``None`` when its derivation is approved."""
    if params is None or params.tag != 0x30:
        raise _Malformed
    parts = _children(buf, params)
    if len(parts) != 2:
        raise _Malformed
    kdf, kdf_params = _algorithm(buf, parts[0])
    if kdf == _PBKDF2:
        return _pbkdf2_problem(buf, kdf_params)
    if kdf == _SCRYPT:
        return _scrypt_problem(buf, kdf_params)
    return "is wrapped with a key derivation this engine does not recognise"


def _pbkdf2_problem(buf: bytes, params: _Tlv | None) -> str | None:
    if params is None or params.tag != 0x30:
        raise _Malformed
    parts = _children(buf, params)
    if len(parts) < 2 or len(parts) > 4:
        raise _Malformed
    iterations = _uint(buf, parts[1])
    prf: str | None = None
    for extra in parts[2:]:
        if extra.tag == 0x02:
            _uint(buf, extra)  # keyLength: read to prove it parses, not needed
        elif extra.tag == 0x30:
            prf, _ = _algorithm(buf, extra)
        else:
            raise _Malformed
    if prf is None or prf == _HMAC_SHA1:
        default = " (the default when the prf field is absent)" if prf is None else ""
        return (
            f"is wrapped with PBKDF2-HMAC-SHA-1{default}. SHA-1-based key derivation is not "
            "approved (ASVS 11.4.1, 11.4.4)"
        )
    approved = PBKDF2_MIN_ITERATIONS.get(prf)
    if approved is None:
        return (
            "is wrapped with PBKDF2 over a hash outside ASVS Appendix C's approved password-based "
            "KDF list (HMAC-SHA-256 or HMAC-SHA-512)"
        )
    name, floor = approved
    if iterations < floor:
        return (
            f"is wrapped with PBKDF2-{name} at {iterations} iterations, under the {floor} floor "
            "ASVS Appendix C sets for it (ASVS 11.4.4). 2048 is the cryptography library's "
            "BestAvailableEncryption default, so a key written that way lands here"
        )
    return None


def _scrypt_problem(buf: bytes, params: _Tlv | None) -> str | None:
    if params is None or params.tag != 0x30:
        raise _Malformed
    parts = _children(buf, params)
    if len(parts) < 4 or len(parts) > 5 or parts[0].tag != 0x04:
        raise _Malformed
    n, r, p = (_uint(buf, t) for t in parts[1:4])
    if r < _SCRYPT_MIN_R or p < 1 or n < _scrypt_min_n(p):
        return (
            f"is wrapped with scrypt at N={n}, r={r}, p={p}, under ASVS Appendix C's floor "
            f"(r of 8 and N of at least {_scrypt_min_n(max(p, 1))} for this p)"
        )
    return None


def _wrap_problem(der: bytes, algorithm: str, params: _Tlv | None) -> str | None:
    """Why the wrap ``algorithm`` is refused, or ``None`` for an approved one."""
    if algorithm == _PBES2:
        return _pbes2_problem(der, params)
    if algorithm in _PBES1:
        return (
            "is wrapped with PKCS#5 PBES1, whose key derivation is MD5 or SHA-1 based and not "
            "approved (ASVS 11.4.1, 11.4.4)"
        )
    if algorithm in _PKCS12_PBE:
        return (
            "is wrapped with a PKCS#12 PBE scheme, whose key derivation is SHA-1 based and not "
            "approved (ASVS 11.4.1, 11.4.4)"
        )
    return "is wrapped with an encryption scheme this engine does not recognise"


_UNREADABLE: Final = "is an encrypted private key this engine cannot read to check its wrap"


def _der_problem(der: bytes, *, known_encrypted: bool) -> tuple[bool, str | None]:
    """``(encrypted, problem)`` for one DER key.

    ``known_encrypted`` is true for the body of an ``ENCRYPTED PRIVATE KEY`` PEM block, which must
    parse as an EncryptedPrivateKeyInfo. Bare DER need not: if its outer shape is not one, it is an
    unencrypted key or not a key at all, and the loader reports the second itself."""
    try:
        found = _encrypted_pkcs8_algorithm(der)
    except _Malformed:
        found = None
    if found is None:
        return (True, _UNREADABLE) if known_encrypted else (False, None)
    # The shape said encrypted; parameters that do not parse are refused, failing closed.
    problem: str | None = _UNREADABLE
    with contextlib.suppress(_Malformed):
        problem = _wrap_problem(der, *found)
    return True, problem


def _inspect(material: bytes) -> tuple[bool, str | None]:
    """``(encrypted, problem)`` over every private key in ``material``, PEM or DER.

    Refuses on the FIRST weak wrap. ``encrypted`` is true when any key in it is encrypted."""
    if b"-----BEGIN" not in material:
        return _der_problem(material, known_encrypted=False)
    encrypted = False
    for match in _PEM_BLOCK.finditer(material):
        label, body = match.group(1), match.group(2)
        if _LEGACY_HEADER.search(body):
            return True, (
                "uses legacy OpenSSL PEM encryption (a Proc-Type: 4,ENCRYPTED header), whose key "
                "is derived with MD5 at one iteration (ASVS 11.4.1, 11.4.4)"
            )
        if label != b"ENCRYPTED PRIVATE KEY":
            continue
        encrypted = True
        der = b""
        try:
            der = base64.b64decode(b"".join(body.split()), validate=True)
        except (binascii.Error, ValueError):
            return True, _UNREADABLE
        _, problem = _der_problem(der, known_encrypted=True)
        if problem is not None:
            return True, problem
    return encrypted, None


def key_wrap_refusal(
    material: bytes,
    *,
    setting: str,
    unlock_setting: str | None,
    passphrase_given: bool,
) -> str | None:
    """The refusal text for ``material``, or ``None`` when every key in it may be loaded.

    ``setting`` names where the key came from, for the message. ``unlock_setting`` names the
    setting that carries its passphrase, or ``None`` for a loader that takes no passphrase at all.
    ``passphrase_given`` says whether the loader is about to pass one. The text holds no key bytes,
    passphrase or path, so a caller may raise it as its own error type."""
    encrypted, problem = _inspect(material)
    if problem is not None:
        return f"{setting}: the private key {problem}. It is refused. {REWRAP_RECIPE}"
    if encrypted and not passphrase_given:
        if unlock_setting is None:
            fix = (
                "this loader takes no passphrase, so supply an unencrypted key and protect the "
                "file with its permissions instead"
            )
        else:
            fix = f"set {unlock_setting} (through env())"
        return (
            f"{setting}: the private key is encrypted and no passphrase is configured for it; {fix}. "
            "Refused before the TLS library could stop to prompt at a terminal"
        )
    return None


def refuse_weak_key_wrap(
    material: bytes,
    *,
    setting: str,
    unlock_setting: str | None,
    passphrase_given: bool,
) -> None:
    """Raise :class:`KeyWrapRefused` when :func:`key_wrap_refusal` refuses ``material``."""
    reason = key_wrap_refusal(
        material,
        setting=setting,
        unlock_setting=unlock_setting,
        passphrase_given=passphrase_given,
    )
    if reason is not None:
        raise KeyWrapRefused(reason)


def refuse_weak_key_file(
    path: str | os.PathLike[str],
    *,
    setting: str,
    unlock_setting: str | None,
    passphrase_given: bool,
) -> None:
    """Read the key file at ``path`` and refuse it as :func:`refuse_weak_key_wrap` does.

    A file that cannot be opened is left to the loader, which fails on it with its own error; so a
    missing path reads exactly as it did before this check. An over-size file is refused."""
    material = b""
    try:
        with open(path, "rb") as handle:
            material = handle.read(_MAX_KEY_FILE_BYTES + 1)
    except (OSError, ValueError):
        return
    if len(material) > _MAX_KEY_FILE_BYTES:
        raise KeyWrapRefused(
            f"{setting}: the key file is over {_MAX_KEY_FILE_BYTES} bytes, too large to check its "
            "wrap; a private key and its chain are a few kilobytes"
        )
    refuse_weak_key_wrap(
        material,
        setting=setting,
        unlock_setting=unlock_setting,
        passphrase_given=passphrase_given,
    )


def refuse_weak_cert_chain_key(
    certfile: str | os.PathLike[str],
    keyfile: str | os.PathLike[str] | None,
    *,
    cert_setting: str,
    key_setting: str,
    unlock_setting: str | None,
    passphrase_given: bool,
) -> None:
    """Check the key an ``ssl.SSLContext.load_cert_chain(certfile, keyfile, ...)`` call would load.

    With no ``keyfile`` OpenSSL reads the key out of ``certfile``, a combined PEM, so that is the
    file checked then. Call this immediately before ``load_cert_chain``. OpenSSL reads the file a
    second time, and a file swapped between the two reads is not caught here; the empty passphrase
    callback each site passes is what keeps a swapped-in encrypted key off the terminal."""
    if keyfile:
        refuse_weak_key_file(
            keyfile,
            setting=key_setting,
            unlock_setting=unlock_setting,
            passphrase_given=passphrase_given,
        )
    else:
        refuse_weak_key_file(
            certfile,
            setting=cert_setting,
            unlock_setting=unlock_setting,
            passphrase_given=passphrase_given,
        )
