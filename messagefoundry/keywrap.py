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
* **PBES2 with PBKDF2** unless its PRF is HMAC-SHA-256 or HMAC-SHA-512 at the iteration floor
  :data:`PBKDF2_MIN_ITERATIONS` holds for it. A PBKDF2 block with NO ``prf`` field means HMAC-SHA-1
  by RFC 8018's default, so it is refused like an explicit SHA-1 one.
* **PBES2 with scrypt** below Appendix C's floor: ``r >= 8``, and ``N`` at least 2^17, 2^16 or 2^15
  for ``p`` of 1, 2, or 3 and up. Those are the table's three rows, encoded as written.
* Any other derivation this module does not recognise, an encrypted key it cannot parse, and a key
  file it cannot read or that is too large to check.
* An encrypted key where the loader has NO passphrase to give, before any library can try it.

``cryptography``'s ``BestAvailableEncryption`` and the ``openssl`` CLI's own default both write
PBKDF2-HMAC-SHA-256 at 2048 iterations, far under the floor, so a key written either way is refused.

PKCS#12 bundles (``cert import``) get the same rules for their bags, plus a MAC rule: only a PBMAC1
MAC at the PBKDF2 floor passes, because any other MAC is keyed by the PKCS#12 KDF, which Appendix C
does not list (:func:`pkcs12_wrap_refusal`). The MAC rule holds whether or not the bags are
encrypted; only a bundle with clear bags and no MAC at all derives nothing from a password, and it
passes. SSH keys cannot reach an approved derivation at all,
so the SFTP connector refuses an encrypted one outright (:func:`ssh_key_encrypted`). A database
driver's own client key is checked as a key file before the driver opens it, when ``odbc_params``
names it with ``sslkey``; a key libpq finds by itself (``PGSSLKEY``, its default path) is not.

What this does NOT check, so a reader does not assume it: the content cipher inside PBES2 (that is a
cipher question, not a derivation one), the inside of a PKCS#12 part that is itself encrypted
(reaching it already needs the passphrase), and any private-key loader this module is not called
from. Read the list of callers as the coverage, and treat it as AT LEAST that list.

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
import ssl
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

__all__ = [
    "PBKDF2_MIN_ITERATIONS",
    "KeyWrapRefused",
    "key_wrap_refusal",
    "load_checked_cert_chain",
    "load_connection_cert_chain",
    "pkcs12_wrap_refusal",
    "refuse_weak_cert_chain_key",
    "refuse_weak_key_file",
    "refuse_weak_key_wrap",
    "refuse_weak_pkcs12",
    "ssh_key_encrypted",
]

_HMAC_SHA256: Final = "1.2.840.113549.2.9"

#: PBKDF2 PRFs this module accepts, by OID, with the iteration floor ASVS 5.0 Appendix C sets for
#: each. Only the two status-A rows of its password-based KDF table are here. PBKDF2-HMAC-SHA-1 is
#: status L there and a SHA-1-based KDF is D in its general KDF table, so it is refused outright.
PBKDF2_MIN_ITERATIONS: Final[Mapping[str, tuple[str, int]]] = {
    _HMAC_SHA256: ("HMAC-SHA-256", 600_000),
    "1.2.840.113549.2.11": ("HMAC-SHA-512", 210_000),
}

#: scrypt's floor from the same table: ``r`` of 8, and the smallest ``N`` for a given ``p``.
_SCRYPT_MIN_R: Final = 8


def _scrypt_min_n(p: int) -> int:
    if p <= 1:
        return 1 << 17
    if p == 2:
        return 1 << 16
    return 1 << 15


#: The iteration count both ``BestAvailableEncryption`` and the openssl CLI write by default.
_LIBRARY_DEFAULT_ITERATIONS: Final = 2048

#: How to re-wrap a refused key for a loader that takes a passphrase. The openssl CLI is named
#: because ``cryptography`` cannot write a PKCS#8 key with a chosen iteration count: its
#: ``encryption_builder`` serves only OpenSSH and PKCS#12. The same command reads a legacy
#: ``Proc-Type`` PEM as its input. The count is formatted in from the table so the two cannot drift.
_SHA256_FLOOR: Final = PBKDF2_MIN_ITERATIONS[_HMAC_SHA256][1]
_REWRAP: Final = (
    f"Re-wrap the key as PKCS#8 PBES2 with PBKDF2-HMAC-SHA-256 at {_SHA256_FLOOR} iterations or "
    "more, for example: openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256 -iter "
    f"{_SHA256_FLOOR} -in <old key> -out <new key>"
)

#: The same advice for a loader that takes no passphrase, where a re-wrapped key would be refused
#: next for having no passphrase to open it.
_DECRYPT: Final = (
    "This setting takes no passphrase, so supply the key unencrypted and protect the file with its "
    "permissions, for example: openssl pkey -in <old key> -out <new key>"
)

#: Bytes checked before giving up. A PEM key, or a key with its certificate chain, is a few
#: kilobytes; anything past this is refused rather than half inspected.
_MAX_KEY_FILE_BYTES: Final = 1 << 20

#: The largest DER INTEGER, in bytes, this reader accepts. Real counts fit in four; eight leaves
#: room and keeps a crafted value from reaching ``int``-to-text conversion limits.
_MAX_INT_BYTES: Final = 8

_PBES2: Final = "1.2.840.113549.1.5.13"
_PBKDF2: Final = "1.2.840.113549.1.5.12"
_SCRYPT: Final = "1.3.6.1.4.1.11591.4.11"
_HMAC_SHA1: Final = "1.2.840.113549.2.7"
_PBES1: Final = frozenset(f"1.2.840.113549.1.5.{n}" for n in (1, 3, 4, 6, 10, 11))
_PKCS12_PBE: Final = frozenset(f"1.2.840.113549.1.12.1.{n}" for n in range(1, 7))

_ENCRYPTED_LABEL: Final = b"ENCRYPTED PRIVATE KEY"


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
    """Dotted text for an OBJECT IDENTIFIER. Bounded: an arc over nine bytes is refused."""
    if tlv.tag != 0x06 or tlv.end == tlv.start or tlv.end - tlv.start > 64:
        raise _Malformed
    body = buf[tlv.start : tlv.end]
    if body[-1] & 0x80:
        raise _Malformed
    first = body[0]
    top = min(first // 40, 2)
    arcs = [top, first - 40 * top]
    value = 0
    width = 0
    for byte in body[1:]:
        value = (value << 7) | (byte & 0x7F)
        width += 1
        if width > 9:
            raise _Malformed
        if not byte & 0x80:
            arcs.append(value)
            value = 0
            width = 0
    return ".".join(str(a) for a in arcs)


def _uint(buf: bytes, tlv: _Tlv) -> int:
    if tlv.tag != 0x02 or tlv.end == tlv.start or tlv.end - tlv.start > _MAX_INT_BYTES:
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


def _encrypted_pkcs8_algorithm(der: bytes) -> _Tlv | None:
    """The AlgorithmIdentifier of an EncryptedPrivateKeyInfo, or ``None`` when ``der`` is not that
    shape. Only the SHAPE is read here; the algorithm itself is parsed by the caller, so a wrap
    whose shape says encrypted and whose algorithm does not parse is refused rather than passed.

    The shape is ``SEQUENCE { AlgorithmIdentifier, OCTET STRING }``. An unencrypted PKCS#8 or a
    traditional key opens with an INTEGER instead, so it returns ``None``. Bytes after the outer
    SEQUENCE are ignored HERE, on purpose: a lenient loader may ignore them too, so a weak wrap with
    a byte appended must still be seen and refused."""
    outer = _read_tlv(der, 0, len(der))
    if outer.tag != 0x30:
        raise _Malformed
    parts = _children(der, outer)
    if len(parts) != 2 or parts[0].tag != 0x30 or parts[1].tag != 0x04:
        return None
    return parts[0]


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
        why = (
            f" {_LIBRARY_DEFAULT_ITERATIONS} is the default of both the cryptography library's "
            "BestAvailableEncryption and the openssl CLI, so a key written either way lands here"
            if iterations == _LIBRARY_DEFAULT_ITERATIONS
            else ""
        )
        return (
            f"is wrapped with PBKDF2-{name} at {iterations} iterations, under the {floor} floor "
            f"ASVS Appendix C sets for it (ASVS 11.4.4).{why}"
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
    # The shape said encrypted; an algorithm or parameters that do not parse are refused, failing
    # closed.
    problem: str | None = _UNREADABLE
    with contextlib.suppress(_Malformed):
        problem = _wrap_problem(der, *_algorithm(der, found))
    return True, problem


_BEGIN: Final = b"-----BEGIN "
_END: Final = b"-----END "
_DASHES: Final = b"-----"

#: The longest PEM label read. Real ones are under 30 bytes; a longer run is not a label.
_MAX_LABEL: Final = 64


def _pem_blocks(material: bytes) -> list[tuple[bytes, bytes]]:
    """``(label, body)`` for every BEGIN/END pair in ``material``, in one linear pass.

    Markers are found ANYWHERE, not only alone on a line: ``cryptography``'s PEM reader and
    OpenSSL both accept a key that is all on one line, has text before BEGIN, or has base64 on the
    BEGIN or END line, so a checker stricter than the loaders would wave those through unchecked.
    Every search starts where the last one stopped, so a garbled file costs one pass."""
    blocks: list[tuple[bytes, bytes]] = []
    pos = 0
    while True:
        begin = material.find(_BEGIN, pos)
        if begin < 0:
            return blocks
        label_start = begin + len(_BEGIN)
        label_end = material.find(_DASHES, label_start, label_start + _MAX_LABEL + 1)
        if label_end < 0:
            pos = label_start
            continue
        body_start = label_end + len(_DASHES)
        end = material.find(_END, body_start)
        if end < 0:
            return blocks
        blocks.append((material[label_start:label_end].strip(), material[body_start:end]))
        pos = end + len(_END)


def _legacy_encrypted(material: bytes) -> bool:
    """True when ``material`` carries a legacy ``Proc-Type: ...ENCRYPTED`` or ``DEK-Info`` header.

    Searched in the whole text, not per block, and without reading line structure: OpenSSL honours
    the header after a blank line, with bare-CR line endings and in other shapes a line reader
    misses, and a false refusal here costs only a re-wrap."""
    lowered = material.lower()
    if b"dek-info:" in lowered:
        return True
    at = lowered.find(b"proc-type:")
    while at >= 0:
        # A bounded window, cut at the line end, so many headers cannot make this quadratic.
        header = lowered[at : at + 128].split(b"\n", 1)[0]
        if b"encrypted" in header:
            return True
        at = lowered.find(b"proc-type:", at + 1)
    return False


def _inspect(material: bytes) -> tuple[bool, str | None]:
    """``(encrypted, problem)`` over every private key in ``material``, PEM or DER.

    Refuses on the FIRST weak wrap. ``encrypted`` is true when any key in it is encrypted."""
    if _legacy_encrypted(material):
        return True, (
            "uses legacy OpenSSL PEM encryption (a Proc-Type: 4,ENCRYPTED header), whose key "
            "is derived with MD5 at one iteration (ASVS 11.4.1, 11.4.4)"
        )
    blocks = _pem_blocks(material)
    if not blocks:
        # No complete PEM block, which includes DER that happens to contain a BEGIN marker.
        return _der_problem(material, known_encrypted=False)
    encrypted = False
    for label, body in blocks:
        known = label == _ENCRYPTED_LABEL
        if not known and not label.endswith(b"PRIVATE KEY"):
            continue  # a certificate or other non-key block
        der = b""
        try:
            der = base64.b64decode(b"".join(body.split()), validate=True)
        except (binascii.Error, ValueError):
            if known:
                return True, _UNREADABLE
            continue  # not base64: the loader rejects it itself
        # Every key block is read for the EncryptedPrivateKeyInfo shape, whatever its label:
        # OpenSSL decrypts that shape under a plain PRIVATE KEY label too.
        block_encrypted, problem = _der_problem(der, known_encrypted=known)
        encrypted = encrypted or block_encrypted
        if problem is not None:
            return True, problem
    return encrypted, None


def _too_large(material: bytes) -> bool:
    return len(material) > _MAX_KEY_FILE_BYTES


# --- PKCS#12 ------------------------------------------------------------------------------------

_PKCS7_DATA: Final = "1.2.840.113549.1.7.1"
_PKCS7_ENCRYPTED_DATA: Final = "1.2.840.113549.1.7.6"
_SHROUDED_KEY_BAG: Final = "1.2.840.113549.1.12.10.1.2"
_SAFE_CONTENTS_BAG: Final = "1.2.840.113549.1.12.10.1.6"
_PBMAC1: Final = "1.2.840.113549.1.5.14"
_MD5: Final = "1.2.840.113549.2.5"
_SHA1: Final = "1.3.14.3.2.26"

#: HMAC schemes a PBMAC1 MAC may use: SHA-2 at 256 bits and up.
_PBMAC1_SCHEMES: Final = frozenset(
    {"1.2.840.113549.2.9", "1.2.840.113549.2.10", "1.2.840.113549.2.11"}
)

#: How deep a SafeContentsBag may nest. Real bundles do not nest at all.
_MAX_BAG_DEPTH: Final = 4

#: How to re-export a refused bundle. PBMAC1 needs OpenSSL 3.4 or later; the second route avoids
#: PKCS#12 altogether. The count is formatted in from the table so the two cannot drift.
_REEXPORT: Final = (
    "Re-export it with OpenSSL 3.4 or later: openssl pkcs12 -export -keypbe AES-256-CBC "
    f"-certpbe AES-256-CBC -iter {_SHA256_FLOOR} -pbmac1_pbkdf2 -pbmac1_pbkdf2_md sha256 "
    "-in <cert> -inkey <key> -out <new pfx>. Or skip PKCS#12: give the certificate and an "
    "unencrypted or approved-wrap PKCS#8 key as PEM files"
)


def _mac_problem(buf: bytes, mac_data: _Tlv) -> str | None:
    """Why a PKCS#12 MacData is refused, or ``None`` for an approved PBMAC1 one.

    Only PBMAC1 (RFC 9579) derives the MAC key with PBKDF2. Every other MacData keys the MAC with
    the PKCS#12 KDF, which ASVS Appendix C does not list, so a password guess can be tested against
    it cheaply whatever the bags use. That is refused over SHA-256 as well as over MD5 and SHA-1."""
    if mac_data.tag != 0x30:
        raise _Malformed
    parts = _children(buf, mac_data)
    if not parts or parts[0].tag != 0x30:
        raise _Malformed
    digest_info = _children(buf, parts[0])
    if len(digest_info) != 2:
        raise _Malformed
    algorithm, params = _algorithm(buf, digest_info[0])
    if algorithm in (_MD5, _SHA1):
        name = "MD5" if algorithm == _MD5 else "SHA-1"
        return (
            f"is integrity-protected by a MAC over {name}, keyed by the PKCS#12 KDF; neither is "
            "approved (ASVS 11.4.1, 11.4.4)"
        )
    if algorithm != _PBMAC1:
        return (
            "is integrity-protected by a MAC keyed by the PKCS#12 KDF rather than PBMAC1; that "
            "derivation is not in ASVS Appendix C, and it lets a password be guessed cheaply"
        )
    if params is None or params.tag != 0x30:
        raise _Malformed
    pbmac1 = _children(buf, params)
    if len(pbmac1) != 2:
        raise _Malformed
    kdf, kdf_params = _algorithm(buf, pbmac1[0])
    scheme, _ = _algorithm(buf, pbmac1[1])
    if kdf != _PBKDF2:
        return (
            "is integrity-protected by PBMAC1 over a key derivation this engine does not recognise"
        )
    problem = _pbkdf2_problem(buf, kdf_params)
    if problem is not None:
        return problem.replace("is wrapped with", "has a PBMAC1 MAC keyed by", 1)
    if scheme not in _PBMAC1_SCHEMES:
        return "has a PBMAC1 MAC over a hash that is not approved (HMAC-SHA-256 or stronger)"
    return None


def _content_info(buf: bytes, tlv: _Tlv) -> tuple[str, _Tlv]:
    """A ContentInfo's type and the single value inside its ``[0]`` EXPLICIT wrapper."""
    if tlv.tag != 0x30:
        raise _Malformed
    parts = _children(buf, tlv)
    if len(parts) != 2 or parts[1].tag != 0xA0:
        raise _Malformed
    inner = _children(buf, parts[1])
    if len(inner) != 1:
        raise _Malformed
    return _oid(buf, parts[0]), inner[0]


def _octet_body(buf: bytes, tlv: _Tlv) -> _Tlv:
    """The SEQUENCE a DER OCTET STRING holds, as a TLV over the same buffer."""
    if tlv.tag != 0x04:
        raise _Malformed
    inner = _read_tlv(buf, tlv.start, tlv.end)
    if inner.end != tlv.end:
        raise _Malformed
    return inner


def _bags_problem(buf: bytes, safe_contents: _Tlv, depth: int) -> tuple[bool, str | None]:
    """``(encrypted, problem)`` over the bags of one SafeContents."""
    if safe_contents.tag != 0x30 or depth > _MAX_BAG_DEPTH:
        raise _Malformed
    encrypted = False
    for bag in _children(buf, safe_contents):
        parts = _children(buf, bag)
        if len(parts) < 2 or parts[1].tag != 0xA0:
            raise _Malformed
        bag_id = _oid(buf, parts[0])
        value = _children(buf, parts[1])
        if len(value) != 1:
            raise _Malformed
        if bag_id == _SHROUDED_KEY_BAG:
            encrypted = True
            epki = _children(buf, value[0])
            if len(epki) != 2 or epki[1].tag != 0x04:
                raise _Malformed
            problem = _wrap_problem(buf, *_algorithm(buf, epki[0]))
            if problem is not None:
                return True, f"holds a private key that {problem}"
        elif bag_id == _SAFE_CONTENTS_BAG:
            inner_encrypted, problem = _bags_problem(buf, value[0], depth + 1)
            encrypted = encrypted or inner_encrypted
            if problem is not None:
                return True, problem
    return encrypted, None


def _pfx_problem(der: bytes) -> tuple[bool, str | None]:
    """``(needs_passphrase, problem)`` for a PKCS#12 bundle: every bag and encrypted part, then its
    MAC. A bundle needs a passphrase when anything in it is encrypted or it carries a MAC.

    The bundle must be DER this reader can walk. ``cryptography`` falls back to BER, so a BER
    bundle loads there; here it is refused as unreadable rather than passed unchecked."""
    outer = _read_tlv(der, 0, len(der))
    if outer.tag != 0x30:
        raise _Malformed
    parts = _children(der, outer)
    if len(parts) not in (2, 3) or parts[0].tag != 0x02:
        raise _Malformed
    content_type, content = _content_info(der, parts[1])
    if content_type != _PKCS7_DATA:
        return True, "is a PKCS#12 bundle protected in a way this engine does not recognise"
    encrypted = False
    for info in _children(der, _octet_body(der, content)):
        info_type, info_value = _content_info(der, info)
        if info_type == _PKCS7_DATA:
            bags_encrypted, problem = _bags_problem(der, _octet_body(der, info_value), 0)
            encrypted = encrypted or bags_encrypted
        elif info_type == _PKCS7_ENCRYPTED_DATA:
            encrypted = True
            encrypted_data = _children(der, info_value)
            if len(encrypted_data) != 2:
                raise _Malformed
            content_info = _children(der, encrypted_data[1])
            if len(content_info) < 2:
                raise _Malformed
            problem = _wrap_problem(der, *_algorithm(der, content_info[1]))
            if problem is not None:
                problem = f"has an encrypted part that {problem}"
        else:
            return True, "holds a PKCS#12 part this engine does not recognise"
        if problem is not None:
            return True, problem
    # A MAC is judged whether or not any bag is encrypted (BACKLOG #1352). To verify it, the loader
    # derives a key from the passphrase and runs the MAC's hash. A PKCS#12-KDF MAC therefore runs a
    # derivation Appendix C does not list, and an MD5 or SHA-1 one runs a disallowed hash. That is
    # true even when the passphrase is empty, so the rule does not ask what the passphrase is.
    # A clear bundle with NO MAC passes. Nothing in it derives a key from a password, just as with
    # an unencrypted PEM key. An encrypted bundle without a MAC is refused.
    if len(parts) == 3:
        problem = _mac_problem(der, parts[2])
        if problem is not None and not encrypted:
            problem = problem.rstrip(".") + (
                ". The MAC rule applies even though no bag is encrypted. Such a bundle passes with "
                "a PBMAC1 MAC at the floor, or with no MAC (openssl pkcs12 -export -keypbe NONE "
                "-certpbe NONE -nomac)"
            )
        # A MAC is keyed by the passphrase, so a bundle that carries one needs it, like an
        # encrypted one does.
        return True, problem
    if encrypted:
        return True, "carries no MAC; an encrypted bundle needs a PBMAC1 MAC"
    return False, None


def pkcs12_wrap_refusal(
    pfx: bytes,
    *,
    setting: str,
    unlock_setting: str,
    passphrase_given: bool,
) -> str | None:
    """The refusal text for a PKCS#12 bundle, or ``None`` when it may be decrypted.

    Refused: a MAC over MD5 or SHA-1, any MAC keyed by the PKCS#12 KDF rather than PBMAC1, a PBMAC1
    or PBES2 derivation under the Appendix C floor, the SHA-1 PKCS#12 PBE and PBES1 bag schemes,
    anything this reader cannot walk, an encrypted bundle with no MAC, and an encrypted bundle with
    no passphrase. The MAC rules apply over clear bags too (BACKLOG #1352), and a bundle that
    carries a MAC needs a passphrase like an encrypted one. A clear bundle with no MAC passes with
    or without one. Same rules for the message as :func:`key_wrap_refusal`: the setting and the
    reason, never the bundle's bytes."""
    if _too_large(pfx):
        return (
            f"{setting}: the bundle is over {_MAX_KEY_FILE_BYTES} bytes, too large to check its "
            "wrap; a certificate bundle is a few kilobytes, so check the path"
        )
    problem: str | None = "is a PKCS#12 bundle this engine cannot read to check its wrap"
    needs_passphrase = True
    with contextlib.suppress(_Malformed):
        needs_passphrase, problem = _pfx_problem(pfx)
    if problem is not None:
        return f"{setting}: the bundle {problem}. It is refused. {_REEXPORT}"
    if needs_passphrase and not passphrase_given:
        return (
            f"{setting}: the bundle is encrypted or carries a MAC, and no passphrase is configured "
            f"for it. It is refused before any library can try to open it. Set {unlock_setting}"
        )
    return None


def refuse_weak_pkcs12(
    pfx: bytes,
    *,
    setting: str,
    unlock_setting: str,
    passphrase_given: bool,
) -> None:
    """Raise :class:`KeyWrapRefused` when :func:`pkcs12_wrap_refusal` refuses ``pfx``."""
    reason = pkcs12_wrap_refusal(
        pfx, setting=setting, unlock_setting=unlock_setting, passphrase_given=passphrase_given
    )
    if reason is not None:
        raise KeyWrapRefused(reason)


# --- SSH keys -----------------------------------------------------------------------------------

_OPENSSH_MAGIC: Final = b"openssh-key-v1\x00"


def ssh_key_encrypted(material: bytes) -> bool:
    """True when an SSH private key is passphrase-protected, legacy PEM or OpenSSH format.

    Neither format can reach an approved derivation: legacy PEM derives with MD5, and OpenSSH
    format with bcrypt_pbkdf, which ASVS Appendix C lists only for password storage. An OpenSSH
    key that cannot be read is treated as encrypted, so it is refused rather than passed."""
    if _legacy_encrypted(material):
        return True
    for label, body in _pem_blocks(material):
        if label != b"OPENSSH PRIVATE KEY":
            continue
        raw = b""
        try:
            raw = base64.b64decode(b"".join(body.split()), validate=True)
        except (binascii.Error, ValueError):
            return True
        if not raw.startswith(_OPENSSH_MAGIC):
            return True
        pos = len(_OPENSSH_MAGIC)
        length = int.from_bytes(raw[pos : pos + 4], "big")
        cipher = raw[pos + 4 : pos + 4 + length]
        if cipher != b"none":
            return True
    return False


def key_wrap_refusal(
    material: bytes,
    *,
    setting: str,
    unlock_setting: str | None,
    passphrase_given: bool,
) -> str | None:
    """The refusal text for ``material``, or ``None`` when every key in it may be loaded.

    ``setting`` names where the key came from, for the message. ``unlock_setting`` names what
    carries its passphrase, in the words an operator would use to set it, or is ``None`` for a
    loader that takes no passphrase at all. ``passphrase_given`` says whether the loader is about to
    pass one. The text holds no key bytes, passphrase or path, so a caller may raise it as its own
    error type."""
    if _too_large(material):
        return (
            f"{setting}: the key file is over {_MAX_KEY_FILE_BYTES} bytes, too large to check its "
            "wrap; a private key and its chain are a few kilobytes, so check the path"
        )
    encrypted, problem = _inspect(material)
    if problem is not None:
        fix = _DECRYPT if unlock_setting is None else _REWRAP
        return f"{setting}: the private key {problem}. It is refused. {fix}"
    if encrypted and not passphrase_given:
        fix = _DECRYPT if unlock_setting is None else f"Set {unlock_setting}"
        return (
            f"{setting}: the private key is encrypted and no passphrase is configured for it. It "
            f"is refused before any library can try to open it. {fix}"
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

    A path that does not exist is left to the loader, which fails on it with its own error, so a
    missing file reads exactly as it did before this check. Any other read failure is refused:
    a file this check cannot read, but a moment later the loader can, is the one thing it exists to
    stop."""
    material = b""
    reason = ""
    try:
        with open(path, "rb") as handle:
            material = handle.read(_MAX_KEY_FILE_BYTES + 1)
    except (FileNotFoundError, ValueError):
        return  # no such file, or a NUL in the path: the loader cannot open it either
    except OSError as exc:
        reason = exc.strerror or type(exc).__name__
    if reason:
        raise KeyWrapRefused(
            f"{setting}: the key file could not be read to check its wrap: {reason}"
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
    file checked then."""
    refuse_weak_key_file(
        keyfile if keyfile else certfile,
        setting=key_setting if keyfile else cert_setting,
        unlock_setting=unlock_setting,
        passphrase_given=passphrase_given,
    )


def _no_passphrase() -> bytes:
    """The password callback for a key given no passphrase: an empty one, never a terminal prompt."""
    return b""


def load_checked_cert_chain(
    ctx: ssl.SSLContext,
    certfile: str | os.PathLike[str],
    keyfile: str | os.PathLike[str] | None,
    password: str | bytes | None,
    *,
    cert_setting: str,
    key_setting: str,
    unlock_setting: str | None,
) -> None:
    """Check the key's wrap, then ``ctx.load_cert_chain`` it. The one way a site loads a TLS key.

    The check and the load are one call, so a site cannot keep one and drop the other. OpenSSL
    reads the file a second time, and a file swapped between the two reads is not caught by the
    check; the empty-passphrase callback passed for ``password=None`` is what keeps a swapped-in
    encrypted key off a terminal prompt then."""
    refuse_weak_cert_chain_key(
        certfile,
        keyfile,
        cert_setting=cert_setting,
        key_setting=key_setting,
        unlock_setting=unlock_setting,
        passphrase_given=password is not None,
    )
    ctx.load_cert_chain(certfile, keyfile, password if password is not None else _no_passphrase)


def load_connection_cert_chain(
    ctx: ssl.SSLContext,
    certfile: object,
    keyfile: object,
    password: object,
) -> None:
    """:func:`load_checked_cert_chain` for a connection's ``tls_cert_file`` / ``tls_key_file`` /
    ``tls_key_password`` settings, which MLLP, the HTTP listener, DICOM and FTPS share."""
    load_checked_cert_chain(
        ctx,
        str(certfile),
        str(keyfile) if keyfile else None,
        password if password is None or isinstance(password, (str, bytes)) else str(password),
        cert_setting="tls_cert_file",
        key_setting="tls_key_file",
        unlock_setting="tls_key_password (through env())",
    )
