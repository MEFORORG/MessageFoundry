# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""PKI helpers (BACKLOG #71/#72): PKCS#12 import, read-only cert inventory, self-signed placeholders.

The single first-party home for the ``cryptography`` PKI primitives the ``cert`` CLI group relies on —
so *all* of that command's crypto lives in one inventoried module (ASVS 11.1.3), and neither
``__main__.py`` nor ``pipeline/cert_expiry.py`` has to import ``cryptography`` directly. It reads only
**public** certificate facts (subject/issuer/notAfter/SAN/days); on import it deserializes a private key
in order to re-serialize it to PEM, but it **never** logs, prints, or embeds key or passphrase material
in a return value or an exception — the caller writes the key PEM with tight permissions.

Pure and side-effect-free (no engine state, I/O, or DB): it takes/returns bytes and small dataclasses so
``pipeline/cert_expiry.py`` can share its single load/notAfter/days path via :func:`read_cert_facts`.
"""

from __future__ import annotations

import datetime
import ipaddress
import os
import string
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Literal

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.utils import CryptographyDeprecationWarning
from cryptography.x509.oid import NameOID

from messagefoundry.keywrap import (
    DerTlv,
    MalformedDer,
    Pkcs12EncryptedPart,
    der_children,
    pkcs12_encrypted_parts,
    read_der_tlv,
    refuse_weak_pkcs12,
    refuse_weak_pkcs12_contents,
)

__all__ = [
    "CertFacts",
    "CrlBlock",
    "CrlFacts",
    "CrlIssuerKey",
    "CrlSignature",
    "CrlSignatureFinding",
    "PROVEN_BAD_SIGNATURE",
    "UNCONFIRMED_SIGNATURE",
    "UNLISTED_SIGNATURE",
    "crl_signature_finding",
    "judge_crl_signatures",
    "judge_every_crl",
    "quoted_issuer",
    "read_crl_facts",
    "read_soonest_crl_facts",
    "crl_pem_blocks",
    "soonest_crl",
    "ca_chain_to_pem",
    "cert_to_pem",
    "key_to_pem",
    "load_pinned_server_certificate",
    "PIN_FILE_MAX_BYTES",
    "PinRefused",
    "oversized_pin_reason",
    "pinned_server_certificate",
    "read_pinned_server_certificate",
    "unreadable_pin_reason",
    "load_pkcs12",
    "make_self_signed",
    "read_cert_facts",
    "read_self_signed_facts",
    "SelfSignedFacts",
    "canonical_dn",
    "IssuerIndex",
]

# Day math shared with pipeline/cert_expiry.py's expiry monitor — keep the convention identical.
_SECONDS_PER_DAY = 86_400


@dataclass(frozen=True)
class CertFacts:
    """Read-only public facts about one certificate (never any private material).

    ``days_remaining`` is negative once the cert is expired (``expired`` is exactly ``days_remaining <
    0``, the same convention as :class:`~messagefoundry.pipeline.cert_expiry.CertCheck`); ``sans`` is the
    list of DNS names **and IP addresses** in the SubjectAlternativeName, in certificate order (empty
    when the cert carries none)."""

    subject: str
    issuer: str
    not_after_iso: str
    sans: list[str]
    days_remaining: int
    expired: bool


def load_pkcs12(
    pfx_bytes: bytes, password: bytes | None
) -> tuple[PrivateKeyTypes | None, x509.Certificate | None, list[x509.Certificate]]:
    """Parse a PKCS#12/.pfx bundle into ``(private_key, leaf_cert, additional_cas)``.

    Thin wrapper over ``cryptography``'s loader. ``password`` is the bundle passphrase (``None`` for an
    unencrypted bundle with no MAC, ``b""`` for an empty passphrase, BACKLOG #2456); it is
    used only to decrypt here and is never logged or returned. A wrong
    password / malformed bundle raises ``ValueError`` from ``cryptography`` — the CLI scrubs that so the
    passphrase can never leak into stderr/logs.

    Before anything decrypts it, the bundle's MAC and bag encryption are checked (BACKLOG #1352,
    #1171): a weak or unreadable wrap, a MAC that is not PBMAC1 at the floor even over unencrypted
    bags, or a bundle that is encrypted or carries a MAC with no passphrase, raises
    :class:`~messagefoundry.keywrap.KeyWrapRefused`, whose text is safe to show.

    Then each encrypted part is opened here and the key bags inside it get the same check, before
    ``cryptography`` decrypts any key (BACKLOG #1352; why the part is opened rather than refused is
    recorded beside :func:`~messagefoundry.keywrap.pkcs12_encrypted_parts`). A wrong passphrase
    usually fails that decryption with a ``ValueError``, as it would in ``cryptography``; about
    once in 256 tries it leaves valid padding, and the refusal then tells the operator to check
    ``MEFOR_PFX_PASSWORD``."""
    setting, unlock_setting = "the --pfx bundle", "MEFOR_PFX_PASSWORD"
    refuse_weak_pkcs12(
        pfx_bytes,
        setting=setting,
        unlock_setting=unlock_setting,
        passphrase_given=password is not None,
    )
    # With no passphrase the check above has already refused any bundle with an encrypted part.
    if password is not None:
        for part in pkcs12_encrypted_parts(pfx_bytes, setting=setting):
            refuse_weak_pkcs12_contents(
                _decrypt_part(part, password), setting=setting, unlock_setting=unlock_setting
            )
    key, cert, cas = pkcs12.load_key_and_certificates(pfx_bytes, password)
    return key, cert, list(cas)


#: The PBKDF2 PRFs a PKCS#12 part may use, by OID. ``keywrap`` hands over only the ones its floor
#: table approves; a test pins this map to that table's keys.
_PART_PRF: dict[str, type[hashes.SHA256] | type[hashes.SHA512]] = {
    "1.2.840.113549.2.9": hashes.SHA256,  # hmacWithSHA256
    "1.2.840.113549.2.11": hashes.SHA512,  # hmacWithSHA512
}


def _decrypt_part(part: Pkcs12EncryptedPart, password: bytes) -> bytes:
    """The SafeContents inside one PBES2 AES-CBC part. PBES2 inside PKCS#12 is keyed by the
    passphrase's own bytes, not the BMPString the PKCS#12 KDF uses. Raises ``ValueError`` when the
    ciphertext or its padding is wrong, which is what a wrong passphrase usually gives."""
    derived = PBKDF2HMAC(
        algorithm=_PART_PRF[part.prf](),
        length=part.key_length,
        salt=part.salt,
        iterations=part.iterations,
    ).derive(password)
    decryptor = Cipher(algorithms.AES(derived), modes.CBC(part.iv)).decryptor()
    padded = decryptor.update(part.ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def cert_to_pem(cert: x509.Certificate) -> bytes:
    """Serialize a certificate to PEM (public material — safe to write world-readable)."""
    return cert.public_bytes(serialization.Encoding.PEM)


def ca_chain_to_pem(cas: list[x509.Certificate]) -> bytes:
    """Concatenate CA certificates into a single PEM chain (public material)."""
    return b"".join(c.public_bytes(serialization.Encoding.PEM) for c in cas)


def key_to_pem(key: PrivateKeyTypes) -> bytes:
    """Serialize a private key to **unencrypted** PKCS#8 PEM.

    Secret material — the caller MUST persist the result through
    ``restricted_file.write_restricted_file`` (the CLI's ``_write_private_key``), never log it, and
    never place it in an exception."""
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


@dataclass(frozen=True)
class CrlFacts:
    """Read-only public facts about one certificate revocation list (BACKLOG #1005).

    The revocation sibling of :class:`CertFacts`, and it keeps that class's conventions exactly:
    ``days_remaining`` is negative once the CRL is past ``nextUpdate``, and ``expired`` is precisely
    ``days_remaining < 0``. Same ``86_400`` s/day arithmetic as the expiry monitor.

    **Why a CRL's expiry is an AVAILABILITY fact and not a security one.** Past ``nextUpdate``
    OpenSSL refuses EVERY client presenting a certificate under that issuer, not merely revoked
    ones -- measured on CPython 3.14.6 / OpenSSL 3.5.7, verify error 12 ``CRL has expired``. So a
    CRL nobody refreshed converts a PKI housekeeping lapse into a total interface outage whose
    first symptom is every partner dropping at once. That is why this is read at construction and
    alarmed on before expiry, rather than discovered at a partner handshake."""

    issuer: str
    next_update_iso: str
    days_remaining: int

    @property
    def expired(self) -> bool:
        return self.days_remaining < 0

    def at(self, now: float) -> CrlFacts:
        """These facts with ``days_remaining`` evaluated at ``now`` instead of when they were read.

        For a CRL a live TLS context loaded earlier (BACKLOG #299): its ``nextUpdate`` is fixed, but
        the days left to it are not."""
        nxt = datetime.datetime.fromisoformat(self.next_update_iso)
        return CrlFacts(self.issuer, self.next_update_iso, _days_until(nxt, now))


def _days_until(when: datetime.datetime, now: float) -> int:
    """Whole days from ``now`` to ``when``, negative once past; certificates and CRLs share it."""
    return int((when.timestamp() - now) // _SECONDS_PER_DAY)


def read_crl_facts(pem: bytes, *, now: float) -> CrlFacts:
    """Parse a PEM CRL into its public inventory facts, evaluated at ``now`` (epoch seconds).

    Tolerates certificate blocks in the same file: the FIRST ``X509 CRL`` block is read and any
    certificate blocks are skipped. So this judges one CRL, never a whole file: a file-level caller
    wants :func:`judge_every_crl` or :func:`read_soonest_crl_facts`. ``harden_crl_check`` is
    stricter again, and refuses a file whose certificates the hop does not already trust (BACKLOG
    #1890).

    Raises ``ValueError`` when the bytes carry no CRL at all -- a configured-but-CRL-less file must
    never degrade to "revocation checking silently off"."""
    crl, nxt = _parse_first_crl(pem)
    return _crl_facts(crl, nxt, now)


def _parse_first_crl(
    pem: bytes,
) -> tuple[x509.CertificateRevocationList, datetime.datetime]:
    """The first ``X509 CRL`` block of ``pem`` that OpenSSL would load (:func:`_crl_blocks`),
    parsed, with its ``nextUpdate``."""
    block = next(_crl_blocks(pem), None)
    if block is None:
        raise ValueError(_NO_CRL)
    if _CRL_END not in block:
        raise ValueError("truncated CRL: an 'X509 CRL' block opened but never closed")
    crl = x509.load_pem_x509_crl(block)
    nxt = crl.next_update_utc
    if nxt is None:
        # RFC 5280 makes nextUpdate optional, but OpenSSL treats a CRL without one as never
        # expiring, which would silence the freshness control entirely. Refuse rather than
        # inherit an unbounded lifetime.
        raise ValueError("the CRL carries no nextUpdate, so its freshness cannot be checked")
    return crl, nxt


def _crl_facts(crl: x509.CertificateRevocationList, nxt: datetime.datetime, now: float) -> CrlFacts:
    return CrlFacts(
        issuer=crl.issuer.rfc4514_string(),
        next_update_iso=nxt.isoformat(),
        days_remaining=_days_until(nxt, now),
    )


def read_soonest_crl_facts(pem: bytes, *, now: float) -> CrlFacts:
    """The facts of the CRL in ``pem`` whose ``nextUpdate`` comes SOONEST (BACKLOG #299).

    A CRL file may hold one CRL per issuer -- ``[tls].crl_file`` is documented that way -- and
    OpenSSL loads every one of them. So the file fails a handshake as soon as ANY of its CRLs
    lapses, and a freshness check that read only the first block would stay silent while a later
    issuer's CRL had already expired. This reads every ``X509 CRL`` block OpenSSL would load
    (:func:`_crl_blocks`) and returns the one that expires first.

    Each block is judged on its own by :func:`read_crl_facts`. A block that cannot be judged (no
    ``nextUpdate``, or unparseable) is skipped, so one such block cannot hide a sibling that is about
    to lapse. Only when NO block can be judged does this raise, with the first block's
    ``ValueError`` -- the same error :func:`read_crl_facts` gives for that file."""
    found: list[CrlFacts] = []
    first_error: ValueError | None = None
    for block in _crl_blocks(pem):
        try:
            found.append(read_crl_facts(block, now=now))
        except ValueError as exc:
            first_error = first_error or exc
    if found:
        return soonest_crl(found)
    if first_error is not None:
        raise first_error
    raise ValueError(_NO_CRL)


@dataclass(frozen=True)
class CrlBlock:
    """One CRL in a file, in the terms OpenSSL uses to choose between CRLs (BACKLOG #299).

    A running context can only gain CRLs. For one issuer, OpenSSL first scores each CRL it holds,
    and a CRL scores lower when it is out of time, when its scope (the Issuing Distribution Point)
    or its Authority Key Identifier does not fit, or when it carries a critical extension OpenSSL
    does not handle. Among equal scores it takes the latest ``thisUpdate``. So ``selection`` holds
    the scope, the key identifier and the critical extension OIDs, and two CRLs score alike only when
    those match. ``fingerprint`` is the SHA-256 of the CRL's DER, so an unchanged CRL is recognised
    however its PEM is wrapped.

    ``issuer`` is the name as text, for a message. ``issuer_key`` is the name as
    :func:`_crl_issuer_key` gives it, and every grouping by issuer uses it, never the text (vault
    BACKLOG #3755). It has no default, so no block can group by a key nobody computed."""

    issuer: str
    issuer_key: CrlIssuerKey
    this_update: datetime.datetime
    next_update: datetime.datetime
    fingerprint: bytes
    selection: tuple[bytes | None, bytes | None, frozenset[str]] = (None, None, frozenset())


def judge_every_crl(
    pem: bytes, *, now: float, refuse_unread_extensions: bool = False
) -> list[tuple[CrlFacts, CrlBlock]]:
    """The facts and the :class:`CrlBlock` of EVERY CRL in ``pem``, in file order, refusing any block
    it cannot judge. One parse per block.

    **Extensions ``cryptography`` cannot read raise as it raised them, unless
    ``refuse_unread_extensions``** (:data:`_UNREAD_EXTENSIONS`; vault BACKLOG #3506). With it, such
    a block refuses by name, as a ``ValueError``, like any other block that cannot be judged. A
    start and the running-hop reload pass it. The expiry scan's check of a CRL in a CA file does
    not, so what it reports for such a CRL is what it reported before #3506: a hold on engine PR
    2566 (vault row #4532) found that that check reported it, by the ``ValueError``, as one to
    replace before a restart, a report it had not made before. ``docs/CONFIGURATION.md``, under
    ``[cert_monitor]``, says what it reports.

    The strict sibling of :func:`read_soonest_crl_facts`, for a context load (``harden_crl_check``)
    and the running-hop reload (BACKLOG #299). The monitor skips a block it cannot judge so one bad
    block cannot hide a sibling that is about to lapse. A context load must not skip it: OpenSSL
    loads that block too, and a CRL with no ``nextUpdate`` is one OpenSSL treats as never expiring.
    So here any such block raises, naming its position, and a file with no CRL raises as
    :func:`read_crl_facts` does. So does a BEGIN marker :func:`_crl_blocks` does not count. That is
    a model of OpenSSL, not a proof, so a load still counts what OpenSSL took
    (:func:`messagefoundry.config.tls_policy.crl_scratch_context`).

    **A delta CRL refuses too.** The engine turns on no extended or delta CRL support, so OpenSSL
    loses a revocation from a base-plus-delta file whichever delta rule it has. The rule changed
    upstream in openssl/openssl PR 31044, "Reject delta CRLs as complete CRL candidates", released
    in at least 3.0.22, 3.4.7, 3.5.8, 3.6.4 and 4.0.2. Before it, OpenSSL uses a newer delta as if
    it were complete, so revocations only the base CRL lists are dropped. After it, OpenSSL sets
    the delta aside, so revocations only the delta lists are dropped. Give the setting base CRLs
    only."""
    blocks = list(_crl_blocks(pem))
    # Refused, never skipped, even when the uncounted marker is only text in a comment line and
    # OpenSSL loads the file (vault BACKLOG #2866, decided 2026-10-12). Two reasons. The engine
    # cannot tell a comment from a CRL the operator meant to load: skipped, a CRL typed after a
    # space would be reported as applied while the hop still checks the old one. And
    # :func:`_crl_blocks` is a model with a measured miss, which its docstring records, so an
    # uncounted marker may be a CRL OpenSSL loads unjudged. A load counts what OpenSSL took, and
    # that count is the backstop; this check does not lean on it.
    if len(blocks) != pem.count(_CRL_BEGIN):
        raise ValueError(
            "it has a '-----BEGIN X509 CRL-----' marker that does not start a line. If that is a "
            "CRL, OpenSSL can skip it as written. If it is text in a comment, the engine "
            "cannot tell it from a CRL the file is meant to hold. Either one refuses the file. "
            "Put each CRL's marker first on its line, after a line feed: no space, tab or other "
            "text before it, and no line that ends in a carriage return alone. Take the marker "
            "text out of any comment"
        )
    if not blocks:
        raise ValueError(_NO_CRL)
    judged: list[tuple[CrlFacts, CrlBlock]] = []
    for index, block in enumerate(blocks, start=1):
        where = f"CRL block {index} of {len(blocks)}"
        try:
            crl, nxt = _parse_first_crl(block)
            try:
                extensions = _crl_extensions(crl)
            except _UNREAD_EXTENSIONS as exc:
                if not refuse_unread_extensions:
                    raise
                raise ValueError(
                    f"its extensions do not read ({type(exc).__name__}: {exc})"
                ) from exc
            if _is_delta_crl(extensions):
                raise ValueError(
                    "it is a delta CRL, and the engine turns on no delta CRL support, so OpenSSL "
                    "loses revocations under either delta rule. Before openssl/openssl PR 31044 it "
                    "can read a newer delta as a complete CRL and lose the base CRL's revocations. "
                    "From that fix on it rejects a delta as a complete CRL and loses the delta's "
                    "revocations. Give base CRLs only"
                )
            judged.append(
                (
                    _crl_facts(crl, nxt, now),
                    CrlBlock(
                        issuer=crl.issuer.rfc4514_string(),
                        issuer_key=_crl_issuer_key(crl.issuer),
                        this_update=crl.last_update_utc,
                        next_update=nxt,
                        fingerprint=crl.fingerprint(hashes.SHA256()),
                        selection=_selection(extensions),
                    ),
                )
            )
        except ValueError as exc:
            raise ValueError(f"{where} cannot be judged: {exc}") from exc
    return judged


def _selection(
    read: _CrlExtensions,
) -> tuple[bytes | None, bytes | None, frozenset[str]]:
    """What OpenSSL scores a CRL on besides time and issuer; :class:`CrlBlock` says why."""
    scope: bytes | None = None
    critical: set[str] = set()
    for ext in read.extensions:
        if ext.critical:
            critical.add(ext.oid.dotted_string)
        if isinstance(ext.value, x509.IssuingDistributionPoint):
            scope = ext.value.public_bytes()
    # The whole AKID: OpenSSL matches its issuer and serial to the CA too, when present. Its
    # bytes as the CRL carries them, since ``read.extensions`` can hold a rewritten serial.
    key_id = None if read.akid is None else read.akid.der
    return scope, key_id, frozenset(critical)


#: What a hop's CA list says about one CRL's signature. :class:`CrlSignature` gives each meaning.
CrlSignatureState = Literal["verified", "bad", "uncheckable", "unproven", "unlisted"]


@dataclass(frozen=True)
class CrlSignature:
    """What a hop's CA list says about the signature of one CRL in a file (vault BACKLOG #2905).

    ``where`` names the block and its issuer, for a message. ``state`` is one of five. A CA "fits"
    when its subject is the CRL's issuer name by :func:`_issuer_name_key` and it fits the CRL's
    Authority Key Identifier (:func:`_akid_fit`). That name test folds the case of ASCII letters,
    as OpenSSL's name comparison does, and is exact otherwise (vault BACKLOG #3543). Before it
    folded case, a listed CA whose name differed from the issuer's only in ASCII letter case read
    ``unlisted`` here, while OpenSSL took it for the issuer and judged peers by the CRL. Measured
    2026-10-13 on CPython 3.14.6 with OpenSSL 3.5.7: such a CRL, badly signed and naming that CA's
    key, started with the warning and then failed its handshake with ``CRL signature failure``.
    OpenSSL's comparison is looser than this one in at least one more way, which
    :func:`_issuer_name_key` names, so every text that describes ``unlisted`` must stay true of
    a CA OpenSSL takes for the issuer and this test does not.

    * ``verified``: a CA that fits verifies the CRL.
    * ``bad``: **proven** badly signed. The CRL's key identifier equals a fitting CA's Subject Key
      Identifier, and every fitting CA's key was checked and does not verify the CRL. The CRL names
      that key, and that key did not sign it.
    * ``uncheckable``: some fitting CA could not be checked, and none verifies. "Cannot check" is
      not "does not verify" (:func:`_verifies`).
    * ``unproven``: every fitting CA was checked and none verifies, but the CRL names none of them
      by key identifier. A CRL with no key identifier fits every CA of that name. So a CA that
      renewed its key reads this way, while the peer's own chain may still carry the CA that
      signed the CRL. That is read from OpenSSL's source, which takes a CRL's issuer from the
      peer's chain. It is not measured for every chain shape.
    * ``unlisted``: no listed CA fits. An intermediate the peer sends in its handshake is never in
      the list, so this is the usual answer for that intermediate's CRL."""

    where: str
    state: CrlSignatureState


def judge_crl_signatures(pem: bytes, ca_ders: Iterable[bytes]) -> Iterator[CrlSignature]:
    """The :class:`CrlSignature` of each CRL in ``pem`` against the CAs in ``ca_ders``, in file
    order, one at a time (vault BACKLOG #2905).

    OpenSSL checks a CRL's signature at the handshake, not when it loads the file. This is the
    engine's own check, for at least a start (``harden_crl_check``), the running-hop reload
    (:func:`crl_signature_finding`) and the expiry scan's check of a CRL in a CA file (BACKLOG
    #3512). A CA that ``cryptography`` cannot read is ignored
    (:data:`_UNREADABLE_CA`): it cannot be shown to be an issuer, and a trust store may hold one
    that OpenSSL loads. Before vault BACKLOG #2905 such a CA raised out of the reload's check,
    which then retried every pass. ``pem`` must be bytes :func:`judge_every_crl` accepted; a
    block that does not parse raises ``ValueError``."""
    cas: list[_ListedCa] = []
    for der in ca_ders:
        try:
            cas.append(_listed_ca(der))
        except _UNREADABLE_CA:
            continue
    blocks = list(_crl_blocks(pem))
    for index, block in enumerate(blocks, start=1):
        crl = x509.load_pem_x509_crl(block)
        issuer = quoted_issuer(crl.issuer.rfc4514_string())
        yield CrlSignature(
            f"CRL block {index} of {len(blocks)} (issuer {issuer})", _signature_state(crl, cas)
        )


#: The most characters of a CRL's quoted issuer name the signature check and the running-hop
#: reload put in a message (vault BACKLOG #3506). A name has no length bound of its own, and each
#: message that quotes it goes to the log or an exception.
_ISSUER_SHOWN = 200


def quoted_issuer(issuer: str) -> str:
    """``issuer`` quoted with ``repr``, whole, or cut so the quoted form holds at most
    :data:`_ISSUER_SHOWN` characters, escapes included. The note on how long the name is stays
    outside the quotes."""
    quoted = repr(issuer)
    if len(quoted) <= _ISSUER_SHOWN:
        return quoted
    # Cut the name, not its quoted form, so the quotes close and no escape is split.
    kept = _ISSUER_SHOWN
    while len(quoted := repr(issuer[:kept])) > _ISSUER_SHOWN:
        kept -= 1
    return f"{quoted}... (cut: the name is {len(issuer)} characters)"


#: What ``cryptography`` raises, at least, for CRL extensions it cannot read, beside a duplicate
#: extension, which :func:`_crl_extensions` refuses itself: a general name it does not support,
#: such as an x400Address, and, where warnings are errors, a deprecation it warns of. Neither is a
#: ``ValueError``. :func:`judge_every_crl` says who refuses these by name (vault BACKLOG #3506).
_UNREAD_EXTENSIONS = (x509.UnsupportedGeneralNameType, CryptographyDeprecationWarning)

#: What ``cryptography`` raises for a CA certificate it cannot read, at least. A CA that raises
#: one is skipped by :func:`judge_crl_signatures`, alone. ``InvalidVersion`` comes from the
#: parse, and ``UnsupportedGeneralNameType`` from reading extensions; neither is a ``ValueError``.
#: ``CryptographyDeprecationWarning`` is raised only where warnings are errors. A CA whose serial
#: number is not positive no longer raises it, because :func:`_listed_ca` reads that CA without
#: the warning, and nor does a CRL whose Authority Key Identifier carries such a serial
#: (:func:`_crl_extensions`). It stays here for any other deprecation the parse warns of, so such
#: a CA is skipped alone rather than ending the whole judgment (vault BACKLOG #3506).
#: :func:`_signature_state` reads a CRL whose own extensions raise one of these as ``unlisted``.
_UNREADABLE_CA = (ValueError, x509.InvalidVersion, *_UNREAD_EXTENSIONS)

#: One name as :func:`_issuer_name_key` compares it: per RDN, in order, the sorted attributes.
_NameKey = tuple[tuple[tuple[str, bool, str | bytes], ...], ...]


@dataclass(frozen=True)
class _ListedCa:
    """One CA from a hop's list, as :func:`_signature_state` reads it. ``serial`` is the serial
    number the certificate carries. ``cert`` can be a copy with its serial numbers rewritten
    (:func:`_listed_ca` says when), so it is read for its names, extensions and key only, never
    for its serial, its fingerprint or as the CA's identity."""

    name: _NameKey
    cert: x509.Certificate
    serial: int


def _listed_ca(der: bytes) -> _ListedCa:
    """The CA certificate ``der``, read for :func:`judge_crl_signatures` (vault BACKLOG #3506).

    **A serial number that is not positive is read without ``cryptography``'s warning.** At
    least some system roots carry serial 0, and some of those name it again in their own
    Authority Key Identifier. ``cryptography`` warns when it parses such a CA, when it reads the
    serial, and when it reads that extension, and where warnings are errors the warning is raised
    instead. That CA was then skipped, so a forged CRL naming its key read ``unlisted`` and loaded
    with a warning. Silencing the warning needs a change to the process's warning filters, and a
    start and a reload can run this on two threads at once. So instead the first byte of each
    such serial is rewritten to ``0x01`` in a copy of the bytes, which keeps the length and makes
    the number positive, and the copy is parsed. The real serial is kept in
    :attr:`_ListedCa.serial` for the Authority Key Identifier match. The copy's own signature is
    then wrong, which nothing here reads: the check uses the subject, the issuer, the Subject Key
    Identifier and the public key, and those bytes are unchanged. A serial that is not minimally
    encoded is left as it is, so the parse refuses it as before. ``cryptography`` says it will
    refuse such a serial outright in a later release; this reads the CA all the same."""
    spans = _der_serial_spans(der)
    if spans is None:  # not that shape: the parse judges it, and reads its serial
        ca = x509.load_der_x509_certificate(der)
        return _ListedCa(_issuer_name_key(ca.subject), ca, ca.serial_number)
    serial = int.from_bytes(der[slice(*spans[0])], "big", signed=True)
    ca = x509.load_der_x509_certificate(_positive_copy(der, spans))
    return _ListedCa(_issuer_name_key(ca.subject), ca, serial)


def _positive_copy(der: bytes, spans: list[tuple[int, int]]) -> bytes:
    """``der`` with the first byte of each INTEGER in ``spans`` that :func:`_not_positive` holds
    set to ``0x01``: the same length, and a positive number. The one rewrite rule the CA side
    (:func:`_listed_ca`) and the CRL side (:func:`_crl_extensions`) share."""
    for start, end in spans:
        if _not_positive(der[start:end]):
            der = der[:start] + b"\x01" + der[start + 1 :]
    return der


def _not_positive(content: bytes) -> bool:
    """Whether the INTEGER content ``content`` is zero, or negative and minimally encoded. A
    non-minimal one is left for the parse to refuse."""
    return content == b"\x00" or (
        content[0] >= 0x80 and not (content[0] == 0xFF and len(content) > 1 and content[1] >= 0x80)
    )


#: The Authority Key Identifier's OID, ``id-ce-authorityKeyIdentifier``, as the content of its
#: DER encoding.
_AKID_OID = bytes.fromhex("551d23")


def _der_serial_spans(der: bytes) -> list[tuple[int, int]] | None:
    """Where the serial numbers sit in the certificate ``der``, as content spans: its own first,
    then any its own Authority Key Identifier carries. ``None`` when the bytes do not have that
    shape; the parse then judges them. A TBSCertificate starts with an optional explicit
    version, tag ``[0]``, and then the serial, an INTEGER. Its extensions are under tag ``[3]``,
    and an Authority Key Identifier carries a serial under tag ``[2]``."""
    try:
        fields = _tbs_fields(der)
        if fields and fields[0].tag == 0xA0:
            fields = fields[1:]
        if not fields:
            return None
        serial = fields[0]
        if serial.tag != 0x02 or serial.start == serial.end:
            return None
        spans = [(serial.start, serial.end)]
        for field in fields:
            if field.tag == 0xA3:
                for value in _akid_values(der, field.start, field.end):
                    spans += _akid_serials(der, value)
    except MalformedDer:
        return None
    return spans


def _tbs_fields(der: bytes) -> list[DerTlv] | None:
    """The fields of the signed part of the certificate or CRL ``der``: a SEQUENCE whose first
    element, the TBSCertificate or TBSCertList, is a SEQUENCE. ``None`` when the bytes do not
    have that shape. Raises :class:`MalformedDer` when they do not parse as DER."""
    outer = read_der_tlv(der, 0, len(der))
    tbs = read_der_tlv(der, outer.start, outer.end)
    if (outer.tag, tbs.tag) != (0x30, 0x30):
        return None
    return der_children(der, tbs)


def _akid_values(der: bytes, start: int, end: int) -> list[tuple[int, int]]:
    """Where each Authority Key Identifier sits in the explicitly tagged extensions whose content
    is ``der[start:end]``, a certificate's ``[3]`` or a CRL's ``[0]``, as the content span of its
    ``extnValue``. Raises :class:`MalformedDer` when the bytes do not have that shape."""
    found: list[tuple[int, int]] = []
    for extension in der_children(der, read_der_tlv(der, start, end)):
        parts = der_children(der, extension)
        if len(parts) >= 2 and der[parts[0].start : parts[0].end] == _AKID_OID:
            found.append((parts[-1].start, parts[-1].end))
    return found


def _akid_serials(der: bytes, value: tuple[int, int]) -> list[tuple[int, int]]:
    """The content spans of the serial, tag ``[2]``, in the Authority Key Identifier whose
    ``extnValue`` content is ``value``. Raises :class:`MalformedDer` when the bytes do not parse."""
    akid = read_der_tlv(der, *value)
    return [
        (part.start, part.end)
        for part in der_children(der, akid)
        if part.tag == 0x82 and part.start < part.end
    ]


@dataclass(frozen=True)
class _CrlAkid:
    """A CRL's own Authority Key Identifier, read once per CRL for :func:`_akid_fit` (vault
    BACKLOG #3506). ``serial`` is the serial the CRL carries, ``issuers`` the directory names it
    carries in :func:`_issuer_name_key` form, and ``der`` its value. ``der`` is the bytes the CRL
    carries wherever :func:`_crl_akid_spans` finds them, and ``cryptography``'s encoding of the
    value only where it does not."""

    key_identifier: bytes | None
    serial: int | None
    issuers: frozenset[_NameKey]
    der: bytes


@dataclass(frozen=True)
class _CrlExtensions:
    """A CRL's extensions, as :func:`_crl_extensions` reads them. ``extensions`` can come from a
    copy with its Authority Key Identifier's serial rewritten, so the AKID is read from ``akid``,
    never from ``extensions``. ``akid`` is ``None`` when the CRL carries none."""

    extensions: x509.Extensions
    akid: _CrlAkid | None


def _crl_extensions(crl: x509.CertificateRevocationList) -> _CrlExtensions:
    """``crl``'s extensions, read without ``cryptography``'s warning about a serial number that is
    not positive (vault BACKLOG #3506). **It encodes the CRL's DER again**, which costs more than
    the parse on a long CRL: measured 2026-10-27 on Windows, CPython 3.14, ``cryptography``
    50.0.2, about 28 ms for a 2.9 MB CRL of 100,000 entries, against about 16 ms to parse it.
    :func:`judge_every_crl` pays that for every CRL, beside the encode its fingerprint takes.
    :func:`_signature_state` pays it only for a CRL some listed CA is named for.

    A CRL's Authority Key Identifier can carry its CA's serial, and a CRL from a root with serial
    0 can carry 0 there. ``cryptography`` warns when it reads that extension, and where warnings
    are errors the warning is raised instead: a start then failed with that raw warning, and the
    signature check read such a CRL as ``unlisted``. So the serial is rewritten in a copy of the
    DER (:func:`_positive_copy`), as :func:`_listed_ca` does for a CA, and the copy's extensions
    are read. The CRL itself is left as it is, so its signature and fingerprint are read from the
    real bytes, and the AKID's serial and encoding are taken from them too. A serial that is not
    minimally encoded is left for the parse to refuse.

    **Raises ``ValueError`` for a duplicate extension**, so :func:`judge_every_crl` refuses the
    block by name. Other extensions ``cryptography`` cannot read raise as it raised them
    (:data:`_UNREAD_EXTENSIONS`), and :func:`judge_every_crl` says which callers refuse those by
    name."""
    der = crl.public_bytes(serialization.Encoding.DER)
    found = _crl_akid_spans(der)
    copy = der if found is None else _positive_copy(der, found[1])
    try:
        extensions = crl.extensions if copy == der else x509.load_der_x509_crl(copy).extensions
        akid = extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
    except x509.ExtensionNotFound:
        return _CrlExtensions(extensions, None)
    except x509.DuplicateExtension as exc:
        raise ValueError(f"the CRL carries a duplicate extension: {exc}") from exc
    serial = akid.authority_cert_serial_number
    raw = akid.public_bytes()
    if found is not None:
        value, serials = found
        raw = der[slice(*value)]
        if copy != der:  # the parsed serial is the copy's
            serial = int.from_bytes(der[slice(*serials[0])], "big", signed=True)
    issuers = frozenset(
        _issuer_name_key(name.value)
        for name in akid.authority_cert_issuer or ()
        if isinstance(name, x509.DirectoryName)
    )
    return _CrlExtensions(extensions, _CrlAkid(akid.key_identifier, serial, issuers, raw))


def _crl_akid_spans(der: bytes) -> tuple[tuple[int, int], list[tuple[int, int]]] | None:
    """Where the CRL ``der``'s own Authority Key Identifier sits, as the content span of its
    ``extnValue``, and the content spans of the serials it carries. ``None`` when it carries
    none, carries more than one, or the bytes do not have that shape; the parse then judges
    them. A TBSCertList's extensions are under tag ``[0]``."""
    try:
        fields = _tbs_fields(der)
        if fields is None:
            return None
        values = [
            value
            for field in fields
            if field.tag == 0xA0
            for value in _akid_values(der, field.start, field.end)
        ]
        if len(values) != 1:
            return None
        return values[0], _akid_serials(der, values[0])
    except MalformedDer:
        return None


#: The 26 ASCII capitals to their lower case, and no other character.
_ASCII_FOLD = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)


def _issuer_name_key(name: x509.Name) -> _NameKey:
    """``name`` in the form :func:`_signature_state` compares a CRL issuer with a CA subject in
    (vault BACKLOG #3543).

    It is ``cryptography``'s own comparison with one change: **the case of ASCII letters is
    folded**, because OpenSSL folds it. OpenSSL compares names by a canonical form. For letters,
    that form lowers ``A`` to ``Z`` and leaves every other letter as it is; it treats white space
    and string types in ways of its own, as the last paragraph says. So a listed CA named
    ``CN=Partner CA`` is the issuer of a CRL from ``CN=PARTNER CA``. Matched exactly, that CA
    read as unlisted, so a badly signed CRL naming its key started with a warning and failed at
    the handshake.

    **Nothing else is loosened, and RFC 5280 is not followed where it reaches further.** Its
    name matching folds case beyond ASCII and maps characters (LDAP StringPrep). OpenSSL does
    neither, and a match looser than OpenSSL's would refuse a start for a CRL OpenSSL never
    judges that CA's peers by. So a letter outside ASCII is compared exactly, as OpenSSL compares
    it. Attributes in one RDN are compared as a multiset, as both do.

    **Where this still differs from OpenSSL, at least.** OpenSSL is looser about white space: it
    drops it around a value, measured on OpenSSL 3.5.7, and by its source collapses a run of it
    to one space. This does not, so a CA whose name differs only there reads ``unlisted``, the
    warning arm, while OpenSSL judges its peers by the CRL. Folding that too would close the same
    gap for spacing; it is left open on purpose, as a change of its own. This is looser about
    string type: ``cryptography`` ignores it, while OpenSSL ignores it only for the text types
    (UTF8String, PrintableString, T61String, IA5String, VisibleString, BMPString,
    UniversalString), by its source. So a value in another type, such as a NumericString, can
    match here where OpenSSL sees another name, and a start can refuse a CRL OpenSSL would not
    judge that CA's peers by. That fails closed, at a start, and names the file."""
    return tuple(tuple(sorted(map(_attribute_key, rdn))) for rdn in name.rdns)


def _attribute_key(attribute: x509.NameAttribute[str | bytes]) -> tuple[str, bool, str | bytes]:
    """One attribute as :func:`_issuer_name_key` compares it. The flag keeps a ``bytes`` value
    (``x500UniqueIdentifier``) from being ordered against a ``str`` one."""
    value = attribute.value
    folded = value.translate(_ASCII_FOLD) if isinstance(value, str) else value
    return attribute.oid.dotted_string, isinstance(value, bytes), folded


#: One issuer name as :func:`_crl_issuer_key` gives it: per RDN, in order, the sorted attributes,
#: each its OID, a string tag (0 for text) and its value.
CrlIssuerKey = tuple[tuple[tuple[str, int, str | bytes], ...], ...]

#: The ASN.1 tags of the string types OpenSSL compares as text (``ASN1_MASK_CANON`` in its
#: source): UTF8String, PrintableString, T61String, IA5String, VisibleString, UniversalString
#: and BMPString.
_OPENSSL_TEXT_TAGS = frozenset({12, 19, 20, 22, 26, 28, 30})

#: The text types OpenSSL reads one byte to a character, as Latin-1: PrintableString,
#: T61String, IA5String and VisibleString. ``cryptography`` decodes their bytes as UTF-8.
_OPENSSL_LATIN1_TAGS = frozenset({19, 20, 22, 26})


def _crl_issuer_key(name: x509.Name) -> CrlIssuerKey:
    """``name`` as :class:`CrlBlock` groups CRLs by issuer (vault BACKLOG #3755).

    OpenSSL compares names by a canonical form, and this follows it in at least three ways. A
    value in a text type has its ASCII letter case folded, and its text type is dropped. A value
    in a one-byte text type, such as a T61String, is read as Latin-1, as OpenSSL reads it.
    A value in any other type keeps its type and is compared exactly, because OpenSSL does not
    fold it. So ``CN=Partner CA`` and ``CN=PARTNER CA`` are one issuer. A case change outside
    ASCII, or in a NumericString, is another issuer.

    Grouped by the exact text before, a replacement CRL whose issuer differed only in ASCII case
    was refused as superseding nothing. Grouped looser than OpenSSL, a reload records a file as
    applied while the hop goes on checking the CRL it held. Folding case in a NumericString did
    that, and so did taking ``cryptography``'s UTF-8 reading of a T61String.

    **Where this still differs from OpenSSL, at least.** White space is compared exactly, as
    :func:`_issuer_name_key` records. Two names OpenSSL takes for one issuer then group apart.
    That gap is safe: a reload asks for a restart, and a start can refuse a future CRL beside a
    current one.

    **It reads a private attribute.** The string type comes from ``cryptography``'s
    ``NameAttribute._type``. If a release drops it, every CRL is refused. A start and a reload
    name that cause. The expiry monitor's check of a CA file says only that it cannot judge the
    CRL. Comparing the exact text instead would reopen the T61String gap with no sign.

    **Latin-1 here covers UTF-8 bytes only.** A one-byte text type whose bytes are not valid
    UTF-8 already fails ``cryptography``'s parse, so the file is refused."""
    return tuple(tuple(sorted(map(_crl_attribute_key, rdn))) for rdn in name.rdns)


def _crl_attribute_key(attribute: x509.NameAttribute[str | bytes]) -> tuple[str, int, str | bytes]:
    """One attribute as :func:`_crl_issuer_key` compares it. One tag holds one value type, so a
    ``bytes`` value is never ordered against a ``str`` one."""
    kind = getattr(attribute, "_type", None)
    tag = getattr(kind, "value", kind)
    if not isinstance(tag, int):
        raise ValueError(
            "the installed cryptography package no longer exposes the string type of an issuer "
            "name, so the engine cannot group CRLs by issuer as OpenSSL does. This is an engine "
            "defect, not a fault in the file"
        )
    value = attribute.value
    if tag in _OPENSSL_TEXT_TAGS and isinstance(value, str):
        if tag in _OPENSSL_LATIN1_TAGS:
            # Never ``encode("latin-1")``: it raises above U+00FF, so it would refuse a valid CRL.
            value = value.encode("utf-8").decode("latin-1")
        return attribute.oid.dotted_string, 0, value.translate(_ASCII_FOLD)
    return attribute.oid.dotted_string, tag, value


def _signature_state(
    crl: x509.CertificateRevocationList, cas: list[_ListedCa]
) -> CrlSignatureState:
    """Which :class:`CrlSignature` state ``cas`` gives ``crl``."""
    issuer = _issuer_name_key(crl.issuer)
    named_cas = [ca for ca in cas if ca.name == issuer]
    if not named_cas:
        return "unlisted"  # the usual case for an intermediate's CRL: its extensions go unread
    try:
        akid = _crl_extensions(crl).akid  # once per CRL, not once per CA
    except _UNREADABLE_CA:
        return "unlisted"  # its extensions do not read: no CA is shown to fit
    fitting = False
    named = False  # the CRL names some fitting CA's key
    unchecked = False
    for ca in named_cas:
        try:
            names_key = _akid_fit(akid, ca)
        except _UNREADABLE_CA:
            continue  # the CA's extensions or its issuer name do not read: not shown to fit
        if names_key is None:
            continue
        fitting = True
        named = named or names_key
        answer = _verifies(crl, ca.cert)
        if answer:
            return "verified"
        unchecked = unchecked or answer is None
    if not fitting:
        return "unlisted"
    if unchecked:
        return "uncheckable"
    return "bad" if named else "unproven"


#: Why a CRL reads :class:`CrlSignature` state ``unlisted``, for a start's warning and a reload's
#: refusal alike. It says what the engine did, not what the CA list holds: a listed CA whose name
#: differs from the issuer's only in white space reads ``unlisted`` too, and OpenSSL can still use
#: that CA (:func:`_issuer_name_key` says why).
UNLISTED_SIGNATURE = (
    "the engine matched it to no CA certificate this hop lists (it compares the issuer name "
    "with the case of ASCII letters folded, as OpenSSL does, and white space exactly, and then "
    "the CRL's authority key identifier, where it carries one)"
)

#: Why the engine could not confirm a CRL's signature against a CA it matched, by
#: :class:`CrlSignature` state, for a start's warning and a reload's refusal alike, so the two
#: cannot drift apart (vault BACKLOG #3506). ``unlisted`` has its own words,
#: :data:`UNLISTED_SIGNATURE`.
UNCONFIRMED_SIGNATURE: dict[CrlSignatureState, str] = {
    "unproven": (
        "a listed CA has that name, ASCII letter case aside, and its key does not "
        "verify the CRL, but the CRL does not "
        "name that CA's key, so a renewed CA key could explain it"
    ),
    "uncheckable": "the engine cannot check its signature with the listed CA's key",
}

#: What a start's refusal and a reload's refusal say of a CRL in state ``bad``, after the block
#: or the CRL it names, so the two cannot drift apart (vault BACKLOG #3506).
PROVEN_BAD_SIGNATURE = (
    "names the key of a CA certificate this hop trusts, and that key does not verify the CRL's "
    "signature. A handshake OpenSSL judges by this CRL fails with 'CRL signature failure'"
)

#: The rank of each state :func:`crl_signature_finding` reports, the strongest lowest. A proof
#: outranks the rest, and a CA that was checked and failed outranks one that was not checked.
_FINDING_RANK: dict[CrlSignatureState, int] = {
    "bad": 0,
    "unproven": 1,
    "uncheckable": 2,
    "unlisted": 3,
}


@dataclass(frozen=True)
class CrlSignatureFinding:
    """The strongest thing a hop's CA list says against the CRLs of one file (vault BACKLOG
    #3506). ``state`` is a :class:`CrlSignature` state other than ``verified``, and ``why`` names
    the block and says what was found, for a message."""

    why: str
    state: CrlSignatureState


def crl_signature_finding(pem: bytes, ca_ders: Iterable[bytes]) -> CrlSignatureFinding | None:
    """The strongest :class:`CrlSignatureFinding` for the CRLs in ``pem`` against the CAs in
    ``ca_ders``, or ``None`` when each CRL is verified (vault BACKLOG #3506).

    The running-hop reload calls this before a live load, because a load cannot be undone
    (BACKLOG #299), and OpenSSL checks a CRL's signature only at the handshake. So OpenSSL itself
    loads a CRL with the right issuer name and Authority Key Identifier but a bad signature, and
    then every handshake it judges fails with ``CRL signature failure``. The states stay apart, so
    the reload can tell a CRL proven badly signed, a file to fix, from one it could not confirm,
    which can be right, as after a CA renews its key. Before vault BACKLOG #3506 the reload read
    one flag that folded ``bad``, ``unproven`` and ``uncheckable`` together.
    :data:`_FINDING_RANK` picks the state reported, the first block of it in file order among
    equals. It stops at the first ``bad`` block, since nothing outranks it.

    A CA that does not parse is ignored. ``pem`` must be bytes :func:`judge_every_crl` accepted;
    a block that does not parse raises ``ValueError``."""
    strongest: CrlSignature | None = None
    for signature in judge_crl_signatures(pem, ca_ders):
        if signature.state == "verified":
            continue
        if strongest is None or _FINDING_RANK[signature.state] < _FINDING_RANK[strongest.state]:
            strongest = signature
        if strongest.state == "bad":
            break
    if strongest is None:
        return None
    if strongest.state == "bad":
        why = f"the CRL {PROVEN_BAD_SIGNATURE}"
    elif strongest.state == "unlisted":
        why = UNLISTED_SIGNATURE
    else:
        why = (
            f"the engine could not confirm its signature: {UNCONFIRMED_SIGNATURE[strongest.state]}"
        )
    return CrlSignatureFinding(f"{strongest.where}: {why}", strongest.state)


def _akid_fit(akid: _CrlAkid | None, listed: _ListedCa) -> bool | None:
    """How the CA ``listed`` fits a CRL's Authority Key Identifier ``akid``, the way OpenSSL's
    ``X509_check_akid`` matches one: each part the AKID carries must match the CA. ``None`` when
    it does not fit.

    When it fits, the answer is whether the CRL **names the CA's key**: the AKID carries a key
    identifier, the CA carries a Subject Key Identifier, and the two are equal. A CRL with no
    AKID or no key identifier fits, and so does a CA with no Subject Key Identifier, but none of
    those names the key."""
    if akid is None:
        return False
    ca = listed.cert
    names_key = False
    if akid.key_identifier is not None:
        try:
            ski = ca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
        except x509.ExtensionNotFound:
            ski = None
        except (x509.DuplicateExtension, ValueError):
            return None
        if ski is not None:
            if ski != akid.key_identifier:
                return None
            names_key = True
    if akid.serial is not None and akid.serial != listed.serial:
        return None
    # By the name test the issuer match uses, since OpenSSL compares this name by the same
    # canonical form. OpenSSL reads only the first directory name here; any one counts here,
    # as it did before vault BACKLOG #3543.
    fits = not akid.issuers or _issuer_name_key(ca.issuer) in akid.issuers
    return names_key if fits else None


def _verifies(crl: x509.CertificateRevocationList, ca: x509.Certificate) -> bool | None:
    """Whether ``ca``'s key verifies ``crl``: True, False when it is **proven** not to, and
    ``None`` when the engine cannot check (vault BACKLOG #2905).

    ``is_signature_valid`` answers False for a signature it cannot check as well as for one that
    fails, because it turns every error inside its own verification into False. So a False from
    it is not proof. The key is then asked directly (:func:`_verify_with`), and only its
    ``InvalidSignature`` counts as proof. Everything else is ``None``: a key or an algorithm
    ``cryptography`` does not support, a key of another kind than the signature, and a
    ``ValueError`` or ``TypeError`` from either call. So is a signature the key accepts after
    ``is_signature_valid`` refused it. Measured 2026-10-13 with ``cryptography`` 50.0.2: an RSA
    PKCS1v15 signature over SHA-1 that the CA did make reads ``None`` that way, and a forged one
    reads False."""
    try:
        key = ca.public_key()
        if crl.is_signature_valid(key):  # type: ignore[arg-type]
            return True
        _verify_with(key, crl)
    except InvalidSignature:
        return False
    except (ValueError, TypeError, UnsupportedAlgorithm):
        return None
    return None  # the key accepts what ``is_signature_valid`` refused: no proof either way


_DSA_SIGNATURES = frozenset(
    {
        x509.SignatureAlgorithmOID.DSA_WITH_SHA1,
        x509.SignatureAlgorithmOID.DSA_WITH_SHA224,
        x509.SignatureAlgorithmOID.DSA_WITH_SHA256,
        x509.SignatureAlgorithmOID.DSA_WITH_SHA384,
        x509.SignatureAlgorithmOID.DSA_WITH_SHA512,
    }
)


def _verify_with(key: object, crl: x509.CertificateRevocationList) -> None:
    """Verify ``crl``'s signature with ``key`` itself. Raises ``InvalidSignature`` when it fails,
    and ``UnsupportedAlgorithm`` when the key and the signature are not a pair this can check."""
    signature, signed = crl.signature, crl.tbs_certlist_bytes
    params = crl.signature_algorithm_parameters
    digest = crl.signature_hash_algorithm
    algorithm = crl.signature_algorithm_oid
    if (
        isinstance(key, rsa.RSAPublicKey)
        and digest is not None
        and isinstance(params, asymmetric_padding.PKCS1v15 | asymmetric_padding.PSS)
    ):
        key.verify(signature, signed, params, digest)
    elif isinstance(key, ec.EllipticCurvePublicKey) and isinstance(params, ec.ECDSA):
        key.verify(signature, signed, params)
    elif (
        isinstance(key, ed25519.Ed25519PublicKey)
        and algorithm == x509.SignatureAlgorithmOID.ED25519
    ) or (isinstance(key, ed448.Ed448PublicKey) and algorithm == x509.SignatureAlgorithmOID.ED448):
        key.verify(signature, signed)
    elif isinstance(key, dsa.DSAPublicKey) and digest is not None and algorithm in _DSA_SIGNATURES:
        key.verify(signature, signed, digest)
    else:
        raise UnsupportedAlgorithm(
            "the CA key and the CRL's signature are not a pair this can check"
        )


def _is_delta_crl(read: _CrlExtensions) -> bool:
    """Whether the CRL ``read`` came from carries a Delta CRL Indicator (RFC 5280 section 5.2.4).
    A duplicate extension already refused in :func:`_crl_extensions`."""
    return any(isinstance(ext.value, x509.DeltaCRLIndicator) for ext in read.extensions)


def soonest_crl(facts: list[CrlFacts]) -> CrlFacts:
    """The CRL in ``facts`` whose ``nextUpdate`` comes first. ``facts`` must not be empty.

    Every CRL counts, a superseded copy of an issuer's CRL included, so a stale copy left beside
    its replacement is judged stale. That can refuse a file OpenSSL would work with, and the fix is
    to remove the stale copy. The alternative, the latest ``nextUpdate`` per issuer, was measured to
    be worse: an older CRL with a longer window then stands in for a newer one that has lapsed, and
    OpenSSL falls back to the older CRL, which lacks the newer revocations."""
    return min(facts, key=lambda f: datetime.datetime.fromisoformat(f.next_update_iso))


_CRL_BEGIN = b"-----BEGIN X509 CRL-----"
_CRL_END = b"-----END X509 CRL-----"
_NO_CRL = "no CRL found in the supplied PEM (expected an 'X509 CRL' block)"


_UTF8_BOM = b"\xef\xbb\xbf"


def _begins_line(pem: bytes, at: int) -> bool:
    """Whether offset ``at`` of ``pem`` starts a line as OpenSSL reads one: the file's start or just
    after a LF, with at most one UTF-8 byte order mark before it."""
    if pem[at - len(_UTF8_BOM) : at] == _UTF8_BOM:
        at -= len(_UTF8_BOM)
    return at == 0 or pem[at - 1 : at] == b"\n"


def crl_pem_blocks(pem: bytes) -> list[bytes]:
    """Each ``X509 CRL`` block in ``pem`` that OpenSSL would load, in file order (:func:`_crl_blocks`
    says which). For a caller that must find or compare the CRLs inside a file that also holds
    certificates, such as a CA bundle (vault BACKLOG #2319)."""
    return list(_crl_blocks(pem))


def _crl_blocks(pem: bytes) -> Iterator[bytes]:
    """Yield each ``X509 CRL`` PEM block in ``pem`` whose BEGIN marker starts a line, in file order.

    **OpenSSL skips a block whose BEGIN marker does not start a line** (BACKLOG #299). This is the
    one place that measurement is recorded. On CPython 3.14.6 / OpenSSL 3.5.7, through
    ``load_verify_locations(cafile=)``, at least these were measured. Skipped: a marker after a
    space, a tab, other text, a lone CR, or two byte order marks. Loaded: a marker after one UTF-8
    byte order mark at a line start, trailing spaces on the BEGIN line, and CRLF line ends. A parser
    that counted a skipped block would judge a CRL the context never holds.

    This models that rule; it is not OpenSSL's reader. OpenSSL splits a line longer than its buffer,
    so a marker after 254 bytes of text on one line was measured to load. Such a file is refused
    here, which fails closed. The authority is what OpenSSL loads, which
    :func:`messagefoundry.config.tls_policy.crl_scratch_context` counts."""
    start = pem.find(_CRL_BEGIN)
    while start >= 0:
        if _begins_line(pem, start):
            stop = pem.find(_CRL_END, start)
            # Slice to this block's own bounds: a copy of the rest of the file per block grows with
            # file size times block count. A truncated last block keeps the tail, so it still raises.
            yield pem[start:] if stop < 0 else pem[start : stop + len(_CRL_END)]
        start = pem.find(_CRL_BEGIN, start + len(_CRL_BEGIN))


def _load_one_certificate(data: bytes) -> x509.Certificate:
    """The certificate in ``data``, PEM or DER. A PEM file is read for its first certificate block,
    as ``load_pem_x509_certificate`` does. Raises ``ValueError`` when ``data`` holds none."""
    if b"-----BEGIN" in data:
        return x509.load_pem_x509_certificate(data)
    return x509.load_der_x509_certificate(data)


class PinRefused(ValueError):
    """Why a SQL Server pin file can never match the server's certificate. Its text is the engine's
    own and names no part of the file, unlike a ``ValueError`` from ``cryptography``'s parser."""


def _signs_certificates(cert: x509.Certificate) -> bool:
    """True when the certificate is marked as an issuer: ``keyUsage`` with ``keyCertSign``, or a
    CA that another CA issued. A self-signed ``CA:TRUE`` certificate with no ``keyCertSign`` is what
    ``openssl req -x509`` makes by default for a server, and a server can present it, so it is not
    treated as an issuer here."""
    try:
        if cert.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign:
            return True
    except x509.ExtensionNotFound:
        pass
    return cert.subject != cert.issuer


def load_pinned_server_certificate(data: bytes) -> x509.Certificate:
    """The one server certificate a SQL Server ``[store].ssl_root_cert`` pin names, PEM or DER.

    The ODBC ``ServerCertificate`` pin is an exact match against the certificate the server presents
    (vault BACKLOG #2223). A file holding several certificates, or a CA certificate that signs
    others, is refused here with a reason rather than by the driver at every connect. Raises
    :class:`PinRefused` for those, and ``cryptography``'s own errors for a file that does not parse.

    **A file with an encryption header is refused too (BACKLOG #3090).** The ODBC driver reads the
    pin file itself, with its own TLS library, and a ``Proc-Type: 4,ENCRYPTED`` block can send a
    TLS library to a password prompt. ``cryptography``'s parser does not stop it. Measured with
    cryptography 50.0.2: a valid certificate block carrying the two RFC 1421 headers parses, and so
    does a certificate followed by an encrypted key block. So the text goes through the check
    ``anchor_cadata`` uses first. The refusal names no part of the file.

    **A file with a private-key label is refused too (BACKLOG #3745).** ``cryptography``'s parser
    reads the certificate and skips a key block beside it, so a key of any label would sit in a
    file the engine treats as public trust material. It goes through the check ``anchor_cadata``
    uses, after the header check."""
    # Lazy: auth.trust_anchors imports far more than this module needs at import time.
    from messagefoundry.auth.trust_anchors import (
        ENCRYPTION_HEADER_SCOPE,
        PRIVATE_KEY_SCOPE,
        has_encryption_header_bytes,
        has_private_key_label_bytes,
    )

    if has_encryption_header_bytes(data):
        raise PinRefused(
            f"it {ENCRYPTION_HEADER_SCOPE}. The ODBC driver loads this file with its own TLS "
            "library, which can wait for a password on an encrypted block; name the server's "
            "certificate without encryption headers"
        )
    if has_private_key_label_bytes(data):
        raise PinRefused(
            f"it {PRIVATE_KEY_SCOPE}. The pin is the server's public certificate, so a private "
            "key does not belong in it; name a file holding only that certificate"
        )
    if b"-----BEGIN" in data:
        certs = x509.load_pem_x509_certificates(data)  # ValueError when the file holds none
        if len(certs) != 1:
            raise PinRefused(
                f"it holds {len(certs)} certificates; the SQL Server pin must be exactly one, the "
                "server's own certificate"
            )
        cert = certs[0]
    else:
        cert = x509.load_der_x509_certificate(data)
    try:
        constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        return cert
    if constraints.ca and _signs_certificates(cert):
        raise PinRefused(
            "it is a CA certificate (basicConstraints CA:TRUE, used to sign certificates); the SQL "
            "Server pin is an exact match, so name the server's own certificate, or trust the CA "
            "through the machine store instead"
        )
    return cert


def read_pinned_server_certificate(path: str) -> x509.Certificate | str:
    """The certificate a SQL Server pin file names, or why it is not usable, as a phrase that
    completes a sentence starting with the setting and the path (vault BACKLOG #2223).

    A reason string rather than an exception, so a caller raises its own refusal outside any
    handler. The phrase holds at least an OS error's ``strerror``, a :class:`PinRefused` reason,
    the size refusal, or the type name of a parser error, never the parser's text or the file's
    bytes.

    It reads at most :data:`PIN_FILE_MAX_BYTES` and one byte more, so a huge or endless file is
    refused as too large rather than read whole (BACKLOG #3714)."""
    try:
        with open(path, "rb") as fh:
            data = fh.read(PIN_FILE_MAX_BYTES + 1)
    except (OSError, ValueError, TypeError) as exc:  # what open() raises for a bad path
        return unreadable_pin_reason(exc)
    return pinned_server_certificate(data)


#: The largest SQL Server pin file the engine accepts (BACKLOG #3714). A pin is one certificate,
#: a few KiB. :func:`read_pinned_server_certificate` reads at most this plus one byte. At store
#: open the cap is judged on the size on disk, then on the bytes after the anchor checks have read
#: the file whole. At least a reload, the serve start preflight, the expiry monitor and ``cert
#: inventory`` read the file with no cap.
PIN_FILE_MAX_BYTES = 1 << 20

_TOO_LARGE = f"is not a usable SQL Server pin: it is larger than {PIN_FILE_MAX_BYTES} bytes"


def oversized_pin_reason(path: str) -> str | None:
    """The reason a pin file is too large to read, from its size on disk, or ``None``. For a
    caller whose read is not bounded, such as the trust-anchor checks, to call first. A file
    that cannot be stat'ed gives ``None``: the read that follows reports it. A file whose size
    the OS does not report, such as a FIFO or a device, passes here, and the store open does not
    guard its read: it can block or never end."""
    try:
        size = os.stat(path).st_size
    except (OSError, ValueError, TypeError):
        return None
    return _TOO_LARGE if size > PIN_FILE_MAX_BYTES else None


def unreadable_pin_reason(exc: OSError | ValueError | TypeError) -> str:
    """The phrase for a pin file that could not be opened, in the shape of
    :func:`read_pinned_server_certificate`'s reasons. An ``OSError`` gives its ``strerror``; a
    ``ValueError`` or ``TypeError`` is a path ``open()`` will not take, such as one holding a NUL.
    Neither names the path's bytes."""
    if isinstance(exc, OSError):
        return f"could not be read: {exc.strerror or type(exc).__name__}"
    return f"could not be read: the path is not usable ({type(exc).__name__})"


def pinned_server_certificate(data: bytes) -> x509.Certificate | str:
    """:func:`read_pinned_server_certificate` over bytes already read, for a caller that has read
    the file once for another check (vault BACKLOG #3714). Bytes past
    :data:`PIN_FILE_MAX_BYTES` are refused as too large, so the cap judges the bytes in hand."""
    if len(data) > PIN_FILE_MAX_BYTES:
        return _TOO_LARGE
    reason: str
    try:
        return load_pinned_server_certificate(data)
    except PinRefused as exc:
        reason = f"is not a usable SQL Server pin: {exc}"
    except Exception as exc:  # cryptography's ValueError, DuplicateExtension and the like
        reason = f"is not a usable SQL Server pin: it is not a certificate ({type(exc).__name__})"
    return reason


def read_cert_facts(pem: bytes, *, now: float) -> CertFacts:
    """Parse a PEM certificate into its public inventory facts, evaluated at ``now`` (epoch seconds).

    The single load / notAfter / days-remaining path shared by the ``cert inventory`` CLI and
    :meth:`~messagefoundry.pipeline.cert_expiry.CertExpiryRunner._inspect` (``86_400`` s/day, matching
    the expiry monitor). Reads only the public certificate — never a private key. Raises ``ValueError``
    (from ``cryptography``) if ``pem`` is not a parseable certificate; the caller handles that.

    ``notAfter``/``days_remaining`` are the monitor-critical facts and must parse (a bad PEM raises
    ``ValueError`` at load). ``subject``/``issuer``/``sans`` are **best-effort enrichment**: a cert with
    a malformed Name or a duplicate/unsupported extension — where ``cryptography`` raises
    ``DuplicateExtension``/``UnsupportedGeneralNameType``, which subclass ``Exception``, **not**
    ``ValueError`` — must not sink a cert whose ``notAfter`` parsed fine. Otherwise ``cert inventory``
    would crash on such a cert and the expiry monitor would silently DROP a cert it used to watch.

    A DER file is read too, because the SQL Server store pin may be one (vault BACKLOG #2223)."""
    cert = _load_one_certificate(pem)
    not_after = cert.not_valid_after_utc  # tz-aware UTC (cryptography >= 42)
    days_remaining = _days_until(not_after, now)
    try:
        subject = cert.subject.rfc4514_string()
    except Exception:
        subject = "(subject unavailable)"
    try:
        issuer = cert.issuer.rfc4514_string()
    except Exception:
        issuer = "(issuer unavailable)"
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        # Both name types, in certificate order. Reading DNSName alone silently under-reports a
        # certificate whose names are IP addresses — which is every certificate minted for the
        # shipped loopback defaults (BACKLOG #1179).
        sans = [
            str(g.value)
            for g in san
            if isinstance(g, (x509.DNSName, x509.IPAddress))  # noqa: UP038 - x509 names, not a union
        ]
    except Exception:
        # No SAN extension (ExtensionNotFound), or a malformed/duplicate/unsupported one
        # (DuplicateExtension / UnsupportedGeneralNameType — Exception subclasses, not ValueError).
        # Best-effort: report no SANs rather than propagating (see the note above).
        sans = []
    return CertFacts(
        subject=subject,
        issuer=issuer,
        not_after_iso=not_after.isoformat(),
        sans=sans,
        days_remaining=days_remaining,
        expired=days_remaining < 0,
    )


@dataclass(frozen=True)
class SelfSignedFacts:
    """The public facts that decide whether an engine-generated certificate is due for renewal, and
    that identify it in the audit record of a replacement (BACKLOG #1276). Never any private material.

    ``engine_shaped`` is the shape :func:`make_self_signed` produces: subject equal to issuer, a
    signature that verifies under the certificate's OWN key, and basic constraints present with
    ``CA=false``. A certificate that fails any of those was not minted by the engine, so the engine
    has no business replacing it, whatever file it sits in."""

    #: SHA-256 over the DER certificate, lowercase hex: the fingerprint a client pins.
    sha256: str
    not_before: float  # epoch seconds
    not_after: float  # epoch seconds
    not_after_iso: str
    engine_shaped: bool


def read_self_signed_facts(pem: bytes) -> SelfSignedFacts:
    """Parse a PEM certificate into :class:`SelfSignedFacts`. Raises ``ValueError`` when ``pem`` is
    not a parseable certificate. Reads only the public certificate, never a key."""
    cert = x509.load_pem_x509_certificate(pem)
    try:
        constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        engine_shaped = not constraints.ca and cert.subject == cert.issuer
        if engine_shaped:
            # Raises unless the certificate's own key signed it: a certificate merely NAMING itself
            # as issuer is not self-signed, and is not the engine's.
            cert.verify_directly_issued_by(cert)
    except (
        x509.ExtensionNotFound,
        x509.DuplicateExtension,
        InvalidSignature,
        UnsupportedAlgorithm,
        ValueError,
        TypeError,
    ):
        # No or a duplicated basic-constraints extension, a signature the key does not verify, or
        # a key or algorithm the verifier does not support. Each means "not the engine's shape".
        engine_shaped = False
    return SelfSignedFacts(
        sha256=cert.fingerprint(hashes.SHA256()).hex(),
        not_before=cert.not_valid_before_utc.timestamp(),
        not_after=cert.not_valid_after_utc.timestamp(),
        not_after_iso=cert.not_valid_after_utc.isoformat(),
        engine_shaped=engine_shaped,
    )


def _general_names(names: list[str]) -> list[x509.GeneralName]:
    """Classify each SAN string: an IP literal becomes ``iPAddress``, anything else ``DNSName``.

    ``ip_address`` is the classifier rather than a regex because it is the same parser the verifier
    ultimately compares against, and it accepts exactly the literals that can appear in a URL host —
    IPv4, IPv6, and the zero-padded and compressed spellings of each."""
    out: list[x509.GeneralName] = []
    for n in names:
        try:
            out.append(x509.IPAddress(ipaddress.ip_address(n)))
        except ValueError:
            out.append(x509.DNSName(n))  # not an IP literal, so it is a hostname
    return out


def make_self_signed(cn: str, sans: list[str], days: int) -> tuple[bytes, bytes]:
    """Mint a self-signed EC P-256 cert + key, a TLS PLACEHOLDER. Returns ``(cert_pem, key_pem)``.

    Self-issued (subject == issuer), SHA-256, basic-constraints CA=false, and a SubjectAlternativeName
    covering ``cn`` plus every name in ``sans`` (``cn`` first, de-duplicated, order-stable). Valid
    from one minute ago (clock-skew slack) for ``days`` days. The returned key PEM is unencrypted
    PKCS#8 — the caller MUST persist it through the CLI's ``_write_private_key``.

    **The pair is a PLACEHOLDER TO BE REPLACED, not an endorsed production terminator.** A
    self-signed certificate has no chain of trust: strictly better than cleartext, strictly worse
    than an operator-supplied chain. Its callers include the engine's own API listener, which
    serves one on first run when no ``[api].tls_cert_file`` is set and no upstream terminator is
    declared (``messagefoundry.api.tls``, ADR 0172), and the ``cert self-signed`` CLI verb. The
    load-test harness (``harness/load/tlsmat.py``) also calls it and writes its per-run pair with a
    plain write and ``chmod``, not through ``_write_private_key``.

    **An IP literal becomes an** ``iPAddress`` **entry, not a** ``DNSName``. Hostname verification for
    an IP-literal URL matches only against ``iPAddress``; a DNS entry spelling the same characters
    does not satisfy it. This is load-bearing rather than pedantic here — ``[api].host`` binds
    ``127.0.0.1`` and every shipped first-party client defaults to the IP LITERAL ``127.0.0.1:8765``,
    so a DNS-only certificate could not verify against a single one of them (BACKLOG #1179). The
    scheme those clients default to is a separate question that is still moving -- the VS Code
    extension went to ``https://`` under BACKLOG #1695 -- and naming it here would go stale; the HOST
    is what this paragraph rests on."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    names = list(dict.fromkeys([cn, *sans]))  # CN first, de-duped, order preserved
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(_general_names(names)), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert_to_pem(cert), key_to_pem(key)


# --- mTLS issuer identity (BACKLOG #2237) -----------------------------------------------------------

#: The nine attribute names cryptography's renderer writes by name. It writes every other attribute,
#: ``E``/``EMAILADDRESS``/``SERIALNUMBER`` included, as a dotted OID.
_RENDERED_TYPES = frozenset({"CN", "L", "ST", "O", "OU", "C", "STREET", "DC", "UID"})
#: Characters RFC 4514 section 2.4 has the renderer escape anywhere in a value.
_ALWAYS_ESCAPED = frozenset('\\,+;<>"')


def _has_rendered_shape(text: str) -> bool:
    """Whether ``text`` has the exact shape cryptography's renderer writes (RFC 4514 section 2.4).

    ``TYPE=value`` pairs joined by ``,`` or ``+``. TYPE is one of :data:`_RENDERED_TYPES` or a dotted
    OID. A value may be empty (``OU=``); otherwise ``\\`` escapes one character, none of
    :data:`_ALWAYS_ESCAPED` appears unescaped, and a leading ``#`` or space and a trailing space are
    escaped. Used only to decide whether a key cryptography's PARSER refuses is still a plausible
    rendered name (see :func:`canonical_dn`).

    A single linear pass rather than one regex: the obvious regex nests quantifiers, which is a
    backtracking (ReDoS) shape on operator-supplied text."""
    pairs = _split_unescaped(text)
    return pairs is not None and all(_is_rendered_pair(pair) for pair in pairs)


def _split_unescaped(text: str) -> list[str] | None:
    """``text`` split at each unescaped ``,`` or ``+``, escapes kept, or ``None`` for a trailing
    lone backslash."""
    pairs: list[str] = []
    start = i = 0
    while i < len(text):
        ch = text[i]
        if ch == "\\":
            if i + 1 >= len(text):
                return None
            i += 2
            continue
        if ch in ",+":
            pairs.append(text[start:i])
            start = i + 1
        i += 1
    pairs.append(text[start:])
    return pairs


def _is_rendered_pair(pair: str) -> bool:
    name, eq, value = pair.partition("=")
    if not eq:
        return False
    parts = name.split(".")
    dotted = len(parts) > 1 and all(p.isascii() and p.isdigit() for p in parts)
    if name not in _RENDERED_TYPES and not dotted:
        return False
    i = 0
    last_escaped = False
    while i < len(value):
        ch = value[i]
        if ch == "\\":
            i += 2  # _split_unescaped already refused a trailing lone backslash
            last_escaped = True
            continue
        if ch in _ALWAYS_ESCAPED or (i == 0 and ch in "# "):
            return False
        last_escaped = False
        i += 1
    return not (value.endswith(" ") and not last_escaped)


def canonical_dn(text: str) -> str | None:
    """The form ``text`` should be written in, ``text`` itself when it already is, or ``None``.

    The ``[api].tls_client_cert_identities`` loader refuses an issuer key for which this does not
    return the key itself. A name ``cryptography`` parses but renders differently (a dotted OID for
    ``CN=``, a hex escape for a plain one) comes back re-rendered, so the loader can say what to write.

    A name ``cryptography``'s parser refuses is returned unchanged only when it still has the exact
    shape its renderer writes (:func:`_has_rendered_shape`), because that parser rejects some names the
    renderer prints for real certificates (a three-letter ``C=``, a ``CN`` over 64 characters).
    Anything else, such as a space after a comma, a long attribute name or a trailing separator, is
    ``None``. Whether a passed-through key names a loaded CA is checked at start instead, by
    :meth:`IssuerIndex.unmatched_keys`."""
    try:
        rendered = x509.Name.from_rfc4514_string(text).rfc4514_string()
    except ValueError:
        return text if _has_rendered_shape(text) else None
    return rendered or None


@dataclass(frozen=True)
class _Anchor:
    cert: x509.Certificate
    subject: str


class IssuerIndex:
    """Which loaded client CA directly issued a verified client certificate (BACKLOG #2237).

    Built ONCE, from the same ``cadata`` bytes the API context loads from ``[api].tls_client_ca_file``,
    so a per-connection lookup costs one dict read and a signature check or two, and it needs nothing
    from the TLS session. That matters: on a RESUMED session OpenSSL keeps the peer certificate but
    not the verified chain, so an issuer read from ``get_verified_chain()`` came back empty and a
    mapped service was denied on every connection after its first.

    The issuer is never read from the leaf's issuer field alone. The issuing CA writes that field, and
    OpenSSL matches it to a CA loosely (case and whitespace folded). A loaded CA counts as the issuer
    only when ``verify_directly_issued_by`` holds: its subject equals the leaf's issuer name exactly
    AND its key verifies the leaf's signature. A client-sent intermediate is never a loaded CA, so it
    never counts. A self-signed client certificate loaded as an anchor issued itself, so it names
    itself, whether or not it is marked as a CA."""

    def __init__(self, cadata: str) -> None:
        seen: set[bytes] = set()  # de-duplicates a certificate listed twice
        self._by_subject_name: dict[x509.Name, list[_Anchor]] = {}
        # Distinct KEYS per rendered subject. A re-issued CA certificate with the same key, or a root
        # beside its own cross-certificate, is one signer and not ambiguous; two keys under one name
        # are, because the map names only the name.
        self._subject_keys: dict[str, set[bytes]] = {}
        self.unreadable = 0
        for block in _pem_certificate_blocks(cadata.encode("ascii", "replace")):
            try:
                cert = x509.load_pem_x509_certificate(block)
                subject = cert.subject.rfc4514_string()
                der = cert.public_bytes(serialization.Encoding.DER)
                key = cert.public_key().public_bytes(
                    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
                )
            except (ValueError, UnsupportedAlgorithm):
                self.unreadable += 1  # OpenSSL may load what cryptography will not; never nameable
                continue
            if der in seen:
                continue  # the same certificate twice is one anchor
            seen.add(der)
            self._by_subject_name.setdefault(cert.subject, []).append(_Anchor(cert, subject))
            self._subject_keys.setdefault(subject, set()).add(key)

    def issuer_of(self, leaf_der: bytes) -> str:
        """The subject of the one loaded CA that directly issued ``leaf_der``, or ``""``.

        ``""`` when no loaded CA issued it, when it does not parse, or when another loaded CA with a
        DIFFERENT key shares the issuing CA's subject: the map is keyed by name, so it could not tell
        the two apart. Never raises."""
        try:
            leaf = x509.load_der_x509_certificate(leaf_der)
            issuers = [
                anchor
                for anchor in self._by_subject_name.get(leaf.issuer, [])
                if _directly_issued(leaf, anchor.cert)
            ]
        except ValueError:
            return ""
        subjects = {anchor.subject for anchor in issuers}
        if len(subjects) != 1:
            return ""
        (subject,) = subjects
        return subject if len(self._subject_keys.get(subject, ())) == 1 else ""

    def unmatched_keys(self, issuer_keys: Iterable[str]) -> dict[str, str]:
        """Each configured issuer key that can never match, with the reason (checked at start)."""
        problems: dict[str, str] = {}
        for key in issuer_keys:
            count = len(self._subject_keys.get(key, ()))
            if count == 0:
                problems[key] = "names no CA certificate loaded from [api].tls_client_ca_file"
            elif count > 1:
                problems[key] = (
                    f"names {count} loaded CA certificates with the same subject and different keys, "
                    "so they cannot be told apart and no certificate maps under it"
                )
        return problems


def _directly_issued(leaf: x509.Certificate, issuer: x509.Certificate) -> bool:
    try:
        leaf.verify_directly_issued_by(issuer)
    except (ValueError, TypeError, InvalidSignature, UnsupportedAlgorithm):
        return False
    return True


def _pem_certificate_blocks(pem: bytes) -> Iterator[bytes]:
    """Each ``CERTIFICATE`` PEM block in ``pem``, in order."""
    begin, end = b"-----BEGIN CERTIFICATE-----", b"-----END CERTIFICATE-----"
    at = 0
    while (start := pem.find(begin, at)) >= 0:
        stop = pem.find(end, start)
        if stop < 0:
            return
        at = stop + len(end)
        yield pem[start:at]
