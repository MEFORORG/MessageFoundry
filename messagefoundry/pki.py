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
from collections.abc import Iterable, Iterator
from dataclasses import dataclass

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from messagefoundry.keywrap import refuse_weak_pkcs12

__all__ = [
    "CertFacts",
    "CrlBlock",
    "CrlFacts",
    "crl_signature_refusal",
    "judge_every_crl",
    "read_crl_facts",
    "read_soonest_crl_facts",
    "soonest_crl",
    "ca_chain_to_pem",
    "cert_to_pem",
    "key_to_pem",
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
    unencrypted bundle with no MAC); it is used only to decrypt here and is never logged or returned. A wrong
    password / malformed bundle raises ``ValueError`` from ``cryptography`` — the CLI scrubs that so the
    passphrase can never leak into stderr/logs.

    Before anything decrypts it, the bundle's MAC and bag encryption are checked (BACKLOG #1352,
    #1171): a weak or unreadable wrap, a MAC that is not PBMAC1 at the floor even over unencrypted
    bags, or a bundle that is encrypted or carries a MAC with no passphrase, raises
    :class:`~messagefoundry.keywrap.KeyWrapRefused`, whose text is safe to show."""
    refuse_weak_pkcs12(
        pfx_bytes,
        setting="the --pfx bundle",
        unlock_setting="MEFOR_PFX_PASSWORD",
        passphrase_given=password is not None,
    )
    key, cert, cas = pkcs12.load_key_and_certificates(pfx_bytes, password)
    return key, cert, list(cas)


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
    however its PEM is wrapped."""

    issuer: str
    this_update: datetime.datetime
    next_update: datetime.datetime
    fingerprint: bytes
    selection: tuple[bytes | None, bytes | None, frozenset[str]] = (None, None, frozenset())


def judge_every_crl(pem: bytes, *, now: float) -> list[tuple[CrlFacts, CrlBlock]]:
    """The facts and the :class:`CrlBlock` of EVERY CRL in ``pem``, in file order, refusing any block
    it cannot judge. One parse per block.

    The strict sibling of :func:`read_soonest_crl_facts`, for a context load (``harden_crl_check``)
    and the running-hop reload (BACKLOG #299). The monitor skips a block it cannot judge so one bad
    block cannot hide a sibling that is about to lapse. A context load must not skip it: OpenSSL
    loads that block too, and a CRL with no ``nextUpdate`` is one OpenSSL treats as never expiring.
    So here any such block raises, naming its position, and a file with no CRL raises as
    :func:`read_crl_facts` does. So does a BEGIN marker :func:`_crl_blocks` does not count. That is
    a model of OpenSSL, not a proof, so a load still counts what OpenSSL took
    (:func:`messagefoundry.config.tls_policy.crl_scratch_context`).

    **A delta CRL refuses too.** The engine turns on no extended CRL support, and without it
    OpenSSL 3.5.7 was measured to use a newer delta CRL as if it were complete. Revocations listed
    only in the base CRL were then dropped, and a revoked client was accepted. OpenSSL fixed that
    in 3.0.22, 3.4.7, 3.5.8 and 3.6.4, and a fixed build ignores the delta instead. The engine
    still refuses one, because which OpenSSL it runs on is the Python build's choice, and a
    distribution can carry an older one. Give the setting base CRLs only."""
    blocks = list(_crl_blocks(pem))
    if len(blocks) != pem.count(_CRL_BEGIN):
        raise ValueError(
            "it has a '-----BEGIN X509 CRL-----' marker that does not start a line, so OpenSSL "
            "does not load that CRL. The marker must be the first thing on its line, after a line "
            "feed: no space, tab or other text before it, and no line that ends in a carriage "
            "return alone"
        )
    if not blocks:
        raise ValueError(_NO_CRL)
    judged: list[tuple[CrlFacts, CrlBlock]] = []
    for index, block in enumerate(blocks, start=1):
        where = f"CRL block {index} of {len(blocks)}"
        try:
            crl, nxt = _parse_first_crl(block)
            if _is_delta_crl(crl):
                raise ValueError(
                    "it is a delta CRL, which an OpenSSL older than 3.0.22, 3.4.7, 3.5.8 or 3.6.4 "
                    "reads as a complete CRL and so drops every revocation listed only in its base "
                    "CRL; give base CRLs only"
                )
            judged.append(
                (
                    _crl_facts(crl, nxt, now),
                    CrlBlock(
                        issuer=crl.issuer.rfc4514_string(),
                        this_update=crl.last_update_utc,
                        next_update=nxt,
                        fingerprint=crl.fingerprint(hashes.SHA256()),
                        selection=_selection(crl),
                    ),
                )
            )
        except ValueError as exc:
            raise ValueError(f"{where} cannot be judged: {exc}") from exc
    return judged


def _selection(
    crl: x509.CertificateRevocationList,
) -> tuple[bytes | None, bytes | None, frozenset[str]]:
    """What OpenSSL scores a CRL on besides time and issuer; :class:`CrlBlock` says why."""
    scope: bytes | None = None
    key_id: bytes | None = None
    critical: set[str] = set()
    for ext in crl.extensions:
        if ext.critical:
            critical.add(ext.oid.dotted_string)
        if isinstance(ext.value, x509.IssuingDistributionPoint):
            scope = ext.value.public_bytes()
        elif isinstance(ext.value, x509.AuthorityKeyIdentifier):
            # The whole AKID: OpenSSL matches its issuer and serial to the CA too, when present.
            key_id = ext.value.public_bytes()
    return scope, key_id, frozenset(critical)


def crl_signature_refusal(pem: bytes, ca_ders: Iterable[bytes]) -> tuple[str, bool] | None:
    """Why some CRL in ``pem`` is not signed by a CA in ``ca_ders``, or ``None`` when each one is.

    The flag is True when a CA for the CRL's issuer was found and its key does not verify the CRL,
    and False when no such CA was found. A block that fails to verify is reported over one whose CA
    was not found, wherever it sits in the file. OpenSSL checks a CRL's signature at the handshake, not at
    the load. So a CRL with the right issuer name and Authority Key Identifier but a bad signature
    loads cleanly, and then every handshake it judges fails with ``CRL signature failure``. The
    running-hop reload calls this before a live load, because a load cannot be undone (BACKLOG #299).

    A CA counts as a CRL's issuer when its subject equals the CRL's issuer name exactly, it fits the
    CRL's AKID, and its key verifies the CRL. A CA that does not parse is ignored. ``pem`` must be
    bytes :func:`judge_every_crl` accepted; a block that does not parse raises ``ValueError``."""
    cas: list[x509.Certificate] = []
    for der in ca_ders:
        try:
            cas.append(x509.load_der_x509_certificate(der))
        except ValueError:
            continue
    blocks = list(_crl_blocks(pem))
    unlisted: str | None = None
    for index, block in enumerate(blocks, start=1):
        crl = x509.load_pem_x509_crl(block)
        where = f"CRL block {index} of {len(blocks)} (issuer {crl.issuer.rfc4514_string()!r})"
        issuers = [ca for ca in cas if ca.subject == crl.issuer and _fits_akid(crl, ca)]
        if not issuers:
            # Go on: a block that is known to be badly signed is the stronger finding.
            unlisted = unlisted or f"{where} names no CA certificate this hop lists as its issuer"
            continue
        if not any(_signed_by(crl, ca) for ca in issuers):
            return (
                f"{where} does not verify against the key of the CA certificate this hop trusts "
                "for that issuer. Loaded, it would make every handshake it judges fail with "
                "'CRL signature failure'",
                True,
            )
    return None if unlisted is None else (unlisted, False)


def _fits_akid(crl: x509.CertificateRevocationList, ca: x509.Certificate) -> bool:
    """Whether ``ca`` fits ``crl``'s Authority Key Identifier, the way OpenSSL's
    ``X509_check_akid`` matches one: each part the AKID carries must match the CA."""
    try:
        akid = crl.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
    except x509.ExtensionNotFound:
        return True
    except x509.DuplicateExtension:
        return False
    if akid.key_identifier is not None:
        try:
            ski = ca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
        except x509.ExtensionNotFound:
            ski = None
        except (x509.DuplicateExtension, ValueError):
            return False
        if ski is not None and ski != akid.key_identifier:
            return False
    serial = akid.authority_cert_serial_number
    if serial is not None and serial != ca.serial_number:
        return False
    names = [
        name.value
        for name in akid.authority_cert_issuer or ()
        if isinstance(name, x509.DirectoryName)
    ]
    return not names or ca.issuer in names


def _signed_by(crl: x509.CertificateRevocationList, ca: x509.Certificate) -> bool:
    """Whether ``ca``'s key verifies ``crl``. A key type the CRL cannot be checked with is False."""
    try:
        return crl.is_signature_valid(ca.public_key())  # type: ignore[arg-type]
    except (ValueError, TypeError, UnsupportedAlgorithm):
        return False


def _is_delta_crl(crl: x509.CertificateRevocationList) -> bool:
    """Whether ``crl`` carries a Delta CRL Indicator (RFC 5280 section 5.2.4)."""
    try:
        crl.extensions.get_extension_for_class(x509.DeltaCRLIndicator)
    except x509.ExtensionNotFound:
        return False
    except x509.DuplicateExtension as exc:
        raise ValueError(f"the CRL carries a duplicate extension: {exc}") from exc
    return True


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
    would crash on such a cert and the expiry monitor would silently DROP a cert it used to watch."""
    cert = x509.load_pem_x509_certificate(pem)
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
