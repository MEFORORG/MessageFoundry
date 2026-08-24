# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""PKI helpers (BACKLOG #71/#72): PKCS#12 import, read-only cert inventory, self-signed dev certs.

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
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

__all__ = [
    "CertFacts",
    "ca_chain_to_pem",
    "cert_to_pem",
    "key_to_pem",
    "load_pkcs12",
    "make_self_signed",
    "read_cert_facts",
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
    unencrypted bundle); it is used only to decrypt here and is never logged or returned. A wrong
    password / malformed bundle raises ``ValueError`` from ``cryptography`` — the CLI scrubs that so the
    passphrase can never leak into stderr/logs."""
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

    Secret material — the caller MUST persist the result with tight permissions (``O_EXCL`` + ``0o600``
    + the Windows DACL via ``_secure_file``), never log it, and never place it in an exception."""
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


def read_crl_facts(pem: bytes, *, now: float) -> CrlFacts:
    """Parse a PEM CRL into its public inventory facts, evaluated at ``now`` (epoch seconds).

    Accepts a bundle: a file may concatenate the issuing CA and its CRL, which is exactly the shape
    ``harden_crl_check`` loads through ``cafile=``. The FIRST ``X509 CRL`` block is read and any
    certificate blocks are skipped, so the same path serves a bare ``.crl`` and a CA+CRL bundle.

    Raises ``ValueError`` when the bytes carry no CRL at all -- a configured-but-CRL-less file must
    never degrade to "revocation checking silently off"."""
    marker = b"-----BEGIN X509 CRL-----"
    end = b"-----END X509 CRL-----"
    start = pem.find(marker)
    if start < 0:
        raise ValueError("no CRL found in the supplied PEM (expected an 'X509 CRL' block)")
    stop = pem.find(end, start)
    if stop < 0:
        raise ValueError("truncated CRL: an 'X509 CRL' block opened but never closed")
    crl = x509.load_pem_x509_crl(pem[start : stop + len(end)])
    nxt = crl.next_update_utc
    if nxt is None:
        # RFC 5280 makes nextUpdate optional, but OpenSSL treats a CRL without one as never
        # expiring, which would silence the freshness control entirely. Refuse rather than
        # inherit an unbounded lifetime.
        raise ValueError("the CRL carries no nextUpdate, so its freshness cannot be checked")
    return CrlFacts(
        issuer=crl.issuer.rfc4514_string(),
        next_update_iso=nxt.isoformat(),
        days_remaining=int((nxt.timestamp() - now) // 86_400),
    )


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
    days_remaining = int((not_after.timestamp() - now) // _SECONDS_PER_DAY)
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
    """Mint a self-signed EC P-256 cert + key for **non-prod** TLS bring-up. Returns ``(cert_pem, key_pem)``.

    Self-issued (subject == issuer), SHA-256, basic-constraints CA=false, and a SubjectAlternativeName
    covering ``cn`` plus every name in ``sans`` (``cn`` first, de-duplicated, order-stable). Valid
    from one minute ago (clock-skew slack) for ``days`` days. The returned key PEM is unencrypted
    PKCS#8 — the caller MUST persist it ``O_EXCL`` + ``0o600`` + ``_secure_file``. DEV ONLY: a
    self-signed cert has no chain of trust and must never front production PHI.

    **An IP literal becomes an** ``iPAddress`` **entry, not a** ``DNSName``. Hostname verification for
    an IP-literal URL matches only against ``iPAddress``; a DNS entry spelling the same characters
    does not satisfy it. This is load-bearing rather than pedantic here — ``[api].host`` binds
    ``127.0.0.1`` and every shipped first-party client defaults to ``http://127.0.0.1:8765``, so a
    DNS-only certificate could not verify against a single one of them (BACKLOG #1179)."""
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
