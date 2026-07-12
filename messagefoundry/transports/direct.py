# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Direct-Project S/MIME-over-SMTP destination (ADR 0085, PR1 — **outbound only**).

The Direct Project carries clinical content between trusted correspondents as an **S/MIME message
over SMTP**: the payload is **signed** with the sender's key/cert (authenticity + integrity) and then
**encrypted** to the recipient's public certificate (confidentiality), so PHI is protected end-to-end
independent of the transport TLS. This destination does exactly that for a single outbound hop:

- take the Handler-produced payload (the clinical *body* — content-agnostic: an HL7 string, a CDA/XML
  document, plain text),
- wrap it in an ``EmailMessage``,
- **SIGN** it (``pkcs7.PKCS7SignatureBuilder``) with the sender key+cert, then **ENCRYPT** the signed
  blob (``pkcs7.PKCS7EnvelopeBuilder`` addressed to the partner's recipient cert),
- submit the resulting S/MIME message over STARTTLS SMTP off the event loop.

**No new dependency** (CLAUDE.md §7, ADR 0085): crypto is core ``cryptography`` (``serialization.pkcs7``);
SMTP is stdlib ``smtplib``. The ``endesive`` library was evaluated and **rejected** (avoidable dep for
what pkcs7 already does); ``dnspython`` (DNS CERT / DNS-based cert discovery) is **deferred** — the
recipient cert + trust anchor are operator-supplied files here.

**Scope (PR1).** Outbound S/MIME send only. An **inbound** Direct mail source (IMAP/POP + S/MIME
decrypt/verify), **MDN** disposition notifications, **DNS CERT / LDAP** certificate discovery, and
**IHE XDR/XDM** are all deferred to later phases (ADR 0085) and are **not** built here.

**Fail-loud at construction** (the ``RestDestination``/``EmailDestination`` pattern): a missing
host/sender/recipient, an unreadable/malformed signing key, cert, recipient cert, or trust anchor, a
signing key that does not match its cert, or a cleartext-credential misconfiguration **raises here**,
so it fails at ``check``/dry-run/start — never as a wire-time surprise. The blocking crypto + SMTP
exchange runs off the event loop via ``asyncio.to_thread``.

**STARTTLS posture is inherited from EMAIL.** The signed+encrypted S/MIME body already protects PHI at
rest and in flight, but the SMTP session still carries envelope metadata (and any AUTH credentials), so
TLS stays on by default; disabling it is refused unless the project-wide ``MEFOR_ALLOW_INSECURE_TLS``
escape is set, and SMTP AUTH over cleartext is refused outright (the ``refuse_cleartext_credentials``
rule). The ``[egress].allowed_direct`` allowlist is the authoritative fail-closed host gate (enforced
by the runner at load/reload/start).

**Idempotency.** Delivery is at-least-once, so a retry re-sends the S/MIME message; a Direct mailbox
has no idempotency key, so a rare duplicate is possible after a transient failure between server-accept
and connector-success — documented and accepted (a duplicate beats a drop), exactly like EMAIL.
"""

from __future__ import annotations

import asyncio
import logging
import smtplib
from email.message import EmailMessage
from pathlib import Path
from collections.abc import Mapping
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs7

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import INSECURE_TLS_ESCAPE_ENV, insecure_tls_allowed
from messagefoundry.transports.base import (
    DeliveryError,
    DeliveryResponse,
    DestinationConnector,
    register_destination,
)

__all__ = ["DirectDestination"]

logger = logging.getLogger(__name__)


def _as_recipients(value: Any) -> list[str]:
    """Coerce the ``recipients`` setting to a non-empty list of Direct address strings (a lone string
    is one recipient). Mirrors :func:`messagefoundry.transports.email._as_recipients`."""
    if isinstance(value, str):
        recipients = [value] if value else []
    elif isinstance(value, (list, tuple)):
        recipients = [str(item) for item in value if str(item)]
    else:
        recipients = []
    if not recipients:
        raise ValueError("Direct destination requires a non-empty 'recipients' setting")
    return recipients


def _read_file(setting: str, value: Any) -> bytes:
    """Read a PEM/DER material file named by a required setting. PHI/secret-safe errors: the setting
    name and the OS error class only, never the file *contents* (a private key)."""
    if not isinstance(value, str) or not value:
        raise ValueError(f"Direct destination requires a '{setting}' file path")
    try:
        return Path(value).read_bytes()
    except OSError as exc:
        # Never echo the path's contents; name the setting + the error class so a misconfig is
        # actionable without leaking key material.
        raise ValueError(
            f"Direct destination '{setting}' is unreadable: {type(exc).__name__}"
        ) from exc


def _load_cert(setting: str, data: bytes) -> x509.Certificate:
    """Parse a PEM- or DER-encoded X.509 certificate, trying PEM first then DER (operators hand us
    either). A malformed cert raises :class:`ValueError` naming only the setting."""
    try:
        return x509.load_pem_x509_certificate(data)
    except ValueError:
        try:
            return x509.load_der_x509_certificate(data)
        except ValueError as exc:
            raise ValueError(
                f"Direct destination '{setting}' is not a valid PEM/DER X.509 certificate"
            ) from exc


class DirectDestination(DestinationConnector):
    """Deliver each transformed payload as a signed+encrypted S/MIME message over SMTP (Direct
    Project, outbound only — ADR 0085 PR1).

    All signing/recipient/trust material is loaded and validated **at construction** (fail loud), so a
    bad key/cert is caught at ``check``/dry-run/start. :meth:`send` builds the ``EmailMessage``, SIGNs
    then ENCRYPTs it, and submits it over STARTTLS SMTP off the event loop.
    """

    def __init__(self, config: Destination) -> None:
        s = config.settings
        host = s.get("host")
        if not isinstance(host, str) or not host:
            raise ValueError("Direct destination requires a 'host' setting")
        sender = s.get("sender")
        if not isinstance(sender, str) or not sender:
            raise ValueError("Direct destination requires a 'sender' setting")
        self.host = host
        self.port = int(s.get("port", 587))
        self.sender = sender
        self.recipients = _as_recipients(s.get("recipients"))
        self.subject = str(s.get("subject", ""))
        username = s.get("username")
        password = s.get("password")
        self.username: str | None = str(username) if username else None
        self.password: str | None = str(password) if password else None
        self.use_tls = bool(s.get("use_tls", True))
        self.timeout: float = float(s.get("timeout_seconds", 30.0))
        self.encoding: str = str(s.get("encoding", "utf-8"))

        # S/MIME material — the whole point of Direct. Loaded and cross-checked at construction so a
        # missing/malformed/mismatched key or cert fails loud here, not on the first message.
        self._signing_cert = _load_cert(
            "signing_cert", _read_file("signing_cert", s.get("signing_cert"))
        )
        self._signing_key = self._load_private_key(
            s.get("signing_key"), s.get("signing_key_password")
        )
        self._verify_signing_key_matches_cert()
        # Per-partner recipient certificate — the encryption target. Direct is 1:1 with a HISP
        # correspondent, so PR1 supports a single recipient cert (a per-recipient cert map is a later
        # phase, ADR 0085).
        self._recipient_cert = _load_cert(
            "recipient_cert", _read_file("recipient_cert", s.get("recipient_cert"))
        )
        # Trust anchor — the CA(s) the recipient cert must chain to. Verified at construction so a cert
        # from an untrusted issuer is refused before we ever encrypt PHI to it.
        self._verify_recipient_trusted(_read_file("trust_anchor", s.get("trust_anchor")))

        # STARTTLS-by-default posture, identical to EmailDestination: the S/MIME body already protects
        # PHI, but the SMTP session still carries envelope metadata + any AUTH credentials, so cleartext
        # SMTP is refused unless the project-wide dev escape is set, and credentials are NEVER sent over
        # a cleartext channel.
        if not self.use_tls:
            if not insecure_tls_allowed():
                raise ValueError(
                    "Direct destination use_tls=false submits over cleartext SMTP; refused unless "
                    f"{INSECURE_TLS_ESCAPE_ENV} is set (dev/trusted-network only) — use STARTTLS "
                    "(the default)"
                )
            if self.username is not None:
                raise ValueError(
                    "Direct destination sends SMTP AUTH credentials over cleartext (use_tls=false); "
                    "refused — credentials require STARTTLS/implicit TLS"
                )
            logger.warning(
                "Direct destination %s has TLS DISABLED (use_tls=false); the SMTP session crosses the "
                "network in CLEARTEXT (dev/trusted-network only)",
                self.host,
            )

    def _load_private_key(self, value: Any, password: Any) -> Any:
        """Load the sender's signing private key (PEM/DER, optionally passphrase-protected). PHI/secret-
        safe: never echo the key bytes or the passphrase."""
        data = _read_file("signing_key", value)
        pw: bytes | None = None
        if password:
            pw = str(password).encode("utf-8")
        try:
            return serialization.load_pem_private_key(data, password=pw)
        except (ValueError, TypeError):
            try:
                return serialization.load_der_private_key(data, password=pw)
            except (ValueError, TypeError) as exc:
                # A wrong passphrase and a malformed key both surface here; do not distinguish (either
                # way the operator must fix the setting) and never leak the material.
                raise ValueError(
                    "Direct destination 'signing_key' could not be loaded "
                    f"(bad key material or wrong 'signing_key_password'): {type(exc).__name__}"
                ) from exc

    def _verify_signing_key_matches_cert(self) -> None:
        """Refuse a signing key whose public half does not match the signing cert — otherwise every
        signature would be produced under a cert that cannot verify it. Compared by serialized public
        key (works across RSA/EC without branching on the key type)."""
        key_pub = self._signing_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        cert_pub = self._signing_cert.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if key_pub != cert_pub:
            raise ValueError(
                "Direct destination 'signing_key' does not match 'signing_cert' (public keys differ)"
            )

    def _verify_recipient_trusted(self, anchor_data: bytes) -> None:
        """Refuse a recipient cert that is not directly issued by (or equal to) an operator-supplied
        trust anchor, so PHI is never encrypted to a certificate from an untrusted issuer (the reason a
        trust anchor is a required setting). This is a **one-level** issuance check (the recipient cert
        chains directly to a supplied anchor, or is a self-signed cert that IS the anchor); full
        multi-level path building is deferred (ADR 0085) — Direct trust is typically a single issuing CA
        or a pinned self-signed correspondent cert. A hostname/SAN match is deliberately NOT done: a
        Direct address is an email, not a TLS SNI."""
        try:
            anchors = x509.load_pem_x509_certificates(anchor_data)
        except ValueError:
            try:
                anchors = [x509.load_der_x509_certificate(anchor_data)]
            except ValueError as exc:
                raise ValueError(
                    "Direct destination 'trust_anchor' is not a valid PEM/DER X.509 certificate"
                ) from exc
        if not anchors:
            raise ValueError("Direct destination 'trust_anchor' contained no certificates")
        for anchor in anchors:
            try:
                # verify_directly_issued_by checks the issuer/subject name match AND that the anchor's
                # public key signed the recipient cert; a self-signed recipient pinned as its own anchor
                # verifies against itself. Raises on any mismatch.
                self._recipient_cert.verify_directly_issued_by(anchor)
                return
            except (ValueError, TypeError, InvalidSignature):
                continue  # try the next anchor
        # PHI-safe: no cert subject in the message (it may identify a patient's provider).
        raise ValueError(
            "Direct destination 'recipient_cert' is not issued by any supplied 'trust_anchor'; "
            "refusing to encrypt PHI to an untrusted certificate"
        )

    async def send(
        self, payload: str, *, metadata: Mapping[str, str] | None = None
    ) -> DeliveryResponse | None:  # metadata (#68): unused — no per-message header knob here
        # Crypto (sign+encrypt) and smtplib are both blocking — keep them off the event loop (the
        # delivery worker awaits this). A one-way delivery: SMTP submission has no application reply to
        # capture, so return None (like File/EMAIL).
        await asyncio.to_thread(self._send, payload)
        return None

    def _build_smime(self, payload: str) -> EmailMessage:
        """Build the outbound S/MIME message: SIGN the body with the sender key+cert, then ENCRYPT the
        signed blob to the recipient cert. Returns a fully-formed ``EmailMessage`` ready to submit."""
        body = payload.encode(self.encoding)
        # SIGN — attach the signer cert so the recipient can verify without a side-channel. Options:
        #   * Binary       — keep the body byte-exact (no MIME/CRLF canonicalization that would corrupt
        #                    an HL7/binary payload).
        #   * NoAttributes — the SignerInfo signature is computed directly over the content (not over a
        #                    set of authenticated attributes), so a recipient verifies with a plain
        #                    RSA/ECDSA-over-content check. CMS signed attributes required by the Direct
        #                    implementation guide (signingTime, ESSCertIDv2/signingCertificate) are a
        #                    documented later-phase refinement (ADR 0085), not a PR1 requirement; the
        #                    core authenticity + integrity guarantee holds without them.
        signed = (
            pkcs7.PKCS7SignatureBuilder()
            .set_data(body)
            .add_signer(self._signing_cert, self._signing_key, hashes.SHA256())
            .sign(
                serialization.Encoding.DER,
                [pkcs7.PKCS7Options.NoAttributes, pkcs7.PKCS7Options.Binary],
            )
        )
        # ENCRYPT the signed blob to the partner's recipient cert (sign-then-encrypt: the signature is
        # itself confidential). DER output is carried as the S/MIME application/pkcs7-mime body.
        # PKCS7Options.Binary is REQUIRED here: the enveloped content is the binary signed DER (and, for
        # a binary HL7/DICOM payload, arbitrary bytes). Without Binary, cryptography text-canonicalizes
        # the content (lone LF → CRLF) before enveloping, which corrupts the signed structure / any
        # binary body — the recipient would recover mangled bytes and a broken signature.
        enveloped = (
            pkcs7.PKCS7EnvelopeBuilder()
            .set_data(signed)
            .add_recipient(self._recipient_cert)
            .encrypt(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary])
        )
        msg = EmailMessage()
        msg["Subject"] = self.subject
        msg["From"] = self.sender
        msg["To"] = ", ".join(self.recipients)
        # RFC 5751 S/MIME enveloped-data content type; the enveloped DER is the body.
        msg.set_content(
            enveloped,
            maintype="application",
            subtype="pkcs7-mime",
            disposition="attachment",
            filename="smime.p7m",
        )
        msg.set_param("smime-type", "enveloped-data", header="Content-Type")
        return msg

    def _connect(self) -> smtplib.SMTP:
        """Open an SMTP connection, applying STARTTLS / implicit TLS per config (identical posture to
        EmailDestination). The caller closes it (``with`` / ``quit``)."""
        if self.port == 465 and self.use_tls:
            return smtplib.SMTP_SSL(self.host, self.port, timeout=self.timeout)
        smtp = smtplib.SMTP(self.host, self.port, timeout=self.timeout)
        if self.use_tls:
            smtp.starttls()
        return smtp

    def _send(self, payload: str) -> None:
        # PHI/secret-safe error text: the host + failure class only, never the body, the recipients'
        # PHI, or the password. Crypto failures (a key/cert problem that slipped past construction) map
        # to a non-transient DeliveryError so the message dead-letters rather than spinning on retry.
        try:
            msg = self._build_smime(payload)
        except (ValueError, TypeError) as exc:
            raise DeliveryError(
                f"Direct {self.host}:{self.port} S/MIME encode failed: {type(exc).__name__}"
            ) from exc
        try:
            with self._connect() as smtp:
                if self.username is not None:
                    smtp.login(self.username, self.password or "")
                smtp.send_message(msg)
        except smtplib.SMTPException as exc:
            raise DeliveryError(
                f"Direct {self.host}:{self.port} SMTP send failed: {type(exc).__name__}"
            ) from exc
        except (TimeoutError, OSError) as exc:
            raise DeliveryError(
                f"Direct {self.host}:{self.port} unreachable: {type(exc).__name__}"
            ) from exc

    async def test_connection(self) -> None:
        await asyncio.to_thread(self._probe)

    def _probe(self) -> None:
        # Reachability/auth only: connect + (STARTTLS) + EHLO + optional login + NOOP, then quit. NO
        # MAIL FROM / DATA, so a connection test never sends a real Direct message (the EMAIL probe
        # pattern). Crypto material was already validated at construction.
        try:
            with self._connect() as smtp:
                smtp.ehlo_or_helo_if_needed()
                if self.username is not None:
                    smtp.login(self.username, self.password or "")
                smtp.noop()
        except smtplib.SMTPException as exc:
            raise DeliveryError(
                f"Direct {self.host}:{self.port} probe failed: {type(exc).__name__}"
            ) from exc
        except (TimeoutError, OSError) as exc:
            raise DeliveryError(
                f"Direct {self.host}:{self.port} unreachable: {type(exc).__name__}"
            ) from exc


register_destination(ConnectorType.DIRECT, DirectDestination)
