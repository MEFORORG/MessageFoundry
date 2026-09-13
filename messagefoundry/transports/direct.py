# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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
import ssl
from collections.abc import Mapping
from email.message import EmailMessage
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs7

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import (
    INSECURE_TLS_ESCAPE_ENV,
    weakened_tls_escape_permitted_here,
)
from messagefoundry.config.tls_policy import (
    InsecureHopRefused,
    build_smtp_tls_context,
    smtp_login_approved,
)
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


#: Smallest RSA modulus this connector will use for ANY Direct S/MIME key material -- the sender's
#: signing key, the partner's recipient certificate, and the trust anchor (ASVS 11.2.3, BACKLOG #1166).
#: Measured before this floor existed: every one of those three loaders was a parse-and-type check
#: only, and a full RSA-1024 set constructed without complaint, against an RSA-2048 positive control
#: in the same run showing the loaders were live and simply never asked how big the modulus was.
#:
#: **2048 is chosen because it refuses nothing a conformant Direct partner could supply, and that is
#: the whole argument for putting it on counterparty-chosen material.** DirectTrust's Community X.509
#: Certificate Policy requires end-entity keys of at least 2048 bits, as does the CA/Browser Forum's
#: S/MIME baseline. So this floor cannot break a correspondent who is already following the rules
#: their own certificate was issued under; it refuses only material that no current policy permits.
#:
#: **IT DOES NOT MEET ASVS 11.2.3, AND MUST NOT BE READ AS DOING SO.** The verb asks for 128 bits of
#: security and names RSA-3072 as the equivalent; RSA-2048 is roughly 112. Raising this to 3072 is a
#: SEPARATE and counterparty-facing decision needing partner field data nobody has gathered, and it
#: would be a live availability choice about a hospital's certificate rather than a tightening of our
#: own. What this floor closes is the UNBOUNDED case -- that a deploying site could configure
#: RSA-1024 and nothing would object -- not the requirement.
#:
#: An EC key reaches the verb today with no such conversation: P-256 is 128-bit, and this connector
#: accepts EC signing keys (see :meth:`DirectDestination._select_rsa_padding`).
_MIN_RSA_BITS = 2048

#: EC curves admitted for Direct S/MIME material. All three are at or above 128-bit security, so
#: unlike the RSA floor this list needs no "does not meet the verb" caveat. Named positively so a
#: curve nobody considered is excluded by construction rather than admitted by an absent deny-rule.
_APPROVED_EC_CURVES = frozenset({"secp256r1", "secp384r1", "secp521r1"})


def _require_key_strength(key: Any, setting: str) -> None:
    """Refuse Direct S/MIME key material that parses and is the right shape but is too weak to use.

    Applied to all three operator-supplied surfaces. Two of them are counterparty-chosen -- the
    partner's ``recipient_cert`` and the issuing ``trust_anchor`` -- which is normally a reason for
    caution, because refusing someone else's certificate is an availability decision about their
    infrastructure rather than a tightening of ours. It is safe at THIS value for the reason recorded
    on :data:`_MIN_RSA_BITS`: no certificate policy governing Direct permits what it refuses.

    A key type this connector cannot classify passes rather than raises. The floor exists to catch a
    weak key of a KNOWN type; turning it into a second, silent type gate would refuse Ed25519 on a
    day someone adds it, for a reason that has nothing to do with strength.
    """
    if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)) and key.key_size < _MIN_RSA_BITS:
        raise ValueError(
            f"Direct destination '{setting}' is RSA-{key.key_size}, below the {_MIN_RSA_BITS}-bit "
            f"floor for Direct S/MIME material (DirectTrust and CA/Browser Forum S/MIME both require "
            f"at least {_MIN_RSA_BITS}). Supply key material of at least {_MIN_RSA_BITS} bits."
        )
    if (
        isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey))
        and key.curve.name not in _APPROVED_EC_CURVES
    ):
        approved = ", ".join(sorted(_APPROVED_EC_CURVES))
        raise ValueError(
            f"Direct destination '{setting}' uses EC curve {key.curve.name!r}, which is not on "
            f"the approved list ({approved}). Supply a key on an approved curve."
        )


#: The RSA signature paddings an operator may select for the CMS SignerInfo, by ``signature_padding``
#: setting value (ASVS 11.3.1, BACKLOG #1168). ``pkcs1v15`` is the default and stays the default: see
#: :meth:`DirectDestination._select_rsa_padding` for why that is an interoperability finding rather
#: than an oversight, and what it would take to move it.
_RSA_SIGNATURE_PADDINGS: dict[str, str] = {
    "pkcs1v15": "RSASSA-PKCS1-v1_5",
    "pss": "RSASSA-PSS",
}


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
        # #323: server-certificate verification on the TLS hop, kept byte-identical to
        # EmailDestination's spelling (this connector's SMTP core is a deliberate copy, not an import —
        # the one-way dependency rule — so the two must not drift).
        self.tls_verify = bool(s.get("tls_verify", True))
        tls_ca_file = s.get("tls_ca_file")
        self.tls_ca_file: str | None = str(tls_ca_file) if tls_ca_file else None
        self.tls_check_hostname = bool(s.get("tls_check_hostname", True))
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
        # The signing cert's public half is compared byte-for-byte against this key just above, so
        # flooring the key covers the cert too -- they cannot differ by the time this runs.
        _require_key_strength(self._signing_key, "signing_key")
        # Which RSA padding the CMS SignerInfo carries. Parsed AFTER the key loads because the
        # validation needs the key's type: `pss` on an EC key is refused here rather than at wire time.
        self.signature_padding: str = self._parse_signature_padding(s.get("signature_padding"))
        self._rsa_padding: padding.PSS | padding.PKCS1v15 | None = self._select_rsa_padding()
        # Per-partner recipient certificate — the encryption target. Direct is 1:1 with a HISP
        # correspondent, so PR1 supports a single recipient cert (a per-recipient cert map is a later
        # phase, ADR 0085).
        self._recipient_cert = _load_cert(
            "recipient_cert", _read_file("recipient_cert", s.get("recipient_cert"))
        )
        _require_key_strength(self._recipient_cert.public_key(), "recipient_cert")
        # Trust anchor — the CA(s) the recipient cert must chain to. Verified at construction so a cert
        # from an untrusted issuer is refused before we ever encrypt PHI to it.
        self._verify_recipient_trusted(_read_file("trust_anchor", s.get("trust_anchor")))

        # STARTTLS-by-default posture, identical to EmailDestination: the S/MIME body already protects
        # PHI, but the SMTP session still carries envelope metadata + any AUTH credentials, so cleartext
        # SMTP is refused unless the project-wide dev escape is set, and credentials are NEVER sent over
        # a cleartext channel.
        if not self.use_tls:
            # #323: read through the CLAMPED escape, not the raw insecure_tls_allowed(). This call site
            # was the last unclamped one in the file, sitting one branch away from the clamped arm
            # below — two different escapes in one connector is how the next bug gets written. The
            # change strictly ADDS refusals (ADR 0092 decision 5): an enforcing production-PHI instance
            # can no longer silence a cleartext Direct hop with the blunt process-wide env var.
            #
            # THE ESCAPE STILL EXISTS — it is CLAMPED, not removed. Stated because this file now has
            # NO CALL to `insecure_tls_allowed()` (only these comments mention it), and reading that
            # as "this connector has no escape" would be a FALSE ABSENCE claim.
            # MEFOR_ALLOW_INSECURE_TLS still governs this hop: weakened_tls_escape_permitted_here() is
            # that same env var plus the production-PHI clamp. Any absence claim about the raw call is
            # scoped to THIS FILE and never repo-wide — `insecure_tls_allowed()` remains live at call
            # sites in auth/ldap.py, pipeline/alert_sinks.py, transports/{ai_broker,database,mllp}.py
            # and config/settings.py (docs/DEPLOYMENT.md enumerates the ones the clamp does not yet
            # cover — see #329). Verified by grep at the time of writing, not assumed.
            if not weakened_tls_escape_permitted_here():
                raise ValueError(
                    "Direct destination use_tls=false submits over cleartext SMTP; refused unless "
                    f"{INSECURE_TLS_ESCAPE_ENV} is set (dev/trusted-network only, and refused on a "
                    "production-PHI instance even with the escape, #200) — use STARTTLS (the default)"
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
        elif not self.tls_verify:
            # #323 arm 2 — same shape and wording as EmailDestination's, deliberately.
            if not weakened_tls_escape_permitted_here():
                raise ValueError(
                    "Direct destination tls_verify=false disables server-certificate verification on "
                    f"the SMTP hop to {self.host} — the session is encrypted but UNAUTHENTICATED. The "
                    "S/MIME body still protects the clinical payload, but envelope metadata and any "
                    "SMTP AUTH credential are exposed to an on-path attacker presenting any "
                    "certificate. Use a trusted CA (tls_ca_file, or [tls].internal_ca_file for the "
                    f"instance), or set {INSECURE_TLS_ESCAPE_ENV}=1 to allow it on a trusted-network "
                    "bind (refused on a production-PHI instance even with the escape, #200)."
                )
            if self.username is not None:
                raise ValueError(
                    "Direct destination sends SMTP AUTH credentials over an UNVERIFIED TLS session "
                    "(tls_verify=false); refused — credentials require a verified TLS session"
                )
        else:
            # BACKLOG #1314: the THIRD weakening axis. The chain IS verified here, but with
            # `tls_check_hostname=false` the peer NAME is not, so any certificate chaining to the
            # configured anchor is accepted whatever it was issued to -- the AUTH exchange then
            # hands the credential to a peer whose identity was never established.
            #
            # ABSOLUTE, like the two arms above, and deliberately keyed on no escape: in both of
            # them the escape governs the BODY posture and never the CREDENTIAL. A third arm keeps
            # that split, so a hop cannot attest its way to a credentialed unverified-name session.
            if not self.tls_check_hostname and self.username is not None:
                raise ValueError(
                    "Direct destination sends SMTP AUTH credentials over a TLS session whose peer "
                    "NAME is unverified (tls_check_hostname=false); refused — credentials "
                    "require a session bound to the host, not merely to the trust anchor"
                )
        # Built once at construction (fail-fast), reused by every send. None when TLS is off entirely.
        # DIRECT does not take a RevocationHopGuard even though the hop now verifies: adding it would
        # make the enumerated count eight and force four "seven verifying hops" docs to change, and the
        # clinical payload is S/MIME-protected at the message layer so the PHI argument is materially
        # weaker than EMAIL's (ADR 0085). Recorded rather than silently omitted.
        self._tls_context: ssl.SSLContext | None = (
            build_smtp_tls_context(
                host=self.host,
                cell="Direct destination",
                verify=self.tls_verify,
                ca_file=self.tls_ca_file,
                check_hostname=self.tls_check_hostname,
                trust_anchor_policy=config.trust_anchor_policy,
            )
            if self.use_tls
            else None
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

    def _parse_signature_padding(self, value: Any) -> str:
        """Validate the ``signature_padding`` setting, defaulting to ``pkcs1v15``.

        Refuses an unknown value **and** ``pss`` on a non-RSA key at construction, so both fail at
        ``check``/dry-run/start rather than on the first message. The second refusal is not defensive
        tidiness: ``add_signer(..., rsa_padding=...)`` raises ``TypeError: Padding is only supported
        for RSA keys``, so an EC signer plus ``pss`` would otherwise abort every delivery at wire time.
        """
        if value is None:
            return "pkcs1v15"
        choice = str(value).strip().lower()
        if choice not in _RSA_SIGNATURE_PADDINGS:
            allowed = ", ".join(sorted(_RSA_SIGNATURE_PADDINGS))
            raise ValueError(
                f"Direct destination 'signature_padding' must be one of: {allowed} (got {choice!r})"
            )
        if choice == "pss" and not isinstance(self._signing_key, rsa.RSAPrivateKey):
            raise ValueError(
                "Direct destination 'signature_padding=pss' requires an RSA 'signing_key'; this key "
                "is EC (ECDSA), which has no padding parameter. Remove the setting — an EC signer "
                "already avoids PKCS#1 v1.5 entirely."
            )
        return choice

    def _select_rsa_padding(self) -> padding.PSS | padding.PKCS1v15 | None:
        """The padding object handed to ``add_signer``, or ``None`` to leave the library default.

        **Why ``pkcs1v15`` is still the default, and what would change it.** ASVS 11.3.1 names PKCS#1
        v1.5 as a weak padding scheme, so the honest end state is an RSASSA-PSS default. It is not the
        default here because the counterparty chose the verifier: a Direct/HISP peer must be able to
        VERIFY what this engine signs, and an S/MIME stack that only implements PKCS#1 v1.5 rejects a
        PSS SignerInfo outright. That is the same distinction ``transports/signing.py`` draws for its
        key-strength floor -- a setting nobody else chose can be tightened unilaterally, a setting the
        far side must interoperate with cannot. Moving the default needs partner PSS support data that
        has not been gathered, not a code change.

        **The escape from the dilemma is a different key type.** An EC (ECDSA) ``signing_key`` reaches
        an approved signature with no padding parameter at all, and this connector already accepts one.

        **The key-transport half of the message is NOT addressed here and cannot be.** Measured
        against the pinned ``cryptography`` (50.0.1, ``requirements.lock``):
        ``PKCS7EnvelopeBuilder.add_recipient()`` takes only a certificate, ``encrypt()`` takes only an
        encoding and an option list, and neither exposes RSAES-OAEP -- a DER envelope built by this
        library carries the ``rsaEncryption`` key-transport OID and no reachable alternative. So the
        enveloped half of every Direct message would use RSAES-PKCS1-v1_5 on a first deployment
        regardless of this setting, and closing that would mean leaving the pinned library for a
        hand-built CMS path. Stated so this setting is not misread as covering the whole message.
        """
        if self.signature_padding == "pss":
            # SHA-256 throughout: the digest is already SHA-256 at add_signer, and DIGEST_LENGTH keeps
            # the salt equal to it, which is the widely-interoperable PSS parameter set.
            return padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH
            )
        # None, not an explicit PKCS1v15() object: the library treats them identically for RSA, and
        # None is also the only value an EC key accepts, so one branch covers both key types.
        return None

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
        # Floored BEFORE the issuance check, so a weak anchor is refused whether or not it happens to
        # be the one that issues this recipient. The loop below returns on the first match, so
        # checking inside it would leave a weak sibling anchor unexamined and still trusted.
        for anchor in anchors:
            _require_key_strength(anchor.public_key(), "trust_anchor")
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
        #   * rsa_padding  — the operator's `signature_padding` choice (ASVS 11.3.1, #1168). None keeps
        #                    the library default (RSASSA-PKCS1-v1_5) and is the only value an EC key
        #                    accepts; `pss` selects RSASSA-PSS. Passed as a keyword rather than
        #                    branching the builder chain, so there is one call site to read.
        builder = (
            pkcs7.PKCS7SignatureBuilder()
            .set_data(body)
            .add_signer(
                self._signing_cert,
                self._signing_key,
                hashes.SHA256(),
                rsa_padding=self._rsa_padding,
            )
        )
        signed = builder.sign(
            serialization.Encoding.DER,
            [pkcs7.PKCS7Options.NoAttributes, pkcs7.PKCS7Options.Binary],
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
            # context= is REQUIRED (#323) — SMTP_SSL's own default is an unverified stdlib context.
            return smtplib.SMTP_SSL(
                self.host, self.port, timeout=self.timeout, context=self._tls_context
            )
        smtp = smtplib.SMTP(self.host, self.port, timeout=self.timeout)
        if self.use_tls:
            smtp.starttls(context=self._tls_context)
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
                    # NOT smtp.login(): it tries CRAM-MD5 FIRST, an HMAC over MD5 (BACKLOG
                    # #1171, ASVS 11.4.1). The helper's cleartext-AUTH refusal is absolute,
                    # matching this cell's construction gate -- a send-time backstop that is
                    # weaker than the gate it backs up is a hole.
                    smtp_login_approved(
                        smtp,
                        self.username,
                        self.password or "",
                        channel_encrypted=self.use_tls,
                        cell="DIRECT outbound",
                    )
                smtp.send_message(msg)
        except InsecureHopRefused as exc:
            # A POLICY refusal is not an internal code error. Unconverted it is a ValueError,
            # which escapes the arms below and lands in the delivery worker's catch-all --
            # labelled "internal error (our bug, not the partner)" and dead-lettered. That
            # sends an operator to read our source over a partner that offers no approved AUTH
            # mechanism, or a connection configured without TLS. Same misdirection as mapping a
            # rejected credential to a refusal, one layer down (BACKLOG #1171).
            #
            # The refusal text is config and capability only -- host, cell, mechanism names --
            # so it is carried whole rather than reduced to a type name: it is the one thing an
            # operator needs and it contains no message content.
            raise DeliveryError(f"Direct {self.host}:{self.port} refused: {exc}") from exc
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
                    # Same restriction as _send: a probe that authenticated via CRAM-MD5
                    # would report a hop healthy that the real send path refuses.
                    smtp_login_approved(
                        smtp,
                        self.username,
                        self.password or "",
                        channel_encrypted=self.use_tls,
                        cell="DIRECT outbound probe",
                    )
                smtp.noop()
        except InsecureHopRefused as exc:
            # A POLICY refusal is not an internal code error. Unconverted it is a ValueError,
            # which escapes the arms below and lands in the delivery worker's catch-all --
            # labelled "internal error (our bug, not the partner)" and dead-lettered. That
            # sends an operator to read our source over a partner that offers no approved AUTH
            # mechanism, or a connection configured without TLS. Same misdirection as mapping a
            # rejected credential to a refusal, one layer down (BACKLOG #1171).
            #
            # The refusal text is config and capability only -- host, cell, mechanism names --
            # so it is carried whole rather than reduced to a type name: it is the one thing an
            # operator needs and it contains no message content.
            raise DeliveryError(f"Direct {self.host}:{self.port} refused: {exc}") from exc
        except smtplib.SMTPException as exc:
            raise DeliveryError(
                f"Direct {self.host}:{self.port} probe failed: {type(exc).__name__}"
            ) from exc
        except (TimeoutError, OSError) as exc:
            raise DeliveryError(
                f"Direct {self.host}:{self.port} unreachable: {type(exc).__name__}"
            ) from exc


register_destination(ConnectorType.DIRECT, DirectDestination)
