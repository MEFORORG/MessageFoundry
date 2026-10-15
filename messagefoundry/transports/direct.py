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
  blob (``pkcs7.PKCS7EnvelopeBuilder`` addressed to the partner's recipient cert, content cipher
  AES-256-CBC set explicitly -- see ``_CONTENT_CIPHER``),
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
signing key that does not match its cert, a recipient cert whose key is not RSA, key material of a
type or strength off the floor (``_require_key_strength``), a trial S/MIME build that fails, or a
cleartext-credential misconfiguration **raises here**, so it fails at ``check``/dry-run/start —
never as a wire-time surprise. The blocking crypto + SMTP
exchange runs off the event loop via ``asyncio.to_thread``.

**STARTTLS posture is inherited from EMAIL.** The signed+encrypted S/MIME body already protects PHI at
rest and in flight, but the SMTP session still carries envelope metadata (and any AUTH credentials), so
TLS stays on by default; disabling it is refused unless the project-wide ``MEFOR_ALLOW_INSECURE_TLS``
escape is set on an instance at ``[security].enforcement = warn``, and SMTP AUTH over cleartext is
refused outright (the ``refuse_cleartext_credentials`` rule). One part is not inherited: EMAIL also
lets ``tls_hop_attested`` or ``cleartext_accepted`` cross this gate, and Direct reads neither. The ``[egress].allowed_direct`` allowlist is the authoritative fail-closed host gate (enforced
by the runner at load/reload/start).

**Idempotency.** Delivery is at-least-once, so a retry re-sends the S/MIME message; a Direct mailbox
has no idempotency key, so a rare duplicate is possible after a transient failure between server-accept
and connector-success — documented and accepted (a duplicate beats a drop), exactly like EMAIL.
"""

from __future__ import annotations

import asyncio
import hmac
import logging
import smtplib
import ssl
from collections.abc import Mapping
from email.message import EmailMessage
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import InternalError, InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.serialization import pkcs7

from messagefoundry.config.models import ConnectorType, Destination, bool_setting
from messagefoundry.config.settings import (
    INSECURE_TLS_ESCAPE_ENV,
    weakened_tls_escape_permitted_here,
)
from messagefoundry.config.tls_policy import (
    InsecureHopRefused,
    RevocationHopGuard,
    build_smtp_tls_context,
    smtp_login_approved,
)
from messagefoundry.controlchars import has_lone_surrogate
from messagefoundry.keywrap import key_wrap_refusal
from messagefoundry.transports.base import (
    DeliveryError,
    DeliveryResponse,
    DestinationConnector,
    NegativeAckError,
    encode_wire_body,
    float_setting,
    register_destination,
)
from messagefoundry.transports.email import checked_envelope, refuse_unverified_smtp_credential

__all__ = ["DirectDestination"]

logger = logging.getLogger(__name__)

#: The CMS content-encryption cipher for every Direct envelope: AES-256-CBC. This is the one place
#: that states why; the docs and tests point here. Left unset, ``PKCS7EnvelopeBuilder`` uses
#: AES-128-CBC (measured on ``cryptography`` 50.0.1), and the owner's 2026-09-22 ASVS 11.3.1 ruling
#: accepts AES-256-CBC as this connector's recorded constraint (BACKLOG #1168). CBC because the
#: builder offers nothing else: ``ContentEncryptionAlgorithm`` is ``type[AES128] | type[AES256]``.
#:
#: **What this does NOT change.** The mode is still CBC and the content key is still wrapped with
#: RSAES-PKCS1-v1_5 (see ``_select_rsa_padding``), so this moves neither the mode nor the padding
#: question in 11.3.1; the cell stays partial. And the message is no stronger than that RSA wrap: a
#: 2048-bit recipient key bounds it near 112 bits of security.
_CONTENT_CIPHER: pkcs7.ContentEncryptionAlgorithm = algorithms.AES256

#: The fixed synthetic body :meth:`DirectDestination._probe_build` signs and encrypts at construction.
#: ASCII, so every codec an operator could configure represents it.
_PROBE_BODY = "MessageFoundry DIRECT construction probe"

#: What a failed S/MIME build raises, named once so the construction probe and the send-time arm
#: cannot drift apart. ``UnsupportedAlgorithm`` and ``InternalError`` subclass ``Exception`` rather
#: than ``ValueError``; the first is the reported FIPS refusal (#1921), and the second is how
#: ``cryptography`` surfaces an OpenSSL error it does not map. Neither is reproduced here.
_BUILD_ERRORS: tuple[type[Exception], ...] = (
    ValueError,
    TypeError,
    UnsupportedAlgorithm,
    InternalError,
)


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
#: ``parsing/xml/signature.py`` holds a copy for its XML-DSig key floor (BACKLOG #1166), and a test
#: pins the two equal. A change here changes that floor too, so it needs the same ruling.
_APPROVED_EC_CURVES = frozenset({"secp256r1", "secp384r1", "secp521r1"})

#: The EdDSA key types the floor admits with no size or curve check: each has one fixed size, and
#: both are at or above 128-bit security. Listed so the floor's allowed key TYPES are the same four
#: as the XML-DSig floor's (RSA, EC, Ed25519, Ed448; BACKLOG #3384), and a test pins the two sets.
#:
#: **On the list because Direct can carry them on one surface, the trust anchor.** Measured on the
#: pinned ``cryptography`` (50.0.2): ``verify_directly_issued_by`` checks an RSA recipient cert
#: issued by an Ed25519 or an Ed448 CA. The other two surfaces cannot use EdDSA, and each refuses it
#: with its own type gate, which names the library limit rather than strength. ``recipient_cert``
#: must be RSA because the envelope builder supports nothing else (BACKLOG #1918). ``signing_key``
#: must be RSA or EC because ``add_signer`` raises ``TypeError: Only RSA & EC keys are supported at
#: this time`` for any other key.
_EDDSA_KEY_TYPES: tuple[type, ...] = (
    ed25519.Ed25519PrivateKey,
    ed25519.Ed25519PublicKey,
    ed448.Ed448PrivateKey,
    ed448.Ed448PublicKey,
)


#: The key types the floor admits, as an error message names them.
_ALLOWED_KEY_TYPES_TEXT = "RSA, EC, Ed25519, Ed448"


def _key_type_name(key: Any) -> str:
    """A short, content-free name for a key's type, for an error message: ``DSAPublicKey`` becomes
    ``DSA``. Only the class name is read, never the key material."""
    if isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        return "EC"
    name = type(key).__name__
    return name.removesuffix("PrivateKey").removesuffix("PublicKey") or name


def _cert_public_key(cert: x509.Certificate, setting: str) -> Any:
    """``cert.public_key()``, with a key algorithm ``cryptography`` cannot load refused as a
    ``ValueError`` naming the setting. Unmapped, it raises ``UnsupportedAlgorithm`` ("Unknown key
    type", measured on 50.0.2), which is not a ``ValueError`` and so escapes the construction
    contract. A type nobody can read is not on the allow-list either (BACKLOG #3384)."""
    try:
        return cert.public_key()
    except UnsupportedAlgorithm as exc:
        raise ValueError(
            f"Direct destination '{setting}' holds a key of a type this connector cannot read, so "
            "it is not on the approved list for Direct S/MIME material "
            f"({_ALLOWED_KEY_TYPES_TEXT})."
        ) from exc


def _require_key_strength(key: Any, setting: str) -> None:
    """Refuse Direct S/MIME key material that parses but is of a type or strength not allowed.

    Applied to all three operator-supplied surfaces. Two of them are counterparty-chosen -- the
    partner's ``recipient_cert`` and the issuing ``trust_anchor`` -- which is normally a reason for
    caution, because refusing someone else's certificate is an availability decision about their
    infrastructure rather than a tightening of ours. It is safe at THIS value for the reason recorded
    on :data:`_MIN_RSA_BITS`: no certificate policy governing Direct permits what it refuses.

    THE KEY TYPE IS ALLOW-LISTED, the same four types as the XML-DSig floor in
    ``parsing/xml/signature.py`` (BACKLOG #3384):

    - RSA passes at :data:`_MIN_RSA_BITS` or more.
    - EC passes only on a curve in :data:`_APPROVED_EC_CURVES`.
    - Ed25519 and Ed448 pass; :data:`_EDDSA_KEY_TYPES` says which surface can use them.
    - DSA, and every other type, is refused at any size.

    On ``recipient_cert`` (RSA only) and ``signing_key`` (RSA or EC only) a type gate runs first
    and is stricter than this list, so there the floor checks RSA size and EC curve only. Each gate
    names the one remedy that works on its surface. The type list does its own refusing on
    ``trust_anchor``, the one surface that can carry every type on it.

    This used to pass any type it could not classify, on the reasoning that a strength floor should
    not also be a type gate. That reasoning let a DSA trust anchor through: measured before this
    change, an RSA recipient cert issued by a 2048-bit DSA CA constructed cleanly. A floor that
    passes what it has not considered is not a floor, so a type nobody listed is now refused by
    construction, and adding one is a deliberate edit to this list.
    """
    if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        if key.key_size < _MIN_RSA_BITS:
            raise ValueError(
                f"Direct destination '{setting}' is RSA-{key.key_size}, below the "
                f"{_MIN_RSA_BITS}-bit floor for Direct S/MIME material (DirectTrust and the "
                f"CA/Browser forum's S/MIME rules both require at least {_MIN_RSA_BITS}). Supply "
                f"key material of at least {_MIN_RSA_BITS} bits."
            )
        return
    if isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        if key.curve.name not in _APPROVED_EC_CURVES:
            approved = ", ".join(sorted(_APPROVED_EC_CURVES))
            raise ValueError(
                f"Direct destination '{setting}' uses EC curve {key.curve.name!r}, which is not on "
                f"the approved list ({approved}). Supply a key on an approved curve."
            )
        return
    if isinstance(key, _EDDSA_KEY_TYPES):
        return
    raise ValueError(
        f"Direct destination '{setting}' key type is {_key_type_name(key)}, which is not on the "
        f"approved list for Direct S/MIME material ({_ALLOWED_KEY_TYPES_TEXT}). DSA is refused "
        f"at any size. Supply an RSA key of at least {_MIN_RSA_BITS} bits, an EC key on an "
        "approved curve, or an Ed25519 or Ed448 key."
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
        # The Email destination's address rule, for the sender and each recipient, with the headers
        # built from the checked text. MAIL FROM and RCPT TO are then passed explicitly at send, so a
        # header parse that decodes an encoded word or expands a group cannot move the envelope
        # (vault BACKLOG #2870). Checked before the crypto material, so _probe_build uses it too.
        self._envelope = checked_envelope("Direct destination", sender, s.get("recipients"))
        self.recipients = list(self._envelope.recipients)
        self.subject = str(s.get("subject", ""))
        # The Email destination's rule. _probe_build below does not catch every surrogate; the
        # has_lone_surrogate docstring says which (vault BACKLOG #2842).
        if has_lone_surrogate(self.subject):
            raise ValueError("Direct destination 'subject' holds a lone surrogate")
        username = s.get("username")
        password = s.get("password")
        self.username: str | None = str(username) if username else None
        self.password: str | None = str(password) if password else None
        self.use_tls = bool_setting(s, "use_tls", default=True)
        # #323: server-certificate verification on the TLS hop, kept byte-identical to
        # EmailDestination's spelling. This connector's TLS and AUTH handling is a copy of that
        # connector's, so the two must not drift; its envelope check is imported from
        # transports/email.py (checked_envelope, vault BACKLOG #2870).
        self.tls_verify = bool_setting(s, "tls_verify", default=True)
        tls_ca_file = s.get("tls_ca_file")
        self.tls_ca_file: str | None = str(tls_ca_file) if tls_ca_file else None
        self.tls_check_hostname = bool_setting(s, "tls_check_hostname", default=True)
        self.timeout: float = float_setting(
            s.get("timeout_seconds", 30.0), knob="timeout_seconds", transport="Direct destination"
        )
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
        # RSA or EC only, because the signer is. add_signer raises `TypeError: Only RSA & EC keys
        # are supported at this time` for any other key (cryptography 50.0.2), so an Ed25519 or
        # Ed448 signer, which the floor admits, would otherwise reach the build probe and be refused
        # there in the library's words. Runs BEFORE the floor, like the recipient's RSA-only gate:
        # it is stricter than the floor's type list, so it refuses DSA and unlisted types too, named
        # by type, with the one remedy that works on this surface (BACKLOG #3384). After this line
        # the signer is RSA or EC, which the padding check below relies on.
        if not isinstance(self._signing_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
            kind = _key_type_name(self._signing_key)
            raise ValueError(
                f"Direct destination 'signing_key' key type is {kind}; "
                "S/MIME signing here supports only RSA and EC signing keys, so every send would "
                f"fail. Supply an RSA key of at least {_MIN_RSA_BITS} bits or an EC key on an "
                "approved curve."
            )
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
        recipient_key = _cert_public_key(self._recipient_cert, "recipient_cert")
        # RSA only, because the envelope is. The pinned cryptography's PKCS7EnvelopeBuilder raises
        # `TypeError: Only RSA keys are supported at this time` for any other recipient key, so an EC
        # cert would construct cleanly and then fail every send (BACKLOG #1918). The signer and the
        # trust anchor are not held to RSA, because add_signer and verify_directly_issued_by both
        # take EC; they meet the floor's key-type allow-list instead (BACKLOG #3384).
        #
        # This gate runs BEFORE the floor on purpose. It is stricter than the floor's type list, so
        # a DSA or unlisted recipient key is refused here, named by type, with the one remedy that
        # works on this surface. Run the other way, an EC key on an unapproved curve would be told
        # to move to an approved curve, and then be refused here.
        if not isinstance(recipient_key, rsa.RSAPublicKey):
            raise ValueError(
                f"Direct destination 'recipient_cert' key type is {_key_type_name(recipient_key)}; "
                "S/MIME encryption here supports only RSA recipient keys, so every send would "
                "fail. Supply the partner's RSA encryption certificate."
            )
        _require_key_strength(recipient_key, "recipient_cert")
        # Trust anchor — the CA(s) the recipient cert must chain to. Verified at construction so a cert
        # from an untrusted issuer is refused before we ever encrypt PHI to it.
        self._verify_recipient_trusted(_read_file("trust_anchor", s.get("trust_anchor")))
        self._probe_build()

        # STARTTLS-by-default posture, identical to EmailDestination: the S/MIME body already protects
        # PHI, but the SMTP session still carries envelope metadata, so cleartext SMTP is refused
        # unless the project-wide dev escape is set. The credential refusal is Email's, and runs
        # first for Email's reason: no lever the arms below name lifts it (vault BACKLOG #3230).
        refuse_unverified_smtp_credential(
            "Direct destination",
            connection=config.name,
            username=self.username,
            use_tls=self.use_tls,
            tls_verify=self.tls_verify,
            tls_check_hostname=self.tls_check_hostname,
        )
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
                    f"{INSECURE_TLS_ESCAPE_ENV} is set on an instance at [security].enforcement = warn "
                    "(dev/trusted-network only; the escape has no effect while enforcing, the default, "
                    "or with no posture) — use STARTTLS (the default)"
                )
            logger.warning(
                "Direct destination %s has TLS disabled (use_tls=false); the SMTP session crosses the "
                "network in CLEARTEXT (dev/trusted-network only)",
                self.host,
            )
        elif not self.tls_verify:
            # #323 arm 2 — same shape and wording as EmailDestination's, deliberately.
            if not weakened_tls_escape_permitted_here():
                raise ValueError(
                    "Direct destination tls_verify=false disables server-certificate verification on "
                    f"the SMTP hop to {self.host} — the session is encrypted but UNAUTHENTICATED. The "
                    "S/MIME body still protects the clinical payload, but envelope metadata is exposed "
                    "to an on-path attacker presenting any certificate. Use a trusted CA "
                    "(tls_ca_file, or [tls].internal_ca_file for the instance), or set "
                    f"{INSECURE_TLS_ESCAPE_ENV}=1 on an instance at "
                    "[security].enforcement = warn to allow it on a trusted-network bind (the escape "
                    "has no effect while enforcing, the default, or with no posture)."
                )
        # Built once at construction (fail-fast), reused by every send. None when TLS is off entirely.
        # DIRECT WITH NO SMTP CREDENTIAL does not take a RevocationHopGuard even though the hop now
        # verifies: the clinical payload is S/MIME-protected at the message layer, so the PHI
        # argument is materially weaker than EMAIL's (ADR 0085). Recorded rather than silently
        # omitted; the decision is unchanged for that case. It never covered a hop that also sends a
        # credential, and that hop is guarded below (BACKLOG #2193).
        #
        # THE SECOND REASON THIS COMMENT USED TO GIVE IS WITHDRAWN, and it is worth saying why rather
        # than deleting it. It read: adding the guard "would make the enumerated count eight and force
        # four 'seven verifying hops' docs to change". That is a documentation cost, not a security
        # argument, and ADR 0173 §4.3 cited this very sentence as evidence that a hardened count had
        # started deciding what gets guarded -- which is the SDS-3.6 defect, a completeness claim
        # reading as coverage. BACKLOG #1498 then moved the count anyway (seven to nine) and rewrote
        # those docs as "at least", so the cost it named is both paid and no longer chargeable. If
        # DIRECT is ever reconsidered, weigh the S/MIME reasoning above and nothing about a count.
        self._tls_context: ssl.SSLContext | None = (
            build_smtp_tls_context(
                host=self.host,
                cell="Direct destination",
                verify=self.tls_verify,
                ca_file=self.tls_ca_file,
                check_hostname=self.tls_check_hostname,
                trust_anchor_policy=config.trust_anchor_policy,
                name=config.name,
            )
            if self.use_tls
            else None
        )
        # BACKLOG #2193 (ADR 0173): the credential leg. S/MIME protects the message body. It does
        # not protect the SMTP authentication exchange, which hands the username and password to
        # whichever peer the certificate names, and stdlib ssl checks no OCSP or CRL, so a revoked
        # certificate would still be accepted there. Taken only when a username is set, which is
        # the S/MIME decline above narrowed to the case it argues. Called AFTER the context exists
        # and handed it, so a [tls].crl_file that reached this hop relaxes the refusal. The three
        # refusals above already require a credentialed hop to use TLS and to verify both the chain
        # and the name, so the context here always verifies.
        if self.username is not None:
            RevocationHopGuard.capture(
                host=self.host,
                # "SMTP authentication", not the two-word all-capital spelling: the log redaction
                # scrubs two adjacent all-capital tokens, and that label reached the log redacted.
                cell="Direct destination (SMTP authentication over verified TLS)",
                description=(
                    "sends its SMTP authentication credential over verified TLS on SMTP "
                    "(no revocation check)"
                ),
                attested=config.tls_revocation_attested,
                attested_reason=config.tls_revocation_attested_reason,
                connection=config.name,
                context=self._tls_context,
            ).enforce_construction()

    def _load_private_key(self, value: Any, password: Any) -> Any:
        """Load the sender's signing private key (PEM/DER, optionally passphrase-protected). PHI/secret-
        safe: never echo the key bytes or the passphrase."""
        data = _read_file("signing_key", value)
        pw: bytes | None = None
        if password:
            pw = str(password).encode("utf-8")
        # BACKLOG #1352 / #1171: read the passphrase wrap before cryptography derives a key through
        # it, on the PEM and the DER paths alike.
        refusal = key_wrap_refusal(
            data,
            setting="Direct destination 'signing_key'",
            unlock_setting="'signing_key_password'",
            passphrase_given=pw is not None,
        )
        if refusal is not None:
            raise ValueError(refusal)
        # UnsupportedAlgorithm too: a key of a type cryptography cannot load raises it, and it is
        # not a ValueError, so unmapped it would escape the construction contract (BACKLOG #3384).
        try:
            return serialization.load_pem_private_key(data, password=pw)
        except (ValueError, TypeError, UnsupportedAlgorithm):
            try:
                return serialization.load_der_private_key(data, password=pw)
            except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
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
        cert_pub = _cert_public_key(self._signing_cert, "signing_cert").public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        # Constant-time over the DER bytes (ASVS 11.2.4, BACKLOG #1167): `!=` stops at the first
        # differing byte. Both operands are public keys, so this closes a bare compare on key
        # material rather than a secret leak; the requirement's verb asks for no short-circuit.
        if not hmac.compare_digest(key_pub, cert_pub):
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
            _require_key_strength(_cert_public_key(anchor, "trust_anchor"), "trust_anchor")
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

    def _probe_build(self) -> None:
        """Build one S/MIME message from a fixed synthetic body, so a build fault fails at
        ``check``/dry-run/start and not on every message.

        Every build input except the body is fixed by now: keys, certs, cipher, subject, addresses
        and codec. A fault in any of them would repeat on every send, and the send-time arm maps a
        build failure to a permanent per-message dead-letter, so without this a connection-wide fault
        (a FIPS OpenSSL refusing the envelope builder, a library that stopped accepting a key, a
        line break inside the subject) would quietly drain the whole queue into the dead-letter
        store. The body is synthetic, so the library's own text is safe to show.

        An unknown ``encoding`` never gets this far on a config path: ``build_check_registry``
        refuses it first (``resolved_encoding_problems``)."""
        try:
            self._build_smime(_PROBE_BODY)
        except _BUILD_ERRORS as exc:
            raise ValueError(
                "Direct destination could not build an S/MIME message from its settings: "
                f"{type(exc).__name__}: {exc}"
            ) from exc

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
        # The shared helper, not a bare .encode(): a UnicodeEncodeError carries the WHOLE payload on
        # `.object`, and the helper raises a content-free error with that chain severed (#1920).
        body = encode_wire_body(payload, self.encoding, transport=f"Direct {self.host}:{self.port}")
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
        # The content cipher is set explicitly; _CONTENT_CIPHER says why and what it does not change.
        enveloped = (
            pkcs7.PKCS7EnvelopeBuilder()
            .set_data(signed)
            .set_content_encryption_algorithm(_CONTENT_CIPHER)
            .add_recipient(self._recipient_cert)
            .encrypt(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary])
        )
        msg = EmailMessage()
        msg["Subject"] = self.subject
        self._envelope.address(msg)
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
        # PHI, or the password. A build failure here is a last resort: _probe_build already built one
        # message from these exact settings at construction, so what reaches this arm changed since
        # (the host's crypto policy, say). It is deterministic, so it is a PERMANENT NegativeAckError:
        # the delivery worker dead-letters it on the first attempt. A plain DeliveryError is the
        # transient class and would be retried to the attempt ceiling for a message that can never
        # build (BACKLOG #1919). An un-encodable body is already permanent: encode_wire_body raises
        # it, and this arm does not catch it.
        #
        # UnsupportedAlgorithm is caught too: it subclasses Exception, not ValueError, so it escaped
        # this arm to the worker's "internal error" path. Reported for a FIPS-enabled OpenSSL, where
        # the envelope builder refuses to construct; mapped defensively, NOT reproduced (#1921).
        #
        # The raise sits OUTSIDE the handler on purpose (BACKLOG #1920): `from exc` would chain the
        # build error as `__cause__`, and `from None` would still leave it on `__context__`. Only the
        # type NAME survives the handler. See `encode_wire_body` in transports/base.py.
        msg: EmailMessage | None = None
        failure = ""
        try:
            msg = self._build_smime(payload)
        except _BUILD_ERRORS as exc:
            failure = type(exc).__name__
        if msg is None:
            # The worker's permanent path dead-letters without a log line, so say it here. Type name
            # only, for the same reason as the error text.
            logger.warning(
                "Direct %s:%s: S/MIME build failed (%s); dead-lettering without retry",
                self.host,
                self.port,
                failure,
            )
            raise NegativeAckError(
                f"Direct {self.host}:{self.port} S/MIME build failed: {failure} (no retry)",
                code="smime-build",
                permanent=True,
            )
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
                self._envelope.send(smtp, msg)
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
