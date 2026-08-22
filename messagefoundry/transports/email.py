# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Email transport: an SMTP destination that delivers each transformed payload as an email (ADR 0029).

The **destination** sends one payload (the email *body*, already produced by the Handler) as a
plain-text SMTP message to a configured server and maps the outcome onto the engine's retry model:

- **send accepted** → delivered (returns ``None`` — a one-way delivery, no application reply to
  capture, exactly like File).
- **connect/EHLO/STARTTLS/AUTH/send failure** (``smtplib.SMTPException`` / ``OSError`` /
  ``TimeoutError``) → :class:`DeliveryError` (transient — the staged queue retries with backoff).

Standard library only (``smtplib`` + ``email.message``) — no new dependency (ADR 0029 §"What this
must not break"; CLAUDE.md §7). The synchronous SMTP core is **lifted** from
``pipeline/alert_sinks.py``'s ``send_plain_email`` (a transport must not import ``pipeline/`` — the
one-way dependency rule, CLAUDE.md §4); the two copies are deliberately independent.

**STARTTLS by default** (``use_tls=True``): the connector issues ``STARTTLS`` before ``AUTH``/data on
the ``587`` submission port; port ``465`` (implicit TLS) maps to ``smtplib.SMTP_SSL``. Disabling TLS
(``use_tls=False``) is **refused unless** the project-wide dev escape ``MEFOR_ALLOW_INSECURE_TLS`` is
set — read through the CLAMPED ``weakened_tls_escape_permitted_here()`` (#200, ADR 0092), so the blunt
global escape can no longer silence a cleartext hop on an enforcing production-PHI instance — or the
connection attests the hop (``tls_hop_attested``). Credentials are **never** sent over a cleartext
channel (a ``username``/``password`` with ``use_tls=False`` raises at construction, even with the
escape) — the same ``refuse_cleartext_credentials`` posture the REST destination takes. The message
**body** is PHI on that same cleartext hop, so it is additionally governed by the shared
:class:`~messagefoundry.transports.mllp.InsecureHopGuard` gradient every other cleartext-egress
transport consumes (refuse enforcing-production-PHI off-loopback, warn non-enforcing PHI, allow
loopback / synthetic / attested), rather than the bare warning it used to get. The
``[egress].allowed_smtp`` allowlist is the authoritative fail-closed host gate (enforced by the runner
at load/reload/start).

**Idempotency.** Delivery is at-least-once, so a retry **re-sends** the email; a mailbox has no
idempotency key, so a rare duplicate is possible after a transient failure between server-accept and
connector-success — **documented and accepted** (ADR 0029), a duplicate beats a drop. See
docs/CONNECTIONS.md.

There is **no email source yet** — an inbound IMAP/POP read + M365/Google XOAUTH2 is Phase 2 (ADR
0029), out of scope here.
"""

from __future__ import annotations

import asyncio
import logging
import smtplib
import ssl
from collections.abc import Mapping
from email.message import EmailMessage
from typing import Any

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import (
    INSECURE_TLS_ESCAPE_ENV,
    weakened_tls_escape_permitted_here,
)
from messagefoundry.config.tls_policy import (
    RevocationHopGuard,
    build_smtp_tls_context,
    smtp_login_approved,
)
from messagefoundry.transports.base import (
    DeliveryError,
    DeliveryResponse,
    DestinationConnector,
    register_destination,
)
from messagefoundry.transports.mllp import InsecureHopGuard

__all__ = ["EmailDestination"]

logger = logging.getLogger(__name__)


def _as_recipients(value: Any) -> list[str]:
    """Coerce the ``recipients`` setting to a non-empty list of address strings (a lone string is
    treated as a single recipient). Raises :class:`ValueError` for an empty/invalid value."""
    if isinstance(value, str):
        recipients = [value] if value else []
    elif isinstance(value, (list, tuple)):
        recipients = [str(item) for item in value if str(item)]
    else:
        recipients = []
    if not recipients:
        raise ValueError("Email destination requires a non-empty 'recipients' setting")
    return recipients


class EmailDestination(DestinationConnector):
    """Deliver each transformed payload as a plain-text SMTP email (outbound only — ADR 0029 Phase 1).

    Validated loud at construction (a missing ``host``/``sender``/``recipients`` or a cleartext-
    credential misconfiguration raises here, so it fails at ``check``/dry-run/start, not as a wire-time
    surprise — the ``RestDestination`` pattern). The blocking SMTP exchange runs off the event loop via
    ``asyncio.to_thread`` inside :meth:`send`.
    """

    def __init__(self, config: Destination) -> None:
        s = config.settings
        host = s.get("host")
        if not isinstance(host, str) or not host:
            raise ValueError("Email destination requires a 'host' setting")
        sender = s.get("sender")
        if not isinstance(sender, str) or not sender:
            raise ValueError("Email destination requires a 'sender' setting")
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
        # #323: server-certificate verification on the TLS hop. Defaults ON — smtplib's own default is
        # an UNVERIFIED context, so before this the encrypted session was unauthenticated.
        self.tls_verify = bool(s.get("tls_verify", True))
        tls_ca_file = s.get("tls_ca_file")
        self.tls_ca_file: str | None = str(tls_ca_file) if tls_ca_file else None
        self.tls_check_hostname = bool(s.get("tls_check_hostname", True))
        self.timeout: float = float(s.get("timeout_seconds", 30.0))
        self.encoding: str = str(s.get("encoding", "utf-8"))

        # STARTTLS-by-default posture, mirroring RestDestination's verify_tls /
        # refuse_cleartext_credentials handling. Disabling TLS puts the body (PHI) and any AUTH
        # credentials on the wire in cleartext, so it is refused unless the project-wide dev escape is
        # set. The escape is the SAME project-wide gate every sibling connector uses — not a new
        # mechanism — but it is now read through the CLAMPED weakened_tls_escape_permitted_here()
        # (#200, ADR 0092 decision 2) rather than the raw insecure_tls_allowed(): the blunt global
        # escape must not silence a cleartext hop on an ENFORCING production-PHI instance, exactly as
        # it no longer does for MLLP/FTPS tls_verify=false or credentialed plain-ftp. A per-connection
        # `tls_hop_attested` also satisfies this opt-in gate, so an operator who has attested the hop
        # is legitimately secure (a trusted segment / on-box relay) is not forced to ALSO set a blunt
        # process-wide env var — without this, attestation would be dead config on EMAIL alone.
        self._hop_guard: InsecureHopGuard | None = None
        if not self.use_tls:
            # ADR 0153: `cleartext_accepted` joins this disjunction. The pre-gate fires BEFORE the shared
            # authority below, so without this arm an SMTP outbound that declared the acceptance would
            # still be refused here and the declaration would be dead config on EMAIL alone — exactly the
            # trap `tls_hop_attested` was added to this gate to avoid. Passing the pre-gate is not
            # permission to cross: the guard below still decides the hop, and an accepted hop is WARNed
            # and audited there, never silently allowed.
            if not (
                weakened_tls_escape_permitted_here()
                or config.tls_hop_attested
                or config.cleartext_accepted
            ):
                raise ValueError(
                    "Email destination use_tls=false sends the message (and any credentials) over "
                    f"cleartext SMTP; refused unless {INSECURE_TLS_ESCAPE_ENV} is set "
                    "(dev/trusted-network only), or the connection sets tls_hop_attested=true (the hop "
                    "IS secure by other means) or cleartext_accepted=true with a cleartext_reason (the "
                    "hop is NOT secure and that is accepted) — use STARTTLS (the default)."
                )
            # Credentials over an un-encrypted channel are never allowed, even with the escape: a
            # cleartext AUTH puts the password on the wire (the refuse_cleartext_credentials rule).
            if self.username is not None:
                raise ValueError(
                    "Email destination sends SMTP AUTH credentials over cleartext (use_tls=false); "
                    "refused — credentials require STARTTLS/implicit TLS"
                )
            # #200 (ADR 0092): the credential is refused outright above, but the message BODY is PHI and
            # was previously only WARNed about before being put on the wire — a warn where the (strictly
            # less sensitive) credential got a refusal. Route the body decision through the ONE shared
            # authority every other cleartext-egress transport consumes (raw TCP / X12 / plaintext DIMSE /
            # anonymous FTP), so SMTP decides identically: REFUSE an enforcing production-PHI hop
            # off-loopback, WARN a non-enforcing PHI hop, ALLOW loopback / synthetic / per-connection-
            # attested. No-op off the enforced construction gate (posture unstamped), so no existing
            # dev/lab lane that already carried the escape breaks.
            self._hop_guard = InsecureHopGuard.capture(
                host=self.host,
                port=self.port,
                cell="EMAIL outbound",
                description="cleartext SMTP egress (use_tls=false)",
                attested=config.tls_hop_attested,
                attested_reason=config.tls_hop_attested_reason,
                cleartext_accepted=config.cleartext_accepted,
                cleartext_reason=config.cleartext_reason,
                connection=config.name,
            )
            self._hop_guard.enforce_construction()
        elif not self.tls_verify:
            # #323 arm 2: TLS is on but verification is off. Refused unless the CLAMPED escape permits
            # it (#200, ADR 0092 decision 2) — inlined here exactly as the MLLP and FTPS verify-off arms
            # inline it (remotefile.py:176, mllp.py:547), not routed through a shared helper, because
            # the sibling cells do it this way and a third spelling is how the next bug gets written.
            # NOTE the raw insecure_tls_allowed() is deliberately NOT used: the blunt process-wide
            # escape must not silence a verify-off PHI hop on an enforcing instance.
            if not weakened_tls_escape_permitted_here():
                raise ValueError(
                    "Email destination tls_verify=false disables server-certificate verification on "
                    f"the SMTP hop to {self.host} — the session is encrypted but UNAUTHENTICATED, so "
                    "an on-path attacker presenting any certificate reads the message body (PHI) and "
                    "any SMTP AUTH credential. Use a trusted CA (tls_ca_file, or [tls].internal_ca_file "
                    f"for the instance), or set {INSECURE_TLS_ESCAPE_ENV}=1 to allow it on a "
                    "trusted-network bind (refused on a production-PHI instance even with the escape, "
                    "#200)."
                )
            # Credentials over an unauthenticated channel are refused for the same reason they are
            # refused over cleartext: an on-path attacker who can present any cert can capture the
            # AUTH exchange. The use_tls=false arm above states the cleartext half of this rule.
            if self.username is not None:
                raise ValueError(
                    "Email destination sends SMTP AUTH credentials over an UNVERIFIED TLS session "
                    "(tls_verify=false); refused — credentials require a verified TLS session"
                )
            # No RevocationHopGuard here: a hop that does not verify the certificate at all has nothing
            # whose revocation status could matter, and the composition rule forbids two gates deciding
            # the same hop (docs/DEPLOYMENT.md §"composition"). The refusal above is that hop's gate.
        else:
            # #201 (ADR 0078 amendment): the hop now genuinely verifies the server cert (#323 — it did
            # not before; smtplib's default context is ssl._create_unverified_context), but stdlib ssl
            # does NO OCSP/CRL revocation, so a revoked-but-unexpired SMTP-server cert is still
            # accepted. The message body carries PHI over this verified hop, so refuse an off-loopback
            # production-PHI hop unless revocation is attested (loopback / synthetic / non-prod /
            # attested byte-identical). Same posture-keyed RevocationHopGuard as the REST/SOAP/FHIR/
            # DICOMweb https paths; SMTP is a different construction seam (smtplib, not the urllib/ssl
            # scheme), so it calls the guard directly rather than the https-scheme-keyed
            # refuse_unrevoked_verified_hop wrapper. Composes with the two refusals above: this arm is
            # reached only when use_tls=true AND tls_verify=true, which is the guard's documented
            # precondition (tls_policy.py: "the caller has already built a verifying context") — that
            # precondition was VIOLATED by this call site before #323.
            RevocationHopGuard.capture(
                host=self.host,
                cell="Email destination (verified SMTP TLS, no revocation check)",
                description="delivers over verified SMTP TLS but performs no certificate revocation checking",
                attested=config.tls_revocation_attested,
            ).enforce_construction()
        # Built once at construction (fail-fast), reused by every send. None when TLS is off entirely.
        self._tls_context: ssl.SSLContext | None = (
            build_smtp_tls_context(
                host=self.host,
                cell="Email destination",
                verify=self.tls_verify,
                ca_file=self.tls_ca_file,
                check_hostname=self.tls_check_hostname,
                trust_anchor_policy=config.trust_anchor_policy,
            )
            if self.use_tls
            else None
        )

    async def send(
        self, payload: str, *, metadata: Mapping[str, str] | None = None
    ) -> DeliveryResponse | None:  # metadata (#68): unused — no per-message header knob here
        # smtplib is blocking — keep it off the event loop (the delivery worker awaits this). A one-way
        # delivery: SMTP submission has no application reply to capture, so return None (like File).
        await asyncio.to_thread(self._send, payload)
        return None

    def _build_message(self, payload: str) -> EmailMessage:
        msg = EmailMessage()
        msg["Subject"] = self.subject
        msg["From"] = self.sender
        msg["To"] = ", ".join(self.recipients)
        # The Handler-produced payload IS the body (content-agnostic — an HL7 string, a JSON/XML report,
        # plain text); rendering it human-readable is the Handler's job, not the transport's.
        msg.set_content(payload, charset=self.encoding)
        return msg

    def _connect(self) -> smtplib.SMTP:
        """Open an SMTP connection, applying STARTTLS / implicit TLS per config. The caller is
        responsible for closing it (``with`` / ``quit``)."""
        if self.port == 465 and self.use_tls:
            # Port 465 is implicit TLS — the whole session is wrapped from connect, so SMTP_SSL rather
            # than SMTP+STARTTLS (ADR 0029 §D3). The submission port (587) keeps STARTTLS below.
            # context= is REQUIRED (#323): SMTP_SSL's own default is an unverified stdlib context.
            return smtplib.SMTP_SSL(
                self.host, self.port, timeout=self.timeout, context=self._tls_context
            )
        smtp = smtplib.SMTP(self.host, self.port, timeout=self.timeout)
        if self.use_tls:
            smtp.starttls(context=self._tls_context)
        return smtp

    def _send(self, payload: str) -> None:
        # Lifted from pipeline/alert_sinks.py send_plain_email (NOT imported — the one-way dependency
        # rule, ADR 0029). PHI/secret-safe error text: the host + SMTP failure class only, never the
        # body, the recipients' PHI, or the password.
        if self._hop_guard is not None:
            # Zero-I/O send-time backstop at the byte crossing (the tcp/x12/dicom pattern): re-assert the
            # captured cleartext decision so a reload can't route PHI around the construction-only gate.
            self._hop_guard.assert_send()
        msg = self._build_message(payload)
        try:
            with self._connect() as smtp:
                if self.username is not None:
                    # NOT smtp.login(): its preference order is internal and tries CRAM-MD5 FIRST, an
                    # HMAC over MD5 (BACKLOG #1171, ASVS 11.4.1 — Appendix C marks MD5 disallowed with
                    # no default-off escape). smtp_login_approved drives auth() against the server's
                    # advertised list restricted to PLAIN/LOGIN.
                    #
                    # escape_permitted=False DELIBERATELY. The helper's escape arm exists for callers
                    # whose cleartext-credential decision is escapable; this cell's is NOT — the
                    # construction gate above refuses username+use_tls=false outright, even with the
                    # escape. Passing True would make the send-time check weaker than the
                    # construction-time one it backs up, which is how a backstop becomes a hole.
                    smtp_login_approved(
                        smtp,
                        self.username,
                        self.password or "",
                        channel_encrypted=self.use_tls,
                        escape_permitted=False,
                        cell="EMAIL outbound",
                    )
                smtp.send_message(msg)
        except smtplib.SMTPException as exc:
            raise DeliveryError(
                f"Email {self.host}:{self.port} SMTP send failed: {type(exc).__name__}"
            ) from exc
        except (TimeoutError, OSError) as exc:
            raise DeliveryError(
                f"Email {self.host}:{self.port} unreachable: {type(exc).__name__}"
            ) from exc

    async def test_connection(self) -> None:
        await asyncio.to_thread(self._probe)

    def _probe(self) -> None:
        # Reachability/auth only: connect + (STARTTLS) + EHLO + optional login + NOOP, then quit. NO
        # MAIL FROM / DATA, so a connection test never sends a real email (ADR 0029 §D5). A connect/
        # TLS/auth failure raises DeliveryError (surfaced as unreachable by POST /connections/{name}/test).
        try:
            with self._connect() as smtp:
                smtp.ehlo_or_helo_if_needed()
                if self.username is not None:
                    # Same restriction as _send: a connection TEST that authenticated via CRAM-MD5
                    # would report a hop healthy that the real send path refuses, which is worse than
                    # either behaviour alone.
                    smtp_login_approved(
                        smtp,
                        self.username,
                        self.password or "",
                        channel_encrypted=self.use_tls,
                        escape_permitted=False,
                        cell="EMAIL outbound probe",
                    )
                smtp.noop()
        except smtplib.SMTPException as exc:
            raise DeliveryError(
                f"Email {self.host}:{self.port} probe failed: {type(exc).__name__}"
            ) from exc
        except (TimeoutError, OSError) as exc:
            raise DeliveryError(
                f"Email {self.host}:{self.port} unreachable: {type(exc).__name__}"
            ) from exc


register_destination(ConnectorType.EMAIL, EmailDestination)
