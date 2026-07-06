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
set (``insecure_tls_allowed()``), and credentials are **never** sent over a cleartext channel (a
``username``/``password`` with ``use_tls=False`` and no escape raises at construction) — the same
``refuse_cleartext_credentials`` posture the REST destination takes. The ``[egress].allowed_smtp``
allowlist is the authoritative fail-closed host gate (enforced by the runner at load/reload/start).

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
from email.message import EmailMessage
from typing import Any

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import INSECURE_TLS_ESCAPE_ENV, insecure_tls_allowed
from messagefoundry.transports.base import (
    DeliveryError,
    DeliveryResponse,
    DestinationConnector,
    register_destination,
)

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
        self.timeout: float = float(s.get("timeout_seconds", 30.0))
        self.encoding: str = str(s.get("encoding", "utf-8"))

        # STARTTLS-by-default posture, mirroring RestDestination's verify_tls /
        # refuse_cleartext_credentials handling. Disabling TLS puts the body (PHI) and any AUTH
        # credentials on the wire in cleartext, so it is refused unless the project-wide dev escape is
        # set, and logged loudly when allowed. The escape is the SAME insecure_tls_allowed() gate the
        # whole project uses — not a new mechanism.
        if not self.use_tls:
            if not insecure_tls_allowed():
                raise ValueError(
                    "Email destination use_tls=false sends the message (and any credentials) over "
                    f"cleartext SMTP; refused unless {INSECURE_TLS_ESCAPE_ENV} is set "
                    "(dev/trusted-network only) — use STARTTLS (the default)"
                )
            # Credentials over an un-encrypted channel are never allowed, even with the escape: a
            # cleartext AUTH puts the password on the wire (the refuse_cleartext_credentials rule).
            if self.username is not None:
                raise ValueError(
                    "Email destination sends SMTP AUTH credentials over cleartext (use_tls=false); "
                    "refused — credentials require STARTTLS/implicit TLS"
                )
            logger.warning(
                "Email destination %s has TLS DISABLED (use_tls=false); the message crosses the "
                "network in CLEARTEXT (dev/trusted-network only)",
                self.host,
            )

    async def send(self, payload: str) -> DeliveryResponse | None:
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
            return smtplib.SMTP_SSL(self.host, self.port, timeout=self.timeout)
        smtp = smtplib.SMTP(self.host, self.port, timeout=self.timeout)
        if self.use_tls:
            smtp.starttls()
        return smtp

    def _send(self, payload: str) -> None:
        # Lifted from pipeline/alert_sinks.py send_plain_email (NOT imported — the one-way dependency
        # rule, ADR 0029). PHI/secret-safe error text: the host + SMTP failure class only, never the
        # body, the recipients' PHI, or the password.
        msg = self._build_message(payload)
        try:
            with self._connect() as smtp:
                if self.username is not None:
                    smtp.login(self.username, self.password or "")
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
                    smtp.login(self.username, self.password or "")
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
