# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Per-user security-event email notifier (ASVS 6.3.5 / 6.3.7).

The concrete :class:`~messagefoundry.auth.notifications.SecurityNotifier` the API lifespan injects into
:class:`~messagefoundry.auth.service.AuthService`. It turns a
:class:`~messagefoundry.auth.notifications.SecurityEvent` into a short plain-text email to the
**affected user's own address** — distinct from the operator alert distribution list — over the
``[alerts]`` SMTP transport. Dispatch runs on a bounded background queue so a notification never blocks
the login / admin path, and every send is best-effort (a failure is logged, never raised).

Lives in ``pipeline/`` (next to the operator alert plumbing it reuses) and imports the contract from
``auth/`` — one-way ``pipeline → auth``, never the reverse (CLAUDE.md §4).
"""

from __future__ import annotations

import asyncio
import logging

from messagefoundry.auth.notifications import (
    ACCOUNT_DISABLED,
    ACCOUNT_LOCKED,
    ADMIN_NEW_IP,
    EMAIL_CHANGED,
    LOGIN_AFTER_FAILURES,
    MFA_DISABLED,
    MFA_ENABLED,
    PASSWORD_CHANGED,
    PASSWORD_RESET,
    ROLES_CHANGED,
    SecurityEvent,
)
from messagefoundry.config.secretprovider import SecretProvider, resolve_connector_secret
from messagefoundry.config.settings import AlertsSettings
from messagefoundry.pipeline.alert_sinks import _BackgroundDispatcher, send_plain_email

log = logging.getLogger(__name__)

_SUBJECTS = {
    ACCOUNT_LOCKED: "Your MessageFoundry account was locked",
    LOGIN_AFTER_FAILURES: "New MessageFoundry sign-in after failed attempts",
    PASSWORD_CHANGED: "Your MessageFoundry password was changed",
    PASSWORD_RESET: "Your MessageFoundry password was reset",
    EMAIL_CHANGED: "Your MessageFoundry account email was changed",
    ROLES_CHANGED: "Your MessageFoundry account roles were changed",
    ACCOUNT_DISABLED: "Your MessageFoundry account was disabled",
    MFA_ENABLED: "Two-factor authentication was enabled on your MessageFoundry account",
    MFA_DISABLED: "Two-factor authentication was disabled on your MessageFoundry account",
    ADMIN_NEW_IP: "A sensitive action on your MessageFoundry account from a new location",
}

_DESCRIPTIONS = {
    ACCOUNT_LOCKED: "Your account was locked after repeated failed sign-in attempts.",
    LOGIN_AFTER_FAILURES: "A sign-in to your account succeeded after several failed attempts.",
    PASSWORD_CHANGED: "Your account password was changed.",
    PASSWORD_RESET: "Your account password was reset by an administrator.",
    EMAIL_CHANGED: "Your account's email address was changed.",
    ROLES_CHANGED: "Your account's roles were changed by an administrator.",
    ACCOUNT_DISABLED: "Your account was disabled by an administrator.",
    MFA_ENABLED: "A two-factor authenticator (TOTP) was enrolled on your account.",
    MFA_DISABLED: "Two-factor authentication was removed from your account.",
    ADMIN_NEW_IP: (
        "A sensitive administrative action on your account was attempted from a client address that "
        "differs from your session's last verified address. It was required to re-verify before "
        "proceeding."
    ),
}


def _build_body(event: SecurityEvent) -> str:
    """A short, PHI-free notice. The recipient is the account owner, so naming their own account /
    source IP / new email is appropriate; no message data or secrets ever appear here."""
    lines = [
        f"A security-relevant change occurred on your MessageFoundry account ({event.username}).",
        "",
        _DESCRIPTIONS.get(event.event_type, "A security event occurred on your account."),
    ]
    failed = event.detail.get("failed_attempts")
    if event.event_type in (ACCOUNT_LOCKED, LOGIN_AFTER_FAILURES) and failed:
        lines.append(f"Failed attempts: {failed}")
    if event.event_type == EMAIL_CHANGED and event.detail.get("new_email"):
        lines.append(f"New email on file: {event.detail['new_email']}")
    if event.client_ip:
        lines.append(f"Source IP: {event.client_ip}")
    lines += [
        "",
        "If this was you, no action is needed. If not, contact your MessageFoundry administrator.",
    ]
    return "\n".join(lines)


class SecurityEventNotifier(_BackgroundDispatcher[SecurityEvent]):
    """Emails the affected user about a security event, on a bounded background queue."""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        sender: str,
        use_tls: bool = True,
        username: str | None = None,
        password: str | None = None,
        timeout: float = 30.0,
        allowed_hosts: tuple[str, ...] = (),
    ) -> None:
        super().__init__()
        self._host = host
        self._port = port
        self._sender = sender
        self._use_tls = use_tls
        self._username = username
        self._password = password
        self._timeout = timeout
        self._allowed_hosts = allowed_hosts

    async def notify(self, event: SecurityEvent) -> None:
        # No deliverable address (common for local accounts / unset email) → nothing to email; the
        # audited /me/security-events feed still records it. Non-blocking enqueue.
        if not event.email:
            return
        self._enqueue(event, dropped=f"{event.event_type} for {event.username}")

    async def _handle(self, event: SecurityEvent) -> None:
        try:
            await asyncio.to_thread(self._send, event)
        except Exception:
            # Best-effort: a failed send must never propagate. The event is also in the audit log.
            log.warning(
                "security-event email failed for %s (%s)",
                event.username,
                event.event_type,
                exc_info=True,
            )

    def _send(self, event: SecurityEvent) -> None:
        if not event.email:  # narrowed for mypy; notify() already filtered these out
            return
        send_plain_email(
            host=self._host,
            port=self._port,
            sender=self._sender,
            recipients=[event.email],
            subject=_SUBJECTS.get(event.event_type, "MessageFoundry security alert"),
            body=_build_body(event),
            use_tls=self._use_tls,
            username=self._username,
            password=self._password,
            timeout=self._timeout,
            allowed_hosts=self._allowed_hosts,
        )


def security_notifier_from_settings(
    alerts: AlertsSettings, *, secret_provider: SecretProvider | None = None
) -> SecurityEventNotifier | None:
    """Build the per-user security notifier from ``[alerts]`` SMTP settings, or ``None`` when no SMTP
    server/sender is configured (then only the ``/me/security-events`` feed records events).

    ``secret_provider`` (ADR 0019 §5) resolves the SMTP password from a ``[secrets].provider`` when
    ``email_password_secret`` is set (fail-closed); ``None``/no reference → the env-sourced
    ``email_password``, byte-identical to before."""
    if not (alerts.email_smtp_host and alerts.email_from):
        return None
    smtp_password = resolve_connector_secret(
        secret_provider,
        ref=alerts.email_password_secret,
        literal=alerts.email_password,
        label="[alerts].email_password",
    )
    return SecurityEventNotifier(
        host=alerts.email_smtp_host,
        port=alerts.email_smtp_port,
        sender=alerts.email_from,
        use_tls=alerts.email_use_tls,
        username=alerts.email_username,
        password=smtp_password,
        timeout=alerts.email_timeout,
        allowed_hosts=tuple(alerts.smtp_allowed_hosts),
    )
