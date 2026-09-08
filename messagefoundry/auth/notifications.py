# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Security-event notification seam (ASVS 6.3.5 / 6.3.7).

A tiny, dependency-free contract the auth layer uses to push an **out-of-band** notice to the affected
user when something security-relevant happens to their account — a suspicious login (lockout, or a
success after repeated failures) or a credential change (password / email / roles / disable).

The contract lives here, in ``auth/``, so :class:`~messagefoundry.auth.service.AuthService` can emit
events **without importing** ``pipeline/`` (the one-way dependency rule, CLAUDE.md §4). The concrete
sender — which turns an event into a per-user email over the ``[alerts]`` SMTP transport — lives in
``pipeline/`` and is injected into ``AuthService``. Emission is always **best-effort**: a notifier
failure is logged and never breaks authentication or an admin action.

The persistent, pull-based companion (``GET /me/security-events``) is a user-scoped view over the
existing tamper-evident audit log — these same events are already audited — so a user with no
deliverable mailbox can still review their security history.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

# Event types (the values double as the audit-action suffix / feed category). PHI-free by construction.
ACCOUNT_LOCKED = "account_locked"  # 6.3.5 — repeated failures crossed the lockout threshold
LOGIN_AFTER_FAILURES = (
    "login_after_failures"  # 6.3.5 — first success following >= N failed attempts
)
PASSWORD_CHANGED = "password_changed"  # nosec B105 — event-type label, not a credential (6.3.7)
PASSWORD_RESET = "password_reset"  # nosec B105 — event label, not a credential; admin-initiated (6.3.7/6.4.6)
EMAIL_CHANGED = "email_changed"  # 6.3.7 — the account's email address was changed
ROLES_CHANGED = "roles_changed"  # 6.3.7 — an admin changed the account's roles
FEDERATED_IDENTITY_BOUND = (
    "federated_identity_bound"  # 6.3.7 - an external identity was bound to the account
)
ACCOUNT_DISABLED = "account_disabled"  # 6.3.7 — an admin disabled the account
MFA_ENABLED = "mfa_enabled"  # 6.3.7 — a second factor (TOTP) was enrolled on the account
MFA_DISABLED = (
    "mfa_disabled"  # 6.3.7 — the account's second factor was removed (self-service or admin reset)
)
# 6.3.7 — a single-use recovery code was spent, which permanently deletes that stored credential.
RECOVERY_CODE_USED = "recovery_code_used"  # nosec B105 — event-type label, not a credential
ADMIN_NEW_IP = (
    "admin_action_new_ip"  # 8.4.2 — a sensitive admin action from a new/unexpected client IP
)

# First success after this many prior failed attempts is flagged as suspicious (6.3.5). Kept modest and
# fixed (not an operator knob) so a single fat-fingered password does not generate a notice.
SUSPICIOUS_LOGIN_FAILURE_THRESHOLD = 3


@dataclass(frozen=True)
class SecurityEvent:
    """One notifiable security event. Carries only the affected user's own identifiers + non-PHI
    metadata; the body sent to the user is built from these by the concrete notifier."""

    event_type: str
    username: str
    # THE ADDRESS THE NOTICE IS SENT TO, and the ONE place the rule for choosing it is stated
    # (SDS-3.5). Callers pass the affected account's ENGINE-OWNED ``users.notify_email`` (BACKLOG
    # #1139, ADR 0182) rather than the directory-mirrored profile address, so a directory repoint
    # cannot redirect an account's notices. None = no deliverable address, and the notifier drops
    # the notice.
    #
    # **THAT IS A RULE EVERY CALLER FOLLOWS, NOT AN INVARIANT ANY CODE ENFORCES.** This comment
    # asserted it as an absolute -- "never the directory-mirrored profile address" -- while
    # ``_upsert_ad_user`` was addressing the directory-repoint notice from the mirror, which is the
    # one notice the rule exists for. Stated absolutely it also invites the reverse reading, that a
    # None here proves no clear occurred; nothing establishes that. Nineteen call sites are the only
    # thing holding the rule up, and giving it a single enforcing choke point is recorded as a
    # follow-on on BACKLOG #1139.
    #
    # ONE DELIBERATE EXCEPTION, at the directory repoint itself: an account that has never carried
    # any address falls back to the incoming directory value, because it is then the only reachable
    # party and there is no earlier holder to protect.
    email: str | None = None
    client_ip: str | None = None  # source IP of the triggering request, when known
    detail: dict[str, Any] = field(
        default_factory=dict
    )  # PHI-free extras (e.g. role from/to counts)


@runtime_checkable
class SecurityNotifier(Protocol):
    """Push a security event to the affected user out-of-band. Implemented in ``pipeline/`` (email over
    the ``[alerts]`` SMTP transport) and injected into :class:`AuthService`. Must be best-effort and
    must not raise into the auth path (the caller still guards it)."""

    async def notify(self, event: SecurityEvent) -> None: ...
