# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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
existing tamper-evident audit log, so a user with no deliverable mailbox can still review their
security history.

**WHAT THE FEED SHOWS IS STATED HERE ONCE; other comments point here.** It selects audit rows whose
actor is the user's username AND whose action starts ``auth.``. The two 6.3.5 events meet both, as
``auth.account_locked`` and ``auth.login_after_failures`` (BACKLOG #1138). An event whose row fails
either test is not in the feed, and the user learns of it only from the notice. At least two kinds
fail: a row naming another actor, such as the administrator who reset a password, and a row under
another action, such as the ``user.updated`` an administrator's email change or disable writes.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

# Event types. PHI-free by construction. A value is NOT an audit action: each call site audits under
# its own action name, and the two 6.3.5 kinds map to theirs in auth/service.py.
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
FEDERATED_IDENTITY_UNBOUND = (
    "federated_identity_unbound"  # 6.3.7 - an admin removed the account's external identity
)
ACCOUNT_DISABLED = "account_disabled"  # 6.3.7 — an admin disabled the account
MFA_ENABLED = "mfa_enabled"  # 6.3.7 — a second factor (TOTP) was enrolled on the account
MFA_DISABLED = (
    "mfa_disabled"  # 6.3.7 — the account's second factor was removed (self-service or admin reset)
)
# 6.3.7 -- ONE enrolled second factor was removed while AT LEAST ONE OTHER REMAINS, so the account
# still has MFA. Distinct from MFA_DISABLED rather than a flag on it (BACKLOG #1139): MFA_DISABLED
# asserts the account no longer has a second factor, and saying that while another one stands is a
# false statement in a security notice. Emitted by the passkey path today; the TOTP self-disable
# still sends MFA_DISABLED even where a passkey remains, which is the same asymmetry on the other
# credential and is not fixed here.
MFA_CREDENTIAL_REMOVED = "mfa_credential_removed"
# 6.3.7 -- the account had no notification address and its holder set one, which is the only way out
# of the first-sign-in confinement (BACKLOG #1139). Sent to the address just set: the account had no
# earlier one, so there is nobody else to tell, and a send that fails shows up in the log now rather
# than at the next real notice.
NOTIFY_EMAIL_SET = "notify_email_set"
# 6.3.7 — a single-use recovery code was spent, which permanently deletes that stored credential.
RECOVERY_CODE_USED = "recovery_code_used"  # nosec B105 — event-type label, not a credential
ADMIN_NEW_IP = (
    "admin_action_new_ip"  # 8.4.2 — a sensitive admin action from a new/unexpected client IP
)
# 6.3.7 -- an administrator created a local account, sent to the notification address it was created
# with (BACKLOG #315). An account minted in someone's name then reaches the address it names. The
# creating administrator chooses that address, so this is not a control against that administrator:
# the operator-side signal for a new Administrator is the ``administrator_granted`` alert.
ACCOUNT_CREATED = "account_created"

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


def deadline_utc(ts: float) -> str | None:
    """A deadline instant as a UTC ISO-8601 stamp, for text a client shows to a person.

    Lives here, in the dependency-free ``auth`` contract, so the ``api`` surfaces and the
    ``pipeline`` notice body (BACKLOG #1141) state one string from one function.
    ``api.security`` re-exports it.

    ``None`` when the instant cannot be rendered. The expiry setting has no upper bound, and
    ``fromtimestamp`` raises past year 9999, or past year 3000 on Windows. A deadline that far out
    is not worth a 500 on the refusal that states it, so the caller drops the sentence instead."""
    try:
        return datetime.datetime.fromtimestamp(ts, datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return None
