# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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
import json
import logging
import threading
from collections.abc import Callable
from typing import Any, Final, Protocol

from messagefoundry.auth.audit_visibility import LOCK_NOTICE_UNDELIVERED_ACTION
from messagefoundry.auth.notifications import (
    ACCOUNT_CREATED,
    ACCOUNT_DISABLED,
    ACCOUNT_LOCKED,
    DIRECTORY_SESSIONS_ENDED,
    EMAIL_CHANGED,
    ENROLMENT_CODE_ISSUED,
    ENROLMENT_CODE_SPENT,
    FEDERATED_IDENTITY_BOUND,
    FEDERATED_IDENTITY_UNBOUND,
    FIRST_ADMINISTRATOR_TAKEOVER,
    LOG_SILENT_EVENT_TYPES,
    LOGIN_AFTER_FAILURES,
    LOGIN_NEW_IP,
    MFA_CREDENTIAL_REMOVED,
    MFA_DISABLED,
    MFA_ENABLED,
    NEW_ADDRESS_REVERIFY,
    NOTIFY_EMAIL_SET,
    PASSWORD_CHANGED,
    PASSWORD_RESET,
    RECOVERY_CODE_USED,
    ROLES_CHANGED,
    TEMPORARY_CREDENTIAL_EXPIRING,
    TEMPORARY_CREDENTIAL_EXPIRING_FOR_ISSUER,
    USERNAME_CHANGED,
    SecurityEvent,
    deadline_utc,
    notice_kind_log_label,
)
from messagefoundry.config.secretprovider import SecretProvider, resolve_connector_secret
from messagefoundry.config.settings import AlertsSettings
from messagefoundry.config.tls_policy import (
    HopPosture,
    TrustAnchorPolicy,
    warn_smtp_verification_off,
)
from messagefoundry.controlchars import scrub_log_argument
from messagefoundry.pipeline.alert_sinks import (
    ALERTS_SMTP_CELL,
    _BackgroundDispatcher,
    _refuse_alert_smtp_revocation,
    _refuse_off_allowlist_smtp_host,
    send_plain_email,
)
from messagefoundry.transports.email import checked_sender

log = logging.getLogger(__name__)

#: BACKLOG #2383: the row :meth:`SecurityEventNotifier._record_undelivered` writes; its docstring
#: states the row. Defined here, not in ``auth/notifications.py``, where every upper-case string is a
#: notice kind.
SECURITY_NOTICE_UNDELIVERED_ACTION: Final = "auth.security_notice_undelivered"
#: How many records may be in flight at once when a queue-full drop starts one. Other records
#: held in the same set take slots too, at least a failed send's and a cut close's. Past it a
#: drop goes unrecorded, so the
#: overload that filled the queue cannot also grow tasks and store writers without bound.
_MAX_RECORDING: Final = 64


class NoticeAuditSink(Protocol):
    """Where :class:`SecurityEventNotifier` records a notice that never left: the one call it makes,
    a structural subset of the store's ``AuditStore``, so a store satisfies it as it is. An offline
    command may pass a sink that opens its store only for the write (BACKLOG #5634)."""

    async def record_audit(
        self,
        action: str,
        *,
        actor: str | None = None,
        channel_id: str | None = None,
        detail: str | None = None,
        client: str | None = None,
        now: float | None = None,
    ) -> None: ...


_SUBJECTS = {
    ACCOUNT_LOCKED: "Your MessageFoundry account was locked",
    LOGIN_AFTER_FAILURES: "New MessageFoundry sign-in after failed attempts",
    PASSWORD_CHANGED: "Your MessageFoundry password was changed",
    PASSWORD_RESET: "Your MessageFoundry password was reset",
    TEMPORARY_CREDENTIAL_EXPIRING: "Your temporary MessageFoundry password expires soon",
    TEMPORARY_CREDENTIAL_EXPIRING_FOR_ISSUER: "A temporary MessageFoundry password you issued expires soon",
    EMAIL_CHANGED: "Your MessageFoundry account email was changed",
    ROLES_CHANGED: "Your MessageFoundry account roles were changed",
    USERNAME_CHANGED: "Your MessageFoundry username was changed",
    FEDERATED_IDENTITY_BOUND: "An external sign-in identity was linked to your MessageFoundry account",
    FEDERATED_IDENTITY_UNBOUND: "An external sign-in identity was removed from your MessageFoundry account",
    FIRST_ADMINISTRATOR_TAKEOVER: "Your MessageFoundry account was made an Administrator from the host",
    ACCOUNT_DISABLED: "Your MessageFoundry account was disabled",
    DIRECTORY_SESSIONS_ENDED: "Your MessageFoundry sessions were ended",
    MFA_ENABLED: "Two-factor authentication was enabled on your MessageFoundry account",
    MFA_DISABLED: "Two-factor authentication was disabled on your MessageFoundry account",
    MFA_CREDENTIAL_REMOVED: "A second factor was removed from your MessageFoundry account",
    NOTIFY_EMAIL_SET: "Security notices for your MessageFoundry account now come to this address",
    RECOVERY_CODE_USED: "A MessageFoundry recovery code was used on your account",
    NEW_ADDRESS_REVERIFY: "A sensitive action on your MessageFoundry account from a new location",
    LOGIN_NEW_IP: "New MessageFoundry sign-in from a new location",
    ACCOUNT_CREATED: "A MessageFoundry account was created with this address",
    ENROLMENT_CODE_ISSUED: "An enrolment code was issued for your MessageFoundry account",
    ENROLMENT_CODE_SPENT: "An enrolment code you issued was used",
}

_DESCRIPTIONS = {
    ACCOUNT_LOCKED: "Your account was locked after repeated failed sign-in attempts.",
    LOGIN_AFTER_FAILURES: "A sign-in to your account succeeded after several failed attempts.",
    PASSWORD_CHANGED: "Your account password was changed.",
    PASSWORD_RESET: "Your account password was reset by an administrator.",
    TEMPORARY_CREDENTIAL_EXPIRING: (
        "An administrator gave your account a temporary password, and you have not replaced it "
        "with your own yet."
    ),
    TEMPORARY_CREDENTIAL_EXPIRING_FOR_ISSUER: (
        "You gave another account a temporary password, and its holder has not replaced it yet."
    ),
    EMAIL_CHANGED: "Your account's email address was changed.",
    # ROLES_CHANGED and ACCOUNT_DISABLED are worded from their evidence (``_evidenced_description``).
    USERNAME_CHANGED: "Your account's username was changed.",
    FEDERATED_IDENTITY_BOUND: "An administrator linked an external identity provider sign-in to your account, and your sessions were ended. Windows single sign-on no longer signs you in. Sign in through that provider; if it is not offered, ask your administrator.",
    FEDERATED_IDENTITY_UNBOUND: "An administrator removed the external identity provider sign-in from your account, and your sessions were ended. That provider can no longer sign you in.",
    # BACKLOG #2019. Names the command because the reader has no console action to trace it to: it
    # ran at the host, against the store, while the install had no enabled Administrator.
    FIRST_ADMINISTRATOR_TAKEOVER: (
        "Someone with access to the MessageFoundry host ran provision-admin on your account. It set "
        "a new password and gave the account the Administrator role, so the password it had before "
        "no longer works."
    ),
    # vault BACKLOG #2140, #3171. One wording for every whole-account reason that sends this kind,
    # with no branch on which one. Which reasons those are is decided in
    # ``AuthService._apply_reconcile_revocation``, and any reason added later falls here too; the
    # constant's comment in ``auth/notifications.py`` names at least the current ones. For at least
    # one of them no directory lookup ran, so neither this nor the subject may say one did, or that
    # the account is disabled or deleted. "Could not confirm" stays true whatever the cause. A role
    # revocation that wrote no role has its own wording (``_ROLE_SESSIONS_ENDED``).
    DIRECTORY_SESSIONS_ENDED: (
        "MessageFoundry ended your sessions. It could not confirm from your organization's "
        "directory that your account may still sign in."
    ),
    MFA_ENABLED: "A two-factor authenticator (TOTP) was enrolled on your account.",
    MFA_DISABLED: "Two-factor authentication was removed from your account.",
    # BACKLOG #1139: this arm reports WHAT CHANGED and states what still stands. It must not borrow
    # the MFA_DISABLED wording, which asserts the account has no second factor left -- untrue here by
    # construction, and a security notice the holder can falsify is one they stop reading. WHICH
    # credential went is deliberately not named: the label is user-authored free text, and the audit
    # row (``auth.webauthn_removed``) already carries it somewhere better protected than a mailbox.
    MFA_CREDENTIAL_REMOVED: (
        "One of the second factors on your account was removed. At least one other factor remains, "
        "so two-factor authentication is still in force."
    ),
    NOTIFY_EMAIL_SET: (
        "This address was set to receive security notices about your account. If you did not set "
        "it, tell your administrator."
    ),
    RECOVERY_CODE_USED: (
        "One of your single-use recovery codes was accepted as a second factor. That code is now "
        "spent and cannot be used again."
    ),
    NEW_ADDRESS_REVERIFY: (
        "A sensitive request on your account (an administrative action, a message read or a "
        "state-changing request) came from a client address that differs from your "
        "session's last verified address. It was required to re-verify before proceeding."
    ),
    ACCOUNT_CREATED: (
        "An administrator created this account and set this address to receive its security notices."
    ),
    # ADR 0207. Neither names the code. The issued notice does not invite a reply: the handover is
    # the control, and it must not run back through a mailbox the directory password opens.
    ENROLMENT_CODE_ISSUED: (
        "An administrator issued a one-time enrolment code for your account, which lets it add its "
        "first two-factor authenticator. The administrator gives it to you directly. If you did not "
        "ask for one, contact your administrator through your organization's identity check."
    ),
    ENROLMENT_CODE_SPENT: (
        "An enrolment code you issued was used to add another account's first two-factor "
        "authenticator. If that was not the person you gave it to, reset that account's MFA."
    ),
    # BACKLOG #288. States what happened and what it cost the session, and nothing about blocking:
    # the sign-in was NOT refused, so a notice implying it was would be false. "Started", because
    # the notice fires at the password step, before any second factor the account owes is proven.
    # No "if this was not you" line: the shared closing below already says it. "Not finished a
    # sign-in from": an address whose earlier sign-ins never completed every factor or step-up is
    # still first-seen (vault BACKLOG #2145), so "not signed in from" would be false.
    LOGIN_NEW_IP: (
        "Someone started a sign-in to your account with valid credentials from a client address it "
        "has not recently finished a sign-in from. It was not blocked."
    ),
}

# Vault BACKLOG #3121. A role change or disable the directory drove, from the session reconciler or
# a directory sign-in's re-sync, names no administrator and carries its source in its own words,
# so neither takes the generic directory line: a re-sync's roles come from the directory's groups
# through the group-to-role map, which an administrator edits in the console, so "not from the
# MessageFoundry console" would be false for it. The directory disable says what the directory
# reported; no MessageFoundry row was disabled. Both kinds are worded from their evidence
# (``_evidenced_description``), from an administrator or the directory alike.
_EVIDENCED_KINDS = frozenset({ROLES_CHANGED, ACCOUNT_DISABLED})

# BACKLOG #6034 (S08-57). What a role or disable notice says rests on the evidence its sender put on
# the event, never on the order of the sender's calls, because the directory senders notify on
# paths where the role write or the revoke raised, or its commit is unknown. At least: the
# reconciler after a role write that raised past its retry or was retried at all, or a revoke that
# raised, and the sign-in re-sync with an error held from either.
# ``roles_written`` is True only once the role write committed; ``sessions_revoked`` is the revoke's
# count, set only once the revoke returned. A count of 0 still proves no session was left open, so
# "any sessions already open were ended" holds for it.
_SESSIONS_ENDED = "Any sessions already open on your account were ended."
_SESSIONS_UNCONFIRMED = (
    "MessageFoundry could not confirm that the sessions already open on your account were ended."
)
_ROLES_WORDING = {
    # (from the directory, the write confirmed)
    (False, True): "Your account's roles were changed by an administrator.",
    # No current administrator sender reaches this: ``set_roles`` notifies only after its write
    # returned applied. It is the fail-closed wording for a sender that passes no evidence.
    (False, False): (
        "An administrator asked to change your account's roles. MessageFoundry could not confirm "
        "that the change was saved."
    ),
    (True, True): (
        "MessageFoundry read your groups in your organization's directory and changed your "
        "account's roles to match them."
    ),
    (True, False): (
        "MessageFoundry read your groups in your organization's directory and tried to change your "
        "account's roles to match them. It could not confirm that the change was saved."
    ),
}
# BACKLOG #6034. The reconciler's role revocation that wrote no role, because the roles already
# stood at its target or moved after its read, only ended the sessions, so it sends
# DIRECTORY_SESSIONS_ENDED. The pass did read the account in the directory, so the whole-account
# wording, "could not confirm ... may still sign in", would mislead here. ``_ROLE_REVOCATION`` is
# the reason ``auth/reconcile.py`` gives a role revocation.
_ROLE_REVOCATION = "roles_changed"
_ROLE_SESSIONS_ENDED = (
    "MessageFoundry read your groups in your organization's directory and ended your sessions."
)
# Each sender has confirmed the disable before it notifies: the administrator's write returned
# applied, and the reconciler sends this only on a READ disabled bit (vault BACKLOG #2140).
_DISABLE_WORDING = {
    False: "Your account was disabled by an administrator.",
    True: "Your organization's directory reports your account as disabled.",
}


def _roles_written(event: SecurityEvent) -> bool:
    """Whether a ROLES_CHANGED sender confirmed its role write committed (BACKLOG #6034). Only the
    literal ``True`` counts."""
    return event.event_type == ROLES_CHANGED and event.detail.get("roles_written") is True


def _roles_unconfirmed(event: SecurityEvent) -> bool:
    """A ROLES_CHANGED whose write is not confirmed, which must claim no change (BACKLOG #6034)."""
    return event.event_type == ROLES_CHANGED and not _roles_written(event)


def _revoked_count(event: SecurityEvent) -> int | None:
    """The ``sessions_revoked`` count, present only once the sender's revoke returned (BACKLOG
    #6034, vault #2609). A bool or any other shape is no count, through :func:`_count`."""
    return _count(event.detail.get("sessions_revoked"))


def _sessions_ended_any(event: SecurityEvent) -> bool:
    """Whether the sender's revoke returned having ended at least one session. A count of 0 backs
    "any sessions already open were ended" but not a subject saying sessions were ended, and a
    retried count can read low, so a 0 claims nothing there (BACKLOG #6034)."""
    count = _revoked_count(event)
    return count is not None and count > 0


def _evidenced_description(event: SecurityEvent, *, from_directory: bool) -> str:
    """The ROLES_CHANGED or ACCOUNT_DISABLED description: the change as far as ``roles_written``
    confirms it, then the sessions sentence ``sessions_revoked`` backs, or the line saying that
    could not be confirmed (BACKLOG #6034)."""
    if event.event_type == ROLES_CHANGED:
        what = _ROLES_WORDING[(from_directory, _roles_written(event))]
    else:
        what = _DISABLE_WORDING[from_directory]
    ended = _revoked_count(event) is not None
    return f"{what} {_SESSIONS_ENDED if ended else _SESSIONS_UNCONFIRMED}"


def _from_directory(event: SecurityEvent) -> bool:
    """Whether the directory, not the holder or an administrator, made this change (BACKLOG #1139,
    #2291, vault #3121). Gated on the kind as well as the tag: the reconciler tags every notice it
    sends, and its ``directory_sessions_ended`` must not claim the directory changed anything."""
    return (
        event.event_type in (EMAIL_CHANGED, USERNAME_CHANGED, *_EVIDENCED_KINDS)
        and event.detail.get("source") == "directory"
    )


def _subject(event: SecurityEvent) -> str:
    # BACKLOG #6034: each subject claims no more than the body's evidence does.
    if _roles_unconfirmed(event):
        return "A change to your MessageFoundry account roles could not be confirmed"
    if event.event_type == ACCOUNT_DISABLED and _from_directory(event):
        # The administrator subject says the MessageFoundry account was disabled, false here.
        if _sessions_ended_any(event):
            return "Your MessageFoundry sessions were ended: your directory account is disabled"
        return "Your directory account is reported as disabled"
    return _SUBJECTS.get(event.event_type, "MessageFoundry security alert")


_LOCAL_REMEDY = (
    "ask your MessageFoundry administrator for a password reset, or the host operator to run "
    "admin-unlock, and then "
)

#: ADR 0197 (BACKLOG #1131): what a SECOND-STEP lock notice says was right, and what to do if the
#: attempts were not the owner's. Closed set, keyed by the notice's ``factor_right`` detail.
_SECOND_STEP_FACTOR = {
    "password": (
        "Your password was right and the authenticator code was wrong.",
        _LOCAL_REMEDY + "change your password",
    ),
    "code": (
        "Your authenticator code was right and the password was wrong.",
        _LOCAL_REMEDY + "replace your authenticator",
    ),
    # ADR 0197 Amendment A, wave 2: the combined passkey sign-in counts only "wrong password, valid
    # passkey" on this counter, so the passkey is the factor that was right.
    "passkey": (
        "Your passkey was right and the password was wrong.",
        _LOCAL_REMEDY + "remove that passkey from your account; if it is your only way past a "
        "sign-in lock, enrol an authenticator app or another passkey first, or ask your "
        "administrator to reset your second factors",
    ),
    "first_step": (
        "The first sign-in step succeeded and the authenticator code was wrong.",
        _LOCAL_REMEDY + "change your password",
    ),
    # A directory account's first step is its directory sign-in; this engine cannot reset that
    # password, so the advice goes to the directory's own administrator.
    "directory": (
        "Your directory sign-in succeeded and the authenticator code was wrong.",
        "tell your directory administrator that your directory sign-in may be in someone else's "
        "hands, and ask the host operator to run admin-unlock",
    ),
}


def _count(value: object) -> int | None:
    """``value`` when it is an ``int`` and not a ``bool``, else ``None``. ``bool`` subclasses
    ``int``, so a bare ``isinstance`` check would print ``True`` as a count (BACKLOG #6034)."""
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _lock_lines(event: SecurityEvent) -> tuple[str | None, list[str], str | None]:
    """The ACCOUNT_LOCKED notice's own description, detail lines and closing (ADR 0197).

    Returns ``(None, [], None)`` for an event with no ``lock`` detail, so the generic wording
    stands. The second-step closing is CONDITIONAL, "if this was not you": the owner's own typos
    land on that counter too, and unconditional advice would tell an owner who mistyped their
    password to replace a working authenticator."""
    lock = event.detail.get("lock")
    cycle = _count(event.detail.get("cycle"))
    lines: list[str] = []
    if cycle is not None:
        lines.append(f"Lock number: {cycle} since the last successful sign-in")
    if lock == "sign_in":
        description = "Your account's sign-in was locked after repeated failed sign-in attempts."
        if event.detail.get("combined_sign_in"):
            lines.append(
                "You can sign in now by entering your password and your authenticator code "
                "together on the sign-in form."
            )
        if event.detail.get("totp_state") == "unknown":
            lines.append(
                "The engine could not check your authenticator app just now, so it cannot say "
                "whether your code will be accepted. If it is refused once, do not keep retrying, "
                "since each refusal counts toward a further lock: use the passkey sign-in below if "
                "you have one, or ask your administrator."
            )
        if event.detail.get("combined_passkey_sign_in"):
            lines.append(
                "You can sign in now by entering your password and choosing 'Sign in with password "
                "and passkey' on the sign-in form."
            )
        return description, lines, None
    if lock == "second_step":
        said, replace = _SECOND_STEP_FACTOR.get(
            str(event.detail.get("factor_right")), _SECOND_STEP_FACTOR["first_step"]
        )
        description = (
            "Your account was locked after repeated sign-in attempts that got one factor right "
            "and the other wrong. " + said
        )
        closing = (
            "If these attempts were your own, for example a mistyped password or code, no action "
            f"is needed: the lock ends on its own. If this was not you, {replace}."
        )
        return description, lines, closing
    return None, [], None


def _shown(text: str, what: str, *, token: bool = False) -> str:
    """``text`` when every character in it is printable, else a placeholder naming ``what``. With
    ``token``, a space of any kind shows the placeholder too, for a value that never holds one, such
    as a URL (BACKLOG #6034).

    A value carrying a line break could write its own lines into a notice, such as a false "If this
    was you" closing (BACKLOG #2291). A directory supplies the username and the email on a
    directory notice, so neither is shaped by this engine. An ASCII space is printable and passes:
    it cannot start a line, and a directory name may hold one. Other space characters, such as a
    no-break space, fail ``isprintable`` and show the placeholder, which is the safe side."""
    if text.isprintable() and not (token and any(c.isspace() for c in text)):
        return text
    return f"{what} that cannot be shown safely here"


def _roles_shown(roles: list[object]) -> str:
    """The role ids, comma-separated, each through :func:`_shown` as one token (BACKLOG #6034): no
    role id holds a space, so one that does cannot carry words into the list. An empty id is named
    as one, so it cannot print as a stray comma or make a list read as no role at all."""
    return ", ".join(
        _shown(text, "a role", token=True) if (text := str(role)) else "a role with no id"
        for role in roles
    )


def _holder_lines(event: SecurityEvent) -> list[str]:
    """The ``Account:`` line naming ``detail["holder"]``, the OTHER account a notice to an issuer is
    about (BACKLOG #2007; ADR 0207 A5), or nothing. Printed only as one printable token, as the
    #2019 address line is: a username carrying a line break could otherwise write its own lines
    into this notice."""
    holder = str(event.detail.get("holder") or "")
    if not holder:
        return []
    if holder.isprintable() and not any(c.isspace() for c in holder):
        return [f"Account: {holder}"]
    return ["Account: (a username that cannot be shown safely here)"]


def _build_body(event: SecurityEvent) -> str:
    """A short, PHI-free notice. The recipient is the account owner, so naming their own account /
    source IP / new email is appropriate; no message data or secrets ever appear here."""
    # BACKLOG #1139, ADR 0182 Amendment A: an administrator moved or set the NOTIFICATION address.
    # The generic wording fits neither: EMAIL_CHANGED names the profile address, NOTIFY_EMAIL_SET
    # assumes the holder set it, and "if this was you" cannot apply to an administrator's act.
    moved_by_admin = (
        event.event_type == EMAIL_CHANGED and event.detail.get("field") == "notify_email"
    )
    set_by_admin = (
        event.event_type == NOTIFY_EMAIL_SET and event.detail.get("set_by") == "administrator"
    )
    from_directory = _from_directory(event)
    unconfirmed = _roles_unconfirmed(event)  # BACKLOG #6034
    if moved_by_admin:
        description = (
            "An administrator changed the address that receives security notices for your account."
        )
    elif set_by_admin:
        description = (
            "An administrator set this address to receive security notices about your account."
        )
    elif event.event_type in _EVIDENCED_KINDS:
        description = _evidenced_description(event, from_directory=from_directory)
    elif (
        event.event_type == DIRECTORY_SESSIONS_ENDED
        and event.detail.get("reason") == _ROLE_REVOCATION
    ):
        description = _ROLE_SESSIONS_ENDED
    else:
        description = _DESCRIPTIONS.get(
            event.event_type, "A security event occurred on your account."
        )
    lock_description, lock_lines, lock_closing = (
        _lock_lines(event) if event.event_type == ACCOUNT_LOCKED else (None, [], None)
    )
    # Every opening prints the name through ``_shown``: a directory supplies it on a directory
    # notice (BACKLOG #2291), and nothing here shapes it on any other.
    account = _shown(event.username, "a username")
    if event.event_type == TEMPORARY_CREDENTIAL_EXPIRING_FOR_ISSUER:
        # BACKLOG #2007: sent to the ISSUER, so nothing changed on the recipient's own account.
        opening = f"A reminder for you as a MessageFoundry administrator ({account})."
    elif event.event_type == ENROLMENT_CODE_SPENT:
        # ADR 0207 A5: also to the ISSUER, but about something that has happened, not a reminder.
        opening = f"A notice for you as a MessageFoundry administrator ({account})."
    elif event.event_type == TEMPORARY_CREDENTIAL_EXPIRING:
        opening = f"A reminder about your MessageFoundry account ({account})."
    elif unconfirmed:
        # BACKLOG #6034: no change is confirmed (see ``_evidenced_description``).
        opening = f"A notice about your MessageFoundry account ({account})."
    else:
        opening = f"A security-relevant change occurred on your MessageFoundry account ({account})."
    lines = [opening, "", lock_description or description]
    failed = _count(event.detail.get("failed_attempts"))
    if event.event_type in (ACCOUNT_LOCKED, LOGIN_AFTER_FAILURES) and failed:
        lines.append(f"Failed attempts: {failed}")
    lines += lock_lines
    if event.event_type == ENROLMENT_CODE_SPENT:
        # ADR 0207 Amendment A, A5: the issuer's notice names the account that spent the code.
        lines += _holder_lines(event)
    if event.event_type in (
        PASSWORD_RESET,
        TEMPORARY_CREDENTIAL_EXPIRING,
        TEMPORARY_CREDENTIAL_EXPIRING_FOR_ISSUER,
    ):
        # BACKLOG #1141 (ASVS 6.4.5): the renewal instruction for an expiring credential. The reset
        # notice and the reminder (#2007) go to the holder; the issuer's reminder names the holder.
        # `expires_at` is the instant the login gate refuses on, read off the stored stamp.
        stamp = event.detail.get("expires_at")
        expires = (
            deadline_utc(stamp)
            if isinstance(stamp, (int, float)) and not isinstance(stamp, bool)
            else None
        )
        if event.event_type == TEMPORARY_CREDENTIAL_EXPIRING_FOR_ISSUER:
            lines += _holder_lines(event)
            if expires is not None:
                lines.append(
                    f"The temporary password stops working at {expires}. If the holder still needs "
                    "to sign in after that, reset the password again to issue a new one."
                )
        elif expires is not None:
            line = (
                f"The temporary password stops working at {expires}. Sign in with it and choose "
                "a new password before then."
            )
            if event.event_type == TEMPORARY_CREDENTIAL_EXPIRING:
                line += " If you cannot, ask your administrator for a new one."
            lines.append(line)
    if event.event_type == EMAIL_CHANGED:
        # BACKLOG #1139: an EMAIL_CHANGED carrying no ``new_email`` is a REMOVAL, not a repoint, and
        # it must not render as the repoint wording minus a line. "Was changed" with the new value
        # silently omitted reads as a truncated notice.
        #
        # WHAT THIS SENTENCE MUST NOT SAY, and did until the column split: that the removal ends the
        # account's notices. THREE things falsify it, and the third is now structural. ``users.email``
        # carries NO UNIQUE constraint on any of the three store backends -- only ``username`` does --
        # so a second account may hold the same address and keep notifying it. ``admin_user_update``
        # applies no ``_externally_managed`` guard, though this same module guards three other routes
        # with one, so an admin may clear a directory account's address and ``_upsert_ad_user``
        # restores it on the next directory login. And the removal reaches the PROFILE MIRROR only:
        # this notice is addressed to ``users.notify_email``, which no clear can strip --
        # ``set_user_notify_email`` takes a non-empty ``str``. (The completeness claim that used to
        # stand here, "every notice, this one included", is struck as a claim this renderer cannot
        # make -- SDS-3.6. The addressing rule and its one exception are stated once, on
        # ``SecurityEvent.email``.)
        #
        # A security notice written to make someone act NOW, resting on a promise the schema
        # contradicts, is the compensating-control-on-a-false-premise shape SDS-3.7 forbids. So this
        # arm reports WHAT CHANGED and states the one thing the schema does guarantee, rather than
        # forecasting what the address will or will not receive.
        new_email = event.detail.get("new_email")
        if new_email and moved_by_admin:
            # Other notices from the same save still come here, so "later changes", not "later
            # notices".
            lines.append(f"New notification address: {_shown(str(new_email), 'an address')}")
            lines.append("Notices about later changes go to the new address, not to this one.")
        elif new_email:
            # A directory notice carries the directory's ``mail`` here, unchecked (BACKLOG #2291).
            lines.append(f"New email on file: {_shown(str(new_email), 'an address')}")
        else:
            lines.append(
                "The email address on the account profile was removed. This notice went to the "
                "account's notification address, which that removal did not change."
            )
    if event.event_type == USERNAME_CHANGED:
        # BACKLOG #2017. Both names, so a holder who did not expect the change can tell which
        # account it was and what it is called now. A name the event lacks is left out rather than
        # printed as "None", and the gap is logged (BACKLOG #2291): at least the sender in
        # ``_refresh_cached_username`` passes both, so a missing one points at a sender defect the
        # holder's mail cannot report. Each name goes through ``_shown``.
        for label, key in (("Previous username", "old_username"), ("New username", "new_username")):
            name = str(event.detail.get(key) or "")
            if name:
                lines.append(f"{label}: {_shown(name, 'a username')}")
            else:
                log.warning(
                    "security notice %s for %s carries no %s, so that line was left out of it",
                    notice_kind_log_label(event.event_type),
                    scrub_log_argument(event.username),
                    key,
                )
    if from_directory and event.event_type not in _EVIDENCED_KINDS:
        # BACKLOG #1139. Say WHERE the change came from, because it changes what the reader can do
        # about it: a directory-driven change is not editable in the console, so "contact your
        # administrator" is the only action, and an unexplained change the holder cannot find a
        # cause for reads as a compromise. The vault #3121 kinds name their source in their own
        # description instead (see ``_EVIDENCED_KINDS``).
        lines.append(
            "This change came from your organization's directory, not from the MessageFoundry "
            "console."
        )
    if event.event_type == FIRST_ADMINISTRATOR_TAKEOVER:
        # BACKLOG #2019: the command may also have moved the notification address. This notice went
        # to the address held BEFORE the takeover, so without these lines the holder would not learn
        # that later notices go elsewhere.
        new_address = event.detail.get("new_notify_email")
        if new_address:
            # The address is operator-typed and shape-checked only for blank, so it is printed only
            # when it is one printable token: a value carrying a line break could write its own
            # lines into a notice meant to warn about the person who typed it.
            text = str(new_address)
            if text.isprintable() and not any(c.isspace() for c in text):
                lines.append(f"New notification address: {text}")
            else:
                lines.append("The notification address for this account was changed.")
            lines.append("Notices about later changes go to the new address, not to this one.")
    if event.event_type in (FEDERATED_IDENTITY_BOUND, FEDERATED_IDENTITY_UNBOUND):
        # BACKLOG #6034 (S08-57): which provider was linked or removed. Both senders pass the
        # issuer, never the subject (BACKLOG #1248). An issuer is a URL, so it prints only as one
        # printable token, as the #2019 address does: a space could carry false words inline.
        issuer = str(event.detail.get("issuer") or "")
        if issuer:
            lines.append(f"Identity provider: {_shown(issuer, 'an identity provider', token=True)}")
    if event.event_type == FEDERATED_IDENTITY_BOUND:
        # vault BACKLOG #2609: the bind ended the holder's sessions. The count lets a holder who
        # was signed in on several devices see that all of them went.
        ended = _revoked_count(event)
        if ended is not None:
            lines.append(f"Sessions ended: {ended}")
    if event.event_type == MFA_ENABLED and event.detail.get("issued_credential"):
        # ADR 0197 Amendment A: this account still held the password it was issued. An
        # authenticator is now enrolled before that password is replaced, so an enrolment the
        # holder did not make means someone else has the issued password.
        lines.append(
            "If you have not signed in to MessageFoundry yet, you did not do this. Contact your "
            "MessageFoundry administrator."
        )
    # BACKLOG #6034: each role id goes through ``_shown`` (S08-56), and a custom role prints by its
    # id, as no display name travels with the event. An administrator's confirmed role change
    # carries the whole set ``set_roles`` wrote (S08-57), so an empty one says the account was left
    # with none; a creation with none prints nothing, as it did. Not an unconfirmed write, nor a
    # directory role change: the sign-in re-sync passes the set it tried to write, so the line
    # could name roles the account does not hold.
    roles = event.detail.get("roles")
    if _roles_written(event) and not from_directory and isinstance(roles, list):
        lines.append(f"Roles now: {_roles_shown(roles) or 'none'}")
    if event.event_type == ACCOUNT_CREATED and isinstance(roles, list) and roles:
        lines.append(f"Roles: {_roles_shown(roles)}")
    if event.event_type == NEW_ADDRESS_REVERIFY and event.detail.get("cap_reached"):
        # vault BACKLOG #2159: past this notice the session reports no further new addresses until
        # it re-verifies, so silence after it must not read as "no more new locations".
        lines.append(
            "This session has now been used from many new addresses. Further new addresses for "
            "this session are not reported until it re-verifies. If this was not you, contact "
            "your MessageFoundry administrator."
        )
    if event.event_type == RECOVERY_CODE_USED:
        remaining = _count(event.detail.get("remaining"))
        if remaining is not None:
            lines.append(f"Recovery codes remaining: {remaining}")
            if remaining == 0:
                lines.append(
                    "That was your last recovery code. Enroll a new authenticator to generate more, "
                    "or you will need an administrator to reset your second factor."
                )
    # BACKLOG #6034: the address prints only as one printable token, as every other value does.
    client_ip = _shown(event.client_ip, "an address", token=True) if event.client_ip else ""
    if client_ip and from_directory:
        # BACKLOG #2291. The directory made this change, so the address is not where it was made,
        # and a bare "Source IP" line would read as the address of whoever made it. The directory
        # notices that pass an address were measured on 2026-10-06 to come from a directory
        # sign-in (``_upsert_ad_user``, and since vault BACKLOG #3121 the role re-sync in
        # ``_complete_ad_login``), but nothing on the event says so, so the line names only the
        # request (BACKLOG #6034). An unconfirmed role write claims no change.
        what = "sent this notice" if unconfirmed else "picked up this change"
        lines.append(f"MessageFoundry {what} while handling a request from {client_ip}.")
    elif client_ip:
        lines.append(f"Source IP: {client_ip}")
    if lock_closing is not None:
        closing = lock_closing
    elif unconfirmed:
        # BACKLOG #6034: "this change" would claim one (see ``_evidenced_description``).
        closing = "If you did not expect this notice, contact your MessageFoundry administrator."
    elif event.event_type == PASSWORD_RESET:
        # An administrator did this, so "if this was you" cannot apply, and "no action is needed"
        # would contradict the deadline line above it (BACKLOG #1141).
        closing = "If you did not expect this reset, contact your MessageFoundry administrator."
    elif event.event_type == TEMPORARY_CREDENTIAL_EXPIRING:
        closing = (
            "If you did not expect a temporary password, contact your MessageFoundry administrator."
        )
    elif event.event_type == TEMPORARY_CREDENTIAL_EXPIRING_FOR_ISSUER:
        # BACKLOG #2007. Says why this reader got it, and that the password is not in it, so the
        # issuer does not go looking for it here.
        closing = (
            "You got this reminder because you issued that password. The password itself is not in "
            "this message."
        )
    elif event.event_type == ENROLMENT_CODE_SPENT:
        # ADR 0207 A5: to the issuer, about another account, so "if this was you" cannot apply.
        closing = (
            "You got this notice because you issued that code. The code itself is not in this "
            "message."
        )
    elif event.event_type == ENROLMENT_CODE_ISSUED:
        # ADR 0207 section 4: the handover runs outside mail, so the closing must not invite a
        # reply through a mailbox the directory password may open.
        closing = (
            "If you did not ask for a code, contact your MessageFoundry administrator in person or "
            "through your organization's identity check, not by replying to this message."
        )
    elif event.event_type == FIRST_ADMINISTRATOR_TAKEOVER:
        # The takeover runs only when the install has no enabled Administrator, so "contact your
        # administrator" would name nobody, or the person who ran it.
        closing = "If you did not expect this, tell whoever operates the MessageFoundry host."
    elif (
        moved_by_admin
        or set_by_admin
        or from_directory
        or (event.event_type == MFA_DISABLED and event.detail.get("reset") is True)
        or event.event_type
        in (
            ACCOUNT_CREATED,
            ROLES_CHANGED,
            ACCOUNT_DISABLED,
            USERNAME_CHANGED,
            FEDERATED_IDENTITY_BOUND,
            FEDERATED_IDENTITY_UNBOUND,
            DIRECTORY_SESSIONS_ENDED,
        )
    ):
        # The holder did not make a directory change, so "if this was you" cannot apply to a
        # directory rename or email change (the email half is BACKLOG #2291), nor to a role
        # change or disable the directory drove (vault BACKLOG #3121). Nor to a federated link or
        # unlink:
        # both routes refuse an administrator changing their own account's binding. Nor to the
        # engine ending sessions on a directory answer (vault BACKLOG #2140). Nor to an
        # administrator's role change or disable, whose description says an administrator did it:
        # ``PUT /users/{id}/roles`` and the disable in ``PATCH /users/{id}`` both refuse a
        # self-target (BACKLOG #6034). Nor to an administrator's MFA reset, whose route refuses one
        # too.
        closing = "If you did not expect this change, contact your MessageFoundry administrator."
    else:
        closing = "If this was you, no action is needed. If not, contact your MessageFoundry administrator."
    lines += ["", closing]
    return "\n".join(lines)


def _consume_outcome(send: asyncio.Future[bool]) -> None:
    """Read a send's outcome, so asyncio never reports it unread: after a cut close nobody else
    reads it (BACKLOG #6832)."""
    if not send.cancelled():
        send.exception()


class _SendGate:
    """Whether a send's thread has begun, so a cut close can stop one still waiting for a worker
    thread from mailing after the close (BACKLOG #6832). Thread-safe: the send's thread calls
    :meth:`begin`, the loop calls :meth:`skip`, and exactly one of them wins."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._started = False
        self._skipped = False

    def begin(self) -> bool:
        """In the send's thread: whether to send. False once :meth:`skip` won."""
        with self._lock:
            if self._skipped:
                return False
            self._started = True
            return True

    def skip(self) -> bool:
        """On the loop: whether the send never began, and now never will."""
        with self._lock:
            if self._started:
                return False
            self._skipped = True
            return True


class SecurityEventNotifier(_BackgroundDispatcher[SecurityEvent]):
    """Emails the affected user about a security event, on a bounded background queue.

    Single use: once :meth:`aclose` has begun, :meth:`notify` refuses every event and :meth:`start`
    raises ``RuntimeError`` (vault BACKLOG #3120). Build a new notifier rather than restart one."""

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
        tls_verify: bool = True,
        tls_ca_file: str | None = None,
        trust_anchor_policy: TrustAnchorPolicy | None = None,
        audit: NoticeAuditSink | None = None,
        posture: HopPosture | None = None,
        revocation_attested: bool = False,
        revocation_attested_reason: str | None = None,
    ) -> None:
        # BACKLOG #5088: the allowlist every send applies, here at the build, with or without a
        # login, so a relay it would refuse at every notice refuses the start instead. First, so a
        # refused build starts nothing, and ahead of the revocation guard, which reads no allowlist.
        _refuse_off_allowlist_smtp_host(host, allowed_hosts)
        # BACKLOG #2193 slice (c): the login rides the alerts SMTP hop, so it takes that hop's
        # revocation guard, with the same [alerts] pair.
        _refuse_alert_smtp_revocation(
            host=host,
            use_tls=use_tls,
            username=username,
            tls_verify=tls_verify,
            tls_ca_file=tls_ca_file,
            trust_anchor_policy=trust_anchor_policy,
            posture=posture,
            attested=revocation_attested,
            attested_reason=revocation_attested_reason,
        )
        super().__init__()
        self._host = host
        self._port = port
        self._sender = sender
        self._use_tls = use_tls
        self._username = username
        self._password = password
        self._timeout = timeout
        self._allowed_hosts = allowed_hosts
        # #323 layer 3: the STARTTLS hop that carries a user's security-event mail now VERIFIES the
        # relay's certificate. Carried as plain data — send_plain_email builds the one context.
        self._tls_verify = tls_verify
        self._tls_ca_file = tls_ca_file
        self._trust_anchor_policy = trust_anchor_policy
        # BACKLOG #2383: where a dropped or failed notice is recorded. None writes no row. The API
        # lifespan passes the store. Of the offline commands, provision-admin passes its store and
        # admin-reset-totp a sink that reopens the store for the write (BACKLOG #5634).
        self._audit = audit
        # The records still being written, at least the queue-full ones and a failed send's, held so
        # the loop keeps them alive and so aclose() can wait for them.
        self._recording: set[asyncio.Future[Any]] = set()
        # The send the drain is waiting on, with what it needs to record or count it, so a cut
        # close can record it (BACKLOG #6832). None between sends.
        self._sending: (
            tuple[SecurityEvent, asyncio.Future[bool], _SendGate, Callable[[], None]] | None
        ) = None
        # Set when the first aclose() has finished or been cut, so a second one waits for it rather
        # than racing it (BACKLOG #6832).
        self._closed = asyncio.Event()
        # Set when aclose() begins, and never cleared: start() refuses (vault BACKLOG #3120). An event
        # queued after that sits behind the stop sentinel, or on a queue nothing reads, and is never
        # sent, so notify() refuses it; the contract on ``SecurityNotifier`` says why.
        self._closing = False
        # Logged now, once, rather than at the first send (BACKLOG #1131): the first send may be a
        # lock notice, and a line appearing then would show a logs:view reader that a lock landed.
        if use_tls and not tls_verify:
            warn_smtp_verification_off(cell=ALERTS_SMTP_CELL, host=host)

    async def notify(self, event: SecurityEvent) -> bool:
        # Returns whether the event was queued for sending, the contract on ``SecurityNotifier``,
        # which lists why it may answer False. Never a delivery receipt.
        #
        # No deliverable address means nothing to email. The caller has audited the event; which
        # events the /me/security-events feed shows is stated once, in auth/notifications.py.
        # Non-blocking enqueue.
        #
        # **WHICH ADDRESS ``event.email`` HOLDS IS A CALLER'S PROPERTY, NOT AN INVARIANT THIS METHOD
        # HOLDS**, and it used to be written here as one (BACKLOG #1139). The rule and its single
        # exception are stated once on ``SecurityEvent.email``; this method enforces nothing beyond
        # the drop below, so do not restate the rule here as though it did.
        if not event.email:
            # BACKLOG #1139: SAY SO. This was the only silent drop of the three in this class -- a
            # full queue warns (``_BackgroundDispatcher._enqueue``) and a failed send warns
            # (``_handle``) -- and it is the most permanent: those two are transient, while an
            # account carrying no address loses every later notice, not one. CLAUDE.md §6: never
            # swallow silently.
            #
            # WHAT THIS COVERS THAT THE STARTUP GATE CANNOT, and an addressless sole administrator
            # is NOT the example to reach for. ``_assert_security_notice_is_deliverable``
            # (``api/app.py``) refuses to start a PHI instance under ``enforce`` over exactly that
            # account, so this line never runs there. (The engine creates no account on its own
            # since ADR 0183 Amendment A; an administrator comes from ``provision-admin`` or the
            # console.) It runs where that gate returns early or cannot
            # see: a non-PHI instance, a non-administrator account, administrators 2..N once one of
            # them carries an address, and any account born without an address after startup. The
            # gate asks once whether SOMEBODY can receive; this names the account that did not.
            #
            # Per occurrence rather than once per account, matching the two sibling drops: each one
            # is a distinct notice nobody received, and collapsing them would hide the count.
            #
            # **Never ``event.detail``** -- an EMAIL_CHANGED carries the new address in it.
            #
            # **Never for a lock notice** (BACKLOG #1131, LOG_SILENT_EVENT_TYPES): the line would show
            # a logs:view reader when a lock landed. The users:manage-only ``auth.lock_notice`` row
            # records ``mailed: false`` for that account instead.
            #
            # "Usually" in the line, not "always" (BACKLOG #3018): the directory reconciler's audit
            # write is soft, so a store that refuses it still lets the notice reach here with no row.
            if event.event_type not in LOG_SILENT_EVENT_TYPES:
                log.warning(
                    "security notice %s for %s dropped: the account has no notification address on "
                    "file, so it was not told out of band (the event is usually still in the audit "
                    "log)",
                    event.event_type,
                    event.username,
                )
            return False
        if self._closing:
            # At shutdown, for example a lock notice the teardown's cut drain left running (vault
            # BACKLOG #3120). Recorded like a full queue's drop. A record started after aclose()
            # has finished is not waited for, and may meet the closed store, where it fails and is
            # swallowed like any other.
            if event.event_type not in LOG_SILENT_EVENT_TYPES:
                log.warning(
                    "%s is closing; dropping %s for %s",
                    type(self).__name__,
                    notice_kind_log_label(event.event_type),
                    scrub_log_argument(event.username),
                )
            self._record_dropped(event, "closing")
            return False
        queued = self._enqueue(
            event,
            dropped=None
            if event.event_type in LOG_SILENT_EVENT_TYPES
            else f"{event.event_type} for {event.username}",
        )
        if not queued:
            self._record_dropped(event, "queue_full")
        return queued

    def _record_dropped(self, event: SecurityEvent, reason: str) -> None:
        # Off the caller's path: a notice must never block a sign-in or an admin action, and this
        # write would wait on the store under exactly the overload that filled the queue.
        if self._audit is None or len(self._recording) >= _MAX_RECORDING:
            return
        task = asyncio.create_task(self._record_undelivered(event, {"reason": reason}))
        self._recording.add(task)
        task.add_done_callback(self._recording.discard)

    def start(self) -> None:
        # Never again once closed (vault BACKLOG #3120). From the moment aclose() begins, notify()
        # refuses every event, so a drain started again would serve a queue nothing fills while the
        # notices it was meant to send were already recorded or sent. The engine builds a new
        # notifier for each lifespan rather than restart one.
        if self._closing:
            raise RuntimeError(f"{type(self).__name__} has been closed and cannot be started again")
        super().start()

    async def aclose(self) -> None:
        """Drain the queue and stop. The close sets no bound of its own: the shutdown's step bound
        cuts it, so every notice the drain mails inside that bound goes out. A close cut short
        cancels the drain and starts recording, with a sink, the send it cut and each notice still
        queued (BACKLOG #6832). It waits for those writes unless it is cancelled again, which stops
        only the wait. The writes are not bounded: past the step's cut grace the shutdown stops
        waiting for them, and they go on, beside engine.stop(), until the store closes, which fails
        the rest. The count of queued notices is logged before any of them is written. A second
        call waits until the first ends, and closes nothing itself: once its record writes end,
        or sooner if a second cancel stops its wait."""
        if self._closing:
            await self._closed.wait()
            return
        self._closing = True  # before the sentinel goes in, so nothing is queued behind it
        try:
            await self._close()
        finally:
            self._closed.set()

    async def _close(self) -> None:
        drain = self._task
        cut = False
        try:
            await super().aclose()
        except asyncio.CancelledError:
            cut = True
            raise
        finally:
            # Taken and logged before any await, so a second cancel cannot leave them untold.
            left = self._take_queued()
            # Skipped here too, before any await, so a send still waiting for a worker thread cannot
            # begin once the close is cut, even while the drain unwinds.
            pending, self._sending = self._sending, None
            skipped = pending is not None and pending[2].skip()
            try:
                if drain is not None:
                    # Cut while the sentinel waited on a full queue, the drain still runs; cut while
                    # the close waited on the drain, it is already cancelled.
                    drain.cancel()
                    self._task = None
                    await asyncio.gather(drain, return_exceptions=True)
                    # Uncut, the base close has already raised the drain's failure to the caller.
                    if cut and not drain.cancelled() and (error := drain.exception()) is not None:
                        log.error("%s drain loop failed", type(self).__name__, exc_info=error)
            finally:
                # Held and shielded like a failed send's record, so a cut of this close stops only
                # its wait: the writes go on until the store closes.
                records = asyncio.ensure_future(self._record_cut(left, pending, skipped))
                self._recording.add(records)
                records.add_done_callback(self._recording.discard)
                # Each one swallows its own failure, so this only waits.
                await asyncio.shield(asyncio.gather(*self._recording, return_exceptions=True))

    def _take_queued(self) -> list[SecurityEvent]:
        """Empty the queue, stop sentinel included, and log how many notices it held. At least a
        cut close, and the close of a notifier never started, leave some."""
        left: list[SecurityEvent] = []
        while not self._queue.empty():
            if (event := self._queue.get_nowait()) is not None:
                left.append(event)
        # A count, never one that includes a lock notice (BACKLOG #1131).
        shown = sum(event.event_type not in LOG_SILENT_EVENT_TYPES for event in left)
        if shown:
            log.warning(
                "%s closed with %d security notice(s) still queued, never sent",
                type(self).__name__,
                shown,
            )
        return left

    async def _record_cut(
        self,
        left: list[SecurityEvent],
        pending: tuple[SecurityEvent, asyncio.Future[bool], _SendGate, Callable[[], None]] | None,
        skipped: bool,
    ) -> None:
        """Record the send a cut close stopped waiting for, and each notice it left queued.
        ``skipped`` says the close stopped that send before its thread began."""
        records: list[tuple[SecurityEvent, str]] = []
        if pending is not None:
            event, send, _gate, delivered = pending
            if skipped:
                # Read first: a skipped send whose thread then ran returns False, and would
                # otherwise read as a send that ended with nothing to record.
                records.append((event, "abandoned"))
            elif not send.done() or send.cancelled():
                # A send still waiting for a worker thread was skipped above, so it never mails
                # after the close: "abandoned", like a queued one. One whose thread began runs on
                # to its own timeout, so the notice may still go out: "interrupted" says its
                # delivery is unknown. No line for it: a cut that leaves notices queued nearly
                # always has a send in flight, so a line skipped for a lock notice would say a lock
                # landed (BACKLOG #1131).
                records.append((event, "interrupted"))
            elif (exc := send.exception()) is not None:
                # It ended before the cut reached the drain, so its outcome is known.
                self._log_send_failed(event, exc)
                records.append((event, "send_failed"))
            elif send.result():
                delivered()
        # "abandoned", apart from "closing": a lock notice refused at notify() reads mailed: false
        # on its auth.lock_notice row, while one queued before the close reads mailed: true.
        records += [(event, "abandoned") for event in left]
        if self._audit is None:
            return  # nowhere to record them; the counts are already in the log
        failed = 0
        try:
            for event, reason in records:
                recorded = await self._record_undelivered(
                    event, {"reason": reason}, log_failure=False
                )
                failed += not recorded and event.event_type not in LOG_SILENT_EVENT_TYPES
        finally:
            if failed:
                # One line, not one per row: a store closing under a full queue refuses them all.
                log.warning(
                    "%d undelivered security notice(s) could not be recorded in the audit log at "
                    "close",
                    failed,
                )

    async def _handle(self, event: SecurityEvent, delivered: Callable[[], None]) -> None:
        # Shielded, so a cut close can read how the send ended (BACKLOG #6832). Its outcome is
        # consumed here, since a cut leaves nobody else to read it.
        gate = _SendGate()
        send = asyncio.ensure_future(asyncio.to_thread(self._send_gated, event, gate))
        send.add_done_callback(_consume_outcome)
        self._sending = (event, send, gate, delivered)
        try:
            sent = await asyncio.shield(send)
        except Exception as exc:
            self._sending = None
            # Best-effort: a failed send must never propagate.
            self._log_send_failed(event, exc)
            # The reason only. The exception's text can quote the relay's reply or the address, and
            # even its class would tell the recipient, in their own feed, that the relay is broken.
            # Shielded and held, so a cut close waits for this write rather than cancelling it.
            record = asyncio.ensure_future(
                self._record_undelivered(event, {"reason": "send_failed"})
            )
            self._recording.add(record)
            record.add_done_callback(self._recording.discard)
            await asyncio.shield(record)
            return
        # A cancel leaves self._sending set, for the cut close to record.
        self._sending = None
        if sent:
            delivered()

    def _log_send_failed(self, event: SecurityEvent, exc: BaseException) -> None:
        # The event is usually also in the audit log; a refused directory-reconciler audit write
        # leaves no row (BACKLOG #3018). A lock notice fails silently here (BACKLOG #1131,
        # LOG_SILENT_EVENT_TYPES): a line per failed lock mail would show a logs:view reader when a
        # lock landed. A relay that is down still shows, on every other kind of notice.
        if event.event_type not in LOG_SILENT_EVENT_TYPES:
            log.warning(
                "security-event email failed for %s (%s)",
                scrub_log_argument(event.username),
                notice_kind_log_label(event.event_type),
                exc_info=exc,
            )

    async def _record_undelivered(
        self, event: SecurityEvent, why: dict[str, str], *, log_failure: bool = True
    ) -> bool:
        """Write the audit row that says this notice never left the engine (BACKLOG #2383).

        Before this, a full queue or a failed send left only a WARNING line, so the trail could not
        say which account was never told. The actor is the notice's recipient, so the row also
        reaches that account's ``/me/security-events`` feed. The detail is the notice kind and
        ``why``, plus the holder's username on an issuer's reminder, which says whose credential it
        was. Never the rest of ``event.detail`` or the address: an EMAIL_CHANGED carries an address
        in its detail. A lock notice writes the hidden ``auth.lock_notice_undelivered`` action (BACKLOG
        #1131). A failed write is swallowed, like the send it reports on. It is logged by class,
        unless ``log_failure`` is False, and never for a lock notice: that kind writes no other
        line, so a lone line would say a lock landed. Returns whether the row was written."""
        if self._audit is None:
            return False
        silent = event.event_type in LOG_SILENT_EVENT_TYPES
        action = LOCK_NOTICE_UNDELIVERED_ACTION if silent else SECURITY_NOTICE_UNDELIVERED_ACTION
        detail = {"notice": notice_kind_log_label(event.event_type), **why}
        holder = event.detail.get("holder")
        if event.event_type == TEMPORARY_CREDENTIAL_EXPIRING_FOR_ISSUER and isinstance(holder, str):
            detail["holder"] = holder
        try:
            await self._audit.record_audit(
                action, actor=event.username, detail=json.dumps(detail, sort_keys=True)
            )
        except Exception as exc:  # noqa: BLE001 - best-effort, like the notice itself
            if log_failure and not silent:
                log.warning(
                    "an undelivered security notice could not be recorded in the audit log (%s)",
                    type(exc).__name__,
                )
            return False
        return True

    def _send_gated(self, event: SecurityEvent, gate: _SendGate) -> bool:
        """Mail the notice unless a cut close skipped it before its thread began."""
        if not gate.begin():
            return False
        return self._send(event)

    def _send(self, event: SecurityEvent) -> bool:
        """Mail the notice, returning whether it was sent."""
        if not event.email:  # narrowed for mypy; notify() already filtered these out
            return False
        send_plain_email(
            host=self._host,
            port=self._port,
            sender=self._sender,
            recipients=[event.email],
            subject=_subject(event),
            body=_build_body(event),
            use_tls=self._use_tls,
            username=self._username,
            password=self._password,
            timeout=self._timeout,
            allowed_hosts=self._allowed_hosts,
            tls_verify=self._tls_verify,
            tls_ca_file=self._tls_ca_file,
            trust_anchor_policy=self._trust_anchor_policy,
        )
        return True


def security_notifier_from_settings(
    alerts: AlertsSettings,
    *,
    secret_provider: SecretProvider | None = None,
    trust_anchor_policy: TrustAnchorPolicy | None = None,
    audit: NoticeAuditSink | None = None,
    posture: HopPosture | None = None,
) -> SecurityEventNotifier | None:
    """Build the per-user security notifier from ``[alerts]`` SMTP settings, or ``None`` when no SMTP
    server/sender is configured (then nothing is emailed; ``auth/notifications.py`` states which events
    the ``/me/security-events`` feed still shows).

    ``secret_provider`` (ADR 0019 §5) resolves the SMTP password from a ``[secrets].provider`` when
    ``email_password_secret`` is set (fail-closed); ``None``/no reference → the env-sourced
    ``email_password``, byte-identical to before. ``audit`` is where a dropped or failed notice is
    recorded (BACKLOG #2383); ``None`` records nothing. ``posture`` keys the SMTP login's
    revocation guard (BACKLOG #2193), as on the alerts sink; ``None`` with none stamped counts as
    enforcing there (ADR 0173 section 12)."""
    if not (alerts.email_smtp_host and alerts.email_from):
        return None
    # The sender is MAIL FROM on every notice, and send_plain_email refuses one that fails the address
    # rule. Refuse it here instead, where it stops startup, rather than at each send, where the
    # failure is only a log line (vault BACKLOG #2870).
    checked_sender("[alerts].email_from", alerts.email_from)
    # BACKLOG #5088: before the password is read, so a relay the allowlist forbids costs no
    # secret-store read, and a store that is down cannot hide this refusal. The build repeats it.
    _refuse_off_allowlist_smtp_host(alerts.email_smtp_host, alerts.smtp_allowed_hosts)
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
        tls_verify=alerts.email_tls_verify,
        tls_ca_file=alerts.email_tls_ca_file,
        trust_anchor_policy=trust_anchor_policy,
        audit=audit,
        posture=posture,
        revocation_attested=alerts.email_tls_revocation_attested,
        revocation_attested_reason=alerts.email_tls_revocation_attested_reason,
    )
