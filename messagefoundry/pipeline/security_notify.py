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
import logging

from messagefoundry.auth.notifications import (
    ACCOUNT_CREATED,
    ACCOUNT_DISABLED,
    ACCOUNT_LOCKED,
    ADMIN_NEW_IP,
    EMAIL_CHANGED,
    FEDERATED_IDENTITY_BOUND,
    FEDERATED_IDENTITY_UNBOUND,
    FIRST_ADMINISTRATOR_TAKEOVER,
    LOG_SILENT_EVENT_TYPES,
    LOGIN_AFTER_FAILURES,
    LOGIN_NEW_IP,
    MFA_CREDENTIAL_REMOVED,
    MFA_DISABLED,
    MFA_ENABLED,
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
)
from messagefoundry.config.secretprovider import SecretProvider, resolve_connector_secret
from messagefoundry.config.settings import AlertsSettings
from messagefoundry.config.tls_policy import TrustAnchorPolicy, warn_smtp_verification_off
from messagefoundry.controlchars import scrub_log_argument
from messagefoundry.pipeline.alert_sinks import (
    ALERTS_SMTP_CELL,
    _BackgroundDispatcher,
    send_plain_email,
)
from messagefoundry.transports.email import checked_sender

log = logging.getLogger(__name__)

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
    MFA_ENABLED: "Two-factor authentication was enabled on your MessageFoundry account",
    MFA_DISABLED: "Two-factor authentication was disabled on your MessageFoundry account",
    MFA_CREDENTIAL_REMOVED: "A second factor was removed from your MessageFoundry account",
    NOTIFY_EMAIL_SET: "Security notices for your MessageFoundry account now come to this address",
    RECOVERY_CODE_USED: "A MessageFoundry recovery code was used on your account",
    ADMIN_NEW_IP: "A sensitive action on your MessageFoundry account from a new location",
    LOGIN_NEW_IP: "New MessageFoundry sign-in from a new location",
    ACCOUNT_CREATED: "A MessageFoundry account was created with this address",
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
    ROLES_CHANGED: "Your account's roles were changed by an administrator.",
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
    ACCOUNT_DISABLED: "Your account was disabled by an administrator.",
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
    ADMIN_NEW_IP: (
        "A sensitive administrative action on your account was attempted from a client address that "
        "differs from your session's last verified address. It was required to re-verify before "
        "proceeding."
    ),
    ACCOUNT_CREATED: (
        "An administrator created this account and set this address to receive its security notices."
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


def _lock_lines(event: SecurityEvent) -> tuple[str | None, list[str], str | None]:
    """The ACCOUNT_LOCKED notice's own description, detail lines and closing (ADR 0197).

    Returns ``(None, [], None)`` for an event with no ``lock`` detail, so the generic wording
    stands. The second-step closing is CONDITIONAL, "if this was not you": the owner's own typos
    land on that counter too, and unconditional advice would tell an owner who mistyped their
    password to replace a working authenticator."""
    lock = event.detail.get("lock")
    cycle = event.detail.get("cycle")
    lines: list[str] = []
    if isinstance(cycle, int):
        lines.append(f"Lock number: {cycle} since the last successful sign-in")
    if lock == "sign_in":
        description = "Your account's sign-in was locked after repeated failed sign-in attempts."
        if event.detail.get("combined_sign_in"):
            lines.append(
                "You can sign in now by entering your password and your authenticator code "
                "together on the sign-in form."
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
    # BACKLOG #1139, #2291: the directory made this change, not the holder and not the console.
    from_directory = event.event_type in (EMAIL_CHANGED, USERNAME_CHANGED) and (
        event.detail.get("source") == "directory"
    )
    if moved_by_admin:
        description = (
            "An administrator changed the address that receives security notices for your account."
        )
    elif set_by_admin:
        description = (
            "An administrator set this address to receive security notices about your account."
        )
    else:
        description = _DESCRIPTIONS.get(
            event.event_type, "A security event occurred on your account."
        )
    lock_description, lock_lines, lock_closing = (
        _lock_lines(event) if event.event_type == ACCOUNT_LOCKED else (None, [], None)
    )
    if event.event_type == TEMPORARY_CREDENTIAL_EXPIRING_FOR_ISSUER:
        # BACKLOG #2007: sent to the ISSUER, so nothing changed on the recipient's own account.
        opening = f"A reminder for you as a MessageFoundry administrator ({event.username})."
    elif event.event_type == TEMPORARY_CREDENTIAL_EXPIRING:
        opening = f"A reminder about your MessageFoundry account ({event.username})."
    else:
        opening = f"A security-relevant change occurred on your MessageFoundry account ({event.username})."
    lines = [opening, "", lock_description or description]
    failed = event.detail.get("failed_attempts")
    if event.event_type in (ACCOUNT_LOCKED, LOGIN_AFTER_FAILURES) and failed:
        lines.append(f"Failed attempts: {failed}")
    lines += lock_lines
    if event.event_type in (
        PASSWORD_RESET,
        TEMPORARY_CREDENTIAL_EXPIRING,
        TEMPORARY_CREDENTIAL_EXPIRING_FOR_ISSUER,
    ):
        # BACKLOG #1141 (ASVS 6.4.5): the renewal instruction for an expiring credential. The reset
        # notice and the reminder (#2007) go to the holder; the issuer's reminder names the holder.
        # `expires_at` is the instant the login gate refuses on, read off the stored stamp.
        stamp = event.detail.get("expires_at")
        expires = deadline_utc(stamp) if isinstance(stamp, (int, float)) else None
        if event.event_type == TEMPORARY_CREDENTIAL_EXPIRING_FOR_ISSUER:
            holder = str(event.detail.get("holder") or "")
            # Printed only as one printable token, as the #2019 address line below is: a username
            # carrying a line break could otherwise write its own lines into this notice.
            if holder.isprintable() and holder and not any(c.isspace() for c in holder):
                lines.append(f"Account: {holder}")
            elif holder:
                lines.append("Account: (a username that cannot be shown safely here)")
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
            lines.append(f"New notification address: {new_email}")
            lines.append("Notices about later changes go to the new address, not to this one.")
        elif new_email:
            lines.append(f"New email on file: {new_email}")
        else:
            lines.append(
                "The email address on the account profile was removed. This notice went to the "
                "account's notification address, which that removal did not change."
            )
    if event.event_type == USERNAME_CHANGED:
        # BACKLOG #2017. Both names, so a holder who did not expect the change can tell which
        # account it was and what it is called now. A name the event lacks is left out rather than
        # printed as "None", and the gap is logged (BACKLOG #2291): the one sender always passes
        # both, so a missing one is a sender defect the holder's mail cannot report.
        for label, key in (("Previous username", "old_username"), ("New username", "new_username")):
            name = event.detail.get(key)
            if name:
                lines.append(f"{label}: {name}")
            else:
                log.warning(
                    "security notice %s for %s carries no %s, so that line was left out of it",
                    USERNAME_CHANGED,
                    scrub_log_argument(event.username),
                    key,
                )
    if from_directory:
        # BACKLOG #1139. Say WHERE the change came from, because it changes what the reader can do
        # about it: a directory-driven change is not editable in the console, so "contact your
        # administrator" is the only action, and an unexplained change the holder cannot find a
        # cause for reads as a compromise.
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
    if event.event_type == FEDERATED_IDENTITY_BOUND:
        # vault BACKLOG #2609: the bind ended the holder's sessions. The count lets a holder who
        # was signed in on several devices see that all of them went.
        ended = event.detail.get("sessions_revoked")
        if isinstance(ended, int) and not isinstance(ended, bool):
            lines.append(f"Sessions ended: {ended}")
    if event.event_type == MFA_ENABLED and event.detail.get("issued_credential"):
        # ADR 0197 Amendment A: this account still held the password it was issued. An
        # authenticator is now enrolled before that password is replaced, so an enrolment the
        # holder did not make means someone else has the issued password.
        lines.append(
            "If you have not signed in to MessageFoundry yet, you did not do this. Contact your "
            "MessageFoundry administrator."
        )
    if event.event_type == ACCOUNT_CREATED:
        roles = event.detail.get("roles")
        if isinstance(roles, list) and roles:
            lines.append("Roles: " + ", ".join(str(r) for r in roles))
    if event.event_type == ADMIN_NEW_IP and event.detail.get("cap_reached"):
        # vault BACKLOG #2159: past this notice the session reports no further new addresses until
        # it re-verifies, so silence after it must not read as "no more new locations".
        lines.append(
            "This session has now been used from many new addresses. Further new addresses for "
            "this session are not reported until it re-verifies. If this was not you, contact "
            "your MessageFoundry administrator."
        )
    if event.event_type == RECOVERY_CODE_USED:
        remaining = event.detail.get("remaining")
        if isinstance(remaining, int):
            lines.append(f"Recovery codes remaining: {remaining}")
            if remaining == 0:
                lines.append(
                    "That was your last recovery code. Enroll a new authenticator to generate more, "
                    "or you will need an administrator to reset your second factor."
                )
    if event.client_ip and from_directory:
        # BACKLOG #2291. The directory made this change, so the address is not where it was made.
        # The only sender passing one is the account's own directory sign-in, which copied the
        # change down, and a bare "Source IP" line would read as the address of whoever made it.
        lines.append(
            f"MessageFoundry picked up this change when your account signed in from "
            f"{event.client_ip}."
        )
    elif event.client_ip:
        lines.append(f"Source IP: {event.client_ip}")
    if lock_closing is not None:
        closing = lock_closing
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
    elif event.event_type == FIRST_ADMINISTRATOR_TAKEOVER:
        # The takeover runs only when the install has no enabled Administrator, so "contact your
        # administrator" would name nobody, or the person who ran it.
        closing = "If you did not expect this, tell whoever operates the MessageFoundry host."
    elif (
        moved_by_admin
        or set_by_admin
        or from_directory
        or event.event_type
        in (
            ACCOUNT_CREATED,
            USERNAME_CHANGED,
            FEDERATED_IDENTITY_BOUND,
            FEDERATED_IDENTITY_UNBOUND,
        )
    ):
        # A directory rename or email change is an administrator's act, so "if this was you"
        # cannot apply to it (the email half is BACKLOG #2291). Nor to a federated link or unlink:
        # both routes refuse an administrator changing their own account's binding.
        closing = "If you did not expect this change, contact your MessageFoundry administrator."
    else:
        closing = "If this was you, no action is needed. If not, contact your MessageFoundry administrator."
    lines += ["", closing]
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
        tls_verify: bool = True,
        tls_ca_file: str | None = None,
        trust_anchor_policy: TrustAnchorPolicy | None = None,
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
        # #323 layer 3: the STARTTLS hop that carries a user's security-event mail now VERIFIES the
        # relay's certificate. Carried as plain data — send_plain_email builds the one context.
        self._tls_verify = tls_verify
        self._tls_ca_file = tls_ca_file
        self._trust_anchor_policy = trust_anchor_policy
        # Logged now, once, rather than at the first send (BACKLOG #1131): the first send may be a
        # lock notice, and a line appearing then would show a logs:view reader that a lock landed.
        if use_tls and not tls_verify:
            warn_smtp_verification_off(cell=ALERTS_SMTP_CELL, host=host)

    async def notify(self, event: SecurityEvent) -> None:
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
            if event.event_type not in LOG_SILENT_EVENT_TYPES:
                log.warning(
                    "security notice %s for %s dropped: the account has no notification address on "
                    "file, so it was not told out of band (the event is still in the audit log)",
                    event.event_type,
                    event.username,
                )
            return
        self._enqueue(
            event,
            dropped=None
            if event.event_type in LOG_SILENT_EVENT_TYPES
            else f"{event.event_type} for {event.username}",
        )

    async def _handle(self, event: SecurityEvent) -> None:
        try:
            await asyncio.to_thread(self._send, event)
        except Exception:
            # Best-effort: a failed send must never propagate. The event is also in the audit log.
            # A lock notice fails silently here (BACKLOG #1131, LOG_SILENT_EVENT_TYPES): a line per
            # failed lock mail would show a logs:view reader when a lock landed. A relay that is down
            # still shows, on every other kind of notice.
            if event.event_type in LOG_SILENT_EVENT_TYPES:
                return
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
            tls_verify=self._tls_verify,
            tls_ca_file=self._tls_ca_file,
            trust_anchor_policy=self._trust_anchor_policy,
        )


def security_notifier_from_settings(
    alerts: AlertsSettings,
    *,
    secret_provider: SecretProvider | None = None,
    trust_anchor_policy: TrustAnchorPolicy | None = None,
) -> SecurityEventNotifier | None:
    """Build the per-user security notifier from ``[alerts]`` SMTP settings, or ``None`` when no SMTP
    server/sender is configured (then nothing is emailed; ``auth/notifications.py`` states which events
    the ``/me/security-events`` feed still shows).

    ``secret_provider`` (ADR 0019 §5) resolves the SMTP password from a ``[secrets].provider`` when
    ``email_password_secret`` is set (fail-closed); ``None``/no reference → the env-sourced
    ``email_password``, byte-identical to before."""
    if not (alerts.email_smtp_host and alerts.email_from):
        return None
    # The sender is MAIL FROM on every notice, and send_plain_email refuses one that fails the address
    # rule. Refuse it here instead, where it stops startup, rather than at each send, where the
    # failure is only a log line (vault BACKLOG #2870).
    checked_sender("[alerts].email_from", alerts.email_from)
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
    )
