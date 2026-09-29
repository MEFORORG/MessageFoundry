# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Which audit rows a reader without ``users:manage`` does not see (BACKLOG #1131).

**Owner ruling 2026-09-28.** The second-step counter is fed only by a right factor, so sending one
candidate password ``lockout_threshold`` times in a combined sign-in locks it only when the
password was right. The rows that lock leaves behind were readable by the built-in Auditor
(``audit:read``, not an administrator), which made them a password oracle at ``lockout_threshold``
requests per candidate. The ruling: the engine still WRITES every lock row (ADR 0197 AC-10), and
an administrator still reads them all, but a reader without ``users:manage`` reads none of them.
In their place that reader sees one uniform ``auth.login_failed`` row per refused sign-in, which
:meth:`AuthService._login_local` writes in every lock state. The accepted cost is that the Auditor
can no longer review lockouts.

This module is the one place that names the hidden rows. Every API read of the trail passes
:func:`audit_exclusion_for` to the store, which applies it in SQL before ``LIMIT``.

**What is hidden, and why each one:**

* ``auth.account_locked`` -- a lock landed. In a combined campaign under a live sign-in lock, only
  a right candidate can make one.
* ``auth.lock_notice`` -- the throttle row of a lock mail, and its detail names the counter.
* ``auth.login_locked`` -- a sign-in refused by a live lock. A live second-step lock refuses a
  later sign-in that a wrong candidate would have been refused for as a plain wrong password.
* ``auth.admin_unlocked`` -- the whole row, not only its lock fields. Its detail records both lock
  expiries and both cycle counts; stripped of those, it would still say that an account needed
  unlocking. An administrator reads it in full, which is who acts on it.
* The lock refusals of the other legs, which share an action with an ordinary failure and say
  "a lock is live" only in their detail: ``auth.mfa_failed`` and ``auth.webauthn_failed`` with
  ``{"reason": "locked"}``, and a directory sign-in's ``auth.login_failed`` with
  ``{"provider": "ad", "reason": "locked"}``. Only a holder of the account's session or directory
  ticket can cause one, but it would still show another reader that a second-step lock was live.

**Considered and left visible:** ``auth.login_after_failures`` (written only on a full sign-in, so
nobody without both factors can cause it), the per-session re-proof cap rows (``auth.reauth`` with
``session_revoked`` and ``auth.password_change_failed`` with ``reason=session_revoked``, which
describe a session and not an account lock), and ``auth.temp_password_expired`` (a separate
password-right signal on an account whose temporary credential has already expired, outside this
ruling).

**The general log is covered too** (Manager decision 2026-09-28): ``GET /logs/tail`` serves it to
``logs:view``, which the Operator holds without ``users:manage``. An undeliverable lock notice writes
no per-event line (``auth.notifications.LOG_SILENT_EVENT_TYPES``), and the tee's audit-row copies
are withheld from such a reader (:func:`reads_audit_copies_in_the_log`).

**The visible row's time is covered too:** :meth:`AuthService.login` writes a refused local
sign-in's rows at a fixed point inside its failure pad, so their ``ts`` does not depend on which
branch refused, and the answer still goes out on its slot.

**Left open:** the owner's own later sign-in, which a live lock refuses. ``docs/SECURITY.md``
(Audit) states it. The factor and directory lock refusals get
no visible stand-in row: only a holder of the account's session or ticket causes one, and that
holder's unrefused attempt would differ anyway (``auth.mfa_verified``, ``auth.login_success``).

``/me/security-events`` is not filtered. It selects rows by the caller's own username, so it shows
the holder their own lock and never another account's.
"""

from __future__ import annotations

import json
import re
from typing import Final

from messagefoundry.auth.identity import Identity
from messagefoundry.auth.permissions import Permission
from messagefoundry.store.audit_exclusion import AuditExclusion

__all__ = [
    "ACCOUNT_LOCKED_ACTION",
    "ADMIN_UNLOCKED_ACTION",
    "DIRECTORY_LOCKED_REFUSAL_DETAIL",
    "HIDDEN_FROM_READERS_WITHOUT_USERS_MANAGE",
    "LOCKED_REFUSAL_DETAIL",
    "LOCK_EVENT_ACTIONS",
    "LOCK_NOTICE_ACTION",
    "LOGIN_LOCKED_ACTION",
    "audit_exclusion_for",
    "is_audit_copy_line",
    "reads_audit_copies_in_the_log",
]

ACCOUNT_LOCKED_ACTION: Final = "auth.account_locked"
LOCK_NOTICE_ACTION: Final = "auth.lock_notice"
LOGIN_LOCKED_ACTION: Final = "auth.login_locked"
ADMIN_UNLOCKED_ACTION: Final = "auth.admin_unlocked"

#: The whole-row hides.
LOCK_EVENT_ACTIONS: Final[frozenset[str]] = frozenset(
    {ACCOUNT_LOCKED_ACTION, LOCK_NOTICE_ACTION, LOGIN_LOCKED_ACTION, ADMIN_UNLOCKED_ACTION}
)

#: The exact detail of a lock refusal on the TOTP/recovery and passkey legs. The writers use this
#: constant, so the stored text and the hidden text cannot drift apart.
LOCKED_REFUSAL_DETAIL: Final = json.dumps({"reason": "locked"}, sort_keys=True)
#: The exact detail of a lock refusal on a directory (Kerberos or OIDC) sign-in.
DIRECTORY_LOCKED_REFUSAL_DETAIL: Final = json.dumps(
    {"provider": "ad", "reason": "locked"}, sort_keys=True
)

HIDDEN_FROM_READERS_WITHOUT_USERS_MANAGE: Final = AuditExclusion(
    actions=LOCK_EVENT_ACTIONS,
    rows=frozenset(
        {
            ("auth.mfa_failed", LOCKED_REFUSAL_DETAIL),
            ("auth.webauthn_failed", LOCKED_REFUSAL_DETAIL),
            ("auth.login_failed", DIRECTORY_LOCKED_REFUSAL_DETAIL),
        }
    ),
)


def audit_exclusion_for(identity: Identity) -> AuditExclusion | None:
    """The rows ``identity`` must not read, or ``None`` when it may read every row.

    Decided by the caller's PERMISSION, never a role name, so a custom role or a future built-in
    gets the right answer without a change here. ``users:manage`` is the permission that already
    reads each account's lock state (``GET /users``), so a reader holding it learns nothing new."""
    if identity.has(Permission.USERS_MANAGE):
        return None
    return HIDDEN_FROM_READERS_WITHOUT_USERS_MANAGE


#: A line of the general log that is the off-box tee's copy of an audit row
#: (:mod:`messagefoundry.store.audit_tee`), in the text format (``<logger>: <message>``) or the JSON
#: format (``"logger": "<logger>"``). The logger name is fixed, so it is the one reliable mark.
_AUDIT_COPY_LINE: Final = re.compile(
    r'(?:\smessagefoundry\.audit:\s|"logger":\s*"messagefoundry\.audit")'
)


def is_audit_copy_line(line: str) -> bool:
    """Whether ``line`` of the general log is the tee's copy of an audit row."""
    return _AUDIT_COPY_LINE.search(line) is not None


def reads_audit_copies_in_the_log(identity: Identity) -> bool:
    """Whether ``identity`` may read the tee's audit copies in ``GET /logs/tail``.

    **The ruling reaches the general log** (Manager decision 2026-09-28): ``logs:view`` is held by
    the built-in Operator, who lacks ``users:manage``, and the tee writes EVERY audit row into that
    log, the lock rows included. Withholding only the lock rows there would not do: each copy carries
    its ``row_id``, so the gaps would count the hidden rows. So a reader without ``users:manage``
    gets no audit copies from the log at all. It reads the trail, if it may, through ``GET /audit``,
    which applies :data:`HIDDEN_FROM_READERS_WITHOUT_USERS_MANAGE`."""
    return audit_exclusion_for(identity) is None
