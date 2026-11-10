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
* ``auth.lock_notice_undelivered`` -- a lock mail the relay's queue dropped or the send lost
  (BACKLOG #2383). It is written only when a lock landed.
* ``auth.login_locked`` -- a sign-in refused by a live lock. A live second-step lock refuses a
  later sign-in that a wrong candidate would have been refused for as a plain wrong password.
* ``auth.directory_login_locked`` -- a directory (Kerberos or OIDC) sign-in refused by a live lock
  (BACKLOG #3726). Its own action, so the whole row is hidden whatever its detail holds, and the
  OIDC ``callback_floor_exempt_amr`` marker can ride it without showing the lock to a reader
  without ``users:manage`` on these read paths. A ``users:manage`` holder reads it with its marker.
* ``auth.admin_unlocked`` -- the whole row, not only its lock fields. Its detail records both lock
  expiries and both cycle counts; stripped of those, it would still say that an account needed
  unlocking. An administrator reads it in full, which is who acts on it.
* The lock refusals of the factor legs, which share an action with an ordinary failure and say
  "a lock is live" only in their detail: ``auth.mfa_failed`` and ``auth.webauthn_failed`` with
  ``{"reason": "locked"}``. Only a holder of the account's session can cause one, but it would
  still show another reader that a second-step lock was live. The pre-#3726 directory text is
  named too; :data:`DIRECTORY_LOCKED_REFUSAL_DETAIL` says why.

**Considered and left visible:** ``auth.login_after_failures`` (written only on a full sign-in, so
nobody without both factors can cause it), the per-session re-proof cap rows (``auth.reauth`` with
``session_revoked`` and ``auth.password_change_failed`` with ``reason=session_revoked``, which
describe a session and not an account lock), and ``auth.temp_password_expired`` (at sign-in a
separate password-right signal on an account whose temporary credential has already expired,
outside this ruling; written later by a session that outlived that deadline, it carries an ``at``
naming the leg and says whether any proof was checked, and ``"at": "session"``, ``"at":
"logout"`` or ``"at": "superseded"`` means none was, BACKLOG #2009, #2298 and #3749).

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

**Some details are narrowed, not the row** (vault BACKLOG #3748 item 6): the channel lists and
scope sources on the rows :data:`CHANNEL_LIST_ACTIONS` names, through :func:`audit_detail_for`, on
``GET /audit``, its console page and the CSV export.

``/me/security-events`` is not filtered. It selects rows by the caller's own username at or after
the account's ``created_at``, so it shows the holder their own rows, the lock rows and the scope
rows whole. It can show another account's where an account keeps its ``created_at`` while its name
or holder changes; ``docs/SECURITY.md`` (the ``GET /me/security-events`` bullet under *Single-route
data rules*) names that residual.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

from messagefoundry.auth.identity import Identity
from messagefoundry.auth.permissions import Permission
from messagefoundry.redaction import json_loads_or_refusal
from messagefoundry.store.audit_exclusion import AuditExclusion

__all__ = [
    "ACCOUNT_LOCKED_ACTION",
    "ADMIN_UNLOCKED_ACTION",
    "AD_SCOPE_RESYNCED_ACTION",
    "AD_SESSION_REVOKED_ACTION",
    "AUDIT_WITHHELD_HEADER",
    "CHANNEL_LIST_ACTIONS",
    "CHANNEL_SCOPE_CHANGED_ACTION",
    "CHANNEL_SCOPE_CHANGE_REFUSED_ACTION",
    "DIRECTORY_LOCKED_REFUSAL_DETAIL",
    "DIRECTORY_LOGIN_LOCKED_ACTION",
    "HIDDEN_FROM_READERS_WITHOUT_USERS_MANAGE",
    "LOCKED_REFUSAL_DETAIL",
    "LOCK_EVENT_ACTIONS",
    "LOCK_NOTICE_ACTION",
    "LOCK_NOTICE_UNDELIVERED_ACTION",
    "LOGIN_LOCKED_ACTION",
    "SCOPE_WITHHELD",
    "audit_detail_for",
    "audit_exclusion_for",
    "is_audit_copy_line",
    "narrows_scope_rows_for",
    "reads_audit_copies_in_the_log",
    "withholds_rows_from",
]

ACCOUNT_LOCKED_ACTION: Final = "auth.account_locked"
LOCK_NOTICE_ACTION: Final = "auth.lock_notice"
#: A lock notice that never left this engine (BACKLOG #2383). Its own name, not
#: ``auth.security_notice_undelivered``, so the whole row can be hidden like the lock rows.
LOCK_NOTICE_UNDELIVERED_ACTION: Final = "auth.lock_notice_undelivered"
LOGIN_LOCKED_ACTION: Final = "auth.login_locked"
ADMIN_UNLOCKED_ACTION: Final = "auth.admin_unlocked"
#: A directory sign-in refused by a live lock (BACKLOG #3726). It used to share
#: ``auth.login_failed`` and be hidden by its exact detail text, so no field could be added to it.
DIRECTORY_LOGIN_LOCKED_ACTION: Final = "auth.directory_login_locked"

#: The whole-row hides.
LOCK_EVENT_ACTIONS: Final[frozenset[str]] = frozenset(
    {
        ACCOUNT_LOCKED_ACTION,
        LOCK_NOTICE_ACTION,
        LOCK_NOTICE_UNDELIVERED_ACTION,
        LOGIN_LOCKED_ACTION,
        DIRECTORY_LOGIN_LOCKED_ACTION,
        ADMIN_UNLOCKED_ACTION,
    }
)

#: The exact detail of a lock refusal on the TOTP/recovery and passkey legs. The writers use this
#: constant, so the stored text and the hidden text cannot drift apart.
LOCKED_REFUSAL_DETAIL: Final = json.dumps({"reason": "locked"}, sort_keys=True)
#: The exact detail a directory (Kerberos or OIDC) lock refusal stored under ``auth.login_failed``
#: before BACKLOG #3726 gave it :data:`DIRECTORY_LOGIN_LOCKED_ACTION`. No writer stores it now.
#: RETAINED DELIBERATELY: removing a filter was out of #3726's scope. It stays in the exclusion
#: below, and uncounted by the sign-in burst signal, until the dead-directory-lock-filter removal,
#: unallocated follow-up work, decides.
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


#: The actions whose rows carry an account's channel scope or who owns it. The writers in
#: :mod:`messagefoundry.auth.service` use these constants, so the written action and the narrowed
#: one cannot drift apart.
CHANNEL_SCOPE_CHANGED_ACTION: Final = "user.channel_scope_changed"
#: BACKLOG #2271: the row a refused :meth:`~messagefoundry.auth.service.AuthService.set_channel_scope`
#: writes. Its detail names the account, the caller's ``expected_source``, the raw stored source the
#: write read (``read_source``), the scope's ``owner`` and a ``reason`` from
#: :data:`~messagefoundry.auth.service.ChannelScopeRefusal`. Never the scope itself. On
#: ``source_changed`` the owner is the one read after the write failed, so it names whoever took the
#: scope: at least a directory sign-in or another administrator's save. A legacy AD scope reads
#: ``read_source`` null and ``owner`` ``"ad"`` (BACKLOG #2252). A store that refuses the row leaves
#: an ERROR log line instead, and the 409 still stands.
CHANNEL_SCOPE_CHANGE_REFUSED_ACTION: Final = "user.channel_scope_change_refused"
AD_SCOPE_RESYNCED_ACTION: Final = "auth.ad_scope_resynced"
AD_SESSION_REVOKED_ACTION: Final = "auth.ad_session_revoked"


@dataclass(frozen=True, slots=True)
class _Narrowed:
    """How a reader without ``users:manage`` reads one action's detail. ``shown`` keys keep their
    value. ``always`` keys read :data:`SCOPE_WITHHELD` whether or not the row holds them, so
    the row's shape cannot say what was stored. ``if_present`` keys read it where the row holds
    them. Every other key is dropped: an allowlist, so a key a later writer adds is withheld until
    someone decides it holds no scope."""

    shown: tuple[str, ...] = ()
    always: tuple[str, ...] = ()
    if_present: tuple[str, ...] = ()


#: The rows narrowed for a reader without ``users:manage`` (vault BACKLOG #3748 item 6): their
#: stored scope and its source are withheld from that reader, as ``GET /users`` withholds them
#: (BACKLOG #3189). Inference from rows left whole is not covered; ``docs/SECURITY.md`` names it. The row itself stays visible: who acted on whose scope, and when,
#: is not the scope. These are the audit actions whose detail names a channel list or a scope's
#: source, by a census of the writers on 2026-11-09:
#:
#: * ``user.channel_scope_changed`` -- the new list in ``channels``.
#: * ``auth.ad_scope_resynced`` -- the list a sign-in wrote, or the one it withdrew in
#:   ``withdrawn``. Read as ``channels`` alone, so a withdrawal reads as a set does.
#: * ``auth.ad_session_revoked`` -- the reconciler's ``scope_from`` and ``scope_to`` on a scope
#:   delta, the only row that carries them. ``scope_changed`` stays, so the row still says a scope
#:   moved.
#: * ``user.channel_scope_change_refused`` -- no list, but ``owner``, ``read_source``,
#:   ``expected_source`` and ``reason`` each say or imply who owns the scope.
#:
#: Checked and left whole: at least ``ad_group_scope_map.updated`` (a count), the session-revoke
#: rows' ``scope`` word (which sessions, not which channels) and ``auth.channel_denied`` (one
#: channel id the caller itself asked for). A NEW action whose detail names a scope is shown whole
#: until it is added here. ``tests/test_audit_scope_census.py`` fails on such a writer when its
#: detail is a dict literal in the call; a detail built elsewhere escapes it.
_NARROWED: Final[Mapping[str, _Narrowed]] = MappingProxyType(
    {
        CHANNEL_SCOPE_CHANGED_ACTION: _Narrowed(shown=("user_id",), always=("channels",)),
        AD_SCOPE_RESYNCED_ACTION: _Narrowed(always=("channels",)),
        AD_SESSION_REVOKED_ACTION: _Narrowed(
            shown=("reason", "sessions", "roles", "scope_changed"),
            if_present=("scope_from", "scope_to"),
        ),
        CHANNEL_SCOPE_CHANGE_REFUSED_ACTION: _Narrowed(
            shown=("user_id", "username"),
            always=("reason", "expected_source", "read_source", "owner"),
        ),
    }
)
CHANNEL_LIST_ACTIONS: Final[frozenset[str]] = frozenset(_NARROWED)
#: What a withheld value reads as. A string, so it cannot be read as a stored ``null``, which
#: denies, or as a list.
SCOPE_WITHHELD: Final = "withheld"


def narrows_scope_rows_for(identity: Identity) -> bool:
    """Whether ``identity`` reads :data:`CHANNEL_LIST_ACTIONS` rows narrowed: every reader
    without ``users:manage``, the permission ``GET /users`` shows a scope to."""
    return not identity.has(Permission.USERS_MANAGE)


def audit_detail_for(identity: Identity, action: str, detail: str | None) -> str | None:
    """``detail`` as ``identity`` may read it: for a reader :func:`narrows_scope_rows_for`
    names, a :data:`CHANNEL_LIST_ACTIONS` row reads as its action's :class:`_Narrowed` rule says.
    A detail that is null, is not a JSON object, or does not parse, depth limit included, reads as
    its ``always`` keys alone. Every other row is unchanged."""
    rule = _NARROWED.get(action)
    if rule is None or not narrows_scope_rows_for(identity):
        return detail
    parsed = None if detail is None else json_loads_or_refusal(detail)[0]
    stored: dict[str, object] = parsed if isinstance(parsed, dict) else {}
    return json.dumps(
        {
            **{key: stored[key] for key in rule.shown if key in stored},
            **{key: SCOPE_WITHHELD for key in rule.if_present if key in stored},
            **dict.fromkeys(rule.always, SCOPE_WITHHELD),
        },
        sort_keys=True,  # the writers' own form (``_json``), so a narrowed row reads like a stored one
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


#: The ``GET /audit/export`` response header that says whether the caller's permissions withheld
#: rows from the CSV (BACKLOG #2446): ``true`` or ``false``. A CSV body has nowhere to say it
#: without breaking the parsers that read it, so the header and the ``audit.export`` row carry it.
AUDIT_WITHHELD_HEADER: Final = "X-Audit-Withheld"


def withholds_rows_from(identity: Identity) -> bool:
    """Whether ``identity`` reads the trail with rows withheld (BACKLOG #2446).

    A reader is told this so a filtered trail does not read as the whole one. It is decided by the
    permission alone, never by whether a hidden row exists in the range read: an answer that
    depended on the rows would itself say whether a lock happened, which is the oracle the
    exclusion closes."""
    return audit_exclusion_for(identity) is not None


def reads_audit_copies_in_the_log(identity: Identity) -> bool:
    """Whether ``identity`` may read the tee's audit copies in ``GET /logs/tail``.

    **The ruling reaches the general log** (Manager decision 2026-09-28): ``logs:view`` is held by
    the built-in Operator, who lacks ``users:manage``, and the tee writes EVERY audit row into that
    log, the lock rows included. Withholding only the lock rows there would not do: each copy carries
    its ``row_id``, so the gaps would count the hidden rows. So a reader without ``users:manage``
    gets no audit copies from the log at all. It reads the trail, if it may, through ``GET /audit``,
    which applies :data:`HIDDEN_FROM_READERS_WITHOUT_USERS_MANAGE`."""
    return audit_exclusion_for(identity) is None
