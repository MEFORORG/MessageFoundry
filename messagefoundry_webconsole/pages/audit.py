# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Audit + self-service security-event page builders for the /ui ops dashboard (ADR 0065, L1c).

Read-only views over the tamper-evident audit log: the audit entries (``audit:read``) and the
caller's own ``auth.*`` security-event history (self-service). Both are metadata-only — the audit
``detail`` is PHI-free JSON — but every value is still placed through the escaping element builders in
:mod:`.._html`, so an actor/action/detail string can never inject markup.

Both page newest first against a total (BACKLOG #2438), through the shared :func:`._common._pager`,
so each page says which rows of how many it shows. A reader who took one page for the whole trail
would read an absence on screen as an absence in the log (BACKLOG #1743); the window-of-total line
is what prevents that.
"""

from __future__ import annotations

from datetime import UTC, datetime

from messagefoundry.api.auth_models import AuditList, SecurityEventsList

from .._html import Markup, el, page, register_nav, rows_table
from ._common import _pager

__all__ = ["audit_log", "security_events"]


def _ts(ts: float) -> str:
    """Render an epoch timestamp as a UTC ISO string (seconds); the raw float is opaque to operators."""
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%d %H:%M:%SZ")


#: Said to a reader whose permissions leave the lock rows out (BACKLOG #2446). It names the class
#: of row and never a row or a count: ``AuditList.withheld`` is decided by permission alone, so this
#: sentence appears whether or not a hidden row falls in range, and cannot say a lock happened.
WITHHELD_NOTE = (
    "Your permissions leave account-lock entries out of this list, its count and the export. "
    "A user with users:manage sees them."
)


#: Said on every security-events page (BACKLOG #2446): the feed selects rows whose actor is the
#: user, so an administrator's change to the account is absent by design, not because none was made.
ADMIN_CHANGES_NOTE = (
    "This page lists only entries recorded under your own name, such as your sign-ins and "
    "lockouts. A change an administrator made to your account, such as a password reset or a role "
    "change, is recorded under the administrator's name, so it is not listed here. The engine "
    "emails you about it when it can send mail to your notification address."
)


def _pin(as_of: float | None) -> dict[str, str]:
    """The snapshot pin a pager link carries (BACKLOG #2438), so Next and Previous read the set
    this page was read from while new rows arrive at the head of the trail. ``repr`` round-trips
    a float exactly, so the next page reads the same bound."""
    return {"as_of": repr(as_of)} if as_of is not None else {}


def _export_note(export_limit: int | None) -> Markup:
    """How to export, for a reader who may (BACKLOG #2446), or nothing for one who may not.

    The link is this console's ``/ui/audit/export``, which streams the engine's own export from the
    cookie session, so an auditor who signs in only through OIDC can export too. The export has its
    own ``limit`` and no offset; ``until`` moves it to older rows."""
    if export_limit is None:
        return Markup("")
    return el(
        "p",
        el("a", "Download the audit export (CSV)", href="/ui/audit/export", class_="btn-link"),
        f" It holds the newest {export_limit} entries. For older entries, add an until parameter "
        "(epoch seconds) to its address, or a larger limit.",
        class_="muted",
    )


def audit_log(data: AuditList, *, export_limit: int | None = None) -> Markup:
    """One page of the audit trail (``audit:read``): actor, action, channel, PHI-free detail.

    Newest first, paged by ``offset`` against ``data.total`` (BACKLOG #2438). The total is the
    caller's own: it is counted under the same lock-row exclusion as the rows (BACKLOG #1131), and
    ``data.withheld`` says so in words (BACKLOG #2446), or a short trail would read as the whole.

    ``export_limit`` is the console export's default cap for a caller holding ``audit:export``, and
    ``None`` for one who does not, who is shown no export link."""
    rows = [
        [_ts(e.ts), e.actor or "—", e.action, e.channel_id or "—", e.detail or ""]
        for e in data.entries
    ]
    return page(
        "Audit",
        el("h1", "Audit log"),
        el(
            "p",
            "The tamper-evident audit trail (metadata only — no PHI). Most recent first.",
            class_="muted",
        ),
        el("p", WITHHELD_NOTE, class_="banner") if data.withheld else Markup(""),
        _export_note(export_limit),
        rows_table(["When", "Actor", "Action", "Channel", "Detail"], rows),
        _pager(
            path="/ui/audit",
            total=data.total,
            limit=data.limit,
            offset=data.offset,
            shown=len(data.entries),
            noun="entry(s)",
            filters=_pin(data.as_of),
        ),
        active="audit",
    )


def security_events(data: SecurityEventsList) -> Markup:
    """The caller's OWN security-event history (self-service): sign-ins, lockouts, password/MFA
    changes on their account, newest first. No permission needed beyond a valid session.

    Paged against ``data.total`` for the same reason as :func:`audit_log`, and the reason is
    sharper here: this is where a user checks whether something happened to their account, so a
    page that read as the whole history would turn an older event into one that never happened.

    The feed lists only entries the user is the actor on (``auth/notifications.py`` states the
    rule), so a change an administrator made to the account is not here. The page says so, and says
    where such a change goes, so its absence does not read as "nothing happened" (BACKLOG #2446)."""
    rows = [[_ts(e.ts), e.action, e.detail or ""] for e in data.events]
    return page(
        "My security events",
        el("h1", "My security events"),
        el(
            "p",
            "Recent security-relevant activity on your account (sign-ins, lockouts, credential "
            "changes). Most recent first.",
            class_="muted",
        ),
        el("p", ADMIN_CHANGES_NOTE, class_="muted"),
        rows_table(["When", "Event", "Detail"], rows),
        _pager(
            path="/ui/security-events",
            total=data.total,
            limit=data.limit,
            offset=data.offset,
            shown=len(data.events),
            noun="event(s)",
            filters=_pin(data.as_of),
        ),
        active="security-events",
    )


# Nav registration (append-at-tail). Co-located with the builders (ADR 0065 §multi-session-build).
register_nav("audit", "/ui/audit", "Audit")
register_nav("security-events", "/ui/security-events", "My security events")
