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


def audit_log(data: AuditList) -> Markup:
    """One page of the audit trail (``audit:read``): actor, action, channel, PHI-free detail.

    Newest first, paged by ``offset`` against ``data.total`` (BACKLOG #2438). The total is the
    caller's own: it is counted under the same lock-row exclusion as the rows (BACKLOG #1131).

    THE EXPORT IS A SEPARATE ROUTE, so the page says how to reach it rather than linking to it.
    ``export_audit`` in ``api/auth_routes.py`` is on the engine API, whose ``require()`` reads only
    an ``Authorization`` bearer header, so this console's cookie does not reach it. It has its own
    ``limit`` and no offset; ``until`` moves it to older rows."""
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
        el(
            "p",
            "The audit export is GET /audit/export on the engine API. It needs audit:export and a "
            "bearer session from POST /auth/login, not this console session. It returns the newest "
            "entries up to its limit parameter. For older entries, set its until parameter (epoch "
            "seconds) to an earlier time.",
            class_="muted",
        ),
        rows_table(["When", "Actor", "Action", "Channel", "Detail"], rows),
        _pager(
            path="/ui/audit",
            total=data.total,
            limit=data.limit,
            offset=data.offset,
            shown=len(data.entries),
            noun="entry(s)",
        ),
        active="audit",
    )


def security_events(data: SecurityEventsList) -> Markup:
    """The caller's OWN security-event history (self-service): sign-ins, lockouts, password/MFA
    changes on their account, newest first. No permission needed beyond a valid session.

    Paged against ``data.total`` for the same reason as :func:`audit_log`, and the reason is
    sharper here: this is where a user checks whether something happened to their account, so a
    page that read as the whole history would turn an older event into one that never happened."""
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
        rows_table(["When", "Event", "Detail"], rows),
        _pager(
            path="/ui/security-events",
            total=data.total,
            limit=data.limit,
            offset=data.offset,
            shown=len(data.events),
            noun="event(s)",
        ),
        active="security-events",
    )


# Nav registration (append-at-tail). Co-located with the builders (ADR 0065 §multi-session-build).
register_nav("audit", "/ui/audit", "Audit")
register_nav("security-events", "/ui/security-events", "My security events")
