# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Audit + self-service security-event page builders for the /ui ops dashboard (ADR 0065, L1c).

Read-only views over the tamper-evident audit log: the most recent audit entries (``audit:read``) and
the caller's own ``auth.*`` security-event history (self-service). Both are metadata-only — the audit
``detail`` is PHI-free JSON — but every value is still placed through the escaping element builders in
:mod:`.._html`, so an actor/action/detail string can never inject markup.

Both are capped windows and neither pages (BACKLOG #1743). They must say so: a reader who takes the
audit page for the whole trail reads an absence on screen as an absence in the log, which is the one
misreading a tamper-evident record exists to prevent.
"""

from __future__ import annotations

from datetime import UTC, datetime

from messagefoundry.api.auth_models import AuditList, SecurityEventsList

from .._html import Markup, el, page, register_nav, rows_table

__all__ = ["audit_log", "security_events"]


def _ts(ts: float) -> str:
    """Render an epoch timestamp as a UTC ISO string (seconds); the raw float is opaque to operators."""
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%d %H:%M:%SZ")


def _window_note(shown: int, limit: int, noun: str) -> Markup:
    """The one sentence that separates "this is everything" from "this is the newest ``limit``".

    STATE THE BOUND, NOT JUST THE COUNT (BACKLOG #1743). A bare "200 entries" is the same sentence
    whether the log holds 200 or 200,000, and the reader cannot tell which — so the cap goes in the
    text beside the count. Styled ``muted`` rather than ``pager``: ``pager`` is the class the two
    real pagers use for a line that CARRIES links, and borrowing it here would dress a dead end up
    as navigation."""
    return el("p", f"{shown} {noun} shown, capped at the newest {limit}.", class_="muted")


def audit_log(data: AuditList, *, limit: int) -> Markup:
    """One window of the audit trail (``audit:read``): actor, action, channel, PHI-free detail.

    NEWEST FIRST, AND ONLY THE NEWEST — the route asks for ``limit`` rows and this page renders what
    came back (BACKLOG #1743). It cannot say window-of-total the way the messages and dead-letter
    pagers do, because ``AuditList`` carries no total and the store's ``list_audit`` has neither an
    offset nor a count; giving this page a pager is a separate row that has to add both. Until then
    the honest surface for a full trail is the ``audit:export`` CSV, which streams its own filter.

    ``limit`` is passed in rather than re-declared here so the sentence states the bound the query
    actually used — a second copy of the number would be wrong the day either one moved."""
    rows = [
        [_ts(e.ts), e.actor or "—", e.action, e.channel_id or "—", e.detail or ""]
        for e in data.entries
    ]
    return page(
        "Audit",
        el("h1", "Audit log"),
        el(
            "p",
            "The tamper-evident audit trail (metadata only — no PHI). Most recent first. This page "
            "shows only the most recent entries, so an older event missing here is off this page, "
            "not out of the log; the audit export is the complete record.",
            class_="muted",
        ),
        rows_table(["When", "Actor", "Action", "Channel", "Detail"], rows),
        _window_note(len(data.entries), limit, "entry(s)"),
        active="audit",
    )


def security_events(data: SecurityEventsList, *, limit: int) -> Markup:
    """The caller's OWN security-event history (self-service): sign-ins, lockouts, password/MFA
    changes on their account, newest first. No permission needed beyond a valid session.

    Capped and pagerless for the same reason as ``audit_log``, and disclosed for a sharper one: this
    is where a user checks whether something happened to their account, so an event older than the
    newest ``limit`` reads as an event that never happened (BACKLOG #1743)."""
    rows = [[_ts(e.ts), e.action, e.detail or ""] for e in data.events]
    return page(
        "My security events",
        el("h1", "My security events"),
        el(
            "p",
            "Recent security-relevant activity on your account (sign-ins, lockouts, credential "
            "changes). Most recent first, and only the most recent — an older event missing here "
            "is off this page, not absent from the record.",
            class_="muted",
        ),
        rows_table(["When", "Event", "Detail"], rows),
        _window_note(len(data.events), limit, "event(s)"),
        active="security-events",
    )


# Nav registration (append-at-tail). Co-located with the builders (ADR 0065 §multi-session-build).
register_nav("audit", "/ui/audit", "Audit")
register_nav("security-events", "/ui/security-events", "My security events")
