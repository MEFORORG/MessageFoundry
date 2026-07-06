# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Audit + self-service security-event page builders for the /ui ops dashboard (ADR 0065, L1c).

Read-only views over the tamper-evident audit log: the full audit trail (``audit:read``) and the
caller's own ``auth.*`` security-event history (self-service). Both are metadata-only — the audit
``detail`` is PHI-free JSON — but every value is still placed through the escaping element builders in
:mod:`.._html`, so an actor/action/detail string can never inject markup.
"""

from __future__ import annotations

from datetime import UTC, datetime

from messagefoundry.api.auth_models import AuditList, SecurityEventsList

from .._html import Markup, el, page, register_nav, rows_table


__all__ = ["audit_log", "security_events"]


def _ts(ts: float) -> str:
    """Render an epoch timestamp as a UTC ISO string (seconds); the raw float is opaque to operators."""
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%d %H:%M:%SZ")


def audit_log(data: AuditList) -> Markup:
    """The full audit trail (``audit:read``): actor, action, channel, and PHI-free detail, newest first."""
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
        rows_table(["When", "Actor", "Action", "Channel", "Detail"], rows),
        active="audit",
    )


def security_events(data: SecurityEventsList) -> Markup:
    """The caller's OWN security-event history (self-service): sign-ins, lockouts, password/MFA
    changes on their account, newest first. No permission needed beyond a valid session."""
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
        active="security-events",
    )


# Nav registration (append-at-tail). Co-located with the builders (ADR 0065 §multi-session-build).
register_nav("audit", "/ui/audit", "Audit")
register_nav("security-events", "/ui/security-events", "My security events")
