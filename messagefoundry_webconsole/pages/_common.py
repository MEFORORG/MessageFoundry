# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Shared cell/format helpers for the /ui page builders (ADR 0065).

Small, escape-neutral formatters imported by the per-area page modules (``connections``,
``messages``, …) so the rendering conventions live in one place, never copy-pasted per module.
"""

from __future__ import annotations

from urllib.parse import quote


def _num(value: object) -> str:
    """Render a count/None as text ('—' for None)."""
    return "—" if value is None else str(value)


def _secs(value: float | None) -> str:
    """Render an age in seconds as a compact string ('—' for None)."""
    if value is None:
        return "—"
    return f"{value:.0f}s"


def _seg(value: object) -> str:
    """Percent-encode ONE path segment, INCLUDING ``/`` (BACKLOG #1370).

    ``quote`` DEFAULTS TO ``safe="/"``, which leaves alone the single character a path segment turns
    on. Measured rather than reasoned: ``quote("IB/ACME")`` returns it UNCHANGED, so a name carrying a
    slash silently becomes two segments and addresses a different route. ``safe=""`` is the whole fix,
    and it is why a bare ``quote`` call at one of these sites reads as protection while providing none
    against the one character that matters.

    CONNECTION NAMES ARE WHY THIS IS NOT THEORETICAL. They are unconstrained free text -- the registry
    checks only for a duplicate and no charset gate exists -- so the "every interpolated id is a
    ``uuid4().hex``" argument that covers most /ui interpolations is FALSE for them.

    NOT FOR A PATH LEGITIMATELY CARRIED IN A QUERY PARAMETER. ``_auth``'s re-auth ``next`` uses
    ``safe="/"`` deliberately, and routing it through here would break it. These sites are partitioned
    by READING each one, never by a blanket builder.
    """
    return quote(str(value), safe="")
