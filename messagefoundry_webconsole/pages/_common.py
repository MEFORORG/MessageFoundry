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
    """Percent-encode ONE path segment, INCLUDING ``/`` (ASVS 1.2.2, BACKLOG #1107).

    ``quote`` defaults to ``safe="/"``, which leaves the single character a path segment turns on.
    Measured rather than reasoned: ``quote("IB/ACME")`` returns it UNCHANGED, so a name carrying a
    slash silently becomes two segments and addresses a different route.

    CONNECTION NAMES are why this is not theoretical. They are unconstrained free text --
    ``Registry._add`` checks only for a duplicate, and no charset gate exists -- so the "every
    interpolated id is a ``uuid4().hex``" argument that covers most /ui interpolations is FALSE for
    them. The remaining id-carrying sites are deliberately NOT routed through here yet: that argument
    is probably true of them, but it rests on a data-grammar invariant no line of URL-building code
    asserts, and deciding it is a separate piece of work.

    NOT for a path legitimately carried in a QUERY parameter. ``_auth``'s reauth ``next`` uses
    ``safe="/"`` on purpose, and routing it through here would break it -- the reason the research on
    #1107 says to partition these sites by READING each one rather than by a blanket builder.
    """
    return quote(str(value), safe="")
