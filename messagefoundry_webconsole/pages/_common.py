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
    """Percent-encode ONE path segment (BACKLOG #1370).

    ``quote`` DEFAULTS TO ``safe="/"``, which leaves alone the single character a path segment turns
    on. Measured rather than reasoned: ``quote("IB/ACME")`` returns it UNCHANGED, which is why a bare
    ``quote`` call at one of these sites reads as protection while providing none against the one
    character that matters. ``safe=""`` is what this function adds.

    **WHAT ``safe=""`` DOES AND DOES NOT HOLD -- read this before citing it as containment
    (BACKLOG #1107).** It holds ``?`` and ``#``: those stay inside the segment, so a value cannot
    start a query string or truncate the path at a fragment. **It does NOT hold ``/`` at the ROUTING
    layer.** ASGI defines ``scope["path"]`` as the DECODED path and Starlette routes on it, so a
    ``%2F`` this function emits is turned back into a separator BEFORE any route is matched. Measured
    on a real uvicorn server, not TestClient: a request line of
    ``/ui/roles/custom%3Aabc%2Fevil/edit`` was handled by the ``{role_id}/{extra}/edit`` route with
    ``role_id="custom:abc"``. Whether a slash-bearing value reaches a DIFFERENT handler is therefore
    decided by the route table's shape, not by this call --
    ``test_a_percent_encoded_slash_does_not_survive_to_the_routing_layer`` pins the measurement and
    names the one same-method console pair where such a sibling exists.

    So this is still the right call at every path-segment site -- it holds two of the three
    metacharacters outright and keeps the rendered link honest -- but it is NOT a containment
    argument for ``/`` on its own.

    CONNECTION NAMES ARE WHY THIS IS NOT THEORETICAL. They are unconstrained free text -- the registry
    checks only for a duplicate and no charset gate exists -- so the "every interpolated id is a
    ``uuid4().hex``" argument that covers most /ui interpolations is FALSE for them.

    NOT FOR A PATH LEGITIMATELY CARRIED IN A QUERY PARAMETER. ``_auth``'s re-auth ``next`` uses
    ``safe="/"`` deliberately, and routing it through here would break it. These sites are partitioned
    by READING each one, never by a blanket builder.
    """
    return quote(str(value), safe="")
