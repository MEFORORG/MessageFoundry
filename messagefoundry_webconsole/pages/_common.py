# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Shared cell/format and URL helpers for the /ui page builders (ADR 0065).

Small, escape-neutral formatters imported by the per-area page modules (``connections``,
``messages``, …) so the rendering conventions live in one place, never copy-pasted per module.

Some of these build a URL or a whole footer rather than format a cell — at least ``_seg`` for one
path segment, ``_pager`` for a listing's Previous/Next query, and ``_window_note`` for a listing
that is capped and cannot page — and that is why they are here rather than in ``.._html``: that
module is the page-agnostic escaping layer and knows nothing about /ui's routes or their query
parameters, while getting an operator-supplied value safely into a link is exactly the convention
this module exists to keep in one place.
"""

from __future__ import annotations

from collections.abc import Mapping
from urllib.parse import quote, urlencode

from .._html import Markup, el, text


def _pager(
    *,
    path: str,
    total: int,
    limit: int,
    offset: int,
    shown: int,
    noun: str,
    filters: Mapping[str, str] | None = None,
) -> Markup:
    """The window-of-total counter plus Previous/Next links for one paged listing (BACKLOG #1743).

    ``total`` is the whole filtered set and ``shown`` is the size of the rendered window, so the line
    states both. A bare count cannot distinguish "you have three" from "you are looking at three of
    forty", which is the reading that makes a pager invisible.

    **``filters`` MUST carry every filter the current listing was run under.** A Previous/Next link
    that drops one re-runs a DIFFERENT, wider query and still returns rows, so the operator reads a
    result set under a filter they typed and the engine did not apply -- the same substitution
    BACKLOG #1744 refused on the date bounds, arriving by a link instead of by a form. Every value
    goes through ``urlencode`` and then the attribute escaping in ``el``, so an operator-supplied
    filter can leave neither the query string nor the attribute.

    **An EMPTY value is omitted, and that is not the same as carrying it.** A blank box means the
    operator set no filter, so the link says so; sending ``status=`` instead would hand the store a
    narrowing predicate. These two readings are visibly different at the message log today --
    measured 2026-09-18 on three messages: ``?channel_id=ch1`` renders all three, while
    ``?channel_id=ch1&status=`` renders none. Omitting is the reading a link should replay.
    **No page can show that difference**, because a blank filter narrows to zero rows and a
    zero-row window renders no links at all -- so this is a statement about which reading is right,
    not a hazard this builder leaves open. That the blank one is reachable AT ALL, from the filter
    form's own submit, is a separate defect of the route and is filed separately.

    The caller passes ``path`` as a plain literal; this builder never interpolates into one.
    ``limit`` is floored at 1 here rather than assumed: every route clamps it (``Query(ge=1)``), but
    none of the three list models declares a bound, so the clamp is a property of today's callers
    and not of this builder, and a zero would 500 the whole page on the division below.
    """
    limit = max(limit, 1)
    active = {k: v for k, v in (filters or {}).items() if v}

    def _link(label: str, target: int) -> Markup:
        query = urlencode({**active, "limit": limit, "offset": target})
        return el("a", label, href=f"{path}?{query}", class_="btn-link")

    # An EMPTY window is not "rows 0 to offset": a bookmarked page-N link outlives the rows it named
    # (a retention purge, a narrowed filter, a hand-typed offset), and "0-100 of 3" reads as a count
    # that contradicts the empty table above it. State the total, then the offset separately so the
    # operator can still say WHERE they were -- which is what the replaced "(offset N)" line gave.
    if shown:
        parts: list[object] = [text(f"{offset + 1}-{offset + shown} of {total} {noun}")]
    else:
        parts = [text(f"0 of {total} {noun} (offset {offset})")]
    if offset > 0:
        # Step back to the last page that HAS rows rather than one window back, which from past the
        # end would still be past the end and would strand the operator on a second empty page.
        past_end = shown == 0 and offset >= total
        previous = (max(total - 1, 0) // limit) * limit if past_end else max(offset - limit, 0)
        parts += [Markup(" "), _link("Previous", previous)]
    if offset + shown < total:
        parts += [Markup(" "), _link("Next", offset + limit)]
    return el("p", *parts, class_="pager")


def _window_note(shown: int, limit: int, noun: str) -> Markup:
    """The footer for a listing that is CAPPED and cannot page — the sentence that separates "this
    is everything" from "this is the newest ``limit``" (BACKLOG #1743).

    STATE THE BOUND, NOT JUST THE COUNT. A bare "200 entries" is the same sentence whether the log
    holds 200 or 200,000, and the reader cannot tell which, so the cap goes in the text beside the
    count. Styled ``muted`` rather than ``pager``: ``pager`` is the class :func:`_pager` uses for a
    line that CARRIES links, and borrowing it here would dress a dead end up as navigation.

    It lives beside :func:`_pager` rather than in the one page that calls it today, because the next
    capped listing needs the same sentence and copying it is how the two pagers diverged."""
    return el("p", f"{shown} {noun} shown, capped at the newest {limit}.", class_="muted")


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
