# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Zero-dependency, autoescape-by-default HTML rendering for the /ui ops dashboard (ADR 0065).

Security model (the reason this exists instead of a template engine): the **only** way to place a
dynamic value into the page is through :func:`el`/:func:`text`, which HTML-escape by default. Markup
that is already known safe must be wrapped explicitly in :class:`Markup`. There is **no**
template-syntax escape hatch (no ``|safe``), so an un-escaped injection of attacker-influenced HL7 is
not expressible in a page builder. Treat every message/HL7 value as hostile data.

This keeps the browser UI at **zero new runtime dependencies** (no jinja2, no npm) — a deliberate
trade recorded in ADR 0065; the module is small and localized so a later swap to a template engine is
contained.
"""

from __future__ import annotations

import contextvars
from collections.abc import Iterable
from html import escape

__all__ = [
    "Markup",
    "attr",
    "current_csp_nonce",
    "el",
    "page",
    "register_nav",
    "reset_csp_nonce",
    "rows_table",
    "set_csp_nonce",
    "text",
]

#: Per-response CSP nonce (ADR 0065 §hardening / BACKLOG #192, ASVS 3.4.7/3.4.8). The /ui security
#: middleware mints one per effective-https response and binds it here BEFORE the route renders;
#: :func:`page` reads it to stamp the ``<script>`` tag so it matches that response's
#: ``script-src 'nonce-…'`` header. A ContextVar (not a module global) so concurrent requests never
#: share a nonce; ``None`` over cleartext loopback means no nonce is emitted (byte-identity with the
#: pre-#192 tag).
_CSP_NONCE: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "mf_ui_csp_nonce", default=None
)


def set_csp_nonce(nonce: str | None) -> contextvars.Token[str | None]:
    """Bind ``nonce`` for the current context (the /ui security middleware, per effective-https
    response). Returns the reset token the middleware restores in its ``finally``."""
    return _CSP_NONCE.set(nonce)


def reset_csp_nonce(token: contextvars.Token[str | None]) -> None:
    """Undo a :func:`set_csp_nonce` binding (middleware teardown)."""
    _CSP_NONCE.reset(token)


def current_csp_nonce() -> str | None:
    """The CSP nonce bound for this response, or ``None`` (cleartext loopback → no nonce emitted)."""
    return _CSP_NONCE.get()


# HTML void elements never get a closing tag or children.
_VOID = frozenset(
    {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "wbr"}
)


class Markup(str):
    """A string already known to be safe HTML — never re-escaped by :func:`el`/:func:`text`.

    Only ever construct this from trusted, developer-authored markup (never from message/HL7 data).
    Results of :func:`el`/:func:`page` are ``Markup`` so builders compose without double-escaping.
    """

    __slots__ = ()


def text(value: object) -> Markup:
    """Escape any value to safe HTML text. ``Markup`` passes through; ``None`` renders empty."""
    if isinstance(value, Markup):
        return value
    return Markup(escape("" if value is None else str(value), quote=True))


def _render_child(child: object) -> str:
    if isinstance(child, Markup):
        return child
    if isinstance(child, (list, tuple)):
        return "".join(_render_child(c) for c in child)
    return escape("" if child is None else str(child), quote=True)


def attr(name: str, value: object) -> Markup:
    """Render a single escaped ``name="value"`` attribute (both sides escaped)."""
    return Markup(f'{escape(name)}="{escape(str(value), quote=True)}"')


def el(tag: str, *children: object, **attrs: object) -> Markup:
    """Build an element with escaped attributes and escaped children.

    Attribute keys map ``_`` → ``-`` and a trailing ``_`` is stripped (so ``class_`` → ``class``,
    ``hx_get`` → ``hx-get``). A ``None``/``False`` attribute value is omitted; ``True`` renders a bare
    attribute. Children that are :class:`Markup` pass through; any other value is HTML-escaped — so a
    raw ``str`` (e.g. an HL7 field) can never inject markup.
    """
    parts: list[str] = [f"<{escape(tag)}"]
    for key, value in attrs.items():
        if value is None or value is False:
            continue
        name = key.rstrip("_").replace("_", "-")
        if value is True:
            parts.append(f" {escape(name)}")
        else:
            parts.append(f' {escape(name)}="{escape(str(value), quote=True)}"')
    parts.append(">")
    if tag in _VOID:
        return Markup("".join(parts))
    for child in children:
        parts.append(_render_child(child))
    parts.append(f"</{escape(tag)}>")
    return Markup("".join(parts))


def page(title: str, *body: object, nav: object = None, active: str = "") -> Markup:
    """Wrap page ``body`` in the shared document chrome (doctype, head, nav, main).

    ``title`` and all ``body`` content are escaped by the element builders. The head links only the
    same-origin ``/ui/static`` assets (CSP ``script-src 'self'`` — no inline script). No inline
    ``<script>`` or ``on*`` handlers anywhere.
    """
    head = Markup(
        "".join(
            [
                el("meta", charset="utf-8"),
                el("meta", name="viewport", content="width=device-width, initial-scale=1"),
                el("meta", name="referrer", content="no-referrer"),
                el("title", f"{title} — MessageFoundry"),
                el("link", rel="stylesheet", href="/ui/static/app.css"),
                # First-party live-poll script (no third-party JS). Over an effective-https response the
                # /ui security middleware binds a per-response CSP nonce that stamps this tag + the
                # matching ``script-src 'nonce-…' 'strict-dynamic'`` header (ADR 0065 §hardening / #192);
                # over cleartext loopback the nonce is None and the tag is byte-identical to before
                # (CSP: script-src 'self').
                el("script", src="/ui/static/app.js", defer=True, nonce=current_csp_nonce()),
            ]
        )
    )
    header = nav if nav is not None else _default_nav(active)
    document = Markup(
        "<!doctype html>"
        + el(
            "html",
            el("head", head),
            el("body", header, el("main", *body)),
            lang="en",
        )
    )
    return document


# The top-nav registry (key, href, label), in display order. Seeded with the core phase-0 items; a
# page lane appends ONE entry via register_nav() co-located with its builder, so parallel lanes never
# collide on a central literal (ADR 0065 §multi-session-build). Display order = registration order.
_NAV_ITEMS: list[tuple[str, str, str]] = [
    ("dashboard", "/ui", "Connections"),
    ("messages", "/ui/messages", "Messages"),
    ("dead-letters", "/ui/dead-letters", "Dead letters"),
]


def register_nav(key: str, href: str, label: str) -> None:
    """Register a top-nav item (idempotent by ``key``; appended at the tail = displayed last).

    A read/admin page lane calls this at import from its own page module to add itself to the nav
    without editing this file — the append-only seam that keeps parallel lanes conflict-free.
    """
    if not any(existing == key for existing, _href, _label in _NAV_ITEMS):
        _NAV_ITEMS.append((key, href, label))


def wordmark(*, tm: bool = False) -> Markup:
    """The **MessageFoundry** wordmark, per the brand wordmark guidelines (June 2026): the single
    camelCase word with ``Message`` in the base text color and ``Foundry`` in molten amber
    (``#f59e0b``, the ``--foundry`` token). ``tm=True`` appends the superscript ™ — set it on the
    primary lockup (the masthead) and the most-prominent appearance (the sign-in heading), and omit
    it on repeated or running-text mentions. The amber stays confined to this mark and headings —
    never body copy. ``Message`` and ``Foundry`` are adjacent with no separating space so the mark
    renders as one word.
    """
    parts: list[object] = ["Message", el("span", "Foundry", class_="wm-foundry")]
    if tm:
        parts.append(el("sup", "™", class_="wm-tm"))
    return el("span", *parts, class_="wordmark")


#: Top-nav groups, each rendered as a dropdown: (menu label, member keys). A registered key not listed
#: here falls into a trailing "More" menu, so a new page lane still appears without editing this.
_NAV_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Traffic", ("dashboard", "messages", "dead-letters", "events")),
    ("Monitoring", ("status", "alerts", "audit")),
    ("Admin", ("users", "config")),
    ("Account", ("account", "security-events")),
)


# Two live status glyphs pinned to the right of the nav (left of Sign out): the alerts bell and the
# engine-health heart. They render NEUTRAL (gray) with data hooks; app.js polls GET /ui/nav-status (~15s,
# from every page) and recolors them — green/orange/blinking-red for engine health, severity-colored or gray
# for alerts. Monochrome inline SVG with fill=currentColor so a CSS `color` drives the tint (emoji can't be
# recolored). The SVGs are static, hand-authored Markup constants with NO data interpolation — no injection
# surface under the CSP. (Material-style glyph paths, 24×24 viewBox.)
_BELL_SVG = Markup(
    '<svg class="statglyph" viewBox="0 0 24 24" width="18" height="18" aria-hidden="true" '
    'focusable="false"><path fill="currentColor" d="M12 22c1.1 0 2-.9 2-2h-4c0 1.1.9 2 2 2zm6-6v-5c0-3.07'
    "-1.63-5.64-4.5-6.32V4c0-.83-.67-1.5-1.5-1.5s-1.5.67-1.5 1.5v.68C7.63 5.36 6 7.92 6 11v5l-2 2v1h16v-1"
    'l-2-2z"/></svg>'
)
_HEART_SVG = Markup(
    '<svg class="statglyph" viewBox="0 0 24 24" width="18" height="18" aria-hidden="true" '
    'focusable="false"><path fill="currentColor" d="M12 21.35l-1.45-1.32C5.4 15.36 2 12.28 2 8.5 2 5.42 '
    "4.42 3 7.5 3c1.74 0 3.41.81 4.5 2.09C13.09 3.81 14.76 3 16.5 3 19.58 3 22 5.42 22 8.5c0 3.78-3.4 "
    '6.86-8.55 11.54L12 21.35z"/></svg>'
)


def _nav_status_icons() -> Markup:
    """The alerts bell + engine-health heart, in that order (alerts left of the heart). Each is a LINK to
    its detail page — the bell to /ui/alerts, the heart to /ui/status — so a colored glyph is a one-click
    path to the related items. Neutral until the first ``/ui/nav-status`` poll recolors them + sets a live
    aria-label (app.js). No ``role=status``: as a link the state rides the aria-label (announced on focus),
    not a live region that would re-announce every 15s poll. The container carries the app.js hook."""
    bell = el(
        "a",
        _BELL_SVG,
        href="/ui/alerts",
        class_="navstat alerts-unknown",
        data_mf_nav_alerts=True,
        title="Active alerts",
        aria_label="Active alerts",
    )
    heart = el(
        "a",
        _HEART_SVG,
        href="/ui/status",
        class_="navstat health-unknown",
        data_mf_nav_health=True,
        title="Engine health",
        aria_label="Engine health",
    )
    return el("div", bell, heart, class_="navstatus", data_mf_nav_status=True)


def _default_nav(active: str) -> Markup:
    by_key = {key: (key, href, label) for key, href, label in _NAV_ITEMS}
    seen: set[str] = set()

    def _link(item: tuple[str, str, str]) -> Markup:
        key, href, label = item
        return el("a", label, href=href, class_="active" if key == active else None)

    def _dropdown(glabel: str, items: list[tuple[str, str, str]]) -> Markup:
        # CSS-only dropdown: opens on :hover AND :focus-within, so it's keyboard-reachable with NO JS
        # (stays within the script-src 'self' CSP). The toggle is a <button> (a menu opener, not a link)
        # and shows active when the current page is one of its members; the items inside navigate.
        active_group = any(item[0] == active for item in items)
        top = el(
            "button",
            f"{glabel} ▾",
            type="button",
            # aria-haspopup marks it a menu opener; aria-expanded is intentionally omitted — a CSS-only
            # menu can't truthfully toggle it without JS, so an honest static button beats a lying attr.
            aria_haspopup="menu",
            class_="navtop active" if active_group else "navtop",
        )
        menu = el("div", *[_link(i) for i in items], class_="navmenu")
        return el("div", top, menu, class_="navgroup")

    groups: list[object] = []
    for glabel, keys in _NAV_GROUPS:
        items = [by_key[k] for k in keys if k in by_key]
        seen.update(k for k in keys if k in by_key)
        if items:
            groups.append(_dropdown(glabel, items))
    extra = [item for item in _NAV_ITEMS if item[0] not in seen]  # future lanes, ungrouped
    if extra:
        groups.append(_dropdown("More", extra))

    brand = el("a", wordmark(tm=True), href="/ui", class_="brand")
    # Logout is a POST (state-changing) rendered as a tiny same-origin form (form-action 'self').
    logout = el(
        "form",
        el("button", "Sign out", type="submit"),
        method="post",
        action="/ui/logout",
        class_="logout",
    )
    # Right cluster: the live status glyphs then Sign out, grouped so nav's space-between keeps the links
    # left and this block flush right (heart sits directly left of Sign out, alerts left of the heart).
    right = el("div", _nav_status_icons(), logout, class_="navright")
    return el("nav", el("div", brand, *groups, class_="navlinks"), right)


def rows_table(
    headers: Iterable[str], rows: Iterable[Iterable[object]], *, adjustable: bool = True
) -> Markup:
    """A table whose header cells and every body cell are escaped (cells accept ``Markup`` for links).

    ``adjustable`` (default) marks it ``data-mf-table`` so ``app.js`` enhances it in the browser with
    click-to-sort + drag-to-resize columns (remembered per table). Use it for DATA GRIDS — the connections
    dashboard, message/audit lists — where sorting and resizing earn their keep.

    Pass ``adjustable=False`` for small **key/value readout** tables (status, connection detail, config
    reload): they render as a plain full-width table (class ``info``) whose long values WRAP instead of the
    fixed-layout grid's explicit width — so they never show a horizontal scrollbar, and they drop the
    sort/resize UI a 2-column readout doesn't need. Purely presentational; with JS off both render plainly.
    """
    head = el("tr", *[el("th", h) for h in headers])
    body = [el("tr", *[el("td", c) for c in row]) for row in rows]
    if adjustable:
        return el("table", el("thead", head), el("tbody", *body), class_="grid", data_mf_table=True)
    return el("table", el("thead", head), el("tbody", *body), class_="grid info")
