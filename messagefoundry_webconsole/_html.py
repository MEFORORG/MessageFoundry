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

from collections.abc import Iterable
from html import escape

__all__ = ["Markup", "attr", "el", "page", "register_nav", "rows_table", "text"]

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
                # First-party live-poll script (no third-party JS). CSP: script-src 'self'.
                el("script", src="/ui/static/app.js", defer=True),
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


def _default_nav(active: str) -> Markup:
    links: list[object] = [el("span", "MessageFoundry", class_="brand")]
    for key, href, label in _NAV_ITEMS:
        links.append(el("a", label, href=href, class_="active" if key == active else None))
    # Logout is a POST (state-changing) rendered as a tiny same-origin form (form-action 'self').
    logout = el(
        "form",
        el("button", "Sign out", type="submit"),
        method="post",
        action="/ui/logout",
        class_="logout",
    )
    return el("nav", el("div", *links, class_="navlinks"), logout)


def rows_table(headers: Iterable[str], rows: Iterable[Iterable[object]]) -> Markup:
    """A table whose header cells and every body cell are escaped (cells accept ``Markup`` for links)."""
    head = el("tr", *[el("th", h) for h in headers])
    body = [el("tr", *[el("td", c) for c in row]) for row in rows]
    return el("table", el("thead", head), el("tbody", *body), class_="grid")
