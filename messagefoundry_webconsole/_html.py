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
    "CSP_PROBE_SRC",
    "SCRIPTS_BLOCKED_BANNER_ID",
    "SCRIPTS_OK_CLASS",
    "Markup",
    "attr",
    "current_csp_nonce",
    "el",
    "minimal_nav",
    "page",
    "register_nav",
    "reset_csp_nonce",
    "rows_table",
    "set_csp_nonce",
    "text",
]

#: Per-response CSP nonce (ADR 0065 §hardening / BACKLOG #192, ASVS 3.4.7/3.4.8). The /ui security
#: middleware mints one per SECURE-CONTEXT response (effective-https OR the loopback secure-context —
#: ``security_headers_context``, ADR 0143) and binds it here BEFORE the route renders; :func:`page`
#: reads it to stamp the ``<script>`` tag so it matches that response's ``script-src 'nonce-…'`` header.
#: A ContextVar (not a module global) so concurrent requests never share a nonce; ``None`` when the
#: middleware binds none (the org opt-out, or a cleartext NON-loopback context) means no nonce is emitted
#: (byte-identity with the pre-#192 tag).
_CSP_NONCE: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "mf_ui_csp_nonce", default=None
)


def set_csp_nonce(nonce: str | None) -> contextvars.Token[str | None]:
    """Bind ``nonce`` for the current context (the /ui security middleware, per secure-context response —
    effective-https OR the loopback secure-context, ADR 0143). Returns the reset token the middleware
    restores in its ``finally``."""
    return _CSP_NONCE.set(nonce)


def reset_csp_nonce(token: contextvars.Token[str | None]) -> None:
    """Undo a :func:`set_csp_nonce` binding (middleware teardown)."""
    _CSP_NONCE.reset(token)


def current_csp_nonce() -> str | None:
    """The CSP nonce bound for this response, or ``None`` (no nonce: the org opt-out, or a cleartext
    NON-loopback context — the loopback secure-context binds one, ADR 0143)."""
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


def page(
    title: str,
    *body: object,
    nav: object = None,
    active: str = "",
    head_extra: object = None,
) -> Markup:
    """Wrap page ``body`` in the shared document chrome (doctype, head, nav, main).

    ``title`` and all ``body`` content are escaped by the element builders. The head links the
    same-origin ``/ui/static`` assets. There are no ``on*`` handlers anywhere.

    **The 3.7.5 hardening detects, all emitted on the single ``nonce is not None`` gate** — a
    per-response CSP nonce is bound, i.e. an effective-https response OR the loopback secure-context
    (``security_headers_context``, ADR 0143). Four artifacts ship together, or none of them do:

    * a NONCE'D inline mark script that stamps :data:`SCRIPTS_OK_CLASS` on ``<html>`` (and, as a belt,
      hides the banner below directly once the body is parsed);
    * an UN-NONCED external ``<script src=`` :data:`CSP_PROBE_SRC` ``>`` — the CSP-enforcement canary,
      deliberately NOT nonced: an enforcing browser must refuse it, so a nonce would invert the signal;
    * a NONCE'D inline detect that raises the insecure-context and CSP-degraded banners;
    * the server-rendered :data:`SCRIPTS_BLOCKED_BANNER_ID` ``role="alert"`` in ``<body>``, which the
      mark script above removes from view on a healthy client.

    With no nonce bound (the org opt-out, or a cleartext NON-loopback context) NONE of the four is
    emitted and the shell is byte-identical to the pre-hardening page: no inline script the static
    ``script-src 'self'`` CSP would block, and no canary that same policy would ALLOW (which would read
    as "CSP not enforced" on a perfectly conforming browser).

    ``head_extra`` appends markup to the ``<head>`` and is ``None`` for every existing caller, so the
    rendered document is byte-identical unless a caller opts in. It exists for the federated-login
    landing hop (ADR 0142), which needs a ``<meta http-equiv="refresh">``: a pragma directive is only
    conforming inside ``<head>``, and relying on browsers' tolerance of one in ``<body>`` would make a
    security-critical redirect depend on undefined behaviour.
    """
    nonce = current_csp_nonce()
    head_parts: list[Markup] = [
        el("meta", charset="utf-8"),
        el("meta", name="viewport", content="width=device-width, initial-scale=1"),
        el("meta", name="referrer", content="no-referrer"),
        el("title", f"{title} — MessageFoundry"),
        el("link", rel="stylesheet", href="/ui/static/app.css"),
        # First-party live-poll script (no third-party JS). On a SECURE-CONTEXT response (effective-https
        # OR the loopback secure-context — ``security_headers_context``, ADR 0143) the /ui security
        # middleware binds a per-response CSP nonce that stamps this tag + the matching
        # ``script-src 'nonce-…' 'strict-dynamic'`` header (ADR 0065 §hardening / #192); when no nonce is
        # bound (opt-out / cleartext non-loopback) the nonce is None and the tag is byte-identical (CSP:
        # script-src 'self').
        el("script", src="/ui/static/app.js", defer=True, nonce=nonce),
    ]
    # 3.7.5 client-side hardening detects: emitted ONLY when a per-response nonce is bound (a
    # secure-context response — effective-https OR loopback, ADR 0143). With no nonce bound (opt-out /
    # cleartext non-loopback) ``nonce is None`` -> the shell is byte-identical AND we never emit an
    # inline <script> the ``script-src 'self'`` CSP would block (nor the canary, which that policy
    # would ALLOW as 'self' and so would falsely read as "CSP not enforced").
    if nonce is not None:
        # (a0) The SCRIPTS-RUNNING MARK: a nonce'd inline script that flags the document element, so
        # the server-rendered ``mf-scripts-blocked-banner`` below is hidden by app.css BEFORE first
        # paint on a healthy client (no flash) and STANDS on a client that runs no script at all. It
        # is first in document order so the mark is set as early as possible, and it is the inverse
        # detect to the canary: the canary catches "CSP not enforced", this catches "our own nonce'd
        # scripts did not run" — a browser that ENFORCES CSP but does not understand nonce sources
        # blocks every script under ``script-src 'nonce-…' 'strict-dynamic'`` (app.js, the detect
        # below, and the 14.3.1 session watchdog), so no script-raised banner could ever render.
        head_parts.append(el("script", Markup(_SCRIPTS_RUNNING_MARK_JS), nonce=nonce))
        # (a) The CSP-ENFORCEMENT CANARY: an UN-NONCED external script. Parser-blocking (no defer/
        # async) so it resolves BEFORE the nonce'd detect below runs — classic scripts execute in
        # document order. Under ``script-src 'nonce-…' 'strict-dynamic'`` an enforcing browser refuses
        # it before the fetch and ``window.__mfCspProbe`` stays undefined; a browser that does not
        # enforce CSP runs it. An EXTERNAL probe rather than an inline one is deliberate: its blocked
        # URL is a unique discriminator, so the one expected violation report can be filtered out of
        # the log by path WITHOUT a filter broad enough to also swallow the report a real inline XSS
        # injection would produce (which is indistinguishable from a blocked inline canary), and
        # without adding ``'report-sample'`` — which would put attacker-influenced script text into
        # the general log.
        head_parts.append(el("script", src=CSP_PROBE_SRC))
        # (b) The nonce'd detect + banner script, which reads (a)'s outcome. Both banners
        # degrade-never-block (see ``_INSECURE_CONTEXT_WARN_JS`` / ``_CSP_NOT_ENFORCED_WARN_JS``).
        head_parts.append(
            el("script", Markup(_INSECURE_CONTEXT_WARN_JS + _CSP_NOT_ENFORCED_WARN_JS), nonce=nonce)
        )
    if head_extra is not None:
        head_parts.append(Markup(str(head_extra)))
    head = Markup("".join(head_parts))
    header = nav if nav is not None else _default_nav(active)
    # The scripts-blocked banner is SERVER-rendered (plain HTML, no script needed to show it) and
    # removed from view by app.css only once the nonce'd mark script has run — fail-VISIBLE. Emitted
    # on the same gate as the head detects, so the no-nonce shell stays byte-identical.
    body_parts: list[object] = []
    if nonce is not None:
        body_parts.append(_SCRIPTS_BLOCKED_BANNER)
    body_parts.extend((header, el("main", *body)))
    document = Markup(
        "<!doctype html>"
        + el(
            "html",
            el("head", head),
            el("body", *body_parts),
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
    ("Monitoring", ("status", "alerts", "flow", "audit", "uploaded-logs")),
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

# 3.7.5 (ASVS): a nonce'd, client-side insecure-context banner. window.isSecureContext is the
# transport precondition a page script can read directly; CSP-nonce ENFORCEMENT is detected
# separately and actively by the un-nonced canary (``_CSP_NOT_ENFORCED_WARN_JS`` below reads its
# outcome). COOP/CORP enforcement remains genuinely undetectable from inside the page — no browser API
# exposes it — and is documented as degrade-silent-with-rationale rather than warned. Both banners are
# a VISIBLE signal, never an active block (degrade-never-block): each only inserts a DOM node, wrapped
# in try/catch, textContent-only, NO inline on* handler.
# Static developer-authored JS with no data interpolation (Markup, like the nav SVGs) => not an
# injection surface. page() emits it whenever a per-response nonce is bound — a secure-context response
# (effective-https OR the loopback secure-context, ADR 0143). With no nonce bound (opt-out / cleartext
# non-loopback) the shell stays byte-identical AND the `script-src 'self'` CSP would otherwise block an
# un-nonced inline script. http://localhost / http://127.0.0.1 are themselves secure contexts, so even
# when the loopback shell now carries this nonce'd script, window.isSecureContext is true and it never
# trips (no banner shown).
_INSECURE_CONTEXT_WARN_JS = Markup(
    "(function(){try{if(window.isSecureContext===false){"
    "var show=function(){"
    "if(!document.body||document.getElementById('mf-insecure-context-banner'))return;"
    "var b=document.createElement('div');b.id='mf-insecure-context-banner';"
    "b.className='mf-insecure-banner';b.setAttribute('role','alert');"
    "b.textContent='Insecure connection: this console is not being served to your browser over "
    "HTTPS. Browser hardening (secure cookies, COOP, CSP nonces) is degraded. Reach it over the "
    "https:// origin behind the documented reverse proxy.';"
    "document.body.insertBefore(b,document.body.firstChild);};"
    "if(document.body){show();}else{document.addEventListener('DOMContentLoaded',show);}"
    "}}catch(e){}})();"
)

#: The un-nonced CSP-enforcement canary the shell loads (see :func:`page`). A browser enforcing the
#: nonce CSP blocks it; the resulting violation report is the ONE expected report, filtered out of the
#: log by this exact path in ``routes.core`` (ASVS 3.7.5).
CSP_PROBE_SRC = "/ui/static/csp-probe.js"

#: The class the nonce'd mark script stamps on ``<html>`` and the id of the server-rendered banner it
#: thereby hides (``app.css`` owns the hiding rule). Named constants because THREE artifacts must
#: agree — the mark script, the banner markup, and the stylesheet.
SCRIPTS_OK_CLASS = "mf-scripts-ok"
SCRIPTS_BLOCKED_BANNER_ID = "mf-scripts-blocked-banner"

# 3.7.5: the nonce'd mark. Static developer-authored JS, no data interpolation (Markup, like the nav
# SVGs) => not an injection surface. ``className +=`` rather than classList for maximum compatibility
# with exactly the old/limited clients this detect exists for.
#
# TWO mechanisms, deliberately: the class stamp (hidden by app.css BEFORE first paint, no flash) is the
# LOAD-BEARING path — it is the only one that can work on a client that runs no script at all, which is
# the case the banner exists for. The direct ``style.display`` hide is a BELT against a warn control
# that cries wolf on a healthy client: the stylesheet link carries no cache-buster (adding one would
# break the byte-identity of the no-nonce shell, a deliberate invariant), and the static mount emits
# etag/last-modified but no Cache-Control, so a browser applying heuristic freshness can render
# post-upgrade HTML against a pre-upgrade app.css that has no hiding rule yet. Scripts run in that
# scenario, so the belt fires and the banner never appears on a conforming client. The banner lives in
# <body>, which the head-parse-time mark script has not reached yet, so the hide is deferred to
# DOMContentLoaded (and runs immediately if the document is already past parsing).
_SCRIPTS_RUNNING_MARK_JS = Markup(
    "(function(){try{document.documentElement.className+=' "
    + SCRIPTS_OK_CLASS
    + "';var hide=function(){var b=document.getElementById('"
    + SCRIPTS_BLOCKED_BANNER_ID
    + "');if(b){b.style.display='none';}};"
    "if(document.readyState!=='loading'){hide();}"
    "else{document.addEventListener('DOMContentLoaded',hide);}"
    "}catch(e){}})();"
)

#: 3.7.5: the FAIL-VISIBLE half of the detect pair. The canary catches a browser that does not enforce
#: CSP; this catches the inverse — a browser that ENFORCES CSP but does not understand ``'nonce-…'`` /
#: ``'strict-dynamic'`` sources (and, incidentally, a browser with JavaScript disabled). Under
#: ``script-src 'nonce-…' 'strict-dynamic'`` such a client has no valid script source at all, so it
#: blocks app.js, both detect scripts AND the 14.3.1 session watchdog — no script-raised banner could
#: ever render, and the console would silently lose its client-side PHI controls. So the warning is
#: SERVER-rendered and visible by default; ``app.css`` hides it under :data:`SCRIPTS_OK_CLASS`, which
#: only the nonce'd mark script above can set. A client that blocks scripts leaves it standing.
_SCRIPTS_BLOCKED_BANNER = el(
    "div",
    "This browser is not running the console's scripts: Content-Security-Policy nonce sources are "
    "unsupported or JavaScript is disabled. Client-side protections — the automatic session "
    "logoff that clears this page, the insecure-connection detect and live status — are NOT "
    "active. Server-side session expiry, permissions and auditing still apply. Use a current "
    "browser with JavaScript enabled.",
    id=SCRIPTS_BLOCKED_BANNER_ID,
    class_="mf-insecure-banner",
    role="alert",
)

# 3.7.5 (ASVS): the ACTIVE CSP-enforcement detect, and the reason the 'JS cannot feature-detect nonce
# enforcement' limitation no longer holds for THIS header. ``window.__mfCspProbe`` can only be true if
# the un-nonced canary script executed, which the nonce CSP forbids — so a truthy flag is positive
# evidence that the browser is NOT enforcing the policy, on the default deployment, where the
# isSecureContext banner is correctly inert (http://127.0.0.1 IS a secure context). Same
# degrade-never-block shape as the banner above: a DOM node, try/catch, textContent only, no on*
# handler, no data interpolation (Markup, like the nav SVGs) => not an injection surface.
_CSP_NOT_ENFORCED_WARN_JS = Markup(
    "(function(){try{if(window.__mfCspProbe===true){"
    "var show=function(){"
    "if(!document.body||document.getElementById('mf-csp-degraded-banner'))return;"
    "var b=document.createElement('div');b.id='mf-csp-degraded-banner';"
    "b.className='mf-insecure-banner';b.setAttribute('role','alert');"
    "b.textContent='This browser does not enforce Content-Security-Policy: console hardening is "
    "degraded and script-injection defenses are not being applied. Use a current browser to reach "
    "this console.';"
    "document.body.insertBefore(b,document.body.firstChild);};"
    "if(document.body){show();}else{document.addEventListener('DOMContentLoaded',show);}"
    "}}catch(e){}})();"
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


def _logout_form() -> Markup:
    """The one-click Sign-out control: a tiny same-origin POST form (form-action 'self'), wired to the
    real server-side revocation. THE single markup site — :func:`_default_nav` and
    :func:`minimal_nav` both render this, so the affordance can never drift between the full chrome and
    the confinement chrome (ASVS 7.4.4)."""
    return el(
        "form",
        el("button", "Sign out", type="submit"),
        method="post",
        action="/ui/logout",
        class_="logout",
    )


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
    # Right cluster: the live status glyphs then Sign out, grouped so nav's space-between keeps the links
    # left and this block flush right (heart sits directly left of Sign out, alerts left of the heart).
    right = el("div", _nav_status_icons(), _logout_form(), class_="navright")
    # ``data-mf-session-watchdog`` (14.3.1) rides the <nav> element deliberately: a nav is rendered
    # ONLY on an authenticated page (the two unauthenticated entry pages pass nav=Markup("")), so the
    # hook is present exactly where a live session's rendered PHI needs discarding when that session
    # ends — with no per-render authentication plumbing to keep in sync. minimal_nav carries it too.
    return el(
        "nav",
        el("div", brand, *groups, class_="navlinks"),
        right,
        data_mf_session_watchdog=True,
    )


def minimal_nav() -> Markup:
    """The **confinement chrome**: the brand wordmark plus the one-click POST Sign-out form, and
    nothing else (ASVS 7.4.4).

    Authenticated pages that deliberately drop the full nav — step-up re-auth, the forced
    must-change-password page, passkey enrolment, the federated landing hop — used to render
    ``nav=Markup("")`` and therefore no logout affordance at all. The must-change page is the severe
    case: :func:`._auth.require_ui` 303s such a session back to it from every other ``/ui`` route, so a
    confined operator had **no reachable sign-out** even though ``POST /ui/logout`` would have accepted
    them (that route carries no ``Depends`` gate precisely so it can).

    It reuses the SAME logout form :func:`_default_nav` renders, so there is one markup site to change.
    It deliberately omits the nav groups (preserving each page's focus/confinement intent) **and**
    :func:`_nav_status_icons` — those glyphs carry the ``data-mf-nav-status`` hook that makes ``app.js``
    poll ``GET /ui/nav-status`` every ~15s, and that route needs ``monitoring:read``; on a
    reauth/must-change/passkey page the poll would 303-loop to the login or change-password page. The
    hook these pages DO keep is the session watchdog (14.3.1), which lives on the ``<nav>`` element
    itself — see :func:`_default_nav`.
    """
    brand = el("a", wordmark(tm=True), href="/ui", class_="brand")
    right = el("div", _logout_form(), class_="navright")
    return el("nav", el("div", brand, class_="navlinks"), right, data_mf_session_watchdog=True)


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
