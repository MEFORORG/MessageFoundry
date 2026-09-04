# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Connections-area page builders for the /ui ops dashboard (ADR 0065).

The dashboard + the pollable connections fragment + the per-connection start/stop/restart controls.
Every dynamic value is placed through the escaping element builders in :mod:`.._html`.
"""

from __future__ import annotations

import base64
import binascii
from datetime import UTC, datetime
from typing import Literal
from urllib.parse import quote

from messagefoundry.api.models import ConnectionEventInfo, ConnectionRow

from .._html import Markup, el, page, rows_table, text
from ._common import _num, _secs, _seg

__all__ = [
    "UNPROVISIONED_NOTICE",
    "bulk_control_result",
    "connection_details",
    "connections_fragment",
    "dashboard",
    "decode_row_key",
    "flag_rejected",
    "purge_confirm",
    "purge_pending",
    "purge_result",
    "unprovisioned_banner",
]


def _ts(value: float) -> str:
    """A connection-event timestamp as a UTC wall-clock string."""
    return datetime.fromtimestamp(value, UTC).strftime("%Y-%m-%d %H:%M:%SZ")


def _display_name(name: str) -> str:
    """Drop the redundant ' ▸ in'/' ▸ out' direction suffix the engine appends to a source/standalone-
    outbound display name (#1) — the Dir column already shows direction. A destination's 'channel ▸ dest'
    name has no such suffix and is left intact. The full name stays the row/detail identity."""
    for suffix in (" ▸ in", " ▸ out"):
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def _name_cell(r: ConnectionRow) -> Markup:
    """The Connection cell: the name (direction suffix stripped, #1) links to that connection's pre-filled
    message search (#4b), with a small 'details' link to its detail page (#4a). Both escaped by the
    builder; the details link keeps the FULL name so the route can look the row up."""
    return el(
        "span",
        el(
            "a",
            _display_name(r.name),
            href=f"/ui/messages?channel_id={quote(r.channel_id)}&defer=1",
        ),
        el(
            "a",
            "ⓘ",
            href=f"/ui/connection/{_seg(r.name)}",
            class_="detail-link",
            title="Connection details",
            aria_label=f"Details for {_display_name(r.name)}",
        ),
    )


def _b64url(value: str) -> str:
    """urlsafe-base64 (padded) of a UTF-8 string — an attribute/path-safe, ``|``-free encoding."""
    return base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii")


def _row_key(r: ConnectionRow) -> str:
    """A stable, server-minted checkbox identity for one dashboard row: ``role|b64url(channel_id)|
    b64url(destination or '')``. Minted from the row's own unique (role, channel_id, destination)
    triple, so it is identical on every render (survives the live poll swap) and round-trips names with
    spaces/unsafe characters. urlsafe-base64 never contains ``|``, so the delimiter can't collide. The
    presentation layer emits this as the checkbox ``value``; the bulk /ui endpoints decode it via
    :func:`decode_row_key`."""
    return f"{r.role}|{_b64url(r.channel_id)}|{_b64url(r.destination or '')}"


def decode_row_key(
    key: str,
) -> tuple[Literal["source", "destination"], str, str] | None:
    """Decode a :func:`_row_key` back to ``(role, channel_id, destination)`` — ``None`` for any
    malformed/forged value (wrong shape, unknown role, non-base64, non-UTF-8). ``destination`` is ``""``
    for a source row. Never raises — a caller renders ``None`` as a fixed 'unrecognized selection' label
    rather than reflecting attacker-controlled bytes."""
    parts = key.split("|")
    if len(parts) != 3:
        return None
    role, cid_b64, dest_b64 = parts
    role_lit: Literal["source", "destination"]
    if role == "source":
        role_lit = "source"
    elif role == "destination":
        role_lit = "destination"
    else:
        return None
    try:
        cid = base64.urlsafe_b64decode(cid_b64).decode("utf-8")
        dest = base64.urlsafe_b64decode(dest_b64).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    return role_lit, cid, dest


#: The bulk-action dropdown options: (option value the JS maps to an action, visible label). Start/
#: Stop/Restart/Reset apply to BOTH roles; Purge top/all apply to a stopped-and-quiesced OUTBOUND only
#: (the JS partitions the live selection and the engine is the final authority).
_TOOLBAR_ACTIONS: list[tuple[str, str]] = [
    ("start", "Start"),
    ("stop", "Stop"),
    ("restart", "Restart"),
    ("reset", "Reset stats"),
    ("purge-top", "Purge top"),
    ("purge-all", "Purge all"),
]


def _selection_checkbox(r: ConnectionRow) -> Markup:
    """One row's selection checkbox. ``value`` is the stable server-minted :func:`_row_key` (the identity
    the bulk /ui endpoints decode); the ``data-*`` carry the row's LIVE role/status/paused/destination so
    ``app.js`` can partition a mixed selection per the role/state matrix (UX-only — the engine is the
    authority). ``data-paused`` (paused AND quiesced) gates purge eligibility INDEPENDENT of the collapsed
    display ``status`` so a failed/filtered-but-paused outbound stays purgeable."""
    return el(
        "input",
        type="checkbox",
        class_="rowcb",
        data_mf_conns_cb=True,
        value=_row_key(r),
        data_role=r.role,
        data_status=r.status,
        data_paused=("1" if r.paused else "0"),
        data_dest=(r.destination or ""),
        # #131: the object-of-interest flag, read by the "Flagged only" client-side filter (app.js).
        data_flagged=("1" if r.flagged else "0"),
    )


def _status_cell(r: ConnectionRow) -> Markup:
    """The Status cell: the connection status pill, plus a small "waiting for reply" badge (#136, ADR
    0065 amendment) while an outbound is awaiting an MLLP ACK past its display delay. The badge is a
    DISPLAY-ONLY, transient state that clears on the next ~1s poll/ws swap once the reply resolves; it
    appears only on ACK-waiting outbounds (``waiting_for_reply`` is False otherwise)."""
    status = el("span", r.status, class_=f"status status-{r.status}")
    if r.waiting_for_reply:
        return el(
            "span",
            status,
            el("span", "⧖ waiting", class_="waiting", title="Waiting for reply (ACK)"),
        )
    return status


def _flag_name(r: ConnectionRow) -> tuple[str, str]:
    """The (connection name, direction) the flag write targets for a row: the inbound name for a source
    row, the outbound name for a destination row. Direction is what ``POST /connections/{name}/flag``
    disambiguates on."""
    if r.role == "source":
        return r.channel_id, "inbound"
    return (r.destination or ""), "outbound"


def _flag_cell(r: ConnectionRow) -> Markup:
    """The Flag cell (#131, ADR 0007 amendment): a same-origin POST toggle form on a
    ``connections.toml``-managed row (the write seam persists there), or a read-only indicator on a
    code-first row (no TOML home for the flag). The glyph is filled (⚑) when flagged, outline (⚐)
    otherwise; the button posts the DESIRED new value so a submit flips it (like the Alerts ack/resolve
    POST forms). Every value is placed through the escaping builder."""
    glyph = "⚑" if r.flagged else "⚐"
    if not r.toml_managed:
        # Code-first / draining: show the state but no toggle (it can't be persisted to connections.toml).
        return el(
            "span",
            glyph if r.flagged else "",
            class_="flag" + (" flagged" if r.flagged else ""),
            title="Flagged (code-first — edit the .py module to change)" if r.flagged else "",
        )
    name, direction = _flag_name(r)
    return el(
        "form",
        el("input", type="hidden", name="direction", value=direction),
        el("input", type="hidden", name="flagged", value=("false" if r.flagged else "true")),
        el(
            "button",
            glyph,
            type="submit",
            class_="flagbtn" + (" flagged" if r.flagged else ""),
            title=("Unflag " if r.flagged else "Flag ") + "this connection",
            aria_label=("Unflag " if r.flagged else "Flag ") + name,
        ),
        method="post",
        action=f"/ui/connections/{_seg(name)}/flag",
        class_="ctl flagform",
    )


def purge_pending(pending: object) -> Markup:
    """Shown when a queue purge is held for a second approver (dual-control, ADR 0014)."""
    approval_id = getattr(pending, "approval_id", "")
    body = el(
        "div",
        el("h1", "Purge held for approval"),
        el("p", "This queue purge is held for a second approver (dual-control).", class_="muted"),
        el("p", text(f"Approval id: {approval_id}"), class_="muted"),
        el("p", el("a", "← Connections", href="/ui")),
        class_="card",
    )
    return page("Pending approval", body, active="dashboard")


def connections_fragment(rows: list[ConnectionRow]) -> Markup:
    """Just the connections table — the poll target that app.js fetches from /ui/connections.

    A leading selection column replaces the old per-row control cell: a header select-all checkbox and a
    per-row checkbox whose ``value`` = :func:`_row_key`. These are the ONLY per-row controls now — the
    Start/Stop/Restart/Reset/Purge actions moved to the un-polled dashboard toolbar, driven over this
    selection by ``app.js`` (the checkboxes are wiped on each poll/ws swap and re-hydrated from a JS Set)."""
    headers: list[str] = [
        el("input", type="checkbox", data_mf_conns_all=True),
        "Flag",
        "Connection",
        "Dir",
        "Status",
        "In",
        "Out",
        "Queued",
        "Errors",
        "Alerts",
        "Idle",
    ]
    body = [
        [
            _selection_checkbox(r),
            _flag_cell(r),
            _name_cell(r),
            r.direction,
            _status_cell(r),
            _num(r.read),
            _num(r.written),
            _num(r.queue_depth),
            _num(r.errored),
            _num(r.alerts_active),
            _secs(r.idle_seconds),
        ]
        for r in rows
    ]
    return el("div", rows_table(headers, body), id="conns")


def _controls_toolbar() -> Markup:
    """The bulk-action toolbar: an action ``<select>`` + Apply button + a feedback ``<span>``.

    It lives in the un-polled dashboard shell (a sibling OUTSIDE the ``[data-poll]`` container), so the 5s
    poll / ~1s ``/ws/stats`` swaps that replace ``#conns`` NEVER wipe it and its ``app.js`` init runs once.
    ``app.js`` reads the chosen option + the live selection's ``data-*`` and dispatches: Start/Stop/Restart
    → POST ``/ui/connections/bulk-control``; Reset stats → POST ``/ui/statistics/reset-many``; Purge
    top/all → GET ``/ui/connections/purge-confirm`` (the step-up unlock flow)."""
    options = [el("option", label, value=value) for value, label in _TOOLBAR_ACTIONS]
    return el(
        "div",
        _filter_box(),  # filter first, then the bulk-action dropdown + Apply
        _flagged_only_toggle(),  # #131: a client-side Flagged-only view filter
        el("select", *options, data_mf_conns_action=True),
        el("button", "Go", type="button", data_mf_conns_apply=True),
        el(
            "span", data_mf_conns_feedback=True, class_="muted"
        ),  # dynamic feedback (empty when idle)
        data_mf_conns_toolbar=True,
        class_="ctlbar",
    )


def _filter_box() -> Markup:
    """A filter-as-you-type box over the connections table (client-side, ``app.js``). It lives OUTSIDE the
    ``[data-poll]`` container so its typed value survives the live swap; ``app.js`` hides rows whose text
    doesn't match and re-applies the filter after each poll/ws swap. Purely presentational — the server
    still sends every row, and a hidden row's checkbox value stays in the selection (filter is view-only)."""
    return el(
        "input",
        type="search",
        placeholder="Filter connections…",
        data_mf_conns_filter=True,
        class_="filterbox",
        autocomplete="off",
        aria_label="Filter connections",
    )


def _flagged_only_toggle() -> Markup:
    """The Flagged Objects filter (#131): a checkbox that hides every non-flagged row (client-side,
    ``app.js``). Lives OUTSIDE ``[data-poll]`` (like the filter box) so its state survives the live swap;
    ``app.js`` re-applies it after each poll/ws swap. Purely presentational — the server still sends every
    row, and a hidden row's checkbox stays in the selection Set."""
    return el(
        "label",
        el("input", type="checkbox", data_mf_conns_flagged=True),
        "Flagged only",
        class_="flagfilter",
        title="Show only flagged connections",
    )


#: Shown on the landing page to an operator whose per-channel scope is empty (BACKLOG #1152).
#: A fresh non-administrator is granted no channel, so every list on this console is legitimately
#: empty for them. Without this sentence that state is indistinguishable from a broken install, and
#: an operator who reads it as broken RBAC files a bug or -- worse -- gets handed a wider grant to
#: make the symptom go away. It says what happened, who fixes it, and nothing about the estate: it
#: must not name a connection the reader is not authorized to know exists.
UNPROVISIONED_NOTICE = (
    "Your account is not granted access to any connection yet, so these lists are empty. "
    "Ask an administrator to set your channel scope."
)


def unprovisioned_banner(unprovisioned: bool) -> Markup:
    """The :data:`UNPROVISIONED_NOTICE` alert, or nothing.

    ``role="alert"`` so it reaches a screen reader that never sees the empty table below it."""
    if not unprovisioned:
        return Markup("")
    return el("p", UNPROVISIONED_NOTICE, class_="banner", role="alert")


def dashboard(rows: list[ConnectionRow], *, unprovisioned: bool = False) -> Markup:
    """The connections dashboard page; the table auto-refreshes via the first-party poll script.

    ``unprovisioned`` raises :data:`UNPROVISIONED_NOTICE` above the table — the first-run affordance
    for an operator with an empty channel scope (BACKLOG #1152). It is DELIBERATELY a page banner
    and not a start-time refusal: refusing to start would make a fresh single-operator install
    unbootable for the same condition, which is a worse answer to the same question. It defaults
    False so every other caller renders byte-identically.

    ``data-poll`` names the same-origin fragment endpoint; ``app.js`` fetches it every ``data-poll-ms``
    and replaces this container's content with the server-rendered, already-escaped fragment. The
    ``#livestats`` strip is filled live by ``app.js`` over the ``/ws/stats`` WebSocket (M-ws); it
    degrades to empty (the polled table still updates) if the socket can't connect. The bulk-action
    ``[data-mf-conns-toolbar]`` and the ``[data-mf-conns-filter]`` box are siblings OUTSIDE ``[data-poll]``
    so a swap never wipes them.
    """
    live = el(
        "div",
        connections_fragment(rows),
        data_poll="/ui/connections",
        data_poll_ms="5000",
    )
    livestats = el("div", id="livestats", class_="livestats")
    return page(
        "Connections",
        # Header + the filter/bulk-action toolbar on one row.
        el("div", el("h1", "Connections"), _controls_toolbar(), class_="page-head"),
        # Outside [data-poll]: the 5s fragment swap replaces the table only, and this notice must
        # survive it — an operator who scrolls past the first refresh must still see why the page
        # is empty.
        unprovisioned_banner(unprovisioned),
        livestats,
        live,
        active="dashboard",
    )


def connection_details(row: ConnectionRow, events: list[ConnectionEventInfo]) -> Markup:
    """Read-only detail view for one connection (#4a): transport/status, live stats, and recent
    connection/transport events — all metadata (no PHI), composed from existing monitoring handlers."""
    peer = row.peer or "—"
    if row.port:
        peer = f"{peer}:{row.port}"
    info = rows_table(
        ["Field", "Value"],
        [
            ["Role", row.role],
            ["Direction", row.direction],
            ["Method", row.method],
            ["Peer", peer],
            ["Channel", row.channel_id],
            ["Status", el("span", row.status, class_=f"status status-{row.status}")],
        ],
        adjustable=False,
    )
    stats = rows_table(
        ["Metric", "Value"],
        [
            ["In", _num(row.read)],
            ["Out", _num(row.written)],
            ["Queued", _num(row.queue_depth)],
            ["Errors", _num(row.errored)],
            ["Alerts", _num(row.alerts_active)],
            ["Idle", _secs(row.idle_seconds)],
        ],
        adjustable=False,
    )
    if events:
        events_tbl: Markup = rows_table(
            ["When", "Kind", "Dir", "Peer", "Reason"],
            [[_ts(e.ts), e.kind, e.direction, e.peer_host or "—", e.reason or "—"] for e in events],
            adjustable=False,
        )
    else:
        events_tbl = el("p", "No recent events.", class_="muted")
    body = el(
        "div",
        el("h1", _display_name(row.name)),
        el(
            "p",
            el(
                "a",
                "View messages →",
                href=f"/ui/messages?channel_id={quote(row.channel_id)}&defer=1",
            ),
            class_="muted",
        ),
        el("h2", "Connection"),
        info,
        el("h2", "Statistics"),
        stats,
        el("h2", "Recent events"),
        events_tbl,
        el("p", el("a", "← Connections", href="/ui")),
        class_="card detail-card",
    )
    return page(f"{_display_name(row.name)} — details", body, active="dashboard")


# --- bulk-action result / confirm pages (connection controls) --------------------
#
# Every per-target label reaching these builders is placed through the escaping ``el``/``rows_table``
# helpers, so a decoded row key / ?dest that carries markup renders inert; an *undecodable* key never
# arrives as raw bytes — the endpoint replaces it with the fixed UNRECOGNIZED label below.

#: Fixed label rendered in place of a forged/undecodable selection (never the raw submitted bytes) —
#: an outcome whose target is ``None`` (the endpoint couldn't decode the row key / ?dest).
_UNRECOGNIZED_LABEL = "unrecognized selection"


def _outcomes_table(outcomes: list[tuple[str | None, str]]) -> Markup:
    """A two-column Target/Result table for a bulk-action outcome page — both cells escaped. A ``None``
    target (an undecodable/forged selection) renders the fixed 'unrecognized selection' label, never the
    raw submitted bytes."""
    return rows_table(
        ["Target", "Result"],
        [
            [_UNRECOGNIZED_LABEL if target is None else target, result]
            for target, result in outcomes
        ],
    )


def bulk_control_result(action: str, outcomes: list[tuple[str | None, str]]) -> Markup:
    """Per-target result of a bulk Start/Stop/Restart (both roles). ``action`` labels the batch; each
    outcome pairs a target name (``None`` → the fixed 'unrecognized selection' label) with what happened
    (applied/forbidden/unknown/error)."""
    body = el(
        "div",
        el("h1", f"Bulk {action}"),
        el("p", f"{len(outcomes)} target(s) processed.", class_="muted"),
        _outcomes_table(outcomes),
        el("p", el("a", "← Connections", href="/ui")),
        class_="card",
    )
    return page("Bulk control", body, active="dashboard")


def purge_result(scope: str, outcomes: list[tuple[str | None, str]]) -> Markup:
    """Per-destination result of a bulk queue purge (step-up + dual-control per dest). ``scope`` is the
    chosen 'top'/'all'; each outcome pairs a destination (``None`` → the fixed 'unrecognized selection'
    label) with its result (purged N / held for approval / skipped-running (409) / forbidden (403) /
    unknown (404))."""
    body = el(
        "div",
        el("h1", "Queue purge"),
        el("p", f"Scope: {scope}. {len(outcomes)} destination(s) processed.", class_="muted"),
        _outcomes_table(outcomes),
        el("p", el("a", "← Connections", href="/ui")),
        class_="card",
    )
    return page("Queue purge", body, active="dashboard")


def flag_rejected(name: str, detail: str) -> Markup:
    """Shown when a flag toggle is refused (#131) — most often the SCOPE FORK: the connection is
    code-first (no ``connections.toml`` home for the flag). Both ``name`` and ``detail`` are escaped."""
    body = el(
        "div",
        el("h1", "Flag not changed"),
        el("p", text(f"Connection: {name}"), class_="muted"),
        el("p", text(detail), class_="muted"),
        el(
            "p",
            "The object flag is settable only on a connections.toml-managed connection. A code-first "
            "connection has no TOML home for it — edit its .py module to change the flag.",
            class_="muted",
        ),
        el("p", el("a", "← Connections", href="/ui")),
        class_="card",
    )
    return page("Flag not changed", body, active="dashboard")


def purge_confirm(dests: list[str], scope: str) -> Markup:
    """Step-up-unlock confirm page for a bulk queue purge. Lists exactly the destinations the server
    re-derived as stopped-and-quiesced (purge-eligible) for ``scope`` and offers a same-origin POST form
    to ``/ui/connections/purge-bulk``. With nothing eligible (e.g. the selection was dropped across a
    step-up re-auth, or every target has since re-started), it renders NO form — the operator returns and
    re-selects (fail-safe: a destructive op is never pre-armed)."""
    if not dests:
        body = el(
            "div",
            el("h1", "Purge queued deliveries"),
            el(
                "p",
                "No stopped, quiesced outbound is selected. Stop an outbound and let it quiesce, "
                "then select it and choose Purge again.",
                class_="muted",
            ),
            el("p", el("a", "← Connections", href="/ui")),
            class_="card",
        )
        return page("Confirm purge", body, active="dashboard")
    fields: list[object] = [el("input", type="hidden", name="scope", value=scope)]
    fields.extend(el("input", type="hidden", name="dest", value=d) for d in dests)
    form = el(
        "form",
        *fields,
        el("button", f"Purge {scope}", type="submit"),
        method="post",
        action="/ui/connections/purge-bulk",
        class_="ctl",
    )
    body = el(
        "div",
        el("h1", "Purge queued deliveries"),
        el(
            "p",
            f"This soft-cancels the {scope} queued deliveries to the following stopped outbound(s). "
            "This cannot be undone.",
            class_="muted",
        ),
        el("ul", *[el("li", text(d)) for d in dests]),
        form,
        el("p", el("a", "← Cancel", href="/ui")),
        class_="card",
    )
    return page("Confirm purge", body, active="dashboard")
