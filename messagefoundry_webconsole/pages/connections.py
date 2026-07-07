# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Connections-area page builders for the /ui ops dashboard (ADR 0065).

The dashboard + the pollable connections fragment + the per-connection start/stop/restart controls.
Every dynamic value is placed through the escaping element builders in :mod:`.._html`.
"""

from __future__ import annotations

import base64
import binascii

from typing import Literal

from messagefoundry.api.models import ConnectionRow

from .._html import Markup, el, page, rows_table, text
from ._common import _num, _secs

__all__ = [
    "bulk_control_result",
    "connections_fragment",
    "dashboard",
    "decode_row_key",
    "purge_confirm",
    "purge_pending",
    "purge_result",
]


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
            r.name,
            r.direction,
            el("span", r.status, class_=f"status status-{r.status}"),
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
        el("select", *options, data_mf_conns_action=True),
        el("button", "Apply", type="button", data_mf_conns_apply=True),
        el("span", data_mf_conns_feedback=True, class_="muted"),
        data_mf_conns_toolbar=True,
        class_="ctlbar",
    )


def dashboard(rows: list[ConnectionRow]) -> Markup:
    """The connections dashboard page; the table auto-refreshes via the first-party poll script.

    ``data-poll`` names the same-origin fragment endpoint; ``app.js`` fetches it every ``data-poll-ms``
    and replaces this container's content with the server-rendered, already-escaped fragment. The
    ``#livestats`` strip is filled live by ``app.js`` over the ``/ws/stats`` WebSocket (M-ws); it
    degrades to empty (the polled table still updates) if the socket can't connect. The bulk-action
    ``[data-mf-conns-toolbar]`` is a sibling OUTSIDE ``[data-poll]`` so a swap never wipes it.
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
        el("h1", "Connections"),
        _controls_toolbar(),
        livestats,
        live,
        active="dashboard",
    )


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
