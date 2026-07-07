# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Messages-area page builders for the /ui ops dashboard (ADR 0065).

The message log + single-message detail (with the AUDITED raw body), the HL7 parse tree, and the
dead-letter list + bulk replay. Every dynamic value — including attacker-influenced HL7/message
content — is placed through the escaping element builders in :mod:`.._html`, so it can never inject
markup.
"""

from __future__ import annotations

from messagefoundry.api.models import (
    DeadLetterList,
    MessageDetail,
    MessageList,
    MessageSearchResults,
)
from messagefoundry.parsing.tree import TreeNode

from .._html import Markup, el, page, rows_table, text

__all__ = [
    "dead_letter_pending",
    "dead_letters",
    "message_detail",
    "message_search",
    "messages",
    "parse_tree_page",
    "parse_tree_unavailable",
]


def _msg_filters(channel_id: str, status: str, message_type: str, control_id: str) -> Markup:
    """A GET filter form for the message log (reuses the /messages query params)."""
    return el(
        "form",
        el("input", name="channel_id", value=channel_id or None, placeholder="channel"),
        el("input", name="status", value=status or None, placeholder="status"),
        el("input", name="message_type", value=message_type or None, placeholder="type"),
        el("input", name="control_id", value=control_id or None, placeholder="control id"),
        el("button", "Filter", type="submit"),
        # Content search (/ui/messages/search) is step-up-gated (bulk PHI decrypt) — a separate page.
        el("a", "Content search →", href="/ui/messages/search", class_="muted"),
        method="get",
        action="/ui/messages",
        class_="filters",
    )


def messages(
    data: MessageList,
    *,
    channel_id: str = "",
    status: str = "",
    message_type: str = "",
    control_id: str = "",
) -> Markup:
    """The message log (list of summaries; each summary is view_summary-redacted server-side)."""
    headers = ["Received", "Channel", "Type", "Status", "Control ID", "Summary"]
    body = [
        [
            m.received_at,
            m.channel_id,
            m.message_type,
            el("span", m.status, class_=f"status status-{m.status}"),
            m.control_id,
            # A link to the audited detail view; the summary text is escaped by the builder.
            el("a", m.summary or "(view)", href=f"/ui/messages/{m.id}"),
        ]
        for m in data.messages
    ]
    pager = el(
        "p",
        text(f"{len(data.messages)} of {data.total} (offset {data.offset})"),
        class_="pager",
    )
    return page(
        "Messages",
        el("h1", "Messages"),
        _msg_filters(channel_id, status, message_type, control_id),
        rows_table(headers, body),
        pager,
        active="messages",
    )


def message_search(
    results: MessageSearchResults | None,
    *,
    content: str = "",
    field_path: str = "",
    field_value: str = "",
    target: str = "both",
    channel_id: str = "",
    status: str = "",
    message_type: str = "",
    control_id: str = "",
    error: str = "",
) -> Markup:
    """The content-search page (a step-up-unlock GET, ADR 0046 #51): search by an HL7 field path
    (``PID-3``) or a raw/summary substring, over the caller's channels. ``results is None`` = the bare
    form (no search yet). Every matched row is a metadata-only summary (server-redacted) linking to the
    audited detail view — no decrypted body is ever rendered here."""
    target_options = [
        el("option", label, value=value, selected=value == target or None)
        for value, label in (
            ("both", "raw + summary"),
            ("raw", "raw only"),
            ("summary", "summary only"),
        )
    ]
    form = el(
        "form",
        el(
            "p",
            "Search decrypts message bodies — a bulk-PHI operation, audited and step-up gated. "
            "Provide a field path + value (e.g. PID-3 / 100), or a substring.",
            class_="muted",
        ),
        el(
            "label",
            "Field path",
            el("input", name="field_path", value=field_path or None, placeholder="PID-3"),
        ),
        el("label", "Field value", el("input", name="field_value", value=field_value or None)),
        el("label", "Substring", el("input", name="content", value=content or None)),
        el("label", "Target", el("select", *target_options, name="target")),
        el("input", name="channel_id", value=channel_id or None, placeholder="channel (optional)"),
        el("input", name="status", value=status or None, placeholder="status (optional)"),
        el("input", name="message_type", value=message_type or None, placeholder="type (optional)"),
        el(
            "input",
            name="control_id",
            value=control_id or None,
            placeholder="control id (optional)",
        ),
        el("button", "Search", type="submit"),
        method="get",
        action="/ui/messages/search",
        class_="filters",
    )
    parts: list[object] = [
        el("h1", "Content search"),
        el("p", el("a", "← Messages", href="/ui/messages")),
        form,
    ]
    if error:
        parts.append(el("p", error, class_="banner"))
    if results is not None:
        rows = [
            [
                m.received_at,
                m.channel_id,
                m.message_type,
                el("span", m.status, class_=f"status status-{m.status}"),
                m.control_id,
                el("a", m.summary or "(view)", href=f"/ui/messages/{m.id}"),
            ]
            for m in results.messages
        ]
        note = f"{results.matched} match(es) after decrypting {results.scanned} candidate(s)" + (
            f" — scan hit the {results.scan_limit} ceiling; narrow the filters"
            if results.truncated
            else ""
        )
        parts.append(el("p", text(note), class_="pager"))
        parts.append(
            rows_table(["Received", "Channel", "Type", "Status", "Control ID", "Summary"], rows)
        )
    return page("Content search", *parts, active="messages")


def message_detail(detail: MessageDetail) -> Markup:
    """A single message: metadata + the AUDITED raw body (escaped inside <pre>) + deliveries/events."""
    meta = rows_table(
        ["Field", "Value"],
        [
            ["ID", detail.id],
            ["Channel", detail.channel_id],
            ["Received", detail.received_at],
            ["Type", detail.message_type],
            ["Control ID", detail.control_id],
            ["Status", detail.status],
            ["Summary", detail.summary],
            ["Error", detail.error],
        ],
    )
    # The raw body is attacker-influenced HL7 — rendered as escaped text inside <pre>, never as markup.
    raw = el("pre", detail.raw, class_="raw")
    outbox = rows_table(
        ["Destination", "Status", "Attempts", "Last error"],
        [[o.destination_name, o.status, o.attempts, o.last_error] for o in detail.outbox],
    )
    events = rows_table(
        ["When", "Event", "Destination", "Detail"],
        [[e.ts, e.event, e.destination, e.detail] for e in detail.events],
    )
    replay = el(
        "form",
        el("button", "Replay", type="submit"),
        method="post",
        action=f"/ui/messages/{detail.id}/replay",
        class_="ctl",
    )
    return page(
        "Message",
        el("p", el("a", "← Messages", href="/ui/messages")),
        el("div", el("h1", "Message detail"), replay, class_="detail-head"),
        meta,
        el(
            "div",
            el("h2", "Raw message"),
            el("a", "Parse tree →", href=f"/ui/messages/{detail.id}/parse-tree", class_="muted"),
            class_="detail-head",
        ),
        raw,
        el("h2", "Deliveries"),
        outbox,
        el("h2", "Events"),
        events,
        active="messages",
    )


def _tree_nodes(nodes: list[TreeNode]) -> Markup:
    """Render HL7 parse-tree nodes as a nested list. Every label/value is escaped by ``el`` — the field
    values are attacker-influenced HL7, so they can never inject markup."""
    items: list[object] = []
    for node in nodes:
        label = el("span", node.label, class_="tlabel")
        value = el("span", node.value, class_="tval") if node.value else Markup("")
        children = _tree_nodes(node.children) if node.children else Markup("")
        items.append(el("li", label, " ", value, children))
    return el("ul", *items, class_="tree")


def parse_tree_page(message_id: str, nodes: list[TreeNode]) -> Markup:
    """The HL7 parse tree for one message (server-parsed via the pure ``parsing`` lib; escaped)."""
    return page(
        "Parse tree",
        el("p", el("a", "← Message", href=f"/ui/messages/{message_id}")),
        el("h1", "HL7 parse tree"),
        _tree_nodes(nodes),
        active="messages",
    )


def parse_tree_unavailable(message_id: str, reason: str) -> Markup:
    """Shown when the raw body has no HL7 parse tree (non-HL7 content, or no parseable MSH)."""
    return page(
        "Parse tree",
        el("p", el("a", "← Message", href=f"/ui/messages/{message_id}")),
        el("h1", "HL7 parse tree"),
        el("p", text(f"No HL7 parse tree for this message: {reason}"), class_="muted"),
        active="messages",
    )


def dead_letters(data: DeadLetterList) -> Markup:
    """The dead-letter list (newest first) + per-channel bulk replay (M3).

    Each row links to the audited message detail (single-message replay lives there, M2b). The bulk
    "Replay all dead" per channel re-queues every dead delivery for that channel (step-up-gated; may be
    held for dual-control approval). Channel names are the ``[TYPE]_[PARTNER]_[MSG]`` URL-safe
    identifiers, carried in the action PATH so the step-up auto-retry re-POST needs no body.
    """
    headers = ["Failed", "Channel", "Destination", "Type", "Attempts", "Last error", "Message"]
    body = [
        [
            d.failed_at,
            d.channel_id,
            d.destination_name,
            d.message_type,
            d.attempts,
            d.last_error,
            el("a", "view", href=f"/ui/messages/{d.message_id}"),
        ]
        for d in data.dead_letters
    ]
    pager = el(
        "p",
        text(f"{len(data.dead_letters)} of {data.total} (offset {data.offset})"),
        class_="pager",
    )
    channels = sorted({d.channel_id for d in data.dead_letters})
    pairs = sorted(
        {(d.channel_id, d.destination_name) for d in data.dead_letters if d.destination_name}
    )
    chan_forms = [
        el(
            "form",
            el("button", f"Replay all dead — {ch}", type="submit"),
            method="post",
            action=f"/ui/dead-letters/{ch}/replay",
            class_="ctl",
        )
        for ch in channels
    ]
    dest_forms = [
        el(
            "form",
            el("button", f"Replay {ch} → {dest}", type="submit"),
            method="post",
            action=f"/ui/dead-letters/{ch}/{dest}/replay",
            class_="ctl",
        )
        for ch, dest in pairs
    ]
    actions: list[object] = []
    if channels:
        # L6b (#75 parity): one action to replay every dead delivery across ALL channels.
        actions += [
            el("h2", "Bulk replay — everything"),
            el(
                "div",
                el(
                    "form",
                    el("button", "Replay all dead (every channel)", type="submit"),
                    method="post",
                    action="/ui/dead-letters/replay-all",
                    class_="ctl",
                ),
                class_="ctls",
            ),
        ]
    if chan_forms:
        actions += [el("h2", "Bulk replay — per channel"), el("div", *chan_forms, class_="ctls")]
    if dest_forms:
        actions += [
            el("h2", "Bulk replay — per destination"),
            el("div", *dest_forms, class_="ctls"),
        ]
    return page(
        "Dead letters",
        el("h1", "Dead letters"),
        rows_table(headers, body),
        pager,
        *actions,
        active="dead-letters",
    )


def dead_letter_pending(pending: object) -> Markup:
    """Shown when a bulk dead-letter replay is held for a second approver (dual-control, ADR 0014)."""
    approval_id = getattr(pending, "approval_id", "")
    body = el(
        "div",
        el("h1", "Replay held for approval"),
        el(
            "p",
            "This dead-letter replay is held for a second approver (dual-control).",
            class_="muted",
        ),
        el("p", text(f"Approval id: {approval_id}"), class_="muted"),
        el("p", el("a", "← Dead letters", href="/ui/dead-letters")),
        class_="card",
    )
    return page("Pending approval", body, active="dead-letters")
