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
    "message_edit",
    "message_search",
    "messages",
    "parse_tree_page",
    "parse_tree_unavailable",
]


def _msg_filters(
    channel_id: str,
    status: str,
    message_type: str,
    control_id: str,
    received_from: str,
    received_to: str,
) -> Markup:
    """A GET filter form for the message log (reuses the /messages query params). ``received_from``/
    ``received_to`` are ``datetime-local`` values (UTC); submitting runs the search (no ``defer``)."""
    return el(
        "form",
        el("input", name="channel_id", value=channel_id or None, placeholder="channel"),
        el("input", name="status", value=status or None, placeholder="status"),
        el("input", name="message_type", value=message_type or None, placeholder="type"),
        el("input", name="control_id", value=control_id or None, placeholder="control id"),
        el(
            "label",
            "From",
            el("input", name="received_from", type="datetime-local", value=received_from or None),
            class_="dtfield",
        ),
        el(
            "label",
            "To",
            el("input", name="received_to", type="datetime-local", value=received_to or None),
            class_="dtfield",
        ),
        el("button", "Search", type="submit"),
        el("span", "(times UTC)", class_="muted"),
        # Content search (/ui/messages/search) is step-up-gated (bulk PHI decrypt) — a separate page.
        el("a", "Content search →", href="/ui/messages/search", class_="muted"),
        method="get",
        action="/ui/messages",
        class_="filters",
    )


def messages(
    data: MessageList | None,
    *,
    deferred: bool = False,
    channel_id: str = "",
    status: str = "",
    message_type: str = "",
    control_id: str = "",
    received_from: str = "",
    received_to: str = "",
) -> Markup:
    """The message log (list of summaries; each summary is view_summary-redacted server-side).

    ``deferred`` (or ``data is None``) renders the pre-filled filter form WITHOUT running a query — the
    "open a connection's messages, adjust, then Search" landing (#4b). Otherwise the results table + pager
    render as usual."""
    filters = _msg_filters(channel_id, status, message_type, control_id, received_from, received_to)
    if deferred or data is None:
        return page(
            "Messages",
            el("h1", "Messages"),
            filters,
            el("p", "Adjust the filters and click Search to run.", class_="muted"),
            active="messages",
        )
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
        filters,
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


def _human_size(n: int) -> str:
    """A compact human-readable byte size (e.g. ``1.2 MiB``) for the attachments panel. Binary units;
    integer bytes below 1 KiB. Pure display — never affects the download."""
    size = float(max(n, 0))
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024 or unit == "TiB":
            return f"{int(size)} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} B"  # unreachable; keeps mypy happy on the loop's implicit path


def message_detail(detail: MessageDetail) -> Markup:
    """A single message: metadata + the AUDITED raw body (escaped inside <pre>) + deliveries/events, plus
    an Attachments panel (#149, ADR 0105 Phase 3b) when very-large documents were detached at ingress."""
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
        adjustable=False,
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
    # Edit-and-resubmit (ADR 0090 §9, BACKLOG #153): a LINK (GET) to the editor page — the editable copy
    # opens there so the ORIGINAL shown here is never altered. GET, not a POST, so it is the step-up
    # `unlock` continuation the re-auth flow can hand back to (a body-carrying POST can't be auto-retried).
    edit = el(
        "a",
        "Edit & resubmit →",
        href=f"/ui/messages/{detail.id}/edit",
        class_="btn-link",
    )
    # Attachments panel (#149, ADR 0105 Phase 3b): shown only when a very-large document was detached
    # from this message. Metadata only (content type + human size); the bytes ride the audited,
    # view_raw-gated download link (a top-level GET carrying the session cookie — the /ui route reuses
    # the engine's audited download handler in-process). Rendered as a normal same-origin link.
    attachments_section: list[object] = []
    if detail.attachments:
        att_rows = [
            [
                a.content_type,
                _human_size(a.total_bytes),
                el(
                    "a",
                    "Download",
                    href=f"/ui/messages/{detail.id}/attachments/{a.id}",
                    class_="btn-link",
                ),
            ]
            for a in detail.attachments
        ]
        attachments_section = [
            el("h2", "Attachments"),
            el(
                "p",
                "Very-large documents detached from this message. Downloading a document is audited "
                "PHI access.",
                class_="muted",
            ),
            rows_table(["Content type", "Size", ""], att_rows),
        ]
    return page(
        "Message",
        el("p", el("a", "← Messages", href="/ui/messages")),
        el("div", el("h1", "Message detail"), replay, edit, class_="detail-head"),
        meta,
        el(
            "div",
            el("h2", "Raw message"),
            el("a", "Parse tree →", href=f"/ui/messages/{detail.id}/parse-tree", class_="muted"),
            class_="detail-head",
        ),
        raw,
        *attachments_section,
        el("h2", "Deliveries"),
        outbox,
        el("h2", "Events"),
        events,
        active="messages",
    )


def message_edit(
    detail: MessageDetail,
    idempotency_key: str,
    *,
    raw_value: str | None = None,
    error: str = "",
    mode: str = "reroute",
    to: str = "",
) -> Markup:
    """The edit-and-resubmit editor (ADR 0090 §9, BACKLOG #153): a COPY of the message's raw body opened
    in an editable ``<textarea>``, a "Modified" badge that app.js reveals as soon as the copy changes, a
    Revert button that restores the original copy, and a Resubmit button that POSTs the edited body. The
    ORIGINAL log entry is untouched — this is a copy — which the banner states explicitly. ``raw_value``
    (a rejected prior attempt echoed back) overrides the pristine copy so a validation error keeps the
    operator's edits; the ``data-original`` attribute always carries the PRISTINE copy for Revert.

    The edited body is attacker-influenced HL7 rendered as escaped ``<textarea>`` text (never markup);
    ``idempotency_key`` is a fresh per-open token so a double-submit of this form is an idempotent no-op.
    """
    original = detail.raw
    shown = original if raw_value is None else raw_value
    is_direct = mode == "direct"
    err = el("p", text(error), class_="banner") if error else Markup("")
    # data-original carries the PRISTINE copy for the client-side Revert; the badge/Revert/Resubmit
    # wiring lives in app.js (no inline script — the /ui CSP forbids it).
    editor = el(
        "textarea",
        text(shown),
        name="raw",
        id="edit-raw",
        class_="edit-raw",
        rows="18",
        spellcheck="false",
        data_original=original,
    )
    modified_badge = el(
        "span", "Modified", id="edit-modified", class_="badge-modified", hidden=True
    )
    # reroute (default) vs a direct alternate outbound. app.js shows/hides the `to` field on toggle;
    # server-side, an empty `to` means re-route (the endpoint's default). On a rejected retry the
    # selected mode + typed outbound are echoed back (via `mode`/`to`) so the operator's destination
    # choice survives alongside their edits — not silently reset to re-route (review #153-4).
    dest = el(
        "div",
        el(
            "label",
            el(
                "input",
                type="radio",
                name="mode",
                value="reroute",
                checked=not is_direct,
                class_="edit-mode",
            ),
            " Re-route on the original channel (re-parse + route normally)",
        ),
        el(
            "label",
            el(
                "input",
                type="radio",
                name="mode",
                value="direct",
                checked=is_direct,
                class_="edit-mode",
            ),
            " Send directly to an outbound connection",
        ),
        el(
            "div",
            el("label", "Outbound connection", for_="edit-to"),
            el(
                "input",
                type="text",
                name="to",
                id="edit-to",
                value=to,
                maxlength="256",
                autocomplete="off",
            ),
            id="edit-to-row",
            class_="edit-to-row",
            hidden=not is_direct,
        ),
        class_="edit-mode-row",
    )
    form = el(
        "form",
        el("input", type="hidden", name="idempotency_key", value=idempotency_key),
        dest,
        editor,
        el(
            "div",
            el("button", "Resubmit", type="submit", id="edit-resubmit", class_="primary"),
            el("button", "Revert", type="button", id="edit-revert", disabled=True),
            modified_badge,
            class_="ctls edit-ctls",
        ),
        method="post",
        action=f"/ui/messages/{detail.id}/edit-resend",
        class_="edit-form",
        id="edit-form",
        data_mf_edit=True,
    )
    return page(
        "Edit & resubmit",
        el("p", el("a", "← Message", href=f"/ui/messages/{detail.id}")),
        el("h1", "Edit & resubmit"),
        el(
            "p",
            "You are editing a COPY. The original message in the log stays unchanged; Resubmit"
            " creates a new, correlated message.",
            class_="muted",
        ),
        err,
        rows_table(
            ["Field", "Value"],
            [["Original ID", detail.id], ["Channel", detail.channel_id], ["Status", detail.status]],
            adjustable=False,
        ),
        form,
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
