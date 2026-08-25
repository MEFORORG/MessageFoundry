# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Offline uploaded-logs page builders (BACKLOG #125/#126, ADR 0134).

The Uploaded Logs page lets an operator import a partner-supplied `.hl7`/`.txt`/`.xml` file and browse
it as a filterable/searchable log, decoupled from any live connection, with per-message resend into a
chosen inbound and a guarded delete. Every dynamic value — including attacker-influenced HL7 content and
the operator-supplied filename — is placed through the escaping ``_html`` builders, so it can never
inject markup. No decrypted message body is ever rendered here (metadata only)."""

from __future__ import annotations

from messagefoundry.api.models import UploadedFileList, UploadedMessagesResult

from .._html import Markup, el, page, register_nav, rows_table, text

__all__ = [
    "uploaded_log_delete_confirm",
    "uploaded_log_detail",
    "uploaded_logs",
    "uploaded_logs_upload",
]


def _human_size(n: int) -> str:
    """A compact human-readable byte size (e.g. ``1.2 MiB``). Pure display."""
    size = float(max(n, 0))
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024 or unit == "TiB":
            return f"{int(size)} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} B"  # unreachable


#: What the listing is scoped to, keyed by ``UploadedFileList.scope`` (ASVS 8.2.2). The engine computes
#: that value once, at the route, from the caller's ``files:access_any`` grant; rendering a fixed
#: sentence per value is what keeps this page from telling an override holder — whose listing DOES carry
#: other operators' files — that it shows only their own. Re-deriving the grant here would put a second
#: copy of the rule in the console, which is how the sentence went stale in the first place.
_SCOPE_NOTES = {
    "own": (
        "This list shows the files you uploaded; reaching another operator's requires "
        "files:access_any."
    ),
    "any_owner": "You hold files:access_any, so this list shows every operator's uploaded files.",
}


def uploaded_logs(data: UploadedFileList, *, error: str = "") -> Markup:
    """The uploaded-files list: an upload link + a table of files (metadata only), each linking to the
    offline browse view and a guarded delete.

    ``error`` is the refused-mutation banner (a resend or delete that did NOT run). The route resolves
    it from an allow-list of fixed module text, so nothing caller-supplied reaches here — but it goes
    through ``text()`` like every other dynamic value regardless."""
    rows = [
        [
            el("a", f.filename, href=f"/ui/uploaded-logs/file/{f.file_id}"),
            f.uploader,
            f.content_type,
            _human_size(f.size),
            f.message_count,
            f.uploaded_at,
            el(
                "a",
                "Delete",
                href=f"/ui/uploaded-logs/file/{f.file_id}/delete-confirm",
                class_="btn-link",
            ),
        ]
        for f in data.files
    ]
    parts: list[object] = [
        el("h1", "Uploaded logs"),
        el(
            "p",
            "Import a partner-supplied message file and browse it offline — decoupled from any live "
            "connection. Uploaded files are PHI at rest; access is audited. "
            + _SCOPE_NOTES[data.scope],
            class_="muted",
        ),
    ]
    if error:
        parts.append(el("p", text(error), class_="banner"))
    parts.extend(
        [
            el("p", el("a", "Upload a file →", href="/ui/uploaded-logs/upload", class_="btn-link")),
            rows_table(
                ["File", "Uploaded by", "Format", "Size", "Messages", "When", ""],
                rows,
            ),
            el("p", text(f"{data.total} file(s)"), class_="pager"),
        ]
    )
    return page("Uploaded logs", *parts, active="uploaded-logs")


def uploaded_logs_upload(*, error: str = "") -> Markup:
    """The upload form (multipart/form-data — hand-parsed server-side, ADR 0134)."""
    parts: list[object] = [
        el("p", el("a", "← Uploaded logs", href="/ui/uploaded-logs")),
        el("h1", "Upload a log file"),
        el(
            "p",
            "Upload a .hl7 / .txt / .xml message file to inspect offline. It is stored encrypted at rest "
            "(when a store key is set) and never ingested into a live connection until you resend a "
            "message. Use synthetic / de-identified data where possible.",
            class_="muted",
        ),
    ]
    if error:
        parts.append(el("p", text(error), class_="banner"))
    parts.append(
        el(
            "form",
            el("input", type="file", name="file", required=True),
            # Consent affordance (ASVS 14.2.8): state, above the submit button, what non-body metadata is
            # retained and who sees it — submitting the form IS the consent (no separate stored flag).
            el(
                "p",
                "The original filename and your username are stored with this upload and shown to "
                "you and to authorized operators holding files:access_any (administrators), and "
                "recorded in the audit log. Submitting this form is your consent. Only plain-text "
                ".hl7 / .txt / .xml logs are accepted.",
                class_="muted",
            ),
            el("button", "Upload", type="submit", class_="primary"),
            method="post",
            action="/ui/uploaded-logs/upload",
            enctype="multipart/form-data",
            class_="ctl",
        )
    )
    return page("Upload a log file", *parts, active="uploaded-logs")


def _browse_filters(
    file_id: str,
    *,
    content: str,
    field_path: str,
    field_value: str,
    message_type: str,
    control_id: str,
) -> Markup:
    """A POST filter form over an uploaded file's split messages (metadata + optional content needle)."""
    return el(
        "form",
        el(
            "label",
            "Field path",
            el("input", name="field_path", value=field_path or None, placeholder="PID-3"),
        ),
        el("label", "Field value", el("input", name="field_value", value=field_value or None)),
        el("label", "Substring", el("input", name="content", value=content or None)),
        el("input", name="message_type", value=message_type or None, placeholder="type (optional)"),
        el(
            "input",
            name="control_id",
            value=control_id or None,
            placeholder="control id (optional)",
        ),
        el("button", "Filter", type="submit"),
        # POST for the same reason the content-search form is one (BACKLOG #1184, ASVS 14.2.1): the
        # field value and substring are PHI-shaped, and a GET form puts them on the URL.
        method="post",
        action=f"/ui/uploaded-logs/file/{file_id}/filter",
        class_="filters",
    )


def uploaded_log_detail(
    result: UploadedMessagesResult,
    *,
    content: str = "",
    field_path: str = "",
    field_value: str = "",
    message_type: str = "",
    control_id: str = "",
    error: str = "",
) -> Markup:
    """Browse one uploaded file's split messages (metadata only), with a per-file resend form (inject a
    message into a chosen inbound) and a link to the guarded delete."""
    file_id = result.file_id
    rows = [[m.index, m.message_type, m.control_id, _human_size(m.size)] for m in result.messages]
    note = f"{result.matched} of {result.total_messages} message(s)" + (
        " — result capped; narrow the filter" if result.truncated else ""
    )
    resend = el(
        "form",
        el(
            "label",
            "Message #",
            el("input", type="number", name="index", min="0", value="0", required=True),
        ),
        el(
            "label",
            "To inbound",
            el(
                "input",
                type="text",
                name="to",
                maxlength="256",
                placeholder="IB_PARTNER_ADT",
                required=True,
            ),
        ),
        el("button", "Resend into inbound", type="submit"),
        method="post",
        action=f"/ui/uploaded-logs/file/{file_id}/resend",
        class_="ctl",
    )
    parts: list[object] = [
        el("p", el("a", "← Uploaded logs", href="/ui/uploaded-logs")),
        el("h1", text(f"Browse: {result.filename}")),
        el(
            "p",
            "Metadata only — no decrypted body is shown. Resend injects the chosen message into a "
            "running inbound connection as a fresh receipt (audited).",
            class_="muted",
        ),
    ]
    if error:
        parts.append(el("p", text(error), class_="banner"))
    parts.extend(
        [
            _browse_filters(
                file_id,
                content=content,
                field_path=field_path,
                field_value=field_value,
                message_type=message_type,
                control_id=control_id,
            ),
            el("p", text(note), class_="pager"),
            rows_table(["#", "Type", "Control ID", "Size"], rows),
            el("h2", "Resend a message"),
            resend,
            el(
                "p",
                el(
                    "a",
                    "Delete this file",
                    href=f"/ui/uploaded-logs/file/{file_id}/delete-confirm",
                    class_="btn-link",
                ),
            ),
        ]
    )
    return page("Uploaded log", *parts, active="uploaded-logs")


def uploaded_log_delete_confirm(file_id: str, filename: str) -> Markup:
    """The delete confirm step (BACKLOG #126) — an explicit two-step so a stray click never destroys a
    file. The POST is step-up-gated + audited server-side."""
    return page(
        "Delete uploaded file",
        el("p", el("a", "← Uploaded logs", href="/ui/uploaded-logs")),
        el("h1", "Delete uploaded file?"),
        el(
            "p",
            text(
                f"This permanently deletes the uploaded file “{filename}”. This cannot be undone."
            ),
            class_="muted",
        ),
        el(
            "form",
            el("button", "Delete permanently", type="submit", class_="danger"),
            el("a", "Cancel", href=f"/ui/uploaded-logs/file/{file_id}", class_="btn-link"),
            method="post",
            action=f"/ui/uploaded-logs/file/{file_id}/delete",
            class_="ctl",
        ),
        active="uploaded-logs",
    )


register_nav("uploaded-logs", "/ui/uploaded-logs", "Uploaded logs")
