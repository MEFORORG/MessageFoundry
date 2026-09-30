# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The Approvals page: the console's side of dual control (ASVS 2.3.5, BACKLOG #1982).

The reload, purge and replay pages could already HOLD an action for a second approver, and nothing
in the console could release one. This page lists the open requests and offers Approve and Reject on
each ``pending`` one, through the same engine handlers as ``POST /approvals/{id}/approve`` and
``/reject``, so the gate's own refusals (self-approval, too new, expired, requester no longer
authorized) stay the engine's to make.

**An ``interrupted`` row gets no buttons.** Its release was cut off while the operation ran, so the
engine answers approve and reject with 409. Recording what it did is the resolve step, which asks for
a fresh step-up and is not built here; the page says where to do it instead.

**No button is hidden from the requester.** The list carries the requester's NAME, and a name is not
the key the self-approval refusal uses (BACKLOG #1540: names are mutable, user ids are not). Hiding
the button by name would be wrong in both directions, so the engine refuses and this page shows why.

Every value goes through the escaping ``el`` builder. Operation labels, user names, ids and the
engine's refusal text are dual-control metadata, never PHI.
"""

from __future__ import annotations

from messagefoundry.api.models import ApprovalDecisionResult, ApprovalList, PendingApprovalInfo

from .._html import Markup, el, page, register_nav, rows_table
from ._common import _seg
from .monitoring import _post_button, _ts

__all__ = [
    "approval_approved",
    "approval_refused",
    "approvals_link",
    "approvals_page",
]

_PAGE = "/ui/approvals"

_INTRO = (
    "Actions held for a second approver (dual control). A different user holding approvals:approve "
    "releases or rejects each one. Approving runs the held operation now, as it was requested. The "
    "requester cannot approve their own request, and may reject it to withdraw it."
)

# The post-action notices, keyed by the redirect's ?m= code. An allow-list, so the query string can
# select a sentence but never supply one.
_NOTICES: dict[str, str] = {
    "rejected": "Request rejected. The held operation did not run.",
}

_INTERRUPTED_NOTE = (
    "These releases were cut off while the operation ran, so it may have done none, some or all of "
    "its work. Nothing re-runs them. Check the operation's own effects, then record what you found "
    "with POST /approvals/{id}/resolve on the engine API, which asks for a fresh step-up. This page "
    "does not offer that step."
)

# Guidance for a refusal, keyed by the status the engine raised. The engine's own message follows it
# verbatim, because one status covers several causes (a 409 is at least already decided, expired,
# too new, interrupted or a requester who lost the authority).
_REFUSALS: dict[int, tuple[str, str]] = {
    403: (
        "Not released",
        "The engine refused this approver. A requester can never approve their own request; a "
        "different user holding approvals:approve must release it.",
    ),
    404: ("No such request", "No approval request has this id."),
    409: (
        "The request cannot be decided now",
        "The request is no longer in a state this action accepts. The engine's message below says "
        "which. A request that is too new can be approved again after the wait it names.",
    ),
    422: (
        "The released operation was refused",
        "The engine ran the release and the operation itself was refused, so it is recorded as "
        "failed. Request the operation again once the cause is fixed.",
    ),
    503: (
        "Dual control is not available",
        "Either this engine has no approval workflow bound, or the audit log could not record the "
        "release, in which case nothing ran and the request is still pending.",
    ),
}
_UNKNOWN_REFUSAL = ("Not done", "The engine refused this action.")


def _back() -> Markup:
    return el("p", el("a", "Back to Approvals", href=_PAGE))


def _when(value: float | None) -> str:
    return "—" if value is None else _ts(value)


def _pending_row(a: PendingApprovalInfo) -> list[object]:
    base = f"{_PAGE}/{_seg(a.id)}"
    actions = el(
        "div",
        _post_button(f"{base}/approve", "Approve"),
        _post_button(f"{base}/reject", "Reject"),
        class_="ctls",
    )
    return [
        _ts(a.requested_at),
        a.label,
        a.requester,
        _when(a.expires_at),
        el("code", a.id),
        actions,
    ]


def _interrupted_row(a: PendingApprovalInfo) -> list[object]:
    return [
        _ts(a.requested_at),
        a.label,
        a.requester,
        a.approver or "—",
        _when(a.decided_at),
        el("code", a.id),
    ]


def approvals_page(listing: ApprovalList, *, notice: str = "") -> Markup:
    """The open requests: ``pending`` ones with Approve and Reject, then ``interrupted`` ones
    read-only. ``notice`` is a redirect's ``?m=`` code and selects from :data:`_NOTICES` only."""
    pending = [a for a in listing.approvals if a.status == "pending"]
    interrupted = [a for a in listing.approvals if a.status == "interrupted"]
    parts: list[object] = [el("h1", "Approvals"), el("p", _INTRO, class_="muted")]
    message = _NOTICES.get(notice)
    if message is not None:
        parts.append(el("p", message, class_="banner"))
    parts.append(el("h2", "Waiting for a second approver"))
    if pending:
        parts.append(
            rows_table(
                ["Requested", "Operation", "Requester", "Expires", "Id", "Actions"],
                [_pending_row(a) for a in pending],
            )
        )
    else:
        parts.append(el("p", "No request is waiting for a second approver.", class_="muted"))
    if interrupted:
        parts.append(el("h2", "Interrupted releases"))
        parts.append(el("p", _INTERRUPTED_NOTE, class_="muted"))
        parts.append(
            rows_table(
                ["Requested", "Operation", "Requester", "Released by", "Cut off", "Id"],
                [_interrupted_row(a) for a in interrupted],
            )
        )
    return page("Approvals", el("div", *parts, class_="card"), active="approvals")


def approval_approved(result: ApprovalDecisionResult) -> Markup:
    """The release outcome, including the operation's own summary (for example ``requeued`` or a
    purge's ``skipped`` reason), which a redirect would drop."""
    facts: list[list[object]] = [
        ["Operation", result.operation],
        ["Requested by", result.requested_by],
        ["Approved by", result.approved_by or "—"],
    ]
    facts += [[str(key), str(value)] for key, value in sorted((result.result or {}).items())]
    body = el(
        "div",
        el("h1", "Request approved"),
        el("p", "The held operation ran. Its result is below.", class_="muted"),
        rows_table(["", ""], facts, adjustable=False),
        _back(),
        class_="card",
    )
    return page("Request approved", body, active="approvals")


def approval_refused(status: int, detail: str) -> Markup:
    """The page for an approvals action the engine refused: guidance keyed by status, then the
    engine's own message verbatim."""
    headline, guidance = _REFUSALS.get(status, _UNKNOWN_REFUSAL)
    body = el(
        "div",
        el("h1", headline),
        el("p", guidance),
        el("h2", f"Engine message (status {status})"),
        el("p", detail),
        _back(),
        class_="card detail-card",
    )
    return page(headline, body, active="approvals")


def approvals_link() -> Markup:
    """The sentence a held-for-approval page ends with, pointing at where the hold is released."""
    return el(
        "p",
        "A different user holding approvals:approve releases or rejects it on the ",
        el("a", "Approvals", href=_PAGE),
        " page.",
        class_="muted",
    )


# Nav registration, co-located with the builders (ADR 0065 §multi-session-build). ``_html._NAV_GROUPS``
# places the key under Admin. The nav is not filtered by permission, like Users and Configuration: the
# route itself refuses an operator without approvals:approve.
register_nav("approvals", _PAGE, "Approvals")
