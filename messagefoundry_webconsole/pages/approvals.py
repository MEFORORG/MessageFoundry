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

**Each row shows the parameters its hold captured** (BACKLOG #2458), so an approver sees what a
release would do: which connection a replay or purge names, its scope, a reload's config directory.

Every value goes through the escaping ``el`` builder. Operation labels, captured parameters, user
names, ids and the engine's refusal text are dual-control metadata, never PHI.
"""

from __future__ import annotations

import json

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
    "requester cannot approve their own request, and may reject it to withdraw it. With dual "
    "control off nothing new is held, and requests held before it was turned off stay here until "
    "they expire."
)

# The post-action notices, keyed by the redirect's ?m= code. An allow-list, so the query string can
# select a sentence but never supply one.
_NOTICES: dict[str, str] = {
    "rejected": "Request rejected. The held operation did not run.",
}

_INTERRUPTED_NOTE = (
    "These releases were cut off while the operation ran, so it may have done none, some or all of "
    "its work. Nothing re-runs them. Check the operation's own effects, then record what you found "
    "through the engine API's resolve call for that row's id, which asks for a fresh step-up. This "
    "page does not offer that step."
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
        "The request is not in a state this action accepts, and the engine's message below says "
        "why. If it is too new, try again after the wait it names. If it was already decided, it "
        "was released or rejected, possibly by your own earlier click. Check the audit log before "
        "you request the operation again.",
    ),
    422: (
        "The released operation was refused",
        "The engine ran the release and the operation itself was refused, so it is recorded as "
        "failed. Request the operation again once the cause is fixed.",
    ),
    503: (
        "Dual control is not available",
        "The engine could not do this now. Its message below says why: at least no approval "
        "workflow bound to this engine, or an audit log that could not record a release. In the "
        "second case nothing ran and the request is still pending.",
    ),
}
_UNKNOWN_REFUSAL = ("Not done", "The engine refused this action.")


def _back() -> Markup:
    return el("p", el("a", "Back to Approvals", href=_PAGE))


def _when(value: float | None) -> str:
    return "—" if value is None else _ts(value)


def _param_value(value: object) -> str:
    if value is None:
        return "not set"
    return value if isinstance(value, str) else json.dumps(value)


def _params(a: PendingApprovalInfo) -> Markup:
    """What a release would re-run, one ``name: value`` line per captured parameter (BACKLOG
    #2458). These are operation metadata such as connection names, never a message body."""
    if a.params is None:
        return el("span", "unreadable", class_="muted")
    if not a.params:
        return el("span", "none", class_="muted")
    return el(
        "div",
        *(el("div", f"{key}: {_param_value(a.params[key])}") for key in sorted(a.params)),
    )


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
        _params(a),
        a.requester,
        _when(a.expires_at),
        el("code", a.id),
        actions,
    ]


def _interrupted_row(a: PendingApprovalInfo) -> list[object]:
    return [
        _ts(a.requested_at),
        a.label,
        _params(a),
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
                ["Requested", "Operation", "Parameters", "Requester", "Expires", "Id", "Actions"],
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
                [
                    "Requested",
                    "Operation",
                    "Parameters",
                    "Requester",
                    "Released by",
                    "Cut off",
                    "Id",
                ],
                [_interrupted_row(a) for a in interrupted],
            )
        )
    return page("Approvals", el("div", *parts, class_="card"), active="approvals")


def _shortfall(result: dict[str, object]) -> str | None:
    """The sentence for a release whose operation returned without doing all of its work, or None.

    Two shapes are known: a purge that skips (``skipped``, for example an outbound still running)
    and a reload that swapped the graph with a follow-on step failed (``degraded``). The request is
    closed either way, so the page says what to do rather than reporting a plain success."""
    skipped = result.get("skipped")
    if skipped:
        return (
            f"The operation skipped its work: {skipped}. Nothing was changed, and this request is "
            "closed. Clear the cause, then request the operation again."
        )
    if result.get("degraded"):
        return (
            f"The reload applied, and at least one follow-on step failed: {result.get('failures')}. "
            "The new graph is live; finish those steps by hand."
        )
    return None


def approval_approved(result: ApprovalDecisionResult) -> Markup:
    """The release outcome, including the operation's own summary (for example ``requeued`` or a
    purge's ``skipped`` reason), which a redirect would drop."""
    summary = result.result or {}
    shortfall = _shortfall(summary)
    facts: list[list[object]] = [
        ["Operation", result.operation],
        ["Requested by", result.requested_by],
        ["Approved by", result.approved_by or "—"],
    ]
    facts += [[str(key), str(value)] for key, value in sorted(summary.items())]
    body = el(
        "div",
        el("h1", "Request approved"),
        el("p", shortfall, class_="banner") if shortfall else Markup(""),
        el("p", "The held operation was released. Its own result is below.", class_="muted"),
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
