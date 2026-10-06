# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The Approvals page: the console's side of dual control (ASVS 2.3.5, BACKLOG #1982).

The reload, purge and replay pages could already HOLD an action for a second approver, and nothing
in the console could release one. This page lists the open requests and offers Approve and Reject on
each ``pending`` one, through the same engine handlers as ``POST /approvals/{id}/approve`` and
``/reject``, so the gate's own refusals (self-approval, too new, expired, requester no longer
authorized) stay the engine's to make.

**An ``interrupted`` row offers the resolve, never approve or reject** (BACKLOG #2460). Its release
was cut off while the operation ran, so the engine answers approve and reject with 409. The resolve
records whether its effects were applied, through the same handler as
``POST /approvals/{id}/resolve``, and its route asks for the same fresh step-up.

**The requester is offered neither Approve nor the resolve** (BACKLOG #2460). The engine marks each
row ``caller_is_requester`` by comparing user ids, the key its refusals use (BACKLOG #1540), so the
page never has to compare names, which are mutable. On a pending row the requester still gets
Withdraw, a reject the gate allows them; on an interrupted row, nothing. The engine refuses a
hand-built POST either way.

**Each row shows the parameters its hold captured** (BACKLOG #2458), so an approver sees what a
release would do. A ``None`` reads as the scope it means, such as all inbound connections.

**A pending row whose operation dual control no longer gates offers no Approve.** The engine marks
it ``gated`` False, from the same test its release refusal uses, so the page offers Reject and says
why, rather than a button the gate answers with 409.

Every value goes through the escaping ``el`` builder.
"""

from __future__ import annotations

import json

from messagefoundry.api.models import (
    ApprovalDecisionResult,
    ApprovalList,
    PendingApprovalInfo,
    ResolveOutcome,
)

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
    "control off nothing new is held. A request held before it was turned off for its operation "
    "can no longer be approved: reject it, or it stays here until it expires."
)

# The post-action notices, keyed by the redirect's ?m= code. An allow-list, so the query string can
# select a sentence but never supply one.
_NOTICES: dict[str, str] = {
    "rejected": "Request rejected. The held operation did not run.",
    "effects_applied": "Recorded: the interrupted release's effects were applied. Nothing was re-run.",
    "effects_not_applied": (
        "Recorded: the interrupted release's effects were not applied. Nothing was re-run."
    ),
    "choose_again": "Nothing was recorded. You proved it is you; choose the outcome again.",
}

# The resolve buttons, one per ResolveOutcome; a test pins that every outcome has one.
_RESOLVE_LABELS: dict[ResolveOutcome, str] = {
    "effects_applied": "Effects applied",
    "effects_not_applied": "Effects not applied",
}

_INTERRUPTED_NOTE = (
    "These releases were cut off while the operation ran, so it may have done none, some or all of "
    "its work. Nothing re-runs them. Check the operation's own effects, then record what you found. "
    "Recording is final, and it may ask you to prove it is you again first; if it does, you come "
    "back here and choose again. The requester cannot record their own."
)

_OWN_REQUEST = "Your request. A different approver decides it."

_UNREADABLE = "Unreadable; reject it."

# Mirrors the engine's approval.no_longer_gated refusal, so the advice is the same either way.
_NOT_GATED = (
    "Dual control no longer applies to this operation, so it cannot be approved. Reject it; if it "
    "is still needed, run it again, without a second approver."
)

# What a None parameter means for the operations that hold one: the broadest scope, not "nothing".
# Any other None reads "not set".
# Worded as "no filter" so it stays true beside a narrower key: a replay of one inbound with no
# destination is every destination of THAT inbound.
_NONE_MEANS: dict[str, str] = {
    "channel_id": "any inbound connection",
    "destination_name": "any destination",
    "config_dir": "the engine's startup config directory",
}

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

# The resolve's own guidance (BACKLOG #2460). Its refusals mean other things than a release's, and
# the approve wording would send an operator to request again an operation that may already have run.
_RESOLVE_REFUSALS: dict[int, tuple[str, str]] = {
    403: (
        "Not recorded",
        "The engine refused this operator. The requester can never record what their own "
        "interrupted release did; a different user holding approvals:approve must.",
    ),
    404: _REFUSALS[404],
    409: (
        "The release cannot be recorded now",
        "The engine's message below says why. At least: another operator recorded it first, it "
        "was never an interrupted release, or it cannot be recorded at all. Check the audit log "
        "before you request the operation again, because it may already have run.",
    ),
    503: (
        "Nothing was recorded",
        "The engine could not record this now, and its message below says why. The release is "
        "still interrupted; record it again once the cause is fixed.",
    ),
}


def _back() -> Markup:
    return el("p", el("a", "Back to Approvals", href=_PAGE))


def _when(value: float | None) -> str:
    return "—" if value is None else _ts(value)


def _param_value(key: str, value: object) -> str:
    if value is None:
        return _NONE_MEANS.get(key, "not set")
    return value if isinstance(value, str) else json.dumps(value)


def _params(a: PendingApprovalInfo) -> Markup:
    """What a release would re-run, one ``name: value`` line per captured parameter (BACKLOG
    #2458)."""
    if a.params is None:
        return el("span", "unreadable", class_="muted")
    # ``requester`` only carries the requester to the executor (BACKLOG #1646), so it is left out
    # while it repeats the Requester column, and shown if it ever differs from it.
    shown = sorted(k for k in a.params if k != "requester" or a.params[k] != a.requester)
    if not shown:
        return el("span", "none", class_="muted")
    return el("div", *(el("div", f"{key}: {_param_value(key, a.params[key])}") for key in shown))


def _pending_row(a: PendingApprovalInfo) -> list[object]:
    base = f"{_PAGE}/{_seg(a.id)}"
    # BACKLOG #2460: Approve is not offered where the gate would refuse it: to the requester, on a
    # row whose operation dual control no longer gates, and on a row whose params are unreadable.
    # Each such row gets the reject and a note saying why, in the order approve() refuses them.
    if a.caller_is_requester:
        note: str | None = _OWN_REQUEST
    elif not a.gated:
        note = _NOT_GATED
    elif a.params is None:
        note = _UNREADABLE
    else:
        note = None
    reject = _post_button(f"{base}/reject", "Withdraw" if a.caller_is_requester else "Reject")
    controls = (
        [_post_button(f"{base}/approve", "Approve"), reject]
        if note is None
        else [reject, el("span", note, class_="muted")]
    )
    actions = el("div", *controls, class_="ctls")
    return [
        _ts(a.requested_at),
        a.label,
        _params(a),
        a.requester,
        _when(a.expires_at),
        el("code", a.id),
        actions,
    ]


def _resolve_form(approval_id: str) -> Markup:
    """One form, one button per outcome (BACKLOG #2460). Each button posts to its own outcome path
    through ``formaction``. The required box means a click is a checked choice, not a slip
    between two adjacent final buttons; the browser enforces it, with no script. The form's own
    action is the page, which answers a POST with 405, so a submission with no button records no
    outcome."""
    base = f"{_PAGE}/{_seg(approval_id)}/resolve"
    buttons = [
        el("button", label, type="submit", formaction=f"{base}/{outcome}")
        for outcome, label in _RESOLVE_LABELS.items()
    ]
    return el(
        "form",
        el("label", el("input", type="checkbox", required=True), " I checked its effects"),
        *buttons,
        method="post",
        action=_PAGE,
        class_="ctl",
    )


def _interrupted_row(a: PendingApprovalInfo) -> list[object]:
    actions = (
        el("span", _OWN_REQUEST, class_="muted") if a.caller_is_requester else _resolve_form(a.id)
    )
    return [
        _ts(a.requested_at),
        a.label,
        _params(a),
        a.requester,
        a.approver or "—",
        _when(a.decided_at),
        el("code", a.id),
        actions,
    ]


def approvals_page(listing: ApprovalList, *, notice: str = "") -> Markup:
    """The open requests: ``pending`` ones with Approve and Reject, then ``interrupted`` ones with
    the resolve. The caller's own pending request offers only Withdraw, and their own interrupted
    one nothing. ``notice`` is a redirect's ``?m=`` code and selects from :data:`_NOTICES` only."""
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
                    "Record",
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


def approval_refused(status: int, detail: str, *, resolving: bool = False) -> Markup:
    """The page for an approvals action the engine refused: guidance keyed by status, then the
    engine's own message verbatim. ``resolving`` selects the resolve's own guidance."""
    table = _RESOLVE_REFUSALS if resolving else _REFUSALS
    headline, guidance = table.get(status, _UNKNOWN_REFUSAL)
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
