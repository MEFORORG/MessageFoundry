# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The receipt contract between the runner and a source that declares ``wants_receipt``.

A source whose answer to the sender is its own protocol status, such as the HTTP listener's ``202``
or a DIMSE C-STORE status, is started with a RECEIPT handler instead of the generic
:data:`~messagefoundry.transports.base.InboundHandler`. The generic handler's ``str`` is a wire reply
and its ``None`` means both "committed" and "refused", which is right for MLLP and the file sources
and is left unchanged for them. A receipt source needs more: whether the body was committed, and when
it was not, why, so it can tell a sender to re-send later from one that must not re-send at all
(BACKLOG #2105, the ADR 0154 amendment of 2026-10-30).

Both outcomes carry a ``message_id``. An accepted body's is its committed ingress row. A refused
body's is the ``ERROR`` row the runner recorded for it before answering (count-and-log), so the
sender's refusal can be matched to its row by id rather than by time and peer.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import cast

__all__ = ["IngressReceipt", "ReceiptHandler", "RefusalKind", "receipt_handler", "require_receipt"]


class RefusalKind(StrEnum):
    """Why the runner refused a body it read, as the sender needs to know it."""

    #: Engine-side, not about the body: the same body may be accepted on a re-send once the cause
    #: clears on its own. At least two are classed here: the streaming detach's in-flight budget
    #: while other detaches hold it, and a strict-validation timeout that fired before any worker
    #: thread began the validate (BACKLOG #5078). A strict-validation timeout whose validate began
    #: is PERMANENT; ADR 0154's amendment of 2026-11-03 says why.
    TEMPORARY = "temporary"
    #: The inbound's own configuration refuses every non-empty body alike, whatever it holds, until
    #: an operator changes it, so the body is not at fault, yet no re-send clears it on its own
    #: (BACKLOG #5102). At least an inbound codec name that sets up no decode (BACKLOG #2431). An
    #: empty body is not this kind: Python decodes empty bytes without looking the codec up, so it
    #: passes the decode and meets what any empty body meets. A ``text`` inbound commits it and
    #: ``Http()`` answers ``202``; one whose later guards refuse an empty body, at least ``hl7v2``
    #: and ``json``, refuses it as PERMANENT. A
    #: refusal that depends on the body, such as a backend that cannot stream refusing only a body
    #: over the streaming threshold, is not this kind. Told apart from TEMPORARY so that a source
    #: whose protocol can say so, at least ``Http()``, does not invite a re-send soon for an
    #: operator-only fault, and from the final kinds so that the answer does not tell a sender to
    #: drop a body the engine takes once the fault is fixed. ADR 0154's amendment of 2026-11-04 says
    #: what each source answers.
    CONFIGURATION = "configuration"
    #: About the body itself: a re-send of the same bytes is refused the same way.
    PERMANENT = "permanent"
    #: Over a size ceiling. Permanent too, but told apart so every over-size path answers one code.
    OVERSIZE = "oversize"


@dataclass(frozen=True, slots=True)
class IngressReceipt:
    """What a receipt handler returns for one body.

    ``refusal`` is ``None`` when the body was committed to the ingress stage, and ``message_id`` is
    then that row's id. Otherwise ``message_id`` is the ``ERROR`` row's id and nothing reached the
    ingress stage. A receipt is never built as a refusal after ``enqueue_ingress`` committed, so an
    accepted object can never read as refused (BACKLOG #1910)."""

    message_id: str
    refusal: RefusalKind | None = None

    @classmethod
    def accepted(cls, message_id: str) -> IngressReceipt:
        return cls(message_id)

    @classmethod
    def refused(cls, kind: RefusalKind, message_id: str) -> IngressReceipt:
        return cls(message_id, kind)


#: The handler the runner starts a ``wants_receipt`` source with.
ReceiptHandler = Callable[[bytes], Awaitable[IngressReceipt]]

#: The attribute :func:`receipt_handler` sets, which :func:`require_receipt` reads.
_RECEIPT_MARK = "__messagefoundry_receipt_handler__"


def receipt_handler[H: Callable[[bytes], Awaitable[object]]](handler: H) -> H:
    """Mark ``handler`` as a receipt handler, so a ``wants_receipt`` source accepts it at start.

    A return annotation cannot be read reliably at run time, and the generic handler and the receipt
    handler are both ``bytes -> Awaitable``, so the declaration is this explicit mark."""
    setattr(handler, _RECEIPT_MARK, True)
    return handler


def require_receipt(handler: object, *, source: str) -> ReceiptHandler:
    """Return ``handler`` if :func:`receipt_handler` marked it, else raise ``TypeError``.

    A receipt source calls this in ``start()``, before it accepts anything. A generic handler would
    commit a body and return a reply or ``None``, and the source would then fail reading a receipt
    from it AFTER the commit: an HTTP ``500`` the sender re-sends, a duplicate, or a DIMSE failure
    for an object that was stored (BACKLOG #2105). Refusing at start keeps that from ever running."""
    if getattr(handler, _RECEIPT_MARK, False) is not True:
        raise TypeError(
            f"{source} declares wants_receipt and must be started with a receipt handler "
            "(transports.receipt.receipt_handler); it was given another handler"
        )
    return cast("ReceiptHandler", handler)  # the mark is the check the type system cannot make
