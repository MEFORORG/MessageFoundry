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

__all__ = ["IngressReceipt", "ReceiptHandler", "RefusalKind"]


class RefusalKind(StrEnum):
    """Why the runner refused a body it read, as the sender needs to know it."""

    #: Engine-side and expected to clear: the same body may be accepted on a re-send. Only the
    #: streaming detach's in-flight budget is classed here; ADR 0154's 2026-10-30 amendment says why
    #: the strict-validation timeout is not.
    TEMPORARY = "temporary"
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
