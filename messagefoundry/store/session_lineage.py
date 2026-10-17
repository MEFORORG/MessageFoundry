# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The session lineage: which token hash replaced a retired one (vault BACKLOG #3028, ADR 0210).

A rotation re-keys a session row to a new token hash, so the old hash stops naming any row. Each
backend's ``rotate_session`` now writes one ``session_lineage`` row in the same transaction: the
retired hash, the hash that replaced it, and when. This module holds the one walk over those rows
that every backend shares, so the three cannot disagree on how far it goes.

**A retired hash authenticates nothing.** No session read consults this table: ``get_session``,
``list_sessions`` and the service's session loader read ``sessions`` only. The one reader is the
revoke below, so the only thing a retired hash can lead to is the END of the session it became.

The rows are NOT sealed under BACKLOG #2592, deliberately. A seal stops a database writer forging
authority, and a link grants none: the most a forged link can do is direct a revoke at a live row,
and a revoke needs no key on any backend (it blanks the row's seal). A writer who can forge a link
can already revoke that row directly.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:  # store.py imports this module, so the record type is for the checker only
    from messagefoundry.store.store import SessionRecord

#: How many links one revoke follows before it gives up and ends nothing. A link is written only by
#: a completed elevation, and every link it follows is inside the caller's window, so a chain this
#: long means that many credential ceremonies on one session inside that window. Bounded so a
#: revoke's work is bounded whatever the table holds.
LINEAGE_MAX_HOPS: Final = 32

#: Revoke the unrevoked row that hash names and return it as revoked, or ``None`` when none did.
type Revoke = Callable[[str], Awaitable[SessionRecord | None]]
#: The hash that replaced this one, by a link retired at or after ``since``, or ``None``.
type Successor = Callable[[str, float], Awaitable[str | None]]


async def revoke_through_lineage(
    token_hash: str,
    *,
    lineage_since: float | None,
    revoke: Revoke,
    successor: Successor,
) -> SessionRecord | None:
    """Revoke the session ``token_hash`` names or, when it names none, the session it BECAME.

    Run it inside ONE store transaction, with ``revoke`` and ``successor`` bound to that
    transaction. Each step first tries to revoke the hash it holds; only when that revokes nothing
    does it read the hash's successor and step to it. So a rotation that commits between a
    ``successor`` read and the next ``revoke`` costs one more step rather than the revoke: the
    re-keyed row's old hash then has a link of its own, written in the rotation's transaction.
    **That order is the control on Postgres and SQL Server, not the transaction:** under READ
    COMMITTED a rotation can commit between two steps. Reading the whole chain first and revoking
    its end afterwards would aim the revoke at a hash such a rotation had already retired.

    ``lineage_since`` is the oldest ``retired_at`` a followed link may carry. ``None`` follows no
    link at all, which is the plain revoke of the hash given (BACKLOG #2146's behaviour).

    Returns the row it revoked, whose ``token_hash`` is the hash it ended under, or ``None`` when
    the walk reached a hash with no unrevoked row and no live link, or ran out of hops."""
    current = token_hash
    for hop in range(LINEAGE_MAX_HOPS + 1):
        ended = await revoke(current)
        if ended is not None or lineage_since is None or hop == LINEAGE_MAX_HOPS:
            return ended
        following = await successor(current, lineage_since)
        if following is None:
            return None
        current = following
    return None
