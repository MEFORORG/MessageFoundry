# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The snapshot pin and the total a numbered pager states, shared by the audit, security-event and
event-log routes (BACKLOG #2438).

Each of those listings grows at its head while a reader pages it: ``GET /audit`` even writes its
own permission-grant row before it reads. So each route pins its pages to a snapshot taken on the
first page, and counts under the same pin.

**The audit trail and the security-event feed pin on a timestamp, never on a row id.** Their rows
carry no id on the wire, and an id would be an oracle: ``audit_log`` ids are global, so the gap
between two visible ids counts the rows a reader may not see, such as the lock rows BACKLOG #1131
hides. A timestamp pin is an ``until`` bound the reader could already send, and every row's ``ts``
is already on the page, so it tells the reader nothing new. The event log pins on its row id
instead: its rows already carry their ids, and its order is by ``ts``, which a burst flush can
write out of order.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from typing import Any

__all__ = ["page_total", "ts_pinned_page"]


async def page_total(
    shown: int, *, limit: int, offset: int, count: Callable[[], Awaitable[int]]
) -> int:
    """The total for a page of ``shown`` rows read at ``offset`` with ``limit``.

    A page that came back short ended the set, so the total is ``offset + shown`` and no count
    query runs. That holds only when the page holds rows or starts at zero: an empty page past the
    end says nothing about where the end is, so it still counts. Otherwise ``count`` is awaited.
    The count is a full scan of the filtered set, so skipping it on the last page matters on a
    large trail.

    A counted total is floored at ``offset + shown`` when the page holds rows. The count is a
    second read, and a retention purge between the two can shrink it below the rows this page
    plainly returned; a client that stops at ``offset + len(rows) >= total`` would then stop
    early."""
    if shown < limit and (shown or offset == 0):
        return offset + shown
    counted = await count()
    return max(counted, offset + shown) if shown else counted


async def ts_pinned_page[Row](
    as_of: float | None,
    *,
    limit: int,
    offset: int,
    read: Callable[[int, int, float | None], Awaitable[Sequence[Row]]],
    count: Callable[[float | None], Awaitable[int]],
    ts_of: Callable[[Row], Any],
) -> tuple[list[Row], int, float | None]:
    """One page of a newest-first listing pinned to rows at or before ``as_of``, its total under
    the same pin, and the pin to hand back.

    ``read(limit, offset, as_of)`` reads the page, newest first, keeping rows whose ``ts`` is at
    most ``as_of`` when it is not None. ``count(as_of)`` counts the same set. A caller that names
    no pin gets the newest ``ts`` at the head of the listing. At offset 0 the page itself is that
    head, so the first page costs no extra read. The pin is None only when the listing was
    empty."""
    if as_of is None:
        head = list(await read(limit if offset == 0 else 1, 0, None))
        # The newest ``ts`` on the head, not the first row's: the order is by id, and a wall
        # clock stepped back can give a later row an earlier ``ts`` than one before it.
        as_of = max(float(ts_of(r)) for r in head) if head else None
        rows = head if offset == 0 else list(await read(limit, offset, as_of))
    else:
        rows = list(await read(limit, offset, as_of))
    pin = as_of
    total = await page_total(len(rows), limit=limit, offset=offset, count=lambda: count(pin))
    return rows, total, as_of
