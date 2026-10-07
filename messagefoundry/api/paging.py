# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The total a numbered pager states, shared by the audit, security-event and event-log routes
(BACKLOG #2438).

Each of those listings grows at its head while a reader pages it: ``GET /audit`` even writes its
own permission-grant row before it reads. So each route pins its pages to a snapshot, a
``before_id`` one above the newest row its first page saw, and counts under the same pin. This
module holds the one rule those routes share about when the count can be skipped.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

__all__ = ["page_total"]


async def page_total(
    shown: int, *, limit: int, offset: int, count: Callable[[], Awaitable[int]]
) -> int:
    """The total for a page of ``shown`` rows read at ``offset`` with ``limit``.

    A page that came back short ended the set, so the total is ``offset + shown`` and no count
    query runs. That holds only when the page holds rows or starts at zero: an empty page past the
    end says nothing about where the end is, so it still counts. Otherwise ``count`` is awaited.
    The count is a full scan of the filtered set, so skipping it on the last page matters on a
    large trail."""
    if shown < limit and (shown or offset == 0):
        return offset + shown
    return await count()
