# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``pool.acquire(timeout=...)`` for the in-memory asyncpg stand-ins the cluster tests drive.

Since BACKLOG #2523 every statement ``DbCoordinator`` sends borrows a connection through a bounded
``pool.acquire`` and runs on that connection, rather than through the pool's own ``execute`` /
``fetchrow`` / ``fetch``. A stand-in that models statements on the pool itself mixes this in and lends
itself as the connection, so its statement methods are reached exactly as before. It records the
timeout each borrow carried, because that value is the bound the item exists to add.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import Any


@asynccontextmanager
async def _lent(con: Any) -> AsyncIterator[Any]:
    yield con


class LendsItself:
    """Mixin: ``acquire`` lends the stand-in itself and records the borrow's timeout."""

    last_acquire_timeout: float | None = None

    def acquire(self, *, timeout: float | None = None) -> AbstractAsyncContextManager[Any]:
        self.last_acquire_timeout = timeout
        return _lent(self)
