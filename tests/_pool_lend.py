# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``pool.acquire(timeout=...)`` and ``pool.release(con, timeout=...)`` for the in-memory asyncpg
stand-ins the cluster tests drive.

Since BACKLOG #2523 every statement ``DbCoordinator`` sends borrows a connection with a bounded
``await pool.acquire(timeout=...)``, runs on it, and hands it back with ``pool.release(con,
timeout=...)``, rather than going through the pool's own ``execute`` / ``fetchrow`` / ``fetch``. A
stand-in that models statements on the pool itself mixes this in and lends itself as the connection,
so its statement methods are reached exactly as before. It records the timeout each borrow carried,
because that value is a bound the item exists to add.

This lends; it does not model asyncpg's release wait. ``tests/test_cluster_bounded_waits.py`` holds
that model, and ``tests/test_cluster_stop_release.py`` a narrower one for ``stop()``'s writes.
"""

from __future__ import annotations

from typing import Any


class LendsItself:
    """Mixin: ``acquire`` lends the stand-in itself and records the borrow's timeout."""

    last_acquire_timeout: float | None = None
    # The statement's own bound: _call_within gives the release the same timeout as the statement.
    last_release_timeout: float | None = None

    async def acquire(self, *, timeout: float | None = None) -> Any:
        self.last_acquire_timeout = timeout
        return self

    async def release(self, con: Any, *, timeout: float | None = None) -> None:
        self.last_release_timeout = timeout
