# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1640: the M-5 summary-access coalescer must be flushed at lifespan shutdown.

``_SummaryAuditCoalescer`` writes ONE ``summary_access`` audit row per (actor, scope, hour) window,
so routine console polling does not produce a row per request while a bulk harvest shows a large
count. A window is emitted when a LATER access rolls it into a new hour -- which means the window
open at shutdown is emitted by nothing.

``flush`` existed and documented itself as the engine-shutdown path. Nothing called it. So a clean
restart dropped the open hour's PHI-summary access audit entirely, and the case where that matters
most is the one the control exists for: an operator restarting shortly after a bulk census fetch.

WHY THE ORDER IS LOAD-BEARING. The flush runs BEFORE ``engine.stop()``, because that ends in
``store.close()`` and the emit needs the store. It is also wrapped, on the reaper's precedent: a
store error during teardown must not skip ``engine.stop()``, or aiosqlite's non-daemon worker keeps
the process alive and a lost audit row becomes a hung service.

``test_the_assertion_can_fail`` is the control. Without it, a test asserting "the row is present
after shutdown" would also pass against a build that emitted the row for some unrelated reason.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from messagefoundry.api import create_managed_app
from messagefoundry.store import Row, open_store, sqlite_settings


async def _summary_rows(db_path: Path) -> list[Row]:
    """Read the audit through a SECOND store opened on the same file, after the app has shut down.

    Reading through the app's own store would prove nothing: the assertion has to survive
    ``store.close()``, because durability is the property under test.
    """
    store = await open_store(sqlite_settings(db_path))
    try:
        return [a for a in await store.list_audit() if a["action"] == "summary_access"]
    finally:
        await store.close()


async def test_the_open_window_is_flushed_at_shutdown(tmp_path: Path) -> None:
    db_path = tmp_path / "flush.db"
    app = create_managed_app(db_path=db_path)

    async with app.router.lifespan_context(app):
        store = app.state.engine.store
        await app.state.summary_auditor.note(store, "alice", None, 7, time.time(), masked=2)
        # The window is OPEN: nothing has rolled it over, so nothing is durable yet. Asserting this
        # here is what makes the post-shutdown assertion below mean "the flush did it".
        live = [a for a in await store.list_audit() if a["action"] == "summary_access"]
        assert live == [], (
            f"the window emitted before shutdown, so this test proves nothing: {live}"
        )

    rows = await _summary_rows(db_path)
    assert len(rows) == 1, f"the open window was dropped at shutdown: {rows}"
    assert rows[0]["actor"] == "alice"


async def test_the_assertion_can_fail(tmp_path: Path, monkeypatch: Any) -> None:
    """Neutralise the flush and the row must disappear. This is the pre-fix behaviour."""
    db_path = tmp_path / "noflush.db"
    app = create_managed_app(db_path=db_path)

    async with app.router.lifespan_context(app):
        store = app.state.engine.store
        monkeypatch.setattr(
            app.state.summary_auditor, "flush", lambda _store: _noop(), raising=True
        )
        await app.state.summary_auditor.note(store, "alice", None, 7, time.time())

    assert await _summary_rows(db_path) == [], (
        "the row survived with the flush neutralised, so the other test is not measuring the flush"
    )


async def _noop() -> None:
    return None


async def test_a_flush_failure_does_not_abort_the_teardown(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A store error in the flush must be absorbed, or the process hangs on the non-daemon worker.

    The narrow assertion is that the lifespan's context manager EXITS. A teardown that raises here
    skips ``engine.stop()``, and the cost of that is the process, not the audit row.
    """
    db_path = tmp_path / "boom.db"
    app = create_managed_app(db_path=db_path)

    async def _boom(_store: object) -> None:
        raise RuntimeError("PROBE: deliberate flush failure")

    async with app.router.lifespan_context(app):
        store = app.state.engine.store
        monkeypatch.setattr(app.state.summary_auditor, "flush", _boom, raising=True)
        await app.state.summary_auditor.note(store, "alice", None, 3, time.time())
    # Reaching here IS the assertion: the teardown completed despite the flush raising.
