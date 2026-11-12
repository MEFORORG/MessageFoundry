# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A passive DR standby runs no backup pass (vault BACKLOG #5712).

A lone DR box runs the NullCoordinator, which always leads, so the backup runner's leader gate
let a standby with ``[backup].enabled`` back up its own store. Each pass writes a ``dr_backup``
audit row. On a server-DB standby that row would satisfy the live seed probe
(``Store.has_prior_backup_history``) on a database nobody restored, and it would become the latest
anchor the restore-token check compares against the DBA-recorded one, refusing a valid restore.
The runner now asks the engine, at each pass, whether the box is a passive standby."""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from messagefoundry.config.settings import (
    BackupSettings,
    DrSettings,
    EgressSettings,
    StoreSettings,
)
from messagefoundry.pipeline import Engine
from messagefoundry.pipeline.dr_backup import BackupRunner
from messagefoundry.store import MessageStore


def _backup_settings(tmp_path: Path, schedule_at: str = "") -> BackupSettings:
    return BackupSettings(
        enabled=True,
        destination=str(tmp_path / "backups"),
        allow_unencrypted=True,
        schedule_at=schedule_at,  # "" is on-demand only: no scheduled pass races the test's own
    )


@pytest.fixture
async def standby_engine(tmp_path: Path) -> AsyncIterator[Engine]:
    """A started DR standby, not activated, with backups enabled."""
    db = tmp_path / "e.db"
    engine = Engine(
        await MessageStore.open(db),
        poll_interval=0.05,
        store_settings=StoreSettings(path=str(db)),
        backup_settings=_backup_settings(tmp_path),
        dr_settings=DrSettings(enabled=True),
        egress_settings=EgressSettings(deny_by_default=False),
    )
    try:
        await engine.start()
        yield engine
    finally:
        await engine.stop()


async def test_a_passive_standby_writes_no_dr_backup_row(standby_engine: Engine) -> None:
    engine = standby_engine
    runner = engine._backup_runner
    assert runner is not None
    assert not engine.dr_active
    assert await runner.run_once(now=1.0) is None
    assert await engine.store.list_audit(action="dr_backup") == []
    # The probe the server-DB activation gate reads still finds no backup history.
    assert await engine.store.has_prior_backup_history() is False


async def test_an_activated_standby_backs_up_and_a_released_one_stops(
    standby_engine: Engine,
) -> None:
    engine = standby_engine
    runner = engine._backup_runner
    assert runner is not None
    # Control: the gate reads the latch live, so the same runner backs up once the box is active.
    engine._set_dr_active(True)
    assert await runner.run_once(now=1.0) is not None
    assert len(await engine.store.list_audit(action="dr_backup")) == 1
    engine._set_dr_active(False)
    assert await runner.run_once(now=2.0) is None
    assert len(await engine.store.list_audit(action="dr_backup")) == 1


async def test_the_scheduled_pass_is_not_due_on_a_passive_standby(tmp_path: Path) -> None:
    db = tmp_path / "b.db"
    store = await MessageStore.open(db)
    standby = True
    runner = BackupRunner(
        store,
        _backup_settings(tmp_path, schedule_at="00:00"),
        store_settings=StoreSettings(path=str(db)),
        config_dir=None,
        passive_standby=lambda: standby,
    )
    try:
        # 00:00 is always reached, and no pass has run today.
        assert runner._backup_due(1_000_000.0) is False
        standby = False
        assert runner._backup_due(1_000_000.0) is True
    finally:
        await store.close()
