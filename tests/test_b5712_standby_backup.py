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

import logging
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from messagefoundry.config.settings import (
    BackupSettings,
    DrSettings,
    EgressSettings,
    StoreBackend,
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
        dr_settings=DrSettings(enabled=True, seed_archive="seed.mfbak"),
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


async def test_an_activated_sqlite_standby_backs_up_and_a_released_one_stops(
    standby_engine: Engine,
) -> None:
    # BACKLOG #5965 (owner ruling 2026-11-26): a SQLite DR box runs no restore-token check, so
    # it keeps backing up while activated.
    engine = standby_engine
    runner = engine._backup_runner
    assert runner is not None
    # The latch alone, as an activation sets it before its reload, which may still fail and
    # roll it back: no pass yet.
    engine._set_dr_active(True)
    assert await runner.run_once(now=1.0) is None
    # Once the activation's profile is applied, the same runner backs up.
    assert await engine._dr_activate_profile() == {}
    assert await runner.run_once(now=2.0) is not None
    assert len(await engine.store.list_audit(action="dr_backup")) == 1
    # A release (or a rolled-back activation) puts the latch back, and the passes stop.
    engine._set_dr_active(False)
    assert await runner.run_once(now=3.0) is None
    engine._set_dr_active(True)
    assert await runner.run_once(now=4.0) is None
    assert len(await engine.store.list_audit(action="dr_backup")) == 1


@pytest.mark.parametrize("backend", [StoreBackend.POSTGRES, StoreBackend.SQLSERVER])
async def test_an_activated_server_db_box_with_a_restore_token_backs_up_nothing(
    tmp_path: Path, backend: StoreBackend, caplog: pytest.LogCaptureFixture
) -> None:
    # BACKLOG #5965 (owner ruling 2026-11-26): its own row would become the restore-token
    # check's latest anchor and refuse a later re-activation of the same restore.
    engine = await _token_engine(
        tmp_path, backend, restore_token=str(tmp_path / "token.json"), schedule_at="02:00"
    )
    try:
        runner = engine._backup_runner
        assert runner is not None and runner.scheduled
        engine._set_dr_active(True)
        with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.engine"):
            assert await engine._dr_activate_profile() == {}
        paused = [
            r for r in caplog.records if "DR backup: scheduled passes are paused" in r.getMessage()
        ]
        assert len(paused) == 1 and "restore_token" in paused[0].getMessage()
        assert engine._dr_profile_applied
        assert await runner.run_once(now=2.0) is None
        assert await engine.store.list_audit(action="dr_backup") == []
    finally:
        await engine.stop()


async def test_an_activated_server_db_box_with_no_restore_token_is_not_paused(
    tmp_path: Path,
) -> None:
    # Control for the test above: the same box without a token is not held back.
    engine = await _token_engine(tmp_path, StoreBackend.POSTGRES, restore_token="")
    try:
        engine._set_dr_active(True)
        assert await engine._dr_activate_profile() == {}
        assert engine._dr_backup_paused() is False
    finally:
        await engine.stop()


async def _token_engine(
    tmp_path: Path, backend: StoreBackend, *, restore_token: str, schedule_at: str = ""
) -> Engine:
    """A started DR standby whose store reads as ``backend``, with backups enabled. The store is
    SQLite underneath, as in test_dr_server_seed_gate, so only the engine's gate is exercised."""
    db = tmp_path / "s.db"
    store = await MessageStore.open(db)
    store.backend = backend
    engine = Engine(
        store,
        poll_interval=0.05,
        store_settings=StoreSettings(path=str(db)),
        backup_settings=_backup_settings(tmp_path, schedule_at),
        dr_settings=DrSettings(
            enabled=True, seed_archive="seed.mfbak", restore_token=restore_token
        ),
        egress_settings=EgressSettings(deny_by_default=False),
    )
    try:
        await engine.start()
    except BaseException:
        await engine.stop()
        raise
    return engine


async def test_a_non_dr_engine_still_backs_up(tmp_path: Path) -> None:
    # Control for the passive test: the same runner on a box that is not a DR standby backs up.
    db = tmp_path / "p.db"
    engine = Engine(
        await MessageStore.open(db),
        poll_interval=0.05,
        store_settings=StoreSettings(path=str(db)),
        backup_settings=_backup_settings(tmp_path),
        egress_settings=EgressSettings(deny_by_default=False),
    )
    try:
        await engine.start()
        runner = engine._backup_runner
        assert runner is not None
        assert await runner.run_once(now=1.0) is not None
        assert len(await engine.store.list_audit(action="dr_backup")) == 1
    finally:
        await engine.stop()


class _RefusingRunner:
    """Stands in for the registry runner during an activation whose reload is refused."""

    registry = None

    def listening_inbounds(self) -> frozenset[str]:
        return frozenset()

    def set_dr_threshold(self, *_args: object, **_kwargs: object) -> None:
        return None

    async def reload(self, **_kwargs: object) -> tuple[tuple[str, str], ...]:
        raise RuntimeError("refused by a trust anchor")

    async def park_intake(self, *_args: object, **_kwargs: object) -> None:
        return None

    async def close_passive_connectors(self) -> None:
        return None


async def test_a_refused_activation_leaves_the_backup_paused(
    standby_engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The activation latches the run-profile before its reload, and the refused reload rolls the
    # latch back. No pass may have run in between, and none runs after.
    engine = standby_engine
    runner = engine._backup_runner
    assert runner is not None
    passes: list[object] = []

    async def preflight(_registry: object) -> None:
        # The latch is not flipped yet; the reload is the step that fails.
        return None

    real_set = engine._set_dr_active

    def set_and_try_a_pass(active: bool) -> None:
        real_set(active)
        passes.append(runner._may_back_up())

    monkeypatch.setattr(engine, "_dr_preflight", preflight)
    monkeypatch.setattr(engine, "_set_dr_active", set_and_try_a_pass)
    monkeypatch.setattr(engine, "_registry_runner", _RefusingRunner())
    with pytest.raises(RuntimeError, match="refused"):
        await engine._dr_activate_profile()
    monkeypatch.setattr(engine, "_registry_runner", None)
    assert passes == [False, False], "a pass could start while the activation was in flight"
    assert not engine.dr_active
    assert await runner.run_once(now=1.0) is None
    assert await engine.store.list_audit(action="dr_backup") == []


async def test_the_scheduled_pass_is_not_due_on_a_passive_standby(tmp_path: Path) -> None:
    db = tmp_path / "b.db"
    store = await MessageStore.open(db)
    standby = True
    runner = BackupRunner(
        store,
        _backup_settings(tmp_path, schedule_at="00:00"),
        store_settings=StoreSettings(path=str(db)),
        config_dir=None,
        dr_paused=lambda: standby,
    )
    day = 1_000_000.0
    try:
        # 00:00 is always reached, and no pass has run that day.
        assert runner._backup_due(day) is False
        # An activation later that day catches the day's pass up, as a late start does.
        standby = False
        assert runner._backup_due(day + 60.0) is True
    finally:
        await store.close()
