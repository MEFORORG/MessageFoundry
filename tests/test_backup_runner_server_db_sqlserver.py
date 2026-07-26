# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""DR-1 sub-test B (SQL Server) — the server-DB DR backup boundary against a LIVE SQL Server store.

The existing ``tests/test_backup_runner.py::test_server_db_is_config_only`` fakes the backend via
``object.__setattr__`` on a SQLite store — it never exercises the REAL ``SqlServerStore.snapshot_to``.
This drives the actual backend behavior:

* ``SqlServerStore.snapshot_to`` raises :class:`DbaDelegatedError` (DB-tier backup is DBA-delegated —
  native BACKUP DATABASE / Always On — never reimplemented in the engine, BACKLOG #52), and
* the :class:`BackupRunner` therefore falls back to a **config-only** archive that restore-verifies PASS
  against the live store (``config_only_on_server_db=True``).

Gated: skipped unless MEFOR_TEST_SQLSERVER is set (+ MEFOR_STORE_* connection env), like
``tests/test_dr_server_seed_gate_sqlserver.py``. Requires the `sqlserver` extra + the scripts/dev SS
container (2022/2025). Run pytest FROM the worktree (CWD shadows the editable install). No failover rig.
(SS py3.14 pyodbc may exit-139 intermittently — re-run once.)"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.settings import BackupSettings
from messagefoundry.pipeline.dr_backup import BackupRunner
from messagefoundry.store.base import DbaDelegatedError

pytestmark = pytest.mark.skipif(
    not os.getenv("MEFOR_TEST_SQLSERVER"),
    reason="set MEFOR_TEST_SQLSERVER=1 (+ MEFOR_STORE_* connection env) to run SQL Server tests",
)


@pytest.fixture
async def store() -> AsyncIterator[Any]:
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.sqlserver import SqlServerStore

    settings = load_settings(environ=os.environ).store
    s = await SqlServerStore.open(settings)
    yield s
    await s.close()


def _store_settings() -> Any:
    from messagefoundry.config.settings import load_settings

    return load_settings(environ=os.environ).store


async def test_snapshot_to_is_dba_delegated(store: Any, tmp_path: Path) -> None:
    # The REAL backend method (not a faked StoreBackend attribute): a server-DB store never snapshots the
    # DB — it raises, so the engine can't produce a half-baked copy of an infra-owned database.
    with pytest.raises(DbaDelegatedError) as exc:
        await store.snapshot_to(tmp_path / "unused.db")
    assert "DBA-delegated" in str(exc.value)


async def test_backup_runner_falls_back_to_config_only(store: Any, tmp_path: Path) -> None:
    # End-to-end: the runner classifies the live SQL Server store as server-DB and produces a
    # CONFIG-ONLY archive (no DB snapshot) that restore-verifies PASS — the AC-7 fallback, proven against
    # the real backend rather than a monkeypatched SQLite store.
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "feed.py").write_text("# a router module\n")
    runner = BackupRunner(
        store,
        BackupSettings(
            enabled=True,
            destination=str(tmp_path / "backups"),
            allow_unencrypted=True,  # the live container store may carry no DEK; the config-only
            config_only_on_server_db=True,  # archive holds no PHI DB, so cleartext is acceptable here
        ),
        store_settings=_store_settings(),
        config_dir=cfg,
        instance="dev",
    )
    result = await runner.run_once(now=1.0)
    assert result is not None
    assert result.config_only is True
    assert result.snapshot_sha256 == ""  # no DB snapshot was taken on the server-DB store
    assert result.verify is not None and result.verify.status == "PASS"
    assert Path(result.archive_path).exists()
