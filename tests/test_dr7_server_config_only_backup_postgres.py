# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Live Postgres proof of the DR-7 server-DB config-only backup (ADR 0049 AC-7, BACKLOG #52/#60): a
REAL server-DB store produces a config-only .mfbak (no store.db snapshot) that restore-verifies PASS,
with exactly one PHI-free dr_backup audit row.

Unlike tests/test_backup_runner.py (which fakes the backend via ``object.__setattr__(store, "backend",
POSTGRES)`` on a SQLite store — its docstring concedes the dr_backup row is asserted on SQLite only),
this exercises the genuine path on a real PostgresStore: ``_is_server_db()`` is true because the store's
``backend`` really is POSTGRES, ``snapshot_to`` really raises ``DbaDelegatedError`` (never called here —
the config-only branch skips it), and the audit row is written to the real backend.

Gated: skipped unless MEFOR_TEST_POSTGRES is set (+ MEFOR_STORE_* connection env), like the seed-gate
quartet (test_dr_server_seed_gate_postgres.py). Requires the `postgres` extra + the scripts/dev PG
container. Run pytest FROM the worktree (CWD shadows the editable install)."""

from __future__ import annotations

import base64
import io
import json
import os
import tarfile
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.settings import BackupSettings
from messagefoundry.pipeline.dr_backup import BackupError, BackupRunner
from messagefoundry.store.backup_codec import decrypt_stream
from messagefoundry.store.base import resolve_active_key

pytestmark = pytest.mark.skipif(
    not os.getenv("MEFOR_TEST_POSTGRES"),
    reason="set MEFOR_TEST_POSTGRES=1 (+ MEFOR_STORE_* connection env) to run Postgres tests",
)


@pytest.fixture
async def store() -> AsyncIterator[Any]:
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.postgres import PostgresStore

    settings = load_settings(environ=os.environ).store
    s = await PostgresStore.open(settings)
    yield s
    await s.close()


def _store_settings() -> Any:
    from messagefoundry.config.settings import load_settings

    return load_settings(environ=os.environ).store


async def _reset_audit(store: Any) -> None:
    # Deterministic dr_backup-row count: clear the audit chain before the run (the container is a
    # shared, no-PHI synthetic store; other tests leave rows behind).
    async with store._pool.acquire() as conn:
        await conn.execute("DELETE FROM audit_log")


def _write_config_dir(base: Path) -> Path:
    # A minimal but real config bundle: a code-first feed module + a connections.toml. Synthetic only.
    cfg = base / "config"
    cfg.mkdir()
    (cfg / "feed.py").write_text("# DR-7 synthetic feed\n")
    (cfg / "connections.toml").write_text(
        '[[inbound]]\nname = "IB_DR7_ADT"\ntype = "mllp"\nport = 12599\nrouter = "r_dr7"\n'
    )
    return cfg


def _archive_member_names(archive_path: str, store_settings: Any) -> list[str]:
    key_b64 = resolve_active_key(store_settings)
    if key_b64:  # encrypted archive: decrypt to a tar in memory, then list members
        out = io.BytesIO()
        with open(archive_path, "rb") as src:
            decrypt_stream(src, out, base64.b64decode(key_b64))
        out.seek(0)
        with tarfile.open(fileobj=out, mode="r") as tar:
            return tar.getnames()
    with tarfile.open(archive_path, mode="r") as tar:  # plaintext archive (no-key synthetic box)
        return tar.getnames()


async def test_server_db_config_only_backup_round_trip(store: Any, tmp_path: Path) -> None:
    await _reset_audit(store)
    ss = _store_settings()
    key_b64 = resolve_active_key(ss)
    cfg = _write_config_dir(tmp_path)
    runner = BackupRunner(
        store,
        BackupSettings(
            enabled=True,
            destination=str(tmp_path / "backups"),
            config_only_on_server_db=True,
            allow_unencrypted=key_b64 is None,  # no-PHI container has no DEK → allow plaintext
        ),
        store_settings=ss,
        config_dir=cfg,
        instance="dr7",
    )

    result = await runner.run_once(now=1000.0)

    # The real server-DB store is config-only: no DB snapshot was taken (DbaDelegatedError branch),
    # and the config-only archive restore-verifies PASS.
    assert result is not None
    assert result.config_only is True
    assert result.snapshot_sha256 == ""  # no store.db snapshot — snapshot_to never ran
    assert result.verify is not None and result.verify.status == "PASS"

    # The archive carries the config bundle but NOT a store.db member.
    names = _archive_member_names(result.archive_path, ss)
    assert "store.db" not in names
    assert any(n.startswith("config/") for n in names)

    # Exactly one PHI-free dr_backup audit row on the REAL server store (DR-8 parity).
    rows = await store.list_audit(limit=50)
    backup_rows = [r for r in rows if r["action"] == "dr_backup"]
    assert len(backup_rows) == 1
    detail = json.loads(backup_rows[0]["detail"])
    assert detail["config_only"] is True
    assert detail["verify"] == "PASS"
    # Metadata only: no message body / config text / key bytes leaked into the audit detail.
    blob = json.dumps(detail)
    assert "IB_DR7_ADT" not in blob
    if key_b64:
        assert key_b64 not in blob


async def test_server_db_config_only_disabled_raises(store: Any, tmp_path: Path) -> None:
    # With config_only_on_server_db=False there is nothing to back up on a real server-DB store — the
    # DB is DBA-delegated — so the run fails at the snapshot phase (the genuine backend gate).
    ss = _store_settings()
    key_b64 = resolve_active_key(ss)
    runner = BackupRunner(
        store,
        BackupSettings(
            enabled=True,
            destination=str(tmp_path / "backups"),
            config_only_on_server_db=False,
            allow_unencrypted=key_b64 is None,
        ),
        store_settings=ss,
        config_dir=None,
    )
    with pytest.raises(BackupError) as exc:
        await runner.run_once(now=1000.0)
    assert exc.value.kind == "snapshot"
