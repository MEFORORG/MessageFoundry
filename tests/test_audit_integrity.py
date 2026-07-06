# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Phase-8 AUDIT-INTEGRITY: tamper-evident audit-log hash chain + verification."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.store import MessageStore


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "audit.db")
    yield s
    await s.close()


async def test_chain_verifies_after_normal_appends(store: MessageStore) -> None:
    for i in range(3):
        await store.record_audit("action", actor="u", detail=f'{{"n":{i}}}')
    ok, message = await store.verify_audit_chain()
    assert ok and "3" in (message or "")


async def test_edit_breaks_the_chain(store: MessageStore) -> None:
    await store.record_audit("login", actor="u")
    await store.record_audit("view", actor="u")
    # Tamper with a row's content out-of-band (its stored hash no longer matches its content).
    await store._db.execute("UPDATE audit_log SET action='HACKED' WHERE id=1")
    await store._db.commit()
    ok, message = await store.verify_audit_chain()
    assert not ok and "id=1" in (message or "")


async def test_delete_breaks_the_chain(store: MessageStore) -> None:
    for action in ("a", "b", "c"):
        await store.record_audit(action, actor="u")
    await store._db.execute("DELETE FROM audit_log WHERE action='b'")  # drop a middle row
    await store._db.commit()
    ok, _ = await store.verify_audit_chain()
    assert not ok  # 'c' now chains from the wrong predecessor


async def test_tail_truncation_caught_only_with_external_anchor(store: MessageStore) -> None:
    # low-1: deleting the NEWEST rows leaves a shorter chain that still verifies; only an anchor
    # snapshotted out-of-band catches it.
    for action in ("a", "b", "c"):
        await store.record_audit(action, actor="u")
    anchor = await store.audit_anchor()
    assert anchor[0] == 3 and anchor[1]  # (count, non-empty head hash)
    await store._db.execute("DELETE FROM audit_log WHERE action='c'")  # drop the newest row
    await store._db.commit()
    ok, _ = await store.verify_audit_chain()
    assert ok  # the within-DB walk can't see tail-truncation
    ok, message = await store.verify_audit_chain(expected_anchor=anchor)
    assert not ok and "anchor" in (message or "")  # the external anchor does


async def test_backfill_chains_legacy_unhashed_rows(tmp_path: Path) -> None:
    db = tmp_path / "legacy.db"
    store = await MessageStore.open(db)
    try:
        # Simulate rows written before hash-chaining: row_hash NULL.
        for i in range(3):
            await store._db.execute(
                "INSERT INTO audit_log (ts, actor, action, channel_id, detail, row_hash)"
                " VALUES (?,?,?,?,?,NULL)",
                (float(i), "u", "legacy", None, None),
            )
        await store._db.commit()
        await store._backfill_audit_chain()
        ok, _ = await store.verify_audit_chain()
        assert ok  # backfill established a continuous chain over the legacy rows
    finally:
        await store.close()


def test_audit_verify_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db = tmp_path / "cli.db"

    async def _seed() -> None:
        s = await MessageStore.open(db)
        await s.record_audit("login", actor="x")
        await s.record_audit("view", actor="x")
        await s.close()

    asyncio.run(_seed())
    assert main(["audit-verify", "--db", str(db)]) == 0
    assert "OK" in capsys.readouterr().out


def test_audit_verify_cli_refuses_missing_db(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # M-31: a typo'd --db must NOT create a fresh DB and report a false "OK: verified 0 rows".
    missing = tmp_path / "typo.db"
    assert main(["audit-verify", "--db", str(missing)]) == 2
    assert "no audit database" in capsys.readouterr().err
    assert not missing.exists()  # we refused before opening, so no empty DB was littered
