# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Live Postgres proof of the #102 server-DB DR seed gate (ADR 0048), reproducing the REAL deployment
path. On a genuinely fresh/unrestored 'mefor' store whose audit_log is NON-EMPTY-but-has-no-dr_backup-row
(the bootstrap+login signature) + attestation → REFUSED (the data-loss case the config-only archive and
the refuted count>0 probe both miss). A store carrying a dr_backup row (restored-primary signature) +
attestation → PASS. No attestation → REFUSED. run_restore_verify is stubbed to PASS so the test isolates
the LIVE restore-provenance probe (has_prior_backup_history against a real backend).

Gated: skipped unless MEFOR_TEST_POSTGRES is set (+ MEFOR_STORE_* connection env), like
test_adr0071_dispatch_wiring_sqlserver.py. Requires the `postgres` extra + the scripts/dev PG container.
Run pytest FROM the worktree (CWD shadows the editable install)."""

from __future__ import annotations

import json
import os
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

import messagefoundry.pipeline.dr as drmod
from messagefoundry.config.settings import DrSettings
from messagefoundry.pipeline.dr import DrActivationError, DrCoordinator
from messagefoundry.pipeline.dr_backup import VerifyResult

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


def _coord(store: Any, **dr_over: object) -> tuple[DrCoordinator, dict[str, bool]]:
    state = {"active": False}

    async def act() -> None:
        state["active"] = True

    async def deact() -> None:
        state["active"] = False

    coord = DrCoordinator(
        store,
        DrSettings(enabled=True, seed_archive="unused.mfbak", **dr_over),  # type: ignore[arg-type]
        store_settings=_store_settings(),
        activate_profile=act,
        deactivate_profile=deact,
    )
    return coord, state


async def _reset_to_fresh_bootstrapped(store: Any) -> None:
    # Reproduce a FRESH/UNRESTORED but engine-started DB: audit_log NON-EMPTY (bootstrap + login) yet with
    # NO dr_backup row. This is the exact real-path state the refuted count>0 probe would have PASSED.
    async with store._pool.acquire() as conn:
        await conn.execute("DELETE FROM audit_log")
    await store.record_audit(
        "auth.bootstrap_admin_created", actor="bootstrap", detail="{}", now=1.0
    )
    await store.record_audit("auth.login_success", actor="alice", detail="{}", now=2.0)


def _stub_verify_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    # Isolate the LIVE gate: the archive restore-verify is proven elsewhere; force PASS so the test drives
    # the provenance probe against the real backend rather than re-exercising the codec.
    async def _pass(*_a: object, **_k: object) -> VerifyResult:
        return VerifyResult("PASS", integrity_ok=True)

    monkeypatch.setattr(drmod, "run_restore_verify", _pass)


async def test_fresh_bootstrapped_db_attested_refused(
    store: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_verify_pass(monkeypatch)
    await _reset_to_fresh_bootstrapped(store)
    count, _ = await store.audit_anchor()
    assert (
        count > 0
    )  # the REAL path: non-empty audit_log, so the old count>0 probe would have PASSED
    assert await store.has_prior_backup_history() is False  # but no dr_backup row → not restored
    coord, state = _coord(store)
    with pytest.raises(DrActivationError) as exc:
        await coord.activate(dba_attests_restored=True, actor="alice")
    assert (
        exc.value.kind == "seed"
    )  # fresh/unrestored fails closed even WITH attestation (defense depth)
    assert not coord.active and not state["active"]


async def test_no_attestation_refused(store: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_verify_pass(monkeypatch)
    await store.record_audit("dr_backup", actor="system", detail="{}", now=1.0)  # probe would pass
    coord, state = _coord(store)
    with pytest.raises(DrActivationError) as exc:
        await coord.activate(actor="alice")  # server DB + no attestation
    assert exc.value.kind == "seed"
    assert not coord.active and not state["active"]


async def test_restored_db_attested_passes(store: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_verify_pass(monkeypatch)
    # A restored-primary signature: a dr_backup row present (the primary wrote one on the backup run).
    await store.record_audit("dr_backup", actor="system", detail="{}", now=1.0)
    assert await store.has_prior_backup_history() is True
    coord, state = _coord(store)
    result = await coord.activate(dba_attests_restored=True, actor="alice")
    assert result.active and coord.active and state["active"]
    assert result.verify_status == "PASS"


# --- DR-27: restore-token vintage-floor cross-check on a REAL server DB (BACKLOG #223, ADR 0102) --------
#
# The #102 gate's branch (c) (DrCoordinator._verify_restore_token + _latest_backup_archive) round-trips
# the live store's list_audit(action="dr_backup") + detail-JSON parse. The unit tests cover it against a
# SQLite store with .backend monkeypatched — this drives it against the REAL asyncpg Record row type
# (row.keys()/row["detail"]) that _latest_backup_archive relies on. Active only when [dr].restore_token
# is set.

_ANCHOR = "mefor-backup-20260101T000000Z.mfbak"


async def _clear_audit(store: Any) -> None:
    async with store._pool.acquire() as conn:
        await conn.execute("DELETE FROM audit_log")


async def _actions(store: Any) -> list[str]:
    return [r["action"] for r in await store.list_audit(limit=50)]


def _write_token(tmp_path: Path, expected_archive: str) -> str:
    token = tmp_path / "restore.token"
    token.write_text(json.dumps({"expected_backup_archive": expected_archive}), encoding="utf-8")
    return str(token)


async def test_restore_token_matches_passes(
    store: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # AC: the token's expected anchor MATCHES the restored DB's latest SUCCESSFUL dr_backup archive read
    # back through the real list_audit round-trip → the vintage floor is satisfied and activation proceeds.
    _stub_verify_pass(monkeypatch)
    await _clear_audit(store)
    await store.record_audit(
        "dr_backup", actor="system", detail=json.dumps({"archive": _ANCHOR}), now=1.0
    )
    token = _write_token(tmp_path, _ANCHOR)
    coord, state = _coord(store, restore_token=token)
    result = await coord.activate(dba_attests_restored=True, actor="alice")
    assert result.active and coord.active and state["active"]
    assert "dr_activation_aborted" not in await _actions(store)


async def test_restore_token_mismatch_refused(
    store: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # The token names a DIFFERENT archive than the restored DB's latest dr_backup anchor (a stale/wrong
    # native restore) → fail closed, kind seed, dr_activation_aborted recorded, never active.
    _stub_verify_pass(monkeypatch)
    await _clear_audit(store)
    await store.record_audit(
        "dr_backup", actor="system", detail=json.dumps({"archive": _ANCHOR}), now=1.0
    )
    token = _write_token(tmp_path, "mefor-backup-19990101T000000Z.mfbak")
    coord, state = _coord(store, restore_token=token)
    with pytest.raises(DrActivationError) as exc:
        await coord.activate(dba_attests_restored=True, actor="alice")
    assert exc.value.kind == "seed"
    assert not coord.active and not state["active"]
    assert "dr_activation_aborted" in await _actions(store)


async def test_restore_token_no_successful_anchor_refused(
    store: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # A dr_backup row exists (so has_prior_backup_history passes branch b), but it is a FAILURE row with no
    # 'archive' in detail → _latest_backup_archive returns None → no vintage to floor against → refused.
    _stub_verify_pass(monkeypatch)
    await _clear_audit(store)
    await store.record_audit(
        "dr_backup", actor="system", detail=json.dumps({"outcome": "error"}), now=1.0
    )
    assert await store.has_prior_backup_history() is True  # branch (b) passes...
    token = _write_token(tmp_path, _ANCHOR)
    coord, state = _coord(store, restore_token=token)
    with pytest.raises(DrActivationError) as exc:
        await coord.activate(dba_attests_restored=True, actor="alice")
    assert exc.value.kind == "seed"  # ...but branch (c) has no successful anchor → refused
    assert not coord.active and not state["active"]
    assert "dr_activation_aborted" in await _actions(store)


async def test_restore_token_skips_failure_row(
    store: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # A later dr_backup ERROR row (higher id, no 'archive') must NOT shadow the earlier SUCCESS archive:
    # _latest_backup_archive scans id-DESC and skips the failure row, matching the token against the
    # success anchor → passes.
    _stub_verify_pass(monkeypatch)
    await _clear_audit(store)
    await store.record_audit(
        "dr_backup", actor="system", detail=json.dumps({"archive": _ANCHOR}), now=1.0
    )
    await store.record_audit(
        "dr_backup", actor="system", detail=json.dumps({"outcome": "error"}), now=2.0
    )
    token = _write_token(tmp_path, _ANCHOR)
    coord, state = _coord(store, restore_token=token)
    result = await coord.activate(dba_attests_restored=True, actor="alice")
    assert result.active and coord.active and state["active"]
    assert "dr_activation_aborted" not in await _actions(store)
