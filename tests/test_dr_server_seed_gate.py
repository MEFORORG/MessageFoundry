# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Server-DB DR seed live gate (BACKLOG #102, ADR 0048). On a Postgres/SQL Server store the #60 backup is
config-only, so run_restore_verify PASSes without restoring/inspecting the DBA-managed live 'mefor' DB —
activation could otherwise promote priority feeds onto a FRESH/UNRESTORED server store (non-empty only
because engine bootstrap + operator login wrote to audit_log). DrCoordinator._verify_live_server_seed
closes that: it fails closed unless (a) an explicit DBA attestation is supplied AND (b) a live
restore-provenance probe (Store.has_prior_backup_history — ≥1 dr_backup row) proves the DB was restored
from an operating primary, not freshly bootstrapped. A mistaken attestation over a fresh DB still fails
closed. SQLite is a no-op (its archive verifies the whole store — byte-identical path).

These are the no-Docker unit tests: a REAL SQLite store + archive, with `backend` monkeypatched to a
server backend to exercise the gate. The real-backend proofs (a genuinely fresh-bootstrapped vs restored
server DB) ride tests/test_dr_server_seed_gate_{sqlserver,postgres}.py."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from messagefoundry.config.settings import (
    BackupSettings,
    DrSettings,
    StoreBackend,
    StoreSettings,
)
from messagefoundry.pipeline.dr import DrActivationError, DrCoordinator
from messagefoundry.pipeline.dr_backup import BackupRunner, run_restore_verify
from messagefoundry.store import MessageStore
from messagefoundry.store.base import (
    DbaDelegatedError,
)  # NOTE: base, NOT config.settings (verdict blocker)
from messagefoundry.store.crypto import generate_key, make_cipher


async def _make_seed(tmp_path: Path) -> tuple[MessageStore, str, StoreSettings]:
    """A real #60 .mfbak cold-seed archive from a small SQLite store. run_once records a 'dr_backup' audit
    row (leader-gated default coordinator is leader), so the store also gains prior-backup-history."""
    key = generate_key()
    store = await MessageStore.open(tmp_path / "msg.db", cipher=make_cipher(key))
    await store.enqueue_message(
        channel_id="c1",
        raw="MSH|^~\\&|x",
        deliveries=[("d1", "OUT|y")],
        control_id="CID-1",
        now=1.0,
    )
    ss = StoreSettings(path=str(tmp_path / "msg.db"), encryption_key=key)
    runner = BackupRunner(
        store,
        BackupSettings(enabled=True, destination=str(tmp_path / "b")),
        store_settings=ss,
        config_dir=None,
    )
    res = await runner.run_once(now=1.0)
    assert res is not None
    return store, res.archive_path, ss


def _coord(
    store: MessageStore, ss: object, **dr_over: object
) -> tuple[DrCoordinator, dict[str, bool]]:
    state = {"active": False}

    async def act() -> None:
        state["active"] = True

    async def deact() -> None:
        state["active"] = False

    coord = DrCoordinator(
        store,
        DrSettings(enabled=True, **dr_over),  # type: ignore[arg-type]
        store_settings=ss,
        activate_profile=act,
        deactivate_profile=deact,
    )
    return coord, state


async def _actions(store: MessageStore) -> list[str]:
    return [r["action"] for r in await store.list_audit(limit=50)]


async def test_server_db_no_attestation_refused(tmp_path: Path) -> None:
    # A server-DB store with NO dba_attests_restored → fail closed BEFORE the probe/VIP/profile step.
    store, archive, ss = await _make_seed(tmp_path)
    try:
        store.backend = StoreBackend.POSTGRES  # type: ignore[assignment]
        coord, state = _coord(store, ss, seed_archive=archive)
        with pytest.raises(DrActivationError) as exc:
            await coord.activate(actor="alice")  # dba_attests_restored defaults False
        assert exc.value.kind == "seed"
        assert not coord.active and not state["active"]
        actions = await _actions(store)
        assert "dr_activation_aborted" in actions and "dr.activate" not in actions
    finally:
        await store.close()


async def test_server_db_attested_but_no_history_refused(tmp_path: Path) -> None:
    # Defense in depth: attestation given, but the restore-provenance probe reports NO prior backup
    # history (fresh/unrestored signature) → still fail closed. Modeled by forcing the probe False. This is
    # the REAL-PATH hole the refuted count>0 probe left open (audit_log is non-empty from bootstrap/login).
    store, archive, ss = await _make_seed(tmp_path)
    try:
        store.backend = StoreBackend.SQLSERVER  # type: ignore[assignment]

        async def _fresh() -> bool:
            return False

        store.has_prior_backup_history = _fresh  # type: ignore[method-assign]
        coord, state = _coord(store, ss, seed_archive=archive)
        with pytest.raises(DrActivationError) as exc:
            await coord.activate(dba_attests_restored=True, actor="alice")
        assert exc.value.kind == "seed"
        assert not coord.active and not state["active"]
        # The abort row is written via the real record_audit (only the probe was patched).
        assert "dr_activation_aborted" in await _actions(store)
    finally:
        await store.close()


async def test_server_db_probe_unreachable_refused(tmp_path: Path) -> None:
    # The restored DB is unreachable / has no audit_log → the probe raises → fail closed (kind seed).
    store, archive, ss = await _make_seed(tmp_path)
    try:
        store.backend = StoreBackend.POSTGRES  # type: ignore[assignment]

        async def _boom() -> bool:
            raise RuntimeError('relation "audit_log" does not exist')

        store.has_prior_backup_history = _boom  # type: ignore[method-assign]
        coord, state = _coord(store, ss, seed_archive=archive)
        with pytest.raises(DrActivationError) as exc:
            await coord.activate(dba_attests_restored=True, actor="alice")
        assert exc.value.kind == "seed"
        assert not coord.active and not state["active"]
    finally:
        await store.close()


async def test_server_db_attested_and_restored_passes(tmp_path: Path) -> None:
    # Happy path: attestation given AND the REAL probe sees prior backup history (the _make_seed run wrote
    # a dr_backup row; add one explicitly for robustness) → activation proceeds and serves.
    store, archive, ss = await _make_seed(tmp_path)
    try:
        await store.record_audit(
            "dr_backup", actor="system", detail="{}", now=1.0
        )  # restored history
        assert await store.has_prior_backup_history() is True  # real probe against real storage
        store.backend = StoreBackend.POSTGRES  # type: ignore[assignment]
        coord, state = _coord(store, ss, seed_archive=archive)  # no takeover_hook → LB path
        result = await coord.activate(dba_attests_restored=True, actor="alice")
        assert result.active and result.verify_status == "PASS"
        assert coord.active and state["active"]
        actions = await _actions(store)
        assert "dr_seed" in actions and "dr.activate" in actions
        assert "dr_activation_aborted" not in actions
    finally:
        await store.close()


async def test_sqlite_backend_ignores_attestation_gate(tmp_path: Path) -> None:
    # SQLite is a no-op for the gate: NO attestation, yet activation still proceeds (the archive already
    # verified the whole store.db). Proves the SQLite path is byte-identical / unaffected by #102.
    store, archive, ss = await _make_seed(tmp_path)
    try:
        assert store.backend is StoreBackend.SQLITE  # unchanged
        coord, state = _coord(store, ss, seed_archive=archive)
        result = await coord.activate(actor="alice")  # no attestation, SQLite doesn't need it
        assert result.active and coord.active and state["active"]
        assert "dr_activation_aborted" not in await _actions(store)
    finally:
        await store.close()


# --- BACKLOG #223 / ADR 0102: opt-in restore-token vintage-floor cross-check ------------------------
#
# When [dr].restore_token is set, the #102 server-DB gate additionally cross-checks the DBA-recorded
# expected source-backup anchor against the restored DB's OWN latest successful dr_backup archive. A
# stale/wrong native restore's latest anchor differs → refused closed. Unset → byte-identical to #102.


def _write_token(tmp_path: Path, expected_archive: object) -> str:
    """Write a restore-token file with the given expected_backup_archive; return its path."""
    token = tmp_path / "restore.token"
    token.write_text(json.dumps({"expected_backup_archive": expected_archive}), encoding="utf-8")
    return str(token)


async def test_restore_token_matching_passes(tmp_path: Path) -> None:
    # AC-2: the token's expected anchor MATCHES the restored DB's latest dr_backup archive (the one
    # _make_seed's run_once recorded) → the vintage floor is satisfied and activation proceeds.
    store, archive, ss = await _make_seed(tmp_path)
    try:
        token = _write_token(tmp_path, Path(archive).name)
        store.backend = StoreBackend.POSTGRES  # type: ignore[assignment]
        coord, state = _coord(store, ss, seed_archive=archive, restore_token=token)
        result = await coord.activate(dba_attests_restored=True, actor="alice")
        assert result.active and coord.active and state["active"]
        assert "dr_activation_aborted" not in await _actions(store)
    finally:
        await store.close()


async def test_restore_token_mismatch_refused(tmp_path: Path) -> None:
    # AC-3: the token names a DIFFERENT archive than the restored DB's latest dr_backup (a stale/wrong
    # native restore) → fail closed BEFORE any VIP/profile step.
    store, archive, ss = await _make_seed(tmp_path)
    try:
        token = _write_token(tmp_path, "mefor-backup-other-19990101T000000Z.mfbak")
        store.backend = StoreBackend.SQLSERVER  # type: ignore[assignment]
        coord, state = _coord(store, ss, seed_archive=archive, restore_token=token)
        with pytest.raises(DrActivationError) as exc:
            await coord.activate(dba_attests_restored=True, actor="alice")
        assert exc.value.kind == "seed"
        assert not coord.active and not state["active"]
        actions = await _actions(store)
        assert "dr_activation_aborted" in actions and "dr.activate" not in actions
    finally:
        await store.close()


async def test_restore_token_missing_file_refused(tmp_path: Path) -> None:
    # AC-4: restore_token is configured but the file is absent on disk (an opted-in but unsatisfiable
    # check) → fail closed, never silently pass.
    store, archive, ss = await _make_seed(tmp_path)
    try:
        missing = str(tmp_path / "does-not-exist.token")
        store.backend = StoreBackend.POSTGRES  # type: ignore[assignment]
        coord, state = _coord(store, ss, seed_archive=archive, restore_token=missing)
        with pytest.raises(DrActivationError) as exc:
            await coord.activate(dba_attests_restored=True, actor="alice")
        assert exc.value.kind == "seed"
        assert not coord.active and not state["active"]
        assert "dr_activation_aborted" in await _actions(store)
    finally:
        await store.close()


async def test_restore_token_malformed_refused(tmp_path: Path) -> None:
    # AC-4: the token file is present but not a JSON object with a non-empty expected_backup_archive
    # string → fail closed.
    store, archive, ss = await _make_seed(tmp_path)
    try:
        bad = tmp_path / "bad.token"
        bad.write_text("not json at all", encoding="utf-8")
        store.backend = StoreBackend.POSTGRES  # type: ignore[assignment]
        coord, state = _coord(store, ss, seed_archive=archive, restore_token=str(bad))
        with pytest.raises(DrActivationError) as exc:
            await coord.activate(dba_attests_restored=True, actor="alice")
        assert exc.value.kind == "seed"
        assert not coord.active and not state["active"]
    finally:
        await store.close()


async def test_restore_token_empty_field_refused(tmp_path: Path) -> None:
    # AC-4: a JSON object whose expected_backup_archive is blank is not a usable anchor → fail closed.
    store, archive, ss = await _make_seed(tmp_path)
    try:
        token = _write_token(tmp_path, "   ")
        store.backend = StoreBackend.POSTGRES  # type: ignore[assignment]
        coord, state = _coord(store, ss, seed_archive=archive, restore_token=token)
        with pytest.raises(DrActivationError) as exc:
            await coord.activate(dba_attests_restored=True, actor="alice")
        assert exc.value.kind == "seed"
        assert not coord.active and not state["active"]
    finally:
        await store.close()


async def test_restore_token_unset_is_noop(tmp_path: Path) -> None:
    # AC-1: with restore_token unset (the default), the gate is byte-identical to #102 — the token
    # cross-check never runs, so attested+restored activation proceeds exactly as before.
    store, archive, ss = await _make_seed(tmp_path)
    try:
        store.backend = StoreBackend.POSTGRES  # type: ignore[assignment]
        coord, state = _coord(store, ss, seed_archive=archive)  # no restore_token
        result = await coord.activate(dba_attests_restored=True, actor="alice")
        assert result.active and coord.active and state["active"]
        assert "dr_activation_aborted" not in await _actions(store)
    finally:
        await store.close()


async def test_restore_token_skips_failure_rows(tmp_path: Path) -> None:
    # The latest dr_backup row can be a FAILURE row (detail = {outcome:error,...}, no archive); the
    # anchor lookup must skip it and match against the latest SUCCESSFUL backup archive.
    store, archive, ss = await _make_seed(tmp_path)
    try:
        # A later dr_backup ERROR row (no 'archive') must NOT become the anchor.
        await store.record_audit(
            "dr_backup",
            actor="system",
            detail=json.dumps({"outcome": "error", "kind": "write", "error": "disk full"}),
            now=2.0,
        )
        token = _write_token(tmp_path, Path(archive).name)  # match the SUCCESS row from _make_seed
        store.backend = StoreBackend.POSTGRES  # type: ignore[assignment]
        coord, state = _coord(store, ss, seed_archive=archive, restore_token=token)
        result = await coord.activate(dba_attests_restored=True, actor="alice")
        assert result.active and coord.active and state["active"]
        assert "dr_activation_aborted" not in await _actions(store)
    finally:
        await store.close()


async def test_restore_token_ignored_on_sqlite(tmp_path: Path) -> None:
    # The whole server-DB gate (incl. the token cross-check) is a no-op on SQLite: even a MISMATCHING
    # token is ignored because the archive already verified the whole store.db.
    store, archive, ss = await _make_seed(tmp_path)
    try:
        token = _write_token(tmp_path, "mefor-backup-would-mismatch.mfbak")
        assert store.backend is StoreBackend.SQLITE  # unchanged
        coord, state = _coord(store, ss, seed_archive=archive, restore_token=token)
        result = await coord.activate(actor="alice")  # no attestation needed on SQLite
        assert result.active and coord.active and state["active"]
        assert "dr_activation_aborted" not in await _actions(store)
    finally:
        await store.close()


async def test_cli_restore_verify_config_only_unaffected(tmp_path: Path) -> None:
    # The activation-only live gate must NOT change run_restore_verify's archive-only contract: a
    # config-only archive (like a server-DB backup) still PASSes verify (the CLI `restore-verify` path).
    # force_config_only=True is the CLI `--config-only` flag; on a real server DB snapshot_to is
    # DBA-delegated (raises DbaDelegatedError) but config-only never reaches it — asserted here by leaving
    # a raising snapshot_to in place that must NOT be called.
    key = generate_key()
    store = await MessageStore.open(tmp_path / "msg.db", cipher=make_cipher(key))
    try:

        async def _delegated(*_a: object, **_k: object) -> None:
            raise DbaDelegatedError("server-DB store: DB backup is DBA-delegated")

        store.snapshot_to = _delegated  # type: ignore[method-assign]
        ss = StoreSettings(path=str(tmp_path / "msg.db"), encryption_key=key)
        runner = BackupRunner(
            store,
            BackupSettings(enabled=True, destination=str(tmp_path / "b")),
            store_settings=ss,
            config_dir=None,
        )
        res = await runner.run_once(now=1.0, force_config_only=True)
        assert res is not None and res.config_only  # a config-only archive was produced
        verify = await run_restore_verify(res.archive_path, store_settings=ss)
        assert (
            verify.ok and verify.status == "PASS"
        )  # archive-only contract intact (no live DB checked)
    finally:
        await store.close()
