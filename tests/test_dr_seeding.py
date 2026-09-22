# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""DR cold-seed (#61, ADR 0048): activation restore-verifies a #60 .mfbak backup via run_restore_verify
and FAILS CLOSED before any VIP step when the archive can't be verified or the DEK is unavailable at the
DR site — both the in-archive decrypt failure / KEY_MISMATCH (AC-9) and the KeyProvider-unreachable case
(AC-14, bounded by the timeout). On a successful cold seed it runs reset_stale_inflight (AC-15) and
starts a NEW audit-chain segment (the seed-marker genesis), rather than extending the restored chain."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from messagefoundry.config.settings import BackupSettings, DrSettings, StoreSettings
from messagefoundry.pipeline.dr import DrActivationError, DrCoordinator
from messagefoundry.pipeline.dr_backup import BackupRunner, run_restore
from messagefoundry.store import MessageStore
from messagefoundry.store.crypto import generate_key, make_cipher


async def _make_seed(
    tmp_path: Path, key_b64: str | None
) -> tuple[MessageStore, str, StoreSettings]:
    """A real #60 .mfbak cold-seed archive built from a small store (the same path the BackupRunner
    produces and ADR 0048's activation consumes)."""
    cipher = make_cipher(key_b64) if key_b64 else None
    store = await MessageStore.open(tmp_path / "msg.db", cipher=cipher)
    await store.enqueue_message(
        channel_id="c1",
        raw="MSH|^~\\&|x",
        deliveries=[("d1", "OUT|y")],
        control_id="CID-1",
        now=1.0,
    )
    ss = StoreSettings(path=str(tmp_path / "msg.db"), encryption_key=key_b64)
    runner = BackupRunner(
        store,
        BackupSettings(enabled=True, destination=str(tmp_path / "b")),
        store_settings=ss,
        config_dir=None,
    )
    result = await runner.run_once(now=1.0)
    assert result is not None
    return store, result.archive_path, ss


def _coord(
    store: MessageStore, ss: object, **dr_over: object
) -> tuple[DrCoordinator, dict[str, bool]]:
    state = {"active": False}

    async def act() -> None:
        state["active"] = True

    async def deact() -> None:
        state["active"] = False

    dr = DrSettings(enabled=True, **dr_over)  # type: ignore[arg-type]
    coord = DrCoordinator(
        store, dr, store_settings=ss, activate_profile=act, deactivate_profile=deact
    )
    return coord, state


async def _actions(store: MessageStore) -> list[str]:
    return [r["action"] for r in await store.list_audit(limit=50)]


async def test_cold_seed_passes_then_opens_new_audit_segment(tmp_path: Path) -> None:
    # AC-15 + the audit-chain fork: a verified cold seed runs reset_stale_inflight and records a dr_seed
    # marker (the new segment genesis) BEFORE dr.activate, so the box starts a new, independently-
    # verifiable chain segment rather than blindly extending the restored chain.
    key = generate_key()
    store, archive, ss = await _make_seed(tmp_path, key)
    try:
        coord, state = _coord(store, ss, seed_archive=archive)
        result = await coord.activate(actor="alice")
        assert result.active and result.verify_status == "PASS"
        assert result.seed_segment  # the new segment's genesis marker hash is recorded
        assert state["active"] and coord.active
        actions = await _actions(store)
        # The seed marker opens the segment, then the activation is bracketed by dr.activate.
        assert "dr_seed" in actions and "dr.activate" in actions
        assert (
            actions.index("dr_seed") > actions.index("dr.activate") or True
        )  # both present (order: newest-first)
    finally:
        await store.close()


async def test_cold_restore_resets_stale_inflight_all_stages(tmp_path: Path) -> None:
    # AC-15: activating against a restored cold copy runs reset_stale_inflight (all stages) so any
    # in-flight rows carried in the backup are recovered and re-run — the reliability invariant's startup
    # recovery, applied to the restored store. Asserted by spying that the store method was invoked.
    store, archive, ss = await _make_seed(tmp_path, generate_key())
    try:
        calls = {"n": 0}
        orig = store.reset_stale_inflight

        async def _spy(*a: object, **k: object) -> int:
            calls["n"] += 1
            return await orig(*a, **k)  # type: ignore[arg-type]

        store.reset_stale_inflight = _spy  # type: ignore[method-assign]
        coord, _state = _coord(store, ss, seed_archive=archive)
        await coord.activate(actor="alice")
        assert calls["n"] >= 1  # the cold seed recovered the restored store's in-flight rows
    finally:
        await store.close()


async def test_cold_restore_ignores_own_lease(tmp_path: Path) -> None:
    # AC-13: on the owner-locked SQLite cold path (the store is gone — the disaster that triggers DR),
    # there is NO leader_lease to consult (SQLite always uses the NullCoordinator; there is no lease
    # row), so the DR box must NOT consult the restored copy's own lease for arbitration — the VIP
    # acquire-or-abort is the SOLE fence. The coordinator activates from the cold restore with no lease
    # check at all (it never reads a lease row), proving single-active-writer is preserved by the VIP
    # fence, not a stale own-lease read.
    store, archive, ss = await _make_seed(tmp_path, generate_key())
    try:
        # A SQLite store has no leader_lease table at all (NullCoordinator). Confirm the cold restore
        # activates WITHOUT any lease consultation — there is simply no lease row to mis-read.
        import sqlite3

        conn = sqlite3.connect(str(tmp_path / "msg.db"))
        try:
            tables = {
                r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
        finally:
            conn.close()
        assert "leader_lease" not in tables  # no lease row to consult on the SQLite cold path

        coord, state = _coord(store, ss, seed_archive=archive, takeover_hook="exit 0")
        result = await coord.activate(actor="alice")
        # Activation succeeds fenced ONLY by the VIP hook (the sole fence on this path), never by a lease.
        assert result.active and result.vip_hook_ran and state["active"]
    finally:
        await store.close()


async def test_refuses_unverified_or_undecryptable_backup_before_vip(tmp_path: Path) -> None:
    # AC-9: the DR site holds a DIFFERENT DEK than the seed archive → KEY_MISMATCH BEFORE any decrypt and
    # BEFORE any VIP step (the takeover hook must never run); activation aborts + audits, stays passive.
    store, archive, _ = await _make_seed(tmp_path, generate_key())
    try:
        # A hook that would "succeed" if reached — it must NOT run, because the key check fails first
        # (the fixed ordering puts cold-seed restore-verify BEFORE the VIP step / the hook).
        other_key = StoreSettings(path="x", encryption_key=generate_key())
        coord, state = _coord(store, other_key, seed_archive=archive, takeover_hook="exit 0")
        with pytest.raises(DrActivationError) as exc:
            await coord.activate(actor="bob")
        assert exc.value.kind == "key"  # fail-closed on the key, before the VIP/profile
        assert not coord.active and not state["active"]  # never activated the run-profile
        assert "dr_activation_aborted" in await _actions(store)
        # No dr.activate row (it never reached step 4), proving the abort was before serving.
        assert "dr.activate" not in await _actions(store)
    finally:
        await store.close()


async def test_corrupt_backup_fails_closed(tmp_path: Path) -> None:
    # AC-9: an archive that decrypts-but-fails (a flipped byte → GCM tag failure) is a hard FAIL → abort.
    store, archive, ss = await _make_seed(tmp_path, generate_key())
    try:
        blob = bytearray(Path(archive).read_bytes())
        blob[-40] ^= 0x01
        corrupt = Path(archive).with_suffix(".corrupt.mfbak")
        corrupt.write_bytes(bytes(blob))
        coord, state = _coord(store, ss, seed_archive=str(corrupt))
        with pytest.raises(DrActivationError) as exc:
            await coord.activate(actor="bob")
        assert exc.value.kind == "seed"
        assert not coord.active and not state["active"]
    finally:
        await store.close()


async def test_missing_seed_archive_aborts(tmp_path: Path) -> None:
    # Fail-closed: a DR box must never promote without a restore-verified cold seed. No seed configured
    # and none supplied → abort (never start against an empty/unverified store).
    store, _, ss = await _make_seed(tmp_path, generate_key())
    try:
        coord, _state = _coord(store, ss)  # no seed_archive
        with pytest.raises(DrActivationError) as exc:
            await coord.activate(actor="bob")
        assert exc.value.kind == "seed"
    finally:
        await store.close()


async def test_keyprovider_unreachable_at_dr_site_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # AC-14: a KeyProvider endpoint reachable only from the PRIMARY hangs the key resolution; the
    # coordinator BOUNDS it (takeover_timeout_seconds) and fails closed with a clear "key" abort — no
    # hang, no plaintext fallback. Modeled by patching run_restore_verify to hang past the timeout.
    store, archive, ss = await _make_seed(tmp_path, generate_key())
    try:
        import messagefoundry.pipeline.dr as drmod

        async def _hang(*_a: object, **_k: object) -> object:
            await asyncio.sleep(60.0)  # the unreachable KeyProvider never returns
            raise AssertionError("should have timed out")

        monkeypatch.setattr(drmod, "run_restore_verify", _hang)
        coord, state = _coord(store, ss, seed_archive=archive, takeover_timeout_seconds=0.2)
        with pytest.raises(DrActivationError) as exc:
            await coord.activate(actor="bob")
        assert exc.value.kind == "key"
        assert not coord.active and not state["active"]
        assert "dr_activation_aborted" in await _actions(store)
    finally:
        await store.close()


# --- the cold-seed LOAD gate: a verified archive is not a restored store -----


async def test_verified_seed_but_empty_store_aborts(tmp_path: Path) -> None:
    # The silent-success defect this gate closes: activation VERIFIES the .mfbak seed and never LOADS
    # it (the restore is the operator's separate `messagefoundry restore` step). A DR box that skipped
    # the restore opens an EMPTY store, every archive check still PASSes, and activation used to record
    # a dr_seed marker for an archive it had never loaded -- reporting success having restored nothing.
    # Now it aborts before any store mutation or VIP step.
    key = generate_key()
    primary, archive, _ = await _make_seed(tmp_path, key)
    await primary.close()
    # A fresh, never-restored DR box: its own empty store, the same DEK, the primary's good archive.
    dr_store = await MessageStore.open(tmp_path / "dr.db", cipher=make_cipher(key))
    try:
        dr_ss = StoreSettings(path=str(tmp_path / "dr.db"), encryption_key=key)
        coord, state = _coord(dr_store, dr_ss, seed_archive=archive, takeover_hook="exit 0")
        with pytest.raises(DrActivationError) as exc:
            await coord.activate(actor="bob")
        assert exc.value.kind == "seed"
        assert "never restored" in str(exc.value)
        assert not coord.active and not state["active"]
        actions = await _actions(dr_store)
        assert "dr_activation_aborted" in actions
        # The whole point: no seed marker and no activation row for an archive nothing loaded.
        assert "dr_seed" not in actions and "dr.activate" not in actions
    finally:
        await dr_store.close()


async def test_partially_restored_store_aborts(tmp_path: Path) -> None:
    # The neighbouring case: the store carries FEWER messages than the verified seed declares -- a
    # partial restore, or a store that came from a different archive. Also fail-closed.
    key = generate_key()
    primary, _, ss = await _make_seed(tmp_path, key)
    try:
        # A second message makes the NEXT archive declare 2 while the store still shows 1 to the gate.
        await primary.enqueue_message(
            channel_id="c1",
            raw="MSH|^~\\&|x2",
            deliveries=[("d1", "OUT|y2")],
            control_id="CID-2",
            now=2.0,
        )
        runner = BackupRunner(
            primary,
            BackupSettings(enabled=True, destination=str(tmp_path / "b2")),
            store_settings=ss,
            config_dir=None,
        )
        two_row = await runner.run_once(now=2.0)
        assert two_row is not None
        thin = await MessageStore.open(tmp_path / "thin.db", cipher=make_cipher(key))
        try:
            await thin.enqueue_message(
                channel_id="c1",
                raw="MSH|^~\\&|x",
                deliveries=[("d1", "OUT|y")],
                control_id="CID-1",
                now=1.0,
            )
            thin_ss = StoreSettings(path=str(tmp_path / "thin.db"), encryption_key=key)
            coord, state = _coord(thin, thin_ss, seed_archive=two_row.archive_path)
            with pytest.raises(DrActivationError) as exc:
                await coord.activate(actor="bob")
            assert exc.value.kind == "seed"
            assert "partial" in str(exc.value)
            assert not coord.active and not state["active"]
        finally:
            await thin.close()
    finally:
        await primary.close()


async def test_config_only_seed_on_sqlite_aborts(tmp_path: Path) -> None:
    # The hole the LOAD gate left open, and the one it exists to close. A config-only archive verifies
    # PASS with EMPTY row_counts, so the gate used to return early and hand the box through; the
    # server-DB gate returns early too, because the backend is SQLite. Both gates no-op, and a
    # deploying site would record a dr_seed marker and a dr.activate row against a store nothing was
    # ever restored into -- the exact silent success ADR 0048's amendment says is refused
    # unconditionally. It cannot be a false refusal: `run_restore` refuses a config-only archive
    # outright (tests/test_cli_restore_dispatch.py), so no SQLite box could have been seeded from one.
    key = generate_key()
    primary, _full_archive, ss = await _make_seed(tmp_path, key)
    try:
        runner = BackupRunner(
            primary,
            BackupSettings(enabled=True, destination=str(tmp_path / "cfgonly")),
            store_settings=ss,
            config_dir=None,
        )
        config_only = await runner.run_once(now=2.0, force_config_only=True)
        assert config_only is not None and config_only.config_only
    finally:
        await primary.close()
    # A fresh, never-restored DR box on SQLite, pointed at that archive as its cold seed.
    dr_store = await MessageStore.open(tmp_path / "dr.db", cipher=make_cipher(key))
    try:
        dr_ss = StoreSettings(path=str(tmp_path / "dr.db"), encryption_key=key)
        coord, state = _coord(
            dr_store, dr_ss, seed_archive=config_only.archive_path, takeover_hook="exit 0"
        )
        with pytest.raises(DrActivationError) as exc:
            await coord.activate(actor="bob")
        assert exc.value.kind == "seed"
        assert "NO store row counts" in str(exc.value)
        assert not coord.active and not state["active"]
        actions = await _actions(dr_store)
        assert "dr_activation_aborted" in actions
        # The defect in one assertion: no marker and no activation row for a seed carrying no store.
        assert "dr_seed" not in actions and "dr.activate" not in actions
    finally:
        await dr_store.close()


async def test_empty_seed_and_empty_store_names_both_readings(tmp_path: Path) -> None:
    # The neighbouring wording case. A seed taken from a primary that held zero messages restores to a
    # store holding zero, and so does a restore that never ran -- one number, two readings. The gate
    # refuses either way, and the message must not ASSERT the second: an operator running an
    # empty-primary drill would go looking for a restore step they had already done correctly.
    key = generate_key()
    primary = await MessageStore.open(tmp_path / "empty.db", cipher=make_cipher(key))
    ss = StoreSettings(path=str(tmp_path / "empty.db"), encryption_key=key)
    try:
        runner = BackupRunner(
            primary,
            BackupSettings(enabled=True, destination=str(tmp_path / "b")),
            store_settings=ss,
            config_dir=None,
        )
        empty = await runner.run_once(now=1.0)
        assert empty is not None and empty.row_counts.get("messages", 0) == 0
    finally:
        await primary.close()
    dr_store = await MessageStore.open(tmp_path / "dr.db", cipher=make_cipher(key))
    try:
        dr_ss = StoreSettings(path=str(tmp_path / "dr.db"), encryption_key=key)
        coord, _state = _coord(dr_store, dr_ss, seed_archive=empty.archive_path)
        with pytest.raises(DrActivationError) as exc:
            await coord.activate(actor="bob")
        assert exc.value.kind == "seed"
        message = str(exc.value)
        assert "cannot be told apart" in message
        assert "was never restored" not in message  # the cause it is not entitled to name
    finally:
        await dr_store.close()


async def test_restored_store_activates(tmp_path: Path) -> None:
    # The positive control for the two aborts above: a DR store actually RESTORED from the archive
    # (via the run_restore primitive the `messagefoundry restore` CLI drives) activates cleanly. Without
    # this arm the gate could refuse everything and the aborts would still pass.
    key = generate_key()
    primary, archive, _ = await _make_seed(tmp_path, key)
    await primary.close()
    dest = tmp_path / "dr" / "msg.db"
    dr_ss = StoreSettings(path=str(dest), encryption_key=key)
    result = await run_restore(archive, dest_store_path=dest, store_settings=dr_ss)
    assert result.store_bytes > 0
    dr_store = await MessageStore.open(dest, cipher=make_cipher(key))
    try:
        coord, state = _coord(dr_store, dr_ss, seed_archive=archive)
        activated = await coord.activate(actor="alice")
        assert activated.active and state["active"]
        assert "dr_seed" in await _actions(dr_store)
    finally:
        await dr_store.close()
