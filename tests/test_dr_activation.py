# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""DR activation fencing + mode (#61, ADR 0048). Acquire-VIP-or-abort: an optional takeover_hook that
SUCCEEDS lets activation proceed; one that FAILS (or times out) aborts activation, binds no priority
listener, stays passive, and records a dr_activation_aborted audit row (AC-6). Activation is MANUAL only
— there is no automatic/background trigger (AC-8); auto mode is rejected at config load."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from messagefoundry.config.settings import (
    BackupSettings,
    DrActivationMode,
    DrSettings,
    StoreSettings,
)
from messagefoundry.pipeline.dr import DrActivationError, DrCoordinator
from messagefoundry.pipeline.dr_backup import BackupRunner
from messagefoundry.store import MessageStore
from messagefoundry.store.crypto import generate_key, make_cipher

# A trivially-succeeding / trivially-failing shell command that works on the runner's shell (Git Bash on
# the dev box, /bin/sh on CI, cmd on a bare Windows box). `exit N` is portable across all of them.
_OK_HOOK = "exit 0"
_FAIL_HOOK = "exit 7"


async def _seed(tmp_path: Path) -> tuple[MessageStore, str, StoreSettings]:
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


async def test_acquire_vip_hook_success_activates(tmp_path: Path) -> None:
    # AC-6 happy path: a takeover_hook that exits 0 = "VIP acquired" → activation proceeds + serves.
    store, archive, ss = await _seed(tmp_path)
    try:
        coord, state = _coord(store, ss, seed_archive=archive, takeover_hook=_OK_HOOK)
        result = await coord.activate(actor="alice")
        assert result.active and result.vip_hook_ran
        assert state["active"] and coord.active
        assert "dr.activate" in await _actions(store)
    finally:
        await store.close()


async def test_acquire_vip_or_abort_records_audit(tmp_path: Path) -> None:
    # AC-6: a takeover_hook that FAILS (non-zero) = "VIP not acquired" → abort, no priority listener
    # bound (the run-profile never activated), stays passive, records dr_activation_aborted.
    store, archive, ss = await _seed(tmp_path)
    try:
        coord, state = _coord(store, ss, seed_archive=archive, takeover_hook=_FAIL_HOOK)
        with pytest.raises(DrActivationError) as exc:
            await coord.activate(actor="alice")
        assert exc.value.kind == "vip"
        assert not coord.active and not state["active"]  # never served the VIP
        actions = await _actions(store)
        assert "dr_activation_aborted" in actions
        assert "dr.activate" not in actions  # never reached the serve step
    finally:
        await store.close()


async def test_vip_hook_timeout_aborts(tmp_path: Path) -> None:
    # A hook that exceeds takeover_timeout_seconds = "not acquired" → abort (no hang).
    store, archive, ss = await _seed(tmp_path)
    try:
        # A portable "sleep a while": python is always present in this environment.
        slow = f'"{sys.executable}" -c "import time; time.sleep(30)"'
        coord, state = _coord(
            store, ss, seed_archive=archive, takeover_hook=slow, takeover_timeout_seconds=0.3
        )
        with pytest.raises(DrActivationError) as exc:
            await coord.activate(actor="alice")
        assert exc.value.kind == "vip"
        assert not coord.active and not state["active"]
    finally:
        await store.close()


async def test_no_hook_relies_on_passive_lb(tmp_path: Path) -> None:
    # With no takeover_hook (the ADR-0047 LB topology — the passive LB is the fence), activation proceeds
    # and binds the priority listeners (the LB then moves the VIP). vip_hook_ran is False.
    store, archive, ss = await _seed(tmp_path)
    try:
        coord, state = _coord(store, ss, seed_archive=archive)  # no hook
        result = await coord.activate(actor="alice")
        assert result.active and not result.vip_hook_ran
        assert state["active"]
    finally:
        await store.close()


async def test_manual_only_activation(tmp_path: Path) -> None:
    # AC-8: manual is the default and the only built mode; the coordinator activates ONLY on the explicit
    # activate() call (the RBAC-gated POST /dr/activate). There is no background/auto trigger — a freshly
    # constructed coordinator (activate=false) is NOT active until activate() is invoked.
    store, archive, ss = await _seed(tmp_path)
    try:
        coord, state = _coord(store, ss, seed_archive=archive)
        assert DrSettings().activation_mode is DrActivationMode.MANUAL  # default + only mode
        assert not coord.active and not state["active"]  # nothing auto-activated it
        await coord.activate(actor="alice")  # the ONLY way it becomes active
        assert coord.active
    finally:
        await store.close()


async def test_activate_idempotent_when_already_active(tmp_path: Path) -> None:
    # A second activate() on an already-serving box is a no-op report (it does NOT re-run the cold seed).
    store, archive, ss = await _seed(tmp_path)
    try:
        coord, _state = _coord(store, ss, seed_archive=archive)
        await coord.activate(actor="alice")
        before = len(await store.list_audit(limit=100))
        r2 = await coord.activate(actor="alice")  # idempotent
        after = len(await store.list_audit(limit=100))
        assert r2.active and after == before  # no new dr_seed / dr.activate rows
    finally:
        await store.close()


async def test_activate_on_non_dr_box_refused(tmp_path: Path) -> None:
    # A box where [dr].enabled is false is not a DR standby — activation is refused (not a silent no-op).
    store, archive, ss = await _seed(tmp_path)
    try:
        coord = DrCoordinator(
            store,
            DrSettings(enabled=False, seed_archive=archive),
            store_settings=ss,
            activate_profile=_noop,
            deactivate_profile=_noop,
        )
        with pytest.raises(DrActivationError) as exc:
            await coord.activate(actor="alice")
        assert exc.value.kind == "state"
    finally:
        await store.close()


async def _noop() -> None:
    return None
