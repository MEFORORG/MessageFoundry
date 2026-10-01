# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""DR activation fencing + mode (#61, ADR 0048). Acquire-VIP-or-abort: an optional takeover_hook that
SUCCEEDS lets activation proceed; one that FAILS (or times out) aborts activation, binds no priority
listener, stays passive, and records a dr_activation_aborted audit row (AC-6). Activation is MANUAL only
— there is no automatic/background trigger (AC-8); auto mode is rejected at config load."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from messagefoundry.config.settings import (
    BackupSettings,
    DrActivationMode,
    DrSettings,
    StoreSettings,
)
from messagefoundry.pipeline import dr as dr_module
from messagefoundry.pipeline.dr import DrActivationError, DrCoordinator
from messagefoundry.pipeline.dr_backup import BackupRunner, VerifyResult, run_restore_verify
from messagefoundry.store import MessageStore
from messagefoundry.store.crypto import generate_key, make_cipher
from tests import _fs_spy

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
    #
    # THE BUDGET IS 3.0s AND NOT 0.3s, AND THAT IS THE WHOLE POINT OF THIS COMMENT.
    # `takeover_timeout_seconds` bounds TWO things, not one: the VIP takeover hook this test is
    # about, and -- earlier in `activate()` -- the cold-seed restore-verify. At 0.3s the second one
    # lost the race intermittently and aborted with kind="key" ("the cold-seed key could not be
    # resolved within 0.3s", ADR 0048 AC-14), so the test failed asserting "vip" against a real
    # timeout of the WRONG step. It reads as a key-resolution defect and is not one.
    #
    # MEASURED before this change: it reds `main`, not just a feature branch -- run 33570805647 at
    # adf8d5905 on 2026-09-01, same assertion, same abort message. Across the 120 most recent CI
    # runs, 2 of the 5 failures of the `test (windows-2022, py3.14)` leg were this one test.
    # Restore-verify decrypts a ~370 KB archive, opens the tar twice and runs a sqlite
    # integrity_check plus two COUNT(*)s -- inside 300 ms, on a 4-vCPU Windows runner under
    # `pytest -n 4`. The median sits close enough to the budget that contention crosses it.
    #
    # 3.0s KEEPS THE TEST HONEST. The hook sleeps 30s, so it still exceeds the budget by 10x and
    # the VIP abort is still what this asserts; only the unrelated step stops being marginal.
    # Every other test in this file uses the 30.0s default (config/settings.py), which is why this
    # one was the only one exposed.
    store, archive, ss = await _seed(tmp_path)
    try:
        # A portable "sleep a while": python is always present in this environment.
        slow = f'"{sys.executable}" -c "import time; time.sleep(30)"'
        coord, state = _coord(
            store, ss, seed_archive=archive, takeover_hook=slow, takeover_timeout_seconds=3.0
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


# --- vault BACKLOG #2581: an archive named in the request is confined to [dr].seed_dir ----------


async def test_a_request_archive_outside_seed_dir_is_refused_untouched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A request may name only an archive under ``[dr].seed_dir``, judged from the text of the path
    before any filesystem call on it.

    RED when ``activate`` hands a request path to the restore-verify unconfined: the spy records
    calls naming the refused path. The control is the last block: the archive inside ``seed_dir``
    still activates through the same argument, and the spy records calls naming it.

    That block also pins WHICH path the restore-verify opens: the resolved one, so the file that
    was checked is the file that is read, however the request spelled it.
    """
    store, archive, ss = await _seed(tmp_path)
    seed_dir = Path(archive).parent
    refused = [
        str(tmp_path / "probe-outside" / "seed.mfbak"),
        str(Path(str(seed_dir) + "-probe-sibling") / "seed.mfbak"),
        str(seed_dir / ".." / "probe-climb.mfbak"),
        *_fs_spy.NON_LOCAL_SHAPES,
    ]
    try:
        coord, state = _coord(store, ss, seed_dir=str(seed_dir))
        calls = _fs_spy.install(monkeypatch)
        messages = set()
        for path in refused:
            with pytest.raises(DrActivationError) as exc:
                await coord.activate(archive=path, actor="alice")
            assert exc.value.kind == "seed", path
            messages.add(str(exc.value))
        # One generic answer, naming no part of any path, so the refusal cannot probe the filesystem.
        assert len(messages) == 1
        assert "probe" not in messages.pop()
        assert _fs_spy.naming(calls, "probe") == []
        assert not coord.active and not state["active"]
        # The audit row alone carries what was asked for, so the refusals can be told apart later.
        aborted = await store.list_audit(action="dr_activation_aborted")
        assert sorted(json.loads(a["detail"])["requested"] for a in aborted) == sorted(refused)

        verified: list[str] = []

        async def recording_verify(path: str, *, store_settings: object) -> VerifyResult:
            verified.append(path)
            return await run_restore_verify(path, store_settings=store_settings)

        monkeypatch.setattr(dr_module, "run_restore_verify", recording_verify)
        name = Path(archive).name
        roundabout = os.path.join(str(seed_dir), "..", seed_dir.name, name)
        result = await coord.activate(archive=roundabout, actor="alice")
        assert result.active and result.archive == name
        assert verified == [str(Path(archive).resolve())]
        assert _fs_spy.naming(calls, name)
    finally:
        await store.close()


async def test_a_request_archive_is_refused_while_no_seed_dir_is_configured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Deny by default: with no [dr].seed_dir there is nowhere a request may point, so even a good
    # archive is refused untouched. The control is the same archive named in [dr].seed_archive,
    # which is operator configuration and is not confined.
    store, archive, ss = await _seed(tmp_path)
    name = Path(archive).name
    try:
        coord, _state = _coord(store, ss)
        calls = _fs_spy.install(monkeypatch)
        with pytest.raises(DrActivationError) as exc:
            await coord.activate(archive=archive, actor="alice")
        assert exc.value.kind == "seed"
        assert name not in str(exc.value)
        assert _fs_spy.naming(calls, name) == []
        assert not coord.active

        configured, _state = _coord(store, ss, seed_archive=archive)
        assert (await configured.activate(actor="alice")).active
        assert _fs_spy.naming(calls, name)
    finally:
        await store.close()


async def test_a_seed_dir_that_cannot_be_resolved_is_an_audited_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # An unreachable seed_dir (a share that is down during the failover, say) makes the resolve
    # raise. That must leave through the one abort path, with its audit row, like any refusal.
    store, archive, ss = await _seed(tmp_path)

    def unreachable(_archive: str, _seed_dir: str) -> Path | None:
        raise OSError("the network location cannot be reached")

    try:
        coord, _state = _coord(store, ss, seed_dir=str(Path(archive).parent))
        monkeypatch.setattr(dr_module, "_confined_archive", unreachable)
        with pytest.raises(DrActivationError) as exc:
            await coord.activate(archive=archive, actor="alice")
        assert exc.value.kind == "seed"
        assert not coord.active
        assert (await _actions(store)).count("dr_activation_aborted") == 1
    finally:
        await store.close()


async def test_a_link_inside_seed_dir_that_leaves_it_is_refused(tmp_path: Path) -> None:
    # The second line: the text check passes a path under seed_dir, and only the resolve can see
    # that a link there points outside it.
    store, archive, ss = await _seed(tmp_path)
    seed_dir = tmp_path / "seeds"
    seed_dir.mkdir()
    link = seed_dir / "linked.mfbak"
    try:
        try:
            link.symlink_to(archive)
        except OSError:
            pytest.skip("this account cannot create a symbolic link")
        coord, _state = _coord(store, ss, seed_dir=str(seed_dir))
        with pytest.raises(DrActivationError) as exc:
            await coord.activate(archive=str(link), actor="alice")
        assert exc.value.kind == "seed"
        assert not coord.active
    finally:
        await store.close()
