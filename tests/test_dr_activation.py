# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""DR activation fencing + mode (#61, ADR 0048). Acquire-VIP-or-abort: an optional takeover_hook that
SUCCEEDS lets activation proceed; one that FAILS (or times out) aborts activation, binds no priority
listener, stays passive, and records a dr_activation_aborted audit row (AC-6). Activation is MANUAL only
— there is no automatic/background trigger (AC-8); auto mode is rejected at config load."""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
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


# --- vault BACKLOG #2622 item 3: a hook that runs past its timeout is killed, with its children ----


def _tree_hook(where: Path, delay: float) -> str:
    """A hook that starts a child of its own and writes ``started`` once both are running. Each
    then writes a marker ``delay`` seconds after its own start, so both markers are due by
    ``started`` + ``delay``. A marker on disk means that process outlived the point where the hook
    was stopped. The hook is shell -> python -> python, so it is a tree on every shell: cmd.exe on
    Windows, /bin/sh elsewhere."""
    script = where / "hook_tree.py"
    script.write_text(
        "import pathlib, subprocess, sys, time\n"
        "here, delay = pathlib.Path(sys.argv[1]), float(sys.argv[2])\n"
        "code = (\n"
        "    'import pathlib, sys, time; here = pathlib.Path(sys.argv[1]);'\n"
        '    \' (here / "grandchild-started").write_text("x");\'\n'
        '    \' time.sleep(float(sys.argv[2])); (here / "grandchild-survived").write_text("x")\'\n'
        ")\n"
        "subprocess.Popen([sys.executable, '-c', code, str(here), str(delay)])\n"
        "deadline = time.monotonic() + 60\n"
        "while not (here / 'grandchild-started').exists() and time.monotonic() < deadline:\n"
        "    time.sleep(0.02)\n"
        "(here / 'started').write_text('x')\n"
        "time.sleep(delay)\n"
        "(here / 'child-survived').write_text('x')\n",
        encoding="utf-8",
    )
    return f'"{sys.executable}" "{script}" "{where}" {delay}'


async def _await_file(path: Path, *, within: float) -> None:
    deadline = time.monotonic() + within
    while not path.exists():
        assert time.monotonic() < deadline, f"{path.name} never appeared"
        await asyncio.sleep(0.05)


def _survivors(where: Path) -> list[str]:
    return sorted(p.name for p in where.glob("*-survived"))


async def test_a_stopped_hook_leaves_no_process_behind(tmp_path: Path) -> None:
    """Stopping the hook stops every process it started.

    ``wait_for`` stops ``_run_command`` by cancelling it, so this cancels it directly once the
    hook's tree is known to be running. RED on the code before #2622, which only awaited the
    shell: both markers appeared after the cancel. The ``started`` file is the control: without
    it, a hook that never ran would also leave no marker."""
    task = asyncio.ensure_future(dr_module._run_command(_tree_hook(tmp_path, 2.0)))
    try:
        await _await_file(tmp_path / "started", within=30.0)
    finally:
        task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    started_at = (tmp_path / "started").stat().st_mtime
    # Wait past the moment each process would have written its marker, plus a margin.
    await asyncio.sleep(max(0.0, started_at + 2.0 + 2.0 - time.time()))
    assert _survivors(tmp_path) == []


async def test_a_stopped_release_hook_is_left_to_finish(tmp_path: Path) -> None:
    """``stop_kills=False``, which the release hook gets, keeps the old behaviour: a stop leaves
    the hook running, since killing a release partway could strand the address. Both markers
    appear. This is also the positive control for the test above: the same hook, not killed,
    does leave survivors."""
    task = asyncio.ensure_future(
        dr_module._run_command(_tree_hook(tmp_path, 1.0), stop_kills=False)
    )
    try:
        await _await_file(tmp_path / "started", within=30.0)
    finally:
        task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await _await_file(tmp_path / "child-survived", within=30.0)
    await _await_file(tmp_path / "grandchild-survived", within=30.0)


def test_the_configuration_page_quotes_the_reap_bound() -> None:
    # docs/CONFIGURATION.md states how long an abort may wait past the timeout for a killed hook.
    page = Path(__file__).resolve().parents[1] / "docs" / "CONFIGURATION.md"
    row = next(
        line
        for line in page.read_text(encoding="utf-8").splitlines()
        if line.startswith("| `takeover_timeout_seconds` |")
    )
    assert f"at most {dr_module._HOOK_REAP_SECONDS:g} more seconds" in row


async def test_a_timed_out_hook_aborts_and_leaves_no_process_behind(tmp_path: Path) -> None:
    """The same, through ``activate``: the timeout records the abort, and the hook is dead by then.

    The budget is above the 3.0s :func:`test_vip_hook_timeout_aborts` explains, because two
    interpreters must start inside it for the control below to hold. The hook's tree writes its
    markers 5.0s after it starts, so it is still running when the 4.0s budget runs out. A slow
    start fails the control; it cannot pass the test with a live tree."""
    store, archive, ss = await _seed(tmp_path)
    where = tmp_path / "hook"
    where.mkdir()
    try:
        coord, state = _coord(
            store,
            ss,
            seed_archive=archive,
            takeover_hook=_tree_hook(where, 5.0),
            takeover_timeout_seconds=4.0,
        )
        with pytest.raises(DrActivationError) as exc:
            await coord.activate(actor="alice")
        assert exc.value.kind == "vip"
        assert "timed out" in str(exc.value)
        assert not coord.active and not state["active"]
        assert "dr_activation_aborted" in await _actions(store)
        # The control: the tree was running before the budget ran out.
        assert (where / "started").exists()
        started_at = (where / "started").stat().st_mtime
        await asyncio.sleep(max(0.0, started_at + 5.0 + 2.0 - time.time()))
        assert _survivors(where) == []
    finally:
        await store.close()


async def test_a_timed_out_release_hook_is_left_to_finish(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Through ``release``: a release hook that runs past the timeout is not killed, and neither is
    anything it started. Killing a release partway could strand the address on this box.

    The tree writes its markers 6.0s after it starts, past the 4.0s budget, so the release has
    timed out before either marker is due. Both markers then appear."""
    store, archive, ss = await _seed(tmp_path)
    where = tmp_path / "hook"
    where.mkdir()
    try:
        coord, state = _coord(
            store,
            ss,
            seed_archive=archive,
            release_hook=_tree_hook(where, 6.0),
            takeover_timeout_seconds=4.0,
        )
        await coord.activate(actor="alice")
        with caplog.at_level("WARNING", logger=dr_module.log.name):
            result = await coord.release(actor="alice")
        assert not result.active and not state["active"]
        assert "VIP release hook timed out" in caplog.text
        assert not (where / "child-survived").exists()  # the release did not wait for the hook
        await _await_file(where / "child-survived", within=30.0)
        await _await_file(where / "grandchild-survived", within=30.0)
    finally:
        await store.close()


def _job_report_hook(report: Path) -> str:
    """A hook that writes, as JSON, whether it is in a Windows job and, if so, that job's limit
    flags and the ids of the processes in it. With no job handle, ``QueryInformationJobObject``
    reads the job the calling process is directly in."""
    script = report.with_suffix(".py")
    script.write_text(
        "import ctypes, json, sys\n"
        "from ctypes import wintypes\n"
        "k = ctypes.WinDLL('kernel32', use_last_error=True)\n"
        "k.GetCurrentProcess.restype = wintypes.HANDLE\n"
        "k.IsProcessInJob.argtypes = [wintypes.HANDLE, wintypes.HANDLE,"
        " ctypes.POINTER(wintypes.BOOL)]\n"
        "k.QueryInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int,"
        " ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p]\n"
        "class Basic(ctypes.Structure):\n"
        "    _fields_ = [('a', ctypes.c_int64), ('b', ctypes.c_int64),"
        " ('LimitFlags', ctypes.c_uint32), ('c', ctypes.c_size_t), ('d', ctypes.c_size_t),"
        " ('e', ctypes.c_uint32), ('f', ctypes.c_size_t), ('g', ctypes.c_uint32),"
        " ('h', ctypes.c_uint32)]\n"
        "class Pids(ctypes.Structure):\n"
        "    _fields_ = [('assigned', wintypes.DWORD), ('listed', wintypes.DWORD),"
        " ('ids', ctypes.c_size_t * 8192)]\n"
        "inside = wintypes.BOOL()\n"
        "assert k.IsProcessInJob(k.GetCurrentProcess(), None, ctypes.byref(inside))\n"
        "out = {'in_job': bool(inside.value)}\n"
        "if inside.value:\n"
        "    basic, pids = Basic(), Pids()\n"
        "    assert k.QueryInformationJobObject(None, 2, ctypes.byref(basic),"
        " ctypes.sizeof(basic), None)\n"
        "    assert k.QueryInformationJobObject(None, 3, ctypes.byref(pids),"
        " ctypes.sizeof(pids), None)\n"
        "    out['flags'] = basic.LimitFlags\n"
        "    out['pids'] = list(pids.ids[: pids.listed])\n"
        "open(sys.argv[1], 'w').write(json.dumps(out))\n",
        encoding="utf-8",
    )
    # Not sys.executable: in a venv on Windows that is a launcher, which runs the real interpreter
    # in a kill-on-close job of the launcher's own. The script would then report that job, on
    # either side. The script needs only the standard library, so the base interpreter runs it.
    python = getattr(sys, "_base_executable", sys.executable)
    return f'"{python}" "{script}" "{report}"'


@pytest.mark.skipif(sys.platform != "win32", reason="Windows job objects")
async def test_only_the_takeover_hook_joins_a_kill_on_close_job(tmp_path: Path) -> None:
    """On Windows the takeover hook runs in a kill-on-close job of its own, so the engine can end
    its tree. The release hook does not: a kill-on-close job also ends its processes when the
    engine exits, which could stop a release partway (vault BACKLOG #2622).

    The release hook must share the engine's own situation: in no job if the engine is in none,
    else in the engine's own job. A job of its own would hold the hook's processes and not the
    engine's, which is what the takeover side asserts."""
    store, archive, ss = await _seed(tmp_path)
    try:
        coord, _state = _coord(
            store,
            ss,
            seed_archive=archive,
            takeover_hook=_job_report_hook(tmp_path / "takeover.json"),
            release_hook=_job_report_hook(tmp_path / "release.json"),
        )
        await coord.activate(actor="alice")
        await coord.release(actor="alice")
        takeover = json.loads((tmp_path / "takeover.json").read_text(encoding="utf-8"))
        release = json.loads((tmp_path / "release.json").read_text(encoding="utf-8"))
        kill_on_close = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        assert takeover["in_job"]
        assert takeover["flags"] & kill_on_close
        assert os.getpid() not in takeover["pids"]
        assert not release["in_job"] or os.getpid() in release["pids"], release
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
        # Its own message: the operator's directory failed, so the remedy is not "set seed_dir".
        assert "could not be resolved" in str(exc.value)
        assert Path(archive).name not in str(exc.value)
        assert not coord.active
        assert (await _actions(store)).count("dr_activation_aborted") == 1
    finally:
        await store.close()


async def test_a_seed_dir_that_does_not_answer_in_time_is_an_audited_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The same abort when the resolve hangs past takeover_timeout_seconds. RED if the bound is
    # dropped (the call then returns late and activation carries on) or if the timeout escapes.
    store, archive, ss = await _seed(tmp_path)

    def slow(_archive: str, _seed_dir: str) -> Path | None:
        time.sleep(0.5)
        return Path(archive)

    try:
        coord, _state = _coord(
            store, ss, seed_dir=str(Path(archive).parent), takeover_timeout_seconds=0.05
        )
        monkeypatch.setattr(dr_module, "_confined_archive", slow)
        with pytest.raises(DrActivationError) as exc:
            await coord.activate(archive=archive, actor="alice")
        assert exc.value.kind == "seed"
        assert "could not be resolved" in str(exc.value)
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
