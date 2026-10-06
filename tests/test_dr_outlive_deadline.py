# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""DR activate and DR release outlive the request deadline, and roll back on cancellation (vault
BACKLOG #2751 finding D-1b, #2752 findings D-1a and D-V1).

The request deadline (``RequestTimeoutMiddleware``, 120 s by default) used to cancel the handler
task, and a cancellation is not an ``Exception``. A release cut off in its drain left both active
flags set, intake unbound and no ``dr.release`` row. An activation cut off at or after step 4 left
the coordinator latched active, and the retry answered success from the idempotent branch with no
``dr.activate`` row. The routes now run each operation so that cancelling the caller does not cancel
it (``api/outlive.py``), and the coordinator's own cancellation arms restore state and record an
interrupted outcome for what can still cancel one, such as a shutdown.

The HTTP tests patch the deadline down to a fraction of a second rather than wait 120 s; the
mechanism under test is the cancellation, not the number. No test here measures how long a real
activation takes on a restored store.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path
from typing import Any

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.api.request_timeout import DEFAULT_REQUEST_TIMEOUT_SECONDS
from messagefoundry.auth import Role
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.service import AuthService
from messagefoundry.config.models import ConnectorType, Priority
from messagefoundry.config.settings import (
    AuthSettings,
    BackupSettings,
    DrSettings,
    EgressSettings,
    StoreSettings,
)
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.pipeline import Engine
from messagefoundry.pipeline import engine as engine_module
from messagefoundry.pipeline.dr import DrActivationError, DrCoordinator
from messagefoundry.pipeline.dr_backup import BackupRunner
from messagefoundry.store import MessageStore, Store
from messagefoundry.store.crypto import generate_key, make_cipher
from tests._admin_account import create_local_user_chosen

PW = "Sup3rSecret!!DR-outlive"
#: Synthetic, never real PHI (CLAUDE.md section 9).
_ADT = "MSH|^~\\&|S|F|R|RF|20260604||ADT^A01|LOW1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"
_OK_HOOK = "exit 0"


async def _wait(predicate: Callable[[], Awaitable[bool]], timeout: float = 10.0) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while not await predicate():
        if asyncio.get_running_loop().time() > deadline:
            raise AssertionError("condition not met within timeout")
        await asyncio.sleep(0.02)


async def _rows(store: Store, action: str) -> list[dict[str, Any]]:
    return [
        json.loads(r["detail"]) for r in await store.list_audit(limit=200) if r["action"] == action
    ]


async def _seed(tmp_path: Path) -> tuple[MessageStore, str, StoreSettings]:
    """An encrypted store with one queued outbound row for a destination no graph here declares,
    and a cold-seed backup of it -- the shape test_dr_failback.py seeds. The row never drains."""
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


def _graph(tmp_path: Path) -> Registry:
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    reg = Registry()
    reg.add_outbound(
        OutboundConnection(
            "file_out",
            ConnectionSpec(
                ConnectorType.FILE, {"directory": str(outdir), "filename": "{MSH-10}.hl7"}
            ),
            priority=Priority.CRITICAL,
        )
    )
    # Start-disabled, so its lane is parked: a row routed to it waits in the outbound stage and
    # never drains, the shape of a row for a parked outbound on a DR box (vault BACKLOG #2752).
    reg.add_outbound(
        OutboundConnection(
            "parked_out",
            ConnectionSpec(
                ConnectorType.FILE, {"directory": str(outdir), "filename": "{MSH-10}.parked"}
            ),
            priority=Priority.CRITICAL,
            auto_start=False,
        )
    )
    reg.add_inbound(
        InboundConnection(
            "file_in",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.02},
            ),
            router="r",
            priority=Priority.CRITICAL,
        )
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("file_out", m))
    return reg


@pytest.fixture
async def seeded(tmp_path: Path) -> AsyncIterator[tuple[Engine, str]]:
    """A started DR engine over the seeded store, running a small graph, not yet activated."""
    store, archive, ss = await _seed(tmp_path)
    eng = Engine(
        store,
        poll_interval=0.02,
        config_dir=None,
        store_settings=ss,
        dr_settings=DrSettings(
            enabled=True,
            activate=False,
            seed_archive=archive,
            takeover_hook=_OK_HOOK,
            priority_threshold=Priority.CRITICAL,
        ),
        egress_settings=EgressSettings(deny_by_default=False),
    )
    eng.add_registry(_graph(tmp_path))
    await eng.start()
    yield eng, archive
    await eng.stop()


async def _admin_client(
    engine: Engine, deadline: float, *, provision: bool = True
) -> tuple[httpx.AsyncClient, Any]:
    """A signed-in administrator client. The deadline is set AFTER the login, whose password hash
    alone takes longer than the fractions of a second these tests use."""
    service = AuthService(
        engine.store, AuthSettings(require_mfa=False, admin_write_min_interval_seconds=0)
    )
    await service.initialize()
    if provision:
        user_id = await create_local_user_chosen(
            service,
            username="dradmin",
            password=PW,
            display_name=None,
            email=None,
            roles=[Role.ADMINISTRATOR.value],
            actor="test",
        )
        await service.set_channel_scope(user_id, [ALL_CHANNELS], actor="test")
        user = await service.store.get_user(user_id)
        assert user is not None and user.password_hash is not None
        await service.store.set_password(
            user_id,
            password_hash=user.password_hash,
            must_change_password=False,
            password_generated=False,
        )
    app = create_app(engine, auth=service)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as login:
        r = await login.post(
            "/auth/login", json={"username": "dradmin", "password": PW, "provider": "local"}
        )
    assert r.status_code == 200, r.text
    app.state.request_timeout_seconds = deadline
    client = httpx.AsyncClient(
        transport=transport,
        base_url="http://t",
        headers={"Authorization": f"Bearer {r.json()['token']}"},
    )
    return client, app


def _coordinator(engine: Engine) -> DrCoordinator:
    coord = engine.dr_coordinator
    assert coord is not None
    return coord


async def _activate_directly(engine: Engine) -> int:
    """Promote the box through the coordinator, so a release test starts from a real activation,
    then queue one row for the parked outbound. Returns the staged depth, which cannot drain."""
    result = await _coordinator(engine).activate(actor="dradmin")
    assert result.active and engine.dr_active
    await engine.store.enqueue_message(
        channel_id="file_in",
        raw=_ADT,
        deliveries=[("parked_out", _ADT)],
        control_id="LOW1",
        now=2.0,
    )
    depth = await engine.store.in_pipeline_depth()
    assert depth >= 1
    return depth


# --- D-1a and D-V1: release through the HTTP stack, with a row that does not drain ------------------


def test_the_release_drain_bound_leaves_room_inside_the_request_deadline() -> None:
    # The release hook (bounded by takeover_timeout_seconds) and the drain both run inside the one
    # request. With the defaults, both together must finish before the deadline, so the operator
    # who asked is the one told how the release ended (vault BACKLOG #2752 closing step 2).
    hook_bound = DrSettings().takeover_timeout_seconds
    drain_bound = engine_module.DR_RELEASE_DRAIN_TIMEOUT_SECONDS
    assert hook_bound + drain_bound < DEFAULT_REQUEST_TIMEOUT_SECONDS


async def test_a_release_cut_off_by_the_deadline_still_hands_back_and_records_the_depth_left(
    seeded: tuple[Engine, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, _archive = seeded
    depth = await _activate_directly(engine)
    rr = engine.registry_runner
    assert rr is not None

    # The drain gives up after 1.0 s; the request deadline fires at 0.3 s, well inside it -- the
    # shape the 120 s pair had, where any non-draining row meant the deadline fired first.
    monkeypatch.setattr(engine_module, "DR_RELEASE_DRAIN_TIMEOUT_SECONDS", 1.0)
    client, app = await _admin_client(engine, deadline=0.3)
    async with client:
        r = await client.post("/dr/release")
        assert r.status_code == 503
        assert "timed out" in r.json()["detail"]

        # The release goes on without its caller and completes the hand-back.
        coord = _coordinator(engine)

        async def released() -> bool:
            return not coord.active and not app.state.outliving_operations.inflight

        await _wait(released)

    assert engine.dr_active is False
    assert not rr.inbound_running("file_in")
    rows = await _rows(engine.store, "dr.release")
    assert len(rows) == 1
    # D-V1: the row records the drain's real result, not a hard-coded "drained": true.
    assert rows[0]["drained"] is False
    assert rows[0]["depth_left"] == depth
    assert await _rows(engine.store, "dr_release_failed") == []

    # A retry is answered by the outcome, and runs no second hand-back.
    client, _app = await _admin_client(engine, deadline=30.0, provision=False)
    async with client:
        r = await client.post("/dr/release")
        assert r.status_code == 200 and r.json()["active"] is False
    assert len(await _rows(engine.store, "dr.release")) == 1


async def test_a_release_whose_drain_gives_up_inside_the_deadline_answers_with_the_depth_left(
    seeded: tuple[Engine, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # The control for the test above: the drain bound inside the deadline, so the caller gets the
    # real answer, and that answer does not claim a drain that did not happen.
    engine, _archive = seeded
    depth = await _activate_directly(engine)
    monkeypatch.setattr(engine_module, "DR_RELEASE_DRAIN_TIMEOUT_SECONDS", 0.3)
    client, _app = await _admin_client(engine, deadline=30.0)
    async with client:
        r = await client.post("/dr/release")
    assert r.status_code == 200
    body = r.json()
    assert body["active"] is False and body["depth_left"] == depth
    rows = await _rows(engine.store, "dr.release")
    assert rows == [{"depth_left": depth, "drained": False, "vip_hook_ran": False}]


async def test_a_release_cancelled_in_its_drain_stays_active_and_records_why(
    seeded: tuple[Engine, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # What still CAN cancel a release, such as a shutdown, reaches the coordinator's own arm: the
    # box stays active (as for a failed drain) and a dr_release_failed row names the phase.
    engine, _archive = seeded
    await _activate_directly(engine)
    monkeypatch.setattr(engine_module, "DR_RELEASE_DRAIN_TIMEOUT_SECONDS", 30.0)
    coord = _coordinator(engine)
    task = asyncio.create_task(coord.release(actor="dradmin"))
    rr = engine.registry_runner
    assert rr is not None

    async def draining() -> bool:
        return not rr.inbound_running("file_in")

    await _wait(draining)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert coord.active and engine.dr_active  # never flipped to passive mid-drain
    assert await _rows(engine.store, "dr.release") == []
    failed = await _rows(engine.store, "dr_release_failed")
    assert len(failed) == 1
    assert failed[0]["reason"] == "interrupted" and failed[0]["phase"] == "drain"


# --- D-1b: activation ----------------------------------------------------------------------------


async def test_an_activation_cut_off_by_the_deadline_completes_and_a_retry_reads_its_outcome(
    seeded: tuple[Engine, str],
) -> None:
    engine, _archive = seeded
    coord = _coordinator(engine)
    real_profile = coord._activate_profile

    async def slow_profile() -> None:
        await asyncio.sleep(0.6)  # outlasts the 0.2 s deadline below
        await real_profile()

    coord._activate_profile = slow_profile
    client, app = await _admin_client(engine, deadline=0.2)
    async with client:
        r = await client.post("/dr/activate", json={})
        assert r.status_code == 503
        assert "timed out" in r.json()["detail"]

        async def settled() -> bool:
            return not app.state.outliving_operations.inflight

        await _wait(settled)
        assert coord.active and engine.dr_active
        rows = await _rows(engine.store, "dr.activate")
        assert len(rows) == 1 and "recorded_late" not in rows[0]

        # The retry is answered from the idempotent branch, and that answer is now true.
        r = await client.post("/dr/activate", json={})
        assert r.status_code == 200 and r.json()["active"] is True
    assert len(await _rows(engine.store, "dr.activate")) == 1


async def test_an_activation_cancelled_in_step_4_rolls_back_and_the_retry_activates_for_real(
    seeded: tuple[Engine, str],
) -> None:
    engine, _archive = seeded
    coord = _coordinator(engine)
    entered = asyncio.Event()
    real_profile = coord._activate_profile

    async def hung_profile() -> None:
        entered.set()
        await asyncio.Event().wait()

    coord._activate_profile = hung_profile
    task = asyncio.create_task(coord.activate(actor="dradmin"))
    await asyncio.wait_for(entered.wait(), 10)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    # Before the fix the flag stayed True here, and the retry took the idempotent branch.
    assert coord.active is False
    assert await _rows(engine.store, "dr.activate") == []
    aborted = await _rows(engine.store, "dr_activation_aborted")
    assert len(aborted) == 1 and aborted[0]["kind"] == "interrupted"
    assert "profile step" in aborted[0]["reason"] and "VIP may have moved" in aborted[0]["reason"]

    coord._activate_profile = real_profile
    result = await coord.activate(actor="dradmin")
    assert result.active and result.archive is not None  # a real activation, not the shortcut
    assert len(await _rows(engine.store, "dr.activate")) == 1


async def test_the_engine_puts_its_dr_latch_back_when_the_profile_reload_is_cancelled(
    seeded: tuple[Engine, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, _archive = seeded
    rr = engine.registry_runner
    assert rr is not None
    entered = asyncio.Event()

    async def hung_reload(_registry: Registry) -> None:
        entered.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(rr, "reload", hung_reload)
    task = asyncio.create_task(engine._dr_activate_profile())
    await asyncio.wait_for(entered.wait(), 10)
    assert engine.dr_active is True  # latched before the reload
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert engine.dr_active is False


async def test_an_activation_whose_row_was_not_written_is_recorded_by_the_retry(
    seeded: tuple[Engine, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # Ledger closing step 4: the idempotent branch does not answer success unless a dr.activate row
    # exists for this activation. The first write fails; the retry writes it, marked late.
    engine, _archive = seeded
    coord = _coordinator(engine)
    store = engine.store
    real_record = store.record_audit
    failures = {"left": 2}

    async def flaky_record(action: str, *args: Any, **kwargs: Any) -> Any:
        if action == "dr.activate" and failures["left"]:
            failures["left"] -= 1
            raise OSError("the audit log refused the write")
        return await real_record(action, *args, **kwargs)

    monkeypatch.setattr(store, "record_audit", flaky_record)
    with pytest.raises(DrActivationError):
        await coord.activate(actor="dradmin")
    assert coord.active  # the run-profile IS applied; only the row is missing

    # The retry cannot write it either, so it refuses rather than answering success.
    with pytest.raises(DrActivationError) as exc:
        await coord.activate(actor="dradmin")
    assert exc.value.kind == "audit"

    result = await coord.activate(actor="dradmin")
    assert result.active
    rows = await _rows(store, "dr.activate")
    assert len(rows) == 1 and rows[0]["recorded_late"] is True
    assert rows[0]["archive"].endswith(".mfbak")


async def test_an_activation_cancelled_while_writing_its_row_writes_it_late(
    seeded: tuple[Engine, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, _archive = seeded
    coord = _coordinator(engine)
    store = engine.store
    real_record = store.record_audit
    entered = asyncio.Event()
    hang = {"once": True}

    async def hanging_record(action: str, *args: Any, **kwargs: Any) -> Any:
        if action == "dr.activate" and hang["once"]:
            hang["once"] = False
            entered.set()
            await asyncio.Event().wait()
        return await real_record(action, *args, **kwargs)

    monkeypatch.setattr(store, "record_audit", hanging_record)
    task = asyncio.create_task(coord.activate(actor="dradmin"))
    await asyncio.wait_for(entered.wait(), 10)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert coord.active and engine.dr_active  # the profile applied, so the box IS active
    rows = await _rows(store, "dr.activate")
    assert len(rows) == 1 and rows[0]["recorded_late"] is True


async def test_an_activation_cancelled_before_the_vip_step_aborts_without_the_warning(
    seeded: tuple[Engine, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, _archive = seeded
    coord = _coordinator(engine)
    entered = asyncio.Event()

    async def hung_reset(*_args: Any, **_kwargs: Any) -> None:
        entered.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(engine.store, "reset_stale_inflight", hung_reset)
    task = asyncio.create_task(coord.activate(actor="dradmin"))
    await asyncio.wait_for(entered.wait(), 10)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert coord.active is False
    aborted = await _rows(engine.store, "dr_activation_aborted")
    assert len(aborted) == 1 and aborted[0]["kind"] == "interrupted"
    assert "store step" in aborted[0]["reason"]
    assert "VIP may have moved" not in aborted[0]["reason"]


async def test_a_release_records_an_activation_still_owed_its_row_before_handing_back(
    seeded: tuple[Engine, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # An owed dr.activate row is never lost to a release that follows it.
    engine, _archive = seeded
    coord = _coordinator(engine)
    store = engine.store
    real_record = store.record_audit
    failures = {"left": 1}

    async def flaky_record(action: str, *args: Any, **kwargs: Any) -> Any:
        if action == "dr.activate" and failures["left"]:
            failures["left"] -= 1
            raise OSError("the audit log refused the write")
        return await real_record(action, *args, **kwargs)

    monkeypatch.setattr(store, "record_audit", flaky_record)
    with pytest.raises(DrActivationError):
        await coord.activate(actor="dradmin")
    assert coord.active

    await coord.release(actor="dradmin")
    rows = await store.list_audit(limit=200)
    seqs = {r["action"]: r["seq"] for r in rows}
    assert seqs["dr.activate"] < seqs["dr.release"]
    assert (await _rows(store, "dr.activate"))[0]["recorded_late"] is True


async def test_a_release_whose_row_was_not_written_is_recorded_by_the_retry(
    seeded: tuple[Engine, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, _archive = seeded
    await _activate_directly(engine)
    monkeypatch.setattr(engine_module, "DR_RELEASE_DRAIN_TIMEOUT_SECONDS", 0.2)
    coord = _coordinator(engine)
    store = engine.store
    real_record = store.record_audit
    failures = {"left": 1}

    async def flaky_record(action: str, *args: Any, **kwargs: Any) -> Any:
        if action == "dr.release" and failures["left"]:
            failures["left"] -= 1
            raise OSError("the audit log refused the write")
        return await real_record(action, *args, **kwargs)

    monkeypatch.setattr(store, "record_audit", flaky_record)
    with pytest.raises(DrActivationError) as refused:
        await coord.release(actor="dradmin")
    assert refused.value.kind == "audit"
    assert not coord.active  # the hand-back happened; only its row is missing

    result = await coord.release(actor="dradmin")
    assert result.active is False and result.depth_left is not None  # the first call's outcome
    rows = await _rows(store, "dr.release")
    assert len(rows) == 1 and rows[0]["recorded_late"] is True and rows[0]["drained"] is False


async def test_a_release_cancelled_in_its_hook_says_the_hook_may_still_move_the_vip(
    seeded: tuple[Engine, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, _archive = seeded
    await _activate_directly(engine)
    coord = _coordinator(engine)
    entered = asyncio.Event()

    async def hung_hook(*_args: Any, **_kwargs: Any) -> bool:
        entered.set()
        await asyncio.Event().wait()
        return True

    monkeypatch.setattr(coord, "_run_vip_hook", hung_hook)
    # A configured release hook, which the stub above stands in for.
    monkeypatch.setattr(
        coord, "_settings", coord.settings.model_copy(update={"release_hook": "exit 0"})
    )
    task = asyncio.create_task(coord.release(actor="dradmin"))
    await asyncio.wait_for(entered.wait(), 10)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert coord.active
    failed = await _rows(engine.store, "dr_release_failed")
    assert len(failed) == 1
    assert failed[0]["phase"] == "release_hook" and failed[0]["hook_left_running"] is True


async def test_a_release_cancelled_while_recording_a_failed_drain_still_leaves_a_row(
    seeded: tuple[Engine, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, _archive = seeded
    await _activate_directly(engine)
    coord = _coordinator(engine)
    store = engine.store
    real_record = store.record_audit
    entered = asyncio.Event()
    hang = {"once": True}

    async def failing_drain() -> int:
        raise RuntimeError("the drain could not run")

    async def hanging_record(action: str, *args: Any, **kwargs: Any) -> Any:
        if action == "dr_release_failed" and hang["once"]:
            hang["once"] = False
            entered.set()
            await asyncio.Event().wait()
        return await real_record(action, *args, **kwargs)

    monkeypatch.setattr(coord, "_deactivate_profile", failing_drain)
    monkeypatch.setattr(store, "record_audit", hanging_record)
    task = asyncio.create_task(coord.release(actor="dradmin"))
    await asyncio.wait_for(entered.wait(), 10)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert coord.active
    failed = await _rows(store, "dr_release_failed")
    assert [row["reason"] for row in failed] == ["interrupted"]
    assert failed[0]["phase"] == "drain"


async def test_an_activation_records_a_release_still_owed_its_row_before_promoting(
    seeded: tuple[Engine, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, _archive = seeded
    await _activate_directly(engine)
    monkeypatch.setattr(engine_module, "DR_RELEASE_DRAIN_TIMEOUT_SECONDS", 0.2)
    coord = _coordinator(engine)
    store = engine.store
    real_record = store.record_audit
    failures = {"left": 1}

    async def flaky_record(action: str, *args: Any, **kwargs: Any) -> Any:
        if action == "dr.release" and failures["left"]:
            failures["left"] -= 1
            raise OSError("the audit log refused the write")
        return await real_record(action, *args, **kwargs)

    monkeypatch.setattr(store, "record_audit", flaky_record)
    with pytest.raises(DrActivationError):
        await coord.release(actor="dradmin")

    await coord.activate(actor="dradmin")
    rows = await store.list_audit(limit=200)
    release_seq = max(r["seq"] for r in rows if r["action"] == "dr.release")
    activate_seq = max(r["seq"] for r in rows if r["action"] == "dr.activate")
    assert release_seq < activate_seq
    assert (await _rows(store, "dr.release"))[0]["recorded_late"] is True
