# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""DR fail-back (#61, ADR 0048 AC-11): POST /dr/release is drain-then-hand-back — it releases the VIP,
unbinds all inbound listeners, and drains the staged queue to completion before returning success (no
dual-accept window). Within the DR store at-least-once + idempotency are preserved across the hand-back
(every queued row is delivered, none dropped); cross-store reconciliation is operator-verified (not an
engine guarantee). Driven through the real Engine callbacks the DR coordinator invokes."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from messagefoundry.config.models import ConnectorType, Priority
from messagefoundry.config.settings import BackupSettings, DrSettings, StoreSettings
from messagefoundry.config.wiring import (
    MLLP,
    ConnectionSpec,
    Registry,
    Send,
    build_inbound_connection,
    build_outbound_connection,
)
from messagefoundry.pipeline import Engine
from messagefoundry.pipeline.dr import DrActivationError, DrCoordinator
from messagefoundry.pipeline.dr_backup import BackupRunner
from messagefoundry.store import MessageStatus, MessageStore
from messagefoundry.store.crypto import generate_key, make_cipher

# A trivially-succeeding / trivially-failing shell command portable across the runner's shell (Git Bash
# on the dev box, /bin/sh on CI, cmd on a bare Windows box) — same pattern as test_dr_activation.py.
_OK_HOOK = "exit 0"
_FAIL_HOOK = "exit 7"

ADT = (
    "MSH|^~\\&|S|F|R|RF|20260604||ADT^A01|FBMSG1|P|2.5.1\r"
    "EVN|A01|20260604\r"
    "PID|1||100^^^H^MR||DOE^JANE\r"
)


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    # A DR box: dr.enabled so the coordinator builds; activate=false so it starts un-activated (the box
    # comes up serving its full graph; the test activates it, then fails it back). store_settings present
    # so the cold-seed key seam exists.
    store = await MessageStore.open(tmp_path / "fb.db")
    eng = Engine(
        store,
        poll_interval=0.02,
        config_dir=None,
        store_settings=StoreSettings(path=str(tmp_path / "fb.db")),
        dr_settings=DrSettings(enabled=True, activate=False),
    )
    yield eng
    await eng.stop()


async def _wait(predicate, timeout: float = 10.0) -> None:  # type: ignore[no-untyped-def]
    elapsed = 0.0
    while not await predicate():
        await asyncio.sleep(0.05)
        elapsed += 0.05
        if elapsed > timeout:
            raise AssertionError("condition not met within timeout")


async def test_release_drains_then_hands_back(engine: Engine, tmp_path: Path) -> None:
    outdir = tmp_path / "out"
    outdir.mkdir()
    reg = Registry()
    reg.add_inbound(
        build_inbound_connection(
            "in_crit", MLLP(port=19501), router="r", priority=Priority.CRITICAL
        )
    )
    reg.add_outbound(
        build_outbound_connection(
            "out",
            ConnectionSpec(
                ConnectorType.FILE, {"directory": str(outdir), "filename": "{MSH-10}.hl7"}
            ),
            priority=Priority.CRITICAL,
        )
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("out", m))
    engine.add_registry(reg)
    await engine.start()

    rr = engine.registry_runner
    assert rr is not None and rr.inbound_running("in_crit")

    # Enqueue a message at ingress (as a received inbound message would) — the worker routes + delivers.
    await engine.store.enqueue_ingress(
        channel_id="in_crit",
        raw=ADT,
        control_id="FBMSG1",
        message_type="ADT^A01",
        summary="DOE^JANE",
        now=1.0,
    )

    # Fail back: drain-then-hand-back via the engine's DR-release callback (what POST /dr/release runs).
    # It unbinds intake + drains the staged queue to completion before returning.
    engine._dr_active = True  # simulate "currently serving under the DR profile"
    await engine._dr_release_drain()

    # No listener is bound after the hand-back (no dual-accept window while the VIP moves).
    assert not rr.inbound_running("in_crit")
    # The staged queue drained to completion — the message was DELIVERED (at-least-once within the store
    # held across the hand-back; nothing dropped).
    assert await engine.store.in_pipeline_depth() == 0
    assert (outdir / "FBMSG1.hl7").exists()
    processed = await engine.store.list_messages(
        channel_id="in_crit", status=MessageStatus.PROCESSED.value
    )
    assert len(processed) == 1  # delivered exactly the once (idempotent outbound, no dup-drop)
    assert engine.dr_active is False  # the run-profile is latched off after a clean hand-back


# --- coordinator-level release branches (injectable harness, SQLite-local) -------------------------
# The tests below drive DrCoordinator.release() directly against the injectable activate/deactivate
# callbacks (the same seam test_dr_activation.py uses for the takeover phase), so they can exercise the
# two release-phase branches the Engine happy-path test above never reaches: a FAILED drain (the box
# stays active, retryable, no dr.release row) and a FAILING release_hook (non-fatal — the hand-back
# still completes). No failover/crash rig — the store is plain SQLite.


async def _seed(tmp_path: Path) -> tuple[MessageStore, str, StoreSettings]:
    # A #60 cold-seed archive over an encrypted SQLite store, mirroring test_dr_activation.py::_seed so
    # activate() clears its restore-verify gate before we ever reach the release path under test.
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


async def _actions(store: MessageStore) -> list[str]:
    return [r["action"] for r in await store.list_audit(limit=50)]


async def test_release_failed_drain_stays_active_then_retry_succeeds(tmp_path: Path) -> None:
    # dr.py:308-319 — a drain that raises must NOT claim a clean hand-back: release() re-raises
    # DrActivationError(kind="state"), the box stays ACTIVE (_active never latched off, so the operator
    # can retry), and NO dr.release audit row is written (the raise precedes record_audit). A retry once
    # the drain recovers then completes the hand-back — proving the retry branch.
    store, archive, ss = await _seed(tmp_path)
    try:
        # A deactivate_profile we can flip from raising to clean, to drive both passes of the branch.
        state = {"active": False, "drain_fails": True}

        async def act() -> None:
            state["active"] = True

        async def deact() -> None:
            if state["drain_fails"]:
                raise RuntimeError("staged queue would not drain to completion")
            state["active"] = False

        coord = DrCoordinator(
            store,
            DrSettings(enabled=True, seed_archive=archive, takeover_hook=_OK_HOOK),
            store_settings=ss,
            activate_profile=act,
            deactivate_profile=deact,
        )
        await coord.activate(actor="alice")
        assert coord.active and state["active"]

        # (A) The drain raises → aborted, box stays active, no dr.release row.
        with pytest.raises(DrActivationError) as exc:
            await coord.release(actor="alice")
        assert exc.value.kind == "state"
        assert coord.active  # _active never latched off — the box stays up for a retry
        assert "dr.release" not in await _actions(store)  # no clean-hand-back row was written

        # Retry once the drain recovers → a clean hand-back: active False + a dr.release row.
        state["drain_fails"] = False
        result = await coord.release(actor="alice")
        assert not result.active and not coord.active
        assert not state["active"]  # the second deactivate_profile ran to completion
        assert "dr.release" in await _actions(store)
    finally:
        await store.close()


async def test_release_hook_failure_is_nonfatal_handback_completes(tmp_path: Path) -> None:
    # dr.py:305-306 & _run_vip_hook release branch (dr.py:610-614) — a FAILING release_hook (exit 7) is
    # logged but does NOT abort the hand-back (contrast the takeover phase, which aborts): release()
    # still returns active=False with a dr.release row carrying drained=true, and the run-profile is off.
    store, archive, ss = await _seed(tmp_path)
    try:
        state = {"active": False}

        async def act() -> None:
            state["active"] = True

        async def deact() -> None:
            state["active"] = False

        coord = DrCoordinator(
            store,
            DrSettings(
                enabled=True,
                seed_archive=archive,
                takeover_hook=_OK_HOOK,
                release_hook=_FAIL_HOOK,
            ),
            store_settings=ss,
            activate_profile=act,
            deactivate_profile=deact,
        )
        await coord.activate(actor="alice")
        assert coord.active and state["active"]

        result = await coord.release(actor="alice")
        assert not result.active and not coord.active  # the hand-back latched the profile off
        assert not state["active"]  # deactivate_profile drained despite the hook failing
        assert result.vip_hook_ran  # the release hook DID run — it was just non-fatal

        release_rows = [r for r in await store.list_audit(limit=50) if r["action"] == "dr.release"]
        assert len(release_rows) == 1
        detail = json.loads(release_rows[0]["detail"])
        assert detail["drained"] is True and detail["vip_hook_ran"] is True
    finally:
        await store.close()
