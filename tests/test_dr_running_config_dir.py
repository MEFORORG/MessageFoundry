# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A DR activation re-applies the running graph under the DR threshold, and reads no config dir.

vault BACKLOG #3067: the runner's DR threshold was set only at construction, and the activation
reloaded through that same runner, so on a box built passive ``POST /dr/activate`` parked nothing.
The engine now hands the runner the threshold before the reload, and clears it on release.

The same item moved the activation off the disk. It used to reload :attr:`Engine.running_config_dir`
(vault BACKLOG #2840), which put live any bytes edited there since the last approved reload, with no
second person, and refused the activation when that dir had gone with the failed site. It now
re-applies the graph the runner holds in memory. A disk that differs is recorded on the
``dr.activate`` row and logged, and only the gated ``POST /config/reload`` applies it.

vault BACKLOG #2839: the seed marker's digest is the running graph's provenance digest, so a file
name that is not UTF-8 cannot fail an activation or a release, and no digest is taken on the loop.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import socket
import threading
import time
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any, NamedTuple

import pytest

from messagefoundry.config import fingerprint as fp
from messagefoundry.config.models import Priority
from messagefoundry.config.settings import DrSettings, EgressSettings
from messagefoundry.config.wiring import WiringError
from messagefoundry.pipeline import Engine
from messagefoundry.pipeline.dr import DrActivationError
from tests.test_dr_activation import _seed

# A name that cannot be encoded as UTF-8: a lone surrogate. NTFS stores it as UTF-16, and on a
# POSIX file system Python writes it as the raw byte 0x80. Under environments/ it is fingerprinted
# (environments/*.toml is in the fold) but never loaded, so the graph still builds.
_BAD_NAME = "x\udc80.toml"

ADT = (
    "MSH|^~\\&|S|F|R|RF|20260604||ADT^A01|HOLD1|P|2.5.1\r"
    "EVN|A01|20260604\r"
    "PID|1||100^^^H^MR||DOE^JANE\r"
)

_CRIT = "IB_CRIT_ADT"
_NORM = "IB_NORM_ADT"


def _free_ports(count: int) -> list[int]:
    """Distinct free ports: every socket stays bound until all are picked, so no two match."""
    socks = [socket.socket() for _ in range(count)]
    try:
        for s in socks:
            s.bind(("127.0.0.1", 0))
        return [int(s.getsockname()[1]) for s in socks]
    finally:
        for s in socks:
            s.close()


def _write_graph(cfg: Path, tmp_path: Path, inbound: str) -> None:
    inbox = tmp_path / f"in-{inbound}"
    outdir = tmp_path / f"out-{inbound}"
    for d in (cfg, inbox, outdir):
        d.mkdir(parents=True, exist_ok=True)
    (cfg / "cfg.py").write_text(
        "from messagefoundry import inbound, outbound, router, handler, Send, File\n"
        f"inbound({inbound!r}, File(directory={str(inbox)!r}, pattern='*.hl7', "
        "poll_seconds=1.0), router='r')\n"
        f"outbound('FILE-OUT_T_ADT', File(directory={str(outdir)!r}))\n"
        "@router('r')\n"
        "def route(msg):\n"
        "    return ['h']\n"
        "@handler('h')\n"
        "def handle(msg):\n"
        "    return Send('FILE-OUT_T_ADT', msg)\n",
        encoding="utf-8",
    )


# A schedule that is never active: the calendar parks OB_NORM_ADT for good. Two windows cover the
# whole day, so no minute is left open, and invert makes being inside one mean down.
_NEVER = (
    "Schedule(invert=True, windows=["
    "ActiveWindow(days=[0, 1, 2, 3, 4, 5, 6], start=time(0, 0), end=time(23, 59)), "
    "ActiveWindow(days=[0, 1, 2, 3, 4, 5, 6], start=time(23, 59), end=time(0, 0))])"
)


def _write_tiered_graph(cfg: Path, tmp_path: Path, *, norm_schedule: str | None = None) -> None:
    """One critical and one normal MLLP inbound, each with an outbound of the same tier."""
    cfg.mkdir(parents=True, exist_ok=True)
    out_crit, out_norm = tmp_path / "out-crit", tmp_path / "out-norm"
    out_crit.mkdir(exist_ok=True)
    out_norm.mkdir(exist_ok=True)
    crit_port, norm_port = _free_ports(2)
    (cfg / "cfg.py").write_text(
        "from messagefoundry import inbound, outbound, router, handler, Send, File, MLLP\n"
        "from datetime import time\n"
        "from messagefoundry.config.models import ActiveWindow, Priority, Schedule\n"
        f"inbound({_CRIT!r}, MLLP(port={crit_port}), router='r', priority=Priority.CRITICAL)\n"
        f"inbound({_NORM!r}, MLLP(port={norm_port}), router='r', priority=Priority.NORMAL)\n"
        f"outbound('OB_CRIT_ADT', File(directory={str(out_crit)!r}), "
        "priority=Priority.CRITICAL)\n"
        f"outbound('OB_NORM_ADT', File(directory={str(out_norm)!r}), priority=Priority.NORMAL"
        f"{f', schedule={norm_schedule}' if norm_schedule else ''})\n"
        "@router('r')\n"
        "def route(msg):\n"
        "    return ['h']\n"
        "@handler('h')\n"
        "def handle(msg):\n"
        "    return [Send('OB_CRIT_ADT', msg), Send('OB_NORM_ADT', msg)]\n",
        encoding="utf-8",
    )


class _Box(NamedTuple):
    engine: Engine
    live: Path
    staging: Path
    tiered: Path
    scheduled: Path


@pytest.fixture
async def box(tmp_path: Path) -> AsyncIterator[_Box]:
    """A passive DR box, with ``live`` as its startup dir and ``staging`` and ``tiered`` as two
    more allowed reload roots. The store is encrypted and carries a cold-seed archive of itself,
    so an activation clears its gates."""
    live = tmp_path / "live"
    staging = tmp_path / "staging"
    tiered = tmp_path / "tiered"
    scheduled = tmp_path / "scheduled"
    _write_graph(live, tmp_path, "IB_LIVE_ADT")
    _write_graph(staging, tmp_path, "IB_STAGING_ADT")
    _write_tiered_graph(tiered, tmp_path)
    _write_tiered_graph(scheduled, tmp_path, norm_schedule=_NEVER)
    store, archive, ss = await _seed(tmp_path)
    engine = Engine(
        store,
        poll_interval=0.05,
        config_dir=live,
        config_reload_roots=[str(staging), str(tiered), str(scheduled)],
        store_settings=ss,
        dr_settings=DrSettings(enabled=True, activate=False, seed_archive=archive),
        egress_settings=EgressSettings(deny_by_default=False),
    )
    # The seed holds a row for a destination none of these graphs declares. A started engine
    # dead-letters it at boot (dead_letter_missing_destinations); these tests never call start(),
    # so do it here, or every release would wait out its whole drain timeout on that one row.
    await store.dead_letter_missing_destinations(set())
    try:
        yield _Box(engine, live, staging, tiered, scheduled)
    finally:
        await engine.stop()


def _inbound_names(engine: Engine) -> set[str]:
    rr = engine.registry_runner
    assert rr is not None
    return set(rr.registry.inbound)


async def _seed_marker(engine: Engine) -> dict[str, object]:
    rows = await engine.store.list_audit(action="dr_seed")
    assert len(rows) == 1
    marker: dict[str, object] = json.loads(rows[0]["detail"])
    return marker


async def _activate_row(engine: Engine) -> dict[str, object]:
    rows = await engine.store.list_audit(action="dr.activate")
    assert len(rows) == 1
    detail: dict[str, object] = json.loads(rows[0]["detail"])
    return detail


def _loaded_digest(engine: Engine) -> str:
    loaded = engine.loaded_config_fingerprint
    assert loaded is not None
    digest = loaded["fingerprint"]
    assert isinstance(digest, str)
    return digest


# --- #3067: the activation parks the below-threshold feeds on a running box -----------------------


async def test_an_activation_parks_the_normal_feed_and_keeps_the_critical_one(box: _Box) -> None:
    """Red before #3067: the runner kept the threshold it was built with (None on a passive box),
    so the activation reload bound both inbounds again."""
    engine = box.engine
    await engine.reload_detail(box.tiered)
    rr = engine.registry_runner
    assert rr is not None
    # Control: a passive box serves its full graph.
    assert rr.inbound_running(_CRIT) and rr.inbound_running(_NORM)
    assert rr.filtered_inbound() == {} and rr.filtered_outbound() == {}

    coord = engine.dr_coordinator
    assert coord is not None
    await coord.activate(actor="alice")

    assert engine.dr_active is True and rr.dr_threshold is Priority.CRITICAL
    assert rr.inbound_running(_CRIT)
    assert not rr.inbound_running(_NORM)
    assert _NORM in rr.filtered_inbound() and _CRIT not in rr.filtered_inbound()
    assert rr.inbound_failed(_NORM) is None  # parked, not failed
    assert "OB_NORM_ADT" in rr.filtered_outbound()
    assert "OB_CRIT_ADT" not in rr.filtered_outbound()

    # An operator reload while the profile is on keeps the normal feed parked.
    await engine.reload_detail(box.tiered)
    assert rr.inbound_running(_CRIT) and not rr.inbound_running(_NORM)


async def test_a_release_then_a_reload_binds_the_normal_feed_again(box: _Box) -> None:
    """Red before #3067 in the other direction: a runner built under the profile kept its threshold
    after a release, so every later reload went on parking the normal feeds."""
    engine = box.engine
    await engine.reload_detail(box.tiered)
    rr = engine.registry_runner
    assert rr is not None
    coord = engine.dr_coordinator
    assert coord is not None
    await coord.activate(actor="alice")
    assert not rr.inbound_running(_NORM)  # control: the profile parked it

    await coord.release(actor="alice")
    assert engine.dr_active is False and rr.dr_threshold is None
    assert not rr.inbound_running(_CRIT)  # the release unbound all intake
    # Until the next reload a parked feed stays parked, so the scheduler cannot bind it.
    assert _NORM in rr.filtered_inbound()

    await engine.reload_detail(box.tiered)
    assert rr.inbound_running(_CRIT) and rr.inbound_running(_NORM)
    assert rr.filtered_inbound() == {} and rr.filtered_outbound() == {}


async def _norm_row(engine: Engine, message_id: str) -> dict[str, Any]:
    (row,) = [
        r
        for r in await engine.store.outbox_for(message_id)
        if r["destination_name"] == "OB_NORM_ADT"
    ]
    return dict(row)


async def _until(predicate: Callable[[], Any], timeout: float = 10.0) -> None:
    elapsed = 0.0
    while not await predicate():
        await asyncio.sleep(0.05)
        elapsed += 0.05
        assert elapsed < timeout, "condition not met within timeout"


async def test_a_row_on_a_parked_outbound_is_held_and_drains_after_release(box: _Box) -> None:
    """Red before #3067's hold: the parked lane's worker claimed the row, found no connector and
    charged it a failed attempt every backoff, so a finite max_attempts dead-lettered it. The
    release then waited out its whole drain timeout on it and still recorded drained: true."""
    engine = box.engine
    await engine.reload_detail(box.tiered)
    rr = engine.registry_runner
    assert rr is not None
    coord = engine.dr_coordinator
    assert coord is not None
    await coord.activate(actor="alice")
    assert "OB_NORM_ADT" in rr.filtered_outbound()

    # The critical feed's handler sends to both tiers, as a received message would.
    message_id = await engine.store.enqueue_ingress(
        channel_id=_CRIT,
        raw=ADT,
        control_id="HOLD1",
        message_type="ADT^A01",
        summary="DOE^JANE",
        now=time.time(),
    )

    async def crit_delivered() -> bool:
        rows = await engine.store.outbox_for(message_id)
        return any(r["destination_name"] == "OB_CRIT_ADT" and r["status"] == "done" for r in rows)

    await _until(crit_delivered)  # control: the pipeline ran, and the critical tier delivered
    await asyncio.sleep(0.5)  # ten poll intervals for a worker that would claim the parked row
    held = await _norm_row(engine, message_id)
    assert held["status"] == "pending"
    assert held["attempts"] == 0
    assert rr.outbound_filtered("OB_NORM_ADT") is not None  # it still reads filtered, not stopped
    # An operator start cannot lift a DR park: there is no connector to deliver through.
    await rr.start_outbound("OB_NORM_ADT")
    await asyncio.sleep(0.5)
    assert (await _norm_row(engine, message_id))["attempts"] == 0

    started = time.monotonic()
    released = await coord.release(actor="alice")
    assert released.drained is True and released.held_on_parked_outbounds == 1
    assert time.monotonic() - started < 10.0  # the drain did not wait on the held row
    (row,) = await engine.store.list_audit(action="dr.release")
    detail = json.loads(row["detail"])
    assert detail["drained"] is True and detail["held_on_parked_outbounds"] == 1

    await engine.reload_detail(box.tiered)  # the profile is off: the park lifts and it drains

    async def norm_delivered() -> bool:
        return (await _norm_row(engine, message_id))["status"] == "done"

    await _until(norm_delivered)
    assert any((box.tiered.parent / "out-norm").iterdir())  # a file reached the target


async def _assert_delivers_after_release(engine: Engine, box: _Box, message_id: str) -> None:
    rr = engine.registry_runner
    assert rr is not None
    coord = engine.dr_coordinator
    assert coord is not None
    await coord.release(actor="alice")
    await engine.reload_detail(box.tiered)

    async def norm_delivered() -> bool:
        return (await _norm_row(engine, message_id))["status"] == "done"

    await _until(norm_delivered)
    assert rr.outbound_status("OB_NORM_ADT") == "running"


async def test_a_restarted_dr_parked_outbound_comes_up_after_release(box: _Box) -> None:
    """Red at 638136f79a: the restart's stop half dropped the engine-park marker and its start
    half kept the lane parked, so no reload lifted it; it read "stopping" and held its row until
    an operator started it."""
    engine = box.engine
    await engine.reload_detail(box.tiered)
    rr = engine.registry_runner
    assert rr is not None
    coord = engine.dr_coordinator
    assert coord is not None
    await coord.activate(actor="alice")
    message_id = await engine.store.enqueue_message(
        channel_id=_CRIT, raw=ADT, deliveries=[("OB_NORM_ADT", ADT)], now=time.time()
    )

    await rr.restart_outbound("OB_NORM_ADT")
    await asyncio.sleep(0.3)
    assert rr.outbound_status("OB_NORM_ADT") == "stopped"  # parked, and never "stopping"
    assert (await _norm_row(engine, message_id))["attempts"] == 0

    await _assert_delivers_after_release(engine, box, message_id)


async def test_a_calendar_parked_outbound_unscheduled_under_dr_comes_up_after_release(
    box: _Box,
) -> None:
    """A reload under the profile removes the schedule of a lane the calendar parked. Red at
    638136f79a: the unscheduled resume met the DR park, left the lane paused with no engine-park
    marker, and no later reload lifted it."""
    engine = box.engine
    await engine.reload_detail(box.scheduled)
    rr = engine.registry_runner
    assert rr is not None

    async def calendar_parked() -> bool:
        return not rr.outbound_running("OB_NORM_ADT")

    await _until(calendar_parked)  # control: the calendar holds it down
    message_id = await engine.store.enqueue_message(
        channel_id=_CRIT, raw=ADT, deliveries=[("OB_NORM_ADT", ADT)], now=time.time()
    )
    coord = engine.dr_coordinator
    assert coord is not None
    await coord.activate(actor="alice")
    await engine.reload_detail(box.tiered)  # the same graph with the schedule gone
    assert (await _norm_row(engine, message_id))["attempts"] == 0

    await _assert_delivers_after_release(engine, box, message_id)


async def test_a_release_drain_that_times_out_is_not_recorded_as_drained(
    box: _Box, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``drained`` is true only when the drainable rows drained; a row on a lane that is not
    parked and cannot deliver keeps it false."""
    engine = box.engine
    await engine.reload_detail(box.tiered)
    rr = engine.registry_runner
    assert rr is not None
    await rr.stop_outbound("OB_CRIT_ADT")  # an operator pause: drainable in principle, not now
    await engine.store.enqueue_message(
        channel_id=_CRIT, raw=ADT, deliveries=[("OB_CRIT_ADT", ADT)], now=time.time()
    )
    real_drain = engine._drain_pipeline

    async def short_drain() -> tuple[bool, int]:
        return await real_drain(timeout=0.3)

    monkeypatch.setattr(engine, "_drain_pipeline", short_drain)
    coord = engine.dr_coordinator
    assert coord is not None
    await coord.activate(actor="alice")
    await coord.release(actor="alice")

    (row,) = await engine.store.list_audit(action="dr.release")
    detail = json.loads(row["detail"])
    assert detail["drained"] is False and detail["held_on_parked_outbounds"] == 0


async def test_a_reload_that_fails_after_the_threshold_is_set_puts_it_back(
    box: _Box, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The one case the rollback exists for: the threshold is on the runner and the re-apply
    fails. Red under a missing rollback, which leaves CRITICAL on a box reported not active."""
    engine = box.engine
    await engine.reload_detail(box.tiered)
    rr = engine.registry_runner
    assert rr is not None
    seen: list[object] = []

    async def failing_reload(registry: object = None) -> None:
        seen.append(rr.dr_threshold)
        raise OSError("a listener could not bind")

    monkeypatch.setattr(rr, "reload", failing_reload)
    coord = engine.dr_coordinator
    assert coord is not None
    with pytest.raises(DrActivationError) as caught:
        await coord.activate(actor="alice")

    assert caught.value.kind == "profile"
    assert seen == [Priority.CRITICAL]  # control: the threshold was on when the reload ran
    assert rr.dr_threshold is None
    assert coord.active is False and engine.dr_active is False


async def test_a_refused_activation_puts_the_threshold_back(
    box: _Box, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The latch and the runner's threshold go back together, so a later reload on a box the
    coordinator reports as not active parks nothing."""
    engine = box.engine
    await engine.reload_detail(box.tiered)
    rr = engine.registry_runner
    assert rr is not None

    async def refuse(registry: object) -> None:
        raise WiringError("a trust anchor this graph names is not readable")

    real_preflight = engine.preflight_registry
    monkeypatch.setattr(engine, "preflight_registry", refuse)
    coord = engine.dr_coordinator
    assert coord is not None
    with pytest.raises(DrActivationError) as caught:
        await coord.activate(actor="alice")

    assert caught.value.kind == "profile"
    assert "could not bind the priority feeds" in str(caught.value)
    assert coord.active is False and engine.dr_active is False
    assert rr.dr_threshold is None
    assert rr.inbound_running(_CRIT) and rr.inbound_running(_NORM)
    monkeypatch.setattr(engine, "preflight_registry", real_preflight)
    await engine.reload_detail(box.tiered)
    assert rr.inbound_running(_NORM)


# --- the activation applies the running graph, not the disk ----------------------------------------


async def test_a_dr_activation_keeps_the_graph_an_operator_reloaded(box: _Box) -> None:
    """Red before #2840: the activation reloaded ``live`` and IB_LIVE_ADT came back."""
    engine = box.engine
    await engine.reload_detail(box.live)
    assert _inbound_names(engine) == {"IB_LIVE_ADT"}  # control: the startup graph went live
    await engine.reload_detail(box.staging)  # the operator's deliberate reload
    assert _inbound_names(engine) == {"IB_STAGING_ADT"}

    coord = engine.dr_coordinator
    assert coord is not None
    await coord.activate(actor="alice")

    assert engine.dr_active is True
    assert _inbound_names(engine) == {"IB_STAGING_ADT"}
    assert engine.last_reload_dir == box.staging.resolve()


async def test_bytes_edited_after_the_reload_are_recorded_and_not_applied(
    box: _Box, caplog: pytest.LogCaptureFixture
) -> None:
    """Red before #3067: the activation reloaded the dir, so an edit nobody approved went live."""
    engine = box.engine
    await engine.reload_detail(box.staging)
    activated = _loaded_digest(engine)
    _write_graph(box.staging, box.staging.parent, "IB_EDITED_ADT")  # nobody approved this
    on_disk = fp.config_fingerprint(box.staging)
    assert on_disk != activated  # control: the disk really moved

    coord = engine.dr_coordinator
    assert coord is not None
    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.engine"):
        await coord.activate(actor="alice")

    assert _inbound_names(engine) == {"IB_STAGING_ADT"}  # the in-memory graph, not the edit
    assert _loaded_digest(engine) == activated
    row = await _activate_row(engine)
    assert row["config_fingerprint"] == activated
    assert row["disk_config"] == "differs"
    assert row["disk_config_fingerprint"] == on_disk
    assert (await _seed_marker(engine))["config_fingerprint"] == activated
    drift = [r.getMessage() for r in caplog.records if "now differs on disk" in r.getMessage()]
    assert len(drift) == 1
    assert activated in drift[0] and on_disk in drift[0] and "IB_EDITED_ADT" not in drift[0]
    # The operator's gated reload is what applies it.
    await engine.reload_detail(box.staging)
    assert _inbound_names(engine) == {"IB_EDITED_ADT"}


async def test_an_unchanged_dir_is_recorded_as_matching(box: _Box) -> None:
    engine = box.engine
    await engine.reload_detail(box.staging)
    coord = engine.dr_coordinator
    assert coord is not None
    await coord.activate(actor="alice")

    row = await _activate_row(engine)
    assert row["config_fingerprint"] == _loaded_digest(engine)
    assert row["disk_config"] == "matches"
    assert "disk_config_fingerprint" not in row


async def test_an_activation_succeeds_with_the_config_dir_removed(
    box: _Box, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Red at 7a59a4bd24 and at #2840's preflight: a gone dir aborted the activation. The
    activation no longer reads it, so it goes ahead, runs the takeover hook, and records that the
    disk could not be read."""
    engine = box.engine
    await engine.reload_detail(box.staging)
    activated = _loaded_digest(engine)
    shutil.rmtree(box.staging)
    coord = engine.dr_coordinator
    assert coord is not None
    hooks: list[str] = []
    real_hook = coord._run_vip_hook

    async def spy(command: str, *, phase: str, actor: str, now: float) -> bool:
        hooks.append(phase)
        return await real_hook(command, phase=phase, actor=actor, now=now)

    monkeypatch.setattr(coord, "_run_vip_hook", spy)

    result = await coord.activate(actor="alice")

    assert result.active is True and engine.dr_active is True
    assert hooks == ["takeover"]
    assert _inbound_names(engine) == {"IB_STAGING_ADT"}
    assert await engine.store.list_audit(action="dr_activation_aborted") == []
    row = await _activate_row(engine)
    assert row["config_fingerprint"] == activated
    assert row["disk_config"] == "unreadable"
    assert isinstance(row["disk_config_error"], str) and row["disk_config_error"]
    # The marker carries the running graph's digest, not None and not an empty bundle's.
    assert (await _seed_marker(engine))["config_fingerprint"] == activated


async def test_a_dir_that_goes_during_the_takeover_hook_does_not_abort(
    box: _Box, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Red at #2840: the profile step reloaded the dir after the hook, so a dir that went while
    the VIP moved left the VIP on a box not running the profile."""
    engine = box.engine
    await engine.reload_detail(box.staging)
    coord = engine.dr_coordinator
    assert coord is not None

    async def hook_removes_the_dir(command: str, *, phase: str, actor: str, now: float) -> bool:
        shutil.rmtree(box.staging)
        return True

    monkeypatch.setattr(coord, "_run_vip_hook", hook_removes_the_dir)

    result = await coord.activate(actor="alice")

    assert result.active is True and engine.dr_active is True
    assert _inbound_names(engine) == {"IB_STAGING_ADT"}
    assert (await _activate_row(engine))["disk_config"] == "unreadable"


async def test_a_drift_check_that_raises_does_not_undo_the_activation(
    box: _Box, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The check runs after the graph is live. A raise there used to reach the coordinator, which
    recorded an abort and reported the box as not active while it served the profile."""
    engine = box.engine
    await engine.reload_detail(box.tiered)
    rr = engine.registry_runner
    assert rr is not None

    async def broken(path: Path) -> tuple[dict[str, object] | None, str | None]:
        raise RuntimeError("the fingerprint module failed")

    monkeypatch.setattr(engine, "fingerprint_bundle", broken)
    coord = engine.dr_coordinator
    assert coord is not None
    result = await coord.activate(actor="alice")

    assert result.active is True and coord.active is True and engine.dr_active is True
    assert not rr.inbound_running(_NORM)
    assert await engine.store.list_audit(action="dr_activation_aborted") == []
    row = await _activate_row(engine)
    assert row["disk_config"] == "unreadable"
    assert "the fingerprint module failed" in str(row["disk_config_error"])


async def test_a_running_graph_with_no_digest_is_recorded_as_unknown(box: _Box) -> None:
    """With nothing to compare, the verdict is ``unknown``, not ``differs``."""
    engine = box.engine
    await engine.reload_detail(box.staging)
    engine.loaded_config_fingerprint = None  # as when the load could not read its bundle
    coord = engine.dr_coordinator
    assert coord is not None
    await coord.activate(actor="alice")

    row = await _activate_row(engine)
    assert row["config_fingerprint"] is None
    assert row["disk_config"] == "unknown"
    assert row["disk_config_fingerprint"] == fp.config_fingerprint(box.staging)


async def test_convergence_still_reloads_the_startup_dir(box: _Box) -> None:
    """Each node converges on its own startup dir, so a convergence after an operator reload from
    another root still loads ``live``."""
    engine = box.engine
    await engine.reload_detail(box.staging)
    assert _inbound_names(engine) == {"IB_STAGING_ADT"}  # control: the operator's graph runs

    await engine._converge_reload()

    assert _inbound_names(engine) == {"IB_LIVE_ADT"}


# --- #2839: the seed marker's digest ---------------------------------------------------------------


async def test_the_seed_marker_carries_the_running_graphs_digest(box: _Box) -> None:
    """Red before #2839: the marker carried the startup dir's digest after a reload elsewhere."""
    engine = box.engine
    await engine.reload_detail(box.staging)
    coord = engine.dr_coordinator
    assert coord is not None
    await coord.activate(actor="alice")

    marker = await _seed_marker(engine)
    assert marker["config_fingerprint"] == fp.config_fingerprint(box.staging)
    assert marker["config_fingerprint"] != fp.config_fingerprint(box.live)  # the two differ


async def test_a_file_name_that_is_not_utf8_does_not_fail_dr(box: _Box) -> None:
    """Red before #2839: reading ``dr_coordinator`` raised UnicodeEncodeError."""
    engine = box.engine
    try:
        (box.live / "environments").mkdir()
        (box.live / "environments" / _BAD_NAME).write_text("", encoding="utf-8")
    except (OSError, UnicodeEncodeError) as exc:
        pytest.skip(f"this file system refuses a name that is not UTF-8: {type(exc).__name__}")
    with pytest.raises(UnicodeEncodeError):
        fp.config_fingerprint(box.live)  # control: the fold really refuses this bundle

    await engine.reload_detail(box.live)  # a reload tolerates it already (#2597)
    coord = engine.dr_coordinator
    assert coord is not None
    result = await coord.activate(actor="alice")
    assert result.active is True
    assert (await _seed_marker(engine))["config_fingerprint"] is None
    assert (await _activate_row(engine))["disk_config"] == "unreadable"

    released = await coord.release(actor="alice")
    assert released.active is False


async def test_the_dr_fingerprint_is_not_taken_on_the_event_loop(
    box: _Box, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Red before #2839: the property called config_fingerprint on the loop's own thread."""
    engine = box.engine
    await engine.reload_detail(box.live)
    loop_thread = threading.get_ident()
    seen: list[tuple[str, int]] = []

    def spy(name: str) -> Callable[[str | Path], Any]:
        real = getattr(fp, name)

        def wrapped(directory: str | Path) -> Any:
            seen.append((name, threading.get_ident()))
            return real(directory)

        return wrapped

    # Both: the old property called the plain one, fingerprint_bundle calls the detail one.
    for name in ("config_fingerprint", "config_fingerprint_detail"):
        monkeypatch.setattr(fp, name, spy(name))

    coord = engine.dr_coordinator
    assert coord is not None
    assert seen == []  # building the coordinator read no file
    await coord.activate(actor="alice")

    # Control: the drift check fingerprinted the dir during the activation, so the calls checked
    # below are not an empty list.
    assert seen, "the activation took no digest of the config dir"
    assert all(thread != loop_thread for _name, thread in seen), seen
