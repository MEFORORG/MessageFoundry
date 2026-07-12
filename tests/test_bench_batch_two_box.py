# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""STRUCTURAL tests for the batch_ab two-box matrix drive (ADR 0075 Bench B).

These prove the engine/driver split WIRES + HANDSHAKES correctly OFFLINE on one PC: the pure band/cell/
argv/aggregation helpers; the full engine+driver matrix round-trip in LOCKSTEP over the file-drop coord
(per-cell READY -> DONE pairing, the batch flag toggled per arm, the engine PID landing in READY + the
engine report for external per-PID CPU correlation); the >= 6 sink-PROCESS fleet aggregation into one
cell record; and the B0/B1 verdict. Every network collaborator (the engine subprocess, the health/port
preflights, the store reset, the connscale-remote spawn) is faked — there is no real cross-box packet
flow here (that + the ~450-500 msg/s number is the AWS rig's job).
"""

from __future__ import annotations

import tempfile
import types
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

import harness.load.connscale.batchbox as bb
from harness.load.connscale.compare import FUSE_GO
from harness.load.connscale.profile import load_connscale_profile_text
from harness.load.connscale.runner import ConnScaleError
from harness.load.coord import BATCH_CELL_DONE, BATCH_CELL_READY, FileDropCoord

_MINIMAL_BATCH = """
[connscale]
name = "batch2box-test"
description = "structural batch two-box test"
claim_modes = ["pooled"]
fuse_modes = [false]
batch_modes = [false, true]
trials = 3
counts = [8]
sweep_mode = "fixed_aggregate"
aggregate_rate = 24.0
hold_seconds = 0.1
drain_timeout_s = 1.0
base_port = 2600
"""


def _profile() -> Any:
    return load_connscale_profile_text(_MINIMAL_BATCH)


# --------------------------------------------------------------------------------------------------
# Pure helpers
# --------------------------------------------------------------------------------------------------


def test_iter_batch_cells_order_and_tags() -> None:
    cells = bb.iter_batch_cells(_profile(), claim_mode="pooled")
    # batch arm (B0 then B1) x count x trial, fusion pinned OFF, claim pinned to the flag.
    assert [c.cell_id for c in cells] == [
        "pooled-f0-bt0-fixed_aggregate-8-t0",
        "pooled-f0-bt0-fixed_aggregate-8-t1",
        "pooled-f0-bt0-fixed_aggregate-8-t2",
        "pooled-f0-bt1-fixed_aggregate-8-t0",
        "pooled-f0-bt1-fixed_aggregate-8-t1",
        "pooled-f0-bt1-fixed_aggregate-8-t2",
    ]
    assert all(c.fuse_mode is False for c in cells)
    assert [c.batch_mode for c in cells] == [False, False, False, True, True, True]


def test_iter_batch_cells_both_halves_agree() -> None:
    # The lockstep guarantee: the same profile + claim mode yields the identical, order-stable list on
    # both boxes.
    a = bb.iter_batch_cells(_profile(), claim_mode="pooled")
    b = bb.iter_batch_cells(_profile(), claim_mode="pooled")
    assert [c.cell_id for c in a] == [c.cell_id for c in b]


def test_plan_driver_bands_disjoint_and_cover() -> None:
    plans = bb.plan_driver_bands(inbound_base=2600, count=8, sink_base=40000, sink_procs=6)
    assert len(plans) == 6
    # Inbound sub-bands partition [2600, 2608) exactly once (no over-drive, no collision).
    covered: list[int] = []
    for p in plans:
        covered.extend(range(p.inbound_base, p.inbound_base + p.conn_count))
    assert covered == list(range(2600, 2608))
    # Each process binds ONE distinct local sink port; index bases are 0..5 (id disjointness).
    assert [p.sink_base for p in plans] == [40000, 40001, 40002, 40003, 40004, 40005]
    assert [p.index for p in plans] == [0, 1, 2, 3, 4, 5]
    assert all(p.sink_ports == 1 for p in plans)


def test_plan_driver_bands_clamps_procs_to_count() -> None:
    # A cell smaller than the sink-process count never yields a zero-connection band.
    plans = bb.plan_driver_bands(inbound_base=2600, count=3, sink_base=40000, sink_procs=6)
    assert len(plans) == 3
    assert sum(p.conn_count for p in plans) == 3
    assert all(p.conn_count >= 1 for p in plans)


def test_plan_driver_bands_rejects_bad_input() -> None:
    with pytest.raises(ConnScaleError):
        bb.plan_driver_bands(inbound_base=2600, count=0, sink_base=40000, sink_procs=6)


def test_build_remote_argv_shape() -> None:
    plan = bb.BandPlan(index=2, inbound_base=2604, conn_count=1, sink_base=40002, sink_ports=1)
    argv = bb.build_remote_argv(
        plan,
        engine_host="10.0.0.5",
        api_port=9001,
        sink_host="0.0.0.0",
        per_conn_rate=3.0,
        hold_seconds=60.0,
        drain_timeout=300.0,
        report_path=Path("out/x.json"),
    )
    assert argv[1:4] == ["-m", "harness", "connscale-remote"]
    assert "--engine-url" in argv and "http://10.0.0.5:9001" in argv
    assert argv[argv.index("--inbound-base") + 1] == "2604"
    assert argv[argv.index("--sink-base") + 1] == "40002"
    assert argv[argv.index("--engine-index-base") + 1] == "2"
    assert argv[argv.index("--count") + 1] == "1"


def _fake_proc(sent: int, sink: int, read: float, arm_b1: bool) -> dict[str, Any]:
    return {
        "traffic": {"sent": sent, "acked": sent, "nak": 0, "deferred": 1, "timeouts": 0},
        "no_loss": {
            "ok": True,
            "sent": sent,
            "engine_read": 1_000_000,  # each proc polls the SAME engine -> engine TOTAL (>> its share)
            "engine_written": 0,
            "sink_received": sink,
            "backlog": 0,
            "detail": "",
        },
        "throughput": {
            "achieved_aggregate_rate": read,
            "delivered_aggregate_rate": read,
            "in_pipeline_peak": 0,
            "drain_seconds": 0.5,
        },
        "offered_aggregate_rate": float(sent),
    }


def test_aggregate_cell_record_sums_client_maxes_engine() -> None:
    cells = bb.iter_batch_cells(_profile(), claim_mode="pooled")
    cell = cells[3]  # a B1 cell
    reports = [_fake_proc(sent=10, sink=10, read=150.0, arm_b1=True) for _ in range(6)]
    rec = bb.aggregate_cell_record(cell, reports)
    # Client counters SUMMED across the disjoint bands; engine totals taken as the MAX (not 6x).
    assert rec.sent == 60 and rec.no_loss.sink_received == 60 and rec.deferred == 6
    assert rec.no_loss.engine_read == 1_000_000  # the engine total, not summed
    assert rec.achieved_read_per_s == 150.0  # the ceiling = engine intake, taken as max
    assert rec.offered_aggregate_rate == 60.0
    # The record is tagged with the cell's arm so build_batch_comparison groups it correctly.
    assert rec.batch_handoff_statements is True and rec.fuse_thread_hops is False
    assert rec.claim_mode == "pooled" and rec.no_loss.ok is True


def test_aggregate_cell_record_flags_loss() -> None:
    cell = bb.iter_batch_cells(_profile(), claim_mode="pooled")[0]
    # sink_received (union) < engine_written -> deliver shortfall -> no_loss fails.
    bad = {
        "traffic": {"sent": 10, "acked": 10, "nak": 0, "deferred": 0, "timeouts": 0},
        "no_loss": {
            "ok": False,
            "sent": 10,
            "engine_read": 100,
            "engine_written": 100,
            "sink_received": 1,
            "backlog": 0,
            "detail": "",
        },
        "throughput": {
            "achieved_aggregate_rate": 5.0,
            "delivered_aggregate_rate": 5.0,
            "in_pipeline_peak": 0,
            "drain_seconds": 0.5,
        },
        "offered_aggregate_rate": 10.0,
    }
    rec = bb.aggregate_cell_record(cell, [bad])
    assert rec.no_loss.ok is False and "sink_received" in rec.no_loss.detail


def test_aggregate_cell_record_drain_timeout_poisons() -> None:
    cell = bb.iter_batch_cells(_profile(), claim_mode="pooled")[0]
    ok_proc = _fake_proc(10, 10, 100.0, arm_b1=False)
    timed_out = _fake_proc(10, 10, 100.0, arm_b1=False)
    timed_out["throughput"]["drain_seconds"] = None  # one band never drained
    rec = bb.aggregate_cell_record(cell, [ok_proc, timed_out])
    assert rec.drain_seconds is None  # None poisons the worst-case drain


# --------------------------------------------------------------------------------------------------
# Fakes for the engine + driver halves
# --------------------------------------------------------------------------------------------------


def _install_engine_fakes(monkeypatch: pytest.MonkeyPatch) -> types.SimpleNamespace:
    rec = types.SimpleNamespace(node_envs=[], node_ids=[], started=[], resets=[])
    counter = {"pid": 30000}

    class FakeNode:
        def __init__(
            self, node_id: str, api_port: int, *, env: Mapping[str, str], config_dir: str, cwd: Any
        ) -> None:
            self.node_id = node_id
            self.api_port = api_port
            self.env = dict(env)
            self.url = f"http://127.0.0.1:{api_port}"
            counter["pid"] += 1
            self.pid: int | None = counter["pid"]
            rec.node_envs.append(self.env)
            rec.node_ids.append(node_id)

        async def start(self) -> None:
            rec.started.append(self.node_id)

        async def stop(self) -> None:
            return None

        def log_tail(self, limit: int = 4000) -> str:
            return ""

    async def fake_await_node_healthy(node: Any, *, timeout: float) -> None:
        return None

    async def fake_await_port(host: str, port: int, *, timeout: float) -> None:
        return None

    async def fake_reset(backend: str, env: Mapping[str, str]) -> tuple[int, int]:
        rec.resets.append(backend)
        return 0, 0

    monkeypatch.setattr(bb, "EngineNode", FakeNode)
    monkeypatch.setattr(bb, "_await_node_healthy", fake_await_node_healthy)
    monkeypatch.setattr(bb, "_await_port", fake_await_port)
    monkeypatch.setattr(bb, "_reset_server_store", fake_reset)
    return rec


def _install_driver_fakes(monkeypatch: pytest.MonkeyPatch) -> types.SimpleNamespace:
    rec = types.SimpleNamespace(spawned=[])

    async def fake_run_remote_proc(argv: list[str], report_path: Path, cwd: Path) -> dict[str, Any]:
        rec.spawned.append(list(argv))
        # The arm is recoverable from the per-proc report filename (it carries the cell id).
        b1 = "-bt1-" in report_path.name
        share = int(argv[argv.index("--count") + 1])
        # B1 (batching on) shows a clean +50% intake lift over B0, identical across trials -> GO.
        read = 150.0 if b1 else 100.0
        return _fake_proc(sent=share, sink=share, read=read, arm_b1=b1)

    monkeypatch.setattr(bb, "_run_remote_proc", fake_run_remote_proc)
    return rec


# --------------------------------------------------------------------------------------------------
# Full matrix handshake in lockstep (engine + driver concurrently on one PC)
# --------------------------------------------------------------------------------------------------


async def test_batch_split_handshake_end_to_end(monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio

    eng_rec = _install_engine_fakes(monkeypatch)
    drv_rec = _install_driver_fakes(monkeypatch)
    profile = _profile()
    engine_ip, loadgen_ip = "10.0.0.5", "10.0.0.9"

    with tempfile.TemporaryDirectory() as tmp:
        coord = FileDropCoord(tmp, run_id="batch_ab")
        engine = asyncio.create_task(
            bb.run_batch_engine(
                profile=profile,
                claim_mode="pooled",
                coord=coord,
                store_env={},
                inbound_bind_host="0.0.0.0",
                sink_host=loadgen_ip,
                sink_base=40000,
                sink_procs=6,
                cell_timeout=10.0,
            )
        )
        driver = asyncio.create_task(
            bb.run_batch_driver(
                profile=profile,
                claim_mode="pooled",
                engine_host=engine_ip,
                coord=coord,
                sink_host=loadgen_ip,
                report_dir=Path(tmp) / "reports",
                cell_timeout=10.0,
            )
        )
        eng_report, drv_report = await asyncio.gather(engine, driver)

        cells = bb.iter_batch_cells(profile, claim_mode="pooled")
        # Every cell's READY and DONE round-tripped (per-cell pairing across the whole matrix).
        for cell in cells:
            cc = coord.for_run(f"batch_ab.{cell.cell_id}")
            ready = cc.read(BATCH_CELL_READY)
            done = cc.read(BATCH_CELL_DONE)
            assert ready is not None, f"no READY for {cell.cell_id}"
            assert done is not None, f"no DONE for {cell.cell_id}"
            # The engine PID + node identity landed in READY (external per-PID CPU correlation).
            assert ready["engine"]["pid"] is not None
            assert ready["engine"]["role"] == "connscale-engine"
            assert ready["batch_mode"] == cell.batch_mode

    # (1) The engine launched one connscale engine per cell with the batch flag toggled per arm + the
    #     claim mode pinned; fusion OFF in both arms.
    assert len(eng_rec.node_envs) == len(cells)
    for env, cell in zip(eng_rec.node_envs, cells):
        want = "true" if cell.batch_mode else "false"
        assert env["MEFOR_PIPELINE_BATCH_HANDOFF_STATEMENTS"] == want
        assert env["MEFOR_PIPELINE_FUSE_THREAD_HOPS"] == "false"
        assert env["MEFOR_PIPELINE_CLAIM_MODE"] == "pooled"
        assert env["MEFOR_INBOUND_BIND_HOST"] == "0.0.0.0"
        assert env["MEFOR_CONNSCALE_SINK_HOST"] == loadgen_ip

    # (2) The engine report carries every cell's PID + node id for CPU correlation.
    assert len(eng_report.cells) == len(cells)
    assert all(c.pid is not None and c.error is None for c in eng_report.cells)
    assert eng_report.ok

    # (3) The driver spawned the >= 6 sink-PROCESS fleet per cell (6 procs x 6 cells) and aggregated
    #     each cell's per-proc reports into ONE record tagged with the cell arm.
    assert len(drv_rec.spawned) == 6 * len(cells)
    assert len(drv_report.records) == len(cells)
    assert [r.batch_handoff_statements for r in drv_report.records] == [c.batch_mode for c in cells]
    # Each record summed its 6 bands' sent to the cell's count (8).
    assert all(r.sent == 8 for r in drv_report.records)

    # (4) The B0/B1 batch verdict was computed from the aggregated records: a clean +50% lift -> GO.
    assert drv_report.batch_comparison is not None
    assert drv_report.batch_comparison.overall_verdict == FUSE_GO
    assert drv_report.exit_code == 0


async def test_batch_engine_claim_mode_per_lane(monkeypatch: pytest.MonkeyPatch) -> None:
    """--claim-mode threads to MEFOR_PIPELINE_CLAIM_MODE on every engine subprocess (ADR 0066 §8.2)."""
    import asyncio

    eng_rec = _install_engine_fakes(monkeypatch)
    profile = _profile()

    with tempfile.TemporaryDirectory() as tmp:
        coord = FileDropCoord(tmp, run_id="batch_ab")

        async def stub_driver() -> None:
            # Stand in for the load-gen box: for each cell, consume READY and post DONE at once.
            for cell in bb.iter_batch_cells(profile, claim_mode="per_lane"):
                cc = coord.for_run(f"batch_ab.{cell.cell_id}")
                await cc.await_message(BATCH_CELL_READY, timeout=10.0, interval=0.02)
                cc.post(BATCH_CELL_DONE, {"cell_id": cell.cell_id})

        engine = asyncio.create_task(
            bb.run_batch_engine(
                profile=profile,
                claim_mode="per_lane",
                coord=coord,
                store_env={},
                cell_timeout=10.0,
            )
        )
        await asyncio.gather(engine, stub_driver())

    assert eng_rec.node_envs
    assert all(env["MEFOR_PIPELINE_CLAIM_MODE"] == "per_lane" for env in eng_rec.node_envs)


# --------------------------------------------------------------------------------------------------
# CLI flag threading
# --------------------------------------------------------------------------------------------------


def test_batch_engine_cli_threads_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    import harness.__main__ as hmain

    captured: dict[str, Any] = {}

    async def fake_engine(**kwargs: Any) -> Any:
        captured.update(kwargs)
        return types.SimpleNamespace(render=lambda: "", to_json_dict=lambda: {}, ok=True)

    monkeypatch.setattr("harness.load.connscale.batchbox.run_batch_engine", fake_engine)
    with tempfile.TemporaryDirectory() as tmp:
        rc = hmain.main(
            [
                "batch-engine",
                "--profile",
                "batch_ab",
                "--claim-mode",
                "per_lane",
                "--sink-host",
                "10.0.0.9",
                "--inbound-bind-host",
                "0.0.0.0",
                "--sink-base",
                "41000",
                "--sink-procs",
                "8",
                "--api-base",
                "9100",
                "--coord-dir",
                tmp,
                "--run-id",
                "cli",
            ]
        )
    assert rc == 0
    assert captured["claim_mode"] == "per_lane"
    assert captured["sink_host"] == "10.0.0.9"
    assert captured["inbound_bind_host"] == "0.0.0.0"
    assert captured["sink_base"] == 41000
    assert captured["sink_procs"] == 8
    assert captured["api_base"] == 9100
    assert captured["coord"].run_id == "cli"
    assert captured["profile"].name == "batch_ab"


def test_batch_driver_cli_threads_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    import harness.__main__ as hmain

    captured: dict[str, Any] = {}

    async def fake_driver(**kwargs: Any) -> Any:
        captured.update(kwargs)
        return types.SimpleNamespace(
            render_console=lambda: "",
            to_json=lambda: "{}",
            exit_code=0,
            batch_comparison=None,
        )

    monkeypatch.setattr("harness.load.connscale.batchbox.run_batch_driver", fake_driver)
    with tempfile.TemporaryDirectory() as tmp:
        rc = hmain.main(
            [
                "batch-driver",
                "--profile",
                "batch_ab",
                "--claim-mode",
                "pooled",
                "--engine-host",
                "10.0.0.5",
                "--sink-host",
                "0.0.0.0",
                "--coord-dir",
                tmp,
                "--run-id",
                "cli",
            ]
        )
    assert rc == 0
    assert captured["engine_host"] == "10.0.0.5"
    assert captured["sink_host"] == "0.0.0.0"
    assert captured["claim_mode"] == "pooled"
    assert captured["coord"].run_id == "cli"


# --------------------------------------------------------------------------------------------------
# FIX 2 — aggregate defense-in-depth: full-band-count guard + null-engine-gauge hard error
# --------------------------------------------------------------------------------------------------


def test_aggregate_cell_record_rejects_short_band_count() -> None:
    """A partial fleet (fewer band reports than the planned bands) cannot fold into a trustworthy
    aggregate — it is a HARD error, not a spuriously-low but valid-looking record."""
    cell = bb.iter_batch_cells(_profile(), claim_mode="pooled")[0]
    reports = [_fake_proc(sent=10, sink=10, read=100.0, arm_b1=False) for _ in range(3)]
    with pytest.raises(ConnScaleError):
        bb.aggregate_cell_record(cell, reports, expected_bands=6)  # planned 6 bands, got 3
    # Matching the expected band count still folds normally (no false positive).
    rec = bb.aggregate_cell_record(cell, reports, expected_bands=3)
    assert rec.sent == 30


def test_aggregate_cell_record_rejects_null_engine_gauge() -> None:
    """A null/missing engine total (engine_read / engine_written / backlog) is a HARD error — never
    coerced to 0, which would fake a drained backlog or a low intake ceiling."""
    cell = bb.iter_batch_cells(_profile(), claim_mode="pooled")[0]
    for key in ("engine_read", "engine_written", "backlog"):
        bad = _fake_proc(sent=10, sink=10, read=100.0, arm_b1=False)
        bad["no_loss"][key] = None
        with pytest.raises(ConnScaleError):
            bb.aggregate_cell_record(cell, [bad])
    # A missing key (not just an explicit None) is caught the same way.
    missing = _fake_proc(sent=10, sink=10, read=100.0, arm_b1=False)
    del missing["no_loss"]["engine_read"]
    with pytest.raises(ConnScaleError):
        bb.aggregate_cell_record(cell, [missing])


def test_failed_cell_record_is_a_tagged_loss() -> None:
    cell = bb.iter_batch_cells(_profile(), claim_mode="pooled")[3]  # a B1 cell
    rec = bb._failed_cell_record(cell, "boom")
    assert rec.no_loss.ok is False and "boom" in rec.no_loss.detail
    assert rec.drain_seconds is None  # a cell that never ran never drained (poisons the worst case)
    # Tagged with the cell's A/B arm so the batch comparison groups + fails it, not a mystery record.
    assert rec.batch_handoff_statements is cell.batch_mode
    assert rec.fuse_thread_hops is cell.fuse_mode and rec.claim_mode == cell.claim_mode


# --------------------------------------------------------------------------------------------------
# FIX 1 — a crashed remote band FAILS the cell (surfaces in the verdict), never silently ABSENT
# --------------------------------------------------------------------------------------------------


async def test_batch_driver_crashed_band_fails_cell_not_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import asyncio

    # A profile that gates on zero-loss so the failed cell surfaces as an SLO failure in the verdict.
    profile = load_connscale_profile_text(_MINIMAL_BATCH + "\n[connscale.slo]\nzero_loss = true\n")

    async def boom(argv: list[str], report_path: Path, cwd: Path) -> dict[str, Any]:
        raise OSError("connscale-remote crashed")

    monkeypatch.setattr(bb, "_run_remote_proc", boom)

    with tempfile.TemporaryDirectory() as tmp:
        coord = FileDropCoord(tmp, run_id="batch_ab")
        cells = bb.iter_batch_cells(profile, claim_mode="pooled")

        async def stub_engine() -> None:
            # Stand in for the engine box: advertise each cell's topology, then consume its DONE.
            for cell in cells:
                cc = coord.for_run(f"batch_ab.{cell.cell_id}")
                cc.post(
                    BATCH_CELL_READY,
                    {
                        "cell_id": cell.cell_id,
                        "batch_mode": cell.batch_mode,
                        "sweep_mode": cell.sweep_mode,
                        "count": cell.count,
                        "trial": cell.trial,
                        "inbound_base": 20000,
                        "api_port": 9000,
                        "sink_base": 40000,
                        "sink_procs": 6,
                        "hold_seconds": profile.hold_seconds,
                        "drain_timeout_s": profile.drain_timeout_s,
                        "aggregate_rate": 24.0,
                    },
                )
                await cc.await_message(BATCH_CELL_DONE, timeout=10.0, interval=0.02)

        driver_task = asyncio.create_task(
            bb.run_batch_driver(
                profile=profile,
                claim_mode="pooled",
                engine_host="10.0.0.5",
                coord=coord,
                sink_host="0.0.0.0",
                report_dir=Path(tmp) / "reports",
                cell_timeout=10.0,
            )
        )
        _, report = await asyncio.gather(stub_engine(), driver_task)

    # (1) Every cell is PRESENT as a failed/loss record (not silently absent) tagged with its arm.
    assert len(report.records) == len(cells)
    assert [r.batch_handoff_statements for r in report.records] == [c.batch_mode for c in cells]
    assert all(r.no_loss.ok is False for r in report.records)
    assert all("cell drive failed" in r.no_loss.detail for r in report.records)
    # (2) The failure SURFACES in the verdict: the zero-loss SLO fails + the run exits non-zero.
    zero_loss = next((s for s in report.slos if s.name == "zero_loss"), None)
    assert zero_loss is not None and zero_loss.ok is False
    assert report.exit_code != 0
