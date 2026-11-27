# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Shard-certification verdicts and the kill leg (BACKLOG #5440, #5441, #5575).

Two halves.

* The verdict tests build reports only through :func:`_build`, which drops a field the class does not
  have. They therefore also IMPORT and RUN against the code before each fix (engine PR 2974's parent
  ``1adbbe5bfd9`` for #5575, PR 3083's parent ``0abad1ab46d`` for #5440 and #5441), where the field that
  carries the defect did not exist yet; there each defect arm fails on its assertion, not on a
  ``TypeError``. The PRs' own tests construct the new fields directly, so against the pre-fix code they
  fail on the constructor and record nothing about the verdict.
* The kill-leg tests (S27-55, S27-56, S27-57, the unadjudicated items of #5440) drive ``run_shardcert``
  and ``run_shardcert_engine`` over the offline fakes of ``tests/test_shardcert_two_box.py``: no
  subprocess, no store, no network.
"""

from __future__ import annotations

import asyncio
import dataclasses
import types
from pathlib import Path
from typing import Any

import pytest

import harness.load.shardcert as sc
from harness.config.shardcert._shape import (
    BROADCAST,
    destinations_for_seq,
    fifo_lane,
    fifo_lane_destination,
)
from harness.load.coord import DRIVE_START, FileDropCoord
from harness.load.failover_track import FailoverTracker
from tests.test_shardcert_two_box import _install_fakes


def _build(cls: type[Any], **kw: object) -> Any:
    """``cls(**kw)`` without the keys ``cls`` has no field for, so one test body runs before and after
    the fix that added the field."""
    names = {f.name for f in dataclasses.fields(cls)}
    return cls(**{k: v for k, v in kw.items() if k in names})


def _report(**over: object) -> sc.ShardCertReport:
    """A healthy co-located broadcast report: 1000 ACKed messages, D = 8, every copy arrived."""
    base: dict[str, object] = {
        "shards": ("s1", "s2"),
        "owned": {"s1": ["OB_1"], "s2": ["OB_2"]},
        "killed_shard": None,
        "sent": 1000,
        "acked": 1000,
        "delivered_distinct": 1000,
        "sink_received": 8000,
        "acked_not_delivered": 0,
        "lane_inversions": 0,
        "lanes_observed": 16,
        "lane_repeats": 0,
        "engine_done": 8000,
        "engine_dead": 0,
        "in_pipeline_final": 0,
        "drained": True,
        "drain_seconds": 2.0,
        "stranded_nonterminal": 0,
        "queue_breakdown": "",
        "offered": 1000,
        "achieved_intake": 1000,
        "dests": 8,
        "handlers": 8,
        "delivering": 8,
        "routing": BROADCAST,
        "acked_copies_missing": 0,
        "dead_total": 0,
    }
    base.update(over)
    rep: sc.ShardCertReport = _build(sc.ShardCertReport, **base)
    return rep


def _ladder(*reports: sc.ShardCertReport) -> sc.ShardCertLadderReport:
    return sc.ShardCertLadderReport(
        records=[
            sc.ShardCertStepRecord.from_report(10.0 * (i + 1), rep, hold_seconds=60.0)
            for i, rep in enumerate(reports)
        ]
    )


def test_control_report_and_ladder_pass() -> None:
    """The control every arm below is measured against passes, before and after each fix."""
    assert _report().ok is True
    assert _ladder(_report(), _report()).ok is True


# --- BACKLOG #5575: a fan-out run that lost most of its copies -------------------------------------------


def test_fanout_run_that_lost_seven_of_eight_copies_fails() -> None:
    """Only destination 0 of 8 ever received a copy, so every ACKed message reached SOME sink and
    ``acked_not_delivered`` is 0, while 7000 of the 8000 expected copies never arrived."""
    tracker = FailoverTracker()
    for seq in range(1000):
        tracker.on_ack(seq)
        tracker.on_delivery(fifo_lane("s1", 0), seq)
    missing = tracker.acked_copies_missing(
        lambda seq: destinations_for_seq(seq, routing=BROADCAST, dests=8, fanout=8),
        fifo_lane_destination,
    )
    assert (tracker.acked_not_delivered(), missing) == (0, 7000)
    rep = _report(sink_received=1000, engine_done=1000, acked_copies_missing=missing)
    assert rep.ok is False
    assert sc.ShardCertStepRecord.from_report(16.0, rep).no_loss is False


# --- BACKLOG #5440: work dead-lettered at the routed stage ------------------------------------------------


def test_routed_stage_dead_letters_fail_the_single_box_report() -> None:
    """A handler that delivers nothing dead-lettered every message at the routed stage: no sink copy is
    missing and the outbound-scoped ``engine_dead`` reads 0. Only the store's all-stage count sees it."""
    rep = _report(dead_total=1000)
    assert rep.engine_dead == 0
    assert rep.ok is False


# --- BACKLOG #5441: the ladder holds each rung to the single-run bar --------------------------------------


@pytest.mark.parametrize(
    "over",
    [
        pytest.param({"lane_repeats": 3}, id="duplicate-deliveries"),
        pytest.param({"lanes_observed": 1}, id="single-lane"),
        pytest.param({"engine_dead": 2}, id="outbound-dead-letters"),
        pytest.param({"dead_total": 2}, id="routed-dead-letters"),
        pytest.param(
            {
                "acked": 0,
                "achieved_intake": 0,
                "offered": 0,
                "delivered_distinct": 0,
                "sink_received": 0,
            },
            id="nothing-acked",
        ),
    ],
)
def test_ladder_fails_a_rung_the_single_run_bar_refuses(over: dict[str, int]) -> None:
    lad = _ladder(_report(), _report(**over))
    assert lad.ok is False
    assert lad.exit_code == 1


# --- #5440 item 1: the kill leg (S27-55, S27-56, S27-57) -------------------------------------------------


@pytest.fixture
def fleet(monkeypatch: pytest.MonkeyPatch) -> types.SimpleNamespace:
    """The two-box test's offline fakes, two engine shards of one lane each, with every node's lifecycle
    logged as ``(event, node index)`` in ``rec.events``. ``rec.fail_start`` names the engine shards, or
    the node indexes, whose start raises."""
    monkeypatch.setenv("MEFOR_SHARDCERT_SHARDS", "a,b")
    monkeypatch.delenv("MEFOR_SHARDCERT_LANES_PER_SHARD", raising=False)
    monkeypatch.delenv("MEFOR_SHARDCERT_PERSISTENT", raising=False)
    # run_shardcert builds the node env from os.environ: an operator's keep directory must not be touched.
    monkeypatch.delenv("MEFOR_BENCH_KEEP_NODE_LOGS", raising=False)
    rec = _install_fakes(monkeypatch)
    rec.events = []
    rec.fail_start = set()
    base: Any = sc.ShardCertNode

    class Node(base):  # type: ignore[misc]
        """Logs start/kill/stop and, under MEFOR_BENCH_KEEP_NODE_LOGS, keeps a log the way EngineNode
        does: ``<dir>/<node_id>.log``, opened for writing when the node is built."""

        def __init__(self, shard: str, api_port: int, **kw: Any) -> None:
            super().__init__(shard, api_port, **kw)
            self.index = len(rec.nodes) - 1
            self.stops = 0
            keep = self.env.get("MEFOR_BENCH_KEEP_NODE_LOGS")
            self.log = None
            if keep:
                Path(keep).mkdir(parents=True, exist_ok=True)
                self.log = open(Path(keep) / f"{self.node_id}.log", "wb")  # noqa: SIM115

        async def start(self, *, provision: bool = True) -> None:
            rec.events.append(("start", self.index))
            if self.shard in rec.fail_start or self.index in rec.fail_start:
                raise RuntimeError(f"node {self.index} failed to start")
            if self.log is not None:
                self.log.write(f"log of node {self.index}\n".encode())

        def kill(self) -> None:
            super().kill()
            rec.events.append(("kill", self.index))

        async def stop(self) -> None:
            self.stops += 1
            rec.events.append(("stop", self.index))
            if self.log is not None:
                self.log.close()

    monkeypatch.setattr(sc, "ShardCertNode", Node)
    return rec


def _sizes(**over: Any) -> dict[str, Any]:
    kw: dict[str, Any] = {
        "dests": 2,
        "aggregate_rate": 40.0,
        "hold_seconds": 0.2,
        "drain_timeout": 2.0,
        "store_env": {},
    }
    kw.update(over)
    return kw


@pytest.mark.parametrize(
    "over",
    [
        pytest.param({"kill_at_fraction": 1.0}, id="fraction-1"),
        pytest.param({"kill_at_fraction": 1.5}, id="fraction-above-1"),
        pytest.param({"kill_at_fraction": 0.0}, id="fraction-0-kills-before-any-load"),
        pytest.param({"kill_at_fraction": -0.1}, id="fraction-negative"),
        pytest.param({"kill_at_fraction": float("nan")}, id="fraction-nan"),
        pytest.param({"kill_shard": "zz"}, id="unknown-shard"),
    ],
)
async def test_colocated_kill_leg_that_cannot_kill_under_load_is_refused_before_launch(
    fleet: types.SimpleNamespace, over: dict[str, Any]
) -> None:
    """S27-55 (1) and (2). Before the fix a fraction of 1 never fired the kill, then started a second
    process over the live engine shard; an unknown one raised KeyError mid-hold after the whole fleet ran."""
    with pytest.raises(ValueError, match="kill_(at_fraction|shard)") as refused:
        await sc.run_shardcert(**_sizes(kill=True, **over))
    assert isinstance(refused.value, sc.KillLegError)
    assert fleet.nodes == []
    assert fleet.resets == []


async def test_engine_kill_leg_with_an_unknown_shard_is_refused_before_launch(
    fleet: types.SimpleNamespace, tmp_path: Path
) -> None:
    coord = FileDropCoord(tmp_path, run_id="unknown")
    with pytest.raises(ValueError, match="kill_(at_fraction|shard)") as refused:
        await sc.run_shardcert_engine(
            dests=2,
            hold_seconds=0.2,
            kill=True,
            kill_shard="zz",
            drain_timeout=2.0,
            sink_port=47100,
            store_env={},
            coord=coord,
            inbound_bind_host="127.0.0.1",
            post_drain_grace=0.0,
        )
    assert isinstance(refused.value, sc.KillLegError)
    assert fleet.nodes == []
    assert fleet.resets == []
    # The drive half is told at once rather than waiting out its SHARDS_READY timeout.
    assert coord.read(sc.ENGINE_SETUP_FAILED) is not None


def test_kill_leg_settings_are_not_read_without_a_kill() -> None:
    sc.require_kill_leg(False, "zz", 7.0, [])
    sc.require_kill_leg(True, None, 0.01, ["a", "b"])
    sc.require_kill_leg(True, "b", 0.99, ["a", "b"])
    with pytest.raises(sc.KillLegError, match="no engine shard"):
        sc.require_kill_leg(True, None, 0.5, [])


async def test_colocated_kill_fires_inside_the_hold_when_ticks_are_far_apart(
    fleet: types.SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    """S27-55 (1), the in-range case: ticks further apart than the hold's remainder. The first tick is
    before the deadline and the next is past the hold, so before the fix the loop ended unkilled, the
    restart started over the live engine shard, and the report still named it killed. The tick now wakes at
    the kill instant."""
    monkeypatch.setattr(sc, "_MAX_TICK_SLEEP", 0.3)
    rep = await sc.run_shardcert(
        **_sizes(aggregate_rate=1.0, hold_seconds=0.1, kill=True, kill_at_fraction=0.5)
    )
    killed = [i for ev, i in fleet.events if ev == "kill"]
    assert len(killed) == 1
    restart = next(n for n in fleet.nodes[2:] if n.shard == rep.killed_shard)
    assert fleet.nodes[killed[0]].shard == rep.killed_shard
    assert fleet.events.index(("kill", killed[0])) < fleet.events.index(("start", restart.index))
    assert rep.recovery_seconds is not None
    assert not any("after the load" in note for note in rep.notes)


async def test_colocated_kill_leg_stops_the_killed_node_and_keeps_its_log(
    fleet: types.SimpleNamespace, tmp_path: Path
) -> None:
    """S27-56. Before the fix the killed node was never stopped (its log handle and temp file leaked), and
    the restart reopened the same kept log for writing, which emptied the pre-kill log."""
    rep = await sc.run_shardcert(
        **_sizes(
            kill=True,
            kill_at_fraction=0.3,
            store_env={"MEFOR_BENCH_KEEP_NODE_LOGS": str(tmp_path)},
        )
    )
    assert len(fleet.nodes) == 3
    assert [n.stops for n in fleet.nodes] == [1, 1, 1]
    old = next(n for n in fleet.nodes[:2] if n.shard == rep.killed_shard)
    restart = fleet.nodes[2]
    assert fleet.events.index(("stop", old.index)) < fleet.events.index(("start", restart.index))
    log = f"shard-{rep.killed_shard}.log"
    assert (tmp_path / log).read_bytes() == f"log of node {old.index}\n".encode()
    assert (tmp_path / "restart" / log).read_bytes() == b"log of node 2\n"


async def test_colocated_node_whose_start_raises_is_still_stopped(
    fleet: types.SimpleNamespace,
) -> None:
    """S27-56: a node opens its log when it is built, so one whose start raised must be torn down too."""
    fleet.fail_start.add("b")
    with pytest.raises(RuntimeError, match="node 1 failed to start"):
        await sc.run_shardcert(**_sizes())
    assert [n.stops for n in fleet.nodes] == [1, 1]


async def test_colocated_restart_whose_start_raises_is_still_stopped(
    fleet: types.SimpleNamespace,
) -> None:
    """S27-56: the restart is registered before it starts, so the teardown stops it when its start raises,
    and the killed node it replaced was stopped before that."""
    fleet.fail_start.add(2)
    with pytest.raises(RuntimeError, match="node 2 failed to start"):
        await sc.run_shardcert(**_sizes(kill=True, kill_at_fraction=0.3))
    assert [n.stops for n in fleet.nodes] == [1, 1, 1]


async def test_colocated_kill_that_never_fired_under_load_fails_the_run(
    fleet: types.SimpleNamespace,
) -> None:
    """S27-55 (1): a hold that ends before the kill instant (here a hold of 0) certifies no kill leg.
    The run fails, no engine shard is killed after the load, and nothing restarts over a live one."""
    with pytest.raises(RuntimeError, match="kill leg never fired"):
        await sc.run_shardcert(**_sizes(hold_seconds=0.0, kill=True, kill_at_fraction=0.5))
    assert [ev for ev, _ in fleet.events if ev == "kill"] == []
    assert len(fleet.nodes) == 2
    assert [n.stops for n in fleet.nodes] == [1, 1]


async def test_engine_kill_leg_stops_the_killed_node(
    fleet: types.SimpleNamespace, tmp_path: Path
) -> None:
    coord = FileDropCoord(tmp_path, run_id="engine-kill")
    coord.post(DRIVE_START, {"t0": 0.0})
    rep = await sc.run_shardcert_engine(
        dests=2,
        hold_seconds=0.2,
        kill=True,
        kill_at_fraction=0.3,
        drain_timeout=2.0,
        sink_port=47200,
        store_env={},
        coord=coord,
        inbound_bind_host="127.0.0.1",
        post_drain_grace=0.0,
    )
    assert rep.recovery_seconds is not None
    assert [n.stops for n in fleet.nodes] == [1, 1, 1]


async def test_engine_kill_timer_is_cancelled_when_the_hold_is(
    fleet: types.SimpleNamespace, tmp_path: Path
) -> None:
    """S27-55 (3). Before the fix a cancelled hold left the SIGKILL timer pending, to fire on an engine shard of
    a run that was already torn down."""
    coord = FileDropCoord(tmp_path, run_id="engine-cancel")
    coord.post(DRIVE_START, {"t0": 0.0})
    engine = asyncio.create_task(
        sc.run_shardcert_engine(
            dests=2,
            hold_seconds=30.0,
            kill=True,
            kill_at_fraction=0.5,
            drain_timeout=2.0,
            sink_port=47300,
            store_env={},
            coord=coord,
            inbound_bind_host="127.0.0.1",
            post_drain_grace=0.0,
        )
    )
    for _ in range(200):
        if _pending_kill_timers():
            break
        await asyncio.sleep(0.01)
    else:
        pytest.fail("the engine never armed its kill timer")
    engine.cancel()
    with pytest.raises(asyncio.CancelledError):
        await engine
    await asyncio.sleep(0)
    assert _pending_kill_timers() == []
    assert all(n.stops == 1 for n in fleet.nodes)


def _pending_kill_timers() -> list[asyncio.Task[Any]]:
    return [
        t
        for t in asyncio.all_tasks()
        if not t.done() and getattr(t.get_coro(), "__name__", None) == "_kill_after"
    ]


def _summing_poller(*, done: int, dead: int) -> type[Any]:
    """A poller whose final sample is what EnginePoller sums over two engine shards that each read
    ``done`` / ``dead`` from the ONE unified store."""
    base: Any = vars(sc)["EnginePoller"]  # the fixture's fake, which the module now names

    class Poller(base):  # type: ignore[misc]
        def __init__(self, urls: Any, token: Any = None, **kw: Any) -> None:
            super().__init__(urls, token, **kw)
            self.final = types.SimpleNamespace(
                done=done * len(urls), dead=dead * len(urls), in_pipeline=0
            )

    return Poller


async def test_colocated_report_reads_the_store_count_not_the_shard_sum(
    fleet: types.SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    """S27-57: the report read engine_done and engine_dead as the sum over both engine shards, twice the store."""
    monkeypatch.setattr(sc, "EnginePoller", _summing_poller(done=400, dead=3))
    rep = await sc.run_shardcert(**_sizes())
    assert (rep.engine_done, rep.engine_dead) == (400, 3)


async def test_engine_report_reads_the_store_dead_count_not_the_shard_sum(
    fleet: types.SimpleNamespace, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(sc, "EnginePoller", _summing_poller(done=400, dead=3))
    coord = FileDropCoord(tmp_path, run_id="engine-dead")
    coord.post(DRIVE_START, {"t0": 0.0})
    rep = await sc.run_shardcert_engine(
        dests=2,
        hold_seconds=0.1,
        drain_timeout=2.0,
        sink_port=47400,
        store_env={},
        coord=coord,
        inbound_bind_host="127.0.0.1",
        post_drain_grace=0.0,
    )
    assert rep.engine_dead == 3


def test_restart_env_moves_only_the_keep_directory(tmp_path: Path) -> None:
    env = {"MEFOR_BENCH_KEEP_NODE_LOGS": str(tmp_path), "MEFOR_STORE_BACKEND": "sqlserver"}
    assert sc._restart_env(env) == {
        "MEFOR_BENCH_KEEP_NODE_LOGS": str(tmp_path / "restart"),
        "MEFOR_STORE_BACKEND": "sqlserver",
    }
    assert env["MEFOR_BENCH_KEEP_NODE_LOGS"] == str(tmp_path)  # the fleet's own env is not changed
    assert sc._restart_env({"MEFOR_STORE_BACKEND": "sqlserver"}) == {
        "MEFOR_STORE_BACKEND": "sqlserver"
    }
