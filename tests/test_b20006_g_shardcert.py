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
import sys
import time
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
    the node indexes, whose start raises; ``rec.kill_fails`` the engine shards whose ``kill()`` fails
    silently, as ``EngineNode.kill`` can; ``rec.already_exited`` those whose process had exited on its
    own before the kill. ``rec.kill_times`` and ``rec.submit_times`` hold the monotonic
    instants of each kill and each message offered; ``rec.stall_first_submit`` blocks the event loop
    for that many seconds on the first message, as a stalled loop would."""
    monkeypatch.setenv("MEFOR_SHARDCERT_SHARDS", "a,b")
    monkeypatch.delenv("MEFOR_SHARDCERT_LANES_PER_SHARD", raising=False)
    monkeypatch.delenv("MEFOR_SHARDCERT_PERSISTENT", raising=False)
    # run_shardcert builds the node env from os.environ: an operator's keep directory must not be touched.
    monkeypatch.delenv("MEFOR_BENCH_KEEP_NODE_LOGS", raising=False)
    rec = _install_fakes(monkeypatch)
    rec.events = []
    rec.fail_start = set()
    rec.kill_fails = set()
    rec.already_exited = set()
    rec.kill_times = []
    rec.submit_times = []
    rec.stall_first_submit = 0.0
    base: Any = sc.ShardCertNode
    # The fixture's fake, which the module now names.
    base_conn: Any = vars(sc)["PersistentConnection"]

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
            rec.kill_times.append(time.monotonic())
            rec.events.append(("kill", self.index))
            if self.shard in rec.already_exited:
                self.kill_calls += (
                    1  # gone already: kill() finds nothing running, and it stays gone
                )
            elif self.shard in rec.kill_fails:
                self.killed_while_running = True  # running, and the kill silently missed it
            else:
                super().kill()

        async def stop(self) -> None:
            self.stops += 1
            rec.events.append(("stop", self.index))
            if self.log is not None:
                self.log.close()

    class Conn(base_conn):  # type: ignore[misc]
        def submit_nowait(self, out: Any) -> bool:
            if not rec.submit_times and rec.stall_first_submit:
                time.sleep(rec.stall_first_submit)  # blocks the loop, as a stalled event loop would
            rec.submit_times.append(time.monotonic())
            return bool(super().submit_nowait(out))

    monkeypatch.setattr(sc, "ShardCertNode", Node)
    monkeypatch.setattr(sc, "PersistentConnection", Conn)
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
        pytest.param({"hold_seconds": 0.0}, id="hold-0"),
        pytest.param({"hold_seconds": -1.0}, id="hold-negative"),
        pytest.param({"hold_seconds": float("nan")}, id="hold-nan"),
    ],
)
async def test_colocated_kill_leg_that_cannot_kill_under_load_is_refused_before_launch(
    fleet: types.SimpleNamespace, over: dict[str, Any]
) -> None:
    """S27-55 (1) and (2). Before the fix a fraction of 1 never fired the kill, then started a second
    process over the live engine shard; an unknown one raised KeyError mid-hold after the whole fleet ran.
    A hold with no load to kill under is refused the same way."""
    with pytest.raises(ValueError, match=_REFUSED) as refused:
        await sc.run_shardcert(**_sizes(kill=True, **over))
    assert isinstance(refused.value, sc.KillLegError)
    assert fleet.nodes == []
    assert fleet.resets == []


#: What every KillLegError message names: the setting it refused.
_REFUSED = "kill_at_fraction|kill_shard|hold_seconds"


@pytest.mark.parametrize(
    "over",
    [
        pytest.param({"kill_at_fraction": 1.0}, id="fraction-1"),
        pytest.param({"kill_at_fraction": 0.0}, id="fraction-0"),
        pytest.param({"kill_at_fraction": -0.1}, id="fraction-negative"),
        pytest.param({"kill_at_fraction": float("nan")}, id="fraction-nan"),
        pytest.param({"kill_shard": "zz"}, id="unknown-shard"),
        pytest.param({"hold_seconds": 0.0}, id="hold-0"),
        pytest.param({"hold_seconds": -1.0}, id="hold-negative"),
        pytest.param({"hold_seconds": float("nan")}, id="hold-nan"),
    ],
)
async def test_engine_kill_leg_that_cannot_kill_under_load_is_refused_before_launch(
    fleet: types.SimpleNamespace, tmp_path: Path, over: dict[str, Any]
) -> None:
    """S27-55 (1) and (2), and the hold (BACKLOG #5440): before the fix the engine half armed its kill timer
    for a fraction outside the hold, or for a NaN or non-positive hold, which has no load to kill under."""
    coord = FileDropCoord(tmp_path, run_id="refused")
    kw: dict[str, Any] = {"hold_seconds": 0.2, **over}
    with pytest.raises(ValueError, match=_REFUSED) as refused:
        await sc.run_shardcert_engine(
            dests=2,
            kill=True,
            drain_timeout=2.0,
            sink_port=47100,
            store_env={},
            coord=coord,
            inbound_bind_host="127.0.0.1",
            post_drain_grace=0.0,
            **kw,
        )
    assert isinstance(refused.value, sc.KillLegError)
    assert fleet.nodes == []
    assert fleet.resets == []
    # The drive half is told at once rather than waiting out its SHARDS_READY timeout.
    assert coord.read(sc.ENGINE_SETUP_FAILED) is not None


async def test_engine_clears_a_stale_setup_failure_before_it_checks_the_kill_leg(
    fleet: types.SimpleNamespace, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An earlier run's refusal is gone before this run's discovery and kill-leg check, so a drive half
    started after this run began never reads it as this run's."""
    coord = FileDropCoord(tmp_path, run_id="stale")
    coord.post(sc.ENGINE_SETUP_FAILED, {"reason": "an earlier run"})
    assert coord.read(sc.ENGINE_SETUP_FAILED) is not None  # control: the stale refusal is readable
    seen: list[object] = []
    real_discover = sc._discover

    def discover(*args: Any, **kw: Any) -> Any:
        seen.append(coord.read(sc.ENGINE_SETUP_FAILED))
        return real_discover(*args, **kw)

    monkeypatch.setattr(sc, "_discover", discover)
    with pytest.raises(sc.KillLegError):
        await sc.run_shardcert_engine(
            dests=2,
            hold_seconds=0.2,
            kill=True,
            kill_shard="zz",
            drain_timeout=2.0,
            sink_port=47150,
            store_env={},
            coord=coord,
            inbound_bind_host="127.0.0.1",
            post_drain_grace=0.0,
        )
    assert seen == [None]


def test_kill_leg_settings_are_not_read_without_a_kill() -> None:
    sc.require_kill_leg(False, "zz", 7.0, [], float("nan"))
    sc.require_kill_leg(True, None, 0.01, ["a", "b"], 0.1)
    sc.require_kill_leg(True, "b", 0.99, ["a", "b"], 60.0)
    with pytest.raises(sc.KillLegError, match="no engine shard"):
        sc.require_kill_leg(True, None, 0.5, [], 60.0)
    with pytest.raises(sc.KillLegError, match="hold_seconds"):
        sc.require_kill_leg(True, None, 0.5, ["a", "b"], float("inf"))


@pytest.mark.parametrize(
    "flags",
    [
        pytest.param(["--kill-at-fraction", "1.5"], id="fraction"),
        pytest.param(["--kill-shard", "zz"], id="unknown-shard"),
        pytest.param(["--hold-seconds", "0"], id="hold-0"),
        pytest.param(["--hold-seconds", "nan"], id="hold-nan"),
    ],
)
def test_engine_cli_exits_2_on_a_refused_kill_leg(
    fleet: types.SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    flags: list[str],
) -> None:
    """BACKLOG #5440: the shardcert-engine CLI let KillLegError escape, so a refused setting exited 1 with
    a traceback, the code of a failed bench result. It is a setup error: exit 2 and one line."""
    import harness.__main__ as hmain

    # Own every variable the CLI writes directly, so monkeypatch restores it (the fixture's delenv of an
    # absent variable records nothing to restore).
    for k in (
        "MEFOR_SHARDCERT_SHARDS",
        "MEFOR_SHARDCERT_LANES_PER_SHARD",
        "MEFOR_SHARDCERT_PERSISTENT",
        "MEFOR_SHARDCERT_ROUTING",
    ):
        monkeypatch.setenv(k, "")
    monkeypatch.setenv("MEFOR_STORE_BACKEND", "sqlserver")
    argv = ["shardcert-engine", "--shards", "a,b", "--dests", "2", "--sink-port", "47500", "--kill"]
    argv += flags
    rc = hmain.main([*argv, "--coord-dir", str(tmp_path), "--run-id", "cli-kill"])
    err = capsys.readouterr().err
    assert rc == 2
    assert err.startswith("refusing to run: ")
    assert err.count("\n") == 1
    assert fleet.nodes == []


async def test_colocated_kill_fires_inside_the_hold_when_ticks_are_far_apart(
    fleet: types.SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    """S27-55 (1), the in-range case: ticks further apart than the hold's remainder. The first tick is
    before the deadline and the next is past the hold, so before the fix the loop ended unkilled, the
    restart started over the live engine shard, and the report still named it killed. The tick's sleep is
    now capped at the kill instant."""
    monkeypatch.setattr(sc, "_MAX_TICK_SLEEP", 1.5)
    rep = await sc.run_shardcert(
        **_sizes(aggregate_rate=1.0, hold_seconds=1.0, kill=True, kill_at_fraction=0.1)
    )
    killed = [i for ev, i in fleet.events if ev == "kill"]
    assert len(killed) == 1
    restart = next(n for n in fleet.nodes[2:] if n.shard == rep.killed_shard)
    assert fleet.nodes[killed[0]].shard == rep.killed_shard
    assert fleet.events.index(("kill", killed[0])) < fleet.events.index(("start", restart.index))
    assert rep.recovery_seconds is not None
    # Inside the hold: the first message is offered as the hold starts and the kill is due 0.1 s after it,
    # while a tick that slept to its own next wake (the next message, due at 1 s) would come back only at
    # the end of the 1 s hold. The 0.9 s between leaves room for a loaded runner.
    assert _kill_offset(fleet) < 1.0


def _kill_offset(rec: types.SimpleNamespace) -> float:
    """Seconds from the first message offered (the start of the hold) to the kill."""
    (kill_at,) = rec.kill_times
    return float(kill_at - rec.submit_times[0])


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
    """S27-55 (1): a loop that stalls past both the kill instant and the end of the hold certifies no kill
    leg. The run fails, no engine shard is killed after the load, and nothing restarts over a live one."""
    fleet.stall_first_submit = 0.3
    with pytest.raises(RuntimeError, match="kill leg never fired"):
        await sc.run_shardcert(**_sizes(hold_seconds=0.1, kill=True, kill_at_fraction=0.5))
    assert [ev for ev, _ in fleet.events if ev == "kill"] == []
    assert len(fleet.nodes) == 2
    assert [n.stops for n in fleet.nodes] == [1, 1]


async def test_colocated_kill_that_did_not_take_effect_fails_the_run(
    fleet: types.SimpleNamespace,
) -> None:
    """BACKLOG #5440: kill() can fail silently. Before the fix the restart stopped the still-running node
    GRACEFULLY and timed a recovery after it, certifying a graceful stop as crash recovery."""
    fleet.kill_fails.update({"a", "b"})
    with pytest.raises(RuntimeError, match="did not take effect"):
        await sc.run_shardcert(**_sizes(kill=True, kill_at_fraction=0.3))
    assert len(fleet.nodes) == 2  # nothing was restarted over the live engine shard
    assert [n.stops for n in fleet.nodes] == [1, 1]  # the teardown stopped it, not the restart


async def test_colocated_kill_of_an_engine_shard_that_had_already_exited_fails_the_run(
    fleet: types.SimpleNamespace,
) -> None:
    """BACKLOG #5440: an engine shard whose own crash was reaped before the kill was killed with no root
    left running, and the run certified a recovery from a crash the rig never caused. The run now fails
    for such a shard. A shard in a case ``ShardCertNode.killed_while_running`` names still gets past this
    check; no test here covers that."""
    fleet.already_exited.update({"a", "b"})
    with pytest.raises(RuntimeError, match="had already exited"):
        await sc.run_shardcert(**_sizes(kill=True, kill_at_fraction=0.3))
    assert len(fleet.nodes) == 2
    assert [n.stops for n in fleet.nodes] == [1, 1]


class _SleeperNode(sc.ShardCertNode):
    """The real ShardCertNode, over a sleeping interpreter instead of ``serve`` (the ``_exec`` seam)."""

    async def _exec(self, *argv: str) -> asyncio.subprocess.Process:
        return await super()._exec(sys.executable, "-c", "import time; time.sleep(60)")


async def test_real_node_wait_exited_sees_the_kill_and_only_the_kill(tmp_path: Path) -> None:
    """The real kill-took-effect check, not the fakes': a running node is not read as exited, a killed one
    is, and the kill records that the process was running when it came."""
    unstarted = _SleeperNode("u", 1, env={}, config_dir=str(tmp_path), cwd=tmp_path)
    try:
        assert await unstarted.wait_exited(0.1) is False
    finally:
        await unstarted.stop()
    node = _SleeperNode("a", 1, env={}, config_dir=str(tmp_path), cwd=tmp_path)
    try:
        await node.start(provision=False)
        assert node.killed_while_running is False
        assert await node.wait_exited(0.3) is False  # control: still running
        node.kill()
        assert node.killed_while_running is True
        assert await node.wait_exited(10.0) is True
        node.kill()  # a second kill finds it gone
        assert node.killed_while_running is False
    finally:
        await node.stop()


async def test_engine_kill_that_did_not_take_effect_fails_the_run(
    fleet: types.SimpleNamespace, tmp_path: Path
) -> None:
    fleet.kill_fails.update({"a", "b"})
    coord = FileDropCoord(tmp_path, run_id="engine-kill-failed")
    coord.post(DRIVE_START, {"t0": 0.0})
    with pytest.raises(RuntimeError, match="did not take effect"):
        await sc.run_shardcert_engine(
            dests=2,
            hold_seconds=0.2,
            kill=True,
            kill_at_fraction=0.3,
            drain_timeout=2.0,
            sink_port=47250,
            store_env={},
            coord=coord,
            inbound_bind_host="127.0.0.1",
            post_drain_grace=0.0,
        )
    assert [ev for ev, _ in fleet.events].count("kill") == 1
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
