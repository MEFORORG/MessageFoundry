# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Co-located round-trip for the WS-C two-box shardcert drive (ADR 0073), reconciled onto the #836
LANES-AWARE base.

These prove the engine/driver split WIRES + HANDSHAKES correctly OFFLINE on one PC over a temp coord
dir: the engine posts SHARDS_READY carrying the lanes-aware topology (``lanes`` + the sink port band),
the driver learns it and opens one MLLP connection per (shard, lane) = ``N*lanes`` total, and a short
drive reconciles no-loss via the ENGINE's store-truth (drained + no stranded non-terminal rows). Every
network collaborator (the ``serve --shard`` subprocess, the health/port preflights, the store reset, the
stranded-INFLIGHT query, the correlation sink, the senders, the ``/stats`` poller) is faked — there is no
real cross-box packet flow here (that + the ~450-500 msg/s number is the AWS rig's job; the live
single-box SS certification is ``tests/test_shard_cert_sqlserver.py``).

The two-box functions are SEPARATE from the single-box ``run_shardcert``: this file exercises only the
new engine/driver halves + the CLI arg-threading; the #836 single-box path + rate-ladder are unchanged.
"""

from __future__ import annotations

import asyncio
import types
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest

import harness.__main__ as hmain
import harness.load.shardcert as sc
from harness.config.shardcert._shape import (
    BROADCAST,
    PARTITIONED,
    PARTITIONED_FANOUT,
    destinations_for_seq,
    fifo_lane_destination,
)
from harness.load.coord import DRIVE_START, SHARDS_READY, FileDropCoord


def _install_fakes(monkeypatch: pytest.MonkeyPatch) -> types.SimpleNamespace:
    """Replace every network collaborator of the two-box engine/driver with a recorder, so the round
    trip completes offline and the test can assert exactly which ports/hosts each piece was wired to.
    ``_discover`` / ``_free_contiguous`` / ``_reset_store``-parity port reservation stay REAL, so the
    lanes-aware port math is genuinely exercised (only the sockets/subprocesses are faked)."""
    rec = types.SimpleNamespace(
        nodes=[],
        sink_hosts=[],
        sink_ports_bound=[],
        conn_hosts=[],
        conn_ports=[],
        awaited_ports=[],
        resets=[],
        queues=[],
        pollers=[],
    )

    class FakeNode:
        def __init__(
            self, shard: str, api_port: int, *, env: Mapping[str, str], config_dir: str, cwd: Any
        ) -> None:
            self.shard = shard
            self.api_port = api_port
            self.env = dict(env)
            self.node_id = f"shard-{shard}"
            self.url = f"http://127.0.0.1:{api_port}"
            self.pid: int | None = api_port  # stand-in PID so node_pids carries a non-None identity
            self.kill_calls = 0
            rec.nodes.append(self)

        async def start(self, *, provision: bool = True) -> None:
            # `provision` mirrors EngineNode.start: the kill leg restarts a shard on a store the
            # run already provisioned, and says so.
            return None

        def kill(self) -> None:
            # A local PID SIGKILL — recorded so a kill-leg test can prove it hit a LOCAL object.
            self.kill_calls += 1

        async def stop(self) -> None:
            return None

        def log_tail(self, limit: int = 4000) -> str:
            return ""

    class FakeSink:
        def __init__(
            self,
            ids: Any,
            correlator: Any,
            metrics: Any,
            *,
            host: str = "127.0.0.1",
            ports: Sequence[int] = (2700,),
            **kw: Any,
        ) -> None:
            rec.sink_hosts.append(host)
            rec.sink_ports_bound.append(tuple(ports))

        async def start(self) -> None:
            return None

        async def stop(self) -> None:
            return None

    class FakeConn:
        def __init__(
            self,
            host: str,
            port: int,
            correlator: Any,
            metrics: Any,
            *,
            expect_ack: bool = True,
            tracker: Any = None,
            **kw: Any,
        ) -> None:
            rec.conn_hosts.append(host)
            rec.conn_ports.append(port)

        def start(self) -> None:
            return None

        def submit_nowait(self, out: Any) -> bool:
            return True

        async def stop(self, grace: float) -> None:
            return None

    class FakePoller:
        def __init__(
            self,
            urls: Any,
            token: Any = None,
            *,
            origin: Any = None,
            allow_insecure: bool = False,
            cacert: str | None = None,
        ) -> None:
            self.final = types.SimpleNamespace(done=0, dead=0, in_pipeline=0)
            # What the two-box drives built their poller with: the scheme, the credential marker and
            # the anchor are the BACKLOG #5640 / #5977 wiring the tests below pin.
            rec.pollers.append(
                {
                    "urls": list(urls),
                    "token": token,
                    "allow_insecure": allow_insecure,
                    "cacert": cacert,
                }
            )

        async def open(self) -> None:
            return None

        async def await_drain(self, *, timeout: float, interval: float) -> float:
            return 0.01

        async def close(self) -> None:
            return None

    async def fake_await_health(url: str, *, timeout: float) -> bool:
        return True

    async def fake_await_port(host: str, port: int, *, timeout: float) -> bool:
        rec.awaited_ports.append((host, port))
        return True

    async def fake_reset_store(env: Mapping[str, str]) -> None:
        rec.resets.append(dict(env))

    async def fake_queue_breakdown(env: Mapping[str, str]) -> sc.QueueBreakdown:
        rec.queues.append(dict(env))
        # A clean store: nothing stranded, nothing dead, at any stage (BACKLOG #229 per-stage split).
        return sc.QueueBreakdown(
            nonterminal=0,
            dead_total=0,
            ingress_stranded=0,
            routed_stranded=0,
            outbound_stranded=0,
            summary="QUEUE <empty>",
        )

    monkeypatch.setattr(sc, "ShardCertNode", FakeNode)
    monkeypatch.setattr(sc, "CorrelationSink", FakeSink)
    monkeypatch.setattr(sc, "PersistentConnection", FakeConn)
    monkeypatch.setattr(sc, "EnginePoller", FakePoller)
    monkeypatch.setattr(sc, "_await_health", fake_await_health)
    monkeypatch.setattr(sc, "_await_port", fake_await_port)
    monkeypatch.setattr(sc, "_reset_store", fake_reset_store)
    monkeypatch.setattr(sc, "_queue_breakdown", fake_queue_breakdown)
    return rec


async def test_two_box_round_trip_lanes_aware(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Engine + driver run concurrently on ONE box over a temp coord dir: SHARDS_READY carries the
    lanes-aware + sink-band fields, the driver opens N*lanes connections at ``base + i*lanes + l``, and
    the engine reconciles no-loss via store-truth (drained + no stranded rows)."""
    # 2 shards x 2 lanes = 4 many-thin-lanes (proves N*lanes, not just N). The lanes/shards env drives
    # `_discover`'s REAL config load; monkeypatch restores them after the test.
    monkeypatch.setenv("MEFOR_SHARDCERT_SHARDS", "a,b")
    monkeypatch.setenv("MEFOR_SHARDCERT_LANES_PER_SHARD", "2")
    monkeypatch.delenv("MEFOR_SHARDCERT_PERSISTENT", raising=False)
    rec = _install_fakes(monkeypatch)

    coord_engine = FileDropCoord(tmp_path, run_id="rt")
    coord_driver = FileDropCoord(tmp_path, run_id="rt")

    engine = asyncio.create_task(
        sc.run_shardcert_engine(
            dests=3,
            hold_seconds=0.2,
            kill=False,
            drain_timeout=5.0,
            sink_port=47000,
            sink_ports=1,
            store_env={"MEFOR_STORE_BACKEND": "sqlserver"},
            coord=coord_engine,
            inbound_bind_host="127.0.0.1",
            sink_host="127.0.0.1",
            post_drain_grace=0.0,  # don't sleep the 3s operator grace in the test
        )
    )
    driver = asyncio.create_task(
        sc.run_shardcert_driver(
            engine_host="127.0.0.1",
            aggregate_rate=20.0,
            hold_seconds=0.2,
            drain_timeout=5.0,
            coord=coord_driver,
            sink_host="127.0.0.1",
        )
    )
    eng_report, drv_report = await asyncio.gather(engine, driver)

    # (1) SHARDS_READY carries the NEW lanes-aware + sink-band fields (plus the back-compat sink_port).
    ready = coord_engine.read(SHARDS_READY)
    assert ready is not None, "engine never posted SHARDS_READY"
    assert ready["shards"] == ["a", "b"]
    assert ready["lanes"] == 2
    assert ready["dests"] == 3
    assert ready["sink_base"] == 47000
    assert ready["sink_ports"] == 1
    assert ready["sink_port"] == 47000  # back-compat field retained for an older driver
    assert len(ready["api_ports"]) == 2
    assert [nd["role"] for nd in ready["nodes"]] == ["engine-shard", "engine-shard"]
    assert all(nd["pid"] is not None for nd in ready["nodes"])  # per-PID CPU correlation identity

    # The driver posted DRIVE_START (the second handshake message round-tripped).
    assert coord_engine.read(DRIVE_START) is not None

    # (2) The driver opened N*lanes = 2*2 = 4 connections, one per (shard, lane), at the contiguous
    #     ports base + i*lanes + l — NOT just N=2.
    inbound_base = int(ready["inbound_base"])
    expected_ports = [inbound_base + i * 2 + lane for i in range(2) for lane in range(2)]
    assert len(rec.conn_ports) == 4
    assert sorted(rec.conn_ports) == sorted(expected_ports)
    assert set(rec.conn_hosts) == {"127.0.0.1"}
    # The readiness preflight (both the engine's own inbound gate AND the driver's off-box reachability
    # check) dialed exactly the N*lanes lane ports on loopback.
    assert {p for _, p in rec.awaited_ports} == set(expected_ports)
    assert {h for h, _ in rec.awaited_ports} == {"127.0.0.1"}

    # (3) The engine reconciles no-loss via STORE-TRUTH: drained, no stranded non-terminal rows, no
    #     dead-letters. The engine is the store-truth reconcile owner (`ok`).
    assert eng_report.stranded_nonterminal == 0
    assert eng_report.drained is True
    assert eng_report.engine_dead == 0
    assert eng_report.dead_total == 0  # all-stage dead-letter count, not just outbound-scoped
    assert eng_report.ok
    assert set(eng_report.shards) == {"a", "b"}
    assert eng_report.killed_shard is None
    # The store reset + stranded query ran against the (engine-owned) store env, not a remote host.
    assert len(rec.resets) == 1 and rec.resets[0]["MEFOR_STORE_BACKEND"] == "sqlserver"
    assert len(rec.queues) == 1

    # The driver bound ONE sink (single-sink correctness topology) over the advertised band, on the
    # load-gen host, and threaded the shard set + killed=None (baseline).
    assert rec.sink_hosts == ["127.0.0.1"]
    assert rec.sink_ports_bound == [(47000,)]
    assert set(drv_report.shards) == {"a", "b"}
    assert drv_report.killed_shard is None


def test_engine_ok_fails_on_ingress_or_routed_dead_letter() -> None:
    """CONFIRMED gap (PR-B review): the engine store-truth `ok` must fail on a dead-letter at ANY
    stage, not only the outbound-scoped `engine_dead`. A router/handler regression dead-letters at the
    ingress|routed stage (`dead_letter_now` leaves `stage` unchanged), which `store.stats().dead`
    (outbound-only, so `engine_dead`) misses. Those rows were ACK-on-receipt'd, so a self-contained
    store-truth verdict has to catch them — the engine half can't lean on the driver half's sink-truth
    for its OWN exit code."""
    base: dict[str, Any] = dict(  # noqa: C408
        shards=("a", "b"),
        owned={"a": ["OB_SHARED_01"], "b": ["OB_SHARED_02"]},
        killed_shard=None,
        stranded_nonterminal=0,
        queue_breakdown="QUEUE ingress/dead=3 outbound/done=100",
        drained=True,
        engine_dead=0,  # outbound-scoped → blind to the ingress-stage dead rows
    )
    # dead_total>0 FAILS the verdict even though drained, nothing stranded, engine_dead==0.
    bad = sc.ShardCertEngineReport(**base, dead_total=3)
    assert bad.dead_total == 3
    assert not bad.ok
    render = bad.render()
    assert "verdict=FAIL" in render and "dead_total=3" in render
    # The same run with no dead rows at any stage passes (regression guard on the happy path).
    good = sc.ShardCertEngineReport(**base, dead_total=0)
    assert good.ok


async def test_two_box_sink_band_fans_out_ports(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """When the engine advertises a sink band wider than 1 (the PR-C fan-out seam), the driver binds the
    contiguous band ``sink_base .. sink_base+sink_ports-1`` — proven now so the field is load-bearing."""
    monkeypatch.setenv("MEFOR_SHARDCERT_SHARDS", "a,b")
    monkeypatch.delenv("MEFOR_SHARDCERT_LANES_PER_SHARD", raising=False)  # single fat lane
    rec = _install_fakes(monkeypatch)

    coord = FileDropCoord(tmp_path, run_id="band")
    engine = asyncio.create_task(
        sc.run_shardcert_engine(
            dests=2,
            hold_seconds=0.1,
            drain_timeout=5.0,
            sink_port=48000,
            sink_ports=3,
            store_env={},
            coord=coord,
            inbound_bind_host="127.0.0.1",
            sink_host="10.0.0.9",
            post_drain_grace=0.0,
        )
    )
    driver = asyncio.create_task(
        sc.run_shardcert_driver(
            engine_host="127.0.0.1",
            aggregate_rate=10.0,
            hold_seconds=0.1,
            drain_timeout=5.0,
            coord=coord.for_run("band"),
            sink_host="10.0.0.9",
        )
    )
    await asyncio.gather(engine, driver)

    ready = coord.read(SHARDS_READY)
    assert ready is not None and ready["sink_ports"] == 3 and ready["sink_base"] == 48000
    # lanes defaulted to 1 → N=2 connections; sink bound as the 3-wide contiguous band on the load-gen box.
    assert len(rec.conn_ports) == 2
    assert rec.sink_hosts == ["10.0.0.9"]
    assert rec.sink_ports_bound == [(48000, 48001, 48002)]


async def test_two_box_kill_leg_hits_a_local_node(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The engine's SIGKILL leg calls ``kill()`` on a LOCAL ShardCertNode (a local PID) on a timer — it
    is never remoted to the driver box; the killed shard is restarted (supervisor-style) and its PID in
    the report/READY refreshes to the survivor process."""
    monkeypatch.setenv("MEFOR_SHARDCERT_SHARDS", "a,b")
    monkeypatch.delenv("MEFOR_SHARDCERT_LANES_PER_SHARD", raising=False)
    rec = _install_fakes(monkeypatch)

    coord = FileDropCoord(tmp_path, run_id="kill")
    engine = asyncio.create_task(
        sc.run_shardcert_engine(
            dests=2,
            hold_seconds=0.4,
            kill=True,
            kill_at_fraction=0.3,
            drain_timeout=5.0,
            sink_port=49000,
            store_env={},
            coord=coord,
            inbound_bind_host="0.0.0.0",
            sink_host="10.0.0.9",
            post_drain_grace=0.0,
        )
    )
    driver = asyncio.create_task(
        sc.run_shardcert_driver(
            engine_host="127.0.0.1",
            aggregate_rate=20.0,
            hold_seconds=0.4,
            drain_timeout=5.0,
            coord=coord.for_run("kill"),
            sink_host="10.0.0.9",
        )
    )
    eng_report, _drv = await asyncio.gather(engine, driver)

    assert eng_report.killed_shard is not None
    killed_nodes = [n for n in rec.nodes if n.shard == eng_report.killed_shard and n.kill_calls > 0]
    assert killed_nodes, "kill() was never invoked on a local node object"
    assert eng_report.recovery_seconds is not None  # recovery timed from the local kill instant


# --- CLI arg threading (both halves) -----------------------------------------------------------------


def test_shardcert_engine_cli_threads_args_and_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The ``shardcert-engine`` CLI flags reach ``run_shardcert_engine`` as the right kwargs, and the
    lanes/persistent knobs land on ``os.environ`` BEFORE the run (mirroring the single-box wiring)."""
    captured: dict[str, object] = {}

    async def fake_engine(**kwargs: Any) -> Any:
        captured.update(kwargs)
        return types.SimpleNamespace(render=lambda: "", ok=True, stranded_nonterminal=0)

    # The dispatcher does `from harness.load.shardcert import run_shardcert_engine` at call time, so
    # patching the module attribute is what it resolves.
    monkeypatch.setattr("harness.load.shardcert.run_shardcert_engine", fake_engine)
    # Own the knob env vars so monkeypatch restores them (the CLI writes os.environ directly), and pass
    # the --store gate.
    for k in (
        "MEFOR_SHARDCERT_SHARDS",
        "MEFOR_SHARDCERT_LANES_PER_SHARD",
        "MEFOR_SHARDCERT_PERSISTENT",
    ):
        monkeypatch.setenv(k, "")
    monkeypatch.setenv("MEFOR_STORE_BACKEND", "sqlserver")

    rc = hmain.main(
        [
            "shardcert-engine",
            "--shards",
            "a,b,c",
            "--dests",
            "6",
            "--lanes-per-shard",
            "3",
            "--persistent",
            "--sink-port",
            "5000",
            "--sink-ports",
            "2",
            "--sink-host",
            "10.0.0.9",
            "--inbound-bind-host",
            "0.0.0.0",
            "--claim-mode",
            "per_lane",
            "--coord-dir",
            str(tmp_path),
            "--run-id",
            "cli",
        ]
    )
    assert rc == 0
    assert captured["dests"] == 6
    assert captured["sink_port"] == 5000
    assert captured["sink_ports"] == 2
    assert captured["sink_host"] == "10.0.0.9"
    assert captured["inbound_bind_host"] == "0.0.0.0"
    assert captured["claim_mode"] == "per_lane"
    coord = captured["coord"]
    assert isinstance(coord, FileDropCoord) and coord.run_id == "cli"
    # The graph-shape knobs were wired into os.environ before the run.
    import os

    assert os.environ["MEFOR_SHARDCERT_SHARDS"] == "a,b,c"
    assert os.environ["MEFOR_SHARDCERT_LANES_PER_SHARD"] == "3"
    assert os.environ["MEFOR_SHARDCERT_PERSISTENT"] == "1"


def test_shardcert_engine_cli_requires_sqlserver(monkeypatch: pytest.MonkeyPatch) -> None:
    """The engine CLI gates on ``MEFOR_STORE_BACKEND=sqlserver`` (N shards on ONE unified server store),
    like the single-box bench — exit 2 when it's unset."""
    monkeypatch.delenv("MEFOR_STORE_BACKEND", raising=False)
    rc = hmain.main(["shardcert-engine", "--sink-port", "5000"])
    assert rc == 2


def test_shardcert_driver_cli_threads_args(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The ``shardcert-driver`` CLI flags reach ``run_shardcert_driver`` as the right kwargs (no engine
    spawn, no store gate — it learns the topology from SHARDS_READY)."""
    captured: dict[str, object] = {}

    async def fake_driver(**kwargs: Any) -> Any:
        captured.update(kwargs)
        return types.SimpleNamespace(
            render=lambda: "",
            ok=True,
            killed_shard=None,
            sent=0,
            acked=0,
            sink_received=0,
            acked_not_delivered=0,
            lane_inversions=0,
            lanes_observed=0,
            lane_repeats=0,
            engine_done=0,
            engine_dead=0,
            in_pipeline_final=0,
            drained=True,
            drain_seconds=0.0,
        )

    monkeypatch.setattr("harness.load.shardcert.run_shardcert_driver", fake_driver)

    rc = hmain.main(
        [
            "shardcert-driver",
            "--engine-host",
            "10.0.0.5",
            "--aggregate-rate",
            "80",
            "--hold-seconds",
            "12",
            "--sink-host",
            "10.0.0.9",
            "--coord-dir",
            str(tmp_path),
            "--run-id",
            "cli",
        ]
    )
    assert rc == 0
    assert captured["engine_host"] == "10.0.0.5"
    assert captured["aggregate_rate"] == 80.0
    assert captured["hold_seconds"] == 12.0
    assert captured["sink_host"] == "10.0.0.9"
    coord = captured["coord"]
    assert isinstance(coord, FileDropCoord) and coord.run_id == "cli"


# --- BACKLOG #5640: the driver verdict counts the outbound COPIES, not just distinct messages -------


def _driver_report(**over: Any) -> sc.ShardCertDriverReport:
    """A clean two-box driver report at a broadcast fan-out of 4: 10 acked messages, 40 copies."""
    fields: dict[str, Any] = {
        "shards": ("a", "b"),
        "killed_shard": None,
        "sent": 10,
        "acked": 10,
        "delivered_distinct": 10,
        "sink_received": 40,
        "acked_not_delivered": 0,
        "lane_inversions": 0,
        "lanes_observed": 4,
        "lane_repeats": 0,
        "engine_done": 10,
        "engine_dead": 0,
        "in_pipeline_final": 0,
        "drained": True,
        "drain_seconds": 0.1,
        "delivering": 4,
        "routing": BROADCAST,
        "acked_copies_missing": 0,
    }
    fields.update(over)
    return sc.ShardCertDriverReport(**fields)


def _tracker(acked: Sequence[int], lanes: Mapping[str, Sequence[int]]) -> Any:
    """A FailoverTracker fed these ACKs and these per-lane deliveries, in order."""
    from harness.load.failover_track import FailoverTracker

    tracker = FailoverTracker()
    for seq in acked:
        tracker.on_ack(seq)
    for lane, seqs in lanes.items():
        for seq in seqs:
            tracker.on_delivery(lane, seq)
    return tracker


_FOUR_LANES = ("a_00", "a_01", "a_02", "a_03")


def _broadcast(fanout: int) -> Any:
    """The expected-destination function the driver builds for a broadcast run at this fan-out."""
    return lambda seq: destinations_for_seq(seq, routing=BROADCAST, dests=8, fanout=fanout)


def test_tracker_counts_each_acked_copy_that_never_arrived() -> None:
    """Per ACKed seq, the expected destinations no copy arrived at. A full broadcast run is 0; one
    copy of each, the old false pass, is 3 per message."""
    acked = range(10)
    full = _tracker(acked, {lane: list(acked) for lane in _FOUR_LANES})
    assert full.acked_copies_missing(_broadcast(4), fifo_lane_destination) == 0
    one_copy_each = _tracker(acked, {"a_00": list(acked)})
    assert one_copy_each.acked_not_delivered() == 0  # the old verdict's only loss signal is clean
    assert one_copy_each.acked_copies_missing(_broadcast(4), fifo_lane_destination) == 30


def test_tracker_copy_check_cannot_be_offset_by_a_surplus() -> None:
    """The aggregate count let a surplus stand in for a lost copy: A=10, D=4, one copy of ACKed seq 3
    lost, and all 4 copies of a timed-out send 10 delivered, gave S=43 inside [40, 44]. Re-delivery
    on a lane the seq already reached, as across a kill, adds nothing either.

    Mutation: count total deliveries instead of distinct destinations. Red: the copy reads 0."""
    acked = list(range(10))
    lanes = {lane: [*acked, 10] for lane in _FOUR_LANES}
    lanes["a_02"] = [s for s in lanes["a_02"] if s != 3]
    lanes["a_00"] = [*lanes["a_00"], 3, 5]  # re-deliveries on lanes those seqs already reached
    tracker = _tracker(acked, lanes)
    assert tracker.acked_copies_missing(_broadcast(4), fifo_lane_destination) == 1
    assert tracker.lane_repeats == 2


def test_tracker_copy_at_an_unexpected_destination_does_not_offset_a_lost_one() -> None:
    """Broadcast with H=8 handlers and D=4 delivering: handler 5 should self-filter. If it regresses
    and delivers seq 7 while handler 2's copy of seq 7 is lost, seq 7 still arrives under 4 distinct
    labels, which a count of labels read as complete. Against the expected set it is 1 missing.

    Mutation: count distinct labels instead of expected-destination membership. Red: it reads 0."""
    acked = list(range(10))
    lanes = {lane: list(acked) for lane in _FOUR_LANES}
    lanes["a_02"] = [s for s in acked if s != 7]
    lanes["a_05"] = [7]
    tracker = _tracker(acked, lanes)
    assert tracker.acked_copies_missing(_broadcast(4), fifo_lane_destination) == 1


def test_tracker_partitioned_copy_at_the_wrong_destination_is_missing() -> None:
    """A partitioned message has ONE destination, ``destinations_for_seq`` with fan-out 1. A copy
    that arrives at any other destination is not its copy: the run lost the expected one."""
    from harness.config.shardcert._shape import fifo_lane

    def expected(seq: int) -> list[int]:
        return destinations_for_seq(seq, routing=PARTITIONED, dests=8, fanout=1)

    acked = list(range(20))
    right: dict[str, list[int]] = {}
    wrong: dict[str, list[int]] = {}
    for s in acked:
        right.setdefault(fifo_lane("a", expected(s)[0]), []).append(s)
        wrong.setdefault(fifo_lane("a", (expected(s)[0] + 1) % 8), []).append(s)
    assert _tracker(acked, right).acked_copies_missing(expected, fifo_lane_destination) == 0
    assert _tracker(acked, wrong).acked_copies_missing(expected, fifo_lane_destination) == 20


def test_destinations_for_seq_matches_the_served_router() -> None:
    """The driver's expected set and the served router's choice come from one function, so they
    cannot drift: the shape's own selectors agree with it at every seq."""
    from harness.config.shardcert._shape import ShardCertShape
    from harness.load.ids import SHARDCERT_IDS
    from messagefoundry.parsing.message import Message

    def shape(routing: str, delivering: int) -> ShardCertShape:
        return ShardCertShape(
            shards=("a",),
            inbound_base=3600,
            dests=8,
            sink_host="127.0.0.1",
            sink_port=3700,
            sink_ports=1,
            transform="edit",
            persistent=False,
            lanes_per_shard=1,
            handlers=8,
            delivering=delivering,
            routing=routing,
        )

    part, fan = shape(PARTITIONED, 8), shape(PARTITIONED_FANOUT, 3)
    for seq in range(64):
        msg = Message.parse(
            f"MSH|^~\\&|A|B|C|D|20260101000000||ADT^A01|{SHARDCERT_IDS.format(seq)}|P|2.5.1\r"
        )
        assert [part.destination_index(msg)] == destinations_for_seq(
            seq, routing=PARTITIONED, dests=8, fanout=1
        )
        assert fan.destination_indices(msg) == destinations_for_seq(
            seq, routing=PARTITIONED_FANOUT, dests=8, fanout=3
        )


def test_driver_verdict_refuses_a_run_that_lost_an_acked_copy() -> None:
    """The verdict gates on the per-message copy check, on a no-kill run and across a kill alike,
    whatever the aggregate ``sink_received`` reads.

    Mutation: drop ``copies_ok`` from ``ok``. Red: both lossy runs pass."""
    assert _driver_report().ok
    lossy = _driver_report(acked_copies_missing=1, sink_received=43, timeouts=1)
    assert not lossy.ok
    assert "acked_copies_missing=1 -> LOSS" in lossy.render()
    assert "aggregate (reported, not gated): S=43 A*delivering=40 timeouts=1" in lossy.render()
    assert not _driver_report(killed_shard="a", acked_copies_missing=1, sink_received=40).ok


def test_driver_verdict_on_a_kill_run_allows_redelivery() -> None:
    """Across a kill, at-least-once may re-deliver: repeats and a surplus are allowed when every
    ACKed copy arrived."""
    assert _driver_report(killed_shard="a", sink_received=44, lane_repeats=4).ok


def test_driver_verdict_ignores_the_aggregate_when_every_copy_arrived() -> None:
    """A send whose ACK this side never saw may still be delivered. Its copies raise the aggregate
    above A*D, and the run still passes, since every ACKed copy arrived and no lane repeated."""
    assert _driver_report(sink_received=44, timeouts=1).ok


def test_driver_verdict_refuses_an_unknown_fanout() -> None:
    """A fan-out below 1 checks nothing and would certify a run that delivered nothing."""
    unknown = _driver_report(delivering=0)
    assert not unknown.ok
    assert "-> UNCHECKED" in unknown.render()


def _post_ready(coord: FileDropCoord, *, drop: Sequence[str] = (), **over: Any) -> None:
    ready: dict[str, Any] = {
        "shards": ["a", "b"],
        "inbound_base": 3600,
        "lanes": 1,
        "api_ports": [9001, 9002],
        "sink_base": 3700,
        "sink_ports": 1,
        "sink_port": 3700,
        "killed": None,
        "dests": 4,
        "handlers": 4,
        "delivering": 4,
        "routing": BROADCAST,
    }
    ready.update(over)
    for key in drop:
        del ready[key]
    coord.post(SHARDS_READY, ready)


async def test_driver_learns_the_fanout_from_shards_ready(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """``delivering`` and ``routing`` come from SHARDS_READY, the engine box's one source of truth,
    and never from ``dests``: a partitioned run's fan-out is 1 whatever its destination count."""
    _install_fakes(monkeypatch)
    coord = FileDropCoord(tmp_path, run_id="fan")
    _post_ready(coord, dests=8, handlers=1, delivering=1, routing=PARTITIONED)
    report = await sc.run_shardcert_driver(
        engine_host="10.0.0.5", hold_seconds=0.05, drain_timeout=1.0, coord=coord
    )
    assert report.delivering == 1
    assert report.routing == PARTITIONED
    assert "routing=partitioned" in report.render()


@pytest.mark.parametrize("killed", [None, "a"])
async def test_driver_fails_an_older_payload_without_the_fanout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, killed: str | None
) -> None:
    """An engine half that predates the keys sends neither. A guessed fan-out of 1 would pass a run
    that lost every copy but one, so the driver takes 0, which fails the copy check, and says why.

    Mutation: default ``delivering`` to 1. Red: the report's fan-out reads 1."""
    _install_fakes(monkeypatch)
    coord = FileDropCoord(tmp_path, run_id=f"old{killed}")
    _post_ready(coord, killed=killed, drop=("delivering", "routing", "handlers", "dests"))
    report = await sc.run_shardcert_driver(
        engine_host="10.0.0.5", hold_seconds=0.05, drain_timeout=1.0, coord=coord
    )
    assert report.delivering == 0
    assert not report.copies_ok
    assert report.routing == BROADCAST
    assert any("cannot be made without the fan-out" in n for n in report.notes), report.notes


async def test_drive_ladder_threads_cacert_and_escapes_an_abort_note(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Every rung's drive gets ``cacert``, and a rung abort's note is escaped before render prints
    it: the abort text can carry a peer's control sequence."""
    import harness.load.shardcert_ladder as ladder
    from harness.load.coord import LADDER_STOP, CoordTimeout

    seen: list[dict[str, Any]] = []

    async def refusing_drive(**kwargs: Any) -> Any:
        seen.append(kwargs)
        raise CoordTimeout("SHARDS_READY not seen: \x1b]0;forged\x07refused")

    monkeypatch.setattr(ladder, "run_shardcert_drive", refusing_drive)
    coord = FileDropCoord(tmp_path, run_id="lad")
    report = await ladder.run_drive_ladder(
        engine_host="10.0.0.5",
        rates=[10.0, 20.0],
        hold_seconds=0.05,
        drain_timeout=1.0,
        driver_count=1,
        sink_count=1,
        sink_host="127.0.0.1",
        base_coord=coord,
        cacert="engine-box.pem",
        do_soak=False,
    )
    assert [kw["cacert"] for kw in seen] == ["engine-box.pem"]
    assert report.exit_code == 2
    assert coord.read(LADDER_STOP) is not None
    rendered = report.render()
    assert "refused" in rendered
    assert "\x1b" not in rendered and "\x07" not in rendered


# --- BACKLOG #5640 / #5977 (https and session half): the two-box drain poll ------------------------


async def test_driver_polls_the_engine_box_over_https_with_the_remote_rig_session(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The engine box serves TLS with sign-in on, so the default drain poll is https, signed in as
    the rig Administrator another process provisioned, verified against ``cacert``.

    Mutation: build the URLs with ``http://`` or pass ``None`` as the token. Red: the assert."""
    from harness.load.rigadmin import REMOTE_RIG_SESSION

    rec = _install_fakes(monkeypatch)
    coord = FileDropCoord(tmp_path, run_id="tls")
    _post_ready(coord)
    await sc.run_shardcert_driver(
        engine_host="10.0.0.5",
        hold_seconds=0.05,
        drain_timeout=1.0,
        coord=coord,
        cacert="engine-box.pem",
    )
    assert rec.pollers == [
        {
            "urls": ["https://10.0.0.5:9001", "https://10.0.0.5:9002"],
            "token": REMOTE_RIG_SESSION,
            "allow_insecure": False,
            "cacert": "engine-box.pem",
        }
    ]


async def test_driver_insecure_keeps_the_plaintext_poll_without_a_credential(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """``--insecure`` stays the opt-in for an engine box that serves plain http, and carries no
    credential on that cleartext hop."""
    rec = _install_fakes(monkeypatch)
    coord = FileDropCoord(tmp_path, run_id="plain")
    _post_ready(coord)
    await sc.run_shardcert_driver(
        engine_host="10.0.0.5",
        hold_seconds=0.05,
        drain_timeout=1.0,
        coord=coord,
        allow_insecure=True,
    )
    assert rec.pollers[0]["urls"] == ["http://10.0.0.5:9001", "http://10.0.0.5:9002"]
    assert rec.pollers[0]["token"] is None
    assert rec.pollers[0]["allow_insecure"] is True


def test_remote_poller_refuses_insecure_with_a_cacert() -> None:
    """A certificate means nothing on a plaintext hop; asking for both is a mistake, said loud."""
    with pytest.raises(ValueError, match="--cacert"):
        sc._remote_engine_poller("10.0.0.5", [9001], allow_insecure=True, cacert="x.pem")


def _refusing_poller(built: list[dict[str, Any]], exc: Exception) -> type:
    class RefusingPoller:
        def __init__(self, urls: Any, token: Any = None, **kw: Any) -> None:
            built.append({"urls": list(urls), "token": token, **kw})

        async def open(self) -> None:
            raise exc

        async def close(self) -> None:
            return None

    return RefusingPoller


async def test_driver_sign_in_refusal_is_a_named_setup_error_before_any_load(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A refused sign-in used to surface only after the whole hold. The poller now opens before
    DRIVE_START, and its refusal is a named error rather than a traceback."""
    from harness.load.rigadmin import RigAdminError

    _install_fakes(monkeypatch)
    built: list[dict[str, Any]] = []
    refusal = RigAdminError("set MEFOR_RIG_ADMIN_USERNAME and MEFOR_RIG_ADMIN_PASSWORD")
    monkeypatch.setattr(sc, "EnginePoller", _refusing_poller(built, refusal))
    coord = FileDropCoord(tmp_path, run_id="refused")
    _post_ready(coord)
    with pytest.raises(sc.RemoteEngineSignInError, match="MEFOR_RIG_ADMIN_PASSWORD"):
        await sc.run_shardcert_driver(
            engine_host="10.0.0.5", hold_seconds=0.05, drain_timeout=1.0, coord=coord
        )
    assert len(built) == 1
    assert coord.read(DRIVE_START) is None, "the driver offered load to an engine it cannot poll"


def test_shardcert_driver_cli_threads_cacert_and_reports_a_sign_in_refusal(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """``--cacert`` reaches the driver, and a refused sign-in exits 2 with its reason in words."""
    captured: dict[str, object] = {}

    async def refusing_driver(**kwargs: Any) -> Any:
        captured.update(kwargs)
        raise sc.RemoteEngineSignInError("could not sign in to the engine box's API: refused")

    monkeypatch.setattr("harness.load.shardcert.run_shardcert_driver", refusing_driver)
    rc = hmain.main(
        [
            "shardcert-driver",
            "--engine-host",
            "10.0.0.5",
            "--cacert",
            "engine-box.pem",
            "--coord-dir",
            str(tmp_path),
        ]
    )
    assert rc == 2
    assert captured["cacert"] == "engine-box.pem"
    assert captured["allow_insecure"] is False
    assert "could not sign in to the engine box's API" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("sub", "extra"),
    [
        ("shardcert-driver", []),
        ("shardcert-drive", []),
        ("shardcert-drive-ladder", ["--rate-ladder", "10,20"]),
    ],
)
@pytest.mark.parametrize("cacert", ["x.pem", ""])
def test_two_box_cli_refuses_insecure_with_cacert(
    sub: str,
    extra: list[str],
    cacert: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exc:
        hmain.main(
            [
                sub,
                "--engine-host",
                "10.0.0.5",
                *extra,
                "--insecure",
                "--cacert",
                cacert,
                "--coord-dir",
                str(tmp_path),
            ]
        )
    assert exc.value.code == 2
    # The named refusal, not argparse's unknown-argument error.
    assert "do not combine" in capsys.readouterr().err


def test_shardcert_drive_cli_threads_cacert(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    captured: dict[str, object] = {}

    async def fake_drive(**kwargs: Any) -> Any:
        captured.update(kwargs)
        return types.SimpleNamespace(render=lambda: "", ok=True)

    monkeypatch.setattr("harness.load.shardcert.run_shardcert_drive", fake_drive)
    rc = hmain.main(
        [
            "shardcert-drive",
            "--engine-host",
            "10.0.0.5",
            "--cacert",
            "engine-box.pem",
            "--coord-dir",
            str(tmp_path),
        ]
    )
    assert rc == 0
    assert captured["cacert"] == "engine-box.pem"


def test_shardcert_drive_cli_exits_2_on_a_sign_in_refusal(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """With no ENGINE_DRAINED gate the poll is the tally's barrier, so a refusal is a setup error."""

    async def refusing_drive(**kwargs: Any) -> Any:
        raise sc.RemoteEngineSignInError("could not sign in to the engine box's API: refused")

    monkeypatch.setattr("harness.load.shardcert.run_shardcert_drive", refusing_drive)
    rc = hmain.main(["shardcert-drive", "--engine-host", "10.0.0.5", "--coord-dir", str(tmp_path)])
    assert rc == 2
    assert "could not sign in to the engine box's API" in capsys.readouterr().err


def test_shardcert_driver_cli_report_json_banks_the_count_balance(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The driver's JSON artifact carries the copy check, its inputs, the reported aggregate and the
    notes that record any fallback, so the banked run shows why it passed or failed.

    Mutation: drop any of the keys from the JSON dump. Red: the assert names it."""
    import json

    report = _driver_report(
        sink_received=41, timeouts=1, notes=["SHARDS_READY carried no `routing`"]
    )

    async def fake_driver(**kwargs: Any) -> Any:
        return report

    monkeypatch.setattr("harness.load.shardcert.run_shardcert_driver", fake_driver)
    out = tmp_path / "driver.json"
    rc = hmain.main(
        [
            "shardcert-driver",
            "--engine-host",
            "10.0.0.5",
            "--coord-dir",
            str(tmp_path),
            "--report-json",
            str(out),
        ]
    )
    assert rc == 0
    banked = json.loads(out.read_text(encoding="utf-8"))
    assert banked["delivering"] == 4
    assert banked["routing"] == BROADCAST
    assert banked["timeouts"] == 1
    assert banked["sink_received"] == 41
    assert banked["acked_copies_missing"] == 0
    assert banked["copies_ok"] is True
    assert banked["notes"] == ["SHARDS_READY carried no `routing`"]
    assert banked["verdict"] == "PASS"
