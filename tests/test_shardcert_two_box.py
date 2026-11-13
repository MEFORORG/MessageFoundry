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
from harness.config.shardcert._shape import BROADCAST, PARTITIONED
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
    }
    fields.update(over)
    return sc.ShardCertDriverReport(**fields)


def test_driver_verdict_refuses_a_broadcast_run_that_lost_outbound_copies() -> None:
    """The tracker counts DISTINCT messages, so one copy of each reaching the sink cleared
    ``acked_not_delivered`` while three of every four broadcast copies were lost. The verdict now
    balances the sink count against the fan-out, as the multi-process drive's ``no_loss`` does.

    Mutation: drop the count-balance term from ``ok``. Red: the one-copy run passes."""
    assert _driver_report().ok
    one_copy_each = _driver_report(sink_received=10)
    assert one_copy_each.acked_not_delivered == 0  # the old verdict's only loss signal is clean
    assert not one_copy_each.ok
    assert not _driver_report(sink_received=39).ok
    # No kill: strict. A copy more than the fan-out is a duplicate the run must not certify.
    surplus = _driver_report(sink_received=41)
    assert not surplus.ok
    assert "expect A*delivering=40) -> LOSS" in one_copy_each.render()
    assert "-> SURPLUS" in surplus.render()


def test_driver_verdict_on_a_kill_run_allows_redelivery_but_not_loss() -> None:
    """Across a kill, at-least-once may re-deliver, so the sink may hold MORE copies than the
    fan-out implies; it may never hold fewer."""
    assert _driver_report(killed_shard="a", sink_received=44, lane_repeats=4).ok
    assert not _driver_report(killed_shard="a", sink_received=39).ok


def test_driver_verdict_allows_copies_of_sends_whose_ack_was_lost() -> None:
    """A send whose ACK this side never saw may still have been committed and delivered, so on a
    no-kill run the sink may hold up to ``(A + timeouts) * D`` copies; past that is a duplicate.
    Below ``A * D`` is still loss, timeouts or not."""
    assert _driver_report(sink_received=44, timeouts=1).ok
    beyond = _driver_report(sink_received=45, timeouts=1)
    assert not beyond.ok
    assert "up to (A+timeouts=1)*delivering=44) -> SURPLUS" in beyond.render()
    assert not _driver_report(sink_received=39, timeouts=5).ok


def test_driver_verdict_refuses_a_vacuous_fanout() -> None:
    """A fan-out below 1 balances 0 == 0 and would certify a run that delivered nothing."""
    assert not _driver_report(delivering=0, sink_received=0).ok


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


async def test_driver_defaults_an_older_payload_to_fanout_one_with_a_note(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An engine half that predates the keys sends neither. The driver reads that as fan-out 1 and
    says so, rather than guessing ``dests``. On a no-kill run at a real fan-out above 1 the sink
    then holds more copies than 1 per message, so the strict balance fails closed (pinned by the
    report below at the real fan-out's sink count)."""
    _install_fakes(monkeypatch)
    coord = FileDropCoord(tmp_path, run_id="old")
    _post_ready(coord, drop=("delivering", "routing", "handlers", "dests"))
    report = await sc.run_shardcert_driver(
        engine_host="10.0.0.5", hold_seconds=0.05, drain_timeout=1.0, coord=coord
    )
    assert report.delivering == 1
    assert report.routing == BROADCAST
    assert any("older engine half" in n for n in report.notes), report.notes
    # At the assumed fan-out of 1, a run that really delivered all 4 copies of 10 messages fails.
    assumed = _driver_report(delivering=report.delivering, sink_received=40)
    assert not assumed.ok
    assert "-> SURPLUS" in assumed.render()


async def test_driver_kill_run_without_the_fanout_fails_the_balance(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A kill run's balance is a lower bound, so a guessed fan-out of 1 would pass a run that lost
    three of every four copies. Without the key it fails instead, and says why."""
    _install_fakes(monkeypatch)
    coord = FileDropCoord(tmp_path, run_id="oldkill")
    _post_ready(coord, killed="a", drop=("delivering", "routing", "handlers", "dests"))
    report = await sc.run_shardcert_driver(
        engine_host="10.0.0.5", hold_seconds=0.05, drain_timeout=1.0, coord=coord
    )
    assert report.delivering == 0
    assert not report.count_balance_ok
    assert any("cannot be checked" in n for n in report.notes), report.notes
    # Even a sink holding every copy cannot balance against an unknown fan-out, and says so.
    unknown = _driver_report(killed_shard="a", delivering=0, sink_received=40)
    assert not unknown.ok
    assert "-> UNCHECKED" in unknown.render()


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


def test_shardcert_driver_cli_report_json_banks_the_count_balance(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The driver's JSON artifact carries the count balance's inputs and verdict, and the notes
    that record any fallback, so the banked run shows why it passed or failed.

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
    assert banked["count_balance_ok"] is True
    assert banked["notes"] == ["SHARDS_READY carried no `routing`"]
    assert banked["verdict"] == "PASS"
