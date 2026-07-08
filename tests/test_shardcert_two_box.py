# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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

        async def start(self) -> None:
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
        def __init__(self, urls: Any, token: Any = None, *, origin: Any = None) -> None:
            self.final = types.SimpleNamespace(done=0, dead=0, in_pipeline=0)

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

    async def fake_queue_breakdown(env: Mapping[str, str]) -> tuple[int, int, str]:
        rec.queues.append(dict(env))
        # (non-terminal, all-stage dead_total, summary) — clean store: nothing stranded, nothing dead.
        return 0, 0, "QUEUE <empty>"

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
    base: dict[str, Any] = dict(
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
