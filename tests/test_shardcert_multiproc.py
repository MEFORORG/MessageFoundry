# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Offline round-trip for the WS-C MULTI-PROCESS SIZING drive (PR-C1, ADR 0073).

The two-box drive of PR-B is ONE sender proc + ONE sink proc, both below the ~450-500 msg/s target, so
a plateau there can't be told apart from the engine/store ceiling. PR-C over-provisions the CLIENT tier
into K sender processes + M sink processes on the load-gen box, and — because the coord channel is
metadata-only, so senders and sinks in different processes can't correlate acked↔delivered per-message —
reconciles no-loss by COUNT-BALANCE + engine store-truth (``S == A*dests`` + engine REMOTE done/dead),
not per-message.

These tests prove the process-split primitives WIRE + PARTITION + RECONCILE correctly OFFLINE on one PC
over a temp coord dir: the exact contiguous sink-port partition (+ fail-loud), the exact band-slice
partition (+ fail-loud), and the count-balance reconcile (PASS on a balanced synthetic set, FAIL on each
loss signal). Every network collaborator (the correlation sink, the senders, ``_drive_load``, the
``/stats`` poller, the port preflight, AND the subprocess spawn seam ``_spawn_proc``) is faked — there is
no real socket/subprocess here; the faked ``_spawn_proc`` itself writes each child's expected coord
messages so the coordinator's awaits resolve. The live ~450-500 msg/s number is the AWS rig's job.

Additive to the single-box ``run_shardcert``, the PR-B two-box halves, and the #836 ladder — none of
those control flows are touched.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import pytest

import harness.load.shardcert as sc
from harness.load.coord import (
    DRIVE_COMPLETE,
    DRIVE_GO,
    DRIVE_START,
    DRIVER_ARMED,
    DRIVER_DONE,
    SHARDS_READY,
    SINK_BOUND,
    SINK_DONE,
    FileDropCoord,
)


async def _until(cond: Callable[[], bool], *, timeout: float = 5.0, interval: float = 0.01) -> None:
    """Poll ``cond`` until true or ``timeout`` — a deterministic wait for a coord file to appear that
    doesn't couple the test to the (slower) production poll interval."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if cond():
            return
        await asyncio.sleep(interval)
    raise AssertionError("condition not met within timeout")


def _install_sink_fake(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, tuple[int, ...]]]:
    """Fake the ``CorrelationSink`` so the sink tier binds no real sockets; record (host, ports)."""
    bound: list[tuple[str, tuple[int, ...]]] = []

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
            bound.append((host, tuple(ports)))

        async def start(self) -> None:
            return None

        async def stop(self) -> None:
            return None

    monkeypatch.setattr(sc, "CorrelationSink", FakeSink)
    return bound


# --- Layer 1: sink-port partition -------------------------------------------------------------------


def test_partition_band_exact_contiguous_tiling() -> None:
    """The band partition is CONTIGUOUS, non-overlapping, and EXACTLY tiles [base, base+width) — no gaps
    (a silent gap would leave a dest port unbound → dropped deliveries the reconcile never counts)."""
    # 8 dest ports across 3 sinks: 3,3,2 (first `width % count` chunks one wider), contiguous, no gap.
    chunks = sc._partition_band(48000, 8, 3)
    assert chunks == [[48000, 48001, 48002], [48003, 48004, 48005], [48006, 48007]]
    flat = [p for chunk in chunks for p in chunk]
    assert flat == list(range(48000, 48008))  # exact tiling: every port bound by exactly one sink
    # One sink per port (sink_count == width) → each chunk is a single distinct port, no overlap.
    solo = sc._partition_band(3600, 4, 4)
    assert solo == [[3600], [3601], [3602], [3603]]


@pytest.mark.parametrize(
    ("width", "count"),
    [(4, 5), (1, 2), (8, 9)],  # count > width ⇒ some sink would bind no ports
)
def test_partition_band_fails_loud_on_more_sinks_than_ports(width: int, count: int) -> None:
    with pytest.raises(ValueError, match="would bind no ports"):
        sc._partition_band(48000, width, count)


@pytest.mark.parametrize(("width", "count"), [(0, 1), (4, 0), (-1, 1)])
def test_partition_band_fails_loud_on_degenerate(width: int, count: int) -> None:
    with pytest.raises(ValueError):
        sc._partition_band(48000, width, count)


async def test_sink_out_of_range_index_fails_loud(tmp_path: Path) -> None:
    """A sink can only bind an EXISTING partition chunk — an out-of-range ``sink_index`` (a chunk that
    isn't in the partition → an uncovered gap) fails loud rather than silently binding nothing."""
    coord = FileDropCoord(tmp_path, run_id="s")
    with pytest.raises(ValueError, match="out of range"):
        await sc.run_shardcert_sink(
            sink_base=48000, sink_ports=4, sink_index=2, sink_count=2, coord=coord
        )


async def test_sink_binds_chunk_and_handshakes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The sink binds ITS contiguous chunk, posts SINK_BOUND.<i> once bound, WAITS for DRIVE_COMPLETE
    (SINK_DONE must not appear before it), then posts SINK_DONE.<i> with its port topology + tally."""
    bound = _install_sink_fake(monkeypatch)
    coord = FileDropCoord(tmp_path, run_id="s")
    task = asyncio.create_task(
        sc.run_shardcert_sink(
            sink_host="10.0.0.9",
            sink_base=48000,
            sink_ports=4,
            sink_index=1,
            sink_count=2,
            coord=coord,
            drive_complete_timeout=5.0,
            post_complete_grace=0.0,
        )
    )
    # SINK_BOUND appears once the (faked) sink is bound; SINK_DONE must NOT until DRIVE_COMPLETE arrives.
    await _until(lambda: coord.read(f"{SINK_BOUND}.1") is not None)
    assert coord.read(f"{SINK_DONE}.1") is None, "sink posted DONE before observing DRIVE_COMPLETE"
    # chunk 1 of [48000,48004) split into 2 contiguous halves = ports 48002,48003, bound on the load-gen host.
    ready = coord.read(f"{SINK_BOUND}.1")
    assert ready is not None and ready["ports"] == [48002, 48003] and ready["sink_index"] == 1
    assert bound == [("10.0.0.9", (48002, 48003))]

    coord.post(DRIVE_COMPLETE, {"ok": True})
    report = await task

    done = coord.read(f"{SINK_DONE}.1")
    assert done is not None
    assert done["ports"] == [48002, 48003] and done["sink_index"] == 1
    # Metadata only: counts + synthetic port topology — never control-ids / bodies.
    assert set(done) == {
        "sink_index",
        "sink_received",
        "lane_inversions",
        "lane_repeats",
        "lanes_observed",
        "ports",
    }
    assert report.ports == (48002, 48003)
    assert report.sink_index == 1 and report.sink_count == 2
    assert report.lanes_observed == 0  # the faked sink absorbed nothing


async def test_sink_reports_partial_on_missing_drive_complete(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A lost DRIVE_COMPLETE can't hang the sink forever — it times out on the bounded max-wait, notes
    the partial tally, and still posts SINK_DONE so the coordinator's reconcile sees (and fails on) it."""
    _install_sink_fake(monkeypatch)
    coord = FileDropCoord(tmp_path, run_id="s")
    report = await sc.run_shardcert_sink(
        sink_base=3600,
        sink_ports=2,
        sink_index=0,
        sink_count=1,
        coord=coord,
        drive_complete_timeout=0.05,
        post_complete_grace=0.0,
    )
    assert report.ports == (3600, 3601)
    assert any("DRIVE_COMPLETE not observed" in n for n in report.notes)
    assert coord.read(f"{SINK_DONE}.0") is not None


# --- Layer 2: sender-worker band slice --------------------------------------------------------------


def _install_worker_fakes(monkeypatch: pytest.MonkeyPatch) -> dict[str, list[Any]]:
    """Fake the sender-worker's network collaborators (persistent connections, the port preflight, the
    drive loop) so a worker round-trips offline. Records what each was wired to."""
    rec: dict[str, list[Any]] = {"conn_ports": [], "awaited": [], "drives": []}

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
            rec["conn_ports"].append((host, port))

        def start(self) -> None:
            return None

        async def stop(self, grace: float) -> None:
            return None

    async def fake_await_port(host: str, port: int, *, timeout: float) -> bool:
        rec["awaited"].append((host, port))
        return True

    async def fake_drive_load(
        conns: Any,
        corpus: Any,
        mix: Any,
        metrics: Any,
        *,
        aggregate_rate: float,
        hold_seconds: float,
    ) -> None:
        rec["drives"].append({"conns": len(conns), "rate": aggregate_rate, "hold": hold_seconds})

    monkeypatch.setattr(sc, "PersistentConnection", FakeConn)
    monkeypatch.setattr(sc, "_await_port", fake_await_port)
    monkeypatch.setattr(sc, "_drive_load", fake_drive_load)
    return rec


def test_band_slice_exact_contiguous_tiling() -> None:
    """Two workers over G=4 bands own contiguous halves; the union tiles [0,G) with no gap (an undriven
    band would understate offered/delivered → false PASS)."""
    assert sc._band_slice(4, 2, 0) == (0, 2)
    assert sc._band_slice(4, 2, 1) == (2, 4)
    # Uneven: G=5 across 2 workers ⇒ B=ceil(5/2)=3 ⇒ [0,3) + [3,5), still contiguous + exhaustive.
    assert sc._band_slice(5, 2, 0) == (0, 3)
    assert sc._band_slice(5, 2, 1) == (3, 5)
    # The whole [0,G) is covered exactly once across all workers (no gap / no overlap).
    covered: list[int] = []
    for j in range(3):
        lo, hi = sc._band_slice(6, 3, j)
        covered.extend(range(lo, hi))
    assert covered == list(range(6))


def test_band_slice_fails_loud_on_more_workers_than_bands() -> None:
    with pytest.raises(ValueError, match="would drive no bands"):
        sc._band_slice(4, 5, 0)


def test_band_slice_fails_loud_on_empty_slice() -> None:
    # G=5, K=4 ⇒ B=2 ⇒ worker 3 owns [6,5) = EMPTY (the count doesn't tile the bands) ⇒ fail loud.
    with pytest.raises(ValueError, match="EMPTY band slice"):
        sc._band_slice(5, 4, 3)


def test_band_slice_fails_loud_on_out_of_range_index() -> None:
    with pytest.raises(ValueError, match="out of range"):
        sc._band_slice(8, 2, 2)


async def test_worker_owns_slice_arms_waits_go_and_drives(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The worker learns G=shards*lanes from SHARDS_READY, opens one connection per OWNED band at
    inbound_base+g, posts DRIVER_ARMED.<j>, WAITS for DRIVE_GO (DRIVER_DONE not before it), drives its
    band-share rate, then posts DRIVER_DONE.<j>."""
    rec = _install_worker_fakes(monkeypatch)
    coord = FileDropCoord(tmp_path, run_id="w")
    # 2 shards x 2 lanes = G=4 bands; worker 0 of 2 owns bands [0,2) at inbound_base 3600 → ports 3600,3601.
    coord.post(
        SHARDS_READY,
        {
            "shards": ["a", "b"],
            "inbound_base": 3600,
            "lanes": 2,
            "dests": 3,
            "api_ports": [9001, 9002],
            "sink_base": 3700,
            "sink_ports": 3,
        },
    )
    task = asyncio.create_task(
        sc.run_shardcert_driver_worker(
            engine_host="10.0.0.5",
            aggregate_rate=40.0,
            hold_seconds=0.1,
            driver_index=0,
            driver_count=2,
            coord=coord,
        )
    )
    await _until(lambda: coord.read(f"{DRIVER_ARMED}.0") is not None)
    assert coord.read(f"{DRIVER_DONE}.0") is None, "worker drove before DRIVE_GO"
    armed = coord.read(f"{DRIVER_ARMED}.0")
    assert armed is not None and armed["bands"] == [0, 1] and armed["driver_index"] == 0
    # One connection per owned band, dialing the ENGINE host at inbound_base + g; both preflighted.
    assert rec["conn_ports"] == [("10.0.0.5", 3600), ("10.0.0.5", 3601)]
    assert rec["awaited"] == [("10.0.0.5", 3600), ("10.0.0.5", 3601)]

    coord.post(DRIVE_GO, {"go": True})
    report = await task

    # Drove exactly its 2 owned bands at len(slice)/G of the aggregate = 2/4 * 40 = 20 msg/s.
    assert len(rec["drives"]) == 1
    assert rec["drives"][0] == {"conns": 2, "rate": 20.0, "hold": 0.1}
    done = coord.read(f"{DRIVER_DONE}.0")
    assert done is not None and done["bands"] == [0, 1] and done["driver_index"] == 0
    assert set(done) == {"driver_index", "sent", "acked", "ack_p50_ms", "ack_p99_ms", "bands"}
    assert report.bands == (0, 1) and report.driver_count == 2


async def test_worker_fails_loud_on_empty_slice(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A worker assigned an empty slice (a driver_count that doesn't tile G) raises rather than silently
    driving nothing — the coordinator would then never see its ARMED and time out (loud, not a false PASS)."""
    _install_worker_fakes(monkeypatch)
    coord = FileDropCoord(tmp_path, run_id="w")
    # G = 1 shard x 5 lanes = 5 bands; driver_count 4 ⇒ worker 3 owns an empty slice.
    coord.post(
        SHARDS_READY,
        {"shards": ["a"], "inbound_base": 3600, "lanes": 5, "dests": 2, "api_ports": [9001]},
    )
    with pytest.raises(ValueError, match="EMPTY band slice"):
        await sc.run_shardcert_driver_worker(
            engine_host="10.0.0.5",
            aggregate_rate=40.0,
            hold_seconds=0.1,
            driver_index=3,
            driver_count=4,
            coord=coord,
        )


# --- Layer 3: coordinator count-balance reconcile ---------------------------------------------------


def _drive_report(**over: Any) -> sc.ShardCertDriveReport:
    """A BALANCED synthetic drive report (A=150 intake, dests=2 fan-out ⇒ S == 300), overridable
    field-by-field to exercise each loss signal. offered=120 (< A/(1-TOL)) so a balanced report is not
    a ceiling. The poller fields (engine_done/engine_dead/in_pipeline_final/drained) are ADVISORY only —
    the gated verdict keys off the SINK count (S) alone; they are set here to healthy values so tests can
    prove the verdict is INDEPENDENT of them by overriding them to unhealthy values."""
    base: dict[str, Any] = dict(
        shards=("a", "b"),
        dests=2,
        driver_count=2,
        sink_count=2,
        aggregate_rate=40.0,
        hold_seconds=3.0,
        offered=120,
        sent=150,
        acked=150,  # A
        sink_received=300,  # S == A*dests
        lane_inversions=0,
        lane_repeats=0,
        lanes_observed=2,
        ack_p50_ms=1.5,
        ack_p99_ms=3.0,
        engine_done=300,  # == A*dests
        engine_dead=0,
        in_pipeline_final=0,
        drained=True,
        drain_seconds=1.0,
    )
    base.update(over)
    return sc.ShardCertDriveReport(**base)


def test_reconcile_passes_on_balanced_set() -> None:
    r = _drive_report()
    assert r.no_loss is True
    assert r.ok is True
    assert r.ceiling is False  # A=150 >= offered(120)*(1-TOL) and no_loss


def test_reconcile_fails_on_sink_short_of_fanout() -> None:
    # (a) S != A*dests: one delivery reached the store-done gauge but the socket dropped it → the sink
    # cross-check catches the store-marked-done-but-socket-dropped copy the engine gauge alone misses.
    r = _drive_report(sink_received=299)
    assert r.no_loss is False and r.ok is False


def test_reconcile_passes_despite_advisory_engine_dead() -> None:
    # PR-C1b: engine_dead is the ADVISORY poller cross-check, NOT gated on the DRIVE box (dead-letters
    # are the ENGINE half's store-truth verdict). With perfect sink balance the DRIVE still PASSes.
    r = _drive_report(engine_dead=1)
    assert r.no_loss is True and r.ok is True


def test_reconcile_passes_despite_advisory_engine_done_mismatch() -> None:
    # PR-C1b: engine_done is advisory (4x shard-API overcount / zeroes under load on a unified store).
    # It must NOT drive the DRIVE verdict — sink socket-truth (S == A*dests) alone certifies no-loss.
    r = _drive_report(engine_done=1)
    assert r.no_loss is True and r.ok is True


def test_reconcile_r2_regression_passes_despite_dead_poller() -> None:
    # r2 REGRESSION (rig HANDOFF#2 2026-07-08, the whole point): the remote /stats poller returned
    # done=0, dead=0, in_pipeline=-1 AND drained=False (drain_seconds=None) on a PROVABLY lossless run,
    # which false-FAILed under the old poller-gated formula. With the sink balance PERFECT the DRIVE must
    # now PASS — the verdict no longer depends on the (unreliable) poller.
    r = _drive_report(
        engine_done=0,
        engine_dead=0,
        in_pipeline_final=-1,
        drained=False,
        drain_seconds=None,
    )
    assert r.no_loss is True
    assert r.ok is True
    assert r.ceiling is False  # sink-based no_loss holds and intake >= offered*(1-TOL)


def test_reconcile_fails_on_inversions() -> None:
    # (c) a per-lane FIFO break FAILs the verdict even though the count balance (no_loss) holds.
    r = _drive_report(lane_inversions=2)
    assert r.no_loss is True and r.ok is False


def test_reconcile_fails_on_duplicates() -> None:
    # No kill ⇒ duplicates are a strict-zero FAIL, count balance notwithstanding.
    r = _drive_report(lane_repeats=1)
    assert r.no_loss is True and r.ok is False


def test_reconcile_fails_on_vacuous_lanes() -> None:
    # (d) lanes_observed < 2 ⇒ the per-lane FIFO check went vacuous — must NOT certify.
    r = _drive_report(lanes_observed=1)
    assert r.no_loss is True and r.ok is False


def test_reconcile_fails_on_zero_intake() -> None:
    # (e) A == 0 would make the count identity VACUOUSLY hold (0 == 0), but the collector-nonzero gate
    # (A > 0) folds into no_loss now, so a run that ingested nothing does NOT certify "no loss".
    r = _drive_report(acked=0, sink_received=0, engine_done=0)
    assert r.no_loss is False
    assert r.ok is False


def test_reconcile_fails_on_zero_sink() -> None:
    # S == 0 with A > 0 is a hard loss (nothing delivered) — no_loss false AND the S>0 gate fails.
    r = _drive_report(sink_received=0)
    assert r.no_loss is False and r.ok is False


def test_drive_report_ceiling_on_intake_shortfall() -> None:
    # Reuse of the #836 ceiling: intake materially short of offered (beyond _INTAKE_TOL) ⇒ ceiling, even
    # though (with the counts still balanced) no_loss holds.
    r = _drive_report(offered=200)  # A=150 < 200*0.95=190 ⇒ ceiling
    assert r.no_loss is True and r.ceiling is True


def test_reconcile_r1_real_loss_ceiling_regardless_of_poller() -> None:
    # r1 (real loss): sinks delivered far fewer than A*dests (S=100 << 300) ⇒ no_loss False, ok False,
    # and ceiling True (not no_loss). A HEALTHY poller (done==A*dests, drained, dead=0) must NOT mask it —
    # the verdict is sink-truth, so a store-marked-done-but-socket-dropped loss is still caught.
    r = _drive_report(sink_received=100, engine_done=300, engine_dead=0, drained=True)
    assert r.no_loss is False
    assert r.ok is False
    assert r.ceiling is True


def test_drive_report_renders_and_serializes() -> None:
    r = _drive_report()
    text = r.render()
    assert "verdict=PASS" in text and "fanout(dests)=2" in text
    # The poller cross-check is rendered but clearly labeled advisory / NOT gated.
    assert "advisory" in text and "NOT gated" in text
    js = r.to_json_dict()
    assert js["kind"] == "shardcert_drive" and js["verdict"] == "PASS"
    assert js["traffic"]["acked"] == 150 and js["traffic"]["sink_received"] == 300
    # The gated correctness block is sink-truth only — the poller terms are NOT in it.
    correctness = js["correctness"]
    assert isinstance(correctness, dict)
    assert "engine_done" not in correctness and "engine_dead" not in correctness
    # The advisory poller fields are retained for telemetry, in their own labeled block.
    advisory = js["advisory_poller"]
    assert isinstance(advisory, dict)
    assert advisory["engine_done"] == 300 and advisory["engine_dead"] == 0
    assert advisory["in_pipeline_final"] == 0 and advisory["drained"] is True
    assert "NOT gated" in str(advisory["note"])


# --- Layer 3: full coordinator round-trip (faked spawn + poller) ------------------------------------


class _FakeProc:
    def __init__(self) -> None:
        self.returncode = 0
        self.killed = False

    async def communicate(self) -> tuple[bytes, bytes]:
        return (b"", b"")

    def kill(self) -> None:
        self.killed = True


def _flags(argv: list[str]) -> dict[str, str]:
    """Parse a child argv (``["shardcert-sink", "--flag", "val", ...]``) into ``{_sub, --flag: val}``."""
    out: dict[str, str] = {"_sub": argv[0]}
    it = iter(argv[1:])
    for tok in it:
        if tok.startswith("--"):
            out[tok] = next(it, "")
    return out


def _install_coordinator_fakes(
    monkeypatch: pytest.MonkeyPatch,
    *,
    sink_tally: dict[int, dict[str, Any]],
    worker_tally: dict[int, dict[str, Any]],
    engine_final: Any,
    drain_seconds: float | None = 0.01,
    insecure_seen: list[bool] | None = None,
) -> list[list[str]]:
    """Fake the subprocess spawn seam + the engine poller. The faked ``_spawn_proc`` itself WRITES each
    child's expected coord messages (SINK_BOUND/DONE, DRIVER_ARMED/DONE) from the per-index tallies, so
    the coordinator's awaits resolve without any real process or socket. Records the spawned argv."""
    spawned: list[list[str]] = []

    async def fake_spawn(argv: list[str]) -> _FakeProc:
        spawned.append(list(argv))
        f = _flags(argv)
        child = FileDropCoord(f["--coord-dir"], run_id=f["--run-id"])
        if f["_sub"] == "shardcert-sink":
            i = int(f["--sink-index"])
            child.post(f"{SINK_BOUND}.{i}", {"sink_index": i, "ports": [int(f["--sink-base"]) + i]})
            child.post(f"{SINK_DONE}.{i}", {"sink_index": i, **sink_tally[i]})
        elif f["_sub"] == "shardcert-driver-worker":
            j = int(f["--driver-index"])
            child.post(f"{DRIVER_ARMED}.{j}", {"driver_index": j, "bands": [j]})
            child.post(f"{DRIVER_DONE}.{j}", {"driver_index": j, **worker_tally[j]})
        return _FakeProc()

    class FakePoller:
        def __init__(
            self,
            urls: Any,
            token: Any = None,
            *,
            origin: Any = None,
            allow_insecure: bool = False,
        ) -> None:
            if insecure_seen is not None:
                insecure_seen.append(allow_insecure)
            self.final = engine_final

        async def open(self) -> None:
            return None

        async def await_drain(self, *, timeout: float, interval: float) -> float | None:
            return drain_seconds

        async def close(self) -> None:
            return None

    monkeypatch.setattr(sc, "_spawn_proc", fake_spawn)
    monkeypatch.setattr(sc, "EnginePoller", FakePoller)
    return spawned


async def test_coordinator_round_trip_aggregates_sum_of_fakes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The coordinator spawns K sender-workers + M sinks (faked), runs the full handshake
    (DRIVE_START + DRIVE_GO → DRIVER_DONE → drain → DRIVE_COMPLETE → SINK_DONE), and its aggregate is the
    SUM of the workers' intake / the sinks' deliveries (lanes_observed by MAX, ack p50/p99 by max)."""
    import types

    worker_tally = {
        0: {"sent": 100, "acked": 100, "ack_p50_ms": 1.0, "ack_p99_ms": 2.0, "bands": [0]},
        1: {"sent": 50, "acked": 50, "ack_p50_ms": 1.5, "ack_p99_ms": 3.0, "bands": [1]},
    }
    sink_tally = {
        0: {
            "sink_received": 150,
            "lane_inversions": 0,
            "lane_repeats": 0,
            "lanes_observed": 2,
            "ports": [3700],
        },
        1: {
            "sink_received": 150,
            "lane_inversions": 0,
            "lane_repeats": 0,
            "lanes_observed": 2,
            "ports": [3701],
        },
    }
    spawned = _install_coordinator_fakes(
        monkeypatch,
        sink_tally=sink_tally,
        worker_tally=worker_tally,
        engine_final=types.SimpleNamespace(done=300, dead=0, in_pipeline=0),
    )

    coord = FileDropCoord(tmp_path, run_id="d")
    # The engine half advertises the topology (dests=2, sink band == dests, 2 shards x 1 lane = G=2).
    coord.post(
        SHARDS_READY,
        {
            "shards": ["a", "b"],
            "inbound_base": 3600,
            "lanes": 1,
            "dests": 2,
            "api_ports": [9001, 9002],
            "sink_base": 3700,
            "sink_ports": 2,
            "sink_port": 3700,
        },
    )
    report = await sc.run_shardcert_drive(
        engine_host="10.0.0.5",
        aggregate_rate=40.0,
        hold_seconds=3.0,
        driver_count=2,
        sink_count=2,
        sink_host="10.0.0.9",
        coord=coord,
    )

    # Aggregate == sum of the fakes.
    assert report.acked == 150 and report.sent == 150  # Σ worker intake
    assert report.sink_received == 300  # Σ sink deliveries == A*dests
    assert report.ack_p50_ms == 1.5 and report.ack_p99_ms == 3.0  # MAX over workers
    assert report.lanes_observed == 2  # MAX over sinks, non-vacuous
    assert report.engine_done == 300 and report.engine_dead == 0 and report.in_pipeline_final == 0
    assert report.drained is True
    assert report.no_loss is True and report.ok is True and report.ceiling is False

    # Spawned exactly M=2 sinks + K=2 workers, with the right per-index args + the shared coord scope.
    subs = sorted(a[0] for a in spawned)
    assert subs == [
        "shardcert-driver-worker",
        "shardcert-driver-worker",
        "shardcert-sink",
        "shardcert-sink",
    ]
    sink_argv = [_flags(a) for a in spawned if a[0] == "shardcert-sink"]
    assert {int(f["--sink-index"]) for f in sink_argv} == {0, 1}
    assert all(f["--sink-base"] == "3700" and f["--sink-ports"] == "2" for f in sink_argv)
    assert all(f["--sink-host"] == "10.0.0.9" and f["--run-id"] == "d" for f in sink_argv)
    worker_argv = [_flags(a) for a in spawned if a[0] == "shardcert-driver-worker"]
    assert {int(f["--driver-index"]) for f in worker_argv} == {0, 1}
    assert all(f["--engine-host"] == "10.0.0.5" and f["--driver-count"] == "2" for f in worker_argv)

    # The coordinator drove the whole handshake — every release/complete message round-tripped.
    assert coord.read(DRIVE_START) is not None
    assert coord.read(DRIVE_GO) is not None
    assert coord.read(DRIVE_COMPLETE) is not None
    # Diagnostic child tails were captured (never the authority) — one note per spawned child.
    assert sum(n.startswith("[sink-") or n.startswith("[worker-") for n in report.notes) == 4


async def test_coordinator_threads_derived_drive_complete_timeout_to_sinks(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """REGRESSION (B6, rig handback 2026-07-10): a sink bounds its DRIVE_COMPLETE await, but that window
    OPENS at its SINK_BOUND post and CLOSES at the coordinator's DRIVE_COMPLETE — strictly WIDER than the
    coordinator's own DRIVER_DONE wait, which the B1 fix already derived. The sink child cannot derive it
    (it never sees hold/drain), so the coordinator must compute it and pass it in the spawn argv. Before
    this fix the child fell back to a hardcoded 600.0: any hold >~540s made every sink truncate its tally
    and drop its socket mid-delivery, and — posting no RUNG_ABORTED marker — slipped past B3's
    abort-invalidation into a REAL stranded>0, i.e. a fabricated collapse. Assert the derived bound
    actually reaches the argv and that a 900s hold clears it."""
    import types

    worker_tally = {
        0: {"sent": 10, "acked": 10, "ack_p50_ms": 1.0, "ack_p99_ms": 2.0, "bands": [0]}
    }
    sink_tally = {
        0: {
            "sink_received": 10,
            "lane_inversions": 0,
            "lane_repeats": 0,
            "lanes_observed": 1,
            "ports": [3700],
        }
    }
    spawned = _install_coordinator_fakes(
        monkeypatch,
        sink_tally=sink_tally,
        worker_tally=worker_tally,
        engine_final=types.SimpleNamespace(done=10, dead=0, in_pipeline=0),
    )

    coord = FileDropCoord(tmp_path, run_id="b6")
    coord.post(
        SHARDS_READY,
        {
            "shards": ["a"],
            "inbound_base": 3600,
            "lanes": 1,
            "dests": 1,
            "api_ports": [9001],
            "sink_base": 3700,
            "sink_ports": 1,
            "sink_port": 3700,
        },
    )
    # The soak's shape: a 900s hold with the ladder's real drain/gate values.
    await sc.run_shardcert_drive(
        engine_host="10.0.0.5",
        aggregate_rate=16.0,
        hold_seconds=900.0,
        driver_count=1,
        sink_count=1,
        sink_host="10.0.0.9",
        coord=coord,
        drain_timeout=150.0,
        await_engine_drained=False,  # keep the fake handshake short; the gate term is unit-tested
    )

    sink_argv = [_flags(a) for a in spawned if a[0] == "shardcert-sink"]
    assert len(sink_argv) == 1
    passed = float(sink_argv[0]["--drive-complete-timeout"])
    expected = sc._derive_drive_complete_timeout(
        900.0,
        150.0,
        child_ready_timeout=120.0,
        engine_drained_timeout=300.0,
        await_engine_drained=False,
    )
    assert passed == expected
    assert passed > 600.0  # the old hardcoded default the sink would otherwise have used
    assert passed > 900.0  # ... and it outlasts the hold itself


async def test_coordinator_threads_allow_insecure_to_remote_poller(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """REGRESSION (rig STEP A 2026-07-08): the coordinator polls the engine's /stats over plaintext http
    to a REMOTE box, so `--insecure` MUST reach the EnginePoller → EngineClient, else it fail-closes on
    the non-loopback URL after spawning children. Assert `allow_insecure` threads through (and defaults
    False so a loopback drive is unaffected)."""
    import types

    worker_tally = {
        0: {"sent": 40, "acked": 40, "ack_p50_ms": 1.0, "ack_p99_ms": 2.0, "bands": [0]}
    }
    sink_tally = {
        0: {
            "sink_received": 40,
            "lane_inversions": 0,
            "lane_repeats": 0,
            "lanes_observed": 2,
            "ports": [3700],
        }
    }
    ready = {
        "shards": ["a"],
        "inbound_base": 3600,
        "lanes": 1,
        "dests": 1,
        "api_ports": [9001],
        "sink_base": 3700,
        "sink_ports": 1,
        "sink_port": 3700,
    }

    for want in (True, False):
        seen: list[bool] = []
        _install_coordinator_fakes(
            monkeypatch,
            sink_tally=sink_tally,
            worker_tally=worker_tally,
            engine_final=types.SimpleNamespace(done=40, dead=0, in_pipeline=0),
            insecure_seen=seen,
        )
        coord = FileDropCoord(tmp_path, run_id=f"ins{want}")
        coord.post(SHARDS_READY, ready)
        await sc.run_shardcert_drive(
            engine_host="10.0.0.5",
            aggregate_rate=20.0,
            hold_seconds=1.0,
            driver_count=1,
            sink_count=1,
            sink_host="10.0.0.9",
            coord=coord,
            allow_insecure=want,
        )
        assert seen == [want], f"poller allow_insecure should be {want}, got {seen}"


async def test_coordinator_fails_loud_on_oversized_sink_count(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A sink_count exceeding the dest-port band fails LOUD before spawning any child (not K/M silently
    doomed children the coordinator can only observe as an opaque timeout)."""
    spawned = _install_coordinator_fakes(
        monkeypatch, sink_tally={}, worker_tally={}, engine_final=None
    )
    coord = FileDropCoord(tmp_path, run_id="d")
    coord.post(
        SHARDS_READY,
        {
            "shards": ["a", "b"],
            "inbound_base": 3600,
            "lanes": 1,
            "dests": 2,
            "api_ports": [9001, 9002],
            "sink_base": 3700,
            "sink_ports": 2,
            "sink_port": 3700,
        },
    )
    with pytest.raises(ValueError, match="would bind no ports"):
        await sc.run_shardcert_drive(
            engine_host="10.0.0.5",
            driver_count=1,
            sink_count=3,  # > sink_ports (2) ⇒ fail loud
            coord=coord,
        )
    assert spawned == []  # nothing spawned — the fleet was rejected up front


async def test_coordinator_fails_loud_on_oversized_driver_count(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """driver_count exceeding G=shards*lanes fails LOUD before spawning (a worker would drive no bands)."""
    spawned = _install_coordinator_fakes(
        monkeypatch, sink_tally={}, worker_tally={}, engine_final=None
    )
    coord = FileDropCoord(tmp_path, run_id="d")
    coord.post(
        SHARDS_READY,
        {
            "shards": ["a"],
            "inbound_base": 3600,
            "lanes": 1,
            "dests": 2,
            "api_ports": [9001],
            "sink_base": 3700,
            "sink_ports": 2,
            "sink_port": 3700,
        },
    )
    with pytest.raises(ValueError, match="would drive no bands"):
        await sc.run_shardcert_drive(
            engine_host="10.0.0.5",
            driver_count=2,  # > G=1 ⇒ fail loud
            sink_count=1,
            coord=coord,
        )
    assert spawned == []
