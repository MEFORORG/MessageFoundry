# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Always-run unit tests for the failover-load harness — the PURE pieces, no live engines.

The full two-node SIGKILL run is container-gated (``tests/test_load_failover_{postgres,sqlserver}.py``);
these cover the parts that don't need a server DB: ``[load.failover]`` parsing, the
:class:`~harness.load.failover_track.FailoverTracker` reconciliation/ordering, phase splitting, the
per-node env, and the report builder's SLO verdicts under synthetic inputs.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import httpx
import pytest

import harness.load.failover as failover
from harness.load.failover import (
    FailoverError,
    FailoverPorts,
    NodeStats,
    _build_report,
    _KillOutcome,
    _node_env,
    _split_phases,
)
from harness.load.failover_track import FailoverTracker, LeadershipTracker
from harness.load.metrics import Counters
from harness.load.profile import LoadProfileError, load_profile_text

# --- a minimal failover profile for the parsing/report tests -----------------

_PROFILE_TMPL = """
[load]
name = "fo-unit"
pool_size = 1
[[load.target]]
name = "adt"
port = 2600
types = ["ADT"]
[load.mix]
"ADT^A01" = 1.0
{failover}
[[load.phase]]
name = "warmup"
kind = "warmup"
loop = "open"
rate_start = 10.0
duration_s = 1.0
[[load.phase]]
name = "sustained"
kind = "sustained"
loop = "open"
rate_start = 20.0
duration_s = 2.0
"""

_FAILOVER_OK = """
[load.failover]
kill_at_fraction = 0.5
heartbeat_seconds = 2.0
leader_fence_timeout_seconds = 4.0
leader_lease_ttl_seconds = 6.0
recovery_ttl_multiple = 2.0
max_dup_rate = 0.1
"""


def _profile(failover: str = _FAILOVER_OK):
    return load_profile_text(_PROFILE_TMPL.format(failover=failover), where="<test>")


# --- profile parsing ---------------------------------------------------------


def test_failover_table_parses() -> None:
    fo = _profile().failover
    assert fo is not None
    assert fo.kill_at_fraction == 0.5
    assert fo.leader_lease_ttl_seconds == 6.0
    assert fo.max_dup_rate == 0.1


def test_failover_defaults_when_table_minimal() -> None:
    fo = _profile("[load.failover]\nkill_at_fraction = 0.3\n").failover
    assert fo is not None
    assert fo.kill_at_fraction == 0.3
    assert fo.heartbeat_seconds == 2.0  # default
    assert fo.leader_lease_ttl_seconds == 6.0  # default
    assert fo.recovery_ttl_multiple == 2.0  # default
    assert fo.max_promotion_seconds is None


def test_absent_failover_table_is_none() -> None:
    # A profile with NO [load.failover] parses byte-identically (the field defaults to None).
    assert _profile(failover="").failover is None


def test_failover_rejects_bad_lease_ordering() -> None:
    bad = "[load.failover]\nheartbeat_seconds = 5.0\nleader_fence_timeout_seconds = 4.0\n"
    with pytest.raises(LoadProfileError, match="heartbeat_seconds < leader_fence"):
        _profile(bad)


def test_failover_rejects_kill_fraction_at_bounds() -> None:
    with pytest.raises(LoadProfileError, match="kill_at_fraction"):
        _profile("[load.failover]\nkill_at_fraction = 0.0\n")
    with pytest.raises(LoadProfileError, match="kill_at_fraction"):
        _profile("[load.failover]\nkill_at_fraction = 1.0\n")


def test_failover_rejects_unknown_key() -> None:
    with pytest.raises(LoadProfileError, match="unknown key"):
        _profile("[load.failover]\nbogus = 1\n")


# --- FailoverTracker ---------------------------------------------------------


def test_tracker_acked_subset_delivered_is_no_loss() -> None:
    t = FailoverTracker()
    for seq in range(5):
        t.on_ack(seq)
    for seq in range(5):
        t.on_delivery("d0", seq)
    assert t.acked_count == 5
    assert t.delivered_count == 5
    assert t.acked_not_delivered() == 0
    assert t.acked_all_delivered is True


def test_tracker_detects_acknowledged_loss() -> None:
    t = FailoverTracker()
    for seq in range(5):
        t.on_ack(seq)
    for seq in (0, 1, 2, 4):  # 3 acked but never delivered
        t.on_delivery("d0", seq)
    assert t.acked_not_delivered() == 1
    assert t.acked_all_delivered is False


def test_tracker_intake_gap_is_not_loss() -> None:
    # A sent-but-un-ACKed message (the kill window) is never recorded as acked, so it can't count as
    # acknowledged loss even though it never arrives.
    t = FailoverTracker()
    t.on_ack(0)
    t.on_ack(1)
    t.on_delivery("d0", 0)
    t.on_delivery("d0", 1)
    # seq 2 was sent but never acked (and never delivered) — not loss.
    assert t.acked_not_delivered() == 0


def test_tracker_ordering_monotonic_ok() -> None:
    t = FailoverTracker()
    for seq in (0, 3, 5, 9):  # a monotonic subsequence on one lane (destination)
        t.on_delivery("d0", seq)
    assert t.lane_inversions == 0


def test_tracker_ordering_inversion_detected() -> None:
    t = FailoverTracker()
    for seq in (0, 5, 3):  # 3 is a NEW seq arriving below the lane's high-water (5) → a FIFO break
        t.on_delivery("d0", seq)
    assert t.lane_inversions == 1


def test_tracker_redelivery_is_repeat_not_inversion() -> None:
    # An at-least-once re-delivery is an ALREADY-SEEN seq arriving again on the lane — a duplicate,
    # never an ordering violation (the crash-recovery path re-delivers in-flight rows).
    t = FailoverTracker()
    t.on_delivery("d0", 3)
    t.on_delivery("d0", 5)
    t.on_delivery("d0", 3)  # re-delivery of an already-seen seq → a repeat, not an inversion
    assert t.lane_repeats == 1
    assert t.lane_inversions == 0


def test_tracker_per_lane_independence() -> None:
    # Two destinations are independent lanes: a low seq on one is not "out of order" vs a high seq on
    # the other (fan-out delivers every seq to every destination).
    t = FailoverTracker()
    t.on_delivery("d0", 5)
    t.on_delivery("d1", 3)
    assert t.lane_inversions == 0


# --- LeadershipTracker (H6 continuous single-leader SLO) ---------------------


def test_leadership_tracker_single_leader_passes() -> None:
    # The normal failover shape: one leader before the kill, a brief window of zero leaders (post-kill,
    # pre-promotion), then one leader again. Never two → the continuous SLO holds.
    t = LeadershipTracker()
    for n in (1, 1, 0, 0, 1, 1, 1):
        t.observe(n)
    assert t.max_concurrent_leaders == 1
    assert t.two_or_more_leader_samples == 0
    assert t.slo_ok is True
    assert t.samples == 7


def test_leadership_tracker_two_leaders_fails_slo() -> None:
    # Split-brain: a single sample with two simultaneous primaries fails the SLO, even amid many good ones.
    t = LeadershipTracker()
    for n in (1, 1, 2, 1, 1):
        t.observe(n)
    assert t.max_concurrent_leaders == 2
    assert t.two_or_more_leader_samples == 1
    assert t.slo_ok is False


def test_leadership_tracker_vacuous_when_never_observed() -> None:
    # A monitor that never sampled the cluster must NOT silently certify "single leader" off zero
    # evidence — slo_ok is False until at least one observation lands.
    t = LeadershipTracker()
    assert t.samples == 0
    assert t.slo_ok is False


def test_leadership_tracker_rejects_negative() -> None:
    t = LeadershipTracker()
    with pytest.raises(ValueError, match="active_leaders"):
        t.observe(-1)


def test_leadership_tracker_counts_every_split_brain_sample() -> None:
    t = LeadershipTracker()
    for n in (2, 2, 1, 2):
        t.observe(n)
    assert t.two_or_more_leader_samples == 3
    assert t.max_concurrent_leaders == 2
    assert t.slo_ok is False


# --- phase splitting ---------------------------------------------------------


def test_split_phases_warmup_then_measured() -> None:
    prefix, measured = _split_phases(_profile())
    assert [p.name for p in prefix] == ["warmup"]
    assert measured.name == "sustained"


def test_split_phases_rejects_two_measured() -> None:
    two = (
        _PROFILE_TMPL.format(failover=_FAILOVER_OK)
        + """
[[load.phase]]
name = "soak"
kind = "soak"
loop = "open"
rate_start = 20.0
duration_s = 2.0
"""
    )
    with pytest.raises(FailoverError, match="exactly one measured"):
        _split_phases(load_profile_text(two, where="<t>"))


def test_split_phases_rejects_measured_not_last() -> None:
    text = """
[load]
name = "x"
[[load.target]]
name = "a"
port = 2600
types = ["ADT"]
[load.mix]
"ADT^A01" = 1.0
[[load.phase]]
name = "sustained"
kind = "sustained"
loop = "open"
rate_start = 20.0
duration_s = 2.0
[[load.phase]]
name = "cooldown"
kind = "ramp"
loop = "open"
rate_start = 5.0
duration_s = 1.0
"""
    with pytest.raises(FailoverError, match="must be the LAST phase"):
        _split_phases(load_profile_text(text, where="<t>"))


# --- per-node env ------------------------------------------------------------


def test_node_env_configures_cluster_and_forces_pool() -> None:
    fo = _profile().failover
    assert fo is not None
    ports = FailoverPorts(2600, 2601, 2602, 2700, 1, 8801, 8802)
    env = _node_env(
        {"MEFOR_STORE_POOL_SIZE": "1", "PATH": "/x"},
        node_id="fo-a",
        ports=ports,
        fo=fo,
        sink_host="127.0.0.1",
    )
    assert env["MEFOR_CLUSTER_ENABLED"] == "true"
    assert env["MEFOR_CLUSTER_NODE_ID"] == "fo-a"
    assert int(env["MEFOR_STORE_POOL_SIZE"]) >= 5  # forced up from the inherited 1
    assert env["MEFOR_LOAD_ADT_PORT"] == "2600"
    assert env["MEFOR_LOAD_SINK_PORT"] == "2700"
    assert env["PATH"] == "/x"  # inherited env is preserved
    # The lease timings are passed through so both nodes agree on the (short) timing.
    assert float(env["MEFOR_CLUSTER_LEADER_LEASE_TTL_SECONDS"]) == 6.0


# --- report builder ----------------------------------------------------------


def _outcome(
    promotion: float | None = 2.0,
    recovery: float | None = 7.0,
    leaders: int = 1,
    leader_samples: int = 10,
):
    return _KillOutcome(
        killed=SimpleNamespace(node_id="fo-a"),  # type: ignore[arg-type]
        survivor=SimpleNamespace(node_id="fo-b"),  # type: ignore[arg-type]
        promotion_seconds=promotion,
        recovery_seconds=recovery,
        max_concurrent_leaders=leaders,
        leader_samples=leader_samples,
    )


def _counters(*, sent=100, acked=98, sink_received=300) -> Counters:
    return Counters(sent=sent, acked=acked, sink_received=sink_received, timeouts=sent - acked)


def _stats(*, done: int = 0, dead: int = 0, in_pipeline: int = 0) -> NodeStats:
    return NodeStats(done=done, dead=dead, pending=in_pipeline, inflight=0, in_pipeline=in_pipeline)


def _report(*, tracker: FailoverTracker, outcome=None, final=None, counters=None, done_at_start=0):
    fo = _profile().failover
    assert fo is not None
    return _build_report(
        _profile(),
        "postgres",
        counters or _counters(),
        tracker,
        outcome or _outcome(),
        final or _stats(done=294),
        done_at_start=done_at_start,
        fo=fo,
        notes=[],
    )


def _full_tracker(n: int = 98) -> FailoverTracker:
    t = FailoverTracker()
    for seq in range(n):
        t.on_ack(seq)
        # In order on two lanes: no inversions, and enough lanes for per_lane_ordering to judge.
        t.on_delivery("d0", seq)
        t.on_delivery("d1", seq)
    return t


def test_build_report_pass() -> None:
    rep = _report(tracker=_full_tracker())
    assert rep.result_ok is True
    assert rep.exit_code == 0
    assert rep.acked_not_delivered == 0
    assert rep.recovery_seconds == 7.0
    assert rep.intake_gap == 2  # sent 100 − acked 98
    assert all(s.ok for s in rep.slos)


def test_build_report_fails_on_acknowledged_loss() -> None:
    t = FailoverTracker()
    for seq in range(98):
        t.on_ack(seq)
    for seq in range(90):  # 8 acked never delivered
        t.on_delivery("d0", seq)
    rep = _report(tracker=t)
    assert rep.acked_not_delivered == 8
    assert rep.result_ok is False
    assert any(s.name == "no_acknowledged_loss" and not s.ok for s in rep.slos)


def test_build_report_fails_when_pipeline_not_drained() -> None:
    rep = _report(
        tracker=_full_tracker(),
        final=NodeStats(done=294, dead=0, pending=3, inflight=1, in_pipeline=4),
    )
    assert rep.result_ok is False
    assert any(s.name == "no_acknowledged_loss" and not s.ok for s in rep.slos)


def test_build_report_fails_on_recovery_timeout() -> None:
    rep = _report(tracker=_full_tracker(), outcome=_outcome(promotion=None, recovery=None))
    assert rep.result_ok is False
    assert any(s.name == "functional_recovery_seconds" and not s.ok for s in rep.slos)
    assert any(s.name == "promotion_observed" and not s.ok for s in rep.slos)


def test_build_report_fails_on_slow_recovery() -> None:
    # TTL 6 × multiple 2 = 12s bound; 15s recovery must fail.
    rep = _report(tracker=_full_tracker(), outcome=_outcome(recovery=15.0))
    assert rep.result_ok is False
    assert any(s.name == "functional_recovery_seconds" and not s.ok for s in rep.slos)


def test_build_report_fails_on_excess_duplicates() -> None:
    # engine_delivered = done 294; sink_received 600 → 306 dups → rate ~1.04 >> 0.1 cap.
    rep = _report(tracker=_full_tracker(), counters=_counters(sink_received=600))
    assert rep.duplicates == 306
    assert rep.result_ok is False
    assert any(s.name == "max_dup_rate" and not s.ok for s in rep.slos)


def test_build_report_fails_on_ordering_inversion() -> None:
    # Everything acked is delivered (no loss), but one NEW seq arrives below the lane's high-water →
    # a genuine per-lane FIFO break that must fail the conformance SLO.
    t = FailoverTracker()
    for seq in range(98):
        t.on_ack(seq)
    for seq in [
        *range(96),
        97,
        96,
    ]:  # 96 arrives AFTER 97 on lane d0 → inversion; all 0..97 delivered
        t.on_delivery("d0", seq)
    assert t.acked_not_delivered() == 0
    rep = _report(tracker=t)
    assert rep.lane_inversions == 1
    assert rep.result_ok is False
    assert any(s.name == "per_lane_ordering" and not s.ok for s in rep.slos)


def test_build_report_flags_split_brain() -> None:
    rep = _report(tracker=_full_tracker(), outcome=_outcome(leaders=2))
    assert rep.result_ok is False
    assert any(s.name == "single_leader" and not s.ok for s in rep.slos)


def test_build_report_single_leader_slo_is_non_vacuous() -> None:
    # H6: a run where the monitor never observed the cluster (leader_samples == 0) must FAIL the
    # single_leader SLO rather than silently certify it off zero evidence (mirrors lanes_observed >= 2).
    rep = _report(tracker=_full_tracker(), outcome=_outcome(leaders=1, leader_samples=0))
    assert rep.leader_samples == 0
    assert rep.result_ok is False
    assert any(s.name == "single_leader" and not s.ok for s in rep.slos)


def test_build_report_single_leader_passes_with_samples() -> None:
    # The complement: max 1 leader AND at least one observation → the SLO passes and the count surfaces.
    rep = _report(tracker=_full_tracker(), outcome=_outcome(leaders=1, leader_samples=12))
    assert rep.leader_samples == 12
    assert any(s.name == "single_leader" and s.ok for s in rep.slos)


def test_any_dead_row_at_the_end_fails_the_run() -> None:
    # The counters cannot separate carried-over dead rows from new ones, so the check stays absolute.
    rep = _report(tracker=_full_tracker(), done_at_start=5000, final=_stats(done=5294, dead=3))
    assert rep.dead_final == 3
    assert rep.result_ok is False
    assert any(s.name == "no_acknowledged_loss" and not s.ok for s in rep.slos)


def test_duplicates_are_measured_against_the_opening_done_count() -> None:
    # 5000 prior done rows and 200 duplicates: 1000 delivered this run, 1200 reached the sink.
    rep = _report(
        tracker=_full_tracker(),
        counters=_counters(sink_received=1200),
        done_at_start=5000,
        final=_stats(done=6000),
    )
    assert rep.engine_delivered == 1000
    assert rep.duplicates == 200
    assert rep.result_ok is False
    assert any(s.name == "max_dup_rate" and not s.ok for s in rep.slos)


class _StatsNode:
    """Answers ``stats`` from a script; the last answer repeats."""

    node_id = "fo-x"

    def __init__(self, answers: list[NodeStats | None]) -> None:
        self._answers = answers
        self.reads = 0

    async def stats(self, client: object) -> NodeStats | None:
        answer = self._answers[min(self.reads, len(self._answers) - 1)]
        self.reads += 1
        return answer


def test_opening_stats_retries_a_failed_read(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(failover, "_OPENING_STATS_RETRY_S", 0.0)
    good = _stats(done=7, dead=2)
    node = _StatsNode([None, None, good])
    got = asyncio.run(failover._opening_stats([node], object()))  # type: ignore[list-item,arg-type]
    assert got == good
    assert node.reads == 3


def test_opening_stats_gives_up_after_its_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(failover, "_OPENING_STATS_RETRY_S", 0.0)
    node = _StatsNode([None])
    with pytest.raises(FailoverError, match="opening"):
        asyncio.run(failover._opening_stats([node], object()))  # type: ignore[list-item,arg-type]
    assert node.reads == failover._OPENING_STATS_ATTEMPTS


@pytest.mark.parametrize("body", [{}, {"outbox_by_status": None}, {"outbox_by_status": []}])
def test_a_stats_answer_with_no_status_map_is_no_reading(
    body: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    node = failover.EngineNode.__new__(failover.EngineNode)

    async def answer(_client: object, _path: str) -> dict[str, object]:
        return body

    monkeypatch.setattr(node, "_signed_in_json", answer)
    assert asyncio.run(node.stats(object())) is None  # type: ignore[arg-type]


def test_a_stats_answer_with_an_empty_status_map_reads_as_zeros(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    node = failover.EngineNode.__new__(failover.EngineNode)

    async def answer(_client: object, _path: str) -> dict[str, object]:
        return {"outbox_by_status": {}, "in_pipeline": 0}

    monkeypatch.setattr(node, "_signed_in_json", answer)
    assert asyncio.run(node.stats(object())) == _stats()  # type: ignore[arg-type]


def test_a_run_whose_opening_stats_never_read_offers_no_load(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The refusal comes before the dispatcher starts, and the teardown still runs."""
    events: list[str] = []

    class _Node:
        def __init__(self, node_id: str, *_a: object, **_k: object) -> None:
            self.node_id = node_id

        async def start(self, *, provision: bool) -> None:
            return None

        async def stats(self, client: object) -> None:
            return None

        async def stop(self) -> None:
            events.append("node-stop")

    class _Sink:
        def __init__(self, *_a: object, **_k: object) -> None:
            pass

        async def start(self) -> None:
            return None

        async def stop(self) -> None:
            events.append("sink-stop")

    class _Dispatcher:
        def __init__(self, *_a: object, **_k: object) -> None:
            pass

        def start(self) -> None:
            raise AssertionError("load was offered with no opening baseline")

        async def stop(self, _grace: float) -> None:
            events.append("dispatcher-stop")

    async def _noop(*_a: object, **_k: object) -> None:
        return None

    async def _leader(nodes: list[_Node], *_a: object, **_k: object) -> _Node:
        return nodes[0]

    monkeypatch.setattr(failover, "_OPENING_STATS_RETRY_S", 0.0)
    monkeypatch.setattr(failover, "EngineNode", _Node)
    monkeypatch.setattr(failover, "CorrelationSink", _Sink)
    monkeypatch.setattr(failover, "Dispatcher", _Dispatcher)
    monkeypatch.setattr(failover, "ConnectionPool", lambda *_a, **_k: object())
    monkeypatch.setattr(failover, "build_corpus", lambda *_a, **_k: object())
    monkeypatch.setattr(failover, "harness_ssl_context", lambda: True)
    monkeypatch.setattr(failover, "_await_all_healthy", _noop)
    monkeypatch.setattr(failover, "_await_single_leader", _leader)
    monkeypatch.setattr(failover, "_await_port", _noop)

    ports = FailoverPorts(
        api_a=1, api_b=2, inbound_adt=3, inbound_results=4, inbound_other=5, sink=6, sink_count=1
    )
    with pytest.raises(FailoverError, match="opening"):
        asyncio.run(failover.run_failover_load(_profile(), ports=ports, base_env={}))
    assert {"dispatcher-stop", "sink-stop", "node-stop"} <= set(events)


def test_report_json_and_console_smoke() -> None:
    rep = _report(tracker=_full_tracker())
    js = rep.to_json_dict()
    assert js["kind"] == "failover"
    assert js["result"] == "PASS"
    assert js["failover"]["recovery_seconds"] == 7.0
    assert js["failover"]["leader_samples"] == 10  # H6 sample count surfaced in the JSON report
    text = rep.render_console()
    assert "Failover-load report" in text
    assert "RESULT: PASS" in text


# --- the rig's status reads of the engine API (ASVS 5.1.1, BACKLOG #1127) ----


def _status_read(body: bytes) -> tuple[int | None, dict[str, object] | None]:
    """``_get_status_json`` against an engine that answers 200 with ``body``."""

    async def run() -> tuple[int | None, dict[str, object] | None]:
        # A stream, not content=: content= is read up front, and the helper reads the raw stream.
        def answer(request: httpx.Request) -> httpx.Response:
            # No content coding, so no compressed chunk is inflated past the cap.
            assert request.headers["accept-encoding"] == "identity"
            return httpx.Response(200, stream=httpx.ByteStream(body))

        transport = httpx.MockTransport(answer)
        async with httpx.AsyncClient(transport=transport) as client:
            return await failover._get_status_json(client, "https://node.invalid/stats", None)

    return asyncio.run(run())


def test_a_status_answer_past_the_cap_is_no_answer_and_one_at_it_is_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(failover, "MAX_STATUS_REPLY_BYTES", 64)
    assert _status_read(b'{"role": "primary"}') == (200, {"role": "primary"})
    assert _status_read(b"x" * 65) == (None, None)
    # At the cap but not JSON: the status stands, the body does not.
    assert _status_read(b"x" * 64) == (200, None)


# --- the recovery monitor's baseline (BACKLOG #5571) -------------------------

# One scripted poll of the survivor: its role, and the ``done`` values its stats reads return in
# order within that poll (the last repeats; None is a failed read). A poll before promotion reads
# stats once before the role; the promotion poll reads it twice, once on each side of the role.
_Poll = tuple[str | None, list[int | None]]


class _World:
    """The scripted cluster. The monitor's sleep ends a poll, so it moves the script to the next
    poll; the last poll repeats."""

    def __init__(self, polls: list[_Poll]) -> None:
        self._polls = polls
        self._poll = 0
        self._read = 0

    def next_poll(self) -> None:
        self._poll = min(self._poll + 1, len(self._polls) - 1)
        self._read = 0

    def role(self) -> str | None:
        return self._polls[self._poll][0]

    def stats(self) -> NodeStats | None:
        reads = self._polls[self._poll][1]
        done = reads[min(self._read, len(reads) - 1)]
        self._read += 1
        if done is None:
            return None
        return NodeStats(done=done, dead=0, pending=0, inflight=0, in_pipeline=0)


class _ScriptedNode:
    """Stands in for an :class:`EngineNode` in ``_monitor_failover``: the survivor answers from the
    world's script; the killed node is down, so it answers nothing."""

    def __init__(self, node_id: str, world: _World | None = None) -> None:
        self.node_id = node_id
        self._world = world

    async def role(self, client: object) -> str | None:
        return self._world.role() if self._world else None

    async def stats(self, client: object) -> NodeStats | None:
        return self._world.stats() if self._world else None


def _monitor(
    polls: list[_Poll], monkeypatch: pytest.MonkeyPatch, deadline_s: float
) -> tuple[_KillOutcome, list[str]]:
    world = _World(polls)
    real_sleep = asyncio.sleep

    async def end_poll(_seconds: float) -> None:
        world.next_poll()
        await real_sleep(0)

    # Only the failover module sees this sleep: its own asyncio name, not the process-wide module,
    # is swapped, so no other event loop in the process can end a scripted poll.
    monkeypatch.setattr(failover, "asyncio", SimpleNamespace(sleep=end_poll))
    notes: list[str] = []
    outcome = asyncio.run(
        failover._monitor_failover(
            _ScriptedNode("fo-a"),  # type: ignore[arg-type]
            _ScriptedNode("fo-b", world),  # type: ignore[arg-type]
            None,  # type: ignore[arg-type]
            0,
            deadline_s,
            notes,
        )
    )
    return outcome, notes


# A run that should see recovery breaks out at once, so its deadline only bounds a regression; one
# that should not runs to the deadline, which is long enough for the script's few polls to play.
_RECOVERS_WITHIN = 10.0
_TIMES_OUT_AFTER = 0.3


def test_monitor_counts_a_recovery_that_drained_before_promotion_was_seen(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RED when: the baseline is first read on the poll that sees the promotion. The survivor
    promoted and delivered the rest in that gap, so the promotion read already holds the progress
    and nothing later exceeds it: a recovery that completed would read as a timeout."""
    outcome, notes = _monitor(
        [("standby", [100]), ("standby", [100]), ("primary", [150])],
        monkeypatch,
        _RECOVERS_WITHIN,
    )
    assert outcome.promotion_seconds is not None
    assert outcome.recovery_seconds is not None
    assert any("forward progress resumed" in n for n in notes)


def test_monitor_never_reads_a_missing_stats_read_as_a_zero_baseline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RED when: a stats read that fails on the promotion poll sets the baseline to zero, so the
    next read, which shows no new delivery, reads as instant recovery and passes the SLO."""
    outcome, notes = _monitor(
        [("standby", [None]), ("primary", [None, 100]), ("primary", [100])],
        monkeypatch,
        _TIMES_OUT_AFTER,
    )
    assert outcome.promotion_seconds is not None
    assert outcome.recovery_seconds is None
    assert any("NOT observed" in n for n in notes)
    assert any("no stats read was usable as a baseline" in n for n in notes)


@pytest.mark.parametrize(
    ("polls", "recovered"),
    [
        # A failed standby read keeps the last good baseline (100): replacing it with zero would
        # pass the first case, and dropping it would fail the second.
        ([("standby", [100]), ("standby", [None]), ("primary", [100])], False),
        ([("standby", [100]), ("standby", [None]), ("primary", [101])], True),
        # A poll whose role read failed proves nothing about promotion, so its stats read (which
        # already holds the survivor's delivery) must not become the baseline.
        ([("standby", [100]), (None, [150]), ("primary", [150])], True),
    ],
    ids=["failed-read-no-progress", "failed-read-then-progress", "unknown-role"],
)
def test_monitor_moves_the_baseline_only_on_a_good_standby_read(
    monkeypatch: pytest.MonkeyPatch, polls: list[_Poll], recovered: bool
) -> None:
    outcome, _ = _monitor(polls, monkeypatch, _RECOVERS_WITHIN if recovered else _TIMES_OUT_AFTER)
    assert outcome.promotion_seconds is not None
    assert (outcome.recovery_seconds is not None) is recovered
