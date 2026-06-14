"""Report assembly: no-loss reconciliation, SLO verdict, JSON/CSV shape (no PHI), baseline compare.

Pure — feeds synthetic counters/histograms/engine-samples, so no engine or sockets. Also checks the
engine poller's sample parsing against a fake client.
"""

from __future__ import annotations

from types import SimpleNamespace

from harness.load.enginepoll import EnginePoller, EngineSample
from harness.load.metrics import Counters, Histogram
from harness.load.profile import load_profile_text
from harness.load.report import PhaseRecord, build_report, compare_to_baseline

_PROFILE = """
[load]
name = "rep"
[[load.target]]
name = "hub"
types = ["ADT"]
[load.mix]
"ADT^A05" = 1.0
[load.slo]
min_sustained_msg_s = 5.0
max_e2e_p99_ms = 5000.0
zero_loss = true
max_drain_seconds = 60.0
[[load.phase]]
name = "warm"
kind = "warmup"
loop = "open"
rate_start = 10.0
duration_s = 1.0
[[load.phase]]
name = "steady"
kind = "sustained"
loop = "open"
rate_start = 50.0
duration_s = 10.0
"""


def _hist(value_ms: float, n: int) -> Histogram:
    h = Histogram()
    for _ in range(n):
        h.record(value_ms * 1e6)  # ms → ns
    return h


def _poller(read: int, written: int, *, backlog: int = 0) -> EnginePoller:
    p = EnginePoller("http://x", None, origin=0.0)
    base = EngineSample(0.0, 0, 0, 0, 0, 0, 0, 0, 0, 1000, "wal", 1.0)
    final = EngineSample(10.0, backlog, 0, written, 0, read, written, 0, backlog, 5000, "wal", 11.0)
    p._samples.extend([base, final])
    return p


def _records(sent: int, acked: int, *, nak: int = 0) -> list[PhaseRecord]:
    profile = load_profile_text(_PROFILE)
    warm, steady = profile.phases
    zero = Counters()
    after_warm = Counters(sent=5, acked=5)
    after_steady = Counters(sent=sent, acked=acked, nak=nak, sink_received=0)
    return [
        PhaseRecord(warm, zero, after_warm, _hist(2.0, 5), _hist(20.0, 5), 1.0),
        PhaseRecord(steady, after_warm, after_steady, _hist(3.0, acked), _hist(40.0, acked), 10.0),
    ]


def test_clean_run_passes_all_slos() -> None:
    profile = load_profile_text(_PROFILE)
    sent = 105
    counters = Counters(sent=sent, acked=sent, sink_received=300)
    poller = _poller(read=sent, written=300)
    report = build_report(profile, "http://x", _records(sent, sent), counters, poller, 2.0)
    assert report.no_loss.ok
    assert report.result_ok and report.exit_code == 0
    # The measured phase's achieved rate ~ (105-5)/10 = 10 msg/s ≥ 5.
    steady = next(p for p in report.phases if p.name == "steady")
    assert steady.achieved_msg_s >= 5.0
    assert all(c.ok for c in report.slos)


def test_message_loss_fails_zero_loss() -> None:
    profile = load_profile_text(_PROFILE)
    sent = 105
    counters = Counters(sent=sent, acked=sent, sink_received=300)
    poller = _poller(read=90, written=300)  # engine only received 90 of 105 sent → loss
    report = build_report(profile, "http://x", _records(sent, sent), counters, poller, 2.0)
    assert not report.no_loss.ok
    assert not report.result_ok and report.exit_code == 1
    assert any(c.name == "zero_loss" and not c.ok for c in report.slos)


def test_undrained_backlog_fails_no_loss() -> None:
    profile = load_profile_text(_PROFILE)
    sent = 105
    counters = Counters(sent=sent, acked=sent, sink_received=300)
    poller = _poller(read=sent, written=300, backlog=12)  # 12 still queued
    report = build_report(profile, "http://x", _records(sent, sent), counters, poller, 2.0)
    assert not report.no_loss.ok
    assert "backlog" in report.no_loss.detail


def test_at_least_once_redeliveries_derived() -> None:
    profile = load_profile_text(_PROFILE)
    sent = 105
    counters = Counters(sent=sent, acked=sent, sink_received=305)  # 5 more arrivals than written
    poller = _poller(read=sent, written=300)
    report = build_report(profile, "http://x", _records(sent, sent), counters, poller, 2.0)
    assert report.no_loss.at_least_once_redeliveries == 5


def test_at_least_once_redelivery_is_not_loss() -> None:
    # sink_received > written (re-deliveries) is benign — it must NOT trip the no-loss check.
    profile = load_profile_text(_PROFILE)
    sent = 105
    counters = Counters(sent=sent, acked=sent, sink_received=305)
    poller = _poller(read=sent, written=300)
    report = build_report(profile, "http://x", _records(sent, sent), counters, poller, 2.0)
    assert report.no_loss.ok and report.result_ok


def test_small_loss_fails_strict_zero_loss() -> None:
    # Just 2 of 105 lost on intake: the strict (exact) gate must FAIL — a percentage slack would
    # have silently passed this (and thousands more at scale).
    profile = load_profile_text(_PROFILE)
    sent = 105
    counters = Counters(sent=sent, acked=sent, sink_received=300)
    poller = _poller(read=sent - 2, written=300)
    report = build_report(profile, "http://x", _records(sent, sent), counters, poller, 2.0)
    assert not report.no_loss.ok
    assert any(c.name == "zero_loss" and not c.ok for c in report.slos)
    assert report.exit_code == 1


def test_json_is_metrics_only_no_phi() -> None:
    profile = load_profile_text(_PROFILE)
    sent = 105
    counters = Counters(sent=sent, acked=sent, sink_received=300)
    report = build_report(
        profile, "http://x", _records(sent, sent), counters, _poller(sent, 300), 2.0
    )
    text = report.to_json()
    assert '"schema_version": 1' in text
    # No raw HL7 / control ids / PHI tokens ever reach the artifact.
    for forbidden in ("MSH|", "PID|", "\r", "MEFOR", "^~"):
        assert forbidden not in text
    assert report.to_csv().count("\n") >= 3  # header + 2 phase rows


def test_console_renders_result_line() -> None:
    profile = load_profile_text(_PROFILE)
    sent = 105
    counters = Counters(sent=sent, acked=sent, sink_received=300)
    out = build_report(
        profile, "http://x", _records(sent, sent), counters, _poller(sent, 300), 2.0
    ).render_console()
    assert "RESULT: PASS" in out and "no-loss: OK" in out


def test_baseline_compare_flags_throughput_regression() -> None:
    profile = load_profile_text(_PROFILE)
    sent = 105
    base = build_report(
        profile,
        "http://x",
        _records(sent, sent),
        Counters(sent=sent, acked=sent, sink_received=300),
        _poller(sent, 300),
        2.0,
    ).to_json_dict()
    # A current run with half the throughput in the steady phase.
    slow = build_report(
        profile,
        "http://x",
        _records(sent, 55),
        Counters(sent=sent, acked=55, sink_received=165),
        _poller(sent, 165),
        2.0,
    ).to_json_dict()
    regressions = compare_to_baseline(slow, base, tolerance=0.1)
    assert any("throughput regressed" in r for r in regressions)
    assert compare_to_baseline(base, base, tolerance=0.1) == []  # identical → no regression


def test_engine_poller_parses_sample_from_client() -> None:
    poller = EnginePoller("http://x", None, origin=0.0)
    poller._client = SimpleNamespace(  # type: ignore[assignment]
        stats=lambda: SimpleNamespace(
            outbox_by_status={"pending": 2, "inflight": 1, "done": 50, "dead": 3}
        ),
        connections=lambda: [
            SimpleNamespace(read=100, written=None, errored=1, queue_depth=None),  # inbound row
            SimpleNamespace(read=None, written=280, errored=3, queue_depth=3),  # outbound row
            SimpleNamespace(read=None, written=20, errored=0, queue_depth=0),  # outbound row
        ],
        status=lambda: SimpleNamespace(
            db=SimpleNamespace(size_bytes=4096, journal_mode="wal"),
            engine=SimpleNamespace(uptime_seconds=12.0),
        ),
    )
    sample = poller._sample_sync()
    assert sample is not None
    assert sample.read == 100  # only inbound row contributes read
    assert sample.written == 300  # 280 + 20 outbound
    assert sample.out_dead == 3  # errored summed over outbound rows
    assert sample.backlog == 3 and sample.queue_depth == 3
    assert sample.db_size_bytes == 4096
