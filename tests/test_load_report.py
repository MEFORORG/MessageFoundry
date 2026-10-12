# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Report assembly: no-loss reconciliation, SLO verdict, JSON/CSV shape (no PHI), baseline compare.

Pure — feeds synthetic counters/histograms/engine-samples, so no engine or sockets. Also checks the
engine poller's sample parsing against a fake client.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from harness.load.enginepoll import EnginePoller, EngineSample, PollerCalibration
from harness.load.metrics import Counters, Histogram
from harness.load.profile import load_profile_text
from harness.load.report import PhaseRecord, _spreadsheet_safe, build_report, compare_to_baseline
from messagefoundry.apiclient import ApiError

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


def _poller(
    read: int,
    written: int,
    *,
    backlog: int = 0,
    committed_txns: int = 0,
    body_copies: int = 0,
    poller_requests: int = 0,
    calibration: PollerCalibration | None = None,
) -> EnginePoller:
    p = EnginePoller("http://x", None, origin=0.0)
    p._calibration = calibration
    base = EngineSample(0.0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1000, "wal", "normal", 1.0)
    # ``committed_txns``/``body_copies`` are the FINAL readings; the baseline stays 0, so the run delta
    # == the value passed (#207). Left 0 (the default) they exercise the Postgres "unwired counter"
    # path — the figure must render "not measured", never a fabricated 0/msg.
    final = EngineSample(
        10.0,
        backlog,
        0,
        written,
        0,
        read,
        written,
        0,
        backlog,
        backlog,
        5000,
        "wal",
        "normal",
        11.0,
        committed_txns=committed_txns,
        body_copies=body_copies,
        poller_requests=poller_requests,
    )
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
    # 4 to 5: engine_side gained the poller's own cost (vault BACKLOG #2794).
    assert '"schema_version": 5' in text
    # No raw HL7 / control ids / PHI tokens ever reach the artifact.
    for forbidden in ("MSH|", "PID|", "\r", "MEFOR", "^~"):
        assert forbidden not in text
    assert report.to_csv().count("\n") >= 3  # header + 2 phase rows


def test_spreadsheet_safe_neutralizes_formula_triggers() -> None:
    # WP-L3-08 / ASVS 1.2.10: a cell beginning with a formula trigger is prefixed with a literal "'".
    assert _spreadsheet_safe("=1+1") == "'=1+1"
    assert _spreadsheet_safe("+SUM(A1)") == "'+SUM(A1)"
    assert _spreadsheet_safe("-2+cmd") == "'-2+cmd"
    assert _spreadsheet_safe("@cmd") == "'@cmd"
    assert _spreadsheet_safe("\tTAB") == "'\tTAB"
    # Benign names (and the empty string) pass through untouched.
    assert _spreadsheet_safe("steady") == "steady"
    assert _spreadsheet_safe("") == ""


def test_to_csv_escapes_formula_in_string_cell() -> None:
    # A profile name beginning with "=" reaches the CSV neutralized, never as a raw formula cell.
    profile = load_profile_text(_PROFILE.replace('name = "rep"', 'name = "=danger()"', 1))
    counters = Counters(sent=105, acked=105, sink_received=300)
    report = build_report(profile, "http://x", _records(105, 105), counters, _poller(105, 300), 2.0)
    csv_text = report.to_csv()
    assert "'=danger()" in csv_text
    # No data row begins with a bare formula trigger (header line is literal column names).
    for line in csv_text.splitlines()[1:]:
        assert not line or line[0] not in "=+-@"


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


def test_measured_txn_per_message_rendered() -> None:
    # #207 loose end 1: committed_txns self-differences to the run delta and divides by the message
    # count (Counters.acked) to render the MEASURED txn/msg beside the analytical 3+2H+2N model.
    profile = load_profile_text(_PROFILE)
    sent = 105
    counters = Counters(sent=sent, acked=sent, sink_received=300)
    # 105 messages, 735 committed transactions ⇒ exactly 7.0/msg (the (H=1, N=1) simple-feed model).
    poller = _poller(read=sent, written=300, committed_txns=735)
    report = build_report(profile, "http://x", _records(sent, sent), counters, poller, 2.0)
    assert report.engine.committed_txns == 735
    assert report.engine.txn_per_message_measured == 7.0
    d = report.to_json_dict()
    engine_side = d["engine_side"]
    assert isinstance(engine_side, dict)
    assert engine_side["committed_txns"] == 735
    assert engine_side["txn_per_message_measured"] == 7.0
    console = report.render_console()
    assert "txn/msg (measured): 7.00/msg" in console
    assert "committed_txns=735" in console


def test_unwired_committed_txns_renders_not_measured_never_zero() -> None:
    # Postgres never wired the counter → it reads a flat 0. The per-message figure MUST be None /
    # "not measured", NEVER a fabricated 0/msg — even though 105 messages were acked. This guard fails
    # loud if a division ever renders 0.0 for an unwired counter.
    profile = load_profile_text(_PROFILE)
    sent = 105
    counters = Counters(sent=sent, acked=sent, sink_received=300)
    poller = _poller(read=sent, written=300, committed_txns=0)  # unwired (Postgres)
    report = build_report(profile, "http://x", _records(sent, sent), counters, poller, 2.0)
    assert report.engine.committed_txns == 0
    assert report.engine.txn_per_message_measured is None  # NOT 0.0
    d = report.to_json_dict()
    engine_side = d["engine_side"]
    assert isinstance(engine_side, dict)
    assert engine_side["txn_per_message_measured"] is None
    console = report.render_console()
    assert "txn/msg (measured): not measured" in console
    # Belt-and-braces: the fabricated "0.00/msg" string never appears.
    assert "0.00/msg" not in console


def test_measured_copies_per_message_rendered_named_by_backend_and_not_as_bytes() -> None:
    # #207 loose end 2 (ADR 0141): body_copies self-differences to the run delta and divides by the
    # message count to render the MEASURED body copies/msg — the live counterpart of the analytical
    # 2+H+N amplification model. It is a COPY COUNT and it is backend-dependent, so both facts are
    # rendered WITH the number, and NO bytes/msg figure is published anywhere in the report.
    profile = load_profile_text(_PROFILE)
    sent = 105
    counters = Counters(sent=sent, acked=sent, sink_received=300)
    # 105 messages x 4 copies each (the 2+H+N simple feed, H=N=1) = 420.
    poller = _poller(read=sent, written=300, body_copies=420)
    report = build_report(
        profile, "http://x", _records(sent, sent), counters, poller, 2.0, db_backend="sqlserver"
    )
    assert report.engine.body_copies == 420
    assert report.engine.copies_per_message == 4.0
    d = report.to_json_dict()
    engine_side = d["engine_side"]
    assert isinstance(engine_side, dict)
    assert engine_side["body_copies"] == 420
    assert engine_side["copies_per_message"] == 4.0
    # The unit and the backend travel WITH the number — a consumer can never read it as bytes, nor
    # carry a SQL Server reading over to SQLite (which dedups an identical fan-out to one copy).
    assert engine_side["copies_per_message_backend"] == "sqlserver"
    assert engine_side["copies_per_message_unit"] == "body copies (NOT bytes)"
    # A2's refusal to publish a bytes/msg number STANDS: no such key exists (ADR 0141).
    assert not any("bytes_per_message" in k for k in engine_side)
    console = report.render_console()
    assert "copies/msg (sqlserver; NOT bytes): 4.00/msg" in console
    assert "body_copies=420" in console


def test_unwired_body_copies_renders_not_measured_never_zero() -> None:
    # Postgres never wired the counter → it reads a flat 0. The per-message figure MUST be None /
    # "not measured", NEVER a fabricated 0/msg — even though 105 messages were acked, each of which
    # writes at least its `messages.raw` + ingress `queue.payload` copies. Red-first guard: a division
    # that renders 0.00/msg for an unwired counter is exactly the plausible-but-wrong publication
    # ADR 0141 forbids.
    profile = load_profile_text(_PROFILE)
    sent = 105
    counters = Counters(sent=sent, acked=sent, sink_received=300)
    poller = _poller(read=sent, written=300, body_copies=0)  # unwired (Postgres)
    report = build_report(
        profile, "http://x", _records(sent, sent), counters, poller, 2.0, db_backend="postgres"
    )
    assert report.engine.body_copies == 0
    assert report.engine.copies_per_message is None  # NOT 0.0
    d = report.to_json_dict()
    engine_side = d["engine_side"]
    assert isinstance(engine_side, dict)
    assert engine_side["copies_per_message"] is None
    console = report.render_console()
    assert "copies/msg (postgres; NOT bytes): not measured" in console
    assert "0.00/msg" not in console


def test_engine_poller_parses_sample_from_client() -> None:
    poller = EnginePoller("http://x", None, origin=0.0)
    # Single-shard parse: one client in the list (the cluster path sums many; see
    # tests/test_enginepoll_aggregate.py). _sample_sync reads self._clients, not the old _client.
    fake_clients: list[Any] = [  # duck-typed EngineClient
        SimpleNamespace(
            stats=lambda: SimpleNamespace(
                outbox_by_status={"pending": 2, "inflight": 1, "done": 50, "dead": 3},
                in_pipeline=4,  # whole-pipeline gauge — deliberately != the outbound-only backlog (3)
            ),
            connections=lambda: [
                SimpleNamespace(read=100, written=None, errored=1, queue_depth=None),  # inbound row
                SimpleNamespace(read=None, written=280, errored=3, queue_depth=3),  # outbound row
                SimpleNamespace(read=None, written=20, errored=0, queue_depth=0),  # outbound row
            ],
            status=lambda: SimpleNamespace(
                db=SimpleNamespace(size_bytes=4096, journal_mode="wal", synchronous="normal"),
                engine=SimpleNamespace(uptime_seconds=12.0),
            ),
        )
    ]
    poller._clients = fake_clients
    sample = poller._sample_sync()
    assert sample is not None
    assert sample.read == 100  # only inbound row contributes read
    assert sample.written == 300  # 280 + 20 outbound
    assert sample.out_dead == 3  # errored summed over outbound rows
    assert sample.backlog == 3 and sample.queue_depth == 3
    assert sample.in_pipeline == 4  # taken straight from /stats, not derived from outbox_by_status
    assert sample.db_size_bytes == 4096
    assert sample.synchronous == "normal"  # B7: the durability mode rides through the sample


# --- vault BACKLOG #2794: the poller's own commits, measured and taken off -------------------------


def _engine_side(report: Any) -> dict[str, Any]:
    engine_side = report.to_json_dict()["engine_side"]
    assert isinstance(engine_side, dict)
    return engine_side


def test_poller_removed_txn_per_message_sits_beside_the_raw_figure() -> None:
    # 105 messages that cost 735 pipeline commits (7.0/msg), plus 60 poller requests at a measured
    # 6 commits per 3-request sample: 120 more. The raw figure keeps them; the second one does not.
    profile = load_profile_text(_PROFILE)
    sent = 105
    counters = Counters(sent=sent, acked=sent, sink_received=300)
    poller = _poller(
        read=sent,
        written=300,
        committed_txns=735 + 120,
        poller_requests=60,
        calibration=PollerCalibration(6, 3),
    )
    report = build_report(profile, "http://x", _records(sent, sent), counters, poller, 2.0)
    assert report.engine.txn_per_message_measured == pytest.approx(855 / 105)
    assert report.engine.txn_per_message_poller_removed == pytest.approx(7.0)
    engine_side = _engine_side(report)
    assert engine_side["committed_txns"] == 855
    assert engine_side["poller_samples"] == 2
    assert engine_side["poller_requests"] == 60
    assert engine_side["poller_renewals"] == 0
    assert engine_side["poller_requests_per_sample"] == 3
    assert engine_side["poller_commits_per_sample_measured"] == 6
    assert engine_side["txn_per_message_poller_removed"] == 7.0
    console = report.render_console()
    assert "txn/msg (measured): 8.14/msg" in console
    assert "txn/msg (engine, poller removed): 7.00/msg" in console
    assert (
        "60 poller requests x 6 commits per 3-request sample measured at idle = 120 commits removed"
        in console
    )


@pytest.mark.parametrize(
    ("committed_txns", "calibration", "per_sample", "note"),
    [
        (855, None, None, "the poller was not calibrated"),
        (
            855,
            PollerCalibration(None, note="an engine did not answer a calibration sample"),
            None,
            "an engine did not answer a calibration sample",
        ),
        # An unwired counter (PostgreSQL, vault BACKLOG #2643) calibrates to a flat 0 as well. That
        # 0 is no evidence the poller is free, so it is not published as a measured cost.
        (0, PollerCalibration(0, 3), None, "the raw figure is not measured"),
        # An idle engine busy with its own work overstates the poller; nothing left is not 0/msg.
        # The calibration itself was taken, so its figure is still published.
        (120, PollerCalibration(6, 3), 6, "is not below committed_txns (120)"),
        # A calibration with no request count cannot be turned into a rate.
        (855, PollerCalibration(6), None, "the calibration counted no requests"),
    ],
)
def test_poller_removed_renders_not_measured_never_a_guess(
    committed_txns: int, calibration: PollerCalibration | None, per_sample: int | None, note: str
) -> None:
    profile = load_profile_text(_PROFILE)
    sent = 105
    counters = Counters(sent=sent, acked=sent, sink_received=300)
    poller = _poller(
        read=sent,
        written=300,
        committed_txns=committed_txns,
        poller_requests=60,
        calibration=calibration,
    )
    report = build_report(profile, "http://x", _records(sent, sent), counters, poller, 2.0)
    assert report.engine.txn_per_message_poller_removed is None
    engine_side = _engine_side(report)
    assert engine_side["txn_per_message_poller_removed"] is None
    assert engine_side["poller_commits_per_sample_measured"] == per_sample
    console = report.render_console()
    assert "txn/msg (engine, poller removed): not measured (" in console
    assert note in console
    assert "0.00/msg" not in console


class _CommittingClient:
    """A fake EngineClient whose engine commits ``per_request`` transactions for every request it
    answers, BEFORE the handler runs, the way the session stamp and grant audit do. Its /stats
    reply therefore already counts the /stats request itself."""

    def __init__(self, per_request: int) -> None:
        self.per_request = per_request
        self.committed = 0

    def _answer(self) -> None:
        self.committed += self.per_request

    def stats(self) -> Any:
        self._answer()
        return SimpleNamespace(outbox_by_status={}, in_pipeline=0, committed_txns=self.committed)

    def connections(self) -> list[Any]:
        self._answer()
        return [SimpleNamespace(read=0, written=None, errored=0, queue_depth=None, port=2600)]

    def status(self) -> Any:
        self._answer()
        return SimpleNamespace(
            db=SimpleNamespace(size_bytes=0, journal_mode="wal", synchronous="normal"),
            engine=SimpleNamespace(uptime_seconds=1.0),
        )


def _committing_poller(shards: int, per_request: int) -> EnginePoller:
    urls = [f"http://shard-{i}" for i in range(shards)]
    poller = EnginePoller(urls, None, origin=0.0)
    clients: list[Any] = [_CommittingClient(per_request) for _ in urls]
    poller._clients = clients
    return poller


@pytest.mark.parametrize(("shards", "per_request"), [(1, 2), (3, 2), (2, 1)])
def test_calibration_measures_the_sample_cost_per_shard_and_audit_setting(
    shards: int, per_request: int
) -> None:
    # Two commits a request with the grant audit on, one with it off; three requests per shard.
    poller = _committing_poller(shards, per_request)
    calibration = poller._calibrate_sync()
    assert calibration == PollerCalibration(3 * shards * per_request, 3 * shards)
    assert poller.calibration is calibration
    assert poller.samples == []  # neither calibration sample is the run's baseline


def test_calibration_that_cannot_sample_is_not_measured() -> None:
    poller = EnginePoller("http://x", None, origin=0.0)
    poller._clients = []
    calibration = poller._calibrate_sync()
    assert calibration.commits_per_sample is None
    assert calibration.note == "no two calibration samples in a row were answered"


def test_poller_requests_cover_the_same_window_as_committed_txns() -> None:
    # The served-ports read between two samples is the poller's too, so it must be counted, and
    # the count must be cut at each shard's /stats read exactly as committed_txns is.
    poller = _committing_poller(3, 2)
    first = poller._sample_sync()
    assert poller.served_ports() == {2600}
    second = poller._sample_sync()
    assert first is not None and second is not None
    requests = second.poller_requests - first.poller_requests
    assert requests == 3 * 3 + 1
    assert second.committed_txns - first.committed_txns == 2 * requests


def _chained(cause: BaseException) -> ApiError:
    try:
        raise ApiError("could not reach engine") from cause
    except ApiError as exc:
        return exc


@pytest.mark.parametrize(
    ("error", "counted"),
    [
        # The engine replied, whatever it then committed.
        (ApiError("refused", status=401), True),
        (ApiError("server error", status=500), True),
        # The engine replied and the client could not decode it; the client chains nothing.
        (ApiError("invalid response from engine: not JSON"), True),
        # The request was sent and the reply was late.
        (_chained(httpx.ReadTimeout("late")), True),
        # The request never arrived.
        (_chained(httpx.ConnectError("refused")), False),
        (_chained(httpx.ConnectTimeout("no route")), False),
    ],
)
def test_a_failed_request_counts_only_when_it_reached_the_engine(
    error: ApiError, counted: bool
) -> None:
    poller = EnginePoller("http://x", None, origin=0.0)

    def call() -> None:
        raise error

    with pytest.raises(ApiError):
        poller._counted(0, call)
    assert poller._requests == [1 if counted else 0]


def test_calibration_keeps_the_cheapest_pair() -> None:
    # The engine's own idle work lands in one pair; it can only add commits, so the cheapest pair
    # is the poller alone.
    poller = _committing_poller(1, 2)
    client: Any = poller._clients[0]
    real_stats = client.stats
    calls = 0

    def stats_with_one_background_commit() -> Any:
        nonlocal calls
        calls += 1
        if calls == 2:
            client.committed += 1
        return real_stats()

    client.stats = stats_with_one_background_commit
    calibration = poller._calibrate_sync()
    assert calibration == PollerCalibration(6, 3)
