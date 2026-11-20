# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Load-harness verdicts fail closed (BACKLOG #5438, #5439).

#5438: the multishard report's PASS read only the per-record no-loss flag, so a step whose own
attribution showed a cross-engine lane steal, an unattributed or idle engine, a timed-out drain or
nothing sent still exited 0. Each case below starts from a clean record that PASSES and changes one
field, so a FAIL here is that field's doing.

#5439: the load baseline comparison raised on a malformed baseline, and returned no regression for
a missing phase, a boolean or non-finite metric, a p99 regression from a zero baseline, and more
errors, NAKs or dead letters. The same control-first shape applies.

Synthetic metrics only; no message bodies.
"""

from __future__ import annotations

import argparse
import copy
import dataclasses
from typing import Any, cast

import pytest

from harness.load.connscale.report import NoLoss
from harness.load.multishard import EngineAttribution, MultiShardRecord, MultiShardReport
from harness.load.report import compare_to_baseline

_C = 3  # inbound lanes per engine


def _engine(k: int, **overrides: object) -> EngineAttribution:
    fields: dict[str, object] = {
        "node_id": f"ms-e{k}",
        "name_tag": f"E{k}",
        "inbound_rows": _C,
        "foreign_rows": 0,
        "reads": 100,
        "failed_lanes": (),
    }
    fields.update(overrides)
    return EngineAttribution(**fields)  # type: ignore[arg-type]


def _ms_record(**overrides: object) -> MultiShardRecord:
    fields: dict[str, object] = {
        "engines": 2,
        "count_per_engine": _C,
        "per_conn_rate": 1.0,
        "offered_aggregate_rate": 6.0,
        "cluster_enabled": False,
        "hold_start_iso": "2026-11-18T00:00:00+00:00",
        "drain_complete_iso": "2026-11-18T00:01:00+00:00",
        "achieved_aggregate_rate": 6.0,
        "delivered_aggregate_rate": 6.0,
        "sent": 200,
        "acked": 200,
        "nak": 0,
        "deferred": 0,
        "no_loss": NoLoss(True, 200, 200, 200, 200, 0, "ok"),
        "in_pipeline_peak": 4,
        "drain_seconds": 1.5,
        "pool_wait_p95_ms": None,
        "ack_p50_ms": 1.0,
        "ack_p95_ms": 2.0,
        "ack_p99_ms": 3.0,
        "per_engine": (_engine(0), _engine(1)),
    }
    fields.update(overrides)
    return MultiShardRecord(**fields)  # type: ignore[arg-type]


def _ms_report(record: MultiShardRecord) -> MultiShardReport:
    return MultiShardReport(store_backend="sqlite", cluster_enabled=False, records=[record])


def test_multishard_clean_record_passes() -> None:
    # The control: without it every FAIL below could be a fixture that never passes at all.
    report = _ms_report(_ms_record())
    assert report.records[0].problems == ()
    assert report.result_ok and report.exit_code == 0
    assert report.to_json_dict()["result"] == "PASS"


@pytest.mark.parametrize(
    ("overrides", "needle"),
    [
        pytest.param(
            {"per_engine": (_engine(0), _engine(1, foreign_rows=1))},
            "cross-engine lane steal",
            id="cross-engine-steal",
        ),
        pytest.param({"per_engine": (_engine(0),)}, "1 of 2 engines attributed", id="unattributed"),
        pytest.param({"per_engine": ()}, "0 of 2 engines attributed", id="no-attribution"),
        pytest.param(
            {"per_engine": (_engine(0), _engine(1, inbound_rows=0, reads=0))},
            "ms-e1: 0 inbound lanes attributed",
            id="no-lanes",
        ),
        pytest.param(
            {
                "per_engine": (
                    _engine(0),
                    _engine(1, inbound_rows=0, reads=0, attribution_failed=True),
                )
            },
            "ms-e1: /connections could not be read for attribution",
            id="unreachable-engine",
        ),
        pytest.param(
            {"per_engine": (_engine(0), _engine(1, reads=0))},
            "ms-e1: read nothing",
            id="idle-engine",
        ),
        pytest.param(
            {"per_engine": (_engine(0), _engine(1, failed_lanes=("IB_E1_CS_00000: bind",)))},
            "ms-e1: 1 inbound lanes not listening",
            id="failed-lanes",
        ),
        pytest.param({"drain_seconds": None}, "the drain timed out", id="drain-timeout"),
        pytest.param({"sent": 0}, "nothing was sent", id="nothing-sent"),
        pytest.param(
            {"no_loss": NoLoss(False, 200, 200, 180, 180, 0, "lost 20")},
            "no-loss LOSS: lost 20",
            id="loss",
        ),
    ],
)
def test_multishard_step_problem_fails_the_report(
    overrides: dict[str, object], needle: str
) -> None:
    record = _ms_record(**overrides)
    report = _ms_report(record)
    assert not report.result_ok
    assert report.exit_code == 1
    doc = report.to_json_dict()
    assert doc["result"] == "FAIL"
    assert any(needle in p for p in record.problems), record.problems
    # The reason travels with the verdict: in the artifact and on the console.
    records = doc["records"]
    assert isinstance(records, list)
    assert any(needle in p for p in records[0]["problems"])
    assert needle in report.render_console()


def test_multishard_revealed_lane_reasons_stay_out_of_the_console() -> None:
    # The reasons come from the audited `/connections` reveal, a PHI read, so they belong only in
    # the JSON artifact's `failed_lanes`, never in `problems` or the console and CI log.
    sentinel = "SENTINEL-REVEALED-REASON-5438"
    engine = _engine(1, failed_lanes=(f"IB_E1_CS_00000: {sentinel}",))
    record = _ms_record(per_engine=(_engine(0), engine))
    report = _ms_report(record)
    assert not report.result_ok
    assert any("ms-e1: 1 inbound lanes not listening" in p for p in record.problems)
    assert not any(sentinel in p for p in record.problems), record.problems
    assert sentinel not in report.render_console()
    records = report.to_json_dict()["records"]
    assert isinstance(records, list)
    assert records[0]["per_engine"][1]["failed_lanes"] == [f"IB_E1_CS_00000: {sentinel}"]


def test_multishard_one_bad_step_fails_a_sweep() -> None:
    bad = dataclasses.replace(_ms_record(), drain_seconds=None)
    report = MultiShardReport(
        store_backend="sqlite", cluster_enabled=False, records=[_ms_record(), bad]
    )
    assert not report.result_ok


def test_multishard_empty_sweep_fails() -> None:
    assert not MultiShardReport(store_backend="sqlite", cluster_enabled=False).result_ok


# --- #5439: the load baseline comparison -------------------------------------


def _phase(name: str, *, rate: object = 100.0, p99: object = 20.0) -> dict[str, Any]:
    return {
        "name": name,
        "measured": True,
        "achieved_msg_s": rate,
        "e2e_ms": {"count": 500, "p99": p99},
    }


def _load_report() -> dict[str, Any]:
    return {
        "phases": [_phase("warmup", rate=50.0), _phase("steady")],
        "totals": {"sent": 1000, "errors": 0, "nak": 0, "timeouts": 0},
        "engine_side": {"dead_letters": 0},
        "no_loss": {"ok": True},
    }


def _with(path: tuple[str | int, ...], value: object, doc: Any = None) -> dict[str, Any]:
    doc = copy.deepcopy(_load_report() if doc is None else doc)
    cur: Any = doc
    for key in path[:-1]:
        cur = cur[key]
    cur[path[-1]] = value
    return doc


def test_baseline_identical_reports_pass() -> None:
    assert compare_to_baseline(_load_report(), _load_report(), tolerance=0.1) == []


_MALFORMED = [
    pytest.param([], id="list"),
    pytest.param("x", id="string"),
    pytest.param(None, id="null"),
    pytest.param({**_load_report(), "phases": "x"}, id="phases-not-list"),
    pytest.param({**_load_report(), "phases": [1]}, id="phase-not-object"),
    pytest.param({**_load_report(), "phases": [{"name": ["x"]}]}, id="phase-name-unhashable"),
    pytest.param({**_load_report(), "phases": [{"achieved_msg_s": 1.0}]}, id="phase-no-name"),
]


@pytest.mark.parametrize(
    "baseline", [*_MALFORMED, pytest.param({**_load_report(), "phases": []}, id="no-phases")]
)
def test_malformed_baseline_is_a_regression_not_a_crash(baseline: object) -> None:
    assert compare_to_baseline(_load_report(), baseline, tolerance=0.1)


@pytest.mark.parametrize("current", _MALFORMED)
def test_malformed_current_report_is_a_regression_not_a_crash(current: object) -> None:
    assert compare_to_baseline(current, _load_report(), tolerance=0.1)


def test_unreadable_phases_do_not_hide_the_counter_checks() -> None:
    current = _with(("phases",), "x", _with(("engine_side", "dead_letters"), 5))
    regressions = compare_to_baseline(current, _load_report(), tolerance=0.1)
    assert any("current report has no phases list" in r for r in regressions), regressions
    assert any("dead letters worsened" in r for r in regressions), regressions


def test_a_repeated_phase_name_is_compared_in_run_order() -> None:
    # A profile may repeat a phase name; both occurrences are compared, the second by position.
    report = {**_load_report(), "phases": [_phase("spike"), _phase("calm"), _phase("spike")]}
    assert compare_to_baseline(report, report, tolerance=0.1) == []
    slow = _with(("phases", 2, "achieved_msg_s"), 10.0, report)
    regressions = compare_to_baseline(slow, report, tolerance=0.1)
    assert any("spike (2): throughput regressed" in r for r in regressions), regressions
    short = {**report, "phases": report["phases"][:2]}
    regressions = compare_to_baseline(short, report, tolerance=0.1)
    assert any("spike (2): phase is in the baseline but missing" in r for r in regressions)


@pytest.mark.parametrize(
    ("current", "needle"),
    [
        pytest.param(
            {**_load_report(), "phases": [_phase("warmup", rate=50.0)]},
            "steady: phase is in the baseline but missing",
            id="missing-phase",
        ),
        pytest.param(_with(("phases", 1, "achieved_msg_s"), True), "not a finite", id="bool-rate"),
        pytest.param(
            _with(("phases", 1, "achieved_msg_s"), float("nan")), "not a finite", id="nan-rate"
        ),
        pytest.param(
            _with(("phases", 1, "achieved_msg_s"), 10**400), "not a finite", id="huge-int"
        ),
        pytest.param(
            _with(("phases", 1, "e2e_ms", "p99"), float("inf")), "not a finite", id="inf-p99"
        ),
        pytest.param(_with(("phases", 1, "e2e_ms"), None), "not a finite", id="missing-p99"),
        pytest.param(
            _with(("phases", 1, "e2e_ms"), {"count": 0, "p99": 0.0}),
            "steady: no e2e samples in the current run",
            id="empty-e2e-histogram",
        ),
        pytest.param(_with(("totals", "errors"), 3), "errors worsened", id="errors"),
        pytest.param(_with(("totals", "nak"), 2), "NAKs worsened", id="naks"),
        pytest.param(
            _with(("engine_side", "dead_letters"), 1), "dead letters worsened", id="dead-letters"
        ),
        pytest.param(_with(("totals", "sent"), None), "sent: current value", id="missing-sent"),
        pytest.param(
            _with(("no_loss",), None), "current no_loss.ok is missing", id="no-loss-missing"
        ),
        pytest.param(
            _with(("no_loss", "ok"), "false"), "current no_loss.ok is missing", id="no-loss-string"
        ),
        pytest.param(
            _with(("no_loss",), {"ok": False}), "current run lost messages", id="no-loss-regressed"
        ),
    ],
)
def test_current_run_regression_is_flagged(current: dict[str, Any], needle: str) -> None:
    regressions = compare_to_baseline(current, _load_report(), tolerance=0.1)
    assert any(needle in r for r in regressions), regressions


def test_counters_compare_per_message_sent() -> None:
    # The same NAK rate on a run that sent twice as much is not a regression; a higher rate is.
    base = _with(("totals", "nak"), 10)
    doubled = _with(("totals", "sent"), 2000, _with(("totals", "nak"), 20))
    assert compare_to_baseline(doubled, base, tolerance=0.1) == []
    worse = _with(("totals", "nak"), 12, base)
    assert any("NAKs worsened" in r for r in compare_to_baseline(worse, base, tolerance=0.1))


def test_p99_regression_from_a_zero_baseline_is_flagged() -> None:
    # A zero p99 over real samples is a floor, so any rise above it is a regression.
    baseline = _with(("phases", 1, "e2e_ms", "p99"), 0.0)
    regressions = compare_to_baseline(_load_report(), baseline, tolerance=0.1)
    assert any("steady: e2e p99 regressed" in r for r in regressions), regressions
    assert compare_to_baseline(baseline, baseline, tolerance=0.1) == []


def test_a_baseline_phase_with_no_e2e_samples_has_no_p99_to_compare() -> None:
    # An empty histogram reports p99 0.0; that is "not measured", not a floor.
    baseline = _with(("phases", 1, "e2e_ms"), {"count": 0, "p99": 0.0})
    assert compare_to_baseline(_load_report(), baseline, tolerance=0.1) == []


def test_non_finite_baseline_metric_is_flagged() -> None:
    baseline = _with(("phases", 1, "achieved_msg_s"), float("nan"))
    regressions = compare_to_baseline(_load_report(), baseline, tolerance=0.1)
    assert any("baseline value nan is not a finite number" in r for r in regressions), regressions


@pytest.mark.parametrize("tolerance", [float("nan"), float("inf"), 1.0, -0.1])
def test_a_tolerance_outside_a_fraction_is_refused(tolerance: float) -> None:
    # NaN answers every threshold False, and 1.0 puts the throughput floor at zero.
    regressions = compare_to_baseline(_load_report(), _load_report(), tolerance=tolerance)
    assert any("is not a fraction in [0, 1)" in r for r in regressions), regressions


@pytest.mark.parametrize("tolerance", [float("nan"), 1.0, -0.1])
def test_a_bad_tolerance_refuses_before_the_run(
    tolerance: float, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # A bad --tolerance refuses as a setup error at once, not after a full load run.
    import harness.__main__ as cli
    import harness.load.runner as runner

    def _no_run(*args: object, **kwargs: object) -> object:
        raise AssertionError("the load run started with a bad --tolerance")

    monkeypatch.setattr(runner, "run_load", _no_run)
    args = argparse.Namespace(
        load="reference",
        baseline="b.json",
        tolerance=tolerance,
        engine="https://127.0.0.1:1",
        token=None,
        sink_port=None,
        sink_ports=None,
        db_backend=None,
        skip_preflight=True,
        shard_engine=None,
        cacert=None,
    )
    assert cli._run_load(args) == 2
    assert "is not a fraction in [0, 1)" in capsys.readouterr().err
    # The control: a good tolerance reaches the run, so the refusal above is the tolerance's doing.
    args.tolerance = 0.1
    with pytest.raises(AssertionError, match="the load run started"):
        cli._run_load(args)


def test_a_loss_against_an_inconclusive_baseline_is_flagged() -> None:
    baseline = _with(("no_loss",), {"ok": False, "inconclusive": True})
    lost = _with(("no_loss",), {"ok": False, "inconclusive": False})
    regressions = compare_to_baseline(lost, baseline, tolerance=0.1)
    assert any("current run lost messages" in r for r in regressions), regressions
    # The control: an inconclusive run against an inconclusive baseline is no worse.
    assert compare_to_baseline(baseline, baseline, tolerance=0.1) == []


def test_timeouts_and_negative_counters_are_flagged() -> None:
    more = compare_to_baseline(_with(("totals", "timeouts"), 300), _load_report(), tolerance=0.1)
    assert any("timeouts worsened" in r for r in more), more
    reset = compare_to_baseline(
        _with(("engine_side", "dead_letters"), -3), _load_report(), tolerance=0.1
    )
    assert any("dead letters: negative count" in r for r in reset), reset


@pytest.mark.parametrize(
    ("side", "count"),
    [pytest.param("baseline", -5, id="baseline"), pytest.param("current", -5, id="current")],
)
def test_a_negative_e2e_count_is_flagged(side: str, count: int) -> None:
    # A sample count below zero is a malformed report, not "the baseline measured nothing".
    bad = _with(("phases", 1, "e2e_ms"), {"count": count, "p99": 0.0})
    if side == "baseline":
        regressions = compare_to_baseline(_load_report(), bad, tolerance=0.1)
    else:
        empty = _with(("phases", 1, "e2e_ms"), {"count": 0, "p99": 0.0})
        regressions = compare_to_baseline(bad, empty, tolerance=0.1)
    assert any("steady: negative e2e count" in r for r in regressions), regressions


@pytest.mark.parametrize(
    ("path", "value", "needle"),
    [
        pytest.param(("phases", 1, "achieved_msg_s"), -5.0, "negative throughput", id="rate"),
        pytest.param(("phases", 1, "e2e_ms", "p99"), -1.0, "negative e2e p99", id="p99"),
    ],
)
@pytest.mark.parametrize("side", ["baseline", "current"])
def test_a_negative_phase_metric_is_flagged(
    side: str, path: tuple[str | int, ...], value: float, needle: str
) -> None:
    bad = _with(path, value)
    pair = (_load_report(), bad) if side == "baseline" else (bad, _load_report())
    regressions = compare_to_baseline(pair[0], pair[1], tolerance=0.1)
    assert any(f"steady: {needle}" in r for r in regressions), regressions


@pytest.mark.parametrize("tolerance", [False, True])
def test_a_bool_tolerance_is_refused(tolerance: bool) -> None:
    regressions = compare_to_baseline(_load_report(), _load_report(), tolerance=tolerance)
    assert any("is not a fraction in [0, 1)" in r for r in regressions), regressions


@pytest.mark.parametrize("side", ["baseline", "current"])
def test_a_negative_sent_is_flagged_with_no_counters(side: str) -> None:
    # Every counter is zero, so the per-sent rate check never runs; the negative sent must still
    # be named rather than skipped.
    bad = _with(("totals", "sent"), -10)
    pair = (_load_report(), bad) if side == "baseline" else (bad, _load_report())
    regressions = compare_to_baseline(pair[0], pair[1], tolerance=0.1)
    assert any("sent: negative count" in r for r in regressions), regressions


def test_a_phase_named_like_a_repeat_is_still_compared() -> None:
    report = {**_load_report(), "phases": [_phase("a"), _phase("a (2)"), _phase("a")]}
    assert compare_to_baseline(report, report, tolerance=0.1) == []
    slow = _with(("phases", 1, "achieved_msg_s"), 1.0, report)
    regressions = compare_to_baseline(slow, report, tolerance=0.1)
    assert any(r.startswith("a (2): throughput regressed") for r in regressions), regressions


def test_a_refused_attribution_sign_in_fails_the_step_not_the_sweep(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import harness.load.multishard as multishard
    from harness.load.rigadmin import RigSignInRateLimited

    def _refuse(url: str, *, cacert: object = None) -> object:
        raise RigSignInRateLimited("429")

    monkeypatch.setattr(multishard, "rig_client", _refuse)
    node = cast(Any, type("Node", (), {"url": "https://n", "cacert": None, "node_id": "ms-e1"})())
    (attribution,) = multishard._attribute_engines_sync([node], 1)
    assert attribution.attribution_failed
    record = _ms_record(per_engine=(_engine(0), attribution))
    assert "ms-e1: /connections could not be read for attribution" in record.problems
    assert not _ms_report(record).result_ok
