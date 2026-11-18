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

import copy
import dataclasses
from typing import Any

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
    return {"name": name, "measured": True, "achieved_msg_s": rate, "e2e_ms": {"p99": p99}}


def _load_report() -> dict[str, Any]:
    return {
        "phases": [_phase("warmup", rate=50.0), _phase("steady")],
        "totals": {"errors": 0, "nak": 0},
        "engine_side": {"dead_letters": 0},
        "no_loss": {"ok": True},
    }


def _with(path: tuple[str | int, ...], value: object) -> dict[str, Any]:
    doc = copy.deepcopy(_load_report())
    cur: Any = doc
    for key in path[:-1]:
        cur = cur[key]
    cur[path[-1]] = value
    return doc


def test_baseline_identical_reports_pass() -> None:
    assert compare_to_baseline(_load_report(), _load_report(), tolerance=0.1) == []


@pytest.mark.parametrize(
    "baseline",
    [
        pytest.param([], id="list"),
        pytest.param("x", id="string"),
        pytest.param(None, id="null"),
        pytest.param({"phases": "x"}, id="phases-not-list"),
        pytest.param({"phases": [1]}, id="phase-not-object"),
        pytest.param({"phases": [{"name": ["unhashable"]}]}, id="phase-name-unhashable"),
        pytest.param({"phases": [{"achieved_msg_s": 1.0}]}, id="phase-no-name"),
        pytest.param({"phases": [_phase("steady"), _phase("steady")]}, id="duplicate-phase"),
        pytest.param({"phases": []}, id="no-phases"),
    ],
)
def test_malformed_baseline_is_a_regression_not_a_crash(baseline: object) -> None:
    assert compare_to_baseline(_load_report(), baseline, tolerance=0.1)


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
            _with(("phases", 1, "e2e_ms", "p99"), float("inf")), "not a finite", id="inf-p99"
        ),
        pytest.param(_with(("phases", 1, "e2e_ms"), None), "not a finite", id="missing-p99"),
        pytest.param(_with(("totals", "errors"), 3), "errors worsened", id="errors"),
        pytest.param(_with(("totals", "nak"), 2), "NAKs worsened", id="naks"),
        pytest.param(
            _with(("engine_side", "dead_letters"), 1), "dead letters worsened", id="dead-letters"
        ),
    ],
)
def test_current_run_regression_is_flagged(current: dict[str, Any], needle: str) -> None:
    regressions = compare_to_baseline(current, _load_report(), tolerance=0.1)
    assert any(needle in r for r in regressions), regressions


def test_p99_regression_from_a_zero_baseline_is_flagged() -> None:
    baseline = _with(("phases", 1, "e2e_ms", "p99"), 0.0)
    regressions = compare_to_baseline(_load_report(), baseline, tolerance=0.1)
    assert any("steady: e2e p99 regressed" in r for r in regressions), regressions
    assert compare_to_baseline(baseline, baseline, tolerance=0.1) == []


def test_non_finite_baseline_metric_is_flagged() -> None:
    baseline = _with(("phases", 1, "achieved_msg_s"), float("nan"))
    regressions = compare_to_baseline(_load_report(), baseline, tolerance=0.1)
    assert any("baseline value nan is not a finite number" in r for r in regressions), regressions
