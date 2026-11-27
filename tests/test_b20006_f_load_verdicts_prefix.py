# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Load-harness verdicts fail closed, on the pre-fix surface (BACKLOG #5438, #5439).

`tests/test_load_verdicts_failclosed.py`, from the fixing PR, cannot be collected against the
pre-fix code: a module-level parametrize builds an `EngineAttribution` with the `attribution_failed`
field the fix added, and several of its cases read the new `MultiShardRecord.problems`. So it cannot
show that it fails on the unfixed code. This file asks the same questions through names that exist
on both sides of the fix: `MultiShardReport.result_ok`, `exit_code` and `to_json_dict()["result"]`,
whether `compare_to_baseline` returns any regression, and the `--load` CLI's exit code. Each failing
case starts from a control that passes on both sides and changes one field.

Synthetic metrics only; no message bodies.
"""

from __future__ import annotations

import argparse
import copy
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


def _ms_report(*records: MultiShardRecord) -> MultiShardReport:
    return MultiShardReport(store_backend="sqlite", cluster_enabled=False, records=list(records))


# --- #5438: the multishard step verdict ----------------------------------------


def test_multishard_clean_record_passes() -> None:
    # The control: without it every FAIL below could be a fixture that never passes at all.
    report = _ms_report(_ms_record())
    assert report.result_ok and report.exit_code == 0
    assert report.to_json_dict()["result"] == "PASS"


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param(
            {"per_engine": (_engine(0), _engine(1, foreign_rows=1))}, id="cross-engine-steal"
        ),
        pytest.param({"per_engine": (_engine(0),)}, id="unattributed"),
        pytest.param({"per_engine": ()}, id="no-attribution"),
        pytest.param(
            {"per_engine": (_engine(0), _engine(1, inbound_rows=0, reads=0))}, id="no-lanes"
        ),
        pytest.param({"per_engine": (_engine(0), _engine(1, reads=0))}, id="idle-engine"),
        pytest.param(
            {"per_engine": (_engine(0), _engine(1, failed_lanes=("IB_E1_CS_00000: bind",)))},
            id="failed-lanes",
        ),
        pytest.param({"drain_seconds": None}, id="drain-timeout"),
        pytest.param({"sent": 0}, id="nothing-sent"),
    ],
)
def test_multishard_step_problem_fails_the_report(overrides: dict[str, object]) -> None:
    report = _ms_report(_ms_record(**overrides))
    assert not report.result_ok
    assert report.exit_code == 1
    assert report.to_json_dict()["result"] == "FAIL"


def test_multishard_one_bad_step_fails_a_sweep() -> None:
    assert not _ms_report(_ms_record(), _ms_record(drain_seconds=None)).result_ok


def test_a_refused_attribution_sign_in_fails_the_step_not_the_sweep(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import harness.load.multishard as multishard
    from harness.load.rigadmin import RigSignInRateLimited, RigSignInRefused

    def _refuse(url: str, *, cacert: object = None) -> object:
        raise RigSignInRateLimited("429")

    monkeypatch.setattr(multishard, "rig_client", _refuse)
    node = cast(Any, type("Node", (), {"url": "https://n", "cacert": None, "node_id": "ms-e1"})())
    try:
        attributions = multishard._attribute_engines_sync([node], 1)
    except RigSignInRefused as exc:
        pytest.fail(f"a refused sign-in escaped attribution and would end the sweep: {exc!r}")
    assert len(attributions) == 1
    assert not _ms_report(_ms_record(per_engine=(_engine(0), attributions[0]))).result_ok


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


def _compare(current: Any, baseline: Any, tolerance: Any = 0.1) -> list[str]:
    # A crash is the defect for a malformed report, so it fails as that, not as an error.
    try:
        return compare_to_baseline(current, baseline, tolerance=tolerance)
    except (AttributeError, TypeError, KeyError, OverflowError) as exc:
        pytest.fail(f"compare_to_baseline crashed instead of returning a regression: {exc!r}")


def test_baseline_controls_pass() -> None:
    # The controls: identical reports, the same NAK rate on twice the traffic, a baseline phase
    # with no e2e samples, and an inconclusive run against an inconclusive baseline are no worse.
    assert _compare(_load_report(), _load_report()) == []
    base = _with(("totals", "nak"), 10)
    assert _compare(_with(("totals", "sent"), 2000, _with(("totals", "nak"), 20)), base) == []
    no_e2e = _with(("phases", 1, "e2e_ms"), {"count": 0, "p99": 0.0})
    assert _compare(_load_report(), no_e2e) == []
    inconclusive = _with(("no_loss",), {"ok": False, "inconclusive": True})
    assert _compare(inconclusive, inconclusive) == []


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
    assert _compare(_load_report(), baseline)


@pytest.mark.parametrize("current", _MALFORMED)
def test_malformed_current_report_is_a_regression_not_a_crash(current: object) -> None:
    assert _compare(current, _load_report())


def _flags(current: Any, baseline: Any, needle: str, tolerance: Any = 0.1) -> None:
    # The needle, not just a non-empty list: the pre-fix code flags some of these cases for an
    # unrelated reason (a boolean rate read as 1.0 msg/s is a throughput drop).
    regressions = _compare(current, baseline, tolerance)
    assert any(needle in r for r in regressions), regressions


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
        pytest.param(_with(("totals", "timeouts"), 300), "timeouts worsened", id="timeouts"),
        pytest.param(
            _with(("engine_side", "dead_letters"), 1), "dead letters worsened", id="dead-letters"
        ),
        pytest.param(
            _with(("engine_side", "dead_letters"), -3),
            "dead letters: negative count",
            id="negative-dead-letters",
        ),
        pytest.param(_with(("totals", "sent"), None), "sent: current value", id="missing-sent"),
        pytest.param(_with(("totals", "sent"), -10), "sent: negative count", id="negative-sent"),
        pytest.param(
            _with(("no_loss",), None), "current no_loss.ok is missing", id="no-loss-missing"
        ),
        pytest.param(
            _with(("no_loss", "ok"), "false"), "current no_loss.ok is missing", id="no-loss-string"
        ),
        pytest.param(
            _with(("phases", 1, "achieved_msg_s"), -5.0),
            "steady: negative throughput",
            id="negative-rate",
        ),
        pytest.param(
            _with(("phases", 1, "e2e_ms", "p99"), -1.0),
            "steady: negative e2e p99",
            id="negative-p99",
        ),
        pytest.param(
            _with(("phases", 1, "e2e_ms"), {"count": -5, "p99": 0.0}),
            "steady: negative e2e count",
            id="negative-e2e-count",
        ),
    ],
)
def test_current_run_regression_is_flagged(current: dict[str, Any], needle: str) -> None:
    baseline = _load_report()
    if needle == "steady: negative e2e count":
        # Against a baseline with samples the count would also read as "no e2e samples".
        baseline = _with(("phases", 1, "e2e_ms"), {"count": 0, "p99": 0.0})
    _flags(current, baseline, needle)


@pytest.mark.parametrize(
    ("baseline", "needle"),
    [
        pytest.param(
            _with(("phases", 1, "achieved_msg_s"), float("nan")),
            "baseline value nan is not a finite number",
            id="nan-rate",
        ),
        pytest.param(
            _with(("phases", 1, "achieved_msg_s"), -5.0),
            "steady: negative throughput",
            id="negative-rate",
        ),
        pytest.param(
            _with(("phases", 1, "e2e_ms", "p99"), -1.0),
            "steady: negative e2e p99",
            id="negative-p99",
        ),
        pytest.param(
            _with(("phases", 1, "e2e_ms"), {"count": -5, "p99": 0.0}),
            "steady: negative e2e count",
            id="negative-e2e-count",
        ),
        pytest.param(_with(("totals", "sent"), -10), "sent: negative count", id="negative-sent"),
    ],
)
def test_malformed_baseline_metric_is_flagged(baseline: dict[str, Any], needle: str) -> None:
    _flags(_load_report(), baseline, needle)


def test_counters_compare_per_message_sent() -> None:
    base = _with(("totals", "nak"), 10)
    _flags(_with(("totals", "nak"), 12, base), base, "NAKs worsened")


def test_p99_regression_from_a_zero_baseline_is_flagged() -> None:
    # A zero p99 over real samples is a floor, so any rise above it is a regression.
    baseline = _with(("phases", 1, "e2e_ms", "p99"), 0.0)
    assert _compare(baseline, baseline) == []
    _flags(_load_report(), baseline, "steady: e2e p99 regressed")


def test_a_loss_against_an_inconclusive_baseline_is_flagged() -> None:
    baseline = _with(("no_loss",), {"ok": False, "inconclusive": True})
    lost = _with(("no_loss",), {"ok": False, "inconclusive": False})
    _flags(lost, baseline, "current run lost messages")


@pytest.mark.parametrize("tolerance", [float("nan"), float("inf"), 1.0, -0.1, False, True])
def test_a_tolerance_outside_a_fraction_is_refused(tolerance: object) -> None:
    _flags(_load_report(), _load_report(), "is not a fraction in [0, 1)", tolerance)


@pytest.mark.parametrize("tolerance", [float("nan"), 1.0, -0.1])
def test_a_bad_tolerance_refuses_before_the_run(
    tolerance: float, monkeypatch: pytest.MonkeyPatch
) -> None:
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
    # The control: a good tolerance reaches the run, so the refusal above is the tolerance's doing.
    args.tolerance = 0.1
    with pytest.raises(AssertionError, match="the load run started"):
        cli._run_load(args)
