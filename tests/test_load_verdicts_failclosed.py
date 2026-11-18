# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Load-harness verdicts fail closed (BACKLOG #5438, #5439).

#5438: the multishard report's PASS read only the per-record no-loss flag, so a step whose own
attribution showed a cross-engine lane steal, an unattributed or idle engine, a timed-out drain or
nothing sent still exited 0. Each case below starts from a clean record that PASSES and changes one
field, so a FAIL here is that field's doing.

Synthetic metrics only; no message bodies.
"""

from __future__ import annotations

import dataclasses

import pytest

from harness.load.connscale.report import NoLoss
from harness.load.multishard import EngineAttribution, MultiShardRecord, MultiShardReport

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
