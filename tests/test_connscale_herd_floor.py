# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The armed empty-claims herd floor (BACKLOG #1415, build 2).

Two things live here. The first is clause (d) of #1415's arming rule: a DELIBERATE NEGATIVE CONTROL,
a herd-gone base reading fed to the armed check, which must trip it while the shipped sign test
passes the same reading. Without it the floor's only evidence would be that it has never fired.

The second is the decision itself, recomputed from the committed harvest on every run. The rule's
clauses (a) to (c) are applied per (leg, lane) cell to
``docs/benchmarks/results/2026-10-01-connscale-herd-floor-harvest/readings.csv``, and the set of
legs that clears all of them must equal the legs the CI profile arms. So the armed set cannot drift
from the evidence by an edit to either side alone.
"""

from __future__ import annotations

import csv
from collections import defaultdict
from pathlib import Path

import pytest

from harness.load.connscale.profile import (
    ConnScaleProfile,
    ConnScaleProfileError,
    load_connscale_profile_text,
)
from harness.load.connscale.report import ConnScaleRecord, predict_herd_levels
from harness.load.connscale.runner import (
    CONNSCALE_LEG_ENV,
    _empty_claims_base_reading_slo,
    _empty_claims_herd_floor_slo,
    current_leg,
    herd_floor_armed,
)
from tests.test_connscale_empty_claims_per_msg import _rec
from tests.test_connscale_smoke import _HERD_FLOOR_LEGS

_ARMED = "ubuntu-latest-py3.14"
_HARVEST = (
    Path(__file__).resolve().parents[1]
    / "docs/benchmarks/results/2026-10-01-connscale-herd-floor-harvest/readings.csv"
)
#: The smoke profile's offered aggregate rate per lane at the base count N=12: aggregate_rate 24.0,
#: and per_conn_rate 1.0 times 12 connections.
_RATE = {"fixed_aggregate": 24.0, "fixed_per_conn": 12.0}
_BASE = 12
#: #1415 clause (a): min(passing base readings) / F must reach this.
_MARGIN = 1.25
#: #1415 clause (c), as the owner set it on 2026-10-01: run 36797223259, job 110163384729,
#: test (windows-2022, py3.14), lane fixed_aggregate, base reading 22.36.
_KNOWN_RUN, _KNOWN_JOB, _KNOWN_LEG, _KNOWN_LANE, _KNOWN_VALUE = (
    "36797223259",
    "110163384729",
    "windows-2022 py3.14",
    "fixed_aggregate",
    22.36,
)


def _profile(
    *legs: str, claim_modes: str = '["per_lane"]', base_reading: str = "true"
) -> ConnScaleProfile:
    return load_connscale_profile_text(
        f"""
[connscale]
name = "unit"
counts = [12, 24]
sweep_mode = "both"
claim_modes = {claim_modes}
aggregate_rate = 24.0
per_conn_rate = 1.0
hold_seconds = 1.5
connect_batch = 8
connect_batch_pause_s = 0.0
poll_interval_s = 0.25
drain_timeout_s = 30.0
base_port = 20000
transform = "cheap"
reload_probe = false
store_backend = "sqlite"
corpus_count_per_trigger = 5

[connscale.slo]
zero_loss = true
empty_claims_base_reading = {base_reading}
empty_claims_herd_floor_legs = {list(legs)}
""",
        where="<unit-test profile>",
    )


def _herd_gone() -> list[ConnScaleRecord]:
    """Both lanes at their predicted HERD-GONE level: positive, and at the idle term exactly."""
    agg = predict_herd_levels(_BASE, _RATE["fixed_aggregate"])
    per_conn = predict_herd_levels(_BASE, _RATE["fixed_per_conn"])
    assert agg is not None and per_conn is not None
    return [
        _rec("fixed_aggregate", 12, per_msg=agg.idle),
        _rec("fixed_aggregate", 24, per_msg=60.0),
        _rec("fixed_per_conn", 12, per_msg=per_conn.idle, rate=_RATE["fixed_per_conn"]),
        _rec("fixed_per_conn", 24, per_msg=60.0, rate=24.0),
    ]


# --- clause (d): the deliberate negative control -------------------------------------------------


def test_a_herd_gone_reading_trips_the_armed_floor_and_passes_the_sign_test() -> None:
    profile = _profile(_ARMED)
    records = _herd_gone()
    check = _empty_claims_herd_floor_slo(profile, records, _ARMED)
    assert check.ok is False, check.observed
    assert "fixed_aggregate@N=12: 6.0 below the predicted floor 15.3" in str(check.observed)
    assert "fixed_per_conn@N=12: 12.0 below the predicted floor 23.24" in str(check.observed)
    # Clause (b): the floor grades more than the sign test. The same records pass that one.
    assert _empty_claims_base_reading_slo(profile, records).ok


def test_a_reading_just_under_the_floor_trips_it_and_one_at_it_does_not() -> None:
    floor = predict_herd_levels(_BASE, _RATE["fixed_aggregate"])
    assert floor is not None
    profile = _profile(_ARMED)
    under = [_rec("fixed_aggregate", 12, per_msg=floor.floor - 0.01)]
    at = [_rec("fixed_aggregate", 12, per_msg=floor.floor)]
    assert _empty_claims_herd_floor_slo(profile, under, _ARMED).ok is False
    assert _empty_claims_herd_floor_slo(profile, at, _ARMED).ok is True


def test_the_harvested_minima_on_the_armed_leg_clear_the_floor() -> None:
    # The lowest passing post_2024 readings of the armed leg's two cells (readings.csv).
    records = [
        _rec("fixed_aggregate", 12, per_msg=26.727272727272727),
        _rec("fixed_per_conn", 12, per_msg=31.6875, rate=_RATE["fixed_per_conn"]),
    ]
    check = _empty_claims_herd_floor_slo(_profile(_ARMED), records, _ARMED)
    assert check.ok and check.observed == f"above the floor on 2 of 2 lane(s), leg {_ARMED}"


@pytest.mark.parametrize("leg", [None, "windows-2022-py3.14", "windows-2025-py3.14", "local"])
def test_an_unarmed_leg_records_the_floor_and_grades_nothing(leg: str | None) -> None:
    check = _empty_claims_herd_floor_slo(_profile(_ARMED), _herd_gone(), leg)
    assert check.ok is True
    assert str(check.observed).startswith("NOT GRADED -- recorded only"), check.observed


def test_an_armed_leg_with_no_base_reading_says_it_graded_nothing() -> None:
    records = [_rec("fixed_aggregate", 24, per_msg=60.0)]
    check = _empty_claims_herd_floor_slo(_profile(_ARMED), records, _ARMED)
    assert check.ok is True and str(check.observed).startswith("NOT GRADED -- 0 of 1"), (
        check.observed
    )


def test_the_leg_comes_from_the_ci_variable_and_nothing_else(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = _profile(_ARMED)
    monkeypatch.delenv(CONNSCALE_LEG_ENV, raising=False)
    assert current_leg() is None and not herd_floor_armed(profile)
    monkeypatch.setenv(CONNSCALE_LEG_ENV, "  ")
    assert current_leg() is None
    monkeypatch.setenv(CONNSCALE_LEG_ENV, _ARMED)
    assert herd_floor_armed(profile)
    monkeypatch.setenv(CONNSCALE_LEG_ENV, "windows-2022-py3.14")
    assert not herd_floor_armed(profile)


# --- the profile seam ----------------------------------------------------------------------------


def test_the_floor_is_off_unless_a_leg_is_named() -> None:
    assert _profile().slo.empty_claims_herd_floor_legs == ()
    assert _profile(_ARMED, f" {_ARMED} ").slo.empty_claims_herd_floor_legs == (_ARMED,)


@pytest.mark.parametrize("bad", ['"ubuntu-latest-py3.14"', "[1]", '[""]'])
def test_a_malformed_leg_list_is_refused(bad: str) -> None:
    text = _profile_text_with(f"empty_claims_herd_floor_legs = {bad}")
    with pytest.raises(ConnScaleProfileError, match="empty_claims_herd_floor_legs"):
        load_connscale_profile_text(text, where="<unit>")


def test_a_pooled_only_profile_cannot_arm_a_floor_that_grades_nothing() -> None:
    with pytest.raises(ConnScaleProfileError, match="empty_claims_herd_floor_legs needs"):
        _profile(_ARMED, claim_modes='["pooled"]', base_reading="false")


def _profile_text_with(slo_line: str) -> str:
    return f"""
[connscale]
name = "unit"
counts = [12, 24]
sweep_mode = "both"
aggregate_rate = 24.0
per_conn_rate = 1.0
hold_seconds = 1.5
connect_batch = 8
connect_batch_pause_s = 0.0
poll_interval_s = 0.25
drain_timeout_s = 30.0
base_port = 20000
transform = "cheap"
reload_probe = false
store_backend = "sqlite"
corpus_count_per_trigger = 5

[connscale.slo]
{slo_line}
"""


# --- the decision, recomputed from the committed harvest -----------------------------------------


def _cells() -> dict[tuple[str, str], list[dict[str, str]]]:
    cells: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    with _HARVEST.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            if row["population"] == "post_2024" and row["count"] == str(_BASE):
                cells[(row["leg"], row["lane"])].append(row)
    return cells


def _passes_rule(leg: str, lane: str, rows: list[dict[str, str]]) -> bool:
    """Clauses (a) to (c) for one cell, candidate F = the cell's predicted floor. (d) is above."""
    prediction = predict_herd_levels(_BASE, _RATE[lane])
    assert prediction is not None
    passing = sorted(float(r["value"]) for r in rows if r["job_conclusion"] == "success")
    margin_ok = passing[0] / prediction.floor >= _MARGIN  # (a)
    excludes_herd_gone = prediction.floor > prediction.idle  # (b)
    known_ok = (leg, lane) != (_KNOWN_LEG, _KNOWN_LANE) or prediction.floor <= _KNOWN_VALUE
    return margin_ok and excludes_herd_gone and known_ok


def test_the_committed_harvest_holds_every_cell_with_enough_readings() -> None:
    cells = _cells()
    assert len(cells) == 6, sorted(cells)  # three legs by two lanes, never pooled
    for key, rows in cells.items():
        passing = [r for r in rows if r["job_conclusion"] == "success"]
        assert len(passing) >= 101, (key, len(passing))  # p1 needs n >= 101 to be a reading


def test_the_known_answer_case_is_in_the_harvest_and_clears_its_cells_floor() -> None:
    (row,) = [
        r
        for r in _cells()[(_KNOWN_LEG, _KNOWN_LANE)]
        if r["run_id"] == _KNOWN_RUN and r["job_id"] == _KNOWN_JOB
    ]
    floor = predict_herd_levels(_BASE, _RATE[_KNOWN_LANE])
    assert floor is not None
    value = float(row["value"])
    print(
        f"#1415 clause (c): run {_KNOWN_RUN} job {_KNOWN_JOB} {_KNOWN_LEG} {_KNOWN_LANE} "
        f"base reading {value} vs F {floor.floor:.4f}: {'not below' if value >= floor.floor else 'BELOW'}"
    )
    assert value == _KNOWN_VALUE and row["job_conclusion"] == "success"
    assert value >= floor.floor


def test_the_armed_legs_are_exactly_the_legs_whose_every_cell_clears_the_rule() -> None:
    by_leg: dict[str, list[bool]] = defaultdict(list)
    for (leg, lane), rows in _cells().items():
        by_leg[leg.replace(" ", "-")].append(_passes_rule(leg, lane, rows))
    cleared = {leg for leg, verdicts in by_leg.items() if all(verdicts)}
    assert cleared == set(_HERD_FLOOR_LEGS) == {_ARMED}, by_leg
    # And the two Windows legs fail on EVERY cell, so no lane-level arming is being left on the table.
    assert not any(v for leg, vs in by_leg.items() if leg != _ARMED for v in vs), by_leg
