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
import functools
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
from scripts import connscale_harvest as ch
from tests.test_connscale_empty_claims_per_msg import _rec
from tests.test_connscale_smoke import _HERD_FLOOR_LEGS, _SMOKE_COUNTS, _smoke_profile

_ARMED = "ubuntu-latest-py3.14"
_HARVEST = (
    Path(__file__).resolve().parents[1]
    / "docs/benchmarks/results/2026-10-01-connscale-herd-floor-harvest/readings.csv"
)
#: Read off the profile CI runs, so a change to its base count or rates cannot leave this module
#: grading the old numbers while the armed legs drift from the evidence.
_SMOKE: ConnScaleProfile = _smoke_profile(20000)  # type: ignore[assignment]
_BASE = min(_SMOKE_COUNTS)
_RATE = {
    lane: _SMOKE.aggregate_rate_for(lane, _BASE) for lane in ("fixed_aggregate", "fixed_per_conn")
}
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


def _profile_text_with(slo_lines: str, claim_modes: str = '["per_lane"]') -> str:
    return f"""
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
{slo_lines}
"""


def _profile(
    *legs: str, claim_modes: str = '["per_lane"]', base_reading: str = "true"
) -> ConnScaleProfile:
    slo = f"empty_claims_base_reading = {base_reading}\nempty_claims_herd_floor_legs = {list(legs)}"
    return load_connscale_profile_text(_profile_text_with(slo, claim_modes), where="<unit>")


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
    assert current_leg() is None and not herd_floor_armed(profile, current_leg())
    monkeypatch.setenv(CONNSCALE_LEG_ENV, "  ")
    assert current_leg() is None
    monkeypatch.setenv(CONNSCALE_LEG_ENV, _ARMED)
    assert herd_floor_armed(profile, current_leg())
    monkeypatch.setenv(CONNSCALE_LEG_ENV, "windows-2022-py3.14")
    assert not herd_floor_armed(profile, current_leg())


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


# --- the decision, recomputed from the committed harvest -----------------------------------------


@functools.cache
def _readings() -> tuple[ch.BaseReading, ...]:
    """The committed readings, typed as the harvest script types them."""

    with _HARVEST.open(encoding="utf-8", newline="") as handle:
        return tuple(
            ch.BaseReading(
                population=row["population"],
                leg=row["leg"],
                lane=row["lane"],
                count=int(row["count"]) if row["count"] else None,
                value=float(row["value"]) if row["value"] else None,
                job_conclusion=row["job_conclusion"],
                run_id=int(row["run_id"]),
                run_attempt=int(row["run_attempt"]),
                job_id=int(row["job_id"]),
                head_sha=row["head_sha"],
                artifact_created_at=row["artifact_created_at"],
            )
            for row in csv.DictReader(handle)
        )


def _cells() -> dict[tuple[str, str], ch.CellSummary]:
    """The fitted population's cells at the base count, summarised by the harvest's own code."""
    result = ch.Harvest("r", "w", None, "s", "u", readings=list(_readings()))
    return {
        (c.leg, c.lane): c
        for c in ch.summarise(result)
        if c.population == ch.POST_2024 and c.count == _BASE
    }


def _passes_rule(leg: str, lane: str, cell: ch.CellSummary) -> bool:
    """Clauses (a) to (c) for one cell, candidate F = the cell's predicted floor. (d) is above."""
    prediction = predict_herd_levels(_BASE, _RATE[lane])
    assert prediction is not None and cell.min is not None
    margin_ok = cell.min / prediction.floor >= _MARGIN  # (a)
    excludes_herd_gone = prediction.floor > prediction.idle  # (b)
    known_ok = (leg, lane) != (_KNOWN_LEG, _KNOWN_LANE) or prediction.floor <= _KNOWN_VALUE  # (c)
    return margin_ok and excludes_herd_gone and known_ok


def test_the_committed_harvest_holds_every_cell_with_enough_readings() -> None:
    cells = _cells()
    assert len(cells) == 6, sorted(cells)  # three legs by two lanes, never pooled
    for key, cell in cells.items():
        assert cell.n_passing >= 101, (key, cell.n_passing)  # p1 needs n >= 101 to be a reading


def test_the_known_answer_case_is_in_the_harvest_and_clears_its_cells_floor() -> None:
    (row,) = [
        r
        for r in _readings()
        if (r.run_id, r.job_id, r.lane) == (int(_KNOWN_RUN), int(_KNOWN_JOB), _KNOWN_LANE)
    ]
    floor = predict_herd_levels(_BASE, _RATE[_KNOWN_LANE])
    assert floor is not None and row.value is not None
    verdict = "not below" if row.value >= floor.floor else "BELOW"
    print(
        f"#1415 clause (c): run {_KNOWN_RUN} job {_KNOWN_JOB} {_KNOWN_LEG} {_KNOWN_LANE} "
        f"base reading {row.value} vs F {floor.floor:.4f}: {verdict}"
    )
    assert (row.leg, row.population, row.job_conclusion) == (_KNOWN_LEG, ch.POST_2024, "success")
    assert row.value == _KNOWN_VALUE
    assert row.value >= floor.floor


def test_the_armed_legs_are_exactly_the_legs_whose_every_cell_clears_the_rule() -> None:
    by_leg: dict[str, list[bool]] = defaultdict(list)
    for (leg, lane), cell in _cells().items():
        by_leg[leg.replace(" ", "-")].append(_passes_rule(leg, lane, cell))
    cleared = {leg for leg, verdicts in by_leg.items() if all(verdicts)}
    assert cleared == set(_HERD_FLOOR_LEGS) == {_ARMED}, by_leg
    # And the two Windows legs fail on EVERY cell, so no lane-level arming is being left on the table.
    assert not any(v for leg, vs in by_leg.items() if leg != _ARMED for v in vs), by_leg
