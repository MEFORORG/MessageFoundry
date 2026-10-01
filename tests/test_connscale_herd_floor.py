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
import json
import random
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

import pytest

from harness.load.connscale.profile import (
    _LEG,
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
#: The point the harvest MEASURED: base count N=12, and per lane the offered aggregate rate there.
#: readings.csv records neither, so they are pinned as literals rather than read off the profile,
#: and ``test_the_ci_profile_still_runs_at_the_harvested_point`` reds when the profile moves away
#: from them. A floor recomputed from a moved profile against old readings would be armed at a
#: point no harvest measured.
_BASE = 12
_RATE = {"fixed_aggregate": 24.0, "fixed_per_conn": 12.0}
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
        _rec("fixed_aggregate", _BASE, per_msg=agg.idle, rate=_RATE["fixed_aggregate"]),
        _rec("fixed_aggregate", 2 * _BASE, per_msg=60.0),
        _rec("fixed_per_conn", _BASE, per_msg=per_conn.idle, rate=_RATE["fixed_per_conn"]),
        _rec("fixed_per_conn", 2 * _BASE, per_msg=60.0, rate=24.0),
    ]


def test_the_ci_profile_still_runs_at_the_harvested_point() -> None:
    smoke: ConnScaleProfile = _smoke_profile(20000)  # type: ignore[assignment]
    assert min(_SMOKE_COUNTS) == _BASE, "the base count moved: re-harvest before arming any leg"
    offered = {lane: smoke.aggregate_rate_for(lane, _BASE) for lane in _RATE}
    assert offered == _RATE, "the offered rates moved: re-harvest before arming any leg"
    # Everything else that shapes the rate window or the reading, at the values the harvest ran.
    shape = {
        "sweep_mode": smoke.sweep_mode,
        "hold_seconds": smoke.hold_seconds,
        "connect_batch": smoke.connect_batch,
        "connect_batch_pause_s": smoke.connect_batch_pause_s,
        "poll_interval_s": smoke.poll_interval_s,
        "transform": smoke.transform,
        "reload_probe": smoke.reload_probe,
        "store_backend": smoke.store_backend,
        "claim_modes": smoke.claim_modes,
        "trials": smoke.trials,
    }
    assert shape == {
        "sweep_mode": "both",
        "hold_seconds": 1.5,
        "connect_batch": 8,
        "connect_batch_pause_s": 0.0,
        "poll_interval_s": 0.25,
        "transform": "cheap",
        "reload_probe": True,
        "store_backend": None,  # store_backend = "sqlite" parses to the default, None
        "claim_modes": ("per_lane",),
        "trials": 1,
    }, "the CI profile moved off the harvested point: re-harvest before arming any leg"


def test_ci_exports_the_leg_in_the_form_the_profile_names_it() -> None:
    # Without this line the armed check reads no leg, reports NOT GRADED with ok=True, and the
    # smoke test's unarmed branch passes it: the only armed gate would go dark with nothing red.
    ci_path = Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml"
    ci = ci_path.read_text(encoding="utf-8").replace("\r\n", "\n")
    step = ci[ci.index("      - name: Tests (pytest)\n") :]
    step = step[: step.index("\n      - name:", 1)]
    expected = f"{CONNSCALE_LEG_ENV}: ${{{{ matrix.os }}}}-py${{{{ matrix.python-version }}}}"
    assert expected in step, step[:400]
    # Each armed leg must be a `test` matrix entry, read from the matrix JSON the `changes` job
    # builds, not from the words appearing anywhere else in ci.yml.
    for leg in _HERD_FLOOR_LEGS:
        os_name, _, version = leg.rpartition("-py")
        entry = f'{{"os":"{os_name}","python-version":"{version}",'
        assert entry in ci, f"no test matrix entry starts {entry}: leg {leg} would never be graded"


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
    # The lowest passing post_2024 reading of each of the armed leg's cells, read from readings.csv.
    cells = _cells()
    leg = _ARMED.replace("-py", " py")
    records = []
    for lane, rate in _RATE.items():
        low = cells[(leg, lane)].min
        assert low is not None
        records.append(_rec(lane, _BASE, per_msg=low, rate=rate))
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


@pytest.mark.parametrize(
    "bad", ['"ubuntu-latest-py3.14"', "[1]", '[""]', '["ubuntu-latest py3.14"]', '["ubuntu"]']
)
def test_a_malformed_leg_list_is_refused(bad: str) -> None:
    text = _profile_text_with(f"empty_claims_herd_floor_legs = {bad}")
    with pytest.raises(ConnScaleProfileError, match="empty_claims_herd_floor_legs"):
        load_connscale_profile_text(text, where="<unit>")


def test_a_floor_cannot_be_armed_over_repeat_trials() -> None:
    # The floor grades the first base record per lane, so trials 2..N would go ungraded.
    text = _profile_text_with(f"empty_claims_herd_floor_legs = ['{_ARMED}']").replace(
        "corpus_count_per_trigger = 5", "corpus_count_per_trigger = 5\ntrials = 3"
    )
    with pytest.raises(ConnScaleProfileError, match="trials = 3"):
        load_connscale_profile_text(text, where="<unit>")


def test_a_pooled_only_profile_cannot_arm_a_floor_that_grades_nothing() -> None:
    with pytest.raises(ConnScaleProfileError, match="empty_claims_herd_floor_legs needs"):
        _profile(_ARMED, claim_modes='["pooled"]', base_reading="false")


# --- the decision, recomputed from the committed harvest -----------------------------------------


@functools.cache
def _readings() -> tuple[ch.BaseReading, ...]:
    """The committed readings, typed as the harvest script types them.

    The writer routes every cell through the spreadsheet formula rule, which prefixes an apostrophe
    to text it quotes. No cell of this file should ever need that, so one that carries it
    is refused here rather than read as a different leg or lane.
    """
    with _HARVEST.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    quoted = [r for r in rows if any(cell.startswith("'") for cell in r.values())]
    assert not quoted, (
        f"readings.csv holds escaped key cells; unescape before reading: {quoted[:3]}"
    )
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
        for row in rows
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


def test_an_armed_leg_says_enforced_in_both_emitters() -> None:
    # The summary and the artifact are what a later harvest and a reader of a red job see. On an
    # armed leg both must say the floor is enforced; by default both must say it is not.
    from tests.test_connscale_empty_claims_per_msg import _report

    report = _report(*_herd_gone())

    def render(enforced: bool) -> str:
        return report.render_readings_markdown(
            "empty_claims_per_msg",
            lambda r: r.empty_claims_per_msg,
            tolerance=0.25,
            base_count=_BASE,
            enforced=enforced,
        )

    def payload_enforced(enforced: bool) -> object:
        payload = report.readings_payload(
            "empty_claims_per_msg",
            lambda r: r.empty_claims_per_msg,
            tolerance=0.25,
            base_count=_BASE,
            enforced=enforced,
        )
        block = payload["herd_floor"]
        assert isinstance(block, dict)
        return block["enforced"]

    armed, unarmed = render(True), render(False)
    assert "(ENFORCED on this leg -- BACKLOG #1415)" in armed
    assert "a BELOW FLOOR row fails the run" in armed
    assert "IS ENFORCED on this leg" in armed and "not enforced" not in armed
    assert (
        "(recorded, not enforced -- BACKLOG #1415)" in unarmed
        and "ENFORCED on this leg" not in unarmed
    )
    assert payload_enforced(True) is True and payload_enforced(False) is False


_HOSTILE_LEGS = {
    "no-version": "a" * 200_000 + "-py",
    "long-version-bad-tail": "a" * 200_000 + "-py" + "1." * 100_000 + "x",
    "every-separator-walked": "a" + "-py" * 100_000,
    "letter-in-version": "a-" * 100_000 + "py3.14x",
}
_SHAPE_ERROR = "must name a CI leg"


@pytest.mark.parametrize("name", sorted(_HOSTILE_LEGS))
def test_a_hostile_long_leg_is_refused_with_the_shape_error(name: str) -> None:
    with pytest.raises(ConnScaleProfileError, match=_SHAPE_ERROR):
        load_connscale_profile_text(
            _profile_text_with(f"empty_claims_herd_floor_legs = ['{_HOSTILE_LEGS[name]}']"),
            where="<unit>",
        )


def test_the_hostile_legs_cannot_hang_the_leg_pattern() -> None:
    # A running regex holds the GIL, so a pytest thread timeout cannot interrupt one. The matches run
    # in a CHILD process instead, and the parent's own timeout kills it: a pattern that ever starts
    # to backtrack on these shapes fails here rather than hanging the CI leg.
    child = (
        "import json, sys\n"
        "from harness.load.connscale.profile import _LEG\n"
        "legs = json.load(sys.stdin)\n"
        "print(json.dumps([bool(_LEG.fullmatch(v)) for v in legs]))\n"
    )
    done = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv: this interpreter and a literal
        [sys.executable, "-c", child],
        input=json.dumps(list(_HOSTILE_LEGS.values())),
        capture_output=True,
        text=True,
        timeout=60,
        cwd=Path(__file__).resolve().parents[1],
        check=False,
    )
    assert done.returncode == 0, done.stderr
    assert json.loads(done.stdout) == [False] * len(_HOSTILE_LEGS)


#: The pattern the nested-quantifier gate flagged, kept here so "nothing else changed" is a claim
#: this module checks rather than one a comment makes. It differs from ``_LEG`` on one class of input
#: on purpose: non-ASCII digits, which ``_LEG`` refuses.
_PRE_GATE_LEG = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*-py\d+(?:\.\d+)*")


@pytest.mark.parametrize(
    ("leg", "ok"),
    [
        ("ubuntu-latest-py3.14", True),
        ("windows-2022-py3.14", True),
        ("a-py3-py3.14", True),  # an os part may itself contain -py; the last one separates
        ("ubuntu-latest-py3", True),
        ("ubuntu-latest py3.14", False),
        ("ubuntu-latest-py", False),
        ("ubuntu-latest-py3..14", False),
        ("ubuntu-latest-py3.14.", False),
        ("-ubuntu-py3.14", False),
        ("_ubuntu-py3.14", False),
        ("ubu ntu-py3.14", False),
        ("-py3.14", False),
    ],
)
def test_the_leg_pattern_decides_each_case_as_before(leg: str, ok: bool) -> None:
    assert bool(_PRE_GATE_LEG.fullmatch(leg)) is ok, "the case table itself is wrong"
    text = _profile_text_with(f"empty_claims_herd_floor_legs = ['{leg}']")
    if ok:
        assert load_connscale_profile_text(
            text, where="<unit>"
        ).slo.empty_claims_herd_floor_legs == (leg,)
    else:
        with pytest.raises(ConnScaleProfileError, match=_SHAPE_ERROR):
            load_connscale_profile_text(text, where="<unit>")


@pytest.mark.parametrize(
    "leg",
    [
        "ubuntu-latest-py３.１４",  # full-width digits
        "ubuntu-latest-py٣.١٤",  # Arabic-Indic digits
        "ubuntu-latest-py3.１４",  # one non-ASCII group after an ASCII one
    ],
    ids=["full-width", "arabic-indic", "mixed"],
)
def test_a_leg_with_non_ascii_digits_is_refused(leg: str) -> None:
    # ci.yml exports the leg in ASCII, so a leg spelled with other digits could never match: parsed,
    # it would disarm the floor with nothing reporting it. The pre-gate pattern accepted it.
    assert _PRE_GATE_LEG.fullmatch(leg), "the pre-gate pattern's \\d did accept this leg"
    with pytest.raises(ConnScaleProfileError, match=_SHAPE_ERROR):
        load_connscale_profile_text(
            _profile_text_with(f"empty_claims_herd_floor_legs = ['{leg}']"), where="<unit>"
        )


def test_the_pattern_is_the_pre_gate_language_restricted_to_ascii() -> None:
    # The exact claim: _LEG accepts a string if and only if the pre-gate pattern did AND it is ASCII.
    # Non-ASCII digits AND a non-ASCII letter are in the alphabet, in every position, so widening any
    # class (a \d or \w, in the os part as well as the version) reds here. The accept count is the
    # control: a generator that never produced a valid leg would make "no disagreement" mean nothing.
    rnd = random.Random(1415)
    alphabet = [*"ab09._- py3.4", "-py", "py", "٣", "３", "é"]
    accepted = 0
    for _ in range(50_000):
        text = "".join(rnd.choice(alphabet) for _ in range(rnd.randint(0, 14)))
        expected = bool(_PRE_GATE_LEG.fullmatch(text)) and text.isascii()
        assert bool(_LEG.fullmatch(text)) is expected, ascii(text)
        accepted += expected
    assert accepted > 50, accepted


def test_the_refusal_names_a_non_ascii_digit_by_its_escape() -> None:
    with pytest.raises(ConnScaleProfileError, match=r"ASCII letters.*\\uff13"):
        load_connscale_profile_text(
            _profile_text_with("empty_claims_herd_floor_legs = ['ubuntu-latest-py３.14']"),
            where="<unit>",
        )


def test_many_distinct_legs_are_kept_in_order_once_each() -> None:
    legs = [f"a{i}-py3" for i in range(20_000)]
    text = _profile_text_with(f"empty_claims_herd_floor_legs = {[*legs, legs[0]]}")
    assert load_connscale_profile_text(text, where="<unit>").slo.empty_claims_herd_floor_legs == (
        tuple(legs)
    )
