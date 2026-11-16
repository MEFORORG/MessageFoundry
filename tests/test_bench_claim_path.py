# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Offline checks of the claim-path benchmark tool (scripts/bench/claim_path.py, vault BACKLOG
#4915). The timed half needs a live server store and runs only in benchmark.yml's claim-path
profile; these cover the parts a wrong figure would come from: the scenario grammar, the statistics,
the before/after table, and the refusal to credit a run to a commit it did not import."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

_PATH = Path(__file__).resolve().parents[1] / "scripts" / "bench" / "claim_path.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("_bench_claim_path", _PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


cp = _load()


def test_scenarios_parse_and_reject_bad_input() -> None:
    assert cp._parse_scenarios("1x1, 64x16,256x0") == [(1, 1), (64, 16), (256, 0)]
    for bad in ("0x1", "4x-1", "4", "ax1"):
        with pytest.raises(ValueError):
            cp._parse_scenarios(bad)


def test_stats_are_order_free_and_pick_the_nearest_rank() -> None:
    samples = [float(v) for v in range(100, 0, -1)]  # 100 .. 1, descending on purpose
    st = cp._stats(samples)
    assert st["n"] == 100.0
    assert (st["min"], st["max"]) == (1.0, 100.0)
    assert st["p50"] == 51.0  # round(0.5 * 99) = 50 -> the 51st smallest
    assert st["p99"] == 99.0
    assert st["mean"] == pytest.approx(50.5)


def _report(tmp: Path, label: str, rnd: int, p50: float) -> Path:
    rep = {
        "label": label,
        "commit": label * 5,
        "round": rnd,
        "backend": "postgres",
        "server": "PostgreSQL 16",
        "scenarios": [
            {
                "lanes": 64,
                "per_lane_limit": 16,
                "rows_claimed": 1024,
                "p50": p50,
                "p90": p50 * 2,
                "p99": p50 * 3,
            }
        ],
    }
    path = tmp / f"postgres-{label}-r{rnd}.json"
    path.write_text(json.dumps(rep), encoding="utf-8")
    return path


def test_compare_gives_the_median_of_rounds_and_the_after_over_before_ratio(
    tmp_path: Path,
) -> None:
    paths = [
        _report(tmp_path, "before", 1, 10.0),
        _report(tmp_path, "before", 2, 12.0),
        _report(tmp_path, "after", 1, 15.0),
        _report(tmp_path, "after", 2, 18.0),
    ]
    table = cp._compare(paths, "before", "after")
    row = next(line for line in table.splitlines() if line.startswith("| 64x16 "))
    cells = [c.strip() for c in row.strip("|").split("|")]
    assert cells[1] == "1024"
    assert cells[2].startswith("11.00 (")  # median of 10 and 12
    assert cells[3].startswith("16.50 (")  # median of 15 and 18
    assert cells[4] == "1.500"


def test_compare_omits_a_scenario_one_side_lacks(tmp_path: Path) -> None:
    table = cp._compare([_report(tmp_path, "before", 1, 10.0)], "before", "after")
    assert "| 64x16 " not in table


def test_a_run_refuses_an_engine_imported_from_outside_the_code_root(tmp_path: Path) -> None:
    # messagefoundry is already imported from this checkout, so a code root that does not hold it
    # must be refused rather than timed and credited to that root's commit.
    import messagefoundry  # noqa: F401

    saved = list(sys.path)
    try:
        with pytest.raises(SystemExit, match="refusing to credit"):
            cp._import_engine(tmp_path)
    finally:
        sys.path[:] = saved
