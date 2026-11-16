# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Offline checks of the claim-path benchmark tool (scripts/bench/claim_path.py, vault BACKLOG
#4915). The timed half needs a live server store and runs only in benchmark.yml's claim-path
profile; these cover the parts a wrong figure would come from: the scenario grammar, the statistics,
the before/after table, the bench-database guard, and the refusal to credit a run to a commit it did
not import."""

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
    for bad in ("0x1", "4x-1", "4", "ax1", "501x1"):
        with pytest.raises(ValueError):
            cp._parse_scenarios(bad)


def test_stats_are_order_free_and_take_the_nearest_rank() -> None:
    samples = [float(v) for v in range(100, 0, -1)]  # 100 .. 1, descending on purpose
    st = cp._stats(samples)
    assert st["n"] == 100.0
    assert (st["min"], st["max"]) == (1.0, 100.0)
    assert st["p50"] == 50.0  # the ceil(0.5 * 100) = 50th smallest
    assert st["p90"] == 90.0
    assert st["p99"] == 99.0
    assert st["mean"] == pytest.approx(50.5)
    assert cp._stats([7.0])["p50"] == 7.0


def test_the_payload_is_padded_to_the_requested_size() -> None:
    raw = cp._raw(2048)
    assert len(raw) == 2048
    assert raw.startswith("MSH|") and "\rNTE|1||" in raw


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


def test_compare_gives_the_median_of_rounds_in_round_order(tmp_path: Path) -> None:
    paths = [
        _report(tmp_path, "before", 2, 12.0),  # listed out of order on purpose
        _report(tmp_path, "before", 1, 10.0),
        _report(tmp_path, "after", 1, 15.0),
        _report(tmp_path, "after", 2, 18.0),
    ]
    table, emitted = cp._compare(paths, "before", "after")
    assert emitted == 1
    row = next(line for line in table.splitlines() if line.startswith("| 64x16 "))
    cells = [c.strip() for c in row.strip("|").split("|")]
    assert cells[1] == "1024"
    assert cells[2] == "11.00 (10.00, 12.00)"  # median of the rounds, then r1, r2
    assert cells[3] == "16.50 (15.00, 18.00)"
    assert cells[4] == "1.500"
    assert cells[7] == "1.500"  # the p90 ratio


def test_compare_names_a_missing_side_and_reports_no_rows(tmp_path: Path) -> None:
    table, emitted = cp._compare([_report(tmp_path, "before", 1, 10.0)], "before", "after")
    assert emitted == 0
    assert "| 64x16 | missing: after |" in table
    assert cp.main(["compare", str(tmp_path / "postgres-before-r1.json")]) == 1


def test_measure_refuses_a_database_that_is_not_a_bench_database() -> None:
    assert cp._check_bench_database({"MEFOR_STORE_DATABASE": "mf_claim_before"})
    assert cp._check_bench_database({"MEFOR_STORE_DATABASE": "MfClaimAfter"})
    for name in ("messagefoundry", "MessageFoundry", ""):
        with pytest.raises(SystemExit, match="not a bench database"):
            cp._check_bench_database({"MEFOR_STORE_DATABASE": name})


def _fake_root(tmp_path: Path, commit: str | None) -> Path:
    root = tmp_path / "root"
    (root / "messagefoundry").mkdir(parents=True)
    (root / "messagefoundry" / "__init__.py").write_text("", encoding="utf-8")
    if commit is not None:
        (root / "CLAIM_PATH_COMMIT").write_text(commit + "\n", encoding="utf-8")
    return root


def test_a_root_that_holds_the_commit_and_the_package_is_accepted(tmp_path: Path) -> None:
    # The positive control: without it, an _import_engine that refused everything would pass the
    # refusal tests below.
    root = _fake_root(tmp_path, "a" * 40)
    saved_path, saved_mod = list(sys.path), sys.modules.pop("messagefoundry", None)
    try:
        mod = cp._import_engine(root, "a" * 40)
        assert Path(mod.__file__).resolve().parent == (root / "messagefoundry").resolve()
    finally:
        sys.path[:] = saved_path
        sys.modules.pop("messagefoundry", None)
        if saved_mod is not None:
            sys.modules["messagefoundry"] = saved_mod


def test_a_root_stamped_with_another_commit_is_refused(tmp_path: Path) -> None:
    root = _fake_root(tmp_path, "b" * 40)
    with pytest.raises(SystemExit, match="refusing to credit"):
        cp._import_engine(root, "a" * 40)
    unstamped = _fake_root(tmp_path / "u", None)
    with pytest.raises(SystemExit, match="refusing to credit"):
        cp._import_engine(unstamped, "a" * 40)


def test_a_run_refuses_an_engine_imported_from_outside_the_code_root(tmp_path: Path) -> None:
    # messagefoundry is already imported from this checkout, so a stamped root that does not hold
    # the imported package must be refused rather than timed and credited to that root's commit.
    import messagefoundry  # noqa: F401

    root = tmp_path / "empty"
    root.mkdir()
    (root / "CLAIM_PATH_COMMIT").write_text("a" * 40, encoding="utf-8")
    saved = list(sys.path)
    try:
        with pytest.raises(SystemExit, match="refusing to credit"):
            cp._import_engine(root, "a" * 40)
    finally:
        sys.path[:] = saved
