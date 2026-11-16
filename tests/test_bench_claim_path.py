# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Offline checks of the claim-path benchmark tool (scripts/bench/claim_path.py, vault BACKLOG
#4915). The timed half needs a live server store and runs only in benchmark.yml's claim-path
profile; these cover the parts a wrong figure would come from: the scenario grammar, the statistics,
the before/after table and its refusal to compare a keyed side with an unkeyed one, the
bench-database guard, the refusal to credit a run to a commit it did
not import, the expected-row arithmetic, and the sampling loop that discards a wrong claim."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
import zlib
from pathlib import Path
from types import ModuleType
from typing import Any

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
    assert raw == cp._raw(2048)  # seeded: the same message on every run and at both commits


def test_the_padding_does_not_compress_and_stays_one_hl7_field() -> None:
    raw = cp._raw(2048)
    pad = raw.split("\rNTE|1||", 1)[1].rstrip("\r")
    assert not set(pad) & set("|^~\\&\r\n")
    # Random base64 carries 6 bits a character, so a compressor keeps about three quarters of it.
    assert len(zlib.compress(pad.encode("ascii"), 9)) > 0.7 * len(pad)
    # The control: the one-character padding this replaced compresses to almost nothing, so the
    # bound above can tell the two apart.
    assert len(zlib.compress(b"X" * len(pad), 9)) < 0.05 * len(pad)


@pytest.mark.parametrize(
    ("lanes", "limit", "rows_per_lane", "expected"),
    [
        (1, 1, 16, 1),
        (64, 16, 16, 1024),
        (256, 16, 16, 4096),
        (64, 32, 16, 1024),  # the limit is capped at what a lane holds
        (256, 0, 16, 0),  # the empty scenario
    ],
)
def test_expected_rows(lanes: int, limit: int, rows_per_lane: int, expected: int) -> None:
    assert cp._expected_rows(lanes, limit, rows_per_lane) == expected


def _scripted(
    script: list[tuple[int, str | None]],
) -> tuple[Any, Any, list[list[int]]]:
    """A claim that returns ``script``'s (row count, lock-timeout phase) in turn, timing the n-th
    call as n milliseconds, and a release that records what it was given."""
    calls = iter(enumerate(script, start=1))
    released: list[list[int]] = []

    async def claim() -> tuple[float, list[Any], str | None]:
        n, (rows, timeout) = next(calls)
        return float(n), list(range(rows)), timeout

    async def release(ids: list[Any]) -> None:
        released.append(list(ids))

    return claim, release, released


def test_sample_drops_the_warmup_and_retries_a_wrong_claim() -> None:
    script = [
        (4, None),  # 1 warm-up
        (2, None),  # 2 short: discarded, the warm-up slot is tried again
        (4, None),  # 3 warm-up
        (0, "head"),  # 4 lock timeout: discarded
        (4, None),  # 5 timed
        (0, None),  # 6 empty: discarded
        (5, None),  # 7 over: discarded
        (4, None),  # 8 timed
        (4, None),  # 9 timed
    ]
    claim, release, released = _scripted(script)
    samples, discards = asyncio.run(
        cp._sample(claim, release, expected=4, warmup=2, iterations=3, max_discards=10)
    )
    assert samples == [5.0, 8.0, 9.0]
    assert discards == {"short": 1, "lock_timeout:head": 1, "empty": 1, "over": 1}
    assert [len(ids) for ids in released] == [4, 2, 4, 4, 5, 4, 4]  # every non-empty claim


def test_sample_discards_a_lock_timeout_even_on_the_empty_scenario() -> None:
    claim, release, _ = _scripted([(0, "head"), (0, None)])
    samples, discards = asyncio.run(
        cp._sample(claim, release, expected=0, warmup=0, iterations=1, max_discards=5)
    )
    assert samples == [2.0]
    assert discards == {"lock_timeout:head": 1}


def test_sample_stops_short_at_the_discard_bound() -> None:
    claim, release, _ = _scripted([(4, None), (0, None), (0, None), (0, None)])
    samples, discards = asyncio.run(
        cp._sample(claim, release, expected=4, warmup=0, iterations=5, max_discards=3)
    )
    assert samples == [1.0]
    assert discards == {"empty": 3}


def _report(
    tmp: Path,
    label: str,
    rnd: int,
    p50: float,
    *,
    payload_bytes: int = 2048,
    n: float = 100.0,
    discarded: dict[str, int] | None = None,
    store_keyed: bool = True,
) -> Path:
    rep = {
        "label": label,
        "commit": label * 5,
        "round": rnd,
        "backend": "postgres",
        "server": "PostgreSQL 16",
        "rows_per_lane": 16,
        "payload_bytes": payload_bytes,
        "iterations": 100,
        "store_keyed": store_keyed,
        "scenarios": [
            {
                "lanes": 64,
                "per_lane_limit": 16,
                "rows_claimed": 1024,
                "discarded": discarded or {},
                "n": n,
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
        _report(tmp_path, "before", 1, 10.0, discarded={"lock_timeout:head": 2}),
        _report(tmp_path, "after", 1, 15.0),
        _report(tmp_path, "after", 2, 18.0, discarded={"empty": 1, "lock_timeout:head": 1}),
    ]
    table, emitted, refused = cp._compare(paths, "before", "after")
    assert (emitted, refused) == (1, 0)
    row = next(line for line in table.splitlines() if line.startswith("| 64x16 "))
    cells = [c.strip() for c in row.strip("|").split("|")]
    assert cells[1] == "1024"
    assert cells[2] == "11.00 (10.00, 12.00)"  # median of the rounds, then r1, r2
    assert cells[3] == "16.50 (15.00, 18.00)"
    assert cells[4] == "1.500"
    assert cells[7] == "1.500"  # the p90 ratio
    assert cells[10] == "2 (lock_timeout:head 2)"  # discards summed over rounds, per side
    assert cells[11] == "2 (empty 1, lock_timeout:head 1)"
    # Each side names whether its store was keyed (claim_path.sh mints a throwaway store key).
    assert f"- before={'before' * 5} on PostgreSQL 16, store keyed" in table
    assert f"- after={'after' * 5} on PostgreSQL 16, store keyed" in table


@pytest.mark.parametrize(
    ("after_kwargs", "why"),
    [
        ({"payload_bytes": 1024}, "refused: payload_bytes differs"),
        ({"n": 60.0}, "refused: fewer samples than iterations (after r1 n=60)"),
        ({"store_keyed": False}, "refused: store_keyed differs across reports (False, True)"),
    ],
)
def test_compare_refuses_sides_that_did_not_measure_the_same_work(
    tmp_path: Path, after_kwargs: dict[str, Any], why: str
) -> None:
    paths = [
        _report(tmp_path, "before", 1, 10.0),
        _report(tmp_path, "after", 1, 15.0, **after_kwargs),
    ]
    table, emitted, refused = cp._compare(paths, "before", "after")
    assert (emitted, refused) == (0, 1)
    assert why in table
    assert cp.main(["compare", *map(str, paths)]) == 1


def test_compare_names_a_missing_side_and_reports_no_rows(tmp_path: Path) -> None:
    table, emitted, refused = cp._compare([_report(tmp_path, "before", 1, 10.0)], "before", "after")
    assert (emitted, refused) == (0, 0)
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
