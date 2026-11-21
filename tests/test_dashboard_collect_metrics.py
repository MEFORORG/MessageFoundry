# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Unit tests for scripts/dashboard/collect_metrics.py: the pure parts, with fakes, no network."""

from __future__ import annotations

import datetime as dt
import importlib.util
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

_PATH = Path(__file__).resolve().parents[1] / "scripts" / "dashboard" / "collect_metrics.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("dashboard_collect_metrics", _PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


cm = _load()


#: Every network or subprocess call a test did not fake is recorded here, so a test can assert none
#: happened. Raising alone is not enough: `collect()` catches it and turns it into a metric error.
REACHED: list[str] = []


def _no_fetch(url: str) -> bytes:
    REACHED.append(url)
    raise cm.CollectError(f"network reached in a test: {url}")


def _no_raw(argv: Sequence[str]) -> bytes:
    REACHED.append(" ".join(argv))
    raise cm.CollectError("subprocess reached in a test")


def _no_stall(cmd: list[str], timeout: float) -> str:
    REACHED.append(" ".join(cmd))
    raise cm.CollectError("stall runner reached in a test")


def _ctx(
    tmp_path: Path, run: Any, *, weeks: int = 3, through: str = "2026-11-18", today: str = ""
) -> Any:
    return cm.Context(
        vault=tmp_path / "vault",
        through=dt.date.fromisoformat(through),
        weeks=weeks,
        workdir=tmp_path,
        run=run,
        run_raw=_no_raw,
        fetch=_no_fetch,
        stall_runner=_no_stall,
        today=dt.date.fromisoformat(today or "2026-11-19"),
    )


# -- weeks -------------------------------------------------------------------------------------


def test_iso_week_and_year_boundary() -> None:
    assert cm.iso_week(dt.date(2026, 11, 4)) == "2026-W45"
    # 2026-12-31 is a Thursday, so it belongs to 2026-W53; 2027-01-01 does too.
    assert cm.iso_week(dt.date(2027, 1, 1)) == "2026-W53"


def test_week_of_timestamp_reads_utc() -> None:
    # Sunday 23:30 at -05:00 is Monday 04:30 UTC: the next ISO week.
    assert cm.week_of_timestamp("2026-11-15T23:30:00-05:00") == "2026-W47"
    assert cm.week_of_timestamp("2026-11-15T23:30:00Z") == "2026-W46"


def test_window_and_start() -> None:
    through = dt.date(2026, 11, 18)  # Wednesday of W47
    assert cm.window(through, 3) == ["2026-W45", "2026-W46", "2026-W47"]
    assert cm.window_start(through, 3) == dt.date(2026, 11, 2)


def test_last_full_week() -> None:
    labels = cm.window(dt.date(2026, 11, 18), 3)
    today = dt.date(2026, 11, 19)
    assert cm.last_full_week(dt.date(2026, 11, 18), labels, today) == "2026-W46"
    sunday = dt.date(2026, 11, 22)
    labels = cm.window(sunday, 2)
    # A Sunday that has ended completes its own week; a run ON that Sunday does not.
    assert cm.last_full_week(sunday, labels, dt.date(2026, 11, 23)) == "2026-W47"
    assert cm.last_full_week(sunday, labels, sunday) == "2026-W46"
    with pytest.raises(cm.CollectError):
        cm.last_full_week(dt.date(2026, 11, 18), ["2026-W47"], today)


def test_bucket_zero_fills_and_drops_out_of_window() -> None:
    labels = ["2026-W45", "2026-W46"]
    got = cm.bucket(
        ["2026-11-03T00:00:00Z", "2026-11-03T05:00:00Z", "2026-01-01T00:00:00Z"], labels
    )
    assert got == [{"week": "2026-W45", "value": 2}, {"week": "2026-W46", "value": 0}]


def test_week_ranges_end_at_through(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path, None, weeks=2)
    assert cm.week_ranges(ctx) == [
        (dt.date(2026, 11, 9), dt.date(2026, 11, 15)),
        (dt.date(2026, 11, 16), dt.date(2026, 11, 18)),
    ]


# -- thresholds --------------------------------------------------------------------------------


def test_status_thresholds() -> None:
    assert cm.status_burn(10, 10) == "good"
    assert cm.status_burn(0, 0) == "good"
    assert cm.status_burn(100, 75) == "warn"
    assert cm.status_burn(100, 74) == "bad"
    assert cm.status_merged(0, [5, 5]) == "bad"
    assert cm.status_merged(2, [10, 10]) == "warn"
    assert cm.status_merged(5, [10, 10]) == "good"
    assert cm.status_flow(7, 0) == "good"
    assert cm.status_flow(7, 1) == "warn"
    assert cm.status_flow(7, None) == "warn"  # an unread stall count is not zero stalls
    assert cm.status_flow(14, 0) == "warn"
    assert cm.status_flow(14.1, 0) == "bad"
    assert cm.status_ci(90, 0) == "good"
    assert cm.status_ci(90, 1) == "warn"
    assert cm.status_ci(74.9, 0) == "bad"
    assert cm.status_ci(None, 0) == "unknown"
    assert cm.status_pct(50, "asvs") == "warn"
    assert cm.status_pct(49.9, "asvs") == "bad"
    assert cm.status_vulns({"high": 1}) == "bad"
    assert cm.status_vulns({"low": 1, "high": 0}) == "warn"
    assert cm.status_vulns({"critical": 0}) == "good"
    assert cm.status_max(0, "owner_waiting") == "good"
    assert cm.status_max(5, "owner_waiting") == "warn"
    assert cm.status_max(6, "owner_waiting") == "bad"
    assert cm.status_max(50, "release_distance") == "good"
    assert cm.status_max(201, "release_distance") == "bad"


def test_ci_pass_series_ignores_cancelled() -> None:
    runs = [
        {"createdAt": "2026-11-10T01:00:00Z", "conclusion": "success"},
        {"createdAt": "2026-11-10T02:00:00Z", "conclusion": "failure"},
        {"createdAt": "2026-11-10T03:00:00Z", "conclusion": "cancelled"},
        {"createdAt": "2026-11-10T04:00:00Z", "conclusion": ""},
    ]
    got = cm.ci_pass_series(runs, ["2026-W46", "2026-W47"])
    assert got == [{"week": "2026-W46", "value": 50.0}, {"week": "2026-W47", "value": None}]


def test_parse_asvs_cells() -> None:
    got = cm.parse_asvs_cells("cells 10: 4 pass, 3 partial, 1 fail, 2 na, 0 needs-review")
    assert got == {"total": 10, "pass": 4, "partial": 3, "fail": 1, "na": 2, "needs-review": 0}
    with pytest.raises(cm.CollectError):
        cm.parse_asvs_cells("cells 10: 4 pass")  # does not sum


# -- failure gives null, never zero --------------------------------------------------------------


def _failing(argv: Sequence[str], cwd: Path | None) -> str:
    raise cm.CollectError("gh exited 1: HTTP 502")


def test_a_failing_source_gives_null_not_zero(tmp_path: Path) -> None:
    REACHED.clear()
    ctx = _ctx(tmp_path, _failing)
    metrics = cm.collect(ctx)
    assert [m.id for m in metrics] == [s.id for s in cm.SPECS]
    for m in metrics:
        assert m.value is None, m.id
        assert m.status == "unknown", m.id
        assert m.error, m.id
        assert m.series is None, m.id
    # Only release_distance reaches the (faked) network; nothing else escaped the fakes.
    assert REACHED == [cm.PYPI_URL]


def test_one_failure_does_not_abort_the_rest(tmp_path: Path) -> None:
    def good(ctx: Any, m: Any) -> None:
        m.value, m.status = 3, "good"

    def bad(ctx: Any, m: Any) -> None:
        m.value = 0  # half-filled before raising: must not survive
        raise KeyError("boom")

    specs = (
        cm.Spec("a", "A", "?", "n", "src", bad),
        cm.Spec("b", "B", "?", "n", "src", good),
    )
    a, b = cm.collect(_ctx(tmp_path, _failing), specs)
    assert (a.value, a.status, a.error) == (None, "unknown", "KeyError: 'boom'")
    assert (b.value, b.status, b.error) == (3, "good", None)


def test_vault_failure_is_read_once(tmp_path: Path) -> None:
    calls: list[list[str]] = []

    def run(argv: Sequence[str], cwd: Path | None) -> str:
        calls.append(list(argv))
        raise cm.CollectError("fetch failed")

    ctx = _ctx(tmp_path, run)
    for _ in range(3):
        with pytest.raises(cm.CollectError):
            ctx.vault_read()
    assert len(calls) == 1


# -- collectors with a fake gh ---------------------------------------------------------------------


def test_prs_merged_per_week_and_truncation(tmp_path: Path) -> None:
    def run(argv: Sequence[str], cwd: Path | None) -> str:
        search = argv[argv.index("--search") + 1]
        if search.startswith("merged:2026-11-09"):
            return json.dumps([{"number": 1, "mergedAt": "2026-11-10T00:00:00Z"}])
        return "[]"

    ctx = _ctx(tmp_path, run, weeks=2)
    m = cm.Metric("prs_merged", "", "", "", "")
    cm.c_prs_merged(ctx, m)
    # Three repos, one merge each in W46 (the last full week).
    assert m.value == 3
    assert m.series == [{"week": "2026-W46", "value": 3}, {"week": "2026-W47", "value": 0}]

    def capped(argv: Sequence[str], cwd: Path | None) -> str:
        return json.dumps([{"number": n, "mergedAt": "2026-11-10T00:00:00Z"} for n in range(1000)])

    with pytest.raises(cm.CollectError, match="truncated"):
        cm.c_prs_merged(_ctx(tmp_path, capped, weeks=2), cm.Metric("x", "", "", "", ""))


def test_release_distance_with_fakes(tmp_path: Path) -> None:
    seen: list[list[str]] = []

    def run(argv: Sequence[str], cwd: Path | None) -> str:
        seen.append(list(argv))
        if "ls-remote" in argv:
            # An annotated tag: the peeled `^{}` commit is the one counted from.
            tab, nl = chr(9), chr(10)
            return nl.join(
                f"{c}{tab}refs/tags/{r}"
                for c, r in [("aaa", "v1.2.3"), ("bbb", "v1.2.3^{}"), ("ccc", "v1.2.30")]
            )
        return "42" if "rev-list" in argv else ""

    ctx = _ctx(tmp_path, run)
    ctx.fetch = lambda url: json.dumps(
        {"info": {"version": "1.2.3"}, "urls": [{"upload_time_iso_8601": "2026-10-01T00:00:00Z"}]}
    ).encode()
    m = cm.Metric("release_distance", "", "", "", "")
    cm.c_release_distance(ctx, m)
    assert (m.value, m.status) == (42, "good")
    assert m.detail["tag"] == "v1.2.3"
    assert m.detail["tag_commit"] == "bbb"
    assert m.detail["uploaded"] == "2026-10-01T00:00:00Z"
    assert seen[-1][-1] == "bbb..origin/main"
    # No local tag is created: nothing fetches into refs/tags.
    assert not any("refs/tags/" in a and ":" in a for argv in seen for a in argv)

    def no_tag(argv: Sequence[str], cwd: Path | None) -> str:
        return ""

    ctx.run = no_tag
    with pytest.raises(cm.CollectError, match="no tag v1.2.3"):
        cm.c_release_distance(ctx, cm.Metric("x", "", "", "", ""))


# -- the --out guard -----------------------------------------------------------------------------


def test_out_inside_a_repo_is_refused(tmp_path: Path) -> None:
    def inside(argv: Sequence[str], cwd: Path | None) -> str:
        return "true\n"

    reason = cm.refuse_reason(tmp_path / "x.json", inside)
    assert reason is not None and "inside a git repository" in reason


def test_out_inside_dot_git_is_refused(tmp_path: Path) -> None:
    assert cm.refuse_reason(tmp_path / "x.json", lambda a, c: "false\n") is not None


def test_out_outside_a_repo_is_allowed(tmp_path: Path) -> None:
    def outside(argv: Sequence[str], cwd: Path | None) -> str:
        raise cm.CollectError("git -C x exited 128: fatal: not a git repository (or any ...)")

    assert cm.refuse_reason(tmp_path / "x.json", outside) is None


def test_out_guard_fails_closed(tmp_path: Path) -> None:
    def broken(argv: Sequence[str], cwd: Path | None) -> str:
        raise cm.CollectError("git could not run: FileNotFoundError")

    assert cm.refuse_reason(tmp_path / "x.json", broken) is not None
    assert cm.refuse_reason(tmp_path / "missing" / "x.json", broken) is not None


def test_real_git_refuses_this_checkout() -> None:
    # The test file itself lives in a work tree, so its directory must be refused for real, and
    # for the inside-a-repo reason, not because git failed some other way.
    reason = cm.refuse_reason(Path(__file__))
    assert reason is not None and "inside a git repository" in reason


def test_real_git_allows_a_directory_outside_any_repo(tmp_path: Path) -> None:
    # The negative control for the test above, through real git: a directory in no repository.
    outside = tmp_path / "out"
    outside.mkdir()
    probe = cm.run_bytes  # real git; skip rather than mis-assert where tmp is itself in a repo
    try:
        probe(["git", "-C", str(outside), "rev-parse", "--is-inside-work-tree"])
    except cm.CollectError:
        assert cm.refuse_reason(outside / "x.json") is None
    else:
        pytest.skip("the temporary directory is inside a git work tree on this machine")


# -- snapshot schema -----------------------------------------------------------------------------


def test_snapshot_schema(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path, _failing)
    metrics = cm.collect(ctx)
    snap = cm.snapshot(ctx, metrics, now=dt.datetime(2026, 11, 18, 12, 0, tzinfo=dt.UTC))
    assert snap["generated_at"] == "2026-11-18T12:00:00+00:00"
    assert snap["weeks"] == ["2026-W45", "2026-W46", "2026-W47"]
    keys = {"id", "label", "question", "value", "unit", "status", "series", "detail", "source"}
    for m in snap["metrics"]:
        assert keys | {"error"} == set(m)
        assert m["status"] in {"good", "warn", "bad", "unknown"}
        assert m["source"]
    json.dumps(snap)  # serialisable
    assert [m["id"] for m in snap["metrics"]] == [
        "backlog_burn",
        "prs_merged",
        "flow_health",
        "ci_main",
        "asvs",
        "dependency_vulns",
        "owner_waiting",
        "release_distance",
    ]
