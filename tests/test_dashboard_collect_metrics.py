# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Unit tests for scripts/dashboard/collect_metrics.py: the pure parts, with fakes, no network."""

from __future__ import annotations

import datetime as dt
import importlib.util
import io
import json
import sys
import zipfile
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

A40, B40 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
VAULT_SHA = "0123456789abcdef0123456789abcdef01234567"
NO_REPO = "fatal: not a git repository (or any of the parent directories): .git"


def _no_fetch(url: str) -> bytes:
    REACHED.append(url)
    raise cm.CollectError(f"network reached in a test: {url}")


def _no_raw(argv: Sequence[str]) -> bytes:
    REACHED.append(" ".join(argv))
    raise cm.CollectError("subprocess reached in a test")


def _ctx(
    tmp_path: Path, run: Any, *, weeks: int = 3, through: str = "2026-11-18", today: str = ""
) -> Any:
    return cm.Context(
        vault=tmp_path / "vault",
        through=dt.date.fromisoformat(through),
        weeks=weeks,
        workdir=tmp_path,
        run=run,
        run_tool=run,
        run_raw=_no_raw,
        fetch=_no_fetch,
        today=dt.date.fromisoformat(today or "2026-11-19"),
        gh_backoff=0.0,
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
                for c, r in [
                    (A40, "v1.2.3"),
                    (B40, "v1.2.3^{}"),
                    ("cccccccccccccccccccccccccccccccccccccccc", "v1.2.30"),
                ]
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
    assert m.detail["tag_commit"] == B40
    assert m.detail["uploaded"] == "2026-10-01T00:00:00Z"
    assert seen[-1][-1] == f"{B40}..refs/remotes/origin/main"
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

    reason = cm.refuse_reason(tmp_path / "x.json", [inside])
    assert reason is not None and "inside a git repository" in reason


def test_out_inside_dot_git_is_refused(tmp_path: Path) -> None:
    assert cm.refuse_reason(tmp_path / "x.json", [lambda a, c: "false\n"]) is not None


def _outside(argv: Sequence[str], cwd: Path | None) -> str:
    raise cm.CollectError("git -C x exited 128: " + NO_REPO, stderr=NO_REPO + "\n")


def test_out_outside_a_repo_is_allowed(tmp_path: Path) -> None:
    assert cm.refuse_reason(tmp_path / "x.json", [_outside]) is None


def test_either_probe_finding_a_repo_refuses(tmp_path: Path) -> None:
    def inside(argv: Sequence[str], cwd: Path | None) -> str:
        return "true\n"

    assert cm.refuse_reason(tmp_path / "x.json", [_outside, inside]) is not None
    assert cm.refuse_reason(tmp_path / "x.json", [inside, _outside]) is not None
    assert cm.refuse_reason(tmp_path / "x.json", [_outside, _outside]) is None


def test_the_safe_phrase_counts_only_as_gits_whole_stderr(tmp_path: Path) -> None:
    # The phrase in the MESSAGE (which carries the probed path) is not git saying it.
    def phrase_in_path(argv: Sequence[str], cwd: Path | None) -> str:
        raise cm.CollectError(
            "git -C D:/not a git repository (or any x exited 128: fatal: unsafe repository",
            stderr="fatal: detected dubious ownership in repository",
        )

    def phrase_with_more(argv: Sequence[str], cwd: Path | None) -> str:
        raise cm.CollectError("git exited 128", stderr=NO_REPO + "\nwarning: something else")

    assert cm.refuse_reason(tmp_path / "x.json", [phrase_in_path]) is not None
    assert cm.refuse_reason(tmp_path / "x.json", [phrase_with_more]) is not None


def test_pruned_worktree_message_is_not_safe(tmp_path: Path) -> None:
    # git's answer for a pruned worktree's gitdir shares the short phrase but is inside a repo.
    def pruned(argv: Sequence[str], cwd: Path | None) -> str:
        text = "fatal: not a git repository: D:/r/.git/worktrees/x"
        raise cm.CollectError("git exited 128: " + text, stderr=text)

    assert cm.refuse_reason(tmp_path / "x.json", [pruned]) is not None


def test_out_guard_fails_closed(tmp_path: Path) -> None:
    def broken(argv: Sequence[str], cwd: Path | None) -> str:
        raise cm.CollectError("git could not run: FileNotFoundError")

    assert cm.refuse_reason(tmp_path / "x.json", [broken]) is not None
    assert cm.refuse_reason(tmp_path / "missing" / "x.json", [broken]) is not None


def test_real_git_refuses_this_checkout() -> None:
    # The test file itself lives in a work tree, so its directory must be refused for real, and
    # for the inside-a-repo reason, not because git failed some other way.
    reason = cm.refuse_reason(Path(__file__))
    assert reason is not None and "rev-parse said 'true'" in reason


def test_real_git_allows_a_directory_outside_any_repo(tmp_path: Path) -> None:
    # The negative control for the test above, through real git: a directory in no repository.
    outside = tmp_path / "out"
    outside.mkdir()
    try:  # real git, under the guard's own env; skip where tmp is itself in a repo
        cm.run_probe(["git", "-C", str(outside), "rev-parse", "--is-inside-work-tree"])
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
        assert m["status"] in {"good", "warn", "bad", "info", "unknown"}
        assert m["source"]
    json.dumps(snap)  # serialisable
    assert [m["id"] for m in snap["metrics"]] == [
        "backlog_burn",
        "backlog_forecast",
        "batch_progress",
        "prs_merged",
        "ci_main",
        "asvs",
        "dependency_vulns",
        "owner_waiting",
        "release_distance",
    ]


# -- success paths with fakes --------------------------------------------------------------------


def test_gh_retries_a_transient_failure(tmp_path: Path) -> None:
    calls: list[int] = []

    def flaky(argv: Sequence[str], cwd: Path | None) -> str:
        calls.append(1)
        if len(calls) < cm.GH_ATTEMPTS:
            raise cm.CollectError("gh exited 1: HTTP 502")
        return "[1]"

    assert cm.gh_json(_ctx(tmp_path, flaky), ["api", "x"]) == [1]
    assert len(calls) == cm.GH_ATTEMPTS


def test_dependency_vulns_counts_slurped_pages(tmp_path: Path) -> None:
    def run(argv: Sequence[str], cwd: Path | None) -> str:
        if "api" in argv:
            page = [
                {"security_advisory": {"severity": "high"}},
                {"security_advisory": {"severity": "low"}},
            ]
            return json.dumps([page, [{"security_advisory": {"severity": "low"}}]])
        raise cm.CollectError("no vuln-metrics run in this test")

    m = cm.Metric("dependency_vulns", "", "", "", "")
    cm.c_dependency_vulns(_ctx(tmp_path, run), m)
    assert m.value == 3
    assert m.status == "bad"
    assert m.detail["open_by_severity"] == {"critical": 0, "high": 1, "medium": 0, "low": 2}
    # The KPI attachment failed: its own error, and a partial_error so the run exits 3.
    assert m.detail["kpis"]["error"]
    assert m.detail["partial_error"].startswith("vuln-metrics KPIs:")


def test_ci_main_per_week(tmp_path: Path) -> None:
    def run(argv: Sequence[str], cwd: Path | None) -> str:
        if "run" in argv:
            created = argv[argv.index("--created") + 1]
            if created.startswith("2026-11-09"):
                return json.dumps(
                    [
                        {"createdAt": "2026-11-10T00:00:00Z", "conclusion": "success"},
                        {"createdAt": "2026-11-11T00:00:00Z", "conclusion": "success"},
                        {"createdAt": "2026-11-12T00:00:00Z", "conclusion": "failure"},
                        {"createdAt": "2026-11-12T00:00:00Z", "conclusion": "cancelled"},
                    ]
                )
            return "[]"
        return json.dumps([{"number": 7}])  # one open ci-red PR

    m = cm.Metric("ci_main", "", "", "", "")
    cm.c_ci_main(_ctx(tmp_path, run, weeks=2, today="2026-11-18"), m)
    assert m.value == 66.6  # 2 of 3, rounded down so it never bands above its rate
    assert m.status == "bad"
    assert m.detail["open_ci_red_prs"] == 1
    assert m.series == [{"week": "2026-W46", "value": 66.6}, {"week": "2026-W47", "value": None}]


def _census(**kw: Any) -> Any:
    base: dict[str, Any] = {
        "rows": 2000,
        "weeks": {
            "2026-W46": {"filed": 4, "closed": 2, "declined": 1},
            "2026-W47": {"filed": 1, "superseded": 3},
        },
        "undated": {"filed": 9},
        "open_by_verdict": {"build": 5, "owner-ruling": 2, "demand-gate": 3, "none": 1, "other": 1},
        "active_verdicts": ["build", "research", "decide", "owner-ruling"],
        "deferred_verdict": "demand-gate",
        "activity": ["filed", "closed", "declined", "superseded"],
    }
    return cm.Census(**{**base, **kw})


def _vault_ctx(tmp_path: Path, census: Any = None) -> Any:
    ctx = _ctx(tmp_path, _failing, weeks=2)
    ctx._vault = cm.VaultRead(sha="abc", root=tmp_path, census=census or _census())
    return ctx


def test_a_renamed_vault_key_is_an_error_not_zero(tmp_path: Path) -> None:
    renamed = _census(activity=["filed", "shipped", "declined", "superseded"])
    with pytest.raises(cm.CollectError, match="no longer defines"):
        cm.c_backlog_burn(_vault_ctx(tmp_path, renamed), cm.Metric("x", "", "", "", ""))
    gone = _census(active_verdicts=["build"])
    with pytest.raises(cm.CollectError, match="owner-ruling"):
        cm.c_owner_waiting(_vault_ctx(tmp_path, gone), cm.Metric("x", "", "", "", ""))


def test_backlog_burn_from_census(tmp_path: Path) -> None:
    m = cm.Metric("backlog_burn", "", "", "", "")
    cm.c_backlog_burn(_vault_ctx(tmp_path), m)
    assert m.value == 1  # closed 6 minus filed 5
    assert m.status == "good"
    assert m.series == [{"week": "2026-W46", "value": -1}, {"week": "2026-W47", "value": 2}]
    d = m.detail
    assert (d["open_active"], d["open_deferred"], d["open_unclassified"]) == (7, 3, 2)
    assert d["vault_origin_main"] == "abc"
    assert "ROWS" in d["counts"]


def test_owner_waiting_from_census(tmp_path: Path) -> None:
    m = cm.Metric("owner_waiting", "", "", "", "")
    cm.c_owner_waiting(_vault_ctx(tmp_path), m)
    assert (m.value, m.status) == (2, "warn")


# -- retries, the shared list guard and partial failures ------------------------------------------


def test_gh_fails_fast_on_a_non_transient_error(tmp_path: Path) -> None:
    calls: list[int] = []

    def not_found(argv: Sequence[str], cwd: Path | None) -> str:
        calls.append(1)
        raise cm.CollectError("gh api x exited 1: HTTP 404: Not Found")

    with pytest.raises(cm.CollectError, match="404"):
        cm.gh_json(_ctx(tmp_path, not_found), ["api", "x"])
    assert len(calls) == 1


@pytest.mark.parametrize(
    ("text", "transient"),
    [
        ("gh exited 1: HTTP 502: Bad Gateway", True),
        ("gh exited 1: API rate limit exceeded for user", True),
        ("gh could not run: TimeoutExpired: timed out after 180 seconds", False),
        ("gh exited 1: error connecting to api.github.com", True),
        ("gh exited 1: context deadline exceeded", True),
        ("gh exited 1: read tcp: connection reset by peer", True),
        ("gh exited 1: HTTP 429: Too Many Requests", True),
        ("gh exited 1: HTTP 404: Not Found", False),
        ("gh exited 1: HTTP 404: Not Found (https://api.github.com/repos/x/502)", False),
        ("gh exited 1: HTTP 401: Bad credentials", False),
        ("gh could not run: FileNotFoundError: gh", False),
    ],
)
def test_is_transient(text: str, transient: bool) -> None:
    assert cm.is_transient(cm.CollectError(text)) is transient


def test_gh_list_refuses_a_capped_answer(tmp_path: Path) -> None:
    def capped(argv: Sequence[str], cwd: Path | None) -> str:
        assert list(argv[-2:]) == ["--limit", str(cm.PR_LIST_LIMIT)]
        return json.dumps([{"number": n} for n in range(cm.PR_LIST_LIMIT)])

    with pytest.raises(cm.CollectError, match="truncated"):
        cm.gh_list(_ctx(tmp_path, capped), ["pr", "list"])
    with pytest.raises(cm.CollectError, match="returned dict"):
        cm.gh_list(_ctx(tmp_path, lambda a, c: "{}"), ["pr", "list"])


def test_ci_main_reads_push_runs_and_skips_ci_red_for_a_past_through(tmp_path: Path) -> None:
    seen: list[list[str]] = []

    def run(argv: Sequence[str], cwd: Path | None) -> str:
        seen.append(list(argv))
        return "[]"

    m = cm.Metric("ci_main", "", "", "", "")
    cm.c_ci_main(_ctx(tmp_path, run, weeks=2), m)  # through 2026-11-18, today 2026-11-19
    runs = [a for a in seen if a[1] == "run"]
    assert runs and all(a[a.index("--event") + 1] == "push" for a in runs)
    assert not any("ci-red" in a for a in seen)
    assert m.detail["open_ci_red_prs"] is None
    assert "not read" in m.detail["open_ci_red_prs_as_of"]


def test_release_distance_records_an_unreadable_upload_time(tmp_path: Path) -> None:
    def run(argv: Sequence[str], cwd: Path | None) -> str:
        if "ls-remote" in argv:
            return A40 + chr(9) + "refs/tags/v1.0.0"
        return "3" if "rev-list" in argv else ""

    ctx = _ctx(tmp_path, run)
    ctx.fetch = lambda url: json.dumps({"info": {"version": "1.0.0"}, "urls": [{}]}).encode()
    m = cm.Metric("release_distance", "", "", "", "")
    cm.c_release_distance(ctx, m)
    assert m.value == 3
    assert m.detail["uploaded"] is None
    assert "upload time unreadable" in m.detail["partial_error"]


def test_vuln_kpis_reads_main_only(tmp_path: Path) -> None:
    seen: list[list[str]] = []

    def run(argv: Sequence[str], cwd: Path | None) -> str:
        seen.append(list(argv))
        return "[]"

    got = cm._vuln_kpis(_ctx(tmp_path, run))
    assert got["error"]
    assert seen[0][seen[0].index("--branch") + 1] == "main"


# -- the --out guard ignores the caller's GIT_* environment ---------------------------------------


def test_probe_env_drops_git_variables(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", "/x")
    monkeypatch.setenv("GIT_DIR", "/y")
    env = cm.probe_env()
    assert "GIT_CEILING_DIRECTORIES" not in env and "GIT_DIR" not in env
    assert env["GIT_DISCOVERY_ACROSS_FILESYSTEM"] == "1"


def test_real_git_refuses_this_checkout_despite_a_ceiling(monkeypatch: pytest.MonkeyPatch) -> None:
    # A ceiling AT the checkout root stops discovery before it, so without the scrub git answers
    # "not a git repository" for tests/. The control proves the ceiling bites on this machine.
    for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR"):  # set under a git hook
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(Path(__file__).resolve().parents[1]))
    assert cm.refuse_reason(Path(__file__), [cm.run_cmd]) is None
    reason = cm.refuse_reason(Path(__file__))
    assert reason is not None and "rev-parse said 'true'" in reason


def test_remove_tree_reports_a_failure(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    def stuck(path: Path, onexc: Any) -> None:
        onexc(cm.os.unlink, str(path / "held.bin"), PermissionError("in use"))

    monkeypatch.setattr(cm.shutil, "rmtree", stuck)
    assert cm.remove_tree(tmp_path) is False
    assert "ERROR: could not remove temporary" in capsys.readouterr().err


def _backdate(monkeypatch: pytest.MonkeyPatch, *stale: Path) -> None:
    # os.utime cannot set a creation time, so the sweep's age read is faked for these.
    real = cm._created
    monkeypatch.setattr(cm, "_created", lambda p: 1_000_000.0 if p in stale else real(p))


def test_sweep_removes_only_stale_prefixed_dirs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    old, fresh, other = tmp_path / "mf-metrics-old", tmp_path / "mf-metrics-new", tmp_path / "keep"
    for d in (old, fresh, other):
        d.mkdir()
    _backdate(monkeypatch, old, other)
    assert cm.sweep_stale(tmp_path, "mf-metrics-") is True
    assert sorted(p.name for p in tmp_path.iterdir()) == ["keep", "mf-metrics-new"]


def test_a_stale_dir_that_will_not_go_fails_the_sweep(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    old = tmp_path / "mf-metrics-old"
    old.mkdir()
    _backdate(monkeypatch, old)
    monkeypatch.setattr(cm, "remove_tree", lambda path: False)
    assert cm.sweep_stale(tmp_path, "mf-metrics-") is False


@pytest.mark.skipif(
    sys.platform != "win32", reason="only Windows keeps a creation time that utime cannot move"
)
def test_sweep_ages_by_creation_not_modified_time(tmp_path: Path) -> None:
    import os

    d = tmp_path / "mf-metrics-x"
    d.mkdir()
    # A modified time far in the past does not make a new directory stale: the age read is the
    # creation time, not the modified time.
    os.utime(d, (1_000_000.0, 1_000_000.0))
    st: Any = d.stat()  # st_birthtime is not in every platform's stub
    assert cm._created(d) == st.st_birthtime != st.st_mtime
    assert cm.sweep_stale(tmp_path, "mf-metrics-") is True
    assert d.exists()


def test_census_child_output_that_is_not_utf8_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(cm, "run_bytes", lambda argv, cwd=None, *, env=None: b'{"a": "\xff"}')
    with pytest.raises(cm.CollectError, match="driver.py wrote non-UTF-8 output"):
        cm.run_child(["driver.py"], tmp_path)
    # Only the scorecard tool opts out of the strict decode.
    assert cm.run_tool_child(["tool.py"], tmp_path) == '{"a": "\ufffd"}'


def test_child_runs_in_utf8_mode() -> None:
    assert "PYTHONUTF8" not in cm.child_env()  # -I would ignore it
    assert cm.run_child(["-c", "import sys; print(sys.flags.utf8_mode)"]).strip() == "1"


# -- the vault read, with a fake archive ------------------------------------------------------------

_FAKE_CHECKER = """
import re

LEDGER_FILE_GLOBS = ("docs/BACKLOG*.md",)
SHIPPED_BANNER, DECLINED_BANNER, RETIRED_BANNER = "S", "D", "R"
PRIORITIZED_BANNER, IN_PROGRESS_BANNER = "O", "I"
PARTIAL_LINE = re.compile(r"^> \\*\\*PARTIAL")


class Item:
    def __init__(self, line, banner):
        self.line, self.body_line, self.section_lines = line, line + 1, []
        self.banner_lines = [(line, banner)]
        self.is_open = banner in (PRIORITIZED_BANNER, IN_PROGRESS_BANNER)


def parse_items(text):
    # One row per "filed" line: the first open, the rest shipped.
    lines = [n for n, ln in enumerate(text.splitlines(), 1) if ln.startswith("filed ")]
    return [Item(n, PRIORITIZED_BANNER if i == 0 else SHIPPED_BANNER) for i, n in enumerate(lines)]
"""
_FAKE_REPORT = """
import datetime as dt
from collections import Counter

from backlog_status_check import LEDGER_FILE_GLOBS  # noqa: F401

DEFAULT_SOURCES = ("docs/BACKLOG one.md",)
MIN_TOTAL_ITEMS = 1
ACTIVE_VERDICTS = ("build", "owner-ruling")
DEFERRED_VERDICT = "demand-gate"
ACTIVITY = ("filed", "closed", "declined", "superseded")


def iso_week(date):
    if date is None:
        return None
    try:
        y, w, _ = dt.date.fromisoformat(date).isocalendar()
    except ValueError:
        return None
    return f"{y}-W{w:02d}"


class Census:
    def __init__(self):
        self.rows, self.per_source, self.weeks, self.undated = 0, [], {}, Counter()
        self.open_by_verdict = Counter({"owner-ruling": 1})

    def count(self, column, date):
        week = iso_week(date)
        if week is None:
            self.undated[column] += 1
        else:
            self.weeks.setdefault(week, Counter())[column] += 1


def read_sources(paths, root, explicit):
    return [(p.relative_to(root).as_posix(), p.read_text(encoding="utf-8")) for p in paths]


def census(sources):
    c = Census()
    for label, text in sources:
        dates = [ln.split()[1] for ln in text.splitlines() if ln.startswith("filed ")]
        c.per_source.append((label, len(dates)))
        c.rows += len(dates)
        for d in dates:
            c.count("filed", d)
    return c


def default_corpus_errors(root, per_source):
    return []
"""


def _tar(files: dict[str, str]) -> bytes:
    import io
    import tarfile

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, text in files.items():
            data = text.encode("utf-8")
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


_VAULT_FILES = {
    "scripts/docs/backlog_status_check.py": _FAKE_CHECKER,
    "scripts/docs/ledger_weekly_report.py": _FAKE_REPORT,
    # Synthetic rows: one inside the window, one after --through in the same ISO week, one undated.
    "docs/BACKLOG one.md": "filed 2026-11-16\nfiled 2026-11-20\nfiled not-a-date\n",
    "docs/security/asvs-scorecard.toml": "# synthetic\n",
}


def _fake_archive(argv: Sequence[str]) -> bytes:
    wanted = list(argv)[list(argv).index("--") + 1 :]
    return _tar(
        {
            k: v
            for k, v in _VAULT_FILES.items()
            if any(k == w or k.startswith(w + "/") for w in wanted)
        }
    )


def _vault_git(argv: Sequence[str], cwd: Path | None) -> str:
    if "rev-parse" in argv:
        return VAULT_SHA + "\n"
    if "ls-tree" in argv:
        assert "-z" in argv
        return "docs/BACKLOG one.md\0docs/notes.txt\0"
    return ""


def test_read_vault_lists_with_nul_and_clips_at_through(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path, _vault_git)
    ctx.run_raw = _fake_archive
    v = ctx.vault_read()  # the vault code runs for real, in a child process
    assert v.sha == VAULT_SHA
    c = v.census
    assert c.rows == 3
    assert c.weeks["2026-W47"]["filed"] == 1  # 2026-11-20 is after --through 2026-11-18
    assert c.weeks[cm.AFTER_THROUGH]["filed"] == 1
    assert c.undated["filed"] == 1  # an unparseable date is still undated, not clipped
    assert c.open_by_verdict == {"owner-ruling": 1}
    assert c.by_priority == {"unscored": {"open": 1, "closed": 2}}
    # Nothing of the vault's was imported into this process.
    assert "ledger_weekly_report" not in sys.modules
    assert "backlog_status_check" not in sys.modules


def test_the_vault_child_gets_no_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GH_TOKEN", "x")
    monkeypatch.setenv("GITHUB_TOKEN", "x")
    monkeypatch.setenv("GIT_DIR", "x")
    monkeypatch.setenv("USERPROFILE", "x")
    env = cm.child_env()
    assert not {k for k in env if "TOKEN" in k or k.startswith("GIT_")}
    assert "USERPROFILE" not in env


def test_a_census_that_never_clipped_is_refused(tmp_path: Path) -> None:
    def driver(argv: Sequence[str], cwd: Path | None = None) -> str:
        # The vault code runs from the archive root, never the caller's work tree.
        assert cwd is not None and str(cwd) == argv[2]
        if argv[1] == "globs":
            return json.dumps({"ledger_file_globs": ["docs/BACKLOG*.md"]})
        return json.dumps(
            {
                "rows": 5,
                "weeks": {},
                "undated": {},
                "open_by_verdict": {},
                "active_verdicts": ["owner-ruling"],
                "deferred_verdict": "demand-gate",
                "activity": ["filed"],
                "min_total_items": 1,
                "structural_errors": [],
                "clip_calls": 0,
            }
        )

    ctx = _ctx(tmp_path, _vault_git)
    ctx.run_raw = _fake_archive
    ctx.run_vault = driver
    with pytest.raises(cm.CollectError, match="--through was not applied"):
        ctx.vault_read()


def test_a_vault_ref_that_is_no_sha_is_refused(tmp_path: Path) -> None:
    def git(argv: Sequence[str], cwd: Path | None) -> str:
        return "origin/main\n" if "rev-parse" in argv else _vault_git(argv, cwd)

    with pytest.raises(cm.CollectError, match="not a commit sha"):
        _ctx(tmp_path, git).vault_read()


def test_read_vault_refuses_when_no_ledger_matches(tmp_path: Path) -> None:
    def git(argv: Sequence[str], cwd: Path | None) -> str:
        return "docs/notes.txt\0" if "ls-tree" in argv else _vault_git(argv, cwd)

    ctx = _ctx(tmp_path, git)
    ctx.run_raw = _fake_archive
    with pytest.raises(cm.CollectError, match="no ledger file"):
        ctx.vault_read()


# -- the ASVS collector --------------------------------------------------------------------------


def _asvs_ctx(tmp_path: Path, printed: str) -> Any:
    def run(argv: Sequence[str], cwd: Path | None) -> str:
        assert "--status" in argv
        return printed

    ctx = _ctx(tmp_path, run)
    ctx.run_raw = _fake_archive
    ctx._vault = cm.VaultRead(sha="abc123", root=tmp_path, census=_census())
    return ctx


def test_asvs_reads_counts_and_the_ref_pair(tmp_path: Path) -> None:
    printed = "# asvs-status scorecard=NO-GIT engine=deadbeef1234\ncells 4: 3 pass, 1 na, 0 needs-review, 0 unverified\n"
    m = cm.Metric("asvs", "", "", "", "")
    cm.c_asvs(_asvs_ctx(tmp_path, printed), m)
    assert (m.value, m.status) == (100.0, "good")
    assert m.detail["engine_ref"] == "deadbeef1234"
    assert "partial_error" not in m.detail
    assert cm.asvs_ref_pair(m.detail) == "scorecard=vault-origin-main@abc123 engine=deadbeef1234"


def test_asvs_value_is_floored_like_the_ci_series(tmp_path: Path) -> None:
    # 2 of 3 is 66.67 percent: floored to 66.6, never rounded up to 66.7.
    printed = "# asvs-status scorecard=NO-GIT engine=deadbeef1234\ncells 3: 2 pass, 1 fail, 0 needs-review, 0 unverified\n"
    m = cm.Metric("asvs", "", "", "", "")
    cm.c_asvs(_asvs_ctx(tmp_path, printed), m)
    assert m.value == 66.6
    assert "partial_error" not in m.detail


def test_asvs_without_no_verdict_counts_withholds_the_headline(tmp_path: Path) -> None:
    # No needs-review or unverified count on the cells line: partial, and no headline at source.
    printed = "# asvs-status scorecard=NO-GIT engine=deadbeef1234\ncells 3: 2 pass, 1 fail\n"
    m = cm.Metric("asvs", "", "", "", "")
    cm.c_asvs(_asvs_ctx(tmp_path, printed), m)
    assert (m.value, m.status) == (None, "unknown")
    assert "needs-review or unverified" in m.detail["partial_error"]


def test_the_scorecard_tool_runs_isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = cm.Context(vault=tmp_path, through=dt.date(2026, 11, 18), weeks=2, workdir=tmp_path)
    assert ctx.run_tool is cm.run_tool_child
    # What run_tool_child hands the process: -I -X utf8, and the allowlist plus home variables only.
    monkeypatch.setenv("GH_TOKEN", "x")
    monkeypatch.setenv("GIT_DIR", "x")
    monkeypatch.setenv("PYTHONPATH", "x")
    monkeypatch.setenv("USERPROFILE", "u")
    got: list[tuple[Sequence[str], dict[str, str] | None]] = []

    def fake_bytes(argv: Sequence[str], cwd: Path | None = None, *, env: Any = None) -> bytes:
        got.append((argv, env))
        return b""

    monkeypatch.setattr(cm, "run_bytes", fake_bytes)
    cm.run_tool_child(["tool.py"], tmp_path)
    cm.run_child(["driver.py"], tmp_path)
    (tool_argv, tool_env), (_, child) = got
    assert list(tool_argv[1:]) == ["-I", "-X", "utf8", "tool.py"]
    assert tool_env is not None and child is not None
    for key in ("GH_TOKEN", "GIT_DIR", "PYTHONPATH"):
        assert key not in tool_env and key not in child
    assert tool_env["USERPROFILE"] == "u"
    assert "USERPROFILE" not in child  # the vault code gets no profile variable
    monkeypatch.undo()
    seen: list[Sequence[str]] = []

    def run_tool(argv: Sequence[str], cwd: Path | None) -> str:
        seen.append(argv)
        return "# asvs-status scorecard=NO-GIT engine=deadbeef1234\ncells 1: 1 pass, 0 needs-review, 0 unverified\n"

    ctx = _asvs_ctx(tmp_path, "unused")
    ctx.run = _failing
    ctx.run_tool = run_tool
    m = cm.Metric("asvs", "", "", "", "")
    cm.c_asvs(ctx, m)
    assert m.value == 100.0
    # c_asvs went through run_tool, never ctx.run (which fails here); the runner supplies the
    # interpreter, so the argv starts at the script.
    assert seen and str(seen[0][0]).endswith("scorecard.py")


def test_asvs_without_an_engine_ref_is_partial(tmp_path: Path) -> None:
    m = cm.Metric("asvs", "", "", "", "")
    cm.c_asvs(_asvs_ctx(tmp_path, "cells 2: 1 pass, 1 fail, 0 needs-review, 0 unverified\n"), m)
    assert m.value == 50.0
    assert m.detail["engine_ref"] is None
    assert "engine= ref" in m.detail["partial_error"]
    with pytest.raises(cm.CollectError, match="no 'cells' line"):
        cm.c_asvs(_asvs_ctx(tmp_path, "nothing\n"), cm.Metric("asvs", "", "", "", ""))


# -- main() ----------------------------------------------------------------------------------------


def _main_metrics(*, partial: bool) -> list[Any]:
    asvs = cm.Metric("asvs", "ASVS", "?", "percent", "src", value=50.0, status="warn")
    asvs.detail = {"scorecard_sha": "abc123", "engine_ref": "deadbeef1234"}
    other = cm.Metric("prs_merged", "PRs", "?", "n", "src", value=4, status="good")
    if partial:
        other.detail = {"partial_error": "stall count: TimeoutExpired"}
    return [asvs, other]


def _WD(tmp_path: Path) -> list[str]:
    # The work dir under tmp_path, so no test probes or sweeps the real temp directory.
    return ["--work-dir", str(tmp_path)]


def test_main_writes_the_snapshot_and_prints_no_value(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    monkeypatch.setattr(cm, "refuse_reason", lambda out: None)
    monkeypatch.setattr(cm, "collect", lambda ctx: _main_metrics(partial=False))
    out = tmp_path / "snap.json"
    rc = cm.main(
        ["--vault", str(tmp_path), *_WD(tmp_path), "--out", str(out), "--through", "2026-11-18"]
    )
    assert rc == 0
    snap = json.loads(out.read_text(encoding="utf-8"))
    assert [m["id"] for m in snap["metrics"]] == ["asvs", "prs_merged"]
    assert sorted(p.name for p in tmp_path.iterdir()) == ["snap.json"]  # no temp left behind
    printed = capsys.readouterr().out
    # Id, status and a read flag only: no value, count, ref or error text reaches stdout.
    assert printed.splitlines() == ["asvs: status=warn read=ok", "prs_merged: status=good read=ok"]


def test_main_never_prints_values_or_errors(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    def metrics(ctx: Any) -> list[Any]:
        bad = cm.Metric("ci_main", "CI", "?", "percent", "src")
        bad.error = "git exited 1: secret-looking stderr"
        return [*_main_metrics(partial=True), bad]

    monkeypatch.setattr(cm, "refuse_reason", lambda out: None)
    monkeypatch.setattr(cm, "collect", metrics)
    assert (
        cm.main(["--vault", str(tmp_path), *_WD(tmp_path), "--out", str(tmp_path / "s.json")]) == 3
    )
    printed = capsys.readouterr().out
    assert "50.0" not in printed and "stderr" not in printed and "TimeoutExpired" not in printed
    assert "prs_merged: status=good read=partial" in printed
    assert "ci_main: status=unknown read=error" in printed


def test_main_puts_its_work_dir_under_work_dir_and_refuses_a_repo(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    seen: list[Path] = []

    def metrics(ctx: Any) -> list[Any]:
        seen.append(ctx.workdir)
        return _main_metrics(partial=False)

    monkeypatch.setattr(cm, "refuse_reason", lambda out: None)
    monkeypatch.setattr(cm, "collect", metrics)
    base = tmp_path / "work"
    base.mkdir()
    out = str(tmp_path / "s.json")
    assert (
        cm.main(["--vault", str(tmp_path), *_WD(tmp_path), "--out", out, "--work-dir", str(base)])
        == 0
    )
    assert seen[0].parent == base.resolve() and seen[0].name.startswith("mf-metrics-")
    assert list(base.iterdir()) == []  # removed at exit
    inside = Path(__file__).resolve().parent
    assert (
        cm.main(["--vault", str(tmp_path), *_WD(tmp_path), "--out", out, "--work-dir", str(inside)])
        == 1
    )
    assert len(seen) == 1  # nothing collected for a refused work dir


def test_main_fails_when_its_work_dir_will_not_go(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(cm, "refuse_reason", lambda out: None)
    monkeypatch.setattr(cm, "collect", lambda ctx: _main_metrics(partial=False))
    monkeypatch.setattr(cm, "remove_tree", lambda path: False)
    assert (
        cm.main(["--vault", str(tmp_path), *_WD(tmp_path), "--out", str(tmp_path / "s.json")]) == 3
    )


def test_release_and_run_ids_are_validated(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path, lambda a, c: "")
    ctx.fetch = lambda url: json.dumps({"info": {"version": "1.0 --upload-pack=x"}}).encode()
    with pytest.raises(cm.CollectError, match="not a canonical release version"):
        cm.c_release_distance(ctx, cm.Metric("x", "", "", "", ""))

    def runs(argv: Sequence[str], cwd: Path | None) -> str:
        return json.dumps([{"databaseId": "1;rm", "createdAt": "x"}])

    assert "not a number" in cm._vuln_kpis(_ctx(tmp_path, runs))["error"]


def test_main_exits_3_on_a_partial_failure(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(cm, "refuse_reason", lambda out: None)
    monkeypatch.setattr(cm, "collect", lambda ctx: _main_metrics(partial=True))
    out = tmp_path / "snap.json"
    assert cm.main(["--vault", str(tmp_path), *_WD(tmp_path), "--out", str(out)]) == 3
    assert out.exists()  # written before the exit status goes red


def test_main_refuses_and_writes_nothing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(cm, "refuse_reason", lambda out: "inside a git repository")
    monkeypatch.setattr(cm, "collect", lambda ctx: pytest.fail("collect ran on a refused --out"))
    out = tmp_path / "snap.json"
    assert cm.main(["--vault", str(tmp_path), *_WD(tmp_path), "--out", str(out)]) == 1
    assert not out.exists()
    assert (
        cm.main(["--vault", str(tmp_path), *_WD(tmp_path), "--out", str(out), "--weeks", "1"]) == 1
    )
    monkeypatch.setattr(cm, "refuse_reason", lambda out: None)
    assert (
        cm.main(
            ["--vault", str(tmp_path), *_WD(tmp_path), "--out", str(out), "--through", "2999-01-01"]
        )
        == 1
    )


def test_ci_red_failure_degrades_only_that_count(tmp_path: Path) -> None:
    def run(argv: Sequence[str], cwd: Path | None) -> str:
        if "ci-red" in argv:
            raise cm.CollectError("gh pr list exited 1: HTTP 403: Forbidden")
        if argv[argv.index("--created") + 1].startswith("2026-11-09"):
            return json.dumps([{"createdAt": "2026-11-10T00:00:00Z", "conclusion": "success"}])
        return "[]"

    m = cm.Metric("ci_main", "", "", "", "")
    cm.c_ci_main(_ctx(tmp_path, run, weeks=2, today="2026-11-18"), m)
    assert m.value == 100.0
    assert m.status == "warn"  # an unread ci-red count caps a good pass rate at warn
    assert m.detail["open_ci_red_prs"] is None
    assert m.detail["partial_error"].startswith("ci-red count:")


def test_a_merged_pr_failure_is_read_once(tmp_path: Path) -> None:
    calls: list[str] = []

    def run(argv: Sequence[str], cwd: Path | None) -> str:
        calls.append(" ".join(argv))
        raise cm.CollectError("gh pr list exited 1: HTTP 403: Forbidden")

    ctx = _ctx(tmp_path, run, weeks=2)
    for _ in range(2):
        with pytest.raises(cm.CollectError, match="403"):
            cm.merged_prs(ctx, cm.ENGINE_REPO)
    assert len(calls) == 1


def test_the_driver_counts_its_clip_calls() -> None:
    import types

    spec = importlib.util.spec_from_file_location("dashboard_vault_census", cm.VAULT_DRIVER)
    assert spec is not None and spec.loader is not None
    driver = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(driver)
    report = types.SimpleNamespace(iso_week=lambda d: None, census=lambda sources: "c")
    assert driver.clipped_census(report, [], dt.date(2026, 11, 18)) == ("c", 0)


def test_asvs_with_an_unattributable_engine_ref_is_partial(tmp_path: Path) -> None:
    printed = "# asvs-status scorecard=NO-GIT engine=NO-GIT\ncells 2: 2 pass, 0 needs-review, 0 unverified\n"
    m = cm.Metric("asvs", "", "", "", "")
    cm.c_asvs(_asvs_ctx(tmp_path, printed), m)
    assert m.value == 100.0
    assert "no attributable ref: engine=NO-GIT" in m.detail["partial_error"]


def test_write_json_atomic_is_strict_and_leaves_no_temp(tmp_path: Path) -> None:
    out = tmp_path / "x.json"
    cm.write_json_atomic(out, {"a": 1})
    assert json.loads(out.read_text(encoding="utf-8")) == {"a": 1}
    with pytest.raises(ValueError):
        cm.write_json_atomic(out, {"a": float("nan")})
    assert [p.name for p in tmp_path.iterdir()] == ["x.json"]


def test_dirty_engine_ref_is_partial(tmp_path: Path) -> None:
    printed = "# asvs-status scorecard=NO-GIT engine=abc123+dirty\ncells 1: 1 pass, 0 needs-review, 0 unverified\n"
    m = cm.Metric("asvs", "", "", "", "")
    cm.c_asvs(_asvs_ctx(tmp_path, printed), m)
    assert "engine=abc123+dirty" in m.detail["partial_error"]


def test_archive_uses_literal_pathspecs(tmp_path: Path) -> None:
    seen: list[list[str]] = []

    def raw(argv: Sequence[str]) -> bytes:
        seen.append(list(argv))
        return _tar({})

    ctx = _ctx(tmp_path, _failing)
    ctx.run_raw = raw
    cm._archive_into(ctx, "v", "sha", ["docs/BACKLOG[1].md"], tmp_path)
    assert seen[0][:2] == ["git", "--literal-pathspecs"]


def test_a_naive_timestamp_is_utc() -> None:
    assert cm.parse_stamp("2026-11-10T00:00:00").tzinfo is not None


def test_release_distance_reads_the_engine_repo(tmp_path: Path) -> None:
    seen: list[list[str]] = []

    def run(argv: Sequence[str], cwd: Path | None) -> str:
        seen.append(list(argv))
        if "ls-remote" in argv:
            return A40 + chr(9) + "refs/tags/v1.0.0"
        return "1" if "rev-list" in argv else ""

    ctx = _ctx(tmp_path, run)
    ctx.engine_repo = tmp_path / "engine"
    ctx.fetch = lambda url: json.dumps({"info": {"version": "1.0.0"}, "urls": []}).encode()
    cm.c_release_distance(ctx, cm.Metric("release_distance", "", "", "", ""))
    assert {a[2] for a in seen if a[0] == "git"} == {str(tmp_path / "engine")}


def test_asvs_from_an_archive_names_the_archived_commit(tmp_path: Path) -> None:
    printed = "# asvs-status scorecard=NO-GIT engine=NO-GIT\ncells 1: 1 pass, 0 needs-review, 0 unverified\n"
    ctx = _asvs_ctx(tmp_path, printed)
    ctx.archive_ref = "1a0c10fd3485"
    m = cm.Metric("asvs", "", "", "", "")
    cm.c_asvs(ctx, m)
    assert m.detail["engine_ref"] == "1a0c10fd3485+archive"
    assert "partial_error" not in m.detail
    assert "git archive of engine commit 1a0c10fd3485" in m.detail["tool"]


def test_asvs_ignores_an_archive_ref_that_is_no_sha(tmp_path: Path) -> None:
    printed = "# asvs-status scorecard=NO-GIT engine=NO-GIT\ncells 1: 1 pass, 0 needs-review, 0 unverified\n"
    ctx = _asvs_ctx(tmp_path, printed)
    ctx.archive_ref = "origin/main"
    m = cm.Metric("asvs", "", "", "", "")
    cm.c_asvs(ctx, m)
    assert m.detail["engine_ref"] == "NO-GIT"
    assert "no attributable ref" in m.detail["partial_error"]


def test_transient_reads_stderr_not_argv() -> None:
    # An argv token that looks transient never makes a 404 retry; the stderr decides.
    err = cm.CollectError("gh api repos/x/timeout exited 1: HTTP 404", stderr="HTTP 404: Not Found")
    assert not cm.is_transient(err)
    assert cm.is_transient(cm.CollectError("gh api x exited 1", stderr="HTTP 502 Bad Gateway"))


def test_the_real_env_probe_sees_across_mounts(monkeypatch: pytest.MonkeyPatch) -> None:
    assert (cm.run_probe, cm.run_real_probe) == cm.PROBES
    seen: list[dict[str, str] | None] = []

    def fake(argv: object, cwd: object = None, *, env: dict[str, str] | None = None) -> bytes:
        seen.append(env)
        return b""

    monkeypatch.setenv("GIT_DIR", "kept")
    monkeypatch.setattr(cm, "run_bytes", fake)
    cm.run_real_probe(["git", "status"])
    env = seen[0]
    assert env is not None and env["GIT_DISCOVERY_ACROSS_FILESYSTEM"] == "1"
    assert env["GIT_DIR"] == "kept"  # the caller's own environment, otherwise untouched


def test_fetches_name_main_only() -> None:
    assert cm.MAIN_REFSPEC == "+refs/heads/main:refs/remotes/origin/main"


# -- ledger history, burndown and forecast -------------------------------------------------------


def test_burn_history_zero_fills_and_crosses_the_year() -> None:
    weeks = {
        "2026-W52": {"filed": 2},
        "2027-W02": {"closed": 1, "declined": 1, "superseded": 1},
        cm.AFTER_THROUGH: {"filed": 9},
        "2027-W05": {"filed": 1},
    }
    hist = cm.burn_history(weeks, "2027-W02")
    # 2026 has 53 ISO weeks, so W53 sits between W52 and 2027-W01.
    assert [p["week"] for p in hist] == ["2026-W52", "2026-W53", "2027-W01", "2027-W02"]
    assert [(p["filed"], p["closed"]) for p in hist] == [(2, 0), (0, 0), (0, 0), (0, 3)]


def test_open_history_works_back_from_the_count_now() -> None:
    hist = [
        {"week": "2026-W46", "filed": 4, "closed": 3},
        {"week": "2026-W47", "filed": 1, "closed": 3},
    ]
    # 12 open now; after the window 2 filed and 1 closed, so 11 at the end of W47, 13 of W46.
    got = cm.open_history(hist, 12, {"filed": 2, "closed": 1})
    assert got == [{"week": "2026-W46", "value": 13}, {"week": "2026-W47", "value": 11}]


def test_backlog_burn_carries_the_history(tmp_path: Path) -> None:
    m = cm.Metric("backlog_burn", "", "", "", "")
    cm.c_backlog_burn(_vault_ctx(tmp_path), m)
    assert [p["week"] for p in m.detail["history"]] == ["2026-W46", "2026-W47"]
    assert m.detail["open_series"][-1] == {"week": "2026-W47", "value": 12}


def test_backlog_forecast_dates_the_finish(tmp_path: Path) -> None:
    weeks = {
        "2026-W43": {"filed": 10, "closed": 2},
        "2026-W44": {"filed": 1, "closed": 5},
        "2026-W45": {"filed": 1, "closed": 5},
        "2026-W46": {"filed": 1, "closed": 5},
        "2026-W47": {"filed": 50},
    }
    m = cm.Metric("backlog_forecast", "", "", "", "")
    # Through Wed 2026-11-18, so W46 is the last full week and W47's 50 filed rows are not read.
    cm.c_backlog_forecast(_vault_ctx(tmp_path, _census(weeks=weeks)), m)
    d = m.detail
    assert d["pace"]["weeks"] == ["2026-W43", "2026-W44", "2026-W45", "2026-W46"]
    assert d["pace"]["net_closed_per_week"] == 1.0
    assert (d["open_total"], d["weeks_to_zero"]) == (12, 12.0)
    assert m.value == d["finish"] == "2027-02-11"  # 2026-11-19 + 84 days
    assert m.status == "good"
    assert (d["short_weeks_to_zero"], d["short_finish"]) == (3.0, "2026-12-10")
    assert d["no_filing_finish"] == "2026-12-09"  # 12 / 4.25 = 2.82 weeks, 20 days


def test_backlog_forecast_says_never_when_filing_outruns_closing(tmp_path: Path) -> None:
    weeks = {f"2026-W{n}": {"filed": 9, "closed": 2} for n in (43, 44, 45, 46)}
    m = cm.Metric("backlog_forecast", "", "", "", "")
    cm.c_backlog_forecast(_vault_ctx(tmp_path, _census(weeks=weeks)), m)
    assert (m.value, m.status) == ("never at this pace", "bad")
    assert m.detail["finish"] is None and m.detail["weeks_to_zero"] is None
    assert m.detail["no_filing_finish"] == "2026-12-31"  # 12 / 2 = 6 weeks


def test_backlog_forecast_dates_from_the_pace_it_prints(tmp_path: Path) -> None:
    # A net of 1 row over 4 weeks is 0.25 a week, printed as 0.25: 12 rows take 48 weeks.
    weeks = {f"2026-W{n}": {"filed": 1, "closed": 1} for n in (43, 44, 45)}
    weeks["2026-W46"] = {"filed": 1, "closed": 2}
    m = cm.Metric("backlog_forecast", "", "", "", "")
    cm.c_backlog_forecast(_vault_ctx(tmp_path, _census(weeks=weeks)), m)
    pace = m.detail["pace"]
    assert (pace["net_closed_per_week"], pace["closed_per_week"]) == (0.25, 1.25)
    assert not any(k.endswith("_raw") for k in pace)
    assert m.detail["weeks_to_zero"] == 48.0
    assert m.detail["no_filing_weeks_to_zero"] == 9.6


def test_the_pace_windows_keep_two_places_exact() -> None:
    # A mean of whole weeks over n is a multiple of 1/n; two places hold it exactly only when n
    # divides 100. Otherwise the rounded pace the finish is dated from moves a small net by weeks.
    for n in (cm.FORECAST_WEEKS, cm.FORECAST_SHORT_WEEKS):
        assert 100 % n == 0, n


def test_backlog_forecast_refuses_a_short_history(tmp_path: Path) -> None:
    with pytest.raises(cm.CollectError, match="fewer than 4 full weeks"):
        cm.c_backlog_forecast(_vault_ctx(tmp_path), cm.Metric("x", "", "", "", ""))


@pytest.mark.parametrize(
    ("weeks", "status"),
    [(0.0, "good"), (13.0, "good"), (13.1, "warn"), (52.0, "warn"), (52.1, "bad"), (None, "bad")],
)
def test_forecast_status_bands(weeks: float | None, status: str) -> None:
    assert cm.status_forecast(weeks) == status


def test_weeks_to_zero() -> None:
    assert cm.weeks_to_zero(0, -5.0) == 0.0
    assert cm.weeks_to_zero(10, 0.0) is None
    assert cm.weeks_to_zero(10, 4.0) == 2.5


# -- the /batch runbook ----------------------------------------------------------------------------

_MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
_RELS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_PKG = "http://schemas.openxmlformats.org/package/2006/relationships"


def _xlsx(sheet_rows: str, *, tab: str = "Batch queue") -> bytes:
    """A minimal workbook: a decoy first tab, then ``tab``, whose part is named absolutely."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(
            "xl/workbook.xml",
            f'<workbook xmlns="{_MAIN}" xmlns:r="{_RELS}"><sheets>'
            '<sheet name="Other" sheetId="1" r:id="rId1"/>'
            f'<sheet name="{tab}" sheetId="2" r:id="rId2"/></sheets></workbook>',
        )
        z.writestr(
            "xl/_rels/workbook.xml.rels",
            f'<Relationships xmlns="{_PKG}">'
            '<Relationship Id="rId1" Type="x" Target="worksheets/sheet1.xml"/>'
            '<Relationship Id="rId2" Type="x" Target="/xl/worksheets/sheet2.xml"/>'
            "</Relationships>",
        )
        z.writestr(
            "xl/sharedStrings.xml",
            f'<sst xmlns="{_MAIN}"><si><t>State</t></si>'
            "<si><r><t>IN </t></r><r><t>PROGRESS</t></r></si></sst>",
        )
        z.writestr(
            "xl/worksheets/sheet1.xml", f'<worksheet xmlns="{_MAIN}"><sheetData/></worksheet>'
        )
        z.writestr(
            "xl/worksheets/sheet2.xml",
            f'<worksheet xmlns="{_MAIN}"><sheetData>{sheet_rows}</sheetData></worksheet>',
        )
    return buf.getvalue()


def _inline(ref: str, text: str) -> str:
    return f'<c r="{ref}" t="inlineStr"><is><t>{text}</t></is></c>'


_QUEUE = (
    '<row r="1">'
    + _inline("A1", "Batch")
    + '<c r="B1" t="s"><v>0</v></c>'
    + _inline("D1", "Ledger closed / rows")
    + "</row>"
    + '<row r="2"><c r="A2"><v>7</v></c><c r="B2" t="s"><v>1</v></c>'
    + _inline("D2", "2/5")
    + "</row>"
    + '<row r="3"><c r="A3"><v>8</v></c>'
    + _inline("B3", "EMPTY")
    + "</row>"
    + '<row r="4"><c r="A4"><v>9</v></c>'
    + _inline("B4", "done")
    + _inline("D4", " 3 / 3 ")
    + "</row>"
    + '<row r="5"><c r="A5"><v>10</v></c>'
    + _inline("B5", "FREE")
    + "</row>"
    + '<row r="6">'
    + _inline("B6", "FREE")
    + _inline("D6", "1/1")
    + "</row>"
)


def test_xlsx_reader_reads_shared_inline_and_numbers() -> None:
    rows = cm.xlsx_sheet_rows(_xlsx(_QUEUE), "Batch queue")
    assert rows[0] == ["Batch", "State", "", "Ledger closed / rows"]
    assert rows[1] == ["7", "IN PROGRESS", "", "2/5"]


def test_batch_census_counts_by_state_and_skips_empty() -> None:
    got = cm.batch_census(cm.xlsx_sheet_rows(_xlsx(_QUEUE), "Batch queue"))
    assert got["batches"] == {"IN PROGRESS": 1, "DONE": 1, "FREE": 1}
    assert (sum(got["rows_closed"].values()), sum(got["rows"].values())) == (5, 8)
    assert got["unread"] == ["10"]


def test_batch_progress_metric(tmp_path: Path) -> None:
    book = tmp_path / "runbook.xlsx"
    book.write_bytes(_xlsx(_QUEUE))
    ctx = _ctx(tmp_path, _failing)
    ctx.runbook = book
    m = cm.Metric("batch_progress", "", "", "", "")
    cm.c_batch_progress(ctx, m)
    assert (m.value, m.status) == (62.5, "info")
    assert m.detail["batches_total"] == 3
    assert "1 batches carry no" in m.detail["partial_error"]


@pytest.mark.parametrize(
    ("data", "match"),
    [
        (b"not a zip", "unreadable workbook"),
        (_xlsx(_QUEUE, tab="Renamed"), "no 'Batch queue' tab"),
        (_xlsx('<row r="1">' + _inline("A1", "Batch") + "</row>"), "no longer has the columns"),
        (_xlsx('<row r="1"><c r="A1" t="s"><v>9</v></c></row>'), "names no shared string"),
    ],
)
def test_batch_progress_refuses_an_unreadable_runbook(
    tmp_path: Path, data: bytes, match: str
) -> None:
    book = tmp_path / "runbook.xlsx"
    book.write_bytes(data)
    ctx = _ctx(tmp_path, _failing)
    ctx.runbook = book
    with pytest.raises(cm.CollectError, match=match):
        cm.c_batch_progress(ctx, cm.Metric("x", "", "", "", ""))


def test_batch_progress_names_a_missing_runbook(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path, _failing)
    with pytest.raises(cm.CollectError, match="no runbook path"):
        cm.c_batch_progress(ctx, cm.Metric("x", "", "", "", ""))
    ctx.runbook = tmp_path / "missing.xlsx"
    with pytest.raises(cm.CollectError, match="cannot read the runbook"):
        cm.c_batch_progress(ctx, cm.Metric("x", "", "", "", ""))


def test_default_runbook() -> None:
    env = {"MEFOR_RUNBOOK": "C:/r.xlsx", "USERPROFILE": "C:/u"}
    assert cm.default_runbook(env) == Path("C:/r.xlsx")
    assert cm.default_runbook({"USERPROFILE": "C:/u"}) == Path(
        "C:/u/OneDrive/Desktop/MEFOR/MEFOR-backlog-runbook.xlsx"
    )
    assert cm.default_runbook({}) is None


@pytest.mark.parametrize(
    "part",
    [
        "xl/workbook.xml",
        "xl/_rels/workbook.xml.rels",
        "xl/sharedStrings.xml",
        "xl/worksheets/sheet2.xml",
    ],
)
def test_the_runbook_parser_refuses_a_dtd_in_every_part(part: str) -> None:
    good = _xlsx(_QUEUE)
    assert cm.xlsx_sheet_rows(good, "Batch queue")  # the control: unaltered, it reads
    buf = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(good)) as src, zipfile.ZipFile(buf, "w") as dst:
        assert part in src.namelist()
        for name in src.namelist():
            data = src.read(name)
            if name == part:
                data = b"<!DOCTYPE x [<!ELEMENT x ANY>]>" + data
            dst.writestr(name, data)
    with pytest.raises(cm.CollectError, match="unreadable workbook: DTDForbidden"):
        cm.xlsx_sheet_rows(buf.getvalue(), "Batch queue")


def test_the_vendored_defusedxml_is_where_the_refresh_archives_it() -> None:
    assert (cm.DEFUSEDXML_DIR / "ElementTree.py").is_file()
    refresh = (_PATH.parent / "scheduled-refresh.ps1").read_text(encoding="utf-8")
    rel = cm.DEFUSEDXML_DIR.relative_to(cm.ENGINE_ROOT).as_posix()
    assert f"'{rel}'" in refresh


def test_burn_history_is_capped_at_its_maximum() -> None:
    # One mistyped year must not stretch the history across decades.
    weeks = {"0026-W45": {"filed": 1}, "2026-W47": {"filed": 2}}
    hist = cm.burn_history(weeks, "2026-W47")
    assert hist[0]["week"] == "2026-W47" and len(hist) == 1
    oldest = cm.iso_week(dt.date(2026, 11, 16) - dt.timedelta(weeks=cm.HISTORY_MAX_WEEKS - 1))
    weeks = {oldest: {"filed": 1}, "2026-W47": {"filed": 2}}
    hist = cm.burn_history(weeks, "2026-W47")
    assert len(hist) == cm.HISTORY_MAX_WEEKS and hist[0]["week"] == oldest


def test_xlsx_cells_without_a_reference_follow_the_previous_cell() -> None:
    rows = cm.xlsx_sheet_rows(
        _xlsx(
            '<row><c t="inlineStr"><is><t>a</t></is></c><c r="C1"><v>3</v></c><c><v>4</v></c></row>'
        ),
        "Batch queue",
    )
    assert rows == [["a", "", "3", "4"]]


# -- ledger rows by priority -----------------------------------------------------------------------


def _load_driver() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "dashboard_vault_census", _PATH.parent / "_vault_census.py"
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Row:
    def __init__(self, banners: list[str], *, section: int = 0, line: int = 1) -> None:
        self.line, self.body_line = line, line + 1 + len(banners)
        self.banner_lines = [(line + 1 + i, b) for i, b in enumerate(banners)]
        self.section_lines = [section] if section else []
        self.is_open = not any(b in "SDR" for b in banners)


_CHECKER = type(
    "Checker",
    (),
    {
        "SHIPPED_BANNER": "S",
        "DECLINED_BANNER": "D",
        "RETIRED_BANNER": "R",
        "IN_PROGRESS_BANNER": "I",
        "PARTIAL_LINE": __import__("re").compile(r"^> \*\*PARTIAL"),
    },
)


#: One case per return branch of ``row_status`` that names a status.
_STATUS_CASES = [
    (["O"], ["> O filed"], "open"),
    (["I", "O"], ["> I working", "> O filed"], "in progress"),
    (["I", "O"], ["> **PARTIAL 2026-10-01 built half**", "> O filed"], "partial"),
    (["S", "I"], ["> S shipped", "> **PARTIAL x**"], "closed"),
    (["D"], ["> D no"], "declined"),
    (["R"], ["> R gone"], "superseded"),
]


@pytest.mark.parametrize(("banners", "block", "status"), _STATUS_CASES)
def test_row_status_buckets_are_disjoint(banners: list[str], block: list[str], status: str) -> None:
    vc = _load_driver()
    lines = ["## 1. Title", *block, "body"]
    assert vc.row_status(_CHECKER, _Row(banners), lines) == status


def test_priority_table_columns_are_exactly_the_driver_statuses() -> None:
    # Both directions: a status the driver returns that the table has no column for, and a column
    # the driver never fills, each fail here. The cases above cover every branch that names one.
    spec = importlib.util.spec_from_file_location(
        "dashboard_to_rows_status_pin", _PATH.parent / "to_rows.py"
    )
    assert spec is not None and spec.loader is not None
    tr = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = tr
    spec.loader.exec_module(tr)
    vc = _load_driver()
    returned = {
        vc.row_status(_CHECKER, _Row(banners), ["## 1. Title", *block, "body"])
        for banners, block, _ in _STATUS_CASES
    }
    assert returned == set(tr.PRIORITY_STATUSES)


def test_row_priority_reads_the_rows_own_section_line() -> None:
    vc = _load_driver()
    lines = [
        "## 1. Title",
        "> O filed",
        "**Cluster:** Ops. **Priority:** P2. **Verdict:** build.",
        "Quotes another row: **Priority:** P1.",
    ]
    assert vc.row_priority(_Row(["O"], section=3), lines) == "P2"
    # Prose that quotes a priority is not the row's own; no section line is unscored.
    assert vc.row_priority(_Row(["O"]), lines) == vc.UNSCORED == "unscored"


def test_backlog_burn_flags_a_priority_table_that_disagrees(tmp_path: Path) -> None:
    m = cm.Metric("backlog_burn", "", "", "", "")
    # The census holds 12 open rows; this table holds 3.
    census = _census(by_priority={"P1": {"open": 2, "partial": 1, "closed": 9}})
    cm.c_backlog_burn(_vault_ctx(tmp_path, census), m)
    assert m.detail["by_priority"] == {"P1": {"open": 2, "partial": 1, "closed": 9}}
    assert "counts 3 open rows, the census 12" in m.detail["partial_error"]
    m = cm.Metric("backlog_burn", "", "", "", "")
    census = _census(by_priority={"P1": {"open": 10, "in progress": 2, "declined": 4}})
    cm.c_backlog_burn(_vault_ctx(tmp_path, census), m)
    assert "partial_error" not in m.detail
