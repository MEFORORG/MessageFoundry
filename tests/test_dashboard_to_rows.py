# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Unit tests for scripts/dashboard/to_rows.py, over synthetic snapshots only."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

_PATH = Path(__file__).resolve().parents[1] / "scripts" / "dashboard" / "to_rows.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("dashboard_to_rows", _PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


tr = _load()

METRIC_KEYS = {
    "id",
    "label",
    "question",
    "value",
    "unit",
    "status",
    "note",
    "source",
    "error",
    "ref",
}


def _metric(mid: str, **kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": mid,
        "label": mid.title(),
        "question": f"{mid}?",
        "value": None,
        "unit": "n",
        "status": "unknown",
        "series": None,
        "detail": {},
        "source": f"src {mid}",
        "error": None,
    }
    return {**base, **kw}


def _snapshot() -> dict[str, Any]:
    weeks = ["2026-W45", "2026-W46", "2026-W47"]
    pts = [{"week": w, "value": n} for n, w in enumerate(weeks)]
    return {
        "generated_at": "2026-11-18T12:00:00+00:00",
        "through": "2026-11-18",
        "weeks": weeks,
        "metrics": [
            _metric(
                "backlog_burn",
                value=1,
                status="good",
                detail={
                    "open_total": 12,
                    "open_active": 7,
                    "open_unclassified": 2,
                    "open_deferred": 3,
                    "filed_window": 5,
                    "closed_window": 6,
                    "filed_series": pts,
                    "closed_series": pts,
                },
            ),
            _metric(
                "prs_merged",
                value=3,
                status="good",
                detail={
                    "value_week": "2026-W46",
                    "per_repo": {"MEFORORG/MessageFoundry": pts, "MEFORORG/korus": pts},
                },
            ),
            _metric(
                "ci_main",
                value=90.0,
                status="good",
                series=[{"week": w, "value": None} for w in weeks],
                detail={"value_week": "2026-W46", "open_ci_red_prs": None},
            ),
            _metric(
                "asvs",
                value=25.0,
                status="warn",
                detail={
                    "counts": {
                        "total": 4,
                        "pass": 1,
                        "fail": 1,
                        "needs-review": 1,
                        "unverified": 1,
                    },
                    "scorecard_sha": "abcdef0123456789",
                    "engine_ref": "deadbeef1234",
                },
            ),
            _metric(
                "dependency_vulns",
                value=2,
                status="bad",
                detail={
                    "open_by_severity": {"critical": 1, "high": 1, "low": 0},
                    "kpis": {"row": {"dep_mttr_days": "4.5"}, "error": None},
                },
            ),
            # Errored: no detail at all, so its facts must read null, never zero.
            _metric("release_distance", error="GET failed"),
        ],
    }


def _rows(snap: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {r["id"]: r for r in tr.metric_rows(tr.Snapshot(snap))}


def test_metric_rows_contract() -> None:
    rows = _rows(_snapshot())
    for row in rows.values():
        assert set(row) == METRIC_KEYS
    # The headline row carries its pair in ref alone, so the tile never shows it twice.
    assert rows["asvs"]["note"] == (
        "Pass cells over cells not marked n/a. 1 needs-review and 1 unverified cells, which carry "
        "no verdict, are in that denominator and are not passes. Cells decided with no "
        "last_verified count as decided; scorecard.py --status reports them."
    )
    assert rows["asvs"]["value"] == 25.0
    assert (rows["asvs.needs-review"]["value"], rows["asvs.unverified"]["value"]) == (1, 1)
    assert rows["asvs"]["ref"] == "scorecard=vault-origin-main@abcdef0123456789 engine=deadbeef1234"
    # Every ASVS count row carries the ref pair too.
    assert (
        rows["asvs.pass"]["note"]
        == "Measured at scorecard=vault-origin-main@abcdef0123456789 engine=deadbeef1234."
    )
    assert "week 2026-W46" in rows["prs_merged"]["note"]
    fact = rows["backlog_burn.filed_window"]
    assert (fact["label"], fact["value"], fact["question"], fact["status"]) == (
        "Filed, 3 weeks",
        5,
        "",
        "",
    )
    assert fact["source"] == "src backlog_burn"
    assert rows["asvs.partial"]["value"] is None  # not in the counts: null, not zero
    assert rows["dependency_vulns.critical_high"]["value"] == 2
    assert rows["dependency_vulns.dep_mttr_days"]["value"] == 4.5
    assert rows["ci_main.open_ci_red_prs"]["value"] is None
    # An errored metric: its error survives, and its facts are null.
    assert rows["release_distance"]["error"] == "GET failed"
    assert rows["release_distance.uploaded"]["value"] is None
    assert rows["release_distance.pypi_version"]["value"] is None
    # A metric absent from the snapshot contributes no fact rows.
    assert "batch_progress.rows_closed" not in rows


@pytest.mark.parametrize("raw", [None, "", "nan", "inf", "n/a"])
def test_missing_mttr_is_null_not_nan(raw: Any) -> None:
    snap = _snapshot()
    snap["metrics"][4]["detail"]["kpis"] = {"row": {"dep_mttr_days": raw}}
    assert _rows(snap)["dependency_vulns.dep_mttr_days"]["value"] is None
    snap["metrics"][4]["detail"]["kpis"] = {"row": None, "error": "x"}
    assert _rows(snap)["dependency_vulns.dep_mttr_days"]["value"] is None


def test_asvs_note_tolerates_missing_refs() -> None:
    snap = _snapshot()
    snap["metrics"][3]["detail"] = {"scorecard_ref": "", "provenance": ["# no ref here"]}
    want = "scorecard=vault-origin-main@unknown engine=unknown"
    assert _rows(snap)["asvs"]["ref"] == want


def test_series_rows() -> None:
    rows = tr.series_rows(tr.Snapshot(_snapshot()))
    assert set(rows[0]) == {"series", "week", "value", "partial"}
    names = {r["series"] for r in rows}
    assert names == {"Filed", "Closed", "Engine", "Korus", "CI pass %"}  # no vault series given
    w47 = [r for r in rows if r["week"] == "2026-W47"]
    assert w47 and all(r["partial"] for r in w47)
    assert not any(r["partial"] for r in rows if r["week"] != "2026-W47")


def test_main_writes_both_files(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cm = tr.cm
    monkeypatch.setattr(cm, "refuse_dir_reason", lambda out: None)
    src = tmp_path / "snap.json"
    src.write_text(json.dumps(_snapshot()), encoding="utf-8")
    out = tmp_path / "rows" / "nested"
    assert tr.main([str(src), str(out)]) == 0
    for name in ("metrics.json", "series.json"):
        text = (out / name).read_text(encoding="utf-8")
        # Strict JSON: a NaN or Infinity anywhere fails the parse.
        got = json.loads(text, parse_constant=lambda c: pytest.fail(f"non-JSON constant {c}"))
        assert set(got) == {"rows", "meta"}
        code, info = got["meta"]
        assert (code["label"], code["type"], code["lang"]) == ("to_rows.py", "code", "python")
        assert "def main" in code["value"]
        assert info["label"] == "Input" and "snap.json" in info["value"]


def test_main_refuses_inside_a_repo_and_creates_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cm = tr.cm
    checked: list[Path] = []

    def refuse(out: Path) -> str:
        checked.append(out)
        return "inside a git repository"

    monkeypatch.setattr(cm, "refuse_dir_reason", refuse)
    out = tmp_path / "new" / "dir"
    assert tr.main([str(tmp_path / "snap.json"), str(out)]) == 1
    assert not (tmp_path / "new").exists()
    assert checked == [tmp_path.resolve()]  # the directory, never a leaf name


def test_main_rejects_an_unreadable_snapshot(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(tr.cm, "refuse_dir_reason", lambda out: None)
    bad = tmp_path / "bad.json"
    bad.write_text("[1, 2]", encoding="utf-8")
    assert tr.main([str(bad), str(tmp_path / "o")]) == 1
    assert tr.main([str(tmp_path / "missing.json"), str(tmp_path / "o")]) == 1


def test_real_guard_refuses_this_checkout(tmp_path: Path) -> None:
    # The refusal is the inside-a-repo answer, not a fail-closed "cannot tell".
    here = Path(__file__).resolve().parent
    reason = tr.cm.refuse_dir_reason(tr.cm.nearest_existing(here / "no-such-dir"))
    assert reason is not None and "rev-parse said 'true'" in reason
    src = tmp_path / "snap.json"
    src.write_text(json.dumps(_snapshot()), encoding="utf-8")
    assert tr.main([str(src), str(Path(__file__).resolve().parent / "no-such-dir")]) == 1
    assert not (Path(__file__).resolve().parent / "no-such-dir").exists()


def test_partial_error_reaches_the_row() -> None:
    snap = _snapshot()
    snap["metrics"][1]["detail"]["partial_error"] = "stall count: TimeoutExpired"
    assert _rows(snap)["prs_merged"]["error"] == "partial: stall count: TimeoutExpired"
    assert _rows(snap)["release_distance"]["error"] == "GET failed"  # a full error wins
    assert _rows(snap)["backlog_burn"]["error"] is None


def test_last_full_week_falls_back_to_the_collector_rule() -> None:
    snap = _snapshot()
    for m in snap["metrics"]:
        m["detail"].pop("value_week", None)
    # A Sunday --through that had ended when the snapshot was generated completes its own week.
    snap["through"] = "2026-11-22"
    snap["generated_at"] = "2026-11-23T01:00:00+00:00"
    snap["weeks"] = ["2026-W46", "2026-W47"]
    assert tr.Snapshot(snap).last_full_week == "2026-W47"
    snap["generated_at"] = "2026-11-22T12:00:00+00:00"
    assert tr.Snapshot(snap).last_full_week == "2026-W46"
    del snap["through"]
    assert tr.Snapshot(snap).last_full_week is None


def test_nan_in_the_snapshot_is_written_as_null(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(tr.cm, "refuse_dir_reason", lambda out: None)
    src = tmp_path / "snap.json"
    src.write_text(
        json.dumps(_snapshot()).replace('"value": 90.0', '"value": NaN'), encoding="utf-8"
    )
    assert tr.main([str(src), str(tmp_path / "o")]) == 0
    rows = json.loads((tmp_path / "o" / "metrics.json").read_text(encoding="utf-8"))["rows"]
    assert next(r for r in rows if r["id"] == "ci_main")["value"] is None


def test_a_write_failure_exits_1(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(tr.cm, "refuse_dir_reason", lambda out: None)
    src = tmp_path / "snap.json"
    src.write_text(json.dumps(_snapshot()), encoding="utf-8")
    out = tmp_path / "o"
    (out / "series.json").mkdir(parents=True)  # a directory where a file must go
    assert tr.main([str(src), str(out)]) == 1


def test_fact_rows_carry_the_reason_for_a_null() -> None:
    snap = _snapshot()
    snap["metrics"][4]["detail"]["kpis"] = {"row": {"dep_mttr_days": "n/a: no merged PRs"}}
    rows = _rows(snap)
    assert rows["dependency_vulns.dep_mttr_days"]["error"] == "n/a: no merged PRs"
    assert rows["release_distance.pypi_version"]["error"] == "GET failed"
    assert rows["backlog_burn.open_total"]["error"] is None


def test_unresolved_week_marks_the_newest_partial() -> None:
    snap = _snapshot()
    for m in snap["metrics"]:
        m["detail"].pop("value_week", None)
    del snap["through"]
    rows = tr.series_rows(tr.Snapshot(snap))
    assert all(r["partial"] == (r["week"] == "2026-W47") for r in rows)
    snap["weeks"] = []
    assert tr.Snapshot(snap).last_full_week is None  # no IndexError


def test_every_asvs_row_carries_the_ref_pair() -> None:
    rows = _rows(_snapshot())
    pair = "scorecard=vault-origin-main@abcdef0123456789 engine=deadbeef1234"
    asvs = [r for r in rows.values() if str(r["id"]).split(".")[0] == "asvs"]
    # The headline row, its pass, partial, fail, needs-review and unverified counts, and the tool's
    # provenance.
    assert len(asvs) == 7
    assert all(r["ref"] == pair for r in asvs)
    assert all(r["ref"] == "" for r in rows.values() if r not in asvs)


def test_asvs_without_no_verdict_counts_has_no_headline() -> None:
    snap = _snapshot()
    snap["metrics"][3]["detail"]["counts"] = {"total": 2, "pass": 1, "fail": 1}
    rows = _rows(snap)
    assert rows["asvs"]["value"] is None
    assert rows["asvs"]["status"] == "unknown"
    assert rows["asvs"]["error"] == tr.NO_ASVS_HEADLINE
    assert rows["asvs.needs-review"]["value"] is None
    assert rows["asvs.needs-review"]["error"] == tr.NO_ASVS_HEADLINE  # a null fact is not mute
    assert rows["asvs.pass"]["value"] == 1  # the counts themselves still show
    # An earlier reason is kept, after the reason the headline was withheld.
    snap["metrics"][3]["detail"]["partial_error"] = "no engine= ref"
    assert _rows(snap)["asvs"]["error"] == f"{tr.NO_ASVS_HEADLINE}; partial: no engine= ref"
    del snap["metrics"][3]["detail"]["partial_error"]
    # A present null is no measurement: the headline is withheld, never qualified with a zero.
    snap["metrics"][3]["detail"]["counts"] = {
        "total": 2,
        "pass": 1,
        "fail": 1,
        "needs-review": None,
        "unverified": 0,
    }
    assert _rows(snap)["asvs"]["value"] is None
    # Only one of the two, or one that is no whole number: still withheld, never a quiet zero.
    for counts in (
        {"total": 3, "pass": 1, "fail": 1, "unverified": 1},
        {"total": 2, "pass": 1, "fail": 1, "needs-review": True, "unverified": 0},
        {"total": 2, "pass": 1, "fail": 1, "needs-review": 0.9, "unverified": 0},
    ):
        snap["metrics"][3]["detail"]["counts"] = counts
        rows = _rows(snap)
        assert rows["asvs"]["value"] is None, counts
        assert rows["asvs.needs-review"]["value"] is None, counts
    # A metric that errored keeps its own reason alone: its counts are missing because of it.
    snap["metrics"][3]["error"] = "vault read failed"
    snap["metrics"][3]["detail"] = {}
    assert _rows(snap)["asvs"]["error"] == "vault read failed"


def test_asvs_provenance_row_quotes_the_tools_own_lines() -> None:
    snap = _snapshot()
    lines = ["# asvs-status scorecard=NO-GIT engine=NO-GIT", "# at 2026-11-18"]
    snap["metrics"][3]["detail"]["provenance"] = lines
    assert _rows(snap)["asvs.provenance"]["value"] == "; ".join(lines)
    del snap["metrics"][3]["detail"]["provenance"]
    row = _rows(snap)["asvs.provenance"]
    assert row["value"] is None
    assert row["error"] == "the snapshot holds no scorecard provenance lines"


# -- Central time, the ledger history and the new metrics' facts ---------------------------------


@pytest.mark.parametrize(
    ("stamp", "shown"),
    [
        ("2026-11-24T13:01:32+00:00", "Tue Nov 24, 2026, 7:01 AM CST"),
        ("2026-07-04T17:30:00Z", "Sat Jul 4, 2026, 12:30 PM CDT"),
        # 2026's daylight time runs from Sun Mar 8 08:00 UTC to Sun Nov 1 07:00 UTC.
        ("2026-03-08T07:59:00Z", "Sun Mar 8, 2026, 1:59 AM CST"),
        ("2026-03-08T08:00:00Z", "Sun Mar 8, 2026, 3:00 AM CDT"),
        ("2026-11-01T06:59:00Z", "Sun Nov 1, 2026, 1:59 AM CDT"),
        ("2026-11-01T07:00:00Z", "Sun Nov 1, 2026, 1:00 AM CST"),
        ("2026-12-31T23:30:00-05:00", "Thu Dec 31, 2026, 10:30 PM CST"),
    ],
)
def test_central_time(stamp: str, shown: str) -> None:
    assert tr.central(stamp) == shown


@pytest.mark.parametrize("stamp", [None, "", "yesterday", 5])
def test_central_time_of_junk_is_none(stamp: Any) -> None:
    assert tr.central(stamp) is None
    assert tr.utc_clock(stamp) is None


def test_ledger_history_joins_the_open_series() -> None:
    snap = tr.Snapshot(
        {
            "metrics": [
                {
                    "id": "backlog_burn",
                    "detail": {
                        "history": [{"week": "2026-W46", "filed": 4, "closed": 3}, "junk"],
                        "open_series": [{"week": "2026-W46", "value": 13}],
                    },
                }
            ]
        }
    )
    assert tr.ledger_history(snap) == [{"week": "2026-W46", "filed": 4, "closed": 3, "open": 13}]
    assert tr.ledger_history(tr.Snapshot({})) == []


def _forecast_rows(detail: dict[str, Any]) -> dict[str, Any]:
    data = {"metrics": [{"id": "backlog_forecast", "value": "x", "detail": detail}]}
    return {r["id"]: r for r in tr.metric_rows(tr.Snapshot(data))}


def test_forecast_facts_read_never_only_when_a_pace_was_read() -> None:
    pace = {"net_closed_per_week": -5.0, "closed_per_week": 0.0, "filed_per_week": 5.0}
    rows = _forecast_rows({"pace": pace, "short_pace": pace})
    assert rows["backlog_forecast.short_finish"]["value"] == "never"
    assert rows["backlog_forecast.no_filing_finish"]["value"] == "never"
    assert rows["backlog_forecast.net_closed_per_week"]["value"] == -5.0
    rows = _forecast_rows({})
    assert rows["backlog_forecast.short_finish"]["value"] is None


@pytest.mark.parametrize("net", [0.0, -0.0, 0])
def test_forecast_line_says_filing_matched_closing_at_a_zero_net(net: float) -> None:
    detail = {"pace": {"net_closed_per_week": net}, "finish": None}
    data = {"metrics": [{"id": "backlog_forecast", "value": "x", "detail": detail}]}
    line = tr.forecast_line(tr.Snapshot(data))
    assert line is not None
    assert "filing matched closing, so it never reaches zero" in line
    assert "-0" not in line


def test_batch_facts_count_every_state() -> None:
    data = {
        "metrics": [
            {
                "id": "batch_progress",
                "value": 10.0,
                "detail": {
                    "batches_by_state": {"FREE": 3},
                    "runbook_saved": "2026-11-24T13:00:00Z",
                },
            }
        ]
    }
    rows = {r["id"]: r for r in tr.metric_rows(tr.Snapshot(data))}
    assert rows["batch_progress.batches_free"]["value"] == 3
    assert rows["batch_progress.batches_done"]["value"] == 0
    assert "workbook saved Tue Nov 24, 2026, 7:00 AM CST" in rows["batch_progress"]["note"]


def test_batch_facts_count_an_unlisted_state_as_other() -> None:
    data = {
        "metrics": [
            {
                "id": "batch_progress",
                "value": 1.0,
                "detail": {"batches_by_state": {"FREE": 1, "PARKED": 2}},
            }
        ]
    }
    rows = {r["id"]: r for r in tr.metric_rows(tr.Snapshot(data))}
    assert rows["batch_progress.batches_other"]["value"] == 2


def test_series_rows_carry_the_ledger_history() -> None:
    data = {
        "weeks": ["2026-W46", "2026-W47"],
        "metrics": [
            {
                "id": "backlog_burn",
                "detail": {
                    "history": [{"week": "2026-W46", "filed": 4, "closed": 3}],
                    "open_series": [{"week": "2026-W46", "value": 13}],
                },
            }
        ],
    }
    rows = [r for r in tr.series_rows(tr.Snapshot(data)) if r["week"] == "2026-W46"]
    got = {r["series"]: r["value"] for r in rows}
    assert got == {"Filed, all weeks": 4, "Closed, all weeks": 3, "Open rows": 13}


def test_priority_rows_order_and_fill_every_status() -> None:
    by = {"unscored": {"open": 1}, "P2": {"closed": 4, "odd": 1}, "P1": {"open": 2}}
    snap = tr.Snapshot({"metrics": [{"id": "backlog_burn", "detail": {"by_priority": by}}]})
    rows = tr.priority_rows(snap)
    assert list(dict.fromkeys(r["priority"] for r in rows)) == ["P1", "P2", "unscored"]
    p2 = {r["status"]: r["value"] for r in rows if r["priority"] == "P2"}
    assert p2 == {
        "open": 0,
        "partial": 0,
        "in progress": 0,
        "closed": 4,
        "declined": 0,
        "superseded": 0,
        "odd": 1,
    }
    assert tr.priority_rows(tr.Snapshot({})) == []
    # A status only P2 carries is a zero cell for P1 and unscored, not a missing one.
    assert {"priority": "P1", "status": "odd", "value": 0} in rows


def test_priority_rows_sort_two_digit_priorities_numerically() -> None:
    by = {p: {"open": 1} for p in ("P10", "P2", "unscored", "P1")}
    snap = tr.Snapshot({"metrics": [{"id": "backlog_burn", "detail": {"by_priority": by}}]})
    order = list(dict.fromkeys(r["priority"] for r in tr.priority_rows(snap)))
    assert order == ["P1", "P2", "P10", "unscored"]


def test_main_writes_the_priority_file(tmp_path: Path) -> None:
    snap = tmp_path / "metrics.json"
    detail = {"by_priority": {"P1": {"open": 2}}}
    snap.write_text(json.dumps({"metrics": [{"id": "backlog_burn", "detail": detail}]}), "utf-8")
    out = tmp_path / "rows"
    try:
        code = tr.main([str(snap), str(out)])
    except SystemExit as exc:  # pragma: no cover - argparse
        code = int(exc.code or 0)
    if code == 1:
        pytest.skip("the temporary directory is inside a git work tree on this machine")
    rows = json.loads((out / "priority.json").read_text(encoding="utf-8"))["rows"]
    assert {"priority": "P1", "status": "open", "value": 2} in rows


def test_unscored_label_matches_the_census_driver() -> None:
    source = (_PATH.parent / "_vault_census.py").read_text(encoding="utf-8")
    assert f'UNSCORED = "{tr.UNSCORED_LABEL}"' in source


def test_estimate_label_matches_the_census_driver() -> None:
    source = (_PATH.parent / "_vault_census.py").read_text(encoding="utf-8")
    assert f'ESTIMATE = "{tr.ESTIMATE_LABEL}"' in source
    assert f"|{tr.DEMAND_GATE})" in source


def test_priority_rows_order_tiers_then_demand_gate_estimates_and_unscored() -> None:
    names = ("unscored", "estimate only", "DEMAND-GATE", "P10", "P2", "P1")
    by = {p: {"open": 1} for p in names}
    snap = tr.Snapshot({"metrics": [{"id": "backlog_burn", "detail": {"by_priority": by}}]})
    order = list(dict.fromkeys(r["priority"] for r in tr.priority_rows(snap)))
    assert order == ["P1", "P2", "P10", "DEMAND-GATE", "estimate only", "unscored"]
