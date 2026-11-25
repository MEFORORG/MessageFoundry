# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Unit tests for scripts/dashboard/render_html.py, over synthetic snapshots, written to tmp_path."""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

_PATH = Path(__file__).resolve().parents[1] / "scripts" / "dashboard" / "render_html.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("dashboard_render_html", _PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


rh = _load()

WEEKS = ["2026-W45", "2026-W46", "2026-W47"]


def _metric(mid: str, **kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": mid,
        "label": mid,
        "question": f"{mid}?",
        "value": None,
        "unit": "n",
        "status": "unknown",
        "series": None,
        "detail": {},
        "source": "src",
        "error": None,
    }
    return {**base, **kw}


def _snapshot() -> dict[str, Any]:
    pts = [{"week": w, "value": n + 1} for n, w in enumerate(WEEKS)]
    return {
        "generated_at": "2026-11-18T12:00:00+00:00",
        "through": "2026-11-18",
        "weeks": WEEKS,
        "metrics": [
            _metric(
                "backlog_burn",
                label="Backlog <burn>",
                value=1,
                status="good",
                detail={"filed_series": pts, "closed_series": pts, "open_total": 12},
            ),
            _metric(
                "prs_merged",
                value=3,
                status="bad",
                label="PRs merged",
                detail={"value_week": "2026-W46", "per_repo": {"MEFORORG/MessageFoundry": pts}},
            ),
            _metric(
                "ci_main",
                value=95.5,
                unit="percent",
                status="warn",
                series=[{"week": w, "value": 90.0} for w in WEEKS],
            ),
            _metric(
                "asvs",
                value=50.0,
                unit="percent",
                error='<script>alert("x")</script>',
                detail={
                    "counts": {
                        "total": 2,
                        "pass": 1,
                        "fail": 1,
                        "needs-review": 0,
                        "unverified": 0,
                    },
                    "scorecard_sha": "abcdef0123456789",
                    "engine_ref": "deadbeef1234",
                },
            ),
        ],
    }


def test_page_is_self_contained_and_counts_statuses() -> None:
    page = rh.render(_snapshot())
    assert page.startswith("<!doctype html>")
    # Nothing fetched from anywhere: no script, no external URL, no link element.
    assert "<script" not in page
    assert "<link" not in page
    assert not re.search(r"(?:src|href)=", page)
    assert not re.search(r"https?://", page)
    assert "prefers-color-scheme:dark" in page
    assert "4 headline metrics: 1 good, 1 warn, 1 bad, 1 with no data. Bad: PRs merged." in page
    assert page.count("<svg") == 4
    assert "95.5%" in page


def test_every_value_is_escaped() -> None:
    page = rh.render(_snapshot())
    assert "Backlog &lt;burn&gt;" in page
    assert "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;" in page
    assert '<script>alert("x")' not in page


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"metrics": None, "weeks": None},
        {"metrics": [{"id": "ci_main"}], "weeks": []},
        {"metrics": [_metric("ci_main", detail=None, series="junk")], "weeks": WEEKS},
    ],
)
def test_missing_data_renders_as_no_data(data: dict[str, Any]) -> None:
    page = rh.render(data)
    assert "no data" in page
    assert page.count("<svg") == 4


def test_null_values_are_no_data_not_zero() -> None:
    page = rh.render({"weeks": WEEKS, "metrics": [_metric("flow_health", label="Flow")]})
    tile = page[page.index("<h3>Flow") :]
    assert '<span class="big"><span class="nodata">no data</span>' in tile


def test_out_dir_resolution_order(tmp_path: Path) -> None:
    home = tmp_path / "home"
    explicit = tmp_path / "explicit"
    env = {rh.ENV_DIR: str(tmp_path / "env")}
    assert rh.resolve_out_dir(explicit, env, home) == explicit
    assert rh.resolve_out_dir(None, env, home) == tmp_path / "env"
    assert rh.resolve_out_dir(None, {}, home) == home / "MEFOR" / "dashboard"
    (home / "OneDrive" / "Desktop" / "MEFOR").mkdir(parents=True)
    want = home / "OneDrive" / "Desktop" / "MEFOR" / "dashboard"
    assert rh.resolve_out_dir(None, {}, home) == want
    assert rh.resolve_out_dir(None, {rh.ENV_DIR: ""}, home) == want  # empty is unset


def _cm() -> Any:
    return rh.cm


def test_main_writes_the_page_only(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    monkeypatch.setattr(_cm(), "refuse_dir_reason", lambda d: None)
    monkeypatch.delenv(rh.ENV_DIR, raising=False)
    src = tmp_path / "in.json"
    src.write_text(json.dumps(_snapshot()), encoding="utf-8")
    out = tmp_path / "site"
    assert rh.main([str(src), "--out-dir", str(out)]) == 0
    # The snapshot is input only: nothing but the page lands in the page folder.
    assert sorted(p.name for p in out.iterdir()) == ["index.html"]
    url = capsys.readouterr().out.strip()
    assert url == (out.resolve() / "index.html").as_uri()
    assert url.startswith("file:///")


def test_main_uses_the_env_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(_cm(), "refuse_dir_reason", lambda d: None)
    monkeypatch.setenv(rh.ENV_DIR, str(tmp_path / "envsite"))
    src = tmp_path / "in.json"
    src.write_text(json.dumps(_snapshot()), encoding="utf-8")
    assert rh.main([str(src)]) == 0
    assert (tmp_path / "envsite" / "index.html").is_file()


def test_main_refuses_inside_a_work_tree(tmp_path: Path) -> None:
    src = tmp_path / "in.json"
    src.write_text(json.dumps(_snapshot()), encoding="utf-8")
    inside = Path(__file__).resolve().parent / "no-such-dashboard-dir"
    assert rh.main([str(src), "--out-dir", str(inside)]) == 1
    assert not inside.exists()
    reason = _cm().refuse_dir_reason(Path(__file__).resolve().parent)
    assert reason is not None and "rev-parse said 'true'" in reason


def test_main_rejects_a_bad_snapshot(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(_cm(), "refuse_dir_reason", lambda d: None)
    bad = tmp_path / "bad.json"
    bad.write_text("[]", encoding="utf-8")
    assert rh.main([str(bad), "--out-dir", str(tmp_path / "o")]) == 1
    assert rh.main([str(tmp_path / "nope.json"), "--out-dir", str(tmp_path / "o")]) == 1
    assert not (tmp_path / "o").exists()


def test_the_asvs_ref_pair_sits_beside_its_value() -> None:
    page = rh.render(_snapshot())
    tile = page[page.index("<h3>asvs") :]
    tile = tile[: tile.index("</section>")]
    pair = "scorecard=vault-origin-main@abcdef0123456789 engine=deadbeef1234"
    assert '<span class="big">50%</span></div><dl>' in tile
    # The pair is on the tile's face, beside the value, and in full inside the disclosure.
    assert f'<summary>Measured at <span class="mono">{pair}</span></summary>' in tile
    assert f'<p class="mono">{pair}</p>' in tile
    # The headline's unexamined counts sit in the same tile.
    assert "<dt>Needs review</dt><dd>0</dd>" in tile
    assert "<dt>Unverified</dt><dd>0</dd>" in tile


def test_the_asvs_headline_is_withheld_without_no_verdict_counts() -> None:
    snap = _snapshot()
    snap["metrics"][3]["detail"]["counts"] = {"total": 2, "pass": 1, "fail": 1}
    snap["metrics"][3]["error"] = None  # withholding applies to a metric that read without error
    page = rh.render(snap)
    tile = page[page.index("<h3>asvs") :]
    tile = tile[: tile.index("</section>")]
    assert '<span class="big"><span class="nodata">no data</span></span>' in tile


def test_print_out_dir_refuses_a_work_tree(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    inside = Path(__file__).resolve().parent / "no-such-dashboard-dir"
    assert rh.main(["--print-out-dir", "--out-dir", str(inside)]) == 1
    assert capsys.readouterr().out == ""
    monkeypatch.setattr(rh.cm, "refuse_dir_reason", lambda d: None)
    assert rh.main(["--print-out-dir", "--out-dir", str(tmp_path / "x")]) == 0
    assert capsys.readouterr().out.strip() == str((tmp_path / "x").resolve())
    assert not (tmp_path / "x").exists()  # nothing written


@pytest.mark.parametrize(
    ("value", "shown"),
    [
        (float("inf"), "no data"),
        (float("nan"), "no data"),
        (0.04, "0.04"),
        (-0.04, "-0.04"),
        (2.0, "2"),
    ],
)
def test_fmt_never_raises_or_shows_a_nonzero_as_zero(value: float, shown: str) -> None:
    assert shown in rh.fmt(value)


def test_an_overflowing_number_renders() -> None:
    snap = {"weeks": WEEKS, "metrics": [_metric("ci_main", value=float("inf"))]}
    assert "no data" in rh.render(snap)


# -- the page's newer parts --------------------------------------------------------------------


def _history_snapshot(n: int) -> dict[str, Any]:
    snap = _snapshot()
    weeks = [f"2026-W{w:02d}" for w in range(48 - n, 48)]
    hist = [{"week": w, "filed": 2400 if i == 0 else 60, "closed": 90} for i, w in enumerate(weeks)]
    snap["metrics"][0]["detail"]["history"] = hist
    snap["metrics"][0]["detail"]["open_series"] = [
        {"week": w, "value": 5000 - i} for i, w in enumerate(weeks)
    ]
    return snap


def test_the_update_time_is_central_and_leads_the_page() -> None:
    page = rh.render(_snapshot())
    stamp = '<p class="stamp">Updated Wed Nov 18, 2026, 6:00 AM CST <span>(12:00 UTC)</span></p>'
    assert stamp in page
    assert page.index(stamp) < page.index('<div class="tiles">')
    assert "Generated at" not in page


def test_an_unreadable_update_time_says_so() -> None:
    snap = _snapshot()
    snap["generated_at"] = "not a time"
    assert "update time unknown" in rh.render(snap)


def test_ledger_ranges_draw_every_range_and_check_13_weeks() -> None:
    page = rh.render(_history_snapshot(30))
    for key in ("4", "8", "13", "26", "all"):
        assert f'id="rg-{key}"' in page
        assert f'<div class="rv rv-{key}">' in page
        assert f"#rg-{key}:checked~.charts .rv-{key}{{display:block}}" in page
    assert 'id="rg-52"' not in page  # longer than the history
    assert '<input class="rg" type="radio" name="range" id="rg-13" checked>' in page
    assert "All (30)" in page
    # Five ranges, two ledger charts each, plus the PR and CI charts; still no script.
    assert page.count("<svg") == 12
    assert "<script" not in page


def test_the_ledger_chart_uses_a_log_axis() -> None:
    page = rh.render(_history_snapshot(30))
    view = page[page.index('<div class="rv rv-all">') :]
    view = view[: view.index("</svg>")]
    labels = re.findall(r'text-anchor="end">([^<]+)</text>', view)
    assert labels == ["0", "10", "100", "1k", "10k"]
    # On a log axis 60 sits well above the floor beside 2,400.
    assert "Filed 2026-W18: 2,400" in view


def test_log_axis_places_powers_of_ten_evenly() -> None:
    axis = rh.Axis(2443, log=True)
    assert axis.top == 10_000
    fracs = [f for f, _ in axis.ticks()]
    assert fracs[0] == 0.0
    steps = [b - a for a, b in zip(fracs[1:], fracs[2:], strict=False)]
    assert max(steps) - min(steps) < 0.01


def test_a_long_range_thins_its_week_labels() -> None:
    weeks = [f"2026-W{w:02d}" for w in range(1, 41)]
    svg = rh.line_chart("t", weeks, [("x", "s1", dict.fromkeys(weeks, 1))], set())
    shown = re.findall(r'text-anchor="middle">(W\d+)</text>', svg)
    assert len(shown) <= rh.MAX_X_LABELS
    assert shown[-1] == "W40"


def test_the_burndown_says_when_the_ledger_empties() -> None:
    snap = _history_snapshot(10)
    snap["metrics"].append(
        _metric(
            "backlog_forecast",
            value="2027-02-11",
            status="good",
            detail={"pace": {"net_closed_per_week": 30.0}, "finish": "2027-02-11"},
        )
    )
    page = rh.render(snap)
    assert "<h2>Backlog burndown</h2>" in page
    assert "it reaches zero about 2027-02-11" in page


def test_asvs_tool_provenance_is_in_the_disclosure_not_the_facts() -> None:
    snap = _snapshot()
    snap["metrics"][3]["detail"]["provenance"] = ["# asvs-status scorecard=NO-GIT", "# generated=x"]
    page = rh.render(snap)
    tile = page[page.index("<h3>asvs") :]
    tile = tile[: tile.index("</section>")]
    assert "<dt>Tool provenance</dt>" not in tile
    face, disclosure = tile.split('<details class="how">')
    # The header line, with its ref pair, is part of the measurement: on the face, not hidden.
    assert '<p class="mono"># asvs-status scorecard=NO-GIT</p>' in face
    assert "# asvs-status" not in disclosure
    assert '<p class="mono"># generated=x</p>' in disclosure


def test_short_pair_cuts_full_commits() -> None:
    full = "a" * 40
    assert rh.short_pair(f"scorecard=vault@{full} engine={full}+archive") == (
        "scorecard=vault@aaaaaaa engine=aaaaaaa+archive"
    )


def test_an_info_status_is_a_progress_pill() -> None:
    snap = _snapshot()
    snap["metrics"].append(_metric("batch_progress", value=11.8, unit="percent", status="info"))
    page = rh.render(snap)
    assert '<span class="pill info">info</span>' in page
    assert "1 progress only" in page


def test_the_burndown_note_counts_the_undated_rows() -> None:
    snap = _history_snapshot(10)
    snap["metrics"][0]["detail"]["undated"] = {"filed": 879}
    page = rh.render(snap)
    card = page[page.index("<h2>Backlog burndown</h2>") :]
    assert (
        "Rows with no readable filing date (879) are never removed going back, so early weeks "
        "overstate the open count by up to that many." in card[: card.index("</section>")]
    )


def test_a_burndown_with_no_open_series_says_no_data() -> None:
    page = rh.render(_snapshot())
    card = page[page.index("<h2>Backlog burndown</h2>") :]
    assert '<p class="nodata">no data</p>' in card[: card.index("</section>")]


def test_provenance_lines_keep_their_own_semicolons() -> None:
    snap = _snapshot()
    snap["metrics"][3]["detail"]["provenance"] = ["# engine: freshness=STALE; behind=3"]
    page = rh.render(snap)
    assert "# engine: freshness=STALE; behind=3</p>" in page


def test_missing_asvs_provenance_is_said_on_the_tile() -> None:
    snap = _snapshot()
    snap["metrics"][3]["error"] = None
    page = rh.render(snap)
    tile = page[page.index("<h3>asvs") :]
    tile = tile[: tile.index("</section>")]
    assert '<p class="err">the snapshot holds no scorecard provenance lines</p>' in tile
    snap["metrics"][3]["detail"]["provenance"] = ["# asvs-status scorecard=x engine=y"]
    tile = rh.render(snap)
    assert "holds no scorecard provenance lines" not in tile


@pytest.mark.parametrize("bad", ["many", float("inf"), 2.0, True, None])
def test_a_malformed_batch_count_renders_no_data(bad: Any) -> None:
    snap = _snapshot()
    by = {"X": bad, "FREE": bad, "DONE": 4}
    snap["metrics"].append(_metric("batch_progress", value=1.0, detail={"batches_by_state": by}))
    page = rh.render(snap)
    nodata = '<dd><span class="nodata">no data</span></dd>'
    assert f"<dt>Other state</dt>{nodata}" in page
    assert f"<dt>Free</dt>{nodata}" in page
    assert "<dt>Done</dt><dd>4</dd>" in page
    assert "<dt>Built</dt><dd>0</dd>" in page  # absent from the map: a real zero


def test_missing_asvs_provenance_is_said_beside_another_error() -> None:
    snap = _snapshot()
    snap["metrics"][3]["error"] = "the tool timed out"
    page = rh.render(snap)
    tile = page[page.index("<h3>asvs") :]
    tile = tile[: tile.index("</section>")]
    assert (
        '<p class="err">the tool timed out; the snapshot holds no scorecard provenance lines</p>'
        in tile
    )


def test_the_priority_table_has_totals_and_every_status() -> None:
    snap = _snapshot()
    snap["metrics"][0]["detail"]["by_priority"] = {
        "P1": {"open": 2, "closed": 3},
        "unscored": {"partial": 1, "declined": 1},
    }
    page = rh.render(snap)
    table = page[page.index('<table class="prio">') : page.index("</table>")]
    heads = re.findall(r"<th>([^<]+)</th>", table[: table.index("</thead>")])
    assert heads == [
        "Priority",
        "Open",
        "Partial",
        "In progress",
        "Closed",
        "Declined",
        "Superseded",
        "Total",
    ]
    assert (
        "<tr><th>P1</th><td>2</td><td>0</td><td>0</td><td>3</td><td>0</td><td>0</td><td>5</td></tr>"
        in table
    )
    assert "<th>Unscored</th>" in table
    assert (
        '<tr class="sum"><th>Total</th><td>2</td><td>1</td><td>0</td><td>3</td><td>1</td><td>0</td><td>7</td></tr>'
        in table
    )
    # The table sits above the charts.
    assert page.index("Ledger rows by priority") < page.index("Ledger range")


def test_a_snapshot_without_a_priority_census_says_no_data() -> None:
    assert "no data: the snapshot holds no priority census" in rh.render(_snapshot())
