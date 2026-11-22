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
    assert page.count("<svg") == 3
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
    assert page.count("<svg") == 3


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
    assert f'<p class="refpair">Collector ref pair: {pair}</p>' in tile
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
