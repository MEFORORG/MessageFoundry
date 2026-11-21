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

METRIC_KEYS = {"id", "label", "question", "value", "unit", "status", "note", "source", "error"}


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
                value=50.0,
                status="warn",
                detail={
                    "counts": {"total": 2, "pass": 1, "fail": 1},
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
    assert rows["asvs"]["note"].endswith(
        "vault origin/main abcdef012345; engine tool ref deadbeef1234."
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
    assert "flow_health.oldest_open_days" not in rows


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
    assert "origin/main unknown; engine tool ref unknown." in _rows(snap)["asvs"]["note"]
    # The older detail shape: refs read from scorecard_ref and the provenance line.
    snap["metrics"][3]["detail"] = {
        "scorecard_ref": "vault origin/main 0123456789abcdef (archived)",
        "provenance": ["# asvs-status scorecard=NO-GIT engine=feedface0000"],
    }
    assert "0123456789ab; engine tool ref feedface0000." in _rows(snap)["asvs"]["note"]


def test_series_rows() -> None:
    rows = tr.series_rows(tr.Snapshot(_snapshot()))
    assert set(rows[0]) == {"series", "week", "value", "partial"}
    names = {r["series"] for r in rows}
    assert names == {"Filed", "Closed", "Engine", "Korus", "CI pass %"}  # no vault series given
    w47 = [r for r in rows if r["week"] == "2026-W47"]
    assert w47 and all(r["partial"] for r in w47)
    assert not any(r["partial"] for r in rows if r["week"] != "2026-W47")


def test_main_writes_both_files(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cm = tr._collector()
    monkeypatch.setattr(cm, "refuse_reason", lambda out: None)
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
    cm = tr._collector()
    checked: list[Path] = []

    def refuse(out: Path) -> str:
        checked.append(out)
        return "inside a git repository"

    monkeypatch.setattr(cm, "refuse_reason", refuse)
    out = tmp_path / "new" / "dir"
    assert tr.main([str(tmp_path / "snap.json"), str(out)]) == 1
    assert not (tmp_path / "new").exists()
    assert checked == [tmp_path.resolve() / "metrics.json"]


def test_main_rejects_an_unreadable_snapshot(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(tr._collector(), "refuse_reason", lambda out: None)
    bad = tmp_path / "bad.json"
    bad.write_text("[1, 2]", encoding="utf-8")
    assert tr.main([str(bad), str(tmp_path / "o")]) == 1
    assert tr.main([str(tmp_path / "missing.json"), str(tmp_path / "o")]) == 1


def test_real_guard_refuses_this_checkout(tmp_path: Path) -> None:
    src = tmp_path / "snap.json"
    src.write_text(json.dumps(_snapshot()), encoding="utf-8")
    assert tr.main([str(src), str(Path(__file__).resolve().parent / "no-such-dir")]) == 1
    assert not (Path(__file__).resolve().parent / "no-such-dir").exists()
