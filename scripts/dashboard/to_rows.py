#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Flatten a ``collect_metrics.py`` snapshot into the dashboard's two row files.

WRITES ``<out>/metrics.json`` (one row per headline metric, then one per fact) and
``<out>/series.json`` (one row per series per ISO week). Each file is ``{"rows": [...], "meta":
[...]}``, and ``meta`` carries this converter's own source and the snapshot it read.

THE ROWS ARE AS PRIVATE AS THE SNAPSHOT: they quote the same vault counts. ``--out`` is refused
inside a git work tree with the collector's own guard (``refuse_reason``).

A VALUE THAT IS NOT IN THE SNAPSHOT IS ``null``, never ``0`` or NaN: a metric that errored has no
detail, and its facts read null rather than as a quiet zero.

EXIT STATUS. 0 when both files were written; 1 when nothing was (a refused ``--out``, an unreadable
snapshot); 2 is argparse's own usage error.

Usage::

    python scripts/dashboard/to_rows.py C:/outside/any/repo/metrics.json C:/outside/any/repo/rows
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import math
import re
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from types import ModuleType
from typing import Any

_HERE = Path(__file__).resolve().parent

#: The ``prs_merged`` detail's per-repo key -> the series name the dashboard plots.
REPO_SERIES = (
    ("MEFORORG/MessageFoundry", "Engine"),
    ("MEFORORG/MessageFoundry-vault", "Vault"),
    ("MEFORORG/korus", "Korus"),
)

_SHA = re.compile(r"\b[0-9a-f]{7,40}\b")
_ENGINE_REF = re.compile(r"\bengine=(\S+)")


def _collector() -> ModuleType:
    """The sibling collector, loaded by path: this directory is no package."""
    name = "dashboard_collect_metrics"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, _HERE / "collect_metrics.py")
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {_HERE / 'collect_metrics.py'}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def finite_float(value: Any) -> float | None:
    """``value`` as a finite float, or ``None``: an empty CSV cell is no measurement, and NaN is
    not valid JSON."""
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


class Snapshot:
    """Read access to one snapshot, tolerant of a metric that is missing or carries no detail."""

    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data
        self.weeks: list[str] = [str(w) for w in data.get("weeks") or []]
        self.metrics: list[dict[str, Any]] = [
            m for m in data.get("metrics") or [] if isinstance(m, dict) and "id" in m
        ]
        self.by_id = {str(m["id"]): m for m in self.metrics}

    def detail(self, mid: str) -> dict[str, Any]:
        return _dict(self.by_id.get(mid, {}).get("detail"))

    def last_full_week(self) -> str | None:
        """The week the collector valued its weekly metrics at; the window's second-last week when
        no metric recorded one."""
        for mid in ("prs_merged", "ci_main"):
            week = self.detail(mid).get("value_week")
            if isinstance(week, str):
                return week
        return self.weeks[-2] if len(self.weeks) >= 2 else None


def asvs_refs(detail: dict[str, Any]) -> tuple[str, str]:
    """``(scorecard sha, engine ref)`` as recorded, each ``"unknown"`` when it is not."""
    sha = detail.get("scorecard_sha")
    if not isinstance(sha, str) or not sha:
        found = _SHA.search(str(detail.get("scorecard_ref") or ""))
        sha = found.group(0) if found else "unknown"
    engine = detail.get("engine_ref")
    if not isinstance(engine, str) or not engine:
        engine = "unknown"
        for line in detail.get("provenance") or []:
            hit = _ENGINE_REF.search(str(line))
            if hit:
                engine = hit.group(1)
                break
    return sha[:12], engine


def notes(snap: Snapshot) -> dict[str, str]:
    week = snap.last_full_week() or "unknown"
    sha, engine = asvs_refs(snap.detail("asvs"))
    return {
        "backlog_burn": "Counts ledger rows, not items.",
        "prs_merged": f"Engine + vault + korus, week {week}.",
        "flow_health": "Open engine PRs right now.",
        "ci_main": f"Pass rate of ci.yml push runs on main, week {week}. Cancelled and skipped "
        "runs not counted.",
        "asvs": "Pass cells over cells not marked n/a. Scorecard: vault origin/main "
        f"{sha}; engine tool ref {engine}.",
        "dependency_vulns": "Open Dependabot alerts on the engine.",
        "owner_waiting": "Open ledger rows with verdict owner-ruling. Open class C questions not "
        "counted yet.",
        "release_distance": "Commits on engine main since the latest PyPI release tag.",
    }


def _critical_high(d: dict[str, Any]) -> int | None:
    sev = d.get("open_by_severity")
    if not isinstance(sev, dict):
        return None
    return int(sev.get("critical") or 0) + int(sev.get("high") or 0)


def _uploaded_day(d: dict[str, Any]) -> str | None:
    stamp = d.get("uploaded")
    return stamp[:10] if isinstance(stamp, str) and stamp else None


Fact = tuple[str, str, str, Callable[[dict[str, Any]], Any]]


def _key(name: str) -> Callable[[dict[str, Any]], Any]:
    return lambda d: d.get(name)


def _count(name: str) -> Callable[[dict[str, Any]], Any]:
    return lambda d: _dict(d.get("counts")).get(name)


def facts(weeks: int) -> list[Fact]:
    """``(metric, key, label, reader)``; each reader takes the metric's detail."""
    return [
        ("backlog_burn", "open_total", "Open rows", _key("open_total")),
        ("backlog_burn", "open_active", "Active", _key("open_active")),
        ("backlog_burn", "open_unclassified", "No verdict", _key("open_unclassified")),
        ("backlog_burn", "open_deferred", "Deferred", _key("open_deferred")),
        ("backlog_burn", "filed_window", f"Filed, {weeks} weeks", _key("filed_window")),
        ("backlog_burn", "closed_window", f"Closed, {weeks} weeks", _key("closed_window")),
        ("flow_health", "oldest_open_days", "Oldest open (days)", _key("oldest_open_days")),
        (
            "flow_health",
            "median_open_to_merge_hours",
            "Median hours to merge",
            _key("median_open_to_merge_hours"),
        ),
        ("flow_health", "green_but_unmergeable", "Stalled", _key("green_but_unmergeable")),
        ("ci_main", "open_ci_red_prs", "PRs labelled ci-red", _key("open_ci_red_prs")),
        ("asvs", "pass", "Pass", _count("pass")),
        ("asvs", "partial", "Partial", _count("partial")),
        ("asvs", "fail", "Fail", _count("fail")),
        ("dependency_vulns", "critical_high", "Critical + high", _critical_high),
        (
            "dependency_vulns",
            "dep_mttr_days",
            "Mean days to patch",
            lambda d: finite_float(_dict(_dict(d.get("kpis")).get("row")).get("dep_mttr_days")),
        ),
        ("release_distance", "pypi_version", "Latest release", _key("pypi_version")),
        ("release_distance", "uploaded", "Released", _uploaded_day),
    ]


def metric_rows(snap: Snapshot) -> list[dict[str, Any]]:
    note = notes(snap)
    rows = [
        {
            "id": m["id"],
            "label": m.get("label", ""),
            "question": m.get("question", ""),
            "value": m.get("value"),
            "unit": m.get("unit", ""),
            "status": m.get("status", "unknown"),
            "note": note.get(str(m["id"]), ""),
            "source": m.get("source", ""),
            "error": m.get("error"),
        }
        for m in snap.metrics
    ]
    for mid, key, label, read in facts(len(snap.weeks)):
        if mid not in snap.by_id:
            continue
        rows.append(
            {
                "id": f"{mid}.{key}",
                "label": label,
                "question": "",
                "value": read(snap.detail(mid)),
                "unit": "",
                "status": "",
                "note": "",
                "source": snap.by_id[mid].get("source", ""),
                "error": None,
            }
        )
    return rows


def series_rows(snap: Snapshot) -> list[dict[str, Any]]:
    last_full = snap.last_full_week()
    rows: list[dict[str, Any]] = []

    def add(name: str, points: Any) -> None:
        for p in points if isinstance(points, list) else []:
            if not isinstance(p, dict) or "week" not in p:
                continue
            week = str(p["week"])
            rows.append(
                {
                    "series": name,
                    "week": week,
                    "value": p.get("value"),
                    # A week after the last complete one is still in progress.
                    "partial": last_full is not None and week > last_full,
                }
            )

    burn = snap.detail("backlog_burn")
    add("Filed", burn.get("filed_series"))
    add("Closed", burn.get("closed_series"))
    per_repo = _dict(snap.detail("prs_merged").get("per_repo"))
    for repo, name in REPO_SERIES:
        add(name, per_repo.get(repo))
    add("CI pass %", snap.by_id.get("ci_main", {}).get("series"))
    return rows


def meta(src: Path, snap: Snapshot) -> list[dict[str, Any]]:
    return [
        {
            "label": Path(__file__).name,
            "value": Path(__file__).read_text(encoding="utf-8"),
            "type": "code",
            "lang": "python",
        },
        {
            "label": "Input",
            "value": f"{src.name}, generated {snap.data.get('generated_at', 'unknown')} by "
            "scripts/dashboard/collect_metrics.py",
        },
    ]


def _nearest_existing(path: Path) -> Path:
    while not path.exists() and path.parent != path:
        path = path.parent
    return path


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("snapshot", type=Path, help="a snapshot written by collect_metrics.py")
    ap.add_argument("out", type=Path, help="directory for metrics.json and series.json")
    args = ap.parse_args(argv)
    cm = _collector()
    out = args.out.resolve()
    # Checked against the nearest directory that exists, BEFORE anything is created, so a refused
    # --out leaves no directory behind inside a repository.
    reason = cm.refuse_reason(_nearest_existing(out) / "metrics.json")
    if reason is not None:
        print(f"ERROR: refusing out {args.out}: {reason}", file=sys.stderr)
        return 1
    try:
        data = json.loads(args.snapshot.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"ERROR: cannot read {args.snapshot}: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    if not isinstance(data, dict):
        print(f"ERROR: {args.snapshot} is not a snapshot object", file=sys.stderr)
        return 1
    snap = Snapshot(data)
    info = meta(args.snapshot, snap)
    metrics = metric_rows(snap)
    series = series_rows(snap)
    out.mkdir(parents=True, exist_ok=True)
    cm.write_json_atomic(out / "metrics.json", {"rows": metrics, "meta": info})
    cm.write_json_atomic(out / "series.json", {"rows": series, "meta": info})
    print(f"{len(metrics)} metric rows, {len(series)} series rows")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
