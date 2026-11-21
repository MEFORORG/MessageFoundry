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

EXIT STATUS. 0 when both files were written; 1 when they were not (a refused ``--out``, an unreadable
snapshot, a failed write, which may leave metrics.json new beside an old series.json); 2 is
argparse's own usage error.

Usage::

    python scripts/dashboard/to_rows.py C:/outside/any/repo/metrics.json C:/outside/any/repo/rows
"""

from __future__ import annotations

import argparse
import datetime as dt
import importlib.util
import json
import math
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from types import ModuleType
from typing import Any

_HERE = Path(__file__).resolve().parent


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


def repo_series() -> tuple[tuple[str, str], ...]:
    """The ``prs_merged`` per-repo key -> the series name the dashboard plots, keyed by the
    collector's own repo names so a rename cannot leave a series quietly empty."""
    cm = _collector()
    return ((cm.ENGINE_REPO, "Engine"), (cm.VAULT_REPO, "Vault"), (cm.KORUS_REPO, "Korus"))


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
        self.last_full_week = self._last_full_week()

    def detail(self, mid: str) -> dict[str, Any]:
        return _dict(self.by_id.get(mid, {}).get("detail"))

    def _last_full_week(self) -> str | None:
        """The week the collector valued its weekly metrics at. When no metric recorded one, the
        collector's own rule, from the snapshot's ``through`` and the day it was generated."""
        for mid in ("prs_merged", "ci_main"):
            week = self.detail(mid).get("value_week")
            if isinstance(week, str):
                return week
        try:
            through = dt.date.fromisoformat(str(self.data["through"]))
            made = dt.datetime.fromisoformat(str(self.data["generated_at"])).date()
            week = _collector().last_full_week(through, self.weeks, made)
        except (KeyError, ValueError, IndexError, _collector().CollectError):
            return None
        return str(week)


def asvs_pair(snap: Snapshot) -> str:
    """The ref pair every ASVS number is quoted beside, rendered by the collector itself."""
    return str(_collector().asvs_ref_pair(snap.detail("asvs")))


def notes(snap: Snapshot) -> dict[str, str]:
    week = snap.last_full_week or "unknown"
    return {
        "backlog_burn": "Counts ledger rows, not items.",
        "prs_merged": f"Engine + vault + korus, week {week}.",
        "flow_health": "Open engine PRs right now.",
        "ci_main": f"Pass rate of ci.yml push runs on main, week {week}. Cancelled and skipped "
        "runs not counted.",
        "asvs": f"Pass cells over cells not marked n/a. Measured at {asvs_pair(snap)}.",
        "dependency_vulns": "Open Dependabot alerts on the engine.",
        "owner_waiting": "Open ledger rows with verdict owner-ruling. Open class C questions not "
        "counted yet.",
        "release_distance": "Commits on engine main since the latest PyPI release tag.",
    }


def _critical_high(d: dict[str, Any]) -> int | None:
    sev = d.get("open_by_severity")
    if not isinstance(sev, dict):
        return None
    try:
        return int(sev.get("critical") or 0) + int(sev.get("high") or 0)
    except (TypeError, ValueError):
        return None


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
            "Median days to merge a security PR",
            lambda d: finite_float(_dict(_dict(d.get("kpis")).get("row")).get("dep_mttr_days")),
        ),
        ("release_distance", "pypi_version", "Latest release", _key("pypi_version")),
        ("release_distance", "uploaded", "Released", _uploaded_day),
    ]


def metric_rows(snap: Snapshot) -> list[dict[str, Any]]:
    note = notes(snap)

    def error(m: dict[str, Any]) -> Any:
        # A part that could not be read reaches the dashboard with its reason, never as a bare null.
        partial = _dict(m.get("detail")).get("partial_error")
        return m.get("error") or (f"partial: {partial}" if partial else None)

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
            "error": error(m),
        }
        for m in snap.metrics
    ]
    for mid, key, label, read in facts(len(snap.weeks)):
        if mid not in snap.by_id:
            continue
        value = read(snap.detail(mid))
        # A null fact carries its metric's reason, so a dashboard showing it alone is not mute.
        reason = None if value is not None else error(snap.by_id[mid])
        if value is None and key == "dep_mttr_days":
            raw = _dict(_dict(snap.detail(mid).get("kpis")).get("row")).get(key)
            reason = reason or (raw if isinstance(raw, str) and raw else None)
        rows.append(
            {
                "id": f"{mid}.{key}",
                "label": label,
                "question": "",
                "value": value,
                "unit": "",
                "status": "",
                # An ASVS count is quoted only beside its ref pair, on every row that carries one.
                "note": f"Measured at {asvs_pair(snap)}." if mid == "asvs" else "",
                "source": snap.by_id[mid].get("source", ""),
                "error": reason,
            }
        )
    return rows


def series_rows(snap: Snapshot) -> list[dict[str, Any]]:
    # Unresolved, the window's newest week is the one that may be in progress: fail closed and
    # mark it partial rather than plot it as complete.
    last_full = snap.last_full_week or (snap.weeks[-2] if len(snap.weeks) >= 2 else "")
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
                    "partial": week > last_full,
                }
            )

    burn = snap.detail("backlog_burn")
    add("Filed", burn.get("filed_series"))
    add("Closed", burn.get("closed_series"))
    per_repo = _dict(snap.detail("prs_merged").get("per_repo"))
    for repo, name in repo_series():
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
    # The DIRECTORY is checked, never a leaf name that a planted link could point elsewhere.
    reason = cm.refuse_dir_reason(_nearest_existing(out).resolve())
    if reason is not None:
        print(f"ERROR: refusing out {args.out}: {reason}", file=sys.stderr)
        return 1
    try:
        # A NaN or infinity in the snapshot reads as null: it is no measurement, nor valid JSON.
        data = json.loads(args.snapshot.read_text(encoding="utf-8"), parse_constant=lambda _: None)
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
    try:
        out.mkdir(parents=True, exist_ok=True)
        cm.write_json_atomic(out / "metrics.json", {"rows": metrics, "meta": info})
        cm.write_json_atomic(out / "series.json", {"rows": series, "meta": info})
    except (OSError, ValueError) as exc:
        print(f"ERROR: cannot write {out}: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(f"{len(metrics)} metric rows, {len(series)} series rows")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
