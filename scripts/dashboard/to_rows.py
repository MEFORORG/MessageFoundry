#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Flatten a ``collect_metrics.py`` snapshot into the dashboard's two row files.

WRITES ``<out>/metrics.json`` (one row per headline metric, then one per fact),
``<out>/series.json`` (one row per series per ISO week) and ``<out>/priority.json`` (one row per
ledger priority per status). Each file is ``{"rows": [...], "meta":
[...]}``, and ``meta`` carries this converter's own source and the snapshot it read.

THE ROWS ARE AS PRIVATE AS THE SNAPSHOT: they quote the same vault counts. ``--out`` is refused
wherever the collector's own guard (``refuse_out_dir``) finds git reporting a work tree; that
guard's docstring says what it cannot see. Every row quoting an ASVS number carries the collector's
ref pair in its ``ref`` field (empty on every other row): the collector builds it from the vault
commit it archived the scorecard at and the ``engine=`` ref, which in an archive run is the commit
the caller archived, because the tool itself then prints ``NO-GIT``. The tool's own ``#`` provenance
lines are a separate row, ``asvs.provenance``.

THE ASVS HEADLINE IS NEVER SHOWN ALONE. It is pass cells over cells not marked n/a, so
needs-review and unverified cells, which carry no verdict, sit in its denominator; their counts are
rows beside it and are named in its note. Unless the snapshot holds both counts as whole numbers,
the headline is null. ``scripts/asvs/scorecard.py`` itself prints no single headline score at all, and this rate
is not one it gives: it does not separate cells decided with no ``last_verified``.

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
import json
import math
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

# The sibling scripts are imported by name from this directory: it is no package, and under
# ``python -I`` the script's own directory is not on the path.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import collect_metrics as cm  # noqa: E402


def _nth_sunday(year: int, month: int, n: int) -> dt.date:
    first = dt.date(year, month, 1)
    return first + dt.timedelta(days=(6 - first.weekday()) % 7 + 7 * (n - 1))


def central_offset(moment: dt.datetime) -> tuple[dt.timedelta, str]:
    """US Central's UTC offset and abbreviation at ``moment`` (aware).

    The US rule since 2007, computed rather than read from a time zone database: Windows Python
    ships none unless ``tzdata`` is installed, and this script runs under ``-I`` with the standard
    library alone. Daylight time runs from 02:00 local on March's second Sunday (08:00 UTC) to
    02:00 local on November's first Sunday (07:00 UTC)."""
    utc = moment.astimezone(dt.UTC)
    start = dt.datetime.combine(_nth_sunday(utc.year, 3, 2), dt.time(8), dt.UTC)
    end = dt.datetime.combine(_nth_sunday(utc.year, 11, 1), dt.time(7), dt.UTC)
    if start <= utc < end:
        return dt.timedelta(hours=-5), "CDT"
    return dt.timedelta(hours=-6), "CST"


def _clock(moment: dt.datetime) -> str:
    hour = moment.hour % 12 or 12
    return f"{hour}:{moment.minute:02d} {'AM' if moment.hour < 12 else 'PM'}"


def central(stamp: Any) -> str | None:
    """An ISO-8601 timestamp as US Central wall time, ``Tue Nov 24, 2026, 7:01 AM CST``; ``None``
    when it cannot be read."""
    try:
        moment = cm.parse_stamp(stamp)
    except (TypeError, ValueError):
        return None
    offset, name = central_offset(moment)
    local = (moment.astimezone(dt.UTC) + offset).replace(tzinfo=None)
    return f"{local:%a %b} {local.day}, {local.year}, {_clock(local)} {name}"


def utc_clock(stamp: Any) -> str | None:
    """The same moment as ``13:01 UTC``; ``None`` when it cannot be read."""
    try:
        moment = cm.parse_stamp(stamp).astimezone(dt.UTC)
    except (TypeError, ValueError):
        return None
    return f"{moment:%H:%M} UTC"


def repo_series() -> tuple[tuple[str, str], ...]:
    """The ``prs_merged`` per-repo key -> the series name the dashboard plots, keyed by the
    collector's own repo names so a rename cannot leave a series quietly empty."""
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
            week = cm.last_full_week(through, self.weeks, made)
        except (KeyError, ValueError, IndexError, cm.CollectError):
            return None
        return str(week)


def asvs_pair(snap: Snapshot) -> str:
    """The collector's ref pair, which every ASVS number is quoted beside."""
    return str(cm.asvs_ref_pair(snap.detail("asvs")))


#: The two states in the headline's denominator that carry no verdict (scorecard.py: neither
#: belongs in a numerator). Not the tool's "unexamined" set: a needs-review cell was examined.
NO_VERDICT = (("needs-review", "Needs review"), ("unverified", "Unverified"))

NO_ASVS_HEADLINE = (
    "no headline: the snapshot does not hold both a needs-review and an unverified count as whole "
    "numbers, so the pass rate cannot be shown beside the cells in its denominator that carry no "
    "verdict"
)


def no_verdict_counts(detail: dict[str, Any]) -> dict[str, int] | None:
    """The ASVS detail's needs-review and unverified counts; ``None`` unless both are whole
    numbers, so the headline cannot be qualified. A missing or null count is no measurement, never
    a quiet zero; the collector marks a cells line without one as partial."""
    counts = _dict(detail.get("counts"))
    got: dict[str, int] = {}
    for key, _ in NO_VERDICT:
        value = counts.get(key)
        if not isinstance(value, int) or isinstance(value, bool):
            return None
        got[key] = value
    return got


def _no_verdict(key: str) -> Callable[[dict[str, Any]], Any]:
    return lambda d: (no_verdict_counts(d) or {}).get(key)


def asvs_note(snap: Snapshot) -> str:
    base = "Pass cells over cells not marked n/a."
    counts = no_verdict_counts(snap.detail("asvs"))
    if counts is None:
        return base
    return (
        f"{base} {counts['needs-review']} needs-review and {counts['unverified']} unverified "
        "cells, which carry no verdict, are in that denominator and are not passes. Cells "
        "decided with no last_verified count as decided; scorecard.py --status reports them."
    )


def _provenance(d: dict[str, Any]) -> str | None:
    lines = d.get("provenance")
    if not isinstance(lines, list):
        return None
    return "; ".join(str(ln) for ln in lines if str(ln).strip()) or None


def notes(snap: Snapshot) -> dict[str, str]:
    week = snap.last_full_week or "unknown"
    return {
        "backlog_burn": "Counts ledger rows, not items.",
        "prs_merged": f"Engine + vault + korus, week {week}.",
        "flow_health": "Open engine PRs right now.",
        "ci_main": f"Pass rate of ci.yml push runs on main, week {week}. Cancelled and skipped "
        "runs not counted.",
        "asvs": asvs_note(snap),
        "dependency_vulns": "Open Dependabot alerts on the engine.",
        "owner_waiting": "Open ledger rows with verdict owner-ruling. Open class C questions not "
        "counted yet.",
        "release_distance": "Commits on engine main since the latest PyPI release tag.",
        "backlog_forecast": forecast_note(snap),
        "batch_progress": batch_note(snap),
    }


def forecast_note(snap: Snapshot) -> str:
    weeks = _dict(snap.detail("backlog_forecast").get("pace")).get("weeks")
    span = f", {weeks[0]} to {weeks[-1]}" if isinstance(weeks, list) and weeks else ""
    return (
        f"Open rows divided by the mean net rows closed per week (closed minus filed) over the "
        f"last {cm.FORECAST_WEEKS} full weeks{span}. A week of heavy filing in that span pushes "
        "the date out until it leaves the span."
    )


def batch_note(snap: Snapshot) -> str:
    saved = central(snap.detail("batch_progress").get("runbook_saved"))
    return (
        "Ledger rows closed across the runbook's batches, as the workbook's own last ledger sync "
        "recorded them" + (f"; workbook saved {saved}." if saved else ".")
    )


def forecast_line(snap: Snapshot) -> str | None:
    """One sentence for the burndown: when the open count reaches zero at the recent pace."""
    m = snap.by_id.get("backlog_forecast")
    if not m or m.get("error") or m.get("value") is None:
        return None
    d = snap.detail("backlog_forecast")
    net = _dict(d.get("pace")).get("net_closed_per_week")
    if not isinstance(net, (int, float)):
        return None
    if d.get("finish"):
        return f"At the last {cm.FORECAST_WEEKS} full weeks' pace ({net:,g} net rows closed a week) it reaches zero about {d['finish']}."
    return (
        f"At the last {cm.FORECAST_WEEKS} full weeks' pace it never reaches zero: filing "
        f"outran closing by {-net:,g} rows a week."
    )


def ledger_history(snap: Snapshot) -> list[dict[str, Any]]:
    """Every week the census holds, oldest first: filed, closed and open rows at its end. Empty
    for a snapshot collected before the history was."""
    d = snap.detail("backlog_burn")
    hist = d.get("history")
    if not isinstance(hist, list):
        return []
    opened = {
        str(p["week"]): p.get("value")
        for p in d.get("open_series") or []
        if isinstance(p, dict) and "week" in p
    }
    return [
        {
            "week": str(p["week"]),
            "filed": p.get("filed"),
            "closed": p.get("closed"),
            "open": opened.get(str(p["week"])),
        }
        for p in hist
        if isinstance(p, dict) and "week" in p
    ]


#: The runbook's batch states, from not started to finished, as its Status board names them.
BATCH_STATES = ("FREE", "IN PROGRESS", "QUIET", "NO BUILDER", "BUILT", "MERGED", "DONE")


def _whole(value: Any) -> int | None:
    """A batch count as the collector writes it, a whole number; anything else is no
    measurement. Never converted, so a float such as 1e999 cannot raise."""
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _other_batches(d: dict[str, Any]) -> Any:
    """Batches in a state the list above does not name, so the breakdown always sums."""
    by = d.get("batches_by_state")
    if not isinstance(by, dict):
        return None
    counts = [_whole(n) for s, n in by.items() if s not in BATCH_STATES]
    return None if None in counts else sum(n for n in counts if n is not None)


def _batches(state: str) -> Callable[[dict[str, Any]], Any]:
    def read(d: dict[str, Any]) -> Any:
        by = d.get("batches_by_state")
        # A state with no batches is absent from the map, so absent is a real zero.
        return _whole(by.get(state, 0)) if isinstance(by, dict) else None

    return read


def _finish_or_never(finish: str, pace_key: str) -> Callable[[dict[str, Any]], Any]:
    # A pace that was read but never empties the ledger is "never", not a missing value.
    return lambda d: d.get(finish) or ("never" if isinstance(d.get(pace_key), dict) else None)


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
        ("backlog_burn", "open_unclassified", "Other or no verdict", _key("open_unclassified")),
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
        *[("asvs", key, label, _no_verdict(key)) for key, label in NO_VERDICT],
        ("asvs", "provenance", "Tool provenance", _provenance),
        ("dependency_vulns", "critical_high", "Critical + high", _critical_high),
        (
            "dependency_vulns",
            "dep_mttr_days",
            "Median days to merge a security PR",
            lambda d: finite_float(_dict(_dict(d.get("kpis")).get("row")).get("dep_mttr_days")),
        ),
        ("release_distance", "pypi_version", "Latest release", _key("pypi_version")),
        ("release_distance", "uploaded", "Released", _uploaded_day),
        (
            "backlog_forecast",
            "net_closed_per_week",
            f"Net closed a week ({cm.FORECAST_WEEKS} wk)",
            lambda d: _dict(d.get("pace")).get("net_closed_per_week"),
        ),
        (
            "backlog_forecast",
            "closed_per_week",
            f"Closed a week ({cm.FORECAST_WEEKS} wk)",
            lambda d: _dict(d.get("pace")).get("closed_per_week"),
        ),
        (
            "backlog_forecast",
            "filed_per_week",
            f"Filed a week ({cm.FORECAST_WEEKS} wk)",
            lambda d: _dict(d.get("pace")).get("filed_per_week"),
        ),
        (
            "backlog_forecast",
            "short_finish",
            f"At the last {cm.FORECAST_SHORT_WEEKS} weeks' pace",
            _finish_or_never("short_finish", "short_pace"),
        ),
        (
            "backlog_forecast",
            "no_filing_finish",
            "If filing stopped",
            _finish_or_never("no_filing_finish", "pace"),
        ),
        ("batch_progress", "rows_closed", "Rows closed", _key("rows_closed")),
        ("batch_progress", "rows_total", "Rows in batches", _key("rows_total")),
        ("batch_progress", "batches_total", "Batches", _key("batches_total")),
        *[
            (
                "batch_progress",
                f"batches_{s.lower().replace(' ', '_')}",
                s.capitalize(),
                _batches(s),
            )
            for s in BATCH_STATES
        ],
        ("batch_progress", "batches_other", "Other state", _other_batches),
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
            "ref": asvs_pair(snap) if m["id"] == "asvs" else "",
        }
        for m in snap.metrics
    ]
    # A metric that errored has its own reason, and no counts because of it.
    asvs_failed = bool(snap.by_id.get("asvs", {}).get("error"))
    withheld = not asvs_failed and no_verdict_counts(snap.detail("asvs")) is None
    headline = next((r for r in rows if r["id"] == "asvs"), None)
    if headline is not None and withheld:
        # No count to qualify it with: no headline. Its reason leads, beside any partial one.
        prior = headline["error"]
        headline.update(
            value=None,
            status="unknown",
            error=f"{NO_ASVS_HEADLINE}; {prior}" if prior else NO_ASVS_HEADLINE,
        )
    # A null ASVS fact whose metric has no error of its own still says why it is null.
    own_reason = {
        **{k: NO_ASVS_HEADLINE for k, _ in NO_VERDICT if withheld},
        "provenance": "the snapshot holds no scorecard provenance lines",
    }
    for mid, key, label, read in facts(len(snap.weeks)):
        if mid not in snap.by_id:
            continue
        value = read(snap.detail(mid))
        # A null fact carries its metric's reason, so a dashboard showing it alone is not mute.
        reason = None if value is not None else error(snap.by_id[mid])
        if value is None and mid == "asvs":
            reason = reason or own_reason.get(key)
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
                # The collector's ref pair, on every row quoting an ASVS number.
                "ref": asvs_pair(snap) if mid == "asvs" else "",
            }
        )
    return rows


#: The bucket ``_vault_census.py`` puts a row whose Cluster line names no priority in.
UNSCORED_LABEL = "unscored"

#: The priority table's columns, in order: the open statuses, then the closed kinds.
PRIORITY_STATUSES = (*cm.OPEN_STATUSES, "closed", "declined", "superseded")


def _priority_key(priority: str) -> tuple[int, str]:
    # P0, P1, ... in order, then anything else (the unscored bucket) after them.
    return (0, priority) if priority[:1] == "P" and priority[1:].isdigit() else (1, priority)


def priority_rows(snap: Snapshot) -> list[dict[str, Any]]:
    """One row per ledger priority per status, priorities in order and every status present, so a
    zero is a measured zero. Empty for a snapshot that holds no priority census."""
    by = snap.detail("backlog_burn").get("by_priority")
    if not isinstance(by, dict):
        return []
    rows: list[dict[str, Any]] = []
    for priority in sorted((str(p) for p in by), key=_priority_key):
        counts = _dict(by.get(priority))
        statuses = [*PRIORITY_STATUSES, *sorted(k for k in counts if k not in PRIORITY_STATUSES)]
        for status in statuses:
            value = counts.get(status, 0)
            rows.append(
                {
                    "priority": priority,
                    "status": status,
                    "value": value
                    if isinstance(value, int) and not isinstance(value, bool)
                    else None,
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
    # The whole ledger history the page's ranged charts and burndown draw, so the row files carry
    # everything the page shows.
    hist = ledger_history(snap)
    for name, key in HISTORY_SERIES:
        add(name, [{"week": p["week"], "value": p[key]} for p in hist])
    return rows


#: ``(series name, ledger_history key)`` for the history series rows.
HISTORY_SERIES = (
    ("Filed, all weeks", "filed"),
    ("Closed, all weeks", "closed"),
    ("Open rows", "open"),
)


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


def load_snapshot(path: Path) -> dict[str, Any] | str:
    """The snapshot at ``path``, or why it cannot be read. A NaN or infinity reads as null: it is
    no measurement, nor valid JSON."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"), parse_constant=lambda _: None)
    except (OSError, ValueError) as exc:
        return f"cannot read {path}: {type(exc).__name__}: {exc}"
    if not isinstance(data, dict):
        return f"{path} is not a snapshot object"
    return data


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("snapshot", type=Path, help="a snapshot written by collect_metrics.py")
    ap.add_argument("out", type=Path, help="directory for metrics.json and series.json")
    args = ap.parse_args(argv)
    out = args.out.resolve()
    # The DIRECTORY is checked, never a leaf name that a planted link could point elsewhere.
    reason = cm.refuse_out_dir(out)
    if reason is not None:
        print(f"ERROR: refusing out {args.out}: {reason}", file=sys.stderr)
        return 1
    data = load_snapshot(args.snapshot)
    if isinstance(data, str):
        print(f"ERROR: {data}", file=sys.stderr)
        return 1
    snap = Snapshot(data)
    info = meta(args.snapshot, snap)
    metrics = metric_rows(snap)
    series = series_rows(snap)
    try:
        out.mkdir(parents=True, exist_ok=True)
        cm.write_json_atomic(out / "metrics.json", {"rows": metrics, "meta": info})
        cm.write_json_atomic(out / "series.json", {"rows": series, "meta": info})
        cm.write_json_atomic(out / "priority.json", {"rows": priority_rows(snap), "meta": info})
    except (OSError, ValueError) as exc:
        print(f"ERROR: cannot write {out}: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(f"{len(metrics)} metric rows, {len(series)} series rows")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
