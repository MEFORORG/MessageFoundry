#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Gather project-progress metrics into ONE JSON snapshot for a private dashboard.

WHAT IT READS. The engine repository (this checkout's ``origin/main``), the private vault at its
``origin/main`` (never its working tree, which may be dirty or on another branch), GitHub through an
already-authenticated ``gh``, and the public PyPI JSON for the ``messagefoundry`` package.

THE SNAPSHOT IS PRIVATE. It quotes counts read from the vault, so it must never land inside a git
repository, where a ``git add .`` would publish it. ``--out`` is refused when its directory is inside
any git work tree (or inside a ``.git`` directory).

A METRIC THAT COULD NOT BE READ IS ``null``, NEVER ``0``. Each collector runs isolated: one that
raises leaves its metric at ``value: null``, ``status: "unknown"`` and its ``error`` text, and the
others still run. A zero would read exactly like a quiet week.

READ-ONLY apart from two fetches that only update remote-tracking refs: ``git fetch origin`` in the
vault and in the engine checkout, so both reads are of the current ``origin/main``.

Usage::

    python scripts/dashboard/collect_metrics.py --vault D:/Code/MessageFoundry-vault \\
        --out C:/somewhere/outside/any/repo/metrics.json [--weeks 8] [--through 2026-11-21]
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import importlib.util
import io
import json
import statistics
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any

ENGINE_ROOT = Path(__file__).resolve().parents[2]

ENGINE_REPO = "MEFORORG/MessageFoundry"
VAULT_REPO = "MEFORORG/MessageFoundry-vault"
KORUS_REPO = "MEFORORG/korus"
MERGED_REPOS = (ENGINE_REPO, VAULT_REPO, KORUS_REPO)

PYPI_URL = "https://pypi.org/pypi/messagefoundry/json"
#: Generic on purpose: no user, host or project detail leaves this machine in the request.
USER_AGENT = "project-metrics-collector/1"
HTTP_TIMEOUT = 20.0

#: Per-call subprocess ceiling, in seconds. The vault fetch and archive are the slow ones.
CMD_TIMEOUT = 180.0

#: ``gh`` list ceilings. A result count EQUAL to one is a truncation signal, not a population, so
#: the collector refuses it rather than under-report.
PR_LIST_LIMIT = 1000

#: The vault paths archived from ``origin/main``. ``ledger_weekly_report.py`` imports its sibling
#: ``backlog_status_check.py`` by bare name, so all of ``scripts/docs`` comes along.
VAULT_PATHS = (
    "scripts/docs",
    "docs/BACKLOG.md",
    "docs/archive/backlog",
    "docs/security/asvs-scorecard.toml",
)

#: Run conclusions that count toward the CI pass rate. ``cancelled`` and ``skipped`` are left out of
#: both sides: a run superseded by a newer push says nothing about whether main is green.
CI_PASS = frozenset({"success"})
CI_FAIL = frozenset({"failure", "timed_out", "startup_failure", "action_required"})

#: STATUS THRESHOLDS, in one place. Each says what "good" means for its metric; anything between
#: "good" and "bad" is "warn". Chosen as plain, defensible bars for a single-owner beta, not as
#: targets anyone signed: change them here, and the tests pin the boundaries.
THRESHOLDS: dict[str, dict[str, float]] = {
    # closed / filed over the window: good when the ledger shrinks or holds, warn down to 75 pct.
    "backlog_burn": {"good_ratio": 1.0, "warn_ratio": 0.75},
    # last full week's merges against the mean of the window's full weeks: warn below half of it,
    # bad at zero merges.
    "prs_merged": {"warn_fraction_of_mean": 0.5},
    # oldest open PR age in days; any green-but-stalled PR is at least warn.
    "flow_health": {"good_oldest_days": 7, "warn_oldest_days": 14},
    # main CI pass percent for the last full week; any open ci-red PR is at least warn.
    "ci_main": {"good_pct": 90, "warn_pct": 75},
    # ASVS pass cells over applicable (non-na) cells.
    "asvs": {"good_pct": 90, "warn_pct": 50},
    # open Dependabot alerts: any critical/high is bad; any other open alert is warn.
    "dependency_vulns": {},
    # open owner-ruling rows: good at zero, warn up to five.
    "owner_waiting": {"warn_max": 5},
    # engine commits on origin/main since the latest PyPI release.
    "release_distance": {"good_max": 50, "warn_max": 200},
}


class CollectError(Exception):
    """A source could not be read. Its text becomes the metric's ``error``."""


# --------------------------------------------------------------------------------------------------
# Pure helpers: weeks and statuses.
# --------------------------------------------------------------------------------------------------


def iso_week(day: dt.date) -> str:
    """``2026-11-04`` -> ``2026-W45``."""
    year, week, _ = day.isocalendar()
    return f"{year}-W{week:02d}"


def week_of_timestamp(stamp: str) -> str:
    """The ISO week of an ISO-8601 timestamp, read in UTC (``Z`` or an offset)."""
    moment = dt.datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=dt.UTC)
    return iso_week(moment.astimezone(dt.UTC).date())


def window(through: dt.date, weeks: int) -> list[str]:
    """The ISO week labels of the ``weeks`` weeks ending with ``through``'s week, oldest first."""
    return [iso_week(through - dt.timedelta(weeks=n)) for n in reversed(range(weeks))]


def window_start(through: dt.date, weeks: int) -> dt.date:
    """The Monday that opens the window's first week."""
    first = through - dt.timedelta(weeks=weeks - 1)
    return first - dt.timedelta(days=first.weekday())


def last_full_week(through: dt.date, labels: Sequence[str]) -> tuple[str, bool]:
    """``(label, partial)``: the newest window week that is complete by ``through``.

    ``through``'s own week is complete only when ``through`` is a Sunday. When no full week is in
    the window (one week, mid-week), the window's only week is returned flagged partial.
    """
    full = iso_week(through if through.weekday() == 6 else through - dt.timedelta(days=7))
    if full in labels:
        return full, False
    return labels[-1], True


def bucket(stamps: Sequence[str], labels: Sequence[str]) -> list[dict[str, Any]]:
    """Count timestamps per window week, zero-filled, as the snapshot's series shape."""
    counts = dict.fromkeys(labels, 0)
    for stamp in stamps:
        week = week_of_timestamp(stamp)
        if week in counts:
            counts[week] += 1
    return [{"week": w, "value": counts[w]} for w in labels]


def series_value(series: Sequence[dict[str, Any]], week: str) -> Any:
    return next((p["value"] for p in series if p["week"] == week), None)


def status_burn(filed: int, closed: int) -> str:
    t = THRESHOLDS["backlog_burn"]
    if filed == 0 or closed >= filed * t["good_ratio"]:
        return "good"
    return "warn" if closed >= filed * t["warn_ratio"] else "bad"


def status_merged(last: int, full_week_values: Sequence[int]) -> str:
    if last == 0:
        return "bad"
    mean = statistics.fmean(full_week_values) if full_week_values else 0.0
    return "warn" if last < mean * THRESHOLDS["prs_merged"]["warn_fraction_of_mean"] else "good"


def status_flow(oldest_days: float | None, stalled: int | None) -> str:
    t = THRESHOLDS["flow_health"]
    if oldest_days is None or oldest_days <= t["good_oldest_days"]:
        base = "good"
    elif oldest_days <= t["warn_oldest_days"]:
        base = "warn"
    else:
        base = "bad"
    return "warn" if base == "good" and stalled else base


def status_ci(pass_pct: float | None, ci_red: int) -> str:
    if pass_pct is None:
        return "unknown"
    t = THRESHOLDS["ci_main"]
    base = "good" if pass_pct >= t["good_pct"] else "warn" if pass_pct >= t["warn_pct"] else "bad"
    return "warn" if base == "good" and ci_red else base


def status_pct(pct: float | None, metric: str) -> str:
    if pct is None:
        return "unknown"
    t = THRESHOLDS[metric]
    return "good" if pct >= t["good_pct"] else "warn" if pct >= t["warn_pct"] else "bad"


def status_vulns(by_severity: dict[str, int]) -> str:
    if by_severity.get("critical", 0) or by_severity.get("high", 0):
        return "bad"
    return "warn" if sum(by_severity.values()) else "good"


def status_max(value: int, metric: str) -> str:
    t = THRESHOLDS[metric]
    good_max = t.get("good_max", 0)
    if value <= good_max:
        return "good"
    return "warn" if value <= t["warn_max"] else "bad"


def ci_pass_series(runs: Sequence[dict[str, Any]], labels: Sequence[str]) -> list[dict[str, Any]]:
    """Per-week pass percent over runs that finished pass or fail; ``None`` for a week with none."""
    passed = dict.fromkeys(labels, 0)
    failed = dict.fromkeys(labels, 0)
    for run in runs:
        week = week_of_timestamp(str(run["createdAt"]))
        conclusion = str(run.get("conclusion") or "").lower()
        if week not in passed:
            continue
        if conclusion in CI_PASS:
            passed[week] += 1
        elif conclusion in CI_FAIL:
            failed[week] += 1
    out: list[dict[str, Any]] = []
    for w in labels:
        n = passed[w] + failed[w]
        out.append({"week": w, "value": round(100.0 * passed[w] / n, 1) if n else None})
    return out


# --------------------------------------------------------------------------------------------------
# The metric record.
# --------------------------------------------------------------------------------------------------


@dataclass
class Metric:
    id: str
    label: str
    question: str
    unit: str
    source: str
    value: Any = None
    status: str = "unknown"
    series: list[dict[str, Any]] | None = None
    detail: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def as_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "question": self.question,
            "value": self.value,
            "unit": self.unit,
            "status": self.status,
            "series": self.series,
            "detail": self.detail,
            "source": self.source,
            "error": self.error,
        }


# --------------------------------------------------------------------------------------------------
# Context: the injectable runner, HTTP fetch, and the shared vault read.
# --------------------------------------------------------------------------------------------------

Runner = Callable[[Sequence[str], Path | None], str]
BytesRunner = Callable[[Sequence[str]], bytes]
Fetcher = Callable[[str], bytes]


def run_bytes(argv: Sequence[str], cwd: Path | None = None) -> bytes:
    """Run one command; its raw stdout. Raises :class:`CollectError` on any failure."""
    try:
        proc = subprocess.run(  # nosec B603 - argv list from this module, no shell
            list(argv), cwd=cwd, capture_output=True, timeout=CMD_TIMEOUT, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CollectError(f"{argv[0]} could not run: {type(exc).__name__}: {exc}") from None
    if proc.returncode != 0:
        tail = proc.stderr.decode("utf-8", "replace").strip()[-400:]
        raise CollectError(f"{' '.join(argv[:4])} exited {proc.returncode}: {tail}")
    return proc.stdout


def run_cmd(argv: Sequence[str], cwd: Path | None = None) -> str:
    """Run one command; stdout as text. Raises :class:`CollectError` on any failure."""
    return run_bytes(argv, cwd).decode("utf-8", "replace")


def fetch_url(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:  # noqa: S310  # nosec B310 - fixed https URL
            body: bytes = resp.read()
            return body
    except OSError as exc:  # URLError and timeouts are OSError
        raise CollectError(f"GET {url} failed: {type(exc).__name__}: {exc}") from None


def gh_json(ctx: Context, args: Sequence[str]) -> Any:
    text = ctx.run(["gh", *args], None)
    try:
        return json.loads(text) if text.strip() else None
    except json.JSONDecodeError as exc:
        raise CollectError(f"gh {' '.join(args[:2])} returned non-JSON: {exc}") from None


@dataclass
class VaultRead:
    sha: str
    root: Path
    census: Any
    report: ModuleType


@dataclass
class Context:
    vault: Path
    through: dt.date
    weeks: int
    workdir: Path
    run: Runner = run_cmd
    run_raw: BytesRunner = run_bytes
    fetch: Fetcher = fetch_url
    engine_root: Path = ENGINE_ROOT
    merged_cache: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    _vault: VaultRead | CollectError | None = None

    @property
    def labels(self) -> list[str]:
        return window(self.through, self.weeks)

    def vault_read(self) -> VaultRead:
        """The vault at origin/main, archived and censused ONCE, shared by every metric."""
        if self._vault is None:
            try:
                self._vault = _read_vault(self)
            except CollectError as exc:
                self._vault = exc
            except (OSError, ValueError, ImportError, tarfile.TarError) as exc:
                self._vault = CollectError(f"vault read failed: {type(exc).__name__}: {exc}")
        if isinstance(self._vault, CollectError):
            raise self._vault
        return self._vault


def _load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise CollectError(f"cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


@contextmanager
def _on_path(directory: Path) -> Iterator[None]:
    sys.path.insert(0, str(directory))
    try:
        yield
    finally:
        sys.path.remove(str(directory))


def _read_vault(ctx: Context) -> VaultRead:
    vault = str(ctx.vault)
    ctx.run(["git", "-C", vault, "fetch", "-q", "origin"], None)
    sha = ctx.run(["git", "-C", vault, "rev-parse", "origin/main"], None).strip()
    tar_bytes = ctx.run_raw(["git", "-C", vault, "archive", "--format=tar", sha, *VAULT_PATHS])
    root = ctx.workdir / "vault"
    root.mkdir()
    with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tar:
        tar.extractall(root, filter="data")

    docs = root / "scripts" / "docs"
    # The vault's bare `from backlog_status_check import ...` must resolve to the ARCHIVED copy, so a
    # same-named module already imported (or on the path) is dropped first.
    sys.modules.pop("backlog_status_check", None)
    with _on_path(docs):
        report = _load_module("vault_ledger_weekly_report", docs / "ledger_weekly_report.py")
    paths = [root / p for p in report.DEFAULT_SOURCES]
    sources = report.read_sources(paths, root, explicit=True)
    census = report.census(sources)
    # The checker's anti-narrowing floors, applied by hand: `default_corpus_errors` asks git for the
    # tracked ledger files, and the archive is not a git tree.
    empty = [label for label, n in census.per_source if n == 0]
    if empty:
        raise CollectError(f"ledger source(s) parsed to no rows: {', '.join(empty)}")
    if census.rows < report.MIN_TOTAL_ITEMS:
        raise CollectError(
            f"{census.rows} ledger rows read, below the floor of {report.MIN_TOTAL_ITEMS}"
        )
    return VaultRead(sha=sha, root=root, census=census, report=report)


# --------------------------------------------------------------------------------------------------
# Collectors, in snapshot order. Each fills a Metric or raises; `collect` isolates them.
# --------------------------------------------------------------------------------------------------


def c_backlog_burn(ctx: Context, m: Metric) -> None:
    v = ctx.vault_read()
    c = v.census
    labels = ctx.labels
    filed_series = []
    closed_series = []
    for w in labels:
        got = c.weeks.get(w, {})
        filed_series.append({"week": w, "value": got.get("filed", 0)})
        closed_series.append(
            {
                "week": w,
                "value": sum(got.get(k, 0) for k in ("closed", "declined", "superseded")),
            }
        )
    filed = sum(p["value"] for p in filed_series)
    closed = sum(p["value"] for p in closed_series)
    active = sum(c.open_by_verdict[k] for k in v.report.ACTIVE_VERDICTS)
    deferred = c.open_by_verdict[v.report.DEFERRED_VERDICT]
    m.value = closed - filed
    m.status = status_burn(filed, closed)
    m.series = [
        {"week": f["week"], "value": cl["value"] - f["value"]}
        for f, cl in zip(filed_series, closed_series, strict=True)
    ]
    m.detail = {
        "counts": "ROWS, not items: a row bundles several findings as numbered items",
        "vault_origin_main": v.sha,
        "filed_window": filed,
        "closed_window": closed,
        "closed_means": "rows whose newest closed banner is shipped, declined or superseded",
        "filed_series": filed_series,
        "closed_series": closed_series,
        "open_total": c.open_rows,
        "open_active": active,
        "open_deferred": deferred,
        "open_unclassified": c.open_by_verdict["none"] + c.open_by_verdict["other"],
        "rows_total": c.rows,
        "undated": dict(c.undated),
        "series_is": "closed minus filed, per week",
    }


def week_ranges(ctx: Context) -> list[tuple[dt.date, dt.date]]:
    """``(monday, last day)`` per window week; the last week ends at ``through``."""
    start = window_start(ctx.through, ctx.weeks)
    out = []
    for n in range(ctx.weeks):
        lo = start + dt.timedelta(weeks=n)
        out.append((lo, min(lo + dt.timedelta(days=6), ctx.through)))
    return out


def list_per_week(
    ctx: Context, args: Sequence[str], qualifier: Callable[[dt.date, dt.date], list[str]]
) -> list[dict[str, Any]]:
    """One ``gh`` list call per window week, concatenated.

    Per week because both GitHub's search API and ``gh run list`` cap one answer at 1000, which
    the engine alone exceeds over an eight-week window. A week that hits the cap is refused.
    """
    out: list[dict[str, Any]] = []
    for lo, hi in week_ranges(ctx):
        rows = gh_json(ctx, [*args, *qualifier(lo, hi), "--limit", str(PR_LIST_LIMIT)])
        if not isinstance(rows, list):
            raise CollectError(f"gh {' '.join(args[:4])} returned {type(rows).__name__}")
        if len(rows) >= PR_LIST_LIMIT:
            raise CollectError(f"gh {' '.join(args[:4])} week of {lo}: hit the limit; truncated")
        out += rows
    return out


def merged_prs(ctx: Context, repo: str) -> list[dict[str, Any]]:
    """Every PR merged in the window, cached per repo so two metrics share one read."""
    if repo not in ctx.merged_cache:
        ctx.merged_cache[repo] = list_per_week(
            ctx,
            ["pr", "list", "-R", repo, "--state", "merged", "--json", "number,createdAt,mergedAt"],
            lambda lo, hi: ["--search", f"merged:{lo.isoformat()}..{hi.isoformat()}"],
        )
    return ctx.merged_cache[repo]


def c_prs_merged(ctx: Context, m: Metric) -> None:
    labels = ctx.labels
    per_repo: dict[str, list[dict[str, Any]]] = {}
    for repo in MERGED_REPOS:
        stamps = [str(r["mergedAt"]) for r in merged_prs(ctx, repo) if r.get("mergedAt")]
        per_repo[repo] = bucket(stamps, labels)
    total = [
        {"week": w, "value": sum(series_value(s, w) for s in per_repo.values())} for w in labels
    ]
    week, partial = last_full_week(ctx.through, labels)
    full_values = [p["value"] for p in total if p["week"] <= week]
    m.value = series_value(total, week)
    m.status = status_merged(m.value, full_values)
    m.series = total
    m.detail = {"value_week": week, "value_week_partial": partial, "per_repo": per_repo}


def c_flow_health(ctx: Context, m: Metric) -> None:
    rows = gh_json(
        ctx,
        [
            "pr",
            "list",
            "-R",
            ENGINE_REPO,
            "--state",
            "open",
            "--limit",
            str(PR_LIST_LIMIT),
            "--json",
            "number,createdAt",
        ],
    )
    if not isinstance(rows, list):
        raise CollectError(f"gh pr list returned {type(rows).__name__}")
    if len(rows) >= PR_LIST_LIMIT:
        raise CollectError("open PR count hit the list limit; truncated")
    now = dt.datetime.combine(ctx.through, dt.time(23, 59, 59), dt.UTC)
    now = min(now, dt.datetime.now(dt.UTC))
    ages = [
        (
            now - dt.datetime.fromisoformat(str(r["createdAt"]).replace("Z", "+00:00"))
        ).total_seconds()
        / 86400
        for r in rows
    ]
    oldest = round(max(ages), 1) if ages else None

    merged = merged_prs(ctx, ENGINE_REPO)
    hours = [
        (
            dt.datetime.fromisoformat(str(r["mergedAt"]).replace("Z", "+00:00"))
            - dt.datetime.fromisoformat(str(r["createdAt"]).replace("Z", "+00:00"))
        ).total_seconds()
        / 3600
        for r in merged
        if r.get("mergedAt") and r.get("createdAt")
    ]
    detail: dict[str, Any] = {
        "open_prs": len(rows),
        "oldest_open_days": oldest,
        "median_open_to_merge_hours": round(statistics.median(hours), 1) if hours else None,
        "merged_prs_measured": len(hours),
    }

    stalled: int | None = None
    try:
        checker = _load_module(
            "dashboard_check_stalled_prs",
            ctx.engine_root / "scripts" / "ci" / "check_stalled_prs.py",
        )
        prs = checker._fetch(ENGINE_REPO, None, lambda cmd, _timeout: ctx.run(cmd, None))
        stalled = len(checker.scan(prs))
        detail["green_but_unmergeable"] = stalled
        detail["green_but_unmergeable_rule"] = (
            "scripts/ci/check_stalled_prs.py signature: OPEN, BEHIND, no failing or pending check"
        )
    except (CollectError, RuntimeError, OSError, ValueError, ImportError) as exc:
        detail["green_but_unmergeable"] = None
        detail["green_but_unmergeable_error"] = f"{type(exc).__name__}: {exc}"
    m.value = len(rows)
    m.status = status_flow(oldest, stalled)
    m.detail = detail


def c_ci_main(ctx: Context, m: Metric) -> None:
    workflow = ctx.engine_root / ".github" / "workflows" / "ci.yml"
    name = next(
        (
            line.split(":", 1)[1].strip().strip("'\"")
            for line in workflow.read_text(encoding="utf-8").splitlines()
            if line.startswith("name:")
        ),
        None,
    )
    if name is None:
        raise CollectError(f"{workflow} carries no top-level name")
    runs = list_per_week(
        ctx,
        [
            "run",
            "list",
            "-R",
            ENGINE_REPO,
            "--branch",
            "main",
            "--workflow",
            "ci.yml",
            "--json",
            "conclusion,createdAt",
        ],
        lambda lo, hi: ["--created", f"{lo.isoformat()}..{hi.isoformat()}"],
    )
    red = gh_json(
        ctx,
        [
            "pr",
            "list",
            "-R",
            ENGINE_REPO,
            "--state",
            "open",
            "--label",
            "ci-red",
            "--limit",
            str(PR_LIST_LIMIT),
            "--json",
            "number",
        ],
    )
    if not isinstance(red, list):
        raise CollectError(f"gh pr list (ci-red) returned {type(red).__name__}")
    labels = ctx.labels
    series = ci_pass_series(runs, labels)
    week, partial = last_full_week(ctx.through, labels)
    m.value = series_value(series, week)
    m.status = status_ci(m.value, len(red))
    m.series = series
    m.detail = {
        "workflow_name": name,
        "workflow_file": "ci.yml",
        "value_week": week,
        "value_week_partial": partial,
        "runs_read": len(runs),
        "counted": "success passes; failure, timed_out, startup_failure, action_required fail; "
        "cancelled, skipped and in-progress runs are not counted",
        "open_ci_red_prs": len(red),
    }
    if m.value is None:
        m.error = f"no finished pass/fail run of main in {week}"


def c_asvs(ctx: Context, m: Metric) -> None:
    v = ctx.vault_read()
    toml = v.root / "docs" / "security" / "asvs-scorecard.toml"
    out = ctx.run(
        [
            sys.executable,
            str(ctx.engine_root / "scripts" / "asvs" / "scorecard.py"),
            "--scorecard",
            str(toml),
            "--status",
        ],
        ctx.engine_root,
    )
    lines = out.splitlines()
    cells = next((ln for ln in lines if ln.startswith("cells ")), None)
    if cells is None:
        raise CollectError("scorecard --status printed no 'cells' line")
    counts = parse_asvs_cells(cells)
    applicable = counts["total"] - counts.get("na", 0)
    pass_pct = round(100.0 * counts.get("pass", 0) / applicable, 1) if applicable else None
    m.value = pass_pct
    m.status = status_pct(pass_pct, "asvs")
    m.detail = {
        "counts": counts,
        "value_means": "pass cells over cells not marked na",
        "provenance": [ln for ln in lines if ln.startswith("#")],
        "scorecard_ref": f"vault origin/main {v.sha} (archived, so the tool prints NO-GIT)",
        "history": "none: --status reads one ref and keeps no history",
    }


def parse_asvs_cells(line: str) -> dict[str, int]:
    """``cells 345: 139 pass, 140 partial, 0 fail`` -> ``{"total": 345, "pass": 139, ...}``."""
    head, _, rest = line.partition(":")
    try:
        out = {"total": int(head.split()[1])}
        for part in rest.split(","):
            n, verdict = part.split(maxsplit=1)
            out[verdict.strip()] = int(n)
    except (IndexError, ValueError) as exc:
        raise CollectError(f"unreadable scorecard cells line {line!r}: {exc}") from None
    if sum(v for k, v in out.items() if k != "total") != out["total"]:
        raise CollectError(f"scorecard cells line does not sum to its total: {line!r}")
    return out


def c_dependency_vulns(ctx: Context, m: Metric) -> None:
    alerts = gh_json(
        ctx,
        [
            "api",
            "--paginate",
            "--slurp",
            f"repos/{ENGINE_REPO}/dependabot/alerts?state=open&per_page=100",
        ],
    )
    if not isinstance(alerts, list):
        raise CollectError(f"gh api dependabot/alerts returned {type(alerts).__name__}")
    flat = [a for page in alerts for a in (page if isinstance(page, list) else [page])]
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for a in flat:
        sev = str((a.get("security_advisory") or {}).get("severity") or "unknown").lower()
        by_severity[sev] = by_severity.get(sev, 0) + 1
    m.value = len(flat)
    m.status = status_vulns(by_severity)
    m.detail = {"open_by_severity": by_severity, "kpis": _vuln_kpis(ctx)}


def _vuln_kpis(ctx: Context) -> dict[str, Any]:
    """The latest successful vuln-metrics run's CSV row; its own error, never the metric's."""
    try:
        runs = gh_json(
            ctx,
            [
                "run",
                "list",
                "-R",
                ENGINE_REPO,
                "--workflow",
                "vuln-metrics.yml",
                "--status",
                "success",
                "--limit",
                "1",
                "--json",
                "databaseId,createdAt",
            ],
        )
        if not isinstance(runs, list) or not runs:
            raise CollectError("no successful vuln-metrics run found")
        run_id = str(runs[0]["databaseId"])
        dest = ctx.workdir / f"vuln-metrics-{run_id}"
        ctx.run(
            [
                "gh",
                "run",
                "download",
                run_id,
                "-R",
                ENGINE_REPO,
                "-n",
                "vuln-metrics",
                "-D",
                str(dest),
            ],
            None,
        )
        with open(dest / "vuln-metrics.csv", newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        if not rows:
            raise CollectError("vuln-metrics.csv holds no rows")
        return {"run_id": run_id, "run_date": runs[0]["createdAt"], "row": rows[-1], "error": None}
    except (CollectError, OSError, KeyError) as exc:
        return {"run_id": None, "row": None, "error": f"{type(exc).__name__}: {exc}"}


def c_owner_waiting(ctx: Context, m: Metric) -> None:
    v = ctx.vault_read()
    n = int(v.census.open_by_verdict["owner-ruling"])
    m.value = n
    m.status = status_max(n, "owner_waiting")
    m.detail = {
        "ledger_owner_ruling_rows": n,
        "vault_origin_main": v.sha,
        "class_c_questions": None,
        "class_c_note": "not read: open class C questions are bundled only by "
        "scripts/coord/digest.ps1, which writes a digest file and is not a read-only query, so "
        "this counts the ledger part only",
    }


def c_release_distance(ctx: Context, m: Metric) -> None:
    try:
        info = json.loads(ctx.fetch(PYPI_URL))
        version = str(info["info"]["version"])
        files = info["releases"].get(version) or []
        uploaded = min((f["upload_time_iso_8601"] for f in files), default=None)
    except (ValueError, KeyError, TypeError) as exc:
        raise CollectError(f"unreadable PyPI JSON: {type(exc).__name__}: {exc}") from None
    # Release tags are `v<version>` (webconsole-v* tag the other distribution; rescue/auto/* are
    # backup tags and are never consulted, since the tag is named from the PyPI version).
    tag = f"v{version}"
    root = str(ctx.engine_root)
    ctx.run(["git", "-C", root, "fetch", "-q", "origin", "main"], None)
    ctx.run(
        ["git", "-C", root, "fetch", "-q", "origin", f"refs/tags/{tag}:refs/tags/{tag}"],
        None,
    )
    count = int(ctx.run(["git", "-C", root, "rev-list", "--count", f"{tag}..origin/main"], None))
    m.value = count
    m.status = status_max(count, "release_distance")
    m.detail = {"pypi_version": version, "uploaded": uploaded, "tag": tag}


@dataclass(frozen=True)
class Spec:
    id: str
    label: str
    question: str
    unit: str
    source: str
    fn: Callable[[Context, Metric], None]


SPECS: tuple[Spec, ...] = (
    Spec(
        "backlog_burn",
        "Backlog burn",
        "Is the ledger shrinking: rows closed against rows filed?",
        "rows (closed minus filed)",
        "vault origin/main: scripts/docs/ledger_weekly_report.py census() over docs/BACKLOG.md "
        "and docs/archive/backlog/BACKLOG-CLOSED.md (git archive)",
        c_backlog_burn,
    ),
    Spec(
        "prs_merged",
        "PRs merged",
        "How many pull requests merged per week across engine, vault and korus?",
        "PRs per week",
        "gh pr list -R <repo> --state merged --search merged:<week> --json number,mergedAt, "
        f"for {', '.join(MERGED_REPOS)}",
        c_prs_merged,
    ),
    Spec(
        "flow_health",
        "Engine PR flow",
        "Are engine pull requests flowing: open count, oldest age, time to merge?",
        "open PRs",
        f"gh pr list -R {ENGINE_REPO} --state open|merged --json createdAt,mergedAt; "
        "scripts/ci/check_stalled_prs.py scan()",
        c_flow_health,
    ),
    Spec(
        "ci_main",
        "CI on main",
        "How often does the engine's CI pass on main?",
        "percent",
        f"gh run list -R {ENGINE_REPO} --branch main --workflow ci.yml --json conclusion,createdAt; "
        "gh pr list --label ci-red",
        c_ci_main,
    ),
    Spec(
        "asvs",
        "ASVS scorecard",
        "What share of applicable ASVS cells pass?",
        "percent",
        "python scripts/asvs/scorecard.py --scorecard <vault origin/main>/docs/security/"
        "asvs-scorecard.toml --status",
        c_asvs,
    ),
    Spec(
        "dependency_vulns",
        "Dependency vulnerabilities",
        "How many dependency vulnerabilities are open, by severity?",
        "open alerts",
        f"gh api repos/{ENGINE_REPO}/dependabot/alerts?state=open; KPIs from the latest "
        "successful vuln-metrics.yml run artifact vuln-metrics.csv",
        c_dependency_vulns,
    ),
    Spec(
        "owner_waiting",
        "Waiting on the owner",
        "How many open ledger rows wait on an owner ruling?",
        "rows",
        "vault origin/main: ledger_weekly_report.py census().open_by_verdict['owner-ruling']",
        c_owner_waiting,
    ),
    Spec(
        "release_distance",
        "Distance from release",
        "How far has engine main moved since the latest PyPI release?",
        "commits",
        f"{PYPI_URL}; git rev-list --count v<version>..origin/main",
        c_release_distance,
    ),
)


def collect(ctx: Context, specs: Sequence[Spec] = SPECS) -> list[Metric]:
    out: list[Metric] = []
    for spec in specs:
        m = Metric(spec.id, spec.label, spec.question, spec.unit, spec.source)
        try:
            spec.fn(ctx, m)
        except Exception as exc:  # noqa: BLE001 - isolation boundary: one metric never aborts the rest
            # Whatever the collector half-filled is discarded: a partial value must not survive
            # next to an error, or it reads as a measurement.
            m = Metric(spec.id, spec.label, spec.question, spec.unit, spec.source)
            m.error = str(exc) if isinstance(exc, CollectError) else f"{type(exc).__name__}: {exc}"
        out.append(m)
    return out


def snapshot(
    ctx: Context, metrics: Sequence[Metric], now: dt.datetime | None = None
) -> dict[str, Any]:
    moment = now or dt.datetime.now(dt.UTC)
    return {
        "generated_at": moment.astimezone(dt.UTC).isoformat(timespec="seconds"),
        "through": ctx.through.isoformat(),
        "weeks": ctx.labels,
        "metrics": [m.as_json() for m in metrics],
    }


# --------------------------------------------------------------------------------------------------
# The --out guard and the CLI.
# --------------------------------------------------------------------------------------------------


def refuse_reason(out: Path, run: Runner = run_cmd) -> str | None:
    """Why ``out`` may not be written, or ``None``. Fails CLOSED when git cannot answer."""
    parent = out.resolve().parent
    if not parent.is_dir():
        return f"{parent} is not an existing directory"
    try:
        answer = run(["git", "-C", str(parent), "rev-parse", "--is-inside-work-tree"], None).strip()
    except CollectError as exc:
        text = str(exc)
        # git's own answer for a directory in no repository: the one failure that means "safe".
        if "not a git repository" in text:
            return None
        return f"cannot tell whether {parent} is inside a git repository: {text}"
    # "true" is a work tree; "false" is inside a .git directory. Both are a repository.
    return (
        f"{parent} is inside a git repository (rev-parse said {answer!r}); the snapshot is private"
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--vault", type=Path, required=True, help="the vault checkout (read at origin/main)"
    )
    ap.add_argument("--out", type=Path, required=True, help="snapshot JSON path, outside any repo")
    ap.add_argument("--weeks", type=int, default=8, help="ISO weeks in the window (default 8)")
    ap.add_argument(
        "--through",
        type=dt.date.fromisoformat,
        default=None,
        metavar="YYYY-MM-DD",
        help="last day of the window (default: today, UTC)",
    )
    args = ap.parse_args(argv)
    if not 1 <= args.weeks <= 104:
        print("ERROR: --weeks must be from 1 to 104", file=sys.stderr)
        return 2
    reason = refuse_reason(args.out)
    if reason is not None:
        print(f"ERROR: refusing --out {args.out}: {reason}", file=sys.stderr)
        return 2
    through = args.through or dt.datetime.now(dt.UTC).date()
    with tempfile.TemporaryDirectory(prefix="mf-metrics-") as tmp:
        ctx = Context(vault=args.vault, through=through, weeks=args.weeks, workdir=Path(tmp))
        metrics = collect(ctx)
        snap = snapshot(ctx, metrics)
    tmp_out = args.out.with_name(args.out.name + ".tmp")
    tmp_out.write_text(json.dumps(snap, indent=2) + "\n", encoding="utf-8")
    tmp_out.replace(args.out)
    for m in metrics:
        print(
            f"{m.id}: value={m.value} status={m.status}" + (f" error={m.error}" if m.error else "")
        )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
