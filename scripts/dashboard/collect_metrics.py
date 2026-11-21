#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Gather project-progress metrics into ONE JSON snapshot for a private dashboard.

WHAT IT READS, at least: the private vault at its ``origin/main`` (never its working tree, which
may be dirty or on another branch); GitHub through an already-authenticated ``gh``; the public PyPI
JSON for the ``messagefoundry`` package; the engine's ``origin/main`` for the release distance; and,
from THIS engine checkout's working tree, ``scripts/asvs/scorecard.py`` and
``scripts/ci/check_stalled_prs.py``, which it runs and imports.

THE SNAPSHOT IS PRIVATE. It quotes counts read from the vault, so it must never land inside a git
repository, where a ``git add .`` would publish it. ``--out`` is refused when its directory is inside
any git work tree (or inside a ``.git`` directory).

A METRIC THAT COULD NOT BE READ IS ``null``, NEVER ``0``. Each collector runs isolated: one that
raises leaves its metric at ``value: null``, ``status: "unknown"`` and its ``error`` text, and the
others still run. A zero would read exactly like a quiet week.

WHAT IT WRITES outside ``--out``, at least: two ``git fetch --no-tags origin main``, one in the
vault and one in the engine checkout. Each moves ``refs/remotes/origin/main`` and also writes
``FETCH_HEAD`` and fetched objects, and may start git's own auto-maintenance. No local tag or branch
is created; the release tag is resolved with ``git ls-remote``. Importing the stalled-PR checker can
write ``__pycache__`` in the engine checkout. Vault files and downloads go to a temporary directory
removed at exit.

WINDOWED AND CURRENT METRICS. ``--weeks``/``--through`` bound the weekly series. The state metrics
(open PRs, open alerts, ASVS counts, open ledger rows, release distance) are read as they stand at
run time whatever ``--through`` says, and each says so in its detail. The open ``ci-red`` PR count
is the exception: for a past ``--through`` it is not read at all, so it cannot pass for history.
The final window week ends at ``--through``, for the ledger counts as for the GitHub ones.

EXIT STATUS. 0 when every metric and every optional part was read. 3 when the snapshot WAS written
but a metric carries an error or a detail carries a ``partial_error``, so a scheduled caller goes red
on an outage rather than publishing nulls quietly. 1 when nothing was written (a refused ``--out``, a
bad ``--weeks`` or ``--through``); 2 is argparse's own usage error, and nothing was written either.

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
import os
import re
import shutil
import statistics
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
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

#: The vault paths archived from ``origin/main`` before the ledger files are known.
#: ``ledger_weekly_report.py`` imports its sibling ``backlog_status_check.py`` by bare name, so all
#: of ``scripts/docs`` comes along. The ledger files themselves are listed from the tree against the
#: checker's own ``LEDGER_FILE_GLOBS``, so a new ledger file is archived too and its floors see it.
VAULT_PATHS = ("scripts/docs",)
VAULT_SCORECARD = "docs/security/asvs-scorecard.toml"

#: Attempts per ``gh`` call, and the pause between them. check_stalled_prs.py measured transient
#: 502s on split ``gh`` queries; a collector making ~35 sequential calls retries the same way.
GH_ATTEMPTS = 3
GH_BACKOFF_SECONDS = 2.0

#: The failures worth a retry: a gateway or server error, a rate limit, a network drop or a
#: timeout. Anything else (a 404, an auth refusal, a bad flag, a missing ``gh``) fails on the first
#: attempt, because a retry would only fail again, slower.
_TRANSIENT = re.compile(
    r"HTTP 5\d\d|\b50[0234]\b|rate limit|timed? ?out|TimeoutExpired|connection (?:reset|refused)"
    r"|\bEOF\b|dial tcp|TLS handshake|temporarily unavailable|Something went wrong",
    re.IGNORECASE,
)

#: The week label a vault date AFTER ``--through`` is counted under, so the final window week is
#: clipped at ``--through`` without the date reading as undated.
AFTER_THROUGH = "after-through"

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
    # dependency_vulns has no number to tune: any open critical/high alert is bad, any other open
    # alert is warn (status_vulns).
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


def last_full_week(through: dt.date, labels: Sequence[str], today: dt.date) -> str:
    """The newest window week that is complete.

    ``through``'s own week is complete only when ``through`` is a Sunday that has already ended,
    that is, earlier than ``today`` (UTC): a run on a Sunday is still inside that week. The CLI
    requires at least two weeks, so the week before ``through``'s is always in the window.
    """
    if through.weekday() == 6 and through < today:
        return iso_week(through)
    full = iso_week(through - dt.timedelta(days=7))
    if full not in labels:
        raise CollectError(f"the window {labels[0]}..{labels[-1]} holds no complete week")
    return full


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
    # An unread stall count (None) is not zero stalls: it caps the status at warn, like a stall.
    return "warn" if base == "good" and (stalled is None or stalled) else base


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


def probe_env() -> dict[str, str]:
    """The environment for the ``--out`` probe: every ``GIT_*`` variable dropped.

    ``GIT_DIR``, ``GIT_WORK_TREE`` or ``GIT_CEILING_DIRECTORIES`` would let the caller's environment
    tell git that a directory inside a repository is in none. Discovery across filesystems is turned
    ON, so a mount boundary never hides an enclosing repository either.
    """
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_")}
    return {**env, "GIT_DISCOVERY_ACROSS_FILESYSTEM": "1", "LC_ALL": "C", "LANGUAGE": "C"}


def run_bytes(
    argv: Sequence[str], cwd: Path | None = None, *, env: dict[str, str] | None = None
) -> bytes:
    """Run one command; its raw stdout. Raises :class:`CollectError` on any failure."""
    # git under the C locale, so the one stderr message read back (refuse_reason) is not localized.
    if env is None and argv[0] == "git":
        env = {**os.environ, "LC_ALL": "C", "LANGUAGE": "C"}
    try:
        proc = subprocess.run(  # nosec B603 - argv list from this module, no shell
            list(argv), cwd=cwd, env=env, capture_output=True, timeout=CMD_TIMEOUT, check=False
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


def run_probe(argv: Sequence[str], cwd: Path | None = None) -> str:
    """:func:`run_cmd` under :func:`probe_env`, for the ``--out`` guard."""
    return run_bytes(argv, cwd, env=probe_env()).decode("utf-8", "replace")


def fetch_url(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:  # noqa: S310  # nosec B310 - fixed https URL
            body: bytes = resp.read()
            return body
    except OSError as exc:  # URLError and timeouts are OSError
        raise CollectError(f"GET {url} failed: {type(exc).__name__}: {exc}") from None


def is_transient(error: CollectError) -> bool:
    """Whether a failed ``gh`` call is worth another attempt; see :data:`_TRANSIENT`."""
    return _TRANSIENT.search(str(error)) is not None


def gh_json(ctx: Context, args: Sequence[str]) -> Any:
    for attempt in range(1, GH_ATTEMPTS + 1):
        try:
            text = ctx.run(["gh", *args], None)
            break
        except CollectError as exc:
            if attempt == GH_ATTEMPTS or not is_transient(exc):
                raise
            time.sleep(ctx.gh_backoff)
    try:
        return json.loads(text) if text.strip() else None
    except json.JSONDecodeError as exc:
        raise CollectError(f"gh {' '.join(args[:2])} returned non-JSON: {exc}") from None


def gh_list(ctx: Context, args: Sequence[str]) -> list[dict[str, Any]]:
    """One ``gh`` list call at :data:`PR_LIST_LIMIT`, refused when it is not a list or is capped."""
    rows = gh_json(ctx, [*args, "--limit", str(PR_LIST_LIMIT)])
    what = " ".join(str(a) for a in args[:4])
    if not isinstance(rows, list):
        raise CollectError(f"gh {what} returned {type(rows).__name__}")
    if len(rows) >= PR_LIST_LIMIT:
        raise CollectError(f"gh {what} hit the limit of {PR_LIST_LIMIT}; truncated")
    return rows


def add_partial(detail: dict[str, Any], text: str) -> None:
    """Record an optional part that could not be read; several join into one ``partial_error``."""
    prior = detail.get("partial_error")
    detail["partial_error"] = f"{prior}; {text}" if prior else text


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
    #: The stalled-PR checker's runner; None uses its own retrying `gh` runner.
    stall_runner: Callable[[list[str], float], str] | None = None
    today: dt.date = field(default_factory=lambda: dt.datetime.now(dt.UTC).date())
    gh_backoff: float = GH_BACKOFF_SECONDS
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
            except (
                OSError,
                ValueError,
                KeyError,
                AttributeError,
                TypeError,
                ImportError,
                tarfile.TarError,
            ) as exc:
                # Cached too: a retry would only fail again, slower.
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


def _archive_into(ctx: Context, vault: str, sha: str, paths: Sequence[str], root: Path) -> None:
    tar_bytes = ctx.run_raw(["git", "-C", vault, "archive", "--format=tar", sha, "--", *paths])
    with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tar:
        tar.extractall(root, filter="data")


def _read_vault(ctx: Context) -> VaultRead:
    vault = str(ctx.vault)
    ctx.run(["git", "-C", vault, "fetch", "-q", "--no-tags", "origin", "main"], None)
    sha = ctx.run(["git", "-C", vault, "rev-parse", "origin/main"], None).strip()
    # A fresh directory per attempt, so an uncaught failure retried by the next metric reports its
    # own cause, never a FileExistsError. RESOLVED, because the vault's read_sources labels a source
    # by path.resolve().relative_to(root): an unresolved temp path (a junction, an 8.3 short TEMP,
    # macOS /var) makes every label absolute, which its floors read as dropped files.
    root = Path(tempfile.mkdtemp(prefix="vault-", dir=ctx.workdir)).resolve()
    _archive_into(ctx, vault, sha, VAULT_PATHS, root)

    docs = root / "scripts" / "docs"
    # The vault's bare `from backlog_status_check import ...` must resolve to the ARCHIVED copy, so a
    # same-named module already imported (or on the path) is dropped first.
    sys.modules.pop("backlog_status_check", None)
    with _on_path(docs):
        report = _load_module("vault_ledger_weekly_report", docs / "ledger_weekly_report.py")
    checker = sys.modules["backlog_status_check"]
    # -z: a path git would otherwise quote (a space, a non-ASCII byte) comes back as written.
    tree = ctx.run(
        ["git", "-C", vault, "ls-tree", "-r", "-z", "--name-only", sha, "--", "docs"], None
    )
    ledger = [
        name
        for name in tree.split("\0")
        if name
        and any(
            PurePosixPath(name).full_match(g, case_sensitive=True)
            for g in checker.LEDGER_FILE_GLOBS
        )
    ]
    if not ledger:
        raise CollectError(f"no ledger file matches the checker's globs at vault {sha}")
    _archive_into(ctx, vault, sha, ledger, root)

    paths = [root / p for p in report.DEFAULT_SOURCES]
    sources = report.read_sources(paths, root, explicit=True)
    census = _clipped_census(report, sources, ctx.through)
    # The checker's anti-narrowing floors, reused: a dropped, emptied or unscanned ledger file, then
    # the row-count floor. The archive is no git top level, so the checker globs it from disk.
    structural = report.default_corpus_errors(root, census.per_source)
    if structural:
        raise CollectError("; ".join(structural))
    if census.rows < report.MIN_TOTAL_ITEMS:
        raise CollectError(
            f"{census.rows} ledger rows read, below the floor of {report.MIN_TOTAL_ITEMS}"
        )
    return VaultRead(sha=sha, root=root, census=census, report=report)


def _clipped_census(report: ModuleType, sources: Any, through: dt.date) -> Any:
    """The vault's census, with every date after ``through`` counted under :data:`AFTER_THROUGH`.

    The census buckets by ISO week alone, so a past ``--through`` would otherwise count the rest of
    its own week. Its ``Census.count`` resolves the module-level ``iso_week`` at call time, which
    is wrapped for the one call and restored after.
    """
    original = getattr(report, "iso_week", None)
    if not callable(original):
        raise CollectError("the vault census has no iso_week to clip at --through")

    def clipped(date: str | None) -> str | None:
        week: str | None = original(date)
        if week is not None and date is not None and dt.date.fromisoformat(date) > through:
            return AFTER_THROUGH
        return week

    setattr(report, "iso_week", clipped)  # noqa: B010 - a vault module, typed only as ModuleType
    try:
        return report.census(sources)
    finally:
        setattr(report, "iso_week", original)  # noqa: B010


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
        "clipped_at": ctx.through.isoformat(),
        "after_through": dict(c.weeks.get(AFTER_THROUGH, {})),
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
        try:
            out += gh_list(ctx, [*args, *qualifier(lo, hi)])
        except CollectError as exc:
            raise CollectError(f"week of {lo}: {exc}") from None
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
    week = last_full_week(ctx.through, labels, ctx.today)
    full_values = [p["value"] for p in total if p["week"] <= week]
    m.value = series_value(total, week)
    m.status = status_merged(m.value, full_values)
    m.series = total
    m.detail = {"value_week": week, "per_repo": per_repo}


def _parse_stamp(stamp: Any) -> dt.datetime:
    return dt.datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))


def c_flow_health(ctx: Context, m: Metric) -> None:
    rows = gh_list(
        ctx, ["pr", "list", "-R", ENGINE_REPO, "--state", "open", "--json", "number,createdAt"]
    )
    # Open PRs are today's set, so their ages are measured from now, never from --through: a past
    # --through would give a PR opened after it a negative age.
    now = dt.datetime.now(dt.UTC)
    ages = [(now - _parse_stamp(r["createdAt"])).total_seconds() / 86400 for r in rows]
    oldest = round(max(ages), 1) if ages else None
    detail: dict[str, Any] = {"open_prs": len(rows), "oldest_open_days": oldest}

    # The merged-PR read feeds only the time-to-merge fields, so its failure nulls those alone.
    try:
        hours = [
            (_parse_stamp(r["mergedAt"]) - _parse_stamp(r["createdAt"])).total_seconds() / 3600
            for r in merged_prs(ctx, ENGINE_REPO)
            if r.get("mergedAt") and r.get("createdAt")
        ]
        detail["median_open_to_merge_hours"] = round(statistics.median(hours), 1) if hours else None
        detail["merged_prs_measured"] = len(hours)
    except (CollectError, ValueError, TypeError) as exc:
        detail["median_open_to_merge_hours"] = None
        detail["merged_prs_measured"] = None
        add_partial(detail, f"merged PRs: {type(exc).__name__}: {exc}")

    stalled: int | None = None
    try:
        checker = _load_module(
            "dashboard_check_stalled_prs",
            ctx.engine_root / "scripts" / "ci" / "check_stalled_prs.py",
        )
        # The checker's own `_fetch` (private, but the one definition of the split query and its
        # fail-closed guards). Its retrying runner is used unless a test injects one.
        prs = checker._fetch(ENGINE_REPO, None, ctx.stall_runner)
        stalled = len(checker.scan(prs))
        detail["green_but_unmergeable"] = stalled
        detail["green_but_unmergeable_rule"] = (
            "scripts/ci/check_stalled_prs.py signature: OPEN, BEHIND, no failing or pending check"
        )
    except (
        CollectError,
        RuntimeError,
        OSError,
        ValueError,
        KeyError,
        AttributeError,
        TypeError,
        ImportError,
        # The checker's own runner calls subprocess.run with a timeout, so a hung `gh` surfaces
        # as TimeoutExpired, which is none of the above.
        subprocess.SubprocessError,
    ) as exc:
        # An optional part: the status is capped at warn and the run exits 3, never a quiet null.
        detail["green_but_unmergeable"] = None
        add_partial(detail, f"stall count: {type(exc).__name__}: {exc}")
    detail["state_as_of"] = "run time; --through does not apply to open PRs"
    m.value = len(rows)
    m.status = status_flow(oldest, stalled)
    m.detail = detail


def c_ci_main(ctx: Context, m: Metric) -> None:
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
            # Pushes only: a scheduled run on main tests the same commit again and would weigh a
            # quiet week toward whatever the nightly legs did.
            "--event",
            "push",
            "--json",
            "conclusion,createdAt",
        ],
        lambda lo, hi: ["--created", f"{lo.isoformat()}..{hi.isoformat()}"],
    )
    # The ci-red label is today's state. A past --through window is not judged by it: the count
    # is left unread, so it can never pass for a historical one.
    current = ctx.through >= ctx.today
    red: list[dict[str, Any]] | None = None
    if current:
        red = gh_list(
            ctx,
            ["pr", "list", "-R", ENGINE_REPO, "--state", "open", "--label", "ci-red"]
            + ["--json", "number"],
        )
    labels = ctx.labels
    series = ci_pass_series(runs, labels)
    week = last_full_week(ctx.through, labels, ctx.today)
    m.value = series_value(series, week)
    m.status = status_ci(m.value, len(red) if red is not None else 0)
    m.series = series
    m.detail = {
        "workflow_file": "ci.yml (the workflow named CI), push events on main only",
        "value_week": week,
        "runs_read": len(runs),
        "counted": "success passes; failure, timed_out, startup_failure, action_required fail; "
        "cancelled, skipped and in-progress runs are not counted",
        "open_ci_red_prs": len(red) if red is not None else None,
        "open_ci_red_prs_as_of": "run time"
        if current
        else "not read: --through is in the past and the label count is current state only",
    }
    if m.value is None:
        m.error = f"no finished pass/fail run of main in {week}"


def c_asvs(ctx: Context, m: Metric) -> None:
    v = ctx.vault_read()
    # Archived here, not with the ledger: a moved scorecard must null this metric alone.
    _archive_into(ctx, str(ctx.vault), v.sha, [VAULT_SCORECARD], v.root)
    toml = v.root / VAULT_SCORECARD
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
    provenance = [ln for ln in lines if ln.startswith("#")]
    engine_ref = asvs_engine_ref(provenance)
    m.value = pass_pct
    m.status = status_pct(pass_pct, "asvs")
    m.detail = {
        "counts": counts,
        "value_means": "pass cells over cells not marked na",
        "provenance": provenance,
        "scorecard_sha": v.sha,
        "engine_ref": engine_ref,
        "scorecard_ref": f"vault origin/main {v.sha} (archived, so the tool prints NO-GIT)",
        "tool": "scripts/asvs/scorecard.py from this engine checkout, whose ref the provenance "
        "line names",
        "history": "none: --status reads one ref and keeps no history",
        "state_as_of": "run time; --through does not apply",
    }
    if engine_ref is None:
        # A score is quoted only beside its ref pair; without the engine half it cannot be.
        add_partial(m.detail, "scorecard provenance printed no engine= ref")


_ENGINE_REF = re.compile(r"\bengine=(\S+)")


def asvs_engine_ref(provenance: Sequence[str]) -> str | None:
    """The ``engine=<ref>`` the scorecard tool's provenance header names, or ``None``."""
    for line in provenance:
        found = _ENGINE_REF.search(line)
        if found:
            return found.group(1)
    return None


def asvs_ref_pair(detail: dict[str, Any]) -> str:
    """``scorecard=<vault sha> engine=<ref>``, ``unknown`` for a half not recorded."""
    sha = detail.get("scorecard_sha") or "unknown"
    return f"scorecard=vault-origin-main@{sha} engine={detail.get('engine_ref') or 'unknown'}"


def parse_asvs_cells(line: str) -> dict[str, int]:
    """``cells 10: 4 pass, 6 partial`` -> ``{"total": 10, "pass": 4, "partial": 6}``."""
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
    kpis = _vuln_kpis(ctx)
    m.detail = {
        "open_by_severity": by_severity,
        "kpis": kpis,
        "state_as_of": "run time; --through does not apply",
    }
    if kpis["error"]:
        m.detail["partial_error"] = f"vuln-metrics KPIs: {kpis['error']}"


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
                # main only: a run on a PR branch measures that branch's lockfile, not main's.
                "--branch",
                "main",
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
    except (CollectError, OSError, ValueError, KeyError, TypeError, csv.Error) as exc:
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
        "state_as_of": "vault origin/main at run time; --through does not apply",
    }


def c_release_distance(ctx: Context, m: Metric) -> None:
    try:
        info = json.loads(ctx.fetch(PYPI_URL))
        version = str(info["info"]["version"])
    except (ValueError, KeyError, TypeError) as exc:
        raise CollectError(f"unreadable PyPI JSON: {type(exc).__name__}: {exc}") from None
    uploaded_error: str | None = None
    try:
        # `urls` lists the latest version's files; the deprecated `releases` map is not needed.
        uploaded = min((str(f["upload_time_iso_8601"]) for f in info["urls"]), default=None)
    except (KeyError, TypeError) as exc:
        uploaded = None
        uploaded_error = f"PyPI upload time unreadable: {type(exc).__name__}: {exc}"
    # Release tags are `v<version>` (webconsole-v* tag the other distribution; rescue/auto/* are
    # backup tags and are never consulted, since the tag is named from the PyPI version).
    tag = f"v{version}"
    root = str(ctx.engine_root)
    ctx.run(["git", "-C", root, "fetch", "-q", "--no-tags", "origin", "main"], None)
    # ls-remote, not a tag fetch: it creates no local ref. An annotated tag also prints its peeled
    # commit as `<ref>^{}`, which is preferred.
    listed = ctx.run(["git", "-C", root, "ls-remote", "origin", f"refs/tags/{tag}*"], None)
    refs: dict[str, str] = {}
    for line in listed.splitlines():
        commit, _, ref = line.partition("\t")
        refs[ref.strip()] = commit.strip()
    sha = refs.get(f"refs/tags/{tag}^{{}}") or refs.get(f"refs/tags/{tag}")
    if sha is None:
        raise CollectError(f"origin carries no tag {tag} for PyPI version {version}")
    count = int(ctx.run(["git", "-C", root, "rev-list", "--count", f"{sha}..origin/main"], None))
    m.value = count
    m.status = status_max(count, "release_distance")
    m.detail = {
        "pypi_version": version,
        "uploaded": uploaded,
        "tag": tag,
        "tag_commit": sha,
        "state_as_of": "run time; --through does not apply",
    }
    if uploaded_error:
        add_partial(m.detail, uploaded_error)


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
        "vault origin/main: scripts/docs/ledger_weekly_report.py census() over its "
        "DEFAULT_SOURCES (git archive of every file LEDGER_FILE_GLOBS matches)",
        c_backlog_burn,
    ),
    Spec(
        "prs_merged",
        "PRs merged",
        "How many pull requests merged per week across engine, vault and korus?",
        "PRs per week",
        "gh pr list -R <repo> --state merged --search merged:<week> --json number,createdAt,mergedAt, "
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


def refuse_reason(out: Path, run: Runner = run_probe) -> str | None:
    """Why ``out`` may not be written, or ``None``. Fails CLOSED when git cannot answer.

    git runs under :func:`probe_env`, so no ``GIT_*`` variable in the caller's environment can
    steer the answer.
    """
    parent = out.resolve().parent
    if not parent.is_dir():
        return f"{parent} is not an existing directory"
    try:
        answer = run(["git", "-C", str(parent), "rev-parse", "--is-inside-work-tree"], None).strip()
    except CollectError as exc:
        text = str(exc)
        # git's own answer for a directory in no repository: the one failure that means "safe".
        # run_bytes runs git under LC_ALL=C, so the message is not localized.
        # The full phrase: a bare "not a git repository" is also git's answer for a pruned
        # worktree's gitdir or a bad GIT_DIR, which ARE inside a repository's tree.
        if "not a git repository (or any" in text:
            return None
        return f"cannot tell whether {parent} is inside a git repository: {text}"
    # "true" is a work tree; "false" is inside a .git directory. Both are a repository.
    return (
        f"{parent} is inside a git repository (rev-parse said {answer!r}); the snapshot is private"
    )


def write_json_atomic(out: Path, payload: Any) -> None:
    """Write ``payload`` as JSON through a sibling temporary file, so a reader never sees half."""
    tmp_out = out.with_name(out.name + ".tmp")
    tmp_out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    tmp_out.replace(out)


def remove_tree(path: Path) -> None:
    """Remove a temporary tree; each path that will not go is warned about on stderr, not raised."""

    def warn(func: Callable[..., Any], target: str, exc: BaseException) -> None:
        print(
            f"WARNING: could not remove temporary {target}: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )

    shutil.rmtree(path, onexc=warn)


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
    # At least two, so the window always holds one complete week for the weekly values.
    # Error text can quote a ledger line or a git message; a cp1252 console must not raise on it.
    for stream in (sys.stdout, sys.stderr):
        if isinstance(stream, io.TextIOWrapper):
            stream.reconfigure(encoding="utf-8", errors="replace")
    if not 2 <= args.weeks <= 104:
        print("ERROR: --weeks must be from 2 to 104", file=sys.stderr)
        return 1
    # Resolved ONCE, and the resolved path is both the one checked and the one written: a symlinked
    # --out must not pass the check on its target and then be written beside the link.
    out = args.out.resolve()
    reason = refuse_reason(out)
    if reason is not None:
        print(f"ERROR: refusing --out {args.out}: {reason}", file=sys.stderr)
        return 1
    today = dt.datetime.now(dt.UTC).date()
    through = args.through or today
    if through > today:
        print(f"ERROR: --through {through} is after today ({today}, UTC)", file=sys.stderr)
        return 1
    tmp = Path(tempfile.mkdtemp(prefix="mf-metrics-"))
    try:
        ctx = Context(vault=args.vault, through=through, weeks=args.weeks, workdir=tmp)
        metrics = collect(ctx)
        write_json_atomic(out, snapshot(ctx, metrics))
    finally:
        # A cleanup failure (a scanner holding a downloaded file) never discards a finished run.
        remove_tree(tmp)
    for m in metrics:
        line = f"{m.id}: value={m.value} status={m.status}"
        if m.id == "asvs" and m.detail:
            # An ASVS number is quoted only beside the ref pair it was measured at.
            line += f" {asvs_ref_pair(m.detail)}"
        print(line + (f" error={m.error}" if m.error else ""))
    # 3 when anything could not be read, after the snapshot is written: an outage goes red.
    return 3 if any(m.error or m.detail.get("partial_error") for m in metrics) else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
