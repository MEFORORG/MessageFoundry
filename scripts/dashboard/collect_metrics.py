#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Gather project-progress metrics into ONE JSON snapshot for a private dashboard.

WHAT IT READS, at least: the private vault at its ``origin/main`` (never its working tree, which
may be dirty or on another branch); GitHub through an already-authenticated ``gh``; the public PyPI
JSON for the ``messagefoundry`` package; the engine's ``origin/main`` for the release distance, in
the git checkout ``--engine-repo`` names (default: the checkout this script sits in); and, from the
tree THIS script sits in, ``scripts/asvs/scorecard.py`` and ``scripts/ci/check_stalled_prs.py``,
which it runs and imports. That tree need not be a git checkout: the scheduled refresh runs a
``git archive`` copy, and passes ``--archive-ref`` with the commit it archived, because the
scorecard tool then stamps ``engine=NO-GIT``.

THE SNAPSHOT IS PRIVATE. It quotes counts read from the vault, so it must never land inside a git
repository, where a ``git add .`` would publish it. ``--out``'s directory, and the work directory the
vault files are extracted into, are refused when git, run from that directory, reports a work tree
or a ``.git`` directory: probed twice, once with every ``GIT_*`` variable dropped and once with the
caller's own environment, and refused if either says so or either cannot answer. A repository git
cannot discover from there is not caught: for example a bare repository whose ``core.worktree``
points at a parent directory, reached only through an explicit ``--git-dir``.

THE VAULT'S CODE RUNS IN A CHILD PROCESS. The ledger census is the vault's own
``scripts/docs/ledger_weekly_report.py``, archived from vault ``origin/main``. It runs through
``_vault_census.py`` under ``python -I`` with an allowlisted environment that holds no token
variable and no ``GIT_*`` variable, never imported into this process. The vault commit it ran at is
recorded. That is NO SANDBOX, and the environment scrub does not limit what that code can do: the
child runs with the full power of the user who runs this script. It can run ``gh`` or ``git`` with
the user's stored credentials (keyring, ``hosts.yml``), read and write any file that user can, and
so alter the engine files this process runs after it, such as ``scripts/ci/check_stalled_prs.py``,
``scripts/asvs/scorecard.py``, ``render_html.py`` and this script. The scrub only keeps a token
variable and a ``GIT_*`` variable from being handed to it. Running this script therefore trusts
vault ``origin/main`` as fully as the engine code itself. Pinning the vault code to a reviewed
commit would narrow that trust; it is not done here.

STDOUT CARRIES NO RAW VALUE. The console summary is each metric's id, status and whether it holds
an error; the values, the counts and the error text are only in the snapshot. A status is a banded
function of its value (the ASVS band among them), so stdout is still not for a public place.

A METRIC THAT COULD NOT BE READ IS ``null``, NEVER ``0``. Each collector runs isolated: one that
raises leaves its metric at ``value: null``, ``status: "unknown"`` and its ``error`` text, and the
others still run. A zero would read exactly like a quiet week.

WHAT IT WRITES outside ``--out``, at least: unless ``--no-fetch``, two
``git fetch --no-tags origin +refs/heads/main:refs/remotes/origin/main``, one in the vault and one
in the engine checkout. Each moves only ``refs/remotes/origin/main``, and also writes
``FETCH_HEAD`` and fetched objects, and may start git's own auto-maintenance. No local tag or branch
is created; the release tag is resolved with ``git ls-remote``. Importing the stalled-PR checker can
write ``__pycache__`` in the tree this script sits in. Vault files and downloads go to a fresh
``mf-metrics-*`` directory under ``--work-dir`` (default: Python's temporary directory), removed at
exit; a removal that fails is an error, and such directories older than two hours are swept at the
start of the next run, since a run killed by a time limit skips its cleanup.

WINDOWED AND CURRENT METRICS. ``--weeks``/``--through`` bound the weekly series. The state metrics
(open PRs, open alerts, ASVS counts, open ledger rows, release distance) are read as they stand at
run time whatever ``--through`` says, and each says so in its detail. The open ``ci-red`` PR count
is the exception: for a past ``--through`` it is not read at all, so it cannot pass for history.
The final window week ends at ``--through``, for the ledger counts as for the GitHub ones.

EXIT STATUS. 0 when every metric and every optional part was read. 3 when the snapshot WAS written
but a metric carries an error or a detail carries a ``partial_error``, so a scheduled caller goes red
on an outage rather than publishing nulls quietly, and also when the work directory, or a stale one
from a killed run, could not be removed. 1 when nothing was written (a refused ``--out`` or work
directory, ``--weeks`` outside 2 to 104, or a ``--through`` in the future); 2 is argparse's own
usage error, a malformed date among them, and nothing was written either.

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
import math
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
from collections.abc import Callable, Sequence
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
#: Generic on purpose: no user or host detail rides in the header. The URL itself names the
#: package, which is public.
USER_AGENT = "project-metrics-collector/1"
HTTP_TIMEOUT = 20.0

#: Per-call subprocess ceiling, in seconds. The vault fetch and archive are the slow ones.
CMD_TIMEOUT = 180.0

#: ``gh`` list ceilings. A result count EQUAL to one is a truncation signal, not a population, so
#: the collector refuses it rather than under-report.
PR_LIST_LIMIT = 1000

#: The one ref a fetch moves: main, into its remote-tracking ref, and nothing else.
MAIN_REFSPEC = "+refs/heads/main:refs/remotes/origin/main"

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
    r"HTTP 5\d\d|HTTP 429|rate limit|timed? ?out|TimeoutExpired|connection (?:reset|refused)"
    r"|\bEOF\b|dial tcp|TLS handshake|temporarily unavailable|Something went wrong"
    r"|error connecting to|context deadline exceeded",
    re.IGNORECASE,
)

#: The week label a vault date AFTER ``--through`` is counted under, so the final window week is
#: clipped at ``--through`` without the date reading as undated.
AFTER_THROUGH = "after-through"

_SHA40 = re.compile(r"[0-9a-f]{40}")
#: The canonical public PEP 440 forms this project releases (``1.2.3``, ``1.2.3rc1``,
#: ``1.2.3.post1``, ``1.2.3.dev4``). Anything else from PyPI is refused before it reaches a git
#: argument or a ref glob.
_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+)*(?:(?:a|b|rc)[0-9]+)?(?:\.post[0-9]+)?(?:\.dev[0-9]+)?")

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
    """A source could not be read. Its text becomes the metric's ``error``.

    ``stderr`` is the failed command's own stderr, kept apart from the message, which also names
    the command and its arguments: a check of what the command SAID must not read its arguments.
    """

    def __init__(self, message: str, *, stderr: str = "") -> None:
        super().__init__(message)
        self.stderr = stderr


# --------------------------------------------------------------------------------------------------
# Pure helpers: weeks and statuses.
# --------------------------------------------------------------------------------------------------


def iso_week(day: dt.date) -> str:
    """``2026-11-04`` -> ``2026-W45``."""
    year, week, _ = day.isocalendar()
    return f"{year}-W{week:02d}"


def week_of_timestamp(stamp: str) -> str:
    """The ISO week of an ISO-8601 timestamp, read in UTC (``Z`` or an offset)."""
    return iso_week(parse_stamp(stamp).astimezone(dt.UTC).date())


def parse_stamp(stamp: Any) -> dt.datetime:
    """An ISO-8601 timestamp (``Z`` or an offset) as an aware datetime; a naive one is UTC."""
    moment = dt.datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
    return moment if moment.tzinfo is not None else moment.replace(tzinfo=dt.UTC)


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


def status_ci(pass_pct: float | None, ci_red: int | None) -> str:
    # An unread ci-red count (None) is not zero: it caps the status at warn, like a red PR.
    if pass_pct is None:
        return "unknown"
    t = THRESHOLDS["ci_main"]
    base = "good" if pass_pct >= t["good_pct"] else "warn" if pass_pct >= t["warn_pct"] else "bad"
    return "warn" if base == "good" and (ci_red is None or ci_red) else base


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


def floor_pct(part: int, whole: int) -> float:
    """``part`` over ``whole`` as a percent rounded DOWN to one decimal: a status is banded on the
    raw rate, and 89.98 must not read as 90.0."""
    return math.floor(1000.0 * part / whole) / 10


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
        out.append({"week": w, "value": floor_pct(passed[w], n) if n else None})
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
        stderr = proc.stderr.decode("utf-8", "replace").strip()
        raise CollectError(
            # Six words, so `python -I -X utf8 <script> <arg>` still names the script it ran.
            f"{' '.join(argv[:6])} exited {proc.returncode}: {stderr[-400:]}",
            stderr=stderr,
        )
    return proc.stdout


def run_cmd(argv: Sequence[str], cwd: Path | None = None) -> str:
    """Run one command; stdout as text. Raises :class:`CollectError` on any failure."""
    return run_bytes(argv, cwd).decode("utf-8", "replace")


def run_probe(argv: Sequence[str], cwd: Path | None = None) -> str:
    """:func:`run_cmd` under :func:`probe_env`, for the ``--out`` guard."""
    return run_bytes(argv, cwd, env=probe_env()).decode("utf-8", "replace")


def run_real_probe(argv: Sequence[str], cwd: Path | None = None) -> str:
    """The caller's own environment, for the ``--out`` guard, with only discovery across
    filesystems turned on and the C locale: otherwise git stops at a mount point with a message
    :data:`_NO_REPO` does not match, and every directory below one would read as "cannot tell"."""
    env = {**os.environ, "GIT_DISCOVERY_ACROSS_FILESYSTEM": "1", "LC_ALL": "C", "LANGUAGE": "C"}
    return run_bytes(argv, cwd, env=env).decode("utf-8", "replace")


#: The environment the vault's census code runs under: what a Windows or POSIX Python needs to
#: start, and nothing else. No token variable (GH_TOKEN, GITHUB_TOKEN), no GIT_* and no profile
#: variable. Not a sandbox: PATH stays, so gh and git, with their stored credentials, still run.
_CHILD_ENV_KEEP = (
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "WINDIR",
    "PATH",
    "PATHEXT",
    "COMSPEC",
    "TEMP",
    "TMP",
)


#: Added for the engine's own scorecard tool only: its git probes read the user's global gitconfig
#: (safe.directory, core.excludesFile) through these, so its engine= stamp matches a plain run.
_HOME_ENV_KEEP = ("HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH")


def child_env(*, home: bool = False) -> dict[str, str]:
    keep = _CHILD_ENV_KEEP + (_HOME_ENV_KEEP if home else ())
    env = {k: v for k, v in os.environ.items() if k.upper() in keep}
    return {**env, "LC_ALL": "C"}


def _run_python(argv: Sequence[str], cwd: Path | None, env: dict[str, str]) -> str:
    # -X utf8, not PYTHONUTF8: -I ignores every PYTHON* variable.
    return run_bytes([sys.executable, "-I", "-X", "utf8", *argv], cwd, env=env).decode(
        "utf-8", "replace"
    )


def run_child(argv: Sequence[str], cwd: Path | None = None) -> str:
    """Run the vault census driver: ``python -I -X utf8`` under :func:`child_env`, from ``cwd``
    (the archive root), so a relative write by the vault code never lands in the caller's work
    tree."""
    return _run_python(argv, cwd, child_env())


def run_tool_child(argv: Sequence[str], cwd: Path | None = None) -> str:
    """Run the engine's scorecard tool: ``python -I -X utf8`` under :func:`child_env` plus the
    home variables its git probes need, from ``cwd`` (the engine tree, which it stamps)."""
    return _run_python(argv, cwd, child_env(home=True))


def fetch_url(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:  # noqa: S310  # nosec B310 - fixed https URL
            body: bytes = resp.read()
            return body
    except OSError as exc:  # URLError and timeouts are OSError
        raise CollectError(f"GET {url} failed: {type(exc).__name__}: {exc}") from None


def is_transient(error: CollectError) -> bool:
    """Whether a failed ``gh`` call is worth another attempt; see :data:`_TRANSIENT`.

    A call that hit :data:`CMD_TIMEOUT` is not: a hung ``gh`` would hang again, and two more full
    timeouts would cost minutes for an answer already known.
    """
    # What the command SAID, never its argv; the message only for a command that could not run.
    text = error.stderr or str(error)
    return "TimeoutExpired" not in str(error) and _TRANSIENT.search(text) is not None


def gh_json(ctx: Context, args: Sequence[str]) -> Any:
    for attempt in range(1, GH_ATTEMPTS + 1):
        try:
            text = ctx.run(["gh", *args], None)
            break
        except CollectError as exc:
            if attempt == GH_ATTEMPTS or not is_transient(exc):
                raise
            # 2 s, then 8 s: a secondary rate limit needs more than a constant short wait.
            time.sleep(ctx.gh_backoff * 4 ** (attempt - 1))
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
class Census:
    """The vault census as the driver printed it, with the vault vocabulary it was read in."""

    rows: int
    weeks: dict[str, dict[str, int]]
    undated: dict[str, int]
    open_by_verdict: dict[str, int]
    active_verdicts: list[str]
    deferred_verdict: str
    activity: list[str]

    @property
    def open_rows(self) -> int:
        return sum(self.open_by_verdict.values())

    def require(self, columns: Sequence[str] = (), verdicts: Sequence[str] = ()) -> None:
        """Refuse a key the vault no longer defines: a renamed column would otherwise read 0."""
        missing = [c for c in columns if c not in self.activity]
        missing += [v for v in verdicts if v not in self.active_verdicts]
        if missing:
            raise CollectError(f"the vault census no longer defines {missing}")


@dataclass
class VaultRead:
    sha: str
    root: Path
    census: Census


VAULT_DRIVER = Path(__file__).resolve().parent / "_vault_census.py"


@dataclass
class Context:
    vault: Path
    through: dt.date
    weeks: int
    workdir: Path
    run: Runner = run_cmd
    run_raw: BytesRunner = run_bytes
    #: Runs the vault census driver in a child process; see :func:`run_child`.
    run_vault: Callable[[Sequence[str], Path | None], str] = run_child
    #: Runs the engine's scorecard tool isolated too; see :func:`run_tool_child`.
    run_tool: Callable[[Sequence[str], Path | None], str] = run_tool_child
    fetch: Fetcher = fetch_url
    #: False when the caller already fetched both repositories' main this run.
    git_fetch: bool = True
    #: The tree the engine scripts are run and imported from.
    engine_root: Path = ENGINE_ROOT
    #: The engine git checkout for the release distance.
    engine_repo: Path = ENGINE_ROOT
    #: The commit ``engine_root`` was ``git archive``d from, when it is no git checkout.
    archive_ref: str | None = None
    #: The stalled-PR checker's runner; None uses its own retrying `gh` runner.
    stall_runner: Callable[[list[str], float], str] | None = None
    today: dt.date = field(default_factory=lambda: dt.datetime.now(dt.UTC).date())
    gh_backoff: float = GH_BACKOFF_SECONDS
    merged_cache: dict[str, list[dict[str, Any]] | CollectError] = field(default_factory=dict)
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
                TypeError,
                AttributeError,
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


def _archive_into(ctx: Context, vault: str, sha: str, paths: Sequence[str], root: Path) -> None:
    # Literal pathspecs: a listed ledger name holding `*`, `?` or `[` archives that file alone.
    argv = ["git", "--literal-pathspecs", "-C", vault, "archive", "--format=tar", sha, "--"]
    tar_bytes = ctx.run_raw([*argv, *paths])
    with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tar:
        tar.extractall(root, filter="data")


def _driver(ctx: Context, mode: str, root: Path, *rest: str) -> dict[str, Any]:
    out = json.loads(ctx.run_vault([str(VAULT_DRIVER), mode, str(root), *rest], root))
    if not isinstance(out, dict):
        raise CollectError(f"the vault census driver printed {type(out).__name__}")
    return out


def _read_vault(ctx: Context) -> VaultRead:
    vault = str(ctx.vault)
    if ctx.git_fetch:
        ctx.run(["git", "-C", vault, "fetch", "-q", "--no-tags", "origin", MAIN_REFSPEC], None)
    sha = ctx.run(
        ["git", "-C", vault, "rev-parse", "--verify", "refs/remotes/origin/main^{commit}"], None
    )
    sha = sha.strip()
    if not _SHA40.fullmatch(sha):
        raise CollectError(f"vault origin/main resolved to {sha!r}, not a commit sha")
    # A fresh directory per attempt, so an uncaught failure retried by the next metric reports its
    # own cause, never a FileExistsError. RESOLVED, because the vault's read_sources labels a source
    # by path.resolve().relative_to(root): an unresolved temp path (a junction, an 8.3 short TEMP,
    # macOS /var) makes every label absolute, which its floors read as dropped files.
    root = Path(tempfile.mkdtemp(prefix="vault-", dir=ctx.workdir)).resolve()
    _archive_into(ctx, vault, sha, VAULT_PATHS, root)
    globs = _driver(ctx, "globs", root).get("ledger_file_globs")
    if not isinstance(globs, list) or not all(isinstance(g, str) for g in globs):
        raise CollectError("the vault census driver printed no ledger globs")
    # -z: a path git would otherwise quote (a space, a non-ASCII byte) comes back as written.
    tree = ctx.run(
        ["git", "-C", vault, "ls-tree", "-r", "-z", "--name-only", sha, "--", "docs"], None
    )
    ledger = [
        name
        for name in tree.split("\0")
        if name and any(PurePosixPath(name).full_match(g, case_sensitive=True) for g in globs)
    ]
    if not ledger:
        raise CollectError(f"no ledger file matches the checker's globs at vault {sha}")
    _archive_into(ctx, vault, sha, ledger, root)

    got = _driver(ctx, "census", root, ctx.through.isoformat())
    census = Census(
        rows=int(got["rows"]),
        weeks={str(w): {str(k): int(v) for k, v in c.items()} for w, c in got["weeks"].items()},
        undated={str(k): int(v) for k, v in got["undated"].items()},
        open_by_verdict={str(k): int(v) for k, v in got["open_by_verdict"].items()},
        active_verdicts=[str(v) for v in got["active_verdicts"]],
        deferred_verdict=str(got["deferred_verdict"]),
        activity=[str(c) for c in got["activity"]],
    )
    # The checker's anti-narrowing floors, reused: a dropped, emptied or unscanned ledger file, then
    # the row-count floor. The archive is no git top level, so the checker globs it from disk.
    if got["structural_errors"]:
        raise CollectError("; ".join(str(e) for e in got["structural_errors"]))
    if census.rows < int(got["min_total_items"]):
        raise CollectError(
            f"{census.rows} ledger rows read, below the floor of {got['min_total_items']}"
        )
    # The clip works only while the census dates through iso_week. A census that read rows but
    # never called it has stopped doing so, and would count past --through without a sound.
    if census.rows and not got["clip_calls"]:
        raise CollectError("the vault census never called iso_week, so --through was not applied")
    return VaultRead(sha=sha, root=root, census=census)


# --------------------------------------------------------------------------------------------------
# Collectors, in snapshot order. Each fills a Metric or raises; `collect` isolates them.
# --------------------------------------------------------------------------------------------------


def c_backlog_burn(ctx: Context, m: Metric) -> None:
    v = ctx.vault_read()
    c = v.census
    c.require(columns=("filed", "closed", "declined", "superseded"))
    labels = ctx.labels
    filed_series: list[dict[str, Any]] = []
    closed_series: list[dict[str, Any]] = []
    for w in labels:
        got = c.weeks.get(w, {})
        filed_series.append({"week": w, "value": got.get("filed", 0)})
        closed_series.append(
            {
                "week": w,
                "value": sum(got.get(k, 0) for k in ("closed", "declined", "superseded")),
            }
        )
    filed = sum(int(p["value"]) for p in filed_series)
    closed = sum(int(p["value"]) for p in closed_series)
    active = sum(c.open_by_verdict.get(k, 0) for k in c.active_verdicts)
    deferred = c.open_by_verdict.get(c.deferred_verdict, 0)
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
        # Whatever is neither active nor deferred, so no bucket name of the vault's is assumed.
        "open_unclassified": c.open_rows - active - deferred,
        "rows_total": c.rows,
        "undated": dict(c.undated),
        "series_is": "closed minus filed, per week",
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
    """Every PR merged in the window, cached per repo so two metrics share one read.

    A failure is cached too, like the vault read: a second metric would only repeat it, slower.
    """
    if repo not in ctx.merged_cache:
        try:
            ctx.merged_cache[repo] = list_per_week(
                ctx,
                ["pr", "list", "-R", repo, "--state", "merged"]
                + ["--json", "number,createdAt,mergedAt"],
                lambda lo, hi: ["--search", f"merged:{lo.isoformat()}..{hi.isoformat()}"],
            )
        except CollectError as exc:
            ctx.merged_cache[repo] = exc
    cached = ctx.merged_cache[repo]
    if isinstance(cached, CollectError):
        raise cached
    return cached


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


def c_flow_health(ctx: Context, m: Metric) -> None:
    rows = gh_list(
        ctx, ["pr", "list", "-R", ENGINE_REPO, "--state", "open", "--json", "number,createdAt"]
    )
    # Open PRs are today's set, so their ages are measured from now, never from --through: a past
    # --through would give a PR opened after it a negative age.
    now = dt.datetime.now(dt.UTC)
    ages = [(now - parse_stamp(r["createdAt"])).total_seconds() / 86400 for r in rows]
    oldest_raw = max(ages) if ages else None
    oldest = None if oldest_raw is None else round(oldest_raw, 1)
    detail: dict[str, Any] = {
        "open_prs": len(rows),
        "oldest_open_days": oldest,
        "median_open_to_merge_hours": None,
        "merged_prs_measured": None,
    }

    # The merged-PR read feeds only the time-to-merge fields, so its failure nulls those alone.
    try:
        hours = [
            (parse_stamp(r["mergedAt"]) - parse_stamp(r["createdAt"])).total_seconds() / 3600
            for r in merged_prs(ctx, ENGINE_REPO)
            if r.get("mergedAt") and r.get("createdAt")
        ]
        detail["median_open_to_merge_hours"] = round(statistics.median(hours), 1) if hours else None
        detail["merged_prs_measured"] = len(hours)
    except (CollectError, ValueError, TypeError, KeyError, AttributeError) as exc:
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
    # Banded on the raw age, so 7.04 days never rounds into the 7-day band.
    m.status = status_flow(oldest_raw, stalled)
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
    red: int | None = None
    red_for_status: int | None = 0
    red_error: str | None = None
    if current:
        # An optional part: its failure caps the status at warn and never nulls the pass rate.
        try:
            red = red_for_status = len(
                gh_list(
                    ctx,
                    ["pr", "list", "-R", ENGINE_REPO, "--state", "open", "--label", "ci-red"]
                    + ["--json", "number"],
                )
            )
        except CollectError as exc:
            red_for_status = None
            red_error = f"ci-red count: {exc}"
    labels = ctx.labels
    series = ci_pass_series(runs, labels)
    week = last_full_week(ctx.through, labels, ctx.today)
    m.value = series_value(series, week)
    m.status = status_ci(m.value, red_for_status)
    m.series = series
    m.detail = {
        "workflow_file": "ci.yml (the workflow named CI), push events on main only",
        "value_week": week,
        "runs_read": len(runs),
        "counted": "success passes; failure, timed_out, startup_failure, action_required fail; "
        "cancelled, skipped and in-progress runs are not counted",
        "open_ci_red_prs": red,
        "open_ci_red_prs_as_of": "run time"
        if current
        else "not read: --through is in the past and the label count is current state only",
    }
    if red_error:
        add_partial(m.detail, red_error)
    if m.value is None:
        m.error = f"no finished pass/fail run of main in {week}"


def c_asvs(ctx: Context, m: Metric) -> None:
    v = ctx.vault_read()
    # Archived here, not with the ledger: a moved scorecard must null this metric alone.
    _archive_into(ctx, str(ctx.vault), v.sha, [VAULT_SCORECARD], v.root)
    toml = v.root / VAULT_SCORECARD
    # Under -I and the allowlisted child environment plus the home variables (run_tool_child), not
    # the vault code's narrower one: no PYTHON* variable and no token variable reaches the tool.
    out = ctx.run_tool(
        [
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
    pass_pct = 100.0 * counts.get("pass", 0) / applicable if applicable else None
    provenance = [ln for ln in lines if ln.startswith("#")]
    engine_ref = asvs_engine_ref(provenance)
    tool = (
        "scripts/asvs/scorecard.py from the tree this collector runs from, whose ref engine= names"
    )
    if (
        engine_ref is not None
        and "NO-GIT" in engine_ref
        and ctx.archive_ref
        and re.fullmatch(r"[0-9a-f]{7,40}", ctx.archive_ref)
    ):
        # The tool ran from a git archive, so it could not stamp its own tree; the caller archived
        # that tree from this commit, and says so.
        engine_ref = f"{ctx.archive_ref}+archive"
        tool = f"scripts/asvs/scorecard.py from a git archive of engine commit {ctx.archive_ref}"
    m.value = None if pass_pct is None else floor_pct(counts.get("pass", 0), applicable)
    # Banded on the raw rate, so a value just under a threshold never rounds up into it.
    m.status = status_pct(pass_pct, "asvs")
    if pass_pct is None:
        m.error = f"the scorecard has no applicable cell: {counts}"

    m.detail = {
        "counts": counts,
        "value_means": "pass cells over cells not marked na; needs-review and unverified cells, "
        "which carry no verdict, are in that denominator and are not passes; cells decided "
        "with no last_verified count as decided",
        "provenance": provenance,
        "scorecard_sha": v.sha,
        "engine_ref": engine_ref,
        "scorecard_ref": f"vault origin/main {v.sha} (archived, so the tool prints NO-GIT)",
        "tool": tool,
        "history": "none: --status reads one ref and keeps no history",
        "state_as_of": "run time; --through does not apply",
    }
    if not {"needs-review", "unverified"} <= counts.keys():
        # The headline is shown only beside these counts; a cells line without them is drift, and
        # the headline is withheld here, at the source, not only on the page.
        m.value, m.status = None, "unknown"
        add_partial(m.detail, "scorecard cells line lacks a needs-review or unverified count")
    if engine_ref is None:
        # A score is quoted only beside its ref pair; without the engine half it cannot be.
        add_partial(m.detail, "scorecard provenance printed no engine= ref")
    elif "NO-GIT" in engine_ref or engine_ref.endswith(("+status-unknown", "+dirty")):
        # +dirty is a measurement against uncommitted changes: not reproducible from the ref.
        add_partial(
            m.detail, f"scorecard provenance names no attributable ref: engine={engine_ref}"
        )


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
        add_partial(m.detail, f"vuln-metrics KPIs: {kpis['error']}")


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
        if not run_id.isascii() or not run_id.isdigit():
            raise CollectError(f"vuln-metrics run id {run_id!r} is not a number")
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
    v.census.require(verdicts=("owner-ruling",))
    n = int(v.census.open_by_verdict.get("owner-ruling", 0))
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
    if not _VERSION.fullmatch(version):
        raise CollectError(f"PyPI version {version!r} is not a canonical release version")
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
    root = str(ctx.engine_repo)
    if ctx.git_fetch:
        ctx.run(["git", "-C", root, "fetch", "-q", "--no-tags", "origin", MAIN_REFSPEC], None)
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
    if not _SHA40.fullmatch(sha):
        raise CollectError(f"tag {tag} resolved to {sha!r}, not a commit sha")
    count = int(
        ctx.run(
            ["git", "-C", root, "rev-list", "--count", f"{sha}..refs/remotes/origin/main"], None
        )
    )
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
        f"gh run list -R {ENGINE_REPO} --branch main --workflow ci.yml --event push "
        "--json conclusion,createdAt; "
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


#: git's whole stderr for a directory in no repository, under LC_ALL=C: the one failure that
#: means "safe". Matched against stderr alone and in full, never against the message, which also
#: carries the probed path. A bare "not a git repository" is also git's answer for a pruned
#: worktree's gitdir or a bad GIT_DIR, which ARE inside a repository's tree.
_NO_REPO = re.compile(r"fatal: not a git repository \(or any of the parent directories\): \.git")

#: The probes :func:`refuse_dir_reason` runs: GIT_* dropped, then the caller's own environment.
PROBES: tuple[Runner, ...] = (run_probe, run_real_probe)


def refuse_reason(out: Path, runs: Sequence[Runner] = PROBES) -> str | None:
    """Why the file ``out`` may not be written, or ``None``; see :func:`refuse_dir_reason`."""
    return refuse_dir_reason(out.resolve().parent, runs)


def refuse_dir_reason(parent: Path, runs: Sequence[Runner] = PROBES) -> str | None:
    """Why no file may be written in the directory ``parent``, or ``None``. Fails CLOSED when git
    cannot answer.

    Each runner in ``runs`` asks git from ``parent``; any one that finds a repository, or cannot
    answer, refuses. The default pair is :func:`run_probe`, so no ``GIT_*`` variable in the
    caller's environment can hide a repository, and :func:`run_real_probe`, so a ``GIT_DIR`` or
    ``GIT_WORK_TREE`` the caller set is seen too. What this does not catch is in the module
    docstring. The caller passes the directory it will write into, already resolved.
    """
    if not parent.is_dir():
        return f"{parent} is not an existing directory"
    for run in runs:
        try:
            argv = ["git", "-C", str(parent), "rev-parse", "--is-inside-work-tree"]
            answer = run(argv, None).strip()
        except CollectError as exc:
            if _NO_REPO.fullmatch(exc.stderr.strip()):
                continue
            return f"cannot tell whether {parent} is inside a git repository: {exc}"
        # "true" is a work tree; "false" is inside a .git directory. Both are a repository.
        return f"{parent} is inside a git repository (rev-parse said {answer!r}); it is private"
    return None


def nearest_existing(path: Path) -> Path:
    """``path``, or its nearest ancestor that exists."""
    while not path.exists() and path.parent != path:
        path = path.parent
    return path


def refuse_out_dir(out: Path) -> str | None:
    """:func:`refuse_dir_reason` for a directory that may not exist yet, checked at its nearest
    existing ancestor BEFORE anything is created, so a refusal leaves nothing behind."""
    return refuse_dir_reason(nearest_existing(out.resolve()).resolve())


def write_json_atomic(out: Path, payload: Any) -> None:
    """Write ``payload`` as strict JSON with :func:`write_text_atomic`. A NaN or infinity raises
    rather than write invalid JSON."""
    write_text_atomic(out, json.dumps(payload, indent=2, allow_nan=False) + "\n")


def write_text_atomic(out: Path, text: str) -> None:
    """Write ``text`` through a sibling temporary file, so a reader never sees half. The temporary
    name is fresh (``mkstemp``), so a planted link or a concurrent run cannot redirect it."""
    fd, name = tempfile.mkstemp(prefix=out.name + ".", suffix=".tmp", dir=out.parent)
    tmp = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        tmp.replace(out)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def remove_tree(path: Path) -> bool:
    """Remove a temporary tree; each path that will not go is reported on stderr. False when any
    did not, so the caller can fail the run: the tree holds private vault files."""
    failed = False

    def report(func: Callable[..., Any], target: str, exc: BaseException) -> None:
        nonlocal failed
        failed = True
        print(
            f"ERROR: could not remove temporary {target}: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )

    shutil.rmtree(path, onexc=report)
    return not failed


#: A leftover work directory older than this is a killed run's, never a live one: the scheduled
#: task stops a run at 30 minutes.
STALE_SECONDS = 2 * 3600


def sweep_stale(base: Path, prefix: str, now: float | None = None) -> bool:
    """Remove ``base/<prefix>*`` directories older than :data:`STALE_SECONDS`. False when one that
    should have gone is still there: it holds private vault files, so the caller fails the run."""
    cutoff = (time.time() if now is None else now) - STALE_SECONDS
    ok = True
    for old in base.glob(f"{prefix}*"):
        try:
            if old.is_dir() and not old.is_symlink() and old.stat().st_mtime < cutoff:
                ok = remove_tree(old) and ok
        except OSError as exc:
            print(f"ERROR: could not sweep {old}: {type(exc).__name__}: {exc}", file=sys.stderr)
            ok = False
    return ok


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--vault", type=Path, required=True, help="the vault checkout (read at origin/main)"
    )
    ap.add_argument("--out", type=Path, required=True, help="snapshot JSON path, outside any repo")
    ap.add_argument(
        "--engine-repo",
        type=Path,
        default=ENGINE_ROOT,
        help="the engine git checkout for the release distance (default: the checkout this "
        "script sits in)",
    )
    ap.add_argument(
        "--archive-ref",
        default=None,
        metavar="SHA",
        help="the engine commit this script's tree was git-archived from, when it is no checkout",
    )
    ap.add_argument(
        "--work-dir",
        type=Path,
        default=None,
        help="where the run's private mf-metrics-* directory goes (default: Python's temp dir)",
    )
    ap.add_argument(
        "--no-fetch",
        action="store_true",
        help="the caller already fetched origin main in the vault and the engine checkout",
    )
    ap.add_argument("--weeks", type=int, default=8, help="ISO weeks in the window (default 8)")
    ap.add_argument(
        "--through",
        type=dt.date.fromisoformat,
        default=None,
        metavar="YYYY-MM-DD",
        help="last day of the window (default: today, UTC)",
    )
    args = ap.parse_args(argv)
    # Error text can quote a ledger line or a git message; a cp1252 console must not raise on it.
    for stream in (sys.stdout, sys.stderr):
        if isinstance(stream, io.TextIOWrapper):
            stream.reconfigure(encoding="utf-8", errors="replace")
    # At least two, so the window always holds one complete week for the weekly values.
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
    base = (args.work_dir or Path(tempfile.gettempdir())).resolve()
    reason = refuse_dir_reason(base)
    if reason is not None:
        print(f"ERROR: refusing work dir {base}: {reason}", file=sys.stderr)
        return 1
    swept = sweep_stale(base, "mf-metrics-")
    tmp = Path(tempfile.mkdtemp(prefix="mf-metrics-", dir=base))
    cleaned = False
    try:
        ctx = Context(
            vault=args.vault,
            through=through,
            weeks=args.weeks,
            workdir=tmp,
            today=today,
            # Resolved once, so a relative path names the same tree for every git call.
            engine_repo=args.engine_repo.resolve(),
            archive_ref=args.archive_ref,
            git_fetch=not args.no_fetch,
        )
        metrics = collect(ctx)
        write_json_atomic(out, snapshot(ctx, metrics))
    finally:
        # A cleanup failure never discards a finished run, but it fails it (exit 3).
        cleaned = remove_tree(tmp)
    # Id, status and an error flag only: values and error text stay in the private snapshot, never
    # in a transcript or a log that captures stdout.
    for m in metrics:
        flag = "error" if m.error else "partial" if m.detail.get("partial_error") else "ok"
        print(f"{m.id}: status={m.status} read={flag}")
    # 3 when anything could not be read, after the snapshot is written: an outage goes red.
    partial = any(m.error or m.detail.get("partial_error") for m in metrics)
    return 3 if partial or not cleaned or not swept else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
