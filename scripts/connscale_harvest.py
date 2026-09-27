#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Harvest the connscale empty-claims BASE READINGS from CI, joined to each job's conclusion.

BACKLOG #1415, build 1 of 2. **This is a scan, not a gate.** It computes no floor, proposes no
threshold and applies no arming rule. Build 2 does that, once post-#1420 data exists and the owner
has ruled. What this script owes build 2 is a distribution a reader can audit and re-run, which the
#1211 harvest was not: that one was drawn by a script outside the tree, into a scratchpad, against
artifacts that expire.

WHAT IT READS. Every ``test (<os>, py<ver>)`` job of the CI workflow uploads its connscale readings
as an artifact named ``connscale-readings-<os>-py<ver>``, holding ``empty_claims.json``. The base
reading is each lane's ``herd_floor.readings[].value`` in that payload. The job's conclusion comes
from the Actions jobs API, never from the payload, because a payload is written before any
assertion runs and so cannot say whether its own job passed.

THE THREE RULES THAT MAKE IT A HARVEST RATHER THAN A SAMPLE.

1. **A job with no readable artifact is UNKNOWN AND ADVERSE, and is counted.** 23.5 percent of the
   #1211 scan had no artifact, mostly cancelled runs. A cancelled or hung run is where a degenerate
   base reading would live, so dropping those runs removes the very cases a floor would grade.
   A missing or unreadable artifact lands here, with the job conclusion beside it. Two cases are
   excluded instead, each by a fact rather than a guess: the job or its ``Tests (pytest)`` step was
   SKIPPED (a scheduled run skips the step by design, so no sweep ran), or the run predates PR 729.
2. **Every (leg, lane, N) cell stands alone.** The leg is the job's own matrix identity, so the two
   Windows legs are two legs and are never pooled, and neither is a second Python on one OS. N is
   the payload's own base count, so a change to the sweep's counts cannot pool two distributions.
3. **Two populations, never mixed.** A payload carrying ``rate_window = "in_hold_excl_drain"`` was
   written after BACKLOG #1420 narrowed the rate window. A payload without it is WITH-TAIL data,
   and counts as that only from a run created after PR 729 (``541c51910``, 2026-09-01T13:01:20Z),
   the commit that added the ``herd_floor`` block. Pass ``--with-tail-until`` once #1420 has
   landed, so a payload that lost the field fails closed rather than joining the with-tail cells.
   Anything else is excluded and counted by reason.

THE JOIN. An artifact names its leg but not its attempt, and a re-run attempt is a separate engine
run. So each artifact is joined to the same-leg job whose run time contains the artifact's creation
time, across every attempt. An artifact no job window contains is listed as unjoined, not guessed.

A HARVESTER FAILURE IS NOT A CI FAILURE. A download that fails twice, or an artifact that has
expired, is ``reader_error``: the artifact's record proves the sweep wrote a payload, so its loss says
when this harvest ran, not how CI went. It is reported as an incomplete harvest (exit code 3), and
never added to the unknown-and-adverse count build 2 will grade. So is a run listing that may have
hit the API's 1,000-result limit. A re-run attempt of "failed jobs only" lists each untouched leg a
second time under a new id with the same run time; that copy is counted once, not twice.

WHAT IT DOES NOT CHECK. The #1415 prerequisite that ``MEFOR_PIPELINE_PER_LANE_WAKE`` is pinned for
every counted run is not observable in the payload. The output says so on every run.

AUTH. Every call goes through ``gh api``, so the token stays inside gh's own login. This script
never reads, prints or stores one.

Usage (PowerShell 7)::

    python scripts/connscale_harvest.py --since 2026-09-01T13:01:20Z --max-runs 20
    python scripts/connscale_harvest.py --since 2026-09-20T00:00:00Z --json-out out/harvest.json
"""

from __future__ import annotations

import argparse
import io
import json
import math
import re
import statistics
import subprocess
import sys
import zipfile
from collections import Counter
from collections.abc import Iterator, Sequence
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlencode

DEFAULT_REPO = "MEFORORG/MessageFoundry"
DEFAULT_WORKFLOW = "ci.yml"
DEFAULT_BRANCH = "main"
ARTIFACT_PREFIX = "connscale-readings-"
READINGS_FILE = "empty_claims.json"
#: The ci.yml step that runs the suite, connscale sweep included. Skipped means no sweep ran.
SUITE_STEP = "Tests (pytest)"

#: The value BACKLOG #1420 writes into the payload once the rate window excludes the drain tail.
POST_1420_RATE_WINDOW = "in_hold_excl_drain"
#: PR 729 (``541c51910``) merged at this instant and added the ``herd_floor`` block. A with-tail
#: payload counts only from a run created after it. This is a fact about the data, not the
#: inclusion window, which is always an argument.
WITH_TAIL_FLOOR = datetime(2026, 9, 1, 13, 1, 20, tzinfo=UTC)
#: The three OS legs #1415 names. A leg missing from a harvest is flagged, never silently absent.
EXPECTED_OS_LEGS = ("ubuntu-latest", "windows-2022", "windows-2025")

POST_1420 = "post_1420"
WITH_TAIL = "with_tail"
POPULATIONS = (POST_1420, WITH_TAIL)

PASSED = "success"
HARVESTED = "harvested"
UNKNOWN_ADVERSE = "unknown_adverse"
EXCLUDED = "excluded"
READER_ERROR = "reader_error"

_JOB_NAME = re.compile(r"^test \((?P<os>[^,()]+), py(?P<py>[^()]+)\)$")
#: Clock slack for the artifact-to-job join, used only when no job window contains the artifact
#: outright. The upload is a step inside its job, so exact containment is the normal case.
_JOIN_SLACK = timedelta(seconds=120)
_PER_PAGE = 100
_API_LISTING_LIMIT = 1000
_GH_TIMEOUT_S = 180
_DOWNLOAD_ATTEMPTS = 2


class HarvestError(RuntimeError):
    """A GitHub API call failed. Raised rather than read as an empty result."""


class Api(Protocol):
    """The two GitHub calls the harvest makes. A fake stands in for it offline."""

    def get_json(self, path: str) -> Any: ...

    def get_bytes(self, path: str) -> bytes: ...


class GhApi:
    """``gh api`` over a subprocess, so auth comes from gh's existing login."""

    def _run(self, path: str) -> bytes:
        try:
            # nosec B603 B607 - fixed argv, no shell; `path` is an API route this module builds.
            proc = subprocess.run(  # noqa: S603  # nosec B603 B607
                ["gh", "api", path],
                capture_output=True,
                timeout=_GH_TIMEOUT_S,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise HarvestError(f"gh api {path}: {exc}") from exc
        if proc.returncode != 0:
            detail = proc.stderr.decode("utf-8", "replace").strip()
            raise HarvestError(f"gh api {path} exited {proc.returncode}: {detail}")
        return proc.stdout

    def get_json(self, path: str) -> Any:
        try:
            return json.loads(self._run(path))
        except ValueError as exc:
            raise HarvestError(f"gh api {path}: response is not JSON: {exc}") from exc

    def get_bytes(self, path: str) -> bytes:
        return self._run(path)


def parse_time(value: str) -> datetime:
    """An ISO 8601 instant; a bare value with no offset is read as UTC."""
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise ValueError(value)
    return number


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _paged(api: Api, path: str, query: dict[str, str], key: str) -> Iterator[dict[str, Any]]:
    """Every item of a paged list endpoint, page by page, until a short page."""
    page = 1
    while True:
        body = api.get_json(f"{path}?{urlencode({**query, 'per_page': _PER_PAGE, 'page': page})}")
        items = body.get(key) if isinstance(body, dict) else None
        if not isinstance(items, list) or not all(isinstance(i, dict) for i in items):
            raise HarvestError(f"{path}: response carries no '{key}' list of objects")
        yield from items
        if len(items) < _PER_PAGE:
            return
        page += 1


def leg_of_job(name: str) -> str | None:
    """``test (windows-2022, py3.14)`` -> ``windows-2022 py3.14``; any other job -> ``None``."""
    m = _JOB_NAME.match(name)
    return f"{m['os']} py{m['py']}" if m else None


def leg_of_artifact(name: str) -> str | None:
    """``connscale-readings-windows-2022-py3.14`` -> ``windows-2022 py3.14``."""
    if not name.startswith(ARTIFACT_PREFIX):
        return None
    os_name, sep, py = name.removeprefix(ARTIFACT_PREFIX).rpartition("-py")
    return f"{os_name} py{py}" if sep and os_name and py else None


def rate_window_of(payload: dict[str, Any]) -> str | None:
    """The payload's ``rate_window``, looked for at the top level, then ``herd_floor``, then ``context``.

    Where #1420 puts the field was not fixed when this was written, so all three places are read.
    Two DIFFERENT values in one payload are returned joined, so they classify as unrecognised rather
    than letting whichever was read first decide the population.
    """
    found: list[str] = []
    for holder in (payload, payload.get("herd_floor"), payload.get("context")):
        if isinstance(holder, dict) and "rate_window" in holder:
            found.append(str(holder["rate_window"]))
    distinct = sorted(set(found))
    if not distinct:
        return None
    return distinct[0] if len(distinct) == 1 else "|".join(distinct)


def classify(
    payload: dict[str, Any], run_created: datetime, with_tail_until: datetime | None = None
) -> tuple[str | None, str]:
    """``(population, reason)``. A ``None`` population means excluded, and ``reason`` says why.

    Keyed on the RUN's creation time, not the artifact's: a re-run of a pre-729 run uploads a fresh
    artifact from pre-729 code. The payload's own ``schema_version`` is checked as well, because a
    version-1 payload has no ``herd_floor`` block whatever its timestamp says.
    """
    version = payload.get("schema_version")
    if isinstance(version, int) and not isinstance(version, bool) and version < 2:
        return None, "schema 1 payload, from before PR 729"
    window = rate_window_of(payload)
    if window == POST_1420_RATE_WINDOW:
        return POST_1420, "rate_window=" + window
    if window is not None:
        return None, f"unrecognised rate_window {window!r}"
    if run_created <= WITH_TAIL_FLOOR:
        return None, "with-tail run from before PR 729"
    if with_tail_until is not None and run_created > with_tail_until:
        return None, "rate_window absent, run after --with-tail-until"
    return WITH_TAIL, "rate_window absent, after PR 729"


@dataclass(frozen=True)
class BaseReading:
    """One lane's base reading from one job. ``value`` is ``None`` when null or non-finite."""

    population: str
    leg: str
    lane: str
    count: int | None
    value: float | None
    job_conclusion: str
    run_id: int
    run_attempt: int
    job_id: int
    head_sha: str
    artifact_created_at: str


@dataclass(frozen=True)
class JobOutcome:
    """One connscale-carrying job and what the harvest made of it.

    ``status`` is ``harvested`` (readings taken), ``unknown_adverse`` (no readable artifact, counted
    against the leg), ``excluded`` (outside both populations, counted by reason) or ``reader_error``
    (this harvester could not download it; the harvest is incomplete).
    """

    leg: str
    conclusion: str
    status: str
    reason: str
    population: str | None
    run_id: int
    run_attempt: int
    job_id: int
    artifact_id: int | None


@dataclass
class Harvest:
    repo: str
    workflow: str
    branch: str
    since: str
    until: str
    #: The selection, recorded so the output alone is enough to re-run it.
    event: str | None = None
    max_runs: int | None = None
    with_tail_until: str | None = None
    runs_scanned: list[int] = field(default_factory=list)
    runs_not_completed: list[int] = field(default_factory=list)
    jobs: list[JobOutcome] = field(default_factory=list)
    readings: list[BaseReading] = field(default_factory=list)
    unjoined_artifacts: list[dict[str, Any]] = field(default_factory=list)
    #: Completed runs that carried no ``test (...)`` job at all, so no leg could have produced a
    #: reading. Listed rather than dropped, so a reader can see the runs the job table cannot.
    runs_without_test_jobs: list[int] = field(default_factory=list)
    #: Runs whose head repository is not ``repo``: a fork's pull request from its own ``main``
    #: matches ``branch=main`` but is not this repository's code. Listed, never scanned.
    runs_from_other_repos: list[int] = field(default_factory=list)
    #: Job rows a "re-run failed jobs" attempt listed again for a leg it did not re-run: same leg,
    #: same start and end, new id. Each is one engine run, so it is counted once, here.
    carried_over_job_copies: int = 0
    #: True when ``max_runs`` stopped the listing before the window was exhausted.
    stopped_at_max_runs: bool = False
    #: The runs endpoint returns at most 1,000 results for a filtered query. A listing that reached
    #: that many without the ``max_runs`` cap stopping it may be truncated, and says so.
    listing_may_be_truncated: bool = False


def _job_window(job: dict[str, Any]) -> tuple[datetime, datetime | None] | None:
    if not job.get("started_at"):
        return None
    completed = parse_time(job["completed_at"]) if job.get("completed_at") else None
    return parse_time(job["started_at"]), completed


def _join(artifact: dict[str, Any], jobs: Sequence[dict[str, Any]]) -> dict[str, Any] | None:
    """The same-leg job whose run time contains the artifact's creation time, or ``None``.

    Exact containment wins over slack. Otherwise a re-run starting within the slack of the previous
    attempt's end would take that attempt's artifact, and the earlier job -- often the failing one
    -- would read as artifact-less.
    """
    created = parse_time(artifact["created_at"])
    for slack in (timedelta(0), _JOIN_SLACK):
        best: tuple[datetime, dict[str, Any]] | None = None
        for job in jobs:
            window = _job_window(job)
            if window is None:
                continue
            started, completed = window
            inside = started - slack <= created and (
                completed is None or created <= completed + slack
            )
            if inside and (best is None or started > best[0]):
                best = (started, job)
        if best is not None:
            return best[1]
    return None


def _read_payload(api: Api, repo: str, artifact: dict[str, Any]) -> dict[str, Any] | str:
    """The artifact's ``empty_claims.json``, or the reason it could not be had.

    A download that fails every attempt returns ``reader_error``, which is this harvester's failure
    and not CI's. A payload that downloads but does not parse is CI's, and is unknown and adverse.
    """
    blob: bytes | None = None
    for attempt in range(1, _DOWNLOAD_ATTEMPTS + 1):
        try:
            blob = api.get_bytes(f"repos/{repo}/actions/artifacts/{artifact['id']}/zip")
            break
        except HarvestError as exc:
            print(f"download attempt {attempt} failed: {exc}", file=sys.stderr)
    if blob is None:
        return READER_ERROR
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            payload = json.loads(zf.read(READINGS_FILE))
    except (zipfile.BadZipFile, KeyError, ValueError, OSError):
        return "artifact unreadable"
    return payload if isinstance(payload, dict) else "artifact unreadable"


def _base_readings(
    payload: dict[str, Any],
) -> list[tuple[str, int | None, float | None]] | None:
    """``(lane, N, value)`` per ``herd_floor`` reading, or ``None`` when the block is unusable.

    An EMPTY readings list is unusable too: a sweep that recorded no lane is the degenerate case the
    harvest exists to count, and returning ``[]`` would file it as harvested with nothing in it.
    A non-finite value is kept as ``None``: it is a recorded reading with no usable magnitude, and
    letting a NaN into a sort would scramble every percentile after it.
    """
    block = payload.get("herd_floor")
    if not isinstance(block, dict):
        return None
    rows = block.get("readings")
    if not isinstance(rows, list) or not rows:
        return None
    base_count = block.get("base_count")
    out: list[tuple[str, int | None, float | None]] = []
    for row in rows:
        if not isinstance(row, dict) or "lane" not in row:
            return None
        value = row.get("value")
        if value is not None and (isinstance(value, bool) or not isinstance(value, int | float)):
            return None
        try:
            number = None if value is None else float(value)
        except OverflowError:
            number = None
        if number is not None and not math.isfinite(number):
            number = None
        count = row.get("count", base_count)
        valid_count = isinstance(count, int) and not isinstance(count, bool)
        out.append((str(row["lane"]), count if valid_count else None, number))
    return out


def _suite_skipped(job: dict[str, Any]) -> bool:
    """True when the job, or its suite step, was SKIPPED, so no connscale sweep ran in it."""
    if job.get("conclusion") == "skipped":
        return True
    steps = job.get("steps")
    if not isinstance(steps, list):
        return False
    return any(
        isinstance(s, dict) and s.get("name") == SUITE_STEP and s.get("conclusion") == "skipped"
        for s in steps
    )


def _unjoined(run_id: int, artifact: dict[str, Any], reason: str) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "artifact_id": artifact["id"],
        "name": artifact["name"],
        "reason": reason,
    }


def harvest_run(api: Api, repo: str, run: dict[str, Any], acc: Harvest) -> None:
    """Join one completed run's connscale jobs to its artifacts, appending to ``acc``."""
    run_id = int(run["id"])
    base = f"repos/{repo}/actions/runs/{run_id}"
    jobs_by_leg: dict[str, list[dict[str, Any]]] = {}
    seen_jobs: set[int] = set()
    seen_windows: set[tuple[str, str, str]] = set()
    listed = _paged(api, f"{base}/jobs", {"filter": "all"}, "jobs")
    # Lowest attempt first, so a carried-over copy is the one dropped and the original is kept.
    for listed_job in sorted(listed, key=lambda j: int(j.get("run_attempt") or 1)):
        leg = leg_of_job(str(listed_job.get("name", "")))
        if leg is None or int(listed_job["id"]) in seen_jobs:
            continue
        seen_jobs.add(int(listed_job["id"]))
        started, completed = listed_job.get("started_at"), listed_job.get("completed_at")
        if started and completed:
            window = (leg, str(started), str(completed))
            if window in seen_windows:
                acc.carried_over_job_copies += 1
                continue
            seen_windows.add(window)
        jobs_by_leg.setdefault(leg, []).append(listed_job)

    artifact_by_job: dict[int, dict[str, Any]] = {}
    for artifact in _paged(api, f"{base}/artifacts", {}, "artifacts"):
        leg = leg_of_artifact(str(artifact.get("name", "")))
        if leg is None:
            continue
        if not jobs_by_leg.get(leg):
            acc.unjoined_artifacts.append(_unjoined(run_id, artifact, "no job for its leg"))
            continue
        job = _join(artifact, jobs_by_leg[leg])
        if job is None:
            acc.unjoined_artifacts.append(_unjoined(run_id, artifact, "no job window contains it"))
            continue
        held = artifact_by_job.get(int(job["id"]))
        if held is not None:
            # Two artifacts on one job: keep the newer, and list the other rather than drop it.
            if parse_time(artifact["created_at"]) > parse_time(held["created_at"]):
                held, artifact = artifact, held
            acc.unjoined_artifacts.append(_unjoined(run_id, artifact, "superseded on its job"))
            artifact = held
        artifact_by_job[int(job["id"])] = artifact

    if not jobs_by_leg:
        acc.runs_without_test_jobs.append(run_id)
    for leg, jobs in sorted(jobs_by_leg.items()):
        for job in jobs:
            acc.jobs.append(_harvest_job(api, repo, run, leg, job, artifact_by_job, acc))


def _harvest_job(
    api: Api,
    repo: str,
    run: dict[str, Any],
    leg: str,
    job: dict[str, Any],
    artifact_by_job: dict[int, dict[str, Any]],
    acc: Harvest,
) -> JobOutcome:
    job_id = int(job["id"])
    conclusion = str(job.get("conclusion") or job.get("status") or "unknown")
    attempt = int(job.get("run_attempt") or run.get("run_attempt") or 1)
    artifact = artifact_by_job.get(job_id)
    run_created = parse_time(run["created_at"])
    with_tail_until = parse_time(acc.with_tail_until) if acc.with_tail_until else None

    def outcome(status: str, reason: str, population: str | None = None) -> JobOutcome:
        return JobOutcome(
            leg=leg,
            conclusion=conclusion,
            status=status,
            reason=reason,
            population=population,
            run_id=int(run["id"]),
            run_attempt=attempt,
            job_id=job_id,
            artifact_id=None if artifact is None else int(artifact["id"]),
        )

    def adverse(reason: str) -> JobOutcome:
        # Before PR 729 no payload carried a base reading, so a missing one hides nothing. The run's
        # time decides, the same time base `classify` uses, so one old run cannot land both ways.
        if run_created <= WITH_TAIL_FLOOR:
            return outcome(EXCLUDED, f"{reason}, run from before PR 729")
        return outcome(UNKNOWN_ADVERSE, reason)

    if artifact is None:
        if _suite_skipped(job):
            return outcome(EXCLUDED, f"no artifact, job or {SUITE_STEP} step skipped")
        return adverse("no artifact")
    if artifact.get("expired"):
        # The artifact record proves the sweep wrote a payload (the upload ignores a missing file),
        # so expiry says when this harvest ran, not how CI went. It is an incomplete read.
        return outcome(READER_ERROR, "artifact expired")
    payload = _read_payload(api, repo, artifact)
    if payload == READER_ERROR:
        return outcome(READER_ERROR, "artifact download failed")
    if isinstance(payload, str):
        return adverse(payload)
    population, reason = classify(payload, run_created, with_tail_until)
    if population is None:
        return outcome(EXCLUDED, reason)
    rows = _base_readings(payload)
    if rows is None:
        return adverse("payload carries no usable herd_floor readings")
    created = _iso(parse_time(artifact["created_at"]))
    for lane, count, value in rows:
        acc.readings.append(
            BaseReading(
                population=population,
                leg=leg,
                lane=lane,
                count=count,
                value=value,
                job_conclusion=conclusion,
                run_id=int(run["id"]),
                run_attempt=attempt,
                job_id=job_id,
                head_sha=str(run.get("head_sha", ""))[:9],
                artifact_created_at=created,
            )
        )
    return outcome(HARVESTED, reason, population)


def harvest(
    api: Api,
    *,
    repo: str,
    workflow: str,
    branch: str,
    since: datetime,
    until: datetime,
    max_runs: int | None = None,
    event: str | None = None,
    with_tail_until: datetime | None = None,
    progress: bool = False,
) -> Harvest:
    """Scan the workflow's runs on ``branch`` created in ``[since, until]``, newest first.

    ``max_runs`` caps the COMPLETED runs scanned. It never selects on whether a run carries
    artifacts: a pool chosen by that outcome could not report the missingness it exists to count.
    """
    result = Harvest(
        repo,
        workflow,
        branch,
        _iso(since),
        _iso(until),
        event=event,
        max_runs=max_runs,
        with_tail_until=None if with_tail_until is None else _iso(with_tail_until),
    )
    query = {"branch": branch, "created": f"{_iso(since)}..{_iso(until)}"}
    if event:
        query["event"] = event
    path = f"repos/{repo}/actions/workflows/{workflow}/runs"
    listed = 0
    seen_runs: set[int] = set()
    for run in _paged(api, path, query, "workflow_runs"):
        listed += 1
        run_id = int(run["id"])
        if run_id in seen_runs:
            continue  # a run that moved between pages while the listing was read
        seen_runs.add(run_id)
        head_repo = run.get("head_repository")
        head_name = head_repo.get("full_name") if isinstance(head_repo, dict) else None
        if head_name is not None and str(head_name).lower() != repo.lower():
            result.runs_from_other_repos.append(run_id)
            continue
        if run.get("status") != "completed":
            result.runs_not_completed.append(run_id)
            continue
        if max_runs is not None and len(result.runs_scanned) >= max_runs:
            result.stopped_at_max_runs = True
            break
        if progress:
            print(f"run {run_id} ({run.get('created_at')})", file=sys.stderr)
        harvest_run(api, repo, run, result)
        result.runs_scanned.append(run_id)
    result.listing_may_be_truncated = (
        not result.stopped_at_max_runs and listed >= _API_LISTING_LIMIT
    )
    return result


def nearest_rank(sorted_values: Sequence[float], pct: float) -> float:
    """The nearest-rank percentile: no interpolation, so every figure is a recorded reading."""
    rank = max(1, math.ceil(pct / 100.0 * len(sorted_values)))
    return sorted_values[rank - 1]


@dataclass(frozen=True)
class CellSummary:
    population: str
    leg: str
    lane: str
    count: int | None
    n_passing: int
    min: float | None
    p1: float | None
    p5: float | None
    median: float | None
    n_non_passing: int
    #: Readings with no usable value, split by whether their job passed: a passing job's null is a
    #: degenerate reading that left the distribution, which a failed job's null is not.
    n_no_value_passing: int
    n_no_value_non_passing: int


def summarise(result: Harvest) -> list[CellSummary]:
    """Per (population, leg, lane, N): the distribution over PASSING jobs, plus what it left out."""
    cells: dict[tuple[str, str, str, int | None], list[BaseReading]] = {}
    for r in result.readings:
        cells.setdefault((r.population, r.leg, r.lane, r.count), []).append(r)
    out: list[CellSummary] = []
    for (population, leg, lane, count), rows in sorted(
        cells.items(), key=lambda kv: (kv[0][:3], -1 if kv[0][3] is None else kv[0][3])
    ):
        passing = sorted(
            r.value for r in rows if r.job_conclusion == PASSED and r.value is not None
        )
        out.append(
            CellSummary(
                population=population,
                leg=leg,
                lane=lane,
                count=count,
                n_passing=len(passing),
                min=passing[0] if passing else None,
                p1=nearest_rank(passing, 1) if passing else None,
                p5=nearest_rank(passing, 5) if passing else None,
                # median_low, so the median is a recorded reading like every other figure here.
                median=statistics.median_low(passing) if passing else None,
                n_non_passing=sum(1 for r in rows if r.job_conclusion != PASSED),
                n_no_value_passing=sum(
                    1 for r in rows if r.value is None and r.job_conclusion == PASSED
                ),
                n_no_value_non_passing=sum(
                    1 for r in rows if r.value is None and r.job_conclusion != PASSED
                ),
            )
        )
    return out


def leg_accounting(result: Harvest) -> dict[str, Counter[tuple[str, str, str]]]:
    """Per leg: jobs counted by ``(status, reason, conclusion)``, so no job leaves silently."""
    out: dict[str, Counter[tuple[str, str, str]]] = {}
    for j in result.jobs:
        out.setdefault(j.leg, Counter())[(j.status, j.reason, j.conclusion)] += 1
    return out


def missing_expected_legs(result: Harvest) -> list[str]:
    """The expected OS legs no scanned job belonged to."""
    seen = {j.leg.split(" ", 1)[0] for j in result.jobs}
    return [leg for leg in EXPECTED_OS_LEGS if leg not in seen]


def _fmt(value: float | None) -> str:
    """Display precision only; ``--json-out`` carries every value exactly."""
    return "-" if value is None else f"{value:.6g}"


def _cell(value: object) -> str:
    """A markdown table cell. A pipe in payload-derived text would otherwise shift the columns."""
    return str(value).replace("|", "\\|").replace("\n", " ")


def is_complete(result: Harvest) -> bool:
    """False when this harvester, not CI, left something unread or unlisted."""
    return not result.listing_may_be_truncated and not any(
        j.status == READER_ERROR for j in result.jobs
    )


def render_markdown(result: Harvest) -> str:
    cap = "none" if result.max_runs is None else str(result.max_runs)
    lines = [
        "# connscale base-reading harvest (BACKLOG #1415, build 1: no gate)",
        "",
        f"repo {result.repo}, workflow {result.workflow}, branch {result.branch}, "
        f"event {result.event or 'any'}",
        f"window {result.since} .. {result.until} (run creation time); "
        f"with-tail ceiling {result.with_tail_until or 'none'}",
        f"runs scanned: {len(result.runs_scanned)} (max-runs {cap}"
        f"{', STOPPED BY IT' if result.stopped_at_max_runs else ''}); "
        f"runs not completed, not scanned: {len(result.runs_not_completed)} "
        f"{result.runs_not_completed}",
        f"scanned runs with no test job at all: {len(result.runs_without_test_jobs)} "
        f"{result.runs_without_test_jobs}",
        f"runs from another head repository, not scanned: {len(result.runs_from_other_repos)} "
        f"{result.runs_from_other_repos}",
        f"carried-over job copies from re-run attempts, counted once: "
        f"{result.carried_over_job_copies}",
        "MEFOR_PIPELINE_PER_LANE_WAKE pin: NOT VERIFIED by this scan; the payload does not record it.",
        "",
    ]
    if result.listing_may_be_truncated:
        lines += [
            "WARNING: the run listing reached the API's 1,000-result limit; narrow the window.",
            "",
        ]
    reader_errors = sum(1 for j in result.jobs if j.status == READER_ERROR)
    if reader_errors:
        lines += [
            f"WARNING: INCOMPLETE HARVEST. {reader_errors} artifact(s) exist but could not be "
            "read here (expired, or failed to download); they are not counted as CI outcomes.",
            "",
        ]
    missing = missing_expected_legs(result)
    if missing:
        lines += [f"WARNING: no job found for expected leg(s): {', '.join(missing)}", ""]
    lines += ["## Jobs per leg, by what the harvest made of them", ""]
    lines += ["| leg | status | reason | job conclusion | jobs |", "|---|---|---|---|---:|"]
    for leg, counts in sorted(leg_accounting(result).items()):
        for (status, reason, conclusion), n in sorted(counts.items()):
            lines.append(
                f"| {_cell(leg)} | {status} | {_cell(reason)} | {_cell(conclusion)} | {n} |"
            )
    lines.append("")
    unknown = Counter(j.leg for j in result.jobs if j.status == UNKNOWN_ADVERSE)
    summaries = summarise(result)
    for population in POPULATIONS:
        lines += [f"## Population {population}", ""]
        cells = [c for c in summaries if c.population == population]
        if not cells:
            lines += ["No readings in this population.", ""]
            continue
        lines += [
            "Distribution over PASSING jobs only. `unknown adverse` is per leg and belongs to no "
            "population: an artifact-less job cannot say which one it would have been.",
            "",
            "| leg | lane | N | n passing | min | p1 | p5 | median (low) | n non-passing "
            "| no value, passing | no value, non-passing | unknown adverse (leg) |",
            "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
        for c in cells:
            lines.append(
                f"| {_cell(c.leg)} | {_cell(c.lane)} | {'-' if c.count is None else c.count} "
                f"| {c.n_passing} | {_fmt(c.min)} | {_fmt(c.p1)} | {_fmt(c.p5)} "
                f"| {_fmt(c.median)} | {c.n_non_passing} | {c.n_no_value_passing} "
                f"| {c.n_no_value_non_passing} | {unknown.get(c.leg, 0)} |"
            )
        lines.append("")
    if result.unjoined_artifacts:
        lines += [f"Unjoined artifacts: {len(result.unjoined_artifacts)}", ""]
        lines += [
            f"- run {a['run_id']}: {_cell(a['name'])} ({a['reason']})"
            for a in result.unjoined_artifacts
        ]
        lines.append("")
    return "\n".join(lines)


def to_json_dict(result: Harvest) -> dict[str, Any]:
    return {
        **asdict(result),
        "complete": is_complete(result),
        "per_lane_wake_pin_verified": False,
        "cells": [asdict(c) for c in summarise(result)],
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument(
        "--since", required=True, type=parse_time, help="window start, ISO 8601 (run creation)"
    )
    parser.add_argument("--until", type=parse_time, help="window end, ISO 8601; default now")
    parser.add_argument("--repo", default=DEFAULT_REPO)
    parser.add_argument("--workflow", default=DEFAULT_WORKFLOW)
    parser.add_argument("--branch", default=DEFAULT_BRANCH)
    parser.add_argument("--event", help="only runs of this trigger event, such as push")
    parser.add_argument(
        "--max-runs", type=_positive_int, help="cap on completed runs scanned, newest first"
    )
    parser.add_argument(
        "--with-tail-until",
        type=parse_time,
        help="exclude a payload without rate_window from any run created after this instant",
    )
    parser.add_argument("--json-out", type=Path, help="also write every reading and job here")
    parser.add_argument("--quiet", action="store_true", help="no per-run progress on stderr")
    args = parser.parse_args(argv)

    until = args.until or datetime.now(UTC)
    if until < args.since:
        parser.error("--until is before --since")
    try:
        result = harvest(
            GhApi(),
            repo=args.repo,
            workflow=args.workflow,
            branch=args.branch,
            since=args.since,
            until=until,
            max_runs=args.max_runs,
            event=args.event,
            with_tail_until=args.with_tail_until,
            progress=not args.quiet,
        )
    except HarvestError as exc:
        print(f"harvest failed: {exc}", file=sys.stderr)
        return 2
    # The JSON first, so a console that cannot print the report does not lose the data.
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(
            json.dumps(to_json_dict(result), indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    text = render_markdown(result) + "\n"
    encoding = sys.stdout.encoding or "utf-8"
    sys.stdout.write(text.encode(encoding, "replace").decode(encoding))
    # 3 says "incomplete" to a caller that only reads the exit code.
    return 0 if is_complete(result) else 3


if __name__ == "__main__":
    raise SystemExit(main())
