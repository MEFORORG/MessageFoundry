#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""One poll of the repository's open pull requests and merge queue, written to ONE local cache file.

WHY ONE POLLER AND ONE FILE. Every Claude account on this box shares one GitHub token
(``scripts/hooks/block-api-burn.ps1`` records the measurement), so all seats draw on one GraphQL
budget. A read-only fleet pane in each of ~11 sessions, each polling for itself, would multiply the
cost by eleven. Instead a scheduled task runs this once every two minutes, and every pane reads
``<git-common-dir>/mefor-coord/pr-state.json`` and makes no API call. docs/WORKTREES.md,
*A PR-state cache for read-only panes*, documents the file for readers.

ONE POLL PER INVOCATION, NEVER A LOOP. The schedule supplies the cadence. Back-off is a timestamp,
``nextPollNotBefore``, written into the cache: a later invocation that starts before it exits
quietly. Nothing here sleeps between API calls; block-api-burn.ps1 denies that pattern for a reason.

WHY PYTHON AND NOT POWERSHELL. The rollup vocabulary already has one reader, ``scripts/ci/_pr_checks.py``,
and a second classifier would drift. The task also runs under ``pythonw.exe``, which opens no window;
a ``pwsh -WindowStyle Hidden`` task still flashes a console every two minutes.

WHY THE LOCK IS AN OS LOCK, NOT lock.ps1. lock.ps1's lock is a file whose existence is the lock, so a
kill (the task's time limit, a logoff, a shutdown) leaves it behind, and recovering it needs a
liveness guess. This poller holds a byte-range lock on an open handle instead (``msvcrt.locking``;
``fcntl.flock`` elsewhere), and the kernel releases it when the process dies, however it dies. A held
lock means another poll is running, so the run exits. Only the lock holder writes the cache.
docs/WORKTREES.md, *A PR-state cache for read-only panes*, is where the lock is described for readers.

A FAILED READ NEVER WRITES AN EMPTY LIST. On any failure the previous good ``data`` block is kept with
its own ``fetchedAt``, ``stale`` is true and ``error`` names the failure. With no previous data,
``data`` is null. An empty ``pullRequests`` list means GitHub said there are none, and nothing else.

Stdlib only. It loads ``coord_root.py``, ``_pr_checks.py`` and ``required_contexts.py`` by path, so
it runs from any 3.11+ interpreter.
"""

from __future__ import annotations

import argparse
import errno
import importlib.util
import json
import os
import re
import subprocess  # nosec B404 - fixed argv, no shell
import sys
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType
from typing import Any

SCHEMA_VERSION = 1
DEFAULT_REPO = "MEFORORG/MessageFoundry"
CACHE_NAME = "pr-state.json"
LOCK_FILE = "pr-state.oslock"
#: The base whose required list, queue and protection are read.
BASE_BRANCH = "main"
#: The open-PR page size. A page that comes back this full may be truncated, and the cache says so.
PR_PAGE = 100
#: PRs per aliased required-context query. Each alias asks for up to CONTEXT_PAGE contexts.
#: check_stalled_prs.py measured one full-rollup query over 67 PRs failing with 502/504, so keep
#: each query well under that.
CONTEXT_CHUNK = 20
CONTEXT_PAGE = 100
#: How often the live required-context list is re-read. It changes when branch protection does.
REQUIRED_REFRESH_SECONDS = 3600
#: After a failed refresh, the next try waits this long, so a persistent 403 costs a few calls an
#: hour, not two every poll.
REQUIRED_RETRY_SECONDS = 600
#: The GraphQL budget is 5000 points an hour, shared by every seat. A poll costs about 4. Below
#: RATE_LOW the poller is the consumer that should yield, so it drops to one poll in RATE_LOW_DELAY.
#: Below RATE_FLOOR it stops until the window resets, leaving the rest for seats doing real work.
RATE_LOW = 1000
RATE_LOW_DELAY = 600
RATE_FLOOR = 300
#: Failure back-off: the schedule's 2 minutes, doubled per consecutive failure, capped.
FAIL_BASE_DELAY = 120
FAIL_MAX_DELAY = 1800
GH_TIMEOUT_SECONDS = 30
#: A rate-limit failure with no resetAt to wait for waits this long instead of the short back-off.
RATE_LIMIT_FALLBACK_SECONDS = 900
#: No legitimate back-off is longer: the cap, or an hour's wait for a rate-limit reset.
#: Two hours, so a reset an hour out read by a clock running behind GitHub still counts.
MAX_BACKOFF = timedelta(seconds=max(FAIL_MAX_DELAY, 3600) * 2)
START_SLACK = timedelta(seconds=15)
#: Where messages go when there is no stderr (pythonw). Capped, so it cannot grow without bound.
LOG_NAME = "pr-state.log"
LOG_MAX_BYTES = 256 * 1024

_HERE = Path(__file__).resolve().parent


def _load(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod  # dataclasses look their module up here
    spec.loader.exec_module(mod)
    return mod


coord_root = _load("_pr_state_coord_root", _HERE / "coord_root.py")
pr_checks = _load("_pr_state_pr_checks", _HERE.parent / "ci" / "_pr_checks.py")
required_contexts = _load(
    "_pr_state_required_contexts", _HERE.parent / "ci" / "required_contexts.py"
)

#: ``gh(args, stdin) -> stdout``. Raises GhError on a non-zero exit. Tests pass a fake.
Gh = Callable[[list[str], str | None], str]


class GhError(RuntimeError):
    def __init__(self, message: str, stdout: str = "") -> None:
        super().__init__(message)
        # gh exits 1 on a GraphQL reply that carries errors, with the reply on stdout.
        self.stdout = stdout


class PollError(RuntimeError):
    def __init__(self, message: str, reset_at: str | None = None, part: str | None = None) -> None:
        # The message carries the part as its prefix, so a raise site names it once.
        super().__init__(f"{part}: {message}" if part else message)
        self.reset_at = reset_at
        #: Cache fields the failing poll did learn, which failed() keeps over the previous ones.
        self.fresh: dict[str, Any] | None = None
        #: Which request failed: "pulls" or "contexts PRs a-b".
        self.part = part


def run_gh(args: list[str], stdin: str | None = None) -> str:
    """Run gh once. UTF-8 both ways: text=True alone decodes cp1252 here and mangles non-ASCII."""
    flags = getattr(
        subprocess, "CREATE_NO_WINDOW", 0
    )  # pythonw: a console child would open a window
    try:
        proc = subprocess.run(  # nosec B603 B607 - fixed argv, no shell
            ["gh", *args],
            input=stdin,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=GH_TIMEOUT_SECONDS,
            check=False,
            creationflags=flags,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GhError(f"gh {' '.join(args[:2])}: {exc}") from exc
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip().splitlines()
        raise GhError(
            f"gh {' '.join(args[:2])} exited {proc.returncode}: {' '.join(detail)[:400]}",
            proc.stdout or "",
        )
    return proc.stdout


def iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


MAIN_QUERY = """
query($owner: String!, $name: String!, $limit: Int!) {
  rateLimit { cost remaining resetAt limit }
  repository(owner: $owner, name: $name) {
    pullRequests(states: OPEN, first: $limit, orderBy: {field: CREATED_AT, direction: DESC}) {
      totalCount
      pageInfo { hasNextPage }
      nodes {
        number title baseRefName headRefName headRefOid isDraft mergeable mergeStateStatus
        labels(first: 30) { nodes { name } }
        mergeQueueEntry { position state }
        autoMergeRequest { enabledAt }
        commits(last: 1) { nodes { commit { oid statusCheckRollup {
          state
          contexts(first: 0) {
            totalCount
            checkRunCountsByState { state count }
            statusContextCountsByState { state count }
          }
        } } } }
      }
    }
    mergeQueue(branch: "%BASE%") {
      entries(first: 100) {
        totalCount
        nodes { position state enqueuedAt pullRequest { number } }
      }
    }
  }
}
""".replace("%BASE%", BASE_BRANCH)


_OID = re.compile(r"\A[0-9a-f]{40}\Z")


def contexts_query(heads: dict[int, str]) -> str:
    """One aliased query asking each PR's head commit, BY SHA, for its contexts and which are required.

    Pinning to the headRefOid the main query returned means a push between the two queries cannot
    make the reply describe another commit, and nothing depends on commits(last: 1) being the head.
    """
    parts = []
    for n, oid in heads.items():
        if not _OID.match(oid):
            raise PollError(f"head SHA for PR {n} is not 40 hex characters: {oid!r}", part="pulls")
        parts.append(
            f'p{n}: object(oid: "{oid}") {{ ... on Commit {{ oid '
            f"statusCheckRollup {{ contexts(first: {CONTEXT_PAGE}) {{ pageInfo {{ hasNextPage }} nodes {{ "
            f"__typename "
            f"... on CheckRun {{ name status conclusion startedAt isRequired(pullRequestNumber: {n}) }} "
            f"... on StatusContext {{ context state createdAt isRequired(pullRequestNumber: {n}) }} "
            f"}} }} }} }} }}"
        )
    body = "\n    ".join(parts)
    return (
        "query($owner: String!, $name: String!) {\n"
        "  rateLimit { cost remaining resetAt limit }\n"
        "  repository(owner: $owner, name: $name) {\n"
        f"    {body}\n"
        "  }\n"
        "}\n"
    )


def graphql(
    gh: Gh, query: str, variables: dict[str, Any], part: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    """``(repository, rateLimit)``. Any GraphQL error fails the whole poll: partial data is not written."""
    body = json.dumps({"query": query, "variables": variables})
    try:
        raw = gh(["api", "graphql", "--input", "-"], body)
    except GhError as exc:
        # gh exits non-zero when the reply carries `errors`; read that reply for its resetAt.
        if '"errors"' not in exc.stdout:
            raise PollError(str(exc), part=part) from exc
        raw = exc.stdout
    try:
        doc = json.loads(raw)
    except ValueError as exc:
        raise PollError(f"reply is not JSON ({len(raw)} bytes): {exc}", part=part) from exc
    if not isinstance(doc, dict):
        raise PollError("reply is not an object", part=part)
    data = doc.get("data")
    rate = data.get("rateLimit") if isinstance(data, dict) else None
    if doc.get("errors"):
        msgs = "; ".join(
            str(e.get("message", e)) if isinstance(e, dict) else str(e) for e in doc["errors"]
        )
        reset = rate.get("resetAt") if isinstance(rate, dict) else None
        err = PollError(f"GraphQL errors: {msgs[:400]}", reset_at=reset, part=part)
        if isinstance(rate, dict):
            err.fresh = {"rateLimit": {**rate, "queries": 1}}
        raise err
    if not isinstance(data, dict) or not isinstance(data.get("repository"), dict):
        raise PollError("reply has no data.repository", part=part)
    return data["repository"], rate if isinstance(rate, dict) else {}


def fetch_required(gh: Gh, repo: str) -> list[str]:
    """Classic branch protection's contexts plus every ruleset's, through scripts/ci/required_contexts.py.

    ``branches/main`` answers without admin scope, where ``.../protection/required_status_checks``
    does not. The parsers are that module's, so the drift check and this poller read one way.
    """
    try:
        branch = json.loads(gh(["api", f"repos/{repo}/branches/{BASE_BRANCH}"], None))
        pages = json.loads(
            gh(["api", "--paginate", "--slurp", f"repos/{repo}/rules/branches/{BASE_BRANCH}"], None)
        )
        rules = [rule for page in pages for rule in page]
        found = required_contexts.branch_protection_contexts(branch)
        found += required_contexts.ruleset_contexts(rules)
    except (ValueError, RuntimeError, KeyError, TypeError, AttributeError) as exc:
        raise PollError(f"required contexts unreadable: {exc!r}") from exc
    return sorted(set(found))


def _nodes(conn: object) -> list[Any]:
    if isinstance(conn, dict) and isinstance(conn.get("nodes"), list):
        return list(conn["nodes"])
    return []


def _head_commit(pr: object) -> dict[str, Any]:
    nodes = _nodes(pr.get("commits") if isinstance(pr, dict) else None)
    commit = nodes[-1].get("commit") if nodes and isinstance(nodes[-1], dict) else None
    return commit if isinstance(commit, dict) else {}


def _counts_by_state(items: object) -> dict[str, int]:
    out: dict[str, int] = {}
    for item in items if isinstance(items, list) else []:
        if isinstance(item, dict) and isinstance(item.get("count"), int):
            out[str(item.get("state"))] = item["count"]
    return out


def required_verdict(
    required: list[str] | None,
    contexts: dict[str, Any] | None,
    head_oid: str | None,
    base: str | None = BASE_BRANCH,
) -> dict[str, Any]:
    """Classify a PR's head against the LIVE required list.

    A required context with no check run yet is PENDING ("missing"), never green. Each matching
    context goes through _pr_checks.counts, so an unrecognised shape reads as unsettled.
    """
    out: dict[str, Any] = {
        "state": "UNKNOWN",
        "failing": [],
        "pending": [],
        "missing": [],
        "unknown": [],
        "requiredByGithubNotInList": [],
        "reason": None,
    }
    if base != BASE_BRANCH:
        # The list is BASE_BRANCH's. Judging another base's PR by it is a verdict about nothing.
        out["reason"] = f"base is {base!r}; only {BASE_BRANCH}'s required list is read"
        return out
    if required is None:
        out["reason"] = "no required-context list"
        return out
    if contexts is None:
        out["reason"] = "required-context query returned nothing for this PR"
        return out
    nodes = [n for n in contexts.get("nodes", []) if n is not None]
    req = set(required)
    flagged = {
        pr_checks.name_of(n) for n in nodes if isinstance(n, dict) and n.get("isRequired") is True
    }
    out["requiredByGithubNotInList"] = sorted(flagged - req)
    if contexts.get("hasNextPage"):
        # A later page may hold a newer run of any name, so no name on a partial page is proven
        # red or green.
        out["reason"] = "context page truncated; no required verdict from a partial page"
        out["unknown"] = sorted(req | flagged)
        return out
    # A check GitHub calls required counts even when the cached list does not name it yet.
    for name in sorted(req | flagged):
        named = [n for n in nodes if pr_checks.name_of(n) == name]
        # GitHub's per-PR isRequired is the truth where it answers: a same-named run from an app the
        # rule does not count (False) cannot speak for the context.
        matching = [n for n in named if not (isinstance(n, dict) and n.get("isRequired") is False)]
        if not matching:
            # Runs of this name exist, but GitHub counts none of them for this PR. The run it would
            # count (another app's, say) may not exist yet, so this proves nothing either way.
            out["unknown" if named else "missing"].append(name)
            continue
        speaker = _speaker(matching)
        failing, unsettled = pr_checks.counts([speaker])
        if pr_checks.verdict_of(speaker) == pr_checks.STALE:
            # GitHub abandoned this run and never re-runs it, so waiting is wrong: it needs a
            # re-run, as a failure does.
            failing = 1
        if failing:
            out["failing"].append(name)
        elif unsettled:
            out["pending"].append(name)
    if out["failing"]:
        out["state"] = "FAILURE"
    elif out["pending"] or out["missing"]:
        out["state"] = "PENDING"
    elif out["unknown"]:
        out["reason"] = "runs exist only from checks GitHub does not count as required here"
    else:
        out["state"] = "SUCCESS"
    return out


def _speaker(runs: list[Any]) -> Any:
    """The run that speaks for one name: clear_stale_ci_red.newest_by_name's rule, on GraphQL fields.

    A run still IN PROGRESS beats a finished one outright; a head can carry two concurrent runs of
    a name and the earlier-started one can finish last. Among finished runs the latest start wins,
    whatever its conclusion, so a COMPLETED run with a STALE or null conclusion does not outrank a
    newer SUCCESS. A run with no timestamp loses. On a tie the worse verdict wins, so list order
    is never used.
    """

    def key(run: Any) -> tuple[int, str, int]:
        if not isinstance(run, dict):
            return (0, "", 1)
        stamp = run.get("startedAt") or run.get("createdAt")
        failing, unsettled = pr_checks.counts([run])
        # Ties go to the worse verdict, so equal stamps never leave the answer to list order.
        worse = 2 if failing else 1 if unsettled else 0
        return (1 if pr_checks.in_progress(run) else 0, str(stamp or ""), worse)

    return max(runs, key=key)


def _known(value: object) -> str | None:
    """GitHub answers UNKNOWN on a cold read while it computes. That is no state, so it is null."""
    return None if value in (None, "UNKNOWN") else str(value)


def shape_pr(
    pr: dict[str, Any], required: list[str] | None, ctx: dict[str, Any] | None
) -> dict[str, Any]:
    commit = _head_commit(pr)
    rollup = (
        commit.get("statusCheckRollup")
        if isinstance(commit.get("statusCheckRollup"), dict)
        else None
    )
    contexts = rollup.get("contexts") if rollup and isinstance(rollup.get("contexts"), dict) else {}
    entry = pr.get("mergeQueueEntry") if isinstance(pr.get("mergeQueueEntry"), dict) else None
    auto = pr.get("autoMergeRequest") if isinstance(pr.get("autoMergeRequest"), dict) else None
    mergeable, merge_state = _known(pr.get("mergeable")), _known(pr.get("mergeStateStatus"))
    return {
        "number": pr.get("number"),
        "title": pr.get("title"),
        "headRefName": pr.get("headRefName"),
        "headRefOid": pr.get("headRefOid"),
        "isDraft": pr.get("isDraft"),
        "mergeable": mergeable,
        "mergeStateStatus": merge_state,
        "mergeStateKnown": mergeable is not None and merge_state is not None,
        "labels": [str(n.get("name")) for n in _nodes(pr.get("labels")) if isinstance(n, dict)],
        "mergeQueueEntry": {"position": entry.get("position"), "state": entry.get("state")}
        if entry
        else None,
        "autoMergeEnabledAt": auto.get("enabledAt") if auto else None,
        "allChecks": {
            # ALL checks, required or not. Current red for merging is `required`, below.
            "state": rollup.get("state") if rollup else None,
            # False when the main query's last commit is not the PR head; the counts then describe
            # another commit.
            "forHead": bool(commit.get("oid")) and commit.get("oid") == pr.get("headRefOid"),
            "total": contexts.get("totalCount"),
            "checkRuns": _counts_by_state(contexts.get("checkRunCountsByState")),
            "statusContexts": _counts_by_state(contexts.get("statusContextCountsByState")),
        },
        "baseRefName": pr.get("baseRefName"),
        "required": required_verdict(required, ctx, pr.get("headRefOid"), pr.get("baseRefName")),
    }


def fetch_contexts(
    gh: Gh, owner: str, name: str, heads: dict[int, str]
) -> tuple[dict[int, dict[str, Any]], list[dict[str, Any]]]:
    out: dict[int, dict[str, Any]] = {}
    rates: list[dict[str, Any]] = []
    numbers = list(heads)
    for i in range(0, len(numbers), CONTEXT_CHUNK):
        chunk = numbers[i : i + CONTEXT_CHUNK]
        part = f"contexts PRs {chunk[0]}-{chunk[-1]}"
        query = contexts_query({n: heads[n] for n in chunk})
        repo, rate = graphql(gh, query, {"owner": owner, "name": name}, part)
        rates.append(rate)
        for n in chunk:
            commit = repo.get(f"p{n}")
            if not isinstance(commit, dict):
                continue
            rollup = commit.get("statusCheckRollup")
            conn = rollup.get("contexts") if isinstance(rollup, dict) else None
            page = conn.get("pageInfo") if isinstance(conn, dict) else None
            out[n] = {
                "oid": commit.get("oid"),
                # No rollup at all means no check has reported: every required name is missing.
                "nodes": _nodes(conn),
                "hasNextPage": bool(page.get("hasNextPage")) if isinstance(page, dict) else False,
            }
    return out, rates


def poll(gh: Gh, repo: str, previous: dict[str, Any] | None, now: datetime) -> dict[str, Any]:
    """One poll. Returns the new cache document, or raises PollError/GhError."""
    owner, _, name = repo.partition("/")
    prev = previous or {}
    required: list[str] | None = (
        prev.get("requiredContexts") if isinstance(prev.get("requiredContexts"), list) else None
    )
    required_at = prev.get("requiredContextsFetchedAt")
    required_error: str | None = None
    fetched = parse_iso(required_at)
    if fetched is not None and fetched > now:
        fetched = None  # a future stamp is a skewed clock, so refresh rather than trust it
    tried = parse_iso(prev.get("requiredContextsTriedAt"))
    if tried is not None and tried > now:
        tried = None
    due = (
        required is None
        or fetched is None
        or (now - fetched).total_seconds() >= REQUIRED_REFRESH_SECONDS
    )
    retry_ok = tried is None or (now - tried).total_seconds() >= REQUIRED_RETRY_SECONDS
    tried_at = prev.get("requiredContextsTriedAt")
    if due and retry_ok:
        tried_at = iso(now)
        try:
            required = fetch_required(gh, repo)
            required_at = iso(now)
        except (GhError, PollError) as exc:
            # A stale list beats none; it is labelled with its own age. No list leaves every PR UNKNOWN.
            required_error = str(exc)

    progress: dict[str, Any] = {"part": "pulls", "rate": None}
    try:
        return _poll_rest(
            gh, repo, owner, name, now, required, required_at, required_error, tried_at, progress
        )
    except (KeyError, TypeError, ValueError, AttributeError) as shape:
        # A reply shape this code did not expect, recorded against the request that returned it.
        err = PollError(f"unexpected reply shape: {shape!r}", part=progress["part"])
    except PollError as exc:
        err = exc
    learned: dict[str, Any] = {
        "requiredContexts": required,
        "requiredContextsFetchedAt": required_at if required is not None else None,
        "requiredContextsError": required_error,
        "requiredContextsTriedAt": tried_at,
    }
    if progress["rate"]:
        learned["rateLimit"] = progress["rate"]  # the main query succeeded; its budget is current
    if err.part is None:
        err.part = progress["part"]
    err.fresh = {**learned, **(err.fresh or {})}
    raise err


def _poll_rest(
    gh: Gh,
    repo: str,
    owner: str,
    name: str,
    now: datetime,
    required: list[str] | None,
    required_at: Any,
    required_error: str | None,
    tried_at: Any,
    progress: dict[str, Any],
) -> dict[str, Any]:
    repo_doc, rate = graphql(
        gh, MAIN_QUERY, {"owner": owner, "name": name, "limit": PR_PAGE}, "pulls"
    )
    progress["rate"] = {**rate, "queries": 1} if rate else None
    conn = repo_doc.get("pullRequests") if isinstance(repo_doc.get("pullRequests"), dict) else None
    if conn is None or not isinstance(conn.get("nodes"), list):
        raise PollError("reply has no pullRequests.nodes", part="pulls")
    prs = [p for p in conn["nodes"] if isinstance(p, dict)]
    total = conn.get("totalCount")
    page = conn.get("pageInfo") if isinstance(conn.get("pageInfo"), dict) else {}
    truncated = (
        len(prs) >= PR_PAGE
        or bool(page.get("hasNextPage"))
        or (isinstance(total, int) and total > len(prs))
    )

    # A PR without a valid head SHA gets no context reply, and so reads UNKNOWN on its own.
    heads = {
        p["number"]: str(p.get("headRefOid"))
        for p in prs
        if isinstance(p.get("number"), int)
        and p.get("baseRefName") == BASE_BRANCH
        and _OID.match(str(p.get("headRefOid")))
    }
    rates = [rate]
    ctx: dict[int, dict[str, Any]] = {}
    if heads:
        progress["part"] = "contexts"
        ctx, more = fetch_contexts(gh, owner, name, heads)
        rates += more
        progress["part"] = "pulls"  # what follows is processing the main reply

    mq = repo_doc.get("mergeQueue")
    queue: list[dict[str, Any]] | None = None
    queue_truncated = False
    if isinstance(mq, dict):
        queue = []
        entries = mq.get("entries")
        queue_total = entries.get("totalCount") if isinstance(entries, dict) else None
        for e in _nodes(mq.get("entries")):
            if not isinstance(e, dict):
                continue
            pr = e.get("pullRequest")
            queue.append(
                {
                    "position": e.get("position"),
                    "state": e.get("state"),
                    "enqueuedAt": e.get("enqueuedAt"),
                    "number": pr.get("number") if isinstance(pr, dict) else None,
                }
            )
        queue_truncated = isinstance(queue_total, int) and queue_total > len(queue)

    last = rates[-1]
    remaining = last.get("remaining")
    doc = _base(repo, now)
    doc.update(
        {
            "stale": False,
            "error": None,
            "errorPart": None,
            "consecutiveFailures": 0,
            "rateLimit": {
                "cost": sum(r.get("cost", 0) for r in rates if isinstance(r.get("cost"), int)),
                "remaining": remaining,
                "limit": last.get("limit"),
                "resetAt": last.get("resetAt"),
                "queries": len(rates),
            },
            "requiredContexts": required,
            "requiredContextsFetchedAt": required_at if required is not None else None,
            "requiredContextsError": required_error,
            "requiredContextsTriedAt": tried_at,
            "data": {
                "fetchedAt": iso(now),
                "openPullRequestCount": total if isinstance(total, int) else None,
                "truncated": truncated,
                "pullRequests": [shape_pr(p, required, ctx.get(p.get("number", -1))) for p in prs],
                "mergeQueue": queue,
                "mergeQueueTruncated": queue_truncated,
            },
        }
    )
    doc["nextPollNotBefore"] = _rate_backoff(remaining, last.get("resetAt"), now)
    return doc


def _rate_backoff(remaining: object, reset_at: object, now: datetime) -> str | None:
    if not isinstance(remaining, int):
        return None
    if remaining < RATE_FLOOR:
        reset = parse_iso(reset_at)
        return iso(reset) if reset and reset > now else iso(now + timedelta(seconds=RATE_LOW_DELAY))
    if remaining < RATE_LOW:
        return iso(now + timedelta(seconds=RATE_LOW_DELAY))
    return None


def _base(repo: str, now: datetime) -> dict[str, Any]:
    return {
        "schemaVersion": SCHEMA_VERSION,
        "repo": repo,
        "host": coord_root.host(),
        "fetchedAt": iso(now),
    }


def failed(
    repo: str,
    previous: dict[str, Any] | None,
    error: str,
    now: datetime,
    reset_at: str | None = None,
    part: str | None = None,
    fresh: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """The cache after a failed poll: the last good data kept, marked stale, and never an empty list."""
    prev = previous or {}
    n = prev.get("consecutiveFailures")
    failures = (n if isinstance(n, int) else 0) + 1
    delay = min(FAIL_BASE_DELAY * 2 ** (failures - 1), FAIL_MAX_DELAY)
    not_before = now + timedelta(seconds=delay)
    if "rate limit" in error.lower():
        # Wait for the window to reset; with no resetAt to read, a fixed long wait, never 2 minutes.
        reset = parse_iso(reset_at)
        if reset is None or reset <= now:
            reset = now + timedelta(seconds=RATE_LIMIT_FALLBACK_SECONDS)
        not_before = max(not_before, reset)
    rate = (fresh or {}).get("rateLimit")
    if isinstance(rate, dict):
        low = parse_iso(_rate_backoff(rate.get("remaining"), rate.get("resetAt"), now))
        if low is not None:
            not_before = max(not_before, low)
    data = prev.get("data") if isinstance(prev.get("data"), dict) else None
    doc = _base(repo, now)
    doc.update(
        {
            "stale": True,
            "error": error,
            # Which request failed, so a reader knows the kept data is whole but old.
            "errorPart": part,
            "consecutiveFailures": failures,
            "rateLimit": prev.get("rateLimit"),
            "requiredContexts": prev.get("requiredContexts"),
            "requiredContextsFetchedAt": prev.get("requiredContextsFetchedAt"),
            "requiredContextsError": prev.get("requiredContextsError"),
            "requiredContextsTriedAt": prev.get("requiredContextsTriedAt"),
            # What this failing poll did learn (a fresh required list, the error reply's rate).
            **(fresh or {}),
            # The previous good block, with its own fetchedAt, or null. Never a fresh empty list.
            "data": data,
            "nextPollNotBefore": iso(not_before),
        }
    )
    return doc


def _previous(out: Path, repo: str) -> dict[str, Any] | None:
    """The previous cache, unless it is another repo's: its list and PRs must not carry over."""
    previous = read_cache(out)
    return previous if previous is not None and previous.get("repo") == repo else None


def read_cache(path: Path) -> dict[str, Any] | None:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        _say(f"previous cache {path} unreadable, starting fresh: {exc!r}")
        return None
    if not isinstance(doc, dict) or doc.get("schemaVersion") != SCHEMA_VERSION:
        return None
    return doc


def write_cache(path: Path, doc: dict[str, Any]) -> None:
    """Temp file then rename, so a reader sees the old file or the new one, never half of one."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    try:
        with tmp.open("w", encoding="utf-8") as fh:
            fh.write(json.dumps(doc, indent=1) + "\n")
            fh.flush()
            os.fsync(fh.fileno())  # so a power loss after the rename cannot leave an empty cache
        for attempt in range(5):
            try:
                os.replace(tmp, path)
                return
            except PermissionError:
                # Windows refuses the rename while a reader holds the file open, briefly.
                if attempt == 4:
                    raise
                time.sleep(0.1)
    finally:
        tmp.unlink(missing_ok=True)


class LockUnavailable(OSError):
    """The lock file could not be opened at all: a missing or unwritable directory, not a holder."""


def acquire_lock(local: Path) -> int | None:
    """An open, locked handle, or None when another process holds the lock.

    Raises LockUnavailable when the lock file cannot be opened. The handle must be passed to
    release_lock; if the process dies first, the kernel releases the lock with the handle.
    """
    lock = lock_path(local)
    try:
        lock.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(lock, os.O_RDWR | os.O_CREAT)
    except OSError as exc:
        raise LockUnavailable(f"cannot open {lock}: {exc!r}") from exc
    try:
        _lock_op(fd, take=True)
    except OSError as exc:
        os.close(fd)
        if exc.errno in _CONTENTION:
            return None  # another process holds it
        raise LockUnavailable(f"cannot lock {lock}: {exc!r}") from exc
    return fd


#: The errnos that mean "another process holds the lock". msvcrt.locking reports EACCES or
#: EDEADLOCK; flock reports EWOULDBLOCK (EAGAIN). Any other error is a broken lock, not a holder.
_CONTENTION = frozenset(
    e
    for e in (
        errno.EACCES,
        getattr(errno, "EDEADLOCK", None),
        errno.EDEADLK,
        errno.EAGAIN,
        errno.EWOULDBLOCK,
    )
    if e is not None
)


def _lock_op(fd: int, *, take: bool) -> None:
    """Take (non-blocking) or drop the one-byte lock at offset 0."""
    if sys.platform == "win32":
        import msvcrt

        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_NBLCK if take else msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB if take else fcntl.LOCK_UN)


def release_lock(fd: int) -> None:
    """Unlock, then close. The lock file stays; it is never deleted."""
    try:
        _lock_op(fd, take=False)
    except OSError as exc:
        _say(f"unlocking failed; closing the handle releases it anyway: {exc!r}")
    try:
        os.close(fd)
    except OSError as exc:
        _say(f"closing the lock handle failed: {exc!r}")


def lock_path(local: Path) -> Path:
    return local / "locks" / LOCK_FILE


_log_path: Path | None = None
_log_failures: list[str] = []


def _say(message: str) -> None:
    """To stderr; under pythonw, where there is none, to <coord-dir>/pr-state.log, capped."""
    if sys.stderr is not None:
        print(f"pr-state: {message}", file=sys.stderr)
        return
    if _log_path is None:
        return
    line = f"{datetime.now(UTC).isoformat()} {message}\n"
    try:
        if _log_path.exists() and _log_path.stat().st_size > LOG_MAX_BYTES:
            _log_path.replace(_log_path.with_suffix(".log.1"))
        with _log_path.open("a", encoding="utf-8") as fh:
            fh.write(line)
    except OSError as exc:
        # R8: no handler drops an error unlogged. The log is what failed, so the one channel left is
        # the task's exit code, which main() still returns; this records the cause in memory.
        _log_failures.append(f"{line.strip()} [log write failed: {exc!r}]")


def main(
    argv: list[str] | None = None,
    *,
    gh: Gh = run_gh,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
    local: Path | None = None,
) -> int:
    ap = argparse.ArgumentParser(
        description="One poll of open-PR and merge-queue state into a local cache."
    )
    ap.add_argument("--repo", default=DEFAULT_REPO)
    ap.add_argument(
        "--out", type=Path, help="cache path; default <git-common-dir>/mefor-coord/pr-state.json"
    )
    ap.add_argument(
        "--force", action="store_true", help="ignore nextPollNotBefore (the lock still holds)"
    )
    ap.add_argument(
        "--coord-dir",
        type=Path,
        help="the local mefor-coord directory; the task passes it so no git process (and window) starts",
    )
    args = ap.parse_args(argv)

    if local is None:
        local = args.coord_dir if args.coord_dir is not None else coord_root.local_root(_HERE)
    if local is None:
        _say("git could not name the common dir; nothing written")
        return 2
    global _log_path
    _log_path = local / LOG_NAME
    if args.repo != DEFAULT_REPO and args.out is None:
        # The default cache is the panes' file for DEFAULT_REPO; another repo must not overwrite it.
        _say(f"--repo {args.repo} needs --out; the default cache belongs to {DEFAULT_REPO}")
        return 2
    out: Path = args.out if args.out is not None else local / CACHE_NAME

    try:
        fd = acquire_lock(local)
    except LockUnavailable as exc:
        # Not written to the cache: only the lock holder writes it. Every unlocked write tried here
        # could overwrite a fresh poll or a pending back-off, so the log and the exit code say it.
        _say(str(exc))
        return 4  # a non-zero task result, so a broken lock is not a silent success
    if fd is None:
        return 0  # another poll is running; it will write the cache
    try:
        start = now()
        previous = _previous(out, args.repo)
        not_before = parse_iso(previous.get("nextPollNotBefore")) if previous else None
        if not_before is not None and not_before > start + MAX_BACKOFF:
            not_before = None  # stamped by a skewed clock or a copied file; never wait on it
        # The slack absorbs interpreter start-up jitter, so a retry due now is not skipped a round.
        if not args.force and not_before is not None and start + START_SLACK < not_before:
            return 0  # backing off; the cache already says until when
        try:
            doc = poll(gh, args.repo, previous, start)
        except PollError as exc:
            doc = failed(
                args.repo,
                previous,
                str(exc),
                start,
                reset_at=exc.reset_at,
                part=exc.part,
                fresh=exc.fresh,
            )
        except GhError as exc:
            # graphql() and fetch_required() convert gh failures; this is a last guard.
            doc = failed(args.repo, previous, str(exc), start, part="gh")
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            # poll() converts reply-shape errors itself; this is a last guard around the rest.
            doc = failed(args.repo, previous, f"unexpected error: {exc!r}", start, part="poller")
        try:
            write_cache(out, doc)
        except OSError as exc:
            # The cache cannot say this about itself, so the log file does.
            _say(f"could not write {out}; the poll's result is lost: {exc!r}")
            return 5
        if doc["error"]:
            _say(f"poll failed, last good data kept: {doc['error']}")
            return 1
        return 0
    finally:
        release_lock(fd)


if __name__ == "__main__":
    sys.exit(main())
