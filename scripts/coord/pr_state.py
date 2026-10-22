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

WHY THE LOCK IS lock.ps1's PROTOCOL, NOT A CALL TO IT. Calling lock.ps1 would mean a pwsh process per
poll, and that window flash again. So this takes the same lock the same way: it exclusively creates
``mefor-coord/locks/pr-state.lock`` and writes the same ``pid= host= at=`` line. A PowerShell caller
running ``Enter-CoordLock -Name pr-state`` excludes this poller and is excluded by it. Like lock.ps1 it
never steals: a held lock means skip. A lock older than ``STALE_LOCK_SECONDS`` is reported as wedged,
with the manual override, because nothing can prove its holder is gone.

A FAILED READ NEVER WRITES AN EMPTY LIST. On any failure the previous good ``data`` block is kept with
its own ``fetchedAt``, ``stale`` is true and ``error`` names the failure. With no previous data,
``data`` is null. An empty ``pullRequests`` list means GitHub said there are none, and nothing else.

Stdlib only. It loads ``coord_root.py`` and ``_pr_checks.py`` by path, so it runs from any interpreter.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
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
LOCK_NAME = "pr-state"
#: The open-PR page size. A page that comes back this full may be truncated, and the cache says so.
PR_PAGE = 100
#: PRs per aliased required-context query. Each alias asks for up to CONTEXT_PAGE contexts.
CONTEXT_CHUNK = 40
CONTEXT_PAGE = 100
#: How often the live required-context list is re-read. It changes when branch protection does.
REQUIRED_REFRESH_SECONDS = 3600
#: The GraphQL budget is 5000 points an hour, shared by every seat. A poll costs about 4. Below
#: RATE_LOW the poller is the consumer that should yield, so it drops to one poll in RATE_LOW_DELAY.
#: Below RATE_FLOOR it stops until the window resets, leaving the rest for seats doing real work.
RATE_LOW = 1000
RATE_LOW_DELAY = 600
RATE_FLOOR = 300
#: Failure back-off: the schedule's 2 minutes, doubled per consecutive failure, capped.
FAIL_BASE_DELAY = 120
FAIL_MAX_DELAY = 1800
#: A poll holds the lock for seconds, and the task's time limit is minutes. Older than this is wedged.
STALE_LOCK_SECONDS = 600
GH_TIMEOUT_SECONDS = 60

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
    pass


class PollError(RuntimeError):
    def __init__(self, message: str, reset_at: str | None = None) -> None:
        super().__init__(message)
        self.reset_at = reset_at


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
        raise GhError(f"gh {' '.join(args[:2])} exited {proc.returncode}: {' '.join(detail)[:400]}")
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
    pullRequests(states: OPEN, first: $limit, orderBy: {field: CREATED_AT, direction: ASC}) {
      totalCount
      pageInfo { hasNextPage }
      nodes {
        number title headRefName headRefOid isDraft mergeable mergeStateStatus
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
    mergeQueue(branch: "main") {
      entries(first: 100) {
        totalCount
        nodes { position state enqueuedAt pullRequest { number } }
      }
    }
  }
}
"""


def contexts_query(numbers: list[int]) -> str:
    """One aliased query asking each PR's head commit for its contexts and whether each is required."""
    parts = []
    for n in numbers:
        parts.append(
            f"p{n}: pullRequest(number: {n}) {{ commits(last: 1) {{ nodes {{ commit {{ oid "
            f"statusCheckRollup {{ contexts(first: {CONTEXT_PAGE}) {{ pageInfo {{ hasNextPage }} nodes {{ "
            f"__typename "
            f"... on CheckRun {{ name status conclusion isRequired(pullRequestNumber: {n}) }} "
            f"... on StatusContext {{ context state isRequired(pullRequestNumber: {n}) }} "
            f"}} }} }} }} }} }} }}"
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


def graphql(gh: Gh, query: str, variables: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """``(repository, rateLimit)``. Any GraphQL error fails the whole poll: partial data is not written."""
    raw = gh(
        ["api", "graphql", "--input", "-"], json.dumps({"query": query, "variables": variables})
    )
    try:
        doc = json.loads(raw)
    except ValueError as exc:
        raise PollError(f"GraphQL reply is not JSON ({len(raw)} bytes): {exc}") from exc
    if not isinstance(doc, dict):
        raise PollError("GraphQL reply is not an object")
    data = doc.get("data")
    rate = data.get("rateLimit") if isinstance(data, dict) else None
    if doc.get("errors"):
        msgs = "; ".join(
            str(e.get("message", e)) if isinstance(e, dict) else str(e) for e in doc["errors"]
        )
        reset = rate.get("resetAt") if isinstance(rate, dict) else None
        raise PollError(f"GraphQL errors: {msgs[:400]}", reset_at=reset)
    if not isinstance(data, dict) or not isinstance(data.get("repository"), dict):
        raise PollError("GraphQL reply has no data.repository")
    return data["repository"], rate if isinstance(rate, dict) else {}


def fetch_required(gh: Gh, repo: str) -> list[str]:
    """Classic branch protection's contexts plus every ruleset's, through scripts/ci/required_contexts.py.

    ``branches/main`` answers without admin scope, where ``.../protection/required_status_checks``
    does not. The parsers are that module's, so the drift check and this poller read one way.
    """
    try:
        branch = json.loads(gh(["api", f"repos/{repo}/branches/main"], None))
        rules = json.loads(gh(["api", f"repos/{repo}/rules/branches/main"], None))
        found = required_contexts.branch_protection_contexts(branch)
        found += required_contexts.ruleset_contexts(rules)
    except (ValueError, RuntimeError) as exc:
        raise PollError(f"required contexts unreadable: {exc}") from exc
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
    required: list[str] | None, contexts: dict[str, Any] | None, head_oid: str | None
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
        "reason": None,
    }
    if required is None:
        out["reason"] = "no required-context list"
        return out
    if contexts is None:
        out["reason"] = "required-context query returned nothing for this PR"
        return out
    if head_oid and contexts.get("oid") and contexts["oid"] != head_oid:
        out["reason"] = "head moved between the two queries"
        return out
    nodes = [n for n in contexts.get("nodes", []) if n is not None]
    more = bool(contexts.get("hasNextPage"))
    for name in required:
        matching = [n for n in nodes if pr_checks.name_of(n) == name]
        if not matching:
            # Absent from a truncated page proves nothing; absent from a complete one is pending.
            out["unknown" if more else "missing"].append(name)
            continue
        failing, unsettled = pr_checks.counts(matching)
        if failing:
            out["failing"].append(name)
        elif unsettled:
            out["pending"].append(name)
    req = set(required)
    flagged = {
        pr_checks.name_of(n) for n in nodes if isinstance(n, dict) and n.get("isRequired") is True
    }
    out["requiredByGithubNotInList"] = sorted(flagged - req)
    if out["failing"]:
        out["state"] = "FAILURE"
    elif out["pending"] or out["missing"]:
        out["state"] = "PENDING"
    elif out["unknown"]:
        out["reason"] = "context page truncated before every required name was seen"
    else:
        out["state"] = "SUCCESS"
    return out


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
            "total": contexts.get("totalCount"),
            "checkRuns": _counts_by_state(contexts.get("checkRunCountsByState")),
            "statusContexts": _counts_by_state(contexts.get("statusContextCountsByState")),
        },
        "required": required_verdict(required, ctx, pr.get("headRefOid")),
    }


def fetch_contexts(
    gh: Gh, owner: str, name: str, numbers: list[int]
) -> tuple[dict[int, dict[str, Any]], list[dict[str, Any]]]:
    out: dict[int, dict[str, Any]] = {}
    rates: list[dict[str, Any]] = []
    for i in range(0, len(numbers), CONTEXT_CHUNK):
        chunk = numbers[i : i + CONTEXT_CHUNK]
        repo, rate = graphql(gh, contexts_query(chunk), {"owner": owner, "name": name})
        rates.append(rate)
        for n in chunk:
            pr = repo.get(f"p{n}")
            if not isinstance(pr, dict):
                continue
            commit = _head_commit(pr)
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
    if (
        required is None
        or fetched is None
        or (now - fetched).total_seconds() >= REQUIRED_REFRESH_SECONDS
    ):
        try:
            required = fetch_required(gh, repo)
            required_at = iso(now)
        except (GhError, PollError) as exc:
            # A stale list beats none; it is labelled with its own age. No list leaves every PR UNKNOWN.
            required_error = str(exc)

    repo_doc, rate = graphql(gh, MAIN_QUERY, {"owner": owner, "name": name, "limit": PR_PAGE})
    conn = repo_doc.get("pullRequests") if isinstance(repo_doc.get("pullRequests"), dict) else None
    if conn is None or not isinstance(conn.get("nodes"), list):
        raise PollError("GraphQL reply has no pullRequests.nodes")
    prs = [p for p in conn["nodes"] if isinstance(p, dict)]
    total = conn.get("totalCount")
    page = conn.get("pageInfo") if isinstance(conn.get("pageInfo"), dict) else {}
    truncated = (
        len(prs) >= PR_PAGE
        or bool(page.get("hasNextPage"))
        or (isinstance(total, int) and total > len(prs))
    )

    numbers = [p["number"] for p in prs if isinstance(p.get("number"), int)]
    rates = [rate]
    ctx: dict[int, dict[str, Any]] = {}
    if numbers:
        ctx, more = fetch_contexts(gh, owner, name, numbers)
        rates += more

    mq = repo_doc.get("mergeQueue")
    queue: list[dict[str, Any]] | None = None
    if isinstance(mq, dict):
        queue = []
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

    last = rates[-1]
    remaining = last.get("remaining")
    doc = _base(repo, now)
    doc.update(
        {
            "stale": False,
            "error": None,
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
            "data": {
                "fetchedAt": iso(now),
                "openPullRequestCount": total if isinstance(total, int) else None,
                "truncated": truncated,
                "pullRequests": [shape_pr(p, required, ctx.get(p.get("number", -1))) for p in prs],
                "mergeQueue": queue,
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
) -> dict[str, Any]:
    """The cache after a failed poll: the last good data kept, marked stale, and never an empty list."""
    prev = previous or {}
    n = prev.get("consecutiveFailures")
    failures = (n if isinstance(n, int) else 0) + 1
    delay = min(FAIL_BASE_DELAY * 2 ** (failures - 1), FAIL_MAX_DELAY)
    not_before = now + timedelta(seconds=delay)
    reset = parse_iso(reset_at)
    if reset and reset > not_before and "rate limit" in error.lower():
        not_before = reset
    data = prev.get("data") if isinstance(prev.get("data"), dict) else None
    doc = _base(repo, now)
    doc.update(
        {
            "stale": True,
            "error": error,
            "consecutiveFailures": failures,
            "rateLimit": prev.get("rateLimit"),
            "requiredContexts": prev.get("requiredContexts"),
            "requiredContextsFetchedAt": prev.get("requiredContextsFetchedAt"),
            "requiredContextsError": prev.get("requiredContextsError"),
            # The previous good block, with its own fetchedAt, or null. Never a fresh empty list.
            "data": data,
            "nextPollNotBefore": iso(not_before),
        }
    )
    return doc


def read_cache(path: Path) -> dict[str, Any] | None:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(doc, dict) or doc.get("schemaVersion") != SCHEMA_VERSION:
        return None
    return doc


def write_cache(path: Path, doc: dict[str, Any]) -> None:
    """Temp file then rename, so a reader sees the old file or the new one, never half of one."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
    for attempt in range(5):
        try:
            os.replace(tmp, path)
            return
        except PermissionError:
            # Windows refuses the rename while a reader holds the file open. Readers hold it briefly.
            if attempt == 4:
                tmp.unlink(missing_ok=True)
                raise
            time.sleep(0.1)


def acquire_lock(local: Path) -> tuple[Path | None, str | None]:
    """``(lock path, None)`` when taken; ``(None, holder)`` when held. lock.ps1's protocol, no retry."""
    lock = lock_path(local)
    lock.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        try:
            holder = lock.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            holder = "(unreadable)"
        return None, holder or "(empty)"
    try:
        stamp = datetime.now(UTC).isoformat()
        os.write(fd, f"pid={os.getpid()} host={coord_root.host()} at={stamp}".encode())
    finally:
        os.close(fd)
    return lock, None


def lock_path(local: Path) -> Path:
    return local / "locks" / f"{LOCK_NAME}.lock"


def lock_age_seconds(local: Path) -> float | None:
    try:
        return time.time() - lock_path(local).stat().st_mtime
    except OSError:
        return None


def _say(message: str) -> None:
    # Under pythonw there is no stderr; print to a None stream is a no-op, which is what we want.
    if sys.stderr is not None:
        print(f"pr-state: {message}", file=sys.stderr)


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
    args = ap.parse_args(argv)

    if local is None:
        local = coord_root.local_root(_HERE)
    if local is None:
        _say("git could not name the common dir; nothing written")
        return 2
    out: Path = args.out if args.out is not None else local / CACHE_NAME

    lock, holder = acquire_lock(local)
    if lock is None:
        age = lock_age_seconds(local)
        if age is not None and age > STALE_LOCK_SECONDS:
            _say(
                f"the pr-state lock has been held {int(age)} s by {holder}. NOT stealing it. If that "
                f"process is gone, delete {lock_path(local)} by hand."
            )
            return 3
        return 0  # another poll is running; it will write the cache
    try:
        start = now()
        previous = read_cache(out)
        not_before = parse_iso(previous.get("nextPollNotBefore")) if previous else None
        if not args.force and not_before is not None and start < not_before:
            return 0  # backing off; the cache already says until when
        try:
            doc = poll(gh, args.repo, previous, start)
        except (PollError, GhError) as exc:
            doc = failed(args.repo, previous, str(exc), start, getattr(exc, "reset_at", None))
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            # A reply shape this code did not expect. Recorded, so the cache does not go silently old.
            doc = failed(args.repo, previous, f"unexpected reply shape: {exc!r}", start)
        write_cache(out, doc)
        if doc["error"]:
            _say(f"poll failed, last good data kept: {doc['error']}")
            return 1
        return 0
    finally:
        lock.unlink(missing_ok=True)


if __name__ == "__main__":
    sys.exit(main())
