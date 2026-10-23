# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The PR-state poller writes one cache that read-only panes trust, so its failure shapes matter most.

These drive the REAL ``main()`` against canned gh replies, with no network. The positive control is
``test_error_path_never_writes_an_empty_list``: it must fail if a failed poll ever wrote ``[]``.
"""

from __future__ import annotations

import errno
import importlib.util
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = _ROOT / "scripts" / "coord" / "pr_state.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("pr_state", _SCRIPT)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


ps = _load()

REQUIRED = ["CI gate", "cla", "test"]
NOW = datetime(2026, 10, 22, 12, 0, 0, tzinfo=UTC)


def _sha(n: int) -> str:
    """A 40-hex head SHA, since the contexts query pins each PR to its head by SHA."""
    return f"{n:040x}"


def _pr(
    number: int, *, mergeable: str = "MERGEABLE", merge_state: str = "CLEAN", base: str = "main"
) -> dict[str, Any]:
    return {
        "number": number,
        "title": f"pr {number}",
        "baseRefName": base,
        "headRefName": f"b{number}",
        "headRefOid": _sha(number),
        "isDraft": False,
        "mergeable": mergeable,
        "mergeStateStatus": merge_state,
        "labels": {"nodes": [{"name": "ci-red"}]},
        "mergeQueueEntry": None,
        "autoMergeRequest": None,
        "commits": {
            "nodes": [
                {
                    "commit": {
                        "oid": _sha(number),
                        "statusCheckRollup": {
                            "state": "SUCCESS",
                            "contexts": {
                                "totalCount": 3,
                                "checkRunCountsByState": [{"state": "SUCCESS", "count": 3}],
                                "statusContextCountsByState": [],
                            },
                        },
                    }
                }
            ]
        },
    }


def _run(name: str, conclusion: str = "SUCCESS", status: str = "COMPLETED") -> dict[str, Any]:
    return {
        "__typename": "CheckRun",
        "name": name,
        "status": status,
        "conclusion": conclusion,
        "isRequired": name in REQUIRED,
    }


class FakeGh:
    """Answers the REST and GraphQL calls the poller makes. ``contexts`` maps PR number to its context nodes."""

    def __init__(
        self,
        prs: list[dict[str, Any]],
        contexts: dict[int, list[dict[str, Any]]],
        *,
        total: int | None = None,
        remaining: int = 4900,
        fail: str | None = None,
    ) -> None:
        self.prs = prs
        self.contexts = contexts
        self.total = len(prs) if total is None else total
        self.remaining = remaining
        self.fail = fail
        self.calls: list[list[str]] = []

    def __call__(self, args: list[str], stdin: str | None) -> str:
        self.calls.append(args)
        if self.fail:
            raise ps.GhError(self.fail)
        rate = {
            "cost": 1,
            "remaining": self.remaining,
            "limit": 5000,
            "resetAt": "2026-10-22T12:40:00Z",
        }
        if args[-1].endswith("/rules/branches/main"):
            rule = {
                "type": "required_status_checks",
                "parameters": {"required_status_checks": [{"context": "cla"}]},
            }
            assert "--paginate" in args and "--slurp" in args
            return json.dumps([[rule]])
        if args[-1].startswith("repos/"):
            protection = {
                "required_status_checks": {"contexts": ["CI gate", "test"], "strict": True}
            }
            return json.dumps({"name": "main", "protection": protection})
        assert stdin is not None
        query = json.loads(stdin)["query"]
        if "pullRequests(states: OPEN" in query:
            repo = {
                "pullRequests": {
                    "totalCount": self.total,
                    "pageInfo": {"hasNextPage": self.total > len(self.prs)},
                    "nodes": self.prs,
                },
                "mergeQueue": {
                    "entries": {
                        "totalCount": 1,
                        "nodes": [
                            {
                                "position": 1,
                                "state": "AWAITING_CHECKS",
                                "enqueuedAt": "2026-10-22T11:59:00Z",
                                "pullRequest": {"number": 1},
                            }
                        ],
                    }
                },
            }
            return json.dumps({"data": {"rateLimit": {**rate, "cost": 3}, "repository": repo}})
        repo = {}
        for n, nodes in self.contexts.items():
            if f"p{n}:" in query:
                assert f'object(oid: "{_sha(n)}")' in query  # pinned to the head SHA
                repo[f"p{n}"] = {
                    "oid": _sha(n),
                    "statusCheckRollup": {
                        "contexts": {"pageInfo": {"hasNextPage": False}, "nodes": nodes}
                    },
                }
        return json.dumps({"data": {"rateLimit": rate, "repository": repo}})


def _green() -> list[dict[str, Any]]:
    return [_run(n) for n in REQUIRED]


def _main(
    tmp_path: Path, gh: Callable[[list[str], str | None], str], now: datetime = NOW, *extra: str
) -> tuple[int, dict[str, Any]]:
    out = tmp_path / "pr-state.json"
    rc = ps.main(["--out", str(out), *extra], gh=gh, now=lambda: now, local=tmp_path)
    return rc, json.loads(out.read_text(encoding="utf-8"))


def test_cache_shape(tmp_path: Path) -> None:
    rc, doc = _main(tmp_path, FakeGh([_pr(1)], {1: _green()}))
    assert rc == 0
    assert doc["schemaVersion"] == ps.SCHEMA_VERSION
    assert doc["fetchedAt"] == "2026-10-22T12:00:00Z"
    assert doc["host"]
    assert doc["error"] is None and doc["stale"] is False
    assert doc["rateLimit"]["cost"] == 4 and doc["rateLimit"]["remaining"] == 4900
    assert doc["requiredContexts"] == sorted(REQUIRED)
    assert doc["requiredContextsFetchedAt"] == "2026-10-22T12:00:00Z"
    data = doc["data"]
    assert data["fetchedAt"] == doc["fetchedAt"]
    assert data["truncated"] is False
    assert data["mergeQueue"] == [
        {
            "position": 1,
            "state": "AWAITING_CHECKS",
            "enqueuedAt": "2026-10-22T11:59:00Z",
            "number": 1,
        }
    ]
    pr = data["pullRequests"][0]
    assert pr["labels"] == ["ci-red"]
    assert pr["required"]["state"] == "SUCCESS"
    assert (
        tmp_path / "locks" / "pr-state.oslock"
    ).exists()  # the lock file stays; the lock does not


def test_missing_required_context_is_pending_not_green(tmp_path: Path) -> None:
    # Every check that HAS run is green; the full rollup says SUCCESS. One required name never ran.
    contexts = [_run("CI gate"), _run("cla"), _run("lint-not-required")]
    _, doc = _main(tmp_path, FakeGh([_pr(1)], {1: contexts}))
    pr = doc["data"]["pullRequests"][0]
    assert pr["allChecks"]["state"] == "SUCCESS"
    assert pr["required"]["state"] == "PENDING"
    assert pr["required"]["missing"] == ["test"]


def test_required_failure_and_nonrequired_failure_are_told_apart(tmp_path: Path) -> None:
    red_required = [*_green()[:2], _run("test", "FAILURE")]
    red_optional = [*_green(), _run("optional", "FAILURE")]
    _, doc = _main(tmp_path, FakeGh([_pr(1), _pr(2)], {1: red_required, 2: red_optional}))
    one, two = doc["data"]["pullRequests"]
    assert one["required"]["state"] == "FAILURE" and one["required"]["failing"] == ["test"]
    assert two["required"]["state"] == "SUCCESS"


def test_status_context_error_counts_as_failing(tmp_path: Path) -> None:
    status = {"__typename": "StatusContext", "context": "cla", "state": "ERROR", "isRequired": True}
    _, doc = _main(tmp_path, FakeGh([_pr(1)], {1: [_run("CI gate"), status, _run("test")]}))
    assert doc["data"]["pullRequests"][0]["required"]["failing"] == ["cla"]


def test_unknown_mergeable_is_recorded_as_unknown(tmp_path: Path) -> None:
    _, doc = _main(
        tmp_path, FakeGh([_pr(1, mergeable="UNKNOWN", merge_state="UNKNOWN")], {1: _green()})
    )
    pr = doc["data"]["pullRequests"][0]
    assert pr["mergeable"] is None and pr["mergeStateStatus"] is None
    assert pr["mergeStateKnown"] is False


def test_full_page_is_flagged_truncated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ps, "PR_PAGE", 2)
    _, doc = _main(tmp_path, FakeGh([_pr(1), _pr(2)], {1: _green(), 2: _green()}))
    assert doc["data"]["truncated"] is True


def test_total_beyond_page_is_flagged_truncated(tmp_path: Path) -> None:
    _, doc = _main(tmp_path, FakeGh([_pr(1)], {1: _green()}, total=5))
    assert doc["data"]["truncated"] is True and doc["data"]["openPullRequestCount"] == 5


def test_failed_poll_keeps_last_good_data(tmp_path: Path) -> None:
    _main(tmp_path, FakeGh([_pr(1)], {1: _green()}))
    later = NOW + timedelta(minutes=2)
    rc, doc = _main(tmp_path, FakeGh([], {}, fail="HTTP 502"), later)
    assert rc == 1
    assert doc["error"] and "502" in doc["error"]
    assert doc["stale"] is True
    assert doc["fetchedAt"] == "2026-10-22T12:02:00Z"
    assert doc["data"]["fetchedAt"] == "2026-10-22T12:00:00Z"
    assert [p["number"] for p in doc["data"]["pullRequests"]] == [1]
    assert doc["consecutiveFailures"] == 1
    assert doc["nextPollNotBefore"] == "2026-10-22T12:04:00Z"


def test_error_path_never_writes_an_empty_list(tmp_path: Path) -> None:
    """POSITIVE CONTROL. With no earlier good poll, a failure writes data=null, never an empty list."""
    rc, doc = _main(tmp_path, FakeGh([], {}, fail="HTTP 504"))
    assert rc == 1
    assert doc["error"]
    # Anything else here, an empty pullRequests list above all, is what a pane misreads as "no PRs".
    assert doc["data"] is None, doc["data"]


def test_graphql_errors_fail_the_poll_and_wait_for_reset(tmp_path: Path) -> None:
    # Real gh exits 1 on a reply carrying `errors` and leaves the reply on stdout.
    reply = {
        "data": {"rateLimit": {"cost": 1, "remaining": 0, "resetAt": "2026-10-22T12:45:00Z"}},
        "errors": [{"message": "API rate limit exceeded"}],
    }

    def gh(args: list[str], stdin: str | None) -> str:
        if args[1] == "graphql":
            raise ps.GhError("gh api graphql exited 1: rate limit", json.dumps(reply))
        return FakeGh([], {})(args, stdin)

    rc, doc = _main(tmp_path, gh)
    assert rc == 1 and "rate limit" in doc["error"] and doc["data"] is None
    assert doc["nextPollNotBefore"] == "2026-10-22T12:45:00Z"


# --- Controls for the 2026-10-22 brief. Each fails on 9cc98a971. -----------------------------------


def test_completed_stale_run_does_not_outrank_a_newer_success(tmp_path: Path) -> None:
    stale = {**_run("test", "STALE"), "startedAt": "2026-10-22T10:00:00Z"}
    newer = {**_run("test"), "startedAt": "2026-10-22T11:00:00Z"}
    _, doc = _main(tmp_path, FakeGh([_pr(1)], {1: [_run("CI gate"), _run("cla"), stale, newer]}))
    assert doc["data"]["pullRequests"][0]["required"]["state"] == "SUCCESS"


def test_in_progress_run_still_outranks_a_newer_finished_one(tmp_path: Path) -> None:
    running = {**_run("test", "", "IN_PROGRESS"), "startedAt": "2026-10-22T10:00:00Z"}
    newer = {**_run("test"), "startedAt": "2026-10-22T11:00:00Z"}
    _, doc = _main(tmp_path, FakeGh([_pr(1)], {1: [_run("CI gate"), _run("cla"), running, newer]}))
    assert doc["data"]["pullRequests"][0]["required"]["pending"] == ["test"]


def test_truncated_page_never_reads_red(tmp_path: Path) -> None:
    """Page one holds an old FAILURE; a newer SUCCESS may sit on page two."""
    ctx = {"oid": _sha(1), "nodes": [*_green()[:2], _run("test", "FAILURE")], "hasNextPage": True}
    verdict = ps.shape_pr(_pr(1), sorted(REQUIRED), ctx)["required"]
    assert verdict["state"] == "UNKNOWN" and verdict["failing"] == []


def test_pr_on_another_base_is_not_judged_by_mains_list(tmp_path: Path) -> None:
    red = [*_green()[:2], _run("test", "FAILURE")]
    _, doc = _main(tmp_path, FakeGh([_pr(1, base="release/1.0")], {1: red}))
    required = doc["data"]["pullRequests"][0]["required"]
    assert required["state"] == "UNKNOWN" and "release/1.0" in required["reason"]


def test_the_lock_is_held_during_the_poll_and_free_after(tmp_path: Path) -> None:
    fake = FakeGh([_pr(1)], {1: _green()})
    seen: list[int | None] = []

    def gh(args: list[str], stdin: str | None) -> str:
        fd = ps.acquire_lock(tmp_path)  # a second handle, as another poller would try
        seen.append(fd)
        if fd is not None:
            ps.release_lock(fd)
        return fake(args, stdin)

    rc, _ = _main(tmp_path, gh)
    assert rc == 0 and seen and all(fd is None for fd in seen)
    after = ps.acquire_lock(tmp_path)
    assert after is not None
    ps.release_lock(after)
    assert ps.lock_path(tmp_path).exists()  # the file stays; only the lock comes and goes


def test_failed_part_is_recorded(tmp_path: Path) -> None:
    reply = {"data": None, "errors": [{"message": "Something went wrong"}]}

    def gh(args: list[str], stdin: str | None) -> str:
        if args[1] == "graphql" and stdin and "p1:" in stdin:
            raise ps.GhError("gh api graphql exited 1", json.dumps(reply))
        return FakeGh([_pr(1)], {1: _green()})(args, stdin)

    rc, doc = _main(tmp_path, gh)
    assert rc == 1 and doc["errorPart"] == "contexts PRs 1-1"


def test_rate_limit_without_reset_waits_the_fixed_long_wait(tmp_path: Path) -> None:
    rc, doc = _main(tmp_path, FakeGh([], {}, fail="HTTP 403: API rate limit exceeded"))
    assert rc == 1
    expected = NOW + timedelta(seconds=ps.RATE_LIMIT_FALLBACK_SECONDS)
    assert doc["nextPollNotBefore"] == ps.iso(expected)


def test_another_repos_cache_is_not_carried_over(tmp_path: Path) -> None:
    _main(tmp_path, FakeGh([_pr(1)], {1: _green()}))
    rc, doc = _main(tmp_path, FakeGh([], {}, fail="HTTP 502"), NOW, "--repo", "o/other")
    assert rc == 1 and doc["repo"] == "o/other"
    assert doc["data"] is None and doc["requiredContexts"] is None


def test_backoff_skips_without_calling_gh(tmp_path: Path) -> None:
    _main(tmp_path, FakeGh([], {}, fail="boom"))  # nextPollNotBefore = NOW + 2 min
    gh = FakeGh([_pr(1)], {1: _green()})
    rc, doc = _main(tmp_path, gh, NOW + timedelta(minutes=1))
    assert rc == 0 and gh.calls == [] and doc["error"] == "pulls: boom"
    rc, doc = _main(tmp_path, gh, NOW + timedelta(minutes=1), "--force")
    assert rc == 0 and doc["error"] is None


def test_failure_backoff_doubles_and_caps(tmp_path: Path) -> None:
    prev: dict[str, Any] | None = None
    delays = []
    for _ in range(8):
        prev = ps.failed("o/r", prev, "x", NOW)
        nb = ps.parse_iso(prev["nextPollNotBefore"])
        assert nb is not None
        delays.append(int((nb - NOW).total_seconds()))
    assert delays[:4] == [120, 240, 480, 960]
    assert max(delays) == ps.FAIL_MAX_DELAY


def test_low_rate_lengthens_interval(tmp_path: Path) -> None:
    _, doc = _main(tmp_path, FakeGh([_pr(1)], {1: _green()}, remaining=ps.RATE_LOW - 1))
    assert doc["nextPollNotBefore"] == "2026-10-22T12:10:00Z"
    _, doc = _main(
        tmp_path, FakeGh([_pr(1)], {1: _green()}, remaining=ps.RATE_FLOOR - 1), NOW, "--force"
    )
    assert doc["nextPollNotBefore"] == "2026-10-22T12:40:00Z"


def test_required_list_is_reused_within_the_hour(tmp_path: Path) -> None:
    _main(tmp_path, FakeGh([_pr(1)], {1: _green()}))
    gh = FakeGh([_pr(1)], {1: _green()})
    _main(tmp_path, gh, NOW + timedelta(minutes=30))
    assert not any(c[-1].startswith("repos/") for c in gh.calls)
    gh = FakeGh([_pr(1)], {1: _green()})
    _, doc = _main(tmp_path, gh, NOW + timedelta(minutes=61))
    assert any(c[-1].startswith("repos/") for c in gh.calls)
    assert doc["requiredContextsFetchedAt"] == "2026-10-22T13:01:00Z"


def test_no_required_list_reads_unknown_not_green(tmp_path: Path) -> None:
    def gh(args: list[str], stdin: str | None) -> str:
        if args[-1].startswith("repos/"):
            raise ps.GhError("HTTP 403")
        return FakeGh([_pr(1)], {1: _green()})(args, stdin)

    rc, doc = _main(tmp_path, gh)
    assert rc == 0
    assert doc["requiredContexts"] is None and "403" in doc["requiredContextsError"]
    assert doc["data"]["pullRequests"][0]["required"]["state"] == "UNKNOWN"


_INSTALLER = _ROOT / "scripts" / "coord" / "install-pr-state-task.ps1"
_PWSH = shutil.which("pwsh")
_NEEDS_PWSH = pytest.mark.skipif(
    _PWSH is None or sys.platform != "win32", reason="a Windows scheduled task; needs pwsh"
)


def _installer(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    assert _PWSH is not None
    return subprocess.run(
        [_PWSH, "-NoProfile", "-NonInteractive", "-File", str(_INSTALLER), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        check=False,
        env={**os.environ, **(env or {})},
    )


@_NEEDS_PWSH
def test_installer_plan_registers_nothing() -> None:
    proc = _installer("-Json")
    assert proc.returncode == 0, proc.stderr
    plan = json.loads(proc.stdout)
    assert plan["taskName"] == "MEFOR-PR-State"
    assert plan["trigger"]["everyMinutes"] == 2
    assert plan["runLevel"] == "Limited" and plan["logonType"] == "Interactive"
    assert plan["poller"].replace("\\", "/").endswith("scripts/coord/pr_state.py")
    assert plan["cache"].replace("\\", "/").endswith("mefor-coord/pr-state.json")
    assert "--coord-dir" in plan["argument"] and plan["argument"].startswith("-I ")


@_NEEDS_PWSH
def test_installer_host_breaker_and_session_refusal() -> None:
    wrong = _installer("-ExpectedHost", "NOT-THIS-HOST-X", "-Json")
    said = wrong.stderr + wrong.stdout
    assert wrong.returncode != 0 and "STOP" in said and "nothing ran" in said
    no_host = _installer(env={"CLAUDECODE": "1"})
    assert no_host.returncode == 2 and "-ExpectedHost" in no_host.stderr
    here = os.environ.get("COMPUTERNAME") or platform.node().split(".")[0].upper()
    # A decoy name and an interpreter that cannot exist: if the session refusal ever regresses, this
    # still registers nothing on the developer's machine.
    decoy = ["-TaskName", "MEFOR-PR-State-TEST-DECOY", "-Python", r"C:\no\such\pythonw.exe"]
    in_session = _installer("-ExpectedHost", here, *decoy, env={"CLAUDECODE": "1"})
    assert in_session.returncode == 2 and "inside Claude Code" in in_session.stderr


def test_rerun_green_speaks_for_the_name(tmp_path: Path) -> None:
    failed_first = {**_run("test", "FAILURE"), "startedAt": "2026-10-22T10:00:00Z"}
    green_later = {**_run("test"), "startedAt": "2026-10-22T11:00:00Z"}
    contexts = [_run("CI gate"), _run("cla"), green_later, failed_first]
    _, doc = _main(tmp_path, FakeGh([_pr(1)], {1: contexts}))
    assert doc["data"]["pullRequests"][0]["required"]["state"] == "SUCCESS"


def test_github_required_check_missing_from_list_still_counts(tmp_path: Path) -> None:
    extra = {**_run("new-required", "FAILURE"), "isRequired": True}
    _, doc = _main(tmp_path, FakeGh([_pr(1)], {1: [*_green(), extra]}))
    required = doc["data"]["pullRequests"][0]["required"]
    assert required["state"] == "FAILURE" and required["failing"] == ["new-required"]
    assert required["requiredByGithubNotInList"] == ["new-required"]


def test_truncated_context_page_never_reads_green(tmp_path: Path) -> None:
    pr = _pr(1)
    ctx = {"oid": _sha(1), "nodes": _green(), "hasNextPage": True}
    verdict = ps.shape_pr(pr, sorted(REQUIRED), ctx)["required"]
    assert verdict["state"] == "UNKNOWN" and sorted(verdict["unknown"]) == sorted(REQUIRED)


def test_unlisted_verdict_is_pending_not_green(tmp_path: Path) -> None:
    # STALE is a real CheckRun conclusion that no list named; _pr_checks now allowlists passes.
    contexts = [_run("CI gate"), _run("cla"), _run("test", "STALE")]
    _, doc = _main(tmp_path, FakeGh([_pr(1)], {1: contexts}))
    assert doc["data"]["pullRequests"][0]["required"]["pending"] == ["test"]


def test_required_list_is_the_union_of_protection_and_rulesets(tmp_path: Path) -> None:
    _, doc = _main(tmp_path, FakeGh([], {}))
    assert doc["requiredContexts"] == sorted(REQUIRED)
    # GitHub said there are none: the one case where an empty list is the right answer.
    assert doc["data"]["pullRequests"] == []


# --- Review round 1 of the 2026-10-22 brief. ---------------------------------------------------------


def test_a_future_backoff_stamp_is_not_obeyed(tmp_path: Path) -> None:
    _main(tmp_path, FakeGh([], {}, fail="boom"))
    path = tmp_path / "pr-state.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    doc["nextPollNotBefore"] = "2026-11-30T00:00:00Z"  # a skewed clock wrote this
    path.write_text(json.dumps(doc), encoding="utf-8")
    gh = FakeGh([_pr(1)], {1: _green()})
    rc, doc = _main(tmp_path, gh, NOW + timedelta(minutes=5))
    assert rc == 0 and gh.calls and doc["error"] is None


def test_unknown_checkrun_status_reads_as_running(tmp_path: Path) -> None:
    odd = {**_run("test", "", "SOMETHING_NEW"), "startedAt": "2026-10-22T10:00:00Z"}
    newer = {**_run("test"), "startedAt": "2026-10-22T11:00:00Z"}
    _, doc = _main(tmp_path, FakeGh([_pr(1)], {1: [_run("CI gate"), _run("cla"), odd, newer]}))
    assert doc["data"]["pullRequests"][0]["required"]["pending"] == ["test"]


# --- The OS lock (review round 2 of the 2026-10-22 brief) ---------------------------------------------


def _hold_lock_elsewhere(local: Path) -> int:
    """Take the poller's lock through a second handle, as another poller's process would."""
    fd = ps.acquire_lock(local)
    assert fd is not None
    return fd


def test_a_held_lock_skips_quietly(tmp_path: Path) -> None:
    """Fails on 9cc98a971, whose lock was a file this held handle does not create."""
    fd = _hold_lock_elsewhere(tmp_path)
    try:
        gh = FakeGh([_pr(1)], {1: _green()})
        rc = ps.main(["--out", str(tmp_path / "c.json")], gh=gh, now=lambda: NOW, local=tmp_path)
        assert rc == 0 and gh.calls == []
        assert not (tmp_path / "c.json").exists()
    finally:
        ps.release_lock(fd)
    rc, doc = _main(tmp_path, FakeGh([_pr(1)], {1: _green()}))
    assert rc == 0 and doc["error"] is None


def test_a_killed_holder_releases_the_lock(tmp_path: Path) -> None:
    """A process that takes the lock and dies without releasing it leaves nothing to steal."""
    code = (
        "import importlib.util, sys; from pathlib import Path\n"
        f"spec = importlib.util.spec_from_file_location('ps', {str(_SCRIPT)!r})\n"
        "m = importlib.util.module_from_spec(spec); sys.modules['ps'] = m; spec.loader.exec_module(m)\n"
        f"assert m.acquire_lock(Path({str(tmp_path)!r})) is not None\n"
        "import os; os._exit(9)\n"
    )
    done = subprocess.run([sys.executable, "-c", code], check=False, timeout=60)
    assert done.returncode == 9
    # Windows frees a dead process's lock "depending on available system resources", so wait a
    # bounded while for the kernel, never for a cleanup this code would have to do.
    deadline = time.monotonic() + 10
    while (fd := ps.acquire_lock(tmp_path)) is None and time.monotonic() < deadline:
        time.sleep(0.05)
    assert fd is not None, "the kernel did not release a dead process's lock within 10 s"
    ps.release_lock(fd)
    rc, doc = _main(tmp_path, FakeGh([_pr(1)], {1: _green()}))
    assert rc == 0 and doc["error"] is None


def test_an_unusable_lock_directory_is_a_failing_result(tmp_path: Path) -> None:
    (tmp_path / "locks").write_text("a file where the directory should be", encoding="utf-8")
    gh = FakeGh([_pr(1)], {1: _green()})
    rc = ps.main(["--out", str(tmp_path / "c.json")], gh=gh, now=lambda: NOW, local=tmp_path)
    assert rc == 4 and gh.calls == []


def test_a_same_named_run_github_does_not_require_cannot_speak(tmp_path: Path) -> None:
    """CONTROL (fails on 3eb3bbc19, which read SUCCESS): the counted run may not exist yet."""
    other_app = {**_run("test"), "isRequired": False}
    _, doc = _main(tmp_path, FakeGh([_pr(1)], {1: [_run("CI gate"), _run("cla"), other_app]}))
    required = doc["data"]["pullRequests"][0]["required"]
    assert required["state"] == "UNKNOWN" and required["unknown"] == ["test"]
    required_run = {**_run("test", "", "QUEUED"), "isRequired": True}
    _, doc = _main(
        tmp_path,
        FakeGh([_pr(1)], {1: [_run("CI gate"), _run("cla"), other_app, required_run]}),
        NOW,
        "--force",
    )
    assert doc["data"]["pullRequests"][0]["required"]["pending"] == ["test"]


def test_a_failure_keeps_what_the_poll_learned(tmp_path: Path) -> None:
    reply = {
        "data": {
            "rateLimit": {
                "cost": 1,
                "remaining": 0,
                "limit": 5000,
                "resetAt": "2026-10-22T12:45:00Z",
            }
        },
        "errors": [{"message": "API rate limit exceeded"}],
    }

    def gh(args: list[str], stdin: str | None) -> str:
        if args[1] == "graphql":
            raise ps.GhError("gh api graphql exited 1", json.dumps(reply))
        return FakeGh([], {})(args, stdin)

    rc, doc = _main(tmp_path, gh)
    assert rc == 1
    assert doc["rateLimit"]["remaining"] == 0
    assert doc["requiredContexts"] == sorted(REQUIRED)
    assert doc["requiredContextsFetchedAt"] == "2026-10-22T12:00:00Z"


# --- The third fix brief of 2026-10-22 ------------------------------------------------------------


def test_a_lock_error_that_is_not_contention_is_exit_4_with_the_error_cached(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """CONTROL (fails on 3eb3bbc19, which read every OSError as "held" and exited 0)."""
    _main(tmp_path, FakeGh([_pr(1)], {1: _green()}))

    def broken(*args: object) -> None:
        raise OSError(errno.EIO, "I/O error")

    if sys.platform == "win32":
        import msvcrt

        monkeypatch.setattr(msvcrt, "locking", broken)
    else:
        import fcntl

        monkeypatch.setattr(fcntl, "flock", broken)
    gh = FakeGh([_pr(1)], {1: _green()})
    rc, doc = _main(tmp_path, gh, NOW + timedelta(minutes=10))
    assert rc == 4 and gh.calls == []
    assert doc["error"] and "cannot lock" in doc["error"] and doc["errorPart"] == "lock"
    assert [p["number"] for p in doc["data"]["pullRequests"]] == [1]


def test_a_contexts_failure_keeps_the_main_querys_budget(tmp_path: Path) -> None:
    def gh(args: list[str], stdin: str | None) -> str:
        if args[1] == "graphql" and stdin and "p1:" in stdin:
            raise ps.GhError("gh api graphql exited 1: HTTP 502")
        return FakeGh([_pr(1)], {1: _green()}, remaining=ps.RATE_FLOOR - 1)(args, stdin)

    rc, doc = _main(tmp_path, gh)
    assert rc == 1 and doc["errorPart"].startswith("contexts")
    assert doc["rateLimit"]["remaining"] == ps.RATE_FLOOR - 1
    assert doc["nextPollNotBefore"] == "2026-10-22T12:40:00Z"  # the reset, not the 2-minute retry


def test_an_unexpected_shape_names_its_part_and_keeps_the_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def odd_reply(*args: object) -> None:
        raise KeyError("a field the contexts reply did not carry")

    monkeypatch.setattr(ps, "fetch_contexts", odd_reply)
    rc, doc = _main(tmp_path, FakeGh([_pr(1)], {1: _green()}))
    assert rc == 1 and doc["errorPart"] == "contexts"
    assert "unexpected reply shape" in doc["error"]
    assert doc["rateLimit"]["remaining"] == 4900 and doc["requiredContexts"] == sorted(REQUIRED)


def test_a_truncated_page_still_lists_github_required_names() -> None:
    extra = {**_run("new-required"), "isRequired": True}
    ctx = {"oid": _sha(1), "nodes": [*_green(), extra], "hasNextPage": True}
    verdict = ps.shape_pr(_pr(1), sorted(REQUIRED), ctx)["required"]
    assert verdict["requiredByGithubNotInList"] == ["new-required"]
    assert "new-required" in verdict["unknown"]


def test_a_stale_required_run_is_not_green(tmp_path: Path) -> None:
    contexts = [_run("CI gate"), _run("cla"), _run("test", "STALE")]
    _, doc = _main(tmp_path, FakeGh([_pr(1)], {1: contexts}))
    assert doc["data"]["pullRequests"][0]["required"]["pending"] == ["test"]


# --- Review round 1 of the third fix brief -----------------------------------------------------------


def test_a_lock_failure_never_overwrites_a_fresh_poll(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _main(tmp_path, FakeGh([_pr(1)], {1: _green()}))
    before = (tmp_path / "pr-state.json").read_bytes()

    def broken(local: Path) -> int | None:
        raise ps.LockUnavailable("cannot open: a sharing violation in this run only")

    monkeypatch.setattr(ps, "acquire_lock", broken)
    rc, _ = _main(tmp_path, FakeGh([], {}), NOW + timedelta(minutes=2))
    assert rc == 4
    assert (tmp_path / "pr-state.json").read_bytes() == before


def test_another_repo_needs_its_own_out(tmp_path: Path) -> None:
    gh = FakeGh([_pr(1)], {1: _green()})
    rc = ps.main(["--repo", "o/other"], gh=gh, now=lambda: NOW, local=tmp_path)
    assert rc == 2 and gh.calls == [] and not (tmp_path / "pr-state.json").exists()


def test_an_unwritable_cache_is_a_distinct_failing_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(path: Path, doc: dict[str, Any]) -> None:
        raise PermissionError("a reader holds the file open")

    monkeypatch.setattr(ps, "write_cache", refuse)
    gh = FakeGh([_pr(1)], {1: _green()})
    rc = ps.main(["--out", str(tmp_path / "c.json")], gh=gh, now=lambda: NOW, local=tmp_path)
    assert rc == 5


def test_messages_go_to_a_log_file_when_there_is_no_stderr(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sys, "stderr", None)
    rc, _ = _main(tmp_path, FakeGh([], {}, fail="HTTP 502"))
    assert rc == 1
    assert "HTTP 502" in (tmp_path / "pr-state.log").read_text(encoding="utf-8")


def test_a_bad_head_sha_never_reaches_the_query() -> None:
    with pytest.raises(ps.PollError):
        ps.contexts_query({1: 'abc") { x } y: object(oid: "'})
