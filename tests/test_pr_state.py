# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The PR-state poller writes one cache that read-only panes trust, so its failure shapes matter most.

These drive the REAL ``main()`` against canned gh replies, with no network. The positive control is
``test_error_path_never_writes_an_empty_list``: it must fail if a failed poll ever wrote ``[]``.
"""

from __future__ import annotations

import importlib.util
import json
import os
import platform
import shutil
import subprocess
import sys
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from tests._dead_pid import never_live_pid

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


def _pr(
    number: int, *, mergeable: str = "MERGEABLE", merge_state: str = "CLEAN", base: str = "main"
) -> dict[str, Any]:
    return {
        "number": number,
        "title": f"pr {number}",
        "baseRefName": base,
        "headRefName": f"b{number}",
        "headRefOid": f"oid{number}",
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
                        "oid": f"oid{number}",
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
                repo[f"p{n}"] = {
                    "commits": {
                        "nodes": [
                            {
                                "commit": {
                                    "oid": f"oid{n}",
                                    "statusCheckRollup": {
                                        "contexts": {
                                            "pageInfo": {"hasNextPage": False},
                                            "nodes": nodes,
                                        }
                                    },
                                }
                            }
                        ]
                    }
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
    assert not (tmp_path / "locks" / "pr-state.lock").exists()


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


def test_lock_held_skips_quietly(tmp_path: Path) -> None:
    (tmp_path / "locks").mkdir()
    lock = tmp_path / "locks" / "pr-state.lock"
    lock.write_text("pid=1 host=X at=now", encoding="utf-8")
    gh = FakeGh([_pr(1)], {1: _green()})
    rc = ps.main(["--out", str(tmp_path / "c.json")], gh=gh, now=lambda: NOW, local=tmp_path)
    assert rc == 0
    assert gh.calls == []
    assert not (tmp_path / "c.json").exists()
    assert lock.read_text(encoding="utf-8") == "pid=1 host=X at=now"  # never stolen


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


def test_wedged_lock_leaves_the_cache_alone(tmp_path: Path) -> None:
    """Only the lock holder writes the cache. A wedged lock shows as an ageing fetchedAt."""
    _main(tmp_path, FakeGh([_pr(1)], {1: _green()}))
    before = (tmp_path / "pr-state.json").read_bytes()
    lock = tmp_path / "locks" / "pr-state.lock"
    lock.write_text("pid=1 host=SOME-OTHER-PC at=then", encoding="utf-8")
    old = lock.stat().st_mtime - ps.STALE_LOCK_SECONDS - 60
    os.utime(lock, (old, old))
    gh = FakeGh([_pr(1)], {1: _green()})
    rc, _ = _main(tmp_path, gh, NOW + timedelta(minutes=20))
    assert rc == 3 and gh.calls == []
    assert (tmp_path / "pr-state.json").read_bytes() == before
    assert lock.read_text(encoding="utf-8") == "pid=1 host=SOME-OTHER-PC at=then"


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
    ctx = {"oid": "oid1", "nodes": [*_green()[:2], _run("test", "FAILURE")], "hasNextPage": True}
    verdict = ps.shape_pr(_pr(1), sorted(REQUIRED), ctx)["required"]
    assert verdict["state"] == "UNKNOWN" and verdict["failing"] == []


def test_pr_on_another_base_is_not_judged_by_mains_list(tmp_path: Path) -> None:
    red = [*_green()[:2], _run("test", "FAILURE")]
    _, doc = _main(tmp_path, FakeGh([_pr(1, base="release/1.0")], {1: red}))
    required = doc["data"]["pullRequests"][0]["required"]
    assert required["state"] == "UNKNOWN" and "release/1.0" in required["reason"]


def test_release_never_deletes_another_pollers_lock(tmp_path: Path) -> None:
    lock = tmp_path / "locks" / "pr-state.lock"
    other = f"pid={never_live_pid()} host=SOME-OTHER-PC at=now"
    fake = FakeGh([_pr(1)], {1: _green()})

    def gh(args: list[str], stdin: str | None) -> str:
        lock.write_text(other, encoding="utf-8")  # another poller's lock replaced ours mid-poll
        return fake(args, stdin)

    rc, _ = _main(tmp_path, gh)
    assert rc == 0
    assert lock.read_text(encoding="utf-8") == other


def test_steal_does_not_take_a_lock_that_changed_after_it_was_judged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "locks").mkdir()
    lock = tmp_path / "locks" / "pr-state.lock"
    lock.write_text(f"pid={never_live_pid()} host={ps.coord_root.host()} at=dead", encoding="utf-8")
    live = "pid=1 host=SOME-OTHER-PC at=live"

    def judged_dead_then_raced(holder: str) -> bool:
        lock.write_text(live, encoding="utf-8")  # a second poller stole and re-locked first
        return True

    monkeypatch.setattr(ps, "_holder_is_gone", judged_dead_then_raced)
    gh = FakeGh([_pr(1)], {1: _green()})
    rc = ps.main(["--out", str(tmp_path / "c.json")], gh=gh, now=lambda: NOW, local=tmp_path)
    assert rc == 0 and gh.calls == []
    assert lock.read_text(encoding="utf-8") == live
    assert list((tmp_path / "locks").iterdir()) == [lock]


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
    assert "--coord-dir" in plan["argument"]


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
    ctx = {"oid": "oid1", "nodes": _green(), "hasNextPage": True}
    verdict = ps.shape_pr(pr, sorted(REQUIRED), ctx)["required"]
    assert verdict["state"] == "UNKNOWN" and sorted(verdict["unknown"]) == sorted(REQUIRED)


@pytest.mark.skipif(sys.platform != "win32", reason="the pid check is Windows-only")
def test_lock_of_a_dead_pid_on_this_host_is_recovered(tmp_path: Path) -> None:
    dead = subprocess.Popen([sys.executable, "-c", "pass"])
    dead.wait()
    (tmp_path / "locks").mkdir()
    lock = tmp_path / "locks" / "pr-state.lock"
    lock.write_text(f"pid={dead.pid} host={ps.coord_root.host()} at=then", encoding="utf-8")
    rc, doc = _main(tmp_path, FakeGh([_pr(1)], {1: _green()}))
    assert rc == 0 and doc["error"] is None and not lock.exists()


def test_live_or_foreign_holder_is_not_recovered() -> None:
    assert ps._holder_is_gone(f"pid={os.getpid()} host={ps.coord_root.host()} at=x") is False
    assert ps._holder_is_gone("pid=1 host=SOME-OTHER-PC at=x") is False
    assert ps._holder_is_gone(f"pid=notanumber host={ps.coord_root.host()}") is False


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
