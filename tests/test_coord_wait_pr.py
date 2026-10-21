# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``scripts/coord/wait-pr.ps1``, the bounded background wait on a pull request.

The AFK-autonomy plan's section 6.2 asked for it (docs/AUTONOMY-PLAN.md, on branch
``autonomy-plan`` and not yet on main when this was written).

Every test drives the script against a stub ``gh`` that answers ``gh api -i`` the way gh 2.102.0
was measured to: a status line and headers on stdout, a blank line, the body, and exit 1 for a 304
or a 4xx. The stub logs each call's arguments, so a test can assert what was SENT (the
``If-None-Match`` header) and not only what came back. The script runs the stub as its own pwsh
child process, the same path a real gh takes, so the per-call timeout and its kill are exercised
by the stub too. A recording sleeper stands in for
``Start-Sleep``, so a 60-minute wait runs in seconds and the clamped interval is observable.

Nothing reaches GitHub.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "coord" / "wait-pr.ps1"
REPO = "acme/widgets"
PR = 7
PR_PATH = f"repos/{REPO}/pulls/{PR}"
SHA = "a" * 40
RUNS_PATH = f"repos/{REPO}/commits/{SHA}/check-runs?per_page=100&page=1"
STATUS_PATH = f"repos/{REPO}/commits/{SHA}/status?per_page=100&page=1"
BRANCH_PATH = f"repos/{REPO}/branches/main"
RULES_PATH = f"repos/{REPO}/rules/branches/main?per_page=100&page=1"
SEAMS = {**os.environ, "MEFOR_WAIT_PR_TEST_SEAMS": "1"}
TIMEOUT = 120

pytestmark = pytest.mark.skipif(shutil.which("pwsh") is None, reason="the script runs under pwsh")

STUB = r"""
$a = @($args)
$path = [string]$a[-1]
Add-Content -LiteralPath '__LOG__' -Value (ConvertTo-Json -Compress -InputObject $a)
$plan = Get-Content -Raw -LiteralPath '__PLAN__' | ConvertFrom-Json -AsHashtable
$counts = @{}
if (Test-Path -LiteralPath '__COUNTS__') {
    $counts = Get-Content -Raw -LiteralPath '__COUNTS__' | ConvertFrom-Json -AsHashtable
}
if (-not $plan.ContainsKey($path)) { [Console]::Error.WriteLine("stub: unplanned $path"); exit 1 }
$n = if ($counts.ContainsKey($path)) { [int]$counts[$path] } else { 0 }
$counts[$path] = $n + 1
Set-Content -LiteralPath '__COUNTS__' -Value (ConvertTo-Json -Compress -InputObject $counts)
$list = @($plan[$path])
$resp = $list[[math]::Min($n, $list.Count - 1)]
if ($resp.ContainsKey('hang')) {
    Add-Content -LiteralPath '__PIDS__' -Value $PID
    Start-Sleep -Seconds 600
    exit 0
}
"HTTP/2.0 $($resp['status']) Stub"
if ($resp.ContainsKey('etag')) { "Etag: $($resp['etag'])" }
if ($resp.ContainsKey('headers')) { $resp['headers'] }
'X-Ratelimit-Resource: core'
''
if ($resp.ContainsKey('body')) { ConvertTo-Json -Compress -Depth 20 -InputObject $resp['body'] }
if ([int]$resp['status'] -ge 300) { [Console]::Error.WriteLine("gh: HTTP $($resp['status'])"); exit 1 }
exit 0
"""

SLEEPER = "Add-Content -LiteralPath '__SLEEPS__' -Value $args[0]\n"


def ok(body: Any, etag: str | None = None) -> dict[str, Any]:
    resp: dict[str, Any] = {"status": 200, "body": body}
    if etag is not None:
        resp["etag"] = etag
    return resp


def rate(remaining: int) -> dict[str, Any]:
    return ok({"resources": {"core": {"remaining": remaining}}})


def pr(
    state: str = "open", merged: bool = False, mergeable: str | None = "blocked", sha: str = SHA
) -> dict[str, Any]:
    return {
        "state": state,
        "merged": merged,
        "mergeable_state": mergeable,
        "head": {"sha": sha},
        "base": {"ref": "main"},
    }


NO_STATUSES = [ok({"state": "pending", "statuses": []})]


def ints(path: Path) -> list[int]:
    return [int(s) for s in path.read_text(encoding="utf-8").split()] if path.exists() else []


class Run:
    def __init__(
        self, proc: subprocess.CompletedProcess[str], log: Path, sleeps: Path, pids: Path
    ) -> None:
        self.code = proc.returncode
        self.out = proc.stdout
        self.err = proc.stderr
        self.calls: list[list[str]] = (
            [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
            if log.exists()
            else []
        )
        self.sleeps = ints(sleeps)
        # The process ids of the stub calls that hung on purpose.
        self.hung = ints(pids)

    def paths(self) -> list[str]:
        return [c[-1] for c in self.calls]


def wait_pr(
    tmp_path: Path,
    until: str,
    plan: dict[str, list[Any]],
    *args: str,
    env: dict[str, str] = SEAMS,
    gh: str | None = None,
) -> Run:
    """Run the script with ``-Until until``; ``plan`` maps a REST path to its answers in order.

    ``gh`` replaces the stub as ``-GhCommand``, so the plan is not read.
    """
    plan.setdefault("rate_limit", [rate(4000)])
    log, counts, sleeps = tmp_path / "gh.log", tmp_path / "counts.json", tmp_path / "sleeps.log"
    pids = tmp_path / "hung.log"
    plan_file = tmp_path / "plan.json"
    plan_file.write_text(json.dumps(plan), encoding="utf-8")
    stub = tmp_path / "gh-stub.ps1"
    stub.write_text(
        STUB.replace("__LOG__", str(log))
        .replace("__PLAN__", str(plan_file))
        .replace("__COUNTS__", str(counts))
        .replace("__PIDS__", str(pids)),
        encoding="utf-8",
    )
    sleeper = tmp_path / "sleeper.ps1"
    sleeper.write_text(SLEEPER.replace("__SLEEPS__", str(sleeps)), encoding="utf-8")
    proc = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-File",
            str(SCRIPT),
            "-Repo",
            REPO,
            "-Pr",
            str(PR),
            "-GhCommand",
            gh or str(stub),
            "-SleepCommand",
            str(sleeper),
            "-Until",
            until,
            *args,
        ],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        env=env,
    )
    return Run(proc, log, sleeps, pids)


def test_an_already_merged_pr_exits_0_after_one_read_and_no_sleep(tmp_path: Path) -> None:
    run = wait_pr(tmp_path, "merged", {PR_PATH: [ok(pr("closed", merged=True))]})
    assert run.code == 0, run.err
    assert "met: merged" in run.out
    assert run.paths() == ["rate_limit", PR_PATH]
    assert run.sleeps == []


def test_a_pr_that_never_merges_times_out_with_exit_2(tmp_path: Path) -> None:
    """4 minutes at 120 s: checks at 0, 120 and 240 s, two sleeps, then exit 2 -- not exit 1."""
    run = wait_pr(tmp_path, "merged", {PR_PATH: [ok(pr())]}, "-MaxMinutes", "4")
    assert run.code == 2, run.err
    assert "timeout: merged not met within 4 min" in run.out
    assert run.sleeps == [120, 120]
    assert run.paths().count(PR_PATH) == 3
    # An unchanging PR prints its state once, not once per check.
    assert run.out.count("state=open") == 1


def test_too_little_rate_budget_refuses_before_reading_the_pr(tmp_path: Path) -> None:
    run = wait_pr(
        tmp_path,
        "merged",
        {"rate_limit": [rate(499)], PR_PATH: [ok(pr("closed", merged=True))]},
    )
    assert run.code == 1
    assert "refusing to start: 499 core requests remain" in run.err
    assert run.paths() == ["rate_limit"]


def test_the_rate_floor_itself_is_enough_to_start(tmp_path: Path) -> None:
    """The control for the refusal above: a script refusing every start would pass that test."""
    run = wait_pr(
        tmp_path,
        "merged",
        {"rate_limit": [rate(500)], PR_PATH: [ok(pr("closed", merged=True))]},
    )
    assert run.code == 0, run.err


def test_the_interval_is_clamped_up_and_the_total_down(tmp_path: Path) -> None:
    """5 s becomes 120 s and 99 min becomes 60 min: 30 sleeps of 120 s, never more."""
    run = wait_pr(
        tmp_path,
        "closed",
        {PR_PATH: [ok(pr())]},
        "-IntervalSeconds",
        "5",
        "-MaxMinutes",
        "99",
    )
    assert run.code == 2, run.err
    assert "interval raised from 5 s to the 120 s floor" in run.out
    assert "total wait lowered from 99 min to the 60 min ceiling" in run.out
    assert run.sleeps == [120] * 30


def test_a_304_reuses_the_cached_body_and_is_not_counted(tmp_path: Path) -> None:
    """The second read sends the first read's ETag back; the 304 it gets is not a state change."""
    etag = '"e1"'
    run = wait_pr(
        tmp_path,
        "merged",
        {PR_PATH: [ok(pr(), etag), {"status": 304, "etag": etag}, ok(pr("closed", True), '"e2"')]},
    )
    assert run.code == 0, run.err
    pr_calls = [c for c in run.calls if c[-1] == PR_PATH]
    assert len(pr_calls) == 3
    assert f"If-None-Match: {etag}" not in pr_calls[0]
    assert f"If-None-Match: {etag}" in pr_calls[1]
    assert f"If-None-Match: {etag}" in pr_calls[2]
    assert run.out.count("state=open") == 1
    assert "3 requests, 1 of them 304 and not counted" in run.out


def test_a_pr_closed_without_merging_on_two_checks_cannot_meet_merged(tmp_path: Path) -> None:
    run = wait_pr(tmp_path, "merged", {PR_PATH: [ok(pr("closed", merged=False))]})
    assert run.code == 1
    assert "closed without merging on two checks in a row" in run.err
    assert run.sleeps == [120]


def test_a_pr_closed_and_reopened_to_rerun_ci_is_still_waited_on(tmp_path: Path) -> None:
    run = wait_pr(
        tmp_path,
        "merged",
        {PR_PATH: [ok(pr("closed")), ok(pr()), ok(pr("closed")), ok(pr("closed", merged=True))]},
    )
    assert run.code == 0, run.err
    assert run.sleeps == [120, 120, 120]


def test_closed_is_met_by_a_pr_closed_without_merging(tmp_path: Path) -> None:
    run = wait_pr(tmp_path, "closed", {PR_PATH: [ok(pr()), ok(pr("closed"))]})
    assert run.code == 0, run.err
    assert "met: closed" in run.out
    assert run.sleeps == [120]


def test_a_transient_5xx_is_read_again_next_interval(tmp_path: Path) -> None:
    run = wait_pr(
        tmp_path,
        "merged",
        {PR_PATH: [ok(pr()), {"status": 502}, ok(pr("closed", merged=True))]},
    )
    assert run.code == 0, run.err
    assert "transient, reading again next interval" in run.out
    assert "HTTP 502" in run.out
    assert run.sleeps == [120, 120]


def test_the_sleep_seam_is_refused_outside_tests(tmp_path: Path) -> None:
    """A no-op sleeper would remove the 120 s floor, so it needs the test-only switch."""
    env = {k: v for k, v in os.environ.items() if k != "MEFOR_WAIT_PR_TEST_SEAMS"}
    run = wait_pr(tmp_path, "merged", {PR_PATH: [ok(pr("closed", True))]}, env=env)
    assert run.code == 1
    assert "-SleepCommand is a test seam" in run.err
    assert run.calls == []


def test_checks_complete_waits_for_a_required_context_that_has_not_started(
    tmp_path: Path,
) -> None:
    """Every listed run is green on the first read, but a required roll-up has no run yet.

    One context is required by classic protection and one by a ruleset, so both reads count.
    """
    lint = {"name": "lint", "status": "completed", "conclusion": "success"}
    gate = {"name": "CI gate", "status": "completed", "conclusion": "failure"}
    run = wait_pr(
        tmp_path,
        "checks-complete",
        {
            PR_PATH: [ok(pr())],
            BRANCH_PATH: [
                ok(
                    {
                        "protected": True,
                        "protection": {"required_status_checks": {"contexts": ["lint"]}},
                    }
                )
            ],
            RULES_PATH: [
                ok(
                    [
                        {"type": "deletion"},
                        {
                            "type": "required_status_checks",
                            "parameters": {"required_status_checks": [{"context": "CI gate"}]},
                        },
                    ]
                )
            ],
            RUNS_PATH: [
                ok({"total_count": 1, "check_runs": [lint]}),
                ok({"total_count": 2, "check_runs": [lint, gate]}),
            ],
            STATUS_PATH: NO_STATUSES,
        },
    )
    assert run.code == 0, run.err
    assert "required contexts on main: 2" in run.out
    assert run.sleeps == [120]
    assert "required not reported=1" in run.out
    assert "met: checks-complete" in run.out
    assert "1 failure, 1 success" in run.out


def test_an_unprotected_base_is_said_out_loud_and_no_check_is_not_complete(
    tmp_path: Path,
) -> None:
    run = wait_pr(
        tmp_path,
        "checks-complete",
        {
            PR_PATH: [ok(pr())],
            BRANCH_PATH: [ok({"name": "main", "protected": False})],
            RULES_PATH: [ok([])],
            RUNS_PATH: [ok({"total_count": 0, "check_runs": []})],
            STATUS_PATH: NO_STATUSES,
        },
        "-MaxMinutes",
        "2",
    )
    # No check at all is not "complete": the wait times out rather than meeting the condition.
    assert run.code == 2, run.err
    assert "no required contexts on main" in run.out


def test_a_transient_failure_reading_the_required_set_reads_it_again(tmp_path: Path) -> None:
    """A 502 part-way through must not leave the base marked read with an empty required set."""
    lint = {"name": "lint", "status": "completed", "conclusion": "success"}
    gate = {"name": "CI gate", "status": "completed", "conclusion": "success"}
    run = wait_pr(
        tmp_path,
        "checks-complete",
        {
            PR_PATH: [ok(pr())],
            BRANCH_PATH: [
                {"status": 502},
                ok({"protected": True, "protection": {"required_status_checks": {"contexts": []}}}),
            ],
            RULES_PATH: [
                ok(
                    [
                        {
                            "type": "required_status_checks",
                            "parameters": {"required_status_checks": [{"context": "CI gate"}]},
                        }
                    ]
                )
            ],
            RUNS_PATH: [
                ok({"total_count": 1, "check_runs": [lint]}),
                ok({"total_count": 2, "check_runs": [lint, gate]}),
            ],
            STATUS_PATH: NO_STATUSES,
        },
    )
    assert run.code == 0, run.err
    # An empty classic list is a real answer; the ruleset still supplies the one required context.
    assert "required contexts on main: 1" in run.out
    assert "required not reported=1" in run.out
    assert run.sleeps == [120, 120]


def test_three_transient_failures_in_a_row_are_an_error(tmp_path: Path) -> None:
    run = wait_pr(tmp_path, "merged", {PR_PATH: [ok(pr()), {"status": 503}]})
    assert run.code == 1
    assert "three transient failures in a row" in run.err
    assert run.sleeps == [120, 120, 120]


def test_a_spent_rate_budget_mid_wait_stops_the_wait(tmp_path: Path) -> None:
    spent = {"status": 403, "headers": ["X-Ratelimit-Remaining: 0"], "body": {"message": "x"}}
    run = wait_pr(tmp_path, "merged", {PR_PATH: [ok(pr()), spent]})
    assert run.code == 1
    assert "X-Ratelimit-Remaining 0" in run.err
    assert run.sleeps == [120]


def test_a_total_shorter_than_one_interval_still_waits_one_interval(tmp_path: Path) -> None:
    run = wait_pr(tmp_path, "merged", {PR_PATH: [ok(pr())]}, "-MaxMinutes", "1")
    assert run.code == 2, run.err
    assert "total wait raised from 1 min to one interval, 120 s" in run.out
    assert run.sleeps == [120]


def test_a_protected_base_with_no_contexts_list_is_an_error_not_an_empty_set(
    tmp_path: Path,
) -> None:
    run = wait_pr(
        tmp_path,
        "checks-complete",
        {PR_PATH: [ok(pr())], BRANCH_PATH: [ok({"protected": True, "protection": {}})]},
    )
    assert run.code == 1
    assert "is protected but its branch payload names no" in run.err


def test_checks_complete_reads_every_page_and_waits_on_a_pending_status(tmp_path: Path) -> None:
    done = [
        {"name": f"leg {i}", "status": "completed", "conclusion": "success"} for i in range(100)
    ]
    late = {"name": "late", "status": "in_progress", "conclusion": None}
    late_done = {"name": "late", "status": "completed", "conclusion": "success"}
    page2 = f"repos/{REPO}/commits/{SHA}/check-runs?per_page=100&page=2"
    green = [{"context": f"ctx {i}", "state": "success"} for i in range(100)]
    status2 = f"repos/{REPO}/commits/{SHA}/status?per_page=100&page=2"

    def ext(state: str) -> dict[str, Any]:
        return ok({"total_count": 101, "statuses": [{"context": "ext", "state": state}]})

    run = wait_pr(
        tmp_path,
        "checks-complete",
        {
            PR_PATH: [ok(pr())],
            BRANCH_PATH: [ok({"protected": False})],
            RULES_PATH: [ok([])],
            RUNS_PATH: [ok({"total_count": 101, "check_runs": done})],
            page2: [
                ok({"total_count": 101, "check_runs": [late]}),
                ok({"total_count": 101, "check_runs": [late_done]}),
            ],
            STATUS_PATH: [ok({"total_count": 101, "statuses": green})],
            status2: [ext("pending"), ext("pending"), ext("success")],
        },
    )
    assert run.code == 0, run.err
    assert "runs=100/101 completed, statuses pending=1/101" in run.out
    assert "runs=101/101 completed, statuses pending=1/101" in run.out
    assert "202 success" in run.out
    assert run.sleeps == [120, 120]


def test_a_base_name_with_a_hash_is_escaped_in_the_path(tmp_path: Path) -> None:
    """`#` is legal in a branch name and would otherwise cut the path at a fragment."""
    body = pr()
    body["base"] = {"ref": "release/1#2"}
    run = wait_pr(
        tmp_path,
        "checks-complete",
        {
            PR_PATH: [ok(body)],
            f"repos/{REPO}/branches/release/1%232": [ok({"protected": False})],
            f"repos/{REPO}/rules/branches/release/1%232?per_page=100&page=1": [ok([])],
            RUNS_PATH: [
                ok(
                    {
                        "total_count": 1,
                        "check_runs": [
                            {"name": "a", "status": "completed", "conclusion": "success"}
                        ],
                    }
                )
            ],
            STATUS_PATH: NO_STATUSES,
        },
    )
    assert run.code == 0, run.err
    assert "no required contexts on release/1#2" in run.out


def test_a_refused_required_context_read_is_an_error_not_an_empty_set(tmp_path: Path) -> None:
    run = wait_pr(
        tmp_path,
        "checks-complete",
        {PR_PATH: [ok(pr())], BRANCH_PATH: [{"status": 404}]},
    )
    assert run.code == 1
    assert "answered HTTP 404" in run.err


@pytest.mark.parametrize("stale", ["dirty", "behind"])
def test_two_reads_that_need_a_push_on_one_head_exit_3(tmp_path: Path, stale: str) -> None:
    run = wait_pr(tmp_path, "merged", {PR_PATH: [ok(pr(mergeable=stale))]})
    assert run.code == 3, run.err
    assert f"needs a push: mergeable_state={stale} on two checks in a row of head {SHA}" in run.out
    assert run.sleeps == [120]


DIRTY = ok(pr(mergeable="dirty"))
MERGED = ok(pr("closed", merged=True))


@pytest.mark.parametrize(
    ("reads", "code", "sleeps"),
    [
        # A clean read between two dirty ones resets the count, so the merge is waited for.
        ([DIRTY, ok(pr(mergeable="clean")), DIRTY, MERGED], 0, 3),
        # Dirty on head A, then on head B: B has been read dirty once, not twice.
        ([DIRTY, ok(pr(mergeable="dirty", sha="b" * 40)), MERGED], 0, 2),
        # A closed read resets too: closed and reopened is a fresh start.
        ([DIRTY, ok(pr("closed", mergeable="dirty")), DIRTY, MERGED], 0, 3),
        # Still computing, or no answer at all, neither counts nor resets: exit 3 on the third
        # read, not the second.
        ([DIRTY, ok(pr(mergeable="unknown")), DIRTY, MERGED], 3, 2),
        ([DIRTY, ok(pr(mergeable=None)), DIRTY, MERGED], 3, 2),
        ([DIRTY, {"status": 502}, DIRTY, MERGED], 3, 2),
    ],
    ids=[
        "clean-resets",
        "new-head-resets",
        "closed-resets",
        "unknown-is-nothing",
        "null-is-nothing",
        "transient-is-nothing",
    ],
)
def test_what_resets_the_needs_a_push_count(
    tmp_path: Path, reads: list[dict[str, Any]], code: int, sleeps: int
) -> None:
    run = wait_pr(tmp_path, "merged", {PR_PATH: reads})
    assert run.code == code, run.err
    assert ("needs a push" in run.out) == (code == 3)
    assert run.sleeps == [120] * sleeps


@pytest.mark.parametrize("until", ["checks-complete", "closed"])
def test_only_until_merged_acts_on_a_pr_that_needs_a_push(tmp_path: Path, until: str) -> None:
    dirty = pr(mergeable="dirty")
    queued = {"name": "a", "status": "queued", "conclusion": None}
    done = {"name": "a", "status": "completed", "conclusion": "success"}
    run = wait_pr(
        tmp_path,
        until,
        {
            PR_PATH: [ok(dirty), ok(dirty), ok(pr("closed", mergeable="dirty"))],
            BRANCH_PATH: [ok({"protected": False})],
            RULES_PATH: [ok([])],
            RUNS_PATH: [
                ok({"total_count": 1, "check_runs": [queued]}),
                ok({"total_count": 1, "check_runs": [queued]}),
                ok({"total_count": 1, "check_runs": [done]}),
            ],
            STATUS_PATH: NO_STATUSES,
        },
    )
    assert run.code == 0, run.err
    assert "needs a push" not in run.out
    assert run.sleeps == [120, 120]


def test_a_gh_call_that_hangs_is_killed_and_counted_as_transient(tmp_path: Path) -> None:
    """Two hung reads keep the wait going; the third in a row is exit 1, and none survives.

    The timeout covers every call, so it is long enough for a cold pwsh start of the stub on a
    loaded runner, and short enough that three of them fit the per-test cap.
    """
    psutil = pytest.importorskip("psutil")
    run = wait_pr(
        tmp_path,
        "merged",
        {PR_PATH: [ok(pr()), {"hang": True}]},
        "-GhTimeoutSeconds",
        "8",
    )
    assert run.code == 1, run.out
    assert f"gh api {PR_PATH} did not finish within 8 s and was killed" in run.out
    assert "three transient failures in a row" in run.err
    assert run.sleeps == [120, 120, 120]
    assert len(run.hung) == 3
    assert not [pid for pid in run.hung if psutil.pid_exists(pid)]


def test_the_timeout_seam_is_refused_outside_tests(tmp_path: Path) -> None:
    env = {k: v for k, v in os.environ.items() if k != "MEFOR_WAIT_PR_TEST_SEAMS"}
    run = wait_pr(
        tmp_path,
        "merged",
        {PR_PATH: [ok(pr("closed", True))]},
        "-GhTimeoutSeconds",
        "5",
        env=env,
    )
    assert run.code == 1
    assert "-GhTimeoutSeconds is a test seam" in run.err
    assert run.calls == []


def test_a_gh_that_is_not_found_is_an_error_before_any_call(tmp_path: Path) -> None:
    run = wait_pr(tmp_path, "merged", {}, gh=str(tmp_path / "no-such-gh.exe"))
    assert run.code == 1
    assert "cannot find gh as" in run.err


def test_a_program_gh_runs_as_itself_and_its_exit_code_is_read(tmp_path: Path) -> None:
    """The path a real gh takes: a program, not a .ps1 stand-in, run with the gh arguments.

    Python stands in for it: `python api ...` cannot open a file named `api`, prints no status
    line and exits 2, so the starting read fails with that exit code in the message.
    """
    run = wait_pr(tmp_path, "merged", {}, gh=sys.executable)
    assert run.code == 1
    assert "gh api rate_limit printed no HTTP status line (exit 2)" in run.err


def test_a_weak_etag_keeps_its_quotes_on_the_way_to_gh(tmp_path: Path) -> None:
    """The ETag goes to gh through ArgumentList, so its embedded quotes and space survive."""
    etag = 'W/"e 1"'
    run = wait_pr(tmp_path, "merged", {PR_PATH: [ok(pr(), etag), ok(pr("closed", True))]})
    assert run.code == 0, run.err
    pr_calls = [c for c in run.calls if c[-1] == PR_PATH]
    assert f"If-None-Match: {etag}" in pr_calls[1]
