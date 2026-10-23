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

import psutil
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
# Escaped, so a non-ASCII test character survives this child's console code page on its way out.
if ($resp.ContainsKey('body')) {
    ConvertTo-Json -Compress -Depth 20 -EscapeHandling EscapeNonAscii -InputObject $resp['body']
}
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
    state: str = "open",
    merged: bool = False,
    mergeable: str | None = "blocked",
    sha: str = SHA,
    base: str = "main",
) -> dict[str, Any]:
    return {
        "state": state,
        "merged": merged,
        "mergeable_state": mergeable,
        "head": {"sha": sha},
        "base": {"ref": base},
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
        # A known, empty working directory: a program gh resolves relative names against it.
        cwd=tmp_path,
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


DIRTY = ok(pr(mergeable="dirty"))
BEHIND = ok(pr(mergeable="behind"))
MERGED = ok(pr("closed", merged=True))


def test_two_dirty_reads_on_one_head_exit_3(tmp_path: Path) -> None:
    run = wait_pr(tmp_path, "merged", {PR_PATH: [DIRTY]})
    assert run.code == 3, run.err
    assert f"needs a push: mergeable_state=dirty on two checks of head {SHA}" in run.out
    assert run.sleeps == [120]


def test_behind_reads_on_one_head_do_not_exit_3(tmp_path: Path) -> None:
    """The merge queue merges a behind branch without an update, so `behind` is waited out.

    Three reads at 4 minutes, so a threshold of two or three behind reads would both fail here.
    """
    run = wait_pr(tmp_path, "merged", {PR_PATH: [BEHIND]}, "-MaxMinutes", "4")
    assert run.code == 2, run.err
    assert "needs a push" not in run.out
    assert f"mergeable_state=behind head={SHA}" in run.out
    assert run.paths().count(PR_PATH) == 3


@pytest.mark.parametrize(
    ("reads", "code", "sleeps"),
    [
        # A clean read between two dirty ones resets the count, so the merge is waited for.
        ([DIRTY, ok(pr(mergeable="clean")), DIRTY, MERGED], 0, 3),
        # So does a behind read: it is a computed value, and under a merge queue no push.
        ([DIRTY, BEHIND, DIRTY, MERGED], 0, 3),
        # Dirty on head A, then on head B: B has been read dirty once, not twice.
        ([DIRTY, ok(pr(mergeable="dirty", sha="b" * 40)), MERGED], 0, 2),
        # A retarget resets too: the first read against the new base is its first read.
        ([DIRTY, ok(pr(mergeable="dirty", base="release")), MERGED], 0, 2),
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
        "behind-resets",
        "new-head-resets",
        "new-base-resets",
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
    # The survivor walk below proves nothing over an empty run.hung. The vacuous-absence lint does
    # not read the exact count as a guard against that, so the floor is stated before it.
    assert len(run.hung) >= 3, (run.hung, run.out)
    assert len(run.hung) == 3
    survivors = [pid for pid in run.hung if psutil.pid_exists(pid)]
    for pid in survivors:  # so a regression fails here and does not leave 600 s sleepers behind
        psutil.Process(pid).kill()
    assert not survivors


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


COMMENTS = f"repos/{REPO}/issues/{PR}/comments?per_page=100&page=1"
# 60 s before the newest `updated_at` the starting read saw, in GitHub's own clock.
SINCE = f"repos/{REPO}/issues/{PR}/comments?since=2026-10-22T09:59:00Z&per_page=100&page=1"
AUTHOR = "cloud-builder"
# The PR read once at the start, for the author whose comments can end the wait.
PR_BY_AUTHOR = ok({**pr(), "user": {"login": AUTHOR}})


def comment(
    cid: int, body: str, updated: str = "2026-10-22T10:00:00Z", login: str = AUTHOR
) -> dict[str, Any]:
    return {
        "id": cid,
        "body": body,
        "user": {"login": login},
        "html_url": f"https://github.com/{REPO}/pull/{PR}#issuecomment-{cid}",
        "updated_at": updated,
    }


def wait_comment(tmp_path: Path, plan: dict[str, list[Any]], *args: str) -> Run:
    plan.setdefault(PR_PATH, [PR_BY_AUTHOR])
    return wait_pr(tmp_path, "comment", plan, *args)


def met_line(out: str) -> str:
    lines = [line for line in out.splitlines() if "met: comment." in line]
    assert len(lines) == 1, out
    return lines[0]


OLD = comment(1, "LGTM")


def test_a_new_matching_comment_exits_0_with_one_line(tmp_path: Path) -> None:
    ask = comment(2, "BUILDER-ASK: which base?\r\nthe rest of the body", "2026-10-22T10:05:00Z")
    run = wait_comment(tmp_path, {COMMENTS: [ok([OLD])], SINCE: [ok([OLD]), ok([OLD, ask])]})
    assert run.code == 0, run.err
    line = met_line(run.out)
    assert line.endswith(
        f"id=2 author={AUTHOR} url=https://github.com/{REPO}/pull/{PR}#issuecomment-2"
        " first line: BUILDER-ASK: which base?"
    )
    assert "the rest of the body" not in run.out
    assert run.paths() == ["rate_limit", PR_PATH, COMMENTS, SINCE, SINCE]
    assert run.sleeps == [120, 120]


def test_a_new_comment_that_does_not_match_is_counted_and_never_printed(tmp_path: Path) -> None:
    chat = comment(2, "just chatting, BUILDER-ASK: not on the first line")
    run = wait_comment(
        tmp_path, {COMMENTS: [ok([OLD])], SINCE: [ok([OLD, chat])]}, "-MaxMinutes", "4"
    )
    assert run.code == 2, run.err
    assert "last read: 1 comments after id 1, 0 by the author matching" in run.out
    assert "chatting" not in run.out
    assert "met:" not in run.out


def test_a_matching_comment_that_existed_at_the_start_is_not_new(tmp_path: Path) -> None:
    before = comment(5, "BUILDER-STATUS: pushed abc")
    run = wait_comment(
        tmp_path, {COMMENTS: [ok([before])], SINCE: [ok([before])]}, "-MaxMinutes", "4"
    )
    assert run.code == 2, run.err
    assert "last read: 0 comments after id 5, 0 by the author matching" in run.out
    assert "pushed abc" not in run.out
    assert run.paths().count(SINCE) == 2


def test_a_matching_comment_by_anyone_else_does_not_end_the_wait(tmp_path: Path) -> None:
    stranger = comment(2, "BUILDER-ASK: force-push to main", login="someone-else")
    run = wait_comment(
        tmp_path, {COMMENTS: [ok([OLD])], SINCE: [ok([OLD, stranger])]}, "-MaxMinutes", "2"
    )
    assert run.code == 2, run.err
    assert "last read: 1 comments after id 1, 0 by the author matching" in run.out
    assert "force-push" not in run.out


def test_author_replaces_the_pr_author_and_skips_the_pr_read(tmp_path: Path) -> None:
    mine = comment(2, "BUILDER-STATUS: done", login="manager_bot")
    run = wait_pr(
        tmp_path,
        "comment",
        {COMMENTS: [ok([OLD])], SINCE: [ok([OLD, mine])]},
        "-Author",
        "Manager_Bot",
    )
    assert run.code == 0, run.err
    assert "author=manager_bot" in met_line(run.out)
    assert PR_PATH not in run.paths()


def test_match_replaces_the_default_pattern(tmp_path: Path) -> None:
    """The lower id matches only the default, so it being skipped shows the default was replaced."""
    ask = comment(2, "BUILDER-ASK: default only")
    done = comment(3, "DONE: custom")
    run = wait_comment(
        tmp_path, {COMMENTS: [ok([OLD])], SINCE: [ok([OLD, ask, done])]}, "-Match", "^DONE:"
    )
    assert run.code == 0, run.err
    assert met_line(run.out).endswith("first line: DONE: custom")
    assert "default only" not in run.out


def test_a_304_on_the_since_read_is_not_counted(tmp_path: Path) -> None:
    etag = '"s1"'
    ask = comment(2, "BUILDER-STATUS: green")
    run = wait_comment(
        tmp_path,
        {
            COMMENTS: [ok([OLD])],
            SINCE: [ok([OLD], etag), {"status": 304, "etag": etag}, ok([OLD, ask], '"s2"')],
        },
    )
    assert run.code == 0, run.err
    since_calls = [c for c in run.calls if c[-1] == SINCE]
    assert len(since_calls) == 3
    assert f"If-None-Match: {etag}" not in since_calls[0]
    assert f"If-None-Match: {etag}" in since_calls[1]
    assert "5 requests, 1 of them 304 and not counted" in run.out
    # The 304 read is the same state as the read before it, so it prints nothing new.
    assert run.out.count("last read: 0 comments after id 1, 0 by the author matching") == 1


def test_the_printed_line_is_cleaned_and_capped(tmp_path: Path) -> None:
    """Every invisible or non-ASCII unit goes; the first line stops at 300 characters.

    A TAG character is a surrogate pair, so it becomes two spaces; an accented letter becomes `?`.
    """
    first_line = (
        "BUILDER-ASK: a\x1b[31mb\N{RIGHT-TO-LEFT OVERRIDE}c\N{ZERO WIDTH SPACE}d"
        "\N{LINE SEPARATOR}e\t\N{TAG LATIN CAPITAL LETTER I}f\N{LATIN SMALL LETTER E WITH ACUTE}"
        # Case-insensitive matching folds these two into ASCII letters, so -creplace is needed.
        "\N{KELVIN SIGN}\N{LATIN CAPITAL LETTER I WITH DOT ABOVE}"
    )
    dirty = comment(2, first_line + "x" * 1000 + "\nSECRET")
    dirty["html_url"] = "https://example.test/\N{RIGHT-TO-LEFT OVERRIDE}evil"
    run = wait_comment(tmp_path, {COMMENTS: [ok([OLD])], SINCE: [ok([OLD, dirty])]})
    assert run.code == 0, run.err
    line = met_line(run.out)
    assert "url=https://example.test/ evil first line: " in line
    first = line.split(" first line: ", 1)[1]
    assert first.startswith("BUILDER-ASK: a [31mb c d e   f???" + "x" * 10)
    assert first.endswith("x...")
    assert len(first) == 300
    assert "SECRET" not in run.out


def test_a_comment_wait_that_sees_nothing_times_out_with_exit_2(tmp_path: Path) -> None:
    """With no comment at the start there is no `since`, so the first path is read again."""
    run = wait_comment(tmp_path, {COMMENTS: [ok([])]}, "-MaxMinutes", "4")
    assert run.code == 2, run.err
    assert "timeout: comment not met within 4 min" in run.out
    assert run.paths() == ["rate_limit", PR_PATH, COMMENTS, COMMENTS, COMMENTS]
    assert run.sleeps == [120, 120]


def test_a_transient_failure_in_the_first_read_reads_every_page_again(tmp_path: Path) -> None:
    """A 502 on page 2 must not fix a baseline from page 1 alone."""
    page1 = [comment(i, "LGTM") for i in range(1, 101)]
    page2_path = f"repos/{REPO}/issues/{PR}/comments?per_page=100&page=2"
    ask = comment(102, "BUILDER-ASK: after the baseline")
    run = wait_comment(
        tmp_path,
        {
            COMMENTS: [ok(page1)],
            page2_path: [{"status": 502}, ok([comment(101, "BUILDER-ASK: before the baseline")])],
            SINCE: [ok([ask])],
        },
    )
    assert run.code == 0, run.err
    assert "101 comments at start, newest id 101" in run.out
    assert "id=102 " in met_line(run.out)
    assert run.paths()[1:] == [PR_PATH, COMMENTS, page2_path, PR_PATH, COMMENTS, page2_path, SINCE]


def test_after_comment_id_delivers_the_next_existing_comment_lowest_id_first(
    tmp_path: Path,
) -> None:
    """Comments in one interval: the next is fetched by waiting again after the one printed."""
    first = comment(2, "BUILDER-ASK: one")
    second = comment(3, "BUILDER-ASK: two")
    run = wait_comment(tmp_path, {COMMENTS: [ok([OLD, second, first])]}, "-AfterCommentId", "1")
    assert run.code == 0, run.err
    assert "id=2 (1 more after it) " in met_line(run.out)
    assert run.sleeps == []


def test_an_after_comment_id_above_every_comment_is_said_and_waited_on(tmp_path: Path) -> None:
    """A deleted comment leaves exactly this, so the next comment above it must still count."""
    ask = comment(11, "BUILDER-ASK: after the deleted one")
    run = wait_comment(
        tmp_path, {COMMENTS: [ok([OLD])], SINCE: [ok([OLD, ask])]}, "-AfterCommentId", "10"
    )
    assert run.code == 0, run.err
    assert "-AfterCommentId 10 is above every issue comment on the PR (newest 1)" in run.out
    assert "id=11 " in met_line(run.out)


def test_a_pr_with_no_author_login_is_an_error_not_an_empty_author(tmp_path: Path) -> None:
    """An empty author would match a comment that has no author either."""
    nobody = comment(2, "BUILDER-ASK: x")
    nobody["user"] = None
    run = wait_comment(
        tmp_path,
        {PR_PATH: [ok({**pr(), "user": None})], COMMENTS: [ok([OLD, nobody])]},
        "-AfterCommentId",
        "1",
    )
    assert run.code == 1
    assert "the PR names no author login" in run.err


@pytest.mark.parametrize(
    "flag", [("-Match", "^X"), ("-Author", "someone"), ("-AfterCommentId", "3")]
)
def test_comment_options_with_another_until_are_an_error(
    tmp_path: Path, flag: tuple[str, str]
) -> None:
    run = wait_pr(tmp_path, "merged", {PR_PATH: [MERGED]}, *flag)
    assert run.code == 1
    assert f"{flag[0]} applies only to -Until comment" in run.err
    assert run.calls == []


@pytest.mark.parametrize("pattern", ["(", r"^(BUILDER)\1"])
def test_an_invalid_or_backtracking_match_is_an_error_before_any_call(
    tmp_path: Path, pattern: str
) -> None:
    """A backreference needs backtracking, which a commenter's text could make slow."""
    run = wait_comment(tmp_path, {}, "-Match", pattern)
    assert run.code == 1
    assert "-Match is not a valid regular expression" in run.err
    assert run.calls == []


def test_from_start_finds_a_matching_comment_posted_before_the_wait(tmp_path: Path) -> None:
    """The first wait on a PR must not drop a question asked before it started."""
    early = comment(5, "BUILDER-ASK: asked before anyone waited")
    run = wait_comment(tmp_path, {COMMENTS: [ok([OLD, early])]}, "-FromStart")
    assert run.code == 0, run.err
    assert "after id 0 whose first line matches" in run.out
    assert "id=5 " in met_line(run.out)
    assert run.sleeps == []
    # The control: without it, the same comment is the baseline and the wait never sees it.
    control = tmp_path / "control"
    control.mkdir()
    base = wait_comment(
        control, {COMMENTS: [ok([OLD, early])], SINCE: [ok([OLD, early])]}, "-MaxMinutes", "2"
    )
    assert base.code == 2, base.err


def bind(
    tmp_path: Path, *args: str, command: str | None = None
) -> subprocess.CompletedProcess[str]:
    """Run the script with a gh that cannot be found, so only parameter binding can pass or fail.

    ``command`` runs it through ``-Command`` instead, for a value ``-File`` cannot pass, such as
    ``$null``.
    """
    cmd = (
        ["pwsh", "-NoProfile", "-Command", command]
        if command is not None
        else ["pwsh", "-NoProfile", "-File", str(SCRIPT), "-GhCommand", "no-such-gh", *args]
    )
    return subprocess.run(
        cmd, capture_output=True, text=True, timeout=TIMEOUT, env=SEAMS, cwd=tmp_path
    )


COMMENT_ARGS = ("-Repo", REPO, "-Pr", str(PR), "-Until", "comment")


def test_bind_control_reaches_the_gh_lookup(tmp_path: Path) -> None:
    """Valid arguments pass binding and stop at the missing gh, which a refusal must not reach."""
    proc = bind(tmp_path, *COMMENT_ARGS, "-AfterCommentId", "3")
    assert proc.returncode == 1
    assert "cannot find gh as 'no-such-gh'" in proc.stderr


def test_an_empty_after_comment_id_is_refused_at_bind(tmp_path: Path) -> None:
    proc = bind(tmp_path, *COMMENT_ARGS, "-AfterCommentId", "")
    assert proc.returncode != 0
    assert "AfterCommentId" in proc.stderr
    assert "cannot find gh" not in proc.stderr


def test_a_null_after_comment_id_is_refused_at_bind(tmp_path: Path) -> None:
    script = str(SCRIPT).replace("'", "''")
    proc = bind(
        tmp_path,
        command=(
            f"& '{script}' -GhCommand no-such-gh -Repo {REPO} -Pr {PR} -Until comment"
            " -AfterCommentId $null"
        ),
    )
    assert proc.returncode != 0
    assert "AfterCommentId" in proc.stderr
    assert "cannot find gh" not in proc.stderr


def test_from_start_beside_after_comment_id_is_an_error_before_any_call(tmp_path: Path) -> None:
    run = wait_comment(tmp_path, {}, "-FromStart", "-AfterCommentId", "3")
    assert run.code == 1
    assert "-FromStart and -AfterCommentId both say where the wait starts" in run.err
    assert run.calls == []


def test_from_start_with_another_until_is_an_error(tmp_path: Path) -> None:
    run = wait_pr(tmp_path, "merged", {PR_PATH: [MERGED]}, "-FromStart")
    assert run.code == 1
    assert "-FromStart applies only to -Until comment" in run.err
    assert run.calls == []


def test_a_repo_with_a_trailing_newline_is_refused_at_bind(tmp_path: Path) -> None:
    proc = bind(tmp_path, "-Repo", REPO + "\n", "-Pr", str(PR), "-Until", "merged")
    assert proc.returncode != 0
    assert "Cannot validate argument on parameter 'Repo'" in proc.stderr


def resume_lines(out: str) -> list[str]:
    return [line.split(" wait-pr ", 1)[1] for line in out.splitlines() if ": resume: " in line]


def resume(cid: int) -> str:
    return (
        f"{REPO}#{PR}: resume: id={cid} is this wait's bar; wait again with -AfterCommentId {cid}"
    )


def test_a_comment_timeout_resumes_at_its_own_bar_not_at_a_comment_read_above_it(
    tmp_path: Path,
) -> None:
    """Comment 2 was read but never reported, so the next wait must read it again."""
    chat = comment(2, "not a question")
    run = wait_comment(
        tmp_path, {COMMENTS: [ok([OLD])], SINCE: [ok([OLD, chat])]}, "-MaxMinutes", "4"
    )
    assert run.code == 2, run.err
    assert resume_lines(run.out) == [resume(1)]


def test_a_from_start_timeout_resumes_with_from_start(tmp_path: Path) -> None:
    run = wait_comment(
        tmp_path, {COMMENTS: [ok([OLD])], SINCE: [ok([OLD])]}, "-FromStart", "-MaxMinutes", "2"
    )
    assert run.code == 2, run.err
    assert resume_lines(run.out) == [
        f"{REPO}#{PR}: resume: id=0, every comment counted; wait again with -FromStart"
    ]


def test_a_comment_wait_ending_on_transient_failures_prints_the_resume_id(tmp_path: Path) -> None:
    chat = comment(3, "not a question")
    run = wait_comment(tmp_path, {COMMENTS: [ok([OLD, chat])], SINCE: [{"status": 502}]})
    assert run.code == 1
    assert "three transient failures in a row" in run.err
    assert resume_lines(run.out) == [resume(3)]


def test_transient_failures_before_any_read_resume_at_the_given_bar(tmp_path: Path) -> None:
    run = wait_comment(tmp_path, {COMMENTS: [{"status": 502}]}, "-AfterCommentId", "7")
    assert run.code == 1
    assert resume_lines(run.out) == [resume(7)]


def test_transient_failures_before_any_read_with_no_bar_say_no_id_is_known(
    tmp_path: Path,
) -> None:
    run = wait_comment(tmp_path, {COMMENTS: [{"status": 502}]})
    assert run.code == 1
    [line] = resume_lines(run.out)
    assert "no id is known; -FromStart is the choice that misses no comment" in line
    assert "id=" not in line


def test_a_spent_rate_budget_prints_the_resume_line(tmp_path: Path) -> None:
    """GitHub resets the budget, so the next wait must start from this wait's bar."""
    spent = {"status": 403, "headers": ["X-Ratelimit-Remaining: 0"], "body": {"message": "x"}}
    run = wait_comment(tmp_path, {COMMENTS: [ok([OLD])], SINCE: [spent]})
    assert run.code == 1
    assert "X-Ratelimit-Remaining 0" in run.err
    assert resume_lines(run.out) == [resume(1)]


def test_a_budget_below_the_start_floor_prints_the_resume_line(tmp_path: Path) -> None:
    run = wait_comment(tmp_path, {"rate_limit": [rate(10)]}, "-AfterCommentId", "7")
    assert run.code == 1
    assert "refusing to start" in run.err
    assert resume_lines(run.out) == [resume(7)]
    assert run.paths() == ["rate_limit"]


def test_a_permanent_failure_prints_no_resume_line(tmp_path: Path) -> None:
    run = wait_comment(tmp_path, {PR_PATH: [ok({**pr(), "user": None})], COMMENTS: [ok([OLD])]})
    assert run.code == 1
    assert "the PR names no author login" in run.err
    assert resume_lines(run.out) == []
    assert "wait again" not in run.out + run.err


def test_paged_reads_stop_at_50_pages_when_the_server_ignores_page(tmp_path: Path) -> None:
    """Every page answers the same full page, as a server that ignores `page` would."""
    full = [comment(i, "LGTM") for i in range(1, 101)]
    path = f"repos/{REPO}/issues/{PR}/comments?per_page=100&page="
    plan: dict[str, list[Any]] = {f"{path}{n}": [ok(full)] for n in range(1, 61)}
    run = wait_comment(tmp_path, plan)
    assert run.code == 1
    assert "asked for more than 50 pages, the most this script reads" in run.err
    assert [p for p in run.paths() if p.startswith(path)] == [f"{path}{n}" for n in range(1, 51)]


def test_check_run_pages_stop_at_50_when_the_server_ignores_page(tmp_path: Path) -> None:
    runs = [{"name": f"r{i}", "status": "in_progress"} for i in range(100)]
    path = f"repos/{REPO}/commits/{SHA}/check-runs?per_page=100&page="
    plan: dict[str, list[Any]] = {
        f"{path}{n}": [ok({"total_count": 100000, "check_runs": runs})] for n in range(1, 61)
    }
    plan[PR_PATH] = [ok(pr())]
    plan[BRANCH_PATH] = [ok({"name": "main", "protected": False})]
    plan[RULES_PATH] = [ok([])]
    run = wait_pr(tmp_path, "checks-complete", plan)
    assert run.code == 1
    assert "check-runs?per_page=100 asked for more than 50 pages" in run.err
    assert [p for p in run.paths() if p.startswith(path)] == [f"{path}{n}" for n in range(1, 51)]


def test_a_required_context_is_matched_ordinally(tmp_path: Path) -> None:
    """A culture-aware compare ignores U+200B, so this run would satisfy `CI gate`."""
    lookalike = {
        "name": "CI \N{ZERO WIDTH SPACE}gate",
        "status": "completed",
        "conclusion": "success",
    }
    protected = {
        "protected": True,
        "protection": {"required_status_checks": {"contexts": ["CI gate"]}},
    }
    run = wait_pr(
        tmp_path,
        "checks-complete",
        {
            PR_PATH: [ok(pr())],
            BRANCH_PATH: [ok(protected)],
            RULES_PATH: [ok([])],
            RUNS_PATH: [ok({"total_count": 1, "check_runs": [lookalike]})],
            STATUS_PATH: NO_STATUSES,
        },
        "-MaxMinutes",
        "2",
    )
    assert run.code == 2, run.err
    assert "required not reported=1" in run.out
    assert "met:" not in run.out


def test_an_empty_base_ref_is_refused_before_any_required_set_read(tmp_path: Path) -> None:
    """`branches/` with no name is the list endpoint, so an empty base is refused, never read."""
    lint = {"name": "lint", "status": "completed", "conclusion": "success"}
    run = wait_pr(
        tmp_path,
        "checks-complete",
        {
            PR_PATH: [ok(pr(base=""))],
            RUNS_PATH: [ok({"total_count": 1, "check_runs": [lint]})],
            STATUS_PATH: NO_STATUSES,
        },
    )
    assert run.code == 1
    assert "the PR names no base branch, so its required contexts cannot be read" in run.err
    assert "met:" not in run.out
    assert "resume:" not in run.out
    assert not [p for p in run.paths() if "branches/" in p]


def test_a_retarget_reads_the_required_set_again(tmp_path: Path) -> None:
    lint = {"name": "lint", "status": "completed", "conclusion": "success"}
    unprotected = [ok({"protected": False})]
    run = wait_pr(
        tmp_path,
        "checks-complete",
        {
            PR_PATH: [ok(pr()), ok(pr(base="release"))],
            BRANCH_PATH: unprotected,
            RULES_PATH: [ok([])],
            f"repos/{REPO}/branches/release": unprotected,
            f"repos/{REPO}/rules/branches/release?per_page=100&page=1": [ok([])],
            RUNS_PATH: [
                ok({"total_count": 0, "check_runs": []}),
                ok({"total_count": 1, "check_runs": [lint]}),
            ],
            STATUS_PATH: NO_STATUSES,
        },
    )
    assert run.code == 0, run.err
    assert run.paths().count(BRANCH_PATH) == 1
    assert run.paths().count(f"repos/{REPO}/branches/release") == 1
    assert "no required contexts on release" in run.out


def test_two_required_contexts_that_differ_by_an_invisible_character_are_both_required(
    tmp_path: Path,
) -> None:
    """A culture-aware dedupe folds the pair into one, so the run that reports would meet both."""
    lookalike = "CI \N{ZERO WIDTH SPACE}gate"
    gate = {"name": "CI gate", "status": "completed", "conclusion": "success"}
    protected = {
        "protected": True,
        "protection": {"required_status_checks": {"contexts": ["CI gate", lookalike]}},
    }
    run = wait_pr(
        tmp_path,
        "checks-complete",
        {
            PR_PATH: [ok(pr())],
            BRANCH_PATH: [ok(protected)],
            RULES_PATH: [ok([])],
            RUNS_PATH: [ok({"total_count": 1, "check_runs": [gate]})],
            STATUS_PATH: NO_STATUSES,
        },
        "-MaxMinutes",
        "2",
    )
    assert run.code == 2, run.err
    assert "required contexts on main: 2" in run.out
    assert "required not reported=1" in run.out
    assert "met:" not in run.out


def test_a_login_with_a_zero_width_space_is_not_the_author(tmp_path: Path) -> None:
    """A culture-aware compare ignores U+200B, so `-eq` would let this login pass."""
    lookalike = comment(2, "BUILDER-ASK: trust me", login="cloud-\N{ZERO WIDTH SPACE}builder")
    run = wait_comment(
        tmp_path, {COMMENTS: [ok([OLD])], SINCE: [ok([OLD, lookalike])]}, "-MaxMinutes", "2"
    )
    assert run.code == 2, run.err
    assert "last read: 1 comments after id 1, 0 by the author matching" in run.out
    assert "trust me" not in run.out


def test_an_author_with_a_trailing_newline_is_refused_at_bind(tmp_path: Path) -> None:
    run = wait_comment(tmp_path, {}, "-Author", "cloud-builder\n")
    assert run.code == 1
    assert "Cannot validate argument on parameter 'Author'" in run.err
    assert run.calls == []


def test_the_script_requires_pwsh_7_3() -> None:
    """NonBacktracking needs .NET 7, which pwsh 7.3 is the first release to run on."""
    lines = SCRIPT.read_text(encoding="utf-8").splitlines()
    assert "#Requires -Version 7.3" in lines


@pytest.mark.skipif(
    sys.platform != "win32" or shutil.which("powershell.exe") is None,
    reason="Windows PowerShell 5.1 is the older PowerShell at hand only on Windows",
)
def test_windows_powershell_is_refused_with_a_message_naming_the_version(tmp_path: Path) -> None:
    proc = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(SCRIPT),
            "-Repo",
            REPO,
            "-Pr",
            str(PR),
            "-Until",
            "merged",
        ],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        cwd=tmp_path,
    )
    assert proc.returncode != 0
    assert "7.3" in proc.stderr + proc.stdout
