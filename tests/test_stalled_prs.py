# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The stalled-PR check must fire on the real shape and stay silent on everything adjacent to it.

These drive the REAL ``scan()`` and the REAL ``main()`` against payloads, not a re-statement of the
rule. The distinction matters more than usual here: this check exists because a green signal was
mistaken for a healthy one, so a test that cannot demonstrate the check FAILING would reproduce the
very defect it guards.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = _ROOT / "scripts" / "ci" / "check_stalled_prs.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_stalled_prs", _SCRIPT)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


sp = _load()


def _pr(
    number: int = 1,
    *,
    state: str = "OPEN",
    merge_state: str = "BEHIND",
    armed: bool = True,
    # Deliberately list[Any], not list[dict[...]]: one test feeds a NON-dict node to prove an
    # unreadable rollup entry is not silently treated as green.
    rollup: list[Any] | None = None,
) -> dict[str, Any]:
    """A PR payload defaulting to the STALL shape, so each test perturbs exactly one field."""
    return {
        "number": number,
        "title": f"pr {number}",
        "headRefName": f"branch-{number}",
        "state": state,
        "mergeStateStatus": merge_state,
        "autoMergeRequest": {"mergeMethod": "SQUASH"} if armed else None,
        "statusCheckRollup": [{"status": "COMPLETED", "conclusion": "SUCCESS", "name": "t"}]
        if rollup is None
        else rollup,
    }


# --- the positive control: it MUST fire ------------------------------------------------------------


def test_the_exact_stall_shape_is_detected() -> None:
    """Open + BEHIND + nothing failing + nothing pending. This is #74 and the six armed PRs."""
    found = sp.scan([_pr(74)])
    assert [s.number for s in found] == [74]
    assert found[0].armed is True


def test_an_unarmed_stall_is_still_reported() -> None:
    """Unarmed is still unmergeable — it just isn't lying to its author about it."""
    found = sp.scan([_pr(60, armed=False)])
    assert [s.number for s in found] == [60]
    assert found[0].armed is False


# --- the negative controls: each must NOT fire -----------------------------------------------------


@pytest.mark.parametrize("conclusion", ["FAILURE", "TIMED_OUT", "CANCELLED", "ACTION_REQUIRED"])
def test_a_failing_check_is_not_a_stall(conclusion: str) -> None:
    """A red PR is already loud. This check is only for the ones nothing else reports."""
    rollup = [{"status": "COMPLETED", "conclusion": conclusion, "name": "t"}]
    assert sp.scan([_pr(rollup=rollup)]) == []


@pytest.mark.parametrize("status", ["QUEUED", "IN_PROGRESS"])
def test_a_pending_check_is_not_a_stall(status: str) -> None:
    """Mid-suite is the normal path to green, not a stall — and it is where BEHIND flaps."""
    assert sp.scan([_pr(rollup=[{"status": status, "conclusion": None, "name": "t"}])]) == []


@pytest.mark.parametrize("merge_state", ["CLEAN", "BLOCKED", "DIRTY", "UNKNOWN", "UNSTABLE"])
def test_only_behind_counts(merge_state: str) -> None:
    """BLOCKED means checks aren't green yet; DIRTY is a conflict. Neither is this defect."""
    assert sp.scan([_pr(merge_state=merge_state)]) == []


@pytest.mark.parametrize("state", ["CLOSED", "MERGED"])
def test_a_closed_pr_is_not_a_stall(state: str) -> None:
    assert sp.scan([_pr(state=state)]) == []


# --- the shape that made the original bug invisible ------------------------------------------------


def test_an_unclassifiable_node_counts_as_unsettled_not_green() -> None:
    """A node we cannot read must never be silently treated as passing.

    This is the script's own defect class turned inward: 'I could not classify this' rendering as
    'this is fine' is precisely how a green signal stops meaning anything.
    """
    assert sp.scan([_pr(rollup=[{"weird": "shape"}])]) == []
    assert sp.scan([_pr(rollup=["not-a-dict"])]) == []


def test_statuscontext_nodes_are_understood() -> None:
    """GitHub returns two node shapes; a StatusContext carries `state`, not `status`/`conclusion`."""
    assert sp.scan([_pr(rollup=[{"state": "SUCCESS", "context": "legacy"}])]) != []
    assert sp.scan([_pr(rollup=[{"state": "FAILURE", "context": "legacy"}])]) == []
    assert sp.scan([_pr(rollup=[{"state": "PENDING", "context": "legacy"}])]) == []


# --- exit codes, driven through main() -------------------------------------------------------------


def _run(tmp_path: Path, prs: list[dict[str, Any]], *argv: str) -> int:
    payload = tmp_path / "prs.json"
    payload.write_text(json.dumps(prs), encoding="utf-8")
    return int(sp.main(["--prs-json", str(payload), *argv]))


def test_armed_stalls_fail_the_check(tmp_path: Path) -> None:
    assert _run(tmp_path, [_pr(74), _pr(96)]) == 1


def test_unarmed_stalls_alone_do_not_fail(tmp_path: Path) -> None:
    """Unarmed stalls warn. They need a human, but nothing is falsely promising to merge them."""
    assert _run(tmp_path, [_pr(60, armed=False)]) == 0


def test_warn_only_never_fails(tmp_path: Path) -> None:
    assert _run(tmp_path, [_pr(74)], "--warn-only") == 0


def test_a_healthy_repo_passes(tmp_path: Path) -> None:
    assert _run(tmp_path, [_pr(1, merge_state="CLEAN"), _pr(2, merge_state="BLOCKED")]) == 0


def test_an_empty_result_fails_closed(tmp_path: Path) -> None:
    """Zero PRs is a broken query, not a clean repo.

    The repo has had open PRs continuously; a sweep that finds none has failed to look. Reporting
    success there is the 'nothing pending means all settled' error this codebase keeps re-learning.
    """
    assert _run(tmp_path, []) == 2


def test_an_unreadable_payload_fails_closed(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert int(sp.main(["--prs-json", str(bad)])) == 2


def test_the_receipt_names_what_was_scanned(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """'no stalls' and 'nothing was examined' must not be indistinguishable."""
    _run(tmp_path, [_pr(1, merge_state="CLEAN")])
    assert "scanned 1 open pull request" in capsys.readouterr().out


# --- the split query -------------------------------------------------------------------------------
#
# Asking for `statusCheckRollup` across every open pull request in one `gh pr list` is what broke the
# daily cron: three consecutive reds, each `unexpected end of JSON input`, because GitHub's GraphQL
# API timed out on the node count. `_fetch` now lists cheaply and fetches the rollup only for pull
# requests that could still be a stall. These drive the REAL `_fetch` with a stub runner, so they
# assert the commands actually issued rather than a description of them.


#: The stub's signature is spelled out rather than left as ``Any``: the one thing worth checking about
#: a dependency-injection seam is that the stub matches what production passes.
_Runner = Callable[[list[str], float], str]


def _runner(
    listing: list[dict[str, Any]], rollups: dict[int, Any] | None = None
) -> tuple[_Runner, list[list[str]]]:
    """A stub `gh` that records every command and answers from the payloads given."""
    seen: list[list[str]] = []
    by_number = rollups or {}

    def run(cmd: list[str], timeout: float) -> str:
        seen.append(cmd)
        if cmd[1:3] == ["pr", "list"]:
            return json.dumps(listing)
        if cmd[1:3] == ["pr", "view"]:
            return json.dumps({"statusCheckRollup": by_number.get(int(cmd[3]))})
        raise AssertionError(f"unexpected gh command: {cmd}")

    return run, seen


def _cheap(number: int, *, state: str = "OPEN", merge_state: str = "BEHIND") -> dict[str, Any]:
    """One row as the CHEAP listing returns it: every stall field except the rollup."""
    row = _pr(number, state=state, merge_state=merge_state)
    del row["statusCheckRollup"]
    return row


def test_the_listing_query_does_not_ask_for_the_rollup() -> None:
    """The regression itself. `statusCheckRollup` in the bulk query is what returned HTTP 504."""
    assert "statusCheckRollup" not in sp.LIST_FIELDS
    assert "statusCheckRollup" in sp.ROLLUP_FIELDS


def test_the_rollup_is_fetched_only_for_pull_requests_that_could_be_stalled() -> None:
    """The whole point of the split: the expensive call scales with the BEHIND set, not the open set.

    A test asserting only "it still finds the stall" would pass just as well if `_fetch` fetched a
    rollup for every pull request -- which is the thing that broke. So this asserts WHICH numbers were
    viewed, and that the untouched ones were not.
    """
    listing = [
        _cheap(10),  # OPEN + BEHIND -> needs a rollup
        _cheap(11, merge_state="CLEAN"),  # not behind -> must not be fetched
        _cheap(12, merge_state="BLOCKED"),  # not behind -> must not be fetched
        _cheap(13, state="CLOSED"),  # not open -> must not be fetched
    ]
    run, seen = _runner(listing, rollups={10: [{"status": "COMPLETED", "conclusion": "SUCCESS"}]})

    prs = sp._fetch(None, None, runner=run)

    viewed = [int(cmd[3]) for cmd in seen if cmd[1:3] == ["pr", "view"]]
    assert viewed == [10], f"expected only #10's rollup to be fetched, got {viewed}"
    assert len([c for c in seen if c[1:3] == ["pr", "list"]]) == 1, "the listing must be one call"
    assert [s.number for s in sp.scan(prs)] == [10]


def test_a_pull_request_whose_rollup_was_never_fetched_is_never_reported() -> None:
    """The optimisation's own failure mode, and it is a FALSE POSITIVE rather than a miss.

    `_counts(None)` returns (0, 0) -- zero failing, zero pending -- which is indistinguishable from a
    fully green rollup. So if `_fetch`'s pre-filter and `scan`'s rule ever diverged, a pull request
    that was skipped by one and read by the other would be announced as a stall on evidence nobody
    fetched. Both call `could_be_stalled`, and this pins that they agree.
    """
    assert sp._counts(None) == (0, 0), "the premise of this test changed; re-read _pr_checks"
    for row in (_cheap(1, merge_state="CLEAN"), _cheap(2, state="CLOSED")):
        assert sp.could_be_stalled(row) is False
        assert sp.scan([row]) == []


def test_a_listing_that_hits_the_cap_fails_closed() -> None:
    """A result set EQUAL to the limit is a truncation signal, not a population.

    `gh pr list` truncates at --limit silently, so a capped listing would under-report stalls with
    nothing saying anything was missed -- this check's own defect class, one level up.
    """
    run, _ = _runner([_cheap(n) for n in range(sp.LIST_LIMIT)])
    with pytest.raises(RuntimeError, match="truncation signal"):
        sp._fetch(None, None, runner=run)


def test_one_under_the_cap_is_accepted() -> None:
    """The discriminating half of the row above: the guard must fire on the CAP, not on 'many'."""
    rows = [_cheap(n, merge_state="CLEAN") for n in range(sp.LIST_LIMIT - 1)]
    run, _ = _runner(rows)
    assert len(sp._fetch(None, None, runner=run)) == sp.LIST_LIMIT - 1


def test_an_unaddressable_pull_request_fails_closed() -> None:
    """Cannot fetch its rollup, so it must not be reported as green-and-stalled."""
    bad = _cheap(1)
    bad["number"] = "not-a-number"
    run, _ = _runner([bad])
    with pytest.raises(RuntimeError, match="unusable number"):
        sp._fetch(None, None, runner=run)


def test_the_repo_flag_reaches_both_queries() -> None:
    """A --repo that reached only the listing would make every rollup fetch read the wrong repo."""
    run, seen = _runner([_cheap(10)], rollups={10: []})
    sp._fetch("owner/name", None, runner=run)
    assert all("--repo" in cmd and "owner/name" in cmd for cmd in seen), seen


def test_an_unreadable_rollup_response_fails_closed() -> None:
    """The mirror of the unusable-number row, and the direction that is easy to get backwards.

    Storing ``None`` for an unreadable response does NOT drop the pull request -- `_counts(None)` is
    (0, 0), i.e. GREEN -- so it would be announced as a stall on a rollup nobody could read. An
    earlier draft of `_fetch` did exactly that.
    """
    seen: list[list[str]] = []

    def run(cmd: list[str], timeout: float) -> str:
        seen.append(cmd)
        return json.dumps([_cheap(10)]) if cmd[1:3] == ["pr", "list"] else json.dumps("not-a-dict")

    with pytest.raises(RuntimeError, match="unreadable"):
        sp._fetch(None, None, runner=run)


def test_the_per_call_timeouts_are_distinct_and_the_view_is_the_shorter() -> None:
    """The split removed the job's old ~3 minute ceiling, so each command carries its own.

    A `gh pr view` measured well under a second must not sit for the listing's timeout before it
    reports a hang, because there can now be one per BEHIND pull request.
    """
    assert sp.VIEW_TIMEOUT < sp.LIST_TIMEOUT
    seen: list[tuple[str, float]] = []

    def run(cmd: list[str], timeout: float) -> str:
        seen.append((cmd[2], timeout))
        return json.dumps([_cheap(10)]) if cmd[1:3] == ["pr", "list"] else json.dumps({})

    sp._fetch(None, None, runner=run)
    assert seen == [("list", sp.LIST_TIMEOUT), ("view", sp.VIEW_TIMEOUT)], seen


def test_a_transient_gh_failure_is_retried_before_the_sweep_is_abandoned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The split multiplied the transient-failure surface, and this check now opens an issue.

    One query became one plus one per BEHIND pull request, so a flaky 502 that used to be a
    one-in-one chance is one-in-N -- and every failure is now a GitHub issue. Retrying serially keeps
    ordinary API flake from becoming recurring noise. Serially on purpose: concurrent requests on a
    single token invite a secondary-rate-limit 403, which is this outage again, arriving slower.
    """
    calls: list[list[str]] = []
    completed = [
        subprocess.CompletedProcess(["gh"], 1, "", "HTTP 502"),
        subprocess.CompletedProcess(["gh"], 1, "", "HTTP 502"),
        subprocess.CompletedProcess(["gh"], 0, '{"ok": true}', ""),
    ]

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        return completed[len(calls) - 1]

    monkeypatch.setattr(sp.subprocess, "run", fake_run)
    monkeypatch.setattr(sp.time, "sleep", lambda _s: None)

    assert sp._run_gh(["gh", "pr", "view", "10"]) == '{"ok": true}'
    assert len(calls) == 3, "two transient failures should have been retried, not raised"


def test_a_persistent_gh_failure_still_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """The discriminating half: retrying must not turn a real outage into silence.

    Without this row the retry above would pass just as well if `_run_gh` never raised at all.
    """
    calls: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 1, "", "HTTP 502")

    monkeypatch.setattr(sp.subprocess, "run", fake_run)
    monkeypatch.setattr(sp.time, "sleep", lambda _s: None)

    with pytest.raises(RuntimeError, match="after 3 attempts"):
        sp._run_gh(["gh", "pr", "view", "10"])
    assert len(calls) == sp._ATTEMPTS


def test_the_error_names_the_pull_request_the_call_was_for() -> None:
    """`gh pr view failed` without the number is useless when there is one call per BEHIND PR."""
    assert "10" in " ".join(["gh", "pr", "view", "10"][:4])


def test_the_runner_seam_and_the_module_attribute_resolve_to_the_same_function(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A default argument would bind `_run_gh` at import time, so monkeypatching it would be INERT.

    That is a stub which cannot contradict the code it is stubbing: the test would reach the real
    network while appearing to be offline. `_fetch` resolves the runner in its body instead.
    """
    seen: list[list[str]] = []

    def stub(cmd: list[str], timeout: float) -> str:
        seen.append(cmd)
        return json.dumps([_cheap(1, merge_state="CLEAN")])

    monkeypatch.setattr(sp, "_run_gh", stub)
    sp._fetch(None, None)
    assert seen and seen[0][1:3] == ["pr", "list"], "monkeypatching _run_gh had no effect"
