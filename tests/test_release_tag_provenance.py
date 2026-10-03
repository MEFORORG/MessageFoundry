# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``scripts/release/tag_provenance.py``: which tagged commits may release.

vault BACKLOG #2631, limb 2. The script asks the server two questions, and these tests grade the
answer it gives from what the server says. The server itself is not called here; the decision is a
pure function of the readings, and that is what is tested. tests/test_release_pipeline.py section
(12) holds where the workflow runs it.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from scripts.ci.required_contexts import branch_protection_contexts, ruleset_contexts
from scripts.release import tag_provenance as tp
from scripts.release.tag_provenance import Report, reports_from, verdict

_REQUIRED = ("CI gate", "cla")


def _check(id_: int, name: str, conclusion: str, state: str = "completed") -> Report:
    return Report(id=id_, context=name, kind="check", state=state, conclusion=conclusion)


def _status(id_: int, name: str, state: str) -> Report:
    return Report(id=id_, context=name, kind="status", state=state)


_GREEN = [_check(1, "CI gate", "success"), _status(2, "cla", "success")]


@pytest.mark.parametrize("compare", ["behind", "identical"])
def test_a_commit_on_main_with_every_check_green_passes(compare: str) -> None:
    """POSITIVE CONTROL: each refusal below is evidence only while this passes."""
    assert verdict(compare, _REQUIRED, _GREEN) == []


@pytest.mark.parametrize("conclusion", ["neutral", "skipped"])
def test_the_conclusions_branch_protection_accepts_pass(conclusion: str) -> None:
    reports = [_check(1, "CI gate", conclusion), _status(2, "cla", "success")]
    assert verdict("behind", _REQUIRED, reports) == []


@pytest.mark.parametrize("compare", ["ahead", "diverged", ""])
def test_a_commit_not_on_main_is_refused(compare: str) -> None:
    problems = verdict(compare, _REQUIRED, _GREEN)
    assert len(problems) == 1 and "not on main" in problems[0], problems


@pytest.mark.parametrize(
    ("reports", "needle"),
    [
        ([_check(1, "CI gate", "failure"), _status(2, "cla", "success")], "did not pass"),
        ([_check(1, "CI gate", "cancelled"), _status(2, "cla", "success")], "did not pass"),
        ([_check(1, "CI gate", "", "in_progress"), _status(2, "cla", "success")], "did not pass"),
        ([_check(1, "CI gate", "success"), _status(2, "cla", "pending")], "did not pass"),
        ([_check(1, "CI gate", "success")], "never reported"),
        # The LATEST report decides: a later red overrides an earlier green.
        (
            [_check(1, "CI gate", "success"), _check(5, "CI gate", "failure")]
            + [_status(2, "cla", "success")],
            "did not pass",
        ),
    ],
    ids=["failure", "cancelled", "unfinished", "status-pending", "missing", "later-red"],
)
def test_a_required_context_that_did_not_pass_is_refused(
    reports: list[Report], needle: str
) -> None:
    problems = verdict("behind", _REQUIRED, reports)
    assert len(problems) == 1 and needle in problems[0], problems


def test_a_later_green_overrides_an_earlier_red() -> None:
    """A re-run that passed is the latest report, so it is what counts."""
    reports = [_check(1, "CI gate", "failure"), _check(9, "CI gate", "success")]
    assert verdict("behind", ["CI gate"], reports) == []


def test_an_empty_required_set_is_refused() -> None:
    """A set with nothing in it would pass every commit, so it proves nothing."""
    problems = verdict("behind", [], _GREEN)
    assert len(problems) == 1 and "no required context" in problems[0], problems


def test_a_check_run_and_a_status_of_one_name_are_each_judged_on_their_own_latest() -> None:
    """The two kinds number their ids separately, so a high status id must not hide a red run."""
    reports = [_check(1, "CI gate", "failure"), _status(10_000, "CI gate", "success")]
    problems = verdict("behind", ["CI gate"], reports)
    assert len(problems) == 1 and "check run completed/failure" in problems[0], problems
    assert verdict("behind", ["CI gate"], [_check(2, "CI gate", "success"), *reports]) == []


def test_reports_are_read_from_the_slurped_pages() -> None:
    checks: list[dict[str, Any]] = [
        {"check_runs": [{"id": 3, "name": "CI gate", "status": "completed", "conclusion": None}]},
        {"check_runs": []},
    ]
    statuses = [[{"id": 4, "context": "cla", "state": "success"}]]
    assert reports_from(checks, statuses) == [
        Report(id=3, context="CI gate", kind="check", state="completed", conclusion=""),
        Report(id=4, context="cla", kind="status", state="success"),
    ]


def test_an_absent_branch_protection_list_raises_rather_than_reading_as_empty() -> None:
    assert branch_protection_contexts(
        {"protection": {"required_status_checks": {"contexts": ["a"]}}}
    ) == ["a"]
    with pytest.raises(RuntimeError, match="not an empty required set"):
        branch_protection_contexts({"protection": {}})


def test_ruleset_contexts_are_read_from_every_required_checks_rule() -> None:
    rules = [
        {"type": "pull_request", "parameters": {}},
        {
            "type": "required_status_checks",
            "parameters": {"required_status_checks": [{"context": "x"}, {"context": "y"}]},
        },
    ]
    assert ruleset_contexts(rules) == ["x", "y"]
    assert ruleset_contexts([]) == []


def test_main_refuses_when_the_server_cannot_be_read(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """An API failure must refuse, never pass."""

    def broken(*_args: object) -> tuple[str, list[str], list[Report]]:
        raise RuntimeError("gh api exited 1: simulated")

    monkeypatch.setattr(tp, "read_server", broken)
    assert tp.main(["--repo", "o/r", "--sha", "abc"]) == 1
    assert "refused" in capsys.readouterr().out


def test_main_unions_the_server_set_with_the_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A context only the file names is still required, and so is one only the server names."""
    contexts = tmp_path / "required-contexts.txt"
    contexts.write_text("# comment\nfrom-file\n", encoding="utf-8")
    reports = [_check(1, "from-server", "success")]
    monkeypatch.setattr(tp, "read_server", lambda *_a: ("behind", ["from-server"], reports))
    args = ["--repo", "o/r", "--sha", "abc", "--contexts-file", str(contexts)]
    assert tp.main(args) == 1
    assert "'from-file' never reported" in capsys.readouterr().out

    reports.append(_check(2, "from-file", "success"))
    assert tp.main(args) == 0


def test_a_server_only_context_that_never_reported_still_refuses(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Nothing tells a context added after the merge apart from one a bypass skipped, so the gate
    holds the commit to every server context, and a red one refuses too."""
    contexts = tmp_path / "required-contexts.txt"
    contexts.write_text("listed\n", encoding="utf-8")
    reports = [_check(1, "listed", "success"), _check(2, "red", "failure")]
    monkeypatch.setattr(tp, "read_server", lambda *_a: ("behind", ["only-server", "red"], reports))
    args = ["--repo", "o/r", "--sha", "abc", "--contexts-file", str(contexts)]
    assert tp.main([*args, "--wait-seconds", "0"]) == 1
    out = capsys.readouterr().out
    assert "'only-server' never reported" in out and "'red' did not pass" in out, out


def test_a_rules_page_that_is_not_a_list_refuses() -> None:
    with pytest.raises(RuntimeError, match="not a list of rule objects"):
        ruleset_contexts(["type"])


def test_main_stops_waiting_when_a_settled_problem_already_refuses(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A commit not on main is refused at once, whatever is still running on it."""
    contexts = tmp_path / "required-contexts.txt"
    contexts.write_text("CI gate\n", encoding="utf-8")
    monkeypatch.setattr(
        tp, "read_server", lambda *_a: ("diverged", [], [_check(1, "CI gate", "", "in_progress")])
    )
    sleeps: list[float] = []
    monkeypatch.setattr(time, "sleep", sleeps.append)
    args = ["--repo", "o/r", "--sha", "abc", "--contexts-file", str(contexts)]
    assert tp.main(args) == 1
    assert sleeps == []


@pytest.mark.parametrize("flag", [["--poll-seconds", "0"], ["--wait-seconds", "-1"]])
def test_wait_arguments_out_of_range_are_usage_errors(flag: list[str]) -> None:
    with pytest.raises(SystemExit) as raised:
        tp.main(["--repo", "o/r", "--sha", "abc", *flag])
    assert raised.value.code == 2


def test_unfinished_names_only_required_contexts_still_running() -> None:
    reports = [
        _check(1, "CI gate", "", "in_progress"),
        _check(2, "other", "", "queued"),
        _status(3, "cla", "pending"),
        _check(4, "done", "failure"),
    ]
    assert tp.unfinished(["CI gate", "cla", "done"], reports) == ["CI gate", "cla"]
    assert tp.unfinished(["CI gate"], [*reports, _check(9, "CI gate", "success")]) == []


def test_main_waits_for_a_running_check_then_judges_the_finished_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A tag pushed right after a merge meets main's push run still going; it is waited for."""
    contexts = tmp_path / "required-contexts.txt"
    contexts.write_text("CI gate\n", encoding="utf-8")
    readings: Iterator[tuple[str, list[str], list[Report]]] = iter(
        [
            ("behind", [], [_check(1, "CI gate", "", "in_progress")]),
            ("behind", [], [_check(1, "CI gate", "success")]),
        ]
    )
    sleeps: list[float] = []
    monkeypatch.setattr(tp, "read_server", lambda *_a: next(readings))
    monkeypatch.setattr(time, "sleep", sleeps.append)
    args = ["--repo", "o/r", "--sha", "abc", "--contexts-file", str(contexts)]
    assert tp.main([*args, "--poll-seconds", "5"]) == 0
    assert sleeps == [5]


def test_main_refuses_a_check_still_running_at_the_deadline(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    contexts = tmp_path / "required-contexts.txt"
    contexts.write_text("CI gate\n", encoding="utf-8")
    monkeypatch.setattr(
        tp, "read_server", lambda *_a: ("behind", [], [_check(1, "CI gate", "", "in_progress")])
    )
    args = ["--repo", "o/r", "--sha", "abc", "--contexts-file", str(contexts)]
    assert tp.main([*args, "--wait-seconds", "0"]) == 1
    out = capsys.readouterr().out
    assert "in_progress" in out and "gave up after 0s" in out, out


def test_read_server_asks_gh_for_each_endpoint_and_reads_its_pages(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The gh arguments and the page shapes, which the tests above replace wholesale."""
    answers: dict[str, Any] = {
        "compare/main...abc?per_page=1": {"status": "behind"},
        "branches/main": {"protection": {"required_status_checks": {"contexts": ["a"]}}},
        "rules/branches/main": [
            [
                {
                    "type": "required_status_checks",
                    "parameters": {"required_status_checks": [{"context": "b"}]},
                }
            ],
            [],
        ],
        "commits/abc/check-runs?per_page=100": [
            {"check_runs": [{"id": 1, "name": "a", "status": "completed", "conclusion": "success"}]}
        ],
        "commits/abc/statuses?per_page=100": [[{"id": 2, "context": "b", "state": "success"}]],
    }
    calls: list[list[str]] = []

    def fake(args: list[str]) -> Any:
        calls.append(list(args))
        endpoint = next(a for a in args if a.startswith("repos/"))
        return answers[endpoint.removeprefix("repos/o/r/")]

    monkeypatch.setattr(tp, "gh_api", fake)
    compare, server, reports = tp.read_server("o/r", "abc", "main")
    assert (compare, server) == ("behind", ["a", "b"])
    assert [r.context for r in reports] == ["a", "b"]
    paginated = [c[-1] for c in calls if "--paginate" in c]
    assert all("--slurp" in c for c in calls if "--paginate" in c)
    assert len(paginated) == 3, calls
    assert calls[0][1:] == ["--jq", "{status}"], calls[0]
