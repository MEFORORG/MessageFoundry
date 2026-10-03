# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``scripts/release/tag_provenance.py``: which tagged commits may release.

vault BACKLOG #2631, limb 2. The script asks the server two questions, and these tests grade the
answer it gives from what the server says. The server itself is not called here; the decision is a
pure function of the readings, and that is what is tested. tests/test_release_pipeline.py section
(12) holds where the workflow runs it.
"""

from __future__ import annotations

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
