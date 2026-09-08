# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The ``ci-red`` reader: does the label get read back, and read back correctly (BACKLOG #1385)?

``failure-signal.yml`` has written the label since PR #716. Nothing read it until
``scripts/ci/report_ci_red.py``, so these are that script's first tests.

The rows below are shaped like real payloads because two of them ARE real: the merge-queue refs and
run names in :func:`test_the_real_pr_669_ejection_is_attributed` were read from this repository's
Actions API for PR 669, the ejection the backlog item was filed about.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "ci" / "report_ci_red.py"


def _load() -> Any:
    """Import the script by path -- ``scripts/`` is not a package, so a plain import cannot see it."""
    spec = importlib.util.spec_from_file_location("report_ci_red", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["report_ci_red"] = module
    spec.loader.exec_module(module)
    return module


mod = _load()


def _run(
    *,
    name: str = "CI",
    event: str = "merge_group",
    conclusion: str = "failure",
    branch: str = "gh-readonly-queue/main/pr-669-3760a93bfce37092b1add060dd6075c83cf4313a",
    created: str = "2026-08-29T12:42:51Z",
    pull_requests: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "name": name,
        "event": event,
        "conclusion": conclusion,
        "head_branch": branch,
        "created_at": created,
        "html_url": "https://github.com/MEFORORG/MessageFoundry/actions/runs/33253197221",
        "pull_requests": pull_requests if pull_requests is not None else [],
    }


def _pr(number: int = 669, title: str = "fix(connscale): the FD probe re-walked") -> dict[str, Any]:
    return {"number": number, "title": title, "state": "OPEN", "headRefName": "claude/x"}


# --- the defect the script exists for ---------------------------------------


def test_the_real_pr_669_ejection_is_attributed() -> None:
    """The end-to-end claim, on the real refs. PR 669's required contexts were GREEN on the PR page;
    it was ejected by a ``merge_group`` CI run the page never surfaced. The reader must name it and
    must mark it as invisible on the page, because that mark is what stops a reader re-queueing."""
    reds = mod.attribute([_pr()], [_run()])
    assert len(reds) == 1
    assert reds[0].attributed
    assert reds[0].hidden_from_the_pr_page
    assert "merge_group -- NOT VISIBLE ON THE PR PAGE" in reds[0].line()


def test_an_ordinary_pull_request_run_is_not_flagged_as_hidden() -> None:
    """The discriminating negative for the mark above. A ``pull_request`` run IS on the PR page, so
    flagging it would train readers to ignore the mark that matters."""
    run = _run(event="pull_request", branch="claude/x", pull_requests=[{"number": 669}])
    reds = mod.attribute([_pr()], [run])
    assert reds[0].attributed
    assert not reds[0].hidden_from_the_pr_page


# --- the security gate copied from the writer -------------------------------


def test_a_spoofed_pr_ref_on_a_non_merge_group_event_resolves_to_nothing() -> None:
    """A branch name is chosen by whoever opened the branch. The ``pr-<N>-`` parse is trustworthy
    ONLY because a fork cannot raise a ``merge_group`` event, so the gate is a security control.

    Mutation: drop the ``event != "merge_group"`` check in ``_pr_for_run``. Red: this attributes a
    fork's ``pr-669-deadbeef`` branch to pull request 669."""
    spoof = _run(event="pull_request", branch="pr-669-deadbeef", pull_requests=[])
    assert mod._pr_for_run(spoof) is None
    assert not mod.attribute([_pr()], [spoof])[0].attributed


def test_the_merge_queue_ref_must_be_a_whole_path_segment() -> None:
    """A branch merely CONTAINING the text is not a queue ref."""
    assert mod._pr_for_run(_run(branch="feature/pr-12-notes-and-things")) is None
    assert mod._pr_for_run(_run(branch="gh-readonly-queue/main/pr-42-abc123")) == 42


def test_the_supplied_pull_request_wins_over_the_ref_parse() -> None:
    """The writer's order: ``pull_requests[0]`` is authoritative where GitHub supplies it."""
    run = _run(branch="gh-readonly-queue/main/pr-669-abc123", pull_requests=[{"number": 42}])
    assert mod._pr_for_run(run) == 42


# --- the two filters that mirror failure-signal.yml -------------------------


def test_a_cancelled_run_is_not_a_red() -> None:
    """A merge-queue ejection CANCELS its siblings on the way out. Counting a cancellation would
    misattribute every ejection to whichever sibling died first, and the writer does not label for
    one either (``failure-signal.yml:51``).

    Mutation: accept ``cancelled`` in ``_RED``. Red: this attributes the cancelled run."""
    assert not mod.attribute([_pr()], [_run(conclusion="cancelled")])[0].attributed


def test_an_unwatched_workflow_is_not_a_red() -> None:
    """CLA Assistant is excluded from the writer deliberately -- a CLA failure is the contributor's
    to resolve. A reader that attributed it would report a cause the label was never applied for."""
    assert not mod.attribute([_pr()], [_run(name="CLA Assistant")])[0].attributed


# --- fail closed ------------------------------------------------------------


def test_a_labelled_pull_request_with_no_failing_run_is_reported_not_dropped() -> None:
    """ "I could not attribute this" must never render as "this is fine". The run aging out of the
    API window is the common, benign cause -- and silently dropping the row would hide the label
    entirely, which is the same blindness this script was written to end."""
    reds = mod.attribute([_pr()], [])
    assert len(reds) == 1
    assert not reds[0].attributed
    assert "UNATTRIBUTED" in reds[0].line()


def test_the_newest_failing_run_wins() -> None:
    """Both of PR 669's ejections failed. The reader must name the LATER one -- the earlier is
    already-acted-on history."""
    older = _run(created="2026-08-29T12:42:51Z")
    newer = _run(created="2026-08-29T13:01:54Z", name="Security")
    assert mod.attribute([_pr()], [older, newer])[0].run_name == "Security"
    assert mod.attribute([_pr()], [newer, older])[0].run_name == "Security"


# --- the CLI contract -------------------------------------------------------


def test_the_cli_exits_zero_and_says_so_when_nothing_carries_the_label(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    prs = tmp_path / "prs.json"
    prs.write_text("[]", encoding="utf-8")
    assert mod.main(["--prs-json", str(prs), "--runs-json", str(prs)]) == 0
    out = capsys.readouterr().out
    assert "0 open pull request(s) carry ci-red" in out  # the liveness receipt, not just the code


def test_the_cli_exits_one_and_names_the_hidden_run_when_a_pr_is_red(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    prs = tmp_path / "prs.json"
    runs = tmp_path / "runs.json"
    prs.write_text(json.dumps([_pr()]), encoding="utf-8")
    runs.write_text(json.dumps([_run()]), encoding="utf-8")
    assert mod.main(["--prs-json", str(prs), "--runs-json", str(runs)]) == 1
    out = capsys.readouterr().out
    assert "#669" in out
    assert "NOT VISIBLE ON THE PR PAGE" in out


def test_the_cli_fails_closed_when_the_payload_is_unreadable(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Exit 2, distinct from both 0 and 1. A query that could not run must not read as a clean repo."""
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert mod.main(["--prs-json", str(bad)]) == 2
    assert "Treating as a FAILURE" in capsys.readouterr().out


def test_warn_only_downgrades_the_finding_but_still_reports_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    prs = tmp_path / "prs.json"
    runs = tmp_path / "runs.json"
    prs.write_text(json.dumps([_pr()]), encoding="utf-8")
    runs.write_text(json.dumps([_run()]), encoding="utf-8")
    assert mod.main(["--prs-json", str(prs), "--runs-json", str(runs), "--warn-only"]) == 0
    assert "#669" in capsys.readouterr().out


# --- the reader must not drift from the writer ------------------------------


def test_the_watched_workflows_match_the_writer() -> None:
    """The reader classifies with two rules copied from ``failure-signal.yml``. If the workflow's
    list moves and this does not, the reader reports causes the label was never applied for.

    This reads the workflow rather than restating it, so the assertion cannot pass by agreeing with
    a stale copy of the list."""
    workflow = (
        Path(__file__).resolve().parents[1] / ".github" / "workflows" / "failure-signal.yml"
    ).read_text(encoding="utf-8")
    declared = next(line for line in workflow.splitlines() if line.strip().startswith("workflows:"))
    names = {n.strip() for n in declared.split("[", 1)[1].rstrip("]").split(",")}
    assert names == set(mod._WATCHED), (
        f"failure-signal.yml watches {names}, the reader watches {set(mod._WATCHED)}"
    )


def test_the_label_the_reader_asks_for_is_the_one_the_writer_applies() -> None:
    workflow = (
        Path(__file__).resolve().parents[1] / ".github" / "workflows" / "failure-signal.yml"
    ).read_text(encoding="utf-8")
    assert f"--add-label {mod.CI_RED_LABEL}" in workflow
