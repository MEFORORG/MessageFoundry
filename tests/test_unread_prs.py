# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The unread-PR signal must fire on the real shape and stay silent on everything adjacent to it.

These drive the REAL ``is_unread()``, ``decide()`` and ``main()`` against payloads, not a re-statement
of the rule. That distinction matters more than usual here, because this check exists to end a
SILENCE: a test that cannot demonstrate it firing would reproduce the very defect it guards.

THE TWO TRAPS ARE PINNED HERE RATHER THAN DESCRIBED, because both are one-line regressions that
redden nothing else:

* ``mergeStateStatus`` collapses to one value with precedence, so ``BEHIND``, ``DIRTY`` and
  ``UNSTABLE`` each mask a missing required check. Two tests hold it: the field is absent from
  ``PR_FIELDS`` so it cannot be read even by accident, and the verdict is identical across every
  value of it.
* The review gate's own conclusion is evidence in NEITHER direction. Red with the label present is a
  gate that has not re-run; GREEN with the label absent is BACKLOG #1423 -- the gate evaluates the
  event payload captured when its run was queued, so a `labeled` run queued behind a `synchronize`
  run passes on state that no longer holds. Both directions have a test.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = _ROOT / "scripts" / "ci" / "check_unread_prs.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_unread_prs", _SCRIPT)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


up = _load()

_GREEN = {"status": "COMPLETED", "conclusion": "SUCCESS", "name": "CI gate"}
_GATE_RED = {"status": "COMPLETED", "conclusion": "FAILURE", "name": up.REVIEW_GATE_CONTEXT}
_GATE_GREEN = {"status": "COMPLETED", "conclusion": "SUCCESS", "name": up.REVIEW_GATE_CONTEXT}


def _pr(
    number: int = 1,
    *,
    state: str = "OPEN",
    draft: bool = False,
    mergeable: str = "MERGEABLE",
    labels: list[str] | None = None,
    # Deliberately list[Any]: one test feeds a NON-dict node to prove an unreadable rollup entry is
    # not silently treated as green.
    rollup: list[Any] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    """A payload defaulting to the UNREAD shape, so each test perturbs exactly one field."""
    return {
        "number": number,
        "title": f"pr {number}",
        "url": f"https://example.invalid/pull/{number}",
        "headRefName": f"branch-{number}",
        "state": state,
        "isDraft": draft,
        "mergeable": mergeable,
        "labels": [{"name": n} for n in (labels if labels is not None else [])],
        "statusCheckRollup": [_GREEN, _GATE_RED] if rollup is None else rollup,
        **extra,
    }


# --- the positive control: it MUST fire -------------------------------------------------------


def test_the_exact_unread_shape_is_flagged() -> None:
    """Open, not draft, mergeable, everything green, no `reviewed` label, not yet flagged."""
    assert up.is_unread(_pr(731)) is True
    assert up.decide(_pr(731)) == up.FLAG


def test_a_pull_request_that_is_behind_is_still_worth_reading() -> None:
    """BEHIND is not a reason to stay silent -- it is a reason to update the branch BEFORE labelling.

    The comment carries that ordering; suppressing the signal instead would restore the silence.
    """
    assert up.decide(_pr(731, mergeStateStatus="BEHIND")) == up.FLAG


# --- the review gate's own conclusion is evidence in NEITHER direction -------------------------


def test_a_red_review_gate_does_not_suppress_the_flag() -> None:
    """The gate is red BECAUSE the label is missing. Reading it would be circular."""
    assert up.decide(_pr(rollup=[_GREEN, _GATE_RED])) == up.FLAG


def test_a_green_review_gate_does_not_suppress_the_flag() -> None:
    """BACKLOG #1423: the gate can pass with the label ABSENT.

    review-gate.yml evaluates ``github.event.pull_request.labels`` -- the payload captured when its
    run was QUEUED. A `labeled` run queued behind a `synchronize` run therefore starts stale and can
    pass on state that no longer holds, and the removal that invalidated it was made with
    GITHUB_TOKEN, which triggers no further run to correct it. So a green gate is not evidence the
    pull request was read. The LIVE label is, and it is what this reads.
    """
    assert up.decide(_pr(rollup=[_GREEN, _GATE_GREEN])) == up.FLAG


def test_a_red_review_gate_with_the_label_present_is_not_unread() -> None:
    """The reviewer labelled it and the gate has not re-run. Reading the gate would report it unread."""
    assert up.is_unread(_pr(labels=["reviewed"], rollup=[_GREEN, _GATE_RED])) is False


# --- the mergeStateStatus trap -----------------------------------------------------------------


def test_merge_state_status_is_never_even_requested() -> None:
    """Not "we ignore it" -- it is absent from the query, so it cannot be read by accident."""
    assert "mergeStateStatus" not in up.PR_FIELDS
    # Positive control for the assertion above: a field name that IS requested must be found by the
    # same test, or this only proves the string spelling was wrong.
    assert "statusCheckRollup" in up.PR_FIELDS


@pytest.mark.parametrize("merge_state", ["CLEAN", "BLOCKED", "BEHIND", "DIRTY", "UNSTABLE"])
def test_the_verdict_is_identical_across_every_merge_state(merge_state: str) -> None:
    """GitHub returns ONE value with precedence, so BEHIND, DIRTY and UNSTABLE all mask BLOCKED.

    A seat triaging on that field sees BEHIND, runs `gh pr update-branch`, fires `synchronize` --
    which strips the label -- and only THEN sees BLOCKED. This check must be immune to that, so the
    verdict may not move when the field does.
    """
    assert up.decide(_pr(mergeStateStatus=merge_state)) == up.FLAG


# --- the negative controls: each must NOT fire --------------------------------------------------


def test_the_reviewed_label_settles_it() -> None:
    assert up.is_unread(_pr(labels=["reviewed"])) is False


@pytest.mark.parametrize("conclusion", ["FAILURE", "TIMED_OUT", "CANCELLED", "ACTION_REQUIRED"])
def test_a_failing_check_is_not_unread(conclusion: str) -> None:
    """A red pull request is already loud -- failure-signal.yml labels it `ci-red`."""
    red = {"status": "COMPLETED", "conclusion": conclusion, "name": "CI gate"}
    assert up.is_unread(_pr(rollup=[red, _GATE_RED])) is False


@pytest.mark.parametrize("status", ["QUEUED", "IN_PROGRESS", "PENDING"])
def test_a_pending_check_is_not_unread(status: str) -> None:
    """Mid-suite is the normal path to green, not a finished pull request."""
    slow = {"status": status, "conclusion": None, "name": "CI gate"}
    assert up.is_unread(_pr(rollup=[slow, _GATE_RED])) is False


def test_nothing_reported_yet_is_not_green() -> None:
    """A rollup that is empty once the gate is removed means nothing has RUN, not that all passed.

    Silence is not success. This is the same rule check_stalled_prs.py applies when zero pull
    requests come back: an empty sweep reporting success is the shape both checks exist to refuse.
    """
    assert up.is_unread(_pr(rollup=[])) is False
    assert up.is_unread(_pr(rollup=[_GATE_RED])) is False


def test_a_draft_is_not_unread() -> None:
    assert up.is_unread(_pr(draft=True)) is False


@pytest.mark.parametrize("state", ["CLOSED", "MERGED"])
def test_a_closed_pull_request_is_not_unread(state: str) -> None:
    assert up.is_unread(_pr(state=state)) is False


def test_a_conflicting_pull_request_is_the_authors_problem_not_a_reviewers() -> None:
    assert up.is_unread(_pr(mergeable="CONFLICTING")) is False


def test_unknown_mergeability_still_reports() -> None:
    """UNKNOWN means GitHub has not computed it yet, and this check errs toward REPORTING.

    Failing to report restores the silence this exists to end; a spurious report costs one glance.
    """
    assert up.is_unread(_pr(mergeable="UNKNOWN")) is True


def test_an_unclassifiable_node_counts_as_unsettled_not_green() -> None:
    """ "I could not classify this" must never render as "this is passing"."""
    assert up.is_unread(_pr(rollup=[{"weird": "shape"}, _GATE_RED])) is False
    assert up.is_unread(_pr(rollup=["not-a-dict", _GATE_RED])) is False


def test_statuscontext_nodes_are_understood() -> None:
    """GitHub returns two node shapes; a StatusContext carries `state` and `context`."""
    ok = {"state": "SUCCESS", "context": "cla"}
    bad = {"state": "FAILURE", "context": "cla"}
    assert up.is_unread(_pr(rollup=[ok, _GATE_RED])) is True
    assert up.is_unread(_pr(rollup=[bad, _GATE_RED])) is False


def test_the_gate_is_excluded_under_its_statuscontext_spelling_too() -> None:
    """A node names itself with `name` OR `context`; excluding on only one spelling would leak."""
    gate = {"state": "FAILURE", "context": up.REVIEW_GATE_CONTEXT}
    assert up.is_unread(_pr(rollup=[_GREEN, gate])) is True


# --- the four actions, which are what makes the comment fire ONCE -------------------------------


def test_an_already_flagged_pull_request_is_kept_not_re_announced() -> None:
    """The label IS the idempotency token: announced once per unread episode, not once per run."""
    assert up.decide(_pr(labels=[up.UNREAD_LABEL])) == up.KEEP


def test_a_flagged_pull_request_that_was_read_is_cleared() -> None:
    assert up.decide(_pr(labels=[up.UNREAD_LABEL, "reviewed"])) == up.CLEAR


def test_an_unflagged_pull_request_that_is_not_unread_needs_nothing() -> None:
    """NONE rather than CLEAR, so the workflow's label removal never runs against an absent label.

    That is what lets the removal step keep its exit code instead of hiding a token failure behind
    a `|| true`.
    """
    assert up.decide(_pr(labels=["reviewed"])) == up.NONE


# --- the mention is derived, so it widens when the roster does ----------------------------------


def test_the_catch_all_owners_are_read_from_codeowners() -> None:
    assert up.root_owners("# a comment\n*  @alice @bob\n/docs/ @carol\n") == ["@alice", "@bob"]


def test_codeowners_is_last_match_wins() -> None:
    """GitHub applies the LAST matching rule, so a later catch-all overrides an earlier one."""
    assert up.root_owners("* @alice\n* @bob\n") == ["@bob"]


def test_a_codeowners_with_no_catch_all_mentions_nobody() -> None:
    """Degrade rather than invent: a comment with no mention still notifies subscribers."""
    assert up.root_owners("/docs/ @carol\n") == []


def test_the_live_codeowners_resolves_to_at_least_one_owner() -> None:
    """The positive control for the three above. Parsing that resolves nothing on the REAL file is
    indistinguishable from a repository with no owners, and would silently ship an unmentioned
    comment.
    """
    live = (_ROOT / ".github" / "CODEOWNERS").read_text(encoding="utf-8")
    assert up.root_owners(live), "the live CODEOWNERS catch-all resolved to no handles"


# --- the comment is the half that reaches a person, so its content is held ----------------------


def _body() -> str:
    return up.comment_body(_pr(731), "owner/name", ["@alice"])


def test_the_comment_names_the_ordering_that_saves_a_round_trip() -> None:
    """Update the branch FIRST, label LAST. Labelling first throws the label away on `synchronize`."""
    body = _body()
    assert "update it FIRST" in body
    assert "gh pr update-branch" in body
    assert body.index("gh pr update-branch") < body.index("--add-label reviewed")


def test_the_comment_warns_off_the_field_that_masks_the_gate() -> None:
    assert "mergeStateStatus" in _body()


def test_the_comment_carries_the_mention_and_the_seat_facing_query() -> None:
    body = _body()
    assert body.startswith("@alice")
    assert f"gh pr list --label {up.UNREAD_LABEL}" in body


def test_the_comment_never_tells_anyone_a_label_proves_a_person_looked() -> None:
    """The `reviewed` label is a PROCESS gate. Saying otherwise is the error the item forbids."""
    flat = " ".join(_body().split())
    assert "PROCESS gate" in flat
    assert "does not establish that an independent party looked" in flat


def test_the_comment_is_ascii_and_carries_no_glyphs() -> None:
    """CLAUDE.md section 11. This text is generated, so nothing else would ever catch a glyph in it."""
    assert _body().isascii()


# --- the CLI, driven end to end -----------------------------------------------------------------


def _run(tmp_path: Path, pr: dict[str, Any], *argv: str) -> int:
    payload = tmp_path / "pr.json"
    payload.write_text(json.dumps(pr), encoding="utf-8")
    return up.main(["--pr-json", str(payload), *argv])


def test_main_reports_the_action_and_writes_the_comment(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    body = tmp_path / "c.md"
    assert _run(tmp_path, _pr(731), "--body-out", str(body), "--repo", "owner/name") == 0
    assert f"action={up.FLAG}" in capsys.readouterr().out
    assert "nobody has marked it read" in body.read_text(encoding="utf-8")


def test_main_writes_no_comment_when_there_is_nothing_to_announce(tmp_path: Path) -> None:
    body = tmp_path / "c.md"
    assert _run(tmp_path, _pr(731, labels=["reviewed"]), "--body-out", str(body)) == 0
    assert not body.exists(), "a comment was written for a pull request that was already read"


def test_main_fails_loudly_on_an_empty_payload(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """ "I could not read the pull request" must never render as "it is fine"."""
    assert _run(tmp_path, {}) == 2
    assert "::error::" in capsys.readouterr().err


def test_main_fails_loudly_on_unreadable_json(tmp_path: Path) -> None:
    payload = tmp_path / "pr.json"
    payload.write_text("{not json", encoding="utf-8")
    assert up.main(["--pr-json", str(payload)]) == 2


def test_it_never_issues_a_write_through_gh() -> None:
    """Every mutation belongs to the workflow, where a reviewer looks for one.

    A script that CAN write a label is one edit away from writing the `reviewed` label, which is the
    fail-open design review-gate.yml's author already rejected. Asserted on the subprocess call
    rather than on the file text, because the header quotes the reviewer's own `gh pr edit` command
    and a substring search would match that prose.
    """
    source = _SCRIPT.read_text(encoding="utf-8")
    assert source.count("subprocess.run(") == 1, "more than one child process; re-read this test"
    assert '["gh", "pr", "view"' in source, "the one child process is no longer a read"
    for verb in ('"edit"', '"comment"', '"merge"', '"api"'):
        assert verb not in source, (
            f"check_unread_prs.py builds a {verb} argument; it must only READ"
        )
