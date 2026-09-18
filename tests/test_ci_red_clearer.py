# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The ``ci-red`` clearer: does the label come OFF, and only when it is earned by nothing?

``failure-signal.yml`` writes the label and ``scripts/ci/report_ci_red.py`` reads it back. Until
``scripts/ci/clear_stale_ci_red.py`` nothing removed it, so these are that script's first tests.

WHY THIS FILE AND NOT AN ADDITION TO ``test_ci_red_reader.py`` OR ``test_failure_signal.py``. Those
two are the reader's and the writer's suites and both are edited by an open pull request (#1240).
A third subject -- the clearer -- gets its own file rather than a merge conflict.

THE ONE ASYMMETRY WORTH KNOWING BEFORE READING THE ASSERTIONS. The bar for REMOVING the label is
deliberately a superset of the bar for applying it: the writer labels on a failure of one of three
watched workflows, while the clearer requires all fifteen contexts in
``.github/required-contexts.txt`` to be a settled success. That direction is safe -- it keeps a
label it cannot justify removing -- and it is asserted rather than left to be rediscovered.

EVERY BEHAVIOURAL ASSERTION HERE HAS A CONTROL, because this suite's whole failure mode is passing
vacuously. A decision function that returned "not clearable" unconditionally would satisfy most of
the rows below on its own; :func:`test_the_decision_can_produce_a_different_answer` is the arm that
rules that out, by driving the real functions with MUTATED COPIES of one baseline and requiring each
mutation to flip exactly one answer. Where a single test could pass over an empty input, it asserts
the input is non-empty first.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = _ROOT / "scripts" / "ci" / "clear_stale_ci_red.py"
_WRITER = _ROOT / ".github" / "workflows" / "failure-signal.yml"


def _load() -> Any:
    """Import the script by path -- ``scripts/`` is not a package, so a plain import cannot see it."""
    spec = importlib.util.spec_from_file_location("clear_stale_ci_red", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["clear_stale_ci_red"] = module
    spec.loader.exec_module(module)
    return module


mod = _load()


# --------------------------------------------------------------------------------------------
# Baseline payloads. One head, green everywhere, no queue evidence. Every behavioural test below
# either asserts against this or mutates a COPY of it, so "the baseline clears" is the control that
# makes each KEEP attributable to the one thing that test changed.
# --------------------------------------------------------------------------------------------

_HEAD = "85c77e39" + "0" * 32  # a full 40-char sha; the script rejects a short one
_SEEN = "2026-09-15T02:45:32Z"


def _check(
    name: str,
    *,
    status: str = "completed",
    conclusion: str | None = "success",
    started: str = "2026-09-15T03:00:00Z",
    ident: int = 1,
) -> dict[str, object]:
    return {
        "name": name,
        "status": status,
        "conclusion": conclusion,
        "started_at": started,
        "id": ident,
    }


def _green_checks(required: list[str]) -> list[dict[str, object]]:
    return [_check(name, ident=i) for i, name in enumerate(required)]


class _Ok:
    """A successful :func:`subprocess.run` result, reduced to the two fields the script reads."""

    returncode = 0
    stderr = ""


def _recorder(sink: list[list[str]]) -> Any:
    """A ``subprocess.run`` stand-in that records the argv and reports success."""

    def _run(cmd: list[str], **kwargs: object) -> _Ok:
        sink.append(cmd)
        return _Ok()

    return _run


@pytest.fixture(scope="module")
def required() -> list[str]:
    ctx = [str(name) for name in mod.required_contexts()]
    # Anti-vacuity: an empty required set would make every unmet_contexts() assertion below pass
    # while checking nothing at all.
    assert ctx, ".github/required-contexts.txt yielded no contexts"
    return ctx


# --------------------------------------------------------------------------------------------
# 1-3: the clearer must read the SAME record the rest of the chain reads, and must only ever remove.
# --------------------------------------------------------------------------------------------


def test_the_required_set_this_script_reads_is_the_checked_in_one(required: list[str]) -> None:
    """The script's own parser agrees with the suite's.

    The script re-implements the two-line parse rather than importing ``tests._workflow_contexts``,
    which pulls in PyYAML and pytest at module scope and so cannot run from a bare checkout. A copy
    is only safe while something compares it, which is this.
    """
    from tests._workflow_contexts import required_contexts as canonical

    assert required == list(canonical())
    # The arm that stops both parsers returning [] from a moved file and passing by agreement.
    assert "CI gate" in required, "the required set no longer names the roll-up; the parse is wrong"


def test_the_label_string_is_the_writers_own() -> None:
    """One label string, taken from the reader, which takes it from the writer."""
    # The clearer imports the reader by path at module scope, which registers it here. Taken from
    # sys.modules rather than imported: `scripts/` is not a package, so a plain import cannot see it.
    reader = sys.modules.get("report_ci_red")
    assert reader is not None, "the clearer did not load the reader; the label chain is broken"
    assert mod.CI_RED_LABEL == reader.CI_RED_LABEL
    text = _WRITER.read_text(encoding="utf-8")
    # The arm: without it, an unreadable workflow would make the `in` test below a search of "".
    assert len(text) > 1000, "failure-signal.yml read back too short to be the real file"
    assert f"--add-label {mod.CI_RED_LABEL}" in text


def test_the_script_can_only_remove_and_never_add() -> None:
    """No route in this file can put the label ON, and the only label it removes is ``ci-red``.

    Asked of the PARSED source, not the text. The script's own header discusses ``--add-label`` in
    prose -- explaining why comparing the label's timestamp cannot detect a re-application -- and a
    substring search over the file cannot tell that sentence from an argv. What matters is whether
    any string the code could hand to ``gh`` is that flag, so the question is put to the string
    CONSTANTS, with docstrings excluded.
    """
    source = _SCRIPT.read_text(encoding="utf-8")
    assert len(source) > 1000, "the script read back too short to be the real file"
    tree = ast.parse(source)

    docstrings = {
        id(node.body[0].value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef)
        and node.body
        and isinstance(node.body[0], ast.Expr)
        and isinstance(node.body[0].value, ast.Constant)
        and isinstance(node.body[0].value.value, str)
    }
    literals = [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in docstrings
    ]
    # The arm: without it, an AST walk that collected nothing would pass both assertions below.
    assert "--remove-label" in literals, (
        "the removal flag is not a string constant; the walk missed it"
    )
    assert "--add-label" not in literals

    # And the label it removes is the shared constant, never a literal spelling of it.
    assert mod.CI_RED_LABEL not in literals, "the label is written out as a literal somewhere"


# --------------------------------------------------------------------------------------------
# 4-5: what counts as green, and the anti-vacuity control for every behavioural row in this file.
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "status, conclusion",
    [
        ("completed", "cancelled"),
        ("completed", "neutral"),
        ("completed", "skipped"),
        ("completed", "stale"),
        ("completed", "timed_out"),
        ("completed", "action_required"),
        ("completed", "failure"),
        ("queued", None),
        ("in_progress", None),
    ],
)
def test_a_context_that_is_not_a_settled_success_keeps_the_label(
    required: list[str], status: str, conclusion: str | None
) -> None:
    """Only ``completed`` + ``success`` clears. Everything else holds the label.

    ``neutral`` and ``skipped`` are the two that matter: branch protection counts them as PASSING,
    and this is deliberately stricter. A check that did not run is not evidence that anything passed,
    and this script removes a red signal on the strength of the answer.
    """
    checks = _green_checks(required)
    checks[0] = _check(required[0], status=status, conclusion=conclusion)
    unmet = mod.unmet_contexts(mod.newest_by_name(checks), required)
    assert unmet == [f"{required[0]}={conclusion if status == 'completed' else status}"]


def test_an_absent_required_context_keeps_the_label(required: list[str]) -> None:
    """A context nothing reported is ABSENT, which is not a pass. The required-but-absent trap."""
    checks = _green_checks(required)[1:]
    assert mod.unmet_contexts(mod.newest_by_name(checks), required) == [f"{required[0]}=ABSENT"]


def test_the_decision_can_produce_a_different_answer(required: list[str]) -> None:
    """THE ANTI-VACUITY CONTROL FOR THIS WHOLE FILE.

    Drives the real decision functions with mutated COPIES of one baseline and requires each mutation
    to flip exactly one answer. Without this, a ``unmet_contexts`` that returned a non-empty list
    unconditionally, or a ``queue_evidence`` that returned everything, would satisfy nearly every
    other test here.

    It is its own control: the untouched baseline must come back CLEAR on both axes, so neither arm
    can be passing because both branches return the same thing.
    """
    checks = _green_checks(required)
    events = [{"event": "labeled", "created_at": "2026-09-15T04:00:00Z"}]

    # Baseline: both axes say "nothing holds this label".
    assert mod.unmet_contexts(mod.newest_by_name(checks), required) == []
    assert mod.queue_evidence(events, _SEEN) == []

    # Mutation A -- one context goes red. The contexts axis flips; the queue axis does not.
    red = [dict(c) for c in checks]
    red[0]["conclusion"] = "failure"
    assert mod.unmet_contexts(mod.newest_by_name(red), required) != []
    assert mod.queue_evidence(events, _SEEN) == []

    # Mutation B -- an ejection lands after the head was seen. The queue axis flips; contexts do not.
    ejected = [*events, {"event": "removed_from_merge_queue", "created_at": "2026-09-15T05:00:00Z"}]
    assert mod.queue_evidence(ejected, _SEEN) != []
    assert mod.unmet_contexts(mod.newest_by_name(checks), required) == []


# --------------------------------------------------------------------------------------------
# 6-8: which run speaks for a context, and how old the head is. Both are ordering traps.
# --------------------------------------------------------------------------------------------


def test_an_unsettled_run_of_a_name_beats_a_settled_success() -> None:
    """A still-running re-run outranks a finished green one of the same name, whatever the clock says.

    Measured on the head shared by PRs 1226 and 1241: two CI runs created 35 seconds apart whose
    durations differed by 67, so the EARLIER-created one finished LAST. Picking "the newest" there
    reads a still-running leg as green.
    """
    settled = _check("CI gate", started="2026-09-15T05:00:00Z", ident=2)
    running = _check(
        "CI gate", status="in_progress", conclusion=None, started="2026-09-15T03:00:00Z", ident=1
    )
    # The arm: two runs of ONE name, and the settled one really is the later-started of the pair.
    assert settled["name"] == running["name"]
    assert str(settled["started_at"]) > str(running["started_at"])

    speaks = mod.newest_by_name([settled, running])
    assert speaks["CI gate"]["id"] == 1, "the unsettled run must speak for the name"


def test_the_list_order_does_not_decide() -> None:
    """The same two runs, reversed, give the same answer. This endpoint promises no order."""
    settled = _check("CI gate", started="2026-09-15T05:00:00Z", ident=2)
    running = _check(
        "CI gate", status="in_progress", conclusion=None, started="2026-09-15T03:00:00Z", ident=1
    )
    forward = mod.newest_by_name([settled, running])["CI gate"]["id"]
    backward = mod.newest_by_name([running, settled])["CI gate"]["id"]
    assert forward == backward == 1, (
        "order changed the answer, or both orders agreed on the wrong run"
    )


def test_among_settled_runs_the_later_start_speaks() -> None:
    """Two settled runs of a name: the later-started one wins. The discriminating positive for 6."""
    old = _check("CI gate", conclusion="failure", started="2026-09-15T03:00:00Z", ident=1)
    new = _check("CI gate", conclusion="success", started="2026-09-15T05:00:00Z", ident=2)
    assert mod.newest_by_name([old, new])["CI gate"]["id"] == 2
    assert mod.newest_by_name([new, old])["CI gate"]["id"] == 2


def test_head_seen_at_is_the_minimum_of_both_clocks() -> None:
    """Neither clock can move the head's first-seen time on its own.

    The git committer date is written by whoever made the commit, so a forward-dated commit alone
    would make a stale head look newer than the ejection holding its label. A "re-run all jobs"
    pushes every check-run start forward, so that alone would make an old head look new. Taking the
    minimum means BOTH would have to move.
    """
    early_check = "2026-09-15T02:45:32Z"
    late_check = "2026-09-16T20:00:00Z"
    early_git = "2026-09-15T02:40:00Z"
    late_git = "2099-01-01T00:00:00Z"

    # The arm: both inputs are present and differ, in both directions, so neither test is one-sided.
    assert early_git < early_check < late_check < late_git

    # A forward-dated commit cannot move it: the check-run start still anchors it.
    assert mod.head_seen_at([_check("CI gate", started=early_check)], late_git) == early_check
    # Re-run-advanced check starts cannot move it: the git date still anchors it.
    assert mod.head_seen_at([_check("CI gate", started=late_check)], early_git) == early_git


# --------------------------------------------------------------------------------------------
# 9-12: the merge-queue latch. This is the half that protects the signal BACKLOG #1403 built.
# --------------------------------------------------------------------------------------------


def test_an_ejection_after_the_head_was_first_seen_keeps_it() -> None:
    """A queue event at or after the head's first-seen time is standing evidence."""
    events = [{"event": "added_to_merge_queue", "created_at": "2026-09-17T00:20:46Z"}]
    assert mod.queue_evidence(events, "2026-09-16T22:25:16Z") != []


def test_an_ejection_that_predates_the_current_head_releases() -> None:
    """The discriminating negative for the row above: same payload, ``since`` moved past it."""
    events = [{"event": "added_to_merge_queue", "created_at": "2026-09-17T00:20:46Z"}]
    assert mod.queue_evidence(events, "2026-09-18T00:00:00Z") == []


def test_an_undated_queue_event_counts_as_evidence() -> None:
    """An event this script cannot place in time is one it cannot rule out. Fails closed."""
    since = "2026-09-18T00:00:00Z"
    dated = {"event": "added_to_merge_queue", "created_at": "2026-09-17T00:20:46Z"}
    undated = {"event": "removed_from_merge_queue"}
    # The arm: `since` is set AFTER the dated event, so only the undated one can match. Without it,
    # a queue_evidence that ignored `since` entirely would pass on the dated event alone.
    assert mod.queue_evidence([dated], since) == []
    found = mod.queue_evidence([dated, undated], since)
    assert len(found) == 1 and "removed_from_merge_queue" in found[0]


def test_the_ejection_comment_is_evidence_and_an_unrelated_comment_is_not() -> None:
    """``EJECTION_PHRASE`` must discriminate, or every commented PR would be held forever."""
    since = "2026-09-15T00:00:00Z"
    stamp = "2026-09-16T00:00:00Z"
    ejection = {
        "event": "commented",
        "created_at": stamp,
        "body": f"CI failed while this pull request was in the merge queue, "
        f"{mod.EJECTION_PHRASE}.\n\nRead the run before retrying.",
    }
    chatter = {"event": "commented", "created_at": stamp, "body": "Rebased onto main, retrying."}
    assert mod.queue_evidence([ejection], since) != []
    assert mod.queue_evidence([chatter], since) == []


def test_the_ejection_phrase_is_the_writers_own() -> None:
    """The phrase matched here is really in ``failure-signal.yml``'s comment body.

    A phrase that has drifted from the writer matches nothing, and matching nothing reads as "this
    pull request was never ejected" -- the clearing direction.
    """
    text = _WRITER.read_text(encoding="utf-8")
    assert len(text) > 1000, "failure-signal.yml read back too short to be the real file"
    assert mod.EJECTION_PHRASE in text


# --------------------------------------------------------------------------------------------
# 13: one whole real payload, transcribed. PR 1229 was a live ejection with a fully green head.
# --------------------------------------------------------------------------------------------


def test_the_real_pr_1229_ejection_is_held(required: list[str]) -> None:
    """The case that makes the latch necessary: every required context green, and the label is RIGHT.

    Transcribed from the live repository on 2026-09-17. PR 1229 sat at ``mergeStateStatus=CLEAN``
    with 42 green check runs while carrying ``ci-red``, because the queue tests the branch MERGED
    WITH the base -- a set of runs the pull request page does not show at all.
    """
    head_seen = "2026-09-16T22:25:16Z"
    checks = _green_checks(required)
    events = [
        {"event": "added_to_merge_queue", "created_at": "2026-09-17T00:20:46Z"},
        {"event": "removed_from_merge_queue", "created_at": "2026-09-17T01:12:44Z"},
        {
            "event": "commented",
            "created_at": "2026-09-17T01:12:50Z",
            "body": f"CI failed while this pull request was in the merge queue, "
            f"{mod.EJECTION_PHRASE}.",
        },
    ]
    # The arm: assert the head really is fully green IN THIS TEST, so the hold below is attributable
    # to the ejection alone and not to a stray red context in the transcript.
    assert mod.unmet_contexts(mod.newest_by_name(checks), required) == []
    assert mod.queue_evidence(events, head_seen) != []


# --------------------------------------------------------------------------------------------
# 14-15: the paginator. Two page shapes, and an unread route must raise rather than read as empty.
# --------------------------------------------------------------------------------------------


def test_a_bare_array_page_shape_is_read(monkeypatch: pytest.MonkeyPatch) -> None:
    """``issues/<n>/timeline`` pages come back as BARE ARRAYS, not object-wrapped.

    A paginator handling only the wrapped shape returns nothing for the timeline, which reads as
    "never ejected" -- the clearing direction.
    """
    pages: list[object] = [[{"event": "added_to_merge_queue"}], [{"event": "labeled"}]]
    monkeypatch.setattr(mod, "_gh", lambda cmd: pages)
    found = mod._pages(None, "issues/1/timeline")
    # The arm: the fake really did hand back bare lists, and a non-empty result came back.
    assert all(isinstance(page, list) for page in pages)
    assert len(found) == 2


def test_an_object_wrapped_page_shape_is_read(monkeypatch: pytest.MonkeyPatch) -> None:
    """``check-runs`` pages wrap a named array. The other half of the pair above."""
    pages: list[object] = [{"check_runs": [_check("CI gate")]}, {"check_runs": [_check("cla")]}]
    monkeypatch.setattr(mod, "_gh", lambda cmd: pages)
    assert len(mod._pages(None, "commits/x/check-runs", "check_runs")) == 2


def test_an_empty_paginated_route_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """No pages is a FAILED READ, never a fact about the repository."""
    monkeypatch.setattr(mod, "_gh", lambda cmd: [])
    with pytest.raises(mod.ReadFailed, match="no pages"):
        mod._pages(None, "issues/1/timeline")


def test_the_paginator_asks_for_every_page(monkeypatch: pytest.MonkeyPatch) -> None:
    """``--paginate --slurp`` is in the argv, not a bare call that would silently stop at 30.

    Measured on this repository: heads carry 41 to 85 check runs against a default page of 30, and a
    truncated list looks exactly like a short one.
    """
    seen: list[list[str]] = []

    def _spy(cmd: list[str]) -> object:
        seen.append(cmd)
        return [[]]

    monkeypatch.setattr(mod, "_gh", _spy)
    mod._pages("o/n", f"issues/1/timeline?per_page={mod.PAGE}")
    assert seen and "--paginate" in seen[0] and "--slurp" in seen[0]
    assert f"per_page={mod.PAGE}" in seen[0][-1] and mod.PAGE == 100


# --------------------------------------------------------------------------------------------
# 16-17: the pre-write guard. Re-derive the evidence, and write only if nothing moved.
# --------------------------------------------------------------------------------------------


def test_the_pre_write_guard_refuses_when_the_evidence_moved(
    monkeypatch: pytest.MonkeyPatch, required: list[str]
) -> None:
    """A different fingerprint at write time means a red landed after the decision. Do not write."""
    calls: list[list[str]] = []
    monkeypatch.setattr(mod, "assess", lambda *a, **k: (True, "clear", '{"head":"MOVED"}'))
    monkeypatch.setattr(mod.subprocess, "run", lambda cmd, **k: calls.append(cmd))
    assert mod._remove(None, 1, required, '{"head":"ORIGINAL"}') is False
    assert calls == []


def test_the_pre_write_guard_writes_when_nothing_moved(
    monkeypatch: pytest.MonkeyPatch, required: list[str]
) -> None:
    """The positive half of the pair above -- without it, a ``_remove`` that never wrote would pass."""
    calls: list[list[str]] = []

    monkeypatch.setattr(mod, "assess", lambda *a, **k: (True, "clear", '{"head":"SAME"}'))
    monkeypatch.setattr(mod.subprocess, "run", _recorder(calls))
    assert mod._remove(None, 1, required, '{"head":"SAME"}') is True
    assert calls and "--remove-label" in calls[0] and mod.CI_RED_LABEL in calls[0]


# --------------------------------------------------------------------------------------------
# 18-20: the command line. Dry by default, a ceiling on a runaway pass, and fail-closed on a bad read.
# --------------------------------------------------------------------------------------------


def _drive(
    monkeypatch: pytest.MonkeyPatch, verdicts: list[tuple[int, bool, str, str]]
) -> list[list[str]]:
    """Run ``main`` against canned verdicts, returning every ``gh pr edit`` argv it attempted."""
    writes: list[list[str]] = []

    monkeypatch.setattr(mod, "_gh", lambda cmd: [{"number": n} for n, *_ in verdicts])
    monkeypatch.setattr(
        mod, "assess", lambda repo, number, req: next(v[1:] for v in verdicts if v[0] == number)
    )
    monkeypatch.setattr(mod.subprocess, "run", _recorder(writes))
    return writes


def test_the_default_is_a_dry_run(monkeypatch: pytest.MonkeyPatch) -> None:
    """No ``--apply``, no write -- even with a clearable pull request in hand."""
    writes = _drive(monkeypatch, [(1, True, "clear", "fp")])
    assert mod.main([]) == 0
    assert writes == []


def test_apply_actually_writes(monkeypatch: pytest.MonkeyPatch) -> None:
    """The positive half. ADDED TOGETHER WITH the row above -- either alone is vacuous."""
    writes = _drive(monkeypatch, [(1, True, "clear", "fp")])
    assert mod.main(["--apply"]) == 0
    assert writes and "--remove-label" in writes[0]


def test_the_circuit_breaker_removes_nothing_and_exits_one(monkeypatch: pytest.MonkeyPatch) -> None:
    """A pass wanting to clear most of the population is a classification bug, not a clean-up."""
    many = [(n, True, "clear", f"fp{n}") for n in range(1, mod.MAX_REMOVALS + 2)]
    writes = _drive(monkeypatch, many)
    # The arm: --apply is passed explicitly, so "nothing was written" cannot be the dry-run default.
    assert mod.main(["--apply"]) == 1
    assert writes == []


def test_an_unreadable_read_exits_two_and_says_it_removed_nothing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """ "I could not ask" must render as "I changed nothing", never as "nothing was stale"."""

    def _boom(cmd: list[str]) -> object:
        raise mod.ReadFailed("the query itself failed")

    monkeypatch.setattr(mod, "_gh", _boom)
    assert mod.main(["--apply"]) == 2
    assert "Removed NOTHING" in capsys.readouterr().out


def test_a_clean_population_exits_zero_and_says_what_it_examined(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The liveness receipt. "Nothing to clear" and "nothing was looked at" must not read alike.

    This is also the discriminating positive for the exit-2 row above: without it, a ``main`` that
    returned 2 on every path would satisfy that test.
    """
    _drive(monkeypatch, [(1, False, "CI gate=failure", "fp")])
    assert mod.main([]) == 0
    out = capsys.readouterr().out
    assert "examined 1 labelled pull request(s)" in out
    assert "every label is still earned" in out
