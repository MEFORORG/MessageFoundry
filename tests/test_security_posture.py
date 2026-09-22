# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A REQUIRED gate must be able to go red. This pins that it still can.

THE DEFECT THIS EXISTS FOR. ``security.yml``'s own header documents the one-line downgrade:

    "To temporarily downgrade one, add `continue-on-error: true` back to its job."

That is a fair note for a human doing it on purpose. It is also the exact edit that makes a **required**
context report SUCCESS while scanning nothing — GitHub takes a job's conclusion, and
``continue-on-error`` rewrites a failure into success before branch protection ever sees it. With
``required_approving_review_count: 0`` and auto-merge armed, the PR then merges unread. Every scanner
this project relies on — bandit, pip-audit, npm-audit, gitleaks, semgrep, crypto-inventory and the
customer/PHI leak guard — sits behind that one line, and nothing guarded it: the three tests in this
repo that read a workflow's ``continue-on-error`` cover ``quality-advisory.yml`` and
``freethread-smoke.yml``, and ``test_lint_scope_parity.py`` opens ``security.yml`` only to compare scan
*scope*.

This is the artifact of a broader lesson the project already learned twice — a gate that reports green
while measuring nothing (``scripts/quality/liveness.py``, ``tests/test_gate_liveness.py``). Liveness
catches a gate that RAN and measured nothing. This catches a gate that was told its findings do not
count.

WHY IT ALSO PINS THE ADVISORY JOBS. The check runs in both directions on purpose. ``sbom`` and
``trivy`` are advisory *by design* and are scheduled for promotion; if one silently loses
``continue-on-error`` it starts blocking merges from a cron-only trigger, which is the
required-but-absent trap wearing the opposite hat. Either move must be a deliberate edit to the lists
below.

NOT VACUOUS BY CONSTRUCTION. ``test_every_security_job_is_classified`` fails when a job is added to
``security.yml`` without being named blocking or advisory here, so a new scanner cannot arrive
unguarded — the failure mode that would otherwise make this whole module a decoration.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

from tests._bash_resolver import (
    CANNOT_RUN_CODES,
    explain_returncode,
    probe_env,
    require_bash,
)
from tests._workflow_contexts import (
    WORKFLOWS,
    context_of,
    jobs_of,
    load_workflow,
    required_contexts,
    resolve,
)

_SECURITY = "security.yml"

# BLOCKING: a finding here must fail the build. Each of these job names is asserted to be in
# .github/required-contexts.txt below, so "blocking" is a checked claim rather than a label.
_BLOCKING_SECURITY_JOBS = frozenset(
    {
        # The two composite roll-ups, PROMOTED 2026-09-15 out of _PENDING_PROMOTION_SECURITY_JOBS
        # after the owner added both contexts to branch protection. Recording a context is what drags
        # its job under every rule in this module for the first time, so this line is the point at
        # which the composites are graded like the seven scans they duplicate rather than like staged
        # work nobody grades.
        #
        # SINCE 2026-09-16 THEY ARE THE ONLY BLOCKING JOBS IN security.yml. The seven original scans --
        # pip-audit, npm-audit, bandit, gitleaks, semgrep, crypto-inventory, forbidden-content -- were
        # listed here until the owner removed their contexts from branch protection at about 18:45Z that
        # day (consolidation step 4, taken before step 3). They are now in
        # _SUPERSEDED_SECURITY_JOBS below. They were NOT deleted from the workflow; this module would
        # red if they had been, because `test_every_security_job_is_classified` asserts set equality
        # over every job in the file.
        "repo-scan",
        "dependency-and-secret-scan",
    }
)

# ADVISORY by design: these MUST keep continue-on-error. Both are cron/dispatch-only, so promoting one
# without also removing its `if:` would wedge every PR (see security.yml's own notes on trivy).
# WHERE the flag sits differs: `sbom` carries it on the job, `trivy` on its one scan step, and a job
# listed in _STEP_ADVISORY_JOBS below is graded there instead of by the job-level rule.
_ADVISORY_SECURITY_JOBS = frozenset({"sbom", "trivy"})

# ADVISORY BY PLACEMENT: hard-failing, but NOT in branch protection. This is a third posture the file
# previously could not express, and it is not new to the repo -- `dast.yml` already ships it and
# .github/required-contexts.txt records it: advisory by placement, not by continue-on-error, so the job
# goes red on a finding.
#
# The distinguishing rule, and the reason this is a separate list rather than an entry in
# _ADVISORY_SECURITY_JOBS: these jobs MUST NOT carry continue-on-error. A job that can never report on
# a PR cannot be required, but that is a reason to keep it out of branch protection -- not a reason to
# discard its findings.
_ADVISORY_BY_PLACEMENT_SECURITY_JOBS = frozenset({"released-line-audit"})

# SUPERSEDED: hard-failing, reporting on EVERY pull request, and deliberately NOT required -- because a
# required COMPOSITE now runs the same scan. Added 2026-09-16, when the owner removed these seven
# contexts from branch protection (consolidation step 4, taken before step 3; docs/CI.md).
#
# WHY THIS IS NOT ONE OF THE THREE BUCKETS ABOVE, checked rather than argued:
#
#   * not _ADVISORY_SECURITY_JOBS      -- those MUST carry `continue-on-error: true`. These must NOT:
#                                         they still scan for real and a finding must still redden the
#                                         job, because `repo-scan`'s copy of that scan is the gate and
#                                         a red original is how a human notices the copy would fail.
#   * not _ADVISORY_BY_PLACEMENT       -- that bucket asserts the job CANNOT report on a pull request
#                                         (schedule/dispatch-only `if:`). These have no `if:` at all
#                                         and report on every one. Filing them there would have made
#                                         `test_advisory_by_placement_jobs_cannot_run_on_a_pull_request`
#                                         red, which is the assertion that keeps that bucket honest.
#   * not _PENDING_PROMOTION           -- that bucket points FORWARD: not required YET, and must become
#                                         required. These point the other way. Sharing the list would
#                                         give one name two opposite meanings, which is the confusion
#                                         every classification in this module exists to prevent.
#
# THIS IS A STAGING BUCKET AND IT MUST EMPTY. It exists only for the window between consolidation step
# 4 (done) and step 3 (deleting the seven jobs). While it is non-empty the repository pays seven runner
# slots a run for scans that gate nothing -- the cost of having inverted the step order, and the cheaper
# of the two windows on offer. Emptying it means deleting the seven jobs from security.yml; nothing
# requires their contexts, so that deletion can no longer wedge a pull request.
#
# WHAT MAKES THE POSTURE SAFE, and it is a checked claim, not a reassurance:
# tests/test_security_composite_parity.py asserts each composite's copy of a scan body is
# BYTE-IDENTICAL to the original's. So every assertion this repository makes about one of these seven
# steps is an assertion about a string the required composite shares. That is also what licenses the
# nine negative controls written about these scans to be re-pointed at the composite contexts in
# tests/negative_controls.toml rather than deleted.
_SUPERSEDED_SECURITY_JOBS = frozenset(
    {
        "pip-audit",
        "npm-audit",
        "bandit",
        "gitleaks",
        "semgrep",
        "crypto-inventory",
        "forbidden-content",
    }
)

# PENDING PROMOTION: hard-failing, running on every pull request, and NOT YET in branch protection --
# the transient fourth posture that step 1 of the security-job consolidation creates. The two
# composites run the same scans as the seven jobs they will replace, and
# tests/test_security_composite_parity.py asserts each copied body is byte-identical to its original,
# so during the overlap the repository runs every scan twice and grades one copy.
#
# IT IS A STAGING BUCKET, NOT A THIRD PERMANENT POSTURE, and the difference from
# _ADVISORY_BY_PLACEMENT_SECURITY_JOBS is the whole reason it is a separate list. That bucket says a
# job CANNOT be required (it never reports on a pull request). This one says a job is not required
# YET, and must become required: the consolidation only pays once branch protection reads the
# composite and the seven originals are gone.
#
# WHY THE OVERLAP EXISTS AT ALL. A required status context is a JOB NAME. Deleting the seven while
# protection still names them wedges every pull request in the repository, and moving protection
# first, to names nothing yet reports, wedges it identically. `security.yml` carries the step list
# above the composite jobs, with an amendment recording which steps have been taken.
#
# THE BUCKET IS EMPTY AS OF 2026-09-15 and the mechanism is kept for the next staged job. The owner
# added both composite contexts to branch protection, a pull request recorded them in
# .github/required-contexts.txt, and the same pull request moved both names into
# _BLOCKING_SECURITY_JOBS above -- which drags them under every rule in this module for the first
# time. `test_pending_promotion_jobs_are_not_recorded_as_required` below is the forcing function that
# made those two halves one change, and it is what reddened when only the file was edited.
#
# WHAT IT DID NOT FORCE, AND MUST NOT: deleting the seven original jobs. Its failure message used to
# name that as part of the same change, which was wrong AT THE TIME and would have wedged the
# repository -- protection then named all seven ORIGINAL contexts alongside the composites, so
# deleting their jobs would have left contexts nothing can report. That is consolidation step 3.
#
# THE HAZARD IS GONE AND THE RULE IS NOT. Branch protection no longer names the seven (that was
# step 4, taken 2026-09-16 AHEAD of step 3 rather than after it), so the deletion can no longer wedge
# anything and needs no protection edit beside it -- `.github/required-contexts.txt` is the record,
# and docs/CI.md carries the ordering hazard for the next staged context. What still must not happen
# is this bucket's forcing function reaching for that deletion: promoting a pending job and deleting
# a superseded one are different changes, and the reason to keep them apart never depended on the
# hazard that has since lapsed.
#
# WHILE THIS LIST IS EMPTY THE THREE `pending_promotion` TESTS BELOW ARE DORMANT, and that is said
# plainly rather than left to be discovered: a loop over an empty set cannot fail. They are kept
# because the staging window recurs, and nothing is licensed by their dormancy -- the composites are
# now graded by `test_blocking_security_jobs_are_in_the_required_set`,
# `test_required_jobs_carry_no_continue_on_error`, `test_required_jobs_have_no_neutered_steps` and
# `test_required_jobs_declare_no_skippable_job_level_if`, all of which are live on them. The guard
# that cannot go vacuous is `test_every_security_job_is_classified`: it asserts SET EQUALITY over
# every job in the workflow, so emptying this bucket is only legal if each name landed in another.
_PENDING_PROMOTION_SECURITY_JOBS: frozenset[str] = frozenset()

#: Every job this module grades, whatever its posture. `test_every_security_job_is_classified`
#: asserts this is SET-EQUAL to the workflow's real job keys, which is what lets other rules build on
#: it: a job added to security.yml cannot silently fall outside anything derived from this name.
_ALL_GRADED_SECURITY_JOBS = (
    _BLOCKING_SECURITY_JOBS
    | _ADVISORY_SECURITY_JOBS
    | _ADVISORY_BY_PLACEMENT_SECURITY_JOBS
    | _SUPERSEDED_SECURITY_JOBS
    | _PENDING_PROMOTION_SECURITY_JOBS
)

# Job-level `if:` expressions that CANNOT skip the job on a pull_request, with the reason each is safe.
# Anything else on a required job is a way for the context to silently not report.
_JOB_IF_ALLOWLIST = {
    ("ci.yml", "ci-gate"): "always()",  # the roll-up must run even when a gated leg failed
}

# Idioms that discard a non-zero exit, i.e. neuter the step without touching continue-on-error.
_NEUTERING = (
    (re.compile(r"\|\|\s*true\b"), "|| true"),
    (re.compile(r"\|\|\s*:\s*(?:$|[;&\n])"), "|| :"),
    (re.compile(r"\|\|\s*exit\s+0\b"), "|| exit 0"),
    (re.compile(r"--exit-zero\b"), "--exit-zero"),
    (re.compile(r"--fail-under=0\b"), "--fail-under=0"),
)

#: A `$( ... )` command substitution on one line. What is inside CANNOT set the step's exit status —
#: it sets the substitution's, which the surrounding assignment then consumes.
_SUBSTITUTION = re.compile(r"\$\([^()]*\)")

#: A trailing shell comment. Approximate on purpose (a `#` inside a quoted string is not a comment),
#: and safe in this direction: stripping a comment can only REMOVE text from the scan, and a real
#: `cmd || true  # note` still reads as `cmd || true` afterwards.
_TRAILING_COMMENT = re.compile(r"(?:^|\s)#.*$")


def _gating_text(line: str) -> str:
    """A step line reduced to the part whose exit status can actually reach the step.

    Two things are removed before the neutering patterns are applied, because both produced false
    positives that would have been "fixed" by weakening a real gate:

    * **Command substitutions.** `claim="$(… | grep -oiE 'BACKLOG #[0-9]+' | head -1 || true)"` is the
      idiomatic guard for `grep` exiting 1 on no-match under `set -euo pipefail`; without it the script
      aborts on the ordinary "no claim in this PR" path. It cannot mask the step's status — the gating
      decision is the explicit `exit 0` / `exit 1` further down. Flagging it suggested "confine it to
      its own step", which is impossible for a variable assignment and would have meant deleting the
      guard from a correct script.
    * **Comments.** The rationale comments in these workflows quote the very idiom being prohibited, so
      a raw scan reports the explanation as the offence — a detector counting itself.

    A standalone `gating_cmd || true`, which is the actual hazard, survives both strips and is caught.
    """
    return _TRAILING_COMMENT.sub("", _SUBSTITUTION.sub("", line))


def _required_jobs() -> dict[tuple[str, str], dict]:
    """Every job backing a required context, keyed by (workflow file, job key)."""
    resolved: dict[tuple[str, str], dict] = {}
    unresolved: list[str] = []
    for ctx in required_contexts():
        where = resolve(ctx)
        if where is None:
            unresolved.append(ctx)
            continue
        resolved[where] = jobs_of(where[0])[where[1]]
    assert not unresolved, (
        f"required context(s) resolve to no job: {unresolved}. Fix that first — a required check that "
        "never reports blocks every PR forever, and this module cannot assess a job it cannot find."
    )
    return resolved


def test_every_security_job_is_classified() -> None:
    """A new job in security.yml must be declared blocking or advisory HERE before it can land.

    Without this, adding a scanner would leave it outside every assertion below and this module would
    quietly stop covering the file it is named for.
    """
    actual = set(jobs_of(_SECURITY))
    classified = _ALL_GRADED_SECURITY_JOBS
    print(f"[security-posture] classified {len(classified)} of {len(actual)} jobs in {_SECURITY}")
    assert actual == classified, (
        f"security.yml jobs are not all classified.\n"
        f"  unclassified (add to _BLOCKING_SECURITY_JOBS, _ADVISORY_SECURITY_JOBS, "
        f"_ADVISORY_BY_PLACEMENT_SECURITY_JOBS, _SUPERSEDED_SECURITY_JOBS or "
        f"_PENDING_PROMOTION_SECURITY_JOBS): "
        f"{sorted(actual - classified)}\n"
        f"  named here but gone from the workflow: {sorted(classified - actual)}"
    )


def test_no_job_is_in_two_posture_buckets() -> None:
    """The buckets make OPPOSITE assertions, so an overlap is a contradiction, not a duplicate.

    `test_every_security_job_is_classified` compares a UNION against the workflow's jobs, and a union
    cannot see a name filed twice -- the set equality holds either way. That matters most for the pair
    this repository actually confused: a job left in `_BLOCKING_SECURITY_JOBS` while also listed as
    `_SUPERSEDED_SECURITY_JOBS` would be asserted both to be in the required set and not to be, and
    whichever assertion ran first would decide which of two contradictory claims the suite reported.
    """
    buckets = {
        "_BLOCKING_SECURITY_JOBS": _BLOCKING_SECURITY_JOBS,
        "_ADVISORY_SECURITY_JOBS": _ADVISORY_SECURITY_JOBS,
        "_ADVISORY_BY_PLACEMENT_SECURITY_JOBS": _ADVISORY_BY_PLACEMENT_SECURITY_JOBS,
        "_SUPERSEDED_SECURITY_JOBS": _SUPERSEDED_SECURITY_JOBS,
        "_PENDING_PROMOTION_SECURITY_JOBS": _PENDING_PROMOTION_SECURITY_JOBS,
    }
    overlaps = [
        f"{job!r} is in both {a} and {b}"
        for i, (a, first) in enumerate(buckets.items())
        for b, second in list(buckets.items())[i + 1 :]
        for job in sorted(first & second)
    ]
    assert not overlaps, (
        "a security.yml job is filed under two postures, which assert contradictory things about it:\n  "
        + "\n  ".join(overlaps)
    )


def test_superseded_jobs_are_not_required() -> None:
    """The whole claim of the bucket. A superseded job that is still required is misfiled, not retired.

    This is the arm that would have caught the 2026-09-16 drift from the other side: while the seven
    sat in `_BLOCKING_SECURITY_JOBS` and protection still named them, nothing here was wrong. The
    moment the register drops them, being listed as blocking becomes false -- and if a future
    protection edit puts one back, this test reddens rather than the repository quietly running a
    required gate that this module grades as retired.
    """
    required = set(required_contexts())
    jobs = jobs_of(_SECURITY)
    still_required = sorted(
        context_of(k, jobs[k])
        for k in _SUPERSEDED_SECURITY_JOBS
        if context_of(k, jobs[k]) in required
    )
    assert not still_required, (
        f"{still_required} is classified SUPERSEDED but is still in .github/required-contexts.txt. "
        "Either branch protection took the context back -- in which case move the job key to "
        "_BLOCKING_SECURITY_JOBS, which is what subjects it to the rules for required gates -- or the "
        "register is wrong. Do not leave it in both lists."
    )


def test_superseded_jobs_carry_no_continue_on_error() -> None:
    """Off the merge path is NOT findings discarded -- the same rule the by-placement bucket carries.

    A superseded scan is the early warning for its own replacement: the composite runs a byte-identical
    copy, so a finding the original reports is a finding the required composite will report too. Neuter
    the original and that warning goes silent while the job still shows a green tick.
    """
    jobs = jobs_of(_SECURITY)
    for key in sorted(_SUPERSEDED_SECURITY_JOBS):
        job = jobs[key]
        assert job.get("continue-on-error") in (None, False), (
            f"security.yml job {key!r} is superseded but must still go red on a finding; it now "
            "declares continue-on-error, which discards them. It is already outside branch protection, "
            "so there is nothing continue-on-error can protect here -- delete the job instead "
            "(consolidation step 3)."
        )
        for step in job.get("steps") or []:
            name = (step or {}).get("name") or (step or {}).get("uses") or "<unnamed step>"
            assert (step or {}).get("continue-on-error") in (None, False), (
                f"security.yml job {key!r}, step {name!r} declares continue-on-error"
            )


def test_every_superseded_job_is_consolidated_by_a_required_composite() -> None:
    """ "Superseded" names a REPLACEMENT, and this is the assertion that it exists and still gates.

    Without it the bucket is a place to park a job whose context somebody dropped, and the seven scans
    would leave the merge path with nothing recording that anything took them over. The mapping is
    read from tests/test_security_composite_parity.py, which is also what asserts the copied bodies are
    byte-identical -- so the claim "the same scan still gates" rests on one mapping, not two.
    """
    from tests.test_security_composite_parity import _COMPOSITES

    required = set(required_contexts())
    jobs = jobs_of(_SECURITY)
    consolidated_by = {
        original: composite
        for composite, originals in _COMPOSITES.items()
        for original in originals
    }
    orphans: list[str] = []
    for key in sorted(_SUPERSEDED_SECURITY_JOBS):
        composite = consolidated_by.get(key)
        if composite is None:
            orphans.append(f"{key!r} is consolidated by no composite in _COMPOSITES")
        elif composite not in jobs:
            orphans.append(
                f"{key!r} names composite {composite!r}, which is not a job in {_SECURITY}"
            )
        elif context_of(composite, jobs[composite]) not in required:
            orphans.append(
                f"{key!r} is superseded by {composite!r}, whose context is NOT required -- the scan "
                "left the merge path and nothing replaced it"
            )
    assert not orphans, (
        "a superseded security.yml job has no required composite carrying its scan:\n  "
        + "\n  ".join(orphans)
        + "\nA scan that stopped gating and was not taken over is coverage lost, not consolidated."
    )


def test_blocking_security_jobs_are_in_the_required_set() -> None:
    """ "Blocking" means "in branch protection". A job that fails but is not required is decoration."""
    required = set(required_contexts())
    jobs = jobs_of(_SECURITY)
    missing = sorted(
        context_of(k, jobs[k])
        for k in _BLOCKING_SECURITY_JOBS
        if context_of(k, jobs[k]) not in required
    )
    assert not missing, (
        f"these security.yml jobs are declared BLOCKING but are absent from "
        f".github/required-contexts.txt: {missing}. A hard-failing job that is not a required context "
        "does not stop auto-merge — it only looks like it does."
    )


def test_advisory_security_jobs_are_not_required() -> None:
    required = set(required_contexts())
    jobs = jobs_of(_SECURITY)
    promoted = sorted(
        context_of(k, jobs[k])
        for k in _ADVISORY_SECURITY_JOBS
        if context_of(k, jobs[k]) in required
    )
    assert not promoted, (
        f"{promoted} is advisory in security.yml but present in the required set. Both advisory jobs "
        "are cron/dispatch-only, so as a required context they would never report on a PR and would "
        "block every merge (docs/CI.md, 'the required-but-absent trap'). Remove the `if:` gate first."
    )


def test_advisory_by_placement_jobs_are_not_required() -> None:
    """Placement is the whole mechanism: these are kept off the merge path by not being required."""
    required = set(required_contexts())
    jobs = jobs_of(_SECURITY)
    promoted = sorted(
        context_of(k, jobs[k])
        for k in _ADVISORY_BY_PLACEMENT_SECURITY_JOBS
        if context_of(k, jobs[k]) in required
    )
    assert not promoted, (
        f"{promoted} is schedule/dispatch-gated but present in the required set. It can never report "
        "on a PR, so requiring it blocks every merge forever (the required-but-absent trap). Remove "
        "the job-level `if:` first if promotion is genuinely intended."
    )


def test_advisory_by_placement_jobs_carry_no_continue_on_error() -> None:
    """The point of this bucket. Off the merge path is NOT the same as findings discarded."""
    jobs = jobs_of(_SECURITY)
    for key in sorted(_ADVISORY_BY_PLACEMENT_SECURITY_JOBS):
        job = jobs[key]
        assert job.get("continue-on-error") in (None, False), (
            f"security.yml job {key!r} is advisory BY PLACEMENT and must still go red on a finding; "
            "it now declares continue-on-error, which discards them. It is already outside branch "
            "protection, so there is nothing continue-on-error can protect here."
        )
        for step in job.get("steps") or []:
            name = (step or {}).get("name") or (step or {}).get("uses") or "<unnamed step>"
            assert (step or {}).get("continue-on-error") in (None, False), (
                f"security.yml job {key!r}, step {name!r} declares continue-on-error"
            )


def test_advisory_by_placement_jobs_cannot_run_on_a_pull_request() -> None:
    """If one of these could report on a PR it would be requirable, and this bucket would be a lie."""
    jobs = jobs_of(_SECURITY)
    for key in sorted(_ADVISORY_BY_PLACEMENT_SECURITY_JOBS):
        expr = str(jobs[key].get("if") or "")
        assert "schedule" in expr and "workflow_dispatch" in expr and "pull_request" not in expr, (
            f"security.yml job {key!r} is classified advisory-by-placement, which asserts it never "
            f"reports on a PR, but its `if:` is {expr!r}. Either restore the schedule/dispatch gate or "
            "reclassify it and add its context to .github/required-contexts.txt and branch protection."
        )


def test_advisory_security_jobs_keep_continue_on_error() -> None:
    """The mirror of the blocking assertion: an accidental promotion must also be a deliberate edit."""
    jobs = jobs_of(_SECURITY)
    step_graded = {key for wf, key, _, _ in _STEP_ADVISORY_JOBS if wf == _SECURITY}
    # Not vacuous by exemption: a step-graded job must still be advisory, and the step test pins
    # exactly one softened step on it. Only the job-level half of the rule moves.
    assert step_graded <= _ADVISORY_SECURITY_JOBS, (
        f"{sorted(step_graded - _ADVISORY_SECURITY_JOBS)} is step-advisory in _STEP_ADVISORY_JOBS "
        "but not advisory here; classify it in one posture, not two."
    )
    for key in sorted(_ADVISORY_SECURITY_JOBS - step_graded):
        assert jobs[key].get("continue-on-error") is True, (
            f"security.yml job {key!r} is advisory by design but no longer declares "
            "`continue-on-error: true`. If this is a deliberate promotion, move it to "
            "_BLOCKING_SECURITY_JOBS, add its context to .github/required-contexts.txt and branch "
            "protection, and remove the schedule/dispatch `if:` gate so it reports on PRs."
        )


def test_pending_promotion_jobs_carry_no_continue_on_error() -> None:
    """The overlap must not be a hole. These scan for real while they wait for protection."""
    jobs = jobs_of(_SECURITY)
    for key in sorted(_PENDING_PROMOTION_SECURITY_JOBS):
        job = jobs[key]
        assert job.get("continue-on-error") in (None, False), (
            f"security.yml job {key!r} is staged for promotion and declares continue-on-error, which "
            "discards its findings. A job nobody grades yet is the easiest place for that line to go "
            "unnoticed, and it would arrive in branch protection already neutered."
        )
        for step in job.get("steps") or []:
            name = (step or {}).get("name") or (step or {}).get("uses") or "<unnamed step>"
            assert (step or {}).get("continue-on-error") in (None, False), (
                f"security.yml job {key!r}, step {name!r} declares continue-on-error"
            )


def test_pending_promotion_jobs_can_report_on_a_pull_request() -> None:
    """Promotion is only safe for a job that already reports. This is the precondition, checked early.

    A required context that never reports blocks every pull request forever, and the cheapest moment
    to find out is before the owner edits branch protection -- not after, when the repository is
    already wedged and the remedy is another protection edit.
    """
    jobs = jobs_of(_SECURITY)
    for key in sorted(_PENDING_PROMOTION_SECURITY_JOBS):
        expr = jobs[key].get("if")
        assert expr is None, (
            f"security.yml job {key!r} is staged for promotion but carries a job-level `if:` "
            f"({str(expr).strip()!r}). An `if:` that evaluates false SKIPS the job, so as a required "
            "context it would wedge every pull request it skipped. Gate the expensive STEPS instead."
        )


def test_pending_promotion_jobs_are_not_recorded_as_required() -> None:
    """The forcing function for step 3: recording the context and reclassifying are ONE change.

    While a job sits in this bucket, nothing in this module grades it the way a blocking job is
    graded. So a context recorded in .github/required-contexts.txt while its job stayed staged would
    be a required gate outside the rules written for required gates -- passing here for the sole
    reason that it is filed in the wrong list.
    """
    required = set(required_contexts())
    jobs = jobs_of(_SECURITY)
    promoted = sorted(
        context_of(k, jobs[k])
        for k in _PENDING_PROMOTION_SECURITY_JOBS
        if context_of(k, jobs[k]) in required
    )
    assert not promoted, (
        f"{promoted} is recorded as required but is still classified as pending promotion. Move the "
        "job key into _BLOCKING_SECURITY_JOBS in the same change, and update the distinct-job count "
        "pinned in test_required_jobs_carry_no_continue_on_error below. Do NOT also delete the "
        "original jobs it consolidates: branch protection still requires those contexts, so deleting "
        "their jobs leaves required contexts nothing can report and wedges every pull request. That "
        "deletion is consolidation step 3 and needs the owner's protection edit in the same window "
        "(docs/CI.md)."
    )


def test_required_jobs_carry_no_continue_on_error() -> None:
    """Job-level AND step-level. Either one turns a red gate green before protection sees it."""
    offenders: list[str] = []
    examined = 0
    for (wf, key), job in _required_jobs().items():
        examined += 1
        if job.get("continue-on-error") not in (None, False):
            offenders.append(f"{wf}:{key} — job-level continue-on-error")
        for step in job.get("steps") or []:
            if (step or {}).get("continue-on-error") not in (None, False):
                name = (step or {}).get("name") or (step or {}).get("uses") or "<unnamed step>"
                offenders.append(f"{wf}:{key} — step {name!r} has continue-on-error")
    # Liveness receipt. NOT `examined == len(required_contexts())`: a MATRIX job reports one context
    # per combination while being one job, so the count collapses. Pinned rather than derived so that a
    # change in the collapse — a matrix split, or a context that quietly stops resolving — forces a
    # look here instead of passing on a self-consistent count.
    #
    # 8/6 since 2026-09-16, when the owner removed the seven original `security.yml` scan contexts from
    # branch protection (consolidation step 4, taken BEFORE step 3; docs/CI.md). It was 15/13 from
    # 2026-09-15, when the owner added the two composite roll-ups (step 2); 13/11 from 2026-09-04, when
    # the owner retired the review requirement and `a reviewer has read this` came off branch
    # protection; 14/12 from 2026-08-31 (BACKLOG #1404), when that context was armed; and 13/11 before
    # that. One collapse throughout: ci.yml's `test` matrix reports 3 contexts from 1 job, so 8 - 2 = 6.
    #
    # 8/6 IS THE FIGURE THE PREVIOUS COMMENT PREDICTED, and it arrived by the other half of the change.
    # That comment read "THE COUNT WILL DROP TO 8/6 AT CONSOLIDATION STEP 3, when the seven original
    # scan jobs are deleted and their contexts come off protection" -- it assumed the deletion and the
    # protection edit would land together. Only the protection edit landed. The count is the same
    # either way, because a deleted job and a job whose context is no longer required are both absent
    # from `_required_jobs()`; but the seven jobs are still in the workflow, still running, and still
    # graded by this module under `_SUPERSEDED_SECURITY_JOBS`. A predicted number arriving for an
    # unpredicted reason is worth the note: the pin cannot tell those two states apart, and the
    # classification is what does.
    #
    # THIS MODULE READS THE CANONICAL FILE, NOT THE SERVER, so a context that reaches protection and
    # not the file is not examined here. That file's own header states the ordering rule -- protection
    # first, the file in the same pull request -- and this pin is only as live as that discipline. Read
    # at 2026-08-31 20:57 CDT the two were SET-EQUAL. The 2026-09-04 removal followed the same order:
    #   gh api repos/MEFORORG/MessageFoundry/branches/main/protection --jq '.required_status_checks.contexts[]'
    # returned thirteen contexts with `a reviewer has read this` absent, and the canonical file drops
    # the same line in this pull request.
    #
    # RECORDING a context drags its job under every rule in this module for the first time, exactly as
    # backlog-hygiene did on 2026-07-29 -- and it paid immediately here: on 2026-08-31 the review-gate
    # job's `|| true` surfaced on the first CI run after that context was recorded. That is why the
    # finding is kept although its subject is gone: the mechanism belongs to RECORDING A CONTEXT, not
    # to review-gate.yml, and it fires again for whatever context is recorded next. The gate itself is
    # retired and the workflow deleted, so nothing here examines it any more.
    print(
        f"[security-posture] examined {examined} distinct jobs backing "
        f"{len(required_contexts())} required contexts"
    )
    assert examined == 6, (
        f"expected the {len(required_contexts())} required contexts to resolve to 6 distinct jobs "
        f"(the 3 `test` legs share one matrix job); got {examined}. If the workflow layout genuinely "
        "changed, update this count."
    )
    assert not offenders, (
        "a REQUIRED status check cannot fail, so it gates nothing:\n  "
        + "\n  ".join(offenders)
        + "\nGitHub reports a continue-on-error job as SUCCESS, so branch protection stays green while "
        "the scanner's findings are discarded. To take a gate off the merge path, remove its context "
        "from branch protection and .github/required-contexts.txt — do not neuter it in place."
    )


def test_required_jobs_have_no_neutered_steps() -> None:
    """`|| true` / `--exit-zero` discard the exit code without touching continue-on-error.

    This is how mutation testing spent months reporting success in 37 seconds while measuring nothing
    (docs/CI.md, 'Gate liveness'). The same one-token edit inside a required security job would be
    invisible.
    """
    offenders: list[str] = []
    scanned_steps = 0
    for (wf, key), job in _required_jobs().items():
        for step in job.get("steps") or []:
            run = str((step or {}).get("run") or "")
            if not run:
                continue
            scanned_steps += 1
            # Per LINE, against the gating text only — see _gating_text for why a whole-body scan
            # reported two false positives, each of which would have been "fixed" by deleting a
            # correct guard or a rationale comment.
            for raw_line in run.splitlines():
                gating = _gating_text(raw_line)
                for pattern, label in _NEUTERING:
                    if pattern.search(gating):
                        name = (step or {}).get("name") or "<unnamed step>"
                        offenders.append(
                            f"{wf}:{key} — step {name!r} contains {label}: {raw_line.strip()!r}"
                        )
    print(f"[security-posture] scanned {scanned_steps} run steps across required jobs")
    assert scanned_steps > 0, "scanned ZERO run steps — the parser stopped seeing steps, not a pass"
    assert not offenders, (
        "a required job discards a non-zero exit code:\n  "
        + "\n  ".join(offenders)
        + "\nIf a specific command legitimately tolerates failure (log tailing, best-effort cleanup), "
        "confine it to its own step so the GATING command's exit code is still the step's."
    )


def test_required_jobs_declare_no_skippable_job_level_if() -> None:
    """A job-level `if:` is the other way a required context silently never reports."""
    offenders: list[str] = []
    for (wf, key), job in _required_jobs().items():
        expr = job.get("if")
        if expr is None:
            continue
        allowed = _JOB_IF_ALLOWLIST.get((wf, key))
        if allowed is None or str(expr).strip() != allowed:
            offenders.append(f"{wf}:{key} — if: {str(expr).strip()!r} (allowlisted: {allowed!r})")
    assert not offenders, (
        "a required job carries an unreviewed job-level `if:`:\n  "
        + "\n  ".join(offenders)
        + "\nAn `if:` that evaluates false SKIPS the job, and a required context that does not report "
        "blocks the PR forever. Gate the expensive STEPS instead — that is what ci.yml's `test` leg "
        "does with `needs: changes`, keeping the context present and green on a docs-only PR. If the "
        "expression genuinely cannot skip a pull_request run, add it to _JOB_IF_ALLOWLIST with the "
        "reason."
    )


# --- the header must not become a second definition of the trigger set (BACKLOG #1079) ------------
#
# A workflow's triggers are defined once, by its `on:` block. `security.yml`'s header carried a second
# description of them, and the two disagreed: the header denied a push-to-main trigger that the `on:`
# block declared ten lines beneath it. CI behaved as the `on:` block said, so nothing was broken --
# what was damaged is the header's credibility, and the rest of that header is load-bearing (it is
# where the continue-on-error trap is documented, the very trap the tests above enforce).
#
# SCOPE, STATED PLAINLY: this catches a DENIAL adjacent to a declared event name -- the shape that
# actually occurred -- and nothing subtler. No regex can decide whether a paragraph of English
# contradicts a YAML block, so this is a tripwire on the known shape, not a proof of consistency. The
# durable rule is the header's own: it defines no triggers at all. _HISTORICAL_DENIAL below is a LIVE
# positive control, kept verbatim so the detector is re-proved able to fire on every run rather than
# being trusted to.
#
# ONE THING TO EXPECT AND NOT MISREAD, since 2026-09-08: the push-to-main arm really was removed, so
# _HISTORICAL_DENIAL's claim is now TRUE of the `on:` block and the detector would still red a header
# that made it. That is not a bug in the tripwire. The rule being enforced is not "the header must be
# accurate about the triggers", it is "the header must not describe them at all" -- an accurate second
# definition is still a second definition, and it is free to go stale the next time the first one
# moves. This exact arm moving twice is the argument, not a counterexample to it.
#: `merge_group` was missing from this list until the required-set tripwire below was built, and it
#: is the arm with the worst consequence: security.yml's `on:` block marks it DO NOT REMOVE, because
#: a required context whose workflow lacks it never reports on a queue entry and NOTHING merges. A
#: header paragraph denying that arm was the one shape this detector could not see.
_HEADER_DENIAL = re.compile(
    r"\bno\s+(pull_request|push|schedule|cron|workflow_dispatch|merge_group)\b", re.I
)

#: POSITIVE CONTROLS. The first is the verbatim historical claim. The second is CONSTRUCTED, not
#: historical, and is labelled so rather than being passed off as a second sighting: it exercises the
#: line-wrap path that `_prose` added to this detector, which the one-line historical control cannot
#: reach. Without it, reverting `_prose` to a no-op would leave this test passing its control while
#: silently losing the coverage that change exists for.
_HISTORICAL_DENIAL = "# NO push-to-main trigger (dropped for CI cost): every push to main is an"
_CONSTRUCTED_WRAPPED_DENIAL = "# this workflow declares no\n# merge_group trigger at all"


def _block_above(text: str, key: str) -> str:
    """Every line of ``text`` above the first line that is exactly ``key`` at column 0.

    Located by CONSTRUCT, never by line number: security.yml's comment blocks are edited repeatedly
    and any anchor into them would be stale within a release. One helper rather than one per key, so
    a later fix to the locator cannot be made to one caller and missed on the other.
    """
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.rstrip() == key:
            return "\n".join(lines[:i])
    raise AssertionError(
        f"no `{key}` line at column 0 in the workflow passed -- that block cannot be located"
    )


def _header_block(text: str) -> str:
    """Every line of the workflow before the `on:` key -- the header comment block."""
    return _block_above(text, "on:")


def _declared_events(name: str) -> set[str]:
    """The event keys of a workflow's `on:` block.

    YAML 1.1 resolves the bare key `on` to the BOOLEAN True, so `wf["on"]` is a KeyError and a lookup
    that quietly returns nothing would make every assertion below vacuous. Both keys are tried, and an
    empty result is an error rather than a pass.
    """
    wf = load_workflow(name)
    block = wf.get("on", wf.get(True))
    assert isinstance(block, dict) and block, f"{name}: could not read its `on:` block ({block!r})"
    return {str(k) for k in block}


def test_the_security_header_does_not_contradict_its_own_triggers() -> None:
    """The header must not deny a trigger the `on:` block declares.

    Non-vacuous three ways: the header block is located by construct and asserted substantial, the
    event set is read from the parsed `on:` block and asserted non-empty, and the detector is fired
    against the historical text in the same run.
    """
    events = _declared_events(_SECURITY)
    # POSITIVE CONTROL ON THE EVENT READ, re-derived 2026-09-08. It pinned `push` until the
    # post-merge `push: branches: [main]` arm was removed as a re-scan of the tree its own
    # merge_group run had just gated -- the merge-queue move the previous wording anticipated. It is
    # re-pointed at `merge_group` and NOT deleted, because its job is to prove `_declared_events`
    # returned a real parse of a real `on:` block: without it a locator or YAML-key failure would
    # make the denial assertion below pass over an empty set. `merge_group` is the strongest anchor
    # available now -- security.yml's own `on:` block marks it DO NOT REMOVE, since a required
    # context that stops reporting in the queue stops all merging.
    assert "merge_group" in events, (
        "security.yml no longer declares a `merge_group` trigger. Read that as a merge-blocking "
        "regression FIRST -- its jobs are required contexts, and a required context whose workflow "
        "has no merge_group arm never reports on the queue commit. If the trigger set was moved "
        "deliberately, re-derive this control against a trigger the file still declares rather than "
        "deleting it, or the header is free to drift again in the other direction."
    )

    header = _header_block((WORKFLOWS / _SECURITY).read_text(encoding="utf-8"))
    assert len(header.splitlines()) > 10, (
        f"security.yml's header block came back as {len(header.splitlines())} lines. That is a "
        "locator failure, not a small header -- this assertion would otherwise pass over nothing."
    )

    # LIVE POSITIVE CONTROL: the detector must still fire on the text this test was written for. An
    # absence claim below is evidence only because this line proves the instrument is not blind.
    for control in (_HISTORICAL_DENIAL, _CONSTRUCTED_WRAPPED_DENIAL):
        assert _HEADER_DENIAL.search(_prose(control)), (
            "the header-denial detector no longer matches a claim it was built for, so its silence "
            f"on the current header proves nothing. Fix the pattern, not this assertion:\n{control}"
        )

    # `_prose` rather than the raw header, added with the required-set tripwire below and for the
    # blind spot measured there: a denial wrapped across two comment lines ("there is" / "# no push
    # trigger") is one sentence to a reader and unmatchable to a line-anchored pattern. The shape
    # this detector exists for can wrap exactly like the one that did.
    found = _HEADER_DENIAL.search(_prose(header))
    assert found is None, (
        f"security.yml's header denies the {found.group(1)!r} trigger its own `on:` block declares "
        f"(events: {sorted(events)}). Two descriptions of the trigger set, free to disagree -- and "
        "the header is where the continue-on-error trap is documented, so a paragraph a reader can "
        "check and find false costs the whole block its credibility. DELETE the header claim; do not "
        "soften it. The `on:` block is the single definition."
    )


# --- the preamble must not become a second definition of the REQUIRED SET (BACKLOG #1705) ---------
#
# Same defect as the trigger tripwire above, one field over. The required set is defined once, by
# branch protection, and mirrored once, in `.github/required-contexts.txt`. `security.yml`'s preamble
# carried a second copy in two places -- the header said every job here except `sbom` and `trivy`
# gated a merge, and the timeout-reasoning block said the file owned a numbered share of the required
# contexts.
#
# HOW LONG EACH SURVIVED, because the two numbers say different things and averaging them would lose
# the sharper one. The MEMBERSHIP claim landed in f4ed79572 (2026-07-29) and died on 2026-09-16: two
# months. The SIZE claim -- "SEVEN of the thirteen" -- landed in cb309b4e5 (2026-09-09) and was
# already false on 2026-09-14, when the set went to fifteen: about FIVE DAYS, and it died one
# protection move earlier than the membership claim did. A claim carrying a number rots faster than
# one carrying a rule, which is the argument for refusing the shape rather than correcting it.
#
# WHAT MAKES THIS WORTH A TRIPWIRE RATHER THAN A CORRECTION IS HOW THEY DIED: with no edit to this
# workflow at all. Branch protection moved and every word in the preamble stayed as it was, so
# nothing in the file's own history marks the day either went false. A guard whose trigger is
# somebody editing the claim cannot see that; refusing the SHAPE can, because the shape is what a
# future editor would reach for.
#
# WHY IT IS NOT A CORRECTED ENUMERATION. A right answer here is still a second definition, free to go
# stale the next time the first one moves -- the argument `test_the_security_header_does_not_
# contradict_its_own_triggers` makes about an accurate trigger paragraph, unchanged. The required set
# has moved repeatedly, so this is the field where that argument is strongest.
#
# SCOPE, STATED PLAINLY: the PREAMBLE only -- everything above the `jobs:` key. Job bodies below it
# say "this is a REQUIRED context" in several places and are not in scope here: they are per-job
# rather than an enumeration, and MOST of them sit in a scan body that
# `tests/test_security_composite_parity.py` holds byte-identical between an original job and its
# composite copy, where the claim is TRUE. That is "most", not "every" -- parity compares `run:`
# strings, so a job-level comment above `steps:` is held by nothing, and the change that added this
# guard found SEVEN such comments labelled "BLOCKING" on jobs that gate nothing and relabelled them
# HARD-FAILING. Consolidation step 3 deletes the originals and takes the copies with them. Like the
# trigger tripwire, this catches known shapes and is not a proof of consistency about English.
_NUMBER_WORD = (
    r"\d+|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|"
    r"fifteen|sixteen|seventeen|eighteen|nineteen|twenty"
)
_GRADED_JOB_NAMES = "|".join(re.escape(job) for job in sorted(_ALL_GRADED_SECURITY_JOBS))
_PREAMBLE_REQUIRED_SET_CLAIM = re.compile(
    # "Every job here except `sbom` and `trivy` is a REQUIRED context" -- a membership enumeration.
    # `[^.]` cannot cross a sentence boundary, and `_prose` below makes a paragraph break one too, so
    # the window cannot wander out of the sentence that was actually written.
    r"\b(?:every|each|all)\s+(?:of\s+the\s+)?jobs?\b[^.]{0,120}?\brequired\s+(?:status\s+)?"
    r"(?:contexts?|checks?)\b"
    # "SEVEN of the thirteen required contexts", "two of the jobs here are required status checks",
    # "the seven required jobs here" -- a size claim. The gap after `of` is a bounded run rather than
    # one word: "two OF THE JOBS IN THIS FILE ARE required status checks" is the same claim.
    rf"|\b(?:{_NUMBER_WORD})\s+(?:of\s+[^.]{{0,40}}?)?required\s+(?:status\s+)?"
    r"(?:contexts?|checks?|jobs?)\b"
    # "bandit, semgrep and gitleaks are required contexts", and the same claim written the other way
    # round -- enumeration by NAMING, which is the form an editor told "do not write a corrected
    # enumeration" reaches for next. BOTH directions, because only testing one is how a detector
    # comes to cover the phrasing its author happened to imagine. Built from the posture buckets
    # rather than a literal list, so a job added to this workflow is covered the day it is classified
    # instead of the day somebody remembers this pattern.
    rf"|\b(?:{_GRADED_JOB_NAMES})\b[^.]{{0,80}}?"
    r"\brequired\s+(?:status\s+)?(?:contexts?|checks?)\b"
    rf"|\brequired\s+(?:status\s+)?(?:contexts?|checks?)\b[^.]{{0,80}}?\b(?:{_GRADED_JOB_NAMES})\b",
    re.IGNORECASE,
)

#: LIVE POSITIVE CONTROLS, verbatim from the text this guard was built against, comment markers and
#: line wraps included -- a claim wrapped across two comment lines is the shape that actually
#: occurred, so the detector has to be proved able to cross one. The retired wording lives HERE
#: rather than being quoted back in the workflow, because quoting it there would trip the guard.
_HISTORICAL_REQUIRED_SET_CLAIMS = (
    "#   READ THAT LAST SENTENCE AS A TRAP, not a procedure. Every job here except `sbom` and "
    "`trivy` is a\n#   REQUIRED context, and GitHub reports a continue-on-error job as SUCCESS",
    "# WORST CASE: it owns SEVEN of the thirteen required contexts, so a hang here does not merely",
    "# these are roughly 3x the observed steady state, rounded up, with a floor of 10 minutes -- the "
    "seven\n# required jobs here run 7 to 79 SECONDS each",
)


def _preamble_block(text: str) -> str:
    """Every line of the workflow above the `jobs:` key.

    Wider than ``_header_block`` on purpose -- the second stale enumeration sat in the
    timeout-reasoning block, which is below `on:` and above `jobs:`.
    """
    return _block_above(text, "jobs:")


def _prose(text: str) -> str:
    """Comment text as flat prose: `#` markers dropped, non-comment lines and blank comment lines
    turned into sentence boundaries, runs of whitespace collapsed.

    TWO FAILURES THIS EXISTS FOR, and they pull opposite ways. A claim wrapped across two comment
    lines reads as one sentence to a human and as ``...the seven\\n# required jobs...`` to a regex,
    so a line-anchored detector misses the very text it was written for -- measured here, on the
    third positive control above, before this helper existed. Flattening fixes that and creates the
    opposite hazard: with every newline gone, a bounded window can splice two unrelated paragraphs
    (or a paragraph and the YAML beneath it) into a sentence nobody wrote, and the failure message
    then quotes the author text they did not write. So a blank comment line and any non-comment line
    become a ``.``, which every pattern above already treats as a hard stop.

    THAT BOUNDS PARAGRAPH AND YAML SPLICES, NOT EVERY SPLICE. Two adjacent non-blank comment lines
    are joined, which is the whole point for a wrapped sentence and means adjacent list items are
    joined too. Claimed narrowly on purpose: the guard is a known-shape tripwire, and a docstring
    promising more than the code does is the defect this module keeps finding elsewhere.
    """
    out: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("#"):
            out.append(".")  # YAML, not prose -- a boundary, never spliced into a sentence.
            continue
        body = re.sub(r"^\s*#\s?", "", line)
        out.append(body if body.strip() else ".")
    return re.sub(r"\s+", " ", " ".join(out))


#: No trailing `\b`: this repository routinely writes `2026-09-16T18:45Z`, and requiring a word
#: boundary after the day would read that as undated and red a record carrying the very date the
#: failure message asks for.
_DATE = re.compile(r"\b20\d\d-\d\d-\d\d")


def _undated_required_set_claims(prose: str) -> list[str]:
    """Required-set claims in ``prose`` whose own sentence carries no date.

    A DATED CLAIM IS ALLOWED, AND THAT IS THE RULE RATHER THAN A HOLE GRUDGINGLY LEFT IN ONE. The
    defect this guard exists for is a claim that went false with nothing marking the day -- the
    reader of a stale sentence had no way to know it had expired. A date is exactly what supplies
    that, so "on 2026-07-30 ten required contexts sat on disabled workflows" is a record and must not
    red this gate; a repository whose house style is dated history would work around a guard that
    refused them, which is worse than the guard not existing.

    THE COST IS NAMED RATHER THAN HIDDEN: "as of <date>, this file owns two of the eight required
    contexts" passes. It is still a second definition and it will still go stale. It will go stale
    VISIBLY, carrying the date it was true, which is the property the undated ones lacked. That is
    the whole of the trade.

    THE WINDOW IS THE PARAGRAPH, NOT THE SENTENCE, and that is a correction rather than a
    convenience. A period is not a sentence boundary in this prose: `.github/required-contexts.txt`
    carries two of them, and the FIRST version of this helper split on any period -- so a record
    reading "the owner moved protection on <date>; `.github/required-contexts.txt` then recorded
    seven required contexts" had its date cut off behind `contexts.txt` and was flagged as undated.
    That put this rule in direct collision with the pointer assertion below, which requires that
    filename in the same preamble. ``_prose`` emits paragraph and YAML breaks as a standalone ``.``
    token, which a filename's dots never are, so those are what bound the window.
    """
    paragraph_break = re.compile(r"(?:^|(?<= ))\.(?:$|(?= ))")
    bounds = [0, *(m.end() for m in paragraph_break.finditer(prose)), len(prose)]
    found: list[str] = []
    for match in _PREAMBLE_REQUIRED_SET_CLAIM.finditer(prose):
        start = max(b for b in bounds if b <= match.start())
        end = min(b for b in bounds if b >= match.end())
        if not _DATE.search(prose[start:end]):
            found.append(match.group(0))
    return found


def test_the_security_preamble_does_not_restate_the_required_set() -> None:
    """The preamble must name no required-set membership and no required-set size.

    Non-vacuous two ways: the preamble is located by construct and asserted substantial, and every
    historical claim is fired at the detector in the same run, so the absence claim below is evidence
    rather than a silence.

    THE POINTER ASSERTION IS A FLOOR AND IS SAID SO RATHER THAN OVERSOLD. It fails only if the
    preamble stops naming ``.github/required-contexts.txt`` ANYWHERE, and other paragraphs name that
    file for their own reasons -- so it would not catch someone deleting just the paragraph that
    answers "which of these jobs gates a merge". It is kept because the failure it does catch is real
    and cheap to hold; what it is not is a proof that the reader is still sent somewhere.
    """
    preamble = _preamble_block((WORKFLOWS / _SECURITY).read_text(encoding="utf-8"))
    assert len(preamble.splitlines()) > 20, (
        f"security.yml's preamble came back as {len(preamble.splitlines())} lines. That is a locator "
        "failure, not a short preamble -- this assertion would otherwise pass over nothing."
    )

    for control in _HISTORICAL_REQUIRED_SET_CLAIMS:
        assert _undated_required_set_claims(_prose(control)), (
            "the required-set detector no longer matches a claim it was built for, so its silence on "
            f"the current preamble proves nothing. Fix the pattern, not this assertion:\n{control}"
        )

    found = _undated_required_set_claims(_prose(preamble))
    assert not found, (
        f"security.yml's preamble states required-set membership or size again: {found}. "
        "Branch protection defines that set and .github/required-contexts.txt mirrors it; a copy "
        "here is a second definition that goes stale when the first one moves, with no edit to this "
        "file to mark the day (BACKLOG #1705). POINT AT THE CANONICAL FILE; do not write a corrected "
        "enumeration and do not write a count. If this is a dated historical record rather than a "
        "live claim, say the date in the same sentence -- that is what distinguishes the two."
    )

    assert "required-contexts.txt" in preamble, (
        "security.yml's preamble no longer points at .github/required-contexts.txt. Removing the "
        "stale enumeration is only half the fix -- a reader asking which of these jobs gates a merge "
        "still needs to be sent to the file that answers it."
    )


def test_the_downgrade_note_points_at_this_guard() -> None:
    """security.yml documents the downgrade. It must also say what will now refuse it.

    The note is accurate and worth keeping — but read alone it presents the edit as a supported
    operation, which is precisely how it would come to be applied to a required gate.
    """
    text = (WORKFLOWS / _SECURITY).read_text(encoding="utf-8")
    if "continue-on-error: true` back to its job" in text:
        assert "test_security_posture" in text, (
            "security.yml still describes adding `continue-on-error: true` to downgrade a gate without "
            "noting that tests/test_security_posture.py refuses it for any job in the required set. "
            "Point the reader at the guard, so the documented remedy and the enforced rule agree."
        )


# --- advisory posture that must sit on a STEP, never on the job ----------------------------------
#
# `security.yml`'s `trivy` job joined this registry on 2026-09-22 for the same defect one level
# worse: its JOB-level flag hid a failing scan, and nothing carried the finding out of the raw log.
# Its entry here replaces the job-level rule `test_advisory_security_jobs_keep_continue_on_error`
# used to apply to it. The paragraphs below were written for `fuzz.yml` and still hold for both.
#
# WHY A JOB IN ANOTHER FILE IS GRADED HERE. Everything above reads `jobs_of(_SECURITY)`, and the one
# sweep that crosses files -- `test_required_jobs_carry_no_continue_on_error` -- reaches only the jobs
# backing a REQUIRED context, which an advisory job by definition is not. Meanwhile `fuzz.yml`'s
# header and ADR 0191 both told the reader that this module refuses a job-level `continue-on-error`
# on that job. It did not. That is a compensating control resting on a false premise (CLAUDE.md
# section 11, SDS-3.7), and the repository has already paid for the underlying defect once in
# `freethread-smoke.yml`. The claim is made true here rather than deleted, because the property it
# asserts is worth holding.
#
# THE PROPERTY IS NOT THE REQUIRED-GATE ONE, so do not read the rules above onto it. A job-level
# `continue-on-error` on an advisory job wedges no merge -- nothing required sits behind it. What it
# does is rewrite EVERY step's failure to SUCCESS, checkout, install and the toolchain-version report
# included. The advisory posture is meant to soften exactly one thing: a fuzz result, which is a
# function of the time budget and the random seed rather than of the diff. Soften the job instead and
# a harness that never ran still reports that every target survived its budget -- the "a clean run
# and a run that never executed look identical" failure that harness exists to avoid.
#
# THE SECOND ARM IS NOT DECORATION. Asserting only the absence of a job-level flag would pass just as
# happily against a job with no steps, a renamed job key, or a file this module failed to parse. The
# softened-step list is read from the same parse and compared against a named expectation, so the
# test cannot pass while seeing nothing -- and it catches the opposite move too, an advisory job
# quietly losing its step-level flag and starting to fail for a reason nobody chose.

#: ``(workflow file, job key, the job's `name:` -- its status-check context -- and the one step name
#: that may carry ``continue-on-error``)``.
_STEP_ADVISORY_JOBS: tuple[tuple[str, str, str, str], ...] = (
    (
        "fuzz.yml",
        "parsers",
        "parser fuzzing (advisory)",
        "Fuzz the tolerant parsers (advisory - never gates)",
    ),
    (
        "security.yml",
        "trivy",
        "trivy (container image vulnerabilities)",
        "Scan the image (advisory - fixable HIGH/CRITICAL reported, never gates)",
    ),
)


def test_step_advisory_jobs_soften_only_their_named_step() -> None:
    """An advisory job must be advisory at the STEP level, never at the job level."""
    for workflow, key, job_name, soft_step in _STEP_ADVISORY_JOBS:
        jobs = jobs_of(workflow)
        assert key in jobs, (
            f"{workflow} declares no job {key!r} (it has: {sorted(jobs)}). Re-point this entry at "
            "the job that now carries the advisory posture -- a renamed key would otherwise leave "
            "this test grading nothing while still passing."
        )
        job = jobs[key]

        # The CONTEXT NAME, pinned because nothing else resolves it against a real job.
        # `_MUST_NOT_BE_REQUIRED` in tests/test_required_contexts.py is free text matched at one
        # place, so renaming this `name:` leaves that guard protecting a dead string while the job's
        # new context is free to be promoted into branch protection. Measured: of ten mutations to
        # this workflow, nine red this test and renaming `name:` was the one that survived.
        assert job.get("name") == job_name, (
            f"{workflow}:{key} reports context {job.get('name')!r}, not {job_name!r}. That string "
            "is what branch protection and _MUST_NOT_BE_REQUIRED match on, so a rename here "
            "silently decouples both from this job."
        )

        assert job.get("continue-on-error") in (None, False), (
            f"{workflow}:{key} carries a job-level `continue-on-error`. GitHub rewrites the job's "
            "conclusion to SUCCESS, so every step in it -- checkout, install, the toolchain-version "
            "report -- stops being able to report a failure, and a harness that broke before it ran "
            "still says it passed. Put the flag on the single step whose result is genuinely "
            "advisory, or take the job out of _STEP_ADVISORY_JOBS deliberately."
        )

        steps = job.get("steps") or []
        # `>= 1`, not `> 1`: the only thing this needs to exclude is an EMPTY list, which is the
        # parse failure that would make the assertion below pass over nothing. A job legitimately
        # refactored down to one step is not a fault, and blaming a parse error for it would send
        # the reader looking in the wrong place.
        assert len(steps) >= 1, (
            f"{workflow}:{key} parsed to no steps. Read that as a parse or locator failure -- the "
            "softened-step assertion below would otherwise pass over nothing."
        )
        softened = [
            (step or {}).get("name") or (step or {}).get("uses") or "<unnamed step>"
            for step in steps
            if (step or {}).get("continue-on-error") not in (None, False)
        ]
        assert softened == [soft_step], (
            f"{workflow}:{key} should soften exactly one step, {soft_step!r}; it softens {softened}. "
            "Softening a second step widens what the job is allowed to ignore. Softening none makes "
            "an advisory job blocking-shaped, which is the same move in the other direction: both "
            "have to be a deliberate edit to _STEP_ADVISORY_JOBS."
        )


# --- trivy: run the scan step and its reporter against each other, verbatim ----------------------
#
# The registry entry above pins WHERE `trivy`'s flag sits. These pin what the two steps DO: a
# substring check over the YAML would pass just as happily against a reporter reading a variable the
# scan step never writes. Trivy is replaced by a shell function defined ahead of the shipped body, so
# no scanner, image or network is needed; the function writes a canned table to the `--output` path
# the shipped command passes and exits with the code each case asks for.

_TRIVY_SCAN_PREFIX = "Scan the image"
_TRIVY_REPORT_PREFIX = "Report the scan"

_TRIVY_TABLE = (
    "messagefoundry:scan (debian 13)\nTotal: 1 (HIGH: 1, CRITICAL: 0)\nCVE-2099-0001 libfake\n"
)

# A stand-in for the real binary. It honours the two flags the hand-off relies on and nothing else:
# `--output <path>` is where the table goes, and `--exit-code <n>` is what a FINDING exits with, as
# in real Trivy. A fault exits 1, which is Trivy's own fatal-error code. So reverting the shipped
# command to `--exit-code 1` makes a finding indistinguishable from a fault, and these tests red.
_FAKE_TRIVY = r"""
trivy() {
  local out="" code="0"
  while [ "$#" -gt 0 ]; do
    if [ "$1" = "--output" ]; then out="$2"; shift; fi
    if [ "$1" = "--exit-code" ]; then code="$2"; shift; fi
    shift
  done
  if [ -n "${out}" ] && [ -n "${FAKE_TRIVY_TABLE:-}" ]; then
    printf '%s' "${FAKE_TRIVY_TABLE}" > "${out}"
  fi
  case "${FAKE_TRIVY_MODE}" in
    clean) return 0 ;;
    finding) return "${code}" ;;
    *) return 1 ;;
  esac
}
"""


def _trivy_step_body(prefix: str) -> str:
    """The shipped ``run:`` body of the one trivy step whose name starts with ``prefix``.

    Refuses a body with an Actions expression in it: Actions substitutes ``${{ }}`` before bash sees
    it, so running such a body here would no longer be running what CI runs.
    """
    steps = jobs_of("security.yml")["trivy"].get("steps") or []
    named = [s for s in steps if str((s or {}).get("name", "")).startswith(prefix)]
    assert len(named) == 1, f"expected one trivy step named {prefix!r}, found {len(named)}"
    body = str(named[0].get("run", ""))
    assert body, f"trivy step {prefix!r} has an empty run body"
    assert "${{" not in body, f"trivy step {prefix!r} interpolates an Actions expression"
    return body


def _run_trivy_step(tmp_path: Path, name: str, script: str, env_extra: dict[str, str]) -> int:
    bash = require_bash(tmp_path)
    path = tmp_path / f"{name}.sh"
    path.write_text(script, encoding="utf-8", newline="\n")
    env = probe_env(Path(bash), dict(os.environ))
    env.update(env_extra)
    proc = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, no shell, test-local paths
        [bash, path.as_posix()],
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
        check=False,
    )
    assert proc.returncode not in CANNOT_RUN_CODES, explain_returncode(proc.returncode, name)
    return proc.returncode


def _read_github_env(path: Path) -> dict[str, str]:
    pairs = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        key, _, value = line.partition("=")
        pairs[key] = value
    return pairs


def _scan_then_report(
    tmp_path: Path, mode: str, table: str = _TRIVY_TABLE, scan_prelude: str = ""
) -> tuple[int, int, str]:
    """Run the scan step, carry its ``$GITHUB_ENV`` into the reporter, return both exits + summary."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    runner_temp = tmp_path / "runner-temp"
    runner_temp.mkdir()
    github_env = tmp_path / "github_env"
    github_env.write_text("", encoding="utf-8")
    summary = tmp_path / "summary.md"
    summary.write_text("", encoding="utf-8")

    scan_code = _run_trivy_step(
        tmp_path,
        "scan",
        _FAKE_TRIVY + scan_prelude + _trivy_step_body(_TRIVY_SCAN_PREFIX),
        {
            "RUNNER_TEMP": runner_temp.as_posix(),
            "GITHUB_ENV": github_env.as_posix(),
            "FAKE_TRIVY_MODE": mode,
            "FAKE_TRIVY_TABLE": table,
        },
    )
    handed_on = _read_github_env(github_env)
    report_code = _run_trivy_step(
        tmp_path,
        "report",
        _trivy_step_body(_TRIVY_REPORT_PREFIX),
        {**handed_on, "GITHUB_STEP_SUMMARY": summary.as_posix()},
    )
    return scan_code, report_code, summary.read_text(encoding="utf-8")


def test_a_finding_reaches_the_summary_and_leaves_the_job_green(tmp_path: Path) -> None:
    scan_code, report_code, summary = _scan_then_report(tmp_path, "finding")
    # The scan step still fails on its own record; `continue-on-error` is what keeps the job green.
    assert scan_code != 0
    assert report_code == 0, "a finding must not red this advisory job"
    assert "fixable HIGH/CRITICAL vulnerabilities" in summary
    assert "CVE-2099-0001" in summary, "the summary must carry the finding, not only announce it"


def test_a_clean_scan_says_so(tmp_path: Path) -> None:
    scan_code, report_code, summary = _scan_then_report(
        tmp_path, "clean", table="Total: 0 (HIGH: 0, CRITICAL: 0)\n"
    )
    assert (scan_code, report_code) == (0, 0)
    assert "no fixable HIGH/CRITICAL vulnerability" in summary


def test_a_scanner_fault_reds_the_job_and_claims_nothing(tmp_path: Path) -> None:
    """Trivy exits 1 on its own fatal errors. That is no verdict, and it must not read as a finding."""
    _, report_code, summary = _scan_then_report(tmp_path, "fault", table="")
    assert report_code != 0, "a scan that produced no verdict must red the job"
    assert "produced no verdict" in summary
    assert "no fixable" not in summary
    assert "fixable HIGH/CRITICAL vulnerabilities" not in summary


def test_a_scan_step_that_dies_early_is_not_reported_clean(tmp_path: Path) -> None:
    """The sentinel case. Kill the scan step before it writes anything; the reporter must not guess.

    `continue-on-error` rewrites that death to success, so without the sentinel the reporter would
    see no findings and write a clean result for a scan that never finished.
    """
    _, report_code, summary = _scan_then_report(tmp_path, "clean", scan_prelude="set -e\nfalse\n")
    assert report_code != 0
    assert "stopped before it recorded a result" in summary
    assert "no fixable" not in summary
