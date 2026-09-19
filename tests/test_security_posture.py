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

import re

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
# first, to names nothing yet reports, wedges it identically. The workflow header carries the four
# steps in order.
#
# THE BUCKET IS EMPTY AS OF 2026-09-15 and the mechanism is kept for the next staged job. The owner
# added both composite contexts to branch protection, a pull request recorded them in
# .github/required-contexts.txt, and the same pull request moved both names into
# _BLOCKING_SECURITY_JOBS above -- which drags them under every rule in this module for the first
# time. `test_pending_promotion_jobs_are_not_recorded_as_required` below is the forcing function that
# made those two halves one change, and it is what reddened when only the file was edited.
#
# WHAT IT DID NOT FORCE, AND MUST NOT: deleting the seven original jobs. Its failure message used to
# name that as part of the same change, which is wrong and would wedge the repository -- protection
# still requires all seven ORIGINAL contexts alongside the composites, so deleting their jobs leaves
# seven required contexts nothing can report. That is consolidation steps 3 and 4, it needs a branch
# protection edit in the same window, and docs/CI.md carries the ordering hazard.
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
    classified = (
        _BLOCKING_SECURITY_JOBS
        | _ADVISORY_SECURITY_JOBS
        | _ADVISORY_BY_PLACEMENT_SECURITY_JOBS
        | _SUPERSEDED_SECURITY_JOBS
        | _PENDING_PROMOTION_SECURITY_JOBS
    )
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
    for key in sorted(_ADVISORY_SECURITY_JOBS):
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
_HEADER_DENIAL = re.compile(r"\bno\s+(pull_request|push|schedule|cron|workflow_dispatch)\b", re.I)
_HISTORICAL_DENIAL = "# NO push-to-main trigger (dropped for CI cost): every push to main is an"


def _header_block(text: str) -> str:
    """Every line of the workflow before the `on:` key -- the header comment block.

    Located by CONSTRUCT (the first line that is exactly `on:` at column 0), never by line number:
    this header has been edited repeatedly and any anchor into it would be stale within a release.
    """
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.rstrip() == "on:":
            return "\n".join(lines[:i])
    raise AssertionError(
        "security.yml has no `on:` key at column 0 -- the header cannot be located"
    )


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
    assert _HEADER_DENIAL.search(_HISTORICAL_DENIAL), (
        "the header-denial detector no longer matches the historical claim it was built for, so its "
        "silence on the current header proves nothing. Fix the pattern, not this assertion."
    )

    found = _HEADER_DENIAL.search(header)
    assert found is None, (
        f"security.yml's header denies the {found.group(1)!r} trigger its own `on:` block declares "
        f"(events: {sorted(events)}). Two descriptions of the trigger set, free to disagree -- and "
        "the header is where the continue-on-error trap is documented, so a paragraph a reader can "
        "check and find false costs the whole block its credibility. DELETE the header claim; do not "
        "soften it. The `on:` block is the single definition."
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
