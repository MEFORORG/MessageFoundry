# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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
    required_contexts,
    resolve,
)

_SECURITY = "security.yml"

# BLOCKING: a finding here must fail the build. Each of these job names is asserted to be in
# .github/required-contexts.txt below, so "blocking" is a checked claim rather than a label.
_BLOCKING_SECURITY_JOBS = frozenset(
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
        _BLOCKING_SECURITY_JOBS | _ADVISORY_SECURITY_JOBS | _ADVISORY_BY_PLACEMENT_SECURITY_JOBS
    )
    print(f"[security-posture] classified {len(classified)} of {len(actual)} jobs in {_SECURITY}")
    assert actual == classified, (
        f"security.yml jobs are not all classified.\n"
        f"  unclassified (add to _BLOCKING_SECURITY_JOBS, _ADVISORY_SECURITY_JOBS or "
        f"_ADVISORY_BY_PLACEMENT_SECURITY_JOBS): "
        f"{sorted(actual - classified)}\n"
        f"  named here but gone from the workflow: {sorted(classified - actual)}"
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
    # Liveness receipt. NOT `examined == len(required_contexts())`: the three `test (<os>, py3.14)`
    # contexts are ONE matrix job, so 13 contexts collapse to 11 jobs. Pinned rather than derived so
    # that a change in the collapse — a matrix split, or a context that quietly stops resolving —
    # forces a look here instead of passing on a self-consistent count.
    #
    # 13/11 since 2026-07-29, when backlog-hygiene was promoted to a required context. Promoting one
    # brings its job under every rule in this module for the first time, which is the point: it
    # immediately surfaced a `|| true` in that job (a false positive, as it turned out — see
    # _gating_text — but the review it forced is exactly what promotion should trigger).
    print(
        f"[security-posture] examined {examined} distinct jobs backing "
        f"{len(required_contexts())} required contexts"
    )
    assert examined == 11, (
        f"expected the 13 required contexts to resolve to 11 distinct jobs (the 3 `test` legs share one "
        f"matrix job); got {examined}. If the workflow layout genuinely changed, update this count."
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
