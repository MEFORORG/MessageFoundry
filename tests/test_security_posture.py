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
    classified = _BLOCKING_SECURITY_JOBS | _ADVISORY_SECURITY_JOBS
    print(f"[security-posture] classified {len(classified)} of {len(actual)} jobs in {_SECURITY}")
    assert actual == classified, (
        f"security.yml jobs are not all classified.\n"
        f"  unclassified (add to _BLOCKING_SECURITY_JOBS or _ADVISORY_SECURITY_JOBS): "
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
    # contexts are ONE matrix job, so 12 contexts collapse to 10 jobs. Pinned rather than derived so
    # that a change in the collapse — a matrix split, or a context that quietly stops resolving —
    # forces a look here instead of passing on a self-consistent count.
    print(
        f"[security-posture] examined {examined} distinct jobs backing "
        f"{len(required_contexts())} required contexts"
    )
    assert examined == 10, (
        f"expected the 12 required contexts to resolve to 10 distinct jobs (the 3 `test` legs share one "
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
            for pattern, label in _NEUTERING:
                if pattern.search(run):
                    name = (step or {}).get("name") or "<unnamed step>"
                    offenders.append(f"{wf}:{key} — step {name!r} contains {label}")
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
