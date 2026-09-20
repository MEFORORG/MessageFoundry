# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The composite security jobs must be byte-identical to the jobs they will replace.

WHY THERE ARE TWO COPIES AT ALL. ``security.yml`` ran SEVEN separate scan jobs, each acquiring its
own runner slot, and each of the seven was a required status context when this consolidation began.
Five of the seven finish inside 55 seconds, so seven slot acquisitions buy about four minutes of
scanning against a measured ceiling of 20 concurrent runners -- and healthy pull requests have been
evicted from the merge queue for want of one. Consolidating the seven into two composites removes
five acquisitions per run at no coverage cost.

A REQUIRED CONTEXT IS A JOB NAME, so the consolidation cannot be one edit. Deleting the seven jobs
while branch protection still names them wedges every pull request in the repository -- protection
waits forever for a context nothing produces -- and moving protection first, to names nothing yet
reports, wedges it the same way. So the composites land ALONGSIDE the originals, branch protection
moves, and only then are the originals deleted. ``security.yml`` carries the step list above the
composite jobs.

THE SEVEN NO LONGER GATE A MERGE, AND THIS MODULE IS WHAT MAKES THAT SAFE. The owner removed their
context names from branch protection on 2026-09-16, ahead of the deletion rather than after it, so
today the seven hard-fail and report on every pull request while a composite is what protection
reads. The claim carrying that posture is this module's: each composite's copy of a scan is
byte-identical to the original, so the scan that stopped gating is the same string as the one that
now gates. ``.github/required-contexts.txt`` is the record of which contexts protection holds, and
it is not restated here -- an in-repo copy of that set is what went stale in ``security.yml``'s own
header (BACKLOG #1705).

WHAT THIS MODULE IS FOR. During the overlap the file carries two copies of every scan, and a
duplicated gate is a gate free to drift: the copy that branch protection eventually reads could
quietly acquire a narrower corpus, a muted severity floor or a shallower history than the one every
other test in this repository grades. The assertions below make the duplication safe by making it
EXACT -- each composite step is compared to its original as a byte string. That is also the argument
that the overlap costs no review: every control this suite asserts about an original step is an
assertion about a string this module proves the copy shares, so nothing has to be re-derived against
the composite, and step 3 is a deletion rather than a rewrite.

THE OTHER HALF IS THAT NOTHING WAS DROPPED. Byte-identity of the steps that ARE present says nothing
about a step that is absent, and a composite silently missing one scan is the failure this whole
change could plausibly introduce. So the comparison runs in both directions over the set of
run-carrying step names, and the mapping below is asserted to name real jobs rather than being
trusted to.
"""

from __future__ import annotations

from typing import Any

from tests._workflow_contexts import jobs_of

_SECURITY = "security.yml"

#: composite job key -> the original job keys it consolidates.
#:
#: Keyed on the JOB KEY rather than the context string on purpose: the context is what branch
#: protection reads and is therefore the thing that must not move, while this mapping is about which
#: YAML block copied which. Step 3 deletes the values and empties this mapping; it does not edit the
#: keys.
_COMPOSITES: dict[str, tuple[str, ...]] = {
    "repo-scan": ("bandit", "semgrep", "crypto-inventory", "forbidden-content"),
    "dependency-and-secret-scan": ("pip-audit", "npm-audit", "gitleaks"),
}

#: `if:` expressions that let a step run after a SIBLING step has failed. Both are correct here and
#: neither discards anything: the step still fails, and a failed step still fails the job. The
#: default (`success()`) is what must not appear on a scan -- it turns a composite into a
#: stop-at-the-first-finding gate, so the second finding only surfaces after the first is fixed.
_SURVIVES_A_SIBLING_FAILURE = frozenset({"${{ !cancelled() }}", "!cancelled()", "always()"})


def _run_steps(job: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """The steps of ``job`` that carry a ``run:``, keyed by name.

    RAISES on a duplicate name rather than losing one. Two steps sharing a name inside one job would
    collapse here and the loser would sit outside every assertion below while the module reported
    green -- the shape ``_hooks()`` in tests/test_lint_scope_parity.py already refuses.
    """
    found: dict[str, dict[str, Any]] = {}
    for step in job.get("steps") or []:
        step = step or {}
        if "run" not in step:
            continue
        name = str(step.get("name") or "")
        assert name, f"a `run:` step in {job.get('name')!r} has no name, so it cannot be compared"
        assert name not in found, f"two steps named {name!r} in the same job"
        found[name] = step
    return found


def test_the_mapping_names_real_jobs() -> None:
    """Non-vacuity. A typo in either half would make every comparison below skip silently."""
    jobs = jobs_of(_SECURITY)
    missing = sorted(
        k for k in (*_COMPOSITES, *(j for v in _COMPOSITES.values() for j in v)) if k not in jobs
    )
    assert not missing, (
        f"_COMPOSITES names {missing}, which no longer exist in {_SECURITY}. If the originals were "
        "deleted, this is step 3 of the consolidation: empty the mapping in the same change and move "
        "the composite names in tests/test_security_posture.py into _BLOCKING_SECURITY_JOBS."
    )


def test_each_composite_carries_every_scan_of_every_job_it_consolidates() -> None:
    """Neither direction is optional. A missing scan and an extra one are different defects."""
    jobs = jobs_of(_SECURITY)
    compared = 0
    for composite, originals in sorted(_COMPOSITES.items()):
        expected: set[str] = set()
        for original in originals:
            expected |= set(_run_steps(jobs[original]))
        actual = set(_run_steps(jobs[composite]))
        assert expected, f"{originals} contribute no `run:` steps -- this comparison sees nothing"
        assert actual == expected, (
            f"{composite} does not run the same set of scans as {list(originals)}.\n"
            f"  in the originals, missing from the composite: {sorted(expected - actual)}\n"
            f"  in the composite, in none of the originals:   {sorted(actual - expected)}"
        )
        compared += len(expected)
    print(f"[composite-parity] compared {compared} scan steps across {len(_COMPOSITES)} composites")
    assert compared, "compared ZERO steps -- an empty comparison must not read as agreement"


def test_every_copied_scan_body_is_byte_identical_to_its_original() -> None:
    """The load-bearing assertion. Everything this suite proves about an original rides on it."""
    jobs = jobs_of(_SECURITY)
    drifted: list[str] = []
    for composite, originals in sorted(_COMPOSITES.items()):
        copies = _run_steps(jobs[composite])
        for original in originals:
            for name, step in _run_steps(jobs[original]).items():
                copy = copies.get(name)
                if copy is None:
                    continue  # the set comparison above owns this failure and reports it better
                if str(copy.get("run")) != str(step.get("run")):
                    drifted.append(f"{composite}:{name!r} differs from {original}:{name!r}")
    assert not drifted, (
        "a composite scan body has drifted from the original it copies:\n  "
        + "\n  ".join(drifted)
        + "\nThe copy is what branch protection will read after the originals are deleted, and every "
        "control this repository asserts about the original -- scan corpus, severity floor, history "
        "depth, fail-closed behaviour -- is an assertion about that string. Re-copy it verbatim; do "
        "not hand-merge the difference."
    )


def test_a_copied_step_keeps_the_working_directory_its_original_job_supplied() -> None:
    """``npm-audit`` sets ``defaults.run.working-directory``, which a composite does not inherit.

    ``npm audit --package-lock-only`` reads the lockfile in the CURRENT directory. Copying the body
    without the directory points it at the repository root, where there is no ``package-lock.json``
    -- and the failure is not obviously a scoping bug from the log.
    """
    jobs = jobs_of(_SECURITY)
    for composite, originals in sorted(_COMPOSITES.items()):
        copies = _run_steps(jobs[composite])
        for original in originals:
            job = jobs[original]
            inherited = ((job.get("defaults") or {}).get("run") or {}).get("working-directory")
            if not inherited:
                continue
            for name in _run_steps(job):
                copy = copies.get(name)
                assert copy is not None and copy.get("working-directory") == inherited, (
                    f"{composite}:{name!r} runs in "
                    f"{(copy or {}).get('working-directory')!r}, but {original} supplies "
                    f"{inherited!r} through its job defaults. A composite has no such default."
                )


def test_a_copied_checkout_is_at_least_as_deep_as_every_original_asked_for() -> None:
    """``gitleaks`` needs ``fetch-depth: 0``; its composite siblings do not care.

    A composite has ONE checkout, so the deepest requirement among its constituents governs. Losing
    it would reduce a secret gate to a single commit while the job went on reporting success -- the
    silent direction, which is why this is asserted rather than left to the workflow comment.
    """
    jobs = jobs_of(_SECURITY)
    for composite, originals in sorted(_COMPOSITES.items()):
        needed = {
            str(((s or {}).get("with") or {}).get("fetch-depth"))
            for original in originals
            for s in jobs[original].get("steps") or []
            if str((s or {}).get("uses", "")).startswith("actions/checkout@")
            and not ((s or {}).get("with") or {}).get("path")
        }
        if "0" not in needed:
            continue
        roots = [
            s
            for s in jobs[composite].get("steps") or []
            if str((s or {}).get("uses", "")).startswith("actions/checkout@")
            and not ((s or {}).get("with") or {}).get("path")
        ]
        assert roots, f"{composite} checks nothing out into the workspace root"
        depths = {str(((s or {}).get("with") or {}).get("fetch-depth")) for s in roots}
        assert depths == {"0"}, (
            f"{composite} consolidates a job that requires the full history, but its checkout "
            f"fetches depth {sorted(depths)}. A shallow clone would scan whatever happened to be "
            "fetched and still report success."
        )


def test_no_scan_in_a_composite_is_skipped_by_an_earlier_failure() -> None:
    """A composite that stops at the first finding is a worse gate than the jobs it replaces.

    Seven jobs report seven verdicts in one run. A composite whose steps carry the default
    ``if: success()`` reports the first failure and skips the rest, so the second finding appears
    only after the first is fixed -- one round trip per finding. Running them all hides nothing: a
    failed step still fails the job, which is the only thing branch protection reads.
    """
    jobs = jobs_of(_SECURITY)
    offenders: list[str] = []
    for composite in sorted(_COMPOSITES):
        for name, step in _run_steps(jobs[composite]).items():
            expr = str(step.get("if") or "").strip()
            if expr not in _SURVIVES_A_SIBLING_FAILURE:
                offenders.append(
                    f"{composite}:{name!r} -- if: {expr or '<the default, success()>'}"
                )
    assert not offenders, (
        "a scan in a composite job is skipped when an earlier scan fails:\n  "
        + "\n  ".join(offenders)
        + f"\nUse one of {sorted(_SURVIVES_A_SIBLING_FAILURE)}. NOT `continue-on-error`, which "
        "discards the finding instead of deferring it (tests/test_security_posture.py refuses it)."
    )
