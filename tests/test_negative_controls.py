# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Every required merge context must have a negative control (BACKLOG #1000).

THE DEFECT THIS EXISTS FOR. The required contexts ARE the entire merge gate -- thirteen when this
was written, sixteen since 2026-08-31 (BACKLOG #1404) -- and, before this, not one of them was
proven able to go red. The class has fired at least four times here with no CI signal, each
found by hand: a required backlog gate computing a two-dot diff and crediting every PR with an older
base; a required SAST gate scanning a two-directory allow-list; a leak gate exiting 0 on content
carrying a real site code; the same gate matching one of four spellings of a Windows path. Each was
filed as its own defect, which is right. None of them established the property that would have caught
all four -- a green run is evidence only if the gate has been shown it can go red on that class.

THIS IS THE CI JOB THE ITEM ASKS FOR, and it deliberately is NOT a new workflow. Running the
reconciliation inside the ``test`` legs makes it BLOCKING today through contexts that are already
required, so it adds no new required context and needs no branch-protection change. A new advisory
workflow would have been weaker (advisory jobs do not stop auto-merge) and a new required one is an
owner decision that also has a live incident history: on 2026-07-29 protection was briefly cut to a
single required context with auto-merge armed and zero approvals, and PRs merged in that window.

THE INSTRUMENT HAS TO ANSWER THE QUESTION ASKED OF IT, and "it runs in CI" is not the same sentence as
"it runs on the pull request shape it exists for". ``ci.yml`` gates the ``test`` legs' expensive steps
on ``needs.changes.outputs.code == 'true'``, and that coupling is exactly how a #320 banner merged
without the suite ever compiling. The decay mode this registry targets is a context arriving in branch
protection and being mirrored into ``.github/required-contexts.txt`` -- so both that file and this
registry must classify as CODE, not docs. Measured, and then pinned: they are now two rows in
``tests/test_ci_docs_only_detector.py::test_code_paths_run_the_suite`` rather than a sentence here.

``.github/required-contexts.txt`` IS READ-ONLY TO THIS FILE. It mirrors the live server, and its own
header states the ordering rule -- branch protection first, then the file. Everything here only reads
it, so the registry can never be the reason a context looks required when it is not.

NOT VACUOUS BY CONSTRUCTION, which is the failure mode of every coverage register. The reconciliation
is driven by the LIVE required set rather than by the registry, so a context added to branch protection
and mirrored into that file arrives here with zero controls and fails -- rather than simply not being
looked at. ``test_the_reconciliation_fails_when_a_context_loses_its_control`` proves the gate can say so
by removing a control and watching it.
"""

from __future__ import annotations

from tests import _negative_controls as reg
from tests._workflow_contexts import required_contexts


def test_the_registry_covers_every_required_context() -> None:
    """THE GATE. It reports WHAT it scanned, not merely a count -- "no gaps" and "nothing was read"
    are otherwise the same green, which is the shape of half the defects this registry indexes."""
    problems, coverage = reg.reconcile()
    print(f"[#1000] reconciling {len(coverage)} required contexts against {reg.REGISTRY.name}")
    for ctx in sorted(coverage):
        print(f"[#1000]   {coverage[ctx]} control(s): {ctx}")
    assert coverage, (
        ".github/required-contexts.txt parsed to ZERO contexts, so this reconciliation compared "
        "nothing. That is a broken check, not a clean sweep."
    )
    assert not problems, "negative-control registry problems:\n  " + "\n  ".join(problems)


def test_every_required_context_is_covered_by_a_context_specific_control() -> None:
    """A universal control (`no required job carries continue-on-error`) is real and valuable, and it
    is NOT what this item asks for. It proves a gate cannot be switched off; it says nothing about
    whether the gate can see the violation it exists for. Each context needs at least one control
    planted at its own subject matter, which is what the per-context registry entries are."""
    _, coverage = reg.reconcile()
    uncovered = sorted(ctx for ctx, n in coverage.items() if n < 1)
    assert not uncovered, f"contexts with no control of their own: {uncovered}"


def test_the_registered_control_count_is_reported_and_has_not_collapsed() -> None:
    """A liveness floor. The registry shrinking is how this decays -- not by anyone deciding a gate no
    longer needs proving, but by a control being deleted alongside the test it names."""
    controls = reg.load()
    red = sum(len(c.red) for c in controls)
    green = sum(len(c.green) for c in controls)
    print(
        f"[#1000] {len(controls)} controls: {red} planted-violation nodes, {green} asymmetry nodes"
    )
    assert len(controls) >= len(required_contexts())
    assert red >= 20 and green >= 15, (
        f"the registry collapsed to {red} red / {green} green nodes. Raise this floor when it "
        "legitimately grows; never lower it to make the suite pass."
    )


# --- The gate's own negative controls. A gate that has never been red is a claim. -------------------


def _problems_for(controls: list[reg.Control]) -> list[str]:
    """Run the same rules over a synthetic control list, without touching the file on disk."""
    coverage = dict.fromkeys(required_contexts(), 0)
    problems: list[str] = []
    for control in controls:
        if control.context in coverage:
            coverage[control.context] += 1
    problems.extend(
        f"required context {ctx!r} has NO negative control" for ctx, n in coverage.items() if n == 0
    )
    problems.extend(f"dangling control node: {m}" for m in reg.unresolved_nodes(controls))
    return problems


def test_the_reconciliation_fails_when_a_context_loses_its_control() -> None:
    """PLANTED: the `gitleaks (secret scan)` entry is dropped. The gate must name that context.

    Without this, "every context is covered" and "the reconciliation compares nothing" produce the
    same green -- which is the defect this whole registry exists to make visible, occurring inside the
    verification of its own fix.
    """
    controls = [c for c in reg.load() if c.context != "gitleaks (secret scan)"]
    problems = _problems_for(controls)
    assert any("gitleaks (secret scan)" in p for p in problems), problems
    print(f"[#1000] negative control: dropping one entry produced {len(problems)} problem(s)")


def test_the_reconciliation_stays_green_on_the_shipped_registry() -> None:
    """THE ASYMMETRY. A reconciliation that reported a problem for everything would satisfy the test
    above while being useless, and the two are indistinguishable from a red alone."""
    assert _problems_for(reg.load()) == []


def test_the_node_resolver_reports_a_test_that_does_not_exist() -> None:
    """PLANTED: a control naming a test function nobody wrote, and one naming a missing file.

    A registry of dangling node ids satisfies every count-based assertion above. Both spellings of the
    failure are planted because they take different branches of the resolver, and a resolver that only
    caught the missing FILE would pass a renamed TEST -- which is the likelier accident.
    """
    ghost = reg.Control(
        context="CI gate",
        plants="x" * 50,
        holds="x" * 50,
        observed="x" * 50,
        red=("tests/test_merge_gate_controls.py::test_this_function_does_not_exist",),
        green=("tests/test_no_such_file_at_all.py::test_whatever",),
        ci=None,
        workflow=None,
    )
    missing = reg.unresolved_nodes([ghost])
    assert len(missing) == 2, missing
    assert any("no test function of that name" in m for m in missing), missing
    assert any("no such file" in m for m in missing), missing
    # ...and it stays silent on the real ones, so the assertion above is about the ghost.
    assert reg.unresolved_nodes(reg.load()) == []


def test_the_ci_wiring_check_reports_a_command_nobody_invokes() -> None:
    """PLANTED: a `ci` control naming a command that appears in no step of the workflow it claims.

    This is the quiet way a fixture-based control dies: the asserter script stays in the tree, the
    registry keeps pointing at it, and the step that ran it is deleted. Nothing else here would notice.
    """
    orphan = reg.Control(
        context="semgrep (project SAST rules)",
        plants="x" * 50,
        holds="x" * 50,
        observed="x" * 50,
        red=(),
        green=(),
        ci="python scripts/ci/this_asserter_is_not_wired.py",
        workflow="security.yml",
    )
    assert reg.unwired_ci_commands([orphan]), "the wiring check cannot see an uninvoked command"
    assert reg.unwired_ci_commands(reg.load()) == [], "a shipped ci control is not actually wired"
