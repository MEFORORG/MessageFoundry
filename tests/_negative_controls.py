# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Load and validate the negative-control registry (BACKLOG #1000).

Shared rather than inlined for the same reason ``_workflow_contexts`` is: this reconciliation is run
from pytest (so it blocks merge through the existing ``test`` contexts, adding no new required context)
and can be run standalone against a checkout. Two copies of the rule set would be free to disagree,
which is the class the registry exists to catch.

WHAT IT VALIDATES, and each rule is a decay mode that has actually happened somewhere in this repo:

* **Every required context has a control.** Otherwise a context added to branch protection tomorrow
  starts life unproven and nothing says so -- the decay mode that makes any one-off audit worthless.
* **Every registered context is required.** A control for a context nobody requires is effort spent
  guarding nothing, and it inflates the coverage count.
* **Node ids resolve.** A control naming a test that does not exist is a control that does not exist.
* **`red` and `green` are both non-empty.** The asymmetry is mandatory: a control that only reddens
  cannot tell you which layer does the work.
* **`ci` commands are wired into the job they claim.** A fixture asserter nobody invokes is a file.

WHAT THE NODE-ID CHECK DOES AND DOES NOT PROVE, stated because the instrument has to answer the
question asked of it. It resolves each id by parsing the named file and looking for a test function of
that name, so it proves the test EXISTS and is spelled right. It does not prove the test is collected
or that it passes -- that is what running the suite does, and every registered id lives under ``tests/``
precisely so the required ``test`` legs execute it.
"""

from __future__ import annotations

import ast
import tomllib
from dataclasses import dataclass
from pathlib import Path

from tests._workflow_contexts import ROOT, jobs_of, required_contexts

REGISTRY = Path(__file__).resolve().parent / "negative_controls.toml"

#: Prose fields that must carry a real explanation. Short enough to admit a terse one, long enough that
#: "n/a" and "TODO" do not pass -- the two ways a mandatory field becomes decoration.
_MIN_PROSE = 40


@dataclass(frozen=True)
class Control:
    context: str
    plants: str
    holds: str
    observed: str
    red: tuple[str, ...]
    green: tuple[str, ...]
    ci: str | None
    workflow: str | None


def load() -> list[Control]:
    raw = tomllib.loads(REGISTRY.read_text(encoding="utf-8"))
    controls = raw.get("control", [])
    return [
        Control(
            context=str(c.get("context", "")),
            plants=str(c.get("plants", "")).strip(),
            holds=str(c.get("holds", "")).strip(),
            observed=str(c.get("observed", "")).strip(),
            red=tuple(str(n) for n in c.get("red", [])),
            green=tuple(str(n) for n in c.get("green", [])),
            ci=str(c["ci"]) if "ci" in c else None,
            workflow=str(c["workflow"]) if "workflow" in c else None,
        )
        for c in controls
    ]


def _test_names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        and node.name.startswith("test_")
    }


def unresolved_nodes(controls: list[Control]) -> list[str]:
    """Node ids that name no test function. A dangling id is a control that does not exist."""
    cache: dict[str, set[str]] = {}
    missing: list[str] = []
    for control in controls:
        for node in control.red + control.green:
            rel, _, name = node.partition("::")
            if not name:
                missing.append(f"{node} (not a `file::test_name` node id)")
                continue
            path = ROOT / rel
            if not path.is_file():
                missing.append(f"{node} (no such file)")
                continue
            if rel not in cache:
                cache[rel] = _test_names(path)
            if name not in cache[rel]:
                missing.append(f"{node} (no test function of that name in {rel})")
    return missing


def unwired_ci_commands(controls: list[Control]) -> list[str]:
    """`ci` commands that do not appear in any step of the workflow they claim.

    A fixture asserter that nobody invokes is a file, not a control -- and it would still satisfy every
    other rule here.
    """
    unwired: list[str] = []
    for control in controls:
        if control.ci is None:
            continue
        if control.workflow is None:
            unwired.append(f"{control.ci} declares no `workflow`")
            continue
        body = "\n".join(
            str(step.get("run", ""))
            for job in jobs_of(control.workflow).values()
            for step in job.get("steps", [])
        )
        if control.ci not in body:
            unwired.append(f"{control.ci!r} appears in no `run:` step of {control.workflow}")
    return unwired


def reconcile() -> tuple[list[str], dict[str, int]]:
    """Return (problems, {context: control count}) over the live required set."""
    controls = load()
    required = required_contexts()
    coverage = dict.fromkeys(required, 0)
    problems: list[str] = []

    for control in controls:
        if control.context not in coverage:
            problems.append(
                f"control for {control.context!r} names a context that is NOT in "
                ".github/required-contexts.txt -- either the context was removed from branch "
                "protection or the string is a typo"
            )
            continue
        coverage[control.context] += 1
        for field, value in (
            ("plants", control.plants),
            ("holds", control.holds),
            ("observed", control.observed),
        ):
            if len(value) < _MIN_PROSE:
                problems.append(
                    f"{control.context!r}: `{field}` is empty or a placeholder. A control without a "
                    "stated violation, a stated asymmetry and a stated observation is a claim."
                )
        if not control.red:
            problems.append(f"{control.context!r}: no `red` nodes -- nothing asserts it can fail")
        if not control.green:
            problems.append(
                f"{control.context!r}: no `green` nodes. The asymmetry is mandatory: a control that "
                "reddens uniformly cannot tell you which layer does the work, and cannot distinguish "
                "'the other cases are safe by design' from 'safe by luck'."
            )

    for ctx, count in coverage.items():
        if count == 0:
            problems.append(
                f"required context {ctx!r} has NO negative control. It blocks merge and nobody has "
                "watched it fail. Register one in tests/negative_controls.toml."
            )

    problems.extend(f"dangling control node: {m}" for m in unresolved_nodes(controls))
    problems.extend(f"unwired ci control: {m}" for m in unwired_ci_commands(controls))
    return problems, coverage
