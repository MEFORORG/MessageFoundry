# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The CI `tooling` path-gate, driven directly.

`ci.yml`'s `changes` job decides whether the `tooling` job runs. That job is the ONLY place the
repo-harness tier executes -- the engine legs deselect it with ``-m 'not tooling'`` -- so a defect in
this gate does not fail loudly, it removes the thing that would have failed. `ci-gate` treats a
skipped need as a pass, so the whole workflow still reports green.

**This is not hypothetical, it is a regression this gate already had.** BACKLOG #327 established that
`.gitignore` must be force-classified as CODE, because six of its rules are the sole control keeping
maintainer-internal material out of a public commit and `tests/test_private_paths_stay_ignored.py` is
what asserts they still match. The tier split broke that one layer above #327's fix: `code=true` still
ran the test legs, but they now DESELECT that guard, and `.gitignore` matched no arm of this gate --
so a `.gitignore`-only PR faced the leak guard on no leg at all. Same defect, new route, and nothing
caught it until an adversarial review did. The first case below is that exact PR shape.

**The regex is READ OUT OF `ci.yml`, never copied here**, and the manifest arm is read out of the
manifest -- the same rule `test_ci_docs_only_detector.py` states for its sibling filter. A test
carrying its own copy of the pattern passes forever while the workflow drifts underneath it, which
reproduces the defect this file exists to prevent one level up.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_CI = _ROOT / ".github" / "workflows" / "ci.yml"
_MANIFEST = _ROOT / "tests" / "tooling_manifest.txt"


def _gate_regex() -> str:
    """Pull the tooling arm's `grep -qE '...'` pattern out of the workflow.

    Anchored on the `tooling=true` emission and searched backwards, so renaming the surrounding
    comment cannot silently pick up a different arm. If the shape changes, this raises and the file
    goes red -- which is the correct outcome, not a false pass.
    """
    text = _CI.read_text(encoding="utf-8")
    # `tooling=true` is emitted THREE times: the workflow_dispatch and push early-exits, and the
    # pull_request path arm. Only the last is a path decision -- the first two are unconditional and
    # sit ahead of any grep in the step. rfind, deliberately: anchoring on the first match found no
    # preceding `grep -qE` at all, which is the honest failure this comment exists to prevent
    # recurring as a silent wrong-arm pickup if the block order ever changes.
    emit = text.rfind('echo "tooling=true" >> "$GITHUB_OUTPUT"')
    assert emit > 0, "the tooling arm's GITHUB_OUTPUT emission is gone; this gate was restructured"
    # the LAST grep -qE before that emission is the path arm
    matches = list(re.finditer(r"grep -qE '([^']*)'", text[:emit]))
    assert matches, "no `grep -qE` found before the tooling emission"
    return matches[-1].group(1)


def _manifest_paths() -> set[str]:
    return {
        ln.strip()
        for ln in _MANIFEST.read_text(encoding="utf-8").splitlines()
        if ln.strip() and not ln.lstrip().startswith("#")
    }


def gate(changed: list[str]) -> bool:
    """Mirror of the shell decision. `grep -qE P` on the path arm, `grep -qxFf` on the manifest arm."""
    pattern = re.compile(_gate_regex())
    if any(pattern.search(p) for p in changed):
        return True
    return bool(set(changed) & _manifest_paths())


# (changed paths, expected, why this row exists)
_CASES = [
    ([".gitignore"], True, "BACKLOG #327: the leak guard must face a .gitignore-only PR"),
    ([".gitattributes"], True, "rides along with .gitignore in the alwayscodepath arm"),
    (["messagefoundry/pipeline/engine.py"], False, "engine-only: the entire point of the split"),
    (["tests/test_api_auth.py"], False, "an unlisted engine test is not harness work"),
    (["tests/test_security_static.py"], False, "stay-listed: runs on the engine legs, which run"),
    (["scripts/worktree/new.ps1"], True, "the harness itself"),
    ([".github/workflows/ci.yml"], True, "the workflow files are a listed test's subject"),
    (["CLAUDE.md"], True, "root CLAUDE.md -- `\\.claude/` matches the DIRECTORY, not this file"),
    (["docs/security/THREAT-MODEL.md"], True, "all of docs/, not just BACKLOG and adr"),
    (["pyproject.toml"], True, "test_new_dependency_check reads it"),
    (["ide/package.json"], True, "test_ide_licence_packaging reads ide/"),
    (["LICENSE"], True, "same test reads LICENSE"),
    (["tests/tooling_manifest.txt"], True, "edit the partition, re-run the tier it defines"),
    (["tests/conftest.py"], True, "the hook that applies the marker"),
    (
        ["messagefoundry/api/app.py", "docs/ARCHITECTURE.md"],
        True,
        "MIXED code+docs is the common PR shape and was the gap",
    ),
]


@pytest.mark.parametrize(("changed", "expected", "why"), _CASES)
def test_gate_decides(changed: list[str], expected: bool, why: str) -> None:
    assert gate(changed) is expected, f"{changed} should gate {expected}: {why}"


def test_every_manifest_entry_trips_its_own_gate() -> None:
    """Editing a listed test must run the tier that owns it.

    Covered by the manifest arm rather than the path regex, so this asserts the arm is wired at all --
    without it a manifest entry outside scripts/ or docs/ could be edited with no coverage.
    """
    missed = sorted(p for p in _manifest_paths() if not gate([p]))
    assert not missed, f"these listed tests do not trip the tooling gate when edited: {missed}"


def test_the_regex_is_read_not_copied() -> None:
    """If the arm is renamed or restructured, `_gate_regex` raises rather than passing on a stale copy."""
    assert "gitignore" in _gate_regex(), (
        "the extracted pattern does not mention .gitignore -- either the wrong grep was picked up, or "
        "the BACKLOG #327 arm was removed"
    )
