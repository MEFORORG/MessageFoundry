# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The CI docs-only short-circuit, driven directly (BACKLOG #1200).

`ci.yml`'s `changes` job decides whether a PR runs the suite at all. When it says `code=false`,
install, lint, type-check and the whole of pytest are skipped — so a defect in this detector does not
fail loudly, it removes the thing that would have failed. That is the worst failure mode a gate has,
and until now the detector had no test of its own.

**The regexes are READ OUT OF `ci.yml`, never copied here.** A test carrying its own copy of the
pattern passes forever while the workflow drifts underneath it, which would reproduce the defect this
file exists to prevent one level up.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

CI = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "ci.yml"


def _extract(var: str, *, required: bool = True) -> str:
    """Pull a single-quoted shell assignment (`name='...'`) out of the workflow."""
    text = CI.read_text(encoding="utf-8")
    m = re.search(rf"^\s*{re.escape(var)}='([^']*)'\s*$", text, re.M)
    if not m and not required:
        return ""
    assert m, f"{var}= not found in {CI.name}; the detector was renamed or restructured"
    return m.group(1)


def classify(
    paths: list[str], *, alwayscode: str | None, noncode: str, alwayscodepath: str = ""
) -> bool:
    """Mirror of the shell decision in `ci.yml`'s `changes` step. Returns `code`.

    `grep -qE P`  -> any line matches P.
    `grep -qvE P` -> any line does NOT match P.

    `alwayscode=None` reproduces the PRE-#1200 logic, which is what makes the regression test below
    able to tell a fixed detector from a deleted one.
    """
    if not paths:
        return True
    if alwayscode is not None and any(re.search(alwayscode, p) for p in paths):
        return True
    # Extensionless config the extension rule cannot reach (BACKLOG #1200 amendment).
    if alwayscodepath and any(re.search(alwayscodepath, p) for p in paths):
        return True
    # The shell's final `elif ... else`: any path outside the docs allowlist means CODE, otherwise the
    # diff is docs-only and short-circuits.
    return any(not re.search(noncode, p) for p in paths)


@pytest.fixture(scope="module")
def pats() -> tuple[str, str, str]:
    return _extract("alwayscode"), _extract("noncode"), _extract("alwayscodepath")


# --- the defect, and proof the probe can see it ---------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "docs/security/asvs-apply-cells.py",  # the ASVS record WRITER, measured exempt 2026-08-09
        "docs/benchmarks/results/2026-07-04-adr0071-b5-executor-marshaling/b5_microbench.py",
        "docs/anything/script.sh",
        "docs/anything/module.ts",
        "docs/anything/config.toml",
        "docs/anything/workflow.yml",
    ],
)
def test_an_executable_under_docs_is_code_and_was_not_before(
    path: str, pats: tuple[str, str, str]
) -> None:
    """THE REGRESSION, asserted in both directions in one test.

    Asserting only that the new detector says CODE cannot distinguish a fixed detector from a deleted
    one — `return True` passes that. So this also asserts the OLD logic said NON-CODE for the same
    path. If someone reverts the fix, the first assertion fails; if someone guts the detector into a
    constant, the second fails.
    """
    alwayscode, noncode, alwayscodepath = pats
    assert classify([path], alwayscode=None, noncode=noncode) is False, (
        "the pre-#1200 detector should classify this as docs-only; if this fails the test has lost "
        "its grip on the historical behaviour and proves nothing about the fix"
    )
    assert (
        classify([path], alwayscode=alwayscode, noncode=noncode, alwayscodepath=alwayscodepath)
        is True
    )


# --- the optimisation this fix must NOT destroy ---------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "docs/SECURITY.md",
        "docs/adr/0156-asvs-scorecard-as-data.md",
        "README.md",
        "LICENSE",
        "NOTICE",
    ],
)
def test_a_real_document_still_short_circuits(path: str, pats: tuple[str, str, str]) -> None:
    """Deleting `^docs/` would have fixed the defect and run the full suite on every prose edit.

    The short-circuit exists to avoid exactly that cost, so preserving it for actual documents is part
    of the requirement, not a nicety.
    """
    alwayscode, noncode, alwayscodepath = pats
    assert (
        classify([path], alwayscode=alwayscode, noncode=noncode, alwayscodepath=alwayscodepath)
        is False
    )


@pytest.mark.parametrize("path", [".gitattributes", ".gitignore"])
def test_extensionless_config_is_code_and_gitattributes_was_not_before(
    path: str, pats: tuple[str, str, str]
) -> None:
    """The gap the EXTENSION rule structurally cannot close (BACKLOG #1200 amendment).

    `#1200` made an executable file code wherever it lives -- keyed on the extension. `.gitattributes`
    has none, and it was still sitting in the docs-only allowlist, so a `.gitattributes`-only PR
    skipped lint, mypy and the entire suite. Not cosmetic: the vault's `asvs-scorecard.yml` records
    that a change here "silently alters how the corpus is materialized, which is exactly what makes
    the digest differ", so it is an input to the ASVS corpus pin.

    Asserted in BOTH directions for `.gitattributes`, because asserting only the new behaviour cannot
    distinguish a fixed detector from a deleted one. `.gitignore` is code under both rules -- #327
    removed it from `noncode` -- so only the forward direction is asserted for it; it is named in
    `alwayscodepath` so that "is code" stops depending on the ABSENCE of a line elsewhere.
    """
    alwayscode, noncode, alwayscodepath = pats
    if path == ".gitattributes":
        assert (
            classify([path], alwayscode=alwayscode, noncode=noncode, alwayscodepath="") is False
        ), "pre-amendment, .gitattributes should classify docs-only; the test has lost its grip"
    assert (
        classify([path], alwayscode=alwayscode, noncode=noncode, alwayscodepath=alwayscodepath)
        is True
    )


# --- ordinary code stays code ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "messagefoundry/api/app.py",
        "scripts/asvs/apply.py",
        "tests/test_asvs_apply.py",
        ".github/workflows/ci.yml",
        "pyproject.toml",
        ".gitignore",  # BACKLOG #327 — deliberately code, and it has no code-ish extension
        # BACKLOG #1000. The negative-control reconciliation runs under pytest, which is gated on
        # `code == 'true'` — the same coupling that let a #320 banner merge without the suite
        # compiling. Its decay mode is a context arriving in branch protection and being mirrored
        # into `.github/required-contexts.txt`, so these two paths MUST classify as code or the gate
        # is skipped on exactly the pull request shape it exists for. The first is extensionless.
        ".github/required-contexts.txt",
        "tests/negative_controls.toml",
    ],
)
def test_code_paths_run_the_suite(path: str, pats: tuple[str, str, str]) -> None:
    alwayscode, noncode, alwayscodepath = pats
    assert (
        classify([path], alwayscode=alwayscode, noncode=noncode, alwayscodepath=alwayscodepath)
        is True
    )


# --- mixed diffs, and the probe's own liveness ------------------------------------------------------


def test_one_executable_among_many_documents_still_runs_the_suite(
    pats: tuple[str, str, str],
) -> None:
    """The realistic shape: a docs PR that also touches one script. Conservative means CODE."""
    alwayscode, noncode, alwayscodepath = pats
    paths = ["docs/a.md", "docs/b.md", "docs/security/helper.py", "README.md"]
    assert (
        classify(paths, alwayscode=alwayscode, noncode=noncode, alwayscodepath=alwayscodepath)
        is True
    )


def test_an_empty_diff_is_treated_as_code(pats: tuple[str, str, str]) -> None:
    """`ci.yml` defaults to running everything when it cannot tell. Pinned so that stays true."""
    alwayscode, noncode, alwayscodepath = pats
    assert (
        classify([], alwayscode=alwayscode, noncode=noncode, alwayscodepath=alwayscodepath) is True
    )


def test_the_probe_is_not_matching_everything(pats: tuple[str, str, str]) -> None:
    """NEGATIVE CONTROL. A regex that accidentally matched every path would make every assertion above
    pass while proving nothing — the same class of blindness the ASVS absence claims guard against with
    a positive control."""
    alwayscode, noncode, alwayscodepath = pats
    assert not re.search(alwayscode, "docs/SECURITY.md")
    assert not re.search(noncode, "messagefoundry/api/app.py")


def test_both_patterns_are_still_read_from_the_workflow(pats: tuple[str, str, str]) -> None:
    """If either assignment is renamed or restructured, `_extract` raises and this file goes red rather
    than silently testing nothing."""
    alwayscode, noncode, alwayscodepath = pats
    assert alwayscode and noncode
    assert "py" in alwayscode and "docs/" in noncode
