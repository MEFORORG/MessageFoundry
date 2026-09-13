# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The docs-only CI lane must be able to FAIL, and its module list must be read from CI (#1262).

The main pytest suite is skipped on a pull request touching only Markdown -- deliberately, and it is
good economics. But several gates take DOCUMENTATION as their subject, so `ci.yml` runs a `DOC_GUARDS`
list on exactly those pull requests. **That lane had never been shown able to fail.**

CI already checks that every named module EXISTS -- a path typo would otherwise make pytest error, or
under a future `-k`/`--ignore` form silently scan nothing and read as a pass. That guard is real and
this module does not duplicate it. What was missing is the other half: *does a documentation violation
introduced by a Markdown-only change actually turn this lane red?* An existence check cannot answer
that, and a lane that has never failed is indistinguishable from one that cannot.

WHY THE LIST IS PARSED OUT OF ci.yml RATHER THAN COPIED
---------------------------------------------------------
A second hand-maintained copy of `DOC_GUARDS` would drift from the one CI runs, and the drift would be
silent in the direction that matters: this module would keep testing a list nobody executes. The same
single-source rule the ledger tooling states for `parse_items`.

WHAT THIS DOES NOT CLAIM
--------------------------
It does not assert the list is COMPLETE. `ci.yml`'s own comment calls it *"a FLOOR, NOT a census"*, and
membership is a judgement about which gates read documentation. This module asserts the lane is wired,
runnable, and falsifiable -- not that it covers every doc-subject gate.

It also does not touch the 89 structural skips in `tests/test_threat_model_doc_drift.py`. Those come
from `docs/security/THREAT-MODEL.md` being vault-only and absent from every public checkout, which
`ci.yml:183-187` already records in terms, ADR 0156 classifies, and no quantity of pytest extras can
change. MEASURED 2026-08-23 in a venv carrying ALL five CI extras plus the webconsole editable: still
exactly 89 skipped, 272 passed. The extras were never the cause.
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_CI = _ROOT / ".github" / "workflows" / "ci.yml"


def _doc_guards() -> list[str]:
    """The DOC_GUARDS list AS CI DEFINES IT. Parsed, never re-typed."""
    text = _CI.read_text(encoding="utf-8")
    m = re.search(r'DOC_GUARDS="([^"]+)"', text)
    assert m is not None, "DOC_GUARDS is no longer a double-quoted shell assignment in ci.yml"
    return m.group(1).split()


def test_every_named_doc_guard_exists() -> None:
    """Mirrors CI's own existence check, locally, so a path typo is caught before it reaches a runner.

    CI does this too and that is not duplication for its own sake: CI's copy only runs on a docs-only
    pull request, which is the rarest path through the workflow, so a typo can sit unnoticed."""
    missing = [m for m in _doc_guards() if not (_ROOT / m).is_file()]
    assert not missing, f"DOC_GUARDS names modules that do not exist: {missing}"


def test_the_lane_is_not_empty_and_names_real_test_modules() -> None:
    """A DOC_GUARDS that parsed to nothing would make the lane pass by scanning zero modules -- the
    empty-scan-reads-as-clean shape this repository treats as worse than no check."""
    guards = _doc_guards()
    assert len(guards) >= 10, f"the doc-guard lane collapsed to {len(guards)} modules"
    assert all(g.startswith("tests/") and g.endswith(".py") for g in guards)


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git to build an isolated fixture")
def test_the_citation_guards_are_IN_the_lane(tmp_path: Path) -> None:
    """A FLOOR MEMBER, NOT A CENSUS (BACKLOG #1235).

    This file's own docstring says the list is "a FLOOR, NOT a census", and this test does not
    change that: it names the members whose ABSENCE was the defect, and says nothing about the rest.

    #1235's whole thesis is a citation to an unallocated number, which is introduced BY EDITING
    PROSE. So its detector must run on the pull requests that edit prose -- and `ci.yml`'s
    documentation-only step is the only leg that runs there. `tests/test_dangling_citation_check.py`
    was absent from DOC_GUARDS while TWO citation siblings were present, so the gate existed,
    passed its own tests, and never ran on the shape it was built for.

    WITHOUT THIS TEST, DELETING THAT LINE REGRESSES SILENTLY. The lane's other checks do not catch
    it: `test_every_named_doc_guard_exists` only validates the modules that ARE named, and
    `test_the_lane_is_not_empty` passes at any count above ten. A guard removed from the list is
    indistinguishable from a guard that was never in it.
    """
    guards = set(_doc_guards())
    # TWO OF THE THREE ORIGINAL MEMBERS WERE LEDGER TOOLS AND ARE GONE (BACKLOG #1250):
    # test_dangling_citation_check and test_backlog_citation_check both read the numbered-item
    # ledger, which left this repository. What remains is the citation guard whose subject is
    # CLAUDE.md, and it is still introduced by editing prose -- so the rule this test enforces is
    # unchanged, over a smaller set.
    required = {
        "tests/test_claude_section_citations.py",
    }
    missing = sorted(required - guards)
    assert not missing, (
        "citation guards dropped from the documentation-only lane: "
        + ", ".join(missing)
        + " -- a citation is introduced by editing prose, so a detector that does not run on a "
        "docs-only PR does not run on the shape it exists for (BACKLOG #1235)."
    )
