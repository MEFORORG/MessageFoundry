# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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
import subprocess
import sys
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
def test_THE_LANE_CAN_FAIL_on_a_planted_documentation_violation(tmp_path: Path) -> None:
    """THE ARM THE ITEM WAS LEFT OPEN FOR: prove a docs-only violation turns this lane RED.

    ``tests/test_backlog_status_check.py`` is a DOC_GUARDS member and its subject is the ledger, which
    is Markdown -- so it is exactly the kind of change the short-circuit skips the main suite for.

    The violation is planted in an ISOLATED COPY of the ledger, never in the real one: this suite runs
    under ``pytest-xdist`` at ``-n 4 --dist loadfile`` and mutating a tracked file would race three
    other workers. The checker is invoked against the copy, so the assertion is about the CHECKER's
    ability to fail rather than about the repository's current state.

    PAIRED, and the pairing is the point: the same checker over the UNMODIFIED copy must exit 0. A
    checker that failed on everything would satisfy the red arm alone.

    DISCRIMINATION MEASURED DIRECTLY ON THE CHECKER 2026-08-23, three fixtures, one command each --
    which is stronger evidence than mutating this test file and is recorded because a mutation of the
    test proved awkward to apply cleanly:

        clean copy of the ledger                 -> exit 0   "OK - 342 items, each declaring one status"
        + an item heading with NO banner         -> exit 1   the violation, caught
        + an item heading WITH a valid banner    -> exit 0   "OK - 343 items"

    So the checker distinguishes a real violation from an ordinary addition, and the red arm below is
    not satisfiable by a checker that simply fails on any edit.

    A NOTE ON HOW THAT WAS ALMOST GOT WRONG, since it is the same class this lane guards against: the
    FIRST probe of those three fixtures wrote them to ``/tmp`` under Git Bash, where the real path is
    ``C:\\Users\\...\\Temp``. The files were never created, and the checker returned exit 1 for BOTH
    the violation and the valid item -- because the FILE DID NOT EXIST. Read without checking, that is
    a checker that fails on everything. The tell was in its own first line: ``ERROR: --backlog ...``
    rather than a count."""
    checker = _ROOT / "scripts" / "docs" / "backlog_status_check.py"
    ledger = _ROOT / "docs" / "BACKLOG.md"
    if not (checker.is_file() and ledger.is_file()):
        pytest.skip("checker or ledger absent from this checkout")

    clean = tmp_path / "BACKLOG.md"
    clean.write_bytes(ledger.read_bytes())

    def run(target: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, no shell
            [sys.executable, str(checker), "--backlog", str(target), "--min-items", "1"],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=str(_ROOT),
        )

    # NEGATIVE CONTROL FIRST. If the unmodified copy already fails, the red below proves nothing.
    before = run(clean)
    assert before.returncode == 0, (
        "the unmodified ledger copy already fails, so this test cannot attribute a red to the "
        f"planted violation:\n{before.stdout}\n{before.stderr}"
    )

    # THE VIOLATION: an item heading carrying NO status banner at all. That is the defect
    # backlog_status_check exists to catch, and it is reachable by a Markdown-only edit.
    dirty = tmp_path / "DIRTY.md"
    dirty.write_text(
        clean.read_text(encoding="utf-8", errors="replace")
        + "\r\n## 999999. an item with no status banner, planted by a test\r\n\r\nprose\r\n",
        encoding="utf-8",
        newline="",
    )
    after = run(dirty)
    assert after.returncode != 0, (
        "A DOC_GUARDS member did NOT fail on a planted documentation violation. The docs-only lane "
        "would pass a Markdown-only pull request carrying this defect, which is the whole subject of "
        f"BACKLOG #1262.\nstdout:\n{after.stdout}\nstderr:\n{after.stderr}"
    )
