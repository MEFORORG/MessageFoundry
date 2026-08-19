# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""A new worktree's venv must resolve to the SAME versions CI uses.

THE DEFECT THIS EXISTS FOR. ``scripts/worktree/new.ps1`` provisioned each worktree with a bare
``pip install -e ".[dev,harness]"``. Every install in ``ci.yml`` passes ``--constraint
constraints.lock`` — its own comment says why: *"Without it, `uv pip install -e ".[extras]"`
RE-RESOLVES"*. ``new.ps1`` was the one place that omitted it, so a worktree resolved freely inside
``pyproject``'s ranges and could differ from CI on any tool.

Measured 2026-07-29: a worktree came up with **ruff 0.16.0** while ``constraints.lock`` pinned
**0.15.22**. Two consequences, and the second is why this is a guard rather than a nicety:

* it reported ~829 findings CI does not have (0.16 enabled stricter defaults), and
* ``ruff check --fix`` **rewrote files** to match — stripping ``# noqa`` directives the pinned ruff
  still wants.

A venv that lints differently from CI does not merely mislead; it edits your source.

NARROWED 2026-08-18, because half of that stopped being true and a stale reason sends a reader to the
wrong file. When the measurement was taken, the ``ruff-check`` pre-commit hook WAS ``ruff check
--fix`` under ``language: system``, so the rewrite above landed on commit, unasked. The ruff hooks
now install their own pinned ruff, so a commit's rewrite is that ruff's rather than this venv's, and
it agrees with CI because ``tests/test_lint_scope_parity.py`` holds the hook's ``rev`` to
``constraints.lock``. Everything this guard is actually about is unchanged: the venv's ruff is what
a developer runs by hand, and at least one of those hand runs WRITES — CONTRIBUTING.md's pre-push
pass is read-only (``ruff check .``, ``ruff format --check .``), but CLAUDE.md section 7's bare
``ruff format .`` is not. And ruff was never the only tool at stake: the same free re-resolution
reaches at least mypy and pytest, and nothing in ``.pre-commit-config.yaml`` pins either.

WHY A TEXT TEST. Nothing in the suite can run ``new.ps1`` — it creates a git worktree and a venv, which
is minutes of I/O and mutates the repo's worktree list. The invariant that actually matters is a
property of the COMMAND, so it is asserted against the command. That is the same posture as
``tests/test_ci_venv_pinning.py``, which pins workflow install lines no test can execute either.
"""

from __future__ import annotations

import re
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
_NEW_PS1 = _REPO / "scripts" / "worktree" / "new.ps1"
_CI = _REPO / ".github" / "workflows" / "ci.yml"
_CONSTRAINTS = _REPO / "constraints.lock"

#: A project install: ``pip install ... -e ".[extras]"``. Matches the editable-dot form specifically,
#: which is what installs THIS checkout; a lockfile install (``-r``) is a different thing and is not
#: what this module is about.
_EDITABLE_PROJECT_INSTALL = re.compile(r"pip\s+install\b[^\n]*-e\s+[\"']\.\[")


def _code_lines(path: Path) -> list[str]:
    """Non-comment lines. The rationale comments quote the very command under test, so scanning the
    raw text would let an explanation satisfy — or trip — the assertion."""
    return [
        ln for ln in path.read_text(encoding="utf-8").splitlines() if not ln.strip().startswith("#")
    ]


def test_new_worktree_installs_against_the_constraint_lock() -> None:
    """The fix itself: every editable project install in new.ps1 pins to constraints.lock."""
    installs = [ln for ln in _code_lines(_NEW_PS1) if _EDITABLE_PROJECT_INSTALL.search(ln)]

    # Non-vacuity. If the provisioning is restructured away, fail loudly rather than pass by finding
    # nothing to check — the failure mode that turns a guard into decoration.
    assert installs, (
        f'{_NEW_PS1.name} no longer contains an editable project install (`pip install -e ".[...]"`). '
        "If provisioning moved, re-point this guard at wherever it went."
    )
    unconstrained = [ln.strip() for ln in installs if "--constraint" not in ln]
    assert not unconstrained, (
        "a worktree venv is provisioned WITHOUT --constraint constraints.lock:\n  "
        + "\n  ".join(unconstrained)
        + "\nThat lets pip re-resolve inside pyproject's ranges, so the worktree can lint, typecheck "
        "and test against different tool versions than CI. It has already happened: ruff 0.16.0 "
        "against a lock pinning 0.15.22, and `ruff check --fix` then rewrote files. Since 2026-08-18 "
        "a commit's rewrite is the pre-commit hooks' own pinned ruff, not this venv's -- what this "
        "venv still drives is the hand run, and CLAUDE.md section 7's bare `ruff format .` writes. "
        "Nothing in .pre-commit-config.yaml pins mypy or pytest either, so this flag is what holds "
        "at least those two to CI."
    )


def test_the_constraint_file_new_ps1_names_actually_exists() -> None:
    """A pin at a path that does not exist fails the install outright — on a developer's first run.

    Cheap to assert, and it is the difference between this change working and it being a typo that
    nobody notices until someone creates a worktree.
    """
    assert _CONSTRAINTS.is_file(), (
        f"{_NEW_PS1.name} passes `--constraint constraints.lock`, but {_CONSTRAINTS} does not exist. "
        "Either the export path moved (see the DEP-1 step in security.yml) or the flag is wrong."
    )
    body = _CONSTRAINTS.read_text(encoding="utf-8")
    pinned = re.findall(r"(?m)^([A-Za-z0-9._-]+)==", body)
    assert len(pinned) > 50, (
        f"constraints.lock parsed to only {len(pinned)} pinned distributions — it is meant to be the "
        "hashless export of the whole resolved set. A near-empty constraint file silently constrains "
        "almost nothing, which is the same outcome as omitting the flag."
    )


def test_new_ps1_matches_the_posture_ci_documents() -> None:
    """CI is the reference. If it stops constraining, this guard is enforcing a stale rule.

    Asserted in this direction on purpose: the point is not "new.ps1 contains a flag", it is
    "developer provisioning agrees with CI provisioning". Should CI ever move off constraints.lock,
    this fails and forces the two to be reconciled deliberately rather than drifting apart again.
    """
    ci_installs = [ln for ln in _code_lines(_CI) if _EDITABLE_PROJECT_INSTALL.search(ln)]
    assert ci_installs, (
        "ci.yml no longer contains an editable project install — re-point this comparison rather than "
        "letting it pass on an empty set."
    )
    ci_unconstrained = [ln.strip() for ln in ci_installs if "--constraint" not in ln]
    assert not ci_unconstrained, (
        "ci.yml has an editable project install without --constraint:\n  "
        + "\n  ".join(ci_unconstrained)
        + "\nIf that is deliberate, new.ps1's constraint is now enforcing a rule CI no longer follows; "
        "reconcile the two in one change."
    )
