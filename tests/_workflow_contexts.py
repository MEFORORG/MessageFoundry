# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Resolve branch-protection status-check CONTEXTS to the jobs that report them.

Shared by ``test_required_contexts.py`` (does every in-repo claim about the required set agree?) and
``test_security_posture.py`` (can a required job be neutered without turning red?). Both need the same
context -> job mapping, and two copies of that mapping would be free to drift apart — which is the
class of bug both suites exist to catch.

THE MAPPING IS NOT OBVIOUS, which is why it lives in one place:

* The context string is the job's ``name:`` if it declares one, else the job KEY. That is why the CLA
  context is ``cla`` and not "CLA Assistant" (cla.yml's workflow name, which matches no status check).
* A matrix job's name is a TEMPLATE — ``test (${{ matrix.os }}, py${{ matrix.python-version }})``
  reports as ``test (ubuntu-latest, py3.14)``. Comparing the template literally would resolve nothing,
  so ``${{ ... }}`` becomes a wildcard.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

# PyYAML stays OPTIONAL (as tests/test_lint_scope_parity.py treats it), and the skip lives HERE rather
# than in each importing test module: done there it would sit before the
# `from tests._workflow_contexts import ...` line and every caller would need an E402 dance.
#
# Import yaml DIRECTLY first, and only fall back to pytest's importorskip when it is genuinely absent.
# This module is no longer test-only — scripts/ci/check_required_workflow_state.py imports the same
# resolver so there is ONE context->workflow mapping rather than two that drift. An unconditional
# `import pytest` at module scope made that impossible: the CI job installs the scanner lock, not the
# test toolchain, so the script died on `ModuleNotFoundError: No module named 'pytest'` while passing
# locally, where a dev venv has pytest. Measured on PR #76.
#
# Behaviour under pytest is unchanged: with PyYAML present the try succeeds (pytest is never imported
# here); with it absent the importorskip still turns the whole importing module into a SKIP.
try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover - exercised only on a venv without PyYAML
    import pytest

    yaml = pytest.importorskip("yaml")

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
CANONICAL_CONTEXTS = ROOT / ".github" / "required-contexts.txt"

_EXPR = re.compile(r"\$\{\{[^}]*\}\}")
_PLACEHOLDER = "\x00"


def required_contexts() -> list[str]:
    """The contexts recorded in ``.github/required-contexts.txt`` (comments/blanks stripped)."""
    lines = CANONICAL_CONTEXTS.read_text(encoding="utf-8").splitlines()
    return [s for line in lines if (s := line.strip()) and not s.startswith("#")]


def load_workflow(name: str) -> dict[str, Any]:
    """Parse one workflow file. ``name`` is the file name, e.g. ``security.yml``."""
    parsed = yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))
    assert isinstance(parsed, dict), f"{name} did not parse to a mapping"
    return parsed


def jobs_of(name: str) -> dict[str, dict[str, Any]]:
    return {k: (v or {}) for k, v in (load_workflow(name).get("jobs") or {}).items()}


def context_of(job_key: str, job: dict[str, Any]) -> str:
    """The status-check context string this job reports (still templated, if it is a matrix job)."""
    return str(job.get("name", job_key))


def _context_pattern(declared: str) -> re.Pattern[str]:
    expr = _EXPR.sub(_PLACEHOLDER, declared)
    body = "".join(
        ".+" if part == _PLACEHOLDER else re.escape(part)
        for part in re.split(f"({_PLACEHOLDER})", expr)
        if part
    )
    return re.compile(f"^{body}$")


def reportable_contexts() -> dict[str, tuple[str, str]]:
    """Every context a workflow here CAN report -> (workflow file, job key).

    Keys are the declared (possibly templated) strings; use :func:`resolve` to match a concrete
    context against them.
    """
    found: dict[str, tuple[str, str]] = {}
    for wf_path in sorted(WORKFLOWS.glob("*.yml")):
        for job_key, job in jobs_of(wf_path.name).items():
            found[context_of(job_key, job)] = (wf_path.name, job_key)
    return found


def resolve(context: str) -> tuple[str, str] | None:
    """Locate the job that reports ``context``, or None if no workflow can ever report it.

    None is the required-but-absent trap (docs/CI.md): a required context nothing reports blocks every
    PR forever. Callers must treat it as a failure, never skip it.
    """
    for declared, where in reportable_contexts().items():
        if _context_pattern(declared).match(context):
            return where
    return None
