# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1799: CI type-checks tests/, and the exemptions from that stay named and bounded.

Nothing type-checked a test file until #1799: the CI mypy steps named their packages, and
pre-commit runs no mypy. That is the third time a gate that reads as repo-wide skipped a directory
(ci.yml's `changes` job records the first two). These tests pin the repair so it cannot quietly
come undone:

* a ci.yml step runs ``mypy`` over ``tests``, gated exactly like the engine pass, never soft-failing;
* no global ``exclude`` reaches a test file;
* the tests profile in pyproject.toml has exactly its reviewed key set, so nobody can widen it (a
  ``disable_error_code``, an ``ignore_errors``) without this file failing;
* the ratchet list of exempt modules names only real test modules, sorted, without duplicates, and
  no longer than its ceiling.

A rename matters for the ratchet. An entry whose file was renamed away would hand the NEXT file to
take that name a free pass, so every entry must resolve to a file today.

What this file cannot see is a listed module that has become clean. Finding that needs a mypy run,
which is too slow for a unit test; the pyproject comment asks whoever fixes a module to drop it.
"""

from __future__ import annotations

import re
import shlex
import tomllib
from typing import Any

from tests._workflow_contexts import ROOT, jobs_of

_PYPROJECT = ROOT / "pyproject.toml"

#: The most modules the ratchet may list. LOWER it when you remove entries; never raise it. A ceiling
#: rather than an exact count, so removing a module does not also require editing this file.
_RATCHET_CEILING = 177

#: The reviewed tests.* profile. pyproject.toml's comment says why each key is there.
_PROFILE_KEYS = {
    "module",
    "disallow_untyped_defs",
    "disallow_incomplete_defs",
    "disallow_untyped_calls",
    "disallow_untyped_decorators",
    "disallow_any_generics",
    "warn_return_any",
    "check_untyped_defs",
}


def _mypy() -> dict[str, Any]:
    data = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    mypy: dict[str, Any] = data["tool"]["mypy"]
    return mypy


def _modules(override: dict[str, Any]) -> list[str]:
    module = override["module"]
    return [module] if isinstance(module, str) else list(module)


def _ratchet() -> list[str]:
    """The ``ignore_errors = true`` list. Empty once every listed module is fixed and it is deleted."""
    lists = [_modules(o) for o in _mypy()["overrides"] if o.get("ignore_errors") is True]
    assert len(lists) <= 1, "expected at most ONE ignore_errors override (the #1799 ratchet)"
    return lists[0] if lists else []


def _mypy_steps() -> list[tuple[dict[str, Any], list[str]]]:
    """Every ci.yml `test`-job step whose run is a single-line mypy command, with its argv."""
    out = []
    for step in jobs_of("ci.yml")["test"].get("steps", []):
        run = str(step.get("run", "")).strip()
        # Other steps are multi-line shell that shlex cannot split, and none of them is mypy.
        if run.startswith("mypy ") and "\n" not in run:
            out.append((step, shlex.split(run)))
    return out


def test_ci_type_checks_the_tests_directory_as_a_hard_gate() -> None:
    steps = _mypy_steps()
    # Positive control: the two engine passes must be found too, or the step reader is broken and
    # the assertions below would fail for the wrong reason (or, inverted, pass on nothing).
    assert len(steps) >= 3, f"expected the two engine mypy steps plus the tests step: {steps}"
    tests_steps = [step for step, argv in steps if "tests" in argv[1:]]
    assert len(tests_steps) == 1, f"expected exactly one ci.yml mypy step over `tests`: {steps}"
    step = tests_steps[0]
    assert "continue-on-error" not in step, "a soft-failing type-check gates nothing"
    engine = next(s for s, argv in steps if "messagefoundry_webconsole" in argv)
    assert step.get("if") == engine.get("if"), (
        "the tests pass must run exactly when the linux engine pass does, not on a narrower condition"
    )


def test_no_global_exclude_reaches_a_test_file() -> None:
    raw = _mypy().get("exclude", [])
    patterns = [raw] if isinstance(raw, str) else list(raw)
    # Positive control: the fixtures exclusion is real and matches what it is meant to.
    assert any(re.search(p, "tests/fixtures/handler_taint/handler-security.py") for p in patterns)
    hit = [p for p in patterns if re.search(p, "tests/test_example.py")]
    assert not hit, f"a global mypy exclude swallows ordinary test files: {hit}"


def test_the_tests_profile_is_exactly_the_reviewed_one() -> None:
    profile = [o for o in _mypy()["overrides"] if "tests.*" in _modules(o)]
    assert len(profile) == 1, "expected exactly one override for the tests.* profile"
    assert set(profile[0]) == _PROFILE_KEYS, (
        f"the tests.* profile changed shape: {sorted(set(profile[0]) ^ _PROFILE_KEYS)}. A new key "
        "can switch checks off for every test; update _PROFILE_KEYS only with the pyproject reason"
    )
    assert profile[0]["check_untyped_defs"] is True, (
        "without check_untyped_defs an unannotated test body is not checked at all"
    )


def test_the_ratchet_names_only_test_modules_and_no_wildcards() -> None:
    bad = [m for m in _ratchet() if not m.startswith("tests.") or "*" in m]
    assert not bad, f"the ratchet may list single tests.* modules only, never a pattern: {bad}"


def test_the_ratchet_never_grows() -> None:
    size = len(_ratchet())
    assert size <= _RATCHET_CEILING, (
        f"the ratchet lists {size} modules against a ceiling of {_RATCHET_CEILING}. A new or newly "
        "failing test module must be fixed, not exempted"
    )


def test_every_ratchet_entry_resolves_to_a_file() -> None:
    missing = [m for m in _ratchet() if not (ROOT / (m.replace(".", "/") + ".py")).is_file()]
    assert not missing, (
        f"ratchet entries with no file: {missing}. Delete them from pyproject.toml -- a stale name "
        "hands the next file to take it a pass it never earned"
    )


def test_the_ratchet_is_sorted_and_unique() -> None:
    modules = _ratchet()
    assert modules == sorted(set(modules)), "keep the ratchet sorted and free of duplicates"
