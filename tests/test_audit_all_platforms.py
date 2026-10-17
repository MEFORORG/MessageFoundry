# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The required dependency audit must see every pin, whatever its environment marker.

The auditor ships in the wheel (``messagefoundry/security/audit_all_platforms.py``, which carries the
defect, the measurement and the reasoning, and whose unit tests are
``tests/test_security_audit_all_platforms.py``). The workflows reach it through the
``scripts/security/audit_all_platforms.py`` wrapper. These tests pin the workflows to that wrapper and
the wrapper to the one implementation, so the audit cannot quietly return to reading a committed lock
on a host that evaluates its markers.
"""

from __future__ import annotations

import re

import pytest
import yaml

from scripts.security.audit_all_platforms import main, requirement_lines, strip_markers
from tests._workflow_contexts import ROOT, WORKFLOWS, step_script

#: The locks the required audit step reads, in both jobs that carry it.
_AUDITED = (
    "requirements.lock",
    "ci/locks/ci-scanners.lock",
    "ci/locks/ci-quality.lock",
    "ci/locks/release-tools.lock",
)
#: Not audited on their own: every pin in each is also in requirements.lock, which
#: test_the_subset_locks_are_covered_by_requirements_lock asserts rather than assumes.
_SUBSET_LOCKS = (
    "docker/locks/requirements-core.lock",
    "docker/locks/requirements-sqlserver.lock",
    "security/locks/requirements-harness.lock",
)
_TREE_LOCKS = (*_AUDITED, *_SUBSET_LOCKS)
_AUDIT_STEP = "Audit the locked dependencies (DEP-1)"
_SCRIPT = "scripts/security/audit_all_platforms.py"


def test_the_wrapper_runs_the_packaged_implementation() -> None:
    """One implementation: the workflows' entry point is the module the adopter's job runs."""
    for imported in (main, strip_markers, requirement_lines):
        assert imported.__module__ == "messagefoundry.security.audit_all_platforms", imported


@pytest.mark.parametrize("lock", _TREE_LOCKS)
def test_every_committed_lock_strips_to_marker_free_pins(lock: str) -> None:
    """Positive control over the real inputs, against an oracle that is not the code under test."""
    source = (ROOT / lock).read_text(encoding="utf-8")
    text, stripped, requirements = strip_markers(source)
    expected = re.sub(r"^([^\s#-]\S*) ; [^\\\n]*?( \\)?$", r"\1\2", source, flags=re.MULTILINE)
    assert requirements >= 10, f"{lock}: read only {requirements} requirements"
    assert text == expected
    assert len(stripped) == len(re.findall(r"^[^\s#-]\S* ; ", source, flags=re.MULTILINE))


def test_the_windows_only_pins_are_in_the_audited_set() -> None:
    """Non-vacuity: the gap this closes is live in the tree, so the strip has something to do."""
    stripped = strip_markers((ROOT / "requirements.lock").read_text(encoding="utf-8"))[1]
    assert any("sys_platform == 'win32'" in entry for entry in stripped)


def _pins(lock: str) -> set[str]:
    text = (ROOT / lock).read_text(encoding="utf-8")
    return {ln.split()[0] for ln in requirement_lines(text)}


@pytest.mark.parametrize("lock", _SUBSET_LOCKS)
def test_the_subset_locks_are_covered_by_requirements_lock(lock: str) -> None:
    """These locks are not audited on their own, which is sound only while this holds."""
    assert _pins(lock) - _pins("requirements.lock") == set()


#: Any invocation of the auditor: the console script or the module, whatever options follow.
_AUDITOR = re.compile(r"pip[-_]audit\b")


def _direct_audits(script: str) -> list[str]:
    """The lines of a ``run:`` script that start pip-audit other than through the script.

    Comments and ``echo`` prose are not invocations; neither is the script, whose name does not
    contain the token. Options are not parsed, so ``pip-audit --desc -r x`` is caught as readily as
    ``pip-audit -r x``.
    """
    lines = (ln.strip() for ln in script.splitlines())
    return [ln for ln in lines if ln and not ln.startswith(("#", "echo ")) and _AUDITOR.search(ln)]


def _run_scripts() -> list[tuple[str, str]]:
    """``(where, run script)`` and ``(where, uses)`` for every step in every workflow and action."""
    found: list[tuple[str, str]] = []
    files = [
        *sorted(WORKFLOWS.glob("*.yml")),
        *sorted((ROOT / ".github" / "actions").rglob("action.yml")),
    ]
    for path in files:
        parsed = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        groups = [job.get("steps") or [] for job in (parsed.get("jobs") or {}).values()]
        groups.append((parsed.get("runs") or {}).get("steps") or [])
        for steps in groups:
            for step in steps:
                step = step or {}
                found += [(path.name, str(step[key])) for key in ("run", "uses") if key in step]
    return found


def test_no_workflow_or_action_calls_pip_audit_directly() -> None:
    """A direct audit of a committed lock would evaluate markers against the runner again."""
    scripts = _run_scripts()
    found = [f"{where}: {ln}" for where, script in scripts for ln in _direct_audits(script)]
    assert len(scripts) > 100, f"read only {len(scripts)} steps -- this guard sees nothing"
    assert not found, f"call {_SCRIPT} instead: {found}"


def test_the_guard_sees_the_spellings_it_names() -> None:
    """Positive control for the guard above."""
    for spelling in (
        "pip-audit -r requirements.lock --desc",
        "pip-audit --desc -r requirements.lock",
        'if "$VENV/bin/pip-audit" -r x.lock; then',
        "python -m pip_audit -r requirements.lock",
        "python3 -mpip_audit --requirement=x.lock",
        "pypa/gh-action-pip-audit@v1",
    ):
        assert _direct_audits(spelling), spelling
    for benign in (
        f"python {_SCRIPT} requirements.lock",
        "# pip-audit -r requirements.lock",
        'echo "covered by the pip-audit job"',
    ):
        assert not _direct_audits(benign), benign


def test_every_exported_lock_is_audited_or_covered() -> None:
    """A lock the DEP-1 step exports must be audited or be a checked subset -- or this goes red."""
    script = step_script("security.yml", "pip-audit", "Check the lockfile is in sync")[1]
    exported = set(re.findall(r"^\s*uv export .* -o (\S+)$", script, flags=re.MULTILINE))
    # The hashless constraints export is a copy of requirements.lock for --constraint, not a lock.
    assert exported - {"constraints.lock"} == set(_TREE_LOCKS)


@pytest.mark.parametrize("job", ["pip-audit", "dependency-and-secret-scan"])
def test_the_audit_step_audits_every_lock_through_the_script(job: str) -> None:
    script = step_script("security.yml", job, _AUDIT_STEP)[1]
    audited = [ln.split(_SCRIPT, 1)[1].split()[0] for ln in script.splitlines() if _SCRIPT in ln]
    assert sorted(audited) == sorted(_AUDITED)
