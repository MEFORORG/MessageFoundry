# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The required-contexts drift detector must fail on drift and fail closed on a bad answer."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

_REPO = Path(__file__).resolve().parents[1]
_SCRIPT = _REPO / "scripts" / "ci" / "check_required_contexts_drift.py"
_CANONICAL = _REPO / ".github" / "required-contexts.txt"

# A frozen payload of the shape `GET /repos/{owner}/{repo}/branches/{branch}` returns. Frozen rather
# than fetched: a test that calls the network measures the network, and this one is about the SCRIPT.
# Regenerate with: gh api repos/MEFORORG/MessageFoundry/branches/main > tests/fixtures/branch_main.json
_FIXTURE = _REPO / "tests" / "fixtures" / "branch_main.json"


def _declared() -> list[str]:
    """The register's own contexts, via the SHARED parser -- never a second hand-rolled scan."""
    sys.path.insert(0, str(_REPO))
    from tests._workflow_contexts import required_contexts

    return list(required_contexts())


def _run(payload: dict[str, Any], tmp_path: Path) -> subprocess.CompletedProcess[str]:
    p = tmp_path / "branch.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(_SCRIPT), "--branch-json", str(p)],
        capture_output=True,
        text=True,
        cwd=str(_REPO),
        timeout=120,
    )


@pytest.fixture(scope="module")
def payload() -> dict[str, Any]:
    if not _FIXTURE.exists():
        pytest.skip(f"no frozen branch payload at {_FIXTURE}")
    parsed: dict[str, Any] = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    return parsed


def _contexts(d: dict[str, Any]) -> list[str]:
    contexts: list[str] = d["protection"]["required_status_checks"]["contexts"]
    return contexts


def test_it_passes_when_the_file_matches_the_server(
    payload: dict[str, Any], tmp_path: Path
) -> None:
    """THE POSITIVE ARM. Without it, a script that always exits 1 would pass every arm below."""
    d = copy.deepcopy(payload)
    _contexts(d)[:] = _declared()
    r = _run(d, tmp_path)
    assert r.returncode == 0, f"clean tree must pass:\n{r.stdout}\n{r.stderr}"
    assert "matches the server exactly" in r.stdout


def test_a_server_only_context_is_detected(payload: dict[str, Any], tmp_path: Path) -> None:
    """The measured 2026-08-30 defect: the server required a context the file did not name."""
    d = copy.deepcopy(payload)
    _contexts(d)[:] = [*_declared(), "Invented (server-only)"]
    r = _run(d, tmp_path)
    assert r.returncode == 1
    assert "Invented (server-only)" in (r.stdout + r.stderr)


def test_a_file_only_context_is_detected(payload: dict[str, Any], tmp_path: Path) -> None:
    """The other direction. A file naming a context the server dropped is drift too."""
    d = copy.deepcopy(payload)
    declared = _declared()
    assert len(declared) > 1, (
        "the register must name more than one context for this arm to mean anything"
    )
    _contexts(d)[:] = declared[1:]
    r = _run(d, tmp_path)
    assert r.returncode == 1
    assert declared[0] in (r.stdout + r.stderr)


def test_zero_server_contexts_fails_rather_than_reporting_accurate(
    payload: dict[str, Any], tmp_path: Path
) -> None:
    """FAIL CLOSED. An empty required set is not evidence the file is right."""
    d = copy.deepcopy(payload)
    _contexts(d)[:] = []
    r = _run(d, tmp_path)
    assert r.returncode != 0
    assert "matches the server exactly" not in r.stdout


def test_a_missing_contexts_key_is_a_distinct_failure(
    payload: dict[str, Any], tmp_path: Path
) -> None:
    """An UNREADABLE answer and a REAL drift are different facts, so they carry different exits."""
    d = copy.deepcopy(payload)
    del d["protection"]["required_status_checks"]["contexts"]
    r = _run(d, tmp_path)
    assert r.returncode == 2, "an unreadable payload must not share an exit code with real drift"
    assert "Treating as a FAILURE" in (r.stdout + r.stderr)


def test_the_canonical_file_is_the_one_being_read() -> None:
    """Guards the seam itself: if the script stops reading the register, every arm above goes quiet."""
    assert _CANONICAL.exists()
    assert "required-contexts.txt" in _SCRIPT.read_text(encoding="utf-8")
