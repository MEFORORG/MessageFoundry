# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Guards for the WIN2025 acceptance matrix + smoke tests for the live host probes.

Marked ``win2025_acceptance`` so the on-server pass can select it (``pytest -m win2025_acceptance``),
but it still runs in the normal suite: the integrity guards keep the matrix from rotting (every PROBE
key registered, every PYTEST node-id file present), and the probe smoke tests prove no probe raises —
they assert a *valid* status, not PASS, so they're green on the dev PC and the server alike.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from harness.acceptance.matrix import MATRIX, SECTIONS, Coverage, Status
from harness.acceptance.probes import PROBES, ProbeResult, run_probe

pytestmark = pytest.mark.win2025_acceptance

_REPO_ROOT = Path(__file__).resolve().parents[1]


def test_row_ids_unique_and_section_consistent() -> None:
    ids = [r.id for r in MATRIX]
    assert len(ids) == len(set(ids)), "duplicate matrix row id"
    for row in MATRIX:
        assert row.section == row.id[0], f"{row.id}: section {row.section!r} != id prefix"
        assert row.section in SECTIONS, f"{row.id}: unknown section {row.section!r}"


def test_probe_rows_reference_registered_probes() -> None:
    for row in MATRIX:
        if row.coverage is Coverage.PROBE:
            assert row.refs, f"{row.id}: PROBE row has no probe key"
            assert row.refs[0] in PROBES, f"{row.id}: probe {row.refs[0]!r} not registered"


def test_every_registered_probe_is_used() -> None:
    used = {row.refs[0] for row in MATRIX if row.coverage is Coverage.PROBE and row.refs}
    assert set(PROBES) == used, f"unused/undeclared probes: {set(PROBES) ^ used}"


def test_pytest_rows_reference_existing_files() -> None:
    for row in MATRIX:
        if row.coverage is Coverage.PYTEST:
            assert row.refs, f"{row.id}: PYTEST row has no node ids"
            for ref in row.refs:
                assert (_REPO_ROOT / ref).is_file(), f"{row.id}: missing test file {ref!r}"


def test_harness_and_manual_rows_carry_guidance() -> None:
    for row in MATRIX:
        if row.coverage is Coverage.HARNESS:
            assert row.refs, f"{row.id}: HARNESS row has no command"
        if row.coverage is Coverage.MANUAL:
            assert row.notes, f"{row.id}: MANUAL row has no instructions"


@pytest.mark.parametrize("key", sorted(PROBES))
def test_probe_returns_valid_result(key: str) -> None:
    result = run_probe(key)
    assert isinstance(result, ProbeResult)
    assert isinstance(result.status, Status)
    assert result.detail, f"probe {key!r} returned an empty detail"
    # A probe must never ERROR in this environment (ERROR means the check itself broke).
    assert result.status is not Status.ERROR, f"probe {key!r} errored: {result.detail}"


def test_run_probe_unknown_key_errors() -> None:
    result = run_probe("does_not_exist")
    assert result.status is Status.ERROR
