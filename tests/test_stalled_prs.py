# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The stalled-PR check must fire on the real shape and stay silent on everything adjacent to it.

These drive the REAL ``scan()`` and the REAL ``main()`` against payloads, not a re-statement of the
rule. The distinction matters more than usual here: this check exists because a green signal was
mistaken for a healthy one, so a test that cannot demonstrate the check FAILING would reproduce the
very defect it guards.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = _ROOT / "scripts" / "ci" / "check_stalled_prs.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_stalled_prs", _SCRIPT)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


sp = _load()


def _pr(
    number: int = 1,
    *,
    state: str = "OPEN",
    merge_state: str = "BEHIND",
    armed: bool = True,
    # Deliberately list[Any], not list[dict[...]]: one test feeds a NON-dict node to prove an
    # unreadable rollup entry is not silently treated as green.
    rollup: list[Any] | None = None,
) -> dict[str, Any]:
    """A PR payload defaulting to the STALL shape, so each test perturbs exactly one field."""
    return {
        "number": number,
        "title": f"pr {number}",
        "headRefName": f"branch-{number}",
        "state": state,
        "mergeStateStatus": merge_state,
        "autoMergeRequest": {"mergeMethod": "SQUASH"} if armed else None,
        "statusCheckRollup": [{"status": "COMPLETED", "conclusion": "SUCCESS", "name": "t"}]
        if rollup is None
        else rollup,
    }


# --- the positive control: it MUST fire ------------------------------------------------------------


def test_the_exact_stall_shape_is_detected() -> None:
    """Open + BEHIND + nothing failing + nothing pending. This is #74 and the six armed PRs."""
    found = sp.scan([_pr(74)])
    assert [s.number for s in found] == [74]
    assert found[0].armed is True


def test_an_unarmed_stall_is_still_reported() -> None:
    """Unarmed is still unmergeable — it just isn't lying to its author about it."""
    found = sp.scan([_pr(60, armed=False)])
    assert [s.number for s in found] == [60]
    assert found[0].armed is False


# --- the negative controls: each must NOT fire -----------------------------------------------------


@pytest.mark.parametrize("conclusion", ["FAILURE", "TIMED_OUT", "CANCELLED", "ACTION_REQUIRED"])
def test_a_failing_check_is_not_a_stall(conclusion: str) -> None:
    """A red PR is already loud. This check is only for the ones nothing else reports."""
    rollup = [{"status": "COMPLETED", "conclusion": conclusion, "name": "t"}]
    assert sp.scan([_pr(rollup=rollup)]) == []


@pytest.mark.parametrize("status", ["QUEUED", "IN_PROGRESS"])
def test_a_pending_check_is_not_a_stall(status: str) -> None:
    """Mid-suite is the normal path to green, not a stall — and it is where BEHIND flaps."""
    assert sp.scan([_pr(rollup=[{"status": status, "conclusion": None, "name": "t"}])]) == []


@pytest.mark.parametrize("merge_state", ["CLEAN", "BLOCKED", "DIRTY", "UNKNOWN", "UNSTABLE"])
def test_only_behind_counts(merge_state: str) -> None:
    """BLOCKED means checks aren't green yet; DIRTY is a conflict. Neither is this defect."""
    assert sp.scan([_pr(merge_state=merge_state)]) == []


@pytest.mark.parametrize("state", ["CLOSED", "MERGED"])
def test_a_closed_pr_is_not_a_stall(state: str) -> None:
    assert sp.scan([_pr(state=state)]) == []


# --- the shape that made the original bug invisible ------------------------------------------------


def test_an_unclassifiable_node_counts_as_unsettled_not_green() -> None:
    """A node we cannot read must never be silently treated as passing.

    This is the script's own defect class turned inward: 'I could not classify this' rendering as
    'this is fine' is precisely how a green signal stops meaning anything.
    """
    assert sp.scan([_pr(rollup=[{"weird": "shape"}])]) == []
    assert sp.scan([_pr(rollup=["not-a-dict"])]) == []


def test_statuscontext_nodes_are_understood() -> None:
    """GitHub returns two node shapes; a StatusContext carries `state`, not `status`/`conclusion`."""
    assert sp.scan([_pr(rollup=[{"state": "SUCCESS", "context": "legacy"}])]) != []
    assert sp.scan([_pr(rollup=[{"state": "FAILURE", "context": "legacy"}])]) == []
    assert sp.scan([_pr(rollup=[{"state": "PENDING", "context": "legacy"}])]) == []


# --- exit codes, driven through main() -------------------------------------------------------------


def _run(tmp_path: Path, prs: list[dict[str, Any]], *argv: str) -> int:
    payload = tmp_path / "prs.json"
    payload.write_text(json.dumps(prs), encoding="utf-8")
    return int(sp.main(["--prs-json", str(payload), *argv]))


def test_armed_stalls_fail_the_check(tmp_path: Path) -> None:
    assert _run(tmp_path, [_pr(74), _pr(96)]) == 1


def test_unarmed_stalls_alone_do_not_fail(tmp_path: Path) -> None:
    """Unarmed stalls warn. They need a human, but nothing is falsely promising to merge them."""
    assert _run(tmp_path, [_pr(60, armed=False)]) == 0


def test_warn_only_never_fails(tmp_path: Path) -> None:
    assert _run(tmp_path, [_pr(74)], "--warn-only") == 0


def test_a_healthy_repo_passes(tmp_path: Path) -> None:
    assert _run(tmp_path, [_pr(1, merge_state="CLEAN"), _pr(2, merge_state="BLOCKED")]) == 0


def test_an_empty_result_fails_closed(tmp_path: Path) -> None:
    """Zero PRs is a broken query, not a clean repo.

    The repo has had open PRs continuously; a sweep that finds none has failed to look. Reporting
    success there is the 'nothing pending means all settled' error this codebase keeps re-learning.
    """
    assert _run(tmp_path, []) == 2


def test_an_unreadable_payload_fails_closed(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert int(sp.main(["--prs-json", str(bad)])) == 2


def test_the_receipt_names_what_was_scanned(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """'no stalls' and 'nothing was examined' must not be indistinguishable."""
    _run(tmp_path, [_pr(1, merge_state="CLEAN")])
    assert "scanned 1 open pull request" in capsys.readouterr().out
