# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for the required-context reachability check.

THE DEFECT IT GUARDS — measured on the sibling vault repo (``wshallwshall/MessageFoundry``),
2026-07-30: 10 required contexts whose workflows were all ``disabled_manually``. A disabled workflow
never dispatches, so NO pull request could merge and every merge had silently been riding admin
bypass — invisible because the symptom reads as "CI is stuck", not "protection is misconfigured".

``tests/test_required_contexts.py`` cannot catch that: a disabled workflow keeps its file and job name
on disk, so resolving a context against YAML passes in the healthy *and* the broken case.

WHY THESE TESTS DRIVE THE REAL ``main()``. Every case below runs the shipped entry point through its
``--states-json`` seam rather than re-implementing the rule. A guard whose test asserts a local copy of
the logic is a guard nobody has run — and this repo has been bitten by exactly that.

MEASUREMENT, DATED so it cannot age into a false claim: on **2026-07-30** MEFORORG had 19 workflows,
all ``active``, and all 13 required contexts resolved to active workflows. The hazard is real but was
not live here on that date. ``test_the_live_repo_is_currently_clean`` is deliberately NOT part of this
module — that would make the suite depend on the network and on a mutable server state.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from scripts.ci.check_required_workflow_state import main  # noqa: E402
from tests._workflow_contexts import required_contexts, resolve  # noqa: E402


def _required_workflow_files() -> set[str]:
    """The workflow FILES that own a required context — resolved by the shipped resolver."""
    out = set()
    for ctx in required_contexts():
        where = resolve(ctx)
        assert where is not None, (
            f"required context {ctx!r} resolves to no job. Fix that first — "
            "tests/test_required_contexts.py owns that assertion."
        )
        out.add(where[0])
    return out


def _payload(states: dict[str, str]) -> dict:
    """An /actions/workflows payload with the given ``{filename: state}``."""
    return {
        "total_count": len(states),
        "workflows": [
            {"id": i, "name": f, "path": f".github/workflows/{f}", "state": s}
            for i, (f, s) in enumerate(sorted(states.items()), start=1)
        ],
    }


def _write(tmp_path: Path, states: dict[str, str]) -> Path:
    p = tmp_path / "states.json"
    p.write_text(json.dumps(_payload(states)), encoding="utf-8")
    return p


def test_all_active_passes(tmp_path: Path) -> None:
    """The healthy case — and the baseline the failure cases are measured against."""
    states = dict.fromkeys(_required_workflow_files(), "active")
    assert main(["--states-json", str(_write(tmp_path, states))]) == 0


def test_one_disabled_workflow_is_caught(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A single disabled workflow makes its context permanently unreportable."""
    files = sorted(_required_workflow_files())
    assert len(files) >= 2, "expected the required set to span at least two workflows"
    states = dict.fromkeys(files, "active")
    states[files[0]] = "disabled_manually"

    assert main(["--states-json", str(_write(tmp_path, states))]) == 1
    err = capsys.readouterr().err
    assert files[0] in err and "disabled_manually" in err, err
    # A single disabled workflow is NOT the vault shape; the catastrophic message must not fire.
    assert "EVERY required context" not in err, (
        "the all-unreachable message fired for a single disabled workflow — it would cry wolf and "
        "train the reader to ignore the one case that means nothing can merge"
    )


def test_the_vault_shape_is_called_out_by_name(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """EVERY required context unreachable means NO PR can merge — say so, loudly.

    This is the case that cost the vault repo real time: it presents as PRs hanging, which reads as
    flakiness. The diagnosis has to be in the output or someone spends a day on it.
    """
    states = dict.fromkeys(_required_workflow_files(), "disabled_manually")
    assert main(["--states-json", str(_write(tmp_path, states))]) == 1
    err = capsys.readouterr().err
    assert "EVERY required context" in err, err
    assert "NO pull request can merge" in err, err


def test_disabled_inactivity_counts_too(tmp_path: Path) -> None:
    """``active`` is the only runnable state — not "anything that isn't disabled_manually".

    ``disabled_inactivity`` arrives on its own after 60 idle days, which is precisely the quiet period
    this check exists to cover. Matching only the one state name seen on the vault would miss it.
    """
    files = sorted(_required_workflow_files())
    states = dict.fromkeys(files, "active")
    states[files[0]] = "disabled_inactivity"
    assert main(["--states-json", str(_write(tmp_path, states))]) == 1


def test_an_empty_workflow_list_fails_closed(tmp_path: Path) -> None:
    """ "The API returned nothing" must never read as "everything is fine"."""
    p = tmp_path / "empty.json"
    p.write_text(json.dumps({"total_count": 0, "workflows": []}), encoding="utf-8")
    assert main(["--states-json", str(p)]) == 2


def test_an_unreadable_payload_fails_closed(tmp_path: Path) -> None:
    """Same blindness, one level up: unable to measure is a FAILURE, not a pass."""
    p = tmp_path / "missing.json"
    assert main(["--states-json", str(p)]) == 2


def test_a_context_whose_workflow_is_absent_server_side_is_reported(tmp_path: Path) -> None:
    """A required context pointing at a workflow the server does not have is equally unreportable.

    Distinct from the disabled case — the file may exist on a branch but never have landed on the
    default branch, so GitHub has no workflow to run.
    """
    files = sorted(_required_workflow_files())
    states = dict.fromkeys(files[1:], "active")  # first workflow simply absent
    assert main(["--states-json", str(_write(tmp_path, states))]) == 1


def test_it_reuses_the_shared_resolver_rather_than_a_second_copy() -> None:
    """One context->workflow mapping, two callers.

    A second implementation is the drift this repo keeps writing parity tests to catch (ruff/bandit
    scan scope; the required-set prose). If the script ever grows its own parser, this fails and forces
    that to be a deliberate decision.
    """
    src = (_ROOT / "scripts" / "ci" / "check_required_workflow_state.py").read_text(
        encoding="utf-8"
    )
    assert "from tests._workflow_contexts import" in src, (
        "the reachability check no longer imports the shared resolver — it has grown a second "
        "context->workflow mapping, which will drift from tests/_workflow_contexts.py"
    )


def test_the_workflow_is_scheduled_and_least_privilege() -> None:
    """Per-PR alone cannot catch it: a workflow disabled AFTER the last PR has no PR to be caught on."""
    yaml = pytest.importorskip("yaml")
    doc = yaml.safe_load(
        (_ROOT / ".github" / "workflows" / "required-workflow-state.yml").read_text(
            encoding="utf-8"
        )
    )
    on = doc.get(True, doc.get("on"))
    assert isinstance(on, dict) and "schedule" in on, (
        f"required-workflow-state.yml must run on a schedule; `on:` is {on!r}. A workflow disabled "
        "after the last PR is invisible to any per-PR check."
    )
    job = doc["jobs"]["reachable"]
    assert job.get("permissions") == {"contents": "read", "actions": "read"}, (
        f"job permissions are {job.get('permissions')!r} — it needs `actions: read` to read workflow "
        "state and nothing more. Notably NOT the admin scope that reading branch protection requires."
    )
