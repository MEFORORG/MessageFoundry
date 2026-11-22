# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Tests for the required-context reachability check.

THE DEFECT IT GUARDS — measured on the sibling vault repo (``MEFORORG/MessageFoundry-vault``),
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
import subprocess
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


def _active_entries() -> list[dict[str, object]]:
    """One well-formed workflow entry per required workflow file, all ``active``."""
    workflows = _payload(dict.fromkeys(_required_workflow_files(), "active"))["workflows"]
    assert isinstance(workflows, list)
    return workflows


def _stub_gh(monkeypatch: pytest.MonkeyPatch, stdout: str) -> list[dict[str, object]]:
    """Replace ``subprocess.run`` for the script; returns the recorded calls."""
    calls: list[dict[str, object]] = []

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append({"cmd": cmd, **kwargs})
        return subprocess.CompletedProcess(cmd, 0, stdout=stdout, stderr="")

    monkeypatch.setattr("scripts.ci.required_contexts.subprocess.run", fake_run)
    return calls


def test_a_conflicting_repeat_across_pages_exits_2(monkeypatch: pytest.MonkeyPatch) -> None:
    """A later ``active`` must not overwrite a ``disabled_manually`` for the same file."""
    entries = _active_entries()
    disabled = {**entries[0], "state": "disabled_manually"}
    _stub_gh(monkeypatch, json.dumps([{"workflows": [disabled]}, {"workflows": entries}]))
    assert main(["--repo", "owner/name"]) == 2


def test_an_identical_repeat_is_harmless(monkeypatch: pytest.MonkeyPatch) -> None:
    """Control for the conflict case: a page shift that repeats an entry unchanged still passes."""
    entries = _active_entries()
    _stub_gh(monkeypatch, json.dumps([{"workflows": entries[:1]}, {"workflows": entries}]))
    assert main(["--repo", "owner/name"]) == 0


def test_a_same_named_file_elsewhere_cannot_stand_in(monkeypatch: pytest.MonkeyPatch) -> None:
    """A ``dynamic/`` entry with a required file's basename does not make that file present."""
    entries = _active_entries()
    name = Path(str(entries[0]["path"])).name
    entries[0] = {**entries[0], "path": f"dynamic/other/{name}"}
    _stub_gh(monkeypatch, json.dumps([{"workflows": entries}]))
    assert main(["--repo", "owner/name"]) == 1


@pytest.mark.parametrize(
    ("returncode", "stdout"), [pytest.param(1, "", id="gh-fails"), pytest.param(0, "", id="empty")]
)
def test_a_failed_gh_read_exits_2(
    monkeypatch: pytest.MonkeyPatch, returncode: int, stdout: str
) -> None:
    def fake_run(cmd: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(cmd, returncode, stdout=stdout, stderr="refused")

    monkeypatch.setattr("scripts.ci.required_contexts.subprocess.run", fake_run)
    assert main(["--repo", "owner/name"]) == 2


@pytest.mark.parametrize(
    ("argv", "route"),
    [
        pytest.param(["--repo", "owner/name"], "repos/owner/name/actions/workflows", id="named"),
        pytest.param([], "repos/{owner}/{repo}/actions/workflows", id="default"),
    ],
)
def test_the_gh_route(monkeypatch: pytest.MonkeyPatch, argv: list[str], route: str) -> None:
    calls = _stub_gh(monkeypatch, json.dumps([{"workflows": _active_entries()}]))
    assert main(argv) == 0
    cmd = calls[0]["cmd"]
    assert isinstance(cmd, list)
    assert cmd[-1] == route


def test_a_gh_timeout_exits_2(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(cmd: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(cmd, 120)

    monkeypatch.setattr("scripts.ci.required_contexts.subprocess.run", fake_run)
    assert main(["--repo", "owner/name"]) == 2


def test_two_slurped_pages_are_both_read(monkeypatch: pytest.MonkeyPatch) -> None:
    """More than 100 workflows arrive as several pages, and a context on page two must resolve.

    gh sends ``per_page=100`` under ``--paginate``, so the trigger is more than 100 workflows.
    """
    entries = _active_entries()
    assert len(entries) >= 2, "expected the required set to span at least two workflows"
    pages = [{"workflows": entries[:1]}, {"workflows": entries[1:]}]
    calls = _stub_gh(monkeypatch, json.dumps(pages))

    assert main(["--repo", "owner/name"]) == 0
    assert len(calls) == 1
    cmd = calls[0]["cmd"]
    assert isinstance(cmd, list)
    assert "--paginate" in cmd and "--slurp" in cmd, cmd
    assert calls[0]["encoding"] == "utf-8"


def test_a_disabled_workflow_on_page_two_is_caught(monkeypatch: pytest.MonkeyPatch) -> None:
    """Control for the two-page pass: page two's states are really read, not just tolerated."""
    entries = _active_entries()
    entries[-1] = {**entries[-1], "state": "disabled_manually"}
    _stub_gh(monkeypatch, json.dumps([{"workflows": entries[:-1]}, {"workflows": entries[-1:]}]))
    assert main(["--repo", "owner/name"]) == 1


def test_a_list_of_workflows_is_still_read(tmp_path: Path) -> None:
    """A saved payload may be a bare workflow list, the other list shape."""
    p = tmp_path / "list.json"
    p.write_text(json.dumps(_active_entries()), encoding="utf-8")
    assert main(["--states-json", str(p)]) == 0


def test_concatenated_pages_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """The output of ``--paginate`` without ``--slurp`` is not one document: unread, so exit 2."""
    page = json.dumps({"workflows": _active_entries()})
    _stub_gh(monkeypatch, page + page)
    assert main(["--repo", "owner/name"]) == 2


_GOOD = {"path": ".github/workflows/ci.yml", "state": "active"}


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param({"message": "Not Found"}, id="object-without-workflows"),
        pytest.param({"workflows": None}, id="workflows-null"),
        pytest.param({"workflows": "ci.yml"}, id="workflows-string"),
        pytest.param({"workflows": {"path": "ci.yml"}}, id="workflows-object"),
        pytest.param({"workflows": ["ci.yml"]}, id="workflow-entry-string"),
        pytest.param({"workflows": [None]}, id="workflow-entry-null"),
        pytest.param({"workflows": [{"state": "active"}]}, id="entry-without-path"),
        pytest.param({"workflows": [{"path": "ci.yml"}]}, id="entry-without-state"),
        pytest.param({"workflows": [{"path": 7, "state": "active"}]}, id="path-not-string"),
        pytest.param({"workflows": [{"path": "ci.yml", "state": 1}]}, id="state-not-string"),
        pytest.param({"workflows": [{"path": "", "state": "active"}]}, id="path-empty"),
        pytest.param({"workflows": [{"path": "ci.yml", "state": ""}]}, id="state-empty"),
        pytest.param({"workflows": [{"path": "   ", "state": "active"}]}, id="path-blank"),
        pytest.param({"workflows": [{"path": "ci.yml", "state": "   "}]}, id="state-blank"),
        pytest.param(
            {"workflows": [{"path": " .github/workflows/ci.yml", "state": "active"}]},
            id="path-outside-directory",
        ),
        pytest.param(
            {"workflows": [{"path": "dynamic/x/y", "state": "active"}]}, id="only-dynamic"
        ),
        pytest.param({"workflows": [{"path": ".", "state": "active"}]}, id="path-with-no-parts"),
        pytest.param([], id="empty-list"),
        pytest.param(["ci.yml"], id="list-of-strings"),
        pytest.param([None], id="list-of-null"),
        pytest.param([[_GOOD]], id="list-of-lists"),
        pytest.param([{"workflows": [_GOOD]}, "page"], id="page-then-string"),
        pytest.param([{"workflows": [_GOOD]}, _GOOD], id="page-mixed-with-workflow"),
        pytest.param([{"workflows": [_GOOD]}, {"workflows": None}], id="second-page-malformed"),
        pytest.param([{"workflows": [_GOOD]}, {"message": "error"}], id="second-page-error"),
        pytest.param(_GOOD, id="top-level-bare-workflow"),
        pytest.param("workflows", id="top-level-string"),
        pytest.param(7, id="top-level-number"),
        pytest.param(None, id="top-level-null"),
    ],
)
def test_a_malformed_shape_exits_2(tmp_path: Path, payload: object) -> None:
    """Exit 1 means "a finding", so an unreadable payload must never produce it, or a pass."""
    p = tmp_path / "bad.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    assert main(["--states-json", str(p)]) == 2


def test_undecodable_bytes_exit_2(tmp_path: Path) -> None:
    """Bytes that are not UTF-8 are one more unreadable payload."""
    p = tmp_path / "bad.json"
    p.write_bytes(b'{"workflows": "\xff"}')
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


def test_the_script_imports_without_pytest_installed() -> None:
    """The CI job installs the SCANNER lock, not the test toolchain — so pytest is absent there.

    This is the regression that broke PR #76's first run. ``tests/_workflow_contexts`` did
    ``import pytest`` at module scope (only to reach ``importorskip("yaml")``), so the script died on
    ``ModuleNotFoundError: No module named 'pytest'`` in CI while passing locally, where a dev venv has
    pytest. A pure environment difference — exactly the class this repo keeps getting bitten by.

    Asserted by importing in a SUBPROCESS and checking ``pytest`` never entered ``sys.modules``. Testing
    it in-process would be meaningless: pytest is, by definition, already imported when this runs.
    """
    probe = (
        "import sys; "
        "sys.path.insert(0, r'" + str(_ROOT) + "'); "
        "import tests._workflow_contexts as m; "
        "assert m.required_contexts(), 'resolver returned no contexts'; "
        "print('PYTEST_IMPORTED' if 'pytest' in sys.modules else 'CLEAN')"
    )
    out = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-c", probe], capture_output=True, text=True, timeout=120
    )
    assert out.returncode == 0, f"importing the resolver failed:\n{out.stderr}"
    assert "CLEAN" in out.stdout, (
        "importing tests/_workflow_contexts pulled in pytest. The CI job for "
        "scripts/ci/check_required_workflow_state.py installs only ci/locks/ci-scanners.lock, so a "
        "pytest import there is a hard failure. Import yaml directly and fall back to importorskip "
        f"only when it is absent.\nstdout: {out.stdout}\nstderr: {out.stderr}"
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
