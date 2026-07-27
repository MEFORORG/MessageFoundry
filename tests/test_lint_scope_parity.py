# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The pre-commit hooks and the CI gates must lint/scan the SAME files.

They did not, and the divergence was silent in the worst direction: the hooks were BROADER than CI.
`ruff check` in CI named six explicit paths while the pre-commit ruff hook has no `exclude` and so
runs on every changed Python file; bandit in CI scanned `-r messagefoundry tee` while its hook scanned
everything but tests/harness/samples. The result was 99 ruff findings in harness/, tee/, samples/ and
docker/ that were gated locally and by nothing in CI — so touching any file there blocked the commit
on errors that no CI run could report, and that no green build had ever been able to reveal.

The direction matters. A hook LOOSER than CI is an annoyance: CI still catches it. A hook STRICTER
than CI is a trap — it blocks work on a standard the project does not actually enforce, which is
what makes people reach for `--no-verify` and lose every other gate with it.

These tests read both configurations and compare them, so the next person to narrow one has to
narrow the other. They assert the CONTRACT, not any particular scope: widen or narrow freely,
provided both sides move together.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

yaml = pytest.importorskip("yaml")

_ROOT = Path(__file__).resolve().parents[1]
_PRECOMMIT = _ROOT / ".pre-commit-config.yaml"
_CI = _ROOT / ".github" / "workflows" / "ci.yml"
_SECURITY = _ROOT / ".github" / "workflows" / "security.yml"


def _hooks() -> dict[str, dict[str, Any]]:
    cfg = yaml.safe_load(_PRECOMMIT.read_text(encoding="utf-8"))
    return {h["id"]: h for repo in cfg["repos"] for h in repo["hooks"]}


def _ci_step_run(workflow: Path, name_fragment: str) -> str:
    """The `run:` body of the first step whose name contains ``name_fragment``."""
    wf = yaml.safe_load(workflow.read_text(encoding="utf-8"))
    for job in wf["jobs"].values():
        for step in job.get("steps") or []:
            if name_fragment.lower() in str(step.get("name", "")).lower() and "run" in step:
                return str(step["run"])
    raise AssertionError(f"no step matching {name_fragment!r} in {workflow.name}")


def test_ruff_lints_the_whole_repo_on_both_sides() -> None:
    """The hook has no `exclude`, so it lints every changed Python file. CI must do the same.

    An allow-list in CI cannot be kept in step with "everything" by hand — it was six paths while the
    hook covered the repo. `ruff check .` makes pyproject's [tool.ruff] extend-exclude the SINGLE
    definition of scope, which is the only arrangement that cannot drift.
    """
    hook = _hooks()["ruff-check"]
    assert "exclude" not in hook, (
        "the ruff-check hook grew an `exclude` — CI runs `ruff check .` over the whole repo, so an "
        "exclude here makes the hook quietly weaker than the gate it mirrors. Put the exclusion in "
        "pyproject [tool.ruff] extend-exclude, where BOTH sides read it."
    )
    run = _ci_step_run(_CI, "Lint (ruff)")
    assert re.search(r"ruff check\s+\.\s*$", run.strip()), (
        f"CI must lint the whole repo (`ruff check .`) to match the hook; got: {run.strip()!r}"
    )


def test_ruff_format_and_lint_agree_on_scope() -> None:
    """Format was already repo-wide (`ruff format --check .`) while lint was an allow-list. Two ruff
    invocations disagreeing about which files are 'the project' is the same bug in miniature."""
    lint = _ci_step_run(_CI, "Lint (ruff)").strip()
    fmt = _ci_step_run(_CI, "Format check (ruff)").strip()
    assert lint.endswith("."), lint
    assert fmt.endswith("."), fmt


def _bandit_skips(text: str) -> set[str]:
    m = re.search(r"--skip[= ]([A-Z0-9,]+)", text)
    assert m, f"no --skip found in: {text[:200]!r}"
    return set(m.group(1).split(","))


def test_bandit_skips_match() -> None:
    hook_args = " ".join(_hooks()["bandit"].get("args") or [])
    ci = _ci_step_run(_SECURITY, "Scan source for insecure patterns")
    assert _bandit_skips(hook_args) == _bandit_skips(ci), (
        "the bandit hook and the CI bandit job disagree about which tests are skipped — one of them "
        "is enforcing a standard the other does not"
    )


def test_bandit_excludes_match() -> None:
    """The hook excludes by regex, CI by comma-separated paths. Compare the PATHS they name.

    CI additionally excludes .venv/node_modules, which pre-commit never passes to a hook (they are
    untracked), so those are ignored rather than required on both sides.
    """
    hook_re = _hooks()["bandit"]["exclude"]
    hook_paths = {p.strip("/") for p in re.findall(r"[\w./-]+/", hook_re)}

    ci = _ci_step_run(_SECURITY, "Scan source for insecure patterns")
    m = re.search(r"--exclude[= ]([^\s\\]+)", ci)
    assert m, "CI bandit step has no --exclude"
    # removeprefix, not strip("./"): strip() removes those CHARACTERS from both ends, so "./.venv"
    # would become "venv" and silently fail to match the untracked set below.
    untracked = {".venv", "node_modules"}
    ci_paths = {p.strip().removeprefix("./").rstrip("/") for p in m.group(1).split(",")} - untracked

    assert hook_paths == ci_paths, (
        f"bandit scope drifted: hook excludes {sorted(hook_paths)}, CI excludes {sorted(ci_paths)}. "
        "A path excluded on ONE side only is scanned by one gate and not the other — which is how "
        "scripts/ came to be gated locally and by nothing in CI."
    )


def test_ci_bandit_scans_the_repo_not_an_allow_list() -> None:
    """`-r messagefoundry tee` silently stopped covering scripts/ the moment security tooling moved
    there. Scanning `.` minus explicit excludes cannot go stale that way."""
    ci = _ci_step_run(_SECURITY, "Scan source for insecure patterns")
    assert re.search(r"bandit\s+-r\s+\.", ci), (
        f"CI bandit must scan `-r .` with explicit --exclude, not an allow-list of dirs; got: {ci!r}"
    )
