# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The `CI gate` roll-up names the leg that reddened it, in words a check-list reader can match
(BACKLOG #1776).

A reader classifying the check rows against the required set saw `CI gate` red beside
`repo harness tests (windows-2025)`, correctly dismissed that row as not required, and could not
explain the roll-up. The job id is `tooling` and the check list shows its display name, so the needs
dump alone never joined the two. A second reader hit the cancelled arm after cancelling runs by hand,
and its message named only supersession.

WHAT THIS FILE PINS, AND HOW. The annotation text is EXECUTED, not grepped: the Python both failing
steps run is lifted out of ci.yml and run against synthetic needs payloads. The id-to-display-name
table inside it is a hand list, so it is pinned against every need's own `name:` here, and a new
need or a renamed job reds this file rather than printing a stale name.

WHAT IS PINNED ELSEWHERE. Which step fires on which results vector, that the two arms partition, and
that a skipped-only vector fires neither, are tests/test_merge_gate_controls.py. This file does not
restate them.
"""

from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

from _bash_resolver import probe_env, require_bash

from tests._workflow_contexts import jobs_of

_TIMEOUT = 120
_FAIL_STEP = "Fail -- a gated leg FAILED"
_CANCEL_STEP = "Fail -- a gated leg was CANCELLED"
_EXPR = re.compile(r"\$\{\{.*?\}\}")
_HEREDOC_OPEN = "python3 - <<'PY'"


def _gate() -> dict[str, Any]:
    return jobs_of("ci.yml")["ci-gate"]


def _step(name: str) -> dict[str, Any]:
    for step in _gate()["steps"]:
        if step.get("name") == name:
            return dict(step)
    raise AssertionError(f"ci.yml `ci-gate` has no step named {name!r}")


def _heredoc(name: str) -> str:
    """The Python body between the heredoc opener and its `PY` terminator, exactly as bash sees it."""
    lines = str(_step(name)["run"]).splitlines()
    starts = [i for i, line in enumerate(lines) if line.startswith(_HEREDOC_OPEN)]
    assert len(starts) == 1, f"{name!r}: expected one `{_HEREDOC_OPEN}` line, found {len(starts)}"
    ends = [i for i, line in enumerate(lines) if line == "PY" and i > starts[0]]
    assert ends, f"{name!r}: the heredoc opened at line {starts[0]} is never closed by `PY`"
    return "\n".join(lines[starts[0] + 1 : ends[0]]) + "\n"


def _needs(**results: str) -> dict[str, Any]:
    """A needs payload shaped like `toJSON(needs)`: every gated leg, skipped unless named."""
    payload: dict[str, Any] = {k: {"result": "skipped", "outputs": {}} for k in _gate()["needs"]}
    for job_id, result in results.items():
        payload[job_id.replace("_", "-")] = {"result": result, "outputs": {}}
    return payload


def _annotate(arm: str, needs: dict[str, Any]) -> list[str]:
    """Run the step's Python the way the runner does, and return its annotation lines."""
    proc = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, the script is this repo's own
        [sys.executable, "-c", _heredoc(_FAIL_STEP)],
        env={**_base_env(), "NEEDS_JSON": json.dumps(needs), "GATE_ARM": arm},
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=_TIMEOUT,
        check=False,
    )
    assert proc.returncode == 0, f"the annotation script crashed:\n{proc.stdout}{proc.stderr}"
    return proc.stdout.splitlines()


def _base_env() -> dict[str, str]:
    env = {"PATH": os.environ.get("PATH", ""), "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"}
    for name in ("SYSTEMROOT", "SystemRoot", "COMSPEC", "TEMP", "TMP", "WINDIR", "PATHEXT"):
        if name in os.environ:
            env[name] = os.environ[name]
    return env


# ---------------------------------------------------------------------------------------------
# Shape: the two arms share one script, and neither can end green.
# ---------------------------------------------------------------------------------------------
def test_both_arms_run_the_same_script_and_still_exit_nonzero() -> None:
    """Two copies of the script may not drift apart; only GATE_ARM may differ between the steps.

    And a crash in the script must not be able to turn the step green or lose the dump: the opener
    carries an `|| echo` fallback and the step's last command is an unconditional `exit 1`.
    """
    assert _heredoc(_FAIL_STEP) == _heredoc(_CANCEL_STEP)
    assert _step(_FAIL_STEP)["env"]["GATE_ARM"] == "failure"
    assert _step(_CANCEL_STEP)["env"]["GATE_ARM"] == "cancelled"
    for name in (_FAIL_STEP, _CANCEL_STEP):
        run = str(_step(name)["run"])
        opener = next(line for line in run.splitlines() if line.startswith(_HEREDOC_OPEN))
        assert '|| echo "::error::' in opener, f"{name!r}: no fallback annotation on a crash"
        assert run.rstrip().splitlines()[-1] == "exit 1", f"{name!r} no longer ends in `exit 1`"
        # Template-injection defence: the needs context reaches the run block through env only.
        assert "${{" not in run, f"{name!r} interpolates an expression inline in its run block"


# ---------------------------------------------------------------------------------------------
# The id-to-check-list table cannot drift from the jobs it describes.
# ---------------------------------------------------------------------------------------------
def _check_names_table() -> dict[str, str]:
    tree = ast.parse(_heredoc(_FAIL_STEP))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "CHECK_NAMES" for t in node.targets
        ):
            table = ast.literal_eval(node.value)
            assert isinstance(table, dict)
            return {str(k): str(v) for k, v in table.items()}
    raise AssertionError("the ci-gate script no longer defines CHECK_NAMES")


def _derived_check_names() -> dict[str, str]:
    """A job's check-list name is its `name:` (else its key), each `${{ ... }}` shown as `*`."""
    jobs = jobs_of("ci.yml")
    return {need: _EXPR.sub("*", str(jobs[need].get("name") or need)) for need in _gate()["needs"]}


def test_the_check_name_table_matches_every_needed_jobs_own_name() -> None:
    """A hand table that disagreed with ci.yml would print a name no check row carries, which is
    the defect this item exists to fix, one layer down. A new need with no entry reds here too."""
    assert _check_names_table() == _derived_check_names()


def test_the_table_reader_sees_a_drifted_entry() -> None:
    """NEGATIVE CONTROL for the test above: the same comparison must REJECT a wrong table.

    A drifted copy, the one #1776 is about: `tooling` shown by its bare id. And the substitution
    must actually fire on the matrix names, or `derived` would carry raw templates and a table
    matching them would read as green.
    """
    jobs = jobs_of("ci.yml")
    derived = _derived_check_names()
    drifted = {**_check_names_table(), "tooling": "tooling"}
    assert drifted != derived
    assert derived["tooling"] == "repo harness tests (*)"
    assert sum(_EXPR.search(str(jobs[n].get("name") or "")) is not None for n in derived) >= 1


# ---------------------------------------------------------------------------------------------
# What the annotations actually say.
# ---------------------------------------------------------------------------------------------
def test_a_failed_leg_is_named_by_id_and_by_its_check_list_name() -> None:
    """The recurrence on pull request 1126: only `tooling` failed."""
    lines = _annotate("failure", _needs(tooling="failure"))
    assert lines[0].startswith("::error::CI gate failed: tooling ")
    assert '"repo harness tests (*)"' in lines[0]
    assert "real break" in lines[0]
    assert not any("CANCELLED" in line for line in lines)


def test_a_leg_whose_name_is_its_id_is_named_once() -> None:
    lines = _annotate("failure", _needs(packaging_build="failure"))
    assert lines[0] == (
        "::error::CI gate failed: packaging-build FAILED. This is a real break; open that leg's log."
    )


def test_a_mixed_run_names_the_failure_first_and_the_cancellation_beside_it() -> None:
    """Both present: the failure arm fires (the partition gives it the mixed case), and must not
    hide the cancelled leg, which also tested nothing."""
    lines = _annotate("failure", _needs(webconsole="failure", load_test="cancelled"))
    assert lines[0].startswith("::error::CI gate failed: webconsole ")
    assert "load-test" not in lines[0]
    assert (
        lines[1]
        == '::error::Also CANCELLED, so untested: load-test (check list: "load test (smoke, sqlite)").'
    )


def test_the_cancelled_arm_names_the_leg_and_all_three_causes() -> None:
    """Supersession, a timeout-minutes kill, and a hand cancellation all end a leg `cancelled`.
    The old text named only the first, so a reader who cancelled by hand found no newer run and no
    explanation."""
    lines = _annotate("cancelled", _needs(tooling="cancelled", webconsole="cancelled"))
    assert lines[0].startswith("::error::CI gate failed: tooling ")
    assert "webconsole" in lines[0] and "CANCELLED" in lines[0]
    text = "\n".join(lines)
    assert "newer run on the same ref" in text
    assert "timeout-minutes" in text
    assert "hand cancellation" in text
    assert "some other cause" in text, "the causes list reads as closed; it is not"
    assert all(line.startswith("::error::") for line in lines)


def test_a_skipped_or_successful_leg_is_never_named() -> None:
    """A skipped need is a pass to this gate; naming it as a culprit would send the reader to a
    job that did nothing."""
    needs = _needs(tooling="failure", webconsole="success")
    lines = _annotate("failure", needs)
    for job_id, need in needs.items():
        if need["result"] in {"skipped", "success"}:
            assert job_id not in "\n".join(lines), f"{job_id} ({need['result']}) was named"


def test_a_null_need_does_not_crash_the_script() -> None:
    needs = _needs(tooling="failure")
    needs["changes"] = None
    assert _annotate("failure", needs)[0].startswith("::error::CI gate failed: tooling ")


# ---------------------------------------------------------------------------------------------
# The whole run block, under bash, as the runner executes it.
# ---------------------------------------------------------------------------------------------
def _run_block(tmp_path: Path, name: str, needs_json: str) -> subprocess.CompletedProcess[str]:
    """Execute the step's entire `run:` under `bash -eo pipefail`, which is GitHub's default shell.

    `python3` is shimmed to this interpreter so the block runs the same on a Windows dev box as on
    ubuntu-latest, where `python3` is the system Python.
    """
    shim_dir = tmp_path / "shim"
    shim_dir.mkdir()
    shim = shim_dir / "python3"
    shim.write_text(f'#!/bin/sh\nexec "{Path(sys.executable).as_posix()}" "$@"\n', encoding="utf-8")
    shim.chmod(0o755)
    script = tmp_path / "step.sh"
    script.write_text(str(_step(name)["run"]), encoding="utf-8", newline="\n")
    bash = require_bash(tmp_path, _base_env())
    base = probe_env(Path(bash), _base_env())
    env = {
        **base,
        "PATH": f"{shim_dir}{os.pathsep}{base.get('PATH', '')}",
        "NEEDS_JSON": needs_json,
        "GATE_ARM": str(_step(name)["env"]["GATE_ARM"]),
    }
    return subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, test-local script
        [bash, "-eo", "pipefail", script.as_posix()],
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=_TIMEOUT,
        check=False,
    )


def test_the_run_block_prints_the_culprit_and_the_dump_then_exits_1(tmp_path: Path) -> None:
    needs_json = json.dumps(_needs(tooling="failure"))
    proc = _run_block(tmp_path, _FAIL_STEP, needs_json)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert proc.stdout.startswith("::error::CI gate failed: tooling "), proc.stdout + proc.stderr
    assert '"tooling"' in proc.stdout, "the needs dump no longer follows the annotation"


def test_a_crashing_script_still_reds_the_step_and_keeps_the_dump(tmp_path: Path) -> None:
    """POSITIVE CONTROL for the fallback: unreadable needs JSON crashes the script. The step must
    still print an annotation, still print the dump, and still exit 1."""
    proc = _run_block(tmp_path, _CANCEL_STEP, "not json")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "::error::CI gate could not name the leg" in proc.stdout, proc.stdout + proc.stderr
    assert "not json" in proc.stdout
