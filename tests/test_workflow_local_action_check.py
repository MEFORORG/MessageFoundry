# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The workflow local-action gate must trip on both failure modes and stay silent on neither.

A gate with only failure arms passes on its own DELETION, so the silent arm is the one that makes
the others mean anything. The checker's own ``--self-test`` asserts the same thing from inside; this
file asserts it from outside, and additionally pins the live tree so the gate cannot quietly stop
covering the repository it was written for.
"""

from __future__ import annotations

import importlib.util
import pathlib
import subprocess
import sys

_ROOT = pathlib.Path(__file__).resolve().parents[1]
_SCRIPT = _ROOT / "scripts" / "quality" / "workflow_local_action_check.py"


def _load():
    spec = importlib.util.spec_from_file_location("workflow_local_action_check", _SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["workflow_local_action_check"] = mod
    spec.loader.exec_module(mod)
    return mod


def _write(root: pathlib.Path, body: str) -> None:
    wf = root / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / "probe.yml").write_text(body, encoding="utf-8")


def _action(root: pathlib.Path, rel: str) -> None:
    d = root / rel
    d.mkdir(parents=True, exist_ok=True)
    (d / "action.yml").write_text("name: probe\n", encoding="utf-8")


_WITH_CHECKOUT = """\
name: probe
on: [push]
jobs:
  j:
    steps:
      - uses: actions/checkout@aaaa
      - uses: ./.github/actions/thing
"""

_NO_CHECKOUT = """\
name: probe
on: [push]
jobs:
  j:
    steps:
      - uses: ./.github/actions/thing
"""


def test_the_self_test_passes_as_a_subprocess() -> None:
    """Run it the way CI does, so an import-time break cannot hide behind a direct call."""
    r = subprocess.run(
        [sys.executable, str(_SCRIPT), "--self-test"], capture_output=True, text=True
    )
    assert r.returncode == 0, r.stdout + r.stderr


def test_a_missing_local_action_trips(tmp_path: pathlib.Path) -> None:
    _write(tmp_path, _WITH_CHECKOUT)  # checkout present, action absent
    problems, files, seen = _load().check_tree(tmp_path)
    assert files == 1 and seen == 1, (files, seen)
    assert problems and "no action.yml" in " ".join(problems), problems


def test_a_present_action_with_no_checkout_trips(tmp_path: pathlib.Path) -> None:
    """The exact shape of the 2026-08-29 breakage: the action was vendored, the checkout was not."""
    _write(tmp_path, _NO_CHECKOUT)
    _action(tmp_path, ".github/actions/thing")
    problems, _, seen = _load().check_tree(tmp_path)
    assert seen == 1
    assert problems and "no actions/checkout" in " ".join(problems), problems


def test_the_silent_arm_stays_silent_and_still_looks(tmp_path: pathlib.Path) -> None:
    """MUST NOT TRIP -- and must still have SEEN the reference.

    Reporting zero problems having examined nothing is the failure this whole gate is about, so the
    count is asserted alongside the silence.
    """
    _write(tmp_path, _WITH_CHECKOUT)
    _action(tmp_path, ".github/actions/thing")
    problems, files, seen = _load().check_tree(tmp_path)
    assert problems == [], problems
    assert (files, seen) == (1, 1), (files, seen)


def test_a_commented_out_uses_is_not_code(tmp_path: pathlib.Path) -> None:
    """Three separate scanners in this repository were wrong on 2026-08-28 by reading prose as code."""
    _write(
        tmp_path,
        "name: probe\non: [push]\njobs:\n  j:\n    steps:\n"
        "      # uses: ./.github/actions/ghost\n"
        "      - uses: some/remote@bbbb # ./also-not-a-path\n",
    )
    problems, _, seen = _load().check_tree(tmp_path)
    assert seen == 0, "a comment and a trailing-comment path must not be read as local uses"
    assert problems == []


def test_an_empty_tree_is_not_a_pass(tmp_path: pathlib.Path) -> None:
    """No workflows means nothing was examined, which the CLI must report as a failure."""
    r = subprocess.run(
        [sys.executable, str(_SCRIPT), "--root", str(tmp_path)], capture_output=True, text=True
    )
    assert r.returncode == 1, r.stdout
    assert "NOTHING WAS EXAMINED" in r.stdout


def test_the_live_repository_is_covered() -> None:
    """Pin that the gate still SEES this repo's workflows.

    Without this, deleting the .github/workflows glob would leave every arm above green while the
    gate covered nothing in the tree it ships with.
    """
    _, files, _ = _load().check_tree(_ROOT)
    assert files >= 10, f"expected the repo's workflow set, scanned {files}"
